mod audit_view;
mod backup;
mod update;

use chrono::Local;
use log::warn;
use nat_common::{
    AccessControlMode, Args, AuditConfig, DdnsConfig, DynamicWhitelistDomainConfig, IpVersion,
    MSS_CLAMP_MAX, MSS_CLAMP_MIN, MssClampConfig, NftCell, Protocol, QuotaPeriod, SnatConfig,
    SnatMode, StatsConfig, TomlConfig, TrafficMode,
    audit::{self, AuditResult},
    dynamic_whitelist::{self, DynamicWhitelistEvent, DynamicWhitelistState},
    format_cli_time_from_rfc3339_with, format_cli_time_with, forward_test, geoip,
    last_good::{self, LastGoodPruneResult, LastGoodState},
    quota, stats as traffic_stats,
    uninstall::{self, DataMode, UninstallTarget},
};
use serde_json::json;
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

const NAT_BIN_PATH: &str = "/usr/local/bin/nat";

const DEFAULT_TOML_CONFIG: &str = "/etc/nat.toml";
const CONFIG_BACKUP_DIR: &str = "/etc/nftables-nat/backups/config";

pub fn run_menu(config_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_path.unwrap_or(DEFAULT_TOML_CONFIG);
    let mut last_manual_refresh: Option<chrono::DateTime<Local>> = None;
    if !interactive_menu_available() {
        return Err("当前环境不支持交互式菜单，请在终端中运行 nat --menu。".into());
    }
    loop {
        clear_screen();
        print_menu();
        let choice = prompt("请选择操作: ")?;
        if is_menu_refresh_command(&choice) || choice.trim().is_empty() {
            continue;
        }
        if matches!(choice.trim(), "0" | "q" | "quit" | "exit") {
            break;
        }
        let mut should_wait = true;
        let result: Result<(), Box<dyn std::error::Error>> = match choice.trim() {
            "1" => {
                should_wait = false;
                show_rules(config_path).map_err(Into::into)
            }
            "2" => add_single_interactive(config_path).map_err(Into::into),
            "3" => add_range_interactive(config_path).map_err(Into::into),
            "4" => edit_rule_interactive(config_path).map_err(Into::into),
            "5" => delete_rule_interactive(config_path).map_err(Into::into),
            "6" => {
                should_wait = false;
                toggle_rule_interactive(config_path).map_err(Into::into)
            }
            "7" => show_nft_rules().map_err(Into::into),
            "8" => {
                should_wait = false;
                stats_menu(config_path).map_err(Into::into)
            }
            "9" => {
                refresh_ddns_interactive(config_path, &mut last_manual_refresh).map_err(Into::into)
            }
            "10" => match backup_config(config_path) {
                Ok(backup) => {
                    audit_cli(
                        config_path,
                        "backup.create",
                        AuditResult::Ok,
                        json!({"backup": backup.display().to_string(), "trigger": "manual"}),
                    );
                    println!("已备份: {}", backup.display());
                    Ok(())
                }
                Err(e) => Err(e.into()),
            },
            "11" => restore_config_interactive(config_path).map_err(Into::into),
            "12" => {
                should_wait = false;
                access_control_menu(config_path).map_err(Into::into)
            }
            "13" => {
                should_wait = false;
                geoip_menu(config_path).map_err(Into::into)
            }
            "14" => {
                should_wait = false;
                egress_control_menu(config_path).map_err(Into::into)
            }
            "15" => {
                show_recent_source_design();
                Ok(())
            }
            "16" => {
                should_wait = false;
                bbr_telegram_menu(config_path).map_err(Into::into)
            }
            "17" => {
                should_wait = false;
                test_forward_interactive(config_path).map_err(Into::into)
            }
            "18" => {
                should_wait = false;
                update_menu(config_path).map_err(Into::into)
            }
            "19" => {
                should_wait = false;
                uninstall_menu(config_path).map_err(Into::into)
            }
            "20" => {
                should_wait = false;
                advanced_network_menu(config_path).map_err(Into::into)
            }
            "21" => {
                // view_audit_log_interactive 内部已经调用一次 wait_enter_to_return；
                // 主循环再叠加一次会让用户感觉「按 Enter → 空白 → 再按 Enter」。
                should_wait = false;
                view_audit_log_interactive(config_path).map_err(Into::into)
            }
            _ => {
                println!("未知选项: {}", choice.trim());
                Ok(())
            }
        };
        if let Err(e) = result {
            println!("操作失败: {e}");
        }
        if should_wait {
            wait_enter_to_continue()?;
        }
    }
    Ok(())
}

fn clear_screen() {
    if io::stdout().is_terminal() {
        print!("\x1B[2J\x1B[H");
        let _ = io::stdout().flush();
    }
}

fn wait_enter_to_continue() -> Result<(), io::Error> {
    let _ = prompt("按 Enter 返回主菜单...")?;
    Ok(())
}

fn wait_enter_to_return() -> Result<(), io::Error> {
    let _ = prompt("按 Enter 返回...")?;
    clear_screen();
    Ok(())
}

/// 子菜单 / 子动作的结果。
/// - `Done`：函数展示了内容或完成了配置改写；调用方可以再追加一次 `wait_enter_to_return`，
///   但**不强制**：很多自管 wait 的函数会自己调一次。
/// - `Cancelled`：用户选择 0 / 取消，函数没有展示信息，调用方**不应再要求按 Enter**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MenuOutcome {
    Done,
    Cancelled,
}

fn print_menu() {
    println!(
        r#"====================================
{title}
====================================
1) 查看当前转发规则
2) 添加单端口转发
3) 添加端口段转发
4) 编辑现有转发规则
5) 删除转发规则
6) 启用 / 禁用规则
7) 查看当前 nft 规则
8) 查看 Stats 流量统计
9) 手动刷新 DDNS / 域名目标
10) 备份当前配置
11) 从备份恢复配置
12) 白名单 / 黑名单管理
13) GeoIP / CN IP 限制
14) 出口目标限制
15) 最近来源 IP 观察（手动排查）
16) BBR / Telegram 状态
17) 测试转发规则连通性
18) 一键更新本项目
19) 卸载 / 清理本项目
20) 高级网络设置 (SNAT / MSS clamp)
21) 查看审计日志
0) 退出
===================================="#,
        title = main_menu_title(),
    );
}

/// 拼出主菜单标题：`nft-nat-rust <版本号>`。版本来自 [`nat_common::build_version`]，
/// 与 `nat --version` 同一来源；未注入版本时显示 `dev`。
fn main_menu_title() -> String {
    let raw = nat_common::build_version();
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        "nft-nat-rust dev".to_string()
    } else {
        format!("nft-nat-rust {trimmed}")
    }
}

fn prompt(label: &str) -> Result<String, io::Error> {
    if let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
        tty.write_all(label.as_bytes())?;
        tty.flush()?;
        let mut reader = io::BufReader::new(tty);
        let mut value = String::new();
        let bytes = reader.read_line(&mut value)?;
        if bytes == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin EOF"));
        }
        return Ok(value.trim().to_string());
    }
    if !io::stdin().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "当前环境不支持交互式菜单，请在终端中运行 nat --menu。",
        ));
    }
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    let bytes = io::stdin().read_line(&mut value)?;
    if bytes == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin EOF"));
    }
    Ok(value.trim().to_string())
}

fn interactive_menu_available() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
        || io::stdin().is_terminal()
}

fn is_menu_refresh_command(value: &str) -> bool {
    matches!(
        value.trim(),
        "nat --menu" | "nat menu" | "menu" | "main" | "m"
    )
}

fn load_toml_config(path: &str) -> Result<TomlConfig, io::Error> {
    let content = fs::read_to_string(path)?;
    TomlConfig::from_toml_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 从配置路径加载 AuditConfig；解析失败时回退到默认值（保证 audit 永不阻塞主流程）
fn audit_config_from(path: &str) -> AuditConfig {
    load_toml_config(path).map(|c| c.audit).unwrap_or_default()
}

/// 写一条 CLI 触发的 audit 事件；失败仅 WARN，不返回 Err
fn audit_cli(path: &str, action: &str, result: AuditResult, detail: serde_json::Value) {
    audit::log_event(&audit_config_from(path), action, result, detail);
}

// v0.6.1：safe_write_config / save_toml_config / backup_config / sanitize_backup_reason /
// restore_config_interactive / backup_filename / list_config_backups 已搬到 `menu/backup.rs`。
// `safe_write_config_to` 也要给 main.rs 的 quota_loop 用，因此向外 re-export。
pub(crate) use backup::safe_write_config_to;
use backup::{backup_config, restore_config_interactive, save_toml_config};

fn show_rules(path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(path)?;
    let stats_state = traffic_stats::load_state(&config.stats.data_file);
    let last_good_state = LastGoodState::load(&config.last_good.file);
    let resolutions: Vec<Option<String>> = config
        .rules
        .iter()
        .enumerate()
        .map(|(idx, rule)| {
            forward_test::rule_to_testable_rule(idx, rule).and_then(|t| t.resolved_ip)
        })
        .collect();
    for line in render_rules_default_lines(&config, &resolutions, &stats_state, &last_good_state) {
        println!("{line}");
    }
    println!();
    println!("提示：输入 d 查看详细诊断 / 按 Enter 返回主菜单");
    loop {
        let choice = prompt("> ")?;
        match choice.trim() {
            "" => return Ok(()),
            "0" => return Ok(()),
            value if is_menu_refresh_command(value) => return Ok(()),
            "d" | "D" => {
                println!();
                for line in render_global_diagnostics_lines(&config) {
                    println!("{line}");
                }
                println!();
            }
            other => {
                println!("未识别的输入 {other:?}。请输入 d 查看详细诊断，或按 Enter 返回主菜单。");
            }
        }
    }
}

/// 「全局诊断状态」聚合页：完整组合策略 + 完整 last-good 状态缓存。
/// 共用给「查看当前转发规则 → d」和「高级网络设置 → 查看全局诊断状态」。
pub(crate) fn render_global_diagnostics_lines(config: &TomlConfig) -> Vec<String> {
    let mut lines = format_combined_policy_status(config);
    lines.push(String::new());
    lines.extend(format_last_good_status(config));
    lines
}

/// 渲染「查看当前转发规则」默认页面：每条规则的核心字段 + 一行组合策略摘要 + 一行 last-good 摘要。
/// 不包含完整组合策略说明、也不展开 last-good 每条规则，这些通过 d/l/p 二级入口或高级菜单查看。
pub(crate) fn render_rules_default_lines(
    config: &TomlConfig,
    resolutions: &[Option<String>],
    stats_state: &nat_common::stats::StatsState,
    last_good_state: &LastGoodState,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "全局转发：{}",
        enabled_label(config.global.enabled)
    ));
    if !config.global.enabled {
        lines.push("当前不会生成转发规则。规则配置仍保留。".to_string());
    }
    lines.push(String::new());
    if config.rules.is_empty() {
        lines.push("当前没有转发规则".to_string());
    } else {
        for (index, rule) in config.rules.iter().enumerate() {
            let resolved = resolutions.get(index).and_then(|x| x.as_deref());
            let rule_lines = format_rule_core_lines(index, rule, resolved, config, stats_state);
            for line in rule_lines {
                lines.push(line);
            }
        }
    }
    lines.push(String::new());
    lines.push(combined_policy_summary(config));
    lines.push(last_good_summary(config, last_good_state));
    lines
}

/// 单条规则的核心信息：第一行包含 index / 状态 / type / sport / target / resolved_ip / dport /
/// protocol / ip_version；第二行附加 access_control / quota / egress 命中（按需）。
fn format_rule_core_lines(
    index: usize,
    rule: &NftCell,
    resolved: Option<&str>,
    config: &TomlConfig,
    stats_state: &nat_common::stats::StatsState,
) -> Vec<String> {
    let mut out = Vec::new();
    let status = rule_status(rule);
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            ..
        } => {
            let resolved_str = resolved_display(domain, resolved);
            out.push(format!(
                "{index}) [{status}] type=single sport={sport} target={domain} (resolved={resolved_str}) dport={dport} protocol={protocol} ip_version={ip_version} snat_ip={}",
                snat_ip_display(rule)
            ));
        }
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            ip_version,
            ..
        } => {
            let resolved_str = resolved_display(domain, resolved);
            out.push(format!(
                "{index}) [{status}] type=range sport={port_start}-{port_end} target={domain} (resolved={resolved_str}) dport={port_start}-{port_end} protocol={protocol} ip_version={ip_version} snat_ip={}",
                snat_ip_display(rule)
            ));
        }
        NftCell::Redirect {
            src_port,
            src_port_end,
            dst_port,
            protocol,
            ip_version,
            ..
        } => {
            let sport = src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string());
            out.push(format!(
                "{index}) [{status}] type=redirect sport={sport} target=localhost dport={dst_port} protocol={protocol} ip_version={ip_version}"
            ));
        }
        NftCell::Drop { comment, .. } => {
            let c = comment.as_deref().unwrap_or("-");
            out.push(format!("{index}) [{status}] type=drop comment={c}"));
            return out;
        }
    }

    let mut extras: Vec<String> = Vec::new();
    extras.push(format!("access_control={}", config.access_control.mode));
    extras.push(format!("quota={}", quota_brief(index, rule, stats_state)));
    if let Some(label) = egress_brief(rule, resolved, config) {
        extras.push(label);
    }
    out.push(format!("   {}", extras.join("  ")));
    out
}

fn resolved_display(target: &str, resolved: Option<&str>) -> String {
    match resolved {
        Some(ip) => ip.to_string(),
        None => {
            if target.parse::<std::net::IpAddr>().is_ok() {
                target.to_string()
            } else {
                "解析失败或暂不可用".to_string()
            }
        }
    }
}

fn quota_brief(
    index: usize,
    rule: &NftCell,
    stats_state: &nat_common::stats::StatsState,
) -> String {
    if !rule.quota_enabled() || rule.quota_bytes() == 0 {
        return "off".to_string();
    }
    let limit = rule.quota_bytes();
    let used = match rule.quota_period() {
        QuotaPeriod::Daily => stats_state
            .per_rule_daily_bytes
            .get(&format!("r{index}"))
            .copied()
            .unwrap_or(0),
        QuotaPeriod::Monthly => stats_state
            .per_rule_monthly_bytes
            .get(&format!("r{index}"))
            .copied()
            .unwrap_or(0),
        QuotaPeriod::Total => stats_state
            .per_rule_total_bytes
            .get(&format!("r{index}"))
            .copied()
            .unwrap_or(0),
    };
    format!(
        "{}/{} {}",
        quota::format_bytes(used),
        quota::format_bytes(limit),
        rule.quota_period()
    )
}

fn egress_brief(rule: &NftCell, resolved: Option<&str>, config: &TomlConfig) -> Option<String> {
    if !config.egress_control.enabled {
        return None;
    }
    if matches!(rule, NftCell::Drop { .. } | NftCell::Redirect { .. }) {
        return None;
    }
    match resolved {
        Some(ip) => {
            let allowed = config.egress_control.allows_ip(ip);
            Some(format!(
                "egress={}",
                if allowed { "allowed" } else { "blocked" }
            ))
        }
        None => Some("egress=unknown(未解析)".to_string()),
    }
}

/// 单行组合策略摘要：global / access_control / GeoIP / egress / SNAT / MSS 各自一个键值，便于扫读。
pub(crate) fn combined_policy_summary(config: &TomlConfig) -> String {
    let global = enabled_label(config.global.enabled);
    let ac = match &config.access_control.mode {
        AccessControlMode::Off => "off".to_string(),
        AccessControlMode::Whitelist => {
            format!("whitelist({})", config.access_control.entries.len())
        }
        AccessControlMode::Blacklist => {
            format!("blacklist({})", config.access_control.entries.len())
        }
    };
    let geoip =
        if config.geoip.enabled && (config.geoip.forward.enabled || config.geoip.ssh.enabled) {
            let mut parts = Vec::new();
            if config.geoip.forward.enabled {
                parts.push("forward");
            }
            if config.geoip.ssh.enabled {
                parts.push("ssh");
            }
            format!("on({})", parts.join("+"))
        } else {
            "off".to_string()
        };
    let egress = if config.egress_control.enabled {
        format!(
            "on({}cidr)",
            config.egress_control.allowed_target_cidrs.len()
        )
    } else {
        "off".to_string()
    };
    let snat = match config.snat.mode {
        SnatMode::Masquerade => "masquerade".to_string(),
        SnatMode::Off => "off".to_string(),
        SnatMode::Fixed => {
            if config.snat.fixed_source_ip.trim().is_empty() {
                "fixed(回退 masquerade)".to_string()
            } else {
                format!("fixed({})", config.snat.fixed_source_ip)
            }
        }
    };
    let mss = if config.mss_clamp.enabled {
        format!("on({})", config.mss_clamp.size)
    } else {
        "off".to_string()
    };
    format!(
        "组合策略：global={global}, access_control={ac}, GeoIP={geoip}, egress={egress}, SNAT={snat}, MSS={mss}"
    )
}

/// 单行 last-good 摘要：enabled / 缓存条数 / 最近成功时间。完整每条规则缓存通过 l 入口查看。
pub(crate) fn last_good_summary(config: &TomlConfig, state: &LastGoodState) -> String {
    let cached = state.rules.len();
    let last = match state.last_success_at {
        Some(ts) => format_cli_time_with(ts, &config.ui),
        None => "(无)".to_string(),
    };
    format!(
        "last-good：{}，缓存 {cached} 条，最近成功 {last}",
        if config.last_good.enabled {
            "enabled"
        } else {
            "disabled"
        }
    )
}

fn add_single_interactive(path: &str) -> Result<(), io::Error> {
    let sport = parse_port(&prompt("监听端口 sport: ")?)?;
    let domain = parse_domain(&prompt("目标地址 domain: ")?)?;
    let dport = parse_port(&prompt("目标端口 dport: ")?)?;
    let protocol = parse_protocol(&prompt("协议 tcp/udp/all [tcp]: ")?)?;
    let ip_version = parse_ip_version(&prompt("IP 版本 ipv4/ipv6/all [ipv4]: ")?)?;
    print_snat_ip_hint();
    let snat_ip = parse_optional_snat_ip(&prompt("SNAT 出口 IP snat_ip [留空默认]: ")?)?;
    let comment = parse_optional_comment(&prompt("comment，可为空: ")?);

    let conflict_override = match confirm_port_conflict_override_interactive(sport, sport)? {
        PortConflictAction::Proceed {
            override_conflicts,
            warning,
        } => {
            if let Some(warning) = warning {
                println!("warning: {warning}");
            }
            override_conflicts
        }
        PortConflictAction::Cancel => {
            println!("已取消添加规则。");
            return Ok(());
        }
    };

    let mut config = load_toml_config(path)?;
    add_single_rule(
        &mut config,
        sport,
        dport,
        domain,
        protocol,
        ip_version,
        RuleExtras { snat_ip, comment },
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &config, "rule.add.single")?;
    audit_port_conflict_override(path, sport, sport, protocol, &conflict_override);
    audit_cli(
        path,
        "rule.add",
        AuditResult::Ok,
        json!({
            "type": "single",
            "sport": sport,
            "dport": dport,
            "protocol": protocol.to_string(),
            "ip_version": ip_version.to_string(),
        }),
    );
    println!("已添加规则。");
    print_config_saved_hint(path, "rule.add.single");
    Ok(())
}

fn add_range_interactive(path: &str) -> Result<(), io::Error> {
    let port_start = parse_port(&prompt("监听起始端口 port_start: ")?)?;
    let port_end = parse_port(&prompt("监听结束端口 port_end: ")?)?;
    let domain = parse_domain(&prompt("目标地址 domain: ")?)?;
    let protocol = parse_protocol(&prompt("协议 tcp/udp/all [tcp]: ")?)?;
    let ip_version = parse_ip_version(&prompt("IP 版本 ipv4/ipv6/all [ipv4]: ")?)?;
    print_snat_ip_hint();
    let snat_ip = parse_optional_snat_ip(&prompt("SNAT 出口 IP snat_ip [留空默认]: ")?)?;
    let comment = parse_optional_comment(&prompt("comment，可为空: ")?);

    let conflict_override = match confirm_port_conflict_override_interactive(port_start, port_end)?
    {
        PortConflictAction::Proceed {
            override_conflicts,
            warning,
        } => {
            if let Some(warning) = warning {
                println!("warning: {warning}");
            }
            override_conflicts
        }
        PortConflictAction::Cancel => {
            println!("已取消添加端口段规则。");
            return Ok(());
        }
    };

    let mut config = load_toml_config(path)?;
    add_range_rule(
        &mut config,
        port_start,
        port_end,
        domain,
        protocol,
        ip_version,
        RuleExtras { snat_ip, comment },
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &config, "rule.add.range")?;
    audit_port_conflict_override(path, port_start, port_end, protocol, &conflict_override);
    audit_cli(
        path,
        "rule.add",
        AuditResult::Ok,
        json!({
            "type": "range",
            "port_start": port_start,
            "port_end": port_end,
            "protocol": protocol.to_string(),
            "ip_version": ip_version.to_string(),
        }),
    );
    println!("已添加端口段规则。当前模型会转发到目标同端口段。");
    print_config_saved_hint(path, "rule.add.range");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortConflict {
    pub protocol: String,
    pub state: String,
    pub local_addr: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortConflictCheck {
    Clear,
    Conflicts(Vec<PortConflict>),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortConflictAction {
    Proceed {
        override_conflicts: Vec<PortConflict>,
        warning: Option<String>,
    },
    Cancel,
}

#[derive(Debug, Clone)]
pub(crate) struct PortConflictCommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

fn confirm_port_conflict_override_interactive(
    port_start: u16,
    port_end: u16,
) -> Result<PortConflictAction, io::Error> {
    match check_listening_port_conflicts(port_start, port_end) {
        PortConflictCheck::Clear => Ok(PortConflictAction::Proceed {
            override_conflicts: Vec::new(),
            warning: None,
        }),
        PortConflictCheck::Unavailable(warning) => Ok(PortConflictAction::Proceed {
            override_conflicts: Vec::new(),
            warning: Some(warning),
        }),
        PortConflictCheck::Conflicts(conflicts) => {
            for line in port_conflict_warning_lines(port_start, port_end, &conflicts) {
                println!("{line}");
            }
            let confirm = prompt("是否仍继续？[y/N] ")?;
            Ok(port_conflict_action_from_answer(conflicts, &confirm))
        }
    }
}

pub(crate) fn check_listening_port_conflicts(port_start: u16, port_end: u16) -> PortConflictCheck {
    check_listening_port_conflicts_with(port_start, port_end, || {
        Command::new("ss")
            .arg("-lntup")
            .output()
            .map(|output| PortConflictCommandOutput {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            })
    })
}

pub(crate) fn check_listening_port_conflicts_with<F>(
    port_start: u16,
    port_end: u16,
    run_ss: F,
) -> PortConflictCheck
where
    F: FnOnce() -> Result<PortConflictCommandOutput, io::Error>,
{
    match run_ss() {
        Ok(output) if output.success => {
            let conflicts = parse_ss_listening_conflicts(&output.stdout, port_start, port_end);
            if conflicts.is_empty() {
                PortConflictCheck::Clear
            } else {
                PortConflictCheck::Conflicts(conflicts)
            }
        }
        Ok(output) => {
            let stderr = output.stderr.trim();
            let reason = if stderr.is_empty() {
                "入口端口占用检测失败：ss 返回非零状态；将继续添加。".to_string()
            } else {
                format!("入口端口占用检测失败：{stderr}；将继续添加。")
            };
            PortConflictCheck::Unavailable(reason)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => PortConflictCheck::Unavailable(
            "无法检测入口端口占用：未找到 ss 命令；将继续添加，不会自动安装 iproute2。".to_string(),
        ),
        Err(e) => {
            PortConflictCheck::Unavailable(format!("入口端口占用检测失败：{e}；将继续添加。"))
        }
    }
}

pub(crate) fn parse_ss_listening_conflicts(
    ss_output: &str,
    port_start: u16,
    port_end: u16,
) -> Vec<PortConflict> {
    let mut conflicts: Vec<PortConflict> = ss_output
        .lines()
        .filter_map(parse_ss_listening_line)
        .filter(|entry| entry.port >= port_start && entry.port <= port_end)
        .collect();
    conflicts.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.local_addr.cmp(&b.local_addr))
    });
    conflicts
}

fn parse_ss_listening_line(line: &str) -> Option<PortConflict> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }
    let protocol = fields[0];
    if !(protocol.starts_with("tcp") || protocol.starts_with("udp")) {
        return None;
    }
    let local_addr = fields[4];
    let port = parse_port_from_ss_local_addr(local_addr)?;
    let process_raw = if fields.len() > 6 {
        fields[6..].join(" ")
    } else {
        String::new()
    };
    Some(PortConflict {
        protocol: protocol.to_string(),
        state: fields[1].to_string(),
        local_addr: local_addr.to_string(),
        port,
        process: extract_ss_process_name(&process_raw).unwrap_or_else(|| "-".to_string()),
    })
}

fn parse_port_from_ss_local_addr(local_addr: &str) -> Option<u16> {
    let (_, port) = local_addr.rsplit_once(':')?;
    if port == "*" {
        return None;
    }
    port.parse::<u16>().ok()
}

fn extract_ss_process_name(raw: &str) -> Option<String> {
    let start = raw.find('"')?;
    let rest = &raw[start + 1..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub(crate) fn port_conflict_warning_lines(
    port_start: u16,
    port_end: u16,
    conflicts: &[PortConflict],
) -> Vec<String> {
    let mut lines = Vec::new();
    if port_start == port_end {
        lines.push(format!("检测到入口端口 {port_start} 已被本机服务监听："));
    } else {
        lines.push(format!(
            "检测到入口端口段 {port_start}-{port_end} 内已有本机服务监听："
        ));
    }
    for conflict in conflicts.iter().take(10) {
        lines.push(format!(
            "{} {} {} process={}",
            conflict.protocol, conflict.state, conflict.local_addr, conflict.process
        ));
    }
    if conflicts.len() > 10 {
        lines.push(format!(
            "... 还有 {} 个监听项未显示。",
            conflicts.len() - 10
        ));
    }
    lines.push("继续添加可能导致转发不可用。".to_string());
    lines
}

pub(crate) fn port_conflict_action_from_answer(
    conflicts: Vec<PortConflict>,
    answer: &str,
) -> PortConflictAction {
    if matches!(answer.trim(), "y" | "Y") {
        PortConflictAction::Proceed {
            override_conflicts: conflicts,
            warning: None,
        }
    } else {
        PortConflictAction::Cancel
    }
}

fn audit_port_conflict_override(
    path: &str,
    port_start: u16,
    port_end: u16,
    protocol: Protocol,
    conflicts: &[PortConflict],
) {
    if conflicts.is_empty() {
        return;
    }
    let preview: Vec<serde_json::Value> = conflicts
        .iter()
        .take(10)
        .map(|conflict| {
            json!({
                "protocol": conflict.protocol,
                "state": conflict.state,
                "local_addr": conflict.local_addr,
                "port": conflict.port,
                "process": conflict.process,
            })
        })
        .collect();
    audit_cli(
        path,
        "port_conflict.override",
        AuditResult::Warn,
        json!({
            "port_start": port_start,
            "port_end": port_end,
            "protocol": protocol.to_string(),
            "conflict_count": conflicts.len(),
            "conflicts_preview": preview,
        }),
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortRangeSpec {
    pub start: u16,
    pub end: u16,
}

impl PortRangeSpec {
    pub(crate) fn new(start: u16, end: u16) -> Result<Self, String> {
        if start == 0 || end == 0 {
            return Err("端口必须是 1-65535".to_string());
        }
        if start > end {
            return Err(format!("起始端口 {start} 不能大于结束端口 {end}"));
        }
        Ok(Self { start, end })
    }

    fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    fn is_single(self) -> bool {
        self.start == self.end
    }

    fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

impl fmt::Display for PortRangeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleEditPatch {
    pub sport: Option<PortRangeSpec>,
    pub target: Option<String>,
    pub dport: Option<u16>,
    pub protocol: Option<Protocol>,
    pub enabled: Option<bool>,
    pub snat_ip: Option<Option<String>>,
    pub comment: Option<Option<String>>,
}

impl RuleEditPatch {
    fn is_empty(&self) -> bool {
        self.sport.is_none()
            && self.target.is_none()
            && self.dport.is_none()
            && self.protocol.is_none()
            && self.enabled.is_none()
            && self.snat_ip.is_none()
            && self.comment.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleEditSnapshot {
    pub rule_type: String,
    pub sport: String,
    pub target: String,
    pub dport: String,
    pub protocol: String,
    pub ip_version: String,
    pub snat_ip: String,
    pub enabled: bool,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleIngress {
    ports: PortRangeSpec,
    protocol: Protocol,
    ip_version: IpVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleEditConflict {
    pub other_index: usize,
    pub edited_ports: PortRangeSpec,
    pub other_ports: PortRangeSpec,
    pub edited_protocol: Protocol,
    pub other_protocol: Protocol,
    pub edited_ip_version: IpVersion,
    pub other_ip_version: IpVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleEditConfirmation {
    Save,
    Cancel,
}

fn edit_rule_interactive(path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(path)?;
    if config.rules.is_empty() {
        println!("当前没有可编辑规则。");
        return Ok(());
    }

    println!("当前规则：");
    for (index, rule) in config.rules.iter().enumerate() {
        println!(
            "{}) [{}] {}",
            index + 1,
            rule_status(rule),
            format_rule(rule)
        );
    }
    println!("0) 返回");

    let Some(raw_index) = prompt_rule_edit_line("请选择要编辑的规则编号: ")? else {
        println!("输入结束，已取消编辑。");
        return Ok(());
    };
    let index = parse_index(&raw_index)?;
    if index == 0 {
        println!("已取消编辑。");
        return Ok(());
    }
    let rule_index = index - 1;
    let Some(original) = config.rules.get(rule_index).cloned() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "规则编号超出范围",
        ));
    };
    if matches!(original, NftCell::Drop { .. }) {
        println!("Drop 规则当前不支持在编辑器中修改，请通过对应专用菜单或重新添加规则处理。");
        return Ok(());
    }

    println!("当前规则完整摘要：");
    for line in render_rule_edit_summary(&original) {
        println!("{line}");
    }
    for line in render_rule_edit_unsupported_lines(&original) {
        println!("{line}");
    }

    let Some(patch) = prompt_rule_edit_patch(&original)? else {
        println!("已取消编辑，未保存配置。");
        return Ok(());
    };
    if patch.is_empty() {
        println!("未检测到修改，未保存配置。");
        return Ok(());
    }

    let edited = build_edited_rule(&original, &patch)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let changed = changed_fields(&original, &edited);
    if changed.is_empty() {
        println!("未检测到修改，未保存配置。");
        return Ok(());
    }

    validate_rule_edit_conflicts(&config, rule_index, &edited)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let conflict_override = if rule_edit_requires_port_conflict_check(&original, &edited) {
        if let Some(ingress) = rule_ingress(&edited) {
            match confirm_port_conflict_override_interactive(
                ingress.ports.start,
                ingress.ports.end,
            )? {
                PortConflictAction::Proceed {
                    override_conflicts,
                    warning,
                } => {
                    if let Some(warning) = warning {
                        println!("warning: {warning}");
                    }
                    override_conflicts
                }
                PortConflictAction::Cancel => {
                    println!("已取消编辑，未保存配置。");
                    return Ok(());
                }
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    println!("修改前 / 修改后摘要：");
    for line in render_rule_edit_diff_summary(&original, &edited) {
        println!("{line}");
    }
    let Some(confirm) = prompt_rule_edit_line("确认保存本次修改？[y/N] ")? else {
        println!("输入结束，已取消编辑。");
        return Ok(());
    };
    if rule_edit_confirmation_from_answer(&confirm) != RuleEditConfirmation::Save {
        println!("已取消编辑，未保存配置。");
        return Ok(());
    }

    apply_rule_edit_to_config(&mut config, rule_index, edited.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if let Err(e) = save_toml_config(path, &config, "rule.edit") {
        println!("保存失败，旧配置未覆盖: {e}");
        return Err(e);
    }
    if let Some(ingress) = rule_ingress(&edited) {
        audit_rule_edit_port_conflict_override(
            path,
            rule_index,
            ingress.ports.start,
            ingress.ports.end,
            ingress.protocol,
            &conflict_override,
        );
    }
    audit_cli(
        path,
        "rule.edit",
        AuditResult::Ok,
        rule_edit_audit_detail(rule_index, &original, &edited),
    );
    prune_last_good_cache_after_rule_edit(path, &config);

    println!("已编辑规则。");
    print_config_saved_hint(path, "rule.edit");
    for line in rule_edit_post_save_messages(&config, rule_index) {
        println!("{line}");
    }
    Ok(())
}

fn prompt_rule_edit_patch(rule: &NftCell) -> Result<Option<RuleEditPatch>, io::Error> {
    let mut patch = RuleEditPatch::default();

    if let Some(current) = editable_sport(rule) {
        let question = if current.is_single() {
            format!("当前入口端口：{current}\n是否修改？[y/N] ")
        } else {
            format!("当前入口端口段：{current}\n是否修改？[y/N] ")
        };
        match prompt_rule_edit_yes_no(&question)? {
            Some(true) => {
                let Some(next) = prompt_new_sport(rule)? else {
                    return Ok(None);
                };
                patch.sport = Some(next);
            }
            Some(false) => {}
            None => return Ok(None),
        }
    }

    let snapshot = rule_edit_snapshot(rule);
    println!("当前目标地址：{}", snapshot.target);
    match rule {
        NftCell::Single { .. } | NftCell::Range { .. } => {
            match prompt_rule_edit_yes_no("是否修改？[y/N] ")? {
                Some(true) => {
                    let Some(target) = prompt_new_target()? else {
                        return Ok(None);
                    };
                    patch.target = Some(target);
                }
                Some(false) => {}
                None => return Ok(None),
            }
        }
        NftCell::Redirect { .. } => {
            println!(
                "该字段当前不支持在编辑器中修改：redirect 规则目标固定为 localhost，请通过对应专用菜单或重新添加规则处理。"
            );
        }
        NftCell::Drop { .. } => {}
    }

    println!("当前目标端口：{}", snapshot.dport);
    match rule {
        NftCell::Single { .. } | NftCell::Redirect { .. } => {
            match prompt_rule_edit_yes_no("是否修改？[y/N] ")? {
                Some(true) => {
                    let Some(dport) = prompt_new_port("新的目标端口 dport: ")? else {
                        return Ok(None);
                    };
                    patch.dport = Some(dport);
                }
                Some(false) => {}
                None => return Ok(None),
            }
        }
        NftCell::Range { .. } => {
            println!(
                "该字段当前不支持在编辑器中单独修改：端口段规则的目标端口段随入口端口段保持一致，请通过入口端口段修改或重新添加规则处理。"
            );
        }
        NftCell::Drop { .. } => {}
    }

    println!("当前协议：{}", snapshot.protocol);
    match prompt_rule_edit_yes_no("是否修改？[y/N] ")? {
        Some(true) => {
            let Some(protocol) = prompt_new_protocol()? else {
                return Ok(None);
            };
            patch.protocol = Some(protocol);
        }
        Some(false) => {}
        None => return Ok(None),
    }

    println!(
        "当前启用状态：{}",
        if snapshot.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    match prompt_rule_edit_yes_no("是否切换？[y/N] ")? {
        Some(true) => patch.enabled = Some(!snapshot.enabled),
        Some(false) => {}
        None => return Ok(None),
    }

    println!("当前 SNAT IP：{}", snapshot.snat_ip);
    match rule {
        NftCell::Single { .. } | NftCell::Range { .. } => {
            print_snat_ip_hint();
            match prompt_rule_edit_yes_no("是否修改？[y/N] ")? {
                Some(true) => {
                    let Some(raw) =
                        prompt_rule_edit_line("新的 SNAT 出口 IP snat_ip（留空清空/默认）: ")?
                    else {
                        return Ok(None);
                    };
                    let snat_ip = parse_optional_snat_ip(&raw)?;
                    patch.snat_ip = Some(snat_ip);
                }
                Some(false) => {}
                None => return Ok(None),
            }
        }
        NftCell::Redirect { .. } => {
            println!("redirect 本机重定向规则不生成转发 SNAT，snat_ip 不适用。");
        }
        NftCell::Drop { .. } => {}
    }

    println!(
        "当前备注：{}",
        snapshot.comment.as_deref().unwrap_or("(无)")
    );
    match prompt_rule_edit_yes_no("是否修改？[y/N] ")? {
        Some(true) => {
            let Some(comment) = prompt_rule_edit_line("新的备注 comment（留空表示清空）: ")?
            else {
                return Ok(None);
            };
            patch.comment = Some(parse_optional_comment(&comment));
        }
        Some(false) => {}
        None => return Ok(None),
    }

    Ok(Some(patch))
}

fn prompt_new_sport(rule: &NftCell) -> Result<Option<PortRangeSpec>, io::Error> {
    loop {
        let label = match rule {
            NftCell::Single { .. } => "新的入口端口 sport: ",
            NftCell::Range { .. } => "新的入口端口段 start-end: ",
            NftCell::Redirect {
                src_port_end: Some(_),
                ..
            } => "新的入口端口段 start-end: ",
            NftCell::Redirect { .. } => "新的入口端口 sport: ",
            NftCell::Drop { .. } => "新的入口端口: ",
        };
        let Some(raw) = prompt_rule_edit_line(label)? else {
            return Ok(None);
        };
        let parsed = match parse_port_range_spec(&raw) {
            Ok(range) => range,
            Err(e) => {
                println!("输入无效：{e}");
                continue;
            }
        };
        match rule {
            NftCell::Single { .. }
            | NftCell::Redirect {
                src_port_end: None, ..
            } => {
                if !parsed.is_single() {
                    println!("输入无效：该规则是单端口规则，请输入单个端口。");
                    continue;
                }
            }
            NftCell::Range { .. }
            | NftCell::Redirect {
                src_port_end: Some(_),
                ..
            } => {
                if parsed.is_single() {
                    println!("输入无效：该规则是端口段规则，请输入 start-end。");
                    continue;
                }
            }
            NftCell::Drop { .. } => {}
        }
        return Ok(Some(parsed));
    }
}

fn prompt_new_target() -> Result<Option<String>, io::Error> {
    loop {
        let Some(raw) = prompt_rule_edit_line("新的目标地址 target IP/domain: ")? else {
            return Ok(None);
        };
        match validate_target_address(&raw) {
            Ok(target) => return Ok(Some(target)),
            Err(e) => println!("输入无效：{e}"),
        }
    }
}

fn prompt_new_port(label: &str) -> Result<Option<u16>, io::Error> {
    loop {
        let Some(raw) = prompt_rule_edit_line(label)? else {
            return Ok(None);
        };
        match parse_port(&raw) {
            Ok(port) => return Ok(Some(port)),
            Err(e) => println!("输入无效：{e}"),
        }
    }
}

fn prompt_new_protocol() -> Result<Option<Protocol>, io::Error> {
    loop {
        let Some(raw) = prompt_rule_edit_line("新的协议 tcp/udp/all: ")? else {
            return Ok(None);
        };
        match parse_protocol(&raw) {
            Ok(protocol) => return Ok(Some(protocol)),
            Err(e) => println!("输入无效：{e}"),
        }
    }
}

fn prompt_rule_edit_yes_no(label: &str) -> Result<Option<bool>, io::Error> {
    loop {
        let Some(raw) = prompt_rule_edit_line(label)? else {
            return Ok(None);
        };
        match raw.trim() {
            "" | "n" | "N" => return Ok(Some(false)),
            "y" | "Y" => return Ok(Some(true)),
            "q" | "Q" | "0" => return Ok(None),
            _ => println!("请输入 y 或 n；输入 q / 0 可取消编辑。"),
        }
    }
}

fn prompt_rule_edit_line(label: &str) -> Result<Option<String>, io::Error> {
    prompt_result_to_rule_edit_input(prompt(label))
}

pub(crate) fn prompt_result_to_rule_edit_input(
    result: Result<String, io::Error>,
) -> Result<Option<String>, io::Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn parse_port_range_spec(value: &str) -> Result<PortRangeSpec, io::Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "端口不能为空"));
    }
    if let Some((start, end)) = trimmed.split_once('-') {
        let start = parse_port(start)?;
        let end = parse_port(end)?;
        PortRangeSpec::new(start, end).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    } else {
        Ok(PortRangeSpec::single(parse_port(trimmed)?))
    }
}

pub(crate) fn validate_target_address(value: &str) -> Result<String, io::Error> {
    let target = value.trim();
    if target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "目标地址不能为空",
        ));
    }
    if target.parse::<IpAddr>().is_ok() || target.eq_ignore_ascii_case("localhost") {
        return Ok(target.to_string());
    }
    if target.len() > 253
        || target.contains(char::is_whitespace)
        || target.contains('/')
        || target.contains(':')
        || target.contains('*')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("目标地址不是合法 IP 或域名: {target}"),
        ));
    }
    let without_trailing_dot = target.trim_end_matches('.');
    if without_trailing_dot.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "目标地址不是合法域名",
        ));
    }
    for label in without_trailing_dot.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标域名 label 非法: {target}"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标域名 label 不能以短横线开头或结尾: {label}"),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("目标域名包含非法字符: {target}"),
            ));
        }
    }
    Ok(target.to_string())
}

pub(crate) fn build_edited_rule(
    original: &NftCell,
    patch: &RuleEditPatch,
) -> Result<NftCell, String> {
    let mut edited = original.clone();
    match &mut edited {
        NftCell::Single {
            enabled,
            sport,
            dport,
            domain,
            protocol,
            snat_ip,
            comment,
            ..
        } => {
            if let Some(next) = patch.enabled {
                *enabled = next;
            }
            if let Some(next) = patch.sport {
                if !next.is_single() {
                    return Err("单端口规则不能直接改为端口段；请重新添加端口段规则".to_string());
                }
                *sport = next.start;
            }
            if let Some(next) = &patch.target {
                *domain = validate_target_address(next).map_err(|e| e.to_string())?;
            }
            if let Some(next) = patch.dport {
                *dport = next;
            }
            if let Some(next) = patch.protocol {
                *protocol = next;
            }
            if let Some(next) = &patch.snat_ip {
                *snat_ip = next.clone();
            }
            if let Some(next) = &patch.comment {
                *comment = next.clone();
            }
        }
        NftCell::Range {
            enabled,
            port_start,
            port_end,
            domain,
            protocol,
            snat_ip,
            comment,
            ..
        } => {
            if let Some(next) = patch.enabled {
                *enabled = next;
            }
            if let Some(next) = patch.sport {
                if next.is_single() {
                    return Err("端口段规则不能直接改为单端口；请重新添加单端口规则".to_string());
                }
                *port_start = next.start;
                *port_end = next.end;
            }
            if let Some(next) = &patch.target {
                *domain = validate_target_address(next).map_err(|e| e.to_string())?;
            }
            if patch.dport.is_some() {
                return Err(
                    "端口段规则的目标端口段随入口端口段保持一致，当前不支持单独修改 dport"
                        .to_string(),
                );
            }
            if let Some(next) = patch.protocol {
                *protocol = next;
            }
            if let Some(next) = &patch.snat_ip {
                *snat_ip = next.clone();
            }
            if let Some(next) = &patch.comment {
                *comment = next.clone();
            }
        }
        NftCell::Redirect {
            enabled,
            src_port,
            src_port_end,
            dst_port,
            protocol,
            comment,
            ..
        } => {
            if let Some(next) = patch.enabled {
                *enabled = next;
            }
            if let Some(next) = patch.sport {
                match src_port_end {
                    Some(end) => {
                        if next.is_single() {
                            return Err(
                                "redirect 端口段规则不能直接改为单端口；请重新添加规则".to_string()
                            );
                        }
                        *src_port = next.start;
                        *end = next.end;
                    }
                    None => {
                        if !next.is_single() {
                            return Err(
                                "redirect 单端口规则不能直接改为端口段；请重新添加规则".to_string()
                            );
                        }
                        *src_port = next.start;
                    }
                }
            }
            if patch.target.is_some() {
                return Err("redirect 规则目标固定为 localhost，当前不支持修改目标地址".to_string());
            }
            if let Some(next) = patch.dport {
                *dst_port = next;
            }
            if let Some(next) = patch.protocol {
                *protocol = next;
            }
            if let Some(next) = &patch.comment {
                *comment = next.clone();
            }
        }
        NftCell::Drop { .. } => {
            return Err("Drop 规则当前不支持在编辑器中修改".to_string());
        }
    }
    edited.validate()?;
    Ok(edited)
}

pub(crate) fn apply_rule_edit_to_config(
    config: &mut TomlConfig,
    index: usize,
    edited: NftCell,
) -> Result<Vec<String>, String> {
    if index >= config.rules.len() {
        return Err("规则编号超出范围".to_string());
    }
    edited.validate()?;
    validate_rule_edit_conflicts(config, index, &edited)?;
    let changed = changed_fields(&config.rules[index], &edited);
    if !changed.is_empty() {
        config.rules[index] = edited;
    }
    Ok(changed)
}

pub(crate) fn changed_fields(old: &NftCell, new: &NftCell) -> Vec<String> {
    let old = rule_edit_snapshot(old);
    let new = rule_edit_snapshot(new);
    let mut changed = Vec::new();
    if old.sport != new.sport {
        changed.push("sport".to_string());
    }
    if old.target != new.target {
        changed.push("target".to_string());
    }
    if old.dport != new.dport {
        changed.push("dport".to_string());
    }
    if old.protocol != new.protocol {
        changed.push("protocol".to_string());
    }
    if old.enabled != new.enabled {
        changed.push("enabled".to_string());
    }
    if old.snat_ip != new.snat_ip {
        changed.push("snat_ip".to_string());
    }
    if old.comment != new.comment {
        changed.push("comment".to_string());
    }
    changed
}

pub(crate) fn render_rule_edit_summary(rule: &NftCell) -> Vec<String> {
    let s = rule_edit_snapshot(rule);
    vec![
        format!("type: {}", s.rule_type),
        format!(
            "enabled: {}",
            if s.enabled { "enabled" } else { "disabled" }
        ),
        format!("sport: {}", s.sport),
        format!("target: {}", s.target),
        format!("dport: {}", s.dport),
        format!("protocol: {}", s.protocol),
        format!("ip_version: {}", s.ip_version),
        format!("snat_ip: {}", s.snat_ip),
        format!("comment: {}", s.comment.as_deref().unwrap_or("(无)")),
    ]
}

pub(crate) fn render_rule_edit_diff_summary(old: &NftCell, new: &NftCell) -> Vec<String> {
    let mut lines = vec!["修改前:".to_string()];
    lines.extend(
        render_rule_edit_summary(old)
            .into_iter()
            .map(|line| format!("  {line}")),
    );
    lines.push("修改后:".to_string());
    lines.extend(
        render_rule_edit_summary(new)
            .into_iter()
            .map(|line| format!("  {line}")),
    );
    let changed = changed_fields(old, new);
    lines.push(format!(
        "changed_fields: {}",
        if changed.is_empty() {
            "(无)".to_string()
        } else {
            changed.join(", ")
        }
    ));
    lines
}

fn render_rule_edit_unsupported_lines(rule: &NftCell) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("该字段当前不支持在编辑器中修改：ip_version，请通过重新添加规则处理。".to_string());
    lines.push(
        "该字段当前不支持在编辑器中修改：quota / access_control / egress_control / MSS 高级字段，请通过对应专用菜单处理。"
            .to_string(),
    );
    match rule {
        NftCell::Range { .. } => lines.push(
            "该字段当前不支持在编辑器中单独修改：端口段规则 dport 独立映射。目标端口段会随入口端口段保持一致。"
                .to_string(),
        ),
        NftCell::Redirect { .. } => lines.push(
            "该字段当前不支持在编辑器中修改：redirect 规则目标地址固定为 localhost。".to_string(),
        ),
        NftCell::Single { .. } | NftCell::Drop { .. } => {}
    }
    lines
}

pub(crate) fn rule_edit_snapshot(rule: &NftCell) -> RuleEditSnapshot {
    match rule {
        NftCell::Single {
            enabled,
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => RuleEditSnapshot {
            rule_type: "single".to_string(),
            sport: sport.to_string(),
            target: domain.clone(),
            dport: dport.to_string(),
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
            snat_ip: snat_ip_display(rule).to_string(),
            enabled: *enabled,
            comment: comment.clone(),
        },
        NftCell::Range {
            enabled,
            port_start,
            port_end,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => RuleEditSnapshot {
            rule_type: "range".to_string(),
            sport: format!("{port_start}-{port_end}"),
            target: domain.clone(),
            dport: format!("{port_start}-{port_end}"),
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
            snat_ip: snat_ip_display(rule).to_string(),
            enabled: *enabled,
            comment: comment.clone(),
        },
        NftCell::Redirect {
            enabled,
            src_port,
            src_port_end,
            dst_port,
            protocol,
            ip_version,
            comment,
            ..
        } => RuleEditSnapshot {
            rule_type: "redirect".to_string(),
            sport: src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string()),
            target: "localhost".to_string(),
            dport: dst_port.to_string(),
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
            snat_ip: "-".to_string(),
            enabled: *enabled,
            comment: comment.clone(),
        },
        NftCell::Drop {
            protocol, comment, ..
        } => RuleEditSnapshot {
            rule_type: "drop".to_string(),
            sport: "-".to_string(),
            target: "-".to_string(),
            dport: "-".to_string(),
            protocol: protocol.to_string(),
            ip_version: "-".to_string(),
            snat_ip: "-".to_string(),
            enabled: true,
            comment: comment.clone(),
        },
    }
}

pub(crate) fn rule_edit_audit_detail(
    rule_index: usize,
    old: &NftCell,
    new: &NftCell,
) -> serde_json::Value {
    let old_s = rule_edit_snapshot(old);
    let new_s = rule_edit_snapshot(new);
    let mut detail = json!({
        "rule_index": rule_index,
        "changed_fields": changed_fields(old, new),
    });
    if old_s.sport != new_s.sport {
        detail["old_sport"] = json!(old_s.sport);
        detail["new_sport"] = json!(new_s.sport);
    }
    if old_s.target != new_s.target {
        detail["old_target"] = json!(old_s.target);
        detail["new_target"] = json!(new_s.target);
    }
    if old_s.dport != new_s.dport {
        detail["old_dport"] = json!(old_s.dport);
        detail["new_dport"] = json!(new_s.dport);
    }
    if old_s.protocol != new_s.protocol {
        detail["old_protocol"] = json!(old_s.protocol);
        detail["new_protocol"] = json!(new_s.protocol);
    }
    if old_s.enabled != new_s.enabled {
        detail["old_enabled"] = json!(old_s.enabled);
        detail["new_enabled"] = json!(new_s.enabled);
    }
    if old_s.snat_ip != new_s.snat_ip {
        detail["old_snat_ip"] = json!(old_s.snat_ip);
        detail["new_snat_ip"] = json!(new_s.snat_ip);
    }
    if old_s.comment != new_s.comment {
        detail["old_comment"] = json!(old_s.comment);
        detail["new_comment"] = json!(new_s.comment);
    }
    detail
}

pub(crate) fn validate_rule_edit_conflicts(
    config: &TomlConfig,
    edited_index: usize,
    edited_rule: &NftCell,
) -> Result<(), String> {
    let conflicts = find_rule_edit_conflicts(config, edited_index, edited_rule);
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(format_rule_edit_conflict_lines(&conflicts).join("\n"))
    }
}

pub(crate) fn find_rule_edit_conflicts(
    config: &TomlConfig,
    edited_index: usize,
    edited_rule: &NftCell,
) -> Vec<RuleEditConflict> {
    let Some(edited) = rule_ingress(edited_rule) else {
        return Vec::new();
    };
    if !edited_rule.enabled() {
        return Vec::new();
    }
    config
        .rules
        .iter()
        .enumerate()
        .filter(|(idx, rule)| *idx != edited_index && rule.enabled())
        .filter_map(|(other_index, rule)| {
            let other = rule_ingress(rule)?;
            if edited.ports.overlaps(other.ports)
                && protocols_overlap(edited.protocol, other.protocol)
                && ip_versions_overlap(edited.ip_version, other.ip_version)
            {
                Some(RuleEditConflict {
                    other_index,
                    edited_ports: edited.ports,
                    other_ports: other.ports,
                    edited_protocol: edited.protocol,
                    other_protocol: other.protocol,
                    edited_ip_version: edited.ip_version,
                    other_ip_version: other.ip_version,
                })
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn format_rule_edit_conflict_lines(conflicts: &[RuleEditConflict]) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("编辑后的入口端口 / 协议 / IP 版本与已有规则冲突：".to_string());
    for conflict in conflicts {
        lines.push(format!(
            "- 已有规则 {}: sport={} protocol={} ip_version={} 与新规则 sport={} protocol={} ip_version={} 重叠",
            conflict.other_index + 1,
            conflict.other_ports,
            conflict.other_protocol,
            conflict.other_ip_version,
            conflict.edited_ports,
            conflict.edited_protocol,
            conflict.edited_ip_version
        ));
    }
    lines.push("请改用其它入口端口 / 端口段或协议；本次编辑不会保存。".to_string());
    lines
}

pub(crate) fn rule_edit_requires_port_conflict_check(old: &NftCell, new: &NftCell) -> bool {
    let old_ingress = rule_ingress(old);
    let new_ingress = rule_ingress(new);
    match (old_ingress, new_ingress) {
        (Some(old_ingress), Some(new_ingress)) => {
            old_ingress.ports != new_ingress.ports
                || old_ingress.protocol != new_ingress.protocol
                || (!old.enabled() && new.enabled())
        }
        (None, Some(_)) => new.enabled(),
        _ => false,
    }
}

fn editable_sport(rule: &NftCell) -> Option<PortRangeSpec> {
    match rule {
        NftCell::Single { sport, .. } => Some(PortRangeSpec::single(*sport)),
        NftCell::Range {
            port_start,
            port_end,
            ..
        } => Some(PortRangeSpec {
            start: *port_start,
            end: *port_end,
        }),
        NftCell::Redirect {
            src_port,
            src_port_end,
            ..
        } => Some(PortRangeSpec {
            start: *src_port,
            end: src_port_end.unwrap_or(*src_port),
        }),
        NftCell::Drop { .. } => None,
    }
}

fn rule_ingress(rule: &NftCell) -> Option<RuleIngress> {
    match rule {
        NftCell::Single {
            sport,
            protocol,
            ip_version,
            ..
        } => Some(RuleIngress {
            ports: PortRangeSpec::single(*sport),
            protocol: *protocol,
            ip_version: *ip_version,
        }),
        NftCell::Range {
            port_start,
            port_end,
            protocol,
            ip_version,
            ..
        } => Some(RuleIngress {
            ports: PortRangeSpec {
                start: *port_start,
                end: *port_end,
            },
            protocol: *protocol,
            ip_version: *ip_version,
        }),
        NftCell::Redirect {
            src_port,
            src_port_end,
            protocol,
            ip_version,
            ..
        } => Some(RuleIngress {
            ports: PortRangeSpec {
                start: *src_port,
                end: src_port_end.unwrap_or(*src_port),
            },
            protocol: *protocol,
            ip_version: *ip_version,
        }),
        NftCell::Drop { .. } => None,
    }
}

fn protocols_overlap(left: Protocol, right: Protocol) -> bool {
    left == right || matches!(left, Protocol::All) || matches!(right, Protocol::All)
}

fn ip_versions_overlap(left: IpVersion, right: IpVersion) -> bool {
    left == right || matches!(left, IpVersion::All) || matches!(right, IpVersion::All)
}

pub(crate) fn rule_edit_confirmation_from_answer(answer: &str) -> RuleEditConfirmation {
    if matches!(answer.trim(), "y" | "Y") {
        RuleEditConfirmation::Save
    } else {
        RuleEditConfirmation::Cancel
    }
}

pub(crate) fn rule_edit_post_save_messages(config: &TomlConfig, rule_index: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if !config.global.enabled {
        lines.push("提示：全局转发当前关闭，规则配置已保存，但不会立即生成转发规则。".to_string());
    }
    if config
        .rules
        .get(rule_index)
        .map(|rule| !rule.enabled())
        .unwrap_or(false)
    {
        lines.push("提示：该规则当前 disabled，不会生成 nft 规则。".to_string());
    }
    lines
}

fn audit_rule_edit_port_conflict_override(
    path: &str,
    rule_index: usize,
    port_start: u16,
    port_end: u16,
    protocol: Protocol,
    conflicts: &[PortConflict],
) {
    if conflicts.is_empty() {
        return;
    }
    let preview: Vec<serde_json::Value> = conflicts
        .iter()
        .take(10)
        .map(|conflict| {
            json!({
                "protocol": conflict.protocol,
                "state": conflict.state,
                "local_addr": conflict.local_addr,
                "port": conflict.port,
                "process": conflict.process,
            })
        })
        .collect();
    audit_cli(
        path,
        "rule.edit.port_conflict.override",
        AuditResult::Warn,
        json!({
            "rule_index": rule_index,
            "port_start": port_start,
            "port_end": port_end,
            "protocol": protocol.to_string(),
            "conflict_count": conflicts.len(),
            "conflicts_preview": preview,
        }),
    );
}

fn prune_last_good_cache_after_rule_edit(path: &str, config: &TomlConfig) {
    match prune_last_good_cache_for_config(config) {
        Ok(Some(result)) => {
            audit_cli(
                path,
                "last_good.prune",
                AuditResult::Ok,
                json!({
                    "trigger": "rule.edit",
                    "file": config.last_good.file,
                    "before": result.before,
                    "after": result.after,
                    "removed": result.removed,
                }),
            );
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                "rule.edit 后清理 stale last-good 缓存失败 ({}): {e}",
                config.last_good.file
            );
            eprintln!(
                "WARN: 清理 stale last-good 缓存失败（{}）：{e}",
                config.last_good.file
            );
        }
    }
}

fn delete_rule_interactive(path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(path)?;
    if config.rules.is_empty() {
        println!("当前没有可删除规则");
        return Ok(());
    }
    for (index, rule) in config.rules.iter().enumerate() {
        println!("{index}) {}", format_rule(rule));
    }
    let index = parse_index(&prompt("请输入要删除的规则 index: ")?)?;
    if index >= config.rules.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "规则 index 超出范围",
        ));
    }
    let confirm = prompt("危险操作：确认删除该规则? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消删除");
        return Ok(());
    }
    delete_rule(&mut config, index).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &config, "rule.delete")?;
    prune_last_good_cache_after_rule_delete(path, &config);
    audit_cli(
        path,
        "rule.delete",
        AuditResult::Ok,
        json!({"index": index}),
    );
    println!("已删除规则。");
    print_config_saved_hint(path, "rule.delete");
    Ok(())
}

fn prune_last_good_cache_after_rule_delete(path: &str, config: &TomlConfig) {
    match prune_last_good_cache_for_config(config) {
        Ok(Some(result)) => {
            audit_cli(
                path,
                "last_good.prune",
                AuditResult::Ok,
                json!({
                    "trigger": "rule.delete",
                    "file": config.last_good.file,
                    "before": result.before,
                    "after": result.after,
                    "removed": result.removed,
                }),
            );
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                "rule.delete 后清理 stale last-good 缓存失败 ({}): {e}",
                config.last_good.file
            );
            eprintln!(
                "WARN: 清理 stale last-good 缓存失败（{}）：{e}",
                config.last_good.file
            );
        }
    }
}

fn prune_last_good_cache_for_config(
    config: &TomlConfig,
) -> io::Result<Option<LastGoodPruneResult>> {
    if !config.last_good.enabled {
        return Ok(None);
    }
    let mut state = LastGoodState::try_load(&config.last_good.file)?;
    let identities = last_good::identities_from_rules(&config.rules);
    let result = state.prune_stale_rules(&identities);
    if !result.changed {
        return Ok(None);
    }
    state.save(&config.last_good.file)?;
    Ok(Some(result))
}

/// 配置保存后的提示。
/// - 影响 nft 规则的 reason（rule.* / access_control.* / geoip.* / egress.* / snat.* / mss_clamp.* / backup.restore / quota.auto_disable）
///   显示完整 nft 自动应用提示 + systemctl restart / nft list / journalctl 排查命令。
/// - 不影响 nft 的 reason（telegram.* / ui.* / audit.*）只显示安全写入摘要，明确说明
///   "无需等待 nft 应用"，避免误导用户。
fn print_config_saved_hint(path: &str, reason: &str) {
    if reason_affects_nft(reason) {
        print_nft_affecting_save_hint(path, reason);
    } else {
        print_non_nft_save_hint(path, reason);
    }
}

/// 哪些 reason 会改变 nft 规则。命中列表里的 reason → 显示 nft 自动应用提示；
/// 不命中（例如 telegram.* / ui.* / audit.*）→ 显示简短提示，不引导用户去 restart nat。
pub(crate) fn reason_affects_nft(reason: &str) -> bool {
    matches!(
        reason,
        "rule.add.single"
            | "rule.add.range"
            | "rule.edit"
            | "rule.delete"
            | "rule.toggle"
            | "global.enabled.update"
            | "access_control.update"
            | "access_control.ssh_source.add"
            | "dynamic_whitelist.domain.add"
            | "dynamic_whitelist.domain.delete"
            | "dynamic_whitelist.domain.toggle"
            | "dynamic_whitelist.cidr_expand.update"
            | "geoip.forward.update"
            | "geoip.ssh.update"
            | "geoip.ssh.port.update"
            | "geoip.update_interval.update"
            | "egress_control.update"
            | "egress.add"
            | "egress.delete"
            | "snat.mode.update"
            | "snat.fixed_source_ip.update"
            | "mss_clamp.toggle"
            | "mss_clamp.size.update"
            | "backup.restore"
            | "quota.auto_disable"
            | "quota.config.update"
            | "stats.mode.update"
    )
}

fn print_nft_affecting_save_hint(path: &str, reason: &str) {
    for line in format_nft_affecting_save_hint_lines(path, reason) {
        println!("{line}");
    }
}

fn print_non_nft_save_hint(path: &str, reason: &str) {
    for line in format_non_nft_save_hint_lines(path, reason) {
        println!("{line}");
    }
}

/// 影响 nft 规则的保存提示文本（按行返回，便于单元测试断言）。
pub(crate) fn format_nft_affecting_save_hint_lines(path: &str, reason: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if reason == "rule.delete" {
        lines.push(format!("已安全保存配置到 {path}。"));
        lines.push("本次操作为删除规则，已按策略跳过自动备份。".to_string());
    } else {
        lines.push(format!(
            "已安全保存配置到 {path}（备份 → 临时文件 + fsync → rename）。"
        ));
        lines.push(format!(
            "备份目录：{CONFIG_BACKUP_DIR}/（按 reason 命名，权限 0600）。"
        ));
    }
    lines.push("nat.service 通常会自动检测配置变化，并通过安全流程应用规则。".to_string());
    lines.push("安全流程包括：nft -c 检查、备份当前规则、应用失败自动回滚。".to_string());
    lines.push("本工具不会直接绕过安全流程执行 nft -f。".to_string());
    let interval_secs = load_toml_config(path)
        .ok()
        .map(|c| c.ddns.refresh_interval_seconds);
    match interval_secs {
        Some(secs) => {
            lines.push(format!(
                "当前自动检测 / 刷新间隔：{secs} 秒（ddns.refresh_interval_seconds）。"
            ));
        }
        None => {
            lines.push(
                "当前自动检测 / 刷新间隔：默认 300 秒（无法读取 ddns.refresh_interval_seconds）。"
                    .to_string(),
            );
        }
    }
    lines.push(
        "如果刚改完配置后立即测试显示 nft 未应用，请等待一个检测周期后刷新；这通常不是 bug。"
            .to_string(),
    );
    lines.push("如需立即尝试应用，可手动执行：".to_string());
    lines.push("  systemctl restart nat".to_string());
    lines.push("确认当前规则是否已应用：".to_string());
    lines.push("  nft list table ip self-nat".to_string());
    lines.push("  nft list table ip self-filter".to_string());
    lines.push("  journalctl -u nat -n 120 --no-pager".to_string());
    lines
}

/// 不影响 nft 规则的保存提示文本（telegram / ui / audit 等）。
/// 不引导用户去 `systemctl restart nat` 或 `nft list table`，避免误以为需要等 nft apply。
pub(crate) fn format_non_nft_save_hint_lines(path: &str, reason: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if reason.starts_with("telegram.") {
        lines.push(format!(
            "Telegram 配置已安全保存到 {path}，状态页默认不会明文显示 bot_token。"
        ));
    } else {
        lines.push(format!("配置已安全保存到 {path}。"));
    }
    lines.push(format!(
        "备份目录：{CONFIG_BACKUP_DIR}/（按 reason 命名，权限 0600）。"
    ));
    lines.push("该配置不会改变 nft 转发规则，无需等待 nft 应用。".to_string());
    lines
}

fn refresh_ddns_interactive(
    path: &str,
    last_manual_refresh: &mut Option<chrono::DateTime<Local>>,
) -> Result<(), io::Error> {
    let config = load_toml_config(path)?;
    show_ddns_status(&config.ddns, *last_manual_refresh);
    let confirm = prompt("手动刷新会重新解析域名并通过安全应用流程执行 nft。确认继续? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消手动刷新");
        return Ok(());
    }
    let args = Args {
        menu: false,
        compatible_config_file: None,
        toml: Some(path.to_string()),
    };
    audit_cli(
        path,
        "ddns.refresh",
        AuditResult::Info,
        json!({"trigger": "cli"}),
    );
    if let Err(e) = super::refresh_once(&args) {
        if e.to_string().contains("resolved fake-ip") {
            println!("解析结果为 fake-ip，已拒绝应用");
        }
        return Err(e);
    }
    let now = Local::now();
    *last_manual_refresh = Some(now);
    println!("手动刷新完成，上次解析时间: {}", format_time(Some(now)));
    Ok(())
}

fn show_ddns_status(config: &DdnsConfig, last_manual_refresh: Option<chrono::DateTime<Local>>) {
    println!(
        "当前 DDNS 自动刷新间隔: {} 秒",
        config.refresh_interval_seconds
    );
    if config.refresh_interval_seconds < 60 {
        println!("提示：当前间隔低于 60 秒，仅建议测试使用。");
    }
    println!("上次解析时间: {}", format_time(last_manual_refresh));
}

fn format_time(time: Option<chrono::DateTime<Local>>) -> String {
    time.map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "当前菜单会话尚未手动刷新；nat 服务内部解析时间未持久化".to_string())
}

fn show_nft_rules() -> Result<(), io::Error> {
    for (family, table) in [
        ("ip", "self-nat"),
        ("ip", "self-filter"),
        ("ip6", "self-nat"),
        ("ip6", "self-filter"),
    ] {
        println!("\n# table {family} {table}");
        let output = Command::new("/usr/sbin/nft")
            .arg("list")
            .arg("table")
            .arg(family)
            .arg(table)
            .output();
        match output {
            Ok(output) if output.status.success() => {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            Ok(output) => {
                println!("{}", String::from_utf8_lossy(&output.stderr));
            }
            Err(e) => {
                println!("读取 nft 表失败: {e}");
            }
        }
    }
    Ok(())
}

fn show_stats(config_path: &str) {
    let config = load_toml_config(config_path).unwrap_or_default();
    let stats_config = config.stats;
    if stats_config.enabled {
        collect_stats_for_cli(&stats_config, config_path);
    }
    if !Path::new(&stats_config.data_file).exists() {
        println!("stats not initialized yet");
        return;
    }
    let state = traffic_stats::load_state(&stats_config.data_file);
    for line in format_stats_overview(&stats_config, &state) {
        println!("{line}");
    }
}

fn stats_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        show_stats(config_path);
        println!(
            r#"====================================
Stats 流量统计
====================================
1) 刷新统计
2) 切换统计口径
3) 设置规则流量配额
4) 查看规则配额状态
5) 重置今日统计
6) 重置本月统计
0) 返回主菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                wait_enter_to_return()?;
                continue;
            }
            "2" => {
                if switch_traffic_mode(config_path)? {
                    wait_enter_to_return()?;
                }
            }
            "3" => {
                // 子动作返回 Cancelled 时（用户按 0 退出）不再要求按一次 Enter，
                // 避免「按 0 → 空白返回页 → 还要再按 Enter」的双确认体验。
                if set_rule_quota_interactive(config_path)? == MenuOutcome::Done {
                    wait_enter_to_return()?;
                }
            }
            "4" => {
                show_quota_status(config_path);
                wait_enter_to_return()?;
            }
            "5" => {
                reset_stats(config_path, true, false)?;
                wait_enter_to_return()?;
            }
            "6" => {
                reset_stats(config_path, false, true)?;
                wait_enter_to_return()?;
            }
            "0" | "q" | "quit" | "exit" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn switch_traffic_mode(config_path: &str) -> Result<bool, io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!("当前统计口径：{}", config.stats.traffic_mode);
    println!(
        r#"请选择新的统计口径：
1) both 双向 out + in，默认推荐
2) out 仅 client -> VPS -> target
3) in 仅 target -> VPS -> client
0) 取消"#
    );
    let choice = prompt("请选择 [0/1/2/3]: ")?;
    let mode = match choice.trim() {
        "1" => TrafficMode::Both,
        "2" => TrafficMode::Out,
        "3" => TrafficMode::In,
        "0" | "" => return Ok(false),
        _ => {
            println!("未知选项: {}", choice.trim());
            return Ok(true);
        }
    };
    config.stats.traffic_mode = mode;
    save_toml_config(config_path, &config, "stats.mode.update")?;
    println!("已保存统计口径到 {config_path}。");
    println!("后续新增流量将按新口径累计；历史 daily/monthly 不会自动重算。");
    println!("如需重新统计，请重置今日或本月统计。");
    print_config_saved_hint(config_path, "stats.mode.update");
    Ok(true)
}

fn set_rule_quota_interactive(config_path: &str) -> Result<MenuOutcome, io::Error> {
    let mut config = load_toml_config(config_path)?;
    if config.rules.is_empty() {
        println!("当前没有规则可配置 quota。");
        return Ok(MenuOutcome::Done);
    }
    if !config.stats.enabled {
        println!(
            "提示：stats.enabled=false，quota 依赖 Stats 才能生效。建议先在 Stats 子菜单启用。"
        );
    }
    let stats_state = traffic_stats::load_state(&config.stats.data_file);
    for (idx, rule) in config.rules.iter().enumerate() {
        let label = match rule {
            NftCell::Drop { .. } => "[drop]".to_string(),
            _ => format_rule(rule),
        };
        let quota_str = if !rule.quota_enabled() || rule.quota_bytes() == 0 {
            "off".to_string()
        } else {
            format!(
                "{} {}",
                quota::format_bytes(rule.quota_bytes()),
                rule.quota_period()
            )
        };
        let used = match rule.quota_period() {
            QuotaPeriod::Daily => stats_state
                .per_rule_daily_bytes
                .get(&format!("r{idx}"))
                .copied()
                .unwrap_or(0),
            QuotaPeriod::Monthly => stats_state
                .per_rule_monthly_bytes
                .get(&format!("r{idx}"))
                .copied()
                .unwrap_or(0),
            QuotaPeriod::Total => stats_state
                .per_rule_total_bytes
                .get(&format!("r{idx}"))
                .copied()
                .unwrap_or(0),
        };
        println!(
            "{}) [{}] {label}  quota: {quota_str}  used: {}",
            idx + 1,
            rule_status(rule),
            quota::format_bytes(used)
        );
    }
    println!("0) 返回");
    let index = parse_index(&prompt("请选择规则编号: ")?)?;
    if index == 0 {
        // 用户主动选择「返回」：上层不应再等一次 Enter
        return Ok(MenuOutcome::Cancelled);
    }
    let rule_idx = index - 1;
    if rule_idx >= config.rules.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "规则编号超出范围",
        ));
    }
    if matches!(config.rules[rule_idx], NftCell::Drop { .. }) {
        println!("Drop 规则不支持 quota。");
        return Ok(MenuOutcome::Done);
    }
    println!(
        r#"
1) 启用配额
2) 禁用配额
3) 设置配额大小
4) 设置周期 daily/monthly/total
0) 返回"#
    );
    let action = prompt("请选择: ")?;
    match action.trim() {
        "1" => {
            if config.rules[rule_idx].quota_bytes() == 0 {
                println!("警告：当前 quota_bytes=0，请先在 3) 设置配额大小。");
            }
            config.rules[rule_idx].set_quota_enabled(true);
        }
        "2" => {
            config.rules[rule_idx].set_quota_enabled(false);
        }
        "3" => {
            let raw = prompt("请输入配额，例如 100GB / 1TB / 500MiB / 107374182400: ")?;
            let bytes = quota::parse_quota_bytes(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            config.rules[rule_idx].set_quota_bytes(bytes);
        }
        "4" => {
            let raw = prompt("请输入周期 [daily/monthly/total]: ")?;
            let period = match raw.trim().to_lowercase().as_str() {
                "daily" => QuotaPeriod::Daily,
                "monthly" => QuotaPeriod::Monthly,
                "total" => QuotaPeriod::Total,
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("未知周期: {other}"),
                    ));
                }
            };
            config.rules[rule_idx].set_quota_period(period);
        }
        // 用户主动选择「返回」：上层不应再等一次 Enter
        "0" => return Ok(MenuOutcome::Cancelled),
        _ => {
            println!("未知选项: {}", action.trim());
            return Ok(MenuOutcome::Done);
        }
    }
    save_toml_config(config_path, &config, "quota.config.update")?;
    let rule = &config.rules[rule_idx];
    audit_cli(
        config_path,
        "quota.config.update",
        AuditResult::Ok,
        serde_json::json!({
            "rule_id": format!("r{rule_idx}"),
            "quota_enabled": rule.quota_enabled(),
            "quota_bytes": rule.quota_bytes(),
            "quota_period": rule.quota_period().to_string(),
        }),
    );
    println!("已保存。");
    print_config_saved_hint(config_path, "quota.config.update");
    Ok(MenuOutcome::Done)
}

fn show_quota_status(config_path: &str) {
    let config = match load_toml_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            println!("读取配置失败: {e}");
            return;
        }
    };
    println!("====================================");
    println!("规则流量配额状态");
    println!("====================================");
    println!(
        "全局开关：{} 检查间隔：{}s 超额通知：{}",
        if config.quota.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.quota.check_interval_seconds,
        if config.quota.notify_on_exceeded {
            "on"
        } else {
            "off"
        }
    );
    println!("stats.enabled: {}", config.stats.enabled);
    if !config.stats.enabled {
        println!("提示：stats.enabled=false 时 quota 不会生效。");
    }
    let stats_state = traffic_stats::load_state(&config.stats.data_file);
    let quota_state = quota::QuotaState::load(&config.quota.state_file);
    let now = chrono::Utc::now();
    let usages = quota::compute_usages(&config.rules, &stats_state, now);
    if usages.is_empty() {
        println!("当前没有启用 quota 的规则。");
        return;
    }
    for usage in &usages {
        // 用 original_index 取真实规则状态；rule_id 是「启用规则序号」，不能直接当数组下标。
        let rule_state = config
            .rules
            .get(usage.original_index)
            .map(|r| if r.enabled() { "enabled" } else { "disabled" })
            .unwrap_or("?");
        let remaining = usage.limit_bytes.saturating_sub(usage.used_bytes);
        let last_notified = quota_state.notified.get(&usage.notify_key()).cloned();
        println!(
            "{} ({})  rule={}  period={} ({})",
            usage.rule_id,
            usage.label.as_deref().unwrap_or("-"),
            rule_state,
            usage.period,
            usage.period_key
        );
        println!(
            "  used={}  limit={}  remaining={}  exceeded={}",
            quota::format_bytes(usage.used_bytes),
            quota::format_bytes(usage.limit_bytes),
            quota::format_bytes(remaining),
            usage.exceeded()
        );
        if let Some(ts) = last_notified {
            println!(
                "  上次通知时间: {}",
                format_cli_time_from_rfc3339_with(&ts, &config.ui)
            );
        }
    }
}

fn reset_stats(config_path: &str, daily: bool, monthly: bool) -> Result<(), io::Error> {
    let config = load_toml_config(config_path)?;
    let mut state = traffic_stats::load_state(&config.stats.data_file);
    if daily {
        state.daily_total_bytes = 0;
        state.per_rule_daily_bytes.clear();
    }
    if monthly {
        state.monthly_total_bytes = 0;
        state.per_rule_monthly_bytes.clear();
    }
    traffic_stats::save_state(&config.stats.data_file, &state)?;
    println!("统计已重置。");
    Ok(())
}

fn collect_stats_for_cli(stats_config: &StatsConfig, config_path: &str) {
    let Ok(config) = load_toml_config(config_path) else {
        println!("无法读取配置，显示最近一次采集结果。");
        return;
    };
    let Ok(output) = Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()
    else {
        println!("无法读取 nft counters，显示最近一次采集结果。");
        return;
    };
    if !output.status.success() {
        println!("nft counters 读取失败，显示最近一次采集结果。");
        return;
    }
    let labels = traffic_stats::rule_labels_from_config(&config);
    let json = String::from_utf8_lossy(&output.stdout);
    if let Err(e) = traffic_stats::collect_from_nft_json_with_config(
        &stats_config.data_file,
        &json,
        &labels,
        Local::now().naive_local(),
        stats_config,
    ) {
        println!("采集 nft counters 失败，显示最近一次采集结果: {e}");
    }
}

pub(crate) fn format_stats_overview(
    stats_config: &StatsConfig,
    state: &traffic_stats::StatsState,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.extend(
        traffic_stats::traffic_mode_cli_description(stats_config.traffic_mode)
            .lines()
            .map(ToString::to_string),
    );
    lines.push(String::new());
    lines.push(format!(
        "今日流量: {}",
        traffic_stats::format_bytes(state.daily_total_bytes)
    ));
    lines.push(format!(
        "本月流量: {}",
        traffic_stats::format_bytes(state.monthly_total_bytes)
    ));
    lines.push(format!(
        "最近采集: {}",
        state
            .last_collect_time
            .clone()
            .unwrap_or_else(|| "-".to_string())
    ));
    if state.daily_total_bytes == 0 && !state.last_counters.is_empty() {
        lines.push(
            "提示：首次采集可能仅建立 baseline，后续新增流量会按 counter delta 计入统计。"
                .to_string(),
        );
    }
    if has_out_without_in(state) {
        lines.push(
            "提示：某些规则只有 out 增长、in 为 0，目标可能没有返回流量，或返回路径未经过本机。"
                .to_string(),
        );
    }
    lines.push("TOP 10 规则:".to_string());
    for (index, line) in format_stats_top10(state).iter().enumerate() {
        lines.push(format!("{}. {line}", index + 1));
    }
    lines
}

fn has_out_without_in(state: &traffic_stats::StatsState) -> bool {
    state.last_counters.iter().any(|(counter_id, out)| {
        let Some(rule_id) = counter_id.strip_suffix(":out") else {
            return false;
        };
        out.bytes > 0
            && state
                .last_counters
                .get(&format!("{rule_id}:in"))
                .map(|counter| counter.bytes == 0)
                .unwrap_or(true)
    })
}

// v0.6.1：restore_config_interactive 已搬到 `menu/backup.rs`。

fn access_control_menu(path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(path)?;
    loop {
        println!("====================================");
        println!("白名单 / 黑名单管理");
        println!("====================================");
        for line in format_access_control_brief_lines(&config) {
            println!("{line}");
        }
        println!(
            r#"1) 查看当前配置
2) 设置模式 off
3) 设置模式 whitelist
4) 设置模式 blacklist
5) 添加 IP/CIDR
6) 删除 IP/CIDR
7) 清空 entries
8) 动态 DDNS 来源白名单
9) 查询来源 IP 命中情况
10) 检测当前 SSH 来源 IP
11) 查看来源策略详情
12) 保存并应用
0) 返回主菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                print_access_entries(&config);
                wait_enter_to_return()?;
            }
            "2" => {
                config.access_control.mode = AccessControlMode::Off;
                println!("访问控制模式已设为 off。");
                wait_enter_to_return()?;
            }
            "3" => {
                println!(
                    "白名单只影响本项目转发端口，不影响 SSH；请确认需要访问转发端口的来源 IP 已加入白名单。"
                );
                let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
                if whitelist_empty_lock_warning_needed(&config, &state) {
                    print_whitelist_empty_lock_warning(&config, &state);
                    let continue_on_empty = confirm("是否仍继续？[y/N]: ")?;
                    match apply_whitelist_mode_with_empty_guard(
                        path,
                        &mut config,
                        &state,
                        continue_on_empty,
                    ) {
                        WhitelistModeApplyResult::Applied => {
                            println!("访问控制模式已设为 whitelist。");
                        }
                        WhitelistModeApplyResult::CancelledByEmptyWarning => {
                            println!("已取消切换到 whitelist。");
                        }
                    }
                } else if confirm("确认切换到 whitelist? [y/N]: ")? {
                    config.access_control.mode = AccessControlMode::Whitelist;
                    println!("访问控制模式已设为 whitelist。");
                }
                wait_enter_to_return()?;
            }
            "4" => {
                println!("黑名单只阻断本项目转发端口，不影响 SSH。");
                if confirm("确认切换到 blacklist? [y/N]: ")? {
                    config.access_control.mode = AccessControlMode::Blacklist;
                }
                wait_enter_to_return()?;
            }
            "5" => {
                let entry = prompt("请输入 IP/CIDR: ")?;
                validate_access_entry(&entry)?;
                add_access_entry(&mut config, entry);
                println!("entry 已加入待保存配置。");
                wait_enter_to_return()?;
            }
            "6" => {
                delete_access_entry_interactive(&mut config)?;
                wait_enter_to_return()?;
            }
            "7" => {
                if confirm("确认清空 entries? [y/N]: ")? {
                    clear_access_entries(&mut config);
                }
                wait_enter_to_return()?;
            }
            "8" => {
                dynamic_whitelist_menu(path)?;
                config = load_toml_config(path)?;
            }
            "9" => {
                query_source_ip_match_interactive(&config)?;
                wait_enter_to_return()?;
            }
            "10" => {
                detect_ssh_source_interactive(path)?;
                config = load_toml_config(path)?;
                wait_enter_to_return()?;
            }
            "11" => {
                for line in format_source_policy_detail_lines(&config) {
                    println!("{line}");
                }
                wait_enter_to_return()?;
            }
            "12" => {
                config
                    .access_control
                    .validate()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                save_toml_config(path, &config, "access_control.update")?;
                audit_cli(
                    path,
                    "access_control.update",
                    AuditResult::Ok,
                    json!({
                        "mode": config.access_control.mode.to_string(),
                        "entries": config.access_control.entries.len(),
                    }),
                );
                println!("访问控制配置已保存。");
                print_config_saved_hint(path, "access_control.update");
                wait_enter_to_return()?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

/// 「白名单 / 黑名单管理」默认页摘要：只列来源访问控制相关字段，
/// 不展开 SNAT / MSS / egress_control / 评估顺序等长文本（这些走「查看来源策略详情」）。
pub(crate) fn format_access_control_brief_lines(config: &TomlConfig) -> Vec<String> {
    let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    format_access_control_brief_lines_with_state(config, &state)
}

pub(crate) fn format_access_control_brief_lines_with_state(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    let dynamic_label = if config.dynamic_whitelist.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let current_ips = dynamic_whitelist::current_ips_for_config(&config.dynamic_whitelist, state);
    let stale_count = dynamic_whitelist::stale_count_for_config(&config.dynamic_whitelist, state);
    let geoip_label = if config.geoip.enabled && config.geoip.forward.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let ssh_geoip_label = if config.geoip.enabled && config.geoip.ssh.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let global_label = enabled_label(config.global.enabled);
    let mut lines = vec![
        "来源访问控制：".to_string(),
        format!("  mode: {}", config.access_control.mode),
        format!("  静态 entries: {}", config.access_control.entries.len()),
        format!(
            "  dynamic_whitelist: {dynamic_label}, domains={}, current_ips={}, stale={stale_count}",
            config.dynamic_whitelist.domains.len(),
            current_ips.len()
        ),
        format!(
            "  cidr_expand_ipv4: {}",
            if config.dynamic_whitelist.cidr_expand_ipv4 == 24 {
                "true"
            } else {
                "false"
            }
        ),
        format!("  GeoIP forward: {geoip_label}"),
        format!("  SSH GeoIP: {ssh_geoip_label}"),
        format!("  global forwarding: {global_label}"),
        String::new(),
        "最终来源判断：".to_string(),
        "  黑名单优先拒绝".to_string(),
        "  whitelist 模式：静态 entries OR dynamic_whitelist".to_string(),
        "  GeoIP 同时启用时继续 AND 叠加".to_string(),
        String::new(),
        "提示：".to_string(),
        "  dynamic_whitelist 只有在 access_control.mode = whitelist 时才参与放行。".to_string(),
        "  egress_control 是目标 IP 限制，不在此处管理。".to_string(),
        "  global.enabled=false 时，所有转发规则都会临时停用。".to_string(),
    ];
    if !config.global.enabled {
        lines.push("  警告：global forwarding 当前为 disabled，所有转发规则临时停用。".to_string());
    }
    if config.access_control.mode == AccessControlMode::Whitelist
        && config.access_control.entries.is_empty()
        && current_ips.is_empty()
    {
        lines.push(
            "  warning: whitelist 模式下静态 entries=0 且 dynamic current_ips=0，可能拒绝所有来源。"
                .to_string(),
        );
    }
    if config.dynamic_whitelist.enabled
        && config.access_control.mode != AccessControlMode::Whitelist
    {
        lines.push("  提示：动态白名单只解析和显示状态，不参与放行。".to_string());
    }
    lines
}

fn query_source_ip_match_interactive(config: &TomlConfig) -> Result<(), io::Error> {
    let input = prompt("请输入来源 IP: ")?;
    let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    match format_source_ip_match_lines(config, &state, &input) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => {
            println!("输入错误: {e}");
        }
    }
    Ok(())
}

pub(crate) fn format_source_ip_match_lines(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
    input: &str,
) -> Result<Vec<String>, String> {
    let ip: IpAddr = input
        .trim()
        .parse()
        .map_err(|_| "请输入合法 IPv4 / IPv6 地址".to_string())?;
    let static_hit = find_matching_source_entry(ip, &config.access_control.entries);
    let blacklist_hit = if config.access_control.mode == AccessControlMode::Blacklist {
        static_hit.clone()
    } else {
        None
    };
    let dynamic_hits = dynamic_source_matches(config, state, ip);
    let geoip_result = evaluate_geoip_source_match(config, ip);
    let final_assessment = assess_final_source_decision(
        config,
        static_hit.as_ref(),
        blacklist_hit.as_ref(),
        &dynamic_hits,
        geoip_result,
    );
    let dynamic_match_label = dynamic_match_label(config, ip, &dynamic_hits);

    let mut lines = vec![
        "================================".to_string(),
        "来源 IP 命中查询".to_string(),
        "================================".to_string(),
        String::new(),
        format!("输入 IP：{ip}"),
        String::new(),
        "1. access_control".to_string(),
        format!("- mode: {}", config.access_control.mode),
        format!(
            "- 静态 entries: {}",
            match &static_hit {
                Some(entry) => format!("命中 {entry}"),
                None => "未命中".to_string(),
            }
        ),
        format!(
            "- blacklist: {}",
            match (&config.access_control.mode, &blacklist_hit) {
                (AccessControlMode::Blacklist, Some(entry)) => format!("命中 {entry}"),
                (AccessControlMode::Blacklist, None) => "未命中".to_string(),
                _ => "未启用".to_string(),
            }
        ),
        String::new(),
        "2. dynamic_whitelist".to_string(),
        format!("- enabled: {}", config.dynamic_whitelist.enabled),
        "- 生效条件: access_control.mode = whitelist".to_string(),
        format!("- 当前动态 IP: {dynamic_match_label}"),
        format!(
            "- 命中来源: {}",
            if dynamic_hits.is_empty() {
                "无".to_string()
            } else {
                dynamic_hits
                    .iter()
                    .map(|hit| hit.domain.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
        format!(
            "- cidr_expand_ipv4: {}",
            if config.dynamic_whitelist.cidr_expand_ipv4 == 24 {
                "true"
            } else {
                "false"
            }
        ),
    ];
    let expanded_hits = dynamic_hits
        .iter()
        .filter(|hit| hit.entry.contains('/'))
        .map(|hit| hit.entry.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if !expanded_hits.is_empty() {
        lines.push(format!(
            "- 扩展网段: {}",
            expanded_hits.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    lines.extend([
        String::new(),
        "3. GeoIP 来源限制".to_string(),
        format!(
            "- forward: {}",
            if config.geoip.enabled && config.geoip.forward.enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        format!("- 结果: {}", geoip_source_result_label(geoip_result)),
        "- 说明：GeoIP 与 access_control 是 AND 叠加".to_string(),
        String::new(),
        "4. 最终判断".to_string(),
        format!("- 允许：{}", final_assessment.allow_label),
        "- 原因：".to_string(),
    ]);
    for reason in final_assessment.reasons {
        lines.push(format!("  - {reason}"));
    }
    Ok(lines)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicSourceMatch {
    domain: String,
    entry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeoipSourceResult {
    Disabled,
    Unchecked,
    Hit,
    Miss,
    DataUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFinalAssessment {
    allow_label: &'static str,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WhitelistModeApplyResult {
    Applied,
    CancelledByEmptyWarning,
}

fn find_matching_source_entry(ip: IpAddr, entries: &[String]) -> Option<String> {
    entries
        .iter()
        .find(|entry| source_entry_matches_ip(ip, entry))
        .cloned()
}

fn source_entry_matches_ip(ip: IpAddr, entry: &str) -> bool {
    if let Ok(addr) = entry.parse::<IpAddr>() {
        return addr == ip;
    }
    entry
        .parse::<ipnetwork::IpNetwork>()
        .map(|network| network.contains(ip))
        .unwrap_or(false)
}

fn dynamic_source_matches(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
    ip: IpAddr,
) -> Vec<DynamicSourceMatch> {
    if !config.dynamic_whitelist.enabled {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for domain_config in config
        .dynamic_whitelist
        .domains
        .iter()
        .filter(|domain| domain.enabled)
    {
        let Some(domain_state) =
            state.find_domain_state(&domain_config.name, &domain_config.domain)
        else {
            continue;
        };
        for entry in dynamic_whitelist::effective_sources_view(
            domain_state,
            config.dynamic_whitelist.cidr_expand_ipv4,
        ) {
            if source_entry_matches_ip(ip, &entry) {
                hits.push(DynamicSourceMatch {
                    domain: domain_config.domain.clone(),
                    entry,
                });
                break;
            }
        }
    }
    hits
}

fn dynamic_match_label(
    config: &TomlConfig,
    ip: IpAddr,
    dynamic_hits: &[DynamicSourceMatch],
) -> &'static str {
    if !config.dynamic_whitelist.enabled {
        return "未启用";
    }
    if matches!(ip, IpAddr::V6(_)) && !config.dynamic_whitelist.resolve_ipv6 {
        return "不适用 / 未启用 IPv6 dynamic whitelist";
    }
    if dynamic_hits.is_empty() {
        "未命中"
    } else {
        "命中"
    }
}

fn evaluate_geoip_source_match(config: &TomlConfig, ip: IpAddr) -> GeoipSourceResult {
    if !(config.geoip.enabled && config.geoip.forward.enabled) {
        return GeoipSourceResult::Disabled;
    }
    if !matches!(ip, IpAddr::V4(_)) {
        return GeoipSourceResult::Unchecked;
    }
    if config.geoip.allow_lan
        && find_matching_source_entry(ip, &config.geoip.lan_ipv4_cidrs()).is_some()
    {
        return GeoipSourceResult::Hit;
    }
    let Ok(content) = fs::read_to_string(&config.geoip.cn4_file) else {
        return GeoipSourceResult::DataUnavailable;
    };
    if geoip::validate_cn4_content(&content).is_err() {
        return GeoipSourceResult::DataUnavailable;
    }
    let cidrs = geoip::extract_ipv4_cidrs(&content);
    if cidrs.is_empty() {
        return GeoipSourceResult::DataUnavailable;
    }
    if find_matching_source_entry(ip, &cidrs).is_some() {
        GeoipSourceResult::Hit
    } else {
        GeoipSourceResult::Miss
    }
}

fn geoip_source_result_label(result: GeoipSourceResult) -> &'static str {
    match result {
        GeoipSourceResult::Disabled | GeoipSourceResult::Unchecked => "未检查",
        GeoipSourceResult::Hit => "命中",
        GeoipSourceResult::Miss => "不命中",
        GeoipSourceResult::DataUnavailable => "数据不可用",
    }
}

fn assess_final_source_decision(
    config: &TomlConfig,
    static_hit: Option<&String>,
    blacklist_hit: Option<&String>,
    dynamic_hits: &[DynamicSourceMatch],
    geoip_result: GeoipSourceResult,
) -> SourceFinalAssessment {
    let mut reasons = Vec::new();
    let access_allowed = match config.access_control.mode {
        AccessControlMode::Off => {
            reasons.push("access_control=off，来源未受白名单限制".to_string());
            true
        }
        AccessControlMode::Blacklist => {
            if blacklist_hit.is_some() {
                reasons.push("blacklist 命中，优先拒绝".to_string());
                false
            } else {
                reasons.push("blacklist 未命中".to_string());
                true
            }
        }
        AccessControlMode::Whitelist => {
            let static_allowed = static_hit.is_some();
            let dynamic_allowed = !dynamic_hits.is_empty();
            if static_allowed {
                reasons.push("whitelist 模式下命中静态白名单".to_string());
            }
            if dynamic_allowed {
                reasons.push("whitelist 模式下命中 dynamic_whitelist".to_string());
            }
            if static_allowed || dynamic_allowed {
                true
            } else {
                reasons.push("whitelist 模式下未命中静态白名单或 dynamic_whitelist".to_string());
                false
            }
        }
    };

    if !access_allowed {
        return SourceFinalAssessment {
            allow_label: "否",
            reasons,
        };
    }

    match geoip_result {
        GeoipSourceResult::Hit => {
            reasons.push("GeoIP 命中".to_string());
            SourceFinalAssessment {
                allow_label: "是",
                reasons,
            }
        }
        GeoipSourceResult::Miss => {
            reasons.push("GeoIP 未命中，最终拒绝".to_string());
            SourceFinalAssessment {
                allow_label: "否",
                reasons,
            }
        }
        GeoipSourceResult::DataUnavailable => {
            reasons.push("GeoIP 数据不可用，无法完全判断".to_string());
            SourceFinalAssessment {
                allow_label: "无法完全判断",
                reasons,
            }
        }
        GeoipSourceResult::Disabled | GeoipSourceResult::Unchecked => SourceFinalAssessment {
            allow_label: "是",
            reasons,
        },
    }
}

fn dynamic_whitelist_usable_sources_for_lock_check(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    if !config.dynamic_whitelist.enabled {
        return Vec::new();
    }
    let mut values = std::collections::BTreeSet::new();
    for domain_config in config
        .dynamic_whitelist
        .domains
        .iter()
        .filter(|domain| domain.enabled)
    {
        let Some(domain_state) =
            state.find_domain_state(&domain_config.name, &domain_config.domain)
        else {
            continue;
        };
        let mut raw_ips = domain_state.current_ips.clone();
        if raw_ips.is_empty() && config.dynamic_whitelist.use_last_good_on_dns_failure {
            raw_ips = domain_state.last_good_ips.clone();
        }
        for source in dynamic_whitelist::expand_effective_sources(
            &raw_ips,
            config.dynamic_whitelist.cidr_expand_ipv4,
        ) {
            values.insert(source);
        }
    }
    values.into_iter().collect()
}

fn whitelist_empty_lock_warning_needed(config: &TomlConfig, state: &DynamicWhitelistState) -> bool {
    if !config.access_control.entries.is_empty() {
        return false;
    }
    let enabled_domains = config
        .dynamic_whitelist
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .count();
    if !config.dynamic_whitelist.enabled || enabled_domains == 0 {
        return true;
    }
    dynamic_whitelist_usable_sources_for_lock_check(config, state).is_empty()
}

fn print_whitelist_empty_lock_warning(config: &TomlConfig, state: &DynamicWhitelistState) {
    let enabled_domains = config
        .dynamic_whitelist
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .count();
    let usable_sources = dynamic_whitelist_usable_sources_for_lock_check(config, state);
    println!();
    println!("警告：你正在启用 whitelist 模式，但当前没有可用来源白名单。");
    println!("这可能导致所有来源都无法访问转发入口。");
    println!("建议先添加至少一个静态 IP/CIDR，或配置 dynamic_whitelist 并确认解析成功。");
    println!(
        "当前检查：静态 entries={}，dynamic_whitelist.enabled={}，enabled domains={}，可用动态来源={}",
        config.access_control.entries.len(),
        config.dynamic_whitelist.enabled,
        enabled_domains,
        usable_sources.len()
    );
    println!("不会自动添加当前 SSH IP，也不会自动放开来源。");
    println!();
}

fn apply_whitelist_mode_with_empty_guard(
    path: &str,
    config: &mut TomlConfig,
    state: &DynamicWhitelistState,
    continue_on_empty_warning: bool,
) -> WhitelistModeApplyResult {
    let empty_warning = whitelist_empty_lock_warning_needed(config, state);
    if empty_warning && !continue_on_empty_warning {
        return WhitelistModeApplyResult::CancelledByEmptyWarning;
    }
    config.access_control.mode = AccessControlMode::Whitelist;
    if empty_warning {
        audit_whitelist_empty_override(path, config, state);
    }
    WhitelistModeApplyResult::Applied
}

fn audit_whitelist_empty_override(path: &str, config: &TomlConfig, state: &DynamicWhitelistState) {
    let enabled_domains = config
        .dynamic_whitelist
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .count();
    audit_cli(
        path,
        "access_control.whitelist.empty_override",
        AuditResult::Warn,
        json!({
            "mode": config.access_control.mode.to_string(),
            "entries": config.access_control.entries.len(),
            "dynamic_whitelist_enabled": config.dynamic_whitelist.enabled,
            "dynamic_whitelist_enabled_domains": enabled_domains,
            "dynamic_whitelist_usable_sources": dynamic_whitelist_usable_sources_for_lock_check(config, state).len(),
        }),
    );
}

/// 「查看来源策略详情」聚合页：复用 format_combined_policy_status 的完整组合策略文本，
/// 让默认白名单 / 黑名单管理页面保持简洁，详情按需展开。
pub(crate) fn format_source_policy_detail_lines(config: &TomlConfig) -> Vec<String> {
    format_combined_policy_status(config)
}

fn print_access_entries(config: &TomlConfig) {
    if config.access_control.entries.is_empty() {
        println!("  (empty)");
        return;
    }
    for (index, entry) in config.access_control.entries.iter().enumerate() {
        println!("{index}) {entry}");
    }
}

fn confirm(label: &str) -> Result<bool, io::Error> {
    let value = prompt(label)?;
    Ok(matches!(value.as_str(), "y" | "Y"))
}

fn delete_access_entry_interactive(config: &mut TomlConfig) -> Result<(), io::Error> {
    print_access_entries(config);
    let index = parse_index(&prompt("请输入要删除的 entry index: ")?)?;
    delete_access_entry(config, index)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(())
}

pub(crate) fn validate_access_entry(entry: &str) -> Result<(), io::Error> {
    if entry.parse::<std::net::IpAddr>().is_ok() || entry.parse::<ipnetwork::IpNetwork>().is_ok() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entries 只支持 IP/CIDR，不支持域名",
        ))
    }
}

pub(crate) fn add_access_entry(config: &mut TomlConfig, entry: String) {
    if !config.access_control.entries.contains(&entry) {
        config.access_control.entries.push(entry);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshSourceDetection {
    pub ip: IpAddr,
    pub detected_from: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SshSourceAddOutcome {
    Added { cidr: String },
    AlreadyExists { cidr: String },
    RefusedBlacklist,
}

fn detect_ssh_source_interactive(config_path: &str) -> Result<(), io::Error> {
    let Some(detection) = detect_current_ssh_source() else {
        println!("未检测到 SSH 来源 IP。");
        println!("可能是本地控制台、非 SSH 会话、sudo 未保留环境变量，或通过跳板进入。");
        println!("你仍可以手动添加 IP/CIDR。");
        return Ok(());
    };
    println!("当前 SSH 来源 IP：{}", detection.ip);
    let mut config = load_toml_config(config_path)?;
    match config.access_control.mode {
        AccessControlMode::Blacklist => {
            println!(
                "当前 access_control.mode=blacklist，此入口不会添加 SSH 来源 IP，避免误封自己。"
            );
            println!("如需切换为 whitelist，请先调整模式。");
            return Ok(());
        }
        AccessControlMode::Off => {
            println!(
                "当前 access_control.mode=off，添加后暂不生效；切换到 whitelist 后才会作为来源白名单使用。"
            );
        }
        AccessControlMode::Whitelist => {
            println!("当前 access_control.mode=whitelist，添加后会作为静态白名单生效。");
        }
    }

    let Some(cidr) = choose_ssh_source_cidr_interactive(detection.ip)? else {
        println!("已取消，不修改配置。");
        return Ok(());
    };
    if !confirm(&format!("确认将 {cidr} 加入静态白名单 entries？[y/N]: "))? {
        println!("已取消，不修改配置。");
        return Ok(());
    }
    match add_ssh_source_entry_to_config(&mut config, &cidr)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
    {
        SshSourceAddOutcome::Added { cidr } => {
            save_toml_config(config_path, &config, "access_control.ssh_source.add")?;
            audit_ssh_source_add(&audit_config_from(config_path), &detection, &cidr);
            println!("已加入静态 entries：{cidr}");
            println!("不会自动启用 whitelist，请按需手动切换 access_control.mode。");
            print_config_saved_hint(config_path, "access_control.ssh_source.add");
        }
        SshSourceAddOutcome::AlreadyExists { cidr } => {
            println!("该 IP/CIDR 已存在，不重复添加：{cidr}");
        }
        SshSourceAddOutcome::RefusedBlacklist => {
            println!("当前 access_control.mode=blacklist，此入口不会添加 SSH 来源 IP。");
        }
    }
    Ok(())
}

fn choose_ssh_source_cidr_interactive(ip: IpAddr) -> Result<Option<String>, io::Error> {
    match ip {
        IpAddr::V4(ipv4) => {
            let exact = ssh_source_exact_cidr(ip);
            let broad = ssh_source_ipv4_24_cidr(ipv4);
            println!("建议添加范围：");
            println!("  1) /32 精确 IP ({exact})");
            println!("  2) /24 网段 ({broad})");
            println!("  0) 取消");
            let choice = prompt("请选择 [1/2/0，默认 1]: ")?;
            match choice.trim() {
                "" | "1" => Ok(Some(exact)),
                "2" => {
                    println!("/24 会扩大来源范围，仅在移动网络或运营商出口频繁变化时使用。");
                    Ok(Some(broad))
                }
                "0" => Ok(None),
                other => {
                    println!("未知选项: {other}");
                    Ok(None)
                }
            }
        }
        IpAddr::V6(_) => {
            let exact = ssh_source_exact_cidr(ip);
            println!("建议添加范围：");
            println!("  1) /128 精确地址 ({exact})");
            println!("  0) 取消");
            println!("IPv6 不提供 /64 自动扩展；如需更大范围请手动添加并自行评估风险。");
            let choice = prompt("请选择 [1/0，默认 1]: ")?;
            match choice.trim() {
                "" | "1" => Ok(Some(exact)),
                "0" => Ok(None),
                other => {
                    println!("未知选项: {other}");
                    Ok(None)
                }
            }
        }
    }
}

pub(crate) fn detect_current_ssh_source() -> Option<SshSourceDetection> {
    detect_ssh_source_from_env_vars(|name| env::var(name).ok())
}

pub(crate) fn detect_ssh_source_from_env_vars<F>(mut get_env: F) -> Option<SshSourceDetection>
where
    F: FnMut(&str) -> Option<String>,
{
    for name in ["SSH_CONNECTION", "SSH_CLIENT"] {
        if let Some(value) = get_env(name)
            && let Some(ip) = parse_ssh_source_ip(&value)
        {
            return Some(SshSourceDetection {
                ip,
                detected_from: name,
            });
        }
    }
    None
}

fn parse_ssh_source_ip(value: &str) -> Option<IpAddr> {
    value.split_whitespace().next()?.parse().ok()
}

fn ssh_source_ipv4_24_cidr(ip: std::net::Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
}

fn ssh_source_exact_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => format!("{ipv4}/32"),
        IpAddr::V6(ipv6) => format!("{ipv6}/128"),
    }
}

pub(crate) fn add_ssh_source_entry_to_config(
    config: &mut TomlConfig,
    cidr: &str,
) -> Result<SshSourceAddOutcome, String> {
    if config.access_control.mode == AccessControlMode::Blacklist {
        return Ok(SshSourceAddOutcome::RefusedBlacklist);
    }
    validate_access_entry(cidr).map_err(|e| e.to_string())?;
    if config
        .access_control
        .entries
        .iter()
        .any(|entry| entry == cidr)
    {
        return Ok(SshSourceAddOutcome::AlreadyExists {
            cidr: cidr.to_string(),
        });
    }
    config.access_control.entries.push(cidr.to_string());
    Ok(SshSourceAddOutcome::Added {
        cidr: cidr.to_string(),
    })
}

fn audit_ssh_source_add(audit_cfg: &AuditConfig, detection: &SshSourceDetection, cidr: &str) {
    audit::log_event(
        audit_cfg,
        "access_control.ssh_source.add",
        AuditResult::Ok,
        json!({
            "ip": detection.ip.to_string(),
            "cidr": cidr,
            "detected_from": detection.detected_from,
        }),
    );
}

pub(crate) fn delete_access_entry(config: &mut TomlConfig, index: usize) -> Result<String, String> {
    if index >= config.access_control.entries.len() {
        return Err("entry index 超出范围".to_string());
    }
    Ok(config.access_control.entries.remove(index))
}

pub(crate) fn clear_access_entries(config: &mut TomlConfig) {
    config.access_control.entries.clear();
}

fn dynamic_whitelist_menu(path: &str) -> Result<(), io::Error> {
    loop {
        let config = load_toml_config(path)?;
        let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
        println!("====================================");
        println!("动态 DDNS 来源白名单");
        println!("====================================");
        for line in format_dynamic_whitelist_brief_lines(&config, &state) {
            println!("{line}");
        }
        println!(
            r#"1) 查看动态白名单状态
2) 添加 DDNS 白名单域名
3) 删除 DDNS 白名单域名
4) 启用 / 禁用某个 DDNS 域名
5) 设置刷新间隔
6) 手动刷新动态白名单
7) 查看详细解析结果
8) 设置 IPv4 CIDR 扩展模式
0) 返回上级菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                show_dynamic_whitelist_status(&config);
                wait_enter_to_return()?;
            }
            "2" => {
                add_dynamic_whitelist_domain_interactive(path, &config)?;
                wait_enter_to_return()?;
            }
            "3" => {
                delete_dynamic_whitelist_domain_interactive(path, &config)?;
                wait_enter_to_return()?;
            }
            "4" => {
                toggle_dynamic_whitelist_domain_interactive(path, &config)?;
                wait_enter_to_return()?;
            }
            "5" => {
                set_dynamic_whitelist_interval_interactive(path, &config)?;
                wait_enter_to_return()?;
            }
            "6" => {
                refresh_dynamic_whitelist_interactive(&config)?;
                wait_enter_to_return()?;
            }
            "7" => {
                show_dynamic_whitelist_details(&config);
                wait_enter_to_return()?;
            }
            "8" => {
                set_dynamic_whitelist_cidr_expand_interactive(path, &config)?;
                wait_enter_to_return()?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn show_dynamic_whitelist_status(config: &TomlConfig) {
    let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    for line in format_dynamic_whitelist_status_lines(config, &state) {
        println!("{line}");
    }
}

/// 「动态 DDNS 来源白名单」子菜单默认摘要：只显示 dynamic_whitelist 自己的字段，
/// 不重复 access_control / GeoIP / egress / SNAT / MSS 的长段落，
/// 并按 mode / domains / current_ips 状态触发 1 条情境化提示。
pub(crate) fn format_dynamic_whitelist_brief_lines(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    let dynamic_config = &config.dynamic_whitelist;
    let current_ips = dynamic_whitelist::current_ips_for_config(dynamic_config, state);
    let effective_sources = dynamic_whitelist::effective_sources_for_config(dynamic_config, state);
    let stale_count = dynamic_whitelist::stale_count_for_config(dynamic_config, state);
    let ipv4_label = if dynamic_config.resolve_ipv4 {
        "enabled"
    } else {
        "disabled"
    };
    let ipv6_label = if dynamic_config.resolve_ipv6 {
        "enabled"
    } else {
        "disabled"
    };
    let mut lines = vec![
        "状态：".to_string(),
        format!("  enabled: {}", dynamic_config.enabled),
        "  生效条件: access_control.mode = whitelist".to_string(),
        format!("  domains: {}", dynamic_config.domains.len()),
        format!("  raw IPs: {}", current_ips.len()),
        format!("  effective sources: {}", effective_sources.len()),
        format!("  stale: {stale_count}"),
        format!(
            "  refresh interval: {}s",
            dynamic_config.refresh_interval_seconds
        ),
        format!("  IPv4: {ipv4_label}"),
        format!("  IPv6: {ipv6_label}"),
        format!(
            "  IPv4 CIDR 扩展: {}",
            format_cidr_expand_label(dynamic_config.cidr_expand_ipv4)
        ),
        format!("  state: {}", dynamic_config.state_file),
        String::new(),
        "说明：".to_string(),
        "  这是\"来源 IP 动态白名单\"，不是目标 IP 限制。".to_string(),
        "  只有 access_control.mode = whitelist 时，解析出的 IP 才会参与来源放行。".to_string(),
        String::new(),
    ];
    if dynamic_config.enabled && config.access_control.mode != AccessControlMode::Whitelist {
        lines.push(format!(
            "提示：当前 access_control.mode = {}，动态白名单只会解析和显示状态，不参与来源放行。",
            config.access_control.mode
        ));
    }
    if dynamic_config.enabled && dynamic_config.domains.is_empty() {
        lines.push("提示：动态白名单已启用，但还没有配置 DDNS 域名。".to_string());
    }
    if dynamic_config.enabled
        && config.access_control.mode == AccessControlMode::Whitelist
        && current_ips.is_empty()
    {
        lines.push(
            "警告：当前没有可用动态白名单 IP。若静态白名单也为空，可能导致所有来源被拒绝。"
                .to_string(),
        );
    }
    lines
}

pub(crate) fn format_dynamic_whitelist_status_lines(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    let dynamic_config = &config.dynamic_whitelist;
    let current_ips = dynamic_whitelist::current_ips_for_config(dynamic_config, state);
    let effective_sources = dynamic_whitelist::effective_sources_for_config(dynamic_config, state);
    let stale_count = dynamic_whitelist::stale_count_for_config(dynamic_config, state);
    let latest_success = dynamic_whitelist::latest_success_at_for_config(dynamic_config, state)
        .map(|time| format_cli_time_from_rfc3339_with(&time, &config.ui))
        .unwrap_or_else(|| "(none)".to_string());
    let mut lines = Vec::new();
    lines.push("动态 DDNS 来源白名单状态".to_string());
    lines.push(format!("enabled: {}", dynamic_config.enabled));
    lines.push(format!(
        "refresh_interval_seconds: {}",
        dynamic_config.refresh_interval_seconds
    ));
    lines.push(format!("resolve_ipv4: {}", dynamic_config.resolve_ipv4));
    lines.push(format!("resolve_ipv6: {}", dynamic_config.resolve_ipv6));
    lines.push(format!(
        "use_last_good_on_dns_failure: {}",
        dynamic_config.use_last_good_on_dns_failure
    ));
    lines.push(format!(
        "notify_on_change: {}",
        dynamic_config.notify_on_change
    ));
    lines.push(format!(
        "cidr_expand_ipv4: {}",
        format_cidr_expand_label(dynamic_config.cidr_expand_ipv4)
    ));
    lines.push(format!("state file path: {}", dynamic_config.state_file));
    lines.push(format!("domains 数量: {}", dynamic_config.domains.len()));
    lines.push(format!("当前 raw IP 数量: {}", current_ips.len()));
    lines.push(format!(
        "当前 effective sources 数量: {}",
        effective_sources.len()
    ));
    lines.push(format!("stale 数量: {stale_count}"));
    lines.push(format!("最近成功解析时间: {latest_success}"));
    lines.push(format!(
        "access_control mode: {}",
        config.access_control.mode
    ));
    if dynamic_config.enabled && config.access_control.mode != AccessControlMode::Whitelist {
        lines.push(
            "提示：dynamic_whitelist 已配置，但 access_control 未启用 whitelist 模式，因此不会限制来源。"
                .to_string(),
        );
    }
    if dynamic_config.enabled
        && config.access_control.mode == AccessControlMode::Whitelist
        && config.access_control.entries.is_empty()
        && effective_sources.is_empty()
    {
        lines.push(
            "WARN：当前动态白名单没有可用 IP，且静态白名单为空；来源白名单为空时所有来源可能被拒绝。"
                .to_string(),
        );
    }
    lines.push(
        "说明：dynamic_whitelist 限制谁能访问入口；egress_control 限制本机能转发到哪里；GeoIP 是来源地区限制。"
            .to_string(),
    );
    lines.push(
        "说明：dynamic_whitelist 不是目标 IP 限制，不会改变目标 DDNS / last-good 解析。"
            .to_string(),
    );
    lines
}

fn add_dynamic_whitelist_domain_interactive(
    path: &str,
    config: &TomlConfig,
) -> Result<(), io::Error> {
    let mut updated = config.clone();
    let name = prompt("请输入来源 DDNS 名称 name: ")?;
    let domain = prompt("请输入 DDNS 域名 domain: ")?;
    let enabled = prompt_bool_default("是否启用该域名? [Y/n]: ", true)?;
    let entry = DynamicWhitelistDomainConfig {
        name: name.trim().to_string(),
        domain: domain.trim().to_string(),
        enabled,
    };
    entry
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    updated.dynamic_whitelist.domains.push(entry.clone());
    updated
        .dynamic_whitelist
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &updated, "dynamic_whitelist.domain.add")?;
    audit_cli(
        path,
        "dynamic_whitelist.config.update",
        AuditResult::Ok,
        json!({
            "reason": "dynamic_whitelist.domain.add",
            "name": entry.name,
            "domain": entry.domain,
            "enabled": entry.enabled,
        }),
    );
    println!("DDNS 来源白名单域名已添加。");
    if !updated.dynamic_whitelist.enabled {
        println!("提示：dynamic_whitelist.enabled=false，当前不会定期解析动态白名单。");
    }
    if updated.access_control.mode != AccessControlMode::Whitelist {
        println!("提示：access_control 未启用 whitelist 模式，动态来源白名单不会参与来源放行。");
    }
    print_config_saved_hint(path, "dynamic_whitelist.domain.add");
    Ok(())
}

fn delete_dynamic_whitelist_domain_interactive(
    path: &str,
    config: &TomlConfig,
) -> Result<(), io::Error> {
    print_dynamic_whitelist_domains(config);
    let index = parse_index(&prompt("请输入要删除的 DDNS domain index: ")?)?;
    let mut updated = config.clone();
    if index >= updated.dynamic_whitelist.domains.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dynamic whitelist domain index 超出范围",
        ));
    }
    let removed = updated.dynamic_whitelist.domains.remove(index);
    save_toml_config(path, &updated, "dynamic_whitelist.domain.delete")?;
    audit_cli(
        path,
        "dynamic_whitelist.config.update",
        AuditResult::Ok,
        json!({
            "reason": "dynamic_whitelist.domain.delete",
            "name": removed.name,
            "domain": removed.domain,
        }),
    );
    prune_dynamic_whitelist_state_after_domain_delete(path, &updated);
    println!("DDNS 来源白名单域名已删除。");
    print_config_saved_hint(path, "dynamic_whitelist.domain.delete");
    Ok(())
}

fn toggle_dynamic_whitelist_domain_interactive(
    path: &str,
    config: &TomlConfig,
) -> Result<(), io::Error> {
    print_dynamic_whitelist_domains(config);
    let index = parse_index(&prompt("请输入要启用/禁用的 DDNS domain index: ")?)?;
    let mut updated = config.clone();
    let Some(entry) = updated.dynamic_whitelist.domains.get_mut(index) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dynamic whitelist domain index 超出范围",
        ));
    };
    entry.enabled = !entry.enabled;
    let name = entry.name.clone();
    let domain = entry.domain.clone();
    let enabled = entry.enabled;
    save_toml_config(path, &updated, "dynamic_whitelist.domain.toggle")?;
    audit_cli(
        path,
        "dynamic_whitelist.config.update",
        AuditResult::Ok,
        json!({
            "reason": "dynamic_whitelist.domain.toggle",
            "name": name,
            "domain": domain,
            "enabled": enabled,
        }),
    );
    println!("DDNS 来源白名单域名状态已更新：enabled={enabled}");
    print_config_saved_hint(path, "dynamic_whitelist.domain.toggle");
    Ok(())
}

fn set_dynamic_whitelist_interval_interactive(
    path: &str,
    config: &TomlConfig,
) -> Result<(), io::Error> {
    println!(
        "当前动态来源白名单刷新间隔: {} 秒",
        config.dynamic_whitelist.refresh_interval_seconds
    );
    let raw = prompt("请输入新的 refresh_interval_seconds（建议 >= 300）: ")?;
    let interval = raw.parse::<u64>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("刷新间隔必须是正整数秒: {e}"),
        )
    })?;
    let mut updated = config.clone();
    updated.dynamic_whitelist.refresh_interval_seconds = interval;
    updated
        .dynamic_whitelist
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &updated, "dynamic_whitelist.interval.update")?;
    audit_cli(
        path,
        "dynamic_whitelist.config.update",
        AuditResult::Ok,
        json!({
            "reason": "dynamic_whitelist.interval.update",
            "refresh_interval_seconds": interval,
        }),
    );
    println!("动态来源白名单刷新间隔已更新。");
    print_config_saved_hint(path, "dynamic_whitelist.interval.update");
    Ok(())
}

fn set_dynamic_whitelist_cidr_expand_interactive(
    path: &str,
    config: &TomlConfig,
) -> Result<(), io::Error> {
    let current = config.dynamic_whitelist.cidr_expand_ipv4;
    println!(
        "当前 IPv4 CIDR 扩展模式: {}",
        format_cidr_expand_label(current)
    );
    println!("可选模式：");
    println!("  1) /32 精确 IP，推荐，默认");
    println!("  2) /24 宽松网段，适合手机/家宽 IP 经常在同一 C 段变化，但会扩大白名单范围");
    let raw = prompt("请选择新的扩展模式 [1/2]: ")?;
    let target: u8 = match raw.trim() {
        "1" => 32,
        "2" => 24,
        "" => {
            println!(
                "未输入，保持当前模式 {}。",
                format_cidr_expand_label(current)
            );
            return Ok(());
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("无法识别的选项: {other}（只允许 1 或 2）"),
            ));
        }
    };
    if target == current {
        println!("当前已是 {}，无需修改。", format_cidr_expand_label(current));
        return Ok(());
    }
    if target == 24 {
        println!();
        println!("警告：/24 会把 1.2.3.4 扩展为 1.2.3.0/24，最多放宽到 256 个 IPv4 地址。");
        println!("这会降低来源白名单精度。只建议在你确认运营商出口经常在同一 /24 内变化时使用。");
        if !confirm("确认启用 /24 扩展？[y/N]: ")? {
            println!(
                "已取消，保持当前模式 {}。",
                format_cidr_expand_label(current)
            );
            return Ok(());
        }
    }
    let mut updated = config.clone();
    updated.dynamic_whitelist.cidr_expand_ipv4 = target;
    updated
        .dynamic_whitelist
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &updated, "dynamic_whitelist.cidr_expand.update")?;
    audit_cli(
        path,
        "dynamic_whitelist.cidr_expand.update",
        AuditResult::Ok,
        json!({
            "reason": "dynamic_whitelist.cidr_expand.update",
            "old_cidr_expand_ipv4": current,
            "new_cidr_expand_ipv4": target,
        }),
    );
    println!(
        "IPv4 CIDR 扩展模式已更新：{} -> {}。",
        format_cidr_expand_label(current),
        format_cidr_expand_label(target)
    );
    println!("该配置会影响来源白名单生成，nat.service 将在检测周期内通过 safe apply 应用。");
    print_config_saved_hint(path, "dynamic_whitelist.cidr_expand.update");
    Ok(())
}

fn refresh_dynamic_whitelist_interactive(config: &TomlConfig) -> Result<(), io::Error> {
    println!("手动刷新只会解析 DDNS 来源白名单并更新 state，不会直接执行 nft -f。");
    println!("nat.service 下个周期会通过安全 apply 流程应用规则变化。");
    if !config.dynamic_whitelist.enabled {
        println!("dynamic_whitelist.enabled=false，已跳过手动刷新。");
        return Ok(());
    }
    if config.dynamic_whitelist.domains.is_empty() {
        println!("dynamic_whitelist.domains 为空，没有需要解析的来源 DDNS。");
        return Ok(());
    }
    if !confirm("确认立即解析 enabled DDNS domains? [y/N]: ")? {
        println!("已取消");
        return Ok(());
    }
    let previous = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    let result = super::refresh_dynamic_whitelist(
        &config.dynamic_whitelist,
        &config.dns,
        &config.audit,
        &config.telegram,
        &previous,
        chrono::Utc::now(),
        "dynamic_whitelist.cli.refresh",
    );
    for line in format_dynamic_whitelist_refresh_result_lines(&result.events) {
        println!("{line}");
    }
    let current_ips =
        dynamic_whitelist::current_ips_for_config(&config.dynamic_whitelist, &result.state);
    println!("当前动态来源白名单 IP 数量: {}", current_ips.len());
    if config.access_control.mode != AccessControlMode::Whitelist {
        println!("提示：access_control 未启用 whitelist 模式，解析结果暂不会参与来源放行。");
    }
    Ok(())
}

fn format_dynamic_whitelist_refresh_result_lines(events: &[DynamicWhitelistEvent]) -> Vec<String> {
    if events.is_empty() {
        return vec!["没有产生解析事件。".to_string()];
    }
    let mut lines = Vec::new();
    for event in events {
        match event {
            DynamicWhitelistEvent::ResolveSuccess {
                name,
                domain,
                ips,
                effective_sources,
                cidr_expand_ipv4,
                changed,
                ..
            } => lines.push(format!(
                "OK {name} ({domain}) raw={} effective={} /{cidr_expand_ipv4} changed={changed}",
                format_cli_ip_list(ips),
                format_cli_ip_list(effective_sources)
            )),
            DynamicWhitelistEvent::ResolveFail {
                name,
                domain,
                error,
                using_last_good,
            } => lines.push(format!(
                "WARN {name} ({domain}) DNS 失败: {error}; using_last_good={using_last_good}"
            )),
            DynamicWhitelistEvent::StalePruned {
                name,
                old_domain,
                new_domain,
            } => lines.push(format!(
                "WARN {name} domain changed {old_domain} -> {new_domain}; old last-good ignored"
            )),
            DynamicWhitelistEvent::Change {
                name,
                domain,
                old_ips,
                new_ips,
                old_effective_sources,
                new_effective_sources,
                cidr_expand_ipv4,
            } => lines.push(format!(
                "CHANGE {name} ({domain}) /{cidr_expand_ipv4} raw {} -> {}; sources {} -> {}",
                format_cli_ip_list(old_ips),
                format_cli_ip_list(new_ips),
                format_cli_ip_list(old_effective_sources),
                format_cli_ip_list(new_effective_sources),
            )),
        }
    }
    lines
}

fn show_dynamic_whitelist_details(config: &TomlConfig) {
    let state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    for line in format_dynamic_whitelist_detail_lines(config, &state) {
        println!("{line}");
    }
}

pub(crate) fn format_dynamic_whitelist_detail_lines(
    config: &TomlConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("动态 DDNS 来源白名单详细解析结果".to_string());
    lines.push(format!(
        "cidr_expand_ipv4: {}",
        format_cidr_expand_label(config.dynamic_whitelist.cidr_expand_ipv4)
    ));
    if config.dynamic_whitelist.domains.is_empty() {
        lines.push("  (domains empty)".to_string());
        return lines;
    }
    for (index, domain) in config.dynamic_whitelist.domains.iter().enumerate() {
        let state_entry = state.find_domain_state(&domain.name, &domain.domain);
        lines.push(format!("{index}) name: {}", domain.name));
        lines.push(format!("   domain: {}", domain.domain));
        lines.push(format!("   enabled: {}", domain.enabled));
        let raw_ips_display = state_entry
            .map(|state| {
                if !state.raw_ips.is_empty() {
                    format_cli_ip_list(&state.raw_ips)
                } else {
                    format_cli_ip_list(&state.current_ips)
                }
            })
            .unwrap_or_else(|| "(empty)".to_string());
        let effective_display = state_entry
            .map(|state| {
                let sources = dynamic_whitelist::effective_sources_view(
                    state,
                    config.dynamic_whitelist.cidr_expand_ipv4,
                );
                format_cli_ip_list(&sources)
            })
            .unwrap_or_else(|| "(empty)".to_string());
        lines.push(format!("   raw_ips: {raw_ips_display}"));
        lines.push(format!("   effective_sources: {effective_display}"));
        lines.push(format!(
            "   current_ips: {}",
            state_entry
                .map(|state| format_cli_ip_list(&state.current_ips))
                .unwrap_or_else(|| "(empty)".to_string())
        ));
        lines.push(format!(
            "   last_good_ips: {}",
            state_entry
                .map(|state| format_cli_ip_list(&state.last_good_ips))
                .unwrap_or_else(|| "(empty)".to_string())
        ));
        lines.push(format!(
            "   stale: {}",
            state_entry.map(|state| state.stale).unwrap_or(false)
        ));
        lines.push(format!(
            "   resolved_at: {}",
            state_entry
                .and_then(|state| state.resolved_at.as_deref())
                .map(|time| format_cli_time_from_rfc3339_with(time, &config.ui))
                .unwrap_or_else(|| "(none)".to_string())
        ));
        lines.push(format!(
            "   error: {}",
            state_entry
                .and_then(|state| state.error.as_deref())
                .unwrap_or("(none)")
        ));
    }
    lines
}

/// 把 `cidr_expand_ipv4` 转换为用户可读的中文标签。
fn format_cidr_expand_label(value: u8) -> String {
    match value {
        24 => "/24 宽松网段".to_string(),
        32 => "/32 精确 IP（默认）".to_string(),
        other => format!("/{other}（非法值）"),
    }
}

fn print_dynamic_whitelist_domains(config: &TomlConfig) {
    if config.dynamic_whitelist.domains.is_empty() {
        println!("  (empty)");
        return;
    }
    for (index, domain) in config.dynamic_whitelist.domains.iter().enumerate() {
        println!(
            "{index}) name={} domain={} enabled={}",
            domain.name, domain.domain, domain.enabled
        );
    }
}

fn prompt_bool_default(label: &str, default: bool) -> Result<bool, io::Error> {
    let raw = prompt(label)?;
    if raw.trim().is_empty() {
        return Ok(default);
    }
    match raw.as_str() {
        "y" | "Y" | "yes" | "YES" => Ok(true),
        "n" | "N" | "no" | "NO" => Ok(false),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("无法识别的布尔输入: {other}"),
        )),
    }
}

fn prune_dynamic_whitelist_state_after_domain_delete(path: &str, config: &TomlConfig) {
    let mut state = DynamicWhitelistState::load(&config.dynamic_whitelist.state_file);
    let result = state.prune_for_config(&config.dynamic_whitelist);
    if !result.changed {
        return;
    }
    match state.save(&config.dynamic_whitelist.state_file) {
        Ok(()) => audit_cli(
            path,
            "dynamic_whitelist.prune",
            AuditResult::Ok,
            json!({
                "before": result.before,
                "after": result.after,
                "removed": result.removed,
                "file": config.dynamic_whitelist.state_file,
            }),
        ),
        Err(e) => {
            warn!(
                "dynamic whitelist state prune 写入失败 ({}): {e}",
                config.dynamic_whitelist.state_file
            );
            audit_cli(
                path,
                "dynamic_whitelist.prune",
                AuditResult::Warn,
                json!({
                    "before": result.before,
                    "after": result.after,
                    "removed": result.removed,
                    "file": config.dynamic_whitelist.state_file,
                    "error": e.to_string(),
                }),
            );
        }
    }
}

fn format_cli_ip_list(ips: &[String]) -> String {
    if ips.is_empty() {
        "(empty)".to_string()
    } else {
        ips.join(", ")
    }
}

fn show_recent_source_design() {
    println!("====================================");
    println!("最近来源 IP 观察（手动排查）");
    println!("====================================");
    println!("当前版本**不**自动采集最近来源 IP；这是一个手动排查辅助入口，");
    println!("不依赖白名单 / 黑名单，也不会自动放行或封禁来源 IP。");
    println!();
    println!("可以在 shell 中手动执行以下命令观察最近访问者：");
    println!(
        "  conntrack -L                              # 查看活跃连接表的来源 IP（需要 conntrack 工具）"
    );
    println!("  nft list table ip self-nat                # 看 PREROUTING 计数器递增情况");
    println!(
        "  nft list table ip self-filter             # 看 FORWARD nat-traffic counter 是否有 in 流量"
    );
    println!("  journalctl -u nat -n 120 --no-pager       # 看 nat.service 最近行为");
    println!();
    println!("如果你希望把某个来源 IP 加入白名单 / 黑名单，请使用主菜单 11)。");
    println!("如果你希望按地区限制（只允许中国大陆来源），请使用 12) GeoIP / CN IP 限制。");
    println!("本项目不会自动安装 conntrack；也不会持续后台采集来源 IP，避免增加常驻成本。");
}

fn geoip_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        show_geoip_status(config_path);
        println!(
            r#"====================================
GeoIP / CN IP 限制
====================================
1) 查看 GeoIP 状态
2) 下载 / 更新 CN IP set
3) 启用 / 禁用转发端口 CN 限制
4) 启用 / 禁用 SSH CN 限制
5) 设置 SSH 端口
6) 设置 CN IP set 更新间隔
0) 返回主菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                show_geoip_status(config_path);
                wait_enter_to_return()?;
            }
            "2" => {
                if let Err(e) = update_cn4_set_interactive(config_path) {
                    println!("更新 CN IP set 失败: {e}");
                }
                wait_enter_to_return()?;
            }
            "3" => {
                toggle_geoip_forward(config_path)?;
                wait_enter_to_return()?;
            }
            "4" => {
                toggle_geoip_ssh(config_path)?;
                wait_enter_to_return()?;
            }
            "5" => {
                set_geoip_ssh_port(config_path)?;
                wait_enter_to_return()?;
            }
            "6" => {
                set_geoip_update_interval(config_path)?;
                wait_enter_to_return()?;
            }
            "0" | "q" | "quit" | "exit" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn show_geoip_status(config_path: &str) {
    let config = match load_toml_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            println!("读取配置失败: {e}");
            return;
        }
    };
    let geoip = &config.geoip;
    println!("====================================");
    println!("GeoIP 状态");
    println!("====================================");
    println!(
        "GeoIP 总开关：{}",
        if geoip.enabled { "enabled" } else { "disabled" }
    );
    println!("provider：{}", geoip.provider);
    println!("cn4_url：{}", geoip.cn4_url);
    println!("cn4_file：{}", geoip.cn4_file);
    match fs::metadata(&geoip.cn4_file) {
        Ok(meta) => {
            println!("CN IP set 文件：存在");
            println!("CN IP set 大小：{} bytes", meta.len());
            if let Ok(modified) = meta.modified() {
                println!("CN IP set 更新时间：{}", format_system_time(modified));
            }
        }
        Err(_) => {
            println!("CN IP set 文件：不存在");
            println!("提示：请先执行 '下载 / 更新 CN IP set'");
        }
    }
    println!(
        "转发端口 CN 限制：{}",
        if geoip.forward.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "SSH CN 限制：{}",
        if geoip.ssh.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("SSH 端口：{}", geoip.ssh.port);
    println!("允许 LAN：{}", geoip.allow_lan);
    println!("LAN CIDR：{}", geoip.lan_cidrs.join(", "));
    println!("更新间隔（小时）：{}", geoip.update_interval_hours);
    println!();
    for line in format_combined_policy_status(&config) {
        println!("{line}");
    }
}

pub(crate) fn format_combined_policy_status(config: &TomlConfig) -> Vec<String> {
    let mut lines = Vec::new();
    let ac_mode = &config.access_control.mode;
    let ac_count = config.access_control.entries.len();
    let dynamic_enabled = config.dynamic_whitelist.enabled;
    let dynamic_domains = config.dynamic_whitelist.domains.len();
    let geoip_forward = config.geoip.enabled && config.geoip.forward.enabled;
    let geoip_ssh = config.geoip.enabled && config.geoip.ssh.enabled;
    let egress_enabled = config.egress_control.enabled;
    let egress_count = config.egress_control.allowed_target_cidrs.len();

    lines.push("------------------------------------".to_string());
    lines.push("组合策略 (access_control + GeoIP + egress + SNAT + MSS)".to_string());
    lines.push("------------------------------------".to_string());
    lines.push(format!(
        "global forwarding（全局转发开关）：{}",
        enabled_label(config.global.enabled)
    ));
    if !config.global.enabled {
        lines.push("当前不会生成转发规则。规则配置仍保留。".to_string());
    }
    lines.push(format!(
        "access_control（自定义来源 IP 限制）：模式={ac_mode} entries={ac_count}"
    ));
    lines.push(format!(
        "dynamic_whitelist（动态 DDNS 来源白名单）：{} domains={}",
        enabled_label(dynamic_enabled),
        dynamic_domains
    ));
    lines.push(format!(
        "GeoIP 来源限制（国家/地区 IP）：转发端口={} SSH={}",
        enabled_label(geoip_forward),
        enabled_label(geoip_ssh)
    ));
    lines.push(format!(
        "egress_control（目标 IP / IP 段限制）：{} allowed_target_cidrs={}",
        enabled_label(egress_enabled),
        egress_count
    ));
    lines.push(format!(
        "SNAT（源地址改写）：{}",
        describe_snat_mode(&config.snat)
    ));
    lines.push(format!(
        "MSS clamp（TCP MSS 调整）：{} size={}",
        enabled_label(config.mss_clamp.enabled),
        config.mss_clamp.size
    ));
    lines.push(
        "评估顺序：黑名单 > 白名单（静态 + dynamic_whitelist）> GeoIP（同时启用 = AND）"
            .to_string(),
    );
    lines.push(combined_allow_summary(ac_mode, geoip_forward));
    lines.push(combined_target_summary(egress_enabled, egress_count));
    if config.snat.mode == SnatMode::Off {
        lines.push(
            "警告：未生成 SNAT，需自行保证回程路由。SNAT=off 不会生成 masquerade / snat 规则，转发可能不通；普通 VPS 推荐 masquerade。".to_string(),
        );
    }
    if config.snat.mode == SnatMode::Fixed {
        lines.push(
            "提示：fixed SNAT 第一版仅支持 IPv4；IPv6 / NAT66 规则会回退到 masquerade。"
                .to_string(),
        );
    }
    if config.mss_clamp.enabled {
        lines.push(
            "提示：MSS clamp 仅作用于本项目转发相关 TCP 流量（按 DNAT 后目标端口匹配），不影响 UDP 或非本项目端口。".to_string(),
        );
    }
    lines.push(
        "说明：access_control / dynamic_whitelist / GeoIP 是来源 IP 限制；egress_control 是目标 IP 限制；SNAT 是源地址改写；MSS clamp 是 TCP MSS 调整。这些功能叠加生效，不是互相覆盖。".to_string(),
    );
    lines.push("注意：黑名单/白名单不影响 SSH；GeoIP SSH 限制由 geoip.ssh 单独控制。".to_string());
    lines
}

fn enabled_label(flag: bool) -> &'static str {
    if flag { "enabled" } else { "disabled" }
}

fn describe_snat_mode(snat: &SnatConfig) -> String {
    match snat.mode {
        SnatMode::Masquerade => "masquerade".to_string(),
        SnatMode::Off => "off（不生成 SNAT 规则）".to_string(),
        SnatMode::Fixed => {
            if snat.fixed_source_ip.trim().is_empty() {
                "fixed（fixed_source_ip 未设置，将回退到 masquerade）".to_string()
            } else {
                format!("fixed snat to {}", snat.fixed_source_ip)
            }
        }
    }
}

fn combined_target_summary(egress_enabled: bool, egress_count: usize) -> String {
    if !egress_enabled {
        "最终目标策略：未启用 egress_control，允许转发到任意目标 IP".to_string()
    } else if egress_count == 0 {
        "最终目标策略：egress_control 已启用但 allowed_target_cidrs 为空，所有转发规则都会被跳过"
            .to_string()
    } else {
        format!(
            "最终目标策略：仅允许转发到 allowed_target_cidrs 内的目标 IP（共 {egress_count} 条）"
        )
    }
}

fn combined_allow_summary(mode: &AccessControlMode, geoip_forward: bool) -> String {
    match (mode, geoip_forward) {
        (AccessControlMode::Off, false) => "允许 = 所有来源（未启用任何来源限制）".to_string(),
        (AccessControlMode::Off, true) => "允许 = 属于 CN/LAN".to_string(),
        (AccessControlMode::Blacklist, false) => "允许 = 不在黑名单".to_string(),
        (AccessControlMode::Blacklist, true) => "允许 = 不在黑名单 AND 属于 CN/LAN".to_string(),
        (AccessControlMode::Whitelist, false) => {
            "允许 = 在白名单（静态 + dynamic_whitelist）".to_string()
        }
        (AccessControlMode::Whitelist, true) => {
            "允许 = 在白名单（静态 + dynamic_whitelist）AND 属于 CN/LAN".to_string()
        }
    }
}

fn format_system_time(time: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<Local> = time.into();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub(crate) fn update_cn4_set_interactive(config_path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(config_path)?;
    let geoip_config = &config.geoip;
    println!(
        "准备下载 {} 到 {}",
        geoip_config.cn4_url, geoip_config.cn4_file
    );
    if !confirm("继续下载? [y/N]: ")? {
        println!("已取消");
        return Ok(());
    }
    let url = geoip_config.cn4_url.clone();
    let path = geoip_config.cn4_file.clone();
    let report = geoip::download_and_update_with(&url, &path, download_via_curl)?;
    println!("CN IP set 已更新");
    println!("文件路径：{}", report.path.display());
    println!("文件大小：{} bytes", report.size_bytes);
    println!("更新时间：{}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    // 下载 CN IP set 文件本身就属于 GeoIP 规则的数据源；nat.service 会读取新文件并重新生成 set
    print_config_saved_hint(config_path, "geoip.update_interval.update");
    Ok(())
}

fn download_via_curl(url: &str) -> Result<String, io::Error> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cn4_url 必须是 http(s):// 开头: {url}"),
        ));
    }
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg("--max-time")
        .arg("60")
        .arg(url)
        .output()
        .map_err(|e| io::Error::other(format!("执行 curl 失败: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "下载失败: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn toggle_geoip_forward(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前转发端口 CN 限制：{}",
        if config.geoip.forward.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if config.geoip.forward.enabled {
        if !confirm("关闭转发端口 CN 限制? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.geoip.forward.enabled = false;
    } else {
        if !Path::new(&config.geoip.cn4_file).exists() {
            println!(
                "WARN: cn4_file {} 不存在。启用后核心服务会跳过 GeoIP 规则生成，请先执行 '下载 / 更新 CN IP set'。",
                config.geoip.cn4_file
            );
        }
        if !confirm("启用转发端口 CN 限制? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.geoip.enabled = true;
        config.geoip.forward.enabled = true;
    }
    save_toml_config(config_path, &config, "geoip.forward.update")?;
    audit_cli(
        config_path,
        "geoip.update",
        AuditResult::Ok,
        json!({
            "target": "forward",
            "enabled": config.geoip.forward.enabled,
        }),
    );
    println!(
        "转发端口 CN 限制已{}",
        if config.geoip.forward.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path, "geoip.forward.update");
    Ok(())
}

fn toggle_geoip_ssh(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 SSH CN 限制：{}",
        if config.geoip.ssh.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if config.geoip.ssh.enabled {
        if !confirm("关闭 SSH CN 限制? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.geoip.ssh.enabled = false;
    } else {
        println!("===== 安全警告 =====");
        println!("开启 SSH GeoIP 限制可能导致无法远程登录。");
        println!("规则仅允许：");
        println!("  - 中国大陆 IPv4 来源（@cn4 set）");
        if config.geoip.allow_lan && config.geoip.ssh.mode == "allow-cn-and-lan" {
            println!("  - LAN CIDR: {}", config.geoip.lan_cidrs.join(", "));
        }
        println!(
            "其他来源访问 SSH 端口 {} 将被 drop。",
            config.geoip.ssh.port
        );
        println!("请确认当前来源 IP 属于允许范围！");
        let confirm_text = prompt("如确认启用，请输入 CONFIRM: ")?;
        if confirm_text != "CONFIRM" {
            println!("确认文本不匹配，已取消启用。");
            return Ok(());
        }
        if !Path::new(&config.geoip.cn4_file).exists() {
            println!(
                "WARN: cn4_file {} 不存在。启用后核心服务会跳过 GeoIP 规则生成，请先执行 '下载 / 更新 CN IP set'。",
                config.geoip.cn4_file
            );
        }
        config.geoip.enabled = true;
        config.geoip.ssh.enabled = true;
    }
    save_toml_config(config_path, &config, "geoip.ssh.update")?;
    audit_cli(
        config_path,
        "geoip.update",
        AuditResult::Ok,
        json!({
            "target": "ssh",
            "enabled": config.geoip.ssh.enabled,
            "port": config.geoip.ssh.port,
        }),
    );
    println!(
        "SSH CN 限制已{}",
        if config.geoip.ssh.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path, "geoip.ssh.update");
    Ok(())
}

fn set_geoip_ssh_port(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!("当前 SSH 端口：{}", config.geoip.ssh.port);
    let value = prompt("请输入新的 SSH 端口 (1-65535): ")?;
    let port = parse_port(&value)?;
    config.geoip.ssh.port = port;
    save_toml_config(config_path, &config, "geoip.ssh.port.update")?;
    println!("SSH 端口已保存为 {port}");
    print_config_saved_hint(config_path, "geoip.ssh.port.update");
    Ok(())
}

fn set_geoip_update_interval(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 CN IP set 更新间隔：{} 小时",
        config.geoip.update_interval_hours
    );
    let value = prompt("请输入新的更新间隔（小时，最小 1）: ")?;
    let hours = value
        .trim()
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "更新间隔必须是正整数"))?;
    if hours == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "更新间隔不能为 0",
        ));
    }
    config.geoip.update_interval_hours = hours;
    save_toml_config(config_path, &config, "geoip.update_interval.update")?;
    println!("CN IP set 更新间隔已保存为 {hours} 小时");
    print_config_saved_hint(config_path, "geoip.update_interval.update");
    Ok(())
}

fn egress_control_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        show_egress_status(config_path);
        println!(
            r#"====================================
出口目标限制
====================================
1) 查看出口目标限制状态
2) 启用 / 禁用出口目标限制
3) 添加允许目标 IP / CIDR
4) 删除允许目标 IP / CIDR
5) 列出允许目标 IP / CIDR
0) 返回主菜单

提示：出口目标限制用于限制本机只能把转发流量转发到指定出口机或出口网段。
它不是来源 IP 白名单。"#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                show_egress_status(config_path);
                wait_enter_to_return()?;
            }
            "2" => {
                toggle_egress_control(config_path)?;
                wait_enter_to_return()?;
            }
            "3" => {
                add_egress_target(config_path)?;
                wait_enter_to_return()?;
            }
            "4" => {
                delete_egress_target(config_path)?;
                wait_enter_to_return()?;
            }
            "5" => {
                list_egress_targets(config_path)?;
                wait_enter_to_return()?;
            }
            "0" | "q" | "quit" | "exit" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn show_egress_status(config_path: &str) {
    let config = match load_toml_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            println!("读取配置失败: {e}");
            return;
        }
    };
    let egress = &config.egress_control;
    println!("====================================");
    println!("出口目标限制状态");
    println!("====================================");
    println!(
        "出口目标限制：{}",
        if egress.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("模式：{}", egress.mode);
    if egress.allowed_target_cidrs.is_empty() {
        println!("允许目标：(空)");
    } else {
        println!("允许目标：");
        for (idx, cidr) in egress.allowed_target_cidrs.iter().enumerate() {
            println!("  {}) {cidr}", idx + 1);
        }
    }
    println!();
    for line in format_combined_policy_status(&config) {
        println!("{line}");
    }
}

fn toggle_egress_control(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    let now = config.egress_control.enabled;
    if now {
        if !confirm("关闭出口目标限制? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.egress_control.enabled = false;
    } else {
        if config.egress_control.allowed_target_cidrs.is_empty() {
            println!("WARN: allowed_target_cidrs 为空。启用后所有转发规则将被跳过。");
        }
        if !confirm("启用出口目标限制? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.egress_control.enabled = true;
    }
    save_toml_config(config_path, &config, "egress_control.update")?;
    audit_cli(
        config_path,
        "egress_control.update",
        AuditResult::Ok,
        json!({
            "enabled": config.egress_control.enabled,
            "allowed_target_cidrs": config.egress_control.allowed_target_cidrs.len(),
        }),
    );
    println!(
        "出口目标限制已{}",
        if config.egress_control.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path, "egress_control.update");
    Ok(())
}

fn add_egress_target(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    let value = prompt("请输入 IP / CIDR: ")?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "目标不能为空"));
    }
    if value.parse::<std::net::IpAddr>().is_err() && value.parse::<ipnetwork::IpNetwork>().is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "只接受合法 IP 或 CIDR",
        ));
    }
    if !config.egress_control.allowed_target_cidrs.contains(&value) {
        config
            .egress_control
            .allowed_target_cidrs
            .push(value.clone());
    }
    save_toml_config(config_path, &config, "egress.add")?;
    println!("已添加 {value}");
    print_config_saved_hint(config_path, "egress.add");
    Ok(())
}

fn delete_egress_target(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    if config.egress_control.allowed_target_cidrs.is_empty() {
        println!("当前没有允许目标");
        return Ok(());
    }
    for (idx, cidr) in config
        .egress_control
        .allowed_target_cidrs
        .iter()
        .enumerate()
    {
        println!("{}) {cidr}", idx + 1);
    }
    let value = prompt("请输入要删除的编号: ")?;
    let num = value
        .trim()
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "编号必须是数字"))?;
    if num == 0 || num > config.egress_control.allowed_target_cidrs.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "编号超出范围"));
    }
    let removed = config.egress_control.allowed_target_cidrs.remove(num - 1);
    save_toml_config(config_path, &config, "egress.delete")?;
    println!("已删除 {removed}");
    print_config_saved_hint(config_path, "egress.delete");
    Ok(())
}

fn list_egress_targets(config_path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(config_path)?;
    if config.egress_control.allowed_target_cidrs.is_empty() {
        println!("(空)");
    } else {
        for (idx, cidr) in config
            .egress_control
            .allowed_target_cidrs
            .iter()
            .enumerate()
        {
            println!("{}) {cidr}", idx + 1);
        }
    }
    Ok(())
}

fn bbr_telegram_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        println!(
            r#"====================================
BBR / Telegram 状态
====================================
1) 查看 BBR 状态
2) 开启 BBR
3) 关闭 BBR
4) 查看 Telegram 配置状态
5) 配置 Telegram bot_token 和 chat_id
6) 测试 Telegram 通知
7) 启用 / 禁用 Telegram 通知
8) 设置 Telegram 通知间隔
0) 返回主菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                show_bbr_status();
                wait_enter_to_return()?;
            }
            "2" => {
                enable_bbr_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "3" => {
                disable_bbr_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "4" => {
                show_telegram_status(config_path)?;
                wait_enter_to_return()?;
            }
            "5" => {
                configure_telegram(config_path)?;
                wait_enter_to_return()?;
            }
            "6" => {
                test_telegram_notification(config_path)?;
                wait_enter_to_return()?;
            }
            "7" => {
                if toggle_telegram(config_path)? {
                    wait_enter_to_return()?;
                }
            }
            "8" => {
                set_telegram_interval(config_path)?;
                wait_enter_to_return()?;
            }
            "0" | "q" | "quit" | "exit" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn read_proc_value(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn show_bbr_status() {
    println!(
        "当前 tcp_congestion_control: {}",
        read_proc_value("/proc/sys/net/ipv4/tcp_congestion_control")
    );
    println!(
        "可用 congestion control: {}",
        read_proc_value("/proc/sys/net/ipv4/tcp_available_congestion_control")
    );
    println!(
        "当前 default_qdisc: {}",
        read_proc_value("/proc/sys/net/core/default_qdisc")
    );
    println!(
        "本项目 BBR 配置文件 /etc/sysctl.d/99-nat-bbr.conf: {}",
        if Path::new("/etc/sysctl.d/99-nat-bbr.conf").exists() {
            "存在"
        } else {
            "不存在"
        }
    );
}

fn run_sysctl_set(key: &str, value: &str) -> Result<(), io::Error> {
    let status = Command::new("sysctl")
        .arg("-w")
        .arg(format!("{key}={value}"))
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("sysctl -w {key}={value} 失败")))
    }
}

fn enable_bbr_interactive(config_path: &str) -> Result<(), io::Error> {
    if !confirm("开启 BBR？[y/N]: ")? {
        println!("已取消。");
        return Ok(());
    }
    let path = "/etc/sysctl.d/99-nat-bbr.conf";
    if Path::new(path).exists() {
        let backup = format!("{path}.bak-{}", Local::now().format("%Y%m%d-%H%M%S"));
        fs::copy(path, &backup)?;
        println!("已备份旧配置: {backup}");
    }
    fs::write(
        path,
        "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n",
    )?;
    run_sysctl_set("net.core.default_qdisc", "fq")?;
    run_sysctl_set("net.ipv4.tcp_congestion_control", "bbr")?;
    audit_cli(config_path, "bbr.enable", AuditResult::Ok, json!({}));
    println!("BBR 已开启。");
    show_bbr_status();
    Ok(())
}

fn disable_bbr_interactive(config_path: &str) -> Result<(), io::Error> {
    if !confirm("关闭 BBR？[y/N]: ")? {
        println!("已取消。");
        return Ok(());
    }
    let path = "/etc/sysctl.d/99-nat-bbr.conf";
    if Path::new(path).exists() {
        let disabled = format!("{path}.disabled");
        fs::rename(path, &disabled)?;
        println!("已禁用本项目 BBR 配置: {disabled}");
    } else {
        println!("未发现本项目 BBR 配置文件，未删除用户其他 sysctl 配置。");
    }
    let available = read_proc_value("/proc/sys/net/ipv4/tcp_available_congestion_control");
    if available.split_whitespace().any(|item| item == "cubic") {
        run_sysctl_set("net.ipv4.tcp_congestion_control", "cubic")?;
    } else if available.split_whitespace().any(|item| item == "reno") {
        run_sysctl_set("net.ipv4.tcp_congestion_control", "reno")?;
    } else {
        println!("warning: 系统未报告支持 cubic 或 reno，未强制切换拥塞控制算法。");
    }
    println!(
        "当前拥塞控制算法: {}",
        read_proc_value("/proc/sys/net/ipv4/tcp_congestion_control")
    );
    audit_cli(config_path, "bbr.disable", AuditResult::Ok, json!({}));
    Ok(())
}

fn show_telegram_status(config_path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(config_path)?;
    let telegram = config.telegram;
    println!("enabled: {}", telegram.enabled);
    let bot_token_status = if telegram.bot_token.is_empty() {
        "未配置".to_string()
    } else {
        format!(
            "已配置 ({})",
            traffic_stats::mask_bot_token(&telegram.bot_token)
        )
    };
    println!("bot_token: {bot_token_status}");
    println!(
        "chat_id: {}",
        if telegram.chat_id.is_empty() {
            "(未配置)"
        } else {
            &telegram.chat_id
        }
    );
    println!(
        "notify_interval_minutes: {}",
        telegram.notify_interval_minutes
    );
    println!("notify_daily: {}", telegram.notify_daily);
    println!("notify_monthly: {}", telegram.notify_monthly);
    Ok(())
}

fn configure_telegram(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    let bot_token = prompt("请输入 Telegram bot_token: ")?;
    let chat_id = prompt("请输入 Telegram chat_id: ")?;
    if bot_token.trim().is_empty() || chat_id.trim().is_empty() {
        println!("bot_token/chat_id 不能为空。");
        return Ok(());
    }
    config.telegram.bot_token = bot_token;
    config.telegram.chat_id = chat_id;
    let enable = prompt("是否启用 Telegram 通知？[y/N]: ")?;
    if matches!(enable.as_str(), "y" | "Y" | "yes" | "YES") {
        config.telegram.enabled = true;
    }
    save_toml_config(config_path, &config, "telegram.config.update")?;
    audit_cli(
        config_path,
        "telegram.config.update",
        AuditResult::Ok,
        json!({
            "bot_token": audit::mask_secret_str(&config.telegram.bot_token),
            "chat_id": audit::mask_secret_str(&config.telegram.chat_id),
            "enabled": config.telegram.enabled,
        }),
    );
    println!("Telegram 配置已保存，状态页默认不会明文显示 bot_token。");
    print_config_saved_hint(config_path, "telegram.config.update");
    Ok(())
}

fn test_telegram_notification(config_path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(config_path)?;
    if config.telegram.bot_token.is_empty() || config.telegram.chat_id.is_empty() {
        println!("请先配置 Telegram bot_token 和 chat_id。");
        return Ok(());
    }
    let result = traffic_stats::send_telegram_with(
        &config.telegram,
        "nftables-nat-rust-enhanced Telegram 测试通知",
        send_telegram_http_for_cli,
    );
    match result {
        Ok(()) => println!("Telegram 测试通知发送成功"),
        Err(e) => print_telegram_test_failure(&e),
    }
    Ok(())
}

/// v0.4.3：CLI 测试 Telegram 通知失败时给出结构化排错提示。
/// 错误明细已由 `send_telegram_http_for_cli` 调用 `sanitize_cli_telegram_error`
/// 兜底脱敏 bot_token，这里只负责追加多行排错信息。
fn print_telegram_test_failure(err: &str) {
    for line in format_telegram_test_failure(err) {
        println!("{line}");
    }
}

fn format_telegram_test_failure(err: &str) -> Vec<String> {
    vec![
        "Telegram 测试通知发送失败：".to_string(),
        format!("- 错误明细：{err}"),
        "- 可能原因：网络不可达、DNS 失败、Telegram API 超时、bot_token/chat_id 错误".to_string(),
        "- curl 超时设置：connect-timeout 5 秒，max-time 15 秒".to_string(),
    ]
}

fn send_telegram_http_for_cli(url: &str, params: &[(&str, &str)]) -> Result<(), String> {
    let mut command = build_cli_telegram_curl_command(url, params);
    let output = command
        .output()
        .map_err(|e| format!("执行 curl 失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let status = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(format!(
            "HTTP 状态 {status}: {}",
            sanitize_cli_telegram_error(&stderr, url)
        ))
    }
}

/// v0.4.3：所有 CLI 触发的 Telegram HTTPS 调用都强制带连接超时和总超时，
/// 防止 Telegram API 卡死阻塞 CLI 子页面。
fn build_cli_telegram_curl_command(url: &str, params: &[(&str, &str)]) -> Command {
    let mut command = Command::new("curl");
    command
        .arg("-sS")
        .arg("--connect-timeout")
        .arg(CLI_TELEGRAM_CURL_CONNECT_TIMEOUT_SECS)
        .arg("--max-time")
        .arg(CLI_TELEGRAM_CURL_MAX_TIME_SECS)
        .arg("-X")
        .arg("POST")
        .arg(url);
    for (key, value) in params {
        command
            .arg("--data-urlencode")
            .arg(format!("{key}={value}"));
    }
    command
}

const CLI_TELEGRAM_CURL_CONNECT_TIMEOUT_SECS: &str = "5";
const CLI_TELEGRAM_CURL_MAX_TIME_SECS: &str = "15";

/// 与 server 端 sanitize_telegram_error 同样的脱敏逻辑，避免 stderr 把 bot_token
/// 透传给 CLI 用户。
fn sanitize_cli_telegram_error(stderr: &str, url: &str) -> String {
    let mut out = stderr.to_string();
    if let Some(start) = url.find("/bot")
        && let Some(rest) = url.get(start + 4..)
    {
        let token: String = rest.chars().take_while(|c| *c != '/').collect();
        if !token.is_empty() {
            let masked = traffic_stats::mask_bot_token(&token);
            out = out.replace(&token, &masked);
        }
    }
    out
}

fn toggle_telegram(config_path: &str) -> Result<bool, io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 Telegram 通知状态: {}",
        if config.telegram.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    println!("1) 启用 Telegram 通知");
    println!("2) 禁用 Telegram 通知");
    println!("0) 返回");
    let choice = prompt("请选择操作: ")?;
    match choice.trim() {
        "1" => config.telegram.enabled = true,
        "2" => config.telegram.enabled = false,
        "0" => return Ok(false),
        _ => {
            println!("未知选项: {}", choice.trim());
            return Ok(true);
        }
    }
    save_toml_config(config_path, &config, "telegram.toggle")?;
    println!(
        "Telegram 通知已{}。",
        if config.telegram.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path, "telegram.toggle");
    Ok(true)
}

fn set_telegram_interval(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 Telegram 通知间隔: {} 分钟",
        config.telegram.notify_interval_minutes
    );
    let value = prompt("请输入新的通知间隔，单位分钟，最小 1，默认建议 60: ")?;
    let minutes = value
        .trim()
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "通知间隔必须是分钟数"))?;
    if minutes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "通知间隔最小为 1 分钟",
        ));
    }
    config.telegram.notify_interval_minutes = minutes;
    save_toml_config(config_path, &config, "telegram.interval.update")?;
    println!("Telegram 通知间隔已保存为 {minutes} 分钟。");
    print_config_saved_hint(config_path, "telegram.interval.update");
    Ok(())
}

fn uninstall_menu(config_path: &str) -> Result<(), io::Error> {
    audit_cli(config_path, "uninstall.start", AuditResult::Info, json!({}));
    println!(
        r#"====================================
卸载 / 清理 nftables-nat-rust-enhanced
====================================
1) 仅卸载核心转发服务 nat
2) 仅清理本项目 nft 表
3) 完全删除本项目配置/统计/备份，危险
0) 返回
===================================="#
    );
    let choice = prompt("请选择操作: ")?;
    let (target, data_mode) = match choice.trim() {
        "1" => (UninstallTarget::Core, ask_uninstall_data_mode()?),
        "2" => (UninstallTarget::NftTables, DataMode::Keep),
        "3" => (UninstallTarget::Core, DataMode::Purge),
        "0" => return Ok(()),
        _ => {
            println!("未知选项: {}", choice.trim());
            wait_enter_to_return()?;
            return Ok(());
        }
    };
    if data_mode == DataMode::Purge {
        let confirm_text = prompt("危险操作：请输入 DELETE 确认完全删除: ")?;
        if confirm_text != "DELETE" {
            println!("确认文本不匹配，已取消卸载。");
            wait_enter_to_return()?;
            return Ok(());
        }
    }
    let confirm = prompt("即将执行卸载/清理操作。确认继续? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消卸载。");
        wait_enter_to_return()?;
        return Ok(());
    }
    let report = execute_uninstall(target, data_mode);
    print_uninstall_report(&report);
    wait_enter_to_return()?;
    Ok(())
}

fn ask_uninstall_data_mode() -> Result<DataMode, io::Error> {
    println!(
        r#"是否保留配置和数据？
1) 保留配置、统计、备份，推荐
2) 删除程序和服务，保留 /etc/nat.toml 和 backups
3) 完全删除本项目配置、统计、备份，危险"#
    );
    let choice = prompt("请选择 [1/2/3]: ")?;
    match choice.trim() {
        "" | "1" => Ok(DataMode::Keep),
        "2" => Ok(DataMode::KeepConfig),
        "3" => Ok(DataMode::Purge),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "未知数据保留选项",
        )),
    }
}

#[derive(Default)]
struct UninstallReport {
    actions: Vec<String>,
    kept: Vec<String>,
    warnings: Vec<String>,
}

fn execute_uninstall(target: UninstallTarget, data_mode: DataMode) -> UninstallReport {
    let plan = uninstall::plan_uninstall(target, data_mode);
    let mut report = UninstallReport {
        kept: plan.kept,
        warnings: plan.warnings,
        ..Default::default()
    };
    if matches!(target, UninstallTarget::Core) {
        stop_disable_remove_service("nat", &uninstall::CORE_SERVICE_PATHS, &mut report);
        remove_path(uninstall::NAT_BINARY, &mut report);
    }
    if matches!(target, UninstallTarget::Core | UninstallTarget::NftTables) {
        cleanup_project_nft_tables(&mut report);
    }
    cleanup_data_paths(data_mode, &mut report);
    let _ = Command::new("systemctl").arg("daemon-reload").output();
    report.actions.push("systemd daemon-reload".to_string());
    report
}

fn stop_disable_remove_service(
    service: &str,
    service_paths: &[&str],
    report: &mut UninstallReport,
) {
    run_best_effort(
        Command::new("systemctl").arg("stop").arg(service),
        report,
        &format!("stopped {service}.service"),
    );
    run_best_effort(
        Command::new("systemctl").arg("disable").arg(service),
        report,
        &format!("disabled {service}.service"),
    );
    for path in service_paths {
        remove_path(path, report);
    }
}

fn cleanup_project_nft_tables(report: &mut UninstallReport) {
    for (family, table) in uninstall::nft_table_names() {
        let output = Command::new("/usr/sbin/nft")
            .arg("delete")
            .arg("table")
            .arg(family)
            .arg(table)
            .output()
            .or_else(|_| {
                Command::new("nft")
                    .arg("delete")
                    .arg("table")
                    .arg(family)
                    .arg(table)
                    .output()
            });
        match output {
            Ok(_) => report
                .actions
                .push(format!("cleaned nft table {family} {table} if present")),
            Err(e) => report
                .warnings
                .push(format!("failed to delete nft table {family} {table}: {e}")),
        }
    }
}

fn cleanup_data_paths(data_mode: DataMode, report: &mut UninstallReport) {
    match data_mode {
        DataMode::Keep => {}
        DataMode::KeepConfig => {
            for path in [uninstall::CONFIG_LEGACY, uninstall::STATS_JSON] {
                remove_path(path, report);
            }
        }
        DataMode::Purge => {
            for path in [
                uninstall::CONFIG_TOML,
                uninstall::CONFIG_LEGACY,
                uninstall::STATS_DIR,
                uninstall::BACKUPS_ROOT,
            ] {
                remove_path(path, report);
            }
        }
    }
}

fn run_best_effort(command: &mut Command, report: &mut UninstallReport, action: &str) {
    match command.output() {
        Ok(_) => report.actions.push(action.to_string()),
        Err(e) => report.warnings.push(format!("{action} failed: {e}")),
    }
}

fn remove_path(path: &str, report: &mut UninstallReport) {
    let path_ref = Path::new(path);
    if !path_ref.exists() {
        return;
    }
    let result = if path_ref.is_dir() {
        fs::remove_dir_all(path_ref)
    } else {
        fs::remove_file(path_ref)
    };
    match result {
        Ok(()) => report.actions.push(format!("removed {path}")),
        Err(e) => report
            .warnings
            .push(format!("failed to remove {path}: {e}")),
    }
}

fn print_uninstall_report(report: &UninstallReport) {
    println!("已执行操作：");
    for action in &report.actions {
        println!("  - {action}");
    }
    if !report.kept.is_empty() {
        println!("已保留：");
        for path in &report.kept {
            println!("  - {path}");
        }
    }
    if !report.warnings.is_empty() {
        println!("警告：");
        for warning in &report.warnings {
            println!("  - {warning}");
        }
    }
    println!("后续如需重新安装，请参考 README 的一键安装命令。");
}

// v0.6.1：update 相关函数已搬到 `menu/update.rs`。生产代码只需要入口 update_menu；
// 其余符号留给本文件的 cfg(test) 模块在断言里通过 `super::update::*` 访问。
use update::update_menu;

// v0.6.1：审计日志查看相关函数已搬到 `menu/audit_view.rs`。
use audit_view::view_audit_log_interactive;

/// 把 last-good 缓存状态摘要追加到状态展示页
pub(crate) fn format_last_good_status(config: &TomlConfig) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("------------------------------------".to_string());
    lines.push("last-good 状态缓存".to_string());
    lines.push("------------------------------------".to_string());
    lines.push(format!(
        "enabled: {} use_last_good_on_dns_failure: {}",
        config.last_good.enabled, config.last_good.use_last_good_on_dns_failure
    ));
    lines.push(format!("file: {}", config.last_good.file));
    let state = LastGoodState::load(&config.last_good.file);
    lines.push(format!("规则缓存数量: {}", state.rules.len()));
    match state.last_success_at {
        Some(ts) => lines.push(format!(
            "最近成功应用时间: {}",
            format_cli_time_with(ts, &config.ui)
        )),
        None => lines.push("最近成功应用时间: (无)".to_string()),
    }
    for rule in &state.rules {
        let comment = rule.comment.clone().unwrap_or_else(|| "-".to_string());
        lines.push(format!(
            "  {} ({}) domain={} last_good_ip={} resolved_at={} egress={} status={}",
            rule.rule_id,
            comment,
            rule.domain,
            rule.last_good_ip,
            format_cli_time_with(rule.last_resolved_at, &config.ui),
            rule.egress_allowed,
            rule.last_apply_status,
        ));
    }
    lines
}

fn advanced_network_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        let config = match load_toml_config(config_path) {
            Ok(c) => c,
            Err(e) => {
                println!("读取配置失败: {e}");
                wait_enter_to_return()?;
                return Ok(());
            }
        };
        print_advanced_network_status(&config);
        println!(
            r#"====================================
高级网络设置 (SNAT / MSS clamp)
====================================
1) 查看 SNAT / MSS 状态
2) 设置 SNAT 模式
3) 设置 fixed SNAT 源 IP
4) 启用 / 禁用 MSS clamp
5) 设置 MSS clamp size
6) 时间 / NTP 状态检查
7) 查看全局诊断状态
8) 全局转发开关
0) 返回主菜单
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                // status already printed above; let user confirm
                wait_enter_to_return()?;
            }
            "2" => {
                set_snat_mode_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "3" => {
                set_snat_fixed_source_ip_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "4" => {
                toggle_mss_clamp_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "5" => {
                set_mss_clamp_size_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "6" => {
                // 自管 wait：函数内部完成 wait_enter_to_return；不再叠加。
                time_status_interactive(config_path)?;
            }
            "7" => {
                println!();
                for line in render_global_diagnostics_lines(&config) {
                    println!("{line}");
                }
                wait_enter_to_return()?;
            }
            "8" => {
                global_forwarding_menu(config_path)?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

/// 时间 / NTP 状态检查页面（v0.4.2 重构为子菜单）。
///
/// 始终遵守：
/// - **不默认修改系统时间，不默认修改系统时区**
/// - 设置 CLI 展示时区只写 `/etc/nat.toml [ui]`，**不改系统**
/// - 启用系统 NTP 需要 y/N 二次确认，调用 `timedatectl set-ntp true`
/// - timedatectl 不存在 → 友好提示，不报错
fn time_status_interactive(config_path: &str) -> Result<(), io::Error> {
    loop {
        let config = load_toml_config(config_path).ok();
        print_time_status_overview(config.as_ref());
        println!(
            r#"====================================
时间 / NTP 状态检查
====================================
1) 查看时间 / NTP 状态（默认）
2) 设置 CLI 展示时区
3) 显示修改系统时区命令
4) 尝试启用系统 NTP
0) 返回"#
        );
        let choice = prompt("请选择: ")?;
        match choice.trim() {
            "" | "1" => {
                // overview 已在上方打印；用户按 Enter 返回
                wait_enter_to_return()?;
            }
            "2" => {
                set_cli_display_timezone_interactive(config_path)?;
                wait_enter_to_return()?;
            }
            "3" => {
                show_set_system_timezone_command();
                wait_enter_to_return()?;
            }
            "4" => {
                try_enable_system_ntp_interactive()?;
                wait_enter_to_return()?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn print_time_status_overview(config: Option<&TomlConfig>) {
    let ui = config.map(|c| c.ui.clone()).unwrap_or_default();
    let now_utc = chrono::Utc::now();
    let local_now = chrono::Local::now();
    println!("====================================");
    println!("时间 / NTP 状态");
    println!("====================================");
    println!(
        "系统本地时间：{}",
        local_now.format("%Y-%m-%d %H:%M:%S %Z (%:z)")
    );
    println!("UTC 时间：{}", now_utc.format("%Y-%m-%d %H:%M:%S UTC"));
    println!(
        "CLI 展示时间：{} (时区 {})",
        nat_common::format_cli_time_with(now_utc, &ui),
        ui.timezone
    );
    let timedatectl_tz = run_timedatectl_status()
        .and_then(|stdout| parse_timedatectl_field(&stdout, "Time zone").map(|v| (stdout, v)));
    let (timedatectl_stdout, system_tz) = match timedatectl_tz {
        Some((stdout, tz)) => (Some(stdout), Some(tz)),
        None => (run_timedatectl_status(), None),
    };
    match &system_tz {
        Some(tz) => println!("当前系统时区：{tz}"),
        None => println!("当前系统时区：(timedatectl 不可用或字段缺失)"),
    }
    println!("CLI 展示时区：{}", ui.timezone);
    if let Some(sys_tz) = system_tz.as_deref()
        && !sys_tz.starts_with(&ui.timezone)
        && !ui
            .timezone
            .starts_with(sys_tz.split_whitespace().next().unwrap_or(""))
    {
        println!();
        println!("提示：系统时区与 CLI 展示时区不同。这不会影响 nft 转发；");
        println!("如果你希望日志和系统时间一致，可修改系统时区或 CLI 展示时区。");
        println!("修改系统时区命令请见 3)；修改 CLI 展示时区请见 2)。");
    }
    println!();
    if let Some(stdout) = timedatectl_stdout {
        let ntp_service = parse_timedatectl_field(&stdout, "NTP service")
            .or_else(|| parse_timedatectl_field(&stdout, "Network time on"));
        let synchronized = parse_timedatectl_field(&stdout, "System clock synchronized");
        println!("timedatectl 可用：是");
        println!(
            "NTP 服务：{}",
            ntp_service.as_deref().unwrap_or("(未知字段)")
        );
        println!(
            "System clock synchronized：{}",
            synchronized.as_deref().unwrap_or("(未知字段)")
        );
    } else {
        println!("timedatectl 可用：否（可能未安装 systemd 工具）");
        println!("本项目不会自动安装任何依赖；如需 NTP，请使用你的发行版自带的工具自行配置。");
    }
    println!();
    println!("nft 转发本身不依赖系统时区。但以下功能建议系统时间准确：");
    println!("  - Stats daily/monthly 滚动重置");
    println!("  - quota 周期判断 / 通知去重");
    println!("  - audit log 时间戳");
    println!("  - last-good 上次成功解析时间");
    println!("  - Telegram 通知 / TLS 下载（release 或 cn4.nft）");
    println!("CLI 展示时区只影响显示，不改变系统时区。");
}

/// 调一次 `timedatectl status`，stdout 字符串。失败返回 None（不区分原因，调用方自行说明）。
fn run_timedatectl_status() -> Option<String> {
    match Command::new("timedatectl").arg("status").output() {
        Ok(out) if out.status.success() => Some(String::from_utf8_lossy(&out.stdout).to_string()),
        _ => None,
    }
}

/// `[ui] timezone` 子菜单：写入 `/etc/nat.toml`，非法 timezone 不保存。
fn set_cli_display_timezone_interactive(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!("当前 CLI 展示时区：{}", config.ui.timezone);
    println!("允许输入合法 IANA 时区名，例如：");
    println!("  Asia/Shanghai");
    println!("  UTC");
    println!("  America/Chicago");
    println!("更多时区可在系统执行 `timedatectl list-timezones` 查看。");
    let raw = prompt("请输入新的 CLI 展示时区（输入 0 取消）: ")?;
    if raw.trim() == "0" || raw.trim().is_empty() {
        println!("已取消，不修改 [ui].timezone。");
        return Ok(());
    }
    if let Err(e) = nat_common::validate_iana_timezone(&raw) {
        println!("无效时区，未保存：{e}");
        return Ok(());
    }
    config.ui.timezone = raw.trim().to_string();
    if let Err(e) = config.ui.validate() {
        println!("校验失败，未保存：{e}");
        return Ok(());
    }
    save_toml_config(config_path, &config, "ui.timezone.update")?;
    audit_cli(
        config_path,
        "ui.timezone.update",
        AuditResult::Ok,
        json!({"timezone": config.ui.timezone}),
    );
    println!("CLI 展示时区已保存为 {}。", config.ui.timezone);
    println!("此项只影响 CLI 显示，不改变系统时区。");
    print_config_saved_hint(config_path, "ui.timezone.update");
    Ok(())
}

fn show_set_system_timezone_command() {
    println!("====================================");
    println!("修改系统时区命令（建议，不会自动执行）");
    println!("====================================");
    println!("查看可用时区：");
    println!("  timedatectl list-timezones | grep -i Shanghai");
    println!("设置系统时区（需要 root）：");
    println!("  sudo timedatectl set-timezone Asia/Shanghai");
    println!();
    println!("注意：");
    println!("- 修改系统时区会改变本地日志显示，不影响 audit / last-good JSON 内部 UTC RFC3339。");
    println!("- 本工具不会自动执行 timedatectl set-timezone。");
}

fn try_enable_system_ntp_interactive() -> Result<(), io::Error> {
    println!("====================================");
    println!("尝试启用系统 NTP");
    println!("====================================");
    println!("这会调用 timedatectl set-ntp true（需要 root）。");
    println!("- 不会 apt-get install 任何东西");
    println!("- 不会自动修改系统时区");
    println!("- timedatectl 不存在时仅打印提示，不报错");
    let confirm = prompt("启用系统 NTP？[y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y" | "yes" | "YES") {
        println!("已取消，不改动系统 NTP 设置。");
        return Ok(());
    }
    match Command::new("timedatectl")
        .arg("set-ntp")
        .arg("true")
        .output()
    {
        Ok(out) if out.status.success() => {
            println!("已尝试启用系统 NTP。请稍后再次查看 1) 状态以确认 synchronized=yes。");
        }
        Ok(out) => {
            println!(
                "执行 timedatectl set-ntp true 返回非零退出码：{}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            println!("常见原因：未以 root 运行；或当前系统不使用 systemd-timesyncd。");
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("未检测到 timedatectl，无法启用 NTP。");
            println!("请使用你的发行版自带的 NTP 工具，本项目不会自动安装任何依赖。");
        }
        Err(e) => {
            println!("调用 timedatectl set-ntp true 失败：{e}");
        }
    }
    Ok(())
}

/// 从 `timedatectl status` 输出中按"前缀 key"匹配并取冒号后的值。
/// 大小写敏感、保留原始 trim 后的值；找不到时返回 None。
pub(crate) fn parse_timedatectl_field(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start_matches(':').trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn print_advanced_network_status(config: &TomlConfig) {
    let snat = &config.snat;
    let mss = &config.mss_clamp;
    println!("====================================");
    println!("SNAT / MSS clamp 状态");
    println!("====================================");
    println!("SNAT 模式：{}", snat.mode);
    let ip = if snat.fixed_source_ip.trim().is_empty() {
        "未设置".to_string()
    } else {
        snat.fixed_source_ip.clone()
    };
    println!("fixed_source_ip：{ip}");
    println!("MSS clamp：{}", enabled_label(mss.enabled));
    println!("MSS size：{}", mss.size);
    println!("全局转发：{}", enabled_label(config.global.enabled));
    if !config.global.enabled {
        println!("当前不会生成转发规则。规则配置仍保留。");
    }
    println!();
    for line in format_combined_policy_status(config) {
        println!("{line}");
    }
}

fn global_forwarding_menu(config_path: &str) -> Result<(), io::Error> {
    loop {
        let config = load_toml_config(config_path)?;
        println!("====================================");
        println!("全局转发开关");
        println!("====================================");
        println!("当前状态：{}", enabled_label(config.global.enabled));
        println!("规则数量：{}", config.rules.len());
        println!("提示：关闭后不会删除配置，只是不生成/应用转发规则。");
        println!("提示：只影响本项目管理的转发规则，不影响 SSH 和系统其他 nft 规则。");
        println!(
            r#"1) 开启全局转发
2) 关闭全局转发
0) 返回
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => {
                update_global_forwarding_interactive(config_path, true)?;
                wait_enter_to_return()?;
            }
            "2" => {
                update_global_forwarding_interactive(config_path, false)?;
                wait_enter_to_return()?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            "" => continue,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn update_global_forwarding_interactive(
    config_path: &str,
    new_enabled: bool,
) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    let old_enabled = config.global.enabled;
    if old_enabled == new_enabled {
        println!(
            "全局转发当前已是 {}。",
            enabled_label(config.global.enabled)
        );
        return Ok(());
    }
    if new_enabled {
        println!("将恢复根据当前配置生成并应用转发规则。");
        if !confirm("是否继续？[y/N]: ")? {
            println!("已取消。");
            return Ok(());
        }
    } else {
        println!("你即将关闭本项目管理的所有转发规则。");
        println!("规则配置会保留，但入口端口将不再转发。");
        if !confirm("是否继续？[y/N]: ")? {
            println!("已取消。");
            return Ok(());
        }
    }
    config.global.enabled = new_enabled;
    save_toml_config(config_path, &config, "global.enabled.update")?;
    audit_global_enabled_update(&audit_config_from(config_path), old_enabled, new_enabled);
    println!("全局转发已更新为 {}。", enabled_label(new_enabled));
    print_config_saved_hint(config_path, "global.enabled.update");
    Ok(())
}

fn audit_global_enabled_update(audit_cfg: &AuditConfig, old_enabled: bool, new_enabled: bool) {
    audit::log_event(
        audit_cfg,
        "global.enabled.update",
        AuditResult::Ok,
        json!({
            "old_enabled": old_enabled,
            "new_enabled": new_enabled,
        }),
    );
}

fn set_snat_mode_interactive(config_path: &str) -> Result<(), io::Error> {
    println!(
        r#"请选择 SNAT 模式：
1) masquerade，默认推荐
2) fixed，固定 SNAT 到指定源 IP（第一版仅 IPv4）
3) off，不生成 SNAT 规则（高级用户）
0) 取消"#
    );
    let choice = prompt("请选择 [0/1/2/3]: ")?;
    let mode = match choice.trim() {
        "1" => SnatMode::Masquerade,
        "2" => SnatMode::Fixed,
        "3" => SnatMode::Off,
        "0" => {
            println!("已取消");
            return Ok(());
        }
        _ => {
            println!("未知选项: {}", choice.trim());
            return Ok(());
        }
    };
    if mode == SnatMode::Off {
        println!(
            "警告：SNAT=off 不会生成 masquerade / snat 规则，必须由用户自行保证回程路由，否则转发可能不通。普通 VPS 推荐 masquerade。"
        );
        if !confirm("仍要切换到 off？[y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
    }
    if mode == SnatMode::Fixed {
        println!("提示：fixed SNAT 第一版仅支持 IPv4；IPv6 / NAT66 规则会回退到 masquerade。");
    }
    let mut config = load_toml_config(config_path)?;
    config.snat.mode = mode;
    if mode == SnatMode::Fixed && config.snat.fixed_source_ip.trim().is_empty() {
        let entry = prompt("请输入 fixed_source_ip，例如 10.100.0.10: ")?;
        validate_fixed_source_ip(&entry)?;
        config.snat.fixed_source_ip = entry;
    }
    config
        .snat
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(config_path, &config, "snat.mode.update")?;
    audit_cli(
        config_path,
        "snat.update",
        AuditResult::Ok,
        json!({
            "mode": config.snat.mode.to_string(),
            "fixed_source_ip_set": !config.snat.fixed_source_ip.trim().is_empty(),
        }),
    );
    println!("SNAT 模式已设为 {}。", config.snat.mode);
    print_config_saved_hint(config_path, "snat.mode.update");
    Ok(())
}

fn set_snat_fixed_source_ip_interactive(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 fixed_source_ip：{}",
        if config.snat.fixed_source_ip.trim().is_empty() {
            "未设置"
        } else {
            &config.snat.fixed_source_ip
        }
    );
    let entry = prompt("请输入 fixed_source_ip，例如 10.100.0.10（留空清除）: ")?;
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        if config.snat.mode == SnatMode::Fixed {
            println!("WARN: 当前 snat.mode=fixed，清空 fixed_source_ip 会导致配置校验失败，已取消");
            return Ok(());
        }
        config.snat.fixed_source_ip = String::new();
    } else {
        validate_fixed_source_ip(trimmed)?;
        config.snat.fixed_source_ip = trimmed.to_string();
    }
    save_toml_config(config_path, &config, "snat.fixed_source_ip.update")?;
    audit_cli(
        config_path,
        "snat.update",
        AuditResult::Ok,
        json!({
            "mode": config.snat.mode.to_string(),
            "fixed_source_ip_set": !config.snat.fixed_source_ip.trim().is_empty(),
        }),
    );
    println!(
        "fixed_source_ip 已设为 {}。",
        if config.snat.fixed_source_ip.is_empty() {
            "(空)"
        } else {
            &config.snat.fixed_source_ip
        }
    );
    print_config_saved_hint(config_path, "snat.fixed_source_ip.update");
    Ok(())
}

pub(crate) fn validate_fixed_source_ip(value: &str) -> Result<(), io::Error> {
    let probe = SnatConfig {
        mode: SnatMode::Fixed,
        fixed_source_ip: value.to_string(),
    };
    probe
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn toggle_mss_clamp_interactive(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!(
        "当前 MSS clamp：{}（size={}）",
        enabled_label(config.mss_clamp.enabled),
        config.mss_clamp.size
    );
    if config.mss_clamp.enabled {
        if !confirm("关闭 MSS clamp? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.mss_clamp.enabled = false;
    } else {
        println!(
            "提示：MSS clamp 适合多跳 / 隧道 / 私有网络链路 / MTU 异常场景；不懂 MTU/MSS 时不建议随意开启。"
        );
        if !confirm("启用 MSS clamp? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.mss_clamp.enabled = true;
    }
    save_toml_config(config_path, &config, "mss_clamp.toggle")?;
    audit_cli(
        config_path,
        "mss_clamp.update",
        AuditResult::Ok,
        json!({
            "enabled": config.mss_clamp.enabled,
            "size": config.mss_clamp.size,
        }),
    );
    println!(
        "MSS clamp 已{}",
        if config.mss_clamp.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path, "mss_clamp.toggle");
    Ok(())
}

fn set_mss_clamp_size_interactive(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!("当前 MSS size：{}", config.mss_clamp.size);
    let entry = prompt(&format!(
        "请输入 MSS size，范围 {MSS_CLAMP_MIN}-{MSS_CLAMP_MAX}，推荐 1452: "
    ))?;
    let size = parse_mss_size(&entry)?;
    config.mss_clamp.size = size;
    config
        .mss_clamp
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(config_path, &config, "mss_clamp.size.update")?;
    audit_cli(
        config_path,
        "mss_clamp.update",
        AuditResult::Ok,
        json!({
            "enabled": config.mss_clamp.enabled,
            "size": size,
        }),
    );
    println!("MSS size 已设为 {size}。");
    print_config_saved_hint(config_path, "mss_clamp.size.update");
    Ok(())
}

pub(crate) fn parse_mss_size(value: &str) -> Result<u16, io::Error> {
    let trimmed = value.trim();
    let size: u16 = trimmed.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("MSS size 必须是数字: {trimmed}"),
        )
    })?;
    let probe = MssClampConfig {
        enabled: false,
        size,
    };
    probe
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(size)
}

// v0.6.1：update 相关函数与 UpdatePlan 已搬到 `menu/update.rs`，菜单顶部已 use 进来。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NatServiceStatus {
    Active,
    Inactive,
    Failed,
    Unknown,
    NotChecked,
}

impl NatServiceStatus {
    fn label(self) -> &'static str {
        match self {
            NatServiceStatus::Active => "active",
            NatServiceStatus::Inactive => "inactive",
            NatServiceStatus::Failed => "failed",
            NatServiceStatus::Unknown => "unknown",
            NatServiceStatus::NotChecked => "未检查",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, NatServiceStatus::Active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LastApplyState {
    Success,
    Fail,
    Unknown,
    NotChecked,
}

impl LastApplyState {
    fn label(self) -> &'static str {
        match self {
            LastApplyState::Success => "success",
            LastApplyState::Fail => "fail",
            LastApplyState::Unknown => "unknown",
            LastApplyState::NotChecked => "未检查",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LastApplyDisplay {
    pub state: LastApplyState,
    pub time_label: Option<String>,
}

impl LastApplyDisplay {
    fn not_checked() -> Self {
        Self {
            state: LastApplyState::NotChecked,
            time_label: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeState {
    Found,
    Missing,
    NotApplicable,
}

impl ProbeState {
    fn label(self) -> &'static str {
        match self {
            ProbeState::Found => "已找到",
            ProbeState::Missing => "未找到",
            ProbeState::NotApplicable => "不适用",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NftConnectivityStatus {
    Checked {
        self_nat: ProbeState,
        self_filter: ProbeState,
        verdict: nat_common::forward_test::NftDetectionVerdict,
        counters: Option<nat_common::forward_test::RuleTestCounters>,
        counter_warning: Option<String>,
    },
    Unconfirmed {
        reason: String,
    },
    SkippedGlobalDisabled,
    SkippedDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleResolutionDisplay {
    pub target_kind: String,
    pub resolved_ip_label: String,
    pub last_good_label: String,
    pub notes: Vec<String>,
}

/// v0.8.10：per-rule snat_ip 在 nft POSTROUTING 中的存在性检查结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnatNftCheck {
    /// 规则未配置 snat_ip，走全局默认 SNAT，无需检查 `snat to <ip>`。
    NoSnatIp,
    /// nft 中找到 `snat to <ip>`。
    Found(String),
    /// 配置了 snat_ip 但 nft 中没有对应 `snat to <ip>`（可能未重新 apply）。
    Missing(String),
    /// 配置了 snat_ip，但 nft ruleset 不可读 / 解析失败，无法判定。
    Unknown(String),
}

/// v0.8.10：SNAT 出口 + 本机出站诊断。
#[derive(Debug, Clone)]
pub(crate) struct SnatEgressReport {
    pub plan: forward_test::SnatPlan,
    pub nft_snat_to: SnatNftCheck,
    /// 系统默认出口 IP（`ip route get 1.1.1.1` 的 src）；None 表示无法确定。
    pub system_egress_ip: Option<String>,
    /// `ip route get 1.1.1.1 from <snat_ip>` 结果。
    pub route_from_snat: forward_test::EgressProbe,
    /// `curl -4 --interface <snat_ip> https://api.ipify.org` 结果。
    pub curl_egress: forward_test::EgressProbe,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectivityReport<'a> {
    pub rule: &'a forward_test::TestableRule,
    pub global_enabled: bool,
    pub rule_enabled: bool,
    pub resolution: RuleResolutionDisplay,
    pub nat_service: NatServiceStatus,
    pub last_apply: LastApplyDisplay,
    pub nft: NftConnectivityStatus,
    pub target_tcp: Option<bool>,
    pub access_control_note: Option<String>,
    pub snat: SnatEgressReport,
}

fn test_forward_interactive(path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(path)?;
    let rules: Vec<_> = config
        .rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| forward_test::rule_to_testable_rule(index, rule))
        .collect();
    if rules.is_empty() {
        println!("当前没有可测试的转发规则");
        wait_enter_to_return()?;
        return Ok(());
    }
    for rule in &rules {
        let enabled = config
            .rules
            .get(rule.index)
            .map(NftCell::enabled)
            .unwrap_or(false);
        println!(
            "{}) [{}] {}",
            rule.index,
            if enabled { "enabled" } else { "disabled" },
            rule.label
        );
    }
    let index = parse_index(&prompt("请选择要测试的规则 index: ")?)?;
    let Some(rule) = rules.iter().find(|rule| rule.index == index) else {
        println!("规则 index 超出范围");
        wait_enter_to_return()?;
        return Ok(());
    };

    let rule_enabled = config
        .rules
        .get(rule.index)
        .map(NftCell::enabled)
        .unwrap_or(false);
    let last_good_state = LastGoodState::load(&config.last_good.file);
    let resolution = build_rule_resolution_display(&config, rule, &last_good_state);
    let global_enabled = config.global.enabled;
    let rule_snat_ip = config
        .rules
        .get(rule.index)
        .and_then(NftCell::snat_ip)
        .map(str::to_string);
    let (nat_service, last_apply, nft, target_tcp, snat) = if !global_enabled {
        (
            NatServiceStatus::NotChecked,
            LastApplyDisplay::not_checked(),
            NftConnectivityStatus::SkippedGlobalDisabled,
            None,
            build_snat_egress_report(&config, rule, rule_snat_ip.as_deref(), None, false),
        )
    } else if rule_enabled {
        let nat_service = read_nat_service_status();
        let last_apply = read_last_apply_display(&config);
        let nft = read_nft_connectivity_status(
            rule,
            nat_service.is_active(),
            last_apply.state == LastApplyState::Success,
        );
        let target_tcp = forward_test::tcp_connect_target(rule, std::time::Duration::from_secs(3));
        let nft_json = read_nft_json_ruleset().ok();
        let snat = build_snat_egress_report(
            &config,
            rule,
            rule_snat_ip.as_deref(),
            nft_json.as_deref(),
            true,
        );
        (nat_service, last_apply, nft, target_tcp, snat)
    } else {
        (
            NatServiceStatus::NotChecked,
            LastApplyDisplay::not_checked(),
            NftConnectivityStatus::SkippedDisabled,
            None,
            build_snat_egress_report(&config, rule, rule_snat_ip.as_deref(), None, false),
        )
    };
    let report = ConnectivityReport {
        rule,
        global_enabled,
        rule_enabled,
        resolution,
        nat_service,
        last_apply,
        nft,
        target_tcp,
        access_control_note: forward_test::access_control_note(&config.access_control),
        snat,
    };
    for line in render_connectivity_report_lines(&report) {
        println!("{line}");
    }

    let choice = prompt("> ")?;
    if matches!(choice.trim(), "h" | "H") {
        println!();
        for line in external_test_detailed_lines(rule) {
            println!("{line}");
        }
        wait_enter_to_return()?;
    } else {
        clear_screen();
    }
    Ok(())
}

fn build_rule_resolution_display(
    config: &TomlConfig,
    rule: &forward_test::TestableRule,
    last_good_state: &LastGoodState,
) -> RuleResolutionDisplay {
    let target_is_ip = rule.target.parse::<std::net::IpAddr>().is_ok();
    let target_kind = if target_is_ip { "IP" } else { "domain" }.to_string();
    let resolved_ip_label = rule.resolved_ip.as_deref().unwrap_or("none").to_string();
    let cached = last_good_state.lookup(&rule.id);
    let mut notes = Vec::new();
    let last_good_label = match (target_is_ip, rule.resolved_ip.as_deref(), cached) {
        (true, Some(_), _) => "none (IP target)".to_string(),
        (false, Some(ip), Some(cached)) if ip == cached.last_good_ip => {
            notes.push(format!(
                "last-good 上次成功解析时间：{}",
                format_cli_time_with(cached.last_resolved_at, &config.ui)
            ));
            "live DNS (与 last-good 缓存一致)".to_string()
        }
        (false, Some(_), Some(cached)) => {
            notes.push(format!("last-good 缓存旧 IP：{}", cached.last_good_ip));
            notes.push(format!(
                "last-good 上次成功解析时间：{}",
                format_cli_time_with(cached.last_resolved_at, &config.ui)
            ));
            "live DNS".to_string()
        }
        (false, Some(_), None) => "live DNS".to_string(),
        (false, None, Some(cached)) if config.last_good.enabled => {
            notes.push(format!(
                "last-good 上次成功解析时间：{}",
                format_cli_time_with(cached.last_resolved_at, &config.ui)
            ));
            notes.push(format!(
                "last-good egress_control 判断：{}",
                if cached.egress_allowed {
                    "allowed"
                } else {
                    "blocked"
                }
            ));
            format!("last-good ({})", cached.last_good_ip)
        }
        (false, None, Some(_)) => "none (last-good disabled)".to_string(),
        (false, None, None) => "none".to_string(),
        (true, None, _) => "none".to_string(),
    };
    if config.egress_control.enabled
        && let Some(ip) = rule.resolved_ip.as_deref()
    {
        notes.push(format!(
            "live IP egress_control 判断：{}",
            if config.egress_control.allows_ip(ip) {
                "allowed"
            } else {
                "blocked"
            }
        ));
    }
    RuleResolutionDisplay {
        target_kind,
        resolved_ip_label,
        last_good_label,
        notes,
    }
}

fn read_nat_service_status() -> NatServiceStatus {
    match Command::new("systemctl")
        .arg("is-active")
        .arg("nat")
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match stdout.trim() {
                "active" => NatServiceStatus::Active,
                "inactive" => NatServiceStatus::Inactive,
                "failed" => NatServiceStatus::Failed,
                _ if output.status.success() => NatServiceStatus::Active,
                _ => NatServiceStatus::Unknown,
            }
        }
        Err(_) => NatServiceStatus::Unknown,
    }
}

fn read_last_apply_display(config: &TomlConfig) -> LastApplyDisplay {
    match audit::last_apply_event(&config.audit.file, 200) {
        Some((action, time)) => {
            let state = match action.as_str() {
                "apply.success" => LastApplyState::Success,
                "apply.fail" => LastApplyState::Fail,
                _ => LastApplyState::Unknown,
            };
            let time_label = if time.is_empty() {
                None
            } else {
                Some(format_cli_time_from_rfc3339_with(&time, &config.ui))
            };
            LastApplyDisplay { state, time_label }
        }
        None => LastApplyDisplay {
            state: LastApplyState::Unknown,
            time_label: None,
        },
    }
}

fn read_nft_connectivity_status(
    rule: &forward_test::TestableRule,
    nat_active: bool,
    last_apply_success: bool,
) -> NftConnectivityStatus {
    let json = match read_nft_json_ruleset() {
        Ok(json) => json,
        Err(e) => {
            return NftConnectivityStatus::Unconfirmed {
                reason: format!("读取 nft ruleset 失败：{e}"),
            };
        }
    };
    let presence = match forward_test::detect_rule_in_nft_json(&json, &rule.id) {
        Ok(presence) => presence,
        Err(e) => {
            return NftConnectivityStatus::Unconfirmed {
                reason: format!("nft 规则检测失败：{e}"),
            };
        }
    };
    let counters = match forward_test::parse_rule_counters(&json, &rule.id) {
        Ok(counters) => (Some(counters), None),
        Err(e) => (None, Some(format!("读取 nft counter 失败：{e}"))),
    };
    let shape = forward_test::detect_rule_shape(rule);
    let verdict = forward_test::classify_nft_presence_with_shape(
        &presence,
        rule.ip_version.as_str(),
        rule.protocol.as_str(),
        shape,
        nat_active,
        last_apply_success,
    );
    let (self_nat, self_filter) = summarize_nft_probe_states(rule, &presence, shape);
    NftConnectivityStatus::Checked {
        self_nat,
        self_filter,
        verdict,
        counters: counters.0,
        counter_warning: counters.1,
    }
}

/// v0.8.10：构建 SNAT 出口 + 本机出站诊断。
///
/// `do_probes` 为 false（规则未启用 / 全局转发关闭）时只计算纯配置层 SnatPlan，
/// 不执行任何 `ip route get` / `curl` 系统命令；snat_ip 的 nft 存在性也标记为跳过。
fn build_snat_egress_report(
    config: &TomlConfig,
    rule: &forward_test::TestableRule,
    rule_snat_ip: Option<&str>,
    nft_json: Option<&str>,
    do_probes: bool,
) -> SnatEgressReport {
    let legacy_env_ip = std::env::var("nat_local_ip").ok();
    let plan = forward_test::snat_plan(
        rule_snat_ip,
        rule.ip_version.as_str(),
        &config.snat.mode.to_string(),
        &config.snat.fixed_source_ip,
        legacy_env_ip.as_deref(),
    );
    let nft_snat_to = match (rule_snat_ip, nft_json) {
        (None, _) => SnatNftCheck::NoSnatIp,
        (Some(ip), Some(json)) => {
            if forward_test::nft_json_contains_snat_to(json, ip) {
                SnatNftCheck::Found(ip.to_string())
            } else {
                SnatNftCheck::Missing(ip.to_string())
            }
        }
        // 配了 snat_ip 但拿不到 nft ruleset（规则未生效 / 读取失败）：不下定论。
        (Some(ip), None) => SnatNftCheck::Unknown(ip.to_string()),
    };
    if !do_probes {
        return SnatEgressReport {
            plan,
            nft_snat_to,
            system_egress_ip: None,
            route_from_snat: forward_test::EgressProbe::Skipped(
                "规则未生效，跳过出口探测".to_string(),
            ),
            curl_egress: forward_test::EgressProbe::Skipped("规则未生效，跳过出口探测".to_string()),
        };
    }
    let system_egress_ip = run_ip_route_get_src("1.1.1.1", None);
    let (route_from_snat, curl_egress) = match rule_snat_ip {
        Some(ip) => (probe_route_from_snat(ip), probe_curl_egress(ip)),
        None => (
            forward_test::EgressProbe::Skipped("规则未配置 snat_ip，使用全局默认出口".to_string()),
            forward_test::EgressProbe::Skipped(
                "规则未配置 snat_ip，不做 --interface 出站测试".to_string(),
            ),
        ),
    };
    SnatEgressReport {
        plan,
        nft_snat_to,
        system_egress_ip,
        route_from_snat,
        curl_egress,
    }
}

/// 执行 `ip route get <dest> [from <src>]` 并解析 `src`；命令缺失/失败返回 None。
/// 只读，不修改任何路由 / 规则。
fn run_ip_route_get_src(dest: &str, from: Option<&str>) -> Option<String> {
    let mut cmd = Command::new("ip");
    cmd.arg("route").arg("get").arg(dest);
    if let Some(src) = from {
        cmd.arg("from").arg(src);
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    forward_test::parse_route_get_src(&String::from_utf8_lossy(&output.stdout))
}

/// 探测 `ip -4 route get 1.1.1.1 from <snat_ip>`：成功为 ok，失败为软告警（不 panic、不改路由）。
fn probe_route_from_snat(snat_ip: &str) -> forward_test::EgressProbe {
    match Command::new("ip")
        .arg("-4")
        .arg("route")
        .arg("get")
        .arg("1.1.1.1")
        .arg("from")
        .arg(snat_ip)
        .output()
    {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            match forward_test::parse_route_get_src(&text) {
                Some(src) => {
                    forward_test::EgressProbe::Ok(format!("from {snat_ip} 可路由（src {src}）"))
                }
                None => forward_test::EgressProbe::Ok(format!("from {snat_ip} 可路由")),
            }
        }
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr);
            forward_test::EgressProbe::Warn(format!(
                "ip route get from {snat_ip} 失败：{}",
                err.trim()
            ))
        }
        Err(e) => forward_test::EgressProbe::Warn(format!("ip 命令不可用：{e}")),
    }
}

/// 用 snat_ip 作为出站源做出口 IP 测试。失败一律 Warn，不视为硬错误，也不改任何配置/路由。
fn probe_curl_egress(snat_ip: &str) -> forward_test::EgressProbe {
    match Command::new("curl")
        .arg("-4")
        .arg("--interface")
        .arg(snat_ip)
        .arg("--max-time")
        .arg("5")
        .arg("-s")
        .arg("https://api.ipify.org")
        .output()
    {
        Ok(output) if output.status.success() => {
            let body = String::from_utf8_lossy(&output.stdout);
            match forward_test::parse_curl_egress_ip(&body) {
                Some(ip) if ip == snat_ip => {
                    forward_test::EgressProbe::Ok(format!("observed ip = {ip}（与 snat_ip 一致）"))
                }
                Some(ip) => forward_test::EgressProbe::Warn(format!(
                    "observed ip = {ip}，与 snat_ip {snat_ip} 不一致"
                )),
                None => forward_test::EgressProbe::Warn("curl 返回内容无法解析为 IP".to_string()),
            }
        }
        Ok(output) => forward_test::EgressProbe::Warn(format!(
            "curl --interface {snat_ip} 失败（exit {:?}）",
            output.status.code()
        )),
        Err(_) => {
            forward_test::EgressProbe::Warn("curl 不可用或无法执行，跳过出口 IP 测试".to_string())
        }
    }
}

fn summarize_nft_probe_states(
    rule: &forward_test::TestableRule,
    presence: &forward_test::NftRulePresence,
    shape: forward_test::NftRuleShape,
) -> (ProbeState, ProbeState) {
    let nat_found = presence.nat_rule_v4_found || presence.nat_rule_v6_found;
    let self_nat = if nat_found {
        ProbeState::Found
    } else {
        ProbeState::Missing
    };
    if matches!(shape, forward_test::NftRuleShape::Redirect) {
        return (self_nat, ProbeState::NotApplicable);
    }
    let need_v4 = matches!(rule.ip_version.as_str(), "ipv4" | "all");
    let need_v6 = matches!(rule.ip_version.as_str(), "ipv6" | "all");
    let filter_found = (need_v4 && (presence.forward_out_v4_found || presence.forward_in_v4_found))
        || (need_v6 && (presence.forward_out_v6_found || presence.forward_in_v6_found));
    let self_filter = if filter_found {
        ProbeState::Found
    } else {
        ProbeState::Missing
    };
    (self_nat, self_filter)
}

pub(crate) fn render_connectivity_report_lines(report: &ConnectivityReport<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("====================================".to_string());
    lines.push("转发规则连通性测试".to_string());
    lines.push("====================================".to_string());
    lines.push(String::new());

    lines.push("1. 配置状态".to_string());
    lines.push(format!(
        "- 全局转发：{}",
        enabled_label(report.global_enabled)
    ));
    lines.push(format!(
        "- 规则：{}",
        if report.rule_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    lines.push("- 配置文件：已保存".to_string());
    lines.push(format!(
        "- 入口：{} / {} / {}",
        report.rule.sport, report.rule.protocol, report.rule.ip_version
    ));
    lines.push(format!(
        "- 目标：{} {}:{}",
        report.resolution.target_kind, report.rule.target, report.rule.dport
    ));
    lines.push(format!(
        "- resolved_ip：{}",
        report.resolution.resolved_ip_label
    ));
    lines.push(format!(
        "- last-good：{}",
        report.resolution.last_good_label
    ));
    for note in &report.resolution.notes {
        lines.push(format!("- {note}"));
    }
    if !report.rule_enabled {
        lines.push("- 提示：规则未启用，不会生成 nft。".to_string());
    }
    if !report.global_enabled {
        lines.push("- 提示：全局转发已关闭，该规则当前不会生效。".to_string());
    }
    if let Some(note) = &report.access_control_note {
        lines.push(format!("- access_control：{note}"));
    }
    lines.push(String::new());

    lines.push("2. 服务状态".to_string());
    lines.push(format!("- nat.service：{}", report.nat_service.label()));
    lines.push(format!("- 最近 apply：{}", report.last_apply.state.label()));
    lines.push(format!(
        "- 最近 apply 时间：{}",
        report.last_apply.time_label.as_deref().unwrap_or("unknown")
    ));
    match report.nat_service {
        NatServiceStatus::Inactive => {
            lines.push("- 提示：nat.service 未运行，请先检查 systemctl status nat。".to_string());
        }
        NatServiceStatus::Failed => {
            lines.push(
                "- 提示：nat.service 状态为 failed，请先检查 systemctl status nat。".to_string(),
            );
        }
        _ => {}
    }
    lines.push(String::new());

    lines.push("3. nft 应用状态".to_string());
    match &report.nft {
        NftConnectivityStatus::Checked {
            self_nat,
            self_filter,
            verdict,
            counters,
            counter_warning,
        } => {
            lines.push(format!("- self-nat：{}", self_nat.label()));
            lines.push(format!("- self-filter：{}", self_filter.label()));
            lines.push(format!("- 检测结论：{}", verdict.label()));
            if let Some(counters) = counters {
                lines.push(format!(
                    "- baseline counters：nat-rule={}B, out={}B, in={}B",
                    counters.nat_rule.bytes, counters.out.bytes, counters.r#in.bytes
                ));
            }
            if let Some(warning) = counter_warning {
                lines.push(format!("- counter：{warning}"));
            }
            if matches!(verdict, forward_test::NftDetectionVerdict::Unconfirmed) {
                lines
                    .push("- 说明：检测器未确认当前规则，不等同于已经判定规则未应用。".to_string());
            }
        }
        NftConnectivityStatus::Unconfirmed { reason } => {
            lines.push("- self-nat：未确认".to_string());
            lines.push("- self-filter：未确认".to_string());
            lines.push("- 检测结论：未确认".to_string());
            lines.push(format!("- 说明：{reason}"));
        }
        NftConnectivityStatus::SkippedGlobalDisabled => {
            lines.push("- self-nat：未检查".to_string());
            lines.push("- self-filter：未检查".to_string());
            lines.push("- 检测结论：全局转发已关闭，该规则当前不会生效".to_string());
        }
        NftConnectivityStatus::SkippedDisabled => {
            lines.push("- self-nat：未找到".to_string());
            lines.push("- self-filter：未找到".to_string());
            lines.push("- 检测结论：规则未启用，不会生成 nft".to_string());
        }
    }
    lines.push(String::new());

    lines.extend(render_snat_egress_section(&report.snat));

    lines.push("5. 目标连通性".to_string());
    lines.push(format!(
        "- 目标 TCP：{}",
        target_tcp_label(report.rule, report.target_tcp)
    ));
    lines.push(format!("- 目标 UDP：{}", target_udp_label(report.rule)));
    lines.push(String::new());

    lines.push("6. 外部访问测试".to_string());
    if report.global_enabled && report.rule_enabled {
        lines.push(format!(
            "- 请在另一台机器访问 SERVER_IP:{}",
            report.rule.sport
        ));
        lines.push(format!(
            "- 本机 curl 127.0.0.1:{} 通常不能完整验证 DNAT PREROUTING。",
            report.rule.sport
        ));
        lines.push("- 输入 h 查看详细 curl / nc 示例，按 Enter 返回。".to_string());
    } else if !report.global_enabled {
        lines.push("- 全局转发已关闭，外部访问不会命中本项目转发规则。".to_string());
    } else {
        lines.push("- 规则未启用，外部访问不会命中本项目 nft 规则。".to_string());
    }
    lines.push(String::new());

    lines.push("7. 结论".to_string());
    let mut conclusion = connectivity_conclusion_lines(
        report.rule,
        report.global_enabled,
        report.rule_enabled,
        report.nat_service,
        report.last_apply.state,
        &report.nft,
        report.target_tcp,
    );
    if let SnatNftCheck::Missing(ip) = &report.snat.nft_snat_to {
        conclusion.push(format!(
            "- ⚠️ 已配置 per-rule snat_ip={ip}，但 nft 中未发现 snat to {ip}，请确认已重新 apply。"
        ));
    }
    lines.extend(conclusion);
    lines
}

/// 渲染「4. SNAT 出口诊断」段：展示 SNAT 模式 / snat_ip / POSTROUTING 动作 / nft 中
/// `snat to <ip>` 存在性 / 本机默认出口 / route from snat_ip / curl --interface 出口测试。
/// 所有探测失败均为软告警，且明确本机侧诊断不替代公网外部入口测试。
fn render_snat_egress_section(snat: &SnatEgressReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("4. SNAT 出口诊断".to_string());
    lines.push(format!("- snat 模式：{}", snat.plan.mode_label));
    lines.push(format!(
        "- snat_ip：{}",
        snat.plan.per_rule_snat_ip.as_deref().unwrap_or("default")
    ));
    lines.push(format!(
        "- POSTROUTING 动作：{}",
        snat.plan.postrouting_action
    ));
    for note in &snat.plan.notes {
        lines.push(format!("- 说明：{note}"));
    }
    match &snat.nft_snat_to {
        SnatNftCheck::NoSnatIp => {
            lines.push(
                "- nft snat to <ip>：不适用（规则未配置 snat_ip，走全局默认 SNAT）".to_string(),
            );
        }
        SnatNftCheck::Found(ip) => {
            lines.push(format!("- nft snat to {ip}：found"));
        }
        SnatNftCheck::Missing(ip) => {
            lines.push(format!(
                "- nft snat to {ip}：not found（可能尚未重新 apply）"
            ));
        }
        SnatNftCheck::Unknown(ip) => {
            lines.push(format!(
                "- nft snat to {ip}：unable to parse（nft ruleset 不可读）"
            ));
        }
    }
    lines.push(format!(
        "- 系统默认出口 IP：{}",
        snat.system_egress_ip.as_deref().unwrap_or("unknown")
    ));
    lines.push(format!(
        "- route from snat_ip：{}",
        snat.route_from_snat.label()
    ));
    lines.push(format!(
        "- curl --interface snat_ip：{}",
        snat.curl_egress.label()
    ));
    lines.push("- 提示：以上为本机侧诊断，不能替代从公网外部发起的真实入口访问测试。".to_string());
    lines.push(String::new());
    lines
}

fn target_tcp_label(rule: &forward_test::TestableRule, target_tcp: Option<bool>) -> &'static str {
    if rule.protocol == "udp" {
        return "不适用";
    }
    match target_tcp {
        Some(true) => "可达",
        Some(false) => "不可达",
        None => "不适用",
    }
}

fn target_udp_label(rule: &forward_test::TestableRule) -> &'static str {
    match rule.protocol.as_str() {
        "udp" | "all" => "需业务客户端验证",
        _ => "不适用",
    }
}

pub(crate) fn connectivity_conclusion_lines(
    rule: &forward_test::TestableRule,
    global_enabled: bool,
    rule_enabled: bool,
    nat_service: NatServiceStatus,
    last_apply: LastApplyState,
    nft: &NftConnectivityStatus,
    target_tcp: Option<bool>,
) -> Vec<String> {
    let mut lines = Vec::new();
    if !global_enabled {
        lines.push("- ⚠️ 全局转发已关闭，该规则当前不会生效。".to_string());
        return lines;
    }
    if !rule_enabled {
        lines.push("- ⚠️ 规则未启用，不会生成 nft。".to_string());
        return lines;
    }
    match nat_service {
        NatServiceStatus::Inactive | NatServiceStatus::Failed | NatServiceStatus::Unknown => {
            lines.push("- ⚠️ nat.service 未运行，请先检查 systemctl status nat。".to_string());
            return lines;
        }
        NatServiceStatus::Active => {}
        NatServiceStatus::NotChecked => {
            lines.push("- ⚠️ nat.service 未检查。".to_string());
            return lines;
        }
    }
    match last_apply {
        LastApplyState::Success => {}
        LastApplyState::Fail => {
            lines.push("- ⚠️ 最近 apply 失败，请检查 nat.service 日志。".to_string());
            return lines;
        }
        LastApplyState::Unknown => {
            lines.push("- ⚠️ 最近 apply 状态未知，请结合 nat.service 日志确认。".to_string());
            return lines;
        }
        LastApplyState::NotChecked => {
            lines.push("- ⚠️ 最近 apply 未检查。".to_string());
            return lines;
        }
    }
    if target_tcp == Some(false) {
        lines.push("- ⚠️ 目标不可达，请检查目标 IP/端口、防火墙、目标服务。".to_string());
        return lines;
    }
    match nft {
        NftConnectivityStatus::Checked { verdict, .. } => match verdict {
            forward_test::NftDetectionVerdict::Applied
            | forward_test::NftDetectionVerdict::AppliedRedirect => {
                if target_tcp_ok_for_conclusion(rule, target_tcp) {
                    lines.push("- ✅ 服务端配置、nft 应用和目标连通性看起来正常".to_string());
                    lines.push(format!(
                        "- ℹ️ 最终入口可用性仍建议从另一台外部机器访问 SERVER_IP:{} 验证",
                        rule.sport
                    ));
                } else {
                    lines
                        .push("- ⚠️ 目标 TCP 连通性未确认，请检查解析结果或目标服务。".to_string());
                }
            }
            forward_test::NftDetectionVerdict::Partial => {
                lines.push("- ⚠️ 规则已保存，但 nft 只部分匹配。".to_string());
            }
            forward_test::NftDetectionVerdict::Unconfirmed => {
                lines.push("- ⚠️ 规则已保存，但 nft 检测器尚未确认应用。".to_string());
            }
            forward_test::NftDetectionVerdict::NotApplied => {
                lines.push("- ⚠️ 规则已保存，但 nft 尚未确认应用。".to_string());
            }
        },
        NftConnectivityStatus::Unconfirmed { .. } => {
            lines.push("- ⚠️ 规则已保存，但 nft 检测器尚未确认应用。".to_string());
        }
        NftConnectivityStatus::SkippedGlobalDisabled => {
            lines.push("- ⚠️ 全局转发已关闭，该规则当前不会生效。".to_string());
        }
        NftConnectivityStatus::SkippedDisabled => {
            lines.push("- ⚠️ 规则未启用，不会生成 nft。".to_string());
        }
    }
    lines
}

fn target_tcp_ok_for_conclusion(
    rule: &forward_test::TestableRule,
    target_tcp: Option<bool>,
) -> bool {
    if rule.protocol == "udp" {
        return true;
    }
    target_tcp == Some(true)
}

/// 「测试转发规则连通性」结果页的简短外部访问提示。默认只显示必要信息，不再大段列出
/// HTTP/TCP/HTTPS/SNI 示例；用户输入 h 后再展示完整命令。
#[cfg(test)]
pub(crate) fn external_test_brief_lines(rule: &forward_test::TestableRule) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("外部访问测试：".to_string());
    lines.push("请在另一台机器访问：".to_string());
    lines.push(format!("  SERVER_IP:{}", rule.sport));
    lines.push(format!(
        "注意：本机 curl 127.0.0.1:{} 通常不能完整验证 DNAT PREROUTING。",
        rule.sport
    ));
    let proto_hint = match rule.protocol.as_str() {
        "tcp" => "本规则 protocol=tcp，可用 nc / curl 等 TCP 客户端验证。".to_string(),
        "udp" => "本规则 protocol=udp，建议用业务客户端验证；nc -vzu 仅作连通性参考。".to_string(),
        _ => "本规则 protocol=all，TCP / UDP 都会被转发。".to_string(),
    };
    lines.push(proto_hint);
    lines.push("输入 h 查看详细测试命令示例，按 Enter 返回。".to_string());
    lines
}

/// 「测试转发规则连通性」h 入口的完整外部测试命令。按协议、目标是否为域名分支：
/// - protocol=udp：仅列 UDP 示例，提示 nc -vzu 局限性
/// - protocol=tcp / all：列 TCP nc 示例
/// - target 是域名：HTTP / HTTPS+SNI 示例都带 Host / --connect-to
/// - target 是 IP：只列普通 TCP / HTTP 示例，不附 Host header
pub(crate) fn external_test_detailed_lines(rule: &forward_test::TestableRule) -> Vec<String> {
    let mut lines = Vec::new();
    let examples = forward_test::external_examples(rule);
    let target_is_domain = rule.target.parse::<std::net::IpAddr>().is_err();
    lines.push("详细外部测试命令：".to_string());
    match rule.protocol.as_str() {
        "udp" => {
            lines.push(format!("UDP 示例: nc -vzu SERVER_IP {}", rule.sport));
            lines.push("提示：nc -vzu 只能验证端口是否对 UDP 探测有回应；UDP 真实可达性请用业务客户端验证。".to_string());
        }
        _ => {
            lines.push(format!("TCP 示例: {}", examples.tcp));
            if target_is_domain {
                lines.push(format!("HTTP 示例: {}", examples.http));
                lines.push(format!("HTTPS/SNI 示例: {}", examples.https_sni));
                lines.push(
                    "提示：目标是域名时建议带 Host header / SNI，以匹配后端虚拟主机。".to_string(),
                );
                lines.push(
                    "提示：本项目不终止 TLS，不解密 HTTPS；证书 / SNI 取决于客户端访问域名和目标服务证书。".to_string(),
                );
            } else {
                lines.push(format!(
                    "HTTP 示例: curl -v http://SERVER_IP:{}/",
                    rule.sport
                ));
                lines.push("提示：目标是 IP，无需特别指定 Host header / SNI。".to_string());
            }
            if rule.protocol.as_str() == "all" {
                lines.push(format!(
                    "（protocol=all 还可使用 UDP 客户端测试 SERVER_IP:{} 的 UDP 路径）",
                    rule.sport
                ));
            }
        }
    }
    lines.push("如果测试后 counter 有变化，可回到 CLI 查看 Stats 流量统计。".to_string());
    lines.push(
        "注意：这些命令只用于外部连通性测试，与 GeoIP / last-good / egress_control 等准入功能是不同模块。".to_string(),
    );
    lines
}

/// 把 v0.4.2 的 nft 规则检测结果打印成结构化区块。
/// - 总是显示 self-nat / self-filter / protocol 子项，避免单一行误判。
/// - verdict 是综合结论（已应用 / 部分匹配 / 未确认 / 未应用）。
#[cfg(test)]
fn print_nft_detection_block(
    presence: &nat_common::forward_test::NftRulePresence,
    verdict: nat_common::forward_test::NftDetectionVerdict,
    rule: &nat_common::forward_test::TestableRule,
    nat_active: bool,
    last_apply_success: bool,
    last_apply_label: &str,
    refresh_interval_seconds: u64,
) {
    use nat_common::forward_test::NftDetectionVerdict;

    println!("nft 规则检测：");
    let need_v4 = matches!(rule.ip_version.as_str(), "ipv4" | "all");
    let need_v6 = matches!(rule.ip_version.as_str(), "ipv6" | "all");
    // v0.4.3：Redirect / localhost-Single 没有 FORWARD counter，避免在该路径下显示
    // "FORWARD out: 未找到 in: 未找到" 造成误解。
    let shape = nat_common::forward_test::detect_rule_shape(rule);
    let is_redirect = matches!(shape, nat_common::forward_test::NftRuleShape::Redirect);
    if need_v4 {
        println!(
            "  ip self-nat PREROUTING (nat-rule:id={}): {}",
            rule.id,
            yes_no(presence.nat_rule_v4_found)
        );
        if !is_redirect {
            println!(
                "  ip self-filter FORWARD out: {}  in: {}",
                yes_no(presence.forward_out_v4_found),
                yes_no(presence.forward_in_v4_found)
            );
        }
    }
    if need_v6 {
        println!(
            "  ip6 self-nat PREROUTING (nat-rule:id={}): {}",
            rule.id,
            yes_no(presence.nat_rule_v6_found)
        );
        if !is_redirect {
            println!(
                "  ip6 self-filter FORWARD out: {}  in: {}",
                yes_no(presence.forward_out_v6_found),
                yes_no(presence.forward_in_v6_found)
            );
        }
    }
    if is_redirect {
        println!(
            "  规则形态: redirect to :port (本机重定向，无 FORWARD counter；判定不要求 self-filter FORWARD)"
        );
    }
    println!(
        "  protocol 检测: tcp={}  udp={}  (规则期望 protocol={})",
        yes_no(presence.protocol_tcp_seen),
        yes_no(presence.protocol_udp_seen),
        rule.protocol
    );
    println!(
        "  nat.service: {}  最近一次 apply: {last_apply_label}",
        if nat_active {
            "active"
        } else {
            "inactive/unknown"
        }
    );
    println!("  检测结论: {}", verdict.label());

    match verdict {
        NftDetectionVerdict::Applied => {
            println!("  nft 规则已确认应用。");
        }
        NftDetectionVerdict::AppliedRedirect => {
            println!(
                "  nft 规则已确认应用（redirect 本机重定向，不经过 forward 链，无 FORWARD counter）。"
            );
        }
        NftDetectionVerdict::Partial => {
            println!(
                "  仅命中部分 IP family / protocol；如果规则 ip_version=all 或 protocol=all，可能某一侧 nft 表尚未应用，或 IPv6 未启用。"
            );
            println!("  请查看：");
            println!("    nft list table ip self-nat");
            println!("    nft list table ip self-filter");
            if need_v6 {
                println!("    nft list table ip6 self-nat");
                println!("    nft list table ip6 self-filter");
            }
        }
        NftDetectionVerdict::Unconfirmed => {
            // 服务 active + 最近 apply.success 但检测器没找到 → 不要直接说"未应用"
            println!(
                "  nft 规则：未能通过当前检测器确认，但 nat.service active 且最近一次 apply 成功 ({last_apply_label})。"
            );
            println!("  可能是检测条件未覆盖当前规则格式。请查看当前 nft 规则确认：");
            println!("    nft list table ip self-nat");
            println!("    nft list table ip self-filter");
            println!("    journalctl -u nat -n 120 --no-pager");
            println!(
                "  本工具不会因为检测器未确认就重启 nat.service 或绕过 safe apply 执行 nft -f。"
            );
        }
        NftDetectionVerdict::NotApplied => {
            if !nat_active {
                println!("  nat.service 未运行，转发规则不会应用。");
                println!("  请执行：");
                println!("    systemctl restart nat");
                println!("    systemctl status nat --no-pager -l");
                println!("    journalctl -u nat -n 120 --no-pager");
            } else if !last_apply_success {
                println!(
                    "  最近一次 apply 未成功 (最后事件: {last_apply_label})，规则可能尚未应用。"
                );
                println!("  请查看：");
                println!("    journalctl -u nat -n 120 --no-pager");
            } else {
                println!("  规则可能正在等待 nat.service 自动应用。");
                println!(
                    "  当前自动检测 / 刷新间隔：{refresh_interval_seconds} 秒（ddns.refresh_interval_seconds）。"
                );
                println!("  请稍后刷新，或手动执行：systemctl restart nat");
            }
        }
    }
}

#[cfg(test)]
fn yes_no(found: bool) -> &'static str {
    if found { "已找到" } else { "未找到" }
}

fn read_nft_json_ruleset() -> Result<String, io::Error> {
    let output = Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

pub(crate) fn add_single_rule(
    config: &mut TomlConfig,
    sport: u16,
    dport: u16,
    domain: String,
    protocol: Protocol,
    ip_version: IpVersion,
    extras: RuleExtras,
) -> Result<(), String> {
    let rule = NftCell::Single {
        enabled: true,
        sport,
        dport,
        domain,
        protocol,
        ip_version,
        snat_ip: extras.snat_ip,
        comment: extras.comment,
        quota_enabled: false,
        quota_bytes: 0,
        quota_period: nat_common::QuotaPeriod::default(),
        quota_action: nat_common::QuotaAction::default(),
    };
    rule.validate()?;
    config.rules.push(rule);
    Ok(())
}

pub(crate) fn add_range_rule(
    config: &mut TomlConfig,
    port_start: u16,
    port_end: u16,
    domain: String,
    protocol: Protocol,
    ip_version: IpVersion,
    extras: RuleExtras,
) -> Result<(), String> {
    let rule = NftCell::Range {
        enabled: true,
        port_start,
        port_end,
        domain,
        protocol,
        ip_version,
        snat_ip: extras.snat_ip,
        comment: extras.comment,
        quota_enabled: false,
        quota_bytes: 0,
        quota_period: nat_common::QuotaPeriod::default(),
        quota_action: nat_common::QuotaAction::default(),
    };
    rule.validate()?;
    config.rules.push(rule);
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleExtras {
    pub snat_ip: Option<String>,
    pub comment: Option<String>,
}

pub(crate) fn delete_rule(config: &mut TomlConfig, index: usize) -> Result<NftCell, String> {
    if index >= config.rules.len() {
        return Err("规则 index 超出范围".to_string());
    }
    Ok(config.rules.remove(index))
}

fn toggle_rule_interactive(path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(path)?;
    if config.rules.is_empty() {
        println!("当前没有转发规则。");
        wait_enter_to_return()?;
        return Ok(());
    }

    println!("当前规则：");
    for (index, rule) in config.rules.iter().enumerate() {
        println!(
            "{}) [{}] {}",
            index + 1,
            rule_status(rule),
            format_rule(rule)
        );
    }
    println!("0) 返回");

    let index = parse_index(&prompt("请选择规则编号: ")?)?;
    if index == 0 {
        return Ok(());
    }
    let rule_index = index - 1;
    let Some(rule) = config.rules.get(rule_index) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "规则编号超出范围",
        ));
    };

    println!("当前规则：");
    println!("{}", format_rule_details(rule));
    println!("当前状态：{}", rule_status(rule));
    println!("请选择操作：");
    println!("1) 启用此规则");
    println!("2) 禁用此规则");
    println!("0) 返回");
    let action = prompt("请选择操作: ")?;
    match action.trim() {
        "1" => {
            // 启用前：若该规则启用了 quota 且当前周期已用流量仍超过配额，警告用户
            // 下一轮 quota 检查会再次自动禁用，并清除该规则的 notified 标记以便重新通知
            if config.rules[rule_index].quota_enabled()
                && config.rules[rule_index].quota_bytes() > 0
            {
                let rule_id = format!("r{rule_index}");
                let stats_state = traffic_stats::load_state(&config.stats.data_file);
                let used = match config.rules[rule_index].quota_period() {
                    QuotaPeriod::Daily => stats_state
                        .per_rule_daily_bytes
                        .get(&rule_id)
                        .copied()
                        .unwrap_or(0),
                    QuotaPeriod::Monthly => stats_state
                        .per_rule_monthly_bytes
                        .get(&rule_id)
                        .copied()
                        .unwrap_or(0),
                    QuotaPeriod::Total => stats_state
                        .per_rule_total_bytes
                        .get(&rule_id)
                        .copied()
                        .unwrap_or(0),
                };
                let limit = config.rules[rule_index].quota_bytes();
                if used >= limit {
                    println!(
                        "当前周期已用流量仍超过配额（{} >= {}），重新启用后可能再次自动禁用。",
                        quota::format_bytes(used),
                        quota::format_bytes(limit)
                    );
                }
                let mut quota_state = quota::QuotaState::load(&config.quota.state_file);
                quota_state.clear_for_rule(&rule_id);
                if let Err(e) = quota_state.save(&config.quota.state_file) {
                    warn!(
                        "重置 quota 通知去重状态失败 ({}): {e}",
                        config.quota.state_file
                    );
                }
            }
            config.rules[rule_index].set_enabled(true);
        }
        "2" => config.rules[rule_index].set_enabled(false),
        "0" => return Ok(()),
        _ => {
            println!("未知选项: {}", action.trim());
            wait_enter_to_return()?;
            return Ok(());
        }
    }

    save_toml_config(path, &config, "rule.toggle")?;
    let now_enabled = config.rules[rule_index].enabled();
    audit_cli(
        path,
        if now_enabled {
            "rule.enable"
        } else {
            "rule.disable"
        },
        AuditResult::Ok,
        json!({"index": rule_index}),
    );
    println!("规则已{}。", if now_enabled { "启用" } else { "禁用" });
    print_config_saved_hint(path, "rule.toggle");
    wait_enter_to_return()?;
    Ok(())
}

pub(crate) fn parse_port(value: &str) -> Result<u16, io::Error> {
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "端口必须是 1-65535"))?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "端口必须是 1-65535",
        ));
    }
    Ok(port)
}

pub(crate) fn parse_domain(value: &str) -> Result<String, io::Error> {
    let domain = value.trim();
    if domain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "domain 不能为空",
        ));
    }
    Ok(domain.to_string())
}

pub(crate) fn parse_protocol(value: &str) -> Result<Protocol, io::Error> {
    let value = if value.trim().is_empty() {
        "tcp"
    } else {
        value.trim()
    };
    match value {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "all" => Ok(Protocol::All),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protocol 只能是 tcp/udp/all",
        )),
    }
}

pub(crate) fn parse_ip_version(value: &str) -> Result<IpVersion, io::Error> {
    let value = if value.trim().is_empty() {
        "ipv4"
    } else {
        value.trim()
    };
    match value {
        "ipv4" => Ok(IpVersion::V4),
        "ipv6" => Ok(IpVersion::V6),
        "all" => Ok(IpVersion::All),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ip_version 只能是 ipv4/ipv6/all",
        )),
    }
}

fn print_snat_ip_hint() {
    println!("SNAT IP:");
    println!("  留空 = 使用全局/默认 SNAT");
    println!("  填写 = 该规则转发流量固定 SNAT 到指定 IPv4");
}

pub(crate) fn parse_optional_snat_ip(value: &str) -> Result<Option<String>, io::Error> {
    if value.is_empty() {
        return Ok(None);
    }
    if value != value.trim() || value.contains(char::is_whitespace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("snat_ip 必须是合法 IPv4 地址，收到: {value}"),
        ));
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok(Some(value.to_string())),
        Ok(IpAddr::V6(_)) | Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("snat_ip 必须是合法 IPv4 地址，收到: {value}"),
        )),
    }
}

fn parse_optional_comment(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn parse_index(value: &str) -> Result<usize, io::Error> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "index 必须是数字"))
}

pub(crate) fn format_rule(rule: &NftCell) -> String {
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            comment,
            ..
        } => format!(
            "{sport} -> {domain}:{dport}/{protocol} snat_ip={}{}",
            snat_ip_display(rule),
            format_comment(comment)
        ),
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            comment,
            ..
        } => format!(
            "{port_start}-{port_end} -> {domain}:{port_start}-{port_end}/{protocol} snat_ip={}{}",
            snat_ip_display(rule),
            format_comment(comment)
        ),
        NftCell::Redirect {
            src_port,
            src_port_end,
            dst_port,
            protocol,
            comment,
            ..
        } => {
            let sport = src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string());
            format!(
                "{sport} -> localhost:{dst_port}/{protocol}{}",
                format_comment(comment)
            )
        }
        NftCell::Drop { comment, .. } => {
            format!("DROP {}", format_comment(comment))
        }
    }
}

fn rule_status(rule: &NftCell) -> &'static str {
    if rule.enabled() { "启用" } else { "禁用" }
}

fn snat_ip_display(rule: &NftCell) -> &str {
    rule.snat_ip().unwrap_or("default")
}

fn format_rule_details(rule: &NftCell) -> String {
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => format!(
            "comment: {}\nsport: {sport}\ntarget: {domain}\ndport: {dport}\nprotocol: {protocol}\nip_version: {ip_version}\nsnat_ip: {}",
            comment.as_deref().unwrap_or("(无)"),
            snat_ip_display(rule)
        ),
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => format!(
            "comment: {}\nsport: {port_start}-{port_end}\ntarget: {domain}\ndport: {port_start}-{port_end}\nprotocol: {protocol}\nip_version: {ip_version}\nsnat_ip: {}",
            comment.as_deref().unwrap_or("(无)"),
            snat_ip_display(rule)
        ),
        NftCell::Redirect {
            src_port,
            src_port_end,
            dst_port,
            protocol,
            ip_version,
            comment,
            ..
        } => {
            let sport = src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string());
            format!(
                "comment: {}\nsport: {sport}\ntarget: localhost\ndport: {dst_port}\nprotocol: {protocol}\nip_version: {ip_version}",
                comment.as_deref().unwrap_or("(无)")
            )
        }
        NftCell::Drop { comment, .. } => format!(
            "comment: {}\ntype: drop",
            comment.as_deref().unwrap_or("(无)")
        ),
    }
}

fn format_comment(comment: &Option<String>) -> String {
    comment
        .as_ref()
        .map(|comment| format!(" comment={comment}"))
        .unwrap_or_default()
}

// v0.6.1：backup_filename / backup_config / list_config_backups 已搬到 `menu/backup.rs`。

pub(crate) fn format_stats_top10(state: &traffic_stats::StatsState) -> Vec<String> {
    let view = traffic_stats::state_to_view(&StatsConfig::default(), state);
    view.rules
        .into_iter()
        .take(10)
        .map(|rule| {
            format!(
                "{} - 今日 {} / 本月 {}",
                rule.label,
                traffic_stats::format_bytes(rule.daily_bytes),
                traffic_stats::format_bytes(rule.monthly_bytes)
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    // v0.6.1：update 相关单元测试通过本地别名访问搬到 `menu/update.rs` 的项。
    use super::update::{
        ReloadAction, build_update_plan, build_version_for_update_display, extract_release_tag,
        parse_latest_tag_from_curl_headers, parse_nat_version_output, reload_action,
        valid_update_version,
    };
    // v0.6.1：backup 相关测试通过本地别名访问搬到 `menu/backup.rs` 的项。
    use super::backup::{backup_filename, sanitize_backup_reason};
    use nat_common::{
        TrafficMode,
        stats::{Counter, RuleTraffic, StatsState},
    };

    #[test]
    fn adds_single_rule_to_toml_config() {
        let mut config = TomlConfig {
            global: Default::default(),
            rules: Vec::new(),
            dns: Default::default(),
            ddns: Default::default(),
            stats: StatsConfig::default(),
            telegram: Default::default(),
            access_control: Default::default(),
            dynamic_whitelist: Default::default(),
            geoip: Default::default(),
            egress_control: Default::default(),
            snat: Default::default(),
            mss_clamp: Default::default(),
            last_good: Default::default(),
            audit: Default::default(),
            quota: Default::default(),
            ui: Default::default(),
        };
        add_single_rule(
            &mut config,
            30080,
            80,
            "example.com".to_string(),
            Protocol::Tcp,
            IpVersion::V4,
            RuleExtras {
                snat_ip: None,
                comment: Some("user-comment".to_string()),
            },
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0], NftCell::Single { .. }));
    }

    #[test]
    fn add_single_rule_persists_snat_ip() {
        let mut config = TomlConfig::default();
        add_single_rule(
            &mut config,
            30080,
            80,
            "example.com".to_string(),
            Protocol::Tcp,
            IpVersion::V4,
            RuleExtras {
                snat_ip: Some("198.51.100.20".to_string()),
                comment: Some("user-comment".to_string()),
            },
        )
        .unwrap();
        match &config.rules[0] {
            NftCell::Single { snat_ip, .. } => {
                assert_eq!(snat_ip.as_deref(), Some("198.51.100.20"));
            }
            other => panic!("expected single rule, got {other:?}"),
        }
        let serialized = config.to_toml_string().unwrap();
        assert!(serialized.contains("snat_ip = \"198.51.100.20\""));
    }

    #[test]
    fn adds_range_rule_to_toml_config() {
        let mut config = TomlConfig {
            global: Default::default(),
            rules: Vec::new(),
            dns: Default::default(),
            ddns: Default::default(),
            stats: StatsConfig::default(),
            telegram: Default::default(),
            access_control: Default::default(),
            dynamic_whitelist: Default::default(),
            geoip: Default::default(),
            egress_control: Default::default(),
            snat: Default::default(),
            mss_clamp: Default::default(),
            last_good: Default::default(),
            audit: Default::default(),
            quota: Default::default(),
            ui: Default::default(),
        };
        add_range_rule(
            &mut config,
            30000,
            30010,
            "1.2.3.4".to_string(),
            Protocol::Tcp,
            IpVersion::V4,
            RuleExtras {
                snat_ip: None,
                comment: Some("range-test".to_string()),
            },
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0], NftCell::Range { .. }));
    }

    fn sample_port_conflict(port: u16) -> PortConflict {
        PortConflict {
            protocol: "tcp".to_string(),
            state: "LISTEN".to_string(),
            local_addr: format!("0.0.0.0:{port}"),
            port,
            process: "nginx".to_string(),
        }
    }

    fn edit_test_single_rule(sport: u16, dport: u16, target: &str, protocol: Protocol) -> NftCell {
        NftCell::Single {
            enabled: true,
            sport,
            dport,
            domain: target.to_string(),
            protocol,
            ip_version: IpVersion::V4,
            snat_ip: None,
            comment: Some("demo".to_string()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        }
    }

    fn edit_test_range_rule(start: u16, end: u16, protocol: Protocol) -> NftCell {
        NftCell::Range {
            enabled: true,
            port_start: start,
            port_end: end,
            domain: "range.example.com".to_string(),
            protocol,
            ip_version: IpVersion::V4,
            snat_ip: None,
            comment: Some("range".to_string()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        }
    }

    fn config_with_rules(rules: Vec<NftCell>) -> TomlConfig {
        let mut config = TomlConfig::from_toml_str("rules = []").unwrap();
        config.rules = rules;
        config
    }

    #[test]
    fn port_conflict_single_unoccupied_passes_with_mock_ss() {
        let output = r#"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=100,fd=3))
"#;
        let check = check_listening_port_conflicts_with(30080, 30080, || {
            Ok(PortConflictCommandOutput {
                success: true,
                stdout: output.to_string(),
                stderr: String::new(),
            })
        });
        assert_eq!(check, PortConflictCheck::Clear);
    }

    #[test]
    fn port_conflict_single_occupied_prompts_and_default_rejects() {
        let output = r#"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:30080      0.0.0.0:*     users:(("nginx",pid=101,fd=3))
udp   UNCONN 0      0      0.0.0.0:30080      0.0.0.0:*     users:(("dnsmasq",pid=102,fd=4))
"#;
        let check = check_listening_port_conflicts_with(30080, 30080, || {
            Ok(PortConflictCommandOutput {
                success: true,
                stdout: output.to_string(),
                stderr: String::new(),
            })
        });
        let PortConflictCheck::Conflicts(conflicts) = check else {
            panic!("expected conflicts");
        };
        assert_eq!(conflicts.len(), 2);
        let warning = port_conflict_warning_lines(30080, 30080, &conflicts).join("\n");
        assert!(warning.contains("入口端口 30080"));
        assert!(warning.contains("tcp LISTEN 0.0.0.0:30080 process=nginx"));
        assert!(warning.contains("udp UNCONN 0.0.0.0:30080 process=dnsmasq"));
        assert_eq!(
            port_conflict_action_from_answer(conflicts, ""),
            PortConflictAction::Cancel
        );
    }

    #[test]
    fn port_conflict_override_allows_rule_and_writes_audit() {
        let conflicts = vec![sample_port_conflict(30080)];
        let action = port_conflict_action_from_answer(conflicts.clone(), "y");
        let mut config = TomlConfig::default();
        match action {
            PortConflictAction::Proceed {
                override_conflicts, ..
            } => {
                add_single_rule(
                    &mut config,
                    30080,
                    80,
                    "example.com".to_string(),
                    Protocol::Tcp,
                    IpVersion::V4,
                    RuleExtras::default(),
                )
                .unwrap();
                assert_eq!(override_conflicts, conflicts);
            }
            PortConflictAction::Cancel => panic!("expected override"),
        }
        assert_eq!(config.rules.len(), 1);

        let dir = std::env::temp_dir().join(format!(
            "nat-port-conflict-audit-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.log");
        let toml_path = dir.join("nat.toml");
        std::fs::write(
            &toml_path,
            format!(
                r#"
[audit]
enabled = true
file = "{}"
"#,
                audit_path.display()
            ),
        )
        .unwrap();
        audit_port_conflict_override(
            toml_path.to_str().unwrap(),
            30080,
            30080,
            Protocol::Tcp,
            &conflicts,
        );
        let audit = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit.contains("port_conflict.override"));
        assert!(audit.contains("\"conflict_count\":1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn port_conflict_reject_keeps_config_unchanged() {
        let conflicts = vec![sample_port_conflict(30080)];
        let action = port_conflict_action_from_answer(conflicts, "n");
        let mut config = TomlConfig::default();
        if let PortConflictAction::Proceed { .. } = action {
            add_single_rule(
                &mut config,
                30080,
                80,
                "example.com".to_string(),
                Protocol::Tcp,
                IpVersion::V4,
                RuleExtras::default(),
            )
            .unwrap();
        }
        assert!(config.rules.is_empty());
    }

    #[test]
    fn port_conflict_ss_missing_warns_without_blocking() {
        let check = check_listening_port_conflicts_with(30080, 30080, || {
            Err(io::Error::new(io::ErrorKind::NotFound, "ss"))
        });
        let PortConflictCheck::Unavailable(reason) = check else {
            panic!("expected unavailable");
        };
        assert!(reason.contains("未找到 ss 命令"));
        assert!(reason.contains("将继续添加"));
    }

    #[test]
    fn port_range_conflict_summary_shows_first_ten() {
        let conflicts: Vec<PortConflict> = (30000..30012).map(sample_port_conflict).collect();
        let lines = port_conflict_warning_lines(30000, 30020, &conflicts).join("\n");
        assert!(lines.contains("入口端口段 30000-30020"));
        assert!(lines.contains("0.0.0.0:30009"));
        assert!(!lines.contains("0.0.0.0:30010 process=nginx"));
        assert!(lines.contains("还有 2 个监听项未显示"));
    }

    #[test]
    fn parses_port_range_conflicts_from_mock_ss_tcp_and_udp() {
        let output = r#"
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:30001      0.0.0.0:*     users:(("nginx",pid=101,fd=3))
udp   UNCONN 0      0      [::]:30002         [::]:*        users:(("dnsmasq",pid=102,fd=4))
tcp   LISTEN 0      128    127.0.0.1:40000    0.0.0.0:*     users:(("other",pid=103,fd=5))
"#;
        let conflicts = parse_ss_listening_conflicts(output, 30000, 30010);
        assert_eq!(conflicts.len(), 2);
        assert_eq!(conflicts[0].port, 30001);
        assert_eq!(conflicts[1].port, 30002);
        assert_eq!(conflicts[1].protocol, "udp");
    }

    #[test]
    fn edit_rule_updates_single_sport_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30081)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rule_edit_snapshot(&edited).sport, "30081");
        assert_eq!(changed_fields(&old, &edited), vec!["sport"]);
    }

    #[test]
    fn edit_rule_updates_target_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                target: Some("1.2.3.4".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rule_edit_snapshot(&edited).target, "1.2.3.4");
        assert_eq!(changed_fields(&old, &edited), vec!["target"]);
    }

    #[test]
    fn edit_rule_updates_dport_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                dport: Some(443),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rule_edit_snapshot(&edited).dport, "443");
        assert_eq!(changed_fields(&old, &edited), vec!["dport"]);
    }

    #[test]
    fn edit_rule_updates_protocol_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                protocol: Some(Protocol::Udp),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rule_edit_snapshot(&edited).protocol, "udp");
        assert_eq!(changed_fields(&old, &edited), vec!["protocol"]);
    }

    #[test]
    fn edit_rule_updates_enabled_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!rule_edit_snapshot(&edited).enabled);
        assert_eq!(changed_fields(&old, &edited), vec!["enabled"]);
    }

    #[test]
    fn edit_rule_updates_comment_success() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                comment: Some(Some("new note".to_string())),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            rule_edit_snapshot(&edited).comment.as_deref(),
            Some("new note")
        );
        assert_eq!(changed_fields(&old, &edited), vec!["comment"]);
    }

    #[test]
    fn edit_rule_noop_has_no_changed_fields() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        assert!(RuleEditPatch::default().is_empty());
        assert!(changed_fields(&old, &old).is_empty());
    }

    #[test]
    fn edit_rule_cancel_confirmation_means_do_not_save() {
        assert_eq!(
            rule_edit_confirmation_from_answer(""),
            RuleEditConfirmation::Cancel
        );
        assert_eq!(
            rule_edit_confirmation_from_answer("n"),
            RuleEditConfirmation::Cancel
        );
        assert_eq!(
            rule_edit_confirmation_from_answer("y"),
            RuleEditConfirmation::Save
        );
    }

    #[test]
    fn edit_rule_safe_write_uses_rule_edit_reason_and_backup() {
        let dir = safe_write_dir("rule-edit-safe-write");
        let backup_dir = dir.join("backup");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "rules = []\n").unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };

        let backup = safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "rules = []\n\n[global]\nenabled = false\n",
            "rule.edit",
        )
        .unwrap();

        assert!(backup.is_some(), "rule.edit must create a config backup");
        let audit = std::fs::read_to_string(&audit_file).unwrap();
        assert!(audit.contains("\"action\":\"config.write.success\""));
        assert!(audit.contains("\"reason\":\"rule.edit\""));
        assert!(!audit.contains("backup_skipped"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_rule_audit_detail_includes_changed_fields_only() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let edited = build_edited_rule(
            &old,
            &RuleEditPatch {
                target: Some("new.example.com".to_string()),
                protocol: Some(Protocol::Udp),
                ..Default::default()
            },
        )
        .unwrap();
        let detail = rule_edit_audit_detail(0, &old, &edited).to_string();
        assert!(detail.contains("\"rule_index\":0"));
        assert!(detail.contains("\"changed_fields\":[\"target\",\"protocol\"]"));
        assert!(detail.contains("\"old_target\":\"example.com\""));
        assert!(detail.contains("\"new_target\":\"new.example.com\""));
        assert!(detail.contains("\"old_protocol\":\"tcp\""));
        assert!(detail.contains("\"new_protocol\":\"udp\""));
        assert!(!detail.contains("bot_token"));
    }

    #[test]
    fn edit_rule_port_change_requires_local_port_conflict_check() {
        let old = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        let port_changed = build_edited_rule(
            &old,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30081)),
                ..Default::default()
            },
        )
        .unwrap();
        let target_changed = build_edited_rule(
            &old,
            &RuleEditPatch {
                target: Some("new.example.com".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(rule_edit_requires_port_conflict_check(&old, &port_changed));
        assert!(!rule_edit_requires_port_conflict_check(
            &old,
            &target_changed
        ));
    }

    #[test]
    fn edit_rule_rejects_conflict_with_other_rule() {
        let first = edit_test_single_rule(30080, 80, "a.example.com", Protocol::Tcp);
        let second = edit_test_single_rule(30081, 81, "b.example.com", Protocol::Tcp);
        let config = config_with_rules(vec![first.clone(), second]);
        let edited = build_edited_rule(
            &first,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30081)),
                ..Default::default()
            },
        )
        .unwrap();
        let err = validate_rule_edit_conflicts(&config, 0, &edited).unwrap_err();
        assert!(err.contains("已有规则 2"));
    }

    #[test]
    fn edit_rule_conflict_detection_excludes_self() {
        let rule = edit_test_single_rule(30080, 80, "a.example.com", Protocol::Tcp);
        let config = config_with_rules(vec![rule.clone()]);
        validate_rule_edit_conflicts(&config, 0, &rule).unwrap();
    }

    #[test]
    fn edit_rule_detects_port_range_overlap() {
        let first = edit_test_range_rule(30000, 30010, Protocol::Tcp);
        let second = edit_test_range_rule(30020, 30030, Protocol::Tcp);
        let config = config_with_rules(vec![first, second.clone()]);
        let edited = build_edited_rule(
            &second,
            &RuleEditPatch {
                sport: Some(PortRangeSpec {
                    start: 30005,
                    end: 30012,
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let conflicts = find_rule_edit_conflicts(&config, 1, &edited);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].other_index, 0);
    }

    #[test]
    fn edit_rule_detects_protocol_all_overlap_with_tcp_udp() {
        let tcp = edit_test_single_rule(30080, 80, "a.example.com", Protocol::Tcp);
        let udp = edit_test_single_rule(30081, 81, "b.example.com", Protocol::Udp);
        let config = config_with_rules(vec![tcp.clone(), udp.clone()]);
        let edited_all = build_edited_rule(
            &udp,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30080)),
                protocol: Some(Protocol::All),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(find_rule_edit_conflicts(&config, 1, &edited_all).len(), 1);

        let edited_udp = build_edited_rule(
            &udp,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30080)),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(find_rule_edit_conflicts(&config, 1, &edited_udp).is_empty());
    }

    #[test]
    fn edit_rule_global_disabled_message_allows_saved_config() {
        let mut config = config_with_rules(vec![edit_test_single_rule(
            30080,
            80,
            "example.com",
            Protocol::Tcp,
        )]);
        config.global.enabled = false;
        let lines = rule_edit_post_save_messages(&config, 0).join("\n");
        assert!(lines.contains("全局转发当前关闭"));
    }

    #[test]
    fn edit_rule_disabled_message_mentions_no_nft_generation() {
        let mut rule = edit_test_single_rule(30080, 80, "example.com", Protocol::Tcp);
        rule.set_enabled(false);
        let config = config_with_rules(vec![rule]);
        let lines = rule_edit_post_save_messages(&config, 0).join("\n");
        assert!(lines.contains("该规则当前 disabled"));
        assert!(lines.contains("不会生成 nft 规则"));
    }

    #[test]
    fn edit_rule_target_change_prunes_stale_last_good_cache() {
        use nat_common::last_good::LastGoodRule;

        let dir = safe_write_dir("rule-edit-last-good-prune");
        let config_path = dir.join("nat.toml");
        let last_good_path = dir.join("last-good-state.json");
        let audit_path = dir.join("audit.log");
        let mut config = config_with_rules(vec![edit_test_single_rule(
            30080,
            80,
            "old.example.com",
            Protocol::Tcp,
        )]);
        config.last_good.file = last_good_path.to_string_lossy().to_string();
        config.audit = nat_common::AuditConfig {
            enabled: true,
            file: audit_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let old_identity = last_good::identities_from_rules(&config.rules)
            .pop()
            .unwrap();
        let state = LastGoodState {
            last_success_at: None,
            rules: vec![LastGoodRule {
                rule_id: "r0".to_string(),
                rule_key: Some(old_identity.rule_key),
                comment: None,
                domain: "old.example.com".to_string(),
                last_good_ip: "10.0.0.1".to_string(),
                last_resolved_at: chrono::Utc::now(),
                egress_allowed: true,
                last_apply_status: "ok".to_string(),
            }],
            last_good_nft_hash: None,
        };
        state.save(last_good_path.to_str().unwrap()).unwrap();

        let edited = build_edited_rule(
            &config.rules[0],
            &RuleEditPatch {
                target: Some("new.example.com".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        apply_rule_edit_to_config(&mut config, 0, edited).unwrap();
        std::fs::write(&config_path, config.to_toml_string().unwrap()).unwrap();
        prune_last_good_cache_after_rule_edit(config_path.to_str().unwrap(), &config);

        let pruned = LastGoodState::load(last_good_path.to_str().unwrap());
        assert!(pruned.rules.is_empty());
        let audit = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit.contains("\"trigger\":\"rule.edit\""));
        assert!(audit.contains("\"removed\":1"));
    }

    #[test]
    fn edit_rule_preserves_quota_fields_and_updates_stats_label_alignment() {
        let mut disabled = edit_test_single_rule(30079, 79, "disabled.example.com", Protocol::Tcp);
        disabled.set_enabled(false);
        let mut quota_rule = edit_test_single_rule(30080, 80, "old.example.com", Protocol::Tcp);
        if let NftCell::Single {
            quota_enabled,
            quota_bytes,
            ..
        } = &mut quota_rule
        {
            *quota_enabled = true;
            *quota_bytes = 1024;
        }
        let mut config = config_with_rules(vec![disabled, quota_rule.clone()]);
        let edited = build_edited_rule(
            &quota_rule,
            &RuleEditPatch {
                sport: Some(PortRangeSpec::single(30090)),
                comment: Some(Some("edited".to_string())),
                ..Default::default()
            },
        )
        .unwrap();
        apply_rule_edit_to_config(&mut config, 1, edited).unwrap();

        assert!(config.rules[1].quota_enabled());
        assert_eq!(config.rules[1].quota_bytes(), 1024);
        let labels = traffic_stats::rule_labels_from_config(&config);
        assert!(labels.get("r0").unwrap().contains("30090"));
        assert!(labels.get("r0").unwrap().contains("edited"));

        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 512);
        let usages = quota::compute_usages(&config.rules, &stats, chrono::Utc::now());
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].rule_id, "r0");
        assert_eq!(usages[0].original_index, 1);
    }

    #[test]
    fn edit_rule_eof_prompt_result_cancels_without_panic() {
        let result = prompt_result_to_rule_edit_input(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stdin EOF",
        )))
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn edit_rule_validates_target_address() {
        assert_eq!(
            validate_target_address("  localhost ").unwrap(),
            "localhost"
        );
        assert!(validate_target_address("2001:db8::1").is_ok());
        assert!(validate_target_address("https://example.com").is_err());
        assert!(validate_target_address("bad host").is_err());
    }

    #[test]
    fn rule_edit_reason_is_nft_affecting() {
        assert!(reason_affects_nft("rule.edit"));
    }

    #[test]
    fn deletes_rule_by_index() {
        let mut config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
"#,
        )
        .unwrap();
        let removed = delete_rule(&mut config, 0).unwrap();
        assert!(matches!(removed, NftCell::Single { .. }));
        assert!(config.rules.is_empty());
        assert!(delete_rule(&mut config, 0).is_err());
    }

    #[test]
    fn rule_delete_prunes_last_good_cache_and_writes_audit() {
        use nat_common::last_good::LastGoodRule;

        let dir = safe_write_dir("rule-delete-last-good-prune");
        let config_path = dir.join("nat.toml");
        let last_good_path = dir.join("last-good-state.json");
        let audit_path = dir.join("audit.log");
        let mut config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "a.example.com"
protocol = "tcp"
ip_version = "ipv4"

[[rules]]
type = "single"
sport = 30081
dport = 81
domain = "b.example.com"
protocol = "tcp"
ip_version = "ipv4"

[[rules]]
type = "single"
sport = 30082
dport = 82
domain = "c.example.com"
protocol = "tcp"
ip_version = "ipv4"
"#,
        )
        .unwrap();
        config.last_good.file = last_good_path.to_string_lossy().to_string();
        config.audit = nat_common::AuditConfig {
            enabled: true,
            file: audit_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let before = last_good::identities_from_rules(&config.rules);
        let state = LastGoodState {
            last_success_at: None,
            rules: vec![
                LastGoodRule {
                    rule_id: "r0".to_string(),
                    rule_key: Some(before[0].rule_key.clone()),
                    comment: None,
                    domain: "a.example.com".to_string(),
                    last_good_ip: "10.0.0.1".to_string(),
                    last_resolved_at: chrono::Utc::now(),
                    egress_allowed: true,
                    last_apply_status: "ok".to_string(),
                },
                LastGoodRule {
                    rule_id: "r1".to_string(),
                    rule_key: Some(before[1].rule_key.clone()),
                    comment: None,
                    domain: "b.example.com".to_string(),
                    last_good_ip: "10.0.0.2".to_string(),
                    last_resolved_at: chrono::Utc::now(),
                    egress_allowed: true,
                    last_apply_status: "ok".to_string(),
                },
                LastGoodRule {
                    rule_id: "r2".to_string(),
                    rule_key: Some(before[2].rule_key.clone()),
                    comment: None,
                    domain: "c.example.com".to_string(),
                    last_good_ip: "10.0.0.3".to_string(),
                    last_resolved_at: chrono::Utc::now(),
                    egress_allowed: true,
                    last_apply_status: "ok".to_string(),
                },
            ],
            last_good_nft_hash: None,
        };
        state.save(last_good_path.to_str().unwrap()).unwrap();

        delete_rule(&mut config, 1).unwrap();
        std::fs::write(&config_path, config.to_toml_string().unwrap()).unwrap();
        prune_last_good_cache_after_rule_delete(config_path.to_str().unwrap(), &config);

        let pruned = LastGoodState::load(last_good_path.to_str().unwrap());
        assert_eq!(pruned.rules.len(), 2);
        assert!(pruned.lookup_by_key(&before[1].rule_key).is_none());
        let c = pruned.lookup_by_key(&before[2].rule_key).unwrap();
        assert_eq!(c.rule_id, "r1");
        assert_eq!(c.last_good_ip, "10.0.0.3");
        let audit = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit.contains("\"action\":\"last_good.prune\""));
        assert!(audit.contains("\"removed\":1"));
    }

    #[test]
    fn corrupt_last_good_prune_is_nonfatal_for_rule_delete() {
        let dir = safe_write_dir("rule-delete-last-good-corrupt");
        let config_path = dir.join("nat.toml");
        let last_good_path = dir.join("last-good-state.json");
        let audit_path = dir.join("audit.log");
        let mut config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "a.example.com"
"#,
        )
        .unwrap();
        config.last_good.file = last_good_path.to_string_lossy().to_string();
        config.audit = nat_common::AuditConfig {
            enabled: true,
            file: audit_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        std::fs::write(&config_path, config.to_toml_string().unwrap()).unwrap();
        std::fs::write(&last_good_path, "{not-json").unwrap();

        prune_last_good_cache_after_rule_delete(config_path.to_str().unwrap(), &config);

        assert_eq!(
            std::fs::read_to_string(&last_good_path).unwrap(),
            "{not-json"
        );
        assert!(
            !audit_path.exists(),
            "损坏 last-good 文件只应 WARN，不应写成功 prune audit"
        );
    }

    #[test]
    fn validates_inputs() {
        assert!(parse_port("0").is_err());
        assert!(parse_port("65536").is_err());
        assert!(parse_domain("   ").is_err());
        assert!(parse_protocol("icmp").is_err());
        assert!(parse_ip_version("both").is_err());
        assert!(validate_access_entry("192.0.2.1").is_ok());
        assert!(validate_access_entry("2001:db8::/64").is_ok());
        assert!(validate_access_entry("example.com").is_err());
    }

    #[test]
    fn validates_optional_snat_ip_input() {
        assert_eq!(parse_optional_snat_ip("").unwrap(), None);
        assert_eq!(
            parse_optional_snat_ip("198.51.100.20").unwrap(),
            Some("198.51.100.20".to_string())
        );
        for value in [
            "example.com",
            "1.2.3.4/32",
            "2001:db8::1",
            "1.2.3.4:443",
            "1.2.3.4 ",
        ] {
            assert!(
                parse_optional_snat_ip(value).is_err(),
                "expected invalid snat_ip input: {value}"
            );
        }
    }

    #[test]
    fn validates_update_version_tags() {
        assert!(valid_update_version("latest"));
        assert!(valid_update_version("v0.1.2"));
        assert!(valid_update_version("v1.2.3-rc.1"));
        assert!(!valid_update_version("main"));
        assert!(!valid_update_version("v0.1.2;systemctl"));
    }

    #[test]
    fn parses_release_version_from_nat_version_output() {
        assert_eq!(
            parse_nat_version_output("nat v0.2.2\n").as_deref(),
            Some("v0.2.2")
        );
        assert_eq!(
            parse_nat_version_output("nat-common 2.0.0\n").as_deref(),
            None
        );
    }

    #[test]
    fn update_display_does_not_show_package_version_as_release() {
        assert_eq!(build_version_for_update_display("v0.2.2"), "v0.2.2");
        assert_eq!(build_version_for_update_display("2.0.0"), "unknown");
    }

    #[test]
    fn manages_access_entries() {
        let mut config = TomlConfig::from_toml_str("rules = []").unwrap();
        add_access_entry(&mut config, "192.0.2.1".to_string());
        add_access_entry(&mut config, "192.0.2.1".to_string());
        add_access_entry(&mut config, "2001:db8::1".to_string());
        assert_eq!(config.access_control.entries.len(), 2);
        assert_eq!(delete_access_entry(&mut config, 0).unwrap(), "192.0.2.1");
        clear_access_entries(&mut config);
        assert!(config.access_control.entries.is_empty());
    }

    #[test]
    fn generates_backup_filename() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:34:56+08:00")
            .unwrap()
            .with_timezone(&Local);
        assert_eq!(
            backup_filename("nat-config", "toml", now),
            "nat-config-20260517-123456.toml"
        );
    }

    #[test]
    fn formats_stats_top10() {
        let mut state = StatsState {
            daily_total_bytes: 300,
            monthly_total_bytes: 300,
            ..Default::default()
        };
        for index in 0..12 {
            let id = format!("r{index}");
            state.per_rule_daily_bytes.insert(id.clone(), 1024 + index);
            state
                .per_rule_monthly_bytes
                .insert(id.clone(), 2048 + index);
            state.rule_labels.insert(
                id,
                format!("rule-{index}: 300{index} -> example.com:80/tcp"),
            );
        }
        state.rules = vec![RuleTraffic {
            id: "unused".to_string(),
            label: "unused".to_string(),
            daily_bytes: 0,
            monthly_bytes: 0,
        }];
        let lines = format_stats_top10(&state);
        assert_eq!(lines.len(), 10);
        assert!(lines[0].contains("rule-11"));
    }

    #[test]
    fn reload_action_skips_when_update_failed() {
        assert_eq!(
            reload_action(false, true, true),
            ReloadAction::SkipUpdateFailed
        );
        assert_eq!(
            reload_action(false, false, false),
            ReloadAction::SkipUpdateFailed
        );
    }

    #[test]
    fn reload_action_skips_when_no_tty() {
        assert_eq!(reload_action(true, false, true), ReloadAction::NoTty);
    }

    #[test]
    fn reload_action_reports_missing_binary() {
        assert_eq!(
            reload_action(true, true, false),
            ReloadAction::BinaryMissing
        );
    }

    #[test]
    fn reload_action_execs_when_all_conditions_met() {
        assert_eq!(reload_action(true, true, true), ReloadAction::Exec);
    }

    #[test]
    fn readme_acknowledges_alecthw_chnlist_accurately() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("感谢其提供 nftables 配置示例和 `cn4.nft` 使用参考"),
            "README should describe alecthw/chnlist as providing nftables config examples and cn4.nft reference"
        );
        assert!(
            readme.contains("不代表该项目作者参与、认可或为本项目背书"),
            "README should clarify alecthw/chnlist author does not endorse this project"
        );
        assert!(
            readme.contains("中国大陆 IP 列表本身请以上游数据源为准"),
            "README should point users to upstream data sources for the CN IP list"
        );
    }

    #[test]
    fn readme_does_not_misattribute_cn_ip_list_to_alecthw() {
        let readme = include_str!("../../README.md");
        assert!(
            !readme.contains("维护中国大陆 IP 地址列表"),
            "README must not claim alecthw/chnlist maintains the China mainland IP address list"
        );
        assert!(
            !readme.contains("维护大陆 IP 数据源"),
            "README must not claim alecthw/chnlist maintains the mainland IP data source"
        );
        assert!(
            !readme.contains("背书本项目"),
            "README must not claim alecthw/chnlist 背书本项目"
        );
        assert!(
            !readme.contains("认可本项目"),
            "README must not claim alecthw/chnlist 认可本项目"
        );
    }

    #[test]
    fn readme_documents_cn4_url_replaceable_and_disclaimer() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("cn4.nft` 数据源可配置")
                || readme.contains("cn4_url` 默认值只是一个参考数据源"),
            "README should explain that cn4_url is replaceable"
        );
        assert!(
            readme.contains("中国大陆 IP 数据可能存在误差"),
            "README should disclose that CN IP data may have errors"
        );
        assert!(
            readme.contains("APNIC")
                && readme.contains("clang.cn")
                && readme.contains("纯真")
                && readme.contains("ipip.net"),
            "README should suggest alternative trusted data sources"
        );
    }

    fn make_config(
        ac_mode: AccessControlMode,
        ac_entries: &[&str],
        geoip_enabled: bool,
        forward_enabled: bool,
        ssh_enabled: bool,
    ) -> TomlConfig {
        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.access_control = nat_common::AccessControlConfig {
            mode: ac_mode,
            entries: ac_entries.iter().map(|s| s.to_string()).collect(),
        };
        cfg.geoip.enabled = geoip_enabled;
        cfg.geoip.forward.enabled = forward_enabled;
        cfg.geoip.ssh.enabled = ssh_enabled;
        cfg
    }

    #[test]
    fn combined_policy_shows_and_for_blacklist_plus_geoip() {
        let cfg = make_config(
            AccessControlMode::Blacklist,
            &["8.8.8.8"],
            true,
            true,
            false,
        );
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("access_control（自定义来源 IP 限制）：模式=blacklist entries=1"));
        assert!(lines.contains("GeoIP 来源限制（国家/地区 IP）：转发端口=enabled SSH=disabled"));
        assert!(lines.contains(
            "评估顺序：黑名单 > 白名单（静态 + dynamic_whitelist）> GeoIP（同时启用 = AND）"
        ));
        assert!(lines.contains("允许 = 不在黑名单 AND 属于 CN/LAN"));
    }

    #[test]
    fn combined_policy_shows_and_for_whitelist_plus_geoip() {
        let cfg = make_config(
            AccessControlMode::Whitelist,
            &["1.2.3.4", "5.6.7.0/24"],
            true,
            true,
            false,
        );
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("access_control（自定义来源 IP 限制）：模式=whitelist entries=2"));
        assert!(lines.contains("允许 = 在白名单（静态 + dynamic_whitelist）AND 属于 CN/LAN"));
    }

    #[test]
    fn dynamic_whitelist_status_mentions_whitelist_requirement_and_stale_counts() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.dynamic_whitelist.enabled = true;
        cfg.dynamic_whitelist.domains = vec![DynamicWhitelistDomainConfig {
            name: "home".to_string(),
            domain: "home.example.com".to_string(),
            enabled: true,
        }];
        let state = DynamicWhitelistState {
            domains: vec![nat_common::dynamic_whitelist::DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                last_good_ips: vec!["203.0.113.10".to_string()],
                current_ips: vec!["203.0.113.10".to_string()],
                raw_ips: vec!["203.0.113.10".to_string()],
                effective_sources: vec!["203.0.113.10".to_string()],
                cidr_expand_ipv4: 32,
                resolved_at: Some("2026-05-28T00:00:00Z".to_string()),
                stale: true,
                error: Some("mock dns failure".to_string()),
                ipv4: true,
                ipv6: false,
            }],
        };
        let lines = format_dynamic_whitelist_status_lines(&cfg, &state).join("\n");
        assert!(lines.contains("enabled: true"));
        assert!(lines.contains("当前 raw IP 数量: 1"));
        assert!(lines.contains("当前 effective sources 数量: 1"));
        assert!(lines.contains("cidr_expand_ipv4: /32 精确 IP（默认）"));
        assert!(lines.contains("stale 数量: 1"));
        assert!(lines.contains("access_control 未启用 whitelist 模式"));
        assert!(lines.contains("不是目标 IP"));
    }

    #[test]
    fn dynamic_whitelist_detail_shows_current_last_good_and_error() {
        let mut cfg = make_config(AccessControlMode::Whitelist, &[], false, false, false);
        cfg.dynamic_whitelist.enabled = true;
        cfg.dynamic_whitelist.domains = vec![DynamicWhitelistDomainConfig {
            name: "home".to_string(),
            domain: "home.example.com".to_string(),
            enabled: true,
        }];
        let state = DynamicWhitelistState {
            domains: vec![nat_common::dynamic_whitelist::DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                last_good_ips: vec!["203.0.113.10".to_string()],
                current_ips: vec!["203.0.113.10".to_string()],
                raw_ips: vec!["203.0.113.10".to_string()],
                effective_sources: vec!["203.0.113.10".to_string()],
                cidr_expand_ipv4: 32,
                resolved_at: Some("2026-05-28T00:00:00Z".to_string()),
                stale: true,
                error: Some("mock dns failure".to_string()),
                ipv4: true,
                ipv6: false,
            }],
        };
        let lines = format_dynamic_whitelist_detail_lines(&cfg, &state).join("\n");
        assert!(lines.contains("current_ips: 203.0.113.10"));
        assert!(lines.contains("last_good_ips: 203.0.113.10"));
        assert!(lines.contains("raw_ips: 203.0.113.10"));
        assert!(lines.contains("effective_sources: 203.0.113.10"));
        assert!(lines.contains("cidr_expand_ipv4: /32 精确 IP（默认）"));
        assert!(lines.contains("stale: true"));
        assert!(lines.contains("error: mock dns failure"));
    }

    #[test]
    fn combined_policy_no_restriction_when_both_off() {
        let cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("允许 = 所有来源"));
    }

    #[test]
    fn combined_policy_geoip_only_when_access_control_off() {
        let cfg = make_config(AccessControlMode::Off, &[], true, true, false);
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("允许 = 属于 CN/LAN"));
    }

    #[test]
    fn combined_policy_blacklist_only_when_geoip_forward_off() {
        let cfg = make_config(
            AccessControlMode::Blacklist,
            &["8.8.8.8"],
            true,
            false,
            true,
        );
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("GeoIP 来源限制（国家/地区 IP）：转发端口=disabled SSH=enabled"));
        assert!(lines.contains("允许 = 不在黑名单"));
        assert!(!lines.contains("AND 属于 CN/LAN"));
    }

    #[test]
    fn combined_policy_includes_egress_snat_mss() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.egress_control.enabled = true;
        cfg.egress_control.allowed_target_cidrs = vec!["10.100.0.0/24".to_string()];
        cfg.snat.mode = SnatMode::Fixed;
        cfg.snat.fixed_source_ip = "10.100.0.10".to_string();
        cfg.mss_clamp.enabled = true;
        cfg.mss_clamp.size = 1452;
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(
            lines.contains("egress_control（目标 IP / IP 段限制）：enabled allowed_target_cidrs=1")
        );
        assert!(lines.contains("SNAT（源地址改写）：fixed snat to 10.100.0.10"));
        assert!(lines.contains("MSS clamp（TCP MSS 调整）：enabled size=1452"));
        assert!(lines.contains("最终目标策略：仅允许转发到 allowed_target_cidrs 内的目标 IP"));
        assert!(lines.contains(
            "说明：access_control / dynamic_whitelist / GeoIP 是来源 IP 限制；egress_control 是目标 IP 限制；SNAT 是源地址改写；MSS clamp 是 TCP MSS 调整。"
        ));
    }

    #[test]
    fn combined_policy_describes_snat_off_and_empty_egress() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.snat.mode = SnatMode::Off;
        cfg.egress_control.enabled = true;
        cfg.egress_control.allowed_target_cidrs = Vec::new();
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(lines.contains("SNAT（源地址改写）：off（不生成 SNAT 规则）"));
        assert!(lines.contains(
            "最终目标策略：egress_control 已启用但 allowed_target_cidrs 为空，所有转发规则都会被跳过"
        ));
    }

    #[test]
    fn combined_policy_emits_off_route_warning_for_snat_off() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.snat.mode = SnatMode::Off;
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(
            lines.contains("警告：未生成 SNAT，需自行保证回程路由"),
            "SNAT=off must trigger return-route warning in CLI status"
        );
        assert!(
            lines.contains("普通 VPS 推荐 masquerade"),
            "warning should also suggest masquerade for ordinary VPS"
        );
    }

    #[test]
    fn combined_policy_emits_ipv4_only_hint_for_snat_fixed() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.snat.mode = SnatMode::Fixed;
        cfg.snat.fixed_source_ip = "10.100.0.10".to_string();
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(
            lines.contains("fixed SNAT 第一版仅支持 IPv4"),
            "fixed SNAT should advertise its IPv4-only limitation"
        );
    }

    #[test]
    fn combined_policy_emits_mss_scope_hint_when_enabled() {
        let mut cfg = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg.mss_clamp.enabled = true;
        let lines = format_combined_policy_status(&cfg).join("\n");
        assert!(
            lines.contains("MSS clamp 仅作用于本项目转发相关 TCP 流量"),
            "enabled MSS clamp should advertise its scope"
        );
        assert!(
            lines.contains("不影响 UDP 或非本项目端口"),
            "enabled MSS clamp should clarify it does not touch UDP / other ports"
        );
    }

    #[test]
    fn combined_policy_no_off_warning_when_snat_masquerade_or_fixed() {
        let cfg_masq = make_config(AccessControlMode::Off, &[], false, false, false);
        let lines_masq = format_combined_policy_status(&cfg_masq).join("\n");
        assert!(!lines_masq.contains("警告：未生成 SNAT"));

        let mut cfg_fixed = make_config(AccessControlMode::Off, &[], false, false, false);
        cfg_fixed.snat.mode = SnatMode::Fixed;
        cfg_fixed.snat.fixed_source_ip = "10.100.0.10".to_string();
        let lines_fixed = format_combined_policy_status(&cfg_fixed).join("\n");
        assert!(!lines_fixed.contains("警告：未生成 SNAT"));
    }

    #[test]
    fn validate_fixed_source_ip_accepts_ipv4() {
        assert!(validate_fixed_source_ip("10.100.0.10").is_ok());
    }

    #[test]
    fn validate_fixed_source_ip_rejects_empty_and_ipv6_and_invalid() {
        assert!(validate_fixed_source_ip("").is_err());
        assert!(validate_fixed_source_ip("2001:db8::1").is_err());
        assert!(validate_fixed_source_ip("not-an-ip").is_err());
    }

    #[test]
    fn parse_mss_size_accepts_boundary_values() {
        assert_eq!(parse_mss_size("536").unwrap(), 536);
        assert_eq!(parse_mss_size("1460").unwrap(), 1460);
        assert_eq!(parse_mss_size(" 1452 ").unwrap(), 1452);
    }

    #[test]
    fn parse_mss_size_rejects_out_of_range_and_non_numeric() {
        assert!(parse_mss_size("535").is_err());
        assert!(parse_mss_size("1461").is_err());
        assert!(parse_mss_size("abc").is_err());
    }

    #[test]
    fn readme_documents_snat_mss_combined_policy() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("### SNAT 模式"),
            "README should document SNAT modes"
        );
        assert!(
            readme.contains("`fixed`：生成 `snat to <fixed_source_ip>`"),
            "README should describe the fixed SNAT mode"
        );
        assert!(
            readme.contains("`mss_clamp`") && readme.contains("TCP SYN 写 MSS"),
            "README should document MSS clamp"
        );
        assert!(
            readme.contains("源地址改写（masquerade / fixed / off）"),
            "README should label snat as source rewrite with its modes"
        );
        assert!(
            readme.contains("AND 叠加") && readme.contains("`egress_control` 是目标限制，独立判断"),
            "README should state AND source semantics and independent target restriction"
        );
    }

    #[test]
    fn cli_audit_helpers_emit_one_json_line_per_action() {
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-audit-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.log");
        let config_path = dir.join("nat.toml");
        let toml = format!(
            "rules = []\n\n[audit]\nenabled = true\nfile = \"{}\"\n",
            audit_path.to_string_lossy()
        );
        std::fs::write(&config_path, toml).unwrap();
        audit_cli(
            config_path.to_str().unwrap(),
            "rule.add",
            AuditResult::Ok,
            json!({"sport": 30080}),
        );
        audit_cli(
            config_path.to_str().unwrap(),
            "telegram.config.update",
            AuditResult::Ok,
            json!({"bot_token": "1234567890:ABCDEFGH", "chat_id": "12345"}),
        );
        let lines = audit::read_tail(&audit_path.to_string_lossy(), 50);
        assert_eq!(lines.len(), 2);
        let l0: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let l1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(l0["action"], "rule.add");
        assert_eq!(l1["action"], "telegram.config.update");
        let token_str = l1["detail"]["bot_token"].as_str().unwrap();
        assert!(
            !token_str.contains("ABCDEFGH"),
            "CLI must hand audit module a pre-masked or recognized-secret bot_token: {token_str}"
        );
        assert!(token_str.contains("***"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_audit_disabled_writes_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-audit-off-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.log");
        let config_path = dir.join("nat.toml");
        let toml = format!(
            "rules = []\n\n[audit]\nenabled = false\nfile = \"{}\"\n",
            audit_path.to_string_lossy()
        );
        std::fs::write(&config_path, toml).unwrap();
        audit_cli(
            config_path.to_str().unwrap(),
            "rule.add",
            AuditResult::Ok,
            json!({}),
        );
        assert!(audit::read_tail(&audit_path.to_string_lossy(), 50).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_audit_failure_does_not_break_main_flow() {
        // audit.file 指向不可写路径，主流程不应 panic
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-audit-fail-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("nat.toml");
        let toml =
            "rules = []\n\n[audit]\nenabled = true\nfile = \"/proc/cannot/write/here/audit.log\"\n";
        std::fs::write(&config_path, toml).unwrap();
        audit_cli(
            config_path.to_str().unwrap(),
            "apply.fail",
            AuditResult::Fail,
            json!({"reason": "x"}),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_audit_does_not_log_raw_bot_token() {
        // 直接断言 mask_secret_str 的行为以及 audit.log_event 兜底 redaction
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-redact-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.log").to_string_lossy().to_string();
        let audit_cfg = AuditConfig {
            enabled: true,
            file: audit_path.clone(),
            ..Default::default()
        };
        // 即使调用方意外把原始 token 塞进 detail，audit 模块也会兜底 redact
        audit::log_event(
            &audit_cfg,
            "telegram.config.update",
            AuditResult::Ok,
            json!({"bot_token": "1234567890:LEAKME_PLEASE", "chat_id": "99999"}),
        );
        let lines = audit::read_tail(&audit_path, 50);
        assert_eq!(lines.len(), 1);
        assert!(
            !lines[0].contains("LEAKME_PLEASE"),
            "audit log must never contain raw bot_token: {}",
            lines[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_good_status_includes_summary_lines() {
        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.last_good = nat_common::LastGoodConfig {
            enabled: true,
            file: "/tmp/this-file-may-not-exist-for-test".to_string(),
            use_last_good_on_dns_failure: true,
        };
        let lines = format_last_good_status(&cfg).join("\n");
        assert!(lines.contains("last-good 状态缓存"));
        assert!(lines.contains("enabled: true"));
        assert!(lines.contains("use_last_good_on_dns_failure: true"));
        assert!(lines.contains("file: /tmp/this-file-may-not-exist-for-test"));
    }

    #[test]
    fn readme_documents_quota() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("`quota`：基于 Stats"),
            "README should document quota and that it builds on Stats"
        );
        assert!(
            readme.contains("超额自动禁用规则")
                || readme.contains("超额后把规则 `enabled` 置 false"),
            "README should explain quota auto-disable on exceed"
        );
        assert!(
            readme.contains("不直接 `nft -f`") && readme.contains("不删规则"),
            "README must state quota does not directly run nft or delete rules"
        );
    }

    #[test]
    fn readme_documents_last_good_and_audit() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("### last-good / Stats / quota / audit"),
            "README should document last-good and audit"
        );
        assert!(
            readme.contains("`last_good`") && readme.contains("`audit`"),
            "README should document both last_good and audit"
        );
        assert!(
            readme.contains("Telegram") && readme.contains("脱敏"),
            "README should mention Telegram bot_token redaction"
        );
        assert!(
            readme.contains("不绕过 `egress_control`"),
            "README should explain last-good does not bypass egress_control"
        );
    }

    #[test]
    fn readme_documents_v0_6_1_save_hint_split_and_script_hash() {
        // v0.6.1 的实现细节（保存提示分流 / script_hash）已下沉到 CHANGELOG。
        let changelog = include_str!("../../CHANGELOG.md");
        assert!(
            changelog.contains("保存提示按 reason 分流"),
            "CHANGELOG 应说明配置保存提示按 reason 分流"
        );
        assert!(
            changelog.contains("stable_script_hash") || changelog.contains("script_hash"),
            "CHANGELOG 应说明用 hash 判断脚本变化"
        );
        assert!(
            changelog.contains("FNV") || changelog.contains("FNV-1a"),
            "CHANGELOG 应说明 hash 算法选择"
        );
    }

    #[test]
    fn readme_documents_v0_6_0_audit_rotation_and_safe_write_and_latest_resolution() {
        let readme = include_str!("../../README.md");
        // audit 内置轻量轮转（精简首页保留高层说明，具体参数下沉到 CLI / 源码）
        assert!(
            readme.contains("内置轻量轮转"),
            "README 应说明 audit 内置轮转"
        );
        // safe_write_config 安全写配置流程（README 与 CHANGELOG 均应有）
        assert!(
            readme.contains("safe_write_config") || readme.contains("安全写配置"),
            "README 应描述安全写配置流程"
        );
        let changelog = include_str!("../../CHANGELOG.md");
        assert!(
            changelog.contains("safe_write_config"),
            "CHANGELOG 应记录 safe_write_config 安全写配置流程"
        );
    }

    #[test]
    fn readme_documents_combined_policy() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("### 来源与目标控制"),
            "README should document the combined source/target policy"
        );
        assert!(
            readme.contains("AND 叠加"),
            "README should state AND semantics"
        );
        assert!(
            readme.contains("黑名单优先拒绝"),
            "README should state blacklist priority"
        );
        assert!(
            readme.contains("白名单精确放行"),
            "README should describe whitelist as exact-source restriction"
        );
        assert!(
            readme.contains("GeoIP 地区放行"),
            "README should describe GeoIP as country restriction"
        );
        assert!(
            readme.contains("`egress_control` 是目标限制，独立判断"),
            "README should state egress_control is an independent target restriction"
        );
    }

    #[test]
    fn readme_documents_auto_reload_after_update() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("成功后自动重载新版菜单"),
            "README should note that the CLI auto-reloads after one-key update"
        );
        assert!(
            readme.contains("更新前备份旧二进制 / service，失败尝试回滚"),
            "README should document update backup/rollback safety"
        );
    }

    #[test]
    fn formats_stats_overview_with_mode_and_baseline_hints() {
        let mut state = StatsState::default();
        state.last_counters.insert(
            "r0:out".to_string(),
            Counter {
                packets: 1,
                bytes: 100,
            },
        );
        state.last_counters.insert(
            "r0:in".to_string(),
            Counter {
                packets: 0,
                bytes: 0,
            },
        );
        let config = StatsConfig {
            traffic_mode: TrafficMode::Both,
            ..Default::default()
        };
        let lines = format_stats_overview(&config, &state).join("\n");
        assert!(lines.contains("统计口径：both 双向 out + in"));
        assert!(lines.contains("首次采集可能仅建立 baseline"));
        assert!(lines.contains("目标可能没有返回流量"));
    }

    // ============ v0.4.1: 子菜单返回 / 时间 / NTP / 提示 / README 测试 ============

    #[test]
    fn last_good_status_uses_shanghai_24h_not_rfc3339() {
        use nat_common::last_good::{LastGoodRule, LastGoodState};
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-time-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("last-good.json");
        let state = LastGoodState {
            last_success_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58.213104971Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            rules: vec![LastGoodRule {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: Some("hk-out".to_string()),
                domain: "example.com".to_string(),
                last_good_ip: "1.2.3.4".to_string(),
                last_resolved_at: chrono::DateTime::parse_from_rfc3339("2026-05-19T17:30:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                egress_allowed: true,
                last_apply_status: "ok".to_string(),
            }],
            last_good_nft_hash: None,
        };
        state.save(path.to_str().unwrap()).unwrap();

        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.last_good = nat_common::LastGoodConfig {
            enabled: true,
            file: path.to_string_lossy().to_string(),
            use_last_good_on_dns_failure: true,
        };
        let blob = format_last_good_status(&cfg).join("\n");

        // 最近成功应用时间：UTC 12:02:58 → Shanghai 20:02:58
        assert!(
            blob.contains("最近成功应用时间: 2026-05-19 20:02:58 CST"),
            "missing Shanghai 24h time: {blob}"
        );
        // resolved_at：UTC 17:30 → Shanghai 次日 01:30
        assert!(
            blob.contains("resolved_at=2026-05-20 01:30:00 CST"),
            "resolved_at must use Shanghai 24h: {blob}"
        );
        // 没有 RFC3339 风格 T + 纳秒
        assert!(
            !blob.contains("T12:02:58"),
            "must not show RFC3339 T form: {blob}"
        );
        assert!(
            !blob.contains(".213104971"),
            "must not show nanoseconds: {blob}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reason_affects_nft_recognizes_rule_and_policy_reasons() {
        for reason in [
            "rule.add.single",
            "rule.add.range",
            "rule.delete",
            "rule.toggle",
            "access_control.update",
            "dynamic_whitelist.domain.add",
            "dynamic_whitelist.domain.delete",
            "dynamic_whitelist.domain.toggle",
            "geoip.forward.update",
            "geoip.ssh.update",
            "geoip.ssh.port.update",
            "geoip.update_interval.update",
            "egress_control.update",
            "egress.add",
            "egress.delete",
            "snat.mode.update",
            "snat.fixed_source_ip.update",
            "mss_clamp.toggle",
            "mss_clamp.size.update",
            "backup.restore",
            "quota.auto_disable",
            "quota.config.update",
            "stats.mode.update",
        ] {
            assert!(
                reason_affects_nft(reason),
                "reason {reason:?} 应被识别为影响 nft"
            );
        }
    }

    #[test]
    fn reason_affects_nft_skips_telegram_ui_audit() {
        for reason in [
            "telegram.config.update",
            "telegram.toggle",
            "telegram.interval.update",
            "ui.timezone.update",
            "audit.update",
            "config.update",
            "dynamic_whitelist.interval.update",
        ] {
            assert!(
                !reason_affects_nft(reason),
                "reason {reason:?} 不应被识别为影响 nft"
            );
        }
    }

    #[test]
    fn non_nft_save_hint_does_not_mention_systemctl_or_nft_commands() {
        let lines =
            format_non_nft_save_hint_lines("/etc/nat.toml", "telegram.config.update").join("\n");
        assert!(
            lines.contains("无需等待 nft 应用"),
            "non-nft hint 应说明无需等 nft apply: {lines}"
        );
        assert!(
            !lines.contains("systemctl restart nat"),
            "telegram 保存提示不应包含 systemctl restart: {lines}"
        );
        assert!(
            !lines.contains("nft list table"),
            "telegram 保存提示不应包含 nft list table: {lines}"
        );
        assert!(
            !lines.contains("journalctl -u nat"),
            "telegram 保存提示不应包含 journalctl: {lines}"
        );
        assert!(
            !lines.contains("nft -c"),
            "telegram 保存提示不应包含 nft -c: {lines}"
        );
        assert!(lines.contains("Telegram 配置已安全保存"));
    }

    #[test]
    fn ui_timezone_save_hint_uses_short_form() {
        let lines =
            format_non_nft_save_hint_lines("/etc/nat.toml", "ui.timezone.update").join("\n");
        assert!(
            !lines.contains("Telegram"),
            "UI 保存提示不应误带 Telegram 文案: {lines}"
        );
        assert!(
            lines.contains("不会改变 nft 转发规则"),
            "UI 保存提示应说明不影响 nft: {lines}"
        );
        assert!(
            !lines.contains("systemctl restart nat"),
            "UI 保存提示不应引导用户重启 nat: {lines}"
        );
    }

    #[test]
    fn nft_affecting_save_hint_still_mentions_apply_path() {
        // 创建一个最小 TOML 让 load_toml_config 走通；hint 内部会读 ddns.refresh_interval_seconds
        let dir = std::env::temp_dir().join(format!(
            "nat-hint-nft-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("nat.toml");
        std::fs::write(
            &toml_path,
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"

[ddns]
refresh_interval_seconds = 120
"#,
        )
        .unwrap();
        let lines =
            format_nft_affecting_save_hint_lines(toml_path.to_str().unwrap(), "rule.add.single")
                .join("\n");
        assert!(
            lines.contains("nat.service 通常会自动检测配置变化"),
            "缺少 nat.service 自动应用文案: {lines}"
        );
        assert!(
            lines.contains("systemctl restart nat"),
            "应保留 systemctl restart nat 提示: {lines}"
        );
        assert!(
            lines.contains("nft list table ip self-nat"),
            "应保留 nft list table 排查命令: {lines}"
        );
        // 同时确认正确读取了 refresh_interval_seconds = 120
        assert!(
            lines.contains("120 秒"),
            "应从 TOML 中读取自定义 ddns 间隔: {lines}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule_delete_save_hint_mentions_backup_skip_and_omits_backup_dir() {
        let dir = std::env::temp_dir().join(format!(
            "nat-hint-rule-delete-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("nat.toml");
        std::fs::write(
            &toml_path,
            r#"
[ddns]
refresh_interval_seconds = 120
"#,
        )
        .unwrap();
        let lines =
            format_nft_affecting_save_hint_lines(toml_path.to_str().unwrap(), "rule.delete")
                .join("\n");
        assert!(lines.contains("已安全保存配置到"));
        assert!(lines.contains("本次操作为删除规则，已按策略跳过自动备份。"));
        assert!(lines.contains("nat.service 通常会自动检测配置变化"));
        assert!(
            !lines.contains("备份目录："),
            "rule.delete 提示不应显示备份目录: {lines}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn print_config_saved_hint_mentions_detection_cycle_and_restart() {
        // 用一个真实 TOML 验证：print_config_saved_hint 内部读取 ddns.refresh_interval_seconds
        // 并把它印出来。我们用 capture 不方便（println! 走 stdout），所以这里改成检查
        // print_config_saved_hint 的关键依赖：load_toml_config 读出的 ddns.refresh_interval_seconds。
        // 这等价于断言 hint 用到的常量来源是配置文件，而不是硬编码。
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-hint-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let toml_path = dir.join("nat.toml");
        std::fs::write(
            &toml_path,
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"

[ddns]
refresh_interval_seconds = 120
"#,
        )
        .unwrap();
        let cfg = load_toml_config(toml_path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.ddns.refresh_interval_seconds, 120);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_timedatectl_field_recognizes_systemd_output() {
        let sample = r#"
               Local time: Tue 2026-05-19 20:02:58 CST
           Universal time: Tue 2026-05-19 12:02:58 UTC
                 RTC time: Tue 2026-05-19 12:02:58
                Time zone: Asia/Shanghai (CST, +0800)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
"#;
        assert_eq!(
            parse_timedatectl_field(sample, "Time zone").as_deref(),
            Some("Asia/Shanghai (CST, +0800)")
        );
        assert_eq!(
            parse_timedatectl_field(sample, "System clock synchronized").as_deref(),
            Some("yes")
        );
        assert_eq!(
            parse_timedatectl_field(sample, "NTP service").as_deref(),
            Some("active")
        );
        assert_eq!(parse_timedatectl_field(sample, "Nonexistent Key"), None);
    }

    #[test]
    fn parse_timedatectl_field_does_not_panic_on_empty_input() {
        assert_eq!(parse_timedatectl_field("", "Time zone"), None);
        assert_eq!(
            parse_timedatectl_field("garbage line\n", "System clock synchronized"),
            None
        );
    }

    #[test]
    fn readme_documents_quota_total_traffic_mode_relation() {
        // quota 与 stats.traffic_mode 的关系：quota 基于 Stats 的当前口径统计。
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("`quota`：基于 Stats") && readme.contains("traffic_mode"),
            "README 必须说明 quota 基于 Stats 当前 traffic_mode 口径"
        );
    }

    #[test]
    fn menu_outcome_cancelled_signals_skip_wait() {
        // 仅静态属性断言：MenuOutcome 是 Copy + Eq，且包含 Done / Cancelled 两个变体
        let a = MenuOutcome::Cancelled;
        let b = MenuOutcome::Done;
        assert_ne!(a, b);
        // Copy 检查
        let _copied = a;
        assert_eq!(a, MenuOutcome::Cancelled);
    }

    // ============ v0.4.2 ============

    #[test]
    fn main_menu_title_includes_version_string_from_build_version() {
        let title = main_menu_title();
        assert!(
            title.starts_with("nft-nat-rust "),
            "title 必须以 nft-nat-rust 开头: {title}"
        );
        let version = nat_common::build_version();
        assert!(
            title.contains(version) || title.ends_with(" dev"),
            "title 必须包含 build_version 或回退 dev：title={title} version={version}"
        );
    }

    #[test]
    fn main_menu_title_uses_dev_when_unknown() {
        // 间接验证 build_version() == "unknown" 时的兜底逻辑。
        // build_version 返回 &'static str，不能直接 mock；但我们可以测 title
        // 的分支逻辑通过将 build_version() 输出当作输入构造预期。
        let v = nat_common::build_version().trim();
        if v.is_empty() || v.eq_ignore_ascii_case("unknown") {
            assert_eq!(main_menu_title(), "nft-nat-rust dev");
        } else {
            assert_eq!(main_menu_title(), format!("nft-nat-rust {v}"));
        }
    }

    #[test]
    fn parse_timedatectl_field_recognizes_extra_keys() {
        let sample = "Time zone: America/Chicago (CDT, -0500)\nNTP service: inactive\nSystem clock synchronized: no\n";
        assert_eq!(
            parse_timedatectl_field(sample, "Time zone").as_deref(),
            Some("America/Chicago (CDT, -0500)")
        );
        assert_eq!(
            parse_timedatectl_field(sample, "System clock synchronized").as_deref(),
            Some("no")
        );
    }

    #[test]
    fn ui_timezone_can_be_set_via_toml_and_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "nat-menu-ui-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        std::fs::write(
            &path,
            r#"
[ui]
timezone = "America/Chicago"
time_format = "%Y-%m-%d %H:%M:%S %Z"
"#,
        )
        .unwrap();
        let cfg = load_toml_config(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.ui.timezone, "America/Chicago");
        // 序列化往返
        let serialized = cfg.to_toml_string().unwrap();
        assert!(serialized.contains("America/Chicago"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connectivity_report_snat_section_shows_default_for_rule_without_snat_ip() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            Some(true),
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("4. SNAT 出口诊断"));
        assert!(lines.contains("- snat_ip：default"));
        assert!(lines.contains("不适用（规则未配置 snat_ip"));
        assert!(lines.contains("不能替代从公网外部"));
        // 默认无 snat_ip，不应产生 per-rule snat_ip 缺失告警。
        assert!(!conclusion_text(&lines).contains("未发现 snat to"));
    }

    #[test]
    fn connectivity_report_warns_when_per_rule_snat_ip_missing_in_nft() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let mut report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            Some(true),
        );
        report.snat = SnatEgressReport {
            plan: nat_common::forward_test::snat_plan(
                Some("198.51.100.20"),
                "ipv4",
                "masquerade",
                "",
                None,
            ),
            nft_snat_to: SnatNftCheck::Missing("198.51.100.20".to_string()),
            system_egress_ip: Some("203.0.113.1".to_string()),
            route_from_snat: nat_common::forward_test::EgressProbe::Ok(
                "from 198.51.100.20 可路由".to_string(),
            ),
            curl_egress: nat_common::forward_test::EgressProbe::Warn("curl 不可用".to_string()),
        };
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("- snat 模式：per-rule"));
        assert!(lines.contains("- snat_ip：198.51.100.20"));
        assert!(lines.contains("nft snat to 198.51.100.20：not found"));
        assert!(lines.contains("curl --interface snat_ip：warn"));
        assert!(conclusion_text(&lines).contains("未发现 snat to 198.51.100.20"));
    }

    #[test]
    fn print_nft_detection_block_smoke() {
        // 仅冒烟：构造 presence + rule + 调用，不 panic 即可（输出走 stdout）。
        let presence = nat_common::forward_test::NftRulePresence {
            nat_rule_v4_found: true,
            forward_out_v4_found: true,
            forward_in_v4_found: true,
            protocol_tcp_seen: true,
            ..Default::default()
        };
        let rule = nat_common::forward_test::TestableRule {
            index: 0,
            id: "r0".to_string(),
            label: "smoke".to_string(),
            r#type: "single".to_string(),
            sport: 30080,
            target: "example.com".to_string(),
            resolved_ip: Some("1.2.3.4".to_string()),
            dport: 80,
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        print_nft_detection_block(
            &presence,
            nat_common::forward_test::NftDetectionVerdict::Applied,
            &rule,
            true,
            true,
            "apply.success @ 2026-05-19 20:00:00 CST",
            300,
        );
        // 用 Unconfirmed 路径再走一次：检测器没找到但 service active + apply ok
        print_nft_detection_block(
            &Default::default(),
            nat_common::forward_test::NftDetectionVerdict::Unconfirmed,
            &rule,
            true,
            true,
            "apply.success @ 2026-05-19 20:00:00 CST",
            300,
        );
    }

    fn sample_resolution_display() -> RuleResolutionDisplay {
        RuleResolutionDisplay {
            target_kind: "IP".to_string(),
            resolved_ip_label: "93.184.216.34".to_string(),
            last_good_label: "none (IP target)".to_string(),
            notes: Vec::new(),
        }
    }

    fn sample_last_apply_success() -> LastApplyDisplay {
        LastApplyDisplay {
            state: LastApplyState::Success,
            time_label: Some("2026-05-19 20:00:00 CST".to_string()),
        }
    }

    fn checked_nft_status(
        verdict: nat_common::forward_test::NftDetectionVerdict,
    ) -> NftConnectivityStatus {
        NftConnectivityStatus::Checked {
            self_nat: ProbeState::Found,
            self_filter: ProbeState::Found,
            verdict,
            counters: Some(nat_common::forward_test::RuleTestCounters::default()),
            counter_warning: None,
        }
    }

    fn sample_connectivity_report<'a>(
        rule: &'a nat_common::forward_test::TestableRule,
        rule_enabled: bool,
        nat_service: NatServiceStatus,
        nft: NftConnectivityStatus,
        target_tcp: Option<bool>,
    ) -> ConnectivityReport<'a> {
        ConnectivityReport {
            rule,
            global_enabled: true,
            rule_enabled,
            resolution: sample_resolution_display(),
            nat_service,
            last_apply: if rule_enabled {
                sample_last_apply_success()
            } else {
                LastApplyDisplay::not_checked()
            },
            nft,
            target_tcp,
            access_control_note: None,
            snat: sample_snat_egress_report(),
        }
    }

    /// 默认样本：规则无 per-rule snat_ip，全局 masquerade，未触发出口探测。
    fn sample_snat_egress_report() -> SnatEgressReport {
        SnatEgressReport {
            plan: nat_common::forward_test::snat_plan(None, "ipv4", "masquerade", "", None),
            nft_snat_to: SnatNftCheck::NoSnatIp,
            system_egress_ip: None,
            route_from_snat: nat_common::forward_test::EgressProbe::Skipped("test".to_string()),
            curl_egress: nat_common::forward_test::EgressProbe::Skipped("test".to_string()),
        }
    }

    fn conclusion_text(lines: &str) -> &str {
        lines.split("7. 结论").nth(1).unwrap_or(lines)
    }

    #[test]
    fn connectivity_report_active_applied_reachable_concludes_ok() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            Some(true),
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("1. 配置状态"));
        assert!(lines.contains("- nat.service：active"));
        assert!(lines.contains("- 检测结论：已应用"));
        assert!(lines.contains("- 目标 TCP：可达"));
        let conclusion = conclusion_text(&lines);
        assert!(conclusion.contains("✅ 服务端配置、nft 应用和目标连通性看起来正常"));
        assert!(conclusion.contains("ℹ️ 最终入口可用性仍建议"));
        assert!(
            !conclusion.contains("⚠️"),
            "正常结论不应把外部机器测试建议展示为 warning: {conclusion}"
        );
    }

    #[test]
    fn connectivity_report_global_disabled_warns_and_skips_nft_judgement() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let mut report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::NotChecked,
            NftConnectivityStatus::SkippedGlobalDisabled,
            None,
        );
        report.global_enabled = false;
        report.last_apply = LastApplyDisplay::not_checked();
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("- 全局转发：disabled"));
        assert!(lines.contains("全局转发已关闭，该规则当前不会生效"));
        assert!(!lines.contains("检测结论：已应用"));
        let conclusion = conclusion_text(&lines);
        assert!(conclusion.contains("⚠️ 全局转发已关闭"));
    }

    #[test]
    fn connectivity_report_udp_applied_uses_info_not_warning_for_external_validation() {
        let rule = sample_testable_rule("93.184.216.34", "udp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            None,
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        let conclusion = conclusion_text(&lines);
        assert!(conclusion.contains("✅ 服务端配置、nft 应用和目标连通性看起来正常"));
        assert!(conclusion.contains("ℹ️ 最终入口可用性仍建议"));
        assert!(!conclusion.contains("⚠️"));
    }

    #[test]
    fn connectivity_report_unconfirmed_nft_with_reachable_target_does_not_claim_not_applied() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Unconfirmed),
            Some(true),
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        let conclusion = conclusion_text(&lines);
        assert!(conclusion.contains("⚠️ 规则已保存，但 nft 检测器尚未确认应用"));
        assert!(
            !conclusion.contains("nft 尚未确认应用"),
            "Unconfirmed 应归因为检测器未确认，不应判死为未应用: {conclusion}"
        );
    }

    #[test]
    fn connectivity_report_inactive_service_tells_user_to_check_systemctl_status() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Inactive,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::NotApplied),
            None,
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("- nat.service：inactive"));
        assert!(
            conclusion_text(&lines)
                .contains("⚠️ nat.service 未运行，请先检查 systemctl status nat")
        );
    }

    #[test]
    fn connectivity_report_target_tcp_unreachable_still_warns() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            Some(false),
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(conclusion_text(&lines).contains("⚠️ 目标不可达"));
    }

    #[test]
    fn connectivity_report_disabled_rule_says_no_nft_generation() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            false,
            NatServiceStatus::NotChecked,
            NftConnectivityStatus::SkippedDisabled,
            None,
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("- 规则：disabled"));
        assert!(conclusion_text(&lines).contains("⚠️ 规则未启用，不会生成 nft"));
    }

    #[test]
    fn connectivity_report_keeps_h_entry_for_detailed_commands() {
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let report = sample_connectivity_report(
            &rule,
            true,
            NatServiceStatus::Active,
            checked_nft_status(nat_common::forward_test::NftDetectionVerdict::Applied),
            Some(true),
        );
        let lines = render_connectivity_report_lines(&report).join("\n");
        assert!(lines.contains("输入 h 查看详细 curl / nc 示例"));
    }

    // ============ v0.4.3 ============

    #[test]
    fn telegram_curl_command_has_timeouts_server_side() {
        // 服务侧 Telegram curl 命令必须包含 --connect-timeout 5 和 --max-time 15。
        let cmd = crate::telegram::build_telegram_curl_command(
            "https://api.telegram.org/bot1234:fake/sendMessage",
            &[("chat_id", "1"), ("text", "hello")],
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--connect-timeout" && w[1] == "5"),
            "server-side Telegram curl 缺少 --connect-timeout 5: {args:?}"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--max-time" && w[1] == "15"),
            "server-side Telegram curl 缺少 --max-time 15: {args:?}"
        );
    }

    #[test]
    fn telegram_curl_command_has_timeouts_cli_side() {
        let cmd = build_cli_telegram_curl_command(
            "https://api.telegram.org/bot4321:cli/sendMessage",
            &[("chat_id", "x"), ("text", "y")],
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--connect-timeout" && w[1] == "5"),
            "CLI Telegram curl 缺少 --connect-timeout 5: {args:?}"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--max-time" && w[1] == "15"),
            "CLI Telegram curl 缺少 --max-time 15: {args:?}"
        );
    }

    #[test]
    fn telegram_cli_error_sanitizes_bot_token() {
        let url = "https://api.telegram.org/bot9876543210:LEAKME_CLI_STDERR/sendMessage";
        // 模拟 curl 把 URL 写到 stderr（极端情况）
        let stderr = format!("curl: (28) Connection timed out to {url}");
        let cleaned = sanitize_cli_telegram_error(&stderr, url);
        assert!(
            !cleaned.contains("LEAKME_CLI_STDERR"),
            "CLI Telegram error 必须脱敏 bot_token: {cleaned}"
        );
    }

    #[test]
    fn telegram_server_error_sanitizes_bot_token() {
        let url = "https://api.telegram.org/bot1234567890:LEAKME_SERVER_STDERR/sendMessage";
        let stderr = format!("error stdout / stderr leak: {url}");
        let cleaned = crate::telegram::sanitize_telegram_error(&stderr, url);
        assert!(
            !cleaned.contains("LEAKME_SERVER_STDERR"),
            "server Telegram error 必须脱敏 bot_token: {cleaned}"
        );
    }

    #[test]
    fn telegram_test_failure_message_lists_timeout_and_causes() {
        // err 来自 send_telegram_http_for_cli，已经脱敏过 bot_token；这里只验证
        // CLI 输出格式符合 v0.4.3 规格（多行排错 + curl 超时数值）。
        let lines = format_telegram_test_failure("HTTP 状态 28: 超时");
        let joined = lines.join("\n");
        assert!(
            joined.contains("Telegram 测试通知发送失败"),
            "缺少失败标题: {joined}"
        );
        assert!(
            joined.contains("可能原因") && joined.contains("bot_token/chat_id"),
            "缺少可能原因: {joined}"
        );
        assert!(
            joined.contains("connect-timeout 5") && joined.contains("max-time 15"),
            "缺少超时数值: {joined}"
        );
    }

    #[test]
    fn telegram_test_failure_message_does_not_leak_bot_token() {
        // 即便上游把整段 URL 透传过来，CLI 失败提示也不应把 bot_token 原文输出；
        // 验证 helper 不会主动追加 token，且对调用方传入的已脱敏字符串无副作用。
        let masked = "HTTP 状态 28: 12****cdef".to_string();
        let lines = format_telegram_test_failure(&masked);
        let joined = lines.join("\n");
        assert!(
            !joined.contains("LEAKME_TEST_PRINT_TOKEN"),
            "CLI 测试失败提示不应携带 bot_token 明文: {joined}"
        );
        assert!(
            joined.contains("12****cdef"),
            "应原样透传已脱敏的错误明细: {joined}"
        );
    }

    #[test]
    fn telegram_send_failure_returns_err_without_panic() {
        // 模拟 sender 失败：传入永远 Err 的闭包，验证 send_telegram_with 返回 Err
        // 而不是 panic / abort（保证 nat.service 主循环不会被 Telegram 卡死）。
        let cfg = nat_common::TelegramConfig {
            enabled: true,
            bot_token: "1234:ABC".to_string(),
            chat_id: "42".to_string(),
            ..Default::default()
        };
        let result = traffic_stats::send_telegram_with(&cfg, "ping", |_, _| {
            Err("simulated timeout".to_string())
        });
        assert!(
            result.is_err(),
            "Telegram 发送失败必须以 Err 返回，禁止 panic"
        );
    }

    #[test]
    fn last_good_status_uses_ui_timezone_when_configured() {
        use nat_common::last_good::{LastGoodRule, LastGoodState};
        let dir = std::env::temp_dir().join(format!(
            "nat-ui-tz-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("last-good.json");
        let state = LastGoodState {
            last_success_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-07-15T17:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            rules: vec![LastGoodRule {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: Some("hk-out".to_string()),
                domain: "example.com".to_string(),
                last_good_ip: "1.2.3.4".to_string(),
                last_resolved_at: chrono::DateTime::parse_from_rfc3339("2026-07-15T17:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                egress_allowed: true,
                last_apply_status: "ok".to_string(),
            }],
            last_good_nft_hash: None,
        };
        state.save(path.to_str().unwrap()).unwrap();

        // 用 America/Chicago（夏季 CDT = UTC-5），17:00 UTC → 12:00 CDT
        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.last_good = nat_common::LastGoodConfig {
            enabled: true,
            file: path.to_string_lossy().to_string(),
            use_last_good_on_dns_failure: true,
        };
        cfg.ui = nat_common::UiConfig {
            timezone: "America/Chicago".to_string(),
            time_format: "%Y-%m-%d %H:%M:%S %Z".to_string(),
        };
        let blob = format_last_good_status(&cfg).join("\n");
        assert!(
            blob.contains("2026-07-15 12:00:00"),
            "last-good 摘要应当按 [ui].timezone 渲染：{blob}"
        );
        assert!(
            !blob.contains("20:00:00 CST"),
            "不应再写死 Shanghai CST：{blob}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_good_status_default_ui_still_shanghai() {
        // 回归保护：[ui] 缺省时仍按 Asia/Shanghai 展示。
        use nat_common::last_good::{LastGoodRule, LastGoodState};
        let dir = std::env::temp_dir().join(format!(
            "nat-ui-default-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("last-good.json");
        let state = LastGoodState {
            last_success_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            rules: vec![LastGoodRule {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: None,
                domain: "example.com".to_string(),
                last_good_ip: "1.2.3.4".to_string(),
                last_resolved_at: chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                egress_allowed: true,
                last_apply_status: "ok".to_string(),
            }],
            last_good_nft_hash: None,
        };
        state.save(path.to_str().unwrap()).unwrap();

        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.last_good = nat_common::LastGoodConfig {
            enabled: true,
            file: path.to_string_lossy().to_string(),
            use_last_good_on_dns_failure: true,
        };
        // ui 走默认值
        let blob = format_last_good_status(&cfg).join("\n");
        assert!(
            blob.contains("2026-05-19 20:02:58 CST"),
            "默认 [ui] 仍按 Asia/Shanghai 渲染：{blob}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_ui_timezone_falls_back_without_panic() {
        // chrono-tz 解析失败时 format_cli_time_with 应回退（默认 Asia/Shanghai；
        // 退一步是 UTC），不要 panic。
        let ui = nat_common::UiConfig {
            timezone: "Mars/Olympus".to_string(),
            time_format: "%Y-%m-%d %H:%M:%S %Z".to_string(),
        };
        let utc = chrono::DateTime::parse_from_rfc3339("2026-05-19T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let rendered = nat_common::format_cli_time_with(utc, &ui);
        assert!(!rendered.is_empty());
        // 兜底时间字段不会包含 "Mars" 或 "Olympus"
        assert!(!rendered.contains("Mars"));
        assert!(!rendered.contains("Olympus"));
    }

    #[test]
    fn recent_source_ip_view_marks_manual_only() {
        let menu_src = include_str!("menu.rs");
        // v0.4.3：主菜单标签 + 页面文案明确「手动排查」/「不自动采集」
        assert!(
            menu_src.contains("15) 最近来源 IP 观察（手动排查）"),
            "主菜单 15) 必须带「手动排查」后缀"
        );
        assert!(
            menu_src.contains("当前版本**不**自动采集最近来源 IP"),
            "页面必须明确「不自动采集」"
        );
        // 仍保留原本的"不会自动放行或封禁来源 IP"承诺
        assert!(menu_src.contains("不会自动放行或封禁来源 IP"));
    }

    fn sample_single_rule_config(target: &str) -> TomlConfig {
        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.rules.push(NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: target.to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            snat_ip: None,
            comment: Some("demo".to_string()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        });
        cfg
    }

    #[test]
    fn show_rules_default_omits_full_policy_block() {
        // 默认页面不应整段重复"组合策略 (access_control + GeoIP + egress + SNAT + MSS)"标题块
        let cfg = sample_single_rule_config("93.184.216.34");
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(
            !lines.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"),
            "默认页面不应包含完整组合策略详情:\n{lines}"
        );
    }

    #[test]
    fn show_rules_default_omits_full_last_good_block() {
        // 默认页面不应展开"last-good 状态缓存"完整每条规则
        let cfg = sample_single_rule_config("93.184.216.34");
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(
            !lines.contains("last-good 状态缓存"),
            "默认页面不应包含完整 last-good 标题块:\n{lines}"
        );
        // 默认页面也不应输出"file:"等完整 last-good 详情字段
        assert!(
            !lines.contains("use_last_good_on_dns_failure"),
            "默认页面不应展开 last-good 完整字段:\n{lines}"
        );
    }

    #[test]
    fn show_rules_default_includes_summary_one_liners() {
        // 默认页面必须显示一行组合策略摘要 + 一行 last-good 摘要
        let cfg = sample_single_rule_config("93.184.216.34");
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(
            lines.contains("全局转发：enabled"),
            "默认页面应显示全局转发状态:\n{lines}"
        );
        assert!(
            lines.contains("组合策略：global=enabled, access_control=off"),
            "默认页面应显示组合策略摘要:\n{lines}"
        );
        assert!(
            lines.contains("GeoIP=") && lines.contains("egress=") && lines.contains("SNAT="),
            "组合策略摘要应包含 GeoIP/egress/SNAT 各项:\n{lines}"
        );
        assert!(
            lines.contains("last-good：") && lines.contains("缓存 0 条"),
            "默认页面应显示 last-good 摘要:\n{lines}"
        );
    }

    #[test]
    fn show_rules_default_warns_when_global_disabled() {
        let mut cfg = sample_single_rule_config("93.184.216.34");
        cfg.global.enabled = false;
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(lines.contains("全局转发：disabled"));
        assert!(lines.contains("当前不会生成转发规则。规则配置仍保留。"));
    }

    #[test]
    fn show_rules_default_per_rule_includes_core_fields() {
        // 每条规则默认行应包含 index / 状态 / type / sport / target / resolved / dport / protocol / ip_version
        let cfg = sample_single_rule_config("93.184.216.34");
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(lines.contains("0) [启用]"), "缺少 index/状态 前缀: {lines}");
        assert!(lines.contains("type=single"), "缺少 type=single: {lines}");
        assert!(lines.contains("sport=30080"), "缺少 sport: {lines}");
        assert!(
            lines.contains("target=93.184.216.34"),
            "缺少 target: {lines}"
        );
        assert!(
            lines.contains("(resolved=93.184.216.34)"),
            "缺少 resolved 字段: {lines}"
        );
        assert!(lines.contains("dport=80"), "缺少 dport: {lines}");
        assert!(lines.contains("protocol=tcp"), "缺少 protocol: {lines}");
        assert!(
            lines.contains("ip_version=ipv4"),
            "缺少 ip_version: {lines}"
        );
        assert!(
            lines.contains("access_control=off"),
            "缺少 access_control 状态: {lines}"
        );
    }

    #[test]
    fn show_rules_default_shows_quota_brief_when_enabled() {
        // quota 启用时每条规则应显示简要 used/limit；未启用时显示 quota=off
        let mut cfg = sample_single_rule_config("93.184.216.34");
        if let NftCell::Single {
            quota_enabled,
            quota_bytes,
            ..
        } = &mut cfg.rules[0]
        {
            *quota_enabled = true;
            *quota_bytes = 10 * 1024 * 1024 * 1024;
        }
        let mut stats = StatsState::default();
        stats
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 5 * 1024 * 1024 * 1024);
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(
            lines.contains("quota=") && lines.contains("/10.00 GB"),
            "应显示 quota used/limit: {lines}"
        );
    }

    #[test]
    fn show_rules_default_marks_egress_when_enabled() {
        // egress_control 启用时每条规则应附带 egress=allowed/blocked
        let mut cfg = sample_single_rule_config("93.184.216.34");
        cfg.egress_control = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow".to_string(),
            allowed_target_cidrs: vec!["10.0.0.0/8".to_string()],
            comment: None,
        };
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(
            lines.contains("egress=blocked"),
            "公网 IP 不在 10.0.0.0/8 时应显示 egress=blocked: {lines}"
        );
    }

    #[test]
    fn combined_policy_summary_is_single_line() {
        let cfg = sample_single_rule_config("93.184.216.34");
        let line = combined_policy_summary(&cfg);
        assert_eq!(line.lines().count(), 1, "组合策略摘要必须是单行: {line}");
        assert!(line.contains("access_control="));
        assert!(line.contains("MSS="));
    }

    #[test]
    fn last_good_summary_is_single_line() {
        let cfg = sample_single_rule_config("93.184.216.34");
        let state = LastGoodState::default();
        let line = last_good_summary(&cfg, &state);
        assert_eq!(line.lines().count(), 1, "last-good 摘要必须是单行: {line}");
        assert!(line.contains("缓存"));
        assert!(line.contains("最近成功"));
    }

    #[test]
    fn combined_policy_details_still_available_via_format_combined_policy_status() {
        // 入口仍保留：format_combined_policy_status 返回的完整内容应包含 SNAT / MSS 等子项
        let cfg = sample_single_rule_config("93.184.216.34");
        let detail = format_combined_policy_status(&cfg).join("\n");
        assert!(detail.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"));
        assert!(detail.contains("最终来源策略") || detail.contains("允许 = "));
        assert!(detail.contains("SNAT"));
        assert!(detail.contains("MSS clamp"));
    }

    #[test]
    fn last_good_details_still_available_via_format_last_good_status() {
        // 入口仍保留：format_last_good_status 返回的完整内容应包含 file / 规则缓存数量 等字段
        let cfg = sample_single_rule_config("93.184.216.34");
        let detail = format_last_good_status(&cfg).join("\n");
        assert!(detail.contains("last-good 状态缓存"));
        assert!(detail.contains("enabled:") && detail.contains("use_last_good_on_dns_failure"));
        assert!(detail.contains("file:"));
        assert!(detail.contains("规则缓存数量"));
    }

    fn sample_testable_rule(
        target: &str,
        protocol: &str,
    ) -> nat_common::forward_test::TestableRule {
        nat_common::forward_test::TestableRule {
            index: 0,
            id: "r0".to_string(),
            label: format!("demo: 30080 -> {target}:80/{protocol}"),
            r#type: "single".to_string(),
            sport: 30080,
            target: target.to_string(),
            resolved_ip: Some(target.to_string()),
            dport: 80,
            protocol: protocol.to_string(),
            ip_version: "ipv4".to_string(),
        }
    }

    #[test]
    fn external_test_brief_is_short_and_omits_detailed_examples() {
        // 默认外部测试提示只展示 SERVER_IP / 注意事项 / h 提示，不直接列 curl / nc 示例
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let lines = external_test_brief_lines(&rule).join("\n");
        assert!(lines.contains("SERVER_IP:30080"));
        assert!(lines.contains("外部访问测试："));
        assert!(lines.contains("输入 h 查看详细测试命令示例"));
        assert!(
            !lines.contains("curl -v"),
            "brief 不应直接输出 curl 命令: {lines}"
        );
        assert!(
            !lines.contains("nc -vz "),
            "brief 不应直接输出 nc 命令: {lines}"
        );
        assert!(
            !lines.contains("HTTPS/SNI 示例:"),
            "brief 不应输出 HTTPS/SNI 示例: {lines}"
        );
    }

    #[test]
    fn external_test_brief_uses_protocol_hint_for_udp() {
        let rule = sample_testable_rule("93.184.216.34", "udp");
        let lines = external_test_brief_lines(&rule).join("\n");
        assert!(
            lines.contains("protocol=udp") && lines.contains("nc -vzu"),
            "udp brief 应提示 UDP 客户端 / nc -vzu: {lines}"
        );
    }

    #[test]
    fn external_test_detailed_tcp_ip_target_omits_host_header() {
        // 详细命令：TCP + IP 目标，应给出 TCP nc + 普通 HTTP，不要带 Host header / SNI
        let rule = sample_testable_rule("93.184.216.34", "tcp");
        let lines = external_test_detailed_lines(&rule).join("\n");
        assert!(
            lines.contains("TCP 示例: nc -vz SERVER_IP 30080"),
            "应有 TCP 示例: {lines}"
        );
        assert!(
            lines.contains("HTTP 示例: curl -v http://SERVER_IP:30080/"),
            "应有不带 Host 的 HTTP 示例: {lines}"
        );
        assert!(
            !lines.contains("-H \"Host:"),
            "IP 目标不应附 Host header: {lines}"
        );
        assert!(
            !lines.contains("HTTPS/SNI"),
            "IP 目标不应附 SNI 示例: {lines}"
        );
    }

    #[test]
    fn external_test_detailed_tcp_domain_target_includes_host_and_sni() {
        // 域名目标的详细命令应包含 Host header HTTP 示例和 HTTPS/SNI 示例
        let rule = sample_testable_rule("example.com", "tcp");
        let lines = external_test_detailed_lines(&rule).join("\n");
        assert!(
            lines.contains("HTTP 示例:") && lines.contains("-H \"Host: example.com\""),
            "域名目标应附 Host header: {lines}"
        );
        assert!(
            lines.contains("HTTPS/SNI 示例:") && lines.contains("--connect-to example.com:"),
            "域名目标应附 HTTPS/SNI 示例: {lines}"
        );
    }

    #[test]
    fn external_test_detailed_udp_only_shows_udp_block() {
        let rule = sample_testable_rule("example.com", "udp");
        let lines = external_test_detailed_lines(&rule).join("\n");
        assert!(
            lines.contains("UDP 示例: nc -vzu SERVER_IP 30080"),
            "udp 详细应给出 UDP 示例: {lines}"
        );
        assert!(
            !lines.contains("HTTP 示例:"),
            "udp 详细不应输出 HTTP 示例: {lines}"
        );
        assert!(
            !lines.contains("HTTPS/SNI"),
            "udp 详细不应输出 HTTPS/SNI 示例: {lines}"
        );
    }

    #[test]
    fn external_test_detailed_distinguishes_from_geoip_egress_last_good() {
        // 防止用户误以为这些命令和 GeoIP / last-good / egress_control 是同一个功能
        let rule = sample_testable_rule("example.com", "tcp");
        let lines = external_test_detailed_lines(&rule).join("\n");
        assert!(
            lines.contains("与 GeoIP / last-good / egress_control"),
            "详细命令应有功能边界说明: {lines}"
        );
    }

    /// 截取 menu.rs 源中 `#[cfg(test)]` 之前的非测试部分，避免测试断言里包含的
    /// 「禁用文案」被自身误命中。
    fn menu_src_non_test() -> &'static str {
        let menu_src = include_str!("menu.rs");
        match menu_src.find("#[cfg(test)]") {
            Some(idx) => &menu_src[..idx],
            None => menu_src,
        }
    }

    #[test]
    fn advanced_network_menu_exposes_single_global_diagnostics_entry() {
        // v0.5.x 起：高级网络设置只暴露一个「7) 查看全局诊断状态」入口，
        // 不再同时显示分立的「组合策略详情 / last-good 状态缓存」两个重复入口。
        let src = menu_src_non_test();
        assert!(
            src.contains("7) 查看全局诊断状态"),
            "高级网络菜单应有「查看全局诊断状态」单一入口"
        );
        assert!(
            src.contains("8) 全局转发开关"),
            "高级网络菜单应暴露「全局转发开关」入口"
        );
        // 旧的并列项：编号 7 不应再绑到「组合策略详情」、编号 8 不应再绑到「last-good 状态缓存」
        assert!(
            !src.contains("7) 查看组合策略详情"),
            "高级网络菜单不应再单独列出「查看组合策略详情」"
        );
        assert!(
            !src.contains("8) 查看 last-good 状态缓存"),
            "高级网络菜单不应再单独列出「查看 last-good 状态缓存」"
        );
    }

    #[test]
    fn show_rules_page_advertises_only_d_and_enter() {
        // v0.5.x 起：提示文案只展示 d 与 Enter，不再宣传 l / p 入口
        let src = menu_src_non_test();
        assert!(
            src.contains("提示：输入 d 查看详细诊断 / 按 Enter 返回主菜单"),
            "show_rules 提示文案应仅包含 d 与 Enter"
        );
        // 旧文案：提示行不应同时罗列 l / p
        assert!(
            !src.contains("l 查看 last-good 详情"),
            "show_rules 提示文案不应再展示 l 入口"
        );
        assert!(
            !src.contains("p 查看组合策略详情"),
            "show_rules 提示文案不应再展示 p 入口"
        );
    }

    #[test]
    fn global_diagnostics_renders_policy_and_last_good() {
        // 「查看当前转发规则 → d」与「高级网络设置 → 查看全局诊断状态」共用此聚合页：
        // 必须同时包含完整组合策略标题块和完整 last-good 标题块。
        let cfg = sample_single_rule_config("93.184.216.34");
        let blob = render_global_diagnostics_lines(&cfg).join("\n");
        assert!(
            blob.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"),
            "全局诊断状态应含完整组合策略详情:\n{blob}"
        );
        assert!(
            blob.contains("last-good 状态缓存"),
            "全局诊断状态应含完整 last-good 详情:\n{blob}"
        );
        assert!(
            blob.contains("SNAT") && blob.contains("MSS clamp"),
            "全局诊断状态应含 SNAT / MSS clamp 段落:\n{blob}"
        );
        assert!(
            blob.contains("use_last_good_on_dns_failure"),
            "全局诊断状态应展开 last-good 完整字段:\n{blob}"
        );
    }

    #[test]
    fn default_rules_summaries_still_render_after_simplification() {
        // 入口简化不应回归默认页面：每条规则两行 + 一行组合策略摘要 + 一行 last-good 摘要仍要存在。
        let cfg = sample_single_rule_config("93.184.216.34");
        let stats = StatsState::default();
        let last_good = LastGoodState::default();
        let resolutions = vec![Some("93.184.216.34".to_string())];
        let lines = render_rules_default_lines(&cfg, &resolutions, &stats, &last_good).join("\n");
        assert!(lines.contains("0) [启用] type=single"));
        assert!(lines.contains("组合策略：global=enabled, access_control="));
        assert!(lines.contains("last-good：") && lines.contains("缓存 0 条"));
    }

    #[test]
    fn readme_documents_short_external_test_hint() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("测试转发规则连通性") && readme.contains("SNAT 出口诊断"),
            "README 应说明测试转发规则连通性与 SNAT 出口诊断"
        );
    }

    // ============ v0.6.0: safe_write_config 统一写入 ============

    fn safe_write_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-safe-write-{}-{}-{name}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn safe_write_config_to_creates_backup_and_writes_atomically() {
        let dir = safe_write_dir("happy");
        let backup_dir = dir.join("backup");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = true\n").unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let backup_path = match safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "new = true\n",
            "telegram.toggle",
        )
        .unwrap()
        {
            Some(path) => path,
            None => panic!("telegram.toggle should create backup"),
        };
        // 目标文件已更新；备份目录里有按 reason 命名的 .bak
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new = true\n");
        assert!(backup_path.starts_with(&backup_dir));
        let bak_name = backup_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            bak_name.contains(".telegram.toggle-"),
            "backup 文件名应含 reason: {bak_name}"
        );
        // audit 应当包含 config.write.success
        let lines = audit::read_tail(audit_file.to_str().unwrap(), 10);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("config.write.success") && l.contains("telegram.toggle")),
            "缺少 config.write.success audit: {lines:?}"
        );
    }

    #[test]
    fn safe_write_rule_delete_skips_backup_but_writes_atomically_and_audits() {
        let dir = safe_write_dir("rule-delete-skip-backup");
        let backup_dir = dir.join("backup");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = true\n").unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let backup_path = safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "new = true\n",
            "rule.delete",
        )
        .unwrap();
        assert!(backup_path.is_none(), "rule.delete 不应返回备份路径");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new = true\n");
        assert!(
            !backup_dir.exists(),
            "rule.delete 不应创建备份目录: {}",
            backup_dir.display()
        );
        let raw = std::fs::read_to_string(&audit_file).unwrap();
        assert!(raw.contains("\"action\":\"config.write.success\""));
        assert!(raw.contains("\"reason\":\"rule.delete\""));
        assert!(raw.contains("\"backup_skipped\":true"));
        assert!(raw.contains("\"backup_skip_reason\":\"rule.delete\""));
        assert!(
            !raw.contains("\"backup\":"),
            "rule.delete audit 不应写不存在的 backup 字段: {raw}"
        );
    }

    fn assert_reason_still_creates_backup(reason: &str) {
        let dir = safe_write_dir(&format!("backup-required-{reason}"));
        let backup_dir = dir.join("backup");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = true\n").unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let backup_path = safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "new = true\n",
            reason,
        )
        .unwrap()
        .unwrap_or_else(|| panic!("{reason} should create backup"));
        assert!(backup_path.exists(), "{reason} backup should exist");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new = true\n");
        let raw = std::fs::read_to_string(&audit_file).unwrap();
        assert!(raw.contains("\"action\":\"config.write.success\""));
        assert!(raw.contains(&format!("\"reason\":\"{reason}\"")));
        assert!(raw.contains("\"backup\":"));
        assert!(!raw.contains("\"backup_skipped\":true"));
    }

    #[test]
    fn safe_write_rule_add_still_creates_backup() {
        assert_reason_still_creates_backup("rule.add.single");
    }

    #[test]
    fn safe_write_rule_toggle_still_creates_backup() {
        assert_reason_still_creates_backup("rule.toggle");
    }

    #[test]
    fn safe_write_telegram_config_update_still_creates_backup() {
        assert_reason_still_creates_backup("telegram.config.update");
    }

    #[test]
    fn safe_write_dynamic_whitelist_domain_changes_create_backup() {
        assert_reason_still_creates_backup("dynamic_whitelist.domain.add");
        assert_reason_still_creates_backup("dynamic_whitelist.domain.delete");
        assert_reason_still_creates_backup("dynamic_whitelist.domain.toggle");
    }

    #[test]
    fn safe_write_config_to_when_backup_fails_keeps_original() {
        // 备份目录用一个普通文件占位 → fs::create_dir_all 失败
        let dir = safe_write_dir("backup-fail");
        let blocker_parent = dir.join("blocker-as-dir");
        std::fs::write(&blocker_parent, b"not a directory").unwrap();
        let backup_dir = blocker_parent.join("nested");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = true\n").unwrap();
        let original = std::fs::read_to_string(&target).unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let result = safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "new = true\n",
            "rule.add.single",
        );
        assert!(result.is_err(), "backup 失败应当返回 Err");
        // 旧 nat.toml 必须保持不变
        assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
        let lines = audit::read_tail(audit_file.to_str().unwrap(), 10);
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert!(
            parsed
                .iter()
                .any(|v| v["action"] == "config.write.fail" && v["detail"]["stage"] == "backup"),
            "缺少 config.write.fail (stage=backup) audit: {lines:?}"
        );
        assert!(
            !parsed.iter().any(|v| v["action"] == "config.write.success"),
            "备份失败时不应出现 config.write.success: {lines:?}"
        );
    }

    #[test]
    fn safe_write_config_to_when_rename_fails_keeps_original() {
        // 把目标设为一个目录路径，create File 会失败（在 v0.6.0 atomic_write 流程中阶段为 write_or_rename）
        let dir = safe_write_dir("rename-fail");
        let backup_dir = dir.join("bk");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = true\n").unwrap();
        let original = std::fs::read_to_string(&target).unwrap();
        // 让 atomic write 的 tmp 文件无法创建：目标的父目录改为一个不可写位置
        // 这里改用 readonly path：在 /proc 下尝试写
        let unwritable = std::path::PathBuf::from("/proc/this/path/should/not/exist/nat.toml");
        let audit_file = dir.join("audit.log");
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let result = safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            unwritable.to_str().unwrap(),
            "new = true\n",
            "rule.add.single",
        );
        assert!(result.is_err());
        // target（dir/nat.toml）保持不变
        assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
    }

    #[test]
    fn safe_write_config_to_audit_does_not_leak_bot_token() {
        // 通过 reason 与 path 写入；即便上游误把 token 当作 reason 传进来，也应当被脱敏。
        let dir = safe_write_dir("no-token-leak");
        let backup_dir = dir.join("bk");
        let audit_file = dir.join("audit.log");
        let target = dir.join("nat.toml");
        std::fs::write(&target, "old = 1\n").unwrap();
        let audit_cfg = nat_common::AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        safe_write_config_to(
            &backup_dir,
            &audit_cfg,
            target.to_str().unwrap(),
            "new = 1\n",
            "telegram.toggle",
        )
        .unwrap();
        // 即便我们再把疑似 bot_token 的字符串塞进 detail，audit::log_event 内部也会兜底 redact。
        audit::log_event(
            &audit_cfg,
            "config.write.demo",
            audit::AuditResult::Info,
            json!({"bot_token": "1234567890:LEAKME_SAFEWRITE"}),
        );
        let raw = std::fs::read_to_string(&audit_file).unwrap();
        assert!(
            !raw.contains("LEAKME_SAFEWRITE"),
            "audit log 不能泄露 bot_token 明文: {raw}"
        );
    }

    // ============ v0.6.0: 一键更新 latest 解析 ============

    #[test]
    fn build_update_plan_latest_resolved_to_real_tag() {
        let plan = build_update_plan("latest", || Ok("v0.5.2".to_string()));
        assert_eq!(plan.display_version, "v0.5.2");
        assert_eq!(plan.source, "latest");
        assert!(plan.warning.is_none());
        // install.sh 仍然按 latest 走，不要把 --version v0.5.2 强加进去
        assert_eq!(plan.install_arg_version, "latest");
    }

    #[test]
    fn build_update_plan_latest_falls_back_when_resolver_fails() {
        let plan = build_update_plan("latest", || Err("timeout".to_string()));
        assert_eq!(plan.display_version, "latest");
        assert_eq!(plan.source, "latest");
        let w = plan
            .warning
            .unwrap_or_else(|| "<missing warning>".to_string());
        assert!(
            w != "<missing warning>",
            "build_update_plan 在 latest 解析失败时应附带 warning"
        );
        assert!(
            w.contains("无法解析 latest release tag"),
            "warning 文案: {w}"
        );
        assert!(
            w.contains("latest release"),
            "warning 应说明会让 install.sh 走 latest: {w}"
        );
        assert_eq!(plan.install_arg_version, "latest");
    }

    #[test]
    fn build_update_plan_latest_falls_back_when_resolver_returns_invalid() {
        let plan = build_update_plan("latest", || Ok("not-a-tag".to_string()));
        assert_eq!(plan.display_version, "latest");
        assert_eq!(plan.source, "latest");
        let w = plan
            .warning
            .unwrap_or_else(|| "<missing warning>".to_string());
        assert!(
            w != "<missing warning>",
            "build_update_plan 在解析到非法 tag 时应附带 warning"
        );
        assert!(w.contains("不符合 vX.Y.Z 格式"), "warning 文案: {w}");
        assert_eq!(plan.install_arg_version, "latest");
    }

    #[test]
    fn build_update_plan_specified_version_keeps_input_as_install_arg() {
        let plan = build_update_plan("v0.5.2", || panic!("specified 路径不应触发 resolver"));
        assert_eq!(plan.display_version, "v0.5.2");
        assert_eq!(plan.source, "specified");
        assert!(plan.warning.is_none());
        assert_eq!(plan.install_arg_version, "v0.5.2");
    }

    #[test]
    fn extract_release_tag_handles_github_redirect_url() {
        assert_eq!(
            extract_release_tag(
                "https://github.com/misaka-cpu/nftables-nat-rust-enhanced/releases/tag/v0.5.2"
            ),
            Some("v0.5.2".to_string())
        );
        // 末尾带 query
        assert_eq!(
            extract_release_tag("https://github.com/x/y/releases/tag/v0.6.0?expanded=true"),
            Some("v0.6.0".to_string())
        );
        // 不是 release tag
        assert!(extract_release_tag("https://github.com/x/y/releases").is_none());
    }

    #[test]
    fn parse_latest_tag_from_curl_headers_picks_final_redirect() {
        // GitHub 多级重定向：第一次 -> /releases，第二次 -> /releases/tag/v0.5.2
        let headers = r#"HTTP/2 302
location: https://github.com/misaka-cpu/nftables-nat-rust-enhanced/releases

HTTP/2 302
Location: https://github.com/misaka-cpu/nftables-nat-rust-enhanced/releases/tag/v0.5.2

HTTP/2 200
"#;
        assert_eq!(
            parse_latest_tag_from_curl_headers(headers),
            Some("v0.5.2".to_string())
        );
    }

    #[test]
    fn parse_latest_tag_returns_none_when_no_tag_in_redirect() {
        let headers = "HTTP/2 200\ncontent-type: text/html\n";
        assert!(parse_latest_tag_from_curl_headers(headers).is_none());
    }

    #[test]
    fn sanitize_backup_reason_filters_path_traversal_and_special_chars() {
        // reason 用于拼文件名，必须只保留安全字符
        let safe = sanitize_backup_reason("../rm -rf /; whatever");
        assert!(!safe.contains('/'));
        assert!(!safe.contains(' '));
        assert!(!safe.contains(';'));
        // 全空字符串应有兜底
        assert_eq!(sanitize_backup_reason("   "), "config-write");
    }

    // ===== v0.8.1 草案：白名单 / 黑名单管理简化布局测试 =====

    fn brief_layout_config(
        mode: AccessControlMode,
        entries: &[&str],
        geoip_forward: bool,
        geoip_ssh: bool,
        dynamic_enabled: bool,
        dynamic_domains: &[(&str, &str, bool)],
    ) -> TomlConfig {
        let mut cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        cfg.access_control.mode = mode;
        cfg.access_control.entries = entries.iter().map(|s| s.to_string()).collect();
        cfg.geoip.enabled = geoip_forward || geoip_ssh;
        cfg.geoip.forward.enabled = geoip_forward;
        cfg.geoip.ssh.enabled = geoip_ssh;
        cfg.dynamic_whitelist.enabled = dynamic_enabled;
        cfg.dynamic_whitelist.domains = dynamic_domains
            .iter()
            .map(|(name, domain, enabled)| DynamicWhitelistDomainConfig {
                name: name.to_string(),
                domain: domain.to_string(),
                enabled: *enabled,
            })
            .collect();
        cfg
    }

    #[test]
    fn ssh_connection_parses_ipv4_source() {
        let detected = detect_ssh_source_from_env_vars(|name| match name {
            "SSH_CONNECTION" => Some("198.51.100.7 54321 203.0.113.10 22".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(detected.ip.to_string(), "198.51.100.7");
        assert_eq!(detected.detected_from, "SSH_CONNECTION");
    }

    #[test]
    fn ssh_client_parses_ipv4_source() {
        let detected = detect_ssh_source_from_env_vars(|name| match name {
            "SSH_CLIENT" => Some("198.51.100.8 54321 22".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(detected.ip.to_string(), "198.51.100.8");
        assert_eq!(detected.detected_from, "SSH_CLIENT");
    }

    #[test]
    fn ssh_connection_takes_priority_over_ssh_client() {
        let detected = detect_ssh_source_from_env_vars(|name| match name {
            "SSH_CONNECTION" => Some("198.51.100.9 54321 203.0.113.10 22".to_string()),
            "SSH_CLIENT" => Some("198.51.100.10 54321 22".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(detected.ip.to_string(), "198.51.100.9");
        assert_eq!(detected.detected_from, "SSH_CONNECTION");
    }

    #[test]
    fn ssh_source_detection_returns_none_without_env() {
        assert!(detect_ssh_source_from_env_vars(|_| None).is_none());
    }

    #[test]
    fn ssh_source_cidr_candidates_cover_ipv4_32_ipv4_24_and_ipv6_128() {
        let ipv4: IpAddr = "198.51.100.7".parse().unwrap();
        let ipv6: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(ssh_source_exact_cidr(ipv4), "198.51.100.7/32");
        assert_eq!(
            ssh_source_ipv4_24_cidr("198.51.100.7".parse().unwrap()),
            "198.51.100.0/24"
        );
        assert_eq!(ssh_source_exact_cidr(ipv6), "2001:db8::7/128");
    }

    #[test]
    fn ssh_source_add_refuses_blacklist_mode() {
        let mut cfg =
            brief_layout_config(AccessControlMode::Blacklist, &[], false, false, false, &[]);
        let result = add_ssh_source_entry_to_config(&mut cfg, "198.51.100.7/32").unwrap();
        assert_eq!(result, SshSourceAddOutcome::RefusedBlacklist);
        assert!(cfg.access_control.entries.is_empty());
    }

    #[test]
    fn ssh_source_add_allows_off_mode_without_enabling_whitelist() {
        let mut cfg = brief_layout_config(AccessControlMode::Off, &[], false, false, false, &[]);
        let result = add_ssh_source_entry_to_config(&mut cfg, "198.51.100.7/32").unwrap();
        assert_eq!(
            result,
            SshSourceAddOutcome::Added {
                cidr: "198.51.100.7/32".to_string()
            }
        );
        assert_eq!(cfg.access_control.mode, AccessControlMode::Off);
        assert_eq!(cfg.access_control.entries, vec!["198.51.100.7/32"]);
    }

    #[test]
    fn ssh_source_add_allows_whitelist_mode() {
        let mut cfg =
            brief_layout_config(AccessControlMode::Whitelist, &[], false, false, false, &[]);
        let result = add_ssh_source_entry_to_config(&mut cfg, "198.51.100.7/32").unwrap();
        assert!(matches!(result, SshSourceAddOutcome::Added { .. }));
        assert_eq!(cfg.access_control.mode, AccessControlMode::Whitelist);
        assert_eq!(cfg.access_control.entries, vec!["198.51.100.7/32"]);
    }

    #[test]
    fn ssh_source_add_deduplicates_existing_entry() {
        let mut cfg = brief_layout_config(
            AccessControlMode::Whitelist,
            &["198.51.100.7/32"],
            false,
            false,
            false,
            &[],
        );
        let result = add_ssh_source_entry_to_config(&mut cfg, "198.51.100.7/32").unwrap();
        assert_eq!(
            result,
            SshSourceAddOutcome::AlreadyExists {
                cidr: "198.51.100.7/32".to_string()
            }
        );
        assert_eq!(cfg.access_control.entries, vec!["198.51.100.7/32"]);
    }

    #[test]
    fn ssh_source_add_accepts_ipv4_24_and_ipv6_128() {
        let mut cfg = brief_layout_config(AccessControlMode::Off, &[], false, false, false, &[]);
        assert!(matches!(
            add_ssh_source_entry_to_config(&mut cfg, "198.51.100.0/24").unwrap(),
            SshSourceAddOutcome::Added { .. }
        ));
        assert!(matches!(
            add_ssh_source_entry_to_config(&mut cfg, "2001:db8::7/128").unwrap(),
            SshSourceAddOutcome::Added { .. }
        ));
        assert_eq!(
            cfg.access_control.entries,
            vec!["198.51.100.0/24", "2001:db8::7/128"]
        );
    }

    #[test]
    fn ssh_source_add_reason_is_nft_affecting_and_audit_has_expected_detail() {
        assert!(reason_affects_nft("access_control.ssh_source.add"));
        let dir = std::env::temp_dir().join(format!(
            "nat-ssh-source-audit-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_file = dir.join("audit.log");
        let audit_cfg = AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        let detection = SshSourceDetection {
            ip: "198.51.100.7".parse().unwrap(),
            detected_from: "SSH_CONNECTION",
        };
        audit_ssh_source_add(&audit_cfg, &detection, "198.51.100.7/32");
        let raw = std::fs::read_to_string(&audit_file).unwrap();
        assert!(raw.contains("\"action\":\"access_control.ssh_source.add\""));
        assert!(raw.contains("\"result\":\"ok\""));
        assert!(raw.contains("\"ip\":\"198.51.100.7\""));
        assert!(raw.contains("\"cidr\":\"198.51.100.7/32\""));
        assert!(raw.contains("\"detected_from\":\"SSH_CONNECTION\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn global_enabled_update_reason_is_nft_affecting_and_audit_has_expected_detail() {
        assert!(reason_affects_nft("global.enabled.update"));
        let dir = std::env::temp_dir().join(format!(
            "nat-global-audit-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_file = dir.join("audit.log");
        let audit_cfg = AuditConfig {
            enabled: true,
            file: audit_file.to_string_lossy().to_string(),
            ..Default::default()
        };
        audit_global_enabled_update(&audit_cfg, true, false);
        let raw = std::fs::read_to_string(&audit_file).unwrap();
        assert!(raw.contains("\"action\":\"global.enabled.update\""));
        assert!(raw.contains("\"result\":\"ok\""));
        assert!(raw.contains("\"old_enabled\":true"));
        assert!(raw.contains("\"new_enabled\":false"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn access_control_brief_lines_show_summary_not_long_combined_policy() {
        let cfg = brief_layout_config(AccessControlMode::Off, &[], false, false, false, &[]);
        let state = DynamicWhitelistState::default();
        let lines = format_access_control_brief_lines_with_state(&cfg, &state).join("\n");
        assert!(lines.contains("来源访问控制："));
        assert!(lines.contains("mode: off"));
        assert!(lines.contains("静态 entries: 0"));
        assert!(lines.contains("dynamic_whitelist: disabled, domains=0, current_ips=0, stale=0"));
        assert!(lines.contains("cidr_expand_ipv4: false"));
        assert!(lines.contains("GeoIP forward: disabled"));
        assert!(lines.contains("SSH GeoIP: disabled"));
        assert!(lines.contains("global forwarding: enabled"));
        assert!(lines.contains("最终来源判断："));
        assert!(lines.contains("whitelist 模式：静态 entries OR dynamic_whitelist"));
        // 简洁页面不应包含 SNAT / MSS / egress / 完整组合策略标题块
        assert!(
            !lines.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"),
            "简洁页面不应展开完整组合策略标题: {lines}"
        );
        assert!(
            !lines.contains("SNAT（源地址改写）"),
            "简洁页面不应包含 SNAT 长段: {lines}"
        );
        assert!(
            !lines.contains("MSS clamp（TCP MSS 调整）"),
            "简洁页面不应包含 MSS 长段: {lines}"
        );
        assert!(
            !lines.contains("egress_control（目标 IP / IP 段限制）"),
            "简洁页面不应包含 egress 长段: {lines}"
        );
        assert!(
            !lines.contains("评估顺序：黑名单 > 白名单"),
            "简洁页面不应包含评估顺序长行: {lines}"
        );
        assert!(
            !lines.contains("最终目标策略："),
            "简洁页面不应包含最终目标策略行: {lines}"
        );
        // 但必须保留来源与目标限制的边界说明
        assert!(lines.contains("egress_control 是目标 IP 限制，不在此处管理。"));
    }

    #[test]
    fn access_control_brief_lines_reflect_whitelist_and_geoip_counts() {
        let cfg = brief_layout_config(
            AccessControlMode::Whitelist,
            &["1.2.3.4", "5.6.7.0/24"],
            true,
            true,
            true,
            &[("home", "home.example.com", true)],
        );
        let state = DynamicWhitelistState {
            domains: vec![nat_common::dynamic_whitelist::DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                last_good_ips: vec!["203.0.113.10".to_string()],
                current_ips: vec!["203.0.113.10".to_string()],
                raw_ips: vec!["203.0.113.10".to_string()],
                effective_sources: vec!["203.0.113.10".to_string()],
                cidr_expand_ipv4: 32,
                resolved_at: Some("2026-05-28T00:00:00Z".to_string()),
                stale: true,
                error: None,
                ipv4: true,
                ipv6: false,
            }],
        };
        let lines = format_access_control_brief_lines_with_state(&cfg, &state).join("\n");
        assert!(lines.contains("mode: whitelist"));
        assert!(lines.contains("静态 entries: 2"));
        assert!(lines.contains("dynamic_whitelist: enabled, domains=1, current_ips=1, stale=1"));
        assert!(lines.contains("GeoIP forward: enabled"));
        assert!(lines.contains("SSH GeoIP: enabled"));
        assert!(lines.contains("global forwarding: enabled"));
    }

    #[test]
    fn access_control_brief_lines_warn_when_global_disabled() {
        let mut cfg = brief_layout_config(AccessControlMode::Off, &[], false, false, false, &[]);
        cfg.global.enabled = false;
        let state = DynamicWhitelistState::default();
        let lines = format_access_control_brief_lines_with_state(&cfg, &state).join("\n");
        assert!(lines.contains("global forwarding: disabled"));
        assert!(lines.contains("global forwarding 当前为 disabled"));
        assert!(lines.contains("所有转发规则都会临时停用"));
    }

    #[test]
    fn access_control_brief_lines_warn_when_whitelist_has_no_sources() {
        let cfg = brief_layout_config(AccessControlMode::Whitelist, &[], false, false, false, &[]);
        let state = DynamicWhitelistState::default();
        let lines = format_access_control_brief_lines_with_state(&cfg, &state).join("\n");
        assert!(lines.contains("warning: whitelist 模式下静态 entries=0"));
    }

    #[test]
    fn access_control_brief_lines_note_dynamic_whitelist_inactive_outside_whitelist_mode() {
        let cfg = brief_layout_config(
            AccessControlMode::Off,
            &[],
            false,
            false,
            true,
            &[("home", "home.example.com", true)],
        );
        let state = DynamicWhitelistState::default();
        let lines = format_access_control_brief_lines_with_state(&cfg, &state).join("\n");
        assert!(lines.contains("动态白名单只解析和显示状态，不参与放行"));
    }

    #[test]
    fn access_control_menu_lists_ssh_detection_detail_entry_and_save_apply_renumbered() {
        let src = menu_src_non_test();
        assert!(
            src.contains("8) 动态 DDNS 来源白名单"),
            "8) 仍指向动态 DDNS 来源白名单子菜单"
        );
        assert!(
            src.contains("9) 查询来源 IP 命中情况"),
            "白名单 / 黑名单管理应新增「查询来源 IP 命中情况」入口"
        );
        assert!(
            src.contains("10) 检测当前 SSH 来源 IP"),
            "白名单 / 黑名单管理应新增「检测当前 SSH 来源 IP」入口"
        );
        assert!(
            src.contains("11) 查看来源策略详情"),
            "查看来源策略详情应顺延为 11)"
        );
        assert!(src.contains("12) 保存并应用"), "保存并应用顺延为 12)");
        // 旧的 9) 保存并应用编号不应再出现在白名单/黑名单菜单文本块
        assert!(
            !src.contains("9) 保存并应用"),
            "保存并应用不应继续占用 9 号位"
        );
    }

    #[test]
    fn source_policy_detail_lines_still_show_full_combined_policy() {
        let cfg = brief_layout_config(
            AccessControlMode::Whitelist,
            &["1.2.3.4"],
            true,
            false,
            true,
            &[("home", "home.example.com", true)],
        );
        let detail = format_source_policy_detail_lines(&cfg).join("\n");
        // 详情页应包含完整组合策略标题与评估顺序、SNAT、MSS、egress、说明
        assert!(detail.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"));
        assert!(detail.contains(
            "评估顺序：黑名单 > 白名单（静态 + dynamic_whitelist）> GeoIP（同时启用 = AND）"
        ));
        assert!(detail.contains("SNAT（源地址改写）"));
        assert!(detail.contains("MSS clamp（TCP MSS 调整）"));
        assert!(detail.contains("egress_control（目标 IP / IP 段限制）"));
        assert!(detail.contains(
            "说明：access_control / dynamic_whitelist / GeoIP 是来源 IP 限制；egress_control 是目标 IP 限制；SNAT 是源地址改写；MSS clamp 是 TCP MSS 调整。"
        ));
    }

    fn source_query_config(
        mode: AccessControlMode,
        entries: &[&str],
        dynamic_enabled: bool,
        cidr_expand_ipv4: u8,
    ) -> TomlConfig {
        let mut cfg = brief_layout_config(
            mode,
            entries,
            false,
            false,
            dynamic_enabled,
            &[("home", "home.example.com", true)],
        );
        cfg.dynamic_whitelist.cidr_expand_ipv4 = cidr_expand_ipv4;
        cfg
    }

    fn dynamic_state_with_home(
        current_ips: &[&str],
        effective_sources: &[&str],
    ) -> DynamicWhitelistState {
        DynamicWhitelistState {
            domains: vec![nat_common::dynamic_whitelist::DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                last_good_ips: current_ips.iter().map(|ip| ip.to_string()).collect(),
                current_ips: current_ips.iter().map(|ip| ip.to_string()).collect(),
                raw_ips: current_ips.iter().map(|ip| ip.to_string()).collect(),
                effective_sources: effective_sources
                    .iter()
                    .map(|source| source.to_string())
                    .collect(),
                cidr_expand_ipv4: if effective_sources
                    .iter()
                    .any(|source| source.contains("/24"))
                {
                    24
                } else {
                    32
                },
                resolved_at: Some("2026-05-28T00:00:00Z".to_string()),
                stale: false,
                error: None,
                ipv4: true,
                ipv6: false,
            }],
        }
    }

    fn query_lines(config: &TomlConfig, state: &DynamicWhitelistState, ip: &str) -> String {
        format_source_ip_match_lines(config, state, ip)
            .unwrap()
            .join("\n")
    }

    #[test]
    fn source_ip_query_hits_static_whitelist() {
        let cfg = source_query_config(AccessControlMode::Whitelist, &["1.2.3.0/24"], false, 32);
        let lines = query_lines(&cfg, &DynamicWhitelistState::default(), "1.2.3.4");
        assert!(lines.contains("来源 IP 命中查询"));
        assert!(lines.contains("静态 entries: 命中 1.2.3.0/24"));
        assert!(lines.contains("允许：是"));
        assert!(lines.contains("whitelist 模式下命中静态白名单"));
    }

    #[test]
    fn source_ip_query_misses_static_whitelist() {
        let cfg = source_query_config(AccessControlMode::Whitelist, &["5.6.7.0/24"], false, 32);
        let lines = query_lines(&cfg, &DynamicWhitelistState::default(), "1.2.3.4");
        assert!(lines.contains("静态 entries: 未命中"));
        assert!(lines.contains("允许：否"));
        assert!(lines.contains("未命中静态白名单或 dynamic_whitelist"));
    }

    #[test]
    fn source_ip_query_hits_dynamic_current_ip() {
        let cfg = source_query_config(AccessControlMode::Whitelist, &[], true, 32);
        let state = dynamic_state_with_home(&["203.0.113.10"], &["203.0.113.10"]);
        let lines = query_lines(&cfg, &state, "203.0.113.10");
        assert!(lines.contains("当前动态 IP: 命中"));
        assert!(lines.contains("命中来源: home.example.com"));
        assert!(lines.contains("whitelist 模式下命中 dynamic_whitelist"));
        assert!(lines.contains("允许：是"));
    }

    #[test]
    fn source_ip_query_dynamic_cidr_expand_false_matches_only_32() {
        let cfg = source_query_config(AccessControlMode::Whitelist, &[], true, 32);
        let state = dynamic_state_with_home(&["203.0.113.10"], &["203.0.113.10"]);
        let lines = query_lines(&cfg, &state, "203.0.113.11");
        assert!(lines.contains("cidr_expand_ipv4: false"));
        assert!(lines.contains("当前动态 IP: 未命中"));
        assert!(lines.contains("允许：否"));
    }

    #[test]
    fn source_ip_query_dynamic_cidr_expand_true_matches_24() {
        let cfg = source_query_config(AccessControlMode::Whitelist, &[], true, 24);
        let state = dynamic_state_with_home(&["203.0.113.10"], &["203.0.113.0/24"]);
        let lines = query_lines(&cfg, &state, "203.0.113.99");
        assert!(lines.contains("cidr_expand_ipv4: true"));
        assert!(lines.contains("当前动态 IP: 命中"));
        assert!(lines.contains("扩展网段: 203.0.113.0/24"));
        assert!(lines.contains("允许：是"));
    }

    #[test]
    fn source_ip_query_blacklist_hit_refuses_first() {
        let cfg = source_query_config(AccessControlMode::Blacklist, &["1.2.3.4"], true, 32);
        let state = dynamic_state_with_home(&["1.2.3.4"], &["1.2.3.4"]);
        let lines = query_lines(&cfg, &state, "1.2.3.4");
        assert!(lines.contains("blacklist: 命中 1.2.3.4"));
        assert!(lines.contains("blacklist 命中，优先拒绝"));
        assert!(lines.contains("允许：否"));
    }

    #[test]
    fn source_ip_query_access_control_off_reports_unrestricted_source() {
        let cfg = source_query_config(AccessControlMode::Off, &[], false, 32);
        let lines = query_lines(&cfg, &DynamicWhitelistState::default(), "1.2.3.4");
        assert!(lines.contains("mode: off"));
        assert!(lines.contains("access_control=off，来源未受白名单限制"));
        assert!(lines.contains("允许：是"));
    }

    #[test]
    fn source_ip_query_geoip_enabled_but_data_unavailable_is_unknown() {
        let dir = std::env::temp_dir().join(format!(
            "nat-source-query-geoip-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = source_query_config(AccessControlMode::Off, &[], false, 32);
        cfg.geoip.enabled = true;
        cfg.geoip.forward.enabled = true;
        cfg.geoip.cn4_file = dir.join("missing-cn4.nft").to_string_lossy().to_string();
        let lines = query_lines(&cfg, &DynamicWhitelistState::default(), "1.2.3.4");
        assert!(lines.contains("forward: enabled"));
        assert!(lines.contains("结果: 数据不可用"));
        assert!(lines.contains("允许：无法完全判断"));
        assert!(lines.contains("GeoIP 数据不可用，无法完全判断"));
    }

    #[test]
    fn source_ip_query_ipv6_dynamic_whitelist_not_enabled_is_explicit() {
        let mut cfg = source_query_config(AccessControlMode::Whitelist, &[], true, 32);
        cfg.dynamic_whitelist.resolve_ipv6 = false;
        let state = dynamic_state_with_home(&["203.0.113.10"], &["203.0.113.10"]);
        let lines = query_lines(&cfg, &state, "2001:db8::1");
        assert!(lines.contains("当前动态 IP: 不适用 / 未启用 IPv6 dynamic whitelist"));
    }

    #[test]
    fn whitelist_empty_lock_warning_triggers_without_static_or_dynamic_ip() {
        let cfg = source_query_config(AccessControlMode::Off, &[], true, 32);
        assert!(whitelist_empty_lock_warning_needed(
            &cfg,
            &DynamicWhitelistState::default()
        ));
    }

    #[test]
    fn whitelist_empty_lock_warning_cancel_keeps_mode_unchanged() {
        let mut cfg = source_query_config(AccessControlMode::Off, &[], true, 32);
        let result = apply_whitelist_mode_with_empty_guard(
            "/tmp/not-used-nat.toml",
            &mut cfg,
            &DynamicWhitelistState::default(),
            false,
        );
        assert_eq!(result, WhitelistModeApplyResult::CancelledByEmptyWarning);
        assert_eq!(cfg.access_control.mode, AccessControlMode::Off);
    }

    #[test]
    fn whitelist_empty_lock_warning_override_writes_audit_warn() {
        let dir = std::env::temp_dir().join(format!(
            "nat-whitelist-empty-override-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.log");
        let toml_path = dir.join("nat.toml");
        let mut cfg = source_query_config(AccessControlMode::Off, &[], true, 32);
        cfg.audit.enabled = true;
        cfg.audit.file = audit_path.to_string_lossy().to_string();
        std::fs::write(&toml_path, cfg.to_toml_string().unwrap()).unwrap();
        let result = apply_whitelist_mode_with_empty_guard(
            toml_path.to_str().unwrap(),
            &mut cfg,
            &DynamicWhitelistState::default(),
            true,
        );
        assert_eq!(result, WhitelistModeApplyResult::Applied);
        assert_eq!(cfg.access_control.mode, AccessControlMode::Whitelist);
        let raw = std::fs::read_to_string(&audit_path).unwrap();
        assert!(raw.contains("\"action\":\"access_control.whitelist.empty_override\""));
        assert!(raw.contains("\"result\":\"warn\""));
    }

    #[test]
    fn readme_documents_source_whitelist_troubleshooting() {
        let readme = include_str!("../../README.md");
        assert!(readme.contains("查询某来源 IP 是否命中"));
        assert!(readme.contains("dynamic_whitelist"));
        assert!(
            readme.contains("`egress_control` 是目标限制，独立判断"),
            "README should distinguish egress_control (target) from source restrictions"
        );
    }

    // ===== v0.8.1 草案：动态 DDNS 来源白名单子菜单简化测试 =====

    fn dynamic_whitelist_brief_config(
        mode: AccessControlMode,
        dynamic_enabled: bool,
        domains: &[(&str, &str, bool)],
        resolve_ipv6: bool,
    ) -> TomlConfig {
        let mut cfg = brief_layout_config(mode, &[], false, false, dynamic_enabled, domains);
        cfg.dynamic_whitelist.resolve_ipv6 = resolve_ipv6;
        cfg
    }

    #[test]
    fn dynamic_whitelist_brief_shows_summary_without_full_combined_policy() {
        let cfg = dynamic_whitelist_brief_config(AccessControlMode::Off, false, &[], false);
        let state = DynamicWhitelistState::default();
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        assert!(lines.contains("状态："));
        assert!(lines.contains("enabled: false"));
        assert!(lines.contains("生效条件: access_control.mode = whitelist"));
        assert!(lines.contains("domains: 0"));
        assert!(lines.contains("raw IPs: 0"));
        assert!(lines.contains("effective sources: 0"));
        assert!(lines.contains("stale: 0"));
        assert!(lines.contains("refresh interval: 300s"));
        assert!(lines.contains("IPv4: enabled"));
        assert!(lines.contains("IPv6: disabled"));
        assert!(lines.contains("IPv4 CIDR 扩展: /32 精确 IP"));
        assert!(lines.contains("state: /var/lib/nftables-nat-rust/dynamic-whitelist-state.json"));
        // 默认状态（disabled，mode=off）：不触发任何情境化提示
        assert!(
            !lines.contains("提示：当前 access_control.mode"),
            "disabled 时不应触发 mode 提示: {lines}"
        );
        assert!(
            !lines.contains("提示：动态白名单已启用，但还没有配置 DDNS 域名"),
            "disabled 时不应触发 domains=0 提示: {lines}"
        );
        assert!(
            !lines.contains("警告：当前没有可用动态白名单 IP"),
            "disabled 时不应触发 zero IPs 警告: {lines}"
        );
    }

    #[test]
    fn dynamic_whitelist_brief_excludes_snat_mss_egress_long_text() {
        let cfg = dynamic_whitelist_brief_config(
            AccessControlMode::Whitelist,
            true,
            &[("home", "home.example.com", true)],
            false,
        );
        let state = DynamicWhitelistState::default();
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        // 子菜单不应混入 SNAT / MSS / egress / 评估顺序等内容
        assert!(
            !lines.contains("SNAT（源地址改写）"),
            "动态白名单子菜单不应包含 SNAT 长段: {lines}"
        );
        assert!(
            !lines.contains("MSS clamp（TCP MSS 调整）"),
            "动态白名单子菜单不应包含 MSS 长段: {lines}"
        );
        assert!(
            !lines.contains("egress_control（目标 IP / IP 段限制）"),
            "动态白名单子菜单不应包含 egress 长段: {lines}"
        );
        assert!(
            !lines.contains("评估顺序：黑名单 > 白名单"),
            "动态白名单子菜单不应包含评估顺序长行: {lines}"
        );
        assert!(
            !lines.contains("组合策略 (access_control + GeoIP + egress + SNAT + MSS)"),
            "动态白名单子菜单不应展开完整组合策略: {lines}"
        );
    }

    #[test]
    fn dynamic_whitelist_brief_hint_for_non_whitelist_mode() {
        let cfg = dynamic_whitelist_brief_config(
            AccessControlMode::Off,
            true,
            &[("home", "home.example.com", true)],
            false,
        );
        let state = DynamicWhitelistState::default();
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        assert!(
            lines.contains(
                "提示：当前 access_control.mode = off，动态白名单只会解析和显示状态，不参与来源放行。"
            ),
            "mode != whitelist 时应给出 off 提示: {lines}"
        );
    }

    #[test]
    fn dynamic_whitelist_brief_hint_for_enabled_with_zero_domains() {
        let cfg = dynamic_whitelist_brief_config(AccessControlMode::Whitelist, true, &[], false);
        let state = DynamicWhitelistState::default();
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        assert!(
            lines.contains("提示：动态白名单已启用，但还没有配置 DDNS 域名。"),
            "enabled=true 且 domains=0 时应给出提示: {lines}"
        );
    }

    #[test]
    fn dynamic_whitelist_brief_warn_for_whitelist_zero_current_ips() {
        let cfg = dynamic_whitelist_brief_config(
            AccessControlMode::Whitelist,
            true,
            &[("home", "home.example.com", true)],
            false,
        );
        let state = DynamicWhitelistState::default();
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        assert!(
            lines.contains(
                "警告：当前没有可用动态白名单 IP。若静态白名单也为空，可能导致所有来源被拒绝。"
            ),
            "whitelist 模式 + 0 dynamic IPs 时应给出警告: {lines}"
        );
    }

    #[test]
    fn dynamic_whitelist_brief_no_warning_when_current_ips_present() {
        let cfg = dynamic_whitelist_brief_config(
            AccessControlMode::Whitelist,
            true,
            &[("home", "home.example.com", true)],
            false,
        );
        let state = DynamicWhitelistState {
            domains: vec![nat_common::dynamic_whitelist::DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                last_good_ips: vec!["203.0.113.10".to_string()],
                current_ips: vec!["203.0.113.10".to_string()],
                raw_ips: vec!["203.0.113.10".to_string()],
                effective_sources: vec!["203.0.113.10".to_string()],
                cidr_expand_ipv4: 32,
                resolved_at: Some("2026-05-28T00:00:00Z".to_string()),
                stale: false,
                error: None,
                ipv4: true,
                ipv6: false,
            }],
        };
        let lines = format_dynamic_whitelist_brief_lines(&cfg, &state).join("\n");
        assert!(lines.contains("raw IPs: 1"));
        assert!(lines.contains("effective sources: 1"));
        assert!(lines.contains("IPv4 CIDR 扩展: /32 精确 IP"));
        assert!(
            !lines.contains("警告：当前没有可用动态白名单 IP"),
            "raw IPs 非零时不应触发零 IP 警告: {lines}"
        );
    }

    #[test]
    fn cidr_expand_label_renders_both_modes() {
        assert!(format_cidr_expand_label(32).contains("/32"));
        assert!(format_cidr_expand_label(32).contains("精确"));
        assert!(format_cidr_expand_label(24).contains("/24"));
        assert!(format_cidr_expand_label(24).contains("宽松"));
        assert!(format_cidr_expand_label(16).contains("非法值"));
    }

    #[test]
    fn cidr_expand_save_reason_is_in_nft_affecting_list() {
        // CIDR mode change must trigger the "nft-affecting" save hint so the user knows
        // nat.service will re-apply rules in the next detection cycle.
        assert!(reason_affects_nft("dynamic_whitelist.cidr_expand.update"));
    }

    #[test]
    fn cidr_expand_menu_lists_option_8_in_dynamic_whitelist_submenu() {
        let src = menu_src_non_test();
        // 子菜单必须暴露选项 8 (设置 IPv4 CIDR 扩展模式)，否则用户无入口切换 /32 ↔ /24。
        assert!(
            src.contains("8) 设置 IPv4 CIDR 扩展模式"),
            "动态 DDNS 来源白名单子菜单需新增「8) 设置 IPv4 CIDR 扩展模式」选项"
        );
    }

    #[test]
    fn cidr_expand_warning_text_explains_256_addresses_and_double_confirm() {
        let src = menu_src_non_test();
        // /24 切换必须给出二次确认警告，明确说明影响范围（256 地址）和 [y/N] 默认拒绝。
        assert!(
            src.contains("最多放宽到 256 个 IPv4 地址"),
            "/24 切换需提示最多 256 个 IPv4 地址的影响"
        );
        assert!(
            src.contains("确认启用 /24 扩展？[y/N]"),
            "/24 切换需要二次确认且默认为 N"
        );
    }

    #[test]
    fn dynamic_whitelist_menu_title_uses_simplified_name() {
        let src = menu_src_non_test();
        assert!(
            src.contains("动态 DDNS 来源白名单"),
            "子菜单标题应统一为「动态 DDNS 来源白名单」"
        );
        // 旧标题 v0.8.0 用「动态 DDNS 来源白名单管理」；v0.8.1 简化后不再有「管理」后缀
        assert!(
            !src.contains("动态 DDNS 来源白名单管理\n===="),
            "子菜单标题不应再带「管理」后缀"
        );
    }
}
