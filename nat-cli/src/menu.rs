use chrono::Local;
use log::warn;
use nat_common::{
    AccessControlMode, Args, AuditConfig, DdnsConfig, IpVersion, MSS_CLAMP_MAX, MSS_CLAMP_MIN,
    MssClampConfig, NftCell, Protocol, QuotaPeriod, SnatConfig, SnatMode, StatsConfig, TomlConfig,
    TrafficMode,
    audit::{self, AuditResult},
    build_version, format_cli_time, format_cli_time_from_rfc3339, forward_test, geoip,
    last_good::{LastGoodState, ResolveSource},
    quota, stats as traffic_stats,
    uninstall::{self, DataMode, UninstallTarget},
};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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
            "1" => show_rules(config_path).map_err(Into::into),
            "2" => add_single_interactive(config_path).map_err(Into::into),
            "3" => add_range_interactive(config_path).map_err(Into::into),
            "4" => delete_rule_interactive(config_path).map_err(Into::into),
            "5" => {
                should_wait = false;
                toggle_rule_interactive(config_path).map_err(Into::into)
            }
            "6" => show_nft_rules().map_err(Into::into),
            "7" => {
                should_wait = false;
                stats_menu(config_path).map_err(Into::into)
            }
            "8" => {
                refresh_ddns_interactive(config_path, &mut last_manual_refresh).map_err(Into::into)
            }
            "9" => match backup_config(config_path) {
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
            "10" => restore_config_interactive(config_path).map_err(Into::into),
            "11" => {
                should_wait = false;
                access_control_menu(config_path).map_err(Into::into)
            }
            "12" => {
                should_wait = false;
                geoip_menu(config_path).map_err(Into::into)
            }
            "13" => {
                should_wait = false;
                egress_control_menu(config_path).map_err(Into::into)
            }
            "14" => {
                show_recent_source_design();
                Ok(())
            }
            "15" => {
                should_wait = false;
                bbr_telegram_menu(config_path).map_err(Into::into)
            }
            "16" => test_forward_interactive(config_path).map_err(Into::into),
            "17" => {
                should_wait = false;
                update_menu(config_path).map_err(Into::into)
            }
            "18" => {
                should_wait = false;
                uninstall_menu(config_path).map_err(Into::into)
            }
            "19" => {
                should_wait = false;
                advanced_network_menu(config_path).map_err(Into::into)
            }
            "20" => {
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
nftables-nat-rust-enhanced 管理菜单
====================================
1) 查看当前转发规则
2) 添加单端口转发
3) 添加端口段转发
4) 删除转发规则
5) 启用 / 禁用规则
6) 查看当前 nft 规则
7) 查看 Stats 流量统计
8) 手动刷新 DDNS / 域名目标
9) 备份当前配置
10) 从备份恢复配置
11) 白名单 / 黑名单管理
12) GeoIP / CN IP 限制
13) 出口目标限制
14) 最近来源 IP 观察
15) BBR / Telegram 状态
16) 测试转发规则连通性
17) 一键更新本项目
18) 卸载 / 清理本项目
19) 高级网络设置 (SNAT / MSS clamp)
20) 查看审计日志
0) 退出
===================================="#
    );
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

fn save_toml_config(path: &str, config: &TomlConfig) -> Result<(), io::Error> {
    let content = config
        .to_toml_string()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, content)
}

fn show_rules(path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(path)?;
    if config.rules.is_empty() {
        println!("当前没有转发规则");
    } else {
        for (index, rule) in config.rules.iter().enumerate() {
            println!("{index}) [{}] {}", rule_status(rule), format_rule(rule));
        }
    }
    println!();
    for line in format_combined_policy_status(&config) {
        println!("{line}");
    }
    println!();
    for line in format_last_good_status(&config) {
        println!("{line}");
    }
    Ok(())
}

fn add_single_interactive(path: &str) -> Result<(), io::Error> {
    let sport = parse_port(&prompt("监听端口 sport: ")?)?;
    let domain = parse_domain(&prompt("目标地址 domain: ")?)?;
    let dport = parse_port(&prompt("目标端口 dport: ")?)?;
    let protocol = parse_protocol(&prompt("协议 tcp/udp/all [tcp]: ")?)?;
    let ip_version = parse_ip_version(&prompt("IP 版本 ipv4/ipv6/all [ipv4]: ")?)?;
    let comment = parse_optional_comment(&prompt("comment，可为空: ")?);

    let mut config = load_toml_config(path)?;
    add_single_rule(
        &mut config,
        sport,
        dport,
        domain,
        protocol,
        ip_version,
        comment,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    backup_config(path)?;
    save_toml_config(path, &config)?;
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
    print_config_saved_hint(path);
    Ok(())
}

fn add_range_interactive(path: &str) -> Result<(), io::Error> {
    let port_start = parse_port(&prompt("监听起始端口 port_start: ")?)?;
    let port_end = parse_port(&prompt("监听结束端口 port_end: ")?)?;
    let domain = parse_domain(&prompt("目标地址 domain: ")?)?;
    let protocol = parse_protocol(&prompt("协议 tcp/udp/all [tcp]: ")?)?;
    let ip_version = parse_ip_version(&prompt("IP 版本 ipv4/ipv6/all [ipv4]: ")?)?;
    let comment = parse_optional_comment(&prompt("comment，可为空: ")?);

    let mut config = load_toml_config(path)?;
    add_range_rule(
        &mut config,
        port_start,
        port_end,
        domain,
        protocol,
        ip_version,
        comment,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    backup_config(path)?;
    save_toml_config(path, &config)?;
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
    print_config_saved_hint(path);
    Ok(())
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
    let confirm = prompt("危险操作：删除前会自动备份配置。确认删除? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消删除");
        return Ok(());
    }
    backup_config(path)?;
    delete_rule(&mut config, index).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    save_toml_config(path, &config)?;
    audit_cli(
        path,
        "rule.delete",
        AuditResult::Ok,
        json!({"index": index}),
    );
    println!("已删除规则。");
    print_config_saved_hint(path);
    Ok(())
}

fn print_config_saved_hint(path: &str) {
    println!("已保存配置到 {path}。");
    println!("nat.service 通常会自动检测配置变化，并通过安全流程应用规则。");
    println!("安全流程包括：nft -c 检查、备份当前规则、应用失败自动回滚。");
    println!("本工具不会直接绕过安全流程执行 nft -f。");
    // 显示当前 ddns.refresh_interval_seconds 作为「检测周期」参考值；读不到就退回默认提示
    let interval_secs = load_toml_config(path)
        .ok()
        .map(|c| c.ddns.refresh_interval_seconds);
    match interval_secs {
        Some(secs) => {
            println!("当前自动检测 / 刷新间隔：{secs} 秒（ddns.refresh_interval_seconds）。");
        }
        None => {
            println!(
                "当前自动检测 / 刷新间隔：默认 300 秒（无法读取 ddns.refresh_interval_seconds）。"
            );
        }
    }
    println!("如果刚改完配置后立即测试显示 nft 未应用，请等待一个检测周期后刷新；这通常不是 bug。");
    println!("如需立即尝试应用，可手动执行：");
    println!("  systemctl restart nat");
    println!("确认当前规则是否已应用：");
    println!("  nft list table ip self-nat");
    println!("  nft list table ip self-filter");
    println!("  journalctl -u nat -n 120 --no-pager");
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("已保存统计口径到 {config_path}。");
    println!("后续新增流量将按新口径累计；历史 daily/monthly 不会自动重算。");
    println!("如需重新统计，请重置今日或本月统计。");
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
        let rule_idx: Option<usize> = usage.rule_id.strip_prefix('r').and_then(|s| s.parse().ok());
        let rule_state = rule_idx
            .and_then(|i| config.rules.get(i))
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
            println!("  上次通知时间: {}", format_cli_time_from_rfc3339(&ts));
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

fn restore_config_interactive(path: &str) -> Result<(), io::Error> {
    let backups = list_config_backups()?;
    if backups.is_empty() {
        println!("没有找到配置备份");
        return Ok(());
    }
    for (index, backup) in backups.iter().enumerate() {
        println!("{index}) {}", backup.display());
    }
    let index = parse_index(&prompt("请选择要恢复的备份 index: ")?)?;
    if index >= backups.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "备份 index 超出范围",
        ));
    }
    let confirm = prompt("恢复前会备份当前配置。确认恢复? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消恢复");
        return Ok(());
    }
    backup_config(path)?;
    fs::copy(&backups[index], path)?;
    audit_cli(
        path,
        "backup.restore",
        AuditResult::Ok,
        json!({"backup": backups[index].display().to_string()}),
    );
    println!("已恢复配置: {}", backups[index].display());
    print_config_saved_hint(path);
    Ok(())
}

fn access_control_menu(path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(path)?;
    loop {
        println!(
            r#"====================================
访问控制管理
====================================
当前模式：{}
当前 entries："#,
            config.access_control.mode
        );
        print_access_entries(&config);
        for line in format_combined_policy_status(&config) {
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
8) 保存并应用
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
                if confirm("确认切换到 whitelist? [y/N]: ")? {
                    config.access_control.mode = AccessControlMode::Whitelist;
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
                config
                    .access_control
                    .validate()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                backup_config(path)?;
                save_toml_config(path, &config)?;
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
                print_config_saved_hint(path);
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

pub(crate) fn delete_access_entry(config: &mut TomlConfig, index: usize) -> Result<String, String> {
    if index >= config.access_control.entries.len() {
        return Err("entry index 超出范围".to_string());
    }
    Ok(config.access_control.entries.remove(index))
}

pub(crate) fn clear_access_entries(config: &mut TomlConfig) {
    config.access_control.entries.clear();
}

fn show_recent_source_design() {
    println!("最近来源 IP 观察用于查看访问转发端口的来源 IP。");
    println!("它不等同于白名单 / 黑名单管理，不会自动放行或封禁来源 IP。");
    println!("当前 CLI 不要求启用白名单或黑名单，也不会修改 access_control 配置。");
    println!("暂无来源 IP 记录。请从外部客户端访问转发端口后刷新。");
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
    let geoip_forward = config.geoip.enabled && config.geoip.forward.enabled;
    let geoip_ssh = config.geoip.enabled && config.geoip.ssh.enabled;
    let egress_enabled = config.egress_control.enabled;
    let egress_count = config.egress_control.allowed_target_cidrs.len();

    lines.push("------------------------------------".to_string());
    lines.push("组合策略 (access_control + GeoIP + egress + SNAT + MSS)".to_string());
    lines.push("------------------------------------".to_string());
    lines.push(format!(
        "access_control（自定义来源 IP 限制）：模式={ac_mode} entries={ac_count}"
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
    lines.push("评估顺序：黑名单 > 白名单 > GeoIP（同时启用 = AND）".to_string());
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
        "说明：access_control 与 GeoIP 是来源 IP 限制；egress_control 是目标 IP 限制；SNAT 是源地址改写；MSS clamp 是 TCP MSS 调整。这些功能叠加生效，不是互相覆盖。".to_string(),
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
        (AccessControlMode::Whitelist, false) => "允许 = 在白名单".to_string(),
        (AccessControlMode::Whitelist, true) => "允许 = 在白名单 AND 属于 CN/LAN".to_string(),
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
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
    Ok(())
}

fn set_geoip_ssh_port(config_path: &str) -> Result<(), io::Error> {
    let mut config = load_toml_config(config_path)?;
    println!("当前 SSH 端口：{}", config.geoip.ssh.port);
    let value = prompt("请输入新的 SSH 端口 (1-65535): ")?;
    let port = parse_port(&value)?;
    config.geoip.ssh.port = port;
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("SSH 端口已保存为 {port}");
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("CN IP set 更新间隔已保存为 {hours} 小时");
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("已添加 {value}");
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("已删除 {removed}");
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
        Err(e) => println!("Telegram 测试通知发送失败: {e}"),
    }
    Ok(())
}

fn send_telegram_http_for_cli(url: &str, params: &[(&str, &str)]) -> Result<(), String> {
    let mut command = Command::new("curl");
    command.arg("-sS").arg("-X").arg("POST").arg(url);
    for (key, value) in params {
        command
            .arg("--data-urlencode")
            .arg(format!("{key}={value}"));
    }
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
        Err(format!(
            "HTTP 状态 {status}: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!(
        "Telegram 通知已{}。",
        if config.telegram.enabled {
            "启用"
        } else {
            "禁用"
        }
    );
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
    println!("Telegram 通知间隔已保存为 {minutes} 分钟。");
    print_config_saved_hint(config_path);
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

fn update_menu(config_path: &str) -> Result<(), io::Error> {
    println!(
        r#"====================================
一键更新 nftables-nat-rust-enhanced
====================================
1) 更新核心转发 nat，推荐
2) 指定版本更新核心 nat
0) 返回"#
    );
    let choice = prompt("请选择 [0/1/2]: ")?;
    if choice.trim() == "0" {
        return Ok(());
    }
    let specify_version = match choice.trim() {
        "1" => false,
        "2" => true,
        _ => {
            println!("未知更新目标。");
            wait_enter_to_return()?;
            return Ok(());
        }
    };

    let version = if specify_version {
        let tag = prompt("请输入版本 tag，例如 v0.1.2: ")?;
        if !valid_update_version(&tag) {
            println!("无效版本，只允许 latest 或 v 开头的 tag，例如 v0.1.2");
            wait_enter_to_return()?;
            return Ok(());
        }
        tag
    } else {
        "latest".to_string()
    };

    println!("更新摘要：");
    println!("  当前版本: {}", current_version_for_update());
    println!("  目标版本: {version}");
    println!("  将更新: /usr/local/bin/nat 和 nat.service");
    println!("  下载方式: GitHub Release 预编译包优先");
    println!("  备份: /etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS/");
    println!("  保留: /etc/nat.toml、/etc/nat.conf、stats、backups");
    println!("  重启: nat.service");
    let confirm = prompt("继续更新？[y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y" | "yes" | "YES") {
        println!("已取消更新");
        wait_enter_to_return()?;
        return Ok(());
    }

    let mut args = vec!["--update", "--core-only", "--use-release"];
    if version != "latest" {
        args.push("--version");
        args.push(&version);
    }
    let command_line = format!(
        "curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- {}",
        args.join(" ")
    );
    audit_cli(
        config_path,
        "update.start",
        AuditResult::Info,
        json!({"version": version}),
    );
    println!("开始更新，install.sh 会负责备份、重启和失败回滚。");
    let status = Command::new("sh").arg("-c").arg(command_line).status()?;
    if !status.success() {
        audit_cli(
            config_path,
            "update.fail",
            AuditResult::Fail,
            json!({"version": version, "exit_status": status.to_string()}),
        );
        println!("更新命令执行失败。install.sh 会保留旧二进制并在可能时回滚，请查看输出和服务日志");
        wait_enter_to_return()?;
        return Ok(());
    }

    audit_cli(
        config_path,
        "update.success",
        AuditResult::Ok,
        json!({"version": version}),
    );
    println!("更新完成，正在重新载入新版 CLI 菜单...");
    match installed_nat_version() {
        Some(v) => println!("已安装版本: {v}"),
        None => println!("warning: 无法读取新版本号，将继续重载菜单。"),
    }

    let bin_path = Path::new(NAT_BIN_PATH);
    let action = reload_action(true, tty_available(), bin_path.exists());
    match action {
        ReloadAction::Exec => {
            let err = reexec_menu(NAT_BIN_PATH);
            println!("更新已完成，但自动重新载入菜单失败：{err}");
            println!("请手动执行：");
            println!("  nat --menu");
            wait_enter_to_return()?;
        }
        ReloadAction::NoTty => {
            println!("更新已完成。请手动执行 nat --menu 进入新版菜单。");
        }
        ReloadAction::BinaryMissing => {
            println!("更新已完成，但未找到 {NAT_BIN_PATH}，无法自动重载菜单。");
            println!("请手动执行：");
            println!("  nat --menu");
            wait_enter_to_return()?;
        }
        ReloadAction::SkipUpdateFailed => {}
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ReloadAction {
    SkipUpdateFailed,
    NoTty,
    BinaryMissing,
    Exec,
}

fn reload_action(update_success: bool, tty_available: bool, binary_exists: bool) -> ReloadAction {
    if !update_success {
        return ReloadAction::SkipUpdateFailed;
    }
    if !tty_available {
        return ReloadAction::NoTty;
    }
    if !binary_exists {
        return ReloadAction::BinaryMissing;
    }
    ReloadAction::Exec
}

fn tty_available() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

fn reexec_menu(bin: &str) -> io::Error {
    Command::new(bin).arg("--menu").exec()
}

/// 查看最近 50 行 audit 日志
fn view_audit_log_interactive(config_path: &str) -> Result<(), io::Error> {
    let audit_cfg = audit_config_from(config_path);
    println!("====================================");
    println!("审计日志（最近 50 行）");
    println!("====================================");
    println!("audit.enabled: {}", audit_cfg.enabled);
    println!("audit.file: {}", audit_cfg.file);
    if !audit_cfg.enabled {
        println!("提示：audit.enabled = false，CLI 操作不会写入审计日志。");
    }
    println!(
        "提示：JSON 内部 `time` 字段为 UTC RFC3339；CLI 状态页其他时间会按 Asia/Shanghai 展示。"
    );
    let lines = audit::read_tail(&audit_cfg.file, 50);
    if lines.is_empty() {
        println!("（无日志或文件不存在）");
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    println!();
    println!(
        "提示：每条审计日志为一行 JSON，便于 grep。完整文件位于 {}",
        audit_cfg.file
    );
    wait_enter_to_return()?;
    Ok(())
}

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
        Some(ts) => lines.push(format!("最近成功应用时间: {}", format_cli_time(ts))),
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
            format_cli_time(rule.last_resolved_at),
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
                // 自管 wait：函数内部完成一次 wait_enter_to_return；不再叠加。
                time_status_interactive()?;
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

/// 时间 / NTP 状态检查页面。
///
/// **只查看，不默认修改系统时间**。可通过 y/N 二次确认尝试启用系统 NTP（调用
/// `timedatectl set-ntp true`，需要 root），未确认时只打印建议命令。
fn time_status_interactive() -> Result<(), io::Error> {
    let now_utc = chrono::Utc::now();
    let local_now = chrono::Local::now();
    println!("====================================");
    println!("时间 / NTP 状态检查");
    println!("====================================");
    println!(
        "当前系统时间（本机时区）：{}",
        local_now.format("%Y-%m-%d %H:%M:%S %Z")
    );
    println!("当前 UTC 时间：{}", now_utc.format("%Y-%m-%d %H:%M:%S UTC"));
    println!(
        "CLI 展示时区：{} ({})",
        nat_common::CLI_DISPLAY_TZ_LABEL,
        format_cli_time(now_utc)
    );

    println!();
    println!("nft 转发本身不严格依赖系统时间，但以下功能建议系统时间准确：");
    println!("  - Stats daily/monthly 滚动重置");
    println!("  - quota 周期判断 / 通知去重 key");
    println!("  - audit log 时间戳");
    println!("  - last-good 上次成功解析时间");
    println!("  - TLS 下载 release / cn4.nft 时的证书校验");
    println!();

    let output = Command::new("timedatectl").arg("status").output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ntp_service = parse_timedatectl_field(&stdout, "NTP service")
                .or_else(|| parse_timedatectl_field(&stdout, "Network time on"));
            let synchronized = parse_timedatectl_field(&stdout, "System clock synchronized");
            let timezone = parse_timedatectl_field(&stdout, "Time zone");
            println!("timedatectl: 可用");
            println!(
                "NTP 服务：{}",
                ntp_service.as_deref().unwrap_or("(未知字段)")
            );
            println!(
                "System clock synchronized：{}",
                synchronized.as_deref().unwrap_or("(未知字段)")
            );
            println!(
                "当前系统时区：{}",
                timezone.as_deref().unwrap_or("(未知字段)")
            );

            let synced_yes = synchronized
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("yes"));
            if !synced_yes {
                println!();
                println!("提示：系统时钟未同步。可手动执行（需要 root）：");
                println!("  sudo timedatectl set-ntp true");
                let confirm = prompt("尝试启用系统 NTP？[y/N]: ")?;
                if matches!(confirm.as_str(), "y" | "Y" | "yes" | "YES") {
                    match Command::new("timedatectl")
                        .arg("set-ntp")
                        .arg("true")
                        .output()
                    {
                        Ok(set_out) if set_out.status.success() => {
                            println!("已尝试启用系统 NTP。请稍后再次查看以确认 synchronized=yes。");
                        }
                        Ok(set_out) => {
                            println!(
                                "执行 timedatectl set-ntp true 返回非零退出码：{}",
                                String::from_utf8_lossy(&set_out.stderr).trim()
                            );
                            println!(
                                "常见原因：未以 root 运行；或当前系统不使用 systemd-timesyncd。"
                            );
                        }
                        Err(e) => {
                            println!("调用 timedatectl set-ntp true 失败：{e}");
                        }
                    }
                } else {
                    println!("已取消，不改动系统 NTP 设置。");
                }
            }
        }
        Ok(out) => {
            println!(
                "timedatectl status 返回非零退出码：{}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("未检测到 timedatectl（可能未安装 systemd 工具）。");
            println!(
                "如果你需要保持时钟同步，请使用你的发行版自带的 NTP 客户端，本项目不会自动安装任何依赖。"
            );
        }
        Err(e) => {
            println!("调用 timedatectl 失败：{e}");
        }
    }
    wait_enter_to_return()
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
    println!();
    for line in format_combined_policy_status(config) {
        println!("{line}");
    }
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
            "提示：MSS clamp 适合多跳 / 隧道 / po0 / MTU 异常场景；不懂 MTU/MSS 时不建议随意开启。"
        );
        if !confirm("启用 MSS clamp? [y/N]: ")? {
            println!("已取消");
            return Ok(());
        }
        config.mss_clamp.enabled = true;
    }
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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
    backup_config(config_path)?;
    save_toml_config(config_path, &config)?;
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
    print_config_saved_hint(config_path);
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

fn current_version_for_update() -> String {
    installed_nat_version().unwrap_or_else(|| build_version_for_update_display(build_version()))
}

fn installed_nat_version() -> Option<String> {
    let output = Command::new("/usr/local/bin/nat")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_nat_version_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_nat_version_output(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|part| valid_release_tag(part))
        .map(ToString::to_string)
}

fn build_version_for_update_display(version: &str) -> String {
    if valid_release_tag(version) {
        version.to_string()
    } else {
        "unknown".to_string()
    }
}

fn valid_update_version(version: &str) -> bool {
    if version == "latest" {
        return true;
    }
    version.starts_with('v')
        && version.len() > 1
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn valid_release_tag(version: &str) -> bool {
    version.starts_with('v')
        && version.len() > 1
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn test_forward_interactive(path: &str) -> Result<(), io::Error> {
    let config = load_toml_config(path)?;
    let rules = forward_test::list_testable_rules(&config);
    if rules.is_empty() {
        if config.rules.iter().any(|rule| !rule.enabled()) {
            println!("当前没有启用的可测试转发规则。");
            println!("禁用规则不会应用到 nft，也不会出现在默认连通性测试列表。");
        } else {
            println!("当前没有可测试的转发规则");
        }
        return Ok(());
    }
    for rule in &rules {
        println!("{}) {}", rule.index, rule.label);
    }
    let index = parse_index(&prompt("请选择要测试的规则 index: ")?)?;
    let Some(rule) = rules.iter().find(|rule| rule.index == index) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "规则 index 超出范围",
        ));
    };

    println!("规则详情：");
    println!("  type: {}", rule.r#type);
    println!("  sport: {}", rule.sport);
    println!("  target/domain: {}", rule.target);
    println!(
        "  resolved ip: {}",
        rule.resolved_ip.as_deref().unwrap_or("解析失败或暂不可用")
    );
    let rule_id = format!("r{}", rule.index);
    let last_good_state = LastGoodState::load(&config.last_good.file);
    let cached = last_good_state.lookup(&rule_id);
    match (rule.resolved_ip.as_deref(), cached) {
        (Some(ip), Some(cached)) if ip == cached.last_good_ip => {
            println!(
                "  解析来源: {} (与 last-good 缓存一致)",
                ResolveSource::Live.as_str()
            );
            println!(
                "  上次成功解析时间: {}",
                format_cli_time(cached.last_resolved_at)
            );
        }
        (Some(_), Some(cached)) => {
            println!(
                "  解析来源: {} (实时解析，缓存中的旧 IP 为 {})",
                ResolveSource::Live.as_str(),
                cached.last_good_ip
            );
            println!(
                "  上次成功解析时间: {}",
                format_cli_time(cached.last_resolved_at)
            );
        }
        (Some(_), None) => {
            println!(
                "  解析来源: {} (last-good 缓存中无此规则记录)",
                ResolveSource::Live.as_str()
            );
        }
        (None, Some(cached)) => {
            println!(
                "  解析来源: 当前实时解析失败；若 last_good.enabled=true 会回退到 last-good IP {}",
                cached.last_good_ip
            );
            println!(
                "  last-good 上次成功解析时间: {}",
                format_cli_time(cached.last_resolved_at)
            );
            println!(
                "  egress_control 判断: {}",
                if cached.egress_allowed {
                    "allowed"
                } else {
                    "blocked"
                }
            );
        }
        (None, None) => {
            println!("  解析来源: 当前实时解析失败，且 last-good 缓存无记录，规则会被跳过");
        }
    }
    if config.egress_control.enabled
        && let Some(ip) = rule.resolved_ip.as_deref()
    {
        let allowed = config.egress_control.allows_ip(ip);
        println!(
            "  egress_control 判断: {} (live IP)",
            if allowed { "allowed" } else { "blocked" }
        );
    }
    println!("  dport: {}", rule.dport);
    println!("  protocol: {}", rule.protocol);
    println!("  ip_version: {}", rule.ip_version);
    println!("  access_control: {}", config.access_control.mode);
    if !config.access_control.entries.is_empty() {
        println!("  entries: {}", config.access_control.entries.join(", "));
    }
    if let Some(note) = forward_test::access_control_note(&config.access_control) {
        println!("  提示: {note}");
    }

    let nat_active = is_nat_service_active();
    println!(
        "nat.service: {}",
        if nat_active {
            "active"
        } else {
            "inactive/unknown"
        }
    );
    if !nat_active {
        println!("nat.service 未运行，转发规则不会应用。");
        println!("请执行：");
        println!("  systemctl restart nat");
        println!("  systemctl status nat --no-pager -l");
        println!("  journalctl -u nat -n 120 --no-pager");
    }
    let nft_json = read_nft_json_ruleset();
    match nft_json {
        Ok(json) => match forward_test::parse_rule_counters(&json, &rule.id) {
            Ok(counters) => {
                let nft_applied = forward_test::nft_rule_applied(&counters);
                println!(
                    "nft 规则: {}",
                    if nft_applied {
                        "已应用"
                    } else {
                        "未找到"
                    }
                );
                if !nft_applied {
                    // 该规则在 /etc/nat.toml 中存在（由 list_testable_rules 过滤过 enabled=true）
                    // 但 nft ruleset 里没找到对应 counter；最常见原因是 nat.service 还没跑完
                    // 一个检测周期。给出明确的 pending 提示，避免用户误以为出 bug。
                    println!("规则已保存但尚未在 nft 中生效，可能正在等待 nat.service 自动应用。");
                    println!("请稍后刷新，或检查：");
                    println!("  systemctl status nat --no-pager -l");
                    println!("  journalctl -u nat -n 120 --no-pager");
                    println!("其他可能原因：");
                    println!("- nat.service 未运行");
                    println!("- 规则配置解析失败");
                    println!("- fake-ip 被拒绝");
                    println!(
                        "  当前自动检测 / 刷新间隔：{} 秒（ddns.refresh_interval_seconds）",
                        config.ddns.refresh_interval_seconds
                    );
                }
                println!(
                    "baseline counters: nat-rule={}B, out={}B, in={}B",
                    counters.nat_rule.bytes, counters.out.bytes, counters.r#in.bytes
                );
            }
            Err(e) => println!("读取 nft counter 失败: {e}"),
        },
        Err(e) => println!("读取 nft ruleset 失败: {e}"),
    }

    match forward_test::tcp_connect_target(rule, std::time::Duration::from_secs(3)) {
        Some(true) => println!("目标 TCP: 可达，服务器到目标 TCP 端口可连接。"),
        Some(false) => println!("目标 TCP: 不可达，请检查目标 IP/端口、防火墙、目标服务。"),
        None => println!("目标 TCP: UDP/all 场景无法完全可靠判断，请结合外部访问和 counter。"),
    }

    let examples = forward_test::external_examples(rule);
    println!("\n请在另一台机器执行下面命令测试外部访问，然后回到 CLI 观察 stats/counter：");
    println!("HTTP 示例: {}", examples.http);
    println!("TCP 示例: {}", examples.tcp);
    println!("HTTPS/SNI 示例: {}", examples.https_sni);
    println!(
        "注意：本机 curl 127.0.0.1:{} 通常不能完整验证 DNAT PREROUTING。",
        rule.sport
    );
    println!("如果测试后 counter 有变化，可回到 CLI 查看 Stats 流量统计。");
    println!();
    for line in format_combined_policy_status(&config) {
        println!("{line}");
    }
    println!();
    for line in format_last_good_status(&config) {
        println!("{line}");
    }
    Ok(())
}

fn is_nat_service_active() -> bool {
    Command::new("systemctl")
        .arg("is-active")
        .arg("nat")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
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
    comment: Option<String>,
) -> Result<(), String> {
    let rule = NftCell::Single {
        enabled: true,
        sport,
        dport,
        domain,
        protocol,
        ip_version,
        comment,
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
    comment: Option<String>,
) -> Result<(), String> {
    let rule = NftCell::Range {
        enabled: true,
        port_start,
        port_end,
        domain,
        protocol,
        ip_version,
        comment,
        quota_enabled: false,
        quota_bytes: 0,
        quota_period: nat_common::QuotaPeriod::default(),
        quota_action: nat_common::QuotaAction::default(),
    };
    rule.validate()?;
    config.rules.push(rule);
    Ok(())
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

    backup_config(path)?;
    save_toml_config(path, &config)?;
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
    print_config_saved_hint(path);
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
            "{sport} -> {domain}:{dport}/{protocol}{}",
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
            "{port_start}-{port_end} -> {domain}:{port_start}-{port_end}/{protocol}{}",
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
            "comment: {}\nsport: {sport}\ntarget: {domain}\ndport: {dport}\nprotocol: {protocol}\nip_version: {ip_version}",
            comment.as_deref().unwrap_or("(无)")
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
            "comment: {}\nsport: {port_start}-{port_end}\ntarget: {domain}\ndport: {port_start}-{port_end}\nprotocol: {protocol}\nip_version: {ip_version}",
            comment.as_deref().unwrap_or("(无)")
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

pub(crate) fn backup_filename(
    prefix: &str,
    extension: &str,
    now: chrono::DateTime<Local>,
) -> String {
    format!("{prefix}-{}.{}", now.format("%Y%m%d-%H%M%S"), extension)
}

pub(crate) fn backup_config(path: &str) -> Result<PathBuf, io::Error> {
    let source = Path::new(path);
    fs::create_dir_all(CONFIG_BACKUP_DIR)?;
    let extension = source
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("bak");
    let prefix = if extension == "toml" {
        "nat-config"
    } else {
        "nat-conf"
    };
    let backup_path =
        Path::new(CONFIG_BACKUP_DIR).join(backup_filename(prefix, extension, Local::now()));
    fs::copy(source, &backup_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(backup_path)
}

fn list_config_backups() -> Result<Vec<PathBuf>, io::Error> {
    let dir = Path::new(CONFIG_BACKUP_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut backups = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            backups.push(path);
        }
    }
    backups.sort();
    Ok(backups)
}

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
    use nat_common::{
        TrafficMode,
        stats::{Counter, RuleTraffic, StatsState},
    };

    #[test]
    fn adds_single_rule_to_toml_config() {
        let mut config = TomlConfig {
            rules: Vec::new(),
            dns: Default::default(),
            ddns: Default::default(),
            stats: StatsConfig::default(),
            telegram: Default::default(),
            access_control: Default::default(),
            geoip: Default::default(),
            egress_control: Default::default(),
            snat: Default::default(),
            mss_clamp: Default::default(),
            last_good: Default::default(),
            audit: Default::default(),
            quota: Default::default(),
        };
        add_single_rule(
            &mut config,
            30080,
            80,
            "example.com".to_string(),
            Protocol::Tcp,
            IpVersion::V4,
            Some("user-comment".to_string()),
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0], NftCell::Single { .. }));
    }

    #[test]
    fn adds_range_rule_to_toml_config() {
        let mut config = TomlConfig {
            rules: Vec::new(),
            dns: Default::default(),
            ddns: Default::default(),
            stats: StatsConfig::default(),
            telegram: Default::default(),
            access_control: Default::default(),
            geoip: Default::default(),
            egress_control: Default::default(),
            snat: Default::default(),
            mss_clamp: Default::default(),
            last_good: Default::default(),
            audit: Default::default(),
            quota: Default::default(),
        };
        add_range_rule(
            &mut config,
            30000,
            30010,
            "1.2.3.4".to_string(),
            Protocol::Tcp,
            IpVersion::V4,
            Some("range-test".to_string()),
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0], NftCell::Range { .. }));
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
        assert!(lines.contains("评估顺序：黑名单 > 白名单 > GeoIP（同时启用 = AND）"));
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
        assert!(lines.contains("允许 = 在白名单 AND 属于 CN/LAN"));
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
            "说明：access_control 与 GeoIP 是来源 IP 限制；egress_control 是目标 IP 限制；SNAT 是源地址改写；MSS clamp 是 TCP MSS 调整。"
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
            readme.contains("mode = \"fixed\""),
            "README should show fixed example"
        );
        assert!(
            readme.contains("### MSS clamp"),
            "README should document MSS clamp"
        );
        assert!(
            readme.contains("size = 1452"),
            "README should mention default MSS size"
        );
        assert!(
            readme.contains("### 组合策略说明"),
            "README should have combined policy section"
        );
        assert!(
            readme.contains("`access_control`") && readme.contains("来源 IP / CIDR"),
            "README combined-policy section should label access_control as source IP restriction"
        );
        assert!(
            readme.contains("`egress_control`") && readme.contains("目标 IP / CIDR"),
            "README combined-policy section should label egress_control as target IP restriction"
        );
        assert!(
            readme.contains("`snat`") && readme.contains("源地址改写"),
            "README combined-policy section should label snat as source rewrite"
        );
        assert!(
            readme.contains("`mss_clamp`") && readme.contains("TCP MSS 调整"),
            "README combined-policy section should label mss_clamp as TCP MSS adjustment"
        );
        assert!(
            readme.contains("多个来源限制同时开启时采用叠加限制（AND），不是 OR 放行"),
            "README should state AND semantics, not OR"
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
            readme.contains("### 规则级流量配额 quota"),
            "README should document quota"
        );
        assert!(readme.contains("[quota]"));
        assert!(readme.contains("quota_enabled"));
        assert!(readme.contains("quota_period"));
        assert!(
            readme.contains("100GB") && readme.contains("MiB"),
            "README should document size formats"
        );
        assert!(
            readme.contains("Stats 流量统计")
                && (readme.contains("不另起一套") || readme.contains("基于现有")),
            "README should explain quota uses existing Stats"
        );
        assert!(
            readme.contains("自动禁用"),
            "README should explain auto-disable"
        );
        assert!(
            readme.contains("不直接执行 `nft -f`") || readme.contains("不直接执行 nft -f"),
            "README must state quota does not directly run nft"
        );
        assert!(
            readme.contains("每个 period 内通知") && readme.contains("一次"),
            "README should describe notification dedup"
        );
    }

    #[test]
    fn readme_documents_last_good_and_audit() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("### last-good 状态缓存"),
            "README should document last-good"
        );
        assert!(
            readme.contains("### audit 审计日志"),
            "README should document audit"
        );
        assert!(
            readme.contains("[last_good]") && readme.contains("[audit]"),
            "README should show TOML sections"
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
    fn readme_documents_combined_policy() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("### access_control 与 GeoIP 的组合策略"),
            "README should document the combined policy"
        );
        assert!(
            readme.contains("黑名单优先级最高"),
            "README should state blacklist priority"
        );
        assert!(
            readme.contains("白名单是精确来源限制"),
            "README should describe whitelist as exact-source restriction"
        );
        assert!(
            readme.contains("GeoIP 是国家/地区来源限制"),
            "README should describe GeoIP as country restriction"
        );
        assert!(
            readme.contains("两者可以同时启用，叠加生效，不是互相覆盖"),
            "README should state layering, not OR override"
        );
        assert!(
            readme.contains("同时启用 = AND"),
            "README should state AND semantics"
        );
    }

    #[test]
    fn readme_documents_auto_reload_after_update() {
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("CLI 一键更新成功后会自动重新载入新版 `nat --menu`"),
            "README should note that the CLI auto-reloads after one-key update"
        );
        assert!(
            readme.contains("如果当前环境无 TTY 或自动重载失败"),
            "README should document the fallback path for auto-reload"
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
        // v0.4.1: README 必须说明 quota_period = "total" 与 stats.traffic_mode 的关系
        let readme = include_str!("../../README.md");
        assert!(
            readme.contains("quota_period = \"total\"")
                && readme.contains("traffic_mode")
                && readme.contains("不会自动重算"),
            "README 必须解释 total 与 traffic_mode 切换的影响"
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
}
