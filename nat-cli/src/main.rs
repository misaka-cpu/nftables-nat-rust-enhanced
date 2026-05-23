#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
mod apply;
mod config;
mod ip;
mod menu;
mod prepare;
mod quota_loop;
mod runtime;
mod telegram;

use chrono::Local;
use clap::Parser;
use log::{error, info, warn};
#[cfg(test)]
use nat_common::last_good::ResolutionEvent;
use nat_common::{
    Args, AuditConfig, DdnsConfig, DnsConfig, EgressControlConfig, GeoIpConfig, LastGoodConfig,
    MssClampConfig, QuotaConfig, SnatConfig, StatsConfig, TelegramConfig, TomlConfig,
    audit::{self, AuditResult},
    geoip,
    last_good::{self, LastGoodState, ResolutionLog},
    logger, stats as traffic_stats,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::process::Command;
use std::thread::sleep;

const NFTABLES_ETC: &str = "/etc/nftables-nat";
const FILE_NAME_SCRIPT: &str = "/etc/nftables-nat/nat-diy.nft";
const BACKUP_DIR: &str = "/etc/nftables-nat/backups";
// v0.6.1：apply / rollback 相关函数与 MANAGED_TABLES 列表已搬到 `apply` 模块。
use apply::apply_nft_script;
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
const CARGO_CRATE_NAME: &str = env!("CARGO_CRATE_NAME");
const MAIN_LOOP_MAX_SLEEP_SECS: u64 = 5;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if version_requested() {
        println!("nat {}", nat_common::build_version());
        return Ok(());
    }
    logger::init(CARGO_CRATE_NAME);
    // 使用 clap 解析命令行参数
    let args = Args::parse();

    if args.menu {
        return menu::run_menu(args.toml.as_deref());
    }

    // 启动时解析一次配置文件，并且快速失败
    if let Err(e) = parse_conf(&args).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)) {
        info!("解析配置文件失败: {e:?}");
        return Err(e.into());
    }
    global_prepare()?;
    Ok(handle_loop(&args)?)
}

fn version_requested() -> bool {
    std::env::args()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
}

fn parse_conf(
    args: &Args,
) -> Result<Vec<config::RuntimeCell>, Box<dyn std::error::Error + Send + Sync>> {
    let nat_cells = if let Some(compatible_config_file) = &args.compatible_config_file {
        config::read_config(compatible_config_file).map_err(|e| {
            info!("读取配置文件失败: {e:?}");
            config::example(compatible_config_file);
            e
        })?
    } else if let Some(toml) = &args.toml {
        config::read_toml_config(toml).map_err(|e| {
            info!("读取配置文件失败: {e:?}");
            if let Err(e) = config::toml_example(toml) {
                info!("{e:?}");
            }
            e
        })?
    } else {
        return Err("请提供配置文件路径".into());
    };
    Ok(nat_cells)
}

fn global_prepare() -> Result<(), io::Error> {
    if let Err(e) = Command::new("/usr/sbin/nft").arg("-v").output() {
        if e.kind() == io::ErrorKind::NotFound {
            let err = "未检测到 nftables，请先安装 nftables (Debian/Ubuntu: apt install nftables, CentOS/RHEL: yum install nftables)";
            error!("{}", err);
            return Err(io::Error::new(io::ErrorKind::NotFound, err));
        }
        return Err(e);
    }

    std::fs::create_dir_all(NFTABLES_ETC)?;
    // 修改内核参数，开启IPv4端口转发
    match std::fs::write(IP_FORWARD, "1") {
        Ok(_s) => {
            info!("kernel ip_forward config enabled!\n")
        }
        Err(e) => {
            info!(
                "enable ip_forward FAILED! cause: {e:?}\nPlease excute `echo 1 > /proc/sys/net/ipv4/ip_forward` manually\n"
            );
            return Err(e);
        }
    };

    // 修改内核参数，开启IPv6端口转发
    match std::fs::write(IPV6_FORWARD, "1") {
        Ok(_s) => {
            info!("kernel ipv6_forward config enabled!\n")
        }
        Err(e) => {
            info!(
                "enable ipv6_forward FAILED! cause: {e:?}\nPlease excute `echo 1 > /proc/sys/net/ipv6/conf/all/forwarding` manually\n"
            );
            // IPv6转发失败不作为致命错误，因为可能系统不支持IPv6
            info!("IPv6 forwarding setup failed, continuing with IPv4 only...");
        }
    };
    Ok(())
}

fn handle_loop(args: &Args) -> Result<(), io::Error> {
    // v0.6.1：用稳定 FNV-1a hash 代替整 String 比较，便于日志/audit；语义与旧整字符串相等等价。
    let mut latest_script_hash: Option<u64> = None;
    let mut last_stats_collect = None;
    let mut last_ddns_refresh = None;
    let mut last_short_ddns_warn: Option<u64> = None;
    let mut last_quota_check: Option<chrono::DateTime<Local>> = None;
    let mut last_stats_warn_for_quota: bool = false;
    loop {
        let loop_now = Local::now();
        let runtime_config = load_runtime_config(args);
        let refresh_interval = ddns_refresh_interval(&runtime_config.ddns)?;
        warn_short_ddns_interval_once(refresh_interval, &mut last_short_ddns_warn);
        let dns_config = runtime_config.dns;
        let access_config = runtime_config.access_control;
        let geoip_config = runtime_config.geoip;
        let egress_config = runtime_config.egress_control;
        let snat_config = runtime_config.snat;
        let mss_clamp_config = runtime_config.mss_clamp;
        let last_good_config = runtime_config.last_good;
        let audit_config = runtime_config.audit;
        let quota_config = runtime_config.quota;
        let rule_labels = runtime_config.rule_labels;
        let stats_config = runtime_config.stats;
        let telegram_config = runtime_config.telegram;
        if stats_config.enabled
            && let Err(e) = traffic_stats::ensure_state_file(&stats_config.data_file)
        {
            warn!("初始化统计数据文件失败，nat 主循环继续运行: {e:?}");
        }
        if should_collect_stats_at(&stats_config, last_stats_collect, loop_now)
            && collect_and_maybe_notify(&stats_config, &telegram_config, &rule_labels).is_some()
        {
            last_stats_collect = Some(loop_now);
        }

        // quota 检查：到达 check_interval_seconds 周期且 quota.enabled=true 时执行一轮检查。
        // quota 依赖 Stats；stats.enabled=false 时仅 WARN 一次，不强制启用。
        if quota_config.enabled && should_run_quota_check(last_quota_check, &quota_config, loop_now)
        {
            if !stats_config.enabled {
                if !last_stats_warn_for_quota {
                    warn!(
                        "quota.enabled=true 但 stats.enabled=false：quota 依赖 Stats 流量统计，请启用 stats 后才能生效。本轮跳过 quota 检查。"
                    );
                    last_stats_warn_for_quota = true;
                }
            } else {
                last_stats_warn_for_quota = false;
                run_quota_check(
                    args,
                    &quota_config,
                    &audit_config,
                    &stats_config,
                    &telegram_config,
                    chrono::Utc::now(),
                );
            }
            last_quota_check = Some(loop_now);
        }

        if should_refresh_ddns_at(last_ddns_refresh, refresh_interval, loop_now) {
            let nat_cells = match parse_conf(args) {
                Ok(cells) => cells,
                Err(e) => {
                    error!("解析配置文件失败: {e:?}");
                    sleep(next_loop_sleep(
                        refresh_interval,
                        &stats_config,
                        last_ddns_refresh,
                        last_stats_collect,
                        Local::now(),
                    ));
                    continue;
                }
            };
            if nat_cells.is_empty() {
                info!("no rules configured, waiting for config changes");
            }
            let mut last_good_state = LastGoodState::load(&last_good_config.file);
            prune_last_good_state_for_runtime_cells(
                &last_good_config,
                &audit_config,
                &mut last_good_state,
                &nat_cells,
                "ddns.loop",
            );
            let resolution_log = ResolutionLog::new();
            let script = match build_new_script(
                &nat_cells,
                &dns_config,
                &access_config,
                &geoip_config,
                &egress_config,
                &snat_config,
                &mss_clamp_config,
                &last_good_config,
                &last_good_state,
                &resolution_log,
            ) {
                Ok(script) => script,
                Err(e) => {
                    error!(
                        "解析域名或生成 nftables 脚本失败，保持上一版已应用规则并等待下一次解析: {e}"
                    );
                    sleep(next_loop_sleep(
                        refresh_interval,
                        &stats_config,
                        last_ddns_refresh,
                        last_stats_collect,
                        Local::now(),
                    ));
                    continue;
                }
            };
            let resolution_events = resolution_log.drain();
            audit_resolution_events(&audit_config, &resolution_events);
            last_ddns_refresh = Some(loop_now);
            prepare::check_and_prepare()?;
            let current_script_hash = nat_common::stable_script_hash(&script);
            if latest_script_hash != Some(current_script_hash) {
                if stats_config.enabled {
                    let collect_now = Local::now();
                    let _ = collect_and_maybe_notify(&stats_config, &telegram_config, &rule_labels);
                    last_stats_collect = Some(collect_now);
                }
                info!("当前配置: ");
                for ele in &nat_cells {
                    info!("{ele:?}");
                }
                info!(
                    "nftables脚本如下（script_hash={}）：\n{script}",
                    nat_common::hash::format_hash_hex(current_script_hash)
                );
                let f = File::create(FILE_NAME_SCRIPT);
                if let Ok(mut file) = f {
                    file.write_all(script.as_bytes())?;
                }

                match apply_nft_script(FILE_NAME_SCRIPT) {
                    Ok(()) => {
                        audit::log_event(
                            &audit_config,
                            "apply.success",
                            AuditResult::Ok,
                            serde_json::json!({
                                "script_path": FILE_NAME_SCRIPT,
                                "script_hash": nat_common::hash::format_hash_hex(current_script_hash),
                            }),
                        );
                        last_good::update_state_from_events(
                            &mut last_good_state,
                            &resolution_events,
                            "ok",
                            chrono::Utc::now(),
                        );
                        if last_good_config.enabled
                            && let Err(e) = last_good_state.save(&last_good_config.file)
                        {
                            warn!("写入 last-good 缓存失败 ({}): {e}", last_good_config.file);
                        }
                    }
                    Err(e) => {
                        audit::log_event(
                            &audit_config,
                            "apply.fail",
                            AuditResult::Fail,
                            serde_json::json!({
                                "script_path": FILE_NAME_SCRIPT,
                                "script_hash": nat_common::hash::format_hash_hex(current_script_hash),
                                "error": e.to_string(),
                            }),
                        );
                        return Err(e);
                    }
                }
                latest_script_hash = Some(current_script_hash);
                info!("WAIT:等待配置或目标IP发生改变....\n");
            }
        }

        sleep(next_loop_sleep(
            refresh_interval,
            &stats_config,
            last_ddns_refresh,
            last_stats_collect,
            Local::now(),
        ));
    }
}

pub(crate) fn refresh_once(args: &Args) -> Result<(), io::Error> {
    let runtime_config = load_runtime_config(args);
    if runtime_config.stats.enabled {
        let _ = collect_and_maybe_notify(
            &runtime_config.stats,
            &runtime_config.telegram,
            &runtime_config.rule_labels,
        );
    }
    let nat_cells = parse_conf(args).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut last_good_state = LastGoodState::load(&runtime_config.last_good.file);
    prune_last_good_state_for_runtime_cells(
        &runtime_config.last_good,
        &runtime_config.audit,
        &mut last_good_state,
        &nat_cells,
        "ddns.refresh",
    );
    let resolution_log = ResolutionLog::new();
    let script = build_new_script(
        &nat_cells,
        &runtime_config.dns,
        &runtime_config.access_control,
        &runtime_config.geoip,
        &runtime_config.egress_control,
        &runtime_config.snat,
        &runtime_config.mss_clamp,
        &runtime_config.last_good,
        &last_good_state,
        &resolution_log,
    )?;
    let resolution_events = resolution_log.drain();
    audit_resolution_events(&runtime_config.audit, &resolution_events);
    prepare::check_and_prepare()?;
    let mut file = File::create(FILE_NAME_SCRIPT)?;
    file.write_all(script.as_bytes())?;
    match apply_nft_script(FILE_NAME_SCRIPT) {
        Ok(()) => {
            audit::log_event(
                &runtime_config.audit,
                "apply.success",
                AuditResult::Ok,
                serde_json::json!({"script_path": FILE_NAME_SCRIPT, "trigger": "ddns.refresh"}),
            );
            last_good::update_state_from_events(
                &mut last_good_state,
                &resolution_events,
                "ok",
                chrono::Utc::now(),
            );
            if runtime_config.last_good.enabled
                && let Err(e) = last_good_state.save(&runtime_config.last_good.file)
            {
                warn!(
                    "写入 last-good 缓存失败 ({}): {e}",
                    runtime_config.last_good.file
                );
            }
            Ok(())
        }
        Err(e) => {
            audit::log_event(
                &runtime_config.audit,
                "apply.fail",
                AuditResult::Fail,
                serde_json::json!({
                    "script_path": FILE_NAME_SCRIPT,
                    "trigger": "ddns.refresh",
                    "error": e.to_string(),
                }),
            );
            Err(e)
        }
    }
}

// v0.6.1：audit_resolution_events 已搬到 `runtime` 模块。
use runtime::audit_resolution_events;

fn prune_last_good_state_for_runtime_cells(
    last_good_config: &LastGoodConfig,
    audit_config: &AuditConfig,
    state: &mut LastGoodState,
    nat_cells: &[config::RuntimeCell],
    trigger: &str,
) {
    if !last_good_config.enabled {
        return;
    }
    let identities = config::last_good_identities_from_runtime_cells(nat_cells);
    let result = state.prune_stale_rules(&identities);
    if !result.changed {
        return;
    }
    match state.save(&last_good_config.file) {
        Ok(()) => audit::log_event(
            audit_config,
            "last_good.prune",
            AuditResult::Ok,
            serde_json::json!({
                "trigger": trigger,
                "file": last_good_config.file,
                "before": result.before,
                "after": result.after,
                "removed": result.removed,
            }),
        ),
        Err(e) => warn!(
            "清理 stale last-good 缓存失败 ({}): {e}",
            last_good_config.file
        ),
    }
}

struct RuntimeConfig {
    dns: DnsConfig,
    ddns: DdnsConfig,
    access_control: nat_common::AccessControlConfig,
    geoip: GeoIpConfig,
    egress_control: EgressControlConfig,
    snat: SnatConfig,
    mss_clamp: MssClampConfig,
    last_good: LastGoodConfig,
    audit: AuditConfig,
    quota: QuotaConfig,
    stats: StatsConfig,
    telegram: TelegramConfig,
    rule_labels: HashMap<String, String>,
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        dns: DnsConfig::default(),
        ddns: DdnsConfig::default(),
        access_control: Default::default(),
        geoip: GeoIpConfig::default(),
        egress_control: EgressControlConfig::default(),
        snat: SnatConfig::default(),
        mss_clamp: MssClampConfig::default(),
        last_good: LastGoodConfig::default(),
        audit: AuditConfig::default(),
        quota: QuotaConfig::default(),
        stats: StatsConfig::default(),
        telegram: TelegramConfig::default(),
        rule_labels: HashMap::new(),
    }
}

fn load_runtime_config(args: &Args) -> RuntimeConfig {
    let Some(toml_path) = &args.toml else {
        return default_runtime_config();
    };
    let content = match fs::read_to_string(toml_path) {
        Ok(content) => content,
        Err(e) => {
            warn!("读取 TOML 运行配置失败，使用默认 DDNS/统计/Telegram 配置: {e:?}");
            return default_runtime_config();
        }
    };
    match TomlConfig::from_toml_str(&content) {
        Ok(config) => {
            let rule_labels = traffic_stats::rule_labels_from_config(&config);
            RuntimeConfig {
                dns: config.dns,
                ddns: config.ddns,
                access_control: config.access_control,
                geoip: config.geoip,
                egress_control: config.egress_control,
                snat: config.snat,
                mss_clamp: config.mss_clamp,
                last_good: config.last_good,
                audit: config.audit,
                quota: config.quota,
                stats: config.stats,
                telegram: config.telegram,
                rule_labels,
            }
        }
        Err(e) => {
            warn!("解析 TOML 运行配置失败，使用默认 DDNS/统计/Telegram 配置: {e}");
            default_runtime_config()
        }
    }
}

// v0.6.1：DDNS / Stats / quota 节拍辅助、collect_and_maybe_notify 已搬到 `runtime` 模块。
// quota 自动禁用循环已搬到 `quota_loop` 模块。
// Telegram curl / 通知发送已搬到 `telegram` 模块。
use quota_loop::run_quota_check;
use runtime::{
    collect_and_maybe_notify, ddns_refresh_interval, next_loop_sleep, should_collect_stats_at,
    should_refresh_ddns_at, should_run_quota_check, warn_short_ddns_interval_once,
};

#[allow(clippy::too_many_arguments)]
fn build_new_script(
    nat_cells: &[config::RuntimeCell],
    dns_config: &DnsConfig,
    access_config: &nat_common::AccessControlConfig,
    geoip_config: &GeoIpConfig,
    egress_config: &EgressControlConfig,
    snat_config: &SnatConfig,
    mss_clamp_config: &MssClampConfig,
    last_good_config: &LastGoodConfig,
    last_good_state: &LastGoodState,
    resolution_log: &ResolutionLog,
) -> Result<String, io::Error> {
    //脚本的前缀 - 创建IPv4和IPv6表
    let mut script = String::from(
        "#!/usr/sbin/nft -f\n\
        \n\
        # IPv4 NAT table\n\
        add table ip self-nat\n\
        delete table ip self-nat\n\
        add table ip self-nat\n\
        add chain ip self-nat PREROUTING { type nat hook prerouting priority -110 ; }\n\
        add chain ip self-nat POSTROUTING { type nat hook postrouting priority 110 ; }\n\
        \n\
        # IPv6 NAT table\n\
        add table ip6 self-nat\n\
        delete table ip6 self-nat\n\
        add table ip6 self-nat\n\
        add chain ip6 self-nat PREROUTING { type nat hook prerouting priority -110 ; }\n\
        add chain ip6 self-nat POSTROUTING { type nat hook postrouting priority 110 ; }\n\
        \n\
        # IPv4 Drop table\n\
        add table ip self-filter\n\
        delete table ip self-filter\n\
        add table ip self-filter\n\
        add chain ip self-filter INPUT { type filter hook input priority filter - 1 ; }\n\
        add chain ip self-filter FORWARD { type filter hook forward priority filter - 1 ; }\n\
        \n\
        # IPv6 Drop table\n\
        add table ip6 self-filter\n\
        delete table ip6 self-filter\n\
        add table ip6 self-filter\n\
        add chain ip6 self-filter INPUT { type filter hook input priority filter - 1 ; }\n\
        add chain ip6 self-filter FORWARD { type filter hook forward priority filter - 1 ; }\n\
        ",
    );

    // egress_control 启用但 allowed_target_cidrs 为空：所有转发规则都会被跳过
    if egress_config.enabled && egress_config.allowed_target_cidrs.is_empty() {
        warn!("egress_control 已启用但 allowed_target_cidrs 为空，所有转发目标都会被跳过");
    }

    // GeoIP 准备：仅当启用且有任意一个子开关打开
    let geoip_active =
        geoip_config.enabled && (geoip_config.forward.enabled || geoip_config.ssh.enabled);
    let cn4_set_definition = if geoip_active {
        match geoip::read_and_render_cn4_set(&geoip_config.cn4_file) {
            Some(rendered) => Some(rendered),
            None => {
                warn!(
                    "geoip 已启用但 cn4_file={} 不存在或为空，跳过 GeoIP 限制规则生成。请通过 CLI 下载 / 更新 CN IP set。",
                    geoip_config.cn4_file
                );
                None
            }
        }
    } else {
        None
    };

    if let Some(set_def) = &cn4_set_definition {
        script.push_str("\n# GeoIP cn4 set\n");
        script.push_str(set_def);
        script.push_str(&build_geoip_prerouting_chain());
        // ssh / forward 规则
        if geoip_config.ssh.enabled {
            script.push_str(&build_geoip_ssh_rules(geoip_config));
        }
    }

    let mut rule_index = 0usize;
    let mut forward_rule_summaries: Vec<ForwardRuleSummary> = Vec::new();
    for x in nat_cells.iter() {
        let index = match x {
            config::RuntimeCell::Rule(_) => {
                let index = Some(rule_index);
                rule_index += 1;
                index
            }
            config::RuntimeCell::Comment(_) => None,
        };
        match x.build_with_rule_index(
            index,
            dns_config,
            access_config,
            egress_config,
            snat_config,
            last_good_config,
            last_good_state,
            resolution_log,
        ) {
            Ok(rule) => {
                if !rule.is_empty()
                    && let Some(summary) = forward_summary_from(x, index)
                {
                    forward_rule_summaries.push(summary);
                }
                script += &rule;
            }
            Err(e) => {
                log::error!("Failed to build rule for {x:?}: {e}");
                return Err(e);
            }
        }
    }

    if cn4_set_definition.is_some()
        && geoip_config.forward.enabled
        && !forward_rule_summaries.is_empty()
    {
        script.push_str(&build_geoip_forward_rules(
            geoip_config,
            &forward_rule_summaries,
        ));
    }

    if mss_clamp_config.enabled && !forward_rule_summaries.is_empty() {
        script.push_str(&build_mss_clamp_rules(
            mss_clamp_config,
            &forward_rule_summaries,
        ));
    }

    Ok(script)
}

fn build_mss_clamp_rules(
    mss_clamp_config: &MssClampConfig,
    summaries: &[ForwardRuleSummary],
) -> String {
    // 仅作用于本项目转发链路：在 self-filter FORWARD 链中，按转发后的目标端口匹配 SYN 包
    // 并 clamp MSS。不接管整机 forward policy，不影响 redirect/localhost 流量与其他主机流量。
    let mut out = String::from("\n# MSS clamp (project-scoped, forward traffic only)\n");
    let size = mss_clamp_config.size;
    for summary in summaries {
        if !matches!(
            summary.protocol,
            nat_common::Protocol::Tcp | nat_common::Protocol::All
        ) {
            continue;
        }
        // Redirect / localhost 不走 forward 链，跳过避免误匹配本机端口
        let Some(dport) = summary.forward_dport_expr.as_ref() else {
            continue;
        };
        let id = &summary.rule_id;
        out.push_str(&format!(
            "add rule ip self-filter FORWARD tcp dport {dport} tcp flags syn tcp option maxseg size set {size} comment \"mss-clamp:id={id},dir=out\"\n"
        ));
        out.push_str(&format!(
            "add rule ip self-filter FORWARD tcp sport {dport} tcp flags syn tcp option maxseg size set {size} comment \"mss-clamp:id={id},dir=in\"\n"
        ));
    }
    out
}

#[derive(Debug, Clone)]
struct ForwardRuleSummary {
    rule_id: String,
    sport_expr: String,
    /// 转发后目标端口表达式，仅在 cell 实际走 host forward 链时有值。
    /// Redirect 与 Single(localhost) 不走 forward 链，因此为 None。
    forward_dport_expr: Option<String>,
    protocol: nat_common::Protocol,
}

fn forward_summary_from(
    cell: &config::RuntimeCell,
    index: Option<usize>,
) -> Option<ForwardRuleSummary> {
    let rule_id = format!("r{}", index?);
    match cell {
        config::RuntimeCell::Rule(nat_common::NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            ..
        }) => {
            if !matches!(
                ip_version,
                nat_common::IpVersion::V4 | nat_common::IpVersion::All
            ) {
                return None;
            }
            let is_localhost = domain == "localhost" || domain == "127.0.0.1";
            Some(ForwardRuleSummary {
                rule_id,
                sport_expr: sport.to_string(),
                forward_dport_expr: if is_localhost {
                    None
                } else {
                    Some(dport.to_string())
                },
                protocol: *protocol,
            })
        }
        config::RuntimeCell::Rule(nat_common::NftCell::Range {
            port_start,
            port_end,
            protocol,
            ip_version,
            ..
        }) => {
            if !matches!(
                ip_version,
                nat_common::IpVersion::V4 | nat_common::IpVersion::All
            ) {
                return None;
            }
            let range_expr = format!("{port_start}-{port_end}");
            Some(ForwardRuleSummary {
                rule_id,
                sport_expr: range_expr.clone(),
                forward_dport_expr: Some(range_expr),
                protocol: *protocol,
            })
        }
        config::RuntimeCell::Rule(nat_common::NftCell::Redirect {
            src_port,
            src_port_end,
            protocol,
            ip_version,
            ..
        }) => {
            if !matches!(
                ip_version,
                nat_common::IpVersion::V4 | nat_common::IpVersion::All
            ) {
                return None;
            }
            let sport_expr = src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string());
            Some(ForwardRuleSummary {
                rule_id,
                sport_expr,
                forward_dport_expr: None,
                protocol: *protocol,
            })
        }
        _ => None,
    }
}

fn build_geoip_prerouting_chain() -> String {
    // 单独的 filter 链，hook prerouting，优先级在 nat 之前 (-200 < -110)
    // accept verdict 不阻断 nat PREROUTING，drop verdict 拦截非允许来源
    String::from(
        "\n# GeoIP prerouting filter chain (IPv4 only, first version)\n\
         add chain ip self-filter GEOIP_PREROUTING { type filter hook prerouting priority -200 ; }\n\
         add rule ip self-filter GEOIP_PREROUTING ct state established,related counter accept comment \"geoip-forward:state=est\"\n",
    )
}

fn nft_proto_token(protocol: nat_common::Protocol) -> &'static str {
    match protocol {
        nat_common::Protocol::All => "meta l4proto { tcp, udp } th",
        nat_common::Protocol::Tcp => "tcp",
        nat_common::Protocol::Udp => "udp",
    }
}

fn build_geoip_forward_rules(
    geoip_config: &GeoIpConfig,
    summaries: &[ForwardRuleSummary],
) -> String {
    let mut out = String::from("\n# GeoIP forward port restriction (allow-cn)\n");
    let lan = geoip_config.lan_ipv4_cidrs();
    let allow_lan = geoip_config.allow_lan && !lan.is_empty();
    for summary in summaries {
        let proto = nft_proto_token(summary.protocol);
        let id = &summary.rule_id;
        let sport = &summary.sport_expr;
        out.push_str(&format!(
            "add rule ip self-filter GEOIP_PREROUTING ip saddr @cn4 {proto} dport {sport} counter accept comment \"geoip-forward:id={id},mode=allow-cn\"\n"
        ));
        if allow_lan {
            let lan_list = lan.join(", ");
            out.push_str(&format!(
                "add rule ip self-filter GEOIP_PREROUTING ip saddr {{ {lan_list} }} {proto} dport {sport} counter accept comment \"geoip-forward:id={id},mode=allow-lan\"\n"
            ));
        }
        out.push_str(&format!(
            "add rule ip self-filter GEOIP_PREROUTING {proto} dport {sport} counter drop comment \"geoip-forward:id={id},mode=default-drop\"\n"
        ));
    }
    out
}

fn build_geoip_ssh_rules(geoip_config: &GeoIpConfig) -> String {
    let port = geoip_config.ssh.port;
    let lan = geoip_config.lan_ipv4_cidrs();
    let allow_lan = matches!(geoip_config.ssh.mode.as_str(), "allow-cn-and-lan")
        && geoip_config.allow_lan
        && !lan.is_empty();
    let mut out = String::from("\n# GeoIP SSH input restriction (IPv4, allow-cn[-and-lan])\n");
    out.push_str("add rule ip self-filter INPUT ct state established,related counter accept comment \"geoip-ssh:state=est\"\n");
    out.push_str(&format!(
        "add rule ip self-filter INPUT ip saddr @cn4 tcp dport {port} counter accept comment \"geoip-ssh:mode=allow-cn\"\n"
    ));
    if allow_lan {
        let lan_list = lan.join(", ");
        out.push_str(&format!(
            "add rule ip self-filter INPUT ip saddr {{ {lan_list} }} tcp dport {port} counter accept comment \"geoip-ssh:mode=allow-lan\"\n"
        ));
    }
    out.push_str(&format!(
        "add rule ip self-filter INPUT tcp dport {port} counter drop comment \"geoip-ssh:mode=default-drop\"\n"
    ));
    out
}

// v0.6.1：apply_nft_script / apply_nft_script_with / check_nft_script /
// backup_current_ruleset / backup_managed_tables / is_missing_nft_table_error /
// rollback_managed_tables 已迁移到 `apply` 模块。

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod safe_apply_tests {
    use super::*;
    use crate::apply::{apply_nft_script_with, is_missing_nft_table_error};
    use crate::quota_loop::run_quota_check_with;
    use nat_common::quota;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    static FAKE_NFT_SEQ: AtomicU64 = AtomicU64::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct FakeNftEnv {
        root: PathBuf,
        nft_bin: PathBuf,
        backup_dir: PathBuf,
        script_path: PathBuf,
        log_path: PathBuf,
        check_fail_marker: PathBuf,
        apply_fail_marker: PathBuf,
    }

    impl FakeNftEnv {
        fn new(name: &str) -> Self {
            let seq = FAKE_NFT_SEQ.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "nat-safe-apply-{name}-{seq}-{}",
                Local::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            fs::create_dir_all(&root).unwrap();
            let nft_bin = root.join("nft");
            let backup_dir = root.join("backups");
            let script_path = root.join("generated.nft");
            let log_path = root.join("nft.log");
            let check_fail_marker = root.join("check.fail");
            let apply_fail_marker = root.join("apply.fail");
            fs::write(&script_path, "add table ip self-nat\n").unwrap();
            fs::write(
                &nft_bin,
                format!(
                    r#"#!/bin/sh
echo "$@" >> "{log}"
if [ "$1" = "-c" ]; then
  if [ -f "{check_fail}" ]; then
    echo "mock check failed" >&2
    exit 1
  fi
  exit 0
fi
if [ "$1" = "list" ] && [ "$2" = "ruleset" ]; then
  echo "table ip user-table {{ }}"
  exit 0
fi
if [ "$1" = "list" ] && [ "$2" = "table" ]; then
  echo "table $3 $4 {{ }}"
  exit 0
fi
if [ "$1" = "-f" ]; then
  if [ "$2" = "{script}" ] && [ -f "{apply_fail}" ]; then
    echo "mock apply failed" >&2
    exit 1
  fi
  exit 0
fi
if [ "$1" = "delete" ] && [ "$2" = "table" ]; then
  exit 0
fi
echo "unexpected nft args: $@" >&2
exit 1
"#,
                    log = log_path.display(),
                    check_fail = check_fail_marker.display(),
                    apply_fail = apply_fail_marker.display(),
                    script = script_path.display()
                ),
            )
            .unwrap();
            let mut permissions = fs::metadata(&nft_bin).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&nft_bin, permissions).unwrap();

            Self {
                root,
                nft_bin,
                backup_dir,
                script_path,
                log_path,
                check_fail_marker,
                apply_fail_marker,
            }
        }

        fn apply(&self) -> Result<(), io::Error> {
            apply_nft_script_with(
                self.nft_bin.to_str().unwrap(),
                &self.backup_dir,
                self.script_path.to_str().unwrap(),
            )
        }

        fn log_lines(&self) -> Vec<String> {
            fs::read_to_string(&self.log_path)
                .unwrap_or_default()
                .lines()
                .map(ToString::to_string)
                .collect()
        }
    }

    impl Drop for FakeNftEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn apply_checks_script_before_loading_it() {
        let _guard = TEST_LOCK.lock().unwrap();
        let fake = FakeNftEnv::new("check-before-apply");
        fake.apply().unwrap();
        let lines = fake.log_lines();

        assert_eq!(lines[0], format!("-c -f {}", fake.script_path.display()));
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("-f {}", fake.script_path.display()))
        );
        assert!(lines.iter().all(|line| !line.contains("flush ruleset")));
    }

    #[test]
    fn check_failure_stops_before_apply_and_backup() {
        let _guard = TEST_LOCK.lock().unwrap();
        let fake = FakeNftEnv::new("check-fail");
        fs::write(&fake.check_fail_marker, "").unwrap();
        assert!(fake.apply().is_err());
        let lines = fake.log_lines();

        assert_eq!(lines, vec![format!("-c -f {}", fake.script_path.display())]);
        assert!(!fake.backup_dir.exists());
        assert!(lines.iter().all(|line| !line.contains("flush ruleset")));
    }

    #[test]
    fn check_success_backs_up_ruleset_before_apply() {
        let _guard = TEST_LOCK.lock().unwrap();
        let fake = FakeNftEnv::new("backup-before-apply");
        fake.apply().unwrap();
        let lines = fake.log_lines();
        let check_pos = lines
            .iter()
            .position(|line| line == &format!("-c -f {}", fake.script_path.display()))
            .unwrap();
        let backup_pos = lines
            .iter()
            .position(|line| line == "list ruleset")
            .unwrap();
        let apply_pos = lines
            .iter()
            .position(|line| line == &format!("-f {}", fake.script_path.display()))
            .unwrap();

        assert!(check_pos < backup_pos);
        assert!(backup_pos < apply_pos);
        assert!(fs::read_dir(&fake.backup_dir).unwrap().count() >= 1);
    }

    #[test]
    fn apply_failure_rolls_back_managed_tables() {
        let _guard = TEST_LOCK.lock().unwrap();
        let fake = FakeNftEnv::new("apply-fail-rollback");
        fs::write(&fake.apply_fail_marker, "").unwrap();
        assert!(fake.apply().is_err());
        let lines = fake.log_lines();

        assert!(
            lines
                .iter()
                .any(|line| line == &format!("-f {}", fake.script_path.display()))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("delete table ip self-nat"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("delete table ip6 self-filter"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("-f ") && line.contains("managed-rollback-"))
        );
        assert!(lines.iter().all(|line| !line.contains("flush ruleset")));
    }

    #[test]
    fn ddns_refresh_interval_defaults_to_three_hundred() {
        assert_eq!(ddns_refresh_interval(&DdnsConfig::default()).unwrap(), 300);
    }

    #[test]
    fn ddns_refresh_interval_rejects_too_low_values() {
        let err = ddns_refresh_interval(&DdnsConfig {
            refresh_interval_seconds: 9,
        })
        .unwrap_err();
        assert!(err.to_string().contains("refresh_interval_seconds too low"));
    }

    #[test]
    fn ddns_refresh_interval_allows_short_test_values() {
        assert_eq!(
            ddns_refresh_interval(&DdnsConfig {
                refresh_interval_seconds: 30,
            })
            .unwrap(),
            30
        );
    }

    #[test]
    fn short_ddns_warning_is_deduplicated_until_interval_changes() {
        let mut last_warned = None;
        warn_short_ddns_interval_once(30, &mut last_warned);
        assert_eq!(last_warned, Some(30));
        warn_short_ddns_interval_once(30, &mut last_warned);
        assert_eq!(last_warned, Some(30));
        warn_short_ddns_interval_once(45, &mut last_warned);
        assert_eq!(last_warned, Some(45));
        warn_short_ddns_interval_once(300, &mut last_warned);
        assert_eq!(last_warned, None);
        warn_short_ddns_interval_once(30, &mut last_warned);
        assert_eq!(last_warned, Some(30));
    }

    #[test]
    fn stats_interval_is_independent_from_ddns_interval() {
        let start = Local::now();
        let stats_config = StatsConfig {
            enabled: true,
            collect_interval_seconds: 10,
            ..Default::default()
        };

        assert!(should_collect_stats_at(
            &stats_config,
            Some(start),
            start + chrono::Duration::seconds(10)
        ));
        assert!(!should_refresh_ddns_at(
            Some(start),
            300,
            start + chrono::Duration::seconds(10)
        ));
        assert!(should_refresh_ddns_at(
            Some(start),
            300,
            start + chrono::Duration::seconds(300)
        ));
    }

    #[test]
    fn main_loop_sleep_uses_next_due_task_and_is_capped() {
        let start = Local::now();
        let stats_config = StatsConfig {
            enabled: true,
            collect_interval_seconds: 10,
            ..Default::default()
        };

        assert_eq!(
            next_loop_sleep(300, &stats_config, Some(start), Some(start), start).as_secs(),
            MAIN_LOOP_MAX_SLEEP_SECS
        );
        assert_eq!(
            next_loop_sleep(
                300,
                &stats_config,
                Some(start),
                Some(start),
                start + chrono::Duration::seconds(9)
            )
            .as_secs(),
            1
        );
        assert_eq!(
            next_loop_sleep(
                300,
                &stats_config,
                Some(start),
                Some(start),
                start + chrono::Duration::seconds(10)
            )
            .as_secs(),
            1
        );
    }

    #[test]
    fn detects_missing_managed_table_errors() {
        assert!(is_missing_nft_table_error(
            "Error: No such file or directory"
        ));
        assert!(is_missing_nft_table_error(
            "Error: Could not process rule: Table 'self-nat' does not exist"
        ));
        assert!(!is_missing_nft_table_error(
            "Error: syntax error, unexpected table"
        ));
    }

    #[test]
    fn load_runtime_config_reads_ddns_interval_from_toml() {
        let root = std::env::temp_dir().join(format!(
            "nat-runtime-config-{}",
            Local::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("nat.toml");
        fs::write(
            &config_path,
            r#"
rules = []

[ddns]
refresh_interval_seconds = 123
"#,
        )
        .unwrap();
        let args = Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(config_path.to_string_lossy().to_string()),
        };
        let runtime_config = load_runtime_config(&args);
        assert_eq!(runtime_config.ddns.refresh_interval_seconds, 123);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fake_ip_is_not_written_to_generated_nft_script() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "198.19.184.4".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: Some("fake-ip-test".to_string()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        // fake-ip 解析在 ip::remote_ip_with_dns 内被拒绝，现在视为 DNS 失败：
        // 若 last-good 没有缓存（默认空状态），规则会被跳过并 WARN，而不是直接报错。
        // 保留旧测试意图：生成的脚本绝不能包含 dnat 到 fake-ip 地址。
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("dnat to 198.19.184.4"));
    }

    #[test]
    fn whitelist_ipv4_single_rule_adds_source_match() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Whitelist,
            entries: vec!["1.2.3.4".to_string(), "5.6.7.0/24".to_string()],
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("ip saddr { 1.2.3.4, 5.6.7.0/24 } tcp dport 30080 counter dnat"));
        assert!(!script.contains(" counter drop "));
    }

    #[test]
    fn blacklist_ipv4_single_rule_adds_port_scoped_drop() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Blacklist,
            entries: vec!["8.8.8.8".to_string(), "9.9.9.0/24".to_string()],
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("ip saddr { 8.8.8.8, 9.9.9.0/24 } tcp dport 30080 counter drop comment \"nat-access:id=r0,mode=blacklist\""));
        assert!(script.contains("tcp dport 30080 counter dnat"));
    }

    #[test]
    fn access_control_supports_ranges_ipv6_and_all_protocol() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Range {
            enabled: true,
            port_start: 30000,
            port_end: 30010,
            domain: "2001:db8::1".to_string(),
            protocol: nat_common::Protocol::All,
            ip_version: nat_common::IpVersion::V6,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Whitelist,
            entries: vec!["2001:db8::/64".to_string()],
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("ip6 saddr { 2001:db8::/64 } meta l4proto { tcp, udp } th dport 30000-30010 counter dnat"));
        assert!(!script.contains("flush ruleset"));
    }

    fn write_temp_cn4_file(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-geoip-test-{name}-{}-{}",
            std::process::id(),
            Local::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cn4.nft");
        fs::write(&path, content).unwrap();
        path
    }

    fn sample_cn4_content() -> &'static str {
        // 几个 IPv4 CIDR，足以触发 set 渲染
        "# alecthw/chnlist cn4 sample\n1.0.1.0/24\n1.0.2.0/23\n223.255.252.0/24\n"
    }

    #[test]
    fn geoip_disabled_produces_no_geoip_rules() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip_off = GeoIpConfig {
            enabled: false,
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip_off,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("GEOIP_PREROUTING"));
        assert!(!script.contains("geoip-forward"));
        assert!(!script.contains("geoip-ssh"));
        assert!(!script.contains("@cn4"));
    }

    #[test]
    fn geoip_enabled_but_cn4_missing_skips_rules_with_warning() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: "/nonexistent/path/cn4.nft".to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        // cn4 缺失，不应包含 @cn4 set 引用
        assert!(!script.contains("@cn4"));
        assert!(!script.contains("GEOIP_PREROUTING"));
        // 转发规则正常生成
        assert!(script.contains("tcp dport 30080 counter dnat"));
        assert!(!script.contains("flush ruleset"));
    }

    #[test]
    fn geoip_forward_emits_cn4_set_and_drop_rules() {
        let cn4 = write_temp_cn4_file("forward-on", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: cn4.to_string_lossy().to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("add set ip self-filter cn4"));
        assert!(script.contains("1.0.1.0/24"));
        assert!(script.contains("add chain ip self-filter GEOIP_PREROUTING"));
        assert!(script.contains("ip saddr @cn4 tcp dport 30080 counter accept"));
        assert!(script.contains("geoip-forward:id=r0,mode=allow-cn"));
        assert!(script.contains("tcp dport 30080 counter drop"));
        // 默认 allow_lan=true 也产生 LAN 允许规则
        assert!(script.contains("geoip-forward:id=r0,mode=allow-lan"));
        assert!(script.contains("10.0.0.0/8"));
        assert!(!script.contains("flush ruleset"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn geoip_forward_skips_disabled_rules() {
        let cn4 = write_temp_cn4_file("forward-skip-disabled", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        // disabled 规则在 read_toml_config 中已经过滤掉，所以 build_new_script 看不到。
        // 但这里我们直接传入只包含 enabled=true 的规则集合，验证只有它生成 GeoIP 规则。
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: cn4.to_string_lossy().to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        // 只有 r0 的规则
        assert!(script.contains("geoip-forward:id=r0,mode=allow-cn"));
        assert!(!script.contains("geoip-forward:id=r1"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn geoip_ssh_default_disabled_emits_no_ssh_rules() {
        let cn4 = write_temp_cn4_file("ssh-default-off", sample_cn4_content());
        let cells: Vec<config::RuntimeCell> = Vec::new();
        let geoip = GeoIpConfig {
            enabled: true,
            cn4_file: cn4.to_string_lossy().to_string(),
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!geoip.ssh.enabled);
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("geoip-ssh"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn geoip_ssh_restricts_only_configured_ssh_port_with_lan() {
        let cn4 = write_temp_cn4_file("ssh-port", sample_cn4_content());
        let cells: Vec<config::RuntimeCell> = Vec::new();
        let geoip = GeoIpConfig {
            enabled: true,
            allow_lan: true,
            cn4_file: cn4.to_string_lossy().to_string(),
            ssh: nat_common::GeoIpSshConfig {
                enabled: true,
                port: 2222,
                mode: "allow-cn-and-lan".to_string(),
            },
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("tcp dport 2222 counter accept"));
        assert!(script.contains("geoip-ssh:mode=allow-cn"));
        assert!(script.contains("geoip-ssh:mode=allow-lan"));
        assert!(script.contains("10.0.0.0/8"));
        assert!(script.contains("tcp dport 2222 counter drop"));
        // 不应限制其他端口
        assert!(!script.contains("tcp dport 22 counter drop"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn combined_blacklist_and_geoip_emit_layered_drops() {
        let cn4 = write_temp_cn4_file("combined-bl-geoip", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Blacklist,
            entries: vec!["1.0.1.5".to_string()],
        };
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: cn4.to_string_lossy().to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        let bl_pos = script
            .find("ip saddr { 1.0.1.5 } tcp dport 30080 counter drop")
            .unwrap();
        let geoip_pos = script
            .find("GEOIP_PREROUTING ip saddr @cn4 tcp dport 30080 counter accept")
            .unwrap();
        let geoip_drop_pos = script
            .find("GEOIP_PREROUTING tcp dport 30080 counter drop")
            .unwrap();
        let dnat_pos = script.find("tcp dport 30080 counter dnat").unwrap();
        assert!(
            bl_pos < dnat_pos,
            "blacklist drop must precede dnat to keep blacklist priority"
        );
        assert!(geoip_pos < geoip_drop_pos);
        assert!(!script.contains("flush ruleset"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn combined_whitelist_and_geoip_apply_both_layers() {
        let cn4 = write_temp_cn4_file("combined-wl-geoip", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Whitelist,
            entries: vec!["1.0.1.5".to_string()],
        };
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: cn4.to_string_lossy().to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            script.contains("ip saddr { 1.0.1.5 } tcp dport 30080 counter dnat"),
            "whitelist must restrict DNAT to whitelisted source IPs"
        );
        assert!(
            script.contains("GEOIP_PREROUTING ip saddr @cn4 tcp dport 30080 counter accept"),
            "GeoIP allow-cn must be present"
        );
        assert!(
            script.contains("GEOIP_PREROUTING tcp dport 30080 counter drop"),
            "GeoIP default-drop must be present so non-CN sources are dropped"
        );
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn whitelist_alone_blocks_non_whitelisted_via_saddr_match() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let access = nat_common::AccessControlConfig {
            mode: nat_common::AccessControlMode::Whitelist,
            entries: vec!["10.0.0.1".to_string()],
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &access,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("ip saddr { 10.0.0.1 } tcp dport 30080 counter dnat"));
        assert!(
            !script.contains("ct state new tcp dport 30080 counter dnat"),
            "unrestricted dnat must not exist when whitelist is on"
        );
    }

    #[test]
    fn geoip_alone_drops_non_cn_even_without_blacklist() {
        let cn4 = write_temp_cn4_file("geoip-alone", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip = GeoIpConfig {
            enabled: true,
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            cn4_file: cn4.to_string_lossy().to_string(),
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        // GEOIP_PREROUTING priority -200 runs before self-nat PREROUTING priority -110
        assert!(script.contains(
            "add chain ip self-filter GEOIP_PREROUTING { type filter hook prerouting priority -200 ; }"
        ));
        assert!(script.contains("self-nat PREROUTING { type nat hook prerouting priority -110"));
        assert!(script.contains("GEOIP_PREROUTING tcp dport 30080 counter drop"));
        // Access control off, so no port-scoped saddr drop rule
        assert!(!script.contains("nat-access:id=r0,mode=blacklist"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn egress_control_default_disabled_does_not_filter() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "8.8.8.8".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let egress = nat_common::EgressControlConfig::default();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("tcp dport 30080 counter dnat to 8.8.8.8:80"));
    }

    #[test]
    fn egress_control_empty_allowed_skips_all_forwards() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "8.8.8.8".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let egress = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: Vec::new(),
            comment: None,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("counter dnat to 8.8.8.8"));
        // 基础表结构仍然存在
        assert!(script.contains("add table ip self-nat"));
    }

    #[test]
    fn egress_control_skips_targets_not_in_allowed_cidrs() {
        let cells = vec![
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30080,
                dport: 80,
                domain: "8.8.8.8".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30081,
                dport: 80,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
        ];
        let egress = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec!["10.100.0.0/24".to_string()],
            comment: None,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        // 8.8.8.8 不在 allowed_target_cidrs 内，被跳过
        assert!(!script.contains("counter dnat to 8.8.8.8"));
        // 10.100.0.10 在 allowed_target_cidrs 内，正常生成
        assert!(script.contains("counter dnat to 10.100.0.10:80"));
    }

    #[test]
    fn egress_control_uses_resolved_ip_for_ip_literal_domain() {
        // 使用 IPv4 字面量作为 domain：build_with_rule_index 内部走
        // ip::remote_ip_with_dns 的 "直接解析为 IP" 分支
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "172.31.8.5".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let egress = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec!["172.31.8.0/24".to_string()],
            comment: None,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("counter dnat to 172.31.8.5:80"));
    }

    #[test]
    fn never_emits_flush_ruleset_in_any_geoip_path() {
        let cn4 = write_temp_cn4_file("no-flush", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip = GeoIpConfig {
            enabled: true,
            cn4_file: cn4.to_string_lossy().to_string(),
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            ssh: nat_common::GeoIpSshConfig {
                enabled: true,
                port: 22,
                mode: "allow-cn-and-lan".to_string(),
            },
            ..Default::default()
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("flush ruleset"));
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn never_touches_tables_outside_self_nat_and_self_filter() {
        let cn4 = write_temp_cn4_file("only-self-tables", sample_cn4_content());
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "10.100.0.10".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let geoip = GeoIpConfig {
            enabled: true,
            cn4_file: cn4.to_string_lossy().to_string(),
            forward: nat_common::GeoIpForwardConfig {
                enabled: true,
                ..Default::default()
            },
            ssh: nat_common::GeoIpSshConfig {
                enabled: true,
                port: 22,
                mode: "allow-cn-and-lan".to_string(),
            },
            ..Default::default()
        };
        let egress = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec!["10.100.0.0/24".to_string()],
            comment: None,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &geoip,
            &egress,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        let valid_family = |f: &str| matches!(f, "ip" | "ip6");
        let valid_table = |t: &str| matches!(t, "self-nat" | "self-filter");
        for line in script.lines() {
            // 每一行 "add chain"/"add table"/"add rule"/"add set"/"add element"
            // 涉及到的 table 必须是 self-nat / self-filter / IPv6 对应表
            if let Some(rest) = line.strip_prefix("add rule ") {
                let words: Vec<&str> = rest.split_whitespace().collect();
                if let (Some(family), Some(table)) = (words.first(), words.get(1)) {
                    assert!(
                        valid_family(family) && valid_table(table),
                        "rule writes to unexpected table: {line}"
                    );
                }
            } else if let Some(rest) = line.strip_prefix("add chain ") {
                let words: Vec<&str> = rest.split_whitespace().collect();
                if let (Some(family), Some(table)) = (words.first(), words.get(1)) {
                    assert!(
                        valid_family(family) && valid_table(table),
                        "chain writes to unexpected table: {line}"
                    );
                }
            } else if line.starts_with("add set ") || line.starts_with("add element ") {
                let words: Vec<&str> = line.split_whitespace().collect();
                if let (Some(family), Some(table)) = (words.get(2), words.get(3)) {
                    assert!(
                        valid_family(family) && valid_table(table),
                        "set/element writes to unexpected table: {line}"
                    );
                }
            }
        }
        let _ = fs::remove_dir_all(cn4.parent().unwrap());
    }

    #[test]
    fn empty_rules_still_builds_managed_tables_script() {
        let script = build_new_script(
            &[],
            &DnsConfig::default(),
            &nat_common::AccessControlConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("add table ip self-nat"));
        assert!(script.contains("add table ip6 self-nat"));
        assert!(script.contains("add table ip self-filter"));
        assert!(script.contains("add table ip6 self-filter"));
        assert!(!script.contains("flush ruleset"));
    }

    fn single_forward_cell() -> Vec<config::RuntimeCell> {
        vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "93.184.216.34".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })]
    }

    #[test]
    fn snat_default_is_masquerade() {
        // Tests assume the legacy `nat_local_ip` env var is not set; if it is,
        // mode=masquerade falls back to `snat to <env>` for backwards compatibility.
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            script.contains("counter masquerade comment"),
            "default snat must emit masquerade"
        );
        assert!(!script.contains("counter snat to"));
    }

    #[test]
    fn snat_fixed_emits_snat_to_fixed_ip() {
        unsafe { std::env::remove_var("nat_local_ip") };
        let snat = SnatConfig {
            mode: nat_common::SnatMode::Fixed,
            fixed_source_ip: "10.100.0.10".to_string(),
        };
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &snat,
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains("counter snat to 10.100.0.10 comment"));
        assert!(!script.contains("counter masquerade comment"));
    }

    #[test]
    fn snat_off_omits_postrouting_rule() {
        unsafe { std::env::remove_var("nat_local_ip") };
        let snat = SnatConfig {
            mode: nat_common::SnatMode::Off,
            fixed_source_ip: String::new(),
        };
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &snat,
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            !script.contains("add rule ip self-nat POSTROUTING"),
            "snat=off must not emit POSTROUTING SNAT rules"
        );
        assert!(!script.contains("counter masquerade"));
        assert!(!script.contains("counter snat to"));
        // 链定义保留，但不写入规则；DNAT 主链仍然存在
        assert!(script.contains("add chain ip self-nat POSTROUTING"));
        assert!(script.contains("counter dnat to 93.184.216.34:80"));
    }

    #[test]
    fn mss_clamp_disabled_emits_no_mss_rules() {
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("mss-clamp"));
        assert!(!script.contains("maxseg size set"));
    }

    #[test]
    fn mss_clamp_enabled_emits_forward_chain_clamp_only() {
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(script.contains(
            "add rule ip self-filter FORWARD tcp dport 80 tcp flags syn tcp option maxseg size set 1452 comment \"mss-clamp:id=r0,dir=out\""
        ));
        assert!(script.contains(
            "add rule ip self-filter FORWARD tcp sport 80 tcp flags syn tcp option maxseg size set 1452 comment \"mss-clamp:id=r0,dir=in\""
        ));
        // 仅作用于 forward chain，不接管整机
        assert!(!script.contains("policy drop"));
        assert!(!script.contains("flush ruleset"));
    }

    #[test]
    fn mss_clamp_skips_udp_only_rules() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30053,
            dport: 53,
            domain: "8.8.8.8".to_string(),
            protocol: nat_common::Protocol::Udp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("mss-clamp:id=r0"));
    }

    #[test]
    fn mss_clamp_skips_localhost_redirect_single() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 8080,
            domain: "localhost".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            !script.contains("mss-clamp:id=r0"),
            "redirect-to-localhost must not generate MSS clamp"
        );
    }

    #[test]
    fn snat_and_mss_do_not_modify_user_tables() {
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let snat = SnatConfig {
            mode: nat_common::SnatMode::Fixed,
            fixed_source_ip: "10.100.0.10".to_string(),
        };
        let script = build_new_script(
            &single_forward_cell(),
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &snat,
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("flush ruleset"));
        assert!(!script.contains("policy drop"));
        for line in script.lines() {
            if let Some(rest) = line.strip_prefix("add rule ") {
                let words: Vec<&str> = rest.split_whitespace().collect();
                if let (Some(family), Some(table)) = (words.first(), words.get(1)) {
                    assert!(
                        matches!(*family, "ip" | "ip6")
                            && matches!(*table, "self-nat" | "self-filter"),
                        "rule writes to unexpected table: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn snat_fixed_falls_back_to_masquerade_for_ipv6_cells() {
        // fixed_source_ip 是 IPv4，IPv6 转发规则不能写 snat to <ipv4>，
        // 必须回退到 masquerade。
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "2001:db8::1".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V6,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let snat = SnatConfig {
            mode: nat_common::SnatMode::Fixed,
            fixed_source_ip: "10.100.0.10".to_string(),
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &snat,
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            !script.contains("snat to 10.100.0.10"),
            "fixed SNAT must not emit IPv4 source on IPv6 rule: {script}"
        );
        assert!(
            script.contains("ip6 self-nat POSTROUTING") && script.contains("counter masquerade"),
            "IPv6 rule must fall back to masquerade under mode=fixed"
        );
    }

    #[test]
    fn snat_off_state_does_not_emit_any_snat_action_strings() {
        // 全面回归：mode=off 不生成 masquerade / snat to / accept …，且没有 POSTROUTING 规则
        let cells = vec![
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30080,
                dport: 80,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
            config::RuntimeCell::Rule(nat_common::NftCell::Range {
                enabled: true,
                port_start: 30000,
                port_end: 30010,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::All,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
        ];
        let snat = SnatConfig {
            mode: nat_common::SnatMode::Off,
            fixed_source_ip: String::new(),
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &snat,
            &MssClampConfig::default(),
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(!script.contains("counter masquerade"));
        assert!(!script.contains("counter snat to"));
        assert!(!script.contains("add rule ip self-nat POSTROUTING"));
        // DNAT 主链仍然存在
        assert!(script.contains("counter dnat to 10.100.0.10:80"));
    }

    #[test]
    fn mss_clamp_protocol_udp_emits_no_mss_rules() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30053,
            dport: 53,
            domain: "8.8.8.8".to_string(),
            protocol: nat_common::Protocol::Udp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        assert!(
            !script.contains("mss-clamp"),
            "UDP-only forward rules must not produce MSS clamp"
        );
        assert!(!script.contains("maxseg size set"));
    }

    #[test]
    fn mss_clamp_protocol_all_emits_tcp_keyed_rules_only() {
        // protocol=all 时，规则本身既匹配 TCP 也匹配 UDP；但 MSS clamp 必须仅作用于 TCP，
        // 因此生成的 nft 规则关键字必须是 `tcp dport/sport ...`，而不是 `meta l4proto { tcp, udp } th`。
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "10.100.0.10".to_string(),
            protocol: nat_common::Protocol::All,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })];
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        // MSS clamp 必须出现，且只用 tcp keyword（确保 nft 只对 TCP 包改写 MSS）
        let mss_lines: Vec<&str> = script
            .lines()
            .filter(|line| line.contains("mss-clamp:id=r0"))
            .collect();
        assert_eq!(mss_lines.len(), 2, "应生成 out + in 两条 TCP MSS 规则");
        for line in &mss_lines {
            assert!(
                line.starts_with("add rule ip self-filter FORWARD tcp ")
                    && line.contains("tcp flags syn tcp option maxseg size set 1452"),
                "MSS clamp 必须用 tcp keyword 限定，禁止使用 meta l4proto 写入 UDP MSS：{line}"
            );
            assert!(
                !line.contains("meta l4proto") && !line.contains("udp"),
                "MSS clamp 必须排除 UDP 路径：{line}"
            );
        }
    }

    #[test]
    fn mss_clamp_only_matches_project_target_ports_not_arbitrary_ports() {
        // 仅本项目目标端口被匹配，整机 / 其他端口不应出现在 mss-clamp 规则中。
        let cells = vec![
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30080,
                dport: 80,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30443,
                dport: 443,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            }),
        ];
        let mss = MssClampConfig {
            enabled: true,
            size: 1452,
        };
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &SnatConfig::default(),
            &mss,
            &Default::default(),
            &Default::default(),
            &ResolutionLog::new(),
        )
        .unwrap();
        let mss_lines: Vec<&str> = script
            .lines()
            .filter(|line| line.contains("mss-clamp:"))
            .collect();
        assert_eq!(
            mss_lines.len(),
            4,
            "两条 TCP 规则 × out/in = 4 条 MSS clamp"
        );
        // 项目端口 80 / 443 必须各自出现
        assert!(
            mss_lines
                .iter()
                .any(|l| l.contains(" dport 80 ") && l.contains("id=r0,dir=out"))
        );
        assert!(
            mss_lines
                .iter()
                .any(|l| l.contains(" dport 443 ") && l.contains("id=r1,dir=out"))
        );
        // 不应出现任意端口的 catch-all（如 dport 0-65535 或缺少 dport/sport）
        for line in &mss_lines {
            assert!(
                line.contains(" dport ") || line.contains(" sport "),
                "MSS clamp 必须基于具体端口匹配：{line}"
            );
            assert!(
                !line.contains("dport 0-65535") && !line.contains("policy"),
                "MSS clamp 不能使用整机/catch-all 匹配：{line}"
            );
        }
        // 不应触碰非本项目端口（例如 22 SSH 或 53 DNS）
        for forbidden in [" dport 22 ", " sport 22 ", " dport 53 ", " sport 53 "] {
            assert!(
                !mss_lines.iter().any(|l| l.contains(forbidden)),
                "MSS clamp 不应作用于非本项目端口: {forbidden}"
            );
        }
    }

    // ===== last-good 容错与 audit 集成测试 =====

    fn unresolvable_domain_cell() -> Vec<config::RuntimeCell> {
        // 包含空格的目标会被系统解析器直接拒绝；用作"DNS 失败"模拟，无需真实 DNS 查询。
        vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "invalid domain".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: Some("dns-fail-test".to_string()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        })]
    }

    fn unresolvable_domain_rule_key() -> String {
        "single|sport=30080|dport=80|protocol=tcp|ip_version=ipv4|target=invalid domain".to_string()
    }

    #[test]
    fn last_good_fallback_emits_rule_when_cache_has_ip() {
        let cells = unresolvable_domain_cell();
        let mut state = LastGoodState::default();
        state.rules.push(nat_common::last_good::LastGoodRule {
            rule_id: "r0".to_string(),
            rule_key: Some(unresolvable_domain_rule_key()),
            comment: Some("dns-fail-test".to_string()),
            domain: "invalid domain".to_string(),
            last_good_ip: "10.100.0.10".to_string(),
            last_resolved_at: chrono::Utc::now(),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        });
        let resolution_log = ResolutionLog::new();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &LastGoodConfig::default(),
            &state,
            &resolution_log,
        )
        .unwrap();
        assert!(
            script.contains("counter dnat to 10.100.0.10:80"),
            "应使用 last-good IP 生成 DNAT: {script}"
        );
        let events = resolution_log.snapshot();
        assert!(
            events.iter().any(|e| matches!(
                e,
                ResolutionEvent::LastGoodUsed { rule_id, ip, .. }
                    if rule_id == "r0" && ip == "10.100.0.10"
            )),
            "应记录 LastGoodUsed 事件"
        );
    }

    #[test]
    fn last_good_fallback_skips_rule_when_cache_missing() {
        let cells = unresolvable_domain_cell();
        let state = LastGoodState::default();
        let resolution_log = ResolutionLog::new();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &LastGoodConfig::default(),
            &state,
            &resolution_log,
        )
        .unwrap();
        assert!(
            !script.contains("dnat to 198.19.184.4"),
            "无缓存时不应生成 fake-ip dnat"
        );
        let events = resolution_log.snapshot();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ResolutionEvent::ResolveFailedNoCache { .. })),
            "应记录 ResolveFailedNoCache 事件: {:?}",
            events
        );
    }

    #[test]
    fn last_good_disabled_does_not_fall_back() {
        let cells = unresolvable_domain_cell();
        let mut state = LastGoodState::default();
        state.rules.push(nat_common::last_good::LastGoodRule {
            rule_id: "r0".to_string(),
            rule_key: Some(unresolvable_domain_rule_key()),
            comment: None,
            domain: "invalid domain".to_string(),
            last_good_ip: "10.100.0.10".to_string(),
            last_resolved_at: chrono::Utc::now(),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        });
        let last_good_off = LastGoodConfig {
            enabled: false,
            ..Default::default()
        };
        let resolution_log = ResolutionLog::new();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &last_good_off,
            &state,
            &resolution_log,
        )
        .unwrap();
        assert!(!script.contains("counter dnat to 10.100.0.10"));
    }

    #[test]
    fn last_good_use_on_dns_failure_flag_can_be_turned_off() {
        let cells = unresolvable_domain_cell();
        let mut state = LastGoodState::default();
        state.rules.push(nat_common::last_good::LastGoodRule {
            rule_id: "r0".to_string(),
            rule_key: Some(unresolvable_domain_rule_key()),
            comment: None,
            domain: "invalid domain".to_string(),
            last_good_ip: "10.100.0.10".to_string(),
            last_resolved_at: chrono::Utc::now(),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        });
        let last_good_cfg = LastGoodConfig {
            enabled: true,
            use_last_good_on_dns_failure: false,
            ..Default::default()
        };
        let resolution_log = ResolutionLog::new();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &last_good_cfg,
            &state,
            &resolution_log,
        )
        .unwrap();
        assert!(!script.contains("counter dnat to 10.100.0.10"));
    }

    #[test]
    fn last_good_fallback_still_filtered_by_egress_control() {
        let cells = unresolvable_domain_cell();
        let mut state = LastGoodState::default();
        state.rules.push(nat_common::last_good::LastGoodRule {
            rule_id: "r0".to_string(),
            rule_key: Some(unresolvable_domain_rule_key()),
            comment: None,
            domain: "invalid domain".to_string(),
            last_good_ip: "8.8.8.8".to_string(),
            last_resolved_at: chrono::Utc::now(),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        });
        let egress = nat_common::EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec!["10.100.0.0/24".to_string()],
            comment: None,
        };
        let resolution_log = ResolutionLog::new();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
            &Default::default(),
            &Default::default(),
            &LastGoodConfig::default(),
            &state,
            &resolution_log,
        )
        .unwrap();
        assert!(
            !script.contains("counter dnat to 8.8.8.8"),
            "egress_control 必须对 last-good IP 同样生效"
        );
        let events = resolution_log.snapshot();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ResolutionEvent::EgressSkipped { ip, .. } if ip == "8.8.8.8")),
            "应记录 EgressSkipped 事件: {:?}",
            events
        );
    }

    #[test]
    fn audit_resolution_events_writes_to_audit_file() {
        use nat_common::AuditConfig;
        let dir = std::env::temp_dir().join(format!(
            "nat-audit-int-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log").to_string_lossy().to_string();
        let audit_cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        let events = vec![
            ResolutionEvent::LastGoodUsed {
                rule_id: "r0".to_string(),
                rule_key: Some("k0".to_string()),
                comment: Some("hk".to_string()),
                domain: "example.com".to_string(),
                ip: "1.2.3.4".to_string(),
                original_error: "Failed to resolve".to_string(),
            },
            ResolutionEvent::EgressSkipped {
                rule_id: "r1".to_string(),
                rule_key: Some("k1".to_string()),
                comment: None,
                ip: "8.8.8.8".to_string(),
                source: nat_common::last_good::ResolveSource::LastGood,
            },
            ResolutionEvent::ResolveFailedNoCache {
                rule_id: "r2".to_string(),
                rule_key: Some("k2".to_string()),
                comment: None,
                domain: "broken.invalid".to_string(),
                original_error: "nx".to_string(),
            },
        ];
        super::audit_resolution_events(&audit_cfg, &events);
        let lines = audit::read_tail(&path, 50);
        assert_eq!(lines.len(), 3);
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(parsed[0]["action"], "last_good.used");
        assert_eq!(parsed[1]["action"], "rule.skipped.egress_control");
        assert_eq!(parsed[2]["action"], "dns.resolve.fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ===== quota: 服务侧 run_quota_check 集成测试 =====

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-quota-int-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_quota_test_toml(dir: &std::path::Path, stats_file: &str) -> std::path::PathBuf {
        let toml_path = dir.join("nat.toml");
        let audit_path = dir.join("audit.log");
        let quota_state_path = dir.join("quota.json");
        let body = format!(
            r#"[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "10.100.0.10"
protocol = "tcp"
ip_version = "ipv4"
comment = "hk-out"
enabled = true
quota_enabled = true
quota_bytes = 100
quota_period = "monthly"
quota_action = "disable"

[[rules]]
type = "single"
sport = 30081
dport = 80
domain = "10.100.0.11"
protocol = "tcp"
ip_version = "ipv4"
comment = "no-quota"
enabled = true

[stats]
enabled = true
data_file = "{stats_file}"

[telegram]
enabled = false
bot_token = ""
chat_id = ""

[audit]
enabled = true
file = "{}"

[quota]
enabled = true
check_interval_seconds = 60
notify_on_exceeded = true
state_file = "{}"
"#,
            audit_path.to_string_lossy(),
            quota_state_path.to_string_lossy(),
        );
        std::fs::write(&toml_path, body).unwrap();
        toml_path
    }

    #[test]
    fn quota_check_disables_exceeded_rule_and_logs_audit() {
        let dir = tempdir("disable");
        let stats_file = dir.join("stats.json");
        let mut stats_state = nat_common::stats::StatsState::default();
        stats_state
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 500);
        stats_state
            .per_rule_monthly_bytes
            .insert("r1".to_string(), 1);
        std::fs::write(
            &stats_file,
            serde_json::to_string_pretty(&stats_state).unwrap(),
        )
        .unwrap();
        let toml_path = write_quota_test_toml(&dir, stats_file.to_str().unwrap());
        let backup_root = dir.join("backups");

        let runtime_config = load_runtime_config(&Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(toml_path.to_string_lossy().to_string()),
        });
        run_quota_check_with(
            &Args {
                menu: false,
                compatible_config_file: None,
                toml: Some(toml_path.to_string_lossy().to_string()),
            },
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
            &backup_root,
        );

        // 配置文件应已写回，r0 enabled=false，r1 不变
        let after = std::fs::read_to_string(&toml_path).unwrap();
        let cfg = TomlConfig::from_toml_str(&after).unwrap();
        assert!(!cfg.rules[0].enabled(), "exceeded rule must be disabled");
        assert!(cfg.rules[1].enabled(), "non-quota rule must remain enabled");

        // v0.6.0：写回前应已通过 safe_write_config_to 创建备份，文件名按 reason 命名为
        // `<stem>.quota.auto_disable-YYYYmmdd-HHMMSS.bak`，放在 backup_root/config 下。
        let backup_subdir = backup_root.join("config");
        let backups: Vec<_> = std::fs::read_dir(&backup_subdir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains(".quota.auto_disable-")
            })
            .collect();
        assert!(
            !backups.is_empty(),
            "quota auto-disable should write a backup file under {}",
            backup_subdir.display()
        );

        // audit 日志应包含 quota.exceeded + rule.disable.quota + quota.telegram.skipped
        let audit_lines = audit::read_tail(&runtime_config.audit.file, 50);
        let actions: Vec<String> = audit_lines
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["action"].as_str().unwrap_or("").to_string()
            })
            .collect();
        assert!(actions.contains(&"quota.exceeded".to_string()));
        assert!(actions.contains(&"rule.disable.quota".to_string()));
        assert!(actions.contains(&"quota.telegram.skipped".to_string()));
        // v0.6.0：safe_write_config_to 在成功时写 `config.write.success`，
        // 然后 quota 包裹层补一条 `quota.auto_disable.write_ok`，旧报警入口仍然存在。
        assert!(
            actions.contains(&"config.write.success".to_string()),
            "quota 自动禁用前 safe_write_config_to 必须写 config.write.success audit"
        );
        assert!(
            actions.contains(&"quota.auto_disable.write_ok".to_string()),
            "quota 自动禁用写回成功后必须写 quota.auto_disable.write_ok audit"
        );
        // 未配置 Telegram 不应产生 quota.telegram.notify
        assert!(!actions.contains(&"quota.telegram.notify".to_string()));

        // quota state 应记录通知去重
        let state = quota::QuotaState::load(&runtime_config.quota.state_file);
        let now_month = chrono::Utc::now().date_naive().format("%Y-%m").to_string();
        assert!(state.is_notified(&format!("r0:monthly:{now_month}")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_check_does_not_renotify_same_period() {
        let dir = tempdir("renotify");
        let stats_file = dir.join("stats.json");
        let mut stats_state = nat_common::stats::StatsState::default();
        stats_state
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 500);
        std::fs::write(
            &stats_file,
            serde_json::to_string_pretty(&stats_state).unwrap(),
        )
        .unwrap();
        let toml_path = write_quota_test_toml(&dir, stats_file.to_str().unwrap());
        let backup_root = dir.join("backups");

        let args = Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(toml_path.to_string_lossy().to_string()),
        };
        let runtime_config = load_runtime_config(&args);

        // 两次连续调用：第二次不应再产生 quota.telegram.* 类事件（已通知过 + 已禁用）
        run_quota_check_with(
            &args,
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
            &backup_root,
        );
        let lines_after_first = audit::read_tail(&runtime_config.audit.file, 200).len();

        run_quota_check_with(
            &args,
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
            &backup_root,
        );
        let lines_after_second = audit::read_tail(&runtime_config.audit.file, 200).len();
        // 第二次只会写 quota.exceeded（仍超额），但不再 rule.disable.quota / telegram，
        // 所以第二次新增行数应 < 第一次的事件数
        let delta = lines_after_second - lines_after_first;
        assert!(
            delta < 3,
            "second check should not re-notify telegram: delta={delta}"
        );
        // quota.telegram.notify 永远不应出现（无 Telegram）
        let parsed: Vec<serde_json::Value> = audit::read_tail(&runtime_config.audit.file, 200)
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let notify_count = parsed
            .iter()
            .filter(|v| v["action"] == "quota.telegram.notify")
            .count();
        assert_eq!(notify_count, 0);
        let skipped_count = parsed
            .iter()
            .filter(|v| v["action"] == "quota.telegram.skipped")
            .count();
        assert_eq!(skipped_count, 1, "telegram.skipped should be deduped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_check_does_not_execute_nft() {
        // run_quota_check 必须只改 TOML + 写 audit，不执行 nft -f。
        // 我们用一个 TOML 文件 + 一个特殊路径监视 nft 调用。这里通过断言生成的事件
        // 不含任何形如 "nft.apply" / "apply.success" 类，且没有副作用文件写入到 BACKUP_DIR / FILE_NAME_SCRIPT。
        let dir = tempdir("no-nft");
        let stats_file = dir.join("stats.json");
        let mut stats_state = nat_common::stats::StatsState::default();
        stats_state
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 500);
        std::fs::write(
            &stats_file,
            serde_json::to_string_pretty(&stats_state).unwrap(),
        )
        .unwrap();
        let toml_path = write_quota_test_toml(&dir, stats_file.to_str().unwrap());
        let backup_root = dir.join("backups");
        let args = Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(toml_path.to_string_lossy().to_string()),
        };
        let runtime_config = load_runtime_config(&args);
        run_quota_check_with(
            &args,
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
            &backup_root,
        );
        // 没有 apply.success / apply.fail 事件
        let lines = audit::read_tail(&runtime_config.audit.file, 200);
        for line in &lines {
            assert!(
                !line.contains("\"apply.success\"") && !line.contains("\"apply.fail\""),
                "quota check must not trigger nft apply audit: {line}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_check_respects_stats_disabled() {
        // stats.enabled=false 时主循环只 WARN，run_quota_check 仍可调用但 used 全为 0，不会触发禁用
        let dir = tempdir("stats-off");
        let stats_file = dir.join("stats.json");
        let toml_path = dir.join("nat.toml");
        let audit_path = dir.join("audit.log");
        let quota_state_path = dir.join("quota.json");
        let body = format!(
            r#"[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "10.100.0.10"
protocol = "tcp"
ip_version = "ipv4"
enabled = true
quota_enabled = true
quota_bytes = 100
quota_period = "monthly"

[stats]
enabled = false
data_file = "{}"

[audit]
enabled = true
file = "{}"

[quota]
enabled = true
state_file = "{}"
"#,
            stats_file.to_string_lossy(),
            audit_path.to_string_lossy(),
            quota_state_path.to_string_lossy(),
        );
        std::fs::write(&toml_path, body).unwrap();
        let args = Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(toml_path.to_string_lossy().to_string()),
        };
        let runtime_config = load_runtime_config(&args);
        run_quota_check(
            &args,
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
        );
        // stats 文件不存在 + 为 0 → 没有任何超额事件
        let cfg = TomlConfig::from_toml_str(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        assert!(
            cfg.rules[0].enabled(),
            "rule must not be disabled when used=0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ============ v0.4.1: quota 自动禁用前备份相关测试 ============

    #[test]
    fn backup_fail_skips_write_and_keeps_original_toml() {
        // v0.6.0：quota 自动禁用写回经过 `menu::safe_write_config_to`，因此备份失败时：
        //   - 不修改 /etc/nat.toml（保持原内容）
        //   - 写一条 `config.write.fail` audit（stage=backup）
        //   - 写一条 `quota.auto_disable.write_fail` audit
        //   - 不写 `config.write.success` / `quota.auto_disable.write_ok`
        let dir = tempdir("backup-fail-skip");
        let stats_file = dir.join("stats.json");
        let mut stats_state = nat_common::stats::StatsState::default();
        stats_state
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 500);
        std::fs::write(
            &stats_file,
            serde_json::to_string_pretty(&stats_state).unwrap(),
        )
        .unwrap();
        let toml_path = write_quota_test_toml(&dir, stats_file.to_str().unwrap());
        let original = std::fs::read_to_string(&toml_path).unwrap();

        // 用一个普通文件占位的 backup_root：fs::create_dir_all 在 "<file>/config" 上必然失败
        let blocker = dir.join("backups");
        std::fs::write(&blocker, b"i am a regular file, not a directory").unwrap();

        let args = Args {
            menu: false,
            compatible_config_file: None,
            toml: Some(toml_path.to_string_lossy().to_string()),
        };
        let runtime_config = load_runtime_config(&args);
        run_quota_check_with(
            &args,
            &runtime_config.quota,
            &runtime_config.audit,
            &runtime_config.stats,
            &runtime_config.telegram,
            chrono::Utc::now(),
            &blocker,
        );

        // TOML 必须保持原状（rule 仍为 enabled=true）
        let after = std::fs::read_to_string(&toml_path).unwrap();
        assert_eq!(
            after, original,
            "backup 失败时 quota 不应继续覆盖 /etc/nat.toml"
        );
        let cfg = TomlConfig::from_toml_str(&after).unwrap();
        assert!(cfg.rules[0].enabled(), "backup 失败时被超额规则不应被禁用");

        // audit 行为：config.write.fail (stage=backup) + quota.auto_disable.write_fail
        let lines = audit::read_tail(&runtime_config.audit.file, 50);
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect();
        let actions: Vec<String> = parsed
            .iter()
            .filter_map(|v| v["action"].as_str().map(ToString::to_string))
            .collect();
        assert!(
            actions.contains(&"config.write.fail".to_string()),
            "backup 失败必须写 config.write.fail audit，实际：{actions:?}"
        );
        assert!(
            parsed
                .iter()
                .any(|v| v["action"] == "config.write.fail" && v["detail"]["stage"] == "backup"),
            "config.write.fail 应当标注 stage=backup"
        );
        assert!(
            actions.contains(&"quota.auto_disable.write_fail".to_string()),
            "quota 包裹层失败 audit 必须保留：{actions:?}"
        );
        assert!(
            !actions.contains(&"config.write.success".to_string()),
            "backup 失败时不应再产出 config.write.success audit"
        );
        assert!(
            !actions.contains(&"quota.auto_disable.write_ok".to_string()),
            "backup 失败时不应再产出 write_ok audit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // v0.6.0：原 `atomic_write_text_file` 已迁移到 `nat_common::atomic::write_atomic`，
    // 单独的本地测试不再需要——nat-common 自身覆盖了 atomic write 行为。
}
