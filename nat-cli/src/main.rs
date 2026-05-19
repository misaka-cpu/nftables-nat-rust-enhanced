#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
mod config;
mod ip;
mod menu;
mod prepare;

use chrono::Local;
use clap::Parser;
use log::{error, info, warn};
use nat_common::{
    Args, DdnsConfig, DnsConfig, EgressControlConfig, GeoIpConfig, StatsConfig, TelegramConfig,
    TomlConfig, geoip, logger,
    stats::{self as traffic_stats, StatsState},
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

const NFTABLES_ETC: &str = "/etc/nftables-nat";
const FILE_NAME_SCRIPT: &str = "/etc/nftables-nat/nat-diy.nft";
const BACKUP_DIR: &str = "/etc/nftables-nat/backups";
const MANAGED_TABLES: [(&str, &str); 4] = [
    ("ip", "self-nat"),
    ("ip6", "self-nat"),
    ("ip", "self-filter"),
    ("ip6", "self-filter"),
];
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
    let mut latest_script = String::new();
    let mut last_stats_collect = None;
    let mut last_ddns_refresh = None;
    let mut last_short_ddns_warn: Option<u64> = None;
    loop {
        let loop_now = Local::now();
        let runtime_config = load_runtime_config(args);
        let refresh_interval = ddns_refresh_interval(&runtime_config.ddns)?;
        warn_short_ddns_interval_once(refresh_interval, &mut last_short_ddns_warn);
        let dns_config = runtime_config.dns;
        let access_config = runtime_config.access_control;
        let geoip_config = runtime_config.geoip;
        let egress_config = runtime_config.egress_control;
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
            let script = match build_new_script(
                &nat_cells,
                &dns_config,
                &access_config,
                &geoip_config,
                &egress_config,
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
            last_ddns_refresh = Some(loop_now);
            prepare::check_and_prepare()?;
            if script != latest_script {
                if stats_config.enabled {
                    let collect_now = Local::now();
                    let _ = collect_and_maybe_notify(&stats_config, &telegram_config, &rule_labels);
                    last_stats_collect = Some(collect_now);
                }
                info!("当前配置: ");
                for ele in &nat_cells {
                    info!("{ele:?}");
                }
                info!("nftables脚本如下：\n{script}");
                let f = File::create(FILE_NAME_SCRIPT);
                if let Ok(mut file) = f {
                    file.write_all(script.as_bytes())?;
                }

                apply_nft_script(FILE_NAME_SCRIPT)?;
                latest_script.clone_from(&script);
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
    let script = build_new_script(
        &nat_cells,
        &runtime_config.dns,
        &runtime_config.access_control,
        &runtime_config.geoip,
        &runtime_config.egress_control,
    )?;
    prepare::check_and_prepare()?;
    let mut file = File::create(FILE_NAME_SCRIPT)?;
    file.write_all(script.as_bytes())?;
    apply_nft_script(FILE_NAME_SCRIPT)
}

struct RuntimeConfig {
    dns: DnsConfig,
    ddns: DdnsConfig,
    access_control: nat_common::AccessControlConfig,
    geoip: GeoIpConfig,
    egress_control: EgressControlConfig,
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

fn ddns_refresh_interval(config: &DdnsConfig) -> Result<u64, io::Error> {
    let interval = config.refresh_interval_seconds;
    if interval < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refresh_interval_seconds too low",
        ));
    }
    Ok(interval)
}

fn warn_short_ddns_interval_once(interval: u64, last_warned: &mut Option<u64>) {
    if interval < 60 && *last_warned != Some(interval) {
        warn!("DDNS refresh interval is very short, recommended >= 300 seconds for production.");
        *last_warned = Some(interval);
    } else if interval >= 60 {
        *last_warned = None;
    }
}

fn should_collect_stats_at(
    stats_config: &StatsConfig,
    last_collect: Option<chrono::DateTime<Local>>,
    now: chrono::DateTime<Local>,
) -> bool {
    if !stats_config.enabled {
        return false;
    }
    let Some(last_collect) = last_collect else {
        return true;
    };
    let elapsed = now.signed_duration_since(last_collect);
    elapsed.num_seconds() >= stats_config.collect_interval_seconds as i64
}

fn should_refresh_ddns_at(
    last_refresh: Option<chrono::DateTime<Local>>,
    refresh_interval_seconds: u64,
    now: chrono::DateTime<Local>,
) -> bool {
    let Some(last_refresh) = last_refresh else {
        return true;
    };
    now.signed_duration_since(last_refresh).num_seconds() >= refresh_interval_seconds as i64
}

fn next_loop_sleep(
    ddns_interval_seconds: u64,
    stats_config: &StatsConfig,
    last_ddns_refresh: Option<chrono::DateTime<Local>>,
    last_stats_collect: Option<chrono::DateTime<Local>>,
    now: chrono::DateTime<Local>,
) -> Duration {
    let ddns_remaining = remaining_seconds(last_ddns_refresh, ddns_interval_seconds, now);
    let stats_remaining = if stats_config.enabled {
        remaining_seconds(
            last_stats_collect,
            stats_config.collect_interval_seconds,
            now,
        )
    } else {
        ddns_remaining
    };
    let sleep_secs = ddns_remaining
        .min(stats_remaining)
        .clamp(1, MAIN_LOOP_MAX_SLEEP_SECS);
    Duration::from_secs(sleep_secs)
}

fn remaining_seconds(
    last_run: Option<chrono::DateTime<Local>>,
    interval_seconds: u64,
    now: chrono::DateTime<Local>,
) -> u64 {
    let Some(last_run) = last_run else {
        return 0;
    };
    let elapsed = now.signed_duration_since(last_run).num_seconds().max(0) as u64;
    interval_seconds.saturating_sub(elapsed)
}

fn collect_and_maybe_notify(
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    rule_labels: &HashMap<String, String>,
) -> Option<StatsState> {
    let now = Local::now().naive_local();
    let output = match Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            warn!("执行 nft -j list ruleset 失败，跳过本次流量统计: {e:?}");
            return None;
        }
    };
    if !output.status.success() {
        warn!(
            "nft -j list ruleset 返回失败，跳过本次流量统计: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let json = String::from_utf8_lossy(&output.stdout);
    let mut state = match traffic_stats::collect_from_nft_json_with_config(
        &stats_config.data_file,
        &json,
        rule_labels,
        now,
        stats_config,
    ) {
        Ok(state) => state,
        Err(e) => {
            warn!("采集 nft counter 失败，nat 主循环继续运行: {e}");
            return None;
        }
    };

    maybe_send_telegram(stats_config, telegram_config, &mut state, now);
    Some(state)
}

fn maybe_send_telegram(
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    state: &mut StatsState,
    now: chrono::NaiveDateTime,
) {
    if !traffic_stats::should_notify(telegram_config, state, now) {
        return;
    }
    let message = traffic_stats::format_telegram_message_with_options(
        state,
        now,
        telegram_config.notify_daily,
        telegram_config.notify_monthly,
        stats_config.traffic_mode,
    );
    match traffic_stats::send_telegram_with(telegram_config, &message, send_telegram_http) {
        Ok(()) => {
            state.last_notify_time = Some(now.format("%Y-%m-%d %H:%M:%S").to_string());
            if let Err(e) = traffic_stats::save_state(&stats_config.data_file, state) {
                warn!("保存 Telegram 通知时间失败: {e:?}");
            }
        }
        Err(e) => {
            warn!(
                "Telegram 通知发送失败 token={} err={}",
                traffic_stats::mask_bot_token(&telegram_config.bot_token),
                e
            );
        }
    }
}

fn send_telegram_http(url: &str, params: &[(&str, &str)]) -> Result<(), String> {
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
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn build_new_script(
    nat_cells: &[config::RuntimeCell],
    dns_config: &DnsConfig,
    access_config: &nat_common::AccessControlConfig,
    geoip_config: &GeoIpConfig,
    egress_config: &EgressControlConfig,
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
        match x.build_with_rule_index(index, dns_config, access_config, egress_config) {
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

    Ok(script)
}

#[derive(Debug, Clone)]
struct ForwardRuleSummary {
    rule_id: String,
    sport_expr: String,
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
            Some(ForwardRuleSummary {
                rule_id,
                sport_expr: sport.to_string(),
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
            Some(ForwardRuleSummary {
                rule_id,
                sport_expr: format!("{port_start}-{port_end}"),
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

fn apply_nft_script(script_path: &str) -> Result<(), io::Error> {
    apply_nft_script_with("/usr/sbin/nft", Path::new(BACKUP_DIR), script_path)
}

fn apply_nft_script_with(
    nft_bin: &str,
    backup_dir: &Path,
    script_path: &str,
) -> Result<(), io::Error> {
    check_nft_script(nft_bin, script_path)?;
    let ruleset_backup = backup_current_ruleset(nft_bin, backup_dir)?;
    let managed_backup = backup_managed_tables(nft_bin);
    info!("已备份当前 ruleset: {}", ruleset_backup.display());

    let output = Command::new(nft_bin).arg("-f").arg(script_path).output()?;
    info!(
        "执行/usr/sbin/nft -f {script_path} 执行结果: {}",
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        return Ok(());
    }

    error!("nft apply failed, rolling back managed tables from backup");
    rollback_managed_tables(nft_bin, backup_dir, &managed_backup)?;
    Err(io::Error::other(format!(
        "nft apply failed; managed tables rolled back; full ruleset backup: {}",
        ruleset_backup.display()
    )))
}

fn check_nft_script(nft_bin: &str, script_path: &str) -> Result<(), io::Error> {
    let output = Command::new(nft_bin)
        .arg("-c")
        .arg("-f")
        .arg(script_path)
        .output()?;
    info!(
        "执行/usr/sbin/nft -c -f {script_path} 执行结果: {}",
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn backup_current_ruleset(nft_bin: &str, backup_dir: &Path) -> Result<PathBuf, io::Error> {
    fs::create_dir_all(backup_dir)?;
    let backup_path = PathBuf::from(format!(
        "{}/ruleset-{}.nft",
        backup_dir.display(),
        Local::now().format("%Y%m%d%H%M%S")
    ));
    let output = Command::new(nft_bin).arg("list").arg("ruleset").output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to backup current ruleset: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    fs::write(&backup_path, output.stdout)?;
    Ok(backup_path)
}

fn backup_managed_tables(nft_bin: &str) -> Vec<(String, String, String)> {
    let mut backups = Vec::new();
    for (family, table) in MANAGED_TABLES {
        match Command::new(nft_bin)
            .arg("list")
            .arg("table")
            .arg(family)
            .arg(table)
            .output()
        {
            Ok(output) if output.status.success() => {
                backups.push((
                    family.to_string(),
                    table.to_string(),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                ));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if is_missing_nft_table_error(&stderr) {
                    info!("managed table {family} {table} does not exist yet, skip table backup");
                } else {
                    error!(
                        "failed to backup managed table {family} {table}: {}",
                        stderr.trim()
                    );
                }
            }
            Err(e) => {
                error!("failed to inspect managed table {family} {table}: {e:?}");
            }
        }
    }
    backups
}

fn is_missing_nft_table_error(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("table") && stderr.contains("does not exist")
}

fn rollback_managed_tables(
    nft_bin: &str,
    backup_dir: &Path,
    backups: &[(String, String, String)],
) -> Result<(), io::Error> {
    for (family, table) in MANAGED_TABLES {
        let output = Command::new(nft_bin)
            .arg("delete")
            .arg("table")
            .arg(family)
            .arg(table)
            .output();
        if let Ok(output) = output
            && !output.status.success()
        {
            info!(
                "delete managed table {family} {table} during rollback returned: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    if backups.is_empty() {
        info!("no managed table backup found; rollback only removed managed tables");
        return Ok(());
    }

    let rollback_path = PathBuf::from(format!(
        "{}/managed-rollback-{}.nft",
        backup_dir.display(),
        Local::now().format("%Y%m%d%H%M%S")
    ));
    let mut rollback_script = String::from("#!/usr/sbin/nft -f\n\n");
    for (_, _, table_script) in backups {
        rollback_script.push_str(table_script);
        rollback_script.push('\n');
    }
    fs::write(&rollback_path, rollback_script)?;

    let output = Command::new(nft_bin)
        .arg("-f")
        .arg(&rollback_path)
        .output()?;
    info!(
        "执行 managed rollback {} 结果: {}",
        rollback_path.display(),
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "managed rollback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod safe_apply_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
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
        })];
        let result = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        assert!(result.is_err());
        assert!(
            !result
                .unwrap_err()
                .to_string()
                .contains("dnat to 198.19.184.4")
        );
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
    fn egress_control_default_disabled_does_not_filter() {
        let cells = vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
            enabled: true,
            sport: 30080,
            dport: 80,
            domain: "8.8.8.8".to_string(),
            protocol: nat_common::Protocol::Tcp,
            ip_version: nat_common::IpVersion::V4,
            comment: None,
        })];
        let egress = nat_common::EgressControlConfig::default();
        let script = build_new_script(
            &cells,
            &DnsConfig::default(),
            &Default::default(),
            &Default::default(),
            &egress,
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
            }),
            config::RuntimeCell::Rule(nat_common::NftCell::Single {
                enabled: true,
                sport: 30081,
                dport: 80,
                domain: "10.100.0.10".to_string(),
                protocol: nat_common::Protocol::Tcp,
                ip_version: nat_common::IpVersion::V4,
                comment: None,
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
        )
        .unwrap();
        assert!(script.contains("add table ip self-nat"));
        assert!(script.contains("add table ip6 self-nat"));
        assert!(script.contains("add table ip self-filter"));
        assert!(script.contains("add table ip6 self-filter"));
        assert!(!script.contains("flush ruleset"));
    }
}
