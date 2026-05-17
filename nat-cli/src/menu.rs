use chrono::Local;
use nat_common::{
    AccessControlMode, Args, DdnsConfig, IpVersion, NftCell, Protocol, StatsConfig, TomlConfig,
    stats as traffic_stats,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TOML_CONFIG: &str = "/etc/nat.toml";
const CONFIG_BACKUP_DIR: &str = "/etc/nftables-nat/backups/config";

pub fn run_menu(config_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config_path.unwrap_or(DEFAULT_TOML_CONFIG);
    let mut last_manual_refresh: Option<chrono::DateTime<Local>> = None;
    loop {
        print_menu();
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => show_rules(config_path)?,
            "2" => add_single_interactive(config_path)?,
            "3" => add_range_interactive(config_path)?,
            "4" => delete_rule_interactive(config_path)?,
            "5" => println!("TODO: 当前规则模型没有 enabled 字段，Phase 4A 暂不实现启用/禁用。"),
            "6" => show_nft_rules()?,
            "7" => show_stats(None),
            "8" => refresh_ddns_interactive(config_path, &mut last_manual_refresh)?,
            "9" => {
                let backup = backup_config(config_path)?;
                println!("已备份: {}", backup.display());
            }
            "10" => restore_config_interactive(config_path)?,
            "11" => access_control_menu(config_path)?,
            "12" => show_recent_source_design(),
            "13" => show_status_design(),
            "0" => break,
            _ => println!("未知选项: {}", choice.trim()),
        }
    }
    Ok(())
}

fn print_menu() {
    println!(
        r#"====================================
nftables-nat-rust 管理菜单
====================================
1) 查看当前转发规则
2) 添加单端口转发
3) 添加端口段转发
4) 删除转发规则
5) 启用/禁用规则
6) 查看当前 nft 规则
7) 查看 stats 流量统计
8) 手动刷新 DDNS / 域名目标
9) 备份当前配置
10) 从备份恢复配置
11) 白名单/黑名单管理
12) 最近来源 IP 观察
13) WebUI / BBR / Telegram 状态
0) 退出
===================================="#
    );
}

fn prompt(label: &str) -> Result<String, io::Error> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn load_toml_config(path: &str) -> Result<TomlConfig, io::Error> {
    let content = fs::read_to_string(path)?;
    TomlConfig::from_toml_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
        return Ok(());
    }
    for (index, rule) in config.rules.iter().enumerate() {
        println!("{index}) {}", format_rule(rule));
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
    println!("已添加规则。未自动应用；如需立即生效，请通过已有 nat 服务安全重载流程处理。");
    ask_apply_hint();
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
    println!("已添加端口段规则。当前模型会转发到目标同端口段。");
    ask_apply_hint();
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
    println!("已删除规则。");
    ask_apply_hint();
    Ok(())
}

fn ask_apply_hint() {
    println!("Phase 4A 不会绕过安全应用流程直接执行 nft -f。");
    println!("如需应用配置，请使用现有 nat 服务，由其执行 nft -c、备份和失败回滚。");
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

fn show_stats(path: Option<&str>) {
    let default_stats_config;
    let data_file = match path {
        Some(path) => path,
        None => {
            default_stats_config = StatsConfig::default();
            default_stats_config.data_file.as_str()
        }
    };
    if !Path::new(data_file).exists() {
        println!("stats not initialized yet");
        return;
    }
    let state = traffic_stats::load_state(data_file);
    println!(
        "今日流量: {}",
        traffic_stats::format_bytes(state.daily_total_bytes)
    );
    println!(
        "本月流量: {}",
        traffic_stats::format_bytes(state.monthly_total_bytes)
    );
    println!(
        "最近采集: {}",
        state
            .last_collect_time
            .clone()
            .unwrap_or_else(|| "-".to_string())
    );
    println!("TOP 10 规则:");
    for (index, line) in format_stats_top10(&state).iter().enumerate() {
        println!("{}. {line}", index + 1);
    }
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
    println!("已恢复配置: {}", backups[index].display());
    ask_apply_hint();
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
        println!(
            r#"1) 查看当前配置
2) 设置模式 off
3) 设置模式 whitelist
4) 设置模式 blacklist
5) 添加 IP/CIDR
6) 删除 IP/CIDR
7) 清空 entries
8) 保存并应用
0) 返回
===================================="#
        );
        let choice = prompt("请选择操作: ")?;
        match choice.trim() {
            "1" => print_access_entries(&config),
            "2" => config.access_control.mode = AccessControlMode::Off,
            "3" => {
                println!(
                    "白名单只影响本项目转发端口，不影响 SSH/WebUI；请确认需要访问转发端口的来源 IP 已加入白名单。"
                );
                if confirm("确认切换到 whitelist? [y/N]: ")? {
                    config.access_control.mode = AccessControlMode::Whitelist;
                }
            }
            "4" => {
                println!("黑名单只阻断本项目转发端口，不影响 SSH/WebUI。");
                if confirm("确认切换到 blacklist? [y/N]: ")? {
                    config.access_control.mode = AccessControlMode::Blacklist;
                }
            }
            "5" => {
                let entry = prompt("请输入 IP/CIDR: ")?;
                validate_access_entry(&entry)?;
                add_access_entry(&mut config, entry);
            }
            "6" => delete_access_entry_interactive(&mut config)?,
            "7" => {
                if confirm("确认清空 entries? [y/N]: ")? {
                    clear_access_entries(&mut config);
                }
            }
            "8" => {
                config
                    .access_control
                    .validate()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                backup_config(path)?;
                save_toml_config(path, &config)?;
                println!("访问控制配置已保存。");
                if confirm("是否立即通过安全流程应用? [y/N]: ")? {
                    let args = Args {
                        menu: false,
                        compatible_config_file: None,
                        toml: Some(path.to_string()),
                    };
                    super::refresh_once(&args)?;
                }
            }
            "0" => break,
            _ => println!("未知选项: {}", choice.trim()),
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
    println!("Phase 4A 设计：最近来源 IP 观察只展示命中，不自动封禁。");
    println!("后续可由用户手动选择加入 blacklist，避免误封。");
}

fn show_status_design() {
    println!("TODO: WebUI / BBR / Telegram 状态将在后续阶段整合。");
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
        sport,
        dport,
        domain,
        protocol,
        ip_version,
        comment,
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
        port_start,
        port_end,
        domain,
        protocol,
        ip_version,
        comment,
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
    use nat_common::stats::{RuleTraffic, StatsState};

    #[test]
    fn adds_single_rule_to_toml_config() {
        let mut config = TomlConfig {
            rules: Vec::new(),
            dns: Default::default(),
            ddns: Default::default(),
            stats: StatsConfig::default(),
            telegram: Default::default(),
            access_control: Default::default(),
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
}
