#![deny(warnings)]
use crate::ip;
use ipnetwork::IpNetwork;
use log::{info, warn};
use nat_common::{
    AccessControlConfig, AccessControlMode, Chain, DdnsConfig, DnsConfig, EgressControlConfig,
    IpVersion, LastGoodConfig, NftCell, ParseError, Protocol, SnatConfig, SnatMode, StatsConfig,
    TelegramConfig, TomlConfig,
    last_good::{self, LastGoodState, ResolutionEvent, ResolutionLog, ResolveSource},
};
use std::env;
use std::fmt::Display;
use std::fs;
use std::io;
use std::str::FromStr;

/// 运行时Cell，包装NftCell和Comment
/// Comment仅用于运行时表示，不进入TOML配置
#[derive(Debug)]
pub enum RuntimeCell {
    Rule(NftCell),
    Comment(String),
}

impl Display for RuntimeCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeCell::Rule(cell) => write!(f, "{}", cell),
            RuntimeCell::Comment(content) => write!(f, "{}", content),
        }
    }
}

/// Protocol扩展trait，提供nftables专用方法
pub trait ProtocolExt {
    fn nft_proto(&self) -> &str;
}

impl ProtocolExt for Protocol {
    /// 返回nft规则中的协议部分
    /// all类型返回"meta l4proto { tcp, udp } th"，匹配所有传输层协议
    /// tcp/udp返回对应的协议名
    fn nft_proto(&self) -> &str {
        match self {
            Protocol::All => "meta l4proto { tcp, udp } th",
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// NftCell构建扩展trait，提供nftables规则构建方法
pub trait NftCellBuilder {
    #[allow(clippy::too_many_arguments)]
    fn build_with_rule_index(
        &self,
        rule_index: Option<usize>,
        dns_config: &DnsConfig,
        access_config: &AccessControlConfig,
        egress_config: &EgressControlConfig,
        snat_config: &SnatConfig,
        last_good_config: &LastGoodConfig,
        last_good_state: &LastGoodState,
        resolution_log: &ResolutionLog,
    ) -> Result<String, io::Error>;
}

impl NftCellBuilder for NftCell {
    fn build_with_rule_index(
        &self,
        rule_index: Option<usize>,
        dns_config: &DnsConfig,
        access_config: &AccessControlConfig,
        egress_config: &EgressControlConfig,
        snat_config: &SnatConfig,
        last_good_config: &LastGoodConfig,
        last_good_state: &LastGoodState,
        resolution_log: &ResolutionLog,
    ) -> Result<String, io::Error> {
        match self {
            NftCell::Drop { .. } => build_drop_rule(self),
            _ => {
                let (domain, ip_version, user_comment) = match &self {
                    NftCell::Single {
                        domain,
                        ip_version,
                        comment,
                        ..
                    } => (domain, ip_version, comment.clone()),
                    NftCell::Range {
                        domain,
                        ip_version,
                        comment,
                        ..
                    } => (domain, ip_version, comment.clone()),
                    NftCell::Redirect { ip_version, .. } => {
                        // Redirect 是本机重定向，不受 egress_control / snat / last-good 约束
                        return build_redirect_rules(self, ip_version, rule_index, access_config);
                    }
                    NftCell::Drop { .. } => unreachable!(),
                };

                let id_str = rule_index
                    .map(|i| format!("r{i}"))
                    .unwrap_or_else(|| "unknown".to_string());

                // 域名解析：先 live；失败时按配置回退到 last-good 缓存
                let (dst_ip, source) = match ip::remote_ip_with_dns(domain, ip_version, dns_config)
                {
                    Ok(ip) => {
                        resolution_log.record(ResolutionEvent::LiveResolved {
                            rule_id: id_str.clone(),
                            comment: user_comment.clone(),
                            domain: domain.clone(),
                            ip: ip.clone(),
                        });
                        (ip, ResolveSource::Live)
                    }
                    Err(e) => {
                        match last_good::fallback_ip(last_good_config, last_good_state, &id_str) {
                            Some(cached)
                                if matches_ip_version(&cached.last_good_ip, ip_version) =>
                            {
                                warn!(
                                    "domain resolve failed for rule id={id_str} ({domain}): {e}; using last-good IP {}",
                                    cached.last_good_ip
                                );
                                resolution_log.record(ResolutionEvent::LastGoodUsed {
                                    rule_id: id_str.clone(),
                                    comment: user_comment.clone(),
                                    domain: domain.clone(),
                                    ip: cached.last_good_ip.clone(),
                                    original_error: e.to_string(),
                                });
                                (cached.last_good_ip.clone(), ResolveSource::LastGood)
                            }
                            _ => {
                                warn!(
                                    "domain resolve failed for rule id={id_str} ({domain}): {e}; no usable last-good cache, skipping rule"
                                );
                                resolution_log.record(ResolutionEvent::ResolveFailedNoCache {
                                    rule_id: id_str.clone(),
                                    comment: user_comment.clone(),
                                    domain: domain.clone(),
                                    original_error: e.to_string(),
                                });
                                return Ok(String::new());
                            }
                        }
                    }
                };

                // egress_control 检查：目标 IP 必须在允许 CIDR 列表中（last-good IP 同样要检查）
                if egress_config.enabled && !egress_config.allows_ip(&dst_ip) {
                    warn!(
                        "egress_control 跳过规则 id={id_str} 目标 {dst_ip} 不在 allowed_target_cidrs (source={})",
                        source.as_str()
                    );
                    resolution_log.record(ResolutionEvent::EgressSkipped {
                        rule_id: id_str.clone(),
                        comment: user_comment.clone(),
                        ip: dst_ip.clone(),
                        source,
                    });
                    return Ok(String::new());
                }

                let mut result = String::new();

                // 检测实际IP类型并生成相应的规则
                let is_ipv6_target = dst_ip.contains(':');

                match ip_version {
                    IpVersion::V4 => {
                        if is_ipv6_target {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPv6 target address resolved but rule is configured for IPv4 only",
                            ));
                        }
                        result += &build_nat_rules(
                            self,
                            &dst_ip,
                            &IpVersion::V4,
                            rule_index,
                            access_config,
                            snat_config,
                        )?;
                    }
                    IpVersion::V6 => {
                        if !is_ipv6_target {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPv4 target address resolved but rule is configured for IPv6 only",
                            ));
                        }
                        result += &build_nat_rules(
                            self,
                            &dst_ip,
                            &IpVersion::V6,
                            rule_index,
                            access_config,
                            snat_config,
                        )?;
                    }
                    IpVersion::All => {
                        if is_ipv6_target {
                            result += &build_nat_rules(
                                self,
                                &dst_ip,
                                &IpVersion::V6,
                                rule_index,
                                access_config,
                                snat_config,
                            )?;
                        } else {
                            result += &build_nat_rules(
                                self,
                                &dst_ip,
                                &IpVersion::V4,
                                rule_index,
                                access_config,
                                snat_config,
                            )?;
                        }
                    }
                }

                Ok(result)
            }
        }
    }
}

impl RuntimeCell {
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_rule_index(
        &self,
        rule_index: Option<usize>,
        dns_config: &DnsConfig,
        access_config: &AccessControlConfig,
        egress_config: &EgressControlConfig,
        snat_config: &SnatConfig,
        last_good_config: &LastGoodConfig,
        last_good_state: &LastGoodState,
        resolution_log: &ResolutionLog,
    ) -> Result<String, io::Error> {
        match self {
            RuntimeCell::Rule(cell) => cell.build_with_rule_index(
                rule_index,
                dns_config,
                access_config,
                egress_config,
                snat_config,
                last_good_config,
                last_good_state,
                resolution_log,
            ),
            RuntimeCell::Comment(content) => Ok(content.clone() + "\n"),
        }
    }
}

/// 检查给定 IP 字符串是否与期望的 ip_version 兼容（用于校验 last-good 缓存里的 IP）
fn matches_ip_version(ip: &str, ip_version: &IpVersion) -> bool {
    let parsed = match ip.parse::<std::net::IpAddr>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    match ip_version {
        IpVersion::V4 => parsed.is_ipv4(),
        IpVersion::V6 => parsed.is_ipv6(),
        IpVersion::All => true,
    }
}

/// 构建过滤规则的nftables脚本
fn build_drop_rule(cell: &NftCell) -> Result<String, io::Error> {
    let NftCell::Drop {
        chain,
        src_ip,
        dst_ip,
        src_port,
        src_port_end,
        dst_port,
        dst_port_end,
        protocol,
        comment,
    } = cell
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected Drop cell",
        ));
    };

    let mut result = String::new();

    // 判断IP版本：如果指定了src_ip或dst_ip，根据其判断family
    // 如果没有指定IP地址，则在v4和v6中都添加规则
    let mut ip_families = Vec::new();

    if let Some(ip) = src_ip.as_ref().or(dst_ip.as_ref()) {
        // 根据IP地址判断family
        if let Ok(network) = IpNetwork::from_str(ip) {
            if network.is_ipv6() {
                ip_families.push(IpVersion::V6);
            } else {
                ip_families.push(IpVersion::V4);
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("无效的IP地址: {}", ip),
            ));
        }
    } else {
        // 没有指定IP地址，在v4和v6中都添加规则
        ip_families.push(IpVersion::V4);
        ip_families.push(IpVersion::V6);
    }

    for ip_version in ip_families {
        result += &build_drop_rule_for_family(
            cell,
            chain,
            src_ip,
            dst_ip,
            src_port,
            src_port_end,
            dst_port,
            dst_port_end,
            protocol,
            comment,
            &ip_version,
        )?;
    }

    Ok(result)
}

/// 为特定IP family构建过滤规则
#[allow(clippy::too_many_arguments)]
fn build_drop_rule_for_family(
    cell: &NftCell,
    chain: &Chain,
    src_ip: &Option<String>,
    dst_ip: &Option<String>,
    src_port: &Option<u16>,
    src_port_end: &Option<u16>,
    dst_port: &Option<u16>,
    dst_port_end: &Option<u16>,
    protocol: &Protocol,
    comment: &Option<String>,
    ip_version: &IpVersion,
) -> Result<String, io::Error> {
    let (family, ip_prefix) = match ip_version {
        IpVersion::V4 => ("ip", "ip"),
        IpVersion::V6 => ("ip6", "ip6"),
        IpVersion::All => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IpVersion::All should be handled at caller level",
            ));
        }
    };

    let chain_name = match chain {
        Chain::Input => "INPUT",
        Chain::Forward => "FORWARD",
    };

    let mut conditions = Vec::new();

    // 添加源IP条件（IP条件应该在协议条件之前）
    if let Some(ip) = src_ip {
        conditions.push(format!("{} saddr {}", ip_prefix, ip));
    }

    // 添加目标IP条件
    if let Some(ip) = dst_ip {
        conditions.push(format!("{} daddr {}", ip_prefix, ip));
    }

    // 添加协议条件
    if *protocol != Protocol::All || src_port.is_some() || dst_port.is_some() {
        let proto = protocol.nft_proto();
        conditions.push(proto.to_string());
    }

    // 添加源端口条件
    if let Some(port) = src_port {
        if let Some(end) = src_port_end {
            conditions.push(format!("sport {}-{}", port, end));
        } else {
            conditions.push(format!("sport {}", port));
        }
    }

    // 添加目标端口条件
    if let Some(port) = dst_port {
        if let Some(end) = dst_port_end {
            conditions.push(format!("dport {}-{}", port, end));
        } else {
            conditions.push(format!("dport {}", port));
        }
    }

    let conditions_str = conditions.join(" ");
    let comment_str = if let Some(cmt) = comment {
        format!(" comment \"{}\"", cmt)
    } else {
        format!(" comment \"{}\"", cell)
    };

    let rule = format!(
        "add rule {family} self-filter {chain_name} {conditions_str} counter drop{comment_str}\n\n"
    );

    Ok(rule)
}

/// 解析 SNAT 动作字符串
/// 返回 None 表示不生成 POSTROUTING SNAT 规则；
/// Some("masquerade") 或 Some("snat to <ip>") 对应具体动作。
/// IPv6 暂不支持 fixed_source_ip（仅 IPv4），回退到 masquerade，并保留 env-var legacy 路径。
pub(crate) fn resolve_snat_action(
    snat_config: &SnatConfig,
    ip_version: &IpVersion,
    legacy_env_var: &str,
) -> Option<String> {
    match snat_config.mode {
        SnatMode::Off => None,
        SnatMode::Fixed => {
            let ip = snat_config.fixed_source_ip.trim();
            // 验证已经在 SnatConfig::validate() 中完成；这里仅保险地回退到 masquerade
            match ip_version {
                IpVersion::V4 if !ip.is_empty() => Some(format!("snat to {ip}")),
                _ => Some("masquerade".to_string()),
            }
        }
        SnatMode::Masquerade => {
            // legacy 环境变量回退路径：保留旧用户的兼容性
            if let Ok(ip) = env::var(legacy_env_var) {
                Some(format!("snat to {ip}"))
            } else {
                Some("masquerade".to_string())
            }
        }
    }
}

fn build_nat_rules(
    cell: &NftCell,
    dst_ip: &str,
    ip_version: &IpVersion,
    rule_index: Option<usize>,
    access_config: &AccessControlConfig,
    snat_config: &SnatConfig,
) -> Result<String, io::Error> {
    let (family, env_var, localhost_addr, fmt_ip) = match ip_version {
        IpVersion::V4 => ("ip", "nat_local_ip", "127.0.0.1", dst_ip.to_string()),
        IpVersion::V6 => ("ip6", "nat_local_ipv6", "::1", format!("[{}]", dst_ip)),
        IpVersion::All => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IpVersion::All should be handled at caller level",
            ));
        }
    };

    let snat_action = resolve_snat_action(snat_config, ip_version, env_var);

    match cell {
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            comment,
            ..
        } => {
            let proto = protocol.nft_proto();
            let access_condition = access_condition(family, access_config);
            if access_config.mode == AccessControlMode::Whitelist && access_condition.is_none() {
                return Ok(String::new());
            }
            let access_condition = access_condition.unwrap_or_default();
            let blacklist_drop = build_access_drop_rules(
                family,
                access_config,
                protocol,
                &format!("{port_start}-{port_end}"),
                rule_index,
            );
            let stats_comment = nat_rule_comment(
                rule_index,
                "range",
                &format!("{port_start}-{port_end}"),
                domain,
                &format!("{port_start}-{port_end}"),
                protocol,
                comment.as_deref(),
            );
            let postrouting = match &snat_action {
                Some(action) => format!(
                    "add rule {family} self-nat POSTROUTING ct state new {family} daddr {dst_ip} {proto} dport {port_start}-{port_end} counter {action} comment \"{cell}\"\n"
                ),
                None => String::new(),
            };
            let res = format!(
                "{blacklist_drop}add rule {family} self-nat PREROUTING ct state new {access_condition}{proto} dport {port_start}-{port_end} counter dnat to {fmt_ip}:{port_start}-{port_end} comment \"{stats_comment}\"\n\
                {postrouting}\n\
                {}\
                ",
                build_traffic_counter_rules(
                    family,
                    dst_ip,
                    protocol,
                    &format!("{port_start}-{port_end}"),
                    &stats_comment,
                ),
            );
            Ok(res)
        }
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            comment,
            ..
        } => {
            let proto = protocol.nft_proto();
            let access_condition = access_condition(family, access_config);
            if access_config.mode == AccessControlMode::Whitelist && access_condition.is_none() {
                return Ok(String::new());
            }
            let access_condition = access_condition.unwrap_or_default();
            let blacklist_drop = build_access_drop_rules(
                family,
                access_config,
                protocol,
                &sport.to_string(),
                rule_index,
            );
            let stats_comment = nat_rule_comment(
                rule_index,
                "single",
                &sport.to_string(),
                domain,
                &dport.to_string(),
                protocol,
                comment.as_deref(),
            );
            let is_localhost = domain == "localhost" || domain == localhost_addr;
            if is_localhost {
                // 重定向到本机
                let res = format!(
                    "{blacklist_drop}add rule {family} self-nat PREROUTING ct state new {access_condition}{proto} dport {sport} counter redirect to :{dport}  comment \"{stats_comment}\"\n\n\
                    ",
                );
                Ok(res)
            } else {
                // 转发到其他机器
                let postrouting = match &snat_action {
                    Some(action) => format!(
                        "add rule {family} self-nat POSTROUTING ct state new {family} daddr {dst_ip} {proto} dport {dport} counter {action} comment \"{cell}\"\n"
                    ),
                    None => String::new(),
                };
                let res = format!(
                    "{blacklist_drop}add rule {family} self-nat PREROUTING ct state new {access_condition}{proto} dport {sport} counter dnat to {fmt_ip}:{dport}  comment \"{stats_comment}\"\n\
                    {postrouting}\n\
                    {}\
                    ",
                    build_traffic_counter_rules(
                        family,
                        dst_ip,
                        protocol,
                        &dport.to_string(),
                        &stats_comment,
                    ),
                );
                Ok(res)
            }
        }
        NftCell::Redirect { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Redirect cell should be built via build_redirect_rules",
        )),
        NftCell::Drop { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Drop cell should be built via build_drop_rule",
        )),
    }
}

fn build_redirect_rules(
    cell: &NftCell,
    ip_version: &IpVersion,
    rule_index: Option<usize>,
    access_config: &AccessControlConfig,
) -> Result<String, io::Error> {
    let mut result = String::new();

    match ip_version {
        IpVersion::All => {
            result += &build_redirect_rule(cell, &IpVersion::V4, rule_index, access_config)?;
            result += &build_redirect_rule(cell, &IpVersion::V6, rule_index, access_config)?;
        }
        _ => {
            result += &build_redirect_rule(cell, ip_version, rule_index, access_config)?;
        }
    }

    Ok(result)
}

fn build_redirect_rule(
    cell: &NftCell,
    ip_version: &IpVersion,
    rule_index: Option<usize>,
    access_config: &AccessControlConfig,
) -> Result<String, io::Error> {
    let family = match ip_version {
        IpVersion::V4 => "ip",
        IpVersion::V6 => "ip6",
        IpVersion::All => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IP version for redirect rule cannot be All",
            ));
        }
    };
    match cell {
        NftCell::Redirect {
            src_port,
            src_port_end,
            dst_port,
            protocol,
            comment,
            ..
        } => {
            let proto = protocol.nft_proto();
            let access_condition = access_condition(family, access_config);
            if access_config.mode == AccessControlMode::Whitelist && access_condition.is_none() {
                return Ok(String::new());
            }
            let access_condition = access_condition.unwrap_or_default();
            let sport = if let Some(end) = src_port_end {
                format!("{src_port}-{end}")
            } else {
                src_port.to_string()
            };
            let stats_comment = nat_rule_comment(
                rule_index,
                "redirect",
                &sport,
                "localhost",
                &dst_port.to_string(),
                protocol,
                comment.as_deref(),
            );
            let res = if let Some(end) = src_port_end {
                let blacklist_drop = build_access_drop_rules(
                    family,
                    access_config,
                    protocol,
                    &format!("{src_port}-{end}"),
                    rule_index,
                );
                // Range redirect
                format!(
                    "{blacklist_drop}add rule {family} self-nat PREROUTING ct state new {access_condition}{proto} dport {src_port}-{src_port_end} counter redirect to :{dst_port} comment \"{stats_comment}\"\n\n\
                    ",
                    src_port_end = end,
                )
            } else {
                let blacklist_drop = build_access_drop_rules(
                    family,
                    access_config,
                    protocol,
                    &src_port.to_string(),
                    rule_index,
                );
                // Single port redirect
                format!(
                    "{blacklist_drop}add rule {family} self-nat PREROUTING ct state new {access_condition}{proto} dport {src_port} counter redirect to :{dst_port} comment \"{stats_comment}\"\n\n\
                    ",
                )
            };
            Ok(res)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not a Redirect cell",
        )),
    }
}

fn nat_rule_comment(
    rule_index: Option<usize>,
    _rule_type: &str,
    _sport: &str,
    _target: &str,
    _dport: &str,
    _protocol: &Protocol,
    _user_comment: Option<&str>,
) -> String {
    format!("nat-rule:id={}", short_rule_id(rule_index))
}

fn build_traffic_counter_rules(
    family: &str,
    dst_ip: &str,
    protocol: &Protocol,
    dport: &str,
    nat_rule_comment: &str,
) -> String {
    let proto = protocol.nft_proto();
    let out_comment = nat_traffic_comment(nat_rule_comment, "out");
    let in_comment = nat_traffic_comment(nat_rule_comment, "in");
    format!(
        "add rule {family} self-filter FORWARD {family} daddr {dst_ip} {proto} dport {dport} counter comment \"{out_comment}\"\n\
        add rule {family} self-filter FORWARD {family} saddr {dst_ip} {proto} sport {dport} counter comment \"{in_comment}\"\n\n",
    )
}

fn nat_traffic_comment(nat_rule_comment: &str, direction: &str) -> String {
    let id = nat_rule_comment
        .strip_prefix("nat-rule:id=")
        .unwrap_or("unknown");
    format!("nat-traffic:id={id},dir={direction}")
}

fn access_condition(family: &str, config: &AccessControlConfig) -> Option<String> {
    if config.mode != AccessControlMode::Whitelist {
        return Some(String::new());
    }
    access_entries_for_family(family, &config.entries)
        .map(|entries| format!("{family} saddr {{ {entries} }} "))
}

fn build_access_drop_rules(
    family: &str,
    config: &AccessControlConfig,
    protocol: &Protocol,
    listen_port: &str,
    rule_index: Option<usize>,
) -> String {
    if config.mode != AccessControlMode::Blacklist {
        return String::new();
    }
    let Some(entries) = access_entries_for_family(family, &config.entries) else {
        return String::new();
    };
    let proto = protocol.nft_proto();
    format!(
        "add rule {family} self-nat PREROUTING {family} saddr {{ {entries} }} {proto} dport {listen_port} counter drop comment \"{}\"\n",
        nat_access_comment("blacklist", rule_index)
    )
}

fn access_entries_for_family(family: &str, entries: &[String]) -> Option<String> {
    let want_ipv6 = family == "ip6";
    let values: Vec<String> = entries
        .iter()
        .filter(|entry| access_entry_is_ipv6(entry) == want_ipv6)
        .cloned()
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

fn access_entry_is_ipv6(entry: &str) -> bool {
    entry.contains(':')
}

fn nat_access_comment(mode: &str, rule_index: Option<usize>) -> String {
    format!("nat-access:id={},mode={mode}", short_rule_id(rule_index))
}

fn short_rule_id(rule_index: Option<usize>) -> String {
    rule_index
        .map(|index| format!("r{index}"))
        .unwrap_or_else(|| "unknown".to_string())
}

/// 解析一行legacy配置，返回RuntimeCell或错误
/// 注释行返回 Some(RuntimeCell::Comment)
/// 空行返回 None
/// 规则行返回 Some(RuntimeCell::Rule)
fn parse_legacy_line(line: &str) -> Option<RuntimeCell> {
    let line = line.trim();

    // 处理注释
    if line.starts_with('#') {
        return Some(RuntimeCell::Comment(line.to_string()));
    }

    // 使用 nat-common 的 TryFrom 解析（包括NAT规则和Drop规则）
    match NftCell::try_from(line) {
        Ok(cell) => Some(RuntimeCell::Rule(cell)),
        Err(ParseError::Skip) => None,
        Err(ParseError::InvalidFormat(msg)) => {
            log::warn!("跳过无效配置行: {}", msg);
            None
        }
    }
}

pub(crate) fn example(conf: &str) {
    info!("请在 {} 编写转发规则，内容类似：", &conf);
    info!(
        "{}",
        "SINGLE,10000,443,baidu.com,all,ipv4\n\
                    RANGE,1000,2000,baidu.com,tcp,ipv6\n\
                    REDIRECT,8000,3128,all,ipv4\n\
                    REDIRECT,8000-9000,3128,tcp,all\n\
                    DROP,input,src_ip=180.213.132.211,all,ipv4\n\
                    DROP,input,src_ip=240e:328:1301::/48,all,ipv6\n\
                    DROP,forward,dst_port=22,tcp,all\n\
                    # 格式: TYPE,port(s),port/domain,protocol,ip_version\n\
                    # TYPE: SINGLE, RANGE, REDIRECT 或 DROP\n\
                    # REDIRECT格式: REDIRECT,src_port,dst_port 或 REDIRECT,src_port-src_port_end,dst_port\n\
                    # DROP格式: DROP,chain,key=value,...,protocol,ip_version\n\
                    #   chain: input 或 forward\n\
                    #   key=value: src_ip=IP, dst_ip=IP, src_port=PORT, dst_port=PORT\n\
                    # protocol: tcp, udp, all\n\
                    # ip_version: ipv4, ipv6, all"
    )
}

pub fn read_config(conf: &str) -> Result<Vec<RuntimeCell>, io::Error> {
    let mut cells = vec![];
    let mut contents = fs::read_to_string(conf)?;
    contents = contents.replace("\r\n", "\n");

    for line in contents.lines() {
        if let Some(cell) = parse_legacy_line(line) {
            cells.push(cell);
        }
    }
    Ok(cells)
}

// 读取TOML配置文件
pub fn read_toml_config(toml_path: &str) -> Result<Vec<RuntimeCell>, io::Error> {
    let contents = fs::read_to_string(toml_path)?;

    // 使用 nat-common 的解析和验证
    let config = TomlConfig::from_toml_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut cells = Vec::new();

    // 处理所有规则（包括NAT和Filter）
    for rule in config.rules.into_iter().filter(NftCell::enabled) {
        // 如果有注释，先添加注释
        let comment = match &rule {
            NftCell::Single { comment, .. } => comment.clone(),
            NftCell::Range { comment, .. } => comment.clone(),
            NftCell::Redirect { comment, .. } => comment.clone(),
            NftCell::Drop { comment, .. } => comment.clone(),
        };

        if let Some(comment_text) = comment {
            cells.push(RuntimeCell::Comment(format!("# {comment_text}")));
        }

        cells.push(RuntimeCell::Rule(rule));
    }

    Ok(cells)
}

// TOML配置示例函数
pub fn toml_example(conf: &str) -> Result<(), io::Error> {
    let example_config = TomlConfig {
        rules: vec![
            NftCell::Single {
                enabled: true,
                sport: 10000,
                dport: 443,
                domain: "baidu.com".to_string(),
                protocol: Protocol::All,
                ip_version: IpVersion::V4,
                comment: Some("百度HTTPS服务转发示例".to_string()),
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            },
            NftCell::Range {
                enabled: true,
                port_start: 1000,
                port_end: 2000,
                domain: "baidu.com".to_string(),
                protocol: Protocol::Tcp,
                ip_version: IpVersion::V4,
                comment: Some("端口范围转发示例".to_string()),
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            },
            NftCell::Redirect {
                enabled: true,
                src_port: 8000,
                src_port_end: None,
                dst_port: 3128,
                protocol: Protocol::All,
                ip_version: IpVersion::V4,
                comment: Some("单端口重定向到本机示例".to_string()),
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            },
            NftCell::Redirect {
                enabled: true,
                src_port: 30001,
                src_port_end: Some(39999),
                dst_port: 45678,
                protocol: Protocol::Tcp,
                ip_version: IpVersion::V4,
                comment: Some("端口范围重定向到本机示例".to_string()),
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: nat_common::QuotaPeriod::default(),
                quota_action: nat_common::QuotaAction::default(),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: Some("180.213.132.211".to_string()),
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: None,
                dst_port_end: None,
                protocol: Protocol::All,
                comment: Some("阻止特定IPv4地址".to_string()),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: Some("240e:328:1301::/48".to_string()),
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: None,
                dst_port_end: None,
                protocol: Protocol::All,
                comment: Some("阻止IPv6网段".to_string()),
            },
            NftCell::Drop {
                chain: Chain::Input,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                src_port_end: None,
                dst_port: Some(22),
                dst_port_end: None,
                protocol: Protocol::Tcp,
                comment: Some("阻止SSH端口访问".to_string()),
            },
        ],
        dns: DnsConfig::default(),
        ddns: DdnsConfig::default(),
        stats: StatsConfig::default(),
        telegram: TelegramConfig::default(),
        access_control: AccessControlConfig::default(),
        geoip: Default::default(),
        egress_control: Default::default(),
        snat: Default::default(),
        mss_clamp: Default::default(),
        last_good: Default::default(),
        audit: Default::default(),
        quota: Default::default(),
        ui: Default::default(),
    };

    let toml_str = example_config
        .to_toml_string()
        .map_err(|e| io::Error::other(format!("序列化TOML失败: {e}")))?;

    info!("请在 {} 编写转发规则，内容类似：\n {toml_str}", &conf);

    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod redirect_parse_tests {
    use super::*;

    #[test]
    fn test_parse_redirect_single_port() {
        let line = "REDIRECT,8000,3128";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            }) => {
                assert_eq!(src_port, 8000);
                assert_eq!(src_port_end, None);
                assert_eq!(dst_port, 3128);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_redirect_port_range() {
        let line = "REDIRECT,30001-39999,45678";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            }) => {
                assert_eq!(src_port, 30001);
                assert_eq!(src_port_end, Some(39999));
                assert_eq!(dst_port, 45678);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_redirect_with_protocol() {
        let line = "REDIRECT,9000,8080,tcp";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Redirect {
                src_port, dst_port, ..
            }) => {
                assert_eq!(src_port, 9000);
                assert_eq!(dst_port, 8080);
            }
            other => panic!("Expected Redirect variant, got {:?}", other),
        }
    }

    #[test]
    fn test_backward_compatibility_localhost() {
        let line = "SINGLE,2222,22,localhost";
        let result = parse_legacy_line(line);
        assert!(result.is_some());
        match result.unwrap() {
            RuntimeCell::Rule(NftCell::Single {
                sport,
                dport,
                domain,
                ..
            }) => {
                assert_eq!(sport, 2222);
                assert_eq!(dport, 22);
                assert_eq!(domain, "localhost");
            }
            other => panic!("Expected Single variant, got {:?}", other),
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod redirect_build_tests {
    use super::*;

    fn nft_comment_values(script: &str) -> Vec<&str> {
        script
            .split("comment \"")
            .skip(1)
            .filter_map(|part| part.split('"').next())
            .collect()
    }

    #[test]
    fn generated_nft_comments_are_short_stable_ids() {
        let long_comment = "x".repeat(300);
        let cell = NftCell::Single {
            enabled: true,
            sport: 34120,
            dport: 44336,
            domain: "93.184.216.34".to_string(),
            protocol: Protocol::All,
            ip_version: IpVersion::V4,
            comment: Some(long_comment.clone()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        };
        let access = AccessControlConfig {
            mode: AccessControlMode::Blacklist,
            entries: vec!["1.2.3.4".to_string()],
        };

        let result = cell
            .build_with_rule_index(
                Some(0),
                &DnsConfig::default(),
                &access,
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &ResolutionLog::new(),
            )
            .unwrap();
        let comments = nft_comment_values(&result);

        assert!(comments.iter().all(|comment| comment.len() <= 120));
        assert!(comments.contains(&"nat-rule:id=r0"));
        assert!(comments.contains(&"nat-traffic:id=r0,dir=out"));
        assert!(comments.contains(&"nat-traffic:id=r0,dir=in"));
        assert!(comments.contains(&"nat-access:id=r0,mode=blacklist"));
        assert!(!result.contains(&long_comment));
    }

    #[test]
    fn chinese_user_comment_is_not_written_to_nft_comment() {
        let long_chinese_comment = "这是一个很长的中文备注".repeat(30);
        let cell = NftCell::Redirect {
            enabled: true,
            src_port: 8000,
            src_port_end: None,
            dst_port: 3128,
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: Some(long_chinese_comment.clone()),
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        };

        let result = cell
            .build_with_rule_index(
                Some(7),
                &DnsConfig::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &ResolutionLog::new(),
            )
            .unwrap();
        let comments = nft_comment_values(&result);

        assert!(comments.iter().all(|comment| comment.len() <= 120));
        assert!(comments.contains(&"nat-rule:id=r7"));
        assert!(!result.contains(&long_chinese_comment));
    }

    #[test]
    fn long_target_and_protocol_all_do_not_make_nft_comments_long() {
        let long_domain = format!("{}.example.com", "very-long-label".repeat(20));
        let rule_comment = nat_rule_comment(
            Some(99),
            "single",
            "34120",
            &long_domain,
            "44336",
            &Protocol::All,
            Some("user comment that should stay outside nft comments"),
        );
        let out_comment = nat_traffic_comment(&rule_comment, "out");
        let in_comment = nat_traffic_comment(&rule_comment, "in");
        let access_comment = nat_access_comment("blacklist", Some(99));

        assert_eq!(rule_comment, "nat-rule:id=r99");
        assert_eq!(out_comment, "nat-traffic:id=r99,dir=out");
        assert_eq!(in_comment, "nat-traffic:id=r99,dir=in");
        assert_eq!(access_comment, "nat-access:id=r99,mode=blacklist");
        for comment in [rule_comment, out_comment, in_comment, access_comment] {
            assert!(comment.len() <= 120);
        }
    }

    #[test]
    fn test_build_redirect_single_ipv4() {
        let cell = NftCell::Redirect {
            enabled: true,
            src_port: 8000,
            src_port_end: None,
            dst_port: 3128,
            protocol: Protocol::All,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        };

        let result = cell
            .build_with_rule_index(
                None,
                &DnsConfig::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &ResolutionLog::new(),
            )
            .unwrap();
        // all协议使用th dport匹配所有传输层协议
        assert!(result.contains("add rule ip self-nat PREROUTING ct state new meta l4proto { tcp, udp } th dport 8000 counter redirect to :3128"));
        assert!(!result.contains("ip6")); // Should not have IPv6 rules
    }

    #[test]
    fn test_build_redirect_range_ipv4() {
        let cell = NftCell::Redirect {
            enabled: true,
            src_port: 30001,
            src_port_end: Some(39999),
            dst_port: 45678,
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        };

        let result = cell
            .build_with_rule_index(
                None,
                &DnsConfig::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &ResolutionLog::new(),
            )
            .unwrap();
        // tcp协议只生成tcp规则
        assert!(result.contains(
            "add rule ip self-nat PREROUTING ct state new tcp dport 30001-39999 counter redirect to :45678"
        ));
        assert!(!result.contains("udp")); // tcp协议不应该包含udp规则
        assert!(!result.contains("ip6")); // Should not have IPv6 rules
    }

    #[test]
    fn test_build_redirect_both_ipv() {
        let cell = NftCell::Redirect {
            enabled: true,
            src_port: 5000,
            src_port_end: None,
            dst_port: 4000,
            protocol: Protocol::All,
            ip_version: IpVersion::All,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: nat_common::QuotaPeriod::default(),
            quota_action: nat_common::QuotaAction::default(),
        };

        let result = cell
            .build_with_rule_index(
                None,
                &DnsConfig::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &Default::default(),
                &ResolutionLog::new(),
            )
            .unwrap();
        // all协议应该使用th dport，同时包含IPv4和IPv6
        assert!(result.contains("add rule ip self-nat PREROUTING ct state new meta l4proto { tcp, udp } th dport 5000 counter redirect to :4000"));
        assert!(
            result.contains("add rule ip6 self-nat PREROUTING ct state new meta l4proto { tcp, udp } th dport 5000 counter redirect to :4000")
        );
    }

    #[test]
    fn disabled_rules_are_not_loaded_into_runtime_cells() {
        let path = std::env::temp_dir().join(format!(
            "nat-disabled-rule-{}-{}.toml",
            std::process::id(),
            chrono::Local::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        fs::write(
            &path,
            r#"
[[rules]]
type = "single"
enabled = false
sport = 30080
dport = 80
domain = "example.com"
"#,
        )
        .unwrap();
        let cells = read_toml_config(path.to_str().unwrap()).unwrap();
        fs::remove_file(path).unwrap();
        assert!(cells.is_empty());
    }
}
