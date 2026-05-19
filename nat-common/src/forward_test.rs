use crate::{AccessControlConfig, NftCell};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestCounter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleTestCounters {
    pub nat_rule: TestCounter,
    pub out: TestCounter,
    pub r#in: TestCounter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestableRule {
    pub index: usize,
    pub id: String,
    pub label: String,
    pub r#type: String,
    pub sport: u16,
    pub target: String,
    pub resolved_ip: Option<String>,
    pub dport: u16,
    pub protocol: String,
    pub ip_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterDelta {
    pub nat_rule: TestCounter,
    pub out: TestCounter,
    pub r#in: TestCounter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalTestExamples {
    pub http: String,
    pub tcp: String,
    pub https_sni: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardTestVerdict {
    pub verdict: String,
    pub message: String,
}

pub fn list_testable_rules(config: &crate::TomlConfig) -> Vec<TestableRule> {
    config
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled())
        .filter_map(|(index, rule)| rule_to_testable_rule(index, rule))
        .collect()
}

pub fn rule_to_testable_rule(index: usize, rule: &NftCell) -> Option<TestableRule> {
    let id = format!("r{index}");
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => Some(TestableRule {
            index,
            id,
            label: label_with_comment(comment, &format!("{sport} -> {domain}:{dport}/{protocol}")),
            r#type: "single".to_string(),
            sport: *sport,
            target: domain.clone(),
            resolved_ip: resolve_target(domain, *dport, *ip_version).ok(),
            dport: *dport,
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
        }),
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            ip_version,
            comment,
            ..
        } => Some(TestableRule {
            index,
            id,
            label: label_with_comment(
                comment,
                &format!("{port_start}-{port_end} -> {domain}:{port_start}-{port_end}/{protocol}"),
            ),
            r#type: "range".to_string(),
            sport: *port_start,
            target: domain.clone(),
            resolved_ip: resolve_target(domain, *port_start, *ip_version).ok(),
            dport: *port_start,
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
        }),
        NftCell::Redirect {
            src_port,
            dst_port,
            protocol,
            ip_version,
            comment,
            ..
        } => Some(TestableRule {
            index,
            id,
            label: label_with_comment(
                comment,
                &format!("{src_port} -> localhost:{dst_port}/{protocol}"),
            ),
            r#type: "redirect".to_string(),
            sport: *src_port,
            target: "localhost".to_string(),
            resolved_ip: Some("127.0.0.1".to_string()),
            dport: *dst_port,
            protocol: protocol.to_string(),
            ip_version: ip_version.to_string(),
        }),
        NftCell::Drop { .. } => None,
    }
}

fn label_with_comment(comment: &Option<String>, route: &str) -> String {
    match comment.as_ref().filter(|comment| !comment.is_empty()) {
        Some(comment) => format!("{comment}: {route}"),
        None => route.to_string(),
    }
}

fn resolve_target(
    target: &str,
    port: u16,
    ip_version: crate::IpVersion,
) -> Result<String, std::io::Error> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let addrs = (target, port).to_socket_addrs()?;
    let selected = match ip_version {
        crate::IpVersion::V4 => addrs.into_iter().find(|addr| addr.is_ipv4()),
        crate::IpVersion::V6 => addrs.into_iter().find(|addr| addr.is_ipv6()),
        crate::IpVersion::All => addrs.into_iter().find(|addr| addr.is_ipv4()).or_else(|| {
            (target, port)
                .to_socket_addrs()
                .ok()?
                .find(|addr| addr.is_ipv6())
        }),
    };
    selected
        .map(|addr| addr.ip().to_string())
        .ok_or_else(|| std::io::Error::other("no matching address resolved"))
}

pub fn parse_rule_counters(json: &str, rule_id: &str) -> Result<RuleTestCounters, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("解析 nft JSON 失败: {e}"))?;
    let entries = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft JSON 缺少 nftables 数组".to_string())?;
    let mut counters = RuleTestCounters::default();

    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let mut counter = None;
        let mut comment = rule_level_comment(rule);
        if let Some(expr) = rule.get("expr") {
            find_counter_and_comment(expr, &mut counter, &mut comment);
        }
        let Some(counter) = counter else {
            continue;
        };
        let Some(comment) = comment else {
            continue;
        };
        if comment == format!("nat-rule:id={rule_id}") {
            counters.nat_rule = counter;
        } else if comment == format!("nat-traffic:id={rule_id},dir=out") {
            counters.out = counter;
        } else if comment == format!("nat-traffic:id={rule_id},dir=in") {
            counters.r#in = counter;
        }
    }

    Ok(counters)
}

fn rule_level_comment(rule: &Value) -> Option<String> {
    rule.get("comment")
        .and_then(Value::as_str)
        .or_else(|| {
            rule.get("comment")
                .and_then(|value| value.get("comment"))
                .and_then(Value::as_str)
        })
        .map(ToString::to_string)
}

fn find_counter_and_comment(
    value: &Value,
    counter: &mut Option<TestCounter>,
    comment: &mut Option<String>,
) {
    match value {
        Value::Array(values) => {
            for item in values {
                find_counter_and_comment(item, counter, comment);
            }
        }
        Value::Object(map) => {
            if let Some(counter_value) = map.get("counter") {
                *counter = Some(TestCounter {
                    packets: counter_value
                        .get("packets")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    bytes: counter_value
                        .get("bytes")
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                });
            }
            if let Some(comment_value) = map.get("comment").and_then(Value::as_str).or_else(|| {
                map.get("comment")
                    .and_then(|value| value.get("comment"))
                    .and_then(Value::as_str)
            }) && (comment.is_none()
                || comment_value.starts_with("nat-rule:")
                || comment_value.starts_with("nat-traffic:"))
            {
                *comment = Some(comment_value.to_string());
            }
            for item in map.values() {
                find_counter_and_comment(item, counter, comment);
            }
        }
        _ => {}
    }
}

pub fn counter_delta(before: &RuleTestCounters, after: &RuleTestCounters) -> CounterDelta {
    CounterDelta {
        nat_rule: single_delta(&before.nat_rule, &after.nat_rule),
        out: single_delta(&before.out, &after.out),
        r#in: single_delta(&before.r#in, &after.r#in),
    }
}

fn single_delta(before: &TestCounter, after: &TestCounter) -> TestCounter {
    TestCounter {
        packets: after.packets.saturating_sub(before.packets),
        bytes: after.bytes.saturating_sub(before.bytes),
    }
}

pub fn nft_rule_applied(counters: &RuleTestCounters) -> bool {
    counters.nat_rule != TestCounter::default()
        || counters.out != TestCounter::default()
        || counters.r#in != TestCounter::default()
}

/// nft 规则在 ruleset 中的存在性检测结果。
///
/// 与 [`RuleTestCounters`] 不同：本结构不依赖 counter 是否非零，只看"评论是否匹配 nat-rule/nat-traffic"。
/// 这样可以避免"规则已生效但还没流量经过 → 显示未应用"的误判。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftRulePresence {
    /// ip self-nat PREROUTING 中找到 `nat-rule:id=rN` 注释
    pub nat_rule_v4_found: bool,
    /// ip6 self-nat PREROUTING 中找到 `nat-rule:id=rN` 注释
    pub nat_rule_v6_found: bool,
    /// ip self-filter FORWARD 中找到 `nat-traffic:id=rN,dir=out`
    pub forward_out_v4_found: bool,
    /// ip self-filter FORWARD 中找到 `nat-traffic:id=rN,dir=in`
    pub forward_in_v4_found: bool,
    /// ip6 self-filter FORWARD 中找到 `nat-traffic:id=rN,dir=out`
    pub forward_out_v6_found: bool,
    /// ip6 self-filter FORWARD 中找到 `nat-traffic:id=rN,dir=in`
    pub forward_in_v6_found: bool,
    /// nat-rule 所在 PREROUTING 规则的 expr 里是否检测到 tcp 协议字段
    pub protocol_tcp_seen: bool,
    /// nat-rule 所在 PREROUTING 规则的 expr 里是否检测到 udp 协议字段
    pub protocol_udp_seen: bool,
}

/// 综合判断：nft 规则在不同 IP family / chain 下的命中状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftDetectionVerdict {
    /// 完整找到（期望的 IP family + PREROUTING + FORWARD 计数器全命中）
    Applied,
    /// 部分命中：只在一个 IP family 或一个方向找到，或 protocol=all 但只看到 tcp/udp 之一
    Partial,
    /// 检测器没找到，但 nat.service active 且最近有 apply.success，可能是检测条件未覆盖
    Unconfirmed,
    /// 未应用：检测器没找到，nat.service inactive 或最近 apply 失败
    NotApplied,
}

impl NftDetectionVerdict {
    pub fn label(self) -> &'static str {
        match self {
            NftDetectionVerdict::Applied => "已应用",
            NftDetectionVerdict::Partial => "部分匹配",
            NftDetectionVerdict::Unconfirmed => "未确认",
            NftDetectionVerdict::NotApplied => "未应用",
        }
    }
}

/// 扫描 `nft -j list ruleset` 输出中是否存在指定 rule_id 的注释。
/// 不要求 counter 非零，因此可以识别"规则已生效但没流量"的情形。
pub fn detect_rule_in_nft_json(json: &str, rule_id: &str) -> Result<NftRulePresence, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("解析 nft JSON 失败: {e}"))?;
    let entries = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft JSON 缺少 nftables 数组".to_string())?;
    let want_nat_rule = format!("nat-rule:id={rule_id}");
    let want_forward_out = format!("nat-traffic:id={rule_id},dir=out");
    let want_forward_in = format!("nat-traffic:id={rule_id},dir=in");
    let mut presence = NftRulePresence::default();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let family = rule.get("family").and_then(Value::as_str).unwrap_or("");
        let table = rule.get("table").and_then(Value::as_str).unwrap_or("");
        let chain = rule.get("chain").and_then(Value::as_str).unwrap_or("");
        // 仅扫描本项目 managed table
        if !(table == "self-nat" || table == "self-filter") {
            continue;
        }
        let mut comments_in_rule: Vec<String> = Vec::new();
        if let Some(c) = rule_level_comment(rule) {
            comments_in_rule.push(c);
        }
        if let Some(expr) = rule.get("expr") {
            collect_expr_comments(expr, &mut comments_in_rule);
        }
        let mut matched_this_rule = false;
        for comment in &comments_in_rule {
            if comment == &want_nat_rule && table == "self-nat" && chain == "PREROUTING" {
                matched_this_rule = true;
                match family {
                    "ip" => presence.nat_rule_v4_found = true,
                    "ip6" => presence.nat_rule_v6_found = true,
                    _ => {}
                }
            } else if comment == &want_forward_out && table == "self-filter" && chain == "FORWARD" {
                match family {
                    "ip" => presence.forward_out_v4_found = true,
                    "ip6" => presence.forward_out_v6_found = true,
                    _ => {}
                }
            } else if comment == &want_forward_in && table == "self-filter" && chain == "FORWARD" {
                match family {
                    "ip" => presence.forward_in_v4_found = true,
                    "ip6" => presence.forward_in_v6_found = true,
                    _ => {}
                }
            }
        }
        // 在 nat-rule 命中的 PREROUTING 行内探测 protocol token，用于 protocol=all 时区分 tcp/udp
        if matched_this_rule && let Some(expr) = rule.get("expr") {
            scan_expr_protocols(
                expr,
                &mut presence.protocol_tcp_seen,
                &mut presence.protocol_udp_seen,
            );
        }
    }
    Ok(presence)
}

/// 在 nft expr 树里收集所有 `comment` 字符串（包括嵌套对象 / 数组 / `{"comment": {"comment": "..."}}` 形式）。
fn collect_expr_comments(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_expr_comments(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(s) = map.get("comment").and_then(Value::as_str) {
                out.push(s.to_string());
            } else if let Some(inner) = map
                .get("comment")
                .and_then(|v| v.get("comment"))
                .and_then(Value::as_str)
            {
                out.push(inner.to_string());
            }
            for v in map.values() {
                collect_expr_comments(v, out);
            }
        }
        _ => {}
    }
}

/// 在 nft expr 中扫描 protocol 标记：
/// - `meta l4proto tcp` / `meta l4proto udp`
/// - `meta l4proto { tcp, udp }`
/// - `tcp dport / sport` / `udp dport / sport`
///
/// 任何上述出现都标记对应 protocol 已见到。
fn scan_expr_protocols(value: &Value, saw_tcp: &mut bool, saw_udp: &mut bool) {
    match value {
        Value::Array(items) => {
            for item in items {
                scan_expr_protocols(item, saw_tcp, saw_udp);
            }
        }
        Value::Object(map) => {
            // match expr：通常形如 {"match": {"left": {"meta": {"key": "l4proto"}}, "op": "==", "right": "tcp"}}
            if let Some(m) = map.get("match")
                && let Some(right) = m.get("right")
            {
                scan_protocol_right(right, saw_tcp, saw_udp);
            }
            // payload expr (tcp dport / udp dport)：{"payload": {"protocol": "tcp", "field": "dport"}}
            if let Some(p) = map.get("payload")
                && let Some(proto) = p.get("protocol").and_then(Value::as_str)
            {
                match proto {
                    "tcp" => *saw_tcp = true,
                    "udp" => *saw_udp = true,
                    _ => {}
                }
            }
            for v in map.values() {
                scan_expr_protocols(v, saw_tcp, saw_udp);
            }
        }
        _ => {}
    }
}

fn scan_protocol_right(value: &Value, saw_tcp: &mut bool, saw_udp: &mut bool) {
    match value {
        Value::String(s) => match s.as_str() {
            "tcp" => *saw_tcp = true,
            "udp" => *saw_udp = true,
            _ => {}
        },
        Value::Array(items) => {
            for item in items {
                scan_protocol_right(item, saw_tcp, saw_udp);
            }
        }
        Value::Object(map) => {
            if let Some(set) = map.get("set") {
                scan_protocol_right(set, saw_tcp, saw_udp);
            }
            for v in map.values() {
                scan_protocol_right(v, saw_tcp, saw_udp);
            }
        }
        _ => {}
    }
}

/// 把 [`NftRulePresence`] 按 ip_version / protocol / nat.service 状态归并出一个综合 verdict。
///
/// 参数：
/// - `expected_ip_version`：规则配置中的 `ip_version`，取值 `"ipv4"` / `"ipv6"` / `"all"`
/// - `expected_protocol`：规则配置中的 `protocol`，取值 `"tcp"` / `"udp"` / `"all"`
/// - `service_active`：systemctl is-active nat 是否返回 active
/// - `last_apply_success`：最近一次 audit 是否记录到 `apply.success`
pub fn classify_nft_presence(
    presence: &NftRulePresence,
    expected_ip_version: &str,
    expected_protocol: &str,
    service_active: bool,
    last_apply_success: bool,
) -> NftDetectionVerdict {
    let need_v4 = matches!(expected_ip_version, "ipv4" | "all");
    let need_v6 = matches!(expected_ip_version, "ipv6" | "all");

    let v4_full =
        presence.nat_rule_v4_found && presence.forward_out_v4_found && presence.forward_in_v4_found;
    let v4_any =
        presence.nat_rule_v4_found || presence.forward_out_v4_found || presence.forward_in_v4_found;
    let v6_full =
        presence.nat_rule_v6_found && presence.forward_out_v6_found && presence.forward_in_v6_found;
    let v6_any =
        presence.nat_rule_v6_found || presence.forward_out_v6_found || presence.forward_in_v6_found;

    // protocol=all 时，要求 protocol_tcp_seen && protocol_udp_seen；
    // 否则只视为部分匹配。
    let protocol_ok = match expected_protocol {
        "all" => presence.protocol_tcp_seen && presence.protocol_udp_seen,
        "tcp" => presence.protocol_tcp_seen,
        "udp" => presence.protocol_udp_seen,
        _ => true,
    };
    let protocol_any = presence.protocol_tcp_seen || presence.protocol_udp_seen;

    let v4_ok = !need_v4 || v4_full;
    let v6_ok = !need_v6 || v6_full;
    let any_family_found = v4_any || v6_any;

    if v4_ok && v6_ok && protocol_ok && any_family_found {
        return NftDetectionVerdict::Applied;
    }
    if any_family_found || protocol_any {
        return NftDetectionVerdict::Partial;
    }
    // 检测器一无所获：根据 service / apply 状态区分 Unconfirmed / NotApplied
    if service_active && last_apply_success {
        NftDetectionVerdict::Unconfirmed
    } else {
        NftDetectionVerdict::NotApplied
    }
}

pub fn verdict_from_delta(delta: &CounterDelta, applied: bool) -> ForwardTestVerdict {
    if !applied {
        return ForwardTestVerdict {
            verdict: "not_applied".to_string(),
            message: "规则尚未应用到 nft，请检查 nat 服务日志或重启 nat。".to_string(),
        };
    }
    if delta.nat_rule.packets == 0 && delta.out.packets == 0 && delta.r#in.packets == 0 {
        return ForwardTestVerdict {
            verdict: "no_external_hit".to_string(),
            message:
                "外部请求没有到达该规则，请检查服务器 IP/端口、安全组、防火墙或 access_control。"
                    .to_string(),
        };
    }
    if delta.nat_rule.packets > 0 && delta.out.packets == 0 {
        return ForwardTestVerdict {
            verdict: "dnat_only".to_string(),
            message:
                "DNAT 已命中，但 FORWARD 出站未增长，可能是 forward/access_control/规则应用异常。"
                    .to_string(),
        };
    }
    if delta.out.packets > 0 && delta.r#in.packets == 0 {
        return ForwardTestVerdict {
            verdict: "forwarded_no_return".to_string(),
            message: "请求已转发到目标，但目标无返回或回程/目标防火墙异常。".to_string(),
        };
    }
    ForwardTestVerdict {
        verdict: "ok".to_string(),
        message: "外部请求已命中并有返回流量。".to_string(),
    }
}

pub fn external_examples(rule: &TestableRule) -> ExternalTestExamples {
    ExternalTestExamples {
        http: format!(
            "curl -v -H \"Host: {}\" http://SERVER_IP:{}/",
            rule.target, rule.sport
        ),
        tcp: format!("nc -vz SERVER_IP {}", rule.sport),
        https_sni: format!(
            "curl -vk --connect-to {}:{}:SERVER_IP:{} https://{}/",
            rule.target, rule.dport, rule.sport, rule.target
        ),
    }
}

pub fn access_control_note(access: &AccessControlConfig) -> Option<String> {
    match access.mode {
        crate::AccessControlMode::Whitelist => {
            Some("请确认测试客户端来源 IP 已在 whitelist 中，否则转发端口不会命中。".to_string())
        }
        crate::AccessControlMode::Blacklist => {
            Some("如果测试客户端来源 IP 在 blacklist 中，连接会被丢弃。".to_string())
        }
        crate::AccessControlMode::Off => None,
    }
}

pub fn tcp_connect_target(rule: &TestableRule, timeout: Duration) -> Option<bool> {
    if rule.protocol == "udp" {
        return None;
    }
    let target = rule.resolved_ip.as_deref().unwrap_or(&rule.target);
    let Ok(addr) = format!("{target}:{}", rule.dport).parse::<SocketAddr>() else {
        return None;
    };
    Some(std::net::TcpStream::connect_timeout(&addr, timeout).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessControlMode, IpVersion, Protocol, TomlConfig};

    fn sample_json(rule_bytes: u64, out_bytes: u64, in_bytes: u64) -> String {
        r#"{
  "nftables": [
    {"rule": {"family": "ip", "table": "self-nat", "chain": "PREROUTING", "handle": 1, "comment": "nat-rule:id=r0", "expr": [{"counter": {"packets": 1, "bytes": RULE_BYTES}}] }},
    {"rule": {"family": "ip", "table": "self-filter", "chain": "FORWARD", "handle": 2, "comment": "nat-traffic:id=r0,dir=out", "expr": [{"counter": {"packets": 5, "bytes": OUT_BYTES}}] }},
    {"rule": {"family": "ip", "table": "self-filter", "chain": "FORWARD", "handle": 3, "expr": [{"counter": {"packets": 4, "bytes": IN_BYTES}}, {"comment": "nat-traffic:id=r0,dir=in"}] }}
  ]
}"#
        .replace("RULE_BYTES", &rule_bytes.to_string())
        .replace("OUT_BYTES", &out_bytes.to_string())
        .replace("IN_BYTES", &in_bytes.to_string())
    }

    #[test]
    fn lists_testable_rules() {
        let config = TomlConfig {
            rules: vec![crate::NftCell::Single {
                enabled: true,
                sport: 30080,
                dport: 80,
                domain: "93.184.216.34".to_string(),
                protocol: Protocol::Tcp,
                ip_version: IpVersion::V4,
                comment: Some("test".to_string()),
                quota_enabled: false,
                quota_bytes: 0,
                quota_period: crate::QuotaPeriod::default(),
                quota_action: crate::QuotaAction::default(),
            }],
            ..Default::default()
        };
        let rules = list_testable_rules(&config);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "r0");
        assert_eq!(rules[0].label, "test: 30080 -> 93.184.216.34:80/tcp");
    }

    #[test]
    fn old_rules_without_enabled_default_to_testable() {
        let config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "93.184.216.34"
"#,
        )
        .unwrap();
        assert!(config.rules[0].enabled());
        assert_eq!(list_testable_rules(&config).len(), 1);
    }

    #[test]
    fn disabled_rules_are_not_testable_by_default() {
        let config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
enabled = false
sport = 30080
dport = 80
domain = "93.184.216.34"
"#,
        )
        .unwrap();
        assert!(list_testable_rules(&config).is_empty());
    }

    #[test]
    fn parses_short_comment_counters_and_delta() {
        let before = parse_rule_counters(&sample_json(10, 100, 50), "r0").unwrap();
        let after = parse_rule_counters(&sample_json(11, 300, 200), "r0").unwrap();
        let delta = counter_delta(&before, &after);
        assert_eq!(delta.nat_rule.bytes, 1);
        assert_eq!(delta.out.bytes, 200);
        assert_eq!(delta.r#in.bytes, 150);
    }

    #[test]
    fn verdicts_cover_common_paths() {
        let none = CounterDelta {
            nat_rule: TestCounter::default(),
            out: TestCounter::default(),
            r#in: TestCounter::default(),
        };
        assert_eq!(verdict_from_delta(&none, true).verdict, "no_external_hit");

        let forwarded = CounterDelta {
            nat_rule: TestCounter {
                packets: 1,
                bytes: 60,
            },
            out: TestCounter {
                packets: 5,
                bytes: 260,
            },
            r#in: TestCounter::default(),
        };
        assert_eq!(
            verdict_from_delta(&forwarded, true).message,
            "请求已转发到目标，但目标无返回或回程/目标防火墙异常。"
        );
    }

    #[test]
    fn access_control_notes_are_explicit() {
        let access = AccessControlConfig {
            mode: AccessControlMode::Whitelist,
            entries: vec!["1.2.3.4".to_string()],
        };
        assert!(access_control_note(&access).unwrap().contains("whitelist"));
    }

    #[test]
    fn udp_tcp_connect_is_not_reliable() {
        let rule = TestableRule {
            index: 0,
            id: "r0".to_string(),
            label: "udp".to_string(),
            r#type: "single".to_string(),
            sport: 30053,
            target: "1.1.1.1".to_string(),
            resolved_ip: Some("1.1.1.1".to_string()),
            dport: 53,
            protocol: "udp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        assert_eq!(tcp_connect_target(&rule, Duration::from_millis(1)), None);
    }

    // ============ v0.4.2: nft 规则存在性检测 ============

    /// 单条 protocol=all 的 nat-rule，PREROUTING 使用 `meta l4proto { tcp, udp }`，
    /// 即使 counter 是 0，detect_rule_in_nft_json 也必须把 nat_rule_v4_found 标 true，
    /// 且 protocol_tcp_seen + protocol_udp_seen 都为 true。
    #[test]
    fn detect_finds_protocol_all_with_zero_counter() {
        let json = r#"{"nftables":[
            {"rule":{"family":"ip","table":"self-nat","chain":"PREROUTING","handle":11,
                "expr":[
                    {"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":{"set":["tcp","udp"]}}},
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-rule:id=r3"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":12,
                "expr":[
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-traffic:id=r3,dir=out"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":13,
                "expr":[
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-traffic:id=r3,dir=in"}
                ]
            }}
        ]}"#;
        let p = detect_rule_in_nft_json(json, "r3").unwrap();
        assert!(p.nat_rule_v4_found, "PREROUTING comment 必须被识别");
        assert!(p.forward_out_v4_found);
        assert!(p.forward_in_v4_found);
        assert!(p.protocol_tcp_seen, "meta l4proto {{tcp,udp}} 应识别为 tcp");
        assert!(p.protocol_udp_seen, "meta l4proto {{tcp,udp}} 应识别为 udp");

        // protocol=all + service active + apply ok → Applied
        let verdict = classify_nft_presence(&p, "ipv4", "all", true, true);
        assert_eq!(verdict, NftDetectionVerdict::Applied);
    }

    /// protocol=all 但 nft 里只有 tcp 一条规则 → 部分匹配。
    #[test]
    fn detect_protocol_all_but_only_tcp_present_is_partial() {
        let json = r#"{"nftables":[
            {"rule":{"family":"ip","table":"self-nat","chain":"PREROUTING","handle":1,
                "expr":[
                    {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":30080}},
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-rule:id=r0"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":2,
                "expr":[
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-traffic:id=r0,dir=out"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
                "expr":[
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-traffic:id=r0,dir=in"}
                ]
            }}
        ]}"#;
        let p = detect_rule_in_nft_json(json, "r0").unwrap();
        assert!(p.protocol_tcp_seen);
        assert!(!p.protocol_udp_seen);
        let verdict = classify_nft_presence(&p, "ipv4", "all", true, true);
        assert_eq!(verdict, NftDetectionVerdict::Partial);
    }

    /// 检测器找不到，但 nat.service active + 最近 apply 成功 → Unconfirmed（而不是 NotApplied）。
    #[test]
    fn no_match_but_service_and_apply_ok_is_unconfirmed() {
        let json = r#"{"nftables":[]}"#;
        let p = detect_rule_in_nft_json(json, "r0").unwrap();
        let verdict = classify_nft_presence(&p, "ipv4", "tcp", true, true);
        assert_eq!(verdict, NftDetectionVerdict::Unconfirmed);
    }

    /// 检测器找不到，nat.service inactive 或最近 apply 失败 → NotApplied。
    #[test]
    fn no_match_and_service_inactive_is_not_applied() {
        let json = r#"{"nftables":[]}"#;
        let p = detect_rule_in_nft_json(json, "r0").unwrap();
        assert_eq!(
            classify_nft_presence(&p, "ipv4", "tcp", false, true),
            NftDetectionVerdict::NotApplied
        );
        assert_eq!(
            classify_nft_presence(&p, "ipv4", "tcp", true, false),
            NftDetectionVerdict::NotApplied
        );
    }

    /// ip_version=all 但 nft 里只有 IPv4 表 → 部分匹配（v6 缺失）。
    #[test]
    fn ip_version_all_with_only_v4_is_partial() {
        let json = r#"{"nftables":[
            {"rule":{"family":"ip","table":"self-nat","chain":"PREROUTING","handle":1,
                "expr":[
                    {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":80}},
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-rule:id=r0"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":2,
                "expr":[{"counter":{"packets":0,"bytes":0}},{"comment":"nat-traffic:id=r0,dir=out"}]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
                "expr":[{"counter":{"packets":0,"bytes":0}},{"comment":"nat-traffic:id=r0,dir=in"}]
            }}
        ]}"#;
        let p = detect_rule_in_nft_json(json, "r0").unwrap();
        assert!(p.nat_rule_v4_found);
        assert!(!p.nat_rule_v6_found);
        let verdict = classify_nft_presence(&p, "all", "tcp", true, true);
        assert_eq!(verdict, NftDetectionVerdict::Partial);
    }

    /// IP family 完整且 protocol=tcp 命中 → Applied，即使 counter 为 0。
    #[test]
    fn applied_with_zero_counter_when_all_pieces_present() {
        let json = r#"{"nftables":[
            {"rule":{"family":"ip","table":"self-nat","chain":"PREROUTING","handle":1,
                "expr":[
                    {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":80}},
                    {"counter":{"packets":0,"bytes":0}},
                    {"comment":"nat-rule:id=r0"}
                ]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":2,
                "expr":[{"counter":{"packets":0,"bytes":0}},{"comment":"nat-traffic:id=r0,dir=out"}]
            }},
            {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
                "expr":[{"counter":{"packets":0,"bytes":0}},{"comment":"nat-traffic:id=r0,dir=in"}]
            }}
        ]}"#;
        let p = detect_rule_in_nft_json(json, "r0").unwrap();
        let verdict = classify_nft_presence(&p, "ipv4", "tcp", true, true);
        assert_eq!(verdict, NftDetectionVerdict::Applied);
    }
}
