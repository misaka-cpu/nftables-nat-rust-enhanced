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
}
