#![allow(dead_code)]
use std::{io, process::Command};

use log::{info, warn};
use serde::{Deserialize, Serialize};

// Docker v28 may set type filter hook forward chain policy drop. This project only warns:
// it must not modify non-managed nft tables outside self-nat/self-filter.
pub(crate) fn check_and_prepare() -> Result<(), io::Error> {
    let check_result = check_current_ruleset()?;
    warn_forward_policy_if_needed(&check_result);
    Ok(())
}

fn warn_forward_policy_if_needed(check_result: &CheckResult) {
    for line in forward_policy_warning_lines(check_result) {
        warn!("{line}");
    }
}

fn forward_policy_warning_lines(check_result: &CheckResult) -> Vec<&'static str> {
    if !check_result.ip_forward_drop && !check_result.ip6_forward_drop {
        return Vec::new();
    }
    let mut lines = vec![
        "检测到系统 FORWARD policy 可能影响转发。",
        "本项目不会自动修改非 self-* 表。",
        "如你确认需要修改，请手动检查：",
    ];
    if check_result.ip_forward_drop {
        lines.push("  nft list chain ip filter FORWARD");
    }
    if check_result.ip6_forward_drop {
        lines.push("  nft list chain ip6 filter FORWARD");
    }
    lines
}

fn check_current_ruleset() -> Result<CheckResult, io::Error> {
    let output = Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()?;

    if !output.status.success() {
        info!("执行 nft -j list ruleset 命令失败");
        return Err(io::Error::other("执行 nft -j list ruleset 命令失败"));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    check_ruleset_json(&json_str)
}

fn check_ruleset_json(json_str: &str) -> Result<CheckResult, io::Error> {
    let mut res = CheckResult::default();
    let nftables_output: NftablesOutput = match serde_json::from_str(json_str) {
        Ok(output) => output,
        Err(e) => {
            info!("解析 nft 输出的 JSON 失败: {e}");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "解析 nft 输出的 JSON 失败",
            ));
        }
    };

    for entry in nftables_output.nftables {
        #[allow(clippy::single_match)]
        match entry {
            NftablesEntry::Chain {
                family,
                table,
                name,
                handle: _,
                r#type,
                hook,
                prio: _,
                policy,
            } => {
                // IPv4 FORWARD链检查
                // nft list table ip filter:
                // chain FORWARD {
                //      type filter hook forward priority filter; policy drop;
                // }
                if family == "ip"
                    && table == "filter"
                    && name == "FORWARD"
                    && r#type == Some("filter".to_string())
                    && hook == Some("forward".to_string())
                    && policy == Some("drop".to_string())
                {
                    info!(
                        "iptables-nft创建的IPv4 FORWARD链存在，且type=filter，hook=forward，policy=drop"
                    );
                    res.ip_forward_drop = true;
                }

                // IPv6 FORWARD链检查
                // nft list table ip6 filter:
                // chain FORWARD {
                //      type filter hook forward priority filter; policy drop;
                // }
                if family == "ip6"
                    && table == "filter"
                    && name == "FORWARD"
                    && r#type == Some("filter".to_string())
                    && hook == Some("forward".to_string())
                    && policy == Some("drop".to_string())
                {
                    info!(
                        "ip6tables-nft创建的IPv6 FORWARD链存在，且type=filter，hook=forward，policy=drop"
                    );
                    res.ip6_forward_drop = true;
                }
            }
            _ => {}
        }
    }

    Ok(res)
}

// 用于解析 nft -j list ruleset 输出的数据结构
#[derive(Debug, Serialize, Deserialize)]
struct NftablesOutput {
    nftables: Vec<NftablesEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
// #[serde(untagged)]
#[serde(rename_all = "snake_case")]
enum NftablesEntry {
    Metainfo {
        version: String,
        release_name: String,
        json_schema_version: u8,
    },
    Table {
        family: String,
        name: String,
        handle: u32,
    },
    Chain {
        family: String,
        table: String,
        name: String,
        handle: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hook: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prio: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy: Option<String>,
    },
    Rule {
        family: String,
        table: String,
        chain: String,
        handle: u32,
        expr: Vec<serde_json::Value>,
    },
    Set {
        family: String,
        table: String,
        name: String,
        handle: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        flags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        elem: Option<Vec<serde_json::Value>>,
    },
    Map {
        family: String,
        table: String,
        name: String,
        handle: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        r#type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        map: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        flags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        elem: Option<Vec<serde_json::Value>>,
    },
    Element {
        family: String,
        table: String,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        elem: Option<Vec<serde_json::Value>>,
    },
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

#[derive(Debug, Serialize, Deserialize)]
struct Metainfo {}

#[derive(Debug, Serialize, Deserialize)]
struct Table {}

#[derive(Debug, Serialize, Deserialize)]
struct Chain {}

#[derive(Debug, Serialize, Deserialize)]
struct Rule {}

#[derive(Debug, Serialize, Deserialize)]
struct Set {}

#[derive(Debug, Serialize, Deserialize)]
struct Map {}

#[derive(Debug, Serialize, Deserialize)]
struct Element {}

#[derive(Default)]
struct CheckResult {
    ip_forward_drop: bool,
    ip6_forward_drop: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_nftables_output() {
        let json_data = r#"{
    "nftables": [
        {
            "metainfo": {
                "version": "1.1.3",
                "release_name": "Commodore Bullmoose #4",
                "json_schema_version": 1
            }
        },
        {
            "table": {
                "family": "inet",
                "name": "filter",
                "handle": 1
            }
        },
        {
            "chain": {
                "family": "inet",
                "table": "filter",
                "name": "input",
                "handle": 1,
                "type": "filter",
                "hook": "input",
                "prio": 0,
                "policy": "accept"
            }
        },
        {
            "chain": {
                "family": "inet",
                "table": "filter",
                "name": "forward",
                "handle": 2,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "accept"
            }
        },
        {
            "chain": {
                "family": "inet",
                "table": "filter",
                "name": "output",
                "handle": 3,
                "type": "filter",
                "hook": "output",
                "prio": 0,
                "policy": "accept"
            }
        },
        {
            "table": {
                "family": "ip",
                "name": "netbird",
                "handle": 2
            }
        },
        {
            "set": {
                "family": "ip",
                "name": "nb0000001",
                "table": "netbird",
                "type": "ipv4_addr",
                "handle": 40,
                "flags": [
                    "dynamic"
                ],
                "elem": [
                    "0.0.0.0"
                ]
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "netbird",
                "chain": "netbird-rt-fwd",
                "handle": 22,
                "expr": [
                    {
                        "match": {
                            "op": "in",
                            "left": {
                                "ct": {
                                    "key": "state"
                                }
                            },
                            "right": [
                                "established",
                                "related"
                            ]
                        }
                    },
                    {
                        "counter": {
                            "packets": 0,
                            "bytes": 0
                        }
                    },
                    {
                        "accept": null
                    }
                ]
            }
        }
    ]
}"#;

        let result: Result<NftablesOutput, _> = serde_json::from_str(json_data);
        assert!(
            result.is_ok(),
            "Failed to deserialize JSON: {:?}",
            result.err()
        );

        let nftables_output = result.unwrap();
        assert_eq!(nftables_output.nftables.len(), 8);

        // 验证 metainfo
        match &nftables_output.nftables[0] {
            NftablesEntry::Metainfo {
                version,
                release_name,
                json_schema_version,
            } => {
                assert_eq!(version, "1.1.3");
                assert_eq!(release_name, "Commodore Bullmoose #4");
                assert_eq!(*json_schema_version, 1);
            }
            _ => panic!("Expected Metainfo entry"),
        }

        // 验证 table
        match &nftables_output.nftables[1] {
            NftablesEntry::Table {
                family,
                name,
                handle,
            } => {
                assert_eq!(family, "inet");
                assert_eq!(name, "filter");
                assert_eq!(*handle, 1);
            }
            _ => panic!("Expected Table entry"),
        }

        // 验证 chain
        match &nftables_output.nftables[2] {
            NftablesEntry::Chain {
                family,
                table,
                handle,
                name,
                r#type,
                hook,
                prio,
                policy,
            } => {
                assert_eq!(family, "inet");
                assert_eq!(table, "filter");
                assert_eq!(name, "input");
                assert_eq!(*handle, 1);
                assert_eq!(*r#type, Some("filter".to_string()));
                assert_eq!(*hook, Some("input".to_string()));
                assert_eq!(*prio, Some(0));
                assert_eq!(*policy, Some("accept".to_string()));
            }
            _ => panic!("Expected Chain entry"),
        }

        // 验证 set
        match &nftables_output.nftables[6] {
            NftablesEntry::Set {
                family,
                table,
                name,
                handle,
                r#type,
                policy: _,
                flags,
                elem: _,
            } => {
                assert_eq!(family, "ip");
                assert_eq!(name, "nb0000001");
                assert_eq!(table, "netbird");
                assert_eq!(*handle, 40);
                assert_eq!(*r#type, Some("ipv4_addr".to_string()));
                assert_eq!(*flags, Some(vec!["dynamic".to_string()]));
            }
            _ => panic!("Expected Set entry"),
        }

        // 验证 rule
        match &nftables_output.nftables[7] {
            NftablesEntry::Rule {
                family,
                table,
                chain,
                handle,
                expr,
            } => {
                assert_eq!(family, "ip");
                assert_eq!(table, "netbird");
                assert_eq!(chain, "netbird-rt-fwd");
                assert_eq!(*handle, 22);
                assert_eq!(expr.len(), 3);
            }
            _ => panic!("Expected Rule entry"),
        }
    }

    #[test]
    fn test_deserialize_unknown_entry() {
        let json_data = r#"{
    "nftables": [
        {
            "unknown_type": {
                "some_field": "some_value",
                "another_field": 123
            }
        }
    ]
}"#;

        let result: Result<NftablesOutput, _> = serde_json::from_str(json_data);
        assert!(
            result.is_ok(),
            "Failed to deserialize JSON with unknown entry: {:?}",
            result.err()
        );

        let nftables_output = result.unwrap();
        assert_eq!(nftables_output.nftables.len(), 1);

        // 验证未知类型被正确处理为 Unknown 变体
        match &nftables_output.nftables[0] {
            NftablesEntry::Unknown(value) => {
                assert!(value.is_object());
                let obj = value.as_object().unwrap();
                assert!(obj.contains_key("unknown_type"));
            }
            _ => panic!("Expected Unknown entry"),
        }
    }

    #[test]
    fn forward_policy_drop_only_emits_warning_lines() {
        let json_data = r#"{
    "nftables": [
        {
            "chain": {
                "family": "ip",
                "table": "filter",
                "name": "FORWARD",
                "handle": 1,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "drop"
            }
        },
        {
            "chain": {
                "family": "ip6",
                "table": "filter",
                "name": "FORWARD",
                "handle": 2,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "drop"
            }
        }
    ]
}"#;

        let result = check_ruleset_json(json_data).unwrap();
        assert!(result.ip_forward_drop);
        assert!(result.ip6_forward_drop);

        let lines = forward_policy_warning_lines(&result);
        let joined = lines.join("\n");
        assert!(joined.contains("检测到系统 FORWARD policy 可能影响转发。"));
        assert!(joined.contains("本项目不会自动修改非 self-* 表。"));
        assert!(joined.contains("nft list chain ip filter FORWARD"));
        assert!(joined.contains("nft list chain ip6 filter FORWARD"));
        assert!(!joined.contains("policy accept"));
        assert!(!joined.contains("chain ip filter FORWARD {"));
    }

    #[test]
    fn forward_policy_accept_emits_no_warning() {
        let json_data = r#"{
    "nftables": [
        {
            "chain": {
                "family": "ip",
                "table": "filter",
                "name": "FORWARD",
                "handle": 1,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "accept"
            }
        }
    ]
}"#;

        let result = check_ruleset_json(json_data).unwrap();
        assert!(!result.ip_forward_drop);
        assert!(!result.ip6_forward_drop);
        assert!(forward_policy_warning_lines(&result).is_empty());
    }
}
