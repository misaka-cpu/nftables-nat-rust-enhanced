//! 动态 DDNS 来源白名单 state 与纯刷新逻辑。
//!
//! 该模块只处理“来源 IP 白名单”的动态解析状态，不复用目标 last-good state，
//! 也不接触 egress_control / 目标域名解析。

use crate::{DynamicWhitelistConfig, atomic};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicWhitelistState {
    #[serde(default)]
    pub domains: Vec<DynamicWhitelistDomainState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicWhitelistDomainState {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub last_good_ips: Vec<String>,
    #[serde(default)]
    pub current_ips: Vec<String>,
    /// 上一次成功解析得到的原始 IP，便于排查；与 `last_good_ips` 同步更新。
    #[serde(default)]
    pub raw_ips: Vec<String>,
    /// 当前生效的来源条目，已应用 `cidr_expand_ipv4` 扩展。
    /// 用于 nft 规则生成与状态展示。
    #[serde(default)]
    pub effective_sources: Vec<String>,
    /// 当前生效条目对应的 IPv4 CIDR 扩展模式，写入 state 便于排查。
    /// 旧 state 缺失时反序列化为 0，会触发下一轮重算。
    #[serde(default)]
    pub cidr_expand_ipv4: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub ipv4: bool,
    #[serde(default)]
    pub ipv6: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicWhitelistPruneResult {
    pub before: usize,
    pub after: usize,
    pub removed: usize,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicWhitelistEvent {
    ResolveSuccess {
        name: String,
        domain: String,
        ips: Vec<String>,
        raw_ips: Vec<String>,
        effective_sources: Vec<String>,
        cidr_expand_ipv4: u8,
        changed: bool,
    },
    ResolveFail {
        name: String,
        domain: String,
        error: String,
        using_last_good: bool,
    },
    StalePruned {
        name: String,
        old_domain: String,
        new_domain: String,
    },
    Change {
        name: String,
        domain: String,
        old_ips: Vec<String>,
        new_ips: Vec<String>,
        old_effective_sources: Vec<String>,
        new_effective_sources: Vec<String>,
        cidr_expand_ipv4: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicWhitelistRefreshResult {
    pub state: DynamicWhitelistState,
    pub events: Vec<DynamicWhitelistEvent>,
}

impl DynamicWhitelistState {
    pub fn try_load(path: &str) -> io::Result<Self> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };
        serde_json::from_str::<Self>(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn load(path: &str) -> Self {
        match Self::try_load(path) {
            Ok(state) => state,
            Err(e) => {
                log::warn!("dynamic whitelist state 读取或解析失败 ({path}): {e}");
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &str) -> io::Result<()> {
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::other(format!("dynamic whitelist state serialize: {e}")))?;
        atomic::write_atomic(path, &body)
    }

    pub fn find_domain_state(
        &self,
        name: &str,
        domain: &str,
    ) -> Option<&DynamicWhitelistDomainState> {
        self.domains
            .iter()
            .find(|state| state.name == name && state.domain == domain)
    }

    pub fn find_domain_state_by_name(&self, name: &str) -> Option<&DynamicWhitelistDomainState> {
        self.domains.iter().find(|state| state.name == name)
    }

    pub fn prune_for_config(
        &mut self,
        config: &DynamicWhitelistConfig,
    ) -> DynamicWhitelistPruneResult {
        let before = self.domains.len();
        self.domains.retain(|state| {
            config
                .domains
                .iter()
                .any(|domain| domain.name == state.name && domain.domain == state.domain)
        });
        let after = self.domains.len();
        DynamicWhitelistPruneResult {
            before,
            after,
            removed: before.saturating_sub(after),
            changed: before != after,
        }
    }
}

pub fn refresh_state_with_resolver<F>(
    config: &DynamicWhitelistConfig,
    previous: &DynamicWhitelistState,
    mut resolver: F,
    now: DateTime<Utc>,
) -> DynamicWhitelistRefreshResult
where
    F: FnMut(&str) -> Result<Vec<IpAddr>, String>,
{
    if !config.enabled {
        return DynamicWhitelistRefreshResult {
            state: previous.clone(),
            events: Vec::new(),
        };
    }

    let cidr_expand_ipv4 = config.cidr_expand_ipv4;
    let mut domains = Vec::new();
    let mut events = Vec::new();
    for domain_config in &config.domains {
        let previous_domain =
            previous.find_domain_state(&domain_config.name, &domain_config.domain);
        if previous_domain.is_none()
            && let Some(stale_domain) = previous.find_domain_state_by_name(&domain_config.name)
            && stale_domain.domain != domain_config.domain
        {
            events.push(DynamicWhitelistEvent::StalePruned {
                name: domain_config.name.clone(),
                old_domain: stale_domain.domain.clone(),
                new_domain: domain_config.domain.clone(),
            });
        }
        if !domain_config.enabled {
            domains.push(disabled_domain_state(
                config,
                domain_config,
                previous_domain,
            ));
            continue;
        }

        let result = if config.resolve_ipv4 || config.resolve_ipv6 {
            resolver(&domain_config.domain).and_then(|ips| filter_resolved_ips(config, ips))
        } else {
            Err("resolve_ipv4=false 且 resolve_ipv6=false，没有启用任何解析类型".to_string())
        };

        match result {
            Ok(new_ips) => {
                let old_ips = previous_domain
                    .map(|state| state.current_ips.clone())
                    .unwrap_or_default();
                let old_effective_sources = previous_domain
                    .map(|state| state.effective_sources.clone())
                    .unwrap_or_default();
                let new_effective_sources = expand_effective_sources(&new_ips, cidr_expand_ipv4);
                let changed = old_effective_sources != new_effective_sources;
                events.push(DynamicWhitelistEvent::ResolveSuccess {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    ips: new_ips.clone(),
                    raw_ips: new_ips.clone(),
                    effective_sources: new_effective_sources.clone(),
                    cidr_expand_ipv4,
                    changed,
                });
                if changed {
                    events.push(DynamicWhitelistEvent::Change {
                        name: domain_config.name.clone(),
                        domain: domain_config.domain.clone(),
                        old_ips,
                        new_ips: new_ips.clone(),
                        old_effective_sources,
                        new_effective_sources: new_effective_sources.clone(),
                        cidr_expand_ipv4,
                    });
                }
                domains.push(DynamicWhitelistDomainState {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    last_good_ips: new_ips.clone(),
                    current_ips: new_ips.clone(),
                    raw_ips: new_ips,
                    effective_sources: new_effective_sources,
                    cidr_expand_ipv4,
                    resolved_at: Some(now.to_rfc3339()),
                    stale: false,
                    error: None,
                    ipv4: config.resolve_ipv4,
                    ipv6: config.resolve_ipv6,
                });
            }
            Err(error) => {
                let last_good_ips = last_good_ips_for_config(config, previous_domain);
                let using_last_good =
                    config.use_last_good_on_dns_failure && !last_good_ips.is_empty();
                let (current_ips, effective_sources) = if using_last_good {
                    let sources = expand_effective_sources(&last_good_ips, cidr_expand_ipv4);
                    (last_good_ips.clone(), sources)
                } else {
                    (Vec::new(), Vec::new())
                };
                events.push(DynamicWhitelistEvent::ResolveFail {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    error: error.clone(),
                    using_last_good,
                });
                let raw_ips = if using_last_good {
                    last_good_ips.clone()
                } else {
                    Vec::new()
                };
                domains.push(DynamicWhitelistDomainState {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    last_good_ips,
                    current_ips,
                    raw_ips,
                    effective_sources,
                    cidr_expand_ipv4,
                    resolved_at: previous_domain.and_then(|state| state.resolved_at.clone()),
                    stale: using_last_good,
                    error: Some(error),
                    ipv4: config.resolve_ipv4,
                    ipv6: config.resolve_ipv6,
                });
            }
        }
    }

    DynamicWhitelistRefreshResult {
        state: DynamicWhitelistState { domains },
        events,
    }
}

fn last_good_ips_for_config(
    config: &DynamicWhitelistConfig,
    previous_domain: Option<&DynamicWhitelistDomainState>,
) -> Vec<String> {
    previous_domain
        .map(|state| {
            state
                .last_good_ips
                .iter()
                .filter(|raw| match raw.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => config.resolve_ipv4,
                    Ok(IpAddr::V6(_)) => config.resolve_ipv6,
                    Err(_) => false,
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// 把原始 IP 列表按 IPv4 CIDR 扩展规则转换为最终生效来源条目。
///
/// - `cidr_expand_ipv4 = 32` 或其它非 24 值：保留原始 IPv4 字符串（IPv6 同样原样保留）。
/// - `cidr_expand_ipv4 = 24`：把每个 IPv4 地址扩展为对应的 /24 网络字符串。
/// - IPv6 不做扩展。
/// - 结果去重并按字符串排序，避免输出顺序受输入顺序影响。
pub fn expand_effective_sources(raw_ips: &[String], cidr_expand_ipv4: u8) -> Vec<String> {
    let mut result = BTreeSet::new();
    for raw in raw_ips {
        if cidr_expand_ipv4 == 24
            && let Ok(IpAddr::V4(ipv4)) = raw.parse::<IpAddr>()
        {
            result.insert(format_ipv4_network(ipv4, 24));
            continue;
        }
        result.insert(raw.clone());
    }
    result.into_iter().collect()
}

fn format_ipv4_network(ip: Ipv4Addr, prefix: u8) -> String {
    debug_assert!(prefix <= 32);
    let host_bits = 32 - prefix;
    let mask: u32 = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    format!("{network}/{prefix}")
}

pub fn current_ips_for_config(
    config: &DynamicWhitelistConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    if !config.enabled {
        return Vec::new();
    }
    let mut values = BTreeSet::new();
    for domain_config in config.domains.iter().filter(|domain| domain.enabled) {
        let Some(domain_state) =
            state.find_domain_state(&domain_config.name, &domain_config.domain)
        else {
            continue;
        };
        for ip in &domain_state.current_ips {
            values.insert(ip.clone());
        }
    }
    values.into_iter().collect()
}

/// 返回当前 enabled domains 的「生效来源条目」集合，已应用 `cidr_expand_ipv4` 扩展。
///
/// 为兼容旧 state（没有 `effective_sources` / `cidr_expand_ipv4` 字段），或配置中
/// `cidr_expand_ipv4` 与 state 中记录的不一致时，会基于 `current_ips` 即时重算，
/// 避免在两次刷新之间使用陈旧的扩展结果。
pub fn effective_sources_for_config(
    config: &DynamicWhitelistConfig,
    state: &DynamicWhitelistState,
) -> Vec<String> {
    if !config.enabled {
        return Vec::new();
    }
    let mut values = BTreeSet::new();
    for domain_config in config.domains.iter().filter(|domain| domain.enabled) {
        let Some(domain_state) =
            state.find_domain_state(&domain_config.name, &domain_config.domain)
        else {
            continue;
        };
        let sources = effective_sources_view(domain_state, config.cidr_expand_ipv4);
        for entry in sources {
            values.insert(entry);
        }
    }
    values.into_iter().collect()
}

/// 取单个 domain state 的「生效来源条目」视图。
///
/// 若 state 中的 `cidr_expand_ipv4` 与配置一致且 `effective_sources` 已经记录，
/// 则直接返回；否则按配置即时基于 `current_ips` 重新扩展，保证旧 state 与
/// 模式切换时的展示和 nft 规则生成都使用最新规则。
pub fn effective_sources_view(
    state: &DynamicWhitelistDomainState,
    cidr_expand_ipv4: u8,
) -> Vec<String> {
    if state.cidr_expand_ipv4 == cidr_expand_ipv4 && !state.effective_sources.is_empty() {
        return state.effective_sources.clone();
    }
    expand_effective_sources(&state.current_ips, cidr_expand_ipv4)
}

pub fn stale_count_for_config(
    config: &DynamicWhitelistConfig,
    state: &DynamicWhitelistState,
) -> usize {
    if !config.enabled {
        return 0;
    }
    config
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .filter(|domain| {
            state
                .find_domain_state(&domain.name, &domain.domain)
                .map(|state| state.stale)
                .unwrap_or(false)
        })
        .count()
}

pub fn latest_success_at_for_config(
    config: &DynamicWhitelistConfig,
    state: &DynamicWhitelistState,
) -> Option<String> {
    if !config.enabled {
        return None;
    }
    config
        .domains
        .iter()
        .filter(|domain| domain.enabled)
        .filter_map(|domain| state.find_domain_state(&domain.name, &domain.domain))
        .filter_map(|state| state.resolved_at.clone())
        .max()
}

fn disabled_domain_state(
    config: &DynamicWhitelistConfig,
    domain_config: &crate::DynamicWhitelistDomainConfig,
    previous_domain: Option<&DynamicWhitelistDomainState>,
) -> DynamicWhitelistDomainState {
    DynamicWhitelistDomainState {
        name: domain_config.name.clone(),
        domain: domain_config.domain.clone(),
        last_good_ips: previous_domain
            .map(|state| state.last_good_ips.clone())
            .unwrap_or_default(),
        current_ips: Vec::new(),
        raw_ips: Vec::new(),
        effective_sources: Vec::new(),
        cidr_expand_ipv4: config.cidr_expand_ipv4,
        resolved_at: previous_domain.and_then(|state| state.resolved_at.clone()),
        stale: false,
        error: None,
        ipv4: config.resolve_ipv4,
        ipv6: config.resolve_ipv6,
    }
}

fn filter_resolved_ips(
    config: &DynamicWhitelistConfig,
    ips: Vec<IpAddr>,
) -> Result<Vec<String>, String> {
    let mut values = BTreeSet::new();
    for ip in ips {
        let allowed = match ip {
            IpAddr::V4(_) => config.resolve_ipv4,
            IpAddr::V6(_) => config.resolve_ipv6,
        };
        if allowed {
            values.insert(ip.to_string());
        }
    }
    let filtered: Vec<String> = values.into_iter().collect();
    if filtered.is_empty() {
        return Err(no_usable_record_message(config));
    }
    Ok(filtered)
}

fn no_usable_record_message(config: &DynamicWhitelistConfig) -> String {
    match (config.resolve_ipv4, config.resolve_ipv6) {
        (true, false) => "未解析到可用 A 记录".to_string(),
        (false, true) => "未解析到可用 AAAA 记录".to_string(),
        (true, true) => "未解析到可用 A/AAAA 记录".to_string(),
        (false, false) => "resolve_ipv4=false 且 resolve_ipv6=false".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{DynamicWhitelistDomainConfig, validate_dynamic_whitelist_domain};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn config_with_domain() -> DynamicWhitelistConfig {
        DynamicWhitelistConfig {
            enabled: true,
            domains: vec![DynamicWhitelistDomainConfig {
                name: "home".to_string(),
                domain: "home.example.com".to_string(),
                enabled: true,
            }],
            ..Default::default()
        }
    }

    fn config_with_domain_name(name: &str, domain: &str) -> DynamicWhitelistConfig {
        DynamicWhitelistConfig {
            enabled: true,
            domains: vec![DynamicWhitelistDomainConfig {
                name: name.to_string(),
                domain: domain.to_string(),
                enabled: true,
            }],
            ..Default::default()
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dynamic-whitelist-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn same_name_same_domain_dns_failure_reuses_last_good() {
        let config = config_with_domain_name("home", "home.example.com");
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        );
        let failed = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );

        let state = &failed.state.domains[0];
        assert_eq!(state.domain, "home.example.com");
        assert_eq!(state.current_ips, vec!["203.0.113.10"]);
        assert_eq!(state.last_good_ips, vec!["203.0.113.10"]);
        assert!(state.stale);
        assert!(matches!(
            failed.events[0],
            DynamicWhitelistEvent::ResolveFail {
                using_last_good: true,
                ..
            }
        ));
    }

    #[test]
    fn same_name_domain_change_dns_failure_does_not_reuse_old_last_good() {
        let old_config = config_with_domain_name("home", "old.example.com");
        let old_state = refresh_state_with_resolver(
            &old_config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        )
        .state;
        let new_config = config_with_domain_name("home", "new.example.com");
        let failed = refresh_state_with_resolver(
            &new_config,
            &old_state,
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );

        let state = &failed.state.domains[0];
        assert_eq!(state.name, "home");
        assert_eq!(state.domain, "new.example.com");
        assert!(state.current_ips.is_empty());
        assert!(state.last_good_ips.is_empty());
        assert!(state.effective_sources.is_empty());
        assert!(!state.stale);
        assert!(failed.events.iter().any(|event| matches!(
            event,
            DynamicWhitelistEvent::StalePruned {
                name,
                old_domain,
                new_domain
            } if name == "home"
                && old_domain == "old.example.com"
                && new_domain == "new.example.com"
        )));
        assert!(failed.events.iter().any(|event| matches!(
            event,
            DynamicWhitelistEvent::ResolveFail {
                using_last_good: false,
                ..
            }
        )));
        assert!(!failed.state.domains.iter().any(|state| {
            state.domain == "old.example.com"
                || state.current_ips.contains(&"203.0.113.10".to_string())
        }));
    }

    #[test]
    fn dns_failure_does_not_reuse_last_good_from_disabled_ip_family() {
        let old_config = config_with_domain_name("home", "home.example.com");
        let old_state = refresh_state_with_resolver(
            &old_config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        )
        .state;
        let mut new_config = config_with_domain_name("home", "home.example.com");
        new_config.resolve_ipv4 = false;
        new_config.resolve_ipv6 = true;

        let failed = refresh_state_with_resolver(
            &new_config,
            &old_state,
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );

        let state = &failed.state.domains[0];
        assert!(state.current_ips.is_empty());
        assert!(state.last_good_ips.is_empty());
        assert!(state.effective_sources.is_empty());
        assert!(!state.stale);
        assert!(failed.events.iter().any(|event| matches!(
            event,
            DynamicWhitelistEvent::ResolveFail {
                using_last_good: false,
                ..
            }
        )));
    }

    #[test]
    fn same_name_domain_change_dns_success_writes_new_last_good() {
        let old_config = config_with_domain_name("home", "old.example.com");
        let old_state = refresh_state_with_resolver(
            &old_config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        )
        .state;
        let new_config = config_with_domain_name("home", "new.example.com");
        let refreshed = refresh_state_with_resolver(
            &new_config,
            &old_state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))]),
            Utc::now(),
        );

        let state = &refreshed.state.domains[0];
        assert_eq!(state.name, "home");
        assert_eq!(state.domain, "new.example.com");
        assert_eq!(state.current_ips, vec!["198.51.100.20"]);
        assert_eq!(state.last_good_ips, vec!["198.51.100.20"]);
        assert_eq!(state.effective_sources, vec!["198.51.100.20"]);
        assert!(!state.current_ips.contains(&"203.0.113.10".to_string()));
        assert!(refreshed.events.iter().any(|event| matches!(
            event,
            DynamicWhitelistEvent::StalePruned {
                name,
                old_domain,
                new_domain
            } if name == "home"
                && old_domain == "old.example.com"
                && new_domain == "new.example.com"
        )));
    }

    #[test]
    fn prune_removes_same_name_domain_mismatch() {
        let config = config_with_domain_name("home", "new.example.com");
        let mut state = DynamicWhitelistState {
            domains: vec![DynamicWhitelistDomainState {
                name: "home".to_string(),
                domain: "old.example.com".to_string(),
                last_good_ips: vec!["203.0.113.10".to_string()],
                current_ips: vec!["203.0.113.10".to_string()],
                raw_ips: vec!["203.0.113.10".to_string()],
                effective_sources: vec!["203.0.113.10".to_string()],
                cidr_expand_ipv4: 32,
                resolved_at: None,
                stale: false,
                error: None,
                ipv4: true,
                ipv6: false,
            }],
        };

        let pruned = state.prune_for_config(&config);
        assert!(pruned.changed);
        assert_eq!(pruned.removed, 1);
        assert!(state.domains.is_empty());
    }

    #[test]
    fn domain_change_success_keeps_exact_ipv4_when_expand_disabled() {
        let old_config = config_with_domain_name("home", "old.example.com");
        let old_state = refresh_state_with_resolver(
            &old_config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        )
        .state;
        let mut new_config = config_with_domain_name("home", "new.example.com");
        new_config.cidr_expand_ipv4 = 32;

        let refreshed = refresh_state_with_resolver(
            &new_config,
            &old_state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))]),
            Utc::now(),
        );

        assert_eq!(
            refreshed.state.domains[0].effective_sources,
            vec!["198.51.100.20"]
        );
        assert_eq!(refreshed.state.domains[0].cidr_expand_ipv4, 32);
    }

    #[test]
    fn domain_change_success_expands_only_new_domain_ipv4_to_24() {
        let old_config = config_with_domain_name("home", "old.example.com");
        let old_state = refresh_state_with_resolver(
            &old_config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        )
        .state;
        let mut new_config = config_with_domain_name("home", "new.example.com");
        new_config.cidr_expand_ipv4 = 24;

        let refreshed = refresh_state_with_resolver(
            &new_config,
            &old_state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))]),
            Utc::now(),
        );

        assert_eq!(
            refreshed.state.domains[0].effective_sources,
            vec!["198.51.100.0/24"]
        );
        assert_eq!(refreshed.state.domains[0].cidr_expand_ipv4, 24);
        assert!(
            !refreshed.state.domains[0]
                .effective_sources
                .contains(&"203.0.113.0/24".to_string())
        );
    }

    #[test]
    fn refresh_success_updates_current_ips_and_state() {
        let config = config_with_domain();
        let result = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        );
        assert_eq!(result.state.domains[0].current_ips, vec!["203.0.113.10"]);
        assert_eq!(result.state.domains[0].last_good_ips, vec!["203.0.113.10"]);
        assert!(!result.state.domains[0].stale);
        assert!(matches!(
            result.events[0],
            DynamicWhitelistEvent::ResolveSuccess { changed: true, .. }
        ));
    }

    #[test]
    fn success_replaces_old_ips_without_accumulating_history() {
        let config = config_with_domain();
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        );
        let second = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))]),
            Utc::now(),
        );
        assert_eq!(second.state.domains[0].current_ips, vec!["203.0.113.20"]);
        assert_eq!(second.state.domains[0].last_good_ips, vec!["203.0.113.20"]);
        assert!(
            !second.state.domains[0]
                .current_ips
                .contains(&"203.0.113.10".to_string())
        );
    }

    #[test]
    fn dns_failure_with_last_good_keeps_stale_ips() {
        let config = config_with_domain();
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
            Utc::now(),
        );
        let failed = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );
        let state = &failed.state.domains[0];
        assert_eq!(state.current_ips, vec!["203.0.113.10"]);
        assert_eq!(state.last_good_ips, vec!["203.0.113.10"]);
        assert!(state.stale);
        assert_eq!(state.error.as_deref(), Some("mock dns failure"));
        assert!(matches!(
            failed.events[0],
            DynamicWhitelistEvent::ResolveFail {
                using_last_good: true,
                ..
            }
        ));
    }

    #[test]
    fn dns_failure_without_last_good_produces_no_whitelist_ip() {
        let config = config_with_domain();
        let failed = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );
        let state = &failed.state.domains[0];
        assert!(state.current_ips.is_empty());
        assert!(state.last_good_ips.is_empty());
        assert!(!state.stale);
    }

    #[test]
    fn corrupted_state_file_loads_empty_without_panic() {
        let path = temp_path("corrupt");
        fs::write(&path, "{not-json").unwrap();
        let state = DynamicWhitelistState::load(path.to_str().unwrap());
        assert!(state.domains.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn state_write_failure_returns_error_without_panic() {
        let state = DynamicWhitelistState::default();
        let result = state.save("/proc/self/dynamic-whitelist-state.json");
        assert!(result.is_err());
    }

    #[test]
    fn current_ips_respect_enabled_flags_and_sort_dedup() {
        let mut config = config_with_domain();
        config.domains.push(DynamicWhitelistDomainConfig {
            name: "phone".to_string(),
            domain: "phone.example.com".to_string(),
            enabled: false,
        });
        let state = DynamicWhitelistState {
            domains: vec![
                DynamicWhitelistDomainState {
                    name: "home".to_string(),
                    domain: "home.example.com".to_string(),
                    last_good_ips: vec![],
                    current_ips: vec!["203.0.113.2".to_string(), "203.0.113.1".to_string()],
                    raw_ips: vec!["203.0.113.2".to_string(), "203.0.113.1".to_string()],
                    effective_sources: vec!["203.0.113.1".to_string(), "203.0.113.2".to_string()],
                    cidr_expand_ipv4: 32,
                    resolved_at: None,
                    stale: false,
                    error: None,
                    ipv4: true,
                    ipv6: false,
                },
                DynamicWhitelistDomainState {
                    name: "phone".to_string(),
                    domain: "phone.example.com".to_string(),
                    last_good_ips: vec![],
                    current_ips: vec!["198.51.100.1".to_string()],
                    raw_ips: vec!["198.51.100.1".to_string()],
                    effective_sources: vec!["198.51.100.1".to_string()],
                    cidr_expand_ipv4: 32,
                    resolved_at: None,
                    stale: false,
                    error: None,
                    ipv4: true,
                    ipv6: false,
                },
            ],
        };
        assert_eq!(
            current_ips_for_config(&config, &state),
            vec!["203.0.113.1", "203.0.113.2"]
        );
    }

    #[test]
    fn ipv6_records_are_ignored_by_default() {
        let config = config_with_domain();
        let failed = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]),
            Utc::now(),
        );
        assert!(failed.state.domains[0].current_ips.is_empty());
        assert!(
            failed.state.domains[0]
                .error
                .as_deref()
                .unwrap()
                .contains("A 记录")
        );
    }

    #[test]
    fn validates_domain_names() {
        assert!(validate_dynamic_whitelist_domain("home.example.com").is_ok());
        assert!(validate_dynamic_whitelist_domain("bad domain.example").is_err());
        assert!(validate_dynamic_whitelist_domain("https://example.com").is_err());
        assert!(validate_dynamic_whitelist_domain("-bad.example.com").is_err());
    }

    #[test]
    fn expand_effective_sources_keeps_exact_ipv4_when_32() {
        let sources = expand_effective_sources(&["1.2.3.4".to_string()], 32);
        assert_eq!(sources, vec!["1.2.3.4"]);
    }

    #[test]
    fn expand_effective_sources_expands_ipv4_to_24() {
        let sources = expand_effective_sources(&["1.2.3.4".to_string()], 24);
        assert_eq!(sources, vec!["1.2.3.0/24"]);
    }

    #[test]
    fn expand_effective_sources_dedupes_same_24_network() {
        let sources = expand_effective_sources(&["1.2.3.4".to_string(), "1.2.3.9".to_string()], 24);
        assert_eq!(sources, vec!["1.2.3.0/24"]);
    }

    #[test]
    fn expand_effective_sources_keeps_different_24_networks() {
        let sources = expand_effective_sources(&["1.2.3.4".to_string(), "5.6.7.8".to_string()], 24);
        assert_eq!(sources, vec!["1.2.3.0/24", "5.6.7.0/24"]);
    }

    #[test]
    fn expand_effective_sources_ipv6_kept_as_is() {
        let sources = expand_effective_sources(&["2001:db8::1".to_string()], 24);
        assert_eq!(sources, vec!["2001:db8::1"]);
    }

    #[test]
    fn refresh_success_records_effective_sources_for_24() {
        let mut config = config_with_domain();
        config.cidr_expand_ipv4 = 24;
        let result = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]),
            Utc::now(),
        );
        let state = &result.state.domains[0];
        assert_eq!(state.raw_ips, vec!["1.2.3.4"]);
        assert_eq!(state.effective_sources, vec!["1.2.3.0/24"]);
        assert_eq!(state.cidr_expand_ipv4, 24);
    }

    #[test]
    fn refresh_change_event_uses_effective_sources_delta() {
        let mut config = config_with_domain();
        config.cidr_expand_ipv4 = 24;
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]),
            Utc::now(),
        );
        // Different raw IP but same /24 — should NOT emit Change (effective_sources equal).
        let same_net = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 99))]),
            Utc::now(),
        );
        assert!(
            !same_net
                .events
                .iter()
                .any(|event| matches!(event, DynamicWhitelistEvent::Change { .. }))
        );
        // Different /24 — Change should fire.
        let other_net = refresh_state_with_resolver(
            &config,
            &same_net.state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]),
            Utc::now(),
        );
        let change = other_net
            .events
            .iter()
            .find(|event| matches!(event, DynamicWhitelistEvent::Change { .. }))
            .expect("/24 network change should emit Change event");
        let DynamicWhitelistEvent::Change {
            old_effective_sources,
            new_effective_sources,
            cidr_expand_ipv4,
            ..
        } = change
        else {
            unreachable!()
        };
        assert_eq!(old_effective_sources, &vec!["1.2.3.0/24".to_string()]);
        assert_eq!(new_effective_sources, &vec!["5.6.7.0/24".to_string()]);
        assert_eq!(*cidr_expand_ipv4, 24);
    }

    #[test]
    fn old_state_without_effective_sources_loads_and_recomputes() {
        // Old state shape: no raw_ips / effective_sources / cidr_expand_ipv4 keys.
        let path = temp_path("legacy");
        let body = r#"{
  "domains": [
    {
      "name": "home",
      "domain": "home.example.com",
      "last_good_ips": ["1.2.3.4"],
      "current_ips": ["1.2.3.4"],
      "resolved_at": null,
      "stale": false,
      "error": null,
      "ipv4": true,
      "ipv6": false
    }
  ]
}"#;
        fs::write(&path, body).unwrap();
        let loaded = DynamicWhitelistState::load(path.to_str().unwrap());
        assert_eq!(loaded.domains.len(), 1);
        assert!(loaded.domains[0].effective_sources.is_empty());
        assert_eq!(loaded.domains[0].cidr_expand_ipv4, 0);

        // With cidr_expand_ipv4=24, effective_sources_for_config should re-expand
        // from current_ips even when the persisted effective_sources is empty.
        let mut config = config_with_domain();
        config.cidr_expand_ipv4 = 24;
        let sources = effective_sources_for_config(&config, &loaded);
        assert_eq!(sources, vec!["1.2.3.0/24"]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn switching_from_32_to_24_recomputes_effective_sources_on_next_refresh() {
        let mut config = config_with_domain();
        config.cidr_expand_ipv4 = 32;
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]),
            Utc::now(),
        );
        assert_eq!(first.state.domains[0].effective_sources, vec!["1.2.3.4"]);

        config.cidr_expand_ipv4 = 24;
        let second = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]),
            Utc::now(),
        );
        assert_eq!(
            second.state.domains[0].effective_sources,
            vec!["1.2.3.0/24"]
        );
        assert_eq!(second.state.domains[0].cidr_expand_ipv4, 24);
    }

    #[test]
    fn effective_sources_view_recomputes_when_mode_differs_from_state() {
        let state = DynamicWhitelistDomainState {
            name: "home".to_string(),
            domain: "home.example.com".to_string(),
            last_good_ips: vec!["1.2.3.4".to_string()],
            current_ips: vec!["1.2.3.4".to_string()],
            raw_ips: vec!["1.2.3.4".to_string()],
            effective_sources: vec!["1.2.3.4".to_string()],
            cidr_expand_ipv4: 32,
            resolved_at: None,
            stale: false,
            error: None,
            ipv4: true,
            ipv6: false,
        };
        // Config wants /24 but state still records /32 — view should re-expand.
        let view = effective_sources_view(&state, 24);
        assert_eq!(view, vec!["1.2.3.0/24"]);
    }

    #[test]
    fn dns_failure_keeps_effective_sources_under_24() {
        let mut config = config_with_domain();
        config.cidr_expand_ipv4 = 24;
        let first = refresh_state_with_resolver(
            &config,
            &DynamicWhitelistState::default(),
            |_| Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]),
            Utc::now(),
        );
        let failed = refresh_state_with_resolver(
            &config,
            &first.state,
            |_| Err("mock dns failure".to_string()),
            Utc::now(),
        );
        let state = &failed.state.domains[0];
        assert_eq!(state.effective_sources, vec!["1.2.3.0/24"]);
        assert!(state.stale);
    }
}
