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
use std::net::IpAddr;

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
        changed: bool,
    },
    ResolveFail {
        name: String,
        domain: String,
        error: String,
        using_last_good: bool,
    },
    Change {
        name: String,
        domain: String,
        old_ips: Vec<String>,
        new_ips: Vec<String>,
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
            .or_else(|| self.domains.iter().find(|state| state.name == name))
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

    let mut domains = Vec::new();
    let mut events = Vec::new();
    for domain_config in &config.domains {
        let previous_domain =
            previous.find_domain_state(&domain_config.name, &domain_config.domain);
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
                let changed = old_ips != new_ips;
                events.push(DynamicWhitelistEvent::ResolveSuccess {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    ips: new_ips.clone(),
                    changed,
                });
                if changed {
                    events.push(DynamicWhitelistEvent::Change {
                        name: domain_config.name.clone(),
                        domain: domain_config.domain.clone(),
                        old_ips,
                        new_ips: new_ips.clone(),
                    });
                }
                domains.push(DynamicWhitelistDomainState {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    last_good_ips: new_ips.clone(),
                    current_ips: new_ips,
                    resolved_at: Some(now.to_rfc3339()),
                    stale: false,
                    error: None,
                    ipv4: config.resolve_ipv4,
                    ipv6: config.resolve_ipv6,
                });
            }
            Err(error) => {
                let last_good_ips = previous_domain
                    .map(|state| state.last_good_ips.clone())
                    .unwrap_or_default();
                let using_last_good =
                    config.use_last_good_on_dns_failure && !last_good_ips.is_empty();
                let current_ips = if using_last_good {
                    last_good_ips.clone()
                } else {
                    Vec::new()
                };
                events.push(DynamicWhitelistEvent::ResolveFail {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    error: error.clone(),
                    using_last_good,
                });
                domains.push(DynamicWhitelistDomainState {
                    name: domain_config.name.clone(),
                    domain: domain_config.domain.clone(),
                    last_good_ips,
                    current_ips,
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

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dynamic-whitelist-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ))
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
}
