//! last-good 状态缓存
//!
//! 当 DDNS / 域名目标解析失败时，允许复用上一次成功解析过的 IP，避免一次 DNS 抖动
//! 把原本可用的转发规则变成不可用。缓存以一个 JSON 文件存在磁盘上，原子化写入。
//! 不存储敏感信息（如 Telegram bot_token），只记录每条规则的目标解析结果和应用状态。

use crate::{IpVersion, LastGoodConfig, NftCell, Protocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// 单条规则的 last-good 信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastGoodRule {
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub domain: String,
    pub last_good_ip: String,
    pub last_resolved_at: DateTime<Utc>,
    #[serde(default = "default_true")]
    pub egress_allowed: bool,
    #[serde(default = "default_apply_status")]
    pub last_apply_status: String,
}

fn default_true() -> bool {
    true
}

fn default_apply_status() -> String {
    "unknown".to_string()
}

/// 整个 last-good 状态文件
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LastGoodState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rules: Vec<LastGoodRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_good_nft_hash: Option<String>,
}

/// 当前配置中一条可使用 last-good 的规则身份。
///
/// `rule_id` 仍对应 nft 注释中的短 id（r0/r1/...），`rule_key` 则由规则内容生成，
/// 用于删除中间规则后识别同一条业务规则，避免仅按 index 错配缓存。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastGoodRuleIdentity {
    pub rule_id: String,
    pub rule_key: String,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LastGoodPruneResult {
    pub before: usize,
    pub after: usize,
    pub removed: usize,
    pub changed: bool,
}

impl LastGoodState {
    pub fn try_load(path: &str) -> io::Result<Self> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Ok(Self::default());
                }
                return Err(e);
            }
        };
        serde_json::from_str::<LastGoodState>(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// 从文件加载；文件不存在或解析失败均返回空状态，并 log::warn
    pub fn load(path: &str) -> Self {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    log::warn!("last-good cache 读取失败 ({path}): {e}");
                }
                return Self::default();
            }
        };
        match serde_json::from_str::<LastGoodState>(&content) {
            Ok(state) => state,
            Err(e) => {
                log::warn!("last-good cache 解析失败 ({path}): {e}");
                Self::default()
            }
        }
    }

    pub fn lookup(&self, rule_id: &str) -> Option<&LastGoodRule> {
        self.rules.iter().find(|r| r.rule_id == rule_id)
    }

    pub fn lookup_by_key(&self, rule_key: &str) -> Option<&LastGoodRule> {
        self.rules
            .iter()
            .find(|r| r.rule_key.as_deref() == Some(rule_key))
    }

    pub fn lookup_current(
        &self,
        _rule_id: &str,
        rule_key: &str,
        _domain: &str,
    ) -> Option<&LastGoodRule> {
        self.lookup_by_key(rule_key)
    }

    pub fn prune_stale_rules(
        &mut self,
        identities: &[LastGoodRuleIdentity],
    ) -> LastGoodPruneResult {
        let before = self.rules.len();
        let mut changed = false;
        let identities_by_key: BTreeMap<&str, &LastGoodRuleIdentity> = identities
            .iter()
            .map(|identity| (identity.rule_key.as_str(), identity))
            .collect();
        let mut current_domain_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut current_by_domain: BTreeMap<String, &LastGoodRuleIdentity> = BTreeMap::new();
        for identity in identities {
            let domain = normalize_domain(&identity.domain);
            *current_domain_counts.entry(domain.clone()).or_insert(0) += 1;
            current_by_domain.insert(domain, identity);
        }
        let mut state_domain_counts: BTreeMap<String, usize> = BTreeMap::new();
        for rule in &self.rules {
            *state_domain_counts
                .entry(normalize_domain(&rule.domain))
                .or_insert(0) += 1;
        }

        let mut kept: BTreeMap<String, (u8, LastGoodRule)> = BTreeMap::new();
        for rule in &self.rules {
            let identity = match rule.rule_key.as_deref() {
                Some(rule_key) => identities_by_key.get(rule_key).copied(),
                None => {
                    let domain = normalize_domain(&rule.domain);
                    if state_domain_counts.get(&domain) == Some(&1)
                        && current_domain_counts.get(&domain) == Some(&1)
                    {
                        current_by_domain.get(&domain).copied()
                    } else {
                        None
                    }
                }
            };
            let Some(identity) = identity else {
                changed = true;
                continue;
            };
            let mut retained = rule.clone();
            if retained.rule_id != identity.rule_id {
                retained.rule_id = identity.rule_id.clone();
                changed = true;
            }
            if retained.rule_key.as_deref() != Some(identity.rule_key.as_str()) {
                retained.rule_key = Some(identity.rule_key.clone());
                changed = true;
            }
            if !same_domain(&retained.domain, &identity.domain) {
                retained.domain = identity.domain.clone();
                changed = true;
            }
            let rank = if rule.rule_key.as_deref() == Some(identity.rule_key.as_str()) {
                2
            } else if rule.rule_id == identity.rule_id {
                1
            } else {
                0
            };
            match kept.get(&identity.rule_key) {
                Some((existing_rank, _)) if *existing_rank > rank => {}
                _ => {
                    kept.insert(identity.rule_key.clone(), (rank, retained));
                }
            }
        }
        let after = kept.len();
        if before != after {
            changed = true;
        }
        self.rules = kept.into_values().map(|(_, rule)| rule).collect();
        LastGoodPruneResult {
            before,
            after,
            removed: before.saturating_sub(after),
            changed,
        }
    }

    /// 原子化写盘：写 .tmp、fsync、rename 替换
    pub fn save(&self, path: &str) -> io::Result<()> {
        let target = PathBuf::from(path);
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let tmp = tmp_path_for(&target);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::other(format!("last-good serialize: {e}")))?;
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(body.as_bytes())?;
            // 尽力保证落盘；失败只 WARN，不阻塞主流程
            if let Err(e) = file.sync_all() {
                log::warn!("last-good fsync 失败 ({}): {e}", tmp.display());
            }
        }
        fs::rename(&tmp, &target)?;
        Ok(())
    }
}

fn tmp_path_for(target: &Path) -> PathBuf {
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// 域名解析结果的来源
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSource {
    Live,
    LastGood,
}

impl ResolveSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolveSource::Live => "live",
            ResolveSource::LastGood => "last-good",
        }
    }
}

/// 在 build_new_script 一轮迭代中累积的解析事件
#[derive(Debug, Clone)]
pub enum ResolutionEvent {
    LiveResolved {
        rule_id: String,
        rule_key: Option<String>,
        comment: Option<String>,
        domain: String,
        ip: String,
    },
    LastGoodUsed {
        rule_id: String,
        rule_key: Option<String>,
        comment: Option<String>,
        domain: String,
        ip: String,
        original_error: String,
    },
    ResolveFailedNoCache {
        rule_id: String,
        rule_key: Option<String>,
        comment: Option<String>,
        domain: String,
        original_error: String,
    },
    EgressSkipped {
        rule_id: String,
        rule_key: Option<String>,
        comment: Option<String>,
        ip: String,
        source: ResolveSource,
    },
}

/// build 流程内累计解析事件的轻量容器（内部 RefCell，避免 &mut 蔓延）
#[derive(Debug, Default)]
pub struct ResolutionLog {
    inner: RefCell<Vec<ResolutionEvent>>,
}

impl ResolutionLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, ev: ResolutionEvent) {
        self.inner.borrow_mut().push(ev);
    }

    pub fn drain(&self) -> Vec<ResolutionEvent> {
        std::mem::take(&mut *self.inner.borrow_mut())
    }

    pub fn snapshot(&self) -> Vec<ResolutionEvent> {
        self.inner.borrow().clone()
    }
}

/// 把 build 过程中累计的 LiveResolved / LastGoodUsed 写回 LastGoodState。
/// 仅在 apply 成功后调用。
pub fn update_state_from_events(
    state: &mut LastGoodState,
    events: &[ResolutionEvent],
    apply_status: &str,
    now: DateTime<Utc>,
) {
    let mut by_id: BTreeMap<String, LastGoodRule> = state
        .rules
        .iter()
        .map(|r| (state_map_key(r), r.clone()))
        .collect();
    for ev in events {
        match ev {
            ResolutionEvent::LiveResolved {
                rule_id,
                rule_key,
                comment,
                domain,
                ip,
            } => {
                let Some(rule_key) = rule_key else {
                    continue;
                };
                by_id.insert(
                    event_map_key(rule_id, Some(rule_key)),
                    LastGoodRule {
                        rule_id: rule_id.clone(),
                        rule_key: Some(rule_key.clone()),
                        comment: comment.clone(),
                        domain: domain.clone(),
                        last_good_ip: ip.clone(),
                        last_resolved_at: now,
                        egress_allowed: true,
                        last_apply_status: apply_status.to_string(),
                    },
                );
            }
            ResolutionEvent::EgressSkipped {
                rule_id,
                rule_key,
                ip,
                ..
            } => {
                if let Some(rule) = by_id.get_mut(&event_map_key(rule_id, rule_key.as_ref())) {
                    rule.egress_allowed = false;
                    rule.last_apply_status = format!("skipped:egress:{ip}");
                }
            }
            // LastGoodUsed / ResolveFailedNoCache：保留已有 last_good_ip 不变；
            // 只把 last_apply_status 改成 fallback / skipped。
            ResolutionEvent::LastGoodUsed {
                rule_id,
                rule_key,
                domain,
                ip,
                ..
            } => {
                if let Some(rule) = by_id.get_mut(&event_map_key(rule_id, rule_key.as_ref())) {
                    if let Some(rule_key) = rule_key {
                        rule.rule_key = Some(rule_key.clone());
                    }
                    rule.domain = domain.clone();
                    rule.last_good_ip = ip.clone();
                    rule.last_apply_status = format!("fallback:last-good:{apply_status}");
                }
            }
            ResolutionEvent::ResolveFailedNoCache {
                rule_id, rule_key, ..
            } => {
                if let Some(rule) = by_id.get_mut(&event_map_key(rule_id, rule_key.as_ref())) {
                    rule.last_apply_status = "skipped:dns-failed".to_string();
                }
            }
        }
    }
    state.rules = by_id.into_values().collect();
    state.last_success_at = Some(now);
}

/// 在调用方使用：如果 cache 启用且配置允许，尝试取出 cached IP
pub fn fallback_ip<'a>(
    config: &LastGoodConfig,
    state: &'a LastGoodState,
    rule_id: &str,
) -> Option<&'a LastGoodRule> {
    if !config.enabled || !config.use_last_good_on_dns_failure {
        return None;
    }
    state.lookup(rule_id)
}

pub fn fallback_ip_for_rule<'a>(
    config: &LastGoodConfig,
    state: &'a LastGoodState,
    rule_id: &str,
    rule_key: &str,
    domain: &str,
) -> Option<&'a LastGoodRule> {
    if !config.enabled || !config.use_last_good_on_dns_failure {
        return None;
    }
    state.lookup_current(rule_id, rule_key, domain)
}

pub fn identities_from_rules(rules: &[NftCell]) -> Vec<LastGoodRuleIdentity> {
    let mut identities = Vec::new();
    for (rule_index, rule) in rules.iter().filter(|rule| rule.enabled()).enumerate() {
        let rule_id = format!("r{rule_index}");
        if let Some(identity) = identity_for_rule(&rule_id, rule) {
            identities.push(identity);
        }
    }
    identities
}

pub fn identity_for_rule(rule_id: &str, rule: &NftCell) -> Option<LastGoodRuleIdentity> {
    let rule_key = rule_key_for_cell(rule)?;
    let domain = cache_domain_for_cell(rule)?;
    Some(LastGoodRuleIdentity {
        rule_id: rule_id.to_string(),
        rule_key,
        domain: domain.to_string(),
    })
}

pub fn rule_key_for_cell(rule: &NftCell) -> Option<String> {
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            ip_version,
            ..
        } if !is_ip_literal(domain) => Some(format!(
            "single|sport={sport}|dport={dport}|protocol={}|ip_version={}|target={}",
            protocol_key(protocol),
            ip_version_key(ip_version),
            normalize_domain(domain)
        )),
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            ip_version,
            ..
        } if !is_ip_literal(domain) => Some(format!(
            "range|port_start={port_start}|port_end={port_end}|protocol={}|ip_version={}|target={}",
            protocol_key(protocol),
            ip_version_key(ip_version),
            normalize_domain(domain)
        )),
        _ => None,
    }
}

fn cache_domain_for_cell(rule: &NftCell) -> Option<&str> {
    match rule {
        NftCell::Single { domain, .. } | NftCell::Range { domain, .. }
            if !is_ip_literal(domain) =>
        {
            Some(domain)
        }
        _ => None,
    }
}

fn state_map_key(rule: &LastGoodRule) -> String {
    rule.rule_key
        .clone()
        .unwrap_or_else(|| format!("legacy:{}", rule.rule_id))
}

fn event_map_key(rule_id: &str, rule_key: Option<&String>) -> String {
    rule_key
        .cloned()
        .unwrap_or_else(|| format!("legacy:{rule_id}"))
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().to_ascii_lowercase()
}

fn same_domain(left: &str, right: &str) -> bool {
    normalize_domain(left) == normalize_domain(right)
}

fn is_ip_literal(domain: &str) -> bool {
    domain.parse::<IpAddr>().is_ok()
}

fn protocol_key(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::All => "all",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn ip_version_key(ip_version: &IpVersion) -> &'static str {
    match ip_version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
        IpVersion::All => "all",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dt(ts: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(ts)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn save_and_load_roundtrips_state() {
        let dir = tempdir();
        let path = dir.join("last-good.json");
        let state = LastGoodState {
            last_success_at: Some(dt("2026-05-19T12:00:00Z")),
            rules: vec![LastGoodRule {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: Some("hk-out".to_string()),
                domain: "example.com".to_string(),
                last_good_ip: "1.2.3.4".to_string(),
                last_resolved_at: dt("2026-05-19T11:59:00Z"),
                egress_allowed: true,
                last_apply_status: "ok".to_string(),
            }],
            last_good_nft_hash: Some("deadbeef".to_string()),
        };
        state.save(path.to_str().unwrap()).unwrap();
        let loaded = LastGoodState::load(path.to_str().unwrap());
        assert_eq!(loaded.rules, state.rules);
        assert_eq!(loaded.last_success_at, state.last_success_at);
        assert_eq!(loaded.last_good_nft_hash, state.last_good_nft_hash);
    }

    #[test]
    fn load_returns_empty_state_on_missing_file() {
        let state = LastGoodState::load("/this/path/should/not/exist/last-good.json");
        assert!(state.rules.is_empty());
        assert!(state.last_success_at.is_none());
    }

    #[test]
    fn fallback_ip_respects_disabled_flag() {
        let mut state = LastGoodState::default();
        state.rules.push(LastGoodRule {
            rule_id: "r0".to_string(),
            rule_key: None,
            comment: None,
            domain: "example.com".to_string(),
            last_good_ip: "1.2.3.4".to_string(),
            last_resolved_at: Utc.timestamp_opt(0, 0).unwrap(),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        });
        let mut cfg = LastGoodConfig::default();
        assert!(fallback_ip(&cfg, &state, "r0").is_some());
        cfg.enabled = false;
        assert!(fallback_ip(&cfg, &state, "r0").is_none());
        cfg.enabled = true;
        cfg.use_last_good_on_dns_failure = false;
        assert!(fallback_ip(&cfg, &state, "r0").is_none());
    }

    #[test]
    fn update_state_from_events_inserts_and_marks() {
        let mut state = LastGoodState::default();
        let now = dt("2026-05-19T12:34:56Z");
        let events = vec![
            ResolutionEvent::LiveResolved {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: Some("hk".to_string()),
                domain: "example.com".to_string(),
                ip: "1.2.3.4".to_string(),
            },
            ResolutionEvent::EgressSkipped {
                rule_id: "r0".to_string(),
                rule_key: Some(
                    "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
                        .to_string(),
                ),
                comment: Some("hk".to_string()),
                ip: "1.2.3.4".to_string(),
                source: ResolveSource::Live,
            },
        ];
        update_state_from_events(&mut state, &events, "ok", now);
        let rule = state.lookup("r0").unwrap();
        assert_eq!(rule.last_good_ip, "1.2.3.4");
        assert!(!rule.egress_allowed);
        assert!(rule.last_apply_status.starts_with("skipped:egress"));
        assert_eq!(state.last_success_at, Some(now));
    }

    fn single_rule(sport: u16, dport: u16, domain: &str) -> NftCell {
        NftCell::Single {
            enabled: true,
            sport,
            dport,
            domain: domain.to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: crate::QuotaPeriod::default(),
            quota_action: crate::QuotaAction::default(),
        }
    }

    fn cached_rule(rule_id: &str, rule_key: &str, domain: &str, ip: &str) -> LastGoodRule {
        LastGoodRule {
            rule_id: rule_id.to_string(),
            rule_key: Some(rule_key.to_string()),
            comment: None,
            domain: domain.to_string(),
            last_good_ip: ip.to_string(),
            last_resolved_at: dt("2026-05-19T12:00:00Z"),
            egress_allowed: true,
            last_apply_status: "ok".to_string(),
        }
    }

    #[test]
    fn prune_removes_deleted_rule_and_rekeys_remaining() {
        let before_rules = vec![
            single_rule(30080, 80, "a.example.com"),
            single_rule(30081, 81, "b.example.com"),
            single_rule(30082, 82, "c.example.com"),
        ];
        let before = identities_from_rules(&before_rules);
        let mut state = LastGoodState {
            last_success_at: Some(dt("2026-05-19T12:00:00Z")),
            rules: vec![
                cached_rule("r0", &before[0].rule_key, "a.example.com", "10.0.0.1"),
                cached_rule("r1", &before[1].rule_key, "b.example.com", "10.0.0.2"),
                cached_rule("r2", &before[2].rule_key, "c.example.com", "10.0.0.3"),
            ],
            last_good_nft_hash: None,
        };
        let after_rules = vec![
            single_rule(30080, 80, "a.example.com"),
            single_rule(30082, 82, "c.example.com"),
        ];
        let after = identities_from_rules(&after_rules);
        let result = state.prune_stale_rules(&after);
        assert_eq!(result.removed, 1);
        assert_eq!(state.rules.len(), 2);
        assert!(state.lookup_by_key(&before[1].rule_key).is_none());
        let c = state.lookup_by_key(&before[2].rule_key).unwrap();
        assert_eq!(c.rule_id, "r1");
        assert_eq!(c.last_good_ip, "10.0.0.3");
    }

    #[test]
    fn prune_drops_ambiguous_legacy_entries_to_avoid_index_mismatch() {
        let after_rules = vec![single_rule(30082, 82, "same.example.com")];
        let after = identities_from_rules(&after_rules);
        let mut state = LastGoodState {
            last_success_at: None,
            rules: vec![
                LastGoodRule {
                    rule_id: "r1".to_string(),
                    rule_key: None,
                    comment: None,
                    domain: "same.example.com".to_string(),
                    last_good_ip: "10.0.0.2".to_string(),
                    last_resolved_at: dt("2026-05-19T12:00:00Z"),
                    egress_allowed: true,
                    last_apply_status: "ok".to_string(),
                },
                LastGoodRule {
                    rule_id: "r2".to_string(),
                    rule_key: None,
                    comment: None,
                    domain: "same.example.com".to_string(),
                    last_good_ip: "10.0.0.3".to_string(),
                    last_resolved_at: dt("2026-05-19T12:00:00Z"),
                    egress_allowed: true,
                    last_apply_status: "ok".to_string(),
                },
            ],
            last_good_nft_hash: None,
        };
        let result = state.prune_stale_rules(&after);
        assert_eq!(result.removed, 2);
        assert!(state.rules.is_empty());
    }

    #[test]
    fn fixed_ip_rules_have_no_last_good_identity() {
        let rules = vec![single_rule(30080, 80, "203.0.113.10")];
        assert!(identities_from_rules(&rules).is_empty());
        assert!(rule_key_for_cell(&rules[0]).is_none());
    }

    #[test]
    fn update_state_ignores_live_resolved_without_rule_key() {
        let mut state = LastGoodState::default();
        update_state_from_events(
            &mut state,
            &[ResolutionEvent::LiveResolved {
                rule_id: "r0".to_string(),
                rule_key: None,
                comment: None,
                domain: "203.0.113.10".to_string(),
                ip: "203.0.113.10".to_string(),
            }],
            "ok",
            dt("2026-05-19T12:00:00Z"),
        );
        assert!(state.rules.is_empty());
    }

    #[test]
    fn domain_rule_identity_is_stable_and_cacheable() {
        let rule = single_rule(30080, 443, "Example.COM");
        let identity = identity_for_rule("r0", &rule).unwrap();
        assert_eq!(identity.rule_id, "r0");
        assert_eq!(
            identity.rule_key,
            "single|sport=30080|dport=443|protocol=tcp|ip_version=ipv4|target=example.com"
        );
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nat-lastgood-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
