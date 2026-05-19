//! last-good 状态缓存
//!
//! 当 DDNS / 域名目标解析失败时，允许复用上一次成功解析过的 IP，避免一次 DNS 抖动
//! 把原本可用的转发规则变成不可用。缓存以一个 JSON 文件存在磁盘上，原子化写入。
//! 不存储敏感信息（如 Telegram bot_token），只记录每条规则的目标解析结果和应用状态。

use crate::LastGoodConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// 单条规则的 last-good 信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastGoodRule {
    pub rule_id: String,
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

impl LastGoodState {
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
        comment: Option<String>,
        domain: String,
        ip: String,
    },
    LastGoodUsed {
        rule_id: String,
        comment: Option<String>,
        domain: String,
        ip: String,
        original_error: String,
    },
    ResolveFailedNoCache {
        rule_id: String,
        comment: Option<String>,
        domain: String,
        original_error: String,
    },
    EgressSkipped {
        rule_id: String,
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
        .map(|r| (r.rule_id.clone(), r.clone()))
        .collect();
    for ev in events {
        match ev {
            ResolutionEvent::LiveResolved {
                rule_id,
                comment,
                domain,
                ip,
            } => {
                by_id.insert(
                    rule_id.clone(),
                    LastGoodRule {
                        rule_id: rule_id.clone(),
                        comment: comment.clone(),
                        domain: domain.clone(),
                        last_good_ip: ip.clone(),
                        last_resolved_at: now,
                        egress_allowed: true,
                        last_apply_status: apply_status.to_string(),
                    },
                );
            }
            ResolutionEvent::EgressSkipped { rule_id, ip, .. } => {
                if let Some(rule) = by_id.get_mut(rule_id) {
                    rule.egress_allowed = false;
                    rule.last_apply_status = format!("skipped:egress:{ip}");
                }
            }
            // LastGoodUsed / ResolveFailedNoCache：保留已有 last_good_ip 不变；
            // 只把 last_apply_status 改成 fallback / skipped。
            ResolutionEvent::LastGoodUsed {
                rule_id,
                domain,
                ip,
                ..
            } => {
                if let Some(rule) = by_id.get_mut(rule_id) {
                    rule.domain = domain.clone();
                    rule.last_good_ip = ip.clone();
                    rule.last_apply_status = format!("fallback:last-good:{apply_status}");
                }
            }
            ResolutionEvent::ResolveFailedNoCache { rule_id, .. } => {
                if let Some(rule) = by_id.get_mut(rule_id) {
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
                comment: Some("hk".to_string()),
                domain: "example.com".to_string(),
                ip: "1.2.3.4".to_string(),
            },
            ResolutionEvent::EgressSkipped {
                rule_id: "r0".to_string(),
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
