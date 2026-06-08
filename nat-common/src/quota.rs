//! 规则级流量配额（quota）
//!
//! 第一版只支持 `quota_action = "disable"`：当某条规则当前周期已用流量 ≥ `quota_bytes` 时，
//! nat.service 主循环会把该规则 `enabled` 置为 false 并保存 `/etc/nat.toml`，由现有安全 apply
//! 流程在下一轮迭代中移除规则。不直接执行 nft -f、不删除规则、不接管限速 / tc。
//!
//! 通知去重：用一个独立的 JSON 状态文件（默认
//! `/var/lib/nftables-nat-rust/quota-state.json`）记录"哪条规则在哪个 period 已经通知过"，
//! 同一 period 内不会重复发送 Telegram。

use crate::{
    NftCell, QuotaConfig, QuotaPeriod, TomlConfig,
    stats::{self, StatsState},
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

/// 通知去重状态。key 形如 `r0:monthly:2026-05` / `r0:daily:2026-05-19` / `r0:total`，
/// value 为通知时间戳（RFC3339）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaState {
    #[serde(default)]
    pub notified: HashMap<String, String>,
}

impl QuotaState {
    pub fn load(path: &str) -> Self {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    log::warn!("quota state 读取失败 ({path}): {e}");
                }
                return Self::default();
            }
        };
        match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("quota state 解析失败 ({path}): {e}");
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &str) -> io::Result<()> {
        let target = PathBuf::from(path);
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::other(format!("quota state serialize: {e}")))?;
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(body.as_bytes())?;
            if let Err(e) = file.sync_all() {
                log::warn!("quota state fsync 失败 ({}): {e}", tmp.display());
            }
        }
        fs::rename(&tmp, &target)?;
        Ok(())
    }

    pub fn is_notified(&self, key: &str) -> bool {
        self.notified.contains_key(key)
    }

    pub fn mark_notified(&mut self, key: &str, when: DateTime<Utc>) {
        self.notified.insert(key.to_string(), when.to_rfc3339());
    }

    /// 当用户重新启用规则时清除该规则的所有 period 通知记录，
    /// 这样下一次再次超额时仍会触发一次新通知。
    pub fn clear_for_rule(&mut self, rule_id: &str) {
        let prefix = format!("{rule_id}:");
        self.notified.retain(|k, _| !k.starts_with(&prefix));
    }
}

/// 当前 period 的 used / limit / key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaUsage {
    /// nft 计数器口径的规则 id（`rN`），N 为「启用规则序号」，与 nft 脚本生成一致。
    pub rule_id: String,
    /// 该规则在 `config.rules` 中的真实数组下标，供 [`apply_disable_actions`] 精确写回。
    /// 不能用 `rule_id` 的数字部分当数组下标——两者只有在没有 disabled 规则时才相等。
    pub original_index: usize,
    pub label: Option<String>,
    pub period: QuotaPeriod,
    pub period_key: String,
    pub used_bytes: u64,
    pub limit_bytes: u64,
}

impl QuotaUsage {
    pub fn exceeded(&self) -> bool {
        self.limit_bytes > 0 && self.used_bytes >= self.limit_bytes
    }

    /// 通知去重 key：rule_id + period + period_key
    pub fn notify_key(&self) -> String {
        format!("{}:{}:{}", self.rule_id, self.period, self.period_key)
    }
}

/// 主循环调用：扫描所有规则，返回每条启用 quota 的规则当前 period 的 usage。
pub fn compute_usages(
    rules: &[NftCell],
    stats_state: &StatsState,
    now: DateTime<Utc>,
) -> Vec<QuotaUsage> {
    let mut out = Vec::new();
    // rule_id（`rN`）必须与 nft 脚本生成完全一致：`read_toml_config` 先 `filter(NftCell::enabled)`
    // 过滤掉 disabled 规则，再对剩余「启用规则」（含 Drop，因为 Drop::enabled() == true）顺序编号
    // r0,r1,…。因此这里用「启用规则序号」而不是 config.rules 数组下标，否则 disabled 规则排在
    // 启用规则之前时，per_rule_*_bytes 的 key 会和这里查的 key 错位。
    let mut enabled_seq = 0usize;
    for (original_index, rule) in rules.iter().enumerate() {
        if !rule.enabled() {
            // 被禁用的规则不会生成 nft 规则、没有计数器，也不占用 rN 序号。
            continue;
        }
        let rule_seq = enabled_seq;
        enabled_seq += 1;
        if matches!(rule, NftCell::Drop { .. }) {
            // Drop 规则会占用一个 rN 序号（和 nft 生成保持对齐），但没有 quota / 流量计数。
            continue;
        }
        if !rule.quota_enabled() {
            continue;
        }
        let limit = rule.quota_bytes();
        if limit == 0 {
            continue;
        }
        let rule_id = format!("r{rule_seq}");
        let period = rule.quota_period();
        let (used, period_key) = match period {
            QuotaPeriod::Daily => (
                stats_state
                    .per_rule_daily_bytes
                    .get(&rule_id)
                    .copied()
                    .unwrap_or(0),
                day_key(now),
            ),
            QuotaPeriod::Monthly => (
                stats_state
                    .per_rule_monthly_bytes
                    .get(&rule_id)
                    .copied()
                    .unwrap_or(0),
                month_key(now),
            ),
            QuotaPeriod::Total => (
                stats_state
                    .per_rule_total_bytes
                    .get(&rule_id)
                    .copied()
                    .unwrap_or(0),
                "total".to_string(),
            ),
        };
        out.push(QuotaUsage {
            label: stats_state.rule_labels.get(&rule_id).cloned(),
            rule_id,
            original_index,
            period,
            period_key,
            used_bytes: used,
            limit_bytes: limit,
        });
    }
    out
}

fn day_key(now: DateTime<Utc>) -> String {
    now.date_naive().format("%Y-%m-%d").to_string()
}

fn month_key(now: DateTime<Utc>) -> String {
    let nd: NaiveDate = now.date_naive();
    format!("{:04}-{:02}", nd.format("%Y"), nd.format("%m"))
}

/// 检查决策
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceededDecision {
    pub usage: QuotaUsage,
    /// 是否本次 check 才发现（false 表示之前 period 已通知过 + 已禁用）
    pub newly_exceeded: bool,
    /// 是否应该发 Telegram（去重后还需要发）
    pub should_notify: bool,
}

/// 主循环调用：跑一遍 quota 检查。返回需要"禁用 + 写 audit"的规则集合。
pub fn check_and_decide(
    rules: &[NftCell],
    stats_state: &StatsState,
    quota_config: &QuotaConfig,
    quota_state: &QuotaState,
    now: DateTime<Utc>,
) -> Vec<ExceededDecision> {
    if !quota_config.enabled {
        return Vec::new();
    }
    let mut decisions = Vec::new();
    for usage in compute_usages(rules, stats_state, now) {
        if !usage.exceeded() {
            continue;
        }
        let key = usage.notify_key();
        let already_notified = quota_state.is_notified(&key);
        let rule_enabled = rules
            .get(usage.original_index)
            .map(|r| r.enabled())
            .unwrap_or(true);
        decisions.push(ExceededDecision {
            usage,
            newly_exceeded: rule_enabled || !already_notified,
            should_notify: quota_config.notify_on_exceeded && !already_notified,
        });
    }
    decisions
}

/// 把配置中超额规则的 `enabled` 字段改成 false；返回被改动的规则索引。
pub fn apply_disable_actions(
    config: &mut TomlConfig,
    decisions: &[ExceededDecision],
) -> Vec<usize> {
    let mut changed = Vec::new();
    for decision in decisions {
        // 必须用 original_index（config.rules 的真实数组下标）写回，而不是把 rule_id 的数字部分
        // 当下标——rule_id 是「启用规则序号」，有 disabled 规则在前时与数组下标并不相等。
        let idx = decision.usage.original_index;
        if let Some(rule) = config.rules.get_mut(idx)
            && rule.enabled()
        {
            rule.set_enabled(false);
            changed.push(idx);
        }
    }
    changed
}

/// 格式化通知正文。已脱敏 / 不包含 bot_token。
pub fn format_telegram_message(decision: &ExceededDecision) -> String {
    let usage = &decision.usage;
    let label = usage.label.as_deref().unwrap_or("(unnamed)");
    format!(
        "规则流量配额已超额并自动禁用\n\n规则：{label}\nrule_id：{rule_id}\n周期：{period} ({period_key})\n已用：{used}\n配额：{limit}\n动作：disabled",
        rule_id = usage.rule_id,
        period = usage.period,
        period_key = usage.period_key,
        used = stats::format_bytes(usage.used_bytes),
        limit = stats::format_bytes(usage.limit_bytes),
    )
}

/// 校验配额字节解析格式：100GB / 1TB / 500MiB / 107374182400
pub fn parse_quota_bytes(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("配额字节数不能为空".to_string());
    }
    // 纯数字 → 视为字节
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(n);
    }
    // 带单位
    let bytes_per: &[(&str, u64)] = &[
        ("KiB", 1024),
        ("MiB", 1024 * 1024),
        ("GiB", 1024 * 1024 * 1024),
        ("TiB", 1024u64.pow(4)),
        ("KB", 1000),
        ("MB", 1000 * 1000),
        ("GB", 1000u64.pow(3)),
        ("TB", 1000u64.pow(4)),
        ("K", 1024),
        ("M", 1024 * 1024),
        ("G", 1024u64.pow(3)),
        ("T", 1024u64.pow(4)),
        ("B", 1),
    ];
    // 不要被前缀重叠误伤：先尝试最长后缀
    for (suffix, mult) in bytes_per.iter().copied() {
        let upper = trimmed.to_uppercase();
        let suffix_upper = suffix.to_uppercase();
        if upper.ends_with(&suffix_upper) {
            let num_part = &trimmed[..trimmed.len() - suffix.len()];
            let n: f64 = num_part
                .trim()
                .parse()
                .map_err(|_| format!("无法解析数字: {num_part}"))?;
            if n < 0.0 || !n.is_finite() {
                return Err(format!("配额必须非负有限: {n}"));
            }
            let bytes = (n * mult as f64) as u64;
            return Ok(bytes);
        }
    }
    Err(format!(
        "无法解析配额: {trimmed}（支持 KB/MB/GB/TB/KiB/MiB/GiB/TiB 或纯字节数）"
    ))
}

/// 格式化字节数（共享 stats 的实现）。提供成顶层 API 便于 CLI 使用。
pub fn format_bytes(value: u64) -> String {
    stats::format_bytes(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{NftCell, Protocol};
    use chrono::TimeZone;

    fn rule_with_quota(sport: u16, limit: u64, period: QuotaPeriod) -> NftCell {
        NftCell::Single {
            enabled: true,
            sport,
            dport: 80,
            domain: "example.com".to_string(),
            protocol: Protocol::Tcp,
            ip_version: Default::default(),
            snat_ip: None,
            comment: Some("hk-out".to_string()),
            quota_enabled: true,
            quota_bytes: limit,
            quota_period: period,
            quota_action: Default::default(),
        }
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn parse_quota_bytes_units() {
        assert_eq!(parse_quota_bytes("100GB").unwrap(), 100_000_000_000);
        assert_eq!(parse_quota_bytes("1TB").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_quota_bytes("500MiB").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_quota_bytes("107374182400").unwrap(), 107_374_182_400);
        assert_eq!(parse_quota_bytes("1KiB").unwrap(), 1024);
        assert!(parse_quota_bytes("").is_err());
        assert!(parse_quota_bytes("abc").is_err());
    }

    #[test]
    fn compute_usages_skips_disabled_quota() {
        let mut rule = rule_with_quota(30080, 1024, QuotaPeriod::Monthly);
        rule.set_quota_enabled(false);
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 9999);
        let usages = compute_usages(&[rule], &stats, ts("2026-05-19T12:00:00Z"));
        assert!(usages.is_empty());
    }

    #[test]
    fn compute_usages_skips_zero_limit() {
        let rule = rule_with_quota(30080, 0, QuotaPeriod::Monthly);
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 9999);
        let usages = compute_usages(&[rule], &stats, ts("2026-05-19T12:00:00Z"));
        assert!(usages.is_empty());
    }

    #[test]
    fn check_decides_exceeded_for_monthly() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Monthly);
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 200);
        let quota_cfg = QuotaConfig::default();
        let state = QuotaState::default();
        let decisions = check_and_decide(
            &[rule],
            &stats,
            &quota_cfg,
            &state,
            ts("2026-05-19T12:00:00Z"),
        );
        assert_eq!(decisions.len(), 1);
        let d = &decisions[0];
        assert!(d.usage.exceeded());
        assert!(d.newly_exceeded);
        assert!(d.should_notify);
        assert_eq!(d.usage.period_key, "2026-05");
        assert_eq!(d.usage.used_bytes, 200);
        assert_eq!(d.usage.limit_bytes, 100);
    }

    #[test]
    fn check_decides_uses_daily_bucket() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Daily);
        let mut stats = StatsState::default();
        stats.per_rule_daily_bytes.insert("r0".to_string(), 150);
        let decisions = check_and_decide(
            &[rule],
            &stats,
            &QuotaConfig::default(),
            &QuotaState::default(),
            ts("2026-05-19T12:00:00Z"),
        );
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].usage.period_key, "2026-05-19");
    }

    #[test]
    fn check_decides_uses_total_bucket() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Total);
        let mut stats = StatsState::default();
        stats.per_rule_total_bytes.insert("r0".to_string(), 999);
        let decisions = check_and_decide(
            &[rule],
            &stats,
            &QuotaConfig::default(),
            &QuotaState::default(),
            ts("2026-05-19T12:00:00Z"),
        );
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].usage.period_key, "total");
    }

    #[test]
    fn check_respects_global_disable() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Monthly);
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 200);
        let quota_cfg = QuotaConfig {
            enabled: false,
            ..QuotaConfig::default()
        };
        let decisions = check_and_decide(
            &[rule],
            &stats,
            &quota_cfg,
            &QuotaState::default(),
            ts("2026-05-19T12:00:00Z"),
        );
        assert!(decisions.is_empty());
    }

    #[test]
    fn check_dedups_notification_within_period() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Monthly);
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 200);
        let mut state = QuotaState::default();
        state.mark_notified("r0:monthly:2026-05", ts("2026-05-19T11:00:00Z"));
        let decisions = check_and_decide(
            &[rule],
            &stats,
            &QuotaConfig::default(),
            &state,
            ts("2026-05-19T12:00:00Z"),
        );
        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].should_notify);
    }

    #[test]
    fn apply_disable_sets_enabled_false_only_for_currently_enabled() {
        let rule = rule_with_quota(30080, 100, QuotaPeriod::Monthly);
        let mut config = TomlConfig::from_toml_str("rules = []").unwrap();
        config.rules.push(rule.clone());
        let usage = QuotaUsage {
            rule_id: "r0".to_string(),
            original_index: 0,
            label: None,
            period: QuotaPeriod::Monthly,
            period_key: "2026-05".to_string(),
            used_bytes: 200,
            limit_bytes: 100,
        };
        let decisions = vec![ExceededDecision {
            usage,
            newly_exceeded: true,
            should_notify: true,
        }];
        let changed = apply_disable_actions(&mut config, &decisions);
        assert_eq!(changed, vec![0]);
        assert!(!config.rules[0].enabled());
        // 第二次调用：规则已经 disabled，不再变动
        let changed2 = apply_disable_actions(&mut config, &decisions);
        assert!(changed2.is_empty());
    }

    #[test]
    fn quota_state_clear_for_rule_drops_all_periods() {
        let mut state = QuotaState::default();
        state.mark_notified("r0:monthly:2026-05", Utc.timestamp_opt(0, 0).unwrap());
        state.mark_notified("r0:daily:2026-05-19", Utc.timestamp_opt(0, 0).unwrap());
        state.mark_notified("r1:monthly:2026-05", Utc.timestamp_opt(0, 0).unwrap());
        state.clear_for_rule("r0");
        assert!(!state.is_notified("r0:monthly:2026-05"));
        assert!(!state.is_notified("r0:daily:2026-05-19"));
        assert!(state.is_notified("r1:monthly:2026-05"));
    }

    #[test]
    fn save_load_roundtrips_quota_state() {
        let dir = std::env::temp_dir().join(format!(
            "nat-quota-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("quota.json").to_string_lossy().to_string();
        let mut state = QuotaState::default();
        state.mark_notified("r0:monthly:2026-05", ts("2026-05-19T12:00:00Z"));
        state.save(&path).unwrap();
        let loaded = QuotaState::load(&path);
        assert!(loaded.is_notified("r0:monthly:2026-05"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn telegram_message_contains_no_secrets() {
        let usage = QuotaUsage {
            rule_id: "r0".to_string(),
            original_index: 0,
            label: Some("hk-out".to_string()),
            period: QuotaPeriod::Monthly,
            period_key: "2026-05".to_string(),
            used_bytes: 105 * 1024 * 1024 * 1024,
            limit_bytes: 100 * 1024 * 1024 * 1024,
        };
        let msg = format_telegram_message(&ExceededDecision {
            usage,
            newly_exceeded: true,
            should_notify: true,
        });
        assert!(msg.contains("hk-out"));
        assert!(msg.contains("monthly"));
        assert!(msg.contains("disabled"));
        assert!(!msg.to_lowercase().contains("bot_token"));
        assert!(!msg.to_lowercase().contains("token"));
    }

    // ---- M-1 回归测试：disabled 规则排在 enabled 规则之前时的 rule_id 对齐 ----

    fn disabled_rule(sport: u16) -> NftCell {
        let mut rule = rule_with_quota(sport, 100, QuotaPeriod::Monthly);
        rule.set_enabled(false);
        rule
    }

    fn drop_rule() -> NftCell {
        NftCell::Drop {
            chain: crate::Chain::Input,
            src_ip: Some("198.51.100.7".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        }
    }

    #[test]
    fn compute_usages_aligns_rule_id_with_nft_when_disabled_rule_precedes() {
        // config.rules = [disabled, enabled_with_quota]
        // nft 只为启用规则编号 → 启用规则是 r0（不是 r1）。
        let rules = vec![
            disabled_rule(30000),
            rule_with_quota(30080, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 200);
        // 故意往 r1 放干扰流量，确保不会被误读。
        stats
            .per_rule_monthly_bytes
            .insert("r1".to_string(), 999_999);

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 1);
        let usage = &usages[0];
        assert_eq!(usage.rule_id, "r0", "启用规则必须对应 nft 的 r0");
        assert_eq!(
            usage.original_index, 1,
            "original_index 必须是 config.rules 真实下标"
        );
        assert_eq!(usage.used_bytes, 200, "必须读到 r0 的流量，而不是 r1");
    }

    #[test]
    fn compute_usages_reads_per_rule_label_with_aligned_rule_id() {
        let rules = vec![
            disabled_rule(30000),
            rule_with_quota(30080, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 50);
        stats.rule_labels.insert(
            "r0".to_string(),
            "hk-out: 30080 -> example.com:80/tcp".to_string(),
        );
        // r1 放一个错误 label，确保不会被误取。
        stats
            .rule_labels
            .insert("r1".to_string(), "WRONG".to_string());

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 1);
        assert_eq!(
            usages[0].label.as_deref(),
            Some("hk-out: 30080 -> example.com:80/tcp")
        );
    }

    #[test]
    fn apply_disable_disables_correct_rule_with_leading_disabled() {
        // 超额的是 config.rules[1]，必须禁用它，不能误动 config.rules[0]。
        let mut config = TomlConfig::from_toml_str("rules = []").unwrap();
        config.rules.push(disabled_rule(30000));
        config
            .rules
            .push(rule_with_quota(30080, 100, QuotaPeriod::Monthly));
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 200);

        let decisions = check_and_decide(
            &config.rules,
            &stats,
            &QuotaConfig::default(),
            &QuotaState::default(),
            ts("2026-05-19T12:00:00Z"),
        );
        assert_eq!(decisions.len(), 1);
        let changed = apply_disable_actions(&mut config, &decisions);
        assert_eq!(changed, vec![1], "必须改 config.rules[1]");
        assert!(!config.rules[1].enabled(), "超额规则（下标 1）必须被禁用");
        // 下标 0 本来就 disabled，不应被 apply 改成 changed。
        assert!(!config.rules[0].enabled());
    }

    #[test]
    fn compute_usages_aligns_multiple_rules_after_leading_disabled() {
        // config.rules = [disabled, enabled_A, enabled_B] → A=r0, B=r1
        let rules = vec![
            disabled_rule(30000),
            rule_with_quota(30080, 100, QuotaPeriod::Monthly),
            rule_with_quota(30090, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 111);
        stats.per_rule_monthly_bytes.insert("r1".to_string(), 222);

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 2);
        // A = config.rules[1] = r0 = 111
        assert_eq!(usages[0].rule_id, "r0");
        assert_eq!(usages[0].original_index, 1);
        assert_eq!(usages[0].used_bytes, 111);
        // B = config.rules[2] = r1 = 222
        assert_eq!(usages[1].rule_id, "r1");
        assert_eq!(usages[1].original_index, 2);
        assert_eq!(usages[1].used_bytes, 222);
    }

    #[test]
    fn compute_usages_renumbers_after_leading_rule_auto_disabled() {
        // 先 [enabled_A, enabled_B] → A=r0, B=r1。A 被自动禁用后 config = [disabled_A, enabled_B]，
        // 下一轮 B 应重新对应 r0，能读到 r0 的流量，而不是继续查旧的 r1。
        let rules = vec![
            disabled_rule(30080),
            rule_with_quota(30090, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 333);

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].rule_id, "r0");
        assert_eq!(usages[0].original_index, 1);
        assert_eq!(usages[0].used_bytes, 333);
    }

    #[test]
    fn compute_usages_drop_rule_consumes_rule_id_slot() {
        // Drop 规则是启用的，会占用 r0 序号（和 nft 生成一致），所以带 quota 的规则是 r1。
        let rules = vec![
            drop_rule(),
            rule_with_quota(30080, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r1".to_string(), 700);
        // r0 是 Drop 的位置，不该被 quota 规则读到。
        stats
            .per_rule_monthly_bytes
            .insert("r0".to_string(), 999_999);

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].rule_id, "r1", "Drop 占用 r0，quota 规则应为 r1");
        assert_eq!(usages[0].original_index, 1);
        assert_eq!(usages[0].used_bytes, 700);
    }

    #[test]
    fn compute_usages_all_enabled_unchanged_behaviour() {
        // 没有 disabled 规则时，启用序号 == 数组下标，行为与修复前一致。
        let rules = vec![
            rule_with_quota(30080, 100, QuotaPeriod::Monthly),
            rule_with_quota(30090, 100, QuotaPeriod::Monthly),
        ];
        let mut stats = StatsState::default();
        stats.per_rule_monthly_bytes.insert("r0".to_string(), 10);
        stats.per_rule_monthly_bytes.insert("r1".to_string(), 20);

        let usages = compute_usages(&rules, &stats, ts("2026-05-19T12:00:00Z"));
        assert_eq!(usages.len(), 2);
        assert_eq!(
            (
                usages[0].rule_id.as_str(),
                usages[0].original_index,
                usages[0].used_bytes
            ),
            ("r0", 0, 10)
        );
        assert_eq!(
            (
                usages[1].rule_id.as_str(),
                usages[1].original_index,
                usages[1].used_bytes
            ),
            ("r1", 1, 20)
        );
    }
}
