//! nat.service quota 自动禁用循环。
//!
//! 拆自原 `main.rs`（v0.6.1 维护性重构），语义未改：
//! - 读 `/etc/nat.toml` + Stats 当前用量 → `quota::check_and_decide`
//! - 超额且未通知 → 写 `quota.exceeded` / `rule.disable.quota` audit，按 Telegram 配置发送通知
//! - 真正禁用 → 走 [`crate::menu::safe_write_config_to`] 写回 TOML（备份 → 原子写 → audit）
//! - 任何步骤失败只 WARN / 写 audit，不让主循环退出

use log::warn;
use nat_common::{
    Args, AuditConfig, QuotaConfig, StatsConfig, TelegramConfig, TomlConfig,
    audit::{self, AuditResult},
    quota, stats as traffic_stats,
};
use std::fs;
use std::path::Path;

use crate::{BACKUP_DIR, menu, telegram::send_telegram_http};

/// 跑一轮 quota 检查：读 TOML + Stats，找出超额规则，禁用并写 audit / Telegram。
/// 任何失败都只 WARN，不让主循环退出。
pub(crate) fn run_quota_check(
    args: &Args,
    quota_config: &QuotaConfig,
    audit_config: &AuditConfig,
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    now: chrono::DateTime<chrono::Utc>,
) {
    run_quota_check_with(
        args,
        quota_config,
        audit_config,
        stats_config,
        telegram_config,
        now,
        Path::new(BACKUP_DIR),
    )
}

/// `run_quota_check` 的可注入备份根目录变体；生产代码走 `run_quota_check`，
/// 测试可以注入 tmpdir，避免污染 /etc/nftables-nat/backups。
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_quota_check_with(
    args: &Args,
    quota_config: &QuotaConfig,
    audit_config: &AuditConfig,
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    now: chrono::DateTime<chrono::Utc>,
    backup_root: &Path,
) {
    let toml_path = match args.toml.as_deref() {
        Some(p) => p,
        None => return,
    };
    let content = match fs::read_to_string(toml_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("quota 检查跳过：读 {toml_path} 失败 {e}");
            return;
        }
    };
    let mut config = match TomlConfig::from_toml_str(&content) {
        Ok(c) => c,
        Err(e) => {
            warn!("quota 检查跳过：解析 {toml_path} 失败 {e}");
            return;
        }
    };
    let stats_state = traffic_stats::load_state(&stats_config.data_file);
    let mut quota_state = quota::QuotaState::load(&quota_config.state_file);
    let decisions =
        quota::check_and_decide(&config.rules, &stats_state, quota_config, &quota_state, now);
    if decisions.is_empty() {
        return;
    }
    let changed_indices = quota::apply_disable_actions(&mut config, &decisions);
    if !changed_indices.is_empty() {
        let toml_str = match config.to_toml_string() {
            Ok(s) => s,
            Err(e) => {
                warn!("quota 写回 TOML 失败：序列化 {e}");
                audit::log_event(
                    audit_config,
                    "quota.auto_disable.skipped",
                    AuditResult::Fail,
                    serde_json::json!({
                        "reason": "serialize",
                        "error": e,
                    }),
                );
                return;
            }
        };
        // v0.6.0：统一走 safe_write_config_to。备份失败 → 跳过写回；
        // 写入失败 → 旧配置不动；成功 → 写 config.write.success audit。
        // 同时仍写 quota.auto_disable.write_ok / write_fail，保留旧报警入口。
        let backup_dir = backup_root.join("config");
        match menu::safe_write_config_to(
            &backup_dir,
            audit_config,
            toml_path,
            &toml_str,
            "quota.auto_disable",
        ) {
            Ok(backup_path) => {
                audit::log_event(
                    audit_config,
                    "quota.auto_disable.write_ok",
                    AuditResult::Ok,
                    serde_json::json!({
                        "toml_path": toml_path,
                        "backup": backup_path.display().to_string(),
                        "changed_indices": changed_indices,
                    }),
                );
            }
            Err(e) => {
                warn!(
                    "quota 写回 TOML 失败（safe_write_config）：{e}；旧配置保持不变，下一轮 quota 检查会重试"
                );
                audit::log_event(
                    audit_config,
                    "quota.auto_disable.write_fail",
                    AuditResult::Fail,
                    serde_json::json!({
                        "toml_path": toml_path,
                        "error": e.to_string(),
                    }),
                );
                return;
            }
        }
    }
    for decision in &decisions {
        let usage = &decision.usage;
        audit::log_event(
            audit_config,
            "quota.exceeded",
            AuditResult::Warn,
            serde_json::json!({
                "rule_id": usage.rule_id,
                "label": usage.label,
                "period": usage.period.to_string(),
                "period_key": usage.period_key,
                "used_bytes": usage.used_bytes,
                "limit_bytes": usage.limit_bytes,
            }),
        );
        if decision.newly_exceeded {
            audit::log_event(
                audit_config,
                "rule.disable.quota",
                AuditResult::Warn,
                serde_json::json!({
                    "rule_id": usage.rule_id,
                    "label": usage.label,
                    "period": usage.period.to_string(),
                }),
            );
        }
        if decision.should_notify {
            if telegram_config.enabled
                && !telegram_config.bot_token.is_empty()
                && !telegram_config.chat_id.is_empty()
                && quota_config.notify_on_exceeded
            {
                let msg = quota::format_telegram_message(decision);
                let send_result =
                    traffic_stats::send_telegram_with(telegram_config, &msg, send_telegram_http);
                audit::log_event(
                    audit_config,
                    "quota.telegram.notify",
                    if send_result.is_ok() {
                        AuditResult::Ok
                    } else {
                        AuditResult::Fail
                    },
                    serde_json::json!({
                        "rule_id": usage.rule_id,
                        "period_key": usage.period_key,
                        "delivered": send_result.is_ok(),
                    }),
                );
            } else {
                audit::log_event(
                    audit_config,
                    "quota.telegram.skipped",
                    AuditResult::Info,
                    serde_json::json!({
                        "rule_id": usage.rule_id,
                        "reason": if !quota_config.notify_on_exceeded {
                            "notify_on_exceeded=false"
                        } else if !telegram_config.enabled {
                            "telegram.disabled"
                        } else {
                            "telegram.unconfigured"
                        },
                    }),
                );
            }
            quota_state.mark_notified(&usage.notify_key(), now);
        }
    }
    if let Err(e) = quota_state.save(&quota_config.state_file) {
        warn!("保存 quota 通知状态失败 ({}): {e}", quota_config.state_file);
    }
}
