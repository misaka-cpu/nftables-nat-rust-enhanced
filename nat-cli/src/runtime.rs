//! nat.service 主循环用到的「时间窗口 / 检测节奏」辅助函数和事件转写。
//!
//! 拆自原 `main.rs`（v0.6.1 维护性重构）。本模块只包含纯计算 / 纯转写：
//! - DDNS 间隔校验与短间隔告警去抖
//! - 下一轮 sleep 时长计算
//! - Stats / quota 节流判定
//! - resolution events → audit log 转写
//! - Stats 采集 + 必要时触发 Telegram 通知
//!
//! `handle_loop` 与 `refresh_once` 仍在 `main.rs`：它们与 `parse_conf` /
//! `build_new_script` / FILE_NAME_SCRIPT / `prepare` 等 crate-root 内部项耦合较深，
//! 单独搬出会引入大量 `pub(crate)` 改动，超出本轮"只搬代码不改可见性"的目标。

use chrono::Local;
use log::warn;
use nat_common::{
    AuditConfig, DdnsConfig, QuotaConfig, StatsConfig, TelegramConfig,
    audit::{self, AuditResult},
    last_good::ResolutionEvent,
    stats::{self as traffic_stats, StatsState},
};
use std::collections::HashMap;
use std::io;
use std::process::Command;
use std::time::Duration;

use crate::MAIN_LOOP_MAX_SLEEP_SECS;
use crate::telegram::maybe_send_telegram;

pub(crate) fn ddns_refresh_interval(config: &DdnsConfig) -> Result<u64, io::Error> {
    let interval = config.refresh_interval_seconds;
    if interval < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refresh_interval_seconds too low",
        ));
    }
    Ok(interval)
}

pub(crate) fn warn_short_ddns_interval_once(interval: u64, last_warned: &mut Option<u64>) {
    if interval < 60 && *last_warned != Some(interval) {
        warn!("DDNS refresh interval is very short, recommended >= 300 seconds for production.");
        *last_warned = Some(interval);
    } else if interval >= 60 {
        *last_warned = None;
    }
}

pub(crate) fn should_collect_stats_at(
    stats_config: &StatsConfig,
    last_collect: Option<chrono::DateTime<Local>>,
    now: chrono::DateTime<Local>,
) -> bool {
    if !stats_config.enabled {
        return false;
    }
    let Some(last_collect) = last_collect else {
        return true;
    };
    let elapsed = now.signed_duration_since(last_collect);
    elapsed.num_seconds() >= stats_config.collect_interval_seconds as i64
}

pub(crate) fn should_refresh_ddns_at(
    last_refresh: Option<chrono::DateTime<Local>>,
    refresh_interval_seconds: u64,
    now: chrono::DateTime<Local>,
) -> bool {
    let Some(last_refresh) = last_refresh else {
        return true;
    };
    now.signed_duration_since(last_refresh).num_seconds() >= refresh_interval_seconds as i64
}

pub(crate) fn next_loop_sleep(
    ddns_interval_seconds: u64,
    stats_config: &StatsConfig,
    last_ddns_refresh: Option<chrono::DateTime<Local>>,
    last_stats_collect: Option<chrono::DateTime<Local>>,
    now: chrono::DateTime<Local>,
) -> Duration {
    let ddns_remaining = remaining_seconds(last_ddns_refresh, ddns_interval_seconds, now);
    let stats_remaining = if stats_config.enabled {
        remaining_seconds(
            last_stats_collect,
            stats_config.collect_interval_seconds,
            now,
        )
    } else {
        ddns_remaining
    };
    let sleep_secs = ddns_remaining
        .min(stats_remaining)
        .clamp(1, MAIN_LOOP_MAX_SLEEP_SECS);
    Duration::from_secs(sleep_secs)
}

pub(crate) fn should_run_quota_check(
    last: Option<chrono::DateTime<Local>>,
    quota_config: &QuotaConfig,
    now: chrono::DateTime<Local>,
) -> bool {
    let Some(last) = last else {
        return true;
    };
    now.signed_duration_since(last).num_seconds() >= quota_config.check_interval_seconds as i64
}

pub(crate) fn remaining_seconds(
    last_run: Option<chrono::DateTime<Local>>,
    interval_seconds: u64,
    now: chrono::DateTime<Local>,
) -> u64 {
    let Some(last_run) = last_run else {
        return 0;
    };
    let elapsed = now.signed_duration_since(last_run).num_seconds().max(0) as u64;
    interval_seconds.saturating_sub(elapsed)
}

/// 采集 nft counter → 更新 Stats 状态 → 若达到 Telegram 通知阈值则触发推送。
/// 任何步骤失败仅 WARN，不让主循环退出。
pub(crate) fn collect_and_maybe_notify(
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    rule_labels: &HashMap<String, String>,
) -> Option<StatsState> {
    let now = Local::now().naive_local();
    let output = match Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            warn!("执行 nft -j list ruleset 失败，跳过本次流量统计: {e:?}");
            return None;
        }
    };
    if !output.status.success() {
        warn!(
            "nft -j list ruleset 返回失败，跳过本次流量统计: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let json = String::from_utf8_lossy(&output.stdout);
    let mut state = match traffic_stats::collect_from_nft_json_with_config(
        &stats_config.data_file,
        &json,
        rule_labels,
        now,
        stats_config,
    ) {
        Ok(state) => state,
        Err(e) => {
            warn!("采集 nft counter 失败，nat 主循环继续运行: {e}");
            return None;
        }
    };

    maybe_send_telegram(stats_config, telegram_config, &mut state, now);
    Some(state)
}

/// 把 build 过程累计的 resolution events 转写到 audit log。
/// `LiveResolved` 不写每条 audit，避免日志爆炸；只记 last-good / 解析失败 / egress 命中等关键事件。
pub(crate) fn audit_resolution_events(audit_config: &AuditConfig, events: &[ResolutionEvent]) {
    for ev in events {
        match ev {
            ResolutionEvent::LiveResolved { .. } => {
                // 正常路径不写每条 audit
            }
            ResolutionEvent::LastGoodUsed {
                rule_id,
                comment,
                domain,
                ip,
                original_error,
                ..
            } => {
                audit::log_event(
                    audit_config,
                    "last_good.used",
                    AuditResult::Warn,
                    serde_json::json!({
                        "rule_id": rule_id,
                        "comment": comment,
                        "domain": domain,
                        "ip": ip,
                        "error": original_error,
                    }),
                );
            }
            ResolutionEvent::ResolveFailedNoCache {
                rule_id,
                comment,
                domain,
                original_error,
                ..
            } => {
                audit::log_event(
                    audit_config,
                    "dns.resolve.fail",
                    AuditResult::Fail,
                    serde_json::json!({
                        "rule_id": rule_id,
                        "comment": comment,
                        "domain": domain,
                        "error": original_error,
                    }),
                );
            }
            ResolutionEvent::EgressSkipped {
                rule_id,
                comment,
                ip,
                source,
                ..
            } => {
                audit::log_event(
                    audit_config,
                    "rule.skipped.egress_control",
                    AuditResult::Warn,
                    serde_json::json!({
                        "rule_id": rule_id,
                        "comment": comment,
                        "ip": ip,
                        "source": source.as_str(),
                    }),
                );
            }
        }
    }
}
