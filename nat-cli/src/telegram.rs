//! nat.service 侧的 Telegram 客户端：基于 `curl` 子进程，绝不阻塞主循环。
//!
//! 拆自原 `main.rs`（v0.6.1 维护性重构）；行为与 v0.6.0 一致：
//! - 强制 `--connect-timeout 5` 和 `--max-time 15`，避免网络挂死阻塞 nat.service
//! - stderr / 错误明细统一走 [`sanitize_telegram_error`] 把 `bot_token` 脱敏
//!
//! CLI 侧的 Telegram 调用（菜单 → 测试通知）有独立的 `cli` 变体，在 `menu` 中实现，
//! 不复用本模块，避免互相耦合。

use log::warn;
use nat_common::{StatsConfig, TelegramConfig, stats as traffic_stats, stats::StatsState};
use std::process::Command;

const TELEGRAM_CURL_CONNECT_TIMEOUT_SECS: &str = "5";
const TELEGRAM_CURL_MAX_TIME_SECS: &str = "15";

/// Stats 通知触发点：节流 / 节假日策略由 `traffic_stats::should_notify` 决定，这里
/// 只负责构造消息体并通过 curl 发送，发送结果只更新通知时间或 WARN。
pub(crate) fn maybe_send_telegram(
    stats_config: &StatsConfig,
    telegram_config: &TelegramConfig,
    state: &mut StatsState,
    now: chrono::NaiveDateTime,
) {
    if !traffic_stats::should_notify(telegram_config, state, now) {
        return;
    }
    let message = traffic_stats::format_telegram_message_with_options(
        state,
        now,
        telegram_config.notify_daily,
        telegram_config.notify_monthly,
        stats_config.traffic_mode,
    );
    match traffic_stats::send_telegram_with(telegram_config, &message, send_telegram_http) {
        Ok(()) => {
            state.last_notify_time = Some(now.format("%Y-%m-%d %H:%M:%S").to_string());
            if let Err(e) = traffic_stats::save_state(&stats_config.data_file, state) {
                warn!("保存 Telegram 通知时间失败: {e:?}");
            }
        }
        Err(e) => {
            warn!(
                "Telegram 通知发送失败 token={} err={}",
                traffic_stats::mask_bot_token(&telegram_config.bot_token),
                e
            );
        }
    }
}

/// nat.service 侧 Telegram 发送器（curl 子进程版）。
pub(crate) fn send_telegram_http(url: &str, params: &[(&str, &str)]) -> Result<(), String> {
    build_telegram_curl_command(url, params)
        .output()
        .map_err(|e| format!("执行 curl 失败: {e}"))
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                // bot_token 已经在 URL 里，stderr 默认不会回显请求体；但稳妥起见，
                // 用 mask_bot_token 把任何意外出现的 token 片段脱敏后再返回给上层。
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                Err(sanitize_telegram_error(&stderr, url))
            }
        })
}

/// 构造 Telegram HTTPS 请求的 curl 命令。强制带上 --connect-timeout 与 --max-time，
/// 防止网络挂死阻塞 nat.service 主循环。
pub(crate) fn build_telegram_curl_command(url: &str, params: &[(&str, &str)]) -> Command {
    let mut command = Command::new("curl");
    command
        .arg("-sS")
        .arg("--connect-timeout")
        .arg(TELEGRAM_CURL_CONNECT_TIMEOUT_SECS)
        .arg("--max-time")
        .arg(TELEGRAM_CURL_MAX_TIME_SECS)
        .arg("-X")
        .arg("POST")
        .arg(url);
    for (key, value) in params {
        command
            .arg("--data-urlencode")
            .arg(format!("{key}={value}"));
    }
    command
}

/// 把可能出现在 stderr 中的 bot_token 字段脱敏（curl 通常只回显 url path 的一部分，
/// 但 5xx / timeout 错误个别版本会回显完整 URL）。
pub(crate) fn sanitize_telegram_error(stderr: &str, url: &str) -> String {
    let mut out = stderr.to_string();
    // url 形如 https://api.telegram.org/bot<TOKEN>/sendMessage；
    // 把 bot<token> 这段替换掉，避免 stderr 携带原 token。
    if let Some(start) = url.find("/bot")
        && let Some(rest) = url.get(start + 4..)
    {
        let token: String = rest.chars().take_while(|c| *c != '/').collect();
        if !token.is_empty() {
            let masked = traffic_stats::mask_bot_token(&token);
            out = out.replace(&token, &masked);
        }
    }
    out
}
