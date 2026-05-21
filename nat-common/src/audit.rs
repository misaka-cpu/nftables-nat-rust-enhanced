//! audit log 审计日志
//!
//! 简单的一行 JSON 追加器。失败只 WARN，不影响主流程。不写入 Telegram bot_token 等敏感字段。

use crate::AuditConfig;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult {
    Ok,
    Fail,
    Warn,
    Info,
}

impl AuditResult {
    fn as_str(self) -> &'static str {
        match self {
            AuditResult::Ok => "ok",
            AuditResult::Fail => "fail",
            AuditResult::Warn => "warn",
            AuditResult::Info => "info",
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditLine<'a> {
    time: String,
    action: &'a str,
    result: &'a str,
    detail: Value,
}

/// 写入一条审计事件。
/// - `config.enabled = false` 时静默不写。
/// - 写盘失败只 WARN，不返回 Err 上抛。
/// - 启用 `rotate` 时，append 前会先调用 [`maybe_rotate`] 做 best-effort 轮转；
///   轮转失败仅 WARN，不影响当前事件写入。
pub fn log_event(config: &AuditConfig, action: &str, result: AuditResult, detail: Value) {
    if !config.enabled {
        return;
    }
    let line = AuditLine {
        time: Utc::now().to_rfc3339(),
        action,
        result: result.as_str(),
        detail: redact(detail),
    };
    let serialized = match serde_json::to_string(&line) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("audit serialize 失败: {e}");
            return;
        }
    };
    if let Err(e) = maybe_rotate(config) {
        log::warn!("audit 轮转失败 ({}): {e}", config.file);
    }
    if let Err(e) = append_line(&config.file, &serialized) {
        log::warn!("audit 写入失败 ({}): {e}", config.file);
    }
}

fn append_line(path: &str, line: &str) -> io::Result<()> {
    let p = Path::new(path);
    if let Some(parent) = p.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(p)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// 检查当前 audit.log 大小，超过阈值时执行 best-effort 轮转。
/// 不抛 panic：任何 io 错误返回 Err，让上层只打印 WARN，不影响主流程。
///
/// 行为：
/// - `config.rotate = false` → 直接返回 Ok，不动文件。
/// - `config.max_size_mb = 0` → 视为禁用阈值检测，直接返回 Ok。
/// - 文件不存在或读不到 metadata → Ok（什么都不做）。
/// - 文件大小 ≤ 阈值 → Ok。
/// - 文件大小 > 阈值 →
///   - `max_backups == 0`：直接截断当前 audit.log（不保留 .1）。
///   - `max_backups >= 1`：滚动重命名 `.N-1 → .N`，最旧的被覆盖；
///     最终 `audit.log → audit.log.1`，并新建空 audit.log。
pub fn maybe_rotate(config: &AuditConfig) -> io::Result<()> {
    if !config.rotate {
        return Ok(());
    }
    if config.max_size_mb == 0 {
        return Ok(());
    }
    let limit = config.max_size_mb.saturating_mul(1024 * 1024);
    let path = Path::new(&config.file);
    let size = match fs::metadata(path) {
        Ok(meta) if meta.is_file() => meta.len(),
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size <= limit {
        return Ok(());
    }
    rotate_now(&config.file, config.max_backups)
}

/// 执行一次轮转（不再判断阈值）。供测试和 `maybe_rotate` 共用。
pub fn rotate_now(file: &str, max_backups: u32) -> io::Result<()> {
    if max_backups == 0 {
        // 直接截断；保留 inode，避免追加流仍指向旧 inode。
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file)?;
        return Ok(());
    }
    // 从最大的索引开始向前滚动，避免覆盖中间文件。
    //   audit.log.{N-1} -> audit.log.{N}   （N == max_backups 时直接删除目标外的）
    //   ...
    //   audit.log.1     -> audit.log.2
    //   audit.log       -> audit.log.1
    let path = Path::new(file);
    let parent = path.parent().unwrap_or(Path::new("."));
    let stem = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "audit.log".to_string());
    let suffix_path = |n: u32| -> PathBuf { parent.join(format!("{stem}.{n}")) };

    // 把最旧的扔掉（如果存在）：audit.log.{N+1} 不该存在，但 audit.log.{N} 要被覆盖
    for n in (1..=max_backups).rev() {
        let from = if n == 1 {
            path.to_path_buf()
        } else {
            suffix_path(n - 1)
        };
        let to = suffix_path(n);
        if !from.exists() {
            continue;
        }
        if to.exists() {
            let _ = fs::remove_file(&to);
        }
        fs::rename(&from, &to)?;
    }
    // rename 走完后 audit.log 已经不存在；下次 append_line 会重新 create。
    Ok(())
}

/// 在最近 `tail_limit` 行 audit 日志中查找最后一次 `apply.success` 的时间。
/// 找不到 → `None`。任何解析失败一律返回 `None`，不让调用方崩。
pub fn last_apply_success_time(path: &str, tail_limit: usize) -> Option<String> {
    last_action_time_matching(path, tail_limit, &["apply.success"])
}

/// 在最近 `tail_limit` 行 audit 日志中查找最后一次 `apply.success` 或 `apply.fail` 的事件，
/// 返回 `(action, time_rfc3339)`。找不到 → `None`。
pub fn last_apply_event(path: &str, tail_limit: usize) -> Option<(String, String)> {
    let lines = read_tail(path, tail_limit);
    for line in lines.iter().rev() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let action = value.get("action").and_then(Value::as_str).unwrap_or("");
        if action == "apply.success" || action == "apply.fail" {
            let time = value
                .get("time")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Some((action.to_string(), time));
        }
    }
    None
}

fn last_action_time_matching(path: &str, tail_limit: usize, actions: &[&str]) -> Option<String> {
    let lines = read_tail(path, tail_limit);
    for line in lines.iter().rev() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let action = value.get("action").and_then(Value::as_str).unwrap_or("");
        if actions.contains(&action) {
            return value
                .get("time")
                .and_then(Value::as_str)
                .map(ToString::to_string);
        }
    }
    None
}

/// 把一行 audit JSON 转成 CLI 友好的多行文本：
///
/// ```text
/// [2026-05-19 21:49:40 CST] update.start  info
///   version: latest
/// ```
///
/// - 时间字段按调用方传入的 `format_time` 闭包格式化（CLI 一般传 `format_cli_time_from_rfc3339`），
///   找不到 / 解析失败时退回原字符串。
/// - 解析失败的行返回 `"[无法解析] {raw_line}"`，不丢数据。
/// - `detail` 中的字段每行一条，已经在 [`log_event`] 流程里走过 [`redact`]，
///   这里再次调用 [`redact`] 作为防御性兜底，避免直接显示文件里残留的明文。
pub fn format_log_line_for_cli<F>(raw_line: &str, format_time: F) -> String
where
    F: Fn(&str) -> String,
{
    let value = match serde_json::from_str::<Value>(raw_line) {
        Ok(v) => v,
        Err(_) => return format!("[无法解析] {raw_line}"),
    };
    let time_raw = value.get("time").and_then(Value::as_str).unwrap_or("");
    let time = if time_raw.is_empty() {
        "(无时间)".to_string()
    } else {
        format_time(time_raw)
    };
    let action = value.get("action").and_then(Value::as_str).unwrap_or("?");
    let result = value.get("result").and_then(Value::as_str).unwrap_or("?");
    let mut out = format!("[{time}] {action}  {result}");
    if let Some(detail) = value.get("detail") {
        let redacted = redact(detail.clone());
        if let Value::Object(map) = redacted {
            for (k, v) in map {
                out.push('\n');
                out.push_str(&format!("  {k}: {}", render_detail_value(&v)));
            }
        } else if !redacted.is_null() {
            out.push('\n');
            out.push_str(&format!("  detail: {}", render_detail_value(&redacted)));
        }
    }
    out
}

fn render_detail_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// 读取 audit 日志的最近 `limit` 行；用于 CLI 查看。
/// 文件不存在 / 读失败均返回空 Vec。
pub fn read_tail(path: &str, limit: usize) -> Vec<String> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    if lines.len() > limit {
        let skip = lines.len() - limit;
        lines = lines.split_off(skip);
    }
    lines
}

/// 隐藏 detail 中可能出现的敏感字段；目前覆盖 Telegram bot_token / chat_id 也做轻度脱敏（保留首/尾各 2 位用于排查）。
/// 不在这里硬编码每个字段名，调用方应该在传入前自己处理；这里作为兜底网。
fn redact(detail: Value) -> Value {
    fn walk(v: Value) -> Value {
        match v {
            Value::Object(mut map) => {
                redact_object(&mut map);
                Value::Object(map)
            }
            Value::Array(arr) => Value::Array(arr.into_iter().map(walk).collect()),
            other => other,
        }
    }
    walk(detail)
}

fn redact_object(map: &mut Map<String, Value>) {
    // 大小写不敏感的子串匹配；覆盖常见敏感字段命名习惯：
    //   - token / bot_token / access_token / refresh_token / auth_token …
    //   - password / passwd
    //   - secret / client_secret / app_secret …
    //   - key / api_key / secret_key / access_key / private_key …
    //   - jwt / jwt_token
    //   - authorization / authorization_header
    // 注意：`key` 是宽匹配，会同时把 `period_key` / `notify_key` 这类非敏感字段也脱敏。
    // 这是有意权衡 —— 审计日志中宁可可读性下降，也不能漏掉一个像 `client_key` 这样的真实凭据。
    const SECRET_KEYS: &[&str] = &[
        "token",
        "password",
        "passwd",
        "secret",
        "key",
        "jwt",
        "authorization",
    ];
    let mut updates: Vec<(String, Value)> = Vec::new();
    let mut recurse: Vec<String> = Vec::new();
    for (key, value) in map.iter() {
        let lower = key.to_lowercase();
        if SECRET_KEYS.iter().any(|k| lower.contains(k)) {
            updates.push((key.clone(), Value::String(mask_value(value))));
        } else if matches!(value, Value::Object(_) | Value::Array(_)) {
            recurse.push(key.clone());
        }
    }
    for (k, v) in updates {
        map.insert(k, v);
    }
    for k in recurse {
        if let Some(v) = map.remove(&k) {
            let v = match v {
                Value::Object(mut inner) => {
                    redact_object(&mut inner);
                    Value::Object(inner)
                }
                Value::Array(arr) => Value::Array(
                    arr.into_iter()
                        .map(|item| match item {
                            Value::Object(mut inner) => {
                                redact_object(&mut inner);
                                Value::Object(inner)
                            }
                            other => other,
                        })
                        .collect(),
                ),
                other => other,
            };
            map.insert(k, v);
        }
    }
}

/// 用于状态显示的脱敏：保留首 2 / 尾 2 字符,中间替换为 ***
pub fn mask_value(value: &Value) -> String {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Null => return "<empty>".to_string(),
        other => other.to_string(),
    };
    mask_secret_str(&raw)
}

pub fn mask_secret_str(raw: &str) -> String {
    if raw.is_empty() {
        return "<empty>".to_string();
    }
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let head: String = chars.iter().take(2).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{head}***{tail}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tempfile(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "nat-audit-{}-{}-{name}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.log").to_string_lossy().to_string()
    }

    #[test]
    fn log_event_appends_one_json_line() {
        let path = tempfile("append");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(&cfg, "rule.add", AuditResult::Ok, json!({"sport": 30080}));
        log_event(&cfg, "rule.delete", AuditResult::Ok, json!({"index": 0}));
        let lines = read_tail(&path, 50);
        assert_eq!(lines.len(), 2);
        let parsed: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed["action"], "rule.add");
        assert_eq!(parsed["result"], "ok");
        assert_eq!(parsed["detail"]["sport"], 30080);
    }

    #[test]
    fn log_event_redacts_known_secret_keys() {
        let path = tempfile("redact");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "telegram.config.update",
            AuditResult::Ok,
            json!({"bot_token": "1234567890:ABCDEFGH", "chat_id": "12345"}),
        );
        let lines = read_tail(&path, 10);
        assert_eq!(lines.len(), 1);
        let parsed: Value = serde_json::from_str(&lines[0]).unwrap();
        let token_str = parsed["detail"]["bot_token"].as_str().unwrap();
        assert!(
            !token_str.contains("ABCDEFGH"),
            "raw bot_token must not be written: {token_str}"
        );
        assert!(token_str.contains("***"));
        assert!(!lines[0].contains("1234567890:ABCDEFGH"));
    }

    #[test]
    fn log_event_disabled_writes_nothing() {
        let path = tempfile("disabled");
        let cfg = AuditConfig {
            enabled: false,
            file: path.clone(),
            ..Default::default()
        };
        log_event(&cfg, "rule.add", AuditResult::Ok, json!({}));
        assert!(read_tail(&path, 10).is_empty());
    }

    #[test]
    fn log_event_failure_does_not_panic() {
        // 不可写路径：parent 无法创建（/proc 下任意文件名）
        let cfg = AuditConfig {
            enabled: true,
            file: "/proc/this/path/should/not/be/writable/audit.log".to_string(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "apply.fail",
            AuditResult::Fail,
            json!({"reason": "x"}),
        );
        // 没有 panic 即通过
    }

    #[test]
    fn read_tail_caps_to_limit() {
        let path = tempfile("tail");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        for i in 0..70 {
            log_event(&cfg, "rule.add", AuditResult::Ok, json!({"i": i}));
        }
        let lines = read_tail(&path, 50);
        assert_eq!(lines.len(), 50);
        let first: Value = serde_json::from_str(&lines[0]).unwrap();
        let last: Value = serde_json::from_str(&lines[49]).unwrap();
        assert_eq!(first["detail"]["i"], 20);
        assert_eq!(last["detail"]["i"], 69);
    }

    #[test]
    fn mask_secret_str_preserves_short_string_form() {
        assert_eq!(mask_secret_str(""), "<empty>");
        assert_eq!(mask_secret_str("ab"), "***");
        assert_eq!(mask_secret_str("abcdef"), "ab***ef");
    }

    #[test]
    fn log_event_redacts_case_insensitively() {
        let path = tempfile("case");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "demo",
            AuditResult::Ok,
            json!({
                "BOT_TOKEN": "9876543210:UPPERCASE_LEAKME",
                "ApiKey": "AKID_LEAKME",
                "JwtToken": "eyJhbGc.LEAKME.SIG",
                "Authorization": "Bearer LEAKME",
                "Password": "p@ssw0rd_LEAKME",
                "private_KEY": "PEM-LEAKME",
            }),
        );
        let lines = read_tail(&path, 1);
        assert_eq!(lines.len(), 1);
        let raw = &lines[0];
        for needle in [
            "UPPERCASE_LEAKME",
            "AKID_LEAKME",
            "eyJhbGc.LEAKME.SIG",
            "Bearer LEAKME",
            "p@ssw0rd_LEAKME",
            "PEM-LEAKME",
        ] {
            assert!(
                !raw.contains(needle),
                "audit log must not leak {needle}: {raw}"
            );
        }
        assert!(raw.contains("***"));
    }

    #[test]
    fn log_event_redacts_nested_authorization_and_jwt() {
        let path = tempfile("nested");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "demo",
            AuditResult::Ok,
            json!({
                "request": {
                    "headers": {
                        "Authorization": "Bearer NESTED_LEAKME",
                        "X-JWT": "JWT_NESTED_LEAKME",
                    }
                },
                "credentials": [
                    {"access_token": "AT_LEAKME"},
                    {"refresh_token": "RT_LEAKME"},
                ]
            }),
        );
        let lines = read_tail(&path, 1);
        assert_eq!(lines.len(), 1);
        let raw = &lines[0];
        for needle in [
            "NESTED_LEAKME",
            "JWT_NESTED_LEAKME",
            "AT_LEAKME",
            "RT_LEAKME",
        ] {
            assert!(
                !raw.contains(needle),
                "nested redact must not leak {needle}: {raw}"
            );
        }
    }

    #[test]
    fn telegram_bot_token_redaction_still_holds() {
        // Regression guard: 即便 SECRET_KEYS 改写后，Telegram bot_token 仍必须被脱敏
        let path = tempfile("tg-regression");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "telegram.config.update",
            AuditResult::Ok,
            json!({
                "bot_token": "1234567890:LEAKME_TG_REGRESSION",
                "chat_id": "99999",
                "enabled": true,
            }),
        );
        let lines = read_tail(&path, 1);
        assert_eq!(lines.len(), 1);
        assert!(
            !lines[0].contains("LEAKME_TG_REGRESSION"),
            "Telegram bot_token regression: {}",
            lines[0]
        );
    }

    // ============ v0.4.2: format_log_line_for_cli / last_apply_event ============

    #[test]
    fn format_log_line_renders_time_action_and_indented_detail() {
        let raw = r#"{"time":"2026-05-19T13:49:40Z","action":"update.start","result":"info","detail":{"version":"latest","trigger":"cli"}}"#;
        let pretty = format_log_line_for_cli(raw, crate::format_cli_time_from_rfc3339);
        // 时间应当转成 Asia/Shanghai 21:49:40
        assert!(
            pretty.contains("[2026-05-19 21:49:40"),
            "missing Shanghai time: {pretty}"
        );
        assert!(pretty.contains("update.start"));
        assert!(pretty.contains("info"));
        // detail 字段应当各自一行，按 kv 缩进
        assert!(pretty.contains("\n  version: latest"));
        assert!(pretty.contains("\n  trigger: cli"));
        // 不允许出现 RFC3339 的 T + 纳秒
        assert!(!pretty.contains("13:49:40Z"));
    }

    #[test]
    fn format_log_line_falls_back_to_raw_on_invalid_json() {
        let raw = "this is not json";
        let pretty = format_log_line_for_cli(raw, crate::format_cli_time_from_rfc3339);
        assert!(pretty.starts_with("[无法解析] "));
        assert!(pretty.contains(raw));
    }

    #[test]
    fn format_log_line_double_redacts_known_secret_keys() {
        let raw = r#"{"time":"2026-05-19T13:49:40Z","action":"telegram.config.update","result":"ok","detail":{"bot_token":"LEAKME_FORMAT","chat_id":"x"}}"#;
        let pretty = format_log_line_for_cli(raw, crate::format_cli_time_from_rfc3339);
        assert!(
            !pretty.contains("LEAKME_FORMAT"),
            "CLI 格式化也必须脱敏 bot_token: {pretty}"
        );
    }

    #[test]
    fn last_apply_event_finds_most_recent() {
        let path = tempfile("last-apply");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(
            &cfg,
            "apply.fail",
            AuditResult::Fail,
            json!({"error": "boom"}),
        );
        log_event(&cfg, "rule.add", AuditResult::Ok, json!({"index": 1}));
        log_event(
            &cfg,
            "apply.success",
            AuditResult::Ok,
            json!({"script_path": "/etc/nftables-nat/nat-diy.nft"}),
        );
        let (action, time) = last_apply_event(&path, 50).unwrap();
        assert_eq!(action, "apply.success");
        assert!(!time.is_empty());
        assert_eq!(
            last_apply_success_time(&path, 50).unwrap(),
            time,
            "last_apply_success_time 应返回与 last_apply_event 相同的时间"
        );
    }

    #[test]
    fn last_apply_event_returns_none_when_no_match() {
        let path = tempfile("no-apply");
        let cfg = AuditConfig {
            enabled: true,
            file: path.clone(),
            ..Default::default()
        };
        log_event(&cfg, "rule.add", AuditResult::Ok, json!({}));
        assert!(last_apply_event(&path, 50).is_none());
        assert!(last_apply_success_time(&path, 50).is_none());
    }

    // ============ v0.6.0: audit log 轻量轮转 ============

    fn audit_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-audit-rot-{}-{}-{name}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn audit_config_defaults_when_legacy_toml_lacks_rotate_fields() {
        // 旧 TOML 缺少 rotate / max_size_mb / max_backups 时，从 [audit] 段反序列化
        // 应当使用默认值：rotate=true、max_size_mb=10、max_backups=3
        #[derive(Debug, serde::Deserialize)]
        struct Wrapper {
            audit: AuditConfig,
        }
        let toml = r#"
            [audit]
            enabled = true
            file = "/tmp/x.log"
        "#;
        let parsed: Wrapper = toml::from_str(toml).unwrap();
        assert!(parsed.audit.rotate);
        assert_eq!(parsed.audit.max_size_mb, 10);
        assert_eq!(parsed.audit.max_backups, 3);
    }

    #[test]
    fn rotate_now_rolls_files_in_order() {
        let dir = audit_dir("order");
        let file = dir.join("audit.log");
        std::fs::write(&file, b"latest\n").unwrap();
        // 先制造 .1 和 .2，验证轮转后 .1->.2，.2->.3
        std::fs::write(dir.join("audit.log.1"), b"first\n").unwrap();
        std::fs::write(dir.join("audit.log.2"), b"second\n").unwrap();
        rotate_now(file.to_str().unwrap(), 3).unwrap();
        // 轮转后 audit.log 不应存在（下次 append_line 会重建）
        assert!(!file.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.1")).unwrap(),
            "latest\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.2")).unwrap(),
            "first\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.3")).unwrap(),
            "second\n"
        );
    }

    #[test]
    fn rotate_now_drops_oldest_when_exceeding_max_backups() {
        let dir = audit_dir("drop-old");
        let file = dir.join("audit.log");
        std::fs::write(&file, b"latest\n").unwrap();
        std::fs::write(dir.join("audit.log.1"), b"old1\n").unwrap();
        std::fs::write(dir.join("audit.log.2"), b"old2\n").unwrap();
        std::fs::write(dir.join("audit.log.3"), b"old3\n").unwrap();
        rotate_now(file.to_str().unwrap(), 3).unwrap();
        assert!(!file.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.1")).unwrap(),
            "latest\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.2")).unwrap(),
            "old1\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.log.3")).unwrap(),
            "old2\n"
        );
        // .4 不应被生成
        assert!(!dir.join("audit.log.4").exists());
    }

    #[test]
    fn rotate_now_max_backups_zero_truncates_current_only() {
        let dir = audit_dir("zero");
        let file = dir.join("audit.log");
        std::fs::write(&file, b"latest\n").unwrap();
        rotate_now(file.to_str().unwrap(), 0).unwrap();
        // max_backups=0：截断当前文件，不生成 .1
        assert!(file.exists());
        assert!(std::fs::read_to_string(&file).unwrap().is_empty());
        assert!(!dir.join("audit.log.1").exists());
    }

    #[test]
    fn maybe_rotate_skips_when_rotate_false() {
        let dir = audit_dir("rotate-false");
        let file = dir.join("audit.log");
        std::fs::write(&file, vec![b'a'; 2 * 1024 * 1024]).unwrap();
        let cfg = AuditConfig {
            enabled: true,
            file: file.to_string_lossy().to_string(),
            rotate: false,
            max_size_mb: 1,
            max_backups: 3,
        };
        maybe_rotate(&cfg).unwrap();
        // 文件保持不动
        assert!(file.exists());
        assert!(!dir.join("audit.log.1").exists());
    }

    #[test]
    fn maybe_rotate_below_threshold_does_nothing() {
        let dir = audit_dir("under-threshold");
        let file = dir.join("audit.log");
        std::fs::write(&file, b"tiny\n").unwrap();
        let cfg = AuditConfig {
            enabled: true,
            file: file.to_string_lossy().to_string(),
            rotate: true,
            max_size_mb: 1,
            max_backups: 3,
        };
        maybe_rotate(&cfg).unwrap();
        assert!(file.exists());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "tiny\n");
        assert!(!dir.join("audit.log.1").exists());
    }

    #[test]
    fn log_event_triggers_rotation_when_size_exceeds_limit() {
        let dir = audit_dir("auto-rotate");
        let file = dir.join("audit.log");
        // 写 1.5MB 数据，超过 1MB 阈值
        std::fs::write(&file, vec![b'X'; 1_572_864]).unwrap();
        let cfg = AuditConfig {
            enabled: true,
            file: file.to_string_lossy().to_string(),
            rotate: true,
            max_size_mb: 1,
            max_backups: 3,
        };
        log_event(&cfg, "rotate.test", AuditResult::Ok, json!({"i": 1}));
        // audit.log.1 应包含旧的 X*；audit.log 应只包含本次新写入的 JSON 行
        let rotated = std::fs::read_to_string(dir.join("audit.log.1")).unwrap();
        assert!(rotated.starts_with('X'));
        let current = std::fs::read_to_string(&file).unwrap();
        let parsed: Value = serde_json::from_str(current.trim()).unwrap();
        assert_eq!(parsed["action"], "rotate.test");
    }

    #[test]
    fn maybe_rotate_does_not_panic_on_unwritable_path() {
        // /proc 下不存在的父目录：metadata 返回 NotFound，应当 Ok 直接返回。
        let cfg = AuditConfig {
            enabled: true,
            file: "/proc/this/path/should/not/exist/audit.log".to_string(),
            rotate: true,
            max_size_mb: 1,
            max_backups: 3,
        };
        assert!(maybe_rotate(&cfg).is_ok());
    }

    #[test]
    fn rotated_files_remain_one_line_json() {
        let dir = audit_dir("json-format");
        let file = dir.join("audit.log");
        let cfg = AuditConfig {
            enabled: true,
            file: file.to_string_lossy().to_string(),
            rotate: true,
            max_size_mb: 1,
            max_backups: 2,
        };
        // 先写一些数据使其超过阈值
        std::fs::write(&file, vec![b'1'; 1_572_864]).unwrap();
        log_event(&cfg, "post.rotate", AuditResult::Ok, json!({"k": "v"}));
        // 当前 audit.log 必须是一行 JSON
        let content = std::fs::read_to_string(&file).unwrap();
        let trimmed = content.trim_end_matches('\n');
        assert!(
            !trimmed.contains('\n'),
            "audit.log must be one JSON line: {content:?}"
        );
        let _: Value = serde_json::from_str(trimmed).unwrap();
    }
}
