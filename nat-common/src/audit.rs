//! audit log 审计日志
//!
//! 简单的一行 JSON 追加器。失败只 WARN，不影响主流程。不写入 Telegram bot_token 等敏感字段。

use crate::AuditConfig;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

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
}
