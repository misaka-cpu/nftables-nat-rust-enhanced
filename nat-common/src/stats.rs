use crate::{NftCell, StatsConfig, TelegramConfig, TomlConfig};
use chrono::{Local, NaiveDateTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCounter {
    pub id: String,
    pub label: String,
    pub counter_id: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsState {
    #[serde(default)]
    pub last_counters: HashMap<String, Counter>,
    #[serde(default)]
    pub daily_total_bytes: u64,
    #[serde(default)]
    pub monthly_total_bytes: u64,
    #[serde(default)]
    pub per_rule_daily_bytes: HashMap<String, u64>,
    #[serde(default)]
    pub per_rule_monthly_bytes: HashMap<String, u64>,
    #[serde(default)]
    pub rule_labels: HashMap<String, String>,
    #[serde(default)]
    pub rules: Vec<RuleTraffic>,
    pub last_day: String,
    pub last_month: String,
    #[serde(default)]
    pub last_collect_time: Option<String>,
    #[serde(default)]
    pub last_notify_time: Option<String>,
}

impl Default for StatsState {
    fn default() -> Self {
        let now = Local::now();
        Self {
            last_counters: HashMap::new(),
            daily_total_bytes: 0,
            monthly_total_bytes: 0,
            per_rule_daily_bytes: HashMap::new(),
            per_rule_monthly_bytes: HashMap::new(),
            rule_labels: HashMap::new(),
            rules: Vec::new(),
            last_day: now.format("%Y-%m-%d").to_string(),
            last_month: now.format("%Y-%m").to_string(),
            last_collect_time: None,
            last_notify_time: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTraffic {
    pub id: String,
    pub label: String,
    pub daily_bytes: u64,
    pub monthly_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsView {
    pub enabled: bool,
    pub data_file: String,
    pub daily_total_bytes: u64,
    pub monthly_total_bytes: u64,
    pub daily_total: String,
    pub monthly_total: String,
    pub last_day: String,
    pub last_month: String,
    pub last_collect_time: Option<String>,
    pub rules: Vec<RuleTraffic>,
}

pub fn parse_nft_counters(json: &str) -> Result<Vec<RuleCounter>, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("解析 nft JSON 失败: {e}"))?;
    let entries = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft JSON 缺少 nftables 数组".to_string())?;
    let mut counters = Vec::new();

    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        let table = rule
            .get("table")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let family = rule
            .get("family")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let chain = rule
            .get("chain")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if table != "self-filter" || chain != "FORWARD" {
            continue;
        }
        let handle = rule
            .get("handle")
            .and_then(Value::as_u64)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "nohandle".to_string());
        let mut counter = None;
        let mut comment = rule_level_comment(rule);
        if let Some(expr) = rule.get("expr") {
            find_counter_and_comment(expr, &mut counter, &mut comment);
        }
        let Some(counter) = counter else {
            continue;
        };
        let Some(comment) = comment else {
            continue;
        };
        let Some((id, counter_id)) = traffic_rule_ids(&comment) else {
            continue;
        };
        counters.push(RuleCounter {
            label: id.clone(),
            id,
            counter_id: counter_id
                .unwrap_or_else(|| format!("{family}/{table}/{chain}/handle/{handle}")),
            packets: counter.packets,
            bytes: counter.bytes,
        });
    }

    Ok(counters)
}

fn traffic_rule_ids(comment: &str) -> Option<(String, Option<String>)> {
    let payload = comment.strip_prefix("nat-traffic:")?;
    let fields = parse_nat_rule_comment(payload);
    let direction = fields
        .get("dir")
        .or_else(|| fields.get("direction"))
        .map(String::as_str)
        .unwrap_or("unknown");
    let id = fields
        .get("id")
        .cloned()
        .or_else(|| fields.get("index").map(|index| format!("r{index}")))?;
    let counter_id = format!("{id}:{direction}");
    Some((id, Some(counter_id)))
}

fn rule_level_comment(rule: &Value) -> Option<String> {
    rule.get("comment")
        .and_then(Value::as_str)
        .or_else(|| {
            rule.get("comment")
                .and_then(|value| value.get("comment"))
                .and_then(Value::as_str)
        })
        .map(ToString::to_string)
}

fn find_counter_and_comment(
    value: &Value,
    counter: &mut Option<Counter>,
    comment: &mut Option<String>,
) {
    match value {
        Value::Array(values) => {
            for item in values {
                find_counter_and_comment(item, counter, comment);
            }
        }
        Value::Object(map) => {
            if let Some(counter_value) = map.get("counter") {
                let packets = counter_value
                    .get("packets")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let bytes = counter_value
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                *counter = Some(Counter { packets, bytes });
            }
            if let Some(comment_value) = map.get("comment").and_then(Value::as_str).or_else(|| {
                map.get("comment")
                    .and_then(|value| value.get("comment"))
                    .and_then(Value::as_str)
            }) && (comment.is_none() || comment_value.starts_with("nat-traffic:"))
            {
                *comment = Some(comment_value.to_string());
            }
            for item in map.values() {
                find_counter_and_comment(item, counter, comment);
            }
        }
        _ => {}
    }
}

fn parse_nat_rule_comment(payload: &str) -> HashMap<String, String> {
    payload
        .split(',')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn rule_labels_from_config(config: &TomlConfig) -> HashMap<String, String> {
    config
        .rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| rule_to_label(rule).map(|label| (format!("r{index}"), label)))
        .collect()
}

fn rule_to_label(rule: &NftCell) -> Option<String> {
    match rule {
        NftCell::Single {
            sport,
            dport,
            domain,
            protocol,
            comment,
            ..
        } => Some(label_with_comment(
            comment,
            &format!("{sport} -> {domain}:{dport}/{protocol}"),
        )),
        NftCell::Range {
            port_start,
            port_end,
            domain,
            protocol,
            comment,
            ..
        } => Some(label_with_comment(
            comment,
            &format!("{port_start}-{port_end} -> {domain}:{port_start}-{port_end}/{protocol}"),
        )),
        NftCell::Redirect {
            src_port,
            src_port_end,
            dst_port,
            protocol,
            comment,
            ..
        } => {
            let sport = src_port_end
                .map(|end| format!("{src_port}-{end}"))
                .unwrap_or_else(|| src_port.to_string());
            Some(label_with_comment(
                comment,
                &format!("{sport} -> localhost:{dst_port}/{protocol}"),
            ))
        }
        NftCell::Drop { .. } => None,
    }
}

fn label_with_comment(comment: &Option<String>, route: &str) -> String {
    match comment.as_ref().filter(|comment| !comment.is_empty()) {
        Some(comment) => format!("{comment}: {route}"),
        None => route.to_string(),
    }
}

pub fn load_state(path: &str) -> StatsState {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

pub fn save_state(path: &str, state: &StatsState) -> Result<(), io::Error> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)
        .map_err(|e| io::Error::other(format!("序列化统计状态失败: {e}")))?;
    fs::write(path, content)
}

pub fn ensure_state_file(path: &str) -> Result<StatsState, io::Error> {
    let path_ref = Path::new(path);
    if path_ref.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("统计数据文件路径是目录: {}", path_ref.display()),
        ));
    }
    if path_ref.exists() {
        return Ok(load_state(path));
    }

    let mut state = StatsState::default();
    state.rules = build_rule_traffic(&state);
    save_state(path, &state)?;
    Ok(state)
}

pub fn apply_counter_snapshot(
    state: &mut StatsState,
    counters: &[RuleCounter],
    labels: &HashMap<String, String>,
    now: NaiveDateTime,
) {
    let day = now.format("%Y-%m-%d").to_string();
    let month = now.format("%Y-%m").to_string();
    if state.last_day != day {
        state.daily_total_bytes = 0;
        state.per_rule_daily_bytes.clear();
        state.last_day = day;
    }
    if state.last_month != month {
        state.monthly_total_bytes = 0;
        state.per_rule_monthly_bytes.clear();
        state.last_month = month;
    }

    for rule in counters {
        let delta = match state.last_counters.get(&rule.counter_id).cloned() {
            Some(previous) if rule.bytes >= previous.bytes => rule.bytes - previous.bytes,
            Some(previous) => {
                log::warn!(
                    "counter reset detected for {}: previous={} current={}",
                    rule.counter_id,
                    previous.bytes,
                    rule.bytes
                );
                0
            }
            None => 0,
        };
        state.daily_total_bytes = state.daily_total_bytes.saturating_add(delta);
        state.monthly_total_bytes = state.monthly_total_bytes.saturating_add(delta);
        *state
            .per_rule_daily_bytes
            .entry(rule.id.clone())
            .or_default() += delta;
        *state
            .per_rule_monthly_bytes
            .entry(rule.id.clone())
            .or_default() += delta;
        state.rule_labels.insert(
            rule.id.clone(),
            labels
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| rule.label.clone()),
        );
        state.last_counters.insert(
            rule.counter_id.clone(),
            Counter {
                packets: rule.packets,
                bytes: rule.bytes,
            },
        );
    }
    state.last_collect_time = Some(now.format("%Y-%m-%d %H:%M:%S").to_string());
    state.rules = build_rule_traffic(state);
}

pub fn collect_from_nft_json(
    path: &str,
    json: &str,
    now: NaiveDateTime,
) -> Result<StatsState, String> {
    collect_from_nft_json_with_labels(path, json, &HashMap::new(), now)
}

pub fn collect_from_nft_json_with_labels(
    path: &str,
    json: &str,
    labels: &HashMap<String, String>,
    now: NaiveDateTime,
) -> Result<StatsState, String> {
    let counters = parse_nft_counters(json)?;
    let mut state = load_state(path);
    apply_counter_snapshot(&mut state, &counters, labels, now);
    save_state(path, &state).map_err(|e| format!("保存统计状态失败: {e}"))?;
    Ok(state)
}

pub fn reset_daily(path: &str) -> Result<StatsState, io::Error> {
    let mut state = load_state(path);
    state.daily_total_bytes = 0;
    state.per_rule_daily_bytes.clear();
    state.rules = build_rule_traffic(&state);
    save_state(path, &state)?;
    Ok(state)
}

pub fn reset_monthly(path: &str) -> Result<StatsState, io::Error> {
    let mut state = load_state(path);
    state.monthly_total_bytes = 0;
    state.per_rule_monthly_bytes.clear();
    state.rules = build_rule_traffic(&state);
    save_state(path, &state)?;
    Ok(state)
}

fn build_rule_traffic(state: &StatsState) -> Vec<RuleTraffic> {
    let mut ids: Vec<String> = state
        .per_rule_daily_bytes
        .keys()
        .chain(state.per_rule_monthly_bytes.keys())
        .cloned()
        .collect();
    ids.sort();
    ids.dedup();

    let mut rules: Vec<RuleTraffic> = ids
        .into_iter()
        .map(|id| RuleTraffic {
            label: state
                .rule_labels
                .get(&id)
                .cloned()
                .unwrap_or_else(|| id.clone()),
            daily_bytes: *state.per_rule_daily_bytes.get(&id).unwrap_or(&0),
            monthly_bytes: *state.per_rule_monthly_bytes.get(&id).unwrap_or(&0),
            id,
        })
        .collect();
    rules.sort_by_key(|rule| Reverse(rule.daily_bytes));
    rules
}

pub fn state_to_view(config: &StatsConfig, state: &StatsState) -> StatsView {
    StatsView {
        enabled: config.enabled,
        data_file: config.data_file.clone(),
        daily_total_bytes: state.daily_total_bytes,
        monthly_total_bytes: state.monthly_total_bytes,
        daily_total: format_bytes(state.daily_total_bytes),
        monthly_total: format_bytes(state.monthly_total_bytes),
        last_day: state.last_day.clone(),
        last_month: state.last_month.clone(),
        last_collect_time: state.last_collect_time.clone(),
        rules: build_rule_traffic(state),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", units[unit])
    }
}

pub fn mask_bot_token(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }
    if token.len() <= 8 {
        return "****".to_string();
    }
    format!("{}****{}", &token[..4], &token[token.len() - 4..])
}

pub fn format_telegram_message(state: &StatsState, now: NaiveDateTime) -> String {
    format_telegram_message_with_options(state, now, true, true)
}

pub fn format_telegram_message_with_options(
    state: &StatsState,
    now: NaiveDateTime,
    notify_daily: bool,
    notify_monthly: bool,
) -> String {
    let mut rules: Vec<RuleTraffic> = state
        .per_rule_daily_bytes
        .iter()
        .map(|(id, daily_bytes)| RuleTraffic {
            id: id.clone(),
            label: state
                .rule_labels
                .get(id)
                .cloned()
                .unwrap_or_else(|| id.clone()),
            daily_bytes: *daily_bytes,
            monthly_bytes: *state.per_rule_monthly_bytes.get(id).unwrap_or(&0),
        })
        .collect();
    rules.sort_by_key(|rule| Reverse(rule.daily_bytes));

    let mut msg = format!("NAT 流量统计\n时间：{}", now.format("%Y-%m-%d %H:%M:%S"));
    if notify_daily {
        msg.push_str(&format!(
            "\n今日流量：{}",
            format_bytes(state.daily_total_bytes)
        ));
    }
    if notify_monthly {
        msg.push_str(&format!(
            "\n本月流量：{}",
            format_bytes(state.monthly_total_bytes)
        ));
    }
    msg.push_str(&format!(
        "\n最近采集：{}\n\nTOP 规则：",
        state
            .last_collect_time
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    ));
    for (idx, rule) in rules.into_iter().take(10).enumerate() {
        msg.push_str(&format!(
            "\n{}. {}：{}",
            idx + 1,
            rule.label,
            format_bytes(rule.daily_bytes)
        ));
    }
    msg
}

pub fn should_notify(config: &TelegramConfig, state: &StatsState, now: NaiveDateTime) -> bool {
    if !config.enabled || config.bot_token.is_empty() || config.chat_id.is_empty() {
        return false;
    }
    let Some(last) = &state.last_notify_time else {
        return true;
    };
    let Ok(last) = NaiveDateTime::parse_from_str(last, "%Y-%m-%d %H:%M:%S") else {
        return true;
    };
    (now - last).num_minutes() >= config.notify_interval_minutes as i64
}

pub fn send_telegram_with<F>(
    config: &TelegramConfig,
    message: &str,
    mut sender: F,
) -> Result<(), String>
where
    F: FnMut(&str, &[(&str, &str)]) -> Result<(), String>,
{
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        config.bot_token
    );
    sender(
        &url,
        &[("chat_id", config.chat_id.as_str()), ("text", message)],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::TomlConfig;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_stats_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "nat-common-stats-{name}-{}-{}",
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed),
            Local::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn sample_json(bytes: u64) -> String {
        format!(
            r#"{{
  "nftables": [
    {{"rule": {{"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
      "expr":[{{"counter":{{"packets":2,"bytes":{bytes}}}}},{{"comment":"nat-traffic:id=r0,dir=out"}}]}}}},
    {{"rule": {{"family":"ip","table":"other","chain":"X","handle":1,
      "expr":[{{"counter":{{"packets":1,"bytes":999}}}}]}}}}
  ]
}}"#
        )
    }

    #[test]
    fn parses_nft_json_counters() {
        let counters = parse_nft_counters(&sample_json(1234)).unwrap();
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].bytes, 1234);
        assert_eq!(counters[0].id, "r0");
        assert_eq!(counters[0].label, "r0");
        assert_eq!(counters[0].counter_id, "r0:out");
    }

    #[test]
    fn handles_counter_increment_and_reset() {
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let counters1 = parse_nft_counters(&sample_json(1000)).unwrap();
        let counters2 = parse_nft_counters(&sample_json(1500)).unwrap();
        let counters3 = parse_nft_counters(&sample_json(200)).unwrap();
        let mut state = StatsState::default();
        apply_counter_snapshot(&mut state, &counters1, &HashMap::new(), now);
        apply_counter_snapshot(&mut state, &counters2, &HashMap::new(), now);
        apply_counter_snapshot(&mut state, &counters3, &HashMap::new(), now);
        assert_eq!(state.daily_total_bytes, 500);
        assert_eq!(state.monthly_total_bytes, 500);
    }

    #[test]
    fn resets_daily_and_monthly_on_date_change() {
        let day1 =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let day2 =
            NaiveDateTime::parse_from_str("2026-05-18 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let month2 =
            NaiveDateTime::parse_from_str("2026-06-01 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let counters = parse_nft_counters(&sample_json(100)).unwrap();
        let mut state = StatsState::default();
        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), day1);
        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), day2);
        assert_eq!(state.daily_total_bytes, 0);
        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), month2);
        assert_eq!(state.monthly_total_bytes, 0);
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(12), "12 B");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn formats_telegram_message() {
        let mut state = StatsState {
            daily_total_bytes: 1024 * 1024,
            monthly_total_bytes: 2 * 1024 * 1024,
            last_collect_time: Some("2026-05-17 11:59:30".to_string()),
            ..Default::default()
        };
        state.per_rule_daily_bytes.insert("r1".to_string(), 900);
        state
            .rule_labels
            .insert("r1".to_string(), "30001 -> example.com:443".to_string());
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let msg = format_telegram_message(&state, now);
        assert!(msg.contains("NAT 流量统计"));
        assert!(msg.contains("1.00 MB"));
        assert!(msg.contains("30001 -> example.com:443"));
    }

    #[test]
    fn builds_friendly_labels_from_toml_config() {
        let config = TomlConfig::from_toml_str(
            r#"
[[rules]]
type = "single"
sport = 34120
dport = 44336
domain = "example.com"
protocol = "all"
ip_version = "ipv4"
comment = "https"
"#,
        )
        .unwrap();
        let labels = rule_labels_from_config(&config);
        assert_eq!(
            labels.get("r0").map(String::as_str),
            Some("https: 34120 -> example.com:44336/all")
        );
    }

    #[test]
    fn masks_bot_token() {
        assert_eq!(mask_bot_token(""), "");
        assert_eq!(mask_bot_token("abcdef"), "****");
        assert_eq!(mask_bot_token("1234567890abcdef"), "1234****cdef");
    }

    #[test]
    fn mock_telegram_send_success_and_failure() {
        let config = TelegramConfig {
            enabled: true,
            bot_token: "token".to_string(),
            chat_id: "chat".to_string(),
            ..Default::default()
        };
        assert!(
            send_telegram_with(&config, "hello", |url, params| {
                assert!(url.contains("/sendMessage"));
                assert_eq!(params[0], ("chat_id", "chat"));
                Ok(())
            })
            .is_ok()
        );
        assert!(
            send_telegram_with(&config, "hello", |_url, _params| Err("fail".to_string())).is_err()
        );
    }

    #[test]
    fn old_toml_without_stats_or_telegram_parses() {
        let config: TomlConfig = toml::from_str(
            r#"
[[rules]]
type = "redirect"
sport = 8080
dport = 3128
"#,
        )
        .unwrap();
        assert!(!config.stats.enabled);
        assert!(!config.telegram.enabled);
        assert_eq!(config.stats.collect_interval_seconds, 60);
    }

    #[test]
    fn dnat_counter_without_traffic_counter_is_not_counted() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-nat","chain":"PREROUTING","handle":3,
      "expr":[{"counter":{"packets":1,"bytes":52}},{"dnat":{"addr":"1.2.3.4","port":80}},{"comment":"r0"}]}}
  ]
}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let mut state = StatsState::default();
        let counters = parse_nft_counters(json).unwrap();
        let labels = HashMap::from([(
            "r0".to_string(),
            "stats-test-http: 30080 -> example.com:80/tcp".to_string(),
        )]);
        apply_counter_snapshot(&mut state, &counters, &labels, now);

        assert!(counters.is_empty());
        assert_eq!(state.daily_total_bytes, 0);
        assert_eq!(state.monthly_total_bytes, 0);
    }

    #[test]
    fn traffic_counters_sum_out_and_in() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
      "expr":[{"counter":{"packets":10,"bytes":1000}},{"comment":"nat-traffic:id=r0,dir=out"}]}},
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":11,
      "expr":[{"counter":{"packets":50,"bytes":5000}},{"comment":"nat-traffic:id=r0,dir=in"}]}}
  ]
}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let mut state = StatsState::default();
        let counters = parse_nft_counters(json).unwrap();
        let labels = HashMap::from([(
            "r0".to_string(),
            "stats-test-http: 30080 -> example.com:80/tcp".to_string(),
        )]);
        apply_counter_snapshot(&mut state, &counters, &labels, now);

        assert_eq!(counters.len(), 2);
        assert_eq!(state.daily_total_bytes, 0);
        assert_eq!(state.monthly_total_bytes, 0);
        assert_eq!(state.rules[0].daily_bytes, 0);
        assert_eq!(state.rules[0].id, "r0");
        assert_eq!(
            state.rules[0].label,
            "stats-test-http: 30080 -> example.com:80/tcp"
        );
    }

    #[test]
    fn traffic_counter_delta_uses_previous_baseline() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
      "expr":[{"counter":{"packets":10,"bytes":823}},{"comment":"nat-traffic:id=r0,dir=out"}]}},
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":11,
      "expr":[{"counter":{"packets":50,"bytes":476}},{"comment":"nat-traffic:id=r0,dir=in"}]}}
  ]
}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let counters = parse_nft_counters(json).unwrap();
        let mut state = StatsState::default();
        state.last_counters.insert(
            "r0:out".to_string(),
            Counter {
                packets: 1,
                bytes: 288,
            },
        );
        state.last_counters.insert(
            "r0:in".to_string(),
            Counter {
                packets: 1,
                bytes: 132,
            },
        );

        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), now);

        assert_eq!(state.daily_total_bytes, 879);
        assert_eq!(state.monthly_total_bytes, 879);
        assert_eq!(state.per_rule_daily_bytes.get("r0"), Some(&879));
    }

    #[test]
    fn counter_reset_does_not_add_current_value() {
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":7,
  "expr":[{"counter":{"packets":1,"bytes":100}},{"comment":"nat-traffic:id=r0,dir=out"}]}}
]}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let counters = parse_nft_counters(json).unwrap();
        let mut state = StatsState::default();
        state.last_counters.insert(
            "r0:out".to_string(),
            Counter {
                packets: 10,
                bytes: 1000,
            },
        );

        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), now);

        assert_eq!(state.daily_total_bytes, 0);
        assert_eq!(
            state.last_counters.get("r0:out").map(|c| c.bytes),
            Some(100)
        );
    }

    #[test]
    fn ignores_dnat_and_masquerade_when_traffic_counters_exist() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-nat","chain":"PREROUTING","handle":3,
      "expr":[{"counter":{"packets":1,"bytes":52}},{"dnat":{"addr":"1.2.3.4","port":80}},{"comment":"r0"}]}},
    {"rule": {"family":"ip","table":"self-nat","chain":"POSTROUTING","handle":4,
      "expr":[{"counter":{"packets":1,"bytes":52}},{"masquerade":null},{"comment":"SINGLE,30080,80,example.com,tcp,ipv4"}]}},
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
      "expr":[{"counter":{"packets":10,"bytes":1000}},{"comment":"nat-traffic:id=r0,dir=out"}]}},
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":11,
      "expr":[{"counter":{"packets":50,"bytes":5000}},{"comment":"nat-traffic:id=r0,dir=in"}]}}
  ]
}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let mut state = StatsState::default();
        let counters = parse_nft_counters(json).unwrap();
        apply_counter_snapshot(&mut state, &counters, &HashMap::new(), now);

        assert_eq!(state.daily_total_bytes, 0);
        assert_ne!(state.daily_total_bytes, 52);
        assert_ne!(state.daily_total_bytes, 104);
        assert_ne!(state.daily_total_bytes, 6104);
    }

    #[test]
    fn reads_nat_traffic_comment_from_rule_field() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
      "comment":"nat-traffic:id=r0,dir=out",
      "expr":[{"counter":{"packets":2,"bytes":260}}]}}
  ]
}"#;
        let counters = parse_nft_counters(json).unwrap();

        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].id, "r0");
        assert_eq!(counters[0].label, "r0");
    }

    #[test]
    fn reads_nat_traffic_comment_from_expr_field() {
        let json = r#"{
  "nftables": [
    {"rule": {"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
      "expr":[{"counter":{"packets":2,"bytes":260}},{"comment":"nat-traffic:id=r0,dir=in"}]}}
  ]
}"#;
        let counters = parse_nft_counters(json).unwrap();

        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].id, "r0");
        assert_eq!(counters[0].label, "r0");
    }

    #[test]
    fn comment_id_survives_handle_changes() {
        let json1 = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":3,
  "expr":[{"counter":{"packets":1,"bytes":100}},{"comment":"nat-traffic:id=r0,dir=out"}]}}
]}"#;
        let json2 = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":9,
  "expr":[{"counter":{"packets":2,"bytes":150}},{"comment":"nat-traffic:id=r0,dir=out"}]}}
]}"#;
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let mut state = StatsState::default();
        let counters1 = parse_nft_counters(json1).unwrap();
        let counters2 = parse_nft_counters(json2).unwrap();
        assert_eq!(counters1[0].id, counters2[0].id);

        apply_counter_snapshot(&mut state, &counters1, &HashMap::new(), now);
        apply_counter_snapshot(&mut state, &counters2, &HashMap::new(), now);

        assert_eq!(state.last_counters.len(), 1);
        assert_eq!(state.daily_total_bytes, 50);
    }

    #[test]
    fn ignores_forward_counters_without_nat_traffic_comment() {
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":7,
  "expr":[{"counter":{"packets":1,"bytes":42}}]}}
]}"#;
        let counters = parse_nft_counters(json).unwrap();

        assert!(counters.is_empty());
    }

    #[test]
    fn parses_udp_and_ipv6_traffic_counters() {
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":7,
  "expr":[{"counter":{"packets":1,"bytes":42}},{"comment":"nat-traffic:id=r1,dir=out"}]}},
  {"rule":{"family":"ip6","table":"self-filter","chain":"FORWARD","handle":8,
  "expr":[{"counter":{"packets":2,"bytes":84}},{"comment":"nat-traffic:id=r2,dir=out"}]}}
]}"#;
        let counters = parse_nft_counters(json).unwrap();

        assert_eq!(counters.len(), 2);
        assert_eq!(counters[0].label, "r1");
        assert_eq!(counters[1].label, "r2");
    }

    #[test]
    fn blacklist_drop_counter_is_not_counted_as_forward_traffic() {
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":7,
  "expr":[{"counter":{"packets":1,"bytes":42}},{"drop":null},{"comment":"blacklist"}]}}
]}"#;
        let counters = parse_nft_counters(json).unwrap();

        assert!(counters.is_empty());
    }

    #[test]
    fn ensure_state_file_creates_missing_parent_and_file() {
        let path = temp_stats_path("missing-parent").join("nested/stats.json");
        assert!(!path.exists());

        let state = ensure_state_file(path.to_str().unwrap()).unwrap();

        assert!(path.exists());
        assert_eq!(state.daily_total_bytes, 0);
        assert_eq!(state.monthly_total_bytes, 0);
        assert!(state.last_counters.is_empty());
        assert!(state.per_rule_daily_bytes.is_empty());
        assert!(state.per_rule_monthly_bytes.is_empty());
        assert!(state.rules.is_empty());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"last_counters\": {}"));
        assert!(content.contains("\"rules\": []"));
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn empty_rules_config_can_initialize_stats_json() {
        let config: TomlConfig = toml::from_str(
            r#"
rules = []

[stats]
enabled = true
data_file = "/tmp/nat-test-stats.json"
"#,
        )
        .unwrap();
        assert!(config.stats.enabled);
        assert!(config.rules.is_empty());

        let path = temp_stats_path("empty-rules").join("stats.json");
        ensure_state_file(path.to_str().unwrap()).unwrap();
        let state = load_state(path.to_str().unwrap());
        assert!(state.rules.is_empty());
        assert_eq!(state.daily_total_bytes, 0);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn collect_empty_ruleset_initializes_stats_json() {
        let path = temp_stats_path("empty-ruleset").join("stats.json");
        let now =
            NaiveDateTime::parse_from_str("2026-05-17 12:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
        let state = collect_from_nft_json(
            path.to_str().unwrap(),
            r#"{"nftables":[{"metainfo":{"json_schema_version":1}}]}"#,
            now,
        )
        .unwrap();

        assert!(path.exists());
        assert!(state.rules.is_empty());
        assert_eq!(
            state.last_collect_time.as_deref(),
            Some("2026-05-17 12:00:00")
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn ensure_state_file_error_does_not_panic() {
        let path = temp_stats_path("path-is-dir");
        fs::create_dir_all(&path).unwrap();

        let result = std::panic::catch_unwind(|| ensure_state_file(path.to_str().unwrap()));

        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
        let _ = fs::remove_dir_all(&path);
    }
}
