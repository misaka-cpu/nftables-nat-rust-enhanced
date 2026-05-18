use crate::config::{
    ConfigFormat, LegacyConfigLine, get_config_info, get_nftables_rules, load_config,
};
use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{Html, Response},
};
use axum_bootstrap::jwt::{Claims, ClaimsPayload, JwtConfig, LOGOUT_COOKIE};
use axum_extra::extract::CookieJar;
use chrono::Local;
use log::{error, info};
use nat_common::{
    AccessControlConfig, StatsConfig, TelegramConfig, TomlConfig, TrafficMode, forward_test,
    stats as traffic_stats,
    uninstall::{self, DataMode, UninstallTarget},
    validate_legacy_config,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

const TCP_CONGESTION_CONTROL: &str = "/proc/sys/net/ipv4/tcp_congestion_control";
const TCP_AVAILABLE_CONGESTION_CONTROL: &str =
    "/proc/sys/net/ipv4/tcp_available_congestion_control";
const DEFAULT_QDISC: &str = "/proc/sys/net/core/default_qdisc";
const BBR_SYSCTL_CONF: &str = "/etc/sysctl.d/99-nat-bbr.conf";
const CONFIG_BACKUP_DIR: &str = "/etc/nftables-nat/backups/config";

#[derive(Clone)]
pub struct AppState {
    pub jwt_config: JwtConfig,
    pub username: String,
    pub password_hash: String,
    /// 命令行指定的 TOML 配置文件路径（优先级高于 systemd 检测）
    pub toml_config: Option<String>,
    /// 命令行指定的传统配置文件路径（优先级高于 systemd 检测）
    pub compatible_config: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<(StatusCode, CookieJar, Json<LoginResponse>), StatusCode> {
    // 验证用户名
    if req.username != state.username {
        return Ok((
            StatusCode::UNAUTHORIZED,
            CookieJar::new(),
            Json(LoginResponse {
                success: false,
                message: "用户名或密码错误".to_string(),
                token: None,
            }),
        ));
    }

    // 验证密码
    let password_valid = bcrypt::verify(&req.password, &state.password_hash).map_err(|e| {
        error!("密码验证失败: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if !password_valid {
        return Ok((
            StatusCode::UNAUTHORIZED,
            CookieJar::new(),
            Json(LoginResponse {
                success: false,
                message: "用户名或密码错误".to_string(),
                token: None,
            }),
        ));
    }

    // 生成JWT token
    let claims = Claims::new(ClaimsPayload {
        username: req.username.clone(),
    });

    // 生成 Cookie（保持向后兼容）
    let cookie = claims.to_cookie(&state.jwt_config).map_err(|e| {
        error!("生成JWT cookie失败: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 从 Cookie 中提取 token 字符串（用于 Authorization header）
    let token_string = cookie.value().to_string();

    let jar = CookieJar::new().add(cookie);

    Ok((
        StatusCode::OK,
        jar,
        Json(LoginResponse {
            success: true,
            message: "登录成功".to_string(),
            token: Some(token_string),
        }),
    ))
}

pub async fn logout_handler() -> Result<(StatusCode, CookieJar, Json<LoginResponse>), StatusCode> {
    let jar = CookieJar::new().add(LOGOUT_COOKIE.clone());

    Ok((
        StatusCode::OK,
        jar,
        Json(LoginResponse {
            success: true,
            message: "已退出登录".to_string(),
            token: None,
        }),
    ))
}

#[derive(Serialize)]
pub struct UserInfo {
    username: String,
}

pub async fn get_current_user(
    Claims { payload, .. }: Claims,
) -> Result<Json<UserInfo>, StatusCode> {
    Ok(Json(UserInfo {
        username: payload.username,
    }))
}

#[derive(Serialize)]
pub struct ConfigResponse {
    format: String,
    content: String, // 直接返回字符串格式
}

pub async fn get_config(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ConfigResponse>, StatusCode> {
    // 优先使用命令行参数，否则从 NAT systemd service 检测配置格式
    let config_info = get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    )
    .map_err(|e| {
        error!("Failed to get config info: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let config = load_config(&config_info).map_err(|e| {
        error!("Failed to load config: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ConfigResponse {
        format: if config_info.is_toml {
            "toml".to_string()
        } else {
            "legacy".to_string()
        },
        content: config.to_string(),
    }))
}

#[derive(Deserialize)]
pub struct SaveConfigRequest {
    format: String,
    content: String, // 直接接收字符串格式
}

pub async fn save_config(
    _user: Claims,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveConfigRequest>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    info!("Saving config, format: {}", req.format);

    // 优先使用命令行参数，否则从 NAT systemd service 检测配置格式
    let config_info = get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    )
    .map_err(|e| {
        error!("Failed to get config info: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("获取配置信息失败: {}", e),
        )
    })?;

    // 验证请求的格式与检测到的格式一致
    let expected_format = if config_info.is_toml {
        "toml"
    } else {
        "legacy"
    };
    if req.format != expected_format {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "配置格式不匹配: 期望 {}, 收到 {}",
                expected_format, req.format
            ),
        ));
    }

    let new_config = match req.format.as_str() {
        "toml" => {
            // 使用 nat-common 的验证功能
            let parsed = TomlConfig::from_toml_str(&req.content).map_err(|e| {
                error!("Invalid TOML config: {:?}", e);
                (StatusCode::BAD_REQUEST, format!("配置验证失败: {}", e))
            })?;
            ConfigFormat::Toml(update_stats_section(&req.content, &parsed.stats)?)
        }
        "legacy" => {
            // 使用 nat-common 的验证功能
            validate_legacy_config(&req.content).map_err(|e| {
                error!("Invalid legacy config: {:?}", e);
                (StatusCode::BAD_REQUEST, format!("配置验证失败: {}", e))
            })?;
            let lines: Vec<LegacyConfigLine> = req
                .content
                .lines()
                .map(|line| LegacyConfigLine {
                    line: line.to_string(),
                })
                .collect();
            ConfigFormat::Legacy(lines)
        }
        _ => return Err((StatusCode::BAD_REQUEST, "未知的配置格式".to_string())),
    };

    // 保存到文件
    new_config
        .save_to_file(&config_info.config_path)
        .map_err(|e| {
            error!("Failed to save config to file: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存配置失败: {}", e),
            )
        })?;

    info!("Config saved successfully");
    Ok((StatusCode::OK, "配置已保存".to_string()))
}

pub async fn get_rules(_user: Claims) -> Result<Html<String>, (StatusCode, String)> {
    let rules = get_nftables_rules().map_err(|e| {
        error!("Failed to get nftables rules: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get rules: {}", e),
        )
    })?;

    Ok(Html(format!("<pre>{}</pre>", rules)))
}

#[derive(Serialize)]
pub struct RulesResponse {
    rules: String,
}

pub async fn get_rules_json(_user: Claims) -> Result<Json<RulesResponse>, (StatusCode, String)> {
    let rules = get_nftables_rules().map_err(|e| {
        error!("Failed to get nftables rules: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get rules: {}", e),
        )
    })?;

    Ok(Json(RulesResponse { rules }))
}

#[derive(Deserialize)]
pub struct ForwardTestIndexRequest {
    index: usize,
}

#[derive(Deserialize)]
pub struct ForwardTestObserveRequest {
    index: usize,
    #[serde(default = "default_observe_seconds")]
    seconds: u64,
}

fn default_observe_seconds() -> u64 {
    30
}

#[derive(Serialize)]
pub struct ForwardTestRulesResponse {
    rules: Vec<forward_test::TestableRule>,
}

#[derive(Serialize)]
pub struct ForwardTestCheckResponse {
    rule: forward_test::TestableRule,
    nat_service_active: bool,
    nft_rule_applied: bool,
    target_tcp_reachable: Option<bool>,
    udp_note: Option<String>,
    access_control: AccessControlConfig,
    access_control_note: Option<String>,
    baseline_counters: forward_test::RuleTestCounters,
    external_test_examples: forward_test::ExternalTestExamples,
}

#[derive(Serialize)]
pub struct ForwardTestObserveResponse {
    rule_id: String,
    seconds: u64,
    delta: forward_test::CounterDelta,
    verdict: String,
    message: String,
}

pub async fn get_forward_test_rules(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ForwardTestRulesResponse>, (StatusCode, String)> {
    let config = load_toml_config_for_forward_test(&state)?;
    Ok(Json(ForwardTestRulesResponse {
        rules: forward_test::list_testable_rules(&config),
    }))
}

pub async fn check_forward_test(
    _user: Claims,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForwardTestIndexRequest>,
) -> Result<Json<ForwardTestCheckResponse>, (StatusCode, String)> {
    let config = load_toml_config_for_forward_test(&state)?;
    let rule = find_testable_rule(&config, req.index)?;
    let nft_json = read_nft_json_ruleset().unwrap_or_default();
    let baseline_counters =
        forward_test::parse_rule_counters(&nft_json, &rule.id).unwrap_or_default();
    let target_tcp_reachable = async_tcp_connect_target(&rule).await;

    Ok(Json(ForwardTestCheckResponse {
        nft_rule_applied: forward_test::nft_rule_applied(&baseline_counters),
        nat_service_active: is_nat_service_active(),
        target_tcp_reachable,
        udp_note: if rule.protocol == "udp" || rule.protocol == "all" {
            Some("UDP 无连接，无法通过 connect 准确判断是否可达，请结合外部客户端访问和 counter 变化确认。".to_string())
        } else {
            None
        },
        access_control_note: forward_test::access_control_note(&config.access_control),
        access_control: config.access_control,
        external_test_examples: forward_test::external_examples(&rule),
        baseline_counters,
        rule,
    }))
}

pub async fn observe_forward_test(
    _user: Claims,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForwardTestObserveRequest>,
) -> Result<Json<ForwardTestObserveResponse>, (StatusCode, String)> {
    let seconds = req.seconds.clamp(1, 60);
    let config = load_toml_config_for_forward_test(&state)?;
    let rule = find_testable_rule(&config, req.index)?;
    let before_json = read_nft_json_ruleset().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 nft counters 失败: {e}"),
        )
    })?;
    let before = forward_test::parse_rule_counters(&before_json, &rule.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("解析 nft counters 失败: {e}"),
        )
    })?;
    sleep(Duration::from_secs(seconds)).await;
    let after_json = read_nft_json_ruleset().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 nft counters 失败: {e}"),
        )
    })?;
    let after = forward_test::parse_rule_counters(&after_json, &rule.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("解析 nft counters 失败: {e}"),
        )
    })?;
    let delta = forward_test::counter_delta(&before, &after);
    let verdict = forward_test::verdict_from_delta(&delta, forward_test::nft_rule_applied(&before));
    Ok(Json(ForwardTestObserveResponse {
        rule_id: rule.id,
        seconds,
        delta,
        verdict: verdict.verdict,
        message: verdict.message,
    }))
}

fn load_toml_config_for_forward_test(state: &AppState) -> Result<TomlConfig, (StatusCode, String)> {
    let config_info = get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("获取配置信息失败: {e}"),
        )
    })?;
    if !config_info.is_toml {
        return Err((
            StatusCode::BAD_REQUEST,
            "转发测试当前仅支持 TOML 配置。".to_string(),
        ));
    }
    let content = fs::read_to_string(&config_info.config_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取配置失败: {e}"),
        )
    })?;
    TomlConfig::from_toml_str(&content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("解析 TOML 配置失败: {e}")))
}

fn find_testable_rule(
    config: &TomlConfig,
    index: usize,
) -> Result<forward_test::TestableRule, (StatusCode, String)> {
    forward_test::list_testable_rules(config)
        .into_iter()
        .find(|rule| rule.index == index)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "规则 index 超出范围".to_string()))
}

fn read_nft_json_ruleset() -> Result<String, io::Error> {
    let output = Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

fn is_nat_service_active() -> bool {
    Command::new("systemctl")
        .arg("is-active")
        .arg("nat")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

async fn async_tcp_connect_target(rule: &forward_test::TestableRule) -> Option<bool> {
    if rule.protocol == "udp" {
        return None;
    }
    let target = rule.resolved_ip.as_deref().unwrap_or(&rule.target);
    let Ok(addr) = format!("{target}:{}", rule.dport).parse::<SocketAddr>() else {
        return None;
    };
    Some(
        timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr))
            .await
            .map(|result| result.is_ok())
            .unwrap_or(false),
    )
}

#[derive(Serialize)]
pub struct BbrStatusResponse {
    enabled: bool,
    tcp_congestion_control: String,
    available_congestion_control: String,
    default_qdisc: String,
    config_file: String,
}

pub async fn get_bbr_status(
    _user: Claims,
) -> Result<Json<BbrStatusResponse>, (StatusCode, String)> {
    let tcp_congestion_control = read_sysctl_value(TCP_CONGESTION_CONTROL);
    let available_congestion_control = read_sysctl_value(TCP_AVAILABLE_CONGESTION_CONTROL);
    let default_qdisc = read_sysctl_value(DEFAULT_QDISC);
    let enabled = tcp_congestion_control == "bbr" && default_qdisc == "fq";

    Ok(Json(BbrStatusResponse {
        enabled,
        tcp_congestion_control,
        available_congestion_control,
        default_qdisc,
        config_file: BBR_SYSCTL_CONF.to_string(),
    }))
}

#[derive(Serialize)]
pub struct BbrEnableResponse {
    success: bool,
    message: String,
    status: BbrStatusResponse,
}

pub async fn enable_bbr(_user: Claims) -> Result<Json<BbrEnableResponse>, (StatusCode, String)> {
    let config = "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n";
    fs::write(BBR_SYSCTL_CONF, config).map_err(|e| {
        error!("Failed to write BBR sysctl config: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("写入 BBR 配置失败: {}", e),
        )
    })?;

    run_sysctl_command(&["-w", "net.core.default_qdisc=fq"])?;
    run_sysctl_command(&["-w", "net.ipv4.tcp_congestion_control=bbr"])?;
    run_sysctl_command(&["-p", BBR_SYSCTL_CONF])?;

    let status = BbrStatusResponse {
        tcp_congestion_control: read_sysctl_value(TCP_CONGESTION_CONTROL),
        available_congestion_control: read_sysctl_value(TCP_AVAILABLE_CONGESTION_CONTROL),
        default_qdisc: read_sysctl_value(DEFAULT_QDISC),
        config_file: BBR_SYSCTL_CONF.to_string(),
        enabled: read_sysctl_value(TCP_CONGESTION_CONTROL) == "bbr"
            && read_sysctl_value(DEFAULT_QDISC) == "fq",
    };

    Ok(Json(BbrEnableResponse {
        success: status.enabled,
        message: if status.enabled {
            "BBR 已开启".to_string()
        } else {
            "已写入配置，但当前内核状态未显示 BBR+fq".to_string()
        },
        status,
    }))
}

#[derive(Serialize)]
pub struct TelegramStatusResponse {
    enabled: bool,
    bot_token_masked: String,
    chat_id: String,
    notify_interval_minutes: u64,
    notify_daily: bool,
    notify_monthly: bool,
}

#[derive(Serialize)]
pub struct TelegramTestResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize, Debug)]
pub struct TelegramConfigRequest {
    enabled: bool,
    #[serde(default)]
    bot_token: Option<String>,
    chat_id: String,
    notify_interval_minutes: u64,
    notify_daily: bool,
    notify_monthly: bool,
}

#[derive(Serialize)]
pub struct TelegramConfigResponse {
    success: bool,
    message: String,
    status: TelegramStatusResponse,
}

#[derive(Deserialize, Debug)]
pub struct StatsConfigRequest {
    traffic_mode: TrafficMode,
}

#[derive(Serialize)]
pub struct StatsConfigResponse {
    success: bool,
    message: String,
    status: traffic_stats::StatsView,
}

#[derive(Serialize)]
pub struct AccessControlStatusResponse {
    mode: String,
    entries: Vec<String>,
    scope: String,
}

#[derive(Serialize)]
pub struct NftTablesStatus {
    ip_self_nat: bool,
    ip6_self_nat: bool,
    ip_self_filter: bool,
    ip6_self_filter: bool,
}

#[derive(Serialize)]
pub struct UninstallFilesStatus {
    config_toml: bool,
    config_legacy: bool,
    stats_json: bool,
    backups_dir: bool,
    console_env: bool,
    console_cert: bool,
    console_key: bool,
}

#[derive(Serialize)]
pub struct UninstallStatusResponse {
    nat_service: String,
    nat_console_service: String,
    nat_binary: bool,
    nat_console_binary: bool,
    nft_tables: NftTablesStatus,
    files: UninstallFilesStatus,
}

#[derive(Deserialize)]
pub struct UninstallRequest {
    target: UninstallTarget,
    #[serde(default)]
    data_mode: DataMode,
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Serialize)]
pub struct UninstallResponse {
    ok: bool,
    actions: Vec<String>,
    kept: Vec<String>,
    warnings: Vec<String>,
}

pub async fn get_stats(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<traffic_stats::StatsView>, (StatusCode, String)> {
    let (stats_config, _) = load_observability_config(&state)?;
    if stats_config.enabled
        && let Err(e) = traffic_stats::ensure_state_file(&stats_config.data_file)
    {
        error!("Failed to initialize stats data file: {:?}", e);
    }
    let stats_state = traffic_stats::load_state(&stats_config.data_file);
    Ok(Json(traffic_stats::state_to_view(
        &stats_config,
        &stats_state,
    )))
}

pub async fn collect_stats_now(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<traffic_stats::StatsView>, (StatusCode, String)> {
    let config = load_toml_config_or_default(&state)?;
    if !config.stats.enabled {
        let stats_state = traffic_stats::load_state(&config.stats.data_file);
        return Ok(Json(traffic_stats::state_to_view(
            &config.stats,
            &stats_state,
        )));
    }
    let output = Command::new("/usr/sbin/nft")
        .arg("-j")
        .arg("list")
        .arg("ruleset")
        .output()
        .map_err(|e| {
            error!("Failed to run nft for collect-now: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("执行 nft -j list ruleset 失败: {}", e),
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        error!("nft collect-now failed: {}", stderr);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("nft -j list ruleset 失败: {}", stderr),
        ));
    }
    let labels = traffic_stats::rule_labels_from_config(&config);
    let stats_state = collect_stats_from_json_now(
        &config.stats,
        &labels,
        &String::from_utf8_lossy(&output.stdout),
        Local::now().naive_local(),
    )?;
    Ok(Json(traffic_stats::state_to_view(
        &config.stats,
        &stats_state,
    )))
}

pub async fn save_stats_config(
    _user: Claims,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StatsConfigRequest>,
) -> Result<Json<StatsConfigResponse>, (StatusCode, String)> {
    let config_info = get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("获取配置信息失败: {e}"),
        )
    })?;
    if !config_info.is_toml {
        return Err((
            StatusCode::BAD_REQUEST,
            "Stats 配置仅支持 TOML 配置文件".to_string(),
        ));
    }
    let config = save_stats_config_to_path(&config_info.config_path, &req, CONFIG_BACKUP_DIR)?;
    let stats_state = traffic_stats::load_state(&config.stats.data_file);
    Ok(Json(StatsConfigResponse {
        success: true,
        message: "统计口径已保存。后续新增流量按新口径累计；历史累计值不会自动重算。".to_string(),
        status: traffic_stats::state_to_view(&config.stats, &stats_state),
    }))
}

pub async fn reset_stats_daily(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<traffic_stats::StatsView>, (StatusCode, String)> {
    let (stats_config, _) = load_observability_config(&state)?;
    let stats_state = traffic_stats::reset_daily(&stats_config.data_file).map_err(|e| {
        error!("Failed to reset daily stats: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("重置今日统计失败: {}", e),
        )
    })?;
    Ok(Json(traffic_stats::state_to_view(
        &stats_config,
        &stats_state,
    )))
}

pub async fn reset_stats_monthly(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<traffic_stats::StatsView>, (StatusCode, String)> {
    let (stats_config, _) = load_observability_config(&state)?;
    let stats_state = traffic_stats::reset_monthly(&stats_config.data_file).map_err(|e| {
        error!("Failed to reset monthly stats: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("重置本月统计失败: {}", e),
        )
    })?;
    Ok(Json(traffic_stats::state_to_view(
        &stats_config,
        &stats_state,
    )))
}

pub async fn get_telegram_status(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TelegramStatusResponse>, (StatusCode, String)> {
    let (_, telegram_config) = load_observability_config(&state)?;
    Ok(Json(telegram_status_response(&telegram_config)))
}

pub async fn save_telegram_config(
    _user: Claims,
    State(state): State<Arc<AppState>>,
    Json(req): Json<TelegramConfigRequest>,
) -> Result<Json<TelegramConfigResponse>, (StatusCode, Json<TelegramConfigResponse>)> {
    let config_info = get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    )
    .map_err(|e| {
        telegram_config_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("获取配置信息失败: {e}"),
        )
    })?;
    if !config_info.is_toml {
        return Err(telegram_config_error(
            StatusCode::BAD_REQUEST,
            "Telegram 配置仅支持 TOML 配置文件",
        ));
    }

    let config = save_telegram_config_to_path(&config_info.config_path, &req, CONFIG_BACKUP_DIR)
        .map_err(|(status, message)| telegram_config_error(status, &message))?;
    Ok(Json(TelegramConfigResponse {
        success: true,
        message: "Telegram 配置已保存，nat 主服务会在下一轮读取配置后生效。".to_string(),
        status: telegram_status_response(&config.telegram),
    }))
}

pub async fn get_access_control_status(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AccessControlStatusResponse>, (StatusCode, String)> {
    let access_control = load_access_control_config(&state)?;
    Ok(Json(AccessControlStatusResponse {
        mode: access_control.mode.to_string(),
        entries: access_control.entries,
        scope: "只作用于本项目转发端口，不影响 SSH/WebUI".to_string(),
    }))
}

pub async fn get_uninstall_status(
    _user: Claims,
) -> Result<Json<UninstallStatusResponse>, (StatusCode, String)> {
    Ok(Json(UninstallStatusResponse {
        nat_service: service_status("nat"),
        nat_console_service: service_status("nat-console"),
        nat_binary: Path::new(uninstall::NAT_BINARY).exists(),
        nat_console_binary: Path::new(uninstall::NAT_CONSOLE_BINARY).exists(),
        nft_tables: NftTablesStatus {
            ip_self_nat: nft_table_exists("ip", "self-nat"),
            ip6_self_nat: nft_table_exists("ip6", "self-nat"),
            ip_self_filter: nft_table_exists("ip", "self-filter"),
            ip6_self_filter: nft_table_exists("ip6", "self-filter"),
        },
        files: UninstallFilesStatus {
            config_toml: Path::new(uninstall::CONFIG_TOML).exists(),
            config_legacy: Path::new(uninstall::CONFIG_LEGACY).exists(),
            stats_json: Path::new(uninstall::STATS_JSON).exists(),
            backups_dir: Path::new(uninstall::BACKUPS_DIR).exists(),
            console_env: Path::new(uninstall::CONSOLE_ENV).exists(),
            console_cert: Path::new(uninstall::CONSOLE_CERT).exists(),
            console_key: Path::new(uninstall::CONSOLE_KEY).exists(),
        },
    }))
}

pub async fn uninstall_handler(
    _user: Claims,
    Json(req): Json<UninstallRequest>,
) -> Result<Json<UninstallResponse>, (StatusCode, String)> {
    uninstall::validate_uninstall_request(req.target, req.data_mode, req.confirm.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut result = execute_uninstall(req.target, req.data_mode);
    result
        .warnings
        .extend(uninstall::plan_uninstall(req.target, req.data_mode).warnings);
    Ok(Json(UninstallResponse {
        ok: result.warnings.is_empty(),
        actions: result.actions,
        kept: result.kept,
        warnings: result.warnings,
    }))
}

pub async fn test_telegram(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TelegramTestResponse>, (StatusCode, Json<TelegramTestResponse>)> {
    let (stats_config, telegram_config) = load_observability_config(&state)
        .map_err(|(status, message)| telegram_test_error(status, &message))?;
    if !telegram_config.enabled
        || telegram_config.bot_token.is_empty()
        || telegram_config.chat_id.is_empty()
    {
        return Err(telegram_test_error(
            StatusCode::BAD_REQUEST,
            "Telegram 未启用，或 bot_token/chat_id 为空",
        ));
    }

    let stats_state = traffic_stats::load_state(&stats_config.data_file);
    let now = Local::now().naive_local();
    let message = traffic_stats::format_telegram_message_with_options(
        &stats_state,
        now,
        telegram_config.notify_daily,
        telegram_config.notify_monthly,
        stats_config.traffic_mode,
    );
    traffic_stats::send_telegram_with(&telegram_config, &message, send_telegram_http).map_err(
        |e| {
            error!(
                "Telegram test failed token={}: {}",
                traffic_stats::mask_bot_token(&telegram_config.bot_token),
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TelegramTestResponse {
                    success: false,
                    message: format!("Telegram 测试发送失败: {}", e),
                }),
            )
        },
    )?;

    Ok(Json(TelegramTestResponse {
        success: true,
        message: "Telegram 测试消息已发送".to_string(),
    }))
}

fn save_telegram_config_to_path(
    config_path: &str,
    req: &TelegramConfigRequest,
    backup_dir: &str,
) -> Result<TomlConfig, (StatusCode, String)> {
    if req.notify_interval_minutes < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "notify_interval_minutes must be >= 1".to_string(),
        ));
    }

    let content = fs::read_to_string(config_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 TOML 配置失败: {e}"),
        )
    })?;
    let mut config = TomlConfig::from_toml_str(&content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("解析 TOML 配置失败: {e}")))?;

    let new_token = req
        .bot_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty());
    if let Some(token) = new_token {
        config.telegram.bot_token = token.to_string();
    }

    config.telegram.enabled = req.enabled;
    config.telegram.chat_id = req.chat_id.trim().to_string();
    config.telegram.notify_interval_minutes = req.notify_interval_minutes;
    config.telegram.notify_daily = req.notify_daily;
    config.telegram.notify_monthly = req.notify_monthly;

    if config.telegram.enabled
        && (config.telegram.bot_token.is_empty() || config.telegram.chat_id.is_empty())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "enabled=true requires non-empty bot_token and chat_id".to_string(),
        ));
    }

    backup_toml_config(config_path, backup_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("备份 TOML 配置失败: {e}"),
        )
    })?;
    let updated = update_telegram_section(&content, &config.telegram)?;
    let updated = update_stats_section(&updated, &config.stats)?;
    fs::write(config_path, updated).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存 Telegram 配置失败: {e}"),
        )
    })?;
    info!(
        "Telegram config saved: enabled={} token={} chat_id_present={} interval={}min",
        config.telegram.enabled,
        traffic_stats::mask_bot_token(&config.telegram.bot_token),
        !config.telegram.chat_id.is_empty(),
        config.telegram.notify_interval_minutes
    );
    Ok(config)
}

fn update_telegram_section(
    content: &str,
    telegram: &TelegramConfig,
) -> Result<String, (StatusCode, String)> {
    let mut root: toml::Table = toml::from_str(content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("解析 TOML 配置失败: {e}")))?;
    let mut telegram_table = toml::Table::new();
    telegram_table.insert(
        "enabled".to_string(),
        toml::Value::Boolean(telegram.enabled),
    );
    telegram_table.insert(
        "bot_token".to_string(),
        toml::Value::String(telegram.bot_token.clone()),
    );
    telegram_table.insert(
        "chat_id".to_string(),
        toml::Value::String(telegram.chat_id.clone()),
    );
    telegram_table.insert(
        "notify_interval_minutes".to_string(),
        toml::Value::Integer(telegram.notify_interval_minutes as i64),
    );
    telegram_table.insert(
        "notify_daily".to_string(),
        toml::Value::Boolean(telegram.notify_daily),
    );
    telegram_table.insert(
        "notify_monthly".to_string(),
        toml::Value::Boolean(telegram.notify_monthly),
    );
    root.insert("telegram".to_string(), toml::Value::Table(telegram_table));
    toml::to_string_pretty(&root).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("序列化 TOML 配置失败: {e}"),
        )
    })
}

fn save_stats_config_to_path(
    config_path: &str,
    req: &StatsConfigRequest,
    backup_dir: &str,
) -> Result<TomlConfig, (StatusCode, String)> {
    let content = fs::read_to_string(config_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 TOML 配置失败: {e}"),
        )
    })?;
    let mut config = TomlConfig::from_toml_str(&content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("解析 TOML 配置失败: {e}")))?;
    config.stats.traffic_mode = req.traffic_mode;

    backup_toml_config(config_path, backup_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("备份 TOML 配置失败: {e}"),
        )
    })?;
    let updated = update_stats_section(&content, &config.stats)?;
    fs::write(config_path, updated).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("保存 Stats 配置失败: {e}"),
        )
    })?;
    Ok(config)
}

fn update_stats_section(
    content: &str,
    stats: &StatsConfig,
) -> Result<String, (StatusCode, String)> {
    let mut root: toml::Table = toml::from_str(content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("解析 TOML 配置失败: {e}")))?;
    let mut stats_table = root
        .remove("stats")
        .and_then(|value| value.as_table().cloned())
        .unwrap_or_default();
    stats_table.insert("enabled".to_string(), toml::Value::Boolean(stats.enabled));
    stats_table.insert(
        "collect_interval_seconds".to_string(),
        toml::Value::Integer(stats.collect_interval_seconds as i64),
    );
    stats_table.insert(
        "data_file".to_string(),
        toml::Value::String(stats.data_file.clone()),
    );
    stats_table.insert(
        "traffic_mode".to_string(),
        toml::Value::String(stats.traffic_mode.to_string()),
    );
    root.insert("stats".to_string(), toml::Value::Table(stats_table));
    toml::to_string_pretty(&root).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("序列化 TOML 配置失败: {e}"),
        )
    })
}

fn backup_toml_config(config_path: &str, backup_dir: &str) -> io::Result<PathBuf> {
    let source = Path::new(config_path);
    fs::create_dir_all(backup_dir)?;
    let backup_path = Path::new(backup_dir).join(format!(
        "nat-config-{}.toml",
        Local::now().format("%Y%m%d-%H%M%S")
    ));
    fs::copy(source, &backup_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(backup_path)
}

fn telegram_config_error(
    status: StatusCode,
    message: &str,
) -> (StatusCode, Json<TelegramConfigResponse>) {
    (
        status,
        Json(TelegramConfigResponse {
            success: false,
            message: message.to_string(),
            status: telegram_status_response(&TelegramConfig::default()),
        }),
    )
}

fn telegram_test_error(
    status: StatusCode,
    message: &str,
) -> (StatusCode, Json<TelegramTestResponse>) {
    (
        status,
        Json(TelegramTestResponse {
            success: false,
            message: message.to_string(),
        }),
    )
}

fn load_observability_config(
    state: &AppState,
) -> Result<(StatsConfig, TelegramConfig), (StatusCode, String)> {
    let config_info = match get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    ) {
        Ok(config_info) => config_info,
        Err(e) => {
            info!("Failed to detect NAT config for observability: {:?}", e);
            return Ok((StatsConfig::default(), TelegramConfig::default()));
        }
    };
    if !config_info.is_toml {
        return Ok((StatsConfig::default(), TelegramConfig::default()));
    }

    let content = fs::read_to_string(&config_info.config_path).map_err(|e| {
        error!("Failed to read TOML config for observability: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 TOML 配置失败: {}", e),
        )
    })?;
    let config = TomlConfig::from_toml_str(&content).map_err(|e| {
        error!("Failed to parse TOML config for observability: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("解析 TOML 配置失败: {}", e),
        )
    })?;
    Ok((config.stats, config.telegram))
}

fn load_toml_config_or_default(state: &AppState) -> Result<TomlConfig, (StatusCode, String)> {
    let config_info = match get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    ) {
        Ok(config_info) => config_info,
        Err(e) => {
            info!("Failed to detect NAT config: {:?}", e);
            return Ok(TomlConfig::default());
        }
    };
    if !config_info.is_toml {
        return Ok(TomlConfig::default());
    }
    let content = fs::read_to_string(&config_info.config_path).map_err(|e| {
        error!("Failed to read TOML config: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 TOML 配置失败: {}", e),
        )
    })?;
    TomlConfig::from_toml_str(&content).map_err(|e| {
        error!("Failed to parse TOML config: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("解析 TOML 配置失败: {}", e),
        )
    })
}

fn collect_stats_from_json_now(
    stats_config: &StatsConfig,
    labels: &std::collections::HashMap<String, String>,
    json: &str,
    now: chrono::NaiveDateTime,
) -> Result<traffic_stats::StatsState, (StatusCode, String)> {
    traffic_stats::collect_from_nft_json_with_config(
        &stats_config.data_file,
        json,
        labels,
        now,
        stats_config,
    )
    .map_err(|e| {
        error!("Failed to collect stats now: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("采集 nft counter 失败: {}", e),
        )
    })
}

fn load_access_control_config(
    state: &AppState,
) -> Result<AccessControlConfig, (StatusCode, String)> {
    let config_info = match get_config_info(
        state.toml_config.as_deref(),
        state.compatible_config.as_deref(),
    ) {
        Ok(config_info) => config_info,
        Err(e) => {
            info!("Failed to detect NAT config for access control: {:?}", e);
            return Ok(AccessControlConfig::default());
        }
    };
    if !config_info.is_toml {
        return Ok(AccessControlConfig::default());
    }
    let content = fs::read_to_string(&config_info.config_path).map_err(|e| {
        error!("Failed to read TOML config for access control: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取 TOML 配置失败: {}", e),
        )
    })?;
    let config = TomlConfig::from_toml_str(&content).map_err(|e| {
        error!("Failed to parse TOML config for access control: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("解析 TOML 配置失败: {}", e),
        )
    })?;
    Ok(config.access_control)
}

fn telegram_status_response(config: &TelegramConfig) -> TelegramStatusResponse {
    TelegramStatusResponse {
        enabled: config.enabled,
        bot_token_masked: traffic_stats::mask_bot_token(&config.bot_token),
        chat_id: config.chat_id.clone(),
        notify_interval_minutes: config.notify_interval_minutes,
        notify_daily: config.notify_daily,
        notify_monthly: config.notify_monthly,
    }
}

fn send_telegram_http(url: &str, params: &[(&str, &str)]) -> Result<(), String> {
    let mut command = Command::new("curl");
    command.arg("-sS").arg("-X").arg("POST").arg(url);
    for (key, value) in params {
        command
            .arg("--data-urlencode")
            .arg(format!("{key}={value}"));
    }
    let output = command
        .output()
        .map_err(|e| format!("执行 curl 失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[derive(Default)]
struct UninstallExecResult {
    actions: Vec<String>,
    kept: Vec<String>,
    warnings: Vec<String>,
}

fn execute_uninstall(target: UninstallTarget, data_mode: DataMode) -> UninstallExecResult {
    let plan = uninstall::plan_uninstall(target, data_mode);
    let mut result = UninstallExecResult {
        kept: plan.kept,
        ..Default::default()
    };
    if matches!(target, UninstallTarget::Core | UninstallTarget::All) {
        stop_disable_remove_service("nat", &uninstall::CORE_SERVICE_PATHS, &mut result);
        remove_path(uninstall::NAT_BINARY, &mut result);
    }
    if matches!(
        target,
        UninstallTarget::Core | UninstallTarget::All | UninstallTarget::NftTables
    ) {
        cleanup_project_nft_tables(&mut result);
    }
    if matches!(target, UninstallTarget::Console | UninstallTarget::All) {
        stop_disable_remove_service(
            "nat-console",
            &uninstall::CONSOLE_SERVICE_PATHS,
            &mut result,
        );
        remove_path(uninstall::NAT_CONSOLE_BINARY, &mut result);
    }
    cleanup_uninstall_data(data_mode, &mut result);
    let _ = Command::new("systemctl").arg("daemon-reload").output();
    result.actions.push("systemd daemon-reload".to_string());
    result
}

fn stop_disable_remove_service(
    service: &str,
    service_paths: &[&str],
    result: &mut UninstallExecResult,
) {
    run_best_effort(
        Command::new("systemctl").arg("stop").arg(service),
        result,
        &format!("stopped {service}.service"),
    );
    run_best_effort(
        Command::new("systemctl").arg("disable").arg(service),
        result,
        &format!("disabled {service}.service"),
    );
    for path in service_paths {
        remove_path(path, result);
    }
}

fn cleanup_project_nft_tables(result: &mut UninstallExecResult) {
    for (family, table) in uninstall::nft_table_names() {
        let output = Command::new("/usr/sbin/nft")
            .arg("delete")
            .arg("table")
            .arg(family)
            .arg(table)
            .output()
            .or_else(|_| {
                Command::new("nft")
                    .arg("delete")
                    .arg("table")
                    .arg(family)
                    .arg(table)
                    .output()
            });
        match output {
            Ok(_) => result
                .actions
                .push(format!("cleaned nft table {family} {table} if present")),
            Err(e) => result
                .warnings
                .push(format!("failed to delete nft table {family} {table}: {e}")),
        }
    }
}

fn cleanup_uninstall_data(data_mode: DataMode, result: &mut UninstallExecResult) {
    match data_mode {
        DataMode::Keep => {}
        DataMode::KeepConfig => {
            for path in [
                uninstall::CONFIG_LEGACY,
                uninstall::STATS_JSON,
                uninstall::CONSOLE_ENV,
                uninstall::CONSOLE_CERT,
                uninstall::CONSOLE_KEY,
            ] {
                remove_path(path, result);
            }
        }
        DataMode::Purge => {
            for path in [
                uninstall::CONFIG_TOML,
                uninstall::CONFIG_LEGACY,
                uninstall::STATS_DIR,
                uninstall::BACKUPS_ROOT,
                uninstall::CONSOLE_DIR,
                uninstall::CONSOLE_CERT,
                uninstall::CONSOLE_KEY,
            ] {
                remove_path(path, result);
            }
        }
    }
}

fn run_best_effort(command: &mut Command, result: &mut UninstallExecResult, action: &str) {
    match command.output() {
        Ok(_) => result.actions.push(action.to_string()),
        Err(e) => result.warnings.push(format!("{action} failed: {e}")),
    }
}

fn remove_path(path: &str, result: &mut UninstallExecResult) {
    let path_ref = Path::new(path);
    if !path_ref.exists() {
        return;
    }
    let remove_result = if path_ref.is_dir() {
        fs::remove_dir_all(path_ref)
    } else {
        fs::remove_file(path_ref)
    };
    match remove_result {
        Ok(()) => result.actions.push(format!("removed {path}")),
        Err(e) => result
            .warnings
            .push(format!("failed to remove {path}: {e}")),
    }
}

fn service_status(service: &str) -> String {
    if !service_file_exists(service) {
        return "missing".to_string();
    }
    match Command::new("systemctl")
        .arg("is-active")
        .arg(service)
        .output()
    {
        Ok(output) if output.status.success() => "active".to_string(),
        Ok(_) => "inactive".to_string(),
        Err(_) => "inactive".to_string(),
    }
}

fn service_file_exists(service: &str) -> bool {
    let filename = format!("{service}.service");
    ["/lib/systemd/system", "/etc/systemd/system"]
        .iter()
        .any(|dir| Path::new(dir).join(&filename).exists())
}

fn nft_table_exists(family: &str, table: &str) -> bool {
    Command::new("/usr/sbin/nft")
        .arg("list")
        .arg("table")
        .arg(family)
        .arg(table)
        .output()
        .or_else(|_| {
            Command::new("nft")
                .arg("list")
                .arg("table")
                .arg(family)
                .arg(table)
                .output()
        })
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn read_sysctl_value(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn run_sysctl_command(args: &[&str]) -> Result<(), (StatusCode, String)> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(args)
        .output()
        .or_else(|_| Command::new("sysctl").args(args).output())
        .map_err(|e| {
            error!("Failed to run sysctl {:?}: {:?}", args, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("应用 sysctl 配置失败: {}", e),
            )
        })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        error!("sysctl {:?} failed: {}", args, stderr);
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("应用 sysctl 配置失败: {}", stderr),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use nat_common::{AccessControlMode, NftCell, TrafficMode};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nat-console-telegram-{name}-{}-{}",
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed),
            Local::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn write_config(path: &Path) {
        let content = r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
comment = "keep-rule"

[stats]
enabled = true
collect_interval_seconds = 30
data_file = "/tmp/stats.json"
traffic_mode = "both"

[ddns]
refresh_interval_seconds = 300

[dns]
reject_fake_ip = false
fake_ip_cidrs = ["198.18.0.0/15"]
resolver_mode = "system"
nameservers = ["1.1.1.1:53"]
fallback_to_system = true

[access_control]
mode = "blacklist"
entries = ["8.8.8.8"]

[telegram]
enabled = false
bot_token = "123456789:oldtokenabcd"
chat_id = "old-chat"
notify_interval_minutes = 60
notify_daily = true
notify_monthly = true
"#;
        fs::write(path, content).unwrap();
    }

    fn request(
        enabled: bool,
        bot_token: Option<&str>,
        chat_id: &str,
        interval: u64,
    ) -> TelegramConfigRequest {
        TelegramConfigRequest {
            enabled,
            bot_token: bot_token.map(str::to_string),
            chat_id: chat_id.to_string(),
            notify_interval_minutes: interval,
            notify_daily: true,
            notify_monthly: false,
        }
    }

    fn section_count(content: &str, section: &str) -> usize {
        content
            .lines()
            .filter(|line| line.trim() == section)
            .count()
    }

    #[test]
    fn telegram_status_does_not_return_plain_token() {
        let config = TelegramConfig {
            bot_token: "123456789:secretabcd".to_string(),
            ..Default::default()
        };
        let status = telegram_status_response(&config);
        assert_eq!(status.bot_token_masked, "1234****abcd");
        assert!(!status.bot_token_masked.contains("secret"));
    }

    #[test]
    fn saves_telegram_config_and_enables_it() {
        let dir = temp_dir("enable");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        let config = save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("987654321:newtokenabcd"), "123456789", 15),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();

        assert!(config.telegram.enabled);
        assert_eq!(config.telegram.bot_token, "987654321:newtokenabcd");
        assert_eq!(config.telegram.chat_id, "123456789");
        assert_eq!(config.telegram.notify_interval_minutes, 15);
        assert!(!config.telegram.notify_monthly);
        assert_eq!(fs::read_dir(&backup_dir).unwrap().count(), 1);
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("[telegram]"));
        assert!(saved.contains("bot_token = \"987654321:newtokenabcd\""));
        assert!(saved.contains("chat_id = \"123456789\""));
        assert_eq!(section_count(&saved, "[telegram]"), 1);
    }

    #[test]
    fn empty_bot_token_preserves_existing_token() {
        let dir = temp_dir("preserve-token");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        let config = save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some(""), "new-chat", 60),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(config.telegram.bot_token, "123456789:oldtokenabcd");
        assert_eq!(config.telegram.chat_id, "new-chat");
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("bot_token = \"123456789:oldtokenabcd\""));
        assert!(!saved.contains("1234****abcd"));
    }

    #[test]
    fn new_bot_token_overwrites_old_token_without_masking() {
        let dir = temp_dir("overwrite-token");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("222222222:newrealabcd"), "chat", 60),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(saved.contains("bot_token = \"222222222:newrealabcd\""));
        assert!(!saved.contains("123456789:oldtokenabcd"));
        assert!(!saved.contains("2222****abcd"));
    }

    #[test]
    fn enabled_requires_final_token_and_chat_id() {
        let dir = temp_dir("missing-required");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        fs::write(
            &path,
            r#"
[telegram]
enabled = false
bot_token = ""
chat_id = ""
"#,
        )
        .unwrap();

        let err = save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, None, "", 60),
            backup_dir.to_str().unwrap(),
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("enabled=true"));
    }

    #[test]
    fn rejects_interval_less_than_one() {
        let dir = temp_dir("bad-interval");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        let err = save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(false, None, "chat", 0),
            backup_dir.to_str().unwrap(),
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("notify_interval_minutes"));
    }

    #[test]
    fn saving_telegram_preserves_other_config_sections() {
        let dir = temp_dir("preserve-sections");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("987654321:newtokenabcd"), "chat", 30),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        let config = TomlConfig::from_toml_str(&saved).unwrap();

        assert_eq!(config.rules.len(), 1);
        assert!(matches!(config.rules[0], NftCell::Single { .. }));
        assert!(config.stats.enabled);
        assert_eq!(config.stats.collect_interval_seconds, 30);
        assert_eq!(config.ddns.refresh_interval_seconds, 300);
        assert!(!config.dns.reject_fake_ip);
        assert_eq!(config.access_control.mode, AccessControlMode::Blacklist);
        assert_eq!(config.access_control.entries, vec!["8.8.8.8"]);
    }

    #[test]
    fn saving_stats_config_updates_traffic_mode_and_preserves_sections() {
        let dir = temp_dir("stats-mode");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        let config = save_stats_config_to_path(
            path.to_str().unwrap(),
            &StatsConfigRequest {
                traffic_mode: TrafficMode::Out,
            },
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert_eq!(config.stats.traffic_mode, TrafficMode::Out);
        assert!(saved.contains("traffic_mode = \"out\""));
        assert_eq!(section_count(&saved, "[stats]"), 1);
        assert_eq!(section_count(&saved, "[telegram]"), 1);
        assert_eq!(TomlConfig::from_toml_str(&saved).unwrap().rules.len(), 1);
        assert!(backup_dir.exists());
    }

    #[test]
    fn saving_telegram_backfills_default_stats_traffic_mode() {
        let dir = temp_dir("telegram-backfill-stats-mode");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        fs::write(
            &path,
            r#"
rules = []

[stats]
enabled = true
collect_interval_seconds = 60
data_file = "/tmp/stats.json"

[telegram]
enabled = false
bot_token = ""
chat_id = ""
"#,
        )
        .unwrap();

        save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(false, None, "", 60),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(saved.contains("traffic_mode = \"both\""));
        assert_eq!(section_count(&saved, "[stats]"), 1);
        assert_eq!(section_count(&saved, "[telegram]"), 1);
    }

    #[test]
    fn saving_telegram_preserves_unknown_future_sections() {
        let dir = temp_dir("preserve-unknown");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);
        fs::write(
            &path,
            format!(
                "{}\n[future]\nname = \"keep-me\"\ncount = 7\n",
                fs::read_to_string(&path).unwrap()
            ),
        )
        .unwrap();

        save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("987654321:newtokenabcd"), "chat", 30),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(saved.contains("[future]"));
        assert!(saved.contains("name = \"keep-me\""));
        assert!(saved.contains("count = 7"));
        assert_eq!(section_count(&saved, "[telegram]"), 1);
    }

    #[test]
    fn appending_telegram_when_missing_creates_one_section() {
        let dir = temp_dir("append-telegram");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        fs::write(
            &path,
            r#"
rules = []

[stats]
enabled = true
"#,
        )
        .unwrap();

        let config = save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("987654321:newtokenabcd"), "chat", 30),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let saved = fs::read_to_string(&path).unwrap();

        assert!(config.telegram.enabled);
        assert_eq!(section_count(&saved, "[telegram]"), 1);
        assert!(saved.contains("bot_token = \"987654321:newtokenabcd\""));
    }

    #[test]
    fn config_loader_reads_latest_saved_telegram() {
        let dir = temp_dir("latest-config");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nat.toml");
        let backup_dir = dir.join("backups");
        write_config(&path);

        save_telegram_config_to_path(
            path.to_str().unwrap(),
            &request(true, Some("987654321:newtokenabcd"), "latest-chat", 45),
            backup_dir.to_str().unwrap(),
        )
        .unwrap();
        let config_format = crate::config::ConfigFormat::from_toml_file(path.to_str().unwrap())
            .unwrap()
            .to_string();

        assert!(config_format.contains("[telegram]"));
        assert!(config_format.contains("bot_token = \"987654321:newtokenabcd\""));
        assert!(config_format.contains("chat_id = \"latest-chat\""));
    }

    #[test]
    fn telegram_test_unconfigured_error_is_clear() {
        let err = telegram_test_error(
            StatusCode::BAD_REQUEST,
            "Telegram 未启用，或 bot_token/chat_id 为空",
        );
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(!err.1.0.success);
        assert!(err.1.0.message.contains("bot_token/chat_id"));
    }

    #[test]
    fn telegram_config_response_masks_token() {
        let config = TelegramConfig {
            enabled: true,
            bot_token: "123456789:secretabcd".to_string(),
            chat_id: "chat".to_string(),
            notify_interval_minutes: 5,
            notify_daily: true,
            notify_monthly: false,
        };
        let response = TelegramConfigResponse {
            success: true,
            message: "ok".to_string(),
            status: telegram_status_response(&config),
        };
        assert_eq!(response.status.bot_token_masked, "1234****abcd");
    }

    #[test]
    fn collect_now_updates_stats_from_nft_json() {
        let dir = temp_dir("collect-now");
        fs::create_dir_all(&dir).unwrap();
        let stats_path = dir.join("stats.json");
        let stats_config = StatsConfig {
            enabled: true,
            collect_interval_seconds: 10,
            data_file: stats_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let mut state = traffic_stats::StatsState::default();
        state.last_counters.insert(
            "r0:out".to_string(),
            traffic_stats::Counter {
                packets: 1,
                bytes: 288,
            },
        );
        state.last_counters.insert(
            "r0:in".to_string(),
            traffic_stats::Counter {
                packets: 1,
                bytes: 132,
            },
        );
        traffic_stats::save_state(&stats_config.data_file, &state).unwrap();
        let labels = std::collections::HashMap::from([(
            "r0".to_string(),
            "30080 -> example.com:80/tcp".to_string(),
        )]);
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
  "expr":[{"counter":{"packets":10,"bytes":823}},{"comment":"nat-traffic:id=r0,dir=out"}]}},
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":11,
  "expr":[{"counter":{"packets":20,"bytes":476}},{"comment":"nat-traffic:id=r0,dir=in"}]}}
]}"#;
        let now = chrono::NaiveDateTime::parse_from_str("2026-05-18 12:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap();

        let state = collect_stats_from_json_now(&stats_config, &labels, json, now).unwrap();

        assert_eq!(state.daily_total_bytes, 879);
        assert_eq!(state.monthly_total_bytes, 879);
        assert_eq!(
            state.last_counters.get("r0:out").map(|c| c.bytes),
            Some(823)
        );
        assert_eq!(state.last_counters.get("r0:in").map(|c| c.bytes), Some(476));
    }

    #[test]
    fn collect_now_initializes_missing_stats_file_as_baseline() {
        let dir = temp_dir("collect-now-baseline");
        fs::create_dir_all(&dir).unwrap();
        let stats_path = dir.join("stats.json");
        let stats_config = StatsConfig {
            enabled: true,
            collect_interval_seconds: 10,
            data_file: stats_path.to_string_lossy().to_string(),
            ..Default::default()
        };
        let labels = std::collections::HashMap::new();
        let json = r#"{"nftables":[
  {"rule":{"family":"ip","table":"self-filter","chain":"FORWARD","handle":10,
  "expr":[{"counter":{"packets":10,"bytes":823}},{"comment":"nat-traffic:id=r0,dir=out"}]}}
]}"#;
        let now = chrono::NaiveDateTime::parse_from_str("2026-05-18 12:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap();

        let state = collect_stats_from_json_now(&stats_config, &labels, json, now).unwrap();

        assert_eq!(state.daily_total_bytes, 0);
        assert_eq!(
            state.last_counters.get("r0:out").map(|c| c.bytes),
            Some(823)
        );
        assert!(stats_path.exists());
    }
}

/// 自定义认证中间件：支持 Authorization header (Bearer token) 和 Cookie 两种方式
pub async fn hybrid_auth_middleware(
    State(jwt_config): State<Arc<JwtConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. 优先检查 Authorization header
    if let Some(auth_header) = request.headers().get(axum::http::header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        // 验证 token
        match Claims::<ClaimsPayload>::decode(token, &jwt_config) {
            Ok(claims) => {
                // 将 Claims 存入 request extensions，供后续 handler 使用
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
            Err(e) => {
                error!("Invalid Bearer token: {:?}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // 2. Fallback: 检查 Cookie
    let jar = CookieJar::from_headers(request.headers());
    if let Some(cookie) = jar.get("token") {
        let token = cookie.value();
        match Claims::<ClaimsPayload>::decode(token, &jwt_config) {
            Ok(claims) => {
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
            Err(e) => {
                error!("Invalid cookie token: {:?}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // 3. 没有找到有效的认证信息
    Err(StatusCode::UNAUTHORIZED)
}
