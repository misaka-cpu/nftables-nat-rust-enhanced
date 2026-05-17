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
    AccessControlConfig, StatsConfig, TelegramConfig, TomlConfig, stats as traffic_stats,
    validate_legacy_config,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use std::sync::Arc;

const TCP_CONGESTION_CONTROL: &str = "/proc/sys/net/ipv4/tcp_congestion_control";
const TCP_AVAILABLE_CONGESTION_CONTROL: &str =
    "/proc/sys/net/ipv4/tcp_available_congestion_control";
const DEFAULT_QDISC: &str = "/proc/sys/net/core/default_qdisc";
const BBR_SYSCTL_CONF: &str = "/etc/sysctl.d/99-nat-bbr.conf";

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
            TomlConfig::from_toml_str(&req.content).map_err(|e| {
                error!("Invalid TOML config: {:?}", e);
                (StatusCode::BAD_REQUEST, format!("配置验证失败: {}", e))
            })?;
            ConfigFormat::Toml(req.content)
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

#[derive(Serialize)]
pub struct AccessControlStatusResponse {
    mode: String,
    entries: Vec<String>,
    scope: String,
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

pub async fn test_telegram(
    _user: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TelegramTestResponse>, (StatusCode, String)> {
    let (stats_config, telegram_config) = load_observability_config(&state)?;
    if !telegram_config.enabled
        || telegram_config.bot_token.is_empty()
        || telegram_config.chat_id.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Telegram 未启用，或 bot_token/chat_id 为空".to_string(),
        ));
    }

    let stats_state = traffic_stats::load_state(&stats_config.data_file);
    let now = Local::now().naive_local();
    let message = traffic_stats::format_telegram_message_with_options(
        &stats_state,
        now,
        telegram_config.notify_daily,
        telegram_config.notify_monthly,
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
                format!("Telegram 测试发送失败: {}", e),
            )
        },
    )?;

    Ok(Json(TelegramTestResponse {
        success: true,
        message: "Telegram 测试消息已发送".to_string(),
    }))
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
