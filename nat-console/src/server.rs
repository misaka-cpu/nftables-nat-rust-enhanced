use crate::Args;
use crate::handlers::{
    AppState, enable_bbr, get_access_control_status, get_bbr_status, get_config, get_current_user,
    get_rules, get_rules_json, get_stats, get_telegram_status, hybrid_auth_middleware,
    login_handler, logout_handler, reset_stats_daily, reset_stats_monthly, save_config,
    test_telegram,
};
use axum::{
    Router,
    http::{Method, StatusCode, header},
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use axum_bootstrap::TlsParam;
use axum_bootstrap::jwt::JwtConfig;
use log::info;
use std::sync::Arc;
use std::time::Duration;
use tower_http::services::ServeDir;

// 嵌入 HTML 文件
const INDEX_HTML: &str = include_str!("../../static/index.html");
const LOGIN_HTML: &str = include_str!("../../static/login.html");

// 路由处理器
async fn serve_index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn serve_login() -> impl IntoResponse {
    Html(LOGIN_HTML)
}

pub async fn run_server(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 生成密码哈希
    let password_hash = bcrypt::hash(&args.password, bcrypt::DEFAULT_COST)?;

    let jwt_config = JwtConfig::new(&args.jwt_secret);

    let state = Arc::new(AppState {
        jwt_config: jwt_config.clone(),
        username: args.username,
        password_hash,
        toml_config: args.toml_config,
        compatible_config: args.compatible_config,
    });

    // 受保护的路由
    let protected_routes = Router::new()
        .route("/api/me", get(get_current_user))
        .route("/api/config", get(get_config).post(save_config))
        .route("/api/rules", get(get_rules_json))
        .route("/api/bbr/status", get(get_bbr_status))
        .route("/api/bbr/enable", post(enable_bbr))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/reset-daily", post(reset_stats_daily))
        .route("/api/stats/reset-monthly", post(reset_stats_monthly))
        .route("/api/telegram/status", get(get_telegram_status))
        .route("/api/telegram/test", post(test_telegram))
        .route("/api/access-control/status", get(get_access_control_status))
        .route("/rules", get(get_rules))
        .layer(middleware::from_fn_with_state(
            Arc::new(jwt_config.clone()),
            hybrid_auth_middleware,
        ));

    // 构建应用
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/login.html", get(serve_login))
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .route("/health", get(|| async { (StatusCode::OK, "OK") }))
        .merge(protected_routes)
        .fallback_service(ServeDir::new("static"))
        .layer((
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::extract::Request| {
                    let method = req.method();
                    let path = req.uri().path();
                    tracing::info_span!("request", %method, %path)
                })
                .on_failure(()),
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .allow_credentials(true),
            tower_http::timeout::TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                Duration::from_secs(30),
            ),
            tower_http::compression::CompressionLayer::new()
                .gzip(true)
                .br(true)
                .deflate(true)
                .zstd(true),
        ))
        .with_state(state);

    // 启动服务器
    let server =
        axum_bootstrap::new_server(args.port, app, axum_bootstrap::generate_shutdown_receiver())
            .with_timeout(Duration::from_secs(600));

    // 如果提供了证书，使用 TLS
    let server = if let (Some(cert), Some(key)) = (args.cert, args.key) {
        info!("Starting HTTPS server on port {}", args.port);
        server.with_tls_param(Some(TlsParam {
            tls: true,
            cert,
            key,
        }))
    } else {
        info!("Starting HTTP server on port {}", args.port);
        info!("⚠️  Warning: Running without TLS! This is not secure for production.");
        server
    };

    server.run().await?;

    Ok(())
}
