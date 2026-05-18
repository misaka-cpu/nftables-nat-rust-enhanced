use crate::Args;
use crate::handlers::{
    AppState, check_forward_test, collect_stats_now, enable_bbr, get_access_control_status,
    get_bbr_status, get_config, get_current_user, get_forward_test_rules, get_rules,
    get_rules_json, get_stats, get_telegram_status, hybrid_auth_middleware, login_handler,
    logout_handler, observe_forward_test, reset_stats_daily, reset_stats_monthly, save_config,
    save_stats_config, save_telegram_config, test_telegram,
};
use axum::{
    Router,
    http::{Method, StatusCode, header},
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use axum_bootstrap::jwt::JwtConfig;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use log::{info, warn};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::services::ServeDir;

// 嵌入 HTML 文件
const INDEX_HTML: &str = include_str!("../../static/index.html");
const LOGIN_HTML: &str = include_str!("../../static/login.html");
const EMFILE_BACKOFF: Duration = Duration::from_secs(1);

// 路由处理器
async fn serve_index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn serve_login() -> impl IntoResponse {
    Html(LOGIN_HTML)
}

pub async fn run_server(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log_open_files_limit();

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
        .route("/api/stats/config", post(save_stats_config))
        .route("/api/stats/collect-now", post(collect_stats_now))
        .route("/api/stats/reset-daily", post(reset_stats_daily))
        .route("/api/stats/reset-monthly", post(reset_stats_monthly))
        .route("/api/telegram/status", get(get_telegram_status))
        .route("/api/telegram/config", post(save_telegram_config))
        .route("/api/telegram/test", post(test_telegram))
        .route("/api/access-control/status", get(get_access_control_status))
        .route("/api/forward-test/rules", get(get_forward_test_rules))
        .route("/api/forward-test/check", post(check_forward_test))
        .route("/api/forward-test/observe", post(observe_forward_test))
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
                Duration::from_secs(70),
            ),
            tower_http::compression::CompressionLayer::new()
                .gzip(true)
                .br(true)
                .deflate(true)
                .zstd(true),
        ))
        .with_state(state);

    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;

    if let (Some(cert), Some(key)) = (args.cert, args.key) {
        info!("Starting HTTPS server on {bind_addr}");
        serve_tls(bind_addr, app, cert, key).await?;
    } else {
        info!("Starting HTTP server on {bind_addr}");
        info!("Warning: Running without TLS! This is not secure for production.");
        serve_plain(bind_addr, app).await?;
    }

    Ok(())
}

fn log_open_files_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if rc == 0 {
        info!(
            "max open files: soft={} hard={}",
            limit.rlim_cur, limit.rlim_max
        );
    } else {
        warn!(
            "failed to read max open files limit: {}",
            io::Error::last_os_error()
        );
    }
}

fn load_tls_config(key: &str, cert: &str) -> Result<Arc<ServerConfig>, io::Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|_| io::Error::other("open cert failed"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("invalid cert pem"))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|_| io::Error::other("failed to read private key"))?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn serve_tls(
    bind_addr: SocketAddr,
    app: Router,
    cert: String,
    key: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind_addr).await?;
    let tls_acceptor = TlsAcceptor::from(load_tls_config(&key, &cert)?);
    let mut emfile_warned = false;
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => {
                emfile_warned = false;
                conn
            }
            Err(e) if is_too_many_open_files(&e) => {
                warn_too_many_open_files_once(&mut emfile_warned, &e);
                sleep(EMFILE_BACKOFF).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let tls_acceptor = tls_acceptor.clone();
        let mut make_service = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::warn!("TLS accept error from {remote_addr}: {e}");
                    return;
                }
            };
            let service = match make_service.call(remote_addr).await {
                Ok(service) => service,
                Err(e) => {
                    log::warn!("build service error from {remote_addr}: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(service);
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                log::warn!("HTTPS connection error from {remote_addr}: {e}");
            }
        });
    }
}

async fn serve_plain(
    bind_addr: SocketAddr,
    app: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind_addr).await?;
    let mut emfile_warned = false;
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => {
                emfile_warned = false;
                conn
            }
            Err(e) if is_too_many_open_files(&e) => {
                warn_too_many_open_files_once(&mut emfile_warned, &e);
                sleep(EMFILE_BACKOFF).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let mut make_service = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();

        tokio::spawn(async move {
            let service = match make_service.call(remote_addr).await {
                Ok(service) => service,
                Err(e) => {
                    warn!("build service error from {remote_addr}: {e}");
                    return;
                }
            };
            let io = TokioIo::new(stream);
            let service = TowerToHyperService::new(service);
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                warn!("HTTP connection error from {remote_addr}: {e}");
            }
        });
    }
}

fn is_too_many_open_files(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMFILE)
        || error.raw_os_error() == Some(libc::ENFILE)
        || error.to_string().contains("Too many open files")
}

fn warn_too_many_open_files_once(warned: &mut bool, error: &io::Error) {
    if !*warned {
        warn!("accept failed: too many open files: {error}; backing off 1s");
        *warned = true;
    }
}
