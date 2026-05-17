use clap::Parser;
use log::{error, info};
use std::env;
mod config;
mod handlers;
mod server;

type DynError = Box<dyn std::error::Error + Send + Sync>;

/// WebUI for nftables NAT management
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 监听端口
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// 用户名
    #[arg(short, long, default_value = "admin")]
    username: String,

    /// 密码
    #[arg(long, default_value = "")]
    password: String,

    /// JWT 密钥
    #[arg(long, default_value = "")]
    jwt_secret: String,

    /// TLS 证书路径
    #[arg(long)]
    cert: Option<String>,

    /// TLS 私钥路径
    #[arg(long)]
    key: Option<String>,

    /// 传统配置文件路径（兼容模式）
    #[arg(long)]
    compatible_config: Option<String>,

    /// TOML 配置文件路径
    #[arg(long)]
    toml_config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    nat_common::logger::init(env!("CARGO_CRATE_NAME"));
    let mut args = Args::parse();

    if let Ok(username) = env::var("NAT_CONSOLE_USERNAME")
        && args.username == "admin"
    {
        args.username = username;
    }
    if args.password.is_empty() {
        args.password = env::var("NAT_CONSOLE_PASSWORD").unwrap_or_default();
    }
    if args.jwt_secret.is_empty() {
        args.jwt_secret = env::var("NAT_CONSOLE_JWT_SECRET").unwrap_or_default();
    }
    if args.password.is_empty() {
        error!("NAT_CONSOLE_PASSWORD or --password is required");
        return Err("NAT_CONSOLE_PASSWORD or --password is required".into());
    }
    if args.jwt_secret.is_empty() {
        error!("NAT_CONSOLE_JWT_SECRET or --jwt-secret is required");
        return Err("NAT_CONSOLE_JWT_SECRET or --jwt-secret is required".into());
    }

    info!("Starting WebUI server on port {}", args.port);
    info!("Username: {}", args.username);

    server::run_server(args).await?;

    Ok(())
}
