#!/bin/bash
set -euo pipefail

# WebUI 安装和启动脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APT_UPDATED=0
MISSING_PACKAGES=()
OS_ID=""
OS_VERSION_ID=""
OS_PRETTY_NAME=""
NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}"
NAT_SKIP_SERVICE_PROMPT="${NAT_SKIP_SERVICE_PROMPT:-0}"
ENV_DIR="/opt/nat-console"
ENV_FILE="$ENV_DIR/env"

log_info() {
    echo "[INFO] $1"
}

log_ok() {
    echo "[OK] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_err() {
    echo "[ERR] $1"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_err "Please run as root"
        exit 1
    fi
    log_ok "root permission confirmed"
}

detect_os() {
    if [ ! -f /etc/os-release ]; then
        log_err "unsupported system: /etc/os-release not found"
        exit 1
    fi

    . /etc/os-release
    OS_ID="${ID:-}"
    OS_VERSION_ID="${VERSION_ID:-}"
    OS_PRETTY_NAME="${PRETTY_NAME:-unknown}"

    case "$OS_ID:$OS_VERSION_ID" in
        debian:11|debian:12|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04)
            log_ok "supported system detected: $OS_PRETTY_NAME"
            ;;
        *)
            log_err "unsupported system: $OS_PRETTY_NAME. Supported: Debian 11/12, Ubuntu 20.04/22.04/24.04"
            exit 1
            ;;
    esac
}

queue_apt_package() {
    local package="$1"
    local existing
    for existing in "${MISSING_PACKAGES[@]}"; do
        if [ "$existing" = "$package" ]; then
            return 0
        fi
    done
    MISSING_PACKAGES+=("$package")
}

ensure_apt_packages() {
    local package
    for package in "$@"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            log_ok "$package found"
        else
            echo "[MISS] $package not found, installing..."
            queue_apt_package "$package"
        fi
    done
}

ensure_commands() {
    local item command package
    for item in "$@"; do
        command="${item%%:*}"
        package="${item#*:}"
        if command -v "$command" >/dev/null 2>&1; then
            log_ok "$command found"
        else
            echo "[MISS] $command not found, installing..."
            queue_apt_package "$package"
        fi
    done
}

install_queued_packages() {
    if [ "${#MISSING_PACKAGES[@]}" -eq 0 ]; then
        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        log_err "apt-get not found"
        exit 1
    fi

    if [ "$APT_UPDATED" -eq 0 ]; then
        log_info "running apt-get update"
        DEBIAN_FRONTEND=noninteractive apt-get update || {
            log_err "apt-get update failed"
            exit 1
        }
        APT_UPDATED=1
    fi

    local package
    for package in "${MISSING_PACKAGES[@]}"; do
        log_info "installing missing package: $package"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" || {
            log_err "failed to install package: $package"
            exit 1
        }
    done
}

preflight_dependencies() {
    require_root
    detect_os
    ensure_apt_packages curl wget ca-certificates openssl systemd procps
    ensure_commands \
        "curl:curl" \
        "wget:wget" \
        "openssl:openssl" \
        "systemctl:systemd" \
        "sysctl:procps"
    install_queued_packages
    log_ok "dependency check completed"
}

generate_password() {
    # Alphanumeric only to avoid systemd ExecStart parsing issues.
    printf 'A%s7b' "$(openssl rand -hex 10)"
}

generate_jwt_secret() {
    # 32 random bytes encoded as 64 hex chars; not printed.
    openssl rand -hex 32
}

env_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

# 使用说明
usage() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -p, --port PORT          WebUI 端口 (默认: 5533)"
    echo "  -c, --cert CERT_FILE     TLS 证书文件路径"
    echo "  -k, --key KEY_FILE       TLS 私钥文件路径"
    echo "  -h, --help               显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                                    # 使用默认端口和自签发证书"
    echo "  $0 -p 8444                            # 指定端口，使用自签发证书"
    echo "  $0 -p 5533 -c /path/cert.pem -k /path/key.pem  # 使用自定义证书"
    echo ""
    echo "注意:"
    echo "  - 配置格式将自动从现有 NAT 服务配置中检测"
    echo "  - 可通过 NAT_CONSOLE_USERNAME/NAT_CONSOLE_PASSWORD/NAT_CONSOLE_PORT/NAT_CONSOLE_JWT_SECRET/NAT_CONSOLE_BIND 覆盖默认值"
    echo "  - 未指定 NAT_CONSOLE_PASSWORD 时交互选择自定义密码或自动生成随机强密码"
    echo "  - 未指定 NAT_CONSOLE_JWT_SECRET 时自动生成随机 JWT secret"
    echo "  - 如果未提供证书和私钥，将自动生成自签发证书"
    echo "  - 证书和私钥必须同时提供"
    exit 1
}

read_hidden_password() {
    local prompt="$1"
    local password
    read -r -s -p "$prompt" password
    echo >&2
    printf '%s' "$password"
}

prompt_username() {
    local username
    read -r -p "请输入 WebUI 用户名 [admin]: " username
    printf '%s' "${username:-admin}"
}

confirm_short_password() {
    local answer
    log_warn "密码长度少于 12 位，存在安全风险。"
    read -r -p "仍然继续使用该密码? [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

prompt_custom_credentials() {
    USERNAME="$(prompt_username)"
    while true; do
        PASSWORD="$(read_hidden_password "请输入 WebUI 密码: ")"
        PASSWORD_CONFIRM="$(read_hidden_password "请再次输入 WebUI 密码: ")"
        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            log_warn "两次输入的密码不一致，请重新输入"
            continue
        fi
        if [ "${#PASSWORD}" -lt 12 ] && ! confirm_short_password; then
            continue
        fi
        PASSWORD_SOURCE="custom"
        break
    done
}

prompt_generated_credentials() {
    USERNAME="$(prompt_username)"
    PASSWORD="$(generate_password)"
    PASSWORD_SOURCE="generated"
    log_ok "generated random WebUI password"
}

prepare_credentials() {
    USERNAME="${NAT_CONSOLE_USERNAME:-admin}"
    PASSWORD_SOURCE="existing"
    PASSWORD=""

    if [ -n "${NAT_CONSOLE_PASSWORD:-}" ]; then
        USERNAME="${NAT_CONSOLE_USERNAME:-admin}"
        PASSWORD="$NAT_CONSOLE_PASSWORD"
        PASSWORD_SOURCE="environment"
        log_info "using WebUI password from environment variable"
    elif [ -f "$ENV_FILE" ] && [ "$NAT_NONINTERACTIVE" = "1" ]; then
        log_info "non-interactive mode: preserving existing $ENV_FILE"
    elif [ -f "$ENV_FILE" ]; then
        local update_choice
        log_warn "$ENV_FILE already exists"
        read -r -p "是否更新 WebUI 凭据? [y/N]: " update_choice
        if [[ "$update_choice" =~ ^[Yy]$ ]]; then
            choose_credentials_interactively
        else
            log_info "preserving existing WebUI credentials"
        fi
    elif [ "$NAT_NONINTERACTIVE" = "1" ]; then
        PASSWORD="$(generate_password)"
        PASSWORD_SOURCE="generated"
        log_ok "generated random WebUI password"
    else
        choose_credentials_interactively
    fi

    if [ -n "${NAT_CONSOLE_JWT_SECRET:-}" ]; then
        JWT_SECRET="$NAT_CONSOLE_JWT_SECRET"
        JWT_SOURCE="environment"
        log_info "using JWT secret from environment variable"
    elif [ -f "$ENV_FILE" ] && [ "$PASSWORD_SOURCE" = "existing" ]; then
        JWT_SECRET=""
        JWT_SOURCE="existing"
    else
        JWT_SECRET="$(generate_jwt_secret)"
        JWT_SOURCE="generated"
        log_ok "generated random JWT secret"
    fi
}

choose_credentials_interactively() {
    local choice
    while true; do
        echo "请选择 WebUI 密码设置方式："
        echo "1) 自定义用户名和密码"
        echo "2) 自动生成强密码"
        read -r -p "请输入选择 [1/2]: " choice
        case "$choice" in
            1)
                prompt_custom_credentials
                return 0
                ;;
            2)
                prompt_generated_credentials
                return 0
                ;;
            *)
                log_warn "请输入 1 或 2"
                ;;
        esac
    done
}

write_env_file() {
    local should_write=0
    if [ ! -f "$ENV_FILE" ]; then
        should_write=1
    elif [ "$PASSWORD_SOURCE" != "existing" ] || [ -n "${NAT_CONSOLE_PORT:-}" ] || [ -n "${NAT_CONSOLE_USERNAME:-}" ] || [ -n "${NAT_CONSOLE_JWT_SECRET:-}" ]; then
        should_write=1
    fi

    if [ "$should_write" -eq 0 ]; then
        log_info "preserved existing $ENV_FILE"
        return 0
    fi

    local existing_password="" existing_jwt_secret="" existing_username="$USERNAME" existing_port="$PORT"
    if [ -f "$ENV_FILE" ]; then
        existing_password="$(grep -E '^NAT_CONSOLE_PASSWORD=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
        existing_jwt_secret="$(grep -E '^NAT_CONSOLE_JWT_SECRET=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
        existing_username="$(grep -E '^NAT_CONSOLE_USERNAME=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
        existing_port="$(grep -E '^NAT_CONSOLE_PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
    fi

    USERNAME="${USERNAME:-${existing_username:-admin}}"
    PASSWORD="${PASSWORD:-$existing_password}"
    JWT_SECRET="${JWT_SECRET:-$existing_jwt_secret}"
    PORT="${PORT:-${existing_port:-5533}}"

    if [ -z "$PASSWORD" ]; then
        PASSWORD="$(generate_password)"
        PASSWORD_SOURCE="generated"
        log_ok "generated random WebUI password"
    fi
    if [ -z "$JWT_SECRET" ]; then
        JWT_SECRET="$(generate_jwt_secret)"
        JWT_SOURCE="generated"
        log_ok "generated random JWT secret"
    fi

    install -d -m 700 "$ENV_DIR"
    cat > "$ENV_FILE" <<EOF
NAT_CONSOLE_PORT=$(env_quote "$PORT")
NAT_CONSOLE_USERNAME=$(env_quote "$USERNAME")
NAT_CONSOLE_PASSWORD=$(env_quote "$PASSWORD")
NAT_CONSOLE_JWT_SECRET=$(env_quote "$JWT_SECRET")
NAT_CONSOLE_CERT=$(env_quote "$CERT_FILE")
NAT_CONSOLE_KEY=$(env_quote "$KEY_FILE")
EOF
    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log_ok "WebUI credentials written to $ENV_FILE"
}

preflight_dependencies

# 检查 NAT 服务是否已安装
NAT_SERVICE_FILE="/lib/systemd/system/nat.service"
if [ ! -f "$NAT_SERVICE_FILE" ]; then
    echo "错误: 未检测到 NAT 服务"
    echo "请先安装 NAT 服务："
    echo "  TOML 格式: bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup.sh) toml"
    echo "  传统格式: bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup.sh) legacy"
    exit 1
fi

# 从 NAT 服务配置中检测配置格式
echo "检测 NAT 服务配置格式..."
if grep -q "ExecStart.*--toml" "$NAT_SERVICE_FILE"; then
    CONFIG_TYPE="toml"
    echo "检测到 TOML 配置格式"
else
    CONFIG_TYPE="legacy"
    echo "检测到传统配置格式"
fi

echo ""

# 解析命令行参数
PORT="${NAT_CONSOLE_PORT:-5533}"
BIND_ADDR="${NAT_CONSOLE_BIND:-0.0.0.0}"
USER_CERT_FILE=""
USER_KEY_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -c|--cert)
            USER_CERT_FILE="$2"
            shift 2
            ;;
        -k|--key)
            USER_KEY_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "错误: 未知选项 $1"
            usage
            ;;
    esac
done

# 验证证书和私钥参数
if [ -n "$USER_CERT_FILE" ] || [ -n "$USER_KEY_FILE" ]; then
    if [ -z "$USER_CERT_FILE" ] || [ -z "$USER_KEY_FILE" ]; then
        echo "错误: 证书和私钥必须同时提供"
        echo "使用 -c 指定证书，-k 指定私钥"
        exit 1
    fi
    
    if [ ! -f "$USER_CERT_FILE" ]; then
        echo "错误: 证书文件不存在: $USER_CERT_FILE"
        exit 1
    fi
    
    if [ ! -f "$USER_KEY_FILE" ]; then
        echo "错误: 私钥文件不存在: $USER_KEY_FILE"
        exit 1
    fi
fi

# 下载并安装 nat-console，可独立于 WebUI assets 流程，不检查 node/npm
DOWNLOAD_URL="https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/nat-console"
TMP_FILE="/tmp/nat-console"
INSTALL_PATH="/usr/local/bin/nat-console"
LOCAL_CONSOLE_BIN="$SCRIPT_DIR/target/release/nat-console"

if [ -x "$LOCAL_CONSOLE_BIN" ]; then
    log_info "using local build: target/release/nat-console"
    install -m 755 "$LOCAL_CONSOLE_BIN" "$INSTALL_PATH"
else
    log_info "local build not found, downloading release binary"
    curl -sSLf "$DOWNLOAD_URL" -o "$TMP_FILE"
    install -m 755 "$TMP_FILE" "$INSTALL_PATH"
fi
log_ok "nat-console installed to $INSTALL_PATH"

# TLS 证书配置
if [ -n "$USER_CERT_FILE" ] && [ -n "$USER_KEY_FILE" ]; then
    # 用户提供了证书和私钥
    CERT_FILE="$USER_CERT_FILE"
    KEY_FILE="$USER_KEY_FILE"
    echo "使用用户提供的 TLS 证书:"
    echo "  证书: $CERT_FILE"
    echo "  私钥: $KEY_FILE"
else
    # 生成自签发证书
    CERT_FILE="/etc/ssl/nat-webui.crt"
    KEY_FILE="/etc/ssl/nat-webui.key"
    mkdir -p /etc/ssl

    # 如果证书不存在，生成自签名证书（仅用于测试）；不覆盖已有证书/私钥
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        log_warn "使用现有的自签发证书: $CERT_FILE / $KEY_FILE"
    elif [ ! -f "$CERT_FILE" ] && [ ! -f "$KEY_FILE" ]; then
        echo "生成自签名 TLS 证书..."
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 365 \
            -subj "/CN=localhost"
        chmod 600 "$KEY_FILE"
        echo "已生成自签发证书 (仅用于测试环境)"
    else
        log_err "检测到 $CERT_FILE 或 $KEY_FILE 只有一个存在；为避免覆盖用户文件，请手动补齐或指定 -c/-k"
        exit 1
    fi
fi

prepare_credentials
write_env_file

echo ""
echo "配置信息:"
echo "  配置格式: $CONFIG_TYPE"
echo "  WebUI 端口: $PORT"
echo "  WebUI 绑定地址: $BIND_ADDR"
echo "  登录用户名: $USERNAME"
if [ "$BIND_ADDR" = "0.0.0.0" ]; then
    log_warn "WebUI 将对所有网卡监听，请确保防火墙和密码强度足够"
else
    log_info "NAT_CONSOLE_BIND 当前用于安装提示；nat-console 运行时监听行为取决于程序默认绑定"
fi
echo "========================================="
echo ""

# 创建 systemd service 文件
echo "创建 systemd service..."
SERVICE_FILE="/lib/systemd/system/nat-console.service"
tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=NAT Console WebUI Service
After=network.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_PATH --port \${NAT_CONSOLE_PORT} --cert \${NAT_CONSOLE_CERT} --key \${NAT_CONSOLE_KEY}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nat-console
log_ok "nat-console.service enabled"

if [ "$NAT_NONINTERACTIVE" = "1" ] || [ "$NAT_SKIP_SERVICE_PROMPT" = "1" ]; then
    log_info "非交互模式：已 enable nat-console.service，不强制 start/restart"
else
    read -r -p "是否立即启动/重启 nat-console.service? [y/N]: " START_CONSOLE
    if [[ "$START_CONSOLE" =~ ^[Yy]$ ]]; then
        if systemctl is-active --quiet nat-console; then
            systemctl restart nat-console
            log_ok "nat-console.service restarted"
        else
            systemctl start nat-console
            log_ok "nat-console.service started"
        fi
    else
        log_info "已跳过立即启动/重启 nat-console.service"
    fi
fi

echo ""
echo "========================================="
echo "安装成功！systemd service 已创建"
echo "========================================="
echo "配置格式: $CONFIG_TYPE"
echo "服务文件: $SERVICE_FILE"
echo ""
echo "使用以下命令管理服务:"
echo "  启动服务: systemctl start nat-console"
echo "  停止服务: systemctl stop nat-console"
echo "  查看状态: systemctl status nat-console"
echo "  开机自启: systemctl enable nat-console"
echo "  查看日志: journalctl -u nat-console -f"
echo ""
echo "WebUI 配置:"
echo "  访问地址: https://localhost:$PORT"
echo "  用户名: $USERNAME"
case "$PASSWORD_SOURCE" in
    generated)
        echo "  密码: $PASSWORD"
        echo "  提示: 密码仅显示一次，请妥善保存。"
        ;;
    custom)
        echo "  密码: 使用用户自定义密码"
        ;;
    environment)
        echo "  密码: 使用 NAT_CONSOLE_PASSWORD 环境变量"
        ;;
    existing)
        echo "  密码: 保留已有凭据"
        ;;
esac
echo "  凭据文件: $ENV_FILE"
echo "========================================="
