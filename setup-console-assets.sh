#!/bin/bash
set -euo pipefail

APT_UPDATED=0
MISSING_PACKAGES=()
OS_ID=""
OS_VERSION_ID=""
OS_PRETTY_NAME=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

check_binary_glibc_compat() {
    local binary="$1"
    local name="$2"
    local err_file
    err_file="$(mktemp)"
    if "$binary" --help >/dev/null 2>"$err_file"; then
        rm -f "$err_file"
        return 0
    fi
    if grep -E "GLIBC_[0-9.]+.*not found|version .*GLIBC_[0-9.]+.*not found" "$err_file" >/dev/null 2>&1; then
        log_err "当前 release 二进制与系统 glibc 不兼容: $name"
        log_err "请使用更新后的 GitHub Release，或使用 --build-from-source 在本机编译。"
        log_err "原始错误: $(tr '\n' ' ' < "$err_file")"
        rm -f "$err_file"
        exit 1
    fi
    log_warn "$name binary smoke check failed; continuing because this is not a GLIBC compatibility error"
    sed 's/^/[WARN] /' "$err_file" || true
    rm -f "$err_file"
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

ensure_node_assets_dependencies() {
    if command -v node >/dev/null 2>&1; then
        log_ok "node found"
    elif command -v nodejs >/dev/null 2>&1; then
        log_ok "nodejs found"
    else
        echo "[MISS] nodejs not found, installing..."
        queue_apt_package "nodejs"
    fi

    if command -v npm >/dev/null 2>&1; then
        log_ok "npm found"
    else
        echo "[MISS] npm not found, installing..."
        queue_apt_package "npm"
    fi
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

check_node_versions() {
    local node_cmd=""
    if command -v node >/dev/null 2>&1; then
        node_cmd="node"
    elif command -v nodejs >/dev/null 2>&1; then
        node_cmd="nodejs"
    fi

    if [ -n "$node_cmd" ]; then
        log_ok "$node_cmd version: $("$node_cmd" -v)"
        log_warn "If the Debian/Ubuntu apt nodejs version is too old for future frontend builds, install a newer Node.js manually. This script will not add NodeSource or other third-party apt sources."
    else
        log_err "node/nodejs is still missing after installation"
        exit 1
    fi

    if command -v npm >/dev/null 2>&1; then
        log_ok "npm version: $(npm -v)"
    else
        log_err "npm is still missing after installation"
        exit 1
    fi
}

preflight_dependencies() {
    require_root
    detect_os
    ensure_apt_packages curl ca-certificates systemd
    ensure_commands \
        "curl:curl" \
        "install:coreutils" \
        "sed:sed" \
        "systemctl:systemd"
    if [ -z "${NAT_STATIC_DIR:-}" ]; then
        ensure_node_assets_dependencies
    fi
    install_queued_packages
    if [ -z "${NAT_STATIC_DIR:-}" ]; then
        check_node_versions
    fi
    log_ok "dependency check completed"
}

preflight_dependencies

TMP_FILE="/tmp/nat-console"
INSTALL_PATH="/usr/local/bin/nat-console"
LOCAL_CONSOLE_BIN="${NAT_BINARY_DIR:-}/nat-console"

echo "安装 nat-console 到 $INSTALL_PATH..."
if [ -x "$LOCAL_CONSOLE_BIN" ]; then
    TMP_FILE="$LOCAL_CONSOLE_BIN"
elif [ -x "$SCRIPT_DIR/target/release/nat-console" ]; then
    TMP_FILE="$SCRIPT_DIR/target/release/nat-console"
else
    echo "错误: nat-console binary not found; run install.sh --assets-only --use-release or cargo build --release first"
    exit 1
fi

if ! install -m 755 "$TMP_FILE" "$INSTALL_PATH"; then
    echo "错误: 安装 nat-console 失败"
    exit 1
fi
check_binary_glibc_compat "$INSTALL_PATH" nat-console

echo "nat-console 安装成功"

if [ -n "${NAT_STATIC_DIR:-}" ] && [ -d "$NAT_STATIC_DIR" ]; then
    install -d -m 755 /opt/nat-console/static
    cp -a "$NAT_STATIC_DIR/." /opt/nat-console/static/
    echo "WebUI static assets 已安装到 /opt/nat-console/static"
fi

# 更新现有的 systemd service 文件，移除已废弃的配置文件参数
SERVICE_FILE="/lib/systemd/system/nat-console.service"
if [ -f "$SERVICE_FILE" ]; then
    echo "更新 systemd service 配置..."
    # 移除 --compatible-config 和 --toml-config 参数
    sed -i 's/ --compatible-config [^ ]*//g' "$SERVICE_FILE"
    sed -i 's/ --toml-config [^ ]*//g' "$SERVICE_FILE"
    if grep -q '^LimitNOFILE=' "$SERVICE_FILE"; then
        sed -i 's/^LimitNOFILE=.*/LimitNOFILE=65535/' "$SERVICE_FILE"
    else
        sed -i '/^RestartSec=/a LimitNOFILE=65535' "$SERVICE_FILE"
    fi
    if ! grep -q '^WorkingDirectory=' "$SERVICE_FILE"; then
        sed -i '/^Type=/a WorkingDirectory=/opt/nat-console' "$SERVICE_FILE"
    fi
    systemctl daemon-reload
    echo "systemd service 配置已更新，配置格式将自动从 NAT 服务检测"
fi
