#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0

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

log_dry_run() {
    echo "[DRY-RUN] $1"
}

usage() {
    cat <<EOF
用法: $0 [选项]

选项:
  --dry-run        只输出计划执行的动作，不实际安装或修改系统
  --core-only      只安装核心转发服务 nat
  --with-console   安装核心转发服务 nat + WebUI nat-console
  --console-only   只安装 WebUI nat-console
  --assets-only    只安装/更新 WebUI 静态资源 assets
  --uninstall      卸载已安装的服务文件和二进制（不删除用户配置）
  --help           显示此帮助

环境变量:
  NAT_CONFIG_TYPE=toml|legacy   非交互核心安装配置格式，默认 toml

示例:
  $0 --dry-run --core-only
  $0 --core-only
  $0 --with-console
  $0 --console-only
  $0 --assets-only
EOF
}

dry_run_core_install() {
    local config_type="$1"
    log_dry_run "would install core nat"
    log_dry_run "would check core dependencies: curl wget ca-certificates nftables iproute2 iptables procps systemd openssl"
    if [ -x "$SCRIPT_DIR/target/release/nat" ]; then
        log_dry_run "would use local build: target/release/nat"
    else
        log_dry_run "local build not found, would download release binary"
    fi
    log_dry_run "would install /usr/local/bin/nat"
    log_dry_run "would create/update /lib/systemd/system/nat.service with $config_type config"
    log_dry_run "would enable nat.service"
    log_dry_run "would preserve existing /etc/nat.conf if present"
    log_dry_run "would preserve existing /etc/nat.toml if present"
    log_dry_run "would preserve existing /opt/nat/env if present"
    log_dry_run "would ask before starting or restarting nat.service in interactive mode"
}

dry_run_console_install() {
    log_dry_run "would install nat-console WebUI service"
    log_dry_run "would check WebUI service dependencies: curl wget ca-certificates openssl systemd procps"
    if [ -x "$SCRIPT_DIR/target/release/nat-console" ]; then
        log_dry_run "would use local build: target/release/nat-console"
    else
        log_dry_run "local build not found, would download release binary"
    fi
    log_dry_run "would install /usr/local/bin/nat-console"
    log_dry_run "would create/update /lib/systemd/system/nat-console.service"
    log_dry_run "would update nat-console.service to use EnvironmentFile"
    log_dry_run "would not put --password or --jwt-secret in ExecStart"
    log_dry_run "would set nat-console.service LimitNOFILE=65535"
    log_dry_run "would use NAT_CONSOLE_USERNAME or default admin"
    log_dry_run "would use NAT_CONSOLE_PORT or default 5533"
    log_dry_run "would use NAT_CONSOLE_BIND or ask user to choose WebUI bind address"
    log_dry_run "would default to 127.0.0.1 for SSH tunnel access"
    if [ -n "${NAT_CONSOLE_PASSWORD:-}" ]; then
        log_dry_run "would use password from NAT_CONSOLE_PASSWORD"
    else
        log_dry_run "would ask user to choose custom password or generated password"
    fi
    if [ -n "${NAT_CONSOLE_JWT_SECRET:-}" ]; then
        log_dry_run "would use JWT secret from NAT_CONSOLE_JWT_SECRET"
    else
        log_dry_run "would generate random JWT secret"
    fi
    log_dry_run "would create /opt/nat-console/env with mode 600"
    log_dry_run "would write NAT_CONSOLE_BIND to /opt/nat-console/env"
    log_dry_run "would not print JWT secret"
    log_dry_run "would enable nat-console.service"
    log_dry_run "would preserve existing /etc/ssl/nat-webui.crt if present"
    log_dry_run "would preserve existing /etc/ssl/nat-webui.key if present"
    log_dry_run "would ask before starting or restarting nat-console.service in interactive mode"
}

dry_run_assets_install() {
    log_dry_run "would install/update WebUI assets"
    log_dry_run "would check asset dependencies: curl wget ca-certificates systemd nodejs npm"
    log_dry_run "would use apt nodejs/npm if node or npm is missing"
    log_dry_run "would not add NodeSource or other third-party apt sources"
    log_dry_run "would install/update /usr/local/bin/nat-console via setup-console-assets.sh"
    log_dry_run "would update nat-console.service compatibility flags if the service exists"
}

dry_run_uninstall() {
    log_dry_run "would uninstall installed service files and binaries"
    log_dry_run "would disable nat.service if present, without stopping it"
    log_dry_run "would remove /lib/systemd/system/nat.service if present"
    log_dry_run "would disable nat-console.service if present, without stopping it"
    log_dry_run "would remove /lib/systemd/system/nat-console.service if present"
    log_dry_run "would remove /usr/local/bin/nat if present"
    log_dry_run "would remove /usr/local/bin/nat-console if present"
    log_dry_run "would run systemctl daemon-reload"
    log_dry_run "would preserve /etc/nat.conf /etc/nat.toml /opt/nat/env /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key"
}

run_core_install() {
    local config_type="${1:-${NAT_CONFIG_TYPE:-toml}}"
    if [ "$config_type" != "legacy" ] && [ "$config_type" != "toml" ]; then
        log_err "invalid config type: $config_type"
        exit 1
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_core_install "$config_type"
        return 0
    fi
    log_info "installing nat core service with $config_type config"
    NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}" bash "$SCRIPT_DIR/setup.sh" "$config_type"
}

run_console_install() {
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_console_install
        return 0
    fi
    log_info "installing nat-console WebUI service"
    NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}" NAT_SKIP_SERVICE_PROMPT="${NAT_SKIP_SERVICE_PROMPT:-0}" bash "$SCRIPT_DIR/setup-console.sh"
}

run_assets_install() {
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_assets_install
        return 0
    fi
    log_info "installing/updating WebUI assets"
    NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}" bash "$SCRIPT_DIR/setup-console-assets.sh"
}

run_uninstall() {
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_uninstall
        return 0
    fi
    log_warn "卸载不会执行 systemctl stop，也不会删除用户配置文件。"

    if [ -f /lib/systemd/system/nat.service ]; then
        systemctl disable nat >/dev/null 2>&1 || true
        rm -f /lib/systemd/system/nat.service
        log_ok "removed /lib/systemd/system/nat.service"
    else
        log_warn "nat.service not found"
    fi

    if [ -f /lib/systemd/system/nat-console.service ]; then
        systemctl disable nat-console >/dev/null 2>&1 || true
        rm -f /lib/systemd/system/nat-console.service
        log_ok "removed /lib/systemd/system/nat-console.service"
    else
        log_warn "nat-console.service not found"
    fi

    rm -f /usr/local/bin/nat
    rm -f /usr/local/bin/nat-console
    log_ok "removed /usr/local/bin/nat and /usr/local/bin/nat-console if present"

    systemctl daemon-reload
    log_ok "systemd daemon reloaded"

    log_warn "保留用户配置: /etc/nat.conf /etc/nat.toml /opt/nat/env /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key"
}

ask_config_type() {
    local config_type
    read -r -p "请选择配置格式 [toml/legacy，默认 toml]: " config_type
    config_type="${config_type:-toml}"
    if [ "$config_type" != "legacy" ] && [ "$config_type" != "toml" ]; then
        log_err "invalid config type: $config_type"
        exit 1
    fi
    echo "$config_type"
}

show_menu() {
    cat <<EOF
=========================================
 nftables-nat-rust 安装菜单
=========================================
1) 只安装核心转发服务 nat
2) 安装核心转发服务 nat + WebUI nat-console
3) 只安装 WebUI nat-console
4) 只安装/更新 WebUI 静态资源 assets
5) 卸载
0) 退出
=========================================
EOF
}

run_menu() {
    local choice config_type
    show_menu
    read -r -p "请选择操作: " choice
    case "$choice" in
        1)
            config_type="$(ask_config_type)"
            run_core_install "$config_type"
            ;;
        2)
            config_type="$(ask_config_type)"
            run_core_install "$config_type"
            run_console_install
            ;;
        3)
            run_console_install
            ;;
        4)
            run_assets_install
            ;;
        5)
            run_uninstall
            ;;
        0)
            log_info "退出"
            ;;
        *)
            log_err "未知选项: $choice"
            exit 1
            ;;
    esac
}

if [ "$#" -eq 0 ]; then
    run_menu
    exit 0
fi

ACTION=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --core-only|--with-console|--console-only|--assets-only|--uninstall|--help|-h)
            if [ -n "$ACTION" ]; then
                log_err "只能指定一个安装动作参数"
                exit 1
            fi
            ACTION="$1"
            ;;
        *)
            log_err "未知参数: $1"
            usage
            exit 1
            ;;
    esac
    shift
done

if [ -z "$ACTION" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        log_err "--dry-run 需要和安装动作参数组合使用"
        usage
        exit 1
    fi
    usage
    exit 1
fi

case "$ACTION" in
    --core-only)
        NAT_NONINTERACTIVE=1 run_core_install "${NAT_CONFIG_TYPE:-toml}"
        ;;
    --with-console)
        NAT_NONINTERACTIVE=1 run_core_install "${NAT_CONFIG_TYPE:-toml}"
        NAT_SKIP_SERVICE_PROMPT=1 run_console_install
        ;;
    --console-only)
        NAT_SKIP_SERVICE_PROMPT=1 run_console_install
        ;;
    --assets-only)
        NAT_NONINTERACTIVE=1 run_assets_install
        ;;
    --uninstall)
        NAT_NONINTERACTIVE=1 run_uninstall
        ;;
    --help|-h)
        usage
        ;;
esac
