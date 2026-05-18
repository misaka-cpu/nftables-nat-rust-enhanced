#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
UNINSTALL_TARGET=""
UNINSTALL_DATA_MODE="keep"

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
  --uninstall      交互卸载/清理本项目
  --core           与 --uninstall 组合，仅卸载核心 nat
  --console        与 --uninstall 组合，仅卸载 WebUI nat-console
  --all            与 --uninstall 组合，卸载全部
  --keep-data      与 --uninstall 组合，保留配置、统计、备份（默认）
  --purge          与 --uninstall 组合，完全删除，必须输入 DELETE
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
    if [ "${NAT_START_SERVICE:-0}" = "1" ]; then
        log_dry_run "would start or restart nat.service"
    fi
    log_dry_run "would preserve existing /etc/nat.conf if present"
    log_dry_run "would preserve existing /etc/nat.toml if present"
    log_dry_run "would preserve existing /opt/nat/env if present"
    log_dry_run "would show CLI management entry: nat --menu"
    if [ "${NAT_START_SERVICE:-0}" != "1" ]; then
        log_dry_run "would ask before starting or restarting nat.service in interactive mode"
    fi
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
    log_dry_run "would run systemctl daemon-reload"
    log_dry_run "would restart nat-console.service"
    log_dry_run "would run WebUI health check: curl -k https://127.0.0.1:${NAT_CONSOLE_PORT:-5533}/health"
    log_dry_run "would preserve existing /etc/ssl/nat-webui.crt if present"
    log_dry_run "would preserve existing /etc/ssl/nat-webui.key if present"
    if [ -x "/usr/local/bin/nat" ]; then
        log_dry_run "would mention existing core nat CLI menu: nat --menu"
    fi
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
    log_dry_run "would ask uninstall target or use --core/--console/--all"
    log_dry_run "would ask data retention mode or use --keep-data/--purge"
    log_dry_run "would stop and disable selected project services"
    log_dry_run "would remove selected project service files and binaries"
    log_dry_run "would delete only project nft tables: ip/ip6 self-nat and ip/ip6 self-filter"
    log_dry_run "would never flush ruleset"
    log_dry_run "would run systemctl daemon-reload"
    log_dry_run "default would preserve /etc/nat.conf /etc/nat.toml /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups /opt/nat-console/env /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key"
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
    NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}" NAT_START_SERVICE="${NAT_START_SERVICE:-0}" bash "$SCRIPT_DIR/setup.sh" "$config_type"
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
    local target="${UNINSTALL_TARGET:-}"
    local data_mode="${UNINSTALL_DATA_MODE:-keep}"
    if [ -z "$target" ]; then
        while true; do
            echo "卸载目标:"
            echo "1) 仅卸载核心转发服务 nat"
            echo "2) 仅卸载 WebUI nat-console"
            echo "3) 卸载全部"
            echo "4) 仅清理本项目 nft 表"
            echo "0) 取消 / 退出卸载"
            read -r -p "请选择 [0/1/2/3/4]: " target_choice
            case "${target_choice:-0}" in
                1) target="core"; break ;;
                2) target="console"; break ;;
                3) target="all"; break ;;
                4) target="nft-tables"; break ;;
                0)
                    echo "已取消卸载。"
                    return 0
                    ;;
                *)
                    log_err "未知卸载目标"
                    ;;
            esac
        done
    fi
    if [ "$data_mode" = "keep" ] && [ "$target" != "nft-tables" ]; then
        echo "是否保留配置和数据？"
        echo "1) 保留配置、统计、备份，推荐"
        echo "2) 删除程序和服务，保留 /etc/nat.toml 和 backups"
        echo "3) 完全删除本项目配置、统计、备份、WebUI env/cert/key，危险"
        read -r -p "请选择 [1/2/3，默认 1]: " data_choice
        case "${data_choice:-1}" in
            1) data_mode="keep" ;;
            2) data_mode="keep-config" ;;
            3) data_mode="purge" ;;
            *) log_err "未知数据保留选项"; exit 1 ;;
        esac
    fi
    if [ "$data_mode" = "purge" ]; then
        read -r -p "危险操作：请输入 DELETE 确认完全删除: " confirm_delete
        if [ "$confirm_delete" != "DELETE" ]; then
            log_err "确认文本不匹配，取消卸载"
            exit 1
        fi
    fi
    log_warn "卸载只清理本项目组件和 self-* nft 表，不会 flush ruleset。"

    case "$target" in
        core|all)
            systemctl stop nat >/dev/null 2>&1 || true
            systemctl disable nat >/dev/null 2>&1 || true
            rm -f /lib/systemd/system/nat.service /etc/systemd/system/nat.service
            rm -f /usr/local/bin/nat
            log_ok "removed core nat service and binary if present"
            cleanup_nft_tables
            ;;
        console)
            ;;
        nft-tables)
            cleanup_nft_tables
            ;;
        *)
            log_err "invalid uninstall target: $target"
            exit 1
            ;;
    esac

    case "$target" in
        console|all)
            systemctl stop nat-console >/dev/null 2>&1 || true
            systemctl disable nat-console >/dev/null 2>&1 || true
            rm -f /lib/systemd/system/nat-console.service /etc/systemd/system/nat-console.service
            rm -f /usr/local/bin/nat-console
            log_ok "removed nat-console service and binary if present"
            ;;
    esac

    cleanup_data_by_mode "$data_mode"

    systemctl daemon-reload
    log_ok "systemd daemon reloaded"

    log_warn "默认保留用户配置和数据；完全删除仅在输入 DELETE 后执行。"
}

cleanup_nft_tables() {
    for spec in "ip self-nat" "ip6 self-nat" "ip self-filter" "ip6 self-filter"; do
        set -- $spec
        nft delete table "$1" "$2" >/dev/null 2>&1 || true
        log_ok "cleaned nft table $1 $2 if present"
    done
}

cleanup_data_by_mode() {
    local data_mode="$1"
    case "$data_mode" in
        keep)
            log_warn "保留配置和数据: /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups /opt/nat-console/env /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key"
            ;;
        keep-config)
            rm -f /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /opt/nat-console/env /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key
            log_warn "保留 /etc/nat.toml 和 /etc/nftables-nat/backups"
            ;;
        purge)
            rm -rf /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust /etc/nftables-nat /opt/nat-console /etc/ssl/nat-webui.crt /etc/ssl/nat-webui.key
            log_warn "已完全删除本项目配置、统计、备份、WebUI env/cert/key"
            ;;
    esac
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
 nftables-nat-rust-enhanced 安装菜单
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
        --core)
            UNINSTALL_TARGET="core"
            ;;
        --console)
            UNINSTALL_TARGET="console"
            ;;
        --all)
            UNINSTALL_TARGET="all"
            ;;
        --keep-data)
            UNINSTALL_DATA_MODE="keep"
            ;;
        --purge)
            UNINSTALL_DATA_MODE="purge"
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
if [ -n "$UNINSTALL_TARGET" ] && [ "$ACTION" != "--uninstall" ]; then
    log_err "--core/--console/--all 只能和 --uninstall 组合使用"
    exit 1
fi
if [ "$UNINSTALL_DATA_MODE" = "purge" ] && [ "$ACTION" != "--uninstall" ]; then
    log_err "--purge 只能和 --uninstall 组合使用"
    exit 1
fi

case "$ACTION" in
    --core-only)
        NAT_NONINTERACTIVE=1 run_core_install "${NAT_CONFIG_TYPE:-toml}"
        ;;
    --with-console)
        NAT_NONINTERACTIVE=1 NAT_START_SERVICE=1 run_core_install "${NAT_CONFIG_TYPE:-toml}"
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
