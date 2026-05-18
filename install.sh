#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
RELEASE_REPO="misaka-cpu/nftables-nat-rust-enhanced"
RELEASE_VERSION="latest"
INSTALL_MODE="auto"
RELEASE_ASSET=""
RELEASE_PAYLOAD_DIR=""
INSTALL_SOURCE_DIR="$SCRIPT_DIR"
USE_RELEASE_SEEN=0
BUILD_SOURCE_SEEN=0
ENTER_MENU=0
UPDATE_MODE=0
ACTION=""
NAT_MENU_BIN="${NAT_MENU_BIN:-/usr/local/bin/nat}"
UNINSTALL_DATA_MODE="keep"

log_info() { echo "[INFO] $1"; }
log_ok() { echo "[OK] $1"; }
log_warn() { echo "[WARN] $1"; }
log_err() { echo "[ERR] $1"; }
log_dry_run() { echo "[DRY-RUN] $1"; }

usage() {
    cat <<EOF
用法: $0 [选项]

选项:
  --dry-run        只输出计划执行的动作，不实际安装或修改系统
  --core-only      安装核心转发服务 nat
  --use-release    优先从 GitHub Releases 下载预编译二进制
  --build-from-source
                   强制从源码 cargo build --release
  --version TAG    指定 GitHub Release 版本，默认 latest
  --repo OWNER/REPO
                   指定 GitHub 仓库，默认 $RELEASE_REPO
  --enter-menu     安装完成后自动进入 CLI 管理菜单
  --update         更新核心组件
  --uninstall      交互卸载/清理核心组件
  --keep-data      与 --uninstall 组合，保留配置、统计、备份（默认）
  --purge          与 --uninstall 组合，完全删除，必须输入 DELETE
  --help           显示此帮助

已移除:
  --with-console / --console-only / --assets-only

环境变量:
  NAT_CONFIG_TYPE=toml|legacy   非交互核心安装配置格式，默认 toml

示例:
  $0 --dry-run --core-only --use-release
  $0 --core-only --use-release --enter-menu
  $0 --update --core-only --use-release
  $0 --uninstall
EOF
}

deprecated_webui_arg() {
    log_err "WebUI / nat-console 已从本项目移除。"
    echo "请使用："
    echo "  --core-only"
    echo "或："
    echo "  --update --core-only"
    exit 2
}

prompt_read() {
    local prompt="$1"
    local var_name="$2"
    if [ -r /dev/tty ] && [ -w /dev/tty ]; then
        read -r -p "$prompt" "$var_name" < /dev/tty
    elif [ -t 0 ]; then
        read -r -p "$prompt" "$var_name"
    else
        return 1
    fi
}

detect_release_platform() {
    local os arch
    os="$(uname -s)"
    arch="${NAT_TEST_UNAME_M:-$(uname -m)}"
    if [ "$os" != "Linux" ]; then
        echo "[WARN] no prebuilt release asset for OS: $os" >&2
        return 1
    fi
    case "$arch" in
        x86_64|amd64) printf '%s' "linux-amd64" ;;
        aarch64|arm64) printf '%s' "linux-arm64" ;;
        *)
            echo "[WARN] no prebuilt release asset for architecture: $arch" >&2
            return 1
            ;;
    esac
}

release_download_base_url() {
    if [ "$RELEASE_VERSION" = "latest" ]; then
        printf 'https://github.com/%s/releases/latest/download' "$RELEASE_REPO"
    else
        printf 'https://github.com/%s/releases/download/%s' "$RELEASE_REPO" "$RELEASE_VERSION"
    fi
}

local_binary_available() {
    [ -x "$SCRIPT_DIR/target/release/nat" ]
}

prepare_release_payload() {
    local platform base_url tmp_dir archive_path sums_path payload_dir
    if ! platform="$(detect_release_platform)"; then
        return 2
    fi

    RELEASE_ASSET="nftables-nat-rust-enhanced-${platform}.tar.gz"
    base_url="$(release_download_base_url)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "would download GitHub Release asset: ${base_url}/${RELEASE_ASSET}"
        log_dry_run "would download SHA256SUMS if available: ${base_url}/SHA256SUMS"
        log_dry_run "would verify ${RELEASE_ASSET} with SHA256SUMS when the asset is listed"
        log_dry_run "would extract release payload and use nat from it"
        return 0
    fi

    for command in curl tar sha256sum; do
        if ! command -v "$command" >/dev/null 2>&1; then
            log_err "$command not found; install lightweight dependencies first"
            log_err "apt update && apt install -y curl ca-certificates nftables iproute2 iptables procps openssl tar nano"
            return 1
        fi
    done

    tmp_dir="$(mktemp -d)"
    archive_path="$tmp_dir/$RELEASE_ASSET"
    sums_path="$tmp_dir/SHA256SUMS"
    log_info "downloading GitHub Release asset: ${base_url}/${RELEASE_ASSET}"
    if ! curl -fsSL "${base_url}/${RELEASE_ASSET}" -o "$archive_path"; then
        log_err "failed to download release asset: ${RELEASE_ASSET}"
        return 1
    fi

    if curl -fsSL "${base_url}/SHA256SUMS" -o "$sums_path"; then
        if grep -F "  ${RELEASE_ASSET}" "$sums_path" >/dev/null 2>&1 || grep -F " *${RELEASE_ASSET}" "$sums_path" >/dev/null 2>&1; then
            (cd "$tmp_dir" && sha256sum -c --ignore-missing SHA256SUMS) || {
                log_err "SHA256 verification failed for ${RELEASE_ASSET}"
                return 1
            }
            log_ok "SHA256 verified: ${RELEASE_ASSET}"
        else
            log_err "SHA256SUMS does not list ${RELEASE_ASSET}; refusing to trust a mismatched checksum file"
            return 1
        fi
    else
        log_warn "SHA256SUMS not available; continuing without checksum verification"
    fi

    mkdir -p "$tmp_dir/payload"
    tar -xzf "$archive_path" -C "$tmp_dir/payload"
    if [ -x "$tmp_dir/payload/nat" ]; then
        payload_dir="$tmp_dir/payload"
    else
        payload_dir="$(find "$tmp_dir/payload" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    fi
    if [ -z "${payload_dir:-}" ] || [ ! -x "$payload_dir/nat" ]; then
        log_err "release payload does not contain executable nat"
        return 1
    fi

    RELEASE_PAYLOAD_DIR="$payload_dir"
    if [ -f "$payload_dir/setup.sh" ]; then
        INSTALL_SOURCE_DIR="$payload_dir"
    elif [ -f "$SCRIPT_DIR/setup.sh" ]; then
        INSTALL_SOURCE_DIR="$SCRIPT_DIR"
    else
        log_err "release payload does not contain setup.sh and local setup.sh is unavailable"
        return 1
    fi
    export NAT_BINARY_DIR="$payload_dir"
    log_ok "release payload ready: $RELEASE_ASSET"
}

build_from_source() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "would build from source with: cargo build --release"
        log_dry_run "would use local binary from target/release/nat"
        return 0
    fi
    if [ ! -f "$SCRIPT_DIR/Cargo.toml" ]; then
        log_err "source tree not found; cannot build from source here"
        log_err "download source first, then run: cargo build --release && bash install.sh --core-only --build-from-source"
        return 1
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        log_err "cargo not found; install Rust toolchain or use --use-release"
        return 1
    fi
    log_info "building from source: cargo build --release"
    cargo build --release
}

prepare_install_payload() {
    if [ "$ACTION" = "--uninstall" ] || [ "$ACTION" = "--help" ] || [ "$ACTION" = "-h" ]; then
        return 0
    fi
    if [ "$INSTALL_MODE" = "source" ]; then
        build_from_source
        return $?
    fi
    if [ "$INSTALL_MODE" = "release" ] || ! local_binary_available; then
        if prepare_release_payload; then
            return 0
        fi
        log_warn "prebuilt release is unavailable or failed"
        log_warn "falling back to source build; use --build-from-source to make this explicit"
        build_from_source
        return $?
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        log_dry_run "would use existing local build: target/release/nat"
    fi
}

dry_run_core_install() {
    local config_type="$1"
    log_dry_run "would install core nat"
    log_dry_run "would check core runtime dependencies: curl ca-certificates nftables iproute2 iptables procps systemd openssl tar"
    if [ -n "$RELEASE_ASSET" ]; then
        log_dry_run "would use release payload: $RELEASE_ASSET"
    elif [ -x "$SCRIPT_DIR/target/release/nat" ]; then
        log_dry_run "would use local build: target/release/nat"
    else
        log_dry_run "local build not found, would try release binary then fallback to source build"
    fi
    log_dry_run "would install /usr/local/bin/nat"
    log_dry_run "would create/update /lib/systemd/system/nat.service with $config_type config"
    log_dry_run "would preserve existing /etc/nat.conf if present"
    log_dry_run "would preserve existing /etc/nat.toml if present"
    log_dry_run "would run systemctl daemon-reload"
    log_dry_run "would run systemctl enable nat"
    log_dry_run "would run systemctl restart nat"
    log_dry_run "would check nat.service active: systemctl is-active nat"
    log_dry_run "would show CLI management entry: nat --menu"
}

backup_update_files() {
    local backup_dir="$1"
    mkdir -p "$backup_dir"
    for path in /usr/local/bin/nat /lib/systemd/system/nat.service /etc/systemd/system/nat.service; do
        if [ -e "$path" ]; then
            mkdir -p "$backup_dir$(dirname "$path")"
            cp -a "$path" "$backup_dir$path"
        fi
    done
}

rollback_update_files() {
    local backup_dir="$1"
    local path
    for path in /usr/local/bin/nat /lib/systemd/system/nat.service /etc/systemd/system/nat.service; do
        if [ -e "$backup_dir$path" ]; then
            cp -a "$backup_dir$path" "$path"
        fi
    done
    systemctl daemon-reload || true
}

run_core_install() {
    local config_type="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_core_install "$config_type"
        return 0
    fi
    NAT_NONINTERACTIVE=1 NAT_START_SERVICE=1 "$INSTALL_SOURCE_DIR/setup.sh" "$config_type"
}

dry_run_update() {
    if [ "$INSTALL_MODE" = "release" ]; then
        prepare_release_payload || true
    fi
    log_dry_run "would update only core nat binary and nat.service"
    log_dry_run "would preserve user data: /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups"
    log_dry_run "would create backup directory: /etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS"
    log_dry_run "would backup old /usr/local/bin/nat and nat.service before replacing"
    dry_run_core_install "${NAT_CONFIG_TYPE:-toml}"
    log_dry_run "would rollback old binary/service files if update or health check fails"
}

run_update() {
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_update
        return 0
    fi
    local backup_dir="/etc/nftables-nat/backups/update-$(date +%Y%m%d-%H%M%S)"
    log_info "creating update backup: $backup_dir"
    backup_update_files "$backup_dir"
    if ! prepare_install_payload; then
        log_err "更新 payload 准备失败，保留旧版本"
        return 1
    fi
    if ! run_core_install "${NAT_CONFIG_TYPE:-toml}"; then
        log_err "更新失败，尝试回滚旧二进制和 service 文件"
        rollback_update_files "$backup_dir"
        log_warn "回滚已执行，请检查服务状态和日志"
        return 1
    fi
    log_ok "更新完成，备份目录: $backup_dir"
}

dry_run_uninstall() {
    log_dry_run "would show core-only uninstall menu"
    log_dry_run "would stop and disable nat.service when uninstalling core"
    log_dry_run "would remove nat.service and /usr/local/bin/nat"
    log_dry_run "would delete only project nft tables: ip/ip6 self-nat and ip/ip6 self-filter"
    log_dry_run "would never flush ruleset"
    log_dry_run "would run systemctl daemon-reload"
    log_dry_run "default would preserve /etc/nat.conf /etc/nat.toml /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups"
}

run_cli_menu() {
    local err_file
    if [ ! -x "$NAT_MENU_BIN" ]; then
        log_warn "未检测到核心 nat，无法进入 CLI 管理菜单。请先安装核心服务。"
        return 0
    fi
    log_info "entering CLI management menu: $NAT_MENU_BIN --menu"
    err_file="$(mktemp)"
    if "$NAT_MENU_BIN" --menu 2>"$err_file"; then
        rm -f "$err_file"
        return 0
    fi
    if grep -E "GLIBC_[0-9.]+.*not found|version .*GLIBC_[0-9.]+.*not found" "$err_file" >/dev/null 2>&1; then
        log_err "当前 release 二进制与系统 glibc 不兼容。"
        log_err "请使用更新后的 GitHub Release，或使用 --build-from-source 在本机编译。"
        log_err "原始错误: $(tr '\n' ' ' < "$err_file")"
        rm -f "$err_file"
        return 1
    fi
    cat "$err_file" >&2
    rm -f "$err_file"
    return 1
}

maybe_enter_cli_menu() {
    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$ENTER_MENU" -eq 1 ]; then
            log_dry_run "would automatically enter CLI management menu after install: $NAT_MENU_BIN --menu"
        else
            log_dry_run "dry-run: 安装完成后可选择进入 CLI 管理菜单"
        fi
        return 0
    fi
    if [ "$ENTER_MENU" -eq 1 ]; then
        run_cli_menu
        return 0
    fi
    if [ -t 0 ] && [ -t 1 ]; then
        local answer
        if prompt_read "是否立即进入 CLI 管理菜单？[y/N]: " answer; then
            case "${answer:-}" in
                y|Y|yes|YES) run_cli_menu ;;
                *) log_info "后续可使用 nat --menu 进入 CLI 管理菜单。" ;;
            esac
        fi
    else
        log_info "后续可使用 nat --menu 进入 CLI 管理菜单。"
    fi
}

cleanup_project_nft_tables() {
    for family in ip ip6; do
        for table in self-nat self-filter; do
            nft delete table "$family" "$table" >/dev/null 2>&1 || true
        done
    done
}

run_uninstall() {
    if [ "$DRY_RUN" -eq 1 ]; then
        dry_run_uninstall
        return 0
    fi
    local choice data_choice confirm_delete confirm
    echo "===================================="
    echo "卸载 / 清理 nftables-nat-rust-enhanced"
    echo "===================================="
    echo "1) 卸载核心转发服务 nat"
    echo "2) 仅清理本项目 nft 表"
    echo "3) 完全删除本项目配置/统计/备份，危险"
    echo "0) 返回"
    if ! prompt_read "请选择操作 [0/1/2/3]: " choice; then
        log_err "当前环境不支持交互卸载，请在 TTY 中运行 bash install.sh --uninstall"
        exit 1
    fi
    case "${choice:-0}" in
        0) log_info "取消卸载"; return 0 ;;
        1) data_choice="keep" ;;
        2) data_choice="nft-only" ;;
        3) data_choice="purge" ;;
        *) log_err "未知选项: $choice"; exit 1 ;;
    esac
    if [ "$data_choice" = "purge" ]; then
        prompt_read "危险操作：请输入 DELETE 确认完全删除: " confirm_delete || exit 1
        if [ "$confirm_delete" != "DELETE" ]; then
            log_err "确认文本不匹配，取消卸载"
            exit 1
        fi
    fi
    prompt_read "即将执行卸载/清理操作。确认继续? [y/N]: " confirm || exit 1
    case "${confirm:-}" in
        y|Y|yes|YES) ;;
        *) log_info "已取消卸载"; return 0 ;;
    esac
    if [ "$data_choice" != "nft-only" ]; then
        systemctl stop nat >/dev/null 2>&1 || true
        systemctl disable nat >/dev/null 2>&1 || true
        rm -f /lib/systemd/system/nat.service /etc/systemd/system/nat.service
        rm -f /usr/local/bin/nat
        log_ok "removed nat service and binary if present"
    fi
    cleanup_project_nft_tables
    log_ok "cleaned project nft tables if present"
    if [ "$data_choice" = "purge" ]; then
        rm -rf /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust /etc/nftables-nat
        log_warn "已完全删除本项目配置、统计、备份"
    else
        log_warn "保留配置和数据: /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups"
    fi
    systemctl daemon-reload || true
}

if [ "$#" -eq 0 ]; then
    ACTION="--core-only"
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --core-only)
            [ -n "$ACTION" ] && { log_err "只能指定一个动作参数"; exit 1; }
            ACTION="--core-only"
            ;;
        --with-console|--console-only|--assets-only|--webui-bind|--webui-port|--webui-username|--webui-password|--webui-auto-password|--webui-random-secret|--console|--all)
            deprecated_webui_arg
            ;;
        --use-release) INSTALL_MODE="release"; USE_RELEASE_SEEN=1 ;;
        --build-from-source) INSTALL_MODE="source"; BUILD_SOURCE_SEEN=1 ;;
        --enter-menu) ENTER_MENU=1 ;;
        --update) UPDATE_MODE=1 ;;
        --version)
            [ "$#" -lt 2 ] || [ -z "$2" ] && { log_err "--version requires a tag"; exit 1; }
            RELEASE_VERSION="$2"
            shift
            ;;
        --repo)
            [ "$#" -lt 2 ] || [ -z "$2" ] && { log_err "--repo requires OWNER/REPO"; exit 1; }
            RELEASE_REPO="$2"
            case "$RELEASE_REPO" in
                */*) ;;
                *) log_err "--repo must be OWNER/REPO"; exit 1 ;;
            esac
            shift
            ;;
        --uninstall)
            [ -n "$ACTION" ] && { log_err "只能指定一个动作参数"; exit 1; }
            ACTION="--uninstall"
            ;;
        --keep-data) UNINSTALL_DATA_MODE="keep" ;;
        --purge) UNINSTALL_DATA_MODE="purge" ;;
        --help|-h) ACTION="--help" ;;
        *)
            log_err "未知参数: $1"
            usage
            exit 1
            ;;
    esac
    shift
done

if [ "$USE_RELEASE_SEEN" -eq 1 ] && [ "$BUILD_SOURCE_SEEN" -eq 1 ]; then
    log_err "--use-release and --build-from-source cannot be used together"
    exit 1
fi

if [ "$UPDATE_MODE" -eq 1 ]; then
    ACTION="${ACTION:-"--core-only"}"
    if [ "$ACTION" != "--core-only" ]; then
        log_err "--update 只能与 --core-only 组合"
        exit 1
    fi
    run_update
    exit $?
fi

case "$ACTION" in
    --core-only|"")
        prepare_install_payload
        run_core_install "${NAT_CONFIG_TYPE:-toml}"
        maybe_enter_cli_menu
        ;;
    --uninstall)
        run_uninstall
        ;;
    --help|-h)
        usage
        ;;
    *)
        log_err "未知动作: $ACTION"
        usage
        exit 1
        ;;
esac
