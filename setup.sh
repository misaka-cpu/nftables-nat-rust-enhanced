#!/bin/bash
set -euo pipefail

# NAT 服务安装脚本 - 支持 legacy 和 toml 配置格式

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APT_UPDATED=0
MISSING_PACKAGES=()
OS_ID=""
OS_VERSION_ID=""
OS_PRETTY_NAME=""
NAT_NONINTERACTIVE="${NAT_NONINTERACTIVE:-0}"
NAT_START_SERVICE="${NAT_START_SERVICE:-0}"

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
    ensure_apt_packages curl ca-certificates nftables iproute2 iptables procps systemd openssl
    ensure_commands \
        "curl:curl" \
        "nft:nftables" \
        "ip:iproute2" \
        "iptables:iptables" \
        "sysctl:procps" \
        "systemctl:systemd" \
        "openssl:openssl"
    install_queued_packages
    log_ok "dependency check completed"
}

# 使用说明
usage() {
    echo "用法: $0 [legacy|toml]"
    echo "  legacy - 使用传统配置格式 (/etc/nat.conf)"
    echo "  toml   - 使用 TOML 配置格式 (/etc/nat.toml)"
    echo ""
    echo "示例:"
    echo "  $0 legacy"
    echo "  $0 toml"
    exit 1
}

# 检查参数
if [ $# -eq 0 ]; then
    echo "错误: 缺少配置格式参数"
    usage
fi

CONFIG_TYPE="$1"

if [ "$CONFIG_TYPE" != "legacy" ] && [ "$CONFIG_TYPE" != "toml" ]; then
    echo "错误: 无效的配置格式 '$CONFIG_TYPE'"
    usage
fi

preflight_dependencies

LOCAL_NAT_BIN="${NAT_BINARY_DIR:-$SCRIPT_DIR/target/release}/nat"
if [ -x "$LOCAL_NAT_BIN" ]; then
    log_info "using nat binary: $LOCAL_NAT_BIN"
    install -m 755 "$LOCAL_NAT_BIN" /usr/local/bin/nat
    check_binary_glibc_compat /usr/local/bin/nat nat
else
    log_err "nat binary not found: $LOCAL_NAT_BIN"
    log_err "run install.sh with --use-release or build first with: cargo build --release"
    exit 1
fi
log_ok "nat installed to /usr/local/bin/nat"

# 根据配置类型设置不同的参数
if [ "$CONFIG_TYPE" = "legacy" ]; then
    EXEC_START="/usr/local/bin/nat /etc/nat.conf"
    CONFIG_FILE="/etc/nat.conf"
    EXAMPLE_FILE="/etc/nat_example.conf"
else
    EXEC_START="/usr/local/bin/nat --toml /etc/nat.toml"
    CONFIG_FILE="/etc/nat.toml"
    EXAMPLE_FILE="/etc/nat_example.toml"
fi

# 创建systemd服务
log_info "创建/更新 systemd 服务..."
cat > /lib/systemd/system/nat.service <<EOF
[Unit]
Description=nat-service
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/nat
EnvironmentFile=/opt/nat/env
ExecStart=$EXEC_START
ExecStop=/bin/bash -c 'nft add table ip self-nat; nft delete table ip self-nat; nft add table ip6 self-nat; nft delete table ip6 self-nat; nft add table ip self-filter; nft delete table ip self-filter; nft add table ip6 self-filter; nft delete table ip6 self-filter'
LimitNOFILE=100000
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# 设置开机启动
systemctl daemon-reload
systemctl enable nat
log_ok "nat.service enabled"

# 创建工作目录
mkdir -p /opt/nat
if [ -e /opt/nat/env ]; then
    log_warn "保留已有环境文件: /opt/nat/env"
else
    touch /opt/nat/env
    log_ok "created /opt/nat/env"
fi

# 根据配置类型创建配置文件
if [ "$CONFIG_TYPE" = "legacy" ]; then
    echo "创建 legacy 格式配置文件..."
    if [ ! -s "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" <<EOF
# 配置方式参考本项目 README：
# https://github.com/misaka-cpu/nftables-nat-rust-enhanced#传统配置文件
EOF
        log_ok "created $CONFIG_FILE"
    else
        log_warn "保留已有配置文件: $CONFIG_FILE"
    fi
    
    # 生成示例配置文件
    cat > "$EXAMPLE_FILE" <<EOF
# 单端口转发：本机端口 -> 目标地址:端口
SINGLE,49999,59999,example.com
# 端口段转发：本机端口段 -> 目标地址:端口段
RANGE,50000,50010,example.com
# 端口重定向：外部端口 -> 本机端口
REDIRECT,8000,3128
# 端口段重定向：外部端口段 -> 本机端口
REDIRECT,30001-39999,45678
# 仅转发 TCP 流量
SINGLE,10000,443,example.com,tcp
# 仅转发 UDP 流量
SINGLE,10001,53,dns.example.com,udp
# 以 # 开头的行为注释
# SINGLE,3000,3000,disabled.example.com
EOF
else
    echo "创建 TOML 格式配置文件..."
    # Check if /etc/nat.toml exists, if not create it with example content
    if [ ! -s "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" <<EOF
# 配置方式参考本项目 README：
# https://github.com/misaka-cpu/nftables-nat-rust-enhanced#toml-配置示例
rules = []

[stats]
enabled = true
collect_interval_seconds = 60
data_file = "/var/lib/nftables-nat-rust/stats.json"
traffic_mode = "both"
EOF
        log_ok "created $CONFIG_FILE"
    else
        log_warn "保留已有配置文件: $CONFIG_FILE"
    fi
    
    # 生成示例配置文件
    cat > "$EXAMPLE_FILE" <<EOF
# 单端口转发示例
[[rules]]
type = "single"
sport = 10000          # 本机端口
dport = 443            # 目标端口
domain = "example.com" # 目标域名或 IP
protocol = "all"       # all, tcp 或 udp
ip_version = "ipv4"    # ipv4, ipv6 或 all
comment = "HTTPS 转发"

# 端口段转发示例
[[rules]]
type = "range"
port_start = 20000      # 起始端口
port_end = 20100        # 结束端口
domain = "example.com"
protocol = "tcp"
ip_version = "all"    # 同时支持 IPv4 和 IPv6
comment = "端口段转发"

# 单端口重定向示例
[[rules]]
type = "redirect"
sport = 8080         # 源端口
dport = 3128         # 目标端口
protocol = "all"
ip_version = "ipv4"
comment = "单端口重定向到本机"

# 端口段重定向示例
[[rules]]
type = "redirect"
sport = 30001        # 起始端口
sport_end = 39999     # 结束端口
dport = 45678        # 目标端口
protocol = "tcp"
ip_version = "all"
comment = "端口段重定向到本机"

# 强制 IPv6 转发
[[rules]]
type = "single"
sport = 9001
dport = 9090
domain = "ipv6.example.com"
protocol = "all"
ip_version = "ipv6"    # 仅使用 IPv6
comment = "IPv6 专用转发"

[stats]
enabled = true
collect_interval_seconds = 60
data_file = "/var/lib/nftables-nat-rust/stats.json"
traffic_mode = "both" # both / out / in
EOF
fi

if [ "$NAT_START_SERVICE" = "1" ]; then
    if systemctl is-active --quiet nat; then
        systemctl restart nat
        log_ok "nat.service restarted"
    else
        systemctl start nat
        log_ok "nat.service started"
    fi
elif [ "$NAT_NONINTERACTIVE" = "1" ]; then
    log_info "非交互模式：已 enable nat.service，不强制 start/restart"
else
    read -r -p "是否立即启动/重启 nat.service? [y/N]: " START_NAT
    if [[ "$START_NAT" =~ ^[Yy]$ ]]; then
        if systemctl is-active --quiet nat; then
            systemctl restart nat
            log_ok "nat.service restarted"
        else
            systemctl start nat
            log_ok "nat.service started"
        fi
    else
        log_info "已跳过立即启动/重启 nat.service"
    fi
fi

echo ""
echo "========================================="
echo "安装成功！"
echo "========================================="
echo "配置格式: $CONFIG_TYPE"
echo "配置文件: $CONFIG_FILE"
echo "示例配置: $EXAMPLE_FILE"
echo ""
echo "请编辑 $CONFIG_FILE 以自定义规则。"
echo ""
echo "配置示例如下："
echo "----------------------------------------"
cat "$EXAMPLE_FILE"
echo "----------------------------------------"
echo ""
echo "后续维护 / 管理："
echo "  nat --menu"
echo "或："
echo "  /usr/local/bin/nat --menu"
echo ""
echo "常用服务命令："
echo "  查看状态: systemctl status nat --no-pager"
echo "  启动服务: systemctl start nat"
echo "  停止服务: systemctl stop nat"
echo "  重启服务: systemctl restart nat"
echo "  查看日志: journalctl -u nat -f"
echo ""
echo "进入 CLI 菜单后可使用“测试转发规则连通性”检查规则是否命中。"
echo "========================================="
