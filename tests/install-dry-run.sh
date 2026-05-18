#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_install() {
    (cd "$ROOT_DIR" && bash install.sh "$@")
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if ! grep -F -- "$needle" <<<"$haystack" >/dev/null; then
        echo "missing expected output: $needle" >&2
        echo "$haystack" >&2
        exit 1
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    if grep -F -- "$needle" <<<"$haystack" >/dev/null; then
        echo "unexpected output: $needle" >&2
        echo "$haystack" >&2
        exit 1
    fi
}

assert_line_not_contains() {
    local haystack="$1"
    local needle="$2"
    if grep -Fx -- "$needle" <<<"$haystack" >/dev/null; then
        echo "unexpected output line: $needle" >&2
        echo "$haystack" >&2
        exit 1
    fi
}

bash -n "$ROOT_DIR/install.sh"
bash -n "$ROOT_DIR/setup.sh"
bash -n "$ROOT_DIR/setup-console.sh"
bash -n "$ROOT_DIR/setup-console-assets.sh"

workflow="$(cat "$ROOT_DIR/.github/workflows/release.yml")"
assert_contains "$workflow" "container: debian:12"
assert_contains "$workflow" "cargo build --release --locked"
assert_contains "$workflow" "GLIBC_2.36"

setup_core="$(cat "$ROOT_DIR/setup.sh")"
setup_console="$(cat "$ROOT_DIR/setup-console.sh")"
setup_assets="$(cat "$ROOT_DIR/setup-console-assets.sh")"
install_script="$(cat "$ROOT_DIR/install.sh")"
menu_script="$(cat "$ROOT_DIR/nat-cli/src/menu.rs")"
main_script="$(cat "$ROOT_DIR/nat-cli/src/main.rs")"
webui_script="$(cat "$ROOT_DIR/static/index.html")"
console_handlers="$(cat "$ROOT_DIR/nat-console/src/handlers.rs")"
assert_contains "$setup_console" "read -r -p \"\$prompt\" \"\$var_name\" < /dev/tty"
assert_contains "$setup_console" "read -r -s -p \"\$prompt\" \"\$var_name\" < /dev/tty"
assert_contains "$setup_console" "当前环境不支持交互输入。"
assert_contains "$setup_console" "NAT_CONSOLE_AUTO_PASSWORD"
assert_contains "$install_script" "--webui-bind"
assert_contains "$install_script" "NAT_CONSOLE_BIND"
assert_contains "$install_script" "NAT_CONSOLE_AUTO_PASSWORD"
assert_contains "$setup_core" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$setup_console" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$setup_assets" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$install_script" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$setup_core" "systemctl restart nat"
assert_contains "$setup_core" "systemctl is-active --quiet nat"
assert_contains "$setup_console" "systemctl restart nat-console"
assert_contains "$setup_console" "WebUI 服务未正常启动，请查看："
assert_contains "$menu_script" "nat.service 未运行，转发规则不会应用。"
assert_contains "$menu_script" "nft 规则未找到。可能原因："
assert_contains "$menu_script" "16) 一键更新本项目"
assert_contains "$menu_script" "0) 返回"
assert_contains "$main_script" "no rules configured, waiting for config changes"
assert_contains "$webui_script" "openUpdateModal()"
assert_contains "$webui_script" "/api/update/status"
assert_contains "$webui_script" "/api/update"
assert_contains "$webui_script" "关闭 BBR"
assert_contains "$webui_script" "/api/bbr/disable"
assert_contains "$webui_script" "await loadBbrStatus();"
assert_contains "$webui_script" "BBR 已关闭，当前拥塞控制"
assert_contains "$webui_script" "background: #f8fafc;"
assert_not_contains "$webui_script" "background: #1e1e1e;"
assert_contains "$webui_script" "overflow-y: visible;"
assert_contains "$webui_script" "class=\"modal-close\""
assert_contains "$webui_script" "<select class=\"telegram-input\" id=\"updateVersion\">"
assert_not_contains "$webui_script" "id=\"updateVersion\" value=\"latest\""
assert_contains "$webui_script" "/api/update/releases"
assert_contains "$webui_script" "startUpdateButton"
assert_contains "$webui_script" "button.disabled = true"
assert_contains "$webui_script" "pollWebUiRecovery"
assert_contains "$webui_script" "window.location.reload()"
assert_contains "$webui_script" "if (target === 'console' || target === 'all') return true"
assert_contains "$webui_script" "setTimeout(loadUpdateStatus, 3000)"
assert_contains "$console_handlers" "valid_update_version"
assert_contains "$console_handlers" "无效版本，只允许 latest 或 v 开头的 semver tag"
assert_contains "$console_handlers" "choose_fallback_congestion_control"
assert_contains "$console_handlers" "net.ipv4.tcp_congestion_control={fallback}"
assert_contains "$console_handlers" "运行时仍为 bbr，但开机配置已移除"
assert_contains "$console_handlers" "BBR_SYSCTL_CONF"
assert_contains "$console_handlers" ".disabled"
assert_contains "$(cat "$ROOT_DIR/nat-console/src/server.rs")" "/api/update/releases"

output="$(run_install --dry-run --with-console --use-release)"
assert_contains "$output" "would download GitHub Release asset:"
assert_contains "$output" "nftables-nat-rust-enhanced-linux-amd64.tar.gz"
assert_contains "$output" "would run systemctl enable nat"
assert_contains "$output" "would run systemctl restart nat"
assert_contains "$output" "would check nat.service active: systemctl is-active nat"
assert_contains "$output" "would install nat-console WebUI service"
assert_contains "$output" "would run systemctl enable nat-console"
assert_contains "$output" "would run systemctl restart nat-console"
assert_contains "$output" "would run WebUI health check:"
assert_contains "$output" "dry-run: 安装完成后可选择进入 CLI 管理菜单"

output="$(run_install --dry-run --with-console --use-release --webui-bind 127.0.0.1 --webui-port 5533 --webui-username admin --webui-auto-password --webui-random-secret)"
assert_contains "$output" "would use WebUI bind from --webui-bind/NAT_CONSOLE_BIND: 127.0.0.1"
assert_contains "$output" "would use WebUI port from NAT_CONSOLE_PORT/--webui-port or default 5533"
assert_contains "$output" "would generate WebUI password because --webui-auto-password was provided"
assert_contains "$output" "would generate new JWT secret because --webui-random-secret was provided"

output="$(run_install --dry-run --core-only --use-release)"
assert_contains "$output" "would check core runtime dependencies"
assert_contains "$output" "would use release payload:"
assert_contains "$output" "would run systemctl enable nat"
assert_contains "$output" "would run systemctl restart nat"
assert_contains "$output" "would check nat.service active: systemctl is-active nat"
assert_not_contains "$output" "nat-console.service"
assert_contains "$output" "dry-run: 安装完成后可选择进入 CLI 管理菜单"

output="$(run_install --dry-run --core-only --enter-menu)"
assert_contains "$output" "would automatically enter CLI management menu after install:"

output="$(run_install --dry-run --core-only --build-from-source)"
assert_contains "$output" "would build from source with: cargo build --release"

output="$(cd "$ROOT_DIR" && NAT_TEST_UNAME_M=riscv64 bash install.sh --dry-run --with-console --use-release 2>&1)"
assert_contains "$output" "no prebuilt release asset for architecture: riscv64"
assert_contains "$output" "falling back to source build"

output="$(run_install --dry-run --core-only --use-release --version v0.1.0 --repo test-owner/test-repo)"
assert_contains "$output" "https://github.com/test-owner/test-repo/releases/download/v0.1.0/"

output="$(run_install --dry-run --console-only)"
assert_contains "$output" "would run systemctl enable nat-console"
assert_contains "$output" "would run systemctl restart nat-console"
assert_contains "$output" "would run WebUI health check:"
assert_line_not_contains "$output" "[DRY-RUN] would run systemctl restart nat"
assert_contains "$output" "console-only does not enter CLI management menu by default"

output="$(run_install --dry-run --console-only --enter-menu)"
assert_contains "$output" "would enter CLI management menu only if core nat is installed"

output="$(run_install --dry-run --uninstall --core)"
assert_contains "$output" "would ask uninstall target"
assert_contains "$output" "would never flush ruleset"
assert_not_contains "$output" "CLI 管理菜单"

output="$(run_install --dry-run --update --core-only --use-release)"
assert_contains "$output" "would download GitHub Release asset:"
assert_contains "$output" "would update only nat binary and nat.service"
assert_contains "$output" "would preserve user data: /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups /opt/nat-console/env"
assert_contains "$output" "would create backup directory: /etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS"
assert_contains "$output" "would rollback old binaries/service files if update or health check fails"
assert_not_contains "$output" "would update only nat-console"

output="$(run_install --dry-run --update --console-only --use-release)"
assert_contains "$output" "would update only nat-console, WebUI static assets, and nat-console.service"
assert_contains "$output" "would run systemctl restart nat-console"
assert_line_not_contains "$output" "[DRY-RUN] would run systemctl restart nat"

output="$(run_install --dry-run --update --with-console --use-release)"
assert_contains "$output" "would update nat + nat-console + WebUI static assets"
assert_contains "$output" "would run systemctl restart nat"
assert_contains "$output" "would run systemctl restart nat-console"

output="$(run_install --dry-run --update --use-release)"
assert_contains "$output" "would auto-detect installed components:"
assert_contains "$output" "would download GitHub Release asset:"

echo "install dry-run checks passed"
