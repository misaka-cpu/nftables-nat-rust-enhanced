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

bash -n "$ROOT_DIR/install.sh"
bash -n "$ROOT_DIR/setup.sh"

workspace="$(cat "$ROOT_DIR/Cargo.toml")"
assert_not_contains "$workspace" "nat-console"
assert_not_contains "$workspace" "axum"
assert_not_contains "$workspace" "tower-http"

workflow="$(cat "$ROOT_DIR/.github/workflows/release.yml")"
assert_contains "$workflow" "check_glibc target/release/nat"
assert_not_contains "$workflow" "target/release/nat-console"
assert_not_contains "$workflow" "static"
assert_not_contains "$workflow" "setup-console"

install_script="$(cat "$ROOT_DIR/install.sh")"
menu_script="$(cat "$ROOT_DIR/nat-cli/src/menu.rs")"
assert_not_contains "$menu_script" "WebUI"
assert_not_contains "$menu_script" "nat-console"
assert_contains "$menu_script" "13) BBR / Telegram 状态"
assert_contains "$menu_script" "15) 一键更新本项目"
assert_contains "$menu_script" "16) 卸载 / 清理本项目"
assert_contains "$menu_script" "1) 更新核心转发 nat，推荐"
assert_contains "$menu_script" "2) 指定版本更新核心 nat"
assert_contains "$menu_script" "install.sh | bash -s -- {}"
assert_contains "$menu_script" "\"--update\", \"--core-only\", \"--use-release\""

uninstall_common="$(cat "$ROOT_DIR/nat-common/src/uninstall.rs")"
assert_not_contains "$uninstall_common" "Console"
assert_not_contains "$uninstall_common" "All"
assert_not_contains "$uninstall_common" "nat-console"

readme="$(cat "$ROOT_DIR/README.md")"
assert_contains "$readme" "CLI-first"
assert_contains "$readme" "nat --menu"
assert_not_contains "$readme" "--with-console"
assert_not_contains "$readme" "--console-only"
assert_not_contains "$readme" "--assets-only"
assert_not_contains "$readme" "https://127.0.0.1:5533"
assert_not_contains "$readme" "NAT_CONSOLE"

output="$(run_install --dry-run --core-only --use-release)"
assert_contains "$output" "would download GitHub Release asset:"
assert_contains "$output" "would extract release payload and use nat from it"
assert_contains "$output" "would install /usr/local/bin/nat"
assert_contains "$output" "would run systemctl enable nat"
assert_contains "$output" "would run systemctl restart nat"
assert_contains "$output" "would check nat.service active: systemctl is-active nat"
assert_not_contains "$output" "nat-console"
assert_not_contains "$output" "static"

output="$(run_install --dry-run --core-only --enter-menu)"
assert_contains "$output" "would automatically enter CLI management menu after install:"
assert_contains "$install_script" '"$NAT_MENU_BIN" --menu < /dev/tty > /dev/tty'
assert_contains "$install_script" "当前环境没有可用 TTY，无法自动进入 CLI 菜单。"
assert_contains "$menu_script" "当前环境不支持交互式菜单，请在终端中运行 nat --menu。"
assert_contains "$menu_script" "is_menu_refresh_command"
assert_contains "$menu_script" "\"nat --menu\" | \"nat menu\" | \"menu\" | \"main\" | \"m\""
assert_not_contains "$menu_script" "未自动应用"
assert_contains "$menu_script" "nat.service 通常会自动检测配置变化"
assert_contains "$menu_script" "nft -c 检查、备份当前规则、应用失败自动回滚"
assert_contains "$menu_script" "7) 查看 Stats 流量统计"
assert_not_contains "$menu_script" "查看 stats 流量统计"
assert_contains "$menu_script" "2) 切换统计口径"
assert_contains "$menu_script" "both 双向 out + in，默认推荐"
assert_contains "$menu_script" "BBR / Telegram 状态"
assert_contains "$menu_script" "开启 BBR"
assert_contains "$menu_script" "关闭 BBR"
assert_contains "$menu_script" "按 Enter 返回..."
assert_contains "$menu_script" "配置 Telegram bot_token 和 chat_id"
assert_contains "$menu_script" "设置 Telegram 通知间隔"
assert_not_contains "$menu_script" "prompt_secret"
assert_contains "$menu_script" "请输入 Telegram bot_token"
assert_contains "$menu_script" "mask_bot_token"
assert_contains "$menu_script" "请先配置 Telegram bot_token 和 chat_id。"
assert_contains "$menu_script" "是否启用 Telegram 通知？[y/N]"
assert_contains "$menu_script" "notify_interval_minutes = minutes"
assert_contains "$menu_script" "set_enabled(false)"
assert_contains "$menu_script" "rule.enabled()"
assert_contains "$menu_script" "禁用规则不会应用到 nft"
assert_contains "$menu_script" "不会自动放行或封禁来源 IP"
assert_contains "$menu_script" "current_version_for_update"
assert_contains "$menu_script" "installed_nat_version"
assert_contains "$menu_script" "parse_nat_version_output"
assert_contains "$menu_script" "build_version_for_update_display"
assert_not_contains "$menu_script" "当前版本: {}\", env!(\"CARGO_PKG_VERSION\")"
assert_contains "$workflow" 'NAT_BUILD_VERSION="${GITHUB_REF_NAME}" cargo build --release --locked'
assert_contains "$workflow" 'target/release/nat --version | grep -F "${GITHUB_REF_NAME}"'

for deprecated in --with-console --console-only --assets-only; do
    set +e
    output="$(run_install --dry-run "$deprecated" 2>&1)"
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        echo "$deprecated unexpectedly succeeded" >&2
        echo "$output" >&2
        exit 1
    fi
    assert_contains "$output" "WebUI / nat-console 已从本项目移除。"
    assert_contains "$output" "--core-only"
    assert_contains "$output" "--update --core-only"
done

output="$(run_install --dry-run --update --core-only --use-release)"
assert_contains "$output" "would update only core nat binary and nat.service"
assert_contains "$output" "would preserve user data: /etc/nat.toml /etc/nat.conf /var/lib/nftables-nat-rust/stats.json /etc/nftables-nat/backups"
assert_contains "$output" "would backup old /usr/local/bin/nat and nat.service before replacing"
assert_not_contains "$output" "nat-console"
assert_not_contains "$output" "static"

output="$(run_install --dry-run --uninstall)"
assert_contains "$output" "would show core-only uninstall menu"
assert_contains "$output" "would remove nat.service and /usr/local/bin/nat"
assert_contains "$output" "would never flush ruleset"
assert_not_contains "$output" "nat-console"
assert_not_contains "$output" "WebUI"

echo "core-only install dry-run checks passed"
