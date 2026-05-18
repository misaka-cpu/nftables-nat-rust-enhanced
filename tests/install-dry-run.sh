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

menu_script="$(cat "$ROOT_DIR/nat-cli/src/menu.rs")"
assert_not_contains "$menu_script" "WebUI"
assert_not_contains "$menu_script" "nat-console"
assert_contains "$menu_script" "13) BBR / Telegram 状态"
assert_contains "$menu_script" "15) 一键更新本项目"
assert_contains "$menu_script" "16) 卸载 / 清理本项目"
assert_contains "$menu_script" "1) 更新核心转发 nat，推荐"
assert_contains "$menu_script" "2) 指定版本更新核心 nat"

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
