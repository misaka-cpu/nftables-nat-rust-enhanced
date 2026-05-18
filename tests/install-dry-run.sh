#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_install() {
    (cd "$ROOT_DIR" && bash install.sh "$@")
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if ! grep -F "$needle" <<<"$haystack" >/dev/null; then
        echo "missing expected output: $needle" >&2
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
assert_contains "$setup_core" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$setup_console" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$setup_assets" "当前 release 二进制与系统 glibc 不兼容"
assert_contains "$install_script" "当前 release 二进制与系统 glibc 不兼容"

output="$(run_install --dry-run --with-console --use-release)"
assert_contains "$output" "would download GitHub Release asset:"
assert_contains "$output" "nftables-nat-rust-enhanced-linux-amd64.tar.gz"
assert_contains "$output" "would install nat-console WebUI service"
assert_contains "$output" "dry-run: 安装完成后可选择进入 CLI 管理菜单"

output="$(run_install --dry-run --core-only --use-release)"
assert_contains "$output" "would check core runtime dependencies"
assert_contains "$output" "would use release payload:"
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
assert_contains "$output" "console-only does not enter CLI management menu by default"

output="$(run_install --dry-run --console-only --enter-menu)"
assert_contains "$output" "would enter CLI management menu only if core nat is installed"

output="$(run_install --dry-run --uninstall --core)"
assert_contains "$output" "would ask uninstall target"
assert_contains "$output" "would never flush ruleset"
if grep -F "CLI 管理菜单" <<<"$output" >/dev/null; then
    echo "uninstall dry-run should not mention CLI menu entry" >&2
    echo "$output" >&2
    exit 1
fi

echo "install dry-run checks passed"
