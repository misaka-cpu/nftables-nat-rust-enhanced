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

output="$(run_install --dry-run --with-console --use-release)"
assert_contains "$output" "would download GitHub Release asset:"
assert_contains "$output" "nftables-nat-rust-enhanced-linux-amd64.tar.gz"
assert_contains "$output" "would install nat-console WebUI service"

output="$(run_install --dry-run --core-only --use-release)"
assert_contains "$output" "would check core runtime dependencies"
assert_contains "$output" "would use release payload:"

output="$(run_install --dry-run --core-only --build-from-source)"
assert_contains "$output" "would build from source with: cargo build --release"

output="$(cd "$ROOT_DIR" && NAT_TEST_UNAME_M=riscv64 bash install.sh --dry-run --with-console --use-release 2>&1)"
assert_contains "$output" "no prebuilt release asset for architecture: riscv64"
assert_contains "$output" "falling back to source build"

output="$(run_install --dry-run --core-only --use-release --version v0.1.0 --repo test-owner/test-repo)"
assert_contains "$output" "https://github.com/test-owner/test-repo/releases/download/v0.1.0/"

output="$(run_install --dry-run --uninstall --core)"
assert_contains "$output" "would ask uninstall target"
assert_contains "$output" "would never flush ruleset"

echo "install dry-run checks passed"
