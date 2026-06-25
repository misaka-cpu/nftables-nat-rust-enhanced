# NAT Check-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe `nat --check-only` path that generates and syntax-checks nftables rules without applying them or changing host forwarding state.

**Architecture:** CLI flags live in `nat-common::Args`. `nat-cli` branches before `global_prepare()` when `--check-only` is set, reuses the normal script generator, writes to an explicit output path or a temp path, then invokes an injectable nft binary with `-c -f`.

**Tech Stack:** Rust, clap, existing `nat-common` config types, existing `nat-cli` script generator, nftables `nft -c -f`.

---

## Files

- Modify: `nat-common/src/lib.rs`
  - Add `Args.check_only` and `Args.output_script`.
  - Add a focused clap parsing test.
- Modify: `nat-cli/src/main.rs`
  - Branch to check-only before `global_prepare()`.
  - Add `run_check_only`, `run_check_only_with`, and a small shared script-building helper.
  - Add tests that use a fake nft binary and temporary config files.
- No install/service files change in this plan.

## Task 1: CLI flags

**Files:**
- Modify: `nat-common/src/lib.rs`

- [ ] **Step 1: Write the failing parser test**

Add this test inside the existing `#[cfg(test)] mod tests` in `nat-common/src/lib.rs`:

```rust
#[test]
fn args_parse_check_only_and_output_script() {
    let args = Args::try_parse_from([
        "nat",
        "--toml",
        "/tmp/nat.toml",
        "--check-only",
        "--output-script",
        "/tmp/nat-preview.nft",
    ])
    .unwrap();

    assert!(args.check_only);
    assert_eq!(args.output_script.as_deref(), Some("/tmp/nat-preview.nft"));
    assert_eq!(args.toml.as_deref(), Some("/tmp/nat.toml"));
}
```

- [ ] **Step 2: Run the test and confirm RED**

Run:

```bash
cargo test -p nat-common args_parse_check_only_and_output_script
```

Expected: compile failure because `Args` has no `check_only` or `output_script` fields yet.

- [ ] **Step 3: Add the minimal Args fields**

In `nat-common/src/lib.rs`, extend `pub struct Args`:

```rust
    /// 只生成并检查 nftables 脚本，不应用规则
    #[arg(long, help = "只生成并检查 nftables 脚本，不应用规则")]
    pub check_only: bool,
    /// check-only 模式下输出生成脚本的路径
    #[arg(
        long,
        value_name = "SCRIPT_PATH",
        requires = "check_only",
        help = "check-only 模式下输出生成脚本的路径"
    )]
    pub output_script: Option<String>,
```

- [ ] **Step 4: Run the test and confirm GREEN**

Run:

```bash
cargo test -p nat-common args_parse_check_only_and_output_script
```

Expected: one test passes.

- [ ] **Step 5: Commit**

```bash
git add nat-common/src/lib.rs
git commit -m "feat: add nat check-only cli flags"
```

## Task 2: Check-only execution path

**Files:**
- Modify: `nat-cli/src/main.rs`

- [ ] **Step 1: Write the failing check-only test**

Add a new `#[cfg(test)] mod check_only_tests` near the existing test modules in `nat-cli/src/main.rs`. The test should create:

- a temp `nat.toml`
- a temp `allow.txt`
- a fake `nft` shell script that records its arguments
- an output path for the generated script

The core assertions:

```rust
assert!(run_check_only_with(&args, fake_nft.path()).is_ok());
assert!(output_script.exists());
let nft_calls = std::fs::read_to_string(&calls_path).unwrap();
assert!(nft_calls.contains("-c -f"));
assert!(!nft_calls.contains(" nft -f "));
let script = std::fs::read_to_string(&output_script).unwrap();
assert!(script.contains("ip saddr"));
assert!(script.contains("203.0.113.10"));
```

- [ ] **Step 2: Run the test and confirm RED**

Run:

```bash
cargo test -p nat-cli check_only_writes_script_and_runs_nft_check_only
```

Expected: compile failure because `run_check_only_with` does not exist.

- [ ] **Step 3: Implement the minimal branch and helper**

In `main()`, branch before the normal parse/prepare/loop path:

```rust
    if args.check_only {
        return Ok(run_check_only(&args)?);
    }
```

Implement helpers:

```rust
pub(crate) fn run_check_only(args: &Args) -> Result<(), io::Error> {
    run_check_only_with(args, "/usr/sbin/nft")
}
```

`run_check_only_with` should:

1. parse config through `parse_conf(args)`;
2. load runtime config through `load_runtime_config(args)`;
