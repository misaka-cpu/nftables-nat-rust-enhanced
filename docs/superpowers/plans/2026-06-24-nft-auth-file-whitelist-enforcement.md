# NFT Auth File Whitelist Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add file-based authenticated source whitelist input to `nftables-nat-rust`, allowing `/var/lib/nft-auth-whitelist/allow.txt` to restrict only NAT-managed forwarded ports.

**Architecture:** Keep `nft-auth-whitelist` responsible for authentication and allow-list delivery. Add `dynamic_whitelist.file_sources` to the NAT project, parse each configured file through the same IP/CIDR validation used by static access control, merge file entries with existing DDNS dynamic whitelist entries, then reuse the existing whitelist DNAT rule generation path. Firewall mutation remains only inside the NAT project's existing managed tables and safe apply flow.

**Tech Stack:** Rust 2024 workspace, `nat-common`, `nat-cli`, TOML config via `serde`/`toml`, nftables script generation, standard-library file IO, existing `ipnetwork` validation.

---

## File structure

- Modify `nat-common/src/lib.rs`
  - Add `DynamicWhitelistConfig.file_sources`.
  - Keep default behavior unchanged with an empty list.
  - Validate configured paths are not blank.
  - Make `validate_access_entry` reusable inside the crate.
  - Add TOML parsing and validation tests.

- Modify `nat-common/src/dynamic_whitelist.rs`
  - Add file-source loading helpers.
  - Treat missing files as empty contributions with warnings.
  - Return errors for invalid entries and non-missing read errors.
  - Deduplicate and sort entries with `BTreeSet`.
  - Add unit tests.

- Modify `nat-cli/src/main.rs`
  - Merge DDNS dynamic whitelist entries and file-source entries before calling `access_config_with_dynamic_whitelist`.
  - Handle file-source errors in the daemon loop by keeping the previously applied rules.
  - Propagate file-source errors from `refresh_once`.
  - Add rule generation tests.

- Modify `nat.toml`
  - Add commented sample `file_sources`.

- Modify `README.md`
  - Document `dynamic_whitelist.file_sources` and the nft-auth integration boundary.

---

### Task 1: Add `dynamic_whitelist.file_sources` config

**Files:**
- Modify: `nat-common/src/lib.rs`

- [ ] **Step 1: Write failing config tests**

Add these tests inside the existing `#[cfg(test)] mod tests` in `nat-common/src/lib.rs` near the current dynamic whitelist tests:

```rust
#[test]
fn dynamic_whitelist_defaults_file_sources_empty() {
    let config = TomlConfig::from_toml_str("rules = []").unwrap_or_else(|e| panic!("{e}"));
    assert!(config.dynamic_whitelist.file_sources.is_empty());
}

#[test]
fn dynamic_whitelist_parses_file_sources() {
    let config = TomlConfig::from_toml_str(
        r#"
rules = []

[dynamic_whitelist]
enabled = true
file_sources = ["/var/lib/nft-auth-whitelist/allow.txt"]
"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(config.dynamic_whitelist.enabled);
    assert_eq!(
        config.dynamic_whitelist.file_sources,
        vec!["/var/lib/nft-auth-whitelist/allow.txt"]
    );
}

#[test]
fn dynamic_whitelist_rejects_blank_file_source() {
    let err = TomlConfig::from_toml_str(
        r#"
rules = []

[dynamic_whitelist]
enabled = true
file_sources = [" "]
"#,
    )
    .unwrap_err();

    assert!(err.contains("dynamic_whitelist.file_sources[1]"));
}
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-common dynamic_whitelist_defaults_file_sources_empty dynamic_whitelist_parses_file_sources dynamic_whitelist_rejects_blank_file_source
```

Expected: compile failure mentioning `file_sources` is not a field on `DynamicWhitelistConfig`.

- [ ] **Step 3: Add the config field, default, and validation**

In `nat-common/src/lib.rs`, replace the current `DynamicWhitelistConfig` struct and its `Default` impl with:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicWhitelistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dynamic_whitelist_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub use_last_good_on_dns_failure: bool,
    #[serde(default = "default_true")]
    pub resolve_ipv4: bool,
    #[serde(default)]
    pub resolve_ipv6: bool,
    #[serde(default = "default_true")]
    pub notify_on_change: bool,
    #[serde(default = "default_dynamic_whitelist_state_file")]
    pub state_file: String,
    #[serde(default = "default_dynamic_whitelist_cidr_expand_ipv4")]
    pub cidr_expand_ipv4: u8,
    #[serde(default)]
    pub file_sources: Vec<String>,
    #[serde(default)]
    pub domains: Vec<DynamicWhitelistDomainConfig>,
}

impl Default for DynamicWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_interval_seconds: default_dynamic_whitelist_refresh_interval_seconds(),
            use_last_good_on_dns_failure: true,
            resolve_ipv4: true,
            resolve_ipv6: false,
            notify_on_change: true,
            state_file: default_dynamic_whitelist_state_file(),
            cidr_expand_ipv4: default_dynamic_whitelist_cidr_expand_ipv4(),
            file_sources: Vec::new(),
            domains: Vec::new(),
        }
    }
}
```

In `impl DynamicWhitelistConfig`, add this validation before validating domains:

```rust
for (idx, path) in self.file_sources.iter().enumerate() {
    if path.trim().is_empty() {
        return Err(format!(
            "dynamic_whitelist.file_sources[{}] 不能为空",
            idx + 1
        ));
    }
}
```

Change the validation helper signature so sibling modules can reuse it:

```rust
pub(crate) fn validate_access_entry(entry: &str) -> Result<(), String> {
    if entry.trim().is_empty() {
        return Err("access_control entries 不能为空".to_string());
    }
    if entry.parse::<IpAddr>().is_ok() || entry.parse::<ipnetwork::IpNetwork>().is_ok() {
        return Ok(());
    }
    Err(format!(
        "access_control entry 只支持 IP/CIDR，不支持域名或非法值: {entry}"
    ))
}
```

- [ ] **Step 4: Run the focused tests and confirm they pass**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-common dynamic_whitelist_defaults_file_sources_empty dynamic_whitelist_parses_file_sources dynamic_whitelist_rejects_blank_file_source
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n git add nat-common/src/lib.rs
sudo -n git commit -m feat:dynamic-whitelist-file-source-config
```

Expected: one commit containing only `nat-common/src/lib.rs`.

---

### Task 2: Parse file-source allow-list entries in `nat-common`

**Files:**
- Modify: `nat-common/src/dynamic_whitelist.rs`

- [ ] **Step 1: Write failing file-source parser tests**

Add these tests inside the existing test module in `nat-common/src/dynamic_whitelist.rs`:

```rust
#[test]
fn file_sources_parse_ip_cidr_ipv6_comments_and_blanks() {
    let path = temp_path("file-source-parse");
    fs::write(
        &path,
        "\n# comment\n203.0.113.10\n203.0.113.0/24\n2001:db8::1\n203.0.113.10\n",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let sources = read_file_sources(&[path.to_string_lossy().to_string()])
        .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        sources,
        vec!["2001:db8::1", "203.0.113.0/24", "203.0.113.10"]
    );
    let _ = fs::remove_file(path);
}

#[test]
fn file_sources_missing_file_contributes_empty() {
    let path = temp_path("file-source-missing");
    let sources = read_file_sources(&[path.to_string_lossy().to_string()])
        .unwrap_or_else(|e| panic!("{e}"));

    assert!(sources.is_empty());
}

#[test]
fn file_sources_reject_invalid_entry() {
    let path = temp_path("file-source-invalid");
    fs::write(&path, "example.com\n").unwrap_or_else(|e| panic!("{e}"));

    let err = read_file_sources(&[path.to_string_lossy().to_string()]).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("example.com"));
    let _ = fs::remove_file(path);
}

#[test]
fn file_sources_read_error_is_returned() {
    let path = temp_path("file-source-directory");
    fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));

    let err = read_file_sources(&[path.to_string_lossy().to_string()]).unwrap_err();

    assert_ne!(err.kind(), io::ErrorKind::NotFound);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn file_sources_disabled_config_returns_empty_without_reading() {
    let config = DynamicWhitelistConfig {
        enabled: false,
        file_sources: vec!["/path/that/does/not/exist".to_string()],
        ..Default::default()
    };

    let sources = file_sources_for_config(&config).unwrap_or_else(|e| panic!("{e}"));

    assert!(sources.is_empty());
}
```

Add `use std::fs;` to the existing test imports if it is not already present.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-common file_sources_
```

Expected: compile failure mentioning `read_file_sources` or `file_sources_for_config` is not found.

- [ ] **Step 3: Implement the file-source loader**

At the top of `nat-common/src/dynamic_whitelist.rs`, change the crate import to:

```rust
use crate::{DynamicWhitelistConfig, atomic, validate_access_entry};
```

Add these functions after `effective_sources_for_config`:

```rust
pub fn file_sources_for_config(config: &DynamicWhitelistConfig) -> io::Result<Vec<String>> {
    if !config.enabled {
        return Ok(Vec::new());
    }
    read_file_sources(&config.file_sources)
}

pub fn read_file_sources(paths: &[String]) -> io::Result<Vec<String>> {
    let mut values = BTreeSet::new();
    for path in paths {
        let path = path.trim();
        if path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dynamic whitelist file source path is empty",
            ));
        }

        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log::warn!("dynamic whitelist file source not found ({path}); no entries loaded");
                continue;
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("dynamic whitelist file source read failed ({path}): {e}"),
                ));
            }
        };

        let before = values.len();
        for (line_idx, raw_line) in content.lines().enumerate() {
            let entry = raw_line.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            validate_access_entry(entry).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "dynamic whitelist file source {path}:{} invalid entry {entry:?}: {e}",
                        line_idx + 1
                    ),
                )
            })?;
            values.insert(entry.to_string());
        }

        if values.len() == before {
            log::warn!("dynamic whitelist file source is empty ({path})");
        }
    }

    Ok(values.into_iter().collect())
}
```

- [ ] **Step 4: Run focused parser tests and existing dynamic whitelist tests**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-common file_sources_
sudo -n cargo test -p nat-common dynamic_whitelist
```

Expected: all tests pass.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n git add nat-common/src/dynamic_whitelist.rs
sudo -n git commit -m feat:parse-dynamic-whitelist-file-sources
```

Expected: one commit containing only `nat-common/src/dynamic_whitelist.rs`.

---

### Task 3: Wire file sources into NAT rule generation paths

**Files:**
- Modify: `nat-cli/src/main.rs`

- [ ] **Step 1: Write failing integration-style rule tests**

Add these helper functions inside the existing test module in `nat-cli/src/main.rs`:

```rust
fn temp_file_source_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|e| panic!("{e}"))
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nat-file-whitelist-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_file_source(name: &str, body: &str) -> std::path::PathBuf {
    let dir = temp_file_source_dir(name);
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let path = dir.join("allow.txt");
    fs::write(&path, body).unwrap_or_else(|e| panic!("{e}"));
    path
}

fn single_ipv4_tcp_cell() -> Vec<config::RuntimeCell> {
    vec![config::RuntimeCell::Rule(nat_common::NftCell::Single {
        enabled: true,
        sport: 30080,
        dport: 80,
        domain: "93.184.216.34".to_string(),
        protocol: nat_common::Protocol::Tcp,
        ip_version: nat_common::IpVersion::V4,
        snat_ip: None,
        comment: None,
        quota_enabled: false,
        quota_bytes: 0,
        quota_period: nat_common::QuotaPeriod::default(),
        quota_action: nat_common::QuotaAction::default(),
    })]
}
```

Add these tests near the existing dynamic whitelist rule generation tests:

```rust
#[test]
fn file_whitelist_source_generates_saddr_match() {
    let path = write_file_source("saddr", "203.0.113.10\n");
    let mut dynamic_config = DynamicWhitelistConfig {
        enabled: true,
        ..Default::default()
    };
    dynamic_config.file_sources = vec![path.to_string_lossy().to_string()];

    let sources = dynamic_whitelist_effective_sources(
        &dynamic_config,
        &DynamicWhitelistState::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(sources, vec!["203.0.113.10"]);

    let access = nat_common::AccessControlConfig {
        mode: nat_common::AccessControlMode::Whitelist,
        entries: Vec::new(),
    };
    let effective = access_config_with_dynamic_whitelist(&access, &sources);
    let script = build_new_script(
        &single_ipv4_tcp_cell(),
        &DnsConfig::default(),
        &effective,
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &ResolutionLog::new(),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(script.contains("ip saddr { 203.0.113.10 } tcp dport 30080 counter dnat"));
    assert!(!script.contains("ct state new tcp dport 30080 counter dnat"));
    let _ = fs::remove_dir_all(path.parent().unwrap_or_else(|| panic!("missing parent")));
}

#[test]
fn file_whitelist_source_merges_with_static_entries() {
    let path = write_file_source("static-merge", "203.0.113.10\n");
    let mut dynamic_config = DynamicWhitelistConfig {
        enabled: true,
        ..Default::default()
    };
    dynamic_config.file_sources = vec![path.to_string_lossy().to_string()];

    let sources = dynamic_whitelist_effective_sources(
        &dynamic_config,
        &DynamicWhitelistState::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let access = nat_common::AccessControlConfig {
        mode: nat_common::AccessControlMode::Whitelist,
        entries: vec!["198.51.100.20".to_string()],
    };
    let effective = access_config_with_dynamic_whitelist(&access, &sources);
    let script = build_new_script(
        &single_ipv4_tcp_cell(),
        &DnsConfig::default(),
        &effective,
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &ResolutionLog::new(),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(script.contains("ip saddr { 198.51.100.20, 203.0.113.10 } tcp dport 30080 counter dnat"));
    let _ = fs::remove_dir_all(path.parent().unwrap_or_else(|| panic!("missing parent")));
}

#[test]
fn empty_file_whitelist_keeps_forward_closed() {
    let path = write_file_source("empty", "\n# no entries\n");
    let mut dynamic_config = DynamicWhitelistConfig {
        enabled: true,
        ..Default::default()
    };
    dynamic_config.file_sources = vec![path.to_string_lossy().to_string()];

    let sources = dynamic_whitelist_effective_sources(
        &dynamic_config,
        &DynamicWhitelistState::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let access = nat_common::AccessControlConfig {
        mode: nat_common::AccessControlMode::Whitelist,
        entries: Vec::new(),
    };
    let effective = access_config_with_dynamic_whitelist(&access, &sources);
    let script = build_new_script(
        &single_ipv4_tcp_cell(),
        &DnsConfig::default(),
        &effective,
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &ResolutionLog::new(),
    )
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(!script.contains("counter dnat"));
    assert!(!script.contains("ip saddr {  }"));
    let _ = fs::remove_dir_all(path.parent().unwrap_or_else(|| panic!("missing parent")));
}

#[test]
fn file_whitelist_does_not_affect_access_control_off() {
    let path = write_file_source("access-off", "203.0.113.10\n");
    let mut dynamic_config = DynamicWhitelistConfig {
        enabled: true,
        ..Default::default()
    };
    dynamic_config.file_sources = vec![path.to_string_lossy().to_string()];

    let sources = dynamic_whitelist_effective_sources(
        &dynamic_config,
        &DynamicWhitelistState::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let access = nat_common::AccessControlConfig {
        mode: nat_common::AccessControlMode::Off,
        entries: Vec::new(),
    };
    let effective = access_config_with_dynamic_whitelist(&access, &sources);

    assert!(effective.entries.is_empty());
    let _ = fs::remove_dir_all(path.parent().unwrap_or_else(|| panic!("missing parent")));
}
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-cli file_whitelist
```

Expected: compile failure mentioning `dynamic_whitelist_effective_sources` is not found.

- [ ] **Step 3: Add merge helpers**

In `nat-cli/src/main.rs`, change:

```rust
use std::collections::HashMap;
```

to:

```rust
use std::collections::{BTreeSet, HashMap};
```

Add these helpers near `access_config_with_dynamic_whitelist`:

```rust
fn dynamic_whitelist_effective_sources(
    config: &DynamicWhitelistConfig,
    state: &DynamicWhitelistState,
) -> Result<Vec<String>, io::Error> {
    let ddns_sources = dynamic_whitelist::effective_sources_for_config(config, state);
    let file_sources = dynamic_whitelist::file_sources_for_config(config)?;
    Ok(merge_source_entries(&ddns_sources, &file_sources))
}

fn merge_source_entries(left: &[String], right: &[String]) -> Vec<String> {
    let mut merged = BTreeSet::new();
    for entry in left {
        merged.insert(entry.clone());
    }
    for entry in right {
        merged.insert(entry.clone());
    }
    merged.into_iter().collect()
}
```

- [ ] **Step 4: Replace both existing dynamic whitelist source calculations**

In the daemon loop, replace:

```rust
let dynamic_whitelist_ips = dynamic_whitelist::effective_sources_for_config(
    &dynamic_whitelist_config,
    &dynamic_whitelist_state,
);
```

with:

```rust
let dynamic_whitelist_ips = match dynamic_whitelist_effective_sources(
    &dynamic_whitelist_config,
    &dynamic_whitelist_state,
) {
    Ok(ips) => ips,
    Err(e) => {
        error!(
            "读取 dynamic_whitelist file_sources 失败，保持上一版已应用规则并等待下一次刷新: {e}"
        );
        sleep(next_loop_sleep_with_dynamic_whitelist(
            refresh_interval,
            &stats_config,
            last_ddns_refresh,
            last_stats_collect,
            Local::now(),
            DynamicWhitelistSleepContext {
                config: &dynamic_whitelist_config,
                interval_seconds: dynamic_whitelist_interval,
                last_refresh: last_dynamic_whitelist_refresh,
            },
        ));
        continue;
    }
};
```

In `refresh_once`, replace:

```rust
let dynamic_whitelist_ips = dynamic_whitelist::effective_sources_for_config(
    &runtime_config.dynamic_whitelist,
    &dynamic_whitelist_state,
);
```

with:

```rust
let dynamic_whitelist_ips = dynamic_whitelist_effective_sources(
    &runtime_config.dynamic_whitelist,
    &dynamic_whitelist_state,
)?;
```

- [ ] **Step 5: Run focused rule tests**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-cli file_whitelist
sudo -n cargo test -p nat-cli dynamic_whitelist
```

Expected: all focused tests pass.

- [ ] **Step 6: Commit Task 3**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n git add nat-cli/src/main.rs
sudo -n git commit -m feat:wire-file-whitelist-into-nat-rules
```

Expected: one commit containing only `nat-cli/src/main.rs`.

---

### Task 4: Document the file source option

**Files:**
- Modify: `nat.toml`
- Modify: `README.md`

- [ ] **Step 1: Update sample config**

In `nat.toml`, under `[dynamic_whitelist]`, add:

```toml
# Optional authenticated source whitelist files, for example the receive-side
# output of nft-auth-whitelist. One IP/CIDR per line; blank lines and full-line
# comments are ignored.
# file_sources = ["/var/lib/nft-auth-whitelist/allow.txt"]
```

- [ ] **Step 2: Update README feature description**

In `README.md`, update the `dynamic_whitelist` bullet to include:

```markdown
- `dynamic_whitelist.file_sources`：读取本机文件中的来源 IP/CIDR，并入来源白名单；适合接入 `nft-auth-whitelist` 在 receive 端生成的 `/var/lib/nft-auth-whitelist/allow.txt`。只作用于本项目管理的转发端口，不保护本机 SSH 或其它本机监听端口。
```

Also update the troubleshooting section near the whitelist note with:

```markdown
- **nft-auth 白名单未生效**：确认 `[access_control] mode = "whitelist"`，`[dynamic_whitelist] enabled = true`，并且 `dynamic_whitelist.file_sources` 指向 receive 端写出的 `allow.txt`。文件为空或无有效条目时不会打开转发端口。
```

- [ ] **Step 3: Run documentation-adjacent checks**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test -p nat-common dynamic_whitelist_parses_file_sources
```

Expected: the sample-related config behavior still parses.

- [ ] **Step 4: Commit Task 4**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n git add nat.toml README.md
sudo -n git commit -m docs:document-nft-auth-file-sources
```

Expected: one commit containing only docs and sample config.

---

### Task 5: Full verification and local handoff

**Files:**
- No new source edits unless verification exposes a bug.

- [ ] **Step 1: Format check**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo fmt --all -- --check
```

Expected: command exits 0. If it reports formatting drift, run `sudo -n cargo fmt --all`, inspect the diff, then commit only the formatting for files changed in Tasks 1-4.

- [ ] **Step 2: Run workspace tests**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 3: Run clippy if available**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n cargo clippy --workspace --all-targets -- -D warnings
```

Expected: command exits 0. If the Rust toolchain lacks clippy, record the exact missing-component message and do not claim clippy passed.

- [ ] **Step 4: Inspect final diff**

Run:

```bash
cd /opt/codex-work/nftables-nat-rust
sudo -n git status --short --branch
sudo -n git log --oneline -6
```

Expected:

- branch is `main`;
- branch is ahead of origin by the design commit, plan commit, and implementation commits;
- no unstaged source changes remain.

- [ ] **Step 5: Stop before po0 apply**

Report the local evidence and stop before any real host firewall mutation. The next real-host step must be a po0 dry-run or nft check of generated rules, not a direct apply.

Expected handoff sentence:

```text
Local implementation is ready for po0 dry-run. I have not changed po0 nftables or restarted NAT services.
```

---

## Plan self-review

- Spec coverage: `file_sources` config, parsing, fail-closed behavior, whitelist-mode merge, empty/missing file behavior, docs, and local verification are covered.
- Type consistency: `DynamicWhitelistConfig.file_sources`, `dynamic_whitelist::file_sources_for_config`, `read_file_sources`, and `dynamic_whitelist_effective_sources` are named consistently across tasks.
- Scope check: the plan only changes the NAT project and does not add local input protection, SSH protection, or `nft-auth-whitelist` firewall ownership.
