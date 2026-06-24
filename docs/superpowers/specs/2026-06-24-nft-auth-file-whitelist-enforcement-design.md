# NFT Auth File Whitelist Enforcement Design

## Status

Approved design direction on 2026-06-24: protect only forwarded ports managed by the NAT project. Do not protect local input ports in this phase.

## Goal

Allow `nft-auth-whitelist` to feed authenticated source CIDRs into `nftables-nat-rust`, so the NAT project only generates DNAT rules for authenticated sources.

## Scope

In scope:

- Read `/var/lib/nft-auth-whitelist/allow.txt` on the po0 host.
- Merge valid entries from that file into NAT source whitelist entries.
- Apply the merged whitelist only when `access_control.mode = "whitelist"`.
- Keep the NAT project as the only owner of NAT and forwarding nftables rules.
- Fail closed when the auth whitelist file is missing, empty, unreadable, or invalid.
- Test rule generation before any real host apply.

Out of scope:

- Local input port protection on po0.
- SSH management port protection.
- Direct nftables rule ownership in `nft-auth-whitelist`.
- Firewall changes outside the NAT project's managed tables.

## Current project context

`nft-auth-whitelist` already authenticates users, signs allow-list snapshots, pushes them to receive hosts, and writes `allow.txt`.

`nftables-nat-rust` already owns forwarding rules and has:

- `AccessControlConfig { mode, entries }` for source whitelist and blacklist policy.
- `DynamicWhitelistConfig` for DDNS-derived source entries.
- `dynamic_whitelist::effective_sources_for_config(...)`.
- `access_config_with_dynamic_whitelist(...)`, which merges dynamic source entries into `access_control.entries` only in whitelist mode.
- DNAT rule generation that adds source conditions through `access_condition(...)`.
- Safe apply behavior: `nft -c`, managed table backup, apply, and managed table rollback.

The smallest safe change is to add an authenticated file source to the existing dynamic whitelist path, not to create a second firewall owner.

## Configuration design

Extend `[dynamic_whitelist]` with one optional file input list:

```toml
[dynamic_whitelist]
enabled = true
file_sources = ["/var/lib/nft-auth-whitelist/allow.txt"]
```

Rules:

- Default is an empty `file_sources` list, preserving current behavior.
- File sources only participate when `dynamic_whitelist.enabled = true`.
- File sources only affect forwarding when `access_control.mode = "whitelist"`, matching current dynamic whitelist behavior.
- The implementation reads plain text files containing one IP or CIDR per line.
- Blank lines are ignored.
- Lines beginning with `#` are ignored.
- Inline comments are not supported. This keeps parsing simple and avoids accepting ambiguous input.
- Entries must pass the same validation path as `access_control.entries`.

The first real host configuration for po0 should be:

```toml
[access_control]
mode = "whitelist"
entries = []

[dynamic_whitelist]
enabled = true
file_sources = ["/var/lib/nft-auth-whitelist/allow.txt"]
```

## Data flow

1. RFC JP authenticates a user.
2. RFC JP pushes a signed allow-list snapshot to po0.
3. po0 `nft-auth-receive` verifies the snapshot and writes `/var/lib/nft-auth-whitelist/allow.txt`.
4. `nftables-nat-rust` reads configured file sources during its normal rule build path.
5. Valid file entries are merged with existing dynamic whitelist effective sources.
6. The merged list is merged into `access_control.entries` in whitelist mode.
7. DNAT rules are generated with `ip saddr { ... }` or `ip6 saddr { ... }`.
8. Non-matching source IPs do not match the DNAT rules, so forwarded ports are not exposed to them.

## Failure behavior

The enforcement side must fail closed:

- Missing file: log a warning and contribute no entries.
- Empty file: log a warning and contribute no entries.
- Unreadable file: return an error before applying rules.
- Invalid entry: return an error before applying rules.
- Mixed IPv4 and IPv6 entries are allowed; existing family filtering decides which entries appear in `ip` and `ip6` rules.

When `access_control.mode = "whitelist"` and the merged whitelist is empty, existing behavior already means no source condition can be generated and forwarding rules are skipped. The implementation should preserve that behavior and keep the existing warning path clear.

## Testing strategy

Unit tests:

- Parse a file with IPv4, IPv4 CIDR, IPv6, blank lines, and full-line comments.
- Reject invalid entries.
- Treat missing file as an empty contribution.
- Return an error for unreadable file when the test platform can model it reliably.
- Deduplicate file entries while keeping deterministic order.

Integration-style rule generation tests:

- With `access_control.mode = "whitelist"` and file source `203.0.113.10`, generated DNAT rules include `ip saddr { 203.0.113.10 }`.
- With static whitelist plus file source, generated DNAT rules contain both entries.
- With empty file source and empty static whitelist, forwarded rules are not opened.
- With `access_control.mode = "off"`, file sources do not add source restrictions.

Real host validation sequence:

1. Build and test on the local Debian development machine.
2. Copy the NAT binary/config candidate to po0 only after local tests pass.
3. On po0, run NAT dry-run or nft check first.
4. Confirm generated rules include the authenticated test source and do not include an unrestricted DNAT rule.
5. After explicit approval, apply rules on po0.
6. Test from a whitelisted source that the forwarded port works.
7. Test from a non-whitelisted source that the forwarded port does not match the DNAT rule.

## Rollout guardrails

- Do not change po0 nftables until dry-run output is reviewed.
- Do not protect local input ports in this phase.
- Do not add `nft-auth-whitelist` hooks that execute NAT reloads.
- Do not flush the full nftables ruleset.
- Keep all firewall mutations inside `nftables-nat-rust` managed tables.
- Keep temporary SSH keys until real host testing is complete, then remove them explicitly.

## Acceptance criteria

- The NAT project can read `/var/lib/nft-auth-whitelist/allow.txt` as a configured dynamic whitelist file source.
- Invalid auth whitelist content blocks apply before nftables changes.
- Empty or missing auth whitelist content does not open forwarded ports.
- Generated DNAT rules include source CIDR matches for authenticated entries.
- Existing DDNS dynamic whitelist tests still pass.
- Existing safe apply and rollback behavior remains unchanged.
