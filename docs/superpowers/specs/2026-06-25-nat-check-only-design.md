# NAT check-only CLI design

## Goal

Add a safe CLI path for pre-deployment validation of generated nftables rules. The command must let us test the `nft-auth-whitelist` file-source integration on a real host before applying rules.

## Assumptions

- The existing normal service path keeps its current behavior: parse config, prepare host state, generate rules, write the managed script, then run safe apply.
- The new path is for operators and deployment tests, not for `nat.service`.
- `nft -c -f <script>` is acceptable because it only validates nft syntax and does not load the ruleset.
- The command may write the generated script to a caller-chosen path under `/tmp` for inspection.
- It must not modify kernel forwarding settings, write `/etc/nftables-nat/nat-diy.nft`, create backups, run `nft -f`, update last-good state, or emit apply-success/apply-fail audit events.
- DNS-backed dynamic whitelist state is read from the existing state file but not refreshed, because resolving domains can write state/audit records and is not needed for the nft-auth file-source validation path.

## CLI behavior

Add two options:

- `--check-only`: generate the script and run nft syntax check, then exit.
- `--output-script <PATH>`: optional output path for generated script in check-only mode.

When `--check-only` is used:

1. Parse the selected legacy config or TOML config exactly like the normal path.
2. Load runtime config, including dynamic whitelist state and file-source entries.
3. Load existing DNS-backed dynamic whitelist state without refreshing domains or writing state.
4. Merge dynamic whitelist sources into access control exactly like normal refresh.
5. Build the nft script with the same generator used by normal refresh.
6. Write the generated script to `--output-script`, or to a temporary file if no output path is provided.
7. Run `/usr/sbin/nft -c -f <script>`.
8. Exit success only when generation and nft syntax check both succeed.

## Safety boundaries

The check-only path must not call:

- `global_prepare()`
- `prepare::check_and_prepare()`
- `apply_nft_script()`
- `nft -f`
- `refresh_dynamic_whitelist()`

This preserves the dry-run promise even on a production-like machine.

## Error handling

- Missing config remains an error.
- Invalid file-source content remains an error.
- Missing file-source paths continue contributing an empty list, preserving the existing fail-closed whitelist behavior.
- `nft -c` failure returns a non-zero CLI result with stderr context.

## Testing

Add unit/integration tests around the new helper using existing test patterns:

- check-only writes the generated script to the requested output path.
- check-only calls the injected nft binary with `-c -f` and never calls `-f` without `-c`.
- check-only rejects invalid dynamic whitelist file-source content before nft check.
- normal refresh/apply behavior remains covered by existing tests.
