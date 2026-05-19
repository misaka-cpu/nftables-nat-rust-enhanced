# TODO（暂缓项）

本文件记录在「最终稳定版架构体检」中被识别、但本次不修复的低优先级改进项。
列在这里 = 现阶段已被讨论并主动放弃；下次迭代或重构时优先考虑。

不属于本文件的内容：
- 与 nft 规则生成、safe apply、quota 自动禁用核心逻辑、last-good 容错、`egress_control` / GeoIP / access_control 组合策略相关的功能性变更 —— 这些是稳定版的契约，不能在 TODO 顺手改动
- 一键更新流程

## 1. `run_quota_check` 自动写配置前补 `backup_config`

**现状**：当 quota 检测到某条规则超额需要自动禁用时，`nat-cli/src/main.rs::run_quota_check` 直接以 `fs::write(toml_path, …)` 覆盖 `/etc/nat.toml`。CLI 入口（`menu.rs`）改配置都会先 `backup_config(path)` 备份到 `/etc/nftables-nat/backups/`，但 nat.service 自动禁用走的是这条裸 write 路径，不会落备份。

**风险**：低。审计日志（`quota.exceeded` + `rule.disable.quota`）已经能完整还原变更，规则也只是 `enabled = false` 而非删除。但与 CLI 行为不对称，未来如果 quota 引入更激进的改写（例如自动重置 `quota_bytes`）就会失去回退点。

**计划**：抽出共享的 `safe_write_config(path)` 工具函数，调用方先备份、再写入；让 `run_quota_check` 与 `menu.rs::save_toml_config` 共用同一条落盘路径。

---

## 2. `nat-cli/src/main.rs` 拆分模块

**现状**：单文件 3701 行，包含主循环、安全 apply 流水线、quota 检查、Telegram HTTP、`safe_apply_tests` 与 `build_new_script` 的大量场景测试。

**风险**：低（编译干净、测试齐全），但已经接近合理可读上限，新增功能容易让单文件继续膨胀。

**计划**（按依赖顺序）：
- `nat-cli/src/apply.rs`：`apply_nft_script` / `check_nft_script` / `backup_current_ruleset` / `backup_managed_tables` / `rollback_managed_tables` + 现有 `safe_apply_tests`
- `nat-cli/src/quota_loop.rs`：`should_run_quota_check` / `run_quota_check` + 相关 audit/Telegram 调用
- `nat-cli/src/build_script.rs`：`build_new_script` / `build_mss_clamp_rules` / `build_geoip_*` + `forward_summary_from` / `ForwardRuleSummary`
- 保持 `main.rs` 只负责 `main` / `handle_loop` / `refresh_once` / `parse_conf`

拆分时**不改任何行为**，纯位置迁移，测试模块跟随被测函数。

---

## 3. `latest_script` 改为 hash-based 判断

**现状**：`handle_loop` 用「整段字符串相等」（`if script != latest_script`）判断是否需要应用新规则。生成顺序当前是稳定的（`nat_cells` 是 `Vec`、各子规则按 `summaries` 顺序拼接），所以可重入。

**风险**：信息性。一旦未来 build 路径里引入 `HashMap`、并行化、或可选 GeoIP set 内嵌等非确定顺序的步骤，「字符串相等」就会误判 `script` 变动，导致每轮都 reapply，触发不必要的 `nft -f` + 备份。

**计划**：把 `latest_script: String` 改成 `latest_script_hash: Option<u64>`（或 `[u8; 32]` SHA256），落盘对比时计算并存哈希，规则字符串只在需要重写文件时落盘一次。这一步**只改判断逻辑**，不改生成内容，与 last-good 缓存里的 `last_good_nft_hash` 字段对齐。

---

## 备注

- 上述三项均不属于本次稳定版发布门槛。
- 实施前请回看本文件，确认现状描述仍然成立。
