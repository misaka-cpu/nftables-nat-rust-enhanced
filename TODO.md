# TODO（暂缓项）

本文件记录在「稳定版架构体检」中被识别、但本轮不修复的低优先级改进项。
列在这里 = 现阶段已被讨论并主动放弃；下次迭代或重构时优先考虑。

不属于本文件的内容：
- 与 nft 规则生成、safe apply、quota 自动禁用核心逻辑、last-good 容错、`egress_control` / GeoIP / access_control 组合策略相关的功能性变更 —— 这些是稳定版的契约，不能在 TODO 顺手改动
- 一键更新流程

---

## ✅ 已在 v0.4.1 落地的项

记录在此处便于回看，不再纳入"待办"。

- `run_quota_check` 自动禁用规则写回 `/etc/nat.toml` 前会先复制到 `/etc/nftables-nat/backups/config/nat.toml.quota-auto-disable-YYYYmmdd-HHMMSS.bak`；备份失败 → 跳过本轮写回，写入失败 → 备份保留。写入走临时文件 + rename 原子替换。新增 audit 事件 `quota.backup.create` / `quota.backup.fail` / `quota.auto_disable.write_ok` / `quota.auto_disable.write_fail` / `quota.auto_disable.skipped`。
- 子菜单返回逻辑：`20) 查看审计日志` 顶层不再叠加一次 `wait_enter_to_return`；`stats_menu → set_rule_quota_interactive` 在用户按 `0` 时返回 `MenuOutcome::Cancelled`，外层不会再要求按 Enter。
- CLI 时间显示统一为 `Asia/Shanghai` 24 小时制 `YYYY-MM-DD HH:MM:SS CST`，去掉 RFC3339 的 `T...` 与纳秒；JSON 状态文件 / audit log 内部仍保留 UTC RFC3339。
- `19) 高级网络设置 (SNAT / MSS clamp)` 新增 `6) 时间 / NTP 状态检查`：只查看，不默认改时间；启用 NTP 需要 y/N 二次确认。
- 规则改完后的提示加上"当前自动检测 / 刷新间隔"实际值 + "请等待一个检测周期后刷新"；连通性测试在 nft 未应用时显示 pending 提示。

---

## 1. `nat-cli/src/main.rs` 拆分模块

**现状**：单文件 ~3900 行（v0.4.1 新增 backup / atomic write 后又长了一些），包含主循环、安全 apply 流水线、quota 检查、Telegram HTTP、`safe_apply_tests` 与 `build_new_script` 的大量场景测试。

**风险**：低（编译干净、测试齐全），但已经接近合理可读上限，新增功能容易让单文件继续膨胀。

**计划**（按依赖顺序）：
- `nat-cli/src/apply.rs`：`apply_nft_script` / `check_nft_script` / `backup_current_ruleset` / `backup_managed_tables` / `rollback_managed_tables` + 现有 `safe_apply_tests`
- `nat-cli/src/quota_loop.rs`：`should_run_quota_check` / `run_quota_check` / `run_quota_check_with` / `backup_toml_for_quota_auto_disable` / `atomic_write_text_file` + 相关 audit/Telegram 调用 + v0.4.1 新增的 backup/atomic-write 测试
- `nat-cli/src/build_script.rs`：`build_new_script` / `build_mss_clamp_rules` / `build_geoip_*` + `forward_summary_from` / `ForwardRuleSummary`
- 保持 `main.rs` 只负责 `main` / `handle_loop` / `refresh_once` / `parse_conf`

拆分时**不改任何行为**，纯位置迁移，测试模块跟随被测函数。

---

## 2. `latest_script` 改为 hash-based 判断

**现状**：`handle_loop` 用「整段字符串相等」（`if script != latest_script`）判断是否需要应用新规则。生成顺序当前是稳定的（`nat_cells` 是 `Vec`、各子规则按 `summaries` 顺序拼接），所以可重入。

**风险**：信息性。一旦未来 build 路径里引入 `HashMap`、并行化、或可选 GeoIP set 内嵌等非确定顺序的步骤，「字符串相等」就会误判 `script` 变动，导致每轮都 reapply，触发不必要的 `nft -f` + 备份。

**计划**：把 `latest_script: String` 改成 `latest_script_hash: Option<u64>`（或 `[u8; 32]` SHA256），落盘对比时计算并存哈希，规则字符串只在需要重写文件时落盘一次。这一步**只改判断逻辑**，不改生成内容，与 last-good 缓存里的 `last_good_nft_hash` 字段对齐。

---

## 3. 统一 CLI / 服务侧的"安全写配置"路径

**现状**：v0.4.1 把 `run_quota_check` 加上了备份 + 原子写回，已经和 CLI 路径（`menu.rs::save_toml_config` → `backup_config(path)` → `fs::write`）行为对齐。但两条路径各自实现：CLI 用 `fs::write`，服务用 `atomic_write_text_file` + 显式备份目录命名。

**风险**：很低。两条路径的副作用各自经过测试。

**计划**：抽出共享的 `nat_common::safe_write::write_toml_safely(path, contents, backup_dir, audit, reason: &str)` 工具函数，统一备份命名规则与原子写入语义。CLI 的 `save_toml_config` 与服务侧的 quota 写回都走它，避免未来出现第三条不一致的写路径。

---

## 4. UI 时区配置项

**现状**：v0.4.1 把 CLI 时间显示硬编码到 `Asia/Shanghai` (UTC+8)。多数中文用户场景成立，但仍有少数边角场景（部分用户实际在 UTC+9 / UTC+8 之外）。

**风险**：信息性。

**计划**：引入 `[ui] timezone = "Asia/Shanghai"` / `time_format = "%Y-%m-%d %H:%M:%S"`，默认值保持现行行为；优先支持 IANA 时区名（chrono-tz），fallback 到固定偏移。这一步**不会改动状态文件内部时间存储**（仍 UTC RFC3339）。

---

## 备注

- 上述四项均不属于本轮 v0.4.1 发布门槛。
- 实施前请回看本文件，确认现状描述仍然成立。
