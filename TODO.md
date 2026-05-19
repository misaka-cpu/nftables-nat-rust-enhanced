# TODO（暂缓项）

本文件记录在历次「稳定版架构体检」中被识别、但本轮不修复的低优先级改进项。

> v0.4.x 系列已进入 **bugfix-only 阶段**：原则上不再加新功能，只修 bug + 文档对齐。
> 真正会动结构的改造请挪到 v0.5.0 计划。

不属于本文件的内容：
- 与 nft 规则生成、safe apply、quota 自动禁用核心逻辑、last-good 容错、`egress_control` / GeoIP / access_control 组合策略相关的功能性变更 —— 这些是稳定版的契约，不能在 TODO 顺手改动
- 一键更新流程

---

## ✅ 已落地的项（按版本归档）

> 不再纳入"待办"。出现在这里 = 已经在 main 分支生效，对应改动可在 git log 中查到。

### v0.4.1

- `run_quota_check` 自动禁用规则写回 `/etc/nat.toml` 前先复制到 `/etc/nftables-nat/backups/config/nat.toml.quota-auto-disable-YYYYmmdd-HHMMSS.bak`；备份失败 → 跳过本轮写回，写入失败 → 备份保留。写入走临时文件 + rename 原子替换。新增 audit 事件 `quota.backup.create` / `quota.backup.fail` / `quota.auto_disable.write_ok` / `quota.auto_disable.write_fail` / `quota.auto_disable.skipped`。
- 子菜单返回逻辑：`20) 查看审计日志` 顶层不再叠加一次 `wait_enter_to_return`；`stats_menu → set_rule_quota_interactive` 在用户按 `0` 时返回 `MenuOutcome::Cancelled`，外层不会再要求按 Enter。
- CLI 时间显示统一为 `Asia/Shanghai` 24 小时制 `YYYY-MM-DD HH:MM:SS CST`，去掉 RFC3339 的 `T...` 与纳秒；JSON 状态文件 / audit log 内部仍保留 UTC RFC3339。
- `19) 高级网络设置 (SNAT / MSS clamp)` 新增 `6) 时间 / NTP 状态检查`：只查看，不默认改时间；启用 NTP 需要 y/N 二次确认。
- 规则改完后的提示加上"当前自动检测 / 刷新间隔"实际值 + "请等待一个检测周期后刷新"；连通性测试在 nft 未应用时显示 pending 提示。

### v0.4.2

- 引入 `[ui] timezone` + `time_format` 配置（chrono-tz，支持 IANA 名，处理 DST）。
- 拓宽 nft 规则检测器：`detect_rule_in_nft_json` + `classify_nft_presence` 四档（Applied / Partial / Unconfirmed / NotApplied）；不再单看 counter。
- audit 日志 CLI 默认格式化展示，加子菜单切换原始 JSON。
- 时间 / NTP 页面重构为 4 项子菜单（查看 / 设 CLI 时区 / 显示 set-timezone 命令 / 尝试启用 NTP），全部需要二次确认。
- 主菜单标题简化为 `nft-nat-rust <version>`。

### v0.4.3

- `[ui].timezone` 改为**全 CLI 生效**：last-good 摘要 / quota 状态 / audit 格式化 / 测试连通性页面统一走 `format_cli_time_with(&config.ui)`；非法 timezone 在 `format_cli_time_with` 内部回退到默认时区，并通过 `from_toml_str` 阶段拒绝持久化。
- nft 规则检测加入 `NftRuleShape` 区分 Dnat / Redirect。Redirect 规则与 domain=`localhost` / `127.0.0.1` / `::1` 的 Single 规则不再被误判为 `Partial`，显示 `已应用 (redirect)`。
- Telegram curl 调用（server + CLI）强制 `--connect-timeout 5 --max-time 15`；新增 `sanitize_telegram_error` 兜底脱敏 bot_token，避免 stderr 透传。
- 主菜单 `14)` 改名为「最近来源 IP 观察（手动排查）」并明确说明当前不自动采集；提供 conntrack / nft list / journalctl 三条手动观察命令。
- 文档对齐：README 加 audit log logrotate 推荐配置、Docker v28 `ip filter FORWARD` 兼容说明；过时的 `v0.2.2` 版本示例改为 `v0.4.x` / `latest`。
- 杂项清理：删除空 `static/` 目录；`build_version()` 强制 `dev` 兜底，避免 `nat --version` 出空字符串。

---

## 待办（按风险 / 收益排序）

### 1. `nat-cli/src/main.rs` 拆分模块（v0.5.0 范围）

**现状**：单文件 ~4000 行，主循环、安全 apply、quota 检查、Telegram HTTP、`safe_apply_tests` 与 `build_new_script` 的大量场景测试都在一起。

**风险**：低（编译干净、测试齐全），但已经接近合理可读上限。

**计划**（按依赖顺序）：

- `nat-cli/src/apply.rs`：`apply_nft_script` / `check_nft_script` / `backup_current_ruleset` / `backup_managed_tables` / `rollback_managed_tables` + 现有 `safe_apply_tests`
- `nat-cli/src/quota_loop.rs`：`should_run_quota_check` / `run_quota_check` / `run_quota_check_with` / `backup_toml_for_quota_auto_disable` / `atomic_write_text_file` + 相关 audit/Telegram 调用 + 备份相关测试
- `nat-cli/src/build_script.rs`：`build_new_script` / `build_mss_clamp_rules` / `build_geoip_*` + `forward_summary_from` / `ForwardRuleSummary`
- `nat-cli/src/telegram_http.rs`：`send_telegram_http` / `build_telegram_curl_command` / `sanitize_telegram_error`
- 保留 `main.rs` 只负责 `main` / `handle_loop` / `refresh_once` / `parse_conf`

拆分时**不改任何行为**，纯位置迁移，测试模块跟随被测函数。

### 2. `latest_script` 改为 hash-based 判断（v0.5.0 范围）

**现状**：`handle_loop` 用「整段字符串相等」（`if script != latest_script`）判断是否需要应用新规则。生成顺序当前是稳定的（`nat_cells` 是 `Vec`、各子规则按 `summaries` 顺序拼接），所以可重入。

**风险**：信息性。一旦未来 build 路径里引入 `HashMap`、并行化、或可选 GeoIP set 内嵌等非确定顺序的步骤，「字符串相等」就会误判 `script` 变动，导致每轮都 reapply，触发不必要的 `nft -f` + 备份。

**计划**：把 `latest_script: String` 改成 `latest_script_hash: Option<u64>`（或 `[u8; 32]` SHA256），落盘对比时计算并存哈希，规则字符串只在需要重写文件时落盘一次。这一步**只改判断逻辑**，不改生成内容，与 last-good 缓存里的 `last_good_nft_hash` 字段对齐。

### 3. audit log 自轮转（v0.5.0 范围）

**现状**：audit log 默认写 `/var/log/nftables-nat-rust-audit.log`，append-only。文件可能无限增长。

**当前应对**：README 推荐 logrotate 配置；CLI 不自动轮转。

**计划**：在 audit 模块内部加 best-effort 自轮转（文件超过例如 10MB 时 rename 为 `.1`，并新建空文件）；失败仅 WARN，不阻塞主流程。不强求引入外部 logrotate。

### 4. apply 失败时不直接退出 nat.service（v0.5.0 范围）

**现状**：`apply_nft_script` 失败时 `handle_loop` 直接 `return Err(e)` → 进程 exit → systemd 按 `Restart=always RestartSec=60` 重启。如果用户配置导致 `nft -c` 持续失败，nat.service 会反复 fail-restart 刷 journal。

**计划**：把 "立即退出" 改成 "记录 audit + sleep 一个 refresh interval + 下一轮重试"。回滚已经在 `apply_nft_script_with` 内做了，主循环不必死掉。需要 careful，避免掩盖真正的不可恢复错误。

### 5. RuntimeConfig 携带 `ui`（v0.5.0 范围 / 可选）

**现状**：v0.4.3 在 menu.rs 全部按需 `load_toml_config(...).ui` 读取；`RuntimeConfig` 仍不携带 `ui`。

**风险**：信息性。

**计划**：把 `ui: UiConfig` 加入 `RuntimeConfig`，让 nat.service 主循环未来如果需要按 [ui] 渲染什么（例如 audit log 启动事件），也能直接拿到。当前没需求，暂缓。

---

## 备注

- 上述待办均**不**属于 v0.4.x bugfix-only 范围。
- 实施前请回看本文件，确认现状描述仍然成立。
