# TODO（暂缓项 / 维护路线）

本文件记录在历次「稳定版架构体检」中被识别、但本轮不修复的低优先级改进项。

> v0.8.0 是 dynamic_whitelist 功能版本；v0.8.1 在其之上做 CLI 白名单 / 黑名单管理与动态 DDNS 来源白名单子菜单的展示层级优化，不改 nft / safe apply / 组合策略。后续仍保持 CLI-first / core-only：不恢复 WebUI / nat-console，不引入多用户架构 / 分布式 agent / 数据库存储，不做 DNS 供应商接口。
> 真正会动结构的改造请挪到独立 minor 版本规划，并先在本文件提案。

不属于本文件的内容：

- 与 nft 规则生成、safe apply、quota 自动禁用核心逻辑、last-good 容错、`egress_control` / GeoIP / access_control 组合策略相关的功能性变更 —— 这些是稳定版的契约，不能在 TODO 顺手改动
- 一键更新流程

---

## ✅ 已落地的项（按版本归档）

> 不再纳入"待办"。出现在这里 = 已经在 main 分支生效，对应改动可在 git log 中查到。

### v0.4.1

- `run_quota_check` 自动禁用规则写回 `/etc/nat.toml` 前先备份；备份失败跳过本轮写回；写入走临时文件 + rename 原子替换。
- 子菜单返回逻辑：`20) 查看审计日志` 与 `set_rule_quota_interactive` 的 `Enter` 叠加修复。
- CLI 时间显示统一为 `Asia/Shanghai` 24h 格式；JSON 内部仍 UTC RFC3339。
- 高级网络设置新增 `6) 时间 / NTP 状态检查`，只查看不默认改时间。
- 「请等待一个检测周期后刷新」+ 连通性测试 pending 提示。

### v0.4.2

- 引入 `[ui] timezone` + `time_format`（chrono-tz，IANA 名 + DST）。
- 拓宽 nft 规则检测器：`detect_rule_in_nft_json` + `classify_nft_presence` 四档。
- audit 日志 CLI 默认格式化展示，子菜单切换原始 JSON。
- 时间 / NTP 页面重构为 4 项子菜单，全部需要二次确认。
- 主菜单标题简化为 `nft-nat-rust <version>`。

### v0.4.3

- `[ui].timezone` 改为全 CLI 生效；非法 timezone 回退默认并拒绝持久化。
- `NftRuleShape` 区分 Dnat / Redirect，避免 localhost-Single / Redirect 被误判为 Partial。
- Telegram curl 强制 `--connect-timeout 5 --max-time 15`；`sanitize_telegram_error` 兜底脱敏 `bot_token`。
- 主菜单 `14)` 改名「最近来源 IP 观察（手动排查）」并明确不自动采集。
- 杂项：删空 `static/`；`build_version()` 强制 `dev` 兜底。

### v0.5.0 / v0.5.x

- 「查看当前转发规则」默认页面只显示规则核心信息 + 一行组合策略摘要 + 一行 last-good 摘要；详细诊断通过 `d` 入口展开。
- 「测试转发规则连通性」默认只显示简短外部测试提示；详细 `curl` / `nc` / SNI 示例通过 `h` 入口查看；按 `protocol` / `target` 分支生成示例。
- 高级网络设置子菜单合并：把分立的「查看组合策略详情」与「查看 last-good 状态缓存」合并为「查看全局诊断状态」。
- 「查看当前转发规则 → d」与「高级网络设置 → 查看全局诊断状态」共用同一份诊断渲染。

### v0.6.0

- **audit log 内置轻量轮转**：`audit` 配置新增 `rotate` / `max_size_mb` / `max_backups` 字段（旧配置默认 `true / 10MB / 3`）；超阈值时 `audit.log → audit.log.1 → audit.log.2 → …`，`max_backups=0` 时截断当前文件；任何 io 失败仅 WARN，不影响主流程；轮转后当前文件仍是一行 JSON。
- **统一 `safe_write_config`**：所有写 `/etc/nat.toml` 的生产路径——CLI 各子菜单、quota 自动禁用——都统一走「备份 → 临时文件 + fsync → rename → audit」。备份失败 / 写入失败 / rename 失败均保留旧文件并写 `config.write.fail`（带 `stage`）audit；成功写 `config.write.success`。audit detail 永不写入 `bot_token` / `chat_id`。
- **一键更新 latest 解析真实 tag**：CLI 选 latest 时通过 `curl -fsI` 解析 GitHub `releases/latest` 重定向，更新摘要直接显示真实版本号；解析失败回退显示 `latest` 并附带 warning，install.sh 行为不变。

### v0.6.1

- **保存提示按 reason 分流**：影响 nft 的 reason 仍显示完整 `nat.service` 自动应用提示；不影响 nft 的 `telegram.*` / `ui.*` / `audit.*` 改为简短提示，避免误导用户去 `systemctl restart nat`。
- **`latest_script` 改 hash-based**：`handle_loop` 不再用整字符串比较新旧 nft 脚本，改用 `nat_common::stable_script_hash`（FNV-1a 64-bit）。跨进程稳定，不依赖 `DefaultHasher` 随机种子；audit `apply.success` / `apply.fail` 新增 `script_hash` 字段；不引入新依赖；行为与字符串比较等价。

### v0.7.0

- **`nat-cli/src/main.rs` 拆分**：抽出 `apply.rs`（safe apply 全流程）、`runtime.rs`（主循环节奏 / Stats 采集 / resolution events audit 转写）、`quota_loop.rs`（quota 自动禁用循环）、`telegram.rs`（curl 超时 / 错误脱敏）；`main.rs` 保留入口与顶层流程。**只搬代码不改行为**，测试通过 `pub(crate) use` 引回搬出去的项。
- **`nat-cli/src/menu.rs` 拆分**：抽出 `menu/update.rs`（一键更新）、`menu/audit_view.rs`（审计日志查看）、`menu/backup.rs`（safe_write_config / 备份 / 恢复）；菜单编号、文案、交互行为保持不变。
- **`nat_common::stable_script_hash` 沉淀到 `hash` 模块**：v0.6.1 引入的 FNV-1a hash 在 v0.7.0 正式进入 `nat-common::hash` 模块并 re-export，行为等价；audit `script_hash` 字段保持。
- **保存提示分流文档化**：v0.6.1 的 reason 分流逻辑在 v0.7.0 不再改动，README 单独加段说明影响 / 不影响 nft 的两类 reason 各自的提示。
- **未改动**：nft 规则生成 / safe apply 语义 / quota 判断 / stats 统计 / last-good 解析与回退 / GeoIP / egress_control / access_control 组合策略 / SNAT / MSS 规则 / install.sh release 安装主流程 / GitHub Actions workflow。也未新增 WebUI / nat-console / tc HTB / 多租户 / server-agent / 数据库 / 任何新依赖。

### v0.8.0

- **动态 DDNS 来源白名单 (`dynamic_whitelist`)**：新增 access_control 来源白名单增强。定期解析用户已有 DDNS 域名，把 A 记录并入来源白名单；默认 disabled，默认 IPv4，独立 state 文件 `/var/lib/nftables-nat-rust/dynamic-whitelist-state.json`。
- **独立 last-good 来源 IP 兜底**：DNS 失败且有上一次成功解析结果时可临时保留 last-good 来源 IP，标记 `stale=true`；不会无限累积历史 IP，不会在无结果时开放所有来源。
- **规则生成保持边界**：只在 `access_control.mode = "whitelist"` 时合并静态白名单 + dynamic whitelist；不影响 `egress_control`、目标 DDNS / 目标 last-good、SSH GeoIP、SNAT、MSS、quota、stats。
- **CLI 管理入口**：`11) 白名单 / 黑名单管理` 增加「动态 DDNS 白名单管理」，支持状态、详情、添加、删除、启停单个域名、刷新间隔、手动刷新 state。
- **audit / Telegram**：解析成功、失败、IP 变化、state prune 写 audit；IP 变化且 `notify_on_change=true` 且 Telegram 可用时通知，沿用 curl 超时和 bot_token 脱敏策略。
- **未引入**：WebUI / nat-console / tc HTB / ifb / 多用户架构 / 分布式 agent / 数据库存储 / DNS 供应商接口。

### v0.8.2

- **dynamic_whitelist 可选 IPv4 /24 扩展模式**：新增 `dynamic_whitelist.cidr_expand_ipv4`（默认 `32`，可选 `24`）。`/32` 保持精确 IP 行为；`/24` 把 `1.2.3.4` 扩展为 `1.2.3.0/24`，最多放宽到 256 个 IPv4 地址，用于运营商出口经常在同一 `/24` 内变化的场景。第一版只支持 IPv4，IPv6 仍按精确地址处理；非 `32` / `24` 的值在配置校验和 CLI 入口两侧都会被拒绝。
- **effective_sources 与 raw_ips state 字段**：state 文件新增 `raw_ips` / `effective_sources` / `cidr_expand_ipv4`，旧 state 兼容读取后会按当前 `cidr_expand_ipv4` 即时重算 `effective_sources`；模式切换不会保留旧网段，不会无限累计历史。
- **CLI 二次确认**：动态 DDNS 来源白名单子菜单新增「设置 IPv4 CIDR 扩展模式」入口；选择 `/24` 会出现警告并默认按 `N` 拒绝；保存走 `safe_write_config`，reason `dynamic_whitelist.cidr_expand.update` 被识别为「影响 nft 规则」，提示 nat.service 将在检测周期内通过 safe apply 应用。
- **audit / Telegram**：`dynamic_whitelist.resolve.success` 与 `dynamic_whitelist.change` 写入 `raw_ips` / `effective_sources` / `cidr_expand_ipv4`；模式切换写 `dynamic_whitelist.cidr_expand.update` audit；Telegram 仅在 `effective_sources` 变化时通知，沿用 bot_token 脱敏与 curl 超时策略；通知文本对超长列表做截断，避免刷屏。
- **未引入**：per-domain 独立 `cidr_expand_ipv4`、`allowed_resolved_cidrs`、Cloudflare / DNSPod / DuckDNS 等 DNS 供应商 API、自动更新 DDNS、WebUI / nat-console、tc HTB / ifb、多租户 / server-agent、数据库存储；也不改 safe apply 主流程，不引入 `flush ruleset` / `sysctl --system` / `nft -f` 直刷。

---

## 待办（按风险 / 收益排序）

以下都是「可选维护项」，按需推进，不许诺时间。

## 可选增强：dynamic_whitelist 后续项

- IPv6 完整支持：当前默认 IPv4，`cidr_expand_ipv4` 也只支持 IPv4，后续可在 ip6 来源限制路径和文档验证充分后增强。
- `allowed_resolved_cidrs`：限制 DDNS 解析结果必须落在用户指定来源 CIDR 内，降低 DDNS 账号被盗后的影响面；和 `cidr_expand_ipv4` 是不同维度的安全增强，可叠加使用。
- per-domain 独立 `cidr_expand_ipv4`：第一版统一应用到全部 domains；后续可考虑按 domain 单独配置，例如手机出口 `/24`、机房专线 `/32`。需要先确认有真实场景再做，避免过度抽象。
- DNS 失败通知节流：第一版只通知 IP 变化，避免 DNS 抖动刷屏；后续可加入失败通知但必须节流。

不规划：多用户架构、WebUI、复杂 DNS 供应商接口、自动更新 DDNS 供应商。

## 可选设计：规则级备用目标 failover

当前版本不实现 failover；本节只是设计备忘，避免未来直接堆重功能。

目标：

一个入口规则可以配置主目标和备用目标。当主目标连续检测失败时，切换到备用目标；当主目标恢复后，可选切回。

示例设计，不实现：

```toml
[[rules]]
sport = 30080
target = "primary.example.com"
dport = 443

[[rules.failover_targets]]
target = "backup1.example.com"
dport = 443
priority = 10

[[rules.failover_targets]]
target = "backup2.example.com"
dport = 443
priority = 20
```

设计原则：

1. 默认不实现，不进入当前版本功能。
2. 如果未来实现，必须继续遵守：
   - 不做负载均衡
   - 不做多出口调度
   - 不做健康检查高频循环
   - 不做用户态 relay
   - 不引入数据库
3. 只考虑轻量 failover：
   - 主目标失败 N 次后切备用
   - 恢复检测低频执行
   - 切换必须写 audit
   - egress_control 必须重新验证备用目标 IP
   - last-good 不得绕过 egress_control
4. 当前版本不实现 failover；不改配置 parser，不改 nft 规则生成，不改 safe apply。

### 1. 继续拆分 `menu.rs` 剩余大块逻辑

**现状**：`menu.rs` 在 v0.7.0 拆出 `menu/update.rs` / `menu/audit_view.rs` / `menu/backup.rs` 后仍有约 6100 行，主要剩下规则增删改、stats / quota 子菜单、access_control / GeoIP / egress 子菜单、Telegram 配置、高级网络（SNAT / MSS / 时间 / NTP）、测试连通性等。

**风险**：低（编译干净、测试齐全），但与 prompt / save_toml_config / confirm 等顶层 helper 耦合较深，单文件搬动会引入大量 `pub(crate)` 改动。

**计划**（按依赖顺序）：

- `menu/stats.rs`：Stats / quota 子菜单（`stats_menu` / `switch_traffic_mode` / `set_rule_quota_interactive` / `show_quota_status` / `reset_stats` 等）
- `menu/security.rs`：access_control / GeoIP / egress_control 子菜单
- `menu/network.rs`：高级网络设置 + 时间 / NTP 子菜单
- `menu/telegram.rs`：CLI 侧 Telegram 配置 / 测试通知（与 nat-cli/src/telegram.rs 区分：前者是 CLI 配置入口，后者是 nat.service 发送客户端）
- `menu/rules.rs`：规则增删改、连通性测试

拆分时**不改任何行为**，纯位置迁移，菜单编号 / 文案 / 交互保持不变。

### 2. audit log 轮转边界继续增强

**现状**：v0.6.0 已经实现按大小轮转（`max_size_mb` 阈值 + `max_backups` 滚动）；轮转失败仅 WARN。

**可选增强**：

- 时间维度轮转（每日轮转一次，无视大小阈值）
- 轮转事件本身写一条 `audit.rotate.success` audit
- 轮转失败的 WARN 内容更具体（点出 stage：metadata / rename / truncate）

### 3. 统一更多测试结构

**现状**：`safe_apply_tests`、菜单 `tests` 模块、quota 集成测试散在 `main.rs` / `menu.rs`；hash / atomic / audit 在 `nat-common` 各自模块内自带测试。

**可选**：把目前嵌在 `main.rs` 大测试模块里的 quota 集成测试搬到 `tests/` 顶层 integration tests，减小 `main.rs` 编译压力。

### 4. install / update 文档继续打磨

**现状**：v0.6.0 起 README 已说明一键更新 latest 解析行为、`config.write.success/fail` audit、内置轮转参数等。v0.7.0 README 加了项目结构与维护路线段落。

**可选**：

- 给 `--use-release` 路径加更直观的「断网 / GitHub 限速 / DNS 污染」troubleshooting 段落
- 把 README 中「与原项目区别」表格按 v0.7.0 现状再核对一遍

---

## 约束（必须遵守）

- 不新增 WebUI / nat-console / static
- 不新增 tc HTB / ifb / rate_limit / egress_mbps
- 不新增 server-agent / 多租户 / 数据库
- 不引入重依赖（如 reqwest、tokio runtime、sqlite 等）
- 不改 nft 规则生成 / safe apply 语义 / quota 判断 / stats 统计 / last-good 解析 / GeoIP / egress_control / access_control 组合策略 / SNAT / MSS 规则
- 不改 install.sh release 安装主流程
- 不改 GitHub Actions workflow

任何越界改动需要先单独立项、走独立 minor 版本，不在 v0.7.x bugfix 范围内。

---

## 备注

- 上述待办均**不**属于 v0.7.x bugfix-only 范围。
- 实施前请回看本文件，确认现状描述仍然成立。
