# nftables-nat-rust-enhanced

`nftables-nat-rust-enhanced` 是基于 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 增强的 CLI-first nftables NAT 转发管理工具。本项目当前为纯 CLI-first 工具，不提供 WebUI。

> 命名约定：项目正式名为 **`nftables-nat-rust-enhanced`**（GitHub 仓库、安装命令、release 资产、README 标题、systemd 服务路径、配置 / 数据 / 日志目录均保持此名）；CLI 主菜单标题为简称 **`nft-nat-rust`**，仅用于交互界面显示。两者指向同一项目，未来不会重命名仓库或破坏安装/数据路径。

当前稳定版本：**v0.7.3**（v0.7.x CLI 与文档小修版本）。v0.7.0 维护性重构详见下面 [v0.7.0](#v070) 段落。

核心原则：

- release 预编译安装，普通 VPS 不需要编译 Rust
- 只管理本项目的 `self-nat` / `self-filter` 表
- 不执行 `flush ruleset`
- 应用 nft 前执行 `nft -c`
- 应用前备份，失败自动回滚本项目 managed tables
- CLI 菜单管理 `/etc/nat.toml`

> **Docker v28 兼容例外**：项目原则上只管理 `self-*` 表，**唯一已知**会触碰非 self-* 表的兼容处理是：启动时检测到 `ip filter FORWARD` 或 `ip6 filter FORWARD` 的默认 policy 是 `drop`（Docker v28 在某些版本会这样设置），会写入 `chain ip(6) filter FORWARD { policy accept ; }`，否则转发链路会被默认 drop。这是一次性兼容修正，不修改链中的规则，也不接管 forward policy。如果你不希望本项目触碰这条策略，请确保 `ip filter FORWARD` 的 policy 在 nat.service 启动前已经是 `accept`。

## 典型使用场景

本项目是 CLI-first / core-only 的 nftables NAT 管理器，只做 Linux nftables DNAT / SNAT 规则管理；不做 TLS 解密，不终止 HTTPS，不做应用层协议封装。

### 1. 普通公网端口转发

```text
客户端
  ↓
VPS 入口端口
  ↓ nft DNAT/SNAT
目标服务
```

适合：

- 固定 IP 目标
- 固定端口
- 个人自用转发

### 2. DDNS / 域名目标转发

```text
客户端
  ↓
VPS 入口端口
  ↓
DDNS 域名解析到目标 IP
  ↓
目标服务
```

说明：

- 域名解析成功后更新规则
- DNS 失败时可用 last-good IP 兜底
- last-good 不会绕过 egress_control

### 3. 国内入口 / po0 / RFC1918 出口机

```text
客户端
  ↓
入口机
  ↓ nft DNAT/SNAT
po0 / 内网出口机
  ↓
目标服务
```

说明：

- 推荐开启 egress_control，只允许转发到固定出口机 IP / 网段
- 如需固定源地址，可使用 SNAT fixed
- SNAT=off 仅适合已经配置好回程路由的高级用户

### 4. 安全固定目标转发

客户端来源限制：

- access_control 白名单 / 黑名单
- GeoIP / CN IP 来源限制

目标限制：

- egress_control allowed_target_cidrs

说明：

- access_control / GeoIP 限制“谁能访问入口”
- egress_control 限制“本机能转发到哪里”
- 两者不是同一个概念
- 同时开启时应叠加限制，不是互相绕过

如果用 HTTPS 做外部测试，证书 / SNI 取决于客户端访问域名和目标服务证书；本项目不终止 TLS，也不替目标服务处理证书。

## v0.7.0

v0.7.0 是**维护性重构版本**，重点是降低代码复杂度、提升后续维护稳定性，不新增用户侧大功能。所有核心转发、安全 apply、quota、stats、last-good、GeoIP、egress_control、access_control、SNAT、MSS 行为均与 v0.6.x 完全一致。

主要变化：

- **`nat-cli/src/main.rs` 拆分**：把原来 ~4000 行的入口文件拆成 `apply.rs`（safe apply / nft -c / 备份 / 回滚）、`quota_loop.rs`（quota 自动禁用循环）、`runtime.rs`（主循环节奏 / Stats 采集 / resolution 事件 audit 转写）、`telegram.rs`（curl 超时 / 错误脱敏）。`main.rs` 保留入口与顶层流程
- **`nat-cli/src/menu.rs` 拆分**：抽出 `menu/update.rs`（一键更新）、`menu/audit_view.rs`（审计日志查看）、`menu/backup.rs`（配置备份 / 恢复 / `safe_write_config`）。菜单编号、文案、交互行为保持不变
- **`stable_script_hash` 判断 nft 脚本是否变化**：nat.service 主循环不再用「整段字符串相等」比较新旧 nft 脚本，改用稳定 FNV-1a 64-bit hash（`nat_common::stable_script_hash`）。等价语义、不引入新依赖，audit `apply.success` / `apply.fail` detail 新增 `script_hash` 字段，便于排查"刚刚应用的是哪一版规则"
- **保存配置后的提示按 reason 分流**：
  - 影响 nft 规则的 reason（`rule.*` / `access_control.*` / `geoip.*` / `egress*` / `snat.*` / `mss_clamp.*` / `backup.restore` / `quota.auto_disable` / `quota.config.update` / `stats.mode.update`）继续显示完整 `nat.service` 自动应用 + `systemctl restart nat` / `nft list table` / `journalctl` 排查命令
  - 不影响 nft 规则的 reason（`telegram.*` / `ui.*` / `audit.*`）改为简短提示：「配置已安全保存…该配置不会改变 nft 转发规则，无需等待 nft 应用。」避免误导用户去 restart nat

**未改动**（v0.7.0 维护约束的契约边界）：

- nft 规则生成 / safe apply 语义 / quota 判断 / stats 统计 / last-good 解析与回退
- GeoIP / egress_control / access_control 组合策略 / SNAT / MSS 规则
- `install.sh` release 安装主流程、GitHub Actions workflow
- 也没有新增 WebUI / nat-console / tc HTB / ifb / 多租户 / server-agent / 数据库

v0.7.x 进入 **maintenance-only / bugfix-only** 阶段，后续路线见末尾 [维护路线](#维护路线)。

## 功能特性

### 核心转发

- 单端口转发
- 端口段转发
- 本机 redirect
- IPv4 / IPv6
- TCP / UDP / all
- IP、域名、DDNS 目标
- TOML 配置，兼容旧版 `/etc/nat.conf` 读取逻辑

### 安全 nft 应用

- 生成规则后先执行 `nft -c -f <generated-file>`
- 应用前备份当前 ruleset
- 应用失败时回滚本项目 managed tables
- 不清空用户其他 nftables table
- nft comment 使用短 ID，规避 nftables comment 128 字符限制

### CLI 菜单

- `nat --menu` 终端交互菜单
- 查看、添加、删除转发规则
- 备份 / 恢复配置
- 查看 Stats
- 查看当前 nft 规则
- 白名单 / 黑名单管理
- 一键更新
- 一键卸载

### DDNS

- 域名目标自动解析
- 支持定时刷新
- 支持 fake-ip 检测，默认拒绝 `198.18.0.0/15`

### Stats 流量统计

- 每日总流量
- 每月总流量
- 每条规则每日/月流量
- 通过 `self-filter FORWARD` 中的 `nat-traffic` counter 统计
- 支持 `traffic_mode = "both"` / `"out"` / `"in"`
- CLI 可在 Stats 页面切换统计口径
- 切换统计口径后，历史 daily/monthly 不会自动重算

### Telegram 通知

- 通过 `/etc/nat.toml` 配置 Telegram bot_token / chat_id
- CLI 可配置 bot_token 和 chat_id
- 输入 bot_token 时为明文输入，方便复制粘贴确认
- CLI 可发送测试通知，测试通知不会自动启用 Telegram 通知
- CLI 可设置通知间隔，单位分钟
- 支持定时通知
- 支持 daily / monthly 流量通知
- bot_token 在状态输出中脱敏
- v0.4.3 起 Telegram curl 调用强制 `--connect-timeout 5 --max-time 15`，Telegram API 不可达 / 网络抖动不会阻塞 nat.service 主循环。失败仅 WARN + audit，并对 stderr 兜底脱敏 bot_token，不会泄露在 audit / CLI 输出中。

### 白名单 / 黑名单

- 只作用于本项目转发端口
- 不影响 SSH
- 不影响用户其他 nftables table
- entries 支持 IP / CIDR

### GeoIP / 中国大陆 IP 限制

可选功能，默认关闭。默认通过 `cn4_url` 拉取 nftables 格式的 `cn4.nft` 作为中国大陆 IPv4 set 来源。
仅 IPv4，IPv6 暂不支持。本项目只管理 `self-*` nft 表，不 `flush ruleset`，不修改用户其他 nft 表。

- 可限制本项目转发端口只允许中国大陆 IPv4（+可选 LAN）访问
- 可选限制 SSH 只允许中国大陆 IPv4 和 LAN 访问；SSH 限制有锁死风险，开启前务必确认
- CN IP set 通过 CLI 手动下载并原子替换，下载失败保留旧文件
- 启用 GeoIP 但 `cn4_file` 不存在或为空时，核心服务会跳过 GeoIP 规则并 WARN
- GeoIP forward 限制当前基于 `cn4.nft`，**仅作用于 IPv4 转发规则**；IPv6 转发规则不会被 `@cn4` 集合过滤，不受 GeoIP 限制。如需 IPv6 GeoIP，需要额外引入 IPv6 数据源（例如 `cn6.nft`），本项目尚未实现 IPv6 GeoIP，请通过 `access_control` / `egress_control` 等限制为 IPv6 规则做来源 / 目标控制。

`cn4.nft` 数据源可配置，`cn4_url` 默认值只是一个参考数据源。中国大陆 IP 数据可能存在误差，使用前请自行确认；如需更严格来源，可替换为 APNIC、clang.cn、纯真、ipip.net 或其他你信任的数据源。

GeoIP 与白名单/黑名单的区别：

- `geoip` 限制的是国家 / 地区来源（中国大陆 IPv4）
- `access_control` 限制的是用户自定义的来源 IP / CIDR 白名单或黑名单
- 两者可以同时启用，叠加生效，不是互相覆盖

### access_control 与 GeoIP 的组合策略

`access_control`（黑/白名单）与 `geoip`（国家/地区限制）是分层叠加的访问控制，不是互相替代。两者同时启用时，使用 AND 逻辑：

```text
allow = (来源不在黑名单)
      AND (whitelist 模式关闭，或来源命中白名单)
      AND (geoip.forward 关闭，或来源属于 CN/可选 LAN)
```

评估顺序（按 nft 链优先级）：

1. **黑名单优先级最高。** `access_control.mode = "blacklist"` 命中即在 `self-nat PREROUTING` 中 drop，无论该来源是否属于 CN/LAN，无论白名单状态。
2. **白名单是精确来源限制。** `access_control.mode = "whitelist"` 时，只有 `entries` 内的来源 IP/CIDR 能匹配本项目转发规则，其他来源不会被 DNAT，等同于拒绝转发；不会因为属于 CN/LAN 而被放行。
3. **GeoIP 是国家/地区来源限制。** `geoip.forward.enabled = true` 时，`self-filter GEOIP_PREROUTING`（优先级 -200，早于 `self-nat PREROUTING` 的 -110）会 drop 非 CN/LAN 来源；不会因为命中白名单而被放行。
4. **同时启用 = AND。** 黑名单 + 白名单 + GeoIP 同时启用时，三层依次叠加，必须同时满足才会被 DNAT。

不要把两者理解为 OR：白名单不会绕过 GeoIP，GeoIP 也不会绕过白名单。例如：

- 来源属于黑名单 **且** 也属于 CN：仍然 drop（黑名单优先）。
- 白名单开启且来源不在白名单：即使属于 CN 也不会被转发。
- GeoIP 开启且来源不属于 CN/LAN：即使不在黑名单，也会在 prerouting 被 drop。
- 白名单 + GeoIP 同时启用：只有 **同时命中白名单 且 属于 CN/LAN** 的来源才会被转发。

CLI 的「白名单 / 黑名单管理」和「GeoIP / CN IP 限制」状态页都会显示当前组合策略，方便核对预期。

注意：上述组合不会 `flush ruleset`，不会修改用户其他 nftables 表；只在本项目的 `self-nat` / `self-filter` 表内叠加规则。

### 出口目标限制

`egress_control` 用于限制本机只能把转发流量转发到指定目标 IP / IP 段。

- 适合限制本机只能转发到自己的 rfc / po0 出口机、落地机、内网出口段
- 防止本机被滥用成开放代理转发器
- 限制的是 **目标 IP**，不是访问来源 IP；来源 IP 限制请使用 `access_control` 或 GeoIP
- `enabled=true` 且 `allowed_target_cidrs` 为空时，所有转发规则都会被跳过并 WARN
- 目标 IP 不在 `allowed_target_cidrs` 内的规则会被跳过，日志输出 WARN
- 域名规则使用当前解析到的 `resolved_ip` 与 `allowed_target_cidrs` 匹配
- `disabled` 规则不参与检查

### SNAT 模式

`snat.mode` 控制 POSTROUTING 阶段的源地址改写方式。普通 VPS 端口转发一般使用默认值 `masquerade`，po0 / RFC1918 出口机或落地机场景可使用 `fixed` 指定固定中转源 IP。

- `mode = "masquerade"`（默认推荐）：生成 `masquerade` 规则，由 nft 自动选择出接口源 IP，适合普通 VPS
- `mode = "fixed"`：生成 `snat to <fixed_source_ip>`，适合 po0 / RFC1918 出口机需要让落地机看到固定中转内网 IP 的场景；**第一版仅支持 IPv4**
- `mode = "off"`：**不生成** POSTROUTING SNAT 规则；仅适合已经自行配置好回程路由的高级用户

> **警告：SNAT=off 不会生成 masquerade / snat 规则，必须由用户自行保证回程路由，否则转发可能不通。普通 VPS / 普通端口转发推荐使用 `masquerade`。**

`fixed` 模式当前仅支持 IPv4：

- `fixed_source_ip` 必须是合法 IPv4 地址；空值、IPv6 地址或非法字符串在 `from_toml_str` / `validate` 阶段直接报错
- IPv6 / NAT66 暂不实现 fixed SNAT：当 `ip_version` 为 IPv6 时不会生成 `snat to <ipv4>`，而是回退到 `masquerade`，避免写出非法 nft 规则
- 如果未来需要 IPv6 fixed SNAT，会单独提供 `fixed_source_ipv6` 字段，不会复用 `fixed_source_ip`
- **同时存在 IPv4 与 IPv6 转发规则时**：IPv4 规则使用 `snat to <fixed_source_ip>`，IPv6 规则会按 `masquerade` / 默认 IPv6 行为处理；nat.service **不会**因为缺少 IPv6 fixed_source_ip 而失败或拒绝 apply

示例：

```toml
[snat]
mode = "masquerade"
fixed_source_ip = ""
```

fixed 示例：

```toml
[snat]
mode = "fixed"
fixed_source_ip = "10.100.0.10"
```

历史版本的 `nat_local_ip` / `nat_local_ipv6` 环境变量仅在 `mode = "masquerade"` 时作为兼容兜底；推荐新配置直接使用 `snat.mode = "fixed"` 显式声明。

### MSS clamp

`mss_clamp` 在本项目转发链路上对 TCP SYN 包写入 `tcp option maxseg size set <size>`，缓解多跳 / 隧道 / po0 / MTU 异常场景下的测速异常、网页卡顿、TLS 握手卡死等问题。

边界：

- 默认 `enabled = false`，**不生成任何 MSS 规则**
- 启用后**仅作用于本项目转发相关 TCP 流量**，按 DNAT 后的目标端口匹配 SYN 包；**不生成全局 TCP MSS 规则、不影响 UDP、不影响非本项目端口**
- 规则 `protocol = "udp"` 时**不生成** MSS clamp
- 规则 `protocol = "all"` 时 MSS clamp 只对其中 TCP 流量生效，nft 规则用 `tcp dport/sport ...` 关键字限定，不会写 `meta l4proto { tcp, udp }` 全协议匹配
- 仅作用于实际经过 forward 链的规则：本机 `localhost` redirect 不会生成 MSS clamp
- 不接管整机 forward policy，不写 `policy drop`，只在 `self-filter FORWARD` 链中添加规则
- `size` 合法范围 536-1460，超出范围会在配置校验阶段报错
- 常见值 1452；不懂 MTU/MSS 时不建议随意开启

示例：

```toml
[mss_clamp]
enabled = false
size = 1452
```

### 组合策略说明

本项目的转发链路上可以同时启用以下功能，它们是分层叠加的，不是互相替代或互相覆盖：

| 功能 | 限制对象 | 控制方式 |
|---|---|---|
| `access_control` | 来源 IP / CIDR | 用户自定义白名单 / 黑名单 |
| `geoip` | 来源 IP（国家/地区） | 中国大陆 IPv4 set + 可选 LAN |
| `egress_control` | 目标 IP / CIDR | `allowed_target_cidrs` |
| `snat` | 源地址改写 | masquerade / fixed / off |
| `mss_clamp` | TCP MSS 调整 | enabled + size |

来源叠加规则（与 `### access_control 与 GeoIP 的组合策略` 一致）：

- 黑名单优先级最高，命中即拒绝
- 白名单是精确来源 IP 限制
- GeoIP 是国家/地区来源 IP 限制
- 多个来源限制同时开启时采用叠加限制（AND），不是 OR 放行

目标限制独立于来源限制：

- `egress_control.enabled = true` 且 `allowed_target_cidrs` 非空时，仅允许转发到 CIDR 命中的目标 IP；其余目标的规则会被跳过并 WARN
- `egress_control.enabled = true` 但 `allowed_target_cidrs` 为空时，所有转发规则都会被跳过并 WARN

SNAT 与 MSS clamp 不参与来源 / 目标 IP 准入判断，它们改变的是数据面的源地址写入方式和 TCP MSS。但它们的当前值仍会在 CLI 状态页显示，避免和上述准入功能混淆。

CLI 的「GeoIP / CN IP 限制」、「出口目标限制」、「高级网络设置」结果页会显示完整的组合策略详情；「查看当前转发规则」默认只展示一行组合策略摘要，输入 `d` 即可展开完整组合策略 + 完整 last-good 状态缓存。「测试转发规则连通性」聚焦于具体规则的连通性诊断，不再默认重复完整组合策略，详细策略可在「高级网络设置 → 查看全局诊断状态」查看。

### last-good 状态缓存

`last_good` 用于在 DDNS / 域名目标解析临时失败时，复用上一次成功解析过的 IP，避免一次 DNS 抖动把可用规则变成不可用。

- 默认 `enabled = true`，`use_last_good_on_dns_failure = true`
- 缓存文件默认 `/var/lib/nftables-nat-rust/last-good-state.json`，原子化写入（tmp + fsync + rename）
- 当 nat.service 通过安全 apply 成功应用规则后，更新缓存为本次解析到的 IP 和应用状态
- 当域名解析失败：
  - 若 `last_good.enabled=true` 且 `use_last_good_on_dns_failure=true` 且该规则有 `last_good_ip` → 使用 last-good IP 继续生成规则，WARN
  - 否则跳过该规则并 WARN，不生成可能失败的 nft 规则
- last-good 不绕过 `egress_control`、`access_control` 或 `geoip`，缓存 IP 同样要满足这些限制；不在 `allowed_target_cidrs` 内的 last-good 目标会被跳过
- last-good 不影响静态 IP 目标规则（这些规则不经过 DNS 解析）
- 缓存文件不写入 Telegram bot_token 或其他敏感配置
- 缓存文件写入失败仅 WARN，不会让 nat.service 崩溃
- CLI 的「查看当前转发规则」、「测试转发规则连通性」结果页会显示每条规则当前用的是 live DNS 还是 last-good IP，以及对应的 egress 判断

示例：

```toml
[last_good]
enabled = true
file = "/var/lib/nftables-nat-rust/last-good-state.json"
use_last_good_on_dns_failure = true
```

last-good 文件结构（节选）：

```json
{
  "last_success_at": "2026-05-19T12:00:00Z",
  "rules": [
    {
      "rule_id": "r0",
      "comment": "hk-out",
      "domain": "example.com",
      "last_good_ip": "1.2.3.4",
      "last_resolved_at": "2026-05-19T11:59:00Z",
      "egress_allowed": true,
      "last_apply_status": "ok"
    }
  ]
}
```

last-good 只是容错机制，不应长期掩盖 DNS 问题。请定期查看 audit log 和 `nat --menu` 的「查看当前转发规则」状态，确认转发是否仍处于 live DNS 路径。

### audit 审计日志

`audit` 用于记录用户通过 CLI 对配置的修改、以及 nat.service 自动行为中的关键事件，方便事后排查“我刚刚改了什么”。

- 默认 `enabled = true`
- 日志文件默认 `/var/log/nftables-nat-rust-audit.log`
- 每条日志为一行 JSON，至少包含 `time` / `action` / `result` / `detail`，便于 `grep` 和后续解析
- 写入失败只 WARN，不会让 nat.service 或 CLI 崩溃
- 不记录敏感明文：Telegram `bot_token` / `chat_id` 在写入前会脱敏为 `头2***尾2`；其他常见 secret key 也会被兜底脱敏

CLI 触发的事件包含但不限于：

- `rule.add` / `rule.delete` / `rule.enable` / `rule.disable`
- `access_control.update` / `geoip.update` / `egress_control.update` / `snat.update` / `mss_clamp.update`
- `ddns.refresh` / `backup.create` / `backup.restore`
- `bbr.enable` / `bbr.disable`
- `telegram.config.update`（bot_token / chat_id 已脱敏）
- `update.start` / `update.success` / `update.fail`
- `uninstall.start`

nat.service 自动行为：

- `apply.success` / `apply.fail`
- `dns.resolve.fail` / `last_good.used`
- `rule.skipped.egress_control`

CLI 主菜单 `20) 查看审计日志` 默认显示最近 50 行，提供子菜单：

```text
1) 查看格式化日志（默认，CLI 友好，按 Asia/Shanghai 24 小时制）
2) 查看原始 JSON 日志
0) 返回
```

- 文件内部仍是一行 JSON，便于 `grep` / `jq` / 脚本解析；`time` 字段为 UTC RFC3339。
- CLI 1) 默认会把 `time` 转成展示时区（受 `[ui].timezone` 影响）并以 `[YYYY-MM-DD HH:MM:SS CST] action  result\n  k: v` 形式打印；如果 JSON 解析失败 fallback 显示 `[无法解析] <原始行>`。
- CLI 2) 原样打印 JSON 行，方便复制粘贴排查。
- 任何展示路径都会再次走 `redact` 兜底，避免直接显示 bot_token / authorization / jwt / key 等敏感字段。
- 完整日志可在 `audit.file`（默认 `/var/log/nftables-nat-rust-audit.log`）用 `tail -F` / `grep` 直接查看。

示例：

```toml
[audit]
enabled = true
file = "/var/log/nftables-nat-rust-audit.log"
rotate = true
max_size_mb = 10
max_backups = 3
```

#### 内置轻量轮转（v0.6.0 起默认开启）

audit 模块本身内置 best-effort 轮转，避免 audit log 在长期运行的小磁盘 VPS 上无限增长：

- 默认 `rotate = true`、`max_size_mb = 10`、`max_backups = 3`；旧配置缺这些字段时使用同一组默认值
- 写入每条 audit 前先检查 `audit.file` 大小：超过 `max_size_mb * 1MB` 时滚动 `audit.log → audit.log.1 → audit.log.2 → audit.log.3`（最旧的被丢弃），然后新建空文件继续 append
- `max_backups = 0`：超过阈值时只截断当前 `audit.log`，不保留任何 `.N` 历史
- `rotate = false`：完全关闭内置轮转，留给系统级 logrotate 处理
- 轮转过程任何 io 失败仅 WARN，不让 nat.service / CLI 崩溃；当前事件仍会尝试 append
- 轮转后的当前 `audit.log` 仍然是一行 JSON 格式；CLI「查看审计日志」依旧读最近 50 行

#### 也可改用系统 logrotate

如果你已经在用 logrotate 管理日志，可以把 `audit.rotate = false` 并在 `/etc/logrotate.d/nftables-nat-rust-audit` 写入：

```
/var/log/nftables-nat-rust-audit.log {
    daily
    rotate 14
    compress
    missingok
    copytruncate
}
```

- `copytruncate` 适合 append 模式：不需要重启 nat.service，nat 会继续 append 到原 inode。
- 本项目不会自动安装 logrotate。如果你的系统没有 logrotate，保持默认 `audit.rotate = true` 即可。

### 规则级流量配额 quota

可为每条转发规则设置 `daily` / `monthly` / `total` 流量配额，超额后**自动禁用规则**（不删除）。

- 配额基于现有 [Stats 流量统计](#stats-流量统计)，按 `stats.traffic_mode` 当前口径（`both` / `out` / `in`）统计；不另起一套计数逻辑
- `stats.enabled = false` 时 quota 不会生效；nat.service 主循环会每隔 `quota.check_interval_seconds` 跑一遍 quota 检查
- `quota_period = "total"` 的累计字节同样基于当前 `stats.traffic_mode` 累积；切换 `traffic_mode` 后**历史 daily / monthly / total 都不会自动重算**，已经累计的 total 字节也不会重新统计。如果切换口径，建议手动确认 `quota.state_file` 与 `stats.data_file`，必要时按需重置 Stats 后再启用 `total` 配额
- 第一版仅支持 `quota_action = "disable"`：超额后 `enabled` 置 false，写回 `/etc/nat.toml`，由现有安全 apply 流程在下一轮迭代中移除该规则的 nft 规则
- **不直接执行 `nft -f`、不删除规则**；规则保留在 TOML 中，方便用户手动重新启用
- v0.4.1 起：nat.service 在 quota 自动禁用规则、写回 `/etc/nat.toml` **前会先备份**到 `/etc/nftables-nat/backups/config/nat.toml.quota-auto-disable-YYYYmmdd-HHMMSS.bak`；备份失败 → **跳过本轮写回**，下一轮再试，不会在没有备份的情况下覆盖配置。写回使用临时文件 + rename 原子替换，写入失败时备份保留并写 audit。
- Telegram 通知（如已配置 + `quota.notify_on_exceeded = true`）只在每个 period 内通知**一次**，去重状态写在独立 JSON 文件 `quota.state_file`
- 写 audit 事件 `quota.exceeded` + `rule.disable.quota` + `quota.telegram.notify` / `quota.telegram.skipped`
- Telegram 未配置或主流程任何写入失败仅 WARN，不让 nat.service 崩溃
- 用户在 CLI「启用 / 禁用规则」中重新启用一条已被 quota 禁用的规则时：
  - 如果当前 period 仍超额，CLI 会打印警告「当前周期已用流量仍超过配额…」
  - 同时清除该规则在 `quota.state_file` 中的所有 period 通知去重记录，下次再次超额时会重新通知一次

配额字节支持的输入格式：纯字节数（如 `107374182400`）、十进制单位 `100KB` / `100MB` / `100GB` / `100TB`、二进制单位 `100KiB` / `100MiB` / `100GiB` / `100TiB`。

配额单位语义（避免混淆）：

- 短缀 `K` / `M` / `G` / `T`：按 **1024 进制**解释（与 `KiB` / `MiB` / `GiB` / `TiB` 等价）
- 长缀 `KB` / `MB` / `GB` / `TB`：按 **1000 进制**解释（十进制，与硬盘厂商口径一致）
- 长缀 `KiB` / `MiB` / `GiB` / `TiB`：按 **1024 进制**解释（IEC 二进制单位）
- `quota_period = "total"` 的累计字节基于当前 `stats.traffic_mode` 累积；**切换 `traffic_mode` 后历史 total 不会自动重算**，已经累计的 total 字节也不会按新口径重新统计。如需切换 mode 后获得"干净"的 total 配额，请手动重置 `stats.data_file` 与 `quota.state_file` 后再启用 `total` 配额

CLI 入口：主菜单 `7) 查看 Stats 流量统计` → `3) 设置规则流量配额` / `4) 查看规则配额状态`。

配置示例：

```toml
[quota]
enabled = true
check_interval_seconds = 60
notify_on_exceeded = true
state_file = "/var/lib/nftables-nat-rust/quota-state.json"

[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
comment = "hk-out"
enabled = true
quota_enabled = true
quota_bytes = 107374182400         # 100 GiB
quota_action = "disable"
quota_period = "monthly"
```

### BBR

CLI 菜单可查看、启用或关闭 BBR。开启/关闭只处理本项目配置文件 `/etc/sysctl.d/99-nat-bbr.conf`，不会删除用户其他 sysctl 配置，也不会调用 `sysctl --system`。

### 时间显示与 NTP

CLI 在状态页、last-good、audit、quota 等位置显示的时间默认按 **Asia/Shanghai 24 小时制** 展示，格式形如 `2026-05-19 20:02:58 CST`，不再使用 RFC3339 的 `T...+00:00` 长格式与纳秒。

- JSON 状态文件 / audit log 内部仍以 **UTC RFC3339** 存储，方便机器解析（grep / 脚本处理）。
- 仅 CLI 显示层做转换；状态文件保持原样。
- 系统时区（`timedatectl` 报告的 `Time zone`）和 CLI 展示时区可以不同；本工具**不会**自动修改系统时区。

#### `[ui]` 配置 CLI 展示时区

v0.4.2 起支持在 `/etc/nat.toml` 配置 CLI 展示时区与时间格式：

```toml
[ui]
timezone = "Asia/Shanghai"
time_format = "%Y-%m-%d %H:%M:%S %Z"
```

- `timezone`：合法 IANA 时区名（处理 DST 由 `chrono-tz` 兜底）。例如：`Asia/Shanghai` / `UTC` / `America/Chicago` / `Europe/Paris`。非法值在 `from_toml_str` / `validate` 阶段直接报错。
- `time_format`：chrono `strftime` 格式串；默认 `"%Y-%m-%d %H:%M:%S %Z"`。
- 仅影响 CLI 展示，不改变系统时区，也不影响 audit/last-good/quota 等 JSON 内部存储。

nft 转发本身不严格依赖系统时间。但以下功能建议系统时间准确：

- Stats daily / monthly 滚动重置
- quota 周期判断与 Telegram 通知去重 key
- audit log 时间戳
- last-good 上次成功解析时间
- TLS 下载 release / `cn4.nft` 时的证书校验

CLI 菜单提供 **时间 / NTP 状态检查**：`19) 高级网络设置 (SNAT / MSS clamp)` → `6) 时间 / NTP 状态检查`。v0.4.2 起为子菜单：

```text
时间 / NTP 状态检查
1) 查看时间 / NTP 状态（默认）
2) 设置 CLI 展示时区
3) 显示修改系统时区命令
4) 尝试启用系统 NTP
0) 返回
```

- 系统时区与 CLI 展示时区不同**不被当成错误**，只提示「这不会影响 nft 转发」；可在 2) 修改 CLI 展示时区或在 3) 查看修改系统时区命令。
- 3) 只 **打印** `sudo timedatectl set-timezone Asia/Shanghai` 等建议命令，**不**自动执行。
- 4) 必须通过 y/N 二次确认才会调用 `timedatectl set-ntp true`；输入其他视为取消。
- `timedatectl` 不存在时一律仅打印提示，不报错；本工具不会 `apt-get install` 任何东西，不会强制改时区，不会自动调用 `sysctl --system`。

### 规则改动 / nat.service 应用延迟

CLI 添加、删除、启用 / 禁用、修改 SNAT / MSS / Telegram / quota 等任意配置时，本工具**只写 `/etc/nat.toml`**，不绕过安全 apply 直接 `nft -f`。

`nat.service` 主循环每隔 `ddns.refresh_interval_seconds`（默认 300 秒）检测一次配置变化，并通过安全流程（`nft -c` → 备份 → `nft -f` → 失败回滚 managed tables）应用规则。

因此：

- 刚改完配置后立即测试 `nft list table ip self-nat` 可能看不到新规则，**这不一定是 bug**，通常是 nat.service 还没跑完一个检测周期。等待一个 `ddns.refresh_interval_seconds` 之后刷新即可。
- 如需立即应用，可手动执行：`systemctl restart nat`。
- 「测试转发规则连通性」页面在 nft 未应用时会显示明确的 pending 提示：「规则已保存但尚未在 nft 中生效，可能正在等待 nat.service 自动应用。」

## 系统要求

推荐：

- Debian 12
- Debian 11
- Ubuntu 20.04 / 22.04 / 24.04

轻量安装依赖：

```bash
apt update && apt install -y curl ca-certificates nftables iproute2 iptables procps openssl tar nano
```

源码编译依赖：

```bash
apt update && apt install -y git curl wget ca-certificates build-essential pkg-config libssl-dev nftables iproute2 iptables procps openssl tar nano
```

## 快速安装

推荐安装并进入 CLI 菜单：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --enter-menu
```

安装但不自动进入菜单：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release
```

指定版本（推荐使用当前稳定版 `v0.7.3`，或省略 `--version` 跟随 latest release）：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --version v0.7.3
```

不指定 `--version` 时使用 latest release。release 包是核心 CLI 版本，包含：

```text
nat
install.sh
setup.sh
README.md
LICENSE
NOTICE
```

安装完成后会：

- 安装 `/usr/local/bin/nat`
- 安装 `nat.service`
- 保留或创建 `/etc/nat.toml`
- 启动并检查 `nat.service`
- 提示 `nat --menu`

## 源码编译安装

低配 VPS 不推荐源码编译。开发者或需要测试最新 main 时可使用：

```bash
tmp="$(mktemp -d)" && cd "$tmp" && curl -fsSL https://github.com/misaka-cpu/nftables-nat-rust-enhanced/archive/refs/heads/main.tar.gz | tar xz --strip-components=1 && cargo build --release && bash install.sh --core-only
```

## CLI 使用

进入菜单：

```bash
nat --menu
```

查看当前版本：

```bash
nat --version
```

示例输出：

```text
nat v0.7.3
```

release 构建会显示 GitHub tag，例如 `v0.7.3`。源码编译如果没有注入 tag，会回退到 `Cargo.toml` 的 workspace version；两者都缺失时显示 `dev`，不会输出空字符串。

菜单（v0.4.2 起标题携带当前版本号，未注入版本时显示 `nft-nat-rust dev`）：

```text
====================================
nft-nat-rust v0.7.3
====================================
1) 查看当前转发规则
2) 添加单端口转发
3) 添加端口段转发
4) 删除转发规则
5) 启用 / 禁用规则
6) 查看当前 nft 规则
7) 查看 Stats 流量统计
8) 手动刷新 DDNS / 域名目标
9) 备份当前配置
10) 从备份恢复配置
11) 白名单 / 黑名单管理
12) GeoIP / CN IP 限制
13) 出口目标限制
14) 最近来源 IP 观察（手动排查）
15) BBR / Telegram 状态
16) 测试转发规则连通性
17) 一键更新本项目
18) 卸载 / 清理本项目
19) 高级网络设置 (SNAT / MSS clamp)
20) 查看审计日志
0) 退出
```

`高级网络设置` 子菜单：查看 SNAT / MSS 状态、设置 SNAT 模式（masquerade / fixed / off）、设置 fixed SNAT 源 IP、启用 / 禁用 MSS clamp、设置 MSS clamp size、**时间 / NTP 状态检查**（v0.4.2 起为子菜单，参见 [时间显示与 NTP](#时间显示与-ntp)）、**查看全局诊断状态**（同时显示完整组合策略与完整 last-good 状态缓存，仅查看不修改配置）。

`查看当前转发规则` 默认只展示每条规则的核心字段（index / 状态 / type / sport / target / resolved / dport / protocol / ip_version / access_control / quota / egress），以及一行组合策略摘要和一行 last-good 摘要。可在页面尾部输入 `d` 展开完整组合策略 + 完整 last-good 状态缓存；按 Enter 直接返回主菜单。

添加单端口 / 端口段转发时，CLI 会尽力使用 `ss -lntup` 检测入口端口是否已被本机 TCP / UDP 监听服务占用。发现占用时默认取消添加，用户明确输入 `y` 后才会继续保存，并写入 `port_conflict.override` audit 事件。若系统没有 `ss` 或检测命令失败，只显示 warning，不阻塞添加，也不会自动安装依赖、kill 进程或修改已有服务。

`查看审计日志` 显示最近 50 行 audit 事件。默认以 CLI 友好格式（按 Asia/Shanghai / `[ui].timezone` 展示时间），可在子菜单切换查看原始 JSON。文件路径默认 `audit.file = /var/log/nftables-nat-rust-audit.log`，可用 `tail -F` / `grep` 直接查看。

`测试转发规则连通性` v0.4.2 起改用更宽松的 nft 规则存在性检测：

- 同时扫描 `ip self-nat / ip self-filter / ip6 self-nat / ip6 self-filter`
- 不依赖 counter 非零（避免「规则刚 apply 还没流量」时误报「未应用」）
- protocol=all 时同时识别 `meta l4proto { tcp, udp }` 与拆分形式
- nft 检测结论分四档：`已应用` / `部分匹配` / `未确认` / `未应用`
- 若检测器未找到，但 `nat.service` 仍 active 且最近一次 `apply.success`，会显示 `未确认` 而不是 `未应用`，并提示用户手动查看：`nft list table ip self-nat` / `journalctl -u nat -n 120 --no-pager`
- 不会因检测未确认就自动重启 nat、也不会绕过 safe apply 直接 `nft -f`

测试页面按层展示含义：配置状态说明规则是否 enabled、目标是域名还是 IP、实时 resolved_ip 与 last-good 来源；服务状态说明 `nat.service` 与最近 apply；nft 应用状态说明 `self-nat` / `self-filter` 是否被检测器确认；目标连通性只表示本机到目标 TCP 的探测结果；外部访问测试仍需要从另一台机器访问 `SERVER_IP:入口端口`。服务端检查正常时，外部机器测试只是最终入口验证建议，不代表服务端配置异常。

CLI 默认只展示简短测试提示（`SERVER_IP:入口端口` + 协议提示），详细 `curl` / `nc` / SNI 示例可在测试页面**输入 h 查看**。详细命令会按规则的 `protocol` 与 `target` 分支：
- `protocol=tcp` 显示 TCP `nc` 与 `curl`，IP 目标不附 `Host` header；
- `protocol=udp` 仅显示 UDP `nc -vzu` 提示，并提醒最终需用业务客户端验证；
- 目标是域名时附 `Host` header 与 `--connect-to ... SNI` 示例。
这些命令只用于外部连通性测试，与 GeoIP / last-good / egress_control 等准入功能是不同模块。HTTPS 测试中的证书 / SNI 取决于客户端访问域名和目标服务证书；本项目不终止 TLS。

`GeoIP / CN IP 限制` 子菜单包含：查看状态、下载 / 更新 CN IP set、启用或禁用转发端口 CN 限制、启用或禁用 SSH CN 限制（需要输入 `CONFIRM`）、设置 SSH 端口、设置更新间隔。

`出口目标限制` 子菜单包含：查看状态、启用或禁用、添加 / 删除 / 列出允许目标 IP / CIDR。出口目标限制用于限制本机只能把转发流量转发到指定出口机或出口网段，它不是来源 IP 白名单。

菜单内误输入 `menu`、`main`、`m`、`nat --menu` 会刷新主菜单；输入 `q`、`quit`、`exit` 或 `0` 退出。

配置变更后，`nat.service` 通常会自动检测并通过安全流程应用规则。安全流程包括 `nft -c` 检查、备份当前规则、应用失败自动回滚。如未自动生效，可执行：

```bash
systemctl restart nat
```

#### 安全写配置（v0.6.0 起统一）

所有写 `/etc/nat.toml` 的生产路径——CLI 各子菜单修改配置、`quota` 自动禁用规则写回——都统一走 `safe_write_config`：

1. 先备份当前 `/etc/nat.toml` 到 `/etc/nftables-nat/backups/config/nat.toml.<reason>-YYYYmmdd-HHMMSS.bak`（权限 0600）
2. 把新内容写到临时文件 `<path>.tmp.<pid>`，best-effort `fsync` 后 `rename` 替换目标文件
3. 写一条 audit 事件 `config.write.success`，包含 `reason` / `path` / `backup`（删除规则除外，见下文）

v0.7.x 起，删除规则 `rule.delete` 默认不创建配置备份，以避免无意义备份堆积；其它配置修改仍会自动备份。删除规则仍使用临时文件 + fsync + rename 原子写入，并写入 audit log，`config.write.success` detail 会包含 `backup_skipped = true`。

任何一步失败：
- 备份失败 → 不覆盖目标文件，写 `config.write.fail`（`stage=backup`）audit，CLI 返回错误；`quota` 自动禁用会跳过本轮，等下一轮重试
- 临时文件 / rename 失败 → 旧 `/etc/nat.toml` 保持不变，写 `config.write.fail`（`stage=write_or_rename`）audit
- audit detail 不写入 `bot_token` / `chat_id` / 任何 secret key（沿用 `redact` 兜底）

保存提示按 reason 分流（v0.6.1 引入，v0.7.0 保持）——CLI 保存配置后会区分配置类型，避免对不影响 nft 的配置误提示等待 nft 应用：

**影响 nft 规则的配置 → 显示完整提示**

- 添加 / 删除 / 启用 / 禁用规则
- access_control（白名单 / 黑名单）
- GeoIP（含转发端口 / SSH 限制 / CN IP set 更新）
- egress_control（出口目标限制）
- SNAT（masquerade / fixed / off）
- MSS clamp
- quota 配置 / 自动禁用
- `stats.mode.update`（统计口径）
- `backup.restore`（从备份恢复）

这些保存后会提示 `nat.service` 自动检测并通过 safe apply 应用规则，并列出 `systemctl restart nat` / `nft list table ip self-nat` / `journalctl -u nat -n 120 --no-pager` 等排查命令。

**不影响 nft 规则的配置 → 显示简短提示**

- Telegram（bot_token / chat_id / 启用 / 通知间隔）
- UI timezone
- audit 显示 / 轮转配置

这些保存后只显示「配置已安全保存到 /etc/nat.toml。该配置不会改变 nft 转发规则，无需等待 nft 应用。」`telegram.*` 还会附加「状态页默认不会明文显示 bot_token」一行。

`启用 / 禁用规则` 会列出所有规则，选择某一条后再启用或禁用。旧配置缺少 `enabled` 字段时默认视为 `true`；`enabled = false` 的规则会保留在 `/etc/nat.toml`，但不会生成到 nft 规则，也不会进入默认连通性测试列表。

`最近来源 IP 观察（手动排查）` v0.4.3 起明确为**手动排查辅助入口**，**不自动采集**最近来源 IP，也不依赖白名单 / 黑名单。页面会打印 `conntrack -L` / `nft list table ip self-nat` / `nft list table ip self-filter` / `journalctl -u nat -n 120 --no-pager` 等命令，供用户在 shell 中手动观察。本项目不会自动安装 conntrack，也不会自动放行或封禁来源 IP，也不会修改访问控制配置。

`BBR / Telegram 状态` 子菜单可查看、开启、关闭 BBR；也可查看 Telegram 配置状态、配置 bot_token 和 chat_id、发送测试通知、启用 / 禁用通知、设置通知间隔。

## 配置文件

默认配置文件：

```text
/etc/nat.toml
```

示例：

```toml
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
comment = "example-http"
enabled = true

[access_control]
mode = "off"
entries = []

[stats]
enabled = true
collect_interval_seconds = 60
data_file = "/var/lib/nftables-nat-rust/stats.json"
traffic_mode = "both"

[telegram]
enabled = false
bot_token = ""
chat_id = ""
notify_interval_minutes = 60
notify_daily = true
notify_monthly = true

[ddns]
refresh_interval_seconds = 300

[dns]
reject_fake_ip = true
fake_ip_cidrs = ["198.18.0.0/15"]
resolver_mode = "system"
nameservers = []
fallback_to_system = true

[geoip]
enabled = false
provider = "chnlist"
cn4_url = "https://raw.githubusercontent.com/alecthw/chnlist/release/nftables/cn4.nft"
cn4_file = "/etc/nftables-nat/sets/cn4.nft"
update_interval_hours = 168
allow_lan = true
lan_cidrs = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
]

[geoip.forward]
enabled = false
mode = "allow-cn"
apply_to_ports = "forward-rules"

[geoip.ssh]
enabled = false
port = 22
mode = "allow-cn-and-lan"

[egress_control]
enabled = false
mode = "allow-targets"
allowed_target_cidrs = [
  "10.100.0.10/32",
  "10.100.0.0/24",
]

[snat]
mode = "masquerade"
fixed_source_ip = ""

[mss_clamp]
enabled = false
size = 1452

[last_good]
enabled = true
file = "/var/lib/nftables-nat-rust/last-good-state.json"
use_last_good_on_dns_failure = true

[audit]
enabled = true
file = "/var/log/nftables-nat-rust-audit.log"

[quota]
enabled = true
check_interval_seconds = 60
notify_on_exceeded = true
state_file = "/var/lib/nftables-nat-rust/quota-state.json"
```

## 服务管理

```bash
systemctl status nat --no-pager -l
systemctl restart nat
journalctl -u nat -f
```

## 更新

轻量 release 更新：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --update --core-only --use-release
```

指定版本（推荐使用当前稳定版 `v0.7.3`，或省略 `--version` 跟随 latest release）：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --update --core-only --use-release --version v0.7.3
```

CLI 更新：

```bash
nat --menu
```

选择：`一键更新本项目`

- CLI 一键更新成功后会自动重新载入新版 `nat --menu`，不需要手动退出再重新进入。
- 如果当前环境无 TTY 或自动重载失败，会显示 fallback 提示，请手动执行 `nat --menu` 进入新版菜单。
- v0.6.0 起：选择 latest 时 CLI 会尽量解析 GitHub 最新 release tag，并在更新摘要中直接显示真实版本号（例如 `目标版本：v0.5.2`、`选择来源：latest`）。解析失败时回退显示 `latest` 并附带 warning，此时仍交由 `install.sh` 走 latest release 流程，不影响最终更新结果。
- 指定版本（`2) 指定版本更新核心 nat` 或 `--version vX.Y.Z`）的语义保持不变，会原样传给 `install.sh --version`，摘要中 `选择来源` 显示 `specified`。

更新默认保留：

- `/etc/nat.toml`
- `/etc/nat.conf`
- `/var/lib/nftables-nat-rust/stats.json`
- `/etc/nftables-nat/backups/`

更新前会备份旧二进制和 service 文件到：

```text
/etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS/
```

如果旧版本的 CLI 一键更新没有可靠生效，可直接使用上面的 release 更新命令。新版 CLI 可通过 `nat --menu` -> `一键更新本项目` 更新核心 `nat`。

失败时会尝试回滚。

#### safe apply 用 hash 判断脚本是否变化（v0.6.1 引入，v0.7.0 保持）

nat.service 主循环以前用「`script != latest_script` 整字符串比较」判断是否要重新跑一次 safe apply。v0.6.1 起改用稳定 FNV-1a 64-bit hash（`nat_common::stable_script_hash`，在 `nat-common/src/hash.rs` 中实现）；v0.7.0 把该 helper 沉淀到 `nat-common::hash` 模块并通过 `nat_common::stable_script_hash` re-export，行为与 v0.6.1 完全等价。

- 相同输入 → 相同 hash，不会 apply；hash 变化 → 走原有 safe apply 流程
- hash 跨进程稳定（**不依赖** `std::collections::hash_map::DefaultHasher` 的随机种子），可在 audit / 日志里以 `0x<16hex>` 形式记录
- audit 事件 `apply.success` / `apply.fail` detail 带 `script_hash` 字段，便于排查"刚刚应用的是哪一版规则"
- **不引入新依赖**：FNV-1a 是 ~10 行纯 Rust 实现，复用现有工作区依赖
- 不改变 apply 触发条件、不改变 nft 脚本内容、不改变 last-good / stats / quota 任何语义

## 卸载

交互卸载：

```bash
bash install.sh --uninstall
```

或：

```bash
nat --menu
```

选择：`卸载 / 清理本项目`

默认保留 `/etc/nat.toml`、Stats、backups。完全删除需要输入 `DELETE`。卸载只清理本项目 `self-*` 表，不会 `flush ruleset`，不会删除用户其他 nftables table。

## 故障排查

### nat.service inactive

```bash
systemctl status nat --no-pager -l
journalctl -u nat -n 120 --no-pager
systemctl restart nat
```

### nft 规则未找到

```bash
nft list table ip self-nat
nft list table ip self-filter
journalctl -u nat -n 120 --no-pager
```

可能原因：

- `nat.service` 未运行
- `/etc/nat.toml` 规则尚未应用
- 规则配置解析失败
- fake-ip 被拒绝

### Stats 为 0

首次采集可能只是建立 baseline。请确认：

- `stats.enabled = true`
- 有外部流量经过转发规则
- `traffic_mode` 符合你的统计口径

统计口径：

- `both`：双向 out + in，默认推荐
- `out`：仅 client -> VPS -> target
- `in`：仅 target -> VPS -> client

可在 CLI 的 Stats 页面切换统计口径。切换后历史 daily/monthly 不会自动重算。

### 白名单导致不通

`access_control.mode = "whitelist"` 时，未命中白名单的来源不会匹配本项目转发规则。检查：

```toml
[access_control]
mode = "whitelist"
entries = ["你的来源IP/32"]
```

### GLIBC_x.xx not found

说明 release 二进制与系统 glibc 不兼容。请升级到修复后的 release，或在本机源码编译：

```bash
bash install.sh --core-only --build-from-source
```

### release asset 下载失败

可指定版本或回退源码编译：

```bash
bash install.sh --core-only --use-release --version v0.7.3
bash install.sh --core-only --build-from-source
```

### curl | bash 交互问题

推荐安装命令已使用非交互参数。需要交互时先下载脚本再执行：

```bash
tmp="$(mktemp)" && curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh -o "$tmp" && bash "$tmp" --core-only --use-release --enter-menu
```

## 项目结构（v0.7.0）

`nat-cli/src/`

- `main.rs`：入口、CLI 参数解析、顶层流程；`handle_loop` / `refresh_once` / `RuntimeConfig` / `parse_conf` / `build_new_script` 等仍保留在这里
- `apply.rs`：safe apply 全流程——`nft -c` 检查、ruleset 备份、`nft -f` 应用、失败回滚 managed tables（`MANAGED_TABLES`：`ip self-nat` / `ip6 self-nat` / `ip self-filter` / `ip6 self-filter`）
- `runtime.rs`：nat.service 主循环节奏——DDNS / Stats / quota 节流判定、`next_loop_sleep`、Stats 采集 + Telegram 通知触发、resolution events → audit 转写
- `quota_loop.rs`：quota 自动禁用检查——读 TOML + Stats、`quota::check_and_decide`、走 `menu::safe_write_config_to` 写回，备份失败跳过本轮
- `telegram.rs`：nat.service 侧 Telegram 客户端——`curl` 子进程、强制 `--connect-timeout 5 --max-time 15`、stderr 兜底脱敏 `bot_token`
- `menu.rs`：CLI 菜单主入口，以及尚未拆分的菜单逻辑（规则增删改、stats / quota 子菜单、access_control / GeoIP / egress / SNAT / MSS 子菜单、Telegram 配置、时间 / NTP 状态、测试连通性等）
  - `menu/update.rs`：一键更新——`update_menu`、`build_update_plan`、`github_latest_resolver`、latest tag 解析、自动重载新版 CLI
  - `menu/audit_view.rs`：「查看审计日志」子菜单——默认 CLI 友好格式 + 原始 JSON 切换
  - `menu/backup.rs`：配置备份 / 恢复 / `safe_write_config`——所有写 `/etc/nat.toml` 的生产路径统一走它（备份 → tmp+fsync+rename → audit）
- `config.rs` / `ip.rs` / `prepare.rs`：配置解析、IP / CIDR 辅助、启动准备

`nat-common/src/`

- `hash.rs`：`stable_script_hash`（FNV-1a 64-bit）+ `format_hash_hex`，跨进程稳定
- `atomic.rs`：原子写文件 helper（`<path>.tmp.<pid>` → fsync → rename，失败时清理 .tmp）
- `audit.rs`：audit log 写入 + 内置轻量轮转（`max_size_mb` / `max_backups` / `rotate`）+ secret 字段兜底脱敏
- `last_good.rs` / `quota.rs` / `stats.rs` / `geoip.rs` / `forward_test.rs` / `uninstall.rs` / `logger.rs`：保持各自原职责，v0.7.0 未改

非 Rust 部分：

- `install.sh` / `setup.sh` / `tests/install-dry-run.sh`：v0.7.0 未改
- `.github/workflows/`：v0.7.0 未改

## 维护路线

v0.7.x 进入 **bugfix-only / maintenance-only** 阶段。

承诺**不**做：

- 新增 WebUI
- 新增 tc HTB / ifb / rate_limit 限速
- 新增多租户 / server-agent 架构
- 新增数据库
- 任何破坏既有 CLI 文案 / 菜单编号 / TOML 字段语义的改动

可选维护项（按需推进，不许诺时间）：

- 继续拆分 `menu.rs` 剩余大块逻辑（stats / network / security 等子菜单）
- 统一更多测试结构、引入更多边界测试
- audit log 轮转边界继续增强（按时间轮转、轮转触发的 audit 自反映）
- install / update 文档继续打磨

bug fix 优先级（高 → 低）：

1. nat.service 死循环 / 异常退出 / 资源泄漏
2. 误改用户 nft 规则、误删 nat.toml、备份失败仍覆盖配置
3. 敏感字段（`bot_token` 等）泄露到 audit / 日志
4. quota / stats / last-good / safe apply 行为偏离文档
5. CLI 菜单可观测性、文案一致性

## 与原项目区别

| 功能 | 原项目 | 本项目 |
|---|---|---|
| 配置格式 | legacy | TOML + legacy 兼容 |
| 安全应用 | 基础 | `nft -c`、备份、失败回滚 |
| 管理范围 | nat 表 | 只管理 `self-nat` / `self-filter` |
| CLI | 基础 | `nat --menu` 运维菜单 |
| DDNS | 基础 | 自动刷新 + fake-ip 保护 |
| Stats | 无 | 每日/月度/每规则统计 |
| Telegram | 无 | 定时流量通知 |
| Access Control | 无 | 端口作用域白名单/黑名单 |
| GeoIP / CN IP 限制 | 无 | 转发端口 / SSH 只允许中国大陆 IPv4 |
| 出口目标限制 | 无 | 限制本机只能转发到指定目标 IP / CIDR |
| 安装 | 源码编译 | release 预编译优先 |

## Acknowledgements

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust)
- [endview/nftpf](https://github.com/endview/nftpf)
- [mora1n/pfwd](https://github.com/mora1n/pfwd)
- [alecthw/chnlist](https://github.com/alecthw/chnlist)：感谢其提供 nftables 配置示例和 `cn4.nft` 使用参考。本项目仅作为可选数据源接入，不代表该项目作者参与、认可或为本项目背书；中国大陆 IP 列表本身请以上游数据源为准。

以上项目提供了设计思路、基础实现参考或 nftables 配置示例，不代表其作者参与或为本项目背书。

## License

MIT License。保留原项目版权声明。
