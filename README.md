# nftables-nat-rust-enhanced

一个 CLI-first 的 nftables NAT 转发管理工具，适合个人 VPS 做固定端口转发、DDNS 目标转发、来源白名单控制和安全回滚管理。

特点：

- release 预编译安装，普通 VPS 不需要编译 Rust
- 只管理本项目的 `self-nat` / `self-filter` 表，不 `flush ruleset`
- 应用前执行 `nft -c`，失败自动回滚
- 支持单端口 / 端口段 / IPv4 / IPv6 / TCP / UDP / all
- 支持 Stats、quota、audit log、Telegram、last-good、dynamic_whitelist
- 不提供 WebUI，不做多租户，不做 tc/ifb 限速

当前稳定版本：**v0.8.2**。本项目在 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 基础上增强。

## 快速安装

安装并进入 CLI 菜单（推荐）：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --enter-menu
```

安装但不自动进入菜单：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release
```

指定版本安装（省略 `--version` 则跟随 latest release）：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --version v0.8.2
```

更新到指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --update --core-only --use-release --version v0.8.2
```

安装完成后会安装 `/usr/local/bin/nat` 与 `nat.service`，保留或创建 `/etc/nat.toml`，并启动服务。

推荐系统：Debian 11 / 12、Ubuntu 20.04 / 22.04 / 24.04。轻量安装依赖：

```bash
apt update && apt install -y curl ca-certificates nftables iproute2 iptables procps openssl tar nano
```

低配 VPS 不推荐源码编译，开发者或需要测试最新 main 时可用：

```bash
tmp="$(mktemp -d)" && cd "$tmp" && curl -fsSL https://github.com/misaka-cpu/nftables-nat-rust-enhanced/archive/refs/heads/main.tar.gz | tar xz --strip-components=1 && cargo build --release && bash install.sh --core-only
```

## 快速使用

进入交互菜单：

```bash
nat --menu
```

查看版本：

```bash
nat --version
# 示例输出：nat v0.8.2
```

常用流程：`nat --menu` → `添加单端口转发` / `添加端口段转发` → 等待一个检测周期或手动 `systemctl restart nat`。

服务管理：

```bash
systemctl status nat --no-pager -l
systemctl restart nat
journalctl -u nat -f
```

## 适合场景

- 个人 VPS 端口转发
- 固定入口端口转发到固定 IP / 域名目标
- DDNS 目标转发
- 多条明确规则的 TCP / UDP 转发
- 需要 audit / rollback / quota 的自用转发
- 需要来源白名单或 DDNS 动态来源白名单的场景

## 不适合场景

- 多租户面板
- 复杂代理分流
- Web 管理面板
- tc/ifb 限速系统
- 多出口负载均衡
- 用户态隧道 / Proxy Protocol / MPTCP
- 替代 Surge / Clash / HAProxy / Realm

本项目只做 Linux nftables DNAT / SNAT 规则管理，不做 TLS 解密、不终止 HTTPS、不做应用层协议封装。

## 核心功能

| 功能 | 说明 |
|---|---|
| NAT 转发 | 单端口、端口段、TCP/UDP/all、IPv4/IPv6，支持本机 redirect |
| DDNS 目标 | 目标域名自动解析，解析失败时可用 last-good 兜底 |
| access_control | 限制谁能访问入口（来源 IP/CIDR 白名单或黑名单） |
| dynamic_whitelist | 解析用户已有 DDNS 域名，动态扩展来源白名单 |
| GeoIP | 可选限制转发端口 / SSH 只允许中国大陆 IPv4 |
| egress_control | 限制本机能转发到哪些目标 IP/CIDR |
| Stats / quota | 统计流量并可按规则配额自动禁用规则 |
| audit log | 记录配置修改、apply、quota、dynamic whitelist 等事件 |
| Telegram | 关键事件通知，带超时，不阻塞主流程 |
| SNAT / MSS | 源地址改写（masquerade / fixed / off）与 TCP MSS clamp |

术语速查：

- `access_control`：限制谁能访问入口
- `dynamic_whitelist`：把 DDNS 解析结果加入来源白名单
- `egress_control`：限制本机能转发到哪里
- `last-good`：DNS 临时失败时复用上一次成功解析到的 IP

各功能的详细行为见下面的 [功能详解](#功能详解)。

## 配置示例

默认配置文件：`/etc/nat.toml`。一份较完整的示例：

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

[dynamic_whitelist]
enabled = false
refresh_interval_seconds = 300
use_last_good_on_dns_failure = true
resolve_ipv4 = true
resolve_ipv6 = false
notify_on_change = true
cidr_expand_ipv4 = 32
state_file = "/var/lib/nftables-nat-rust/dynamic-whitelist-state.json"

[[dynamic_whitelist.domains]]
name = "home"
domain = "home.example.com"
enabled = true

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

CLI 兼容旧版 `/etc/nat.conf` 读取逻辑。

## 常用菜单说明

主菜单（标题携带当前版本号，未注入版本时显示 `nft-nat-rust dev`）：

```text
====================================
nft-nat-rust v0.8.2
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

几个常用入口：

- **查看当前转发规则**：默认展示每条规则的核心字段（index / 状态 / type / sport / target / resolved / dport / protocol / ip_version / access_control / quota / egress），以及一行组合策略摘要和一行 last-good 摘要。页面尾部输入 `d` 展开完整组合策略 + 完整 last-good 状态缓存。
- **添加单端口 / 端口段转发**：会尽力用 `ss -lntup` 检测入口端口是否已被本机服务占用，发现占用时默认取消，输入 `y` 才继续并写 `port_conflict.override` audit。没有 `ss` 时只 warning，不阻塞，也不会自动安装依赖或 kill 进程。
- **测试转发规则连通性**：扫描 `ip/ip6 self-nat / self-filter`，结论分 `已应用` / `部分匹配` / `未确认` / `未应用`；不依赖 counter 非零，不会因检测未确认就自动重启 nat。CLI 默认只展示简短测试提示（`SERVER_IP:入口端口` + 协议提示），详细 `curl` / `nc` / SNI 示例可在测试页面输入 h 查看（按 `protocol` / `target` 分支生成）。
- **高级网络设置**：查看 / 设置 SNAT 模式、fixed SNAT 源 IP、MSS clamp、时间 / NTP 状态检查、查看全局诊断状态（完整组合策略 + 完整 last-good 状态缓存，仅查看不修改）。
- **查看审计日志**：默认按展示时区显示最近 50 行格式化日志，子菜单可切换原始 JSON。文件路径默认 `audit.file = /var/log/nftables-nat-rust-audit.log`，可用 `tail -F` / `grep` 直接查看。
- **最近来源 IP 观察（手动排查）**：只打印 `conntrack -L` / `nft list table ...` / `journalctl` 等命令供手动观察，不自动采集来源 IP，也不会放行或封禁来源。

菜单内输入 `menu` / `main` / `m` / `nat --menu` 刷新主菜单；输入 `q` / `quit` / `exit` / `0` 退出。

### 规则改动 / nat.service 应用延迟

CLI 修改任意配置时**只写 `/etc/nat.toml`**，不绕过安全 apply 直接 `nft -f`。`nat.service` 主循环每隔 `ddns.refresh_interval_seconds`（默认 300 秒）检测一次配置变化并通过安全流程应用。

因此：

- 刚改完配置后立即 `nft list table ip self-nat` 可能看不到新规则，**这不一定是 bug**，通常是还没跑完一个检测周期。
- 如需立即应用：`systemctl restart nat`。
- 「测试转发规则连通性」在 nft 未应用时会显示明确的 pending 提示。

## 安全设计

本项目的核心约束是**只管理自己的表、改动可回滚、不碰用户其他规则**：

- 只管理 `self-nat` / `self-filter` 表，不执行 `flush ruleset`，不修改用户其他 nftables table
- safe apply 流程：生成规则后先 `nft -c` 检查 → 备份当前 ruleset → `nft -f` 应用 → 失败回滚本项目 managed tables（`ip/ip6 self-nat`、`ip/ip6 self-filter`）
- nft comment 使用短 ID，规避 nftables comment 128 字符限制
- 配置写入统一走 `safe_write_config`：备份 → 临时文件 + fsync → rename 原子替换 → 写 audit；任何一步失败都保留旧文件
- audit log 记录配置修改与 nat.service 自动行为；Telegram `bot_token` / `chat_id` 在写入前脱敏
- `dynamic_whitelist` 是来源白名单增强，不会放开所有来源；`egress_control` 限制目标 IP；GeoIP 与 `access_control` 是 AND 叠加，不是互相绕过
- 卸载只清理本项目 `self-*` 表，默认保留 `/etc/nat.toml`、Stats、backups

> **Docker v28 兼容例外**：项目原则上只管理 `self-*` 表。唯一例外是：启动时若检测到 `ip filter FORWARD` 或 `ip6 filter FORWARD` 的默认 policy 是 `drop`（Docker v28 某些版本会这样设置），会写入 `chain ip(6) filter FORWARD { policy accept ; }`，否则转发链路会被默认 drop。这是一次性兼容修正，不修改链中的规则，也不接管 forward policy。如果不希望本项目触碰这条策略，请确保 `ip filter FORWARD` 的 policy 在 nat.service 启动前已经是 `accept`。

### 安全写配置

所有写 `/etc/nat.toml` 的生产路径（CLI 各子菜单、`quota` 自动禁用规则写回）都统一走 `safe_write_config`：

1. 先备份当前 `/etc/nat.toml` 到 `/etc/nftables-nat/backups/config/nat.toml.<reason>-YYYYmmdd-HHMMSS.bak`（权限 0600）
2. 把新内容写到临时文件 `<path>.tmp.<pid>`，best-effort `fsync` 后 `rename` 替换目标文件
3. 写一条 `config.write.success` audit（删除规则除外，见下文）

删除规则 `rule.delete` 默认不创建配置备份（避免无意义备份堆积），但仍走临时文件 + fsync + rename 原子写入，并写 audit，`config.write.success` detail 含 `backup_skipped = true`。

任何一步失败都不会覆盖原配置：备份失败写 `config.write.fail`（`stage=backup`）；临时文件 / rename 失败写 `config.write.fail`（`stage=write_or_rename`）。audit detail 永不写入 `bot_token` / `chat_id` / 任何 secret key。

保存提示按 reason 分流，避免对不影响 nft 的配置误提示等待 nft 应用：

- **影响 nft 规则的配置**（规则增删改、access_control、dynamic_whitelist 域名增删启停、GeoIP、egress_control、SNAT、MSS、quota、`stats.mode.update`、`backup.restore`）→ 显示完整提示并列出 `systemctl restart nat` / `nft list table ip self-nat` / `journalctl -u nat -n 120 --no-pager`。
- **不影响 nft 规则的配置**（Telegram、dynamic_whitelist 刷新间隔、UI timezone、audit 显示 / 轮转）→ 只显示「配置已安全保存…该配置不会改变 nft 转发规则，无需等待 nft 应用。」这类不影响 nft 规则的 reason 不会引导用户执行 `systemctl restart nat`。

## 功能详解

### 核心转发

- 单端口 / 端口段转发、本机 redirect
- IPv4 / IPv6，TCP / UDP / all
- 目标支持 IP、域名、DDNS
- TOML 配置，兼容旧版 `/etc/nat.conf`

### DDNS

- 域名目标自动解析，支持定时刷新
- 支持 fake-ip 检测，默认拒绝 `198.18.0.0/15`
- 解析临时失败时可用 last-good IP 兜底（见 [last-good](#last-good-状态缓存)），last-good 不绕过 `egress_control`

### 白名单 / 黑名单（access_control）

`access_control` 限制谁能访问本项目转发端口：

- 只作用于本项目转发端口，不影响 SSH，不影响用户其他 nftables table
- `entries` 支持 IP / CIDR
- `mode = "whitelist"`：只放行命中 `entries`（及 dynamic_whitelist 解析结果）的来源
- `mode = "blacklist"`：命中即拒绝

### GeoIP / 中国大陆 IP 限制

可选功能，默认关闭。默认通过 `cn4_url` 拉取 nftables 格式的 `cn4.nft` 作为中国大陆 IPv4 set 来源，仅 IPv4。

- 可限制转发端口只允许中国大陆 IPv4（+可选 LAN）访问
- 可选限制 SSH 只允许中国大陆 IPv4 和 LAN 访问；SSH 限制有锁死风险，开启前务必确认
- CN IP set 通过 CLI 手动下载并原子替换，下载失败保留旧文件
- 启用但 `cn4_file` 不存在或为空时，核心服务跳过 GeoIP 规则并 WARN
- GeoIP forward 限制基于 `cn4.nft`，**仅作用于 IPv4 转发规则**；IPv6 转发规则不受 GeoIP 限制，请用 `access_control` / `egress_control` 为 IPv6 规则做来源 / 目标控制

`cn4_url` 默认值只是一个参考数据源，中国大陆 IP 数据可能存在误差，使用前请自行确认；如需更严格来源，可替换为 APNIC、clang.cn、纯真、ipip.net 或其他你信任的数据源。

### access_control 与 GeoIP 的组合策略

`access_control`（黑/白名单）、`dynamic_whitelist`（动态 DDNS 来源白名单）与 `geoip`（国家/地区限制）是分层叠加的访问控制，使用 AND 逻辑：

```text
allow = (来源不在黑名单)
      AND (whitelist 模式关闭，或来源命中静态白名单 / dynamic_whitelist)
      AND (geoip.forward 关闭，或来源属于 CN/可选 LAN)
```

评估顺序（按 nft 链优先级）：

1. **黑名单优先级最高。** 命中即在 `self-nat PREROUTING` 中 drop，无论白名单 / GeoIP 状态。
2. **白名单是精确来源限制。** `mode = "whitelist"` 时只有 `entries` 或 dynamic_whitelist 当前解析出的来源能被 DNAT，其他来源等同于拒绝转发。
3. **GeoIP 是国家/地区来源限制。** `geoip.forward.enabled = true` 时 `self-filter GEOIP_PREROUTING`（优先级 -200，早于 PREROUTING 的 -110）drop 非 CN/LAN 来源。
4. **同时启用 = AND。** 三层依次叠加，必须同时满足才会被 DNAT。

不要理解为 OR：白名单不会绕过 GeoIP，GeoIP 也不会绕过白名单。GeoIP 与 access_control 两者可以同时启用，叠加生效，不是互相覆盖。组合不会 `flush ruleset`，只在本项目 `self-nat` / `self-filter` 表内叠加规则。

CLI 的「白名单 / 黑名单管理」默认页只显示来源访问控制的简洁摘要（mode / 静态 entries 数量 / 动态 DDNS 状态 / GeoIP / SSH GeoIP），完整组合策略通过子菜单「查看来源策略详情」按需展开。

### dynamic_whitelist / DDNS 来源白名单

`dynamic_whitelist` 用于自己的家宽 / 手机热点 / 公司出口 IP 经常变化的场景。用户先在自己的 DDNS 服务中维护域名解析，本项目只定期解析这些域名，把解析到的 IP 加入来源白名单。

它**是**：

- `access_control` 的来源 IP 白名单增强，限制「谁能访问入口」
- `access_control.mode = "whitelist"` 时才参与放行
- DNS 成功时解析到哪些 IP 就放行哪些；DNS 失败时可用 last-good 来源 IP 临时兜底
- IP 变化写 audit，可选 Telegram 通知

它**不是**：目标转发 DDNS、`egress_control`、目标 IP 限制、代理或用户态 relay；它不会自动更新 DDNS、不会调用任何 DNS 供应商接口、不会无限累积历史 IP。

最小示例：

```toml
[access_control]
mode = "whitelist"

[dynamic_whitelist]
enabled = true
refresh_interval_seconds = 300
use_last_good_on_dns_failure = true
resolve_ipv4 = true
resolve_ipv6 = false
cidr_expand_ipv4 = 32

[[dynamic_whitelist.domains]]
name = "home"
domain = "home.example.com"
enabled = true
```

行为说明：

- `enabled = false` 或 `domains` 为空时不生成动态白名单
- `mode = "off"` / `"blacklist"` 时可解析和显示状态，但不参与放行逻辑
- `mode = "whitelist"` 时，最终来源白名单 = 静态 `entries` + 当前动态解析得到的 effective sources
- 动态解析为空且静态白名单也为空时，不会自动开放所有来源；规则因无来源白名单无法匹配并 WARN
- GeoIP 同时开启仍是 AND
- 默认只解析 A 记录作为 IPv4 来源；`resolve_ipv6 = true` 时才尝试 AAAA
- state 文件默认 `/var/lib/nftables-nat-rust/dynamic-whitelist-state.json`，独立于目标 last-good state；损坏会 WARN 并尝试重新生成

DNS 成功 / 失败：

- 成功：更新 `current_ips` / `last_good_ips`，旧 IP 在下一次成功解析后自动移除
- 失败且 `use_last_good_on_dns_failure=true` 且有上一次成功 IP：临时保留 last-good 来源 IP，标记 `stale=true`
- 失败且没有 last-good：该 domain 不产生动态白名单 IP，不会放行所有来源，也不会 panic

#### IPv4 CIDR 扩展模式（v0.8.2）

`cidr_expand_ipv4` 默认 `32`，合法值只有 `32` 与 `24`，其它值在配置校验和 CLI 入口两侧都会被拒绝。

- `/32`（默认，推荐）：精确 IP 模式，A 记录解析到 `1.2.3.4` 就放行 `1.2.3.4/32`
- `/24`：宽松网段模式，A 记录解析到 `1.2.3.4` 就放行 `1.2.3.0/24`

第一版只支持 IPv4 扩展；`resolve_ipv6 = true` 时 AAAA 结果仍按精确 IPv6 地址处理，不做 prefix 扩展。

安全提醒：

- `/24` 会把单个 IP 扩展为 256 个 IPv4 地址，等同于把整段运营商出口放进白名单
- 只建议在确认手机 / 家宽出口 IP 经常在同一 `/24` 内变化时启用；不确定就保持默认 `/32`
- CLI 切换到 `/24` 必须二次确认，默认按 `N` 拒绝
- 只使用你自己控制的 DDNS；DDNS 账号被盗时攻击者可能把恶意 IP 加入白名单，建议保留至少一个静态白名单 IP 作为兜底，不要把 dynamic whitelist 当成公开访问授权机制

state 行为：

- DNS 成功时按当前 `cidr_expand_ipv4` 重算 `effective_sources`，**不会**无限累计历史网段
- DNS 失败用 last-good 时按**当前**模式重新扩展 last-good 原始 IP，保证模式切换立刻生效
- 切换 `/32 ↔ /24` 后下一次解析或刷新会重算并替换 `effective_sources`，不保留旧模式网段
- v0.8.2 之前的旧 state（无 `effective_sources` / `cidr_expand_ipv4` 字段）可兼容读取，读取后基于 `current_ips` 即时扩展
- `/24` 扩展只影响 dynamic_whitelist 来源白名单的最终条目，不影响静态 `entries`、`egress_control`、目标 DDNS / last-good、SSH GeoIP、SNAT、MSS、quota、stats

CLI / audit / Telegram：状态页与详细结果显示当前 `cidr_expand_ipv4`、原始 `raw_ips` 与扩展后的 `effective_sources`；`dynamic_whitelist.resolve.success` / `dynamic_whitelist.change` 事件记录 `raw_ips` / `effective_sources` / `cidr_expand_ipv4`；切换模式写 `dynamic_whitelist.cidr_expand.update` audit；`notify_on_change = true` 时只在 `effective_sources` 真正变化时通知，同一 `/24` 内 IP 抖动不会刷屏。

### egress_control（出口目标限制）

`egress_control` 限制本机只能把转发流量转发到指定目标 IP / IP 段，防止本机被滥用成开放代理转发器。

- 适合限制本机只能转发到自己的私有网络出口机、落地机、内网出口段
- 限制的是**目标 IP**，不是来源 IP；来源限制请用 `access_control` 或 GeoIP
- `enabled=true` 且 `allowed_target_cidrs` 为空时，所有转发规则都会被跳过并 WARN
- 目标 IP 不在 `allowed_target_cidrs` 内的规则会被跳过并 WARN
- 域名规则用当前 `resolved_ip` 与 `allowed_target_cidrs` 匹配；`disabled` 规则不参与检查

### SNAT 模式

`snat.mode` 控制 POSTROUTING 阶段的源地址改写方式。

- `mode = "masquerade"`（默认推荐）：由 nft 自动选择出接口源 IP，适合普通 VPS
- `mode = "fixed"`：生成 `snat to <fixed_source_ip>`，适合私有网络出口机需要固定中转源 IP 的场景；**第一版仅支持 IPv4**
- `mode = "off"`：**不生成** POSTROUTING SNAT 规则，必须由用户自行保证回程路由，否则转发可能不通；仅适合已配置好回程路由的高级用户

`fixed` 模式细节：`fixed_source_ip` 必须是合法 IPv4，空值 / IPv6 / 非法字符串在校验阶段报错；`ip_version` 为 IPv6 时回退到 `masquerade`，避免写出非法 nft 规则；同时存在 IPv4 与 IPv6 规则时，IPv4 用 `snat to <fixed_source_ip>`，IPv6 按 `masquerade` 处理，nat.service 不会因缺少 IPv6 fixed_source_ip 而失败。

```toml
[snat]
mode = "fixed"
fixed_source_ip = "10.100.0.10"
```

历史版本的 `nat_local_ip` / `nat_local_ipv6` 环境变量仅在 `mode = "masquerade"` 时作为兼容兜底；推荐新配置直接用 `snat.mode = "fixed"`。

### MSS clamp

`mss_clamp` 在转发链路上对 TCP SYN 包写入 `tcp option maxseg size set <size>`，缓解多跳 / 隧道 / MTU 异常场景下的测速异常、网页卡顿、TLS 握手卡死。

- 默认 `enabled = false`，不生成任何 MSS 规则
- 启用后仅作用于本项目转发相关 TCP 流量，按 DNAT 后的目标端口匹配 SYN 包；不生成全局 TCP MSS 规则、不影响 UDP、不影响非本项目端口
- `protocol = "udp"` 不生成；`protocol = "all"` 只对其中 TCP 生效
- 本机 `localhost` redirect 不生成 MSS clamp
- 不接管整机 forward policy，只在 `self-filter FORWARD` 链中添加规则
- `size` 合法范围 536-1460，常见值 1452；不懂 MTU/MSS 时不建议随意开启

### 组合策略说明

转发链路上可以同时启用以下功能，它们分层叠加：

| 功能 | 限制对象 | 控制方式 |
|---|---|---|
| `access_control` | 来源 IP / CIDR | 用户自定义白名单 / 黑名单 |
| `dynamic_whitelist` | 来源 IP | 解析用户已有 DDNS 域名并并入来源白名单 |
| `geoip` | 来源 IP（国家/地区） | 中国大陆 IPv4 set + 可选 LAN |
| `egress_control` | 目标 IP / CIDR | `allowed_target_cidrs` |
| `snat` | 源地址改写 | masquerade / fixed / off |
| `mss_clamp` | TCP MSS 调整 | enabled + size |

来源限制采用 AND 叠加：黑名单优先拒绝，白名单 / dynamic_whitelist 精确放行，GeoIP 地区放行；多个来源限制同时开启时采用叠加限制（AND），不是 OR 放行。目标限制（`egress_control`）独立于来源限制。SNAT 与 MSS clamp 不参与准入判断，只改变数据面行为，但当前值仍会在 CLI 状态页显示以免混淆。

### last-good 状态缓存

`last_good` 在 DDNS / 域名目标解析临时失败时复用上一次成功解析过的 IP，避免一次 DNS 抖动把可用规则变成不可用。

- 默认 `enabled = true`、`use_last_good_on_dns_failure = true`
- 缓存文件默认 `/var/lib/nftables-nat-rust/last-good-state.json`，原子写入（tmp + fsync + rename）
- 解析失败时：有 `last_good_ip` → 用 last-good IP 继续生成规则并 WARN；否则跳过该规则并 WARN
- last-good 不绕过 `egress_control` / `access_control` / `geoip`；不影响静态 IP 目标规则
- 缓存文件不写入 bot_token，写入失败仅 WARN

```toml
[last_good]
enabled = true
file = "/var/lib/nftables-nat-rust/last-good-state.json"
use_last_good_on_dns_failure = true
```

文件结构（节选）：

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

last-good 只是容错机制，不应长期掩盖 DNS 问题；请定期查看 audit log 和「查看当前转发规则」确认是否仍在 live DNS 路径。

### Stats 流量统计

- 每日 / 每月总流量，以及每条规则每日/月流量
- 通过 `self-filter FORWARD` 中的 `nat-traffic` counter 统计
- `traffic_mode` 支持 `both`（双向，默认推荐）/ `out`（client→VPS→target）/ `in`（target→VPS→client）
- CLI 可在 Stats 页面切换统计口径；切换后历史 daily/monthly 不会自动重算

### 规则级流量配额 quota

可为每条规则设置 `daily` / `monthly` / `total` 流量配额，超额后**自动禁用规则**（不删除）。

- 基于现有 Stats，按 `stats.traffic_mode` 当前口径统计；`stats.enabled = false` 时不生效
- 第一版仅支持 `quota_action = "disable"`：超额后 `enabled` 置 false 写回 `/etc/nat.toml`，由 safe apply 在下一轮移除该规则的 nft 规则，**不直接执行 `nft -f`、不删除规则**
- 自动禁用写回前会先备份到 `nat.toml.quota-auto-disable-*.bak`，备份失败则跳过本轮、下一轮再试
- Telegram 通知在每个 period 内通知一次，去重状态写在 `quota.state_file`
- 写 audit：`quota.exceeded` / `rule.disable.quota` / `quota.telegram.notify` 等
- 在 CLI 重新启用一条被 quota 禁用的规则时，若当前 period 仍超额会打印警告并清除该规则的通知去重记录

配额字节输入格式：纯字节数（如 `107374182400`）、十进制单位（如 `100GB`、`100MB`）；十进制 `KB`/`MB`/`GB`/`TB`（1000 进制）；短缀 `K`/`M`/`G`/`T` 与 `KiB`/`MiB`/`GiB`/`TiB`（1024 进制）。`quota_period = "total"` 的累计字节随当前 `traffic_mode` 累积，切换口径后历史 total 不会自动重算。

CLI 入口：`7) 查看 Stats 流量统计` → `3) 设置规则流量配额` / `4) 查看规则配额状态`。

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

### audit 审计日志

`audit` 记录用户通过 CLI 的配置修改以及 nat.service 自动行为中的关键事件。

- 默认 `enabled = true`，日志文件默认 `/var/log/nftables-nat-rust-audit.log`
- 每条日志为一行 JSON（至少含 `time` / `action` / `result` / `detail`），便于 `grep` / `jq`；`time` 为 UTC RFC3339
- 写入失败只 WARN，不让 nat.service / CLI 崩溃
- 不记录敏感明文：`bot_token` / `chat_id` 脱敏为 `头2***尾2`，其他常见 secret key 也兜底脱敏

常见事件：`rule.add` / `rule.delete` / `rule.enable` / `rule.disable`、`access_control.update` / `dynamic_whitelist.config.update` / `geoip.update` / `egress_control.update` / `snat.update` / `mss_clamp.update`、`apply.success` / `apply.fail`（带 `script_hash`）、`dns.resolve.fail` / `last_good.used`、`dynamic_whitelist.resolve.success` / `.resolve.fail` / `.change` / `.prune`、`rule.skipped.egress_control`、`update.*` / `uninstall.start` 等。

CLI `20) 查看审计日志` 默认显示最近 50 行格式化日志（按 `[ui].timezone`），子菜单可切换原始 JSON；任何展示路径都会再走 `redact` 兜底。

audit 内置轻量轮转（v0.6.0 起默认开启，best-effort）：默认 `rotate = true` / `max_size_mb = 10` / `max_backups = 3`；超阈值时滚动 `audit.log → .1 → .2 → .3`，`max_backups = 0` 时只截断当前文件，`rotate = false` 关闭内置轮转交给系统 logrotate。

```toml
[audit]
enabled = true
file = "/var/log/nftables-nat-rust-audit.log"
rotate = true
max_size_mb = 10
max_backups = 3
```

如使用系统 logrotate，可设 `audit.rotate = false` 并在 `/etc/logrotate.d/nftables-nat-rust-audit` 写入（`copytruncate` 适合 append 模式，无需重启 nat.service）：

```
/var/log/nftables-nat-rust-audit.log {
    daily
    rotate 14
    compress
    missingok
    copytruncate
}
```

### Telegram 通知

- 通过 `/etc/nat.toml` 或 CLI 配置 bot_token / chat_id，输入 bot_token 为明文方便确认
- CLI 可发送测试通知（不会自动启用通知）、设置通知间隔（分钟）、daily / monthly 流量通知
- bot_token 在状态输出中脱敏
- Telegram curl 调用强制 `--connect-timeout 5 --max-time 15`，API 不可达 / 网络抖动不会阻塞 nat.service 主循环；失败仅 WARN + audit，并对 stderr 兜底脱敏 bot_token

### BBR

CLI 可查看、启用或关闭 BBR。开关只处理本项目配置文件 `/etc/sysctl.d/99-nat-bbr.conf`，不会删除用户其他 sysctl 配置，也不会调用 `sysctl --system`。

### 时间显示与 NTP

CLI 显示的时间默认按 **Asia/Shanghai 24 小时制**（形如 `2026-05-19 20:02:58 CST`）；JSON 状态文件 / audit log 内部仍以 **UTC RFC3339** 存储。系统时区和 CLI 展示时区可以不同，本工具**不会**自动修改系统时区。

```toml
[ui]
timezone = "Asia/Shanghai"
time_format = "%Y-%m-%d %H:%M:%S %Z"
```

- `timezone`：合法 IANA 时区名（DST 由 `chrono-tz` 兜底），非法值在校验阶段报错
- `time_format`：chrono `strftime` 格式串

nft 转发本身不严格依赖系统时间，但 Stats 滚动重置、quota 周期判断、audit 时间戳、last-good 时间、TLS 证书校验建议系统时间准确。CLI 在 `19) 高级网络设置 → 时间 / NTP 状态检查` 提供查看状态、设置 CLI 展示时区、显示修改系统时区命令（只打印不执行）、尝试启用 NTP（需 y/N 确认）等子项；不会 `apt-get install` 任何东西，不会强制改时区。

## 典型使用场景

### 1. 普通公网端口转发

```text
客户端 → VPS 入口端口 → nft DNAT/SNAT → 目标服务
```

适合固定 IP 目标、固定端口的个人自用转发。

### 2. DDNS / 域名目标转发

```text
客户端 → VPS 入口端口 → DDNS 域名解析到目标 IP → 目标服务
```

域名解析成功后更新规则；DNS 失败时可用 last-good IP 兜底，last-good 不绕过 `egress_control`。

### 3. 入口机 / 私有网络出口机

```text
客户端 → 入口机 → nft DNAT/SNAT → 私有网络出口机 → 目标服务
```

推荐开启 `egress_control` 只允许转发到固定出口机 IP / 网段；如需固定源地址用 SNAT fixed；`SNAT=off` 仅适合已配置好回程路由的高级用户。

### 4. 安全固定目标转发

来源限制用 `access_control` / `dynamic_whitelist` / GeoIP（限制「谁能访问入口」），目标限制用 `egress_control.allowed_target_cidrs`（限制「本机能转发到哪里」）。两者不是同一个概念，同时开启时叠加限制，不互相绕过。

外部 HTTPS 测试中的证书 / SNI 取决于客户端访问域名和目标服务证书；本项目不终止 TLS，也不替目标服务处理证书。

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

可能原因：`nat.service` 未运行、规则尚未应用（等一个检测周期）、配置解析失败、fake-ip 被拒绝。

### Stats 为 0

首次采集可能只是建立 baseline。确认 `stats.enabled = true`、有外部流量经过转发规则、`traffic_mode` 符合你的统计口径。切换口径后历史 daily/monthly 不会自动重算。

### 白名单导致不通

`access_control.mode = "whitelist"` 时未命中白名单的来源不会匹配转发规则。检查：

```toml
[access_control]
mode = "whitelist"
entries = ["你的来源IP/32"]
```

### GLIBC_x.xx not found

release 二进制与系统 glibc 不兼容。升级到修复后的 release，或本机源码编译：

```bash
bash install.sh --core-only --build-from-source
```

### release asset 下载失败

指定版本或回退源码编译：

```bash
bash install.sh --core-only --use-release --version v0.8.2
bash install.sh --core-only --build-from-source
```

### curl | bash 交互问题

推荐安装命令已使用非交互参数。需要交互时先下载脚本再执行：

```bash
tmp="$(mktemp)" && curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh -o "$tmp" && bash "$tmp" --core-only --use-release --enter-menu
```

## 更新与卸载

CLI 更新：`nat --menu` → `一键更新本项目`。CLI 一键更新成功后会自动重新载入新版 `nat --menu`，不需要手动退出再进入；如果当前环境无 TTY 或自动重载失败，会显示 fallback 提示，请手动执行 `nat --menu`。选择 latest 时会尽量解析 GitHub 最新 release tag 并显示真实版本号，更新摘要中的『选择来源』字段显示 `latest` 或 `specified`。

更新默认保留 `/etc/nat.toml`、`/etc/nat.conf`、`stats.json`、`backups/`；更新前会把旧二进制和 service 文件备份到 `/etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS/`，失败时会尝试回滚。

卸载：`bash install.sh --uninstall` 或 `nat --menu` → `卸载 / 清理本项目`。默认保留 `/etc/nat.toml`、Stats、backups，完全删除需输入 `DELETE`。卸载只清理本项目 `self-*` 表，不会 `flush ruleset`。

## 项目结构

> 命名约定：项目正式名为 `nftables-nat-rust-enhanced`（GitHub 仓库、安装命令、release 资产、systemd 服务路径、配置 / 数据 / 日志目录均用此名）；CLI 主菜单标题为简称 `nft-nat-rust`，仅用于界面显示。两者指向同一项目。

release 包内容：`nat` / `install.sh` / `setup.sh` / `README.md` / `LICENSE` / `NOTICE`。

`nat-cli/src/`

- `main.rs`：入口、CLI 参数解析、顶层流程；`handle_loop` / `refresh_once` / `RuntimeConfig` / `parse_conf` / `build_new_script` / dynamic_whitelist 刷新与合并等
- `apply.rs`：safe apply 全流程（`nft -c` → ruleset 备份 → `nft -f` → 失败回滚 managed tables）
- `runtime.rs`：主循环节奏（DDNS / Stats / quota 节流、Stats 采集 + Telegram 触发、resolution events → audit）
- `quota_loop.rs`：quota 自动禁用检查
- `telegram.rs`：nat.service 侧 Telegram 客户端（curl 超时、stderr 兜底脱敏）
- `menu.rs`：CLI 菜单主入口及尚未拆分的菜单逻辑
  - `menu/update.rs`：一键更新；`menu/audit_view.rs`：审计日志查看；`menu/backup.rs`：配置备份 / 恢复 / `safe_write_config`
- `config.rs` / `ip.rs` / `prepare.rs`：配置解析、IP / CIDR / DNS 辅助、启动准备

`nat-common/src/`

- `hash.rs`：`stable_script_hash`（FNV-1a 64-bit）+ `format_hash_hex`
- `atomic.rs`：原子写文件 helper；`audit.rs`：audit log 写入 + 内置轮转 + secret 兜底脱敏
- `dynamic_whitelist.rs`：动态 DDNS 来源白名单 state、解析刷新、last-good 来源 IP 兜底
- `last_good.rs` / `quota.rs` / `stats.rs` / `geoip.rs` / `forward_test.rs` / `uninstall.rs` / `logger.rs`

非 Rust 部分：`install.sh` / `setup.sh` / `tests/install-dry-run.sh`、`.github/workflows/`（release 构建）。

源码编译依赖：

```bash
apt update && apt install -y git curl wget ca-certificates build-essential pkg-config libssl-dev nftables iproute2 iptables procps openssl tar nano
```

## 版本说明

### v0.8.2（当前稳定版）

- dynamic_whitelist 新增可选 IPv4 `/24` 扩展模式 `cidr_expand_ipv4`，默认 `/32` 精确 IP 行为不变；非 `32` / `24` 的值在配置校验和 CLI 两侧都会被拒绝
- state 文件新增 `raw_ips` / `effective_sources` / `cidr_expand_ipv4` 字段，旧 state 兼容读取、即时重算，模式切换不保留旧网段、不无限累计
- CLI 切换 `/24` 二次确认；audit / Telegram 记录原始与扩展后的来源，只在 `effective_sources` 变化时通知
- 不改 safe apply 主流程、nft 规则语义、组合策略

### v0.8.1

- CLI 白名单 / 黑名单管理与动态 DDNS 来源白名单子菜单的展示层级优化，不改 nft / safe apply / 组合策略

### v0.8.0

- 新增动态 DDNS 来源白名单（`dynamic_whitelist`）：定期解析用户已有 DDNS 域名并把 A 记录并入来源白名单；默认 disabled、默认 IPv4、独立 state 文件
- DNS 失败时可临时保留 last-good 来源 IP（标记 `stale`），不无限累计、不在无结果时开放所有来源
- 只在 `access_control.mode = "whitelist"` 时合并静态白名单 + dynamic whitelist，不影响 `egress_control` / 目标 DDNS / SSH GeoIP / SNAT / MSS / quota / stats

### v0.7.x

- 维护性重构：拆分 `main.rs` / `menu.rs`（safe apply、quota loop、runtime、telegram、update、audit_view、backup 等模块化），行为与 v0.6.x 完全一致
- safe apply 用稳定 FNV-1a 64-bit hash（`nat_common::stable_script_hash`）判断脚本是否变化，audit `apply.*` 新增 `script_hash` 字段，不引入新依赖
- 统一 `safe_write_config`（备份 → tmp+fsync → rename → audit）；删除规则默认 `backup_skipped`
- 保存提示按 reason 分流（影响 / 不影响 nft 两类）
- 进入 maintenance-only / bugfix-only 阶段

## 维护路线

后续保持 CLI-first / core-only。承诺**不**做：WebUI、tc/ifb 限速、多租户 / server-agent 架构、数据库存储、DNS 供应商接口，以及任何破坏既有 CLI 文案 / 菜单编号 / TOML 字段语义的改动。

可选维护项（按需推进，不许诺时间）：继续拆分 `menu.rs` 剩余子菜单、统一测试结构、audit 轮转按时间维度增强、install / update 文档打磨。

bug fix 优先级（高 → 低）：

1. nat.service 死循环 / 异常退出 / 资源泄漏
2. 误改用户 nft 规则、误删 nat.toml、备份失败仍覆盖配置
3. 敏感字段泄露到 audit / 日志
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
| Access Control | 无 | 端口作用域白名单/黑名单 + 动态 DDNS 来源白名单 |
| GeoIP / CN IP 限制 | 无 | 转发端口 / SSH 只允许中国大陆 IPv4 |
| 出口目标限制 | 无 | 限制本机只能转发到指定目标 IP / CIDR |
| 安装 | 源码编译 | release 预编译优先 |

## Acknowledgements

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust)
- [endview/nftpf](https://github.com/endview/nftpf)
- [mora1n/pfwd](https://github.com/mora1n/pfwd)
- [alecthw/chnlist](https://github.com/alecthw/chnlist)：感谢其提供 nftables 配置示例和 `cn4.nft` 使用参考。本项目仅作为可选数据源接入，不代表该项目作者参与、认可或为本项目背书；中国大陆 IP 列表本身请以上游数据源为准。

以上项目提供了设计思路、基础实现参考或 nftables 配置示例。

## License

MIT License。保留原项目版权声明。
