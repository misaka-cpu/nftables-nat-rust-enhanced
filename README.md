# nftables-nat-rust-enhanced

`nftables-nat-rust-enhanced` 是基于 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 增强的 CLI-first nftables NAT 转发管理工具。本项目当前为纯 CLI-first 工具，不提供 WebUI。

核心原则：

- release 预编译安装，普通 VPS 不需要编译 Rust
- 只管理本项目的 `self-nat` / `self-filter` 表
- 不执行 `flush ruleset`
- 应用 nft 前执行 `nft -c`
- 应用前备份，失败自动回滚本项目 managed tables
- CLI 菜单管理 `/etc/nat.toml`

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

### BBR

CLI 菜单可查看、启用或关闭 BBR。开启/关闭只处理本项目配置文件 `/etc/sysctl.d/99-nat-bbr.conf`，不会删除用户其他 sysctl 配置，也不会调用 `sysctl --system`。

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

指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --version v0.1.4 --enter-menu
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

release 构建会显示 GitHub tag，例如 `v0.2.2`。源码编译如果没有注入 tag，可能显示开发版本或在更新菜单中显示 `unknown`。

菜单：

```text
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
14) 最近来源 IP 观察
15) BBR / Telegram 状态
16) 测试转发规则连通性
17) 一键更新本项目
18) 卸载 / 清理本项目
0) 退出
```

`GeoIP / CN IP 限制` 子菜单包含：查看状态、下载 / 更新 CN IP set、启用或禁用转发端口 CN 限制、启用或禁用 SSH CN 限制（需要输入 `CONFIRM`）、设置 SSH 端口、设置更新间隔。

`出口目标限制` 子菜单包含：查看状态、启用或禁用、添加 / 删除 / 列出允许目标 IP / CIDR。出口目标限制用于限制本机只能把转发流量转发到指定出口机或出口网段，它不是来源 IP 白名单。

菜单内误输入 `menu`、`main`、`m`、`nat --menu` 会刷新主菜单；输入 `q`、`quit`、`exit` 或 `0` 退出。

配置变更后，`nat.service` 通常会自动检测并通过安全流程应用规则。安全流程包括 `nft -c` 检查、备份当前规则、应用失败自动回滚。如未自动生效，可执行：

```bash
systemctl restart nat
```

`启用 / 禁用规则` 会列出所有规则，选择某一条后再启用或禁用。旧配置缺少 `enabled` 字段时默认视为 `true`；`enabled = false` 的规则会保留在 `/etc/nat.toml`，但不会生成到 nft 规则，也不会进入默认连通性测试列表。

`最近来源 IP 观察` 用于观察访问转发端口的来源 IP，不等同于白名单 / 黑名单，不会自动放行或封禁来源 IP，也不会修改访问控制配置。

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

指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --update --core-only --use-release --version v0.1.4
```

CLI 更新：

```bash
nat --menu
```

选择：`一键更新本项目`

- CLI 一键更新成功后会自动重新载入新版 `nat --menu`，不需要手动退出再重新进入。
- 如果当前环境无 TTY 或自动重载失败，会显示 fallback 提示，请手动执行 `nat --menu` 进入新版菜单。

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
bash install.sh --core-only --use-release --version v0.1.4
bash install.sh --core-only --build-from-source
```

### curl | bash 交互问题

推荐安装命令已使用非交互参数。需要交互时先下载脚本再执行：

```bash
tmp="$(mktemp)" && curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh -o "$tmp" && bash "$tmp" --core-only --use-release --enter-menu
```

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
