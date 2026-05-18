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

- 通过 `/etc/nat.toml` 配置 Telegram token / chat_id
- CLI 可配置 token 和 chat_id
- CLI 可发送测试通知，测试通知不会自动启用 Telegram 通知
- CLI 可设置通知间隔，单位分钟
- 支持定时通知
- 支持 daily / monthly 流量通知
- token 在状态输出中脱敏

### 白名单 / 黑名单

- 只作用于本项目转发端口
- 不影响 SSH
- 不影响用户其他 nftables table
- entries 支持 IP / CIDR

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
12) 最近来源 IP 观察
13) BBR / Telegram 状态
14) 测试转发规则连通性
15) 一键更新本项目
16) 卸载 / 清理本项目
0) 退出
```

菜单内误输入 `menu`、`main`、`m`、`nat --menu` 会刷新主菜单；输入 `q`、`quit`、`exit` 或 `0` 退出。

配置变更后，`nat.service` 通常会自动检测并通过安全流程应用规则。安全流程包括 `nft -c` 检查、备份当前规则、应用失败自动回滚。如未自动生效，可执行：

```bash
systemctl restart nat
```

`启用 / 禁用规则` 会列出所有规则，选择某一条后再启用或禁用。旧配置缺少 `enabled` 字段时默认视为 `true`；`enabled = false` 的规则会保留在 `/etc/nat.toml`，但不会生成到 nft 规则，也不会进入默认连通性测试列表。

`最近来源 IP 观察` 用于观察访问转发端口的来源 IP，不等同于白名单 / 黑名单，不会自动放行或封禁来源 IP，也不会修改访问控制配置。

`BBR / Telegram 状态` 子菜单可查看、开启、关闭 BBR；也可查看 Telegram 配置状态、配置 token 和 chat_id、发送测试通知、启用 / 禁用通知、设置通知间隔。

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
| 安装 | 源码编译 | release 预编译优先 |

## Acknowledgements

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust)
- [endview/nftpf](https://github.com/endview/nftpf)
- [mora1n/pfwd](https://github.com/mora1n/pfwd)

以上项目提供了设计思路或基础实现参考，不代表其作者参与或背书本项目。

## License

MIT License。保留原项目版权声明。
