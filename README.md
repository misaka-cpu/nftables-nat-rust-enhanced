# NFTables NAT Rust

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

基于 nftables 的高性能 NAT 端口转发管理工具，使用 Rust 语言开发。

## ✨ 核心特性

- 🔄 **动态 NAT 转发**：自动监测配置文件和目标域名 IP 变化，实时更新转发规则
- 🛡️ **防火墙过滤**：支持 Drop 功能，实现类似防火墙的黑名单过滤（INPUT/FORWARD链）
- 🌐 **IPv4/IPv6 双栈支持**：完整支持 IPv4 和 IPv6 NAT 转发和过滤
- 📝 **灵活配置**：支持传统配置文件和 TOML 格式，满足不同使用场景
- 🎯 **精准控制**：支持单端口、端口段、TCP/UDP 协议选择、IP地址和网段过滤
- 🔌 **本地重定向**：支持端口重定向到本机其他端口
- 🐋 **Docker 兼容**：与 Docker 网络完美兼容
- ⚡ **高性能轻量**：基于 Rust 编写，仅依赖标准库和少量核心库
- 🚀 **开机自启**：支持 systemd 服务管理，开机自动启动
- 🔍 **域名解析**：支持域名和 IP 地址，自动 DNS 解析和缓存
- 🖥️ **Web 管理界面**：提供可视化的 WebUI 管理配置和查看规则，并且支持切换后端地址
- 🧰 **终端管理菜单**：提供 SSH 终端交互入口，支持查看、添加、删除、备份和恢复规则

## 🖥️ 系统要求

适用于以下 Linux 发行版：

- CentOS 8+ / RHEL 8+ / Fedora
- Debian 10+ / Ubuntu 18.04+
- 其他支持 nftables 的现代 Linux 发行版

## ⚙️ 系统准备

### CentOS / RHEL / Fedora

```bash
# 关闭 firewalld
systemctl disable --now firewalld

# 关闭 SELinux
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

# 安装 nftables
yum install -y nftables
```

### Debian / Ubuntu

```bash
# 安装 nftables
apt update && apt install -y nftables

# 禁用 iptables（可选）
systemctl disable --now iptables
```

## 📦 快速安装

> 升级也使用相同的安装命令

### 统一安装入口 install.sh

从源码目录或已下载的 release 包中，可以使用 `install.sh` 作为统一安装入口。无参数运行时会显示交互菜单：

```bash
bash install.sh
```

菜单包含：

```text
1) 只安装核心转发服务 nat
2) 安装核心转发服务 nat + WebUI nat-console
3) 只安装 WebUI nat-console
4) 只安装/更新 WebUI 静态资源 assets
5) 卸载
0) 退出
```

也可以使用非交互参数：

```bash
bash install.sh --core-only      # 只安装核心 nat，不安装 WebUI，不安装 nodejs/npm
bash install.sh --with-console   # 安装核心 nat + WebUI nat-console
bash install.sh --console-only   # 只安装 WebUI nat-console
bash install.sh --assets-only    # 只安装/更新 WebUI 静态资源
bash install.sh --uninstall      # 卸载
bash install.sh --help           # 查看帮助
```

安全预演模式不会执行真实安装动作，适合先确认安装计划：

```bash
bash install.sh --dry-run --core-only
bash install.sh --dry-run --with-console
bash install.sh --dry-run --console-only
bash install.sh --dry-run --assets-only
```

安装脚本会优先使用当前目录的本地编译产物：

- `target/release/nat`
- `target/release/nat-console`

只有本地二进制不存在时，才下载 release 二进制。核心 nat 安装不会依赖 nodejs/npm；只有 WebUI 静态资源构建或更新流程才会检查 nodejs/npm。

## 🧰 CLI 终端管理菜单

除 WebUI 外，`nat` 二进制也提供 SSH 终端交互菜单，适合习惯命令行的管理员在服务器本机维护配置：

```bash
nat --menu
nat --menu --toml /etc/nat.toml
```

菜单入口：

```text
====================================
nftables-nat-rust 管理菜单
====================================
1) 查看当前转发规则
2) 添加单端口转发
3) 添加端口段转发
4) 删除转发规则
5) 启用/禁用规则
6) 查看当前 nft 规则
7) 查看 stats 流量统计
8) 手动刷新 DDNS / 域名目标
9) 备份当前配置
10) 从备份恢复配置
11) 白名单/黑名单管理
12) 最近来源 IP 观察
13) WebUI / BBR / Telegram 状态
0) 退出
====================================
```

Phase 4A 已实现查看规则、添加单端口、添加端口段、删除规则、只读查看本项目 nft 表、查看 stats、备份配置和恢复配置。启用/禁用、DDNS 手动刷新、白名单/黑名单、最近来源 IP 观察和状态聚合先保留为后续扩展入口。

CLI 菜单与 WebUI 使用同一份 `/etc/nat.toml`。CLI 更适合 SSH 老手和应急维护；WebUI 更适合不熟悉终端操作的用户。两者都不改变本项目的安全边界：本项目不会执行 `flush ruleset`，不会清空用户其他 nftables table，只管理 `self-nat` / `self-filter` 表。

配置备份目录：

```text
/etc/nftables-nat/backups/config/
```

删除或恢复配置前会先备份当前配置。备份文件权限设置为 `600`，避免配置里的敏感字段被普通用户读取。

本项目借鉴 nftpf 的终端交互体验，但不会照搬其全局 flush 行为；同时继续保留 WebUI、BBR、Stats 和 Telegram 通知能力。

### 方法一：TOML 配置文件版本（推荐）

```bash
bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup.sh) toml
```

### 方法二：传统配置文件版本

```bash
bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup.sh) legacy
```

## 🆕 WebUI 管理界面

本项目现已支持 Web 管理界面，可以通过浏览器方便地管理 NAT 配置。

- 🔐 基于 JWT 的安全认证
- 🔒 支持 HTTPS/TLS 加密传输
- 📝 可视化编辑配置文件（支持传统格式和 TOML 格式）
- 📋 实时查看 nftables 规则
- 🌐 支持多后端地址切换，可管理多台服务器
- 🎨 现代化的用户界面

### 安装管理界面 WebUI

```bash
bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup-console.sh) # -p 5533  -k /root/.acme.sh/arloor.dev/arloor.dev.key -c /root/.acme.sh/arloor.dev/fullchain.cer
```

1. 安装过程会交互式提示或自动生成 WebUI 登录凭据。默认用户名为 `admin`，默认密码不再是 `admin`；如果没有通过环境变量指定密码，安装脚本会生成随机强密码。
2. 通过 `-p` 参数可以指定 WebUI 监听端口，默认端口为 5533。
3. 通过 `-c` 和 `-k` 参数可以指定自定义 TLS 证书和私钥文件路径，如果未提供，将自动生成自签名证书。
4. 安装脚本会自动检测现有 NAT 服务的配置格式，并根据配置格式生成相应的 systemd service 文件。

安装完成后，访问 `https://your-server-ip:5533` 即可使用管理界面。

WebUI 安全相关环境变量：

```bash
export NAT_CONSOLE_USERNAME=admin
export NAT_CONSOLE_PASSWORD='your-strong-password'
export NAT_CONSOLE_PORT=5533
export NAT_CONSOLE_BIND=0.0.0.0
export NAT_CONSOLE_JWT_SECRET='your-random-jwt-secret'
```

如果未设置 `NAT_CONSOLE_PASSWORD` 或 `NAT_CONSOLE_JWT_SECRET`，安装脚本会自动生成。不要复用默认口令，不要公开 JWT secret。WebUI 默认可能监听 `0.0.0.0`，请结合防火墙、反向代理或安全组限制访问来源。

**多后端管理**：登录页面可配置后端 API 地址，支持跨域访问不同服务器。在"后端设置"标签页可添加、切换多个后端地址，方便管理多台服务器。留空后端地址则使用当前服务器。

详细文档请查看 [nat-console/README.md](nat-console/README.md)

### 升级 WebUI

```bash
bash <(curl -sSLf https://us.arloor.dev/https://github.com/arloor/nftables-nat-rust/releases/download/v2.0.0/setup-console-assets.sh)
systemctl restart nat-console
```

### WebUI 页面

![alt text](image.png)

![alt text](image1.png)

### BBR API

WebUI 提供 BBR 状态和开启接口：

```text
GET  /api/bbr/status
POST /api/bbr/enable
```

`POST /api/bbr/enable` 会写入本项目自己的配置文件：

```text
/etc/sysctl.d/99-nat-bbr.conf
```

内容为：

```text
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

随后只加载本项目配置：

```bash
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -p /etc/sysctl.d/99-nat-bbr.conf
```

不会使用 `sysctl --system`。

## 📝 配置说明

### TOML 配置文件（推荐）

配置文件位置：`/etc/nat.toml`

**优势**：

- ✅ 支持配置验证，保证格式正确
- ✅ 支持注释，便于维护
- ✅ WebUI 可视化编辑和验证
- ✅ 结构化配置，可读性更好

```toml
# ============ NAT 转发规则 ============

# 1. 单端口转发 - HTTPS 流量转发
[[rules]]
type = "single"
sport = 10443          # 本机监听端口
dport = 443            # 目标服务端口
domain = "example.com" # 目标域名或 IP 地址
protocol = "all"       # 协议: all, tcp 或 udp
ip_version = "ipv4"    # IP 版本: ipv4, ipv6 或 all
comment = "转发 HTTPS 到 example.com"

# 2. 端口段转发 - 批量游戏端口
[[rules]]
type = "range"
port_start = 20000     # 起始端口
port_end = 20100       # 结束端口（含）
domain = "game.example.com"
protocol = "tcp"       # 仅 TCP 协议
ip_version = "all"     # 同时支持 IPv4 和 IPv6
comment = "游戏服务器端口段"

# 3. UDP 专用转发 - DNS 服务
[[rules]]
type = "single"
sport = 5353           # 本机 DNS 端口
dport = 53             # 目标 DNS 端口
domain = "8.8.8.8"     # 也可以直接使用 IP 地址
protocol = "udp"       # 仅 UDP 协议
ip_version = "ipv4"
comment = "DNS 查询转发"

# ============ 本地重定向规则 ============

# 4. 单端口重定向到本机服务
[[rules]]
type = "redirect"
sport = 8080           # 外部访问端口
dport = 3128           # 本机实际服务端口
protocol = "all"
ip_version = "ipv4"
comment = "代理服务端口重定向"

# 5. 端口段重定向到本机
[[rules]]
type = "redirect"
sport = 30001          # 起始端口
sport_end = 30100      # 结束端口
dport = 45678          # 本机目标端口
protocol = "tcp"
ip_version = "all"
comment = "批量端口重定向到本机"

# ============ 防火墙过滤规则 (Drop) ============

# 6. 阻止特定 IPv4 地址访问
[[rules]]
type = "drop"
chain = "input"                    # 链类型: input 或 forward
src_ip = "180.213.132.211"        # 源 IP 地址
protocol = "all"                   # 协议: all, tcp 或 udp
comment = "阻止恶意 IP 访问"

# 7. 阻止 IPv6 网段访问
[[rules]]
type = "drop"
chain = "input"
src_ip = "240e:328:1301::/48"     # IPv6 网段
protocol = "all"
comment = "阻止 IPv6 网段访问"

# 8. 阻止特定端口（如 SSH）
[[rules]]
type = "drop"
chain = "input"
dst_port = 22                      # 目标端口
protocol = "tcp"
comment = "阻止 SSH 端口访问"

# 9. 阻止端口范围
[[rules]]
type = "drop"
chain = "forward"
dst_port = 1000                    # 起始端口
dst_port_end = 2000                # 结束端口
protocol = "tcp"
comment = "阻止转发到端口范围 1000-2000"

# 10. 组合过滤：特定IP访问特定端口
[[rules]]
type = "drop"
chain = "input"
src_ip = "192.168.1.0/24"         # 源 IP 网段
dst_port = 3306                    # 目标端口 (MySQL)
protocol = "tcp"
comment = "阻止内网访问 MySQL"

# ============ 高级场景示例 ============

# 11. 强制 IPv6 转发
[[rules]]
type = "single"
sport = 9001
dport = 9090
domain = "ipv6.example.com"
protocol = "all"
ip_version = "ipv6"    # 仅使用 IPv6 进行转发
comment = "IPv6 专用服务"

# 12. 双栈支持示例 - 自动选择 IPv4/IPv6
[[rules]]
type = "single"
sport = 10080
dport = 80
domain = "dual-stack.example.com"  # 域名同时有 A 和 AAAA 记录
protocol = "tcp"
ip_version = "all"     # 根据客户端 IP 版本自动选择
comment = "双栈 Web 服务"

# ============ DNS / fake-ip 防护 ============

[dns]
reject_fake_ip = true
fake_ip_cidrs = ["198.18.0.0/15"]
resolver_mode = "system"
nameservers = ["1.1.1.1:53", "8.8.8.8:53"]
fallback_to_system = true

# ============ DDNS / 域名目标自动刷新 ============

[ddns]
refresh_interval_seconds = 60

# ============ 流量统计与 Telegram 通知 ============

[stats]
enabled = false
collect_interval_seconds = 60
data_file = "/var/lib/nftables-nat-rust/stats.json"

[telegram]
enabled = false
bot_token = ""
chat_id = ""
notify_interval_minutes = 60
notify_daily = true
notify_monthly = true

# ============ 白名单 / 黑名单访问控制 ============

[access_control]
mode = "off" # off / whitelist / blacklist
entries = []
```

如果系统使用 Surge、Clash、sing-box 等 fake-ip DNS，域名转发可能被解析到 `198.18.0.0/15`。本项目默认拒绝 fake-ip，避免把错误地址写入 `dnat` 规则。当前 `resolver_mode = "system"` 沿用系统解析但会做 fake-ip 检查；`custom` resolver 作为后续扩展预留。正式环境建议使用真实 IP、正常 DDNS，或后续配置 custom DNS resolver。

`[ddns]` 控制 nat 主循环重新解析配置和域名目标的间隔，单位是秒。旧配置没有 `[ddns]` 时默认 `60` 秒。低于 `10` 秒会拒绝启动；`10` 到 `59` 秒允许用于测试但会输出 WARN。建议测试环境使用 `30` 秒，正式环境使用 `300` 到 `600` 秒。项目继续复用 nat 主循环，不需要额外 systemd timer。

`[access_control]` 默认关闭，只作用于本项目管理的转发端口，不影响 SSH、WebUI 或用户其他 nftables table。`entries` 只支持 IP/CIDR，不支持域名；IPv4 entries 用于 `table ip`，IPv6 entries 用于 `table ip6`。

白名单示例：

```toml
[access_control]
mode = "whitelist"
entries = ["1.2.3.4", "5.6.7.0/24"]
```

whitelist 模式下，只有来源 IP 命中 entries 的连接才会匹配本项目 DNAT/REDIRECT 规则；未命中连接不会被本项目转发。启用前请确认需要访问转发端口的来源 IP 已加入白名单。

黑名单示例：

```toml
[access_control]
mode = "blacklist"
entries = ["8.8.8.8", "9.9.9.0/24"]
```

blacklist 模式下，本项目只针对已配置的转发监听端口生成 drop，不生成全局 drop，不影响 SSH/WebUI。访问控制 drop counter 不计入正常转发流量统计。

### 流量统计

启用 `[stats]` 后，nat 会周期性执行只读命令 `nft -j list ruleset`，只解析本项目管理的表：

- `table ip self-nat`
- `table ip6 self-nat`
- `table ip self-filter`
- `table ip6 self-filter`

统计文件默认路径：

```text
/var/lib/nftables-nat-rust/stats.json
```

当 `stats.enabled = true` 时，如果统计文件父目录不存在会自动创建；如果 `stats.json` 不存在，会自动写入初始状态。即使 `rules = []`，也会初始化统计文件。初始化失败只写日志，不影响 nat 主循环或 WebUI。

当前第一版只保留当天和当月统计，不做历史报表。

WebUI/API：

```text
GET  /api/stats
POST /api/stats/reset-daily
POST /api/stats/reset-monthly
```

### Telegram 定时通知

Telegram 配置示例：

```toml
[telegram]
enabled = true
bot_token = "123456:example-bot-token"
chat_id = "123456789"
notify_interval_minutes = 60
notify_daily = true
notify_monthly = true
```

`notify_interval_minutes` 的单位是分钟。`bot_token` 是敏感凭据，不要提交到公开仓库，不要在日志、截图或 issue 中公开。WebUI 的 Telegram 状态接口只返回脱敏 token。

WebUI/API：

```text
GET  /api/telegram/status
POST /api/telegram/test
```

`POST /api/telegram/test` 只有在 Telegram 已启用，并且 `bot_token` 与 `chat_id` 都非空时才会发送测试消息。

### 测试机验证流程

以下命令用于测试机验证安装和 WebUI/API。请先确认当前 SSH 连接和防火墙策略，避免误操作影响远程访问。

```bash
cargo build --release
bash install.sh --dry-run --with-console
bash install.sh --console-only
systemctl restart nat-console
curl -k https://127.0.0.1:5533/api/stats
curl -k https://127.0.0.1:5533/api/telegram/status
```

如果 WebUI 启用了登录认证，请先通过 `/api/login` 获取认证 Cookie 或 Bearer token，再访问受保护 API。

### 传统配置文件

配置文件位置：`/etc/nat.conf`

**基础格式**：

- `SINGLE,本机端口,目标端口,目标地址[,协议][,IP版本]` - 单端口转发
- `RANGE,起始端口,结束端口,目标地址[,协议][,IP版本]` - 端口段转发
- `REDIRECT,源端口,目标端口[,协议][,IP版本]` - 重定向到本机端口
- `REDIRECT,起始端口-结束端口,目标端口[,协议][,IP版本]` - 端口段重定向
- `DROP,链类型,过滤条件[,协议]` - 防火墙过滤规则

**参数说明**：

- 协议可选值：`tcp`、`udp`、`all`（默认为 `all`）
- 链类型可选值：`input`、`forward`
- 过滤条件格式：`key=value`，支持 `src_ip`、`dst_ip`、`src_port`、`dst_port`
- 端口格式：支持单个端口(如 `dst_port=443`)和端口段（如 `dst_port=1000-2000`）
- ip地址格式：支持单个 IP（如`192.168.1.0`）和IP 网段（如`192.168.1.0/24`）
- 以 `#` 开头的行为注释

**配置示例**：

```bash
# ============ 基础转发 ============

# 单端口转发 - HTTPS 流量
SINGLE,10443,443,example.com

# 端口段转发 - 游戏服务器端口（20000-20100）
RANGE,20000,20100,game.example.com

# ============ 协议指定 ============

# 仅转发 TCP 流量 - Web 服务
SINGLE,10080,80,web.example.com,tcp

# 仅转发 UDP 流量 - DNS 查询
SINGLE,5353,53,8.8.8.8,udp

# ============ 本地重定向 ============

# 单端口重定向到本机服务
REDIRECT,8080,3128

# 端口段重定向到本机（30001-30100 → 45678）
REDIRECT,30001-30100,45678

# TCP 专用重定向
REDIRECT,7000-7100,8080,tcp

# ============ IPv6 支持 ============

# 强制使用 IPv6 转发
SINGLE,9001,9090,ipv6.example.com,all,ipv6

# 双栈支持（根据客户端自动选择）
SINGLE,10080,80,dual-stack.example.com,tcp,all

# ============ 防火墙过滤规则 (Drop) ============

# 阻止特定 IPv4 地址访问
DROP,input,src_ip=180.213.132.211,all

# 阻止 IPv6 网段访问
DROP,input,src_ip=240e:328:1301::/48,all

# 阻止 SSH 端口访问（所有IP）
DROP,input,dst_port=22,tcp

# 阻止端口范围转发
DROP,forward,dst_port=1000-2000,tcp

# 组合过滤：阻止特定网段访问MySQL
DROP,input,src_ip=192.168.1.0/24,dst_port=3306,tcp

# 阻止特定源端口
DROP,forward,src_port=5000-6000,tcp

# 禁用的规则（以 # 开头）
# SINGLE,3000,3000,disabled.example.com
```

## 🚀 使用方法

### 启动/停止服务

```bash
# 启动服务
systemctl start nat

# 停止服务
systemctl stop nat

# 重启服务
systemctl restart nat

# 查看服务状态
systemctl status nat

# 开机自启
systemctl enable nat

# 取消开机自启
systemctl disable nat
```

### 修改配置

修改配置文件后，程序会在 **60 秒内自动应用新配置**，无需手动重启服务。

```bash
# TOML 版本
vim /etc/nat.toml

# 传统版本
vim /etc/nat.conf
```

### 查看日志

```bash
# 实时查看日志
journalctl -fu nat

# 查看详细日志
journalctl -exfu nat

# 查看最近 100 行日志
journalctl -u nat -n 100
```

### 查看 nftables 规则

```bash
# 查看所有规则
nft list ruleset

# 仅查看 NAT 表
nft list table ip self-nat
nft list table ip6 self-nat6
```

## 🔧 高级配置

### 自定义源 IP（多网卡场景）

默认使用 masquerade 自动处理 SNAT。如需指定源 IP：

```bash
# 设置自定义源 IP
echo "nat_local_ip=10.10.10.10" > /opt/nat/env

# 重启服务
systemctl restart nat
```

## 🐋 Docker 兼容性

本工具已与 Docker 完全兼容。程序会自动调整 nftables 规则以适配 Docker 网络。

> **说明**：Docker v28 将 filter 表 forward 链默认策略改为 DROP，本工具会自动将其重置为 ACCEPT 以确保 NAT 规则正常工作。

## 📌 注意事项

### REDIRECT 类型限制

`REDIRECT` 类型工作在 PREROUTING 链，仅对外部流量有效：

- ✅ **有效**：外部机器访问重定向端口 → 成功重定向
- ❌ **无效**：本机进程访问重定向端口 → 不会重定向

**原因**：本机流量直接进入 OUTPUT 链，不经过 PREROUTING 链。

**示例**：

```bash
# 配置：REDIRECT,8000,3128
curl http://remote-server:8000  # ✅ 成功重定向到 3128
curl http://localhost:8000      # ❌ 不会重定向，直接访问 8000
```

### TLS/Trojan 转发

转发 TLS/Trojan 等加密协议时，常见问题是证书配置错误。

**解决方案**：

1. **简单**：客户端禁用证书验证
2. **推荐**：正确配置证书和域名，确保证书域名与中转机匹配

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 🙏 Acknowledgements / Credits

本项目基于 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 修改，保留原项目 MIT License 与版权声明。

功能设计上参考了以下 MIT License 项目的思路：

- [endview/nftpf](https://github.com/endview/nftpf)：CLI 菜单、DDNS、访问控制、备份与回滚等管理体验。
- [mora1n/pfwd](https://github.com/mora1n/pfwd)：端口转发管理思路。

以上为开源项目致谢与设计思路参考说明，不表示相关作者参与了本项目开发，也不表示本项目复制了上述项目代码。详见 [NOTICE](NOTICE)。

## 🔗 相关链接

- **项目地址**：https://github.com/arloor/nftables-nat-rust
- **问题反馈**：https://github.com/arloor/nftables-nat-rust/issues
- **前代项目**：[arloor/iptablesUtils](https://github.com/arloor/iptablesUtils)（不兼容）

---

**注意**：与旧版 iptablesUtils 不兼容，切换时请先卸载旧版或重装系统。
