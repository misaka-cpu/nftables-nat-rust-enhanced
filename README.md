# nftables-nat-rust-enhanced

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

`nftables-nat-rust-enhanced` 是基于 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 修改增强的 nftables NAT 转发管理工具，面向 Debian / Ubuntu 服务器，用于管理端口转发、域名/DDNS 目标、访问控制、流量统计、Telegram 通知和 WebUI 运维。

本项目的核心安全边界：

- 不执行 `flush ruleset`
- 只管理本项目自己的 `self-nat` / `self-filter` 表
- 应用 nft 前先执行 `nft -c`
- 应用前备份当前 ruleset
- 应用失败自动回滚本项目 managed tables
- WebUI 和 CLI 共用 `/etc/nat.toml`

## 功能特性

### 核心转发

- 单端口转发
- 端口段转发
- 本机 redirect
- IPv4 / IPv6
- TCP / UDP / all
- IP、域名、DDNS 目标
- TOML 配置，兼容旧配置读取逻辑

### 安全 nft 应用

- `nft -c -f <generated-file>` 预检查
- 应用前备份完整 ruleset
- `nft -f` 失败时自动回滚
- 不清空用户其他 nftables table
- 不影响 SSH / WebUI / 用户自有规则
- nft comment 使用短 ID，规避 nftables 128 字符限制

### WebUI

- 可选安装，不强制安装
- HTTPS Web 管理界面
- JWT 登录认证
- WebUI 绑定地址可选：
  - `127.0.0.1`，推荐，配合 SSH 隧道
  - `0.0.0.0`，仅适合局域网或已配置防火墙环境
  - 自定义绑定地址
- 密码与 JWT secret 存放在 `/opt/nat-console/env`
- systemd `ExecStart` 不暴露 `--password` / `--jwt-secret`

### CLI 菜单

- `nat --menu` 终端交互菜单
- 查看、添加、删除转发规则
- 备份 / 恢复配置
- 查看 stats
- 查看本项目 nft 表
- 白名单 / 黑名单管理入口
- 每次操作完成后按 Enter 返回主菜单，主菜单会重新清屏绘制

### Stats 流量统计

- 每日总流量
- 每月总流量
- 每条规则每日/月流量
- 使用 `self-filter FORWARD` 中的 `nat-traffic` counter
- 不统计 DNAT 新连接包
- 不统计 POSTROUTING masquerade
- 不统计 blacklist drop counter
- 支持 `traffic_mode = "both"` / `"out"` / `"in"` 选择统计口径
- 支持 `POST /api/stats/collect-now` 立即采集

### Telegram 通知

- WebUI 配置 Telegram
- 支持 Bot Token / Chat ID / 通知间隔
- 支持测试通知
- 支持定时通知
- `notify_interval_minutes` 单位为分钟
- API 状态只返回脱敏 token

### fake-ip 保护

- 默认拒绝 `198.18.0.0/15`
- 避免 Clash / Surge / sing-box fake-ip DNS 结果写入 nft DNAT
- 支持 `[dns]` 配置 fake-ip CIDR

### 白名单 / 黑名单

- 默认关闭
- 只作用于本项目转发端口
- 不生成全局 drop
- 不影响 SSH / WebUI / 用户其他服务
- entries 只支持 IP / CIDR，不支持域名

### BBR

- WebUI/API 查看 BBR 状态
- 可写入本项目 sysctl 配置并加载
- 不使用 `sysctl --system`

## 系统要求

推荐：

- Debian 12
- Debian 11
- Ubuntu 20.04 / 22.04 / 24.04

轻量安装依赖（使用 GitHub Release 预编译二进制，不需要 Rust 工具链）：

```bash
apt update && apt install -y curl ca-certificates nftables iproute2 iptables procps openssl tar nano
```

源码编译依赖：

```bash
apt update && apt install -y git curl wget ca-certificates build-essential pkg-config libssl-dev nftables iproute2 iptables procps openssl tar nano
```

使用 release 二进制时不需要安装 `build-essential`、`pkg-config`、`libssl-dev`、`rustup`、`cargo`。只有从源码构建时才需要 Rust / Cargo。

## 快速安装

当前仓库：

```text
https://github.com/misaka-cpu/nftables-nat-rust-enhanced
```

### 轻量安装 / 预编译二进制安装

推荐普通用户使用 GitHub Release 预编译安装，安装更快，占用内存更少，不需要 Rust 工具链。脚本会按当前系统架构选择 release asset：

```text
nftables-nat-rust-enhanced-linux-amd64.tar.gz
nftables-nat-rust-enhanced-linux-arm64.tar.gz
SHA256SUMS
```

每个 tar.gz 包含 `nat`、`nat-console`、`static/`、`install.sh`、`setup.sh`、`setup-console.sh`、`setup-console-assets.sh`、`README.md`、`LICENSE`、`NOTICE`。下载后如果 `SHA256SUMS` 可用，安装脚本会校验 SHA256；校验失败或资产不匹配会停止，不会静默执行错误版本。

当前 release workflow 第一版构建并发布 `linux-amd64`。`linux-arm64` 是安装脚本支持的资产命名；如果 Release 暂未提供 arm64 包，脚本会提示没有匹配预编译包并 fallback 到源码编译，或可显式使用 `--build-from-source`。

正式 VPS 的 WebUI 建议绑定 `127.0.0.1`，并通过 SSH 隧道访问；`0.0.0.0` 只建议局域网或已配置防火墙时使用。

核心 + WebUI：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --with-console --use-release
```

只装核心：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release
```

只装 WebUI：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --console-only --use-release
```

dry-run 预演：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --dry-run --with-console --use-release
```

只安装核心服务后，可以通过 `nat --menu` 进入终端管理菜单。

### 从源码构建并安装

开发者、需要测试最新 `main`、需要自定义修改、或当前架构没有预编译包时，使用源码编译安装：

```bash
tmp="$(mktemp -d)" && cd "$tmp" && curl -fsSL https://github.com/misaka-cpu/nftables-nat-rust-enhanced/archive/refs/heads/main.tar.gz | tar xz --strip-components=1 && cargo build --release && bash install.sh --with-console
```

安装核心 + WebUI 时，安装脚本会刷新 systemd、启用并启动/重启 `nat.service` 和 `nat-console.service`，随后对 WebUI 执行本机健康检查：

```bash
curl -k https://127.0.0.1:5533/health
```

如果健康检查失败，请先查看 `nat-console` 状态和日志，不要只看服务是否 enabled。

```bash
apt update
apt install -y \
  git curl wget ca-certificates \
  build-essential pkg-config libssl-dev \
  nftables iproute2 iptables procps openssl \
  tar nano

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

git clone -b main https://github.com/misaka-cpu/nftables-nat-rust-enhanced.git
cd nftables-nat-rust-enhanced

cargo build --release

bash install.sh --dry-run --with-console
bash install.sh --with-console --build-from-source
```

### 只安装核心转发服务

```bash
cargo build --release
bash install.sh --dry-run --core-only
bash install.sh --core-only
```

### 只安装 WebUI

```bash
cargo build --release
bash install.sh --dry-run --console-only
bash install.sh --console-only
```

### 交互式安装菜单

```bash
bash install.sh
```

菜单：

```text
1) 只安装核心转发服务 nat
2) 安装核心转发服务 nat + WebUI nat-console
3) 只安装 WebUI nat-console
4) 只安装/更新 WebUI 静态资源 assets
5) 卸载
0) 退出
```

## install.sh 参数

```text
--core-only      只安装核心转发服务 nat
--with-console   安装核心转发服务 nat + WebUI nat-console
--console-only   只安装 WebUI nat-console
--assets-only    只安装/更新 WebUI 静态资源
--dry-run        预演安装计划，不写文件、不启动服务、不安装依赖
--use-release    优先从 GitHub Releases 下载预编译二进制
--build-from-source
                 强制源码编译 cargo build --release
--version <tag>  指定 release 版本，例如 v0.1.0；默认 latest
--repo <owner/repo>
                 指定 release 仓库；默认 misaka-cpu/nftables-nat-rust-enhanced
--uninstall      卸载服务文件和二进制，保留用户配置
--help           显示帮助
```

示例：

```bash
bash install.sh --dry-run --core-only
bash install.sh --dry-run --with-console --use-release
bash install.sh --core-only --use-release
bash install.sh --with-console --use-release
bash install.sh --console-only --use-release
bash install.sh --assets-only
bash install.sh --with-console --version v0.1.0 --repo misaka-cpu/nftables-nat-rust-enhanced
bash install.sh --with-console --build-from-source
```

默认行为：

- 如果当前源码目录已有 `target/release/nat` / `target/release/nat-console`，默认优先使用本地构建产物。
- 如果缺少所需本地二进制，默认尝试下载 GitHub Release 预编译包。
- `--use-release` 会优先下载 release，即使本地存在构建产物。
- release 下载失败、架构不匹配或校验失败时，会明确输出错误并 fallback 到源码编译；可用 `--build-from-source` 强制源码编译。
- dry-run 模式只显示计划下载的 asset、校验和 fallback 流程，不会真实下载、安装、执行 systemctl、nft、apt-get。

核心 nat 安装不依赖 nodejs/npm；使用 release payload 更新 WebUI assets 时也不需要 nodejs/npm。

## WebUI 安全访问

推荐选择绑定：

```text
127.0.0.1
```

然后通过 SSH 隧道访问：

```bash
ssh -p 22369 -L 5533:127.0.0.1:5533 root@VPS_IP
```

浏览器访问：

```text
https://127.0.0.1:5533
```

如果你希望本地浏览器使用另一个端口，例如 `15533`：

```bash
ssh -p 22369 -L 15533:127.0.0.1:5533 root@VPS_IP
```

则浏览器访问：

```text
https://127.0.0.1:15533
```

端口映射关系说明：

- `ssh -p 22369 -L 15533:127.0.0.1:5533 root@VPS_IP` 对应浏览器打开 `https://127.0.0.1:15533`
- `ssh -p 22369 -L 5533:127.0.0.1:5533 root@VPS_IP` 对应浏览器打开 `https://127.0.0.1:5533`

### SSH known_hosts 指纹变化

如果 VPS 重装、重建、换系统或更换 SSH host key，本地 SSH 客户端可能报错：

```text
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
Host key verification failed.
```

这不是本项目 bug，而是本地 `known_hosts` 缓存了旧主机指纹。

Windows 下如果 SSH 端口不是 22，例如 `22369`：

```bash
ssh-keygen -R "[你的VPS_IP]:22369"
```

然后重新连接隧道：

```bash
ssh -p 22369 -L 15533:127.0.0.1:5533 root@你的VPS_IP
```

浏览器访问：

```text
https://127.0.0.1:15533
```

如果使用默认 22 端口：

```bash
ssh-keygen -R "你的VPS_IP"
```

macOS / Linux 也可能遇到同样问题，处理命令相同：

```bash
ssh-keygen -R "[你的VPS_IP]:你的SSH端口"
```

常见 `known_hosts` 路径：

```text
Windows: C:\Users\你的用户名\.ssh\known_hosts
macOS/Linux: ~/.ssh/known_hosts
```

安全提醒：只有在确认 VPS 确实是自己重装、重建或更换系统后，才删除旧 host key。如果你没有重装或更换服务器，却突然出现该警告，应先确认是否连错 IP 或存在中间人攻击风险。

如果选择 `0.0.0.0`：

- 仅建议局域网或已配置防火墙/安全组的环境
- 必须使用强密码
- 不要把 WebUI 直接暴露到公网

WebUI 凭据文件：

```text
/opt/nat-console/env
```

权限应为：

```text
root:root
600
```

示例，敏感值已脱敏：

```env
NAT_CONSOLE_BIND="127.0.0.1"
NAT_CONSOLE_PORT="5533"
NAT_CONSOLE_USERNAME="admin"
NAT_CONSOLE_PASSWORD="***"
NAT_CONSOLE_JWT_SECRET="***"
NAT_CONSOLE_CERT="/etc/ssl/nat-webui.crt"
NAT_CONSOLE_KEY="/etc/ssl/nat-webui.key"
```

## 文件路径

```text
/etc/nat.toml                                  TOML 配置文件
/etc/nat.conf                                  legacy 配置文件，兼容保留
/usr/local/bin/nat                             核心转发服务二进制
/usr/local/bin/nat-console                     WebUI 二进制
/lib/systemd/system/nat.service                nat systemd 服务
/lib/systemd/system/nat-console.service        WebUI systemd 服务
/opt/nat-console/env                           WebUI 环境变量和密钥
/etc/ssl/nat-webui.crt                         WebUI TLS 证书
/etc/ssl/nat-webui.key                         WebUI TLS 私钥
/var/lib/nftables-nat-rust/stats.json          流量统计数据
/etc/nftables-nat/backups/                     nft ruleset 和配置备份
/etc/nftables-nat/backups/config/              配置备份目录
```

## TOML 配置示例

完整示例：

```toml
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
comment = "http-forward"

[[rules]]
type = "single"
sport = 34120
dport = 44336
domain = "example.com"
protocol = "all"
ip_version = "ipv4"
comment = "https-all"

[[rules]]
type = "range"
port_start = 30000
port_end = 30010
domain = "1.2.3.4"
protocol = "tcp"
ip_version = "ipv4"
comment = "range-forward"

[[rules]]
type = "redirect"
sport = 18080
dport = 8080
protocol = "tcp"
ip_version = "ipv4"
comment = "local-redirect"

[stats]
enabled = true
collect_interval_seconds = 60
data_file = "/var/lib/nftables-nat-rust/stats.json"
traffic_mode = "both" # both / out / in

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
nameservers = ["1.1.1.1:53", "8.8.8.8:53"]
fallback_to_system = true

[access_control]
mode = "off" # off / whitelist / blacklist
entries = []
```

`traffic_mode` 说明：

- `both`：双向统计，`out + in`，默认推荐。
- `out`：只统计 `client -> VPS -> target`。
- `in`：只统计 `target -> VPS -> client`。
- 旧配置不写 `traffic_mode` 也会按 `both` 处理；建议显式写出，方便确认当前统计口径。
- 如果 VPS/商家按单向流量计费，可根据实际计费方向选择 `out` 或 `in`。
- 切换 `traffic_mode` 后，历史 daily/monthly 不会自动重算；建议重置今日/月后重新统计。
- 首次采集可能仅建立 baseline，不会把历史 nft counter 全部算入今日流量。

白名单示例：

```toml
[access_control]
mode = "whitelist"
entries = ["1.2.3.4", "5.6.7.0/24"]
```

黑名单示例：

```toml
[access_control]
mode = "blacklist"
entries = ["8.8.8.8", "9.9.9.0/24"]
```

DDNS 建议：

```toml
[ddns]
refresh_interval_seconds = 300
```

- 测试环境可以使用 30 秒
- 生产环境建议 300～600 秒
- 小于 10 秒会拒绝启动

## 服务管理命令

核心服务：

```bash
systemctl status nat
systemctl start nat
systemctl stop nat
systemctl restart nat
journalctl -u nat -f
```

WebUI 服务：

```bash
systemctl status nat-console
systemctl start nat-console
systemctl stop nat-console
systemctl restart nat-console
journalctl -u nat-console -f
```

只读查看本项目 nft 表：

```bash
nft list table ip self-nat
nft list table ip self-filter
nft list table ip6 self-nat
nft list table ip6 self-filter
```

## CLI 菜单

启动：

```bash
nat --menu
/usr/local/bin/nat --menu
nat --menu --toml /etc/nat.toml
```

核心安装完成后，直接执行 `nat --menu` 即可进入终端管理菜单；如果 PATH 未刷新，也可以使用 `/usr/local/bin/nat --menu`。

菜单中的“测试转发规则连通性”可选择某条规则，查看规则详情、当前 counter baseline、目标 TCP 可达性，并给出外部客户端测试命令。本机直接 `curl 127.0.0.1:监听端口` 通常不能完整验证 DNAT，因为本机流量不一定走 PREROUTING；推荐从另一台机器访问 `服务器IP:监听端口`，再观察 `nat-rule` / `nat-traffic out` / `nat-traffic in` counter 是否增长。

HTTPS/SNI 场景建议使用：

```bash
curl -vk --connect-to 目标域名:目标端口:服务器IP:监听端口 https://目标域名/
```

菜单示例：

```text
====================================
nftables-nat-rust-enhanced 管理菜单
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
14) 测试转发规则连通性
0) 退出
```

CLI 菜单会直接操作 `/etc/nat.toml`，删除、恢复和访问控制等危险操作会先备份配置。

## WebUI API 概览

```text
GET  /health
POST /api/login
POST /api/logout
GET  /api/me

GET  /api/config
POST /api/config
GET  /api/rules

GET  /api/bbr/status
POST /api/bbr/enable

GET  /api/stats
POST /api/stats/config
POST /api/stats/collect-now
POST /api/stats/reset-daily
POST /api/stats/reset-monthly

GET  /api/telegram/status
POST /api/telegram/config
POST /api/telegram/test

GET  /api/access-control/status
GET  /api/forward-test/rules
POST /api/forward-test/check
POST /api/forward-test/observe

GET  /api/uninstall/status
POST /api/uninstall
```

WebUI 的“规则查看”页内分为两个子页：

- `nft 规则`：查看当前已应用的 `self-nat` / `self-filter` 规则，并支持复制规则文本。
- `转发测试`：选择规则后做只读检查和 counter 观察。

转发测试会读取配置、读取 `nft -j list ruleset`、检查 `nat.service` 状态、对 TCP 目标做 3 秒 connect 测试，并生成外部测试命令；不会修改配置、不会执行 `nft -f`、不会重启 systemd。测试完成后可点击“测试完成后刷新统计”调用现有 `POST /api/stats/collect-now` 更新流量统计。

本机直接 `curl 127.0.0.1:监听端口` 通常不能完整验证 DNAT，因为本机流量不一定走 PREROUTING。推荐从另一台机器访问 `服务器IP:监听端口`，再观察 DNAT 和 FORWARD counter 是否增长。HTTPS/SNI 场景可使用：

```bash
curl -vk --connect-to 目标域名:目标端口:服务器IP:监听端口 https://目标域名/
```

`POST /api/stats/collect-now` 只执行只读 `nft -j list ruleset` 并更新 `stats.json`，不会执行 `nft -f`、不会重启服务、不会改规则、不会发送 Telegram。

`POST /api/telegram/test` 会真实发送 Telegram 测试消息。只有在 Telegram 已启用，并且 `bot_token` / `chat_id` 配置完整时才会发送。

## 卸载

交互卸载：

```bash
bash install.sh --uninstall
```

交互卸载菜单支持输入 `0` 取消；直接按 Enter 也会默认取消，不会停止服务、删除文件或清理 nft 表。

非交互目标示例：

```bash
bash install.sh --uninstall --core
bash install.sh --uninstall --console
bash install.sh --uninstall --all
```

CLI 卸载：

```bash
nat --menu
```

选择“卸载 / 清理本项目”。

WebUI 卸载：

```text
卸载 / 清理 -> 选择目标 -> 选择数据保留策略 -> 执行卸载 / 清理
```

默认会保留：

- `/etc/nat.toml`
- `/etc/nat.conf`
- `/etc/nftables-nat/backups/`
- `/var/lib/nftables-nat-rust/stats.json`
- `/opt/nat-console/env`
- `/etc/ssl/nat-webui.crt`
- `/etc/ssl/nat-webui.key`

完全删除配置、统计、备份、WebUI env/cert/key 时必须输入：

```text
DELETE
```

默认不会执行 purge；只有选择完全删除并输入 `DELETE` 后才会删除配置和数据。

卸载只清理本项目组件和本项目 nft 表：

- `table ip self-nat`
- `table ip6 self-nat`
- `table ip self-filter`
- `table ip6 self-filter`

不会 `flush ruleset`，不会删除用户其他 nftables table，不会删除 SSH、防火墙、系统网络配置，也不会卸载 nftables/Rust/cargo 或用户安装的依赖。

## 安全说明

- 本项目不执行 `flush ruleset`
- 本项目只管理：
  - `table ip self-nat`
  - `table ip6 self-nat`
  - `table ip self-filter`
  - `table ip6 self-filter`
- nft 应用流程包含：
  - `nft -c`
  - 备份 ruleset
  - 应用
  - 失败回滚
- WebUI secret 从 `/opt/nat-console/env` 读取
- `/opt/nat-console/env` 权限应为 `600`
- `systemctl status nat-console` 不应直接显示 WebUI 密码/JWT secret
- Telegram `bot_token` 不要公开，不要截图
- WebUI 配置管理页会显示真实 TOML，可能包含 `bot_token`
- nft comment 使用短 ID，例如：

```text
nat-rule:id=r0
nat-traffic:id=r0,dir=out
nat-traffic:id=r0,dir=in
nat-access:id=r0,mode=blacklist
```

这样可以避免 nftables comment 128 字符限制。用户 TOML 里的长备注、中文备注仍保留在配置、WebUI、CLI 和统计标签中，不完整写入 nft comment。

access_control 安全边界：

- 只作用于本项目转发端口
- 不影响 SSH
- 不影响 WebUI
- 不影响用户其他 nftables table
- whitelist 未命中时只是不匹配本项目 DNAT，不生成全局 drop
- blacklist 只对本项目监听端口生成 drop

## 常见问题

### WebUI 打不开

检查服务：

```bash
systemctl status nat-console --no-pager -l
journalctl -u nat-console -n 120 --no-pager
ss -lntp | grep 5533
curl -k https://127.0.0.1:5533/health
```

如果 `nat-console` 是 `inactive (dead)`，可以手动启动或重启：

```bash
systemctl restart nat-console
```

如果 WebUI 绑定 `127.0.0.1`，需要 SSH 隧道：

```bash
ssh -p 22369 -L 5533:127.0.0.1:5533 root@VPS_IP
```

然后访问：

```text
https://127.0.0.1:5533
```

### 规则没生效

检查服务和 nft 表：

```bash
systemctl status nat
journalctl -u nat -f
nft list table ip self-nat
nft list table ip self-filter
```

如果 `nft -c` 检查失败，规则不会应用。请查看 `nat` 日志中的错误。

### 域名解析成 198.19.x.x

`198.18.0.0/15` 常见于 fake-ip DNS。默认配置会拒绝该结果，避免生成错误 DNAT：

```toml
[dns]
reject_fake_ip = true
fake_ip_cidrs = ["198.18.0.0/15"]
```

建议生产环境使用真实 IP、正常 DDNS，或确保系统 DNS 不返回 fake-ip。

### 流量统计为 0

可能原因：

- `stats.enabled = false`
- `nat` 服务未运行
- 还没有命中转发流量
- stats 首次采集只建立 baseline，不把已有 counter 当作新增流量
- WebUI 未点击“立即采集并刷新”

检查：

```bash
cat /var/lib/nftables-nat-rust/stats.json
nft list table ip self-filter
```

### 白名单后访问不通

whitelist 模式下，只有 `entries` 中的来源 IP/CIDR 能命中本项目转发规则。确认访问来源公网 IP 已加入白名单。

```toml
[access_control]
mode = "whitelist"
entries = ["1.2.3.4"]
```

### HTTPS 目标访问证书/SNI 问题

本项目做的是 TCP/UDP 层 NAT 转发，不会修改 TLS SNI 或证书。浏览器访问时证书校验仍取决于目标服务证书和访问域名是否匹配。

### comment too long

nftables comment 最大 128 字符。本项目已改为短 comment ID，不再把完整域名或用户备注写入 nft comment。若仍出现该错误，请确认运行的是当前增强版二进制：

```bash
/usr/local/bin/nat --version
```

并优先使用本地构建产物重新安装：

```bash
cargo build --release
bash install.sh --core-only
```

## 和原项目区别

| 功能 | arloor/nftables-nat-rust | enhanced |
| --- | --- | --- |
| 核心 nftables NAT 转发 | 支持 | 支持 |
| WebUI | 基础/原始能力 | 可选安装，含 BBR、Stats、Telegram 配置 |
| CLI 菜单 | 无 | `nat --menu` |
| 安全 apply | 简单应用 | `nft -c`、备份、失败回滚 |
| flush ruleset | 原项目行为以其实现为准 | 明确不 flush 全局 ruleset |
| 管理范围 | NAT 规则生成 | 只管理 `self-nat` / `self-filter` |
| BBR | 无 | API + WebUI |
| Stats | 无 | 每日/月、per-rule、collect-now |
| Telegram | 无 | WebUI 配置、测试、定时通知 |
| fake-ip 保护 | 无 | 默认拒绝 `198.18.0.0/15` |
| access control | 有限 | 全局 whitelist / blacklist，仅作用本项目转发端口 |
| WebUI bind | 非重点 | 127.0.0.1 / 0.0.0.0 / 自定义 |
| WebUI secret | 命令行参数风险 | `/opt/nat-console/env` |
| nft comment 长度 | 可能受用户备注影响 | 短 ID 规避 128 字符限制 |

## Acknowledgements

This project is based on and modified from:

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) — original nftables NAT forwarding project, MIT License.

Feature ideas and design references:

- [endview/nftpf](https://github.com/endview/nftpf) — terminal menu, DDNS refresh, access-control, backup/rollback design ideas.
- [mora1n/pfwd](https://github.com/mora1n/pfwd) — port-forwarding management ideas.

These projects inspired parts of the design, but this fork keeps its own implementation and safety model. The referenced authors are not responsible for this fork unless explicitly stated.

## License

MIT License.

Original project:

```text
Copyright (c) 2020 arloor
```

Enhanced modifications:

```text
Copyright (c) 2026 misaka-cpu
```

Please keep the original copyright and license notices when redistributing modified versions.

详见：

```text
LICENSE
NOTICE
```
