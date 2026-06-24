# nftables-nat-rust-enhanced

CLI-first 的 nftables NAT 转发管理工具，适合个人 VPS 做固定端口转发、DDNS 目标、来源白名单、SNAT、Stats/quota 和安全回滚。

当前版本：**v0.8.10**。在 [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust) 基础上增强。

- release 预编译安装，普通 VPS 不用编译 Rust
- 只管理本项目的 `self-nat` / `self-filter` 表，不 `flush ruleset`
- 应用前 `nft -c` 检查，失败自动回滚
- 单端口 / 端口段，IPv4 / IPv6，TCP / UDP / all

## 快速安装

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --version v0.8.10 --enter-menu
```

安装后会部署 `/usr/local/bin/nat` 与 `nat.service`，保留或创建 `/etc/nat.toml` 并启动服务。常用命令：

```bash
nat --menu                              # 进入管理菜单
nat --version                           # 例如 nat v0.8.10
systemctl status nat --no-pager -l
```

常用流程：`nat --menu` → 添加规则 → 等一个检测周期，或 `systemctl restart nat` 立即应用。

推荐系统：Debian 11/12、Ubuntu 20.04/22.04/24.04。其它安装方式（不进菜单、指定版本更新、自建 mirror、离线上传 binary/asset、源码编译）见[更多安装方式](#更多安装方式)。

## 适合场景

- 个人 VPS 端口转发，固定入口端口转发到固定 IP / 域名
- DDNS 目标转发
- 多 IP 机器用 per-rule `snat_ip` 指定出口
- 需要来源白名单、dynamic_whitelist、quota、audit 的自用转发

## 不适合场景

- WebUI 面板、多租户
- 复杂代理分流、多出口负载均衡
- tc/ifb 限速、省市级地域防火墙
- 用户态隧道 / Proxy Protocol / MPTCP
- 替代 Surge / Clash / HAProxy / Realm

本项目只做 Linux nftables DNAT / SNAT 规则管理，不做 TLS 解密，不终止 HTTPS，不做应用层封装。

## 核心功能

| 功能 | 说明 |
|---|---|
| NAT 转发 | 单端口 / 端口段，TCP/UDP/all，IPv4/IPv6，支持本机 redirect |
| 规则编辑 | 增 / 删 / 改 / 启停规则，保存走安全写入 + audit |
| global.enabled | 临时停用 / 恢复本项目所有转发规则，不删配置、不影响 SSH |
| per-rule snat_ip | 指定某条 IPv4 规则固定走某个出口 IP |
| 测试连通性 | nft 应用状态 + 目标连通性 + 本机侧 SNAT/出口诊断 |
| access_control | 来源 IP/CIDR 白名单或黑名单 |
| dynamic_whitelist | 解析自有 DDNS 域名并入来源白名单 |
| GeoIP | 可选限制转发端口 / SSH 只允许中国大陆 IPv4 |
| egress_control | 限制本机能转发到哪些目标 IP/CIDR |
| Stats / quota | 按规则统计流量，超额自动禁用规则 |
| audit log | 记录配置修改、apply、quota 等事件，敏感字段脱敏 |
| Telegram | 关键事件通知，带超时，不阻塞主循环 |
| SNAT / MSS | 源地址改写（masquerade / fixed / off）与 TCP MSS clamp |
| 安装来源 | release / 自建 mirror / 离线 binary / 离线 asset |

术语：`access_control`=限制谁能访问入口；`dynamic_whitelist`=把 DDNS 解析结果并入来源白名单；`egress_control`=限制能转发到哪里；`last-good`=DNS 临时失败时复用上次成功解析的 IP。

## 快速使用

`nat --menu` 常用入口：

- **添加 / 编辑规则**：增改入口端口、目标、协议、启用状态、备注；添加时尽力用 `ss` 检测入口端口占用。
- **测试转发规则连通性**：查看规则是否已应用到 nft、目标 TCP/UDP 连通性，以及 SNAT 出口诊断。
- **查看 Stats 流量统计**：每日 / 每月 / 每规则流量，可设规则配额。
- **白名单 / 黑名单管理**：查看来源策略、查询某来源 IP 是否命中、按确认加入 SSH 来源。
- **高级网络设置**：SNAT 模式、fixed 源 IP、MSS clamp、全局转发开关、时间 / NTP。

完整菜单见 [常用菜单说明](#常用菜单说明)。CLI 改配置时只写 `/etc/nat.toml`，由 `nat.service` 每 `ddns.refresh_interval_seconds`（默认 300 秒）检测并安全应用；刚改完想立即生效用 `systemctl restart nat`。

## 关键安全设计

- 只管理 `self-nat` / `self-filter` 表，不 `flush ruleset`，不动用户其它 nftables table。
- safe apply：生成规则 → `nft -c` 检查 → 备份当前 ruleset → `nft -f` 应用 → 失败回滚本项目 managed tables。
- 配置写入走 `safe_write_config`：备份 → 临时文件 + fsync → rename 原子替换 → audit；任一步失败都保留旧文件。
- audit log 记录配置修改与自动行为；`bot_token` / `chat_id` 等敏感字段脱敏。
- `global.enabled=false` 只停用本项目转发规则，不影响 SSH，不影响系统其它 nft table。
- 启动时若检测到 `filter FORWARD` 默认 policy 可能影响转发（如 Docker v28），只 WARN 提示，不自动修改非 `self-*` 表。
- 卸载只清理本项目 `self-*` 表，默认保留 `/etc/nat.toml`、Stats、backups。

## 配置示例

默认配置文件 `/etc/nat.toml`，CLI 兼容旧版 `/etc/nat.conf`。最小示例：

```toml
[global]
enabled = true

[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
snat_ip = ""          # 留空走全局 SNAT；填 IPv4 则该规则固定走此出口
comment = "example-http"
enabled = true

[snat]
mode = "masquerade"   # masquerade / fixed / off
fixed_source_ip = ""

[access_control]
mode = "off"          # off / whitelist / blacklist
entries = []
```

完整配置项（dns / ddns / dynamic_whitelist / geoip / egress_control / stats / quota / mss_clamp / last_good / audit / telegram / ui）大多默认关闭或安全默认值，按需在 CLI 对应菜单开启。各功能要点见 [功能说明](#功能说明)。

## 功能说明

### per-rule snat_ip 与双 IP 出口

本工具不改系统默认路由（`ip route` / `ip rule`）；系统默认出口由用户自行设置，本工具只控制本项目转发流量的 nftables SNAT。需要让某条转发规则固定走另一个出口时，在 IPv4 规则里填 `snat_ip = "<出口IP>"`，未填的规则行为不变。`snat_ip` 必须是本机已分配的 IPv4，不支持域名 / CIDR / 端口 / IPv6。

配置后可在「测试转发规则连通性」的「SNAT 出口诊断」段确认：`snat_ip` 是否被识别、nft 中是否生成 `snat to <ip>`、`ip route get from <snat_ip>` 是否正常、`curl --interface <snat_ip>` 观测到的出口 IP。该诊断只做本机侧检查（`ip route` / `curl` 缺失或失败按 WARN），不能替代从公网外部发起的真实入口访问测试。

### SNAT 模式

- `masquerade`（默认）：由 nft 自动选源 IP，适合普通 VPS。
- `fixed`：生成 `snat to <fixed_source_ip>`，仅 IPv4；IPv6 规则回退 masquerade。
- `off`：不生成 POSTROUTING SNAT，需用户自行保证回程路由，仅适合高级用户。

### 来源与目标控制

- `access_control`：来源 IP/CIDR 白名单或黑名单，只作用于本项目转发端口，不影响 SSH。
- `dynamic_whitelist`：定期解析自有 DDNS 域名，把结果并入来源白名单，仅在 `whitelist` 模式参与放行；DNS 失败可用 last-good 来源 IP 兜底。可选 `/24` 扩展（`cidr_expand_ipv4`，默认 `/32`，切换需二次确认）。
- `dynamic_whitelist.file_sources`：读取本机文件中的来源 IP/CIDR，并入来源白名单；适合接入 `nft-auth-whitelist` 在 receive 端生成的 `/var/lib/nft-auth-whitelist/allow.txt`。只作用于本项目管理的转发端口，不保护本机 SSH 或其它本机监听端口。缺失的 allow.txt 按空贡献处理；已有文件不可读或内容无效会阻止刷新/应用。
- `geoip`：可选，仅 IPv4。限制转发端口 / SSH 只允许中国大陆 IPv4（+可选 LAN）。SSH 限制有锁死风险，开启前务必确认。
- `egress_control`：限制本机只能转发到 `allowed_target_cidrs`，防止被当成开放代理。

`access_control`、`dynamic_whitelist`、`geoip` 是来源限制，按 AND 叠加（黑名单优先拒绝，白名单精确放行，GeoIP 地区放行）；`egress_control` 是目标限制，独立判断。

GeoIP 默认通过 `cn4_url` 拉取 `cn4.nft` 作为中国大陆 IPv4 set。`cn4_url` 默认值只是一个参考数据源，中国大陆 IP 数据可能存在误差，使用前请自行确认；如需更严格来源，可替换为 APNIC、clang.cn、纯真、ipip.net 或其他你信任的数据源。

### last-good / Stats / quota / audit

- `last_good`：DDNS 解析临时失败时复用上次成功 IP，避免一次抖动让规则失效；不绕过 `egress_control` / `access_control` / `geoip`。
- `Stats`：按 `self-filter FORWARD` 的 counter 统计每日 / 每月 / 每规则流量，`traffic_mode` 可选 `both` / `out` / `in`。
- `quota`：基于 Stats，超额后把规则 `enabled` 置 false 写回配置，由 safe apply 在下一轮移除，不直接 `nft -f`、不删规则。
- `audit`：每条一行 JSON（`time` 为 UTC RFC3339），写入失败只 WARN；内置轻量轮转，也可交给系统 logrotate。

### 其它

- `mss_clamp`：可选，对本项目转发的 TCP SYN 写 MSS，缓解隧道 / MTU 异常；默认关闭。
- `Telegram`：关键事件通知，curl 调用带超时，失败只 WARN。
- `BBR`：CLI 可开关，只改本项目 `/etc/sysctl.d/99-nat-bbr.conf`，不调用 `sysctl --system`。
- 时间显示：CLI 默认 Asia/Shanghai 24 小时制，状态 / audit 内部存 UTC；不会自动改系统时区。

## 常用菜单说明

```text
1) 查看当前转发规则        2) 添加单端口转发       3) 添加端口段转发
4) 编辑现有转发规则        5) 删除转发规则         6) 启用 / 禁用规则
7) 查看当前 nft 规则       8) 查看 Stats 流量统计   9) 手动刷新 DDNS
10) 备份当前配置           11) 从备份恢复配置       12) 白名单 / 黑名单管理
13) GeoIP / CN IP 限制     14) 出口目标限制         15) 最近来源 IP 观察
16) BBR / Telegram 状态    17) 测试转发规则连通性    18) 一键更新本项目
19) 卸载 / 清理本项目      20) 高级网络设置          21) 查看审计日志
0) 退出
```

菜单内输入 `menu` / `main` / `m` 刷新主菜单；`q` / `quit` / `exit` / `0` 退出。「最近来源 IP 观察」只打印 `conntrack` / `nft list` / `journalctl` 命令供手动排查，不自动采集或封禁。

## 故障排查

- **nat.service inactive**：`systemctl status nat --no-pager -l`、`journalctl -u nat -n 120 --no-pager`、`systemctl restart nat`。
- **nft 规则未找到**：`nft list table ip self-nat`；常见原因是服务未运行、规则尚未应用（等一个检测周期）、配置解析失败或 fake-ip 被拒。
- **Stats 为 0**：首次采集建立 baseline；确认 `stats.enabled=true`、有流量经过、`traffic_mode` 符合口径。
- **白名单导致不通**：`whitelist` 模式未命中来源不会匹配规则，检查 `access_control.entries`。
- **nft-auth 白名单未生效**：确认 `[access_control] mode = "whitelist"`，`[dynamic_whitelist] enabled = true`，并且 `dynamic_whitelist.file_sources` 指向 receive 端写出的 `allow.txt`。文件为空或无有效条目时不会打开转发端口。
- **GLIBC_x.xx not found**：release 与系统 glibc 不兼容，升级 release 或 `bash install.sh --core-only --build-from-source`。
- **release 下载失败**：`bash install.sh --core-only --use-release --version v0.8.10`，或回退源码编译。

## 更多安装方式

不自动进菜单 / 更新到指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --core-only --use-release --version v0.8.10
curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- --update --core-only --use-release --version v0.8.10
```

国内机器无法访问 GitHub 时，可先把 `install.sh` 和安装文件通过可信渠道上传，再选下面一种方式。本项目不内置第三方公共 GitHub proxy，也不关闭 TLS 校验。mirror / local 都是供应链敏感路径，安装前建议 `sha256sum` 校验来源。

```bash
# 自建 mirror（按 MIRROR_BASE/VERSION/ASSET 存放 release asset）
bash install.sh --core-only --use-release --version v0.8.10 --mirror-base https://mirror.example.com/nftables-nat-rust-enhanced

# 离线上传 binary
bash install.sh --core-only --local-binary /root/nat

# 离线上传 release asset
bash install.sh --core-only --local-asset /root/nftables-nat-rust-enhanced-linux-amd64.tar.gz

# 源码编译（开发或测试最新 main）
tmp="$(mktemp -d)" && cd "$tmp" && curl -fsSL https://github.com/misaka-cpu/nftables-nat-rust-enhanced/archive/refs/heads/main.tar.gz | tar xz --strip-components=1 && cargo build --release && bash install.sh --core-only
```

安装脚本会拒绝危险 tar 成员（绝对路径、`..`、链接、特殊文件、多个 `nat` 候选）。

## 更新与卸载

- 更新：`nat --menu` → 一键更新本项目（成功后自动重载新版菜单）。更新默认保留 `/etc/nat.toml`、`/etc/nat.conf`、`stats.json`、`backups/`，并在更新前备份旧二进制 / service，失败尝试回滚。
- 卸载：`bash install.sh --uninstall` 或菜单「卸载 / 清理本项目」。默认保留 `/etc/nat.toml`、Stats、backups，完全删除需输入 `DELETE`；只清理本项目 `self-*` 表，不 `flush ruleset`。

## 版本摘要

- **v0.8.10（当前稳定版）**：「测试转发规则连通性」增强为「测试连通性 + 本机侧规则诊断」，新增 SNAT 出口诊断（snat_ip default / 具体 IP、`snat to <ip>` 缺失 WARN、`route from snat_ip`、`curl --interface snat_ip`、目标 TCP/UDP），并明确本机侧诊断不替代公网外部入口测试。
- **v0.8.9**：新增 per-rule `snat_ip` override，用于双出口转发。
- 更早版本（v0.8.8 编辑规则、v0.8.6 全局开关、v0.8.0 dynamic_whitelist 等）见 [CHANGELOG.md](CHANGELOG.md)。

后续保持 CLI-first / core-only，不做 WebUI、tc/ifb 限速、多租户 / server-agent、数据库存储、DNS 供应商接口。

## 与原项目区别

| 功能 | 原项目 | 本项目 |
|---|---|---|
| 配置格式 | legacy | TOML + legacy 兼容 |
| 安全应用 | 基础 | `nft -c`、备份、失败回滚 |
| 管理范围 | nat 表 | 只管理 `self-nat` / `self-filter` |
| CLI | 基础 | `nat --menu` 运维菜单 |
| DDNS | 基础 | 自动刷新 + fake-ip 保护 |
| Stats / Telegram | 无 | 流量统计 + 定时通知 |
| 来源 / 目标控制 | 无 | access_control + dynamic_whitelist + GeoIP + egress_control |
| 安装 | 源码编译 | release 预编译优先 |

## Acknowledgements

- [arloor/nftables-nat-rust](https://github.com/arloor/nftables-nat-rust)
- [endview/nftpf](https://github.com/endview/nftpf)
- [mora1n/pfwd](https://github.com/mora1n/pfwd)
- [alecthw/chnlist](https://github.com/alecthw/chnlist)：感谢其提供 nftables 配置示例和 `cn4.nft` 使用参考。本项目仅作为可选数据源接入，不代表该项目作者参与、认可或为本项目背书；中国大陆 IP 列表本身请以上游数据源为准。

以上项目提供了设计思路、基础实现参考或 nftables 配置示例。

## License

MIT License。保留原项目版权声明。
