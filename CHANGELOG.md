# Changelog

本文件保存详细版本历史。README 只保留最近版本摘要。

## v0.8.10（当前稳定版）

- 「测试转发规则连通性」新增「SNAT 出口诊断」段：展示 SNAT 模式、per-rule `snat_ip`、POSTROUTING 动作、nft 中 `snat to <ip>` 是否存在、系统默认出口 IP、`ip route get from <snat_ip>` 与可选的 `curl --interface <snat_ip>` 出口 IP 测试，以及目标连通性。
- 复用现有连通性测试入口与判定逻辑；未配置 `snat_ip` 的规则显示 `default` 并跳过 `snat_ip` 专属检查；`ip route` / `curl` 缺失或失败按 WARN 处理，不修改任何路由 / 规则 / 配置。
- 本机侧诊断检查本机配置、nftables 规则、SNAT 出口和目标连通性；它不能替代从公网外部发起的真实入口访问测试。

## v0.8.9

- 新增可选 per-rule `snat_ip`，用于双出口转发场景。
- `snat_ip` 为空或未配置时保持旧规则行为不变；配置 IPv4 literal 时仅该条转发规则的 POSTROUTING 使用 `snat to <snat_ip>`。
- CLI 添加 / 编辑 / 查看规则支持 `snat_ip`；配置校验拒绝域名、CIDR、IPv6、带端口或带空格的值。

## v0.8.8

- 新增 CLI「编辑现有转发规则」入口，可修改入口端口 / 端口段、目标地址、目标端口、协议、启用状态和备注。
- 编辑保存统一走 `safe_write_config`、配置备份和 `rule.edit` audit；修改入口端口或协议时会做本机端口占用检测和规则冲突检测。
- 编辑 target / sport / dport / protocol 后会按现有 last-good rule_key / prune 机制避免旧缓存误复用；不改 Stats / quota 的 rule_id 对齐策略。

## v0.8.7

- 修复 disabled 规则位于启用规则之前时 Stats / quota 的 `rule_id` 对齐问题（与 nft 计数器口径统一为「启用规则序号」）。

## v0.8.6

- 新增 `[global] enabled` 全局转发开关，可临时停用 / 恢复本项目所有转发规则生成，不删除规则配置。
- `global.enabled=false` 时仍保留 managed table 基础结构，不生成 DNAT/SNAT 转发规则，不影响 SSH 和系统其他 nft table。
- 白名单 / 黑名单管理新增「检测当前 SSH 来源 IP」，只提示并在用户确认后手动加入静态 entries；blacklist 模式下拒绝添加以避免误封。
- 来源策略摘要新增 `global forwarding` 状态、global disabled 提示、whitelist 空白名单 warning、dynamic whitelist 非 whitelist 模式提示。
- 测试转发规则连通性在 global disabled 时直接给 warning，不继续给出误导性的 nft 应用判断。

## v0.8.5

- 白名单 / 黑名单管理新增「查询来源 IP 命中情况」只读诊断入口。
- 来源策略摘要显示静态 entries、dynamic_whitelist current/stale、`cidr_expand_ipv4`、GeoIP forward / SSH GeoIP。
- 设置 whitelist 时增加空白名单防锁死提示，强制继续会写 `access_control.whitelist.empty_override` audit warning。
- README 增加「来源白名单排查」，明确来源限制与 `egress_control` 目标限制的边界。

## v0.8.4

- `prepare::check_and_prepare` 对 Docker v28 / FORWARD policy 只检测并 WARN，不再自动修改非 `self-*` 表。
- 本地源码构建未注入 release tag 时 `nat --version` 显示 `dev`，release 构建仍显示注入的 tag。
- release / local asset 解压前统一校验 tar 成员，拒绝绝对路径、`..`、链接、特殊文件和多个 `nat` 候选。
- dynamic_whitelist 同名域名变更后 DNS 失败不再复用旧域名 last-good 来源 IP，并写 prune audit。

## v0.8.3

- install.sh 新增 `--mirror-base`，支持使用自建 mirror 下载 release asset，mirror 下载失败会明确提示并 fallback GitHub。
- install.sh 新增 `--local-binary` / `--local-asset`，支持手动上传二进制或 release tar.gz 后离线安装，`--update --core-only` 同样支持。
- README 增加国内机器无法访问 GitHub 时的安装方式，并提醒 mirror / local 安装路径需要校验来源和 SHA256。

## v0.8.2

- dynamic_whitelist 新增可选 IPv4 `/24` 扩展模式 `cidr_expand_ipv4`，默认 `/32` 精确 IP 行为不变；非 `32` / `24` 的值在配置校验和 CLI 两侧都会被拒绝。
- state 文件新增 `raw_ips` / `effective_sources` / `cidr_expand_ipv4` 字段，旧 state 兼容读取、即时重算，模式切换不保留旧网段、不无限累计。
- CLI 切换 `/24` 二次确认；audit / Telegram 记录原始与扩展后的来源，只在 `effective_sources` 变化时通知。

## v0.8.1

- CLI 白名单 / 黑名单管理与动态 DDNS 来源白名单子菜单的展示层级优化，不改 nft / safe apply / 组合策略。

## v0.8.0

- 新增动态 DDNS 来源白名单（`dynamic_whitelist`）：定期解析用户已有 DDNS 域名并把 A 记录并入来源白名单；默认 disabled、默认 IPv4、独立 state 文件。
- DNS 失败时可临时保留 last-good 来源 IP（标记 `stale`），不无限累计、不在无结果时开放所有来源。
- 只在 `access_control.mode = "whitelist"` 时合并静态白名单 + dynamic whitelist，不影响 `egress_control` / 目标 DDNS / SSH GeoIP / SNAT / MSS / quota / stats。

## v0.7.x

- 维护性重构：拆分 `main.rs` / `menu.rs`（safe apply、quota loop、runtime、telegram、update、audit_view、backup 等模块化），行为与 v0.6.x 完全一致。
- safe apply 用稳定 FNV-1a 64-bit hash（`nat_common::stable_script_hash`）判断脚本是否变化，audit `apply.*` 新增 `script_hash` 字段。
- 统一 `safe_write_config`（备份 → tmp+fsync → rename → audit）；删除规则默认 `backup_skipped`。
- 保存提示按 reason 分流（影响 / 不影响 nft 两类）。
