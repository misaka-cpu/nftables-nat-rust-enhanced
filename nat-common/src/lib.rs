use clap::Parser;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Display;
use std::net::IpAddr;
use std::num::ParseIntError;
use std::str::FromStr;

pub mod atomic;
pub mod audit;
pub mod dynamic_whitelist;
pub mod forward_test;
pub mod geoip;
pub mod hash;
pub mod last_good;
pub mod logger;
pub mod quota;
pub mod stats;
pub mod uninstall;

pub use hash::stable_script_hash;

pub fn build_version() -> &'static str {
    // release CI 注入 NAT_BUILD_VERSION=<tag>；源码编译没有注入时回退 Cargo 包版本。
    // 两者都为空（极端情况，例如手动 unset 后编译）时退回 "dev"，避免 `nat --version`
    // 和主菜单标题出现空字符串。
    let injected = option_env!("NAT_BUILD_VERSION").unwrap_or("");
    if !injected.is_empty() {
        return injected;
    }
    let pkg = env!("CARGO_PKG_VERSION");
    if !pkg.is_empty() {
        return pkg;
    }
    "dev"
}

/// CLI 默认展示时区：Asia/Shanghai（IANA 名，处理潜在 DST 由 chrono-tz 兜底）。
pub const CLI_DISPLAY_TZ_DEFAULT: &str = "Asia/Shanghai";
/// CLI 默认时间格式：24 小时制 + 时区缩写（chrono 的 `%Z`），无 T、无纳秒。
pub const CLI_DISPLAY_TIME_FORMAT_DEFAULT: &str = "%Y-%m-%d %H:%M:%S %Z";

/// 用户可在 `[ui]` 节配置 CLI 展示时区与时间格式。
///
/// - `timezone`：IANA 时区名（"Asia/Shanghai" / "UTC" / "America/Chicago" 等）。
///   非法值会在 `from_toml_str → validate` 阶段被拒绝；不会"隐式回退"。
/// - `time_format`：chrono strftime 字符串，默认 `"%Y-%m-%d %H:%M:%S %Z"`。
/// - 仅影响 CLI 展示，不改变系统时区，也不影响 audit/last-good/quota 等 JSON 内部存储（仍 UTC RFC3339）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    #[serde(default = "default_ui_timezone")]
    pub timezone: String,
    #[serde(default = "default_ui_time_format")]
    pub time_format: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            timezone: default_ui_timezone(),
            time_format: default_ui_time_format(),
        }
    }
}

impl UiConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_iana_timezone(&self.timezone)?;
        if self.time_format.trim().is_empty() {
            return Err("ui.time_format 不能为空".to_string());
        }
        Ok(())
    }
}

fn default_ui_timezone() -> String {
    CLI_DISPLAY_TZ_DEFAULT.to_string()
}

fn default_ui_time_format() -> String {
    CLI_DISPLAY_TIME_FORMAT_DEFAULT.to_string()
}

/// 校验 IANA 时区名是否合法（chrono-tz 数据库可解析）。
pub fn validate_iana_timezone(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("ui.timezone 不能为空".to_string());
    }
    if trimmed.parse::<chrono_tz::Tz>().is_err() {
        return Err(format!(
            "ui.timezone 不是合法的 IANA 时区名: {trimmed}（例如 Asia/Shanghai / UTC / America/Chicago）"
        ));
    }
    Ok(())
}

/// 把任意时区的 `DateTime` 按 CLI 默认设置（Asia/Shanghai，24 小时制）转换为字符串。
///
/// 这是历史 API（v0.4.1），保留向后兼容；新代码推荐 [`format_cli_time_with`]。
pub fn format_cli_time<Tz: chrono::TimeZone>(dt: chrono::DateTime<Tz>) -> String {
    format_cli_time_with(dt, &UiConfig::default())
}

/// 用给定的 [`UiConfig`] 格式化时间。非法配置（应已被 [`UiConfig::validate`] 拦截）
/// 退回 Asia/Shanghai + 默认格式，永不 panic。
pub fn format_cli_time_with<Tz: chrono::TimeZone>(
    dt: chrono::DateTime<Tz>,
    ui: &UiConfig,
) -> String {
    let tz: chrono_tz::Tz = ui
        .timezone
        .parse()
        .or_else(|_| CLI_DISPLAY_TZ_DEFAULT.parse::<chrono_tz::Tz>())
        .unwrap_or(chrono_tz::UTC);
    let fmt = if ui.time_format.trim().is_empty() {
        CLI_DISPLAY_TIME_FORMAT_DEFAULT
    } else {
        ui.time_format.as_str()
    };
    dt.with_timezone(&tz).format(fmt).to_string()
}

/// 把可能为 RFC3339 字符串的时间标签转换成 CLI 展示格式（默认 UI 配置）。解析失败则原样返回。
pub fn format_cli_time_from_rfc3339(value: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(dt) => format_cli_time(dt),
        Err(_) => value.to_string(),
    }
}

/// 用给定 [`UiConfig`] 把 RFC3339 字符串转 CLI 展示。
pub fn format_cli_time_from_rfc3339_with(value: &str, ui: &UiConfig) -> String {
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(dt) => format_cli_time_with(dt, ui),
        Err(_) => value.to_string(),
    }
}

/// NAT CLI 命令行参数
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// 打开交互式终端管理菜单
    #[arg(long, help = "打开交互式终端管理菜单")]
    pub menu: bool,
    /// 配置文件路径
    #[arg(value_name = "CONFIG_FILE", help = "老版本配置文件")]
    pub compatible_config_file: Option<String>,
    #[arg(long, value_name = "TOML_CONFIG", help = "toml配置文件")]
    pub toml: Option<String>,
}

/// Legacy配置解析错误
#[derive(Debug)]
pub enum ParseError {
    /// 注释或空行，应跳过
    Skip,
    /// 解析错误
    InvalidFormat(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Skip => write!(f, "跳过（注释或空行）"),
            ParseError::InvalidFormat(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> Self {
        ParseError::InvalidFormat(format!("端口解析失败: {}", e))
    }
}

// IP版本枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersion {
    V4,
    V6,
    #[default]
    All, // 优先IPv4，如果IPv4不可用则使用IPv6
}

impl Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::V4 => write!(f, "ipv4"),
            IpVersion::V6 => write!(f, "ipv6"),
            IpVersion::All => write!(f, "all"),
        }
    }
}

impl From<String> for IpVersion {
    fn from(version: String) -> Self {
        match version.to_lowercase().as_str() {
            "ipv4" => IpVersion::V4,
            "ipv6" => IpVersion::V6,
            "all" => IpVersion::All,
            _ => IpVersion::All,
        }
    }
}

impl From<&str> for IpVersion {
    fn from(version: &str) -> Self {
        match version.to_lowercase().as_str() {
            "ipv4" => IpVersion::V4,
            "ipv6" => IpVersion::V6,
            "all" => IpVersion::All,
            _ => IpVersion::All,
        }
    }
}

impl Serialize for IpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(IpVersion::from(s))
    }
}

// 协议枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    All,
    Tcp,
    Udp,
}

// Drop链类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Chain {
    #[default]
    Input,
    Forward,
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Input => write!(f, "input"),
            Chain::Forward => write!(f, "forward"),
        }
    }
}

impl From<String> for Chain {
    fn from(chain: String) -> Self {
        match chain.to_lowercase().as_str() {
            "input" => Chain::Input,
            "forward" => Chain::Forward,
            _ => Chain::Input,
        }
    }
}

impl From<&str> for Chain {
    fn from(chain: &str) -> Self {
        match chain.to_lowercase().as_str() {
            "input" => Chain::Input,
            "forward" => Chain::Forward,
            _ => Chain::Input,
        }
    }
}

impl Serialize for Chain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Chain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Chain::from(s))
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::All => write!(f, "all"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl From<String> for Protocol {
    fn from(protocol: String) -> Self {
        match protocol.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => Protocol::All,
        }
    }
}

impl From<&str> for Protocol {
    fn from(protocol: &str) -> Self {
        match protocol.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => Protocol::All,
        }
    }
}

impl From<Protocol> for String {
    fn from(protocol: Protocol) -> Self {
        protocol.to_string()
    }
}

impl Serialize for Protocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Protocol::from(s))
    }
}

// TOML配置结构定义
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TomlConfig {
    #[serde(default)]
    pub rules: Vec<NftCell>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub ddns: DdnsConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub access_control: AccessControlConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub egress_control: EgressControlConfig,
    #[serde(default)]
    pub dynamic_whitelist: DynamicWhitelistConfig,
    #[serde(default)]
    pub snat: SnatConfig,
    #[serde(default)]
    pub mss_clamp: MssClampConfig,
    #[serde(default)]
    pub last_good: LastGoodConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub quota: QuotaConfig,
    #[serde(default)]
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub reject_fake_ip: bool,
    #[serde(default = "default_fake_ip_cidrs")]
    pub fake_ip_cidrs: Vec<String>,
    #[serde(default = "default_resolver_mode")]
    pub resolver_mode: String,
    #[serde(default = "default_nameservers")]
    pub nameservers: Vec<String>,
    #[serde(default = "default_true")]
    pub fallback_to_system: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            reject_fake_ip: true,
            fake_ip_cidrs: default_fake_ip_cidrs(),
            resolver_mode: default_resolver_mode(),
            nameservers: default_nameservers(),
            fallback_to_system: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    #[serde(default = "default_ddns_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            refresh_interval_seconds: default_ddns_refresh_interval_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_collect_interval_seconds")]
    pub collect_interval_seconds: u64,
    #[serde(default = "default_stats_data_file")]
    pub data_file: String,
    #[serde(default)]
    pub traffic_mode: TrafficMode,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            collect_interval_seconds: default_collect_interval_seconds(),
            data_file: default_stats_data_file(),
            traffic_mode: TrafficMode::Both,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrafficMode {
    #[default]
    Both,
    Out,
    In,
}

impl Display for TrafficMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficMode::Both => write!(f, "both"),
            TrafficMode::Out => write!(f, "out"),
            TrafficMode::In => write!(f, "in"),
        }
    }
}

impl Serialize for TrafficMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TrafficMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "both" => Ok(TrafficMode::Both),
            "out" => Ok(TrafficMode::Out),
            "in" => Ok(TrafficMode::In),
            _ => Err(serde::de::Error::custom(
                "stats.traffic_mode must be one of: both, out, in",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
    #[serde(default = "default_notify_interval_minutes")]
    pub notify_interval_minutes: u64,
    #[serde(default = "default_true")]
    pub notify_daily: bool,
    #[serde(default = "default_true")]
    pub notify_monthly: bool,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            notify_interval_minutes: default_notify_interval_minutes(),
            notify_daily: true,
            notify_monthly: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    #[serde(default)]
    pub mode: AccessControlMode,
    #[serde(default)]
    pub entries: Vec<String>,
}

/// 动态 DDNS 来源白名单配置。
///
/// 该配置只描述“来源 IP 白名单”增强，不参与目标域名解析、last-good 目标缓存或
/// egress_control 目标限制。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicWhitelistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dynamic_whitelist_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub use_last_good_on_dns_failure: bool,
    #[serde(default = "default_true")]
    pub resolve_ipv4: bool,
    #[serde(default)]
    pub resolve_ipv6: bool,
    #[serde(default = "default_true")]
    pub notify_on_change: bool,
    #[serde(default = "default_dynamic_whitelist_state_file")]
    pub state_file: String,
    #[serde(default = "default_dynamic_whitelist_cidr_expand_ipv4")]
    pub cidr_expand_ipv4: u8,
    #[serde(default)]
    pub domains: Vec<DynamicWhitelistDomainConfig>,
}

impl Default for DynamicWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_interval_seconds: default_dynamic_whitelist_refresh_interval_seconds(),
            use_last_good_on_dns_failure: true,
            resolve_ipv4: true,
            resolve_ipv6: false,
            notify_on_change: true,
            state_file: default_dynamic_whitelist_state_file(),
            cidr_expand_ipv4: default_dynamic_whitelist_cidr_expand_ipv4(),
            domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicWhitelistDomainConfig {
    pub name: String,
    pub domain: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            mode: AccessControlMode::Off,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessControlMode {
    #[default]
    Off,
    Whitelist,
    Blacklist,
}

impl Display for AccessControlMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessControlMode::Off => write!(f, "off"),
            AccessControlMode::Whitelist => write!(f, "whitelist"),
            AccessControlMode::Blacklist => write!(f, "blacklist"),
        }
    }
}

impl From<&str> for AccessControlMode {
    fn from(mode: &str) -> Self {
        match mode.to_lowercase().as_str() {
            "whitelist" => AccessControlMode::Whitelist,
            "blacklist" => AccessControlMode::Blacklist,
            _ => AccessControlMode::Off,
        }
    }
}

impl Serialize for AccessControlMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccessControlMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "off" => Ok(AccessControlMode::Off),
            "whitelist" => Ok(AccessControlMode::Whitelist),
            "blacklist" => Ok(AccessControlMode::Blacklist),
            _ => Err(serde::de::Error::custom(format!(
                "invalid access_control mode: {s}"
            ))),
        }
    }
}

/// GeoIP / CN IP set 限制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_geoip_provider")]
    pub provider: String,
    #[serde(default = "default_cn4_url")]
    pub cn4_url: String,
    #[serde(default = "default_cn4_file")]
    pub cn4_file: String,
    #[serde(default = "default_geoip_update_interval_hours")]
    pub update_interval_hours: u64,
    #[serde(default = "default_true")]
    pub allow_lan: bool,
    #[serde(default = "default_lan_cidrs")]
    pub lan_cidrs: Vec<String>,
    #[serde(default)]
    pub forward: GeoIpForwardConfig,
    #[serde(default)]
    pub ssh: GeoIpSshConfig,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_geoip_provider(),
            cn4_url: default_cn4_url(),
            cn4_file: default_cn4_file(),
            update_interval_hours: default_geoip_update_interval_hours(),
            allow_lan: true,
            lan_cidrs: default_lan_cidrs(),
            forward: GeoIpForwardConfig::default(),
            ssh: GeoIpSshConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpForwardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_geoip_forward_mode")]
    pub mode: String,
    #[serde(default = "default_geoip_apply_to_ports")]
    pub apply_to_ports: String,
}

impl Default for GeoIpForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_geoip_forward_mode(),
            apply_to_ports: default_geoip_apply_to_ports(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpSshConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default = "default_geoip_ssh_mode")]
    pub mode: String,
}

impl Default for GeoIpSshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_ssh_port(),
            mode: default_geoip_ssh_mode(),
        }
    }
}

/// 出口目标限制配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressControlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_egress_mode")]
    pub mode: String,
    #[serde(default)]
    pub allowed_target_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Default for EgressControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_egress_mode(),
            allowed_target_cidrs: Vec::new(),
            comment: None,
        }
    }
}

impl EgressControlConfig {
    /// 检查给定 IP 是否在 allowed_target_cidrs 中
    /// 非法 CIDR 跳过；任意一个 CIDR 包含该 IP 即返回 true
    pub fn allows_ip(&self, ip: &str) -> bool {
        let Ok(parsed) = ip.parse::<IpAddr>() else {
            return false;
        };
        self.allowed_target_cidrs
            .iter()
            .filter_map(|cidr| {
                cidr.parse::<ipnetwork::IpNetwork>()
                    .ok()
                    .or_else(|| cidr.parse::<IpAddr>().ok().map(ipnetwork::IpNetwork::from))
            })
            .any(|network| network.contains(parsed))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mode != "allow-targets" {
            return Err(format!(
                "egress_control.mode 当前仅支持 'allow-targets'，收到: {}",
                self.mode
            ));
        }
        for entry in &self.allowed_target_cidrs {
            if entry.trim().is_empty() {
                return Err("egress_control.allowed_target_cidrs 条目不能为空".to_string());
            }
            if entry.parse::<IpAddr>().is_err() && entry.parse::<ipnetwork::IpNetwork>().is_err() {
                return Err(format!(
                    "egress_control.allowed_target_cidrs 条目不是合法 IP/CIDR: {entry}"
                ));
            }
        }
        Ok(())
    }
}

/// SNAT 源地址改写配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnatConfig {
    #[serde(default)]
    pub mode: SnatMode,
    #[serde(default)]
    pub fixed_source_ip: String,
}

impl Default for SnatConfig {
    fn default() -> Self {
        Self {
            mode: SnatMode::Masquerade,
            fixed_source_ip: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnatMode {
    #[default]
    Masquerade,
    Fixed,
    Off,
}

impl Display for SnatMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnatMode::Masquerade => write!(f, "masquerade"),
            SnatMode::Fixed => write!(f, "fixed"),
            SnatMode::Off => write!(f, "off"),
        }
    }
}

impl Serialize for SnatMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SnatMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "masquerade" => Ok(SnatMode::Masquerade),
            "fixed" => Ok(SnatMode::Fixed),
            "off" => Ok(SnatMode::Off),
            other => Err(serde::de::Error::custom(format!(
                "invalid snat.mode: {other}，只支持 masquerade / fixed / off"
            ))),
        }
    }
}

impl SnatConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self.mode {
            SnatMode::Masquerade | SnatMode::Off => Ok(()),
            SnatMode::Fixed => {
                let ip = self.fixed_source_ip.trim();
                if ip.is_empty() {
                    return Err(
                        "snat.mode=fixed 时 fixed_source_ip 不能为空，请填写合法 IPv4 地址"
                            .to_string(),
                    );
                }
                match ip.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => Ok(()),
                    Ok(IpAddr::V6(_)) => {
                        Err(format!("snat.fixed_source_ip 当前仅支持 IPv4，收到: {ip}"))
                    }
                    Err(_) => Err(format!("snat.fixed_source_ip 不是合法 IPv4 地址: {ip}")),
                }
            }
        }
    }
}

/// TCP MSS clamp 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssClampConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mss_clamp_size")]
    pub size: u16,
}

impl Default for MssClampConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size: default_mss_clamp_size(),
        }
    }
}

pub const MSS_CLAMP_MIN: u16 = 536;
pub const MSS_CLAMP_MAX: u16 = 1460;

impl MssClampConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(MSS_CLAMP_MIN..=MSS_CLAMP_MAX).contains(&self.size) {
            return Err(format!(
                "mss_clamp.size 必须在 {MSS_CLAMP_MIN}-{MSS_CLAMP_MAX} 之间，收到: {}",
                self.size
            ));
        }
        Ok(())
    }
}

fn default_mss_clamp_size() -> u16 {
    1452
}

/// last-good 状态缓存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastGoodConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_last_good_file")]
    pub file: String,
    #[serde(default = "default_true")]
    pub use_last_good_on_dns_failure: bool,
}

impl Default for LastGoodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: default_last_good_file(),
            use_last_good_on_dns_failure: true,
        }
    }
}

impl LastGoodConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.file.trim().is_empty() {
            return Err("last_good.file 不能为空".to_string());
        }
        Ok(())
    }
}

fn default_last_good_file() -> String {
    "/var/lib/nftables-nat-rust/last-good-state.json".to_string()
}

/// audit log 审计日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_file")]
    pub file: String,
    /// 内置轻量轮转开关；旧配置缺省时为 true，避免日志无限增长。
    #[serde(default = "default_true")]
    pub rotate: bool,
    /// 触发轮转的阈值（MB）。0 视为禁用阈值检测。
    #[serde(default = "default_audit_max_size_mb")]
    pub max_size_mb: u64,
    /// 保留的历史备份数量（.1 / .2 / .3 …）。
    /// `0` 表示仅截断当前日志、不保留旧文件。
    #[serde(default = "default_audit_max_backups")]
    pub max_backups: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: default_audit_file(),
            rotate: true,
            max_size_mb: default_audit_max_size_mb(),
            max_backups: default_audit_max_backups(),
        }
    }
}

impl AuditConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.file.trim().is_empty() {
            return Err("audit.file 不能为空".to_string());
        }
        Ok(())
    }
}

fn default_audit_file() -> String {
    "/var/log/nftables-nat-rust-audit.log".to_string()
}

fn default_audit_max_size_mb() -> u64 {
    10
}

fn default_audit_max_backups() -> u32 {
    3
}

/// 规则级流量配额全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_quota_check_interval_seconds")]
    pub check_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub notify_on_exceeded: bool,
    #[serde(default = "default_quota_state_file")]
    pub state_file: String,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: default_quota_check_interval_seconds(),
            notify_on_exceeded: true,
            state_file: default_quota_state_file(),
        }
    }
}

impl QuotaConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.check_interval_seconds == 0 {
            return Err("quota.check_interval_seconds 不能为 0".to_string());
        }
        if self.state_file.trim().is_empty() {
            return Err("quota.state_file 不能为空".to_string());
        }
        Ok(())
    }
}

fn default_quota_check_interval_seconds() -> u64 {
    60
}

fn default_quota_state_file() -> String {
    "/var/lib/nftables-nat-rust/quota-state.json".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaPeriod {
    Daily,
    #[default]
    Monthly,
    Total,
}

impl Display for QuotaPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaPeriod::Daily => write!(f, "daily"),
            QuotaPeriod::Monthly => write!(f, "monthly"),
            QuotaPeriod::Total => write!(f, "total"),
        }
    }
}

impl Serialize for QuotaPeriod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for QuotaPeriod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "daily" => Ok(QuotaPeriod::Daily),
            "monthly" => Ok(QuotaPeriod::Monthly),
            "total" => Ok(QuotaPeriod::Total),
            other => Err(serde::de::Error::custom(format!(
                "invalid quota_period: {other}, 只支持 daily / monthly / total"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaAction {
    #[default]
    Disable,
}

impl Display for QuotaAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaAction::Disable => write!(f, "disable"),
        }
    }
}

impl Serialize for QuotaAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for QuotaAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "disable" => Ok(QuotaAction::Disable),
            other => Err(serde::de::Error::custom(format!(
                "invalid quota_action: {other}, 第一版仅支持 disable"
            ))),
        }
    }
}

impl GeoIpConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.update_interval_hours == 0 {
            return Err("geoip.update_interval_hours 不能为 0".to_string());
        }
        for cidr in &self.lan_cidrs {
            if cidr.parse::<ipnetwork::IpNetwork>().is_err() && cidr.parse::<IpAddr>().is_err() {
                return Err(format!("geoip.lan_cidrs 条目不是合法 CIDR: {cidr}"));
            }
        }
        if self.ssh.port == 0 {
            return Err("geoip.ssh.port 不能为 0".to_string());
        }
        if self.forward.mode != "allow-cn" {
            return Err(format!(
                "geoip.forward.mode 当前仅支持 'allow-cn'，收到: {}",
                self.forward.mode
            ));
        }
        if !matches!(self.ssh.mode.as_str(), "allow-cn-and-lan" | "allow-cn") {
            return Err(format!(
                "geoip.ssh.mode 当前仅支持 'allow-cn-and-lan' / 'allow-cn'，收到: {}",
                self.ssh.mode
            ));
        }
        Ok(())
    }

    /// 仅过滤出 IPv4 的 LAN CIDR；第一版仅支持 IPv4
    pub fn lan_ipv4_cidrs(&self) -> Vec<String> {
        self.lan_cidrs
            .iter()
            .filter(|entry| {
                if let Ok(network) = entry.parse::<ipnetwork::IpNetwork>() {
                    return network.is_ipv4();
                }
                if let Ok(IpAddr::V4(_)) = entry.parse::<IpAddr>() {
                    return true;
                }
                false
            })
            .cloned()
            .collect()
    }
}

fn default_geoip_provider() -> String {
    "chnlist".to_string()
}

fn default_cn4_url() -> String {
    "https://raw.githubusercontent.com/alecthw/chnlist/release/nftables/cn4.nft".to_string()
}

fn default_cn4_file() -> String {
    "/etc/nftables-nat/sets/cn4.nft".to_string()
}

fn default_geoip_update_interval_hours() -> u64 {
    168
}

fn default_lan_cidrs() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
    ]
}

fn default_geoip_forward_mode() -> String {
    "allow-cn".to_string()
}

fn default_geoip_apply_to_ports() -> String {
    "forward-rules".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

fn default_geoip_ssh_mode() -> String {
    "allow-cn-and-lan".to_string()
}

fn default_egress_mode() -> String {
    "allow-targets".to_string()
}

fn default_collect_interval_seconds() -> u64 {
    60
}

fn default_fake_ip_cidrs() -> Vec<String> {
    vec!["198.18.0.0/15".to_string()]
}

fn default_resolver_mode() -> String {
    "system".to_string()
}

fn default_nameservers() -> Vec<String> {
    vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
}

fn default_ddns_refresh_interval_seconds() -> u64 {
    300
}

fn default_dynamic_whitelist_refresh_interval_seconds() -> u64 {
    300
}

fn default_dynamic_whitelist_state_file() -> String {
    "/var/lib/nftables-nat-rust/dynamic-whitelist-state.json".to_string()
}

fn default_dynamic_whitelist_cidr_expand_ipv4() -> u8 {
    32
}

fn default_stats_data_file() -> String {
    "/var/lib/nftables-nat-rust/stats.json".to_string()
}

fn default_notify_interval_minutes() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NftCell {
    #[serde(rename = "single")]
    Single {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(rename = "sport")]
        sport: u16,
        #[serde(rename = "dport")]
        dport: u16,
        #[serde(rename = "domain")]
        domain: String,
        #[serde(default)]
        protocol: Protocol,
        #[serde(default)]
        ip_version: IpVersion,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        #[serde(default)]
        quota_enabled: bool,
        #[serde(default)]
        quota_bytes: u64,
        #[serde(default)]
        quota_period: QuotaPeriod,
        #[serde(default)]
        quota_action: QuotaAction,
    },
    #[serde(rename = "range")]
    Range {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(rename = "port_start")]
        port_start: u16,
        #[serde(rename = "port_end")]
        port_end: u16,
        #[serde(rename = "domain")]
        domain: String,
        #[serde(default)]
        protocol: Protocol,
        #[serde(default)]
        ip_version: IpVersion,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        #[serde(default)]
        quota_enabled: bool,
        #[serde(default)]
        quota_bytes: u64,
        #[serde(default)]
        quota_period: QuotaPeriod,
        #[serde(default)]
        quota_action: QuotaAction,
    },
    #[serde(rename = "redirect")]
    Redirect {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(rename = "sport")]
        src_port: u16,
        #[serde(rename = "sport_end", skip_serializing_if = "Option::is_none")]
        src_port_end: Option<u16>,
        #[serde(rename = "dport")]
        dst_port: u16,
        #[serde(default)]
        protocol: Protocol,
        #[serde(default)]
        ip_version: IpVersion,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        #[serde(default)]
        quota_enabled: bool,
        #[serde(default)]
        quota_bytes: u64,
        #[serde(default)]
        quota_period: QuotaPeriod,
        #[serde(default)]
        quota_action: QuotaAction,
    },
    #[serde(rename = "drop")]
    Drop {
        #[serde(default)]
        chain: Chain,
        #[serde(skip_serializing_if = "Option::is_none")]
        src_ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dst_ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        src_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        src_port_end: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dst_port: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dst_port_end: Option<u16>,
        #[serde(default)]
        protocol: Protocol,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
    },
}

impl Display for NftCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NftCell::Single {
                sport,
                dport,
                domain,
                protocol,
                ip_version,
                ..
            } => write!(f, "SINGLE,{sport},{dport},{domain},{protocol},{ip_version}"),
            NftCell::Range {
                port_start,
                port_end,
                domain,
                protocol,
                ip_version,
                ..
            } => write!(
                f,
                "RANGE,{port_start},{port_end},{domain},{protocol},{ip_version}"
            ),
            NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                protocol,
                ip_version,
                ..
            } => {
                if let Some(end) = src_port_end {
                    write!(
                        f,
                        "REDIRECT,{src_port}-{end},{dst_port},{protocol},{ip_version}"
                    )
                } else {
                    write!(f, "REDIRECT,{src_port},{dst_port},{protocol},{ip_version}")
                }
            }
            NftCell::Drop {
                chain,
                src_ip,
                dst_ip,
                src_port,
                src_port_end,
                dst_port,
                dst_port_end,
                protocol,
                ..
            } => {
                let mut parts = vec![format!("DROP,{}", chain)];

                if let Some(ip) = src_ip {
                    parts.push(format!("src_ip={}", ip));
                }
                if let Some(ip) = dst_ip {
                    parts.push(format!("dst_ip={}", ip));
                }
                if let Some(port) = src_port {
                    if let Some(end) = src_port_end {
                        parts.push(format!("src_port={}-{}", port, end));
                    } else {
                        parts.push(format!("src_port={}", port));
                    }
                }
                if let Some(port) = dst_port {
                    if let Some(end) = dst_port_end {
                        parts.push(format!("dst_port={}-{}", port, end));
                    } else {
                        parts.push(format!("dst_port={}", port));
                    }
                }
                parts.push(format!("{}", protocol));

                write!(f, "{}", parts.join(","))
            }
        }
    }
}

impl NftCell {
    pub fn enabled(&self) -> bool {
        match self {
            NftCell::Single { enabled, .. }
            | NftCell::Range { enabled, .. }
            | NftCell::Redirect { enabled, .. } => *enabled,
            NftCell::Drop { .. } => true,
        }
    }

    pub fn set_enabled(&mut self, value: bool) {
        match self {
            NftCell::Single { enabled, .. }
            | NftCell::Range { enabled, .. }
            | NftCell::Redirect { enabled, .. } => *enabled = value,
            NftCell::Drop { .. } => {}
        }
    }

    pub fn quota_enabled(&self) -> bool {
        match self {
            NftCell::Single { quota_enabled, .. }
            | NftCell::Range { quota_enabled, .. }
            | NftCell::Redirect { quota_enabled, .. } => *quota_enabled,
            NftCell::Drop { .. } => false,
        }
    }

    pub fn quota_bytes(&self) -> u64 {
        match self {
            NftCell::Single { quota_bytes, .. }
            | NftCell::Range { quota_bytes, .. }
            | NftCell::Redirect { quota_bytes, .. } => *quota_bytes,
            NftCell::Drop { .. } => 0,
        }
    }

    pub fn quota_period(&self) -> QuotaPeriod {
        match self {
            NftCell::Single { quota_period, .. }
            | NftCell::Range { quota_period, .. }
            | NftCell::Redirect { quota_period, .. } => *quota_period,
            NftCell::Drop { .. } => QuotaPeriod::Monthly,
        }
    }

    pub fn quota_action(&self) -> QuotaAction {
        match self {
            NftCell::Single { quota_action, .. }
            | NftCell::Range { quota_action, .. }
            | NftCell::Redirect { quota_action, .. } => *quota_action,
            NftCell::Drop { .. } => QuotaAction::Disable,
        }
    }

    pub fn set_quota_enabled(&mut self, value: bool) {
        match self {
            NftCell::Single { quota_enabled, .. }
            | NftCell::Range { quota_enabled, .. }
            | NftCell::Redirect { quota_enabled, .. } => *quota_enabled = value,
            NftCell::Drop { .. } => {}
        }
    }

    pub fn set_quota_bytes(&mut self, value: u64) {
        match self {
            NftCell::Single { quota_bytes, .. }
            | NftCell::Range { quota_bytes, .. }
            | NftCell::Redirect { quota_bytes, .. } => *quota_bytes = value,
            NftCell::Drop { .. } => {}
        }
    }

    pub fn set_quota_period(&mut self, value: QuotaPeriod) {
        match self {
            NftCell::Single { quota_period, .. }
            | NftCell::Range { quota_period, .. }
            | NftCell::Redirect { quota_period, .. } => *quota_period = value,
            NftCell::Drop { .. } => {}
        }
    }
}

impl TomlConfig {
    /// 验证配置是否合法
    pub fn validate(&self) -> Result<(), String> {
        self.access_control.validate()?;
        self.dynamic_whitelist.validate()?;
        self.geoip.validate()?;
        self.egress_control.validate()?;
        self.snat.validate()?;
        self.mss_clamp.validate()?;
        self.last_good.validate()?;
        self.audit.validate()?;
        self.quota.validate()?;
        self.ui.validate()?;
        for (idx, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .map_err(|e| format!("规则 {} 验证失败: {}", idx + 1, e))?;
        }
        Ok(())
    }

    /// 从 TOML 字符串解析配置并验证
    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let config: TomlConfig = toml::from_str(s).map_err(|e| format!("解析TOML失败: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// 转换为 TOML 字符串
    pub fn to_toml_string(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| format!("序列化TOML失败: {}", e))
    }
}

impl AccessControlConfig {
    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.entries {
            validate_access_entry(entry)?;
        }
        Ok(())
    }
}

impl DynamicWhitelistConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.refresh_interval_seconds < 10 {
            return Err(
                "dynamic_whitelist.refresh_interval_seconds 不能低于 10 秒，生产环境建议 >= 300 秒"
                    .to_string(),
            );
        }
        if self.state_file.trim().is_empty() {
            return Err("dynamic_whitelist.state_file 不能为空".to_string());
        }
        if self.cidr_expand_ipv4 != 32 && self.cidr_expand_ipv4 != 24 {
            return Err(format!(
                "dynamic_whitelist.cidr_expand_ipv4 只能是 32 或 24，当前值: {}",
                self.cidr_expand_ipv4
            ));
        }
        for (idx, domain) in self.domains.iter().enumerate() {
            domain
                .validate()
                .map_err(|e| format!("dynamic_whitelist.domains[{}] {e}", idx + 1))?;
        }
        Ok(())
    }
}

impl DynamicWhitelistDomainConfig {
    pub fn validate(&self) -> Result<(), String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("name 不能为空".to_string());
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(format!(
                "name 只能包含 ASCII 字母、数字、下划线、短横线或点: {name}"
            ));
        }
        validate_dynamic_whitelist_domain(&self.domain)?;
        Ok(())
    }
}

pub fn validate_dynamic_whitelist_domain(domain: &str) -> Result<(), String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err("domain 不能为空".to_string());
    }
    if trimmed.len() > 253 {
        return Err(format!("domain 长度超过 253 字符: {trimmed}"));
    }
    if trimmed.contains(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains(':')
        || trimmed.contains('*')
    {
        return Err(format!("domain 不是合法 DDNS 域名: {trimmed}"));
    }
    let without_trailing_dot = trimmed.trim_end_matches('.');
    if without_trailing_dot.is_empty() {
        return Err("domain 不是合法 DDNS 域名: .".to_string());
    }
    for label in without_trailing_dot.split('.') {
        if label.is_empty() {
            return Err(format!("domain 包含空 label: {trimmed}"));
        }
        if label.len() > 63 {
            return Err(format!("domain label 长度超过 63 字符: {label}"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("domain label 不能以短横线开头或结尾: {label}"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("domain 包含非法字符: {trimmed}"));
        }
    }
    Ok(())
}

fn validate_access_entry(entry: &str) -> Result<(), String> {
    if entry.trim().is_empty() {
        return Err("access_control entries 不能为空".to_string());
    }
    if entry.parse::<IpAddr>().is_ok() || entry.parse::<ipnetwork::IpNetwork>().is_ok() {
        return Ok(());
    }
    Err(format!(
        "access_control entry 只支持 IP/CIDR，不支持域名或非法值: {entry}"
    ))
}

impl TryFrom<&str> for NftCell {
    type Error = ParseError;

    /// 从legacy格式行解析NftCell
    /// 注释行和空行返回 Err(ParseError::Skip)
    /// 格式错误返回 Err(ParseError::InvalidFormat)
    fn try_from(line: &str) -> Result<Self, Self::Error> {
        let line = line.trim();

        // 处理注释和空行
        if line.is_empty() || line.starts_with('#') {
            return Err(ParseError::Skip);
        }

        let cells: Vec<&str> = line.split(',').collect();
        let rule_type = cells.first().map(|s| s.trim()).unwrap_or("");

        // 处理DROP类型
        if rule_type == "DROP" {
            if cells.len() < 3 {
                return Err(ParseError::InvalidFormat(format!(
                    "无效的过滤规则: {line}, DROP类型至少需要3个字段"
                )));
            }

            let chain: Chain = cells[1].trim().into();

            let mut src_ip: Option<String> = None;
            let mut dst_ip: Option<String> = None;
            let mut src_port: Option<u16> = None;
            let mut src_port_end: Option<u16> = None;
            let mut dst_port: Option<u16> = None;
            let mut dst_port_end: Option<u16> = None;
            let mut protocol = Protocol::All;

            // 解析key=value对和其他参数
            for cell in cells.iter().skip(2) {
                let cell = cell.trim();

                // 检查是否是协议
                if cell == "tcp" || cell == "udp" || cell == "all" {
                    protocol = cell.into();
                    continue;
                }

                // 解析key=value
                if let Some(eq_pos) = cell.find('=') {
                    let key = &cell[..eq_pos];
                    let value = &cell[eq_pos + 1..];

                    match key {
                        "src_ip" => src_ip = Some(value.to_string()),
                        "dst_ip" => dst_ip = Some(value.to_string()),
                        "src_port" => {
                            if value.contains('-') {
                                let parts: Vec<&str> = value.split('-').collect();
                                if parts.len() != 2 {
                                    return Err(ParseError::InvalidFormat(format!(
                                        "无效的端口范围格式: {value}"
                                    )));
                                }
                                src_port = Some(parts[0].parse::<u16>()?);
                                src_port_end = Some(parts[1].parse::<u16>()?);
                            } else {
                                src_port = Some(value.parse::<u16>()?);
                            }
                        }
                        "dst_port" => {
                            if value.contains('-') {
                                let parts: Vec<&str> = value.split('-').collect();
                                if parts.len() != 2 {
                                    return Err(ParseError::InvalidFormat(format!(
                                        "无效的端口范围格式: {value}"
                                    )));
                                }
                                dst_port = Some(parts[0].parse::<u16>()?);
                                dst_port_end = Some(parts[1].parse::<u16>()?);
                            } else {
                                dst_port = Some(value.parse::<u16>()?);
                            }
                        }
                        _ => {
                            return Err(ParseError::InvalidFormat(format!(
                                "未知的过滤参数: {key}"
                            )));
                        }
                    }
                }
            }

            return Ok(NftCell::Drop {
                chain,
                src_ip,
                dst_ip,
                src_port,
                src_port_end,
                dst_port,
                dst_port_end,
                protocol,
                comment: None,
            });
        }

        // 验证字段数量（对于非DROP类型）
        match rule_type {
            "REDIRECT" => {
                if cells.len() < 3 || cells.len() > 5 {
                    return Err(ParseError::InvalidFormat(format!(
                        "无效的配置行: {line}, REDIRECT类型需要3-5个字段"
                    )));
                }
            }
            "SINGLE" | "RANGE" => {
                if cells.len() < 4 || cells.len() > 6 {
                    return Err(ParseError::InvalidFormat(format!(
                        "无效的配置行: {line}, 字段数量不正确（需要4-6个字段）"
                    )));
                }
            }
            _ => {
                return Err(ParseError::InvalidFormat(format!(
                    "无效的转发规则类型: {}",
                    rule_type
                )));
            }
        }

        // 解析协议
        let protocol: Protocol = if rule_type == "REDIRECT" {
            if cells.len() >= 4 {
                cells[3].trim().into()
            } else {
                Protocol::All
            }
        } else if cells.len() >= 5 {
            cells[4].trim().into()
        } else {
            Protocol::All
        };

        // 解析IP版本
        let ip_version: IpVersion = if rule_type == "REDIRECT" {
            if cells.len() >= 5 {
                cells[4].trim().into()
            } else {
                IpVersion::V4 // 默认IPv4以保持向后兼容
            }
        } else if cells.len() >= 6 {
            cells[5].trim().into()
        } else {
            IpVersion::V4 // 默认IPv4以保持向后兼容
        };

        // 解析类型并创建NftCell
        match rule_type {
            "RANGE" => {
                let port_start = cells[1].trim().parse::<u16>()?;
                let port_end = cells[2].trim().parse::<u16>()?;

                Ok(NftCell::Range {
                    enabled: true,
                    port_start,
                    port_end,
                    domain: cells[3].trim().to_string(),
                    protocol,
                    ip_version,
                    comment: None,
                    quota_enabled: false,
                    quota_bytes: 0,
                    quota_period: QuotaPeriod::default(),
                    quota_action: QuotaAction::default(),
                })
            }
            "SINGLE" => {
                let sport = cells[1].trim().parse::<u16>()?;
                let dport = cells[2].trim().parse::<u16>()?;

                Ok(NftCell::Single {
                    enabled: true,
                    sport,
                    dport,
                    domain: cells[3].trim().to_string(),
                    protocol,
                    ip_version,
                    comment: None,
                    quota_enabled: false,
                    quota_bytes: 0,
                    quota_period: QuotaPeriod::default(),
                    quota_action: QuotaAction::default(),
                })
            }
            "REDIRECT" => {
                let port_field = cells[1].trim();
                let (src_port, src_port_end) = if port_field.contains('-') {
                    let parts: Vec<&str> = port_field.split('-').collect();
                    if parts.len() != 2 {
                        return Err(ParseError::InvalidFormat(format!(
                            "无效的端口范围格式: {port_field}，应为 start-end"
                        )));
                    }
                    let start = parts[0].trim().parse::<u16>()?;
                    let end = parts[1].trim().parse::<u16>()?;
                    (start, Some(end))
                } else {
                    (port_field.parse::<u16>()?, None)
                };

                let dst_port = cells[2].trim().parse::<u16>()?;

                Ok(NftCell::Redirect {
                    enabled: true,
                    src_port,
                    src_port_end,
                    dst_port,
                    protocol,
                    ip_version,
                    comment: None,
                    quota_enabled: false,
                    quota_bytes: 0,
                    quota_period: QuotaPeriod::default(),
                    quota_action: QuotaAction::default(),
                })
            }
            _ => Err(ParseError::InvalidFormat(format!(
                "无效的转发规则类型: {}",
                rule_type
            ))),
        }
    }
}

impl NftCell {
    /// 验证单个规则是否合法
    pub fn validate(&self) -> Result<(), String> {
        match self {
            NftCell::Single {
                sport,
                dport,
                domain,
                ..
            } => {
                if domain.trim().is_empty() {
                    return Err("域名不能为空".to_string());
                }
                validate_port(*sport)?;
                validate_port(*dport)?;
            }
            NftCell::Range {
                port_start,
                port_end,
                domain,
                ..
            } => {
                if domain.trim().is_empty() {
                    return Err("域名不能为空".to_string());
                }
                if port_start >= port_end {
                    return Err(format!(
                        "起始端口 {} 必须小于结束端口 {}",
                        port_start, port_end
                    ));
                }
                validate_port(*port_start)?;
                validate_port(*port_end)?;
            }
            NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            } => {
                if let Some(end) = src_port_end {
                    if src_port >= end {
                        return Err(format!("起始端口 {} 必须小于结束端口 {}", src_port, end));
                    }
                    validate_port(*end)?;
                }
                validate_port(*src_port)?;
                validate_port(*dst_port)?;
            }
            NftCell::Drop {
                src_ip,
                dst_ip,
                src_port,
                src_port_end,
                dst_port,
                dst_port_end,
                ..
            } => {
                // 至少需要指定一个过滤条件
                if src_ip.is_none() && dst_ip.is_none() && src_port.is_none() && dst_port.is_none()
                {
                    return Err(
                        "至少需要指定一个过滤条件（源IP、目标IP、源端口或目标端口）".to_string()
                    );
                }

                // 验证端口范围
                if let Some(port) = src_port {
                    validate_port(*port)?;
                    if let Some(end) = src_port_end {
                        validate_port(*end)?;
                        if port >= end {
                            return Err(format!("源端口起始 {} 必须小于结束端口 {}", port, end));
                        }
                    }
                }

                if let Some(port) = dst_port {
                    validate_port(*port)?;
                    if let Some(end) = dst_port_end {
                        validate_port(*end)?;
                        if port >= end {
                            return Err(format!("目标端口起始 {} 必须小于结束端口 {}", port, end));
                        }
                    }
                }

                // 验证IP地址格式
                if let Some(ip) = src_ip {
                    if ip.trim().is_empty() {
                        return Err("源IP不能为空".to_string());
                    }
                    validate_ip_address(ip, "源IP")?;
                }

                if let Some(ip) = dst_ip {
                    if ip.trim().is_empty() {
                        return Err("目标IP不能为空".to_string());
                    }
                    validate_ip_address(ip, "目标IP")?;
                }
            }
        }
        Ok(())
    }
}

fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("端口号不能为0".to_string());
    }
    Ok(())
}

/// 验证IP地址格式
fn validate_ip_address(ip: &str, field_name: &str) -> Result<(), String> {
    // 尝试解析为 IpNetwork（支持 CIDR 表示法）
    if ipnetwork::IpNetwork::from_str(ip).is_ok() {
        Ok(())
    } else {
        Err(format!("{}地址 '{}' 格式无效", field_name, ip))
    }
}

/// 验证legacy格式配置内容
/// 返回第一个遇到的错误，跳过注释和空行
pub fn validate_legacy_config(content: &str) -> Result<(), String> {
    for (line_num, line) in content.lines().enumerate() {
        match NftCell::try_from(line) {
            Ok(cell) => {
                cell.validate()
                    .map_err(|e| format!("第 {} 行验证失败: {}", line_num + 1, e))?;
            }
            Err(ParseError::Skip) => continue,
            Err(ParseError::InvalidFormat(msg)) => {
                return Err(format!("第 {} 行解析失败: {}", line_num + 1, msg));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cli_time_renders_shanghai_24h_without_nanos() {
        let utc = chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58.213104971Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let rendered = format_cli_time(utc);
        assert_eq!(rendered, "2026-05-19 20:02:58 CST");
        // 不允许 RFC3339 风格的时间 + 时区分隔符：日期和时间之间用空格，不用 T；不要 "+08:00"。
        // 注意 "CST" 后缀里也带 'T'，所以要检查"时间字段后紧接 T"的形式，而不是泛 contains('T')。
        assert!(
            !rendered.contains("T2") && !rendered.contains("T0") && !rendered.contains("T1"),
            "must not use RFC3339 date-T-time form: {rendered}"
        );
        assert!(!rendered.contains('.'), "must not include nanoseconds");
        assert!(
            !rendered.contains('+'),
            "must not show numeric offset like +08:00"
        );
    }

    #[test]
    fn format_cli_time_handles_midnight_utc_wraps_into_next_day_shanghai() {
        let utc = chrono::DateTime::parse_from_rfc3339("2026-05-19T17:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // UTC 17:30 → Shanghai 01:30 the next day
        let rendered = format_cli_time(utc);
        assert_eq!(rendered, "2026-05-20 01:30:00 CST");
    }

    #[test]
    fn format_cli_time_from_rfc3339_falls_back_on_unknown_format() {
        assert_eq!(
            format_cli_time_from_rfc3339("2026-05-19T12:02:58Z"),
            "2026-05-19 20:02:58 CST"
        );
        assert_eq!(
            format_cli_time_from_rfc3339("not-a-timestamp"),
            "not-a-timestamp"
        );
    }

    // ============ v0.4.2: UiConfig + format_cli_time_with ============

    #[test]
    fn ui_config_default_is_asia_shanghai_24h() {
        let ui = UiConfig::default();
        assert_eq!(ui.timezone, "Asia/Shanghai");
        assert!(ui.time_format.contains("%H:%M:%S"));
        ui.validate().unwrap();
    }

    #[test]
    fn ui_config_validate_rejects_invalid_timezone() {
        let ui = UiConfig {
            timezone: "Invalid/Zone".to_string(),
            time_format: "%Y-%m-%d %H:%M:%S %Z".to_string(),
        };
        assert!(ui.validate().is_err());
        assert!(validate_iana_timezone("Invalid/Zone").is_err());
        assert!(validate_iana_timezone("").is_err());
    }

    #[test]
    fn ui_config_validate_accepts_common_iana_names() {
        for tz in ["Asia/Shanghai", "UTC", "America/Chicago", "Europe/Paris"] {
            validate_iana_timezone(tz).unwrap_or_else(|e| panic!("{tz} should be valid: {e}"));
        }
    }

    #[test]
    fn format_cli_time_with_utc_renders_utc_clock() {
        let utc = chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ui = UiConfig {
            timezone: "UTC".to_string(),
            time_format: "%Y-%m-%d %H:%M:%S %Z".to_string(),
        };
        let rendered = format_cli_time_with(utc, &ui);
        assert!(rendered.starts_with("2026-05-19 12:02:58"));
        assert!(rendered.contains("UTC"));
    }

    #[test]
    fn format_cli_time_with_america_chicago_applies_dst_offset() {
        // 2026-07-15 = CDT（夏令时，UTC-5）。chrono-tz 必须正确处理。
        let utc = chrono::DateTime::parse_from_rfc3339("2026-07-15T17:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ui = UiConfig {
            timezone: "America/Chicago".to_string(),
            time_format: "%Y-%m-%d %H:%M:%S %Z".to_string(),
        };
        let rendered = format_cli_time_with(utc, &ui);
        // Chicago CDT = UTC-5：17:00 → 12:00
        assert!(
            rendered.starts_with("2026-07-15 12:00:00"),
            "got {rendered}"
        );
    }

    #[test]
    fn format_cli_time_default_still_returns_shanghai() {
        // 回归保护：默认 UiConfig 渲染仍是 Asia/Shanghai +8
        let utc = chrono::DateTime::parse_from_rfc3339("2026-05-19T12:02:58Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(format_cli_time(utc), "2026-05-19 20:02:58 CST");
    }

    #[test]
    fn from_toml_str_rejects_invalid_ui_timezone() {
        let body = r#"
[ui]
timezone = "Mars/Olympus"
"#;
        let err = TomlConfig::from_toml_str(body).unwrap_err();
        assert!(
            err.contains("ui.timezone"),
            "expected ui.timezone error: {err}"
        );
    }

    #[test]
    fn from_toml_str_accepts_ui_section() {
        let body = r#"
[ui]
timezone = "UTC"
time_format = "%Y-%m-%d %H:%M:%S %Z"
"#;
        let cfg = TomlConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.ui.timezone, "UTC");
    }

    #[test]
    fn test_validate_single_rule() {
        let rule = NftCell::Single {
            enabled: true,
            sport: 10000,
            dport: 443,
            domain: "example.com".to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_domain() {
        let rule = NftCell::Single {
            enabled: true,
            sport: 10000,
            dport: 443,
            domain: "".to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_validate_range_rule() {
        let rule = NftCell::Range {
            enabled: true,
            port_start: 1000,
            port_end: 2000,
            domain: "example.com".to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::All,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_range() {
        let rule = NftCell::Range {
            enabled: true,
            port_start: 2000,
            port_end: 1000,
            domain: "example.com".to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_parse_and_validate_toml() {
        let toml_str = r#"
[[rules]]
type = "single"
sport = 10000
dport = 443
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"

[[rules]]
type = "range"
port_start = 1000
port_end = 2000
domain = "example.com"
protocol = "all"
ip_version = "all"
"#;
        let result = TomlConfig::from_toml_str(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_access_control_defaults_when_missing() {
        let config = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(config.dns.reject_fake_ip);
        assert_eq!(config.dns.fake_ip_cidrs, vec!["198.18.0.0/15"]);
        assert_eq!(config.ddns.refresh_interval_seconds, 300);
        assert_eq!(config.access_control.mode, AccessControlMode::Off);
        assert!(config.access_control.entries.is_empty());
        assert!(!config.dynamic_whitelist.enabled);
        assert_eq!(config.dynamic_whitelist.refresh_interval_seconds, 300);
        assert!(config.dynamic_whitelist.use_last_good_on_dns_failure);
        assert!(config.dynamic_whitelist.resolve_ipv4);
        assert!(!config.dynamic_whitelist.resolve_ipv6);
        assert!(config.dynamic_whitelist.notify_on_change);
        assert_eq!(config.dynamic_whitelist.cidr_expand_ipv4, 32);
        assert!(config.dynamic_whitelist.domains.is_empty());
    }

    #[test]
    fn test_dns_config_parses() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[dns]
reject_fake_ip = false
fake_ip_cidrs = ["198.18.0.0/15", "100.64.0.0/10"]
resolver_mode = "system"
nameservers = ["1.1.1.1:53"]
fallback_to_system = true
"#,
        )
        .unwrap();
        assert!(!config.dns.reject_fake_ip);
        assert_eq!(config.dns.fake_ip_cidrs.len(), 2);
    }

    #[test]
    fn test_ddns_config_parses() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[ddns]
refresh_interval_seconds = 120
"#,
        )
        .unwrap();
        assert_eq!(config.ddns.refresh_interval_seconds, 120);
    }

    #[test]
    fn test_access_control_parses() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[access_control]
mode = "whitelist"
entries = ["192.0.2.1", "2001:db8::/64"]
"#,
        )
        .unwrap();
        assert_eq!(config.access_control.mode, AccessControlMode::Whitelist);
        assert_eq!(config.access_control.entries.len(), 2);
    }

    #[test]
    fn dynamic_whitelist_parses_defaults_and_domains() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true

[[dynamic_whitelist.domains]]
name = "home"
domain = "home.example.com"
"#,
        )
        .unwrap();
        assert!(config.dynamic_whitelist.enabled);
        assert_eq!(config.dynamic_whitelist.refresh_interval_seconds, 300);
        assert!(config.dynamic_whitelist.use_last_good_on_dns_failure);
        assert!(config.dynamic_whitelist.resolve_ipv4);
        assert!(!config.dynamic_whitelist.resolve_ipv6);
        assert!(config.dynamic_whitelist.notify_on_change);
        assert_eq!(config.dynamic_whitelist.cidr_expand_ipv4, 32);
        assert_eq!(config.dynamic_whitelist.domains.len(), 1);
        assert!(config.dynamic_whitelist.domains[0].enabled);
    }

    #[test]
    fn dynamic_whitelist_cidr_expand_24_is_valid() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true
cidr_expand_ipv4 = 24

[[dynamic_whitelist.domains]]
name = "home"
domain = "home.example.com"
"#,
        )
        .unwrap();
        assert_eq!(config.dynamic_whitelist.cidr_expand_ipv4, 24);
    }

    #[test]
    fn dynamic_whitelist_cidr_expand_invalid_values_rejected() {
        for value in [0u8, 16, 25, 33] {
            let toml = format!(
                "rules = []\n\n[dynamic_whitelist]\nenabled = true\ncidr_expand_ipv4 = {value}\n"
            );
            let err = TomlConfig::from_toml_str(&toml).unwrap_err();
            assert!(
                err.contains("cidr_expand_ipv4"),
                "value {value} should be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn dynamic_whitelist_allows_empty_domains() {
        let config = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true
domains = []
"#,
        )
        .unwrap();
        assert!(config.dynamic_whitelist.domains.is_empty());
    }

    #[test]
    fn dynamic_whitelist_rejects_empty_name_and_domain() {
        let empty_name = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true

[[dynamic_whitelist.domains]]
name = ""
domain = "home.example.com"
"#,
        )
        .unwrap_err();
        assert!(empty_name.contains("name 不能为空"));

        let empty_domain = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true

[[dynamic_whitelist.domains]]
name = "home"
domain = ""
"#,
        )
        .unwrap_err();
        assert!(empty_domain.contains("domain 不能为空"));
    }

    #[test]
    fn dynamic_whitelist_rejects_invalid_domain() {
        let err = TomlConfig::from_toml_str(
            r#"
rules = []

[dynamic_whitelist]
enabled = true

[[dynamic_whitelist.domains]]
name = "home"
domain = "https://home.example.com"
"#,
        )
        .unwrap_err();
        assert!(err.contains("不是合法 DDNS 域名"));
    }

    #[test]
    fn test_access_control_rejects_invalid_mode() {
        let err = TomlConfig::from_toml_str(
            r#"
rules = []

[access_control]
mode = "allow"
"#,
        )
        .unwrap_err();
        assert!(err.contains("invalid access_control mode"));
    }

    #[test]
    fn test_access_control_rejects_invalid_entry() {
        let err = TomlConfig::from_toml_str(
            r#"
rules = []

[access_control]
mode = "blacklist"
entries = ["example.com"]
"#,
        )
        .unwrap_err();
        assert!(err.contains("access_control entry 只支持 IP/CIDR"));
    }

    #[test]
    fn snat_defaults_to_masquerade_when_section_missing() {
        let cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        assert_eq!(cfg.snat.mode, SnatMode::Masquerade);
        assert!(cfg.snat.fixed_source_ip.is_empty());
    }

    #[test]
    fn snat_accepts_masquerade_fixed_off_modes() {
        for mode in ["masquerade", "fixed", "off"] {
            let body = if mode == "fixed" {
                format!(
                    "rules = []\n\n[snat]\nmode = \"{mode}\"\nfixed_source_ip = \"10.100.0.10\"\n"
                )
            } else {
                format!("rules = []\n\n[snat]\nmode = \"{mode}\"\n")
            };
            let cfg = TomlConfig::from_toml_str(&body)
                .unwrap_or_else(|e| panic!("mode={mode} should parse, got: {e}"));
            assert_eq!(cfg.snat.mode.to_string(), mode);
        }
    }

    #[test]
    fn snat_rejects_unknown_mode() {
        let err =
            TomlConfig::from_toml_str("rules = []\n\n[snat]\nmode = \"bogus\"\n").unwrap_err();
        assert!(err.contains("invalid snat.mode"));
    }

    #[test]
    fn snat_fixed_requires_non_empty_ip() {
        let err = TomlConfig::from_toml_str(
            "rules = []\n\n[snat]\nmode = \"fixed\"\nfixed_source_ip = \"\"\n",
        )
        .unwrap_err();
        assert!(err.contains("fixed_source_ip 不能为空"));
    }

    #[test]
    fn snat_fixed_rejects_ipv6_address() {
        let err = TomlConfig::from_toml_str(
            "rules = []\n\n[snat]\nmode = \"fixed\"\nfixed_source_ip = \"2001:db8::1\"\n",
        )
        .unwrap_err();
        assert!(err.contains("仅支持 IPv4"));
    }

    #[test]
    fn snat_fixed_rejects_invalid_ip_literal() {
        let err = TomlConfig::from_toml_str(
            "rules = []\n\n[snat]\nmode = \"fixed\"\nfixed_source_ip = \"not-an-ip\"\n",
        )
        .unwrap_err();
        assert!(err.contains("不是合法 IPv4 地址"));
    }

    #[test]
    fn mss_clamp_defaults_disabled_with_1452() {
        let cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(!cfg.mss_clamp.enabled);
        assert_eq!(cfg.mss_clamp.size, 1452);
    }

    #[test]
    fn mss_clamp_rejects_size_too_small() {
        let err =
            TomlConfig::from_toml_str("rules = []\n\n[mss_clamp]\nenabled = true\nsize = 535\n")
                .unwrap_err();
        assert!(err.contains("536-1460"));
    }

    #[test]
    fn mss_clamp_rejects_size_too_large() {
        let err =
            TomlConfig::from_toml_str("rules = []\n\n[mss_clamp]\nenabled = true\nsize = 1461\n")
                .unwrap_err();
        assert!(err.contains("536-1460"));
    }

    #[test]
    fn last_good_defaults_when_section_missing() {
        let cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(cfg.last_good.enabled);
        assert!(cfg.last_good.use_last_good_on_dns_failure);
        assert_eq!(
            cfg.last_good.file,
            "/var/lib/nftables-nat-rust/last-good-state.json"
        );
    }

    #[test]
    fn audit_defaults_when_section_missing() {
        let cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(cfg.audit.enabled);
        assert_eq!(cfg.audit.file, "/var/log/nftables-nat-rust-audit.log");
    }

    #[test]
    fn last_good_validates_empty_file() {
        let err = TomlConfig::from_toml_str("rules = []\n[last_good]\nfile = \"\"\n").unwrap_err();
        assert!(err.contains("last_good.file"));
    }

    #[test]
    fn audit_validates_empty_file() {
        let err = TomlConfig::from_toml_str("rules = []\n[audit]\nfile = \"\"\n").unwrap_err();
        assert!(err.contains("audit.file"));
    }

    #[test]
    fn quota_defaults_when_section_missing() {
        let cfg = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(cfg.quota.enabled);
        assert_eq!(cfg.quota.check_interval_seconds, 60);
        assert!(cfg.quota.notify_on_exceeded);
        assert_eq!(
            cfg.quota.state_file,
            "/var/lib/nftables-nat-rust/quota-state.json"
        );
    }

    #[test]
    fn quota_validates_zero_check_interval() {
        let err = TomlConfig::from_toml_str("rules = []\n[quota]\ncheck_interval_seconds = 0\n")
            .unwrap_err();
        assert!(err.contains("check_interval_seconds"));
    }

    #[test]
    fn rule_quota_fields_default_when_missing() {
        let toml = r#"
[[rules]]
type = "single"
sport = 30080
dport = 80
domain = "example.com"
protocol = "tcp"
ip_version = "ipv4"
comment = "no-quota"
enabled = true
"#;
        let cfg = TomlConfig::from_toml_str(toml).unwrap();
        let rule = &cfg.rules[0];
        assert!(!rule.quota_enabled());
        assert_eq!(rule.quota_bytes(), 0);
        assert_eq!(rule.quota_period(), QuotaPeriod::Monthly);
        assert_eq!(rule.quota_action(), QuotaAction::Disable);
    }

    #[test]
    fn rule_quota_fields_parse_and_serde() {
        let toml = r#"
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
quota_bytes = 107374182400
quota_period = "monthly"
quota_action = "disable"
"#;
        let cfg = TomlConfig::from_toml_str(toml).unwrap();
        let rule = &cfg.rules[0];
        assert!(rule.quota_enabled());
        assert_eq!(rule.quota_bytes(), 107_374_182_400);
        assert_eq!(rule.quota_period(), QuotaPeriod::Monthly);
        assert_eq!(rule.quota_action(), QuotaAction::Disable);
        // 序列化往返
        let roundtrip = cfg.to_toml_string().unwrap();
        assert!(roundtrip.contains("quota_enabled = true"));
        assert!(roundtrip.contains("quota_period = \"monthly\""));
    }

    #[test]
    fn rule_quota_period_rejects_invalid_value() {
        let err = TomlConfig::from_toml_str(
            "[[rules]]\ntype=\"single\"\nsport=1\ndport=1\ndomain=\"x\"\nquota_period=\"yearly\"\n",
        )
        .unwrap_err();
        assert!(err.contains("quota_period"));
    }

    #[test]
    fn rule_quota_action_rejects_invalid_value() {
        let err = TomlConfig::from_toml_str(
            "[[rules]]\ntype=\"single\"\nsport=1\ndport=1\ndomain=\"x\"\nquota_action=\"throttle\"\n",
        )
        .unwrap_err();
        assert!(err.contains("quota_action"));
    }

    #[test]
    fn mss_clamp_accepts_boundary_values() {
        let lo =
            TomlConfig::from_toml_str("rules = []\n\n[mss_clamp]\nenabled = true\nsize = 536\n")
                .unwrap();
        let hi =
            TomlConfig::from_toml_str("rules = []\n\n[mss_clamp]\nenabled = true\nsize = 1460\n")
                .unwrap();
        assert_eq!(lo.mss_clamp.size, 536);
        assert_eq!(hi.mss_clamp.size, 1460);
    }

    #[test]
    fn test_ip_version_serde() {
        assert_eq!(IpVersion::from("ipv4"), IpVersion::V4);
        assert_eq!(IpVersion::from("ipv6"), IpVersion::V6);
        assert_eq!(IpVersion::from("all"), IpVersion::All);
        assert_eq!(IpVersion::from("unknown"), IpVersion::All);
    }

    #[test]
    fn test_protocol_serde() {
        assert_eq!(Protocol::from("tcp"), Protocol::Tcp);
        assert_eq!(Protocol::from("udp"), Protocol::Udp);
        assert_eq!(Protocol::from("all"), Protocol::All);
        assert_eq!(Protocol::from("unknown"), Protocol::All);
    }

    #[test]
    fn test_nft_cell_display() {
        let cell = NftCell::Single {
            enabled: true,
            sport: 10000,
            dport: 443,
            domain: "example.com".to_string(),
            protocol: Protocol::Tcp,
            ip_version: IpVersion::V4,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert_eq!(cell.to_string(), "SINGLE,10000,443,example.com,tcp,ipv4");

        let cell = NftCell::Redirect {
            enabled: true,
            src_port: 8000,
            src_port_end: Some(9000),
            dst_port: 3128,
            protocol: Protocol::All,
            ip_version: IpVersion::All,
            comment: None,
            quota_enabled: false,
            quota_bytes: 0,
            quota_period: QuotaPeriod::default(),
            quota_action: QuotaAction::default(),
        };
        assert_eq!(cell.to_string(), "REDIRECT,8000-9000,3128,all,all");
    }

    #[test]
    fn test_try_from_single() {
        let line = "SINGLE,10000,443,example.com,tcp,ipv4";
        let cell = NftCell::try_from(line).unwrap();
        match cell {
            NftCell::Single {
                sport,
                dport,
                domain,
                protocol,
                ip_version,
                ..
            } => {
                assert_eq!(sport, 10000);
                assert_eq!(dport, 443);
                assert_eq!(domain, "example.com");
                assert_eq!(protocol, Protocol::Tcp);
                assert_eq!(ip_version, IpVersion::V4);
            }
            _ => panic!("Expected Single variant"),
        }
    }

    #[test]
    fn test_try_from_redirect_range() {
        let line = "REDIRECT,30001-39999,45678,tcp,ipv4";
        let cell = NftCell::try_from(line).unwrap();
        match cell {
            NftCell::Redirect {
                src_port,
                src_port_end,
                dst_port,
                ..
            } => {
                assert_eq!(src_port, 30001);
                assert_eq!(src_port_end, Some(39999));
                assert_eq!(dst_port, 45678);
            }
            _ => panic!("Expected Redirect variant"),
        }
    }

    #[test]
    fn test_try_from_comment() {
        let line = "# This is a comment";
        let result = NftCell::try_from(line);
        assert!(matches!(result, Err(ParseError::Skip)));
    }

    #[test]
    fn test_try_from_empty() {
        let line = "   ";
        let result = NftCell::try_from(line);
        assert!(matches!(result, Err(ParseError::Skip)));
    }

    #[test]
    fn test_try_from_invalid() {
        let line = "INVALID,123,456";
        let result = NftCell::try_from(line);
        assert!(matches!(result, Err(ParseError::InvalidFormat(_))));
    }

    #[test]
    fn test_validate_legacy_config() {
        let content = "# Comment\nSINGLE,10000,443,example.com,tcp,ipv4\nREDIRECT,8000,3128\n";
        assert!(validate_legacy_config(content).is_ok());
    }

    #[test]
    fn test_validate_legacy_config_invalid() {
        let content = "SINGLE,10000,443,example.com\nINVALID,123";
        let result = validate_legacy_config(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_drop_ipv4_with_ipv4_address() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_with_ipv6_address() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("2001:db8::1".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_ipv4_with_ipv6_address_fails() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("2001:db8::1".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_ipv6_with_ipv4_address_fails() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: None,
            dst_ip: Some("192.168.1.1".to_string()),
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_all_with_ipv4_address() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("10.0.0.1".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_all_with_ipv6_address() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("fe80::1".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_ipv4_cidr_notation() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_ipv6_cidr_notation() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("2001:db8::/32".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_drop_invalid_ip_address() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("invalid.ip.address".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        let result = rule.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("格式无效"));
    }

    #[test]
    fn test_drop_invalid_cidr() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("192.168.1.1/99".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        let result = rule.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("格式无效"));
    }

    #[test]
    fn geoip_and_egress_default_disabled_when_missing() {
        let config = TomlConfig::from_toml_str("rules = []").unwrap();
        assert!(!config.geoip.enabled);
        assert!(!config.geoip.forward.enabled);
        assert!(!config.geoip.ssh.enabled);
        assert_eq!(config.geoip.provider, "chnlist");
        assert_eq!(
            config.geoip.cn4_url,
            "https://raw.githubusercontent.com/alecthw/chnlist/release/nftables/cn4.nft"
        );
        assert_eq!(config.geoip.cn4_file, "/etc/nftables-nat/sets/cn4.nft");
        assert_eq!(config.geoip.update_interval_hours, 168);
        assert!(config.geoip.allow_lan);
        assert_eq!(config.geoip.ssh.port, 22);
        assert!(!config.egress_control.enabled);
        assert_eq!(config.egress_control.mode, "allow-targets");
        assert!(config.egress_control.allowed_target_cidrs.is_empty());
    }

    #[test]
    fn geoip_validates_mode_strings() {
        let mut config = GeoIpConfig::default();
        config.forward.mode = "deny-cn".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn egress_control_validates_mode_and_cidrs() {
        let mut config = EgressControlConfig {
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        config.allowed_target_cidrs.push("not-an-ip".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn egress_control_contains_matches_cidrs() {
        let config = EgressControlConfig {
            enabled: true,
            mode: "allow-targets".to_string(),
            allowed_target_cidrs: vec![
                "10.100.0.10/32".to_string(),
                "10.100.0.0/24".to_string(),
                "172.31.8.0/24".to_string(),
            ],
            comment: None,
        };
        assert!(config.allows_ip("10.100.0.10"));
        assert!(config.allows_ip("10.100.0.123"));
        assert!(config.allows_ip("172.31.8.1"));
        assert!(!config.allows_ip("8.8.8.8"));
        assert!(!config.allows_ip("not-an-ip"));
    }

    #[test]
    fn geoip_lan_ipv4_cidrs_only_returns_ipv4() {
        let config = GeoIpConfig {
            allow_lan: true,
            lan_cidrs: vec![
                "10.0.0.0/8".to_string(),
                "fd00::/8".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            ..Default::default()
        };
        let v4 = config.lan_ipv4_cidrs();
        assert_eq!(v4.len(), 2);
        assert!(v4.contains(&"10.0.0.0/8".to_string()));
        assert!(v4.contains(&"192.168.0.0/16".to_string()));
    }

    #[test]
    fn geoip_default_ssh_port_is_22_and_default_interval_one_week() {
        let g = GeoIpConfig::default();
        assert_eq!(g.ssh.port, 22);
        assert_eq!(g.update_interval_hours, 168);
        assert_eq!(g.ssh.mode, "allow-cn-and-lan");
    }

    #[test]
    fn test_drop_valid_ipv6_full() {
        let rule = NftCell::Drop {
            chain: Chain::Input,
            src_ip: Some("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string()),
            dst_ip: None,
            src_port: None,
            src_port_end: None,
            dst_port: None,
            dst_port_end: None,
            protocol: Protocol::All,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }
}
