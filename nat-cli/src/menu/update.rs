//! CLI 一键更新菜单：选择 latest / 指定版本 → 渲染更新摘要 → 调用 install.sh。
//!
//! 拆自原 `nat-cli/src/menu.rs`（v0.6.1 维护性重构），行为未变。包含：
//! - `update_menu`：菜单入口
//! - `UpdatePlan` / `build_update_plan`：把 latest / 指定版本转换为摘要数据
//! - `github_latest_resolver`：调用 curl 解析 GitHub releases/latest 的重定向
//! - `current_version_for_update` / `installed_nat_version` / `parse_nat_version_output` /
//!   `build_version_for_update_display` / `valid_update_version` / `valid_release_tag`
//! - `ReloadAction` / `reload_action` / `tty_available` / `reexec_menu`：成功后自动重载 CLI
//!
//! 测试在文件末尾的 `mod tests`，覆盖 build_update_plan / extract_release_tag /
//! parse_latest_tag_from_curl_headers。生产 resolver 不被单测调用——它会真实 curl GitHub。

use nat_common::audit::AuditResult;
use serde_json::json;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use super::{NAT_BIN_PATH, audit_cli, prompt, wait_enter_to_return};

pub(crate) fn update_menu(config_path: &str) -> Result<(), io::Error> {
    println!(
        r#"====================================
一键更新 nftables-nat-rust-enhanced
====================================
1) 更新核心转发 nat，推荐
2) 指定版本更新核心 nat
0) 返回"#
    );
    let choice = prompt("请选择 [0/1/2]: ")?;
    if choice.trim() == "0" {
        return Ok(());
    }
    let specify_version = match choice.trim() {
        "1" => false,
        "2" => true,
        _ => {
            println!("未知更新目标。");
            wait_enter_to_return()?;
            return Ok(());
        }
    };

    let version = if specify_version {
        let tag = prompt("请输入版本 tag，例如 v0.1.2: ")?;
        if !valid_update_version(&tag) {
            println!("无效版本，只允许 latest 或 v 开头的 tag，例如 v0.1.2");
            wait_enter_to_return()?;
            return Ok(());
        }
        tag
    } else {
        "latest".to_string()
    };
    let plan = build_update_plan(&version, github_latest_resolver);

    println!("更新摘要：");
    println!("  当前版本：{}", current_version_for_update());
    println!("  目标版本：{}", plan.display_version);
    println!("  选择来源：{}", plan.source);
    if let Some(w) = &plan.warning {
        println!("  warning：{w}");
    }
    println!("  将更新：/usr/local/bin/nat 和 nat.service");
    println!("  下载方式：GitHub Release 预编译包优先");
    println!("  备份：/etc/nftables-nat/backups/update-YYYYmmdd-HHMMSS/");
    println!("  保留：/etc/nat.toml、/etc/nat.conf、stats、backups");
    println!("  重启：nat.service");
    let confirm = prompt("继续更新？[y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y" | "yes" | "YES") {
        println!("已取消更新");
        wait_enter_to_return()?;
        return Ok(());
    }

    let mut args = vec!["--update", "--core-only", "--use-release"];
    if plan.install_arg_version != "latest" {
        args.push("--version");
        args.push(&plan.install_arg_version);
    }
    let command_line = format!(
        "curl -fsSL https://raw.githubusercontent.com/misaka-cpu/nftables-nat-rust-enhanced/main/install.sh | bash -s -- {}",
        args.join(" ")
    );
    audit_cli(
        config_path,
        "update.start",
        AuditResult::Info,
        json!({
            "version": plan.install_arg_version,
            "display_version": plan.display_version,
            "source": plan.source,
        }),
    );
    println!("开始更新，install.sh 会负责备份、重启和失败回滚。");
    let status = Command::new("sh").arg("-c").arg(command_line).status()?;
    if !status.success() {
        audit_cli(
            config_path,
            "update.fail",
            AuditResult::Fail,
            json!({
                "version": plan.install_arg_version,
                "display_version": plan.display_version,
                "source": plan.source,
                "exit_status": status.to_string(),
            }),
        );
        println!("更新命令执行失败。install.sh 会保留旧二进制并在可能时回滚，请查看输出和服务日志");
        wait_enter_to_return()?;
        return Ok(());
    }

    audit_cli(
        config_path,
        "update.success",
        AuditResult::Ok,
        json!({
            "version": plan.install_arg_version,
            "display_version": plan.display_version,
            "source": plan.source,
        }),
    );
    println!("更新完成，正在重新载入新版 CLI 菜单...");
    match installed_nat_version() {
        Some(v) => println!("已安装版本: {v}"),
        None => println!("warning: 无法读取新版本号，将继续重载菜单。"),
    }

    let bin_path = Path::new(NAT_BIN_PATH);
    let action = reload_action(true, tty_available(), bin_path.exists());
    match action {
        ReloadAction::Exec => {
            let err = reexec_menu(NAT_BIN_PATH);
            println!("更新已完成，但自动重新载入菜单失败：{err}");
            println!("请手动执行：");
            println!("  nat --menu");
            wait_enter_to_return()?;
        }
        ReloadAction::NoTty => {
            println!("更新已完成。请手动执行 nat --menu 进入新版菜单。");
        }
        ReloadAction::BinaryMissing => {
            println!("更新已完成，但未找到 {NAT_BIN_PATH}，无法自动重载菜单。");
            println!("请手动执行：");
            println!("  nat --menu");
            wait_enter_to_return()?;
        }
        ReloadAction::SkipUpdateFailed => {}
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReloadAction {
    SkipUpdateFailed,
    NoTty,
    BinaryMissing,
    Exec,
}

pub(crate) fn reload_action(
    update_success: bool,
    tty_available: bool,
    binary_exists: bool,
) -> ReloadAction {
    if !update_success {
        return ReloadAction::SkipUpdateFailed;
    }
    if !tty_available {
        return ReloadAction::NoTty;
    }
    if !binary_exists {
        return ReloadAction::BinaryMissing;
    }
    ReloadAction::Exec
}

pub(crate) fn tty_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

pub(crate) fn reexec_menu(bin: &str) -> io::Error {
    Command::new(bin).arg("--menu").exec()
}

pub(crate) fn current_version_for_update() -> String {
    installed_nat_version()
        .unwrap_or_else(|| build_version_for_update_display(nat_common::build_version()))
}

pub(crate) fn installed_nat_version() -> Option<String> {
    let output = Command::new("/usr/local/bin/nat")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_nat_version_output(&String::from_utf8_lossy(&output.stdout))
}

pub(crate) fn parse_nat_version_output(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|part| valid_release_tag(part))
        .map(ToString::to_string)
}

pub(crate) fn build_version_for_update_display(version: &str) -> String {
    if valid_release_tag(version) {
        version.to_string()
    } else {
        "unknown".to_string()
    }
}

pub(crate) fn valid_update_version(version: &str) -> bool {
    if version == "latest" {
        return true;
    }
    version.starts_with('v')
        && version.len() > 1
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub(crate) fn valid_release_tag(version: &str) -> bool {
    version.starts_with('v')
        && version.len() > 1
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdatePlan {
    pub display_version: String,
    pub source: &'static str,
    pub warning: Option<String>,
    pub install_arg_version: String,
}

pub(crate) fn build_update_plan<F>(version: &str, resolver: F) -> UpdatePlan
where
    F: FnOnce() -> Result<String, String>,
{
    if version == "latest" {
        match resolver() {
            Ok(tag) if valid_release_tag(&tag) => UpdatePlan {
                display_version: tag,
                source: "latest",
                warning: None,
                install_arg_version: "latest".to_string(),
            },
            Ok(other) => UpdatePlan {
                display_version: "latest".to_string(),
                source: "latest",
                warning: Some(format!(
                    "解析到的 release tag {other:?} 不符合 vX.Y.Z 格式，将交由 install.sh 使用 latest release。"
                )),
                install_arg_version: "latest".to_string(),
            },
            Err(e) => UpdatePlan {
                display_version: "latest".to_string(),
                source: "latest",
                warning: Some(format!(
                    "无法解析 latest release tag（{e}），将交由 install.sh 使用 latest release。"
                )),
                install_arg_version: "latest".to_string(),
            },
        }
    } else {
        UpdatePlan {
            display_version: version.to_string(),
            source: "specified",
            warning: None,
            install_arg_version: version.to_string(),
        }
    }
}

pub(crate) fn github_latest_resolver() -> Result<String, String> {
    let output = Command::new("curl")
        .arg("-fsI")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("10")
        .arg("https://github.com/misaka-cpu/nftables-nat-rust-enhanced/releases/latest")
        .output()
        .map_err(|e| format!("执行 curl 失败: {e}"))?;
    if !output.status.success() {
        return Err(format!("curl 退出码非零: {}", output.status));
    }
    let header = String::from_utf8_lossy(&output.stdout);
    parse_latest_tag_from_curl_headers(&header)
        .ok_or_else(|| "curl 响应里找不到 /releases/tag/<vX.Y.Z>".to_string())
}

pub(crate) fn parse_latest_tag_from_curl_headers(headers: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for line in headers.lines() {
        let lower = line.trim().to_ascii_lowercase();
        if !(lower.starts_with("location:") || lower.starts_with("location :")) {
            continue;
        }
        let (_, value) = line.split_once(':')?;
        let value = value.trim();
        if let Some(tag) = extract_release_tag(value) {
            best = Some(tag);
        }
    }
    best
}

pub(crate) fn extract_release_tag(url: &str) -> Option<String> {
    let idx = url.rfind("/tag/")?;
    let rest = &url[idx + 5..];
    let tag = rest
        .split(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
        .next()?;
    if tag.is_empty() {
        return None;
    }
    Some(tag.to_string())
}
