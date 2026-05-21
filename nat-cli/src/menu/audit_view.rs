//! CLI 「查看审计日志」子菜单：默认 CLI 友好格式（time 按展示时区 24h 展示），
//! 子菜单可切换为原始 JSON 行。文件内部仍是一行 JSON，便于 grep / jq。
//!
//! 拆自 `nat-cli/src/menu.rs`（v0.6.1 维护性重构），行为未变。

use nat_common::{AuditConfig, audit, format_cli_time_from_rfc3339_with};
use std::io;

use super::{
    audit_config_from, is_menu_refresh_command, load_toml_config, prompt, wait_enter_to_return,
};

pub(crate) fn view_audit_log_interactive(config_path: &str) -> Result<(), io::Error> {
    loop {
        let audit_cfg = audit_config_from(config_path);
        // ui_for_display：尽力读 [ui]；解析失败时回退默认，永不阻塞日志查看。
        let ui = load_toml_config(config_path)
            .map(|c| c.ui)
            .unwrap_or_default();
        println!("====================================");
        println!("审计日志（最近 50 行）");
        println!("====================================");
        println!("audit.enabled: {}", audit_cfg.enabled);
        println!("audit.file: {}", audit_cfg.file);
        if !audit_cfg.enabled {
            println!("提示：audit.enabled = false，CLI 操作不会写入审计日志。");
        }
        println!(
            "1) 查看格式化日志（默认，CLI 友好，按 [ui].timezone={} 展示）",
            ui.timezone
        );
        println!("2) 查看原始 JSON 日志");
        println!("0) 返回");
        let choice = prompt("请选择: ")?;
        match choice.trim() {
            "" | "1" => {
                show_audit_log_formatted(&audit_cfg, &ui);
                wait_enter_to_return()?;
            }
            "2" => {
                show_audit_log_raw(&audit_cfg);
                wait_enter_to_return()?;
            }
            "0" => break,
            value if is_menu_refresh_command(value) => break,
            _ => {
                println!("未知选项: {}", choice.trim());
                wait_enter_to_return()?;
            }
        }
    }
    Ok(())
}

fn show_audit_log_formatted(audit_cfg: &AuditConfig, ui: &nat_common::UiConfig) {
    println!();
    println!(
        "提示：JSON 内部 `time` 字段为 UTC RFC3339；CLI 按 [ui].timezone={} 展示。",
        ui.timezone
    );
    println!("------------------------------------");
    let lines = audit::read_tail(&audit_cfg.file, 50);
    if lines.is_empty() {
        println!("（无日志或文件不存在）");
    } else {
        for line in lines {
            let formatted =
                audit::format_log_line_for_cli(&line, |s| format_cli_time_from_rfc3339_with(s, ui));
            println!("{formatted}");
            println!();
        }
    }
    println!(
        "提示：每条审计日志为一行 JSON，便于 grep。完整文件位于 {}",
        audit_cfg.file
    );
}

fn show_audit_log_raw(audit_cfg: &AuditConfig) {
    println!();
    println!("------------------------------------");
    let lines = audit::read_tail(&audit_cfg.file, 50);
    if lines.is_empty() {
        println!("（无日志或文件不存在）");
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    println!();
    println!(
        "提示：每条审计日志为一行 JSON，便于 grep。完整文件位于 {}",
        audit_cfg.file
    );
}
