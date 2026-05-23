//! 「写 /etc/nat.toml 的安全流程」与「备份 / 恢复」相关的 helper。
//!
//! 拆自 `nat-cli/src/menu.rs`（v0.6.1 维护性重构），行为未变。
//!
//! - `safe_write_config` / `safe_write_config_to`：备份（rule.delete 跳过）→ 临时文件 + fsync → rename → audit
//! - `save_toml_config` / `save_toml_config_from_string`：把 TomlConfig 序列化后走 safe_write
//! - `backup_config_to` / `backup_config` / `backup_filename` / `list_config_backups`：备份相关
//! - `sanitize_backup_reason`：把 reason 字符串约束到文件名安全字符集
//! - `restore_config_interactive`：CLI 主菜单「10) 从备份恢复配置」

use chrono::Local;
use nat_common::{
    AuditConfig, TomlConfig, atomic,
    audit::{self, AuditResult},
};
use serde_json::json;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{
    CONFIG_BACKUP_DIR, audit_cli, audit_config_from, parse_index, print_config_saved_hint, prompt,
};

pub(crate) fn save_toml_config(
    path: &str,
    config: &TomlConfig,
    reason: &str,
) -> Result<Option<PathBuf>, io::Error> {
    let content = config
        .to_toml_string()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    safe_write_config(path, &content, reason)
}

pub(crate) fn save_toml_config_from_string(
    path: &str,
    content: &str,
    reason: &str,
) -> Result<Option<PathBuf>, io::Error> {
    safe_write_config(path, content, reason)
}

/// 安全写 TOML 配置：备份（rule.delete 跳过）→ tmp+fsync+rename → audit。
/// 备份目录使用 [`CONFIG_BACKUP_DIR`]；audit 从 `path` 解析 [`AuditConfig`]。
pub(crate) fn safe_write_config(
    path: &str,
    content: &str,
    reason: &str,
) -> Result<Option<PathBuf>, io::Error> {
    let audit_cfg = audit_config_from(path);
    safe_write_config_to(
        Path::new(CONFIG_BACKUP_DIR),
        &audit_cfg,
        path,
        content,
        reason,
    )
}

/// 可注入备份目录与 audit 配置的 safe_write 内核；测试与 quota 自动禁用复用。
///
/// - `reason == "rule.delete"` → 跳过备份，但仍原子写入并写 `backup_skipped=true` audit。
/// - 其它 reason 备份失败 → 返回 Err，不覆盖旧文件，写 `config.write.fail` audit。
/// - 临时文件写入或 rename 失败 → 返回 Err，旧文件保持不变，写 `config.write.fail` audit。
///   - rename 失败时 [`atomic::write_atomic`] 会清理 .tmp。
/// - 成功 → 写 `config.write.success` audit，返回备份路径；跳过备份时返回 `None`。
///
/// audit detail 不包含 TOML 内容本身、不包含 bot_token；只包含 reason / path / backup / error。
pub(crate) fn safe_write_config_to(
    backup_dir: &Path,
    audit_cfg: &AuditConfig,
    path: &str,
    content: &str,
    reason: &str,
) -> Result<Option<PathBuf>, io::Error> {
    let backup_path = if skips_config_backup(reason) {
        None
    } else {
        match backup_config_to(backup_dir, path, reason) {
            Ok(p) => Some(p),
            Err(e) => {
                audit::log_event(
                    audit_cfg,
                    "config.write.fail",
                    AuditResult::Fail,
                    json!({
                        "reason": reason,
                        "path": path,
                        "stage": "backup",
                        "error": e.to_string(),
                    }),
                );
                return Err(e);
            }
        }
    };
    if let Err(e) = atomic::write_atomic(path, content) {
        let mut detail = json!({
            "reason": reason,
            "path": path,
            "stage": "write_or_rename",
            "error": e.to_string(),
        });
        if let Some(backup_path) = &backup_path {
            detail["backup"] = json!(backup_path.display().to_string());
        } else if skips_config_backup(reason) {
            detail["backup_skipped"] = json!(true);
            detail["backup_skip_reason"] = json!(reason);
        }
        audit::log_event(audit_cfg, "config.write.fail", AuditResult::Fail, detail);
        return Err(e);
    }
    let detail = if let Some(backup_path) = &backup_path {
        json!({
            "reason": reason,
            "path": path,
            "backup": backup_path.display().to_string(),
        })
    } else {
        json!({
            "reason": reason,
            "path": path,
            "backup_skipped": true,
            "backup_skip_reason": reason,
        })
    };
    audit::log_event(audit_cfg, "config.write.success", AuditResult::Ok, detail);
    Ok(backup_path)
}

fn skips_config_backup(reason: &str) -> bool {
    reason == "rule.delete"
}

/// `backup_config_to`：按 reason 命名备份并设 0600 权限。
/// 备份文件名形如 `nat.toml.<reason>-YYYYmmdd-HHMMSS.bak`，与 `quota.backup.create` 的命名风格一致。
pub(crate) fn backup_config_to(
    backup_dir: &Path,
    source_path: &str,
    reason: &str,
) -> Result<PathBuf, io::Error> {
    fs::create_dir_all(backup_dir)?;
    let source = Path::new(source_path);
    let stem = source
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("nat.toml");
    let safe_reason = sanitize_backup_reason(reason);
    let backup_path = backup_dir.join(format!(
        "{stem}.{safe_reason}-{}.bak",
        Local::now().format("%Y%m%d-%H%M%S")
    ));
    fs::copy(source, &backup_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(backup_path)
}

/// reason 在文件名里的字符约束：保留 ASCII 字母/数字/下划线/短横线/点；其余替换为 `-`。
pub(crate) fn sanitize_backup_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "config-write".to_string();
    }
    trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub(crate) fn backup_filename(
    prefix: &str,
    extension: &str,
    now: chrono::DateTime<Local>,
) -> String {
    format!("{prefix}-{}.{}", now.format("%Y%m%d-%H%M%S"), extension)
}

pub(crate) fn backup_config(path: &str) -> Result<PathBuf, io::Error> {
    let source = Path::new(path);
    fs::create_dir_all(CONFIG_BACKUP_DIR)?;
    let extension = source
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("bak");
    let prefix = if extension == "toml" {
        "nat-config"
    } else {
        "nat-conf"
    };
    let backup_path =
        Path::new(CONFIG_BACKUP_DIR).join(backup_filename(prefix, extension, Local::now()));
    fs::copy(source, &backup_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(backup_path)
}

pub(crate) fn list_config_backups() -> Result<Vec<PathBuf>, io::Error> {
    let dir = Path::new(CONFIG_BACKUP_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut backups = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            backups.push(path);
        }
    }
    backups.sort();
    Ok(backups)
}

pub(crate) fn restore_config_interactive(path: &str) -> Result<(), io::Error> {
    let backups = list_config_backups()?;
    if backups.is_empty() {
        println!("没有找到配置备份");
        return Ok(());
    }
    for (index, backup) in backups.iter().enumerate() {
        println!("{index}) {}", backup.display());
    }
    let index = parse_index(&prompt("请选择要恢复的备份 index: ")?)?;
    if index >= backups.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "备份 index 超出范围",
        ));
    }
    let confirm = prompt("恢复前会备份当前配置。确认恢复? [y/N]: ")?;
    if !matches!(confirm.as_str(), "y" | "Y") {
        println!("已取消恢复");
        return Ok(());
    }
    let restored_content = fs::read_to_string(&backups[index])?;
    save_toml_config_from_string(path, &restored_content, "backup.restore")?;
    audit_cli(
        path,
        "backup.restore",
        AuditResult::Ok,
        json!({"backup": backups[index].display().to_string()}),
    );
    println!("已恢复配置: {}", backups[index].display());
    print_config_saved_hint(path, "backup.restore");
    Ok(())
}
