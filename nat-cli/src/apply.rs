//! nat.service safe apply：nft -c check → ruleset 备份 → nft -f → 失败回滚到 managed tables。
//!
//! 拆自原 `main.rs`（v0.6.1 维护性重构），语义未改：只管理 `self-nat` / `self-filter` 两张
//! managed table 的 IPv4 / IPv6 版本，绝不 `flush ruleset`，绝不动用户其他表。

use chrono::Local;
use log::{error, info};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::BACKUP_DIR;

pub(crate) const MANAGED_TABLES: [(&str, &str); 4] = [
    ("ip", "self-nat"),
    ("ip6", "self-nat"),
    ("ip", "self-filter"),
    ("ip6", "self-filter"),
];

pub(crate) fn apply_nft_script(script_path: &str) -> Result<(), io::Error> {
    apply_nft_script_with("/usr/sbin/nft", Path::new(BACKUP_DIR), script_path)
}

pub(crate) fn apply_nft_script_with(
    nft_bin: &str,
    backup_dir: &Path,
    script_path: &str,
) -> Result<(), io::Error> {
    check_nft_script(nft_bin, script_path)?;
    let ruleset_backup = backup_current_ruleset(nft_bin, backup_dir)?;
    let managed_backup = backup_managed_tables(nft_bin);
    info!("已备份当前 ruleset: {}", ruleset_backup.display());

    let output = Command::new(nft_bin).arg("-f").arg(script_path).output()?;
    info!(
        "执行/usr/sbin/nft -f {script_path} 执行结果: {}",
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        return Ok(());
    }

    error!("nft apply failed, rolling back managed tables from backup");
    rollback_managed_tables(nft_bin, backup_dir, &managed_backup)?;
    Err(io::Error::other(format!(
        "nft apply failed; managed tables rolled back; full ruleset backup: {}",
        ruleset_backup.display()
    )))
}

pub(crate) fn check_nft_script(nft_bin: &str, script_path: &str) -> Result<(), io::Error> {
    let output = Command::new(nft_bin)
        .arg("-c")
        .arg("-f")
        .arg(script_path)
        .output()?;
    info!(
        "执行/usr/sbin/nft -c -f {script_path} 执行结果: {}",
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

pub(crate) fn backup_current_ruleset(
    nft_bin: &str,
    backup_dir: &Path,
) -> Result<PathBuf, io::Error> {
    fs::create_dir_all(backup_dir)?;
    let backup_path = PathBuf::from(format!(
        "{}/ruleset-{}.nft",
        backup_dir.display(),
        Local::now().format("%Y%m%d%H%M%S")
    ));
    let output = Command::new(nft_bin).arg("list").arg("ruleset").output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to backup current ruleset: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    fs::write(&backup_path, output.stdout)?;
    Ok(backup_path)
}

pub(crate) fn backup_managed_tables(nft_bin: &str) -> Vec<(String, String, String)> {
    let mut backups = Vec::new();
    for (family, table) in MANAGED_TABLES {
        match Command::new(nft_bin)
            .arg("list")
            .arg("table")
            .arg(family)
            .arg(table)
            .output()
        {
            Ok(output) if output.status.success() => {
                backups.push((
                    family.to_string(),
                    table.to_string(),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                ));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if is_missing_nft_table_error(&stderr) {
                    info!("managed table {family} {table} does not exist yet, skip table backup");
                } else {
                    error!(
                        "failed to backup managed table {family} {table}: {}",
                        stderr.trim()
                    );
                }
            }
            Err(e) => {
                error!("failed to inspect managed table {family} {table}: {e:?}");
            }
        }
    }
    backups
}

pub(crate) fn is_missing_nft_table_error(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("table") && stderr.contains("does not exist")
}

pub(crate) fn rollback_managed_tables(
    nft_bin: &str,
    backup_dir: &Path,
    backups: &[(String, String, String)],
) -> Result<(), io::Error> {
    for (family, table) in MANAGED_TABLES {
        let output = Command::new(nft_bin)
            .arg("delete")
            .arg("table")
            .arg(family)
            .arg(table)
            .output();
        if let Ok(output) = output
            && !output.status.success()
        {
            info!(
                "delete managed table {family} {table} during rollback returned: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    if backups.is_empty() {
        info!("no managed table backup found; rollback only removed managed tables");
        return Ok(());
    }

    let rollback_path = PathBuf::from(format!(
        "{}/managed-rollback-{}.nft",
        backup_dir.display(),
        Local::now().format("%Y%m%d%H%M%S")
    ));
    let mut rollback_script = String::from("#!/usr/sbin/nft -f\n\n");
    for (_, _, table_script) in backups {
        rollback_script.push_str(table_script);
        rollback_script.push('\n');
    }
    fs::write(&rollback_path, rollback_script)?;

    let output = Command::new(nft_bin)
        .arg("-f")
        .arg(&rollback_path)
        .output()?;
    info!(
        "执行 managed rollback {} 结果: {}",
        rollback_path.display(),
        output.status
    );
    log::info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::error!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "managed rollback failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}
