//! 原子化写文本文件：`<path>.tmp.<pid>` → fsync → rename。
//!
//! - 失败时尽量删除残留 .tmp 文件，避免污染目录。
//! - fsync 失败仅 WARN，不阻断主流程（旧主机或某些文件系统可能不支持）。
//! - 仅做"写文件"这一件事，不负责备份 / audit。调用方在更高层包装。

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// 把 `contents` 原子化写入 `path`。
///
/// 实现细节：
/// - 在同目录下创建 `<file>.tmp.<pid>`，写完 → `sync_all()`（best-effort）→ `rename` 到目标。
/// - 目标的父目录不存在时会先 `create_dir_all`，避免菜单首次写 nat.toml 时出错。
/// - rename 失败时尝试清理 .tmp 文件。
pub fn write_atomic(path: &str, contents: &str) -> io::Result<()> {
    let target = Path::new(path);
    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_name = target
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path: PathBuf = target
        .parent()
        .map(|p| p.join(&tmp_name))
        .unwrap_or_else(|| PathBuf::from(&tmp_name));

    let write_result: io::Result<()> = (|| {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        if let Err(e) = file.sync_all() {
            log::warn!("write_atomic fsync 失败 ({}): {e}", tmp_path.display());
        }
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nat-atomic-{}-{}-{name}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_creates_file_and_cleans_tmp() {
        let dir = tmpdir("create");
        let target = dir.join("nat.toml");
        write_atomic(target.to_str().unwrap(), "rules = []\n").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "rules = []\n");
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftover.is_empty(),
            "tmp file should be cleaned: {leftover:?}"
        );
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let dir = tmpdir("overwrite");
        let target = dir.join("nat.toml");
        fs::write(&target, "OLD").unwrap();
        write_atomic(target.to_str().unwrap(), "NEW").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "NEW");
    }

    #[test]
    fn write_atomic_returns_err_when_parent_unwritable() {
        // /proc 下不可写路径
        let result = write_atomic("/proc/self/atomic-test-target", "x");
        assert!(result.is_err(), "expected error writing to /proc tree");
    }

    #[test]
    fn write_atomic_creates_parent_dir_when_missing() {
        let dir = tmpdir("nested");
        let target = dir.join("a/b/c/nat.toml");
        write_atomic(target.to_str().unwrap(), "ok").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "ok");
    }
}
