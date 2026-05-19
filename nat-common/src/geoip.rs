//! GeoIP / CN IPv4 set 下载、校验、解析与更新逻辑。
//!
//! 第一版仅支持 IPv4。来源：alecthw/chnlist 提供的 nft set 格式 cn4.nft。
//! 本模块不依赖 HTTP 客户端，下载函数采用注入式 fetcher 以便在测试中 mock。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const SET_NAME: &str = "cn4";

/// 下载并原子替换 cn4 set 文件。下载失败保留旧文件。
///
/// fetcher 接受 url，返回下载内容。任何 IO/网络/校验失败都会返回 Err，
/// 且不会覆盖目标文件。
pub fn download_and_update_with<F>(
    url: &str,
    target_path: &str,
    fetcher: F,
) -> Result<DownloadReport, io::Error>
where
    F: FnOnce(&str) -> Result<String, io::Error>,
{
    let target = PathBuf::from(target_path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = tmp_path_for(&target);

    let content = fetcher(url)?;
    if let Err(e) = validate_cn4_content(&content) {
        // 不写入磁盘，保留旧文件
        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
    }
    fs::write(&tmp_path, content.as_bytes())?;
    // 原子替换
    fs::rename(&tmp_path, &target)?;

    let metadata = fs::metadata(&target)?;
    Ok(DownloadReport {
        path: target,
        size_bytes: metadata.len(),
    })
}

fn tmp_path_for(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "cn4.nft".to_string());
    name.push_str(".tmp");
    target.with_file_name(name)
}

/// 校验 cn4 内容：非空，包含 nft set 结构或明显的 IPv4 CIDR。
pub fn validate_cn4_content(content: &str) -> Result<(), String> {
    if content.trim().is_empty() {
        return Err("cn4 内容为空".to_string());
    }
    let lower = content.to_lowercase();
    let has_set_struct = lower.contains("set ") || lower.contains("define ");
    let has_cidr = content.lines().any(line_has_ipv4_cidr);
    if !has_set_struct && !has_cidr {
        return Err("cn4 内容既不包含 nft set 结构，也没有明显的 IPv4 CIDR".to_string());
    }
    Ok(())
}

/// 从 cn4 内容中提取 IPv4 CIDR 列表，剔除注释与无效 token。
pub fn extract_ipv4_cidrs(content: &str) -> Vec<String> {
    let mut result = Vec::new();
    for raw_line in content.lines() {
        // 去掉 # 之后的注释
        let line = raw_line.split('#').next().unwrap_or("");
        for token in line.split(|c: char| {
            c.is_whitespace() || matches!(c, ',' | '{' | '}' | ';' | '(' | ')' | '=')
        }) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if is_ipv4_cidr_or_addr(token) {
                let normalized = if token.contains('/') {
                    token.to_string()
                } else {
                    format!("{token}/32")
                };
                result.push(normalized);
            }
        }
    }
    result
}

fn is_ipv4_cidr_or_addr(token: &str) -> bool {
    if let Ok(net) = token.parse::<ipnetwork::IpNetwork>() {
        return net.is_ipv4();
    }
    if let Ok(std::net::IpAddr::V4(_)) = token.parse::<std::net::IpAddr>() {
        return true;
    }
    false
}

fn line_has_ipv4_cidr(line: &str) -> bool {
    line.split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}' | ';'))
        .map(str::trim)
        .any(is_ipv4_cidr_or_addr)
}

/// 用提取出的 CIDR 生成 nft set 定义（嵌入到本项目 self-filter 表中）。
/// 如果 cidrs 为空，返回空字符串，调用方应该跳过 set 嵌入并 WARN。
pub fn render_cn4_set_definition(cidrs: &[String]) -> String {
    if cidrs.is_empty() {
        return String::new();
    }
    let mut lines = String::new();
    lines.push_str(&format!(
        "add set ip self-filter {SET_NAME} {{ type ipv4_addr; flags interval; }}\n"
    ));
    // 大集合可能很大，逐批 add element 防止单行过长
    let mut chunk: Vec<&str> = Vec::with_capacity(256);
    for cidr in cidrs {
        chunk.push(cidr.as_str());
        if chunk.len() == 256 {
            lines.push_str(&render_element_line(&chunk));
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        lines.push_str(&render_element_line(&chunk));
    }
    lines
}

fn render_element_line(chunk: &[&str]) -> String {
    let body = chunk.join(", ");
    format!("add element ip self-filter {SET_NAME} {{ {body} }}\n")
}

/// 读取 cn4 文件并构造 set 定义。若文件不存在或解析后为空，返回 None。
pub fn read_and_render_cn4_set(file_path: &str) -> Option<String> {
    let content = fs::read_to_string(file_path).ok()?;
    if validate_cn4_content(&content).is_err() {
        return None;
    }
    let cidrs = extract_ipv4_cidrs(&content);
    if cidrs.is_empty() {
        return None;
    }
    Some(render_cn4_set_definition(&cidrs))
}

#[derive(Debug, Clone)]
pub struct DownloadReport {
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty() {
        assert!(validate_cn4_content("").is_err());
        assert!(validate_cn4_content("   \n\n").is_err());
    }

    #[test]
    fn validate_accepts_set_structure() {
        let content = "table ip cn {\n  set cn4 { type ipv4_addr; }\n}\n";
        assert!(validate_cn4_content(content).is_ok());
    }

    #[test]
    fn validate_accepts_cidr_lines() {
        let content = "1.0.1.0/24\n1.0.2.0/23\n";
        assert!(validate_cn4_content(content).is_ok());
    }

    #[test]
    fn validate_rejects_non_cidr_text() {
        let content = "Hello world, this is not nft\n";
        assert!(validate_cn4_content(content).is_err());
    }

    #[test]
    fn extract_handles_mixed_format() {
        let content = "# header\nset cn4 {\n  type ipv4_addr;\n  flags interval;\n  elements = {\n    1.0.1.0/24,\n    1.0.2.0/23,\n    invalid,\n    192.0.2.1\n  }\n}\n";
        let cidrs = extract_ipv4_cidrs(content);
        assert!(cidrs.contains(&"1.0.1.0/24".to_string()));
        assert!(cidrs.contains(&"1.0.2.0/23".to_string()));
        assert!(cidrs.contains(&"192.0.2.1/32".to_string()));
        assert!(!cidrs.iter().any(|s| s == "invalid"));
    }

    #[test]
    fn render_set_includes_table_and_elements() {
        let cidrs = vec!["1.0.1.0/24".to_string(), "1.0.2.0/23".to_string()];
        let rendered = render_cn4_set_definition(&cidrs);
        assert!(rendered.contains("add set ip self-filter cn4"));
        assert!(rendered.contains("add element ip self-filter cn4"));
        assert!(rendered.contains("1.0.1.0/24"));
        assert!(rendered.contains("1.0.2.0/23"));
    }

    #[test]
    fn render_handles_empty() {
        assert!(render_cn4_set_definition(&[]).is_empty());
    }

    #[test]
    fn download_writes_via_atomic_rename() {
        let dir = std::env::temp_dir().join(format!("nat-geoip-download-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let target = dir.join("cn4.nft");
        let report = download_and_update_with(
            "https://example.test/cn4.nft",
            target.to_str().unwrap(),
            |_url| Ok("1.0.1.0/24\n1.0.2.0/23\n".to_string()),
        )
        .unwrap();
        assert_eq!(report.path, target);
        assert!(report.size_bytes > 0);
        assert!(target.exists());
        // tmp 已被原子替换
        let tmp = dir.join("cn4.nft.tmp");
        assert!(!tmp.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_does_not_overwrite_on_validation_failure() {
        let dir = std::env::temp_dir().join(format!("nat-geoip-keep-old-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("cn4.nft");
        fs::write(&target, "EXISTING-OLD-CONTENT-1.0.1.0/24\n").unwrap();

        let result = download_and_update_with(
            "https://example.test/cn4.nft",
            target.to_str().unwrap(),
            |_url| Ok("not nft data".to_string()),
        );
        assert!(result.is_err());
        let preserved = fs::read_to_string(&target).unwrap();
        assert!(preserved.contains("EXISTING-OLD-CONTENT"));
        let tmp = dir.join("cn4.nft.tmp");
        assert!(!tmp.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_does_not_overwrite_on_fetcher_error() {
        let dir =
            std::env::temp_dir().join(format!("nat-geoip-fetcher-err-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("cn4.nft");
        fs::write(&target, "OLD-CONTENT-1.0.1.0/24\n").unwrap();

        let result = download_and_update_with(
            "https://example.test/cn4.nft",
            target.to_str().unwrap(),
            |_url| Err(io::Error::other("network down")),
        );
        assert!(result.is_err());
        let preserved = fs::read_to_string(&target).unwrap();
        assert!(preserved.contains("OLD-CONTENT"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_and_render_returns_none_for_missing() {
        let missing = std::env::temp_dir().join("nat-geoip-not-exist.nft");
        let _ = fs::remove_file(&missing);
        assert!(read_and_render_cn4_set(missing.to_str().unwrap()).is_none());
    }

    #[test]
    fn read_and_render_returns_set_for_valid_file() {
        let dir = std::env::temp_dir().join(format!("nat-geoip-render-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cn4.nft");
        fs::write(&path, "1.0.1.0/24\n1.0.2.0/23\n").unwrap();
        let rendered = read_and_render_cn4_set(path.to_str().unwrap()).unwrap();
        assert!(rendered.contains("add set ip self-filter cn4"));
        assert!(rendered.contains("1.0.1.0/24"));
        let _ = fs::remove_dir_all(&dir);
    }
}
