//! 跨进程稳定的 FNV-1a 64-bit hash。
//!
//! 用于 nat.service 主循环对比"上一次生成的 nft 脚本"与"当前生成的 nft 脚本"是否相同——
//! 不需要密码学安全，但**必须跨进程跨启动稳定**：不能用 `std::collections::hash_map::DefaultHasher`，
//! 那个带随机种子，每次进程启动 hash 都会变，无法在重启后复用「上次成功 hash」。
//!
//! FNV-1a 是无种子的简单乘加 hash，相同输入永远产生相同输出，足够区分 nft 脚本。

const FNV_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit。相同输入 → 相同输出，跨进程稳定。
pub fn stable_script_hash(input: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

/// 把 hash 渲染成 `0x` 前缀的 16 位十六进制串，用于 log / audit。
pub fn format_hash_hex(hash: u64) -> String {
    format!("0x{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_input_gives_same_hash() {
        let a = stable_script_hash("add table ip self-nat\nadd chain ip self-nat PREROUTING\n");
        let b = stable_script_hash("add table ip self-nat\nadd chain ip self-nat PREROUTING\n");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_give_different_hashes() {
        let a = stable_script_hash("rule a\n");
        let b = stable_script_hash("rule b\n");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_input_is_offset_basis() {
        assert_eq!(stable_script_hash(""), FNV_OFFSET_BASIS_64);
    }

    #[test]
    fn known_vector_a() {
        // 标准 FNV-1a 64 测试向量："a" → 0xaf63dc4c8601ec8c
        assert_eq!(stable_script_hash("a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn known_vector_foobar() {
        // 标准 FNV-1a 64 测试向量："foobar" → 0x85944171f73967e8
        assert_eq!(stable_script_hash("foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn hash_stable_across_invocations() {
        // 不依赖随机种子：连续多次调用都返回同一个值
        let s = "the quick brown fox jumps over the lazy dog";
        let h1 = stable_script_hash(s);
        let h2 = stable_script_hash(s);
        let h3 = stable_script_hash(s);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn format_hash_hex_pads_to_16_chars_with_prefix() {
        assert_eq!(format_hash_hex(0x1), "0x0000000000000001");
        assert_eq!(format_hash_hex(0xaf63_dc4c_8601_ec8c), "0xaf63dc4c8601ec8c");
    }
}
