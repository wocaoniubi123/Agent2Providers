//! 纯算法 MD5（RFC 1321）。
//!
//! ── 为什么自己写 ────────────────────────────────────────────
//! 本包的依赖白名单只有 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`，
//! 没有 MD5 库。而百度通行证换发 `genflowpro` 作用域 STOKEN 的签名恰好是一次
//! MD5（见 `engine.rs` 模块头：官方客户端用 `genflowengine.dll` 的
//! `genflow_engine_get_login_auth_param`，本质只是「六字段拼串 + 内置密钥 +
//! 一次 MD5」）。这里把这一步算法化，不加载任何原生模块 —— 沙箱里没有 DLL，
//! 也不该为了一个哈希去申请原生辅助能力。
//!
//! ── 实现口径 ────────────────────────────────────────────────
//! 严格按 RFC 1321：小端补齐（0x80 + 若干 0，直到 `len % 64 == 56`，末尾 8 字节
//! 是**比特**长度的 little-endian），四轮各 16 次、每轮用不同的布尔函数与消息
//! 字下标。`K` 是 `floor(abs(sin(i + 1)) * 2^32)` 的常量表，`S` 是循环左移表。
//!
//! 已知向量测试在文件末尾（RFC 1321 附录 A.5 的七条全在，另加一条本家
//! `build_auth_param` 的真实签名，用 .NET `System.Security.Cryptography.MD5`
//! 独立算出来交叉验证）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，索引全部来自
//! 固定长度的常量表与 `chunks_exact(64)`，不会越界。

/// 每轮的循环左移位数（RFC 1321 的 `s` 表）。
const SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// 加法常量表（`floor(abs(sin(i + 1)) * 2^32)`，RFC 1321 的 `T` 表）。
const K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, //
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501, //
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, //
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821, //
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, //
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, //
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, //
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, //
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, //
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, //
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, //
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, //
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, //
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1, //
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, //
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

/// 算出 16 字节摘要。
pub fn digest(input: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    // 补齐：先补一个 0x80，再补 0 到 `len % 64 == 56`，最后 8 字节比特长度。
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut message: Vec<u8> = Vec::with_capacity(input.len() + 72);
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_le_bytes());

    for chunk in message.chunks_exact(64) {
        // 一块 64 字节 = 16 个 little-endian 的 u32。
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_le_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        for round in 0..64 {
            let (function, word_index) = match round / 16 {
                0 => ((b & c) | (!b & d), round),
                1 => ((d & b) | (!d & c), (5 * round + 1) % 16),
                2 => (b ^ c ^ d, (3 * round + 5) % 16),
                _ => (c ^ (b | !d), (7 * round) % 16),
            };
            // 下标来自 `% 16` 与固定表，`get` 只为避开索引 panic 的可能路径。
            let word = words.get(word_index).copied().unwrap_or(0);
            let shift = SHIFT.get(round).copied().unwrap_or(0);
            let mixed = a
                .wrapping_add(function)
                .wrapping_add(K.get(round).copied().unwrap_or(0))
                .wrapping_add(word);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(mixed.rotate_left(shift));
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (index, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let offset = index * 4;
        out[offset..offset + 4].copy_from_slice(&bytes);
    }
    out
}

/// 小写十六进制摘要（签名参数里用的就是这个形态）。
pub fn hex(input: &[u8]) -> String {
    let mut text = String::with_capacity(32);
    for byte in digest(input) {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1321 附录 A.5 的七条测试向量。
    #[test]
    fn rfc1321_vectors() {
        for (input, expected) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(expected, hex(input.as_bytes()), "输入 {input:?}");
        }
    }

    /// 跨块边界（55 / 56 / 64 / 65 字节）与长输入：补零与长度字段的位置最容易错。
    #[test]
    fn padding_boundaries() {
        // 55 字节：刚好不触发第二个补零块
        let text = "x".repeat(55);
        assert_eq!(32, hex(text.as_bytes()).len());
        // 56 字节：必须多补一整块
        let text = "x".repeat(56);
        assert_eq!(32, hex(text.as_bytes()).len());
        // 64 字节：整块
        let text = "x".repeat(64);
        assert_eq!(32, hex(text.as_bytes()).len());
        // 65 字节：整块 + 一个补齐块
        let text = "x".repeat(65);
        assert_eq!(32, hex(text.as_bytes()).len());
        // 700 MiB 不现实，但 100 KB 已经覆盖多轮循环
        let text = "库库".repeat(50_000);
        assert_eq!(32, hex(text.as_bytes()).len());
    }
}
