//! MD5（RFC 1321）的最小实现 —— 只为 AutoClaw 的客户端指纹服务。
//!
//! ── 为什么自己写 ────────────────────────────────────────────
//! 插件依赖被限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`
//! 四件，`md-5` 不在其中。本家的用途是**协议要求**、不是安全用途：
//! `X-Auth-Sign = MD5("{appId}&{秒级时间戳}&{appKey}")` —— 这套头是 AutoClaw
//! 桌面端客户端的固定指纹（appId/appKey 内嵌在客户端里），用于让刷新 / 余额 /
//! 签到 / 目录这些 userapi 接口认出来自官方客户端；缺任一个都会被判签名失败
//! （`code 400002`，刷新链因此降级 `agent-refresh`）。
//!
//! 因此实现必须与 Node `crypto.createHash('md5').digest('hex')` 逐字节一致，
//! 并与标准测试向量对齐（见文件末尾的测试）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

/// 每轮的循环左移位数（RFC 1321 §3.4 的四张表按轮拼成一张）。
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// 正弦常量表 `K[i] = floor(2^32 × |sin(i + 1)|)`（RFC 1321 §3.4）。
const K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
    0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
    0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
    0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
    0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
    0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
    0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
    0xeb86_d391,
];

/// 一个消息块（64 字节）的 64 步处理（RFC 1321 §3.3）。
fn block(state: &mut [u32; 4], chunk: &[u8]) {
    let mut words = [0u32; 16];
    for (index, word) in chunk.chunks(4).enumerate() {
        if word.len() == 4 {
            words[index] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for step in 0..64 {
        // F / G / H / I 四轮各自的选择函数与下标函数（RFC 1321 §3.4）。
        let (f, g) = match step {
            0..=15 => ((b & c) | (!b & d), step),
            16..=31 => ((d & b) | (!d & c), (5 * step + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * step + 5) % 16),
            _ => (c ^ (b | !d), (7 * step) % 16),
        };
        let rotated = a
            .wrapping_add(f)
            .wrapping_add(K[step])
            .wrapping_add(words[g])
            .rotate_left(SHIFTS[step]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(rotated);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// 摘要（16 字节，小端状态串接）。
pub fn digest(input: &[u8]) -> [u8; 16] {
    // 初始向量（RFC 1321 §3.3）
    let mut state = [0x6745_2301_u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let bit_length = (input.len() as u64).wrapping_mul(8);
    // 补位：0x80 + 0x00… + 64 位原始长度（小端）
    let mut message = Vec::with_capacity(input.len() + 72);
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_le_bytes());
    for chunk in message.chunks(64) {
        block(&mut state, chunk);
    }
    let mut output = [0u8; 16];
    output[0..4].copy_from_slice(&state[0].to_le_bytes());
    output[4..8].copy_from_slice(&state[1].to_le_bytes());
    output[8..12].copy_from_slice(&state[2].to_le_bytes());
    output[12..16].copy_from_slice(&state[3].to_le_bytes());
    output
}

/// 小写十六进制摘要（与 Node `digest('hex')` 逐字节一致）。
pub fn hex(text: &str) -> String {
    let mut output = String::with_capacity(32);
    for byte in digest(text.as_bytes()) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 标准测试向量（RFC 1321 §A.5）。签名算错 = 稳定 400002，且只在
    /// 刷新 / 余额 / 签到 / 目录四条链路上一起失败，排障时极难定位。
    #[test]
    fn rfc1321_vectors() {
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", hex(""));
        assert_eq!("900150983cd24fb0d6963f7d28e17f72", hex("abc"));
        assert_eq!(
            "9e107d9d372bb6826bd81d3542a419d6",
            hex("The quick brown fox jumps over the lazy dog")
        );
    }

    /// 跨 64 字节块（补位 + 多块循环）的一条：80 位数字的 RFC 向量。
    #[test]
    fn crosses_block_boundary() {
        assert_eq!(
            "57edf4a22be3c955ac49da2e2107b67a",
            hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
        );
    }

    /// 签名形态的冒烟：`md5("100003&1700000000&<key>")` 必须是 32 位小写十六进制。
    #[test]
    fn signature_shape() {
        let sign = hex("100003&1700000000&38d2391985e2369a5fb8227d8e6cd5e5");
        assert_eq!(32, sign.len());
        assert!(sign.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }
}
