//! 本家签名链需要的**最小密码学原语**（自实现，不引第三方 crate）。
//!
//! ── 为什么自己写 ────────────────────────────────────────────
//! 本插件的依赖白名单只有 `agent2api-wasm-sdk` / `serde_json` / `sha2` /
//! `chrono`，而 CAccount 的签名链需要 HMAC-SHA1 + MD5 + base64 三样；
//! `sha2` 只覆盖 SHA-2 家族（SHA-224/256/384/512），既没有 SHA-1 也没有 MD5。
//! 三样都是**固定算法**，实现长度可控，且写错会在第一次登录时立刻暴露
//! （服务端按同一算法校验），所以自实现是这里唯一可行的路径。
//!
//! ── 这不是安全边界 ──────────────────────────────────────────
//! 与 native 侧 `sign.rs` 同一取向：AccessKey 随官方客户端分发，签名只用于
//! 复刻官方客户端行为，不承担机密性或完整性保证。
//!
//! ── 自检 ────────────────────────────────────────────────────
//! 文件末尾的 `tests` 用公开测试向量逐个核过四种算法（`cargo test` 可跑；
//! 不进 wasm 产物）。

/// base64 标准字母表（RFC 4648 §4）
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64 编码（带 `=` 填充）。
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let group = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(group >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(group >> 12) as usize & 0x3f] as char);
        // 缺字节的位置用 `=` 补齐（与标准实现一致）
        if chunk.len() > 1 {
            out.push(ALPHABET[(group >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[group as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 标准 base64 解码（容忍换行与空白；非法字符给 `None` 而不是猜）。
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            // 填充与空白都不参与累加
            b'=' => break,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// 小写十六进制（签名里的 traceid / nonce 都是这个形态）。
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ─── SHA-1（FIPS 180-4）──────────────────────────────────────

/// SHA-1 摘要。
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for block in message.chunks(64) {
        let mut words = [0u32; 80];
        for (index, slot) in words.iter_mut().take(16).enumerate() {
            let at = index * 4;
            *slot = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for index in 16..80 {
            words[index] = (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    digest
}

/// HMAC-SHA1（RFC 2104）——CAccount 的 `Authorization` 用的就是这个。
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    // 块长固定 64 字节；超长密钥先摘要成 20 字节（RFC 2104 的规定）
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner_digest = sha1(&inner);
    let mut outer = Vec::with_capacity(84);
    outer.extend(block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_digest);
    sha1(&outer)
}

// ─── MD5（RFC 1321）─────────────────────────────────────────

/// 每轮的左移位数（四轮各 16 步，同一组模式重复四次）
const MD5_SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// 正弦常量表（RFC 1321 §3.4：`floor(2^32 × |sin(i)|)`）
const MD5_TABLE: [u32; 64] = [
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

/// MD5 摘要（签名串第 4 段的 `base64(md5(body))` 用它）。
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    // MD5 的尾部长度是**小端**（与 SHA-1 相反）
    message.extend_from_slice(&bit_length.to_le_bytes());

    for block in message.chunks(64) {
        let mut words = [0u32; 16];
        for (index, slot) in words.iter_mut().enumerate() {
            let at = index * 4;
            *slot = u32::from_le_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        for index in 0..64 {
            let (f, g) = match index {
                0..=15 => ((b & c) | ((!b) & d), index),
                16..=31 => ((d & b) | ((!d) & c), (5 * index + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * index) % 16),
            };
            let mixed = f
                .wrapping_add(a)
                .wrapping_add(MD5_TABLE[index])
                .wrapping_add(words[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(mixed.rotate_left(MD5_SHIFT[index]));
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::{base64_decode, base64_encode, hex, hmac_sha1, md5, sha1};

    #[test]
    fn sha1_matches_published_vectors() {
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn hmac_sha1_matches_rfc2202() {
        // RFC 2202 case 2：key = "Jefe"，data = "what do ya want for nothing?"
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn md5_matches_published_vectors() {
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_decode("YWJj").as_deref(), Some(&b"abc"[..]));
        assert_eq!(base64_decode("YWI=").as_deref(), Some(&b"ab"[..]));
        assert_eq!(base64_decode("!!").is_none(), true);
        // Content-MD5 的真实形态：md5("") 的 base64
        assert_eq!(base64_encode(&md5(b"")), "1B2M2Y8AsgTpgAmY7PhCfg==");
    }
}
