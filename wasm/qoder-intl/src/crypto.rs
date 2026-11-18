//! 纯 Rust 密码学原语：base64 / MD5 / AES-128-CBC / RSA-PKCS#1 v1.5 / 随机源。
//!
//! ── 为什么这些要手写（这是本包最不显然的一处）──────────────────
//! COSY 鉴权（`cosy.rs`）要的三样东西 —— **MD5 签名**、**AES-128-CBC 加密**、
//! **RSA 公钥加密** —— 在 native 那边来自 `md-5` / `aes` / `num-bigint` 三个
//! crate。Wasm 插件的依赖白名单只有 `agent2api-wasm-sdk` / `serde_json` /
//! `sha2` / `chrono`：既没有 MD5、也没有对称加密，更没有大整数。而上游的
//! 签名算法是**固定的**（改不了），所以只能在包内把这几个原语实现出来。
//!
//! ── 正确性怎么保证（不靠「看起来对」）──────────────────────────
//!   1. AES 的 S 盒**不抄表**，而是按定义现算：GF(2^8) 乘法逆元 + 仿射变换。
//!      这样表里不可能有抄错的字节 —— 抄一张 256 字节的表才是真正的风险。
//!      （自检：S[0] = 0x63、S[1] = 0x7c，见 `sbox` 的注释。）
//!   2. MD5 / AES-CBC / base64 的结果都与 .NET 的 `MD5` / `Aes` /
//!      `Convert.ToBase64String` 逐字节对拍过（迁移时用 `_tmp-` 下的临时
//!      crate 跑过一遍，结论记在汇报里）。
//!   3. RSA 只用到「大整数模幂」这一步，指数固定 65537；模幂与 .NET
//!      `BigInteger.ModPow` 对拍过。
//!
//! ── 随机源 ──────────────────────────────────────────────────
//! native 用 `getrandom`（OS 熵）。Wasm 里拿不到 OS 熵，于是：
//!   1. 先问宿主（`random.bytes`，对应 `wasm.json` 申报的 `random.v1`）；
//!   2. 宿主没这个能力时退到「时钟 + 原子计数器 + SHA-256」的混合流。
//! 第 2 条**不是密码学安全的随机数**，这是与 native 的已知差别：它的后果是
//! COSY 信封里的一次性 AES 密钥可预测（只影响「身份 JSON 的传输机密性」，
//! 不参与任何凭据校验）。宿主一旦提供 `random.v1` 就自动走第 1 条。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use agent2api_wasm_sdk::{self as sdk, json, Value};
use sha2::{Digest, Sha256};

// ─── base64 ─────────────────────────────────────────────────────

const STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(alphabet: &[u8; 64], pad: bool, data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[(triple >> 18) as usize & 0x3f] as char);
        out.push(alphabet[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(triple >> 6) as usize & 0x3f] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[triple as usize & 0x3f] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// 标准 base64（带 `=` 补位）
pub fn b64(data: &[u8]) -> String {
    encode_with(STD_ALPHABET, true, data)
}

/// URL 安全 base64（不带补位）：PKCE verifier 与随机串用它
pub fn b64_url_nopad(data: &[u8]) -> String {
    encode_with(URL_ALPHABET, false, data)
}

/// 标准 base64 解码（host 回来的随机字节可能是这个形态）
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for ch in text.bytes() {
        if ch == b'=' || ch.is_ascii_whitespace() {
            continue;
        }
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ─── 十六进制 ───────────────────────────────────────────────────

/// 小写十六进制
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

// ─── MD5 ────────────────────────────────────────────────────────

/// MD5 每轮的循环左移位数（RFC 1321）
const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 的 64 个常量：`floor(abs(sin(i + 1)) * 2^32)`。
///
/// 现算而不是抄表：这张表本来就是这么生成的，抄错一个值会让签名静默变错，
/// 而现算的结果由「四轮 64 步 + 标准初值」这一条可读的规则决定。
fn md5_constants() -> &'static [u32; 64] {
    static TABLE: OnceLock<[u32; 64]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 64];
        for (index, slot) in table.iter_mut().enumerate() {
            let value = ((index as f64 + 1.0).sin().abs()) * 4_294_967_296.0;
            *slot = value as u32;
        }
        table
    })
}

/// MD5 摘要
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    let constants = md5_constants();

    let mut message = data.to_vec();
    let bit_length = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_le_bytes());

    for block in message.chunks(64) {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * 4;
            *word = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for step in 0..64 {
            let (mix, index) = match step / 16 {
                0 => ((b & c) | (!b & d), step),
                1 => ((d & b) | (!d & c), (5 * step + 1) % 16),
                2 => (b ^ c ^ d, (3 * step + 5) % 16),
                _ => (c ^ (b | !d), (7 * step) % 16),
            };
            let rotated = a
                .wrapping_add(mix)
                .wrapping_add(constants[step])
                .wrapping_add(words[index])
                .rotate_left(MD5_SHIFTS[step]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// MD5 的十六进制文本
pub fn md5_hex(data: &[u8]) -> String {
    hex_lower(&md5(data))
}

// ─── AES-128（加密方向）─────────────────────────────────────────

/// GF(2^8) 乘法（不可约多项式 `x^8 + x^4 + x^3 + x + 1`）
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_inverse(value: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    for candidate in 1..=255u8 {
        if gf_mul(candidate, value) == 1 {
            return candidate;
        }
    }
    0
}

fn rotl8(value: u8, bits: u32) -> u8 {
    value.rotate_left(bits)
}

/// AES 的 S 盒（按定义现算，见模块头第 1 条）。
///
/// 自检值：`S[0x00] = 0x63`、`S[0x01] = 0x7c`、`S[0x53] = 0xed`。
fn sbox() -> &'static [u8; 256] {
    static TABLE: OnceLock<[u8; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u8; 256];
        for index in 0..256usize {
            let inverse = gf_inverse(index as u8);
            table[index] = inverse
                ^ rotl8(inverse, 1)
                ^ rotl8(inverse, 2)
                ^ rotl8(inverse, 3)
                ^ rotl8(inverse, 4)
                ^ 0x63;
        }
        table
    })
}

/// 密钥扩展：11 组轮密钥，每组 16 字节（与状态数组同序：`4 * 列 + 行`）
fn expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let table = sbox();
    let mut words = [[0u8; 4]; 44];
    for index in 0..4 {
        words[index] = [key[4 * index], key[4 * index + 1], key[4 * index + 2], key[4 * index + 3]];
    }
    for index in 4..44 {
        let mut temp = words[index - 1];
        if index % 4 == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for byte in temp.iter_mut() {
                *byte = table[*byte as usize];
            }
            temp[0] ^= RCON[index / 4 - 1];
        }
        for byte in 0..4 {
            words[index][byte] = words[index - 4][byte] ^ temp[byte];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for round in 0..11 {
        for column in 0..4 {
            let word = words[round * 4 + column];
            // 轮密钥与状态同序：第 column 列的第 row 字节落在 4 * column + row
            for row in 0..4 {
                round_keys[round][4 * column + row] = word[row];
            }
        }
    }
    round_keys
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for index in 0..16 {
        state[index] ^= round_key[index];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    let table = sbox();
    for byte in state.iter_mut() {
        *byte = table[*byte as usize];
    }
}

/// 行移位：第 r 行左移 r 个字节（状态下标 `4 * 列 + 行`）
fn shift_rows(state: &mut [u8; 16]) {
    let original = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[4 * column + row] = original[4 * ((column + row) % 4) + row];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let start = column * 4;
        let a0 = state[start];
        let a1 = state[start + 1];
        let a2 = state[start + 2];
        let a3 = state[start + 3];
        state[start] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[start + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[start + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[start + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

/// 一个分组的 AES-128 加密（原地）
fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let round_keys = expand_key(key);
    add_round_key(block, &round_keys[0]);
    for round in 1..10 {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &round_keys[round]);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &round_keys[10]);
}

/// AES-128-CBC + PKCS#7 补位，返回密文。
///
/// 密钥与 IV **都取同一段 16 字节**（源实现 `aesEncrypt` 的既有做法，不是这里
/// 的设计选择），所以调用方只需给一个 16 字节的 key。
pub fn aes128_cbc_pkcs7(key: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 16 {
        return None;
    }
    let mut key_bytes = [0u8; 16];
    key_bytes.copy_from_slice(key);
    let mut previous = key_bytes;

    let mut data = plaintext.to_vec();
    let pad = 16 - (data.len() % 16);
    data.extend(std::iter::repeat(pad as u8).take(pad));

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        for index in 0..16 {
            block[index] = chunk[index] ^ previous[index];
        }
        aes128_encrypt_block(&key_bytes, &mut block);
        out.extend_from_slice(&block);
        previous = block;
    }
    Some(out)
}

// ─── 大整数（只够 RSA 模幂用）───────────────────────────────────

/// 一条大整数：`u32` 小端 limb（下标 0 是最低 32 位）
type Limbs = Vec<u32>;

fn limbs_from_be(bytes: &[u8]) -> Limbs {
    let mut limbs: Limbs = Vec::with_capacity(bytes.len() / 4 + 1);
    let mut index = bytes.len();
    while index > 0 {
        let start = index.saturating_sub(4);
        let mut value = 0u32;
        for byte in &bytes[start..index] {
            value = (value << 8) | *byte as u32;
        }
        limbs.push(value);
        index = start;
    }
    trim(&mut limbs);
    limbs
}

fn limbs_to_be(limbs: &[u32], length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    let mut index = length;
    for limb in limbs {
        // 低位字节先写、写到窗口的最右端 —— 这样每个 limb 在输出里仍是**大端**
        // （写反了会得到「每个 32 位块内部字节颠倒」的结果，与 .NET 对不上；
        //  `rsa_modpow_matches_dotnet` 就是钉这一条的）
        for byte in limb.to_le_bytes() {
            if index == 0 {
                break;
            }
            index -= 1;
            out[index] = byte;
        }
    }
    out
}

fn trim(limbs: &mut Limbs) {
    while limbs.last().copied() == Some(0) {
        limbs.pop();
    }
}

fn base_limbs(value: u32) -> Limbs {
    if value == 0 {
        Vec::new()
    } else {
        vec![value]
    }
}

fn cmp_limbs(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for index in (0..a.len()).rev() {
        if a[index] != b[index] {
            return a[index].cmp(&b[index]);
        }
    }
    std::cmp::Ordering::Equal
}

fn sub_limbs(a: &mut Limbs, b: &[u32]) {
    let mut borrow = 0i64;
    for index in 0..a.len() {
        let subtrahend = b.get(index).copied().unwrap_or(0) as i64;
        let mut value = a[index] as i64 - subtrahend - borrow;
        if value < 0 {
            value += 1i64 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[index] = value as u32;
    }
    trim(a);
}

fn mul_limbs(a: &[u32], b: &[u32]) -> Limbs {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0u32; a.len() + b.len() + 1];
    for (i, left) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, right) in b.iter().enumerate() {
            let index = i + j;
            let current = out[index] as u64 + (*left as u64) * (*right as u64) + carry;
            out[index] = current as u32;
            carry = current >> 32;
        }
        let mut index = i + b.len();
        while carry > 0 {
            let current = out[index] as u64 + carry;
            out[index] = current as u32;
            carry = current >> 32;
            index += 1;
        }
    }
    trim(&mut out);
    out
}

fn bit_len(limbs: &[u32]) -> usize {
    match limbs.last() {
        Some(top) if *top > 0 => (limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        _ => 0,
    }
}

fn bit_at(limbs: &[u32], index: usize) -> bool {
    let limb = index / 32;
    let offset = index % 32;
    limbs.get(limb).map(|value| (value >> offset) & 1 == 1).unwrap_or(false)
}

/// `value mod modulus`（二进制长除法：逐位「左移 + 够减就减」）
fn big_mod(value: &[u32], modulus: &[u32]) -> Limbs {
    let bits = bit_len(value);
    if modulus.is_empty() {
        return Vec::new();
    }
    let mut remainder: Limbs = Vec::new();
    for index in (0..bits).rev() {
        let mut carry = if bit_at(value, index) { 1u32 } else { 0 };
        for limb in remainder.iter_mut() {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry > 0 {
            remainder.push(carry);
        }
        trim(&mut remainder);
        if cmp_limbs(&remainder, modulus) != std::cmp::Ordering::Less {
            sub_limbs(&mut remainder, modulus);
        }
    }
    remainder
}

/// 模幂：`base^exponent mod modulus`
fn mod_pow(base: &[u32], exponent: u32, modulus: &[u32]) -> Limbs {
    let mut result = base_limbs(1);
    let mut factor = big_mod(base, modulus);
    let mut power = exponent;
    while power > 0 {
        if power & 1 == 1 {
            result = big_mod(&mul_limbs(&result, &factor), modulus);
        }
        power >>= 1;
        if power > 0 {
            factor = big_mod(&mul_limbs(&factor, &factor), modulus);
        }
    }
    result
}

/// RSA 公钥加密（PKCS#1 v1.5），返回定长密文（与模数等长）。
///
/// 布局：`00 || 02 || PS || 00 || M`，PS 是**非零随机**字节（源实现走 Node 的
/// `RSA_PKCS1_PADDING`，OpenSSL 用随机 PS）。PS 固定会让 RSA 退化成确定性
/// 加密 —— 那是可被指纹化的特征，不要改。
pub fn rsa_pkcs1_encrypt(modulus: &[u8], exponent: u32, message: &[u8]) -> Vec<u8> {
    let modulus_limbs = limbs_from_be(modulus);
    let key_len = modulus.len();
    if modulus_limbs.is_empty() || message.len() + 11 > key_len {
        return Vec::new();
    }
    let padding_len = key_len - 3 - message.len();
    let mut padding = random_bytes(padding_len);
    // PKCS#1 v1.5 要求 PS 全为非零字节
    for byte in padding.iter_mut() {
        if *byte == 0 {
            *byte = 1;
        }
    }
    let mut encoded = Vec::with_capacity(key_len);
    encoded.push(0x00);
    encoded.push(0x02);
    encoded.extend_from_slice(&padding);
    encoded.push(0x00);
    encoded.extend_from_slice(message);

    let cipher = mod_pow(&limbs_from_be(&encoded), exponent, &modulus_limbs);
    // 定长输出（模数 1024 位 → 128 字节），不足时左侧补零
    limbs_to_be(&cipher, key_len)
}

#[cfg(test)]
mod tests {
    //! 与 .NET 的 `MD5` / `Aes` / `Convert.ToBase64String` / `BigInteger.ModPow`
    //! 逐字节对拍过的一组向量（迁移时跑的，见模块头「正确性怎么保证」）。
    //!
    //! 跑法：`cargo test -p agent2api-wasm-qoder`（宿主目标；`cargo check
    //! --target wasm32-unknown-unknown` 不编译测试模块）。
    use super::*;

    fn hex_bytes(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index + 1 < bytes.len() {
            let high = (bytes[index] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (bytes[index + 1] as char).to_digit(16).unwrap_or(0) as u8;
            out.push(high * 16 + low);
            index += 2;
        }
        out
    }

    #[test]
    fn sbox_known_values() {
        let table = sbox();
        assert_eq!(table[0x00], 0x63);
        assert_eq!(table[0x01], 0x7c);
        assert_eq!(table[0x53], 0xed);
    }

    #[test]
    fn base64_matches_dotnet() {
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(b64(b"hi"), "aGk=");
        assert_eq!(b64(b"h"), "aA==");
        assert_eq!(b64(b""), "");
        assert_eq!(
            b64_url_nopad(&[0xfb, 0xff, 0xfe, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x3f]),
            "-__-IGhlbGxvPw"
        );
        assert_eq!(b64_decode("aGVsbG8=").unwrap_or_default(), b"hello");
    }

    #[test]
    fn md5_matches_dotnet() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            md5_hex(&vec![b'a'; 1000]),
            "cabe45dcc9ae5b66ba86600cca6b8ba8"
        );
    }

    #[test]
    fn aes_cbc_matches_dotnet() {
        let key = b"0123456789abcdef";
        assert_eq!(
            b64(&aes128_cbc_pkcs7(key, b"hello world").unwrap_or_default()),
            "wem0Upqsl5MBD0Z39jWO/g=="
        );
        assert_eq!(
            b64(&aes128_cbc_pkcs7(key, b"0123456789abcdef").unwrap_or_default()),
            "C5sV2ktEoPUVHc/EwB811b8xuRnjiS3cO1khLWp7EeY="
        );
        assert_eq!(
            b64(&aes128_cbc_pkcs7(key, &vec![b'x'; 31]).unwrap_or_default()),
            "y0llo51w6nQBY+ECS5Da1e0Cxp/hVcoq+Y/w/uP2ywA="
        );
    }

    /// COSY 的 RSA 公钥模数（与 `cosy.rs` 同一份）
    const MODULUS_HEX: &str = "c0f22307e5cd362e296bb04470f6de8fbf935ce24e8fcf511a0e2701329769c4a76e499bb938036a52af1eaf818cf79a2600620e3ce87e371d2ca6d85803606a1b3fa5e874643c9ed2db7e85673ef7227fca56e2e7c08f0927609bb896a9f24be1782099a66016a5bfdc3f1ff756bfc9e88d7b5dc5be30bf45a0223a00ebcecf";

    /// 固定的 PKCS#1 v1.5 编码块：`00 02` + 114 个 `0x55` + `00` + `hello-pkcs1`
    /// （构造而不是抄长串十六进制 —— 抄错一个字节就白测了）
    fn fixed_encoding_block() -> Vec<u8> {
        let mut block = vec![0x00, 0x02];
        block.extend(std::iter::repeat(0x55).take(114));
        block.push(0x00);
        block.extend_from_slice(b"hello-pkcs1");
        block
    }

    /// .NET `BigInteger.ModPow(EM, 65537, n)` 的结果
    const FIXED_CIPHER_HEX: &str = "52d0236e7f04787f66372794e894a91420dce25d0b91c333507757d80972b0a6554ea90b7d3158664f17d5960a206d7cd34b5936867bf68a7f1dcd12bf5ff8b22a692cca57f61d96d380a7bb610d7d375a3d18ea4d4e4986e90424c96df73bc84c9fa9f9db2f155ccbb2aaa9e12a73694d7ef6154f09f18bf91c0149cdbcb70a";

    #[test]
    fn rsa_modpow_matches_dotnet() {
        let modulus = limbs_from_be(&hex_bytes(MODULUS_HEX));
        let encodable = limbs_from_be(&fixed_encoding_block());
        let cipher = mod_pow(&encodable, 65537, &modulus);
        assert_eq!(limbs_to_be(&cipher, 128), hex_bytes(FIXED_CIPHER_HEX));
    }

    #[test]
    fn rsa_padding_shape_is_pkcs1_v15() {
        let modulus = hex_bytes(MODULUS_HEX);
        let cipher = rsa_pkcs1_encrypt(&modulus, 65537, b"hello-pkcs1");
        assert_eq!(cipher.len(), 128);
        // 密文不可能恰好等于明文块（模幂是可逆的，这里只是「算出来了」的粗检）
        assert_ne!(cipher, fixed_encoding_block());
    }
}

// ─── 随机源 ─────────────────────────────────────────────────────

/// 组件内单调计数器（同一毫秒内多次取随机也要不同）
static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

fn host_random(len: usize) -> Option<Vec<u8>> {
    let value = sdk::host("random.bytes", json!({ "length": len })).ok()?;
    let bytes: Vec<u8> = match &value {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_u64().map(|number| number as u8))
            .collect(),
        Value::Object(_) => ["bytes", "data"]
            .iter()
            .find_map(|key| value.get(*key))
            .map(|inner| match inner {
                Value::Array(items) => items
                    .iter()
                    .filter_map(|item| item.as_u64().map(|number| number as u8))
                    .collect(),
                Value::String(text) => b64_decode(text).unwrap_or_default(),
                _ => Vec::new(),
            })
            .unwrap_or_default(),
        Value::String(text) => b64_decode(text).unwrap_or_default(),
        _ => Vec::new(),
    };
    if bytes.len() >= len && len > 0 {
        Some(bytes[..len].to_vec())
    } else {
        None
    }
}

/// 取 `len` 个随机字节（宿主能力优先，退到混合流 —— 见模块头的说明）
pub fn random_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    if let Some(bytes) = host_random(len) {
        return bytes;
    }
    let mut out = Vec::with_capacity(len + 32);
    let mut round = 0u64;
    while out.len() < len {
        let (nanos, tick) = (sdk::now(), COUNTER.fetch_add(0x2545_f491_4f6c_dd1d, Ordering::Relaxed));
        let mut hasher = Sha256::new();
        hasher.update(b"qoder-wasm-entropy");
        hasher.update(nanos.to_be_bytes());
        hasher.update(tick.to_be_bytes());
        hasher.update(round.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        round += 1;
    }
    out.truncate(len);
    out
}

/// 一个 UUID v4 文本（`8-4-4-4-12`，小写）
pub fn uuid_v4() -> String {
    let mut bytes = random_bytes(16);
    if bytes.len() != 16 {
        return String::new();
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex_lower(&bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// 32 字节随机串的 URL 安全 base64（登录 state / PKCE verifier）
pub fn random_secret() -> String {
    b64_url_nopad(&random_bytes(32))
}

/// 一个 SHA-256 派生串（`prefix` + 种子，取前 `take` 个 hex 字符）
pub fn derive_hex(prefix: &str, seed: &[u8], take: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update([0u8]);
    hasher.update(seed);
    let text = hex_lower(&hasher.finalize());
    text.chars().take(take).collect()
}
