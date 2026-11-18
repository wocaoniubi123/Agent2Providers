//! 编码与随机源的小工具。
//!
//! ── 为什么这里会有一个 base64 ────────────────────────────────
//! 插件依赖被限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`
//! 四件，`base64` 不在其中。本家只用它做三件事：读 JWT 声明（不验签，只读
//! `exp` / `iat` / `TokenExpireAt`）、拼 PEM 的 64 字符折行、给 PKCE 的
//! verifier / challenge 编码 —— 所以自己写这一小份，比拉一个新依赖干净。
//!
//! ── 随机源为什么要问宿主 ────────────────────────────────────
//! `getrandom` 在 wasm32-unknown-unknown 上没有默认后端，硬链进来会是
//! 运行期 panic。宿主的 `random.v1` 能力就是给这件事准备的：先问它；
//! 问不到（老宿主 / 未授予）才退到时钟 + 计数器派生。用随机的都是
//! **一次性标识**（uuid、device id、X-Request-Id），不是安全令牌 ——
//! 退化不会让登录更不安全，只是让两个请求的 id 更可能撞上。

use agent2api_wasm_sdk::{self as sdk, json, Value};

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准字母表（带 `=` 填充），PEM 用。
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0) as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let block = (first << 16) | (second << 8) | third;
        out.push(STANDARD[(block >> 18) as usize & 0x3f] as char);
        out.push(STANDARD[(block >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 { STANDARD[(block >> 6) as usize & 0x3f] as char } else { '=' });
        out.push(if chunk.len() > 2 { STANDARD[block as usize & 0x3f] as char } else { '=' });
    }
    out
}

/// 标准字母表解码（接受 `=` 填充，也接受缺填充）。
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut block: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        block = (block << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((block >> bits) as u8);
            block &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

/// 向宿主要随机字节；拿不到就用时钟派生（见模块头）。
pub fn random_bytes(length: usize) -> Vec<u8> {
    if let Ok(value) = sdk::host("random.bytes", json!({ "length": length })) {
        if let Some(bytes) = host_random(&value, length) {
            return bytes;
        }
    }
    fallback_random(length)
}

/// 宿主回包形态没有契约文档，所以三种常见形态都认：数组、
/// `{bytes|data}` 下的 base64、`{hex}` 下的十六进制。
fn host_random(value: &Value, length: usize) -> Option<Vec<u8>> {
    if let Some(items) = value.as_array() {
        let bytes: Vec<u8> = items.iter().filter_map(|item| item.as_u64().map(|number| number as u8)).collect();
        if bytes.len() >= length {
            return Some(bytes[..length].to_vec());
        }
    }
    for key in ["bytes", "data", "random"] {
        let Some(text) = value[key].as_str() else { continue };
        if let Some(bytes) = base64_decode(text) {
            if bytes.len() >= length {
                return Some(bytes[..length].to_vec());
            }
        }
        if let Some(bytes) = hex_decode(text) {
            if bytes.len() >= length {
                return Some(bytes[..length].to_vec());
            }
        }
    }
    if let Some(text) = value["hex"].as_str().and_then(hex_decode) {
        if text.len() >= length {
            return Some(text[..length].to_vec());
        }
    }
    None
}

fn fallback_random(length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(length + 32);
    let mut round = 0u64;
    while out.len() < length {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!(
            "trae:{}:{}:{}:{:p}",
            sdk::now(),
            counter,
            round,
            &COUNTER as *const AtomicU64
        );
        out.extend_from_slice(&Sha256::digest(seed.as_bytes()));
        round = round.saturating_add(1);
    }
    out.truncate(length);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for case in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = base64_encode(case.as_bytes());
            assert_eq!(base64_decode(&encoded).unwrap_or_default(), case.as_bytes());
        }
        assert_eq!(base64_url_decode("eyJhIjoxfQ"), Some(b"{\"a\":1}".to_vec()));
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(hex_decode("00ff1a"), Some(vec![0x00, 0xff, 0x1a]));
    }
}

/// base64url（无填充）解码 —— JWT 的 payload 段用它。
pub fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(text.trim_end_matches('='))
}
