//! 编码 / 随机 / 查询串小工具（Accio 两个包共用）。
//!
//! ── 为什么这里有一份 base64 ─────────────────────────────────
//! 依赖被限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono` 四件，
//! `base64` 不在其中。本家只用它做一件事：PKCE 的
//! `code_challenge = base64url(SHA-256(verifier))`（见 `oauth.rs`）。因此自己
//! 写这一份无填充 base64url，比拉一个新依赖干净。
//!
//! ── 随机源为什么要问宿主 ────────────────────────────────────
//! `getrandom` 在 wasm32-unknown-unknown 上没有默认后端，硬链进来会是运行期
//! panic。宿主的 `random.v1` 能力就是给这件事准备的（`wasm.json` 已申报）：
//! 先问它；问不到（老宿主 / 未授予）才退到时钟 + 计数器派生。用随机的都是
//! **一次性标识**（PKCE verifier、device id、流程 id）—— PKCE 的 verifier
//! 退化成可预测值时防换码那一道会变弱，但仍是「一次性串」；登录本身另有
//! state 逐字比对（见 `login.rs`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// base64url 字母表（RFC 4648 §5：`-` `_` 代替 `+` `/`）。
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编码，**不带 `=` 填充**（PKCE 的 challenge / verifier 都是这个形态）。
pub fn base64_url_no_pad(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0) as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let block = (first << 16) | (second << 8) | third;
        output.push(URL_SAFE[(block >> 18) as usize & 0x3f] as char);
        output.push(URL_SAFE[(block >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            output.push(URL_SAFE[(block >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            output.push(URL_SAFE[block as usize & 0x3f] as char);
        }
    }
    output
}

/// 小写十六进制。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// 向宿主要随机字节；拿不到就用时钟 + 计数器派生（见模块头）。
pub fn random_bytes(length: usize) -> Vec<u8> {
    if let Ok(value) = sdk::host("random.bytes", json!({ "length": length })) {
        if let Some(bytes) = host_random(&value, length) {
            return bytes;
        }
    }
    fallback_random(length)
}

/// 宿主回包的三种常见形态都认：字节数组、`{bytes|data}` 的 base64、十六进制串。
fn host_random(value: &Value, length: usize) -> Option<Vec<u8>> {
    if let Some(items) = value.as_array() {
        let bytes: Vec<u8> = items
            .iter()
            .filter_map(|item| item.as_u64().map(|number| number as u8))
            .collect();
        if bytes.len() >= length {
            return Some(bytes[..length].to_vec());
        }
    }
    for key in ["bytes", "data", "random"] {
        let Some(text) = value[key].as_str() else { continue };
        if let Some(bytes) = decode_maybe_base64(text).filter(|bytes| bytes.len() >= length) {
            return Some(bytes[..length].to_vec());
        }
        if let Some(bytes) = decode_hex(text).filter(|bytes| bytes.len() >= length) {
            return Some(bytes[..length].to_vec());
        }
    }
    None
}

/// 宽松 base64 解码（两种字母表都认，忽略填充与空白）。
fn decode_maybe_base64(text: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len() / 4 * 3);
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
            output.push((block >> bits) as u8);
            block &= (1u32 << bits) - 1;
        }
    }
    Some(output)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        output.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(output)
}

fn fallback_random(length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut output = Vec::with_capacity(length + 32);
    let mut round = 0u64;
    while output.len() < length {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!("accio:{}:{}:{}", sdk::now(), counter, round);
        output.extend_from_slice(&Sha256::digest(seed.as_bytes()));
        round = round.saturating_add(1);
    }
    output.truncate(length);
    output
}

/// 一次性随机串（32 字节 → base64url 43 字符，落在 PKCE 要求的 43–128 之间）。
pub fn random_token() -> String {
    base64_url_no_pad(&random_bytes(32))
}

/// `application/x-www-form-urlencoded` 的编码（只转义必须转义的字节）。
pub fn urlencode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

/// 百分号解码（`+` 按空格处理：浏览器在查询串里就是这么编的）。
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        output.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        output.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            other => {
                output.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

/// 查询串 → 有序键值对（调用方按需查表；重复键保留最后一个，与 `URLSearchParams` 同口径）。
pub fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .trim_start_matches('?')
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| match pair.split_once('=') {
            Some((key, value)) => Some((percent_decode(key), percent_decode(value))),
            None => Some((percent_decode(pair), String::new())),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// RFC 4648 的 base64url 示例（无填充）—— PKCE 的 challenge 走同一个编码器。
    #[test]
    fn base64_url_matches_rfc_vector() {
        assert_eq!("", base64_url_no_pad(b""));
        assert_eq!("Zg", base64_url_no_pad(b"f"));
        assert_eq!("Zm8", base64_url_no_pad(b"fo"));
        assert_eq!("Zm9v", base64_url_no_pad(b"foo"));
        // RFC 7636 附录 B 的 PKCE 示例：verifier → challenge
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            base64_url_no_pad(&Sha256::digest(verifier.as_bytes()))
        );
    }

    #[test]
    fn query_round_trip() {
        let encoded = format!("a={}&b=x%20y", urlencode("https://www.accio.com/login?x=1&y=2"));
        let pairs = query_pairs(&encoded);
        assert_eq!(Some(("a".to_string(), "https://www.accio.com/login?x=1&y=2".to_string())), pairs.first().cloned());
        assert_eq!(Some(("b".to_string(), "x y".to_string())), pairs.get(1).cloned());
    }

    #[test]
    fn percent_decode_keeps_bad_escapes() {
        assert_eq!("%zz", percent_decode("%zz"));
        assert_eq!("a b", percent_decode("a+b"));
    }
}
