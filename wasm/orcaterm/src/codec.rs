//! 编码与随机源的小工具。
//!
//! ── 为什么自带一份 base64 ──────────────────────────────────
//! 插件依赖被限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`
//! 四件，`base64` 不在其中。本家要用它做两件事：
//!   1. 读 JWT 的 payload 段（**只解声明、不验签** —— token 好不好用由上游
//!      说了算，我们要的只是 `userId` 与 `exp` 两个读数）；
//!   2. 解 `file_base64` 来源的 data.bin（用户选文件时网关给的是 base64）。
//! 两个方向都只需要**解码**，所以这里只留一份解码器（编码器一行都不写）。
//!
//! ── 随机源为什么要问宿主 ────────────────────────────────────
//! `getrandom` 在 wasm32-unknown-unknown 上没有默认后端，硬链进来就是运行期
//! 失败。宿主的 `random.v1` 能力就是给这件事准备的：先问它；问不到（老宿主 /
//! 未授予）才退到时钟 + 计数器派生。用随机的都是**一次性标识**（会话 id、
//! `x-seqid`、OAuth `session_id`），不是安全令牌 —— 退化只会让 id 更容易撞上，
//! 不会让凭证更不安全。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 解码：标准与 URL 安全两张字母表都认（`+/` 与 `-_` 等价），填充可缺。
///
/// 出现字母表以外的字符就返回 `None` —— 调用方据此给出「不是合法 base64」这类
/// 可读错误，而不是悄悄解出半截字节。
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

/// base64url（无填充）解码 —— JWT 的 payload 段用它。
pub fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(text.trim_end_matches('='))
}

/// 小写十六进制。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

/// 宿主回包形态没有契约文档，所以三种常见形态都认：数组、`{bytes|data}` 下的
/// base64、`{hex}` 下的十六进制。
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
    if let Some(bytes) = value["hex"].as_str().and_then(hex_decode) {
        if bytes.len() >= length {
            return Some(bytes[..length].to_vec());
        }
    }
    None
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

/// 时钟派生的兜底随机（只在宿主随机源不可用时走到）。
fn fallback_random(length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(length + 32);
    let mut round = 0u64;
    while out.len() < length {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!("orcaterm:{}:{}:{}", sdk::now(), counter, round);
        out.extend_from_slice(&Sha256::digest(seed.as_bytes()));
        round = round.saturating_add(1);
    }
    out.truncate(length);
    out
}

/// RFC 4122 v4 形态的随机 id（会话 id / `x-seqid` / OAuth `session_id` 都用它）。
///
/// 上游对 `sessionId` 做格式校验，非 UUID 直接回
/// `api-params-verify-fail: sessionId must be a UUID`，所以版本位与变体位必须写。
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    let raw = random_bytes(16);
    let take = raw.len().min(16);
    bytes[..take].copy_from_slice(&raw[..take]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex_lower(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 的已知向量：长度 0..=6 的每种余数（填充为 0/1/2 个 `=`）全覆盖，
    /// 另含缺填充的形态。
    #[test]
    fn base64_known_vectors() {
        for (encoded, plain) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zg", "f"),
            ("Zm8=", "fo"),
            ("Zm8", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(base64_decode(encoded), Some(plain.as_bytes().to_vec()), "encoded={encoded}");
        }
    }

    /// 非法字符必须被拒（否则「不是合法 base64」这条错误永远触发不了）。
    #[test]
    fn base64_rejects_garbage() {
        assert_eq!(base64_decode("Zm9v*YmFy"), None);
    }

    /// JWT payload 段（base64url、无填充）的已知向量。
    #[test]
    fn base64_url_known_vector() {
        let payload = "eyJ1c2VySWQiOjEwMDAxLCJleHAiOjE3MDAwMDAwMDB9";
        let bytes = base64_url_decode(payload).unwrap_or_default();
        assert_eq!(String::from_utf8(bytes).unwrap_or_default(), r#"{"userId":10001,"exp":1700000000}"#);
        // 带 `-` / `_` 的 URL 安全字母表也要解对
        assert_eq!(
            base64_url_decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9").map(|b| String::from_utf8(b).unwrap_or_default()),
            Some(r#"{"alg":"HS256","typ":"JWT"}"#.to_string())
        );
    }

    #[test]
    fn hex_is_lowercase_and_even() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(hex_decode("00ff1a"), Some(vec![0x00, 0xff, 0x1a]));
        assert_eq!(hex_decode("00f"), None);
    }

    /// UUID 形态：36 字符、四段分隔、版本位 4、变体位 8/9/a/b。
    #[test]
    fn uuid_shape() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36, "{id}");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.iter().map(|part| part.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
        assert_eq!(parts[2].chars().next(), Some('4'));
        assert!(matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b')));
    }
}
