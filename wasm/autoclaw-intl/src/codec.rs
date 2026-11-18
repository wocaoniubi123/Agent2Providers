//! 编码 / 随机 / 查询串 / JWT 载荷小工具（AutoClaw 两个包共用）。
//!
//! ── 为什么这里会有一份 base64 与 JWT 解析 ─────────────────────
//! 依赖被限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono` 四件，
//! `base64` 不在其中。本家只用它读 JWT 载荷（**不验签**，只读 `user_id` /
//! `exp` / `device_id`）：token 是不透明串时就只能靠这几条声明认人 ——
//! 与 native `crypto::decode_jwt_claims` 同一取向。
//!
//! ── 随机源为什么要问宿主 ────────────────────────────────────
//! `getrandom` 在 wasm32-unknown-unknown 上没有默认后端，硬链进来会是运行期
//! panic。宿主的 `random.v1` 能力就是给这件事准备的（`wasm.json` 已申报）：
//! 先问它；问不到（老宿主 / 未授予）才退到时钟 + 计数器派生。用随机的都是
//! **一次性标识**（device id、请求 id、流程 id），不是安全令牌。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

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
        if let Some(bytes) = decode_base64(text).filter(|bytes| bytes.len() >= length) {
            return Some(bytes[..length].to_vec());
        }
        if let Some(bytes) = decode_hex(text).filter(|bytes| bytes.len() >= length) {
            return Some(bytes[..length].to_vec());
        }
    }
    None
}

/// 宽松 base64 解码（标准与 url-safe 两种字母表都认，忽略填充与空白）。
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
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
        let seed = format!("autoclaw:{}:{}:{}", sdk::now(), counter, round);
        output.extend_from_slice(&Sha256::digest(seed.as_bytes()));
        round = round.saturating_add(1);
    }
    output.truncate(length);
    output
}

/// 64 位十六进制随机串（device id 的形态：官方客户端是 ed25519 公钥的
/// SHA-256，服务端只把它当不透明串，32 字节随机即可承担「区分设备」的职责）。
pub fn random_hex_id() -> String {
    hex_lower(&random_bytes(32))
}

/// 32 位小写 hex（一次性流程 id 用）。
pub fn random_flow_id() -> String {
    hex_lower(&random_bytes(16))
}

/// 读 JWT 的载荷（不验签）。解析不出来返回 None。
///
/// 只读三样：`user_id`（账号身份）、`device_id`（设备指纹）、`exp`（到期秒）。
pub fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = decode_base64(payload)?;
    serde_json::from_slice(&bytes).ok()
}

/// 去掉 `Bearer ` 前缀（大小写不敏感）。
///
/// ── 为什么必须剥（issue #386）───────────────────────────────
/// 登录拿到的 `access_token` 本身可能已经带 `Bearer `，直接拼会得到
/// `Bearer Bearer eyJ…`，上游按空格切分后拿到字面量 `Bearer …`（不是合法
/// JWT）→ 恒定 401 `Invalid token`。剥在这里（出口唯一一处）才不会漏掉某条链路。
pub fn strip_bearer(token: &str) -> String {
    let trimmed = token.trim();
    if trimmed.get(..7).is_some_and(|prefix| prefix.eq_ignore_ascii_case("Bearer ")) {
        return trimmed[7..].trim().to_string();
    }
    trimmed.to_string()
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

/// 查询串 → 有序键值对（重复键保留最后一个，与 `URLSearchParams` 同口径）。
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

    /// JWT 载荷解码（不验签）与 `Bearer ` 剥离 —— 两条都在认证链路上。
    #[test]
    fn jwt_and_bearer() {
        // {"user_id":"42","exp":1700000000} 的 base64url（无填充），放在 JWT 第二段
        let token = "h.eyJ1c2VyX2lkIjoiNDIiLCJleHAiOjE3MDAwMDAwMDB9.s";
        let claims = jwt_claims(token).unwrap_or(Value::Null);
        assert_eq!("42", claims["user_id"].as_str().unwrap_or(""));
        assert_eq!(1_700_000_000_i64, claims["exp"].as_i64().unwrap_or(0));
        assert_eq!("abc", strip_bearer("Bearer abc"));
        assert_eq!("abc", strip_bearer("abc"));
        assert_eq!(None, jwt_claims("not-a-jwt"));
    }

    #[test]
    fn query_round_trip() {
        let pairs = query_pairs("?code=a%2Fb&state=x+y");
        assert_eq!(Some(("code".to_string(), "a/b".to_string())), pairs.first().cloned());
        assert_eq!(Some(("state".to_string(), "x y".to_string())), pairs.get(1).cloned());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!("00ff1a", hex_lower(&[0x00, 0xff, 0x1a]));
        assert_eq!(Some(vec![0x00, 0xff, 0x1a]), decode_hex("00ff1a"));
    }
}
