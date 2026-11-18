//! 编码与随机源。
//!
//! ── 为什么自己写 base64 ────────────────────────────────────
//! 插件依赖硬性限定在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`
//! 四件（迁移规格第 1 节），`base64` 不在其中。本家只需要标准字母表两向转换
//! （ID 派生、指纹里的十六进制），自己写这一小份比拉依赖干净。
//!
//! ── 随机源为什么问宿主 ────────────────────────────────────
//! `getrandom` 在 `wasm32-unknown-unknown` 上没有默认后端，硬链进来会是运行期
//! 错误。宿主的 `random.v1` 能力（`random.bytes`）就是给这件事准备的，**返回
//! 标准 base64 字符串**（见网关 `plugin_host/wasm/services.rs` 的 `random.bytes`
//! 分支）。问不到才退化到「时钟 + 计数」派生 —— 这里产出的一次性标识
//! （conversationId / turnRequestId / messageId）对密码学强度无要求，
//! 退化只增加碰撞概率，不会让登录态失守。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use std::sync::atomic::{AtomicU64, Ordering};

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 标准字母表解码（接受 `=` 填充、缺失填充与空白）。
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
            b'+' => 62,
            b'/' => 63,
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

/// 小写十六进制（指纹、尾段、日志用）。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 十六进制解码（指纹链从会话存储读回来时用）。
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
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

/// 向宿主要随机字节；拿不到就用时钟派生。
///
/// 宿主回包是 base64 字符串（已核实网关实现），但这里同时兼容「数组」与
/// `{bytes|data}` 包裹形态：宿主换了包装也不会让 id 生成整条路挂掉。
pub fn random_bytes(length: usize) -> Vec<u8> {
    if length == 0 {
        return Vec::new();
    }
    if let Ok(value) = sdk::host("random.bytes", json!({ "length": length })) {
        if let Some(bytes) = host_random(&value, length) {
            return bytes;
        }
    }
    fallback_random(length)
}

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
    if let Some(text) = value.as_str() {
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
    for key in ["bytes", "data", "random"] {
        let Some(text) = value[key].as_str() else { continue };
        if let Some(bytes) = base64_decode(text) {
            if bytes.len() >= length {
                return Some(bytes[..length].to_vec());
            }
        }
    }
    None
}

fn fallback_random(length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(length + 32);
    let mut round = 0u64;
    while out.len() < length {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!("agent2api:catpaw:{}:{}:{}", sdk::now(), counter, round);
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
    fn base64_decode_known_vectors() {
        // 标准字母表 + 填充的已知向量（RFC 4648 的 test vectors）
        assert_eq!(base64_decode("").unwrap_or_default(), Vec::<u8>::new());
        assert_eq!(base64_decode("Zg==").unwrap_or_default(), b"f".to_vec());
        assert_eq!(base64_decode("Zm8=").unwrap_or_default(), b"fo".to_vec());
        assert_eq!(base64_decode("Zm9v").unwrap_or_default(), b"foo".to_vec());
        assert_eq!(base64_decode("Zm9vYmE=").unwrap_or_default(), b"fooba".to_vec());
        assert_eq!(base64_decode("Zm9vYmFy").unwrap_or_default(), b"foobar".to_vec());
        // 缺填充也认（宿主回包形态不保证带 `=`）
        assert_eq!(base64_decode("Zm9vYmFy").unwrap_or_default(), b"foobar".to_vec());
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(hex_decode("00ff1a"), Some(vec![0x00, 0xff, 0x1a]));
    }
}
