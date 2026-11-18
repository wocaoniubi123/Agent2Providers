//! 请求标识：签名 nonce、请求信封 `traceid` 与追踪头里的 id。
//!
//! ── 为什么全部走主程序的随机源 ────────────────────────────────
//! Wasm 插件没有系统时钟/熵源可用（硬约束也只允许四个依赖），随机只能经
//! `random.bytes` 向主程序要。拿不到时退化成「时钟 + xorshift」，理由与 native
//! 侧一致：这些 id 的用途是**一次性**（nonce 防重放口径由服务端时间窗保证、
//! traceid 只是串联日志），唯一性够用即可，不承担安全职责。

use agent2api_wasm_sdk::{self as sdk, json};

use super::crypto;

/// 取 `count` 个随机字节。
pub fn random_bytes(count: usize) -> Vec<u8> {
    if count == 0 || count > 256 {
        return Vec::new();
    }
    if let Ok(value) = sdk::host("random.bytes", json!({ "length": count })) {
        if let Some(bytes) = value.as_str().and_then(crypto::base64_decode) {
            if bytes.len() == count {
                return bytes;
            }
        }
    }
    fallback(count)
}

/// 主程序随机源不可用时的兜底（xorshift64，种子取当前毫秒）。
fn fallback(count: usize) -> Vec<u8> {
    let mut seed = (sdk::now() as u64) ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.push((seed >> 24) as u8);
    }
    out
}

/// 小写十六进制随机串（`traceid` 的形态）。
pub fn hex_token(count: usize) -> String {
    crypto::hex(&random_bytes(count))
}

/// UUID v4 形态的 Nonce（客户端签名用的是**带连字符**的 randomUUID 原样值）。
pub fn uuid_v4() -> String {
    let mut bytes = random_bytes(16);
    if bytes.len() != 16 {
        return hex_token(16);
    }
    // RFC4122 v4：版本位与变体位
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = crypto::hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// 追踪头里的 message id（`MsgId`）
pub fn message_id() -> String {
    hex_token(16)
}

/// 追踪头里的 span id（`traceparent` 中间那段）
pub fn span_id() -> String {
    hex_token(8)
}

/// 生成一个带前缀的随机 id（`msg_<32 位十六进制>` 形态，与网关出站转换器同款）。
///
/// 这些 id 会出现在**下发帧**里（`chat.completion.chunk.id`），客户端可能用它
/// 做关联与去重；同一秒内的两次请求拿到相同 id 会让客户端侧串台，所以不用时间戳。
pub fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", hex_token(16))
}
