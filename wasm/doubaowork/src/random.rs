//! 随机源与标识生成。
//!
//! ── 为什么走宿主 ────────────────────────────────────────────
//! native 用 `crate::ids::uuid_v4()` / `random_id()`；wasm 沙箱内没有随机源，
//! 只能调 `random.bytes`（能力 `random.v1`）。豆包信封里的 `local_message_id`
//! 与 `unique_key` 必须是每次请求不同的标识，所以随机源失败时整次请求失败，
//! 而不是退回时间戳（重复的 `unique_key` 会被上游当成同一条消息）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result};

use super::codec;

fn bytes(count: usize) -> Result<Vec<u8>> {
    let value = sdk::host("random.bytes", json!({ "length": count }))?;
    codec::base64_decode(value.as_str().unwrap_or(""))
        .filter(|bytes| bytes.len() == count)
        .ok_or_else(|| Error::new("随机源返回的字节数不符"))
}

/// RFC 4122 v4 形态的随机标识。
pub fn uuid() -> Result<String> {
    let mut raw = bytes(16)?;
    if let Some(first) = raw.first_mut() {
        *first = (*first & 0x0f) | 0x40;
    }
    if let Some(seventh) = raw.get_mut(8) {
        *seventh = (*seventh & 0x3f) | 0x80;
    }
    let hex = codec::hex(&raw);
    let part = |from: usize, to: usize| hex.get(from..to).unwrap_or("").to_string();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    ))
}

/// `<prefix>-<32 位十六进制>`，给内部标记与工具调用 id 用。
pub fn id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}-{}", codec::hex(&bytes(16)?)))
}
