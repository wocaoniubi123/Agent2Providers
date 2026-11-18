//! 编解码原语：base64 解码（宿主随机源的返回形态）与 uuid v4 生成。
//!
//! ── 为什么要自己写 base64 解码 ──────────────────────────────
//! 本包只允许依赖 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`，
//! 而宿主 `random.bytes` 给的是 base64（`wasm/services.rs` 的 `random.bytes`
//! 分支：`base64::STANDARD.encode(bytes)`）。本家有两处真的要随机字节：
//!
//!   1. **登录的 `uuid` 载荷件** —— 换码时下发、续期时必须原样回传
//!      （见 `credentials.rs` 的模块头：它丢了账号就永远续不了期）；
//!   2. **签到的 `idempotencyKey`** —— 上游没有「今天签过了就返回已签」的
//!      幂等语义，重复键由客户端负责（见 `checkin.rs` 的模块头）。
//!
//! 两处都只需要 16 字节 + uuid v4 的版本位 / 变体位，所以解码器只做
//! 「标准表 + padding 容忍」这一档，不做流式 / 多方言。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result};

/// base64 解码（标准表；`=` 与空白字符一律跳过，`-` / `_` 按 URL 安全表认）。
///
/// 返回 `None` 只可能是「出现了表外字符」—— 那不是编码问题，是宿主给的东西
/// 不是 base64，调用方要如实报错而不是拿半份字节去当 uuid。
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(text.len() * 3 / 4 + 3);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
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
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

/// 小写十六进制（uuid 的渲染形态）。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 从 16 字节拼成 uuid v4 的字符串形态（**纯函数**，便于脱网测试）。
///
/// 版本位与变体位在这里改写：`bytes[6]` 高 4 位固定 `0100`（版本 4），
/// `bytes[8]` 高 2 位固定 `10`（RFC 4122 变体）。
pub fn uuid_from_bytes(bytes: &[u8; 16]) -> String {
    let mut raw = *bytes;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let hex = hex_lower(&raw);
    let part = |start: usize, end: usize| hex.get(start..end).unwrap_or("").to_string();
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

/// 向宿主要 16 字节随机数并拼成 uuid v4。
///
/// ── 为什么走 `random.v1` 而不是自己凑熵 ─────────────────────
/// 签到幂等键与登录 uuid 都要「同一时刻两次调用不能撞」，`clock.now` 加
/// 计数器做不到这一点（同一毫秒内的两次调用会撞）。宿主的 `random.bytes`
/// 直接取系统随机源，正是为这种场景准备的。
pub fn uuid_v4() -> Result<String> {
    let encoded = sdk::host("random.bytes", json!({ "length": 16 }))?;
    let text = encoded
        .as_str()
        .ok_or_else(|| Error::new("LobsterAI 随机源回应不是文本"))?;
    let decoded = base64_decode(text).ok_or_else(|| Error::new("LobsterAI 随机源回应不是有效 base64"))?;
    if decoded.len() < 16 {
        return Err(Error::new("LobsterAI 随机源返回的字节不足 16 个"));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&decoded[..16]);
    Ok(uuid_from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        // RFC 4648 的经典向量（含 padding 与无 padding 两种收尾）
        assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("TWFu"), Some(b"Man".to_vec()));
        assert_eq!(base64_decode("TWE="), Some(b"Ma".to_vec()));
        assert_eq!(base64_decode("TQ=="), Some(b"M".to_vec()));
        assert_eq!(base64_decode(""), Some(Vec::new()));
        // 16 字节：0x00..0x0f（宿主返回 16 字节时的形态）
        let sixteen = base64_decode("AAECAwQFBgcICQoLDA0ODw==");
        assert_eq!(
            sixteen,
            Some((0u8..16).collect::<Vec<u8>>())
        );
        // 空白与换行按 MIME 习惯跳过
        assert_eq!(base64_decode("aGVs\nbG8="), Some(b"hello".to_vec()));
        // URL 安全表同样认（`-` / `_`）
        assert_eq!(base64_decode("a-_b"), Some(vec![0x6b, 0xef, 0xdb]));
    }

    #[test]
    fn base64_rejects_outside_the_table() {
        // 表外字符必须是 None，而不是「悄悄丢字节」——否则 uuid 会变成半截
        assert_eq!(base64_decode("aGVs*bG8="), None);
        assert_eq!(base64_decode("中文"), None);
    }

    #[test]
    fn uuid_sets_version_and_variant_bits() {
        let uuid = uuid_from_bytes(&[0u8; 16]);
        // 全零输入：版本位与变体位必须被改写，其余仍是 0
        assert_eq!(uuid, "00000000-0000-4000-8000-000000000000");
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.split('-').map(str::len).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
        let uuid = uuid_from_bytes(&[0xffu8; 16]);
        assert_eq!(uuid, "ffffffff-ffff-4fff-bfff-ffffffffffff");
    }

    #[test]
    fn hex_lower_is_two_digits_per_byte() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_lower(&[]), "");
    }
}
