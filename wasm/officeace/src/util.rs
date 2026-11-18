//! 编码、随机源、时间与取值的小工具。
//!
//! ── 为什么这里会有一份 base64 ────────────────────────────────
//! 插件依赖被钉死在 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono` 四件，
//! `base64` 不在其中。本家用它做四件事：Basic 鉴权头、PKCE 的 verifier/challenge、
//! DPoP 的 JWS 三段、以及 JWT / `user_profile` 的解码。自己写这一小份，比为一个
//! 编解码函数拉一个新依赖干净。
//!
//! ── 随机源为什么要问宿主 ────────────────────────────────────
//! `getrandom` 在 wasm32-unknown-unknown 上没有默认后端，硬链进来会是运行期 panic。
//! 宿主的 `random.v1` 能力就是给这件事准备的：先问它；问不到（老宿主 / 未授予）
//! 才退到时钟 + 计数器派生。本家用随机的两处性质不同：
//!   · `Chat-Id` / `Session-Id` / DPoP 的 `jti` / OAuth `state` —— **一次性标识**，
//!     退化只让两个请求更容易撞 id，不影响安全；
//!   · PKCE verifier 与 **ECDSA 的 k** —— 前者退化仍可用；后者退化会让签名可预测
//!     （k 与私钥的线性关系能反解出私钥）。所以 [`random_bytes`] 失败时调用方
//!     （`p256::sign`）宁可报错，不拿时间戳硬顶 —— 见那边模块头。
//!
//! ── 为什么北京时间另起一套 ──────────────────────────────────
//! 签到台账按「北京自然日」分天（上游活动周期就是 UTC+8 零点）。跟着机器时区走
//! 会让边界整体漂移，所以这里直接用固定 UTC+8 偏移 —— 中国标准时间没有夏令时，
//! 一个固定偏移就够，且不依赖宿主机 tzdata。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 标准字母表（带 `=` 填充）：Basic 鉴权头用。
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// URL 安全字母表（无填充）：JWS / JWK / PKCE 用。
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// 北京时间固定偏移（秒）。
pub const BEIJING_OFFSET_SECONDS: i32 = 8 * 3600;

// ── 取值 ─────────────────────────────────────────────────────

/// 按候选键取第一个非空字符串（本仓账号记录的历史别名很多，逐家都这么取）。
pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            value[*key]
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
        })
        .unwrap_or("")
        .to_string()
}

/// 取一个字符串键（trim 后为空算没有）。
pub fn text_of(container: &Value, key: &str) -> Option<String> {
    container
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 上游数值字段 → f64：数字直接用、字符串解析、其余给 0（与 JS 的 `Number(v)` 同口径）。
///
/// 必须走这里：本家上游把数值写成**字符串**（实测 `"sku_value": "500"`、
/// `"points": "4000"`），`Value::as_f64()` 对字符串恒回 `None`，直接用它会把
/// 余额与奖励全算成 0。
pub fn num(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0),
        Some(Value::String(text)) => text.trim().parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// 上游数值字段 → `Option<f64>`（缺失 / 空串 / 非数字 / 非有限值一律 `None`）。
///
/// 与 [`num`] 的分工：聚合读数要一个**可加的数**，缺失折 0；明细行要回答
/// 「上游到底给没给」，缺失必须**整个不写这个键** —— 写成 0 会被界面画成
/// 「只剩 0 / 已用 0」，这是明细那条线最要防的事故。
pub fn num_opt(value: Option<&Value>) -> Option<f64> {
    let parsed = match value {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
        _ => None,
    };
    parsed.filter(|value| value.is_finite())
}

/// 按字符数截断（不是字节：中文按字节截会切出半个字符）。
pub fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value.chars().take(limit).collect()
}

// ── 时间 ─────────────────────────────────────────────────────

/// 当前毫秒时间戳（宿主时钟，wasm 里没有系统时间）。
pub fn now_ms() -> i64 {
    sdk::now()
}

/// RFC3339（`2026-10-10T05:15:00Z`）→ 毫秒时间戳。
///
/// native 手写了一份 `days_from_civil`；wasm 侧 `chrono` 已在依赖清单里，用它可以
/// 少一份「闰年算错」的风险面，语义不变（只认带时区或 `Z` 的完整形态）。
pub fn parse_rfc3339_ms(input: &str) -> Option<i64> {
    let text = input.trim();
    if text.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.timestamp_millis())
}

/// 毫秒时间戳落在北京时间的哪一天（`YYYY-MM-DD`）。
pub fn date_key_of_ms(ms: i64) -> Option<String> {
    let offset = chrono::FixedOffset::east_opt(BEIJING_OFFSET_SECONDS)?;
    chrono::DateTime::from_timestamp_millis(ms).map(|utc| utc.with_timezone(&offset).format("%Y-%m-%d").to_string())
}

/// 北京时间的今天（`YYYY-MM-DD`）。
pub fn beijing_today_key() -> String {
    date_key_of_ms(now_ms()).unwrap_or_default()
}

// ── 十六进制 ─────────────────────────────────────────────────

/// 字节串 → 小写十六进制。
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 小写十六进制 → 字节串（非法字符 / 奇数长度给 None）。
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

// ── base64 ───────────────────────────────────────────────────

fn encode_with(alphabet: &[u8; 64], bytes: &[u8], padding: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk.first().copied().unwrap_or(0) as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let block = (first << 16) | (second << 8) | third;
        out.push(alphabet[(block >> 18) as usize & 0x3f] as char);
        out.push(alphabet[(block >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(block >> 6) as usize & 0x3f] as char);
        } else if padding {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[block as usize & 0x3f] as char);
        } else if padding {
            out.push('=');
        }
    }
    out
}

/// 标准字母表 + `=` 填充（Basic 鉴权头）。
pub fn base64_encode(bytes: &[u8]) -> String {
    encode_with(STANDARD, bytes, true)
}

/// URL 安全字母表、**无填充**（JWS / JWK / PKCE）。
pub fn base64url_encode(bytes: &[u8]) -> String {
    encode_with(URL_SAFE, bytes, false)
}

/// 解码：两套字母表都认（`+`/`-`、`/`/`_` 混用也无所谓），`=` 与空白跳过。
///
/// 两套都认是刻意的：上游在这个字段上没给过口径（见 native `oauth::decode_user_profile`
/// 的注释），而这条链的代价只是「取不到名字 / 解不开一段 JWT」，不是「取错值」。
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

/// base64url 解码（接受填充与缺填充）。
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(text.trim_end_matches('='))
}

// ── 随机 ─────────────────────────────────────────────────────

/// 向宿主要随机字节；拿不到就用时钟派生（见模块头）。
pub fn random_bytes(length: usize) -> Vec<u8> {
    if let Ok(value) = sdk::host("random.bytes", json!({ "length": length })) {
        if let Some(bytes) = host_random(&value, length) {
            return bytes;
        }
    }
    fallback_random(length)
}

/// 只走宿主随机源；拿不到给 `None`（ECDSA 的 k 用这条 —— 见模块头）。
pub fn secure_random_bytes(length: usize) -> Option<Vec<u8>> {
    let value = sdk::host("random.bytes", json!({ "length": length })).ok()?;
    host_random(&value, length)
}

/// 宿主回包形态没有契约文档，所以三种常见形态都认：数组、`{bytes|data}` 下的
/// base64、`{hex}` 下的十六进制。
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
    value["hex"]
        .as_str()
        .and_then(hex_decode)
        .filter(|bytes| bytes.len() >= length)
        .map(|bytes| bytes[..length].to_vec())
}

fn fallback_random(length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(length + 32);
    let mut round = 0u64;
    while out.len() < length {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!("officeace:{}:{}:{}", now_ms(), counter, round);
        out.extend_from_slice(&Sha256::digest(seed.as_bytes()));
        round = round.saturating_add(1);
    }
    out.truncate(length);
    out
}

/// `count` 字节随机数的十六进制串（`Chat-Id` / `Session-Id` 的形态）。
pub fn random_hex(count: usize) -> String {
    hex_lower(&random_bytes(count))
}

// ── URL 编码 ─────────────────────────────────────────────────

/// `encodeURIComponent` 口径的百分号编码（PKCE challenge、OAuth 表单与授权地址共用）。
///
/// 未保留集是 JS 的那一组：字母数字 + `- _ . ~`。**这与签名层的未保留集不是同一套**
/// （签名那份把 `! ' ( ) *` 也转义，见 `signer::encode_component`）—— 两处服务于
/// 不同协议，别合并。
pub fn url_escape(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

// ── 账号 id 派生 ─────────────────────────────────────────────

/// FNV-1a 64 位（`&str` → 16 位 hex，取前 12 位）。与内置版逐字一致。
///
/// ── 为什么必须逐字一致 ──────────────────────────────────────
/// 这个 hash 是**落盘契约**的一部分：内置版时代落库的账号 id 就是
/// `officeace-<hash>`。换一套派生规则，升级后重新导入同一套凭据会多出一条重复账号，
/// 而老账号还占着队列位置。
pub fn short_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}").chars().take(12).collect()
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
        assert_eq!(base64url_decode("eyJhIjoxfQ"), Some(b"{\"a\":1}".to_vec()));
    }

    #[test]
    fn base64url_has_no_padding() {
        // RFC 7515 附录 C 的第一个例子的编解码形态
        assert_eq!(base64url_encode(b"{\"a\":1}"), "eyJhIjoxfQ");
        // 0xff 0x00 → 6+6+4 位：63='_'、48='w'、补零='A'
        assert_eq!(base64url_encode(&[0xff, 0x00]), "_wA");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_lower(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(hex_decode("00ff1a"), Some(vec![0x00, 0xff, 0x1a]));
        assert_eq!(hex_decode("0"), None, "奇数长度不是合法十六进制");
    }

    #[test]
    fn short_hash_matches_fnv1a() {
        // FNV-1a 64 位的公开测试向量："" → cbf29ce484222325（取前 12 位）
        assert_eq!(short_hash(""), "cbf29ce48422");
        // "a" → af63dc4c8601ec8c
        assert_eq!(short_hash("a"), "af63dc4c8601");
    }

    #[test]
    fn url_escape_matches_encode_uri_component() {
        assert_eq!("a-b_c.d~e", url_escape("a-b_c.d~e"));
        assert_eq!("%20", url_escape(" "));
        assert_eq!("%2F", url_escape("/"));
        // `!'()*` 在 encodeURIComponent 里也转义（与签名层那套相反）
        assert_eq!("%21%27%28%29%2A", url_escape("!'()*"));
    }

    #[test]
    fn rfc3339_and_beijing_day() {
        assert_eq!(parse_rfc3339_ms("2026-10-10T05:15:00Z"), Some(1_791_609_300_000));
        // 北京时间比 UTC 早 8 小时：UTC 16:30 已经是次日 00:30
        assert_eq!(date_key_of_ms(1_791_609_300_000).as_deref(), Some("2026-10-10"));
        assert_eq!(date_key_of_ms(1_791_609_300_000 + 19 * 3600 * 1000).as_deref(), Some("2026-10-11"));
        assert_eq!(parse_rfc3339_ms("不是时间"), None);
    }
}
