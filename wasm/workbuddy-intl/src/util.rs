//! 插件内的通用小工具。
//!
//! ── 为什么有这个文件 ────────────────────────────────────────
//! native 侧这些函数分散在 `ids` / `json` / `beijing` / `crypto` / `store` 几个
//! 公共模块里（那是整个 providers crate 共用的）。wasm 包只能依赖
//! `agent2api-wasm-sdk` + `serde_json` + `sha2` + `chrono`，所以把**本家真正
//! 用到的**那几个搬进来，语义逐条对齐原实现 —— 迁移里最怕的是「取值链悄悄
//! 换了口径」，那会让同一份上游响应在两边解释出不同的账号身份或余额。
//!
//! ── 缺什么就自己写什么 ──────────────────────────────────────
//! 缺 `uuid`（native 用 getrandom 拼 uuidv7）：wasm 里没有熵源，这里用
//! `sha256(时间戳 | 计数 | 标签)` 派生，形态（版本位 / 变体位 / 分组）与 native
//! 逐字相同 —— 上游按**形态**认这几个头，不看随机性。
//! 缺 `base64`：JWT 的 payload 解不开就没法做「续期后重新核对身份」，所以手写
//! 一份 url-safe base64 解码（附已知向量测试）。
//! 缺 `url`：只需要「同源判定 / 取 authority / 拆查询串」三件事，手写比引一个
//! crate 更可控。
//!
//! ── 时间为什么不算时区 ──────────────────────────────────────
//! native 的 `beijing` 模块用 chrono 取「北京时间今天」。chrono 的 `Local`
//! 需要 `clock` feature（本包按样板只开 `std`），而「UTC+8 自然日」这件事本身
//! 只是整数除法 —— 直接按毫秒算，既没有 Option 兜底链，也不依赖宿主机 tzdata。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic（release 的 `panic=abort` 会整包带走）。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 当前毫秒时间戳（宿主时钟）。
pub fn now_ms() -> i64 {
    sdk::now()
}

// ─── 北京时间 ───────────────────────────────────────────────

/// UTC+8 的固定偏移（毫秒）。中国标准时间没有夏令时，固定偏移就够用。
pub const OFFSET_MS: i64 = 8 * 3600 * 1000;

/// 一天（毫秒）。
pub const DAY_MS: i64 = 86_400_000;

/// 毫秒时间戳 → 北京时间的 (年, 月, 日, 时, 分, 秒)。
///
/// 纯整数运算（Howard Hinnant 的 civil_from_days）：1970-01-01 起的天数换成
/// 公历年月日，与时区库无关，也不会因为时间戳越界 panic。
pub fn beijing_parts(ms: i64) -> (i64, i64, i64, i64, i64, i64) {
    let shifted = ms.saturating_add(OFFSET_MS);
    let days = shifted.div_euclid(DAY_MS);
    let millis_of_day = shifted.rem_euclid(DAY_MS);
    let seconds = millis_of_day / 1000;
    // civil_from_days：把「1970-01-01 起的天数」换算成公历年月日
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, seconds / 3600, (seconds % 3600) / 60, seconds % 60)
}

/// 北京时间的日期键 `YYYY-MM-DD`（定长，字典序即时间序）。
pub fn date_key_of_ms(ms: i64) -> String {
    let (year, month, day, _, _, _) = beijing_parts(ms);
    format!("{year:04}-{month:02}-{day:02}")
}

/// 北京时间的今天（`YYYY-MM-DD`）—— 「今天」的唯一口径（上游按 UTC+8 切自然日）。
pub fn today_key() -> String {
    date_key_of_ms(now_ms())
}

/// 北京时间的昨天（`YYYY-MM-DD`）。
pub fn yesterday_key() -> String {
    date_key_of_ms(now_ms().saturating_sub(DAY_MS))
}

/// 北京时间的小时（0-23，夜猫窗口判定用）。
pub fn beijing_hour() -> i64 {
    beijing_parts(now_ms()).3
}

/// 北京时间「今天 00:00:00」的毫秒时间戳。
pub fn beijing_day_start(ms: i64) -> i64 {
    ms.saturating_add(OFFSET_MS).div_euclid(DAY_MS).saturating_mul(DAY_MS).saturating_sub(OFFSET_MS)
}

// ─── JSON 取值 ─────────────────────────────────────────────

/// JS 的 `String(value)`：非字符串也照转（`null` → 空串）。
pub fn string_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// JS 真值判定（`Boolean(x)`）：null/false/0/"" 为假，空数组/空对象为真。
pub fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|item| item != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// 从 secret / record 里取第一个非空字符串（多候选键，宽容读取）。
pub fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 令牌尾 4 字符（公开视图的展示字段，让用户认出「这是哪把 token」）。
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 按**字符**截断（不是字节）。
///
/// native 用 `json::truncate_text`：按字节切会切在半个汉字上（乱码），而且
/// `&s[..n]` 落在非字符边界上会 panic —— release 是 `panic=abort`。
pub fn truncate_text(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// `f64` → JSON 数字（整数走 i64，非有限值给 Null）。
///
/// 与 native `json::json_number` 同口径：直接 `json!(f64)` 会让界面看到
/// `1780000000000.0`，而整数形态才是那边一直在读的形状。
pub fn json_number(value: f64) -> Value {
    if !value.is_finite() {
        return Value::Null;
    }
    if value.fract() == 0.0 && value.abs() < i64::MAX as f64 {
        return Value::from(value as i64);
    }
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// 取候选键里第一个非空字符串（去空白）。
pub fn text_at(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    String::new()
}

/// 头集合（有序 `Vec`）→ 宿主 `http.open` 要的 JSON 对象。
///
/// 同名头后者覆盖前者 —— 与 native `send_raw` 收到 `Vec<(String,String)>` 时
/// 组 `HeaderMap` 的语义一致（insert 覆盖）。
pub fn headers_value(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.to_ascii_lowercase(), json!(value));
    }
    Value::Object(object)
}

/// 从响应头对象里取一个头（大小写不敏感；宿主给的是小写键，这里再兜一次底）。
pub fn header_of(headers: &Value, name: &str) -> String {
    if let Some(value) = headers.get(name).and_then(Value::as_str) {
        return value.to_string();
    }
    let wanted = name.to_ascii_lowercase();
    for (key, value) in headers.as_object().into_iter().flatten() {
        if key.to_ascii_lowercase() == wanted {
            return value.as_str().unwrap_or("").to_string();
        }
    }
    String::new()
}

// ─── 标识生成（uuidv7 家族，与 native `ids` 同形态）────────────

/// 进程内单调计数：保证同一毫秒内生成的两个 id 不撞。
fn next_sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// 16 字节的「uuidv7 形态」：毫秒时间前缀 + 版本位 7 + 变体位 10 + 哈希尾。
///
/// native 用 getrandom 取尾段；wasm 没有熵源，这里改用
/// `sha256(标签 | 时间戳 | 计数)` 派生。**上游按形态认头**（32 位 hex、带连字符
/// 的 UUID），不校验随机性，所以这条替代在同形态下等价。
fn uuid7_bytes(label: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let millis = now_ms().max(0) as u64 & ((1 << 48) - 1);
    let mut hasher = Sha256::new();
    hasher.update(b"workbuddy-uuid7");
    hasher.update(label.as_bytes());
    hasher.update(millis.to_be_bytes());
    hasher.update(next_sequence().to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // 高 48 位写毫秒时间前缀（v7 的可排序性），随后写版本位与变体位
    let prefix = millis.to_be_bytes();
    bytes[0] = prefix[2];
    bytes[1] = prefix[3];
    bytes[2] = prefix[4];
    bytes[3] = prefix[5];
    bytes[4] = prefix[6];
    bytes[5] = prefix[7];
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 请求 / 消息 id（`X-Request-ID` 那四个头）：32 位无连字符 hex。
pub fn new_message_id() -> String {
    hex(&uuid7_bytes("message"))
}

/// 会话 id（`X-Conversation-ID`）：带连字符的 UUID 形态。
pub fn new_conversation_id() -> String {
    let bytes = uuid7_bytes("conversation");
    let text = hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        text.get(0..8).unwrap_or(""),
        text.get(8..12).unwrap_or(""),
        text.get(12..16).unwrap_or(""),
        text.get(16..20).unwrap_or(""),
        text.get(20..32).unwrap_or("")
    )
}

/// 链路追踪的 span id（`traceparent` / b3 / `X-B3-SpanId`）：16 位 hex。
pub fn new_span_id() -> String {
    hex(&uuid7_bytes("span")[..8])
}

/// UUID v4 形态的一次性令牌（`client_token` / `draw_uuid` 用）。
///
/// native 用 getrandom；wasm 没有熵源，用「时间戳 + 计数」哈希派生。
/// 语义要求只是「同一次点击只兑一次 / 每抽一个新值」，不参与任何校验。
pub fn uuid_v4() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"workbuddy-token");
    hasher.update(now_ms().to_be_bytes());
    hasher.update(next_sequence().to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let text = hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        text.get(0..8).unwrap_or(""),
        text.get(8..12).unwrap_or(""),
        text.get(12..16).unwrap_or(""),
        text.get(16..20).unwrap_or(""),
        text.get(20..32).unwrap_or("")
    )
}

/// 由 uid + 盐稳定派生一个 32 位 hex 设备标识（幂等）。
///
/// native 用 md5（`growth::GrowthAccount::derive_id`）；这里没有 md5 依赖，
/// 改用 sha256 取前 16 字节 —— 用途只是「模拟同一台固定设备」的事件指纹，
/// 不参与业务逻辑，两个实现给出的都是稳定的 32 位 hex。
pub fn derive_id(salt: &str, uid: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{salt}:{uid}").as_bytes());
    hex(&hasher.finalize()[..16])
}

// ─── URL 工具（不引入 `url` crate）────────────────────────────

/// 百分号编码的**查询串**分量。
///
/// 与 native `login::encode` 同一套字符集（RFC 3986 unreserved + 若干子分隔符）：
/// 上游的 state 是 base64url 串，多编码或少编码一个字符都会让登录轮询永远
/// 停在 11217（「token 未就绪」）。
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')')
        {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `scheme://host[:port]`（小写 scheme/host）。解析不出返回 None。
///
/// 手写而不是 `url::Url`：本包不引 `url`，而这里只需要「同源判定」这一件事。
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// 端点 authority（`host` 或 `host:port`），解析不出给空串。
pub fn authority_of(url: &str) -> String {
    origin_of(url)
        .and_then(|origin| origin.split_once("://").map(|(_, rest)| rest.to_string()))
        .unwrap_or_default()
}

/// 拆 `scheme://authority/path?query#fragment` → (scheme, authority, path, query, fragment)。
pub fn split_url(url: &str) -> Option<(String, String, String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let (rest, fragment) = match rest.split_once('#') {
        Some((head, tail)) => (head, tail.to_string()),
        None => (rest, String::new()),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((head, tail)) => (head, tail.to_string()),
        None => (rest, String::new()),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((head, tail)) => (head.to_string(), format!("/{tail}")),
        None => (rest.to_string(), String::new()),
    };
    Some((scheme.to_ascii_lowercase(), authority.to_ascii_lowercase(), path, query, fragment))
}

/// 取查询串里的全部同名参数值（按出现顺序）。
pub fn query_values(query: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        if decode_component(key) == name {
            out.push(decode_component(value));
        }
    }
    out
}

/// 百分号解码（`+` 按空格处理，与 `application/x-www-form-urlencoded` 一致）。
fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => out.push((high * 16 + low) as u8),
                    _ => out.push(bytes[index]),
                }
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ─── JWT ───────────────────────────────────────────────────

/// url-safe base64 解码（`-_` 视作 `+/`，容忍缺省填充）。
///
/// 手写：本包不能引 `base64`。JWT 的 payload 段恒为 url-safe 变体。
fn base64_url_decode(text: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out: Vec<u8> = Vec::with_capacity(text.len() * 3 / 4 + 3);
    for ch in text.chars() {
        let value = match ch {
            '=' => break,
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// 去 `Bearer ` 前缀（大小写不敏感，循环剥离 —— 实测导入的 token 偶发双前缀）。
pub fn strip_bearer(token: &str) -> String {
    let mut text = token.trim();
    loop {
        let lower = text.to_ascii_lowercase();
        if !lower.starts_with("bearer") {
            break;
        }
        let rest = &text[6..];
        match rest.strip_prefix(' ').or_else(|| rest.strip_prefix('\t')) {
            Some(rest) => text = rest.trim_start(),
            None => break,
        }
    }
    text.to_string()
}

/// 解 JWT 的 payload 段（不验签 —— 网关不做鉴权判定，token 能不能用由上游说了算）。
pub fn decode_jwt_claims(token: &str) -> Option<Value> {
    let raw = strip_bearer(token);
    let payload = raw.split('.').nth(1)?;
    if payload.is_empty() {
        return None;
    }
    let bytes = base64_url_decode(payload)?;
    let text = String::from_utf8(bytes).ok()?;
    let claims = serde_json::from_str::<Value>(&text).ok()?;
    claims.is_object().then_some(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_url_decode_matches_known_vectors() {
        // "eyJzdWIiOiJ1LTEifQ" = {"sub":"u-1"}（url-safe 无填充）
        let bytes = base64_url_decode("eyJzdWIiOiJ1LTEifQ").unwrap_or_default();
        assert_eq!(String::from_utf8(bytes).unwrap_or_default(), r#"{"sub":"u-1"}"#);
        assert!(base64_url_decode("!!!").is_none());
    }

    #[test]
    fn decode_jwt_claims_reads_the_payload_segment() {
        let claims = decode_jwt_claims("h.eyJzdWIiOiJ1LTEifQ.s").unwrap_or(Value::Null);
        assert_eq!(claims["sub"], json!("u-1"));
        assert!(decode_jwt_claims("not-a-jwt").is_none());
        // 双 Bearer 前缀也要剥干净
        let claims = decode_jwt_claims("Bearer Bearer h.eyJzdWIiOiJ1LTEifQ.s").unwrap_or(Value::Null);
        assert_eq!(claims["sub"], json!("u-1"));
    }

    #[test]
    fn origin_and_authority_are_stable() {
        assert_eq!(
            origin_of("https://Www.WorkBuddy.cn/v2/x").as_deref(),
            Some("https://www.workbuddy.cn")
        );
        assert_eq!(authority_of("https://copilot.tencent.com/v2"), "copilot.tencent.com");
        assert_eq!(origin_of("workbuddy://experts"), None);
        assert_eq!(authority_of(""), "");
    }

    #[test]
    fn query_values_reads_repeated_keys() {
        assert_eq!(query_values("deeplink=a%3A1&x=2", "deeplink"), vec!["a:1".to_string()]);
        assert!(query_values("a=1", "deeplink").is_empty());
    }

    #[test]
    fn beijing_parts_matches_known_dates() {
        // 2026-11-19 02:57:24 +08:00
        assert_eq!(date_key_of_ms(1_763_496_000_000), "2025-11-19");
        // 1970-01-01 00:00:00 UTC == 08:00 北京时间
        assert_eq!(date_key_of_ms(0), "1970-01-01");
        assert_eq!(beijing_parts(0).3, 8);
        // 1999-12-31 23:30 UTC == 2000-01-01 07:30 北京时间
        assert_eq!(date_key_of_ms(946_683_000_000), "2000-01-01");
        assert_eq!(beijing_parts(946_683_000_000).3, 7);
    }

    #[test]
    fn uuid_shapes_match_upstream_expectations() {
        let message = new_message_id();
        assert_eq!(message.len(), 32);
        assert!(message.chars().all(|ch| ch.is_ascii_hexdigit()));
        let conversation = new_conversation_id();
        let parts: Vec<&str> = conversation.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[2].len(), 4);
        assert!(parts[2].starts_with('7'));
        assert_eq!(new_span_id().len(), 16);
        let token = uuid_v4();
        assert_eq!(token.len(), 36);
        assert!(token.split('-').nth(2).is_some_and(|part| part.starts_with('4')));
        assert_ne!(token, uuid_v4());
    }

    #[test]
    fn json_number_keeps_integer_shape() {
        assert_eq!(json_number(1_700_000_000_000.0), json!(1_700_000_000_000_i64));
        assert_eq!(json_number(f64::NAN), Value::Null);
    }

    #[test]
    fn truncate_text_counts_characters() {
        assert_eq!(truncate_text("腾讯每日签到", 2), "腾讯");
        assert_eq!(truncate_text("ab", 5), "ab");
    }
}
