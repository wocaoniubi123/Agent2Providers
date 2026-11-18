//! 全插件共用的小工具（native `crates/providers/src/json.rs`、`ids.rs`、
//! `credentials::new_uuid`、`claim::urlencode` 的等价物）。
//!
//! ── 为什么集中在一个文件 ────────────────────────────────────
//! 取值口径（「JS 的 `String(x)` 语义」「真值判定」「内容块拍平」）在 native
//! 侧散在四个模块里，但它们是同一套约定的不同投影。插件只有一份，放一起才能
//! 保证两个方向（请求转换 / 响应折叠）读到的是同一条规则 —— 分开放迟早出现
//! 「转换层认这种形状、折叠层认另一种」。
//!
//! ── 随机源为什么是「宿主随机 + 摘要派生」─────────────────────
//! native 用 `getrandom` 直接取 16 / 32 字节。Wasm 插件没有系统调用，随机数
//! 只能问宿主（`random.bytes`，返回 base64）。这里不手写 base64 解码器：把
//! 宿主给的 base64 文本过一遍 SHA-256，取前 N 字节即为定长随机字节 —— 摘要
//! 不减少熵（输入本身已是密码学随机），而 `sha2` 本来就在依赖里（硬约束允许
//! 的三件依赖之一）。取不到随机源时**如实返回 None**，调用方按 native 的兜底
//! 分支处理（宁可少一个追踪头，也不编一个可预测的「随机」值）。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use sha2::{Digest, Sha256};

/// 北京时间在 UTC 之上的秒偏移（native `crate::beijing::OFFSET_SECONDS`）。
///
/// 上游的活动窗口（每天 19:00 起可领）与界面上的时间列都按北京时间读 ——
/// 这一家是国内 / 国际共用一套活动运营时间，不是按用户本机时区。
pub const BEIJING_OFFSET_SECONDS: i64 = 8 * 3600;

/// 当前时刻（Unix 毫秒）。宿主时钟。
pub fn now_ms() -> i64 {
    sdk::now()
}

/// JS 的 `String(value)`：非字符串也照转（`null` → 空串）。
pub fn string_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// 取一个对象成员并转成字符串（缺失 → 空串）。
pub fn string_field(value: &Value, key: &str) -> String {
    value.get(key).map(string_value).unwrap_or_default()
}

/// 按候选键取第一个非空字符串（已 trim）。
pub fn text_of(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
        })
        .unwrap_or("")
        .to_string()
}

/// 数字取值：数字原样，数字形态的字符串也认（`integer` 的宽松版）。
pub fn number_of(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number
            .as_f64()
            .filter(|number| number.is_finite()),
        Value::String(text) => text.trim().parse::<f64>().ok().filter(|number| number.is_finite()),
        _ => None,
    }
}

/// 整数取值：数字与数字字符串两种写法都认（native `claim::plans::integer`）。
pub fn integer_of(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// JS 真值判定（`Boolean(x)`）。
pub fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|item| item != 0.0).unwrap_or(false),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// JS 的 `jsonText(value)`：字符串原样返回，其余 JSON 序列化。
pub fn json_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// 内容块数组（非数组时给空切片）。
pub fn content_parts(content: &Value) -> &[Value] {
    content.as_array().map(Vec::as_slice).unwrap_or(&[])
}

/// 从内容块数组里抽出纯文本（只认 text 类块）。
pub fn content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                if let Some(text) = part.as_str() {
                    out.push_str(text);
                    continue;
                }
                let kind = string_field(part, "type").to_lowercase();
                if matches!(kind.as_str(), "text" | "input_text" | "output_text") {
                    out.push_str(&string_field(part, "text"));
                }
            }
            out
        }
        _ => String::new(),
    }
}

/// 把工具参数（字符串或对象）解析成对象。
///
/// 上游对非对象的 `input` 会直接 400，所以解析不了时包一层保证是对象
/// （native `anthropic_shared::parse_json_object` 的兜底分支 `{"value": …}`）。
pub fn parse_json_object(value: &Value) -> Value {
    if value.is_object() {
        return value.clone();
    }
    let text = json_text(value);
    if text.is_empty() {
        return json!({});
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(parsed) if parsed.is_object() => parsed,
        _ => json!({ "value": value.clone() }),
    }
}

/// 查询值的百分号编码（RFC 3986 unreserved 之外一律转义）。
///
/// native `claim::urlencode` 逐字移植：版本号与平台标识理论上都是 ASCII，
/// 但 `appVersion` 是用户可覆盖的设置项，一个带 `&` 的值就能拼出畸形 URL。
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 路径段编码（native `coding_key::encode_path_segment`）。
pub fn path_encode(value: &str) -> String {
    urlencode(value)
}

/// 向宿主取随机字节（长度 1..=256）。
///
/// 返回 `None` = 宿主随机源不可用（能力未授予或调用失败）—— 调用方必须处理
/// 这个分支，不能拿一个常量顶替。
fn host_random(count: usize) -> Option<Vec<u8>> {
    if count == 0 || count > 256 {
        return None;
    }
    let value = sdk::host("random.bytes", json!({ "length": count })).ok()?;
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    // 摘要派生（见模块头）：取前 `count` 字节即可，熵来自宿主随机源。
    let digest = Sha256::digest(text.as_bytes());
    Some(digest.iter().copied().take(count).collect())
}

/// 32 随机字节的十六进制串（native `oauth::random_hex_32`，登录流程的 poll token）。
pub fn random_hex_32() -> Option<String> {
    let bytes = host_random(32)?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// 生成一个 UUID v4 形态的随机串（native `credentials::new_uuid`）。
///
/// 用途有两处：设备标识（`X-Device-Mid`，**长期稳定**，生成一次落盘）与每条
/// 请求的追踪头（`x-request-id` / `x-zcode-trace-id`，**每条都不同**）。
/// 上游把设备标识当 UUID 解析，非 UUID 形态与缺失同效（都是 biz 3001）。
pub fn new_uuid() -> Option<String> {
    let mut bytes = host_random(16)?;
    // 版本位（v4）与变体位（RFC 4122）
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

/// 毫秒时间戳 → 北京时间（`chrono` 只带 `std` 特性，不带 `clock`：
/// 时间一律由宿主 `clock.now` 提供，绝不用本机时钟）。
pub fn beijing_datetime(ms: i64) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    use chrono::TimeZone;
    let zone = chrono::FixedOffset::east_opt(BEIJING_OFFSET_SECONDS as i32)?;
    zone.timestamp_millis_opt(ms).single()
}

/// 毫秒时间戳 → 北京时间 `MM-DD HH:MM`（界面上的重置 / 到期时刻）。
pub fn beijing_mmdd_hhmm(ms: i64) -> Option<String> {
    beijing_datetime(ms).map(|at| at.format("%m-%d %H:%M").to_string())
}

/// 毫秒时间戳 → 北京时间 `YYYY-MM-DD`（系统提示词里的「今天是哪天」）。
pub fn beijing_date(ms: i64) -> Option<String> {
    beijing_datetime(ms).map(|at| at.format("%Y-%m-%d").to_string())
}

/// 令牌尾巴（账号页显示用，native `store::token_tail` 的等价物）。
pub fn token_tail(value: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        return String::new();
    }
    text.chars().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect()
}

/// 从 tokens 里按候选键取第一个非空串（`secret` 的读写共用一处口径）。
pub fn secret_text(secret: &Value, keys: &[&str]) -> String {
    text_of(secret, keys)
}

/// 把 `(name, value)` 对折成 HTTP 头对象（`sdk::http::open` 要 Value）。
pub fn headers_object(pairs: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in pairs {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}

/// base64url 解码（JWT 的 payload 段用；`-`/`_` 字母表，允许缺 padding）。
///
/// 硬约束只允许 `serde_json` / `sha2` / `chrono`，没有 base64 crate，所以这里
/// 手写一个最小实现。它只服务两件事：读账号页的**展示用**过期时间戳、以及
/// 自测；解码失败一律 None（不 panic）。已知向量见 `anthropic.rs` 的测试。
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    fn value_of(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            // JWT 用 base64url；标准 base64 的两个字符一并接受（上游偶尔混用）
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        let value = value_of(*byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}
