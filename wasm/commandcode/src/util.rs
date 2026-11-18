//! 小工具：JSON 取值口径、头集合、时间与随机源。
//!
//! ── 为什么要有单独一层取值函数 ────────────────────────────────
//! native 的 `plan.rs` 用的是网关 `protocol::{is_truthy, string_value}`，
//! 那两个函数的语义（`null` 是假、数字 0 是假、空串是假、数组/对象恒真；
//! 非字符串一律 `to_string()`）直接决定了信封里哪些字段会被写进去。wasm 侧
//! 看不到网关模块，因此在这里按**逐字同口径**重建一份 —— 口径一旦分叉，
//! `params` 的形状就会跟着变。
//!
//! ── 随机源与时间 ──────────────────────────────────────────────
//! wasm 沙箱里没有 `std::time::SystemTime`（读它会 panic）、也没有
//! `getrandom`。时间一律走宿主 `clock.now`（毫秒），随机一律走宿主
//! `random.bytes`（返回 base64，见 `plugin_host/wasm/services.rs`）——
//! 后者失败时回落到「时间戳 + 进程内计数」，与 native 的
//! `random_hex`（系统随机源不可用时回落时间戳）同一处置：
//! 它只是 `traceparent` / `sess_…` 这类追踪串，不是凭证。
//!
//! ── 硬约束 ────────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};
use sha2::{Digest, Sha256};

/// 一个值是否「真」（与网关 `protocol::is_truthy` 逐字同口径）
pub fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|item| item != 0.0).unwrap_or(false),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// 转成字符串（与网关 `protocol::string_value` 逐字同口径：非字符串走 JSON 文本）
pub fn string_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// 读一个字符串字段并去首尾空白（缺失 / 非字符串给空串）
pub fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

/// 按候选键读第一个非空字符串（记录可能被手工编辑过，宽容读取）
pub fn pick(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        let found = text(value, key);
        if !found.is_empty() {
            return found;
        }
    }
    String::new()
}

/// 按候选键读第一个整数（缺失 / 非数字给 0；浮点按截断处理）
pub fn number_of(value: &Value, keys: &[&str]) -> i64 {
    for key in keys {
        if let Some(number) = value.get(*key).and_then(Value::as_i64) {
            return number;
        }
        if let Some(number) = value
            .get(*key)
            .and_then(Value::as_f64)
            .filter(|number| number.is_finite())
        {
            return number as i64;
        }
    }
    0
}

/// 宿主时钟（毫秒）。宿主的 `clock.now` 就是网关的 `now_ms()`
pub fn now_ms() -> i64 {
    sdk::now()
}

/// 头集合（有序 `Vec`）→ 宿主 `http.open` 要的 JSON 对象。
///
/// 同名头后者覆盖前者 —— 与 native 组 `HeaderMap` 时的 insert 语义一致。
/// 键统一小写：协议里约定头名小写（与 HTTP/2 一致），两边各写一套大小写规则
/// 的下场是「插件收不到某个头」而没有任何报错。
pub fn headers_value(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.to_ascii_lowercase(), json!(value));
    }
    Value::Object(object)
}

/// 从响应头 / 客户端头对象里取一个头（大小写不敏感）
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

/// 进程内单调计数（同一毫秒内的两次调用要拿到不同的派生输入）
fn next_sequence() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// 宿主随机源给出的 base64 文本（失败时回落到时间戳 + 计数）
///
/// 之所以把随机字节再过一道 SHA-256 而不是手写 base64 解码：本包要的是
/// **hex 形态的随机串**（`traceparent` 与 `sess_…`），而 SHA-256 正好把
/// 「任意熵 → 固定长度 hex」，且 `sha2` 已在依赖白名单里。
fn random_seed(bytes: usize) -> String {
    let length = bytes.clamp(1, 64);
    sdk::host("random.bytes", json!({ "length": length }))
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| format!("{}:{}", now_ms(), next_sequence()))
}

/// `bytes` 字节的随机 hex（最长 32 字节：SHA-256 的输出上限）
pub fn random_hex(bytes: usize) -> String {
    let seed = random_seed(bytes);
    let digest = Sha256::digest(format!("commandcode-trace\0{seed}").as_bytes());
    let take = bytes.clamp(1, digest.len());
    let mut out = String::with_capacity(take * 2);
    for byte in &digest[..take] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthiness_matches_gateway_rules() {
        assert!(!is_truthy(&Value::Null));
        assert!(!is_truthy(&json!(false)));
        assert!(!is_truthy(&json!(0)));
        assert!(!is_truthy(&json!("")));
        assert!(is_truthy(&json!(0.5)));
        assert!(is_truthy(&json!([])));
        assert!(is_truthy(&json!({})));
    }

    #[test]
    fn headers_are_lowercased_and_override_in_order() {
        let value = headers_value(&[
            ("User-Agent".to_string(), "cli".to_string()),
            ("x-cmd-zdr".to_string(), "1".to_string()),
            ("user-agent".to_string(), "cli-2".to_string()),
        ]);
        assert_eq!(value["user-agent"], json!("cli-2"));
        assert_eq!(header_of(&value, "X-Cmd-ZDR"), "1");
        assert_eq!(header_of(&value, "missing"), "");
    }

    #[test]
    fn numbers_accept_integers_and_floats() {
        let value = json!({ "a": 12, "b": 3.9, "c": "7" });
        assert_eq!(number_of(&value, &["a"]), 12);
        assert_eq!(number_of(&value, &["b"]), 3);
        assert_eq!(number_of(&value, &["c", "a"]), 12);
        assert_eq!(number_of(&value, &["missing"]), 0);
    }
}
