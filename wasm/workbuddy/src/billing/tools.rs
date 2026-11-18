//! JS 语义工具（`Number()` / `parseTime` / `String(Math.floor(n))` 的等价物）。
//!
//! 从网关 `billing::request` 的工具段原样搬来 —— 这些函数服务的正是「把上游那套
//! JS 写法的计费响应翻译成前端契约」这件事，两处各写一份必然在时区、假值、`0`
//! 与 `null` 的边界上分叉。
//!
//! ── 时区语义必须逐字对齐（实测踩过）────────────────────────
//! JS 的 `new Date(str)` 对**无时区**的格式分两类：
//!   `"2026-09-30"`（仅日期）      → **UTC** 零点（ECMAScript 规范规定）
//!   `"2026-09-30 23:59:59"`       → **本地时区**（实现相关的宽松解析）
//! 上游的 `CycleEndTime` / `CycleStartTime` 正是 `"YYYY-MM-DD HH:MM:SS"` 形态，
//! 按 UTC 解析会让 `refreshAt` 整体偏 8 小时。
//!
//! ── wasm 侧的一处差异（有意）────────────────────────────────
//! native 用 `chrono::Local`（宿主机时区）。wasm 里没有 `Local`（本包只开
//! `chrono` 的 `std`），而且本家全部时间口径都是「北京时间」—— 这里固定用
//! UTC+8。对国内版账号这与宿主机在中国大陆的情形逐字相同；对其它时区的部署，
//! 它比「跟着宿主机漂」更接近上游的真实语义。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::Value;

/// JS `toInt(value)`：`Math.floor(Number(value))`，NaN → None
pub fn to_int(value: &Value) -> Option<i64> {
    let number = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        _ => None,
    };
    match number {
        Some(number) if number.is_finite() => Some(number.floor() as i64),
        _ => None,
    }
}

/// `parseTime(x) || null` 的等价物：解析不出（得到 0）时给 None。
///
/// 单独一个函数是因为 Node 里这两种写法混用：`parseTime(x) || parseTime(y)`
/// 会跳过第一个解不出的，而 `parseTime(x) || 0` 会退化成 0。
pub fn time_or_null(value: Option<&Value>) -> Option<i64> {
    let text = match value {
        None | Some(Value::Null) => return None,
        Some(Value::Number(number)) => {
            let parsed = number.as_f64()? as i64;
            return if parsed == 0 { None } else { Some(parsed) };
        }
        Some(Value::String(text)) => text.trim().to_string(),
        Some(_) => return None,
    };
    if text.is_empty() {
        return None;
    }
    // `/^\d+$/` 的等价判断：全数字按时间戳读
    let parsed = if text.chars().all(|ch| ch.is_ascii_digit()) {
        text.parse::<i64>().ok()
    } else {
        parse_date_text(&text)
    };
    // 0 是「解不出」的哨兵值（与 parseTime 返回 0 等价）
    parsed.filter(|value| *value != 0)
}

/// 日期文本 → 毫秒时间戳，时区语义与 JS 的 `new Date(str)` 对齐（见模块头）。
fn parse_date_text(text: &str) -> Option<i64> {
    use chrono::TimeZone;

    // 带时区偏移：交给 chrono 直接按绝对时间解析（与 JS 一致）
    if let Ok(value) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(value.timestamp_millis());
    }
    // 仅日期：JS 规范规定按 **UTC** 解读（不是本地！）
    if let Ok(date) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return date
            .and_hms_opt(0, 0, 0)
            .map(|value| value.and_utc().timestamp_millis());
    }
    // 无时区的日期时间：按 UTC+8 解读（"YYYY-MM-DD HH:MM:SS" 与 ISO 的 T 形态）
    let naive = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S"))
        .ok()?;
    chrono::FixedOffset::east_opt((crate::util::OFFSET_MS / 1000) as i32)
        .and_then(|zone| zone.from_local_datetime(&naive).single())
        .map(|value| value.timestamp_millis())
        .or_else(|| Some(naive.and_utc().timestamp_millis()))
}

/// JS `String(Math.floor(n))` 的近似：整数输出整数形态，浮点保留到不是整数为止。
pub fn js_int_string(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_string();
    }
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        let text = format!("{value}");
        text.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn date_only_is_utc_and_datetime_is_utc8() {
        // 仅日期：UTC 零点
        assert_eq!(parse_date_text("2026-09-30"), Some(1_790_726_400_000));
        // 无时区日期时间：UTC+8（2026-09-30 23:59:59 +08:00）
        assert_eq!(parse_date_text("2026-09-30 23:59:59"), Some(1_790_783_999_000));
    }

    #[test]
    fn numeric_strings_are_timestamps() {
        assert_eq!(time_or_null(Some(&json!("1789213426000"))), Some(1_789_213_426_000));
        // 0 / 空串 / null 都是「没给」
        assert_eq!(time_or_null(Some(&json!(0))), None);
        assert_eq!(time_or_null(Some(&json!(""))), None);
        assert_eq!(time_or_null(Some(&Value::Null)), None);
        assert_eq!(time_or_null(None), None);
    }

    #[test]
    fn to_int_floors_like_js() {
        assert_eq!(to_int(&json!(3.9)), Some(3));
        assert_eq!(to_int(&json!("12")), Some(12));
        assert_eq!(to_int(&json!(true)), Some(1));
        assert_eq!(to_int(&json!({})), None);
    }

    #[test]
    fn numbers_degrade_to_zero_instead_of_panicking() {
        assert_eq!(js_int_string(1024.0), "1024");
        assert_eq!(js_int_string(f64::NAN), "0");
        assert_eq!(to_int(&json!("abc")), None);
    }
}
