//! OrcaTerm 余额：`DescribeUserBillingStatus` 的月度 AI 配额 → 统一 usage 形状。
//!
//! ── 上游形态（2026-10-16 实测）──────────────────────────────
//! ```jsonc
//! { "roleType": "basic", "usageStats": [
//!     { "feature": "hunyuan_ai", "quotaLimit": 1000, "quotaUsed": 0,
//!       "quotaStartDate": "…", "quotaEndDate": "2026-11-15T16:00:00.000Z" }, … ] }
//! ```
//! 配额按自然月重置；`hunyuan_ai` 就是 AI 助手的对话额度（基础版 1000/月、
//! 专业版 6000/月）。其余（session_share / secret / space）不是推理额度，
//! 不进 usage。
//!
//! ── 归一形状 ────────────────────────────────────────────────
//! `available` = limit - used、`unit` = "次"、`subscription` 带套餐档与
//! 重置时刻（`roleType` 映射展示名，其余原样透出 —— 套餐名以上游原文为准，
//! 不引入本地码表）。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, upstream};

/// AI 助手配额在 `usageStats[].feature` 里的取值。
const HUNYUAN_FEATURE: &str = "hunyuan_ai";

/// 查询某账号的 AI 配额。
pub fn query() -> Result<Value> {
    let record = account::record()?;
    let mut credentials = account::snapshot(&record)?;
    // 临期先续期：余额接口同样吃 Bearer 头，401 会把「没额度」误报成「登录失效」
    credentials = account::renew(&credentials, false)?;
    let response = upstream::cgi_action(&credentials, "DescribeUserBillingStatus", json!({}))?;
    if let Some(error) = response.get("Error") {
        let code = error["Code"].as_str().unwrap_or("UNKNOWN");
        let message = error["Message"].as_str().unwrap_or("上游错误");
        return Err(Error::http(
            502,
            format!("OrcaTerm 余额查询被上游拒绝（{code}：{message}）"),
        ));
    }
    report_of(&response)
}

/// 把上游响应归一成 usage 形状。
fn report_of(response: &Value) -> Result<Value> {
    let role_type = response["roleType"].as_str().unwrap_or("");
    let stats = response["usageStats"].as_array().cloned().unwrap_or_default();
    let ai = stats
        .iter()
        .find(|item| item["feature"].as_str() == Some(HUNYUAN_FEATURE))
        .ok_or_else(|| Error::http(502, "OrcaTerm 余额响应里没有 AI 助手配额项（hunyuan_ai）"))?;
    let limit = ai["quotaLimit"].as_i64().unwrap_or(0);
    let used = ai["quotaUsed"].as_i64().unwrap_or(0);
    let available = if limit > used { limit - used } else { 0 };
    let reset_at = iso_to_ms(ai["quotaEndDate"].as_str());
    let plan_name = match role_type {
        "basic" => "基础版",
        "professional" => "专业版",
        other => other,
    };
    Ok(json!({
        "available": available,
        "unit": "次",
        "availableView": if limit > 0 { format!("{available}/{limit} 次") } else { String::new() },
        "subscription": {
            "planName": plan_name,
            "status": "active",
            "expireAt": reset_at,
            "remainQuota": available,
            "totalQuota": limit,
        },
        "raw": response,
    }))
}

/// ISO-8601 时间串 → 毫秒时间戳（解析不出给 0）。
fn iso_to_ms(text: Option<&str>) -> i64 {
    text.and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .map(|value| value.timestamp_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "roleType": "basic",
            "usageStats": [
                { "feature": "session_share", "quotaLimit": 5, "quotaUsed": 5 },
                { "feature": "hunyuan_ai", "quotaLimit": 1000, "quotaUsed": 250,
                  "quotaEndDate": "2026-11-15T16:00:00.000Z" },
            ],
        })
    }

    #[test]
    fn reads_hunyuan_quota_only() {
        let report = report_of(&sample()).unwrap_or(Value::Null);
        assert_eq!(report["available"], json!(750));
        assert_eq!(report["unit"], json!("次"));
        assert_eq!(report["availableView"], json!("750/1000 次"));
        assert_eq!(report["subscription"]["planName"], json!("基础版"));
        assert_eq!(report["subscription"]["totalQuota"], json!(1000));
        assert_eq!(
            report["subscription"]["expireAt"],
            json!(1_794_758_400_000i64)
        );
    }

    #[test]
    fn used_beyond_limit_floors_at_zero() {
        let report = report_of(&json!({
            "roleType": "professional",
            "usageStats": [{ "feature": "hunyuan_ai", "quotaLimit": 10, "quotaUsed": 30 }],
        }))
        .unwrap_or(Value::Null);
        assert_eq!(report["available"], json!(0));
        assert_eq!(report["subscription"]["planName"], json!("专业版"));
        assert_eq!(report["subscription"]["expireAt"], json!(0));
    }

    #[test]
    fn missing_quota_is_an_error_not_a_zero_balance() {
        let error = report_of(&json!({ "usageStats": [] })).err();
        assert_eq!(error.and_then(|error| error.status), Some(502));
    }

    #[test]
    fn parses_rfc3339_with_millis() {
        assert_eq!(iso_to_ms(Some("1970-01-01T00:00:00.000Z")), 0);
        assert_eq!(iso_to_ms(Some("2026-11-15T16:00:00.000Z")), 1_794_758_400_000);
        assert_eq!(iso_to_ms(None), 0);
        assert_eq!(iso_to_ms(Some("不是时间")), 0);
    }
}
