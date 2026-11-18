//! Kiro 余额：`Get-Usage-Limits` 的月额度、免费试用与 bonus 积分。
//!
//! ── 两套调用路径 ────────────────────────────────────────────
//! ```text
//!   OAuth  GET  /Get-Usage-Limits?origin=KIRO_CLI&profileArn=…&resourceType=CREDIT
//!   API key POST /?origin=KIRO_CLI   X-Amz-Target: AmazonCodeWhispererService.GetUsageLimits
//! ```
//!
//! ── 窗口口径 ────────────────────────────────────────────────
//! `resetsAt` / `runsOutAt` 是**毫秒时间戳**；`used` 是百分比（0–100），
//! `amount` / `limit` 是原始积分，`display` 是给人看的一行。
//! bonus 与「月额度用完但 bonus 还有余量」标 `aside`：它们不重置、只做展示，
//! 不该让「本月已用完」被判成账号没额度。

use agent2api_wasm_sdk::{self as sdk, http, json, Result, Value};

use super::credentials::Credentials;
use super::endpoints;

fn number(value: Option<&Value>) -> f64 {
    value
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
        .filter(|number| number.is_finite())
        .unwrap_or(0.0)
}

fn seconds_to_ms(value: Option<&Value>) -> Option<i64> {
    let seconds = number(value);
    if seconds <= 0.0 {
        return None;
    }
    Some((seconds as i64).saturating_mul(1000))
}

/// 订阅名（`KIRO FREE` → `Kiro Free`）。
pub fn plan_name(title: &str) -> String {
    title
        .split_whitespace()
        .map(|word| {
            if word.eq_ignore_ascii_case("kiro") {
                "Kiro".to_string()
            } else {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn short(value: f64) -> String {
    if value.fract().abs() < 0.005 {
        return format!("{}", value.round() as i64);
    }
    let text = format!("{value:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn count(used: f64, limit: f64) -> String {
    format!("{} / {}", short(used), short(limit))
}

/// 一条额度窗口的明细行（界面 `credits[]` 契约：面额 / 已用 / 剩余）。
fn credit_row(name: &str, used: f64, limit: f64, remaining: f64, remaining_percent: f64) -> Value {
    json!({
        "name": name,
        "remain": remaining,
        "total": limit,
        "used": used,
        "unit": "credits",
        "remainingPercent": remaining_percent.clamp(0.0, 100.0),
    })
}

/// 把 `Get-Usage-Limits` 的返回折成网关的用量报告。
pub fn report(payload: &Value) -> Value {
    let now = sdk::now();
    let mut windows: Vec<Value> = Vec::new();
    let mut credits: Vec<Value> = Vec::new();
    for breakdown in payload
        .get("usageBreakdownList")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(trial) = breakdown.get("freeTrialInfo") {
            let active = trial
                .get("freeTrialStatus")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("ACTIVE"));
            let limit = number(trial.get("usageLimitWithPrecision"));
            if active && limit > 0.0 {
                let used = number(trial.get("currentUsageWithPrecision"));
                let used_percent = (100.0 * used / limit).clamp(0.0, 100.0);
                let mut window = json!({
                    "name": "Free trial",
                    "label": "Free trial",
                    "used": used_percent,
                    "remainingPercent": (100.0 - used_percent).clamp(0.0, 100.0),
                    "remaining": (limit - used).max(0.0),
                    "display": count(used, limit),
                    "amount": used,
                    "limit": limit,
                    "unit": "credits",
                });
                let expiry = seconds_to_ms(trial.get("freeTrialExpiry"));
                if let Some(at) = expiry {
                    window["resetsAt"] = json!(at);
                }
                let mut credit = credit_row("Free trial", used, limit, (limit - used).max(0.0), 100.0 - used_percent);
                if let Some(at) = expiry {
                    credit["expireAt"] = json!(at);
                }
                windows.push(window);
                credits.push(credit);
            }
        }
        let mut bonuses: Vec<Value> = Vec::new();
        for bonus in breakdown.get("bonuses").and_then(Value::as_array).into_iter().flatten() {
            let active = bonus
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("ACTIVE"));
            let limit = number(bonus.get("usageLimit"));
            let expires = seconds_to_ms(bonus.get("expiresAt"));
            if !active || limit <= 0.0 {
                continue;
            }
            if expires.is_some_and(|at| at <= now) {
                continue;
            }
            let used = number(bonus.get("currentUsage"));
            let left = (limit - used).max(0.0);
            let name = bonus
                .get("displayName")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("Bonus credits");
            let used_percent = (100.0 * used / limit).clamp(0.0, 100.0);
            let mut window = json!({
                "name": name,
                "label": name,
                "used": used_percent,
                "remainingPercent": (100.0 - used_percent).clamp(0.0, 100.0),
                "remaining": left,
                "display": count(used, limit),
                "amount": used,
                "limit": limit,
                "unit": "credits",
                "aside": true,
            });
            if let Some(at) = expires {
                if left > 0.0 {
                    window["runsOutAt"] = json!(at);
                    window["runsOut"] = json!(left);
                }
            }
            let mut credit = credit_row(name, used, limit, left, 100.0 - used_percent);
            if let Some(at) = expires {
                credit["expireAt"] = json!(at);
            }
            bonuses.push(window);
            credits.push(credit);
        }
        let used = number(breakdown.get("currentUsageWithPrecision"));
        let limit = number(breakdown.get("usageLimitWithPrecision"));
        if limit > 0.0 {
            let reset = seconds_to_ms(breakdown.get("nextDateReset"))
                .or_else(|| seconds_to_ms(payload.get("nextDateReset")));
            let carried = used >= limit
                && bonuses.iter().any(|bonus| {
                    let amount = number(bonus.get("amount"));
                    let limit = number(bonus.get("limit"));
                    amount < limit
                });
            let name = breakdown
                .get("displayNamePlural")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .or_else(|| breakdown.get("displayName").and_then(Value::as_str))
                .unwrap_or("Credits");
            let used_percent = (100.0 * used / limit).clamp(0.0, 100.0);
            let mut window = json!({
                "name": name,
                "label": name,
                "used": used_percent,
                "remainingPercent": (100.0 - used_percent).clamp(0.0, 100.0),
                "remaining": (limit - used).max(0.0),
                "display": count(used, limit),
                "amount": used,
                "limit": limit,
                "unit": "credits",
                "span": 30 * 24 * 3600,
            });
            if let Some(at) = reset {
                window["resetsAt"] = json!(at);
            }
            if carried {
                window["aside"] = json!(true);
            }
            let mut credit = credit_row(name, used, limit, (limit - used).max(0.0), 100.0 - used_percent);
            if let Some(at) = reset {
                credit["resetAt"] = json!(at);
                credit["rolling"] = json!(true);
            }
            windows.push(window);
            credits.push(credit);
        }
        windows.extend(bonuses);
    }
    let email = payload.pointer("/userInfo/email").and_then(Value::as_str).unwrap_or("");
    let title = payload
        .pointer("/subscriptionInfo/subscriptionTitle")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut report = json!({
        "provider": "kiro",
        "unit": "credits",
        "windows": windows,
        "credits": credits,
    });
    if !title.is_empty() {
        report["plan"] = json!(plan_name(title));
    }
    if !email.is_empty() {
        report["user"] = json!(email);
    }
    report
}

/// `usage.query`。
pub fn query() -> Result<Value> {
    let (_, credentials) = super::refresh::ensure(false)?;
    let payload = fetch(&credentials)?;
    Ok(report(&payload))
}

/// 调 `Get-Usage-Limits`（两套路径）。
pub fn fetch(credentials: &Credentials) -> Result<Value> {
    let region = credentials.region();
    if credentials.is_api_key() {
        let url = format!("{}/?origin=KIRO_CLI", endpoints::management(&region));
        let response = http::open(
            "POST",
            &url,
            json!({
                "accept": "application/json",
                "content-type": "application/x-amz-json-1.0",
                "x-amz-target": endpoints::TARGET_USAGE_LIMITS,
                "x-amzn-codewhisperer-optout": "false",
                "authorization": format!("Bearer {}", credentials.access),
                "tokentype": "API_KEY",
            }),
            Some(&json!({ "origin": "KIRO_CLI" })),
        )?;
        let status = response.status;
        let bytes = response.bytes(1024 * 1024)?;
        if !(200..300).contains(&status) {
            return Err(http_status("查询 Kiro 额度失败", status));
        }
        return serde_json::from_slice(&bytes)
            .map_err(|_| agent2api_wasm_sdk::Error::http(502, "Kiro 额度返回不是有效 JSON"));
    }
    let mut url = format!(
        "{}/Get-Usage-Limits?origin=KIRO_CLI&resourceType=CREDIT&isEmailRequired=true",
        endpoints::management(&region)
    );
    if !credentials.profile.is_empty() {
        url.push_str("&profileArn=");
        url.push_str(&profile_query(&credentials.profile));
    }
    let mut headers = json!({
        "accept": "application/json",
        "authorization": format!("Bearer {}", credentials.access),
    });
    if let Some(kind) = credentials.token_type() {
        headers["tokentype"] = json!(kind);
    }
    let response = http::open("GET", &url, headers, None)?;
    let status = response.status;
    let bytes = response.bytes(1024 * 1024)?;
    if !(200..300).contains(&status) {
        return Err(http_status("查询 Kiro 额度失败", status));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| agent2api_wasm_sdk::Error::http(502, "Kiro 额度返回不是有效 JSON"))
}

fn http_status(prefix: &str, status: u16) -> agent2api_wasm_sdk::Error {
    let code = if status == 401 || status == 403 { 401 } else { 502 };
    agent2api_wasm_sdk::Error::http(code, format!("{prefix}（HTTP {status}）"))
}

/// profile ARN 的 query 编码（只保留 unreserved 字符）。
fn profile_query(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
