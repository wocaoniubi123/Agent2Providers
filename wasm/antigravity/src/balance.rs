//! Antigravity 余额：`retrieveUserQuotaSummary` 的窗口剩余比例 + `loadCodeAssist` 的订阅档。
//!
//! ── 与模型目录里的 `quota` 不是一回事 ──────────────────────
//! 目录里的 `quota` 是**单模型**读数（随 `:fetchAvailableModels` 进缓存）；
//! 这里是**账号级**的窗口额度（5 小时 / 每周）。两者并存，互不替代。
//!
//! ── 上游只给比例 ───────────────────────────────────────────
//! `retrieveUserQuotaSummary` 不给绝对 token 数，只给每个窗口的剩余比例；
//! 所以钱包行画的是纯比例读数（四个窗口：Gemini 两条 + Claude/GPT 两条）。

use agent2api_wasm_sdk::{http, json, Result, Value};

use super::credentials::AntigravityCredentials;
use super::endpoints;

/// 一个窗口的读数（从 `buckets` / `groups` 里折出来）。
fn window_of(label: &str, remaining: f64) -> Value {
    let remaining = remaining.clamp(0.0, 100.0);
    json!({
        "name": label,
        "label": label,
        "remainingPercent": remaining,
        "used": (100.0 - remaining).clamp(0.0, 100.0),
        "display": format!("{remaining:.0}% 剩余"),
        "unit": "%",
    })
}

/// 从一份额度摘要里折出窗口（字段名按两套参考实现的交集取）。
fn windows_of(payload: &Value) -> Vec<Value> {
    let mut windows: Vec<Value> = Vec::new();
    let lists = [
        payload.get("quotaGroups"),
        payload.get("groups"),
        payload.get("buckets"),
    ];
    for list in lists.into_iter().flatten() {
        let Some(items) = list.as_array() else {
            continue;
        };
        for item in items {
            let label = item
                .get("displayName")
                .or_else(|| item.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("额度");
            let remaining = item
                .get("remainingPercent")
                .or_else(|| item.get("remainingPercentage"))
                .or_else(|| item.get("remaining"))
                .and_then(|value| value.as_f64());
            if let Some(remaining) = remaining.filter(|value| value.is_finite()) {
                windows.push(window_of(label, remaining));
            }
        }
    }
    windows
}

/// `usage.query`。
pub fn query(credentials: &AntigravityCredentials) -> Result<Value> {
    if credentials.access_token.is_empty() {
        return Err(agent2api_wasm_sdk::Error::http(
            401,
            "Antigravity 账号缺少 access token，请重新登录",
        ));
    }
    let mut windows: Vec<Value> = Vec::new();
    let mut plan: Option<String> = None;
    let mut last = String::new();
    // 基址顺序与目录一致：sandbox → daily → prod。
    for base in endpoints::V1_BASE_URLS {
        let response = http::open(
            "POST",
            &endpoints::retrieve_user_quota_summary_url(base),
            endpoints::quota_headers(&credentials.access_token, &credentials.project_id),
            Some(&json!({})),
        );
        let Ok(response) = response else {
            last = "网络失败".to_string();
            continue;
        };
        if !(200..300).contains(&response.status) {
            last = format!("HTTP {}", response.status);
            continue;
        }
        let payload = match response.json() {
            Ok(payload) => payload,
            Err(_) => {
                last = "额度返回不是有效 JSON".to_string();
                continue;
            }
        };
        windows = windows_of(&payload);
        break;
    }
    // 订阅档：`loadCodeAssist`（固定 prod）。
    if let Ok(response) = http::open(
        "POST",
        &endpoints::load_code_assist_url(),
        endpoints::admin_headers(&credentials.access_token, ""),
        Some(&json!({ "metadata": { "pluginType": "GEMINI" } })),
    ) {
        if (200..300).contains(&response.status) {
            if let Ok(payload) = response.json() {
                plan = payload
                    .pointer("/currentTier/name")
                    .or_else(|| payload.get("currentTier").and_then(|tier| tier.get("id")))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
    }
    if windows.is_empty() && plan.is_none() {
        return Ok(json!({
            "provider": "antigravity",
            "plan": "Antigravity",
            "windows": [],
            "error": if last.is_empty() { "Antigravity 未返回可识别的额度窗口".to_string() } else { format!("Antigravity 额度不可达：{last}") },
        }));
    }
    let mut report = json!({ "provider": "antigravity", "windows": windows });
    report["plan"] = json!(plan.unwrap_or_else(|| "Antigravity".to_string()));
    if !credentials.email.is_empty() {
        report["user"] = json!(credentials.email);
    }
    Ok(report)
}
