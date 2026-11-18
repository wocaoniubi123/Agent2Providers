//! Antigravity 模型目录：`:fetchAvailableModels` + 内置兜底 + 对外 id → 上游真名。
//!
//! ── 两套 id 的关系（最容易搞混的一处）──────────────────────
//! ```text
//!   对外 id      内置兜底清单里的键（gemini-3.6-flash / claude-sonnet-4-6 …）
//!   上游真名     远程目录下发的 id（gemini-3.6-flash-tiered / claude-…-thinking）
//! ```
//! 远程目录下发的 id **本身就是真名**，所以映射表只处理「客户端拿旧名或别名
//! 来请求」的情形；表里没有的一律原样透传。
//!
//! ── 两条改写规则 ────────────────────────────────────────────
//!   1. 精确别名表（旧代 Claude → 4.6、`gemini-3.1-pro-high` → `gemini-pro-agent`）；
//!   2. 「无后缀、版本 ≥ 3.6 的 `gemini-<x.y>-flash`」追加 `-tiered`。
//!
//! ── 缓存放哪 ────────────────────────────────────────────────
//! native 是进程内按账号；wasm 放会话状态（TTL 10 分钟）。

use agent2api_wasm_sdk::{self as sdk, http, json, Result, Value};

use super::endpoints;

/// 缓存有效期。
const TTL_MS: i64 = 10 * 60 * 1000;

/// 精确别名表（与 native 的 `UPSTREAM_ALIASES` 逐条一致）。
const UPSTREAM_ALIASES: [(&str, &str); 21] = [
    ("gemini-3.6-flash", "gemini-3.6-flash-tiered"),
    ("gemini-3.7-flash", "gemini-3.7-flash-tiered"),
    ("gemini-3.8-flash", "gemini-3.8-flash-tiered"),
    ("gemini-3.1-pro-high", "gemini-pro-agent"),
    ("gemini-3-pro-high", "gemini-pro-agent"),
    ("gemini-2.5-flash-lite", "gemini-2.5-flash"),
    ("claude-sonnet-4-5", "claude-sonnet-4-6"),
    ("claude-sonnet-4-5-thinking", "claude-sonnet-4-6-thinking"),
    ("claude-sonnet-4-5-20250929", "claude-sonnet-4-6-thinking"),
    ("claude-opus-4", "claude-opus-4-6-thinking"),
    ("claude-opus-4-5-thinking", "claude-opus-4-6-thinking"),
    ("claude-opus-4-5-20251101", "claude-opus-4-6-thinking"),
    ("claude-opus-4-6", "claude-opus-4-6-thinking"),
    ("claude-opus-4.6", "claude-opus-4-6-thinking"),
    ("claude-opus-4.6-thinking", "claude-opus-4-6-thinking"),
    ("claude-opus-4-6-20260201", "claude-opus-4-6-thinking"),
    ("claude-3-5-sonnet-20241022", "claude-sonnet-4-6"),
    ("claude-3-5-sonnet-20240620", "claude-sonnet-4-6"),
    ("claude-haiku-4", "claude-sonnet-4-6"),
    ("claude-haiku-4-5-20251001", "claude-sonnet-4-6"),
    ("claude-3-haiku-20240307", "claude-sonnet-4-6"),
];

/// 对外 id（或上游真名）→ 真正发给 v1internal 的模型 id。
pub fn upstream_model_id(id: &str) -> String {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lowered = trimmed.to_ascii_lowercase();
    for (alias, target) in UPSTREAM_ALIASES {
        if lowered == alias {
            return target.to_string();
        }
    }
    if let Some(tiered) = tiered_flash_id(trimmed, &lowered) {
        return tiered;
    }
    trimmed.to_string()
}

/// 「无后缀、版本 ≥ 3.6 的 `gemini-<x.y>-flash`」→ 追加 `-tiered`。
fn tiered_flash_id(original: &str, lowered: &str) -> Option<String> {
    for suffix in ["-high", "-medium", "-low", "-extra-low", "-tiered", "-preview", "-agent", "-thinking", "-image"] {
        if lowered.contains(suffix) {
            return None;
        }
    }
    if !lowered.contains("flash") {
        return None;
    }
    let rest = lowered.strip_prefix("gemini-")?;
    let version: String = rest.chars().take_while(|ch| ch.is_ascii_digit() || *ch == '.').collect();
    let version = version.trim_end_matches('.').parse::<f64>().ok()?;
    if version < 3.6 {
        return None;
    }
    Some(format!("{original}-tiered"))
}

/// 是不是 Claude 家族（决定 `anthropic-beta` 头、思考块占位与思考预算）。
pub fn is_claude_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("claude")
}

/// 是不是图片模型。
pub fn is_image_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("-image")
}

/// 会话缓存键。
fn cache_key(account: &str) -> String {
    format!("antigravity:catalog:{account}")
}

/// 当前目录（会话缓存 → 内置兜底）。
pub fn list(metadata: &Value) -> Value {
    let account = sdk::account()
        .ok()
        .and_then(|record| record["id"].as_str().map(str::to_string))
        .unwrap_or_default();
    if let Ok(saved) = sdk::session_get(&cache_key(&account)) {
        let fetched_at = saved.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
        if let Some(models) = saved.get("models").and_then(Value::as_array) {
            if !models.is_empty() && sdk::now() - fetched_at < TTL_MS {
                return json!({
                    "models": models,
                    "meta": { "remote": true, "refreshed_at": fetched_at },
                });
            }
        }
    }
    json!({
        "models": metadata.get("default_models").cloned().unwrap_or_else(|| json!([])),
        "meta": { "remote": false, "refreshed_at": 0 },
    })
}

/// `models.refresh`：按 sandbox → daily → prod 依次试（429/5xx 换下一条）。
pub fn refresh_catalog(force: bool) -> Result<Value> {
    let (record, credentials) = super::refresh::ensure(false)?;
    let account_id = record["id"].as_str().unwrap_or("").to_string();
    if !force {
        if let Ok(saved) = sdk::session_get(&cache_key(&account_id)) {
            let fetched_at = saved.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
            if let Some(models) = saved.get("models").and_then(Value::as_array) {
                if !models.is_empty() && sdk::now() - fetched_at < TTL_MS {
                    return Ok(json!({ "refreshed": false, "count": models.len() }));
                }
            }
        }
    }
    if credentials.access_token.is_empty() {
        return Ok(json!({ "refreshed": false, "message": "Antigravity 账号缺少 access token，请重新登录" }));
    }
    let mut last = String::new();
    for base in endpoints::V1_BASE_URLS {
        let url = endpoints::fetch_available_models_url(base);
        let response = match http::open(
            "POST",
            &url,
            endpoints::catalog_headers(&credentials.access_token, &credentials.project_id),
            Some(&json!({})),
        ) {
            Ok(response) => response,
            Err(error) => {
                last = error.message;
                continue;
            }
        };
        let status = response.status;
        let bytes = response.bytes(4 * 1024 * 1024)?;
        if !(200..300).contains(&status) {
            last = format!("HTTP {status}");
            continue;
        }
        let payload: Value = match serde_json::from_slice(&bytes) {
            Ok(payload) => payload,
            Err(_) => {
                last = "目录不是有效 JSON".to_string();
                continue;
            }
        };
        let models = parse_models(&payload);
        if models.is_empty() {
            last = "目录为空".to_string();
            continue;
        }
        let count = models.len();
        let _ = sdk::session_put(
            &cache_key(&account_id),
            json!({ "models": models, "fetchedAt": sdk::now() }),
            TTL_MS,
        );
        return Ok(json!({ "refreshed": true, "count": count, "models": models }));
    }
    Ok(json!({
        "refreshed": false,
        "message": if last.is_empty() { "Antigravity 模型目录刷新失败".to_string() } else { format!("Antigravity 模型目录刷新失败：{last}") },
    }))
}

/// 解析 `:fetchAvailableModels` 的回包。
///
/// 形状是 `{"models":{ "<上游真名>": { "displayName": …, "quota": {…} } }}`
/// （键是模型名而不是数组）—— 两套参考实现都按这个读。
fn parse_models(payload: &Value) -> Vec<Value> {
    let Some(map) = payload.get("models").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut models: Vec<Value> = Vec::new();
    for (id, entry) in map {
        if id.trim().is_empty() {
            continue;
        }
        let name = entry
            .get("displayName")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .unwrap_or(id);
        let mut record = json!({
            "id": id,
            "name": name,
            "supportsToolCall": true,
            "supportsReasoning": !is_image_model(id),
            "supportsImages": !is_image_model(id),
            "isDefault": id == "gemini-3-flash",
        });
        if is_image_model(id) {
            record["kind"] = json!("image");
            record["output_modalities"] = json!(["image"]);
            record["supportsToolCall"] = json!(false);
        }
        if entry.get("quota").is_some() {
            record["quota"] = entry["quota"].clone();
        }
        models.push(record);
    }
    // 有默认模型就把它排到最前（与 native 的「默认项优先」同口径）。
    models.sort_by_key(|model| {
        if model.get("isDefault").and_then(Value::as_bool) == Some(true) {
            0
        } else {
            1
        }
    });
    models
}
