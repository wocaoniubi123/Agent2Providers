//! Kiro 模型目录：`List-Available-Models`（OAuth）与 `ListAvailableModels`（API key）。
//!
//! ── 上游形状 ────────────────────────────────────────────────
//! ```json
//! {"models":[{"modelId":"…","modelName":"…","tokenLimits":{"maxInputTokens":200000,
//!   "maxOutputTokens":64000},"supportedInputTypes":["TEXT","IMAGE"],
//!   "additionalModelRequestFieldsSchema":{…}}],
//!  "defaultModel":{"modelId":"auto"}}
//! ```
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! native 是进程内按账号 10 分钟；wasm 放会话状态（TTL 10 分钟）。
//! 缓存里同时存三份读数：模型行、原生思考档位（`additionalModelRequestFieldsSchema`
//! 解析结果）、上下文窗口（`events` 用百分比估输入时要用它）。

use agent2api_wasm_sdk::{self as sdk, http, json, Result, Value};

use super::credentials::Credentials;
use super::endpoints;
use super::refresh;

/// 缓存有效期。
const TTL_MS: i64 = 10 * 60 * 1000;

/// 一个模型的原生思考档位（`additionalModelRequestFields` 的路径与可选值）。
#[derive(Clone)]
pub struct NativeEffort {
    pub path: String,
    pub levels: Vec<String>,
}

/// 会话缓存键。
fn cache_key(account: &str) -> String {
    format!("kiro:catalog:{account}")
}

/// 内置兜底（native 的 `fallback_models`）。
pub fn fallback_models() -> Vec<Value> {
    vec![json!({
        "id": "auto",
        "name": "Auto",
        "supportsToolCall": true,
        "supportsReasoning": true,
        "isDefault": true,
    })]
}

/// 模型会不会思考（决定要不要注入 thinking 预算）。
pub fn thinks(model_id: &str) -> bool {
    let lower = model_id.to_ascii_lowercase();
    lower == "auto" || lower.contains("claude") || lower.contains("sonnet") || lower.contains("opus")
        || lower.contains("haiku") || lower.contains("thinking")
}

/// 当前账号的缓存（没有就兜底）。
fn cached(account: &str) -> Option<Value> {
    let value = sdk::session_get(&cache_key(account)).ok()?;
    let fetched_at = value.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
    if sdk::now() - fetched_at > TTL_MS {
        return None;
    }
    Some(value)
}

/// 某个模型的上下文窗口（拿不到给 0）。
pub fn window_of(account: &str, model: &str) -> i64 {
    cached(account)
        .and_then(|value| {
            value
                .get("windows")
                .and_then(|windows| windows.get(model))
                .and_then(Value::as_i64)
        })
        .unwrap_or(0)
}

/// 某个模型的原生思考档位。
pub fn native_of(account: &str, model: &str) -> Option<NativeEffort> {
    let entry = cached(account)?.get("natives")?.get(model)?.clone();
    let path = entry.get("path").and_then(Value::as_str)?.to_string();
    let levels: Vec<String> = entry
        .get("levels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|level| level.as_str().map(str::to_string))
        .collect();
    Some(NativeEffort { path, levels })
}

/// `models.list`。
pub fn list() -> Value {
    let account = current_account();
    match cached(&account) {
        Some(value) => json!({
            "models": value.get("models").cloned().unwrap_or_else(|| json!(fallback_models())),
            "meta": { "remote": true, "refreshed_at": value.get("fetchedAt").cloned().unwrap_or(Value::Null) },
        }),
        None => json!({ "models": fallback_models(), "meta": { "remote": false, "refreshed_at": 0 } }),
    }
}

/// `models.refresh`：拉一次目录（`force` 时无视缓存）。
pub fn refresh_catalog(force: bool) -> Result<Value> {
    let (record, credentials) = refresh::ensure(false)?;
    let account_id = record["id"].as_str().unwrap_or("").to_string();
    if !force {
        if let Some(value) = cached(&account_id) {
            let count = value.get("models").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
            return Ok(json!({ "refreshed": false, "count": count }));
        }
    }
    let payload = if credentials.is_api_key() {
        key_models(&credentials)?
    } else {
        management_models(&credentials)?
    };
    let (models, natives, windows) = parse_models(&payload)?;
    if models.is_empty() {
        return Ok(json!({ "refreshed": false, "message": "Kiro 没有返回任何模型" }));
    }
    let count = models.len();
    let _ = sdk::session_put(
        &cache_key(&account_id),
        json!({
            "models": models,
            "natives": Value::Object(natives),
            "windows": Value::Object(windows),
            "fetchedAt": sdk::now(),
        }),
        TTL_MS,
    );
    Ok(json!({ "refreshed": true, "count": count, "models": models }))
}

/// 当前账号 id（拿不到给空串）。
fn current_account() -> String {
    sdk::account()
        .ok()
        .and_then(|record| record["id"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// 解析目录体 → （模型行, 原生档位表, 窗口表）。
fn parse_models(payload: &Value) -> Result<(Vec<Value>, serde_json::Map<String, Value>, serde_json::Map<String, Value>)> {
    let rows = payload.get("models").and_then(Value::as_array).cloned().unwrap_or_default();
    let default_id = payload
        .pointer("/defaultModel/modelId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut models: Vec<Value> = Vec::new();
    let mut natives = serde_json::Map::new();
    let mut windows = serde_json::Map::new();
    for row in &rows {
        let Some(model_id) = row.get("modelId").and_then(Value::as_str) else {
            continue;
        };
        if model_id.is_empty() {
            continue;
        }
        let name = row
            .get("modelName")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && *value != model_id)
            .unwrap_or(if model_id == "auto" { "Auto" } else { model_id });
        let context = row.pointer("/tokenLimits/maxInputTokens").and_then(Value::as_i64).unwrap_or(0);
        let output = row.pointer("/tokenLimits/maxOutputTokens").and_then(Value::as_i64).unwrap_or(0);
        let images = row
            .get("supportedInputTypes")
            .and_then(Value::as_array)
            .is_some_and(|types| {
                types.iter().any(|value| value.as_str().is_some_and(|text| text.eq_ignore_ascii_case("IMAGE")))
            });
        let mut record = json!({
            "id": model_id,
            "name": name,
            "maxInputTokens": context,
            "maxOutputTokens": output,
            "supportsToolCall": true,
            "supportsReasoning": thinks(model_id),
            "isDefault": !default_id.is_empty() && model_id == default_id,
        });
        if images {
            record["supportsImages"] = json!(true);
        }
        if model_id == "auto" || !default_id.is_empty() {
            record["isDefault"] = json!(model_id == default_id || (default_id.is_empty() && model_id == "auto"));
        }
        if context > 0 {
            windows.insert(model_id.to_string(), json!(context));
        }
        if let Some(native) = native_of_schema(row.get("additionalModelRequestFieldsSchema")) {
            natives.insert(model_id.to_string(), native);
        }
        if model_id == default_id {
            models.insert(0, record);
        } else {
            models.push(record);
        }
    }
    Ok((models, natives, windows))
}

/// `additionalModelRequestFieldsSchema` → 原生档位（路径 + 可选值）。
fn native_of_schema(schema: Option<&Value>) -> Option<Value> {
    let schema = schema?.get("properties")?.as_object()?;
    if let Some(effort) = schema.get("thinking") {
        let path = "thinking".to_string();
        let levels: Vec<String> = effort
            .pointer("/properties/effort/enum")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        if !levels.is_empty() {
            return Some(json!({ "path": path, "levels": levels }));
        }
    }
    for (key, value) in schema {
        let levels: Vec<String> = value
            .pointer("/properties/effort/enum")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        if !levels.is_empty() {
            return Some(json!({ "path": key, "levels": levels }));
        }
    }
    None
}

/// 管理面（OAuth 登录态）：`GET /List-Available-Models`。
fn management_models(credentials: &Credentials) -> Result<Value> {
    let region = credentials.region();
    let mut url = format!("{}/List-Available-Models?origin=KIRO_CLI", endpoints::management(&region));
    if !credentials.profile.is_empty() {
        url.push_str("&profileArn=");
        url.push_str(&urlencode(&credentials.profile));
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
    let bytes = response.bytes(4 * 1024 * 1024)?;
    if !(200..300).contains(&status) {
        return Err(agent2api_wasm_sdk::Error::http(
            if status == 401 || status == 403 { 401 } else { 502 },
            format!("拉取 Kiro 模型目录失败（HTTP {status}）"),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| agent2api_wasm_sdk::Error::http(502, "Kiro 模型目录不是有效 JSON"))
}

/// API key：控制面的 `ListAvailableModels`（按 nextToken 分页）。
fn key_models(credentials: &Credentials) -> Result<Value> {
    let region = credentials.region();
    let mut models: Vec<Value> = Vec::new();
    let mut default_model = Value::Null;
    let mut next: Option<String> = None;
    for _ in 0..20 {
        let mut body = json!({ "origin": "KIRO_CLI" });
        if let Some(token) = &next {
            body["nextToken"] = json!(token);
        }
        let url = format!("{}/?origin=KIRO_CLI", endpoints::management(&region));
        let response = http::open(
            "POST",
            &url,
            json!({
                "accept": "application/json",
                "content-type": "application/x-amz-json-1.0",
                "x-amz-target": endpoints::TARGET_KEY_MODELS,
                "x-amzn-codewhisperer-optout": "false",
                "authorization": format!("Bearer {}", credentials.access),
                "tokentype": "API_KEY",
            }),
            Some(&body),
        )?;
        let status = response.status;
        let bytes = response.bytes(4 * 1024 * 1024)?;
        if !(200..300).contains(&status) {
            return Err(agent2api_wasm_sdk::Error::http(
                if status == 401 || status == 403 { 401 } else { 502 },
                format!("拉取 Kiro 模型目录失败（HTTP {status}）"),
            ));
        }
        let page: Value = serde_json::from_slice(&bytes)
            .map_err(|_| agent2api_wasm_sdk::Error::http(502, "Kiro 模型目录不是有效 JSON"))?;
        if let Some(list) = page.get("models").and_then(Value::as_array) {
            models.extend(list.iter().cloned());
        }
        if default_model.is_null() {
            if let Some(value) = page.get("defaultModel") {
                if !value.is_null() {
                    default_model = value.clone();
                }
            }
        }
        next = page.get("nextToken").and_then(Value::as_str).map(str::to_string);
        if next.is_none() {
            break;
        }
    }
    Ok(json!({ "models": models, "defaultModel": default_model }))
}

/// query 编码（profile ARN 里有 `:` 与 `/`）。
fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
