//! AStudio 模型目录：按账号实时拉取（读取不计费），带缓存与静态兜底。
//!
//! ── 上游形状 ────────────────────────────────────────────────
//! ```json
//! {"code":0,"data":{"models":[{"slug":"spark-x2.6","display_name":"Spark-X2.6",
//!   "context_window":262144,"max_output_tokens":32768,
//!   "input_modalities":["text","image"],
//!   "supported_reasoning_levels":[{"effort":"none"},{"effort":"high"}],
//!   "badge":{"text":{"en":"Free"}},"visibility":"public","supported_in_api":true}]}}
//! ```
//!
//! ── 缓存放哪 ────────────────────────────────────────────────
//! native 是进程内 10 分钟；wasm 没有长驻进程，缓存进会话状态（TTL 10 分钟），
//! 重启后首轮重拉一次 —— 与 native 的 `TTL_MS` 同值。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::{account, client};

/// 缓存有效期（与 native 同值）。
const TTL_MS: i64 = 10 * 60 * 1000;

/// 会话缓存键（按账号 id 区分）。
fn cache_key(account: &str) -> String {
    format!("astudio:catalog:{account}")
}

/// 静态兜底（native 的实测快照，2026-11-01）。
pub fn fallback_models() -> Vec<Value> {
    let rows: [(&str, &str, i64, i64, bool); 7] = [
        ("astronclaw-auto", "Auto", 262_144, 32_768, false),
        ("spark-x2.6", "Spark-X2.6", 262_144, 32_768, false),
        ("spark-x2.6-4b", "Spark-X2.6-Lite", 1_048_576, 110_000, true),
        ("spark-x2.5", "Spark-X2.5", 262_144, 32_768, false),
        ("xopglm52", "GLM-5.2", 1_048_576, 32_768, false),
        ("xopdeepseekv4pro0813", "DeepSeek-V4-Pro", 1_048_576, 32_768, false),
        ("xopdsv4flash0731in", "DeepSeek-V4-Flash", 1_048_576, 32_768, false),
    ];
    rows.iter()
        .map(|(id, name, context, output, free)| {
            let mut record = json!({
                "id": id,
                "name": name,
                "maxInputTokens": context,
                "maxOutputTokens": output,
                "supportsToolCall": true,
                "supportsReasoning": true,
                "isDefault": *id == "astronclaw-auto",
            });
            if *free {
                record["free"] = json!(true);
            }
            record
        })
        .collect()
}

/// 一行上游模型 → 对外模型记录（不可用的直接丢掉）。
fn row_of(entry: &Value) -> Option<Value> {
    let id = entry
        .get("slug")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if entry.get("visibility").and_then(Value::as_str) == Some("hidden") {
        return None;
    }
    if entry.get("supported_in_api").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let name = entry
        .get("display_name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(id);
    let context = entry
        .get("context_window")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(0);
    let output = entry
        .get("max_output_tokens")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(32_768);
    let images = entry
        .get("input_modalities")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str().is_some_and(|text| text == "image")));
    let reasoning = entry
        .get("supported_reasoning_levels")
        .and_then(Value::as_array)
        .is_some_and(|levels| {
            levels.iter().any(|level| {
                level
                    .get("effort")
                    .and_then(Value::as_str)
                    .is_some_and(|effort| !effort.is_empty() && effort != "none")
            })
        });
    let free = entry
        .pointer("/badge/text/en")
        .and_then(Value::as_str)
        .is_some_and(|text| text == "Free");
    let mut record = json!({
        "id": id,
        "name": name,
        "maxInputTokens": context,
        "maxOutputTokens": output,
        "supportsToolCall": true,
        "supportsReasoning": reasoning,
        "isDefault": id == "astronclaw-auto",
    });
    if images {
        record["supportsImages"] = json!(true);
    }
    if free {
        record["free"] = json!(true);
    }
    Some(record)
}

/// 解析目录体。
fn parse(payload: &Value) -> std::result::Result<Vec<Value>, String> {
    let list = payload
        .pointer("/data/models")
        .and_then(Value::as_array)
        .ok_or_else(|| "AStudio 模型目录格式异常".to_string())?;
    let mut models: Vec<Value> = list.iter().filter_map(row_of).collect();
    if models.is_empty() {
        return Err("AStudio 模型目录为空".to_string());
    }
    models.sort_by_key(|model| {
        if model.get("isDefault").and_then(Value::as_bool) == Some(true) {
            0
        } else {
            1
        }
    });
    Ok(models)
}

/// 当前清单（会话缓存优先；没有缓存用兜底）。
pub fn list() -> Value {
    let id = sdk::account()
        .ok()
        .and_then(|record| record["id"].as_str().map(str::to_string))
        .unwrap_or_default();
    if let Ok(saved) = sdk::session_get(&cache_key(&id)) {
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
    json!({ "models": fallback_models(), "meta": { "remote": false, "refreshed_at": 0 } })
}

/// `models.refresh`：拉一次目录并写会话缓存。
pub fn refresh(force: bool) -> Value {
    let record = match sdk::account() {
        Ok(record) => record,
        Err(error) => return json!({ "refreshed": false, "message": error.message }),
    };
    let id = record["id"].as_str().unwrap_or("").to_string();
    let key = cache_key(&id);
    if !force {
        if let Ok(saved) = sdk::session_get(&key) {
            let fetched_at = saved.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
            if let Some(models) = saved.get("models").and_then(Value::as_array) {
                if !models.is_empty() && sdk::now() - fetched_at < TTL_MS {
                    return json!({ "refreshed": false, "count": models.len() });
                }
            }
        }
    }
    let credentials = match account::current() {
        Ok(secret) => super::account::Credentials::from_secret(&secret),
        Err(error) => return json!({ "refreshed": false, "message": error.message }),
    };
    if credentials.key.is_empty() {
        return json!({ "refreshed": false, "message": "AStudio 账号缺少 modelBearerToken，请重新添加" });
    }
    let payload = match client::fetch_catalog(&credentials.key) {
        Ok(payload) => payload,
        Err(client::CatalogError::Expired) => {
            return json!({ "refreshed": false, "message": "AStudio 拒绝了这份凭据（HTTP 401/403），请重新登录" })
        }
        Err(client::CatalogError::Failed(message)) => {
            return json!({ "refreshed": false, "message": format!("拉取 AStudio 模型目录失败：{message}") })
        }
    };
    let models = match parse(&payload) {
        Ok(models) => models,
        Err(message) => return json!({ "refreshed": false, "message": message }),
    };
    let count = models.len();
    let _ = sdk::session_put(&key, json!({ "models": models, "fetchedAt": sdk::now() }), TTL_MS);
    json!({ "refreshed": true, "count": count, "models": models })
}

/// 供 `models.refresh` 失败时用的统一形状。
#[allow(dead_code)]
pub fn failed(message: &str) -> Result<Value> {
    Ok(json!({ "refreshed": false, "message": message }))
}

/// 供上层构造错误（保留 native 的文案风格）。
#[allow(dead_code)]
pub fn catalog_error(message: &str) -> Error {
    Error::http(502, message.to_string())
}
