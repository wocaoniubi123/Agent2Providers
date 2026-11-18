//! QuWork 模型目录：公开配置 JSON（`img1.rrzuji.cn`）+ 内置兜底。
//!
//! ── 为什么目录要校验到这么细 ────────────────────────────────
//! 这份 JSON 决定「模型名发到哪个地址」与「用哪套 OpenAI 兼容开关」。
//! native 的校验逐条照搬：`key` / `schemaVersion` / `enabled` 必须对得上，
//! 提供商必须是 `qurwork` + `openai-completions`，`baseURL` 必须是已知的
//! 模型网关（**地址被改过就拒收**，不向未确认的地址发凭证），模型名唯一。
//!
//! ── 缓存放在哪 ──────────────────────────────────────────────
//! native 用 `ctx.settings_set` 落用户设置；wasm 插件的设置是「用户覆盖值」，
//! 写它就是改用户的配置。所以缓存走会话状态（10 分钟 TTL），进程重启后
//! 首轮重新拉一次 —— 与 native 的 `CACHE_KEY` 同一个有效期。

use agent2api_wasm_sdk::{self as sdk, json, Result, Value};

use super::upstream;

/// 会话里的缓存键。
const CACHE_KEY: &str = "quwork:catalog";

/// 缓存有效期（与大 native 的 `TTL_MS` 同值）。
const TTL_MS: i64 = 10 * 60_000;

/// 内置兜底目录（官方 1.6.0 的 `qurvis-desktop-model-config`，逐字照搬）。
const FALLBACK: &str = include_str!("catalog.json");

/// 一份可用目录。
pub struct Catalog {
    pub config: Value,
    pub fetched_at: i64,
}

/// 兜底目录（永远可用）。
pub fn fallback() -> Catalog {
    Catalog {
        config: serde_json::from_str(FALLBACK).unwrap_or(Value::Null),
        fetched_at: 0,
    }
}

/// 目录校验：任何一条不满足都拒收（见模块头）。
pub fn validate(config: &Value) -> Result<()> {
    if config.get("key").and_then(Value::as_str) != Some("qurvis-desktop-model-config")
        || config.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || config.get("enabled").and_then(Value::as_bool).is_none()
    {
        return Err(sdk::Error::new("QuWork 模型配置格式不兼容"));
    }
    let providers = config
        .get("providers")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 8)
        .ok_or_else(|| sdk::Error::new("QuWork 模型提供商配置异常"))?;
    let mut ids: Vec<String> = Vec::new();
    for provider in providers {
        if provider.get("id").and_then(Value::as_str) != Some("qurwork") {
            continue;
        }
        if provider.get("api").and_then(Value::as_str) != Some("openai-completions") {
            return Err(sdk::Error::new("QuWork 模型接口协议已变化，请更新插件"));
        }
        if provider
            .get("baseURL")
            .and_then(Value::as_str)
            .map(|url| url.trim_end_matches('/'))
            != Some(upstream::MODEL_ORIGIN)
        {
            return Err(sdk::Error::new("QuWork 模型服务地址已变化，未向未确认的地址发送凭证"));
        }
        let rows = provider
            .get("models")
            .and_then(Value::as_array)
            .filter(|rows| rows.len() <= 128)
            .ok_or_else(|| sdk::Error::new("QuWork 模型清单格式异常"))?;
        for row in rows {
            let id = row
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
                .ok_or_else(|| sdk::Error::new("QuWork 模型名称格式异常"))?;
            if ids.iter().any(|known| known == id) {
                return Err(sdk::Error::new("QuWork 模型清单存在重复名称"));
            }
            ids.push(id.to_string());
            if row.get("enabled").and_then(Value::as_bool).is_none() {
                return Err(sdk::Error::new("QuWork 模型启用状态不明确"));
            }
        }
    }
    if !providers
        .iter()
        .any(|provider| provider.get("id").and_then(Value::as_str) == Some("qurwork"))
    {
        return Err(sdk::Error::new("QuWork 模型配置未包含模型提供商"));
    }
    Ok(())
}

/// 当前目录：会话缓存 → 兜底。
pub fn current() -> Catalog {
    if let Ok(saved) = sdk::session_get(CACHE_KEY) {
        if let Some(config) = saved.get("config").filter(|config| validate(config).is_ok()) {
            return Catalog {
                config: config.clone(),
                fetched_at: saved.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0),
            };
        }
    }
    fallback()
}

impl Catalog {
    /// 启用中的模型行（按 `sort` 排序）。
    pub fn rows(&self) -> Vec<&Value> {
        if self.config.get("enabled").and_then(Value::as_bool) != Some(true) {
            return Vec::new();
        }
        let mut rows: Vec<&Value> = self
            .config
            .get("providers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|provider| provider.get("id").and_then(Value::as_str) == Some("qurwork"))
            .flat_map(|provider| provider.get("models").and_then(Value::as_array).into_iter().flatten())
            .filter(|model| model.get("enabled").and_then(Value::as_bool) == Some(true))
            .collect();
        rows.sort_by_key(|row| row.get("sort").and_then(Value::as_i64).unwrap_or(i64::MAX));
        rows
    }

    /// 按 id 找一行（对话前的白名单校验）。
    pub fn model(&self, id: &str) -> Option<&Value> {
        self.rows()
            .into_iter()
            .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
    }

    /// 对外模型清单（`catalog.v1` 的形状）。
    pub fn list(&self) -> Value {
        let default = self
            .config
            .pointer("/defaultModel/modelId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let models: Vec<Value> = self
            .rows()
            .into_iter()
            .map(|row| {
                let id = row.get("id").and_then(Value::as_str).unwrap_or("");
                let efforts = row.get("reasoningEfforts").and_then(Value::as_object);
                let mut model = json!({
                    "id": id,
                    "name": row.get("name").and_then(Value::as_str).unwrap_or(id),
                    "supportsToolCall": true,
                    "supportsImages": row.get("supportsImage").and_then(Value::as_bool).unwrap_or(false),
                    "isDefault": id == default,
                });
                for (target, source) in [("maxInputTokens", "contextWindow"), ("maxOutputTokens", "maxTokens")] {
                    if let Some(value) = row.get(source).and_then(Value::as_u64).filter(|value| *value > 0) {
                        model[target] = json!(value);
                    }
                }
                if let Some(efforts) = efforts {
                    model["supportsReasoning"] = json!(true);
                    model["reasoningLevels"] = json!(efforts.keys().collect::<Vec<_>>());
                }
                model
            })
            .collect();
        json!({
            "models": models,
            "meta": { "remote": self.fetched_at > 0, "refreshed_at": self.fetched_at },
        })
    }
}

/// `models.list`。
pub fn list() -> Value {
    current().list()
}

/// `models.refresh`：拉公开目录并校验；失败如实回 `{refreshed:false,message}`。
pub fn refresh(force: bool) -> Result<Value> {
    let catalog = current();
    if !force && catalog.fetched_at > 0 && sdk::now().saturating_sub(catalog.fetched_at) < TTL_MS {
        return Ok(if catalog.list()["models"].as_array().is_some_and(|rows| rows.is_empty()) {
            json!({ "refreshed": false, "message": "QuWork 当前未开放可用模型" })
        } else {
            json!({ "refreshed": false, "count": catalog.list()["models"].as_array().map(Vec::len).unwrap_or(0) })
        });
    }
    let config = match upstream::public_config() {
        Ok(config) => config,
        Err(error) => return Ok(json!({ "refreshed": false, "message": error.message })),
    };
    if let Err(error) = validate(&config) {
        return Ok(json!({ "refreshed": false, "message": error.message }));
    }
    let catalog = Catalog {
        config,
        fetched_at: sdk::now(),
    };
    let _ = sdk::session_put(
        CACHE_KEY,
        json!({ "config": catalog.config, "fetchedAt": catalog.fetched_at }),
        TTL_MS,
    );
    let count = catalog.list()["models"].as_array().map(Vec::len).unwrap_or(0);
    if count == 0 {
        return Ok(json!({ "refreshed": false, "message": "QuWork 当前未开放可用模型，未发送任何模型请求" }));
    }
    Ok(json!({ "refreshed": true, "count": count, "models": catalog.list()["models"] }))
}
