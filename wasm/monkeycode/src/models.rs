//! MonkeyCode 模型目录：`GET /api/v1/users/models` + 宿主会话缓存。
//!
//! ── 上游形态（`mvp/models.py::list_models` + `docs/03-llm/01-model-management-api.md`）──
//! `{"code":0,"data":{"models":[{…}]}}`（也有 `{"models":[…]}` 的兼容形态）。
//! 每个条目的关键字段（参考 `domain/model.go` 的 Model 实体）：
//!   - `id`           模型 UUID（**创建任务时用的 `model_id`**，`task.rs` 反查它）；
//!   - `provider`     提供商名（`siliconflow` / `openai` / …）；
//!   - `model`        上游模型名（`gpt-4o` / `Qwen/Qwen3.5-Plus`）；
//!   - `display_name` 展示名（可能为空）；
//!   - `interface_type` `openai_chat` / `openai_responses` / `anthropic`；
//!   - `context_limit` / `output_limit` 上下文与输出上限（可能为 0）；
//!   - `is_free` / `is_default` / `access_level` 免费 / 默认 / 订阅档。
//!
//! 参考实现（`proxy/src/models.ts`）给下游的模型 id 是
//! `monkeycode/{provider}/{model}` —— 本模块的目录 `id` 采用同一形态
//! （`{provider}/{model}`，provider 为空时退化成 `model`），UUID 另存为
//! `upstreamId`。`interface_type` 保留为目录元数据；云任务统一使用 OpenCode，
//! 不能按接口类型选择执行器。目录中的 `cliName` 仅用于展示，不参与任务创建。
//!
//! ── 目录的 id 与「发什么给上游」是两回事 ────────────────────────
//! 客户端请求的 `id` 是本目录的 `{provider}/{model}`；转发时必须反查
//! `upstreamId`（UUID）作为建任务的 `model_id`，不能只保留展示字段。
//!
//! ── 缓存（迁移时改了：进程内 → 宿主会话存储）──────────────────
//! native 是「进程内 `Mutex` + 网关 `catalog_cache` 落盘」。wasm 实例**一次调用
//! 一个沙箱**，静态变量不跨请求，所以缓存改用 `sdk::session_*`（`sessions.v1`）：
//! 键是全局的（不带账号），与 native 的进程级全局缓存同义。
//! 另外多了一条**回落读取**：会话缓存为空时问一次 `catalog.get`（网关侧持久化的
//! 模型目录快照），这样插件换了沙箱、网关重启后也不必先刷一次目录才能对话。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::{client, credentials, endpoints, logging};

/// 自动路径的缓存 TTL（与客户端自己的节奏同档）
const TTL_MS: i64 = 10 * 60 * 1000;

/// 会话缓存的键
const CACHE_KEY: &str = "monkeycode:model-catalog";

/// 从上游条目里取字符串（trim 后非空才算有值）
fn text_of(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 把一个上游模型条目映射成聚合层认的形态。
///
/// 键名对照 `core/models/shape.rs::list_item`：`id` / `name` /
/// `maxInputTokens` / `maxOutputTokens` / `supportsImages` / `supportsVideo` /
/// `supportsReasoning` / `supportsToolCall` / `isDefault`。另保留三个元数据键：
/// `upstreamId`（UUID）、`cliName`、`interfaceType`。只有 `upstreamId` 参与转发。
///
/// 没有 `model` 字段的条目直接跳过（没有上游模型名就无法建任务）；
/// `display_name` 空时用 `model` 兜底展示名。
fn map_entry(row: &Value) -> Option<Value> {
    let model_name = text_of(row, "model");
    if model_name.is_empty() {
        return None;
    }
    let provider = text_of(row, "provider");
    // 目录 id：`{provider}/{model}`（provider 为空时退化成 `model`）—— 与参考
    // 实现 `toOpenAIModelId` 同形态（去掉 `monkeycode/` 前缀，因为网关按 provider
    // 区分归属）
    let id = if provider.is_empty() {
        model_name.clone()
    } else {
        format!("{provider}/{model_name}")
    };
    let display_name = text_of(row, "display_name");
    let name = if display_name.is_empty() {
        model_name.clone()
    } else {
        display_name
    };
    let mut item = serde_json::Map::new();
    item.insert("id".to_string(), json!(id));
    item.insert("name".to_string(), json!(name));
    item.insert("provider".to_string(), json!(provider));
    item.insert("model".to_string(), json!(model_name));
    item.insert("upstreamId".to_string(), json!(text_of(row, "id")));
    item.insert("interfaceType".to_string(), json!(text_of(row, "interface_type")));
    item.insert("cliName".to_string(), json!(endpoints::TASK_CLI_NAME));
    // 能力位：本家目录没有 capabilities 对象。工具调用是**上游 coding agent
    // 网关**的固有能力（opencode / codex / claude 都走工具循环），给 true；
    // 思考位如实取 `thinking_enabled`（创建模型时的字段，目录里可能缺失）；
    // 图片位参考没给依据，保守 false。
    item.insert("supportsToolCall".to_string(), Value::Bool(true));
    item.insert("supportsImages".to_string(), Value::Bool(false));
    item.insert("supportsVideo".to_string(), Value::Bool(false));
    item.insert(
        "supportsReasoning".to_string(),
        Value::Bool(
            row.get("thinking_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    item.insert(
        "isDefault".to_string(),
        Value::Bool(row.get("is_default").and_then(Value::as_bool).unwrap_or(false)),
    );
    // 免费 / 订阅档：非聚合层字段，但账号页与排障会看（保留原样）
    if let Some(is_free) = row.get("is_free").and_then(Value::as_bool) {
        item.insert("isFree".to_string(), Value::Bool(is_free));
    }
    let access_level = text_of(row, "access_level");
    if !access_level.is_empty() {
        item.insert("accessLevel".to_string(), json!(access_level));
    }
    for (key, target) in [
        ("context_limit", "maxInputTokens"),
        ("output_limit", "maxOutputTokens"),
    ] {
        if let Some(value) = row.get(key).and_then(Value::as_i64) {
            if value > 0 {
                item.insert(target.to_string(), Value::from(value));
            }
        }
    }
    Some(Value::Object(item))
}

/// 解析 `/api/v1/users/models` 响应（`{code,data:{models:[]}}` 或 `{models:[]}`）
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let data = payload.get("data").unwrap_or(payload);
    let rows = data
        .get("models")
        .and_then(Value::as_array)
        .or_else(|| data.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

/// 读会话缓存里的 `(models, fetched_at)`（读不到给空）。
fn cached() -> (Vec<Value>, i64) {
    let Ok(value) = sdk::session_get(CACHE_KEY) else {
        return (Vec::new(), 0);
    };
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.trim().is_empty())
        })
        .collect();
    let fetched_at = value.get("fetched_at").and_then(Value::as_i64).unwrap_or(0);
    (models, fetched_at)
}

/// 写会话缓存（写失败不影响本次结果）。
fn store(models: &[Value], fetched_at: i64) {
    let _ = sdk::session_put(
        CACHE_KEY,
        json!({ "models": models, "fetched_at": fetched_at }),
        TTL_MS * 2,
    );
}

/// 网关侧持久化的目录快照（`catalog.get`，本包申报了 `catalog.v1`）。
///
/// 只是一条**回落**：会话缓存为空（新沙箱 / 网关刚重启）时读它，省掉「先刷一次
/// 目录才能对话」这一轮。读不到就是空表，不报错。
fn persisted() -> (Vec<Value>, i64) {
    let Ok(value) = sdk::host("catalog.get", json!({})) else {
        return (Vec::new(), 0);
    };
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fetched_at = value
        .pointer("/meta/refreshed_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    (models, fetched_at)
}

/// 当前可用的模型清单（会话缓存 → 网关快照 → 空）。
pub fn current() -> Vec<Value> {
    let (models, _) = cached();
    if !models.is_empty() {
        return models;
    }
    persisted().0
}

/// 最近一次成功刷新的时刻（毫秒；没刷过为 0）—— 界面「更新日期」列读它。
pub fn last_refreshed_at() -> i64 {
    let (models, fetched_at) = cached();
    if models.is_empty() {
        persisted().1
    } else {
        fetched_at
    }
}

/// `models.list`：当前清单 + 来源标记。
///
/// 上游没有内置兜底清单：有内容就等于远程拉到过。
pub fn list() -> Value {
    let models = current();
    json!({
        "models": models,
        "meta": {
            "remote": !models.is_empty(),
            "refreshed_at": last_refreshed_at(),
        },
    })
}

/// `models.refresh`：拉一次目录并落会话缓存。
///
/// ── 失败为什么不返回错误 ────────────────────────────────────
/// 与 native 同一取舍：目录刷新失败时**保留现有清单**、把原因放进返回体
/// （`catalog::failed`），编排层据此提示「已保留旧清单」，而不是让整个账号进入
/// 错误态（模型清单过期不影响已有模型继续对话）。
pub fn refresh(force: bool, account: &str) -> Result<Value> {
    let count_now = current().len();
    let credentials = match credentials::current() {
        Ok(credentials) => credentials,
        Err(_) => {
            // 「一个账号都没有」不是失败 —— 那是「用户还没添加账号」的正常状态，
            // 返回 unchanged（脚本 / CI 不该看到一个红色失败）。
            if account.trim().is_empty() {
                logging::verbose("[MonkeyCode] 模型目录刷新跳过：尚未添加账号");
                return Ok(sdk::catalog::unchanged(count_now));
            }
            return Ok(sdk::catalog::failed("指定的账号不存在或不可用，请重新选择"));
        }
    };
    if !force {
        let (models, fetched_at) = cached();
        if !models.is_empty() && sdk::now().saturating_sub(fetched_at) < TTL_MS {
            return Ok(sdk::catalog::unchanged(models.len()));
        }
    }
    let payload = match client::get_json(endpoints::MODELS_PATH, &credentials.session, "模型目录查询") {
        Ok(payload) => payload,
        Err(error) => return Ok(sdk::catalog::failed(&error.message)),
    };
    let models = parse_models(&payload);
    if models.is_empty() {
        return Ok(sdk::catalog::failed(
            "MonkeyCode 模型目录为空或格式不认识（保留现有清单）",
        ));
    }
    let count = models.len();
    store(&models, sdk::now());
    logging::verbose(&format!("[MonkeyCode] 模型目录已刷新：{count} 个"));
    Ok(sdk::catalog::refreshed(models))
}

/// 建任务要用的目录字段（客户端请求的模型名 → 上游 UUID）。
pub struct TaskTarget {
    /// 上游模型 UUID（建任务的 `model_id`）
    pub model_id: String,
    /// 上游模型名（日志与报错文案用）
    pub model: String,
}

/// 按客户端请求的名字反查建任务参数。
///
/// ── 判据链（都是精确匹配，不做模糊 / 默认回落）──────────────────
///   1. 目录 id（`{provider}/{model}`，客户端点名的就是这个）—— 主判据；
///   2. 上游真名 `model`（客户端可能直接写上游名）；
///   3. 展示名 `name`；
///   4. `upstreamId`（UUID，排障时可能直接点）。
/// 全部大小写不敏感。取到的条目必须带**非空** `upstreamId`（没有 UUID 就建不出
/// 任务），否则视为查不到 —— 返回 `None` 让调用方报可读错误，而不是拿空串去撞
/// 上游的 400。
///
/// ── 为什么不做参考实现那样的「模糊匹配 + 默认模型回落」────────────
/// 参考的 `resolveModel` 在找不到时回落到 `is_default` / `models[0]`。网关侧
/// 不能这么做：入口校验已按**广告视图**解析过模型名，走到转发这一步时名字必然
/// 是清单里的某一个；把「找不到」静默换成另一个模型，就是「选了 A、用的是 B」
/// —— 本仓对这类静默错误一律报错。
pub fn resolve_task_model(requested: &str) -> Option<TaskTarget> {
    let requested = requested.trim();
    if requested.is_empty() {
        return None;
    }
    let models = current();
    let matched = models
        .iter()
        .find(|item| text_of(item, "id").eq_ignore_ascii_case(requested))
        .or_else(|| models.iter().find(|item| text_of(item, "model").eq_ignore_ascii_case(requested)))
        .or_else(|| models.iter().find(|item| text_of(item, "name").eq_ignore_ascii_case(requested)))
        .or_else(|| {
            models
                .iter()
                .find(|item| text_of(item, "upstreamId").eq_ignore_ascii_case(requested))
        })?;
    let model_id = text_of(matched, "upstreamId");
    if model_id.is_empty() {
        return None;
    }
    Some(TaskTarget { model_id, model: text_of(matched, "model") })
}

/// 目录里找不到模型时的可读错误（转发入口与目录刷新共用一条文案）。
pub fn missing_model_error(requested: &str) -> Error {
    Error::http(
        503,
        format!("MonkeyCode 模型目录里找不到模型「{requested}」：请在模型管理页刷新清单后重试"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_mapping_matches_the_aggregate_shape() {
        let payload = json!({
            "code": 0,
            "data": { "models": [
                {
                    "id": "uuid-1", "provider": "siliconflow", "model": "Qwen/Qwen3.5-Plus",
                    "display_name": "通义千问 3.5", "interface_type": "openai_chat",
                    "context_limit": 131072, "output_limit": 8192,
                    "is_free": true, "is_default": true, "thinking_enabled": true
                },
                // 没有 model 的条目必须跳过（建不出任务）
                { "id": "uuid-2", "provider": "x" }
            ] }
        });
        let models = parse_models(&payload);
        assert_eq!(1, models.len());
        let item = models.first().cloned().unwrap_or(Value::Null);
        assert_eq!("siliconflow/Qwen/Qwen3.5-Plus", item["id"].as_str().unwrap_or(""));
        assert_eq!("通义千问 3.5", item["name"].as_str().unwrap_or(""));
        assert_eq!("uuid-1", item["upstreamId"].as_str().unwrap_or(""));
        assert_eq!("opencode", item["cliName"].as_str().unwrap_or(""));
        assert_eq!(131072, item["maxInputTokens"].as_i64().unwrap_or(0));
        assert_eq!(true, item["supportsReasoning"].as_bool().unwrap_or(false));
        assert_eq!(true, item["isDefault"].as_bool().unwrap_or(false));
        assert_eq!(true, item["isFree"].as_bool().unwrap_or(false));
        assert_eq!(false, item["supportsImages"].as_bool().unwrap_or(true));
    }

    #[test]
    fn parse_accepts_both_envelopes() {
        let flat = json!({ "models": [{ "id": "u", "model": "m" }] });
        assert_eq!(1, parse_models(&flat).len());
        let array = json!([{ "id": "u", "model": "m", "provider": "" }]);
        let first = parse_models(&array).first().cloned().unwrap_or(Value::Null);
        assert_eq!("m", first["id"].as_str().unwrap_or(""));
        assert!(parse_models(&Value::Null).is_empty());
    }

    #[test]
    fn missing_model_error_is_a_503() {
        let error = missing_model_error("x");
        assert_eq!(Some(503), error.status);
        assert!(error.message.contains("模型管理页"));
    }
}
