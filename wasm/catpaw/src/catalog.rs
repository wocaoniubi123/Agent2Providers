//! CatPaw 模型目录：远程拉取（`POST /api/agent/maas/model-types`）+ 静态表回落。
//!
//! ── 为什么上游有目录接口（native `catalog.rs` 的结论，原样保留）────
//! 桌面端 `modelTypesService` 里那句 `T('/api/agent/maas/model-types',
//! {tenant, scene, env})` 看着像 GET 的 query 参数，实际 `tenant/scene/env`
//! 是 **POST 的 JSON body**。而它的 base 域名是**桌面端直连域名**
//! `ai.catpaw.meituan.com` —— 与转发链路用的 `DEFAULT_BASE_URL` 同一个 host，
//! 凭证头也完全一致（`Cookie: X-Passport-Token`）。
//!
//! ── 静态表为什么还要留着 ──────────────────────────────────────
//! 远程目录是**锦上添花，不是替代**：
//!   - 目录拉取需要登录态（无凭证时上游 401），而转发本身也可能在没有目录时
//!     工作；
//!   - `MODELS` 表里的 `host_model_id` / `context_windows` 是**实测核对过**的
//!     上游数字 ID 与档位（`models.rs` 表头逐条记了证据），远程条目里上下文
//!     窗口藏在 `parameterDefinitions` 的 ENUM 里、形态更难直接消费。
//! 因此分工是：远程目录负责「有哪些模型、叫什么、倍率多少」这类会变的信息；
//! 静态表继续负责「上游数字 ID 与 context 档位」这类必须实测坐实的信息。
//!
//! ── 迁移到 wasm 后缓存落在哪 ─────────────────────────────────
//! native 用进程内 `RwLock<CatalogState>` 缓存（并声明重启后首轮必须真打上游）。
//! wasm 插件每次调用都可能换实例，进程内缓存不可靠；这里改成：
//!   - `models.refresh` 把清单**返回给宿主**（`sdk::catalog::refreshed`），
//!     由宿主保存；
//!   - `models.list` 读 `sdk::catalog::cached()`（宿主保存的那份）；
//!   - 宿主没有缓存时回落到静态表。
//! 15 分钟 TTL 的判定仍在这里做：读宿主缓存的 `meta.refreshed_at` 比较即可，
//! 失败**保留上一份成功结果**（不清空）—— 与 native 同一取向。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use super::account::Credentials;
use super::models::MODELS;
use super::upstream;

/// 目录路径（`modelTypesService-CPgwL2qX.js` 的路径常量）
const MODEL_TYPES_PATH: &str = "/api/agent/maas/model-types";

/// 远程清单缓存有效期（毫秒；上游桌面端自己用 5 分钟，我们放宽到 15 分钟）
const CACHE_TTL_MS: i64 = 15 * 60 * 1000;

/// 请求体：`{tenant, scene, env}` —— 桌面端的调用参数逐字照搬
/// （`tenant = 'CatDesk'`、`scene = 'CATX_APP'`、`env = 'EXTERNAL'`）。
///
/// 三个值都是常量而不是配置：它们是**客户端身份**的一部分，单独改一个没有语义。
fn request_body() -> Value {
    json!({
        "tenant": "CatDesk",
        "scene": "CATX_APP",
        "env": "EXTERNAL",
    })
}

/// 宿主保存的目录（`{models, meta}` 形态；没有缓存时返回 None）。
fn cached_state() -> Option<(Vec<Value>, i64)> {
    let value = sdk::catalog::cached().ok()?;
    let models = value.get("models").and_then(Value::as_array).cloned()?;
    if models.is_empty() {
        return None;
    }
    let refreshed_at = value
        .pointer("/meta/refreshed_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Some((models, refreshed_at))
}

/// 远程清单是否已就绪（聚合目录判「这家现在有没有可用清单」时用）
pub fn remote_models() -> Vec<Value> {
    cached_state().map(|(models, _)| models).unwrap_or_default()
}

/// 上次成功刷新时刻（毫秒；0 = 从未成功）
pub fn last_refreshed_at() -> i64 {
    cached_state().map(|(_, at)| at).unwrap_or(0)
}

/// `js_truthy`（`Boolean(x)`）：null/false/0/"" 为假，其余为真。
///
/// 上游的 `isAuto` 两种形态都给过：布尔与字符串 `"true"`。
fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|item| item != 0.0).unwrap_or(false),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// 按 id 或展示名找远程条目（大小写不敏感）。
///
/// ── 为什么要同时认展示名 ────────────────────────────────────
/// 聚合目录是**先比 id、再比展示名**的两轮判定，所以「客户端传展示名」在目录层
/// 是**放行**的（既有客户端行为，不得退化）。若这里只比 id，同一个名字就会
/// 「目录层认识、转发层不认识」—— `/v1/models` 里列着、请求却报 400。
pub fn find_remote(id: &str) -> Option<Value> {
    let wanted = id.trim().to_lowercase();
    if wanted.is_empty() {
        return None;
    }
    remote_models().into_iter().find(|item| {
        ["id", "name"].iter().any(|key| {
            item.get(*key)
                .and_then(Value::as_str)
                .map(|text| text.trim().to_lowercase() == wanted)
                .unwrap_or(false)
        })
    })
}

/// 当前清单里所有可转发的模型名（报错文案用）
pub fn known_ids() -> Vec<String> {
    list()
        .get("models")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 把一条上游条目归一成**聚合层认的形态**。
///
/// 字段名对齐网关 `core/models/shape.rs::list_item` 读的那些键
/// （`id` / `name` / `maxInputTokens` / `maxOutputTokens` / `supportsImages` /
/// `supportsReasoning` / `credits` / `supportsToolCall`）。
///
/// ── 为什么过滤 `USER_CUSTOM` ─────────────────────────────────
/// 上游目录里除了官方模型还有用户自建的模型（`provider === "USER_CUSTOM"`）。
/// 那些模型依赖客户端本地的 apiKey 配置，网关拿到它们既没有凭证也不该转发。
///
/// ── 为什么丢弃 auto 伪模型 ───────────────────────────────────
/// `extendedInfo.isAuto = "true"` 的那条是**档位入口**而不是真实模型
/// （实测它没有 `rateMultiplier`、没有 `parameterDefinitions`）。列进
/// `/v1/models` 会让客户端拿一个转不了发的名字。
fn normalize_entry(item: &Value) -> Option<Value> {
    let model_type_id = item.get("modelTypeId").and_then(Value::as_i64);
    let extended = item.get("extendedInfo");
    // auto 伪模型：`isAuto` 可能是布尔或字符串 `"true"`（上游两种都给过）
    if extended
        .and_then(|info| info.get("isAuto"))
        .map(js_truthy)
        .unwrap_or(false)
    {
        return None;
    }
    if item
        .get("provider")
        .and_then(Value::as_str)
        .map(|text| text.trim().eq_ignore_ascii_case("USER_CUSTOM"))
        .unwrap_or(false)
    {
        return None;
    }
    // 上游 id 取 `modelTypeName`（真实名字，如 `glm-5.3-flash`）——
    // `id` 是本地记录主键、`catPawModelType` 是数字的字符串形态，都不是名字
    let id = item
        .get("modelTypeName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)?;
    // 展示名优先中文 caption，回落 `description`（实测是英文展示名）
    let name = extended
        .and_then(|info| info.get("modelCaptionZhCN"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .or_else(|| {
            item.get("description")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| id.clone());
    // 倍率：`extendedInfo.rateMultiplier`，**字符串**形态（`"0.94"` / `"0.00"`），
    // 尾零是上游刻意保留的展示形态，转成数字再格式化会丢（`"0.00"` 会变成 `0`）
    let credits = extended
        .and_then(|info| info.get("rateMultiplier"))
        .map(rate_text)
        .unwrap_or_default();
    // 思考能力：`supportThinking` 是条目顶层布尔。**缺省时看参数的佐证** ——
    // 目录里带 `effort` 枚举（low/high/max）的模型一定支持思考档位。
    let supports_thinking = match item.get("supportThinking") {
        Some(value) => js_truthy(value),
        None => item
            .get("parameterDefinitions")
            .and_then(Value::as_array)
            .map(|definitions| {
                definitions.iter().any(|definition| {
                    definition.get("id").and_then(Value::as_str) == Some("effort")
                })
            })
            .unwrap_or(false),
    };
    let mut entry = json!({
        "id": id,
        "name": name,
        "supportsImages": item.get("supportImage").map(js_truthy).unwrap_or(false),
        "supportsReasoning": supports_thinking,
        "supportsToolCall": true,
        "kind": "chat",
    });
    let object = entry.as_object_mut()?;
    if let Some(model_type_id) = model_type_id {
        // 上游数字 modelType（转发必须用；远程条目自带）
        object.insert("modelType".to_string(), Value::from(model_type_id));
    }
    if !credits.is_empty() {
        object.insert("credits".to_string(), Value::String(credits));
    }
    // 上下文档位：上游藏在 `parameterDefinitions` 的 ENUM 里。
    // 取档位**上限**作为 `maxInputTokens`（客户端按它估算截断），
    // 默认档位另存 —— 与静态表的两个字段语义一致
    if let Some(definitions) = item.get("parameterDefinitions").and_then(Value::as_array) {
        if let Some(max_window) = enum_max(definitions, "context") {
            object.insert("maxInputTokens".to_string(), Value::from(max_window));
        }
        if let Some(default_window) = enum_default(definitions, "context") {
            object.insert("defaultContextWindow".to_string(), Value::String(default_window));
        }
    }
    Some(entry)
}

/// `extendedInfo.rateMultiplier` → 倍率文本。
///
/// 上游给的是字符串形式的浮点，**原样保留**：`"0.03"` 去掉尾零会变成 `0.03`
/// （同样）但 `"0.00"` 会变成 `0` —— 而 `0` 在界面上的语义是「免费」，
/// 与「上游没给」只差一个键的存在性。
fn rate_text(value: &Value) -> String {
    let plain = match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => number.to_string(),
        _ => return String::new(),
    };
    if plain.is_empty() || plain.parse::<f64>().is_err() {
        return String::new();
    }
    format!("x{plain} credits")
}

/// `parameterDefinitions[]` 里某个 ENUM 参数的档位上限（数值最大的一项）
fn enum_max(definitions: &[Value], id: &str) -> Option<i64> {
    let values = definitions
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(id))?
        .get("values")?
        .as_array()?;
    values
        .iter()
        .filter_map(|item| item.get("value"))
        .filter_map(|value| match value {
            Value::String(text) => text.trim().parse::<i64>().ok(),
            Value::Number(number) => number.as_i64(),
            _ => None,
        })
        .max()
}

/// `parameterDefinitions[]` 里某个 ENUM 参数的默认档位
fn enum_default(definitions: &[Value], id: &str) -> Option<String> {
    definitions
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(id))?
        .get("defaultValue")
        .and_then(Value::as_str)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// 拉取并落地远程目录（`models.refresh`）。
///
/// 三档返回值与 `RefreshOutcome` 的契约一致（成功 / 没刷 / 失败了）：
///   - `force = false` 时命中 TTL 直接早退（自动路径）；
///   - 用户手动点刷新时调用方传 `true` 绕过。
///
/// 凭证 = `Cookie: X-Passport-Token`，与转发链路**同一套**（`upstream::request_headers`
/// 复用，不另起一份）。
pub fn refresh(force: bool) -> Result<Value, super::errors::CatPawError> {
    if !force {
        if let Some((models, refreshed_at)) = cached_state() {
            let age = sdk::now().saturating_sub(refreshed_at);
            if refreshed_at > 0 && (0..CACHE_TTL_MS).contains(&age) {
                return Ok(sdk::catalog::unchanged(models.len()));
            }
        }
    }
    let credentials = match super::account::current() {
        Ok(credentials) => credentials,
        Err(_) => {
            // 没有登录态时上游必然 401，本家也拉不到目录。**不是错误**：
            // 报一条红色失败会让「还没配账号」的用户以为哪里坏了。
            super::logging::verbose("CatPaw 模型目录刷新跳过：没有可用登录态");
            return Ok(sdk::catalog::unchanged(static_list().len()));
        }
    };
    if credentials.token.trim().is_empty() {
        return Ok(sdk::catalog::unchanged(static_list().len()));
    }
    let payload = match fetch(&credentials) {
        Ok(payload) => payload,
        Err(error) => {
            // 401 单独给一句可操作的文案：这是最可能的一种失败，
            // 而「上游 HTTP 401」对用户没有信息量
            if error.status == 401 {
                return Ok(sdk::catalog::failed(
                    "CatPaw 登录态已失效，请在账号页重新导入或重新登录",
                ));
            }
            return Ok(sdk::catalog::failed(&error.message));
        }
    };
    let Some(entries) = payload.as_array() else {
        return Ok(sdk::catalog::failed("上游返回的模型目录不是数组"));
    };
    let models: Vec<Value> = entries.iter().filter_map(normalize_entry).collect();
    if models.is_empty() {
        return Ok(sdk::catalog::failed("上游返回的模型目录为空"));
    }
    let count = models.len();
    let mut value = sdk::catalog::refreshed(models);
    value["count"] = json!(count);
    Ok(value)
}

/// 真的打一次目录接口（失败由调用方决定「没刷」还是「失败」）。
fn fetch(credentials: &Credentials) -> Result<Value, super::errors::CatPawError> {
    let url = format!("{}{MODEL_TYPES_PATH}", upstream::base_url());
    let headers = upstream::request_headers(credentials, "application/json");
    let response = agent2api_wasm_sdk::http::open("POST", &url, headers, Some(&request_body()))
        .map_err(|error| {
            super::errors::CatPawError::upstream(format!("模型目录请求失败: {}", error.message))
        })?;
    let status = response.status;
    let bytes = response
        .bytes(2 * 1024 * 1024)
        .map_err(|error| super::errors::CatPawError::upstream(format!("模型目录读取失败: {}", error.message)))?;
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&bytes).trim().chars().take(300).collect::<String>();
        return Err(super::errors::CatPawError::http(
            status,
            if text.is_empty() {
                format!("模型目录返回 HTTP {status}")
            } else {
                format!("模型目录返回 HTTP {status}: {text}")
            },
        ));
    }
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    super::openai::unwrap_api_data(parsed)
}

/// 清单：**远程优先**，命中静态表时把静态表里实测坐实的数字 ID 与档位并进去。
///
/// ── 最后一道闸：没有上游数字 ID 的条目一律不广告 ──────────────
/// CatPaw 建会话**必须先有数字 `modelType`**（协议要求）。一条既没有远程
/// `modelTypeId`、静态表里也查不到的条目转发不了 —— 把它列进 `/v1/models`
/// 会造出「清单里有、请求却报 400」的自相矛盾。宁可少广告一个。
pub fn list() -> Value {
    let remote = remote_models();
    if remote.is_empty() {
        let models = static_list();
        return json!({
            "models": models,
            "meta": { "remote": false, "refreshed_at": 0 },
        });
    }
    let models: Vec<Value> = remote
        .into_iter()
        .filter_map(|mut entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(spec) = spec_of(&id) {
                if let Some(object) = entry.as_object_mut() {
                    // 静态表里的数字 ID 是**实测**过的；两者一致时以远程为准
                    // （它更新），但远程没给数字时用静态表的补上
                    object
                        .entry("modelType".to_string())
                        .or_insert_with(|| Value::from(spec.host_model_id));
                    if !object.contains_key("maxInputTokens") {
                        if let Some(window) = spec
                            .context_windows
                            .iter()
                            .filter_map(|text| text.parse::<i64>().ok())
                            .max()
                        {
                            object.insert("maxInputTokens".to_string(), Value::from(window));
                        }
                    }
                    if object
                        .get("name")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    {
                        object.insert("name".to_string(), Value::String(spec.name.to_string()));
                    }
                }
            }
            // 闸门：数字 ID 是转发的必要条件（远程或静态表，二者至少有一个）
            entry.get("modelType").and_then(Value::as_i64)?;
            Some(entry)
        })
        .collect();
    json!({
        "models": models,
        "meta": { "remote": true, "refreshed_at": last_refreshed_at() },
    })
}

/// 静态表形态的清单（远程不可用时的回落，也是 `list()` 的兜底）
fn static_list() -> Vec<Value> {
    MODELS
        .iter()
        .map(|model| {
            let mut entry = json!({
                "id": model.id,
                "name": model.name,
                "supportsImages": model.support_image,
                "supportsReasoning": model.support_thinking,
                "supportsToolCall": true,
                "kind": "chat",
                // 上游数字 modelType：转发必须用（客户端请求的模型名要反查它）
                "modelType": model.host_model_id,
            });
            if let Some(object) = entry.as_object_mut() {
                if let Some(window) = model
                    .context_windows
                    .iter()
                    .filter_map(|text| text.parse::<i64>().ok())
                    .max()
                {
                    object.insert("maxInputTokens".to_string(), Value::from(window));
                }
                if let Some(default) = model.default_context_window {
                    object.insert(
                        "defaultContextWindow".to_string(),
                        Value::String(default.to_string()),
                    );
                }
                // 静态表没有倍率（上游目录才有），键缺失 → 界面显示 `—`
            }
            entry
        })
        .collect()
}

/// 静态表里按 id 找条目（大小写/分隔符宽容，见 `models::find_model_entry`）
fn spec_of(id: &str) -> Option<&'static super::models::ModelSpec> {
    let wanted = super::models::normalize_model_name(id);
    MODELS.iter().find(|entry| {
        super::models::normalize_model_name(entry.id) == wanted
            || super::models::normalize_model_name(entry.name) == wanted
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_entry_maps_fields_and_filters_auto() {
        let item = json!({
            "modelTypeName": "glm-5.3-flash",
            "modelTypeId": 91,
            "description": "GLM-5.3-Flash",
            "supportImage": true,
            "supportThinking": true,
            "extendedInfo": { "rateMultiplier": "0.94", "modelCaptionZhCN": "GLM-5.3-Flash" },
            "parameterDefinitions": [
                { "id": "context", "values": [{"value":"204800"},{"value":"1024000"}], "defaultValue": "1024000" }
            ]
        });
        let entry = normalize_entry(&item).unwrap_or(Value::Null);
        assert_eq!(entry["id"], json!("glm-5.3-flash"));
        assert_eq!(entry["modelType"], json!(91));
        assert_eq!(entry["credits"], json!("x0.94 credits"));
        assert_eq!(entry["maxInputTokens"], json!(1024000));
        assert_eq!(entry["defaultContextWindow"], json!("1024000"));

        let auto = json!({ "modelTypeName": "auto", "extendedInfo": { "isAuto": "true" } });
        assert!(normalize_entry(&auto).is_none());
        let custom = json!({ "modelTypeName": "mine", "provider": "USER_CUSTOM" });
        assert!(normalize_entry(&custom).is_none());
    }

    #[test]
    fn static_list_always_carries_model_type() {
        for entry in static_list() {
            assert!(entry.get("modelType").and_then(Value::as_i64).is_some());
        }
    }
}
