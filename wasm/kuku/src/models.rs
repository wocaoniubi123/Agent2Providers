//! KukuAI 模型目录：静态兜底 + 远程刷新（`/wenchain/genflowpro/model/list`）。
//!
//! ── 为什么有两层（与 native `kuku/models.rs` 同一结构）────────
//!   1. **静态兜底**：kuku2api 2026-09-13 实测的 `MODEL_IDS`（上游模型接口响应体
//!      的 `model_name` 集合，13 个）。离线时 `/v1/models` 也有清单可列，未知模型名
//!      照样**显式回退 `auto`**（不静默降级）；
//!   2. **远程刷新**：上游清单会变（新增模型 / 下线），`GET /wenchain/genflowpro/
//!      model/list`（带会话三件套）拉最新列表。TTL 10 分钟，`force = true` 跳过。
//!      注意路径是 `model/list`（2026-10-07 依据 app.asar + 真实凭证实测；
//!      旧路径 `model_list` 已废弃返回 404），响应是顶层 `{status, data}` 包络
//!      （与余额接口同款，不是 `errno` 顶层）。
//!
//! ── 缓存载体：宿主会话存储 ──────────────────────────────────
//! native 用进程级 `Mutex<Option<RemoteCatalog>>`；wasm 实例一次调用一个沙箱，
//! 静态不跨请求，所以改用 `sdk::session_*`（`sessions.v1`）。键是全局的（不带账号），
//! 与 native 的进程级全局缓存同一语义：模型目录本身是上游账号同一份清单。
//!
//! ── 条目形态 ────────────────────────────────────────────────
//! 聚合层只读 `id` / `name`。kuku 的模型 id 就是上游 `model_name`
//! （`gateway-deepseek-v4.1-flash-tencent` 这类长名与别家天然不撞，客户端可直接
//! 点名；`auto` 是上游自动选路）。本模块只给 id + name，其余能力字段（图像 /
//! 思考 / 工具）上游不声明，不给假值。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account::{self, KukuCredentials};
use super::session;
use super::upstream;

/// 远程目录缓存有效期（10 分钟，与 native / raccoon 同值）
const CATALOG_CACHE_TTL_MS: i64 = 10 * 60_000;

/// 目录缓存键（宿主会话存储）
const CACHE_KEY: &str = "kuku:model-catalog";

/// 静态兜底清单（kuku2api 实测的 `MODEL_IDS`，2026-09-13）。
pub const FALLBACK_MODEL_IDS: [&str; 13] = [
    "auto",
    "gateway-deepseek-v4.1-flash-tencent",
    "gateway-deepseek-v4-pro-tencent",
    "gateway-deepseek-v4-flash-tencent",
    "gateway-glm-5.3-flash",
    "glm-5.3",
    "gateway-glm-5.2",
    "gateway-glm-5.1-kuaishou",
    "ernie-5.1",
    "ms-kimi-k3",
    "gateway-kimi-k2.7-code-tencent",
    "gateway-kimi-k2.6",
    "ali-minimax/minimax-m3",
];

/// 远程目录的本地快照。
#[derive(Clone, Debug, Default)]
struct Catalog {
    models: Vec<Value>,
    fetched_at_ms: i64,
}

/// 一条清单条目（聚合层口径：id + name）。
fn listing_entry(model_name: &str) -> Value {
    json!({ "id": model_name, "name": model_name })
}

/// 静态兜底清单。
fn fallback_models() -> Vec<Value> {
    FALLBACK_MODEL_IDS.iter().map(|id| listing_entry(id)).collect()
}

/// 读缓存快照（读不到给空快照）。
fn cached() -> Catalog {
    let Ok(value) = sdk::session_get(CACHE_KEY) else {
        return Catalog::default();
    };
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| item.get("id").and_then(Value::as_str).is_some_and(|id| !id.trim().is_empty()))
        .collect();
    let fetched_at_ms = value.get("fetched_at").and_then(Value::as_i64).unwrap_or(0);
    Catalog { models, fetched_at_ms }
}

/// 写缓存快照（写失败不影响本次结果）。
fn store(models: &[Value], fetched_at_ms: i64) {
    let _ = sdk::session_put(
        CACHE_KEY,
        json!({ "models": models, "fetched_at": fetched_at_ms }),
        CATALOG_CACHE_TTL_MS * 2,
    );
}

/// `models.list`：远程优先，未拉到 / 未刷过用静态兜底。
pub fn list() -> Value {
    let catalog = cached();
    let remote = !catalog.models.is_empty();
    let models = if remote { catalog.models } else { fallback_models() };
    json!({
        "models": models,
        "meta": {
            "remote": remote,
            "refreshed_at": catalog.fetched_at_ms,
        },
    })
}

/// 当前清单条数（`catalog::unchanged` 要它）。
fn count_now() -> usize {
    let catalog = cached();
    if catalog.models.is_empty() {
        FALLBACK_MODEL_IDS.len()
    } else {
        catalog.models.len()
    }
}

/// `models.refresh`：刷新远程目录。
///
/// ── 失败为什么不返回错误 ────────────────────────────────────
/// 与 native 同一取舍：目录刷新失败时**保留现有清单**、把原因放进返回体
/// （`catalog::failed`），编排层据此提示「已保留旧清单」，而不是让整个
/// 账号进入错误态（模型清单过期不影响已有模型继续对话）。
pub fn refresh(force: bool) -> Result<Value> {
    // 凭证解析失败（没账号）→「没刷」而不是「失败」（native 同口径）
    let credentials = match account::current() {
        Ok(credentials) => credentials,
        Err(_) => return Ok(sdk::catalog::unchanged(count_now())),
    };
    if !force {
        let catalog = cached();
        if !catalog.models.is_empty() && sdk::now().saturating_sub(catalog.fetched_at_ms) < CATALOG_CACHE_TTL_MS {
            return Ok(sdk::catalog::unchanged(catalog.models.len()));
        }
    }
    match fetch_remote(&credentials) {
        Ok(models) => {
            let fetched_at = sdk::now();
            store(&models, fetched_at);
            Ok(sdk::catalog::refreshed(models))
        }
        Err(error) => Ok(sdk::catalog::failed(&error.message)),
    }
}

/// 真打一次上游目录接口。
fn fetch_remote(credentials: &KukuCredentials) -> Result<Vec<Value>> {
    let triple = session::ensure(credentials, false)?;
    // 客户端路径是 `/wenchain/genflowpro/model/list`（2026-10-07 依据客户端实现
    // 确认 + 真实凭证实测；旧路径 `model_list` 已废弃返回 404）。
    let url = format!(
        "{}/wenchain/genflowpro/model/list?{}{}",
        upstream::BASE_URL,
        upstream::WEB_QUERY,
        session::token_query(&triple)
    );
    let value = upstream::get_json(&url, &upstream::headers(&credentials.cookie_header()))?;
    // 顶层包络（与余额接口同款，2026-10-07 实测）：判据在 status.code，
    // 业务字段在 data（`errno` 顶层是旧版 / 其他接口的形态）。
    let status = value.get("status").cloned().unwrap_or(Value::Null);
    let code = status.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        let message = status
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(Error::http(
            502,
            format!("KukuAI 模型目录接口失败（status.code={code}：{message}）"),
        ));
    }
    let names = value
        .get("data")
        .map(extract_model_names)
        .unwrap_or_default();
    let mut models: Vec<Value> = Vec::new();
    for name in names {
        if models
            .iter()
            .any(|item| item.get("id").and_then(Value::as_str) == Some(name.as_str()))
        {
            continue;
        }
        models.push(listing_entry(&name));
    }
    if models.is_empty() {
        // 认不出结构 → 回落静态兜底（保底：至少 auto 可用）
        models = fallback_models();
    }
    Ok(models)
}

/// 从上游响应里宽松提取模型名集合（`model/list` 的响应结构未公开，容错读取：
/// 递归找 `model_name` / `modelName` / `modelId` 字符串字段；认不出就空集，
/// 由调用方回落静态兜底）。
fn extract_model_names(value: &Value) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    collect_model_names(value, &mut names, 0);
    names.sort();
    names.dedup();
    names
}

fn collect_model_names(value: &Value, out: &mut Vec<String>, depth: usize) {
    // 深度上限：上游响应本不该很深，防的是异常响应把递归打穿
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if matches!(lower.as_str(), "model_name" | "modelname" | "modelid") {
                    if let Some(text) = child.as_str() {
                        let text = text.trim();
                        if !text.is_empty() {
                            out.push(text.to_string());
                            continue;
                        }
                    }
                }
                collect_model_names(child, out, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_model_names(item, out, depth + 1);
            }
        }
        _ => {}
    }
}

/// 把客户端请求的模型名归一成上游 `model_name`。
///
/// 接受 `auto` / `kuku/<name>` / 裸名；未知模型显式回退 `auto`（上游对未知名会
/// 静默降级，显式回退更清晰，与参考实现同一取舍）。
pub fn resolve_model(name: &str) -> String {
    let mut name = name.trim().to_string();
    if let Some(rest) = name.strip_prefix("kuku/") {
        name = rest.trim().to_string();
    }
    if name.is_empty() {
        return upstream::DEFAULT_MODEL.to_string();
    }
    let remote_known = cached()
        .models
        .iter()
        .any(|item| item.get("id").and_then(Value::as_str) == Some(name.as_str()));
    if remote_known || FALLBACK_MODEL_IDS.contains(&name.as_str()) {
        name
    } else {
        upstream::DEFAULT_MODEL.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_list_matches_metadata_default_models() {
        // metadata.json 的 default_models 与这张表必须同源：一处改了另一处漏改，
        // 界面上的「默认模型」就会和实际出站名不一致。
        let metadata: Value = serde_json::from_str(include_str!("metadata.json")).unwrap_or(Value::Null);
        let declared = metadata
            .get("default_models")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(FALLBACK_MODEL_IDS.len(), declared.len());
        for (index, id) in FALLBACK_MODEL_IDS.iter().enumerate() {
            let entry = declared.get(index).cloned().unwrap_or(Value::Null);
            assert_eq!(*id, entry.get("id").and_then(Value::as_str).unwrap_or_default());
        }
    }

    #[test]
    fn resolve_model_strips_prefix_and_falls_back() {
        assert_eq!("auto", resolve_model(""));
        assert_eq!("auto", resolve_model("   "));
        assert_eq!("glm-5.3", resolve_model("glm-5.3"));
        assert_eq!("glm-5.3", resolve_model("kuku/glm-5.3"));
        // 未知模型显式回退 auto（上游会静默降级，回退比降级可解释）
        assert_eq!("auto", resolve_model("no-such-model"));
        assert_eq!("auto", resolve_model("kuku/"));
    }

    #[test]
    fn unknown_names_are_ignored_when_extracting() {
        let value = json!({
            "data": {
                "model_list": [
                    { "model_name": "glm-5.3" },
                    { "modelName": "ernie-5.1" },
                    { "modelId": "glm-5.3" },
                    { "id": "should-not-count" }
                ]
            }
        });
        let names = extract_model_names(&value);
        assert_eq!(vec!["ernie-5.1".to_string(), "glm-5.3".to_string()], names);
    }
}
