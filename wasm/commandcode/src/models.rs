//! Command Code 模型目录：`GET /provider/v1/models` + 5 分钟缓存 + 内置兜底清单。
//!
//! ── 上游形态 ────────────────────────────────────────────────
//! ```text
//!   { "data": [ { "id": "deepseek/deepseek-v4-flash", "object": "model", … } ] }
//! ```
//! 只依赖 `data[].id`，并且**失败时回落到内置清单**（26 项）—— 绝不把目录
//! 清空（清了会让「这家有账号但模型列表是空的」）。
//!
//! ── 模型 id 的命名规律 ──────────────────────────────────────
//! Anthropic / OpenAI 系**无前缀**，开源系**带厂商前缀**。id 原样透传：
//! 本家不做任何名称重写。
//!
//! ── 能力位的来源（为什么只有图片位是「点名给」的）─────────────────
//! 上游目录**不返回**结构化能力位。工具调用是本家 wire 协议的一等公民
//! （`params.tools` 总是下发）→ true；思考同样是一等字段 → true。
//! 图片位**没有目录依据**，只有规格点名的几支给 true，其余 conservative
//! false —— 报错方向只能选「少报」。
//!
//! ── 缓存为什么不落盘（与网关版的一处差别）──────────────────────
//! 网关版把目录写进 `catalog_cache`（进程重启后读回）。插件侧没有那个设施，
//! 而且**不需要**：网关自己会缓存插件返回的清单（`catalog.get` 就是它），插件
//! 进程重启后重新拉一次即可。少一层落盘就少一处「插件和网关的缓存不一致」。
//! 因此 `list()` 的「当前清单」= 宿主的 `catalog.get`，插件只负责**拉取 + 归一**，
//! 刷新结果经 `catalog.refreshed(..)` 交回宿主。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, json, Value};

use super::{credentials, endpoints, util};

/// 自动路径的缓存 TTL（与 native 同值）
const TTL_MS: i64 = 5 * 60 * 1000;

/// 内置兜底清单（id + 展示名）。
///
/// 上游拉不到时的保底：它同时是「没有账号时点什么」的那张表。
/// id 是转发时直接下发的名字，改一个字母就等于换模型，逐字保留。
const FALLBACK_MODELS: [(&str, &str); 26] = [
    ("claude-sonnet-4-6", "Claude Sonnet 4.6"),
    ("claude-opus-4-8", "Claude Opus 4.8"),
    ("claude-opus-4-7", "Claude Opus 4.7"),
    ("claude-haiku-4-5-20251001", "Claude Haiku 4.5"),
    ("gpt-5.5", "GPT-5.5"),
    ("gpt-5.4", "GPT-5.4"),
    ("gpt-5.4-mini", "GPT-5.4 Mini"),
    ("gpt-5.3-codex", "GPT-5.3 Codex"),
    ("deepseek/deepseek-v4-pro", "DeepSeek V4 Pro"),
    ("deepseek/deepseek-v4-flash", "DeepSeek V4 Flash"),
    ("moonshotai/Kimi-K2.6", "Kimi K2.6"),
    ("moonshotai/Kimi-K2.5", "Kimi K2.5"),
    ("zai-org/GLM-5.1", "GLM 5.1"),
    ("zai-org/GLM-5", "GLM 5"),
    ("MiniMaxAI/MiniMax-M3", "MiniMax M3"),
    ("MiniMaxAI/MiniMax-M2.7", "MiniMax M2.7"),
    ("MiniMaxAI/MiniMax-M2.5", "MiniMax M2.5"),
    ("Qwen/Qwen3.6-Max-Preview", "Qwen 3.6 Max Preview"),
    ("Qwen/Qwen3.6-Plus", "Qwen 3.6 Plus"),
    ("Qwen/Qwen3.7-Max", "Qwen 3.7 Max"),
    ("stepfun/Step-3.7-Flash", "Step 3.7 Flash"),
    ("stepfun/Step-3.5-Flash", "Step 3.5 Flash"),
    ("xiaomi/mimo-v2.5-pro", "MiMo V2.5 Pro"),
    ("xiaomi/mimo-v2.5", "MiMo V2.5"),
    ("google/gemini-3.5-flash", "Gemini 3.5 Flash"),
    ("google/gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite"),
];

/// 这个模型 id 是否声明支持图片输入（**只有规格点名的几支**）
fn supports_images(id: &str) -> bool {
    let lowered = id.to_lowercase();
    lowered.contains("vision") || lowered.contains("mimo-v2.5") || lowered.contains("kimi-k2.5")
}

/// 把一个上游目录条目映射成聚合层认的形态
fn map_entry(row: &Value) -> Option<Value> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let name = row
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(id);
    Some(json!({
        "id": id,
        "name": name,
        "supportsToolCall": true,
        "supportsReasoning": true,
        "supportsImages": supports_images(id),
    }))
}

/// 内置兜底清单的聚合层形态
pub fn fallback_models() -> Vec<Value> {
    FALLBACK_MODELS
        .iter()
        .map(|(id, name)| {
            json!({
                "id": id,
                "name": name,
                "supportsToolCall": true,
                "supportsReasoning": true,
                "supportsImages": supports_images(id),
            })
        })
        .collect()
}

/// 解析 `/provider/v1/models` 的响应（`{data:[…]}` 或裸数组）
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let rows = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

/// 当前模型清单（宿主目录 → 内置兜底；永远非空）
pub fn list() -> Value {
    let catalog = sdk::catalog::cached().unwrap_or(Value::Null);
    let remote: Vec<Value> = catalog
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if remote.is_empty() {
        // 没有远程清单 = 内置兜底（`remote: false` 让界面显示「内置」）
        return json!({
            "models": fallback_models(),
            "meta": { "remote": false, "refreshed_at": 0 },
        });
    }
    let meta = if catalog.get("meta").is_some_and(Value::is_object) {
        catalog["meta"].clone()
    } else {
        json!({ "remote": true, "refreshed_at": 0 })
    };
    json!({ "models": remote, "meta": meta })
}

/// 拉一次模型目录并交回宿主（`catalog.refreshed`）。
///
/// `force = false`（自动路径）时 5 分钟 TTL 内早退为 `unchanged()`；
/// `force = true`（用户手动刷新）真打上游。
///
/// 失败时**保留现有清单**，返回 `failed(原因)` 让手动路径如实汇报。
pub fn refresh(force: bool) -> Value {
    // 没有账号：用内置清单刷新（与 native 的同一条分支同一语义）。
    // native 在这里返回 `unchanged()`（网关知道「用户还没添加账号」），wasm 侧
    // 插件拿不到那个事实，而它手里有一份**可用的内置兜底清单** —— 直接用它
    // 刷新比静默跳过更有价值：界面能看到 26 个可点选的模型。
    let record = match sdk::account() {
        Ok(record) => record,
        Err(_) => {
            // 没有账号 = 拿不到远程目录。**不能**伪造一个 refreshed ——
            // 网关 `api/models.rs` 在 `refreshed: true` 时要求
            // `meta.remote == true` 且 `count == models.len()`，伪造会被判
            // 「插件刷新缺少同次真实远程模型快照，已保留旧清单」（2026-11-19 实测踩过）。
            // 如实报失败，并把「内置清单仍可用」写进文案。
            return sdk::catalog::failed(&format!(
                "没有可用账号，无法刷新 Command Code 模型目录；内置 {} 个模型仍可直接使用",
                fallback_models().len()
            ));
        }
    };
    let api_key = match credentials::api_key_of(&record["secret"]) {
        Ok(key) => key,
        // 账号存在但凭证坏了：如实报失败（不是「没有账号」）
        Err(reason) => return sdk::catalog::failed(&reason),
    };

    let now = util::now_ms();
    if !force {
        let previous = list();
        let age = now.saturating_sub(previous["meta"]["refreshed_at"].as_i64().unwrap_or(0));
        let count = previous["models"].as_array().map(Vec::len).unwrap_or(0);
        if previous["meta"]["remote"] == true && (0..TTL_MS).contains(&age) {
            return sdk::catalog::unchanged(count);
        }
    }

    let mut headers = endpoints::cli_headers();
    headers.extend(endpoints::auth_headers(&api_key));
    let response = match http::open(
        "GET",
        &endpoints::url(endpoints::MODELS_PATH),
        util::headers_value(&headers),
        None,
    ) {
        Ok(response) => response,
        Err(error) => {
            return sdk::catalog::failed(&format!(
                "Command Code 模型目录查询失败：{}（保留现有清单）",
                error.message
            ))
        }
    };
    if !(200..300).contains(&response.status) {
        let status = response.status;
        return sdk::catalog::failed(&format!(
            "Command Code 模型目录返回 HTTP {status}（保留现有清单）"
        ));
    }
    let payload = match response.json() {
        Ok(payload) => payload,
        Err(error) => {
            return sdk::catalog::failed(&format!(
                "Command Code 模型目录响应无法解析：{}（保留现有清单）",
                error.message
            ))
        }
    };
    let models = parse_models(&payload);
    if models.is_empty() {
        return sdk::catalog::failed("Command Code 模型目录为空或格式不认识（保留现有清单）");
    }
    sdk::catalog::refreshed(models)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_list_has_26_entries_and_declares_capabilities() {
        let models = fallback_models();
        assert_eq!(models.len(), 26);
        for model in &models {
            assert!(model["id"].as_str().is_some_and(|id| !id.is_empty()));
            assert_eq!(model["supportsToolCall"], json!(true));
            assert_eq!(model["supportsReasoning"], json!(true));
            assert!(model["supportsImages"].is_boolean());
        }
        // 规格点名的三支图片模型
        let vision: Vec<&str> = models
            .iter()
            .filter(|model| model["supportsImages"] == json!(true))
            .filter_map(|model| model["id"].as_str())
            .collect();
        assert_eq!(
            vision,
            vec![
                "moonshotai/Kimi-K2.5",
                "xiaomi/mimo-v2.5-pro",
                "xiaomi/mimo-v2.5"
            ]
        );
    }

    #[test]
    fn parse_accepts_wrapped_and_bare_arrays() {
        let wrapped = parse_models(&json!({
            "data": [
                { "id": "gpt-5.5" },
                { "id": "  ", "name": "空 id" },
                { "id": "claude-sonnet-4-6", "name": "Claude Sonnet 4.6" },
            ],
        }));
        assert_eq!(wrapped.len(), 2);
        assert_eq!(wrapped[0]["name"], json!("gpt-5.5"));
        assert_eq!(wrapped[1]["name"], json!("Claude Sonnet 4.6"));
        let bare = parse_models(&json!([{ "id": "gpt-5.4" }]));
        assert_eq!(bare.len(), 1);
        assert_eq!(parse_models(&json!({})).len(), 0);
    }

    #[test]
    fn images_are_only_declared_for_the_named_families() {
        assert!(supports_images("moonshotai/Kimi-K2.5"));
        assert!(supports_images("xiaomi/mimo-v2.5"));
        assert!(supports_images("some-vision-model"));
        assert!(!supports_images("gpt-5.5"));
        assert!(!supports_images("moonshotai/Kimi-K2.6"));
    }
}
