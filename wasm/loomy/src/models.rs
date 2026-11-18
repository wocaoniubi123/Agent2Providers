//! Loomy 模型目录：`GET {集成网关}/api/v1/models`（OpenAI 格式）+ 宿主侧缓存。
//!
//! ── 上游形态（客户端 `electron/model-service.js` 的 `fetchModelsFromProvider`）──
//! 标准 OpenAI 形态 `{data:[{id, protocol, ...}]}`；目录带 `protocol` 决定推理走
//! Chat Completions 或 Anthropic Messages，缺省为 OpenAI。目录查询使用 session。
//!
//! 拉取失败时**不编造模型名**：Loomy 官方 imodel 网关没有内置兜底清单
//! （客户端 `BUILTIN_FALLBACK_MODELS` 为空表），这里如实报失败、保留旧清单。
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! Wasm 实例**每次调用后销毁**（见 SDK 的 `dispatch`），进程内静态变量活不过一次
//! 调用，所以缓存只能放在主程序：`models.list` 读 `catalog.get`（按账号的快照），
//! `models.refresh` 把新清单连同 `meta` 一起交回去由主程序落缓存。这与 native 侧重
//! 要的一点相同：**插件自己不落盘**，否则就是两套状态互相不一致。
//!
//! ── 能力位 ──────────────────────────────────────────────────
//! 思考 / 工具 / 图片 / 视频位都读上游条目的 `capabilities`（`reasoning` /
//! `function_calling` / `vision` / `input_modalities`，实测 2026-10 每个条目都
//! 带这四个键）。旧实现只按模型 id 判思考位（spark-x）、硬编码工具位 ——
//! 那会丢掉 GLM-5.3-Flash 等模型的 vision 声明，目录里全部显示成不支持图片。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::client;

/// 自动路径的缓存 TTL（与客户端自己的轮询周期同档）
const TTL_MS: i64 = 10 * 60 * 1000;

/// 模型列表路径（相对集成网关）
pub const MODELS_PATH: &str = "/api/v1/models";

/// 该模型 id 是不是思考模型（客户端只对 spark-x 挂 reasoning 能力位）
fn is_reasoning_model(id: &str) -> bool {
    id.eq_ignore_ascii_case("spark-x") || id.to_ascii_lowercase().contains("spark-x")
}

/// 从上游展示名里拆出**积分倍率**后缀（`(x3.0)` / `(x0.8)` / `（x12）`）。
///
/// ── 为什么倍率要从名字里拆（有实测依据，不是猜）────────────────
/// 上游 `/models` **没有**结构化的倍率字段，它把倍率拼在展示名尾部 ——
/// 实测（2026-10，真实账号拉下来的 11 条目录）：
/// `DeepSeek V4 Flash 0731 (x3.0)`、`GLM 5.3 Flash(x0.8)`、`Spark X2.5 (x0.1)`。
/// 而本网关的「倍率」列读的是 `credits`，不拆的话那一列永远显示 `—`。
///
/// 客户端自己也这么拆（`splitModelDisplayName`：末尾括号内容作为展示标签，
/// ASCII 与全角括号都认），这里跟随同一口径。与客户端唯一的差别：**只把
/// `x<数字>` 形态的括号算倍率** —— 其余标签（如「限时免费」）本网关没有承载
/// 字段，原样留在名字里，不静默丢弃信息。
fn split_rate_suffix(name: &str) -> (String, Option<String>) {
    let trimmed = name.trim_end();
    let (body, inner) = if let Some(body) = trimmed.strip_suffix(')') {
        match body.rfind('(') {
            Some(open) => (&body[..open], body[open + 1..].trim()),
            None => return (name.to_string(), None),
        }
    } else if let Some(body) = trimmed.strip_suffix('）') {
        match body.rfind('（') {
            Some(open) => (&body[..open], body[open + '（'.len_utf8()..].trim()),
            None => return (name.to_string(), None),
        }
    } else {
        return (name.to_string(), None);
    };
    let Some(number) = inner.strip_prefix('x').or_else(|| inner.strip_prefix('X')) else {
        return (name.to_string(), None);
    };
    let number = number.trim();
    if number.is_empty()
        || !number.chars().any(|ch| ch.is_ascii_digit())
        || !number.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
    {
        return (name.to_string(), None);
    }
    let cleaned = body.trim_end();
    if cleaned.is_empty() {
        return (name.to_string(), Some(format!("x{number}")));
    }
    (cleaned.to_string(), Some(format!("x{number}")))
}

/// 从上游 `capabilities` 对象里取布尔位（缺失 / 非布尔一律 false）
fn caps_bool(caps: Option<&serde_json::Map<String, Value>>, key: &str) -> bool {
    caps.and_then(|caps| caps.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// `capabilities.input_modalities` 数组里有没有指定模态（大小写不敏感）
fn caps_modal(caps: Option<&serde_json::Map<String, Value>>, modal: &str) -> bool {
    caps.and_then(|caps| caps.get("input_modalities"))
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|text| text.eq_ignore_ascii_case(modal))
            })
        })
}

/// 协议归一：只有 `anthropic` / `anthropic_messages` 算 Anthropic，其余走 Chat。
fn normalize_protocol(value: Option<&str>) -> &'static str {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("anthropic" | "anthropic_messages") => "anthropic",
        _ => "openai",
    }
}

/// 把一个 OpenAI 目录条目映射成聚合层认的形态
/// （键名对照网关的 `core/models/shape.rs::list_item`）。
fn map_entry(row: &Value) -> Option<Value> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let raw_name = row
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(id);
    let (name, rate) = split_rate_suffix(raw_name);
    let caps = row.get("capabilities").and_then(Value::as_object);
    let image_generation = row.get("type").and_then(Value::as_str) == Some("image")
        || row
            .get("output_modalities")
            .or_else(|| row.pointer("/capabilities/output_modalities"))
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("image")));
    let tool_call = !image_generation && (caps_bool(caps, "function_calling") || caps.is_none());
    let reasoning = !image_generation && (caps_bool(caps, "reasoning") || is_reasoning_model(id));
    let mut item = json!({
        "id": id,
        "name": name,
        "protocol": normalize_protocol(row.get("protocol").and_then(Value::as_str)),
        "supportsToolCall": tool_call,
        "supportsReasoning": reasoning,
    });
    if image_generation {
        item["kind"] = json!("image");
        item["output_modalities"] = json!(["image"]);
        item["supports_image_editing"] = json!(true);
        item["isDefault"] = json!(false);
    }
    if caps_bool(caps, "vision") || caps_modal(caps, "image") {
        if let Some(object) = item.as_object_mut() {
            object.insert("supportsImages".to_string(), Value::Bool(true));
        }
    }
    if caps_modal(caps, "video") {
        if let Some(object) = item.as_object_mut() {
            object.insert("supportsVideo".to_string(), Value::Bool(true));
        }
    }
    if let Some(rate) = rate {
        if let Some(object) = item.as_object_mut() {
            object.insert("credits".to_string(), Value::String(rate));
        }
    }
    // 上游给了上下文 / 输出上限就透传（键名取自客户端自己的规范化器
    // `normalizeFetchedModelMetadata` 读的那组，是上游字段名的一手依据）。
    if let Some(object) = item.as_object_mut() {
        let pick_number = |keys: &[&str]| -> Option<i64> {
            for key in keys {
                if let Some(value) = row.get(*key).and_then(Value::as_i64) {
                    if value > 0 {
                        return Some(value);
                    }
                }
            }
            None
        };
        if let Some(max_input) = pick_number(&[
            "context_length",
            "context_window",
            "input_token_limit",
            "max_input_tokens",
            "maxInputTokens",
        ]) {
            object.insert("maxInputTokens".to_string(), Value::from(max_input));
        }
        if let Some(max_output) = pick_number(&[
            "max_output_tokens",
            "max_completion_tokens",
            "max_tokens",
            "maxOutputTokens",
        ]) {
            object.insert("maxOutputTokens".to_string(), Value::from(max_output));
        }
    }
    Some(item)
}

/// 解析 `/models` 响应（OpenAI `{data:[...]}` 或裸数组）
pub fn parse(payload: &Value) -> Vec<Value> {
    let rows = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

/// 当前模型清单（主程序缓存的快照；没有时给空清单 + 未远程标记）。
pub fn cached() -> Value {
    let list = sdk::catalog::cached().unwrap_or(Value::Null);
    if list.is_object() && list.get("models").is_some_and(Value::is_array) {
        list
    } else {
        json!({ "models": [], "meta": { "remote": false, "refreshed_at": 0 } })
    }
}

/// 某个模型该走哪套协议（`"anthropic"` / `"openai"`；目录里没有该模型 → None）。
pub fn protocol_of(model: &str) -> Option<String> {
    let list = cached();
    let name = model.trim();
    list["models"].as_array()?.iter().find_map(|item| {
        let id = item.get("id").and_then(Value::as_str)?;
        id.eq_ignore_ascii_case(name)
            .then(|| normalize_protocol(item.get("protocol").and_then(Value::as_str)).to_string())
    })
}

/// 真打一次上游，返回可直接落缓存的清单（`{models, meta}`）。
///
/// 业务码口径与 native 一致：模型列表接口**不返回 `code`** 的形态是合法的
/// （`code` 为空串时放行），只有明确给了非 `000000` 的码才算失败。
pub fn fetch(session: &str) -> Result<Value> {
    let payload = client::token_request("GET", MODELS_PATH, session, None, "模型目录查询")?;
    let code = client::business_code(&payload);
    if !code.is_empty() && code != client::SUCCESS_CODE {
        return Err(Error::http(
            if client::is_auth_error_code(&code) { 401 } else { 502 },
            if client::is_auth_error_code(&code) {
                "Loomy 登录态已失效，无法查询模型目录（请重新登录）".to_string()
            } else {
                format!(
                    "Loomy 模型目录查询失败（code={code}）：{}",
                    client::upstream_message(&payload)
                )
            },
        ));
    }
    let models = parse(&payload);
    if models.is_empty() {
        return Err(Error::http(
            502,
            "Loomy 模型目录为空或格式不认识（保留现有清单）",
        ));
    }
    Ok(json!({
        "models": models,
        "meta": { "remote": true, "refreshed_at": sdk::now() },
    }))
}

/// 拉一次模型目录并返回给主程序落缓存。
///
/// `force = false`（自动路径）时 10 分钟 TTL 内早退为 `{refreshed:false}`；
/// `force = true`（用户手动刷新）真打上游。
///
/// ── 为什么失败也返回 `refreshed:false` 而不是抛错 ─────────────
/// 主程序的 `models.refresh` 契约是 `RefreshOutcome`（失败原因放 `message`），
/// 抛出错误会让界面只能显示一句泛化的 502。这与 native 侧 `RefreshOutcome::failed`
/// 同一个表达。
pub fn refresh(force: bool) -> Value {
    if !force {
        let previous = cached();
        let age = sdk::now().saturating_sub(previous["meta"]["refreshed_at"].as_i64().unwrap_or(0));
        let count = previous["models"].as_array().map(Vec::len).unwrap_or(0);
        if previous["meta"]["remote"] == true && count > 0 && (0..TTL_MS).contains(&age) {
            return json!({ "refreshed": false, "count": count });
        }
    }
    let session = match super::credentials::snapshot() {
        Ok(credentials) => credentials.session,
        Err(error) => return json!({ "refreshed": false, "count": 0, "message": error.message }),
    };
    match fetch(&session) {
        Ok(list) => {
            let count = list["models"].as_array().map(Vec::len).unwrap_or(0);
            json!({
                "refreshed": true,
                "count": count,
                "models": list["models"].clone(),
                "meta": list["meta"].clone(),
            })
        }
        Err(error) => json!({ "refreshed": false, "count": 0, "message": error.message }),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, split_rate_suffix};
    use agent2api_wasm_sdk::{json, Value};

    #[test]
    fn rate_suffix_splits_ascii_and_fullwidth_parentheses() {
        assert_eq!(
            split_rate_suffix("GLM 5.3 Flash(x0.8)"),
            ("GLM 5.3 Flash".to_string(), Some("x0.8".to_string()))
        );
        assert_eq!(
            split_rate_suffix("Spark X2.5 （x0.1）"),
            ("Spark X2.5".to_string(), Some("x0.1".to_string()))
        );
        // 非倍率标签原样留在名字里（本网关没有承载字段，不静默丢信息）
        assert_eq!(
            split_rate_suffix("DeepSeek V4 (限时免费)"),
            ("DeepSeek V4 (限时免费)".to_string(), None)
        );
        assert_eq!(split_rate_suffix("无括号模型"), ("无括号模型".to_string(), None));
    }

    #[test]
    fn parse_maps_protocol_and_capabilities() {
        let payload = json!({ "data": [
            {
                "id": "spark-x",
                "name": "Spark X2.5 (x0.1)",
                "protocol": "Anthropic",
                "capabilities": {
                    "reasoning": true,
                    "function_calling": true,
                    "vision": true,
                    "input_modalities": ["text", "image", "video"]
                },
                "context_length": 128000,
                "max_output_tokens": 8192
            },
            {
                "id": "glm5.3-flash",
                "name": "GLM 5.3 Flash(x0.8)",
                "capabilities": { "vision": true }
            },
            // 图片模型：不能带工具位，且要标 kind
            {
                "id": "loomy-image",
                "type": "image",
                "capabilities": {}
            },
            // 没有 id 的条目直接丢弃
            { "name": "坏条目" }
        ]});
        let rows = parse(&payload);
        assert_eq!(rows.len(), 3);

        let spark = &rows[0];
        assert_eq!(spark["protocol"], Value::String("anthropic".into()));
        assert_eq!(spark["name"], Value::String("Spark X2.5".into()));
        assert_eq!(spark["credits"], Value::String("x0.1".into()));
        assert_eq!(spark["supportsReasoning"], Value::Bool(true));
        assert_eq!(spark["supportsImages"], Value::Bool(true));
        assert_eq!(spark["supportsVideo"], Value::Bool(true));
        assert_eq!(spark["maxInputTokens"], Value::from(128000));
        assert_eq!(spark["maxOutputTokens"], Value::from(8192));

        let glm = &rows[1];
        // 缺 protocol → 默认 openai；缺 capabilities.function_calling → 工具位 false
        assert_eq!(glm["protocol"], Value::String("openai".into()));
        assert_eq!(glm["supportsToolCall"], Value::Bool(false));
        assert_eq!(glm["supportsImages"], Value::Bool(true));

        let image = &rows[2];
        assert_eq!(image["kind"], Value::String("image".into()));
        assert_eq!(image["supportsToolCall"], Value::Bool(false));
        assert_eq!(image["supportsReasoning"], Value::Bool(false));
    }

    #[test]
    fn parse_accepts_bare_array() {
        let rows = parse(&json!([{ "id": "a" }, { "id": "b" }]));
        assert_eq!(rows.len(), 2);
    }
}
