//! Qoder 模型目录（native `models.rs` 的单站点裁剪版）。
//!
//! ── 清单从哪来 ──────────────────────────────────────────────
//!   1. **静态兜底**：`metadata.json` 里的 `default_models`（那是照客户端内置
//!      抄的 Qoder 中国版清单）。启动即可用，网络不通 / 没账号时 `/v1/models`
//!      仍然有内容。
//!   2. **远程刷新**：`GET {gateway}algo/api/v2/model/list?Encode=1`（COSY 签名，
//!      缓存 1 小时）。结果由宿主目录缓存（`catalog.get`）持有，进程重启后仍在。
//!
//! ── 千问办公那套分支为什么不见了 ───────────────────────────
//! native 里还有 `qwork` 场景、`enable` 全量保留、`display_name` 补宽字段等
//! 分支，那些只服务 `qwenwork*` 两个 id（本包不申报）。Qoder 中国版的规则就
//! 是：读 `chat` 场景、再补 `app` 独有的 OpenAI 格式模型，同 key 以 `chat`
//! 为准，`enable` 只表示账号权益、保留未启用条目。
//!
//! ── 可见性不能读上游 `enable`（2026-10-17 修正，原样保留）──────────
//! 早先把 `enable` 当可见性判据是**错的**，实测数据否掉了它：一个普通账号拉回
//! 的目录里 17 条只有 `Qwen3.8-Flash` 是 `enable: true`，其余（`GLM-5.3` /
//! `Kimi-K3` / `DeepSeek-V4-Pro` …）全是 `false` —— 而它们明明出现在官方客户端
//! 的模型列表里。`enable` 的语义是「当前账号当前套餐能不能用」，是逐账号的权益
//! 位，不是「客户端展不展示」。所以可见性继续用「世代 / 档位别名」判据。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::context;
use super::cosy::{self, CosyIdentity};
use super::credentials::Credentials;
use super::protocol::truthy;
use super::site;

/// 远程目录缓存有效期（源实现 `CACHE_TTL_MS`：1 小时）
const CACHE_TTL_MS: i64 = 60 * 60 * 1000;

/// 目录条目没给上下文长度时的兜底
const DEFAULT_CONTEXT_WINDOW: i64 = 200_000;

/// 本站点的静态兜底清单（`metadata.json` 的 `default_models`）。
///
/// ── 为什么不在这里再抄一份表 ────────────────────────────────
/// 这份表已经作为 `metadata.json` 的 `default_models` 落在包里（宿主启动时
/// 会读它做初始目录），native 那张 CN 表与它逐条相同（id / upstreamKey /
/// enabled / efforts / vision / credits / visibility 都一致）。再抄一份等于
/// 两处事实源 —— 改一处忘另一处时，界面与转发会看到两个不同的清单。
pub fn fallback() -> Vec<Value> {
    super::metadata()["default_models"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// 宿主目录缓存里的远程清单（没有则空）
fn remote() -> Vec<Value> {
    sdk::catalog::cached()
        .ok()
        .and_then(|cached| cached["models"].as_array().cloned())
        .unwrap_or_default()
}

/// 当前生效的清单：远程优先，否则静态兜底。
pub fn list() -> Vec<Value> {
    let mut models = remote();
    if models.is_empty() {
        models = fallback();
    }
    for model in models.iter_mut() {
        if let Some(object) = model.as_object_mut() {
            object.insert(
                "providerId".to_string(),
                Value::String(site::PROVIDER_ID.to_string()),
            );
        }
    }
    models
        .into_iter()
        .filter(|model| model.get("id").and_then(Value::as_str).is_some_and(|id| !id.is_empty()))
        .collect()
}

/// 把客户端的模型名解析成「上游标识 + 模型配置」。
///
/// ── 匹配顺序（与 native `catalog::providers_for_model` 同口径）────
/// 先按 `id` 全等（忽略大小写），再按 `name` 全等，最后按 `upstreamKey`。
pub fn resolve(model_id: &str) -> Option<Value> {
    let wanted = model_id.trim().to_lowercase();
    if wanted.is_empty() {
        return None;
    }
    let models = list();
    for key in ["id", "name", "upstreamKey"] {
        if let Some(found) = models.iter().find(|model| {
            model
                .get(key)
                .and_then(Value::as_str)
                .map(|text| text.trim().to_lowercase() == wanted)
                .unwrap_or(false)
        }) {
            return Some(found.clone());
        }
    }
    // 远程目录里没有时再查一遍静态兜底（覆盖「远程清单缺这一条」的情形）
    fallback().into_iter().find(|model| {
        ["id", "name", "upstreamKey"].iter().any(|key| {
            model
                .get(*key)
                .and_then(Value::as_str)
                .map(|text| text.trim().to_lowercase() == wanted)
                .unwrap_or(false)
        })
    })
}

/// `models.list` 的应答（三档语义：远程 / 兜底）。
pub fn list_response() -> Result<Value> {
    let cached = sdk::catalog::cached().unwrap_or(Value::Null);
    let models = list();
    let is_remote = cached["models"]
        .as_array()
        .is_some_and(|items| !items.is_empty());
    Ok(json!({
        "models": models,
        "meta": {
            "remote": is_remote,
            "refreshed_at": if is_remote { cached["meta"]["refreshed_at"].clone() } else { json!(0) },
        },
    }))
}

/// 拉取并返回远程目录（结果交给宿主缓存）。
///
/// `force = false` 时命中 TTL 直接早退（自动路径）；用户手动点刷新时调用方传
/// `true` —— 缓存该不该复用只由**谁发起**决定。
///
/// ── 没有账号时为什么返回「没刷」而不是「失败」──────────────────
/// 手动刷新的逐家结果会显示在模型页上。一个从不用 Qoder 的用户点刷新时，
/// 报一条红色失败会让他以为哪里坏了 —— 而事实只是「这家没有可刷的东西」。
/// 三档语义里这正是 `unchanged`（skipped）的定义：**不是错误**。自动路径每次
/// 拉目录/启动都会走到这里，所以也只回 unchanged。
pub fn refresh(force: bool) -> Result<Value> {
    let credentials = match super::refresh::snapshot() {
        Ok((_, credentials)) => credentials,
        Err(_) => return Ok(json!({ "refreshed": false, "count": 0 })),
    };
    let credentials = if credentials.expiring() {
        super::refresh::ensure_fresh(true)?
    } else {
        credentials
    };
    if !force {
        let cached = sdk::catalog::cached().unwrap_or(Value::Null);
        let age = sdk::now() - cached["meta"]["refreshed_at"].as_i64().unwrap_or(0);
        if cached["models"].as_array().is_some_and(|items| !items.is_empty())
            && (0..CACHE_TTL_MS).contains(&age)
        {
            return Ok(json!({
                "refreshed": false,
                "count": cached["models"].as_array().map(Vec::len).unwrap_or(0),
            }));
        }
    }
    let payload = fetch(&credentials)?;
    let models = parse_catalog(&payload);
    if models.is_empty() {
        return Err(Error::http(502, "上游返回的模型目录为空"));
    }
    Ok(json!({
        "refreshed": true,
        "count": models.len(),
        "models": models,
        "meta": { "remote": true, "refreshed_at": sdk::now() },
    }))
}

/// 打一次目录请求（COSY 签名；GET 的签名体为空）。
fn fetch(credentials: &Credentials) -> Result<Value> {
    let url = site::gateway_url("algo/api/v2/model/list?Encode=1");
    let identity = CosyIdentity {
        user_id: &credentials.user_id,
        auth_token: &credentials.access_token,
        name: &credentials.name,
        email: &credentials.email,
        machine_id: &credentials.machine_id,
    };
    let headers = cosy::build_auth_headers(None, &url, &identity)?;
    let response = super::auth::request("GET", &url, None, &headers)?;
    if !response.ok {
        return Err(Error::http(
            response.status.max(400),
            format!("模型目录刷新失败（HTTP {}）", response.status),
        ));
    }
    let payload = response.payload.unwrap_or(Value::Null);
    if let Some(message) = envelope_error(&payload) {
        return Err(Error::http(502, message));
    }
    Ok(payload)
}

/// 上游目录响应里的业务错误（HTTP 200 也可能带错误）
fn envelope_error(payload: &Value) -> Option<String> {
    let code = payload
        .get("statusCodeValue")
        .and_then(Value::as_i64)
        .or_else(|| payload.get("code").and_then(Value::as_i64));
    match code {
        Some(200) | None => None,
        Some(code) => Some(format!(
            "上游返回业务错误 {code}: {}",
            payload
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| payload.get("body").and_then(Value::as_str))
                .unwrap_or("")
                .chars()
                .take(200)
                .collect::<String>()
        )),
    }
}

/// 解析目录响应（Qoder：`chat` + `app` 独有的 OpenAI 格式模型）。
///
/// 对外模型 id 用 `display_name` **去掉空白**（源实现 `toModelId`）——
/// 于是客户端看到的名称可读，请求时再映射回 `key`。
fn parse_catalog(payload: &Value) -> Vec<Value> {
    let mut rows: Vec<&Value> = payload
        .get("chat")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let mut seen_keys: Vec<&str> = rows
        .iter()
        .copied()
        .filter_map(|item| item.get("key").and_then(Value::as_str))
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .collect();
    for item in payload.get("app").and_then(Value::as_array).into_iter().flatten() {
        let key = item.get("key").and_then(Value::as_str).unwrap_or("").trim();
        if key.is_empty()
            || seen_keys.contains(&key)
            || item.get("format").and_then(Value::as_str) != Some("openai")
        {
            continue;
        }
        seen_keys.push(key);
        rows.push(item);
    }
    let mut models: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for item in rows {
        let key = item.get("key").and_then(Value::as_str).unwrap_or("").trim();
        let display = item.get("display_name").and_then(Value::as_str).unwrap_or("").trim();
        if key.is_empty() || display.is_empty() {
            continue;
        }
        let id: String = display.chars().filter(|ch| !ch.is_whitespace()).collect();
        if id.is_empty() {
            continue;
        }
        let lowered = id.to_lowercase();
        if seen.iter().any(|known| known == &lowered) {
            continue;
        }
        seen.push(lowered);

        let vision = item.get("is_vl").map(truthy).unwrap_or(false);
        let reasoning = item.get("is_reasoning").map(truthy).unwrap_or(false)
            || item.get("thinking_config").map(truthy).unwrap_or(false);
        // 上游在该模型条目里声明支持的思考档位，作为请求时的白名单
        let efforts: Vec<Value> = item
            .pointer("/thinking_config/enabled/efforts")
            .and_then(Value::as_object)
            .map(|map| map.keys().map(|key| Value::String(key.clone())).collect())
            .unwrap_or_default();
        let context_window = context_window_of(item);
        let source = item.get("source").and_then(Value::as_str).unwrap_or("system");
        // 倍率（官方中文名「Credit 消耗倍率」）：上游在模型条目**顶层**给
        // `price_factor`，取值 0～3.2。折扣时段它本身就是折后价
        // （另有 `original_price_factor` 记原价）—— 取实际生效的那个。
        let credits = credits_of(item);
        let enabled = item.get("enable").map(truthy).unwrap_or(false);

        let mut model = entry(
            &id,
            display,
            key,
            reasoning,
            vision,
            enabled,
            context_window,
            source,
            &credits,
            fallback_visibility(&id),
        );
        if let Some(object) = model.as_object_mut() {
            object.insert("efforts".to_string(), Value::Array(efforts));
            if let Some(format) = item.get("format") {
                if !format.is_null() {
                    if let Some(config) = object.get_mut("config").and_then(Value::as_object_mut) {
                        config.insert("format".to_string(), format.clone());
                    }
                }
            }
            // 上下文档位（请求时按 prompt 估算升级，见 `context.rs`）：含上游
            // **当前**选中的那档（`max_input_tokens`）—— 升档判据要与它比。
            if let Some(config) = object.get_mut("config").and_then(Value::as_object_mut) {
                let tiers = context::tiers_from_catalog(item);
                if !tiers.is_empty() {
                    config.insert("tiers".to_string(), Value::Array(tiers));
                }
                if let Some(current) = item.get("max_input_tokens").and_then(Value::as_i64) {
                    if current > 0 {
                        config.insert("max_input_tokens".to_string(), Value::from(current));
                    }
                }
            }
        }
        models.push(model);
    }
    models
}

/// 构造一条目录条目（与 `metadata.json` 的 `default_models` 同形）。
pub fn entry(
    id: &str,
    name: &str,
    upstream_key: &str,
    reasoning: bool,
    vision: bool,
    enabled: bool,
    context_window: i64,
    source: &str,
    credits: &str,
    visibility: &str,
) -> Value {
    let mut model = json!({
        "id": id,
        "name": name,
        "upstreamKey": upstream_key,
        "enabled": enabled,
        // 可见性**不能**直接拿 `enabled` 顶替（两者语义不同）：静态兜底表里
        // `Auto` 这些档位别名恰好是 `enabled: false`，但它们不可见的理由不是
        // 「没启用」。真正的判据由调用方显式传 `visibility`。
        "visibility": visibility,
        "reasoning": reasoning,
        "supportsReasoning": reasoning,
        "supportsImages": vision,
        // 本家的上游是 agent 形态，工具调用是固有能力
        "supportsToolCall": true,
        "efforts": [],
        "maxInputTokens": context_window,
        "maxOutputTokens": super::protocol::MAX_OUTPUT_TOKENS,
        "isDefault": false,
        "kind": "chat",
        "config": {
            "key": upstream_key,
            "is_reasoning": reasoning,
            "is_vl": vision,
            "source": source,
        },
    });
    // 倍率键只在有值时插入：少一个键让「上游没给」与「上游给了空串」可区分
    if !credits.is_empty() {
        if let Some(object) = model.as_object_mut() {
            object.insert("credits".to_string(), Value::String(credits.to_string()));
        }
    }
    model
}

/// 静态 / 远程共用的可见性判据：**世代 + 档位别名**。
///
/// 官方 IDE 的模型选择器只列当前一代的模型；`Qwen3.7-Max` / `Qwen3.7-Plus` /
/// `Kimi-K2.8-Preview` 这些是上一代，`Auto` / `Ultimate` / `Performance` /
/// `Efficient` 是**档位别名**（不是具体模型）。两类都算 `hidden`。
///
/// `Sonus` / `Cantus` 是官方在售的内置模型，**不能**因为名字陌生就判隐藏。
fn fallback_visibility(id: &str) -> &'static str {
    const TIER_ALIASES: &[&str] = &["Auto", "Ultimate", "Performance", "Efficient"];
    if TIER_ALIASES.iter().any(|alias| alias.eq_ignore_ascii_case(id)) {
        return "hidden";
    }
    let lowered = id.to_ascii_lowercase();
    if lowered.starts_with("qwen3.7") || lowered.contains("k2.8-preview") {
        return "hidden";
    }
    "shown"
}

/// 上游 `price_factor` → 展示文本（远程路径）。
///
/// `price_factor = 0` 是**合法值**（Qwen3.8-Flash 免费档，界面显示 `0x`），
/// 不能当缺失去掉。因此返回**字符串**而非数字（数字 0 会被真值判定丢掉）。
/// 也接受字符串形态（同一家的其它目录字段就混着两种形态）。
fn credits_of(item: &Value) -> String {
    let factor = match item.get("price_factor") {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
        _ => None,
    };
    let Some(factor) = factor else {
        return String::new();
    };
    if !factor.is_finite() || factor < 0.0 {
        return String::new();
    }
    format!("x{} credits", format_factor(factor))
}

/// 倍率数字 → 紧凑文本（整数不带小数点，其余最多两位小数、裁掉尾零）。
///
/// 不用 `{:.1}`：Qoder 的倍率有 `0.04` 这一档，一位小数会四舍五入成 `0.0`
/// —— 一个「免费」的错误暗示。
fn format_factor(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    if (rounded - rounded.trunc()).abs() < 1e-9 {
        return format!("{}", rounded.trunc() as i64);
    }
    let text = format!("{rounded:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// 上下文窗口：取 `context_config` 里各档位的最大 `token_count`，没有档位就退回
/// 文档默认值。
fn context_window_of(item: &Value) -> i64 {
    let max = context::max_tokens(&context::tiers_from_catalog(item));
    if max > 0 {
        return max;
    }
    DEFAULT_CONTEXT_WINDOW
}
