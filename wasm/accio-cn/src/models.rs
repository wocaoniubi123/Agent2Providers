//! Accio 模型目录：静态兜底 + `/api/llm/config` 远程刷新。
//!
//! ── 清单从哪来 ──────────────────────────────────────────────
//!   1. **静态兜底**：`FALLBACK`（10 个可见模型，抄自客户端内置的
//!      `@ali/accio-adk-ts/model-catalog.json`，2026-09 快照）。启动即可用，
//!      没有账号 / 网络不通时 `/v1/models` 仍有内容。
//!   2. **远程刷新**：`POST {gw}/api/llm/config`，body `{token, supportAutoModel}`，
//!      头带 `x-package-region`（GLOBAL / CN）。上游按地区与账号权限给清单。
//!
//! ── 上游响应形态（2026-09 实测，解析必须按这一份）──────────────
//! ```jsonc
//! { "success": true, "code": "200", "message": "0",
//!   "data": [                       // ← **provider 数组**，不是 {providers:[…]}
//!     { "provider": "openai", "providerDisplayName": "OpenAI",
//!       "modelList": [ { "modelCode": "1Helix-G6aS8tR2qN7m", "modelName": "…",
//!                        "modelDisplayName": "GPT 6 Astra", "visible": true,
//!                        "protocol": "responses", "group": "azure", … } ] } ] }
//! ```
//! 早先的解析假设 `data` 是 `{providers:[…]}` **对象**，而它其实是数组 ——
//! 于是清单恒为空、而 HTTP 是 200（走不到错误分支），前端只看到「上游目录里
//! 没有可见模型」。数组与对象两种形态都接受。
//!
//! ── 上游把模型名换成了混淆代号（同一批实测）────────────────────
//! `modelCode` / `modelName` 现在是 `1Orbit-I9eY7YK8bW1f`（Claude Sonnet 4.6）
//! 这类不透明代号，人类可读名只在 `modelDisplayName` 里。**老名字仍然可用**
//! （实测 `claude-sonnet-4-6` 与代号都能正常出流），所以：
//!   - `upstreamKey` 存上游代号 —— 发给上游的就是它；
//!   - 对外 `id` 走 `STABLE_IDS`：**能沿用老名字就沿用**（用户已配好的名字
//!     不用改），新模型没有老名字可用，才用代号。
//!
//! ── 缓存放在哪里（与 native 的进程级 RwLock 不同）────────────────
//! native 用进程内的 `OnceLock<[RwLock<RegionCache>; 2]>`；wasm 实例每次调用
//! 后销毁，`static` 不可依赖。等价的载体是宿主状态：`state::Scope::Account`
//! 下的 `accio-catalog` 一条（账号范围内持久，网关重启也还在）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic；读网络绝不持锁。

use agent2api_wasm_sdk::{self as sdk, json, state, Error, Result, Value};

use super::credential::Credential;
use super::region;
use super::upstream;

/// 远程目录缓存有效期（1 小时：目录变化不频繁，用户点「刷新模型」时 force
/// 会绕过这里）
const CACHE_TTL_MS: i64 = 60 * 60 * 1000;

/// 宿主持久状态里的键（账号作用域）
const STATE_KEY: &str = "accio-catalog";
const SCHEMA: u32 = 1;

/// 静态兜底：客户端内置 `model-catalog.json` 里 `visible: true` 的条目。
///
/// 字段名已经是**归一后的形态**（见模块头），`upstreamKey` 是发给上游的
/// `model` 字段值（就是 `modelCode` —— Accio 不做通道前缀那一套）。
///
/// 这张表只服务「没有账号 / 拉不到目录」的时刻。保留它的作用是启动即有清单可用、
/// 断网 / 未登录时 `/v1/models` 不为空。远程清单拉到之后这份退居兜底。
///
/// `EffortPlacement` 一列是思考档位落点（实测口径见 [`EffortPlacement`]）：
/// 静态表里没有上游的 `protocol` 字段，所以按同一批实测逐条写死 —— 远程清单
/// 走「读 `protocol`」，两条路都不再按模型名猜。
const FALLBACK: &[(&str, &str, u64, bool, &[&str], bool, EffortPlacement)] = &[
    // (modelCode, 展示名, contextWindow, multimodal, reasoningEfforts, isDefault, 档位落点)
    ("gemini-3-flash-preview", "Gemini 3 Flash", 1_000_000, true, &["low", "high"], true, EffortPlacement::Top),
    ("gemini-3.1-pro-preview", "Gemini 3.1 Pro", 1_000_000, true, &["low", "high"], false, EffortPlacement::Top),
    ("qwen3.6-plus", "Qwen 3.6 Plus", 991_808, false, &[], false, EffortPlacement::Top),
    ("qwen3-max-2026-01-23", "Qwen 3 Max", 262_144, false, &[], false, EffortPlacement::Top),
    ("gpt-5.4", "GPT 5.4", 1_050_000, true, &["low", "high"], false, EffortPlacement::Properties),
    ("gpt-5.2-1211", "GPT 5.2", 400_000, true, &["low", "high"], false, EffortPlacement::Properties),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6", 1_000_000, true, &["low", "medium", "high", "max"], false, EffortPlacement::Top),
    ("claude-opus-4-6", "Claude Opus 4.6", 1_000_000, true, &["low", "medium", "high", "max"], false, EffortPlacement::Top),
    ("glm-5", "GLM-5", 200_000, false, &[], false, EffortPlacement::Top),
    ("MiniMax-M2.5", "MiniMax M2.5", 204_800, true, &[], false, EffortPlacement::Properties),
];

/// 老模型名 → 上游**展示名**（`modelDisplayName`）。
///
/// ── 这张表干什么 ────────────────────────────────────────────
/// 上游把目录里的模型名换成了不透明代号，而用户手上的配置写的是代号之前的
/// 名字（`claude-sonnet-4-6`）。若清单直接广告代号，那些配置会立刻 404。
/// 这里把它们接回来：目录里只要有「Claude Sonnet 4.6」这一条，它就**沿用老
/// 名字当对外 id**（`upstreamKey` 仍是代号，发上游用代号）。
///
/// ── 为什么按展示名而不是硬编码代号 ─────────────────────────────
/// 代号是上游随时会换的不透明串；硬编码等于把「上游换次代号就失效」写进实现。
/// 展示名才是上游稳定对外的东西，这张表**不需要跟着代号变**。
///
/// 版本跃迁不在这里接（`kimi-k2.5` → `Kimi K2.6` 等）：用户点名 A 却拿到 B
/// 是静默替换，宁可 404 让客户端看到相近候选。
const STABLE_IDS: &[(&str, &str)] = &[
    ("claude-sonnet-4-6", "Claude Sonnet 4.6"),
    ("claude-opus-4-6", "Claude Opus 4.6"),
    ("gemini-3-flash-preview", "Gemini 3 Flash"),
    ("gemini-3.1-pro-preview", "Gemini 3.1 Pro"),
    ("glm-5", "GLM-5"),
];

/// 某条目录条目的**对外 id**：能用老名字就用老名字，否则用上游代号。
fn stable_id(code: &str, display: &str) -> String {
    STABLE_IDS
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(display))
        .map(|(alias, _)| (*alias).to_string())
        .unwrap_or_else(|| code.to_string())
}

/// 思考档位该放哪一层（`properties.reasoning_effort` 还是顶层 `reasoning_effort`）。
///
/// ── 为什么不能按模型名猜（2026-09 实测）───────────────────────
/// 上游把模型名换成了不透明代号（`1Helix-…` / `1Orbit-…`），
/// `contains("gpt")` 这种判据全部失效。改用上游自己在目录里给的 `protocol`：
///
/// | `protocol`  | 例子           | 档位落点   | 依据（实测）                              |
/// |-------------|----------------|------------|-------------------------------------------|
/// | `responses` | GPT 系         | properties | 只有 properties 能出思考内容（80 帧 thought，顶层 0） |
/// | `openai`    | MiniMax M3     | properties | 同上（`openai` 沿同一落点）                |
/// | 空          | Claude / Gemini 系 | 顶层    | Gemini 系放 properties **直接 400**：`Unknown name "reasoning_effort"` |
///
/// 兜底取「顶层」：它是唯一在三种模型上都不会报错的落点（Gemini 系放
/// properties 是硬错误，放顶层只是不产生思考内容 —— 少个功能好过 400）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EffortPlacement {
    /// `properties.reasoning_effort`（`protocol` = `responses` / `openai`）
    Properties,
    /// 顶层 `reasoning_effort`（`protocol` 为空或未知）
    #[default]
    Top,
}

impl EffortPlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Properties => "properties",
            Self::Top => "top",
        }
    }

    /// 从条目上的自有键读回落点（发送侧用）。缺键 / 值不认识 → `Top`。
    pub fn from_entry(entry: &Value) -> Self {
        match entry.get("protocolKind").and_then(Value::as_str) {
            Some("properties") => Self::Properties,
            _ => Self::Top,
        }
    }
}

/// 上游模型条目 → 思考档位落点。
///
/// 认的是目录里的 `protocol`（上游自己声明的协议）；`group`（执行池）与
/// `thinkLevel` 是另一回事，都不参与这条判定。
fn effort_placement(entry: &Value) -> EffortPlacement {
    match entry
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "responses" | "openai" => EffortPlacement::Properties,
        _ => EffortPlacement::Top,
    }
}

/// 远程条目的归一（上游字段 → 聚合层认识的键名）。
fn normalize_entry(entry: &Value) -> Value {
    let code = entry
        .get("modelCode")
        .or_else(|| entry.get("modelName"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let display = entry
        .get("modelDisplayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&code)
        .to_string();
    let context_window = entry.get("contextWindow").and_then(Value::as_u64).unwrap_or(0);
    let multimodal = entry.get("multimodal").and_then(Value::as_bool).unwrap_or(false);
    let efforts: Vec<Value> = entry
        .get("reasoningEfforts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| Value::String(text.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut item = json!({
        // 对外 id 用老名字（能用的话），上游发送名走 `upstreamKey`
        "id": stable_id(&code, &display),
        "name": display,
        "maxInputTokens": context_window,
        // 上游没给输出上限；与 contextWindow 同量级地给一个保守值会让界面误导，
        // 因此留空（`list_item` 在缺键时不输出这个字段）
        "supportsImages": multimodal,
        // ADK 信封支持 functionCall / functionResponse，工具调用一律可用
        "supportsToolCall": true,
        "isDefault": entry.get("isDefault").and_then(Value::as_bool).unwrap_or(false),
        "kind": "chat",
        // 自有键（进不了 /v1/models，路由与思考档位要用）
        "upstreamKey": code,
        "reasoningEfforts": Value::Array(efforts.clone()),
        "protocolKind": effort_placement(entry).as_str(),
        "modelDesc": entry.get("modelDesc").cloned().unwrap_or(Value::Null),
        "usageMultiple": entry.get("usageMultiple").cloned().unwrap_or(Value::Null),
    });
    // 「支持思考」不从这里推断（2026-10 改）：此前写的是 `!efforts.is_empty()`，
    // 把「有没有**命名档位**」当成了「支不支持思考」—— 只声明开关的模型因此被
    // 标成「不支持思考」，而上游没给这个位，就别替它答：有命名档位时按档位推断
    // （那是上游数据），没有则留给 `core::model_meta` 由 models.dev 补。
    if !efforts.is_empty() {
        item["supportsReasoning"] = Value::Bool(true);
    }
    item
}

fn fallback_models() -> Vec<Value> {
    FALLBACK
        .iter()
        .map(|(code, name, window, multimodal, efforts, is_default, placement)| {
            let mut item = normalize_entry(&json!({
                "modelCode": code,
                "modelDisplayName": name,
                "contextWindow": window,
                "multimodal": multimodal,
                "reasoningEfforts": efforts,
                "isDefault": is_default,
            }));
            // 静态表自己带着落点（没有上游的 `protocol` 可读），写进去覆盖
            // `normalize_entry` 的兜底值
            if let Some(object) = item.as_object_mut() {
                object.insert(
                    "protocolKind".to_string(),
                    Value::String(placement.as_str().to_string()),
                );
            }
            item
        })
        .collect()
}

/// 读回持久缓存（`{models: [...], fetchedAt: ms}`）。
fn cached() -> Option<(Vec<Value>, i64)> {
    let snapshot = state::get(state::Scope::Account, STATE_KEY, SCHEMA).ok()?;
    if !snapshot.compatible {
        return None;
    }
    let models = snapshot.value.get("models").and_then(Value::as_array).cloned().unwrap_or_default();
    if models.is_empty() {
        return None;
    }
    let fetched_at = snapshot.value.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
    Some((models, fetched_at))
}

/// 写回持久缓存（CAS：并发刷新时后到的那个失败，而不是互相覆盖）。
fn save(models: &[Value], fetched_at: i64) {
    let value = json!({ "models": models, "fetchedAt": fetched_at });
    let Ok(snapshot) = state::get(state::Scope::Account, STATE_KEY, SCHEMA) else { return };
    let _ = state::compare_exchange(
        state::Scope::Account,
        STATE_KEY,
        SCHEMA,
        snapshot.revision,
        value,
        CACHE_TTL_MS,
    );
}

/// 当前清单：远程（有的话）优先，否则静态兜底。
pub fn list() -> Vec<Value> {
    match cached() {
        Some((models, _)) => models,
        None => fallback_models(),
    }
}

/// 某地区最近一次远程刷新是否成功过（模型管理页「来源」列用）
pub fn remote_models() -> Vec<Value> {
    cached().map(|(models, _)| models).unwrap_or_default()
}

/// 最近一次刷新的时刻（毫秒；0 = 从未）
pub fn last_refreshed_at() -> i64 {
    cached().map(|(_, fetched_at)| fetched_at).unwrap_or(0)
}

/// 客户端点名的模型 → 上游发送名。
///
/// 与聚合目录同一口径（先 `id` 再 `name`，trim + 忽略大小写），否则会出现
/// 「目录放行、转发层认不出」的静默失配。
///
/// ── 老名字为什么也认 ────────────────────────────────────────
/// 远程条目的 `id` 已经是「能沿用就沿用」的老名字（见 [`STABLE_IDS`]），
/// 所以用户手上的老配置直接命中 `id`；`upstreamKey` 兜住「客户端从桌面端
/// 抄了代号过来」这一种输入。两条都在这里一次认全。
pub fn resolve(model_name: &str) -> Option<Value> {
    let wanted = model_name.trim();
    if wanted.is_empty() {
        return None;
    }
    list()
        .into_iter()
        .find(|item| {
            ["id", "name", "upstreamKey"].iter().any(|key| {
                item.get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(wanted))
            })
        })
}

/// 模型管理页的可选项（排障文案用）
pub fn known_names() -> Vec<String> {
    list()
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// 远程刷新（`POST /api/llm/config`，失败回落 `/api/llm/config/v2`）。
///
/// `force = false` 时按 TTL 早退（自动路径：客户端每次拉模型列表都真打上游既
/// 没必要且会加重上游负担）；`force = true` 是用户点「刷新模型清单」的语义。
pub fn refresh(credential: &Credential, force: bool) -> Result<Value> {
    let cached_state = cached();
    if !force {
        if let Some((models, fetched_at)) = &cached_state {
            if *fetched_at > 0 && sdk_now() - fetched_at < CACHE_TTL_MS {
                return Ok(sdk::catalog::unchanged(models.len()));
            }
        }
    }
    if credential.access_token.trim().is_empty() {
        return Ok(sdk::catalog::failed("Accio 账号没有可用凭证，无法刷新模型目录"));
    }
    // v1 是完整清单（见 `region::MODEL_CONFIG_PATH`），v2 只在它出意外时兜一次底
    let body = json!({ "token": credential.access_token, "supportAutoModel": true });
    let mut last_error: Option<String> = None;
    let mut models: Vec<Value> = Vec::new();
    for path in [region::MODEL_CONFIG_PATH, region::MODEL_CONFIG_PATH_V2] {
        let payload = match upstream::post_json(region::REGION, path, &body, "模型目录查询") {
            Ok(payload) => payload,
            Err(error) => {
                last_error = Some(format!("目录请求失败：{}", error.message));
                continue;
            }
        };
        let parsed = parse_catalog(&payload);
        if parsed.is_empty() {
            last_error = Some("上游目录里没有可见模型".to_string());
            continue;
        }
        models = parsed;
        break;
    }
    if models.is_empty() {
        return Ok(sdk::catalog::failed(
            &last_error.unwrap_or_else(|| "上游目录里没有可见模型".to_string()),
        ));
    }
    save(&models, sdk_now());
    Ok(sdk::catalog::refreshed(models))
}

/// 宿主时钟（毫秒）—— 单独包一层，纯函数部分才好测。
fn sdk_now() -> i64 {
    sdk::now()
}

/// 解析模型目录响应。
///
/// ── 两种信封都要认（2026-09 实测的第一种是当前形态）───────────
///   1. `{success, data:[{provider, modelList:[…]}, …]}` —— **现在就是这个**，
///      `data` 是 provider 数组（早先的解析按对象找 `providers`，于是恒为空）；
///   2. `{data:{providers:[{modelList:[…]}]}}` —— 旧形态，保留兼容。
///
/// ── 两道过滤 ────────────────────────────────────────────────
///   - `visible: false` 是上游给内部用的（图像 / 预览版，实测 69 条里 28 条）；
///   - [`is_chat_entry`] 挡掉专用生成模型。
fn parse_catalog(payload: &Value) -> Vec<Value> {
    // 先看 `data` 本身是不是 provider 数组（形态 1）
    let root = payload.get("data").unwrap_or(payload);
    let providers = root
        .as_array()
        .or_else(|| root.get("providers").and_then(Value::as_array));
    let Some(providers) = providers else {
        return Vec::new();
    };
    let mut models: Vec<Value> = Vec::new();
    for provider in providers {
        let Some(model_list) = provider.get("modelList").and_then(Value::as_array) else {
            continue;
        };
        for entry in model_list {
            if entry.get("visible").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            if !is_chat_entry(entry) {
                continue;
            }
            let normalized = normalize_entry(entry);
            let id = normalized.get("id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            if models.iter().any(|existing| {
                existing
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    == Some(id.to_ascii_lowercase())
            }) {
                continue;
            }
            models.push(normalized);
        }
    }
    models
}

/// 这条目录条目是不是**对话**模型。
///
/// ── 为什么光看 `visible` 不够（2026-09 实测）───────────────────
/// 目录里有专用生成模型（视频生成那一组），它们的 `visible` 是 **null 而不是
/// false**，只按 `visible == false` 过滤会漏进来一条 `rlab-1.0-storyboard`
/// （「Multi-shot Video」，`contextWindow` 也是 null），它会以「上下文 0」的
/// 形态出现在列表里，点它必然失败。这类条目的判据是 `supportedOperationList`：
/// 实测**对话条目一律为 null**，只有视频生成那条给了 `["VIDEO_GENERATION"]`。
///
/// 用「点名挡掉已知的非对话操作」而不是「只放行空列表」：上游将来给对话条目
/// 填上这个字段时，宁可多收一个也不要把正常模型挡在门外（少个模型是静默的，
/// 多一个奇怪的模型至少看得见）。
fn is_chat_entry(entry: &Value) -> bool {
    const NON_CHAT_OPERATIONS: &[&str] = &["VIDEO_GENERATION", "IMAGE_GENERATION", "AUDIO_GENERATION"];
    entry
        .get("supportedOperationList")
        .and_then(Value::as_array)
        .is_none_or(|operations| {
            !operations.iter().filter_map(Value::as_str).any(|operation| {
                NON_CHAT_OPERATIONS
                    .iter()
                    .any(|blocked| operation.eq_ignore_ascii_case(blocked))
            })
        })
}

/// 供自检：把一个未知模型名报给用户时附上可选项。
pub fn unknown_model_error(model_name: &str) -> Error {
    let names = known_names();
    let sample: Vec<String> = names.iter().take(6).cloned().collect();
    Error::http(
        400,
        format!(
            "模型不存在: {model_name}。Accio 可用模型：{}（完整清单见模型页）",
            sample.join(" / ")
        ),
    )
    .with_code("model_not_found")
}

/// 把内部条目翻译成协议里的“上游名”（chat 构造用）。
pub fn wire_id(entry: &Value) -> Option<String> {
    entry
        .get("upstreamKey")
        .or_else(|| entry.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

/// 条目声明的思考档位集合
pub fn efforts_of(entry: &Value) -> Vec<String> {
    entry
        .get("reasoningEfforts")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 静态兜底必须非空且每个条目都能解析（没有账号时界面照样有清单）。
    #[test]
    fn fallback_is_usable() {
        let models = fallback_models();
        assert!(!models.is_empty());
        for item in &models {
            assert!(item["id"].as_str().is_some_and(|id| !id.is_empty()));
            assert!(item["upstreamKey"].as_str().is_some_and(|key| !key.is_empty()));
            assert!(matches!(item["protocolKind"].as_str(), Some("top" | "properties")));
        }
    }

    /// 远程条目：代号作为 upstreamKey、老展示名沿用为 id、隐藏条目被过滤。
    #[test]
    fn catalog_normalizes_codes_and_filters_hidden() {
        let payload = json!({
            "data": [
                { "provider": "anthropic", "modelList": [
                    { "modelCode": "1Orbit-abc", "modelDisplayName": "Claude Sonnet 4.6", "visible": true, "protocol": "" },
                    { "modelCode": "hidden-1", "modelDisplayName": "Hidden", "visible": false }
                ]},
                { "provider": "openai", "modelList": [
                    { "modelCode": "1Helix-xyz", "modelDisplayName": "GPT 6 Astra", "visible": true, "protocol": "responses" }
                ]}
            ]
        });
        let models = parse_catalog(&payload);
        assert_eq!(2, models.len());
        assert_eq!("claude-sonnet-4-6", models[0]["id"].as_str().unwrap_or(""));
        assert_eq!("1Orbit-abc", models[0]["upstreamKey"].as_str().unwrap_or(""));
        assert_eq!("top", models[0]["protocolKind"].as_str().unwrap_or(""));
        assert_eq!("properties", models[1]["protocolKind"].as_str().unwrap_or(""));
    }

    /// 旧信封（`{data:{providers:[…]}}`）也要认 —— 上游改回去过。
    #[test]
    fn catalog_accepts_legacy_envelope() {
        let payload = json!({ "data": { "providers": [
            { "modelList": [{ "modelCode": "glm-5", "modelDisplayName": "GLM-5", "visible": true }] }
        ]}});
        assert_eq!(1, parse_catalog(&payload).len());
    }
}
