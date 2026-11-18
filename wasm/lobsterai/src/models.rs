//! LobsterAI 的模型目录：`GET /api/models/available` 是权威来源，**另有一份
//! 19 条静态兜底**（远程拉不到 / 关掉发现时用）。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/models.rs`。
//!
//! ── 响应信封：`data` 是**单层数组**，别拿通用对象信封解析器来套 ──────
//! ```text
//!   {"code":0,"message":"success","data":[ {modelId, modelName, …}, … ]}
//! ```
//! Go 参考在 `models.go:216-244` 明确警告：它**不**复用 `parseEnvelope` ——
//! 那个解析器要求 `data` 是**对象**（这样 `data:null` 才能被当成「令牌失效」），
//! 而这个端点的 `data` 是数组；套上去会让整份模型清单**静默为空**。
//! 本模块自带 [`read_model_array`]，并兼容「双层层套」（`data.data[]`，
//! 参考实现说野生形态里两种都出现过）。
//!
//! ── keyfrom 只进 query，**绝不带 refresh token** ────────────────
//! 目录端点的身份是 `firstKeyfrom` / `latestKeyfrom` / `version`（+ 可选的
//! `uuid` / `userId`），不带 refresh token —— query 会进服务端的访问日志
//! （`models.go:523-526` 的原话）。拼法与 `credentials::keyfrom_fields` 同源。
//!
//! ── 两个 `X-LobsterAI-Client-*` 头**在这条端点上尤其重要** ─────────
//! 服务端按 `ClientCapabilities` **过滤**返回的模型集合：不带
//! `kimi-k3-agentic-v1` 时目录里少一个模型（实测 25 vs 26）。少发这个头不是
//! 「少一条头」，是**少一个模型**。
//!
//! ── 字段只按上游声明的取值，缺了就不广告 ─────────────────────────
//! `supportsImage` / `supportsThinking` / `costMultiplier` 缺失时**保持未知**
//! （`0` 与「字段不存在」是两回事：`0` 意思是免费）—— 与 Go 的 `remoteModel`
//! 注释（`models.go:110-131`）同一口径：编一个 `false` / `0` 会把将来的模型
//! 静默归类错。
//!
//! ── 缓存由网关持有（与 native 的差异）────────────────────────────
//! native 有一份进程内 `Mutex<Option<CatalogState>>`；wasm 实例会被回收重建，
//! 进程内状态不可靠。所以这里读**网关的目录缓存**（`catalog.get`，就是上一次
//! `models.refresh` 返回、被网关落库的那一份）。插件自己再存一份会与网关那边
//! 出现「两份真相」—— 用户改了网关的缓存策略而插件还按自己的 TTL 走，是最难
//! 查的那类不一致（native 的模块头也写了这条）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::Credentials;
use super::upstream::{
    self, CLIENT_CAPABILITIES, MAX_BODY_BYTES, MODELS_PATH, USER_AGENT, models_url,
};
use super::version;

/// 目录缓存时长（与参考实现的 2 小时同档；网关按 `meta.refreshed_at` 判新鲜度）
const CATALOG_TTL_MS: i64 = 2 * 60 * 60 * 1000;

/// 兜底目录里每条模型的上下文窗口（**照抄参考实现**，是桥接层的估计值
/// `131072`，**不是**逐模型实测 —— 见 [`fallback_ids`] 的说明）
const FALLBACK_CONTEXT_WINDOW: i64 = 131_072;

/// 静态兜底目录：**19 条，逐条照抄 Go 参考**（`models.go:138-158` 的
/// `fallbackModels`，其顺序也照抄，便于与上游对账）。上下文窗口统一
/// [`FALLBACK_CONTEXT_WINDOW`]（那是桥接层的估计值，不是逐模型实测）。
///
/// 只在「远程发现关掉 / 拉取失败 / 还没刷过」时对外 —— 远程一旦成功就是权威。
pub fn fallback_ids() -> [&'static str; 19] {
    [
        "deepseek-v4-flash",
        "deepseek-v4-pro",
        "MiniMax-M3",
        "MiniMax-M2.7",
        "qwen3.7-max",
        "qwen3.7-plus",
        "qwen3.6-plus",
        "qwen3.5-plus-2026-04-20",
        "kimi-k2.7-code",
        "kimi-k2.7-code-highspeed",
        "kimi-k2.6",
        "kimi-k2.5",
        "doubao-seed-2-1-pro-260628",
        "doubao-seed-2-1-turbo-260628",
        "doubao-seed-2-0-code-preview-260215",
        "glm-5.2",
        "glm-5.1",
        "glm-5v-turbo",
        "glm-5",
    ]
}

/// Go 参考的**规范化别名 → 线上 id** 表（`models.go:388-395` 的 `upstreamModelIDs`）。
///
/// ── 为什么需要它（这条回答「发布名能不能不等于线上 id」）────────────
/// **能**。Go 参考对外发布的是**规范化大小写的 id**（`publicModelIDs`），并另建
/// 一张反向表把请求里的规范化名折回线上 id（它自己的注释说：CPA 会跳过只差大小写
/// 的别名，所以规范大小写必须由插件自己发布）。本包的目录直接以 `modelId`
/// （线上 id）作为对外 `id`，因此**绝大多数情况下两者相同**；这张表只为
/// 「客户端手里握着旧规范化名」那条路兜底。
///
/// 键一律按小写比较。
pub const UPSTREAM_ALIASES: [(&str, &str); 6] = [
    ("deepseek-v4.1-flash", "deepseek-flash"),
    ("glm-5.3-flash", "glm-5.3-flash"),
    ("glm-5.3", "glm-5.3"),
    ("qwen3.8-max", "qwen3.8-max"),
    ("qwen3.8-flash-next", "qwen3.8-flash"),
    ("kimi-k2.7-code", "kimi-k2.7-code"),
];

/// 读一个数字（数字或数字字符串都认）
fn read_number(value: &Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    value
        .as_str()
        .and_then(|text| text.trim().parse::<f64>().ok())
}

/// 读一个正数（`> 0` 才算，否则视为缺失 —— 与 Go `contextWindow > 0` 同口径）
fn read_positive(value: Option<&Value>) -> i64 {
    value
        .and_then(read_number)
        .filter(|number| *number > 0.0)
        .map(|number| number as i64)
        .unwrap_or(0)
}

/// `thinkingConfig` 是否声明了可选档位（非空 `options` 且不止一个 `off`）。
///
/// Go 的 `parseThinkingConfig` 会丢弃整块结构不符的配置，并且「只有 off 一档」
/// 等于「没有可选档位」—— 这里只需要一个布尔，按同一口径折叠。
fn thinking_config_present(value: Option<&Value>) -> bool {
    let Some(options) = value
        .and_then(|config| config.get("options"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    options
        .iter()
        .filter(|option| {
            option
                .get("openclawLevel")
                .and_then(Value::as_str)
                .is_some_and(|level| !level.trim().is_empty())
        })
        .count()
        > 1
}

/// 倍率的展示串：`0` → 免费，其余 → `x<数字>`（前端 `formatCredits` 认 `x\d`）。
///
/// 这条口径照抄 Go 的 `displayNameFor`（`models.go:303-314`）：`0` 渲染成
/// 「免费」而不是「x0」。差别只在本仓把它放进 `credits` 键而不是拼进展示名。
fn credits_label(multiplier: f64) -> String {
    if multiplier == 0.0 {
        return "免费".to_string();
    }
    format!("x{multiplier}")
}

/// 把一条 `models/available` 条目映射成清单形态（缺 `modelId` 的丢掉）。
///
/// 返回 `None` 表示这一条不可用（上游没给 id），由调用方过滤。
pub fn entry_from_upstream(value: &Value) -> Option<Value> {
    let wire_id = value
        .get("modelId")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if wire_id.is_empty() {
        return None;
    }
    let display_name = match value.get("modelName").and_then(Value::as_str) {
        Some(name) if !name.trim().is_empty() => name.trim().to_string(),
        _ => wire_id.clone(),
    };
    let context_window = read_positive(value.get("contextWindow"));
    let max_tokens = read_positive(value.get("maxTokens"));
    let supports_image = value.get("supportsImage").and_then(Value::as_bool);
    let supports_thinking = value
        .get("supportsThinking")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || thinking_config_present(value.get("thinkingConfig"));
    // costMultiplier 是**裸数字**；`0` 意思是免费，必须保留而不是当缺失去掉
    let cost_multiplier = value.get("costMultiplier").and_then(read_number);

    let mut object = serde_json::Map::new();
    object.insert("id".to_string(), Value::String(wire_id.clone()));
    if !display_name.is_empty() {
        object.insert("name".to_string(), Value::String(display_name));
    }
    if context_window > 0 {
        object.insert("maxInputTokens".to_string(), Value::from(context_window));
    }
    if max_tokens > 0 {
        object.insert("maxOutputTokens".to_string(), Value::from(max_tokens));
    }
    // 模态位：上游**没给**时按不支持折叠，但不声称支持（有实测依据才广告）
    object.insert(
        "supportsImages".to_string(),
        Value::Bool(supports_image.unwrap_or(false)),
    );
    object.insert("supportsVideo".to_string(), Value::Bool(false));
    object.insert(
        "supportsReasoning".to_string(),
        Value::Bool(supports_thinking),
    );
    // 上游就是 OpenAI Chat Completions，tools 原样透传 ⇒ 支持工具调用
    object.insert("supportsToolCall".to_string(), Value::Bool(true));
    if let Some(multiplier) = cost_multiplier {
        object.insert("credits".to_string(), Value::String(credits_label(multiplier)));
    }
    Some(Value::Object(object))
}

/// 读模型数组。
///
/// **不**复用通用的对象信封解析器（会要求 `data` 是对象，从而把整份清单判空，
/// 见模块头）；`code != 0` 一律判失败，`data` 支持单层数组与 `data.data[]` 双层。
pub fn read_model_array(payload: &Value) -> Option<Vec<Value>> {
    let record = payload.as_object()?;
    let code = record.get("code").and_then(read_number)?;
    if code != 0.0 {
        return None;
    }
    if let Some(array) = record.get("data").and_then(Value::as_array) {
        return Some(array.clone());
    }
    record
        .get("data")
        .and_then(Value::as_object)
        .and_then(|nested| nested.get("data"))
        .and_then(Value::as_array)
        .cloned()
}

/// 网关目录缓存里的条目与刷新时刻（`None` = 从没刷过 / 缓存不是本家形状）。
fn remote_catalog() -> Option<(Vec<Value>, i64)> {
    let cached = sdk::catalog::cached().ok()?;
    let models = cached.get("models")?.as_array()?.clone();
    if models.is_empty() {
        return None;
    }
    let refreshed_at = cached
        .get("meta")
        .and_then(|meta| meta.get("refreshed_at"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    Some((models, refreshed_at))
}

/// 19 条兜底的清单形态（`contextWindow` 统一按参考实现的估计值）。
fn fallback_entries() -> Vec<Value> {
    fallback_ids()
        .iter()
        .map(|id| {
            json!({
                "id": *id,
                "name": *id,
                "maxInputTokens": FALLBACK_CONTEXT_WINDOW,
                "supportsImages": false,
                "supportsVideo": false,
                "supportsReasoning": false,
                "supportsToolCall": true,
            })
        })
        .collect()
}

/// 当前对外目录（`models.list` 的实现）：**远程优先，没有则兜底**。
pub fn list() -> Value {
    match remote_catalog() {
        Some((models, refreshed_at)) => json!({
            "models": models,
            "meta": { "remote": true, "refreshed_at": refreshed_at },
        }),
        None => json!({
            "models": fallback_entries(),
            "meta": { "remote": false, "refreshed_at": 0 },
        }),
    }
}

/// 把 `keyfrom_fields` 拼成 URL query（`k=v&k2=v2`，值 urlencoded，**不含
/// refresh token** —— 见模块头）。
fn keyfrom_query(credentials: &Credentials, client_version: &str) -> String {
    let fields = credentials.keyfrom_fields(client_version);
    let mut query = String::new();
    for (key, value) in fields {
        let escaped = upstream::urlencode(&value);
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(key);
        query.push('=');
        query.push_str(&escaped);
    }
    query
}

/// 目录端点 URL（query 为空时退回不带 `?` 的形态，与 Go `buildModelsURL` 同口径）
fn catalog_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        format!("{}{MODELS_PATH}", upstream::API_BASE)
    } else {
        models_url(trimmed)
    }
}

/// 拉一次目录（返回清单条目；`code != 0` 或形状不符时报错）。
fn fetch_catalog(credentials: &Credentials) -> Result<Vec<Value>> {
    // 版本头与 query 里的 version 用**同一个值**，避免「声明是这个版本、
    // 目录按那个版本过滤」的错位。
    let version = version::resolve();
    let url = catalog_url(&keyfrom_query(credentials, &version));
    let headers = vec![
        (
            "authorization".to_string(),
            format!("Bearer {}", credentials.access_token),
        ),
        ("accept".to_string(), "application/json".to_string()),
        (
            "x-lobsterai-client-capabilities".to_string(),
            CLIENT_CAPABILITIES.to_string(),
        ),
        (
            "x-lobsterai-client-version".to_string(),
            version.clone(),
        ),
        ("user-agent".to_string(), USER_AGENT.to_string()),
    ];
    let reply = upstream::send("GET", &url, &headers, None, MAX_BODY_BYTES)?;
    if !reply.ok() {
        return Err(Error::http(
            reply.status,
            format!("LobsterAI 目录接口返回 HTTP {}", reply.status),
        ));
    }
    let payload = reply
        .json()
        .ok_or_else(|| Error::http(502, "LobsterAI 目录接口响应不是 JSON"))?;
    let items = read_model_array(&payload).ok_or_else(|| {
        Error::http(
            502,
            "LobsterAI 目录响应结构不符（code != 0 或缺 data 数组）",
        )
    })?;
    Ok(items.iter().filter_map(entry_from_upstream).collect())
}

/// 刷新目录：远程成功即权威；失败时**保留现有清单**并如实汇报原因。
///
/// `account` 是宿主给的账号 id（空串 = 还没添加账号）。「一个账号都没有」不是
/// 失败 —— 那是「用户还没添加账号」的正常状态，返回 `unchanged()`（脚本 / CI
/// 不该看到一个红色失败，与 AtomCode / Loomy 同口径）。
pub fn refresh(force: bool, account: &str, secret: Option<&Value>) -> Value {
    if !force {
        if let Some((models, refreshed_at)) = remote_catalog() {
            let age = sdk::now().saturating_sub(refreshed_at);
            if age >= 0 && age < CATALOG_TTL_MS {
                return json!({ "refreshed": false, "count": models.len() });
            }
        }
    }
    if account.trim().is_empty() {
        return json!({ "refreshed": false, "count": 0 });
    }
    let Some(secret) = secret else {
        return json!({
            "refreshed": false,
            "count": 0,
            "message": "指定的账号不存在或不可用，请重新选择",
        });
    };
    let credentials = match Credentials::from_secret(secret) {
        Ok(credentials) => credentials,
        Err(error) => {
            return json!({ "refreshed": false, "count": 0, "message": error.message });
        }
    };
    match fetch_catalog(&credentials) {
        Ok(entries) if !entries.is_empty() => json!({
            "refreshed": true,
            "count": entries.len(),
            "models": entries,
            "meta": { "remote": true, "refreshed_at": sdk::now() },
        }),
        Ok(_) => json!({
            "refreshed": false,
            "count": 0,
            "message": "LobsterAI 目录为空（上游未返回可用模型）",
        }),
        Err(error) => json!({ "refreshed": false, "count": 0, "message": error.message }),
    }
}

/// 客户端请求里的模型名 → 发给上游的模型名。
///
/// 顺序：目录（按线上 id 或展示名命中）→ 规范化别名表 → 认不出返回 `None`
/// （由调用方**原样发**：猜一个更接近的名字比原样发更糟 —— 那会把「名字没映射」
/// 变成一个静默的错误重试）。
pub fn upstream_id_for(requested: &str) -> Option<String> {
    let target = requested.trim();
    if target.is_empty() {
        return None;
    }
    let entries = match remote_catalog() {
        Some((models, _)) => models,
        None => fallback_entries(),
    };
    if let Some(wire_id) = entries.iter().find_map(|entry| {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or("");
        let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
        if id == target || name == target {
            Some(id.to_string())
        } else {
            None
        }
    }) {
        return Some(wire_id);
    }
    let lower = target.to_lowercase();
    UPSTREAM_ALIASES
        .iter()
        .find(|(alias, _)| *alias == lower)
        .map(|(_, wire)| (*wire).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_names_are_the_nineteen_from_the_reference() {
        let ids = fallback_ids();
        assert_eq!(ids.len(), 19);
        assert_eq!(ids[0], "deepseek-v4-flash");
        assert_eq!(ids[18], "glm-5");
        // 兜底清单里**不带**倍率（那要上游逐条声明，编一个 0 会误导）
        let entries = fallback_entries();
        assert_eq!(entries.len(), 19);
        assert!(entries.iter().all(|entry| entry.get("credits").is_none()));
        assert_eq!(entries[0]["maxInputTokens"], json!(FALLBACK_CONTEXT_WINDOW));
    }

    #[test]
    fn read_model_array_accepts_single_and_double_envelopes() {
        let single = json!({ "code": 0, "data": [{ "modelId": "a" }] });
        assert_eq!(read_model_array(&single).map(|items| items.len()), Some(1));
        let double = json!({ "code": 0, "data": { "data": [{ "modelId": "a" }, { "modelId": "b" }] } });
        assert_eq!(read_model_array(&double).map(|items| items.len()), Some(2));
        // code != 0 一律失败（哪怕是数组形态）
        let failing = json!({ "code": 40100, "data": [{ "modelId": "a" }] });
        assert!(read_model_array(&failing).is_none());
        // data 为 null（令牌失效）→ 没有数组
        let empty = json!({ "code": 0, "data": Value::Null });
        assert!(read_model_array(&empty).is_none());
        assert!(read_model_array(&Value::Null).is_none());
    }

    #[test]
    fn entries_map_only_what_upstream_declares() {
        // `unwrap_or(Value::Null)` 而不是 expect：映射失败时断言会直接打出实际值
        let entry = entry_from_upstream(&json!({
            "modelId": "glm-5",
            "modelName": "GLM-5",
            "contextWindow": 200000,
            "maxTokens": 8192,
            "supportsImage": true,
            "supportsThinking": true,
            "costMultiplier": 0,
        }))
        .unwrap_or(Value::Null);
        assert_eq!(entry["id"], json!("glm-5"));
        assert_eq!(entry["name"], json!("GLM-5"));
        assert_eq!(entry["maxInputTokens"], json!(200000));
        assert_eq!(entry["maxOutputTokens"], json!(8192));
        assert_eq!(entry["supportsImages"], json!(true));
        assert_eq!(entry["supportsReasoning"], json!(true));
        assert_eq!(entry["supportsToolCall"], json!(true));
        assert_eq!(entry["supportsVideo"], json!(false));
        // 倍率 0 = 免费（必须保留，不能当缺失去掉）
        assert_eq!(entry["credits"], json!("免费"));

        // 缺 modelId → 丢弃
        assert!(entry_from_upstream(&json!({ "modelName": "x" })).is_none());
        // 上游没给模态位 → 折叠成不支持，但不写 credits / maxOutputTokens
        let minimal = entry_from_upstream(&json!({ "modelId": "m" })).unwrap_or(Value::Null);
        assert_eq!(minimal["name"], json!("m"));
        assert_eq!(minimal["supportsImages"], json!(false));
        assert_eq!(minimal["supportsReasoning"], json!(false));
        assert!(minimal.get("maxInputTokens").is_none());
        assert!(minimal.get("credits").is_none());
        // 倍率非 0 → x<数字>
        let paid = entry_from_upstream(&json!({ "modelId": "p", "costMultiplier": 0.05 }))
            .unwrap_or(Value::Null);
        assert_eq!(paid["credits"], json!("x0.05"));
    }

    #[test]
    fn thinking_config_counts_only_more_than_one_level() {
        // 只有 off 一档 = 没有可选档位
        let only_off = json!({ "options": [{ "openclawLevel": "" }] });
        assert!(!thinking_config_present(Some(&only_off)));
        let two = json!({ "options": [{ "openclawLevel": "off" }, { "openclawLevel": "high" }] });
        assert!(thinking_config_present(Some(&two)));
        assert!(!thinking_config_present(None));
    }

    #[test]
    fn aliases_are_lowercase_and_map_to_wire_ids() {
        for (alias, wire) in UPSTREAM_ALIASES {
            assert_eq!(alias, alias.to_lowercase(), "别名表必须全小写：{alias}");
            assert!(!wire.trim().is_empty());
        }
        // 兜底目录里的 id 本身就是线上 id（恒等确认），别名表只兜旧规范化名
        assert_eq!(upstream_id_for("glm-5").as_deref(), Some("glm-5"));
        // 大小写不同的名字**不猜**（native 口径：认不出就原样发）
        assert_eq!(upstream_id_for("GLM-5"), None);
        assert_eq!(
            upstream_id_for("deepseek-v4.1-flash").as_deref(),
            Some("deepseek-flash")
        );
        assert_eq!(upstream_id_for(""), None);
        assert_eq!(upstream_id_for("   "), None);
        assert_eq!(upstream_id_for("not-a-model"), None);
    }

    #[test]
    fn catalog_url_drops_the_query_when_empty() {
        assert_eq!(
            catalog_url(""),
            format!("{}{MODELS_PATH}", upstream::API_BASE)
        );
        assert!(catalog_url("version=1").ends_with("/api/models/available?version=1"));
    }
}
