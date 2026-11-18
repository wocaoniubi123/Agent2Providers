//! 模型目录：三源发现（agent detail / builtin / 福利网关）+ 解析 + 缓存。
//!
//! ── 为什么要三个源 ──────────────────────────────────────────
//!   · `agent-center/agents/useragents` + `agents/detail`：账号自己可见的 agent
//!     模型（`gpts.models`）。名字与上下文长度以它为准；
//!   · `/v1/model/builtin`：内置目录。**多模态模型只在这个源里出现** —— 丢掉它
//!     等于丢掉识图能力，所以即使 `display_enabled` 是 false 也保留；
//!   · 福利网关 `opengw…/api/v1/gateway/config`：领福利后可见的免费模型，转发时
//!     必须带 `maas_type: benefit`（源决定要不要带，带错必被上游拒）。
//!
//! ── 为什么缓存能"空着"而不造兜底 ────────────────────────────
//! 该账号一个模型都没返回时缓存就是空的，上层据此报「账号没有可用模型」。
//! **绝不**塞一份静态兜底清单：那会广告出一批"列出来但一调就 400"的幽灵模型。
//!
//! ── 缓存落在宿主会话存储里（不是进程内存）────────────────────
//! wasm 插件每次调用都是新实例，进程内的 `static` 活不过一次调用。目录是**跨
//! 调用**要用的东西，只能放 `session.put`（宿主代持、带 TTL）。代价是每次读都
//! 多一次宿主调用，换来的是「刷新一次、之后每次转发都能用」。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::credentials::Credential;
use super::signer;
use super::upstream;

/// 目录缓存键与有效期。
const CACHE_KEY: &str = "codearts:catalog";
const CACHE_TTL_MS: i64 = 5 * 60 * 1000;
const CACHE_TTL_WARNING_MS: i64 = 30 * 1000;

/// 模型来自哪个源（决定路由与 `maas_type` 注入）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelSource {
    Agent,
    Builtin,
    Benefit,
}

impl ModelSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Builtin => "builtin",
            Self::Benefit => "benefit",
        }
    }

    /// 福利源的模型必须显式带 `maas_type: benefit`，别的源带了反而会被判成
    /// "没领福利"（见 `chat::build_upstream_request`）。
    pub fn needs_benefit_header(self) -> bool {
        self == Self::Benefit
    }

    fn from_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "agent" => Some(Self::Agent),
            "builtin" => Some(Self::Builtin),
            "benefit" => Some(Self::Benefit),
            _ => None,
        }
    }
}

/// 一条模型。
#[derive(Clone, Debug, Default)]
pub struct ModelConfig {
    /// 上游真名（大小写敏感，转发时必须用这个）
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub context_length: i64,
    pub max_output_tokens: i64,
    pub supports_images: bool,
    pub source: ModelSource,
    /// 积分倍率的**官方文案**（`credit[].ratio_display`，形如 `0.7x`）。空串 = 上游没给。
    pub credit_display: String,
    /// 上游声明的「是否出现在官方客户端里」：`None` = 没给字段（按可见处理）。
    pub display_enabled: Option<bool>,
}

impl Default for ModelSource {
    fn default() -> Self {
        Self::Agent
    }
}

impl ModelConfig {
    /// 转发时要不要带 `maas_type: benefit`。
    pub fn benefit(&self) -> bool {
        self.source.needs_benefit_header()
    }

    fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "display_name": self.display_name,
            "description": self.description,
            "context_length": self.context_length,
            "max_output_tokens": self.max_output_tokens,
            "supports_images": self.supports_images,
            "source": self.source.as_str(),
            "credit_display": self.credit_display,
            "display_enabled": self.display_enabled,
        })
    }

    fn from_value(value: &Value) -> Option<Self> {
        let id = value["id"].as_str()?.trim().to_string();
        if id.is_empty() {
            return None;
        }
        Some(Self {
            id,
            display_name: value["display_name"].as_str().unwrap_or("").to_string(),
            description: value["description"].as_str().unwrap_or("").to_string(),
            context_length: value["context_length"].as_i64().unwrap_or(0),
            max_output_tokens: value["max_output_tokens"].as_i64().unwrap_or(0),
            supports_images: value["supports_images"].as_bool().unwrap_or(false),
            source: value["source"].as_str().and_then(ModelSource::from_label).unwrap_or_default(),
            credit_display: value["credit_display"].as_str().unwrap_or("").to_string(),
            display_enabled: value["display_enabled"].as_bool(),
        })
    }
}

/// 合并后的清单 + 诊断信息。
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    pub models: Vec<ModelConfig>,
    pub warnings: Vec<String>,
}

impl Catalog {
    /// 大小写无关地找一条模型（客户端写 `glm-5.2` 而上游要 `GLM-5.2`）。
    pub fn resolve(&self, requested: &str) -> Option<&ModelConfig> {
        let wanted = requested.trim();
        self.models
            .iter()
            .find(|model| model.id.eq_ignore_ascii_case(wanted))
    }
}

/// 按 id 先到先得地合并（前者已报过的 id 不再被后者覆盖）。
fn append_unique(target: &mut Vec<ModelConfig>, incoming: Vec<ModelConfig>) {
    for model in incoming {
        if !target.iter().any(|existing| existing.id == model.id) {
            target.push(model);
        }
    }
}

// ── 解析 ─────────────────────────────────────────────────────

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

fn number(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// 目录自述的 `max_tokens` 不能当请求上限用：上游实际执行的硬顶是 65536，而目录
/// 里 GLM-5.2 写 131072、deepseek 系列写 384000。这些数经 `/v1/models` 广告出去，
/// 客户端照它写值就会被上游整条拒收，所以出口先夹一遍。`0` 表示目录没给，原样留着。
fn capped_output(value: &Value, key: &str) -> i64 {
    let declared = number(value, key);
    if declared <= 0 {
        declared
    } else {
        declared.min(super::chat::MAX_OUTPUT_TOKENS)
    }
}

/// `credit[]` → 倍率文案（`ratio_display`）。
///
/// 上游按**输入长度分档**给多条，而倍率列只有一格，所以取**基础档**
/// （`input_from == 0`）那一条 —— 与官网徽章一致。三条保守规则：`status` 显式
/// 非 `"0"` 的档跳过；没有基础档时退回第一条能读出文案的档；原样透传不解析。
fn credit_display_of(entry: &Value) -> String {
    let Some(tiers) = entry.get("credit").and_then(Value::as_array) else {
        return String::new();
    };
    let mut fallback = String::new();
    for tier in tiers {
        if matches!(tier.get("status").and_then(Value::as_str), Some(value) if value.trim() != "0") {
            continue;
        }
        let display = text(tier, "ratio_display");
        if display.is_empty() {
            continue;
        }
        if number(tier, "input_from") == 0 {
            return display;
        }
        if fallback.is_empty() {
            fallback = display;
        }
    }
    fallback
}

fn first_non_empty(values: &[String]) -> String {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// 解析 `/v1/model/builtin`。`enable` **显式 false 才跳过**（缺字段当可用）。
pub fn parse_builtin(body: &str) -> Result<Vec<ModelConfig>> {
    let payload: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts builtin 目录不是合法 JSON"))?;
    let entries = payload
        .get("builtinModels")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "CodeArts builtin 目录缺少 builtinModels 数组"))?;
    let mut models = Vec::new();
    for entry in entries {
        if entry.get("enable").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let model_id = text(entry, "model_id");
        let model_name = text(entry, "model_name");
        let id = if model_id.is_empty() { model_name.clone() } else { model_id };
        if id.is_empty() {
            continue;
        }
        models.push(ModelConfig {
            display_name: if model_name.is_empty() { id.clone() } else { model_name },
            description: text(entry, "model_desc"),
            context_length: number(entry, "context_window"),
            max_output_tokens: capped_output(entry, "max_tokens"),
            supports_images: entry.get("supports_images").and_then(Value::as_bool).unwrap_or(false),
            credit_display: credit_display_of(entry),
            // builtin 源**不**按它过滤：多模态模型只在这里出现，丢掉这个源等于丢识图能力
            display_enabled: entry.get("display_enabled").and_then(Value::as_bool),
            id,
            source: ModelSource::Builtin,
        });
    }
    Ok(models)
}

/// 解析 agent detail 的 `gpts.models`。
///
/// `enabled` 显式 false 跳过；`display_enabled` **不再丢弃** —— 它表达的正是
/// 「官方客户端列不列它」，正是「可见性」列要显示的东西。把它当解析期硬过滤，
/// 那个信息就没了，管理页也就无从告诉用户「这条上游能用但不展示」。
pub fn parse_agent_detail(body: &str, language: &str) -> Result<Vec<ModelConfig>> {
    let payload: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts agent detail 不是合法 JSON"))?;
    let gpts = payload
        .get("gpts")
        .ok_or_else(|| Error::http(502, "CodeArts agent detail 没有 gpts 目录"))?;
    let entries = gpts.get("models").and_then(Value::as_array).cloned().unwrap_or_default();
    let english = language.trim().to_ascii_lowercase().starts_with("en");
    let mut models = Vec::new();
    for entry in entries {
        let parameters = entry.get("model_parameters").cloned().unwrap_or(Value::Null);
        if parameters.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let display_enabled = parameters.get("display_enabled").and_then(Value::as_bool);
        // 扩展把 model_parameters 摊在 model_alias 上，所以嵌套的 model_id 优先
        let id = first_non_empty(&[
            text(&parameters, "model_id"),
            text(&entry, "model_alias"),
            text(&entry, "model_id"),
        ]);
        if id.is_empty() {
            continue;
        }
        let description = if english {
            first_non_empty(&[text(&parameters, "model_desc_en"), text(&parameters, "model_desc")])
        } else {
            first_non_empty(&[text(&parameters, "model_desc"), text(&parameters, "model_desc_en")])
        };
        let model_name = text(&entry, "model_name");
        models.push(ModelConfig {
            display_name: if model_name.is_empty() { id.clone() } else { model_name },
            description,
            context_length: number(&parameters, "context_window"),
            max_output_tokens: capped_output(&parameters, "max_tokens"),
            supports_images: parameters.get("supports_images").and_then(Value::as_bool).unwrap_or(false),
            credit_display: credit_display_of(&entry),
            display_enabled,
            id,
            source: ModelSource::Agent,
        });
    }
    Ok(models)
}

/// 解析 agent id 列表（`agent_id` 优先，回退 `original_id`），并去重。
pub fn parse_agent_ids(body: &str) -> Result<Vec<String>> {
    let payload: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts agent 列表不是合法 JSON"))?;
    let agents = payload
        .get("agents")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::http(502, "CodeArts agent 列表响应没有 agents 数组"))?;
    let mut ids = Vec::new();
    for agent in agents {
        let id = first_non_empty(&[text(agent, "agent_id"), text(agent, "original_id")]);
        if !id.is_empty() && !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// 解析 `/v1/benefit-gateway-config` 的总开关。`false` 表示"这个部署没有福利网关"。
pub fn parse_benefit_gate(body: &str) -> Result<bool> {
    let payload: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts 福利开关不是合法 JSON"))?;
    payload
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::http(502, "CodeArts 福利开关响应没有 enabled 字段"))
}

/// 解析福利网关的 `result.models`。
///
/// 成功判定看 **envelope 的 `error_code == "0000"`**，不是 HTTP 状态 —— 这个网关
/// 会把失败塞在 200 的体里（与流内错误信封同一个味道）。
pub fn parse_benefit(body: &str) -> Result<Vec<ModelConfig>> {
    let payload: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts 福利目录不是合法 JSON"))?;
    let code = text(&payload, "error_code");
    if code != "0000" {
        return Err(Error::http(502, format!("CodeArts 福利目录未成功（error_code={code}）")));
    }
    let result = payload
        .get("result")
        .ok_or_else(|| Error::http(502, "CodeArts 福利目录缺少 result"))?;
    let mut entries: Vec<(i64, Value)> = result
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|entry| (number(&entry, "sort"), entry))
        .collect();
    // 稳定排序：`sort` 相同的保持上游给的顺序
    entries.sort_by_key(|(sort, _)| *sort);
    let mut models = Vec::new();
    for (_, entry) in entries {
        let id = text(&entry, "model_id");
        if id.is_empty() {
            continue;
        }
        let name = text(&entry, "model_name");
        models.push(ModelConfig {
            display_name: if name.is_empty() { id.clone() } else { name },
            description: String::new(),
            context_length: number(&entry, "context_window"),
            max_output_tokens: capped_output(&entry, "max_tokens"),
            // 福利源对所有条目都写 false（不可信）；凭它拦请求会把真能看图的福利
            // 模型一起挡在门外，所以只作展示、不作判据
            supports_images: false,
            // 福利网关的条目没有 `credit`
            credit_display: String::new(),
            display_enabled: None,
            id,
            source: ModelSource::Benefit,
        });
    }
    if models.is_empty() {
        return Err(Error::http(502, "CodeArts 福利网关没有返回任何模型"));
    }
    Ok(models)
}

// ── 发现 ─────────────────────────────────────────────────────

/// 只签一次名的 GET（目录类请求都是 GET + 空体）。
fn fetch_signed(
    url: &str,
    agent_type: &str,
    credential: &Credential,
    host_signed: bool,
    domainless: bool,
) -> Result<String> {
    let signing = signer::Credential {
        access_key_id: credential.access_key_id.clone(),
        secret_access_key: credential.secret_access_key.clone(),
        security_token: credential.security_token.clone(),
        // 福利网关的签名契约：**带 Host、不带 X-Domain-Id**
        domain_id: if domainless { String::new() } else { credential.domain_id.clone() },
    };
    let mut headers = base_headers();
    if !agent_type.is_empty() {
        headers.push(("Agent-Type".to_string(), agent_type.to_string()));
    }
    let signed = signer::sign("GET", url, &headers, b"", &signing, host_signed)
        .map_err(|reason| Error::http(500, reason))?;
    let (status, body) = upstream::read_body(
        upstream::get(url, upstream::header_object(&signed))?,
        1024 * 1024,
    )?;
    if status != 200 {
        return Err(Error::http(status, format!("HTTP {status}")));
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

/// 目录类请求共用的头（参与签名，少一个就 401）。
fn base_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
        ("X-Language".to_string(), upstream::DEFAULT_LANGUAGE.to_string()),
        ("plugin-name".to_string(), upstream::DEFAULT_PLUGIN_NAME.to_string()),
        ("plugin-version".to_string(), upstream::DEFAULT_PLUGIN_VERSION.to_string()),
        (
            "client_version".to_string(),
            format!("Vscode_{}", upstream::DEFAULT_PLUGIN_VERSION),
        ),
        ("is_confidential".to_string(), "false".to_string()),
    ]
}

/// agent id 列表（分页，照参考实现的 100/页、最多 100 页）。
fn fetch_agent_ids(credential: &Credential) -> Result<Vec<String>> {
    const PAGE: usize = 100;
    let base = upstream::base();
    let mut ids = Vec::new();
    for page in 0..100usize {
        let query = format!(
            "offset={}&limit={PAGE}&is_primary_agent=true&supported_client=VSCODE&min_compatible_plugin_version={}",
            page * PAGE,
            upstream::form_escape(upstream::DEFAULT_PLUGIN_VERSION)
        );
        let body = fetch_signed(
            &format!("{base}/v1/agent-center/agents/useragents?{query}"),
            "AgentCenter",
            credential,
            false,
            false,
        )?;
        let page_ids = parse_agent_ids(&body)?;
        let count = page_ids.len();
        for id in page_ids {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if count < PAGE {
            break;
        }
    }
    Ok(ids)
}

/// 福利网关：先看总开关，开了再取目录。
fn fetch_benefit(credential: &Credential) -> Result<Option<Vec<ModelConfig>>> {
    let base = upstream::base();
    let gate = fetch_signed(
        &format!("{base}/v1/benefit-gateway-config"),
        "PromptCenter",
        credential,
        false,
        false,
    )?;
    if !parse_benefit_gate(&gate)? {
        return Ok(None);
    }
    let body = fetch_signed(
        &format!("{}/api/v1/gateway/config", upstream::benefit_base()),
        "",
        credential,
        true,
        true,
    )?;
    parse_benefit(&body).map(Some)
}

/// 抓三个源并合并成一份清单。
///
/// 任何一个源失败都只记 `warnings` 不中断 —— 目录是"能拿到多少算多少"，
/// 少一个源最多是少几个模型，不该让整个刷新失败。
pub fn discover(credential: &Credential) -> Catalog {
    let base = upstream::base();
    let mut catalog = Catalog::default();
    let mut agent_models = Vec::new();
    match fetch_agent_ids(credential) {
        Ok(ids) => {
            for id in ids {
                let url = format!(
                    "{base}/v1/agent-center/agents/detail?agent_id={}",
                    upstream::form_escape(&id)
                );
                match fetch_signed(&url, "AgentCenter", credential, false, false) {
                    Ok(body) => match parse_agent_detail(&body, upstream::DEFAULT_LANGUAGE) {
                        Ok(models) => append_unique(&mut agent_models, models),
                        Err(error) => catalog.warnings.push(format!("agent 目录 {id}：{}", error.message)),
                    },
                    Err(error) => catalog.warnings.push(format!("agent 目录 {id}：{}", error.message)),
                }
            }
        }
        Err(error) => catalog.warnings.push(format!("agent 列表：{}", error.message)),
    }
    let builtin = match fetch_signed(
        &format!("{base}/v1/model/builtin"),
        "PromptCenter",
        credential,
        false,
        false,
    ) {
        Ok(body) => match parse_builtin(&body) {
            Ok(models) => models,
            Err(error) => {
                catalog.warnings.push(format!("builtin 目录：{}", error.message));
                Vec::new()
            }
        },
        Err(error) => {
            catalog.warnings.push(format!("builtin 目录：{}", error.message));
            Vec::new()
        }
    };
    let mut models = agent_models;
    append_unique(&mut models, builtin);

    match fetch_benefit(credential) {
        Ok(Some(benefit)) => append_unique(&mut models, benefit),
        Ok(None) => {}
        Err(error) => catalog.warnings.push(format!("福利目录：{}", error.message)),
    }
    if models.is_empty() {
        catalog.warnings.push("该账号没有返回任何可用模型".to_string());
    }
    catalog.models = models;
    catalog
}

// ── 缓存 ─────────────────────────────────────────────────────

/// 清单 → 缓存 payload（带 `fetchedAt`：恢复时界面「更新日期」才如实）。
fn saved_payload(catalog: &Catalog) -> Value {
    json!({
        "fetchedAt": sdk::now(),
        "catalog": {
            "models": catalog.models.iter().map(ModelConfig::to_value).collect::<Vec<_>>(),
            "warnings": catalog.warnings,
        },
    })
}

/// 缓存 payload → 清单（空清单按「没有缓存」处理）。
fn from_saved(payload: &Value) -> Option<(Catalog, i64)> {
    let entries = payload["catalog"]["models"].as_array()?;
    let models: Vec<ModelConfig> = entries.iter().filter_map(ModelConfig::from_value).collect();
    if models.is_empty() {
        return None;
    }
    let warnings: Vec<String> = payload["catalog"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect();
    Some((Catalog { models, warnings }, payload["fetchedAt"].as_i64().unwrap_or(0)))
}

/// 一份清单的缓存时长：正常 5 分钟；**有告警时 30 秒** —— 少几个模型时更该快点
/// 重试，而不是把不完整的清单钉住五分钟。
fn ttl_for(catalog: &Catalog) -> i64 {
    if catalog.warnings.is_empty() {
        CACHE_TTL_MS
    } else {
        CACHE_TTL_WARNING_MS
    }
}

/// 读缓存（不论是否过期都返回，另带拉取时刻）。
pub fn cached() -> Option<(Catalog, i64)> {
    from_saved(&sdk::session_get(CACHE_KEY).ok()?)
}

/// 写缓存。写失败不影响本次刷新（只是下次要重新拉）。
fn store(catalog: &Catalog) {
    let ttl = ttl_for(catalog).max(CACHE_TTL_MS);
    let _ = sdk::session_put(CACHE_KEY, saved_payload(catalog), ttl);
}

/// 转发前的**目录准备**：缓存 → 就地补拉一次。
///
/// ── 为什么要就地补拉 ────────────────────────────────────────
/// 原来拿不到目录就直接拒绝（"请先在模型页执行一次「获取模型」"），于是**每次
/// 插件重启后**、在刷新链路成功之前，所有请求都被拒。而网关自己恢复出来的那份
/// 目录喂的是它的 `/v1/models` 与选路 —— 插件拿不到它。症状就是「模型页列得
/// 出来、一发请求却说目录没拉取过」。现在：缓存有就用；没有就**真拉一次**，拉
/// 不到才报错 —— 那是个不该存在的门槛。
pub fn ensure_catalog() -> Result<Catalog> {
    if let Some((catalog, _)) = cached() {
        return Ok(catalog);
    }
    let credential = super::credentials::ensure(false)?;
    let catalog = discover(&credential);
    if catalog.models.is_empty() {
        let reason = catalog
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "上游没有返回可用的模型目录".to_string());
        return Err(Error::http(
            503,
            format!(
                "CodeArts 模型目录还没有拉取成功：{reason}\
                 （稍后会自动重试，也可在模型页点一次「获取模型」）"
            ),
        )
        .with_code("catalog_unavailable"));
    }
    store(&catalog);
    Ok(catalog)
}

/// 刷新目录（`models.refresh` 的实现）。
pub fn refresh(force: bool) -> Result<Value> {
    if !force {
        if let Some((catalog, fetched_at)) = cached() {
            let age = sdk::now().saturating_sub(fetched_at);
            if age >= 0 && age < ttl_for(&catalog) {
                return Ok(json!({ "refreshed": false, "count": catalog.models.len() }));
            }
        }
    }
    let credential = super::credentials::ensure(false)?;
    let catalog = discover(&credential);
    if catalog.models.is_empty() {
        let reason = catalog
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "该账号没有返回任何可用模型".to_string());
        return Ok(json!({ "refreshed": false, "message": reason }));
    }
    store(&catalog);
    Ok(json!({
        "refreshed": true,
        "count": catalog.models.len(),
        "models": entries_of(&catalog),
        "meta": { "remote": true, "refreshed_at": sdk::now(), "warnings": catalog.warnings },
    }))
}

/// 缓存清单转成适配器契约要的条目形状（camelCase，与其余家的 `list()` 一致）。
///
/// `contextWindow` 为 0 时不写这个键 —— 上层对缺字段是"未知"，对 0 是"没有上下文"。
pub fn list() -> Value {
    match cached() {
        Some((catalog, fetched_at)) => json!({
            "models": entries_of(&catalog),
            "meta": { "remote": true, "refreshed_at": fetched_at, "warnings": catalog.warnings },
        }),
        // 没刷过就是空清单：上层据此报「账号没有可用模型」。
        // **绝不**塞静态兜底（那会广告出一批"列出来但一调就 400"的幽灵模型）。
        None => json!({ "models": [], "meta": { "remote": false, "refreshed_at": 0 } }),
    }
}

/// `Catalog` → 条目数组。
fn entries_of(catalog: &Catalog) -> Vec<Value> {
    catalog
        .models
        .iter()
        .map(|model| {
            let mut entry = serde_json::Map::new();
            entry.insert("id".to_string(), Value::String(model.id.clone()));
            entry.insert(
                "name".to_string(),
                Value::String(if model.display_name.is_empty() {
                    model.id.clone()
                } else {
                    model.display_name.clone()
                }),
            );
            entry.insert("providerModel".to_string(), Value::String(model.id.clone()));
            entry.insert("supportsImages".to_string(), Value::Bool(model.supports_images));
            entry.insert("supportsToolCall".to_string(), Value::Bool(true));
            entry.insert("source".to_string(), Value::String(model.source.as_str().to_string()));
            entry.insert("benefit".to_string(), Value::Bool(model.benefit()));
            if model.context_length > 0 {
                entry.insert("contextWindow".to_string(), Value::from(model.context_length));
            }
            if model.max_output_tokens > 0 {
                entry.insert("maxOutputTokens".to_string(), Value::from(model.max_output_tokens));
            }
            if !model.description.is_empty() {
                entry.insert("description".to_string(), Value::String(model.description.clone()));
            }
            // 倍率列：`credits` 是本仓跨家共用的键，上游给的 `0.7x` 原样显示
            if !model.credit_display.is_empty() {
                entry.insert("credits".to_string(), Value::String(model.credit_display.clone()));
            }
            // 三态：`Some(true)` 官方展示；`Some(false)` 上游说不展示；`None` 按可见处理。
            // **只有显式 false 才判藏** —— 上游删字段不能把整张表滤空。
            if let Some(flag) = model.display_enabled {
                entry.insert("display_enabled".to_string(), Value::Bool(flag));
            }
            let visibility = if model.display_enabled == Some(false) { "hidden" } else { "shown" };
            entry.insert("visibility".to_string(), Value::String(visibility.to_string()));
            Value::Object(entry)
        })
        .collect()
}

/// 模型不在清单里时的错误（带 `model_not_found`：别家都带这个 code，
/// 少一个就会让「按 code 分支」的客户端在本家落到默认分支）。
pub fn unknown_model_error(requested: &str, catalog: &Catalog) -> Error {
    let mut hint: Vec<&str> = catalog.models.iter().take(6).map(|model| model.id.as_str()).collect();
    if catalog.models.len() > hint.len() {
        hint.push("…");
    }
    Error::http(
        400,
        format!(
            "CodeArts 账号没有模型 {requested:?}（该账号当前可用：{}）",
            hint.join(", ")
        ),
    )
    .with_code("model_not_found")
}
