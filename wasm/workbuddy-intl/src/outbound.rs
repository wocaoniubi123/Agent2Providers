//! 对话 URL、请求头与会话折叠（native `outbound.rs` 的插件侧副本）。
//!
//! ── 会话折叠为什么必须做 ────────────────────────────────────
//! 网关的账号记录本身就是会话形状（`account_store::session_from_record` 把记录
//! 上的字段收进 `account` / `auth` 两个子对象）。插件拿到的 secret 是**扁平的**
//! （各家自定义），而 `build_auth_headers` / `normalize` / billing 都按会话形状读。
//! 所以这里做一次折叠，让那些函数逐字可用。

use agent2api_wasm_sdk::{json, Value};

use crate::auth;
use crate::endpoints::{edition, normalize_endpoint, setting_text};
use crate::util;

/// 首条消息不是 system 时注入的兜底提示词（与 native 逐字相同）。
pub const DEFAULT_SYSTEM_PROMPT: &str = "你是一个得力助手";

/// 客户端首条消息不是 `system` 时，在最前面补一条兜底 system。
///
/// **必须在 `normalize_roles` 之后调用**：客户端用 `developer` 打头时，先归一成
/// `system` 才判得出「首条已是 system」；反过来会多注入一条兜底 system，而上游
/// 对多 system 的行为未实测。
pub fn ensure_leading_system_message(body: &Value) -> Option<Value> {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .filter(|messages| !messages.is_empty())?;
    let role = messages
        .first()
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if role.eq_ignore_ascii_case("system") {
        return None;
    }
    let mut next = body.clone();
    let fields = next.as_object_mut()?;
    let mut with_system = Vec::with_capacity(messages.len() + 1);
    with_system.push(json!({ "role": "system", "content": DEFAULT_SYSTEM_PROMPT }));
    with_system.extend(messages.iter().cloned());
    fields.insert("messages".into(), Value::Array(with_system));
    Some(next)
}

/// 扁平 secret → 会话形状（`{account, auth, edition, id, endpoint, ...}`）。
pub fn session_of_record(record: &Value) -> Value {
    let mut account = serde_json::Map::new();
    for key in [
        "uid",
        "enterpriseId",
        "type",
        "departmentFullName",
        "name",
        "nickname",
        "oneidAccountId",
        "idp",
    ] {
        if let Some(value) = record.get(key) {
            account.insert(key.into(), value.clone());
        }
    }
    let mut auth = serde_json::Map::new();
    for key in [
        "accessToken",
        "refreshToken",
        "expiresAt",
        "refreshExpiresAt",
        "domain",
        "tokenType",
    ] {
        if let Some(value) = record.get(key) {
            auth.insert(key.into(), value.clone());
        }
    }
    let mut session = serde_json::Map::new();
    session.insert("account".into(), Value::Object(account));
    session.insert("auth".into(), Value::Object(auth));
    session.insert("edition".into(), Value::String(edition().id.into()));
    for key in ["id", "endpoint", "prefixPath", "platform"] {
        if let Some(value) = record.get(key) {
            session.insert(key.into(), value.clone());
        }
    }
    Value::Object(session)
}

/// 对话请求头（与 native `chat_headers(Region::Intl)` 逐字相同）。
///
/// 这套头是上游按客户端身份识别通道的地方：UA / X-IDE-* / 追踪族（`traceparent`、
/// `b3`、`X-B3-*`）都按官方客户端抓包对齐。国际版的 UA 是
/// `WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0`（见 `endpoints::EDITION_INTL`）。
pub fn chat_headers(session: &Value, accept: Option<&str>) -> Vec<(String, String)> {
    let info = edition();
    let request_id = util::new_message_id();
    let message_id = util::new_message_id();
    let trace_id = util::new_message_id();
    let span_id = util::new_span_id();
    let mut headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("User-Agent".into(), info.chat_ua.into()),
        ("X-IDE-Type".into(), info.ua_platform.into()),
        ("X-IDE-Name".into(), info.ua_platform.into()),
        ("X-IDE-Version".into(), info.chat_ide_version.into()),
        ("X-Product".into(), "SaaS".into()),
        ("X-Agent-Intent".into(), "craft".into()),
        ("X-Agent-Purpose".into(), "conversation".into()),
        ("X-Agent-Type".into(), "main".into()),
        ("X-Private-Data".into(), "true".into()),
        ("X-Conversation-ID".into(), util::new_conversation_id()),
        ("X-Conversation-Request-ID".into(), request_id.clone()),
        ("X-Root-Request-ID".into(), request_id),
        ("X-Conversation-Message-ID".into(), message_id.clone()),
        ("X-Request-ID".into(), message_id),
        ("X-Trace-ID".into(), trace_id.clone()),
        ("traceparent".into(), format!("00-{trace_id}-{span_id}-01")),
        ("b3".into(), format!("{trace_id}-{span_id}-1")),
        ("X-B3-TraceId".into(), trace_id),
        ("X-B3-SpanId".into(), span_id),
        ("X-B3-Sampled".into(), "1".into()),
        ("X-Requested-With".into(), "XMLHttpRequest".into()),
    ];
    // ── 国际版与国内版在这一段的差别（native `chat_headers` 的 region 分叉）──
    // 国内版会额外带 `X-Agent-Runtime: local-agent`（官方客户端在「本地 agent」
    // 形态下才发）—— 国际版**不带**，带了会被渠道校验当成另一条通道。
    headers.extend(auth::build_auth_headers(session));
    // 国际版把 `X-Domain` 固定成官网 host：native 的
    // `headers.retain(!= X-Domain)` + `push("X-Domain", "www.workbuddy.ai")` 逐字对应。
    // 上游按这个头判「请求来自哪个站点」，跟着 `auth.domain` 走会在换了域名的账号上
    // 落到另一套渠道。
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("X-Domain"));
    headers.push(("X-Domain".into(), "www.workbuddy.ai".into()));
    if let Some(accept) = accept {
        headers.push(("Accept".into(), accept.into()));
    }
    headers
}

/// 会话端点：记录里的 `endpoint` 优先，其次设置项覆盖，最后地区默认值。
///
/// native 这一支还读 `WORKBUDDY_ENDPOINT` 环境变量；wasm 里换成设置项
/// （见 [`crate::endpoints::endpoint_override`]）。
pub fn session_endpoint_of(session: &Value) -> String {
    session
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(normalize_endpoint)
        .unwrap_or_else(|| {
            let fallback = setting_text("endpoint")
                .unwrap_or_else(|| edition().endpoint.to_string());
            normalize_endpoint(&fallback)
        })
}

/// 对话地址：`{endpoint}/v2/chat/completions`（不带 prefixPath）。
pub fn chat_completions_url(session: &Value) -> String {
    format!("{}/v2/chat/completions", session_endpoint_of(session))
}
