//! 套餐池请求的**会话归因**（native `zcode/request_context.rs` 的移植）。
//!
//! ── 为什么请求头与 metadata 必须用同一个会话标识 ──────────────
//! 上游按 `x-session-id`（头）与 `metadata.user_id` 里那个 JSON 的 `session_id`
//! 把一次请求归到同一个会话上。两处取不同的值，等于向上游声称「这是两个会话
//! 的请求」—— 后果是会话归因错乱（上游报表按会话聚合），而不是一次可见的
//! 报错。所以两条路都必须从**同一个** [`RequestContext`] 取值。
//!
//! ── 取值顺序（逐条照抄 native）───────────────────────────────
//! 会话 id：请求头（7 个候选名）→ metadata 的 `sessionId` / `conversationId`
//! → `metadata.user_id` 里 JSON 的 `session_id` → 新生成一个 UUID。
//! 前缀（`sess_` / `subagent_agent_`）会剥掉：上游认裸 id。
//!
//! `session_type` 恒 `main`：本通道装配主会话提示词，不能沿用客户端的子代理
//! 会话类型（那会让上游按子代理的形态校验这份报文）。

use agent2api_wasm_sdk::Value;

use super::common::new_uuid;

/// 会话 id 上会出现的两种前缀（剥掉后才是上游认的裸 id）。
const SESSION_PREFIXES: [&str; 2] = ["sess_", "subagent_agent_"];

/// 客户端可能用哪几个头传会话 id（按优先级）。
const SESSION_HEADERS: [&str; 7] = [
    "x-opencode-session",
    "x-claude-code-session-id",
    "claude-code-session-id",
    "x-vscode-sessionid",
    "x-session-id",
    "x-parent-session-id",
    "helicone-session-id",
];

/// 一次请求的归因字段。
pub struct RequestContext {
    request_id: Option<String>,
    trace_id: Option<String>,
    query_id: Option<String>,
    session_id: Option<String>,
    session_type: &'static str,
}

impl RequestContext {
    /// 从客户端头与请求体构造。
    ///
    /// `headers` 是网关给的小写键映射（`ConversationRequest.headers`）。
    pub fn new(headers: &serde_json::Map<String, Value>, body: &Value) -> Self {
        let metadata = body.get("metadata");
        // `metadata.user_id` 在 Claude Code 那一族客户端里是一个**JSON 字符串**
        // （`{"session_id": "…"}`），解析不出来的按「没有」处理
        let user_id = metadata
            .and_then(|value| value.get("user_id"))
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok());
        let session_id = header(headers, &SESSION_HEADERS)
            .or_else(|| field(metadata, &["sessionId", "session_id", "conversationId", "conversation_id"]))
            .or_else(|| field(user_id.as_ref(), &["session_id"]))
            .or_else(new_uuid);
        Self {
            request_id: header(headers, &["x-request-id", "x-client-request-id"])
                .or_else(|| field(metadata, &["requestId", "request_id"]))
                .or_else(new_uuid),
            trace_id: header(headers, &["x-zcode-trace-id"])
                .or_else(|| field(metadata, &["traceId", "trace_id"]))
                .or_else(new_uuid),
            query_id: header(headers, &["x-query-id"])
                .or_else(|| field(metadata, &["queryId", "query_id"]))
                .map(|id| strip_prefixes(&id, &["query_"]).to_string()),
            session_id: session_id.map(|id| strip_prefixes(&id, &SESSION_PREFIXES).to_string()),
            // 本通道装配主会话提示词，不能沿用客户端的子代理会话类型。
            session_type: "main",
        }
    }

    /// 要发上游的归因头（顺序与 native 一致）。
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if let Some(id) = &self.request_id {
            headers.push(("x-request-id".to_string(), id.clone()));
        }
        headers.push(("x-zcode-session-type".to_string(), self.session_type.to_string()));
        if let Some(id) = &self.trace_id {
            headers.push(("x-zcode-trace-id".to_string(), id.clone()));
        }
        if let Some(id) = &self.query_id {
            headers.push(("x-query-id".to_string(), id.clone()));
        }
        if let Some(id) = &self.session_id {
            headers.push(("x-session-id".to_string(), id.clone()));
        }
        headers
    }

    /// `metadata.user_id` 的值（一个 JSON 字符串，见本文件的取值顺序）。
    ///
    /// `account_uuid` 恒空：上游的账号身份不在这条通道上（它认 JWT），
    /// 填一个猜的值反而是错的信息。
    pub fn metadata_user_id(&self, device_mid: &str) -> Option<String> {
        let mut blob = serde_json::json!({
            "account_uuid": "",
            "session_id": self.session_id.as_deref().unwrap_or(""),
        });
        if !device_mid.trim().is_empty() {
            blob["device_id"] = Value::String(device_mid.trim().to_string());
        }
        serde_json::to_string(&blob).ok()
    }
}

/// 按候选头名取值（键已小写；值必须是可打印 ASCII）。
fn header(headers: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        headers
            .get(*key)
            .and_then(Value::as_str)
            .and_then(printable)
    })
}

/// 从 JSON 对象里按候选键取值。
fn field(value: Option<&Value>, keys: &[&str]) -> Option<String> {
    let value = value?;
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).and_then(printable))
}

/// 只接受可打印 ASCII、长度合理（防止把控制字符塞进上游头）。
fn printable(raw: &str) -> Option<String> {
    let text = raw.trim();
    (!text.is_empty()
        && text.len() <= 2048
        && text.bytes().all(|byte| (32..=126).contains(&byte)))
    .then(|| text.to_string())
}

/// 剥掉已知前缀（只剥一层，与 native `strip_prefixes` 同义）。
fn strip_prefixes<'a>(value: &'a str, prefixes: &[&str]) -> &'a str {
    let mut out = value;
    for prefix in prefixes {
        if let Some(rest) = out.strip_prefix(prefix).filter(|rest| !rest.is_empty()) {
            out = rest;
        }
    }
    out
}
