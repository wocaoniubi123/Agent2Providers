//! AutoClaw 对话转发（`conversation` 方法的实现主体）。
//!
//! ── 为什么是 `conversation` 而不是 `chat` ────────────────────
//! 网关对 wasm 包的 `chat` 直接返回 501，且 `forwards_response()` 对 wasm 恒为
//! true —— 所以对话一律走会话式通道：插件自己 `http::open` 发请求，再用
//! `stream_head` / `stream_bytes` 把 SSE 回传。
//!
//! ── 上游是 OpenAI 兼容代理，但仍要自己发 ────────────────────
//! 请求体基本透传，但有**四道闸**要在出站前处理（每条都有实测依据，见
//! `prompt.rs` 与 `chat::normalize_max_tokens`）：
//!   1. `max_tokens` 小正整数 → 406 空响应体 → 归一到 10000；
//!   2. system 首句指纹 → 403 / 406 → `prompt::normalize` 前置身份前缀 + 改写
//!      外来身份句；
//!   3. `X-Harness-Type: zcode` → 403 pay-view / 406 → 转发**不发**这个头；
//!   4. 请求体带 `metadata` → 500 `parse response failed` → 整段删除。
//!
//! ── 两种流式改写（`wasm.json` 里的能力位与这里一一对应）────────
//!   · `sse_model_rewrite`：上游回自己的路由名，要改写成客户端请求的名字；
//!   · `sse_strip_newline_chunks`：上游把每帧都拼成 `{role, content}`，纯换行的
//!     节拍帧要丢（否则客户端会看到一堆空行）。
//!
//! ── 两种边界 ────────────────────────────────────────────────
//!   - **尚未下发就出错**：直接 `Err`（网关据此写错误响应、换号 / 刷新）；
//!   - **已下发后出错**：先补 `{error}` 帧 + `[DONE]` 再 `Err` —— 客户端看到的
//!     是一条完整的流（带错误说明），而不是半截断线。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};
use std::collections::VecDeque;

use super::credential::{self, Credential};
use super::models;
use super::prompt;
use super::region::{self, Region};
use super::sign;

/// 客户端透传头：`(上游头名, 客户端头名)`（源 `modelProxyUpstreamHeaders` 的表）。
///
/// 客户端带了才发（去空白后非空），没带就整条不发 —— 这三个是 ZCode/Agent 会话
/// 的关联 id，空值发上去会让上游按「有会话」处理。
const PASSTHROUGH_HEADERS: &[(&str, &str)] = &[
    ("X-Session-Id", "x-autoclaw-session-id"),
    ("X-Agent-Id", "x-autoclaw-agent-id"),
    ("X-ZCode-Invocation-Id", "x-autoclaw-zcode-invocation-id"),
];

/// 上游对出站 `max_tokens` 的下限（实测 8192 拒、10000 过）。
const MAX_TOKENS_FLOOR: i64 = 10_000;

/// 一次转发计划
struct ChatPlan {
    url: String,
    headers: Value,
    body: Value,
    /// 客户端请求的模型名（回流帧的 `model` 字段用它）
    model_name: String,
    /// 完整路由 ID（`X-Request-Model`）
    #[allow(dead_code)]
    route_model_id: String,
}

/// 客户端请求体 → 一次上游调用计划。
fn build_plan(region: Region, credential: &Credential, body: &Value) -> Result<ChatPlan> {
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let requested = body["model"].as_str().map(str::trim).unwrap_or("");
    // 客户端请求的模型名 → (路由 ID, body 模型 ID)。没给 model 时回落到默认路由。
    let route = models::resolve_model_route(region, requested);
    let mut headers = sign::brand_headers();
    if let Some(object) = headers.as_object_mut() {
        object.insert("Content-Type".to_string(), json!("application/json"));
        // 源实现给的是 `Accept: */*`（LLM 代理两种响应形态都可能回）
        object.insert("Accept".to_string(), json!("*/*"));
        // 认证头名照抄源实现（`X-Authorization`，不是 `Authorization`）
        object.insert(
            "X-Authorization".to_string(),
            json!(format!("Bearer {}", credential.token)),
        );
        object.insert("X-Request-Id".to_string(), json!(super::codec::random_hex_id()));
        object.insert("X-Request-Model".to_string(), json!(route.route_model_id.clone()));
    }
    let mut out_body = body.clone();
    if let Some(object) = out_body.as_object_mut() {
        object.insert("model".to_string(), json!(route.body_model_id.clone()));
    }
    normalize_max_tokens(&mut out_body);
    prompt::normalize(&mut out_body);
    // 最后一道：删掉客户端自带的 `metadata`（第四道闸，issue #388）。
    // 放在 prompt::normalize 之后，因为它只动 `messages`，两者互不干扰。
    strip_client_metadata(&mut out_body);
    Ok(ChatPlan {
        url: format!("{}/chat/completions", region::upstream_base()),
        headers,
        body: out_body,
        model_name: route.requested_model.clone(),
        route_model_id: route.route_model_id,
    })
}

/// 把客户端 header 里的三个关联 id 透传上去（带了才发）。
fn passthrough_headers(client_headers: &Value) -> Vec<(String, String)> {
    let mut output = Vec::new();
    for (upstream_name, client_name) in PASSTHROUGH_HEADERS {
        let value = client_headers
            .get(*client_name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(value) = value {
            output.push(((*upstream_name).to_string(), value.to_string()));
        }
    }
    output
}

/// 出站请求体 `max_tokens` 的**下限归一**（就地修改；#58 / #69 的修复）。
///
/// ── 上游行为 ────────────────────────────────────────────────
/// 上游对出站请求体里的 `max_tokens` **取值**有预校验：30 / 100 / 256 / 512 /
/// 1024 / 8192 这类**小正整数一律拒成 406 空响应体**；**不传该字段**或取值
/// ≥ 10000 都 200。下界落在 8192（拒）与 10000（过）之间，取实测过的安全值
/// 10000。超上界（超过该模型输出上限）上游回 500 —— 那是它自己的语义，本函数
/// **不碰**。`max_completion_tokens` 不参与该校验，**一字不动**。
///
/// ── 归一规则（只在「小正整数」窗口里动手）──────────────────
///   - 字段存在、是正整数、且 < 下限 → 改写为下限；
///   - **缺省时不注入**：上游对缺省是 200，凭空注入反而改变行为；
///   - ≥ 下限 / 0 / 负数 / null / 字符串 / 浮点 → **原样**：只归一实测过被拒的
///     「小正整数」形态，其余形态交上游自己报错，不在网关里猜语义。
fn normalize_max_tokens(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let below_floor = matches!(object.get("max_tokens"), Some(Value::Number(number))
        if number.as_i64().is_some_and(|value| value > 0 && value < MAX_TOKENS_FLOOR));
    if below_floor {
        object.insert(
            "max_tokens".to_string(),
            Value::Number(serde_json::Number::from(MAX_TOKENS_FLOOR)),
        );
    }
}

/// 删掉客户端自带的 `metadata` 字段（第四道上游闸，issue #388）。
///
/// ── 为什么必须删，而不是「转换」────────────────────────────────
/// 上游 `/chat/completions` 收到 `metadata` 时直接回 **500
/// `parse response failed`** —— 这不是 4xx 参数错误，而是一个看起来像
/// 「服务端坏了」的 500。于是客户端侧的表现为：调参数、换模型、重试全都没用，
/// 因为坏的是请求体的**形状**而不是内容。实测「同一完整请求仅删除 metadata
/// 就恢复 200」，因此这里整段删除而不是挑字段改写。
fn strip_client_metadata(body: &mut Value) {
    if let Some(object) = body.as_object_mut() {
        object.remove("metadata");
    }
}

/// 错误分类（逐条对照源实现 `forwardModelRequest`）。
///
///   - 401 → `token_expired`（刷新后同账号重试一次）；
///   - 429 → `quota_limited`（只按 HTTP 状态码；上游不给结构化恢复时间）；
///   - 400 等 → 内容拦截判定（这里按 fatal 处理，内容拦截在网关层）；
///   - 其余 → `fatal` 原样透传。
///
/// ── 406 空响应体为什么补一句提示 ────────────────────────────
/// 406 是上游预校验拒收的统一形态，实测过三个独立方向（`max_tokens` 取值 /
/// system 首句指纹 / 请求形态风控）。不给提示的话用户只会看到「上游返回
/// 406: 上游错误」，无从判断该改什么。
fn classify_status(status: u16, upstream_message: Option<&str>) -> (u16, String) {
    let message = match upstream_message {
        Some(text) if !text.trim().is_empty() => format!("上游返回 {status}: {}", text.trim()),
        _ if status == 406 => format!("上游返回 406: 上游错误{}", prompt::UPSTREAM_406_HINT),
        _ => format!("上游返回 {status}: 上游错误"),
    };
    let mapped = match status {
        401 => 401,
        429 => 429,
        _ => 502,
    };
    (mapped, message)
}

/// 已解码但未消费的 SSE 事件流。
struct EventStream {
    response: http::Response,
    decoder: SseDecoder,
    pending: VecDeque<String>,
    ended: bool,
    bytes_seen: usize,
}

impl EventStream {
    fn new(response: http::Response) -> Self {
        Self {
            response,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            ended: false,
            bytes_seen: 0,
        }
    }

    fn next_event(&mut self) -> Result<Option<String>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            if self.ended {
                return Ok(None);
            }
            match self.response.read()? {
                Some(bytes) => {
                    self.bytes_seen = self.bytes_seen.saturating_add(bytes.len());
                    for event in self.decoder.push(&bytes)? {
                        self.pending.push_back(event);
                    }
                }
                None => self.ended = true,
            }
        }
    }

    fn no_output_error(&self) -> Error {
        Error::http(
            502,
            format!("AutoClaw 上游返回空响应（已接收 {} 字节）", self.bytes_seen),
        )
        .with_code("autoclaw_empty_response")
    }
}

/// 一帧里有没有真正的增量（正文 / 思考 / 工具调用）。
fn frame_has_content(value: &Value) -> bool {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return false;
    };
    choices.iter().any(|choice| {
        let delta = &choice["delta"];
        delta["content"].as_str().is_some_and(|text| !text.is_empty())
            || delta["reasoning_content"].as_str().is_some_and(|text| !text.is_empty())
            || delta["reasoning"].as_str().is_some_and(|text| !text.is_empty())
            || delta["tool_calls"].as_array().is_some_and(|calls| !calls.is_empty())
            || choice["finish_reason"].is_string()
    })
}

/// `sse_strip_newline_chunks`：丢掉「正文只有换行 / 空白」的节拍帧。
///
/// 上游把每帧都拼成 `{role, content}`，纯换行的帧会让客户端渲染出一堆空行。
/// 判据只看**唯一的** content 选择项：带工具调用或 finish_reason 的帧一律保留
/// （哪怕 content 是空的）。
fn is_newline_only(value: &Value) -> bool {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return false;
    };
    if choices.len() != 1 {
        return false;
    }
    let choice = &choices[0];
    if choice["finish_reason"].is_string() {
        return false;
    }
    let delta = &choice["delta"];
    if delta["tool_calls"].as_array().is_some_and(|calls| !calls.is_empty()) {
        return false;
    }
    match delta["content"].as_str() {
        Some(text) => !text.is_empty() && text.trim().is_empty(),
        None => false,
    }
}

/// `sse_model_rewrite`：把回流帧的 `model` 改成客户端请求的名字。
fn rewrite_model(value: &mut Value, model_name: &str) {
    if model_name.is_empty() {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert("model".to_string(), json!(model_name));
    }
}

/// 收尾帧：`[DONE]`。
fn done_frame() -> String {
    "data: [DONE]\n\n".to_string()
}

/// 失败收尾（已下发过头之后）。
fn failure_frames(message: &str) -> String {
    let mut output = format!(
        "data: {}\n\n",
        json!({ "error": { "message": message, "type": "upstream_error" } })
    );
    output.push_str(&done_frame());
    output
}

/// `conversation` 的入口。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    let client_headers = params["headers"].clone();
    let record = credential::record()?;
    let mut credential = credential::credential(&record)?;
    // 临期先刷一次（与 `token.ensure` 同一判据）
    if credential.is_expiring() && credential.can_refresh() {
        credential::ensure()?;
        let record = credential::record()?;
        credential = credential::credential(&record)?;
    }
    let mut refreshed = false;
    loop {
        let plan = build_plan(region::REGION, &credential, &body)?;
        let mut headers = plan.headers.clone();
        if let Some(object) = headers.as_object_mut() {
            for (key, value) in passthrough_headers(&client_headers) {
                object.insert(key, json!(value));
            }
        }
        let response = http::open("POST", &plan.url, headers, Some(&plan.body))?;
        if !(200..300).contains(&response.status) {
            let status = response.status;
            let bytes = response.bytes(1024 * 1024).unwrap_or_default();
            let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let upstream_message = payload
                .get("message")
                .or_else(|| payload.get("msg"))
                .and_then(Value::as_str);
            let (mapped, message) = classify_status(status, upstream_message);
            let error = Error::http(mapped, message);
            // 只在首个有效输出之前补救，避免已下发内容或工具调用被重复执行
            if status == 401 && !refreshed && credential.can_refresh() {
                refreshed = true;
                credential::refresh()?;
                let record = credential::record()?;
                credential = credential::credential(&record)?;
                continue;
            }
            return Err(error);
        }
        let content_type = response
            .headers
            .get("content-type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        // 非流式（一次性 JSON）：转成一个 chunk 帧再收尾
        if content_type.contains("application/json") {
            let bytes = response.bytes(4 * 1024 * 1024)?;
            let mut value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| Error::http(502, "AutoClaw 响应不是有效 JSON"))?;
            if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("上游返回错误");
                return Err(Error::http(502, message.to_string()));
            }
            rewrite_model(&mut value, &plan.model_name);
            let mut chunk = value.clone();
            chunk["object"] = json!("chat.completion.chunk");
            if let Some(choices) = value.get("choices").and_then(Value::as_array) {
                chunk["choices"] = Value::Array(
                    choices
                        .iter()
                        .map(|choice| {
                            let mut choice = choice.clone();
                            choice["delta"] = choice["message"].clone();
                            if let Some(object) = choice.as_object_mut() {
                                object.remove("message");
                            }
                            choice
                        })
                        .collect(),
                );
            }
            sdk::stream_head(200)?;
            sdk::stream_bytes(format!("data: {chunk}\n\n").as_bytes())?;
            sdk::stream_bytes(done_frame().as_bytes())?;
            return Ok(());
        }
        if content_type.contains("text/html") {
            return Err(Error::http(502, "AutoClaw 返回了网页而不是模型回答"));
        }
        // 流式：先预读第一帧有内容的帧，再发响应头
        let mut stream = EventStream::new(response);
        let mut started = false;
        let mut pending: Vec<Value> = Vec::new();
        loop {
            let event = match stream.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    // 已下发：补一帧错误再收尾，客户端看到的是完整流
                    if started {
                        let _ = sdk::stream_bytes(failure_frames(&error.message).as_bytes());
                    }
                    return Err(error);
                }
            };
            let trimmed = event.trim();
            if trimmed == "[DONE]" {
                break;
            }
            let Ok(mut value) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("上游返回错误")
                    .to_string();
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(502);
                let mapped = if code == 401 { 401 } else { 502 };
                return Err(Error::http(mapped, message));
            }
            // 纯换行的节拍帧丢掉（`sse_strip_newline_chunks`）
            if is_newline_only(&value) {
                continue;
            }
            rewrite_model(&mut value, &plan.model_name);
            if !started {
                if !frame_has_content(&value) {
                    // 还没看到真正的内容：先攒着，不提前下发响应头
                    pending.push(value);
                    continue;
                }
                sdk::stream_head(200)?;
                started = true;
                for frame in pending.drain(..) {
                    sdk::stream_bytes(format!("data: {frame}\n\n").as_bytes())?;
                }
            }
            sdk::stream_bytes(format!("data: {value}\n\n").as_bytes())?;
        }
        if !started {
            return Err(stream.no_output_error());
        }
        sdk::stream_bytes(done_frame().as_bytes())?;
        return Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `max_tokens` 只在小正整数窗口里归一；缺省与其它形态原样。
    #[test]
    fn max_tokens_floor() {
        let mut body = json!({ "max_tokens": 1024 });
        normalize_max_tokens(&mut body);
        assert_eq!(10_000, body["max_tokens"].as_i64().unwrap_or(0));

        let mut body = json!({ "messages": [] });
        normalize_max_tokens(&mut body);
        assert!(body.get("max_tokens").is_none());

        let mut body = json!({ "max_tokens": 20000 });
        normalize_max_tokens(&mut body);
        assert_eq!(20_000, body["max_tokens"].as_i64().unwrap_or(0));
    }

    /// 纯换行的节拍帧被丢；带 finish_reason 或工具调用的帧保留。
    #[test]
    fn newline_chunks_are_stripped() {
        assert!(is_newline_only(&json!({ "choices": [{ "delta": { "role": "assistant", "content": "\n" } }] })));
        assert!(!is_newline_only(&json!({ "choices": [{ "delta": { "content": "hi" } }] })));
        assert!(!is_newline_only(&json!({ "choices": [{ "delta": { "content": "\n" }, "finish_reason": "stop" }] })));
    }

    /// `metadata` 必须整段删掉（否则上游 500）。
    #[test]
    fn metadata_is_stripped() {
        let mut body = json!({ "metadata": { "user_id": "x" }, "messages": [] });
        strip_client_metadata(&mut body);
        assert!(body.get("metadata").is_none());
    }
}
