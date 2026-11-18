//! 对话转发：插件自己发请求、自己转 SSE，按 OpenAI chat 的形态吐给宿主。
//!
//! ── 为什么是 `conversation` 而不是 `chat` ────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对任何 wasm 包直接返回
//! 501「Wasm 对话必须使用标准流通道，不接受主程序代发计划」。真正生效的是
//! `conversation`：插件自己 `http::open` 发上游请求，再用 `stream_head` /
//! `stream_bytes` 把 SSE 回给宿主。所以本文件同时挂在两个方法名上，`chat` 那条
//! 路径事实上不会被执行到。
//!
//! ── 缓冲策略（与 atomcode 的 `Output` 同一手法）───────────────
//! 先把事件攒进 `pending`，直到出现「确定是正常回答」的信号（正文 / 工具调用 /
//! 思考 / finish_reason）或攒满 64 KiB，才 `stream_head(200)` 并把缓冲一次性吐出。
//! 这样：
//!   - 上游回 200 但第一帧就是错误 → 一次干净的失败（status 由分类结果决定）；
//!   - 上游回 200 但正文是网页 / 空流 → 同样是一次失败，不会让客户端看到
//!     「200 + 空回答」。
//!
//! ── `sse_strip_newline_chunks`（能力位为 true）为什么在这里实现 ──
//! native 把这个能力位交给网关的 SSE 状态机，由它剥掉「整片只有换行」的正文分片
//! （实测占 34.5%）。wasm 侧的字节流**不经过**网关的状态机，所以这一层必须在
//! 插件里做：否则客户端会看到大量空行进正文。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use crate::account;
use crate::catalog;
use crate::errors;
use crate::normalize;
use crate::outbound;
use crate::reasoning;

/// 缓冲上限：攒到这个大小还没出现决定性信号，就当作正常流开始下发。
const PENDING_LIMIT: usize = 64 * 1024;

/// 上游错误体的读取上限（超过就只报状态码）。
const ERROR_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
struct Output {
    pending: Vec<Vec<u8>>,
    pending_size: usize,
    /// head 是否已经发出去
    started: bool,
    complete: bool,
    normal_finish: bool,
}

impl Output {
    /// 发 head 并把缓冲吐出去。
    fn start(&mut self) -> Result<()> {
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
        }
        for bytes in self.pending.drain(..) {
            sdk::stream_bytes(&bytes)?;
        }
        self.pending_size = 0;
        Ok(())
    }

    /// 一条 SSE 事件（`data:` 后面的那段文本）。
    fn event(&mut self, data: &str) -> Result<()> {
        if self.complete {
            return Ok(());
        }
        if data.trim() == "[DONE]" {
            if !self.started {
                // 一帧正文都没发就结束了：这不是正常回答
                if !self.normal_finish {
                    return Err(Error::http(502, "WorkBuddy 未返回有效内容或结束原因"));
                }
                self.start()?;
            }
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            self.complete = true;
            return Ok(());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| Error::new("WorkBuddy 流式事件格式无效"))?;
        // 流内错误帧：上游偶尔用 200 + {"error": …} 表达失败
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(errors::http_error(stream_status(&value), &value));
        }
        // 业务信封（`{code, msg}`）出现在流里同样算失败
        if errors::code(&value).is_some_and(|code| code != 0) {
            return Err(errors::http_error(502, &value));
        }
        let choices = value["choices"]
            .as_array()
            .ok_or_else(|| Error::new("WorkBuddy 流式事件缺少 choices"))?;
        let mut decisive = false;
        for choice in choices {
            let delta = &choice["delta"];
            if delta["content"].as_str().is_some_and(|text| !text.is_empty()) {
                decisive = true;
            }
            decisive |= delta["tool_calls"].as_array().is_some_and(|calls| !calls.is_empty())
                || delta["reasoning_content"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty())
                || delta["reasoning"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty());
            if let Some(reason) = choice["finish_reason"].as_str() {
                if matches!(reason, "content_filter" | "safety") {
                    return Err(Error::http(403, "WorkBuddy 上游内容审核未通过")
                        .with_code("content_filter"));
                }
                self.normal_finish = true;
            }
        }
        // 「整片只有换行」的节拍：不带 finish_reason 也不带工具/思考，直接丢弃
        // （能力位 `sse_strip_newline_chunks` 的插件侧实现，见模块头）
        if newline_only(&value) {
            return Ok(());
        }
        let bytes = format!("data: {data}\n\n").into_bytes();
        if self.started {
            sdk::stream_bytes(&bytes)?;
            return Ok(());
        }
        self.pending_size += bytes.len();
        self.pending.push(bytes);
        if decisive || self.normal_finish || self.pending_size > PENDING_LIMIT {
            self.start()?;
        }
        Ok(())
    }

    /// 消费一次上游响应（已确认 2xx）。
    fn consume(&mut self, mut response: http::Response) -> Result<()> {
        let content_type =
            crate::util::header_of(&response.headers, "content-type").to_ascii_lowercase();
        // 非流式 JSON：上游忽略了 stream 参数（客户端要流式时不能让界面卡住，
        // 所以这里把整段回答折成一条 chunk + [DONE]，与 atomcode 同一手法）
        if content_type.contains("application/json") {
            let value = response.json()?;
            if value.get("error").is_some_and(|error| !error.is_null()) {
                return Err(errors::http_error(502, &value));
            }
            if errors::code(&value).is_some_and(|code| code != 0) {
                return Err(errors::http_error(502, &value));
            }
            let choices = value["choices"]
                .as_array()
                .ok_or_else(|| Error::new("WorkBuddy 响应缺少 choices"))?;
            let mut chunk = value.clone();
            chunk["object"] = json!("chat.completion.chunk");
            chunk["choices"] = Value::Array(
                choices
                    .iter()
                    .map(|choice| {
                        let mut choice = choice.clone();
                        choice["delta"] = choice["message"].clone();
                        if let Some(choice) = choice.as_object_mut() {
                            choice.remove("message");
                        }
                        choice
                    })
                    .collect(),
            );
            self.event(&chunk.to_string())?;
            return self.event("[DONE]");
        }
        // 网页 / HTML：多半是被网关或风控拦了，绝不能当回答转出去
        if content_type.contains("text/html") {
            return Err(Error::http(502, "WorkBuddy 返回了网页而不是模型回答"));
        }
        let mut decoder = SseDecoder::default();
        while let Some(bytes) = response.read()? {
            for event in decoder.push(&bytes)? {
                self.event(&event)?;
            }
            if self.complete {
                return Ok(());
            }
        }
        // 上游没有 `[DONE]`：实测它偶尔只给 finish_reason 就断流。已经收到过
        // finish_reason 的按正常结束处理（补一个 [DONE]），否则如实报中断。
        if self.normal_finish {
            self.event("[DONE]")
        } else {
            Err(Error::http(
                502,
                "WorkBuddy 上游流提前中断，未收到完整结束标记",
            ))
        }
    }
}

/// 这一帧是不是「整片只有换行」的正文节拍（可以安全丢弃）。
fn newline_only(value: &Value) -> bool {
    let Some(choices) = value["choices"].as_array() else {
        return false;
    };
    if choices.is_empty() {
        return false;
    }
    choices.iter().all(|choice| {
        if choice.get("finish_reason").is_some_and(|value| !value.is_null()) {
            return false;
        }
        let delta = &choice["delta"];
        let content = delta.get("content").and_then(Value::as_str).unwrap_or("");
        if content.is_empty() {
            return false;
        }
        if !content.chars().all(|ch| ch == '\n' || ch == '\r') {
            return false;
        }
        !["tool_calls", "reasoning_content", "reasoning", "function_call"]
            .iter()
            .any(|key| delta.get(*key).is_some_and(|value| !value.is_null()))
    })
}

/// 流内错误帧的状态码（`error.status` / `error.code`，只接受 4xx-5xx）。
fn stream_status(value: &Value) -> u16 {
    value["error"]["status"]
        .as_u64()
        .or_else(|| value["error"]["code"].as_u64())
        .or_else(|| {
            value["error"]["code"]
                .as_str()
                .and_then(|code| code.parse::<u64>().ok())
        })
        .filter(|status| (400..600).contains(status))
        .unwrap_or(502) as u16
}

/// `chat` / `conversation` 的共同实现。
///
/// 入参就是宿主传下来的同一份请求 JSON（`ConversationRequest` 的序列化形态）：
/// `{provider, account, body, headers, stream, wire_model, …}`。
pub fn forward(params: &Value) -> Result<()> {
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "WorkBuddy 请求体必须是 JSON 对象"));
    }
    let requested = body["model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::http(400, "请求缺少模型名称"))?
        .to_string();

    // 账号会话（扁平 secret → 会话形状），与 native `session_of` 同形
    let record = account::record()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    if !secret.is_object() {
        return Err(Error::http(401, "WorkBuddy 当前没有可用账号，请先完成登录"));
    }
    let token = account::ensure()?;
    // `ensure` 可能刚换过 token：重建一份会话并把最新 token 写回去，避免拿旧
    // token 拼头（`ensure` 内部回写账号后会重新读记录）
    let latest = account::secret().unwrap_or(secret);
    let mut session = outbound::session_of_record(&latest);
    session["auth"]["accessToken"] = json!(token);

    // 发送名：网关解析出的 wire_model 优先（备援改写之后、上游认识的那个名字）
    let wire_model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(requested.as_str())
        .to_string();
    let wire_model = catalog::wire_id(&wire_model, params["account"].as_str().unwrap_or(""));
    // 企业账号的模型授权守卫（个人账号只会挡「仅企业目录声明」的模型）
    let model = catalog::check(&session, &wire_model)?;
    body["model"] = json!(wire_model);

    // 出站归一（顺序不可调换：先归一 role，再判首条 system）
    let (mut normalized, report) = normalize::normalize_outbound(&body, &session);
    reasoning::normalize_outbound(&mut normalized, model.as_ref());
    let _ = report.describe();
    let body = outbound::ensure_leading_system_message(&normalized).unwrap_or(normalized);

    let mut body = body;
    // 插件自己发就一定要流式：宿主那一侧是按 SSE 转发的，上游若回整段 JSON
    // 由 `consume` 折成一条 chunk（见那里的说明）。上游对 stream:false 会回
    // code=11101，所以这一步也是必须的。
    body["stream"] = json!(true);
    if !body.get("stream_options").is_some_and(Value::is_object) {
        body["stream_options"] = json!({});
    }
    body["stream_options"]["include_usage"] = json!(true);

    let url = outbound::chat_completions_url(&session);
    let headers = outbound::chat_headers(&session, Some("text/event-stream"));
    let response = http::open("POST", &url, crate::util::headers_value(&headers), Some(&body))
        .map_err(|error| crate::httpio::transport_error("WorkBuddy 对话请求", error))?;
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let bytes = response.bytes(ERROR_BODY_LIMIT)?;
        let error: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        return Err(errors::http_error(status, &error));
    }
    let mut output = Output::default();
    match output.consume(response) {
        Ok(()) => Ok(()),
        Err(error) if output.started => {
            // 已下发内容后只报告中断，不能把整个请求悄悄从头重发。
            sdk::stream_event(&errors::error_event(&error))?;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_only_chunks_are_dropped() {
        assert!(newline_only(&json!({
            "choices": [{ "delta": { "content": "\n\n" }, "finish_reason": null }]
        })));
        // 正文里带实字：不能丢
        assert!(!newline_only(&json!({
            "choices": [{ "delta": { "content": "a\n" }, "finish_reason": null }]
        })));
        // 带 finish_reason：不能丢（那是结束信号）
        assert!(!newline_only(&json!({
            "choices": [{ "delta": { "content": "\n" }, "finish_reason": "stop" }]
        })));
        // 带工具调用：不能丢
        assert!(!newline_only(&json!({
            "choices": [{ "delta": { "content": "\n", "tool_calls": [{ "id": "x" }] }, "finish_reason": null }]
        })));
        // 纯 usage 帧（choices 空）：不能丢
        assert!(!newline_only(&json!({ "choices": [] })));
    }

    #[test]
    fn stream_status_prefers_explicit_codes() {
        assert_eq!(stream_status(&json!({ "error": { "status": 429 } })), 429);
        assert_eq!(stream_status(&json!({ "error": { "code": "401" } })), 401);
        assert_eq!(stream_status(&json!({ "error": { "code": 1_000_007 } })), 502);
        assert_eq!(stream_status(&json!({})), 502);
    }

    #[test]
    fn forward_rejects_bad_bodies_before_any_network_call() {
        assert_eq!(forward(&json!({})).err().and_then(|e| e.status), Some(400));
        assert_eq!(
            forward(&json!({ "body": { "messages": [] } })).err().and_then(|e| e.status),
            Some(400)
        );
    }
}
