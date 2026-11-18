//! Accio 对话转发（`conversation` 方法的实现主体）。
//!
//! ── 为什么是 `conversation` 而不是 `chat` ────────────────────
//! 网关对 wasm 包的 `chat` 直接返回 501（`plugin_host/rpc.rs`：
//! `build_chat_request_async`），且 `forwards_response()` 对 wasm 恒为 true ——
//! 所以 wasm 包的对话一律走会话式通道：插件自己 `http::open` 发请求，
//! 再用 `stream_head` / `stream_bytes` 把 SSE 回传。
//!
//! ── 一次转发分三步 ─────────────────────────────────────────
//!   构造（[`build_plan`]）→ 发送（`http::open`）→ 翻译（`stream::Translator`）。
//! 与 native 的 `chat.rs` 完全同构，只是把 `reqwest` 换成了宿主 HTTP、
//! 把 `ConversationSink` 换成了 `stream_*`。
//!
//! ── 流内业务错误为什么要判两次 ────────────────────────────────
//! 上游的业务错误**不体现在 HTTP 状态码上**（常是 200 + 帧里的 `error_code`）。
//! 因此：
//!   - **首帧预读**：把第一个内容帧拦在 `stream_head` 之前，错误帧转成带状态码
//!     的 `Err` 交回编排层换号（此刻还没下发任何字节，换号无损）；
//!   - **流内**：中途才冒出来的额度/鉴权错误在错误现场写一个 error 帧再收尾
//!     （已经下发过头，改不了状态码了）。
//!
//! ── 两种边界 ────────────────────────────────────────────────
//!   - **尚未下发就出错**：直接 `Err` —— 网关据此写错误响应、换号 / 刷新；
//!   - **已下发后出错**：先补 `{error}` 帧 + `[DONE]` 再 `Err` —— 客户端看到的是
//!     一条完整的流（带错误说明），而不是半截断线。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic；发送前取好凭证快照。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};
use std::collections::VecDeque;

use super::credential::{self, Credential};
use super::models::{self, EffortPlacement};
use super::protocol::{self, UpstreamKind};
use super::region;
use super::stream::{self, Delta, Frame, Translator};

/// 首帧预读的上限：帧数与工具参数字节（防上游用「只有工具碎片」的流撑爆内存）
const PREFETCH_MAX_FRAMES: usize = 1024;
const PREFETCH_MAX_TOOL_BYTES: usize = 1024 * 1024;

/// 一次上游调用的完整计划（构造阶段不含网络）
#[allow(dead_code)]
struct ChatPlan {
    url: String,
    headers: Value,
    body: Value,
    /// 客户端请求的模型名（下发帧的 `model` 字段）
    model_name: String,
    /// 上游模型 code（排障时看「这次到底发了哪个代号」）
    upstream_key: String,
}

/// 客户端请求体 → 一次上游调用的完整计划。
fn build_plan(credential: &Credential, body: &Value) -> Result<ChatPlan> {
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let model_name = body["model"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::http(400, "请求缺少模型名称"))?
        .to_string();
    let entry = models::resolve(&model_name).ok_or_else(|| models::unknown_model_error(&model_name))?;
    let upstream_key = models::wire_id(&entry)
        .ok_or_else(|| Error::http(502, "Accio 模型目录缺少上游标识"))?;
    let efforts = models::efforts_of(&entry);
    // 档位按模型自己声明的集合收敛（发一个它没声明的档位要么被忽略要么 400）
    let requested = protocol::client_effort(body);
    let resolved_effort = requested.and_then(|level| protocol::resolve_effort(&level, &efforts));
    // 档位落点由目录条目的 `protocol` 决定（见 `models::EffortPlacement`）
    let placement: EffortPlacement = EffortPlacement::from_entry(&entry);
    let built = protocol::build_upstream_body(
        body,
        &upstream_key,
        &credential.access_token,
        resolved_effort.as_deref(),
        placement,
    );
    let request_id = built
        .body
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut headers = json!({
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "User-Agent": region::ADAPTER_USER_AGENT,
        "x-language": region::ACCEPT_LANGUAGE,
        // 两个版本头共用一份取值（`appVersion` 设置可覆盖），别各写各的
        "x-app-version": region::app_version(),
        "version": region::app_version(),
        "x-package-region": region::REGION.package_region(),
        // **必带**：缺了它上游不报错，而是回一段「当前版本已不再支持，请升级」
        // 的普通文本（HTTP 200 + 正常帧形态），会被当成模型输出吐给下游。
        "appKey": region::app_key(),
        // 设备指纹（utdid）：**必带**。上游把它当风控基线，缺了会回 HTTP 200 +
        // HTML 拦截页（bixi-intl 的 punish 脚本），症状是「空响应 / 模型不回复」。
        "utdid": credential.utdid(),
    });
    // 浏览器会话的伴随标识：有就带上（与官方客户端同形），没有也照发
    if !credential.sgcookie.is_empty() {
        headers["sgcookie"] = json!(credential.sgcookie);
    }
    Ok(ChatPlan {
        url: protocol::generate_content_url(&region::llm_base(), &request_id),
        headers,
        body: built.body,
        model_name,
        upstream_key,
    })
}

/// 已解码但未消费的 SSE 事件流。
struct EventStream {
    response: http::Response,
    decoder: SseDecoder,
    pending: VecDeque<String>,
    ended: bool,
    /// 收过多少字节（空响应 / 非 SSE 的排错文案要用）
    bytes_seen: usize,
    /// 收过任何 `data:` 事件（区分「空响应」与「非 SSE 响应」）
    saw_event: bool,
}

impl EventStream {
    fn new(response: http::Response) -> Self {
        Self {
            response,
            decoder: SseDecoder::default(),
            pending: VecDeque::new(),
            ended: false,
            bytes_seen: 0,
            saw_event: false,
        }
    }

    /// 下一个事件（None = 流结束）。
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
                // 上游总会以空行结束最后一条事件；没有收尾的残留数据按截断处理
                None => self.ended = true,
            }
        }
    }

    /// 下游可见的「没有有效输出」原因（把风控页 / HTML 与真空响应分开）。
    fn no_output_error(&self) -> Error {
        if self.bytes_seen == 0 || self.saw_event {
            return Error::http(502, "Accio 上游返回空响应（没有有效正文、思考或工具调用）")
                .with_code("accio_empty_response");
        }
        Error::http(
            502,
            format!("Accio 上游未返回 SSE 数据帧（已接收 {} 字节，可能是风控拦截页）", self.bytes_seen),
        )
        .with_code("accio_non_sse_response")
    }
}

/// 一帧的错误 → 网关错误（额度类带 429、鉴权类带 401）。
fn frame_error(frame: &Frame) -> Error {
    let text = frame.error_text();
    let status = frame.error_code.parse::<u16>().ok().unwrap_or(200);
    let kind = protocol::classify_upstream_error(status, &text);
    let mapped = match kind {
        UpstreamKind::Quota => 429,
        UpstreamKind::Auth => 401,
        UpstreamKind::Other => 502,
    };
    Error::http(mapped, format!("Accio 上游错误：{text}")).with_code("accio_upstream")
}

/// 失败响应 → 客户端可用错误（流内错误另走 [`frame_error`]）。
fn http_error(status: u16, bytes: &[u8]) -> Error {
    let text = String::from_utf8_lossy(bytes);
    let detail: String = text.chars().take(300).collect();
    let kind = protocol::classify_upstream_error(status, &text);
    let mapped = match kind {
        // 额度用尽 → 429（编排层据此换号）
        UpstreamKind::Quota => 429,
        // 凭证失效 → 401（编排层据此刷新后重试一次）
        UpstreamKind::Auth => 401,
        UpstreamKind::Other => 502,
    };
    let message = if detail.is_empty() {
        format!("上游返回 {status}")
    } else {
        format!("上游返回 {status}: {detail}")
    };
    Error::http(mapped, message).with_code("accio_upstream")
}

/// 面向客户端的 chunk 构造（流式）
fn chunk_frame(translator: &Translator, delta: Value, finish_reason: Value) -> Value {
    json!({
        "id": translator.response_id(),
        "object": "chat.completion.chunk",
        "created": translator.created(),
        "model": translator.model_out(),
        "choices": [{ "index": 0, "delta": delta, "finish_reason": finish_reason }],
    })
}

/// 把一批 delta 翻成下发的 SSE 帧
fn frames_for_deltas(translator: &mut Translator, deltas: &[Delta]) -> String {
    let mut out = String::new();
    if !deltas.is_empty() && translator.take_role_frame() {
        out.push_str(&stream::sse_frame(&chunk_frame(
            translator,
            json!({ "role": "assistant", "content": "" }),
            Value::Null,
        )));
    }
    for delta in deltas {
        let payload = match delta {
            Delta::Content(text) => json!({ "content": text }),
            Delta::Reasoning(text) => json!({ "reasoning_content": text }),
            Delta::ToolCall { index, id, name, arguments } => {
                let mut function = serde_json::Map::new();
                if let Some(name) = name {
                    function.insert("name".to_string(), Value::String(name.clone()));
                }
                if let Some(arguments) = arguments {
                    function.insert("arguments".to_string(), Value::String(arguments.clone()));
                }
                let mut call = serde_json::Map::new();
                call.insert("index".to_string(), json!(index));
                if let Some(id) = id {
                    call.insert("id".to_string(), Value::String(id.clone()));
                    call.insert("type".to_string(), Value::String("function".to_string()));
                }
                call.insert("function".to_string(), Value::Object(function));
                json!({ "tool_calls": [Value::Object(call)] })
            }
        };
        out.push_str(&stream::sse_frame(&chunk_frame(translator, payload, Value::Null)));
    }
    out
}

fn usage_frame(translator: &Translator) -> String {
    translator
        .usage()
        .map(|usage| {
            stream::sse_frame(&json!({
                "id": translator.response_id(),
                "object": "chat.completion.chunk",
                "created": translator.created(),
                "model": translator.model_out(),
                "choices": [],
                "usage": usage,
            }))
        })
        .unwrap_or_default()
}

/// 收尾帧（finish_reason + usage + [DONE]）
fn tail_frames(translator: &mut Translator) -> String {
    let mut out = String::new();
    out.push_str(&stream::sse_frame(&chunk_frame(
        translator,
        json!({}),
        Value::String(translator.final_finish_reason()),
    )));
    out.push_str(&usage_frame(translator));
    out.push_str(&stream::sse_done());
    out
}

/// 失败收尾（已下发过头之后）：usage + error 帧 + [DONE]。
fn failure_frames(translator: &Translator, error: &Error) -> String {
    let mut out = usage_frame(translator);
    out.push_str(&stream::sse_frame(&json!({
        "error": { "message": error.message, "type": "upstream_error" },
    })));
    out.push_str(&stream::sse_done());
    out
}

/// 首帧预读：没有有效正文、思考或具名工具调用时，不能发出成功响应头。
///
/// 返回「已经读到的帧」（可能为空：上游先给了 usage 帧再给内容帧）。
fn prefetch(stream: &mut EventStream) -> Result<Vec<Frame>> {
    let mut frames: Vec<Frame> = Vec::new();
    let mut usage: Option<Value> = None;
    let mut tool_bytes = 0usize;
    while let Some(event) = stream.next_event()? {
        stream.saw_event = true;
        if event.trim() == "[DONE]" {
            break;
        }
        let Some(mut frame) = stream::parse_frame(&event) else { continue };
        if frame.is_error() {
            return Err(frame_error(&frame));
        }
        if frame.has_output() {
            if let Some(usage) = usage.take() {
                frames.push(Frame { usage: Some(usage), ..Frame::default() });
            }
            frames.push(frame);
            return Ok(frames);
        }
        if let Some(next) = frame.usage.take() {
            usage = Some(next);
        }
        let finished = frame.turn_complete;
        frame.parts.retain(|part| matches!(part, stream::Part::FunctionCall { .. }));
        if !frame.parts.is_empty() {
            tool_bytes = frame.parts.iter().fold(tool_bytes, |size, part| match part {
                stream::Part::FunctionCall { id, name, args } => {
                    size.saturating_add(id.len() + name.len() + args.len())
                }
                _ => size,
            });
            if tool_bytes > PREFETCH_MAX_TOOL_BYTES || frames.len() >= PREFETCH_MAX_FRAMES {
                return Err(Error::http(502, "Accio 首帧前的工具参数过大，已中断"));
            }
            frames.push(frame);
        }
        if finished {
            break;
        }
    }
    Err(stream.no_output_error())
}

/// 响应 id（与另外几家同形：`chatcmpl-` + 24 位随机）
fn response_id() -> String {
    let short: String = protocol::new_request_id().chars().take(24).collect();
    format!("chatcmpl-{short}")
}

/// `conversation` 的入口：一次完整的「构造 → 发送 → 翻译」。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    let record = credential::record()?;
    let mut credential = credential::credential(&record)?;
    // 临期先刷一次（与 `token.ensure` 同一判据）；401 之后的强制续期在下面
    if credential.expiring() {
        credential::ensure()?;
        let record = credential::record()?;
        credential = credential::credential(&record)?;
    }
    let mut refreshed = false;
    loop {
        let plan = build_plan(&credential, &body)?;
        let response = http::open("POST", &plan.url, plan.headers.clone(), Some(&plan.body))?;
        if !(200..300).contains(&response.status) {
            let status = response.status;
            let bytes = response.bytes(1024 * 1024).unwrap_or_default();
            let error = http_error(status, &bytes);
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
        let mut stream = EventStream::new(response);
        let prefetched = match prefetch(&mut stream) {
            Ok(value) => value,
            Err(error) => {
                if error.status == Some(401) && !refreshed && credential.can_refresh() {
                    refreshed = true;
                    credential::refresh()?;
                    let record = credential::record()?;
                    credential = credential::credential(&record)?;
                    continue;
                }
                return Err(error);
            }
        };
        // 到这里才确定「这一轮一定有内容」—— 之前一个字节都没下发
        sdk::stream_head(200)?;
        let mut translator = Translator::new(response_id(), plan.model_name.clone());
        let _ = &plan.upstream_key;
        // 预读到的帧先翻下发
        for frame in &prefetched {
            let deltas = translator.consume(frame);
            let text = frames_for_deltas(&mut translator, &deltas);
            if !text.is_empty() {
                sdk::stream_bytes(text.as_bytes())?;
            }
            if frame.turn_complete {
                sdk::stream_bytes(tail_frames(&mut translator).as_bytes())?;
                return Ok(());
            }
        }
        // 继续消费剩下的流
        loop {
            let event = match stream.next_event() {
                Ok(event) => event,
                Err(error) => {
                    // 已下发：补一帧错误再收尾，客户端看到的是完整流
                    let _ = sdk::stream_bytes(failure_frames(&translator, &error).as_bytes());
                    return Err(error);
                }
            };
            let Some(event) = event else { break };
            stream.saw_event = true;
            if event.trim() == "[DONE]" {
                break;
            }
            let Some(frame) = stream::parse_frame(&event) else { continue };
            if frame.is_error() {
                let error = frame_error(&frame);
                let _ = sdk::stream_bytes(failure_frames(&translator, &error).as_bytes());
                return Err(error);
            }
            let deltas = translator.consume(&frame);
            let text = frames_for_deltas(&mut translator, &deltas);
            if !text.is_empty() {
                sdk::stream_bytes(text.as_bytes())?;
            }
            if frame.turn_complete {
                sdk::stream_bytes(tail_frames(&mut translator).as_bytes())?;
                return Ok(());
            }
        }
        if !translator.has_output() {
            let error = stream.no_output_error();
            let _ = sdk::stream_bytes(failure_frames(&translator, &error).as_bytes());
            return Err(error);
        }
        sdk::stream_bytes(tail_frames(&mut translator).as_bytes())?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 未命中的模型名要给出可选项（而不是一个空 400）。
    #[test]
    fn unknown_model_error_lists_candidates() {
        let error = models::unknown_model_error("no-such-model");
        assert_eq!(Some(400), error.status);
        assert!(error.message.contains("模型不存在"));
    }

    /// 空 body 的两种拒绝都要落在 400（不是 500）。
    #[test]
    fn build_plan_rejects_bad_bodies() {
        let credential = Credential { access_token: "t".to_string(), ..Credential::default() };
        assert_eq!(Some(400), build_plan(&credential, &json!({})).err().and_then(|error| error.status));
        assert_eq!(
            Some(400),
            build_plan(&credential, &json!({ "messages": [] })).err().and_then(|error| error.status)
        );
    }
}
