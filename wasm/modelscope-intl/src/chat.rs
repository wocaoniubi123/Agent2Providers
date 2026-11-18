//! ModelScope 对话：`conversation` 的唯一实现（网关对 wasm 包不走 `chat`）。
//!
//! ── 为什么整条发送链在插件里 ────────────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回
//! 501（「Wasm 对话必须使用标准流通道，不接受主程序代发计划」），而
//! `forwards_response()` 对 wasm 恒为 true —— 所以对话一律走会话式通道：
//! 插件自己 `http::open` 发请求、自己读上游 SSE、再用 `stream_head` /
//! `stream_bytes` 回传。`chat` 写了也不会被调用（见 `lib.rs` 的 `chat` 分支）。
//!
//! ── 这一家的上游形态很老实 ────────────────────────────────
//! 标准 OpenAI Chat Completions SSE：`data: {...}` 逐帧 + `data: [DONE]` 收尾。
//! 没有信封、没有翻译层、没有「HTTP 200 里的业务错误码」那一套 —— 除了一处
//! 必须注入的字段（见 [`inject_usage`]）。
//!
//! ── 流式转发的两条铁律 ─────────────────────────────────────
//!   · **一个字节都没下发之前**判出错误 ⇒ 直接返回 `Err`，让编排层换账号；
//!   · **已经下发之后**再出错 ⇒ 补一条 SSE 错误事件再返回 `Err`，绝不假装成功
//!     （也绝不悄悄从头重发：客户端已经看到半段内容）。
//!
//! ── 首包门为什么在这里也需要 ────────────────────────────────
//! 上游把额度类拒绝放在 **HTTP 200 的流里**（`data: {"error":{…}}`）时，只看
//! 状态码会把它当成一次「成功但没内容」的回答 —— 换账号的时机就错过了。
//! 所以前若干帧先攒着，见到第一帧真内容（或攒满 64 KiB）才发 `stream_head`，
//! 之前判出的错误一律按「还没下发」处理。
//!
//! ── panic = abort ─────────────────────────────────────────
//! 本模块在对话链路上，零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::{account, errors, upstream};

/// SSE 结束哨兵。
const DONE_SENTINEL: &str = "[DONE]";
/// 首包门最多攒这么多字节的事件；超过就认为「已经有内容」，直接放行。
///
/// 这个上限存在的理由是**内存**：一个只会发心跳帧的上游能让首包门无限攒下去，
/// 而 wasm 实例的内存配额是 64 MiB（`wasm.json`）。
const HEAD_BUFFER_LIMIT: usize = 64 * 1024;
/// 非 2xx 诊断体的读取预算。
const ERROR_BODY_BUDGET: usize = 8 * 1024;

/// 转发一次对话（`conversation`）。
pub fn forward(params: &Value) -> Result<()> {
    let record = sdk::account()?;
    let token = account::token_of(&record["secret"])?;
    let body = request_body(params)?;
    let mut response = http::open(
        "POST",
        &upstream::inference_url("/chat/completions"),
        upstream::inference_headers(&token, "text/event-stream"),
        Some(&body),
    )?;

    // ① 非 2xx：分类后直接交回编排层（一个字节都还没下发）
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let (text, truncated) = read_limited(&mut response, ERROR_BODY_BUDGET)?;
        let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err(errors::response_error(status, &payload, &text, truncated));
    }

    let content_type = response.headers["content-type"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("application/json") {
        // 我们强制 `stream=true`，理论上不会走到这里；真走到了就把整条 completion
        // 折成一帧 chunk 下发 —— 客户端拿到的仍然是合法 SSE。
        let payload = response.json()?;
        if payload.get("error").is_some_and(|error| !error.is_null()) {
            return Err(errors::frame_error(&payload));
        }
        return single_shot(payload);
    }
    if content_type.contains("text/html") {
        return Err(Error::http(502, "ModelScope 返回了网页而不是模型回答"));
    }

    relay(response)
}

// ── 出站请求 ─────────────────────────────────────────────────

/// 构造出站请求体。
///
/// ── 为什么**不**改别的（模型与其余参数原样透传）──────────────
/// 魔搭的 `/v1/models` 里混着非对话模型，但「哪些模型支持什么」本插件没有任何
/// 可信依据去猜（按 id 猜会猜错），让上游自己判 —— 它给的 400 会被 `classify`
/// 如实透出。模型 id 也原样发（`组织/模型名`）。
fn request_body(params: &Value) -> Result<Value> {
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "ModelScope 请求体必须是 JSON 对象"));
    }
    let requested = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    // 网关已经把「用户选的模型」按 model_rules 解析成发送名；以它为准，
    // 免得规则改写的名字被 body 里的旧名字盖回去。
    let wire = params["wire_model"].as_str().map(str::trim).unwrap_or("");
    if !wire.is_empty() {
        body["model"] = json!(wire);
    } else if requested.is_empty() {
        return Err(Error::http(400, "请求缺少模型名称"));
    }
    // 本插件只按 SSE 读上游；客户端要非流式时由网关把流折回 JSON 再返回。
    body["stream"] = json!(true);
    Ok(inject_usage(body))
}

/// 出站请求体：原样透传 + 把 `stream_options.include_usage` 置真。
///
/// ── 为什么必须注入（实测，一个会静默毁账的坑）───────────────────
/// 魔搭的流式响应是**非标准形态**：**每一个 chunk 都带一个 `usage` 对象**，
/// 而且**值全是 0**（标准 OpenAI 是除最后一块外都为 `null`）。真值只在末尾
/// 那个 `choices: []` 的 usage-only 块里 —— **而且那一块只在请求显式带上
/// `stream_options.include_usage: true` 时才发**。实测对照：
///
/// ```text
///   不带 include_usage：最后一帧是 {"choices":[{"finish_reason":"stop"}],
///                                  "usage":{0,0,0}}          ← 真值根本没出现
///   带   include_usage：{"choices":[], "usage":{62,32,94}}    ← 真值在这一块
/// ```
///
/// 后果链：本网关**恒以流式请求上游**，客户端要非流式时再由聚合器把流折成
/// 完整响应。不注入这个开关时，聚合器读到的最后一个 usage 就是那串全零 ——
/// 于是**非流式请求的 usage 恒为 0**，请求日志、报表与前端 token 显示一起归零，
/// 而内容完全正常（这个故障只在统计上可见，排查时极难联想到「上游少发了一帧」）。
///
/// 客户端已经自己写了 `stream_options` 时**保留它的其余键**、只把
/// `include_usage` 置真：覆盖整个对象会把用户显式设过的东西悄悄丢掉。
///
/// 非对象 body（畸形请求）原样返回，不在这一层报错 —— 让上游去拒绝它。
fn inject_usage(mut payload: Value) -> Value {
    let Some(object) = payload.as_object_mut() else {
        return payload;
    };
    let mut options = object
        .get("stream_options")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    options.insert("include_usage".to_string(), Value::Bool(true));
    object.insert("stream_options".to_string(), Value::Object(options));
    payload
}

// ── 流式中转 ─────────────────────────────────────────────────

/// 首包门 + 已下发后的状态机。
#[derive(Default)]
struct Relay {
    /// `stream_head` 发出去了没有（= 客户端是否已经看到字节）
    started: bool,
    /// 是否已经见到 `[DONE]`
    done: bool,
    /// 首包门期间攒下的事件（一行一个 data 负载）
    pending: Vec<String>,
    pending_bytes: usize,
}

impl Relay {
    /// 放行：先发 head，再把攒下的事件按顺序补发。
    ///
    /// 顺序不能反 —— 客户端拿到 head 之前不可能接受 chunk，宿主也会拒。
    fn start(&mut self) -> Result<()> {
        if !self.started {
            sdk::stream_head(200)?;
            self.started = true;
            let pending = std::mem::take(&mut self.pending);
            for event in pending {
                emit(&event)?;
            }
            self.pending_bytes = 0;
        }
        Ok(())
    }

    /// 处理一帧。
    fn push(&mut self, event: &str) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let trimmed = event.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if trimmed == DONE_SENTINEL {
            self.done = true;
            self.start()?;
            return emit_done();
        }
        let value: Value = serde_json::from_str(trimmed)
            .map_err(|_| Error::new("ModelScope 流式事件格式无效"))?;
        // 流内错误（HTTP 200 + `{"error":…}`）：还没下发就交给编排层换账号
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(errors::frame_error(&value));
        }
        let decisive = decisive(&value);
        if self.started {
            return emit(trimmed);
        }
        self.pending_bytes = self.pending_bytes.saturating_add(trimmed.len() + 8);
        self.pending.push(trimmed.to_string());
        if opens_gate(decisive, self.pending_bytes) {
            self.start()?;
        }
        Ok(())
    }
}

/// 首包门要不要放行：见到真内容，或者攒得够多了（防无界缓冲）。
fn opens_gate(decisive: bool, pending_bytes: usize) -> bool {
    decisive || pending_bytes > HEAD_BUFFER_LIMIT
}

/// 读上游流并中转。
fn relay(mut response: http::Response) -> Result<()> {
    let mut relay = Relay::default();
    let mut decoder = SseDecoder::default();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let events = match decoder.push(&chunk) {
                    Ok(events) => events,
                    Err(error) => return failed(relay.started, error),
                };
                for event in events {
                    if let Err(error) = relay.push(&event) {
                        return failed(relay.started, error);
                    }
                }
                if relay.done {
                    return Ok(());
                }
            }
            Ok(None) => break,
            Err(error) => {
                let failure = Error::http(
                    502,
                    format!("ModelScope 上游流中断：{}", error.message),
                );
                return failed(relay.started, failure);
            }
        }
    }

    // 上游既没给结束哨兵、也没攒下任何事件就断了：这是真的中断，不是「空回答」。
    // 一个字节都没下发，可以放心按失败交回去（触发换账号），
    // 而不是给客户端一个「200 + 一个字都没有」。
    if !relay.started {
        if relay.pending.is_empty() {
            return Err(Error::http(502, "ModelScope 上游流提前中断，未收到任何内容"));
        }
        relay.start()?;
    }
    if !relay.done {
        // 上游没给结束哨兵就断了：补一条，免得客户端一直挂着等。
        // 少了这一条，聚合器会一直等「最后一块」，客户端表现为回答永远不结束。
        emit_done()?;
    }
    Ok(())
}

/// 出错时的收尾：已经下发过内容就补一条错误事件，然后照样把错误交回去。
fn failed(started: bool, error: Error) -> Result<()> {
    if started {
        sdk::stream_event(&errors::error_event(&error))?;
    }
    Err(error)
}

/// 一帧里是否已经有「真内容」——首包门据此决定放行。
fn decisive(value: &Value) -> bool {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return false;
    };
    choices.iter().any(|choice| {
        let delta = &choice["delta"];
        text_field(delta, "content")
            || text_field(delta, "reasoning_content")
            || text_field(delta, "reasoning")
            || delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
            || choice
                .get("finish_reason")
                .is_some_and(|reason| !reason.is_null())
    })
}

/// 某个字段里有没有非空文本（字符串或多模态分段数组两种形态）。
fn text_field(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(parts)) => parts.iter().any(|part| {
            part.get("text")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty())
        }),
        _ => false,
    }
}

/// 上游没按流式回（HTTP 200 + 整条 completion）：折成一帧 chunk 再补 [DONE]。
fn single_shot(value: Value) -> Result<()> {
    if !value.is_object() {
        return Err(Error::http(502, "ModelScope 返回了无法识别的响应"));
    }
    let choices = value["choices"].as_array().cloned().unwrap_or_default();
    let mut chunk = value;
    chunk["object"] = json!("chat.completion.chunk");
    chunk["choices"] = Value::Array(
        choices
            .iter()
            .map(|choice| {
                let mut choice = choice.clone();
                // 只在对象上改键：`choice` 是别的形态时原样保留，
                // 宁可直接透传也不让一次畸形响应把实例带走（panic = abort）
                if let Some(object) = choice.as_object_mut() {
                    let message = object.remove("message").unwrap_or(Value::Null);
                    object.insert("delta".to_string(), message);
                }
                choice
            })
            .collect(),
    );
    sdk::stream_head(200)?;
    sdk::stream_event(&chunk)?;
    emit_done()
}

/// 下发一帧（按事件重建，不原样搬字节：解码器可能已经跨过了分块边界）。
fn emit(event: &str) -> Result<()> {
    sdk::stream_bytes(format!("data: {event}\n\n").as_bytes())
}

/// 下发结束哨兵。
fn emit_done() -> Result<()> {
    sdk::stream_bytes(format!("data: {DONE_SENTINEL}\n\n").as_bytes())
}

/// 读响应体，最多读到 `limit` 字节；返回（文本，是否被截断）。
///
/// 读诊断体本身失败时不算失败：手上这一截照样有用，如实标「被截断」即可。
fn read_limited(response: &mut http::Response, limit: usize) -> Result<(String, bool)> {
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(body.len());
                if chunk.len() > room {
                    body.extend_from_slice(&chunk[..room]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
                if body.len() >= limit {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    Ok((String::from_utf8_lossy(&body).to_string(), truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `include_usage` 必须置真，且不许把客户端自己写的其余键洗掉。
    #[test]
    fn the_usage_switch_is_injected_without_losing_other_keys() {
        let body = inject_usage(json!({
            "model": "Qwen/Qwen3-Max",
            "stream_options": { "custom": "keep-me" }
        }));
        assert_eq!(true, body["stream_options"]["include_usage"].as_bool().unwrap_or(false));
        assert_eq!("keep-me", body["stream_options"]["custom"].as_str().unwrap_or_default());

        let absent = inject_usage(json!({ "model": "x" }));
        assert_eq!(true, absent["stream_options"]["include_usage"].as_bool().unwrap_or(false));
    }

    /// 首包门：只有真内容才放行；role-only 帧与 usage-only 帧都不算。
    #[test]
    fn only_a_frame_with_real_content_opens_the_gate() {
        assert!(decisive(&json!({ "choices": [{ "delta": { "content": "你" } }] })));
        assert!(decisive(&json!({ "choices": [{ "delta": { "tool_calls": [{ "id": "t" }] } }] })));
        assert!(decisive(&json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] })));
        assert!(!decisive(&json!({ "choices": [{ "delta": { "role": "assistant" } }] })));
        assert!(!decisive(&json!({ "choices": [], "usage": { "total_tokens": 9 } })));
        assert!(!decisive(&json!({ "object": "chat.completion.chunk" })));
    }

    /// 首包门：没真内容就不放行，攒满 64 KiB 才被动放行（防无界缓冲）。
    ///
    /// 这里只验判据本身。放行动作会调宿主（`stream_head`），在非 wasm 目标下
    /// 必然失败，所以端到端的放行顺序由 `relay()` 的代码结构保证，不在单测里伪造。
    #[test]
    fn the_gate_stays_closed_until_content_or_the_buffer_limit() {
        assert!(!opens_gate(false, 0));
        assert!(!opens_gate(false, HEAD_BUFFER_LIMIT));
        assert!(opens_gate(false, HEAD_BUFFER_LIMIT + 1));
        assert!(opens_gate(true, 0));
    }
}
