//! 对话转发（会话式通道）。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/chat.rs`。
//!
//! ── 为什么只能走 `conversation` ─────────────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接返回
//! 501，`forwards_response()` 对 wasm 恒为 true —— 所以本家的对话一律走会话式
//! 通道：插件自己 `http::open` 发请求，再用 `stream_head` / `stream_bytes`
//! 回传 chat SSE。`chat` 写了也不会被调用。
//!
//! ── 宿主还给这条通道加了固定校验 ───────────────────────────
//! `POST https://www.doubao.com/chat/completion` 走宿主 `doubao_turn`：
//!   1. 需要能力 `http.doubao-turn.v1`（只有本包能声明）；
//!   2. 请求头里的 Cookie 必须与账号 secret 逐项相等，且 URL 上
//!      `device_id` / `fp=verify_<device>` 必须对得上；
//!   3. `messages[0].local_message_id` 会被当成本次轮次的标识（停止任务回执的键）；
//!   4. 允许 `/chat/async/chunk_stream` 续读，但一个上下文只能提交一次
//!      `/chat/completion`。
//! 这些不是插件能绕开的，所以本文件只负责「把信封构造对 + 把流折成 chat SSE」。
//!
//! ── 首包门 ──────────────────────────────────────────────────
//! 上游的额度/凭证类失败可能是一条 HTTP 200 的 SSE 错误事件。若先把 head 发出去
//! 再报错，客户端拿到的是「成功但没话」，网关也不会换账号。所以这里先取**第一帧**：
//! 是错误就直接返回 `Err`（一个字节都不下发），是内容才 `stream_head(200)`。
//!
//! ── 工具调用要整轮读完 ──────────────────────────────────────
//! 有工具声明时，回答是一整段 JSON（见 `prompt::ToolBridge`），必须先读完才能
//! 解析，所以这条分支是「读完 → 一次性发 `tool_calls` 帧」。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::prompt::{self, ToolBridge};
use super::stream::{Decoder, Delta, FrameQueue, SseParser};
use super::{account, api, catalog, upload};

fn chunk(id: &str, model: &str, delta: Value, reason: Value) -> Vec<u8> {
    format!(
        "data: {}\n\n",
        json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": sdk::now() / 1000,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": reason}],
        })
    )
    .into_bytes()
}

/// 把 `drain_images` 交出来的图片增量拼成一段 markdown（正文之后补发用）。
fn image_markdown(deltas: Vec<Delta>) -> String {
    deltas
        .into_iter()
        .filter_map(|delta| match delta {
            Delta::Text(text) => Some(text),
            Delta::Reasoning(_) => None,
        })
        .collect()
}

/// 从流里取下一个增量；`None` = 这一轮结束了。
fn pump(
    response: &mut http::Response,
    parser: &mut SseParser,
    queue: &mut FrameQueue,
    decoder: &mut Decoder,
) -> Result<Option<Delta>> {
    loop {
        if let Some(delta) = queue.next(decoder)? {
            return Ok(Some(delta));
        }
        if decoder.done {
            return Ok(None);
        }
        match response.read()? {
            Some(bytes) => queue.push(parser.push(&bytes)?),
            None => {
                if let Some(frame) = parser.finish() {
                    queue.push(vec![frame]);
                    if let Some(delta) = queue.next(decoder)? {
                        return Ok(Some(delta));
                    }
                }
                if decoder.done {
                    return Ok(None);
                }
                return Err(Error::http(502, "豆包工作响应在 SSE_REPLY_END 之前中断"));
            }
        }
    }
}

fn emit(delta: &Delta, id: &str, model: &str) -> Result<()> {
    let body = match delta {
        Delta::Text(text) => json!({"role": "assistant", "content": text}),
        Delta::Reasoning(reasoning) => json!({"reasoning_content": reasoning}),
    };
    sdk::stream_bytes(&chunk(id, model, body, Value::Null))
}

/// `conversation` 的入口。
pub fn run(params: &Value) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "豆包工作请求体必须是 JSON 对象"));
    }
    let requested = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let wire_model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(requested.as_str())
        .to_string();
    let bridge = ToolBridge::new(body)?;
    let (text, images) = prompt::content(body, &bridge)?;
    let secret = account::current_secret()?;
    let credentials = account::credential(&secret)?;
    credentials.require_device()?;
    let (bot, model) = catalog::resolve(&credentials, &wire_model)?;
    let mut attachments = Vec::new();
    for image in images {
        attachments.push(upload::image(&image)?);
    }
    let payload = prompt::payload(&bot, &model, &text, attachments, body)?;
    let mut response = http::open(
        "POST",
        &credentials.endpoint("/chat/completion"),
        credentials.headers(),
        Some(&payload),
    )?;
    let status = response.status;
    let sse = response
        .headers
        .get("content-type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if !(200..300).contains(&status) || !sse {
        let bytes = response.bytes(1 << 20)?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(api::error(status, &value));
    }

    let id = super::random::id("chatcmpl")?;
    let mut decoder = Decoder::default();
    let mut parser = SseParser::default();
    let mut queue = FrameQueue::default();

    if bridge.active() {
        // 工具声明存在：整轮读完再解析（见模块头）。
        while pump(&mut response, &mut parser, &mut queue, &mut decoder)?.is_some() {}
        if !decoder.done && decoder.text.is_empty() && !decoder.has_images() {
            return Err(Error::http(502, "豆包工作没有返回回答"));
        }
        // 解析工具调用要用**不含图片链接**的正文：那段 markdown 会让 JSON 解析
        // 失败，进而被当成「工具调用不完整」报错。
        let text = decoder.text.clone();
        let images = image_markdown(decoder.drain_images());
        if text.is_empty() && images.is_empty() {
            return Err(Error::http(502, "豆包工作没有返回回答"));
        }
        let mut message = bridge.message(&text)?;
        if !images.is_empty() && message["tool_calls"].is_null() {
            let content = message["content"].as_str().unwrap_or("");
            message["content"] = json!(format!("{content}{images}"));
        }
        if !decoder.reasoning.is_empty() {
            message["reasoning_content"] = json!(decoder.reasoning);
        }
        let reason = if message["tool_calls"].is_array() {
            "tool_calls"
        } else {
            "stop"
        };
        if let Some(calls) = message["tool_calls"].as_array_mut() {
            for (index, call) in calls.iter_mut().enumerate() {
                call["index"] = json!(index);
            }
        }
        sdk::stream_head(200)?;
        sdk::stream_bytes(&chunk(&id, &wire_model, message, Value::Null))?;
        sdk::stream_bytes(&chunk(&id, &wire_model, json!({}), json!(reason)))?;
        sdk::stream_bytes(b"data: [DONE]\n\n")?;
        api::finish_turn();
        return Ok(());
    }

    // 首包门：先取第一帧，是错误就在这里返回（一个字节都不下发）。
    // 允许第一帧就是流末（`None`）：生图这一类回答可能**只有图片没有正文**，
    // 图片在流末由 `drain_images` 补发，这里把「没有正文」提前判死会误报。
    let mut next = pump(&mut response, &mut parser, &mut queue, &mut decoder)?;
    sdk::stream_head(200)?;
    while let Some(delta) = next {
        emit(&delta, &id, &wire_model)?;
        next = pump(&mut response, &mut parser, &mut queue, &mut decoder)?;
    }
    if decoder.text.is_empty() && !decoder.has_images() {
        return Err(Error::http(502, "豆包工作完成响应但没有回答正文"));
    }
    // 图片排在正文之后：这里已经是流末，`drain_images` 拿得到无水印原图。
    let images = image_markdown(decoder.drain_images());
    if !images.is_empty() {
        sdk::stream_bytes(&chunk(
            &id,
            &wire_model,
            json!({"role": "assistant", "content": images}),
            Value::Null,
        ))?;
    }
    sdk::stream_bytes(&chunk(&id, &wire_model, json!({}), json!("stop")))?;
    sdk::stream_bytes(b"data: [DONE]\n\n")?;
    api::finish_turn();
    Ok(())
}
