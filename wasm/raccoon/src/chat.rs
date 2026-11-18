//! 对话转发：插件自己发请求、自己转 SSE，按 OpenAI chat 的形态吐给宿主。
//!
//! ── 为什么走「自己发」这条路 ────────────────────────────────
//! 小浣熊的上游就是标准 OpenAI chat SSE（native 侧 `ChatPlan::chat(..)` 用的就是
//! `UpstreamKind::Chat`），照理把 `{url, headers, body}` 交回宿主也能跑。
//! 但有一类边界只有插件自己看得见：**上游用 HTTP 200 回一个失败帧**
//! （流内 `{"error": …}`、`finish_reason: content_filter`、或者干脆回一段网页）。
//! 交给宿主发的时候，插件拿不到响应体，这些情况只能被当成「一条成功的流」；
//! 自己发则可以在**下发第一个字节之前**分类，把错误变成一次真正的失败。
//! 代价是插件要复制一遍转发，收益是边界不漏。
//!
//! ── 缓冲策略（与 atomcode 的 `Output` 同一手法）────────────────
//! 先把事件攒进 `pending`，直到出现「确定是正常回答」的信号（正文 / 工具调用 /
//! 思考 / finish_reason）或攒满 64 KiB，才 `stream_head(200)` 并把缓冲一次性
//! 吐出。这样：
//!   - 上游回 200 但第一帧就是错误 → 一次干净的失败（status 由分类结果决定）；
//!   - 上游回 200 但正文是网页 / 空流 → 同样是一次失败，不会让客户端看到
//!     「200 + 空回答」。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use crate::{client_identity, conversation, credentials, errors, headers, image, reasoning, upstream};

/// 缓冲上限：攒到这个大小还没出现决定性信号，就当作正常流开始下发。
const PENDING_LIMIT: usize = 64 * 1024;

/// 上游错误体的读取上限（超过就只报状态码）。
const ERROR_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
struct Output {
    pending: Vec<Vec<u8>>,
    pending_size: usize,
    /// 已下发多少个字节（0 = head 还没发）
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
                    return Err(Error::http(502, "小浣熊未返回有效内容或结束原因"));
                }
                self.start()?;
            }
            sdk::stream_bytes(b"data: [DONE]\n\n")?;
            self.complete = true;
            return Ok(());
        }
        let value: Value =
            serde_json::from_str(data).map_err(|_| Error::new("小浣熊流式事件格式无效"))?;
        // 流内错误帧：上游偶尔用 200 + {"error": …} 表达失败
        if value.get("error").is_some_and(|error| !error.is_null()) {
            return Err(errors::http_error(stream_status(&value), &value["error"]));
        }
        // 业务码（小浣熊的 `{code, message}` 形态）出现在流里同样算失败
        if crate::errors::business_code(&value).is_some_and(|code| code != 0) {
            return Err(errors::http_error(502, &value));
        }
        let choices = value["choices"]
            .as_array()
            .ok_or_else(|| Error::new("小浣熊流式事件缺少 choices"))?;
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
                || delta["reasoning"].as_str().is_some_and(|text| !text.is_empty());
            if let Some(reason) = choice["finish_reason"].as_str() {
                if matches!(reason, "content_filter" | "safety") {
                    return Err(Error::http(403, "小浣熊上游内容审核未通过").with_code("content_filter"));
                }
                self.normal_finish = true;
                decisive = true;
            }
        }
        let bytes = format!("data: {data}\n\n").into_bytes();
        if self.started {
            sdk::stream_bytes(&bytes)?;
            return Ok(());
        }
        self.pending_size += bytes.len();
        self.pending.push(bytes);
        if decisive || self.pending_size > PENDING_LIMIT {
            self.start()?;
        }
        Ok(())
    }

    /// 消费一次上游响应（已确认 2xx）。
    fn consume(&mut self, mut response: http::Response) -> Result<()> {
        let content_type = response.headers["content-type"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        // 非流式 JSON：上游忽略了 stream 参数（客户端要流式时不能让界面卡住，
        // 所以这里把整段回答折成一条 chunk + [DONE]，与 atomcode 同一手法）
        if content_type.contains("application/json") {
            let value = response.json()?;
            if value.get("error").is_some_and(|error| !error.is_null()) {
                return Err(errors::http_error(502, &value["error"]));
            }
            if crate::errors::business_code(&value).is_some_and(|code| code != 0) {
                return Err(errors::http_error(502, &value));
            }
            let choices = value["choices"]
                .as_array()
                .ok_or_else(|| Error::new("小浣熊响应缺少 choices"))?;
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
            return Err(Error::http(502, "小浣熊返回了网页而不是模型回答"));
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
        Err(Error::http(
            502,
            "小浣熊上游流提前中断，未收到完整结束标记",
        ))
    }
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
/// 入参就是宿主传下来的同一份请求 JSON（`ChatRequest` /
/// `ConversationRequest` 的序列化形态）：`{provider, account, body, headers,
/// stream, wire_model, …}`。
pub fn forward(params: &Value) -> Result<()> {
    let account = params["account"].as_str().unwrap_or("");
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "小浣熊请求体必须是 JSON 对象"));
    }
    let requested = body["model"]
        .as_str()
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| Error::http(400, "请求缺少模型名称"))?
        .to_string();
    if let Some(error) = image::unsupported(&requested) {
        return Err(error);
    }
    // 网关解析出的**发送名**（备援改写之后、上游认识的那个名字）。native 的
    // 无状态路径由网关改 body 里的 model；这里插件自己发，所以要自己写回去。
    let wire_model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(requested.as_str())
        .to_string();
    body["model"] = json!(wire_model);

    let (token, org_code) = credentials::request_identity(account)?;
    if token.is_empty() {
        return Err(Error::http(
            401,
            "小浣熊账号缺少 accessToken，无法转发",
        ));
    }
    let mut request_headers: Vec<(String, String)> = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
        ("Authorization".to_string(), format!("Bearer {token}")),
    ];
    headers::append_org(&mut request_headers, &org_code)?;
    request_headers.extend(client_identity::headers());
    request_headers.extend(conversation::headers(params, &token, &org_code)?);
    headers::append_external(&mut request_headers);

    let mut body = reasoning::normalize(&body, &wire_model)?;
    // 插件自己发就一定要流式：宿主那一侧是按 SSE 转发的，上游若回整段 JSON
    // 由 `consume` 折成一条 chunk（见那里的说明）。
    body["stream"] = json!(true);
    if !body.get("stream_options").is_some_and(Value::is_object) {
        body["stream_options"] = json!({});
    }
    body["stream_options"]["include_usage"] = json!(true);

    let url = format!("{}/chat/completions", upstream::llm_base());
    let response = http::open(
        "POST",
        &url,
        upstream::headers_value(&request_headers),
        Some(&body),
    )
    .map_err(|error| upstream::transport("小浣熊对话请求失败", error))?;
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

    /// 只取错误侧；意外成功时给一条哨兵错误，让下面的状态码断言失败。
    fn failure_of(params: &Value) -> Error {
        match forward(params) {
            Err(error) => error,
            Ok(()) => Error::new("未按预期失败"),
        }
    }

    #[test]
    fn rejects_non_object_bodies_before_any_network_call() {
        let error = failure_of(&json!({ "body": "不是对象" }));
        assert_eq!(error.status, Some(400));
        assert!(error.message.contains("JSON 对象"), "{}", error.message);
        // 空请求体（params 为 Null/空对象）同样在发请求之前就被拦下
        assert_eq!(failure_of(&json!({})).status, Some(400));
    }

    #[test]
    fn rejects_missing_model() {
        let error = failure_of(&json!({ "body": { "messages": [] } }));
        assert_eq!(error.status, Some(400));
        assert!(error.message.contains("模型名称"), "{}", error.message);
    }

    #[test]
    fn rejects_the_image_model_with_a_readable_message() {
        let error = failure_of(&json!({ "body": { "model": "raccoon-image" } }));
        assert_eq!(error.status, Some(400));
        assert!(error.message.contains("图片"), "{}", error.message);
    }

    #[test]
    fn stream_status_prefers_explicit_codes() {
        assert_eq!(stream_status(&json!({ "error": { "status": 429 } })), 429);
        assert_eq!(stream_status(&json!({ "error": { "code": "401" } })), 401);
        // 不在 4xx-5xx 的数字（比如业务码 1000007）或缺失 → 502
        assert_eq!(stream_status(&json!({ "error": { "code": 1_000_007 } })), 502);
        assert_eq!(stream_status(&json!({})), 502);
    }
}
