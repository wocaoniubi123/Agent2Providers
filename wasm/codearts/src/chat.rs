//! CodeArts 对话：出站请求构造、首包门、非流式聚合与流式透传。
//!
//! ── 上游协议 ────────────────────────────────────────────────
//! 对话打 `POST {base}/api/v2/chat/completions`，**但请求不是纯 OpenAI 形状**：
//! 除了标准的 `model` / `messages` / `stream`，还要带上模型名相关的三个头
//! （`model-id` / `model-name` / `x-model-id`），福利模型还要额外带
//! `maas_type: benefit`。这些头**参与签名**，所以必须与 body 一起决定。
//!
//! ── 为什么这一整条链放在 `conversation` 里（而不是无状态 `chat`）────
//! 无状态路径假设「网关自己发请求、插件只回答怎么构造」。本家两件事做不到：
//!   1. 要先占一个上游会话槽（心跳 busy/idle），那是**跨请求**的状态；
//!   2. 失败判据在**流里**（HTTP 200 + 一帧 `InferHub.4291.200 / insufficient
//!      quota`），必须由插件在首包门里判掉才能触发换账号。
//!
//! ── 流式转发的两条铁律 ─────────────────────────────────────
//!   · **一个字节都没下发之前**判出错误 ⇒ 直接返回 `Err`，让编排层换账号；
//!   · **已经下发之后**再出错 ⇒ 补一条 SSE 错误事件再返回 `Err`，绝不假装成功
//!     （也绝不悄悄从头重发：客户端已经看到半段内容）。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本模块在对话链路上，零 `unwrap` / `expect` / `panic`。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::credentials::Credential;
use super::models;
use super::{redact, signer, stream_fault, tool_names, upstream};

/// SSE 结束哨兵。
const DONE_SENTINEL: &str = "[DONE]";
/// 上游对**输出上限**（`max_tokens` / `max_completion_tokens` 取值）的硬顶。
pub const MAX_OUTPUT_TOKENS: i64 = 65_536;
/// 「短额度」的判定线：客户端给的额度低于它就考虑抬一抬（见 `reserve_for_thinking`）。
pub const SHORT_OUTPUT_TOKENS: i64 = 1024;
/// 为思考预留的额度增量。
pub const THINKING_RESERVE: i64 = 1024;
/// 首包门最多缓冲这么多字节的原始流；超过就认为「已经有内容」，直接放行。
const HEAD_BUFFER_LIMIT: usize = 64 * 1024;
/// 非 2xx 诊断体的读取预算。
const ERROR_BODY_BUDGET: usize = 8 * 1024;
/// 实测的**可用上界**：5,310,247 字节走得过去，6,372,244 起被拒。取 6 MiB。
pub const SIZE_CEILING_KNOWN_BYTES: i64 = 6 * 1024 * 1024;
/// 尺寸门的存续时长。
const GATE_TTL_MS: i64 = 120_000;
/// 尺寸门在会话存储里的键。
const GATE_KEY: &str = "codearts:size-gate";
/// 一次响应里最多接受多少个并行 tool_call。
///
/// **这个上限存在的理由是内存，不是协议**：上游只要发一帧 `{"index":4294967295}`，
/// 下面那个「补齐到 index」的循环就会去分配四十亿个 JSON 值 —— 进程当场被带走，
/// 而这只是解析一个响应帧。
const MAX_TOOL_CALLS: usize = 64;

// ── 出站请求 ─────────────────────────────────────────────────

/// 一次对话请求要用的头（不含签名）。这些头**全部参与签名**，顺序与内容都不能
/// 随手改（签名层会把它们按名字排序后拼进规范请求串）。
pub struct HeaderProfile {
    pub plugin_name: String,
    pub plugin_version: String,
    pub language: String,
    pub is_confidential: bool,
    /// 会话并发心跳用的 `User-Session-Id`（宿主会话 id）
    pub chat_session_id: Option<String>,
}

impl Default for HeaderProfile {
    fn default() -> Self {
        Self {
            plugin_name: upstream::DEFAULT_PLUGIN_NAME.to_string(),
            plugin_version: upstream::DEFAULT_PLUGIN_VERSION.to_string(),
            language: upstream::DEFAULT_LANGUAGE.to_string(),
            is_confidential: false,
            chat_session_id: None,
        }
    }
}

impl HeaderProfile {
    fn headers(&self, model: &str) -> Vec<(String, String)> {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/event-stream".to_string()),
            ("client_version".to_string(), format!("Vscode_{}", self.plugin_version)),
            ("Agent-Type".to_string(), "ChatAgent".to_string()),
            ("X-Language".to_string(), self.language.clone()),
            (
                "is_confidential".to_string(),
                if self.is_confidential { "true" } else { "false" }.to_string(),
            ),
            ("plugin-name".to_string(), self.plugin_name.clone()),
            ("plugin-version".to_string(), self.plugin_version.clone()),
            // 上游把模型名也当请求头（三个键都要，少一个都不行）
            ("model-id".to_string(), model.to_string()),
            ("model-name".to_string(), model.to_string()),
            ("x-model-id".to_string(), model.to_string()),
        ];
        if let Some(session_id) = self.chat_session_id.as_ref() {
            headers.push(("User-Session-Id".to_string(), session_id.clone()));
        }
        headers
    }
}

/// 构造一次出站对话请求，返回 `(完整地址, 已签名的头, 请求体字节)`。
///
/// `stream` 恒为真（上游只有流式）；`benefit` 为真时注入 `maas_type: benefit`
/// （福利模型才需要，普通模型带了反而会被判成"没领福利"）。
pub fn build_upstream_request(
    base_url: &str,
    model: &str,
    mut payload: Value,
    stream: bool,
    benefit: bool,
    profile: &HeaderProfile,
    credential: &Credential,
) -> Result<(String, Vec<(String, String)>, Vec<u8>)> {
    let model = model.trim();
    if model.is_empty() {
        return Err(Error::http(400, "CodeArts 模型名为空，请从 /v1/models 里选一个"));
    }
    if payload.get("messages").and_then(Value::as_array).is_none() {
        return Err(Error::http(400, "请求体缺少 messages 数组"));
    }
    let endpoint = format!("{}{}", base_url.trim_end_matches('/'), upstream::CHAT_PATH);
    let object = payload
        .as_object_mut()
        .ok_or_else(|| Error::http(400, "请求体必须是 JSON 对象"))?;
    object.insert("model".to_string(), Value::String(model.to_string()));
    object.insert("stream".to_string(), Value::Bool(stream));
    if stream {
        // 让上游在最后一帧带上 usage（不要求它就永远不会给）
        object.insert("stream_options".to_string(), json!({ "include_usage": true }));
    }
    // 「关思考」在本家没有可发送的表达：始终思考的名字收到 `reasoning_effort:"none"`
    // 会被上游整条拒掉（`InferHub.malformed_json.400`）。客户端自己写的这个键也算
    // 注入，所以在签名前摘掉。
    drop_thinking_off(&mut payload);
    // 丢历史思考也要在序列化之前：签名覆盖的就是这串字节，少发的字节才算数
    strip_historical_reasoning(&mut payload);
    // 强制某工具的 `tool_choice` 在本家发不出去，折成字符串 `required`
    fold_forced_tool_choice(&mut payload);
    // 输出上限钳制：放在序列化前的最后一步，此后没有任何一步会再动 body
    clamp_output_tokens(&mut payload);
    let body = serde_json::to_vec(&payload).map_err(|_| Error::http(400, "请求体序列化失败"))?;
    let mut headers = profile.headers(model);
    if benefit {
        headers.push(("maas_type".to_string(), "benefit".to_string()));
    }
    let signing = signer::Credential {
        access_key_id: credential.access_key_id.clone(),
        secret_access_key: credential.secret_access_key.clone(),
        security_token: credential.security_token.clone(),
        domain_id: credential.domain_id.clone(),
    };
    let signed = signer::sign("POST", &endpoint, &headers, &body, &signing, false)
        .map_err(|reason| Error::http(500, reason))?;
    Ok((endpoint, signed, body))
}

/// 摘掉客户端请求体里表达「关闭思考」的键。
///
/// 三种写法都算：`reasoning_effort` / `reasoningEffort` / `effort` 的值为 `off`
/// 或 `none`，以及布尔形式的 `enable_thinking:false`。
/// **只摘这几种，别的值一律原样走**：`low` / `medium` / `high` / `max` 是上游收的
/// 档位，`enable_thinking:true` 是「开思考」，都不该由网关替客户端做主。
pub fn drop_thinking_off(payload: &mut Value) -> Vec<String> {
    let mut dropped = Vec::new();
    let Some(object) = payload.as_object_mut() else {
        return dropped;
    };
    for key in ["reasoning_effort", "reasoningEffort", "effort"] {
        let off = object
            .get(key)
            .and_then(Value::as_str)
            .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "off" | "none"))
            .unwrap_or(false);
        if off && object.remove(key).is_some() {
            dropped.push(key.to_string());
        }
    }
    if object.get("enable_thinking").and_then(Value::as_bool) == Some(false) {
        object.remove("enable_thinking");
        dropped.push("enable_thinking".to_string());
    }
    dropped
}

/// 丢掉历史消息里的思考内容。
///
/// ── 为什么值得丢 ────────────────────────────────────────────
/// 重放给下一个模型没有信息量，实测占体积 38–45%；而本家对请求体大小有硬墙
/// （6 MiB 起拒）。**只动历史**：最后一条 assistant 的思考是本次回答的一部分，
/// 由流式输出负责，不在这里碰。
pub fn strip_historical_reasoning(payload: &mut Value) -> usize {
    let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut dropped = 0usize;
    for message in messages.iter_mut() {
        let Some(object) = message.as_object_mut() else {
            continue;
        };
        if object.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        for key in ["reasoning_content", "reasoning"] {
            if object.remove(key).is_some() {
                dropped += 1;
            }
        }
    }
    dropped
}

/// 把 OpenAI 的对象形态 `tool_choice`（指名某函数）折成字符串 `"required"`。
///
/// ── 依据（2026-10-10 在 dev 上量的）──────────────────────────
/// · 对象形态 `{"type":"function","function":{"name":X}}` ⇒ **必拒**：
///   `InferHub.001001005.400 The request param is invalid`；
/// · 与 `tools` 有没有、名字长短都无关；
/// · 换成 `"required"` ⇒ 200 且真产生 tool_call。`"none"` / `"auto"` / 不带 ⇒ 都 200。
///
/// 语义损失要说清：`required` 保住了「这轮必须调工具」，但**不再指定调哪个**。
/// 只动 `type == "function"` 这一种；别的不认识的对象形态原样发。
pub fn fold_forced_tool_choice(payload: &mut Value) -> Option<String> {
    let Value::Object(object) = payload else {
        return None;
    };
    let named = object
        .get("tool_choice")
        .and_then(Value::as_object)
        .filter(|choice| choice.get("type").and_then(Value::as_str) == Some("function"))
        .and_then(|choice| choice.get("function"))
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(str::to_owned)?;
    object.insert("tool_choice".to_string(), Value::String("required".to_string()));
    Some(named)
}

/// 出站请求体 `max_tokens` / `max_completion_tokens` 的上限归一（就地修改）。
///
/// ── 上游行为（2026-10-09 实测，逐格结论）──────────────────
/// 这两个键的**取值**参与上游预校验：**65536 放行、65537 起一律拒收**，整条请求回
/// `InferHub.001001005.400`。与提示词长度、模型、其它参数都无关，是平台级校验。
///
/// ── 目录里的 maxOutputTokens 不是依据 ───────────────────────
/// 上游目录给 `glm-5.3-flash` 声明 131072（`deepseek-v4-*` 甚至 393216），**与实际
/// 执行的 65536 不符** —— 照声明钳等于没钳。
///
/// ── 为什么必须修 ────────────────────────────────────────────
/// ZCode 这类客户端按自己的上下文长度发 `max_completion_tokens: 128000`，原样
/// 透传时表现为「CodeArts 账号逐个 502、换号也没用」，而模型测试路径不带这个字段、
/// 一路 200 —— 两边现象对不上，极易把排查带向账号 / 网络。
///
/// 规则：字段存在、是整数且超顶 → 改写为顶值（**钳而不是删**：删等于让上游按
/// 默认档回答，客户端"要长回答"的意图直接丢失）；缺省不注入、非整数形态不碰。
fn clamp_output_tokens(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    for key in ["max_tokens", "max_completion_tokens"] {
        let over = matches!(object.get(key), Some(Value::Number(n))
            if n.as_i64().is_some_and(|value| value > MAX_OUTPUT_TOKENS));
        if over {
            object.insert(key.to_string(), Value::from(MAX_OUTPUT_TOKENS));
        }
    }
}

/// 客户端额度太小、而这个模型一定先思考时，把它抬到「原值 + 预留」。
///
/// 不抬的话上游会把额度全花在 reasoning 上，客户端收到一次"成功的空回答"。
/// 三条边界：只在短额度动手；按模型自述上限截顶（`0` = 未声明，不截）；
/// **永不把额度改小**。
pub fn reserve_for_thinking(payload: &mut Value, max_output_tokens: i64) -> Option<(i64, i64)> {
    let key = ["max_tokens", "max_completion_tokens"]
        .into_iter()
        .find(|name| payload.get(*name).and_then(Value::as_i64).is_some())?;
    let client = payload.get(key).and_then(Value::as_i64)?;
    if client <= 0 || client >= SHORT_OUTPUT_TOKENS {
        return None;
    }
    let wanted = client.saturating_add(THINKING_RESERVE);
    let next = if max_output_tokens > 0 {
        wanted.min(max_output_tokens)
    } else {
        wanted
    };
    if next <= client {
        return None;
    }
    payload.as_object_mut()?.insert(key.to_string(), Value::from(next));
    Some((client, next))
}

// ── 聚合器与首包门 ───────────────────────────────────────────

/// 一整段 SSE 折叠出来的回答。
#[derive(Default)]
pub struct Aggregated {
    /// 正文（`choices[].delta.content` 的拼接）
    pub content: String,
    /// 思考内容（`reasoning_content`），单列出来不混进正文
    pub reasoning: String,
    pub tool_calls: Vec<Value>,
    pub usage: Option<Value>,
    pub finish_reason: String,
    pub id: Option<String>,
    pub model: Option<String>,
}

impl Aggregated {
    /// 这次回答算不算"有内容"。
    ///
    /// **只有 reasoning 也算有**：`max_tokens` 给小值时上游会只吐思考段而正文为空，
    /// 若按正文判空就会把一次成功的回答报成"上游空回复"并触发没必要的换账号。
    pub fn has_content(&self) -> bool {
        !self.content.is_empty() || !self.reasoning.is_empty() || !self.tool_calls.is_empty()
    }

    /// 渲染成 OpenAI 非流式回答体。
    pub fn completion(&self, fallback_model: &str) -> Value {
        let mut message = json!({ "role": "assistant", "content": self.content });
        if !self.reasoning.is_empty() {
            message["reasoning_content"] = Value::String(self.reasoning.clone());
        }
        if !self.tool_calls.is_empty() {
            message["tool_calls"] = Value::Array(self.tool_calls.clone());
        }
        let finish_reason = if !self.finish_reason.is_empty() {
            self.finish_reason.clone()
        } else if self.tool_calls.is_empty() {
            "stop".to_string()
        } else {
            "tool_calls".to_string()
        };
        let mut body = json!({
            "id": self.id.clone().unwrap_or_else(|| format!("chatcmpl-codearts-{}", short_id())),
            "object": "chat.completion",
            "created": sdk::now() / 1000,
            "model": self.model.clone().unwrap_or_else(|| fallback_model.to_string()),
            "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason }],
        });
        if let Some(usage) = self.usage.clone() {
            body["usage"] = usage;
        }
        body
    }
}

/// 把一整段上游 SSE 体折叠成一条回答；同时把流内错误信封挖出来。
///
/// 返回 `Err` 的两种情形都要与"成功但空"区分开：
///   * 流里带了错误信封 → 那个错误（**这是换账号的唯一触发点**）
///   * 流干净结束但一个字都没有 → `upstream_empty_response`（502）
pub fn aggregate_sse(body: &[u8], fallback_model: &str) -> Result<Value> {
    let mut decoder = SseDecoder::default();
    let mut aggregated = Aggregated::default();
    let mut seen_done = false;
    let mut error: Option<Error> = None;
    let mut consume = |data: &str| {
        if seen_done || error.is_some() {
            return;
        }
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed == DONE_SENTINEL {
            seen_done = true;
            return;
        }
        if let Some(fault) = stream_fault::stream_frame_fault(trimmed) {
            error = Some(stream_fault::fault_error(&fault, fallback_model));
            return;
        }
        merge_chunk(&mut aggregated, trimmed);
    };
    if let Ok(events) = decoder.push(body) {
        for event in events {
            consume(&event);
        }
    }
    if let Some(error) = error {
        return Err(error);
    }
    if !aggregated.has_content() {
        // 空回答是**失败**：不这样处理，跨账号降级链永远不会被触发
        return Err(Error::http(
            502,
            if seen_done {
                "CodeArts 上游流正常结束但没有返回任何内容"
            } else {
                "CodeArts 上游流意外中断且没有返回任何内容"
            },
        )
        .with_code("upstream_empty_response"));
    }
    Ok(aggregated.completion(fallback_model))
}

/// 把一帧 `choices[].delta` 合进聚合器（tool_calls 按下标合并，参数是分片拼接）。
fn merge_chunk(aggregated: &mut Aggregated, payload: &str) {
    let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
        return;
    };
    if let Some(id) = chunk.get("id").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        aggregated.id = Some(id.to_string());
    }
    if let Some(model) = chunk.get("model").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        aggregated.model = Some(model.to_string());
    }
    if let Some(usage) = chunk.get("usage").filter(|value| !value.is_null()) {
        aggregated.usage = Some(usage.clone());
    }
    let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
        return;
    };
    for choice in choices {
        if let Some(delta) = choice.get("delta").and_then(Value::as_object) {
            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                aggregated.content.push_str(content);
            }
            if let Some(reasoning) = delta.get("reasoning_content").and_then(Value::as_str) {
                aggregated.reasoning.push_str(reasoning);
            }
            if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for call in calls {
                    merge_tool_call(&mut aggregated.tool_calls, call);
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str).filter(|value| !value.is_empty()) {
            aggregated.finish_reason = reason.to_string();
        }
    }
}

/// 按 `index` 合并 tool_call 分片：id/type/name 取首个非空，`arguments` 是**拼接**。
fn merge_tool_call(calls: &mut Vec<Value>, incoming: &Value) {
    let index = incoming.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
    if index >= MAX_TOOL_CALLS {
        // 越界的分片**丢掉**而不是扩容：真实的并行工具调用不会到这个量级
        return;
    }
    while calls.len() <= index {
        calls.push(json!({ "index": calls.len(), "type": "function", "function": { "name": "", "arguments": "" } }));
    }
    let Some(target) = calls.get_mut(index) else {
        return;
    };
    if let Some(id) = incoming.get("id").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        target["id"] = Value::String(id.to_string());
    }
    if let Some(kind) = incoming.get("type").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        target["type"] = Value::String(kind.to_string());
    }
    if let Some(function) = incoming.get("function").and_then(Value::as_object) {
        if let Some(name) = function.get("name").and_then(Value::as_str).filter(|value| !value.is_empty()) {
            target["function"]["name"] = Value::String(name.to_string());
        }
        if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
            let joined = format!(
                "{}{}",
                target["function"]["arguments"].as_str().unwrap_or(""),
                arguments
            );
            target["function"]["arguments"] = Value::String(joined);
        }
    }
}

/// 首包门的判定：流结束时的状态。
enum HeadVerdict {
    /// 拿到了内容，可以下发
    Answered,
    /// 流在第一个内容帧之前就结束了 → 空回答（当失败处理，触发换账号）
    Empty,
    /// 第一个内容帧之前撞上错误信封
    Fault(stream_fault::StreamFault),
}

/// 首包门核心：喂一串**已经解析好的** SSE 数据帧，判定能不能交给客户端。
fn head_verdict<'a>(frames: impl IntoIterator<Item = &'a str>) -> HeadVerdict {
    for data in frames {
        let data = data.trim();
        if data.is_empty() || data == DONE_SENTINEL {
            continue;
        }
        if let Some(fault) = stream_fault::stream_frame_fault(data) {
            return HeadVerdict::Fault(fault);
        }
        // 「有内容」的判据与聚合器一致（只有 reasoning 也算）
        let mut scratch = Aggregated::default();
        merge_chunk(&mut scratch, data);
        if scratch.has_content() {
            return HeadVerdict::Answered;
        }
    }
    HeadVerdict::Empty
}

fn short_id() -> String {
    // 不做强随机：只用于给非流式回答造一个 id，撞了也无害（宿主的 random 能力
    // 还要一条声明，为这点小事多要一个权限不值得）。
    let now = sdk::now();
    format!("{:x}{:x}", now, std::process::id())
}

// ── 尺寸门 ───────────────────────────────────────────────────

/// 这一发是不是**体积**被拒？是的话给出那句给人读的原因。
///
/// 判据只取文案、**不取状态码也不取错误码**：`APIG.0201` 是过载码（官方错误码表
/// 把它同时给了 400/413/414/494/502/504/500）；同一句 `Request entity too large`
/// 实测出现过 400 与 502 两种状态。这两句文案本身足够特定。
pub fn size_rejection_text(text: &str) -> Option<&'static str> {
    let lowered = text.to_lowercase();
    if lowered.contains("parse_request_data_exception") {
        return Some("上游解析不了该体积的请求体（400 PARSE_REQUEST_DATA_EXCEPTION）");
    }
    if lowered.contains("request entity too large") {
        return Some("上游网关拒收该体积（413 Request entity too large）");
    }
    None
}

/// 第二条判据：泛化的「请求参数无效」+ **这发的字节数已越过实测上界**。
///
/// 上游对超限体的回法不止一种形状：经网关这一路拿到的 SSE 帧只有
/// `InferHub.001001005.400`，没有任何尺寸字样。所以这条用**相关性**而不是文案：
/// 错误码 + 我们确知的发出字节数越界 ⇒ 记门。小体撞上同一个码就是真的参数错，
/// 不能记 —— 那是把一家冤枉关在门外 120 秒。
pub fn size_rejection_by_shape(text: &str, wire_bytes: i64) -> Option<&'static str> {
    if wire_bytes <= SIZE_CEILING_KNOWN_BYTES {
        return None;
    }
    if text.to_lowercase().contains("inferhub.001001005.400") {
        return Some("上游回「请求参数无效」，而这发已越过实测的 6 MiB 上界（按尺寸失败处理）");
    }
    None
}

/// 三处出口统一走这里：标记版优先，命不中再按体积相关性判。
pub fn size_rejection_any(text: &str, wire_bytes: i64) -> Option<&'static str> {
    size_rejection_text(text).or_else(|| size_rejection_by_shape(text, wire_bytes))
}

/// 登记尺寸门（只在从放行变成挡住那一次写存储）。
fn hold_gate(wire_bytes: i64, now_ms: i64) {
    let _ = sdk::session_put(
        GATE_KEY,
        json!({ "floor": wire_bytes, "at": now_ms }),
        GATE_TTL_MS,
    );
}

/// 当前尺寸门：`(字节下界, 剩余毫秒)`；未登记或已过期返回 None。
pub fn gate(now_ms: i64) -> Option<(i64, i64)> {
    let value = sdk::session_get(GATE_KEY).ok()?;
    let at = value["at"].as_i64()?;
    let elapsed = now_ms.saturating_sub(at);
    if elapsed > GATE_TTL_MS {
        return None;
    }
    let floor = value["floor"].as_i64().filter(|floor| *floor > 0)?;
    Some((floor, GATE_TTL_MS.saturating_sub(elapsed)))
}

/// 把一次尺寸失败登记进门（返回是否**刚**登记上）。
fn note_size_gate(reason: Option<&'static str>, wire_bytes: i64) {
    let Some(_reason) = reason else { return };
    let now = sdk::now();
    // 只在「从放行变成挡住」那一次写：门存续期内每发大请求都会命中判据
    if gate(now).is_none() {
        hold_gate(wire_bytes, now);
    }
}

// ── 对话主流程 ───────────────────────────────────────────────

/// 一次上游响应的读取结果。
struct Prefetch {
    /// 首包门期间攒下的原始字节（`idle` 路径原样下发）
    bytes: Vec<u8>,
    /// 首包门期间解出来的事件（`tool_names` 需要改写时按事件重建）
    events: Vec<String>,
    /// 是否已经见到 `[DONE]`
    done: bool,
}

/// 转发一次对话。
pub fn forward(params: &Value) -> Result<()> {
    let account_id = params["account"].as_str().unwrap_or("").trim().to_string();
    if account_id.is_empty() {
        return Err(Error::http(400, "没有可用的 CodeArts 账号：请在账号页添加并启用账号"));
    }
    let client_stream = params["client_stream"].as_bool().unwrap_or(true);
    let mut body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    // ① 凭据（含临期主动续期与写回）
    let credential = super::credentials::ensure(false)?;

    // ② 模型名归一：客户端习惯小写，上游要真名；福利模型要带 maas_type
    let requested = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let catalog = models::ensure_catalog()?;
    let Some(model) = catalog.resolve(&requested) else {
        return Err(models::unknown_model_error(&requested, &catalog));
    };
    let benefit = model.benefit();
    let upstream_model = model.id.clone();
    let max_output_tokens = model.max_output_tokens;

    // ②.5 尺寸门：这一家刚在「体 ≥ N 字节」上被上游拒过（TTL 内），同尺寸的
    // 就别再发出去 —— 上游那道墙按字节判，重发同一份体结论不变。
    const ESTIMATE_SLACK_BYTES: i64 = 64 * 1024;
    let now_ms = sdk::now();
    if let Some((floor, ms_left)) = gate(now_ms) {
        let estimate = serde_json::to_string(&body).map(|text| text.len() as i64).unwrap_or_default();
        if estimate + ESTIMATE_SLACK_BYTES >= floor {
            return Err(Error::http(
                413,
                format!(
                    "CodeArts 发不出这么大的请求体（本次约 {} 字节，这一家已知 ≥ {} 字节会被上游拒）：\
                     本轮绕开这一家，最长 {} 秒后会重新探一次；\
                     要立刻可用就减小上下文（少带历史 / 别整份贴文件）",
                    estimate,
                    floor,
                    ms_left / 1000
                ),
            )
            .with_code("codearts_body_too_large"));
        }
    }

    // ③ 占一个上游会话槽（心跳 busy + 后台续期全在宿主里）
    let session = upstream::Session::open()?;
    let session_id = session.id().to_string();

    // ④ 构造并发出（签名要覆盖到刚生成的 session id，所以顺序在后）
    let profile = HeaderProfile { chat_session_id: Some(session_id), ..Default::default() };
    // 客户端额度太小、而这个模型一定先思考时抬一抬
    reserve_for_thinking(&mut body, max_output_tokens);
    // 函数名超上限的改写也必须发生在签名之前：改名动了 `tools`，
    // 而签名覆盖的就是出门那串字节。
    let restorer = tool_names::shorten(&mut body);
    let (url, headers, payload) = build_upstream_request(
        &upstream::base(),
        &upstream_model,
        body,
        true,
        benefit,
        &profile,
        &credential,
    )?;
    let wire_bytes = payload.len() as i64;
    let mut response = sdk::http::open_raw("POST", &url, upstream::header_object(&headers), Some(&payload))?;

    // ⑤ 非 2xx：原样带状态码 + 脱敏诊断体
    if !(200..300).contains(&response.status) {
        let status = response.status;
        let (mut buffer, truncated) = read_limited(&mut response, ERROR_BODY_BUDGET)?;
        if buffer.len() > ERROR_BODY_BUDGET {
            buffer.truncate(ERROR_BODY_BUDGET);
        }
        let text = String::from_utf8_lossy(&buffer).to_string();
        note_size_gate(size_rejection_any(&text, wire_bytes), wire_bytes);
        let detail = redact::redact(&text, &credential, truncated);
        let detail = detail.trim();
        let mut message = format!("CodeArts 上游返回 HTTP {status}");
        if !detail.is_empty() {
            message.push('：');
            message.push_str(&truncate_chars(detail, 2000));
        }
        if truncated {
            message.push_str("（诊断体已截断）");
        }
        let message = stream_fault::humanize_fault_message(message, &upstream_model);
        let error = Error::http(status, message);
        return Err(match status {
            403 => error.with_code("insufficient_quota"),
            429 => error.with_code("rate_limit_exceeded"),
            _ => error,
        });
    }

    // ⑥ 首包门：一个字节都没下发之前就决定"交出去"还是"换账号"
    let mut decoder = SseDecoder::default();
    let mut prefetched = Prefetch { bytes: Vec::new(), events: Vec::new(), done: false };
    let mut verdict: Option<HeadVerdict> = None;
    loop {
        if verdict.is_some() {
            break;
        }
        let chunk = match response.read() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                // 读首包就断了：还没下发任何字节，直接当失败
                return Err(Error::http(502, format!("CodeArts 上游流中断：{}", error.message)));
            }
        };
        prefetched.bytes.extend_from_slice(&chunk);
        match decoder.push(&chunk) {
            Ok(events) => {
                for event in events {
                    if event.trim() == DONE_SENTINEL {
                        prefetched.done = true;
                    }
                    prefetched.events.push(event);
                }
            }
            Err(error) => return Err(error),
        }
        verdict = match head_verdict(prefetched.events.iter().map(String::as_str)) {
            HeadVerdict::Empty => None,
            other => Some(other),
        };
        if verdict.is_none() && prefetched.bytes.len() > HEAD_BUFFER_LIMIT {
            // 攒够了还没判定：按「有内容」放行，避免无界缓冲
            verdict = Some(HeadVerdict::Answered);
        }
    }
    match verdict {
        Some(HeadVerdict::Fault(fault)) => {
            // ⑦.5 体积墙也走在**流里**：HTTP 200 + 一帧 `InferHub.001001005.400`
            let text = prefetched.events.join("\n");
            note_size_gate(size_rejection_any(&text, wire_bytes), wire_bytes);
            return Err(stream_fault::fault_error(&fault, &upstream_model));
        }
        Some(HeadVerdict::Answered) => {}
        _ => {
            // 一个内容帧都没有就结束了：空回答当失败，触发换账号
            let text = prefetched.events.join("\n");
            note_size_gate(size_rejection_any(&text, wire_bytes), wire_bytes);
            return Err(Error::http(502, "CodeArts 上游流正常结束但没有返回任何内容")
                .with_code("upstream_empty_response"));
        }
    }

    if !client_stream {
        // 非流式：把剩下的读完再折叠（上游只有流式）
        let mut all = prefetched.bytes.clone();
        loop {
            match response.read() {
                Ok(Some(chunk)) => all.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => {
                    return Err(Error::http(502, format!("CodeArts 上游流中断：{}", error.message)))
                }
            }
        }
        note_size_gate(size_rejection_any(&String::from_utf8_lossy(&all), wire_bytes), wire_bytes);
        let mut completion = aggregate_sse(&all, &upstream_model)?;
        // 非流式也要把函数名还原回客户端原来的写法（改过名时聚合结果里是短名）
        if let Some(restorer) = restorer.as_ref() {
            restorer.apply(&mut completion);
        }
        let payload = serde_json::to_string(&completion)
            .map_err(|_| Error::http(502, "CodeArts 聚合结果序列化失败"))?;
        sdk::stream_head(200)?;
        sdk::stream_bytes(payload.as_bytes())?;
        return Ok(());
    }

    // ⑦ 流式：透传（上游已是 OpenAI chunk 形状）
    sdk::stream_head(200)?;
    let idle = restorer.as_ref().is_none_or(|restorer| restorer.idle());
    if idle {
        if !prefetched.bytes.is_empty() {
            sdk::stream_bytes(&prefetched.bytes)?;
        }
    } else if let Some(restorer) = restorer.as_ref() {
        for event in &prefetched.events {
            emit_event(event, restorer)?;
        }
    }
    let mut done = prefetched.done;
    loop {
        let chunk = match response.read() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                // 已经下发过内容：如实按中断上报，绝不从头重发
                let failure = Error::http(502, format!("CodeArts 上游流中断：{}", error.message));
                sdk::stream_event(&stream_fault::error_event(&failure))?;
                return Err(failure);
            }
        };
        if idle {
            sdk::stream_bytes(&chunk)?;
            if contains_done(&chunk) {
                done = true;
            }
        } else {
            match decoder.push(&chunk) {
                Ok(events) => {
                    for event in events {
                        if event.trim() == DONE_SENTINEL {
                            done = true;
                        }
                        if let Some(restorer) = restorer.as_ref() {
                            emit_event(&event, restorer)?;
                        }
                    }
                }
                Err(error) => {
                    sdk::stream_event(&stream_fault::error_event(&error))?;
                    return Err(error);
                }
            }
        }
    }
    if !done {
        // 上游没给结束哨兵就断了：补一条，免得客户端一直挂着等
        sdk::stream_bytes(format!("data: {DONE_SENTINEL}\n\n").as_bytes())?;
    }
    Ok(())
}

/// 发一条事件（非 idle 路径按事件重建，顺带还原工具名）。
fn emit_event(event: &str, restorer: &tool_names::Restorer) -> Result<()> {
    let trimmed = event.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed == DONE_SENTINEL {
        return sdk::stream_bytes(format!("data: {DONE_SENTINEL}\n\n").as_bytes());
    }
    let restored = restorer.apply_text(trimmed);
    sdk::stream_bytes(format!("data: {restored}\n\n").as_bytes())
}

/// 这段字节里有没有 `[DONE]`（只用于判断收尾，不需要精确的 SSE 解析）。
fn contains_done(bytes: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"[DONE]";
    bytes.windows(NEEDLE.len()).any(|window| window == NEEDLE)
}

/// 读响应体，最多读到 `limit + 1` 字节（多读一个字节用于判断「还有没有」）。
fn read_limited(response: &mut http::Response, limit: usize) -> Result<(Vec<u8>, bool)> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(body.len());
                if chunk.len() > room {
                    body.extend_from_slice(&chunk[..room]);
                    return Ok((body, true));
                }
                body.extend_from_slice(&chunk);
                if body.len() >= limit {
                    return Ok((body, true));
                }
            }
            Ok(None) => return Ok((body, false)),
            // 读诊断体本身失败：手上这一截照样有用，如实标注不完整
            Err(_) => return Ok((body, true)),
        }
    }
}

/// 按字符数截断（不是字节：中文文案按字节截会切出半个字符）。
fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value.chars().take(limit).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(frames: &[&str]) -> Vec<u8> {
        let mut body = String::new();
        for frame in frames {
            body.push_str("data: ");
            body.push_str(frame);
            body.push_str("\n\n");
        }
        body.into_bytes()
    }

    /// 上游对输出上限的取值做预校验：65536 过、65537 起整条拒收。
    #[test]
    fn the_output_cap_is_clamped_but_never_invented() {
        let mut payload = json!({ "max_completion_tokens": 128_000 });
        clamp_output_tokens(&mut payload);
        assert_eq!(MAX_OUTPUT_TOKENS, payload["max_completion_tokens"].as_i64().unwrap_or(-1));

        let mut exact = json!({ "max_tokens": MAX_OUTPUT_TOKENS });
        clamp_output_tokens(&mut exact);
        assert_eq!(MAX_OUTPUT_TOKENS, exact["max_tokens"].as_i64().unwrap_or(-1));

        let mut absent = json!({ "messages": [] });
        clamp_output_tokens(&mut absent);
        assert!(absent.get("max_tokens").is_none(), "缺省时不注入");

        let mut text = json!({ "max_tokens": "128000" });
        clamp_output_tokens(&mut text);
        assert_eq!("128000", text["max_tokens"].as_str().unwrap_or_default(), "非整数形态不碰");
    }

    /// 抬额度：只在短额度动手、按模型上限截顶、永不改小。
    #[test]
    fn a_short_output_cap_is_raised_for_thinking() {
        let mut short = json!({ "max_tokens": 60 });
        assert_eq!(Some((60, 60 + THINKING_RESERVE)), reserve_for_thinking(&mut short, 384_000));
        assert_eq!(60 + THINKING_RESERVE, short["max_tokens"].as_i64().unwrap_or(-1));

        let mut capped = json!({ "max_tokens": 60 });
        assert_eq!(Some((60, 80)), reserve_for_thinking(&mut capped, 80), "按模型上限截顶");

        let mut generous = json!({ "max_tokens": 4096 });
        assert_eq!(None, reserve_for_thinking(&mut generous, 384_000), "够用就不动");

        let mut unknown = json!({ "max_tokens": 60 });
        assert_eq!(Some((60, 60 + THINKING_RESERVE)), reserve_for_thinking(&mut unknown, 0));
    }

    /// 「关思考」的三种写法要摘掉；档位值原样走。
    #[test]
    fn thinking_off_keys_are_removed_and_real_levels_are_kept() {
        let mut off = json!({ "reasoning_effort": "none", "enable_thinking": false, "temperature": 1 });
        let dropped = drop_thinking_off(&mut off);
        assert_eq!(2, dropped.len());
        assert!(off.get("reasoning_effort").is_none());
        assert!(off.get("enable_thinking").is_none());
        assert_eq!(1, off["temperature"].as_i64().unwrap_or(-1));

        let mut kept = json!({ "reasoning_effort": "high", "enable_thinking": true });
        assert!(drop_thinking_off(&mut kept).is_empty());
        assert_eq!("high", kept["reasoning_effort"].as_str().unwrap_or_default());
    }

    /// 对象形态的 `tool_choice` 必被拒，折成字符串 `required`。
    #[test]
    fn a_forced_tool_choice_is_folded_into_required() {
        let mut payload = json!({ "tool_choice": { "type": "function", "function": { "name": "alpha" } } });
        assert_eq!(Some("alpha".to_string()), fold_forced_tool_choice(&mut payload));
        assert_eq!("required", payload["tool_choice"].as_str().unwrap_or_default());

        for kept in ["auto", "none", "required"] {
            let mut payload = json!({ "tool_choice": kept });
            assert_eq!(None, fold_forced_tool_choice(&mut payload), "{kept} 不该被改");
        }
    }

    /// 正常流折叠成一条 completion；只有 reasoning 也算有内容。
    #[test]
    fn a_normal_stream_folds_into_a_completion() {
        let body = sse(&[
            r#"{"id":"x","model":"GLM-5.2","choices":[{"index":0,"delta":{"reasoning_content":"想想"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"content":"你好"},"finish_reason":"stop"}]}"#,
            r#"{"usage":{"total_tokens":9}}"#,
            "[DONE]",
        ]);
        let completion = match aggregate_sse(&body, "GLM-5.2") {
            Ok(value) => value,
            Err(_) => panic!("正常流必须能聚合"),
        };
        assert_eq!("chat.completion", completion["object"].as_str().unwrap_or_default());
        assert_eq!("你好", completion["choices"][0]["message"]["content"].as_str().unwrap_or_default());
        assert_eq!("想想", completion["choices"][0]["message"]["reasoning_content"].as_str().unwrap_or_default());
        assert_eq!(9, completion["usage"]["total_tokens"].as_i64().unwrap_or(-1));
    }

    /// 流干净结束但一个字都没答 = 失败（否则跨账号降级链永不被触发）。
    #[test]
    fn an_empty_stream_is_a_failure() {
        let body = sse(&[r#"{"choices":[{"index":0,"delta":{}}]}"#, "[DONE]"]);
        let error = match aggregate_sse(&body, "GLM-5.2") {
            Ok(_) => panic!("空回答必须报错"),
            Err(error) => error,
        };
        assert_eq!(Some(502), error.status);
        assert_eq!(Some("upstream_empty_response".to_string()), error.code);
    }

    /// 流里的额度信封必须变成 403，而不是当成一次成功的空回答。
    #[test]
    fn a_quota_envelope_inside_the_stream_becomes_forbidden() {
        let body = sse(&[r#"{"error_code":"InferHub.4291.200","error_msg":"insufficient quota"}"#]);
        let error = match aggregate_sse(&body, "GLM-5.3-flash") {
            Ok(_) => panic!("额度信封必须报错"),
            Err(error) => error,
        };
        assert_eq!(Some(403), error.status);
        assert_eq!(Some("insufficient_quota".to_string()), error.code);
    }

    /// 首包门：有内容才放行；错误信封在内容之前就判掉。
    #[test]
    fn the_head_gate_decides_before_anything_is_sent() {
        assert!(matches!(
            head_verdict([r#"{"choices":[{"index":0,"delta":{"content":"hi"}}]}"#]),
            HeadVerdict::Answered
        ));
        assert!(matches!(head_verdict(["", "[DONE]"]), HeadVerdict::Empty));
        assert!(matches!(
            head_verdict([r#"{"error_code":"InferHub.4291.200","error_msg":"insufficient quota"}"#]),
            HeadVerdict::Fault(_)
        ));
    }

    /// 体积墙的两句文案（状态码不可信，判据只取文案）。
    #[test]
    fn size_rejection_markers_are_recognized_by_text_only() {
        assert!(size_rejection_text("413 Request entity too large").is_some());
        assert!(size_rejection_text(r#"{"details":[{"error_code":"PARSE_REQUEST_DATA_EXCEPTION"}]}"#).is_some());
        // 反面对照：模型名问题不是体积问题
        assert!(size_rejection_text("InferHub.002002009.404 The model is not registered").is_none());
        // 未越界的 001001005 不能记门（那是真的参数错）
        assert!(size_rejection_any("InferHub.001001005.400", 1024).is_none());
        // 越界后同一个码才记门
        assert!(size_rejection_any("InferHub.001001005.400", SIZE_CEILING_KNOWN_BYTES + 1).is_some());
    }
}
