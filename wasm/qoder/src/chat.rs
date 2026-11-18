//! Qoder 对话转发（native `chat.rs` + `piping.rs` + `mod.rs::run_conversation`）。
//!
//! ── 为什么走会话式入口（`stateful`）────────────────────────────
//! 无状态路径假设「请求体由通用层序列化后原样发出、响应是 OpenAI 协议的 SSE」。
//! Qoder 两条都不满足：
//!   1. 请求体必须**先编码再签名**（`cosy::encode_body` → `cosy::build_auth_headers`），
//!      而签名覆盖编码后的字节 —— 通用层序列化出来的字节既没编码也没被签名覆盖；
//!   2. 下游帧需要**拆掉上游的一层信封**（`{statusCodeValue, body}` → 内层
//!      OpenAI chunk），通用层的 SSE 透传不认识这层包装。
//! 因此本模块把「构造 → 发送 → 翻译」整条链收进来。
//!
//! ── 额度/鉴权错误为什么在流内也要判 ───────────────────────────
//! 上游的业务错误**不体现在 HTTP 状态码上**（永远是 200），而是放在 SSE 信封的
//! `statusCodeValue` 里。所以「换个账号重试」这个动作必须由本模块在读到信封错误
//! 时**主动转成带状态码的错误**交回编排层：额度/限流报 429、鉴权报 401。
//!
//! ── 首帧预读（issue #8 的修复，原样保留）────────────────────
//! 拿到 HTTP 200 不能直接报头：Qoder 的额度错误恰恰写在 200 的 SSE 信封里。
//! 预读把首个事件拦在报头之前 —— 业务错误转成带状态码的 `Err` 交回编排层换号
//! （此刻还没有任何字节下发，换号无损）；拿到内容帧才 `stream_head(200)`，
//! 预读帧随后补发。**流已经开始下发之后的错误只能留在流里**：补一帧
//! `{"error":…}` + `[DONE]` 再返回错误。
//!
//! ── 与 native 的两处差别（都有明确原因）──────────────────────
//!   1. **非流式聚合不做了**：wasm 的 `stream_head` 固定 `text/event-stream`，
//!      而宿主对 wasm 插件按 SSE 消费（同 `wasm/atomcode`）。上游本来也只支持
//!      流式，客户端要非流式时由网关那一层聚合。native 的 `drive_aggregate`
//!      因此不迁。
//!   2. **排队等待的次数与时长不再读设置页**：native 读 `config::queue_settings`
//!      （网关的用户配置），插件拿不到那份配置。这里用 native 的缺省语义
//!      （最多等 2 次、单次跟随上游建议 5～30 秒、缺省 15 秒）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use std::collections::BTreeMap;

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Error, Result, Value};

use super::context;
use super::cosy::{self, CosyIdentity};
use super::credentials::Credentials;
use super::errors::{self, Attempt};
use super::models;
use super::protocol;
use super::site;
use super::stream;

/// 一次转发所需的全部素材（进函数时组装好，之后只读）
pub struct ChatPlan {
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// 已编码的请求体（签名覆盖的就是它）
    pub body: Vec<u8>,
    /// 客户端请求的模型名（下发帧的 `model` 字段用它）
    pub model_name: String,
    /// 是否要下发思考内容（决定要不要启用标签拆解器）
    pub thinking: bool,
}

/// 一个上游响应 id（客户端按它关联同一次回答；形态照抄 OpenAI）
fn response_id() -> String {
    let uuid = cosy::random_uuid().replace('-', "");
    let short: String = uuid.chars().take(24).collect();
    format!("chatcmpl-{short}")
}

/// 客户端请求体 → 一次上游调用的完整计划（**不含网络**）。
pub fn build_plan(credentials: &Credentials, body: &Value, model_name: &str) -> Result<ChatPlan> {
    let model = models::resolve(model_name).ok_or_else(|| {
        Error::http(
            400,
            format!(
                "模型不存在: {model_name}。{} 可用模型见 GET /v1/models",
                site::display_name()
            ),
        )
        .with_code("model_not_found")
    })?;
    let upstream_key = model
        .get("upstreamKey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if upstream_key.is_empty() {
        return Err(Error::http(502, "Qoder 模型目录缺少上游标识"));
    }
    let model_config = model.get("config").cloned().unwrap_or(Value::Null);

    // ── 消息规整 ──────────────────────────────────────────────
    let raw_messages = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let messages = protocol::normalize_messages(&raw_messages);
    // system 提示必须放进 messages 里（上游顶层 system 字段无效），
    // 且要排在**最前面** —— 源实现在调用处显式做了这一步
    let system_texts: Vec<String> = raw_messages
        .iter()
        .filter(|message| {
            let role = message.get("role").and_then(Value::as_str).unwrap_or("");
            role == "system" || role == "developer"
        })
        .map(|message| {
            message
                .get("content")
                .map(protocol::content_to_text)
                .unwrap_or_default()
        })
        .filter(|text| !text.is_empty())
        .collect();
    let final_messages: Vec<Value> = if system_texts.is_empty() {
        messages
    } else {
        let mut ordered: Vec<Value> = system_texts
            .iter()
            .map(|text| json!({ "role": "system", "content": text }))
            .collect();
        ordered.extend(
            messages
                .into_iter()
                .filter(|message| message.get("role").and_then(Value::as_str) != Some("system")),
        );
        ordered
    };

    let tools = protocol::normalize_tools(body.get("tools"));
    let thinking = protocol::resolve_thinking(body, &model);
    let max_tokens = body
        .get("max_tokens")
        .and_then(Value::as_i64)
        .or_else(|| body.get("max_completion_tokens").and_then(Value::as_i64));
    // 下游若给了 user / session_id，用它做会话种子，同一对话复用同一 session
    let session_seed = body
        .get("user")
        .and_then(Value::as_str)
        .or_else(|| body.get("session_id").and_then(Value::as_str));

    let mut upstream_body = protocol::build_upstream_body(
        &upstream_key,
        &model_config,
        &final_messages,
        tools.as_ref(),
        max_tokens,
        &thinking,
        &credentials.user_id,
        session_seed,
    );

    // ── 上下文档位：装了才升级 ────────────────────────────────
    // 上游每个模型有多档上下文窗口（200K / 400K / 1M），默认只启用其中一档。
    // prompt 超过当前档时升到「最小的够用档」—— 多数请求不触发（`resolve`
    // 返回 None），那时的请求体与改造前逐字相同。
    if let Some(tier) = context::resolve(&model_config, &final_messages, tools.as_ref()) {
        context::apply(&mut upstream_body, &tier);
    }

    // ── 编码 → 签名（顺序不能颠倒，理由见模块头）────────────────
    let encoded = cosy::encode_body(upstream_body.to_string().as_bytes());
    let url = site::gateway_url(
        "algo/api/v2/service/pro/sse/agent_chat_generation\
         ?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1",
    );
    let identity = CosyIdentity {
        user_id: &credentials.user_id,
        auth_token: &credentials.access_token,
        name: &credentials.name,
        email: &credentials.email,
        machine_id: &credentials.machine_id,
    };
    let mut headers = cosy::build_auth_headers(Some(&encoded), &url, &identity)?;
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    headers.push(("Accept".to_string(), "text/event-stream".to_string()));
    headers.push(("Cache-Control".to_string(), "no-cache".to_string()));
    headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
    // 上游靠这两个头做模型路由与来源标记。来源取目录条目自己的 `source`
    // （兜底 "system"）：写死会让 BYOK 一类的条目被标错来源。
    let model_source = model_config
        .get("source")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("system")
        .to_string();
    headers.push(("X-Model-Key".to_string(), upstream_key.clone()));
    headers.push(("X-Model-Source".to_string(), model_source));

    Ok(ChatPlan {
        url,
        headers,
        body: encoded,
        model_name: model_name.to_string(),
        // 只有「模型支持思考」时才启用标签拆解（否则正文里的尖括号是用户内容）
        thinking: thinking.enable.is_some() || thinking.effort.is_some(),
    })
}

// ─── 翻译器（上游 chunk → 客户端 delta）──────────────────────────

#[derive(Default)]
struct ToolCallState {
    id: String,
    name: String,
    arguments: String,
}

/// 从上游 chunk 翻译出的一条增量
pub enum TranslatedDelta {
    Content(String),
    Reasoning(String),
    ToolCall {
        index: i64,
        id: Option<String>,
        name: Option<String>,
        arguments: Option<String>,
    },
}

/// 把一条 `TranslatedDelta` 变成 OpenAI 的 delta JSON（流式下发用）
pub fn delta_json(delta: &TranslatedDelta) -> Value {
    match delta {
        TranslatedDelta::Content(text) => json!({ "content": text }),
        TranslatedDelta::Reasoning(text) => json!({ "reasoning_content": text }),
        TranslatedDelta::ToolCall { index, id, name, arguments } => {
            let mut function = serde_json::Map::new();
            if let Some(name) = name {
                function.insert("name".to_string(), Value::String(name.clone()));
            }
            if let Some(arguments) = arguments {
                function.insert("arguments".to_string(), Value::String(arguments.clone()));
            }
            let mut call = serde_json::Map::new();
            call.insert("index".to_string(), Value::from(*index));
            if let Some(id) = id {
                call.insert("id".to_string(), Value::String(id.clone()));
            }
            call.insert("type".to_string(), Value::String("function".to_string()));
            call.insert("function".to_string(), Value::Object(function));
            json!({ "tool_calls": [Value::Object(call)] })
        }
    }
}

/// 上游帧 → 客户端帧 的翻译状态。
///
/// ── 为什么把「翻译」与「下发」分开 ────────────────────────────
/// 解析与拆解规则（尤其是思考标签的跨分片处理）只写在这里一份，下发侧只负责
/// 把产出变成 SSE 帧。
pub struct Translator {
    /// 面向客户端的响应 id
    pub response_id: String,
    created: i64,
    model_name: String,
    /// 上游回传的模型名（映射回对外 id 后下发）
    model_reported: Option<String>,
    /// 下发帧固定回客户端请求的那个名字（见 `new` 的说明）
    echo_requested_model: bool,
    /// 工具调用按 index 累积
    tool_state: BTreeMap<i64, ToolCallState>,
    /// 是否已下发过 role 帧（流式）
    role_sent: bool,
    /// 思考标签拆解器（**跨 chunk 长驻**）。
    ///
    /// ── 为什么是字段而不是每次现建 ─────────────────────────────
    /// 拆解器要在缓冲区里留「可能是标签前缀」的尾巴（`<thi` + `nking>` 分两片
    /// 到达）。若每个 chunk 都新建一个，那片尾巴会在 chunk 结束时被当成正文
    /// 吐出去 —— 跨分片的标签拆解就永远不会生效，而这正是它存在的全部理由。
    parser: Option<stream::ThinkingParser>,
    /// usage 取最后一次出现
    pub usage: Option<Value>,
    /// finish_reason 取最后一次非空
    pub finish_reason: Option<String>,
    /// 收到的 chunk 数（排障用）
    pub chunk_count: usize,
}

impl Translator {
    /// ── 为什么「客户端给的名字认得出来」就固定回它 ────────────────
    /// 上游回的 `model` 是**路由档位**而不是我们请求的那个模型：请求
    /// `Qwen3.8-Flash`（上游 key `qfmodel`）时实测回的是 `"auto"`。按它做映射
    /// 会把下游帧里的模型名换成另一个模型（`auto` → 清单里的 `Auto`），
    /// 客户端日志与计费归集都会看到「我没请求过的模型」。
    ///
    /// 只有当客户端写的是**内部 key**（`qfmodel` 这类认不出来的名字）时才保留
    /// 映射：那种情况的映射是在把它归一成可读的模型名，是需要的。
    pub fn new(response_id: String, model_name: String, thinking_enabled: bool) -> Self {
        let echo_requested_model = models::resolve(&model_name).is_some();
        Self {
            response_id,
            created: sdk::now() / 1000,
            model_name,
            model_reported: None,
            echo_requested_model,
            tool_state: BTreeMap::new(),
            role_sent: false,
            parser: if thinking_enabled {
                Some(stream::ThinkingParser::new())
            } else {
                None
            },
            usage: None,
            finish_reason: None,
            chunk_count: 0,
        }
    }

    /// 一个上游 chunk → 若干个「面向客户端的 delta」。
    pub fn consume(&mut self, chunk: &Value) -> Vec<TranslatedDelta> {
        self.chunk_count += 1;
        if let Some(model) = chunk.get("model").and_then(Value::as_str) {
            if !model.is_empty() {
                self.model_reported = protocol::map_model_back(model);
            }
        }
        if let Some(usage) = chunk.get("usage").filter(|value| value.is_object()) {
            self.usage = Some(usage.clone());
        }
        let mut out: Vec<TranslatedDelta> = Vec::new();
        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            return out;
        };
        if let Some(finish) = choice.get("finish_reason").and_then(Value::as_str) {
            if !finish.is_empty() {
                self.finish_reason = Some(finish.to_string());
            }
        }
        let Some(delta) = choice.get("delta") else {
            return out;
        };

        // 上游显式给出的 reasoning_content 优先（且要去掉偶带的标签）
        if let Some(reasoning) = delta.get("reasoning_content").and_then(Value::as_str) {
            let cleaned = stream::strip_thinking_tags(reasoning);
            if !cleaned.is_empty() {
                out.push(TranslatedDelta::Reasoning(cleaned));
            }
        }
        if let Some(content) = delta.get("content").and_then(Value::as_str) {
            if !content.is_empty() {
                if self.parser.is_some() {
                    // 上游可能把思考混在正文里：按标签拆开（**跨分片的标签前缀
                    // 留在解析器缓冲里**，所以解析器必须长驻，见字段说明）
                    let pieces = {
                        let parser = self.parser.as_mut();
                        let Some(parser) = parser else {
                            return out;
                        };
                        parser.push(content);
                        parser.take()
                    };
                    for piece in pieces {
                        if piece.is_thinking {
                            out.push(TranslatedDelta::Reasoning(piece.text));
                        } else {
                            out.push(TranslatedDelta::Content(piece.text));
                        }
                    }
                } else {
                    out.push(TranslatedDelta::Content(content.to_string()));
                }
            }
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let index = call.get("index").and_then(Value::as_i64).unwrap_or(0);
                let entry = self.tool_state.entry(index).or_default();
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    if !id.is_empty() {
                        entry.id = id.to_string();
                    }
                }
                if let Some(name) = call.pointer("/function/name").and_then(Value::as_str) {
                    if !name.is_empty() {
                        entry.name = name.to_string();
                    }
                }
                if let Some(arguments) = call.pointer("/function/arguments").and_then(Value::as_str) {
                    entry.arguments.push_str(arguments);
                }
                out.push(TranslatedDelta::ToolCall {
                    index,
                    id: call.get("id").and_then(Value::as_str).map(str::to_string),
                    name: call
                        .pointer("/function/name")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    arguments: call
                        .pointer("/function/arguments")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            }
        }
        out
    }

    /// 收尾：把解析器缓冲里残留的尾巴冲刷出来（幂等）。
    ///
    /// **必须在流结束时调用**：解析器留着「可能是标签前缀」的尾巴，不冲刷的话
    /// 回答末尾会少几个字符（例如正文以 `<think` 结尾时，那几个字符会永远留在
    /// 缓冲里）。
    pub fn finish(&mut self) -> Vec<TranslatedDelta> {
        let Some(parser) = self.parser.as_mut() else {
            return Vec::new();
        };
        parser.finish();
        let mut out = Vec::new();
        for piece in parser.take() {
            if piece.is_thinking {
                out.push(TranslatedDelta::Reasoning(piece.text));
            } else {
                out.push(TranslatedDelta::Content(piece.text));
            }
        }
        out
    }

    /// 下游要的 model 名（见 `new` 的说明）
    pub fn model_out(&self) -> String {
        if self.echo_requested_model {
            return self.model_name.clone();
        }
        self.model_reported
            .clone()
            .unwrap_or_else(|| self.model_name.clone())
    }

    /// 流式的 role 帧是否已发过（第一次产出 delta 前要补一帧 role）
    pub fn take_role_frame(&mut self) -> bool {
        if self.role_sent {
            return false;
        }
        self.role_sent = true;
        true
    }

    /// 最终 finish_reason：有工具调用就是 `tool_calls`
    pub fn final_finish(&self) -> String {
        if !self.tool_state.is_empty() {
            return "tool_calls".to_string();
        }
        self.finish_reason.clone().unwrap_or_else(|| "stop".to_string())
    }

    /// 流式 chunk 帧（OpenAI `chat.completion.chunk`）
    pub fn chunk_frame(&self, delta: Value, finish: Option<&str>) -> Value {
        let mut choice = serde_json::Map::new();
        choice.insert("index".to_string(), Value::from(0));
        choice.insert("delta".to_string(), delta);
        choice.insert(
            "finish_reason".to_string(),
            finish.map(|text| Value::String(text.to_string())).unwrap_or(Value::Null),
        );
        json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model_out(),
            "choices": [Value::Object(choice)],
        })
    }

    /// usage 帧（OpenAI 在流的末尾下发的形态：choices 为空数组）
    pub fn usage_frame(&self) -> Value {
        json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model_out(),
            "choices": [],
            "usage": self.usage.clone().unwrap_or(Value::Null),
        })
    }
}

// ─── 下发 ───────────────────────────────────────────────────────

fn send_frame(value: &Value) -> Result<()> {
    sdk::stream_bytes(stream::sse_frame(value).as_bytes())
}

/// 一个内层 chunk → 若干 OpenAI delta 帧。
///
/// 「首个产出前补 role 帧」「空 delta 不发」的规则都在这里：预读补发与主循环
/// 续传共用同一套，两条路径的帧序不会漂移。
fn emit_chunk(translator: &mut Translator, chunk: &Value) -> Result<()> {
    let deltas = translator.consume(chunk);
    if deltas.is_empty() {
        return Ok(());
    }
    if translator.take_role_frame() {
        let frame = translator.chunk_frame(json!({ "role": "assistant", "content": "" }), None);
        send_frame(&frame)?;
    }
    for delta in &deltas {
        let frame = translator.chunk_frame(delta_json(delta), None);
        send_frame(&frame)?;
    }
    Ok(())
}

/// 预读结论
enum Prefetch {
    /// 拿到内容帧（可能一批里有多条）
    Content(Vec<Value>),
    /// 流直接收尾（无内容无错误）
    Done,
    /// 首帧之前的业务错误 / 传输失败
    Failed(Attempt),
}

/// 流式首帧预读：把上游拉到**第一个内容帧**（或流结束）才决定返回什么。
///
/// 首帧之前的错误在这里落定：调用方据此换号（鉴权）、退避（排队）或原样返回。
fn prefetch(response: &mut http::Response) -> Result<Prefetch> {
    let mut decoder = SseDecoder::default();
    let mut chunks: Vec<Value> = Vec::new();
    loop {
        let bytes = match response.read()? {
            Some(bytes) => bytes,
            None => {
                // 上游没以空行收尾时，把解码器里剩的那条事件补出来再判
                let tail = decoder.push(b"\n\n")?;
                for event in &tail {
                    match stream::parse_sse_line(event) {
                        stream::SseEvent::Chunk(chunk) => chunks.push(chunk),
                        stream::SseEvent::Error { status, kind, raw, message, pricing_url, queue } => {
                            return Ok(Prefetch::Failed(errors::business_error(
                                status,
                                kind,
                                &raw,
                                &message,
                                pricing_url.as_deref(),
                                queue,
                            )));
                        }
                        _ => {}
                    }
                }
                if chunks.is_empty() {
                    return Ok(Prefetch::Failed(Attempt::Fatal(Error::http(
                        502,
                        "Qoder 上游流提前中断，未收到任何内容",
                    ))));
                }
                return Ok(Prefetch::Content(chunks));
            }
        };
        for event in decoder.push(&bytes)? {
            match stream::parse_sse_line(&event) {
                stream::SseEvent::Skip => {}
                stream::SseEvent::Done => {
                    if chunks.is_empty() {
                        return Ok(Prefetch::Done);
                    }
                    return Ok(Prefetch::Content(chunks));
                }
                stream::SseEvent::Error { status, kind, raw, message, pricing_url, queue } => {
                    return Ok(Prefetch::Failed(errors::business_error(
                        status,
                        kind,
                        &raw,
                        &message,
                        pricing_url.as_deref(),
                        queue,
                    )));
                }
                stream::SseEvent::Chunk(chunk) => chunks.push(chunk),
            }
        }
        // 「这一批字节里见到过内容帧」才停：一个 HTTP 分片可能拆出多行，
        // 后面的行还在这批里 —— 继续解析，直到出内容 / 流结束才回到外层。
        if !chunks.is_empty() {
            return Ok(Prefetch::Content(chunks));
        }
    }
}

/// 排队退避：还能等就睡一觉并返回 `Ok`（调用方重新签名再发一次）；
/// 预算用尽返回 `Err`（排队落定成 503，文案带已等待时长与上游原文）。
///
/// ── 等待次数为什么写死 2 次 ─────────────────────────────────
/// native 读设置页「通用 → 排队等待」（`queueMaxWaits` / `queueWaitSeconds`）。
/// 那份配置在网关侧，插件读不到；这里用 native 的**缺省值**（最多 2 次、单次
/// 跟随上游建议）。要改等待策略得在网关侧加设置下发，而不是在这里猜键名。
fn queue_backoff(waits: &mut usize, queued: &errors::Queued) -> Result<()> {
    const MAX_WAITS: usize = 2;
    if *waits >= MAX_WAITS {
        return Err(errors::queued_error(queued, 0));
    }
    *waits += 1;
    sdk::sleep(queued.retry_after_ms)?;
    Ok(())
}

/// 鉴权类失败后的补救：**强制**续期凭证一次，成功则交回新快照供调用方重发。
///
/// ── 为什么是「强制」而不是 `ensure` ──────────────────────────
/// `ensure_fresh(force = false)` 只在临期窗口内才真续期。而 401 完全可能发生在
/// 一个**时间上还很新**的 token 上（服务端侧作废、被别处顶下线、refreshToken
/// 轮换过）—— 那时 `ensure` 会把同一个被拒的 token 原样交回来，白试一次。
///
/// ── 为什么只做一次 ──────────────────────────────────────────
/// 续出来还被拒，说明问题不在凭证新旧（权限、地区、模型未开通）。再刷就是
/// 对着同一个结果反复重试，还会把上游的刷新接口打成限流的形状。
fn refresh_after_auth(attempts: &mut usize, error: Error) -> Result<Credentials> {
    if *attempts > 0 {
        return Err(error);
    }
    *attempts += 1;
    super::refresh::ensure_fresh(true)
}

/// 转发前的**目录准备**：宿主目录为空时就地补拉一次。
///
/// ── 为什么不是「拿不到就拒发」───────────────────────────────
/// Qoder 有静态兜底表，拿不到远程清单也能解析一部分模型 —— 拒发反而更糟。
/// 但兜底表是「照客户端内置抄的」一份旧清单，上游新加的模型不在里面：
/// `resolve` 找不到就报 400「模型不存在」。所以这里做的是**尽力补全**：
/// 补到了就用真的，补不到仍旧走兜底那条路（行为不倒退，只是多了一次能成的机会）。
///
/// 补拉失败会记一条会话级冷却（5 分钟），避免每个请求都打一次上游。
fn ensure_catalog() {
    let cached = sdk::catalog::cached().unwrap_or(Value::Null);
    if cached["models"].as_array().is_some_and(|items| !items.is_empty()) {
        return;
    }
    const KEY: &str = "qoder-catalog-attempt";
    if sdk::session_get(KEY).map(|value| value == true).unwrap_or(false) {
        return;
    }
    let _ = sdk::session_put(KEY, json!(true), 300_000);
    let _ = models::refresh(false);
}

/// 会话式转发入口：构造（编码 + 签名）→ 发送 → 翻译。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    let model_name = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| Error::http(400, "请求缺少模型名称"))?
        .to_string();

    // 凭证（含临期主动刷新）。本家没有环境变量旁路：没有账号就立刻报错。
    let mut credentials = super::refresh::ensure_fresh(false).map_err(|error| {
        if error.status == Some(404) {
            Error::http(503, format!("没有可用的 {} 账号：请在账号页添加并启用账号", site::display_name()))
        } else {
            error
        }
    })?;
    ensure_catalog();

    let mut queue_waits: usize = 0;
    let mut auth_retries: usize = 0;

    // ── 为什么这里是一个循环 ────────────────────────────────
    // 上游对免费模型走排队制，繁忙时会用 403 + 业务码 10605 回一句
    // 「暂不可服务，建议 N 秒后再来」。那是**可以原地等一会儿重发**的状态，
    // 所以「构造 → 发送 → 读首帧」这一整段每轮重跑一次：排队就睡一觉再来，
    // 其它错误按原样返回。首帧之后（流已开始下发）不再重试。
    loop {
        // 每轮都重新构造：COSY 签名覆盖 request_id 与请求体，**重放同一份签名**
        // 会被上游判成重复请求（403 / code 103），所以退避之后必须换一份新的
        // request_id 与签名。
        let plan = build_plan(&credentials, &body, &model_name)?;
        let mut response = http::open_raw(
            "POST",
            &plan.url,
            site::headers_object(&plan.headers),
            Some(&plan.body),
        )?;

        if !(200..300).contains(&response.status) {
            // 只有失败响应才读体（成功的是 SSE 流，读了就没流了）
            let status = response.status;
            let bytes = response.bytes(1024 * 1024).unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).to_string();
            match errors::http_error(status, &text) {
                Attempt::Auth(error) => {
                    credentials = refresh_after_auth(&mut auth_retries, error)?;
                    continue;
                }
                Attempt::Queued(queued) => {
                    queue_backoff(&mut queue_waits, &queued)?;
                    continue;
                }
                Attempt::Fatal(error) => return Err(error),
            }
        }

        let mut translator = Translator::new(response_id(), plan.model_name.clone(), plan.thinking);
        match prefetch(&mut response) {
            Ok(Prefetch::Content(prefetched)) => {
                // 首帧是内容：此刻才能报头（业务错误已经在预读里拦下）
                sdk::stream_head(200)?;
                return drive(&mut response, &mut translator, prefetched);
            }
            Ok(Prefetch::Done) => {
                sdk::stream_head(200)?;
                return finish_stream(&mut translator);
            }
            // 首帧就是排队信封（HTTP 200 + statusCodeValue 403）：还没报头，
            // 退避重发（和 HTTP 层的排队走同一条路）
            Ok(Prefetch::Failed(Attempt::Queued(queued))) => {
                queue_backoff(&mut queue_waits, &queued)?;
                continue;
            }
            Ok(Prefetch::Failed(Attempt::Auth(error))) => {
                credentials = refresh_after_auth(&mut auth_retries, error)?;
                continue;
            }
            Ok(Prefetch::Failed(Attempt::Fatal(error))) => return Err(error),
            Err(error) => return Err(error),
        }
    }
}

/// 流式续传：预读帧先补发，再边读边发，收尾发 finish / usage / `[DONE]`。
///
/// 错误处理分两段：
///   - **首帧之前**的错误已在预读阶段转成 `Err` 交回编排层换号，走不到这里；
///   - 流开始后的中途错误：客户端可能已收到部分内容（HTTP 头早已发出），
///     换号不再可能 —— 只能补「错误帧 + [DONE]」收尾。
fn drive(
    response: &mut http::Response,
    translator: &mut Translator,
    prefetched: Vec<Value>,
) -> Result<()> {
    for chunk in &prefetched {
        emit_chunk(translator, chunk)?;
    }
    if let Err(error) = pump(response, translator) {
        // 失败前先把拆解器缓冲里已确定的内容冲刷出去（用户已经看到的部分不丢）
        for delta in translator.finish() {
            let frame = translator.chunk_frame(delta_json(&delta), None);
            send_frame(&frame)?;
        }
        if translator.usage.is_some() {
            let usage = translator.usage_frame();
            send_frame(&usage)?;
        }
        sdk::stream_event(&errors::error_event(&error))?;
        sdk::stream_bytes(stream::sse_done().as_bytes())?;
        return Err(error);
    }
    finish_stream(translator)
}

/// 把上游剩余字节拉到底：正常结束返回 `Ok`，中途出错返回 `Err`。
///
/// 传输中断、解码失败、信封业务错误都在这里落成 `Err` —— 由 `drive` 统一补
/// 「错误帧 + [DONE]」再交回编排层。
fn pump(response: &mut http::Response, translator: &mut Translator) -> Result<()> {
    let mut decoder = SseDecoder::default();
    loop {
        let bytes = match response.read() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break,
            Err(error) => {
                return Err(Error::http(502, format!("上游流式传输中断: {}", error.message)))
            }
        };
        if handle_events(&decoder.push(&bytes)?, translator)? {
            return Ok(());
        }
    }
    // 上游没以空行收尾时，把解码器里剩的那条事件补出来（否则最后一条会丢）
    let tail = decoder.push(b"\n\n")?;
    handle_events(&tail, translator)?;
    Ok(())
}

/// 处理一批已解码的事件；返回 `true` = 见到 `[DONE]`（流正常结束）。
fn handle_events(events: &[String], translator: &mut Translator) -> Result<bool> {
    for event in events {
        match stream::parse_sse_line(event) {
            stream::SseEvent::Skip => {}
            stream::SseEvent::Done => return Ok(true),
            stream::SseEvent::Error { status, kind, raw, message, pricing_url, queue } => {
                // 上游的业务错误（HTTP 200 里的信封错误）：流已开始，换号与
                // 排队退避都不再可能，只能把错误随流下发给客户端
                return Err(errors::business_error(
                    status,
                    kind,
                    &raw,
                    &message,
                    pricing_url.as_deref(),
                    queue,
                )
                .into_error());
            }
            stream::SseEvent::Chunk(chunk) => emit_chunk(translator, &chunk)?,
        }
    }
    Ok(false)
}

/// 正常收尾：冲刷拆解器 → finish 帧 → usage 帧（有则发）→ `[DONE]`。
fn finish_stream(translator: &mut Translator) -> Result<()> {
    for delta in translator.finish() {
        let frame = translator.chunk_frame(delta_json(&delta), None);
        send_frame(&frame)?;
    }
    let finish = translator.final_finish();
    let frame = translator.chunk_frame(json!({}), Some(&finish));
    send_frame(&frame)?;
    if translator.usage.is_some() {
        let usage = translator.usage_frame();
        send_frame(&usage)?;
    }
    sdk::stream_bytes(stream::sse_done().as_bytes())
}
