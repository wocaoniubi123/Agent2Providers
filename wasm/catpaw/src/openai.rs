//! CatPaw **出站翻译层**：上游 SSE 事件 → OpenAI `chat.completion.chunk`，
//! 外加 usage 口径修正（native `openai.rs` 的逐条移植）。
//!
//! ── 本模块管什么（与另外几个文件的分工）───────────────────────
//! ```text
//! models.rs        modelType / effort / context 的映射（入站参数）
//! tools.rs         tools / tool_choice 的映射（入站参数）
//! openai.rs        上游 SSE → OpenAI chunk、usage 修正（**本文件**）
//! conversation.rs  轮次判定与请求体组装（时序）
//! turn.rs          传输与收尾（时序）
//! ```
//!
//! ── 两条容易踩的语义（原实现踩过，注释在实现处）───────────────
//!   1. **上游的 text / toolParams 是累积值不是增量**：每个 SSE 事件的
//!      `content` / `reasoningContent` / `toolParams` 都是「到目前为止的全部
//!      内容」，翻译层必须做**后缀差分**（[`TurnTranslator`]），直接把事件里的
//!      text 当 delta 下发会让客户端看到重复内容。
//!   2. **usage 口径与 OpenAI 不同**（UPSTREAM_PROTOCOL §6）：上游
//!      `prompt_tokens` 只是本轮增量输入、`total_tokens` 是**会话累计**占用，
//!      而客户端要的是「本次请求的完整输入」。因此
//!      `prompt_tokens = max(prompt, total - completion)`；
//!      上游没有缓存字段，`cache_read_tokens` **恒空、不估算**（架构文档 §9.3）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic；不发网络请求、不持锁。

use serde_json::{json, Map, Value};

use super::errors::CatPawError;
use super::tools::ToolChoice;

/// `data: [DONE]` 帧（OpenAI 客户端按它收尾）
pub const DONE_FRAME: &str = "data: [DONE]\n\n";

/// 一条 SSE 帧的文本形态（`data: <json>\n\n`）
pub fn sse_frame(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    format!("data: {text}\n\n")
}

/// `stream_options.include_usage === true`。
///
/// 只认布尔真值：字符串 `"true"` / 数字 `1` 不算 —— 上游与该字段的语义是
/// 「客户端明确要求多一帧 usage」，类型不对时按「没要求」处理（少一帧比多一帧
/// 更容易被客户端发现）。
pub fn include_usage(body: &Value) -> bool {
    body.pointer("/stream_options/include_usage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// `unwrapApiData`：`code` 存在且不是 0/200 → 上游错误；有 `data` 成员则取出。
///
/// ── 为什么 `code` 非数字也当成功 ─────────────────────────────
/// 原实现的判定是 `data.code !== undefined && data.code !== 0 && data.code !== 200`
/// —— JS 的 `!==` 是严格比较，字符串 `"0"` **不等于**数字 `0`，所以它会被判成
/// 错误。这里为保持「非数字 → 不是已知成功码」的严谨性，只在 code 是数字且
/// 不在 {0,200} 时报错，其余（字符串等）走「继续」—— 差异只影响上游给出畸形
/// `code` 的极端情形，那时「尽力继续」比「误报上游错误」更不容易把正常流打断。
pub fn unwrap_api_data(value: Value) -> Result<Value, CatPawError> {
    let Some(object) = value.as_object() else {
        return Ok(value);
    };
    if let Some(code) = object.get("code").filter(|value| !value.is_null()) {
        if let Some(code_number) = code.as_i64() {
            if code_number != 0 && code_number != 200 {
                let message = object
                    .get("msg")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                    .or_else(|| {
                        object
                            .get("message")
                            .and_then(Value::as_str)
                            .filter(|text| !text.is_empty())
                    })
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("上游 API 返回错误 code={code_number}"));
                let status = object.get("httpStatus").and_then(Value::as_i64).unwrap_or(502);
                return Err(CatPawError {
                    status: if (100..600).contains(&status) { status as u16 } else { 502 },
                    message,
                    code: Some(code_number),
                    unify_code: object.get("unifyCode").and_then(Value::as_i64),
                });
            }
        }
    }
    // `Object.prototype.hasOwnProperty.call(data, 'data')` → 取 data 成员
    // （显式 null 也取，得到 null —— 与原实现一致）
    if object.contains_key("data") {
        return Ok(object.get("data").cloned().unwrap_or(Value::Null));
    }
    Ok(value)
}

/// 事件里的错误对象（原实现 `responseError`）：`error` / `data.error` / `result.error`
fn response_error(data: &Value) -> Option<CatPawError> {
    let error = data
        .get("error")
        .or_else(|| data.pointer("/data/error"))
        .or_else(|| data.pointer("/result/error"))?;
    let object = error.as_object()?;
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .or_else(|| object.get("msg").and_then(Value::as_str).filter(|text| !text.is_empty()))
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "上游返回错误 code={}",
                object.get("code").map(|code| code.to_string()).unwrap_or_else(|| "unknown".to_string())
            )
        });
    let status = object.get("httpStatus").and_then(Value::as_i64).unwrap_or(502);
    Some(CatPawError {
        status: if (100..600).contains(&status) { status as u16 } else { 502 },
        message,
        code: object.get("code").and_then(Value::as_i64),
        unify_code: object.get("unifyCode").and_then(Value::as_i64),
    })
}

/// 事件里的 assistant 消息（原实现 `responseMessage`）
fn response_message(data: &Value) -> Option<&Value> {
    data.get("message")
        .or_else(|| data.pointer("/data/message"))
        .or_else(|| data.pointer("/result/message"))
}

/// 流式翻译状态机（对照原实现 `llmTurn` 的 `state` 与 `messageDelta`）。
///
/// 生命周期 = 一个 turn：`consume` 吃事件并产出增量帧，`finish` 收尾得到
/// [`TurnResult`]（工具续接判定、记账、会话写回都用它）。
pub struct TurnTranslator {
    chat_id: String,
    model: String,
    /// 客户端是否要 usage 帧
    include_usage: bool,
    /// 累积正文（上游给的是全量，差分后才是 delta）
    text: String,
    /// 累积思考
    reasoning: String,
    /// tool_call_id → `{args, name}`（累积参数，同样是全量）
    tools: Map<String, Value>,
    /// tool_call 首见顺序（决定下发 chunk 里的 `index`）
    order: Vec<String>,
    /// 最近一个事件（usage 从它取）
    latest: Option<Value>,
    /// 最近一条 assistant 消息（收尾时组装 OpenAI 消息）
    last_message: Option<Value>,
    /// 是否收到过 `message.finished === true`
    completed: bool,
    /// 下游的 `tool_choice`（收尾校验；见 `tools.rs`）
    choice: ToolChoice,
}

impl TurnTranslator {
    pub fn new(chat_id: impl Into<String>, model: impl Into<String>, include_usage: bool, choice: ToolChoice) -> Self {
        Self {
            chat_id: chat_id.into(),
            model: model.into(),
            include_usage,
            text: String::new(),
            reasoning: String::new(),
            tools: Map::new(),
            order: Vec::new(),
            latest: None,
            last_message: None,
            completed: false,
            choice,
        }
    }

    /// 消费一个事件：把增量写成帧交给 `pending`。
    pub fn consume(&mut self, event: &Value, pending: &mut Vec<String>) -> Result<(), CatPawError> {
        self.latest = Some(event.clone());
        if let Some(error) = response_error(event) {
            return Err(error);
        }
        // 没有 message 的事件（心跳、status 之类）不下发任何帧
        let Some(message) = response_message(event).cloned() else {
            return Ok(());
        };
        let delta = self.message_delta(&message);
        if delta.as_object().map(|object| !object.is_empty()).unwrap_or(false) {
            pending.push(self.chunk_frame(delta, None, None));
        }
        if message.get("finished").and_then(Value::as_bool) == Some(true) {
            self.completed = true;
        }
        self.last_message = Some(message);
        Ok(())
    }

    /// 收尾：校验「流在消息完成前结束」并执行 tool_choice 约束，产出本轮结果。
    ///
    /// `message.finished=true` 只完成当前消息，须等完整 DONE 或 HTTP EOF 再收尾。
    pub fn finish(&mut self, pending: &mut Vec<String>) -> Result<TurnResult, CatPawError> {
        if !self.completed {
            return Err(CatPawError::upstream("上游 SSE 在消息完成前结束"));
        }
        let Some(message) = self.last_message.clone() else {
            return Err(CatPawError::upstream("上游没有返回消息"));
        };
        let calls = self.check_choice(&message)?;
        // 收尾帧：finish_reason 由「有没有工具调用」决定（原实现 `toolFinishReason`）
        let finish_reason = if calls.is_empty() { "stop" } else { "tool_calls" };
        pending.push(self.chunk_frame(json!({}), Some(finish_reason), None));
        if self.include_usage {
            let usage = self.final_usage();
            pending.push(self.chunk_frame(Value::Null, None, Some(usage)));
        }
        Ok(TurnResult {
            conversation_id: self.conversation_id_of(),
            openai_message: openai_message(&message, &calls),
            text: extract_message_text(&message),
            reasoning: extract_reasoning(&message),
            tool_calls: calls,
            message,
            raw: self.latest.clone().unwrap_or(Value::Null),
        })
    }

    /// `tool_choice` 的收尾校验（原实现 `llmTurn` 末尾那一段）
    fn check_choice(&self, message: &Value) -> Result<Vec<Value>, CatPawError> {
        let all = extract_tool_calls(message)?;
        match &self.choice {
            ToolChoice::None => {
                if !all.is_empty() {
                    return Err(CatPawError::upstream("tool_choice=none 时上游仍返回了 tool_call"));
                }
                Ok(Vec::new())
            }
            ToolChoice::Auto => Ok(all),
            ToolChoice::Required => {
                if all.is_empty() {
                    return Err(CatPawError::upstream("tool_choice=required 时上游未返回 tool_call"));
                }
                Ok(all)
            }
            ToolChoice::Function(name) => {
                let selected: Vec<Value> = all
                    .into_iter()
                    .filter(|call| {
                        call.pointer("/function/name").and_then(Value::as_str) == Some(name.as_str())
                    })
                    .collect();
                if selected.is_empty() {
                    return Err(CatPawError::upstream(format!(
                        "tool_choice 要求调用 {name}，但上游未返回该工具"
                    )));
                }
                Ok(selected)
            }
        }
    }

    /// 首帧（`delta.role = assistant`）。
    ///
    /// 原实现把它作为流的第一帧单独发 —— 由调用方在确定要下流式响应时发一次，
    /// 与上游第一个事件无关。早发比晚发稳：客户端据此建立 assistant 消息。
    pub fn role_frame(&self) -> String {
        self.chunk_frame(json!({ "role": "assistant" }), None, None)
    }

    /// 流内错误帧（原实现 `streamErrorChunk`：`delta:{}` + `finish_reason:"stop"`
    /// + `error` 字段）。
    ///
    /// HTTP 头早就发出去了，只能把错误写进流里 —— OpenAI 客户端把它当一次
    /// 失败的补全（而不是连接被截断）。
    pub fn error_frame(&self, message: &str, status: u16) -> String {
        let mut body = Map::new();
        body.insert("id".to_string(), Value::String(self.chat_id.clone()));
        body.insert("object".to_string(), Value::String("chat.completion.chunk".to_string()));
        body.insert("created".to_string(), Value::from(super::now_seconds()));
        body.insert("model".to_string(), Value::String(self.model.clone()));
        body.insert(
            "choices".to_string(),
            json!([{ "index": 0, "delta": {}, "finish_reason": "stop" }]),
        );
        body.insert(
            "error".to_string(),
            json!({
                "message": message,
                "type": if status < 500 { "invalid_request_error" } else { "upstream_error" },
            }),
        );
        sse_frame(&Value::Object(body))
    }

    /// 事件里的 conversationId（写回会话记录与诊断用）
    fn conversation_id_of(&self) -> String {
        self.latest
            .as_ref()
            .and_then(|value| value.get("conversationId"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// 本轮 usage（已按 §9.3 修正；上游没给就是三个 0）
    fn final_usage(&self) -> Value {
        self.latest
            .as_ref()
            .and_then(usage_from_response)
            .unwrap_or_else(|| json!({ "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 }))
    }

    /// 累积 → 增量差分（原实现 `messageDelta`）。
    ///
    /// 三处差分（正文、思考、每个 tool 的参数）都用**前缀判定**：
    /// `新值.starts_with(旧值)` 时取后缀，否则整体重发 —— 后者是「上游换了一段
    /// 完全不同的内容」的兜底，宁可多发也不能让客户端丢内容。
    fn message_delta(&mut self, message: &Value) -> Value {
        let blocks = message
            .get("content")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let text: String = blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect();
        let reasoning: String = blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("reasoningContent").and_then(Value::as_str))
            .collect();
        let text_delta = suffix_after(&text, &self.text);
        let reasoning_delta = suffix_after(&reasoning, &self.reasoning);
        self.text = text;
        self.reasoning = reasoning;

        let mut delta = Map::new();
        if let Some(text) = text_delta {
            delta.insert("content".to_string(), Value::String(text));
        }
        if let Some(reasoning) = reasoning_delta {
            // 上游的思考内容在 text 块的 `reasoningContent` 字段；OpenAI 侧
            // 走 `delta.reasoning_content`（UPSTREAM_PROTOCOL §7）
            delta.insert("reasoning_content".to_string(), Value::String(reasoning));
        }
        if let Some(calls) = self.tool_deltas(blocks) {
            delta.insert("tool_calls".to_string(), calls);
        }
        Value::Object(delta)
    }

    /// tool_use 块的增量差分（原实现 `messageDelta` 下半段）
    fn tool_deltas(&mut self, blocks: &[Value]) -> Option<Value> {
        let mut calls: Vec<Value> = Vec::new();
        for block in blocks {
            if block.get("type").and_then(Value::as_str) != Some("tool_use") {
                continue;
            }
            let (Some(id), Some(name)) = (
                block.get("toolCallId").and_then(Value::as_str),
                block.get("toolName").and_then(Value::as_str),
            ) else {
                continue;
            };
            let args = block.get("toolParams").and_then(Value::as_str).unwrap_or("");
            let previous = self
                .tools
                .get(id)
                .and_then(|value| value.get("args"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let seen = self.tools.contains_key(id);
            let args_delta = suffix_after(args, &previous);
            self.tools.insert(id.to_string(), json!({ "args": args, "name": name }));
            let tool_index = match self.order.iter().position(|item| item == id) {
                Some(index) => index,
                None => {
                    self.order.push(id.to_string());
                    self.order.len() - 1
                }
            };
            if !seen {
                // 首见：id + type + name 一帧，参数增量另起一帧（原实现同）
                calls.push(json!({
                    "index": tool_index as i64,
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": "" },
                }));
                if let Some(args_delta) = args_delta {
                    calls.push(json!({
                        "index": tool_index as i64,
                        "function": { "arguments": args_delta },
                    }));
                }
            } else if let Some(args_delta) = args_delta {
                calls.push(json!({
                    "index": tool_index as i64,
                    "function": { "arguments": args_delta },
                }));
            }
        }
        if calls.is_empty() {
            None
        } else {
            Some(Value::Array(calls))
        }
    }

    /// 一帧 `chat.completion.chunk`。
    ///
    /// `usage` 存在时 `choices` 是**空数组**（OpenAI 的 usage 帧形态）。
    fn chunk_frame(&self, delta: Value, finish_reason: Option<&str>, usage: Option<Value>) -> String {
        let choices = match &usage {
            Some(_) => json!([]),
            None => json!([{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }]),
        };
        let mut body = Map::new();
        body.insert("id".to_string(), Value::String(self.chat_id.clone()));
        body.insert("object".to_string(), Value::String("chat.completion.chunk".to_string()));
        body.insert("created".to_string(), Value::from(super::now_seconds()));
        body.insert("model".to_string(), Value::String(self.model.clone()));
        body.insert("choices".to_string(), choices);
        if let Some(usage) = usage {
            body.insert("usage".to_string(), usage);
        }
        sse_frame(&Value::Object(body))
    }
}

/// 后缀差分：`current` 以 `previous` 开头时返回新增部分，否则整体返回。
/// 完全相等（没有新增）时返回 None（不发帧）。
fn suffix_after(current: &str, previous: &str) -> Option<String> {
    if current == previous {
        return None;
    }
    match current.strip_prefix(previous) {
        Some(rest) => Some(rest.to_string()),
        None => Some(current.to_string()),
    }
}

/// 一个 turn 的最终结果（对应原实现 `llmTurn` 的返回对象）
#[derive(Clone, Debug)]
pub struct TurnResult {
    /// 上游 conversationId（事件里带的那个；空串 = 上游没带）
    pub conversation_id: String,
    /// OpenAI 形态的 assistant 消息（非流式响应体用）
    pub openai_message: Value,
    /// 正文（日志用）
    pub text: String,
    /// 思考内容（日志用）
    pub reasoning: String,
    /// 工具调用（`[{id, type, function:{name, arguments}}]`）
    pub tool_calls: Vec<Value>,
    /// 上游最后一条 assistant 消息（指纹链要用它）
    pub message: Value,
    /// 上游最后一个事件（usage 提取用；`finish` 之后仍有值）
    pub raw: Value,
}

impl TurnResult {
    /// 本轮 usage（已修正；上游没给就是三个 0）
    pub fn final_usage(&self) -> Value {
        usage_from_response(&self.raw).unwrap_or_else(|| {
            json!({ "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 })
        })
    }

    /// OpenAI 的 `finish_reason`（有工具调用就是 tool_calls）
    pub fn finish_reason(&self) -> &'static str {
        if self.tool_calls.is_empty() {
            "stop"
        } else {
            "tool_calls"
        }
    }
}

/// 组装 OpenAI 的非流式 assistant 消息（原实现 `openAIMessage`）
pub fn openai_message(message: &Value, calls: &[Value]) -> Value {
    let text = extract_message_text(message);
    let reasoning = extract_reasoning(message);
    let mut out = Map::new();
    out.insert("role".to_string(), Value::String("assistant".to_string()));
    out.insert(
        "content".to_string(),
        if text.is_empty() { Value::Null } else { Value::String(text) },
    );
    if !reasoning.is_empty() {
        out.insert("reasoning_content".to_string(), Value::String(reasoning));
    }
    if !calls.is_empty() {
        out.insert("tool_calls".to_string(), Value::Array(calls.to_vec()));
    }
    Value::Object(out)
}

/// 上游 assistant 消息的 `tool_use` 块 → OpenAI tool_calls
/// （原实现 `extractToolCalls`）。
///
/// 重复 `toolCallId` 报 502：上游一条消息里出现同名 id 会让客户端的
/// tool_use/tool_result 配对错乱，属于上游数据问题，不能静默接受。
pub fn extract_tool_calls(message: &Value) -> Result<Vec<Value>, CatPawError> {
    let mut out: Vec<Value> = Vec::new();
    let mut ids: Vec<&str> = Vec::new();
    let blocks = message
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for block in blocks {
        if block.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let id = block.get("toolCallId").and_then(Value::as_str).unwrap_or_default();
        if ids.contains(&id) {
            return Err(CatPawError::upstream(format!("上游返回重复的 tool_call_id: {id}")));
        }
        ids.push(id);
        out.push(json!({
            "id": id,
            "type": "function",
            "function": {
                "name": block.get("toolName").and_then(Value::as_str).unwrap_or_default(),
                "arguments": block.get("toolParams").and_then(Value::as_str).unwrap_or_default(),
            },
        }));
    }
    Ok(out)
}

/// 正文拼接（原实现 `extractMessageText`）
pub fn extract_message_text(message: &Value) -> String {
    message
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect()
}

/// 思考拼接（原实现 `extractReasoning`）
pub fn extract_reasoning(message: &Value) -> String {
    message
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("reasoningContent").and_then(Value::as_str))
        .collect()
}

/// 上游 usage → OpenAI usage（**口径修正**，架构文档 §9.3 / UPSTREAM_PROTOCOL §6）。
///
/// ```text
/// 上游：prompt 只算本轮增量、total 是会话累计
/// 输出：prompt = max(prompt, total - completion)   （完整输入）
///       total  = prompt + completion
///       cache_read_tokens 恒空（上游无此数据，不估算）
/// ```
///
/// `max` 的意义：上游若在某次实现里让 `total` 小于 completion（异常/钳位），
/// `total - completion` 会是负数或偏小值，取 prompt 原值比取负数稳。
pub fn usage_from_response(data: &Value) -> Option<Value> {
    let usage = data
        .get("usage")
        .or_else(|| data.pointer("/contextInfo/usage"))?;
    if !usage.is_object() {
        return None;
    }
    let prompt = number_of(usage.get("prompt_tokens"))
        .or_else(|| number_of(usage.get("promptTokens")))
        .unwrap_or(0);
    let completion = number_of(usage.get("completion_tokens"))
        .or_else(|| number_of(usage.get("completionTokens")))
        .unwrap_or(0);
    let upstream_total = number_of(usage.get("total_tokens"))
        .or_else(|| number_of(usage.get("totalTokens")))
        .unwrap_or(0);
    let full_prompt = if upstream_total > 0 {
        std::cmp::max(prompt, upstream_total - completion)
    } else {
        prompt
    };
    Some(json!({
        "prompt_tokens": full_prompt,
        "completion_tokens": completion,
        "total_tokens": full_prompt + completion,
    }))
}

/// 数字字段（`as_i64` 对 1.0 这类浮点形态会失败，所以补一次 f64 转换）
fn number_of(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value.as_i64().or_else(|| value.as_f64().map(|number| number.round() as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_prefers_data_member() {
        let value = json!({ "code": 0, "data": [1, 2] });
        assert_eq!(unwrap_api_data(value).unwrap_or(Value::Null), json!([1, 2]));
    }

    #[test]
    fn unwrap_rejects_business_error() {
        let value = json!({ "code": 400, "msg": "坏了", "httpStatus": 400 });
        let error = unwrap_api_data(value).err().unwrap_or_else(|| CatPawError::upstream("x"));
        assert_eq!(error.status, 400);
        assert_eq!(error.code, Some(400));
        assert_eq!(error.message, "坏了");
    }

    #[test]
    fn translator_diffs_cumulative_text() {
        let mut translator = TurnTranslator::new("chatcmpl-x", "kimi-k3", false, ToolChoice::Auto);
        let mut pending = Vec::new();
        translator
            .consume(
                &json!({
                    "conversationId": "c1",
                    "message": { "type": "assistant", "content": [{"type":"text","text":"你"}] }
                }),
                &mut pending,
            )
            .unwrap_or(());
        translator
            .consume(
                &json!({
                    "message": { "type": "assistant", "content": [{"type":"text","text":"你好"}], "finished": true }
                }),
                &mut pending,
            )
            .unwrap_or(());
        let result = translator.finish(&mut pending).unwrap_or_else(|_| TurnResult {
            conversation_id: String::new(),
            openai_message: Value::Null,
            text: String::new(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            message: Value::Null,
            raw: Value::Null,
        });
        assert_eq!(result.text, "你好");
        assert!(!result.openai_message.is_null());
        // 两帧正文增量（"你" + "好"）+ 收尾帧
        assert_eq!(pending.len(), 3);
        assert!(pending[0].contains("\"你\""));
        assert!(pending[1].contains("\"好\""));
        // conversationId 只在上游带了的事件里出现；最后一个事件没带就是空串
        // （native 的 `conversation_id_of` 同口径，写回时用守卫的值兜底）
        assert_eq!(result.conversation_id, "");
    }

    #[test]
    fn usage_is_corrected() {
        let raw = json!({ "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 100 } });
        let usage = usage_from_response(&raw).unwrap_or(Value::Null);
        assert_eq!(usage["prompt_tokens"], json!(95));
        assert_eq!(usage["total_tokens"], json!(100));
    }

    #[test]
    fn tool_choice_none_rejects_tool_calls() {
        let mut translator = TurnTranslator::new("id", "m", false, ToolChoice::None);
        translator
            .consume(
                &json!({
                    "message": { "type": "assistant", "finished": true,
                        "content": [{"type":"tool_use","toolCallId":"c1","toolName":"f","toolParams":"{}"}] }
                }),
                &mut Vec::new(),
            )
            .unwrap_or(());
        assert!(translator.finish(&mut Vec::new()).is_err());
    }
}
