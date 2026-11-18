//! OrcaTerm 对话：建会话 → assistant SSE → OpenAI 帧。
//!
//! ── 上游是两步（2026-10-16 实测，curl 直连复现）──────────────
//!   1. `POST {LIGHTAI}/assistant/conversation` → `cid-<uuid>-orcaterm`；
//!   2. `POST {LIGHTAI}/assistant/chat?name=orcaterm&mode=0&csrfCode=&sseresume=true`
//!      → SSE：`data: {content|reasoningContent}` … `data: [DONE]`。
//! SSE 帧字段：`content` / `reasoningContent` / `reasoning`（true = 思考增量）
//! / `type:"ai"` / `code:0`；错误帧**不是 JSON**：`data: [ERROR]: [LLM_ERROR]: …`。
//!
//! ── 多轮：历史拍平为单条输入（与 KukuAI 同一口径）────────────
//! 上游按 conversationId 在服务端留存历史，但输入通道只有一条 `start`
//! 消息，而 OpenAI 客户端每轮自带全量 messages —— 因此按**请求内会话**
//! 处理：每个请求新建会话，历史拍平进输入文本。无注册表、无指纹链、
//! 重启即忘。
//!
//! ── 信封解包（本家独有的下游形态）───────────────────────────
//! 上游是 agent 协议：模型正文倾向输出 ACP 动作信封（```json 围栏或裸
//! JSON，形如 `{"action":"completion","taskCompletion":"…"}`），桌面端 UI
//! 自己解析它 —— 但 OpenAI 客户端要的是纯文本。因此第一个正文增量到达时
//! 判定形态（``` / `{` 开头 → 缓冲模式），结束时解包；解不出就原样透传。
//!
//! ── 401 自愈 ───────────────────────────────────────────────
//! 建会话 / 对话拿到 401 时强制续期一次并重发同一步（只重试一次）。
//!
//! ── wasm 侧的两条边界（本文件最要紧的一段）──────────────────
//! 宿主把「插件返回什么」直接翻成客户端看到的东西，所以两条边界必须分开：
//!
//!   * **尚未下发任何字节**（还没 `stream_head`）就出错 → 返回带状态码的
//!     `Error`。网关据此还能换账号 / 换凭证重试；把这种错误写进流里，
//!     客户端就只会看到一个「成功但立刻断掉」的空回答。
//!   * **已经下发内容**之后再出错 → 只能在流里写一条 `{"error":…}` 帧再
//!     `[DONE]`，并把这一轮按「已如实告知」正常结束（native 的
//!     `finish_with_error` 是同一处置）。此时再返回 `Err` 只会让网关对着一个
//!     已经发出的 200 重复上报。
//!
//! 因此本文件把「帧」与「下发」拆开：`OrcaStream` 只产出帧，`Output` 决定
//! 什么时候发 head、以及错误帧该不该升级成 `Err`。

use agent2api_wasm_sdk::{self as sdk, http, json, Error, Result, Value};

use super::{account, codec, errors, models, upstream};

/// 一次 401 自愈重试的上限（每步各一次，不循环）。
const AUTH_RETRY: usize = 1;

/// `conversation` 的入口。
pub fn run(params: &Value) -> Result<()> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "OrcaTerm 请求体必须是 JSON 对象"));
    }
    let record = account::record()?;
    let mut credentials = account::snapshot(&record)?;
    // 临期主动续期（结果回写账号记录；账号锁保证并发只刷一次）
    credentials = account::renew(&credentials, false)?;

    let client_model = body["model"].as_str().unwrap_or("").to_string();
    let model = models::resolve_model(&client_model);
    let prompt = build_prompt(body.get("messages"));

    // ── 建会话（401 自愈：强制续期后重试一次）────────────────
    let conversation = retry_after_renew(&mut credentials, create_conversation)?;
    // 会话可能已在上一步建出（无妨：换 token 后重开流，conversationId 仍有效）
    let mut response = retry_after_renew(&mut credentials, |credentials| {
        open_chat_stream(credentials, &conversation, &model, &prompt)
    })?;

    let mut output = Output::default();
    let mut stream = OrcaStream::new(&client_model);
    loop {
        match response.read() {
            Ok(Some(chunk)) => {
                output.push(stream.feed(&chunk))?;
                if stream.saw_end {
                    return Ok(());
                }
            }
            Ok(None) => break,
            Err(error) => {
                // 流断在半路：已下发则如实写进流里；还没下发就升级成带状态的错误
                let frames = stream
                    .finish_with_error(&format!("OrcaTerm 上游流式传输中断：{}", error.message));
                return output.push(frames);
            }
        }
    }
    output.push(stream.finish())
}

/// 这一步失败时：是登录态失效就强制续期一次再试，其余错误原样抛出。
fn retry_after_renew<T>(
    credentials: &mut account::Credentials,
    mut action: impl FnMut(&account::Credentials) -> Result<T>,
) -> Result<T> {
    let mut attempt = 0;
    loop {
        match action(credentials) {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt >= AUTH_RETRY || !upstream::is_auth(&error) {
                    return Err(error);
                }
                attempt += 1;
                match account::renew(credentials, true) {
                    Ok(next) => *credentials = next,
                    // 续期也失败：把**原来的**错误交出去（它才是用户该看到的）
                    Err(_) => return Err(error),
                }
            }
        }
    }
}

/// 建会话 → `cid-<uuid>-orcaterm`。
fn create_conversation(credentials: &account::Credentials) -> Result<String> {
    let uuid = codec::uuid_v4();
    let url = format!("{}/assistant/conversation", upstream::LIGHTAI_BASE);
    let body = json!({
        "id": uuid,
        "title": "新对话",
        "ts": sdk::now(),
        "customTitle": "",
        "aiTitle": "",
        "tags": ["orcaterm"],
    });
    let headers = upstream::lightai_headers(credentials, &codec::uuid_v4());
    let value = upstream::post_json(&url, &headers, &body)?;
    let code = value["code"].as_i64().unwrap_or(-1);
    if code != 0 {
        let message = value["message"].as_str().unwrap_or("未知错误");
        if is_credential_rejection(code, message) {
            return Err(Error::http(
                401,
                format!("OrcaTerm 登录态已失效（code={code}：{message}）"),
            ));
        }
        return Err(Error::http(
            502,
            format!("OrcaTerm 建会话失败（code={code}：{message}）"),
        ));
    }
    Ok(format!("cid-{uuid}-orcaterm"))
}

/// 上游用 HTTP 200 包装凭证失效，须与普通业务错误区分。
fn is_credential_rejection(code: i64, message: &str) -> bool {
    if code == 0 {
        return false;
    }
    let text = message.to_ascii_lowercase();
    text.contains("token")
        && (text.contains("invalid")
            || text.contains("expired")
            || text.contains("失效")
            || text.contains("过期"))
}

/// 打开对话 SSE 流。
fn open_chat_stream(
    credentials: &account::Credentials,
    conversation_id: &str,
    model: &str,
    prompt: &str,
) -> Result<http::Response> {
    let seq_id = codec::uuid_v4();
    let url = format!("{}/assistant/chat?{}", upstream::LIGHTAI_BASE, upstream::ASSISTANT_QUERY);
    let body = json!({
        "conversationId": conversation_id,
        "user": {
            "id": credentials.user_id,
            "setting": {
                "model": model,
                "mcpServers": [],
                "uiServers": [],
                "tools": [],
                "approvedTools": [],
                "approvedMCPTools": [],
                "enableAutoSubtaskExecution": false,
                "env": [],
                // 上游是 agent 协议；网关不做工具注入（纯文本直通）
                "hideToolMessage": true,
                "language": "zh",
            },
        },
        "input": {
            "type": "start",
            "input": prompt,
            "id": seq_id,
            "emphasisPrompt": "",
            "files": [],
        },
        "stream": true,
    });
    let headers = upstream::lightai_headers(credentials, &seq_id);
    upstream::sse_post(&url, &headers, &body, "OrcaTerm 对话")
}

/// 把 OpenAI messages 压成单条输入。
///
/// 单条消息原样直通（最常见的单轮用法不引入任何包装）；多轮时把历史拍平成
/// 带角色前缀的记录，让上游把整段当作对话上下文来回应最后一条用户消息。
pub fn build_prompt(messages: Option<&Value>) -> String {
    let Some(Value::Array(items)) = messages else {
        return "你好".to_string();
    };
    let usable: Vec<&Value> = items
        .iter()
        .filter(|message| content_text(message).map(|text| !text.trim().is_empty()).unwrap_or(false))
        .collect();
    if usable.is_empty() {
        return "你好".to_string();
    }
    if usable.len() == 1 {
        return content_text(usable[0]).unwrap_or_else(|| "你好".to_string());
    }
    let mut lines: Vec<String> = Vec::new();
    lines.push("[以下是本轮之前的对话记录，供你了解上下文]".to_string());
    for message in usable {
        let role = message["role"].as_str().unwrap_or("user");
        let Some(text) = content_text(message) else { continue };
        match role {
            "system" => lines.push(format!("[系统指令] {text}")),
            "assistant" => lines.push(format!("[助手] {text}")),
            _ => lines.push(format!("[用户] {text}")),
        }
    }
    lines.push("[对话记录结束；请回应其中最后一条用户消息]".to_string());
    lines.join("\n\n")
}

/// 取一条消息的可读文本（content 字符串或 text 类型部件数组）。
fn content_text(message: &Value) -> Option<String> {
    let content = message.get("content")?;
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let mut out: Vec<String> = Vec::new();
            for part in parts {
                if let Some(text) = part["text"].as_str() {
                    out.push(text.to_string());
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        _ => None,
    }
}

// ─── SSE 解析 ────────────────────────────────────────────────

/// 一条已解析的上游事件。
enum OrcaEvent {
    /// 思考增量（`reasoning:true` 帧）
    Reasoning(String),
    /// 正文增量（`reasoning:false` 帧的 `content`）
    Delta(String),
    /// 结束（`data: [DONE]`）
    Done,
    /// 流内错误（`data: [ERROR]: …`；HTTP 恒 200，错误在流里）
    Error(String),
}

/// 完整 SSE 事件解码。
///
/// SDK 自带 `sse::SseDecoder`，但它没有 `finish`（EOF 时缓冲区里没有空行结尾
/// 的那一帧会被静默丢掉）。本家上游的最后一帧经常正好贴在 EOF 上，所以这里
/// 自己留一份带 `finish` 的解码 —— 口径与 native 的 `sse_events::DataEvents`
/// 逐条对齐：只认 `data:` 行、空行分帧、多行 data 用 `\n` 拼接、BOM 在首行剥掉。
#[derive(Default)]
struct DataEvents {
    line: Vec<u8>,
    data: Vec<u8>,
    line_bytes: usize,
    event_bytes: usize,
    skip_lf: bool,
    first_line_seen: bool,
}

impl DataEvents {
    /// 单条事件上限：超过就整条丢弃（本家流里的帧都是短 JSON，走到这里说明上游异常）。
    const MAX_EVENT_BYTES: usize = 1024 * 1024;

    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if byte == b'\r' || byte == b'\n' {
                self.line_end(&mut events);
                self.skip_lf = byte == b'\r';
            } else {
                self.line_bytes = self.line_bytes.saturating_add(1);
                self.event_bytes = self.event_bytes.saturating_add(1);
                if self.event_bytes > Self::MAX_EVENT_BYTES {
                    self.line.clear();
                    self.data.clear();
                } else {
                    self.line.push(byte);
                }
            }
        }
        events
    }

    /// 一行结束：空行 = 一次事件结束（产出）；`data:` 行 = 并入缓冲。
    fn line_end(&mut self, events: &mut Vec<String>) {
        if self.line_bytes == 0 {
            if !self.data.is_empty() {
                let data = std::mem::take(&mut self.data);
                let data = data.strip_suffix(b"\n").unwrap_or(&data);
                if let Ok(text) = std::str::from_utf8(data) {
                    events.push(text.to_string());
                }
            }
            self.event_bytes = 0;
        } else {
            // 首行的 BOM 要剥掉，否则第一个 `data:` 前缀匹配失败、首帧内容整条丢失
            let line: &[u8] = if self.first_line_seen {
                &self.line
            } else {
                self.line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&self.line)
            };
            if let Some(payload) = line.strip_prefix(b"data:") {
                let payload = payload.strip_prefix(b" ").unwrap_or(payload);
                self.data.extend_from_slice(payload);
                self.data.push(b'\n');
            }
        }
        self.first_line_seen = true;
        self.line.clear();
        self.line_bytes = 0;
    }

    /// EOF：把残留读出来。
    ///
    /// native 的纪律照搬：EOF 的最后一段**只用于读出完整 JSON**，未结束的
    /// `[DONE]` 不能当成协议完成 —— 否则被截断的流会被当成正常结束。
    fn finish(&mut self) -> Vec<String> {
        let mut events = Vec::new();
        if self.line_bytes > 0 {
            self.line_end(&mut events);
        }
        if !self.data.is_empty() {
            let data = std::mem::take(&mut self.data);
            let data = data.strip_suffix(b"\n").unwrap_or(&data);
            if !is_done(data) {
                if let Ok(text) = std::str::from_utf8(data) {
                    events.push(text.to_string());
                }
            }
        }
        self.line.clear();
        self.line_bytes = 0;
        self.event_bytes = 0;
        events
    }
}

/// `data: [DONE]`（容忍前后空白）。
fn is_done(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| text.trim() == "[DONE]")
}

fn parse_event(payload: &str) -> Option<OrcaEvent> {
    if is_done(payload.as_bytes()) {
        return Some(OrcaEvent::Done);
    }
    if let Some(error) = payload.trim_start().strip_prefix("[ERROR]:") {
        return Some(OrcaEvent::Error(error.trim().to_string()));
    }
    let parsed: Value = serde_json::from_str(payload).ok()?;
    if parsed["type"].as_str() != Some("ai") {
        return None;
    }
    let reasoning = parsed["reasoning"].as_bool().unwrap_or(false);
    let key = if reasoning { "reasoningContent" } else { "content" };
    let text = parsed[key]
        .as_str()
        .filter(|text| !text.is_empty())?
        .to_string();
    Some(if reasoning { OrcaEvent::Reasoning(text) } else { OrcaEvent::Delta(text) })
}

// ─── OpenAI 帧产出 ──────────────────────────────────────────

/// 一帧出站内容。
enum Frame {
    Chunk(Value),
    /// OpenAI 形态的流内错误帧 —— 整程没有正文、只有上游错误时下发，
    /// 客户端据此显示失败原因而不是空白。
    Error(String),
    Done,
}

impl Frame {
    /// 落到线上的字节（含 `\n\n` 帧尾）。
    fn wire(&self) -> String {
        match self {
            Frame::Chunk(chunk) => format!("data: {chunk}\n\n"),
            Frame::Error(message) => format!("data: {}\n\n", errors::error_event(message)),
            Frame::Done => "data: [DONE]\n\n".to_string(),
        }
    }
}

/// 下发器：负责「什么时候发 head」与「未下发时的错误要不要升级成 Err」。
#[derive(Default)]
struct Output {
    head_sent: bool,
}

impl Output {
    fn push(&mut self, frames: Vec<Frame>) -> Result<()> {
        for frame in frames {
            if let Frame::Error(message) = &frame {
                if !self.head_sent {
                    // 尚未下发任何字节：让网关看到状态码（它据此换账号 / 续期）
                    return Err(Error::http(502, format!("OrcaTerm 上游错误：{message}")));
                }
            }
            self.write(frame)?;
        }
        Ok(())
    }

    fn write(&mut self, frame: Frame) -> Result<()> {
        if !self.head_sent {
            // `stream_head` 固定发 `content-type: text/event-stream`：非流式请求
            // 同样按 SSE 下发，由网关聚合回 JSON（native 的「聚合后一次返回」
            // 分支因此不用迁）。
            sdk::stream_head(200)?;
            self.head_sent = true;
        }
        sdk::stream_bytes(frame.wire().as_bytes())
    }
}

/// 流式转换器：喂上游字节，产出 OpenAI chunk。
struct OrcaStream {
    id: String,
    created: i64,
    model: String,
    scanner: DataEvents,
    saw_end: bool,
    /// 正文缓冲（信封模式下累积；直播模式恒空）
    content: String,
    /// 形态判定结果（第一个正文增量到达时定档）
    buffered: Option<bool>,
    /// 最后一条流内错误（正文为空时它就是这次请求的真实结果）
    last_error: Option<String>,
}

impl OrcaStream {
    fn new(model: &str) -> Self {
        let now = sdk::now();
        Self {
            id: format!("chatcmpl-{}", now.saturating_mul(1000) % 1_000_000_000_000_000),
            created: now / 1000,
            model: model.to_string(),
            scanner: DataEvents::default(),
            saw_end: false,
            content: String::new(),
            buffered: None,
            last_error: None,
        }
    }

    /// 喂一段字节，返回该段触发的帧。
    fn feed(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let events = self.scanner.push(bytes).iter().filter_map(|payload| parse_event(payload)).collect();
        self.consume(events)
    }

    fn consume(&mut self, events: Vec<OrcaEvent>) -> Vec<Frame> {
        if self.saw_end {
            return Vec::new();
        }
        let mut frames = Vec::new();
        for event in events {
            match event {
                OrcaEvent::Reasoning(delta) => {
                    frames.push(self.chunk(delta, None, true));
                }
                OrcaEvent::Delta(delta) => match self.buffered {
                    // 形态未定：看开头是不是信封形态（``` 围栏 / JSON 对象）
                    None => {
                        if self.content.is_empty() && !delta.trim_start().is_empty() {
                            let head = delta.trim_start();
                            let envelope_shaped = head.starts_with("```") || head.starts_with('{');
                            self.buffered = Some(envelope_shaped);
                        }
                        self.content.push_str(&delta);
                        if !self.buffered.unwrap_or(false) {
                            frames.push(self.chunk(delta, None, false));
                        }
                    }
                    // 信封形态：只缓冲，不发帧
                    Some(true) => self.content.push_str(&delta),
                    // 直播形态：逐增量下发
                    Some(false) => frames.push(self.chunk(delta, None, false)),
                },
                OrcaEvent::Done => {
                    self.saw_end = true;
                    frames.extend(self.final_frames(Some("stop")));
                    break;
                }
                OrcaEvent::Error(message) => {
                    self.last_error = Some(message);
                    self.saw_end = true;
                    frames.extend(self.final_frames(None));
                    break;
                }
            }
        }
        frames
    }

    /// 收尾帧：信封模式在这里解包并一次性下发正文。
    ///
    /// ── 流内错误的两种处置 ──────────────────────────────────
    /// 正文**为空**时，流内错误就是整次请求的结果 —— 下发一帧 error 对象
    /// 再收尾（面板上那个未挂载的模型走的就是这条路）；已发出正文后的
    /// ERROR 仍保留内容、静默收尾。
    fn final_frames(&mut self, finish_reason: Option<&str>) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.buffered == Some(true) {
            let raw = self.content.clone();
            match unwrap_envelope(&raw) {
                Some(text) => frames.push(self.chunk(text, finish_reason, false)),
                // 解不出信封文本 = 不是信封（或字段认不出）：原样下发，
                // 宁可透传也不错杀用户自己要的 JSON
                None => {
                    if !raw.is_empty() {
                        frames.push(self.chunk(raw, finish_reason, false));
                    } else if let Some(reason) = finish_reason {
                        frames.push(self.chunk(String::new(), Some(reason), false));
                    }
                }
            }
        } else if let Some(reason) = finish_reason {
            // 直播模式：内容已实时下发，只补结束帧
            frames.push(self.chunk(String::new(), Some(reason), false));
        }
        if self.content.is_empty() {
            if let Some(message) = &self.last_error {
                frames.push(Frame::Error(message.clone()));
            }
        }
        frames.push(Frame::Done);
        frames
    }

    fn flush_tail(&mut self) -> Vec<Frame> {
        let events: Vec<OrcaEvent> = self
            .scanner
            .finish()
            .iter()
            .filter_map(|payload| parse_event(payload))
            .collect();
        self.consume(events)
    }

    fn finish(&mut self) -> Vec<Frame> {
        let mut frames = self.flush_tail();
        if !self.saw_end {
            frames.extend(self.final_frames(Some("stop")));
        }
        self.saw_end = true;
        frames
    }

    fn finish_with_error(&mut self, message: &str) -> Vec<Frame> {
        let mut frames = self.flush_tail();
        if self.saw_end {
            return frames;
        }
        self.saw_end = true;
        let mut tail = self.final_frames(None);
        if !tail.iter().any(|frame| matches!(frame, Frame::Error(_))) {
            // 插在 `[DONE]` 之前：客户端先看到失败原因，再看到流结束
            tail.insert(tail.len().saturating_sub(1), Frame::Error(message.to_string()));
        }
        frames.extend(tail);
        frames
    }

    fn chunk(&mut self, delta: String, finish_reason: Option<&str>, reasoning: bool) -> Frame {
        let mut delta_body = serde_json::Map::new();
        if !delta.is_empty() {
            if reasoning {
                delta_body.insert("reasoning_content".to_string(), json!(delta));
            } else {
                delta_body.insert("content".to_string(), json!(delta));
            }
        }
        Frame::Chunk(json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": Value::Object(delta_body),
                "finish_reason": finish_reason,
            }],
        }))
    }
}

/// ACP 动作信封解包：整段正文（剥一层 ``` 围栏后）是带 `action` 键的 JSON
/// 对象时，抽出给人看的文本。
///
/// 取值链照抄桌面端 UI：`completion → taskCompletion`、`default → content`、
/// 其余动作按 `taskCompletion / content / question` 取第一个非空。
fn unwrap_envelope(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let inner = if trimmed.starts_with("```") {
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
    } else {
        trimmed
    };
    let parsed: Value = serde_json::from_str(inner).ok()?;
    let object = parsed.as_object()?;
    let action = object.get("action").and_then(Value::as_str)?;
    let text = match action {
        "completion" => object.get("taskCompletion").and_then(Value::as_str),
        "default" => object.get("content").and_then(Value::as_str),
        _ => ["taskCompletion", "content", "question"]
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str)),
    }?
    .trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(frames: &[Frame]) -> String {
        let mut out = String::new();
        for frame in frames {
            if let Frame::Chunk(chunk) = frame {
                if let Some(text) = chunk["choices"][0]["delta"]["content"].as_str() {
                    out.push_str(text);
                }
            }
        }
        out
    }

    fn finish_of(frames: &[Frame]) -> Option<String> {
        frames.iter().find_map(|frame| match frame {
            Frame::Chunk(chunk) => chunk["choices"][0]["finish_reason"].as_str().map(str::to_string),
            _ => None,
        })
    }

    #[test]
    fn single_message_passes_through() {
        let messages = json!([{ "role": "user", "content": "你好呀" }]);
        assert_eq!(build_prompt(Some(&messages)), "你好呀");
    }

    #[test]
    fn multi_turn_is_flattened_with_roles() {
        let messages = json!([
            { "role": "system", "content": "你是助手" },
            { "role": "user", "content": "1+1" },
            { "role": "assistant", "content": "2" },
            { "role": "user", "content": "再算 2+2" },
        ]);
        let prompt = build_prompt(Some(&messages));
        assert!(prompt.contains("[系统指令] 你是助手"), "{prompt}");
        assert!(prompt.contains("[用户] 再算 2+2"), "{prompt}");
        assert!(prompt.ends_with("[对话记录结束；请回应其中最后一条用户消息]"), "{prompt}");
    }

    #[test]
    fn empty_messages_fall_back_to_greeting() {
        assert_eq!(build_prompt(None), "你好");
        assert_eq!(build_prompt(Some(&json!([]))), "你好");
        assert_eq!(build_prompt(Some(&json!([{ "role": "user", "content": "   " }]))), "你好");
    }

    #[test]
    fn array_content_joins_text_parts() {
        let messages = json!([{ "role": "user", "content": [{ "type": "text", "text": "第一段" }, { "type": "text", "text": "第二段" }] }]);
        assert_eq!(build_prompt(Some(&messages)), "第一段\n第二段");
    }

    /// 直播形态：正文逐增量下发，末帧补 finish_reason + [DONE]。
    #[test]
    fn streams_live_content() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"你"}

data: {"type":"ai","reasoning":false,"content":"好"}

data: [DONE]

"#
            .as_bytes(),
        );
        assert_eq!(text_of(&frames), "你好");
        assert_eq!(finish_of(&frames), Some("stop".to_string()));
        assert!(matches!(frames.last(), Some(Frame::Done)));
        assert!(stream.saw_end);
    }

    /// 思考增量走 `reasoning_content`，不进正文。
    #[test]
    fn reasoning_increments_use_reasoning_content() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":true,"reasoningContent":"想一下"}

data: {"type":"ai","reasoning":false,"content":"答案"}

data: [DONE]

"#
            .as_bytes(),
        );
        let reasoning: String = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Chunk(chunk) => {
                    chunk["choices"][0]["delta"]["reasoning_content"].as_str().map(str::to_string)
                }
                _ => None,
            })
            .collect();
        assert_eq!(reasoning, "想一下");
        assert_eq!(text_of(&frames), "答案");
    }

    /// 信封形态：先缓冲、收尾时解包成纯文本；流式过程中一个字节都不能下发。
    #[test]
    fn envelope_is_buffered_then_unwrapped() {
        let mut stream = OrcaStream::new("hy3");
        let first = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"{\"action\":\"completion\","}

"#
            .as_bytes(),
        );
        assert!(first.is_empty(), "信封形态的第一个增量不应下发");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"\"taskCompletion\":\"做完了\"}"}

data: [DONE]

"#
            .as_bytes(),
        );
        assert_eq!(text_of(&frames), "做完了");
        assert_eq!(finish_of(&frames), Some("stop".to_string()));
    }

    /// 解不出信封时原样透传（不能把用户自己要的 JSON 吃掉）。
    #[test]
    fn unknown_envelope_passes_through() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"{\"hello\":1}"}

data: [DONE]

"#
            .as_bytes(),
        );
        assert_eq!(text_of(&frames), r#"{"hello":1}"#);
    }

    /// 正文为空 + 流内错误 → 产出 error 帧（`Output` 在未下发时会把它升级成 Err）。
    #[test]
    fn empty_content_with_error_frame() {
        let mut stream = OrcaStream::new("hy4-preview");
        let frames = stream.feed(
            r#"data: [ERROR]: [LLM_ERROR]: LLM(TokenHub/hy4-preview) is not loaded

"#
            .as_bytes(),
        );
        assert!(frames.iter().any(|frame| matches!(frame, Frame::Error(_))));
        assert!(matches!(frames.last(), Some(Frame::Done)));
    }

    /// 已有正文之后的 ERROR 静默收尾（内容留下，不额外报错）。
    #[test]
    fn error_after_content_is_silent() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"半句"}

data: [ERROR]: 上游自己断了

"#
            .as_bytes(),
        );
        assert_eq!(text_of(&frames), "半句");
        assert!(!frames.iter().any(|frame| matches!(frame, Frame::Error(_))));
    }

    /// 流断在半路：已下发内容时补一条 error 帧再 [DONE]。
    #[test]
    fn interruption_reports_in_stream() {
        let mut stream = OrcaStream::new("hy3");
        let first = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"半句"}

"#
            .as_bytes(),
        );
        assert_eq!(text_of(&first), "半句");
        let frames = stream.finish_with_error("OrcaTerm 上游流式传输中断：连接重置");
        let errors: Vec<&str> = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Error(message) => Some(message.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("连接重置"));
        assert!(matches!(frames.last(), Some(Frame::Done)));
    }

    /// 没有空行结尾的最后一帧（贴在 EOF 上）要靠 `finish` 读出来：
    /// 帧边界是空行，`feed` 在没有空行时本来就不该产出事件。
    #[test]
    fn tail_frame_without_blank_line() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            r#"data: {"type":"ai","reasoning":false,"content":"尾帧"}"#.as_bytes(),
        );
        assert!(text_of(&frames).is_empty(), "没有空行就没有完整事件");
        let tail = stream.finish();
        assert_eq!(text_of(&tail), "尾帧");
        assert!(matches!(tail.last(), Some(Frame::Done)));
        assert_eq!(finish_of(&tail), Some("stop".to_string()));
    }

    /// 被截断的 `[DONE]` 不算协议完成：EOF 里的 DONE 要被丢掉。
    #[test]
    fn truncated_done_is_not_completion() {
        let mut scanner = DataEvents::default();
        assert!(scanner.push(b"data: [DONE]").is_empty());
        assert!(scanner.finish().is_empty());
    }

    /// 首行 BOM 不能把第一帧吃掉。
    #[test]
    fn bom_on_first_line_is_stripped() {
        let mut stream = OrcaStream::new("hy3");
        let frames = stream.feed(
            b"\xef\xbb\xbfdata: {\"type\":\"ai\",\"reasoning\":false,\"content\":\"ok\"}\n\ndata: [DONE]\n\n",
        );
        assert_eq!(text_of(&frames), "ok");
    }

    /// 判据照抄 native：**同时**出现 `token` 与失效词才算凭证失效
    /// （实测上游的凭证类文案都带 `token` 字样；只写「令牌失效」不会命中，
    /// 那种情况按普通业务错误 502 透传 —— 保持与 native 一致）。
    #[test]
    fn credential_rejection_detection() {
        assert!(is_credential_rejection(1, "token expired"));
        assert!(is_credential_rejection(1, "token 已失效"));
        assert!(is_credential_rejection(1, "invalid token"));
        assert!(!is_credential_rejection(0, "token expired"));
        assert!(!is_credential_rejection(500, "server error"));
        assert!(!is_credential_rejection(500, "令牌失效"));
    }
}
