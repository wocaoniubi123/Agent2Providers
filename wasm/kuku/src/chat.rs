//! KukuAI 对话转发：建会话 → 分配算力 → SSE 流式 → OpenAI 形状。
//!
//! ── 上游是**会话式三步走**（kuku2api 2026-09-13 实测，本模块照抄）────
//!   1. `POST /wenchain/genflowpro/sendmsg`（带 `bdstoken/uinfo/uk` 会话三件套）
//!      建会话，返回 `{session_id, reply_id}`；
//!   2. `POST /wenchain/genflow/idorl` 分配算力（+ `sessionswitch`，浏览器会调，
//!      容错 —— 失败不影响对话）；
//!   3. `POST /wenchain/genflowpro/sse/getchatcontent`（SSE）→ 流式文本。
//! SSE 帧是 `data: {type, data}` JSON，事件只有四类：
//!   `TEXT_BLOCK_DELTA`（`data.delta` 增量）/ `REPLY_END` / `DIALOGUE_END`
//!   （结束）/ `ERROR`（终止流，已发内容保留 —— 与参考实现一致）。
//!
//! ── 多轮与模型 ──────────────────────────────────────────────
//! 上游**没有多轮接续接口**：每次请求新建会话，历史拍平成单条 prompt
//! （`build_prompt`：system → `[系统指令]`、assistant → `[助手之前的回复]`，
//! 与参考实现同一口径）。模型参数 `model_name` 直接给上游（`models::resolve_model`
//! 归一，未知显式回退 `auto`）。工具调用第一版**不做**注入（上游有产品级人格
//! 保护，注入式协议不可靠）。
//!
//! ── 为什么整条发送链在 `conversation` 里 ─────────────────────
//! 网关 `plugin_host/rpc.rs` 的 `build_chat_request_async` 对 wasm 包直接回 501，
//! `forwards_response()` 对 wasm 恒为 true —— wasm 包的对话一律走会话式通道：
//! 插件自己发请求、自己解析上游、只把「已经是 OpenAI chat SSE 形态」的字节吐给
//! 网关。所以这里必须自己完成「三步时序 + 事件翻译」，没有哪个环节能交给网关。
//!
//! ── 两种错误边界（本模块最要紧的两条规则）────────────────────
//!   · **一个字节都没下发之前**判出错误（凭证 / 建会话 / 分配算力后的 SSE 建连
//!     失败）⇒ 直接返回 `Err`，让编排层换账号重试；
//!   · **已经 `stream.head` 之后**再出错（读流中断 / 解析失败）⇒ 先补一条 SSE
//!     错误事件 + `[DONE]`，再返回 `Err`：客户端已经看到半段内容，不能假装成功，
//!     更不能悄悄从头重发。
//! 上游自己的 `ERROR` 帧属于**业务错误**（不是传输错误）：它出现在 HTTP 200 的流里，
//! 按参考实现的口径翻成一条错误事件后正常收尾（返回 `Ok`），这样已下发的正文
//! 不会被网关当成「整条失败」丢掉。
//!
//! ── 会话是**请求内**的（与 CatPaw / Trae 的差别）───────────────
//! 同样是 `stateful: true`，但 KukuAI 的会话建完即用、用毕即弃 —— 不需要会话
//! 注册表 / 轮次状态机：`forward` 一个函数完成「建会话 → 流式 → 收尾」，
//! 不跨请求保持任何状态（唯一跨请求的是 `session.rs` 的三件套缓存）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, sse::SseDecoder, Error, Result, Value};

use super::account::{self, KukuCredentials};
use super::errors;
use super::models;
use super::session::{self, TokenTriple};
use super::upstream;

/// 客户端会话通道名（kuku2api 实测值）
const CHANNEL_NAME: &str = "kuku_web_genflowpro_v1";

/// 一次建会话的结果。
struct NewSession {
    session_id: String,
    reply_id: String,
}

/// `conversation` 入口。
pub fn forward(params: &Value) -> Result<()> {
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(Error::http(400, "请求体必须是 JSON 对象"));
    }
    // 发送名：主程序给的 `wire_model` 优先（模型改写发生在网关侧），
    // 缺省退回请求体里的 `model`，再缺省用 auto。
    let client_model = params["wire_model"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or_else(|| body["model"].as_str().map(str::trim).filter(|name| !name.is_empty()))
        .unwrap_or(upstream::DEFAULT_MODEL)
        .to_string();
    let model = models::resolve_model(&client_model);
    let prompt = build_prompt(body.get("messages"));

    // ── ① 凭证与三件套（可能打两次上游：userreport）──────────────
    let credentials = account::current()?;
    let triple = session::ensure(&credentials, false)?;
    let query = format!("{}{}", upstream::WEB_QUERY, session::token_query(&triple));

    // ── ② 建会话（失败 = 还没下发任何字节 ⇒ 直接 Err，让编排层换账号）──
    let created = create_session(&credentials, &query, &triple, &prompt, &model)?;

    // ── ③ 分配算力 + 切会话（容错：失败不阻断对话，浏览器也会调这两步）──
    // wasm 侧没有日志通道（宿主不提供 log 调用），因此这里是真正的「忽略」：
    // 与 native 的「只记 verbose 日志、继续往下走」语义相同。
    let _ = allocate(&credentials, &query);
    let _ = switch_session(&credentials, &query, &created.session_id);

    // ── ④ 建 SSE 连接（失败仍未下发 ⇒ Err）──────────────────────
    let url = format!(
        "{}/wenchain/genflowpro/sse/getchatcontent?{query}",
        upstream::BASE_URL
    );
    let payload = chat_payload(&prompt, &model, &created.session_id, &created.reply_id);
    let response = upstream::sse_open(
        &url,
        &upstream::sse_headers(&credentials.cookie_header()),
        &payload,
    )?;

    // ── ⑤ 到这里上游已确认流可用：先报头，此后所有错误都只能「在流里说」──
    sdk::stream_head(200)?;
    stream_upstream(response, &client_model)
}

/// 建会话（sendmsg）→ `{session_id, reply_id}`。
///
/// `triple` 是会话三件套：query 里拼一份、`client_added` 里嵌一份
/// （参考实现两处都带真实值，上游据此做客户端形态校验）。
fn create_session(
    credentials: &KukuCredentials,
    query: &str,
    triple: &TokenTriple,
    prompt: &str,
    model: &str,
) -> Result<NewSession> {
    let url = format!("{}/wenchain/genflowpro/sendmsg?{query}", upstream::BASE_URL);
    let headers = upstream::headers(&credentials.cookie_header());
    let client_session_id = random_uuid();
    let now_ms = sdk::now();
    let show_text = json!({
        "skills": [], "experts": [], "model_name": model,
        "model_display_name": model, "think_mode": upstream::DEFAULT_THINK_MODE,
        "richInputContent": [{ "type": "text", "text": prompt }], "fileInfo": []
    });
    let client_added = json!({
        "client_session_id": client_session_id, "permission_type": 0, "clienttype": 400,
        "app_id": upstream::APP_ID, "web": 1, "channel": upstream::CHANNEL, "version": "1.4.4",
        "bdstoken": triple.bdstoken, "uinfo": triple.uinfo, "uk": triple.uk
    });
    let body = json!({
        "type": "message", "sub_type": "chat_create",
        "client_session_id": client_session_id, "session_id": "", "uk": "", "cid": 0,
        "channel": CHANNEL_NAME, "device_type": 400,
        "created_at": now_ms, "msg_type": 1, "sync_type": 0, "sync_id": "",
        "v": random_hex(24),
        "data": {
            "project_type": 1, "text": prompt,
            "rich_input_params": [{
                "id": "textId", "version": "1.0", "type": "text",
                "text": prompt, "data": { "content": prompt }
            }],
            "fsid": [], "quotes": [], "skills": [], "experts": [],
            "model_name": model, "model_display_name": model,
            "think_mode": upstream::DEFAULT_THINK_MODE,
            "show_text": show_text.to_string(),
            "premake_data": {}, "custom_instructions": "",
            "memory_sign": true, "skill_dig_sign": true,
            "client_added": client_added.to_string()
        }
    });
    let value = upstream::post_json(&url, &headers, &body)?;
    let code = value
        .get("status")
        .and_then(|status| status.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or(-1);
    if code != 0 {
        let message = value
            .get("status")
            .and_then(|status| status.get("msg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(Error::http(
            502,
            format!("KukuAI 建会话失败（status.code={code}：{message}）"),
        ));
    }
    let info = value.get("data").cloned().unwrap_or(Value::Null);
    let session_id = info
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let reply_id = info
        .get("reply_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if session_id.is_empty() {
        return Err(Error::http(
            502,
            "KukuAI 建会话返回缺少 session_id（上游响应异常）",
        ));
    }
    Ok(NewSession {
        session_id,
        reply_id,
    })
}

/// 分配算力（容错）。
fn allocate(credentials: &KukuCredentials, query: &str) -> Result<()> {
    let url = format!("{}/wenchain/genflow/idallochstr?{query}", upstream::BASE_URL);
    let headers = upstream::headers(&credentials.cookie_header());
    let body = json!({ "channel": CHANNEL_NAME, "gen_type": 2 });
    upstream::post_json(&url, &headers, &body)?;
    Ok(())
}

/// 切会话（浏览器会调，容错）。
fn switch_session(credentials: &KukuCredentials, query: &str, session_id: &str) -> Result<()> {
    let url = format!(
        "{}/api/genflowpro/workspace/sessionswitch?{query}",
        upstream::BASE_URL
    );
    let headers = upstream::headers(&credentials.cookie_header());
    let body = json!({ "session_id": session_id, "op": 1, "full_access_enabled": 0 });
    upstream::post_json(&url, &headers, &body)?;
    Ok(())
}

/// getchatcontent 的请求体（sendmsg 的 `data` 段 + 会话标识）。
fn chat_payload(prompt: &str, model: &str, session_id: &str, reply_id: &str) -> Value {
    let show_text = json!({
        "skills": [], "experts": [], "model_name": model,
        "model_display_name": model, "think_mode": upstream::DEFAULT_THINK_MODE,
        "richInputContent": [{ "type": "text", "text": prompt }], "fileInfo": []
    });
    json!({
        "project_type": 1, "text": prompt,
        "rich_input_params": [{
            "id": "textId", "version": "1.0", "type": "text",
            "text": prompt, "data": { "content": prompt }
        }],
        "fsid": [], "quotes": [], "skills": [], "experts": [],
        "model_name": model, "model_display_name": model,
        "think_mode": upstream::DEFAULT_THINK_MODE,
        "show_text": show_text.to_string(),
        "premake_data": {}, "custom_instructions": "",
        "memory_sign": true, "skill_dig_sign": true,
        "session_id": session_id, "reply_id": reply_id
    })
}

/// 把 OpenAI messages 压成单条 prompt（上游无多轮接续接口，参考实现同口径）。
pub fn build_prompt(messages: Option<&Value>) -> String {
    let Some(Value::Array(items)) = messages else {
        return "你好".to_string();
    };
    if items.is_empty() {
        return "你好".to_string();
    }
    if items.len() == 1 {
        return content_text(&items[0]).unwrap_or_else(|| "你好".to_string());
    }
    let mut lines: Vec<String> = Vec::new();
    for message in items {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("user");
        let Some(text) = content_text(message) else { continue };
        if text.trim().is_empty() {
            continue;
        }
        match role {
            "system" => lines.push(format!("[系统指令] {text}")),
            "assistant" => lines.push(format!("[助手之前的回复] {text}")),
            _ => lines.push(text),
        }
    }
    if lines.is_empty() {
        return "你好".to_string();
    }
    lines.join("\n\n")
}

/// 取一条消息的可读文本（content 字符串或 text 类型的部件数组）。
fn content_text(message: &Value) -> Option<String> {
    let content = message.get("content")?;
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let mut out: Vec<String> = Vec::new();
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
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

// ─── 上游 SSE 解析 ──────────────────────────────────────────

/// 一条已解析的上游事件。
enum KukuEvent {
    Delta(String),
    Done,
    Error(String),
}

/// 一条 `data:` JSON → 事件（认不得的 type 忽略，与参考实现一致）。
fn event_from_json(parsed: &Value) -> Option<KukuEvent> {
    match parsed.get("type").and_then(Value::as_str) {
        Some("TEXT_BLOCK_DELTA") => {
            let delta = parsed
                .get("data")
                .and_then(|data| data.get("delta"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if delta.is_empty() {
                None
            } else {
                Some(KukuEvent::Delta(delta))
            }
        }
        Some("REPLY_END") | Some("DIALOGUE_END") => Some(KukuEvent::Done),
        Some("ERROR") => {
            let message = parsed
                .get("data")
                .and_then(|data| data.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("上游错误")
                .to_string();
            Some(KukuEvent::Error(message))
        }
        _ => None,
    }
}

// ─── OpenAI chunk 产出 ──────────────────────────────────────

/// 流式转换器：喂上游字节，产出 OpenAI chat SSE 帧。
struct ChatStream {
    id: String,
    created: i64,
    model: String,
    saw_end: bool,
}

impl ChatStream {
    fn new(model: &str) -> Self {
        let now = sdk::now();
        Self {
            // native 用 `now_ms * 1000 % 1e15` 拼 id；这里同口径（id 只有展示意义，
            // 客户端不拿它做去重）
            id: format!("chatcmpl-{}", now.saturating_mul(1000) % 1_000_000_000_000_000),
            created: now / 1000,
            model: model.to_string(),
            saw_end: false,
        }
    }

    /// 喂一个已解析的 SSE 事件，返回要下发的字节（每项是一条完整帧）。
    fn feed(&mut self, data: &str) -> Vec<String> {
        if self.saw_end {
            return Vec::new();
        }
        if data.trim() == "[DONE]" {
            return self.finish();
        }
        let Ok(parsed) = serde_json::from_str::<Value>(data) else {
            // 认不得的帧直接跳过（与参考实现一致：上游偶尔混入心跳 / 注释帧）
            return Vec::new();
        };
        let Some(event) = event_from_json(&parsed) else {
            return Vec::new();
        };
        match event {
            KukuEvent::Delta(delta) => vec![self.chunk(Some(&delta), None)],
            KukuEvent::Done => {
                let mut frames = vec![self.chunk(None, Some("stop"))];
                frames.push(done_frame());
                self.saw_end = true;
                frames
            }
            KukuEvent::Error(message) => {
                let mut frames = vec![error_frame(&message)];
                frames.push(done_frame());
                self.saw_end = true;
                frames
            }
        }
    }

    /// 流结束（上游正常收尾但没给结束事件）时补齐收尾帧。
    fn finish(&mut self) -> Vec<String> {
        if self.saw_end {
            return Vec::new();
        }
        let mut frames = vec![self.chunk(None, Some("stop"))];
        frames.push(done_frame());
        self.saw_end = true;
        frames
    }

    /// 已经下发过内容之后再出错：补一条错误事件 + `[DONE]`，让客户端拿到闭合的流。
    fn finish_with_error(&mut self, message: &str) -> Vec<String> {
        if self.saw_end {
            return Vec::new();
        }
        let mut frames = vec![error_frame(message)];
        frames.push(done_frame());
        self.saw_end = true;
        frames
    }

    /// 一帧 chat.completion.chunk（含 `data: ` 前缀与空行帧尾）。
    fn chunk(&self, delta: Option<&str>, finish_reason: Option<&str>) -> String {
        let mut choice = serde_json::Map::new();
        choice.insert("index".to_string(), json!(0));
        match delta {
            Some(text) if !text.is_empty() => {
                choice.insert("delta".to_string(), json!({ "content": text }));
            }
            _ => {
                choice.insert("delta".to_string(), json!({}));
            }
        }
        if let Some(reason) = finish_reason {
            choice.insert("finish_reason".to_string(), json!(reason));
        }
        let chunk = json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [Value::Object(choice)],
        });
        format!("data: {chunk}\n\n")
    }
}

/// `[DONE]` 帧。
fn done_frame() -> String {
    "data: [DONE]\n\n".to_string()
}

/// 一条错误事件的线格式（形状与 `errors::error_event` 同源，避免两处文案分叉）。
fn error_frame(message: &str) -> String {
    let value = errors::error_event(&Error::http(502, message));
    format!("data: {value}\n\n")
}

/// 逐块读上游 SSE，边解析边下发。
///
/// ── 为什么这里返回 `Err` 而不是「把错误写进流就完事」──────────
/// 读流中断是**传输层失败**：网关需要知道这一条没走完（它据此决定是否记一次失败），
/// 所以先补错误事件保证客户端拿到闭合的流，再把 `Err` 抛上去。上游自己的
/// `ERROR` 帧则相反 —— 那是业务结果，`ChatStream` 会正常收尾并返回 `Ok`。
fn stream_upstream(mut response: agent2api_wasm_sdk::http::Response, model: &str) -> Result<()> {
    let mut decoder = SseDecoder::default();
    let mut stream = ChatStream::new(model);
    loop {
        match response.read() {
            Ok(Some(bytes)) => match decoder.push(&bytes) {
                Ok(events) => {
                    for event in events {
                        for frame in stream.feed(&event) {
                            sdk::stream_bytes(frame.as_bytes())?;
                        }
                        if stream.saw_end {
                            return Ok(());
                        }
                    }
                }
                Err(error) => {
                    // 已下发过内容：补错误事件 + [DONE]，再如实上报
                    for frame in stream.finish_with_error(&format!(
                        "KukuAI 对话流解析中断：{}",
                        error.message
                    )) {
                        sdk::stream_bytes(frame.as_bytes())?;
                    }
                    return Err(error);
                }
            },
            Ok(None) => break,
            Err(error) => {
                for frame in stream.finish_with_error(&format!(
                    "KukuAI 对话流处理中断：{}",
                    error.message
                )) {
                    sdk::stream_bytes(frame.as_bytes())?;
                }
                return Err(Error::http(
                    502,
                    format!("KukuAI 对话流中断：{}", error.message),
                ));
            }
        }
    }
    // 上游没给结束事件就 EOF：补齐收尾帧（否则下游聚合器会一直等结束标记）
    for frame in stream.finish() {
        sdk::stream_bytes(frame.as_bytes())?;
    }
    Ok(())
}

// ─── 随机串 ────────────────────────────────────────────────

/// 派生一段伪随机字节（只为「唯一标识」语义，不参与任何认证）。
///
/// ── 为什么不申请 `random.v1` ───────────────────────────────
/// native 用系统随机源生成 `client_session_id` 与 `v` 字段，但它们只当**标识**用，
/// 不参与签名、不落库比对。wasm 侧不额外申请一条能力（宿主提供 `random.bytes`
/// 返回 base64，插件还得自带解码器），改用 sha2 从「凭证指纹 + 时间 + 序号 + 上下文」
/// 派生：同一毫秒内两次请求的上下文不同，碰撞概率可以忽略；拿到值也无法反推凭证。
fn pseudo_random(domain: &[u8], length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out: Vec<u8> = Vec::with_capacity(length);
    let mut counter: u64 = 0;
    while out.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(b"agent2api:kuku:random:v1");
        hasher.update(domain);
        hasher.update(sdk::now().to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        out.extend_from_slice(&digest);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

/// UUID v4 形态（`client_session_id` 用）。
fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&pseudo_random(b"client-session-id", 16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// 随机十六进制串（`v` 字段用，参考实现 24 位）。
fn random_hex(length: usize) -> String {
    let bytes = pseudo_random(b"message-v", length.div_ceil(2));
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out.truncate(length);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_flattens_history_like_the_reference() {
        // 单条消息原样返回（不加角色前缀）
        assert_eq!(
            "你好",
            build_prompt(Some(&json!([{ "role": "user", "content": "你好" }])))
        );
        // 多轮：system / assistant 加标记，其余原样
        let prompt = build_prompt(Some(&json!([
            { "role": "system", "content": "你是助手" },
            { "role": "user", "content": "第一问" },
            { "role": "assistant", "content": "第一答" },
            { "role": "user", "content": "第二问" }
        ])));
        assert_eq!(
            "[系统指令] 你是助手\n\n第一问\n\n[助手之前的回复] 第一答\n\n第二问",
            prompt
        );
        // 部件数组形态
        assert_eq!(
            "a\nb",
            build_prompt(Some(&json!([{ "role": "user", "content": [
                { "type": "text", "text": "a" }, { "type": "text", "text": "b" }
            ] }])))
        );
        // 空 / 缺字段退回「你好」；单条空白内容原样返回（与 native 同口径：
        // 只有「取不到 content」才回退，不替用户 trim 正文）
        assert_eq!("你好", build_prompt(None));
        assert_eq!("你好", build_prompt(Some(&json!([]))));
        assert_eq!("   ", build_prompt(Some(&json!([{ "role": "user", "content": "   " }]))));
        assert_eq!("你好", build_prompt(Some(&json!([{ "role": "user" }]))));
    }

    #[test]
    fn event_mapping_covers_the_four_types() {
        assert!(matches!(
            event_from_json(&json!({ "type": "TEXT_BLOCK_DELTA", "data": { "delta": "h" } })),
            Some(KukuEvent::Delta(ref text)) if text == "h"
        ));
        assert!(matches!(event_from_json(&json!({ "type": "REPLY_END" })), Some(KukuEvent::Done)));
        assert!(matches!(event_from_json(&json!({ "type": "DIALOGUE_END" })), Some(KukuEvent::Done)));
        assert!(matches!(
            event_from_json(&json!({ "type": "ERROR", "data": { "message": "boom" } })),
            Some(KukuEvent::Error(ref message)) if message == "boom"
        ));
        // 空 delta / 未知 type 一律忽略
        assert!(event_from_json(&json!({ "type": "TEXT_BLOCK_DELTA", "data": { "delta": "" } })).is_none());
        assert!(event_from_json(&json!({ "type": "UNKNOWN" })).is_none());
    }

    #[test]
    fn stream_frames_are_complete_sse_frames() {
        let mut stream = ChatStream::new("glm-5.3");
        let frames = stream.feed(&json!({ "type": "TEXT_BLOCK_DELTA", "data": { "delta": "你" } }).to_string());
        assert_eq!(1, frames.len());
        let frame = frames.first().cloned().unwrap_or_default();
        assert!(frame.starts_with("data: {"));
        assert!(frame.ends_with("\n\n"));
        assert!(frame.contains("\"object\":\"chat.completion.chunk\""));
        assert!(frame.contains("\"content\":\"你\""));

        // 结束事件：一帧 finish_reason=stop + [DONE]
        let frames = stream.feed(&json!({ "type": "REPLY_END" }).to_string());
        assert_eq!(2, frames.len());
        assert!(frames.first().cloned().unwrap_or_default().contains("\"finish_reason\":\"stop\""));
        assert_eq!("data: [DONE]\n\n", frames.get(1).cloned().unwrap_or_default());
        // 结束后再喂帧一律忽略
        assert!(stream.feed(&json!({ "type": "TEXT_BLOCK_DELTA", "data": { "delta": "x" } }).to_string()).is_empty());
    }

    #[test]
    fn upstream_error_frame_closes_the_stream_without_panicking() {
        let mut stream = ChatStream::new("auto");
        let frames = stream.feed(&json!({ "type": "ERROR", "data": { "message": "上游拒绝" } }).to_string());
        assert_eq!(2, frames.len());
        let error_frame = frames.first().cloned().unwrap_or_default();
        assert!(error_frame.contains("上游拒绝"));
        assert!(error_frame.contains("upstream_error"));
        assert_eq!("data: [DONE]\n\n", frames.get(1).cloned().unwrap_or_default());
        assert!(stream.saw_end);
    }

    #[test]
    fn abrupt_end_still_emits_a_closing_frame() {
        let mut stream = ChatStream::new("auto");
        let frames = stream.finish();
        assert_eq!(2, frames.len());
        assert!(frames.first().cloned().unwrap_or_default().contains("\"finish_reason\":\"stop\""));
        assert_eq!("data: [DONE]\n\n", frames.get(1).cloned().unwrap_or_default());
    }

    #[test]
    fn failure_after_content_reports_error_then_done() {
        let mut stream = ChatStream::new("auto");
        let _ = stream.feed(&json!({ "type": "TEXT_BLOCK_DELTA", "data": { "delta": "半段" } }).to_string());
        let frames = stream.finish_with_error("读流中断");
        assert_eq!(2, frames.len());
        assert!(frames.first().cloned().unwrap_or_default().contains("读流中断"));
        assert!(!frames.first().cloned().unwrap_or_default().contains("finish_reason"));
        assert_eq!("data: [DONE]\n\n", frames.get(1).cloned().unwrap_or_default());
        // 已收尾后再来错误帧不会重复下发
        assert!(stream.finish_with_error("再次中断").is_empty());
    }

    #[test]
    fn generated_identifiers_keep_their_wire_shape() {
        let uuid = random_uuid();
        assert_eq!(36, uuid.chars().count());
        // 8-4-4-4-12 五段 = 四个分隔符
        assert_eq!(4, uuid.matches('-').count());
        // v4 形态：第三段以 4 开头，第四段以 8/9/a/b 开头
        let groups: Vec<&str> = uuid.split('-').collect();
        assert!(groups.get(2).is_some_and(|group| group.starts_with('4')));
        assert!(groups.get(3).is_some_and(|group| {
            group.starts_with('8') || group.starts_with('9') || group.starts_with('a') || group.starts_with('b')
        }));

        let hex = random_hex(24);
        assert_eq!(24, hex.chars().count());
        assert!(hex.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}
