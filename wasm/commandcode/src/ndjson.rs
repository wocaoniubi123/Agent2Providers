//! 上游 **AI SDK v5 风格 NDJSON** 字节流 → 标准 chat SSE 字节流（状态机）。
//!
//! ── 这份折叠器为什么在插件里（与 native 的最大结构差异）──────────
//! native 只需在 `build_chat` 里报 `UpstreamKind::Ndjson`，由网关的
//! `core/protocol/ai_sdk_ndjson.rs` 把这台状态机接在上游响应之后 ——
//! 账号轮换、限额冷却、退避重试、usage 与取消处理全部留在网关编排层。
//! **wasm 包没有翻译层**（`plugin_host/rpc.rs` 的 `build_chat_request_async`
//! 对任何 wasm 包直接 501，对话一律走 `conversation`：插件自己发请求、自己
//! 推 SSE）。所以这台状态机必须原样搬进插件 —— 本文件逐条对齐网关那份：
//! 事件词表、收尾时序、错误帧类型、usage 归一、零输出兜底都不改动。
//!
//! ── 事件折法 ────────────────────────────────────────────────
//!   - `start` / `start-step` / `text-start` / `text-end` / `reasoning-start` /
//!     `reasoning-end` / `tool-input-start` / `tool-input-delta` / `tool-input-end` /
//!     `tool-error` / `provider-metadata` → 信号，无用户可见内容，忽略
//!   - `text-delta` → `delta.content`（取 `text`，兼容 `delta` 字段）
//!   - `reasoning-delta` → `delta.reasoning_content`
//!   - `tool-call` → `tool_calls` 帧（`id` / `name` / `arguments` 一次给全，
//!     与 Anthropic 那条的「宣告帧 + 参数帧」不同：这类工具调用是**整体**事件）
//!   - `finish-step` → 记「见过完成信号」+ 记 finishReason/usage（**不发帧**）
//!   - `finish` → **终态**：finish 帧 + usage 帧 + `data: [DONE]`
//!   - `error` → 记下 SDK 错误（由 `chat.rs` 折成错误帧 + `[DONE]`），
//!     按 [`map_upstream_status`] 折出下行的 error.type
//!
//! ── `finish` 与 [DONE] 的收尾时序 ───────────────────────────
//!   1. 内容帧永远先于收尾帧：收尾帧一次给全 —— `finish_reason` 帧、
//!      usage 帧、`data: [DONE]`，三者之后流结束；
//!   2. **没有完成信号**（既无 `finish`、也无 `finish-step`）就 EOF：
//!      按「响应被截断」报错（可重试 502 语义），**不补** finish_reason/[DONE]
//!      —— 那等于把截断谎报成完整回答；
//!   3. 只见 `finish-step`、没有终态 `finish`：按「上游给过完成信号」正常收尾
//!      （真正要拦的是「一个完成信号都没有」）；
//!   4. `finish` 的 `finishReason` 归一后有 `upstream_error` 一档（裸 `error` /
//!      `network|connection|upstream-error`）：它是**可重试的连接失败**而不是
//!      合法 finish_reason，因此走错误帧而不是收尾帧（原样透出会让严格客户端
//!      整条流反序列化失败）。
//!
//! ── 错误帧的 `error.type` ────────────────────────────────────
//! 用 [`map_upstream_status`] 的映射表（`rate_limit_error` /
//! `authentication_error` / …）而不是一律 `upstream_error`：NDJSON 的
//! `error` 事件带了 `statusCode` / `code`，这一档信息在帧里能保留就保留。
//!
//! ── **HTTP 恒 200** 这条特性怎么兜（本家的核心风险）──────────────
//! 认证失败 / 限流 / 余额不足都在流内 `{"type":"error"}` 表达，HTTP 状态码永远
//! 是 200。因此本折叠器把「错误」当成**事件**处理，而不是响应状态：
//!   - `type == "error"` → 立即收尾并抛 SDK 错误（状态码从 `error.statusCode`、
//!     文案里的 `<NNN>` 前缀、或回落 502 折出来）；
//!   - 错误发生在**首帧内容之前** → `chat.rs` 还没发 head，客户端拿到的是一次
//!     干净的失败（HTTP 状态由分类结果决定，而不是假的 200 + 空回答）；
//!   - 错误发生在**内容之后** → 已发的字节收不回来，改为下发一条错误帧 +
//!     `[DONE]`（形态见 `errors::error_event`），再把错误抛给网关记日志；
//!   - 一个完成信号都没有就 EOF → 502 截断（不谎报完整）；
//!   - **`type` 缺失但对象里带 `error` / `message`** → 也按错误体处理。这是对
//!     网关那份的**一处有意增强**：它把「未知事件」一律忽略，于是「200 + 一次性
//!     错误 JSON」会被降级成「截断 502」，丢掉本该是 401/429 的状态码。正常流
//!     的每个事件都带 `type`，所以这条分支碰不到正常路径。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Value};

use super::util;

/// OpenAI 侧认得的 `finish_reason` 全集（照抄参考实现的 `OPENAI_FINISH_REASONS`）。
const OPENAI_FINISH_REASONS: [&str; 5] = [
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "function_call",
];

/// 单行 NDJSON 的上限（防止一行坏数据把 64 MiB 的实例内存吃光）
const MAX_LINE: usize = 4 * 1024 * 1024;

/// 上游错误事件 → 下行 `(status, error.type)`。
///
/// 未列出的状态码一律 502 `upstream_error`。
/// 402（付费失败）映射 429、403（权限/风控）映射 401 是**有意**的下游语义
/// （让下游按限流退避 / 换账号，而不是当成服务端故障）。
fn map_upstream_status(status: Option<i64>) -> (u16, &'static str) {
    match status {
        Some(400) | Some(422) => (400, "invalid_request_error"),
        Some(401) | Some(403) => (401, "authentication_error"),
        // 402 付费失败 → 按限流（充值/换套餐是用户侧的事，下游该退避）
        Some(402) => (429, "rate_limit_error"),
        Some(404) => (404, "not_found"),
        Some(429) => (429, "rate_limit_error"),
        Some(500) | Some(502) => (502, "upstream_error"),
        Some(503) => (503, "temporarily_unavailable"),
        _ => (502, "upstream_error"),
    }
}

/// OpenAI 口径的 `error.type` → 网关认的内部 `kind`（`Error.code` 那一栏）
fn internal_kind(kind: &str) -> &'static str {
    match kind {
        "authentication_error" => "token_expired",
        "rate_limit_error" => "quota_limited",
        "invalid_request_error" => "content_blocked",
        _ => "fatal",
    }
}

/// 上游 finishReason → 本机内部词表（照抄参考实现的 `mapFinishReason`）。
///
/// `length` 家族**不止 `length` 一个值**：`max_output_tokens` 与
/// `model_context_window_exceeded` 都是「输出被截断」，折成 stop 等于把半截回答
/// 谎报成完整回答。裸 `error` 与 `network|connection|upstream-error` 一族并进
/// `upstream_error`（可重试的连接失败，不是合法 finish_reason）。
fn map_finish_reason(reason: &str) -> String {
    let value = reason.trim().to_lowercase();
    if value.is_empty() {
        return "stop".to_string();
    }
    match value.as_str() {
        "tool-calls" | "tool_calls" | "tool_use" => "tool_calls".to_string(),
        "length" | "max_tokens" | "max_output_tokens" | "model_context_window_exceeded" => {
            "length".to_string()
        }
        "error" => "upstream_error".to_string(),
        other => {
            if is_network_failure_finish(other) {
                "upstream_error".to_string()
            } else {
                other.to_string()
            }
        }
    }
}

/// `/^(network|connection|upstream)[-_\s]?error$/` 的 Rust 形态（不用 regex 依赖）
fn is_network_failure_finish(value: &str) -> bool {
    for prefix in ["network", "connection", "upstream"] {
        let Some(rest) = value.strip_prefix(prefix) else {
            continue;
        };
        let rest = rest.trim_start_matches(['-', '_', ' ']);
        if rest == "error" {
            return true;
        }
    }
    false
}

/// 内部词表 → 真正下发的 `finish_reason`（照抄参考的 `toOpenAIFinishReason`）。
///
/// `pause_turn`（Anthropic 原生语义「后面还有内容」）在 Chat 侧折 `length`；
/// 不认识的结束原因折 `stop`（上游确实发过 finish，只是原因不在词表 ——
/// 不能报截断）；`upstream_error` 走错误帧，不从这里出。
fn to_openai_finish_reason(reason: &str) -> String {
    if reason == "pause_turn" {
        return "length".to_string();
    }
    if OPENAI_FINISH_REASONS.contains(&reason) {
        return reason.to_string();
    }
    "stop".to_string()
}

/// message 里的 `<NNN>` 前缀（参考的 `parseEmbeddedErrorJSON(message)?.status`）
fn embedded_status(message: &str) -> Option<i64> {
    let rest = message.trim().strip_prefix('<')?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() != 3 {
        return None;
    }
    digits.parse::<i64>().ok()
}

/// 上游 usage → chat 口径（参考 `normalizeUsage` + usage 帧的字段映射）。
///
/// `inputTokens` 是**总数（含缓存）**，chat 的 `prompt_tokens` 口径本来就含缓存，
/// 因此它可以直接沿用；缓存另开 `prompt_tokens_details.cached_tokens`
/// （请求统计的「缓存」列按它取值）。
/// `outputTokens === 0` 时清零 input/cached：上游异常时的 0 输出不该产生
/// 一笔输入计费（参考实现同款防误计费规则）。
fn normalized_usage(usage: &Value) -> Value {
    let mut input = util::number_of(usage, &["inputTokens"]);
    let mut output = util::number_of(usage, &["outputTokens", "completionTokens"]);
    let mut cached = util::number_of(usage, &["cachedInputTokens", "cacheReadTokens"]);
    if output == 0 {
        input = 0;
        cached = 0;
    }
    if output < 0 {
        output = 0;
        input = 0;
        cached = 0;
    }
    json!({
        "prompt_tokens": input,
        "completion_tokens": output,
        "total_tokens": input + output,
        "prompt_tokens_details": { "cached_tokens": cached },
    })
}

/// NDJSON 行缓冲：上游按 TCP 分片到达，一行 JSON 完全可能被切成两半。
///
/// 与 SSE 解码器的差别只有一处：NDJSON **没有 `data:` 前缀**，整行就是 JSON；
/// 因此这里不做前缀剥离，只按 `\n` 切分并在 EOF 时冲刷残留（上游发完最后一帧
/// 却没带收尾换行是真实存在的形态，冲刷能让它被正确识别）。
#[derive(Default)]
struct LineBuffer {
    tail: Vec<u8>,
}

impl LineBuffer {
    /// 吃一段字节，吐出其中**完整**的行（已过滤空行 / `[DONE]` / 注释行）
    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        self.tail.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(offset) = self.tail[start..].iter().position(|byte| *byte == b'\n') {
            let end = start + offset;
            let line = String::from_utf8_lossy(&self.tail[start..end]).to_string();
            if let Some(line) = keep_line(&line) {
                out.push(line);
            }
            start = end + 1;
        }
        self.tail.drain(..start);
        out
    }

    /// 流结束：把残留的半行也当一行处理（判据与 [`Self::push`] 相同）
    fn finish(&mut self) -> Vec<String> {
        if self.tail.is_empty() {
            return Vec::new();
        }
        let line = String::from_utf8_lossy(&self.tail).to_string();
        self.tail.clear();
        keep_line(&line).into_iter().collect()
    }
}

/// 一行是否要交给解析器（空行 / `[DONE]` / `:` 注释行都不是事件）
///
/// 容错：个别中间层会在每行前加 SSE 的 `data: ` 前缀（本家规范是不加的）。
/// 正常 NDJSON 事件行以 `{` 开头，所以剥前缀不会误伤正常事件；不剥的话
/// 「上游按 SSE 形态发」会整条流被判成截断。
fn keep_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let trimmed = trimmed
        .strip_prefix("data:")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed == "[DONE]" || trimmed.starts_with(':') {
        return None;
    }
    Some(trimmed.to_string())
}

/// 一个 chat SSE 帧（`data: <json>\n\n`）
fn chat_frame(value: &Value) -> String {
    format!("data: {value}\n\n")
}

/// `data: [DONE]\n\n`
fn done_frame() -> &'static str {
    "data: [DONE]\n\n"
}

/// 一个 id（形态与网关的 `random_id` 同款：`<前缀>-<随机 hex>`）
fn random_id(prefix: &str) -> String {
    format!("{prefix}-{}", util::random_hex(12))
}

/// 一个对象是否「像错误体」（`type` 缺失时的兜底判定，见模块头）
fn looks_like_error(event: &Value) -> bool {
    if event
        .get("error")
        .is_some_and(|value| !value.is_null() && util::is_truthy(value))
    {
        return true;
    }
    let has_text = ["message", "msg", "detail"]
        .iter()
        .any(|key| event.get(*key).and_then(Value::as_str).is_some_and(|text| !text.trim().is_empty()));
    has_text && event.get("code").is_some()
}

/// 上游 NDJSON 字节流 → 标准 chat SSE 字节流（状态机）。
pub struct Fold {
    /// 输出帧的 model（发给上游的真名）
    model: String,
    id: String,
    created: i64,
    /// 已下发过首帧（role assistant）——同时也表达「上游给过内容事件」
    started: bool,
    finished: bool,
    /// 见过任何完成信号（终态 `finish` 或 `finish-step`）
    saw_finish: bool,
    /// `finish-step` 带来的结束原因（规范化后；`finish` 缺席时用它收尾）
    step_finish_reason: Option<String>,
    /// 工具调用的序号（`tool_calls[].index`，一个流内自增）
    tool_index: i64,
    /// usage（`finish-step` 的 `usage` → `finish` 的 `totalUsage` 覆盖）
    usage: Option<Value>,
    buffer: LineBuffer,
    /// 本次 push / finish 累积的 SSE 文本
    out: String,
    /// 折叠过程中产生的 SDK 错误（`chat.rs` 决定何时把它折成错误帧）
    error: Option<Error>,
}

impl Fold {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            id: String::new(),
            created: util::now_ms() / 1000,
            started: false,
            finished: false,
            saw_finish: false,
            step_finish_reason: None,
            tool_index: 0,
            usage: None,
            buffer: LineBuffer::default(),
            out: String::new(),
            error: None,
        }
    }

    /// 吃一段上游字节，吐出要下发的 chat SSE 帧
    pub fn push(&mut self, chunk: &[u8]) -> String {
        if self.finished {
            return std::mem::take(&mut self.out);
        }
        for line in self.buffer.push(chunk) {
            self.consume_line(&line);
            if self.finished {
                break;
            }
        }
        // 保护：一行坏数据不得把实例内存吃光
        if !self.finished && self.buffer.tail.len() > MAX_LINE {
            self.buffer.tail.clear();
            self.fail_protocol(
                "上游 NDJSON 单行超过 4 MiB，已中断本次流",
                "upstream_error",
                502,
                None,
            );
        }
        std::mem::take(&mut self.out)
    }

    /// 上游流结束：冲刷残留半行，再按「有没有完成信号」收尾
    pub fn finish(&mut self) -> String {
        if self.finished {
            return std::mem::take(&mut self.out);
        }
        for line in self.buffer.finish() {
            self.consume_line(&line);
            if self.finished {
                return std::mem::take(&mut self.out);
            }
        }
        if !self.saw_finish {
            // 一个完成信号都没有：上游契约里就是「没走完」，不能补 finish_reason
            self.fail_protocol(
                "上游流在收到完成事件之前结束（响应被截断）",
                "upstream_error",
                502,
                None,
            );
            return std::mem::take(&mut self.out);
        }
        let reason = self
            .step_finish_reason
            .clone()
            .unwrap_or_else(|| "stop".to_string());
        self.complete(&reason);
        std::mem::take(&mut self.out)
    }

    /// 取走折叠过程中的错误（取走即清空）
    pub fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// 流是否已进入终态（正常收尾或已报错）
    pub fn finished(&self) -> bool {
        self.finished
    }

    /// 一行文本 → 零到多个帧（解析失败的行按「不是事件」跳过，与网关同款）
    fn consume_line(&mut self, line: &str) {
        match serde_json::from_str::<Value>(line) {
            Ok(event) => self.consume(&event),
            Err(_) => {
                // 半行 / 非 JSON 噪声：上游偶尔会在流里夹一个心跳。静默跳过 ——
                // 「没有完成信号」那条判据最终仍会兜住真正的截断。
            }
        }
    }

    /// 一个 NDJSON 事件 → 零到多个帧
    fn consume(&mut self, event: &Value) {
        if self.finished {
            return;
        }
        let Some(object) = event.as_object() else {
            return;
        };
        let kind = util::text(event, "type").to_lowercase();
        if kind.is_empty() {
            // ── HTTP 恒 200 的兜底（本文件模块头最后两条）──────────────
            // 正常事件都带 `type`；缺 `type` 又带 `error` / `message` 的对象
            // 只可能是「200 + 一次性错误体」。
            if looks_like_error(event) {
                self.fail(event);
            }
            return;
        }
        match kind.as_str() {
            // 信号类事件：无用户可见内容（与参考实现的静默列表逐字对齐）
            "start" | "start-step" | "text-start" | "text-end" | "reasoning-start"
            | "reasoning-end" | "tool-input-start" | "tool-input-delta" | "tool-input-end"
            | "tool-error" | "provider-metadata" => {}
            "text-delta" => {
                // 正文增量：`text` 为主、兼容部分实现的 `delta`
                let primary = util::text(event, "text");
                let text = if primary.is_empty() {
                    util::text(event, "delta")
                } else {
                    primary
                };
                if text.is_empty() {
                    return;
                }
                self.start();
                let frame = self.delta_frame(json!({ "content": text }));
                self.out.push_str(&frame);
            }
            "reasoning-delta" => {
                // 思考增量：只取 `text`（与参考一致，不读 `delta`）
                let text = util::text(event, "text");
                if text.is_empty() {
                    return;
                }
                self.start();
                let frame = self.delta_frame(json!({ "reasoning_content": text }));
                self.out.push_str(&frame);
            }
            "tool-call" => {
                // 工具调用是**整体**事件（id / name / 完整参数一次给全）
                let raw_id = util::text(event, "toolCallId");
                let id = if raw_id.is_empty() {
                    random_id("call")
                } else {
                    raw_id
                };
                let name = util::text(event, "toolName");
                let input = object.get("input").cloned().unwrap_or(Value::Null);
                let arguments = match &input {
                    Value::String(text) => text.clone(),
                    Value::Null => "{}".to_string(),
                    other => other.to_string(),
                };
                let index = self.tool_index;
                self.tool_index = self.tool_index.saturating_add(1);
                self.start();
                let frame = self.delta_frame(json!({
                    "tool_calls": [{
                        "index": index,
                        "id": id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    }],
                }));
                self.out.push_str(&frame);
            }
            "finish-step" => {
                // 单步结束：只算「见过完成信号」，帧由 finish 或缺席时的 EOF 出
                self.saw_finish = true;
                if let Some(reason) = object
                    .get("finishReason")
                    .filter(|value| util::is_truthy(value))
                    .map(util::string_value)
                    .filter(|value| !value.trim().is_empty())
                {
                    self.step_finish_reason = Some(map_finish_reason(&reason));
                }
                if let Some(usage) = object.get("usage").filter(|usage| usage.is_object()) {
                    self.usage = Some(normalized_usage(usage));
                }
            }
            "finish" => {
                self.saw_finish = true;
                // 参考的取值链：finish-step 的 finishReason 优先，其次 finish 自己的
                let reason = match self.step_finish_reason.clone() {
                    Some(reason) => reason,
                    None => {
                        let raw = util::text(event, "finishReason");
                        if raw.trim().is_empty() {
                            "stop".to_string()
                        } else {
                            map_finish_reason(&raw)
                        }
                    }
                };
                if let Some(usage) = object
                    .get("totalUsage")
                    .or_else(|| object.get("usage"))
                    .filter(|usage| usage.is_object())
                {
                    self.usage = Some(normalized_usage(usage));
                }
                // `upstream_error` 一档（裸 `error` / `network|connection|upstream-error`）
                // 由 `complete` 统一转成可重试的错误 —— 它不是合法 finish_reason
                self.complete(&reason);
            }
            "error" => self.fail(event),
            // 未知事件：忽略（事件词表若发生漂移，症状就是「这条内容没出现」）
            _ => {}
        }
    }

    /// 首帧（role assistant），只发一次
    fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        if self.id.is_empty() {
            self.id = random_id("chatcmpl");
        }
        let frame = self.delta_frame(json!({ "role": "assistant", "content": "" }));
        self.out.push_str(&frame);
    }

    /// 收尾：finish 帧 + usage 帧 + `[DONE]`（只做一次）。
    ///
    /// `reason` 是**归一后的内部词表**取值（`map_finish_reason` 的输出）：
    /// `upstream_error` 在这里转成可重试的错误（它不是合法 finish_reason）；
    /// 其余经 `to_openai_finish_reason` 折成 OpenAI 认的值。
    ///
    /// 上游一个内容事件都没给就走到这里（只有 finish / finish-step）时按空响应
    /// 报错：那是一条「成功但什么都没有」的流，记成成功会让下游按空回答计费。
    fn complete(&mut self, reason: &str) {
        if self.finished {
            return;
        }
        // 顺序是刻意的（与参考实现同款）：**先判连接失败族，再判零输出** ——
        // provider 报连接失败时「零输出」只是表象，按 502 报才指向真实原因
        if reason == "upstream_error" {
            self.fail_protocol(
                "上游报告连接失败（provider reported an upstream connection failure）",
                "upstream_error",
                502,
                None,
            );
            return;
        }
        if !self.started {
            self.fail_protocol(
                "上游返回空响应（没有任何内容事件）",
                "rate_limit_error",
                429,
                None,
            );
            return;
        }
        self.finished = true;
        self.start();
        let finish = self.finish_frame(&to_openai_finish_reason(reason));
        self.out.push_str(&finish);
        let usage = chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": self.usage_payload(),
        }));
        self.out.push_str(&usage);
        self.out.push_str(done_frame());
    }

    /// 上游错误事件 → SDK 错误（只做一次）
    ///
    /// 状态码取值链（参考实现 `mapCcEventError`）：message 里的 `<NNN>` 前缀
    /// 优先，其次 `error.statusCode`，都没有回落 502 —— 拿不到真实状态码会让
    /// 429/503 全塌成 502，下游不再退避、监控误判成后端故障。
    fn fail(&mut self, event: &Value) {
        if self.finished {
            return;
        }
        let error = event.get("error").filter(|value| util::is_truthy(value));
        // 文案取值链与参考实现同款：`error.message` → `event.message` → 兜底文案
        let message = match error {
            Some(error) => {
                let text = util::text(error, "message");
                if text.trim().is_empty() {
                    util::text(event, "message")
                } else {
                    text
                }
            }
            None => {
                let primary = util::text(event, "message");
                if primary.trim().is_empty() {
                    util::text(event, "msg")
                } else {
                    primary
                }
            }
        };
        let message = if message.trim().is_empty() {
            "上游流式返回错误".to_string()
        } else {
            message
        };
        let reported = error
            .and_then(|error| {
                embedded_status(&message).or_else(|| error.get("statusCode").and_then(Value::as_i64))
            })
            .or_else(|| event.get("statusCode").and_then(Value::as_i64))
            .or_else(|| event.get("status").and_then(Value::as_i64));
        // 机器可读分类：`error.code` → `event.code`
        let code = error
            .and_then(|error| {
                error
                    .get("code")
                    .filter(|value| util::is_truthy(value))
                    .or_else(|| event.get("code").filter(|value| util::is_truthy(value)))
            })
            .map(util::string_value)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                event
                    .get("code")
                    .filter(|value| util::is_truthy(value))
                    .map(util::string_value)
                    .filter(|value| !value.is_empty())
            });
        let (status, kind) = map_upstream_status(reported);
        self.fail_protocol(&message, kind, status, code.as_deref());
    }

    /// 把「协议级失败」落成 SDK 错误（只做一次）
    ///
    /// ── 为什么这里**不**产出帧 ──────────────────────────────────
    /// 是否补「错误帧 + `[DONE]`」取决于**正文是否已经下发**（`chat.rs` 的
    /// `Output.started`）。带 `usage` 且 `choices` 为空的帧正是 OpenAI 流式的
    /// 收尾帧形态，部分客户端据此判定「流已结束」—— 在它之后补错误帧等于让
    /// 那些客户端永远看不到失败，把一次错误渲染成一次空回答。错误路径只发
    /// 「错误帧 + `[DONE]`」（与网关 `ForwardStream` 的断流收尾逐字同形）。
    fn fail_protocol(&mut self, message: &str, kind: &str, status: u16, code: Option<&str>) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut error = Error::http(status, message.to_string()).with_code(internal_kind(kind));
        if status == 429 {
            // 限流必须带 retry_after，否则 SDK 不知道该等多久（参考实现同款）
            error.reset_at = Some(util::now_ms() + 30_000);
        }
        if let Some(code) = code {
            error.upstream_code = code.parse::<i64>().ok();
        }
        self.error = Some(error);
    }

    /// chat 口径的 usage
    fn usage_payload(&self) -> Value {
        match self.usage.clone() {
            Some(usage) => usage,
            None => json!({
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }),
        }
    }

    /// 一个 delta 帧
    fn delta_frame(&self, delta: Value) -> String {
        chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": delta, "finish_reason": Value::Null }],
        }))
    }

    /// 收尾帧（空 delta + finish_reason）
    fn finish_frame(&self, finish_reason: &str) -> String {
        chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": finish_reason }],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(text: &str) -> Vec<Value> {
        text.split("\n\n")
            .filter(|part| !part.trim().is_empty() && part.trim() != "data: [DONE]")
            .filter_map(|part| part.trim().strip_prefix("data: "))
            .filter_map(|payload| serde_json::from_str::<Value>(payload).ok())
            .collect()
    }

    #[test]
    fn text_delta_becomes_a_content_frame() {
        let mut fold = Fold::new("gpt-5.5");
        let out = fold.push(
            "{\"type\":\"start\"}\n{\"type\":\"text-delta\",\"text\":\"你好\"}\n".as_bytes(),
        );
        let list = frames(&out);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["choices"][0]["delta"]["role"], json!("assistant"));
        assert_eq!(list[1]["choices"][0]["delta"]["content"], json!("你好"));
        assert_eq!(list[1]["object"], json!("chat.completion.chunk"));
        assert_eq!(list[1]["model"], json!("gpt-5.5"));
    }

    #[test]
    fn text_delta_accepts_the_delta_field() {
        let mut fold = Fold::new("m");
        let out = fold.push("{\"type\":\"text-delta\",\"delta\":\"兼容\"}\n".as_bytes());
        let list = frames(&out);
        assert_eq!(list[1]["choices"][0]["delta"]["content"], json!("兼容"));
    }

    #[test]
    fn reasoning_delta_maps_to_reasoning_content() {
        let mut fold = Fold::new("m");
        let out = fold.push("{\"type\":\"reasoning-delta\",\"text\":\"思考\"}\n".as_bytes());
        let list = frames(&out);
        assert_eq!(
            list[1]["choices"][0]["delta"]["reasoning_content"],
            json!("思考")
        );
    }

    #[test]
    fn tool_call_is_one_complete_frame() {
        let mut fold = Fold::new("m");
        let out = fold.push(
            b"{\"type\":\"tool-call\",\"toolCallId\":\"call_1\",\"toolName\":\"run\",\"input\":{\"a\":1}}\n",
        );
        let list = frames(&out);
        let call = &list[1]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(call["index"], json!(0));
        assert_eq!(call["id"], json!("call_1"));
        assert_eq!(call["type"], json!("function"));
        assert_eq!(call["function"]["name"], json!("run"));
        assert_eq!(call["function"]["arguments"], json!("{\"a\":1}"));
    }

    #[test]
    fn tool_call_positions_increment() {
        let mut fold = Fold::new("m");
        let out = fold.push(
            b"{\"type\":\"tool-call\",\"toolCallId\":\"a\",\"toolName\":\"x\",\"input\":{}}\n{\"type\":\"tool-call\",\"toolCallId\":\"b\",\"toolName\":\"y\",\"input\":{}}\n",
        );
        let list = frames(&out);
        assert_eq!(list[1]["choices"][0]["delta"]["tool_calls"][0]["index"], json!(0));
        assert_eq!(list[2]["choices"][0]["delta"]["tool_calls"][0]["index"], json!(1));
    }

    #[test]
    fn finish_emits_finish_frame_usage_frame_and_done() {
        let mut fold = Fold::new("m");
        let mut out = fold.push(b"{\"type\":\"text-delta\",\"text\":\"ok\"}\n");
        out.push_str(&fold.push(
            b"{\"type\":\"finish-step\",\"finishReason\":\"stop\",\"usage\":{\"inputTokens\":10,\"outputTokens\":5,\"cachedInputTokens\":3}}\n",
        ));
        out.push_str(&fold.push(b"{\"type\":\"finish\"}\n"));
        assert!(fold.finished());
        assert!(out.ends_with("data: [DONE]\n\n"));
        let list = frames(&out);
        let last = &list[list.len() - 1];
        assert_eq!(last["choices"], json!([]));
        assert_eq!(last["usage"]["prompt_tokens"], json!(10));
        assert_eq!(last["usage"]["completion_tokens"], json!(5));
        assert_eq!(last["usage"]["total_tokens"], json!(15));
        assert_eq!(last["usage"]["prompt_tokens_details"]["cached_tokens"], json!(3));
        // 收尾帧在 usage 帧之前
        let finish = &list[list.len() - 2];
        assert_eq!(finish["choices"][0]["finish_reason"], json!("stop"));
        assert!(fold.take_error().is_none());
    }

    #[test]
    fn finish_reason_families_are_normalized() {
        for (raw, expected) in [
            ("tool-calls", "tool_calls"),
            ("tool_use", "tool_calls"),
            ("max_output_tokens", "length"),
            ("model_context_window_exceeded", "length"),
            ("pause_turn", "length"),
            ("weird_thing", "stop"),
        ] {
            let mut fold = Fold::new("m");
            let out = fold.push(
                format!("{{\"type\":\"text-delta\",\"text\":\"x\"}}\n{{\"type\":\"finish\",\"finishReason\":\"{raw}\"}}\n")
                    .as_bytes(),
            );
            let list = frames(&out);
            let finish = &list[list.len() - 2];
            assert_eq!(
                finish["choices"][0]["finish_reason"],
                json!(expected),
                "raw={raw}"
            );
        }
    }

    #[test]
    fn error_event_before_content_yields_a_clean_error() {
        let mut fold = Fold::new("m");
        let out = fold.push(
            b"{\"type\":\"error\",\"error\":{\"message\":\"invalid api key\",\"statusCode\":401}}\n",
        );
        assert!(out.is_empty(), "错误帧之前不应有任何正文帧");
        let error = fold.take_error();
        let Some(error) = error else {
            assert!(false, "必须抛出一个 SDK 错误");
            return;
        };
        assert_eq!(error.status, Some(401));
        assert_eq!(error.code.as_deref(), Some("token_expired"));
        assert!(fold.finished());
    }

    #[test]
    fn embedded_status_in_message_wins() {
        let mut fold = Fold::new("m");
        let _ = fold.push(b"{\"type\":\"error\",\"error\":{\"message\":\"<429> slow down\"}}\n");
        let error = fold.take_error();
        let Some(error) = error else {
            assert!(false, "必须抛出一个 SDK 错误");
            return;
        };
        assert_eq!(error.status, Some(429));
        assert_eq!(error.code.as_deref(), Some("quota_limited"));
        assert!(error.reset_at.is_some(), "429 必须带 retry_after");
    }

    #[test]
    fn finish_without_any_content_is_a_429() {
        let mut fold = Fold::new("m");
        let out = fold.push(b"{\"type\":\"finish\",\"finishReason\":\"stop\"}\n");
        assert!(out.is_empty());
        let Some(error) = fold.take_error() else {
            assert!(false, "空响应必须报错");
            return;
        };
        assert_eq!(error.status, Some(429));
        assert_eq!(error.code.as_deref(), Some("quota_limited"));
    }

    #[test]
    fn truncated_stream_is_reported_not_completed() {
        let mut fold = Fold::new("m");
        let _ = fold.push(b"{\"type\":\"text-delta\",\"text\":\"half\"}\n");
        let out = fold.finish();
        assert!(!out.contains("[DONE]"), "截断不得补 [DONE]");
        let Some(error) = fold.take_error() else {
            assert!(false, "截断必须报错");
            return;
        };
        assert_eq!(error.status, Some(502));
        assert_eq!(error.code.as_deref(), Some("fatal"));
    }

    #[test]
    fn finish_step_alone_completes_the_stream() {
        let mut fold = Fold::new("m");
        let _ = fold.push(b"{\"type\":\"text-delta\",\"text\":\"ok\"}\n");
        let _ = fold.push(b"{\"type\":\"finish-step\",\"finishReason\":\"tool-calls\"}\n");
        let out = fold.finish();
        assert!(out.contains("[DONE]"));
        let list = frames(&out);
        let finish = &list[list.len() - 2];
        assert_eq!(finish["choices"][0]["finish_reason"], json!("tool_calls"));
        assert!(fold.take_error().is_none());
    }

    #[test]
    fn upstream_connection_failure_finish_is_an_error() {
        let mut fold = Fold::new("m");
        let _ = fold.push(b"{\"type\":\"text-delta\",\"text\":\"x\"}\n");
        let _ = fold.push(b"{\"type\":\"finish\",\"finishReason\":\"network-error\"}\n");
        let Some(error) = fold.take_error() else {
            assert!(false, "连接失败必须报错");
            return;
        };
        assert_eq!(error.status, Some(502));
    }

    #[test]
    fn zero_output_tokens_do_not_bill_input() {
        let usage = normalized_usage(&json!({
            "inputTokens": 100,
            "outputTokens": 0,
            "cachedInputTokens": 50,
        }));
        assert_eq!(usage["prompt_tokens"], json!(0));
        assert_eq!(usage["prompt_tokens_details"]["cached_tokens"], json!(0));
        assert_eq!(usage["completion_tokens"], json!(0));
    }

    #[test]
    fn typeless_error_body_is_recognized() {
        // 200 + 一次性错误体（无 type）：本家 HTTP 恒 200 时最容易踩的形态
        let mut fold = Fold::new("m");
        let out = fold.push(b"{\"message\":\"invalid api key\",\"code\":401}\n");
        assert!(out.is_empty());
        let Some(error) = fold.take_error() else {
            assert!(false, "错误体必须被识别");
            return;
        };
        // 文案里没有 <NNN>、也没有同名状态字段 → 502 兜底（与参考一致）
        assert_eq!(error.status, Some(502));
    }

    #[test]
    fn unknown_events_are_ignored_without_breaking_the_stream() {
        let mut fold = Fold::new("m");
        let out = fold.push(b"{\"type\":\"provider-metadata\",\"x\":1}\n{\"type\":\"???\"}\n");
        assert!(out.is_empty());
        assert!(fold.take_error().is_none());
        assert!(!fold.finished());
    }

    #[test]
    fn blank_lines_and_done_markers_are_not_events() {
        let mut fold = Fold::new("m");
        let out = fold.push(b"\n  \n[DONE]\n: heartbeat\n");
        assert!(out.is_empty());
        assert!(fold.take_error().is_none());
    }

    #[test]
    fn data_prefix_is_tolerated() {
        // 个别中间层会给每行加 SSE 前缀；剥掉后仍是一个正常事件
        let mut fold = Fold::new("m");
        let out = fold.push("data: {\"type\":\"text-delta\",\"text\":\"前缀\"}\n".as_bytes());
        let list = frames(&out);
        assert_eq!(list[1]["choices"][0]["delta"]["content"], json!("前缀"));
        // `data: [DONE]` 也不会被当成事件
        let mut second = Fold::new("m");
        assert!(second.push(b"data: [DONE]\n").is_empty());
    }

    #[test]
    fn split_lines_across_chunks_are_reassembled() {
        let mut fold = Fold::new("m");
        assert!(fold.push(b"{\"type\":\"text-del").is_empty());
        let out = fold.push("ta\",\"text\":\"拼接\"}\n".as_bytes());
        let list = frames(&out);
        assert_eq!(list[1]["choices"][0]["delta"]["content"], json!("拼接"));
    }
}
