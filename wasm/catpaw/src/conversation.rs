//! CatPaw **轮次状态机**：round → event(running) → turn(SSE) → 工具循环 → event(completed)。
//!
//! ── 这个模块存在的理由（与其它 provider 的本质差别）────────────
//! WorkBuddy / 小浣熊是「一次 HTTP 请求 = 一次对话」；CatPaw 的上游是一套
//! **有状态会话协议**（UPSTREAM_PROTOCOL.md 是唯一权威），一次客户端请求会
//! 变成好几个上游请求，中间还要维护「x-session-id → conversationId」映射与
//! 已同步消息的指纹链。时序与状态因此不能塞进单请求契约，本文件就是那份时序。
//!
//! ```text
//! 全新会话         round(全量)   → event(running) → turn(user)     → … → event(completed)
//! 长会话新轮次     round(增量)   → event(running) → turn(user)     → … → event(completed)
//! 工具续接         （不 round）  →                  turn(tool 结果) → …
//! ```
//!
//! ── 三条轮次判定规则（架构文档 §9.2；顺序勿改）─────────────────
//! 见 `decision.rs` 的模块头（规则顺序与理由都在那边）。
//!
//! ── 三条硬约束（上游行为特性，违反会导致会话卡死或 504，§9.3）──
//!   1. **每个轮次结束必须回报 event(completed)**，否则 conversation 停在上游的
//!      「执行中」状态，下一轮 round 会被拒绝（`会话正在执行中，无法创建新轮次`）。
//!      失败/打断路径回报 failed / canceled；例外：本轮返回工具调用时**不报**
//!      completed —— 那一轮在上游语义里还没结束，客户端马上会带着 tool 结果回来。
//!   2. turn 的 SSE 必须消费到**服务端关闭连接**（`message.finished=true`
//!      ≠ turn 结束），这条在 `turn.rs` 里落实。
//!   3. 同一 `x-session-id` 已有流式请求在跑 → 新请求走**独立 conversation**，
//!      结束释放占用；`stream:false` 的辅助请求（标题/摘要）**不读不写**会话映射。
//!
//! ── 与 native 的三处有意差异（如实记录）─────────────────────
//!   1. 不搬运会话里那几份「上一轮的副本」（systemPrompt、rulesMessage、
//!      toolConfigs、toolCatalog、contextWindow）：客户端每次请求都会重发这些
//!      内容（OpenAI 语义是无状态的），用**本次请求的值**比用上一轮的副本更准。
//!   2. **图片压缩由宿主完成**：网关在会话调用准备阶段对 `params.body` 跑
//!      `inline_images::prepare`（catpaw 专属，内联 + >60KB 压缩），所以 native
//!      的 `image_compress.rs` 不搬过来 —— 搬了会是同一件事做两遍，而第二次
//!      压缩没有意义（第一次已经把图压到 120KB 以内）。
//!   3. **客户端断开后不能后台续读**：native 起后台任务把上游 SSE 读到底再回报
//!      终态；wasm 里插件调用就是一次函数调用，宿主在调用结束后不会再给我们
//!      执行时间。所以这里改成「客户端断开 → 立即尽力 turn/stop + 回报 canceled」，
//!      语义上仍然是「上游不能停在执行中」，但**没有** native 那份「继续读完」的
//!      保证（如实记录在报告里）。
//!
//! ── 硬约束（代码纪律）──────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic；持锁期间不发网络请求。

use agent2api_wasm_sdk::{self as sdk, json, Error, Value};

use super::decision::{self, Decision, RequestFacts, TurnMode};
use super::errors::CatPawError;
use super::messages::{
    message_type, normalize_messages, synthetic_continue_message, NormalizeOptions,
};
use super::models::{
    resolve_context_window, resolve_effort, resolve_model_request, ModelResolution,
};
use super::tools::{normalize_tools, select_tools, tool_choice_mode, ToolChoice};
use super::upstream::{
    self, DEFAULT_MODE, DEFAULT_SOURCE, DEFAULT_TOOL_VERSION, PERMISSION_MODE,
};

/// 一次请求的全部「已归一化素材」
pub struct Prepared {
    /// 模型解析结果（`modelType` 与展示名）
    pub resolution: ModelResolution,
    /// 归一化后的上游消息块（不含 system / developer）
    pub messages: Vec<Value>,
    /// 本轮要提交的那条消息（增量轮次的末尾消息）
    pub final_message: Value,
    /// `system` 消息抽离出的系统提示（round/turn 的 `systemPromptContext`）
    pub system_prompt: Option<String>,
    /// `developer` 消息抽离出的规则文本（round/turn 的 `rulesMessage`）
    pub rules_message: Option<String>,
    /// `reasoning_effort` → `declarativeParams.effort`
    pub effort: Option<String>,
    /// `context_window` → `declarativeParams.context`
    pub context: Option<String>,
    /// 归一化后的 `tool_choice`（收尾校验「上游有没有按 choice 返回」用）
    pub choice: ToolChoice,
    /// 按 `tool_choice` 裁剪后**本轮实际下发**的工具集。
    ///
    /// 在准备阶段就算好（而不是发 turn 时才算）的理由：`tool_choice` 指向一个
    /// 不存在的工具、或 `required` 但一个工具都没给，都是**客户端入参错误** ——
    /// 原实现在 `prepareRequest` 阶段就抛（早于 round），客户端拿到的是一条干净的
    /// 400 而不是「先建了会话再失败」。
    pub selected_tools: Vec<Value>,
    /// 末尾那条 user 消息是**本地补的**（客户端历史以 tool 结果结尾）。
    ///
    /// 调用方据此把它排除在指纹链之外：它不在客户端历史里，写进链会让下一轮
    /// `locate_increment` 定位不到、误判「历史被改写」而反复全量重建。
    pub synthetic_tail: bool,
}

/// 归一化 + 参数解析（原实现 `prepareRequest` 在网关语义下的形态）。
///
/// ── 校验顺序照抄原实现 ──────────────────────────────────────
/// 消息 → effort → tools → tool_choice 的**报错优先级**是客户端可感知的行为
/// （同时给错两处时先报哪一个），因此这里保持同一顺序：参数先、消息后。
pub fn prepare(body: &Value) -> Result<Prepared, CatPawError> {
    let resolution = resolve_model_request(body.get("model").unwrap_or(&Value::Null))?;
    let effort = resolve_effort(body)?;
    let context = resolve_context_window(body, &resolution)?;
    let choice = tool_choice_mode(body.get("tool_choice"))?;
    let all_tools = normalize_tools(body.get("tools"))?;
    // 工具集裁剪同时是入参校验（`required` 没给工具、指定的工具不存在都报 400）：
    // 放在这里是为了让这类错误**不经过 round**
    let selected_tools = select_tools(&all_tools, &choice)?;
    // `parallel_tool_calls` 只做类型校验：上游的 turn 请求体里没有对应字段，
    // 原实现也是「收了但不用」（校验失败报 400，避免客户端以为它生效了）
    if let Some(value) = body.get("parallel_tool_calls").filter(|value| !value.is_null()) {
        if !value.is_boolean() {
            return Err(CatPawError::bad_request("parallel_tool_calls 必须是布尔值"));
        }
    }

    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| CatPawError::bad_request("messages 必须是非空数组"))?;
    // `NormalizeOptions::default()`：不允许多余的尾部 tool_call（`allow_trailing_tool_calls`
    // 只对「工具续接」那条路径有意义，而它由 decision.rs 自己从原始消息里切片段）
    let normalized = normalize_messages(messages, NormalizeOptions::default())?;
    let mut messages = normalized.messages;
    // 上游硬性要求 round/turn 的消息列表以 user 收尾（UPSTREAM_PROTOCOL §3.1）。
    // 客户端重放一段「以 tool 结果结尾」的历史时会撞上这条 —— 典型场景是插件
    // 重启后会话记录丢了、或客户端换了模型重发上一轮。这里补一条合成 user 消息
    // 满足约束：它只进本轮提交，不写回客户端、也不进指纹链。
    let synthetic_tail = if messages.last().and_then(message_type) == Some("tool") {
        messages.push(synthetic_continue_message());
        true
    } else {
        false
    };
    let final_message = messages
        .last()
        .cloned()
        .ok_or_else(|| CatPawError::bad_request("system/developer 之外至少需要一条对话消息"))?;
    Ok(Prepared {
        resolution,
        messages,
        final_message,
        synthetic_tail,
        system_prompt: normalized.system_prompt,
        rules_message: normalized.rules_message,
        effort,
        context,
        choice,
        selected_tools,
    })
}

/// 一次会话转发的执行上下文（`turn.rs` 收尾要用）
pub struct TurnContext {
    pub credentials: super::account::Credentials,
    /// 面向客户端的响应 id（`chatcmpl-…`）
    pub chat_id: String,
    /// 客户端请求的模型名（进 chunk 的 `model` 字段）
    pub model_name: String,
    /// 客户端是否要 usage 帧（`stream_options.include_usage`）
    pub include_usage: bool,
    /// 本轮的 tool_choice（收尾校验用）
    pub choice: ToolChoice,
    /// 账号 id（会话记录的账号维度）
    pub account_id: String,
    /// 本次凭证里的 uid（身份第二个维度；会话记录按它判「同一账号换了用户」）
    pub uid: String,
    /// 上游数字模型 ID（会话记录按它判「换模型就重建」）
    pub model_type: i64,
    /// 客户端 `x-session-id`（空 = 无长会话语义）
    pub session_id: String,
    /// 是否长会话（决定要不要把映射写回会话记录）
    pub persistent: bool,
    /// 本轮最终使用的 conversationId（自愈重试会换成新的，以守卫为准）
    pub conversation_id: String,
    /// 本轮的 turnRequestId（`turn/stop` 要带上它）
    pub turn_request_id: String,
}

/// 收尾责任（硬约束 1 的落点；native `FinishGuard` 的 wasm 版）。
///
/// ── 谁负责什么 ──────────────────────────────────────────────
///   - `Drop` **只释放占用**（同步存储操作；Drop 里发网络请求是错的，而且 wasm
///     的 Drop 之后宿主不会再给异步执行机会）；
///   - 正常/失败/取消三个终态由调用方显式 `close(status)` 上报；
///   - 「流被提前结束且没显式收尾」这条 wasm 里**做不到**后台补 canceled ——
///     如实记在模块头差异 3。
pub struct FinishGuard {
    pub credentials: super::account::Credentials,
    /// conversationId（自愈重试时会换成新的，所以是可变的）
    pub conversation_id: String,
    pub turn_request_id: String,
    session_id: String,
    /// 是否占用了 inflight 标记
    inflight: bool,
    /// round + event(running) 是否都成功过（决定要不要报终态）
    active: bool,
    /// 是否已显式收尾（幂等）
    closed: bool,
    /// 是否已完成本轮交接（返回工具调用或已报终态）
    settled: bool,
}

impl FinishGuard {
    fn new(ctx: &TurnContext, inflight: bool) -> Self {
        Self {
            credentials: ctx.credentials.clone(),
            conversation_id: ctx.conversation_id.clone(),
            turn_request_id: ctx.turn_request_id.clone(),
            session_id: ctx.session_id.clone(),
            inflight,
            active: false,
            closed: false,
            settled: false,
        }
    }

    /// 上游对话执行已开始（round + event(running) 成功）—— 此后失败都要报终态
    pub fn mark_active(&mut self) {
        self.active = true;
    }

    /// 报一个终态并收尾（幂等；`event` 上报失败不影响结果）
    pub fn close(&mut self, status: &str, error: Option<&CatPawError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.settled = true;
        if self.active {
            upstream::report_terminal(&self.credentials, &self.conversation_id, status, error);
        }
        self.release();
    }

    /// **只**放开占用，并标记本轮「已交接」——用于「返回工具调用、等客户端续接」
    /// 这条路径：本轮不报终态（上游语义里这一轮还没结束），但也绝不能触发
    /// 兜底取消（那会给上游发一个错误的 canceled，让客户端接下来提交的 tool
    /// 结果无处可去）。
    pub fn release(&mut self) {
        self.settled = true;
        if self.inflight && !self.session_id.is_empty() {
            super::registry::release_inflight(&self.session_id);
            self.inflight = false;
        }
    }

    /// 打断当前轮次（客户端断开时调）
    pub fn interrupt(&self) {
        upstream::stop_turn(&self.credentials, &self.conversation_id, &self.turn_request_id);
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        // 只释放占用（同步、无网络）。终态上报必须在显式路径里完成 ——
        // wasm 的 Drop 之后没有执行机会，起不了 native 那样的后台补发任务。
        self.release();
    }
}

/// `conversation` 的入口：一次客户端请求 → 一轮（可能是工具续接）的上游交互。
pub fn run(params: &Value) -> agent2api_wasm_sdk::Result<()> {
    let body = params["body"].clone();
    if !body.is_object() {
        return Err(super::errors::invalid(CatPawError::bad_request(
            "请求体必须是 JSON 对象",
        )));
    }
    let account_id = params["account"].as_str().unwrap_or("").to_string();
    // 凭证先解析：拿不到就报错（不要先建 conversation 再失败）
    let credentials = super::account::current().map_err(|error| {
        Error::http(error.status.unwrap_or(503), error.message)
    })?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(
            503,
            "CatPaw 没有可用的登录凭证：请在账号页添加账号，或导入本机登录态",
        ));
    }
    let prepared = prepare(&body).map_err(super::errors::invalid)?;
    execute(params, &body, &account_id, credentials, prepared).map_err(|error| error.to_error())
}

/// 执行一次会话：占用判定 → 判定模式 → round → event(running) → turn → 收尾。
fn execute(
    params: &Value,
    body: &Value,
    account_id: &str,
    credentials: super::account::Credentials,
    prepared: Prepared,
) -> std::result::Result<(), CatPawError> {
    // 客户端是否要流式（`params.client_stream`；网关恒发 `stream:true`，
    // 而「客户端要不要流式」由网关聚合，见 lib.rs 的模块头）
    let client_stream = params["client_stream"].as_bool().unwrap_or(true);
    // `stream:false` 的辅助请求（客户端标题/摘要类）**不读也不写**会话映射：
    // 它们的历史末尾常是 assistant，与主对话共用映射会互相覆盖（§9.3 硬约束 3）。
    let stateless = !client_stream;
    let session_id = session_from_params(params);
    let uid = credentials.uid.clone();

    // ── 并发占用（同一 x-session-id 已有流式请求在跑 → 本次走独立 conversation）
    let mut inflight = false;
    if !session_id.is_empty() && !stateless {
        inflight = super::registry::mark_inflight(&session_id);
        if !inflight {
            super::logging::verbose("同一 x-session-id 已有流式请求在跑，本次走独立 conversation");
        }
    }
    let persistent = inflight;

    let facts = RequestFacts {
        body,
        session_id: &session_id,
        account_id,
        uid: &uid,
        persistent,
    };
    let decision = match decision::decide(&facts, &prepared) {
        Ok(decision) => decision,
        Err(error) => {
            // 判定阶段失败也要把占用的标记放开（否则同 session 会被永久挡住）
            if inflight {
                super::registry::release_inflight(&session_id);
            }
            return Err(error);
        }
    };

    // turnRequestId 在 round 之前就定好：它属于本轮，round 之后才有 turn，
    // 而「上一轮被打断」时要用它去 stop
    let mut ctx = TurnContext {
        credentials,
        chat_id: super::ids::new_chat_id(),
        model_name: prepared.resolution.display_name.clone(),
        include_usage: super::openai::include_usage(body),
        choice: prepared.choice.clone(),
        account_id: account_id.to_string(),
        // `uid` 在判定阶段已经取过一次（facts 用），这里直接搬进上下文
        uid,
        model_type: prepared.resolution.model_type,
        session_id: session_id.clone(),
        persistent,
        conversation_id: decision.conversation_id.clone(),
        turn_request_id: super::ids::new_id(),
    };
    let mut history = HistoryFingerprints::new(
        decision
            .session
            .as_ref()
            .map(|session| session.fingerprints.clone())
            .unwrap_or_default(),
        decision::submitted_fingerprints(&decision, prepared.synthetic_tail),
    );
    let mut guard = FinishGuard::new(&ctx, inflight);

    // ── round（工具续接不 round）─────────────────────────────────
    if decision.round_messages.is_some() {
        // 上一轮的工具调用被打断时 conversation 仍停在上游「执行中」，
        // 必须先停掉旧轮次（对齐桌面端的 turn_stop），否则新 round 被拒 ——
        // 这是 §9.3 第二处 turn/stop 的用途。
        if let Some(session) = &decision.session {
            if !session.pending_call_ids.is_empty() {
                if let Some(turn_id) = &session.turn_request_id {
                    upstream::stop_turn(&ctx.credentials, &session.conversation_id, turn_id);
                    upstream::report_terminal(
                        &ctx.credentials,
                        &session.conversation_id,
                        "canceled",
                        None,
                    );
                }
            }
        }
        match submit_round_with_self_heal(&ctx, &prepared, &mut guard, &decision) {
            Ok(RoundOutcome::Fresh) => {}
            Ok(RoundOutcome::Healed) => {
                // 自愈换了 conversation 且**全量**重提交：旧指纹链对新 conversation
                // 毫无意义（它没见过那些消息），前缀必须清空、提交集换成全量 ——
                // 否则下一轮 `locate_increment` 会以为上游已见过整段历史。
                history = HistoryFingerprints::new(
                    Vec::new(),
                    super::fingerprint::fingerprints_for(&prepared.messages),
                );
                ctx.conversation_id = guard.conversation_id.clone();
            }
            Err(error) => {
                // round 没成功：conversation 没建起来（或没进入执行），不必报终态
                drop(guard);
                return Err(error);
            }
        }
    }

    // ── event(running)（工具续接不重复报）────────────────────────
    if decision.round_messages.is_some() {
        if let Err(error) = upstream::report_status(
            &ctx.credentials,
            &guard.conversation_id,
            "running",
            None,
        ) {
            // round 成功但 running 回报失败：上游可能不认这次轮次，
            // 报一个 failed 收尾（尽力而为），再把错误交给客户端
            guard.mark_active();
            guard.close("failed", Some(&error));
            return Err(error);
        }
    }
    guard.mark_active();

    // ── turn 请求体（含「末尾必须是 user」的持久会话校验）───────────
    let TurnBody { body: turn_body, final_type } = build_turn_body(&prepared, &decision, &guard)?;
    super::logging::verbose(&format!(
        "mode={} conversationId={} modelType={} msgs={} roundMsgs={} finalType={} tools={} persistent={} stateless={}",
        decision.mode.as_str(),
        super::logging::short_id(&guard.conversation_id),
        prepared.resolution.model_type,
        prepared.messages.len(),
        decision.round_messages.as_ref().map(Vec::len).unwrap_or(0),
        final_type,
        prepared.selected_tools.len(),
        persistent,
        stateless,
    ));
    if decision.mode != TurnMode::ToolContinuation && final_type != "user" && persistent {
        // 只有持久会话要求轮次以 user 结尾；无状态辅助请求末尾可以是 assistant。
        // 走到这里说明客户端提交的历史与映射对不上（例如上一轮工具会话已失效），
        // 作废映射让它下一轮全量重来
        super::registry::forget(&session_id);
        guard.close("failed", None);
        return Err(CatPawError::bad_request("工具会话已失效，请重新发起当前回合"));
    }

    let response = match upstream::turn_open(&ctx.credentials, &turn_body) {
        Ok(response) => response,
        Err(error) => {
            // turn 在请求头阶段就失败（网络/上游拒绝）：对话已经 round 过了，
            // 不报终态会让上游卡在「执行中」，因此必须报 failed
            guard.close("failed", Some(&error));
            return Err(error);
        }
    };

    // 先报头，再逐帧下发。`stream_head` 之后任何失败都只能写进流里
    // （HTTP 头早发出去了），所以两条边界要分开处理（见 `turn.rs`）。
    super::turn::drive(&ctx, response, &mut guard, &history)?;
    Ok(())
}

/// 从 `params` 取 `x-session-id` 并归一化（原实现 `normalizeClientSessionId`）。
///
/// 归一化规则：非字符串 / 空 / 超 256 个字符一律当「没有会话 id」——
/// 超长 id 不做截断而是丢弃：截断后的 id 会在两次请求之间不稳定地碰撞
/// （前 256 位相同、后面不同的两个客户端会话会被当成同一个）。
///
/// `params.session` 是网关按同一套规则算好的会话键（`plugin_session_id`）；
/// 头部直接给 `x-session-id` 时优先用头部（与 native 的取值点一致）。
fn session_from_params(params: &Value) -> String {
    let headers = &params["headers"];
    let header = ["x-session-id", "X-Session-Id"]
        .iter()
        .find_map(|key| headers.get(*key).and_then(Value::as_str))
        .unwrap_or("");
    let trimmed = header.trim();
    if !trimmed.is_empty() && trimmed.chars().count() <= 256 {
        return trimmed.to_string();
    }
    if !trimmed.is_empty() {
        // 超长头：按 native 的口径丢弃，但回落到网关给的会话键（它已归一化）
        super::logging::verbose("x-session-id 超长，按无会话处理");
    }
    params["session"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.chars().count() <= 256)
        .unwrap_or("")
        .to_string()
}

/// turn 请求体 + 末尾消息类型（类型用于「持久会话必须以 user 结尾」的校验）
struct TurnBody {
    body: Value,
    final_type: String,
}

/// 构造 turn 请求体（UPSTREAM_PROTOCOL §3.2）
fn build_turn_body(
    prepared: &Prepared,
    decision: &Decision,
    guard: &FinishGuard,
) -> Result<TurnBody, CatPawError> {
    let message = match decision.mode {
        TurnMode::ToolContinuation => decision
            .continuation
            .clone()
            .ok_or_else(|| CatPawError::bad_request("工具结果续接请求缺少 tool 消息"))?,
        _ => prepared.final_message.clone(),
    };
    let final_type = message
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let selected_tools = prepared.selected_tools.clone();
    let available: Vec<Value> = selected_tools
        .iter()
        .filter_map(|tool| tool.get("name").cloned())
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("conversationId".to_string(), Value::String(guard.conversation_id.clone()));
    body.insert("turnRequestId".to_string(), Value::String(guard.turn_request_id.clone()));
    body.insert("source".to_string(), Value::String(DEFAULT_SOURCE.to_string()));
    body.insert("action".to_string(), Value::String("turn".to_string()));
    body.insert("message".to_string(), message);
    body.insert("modelType".to_string(), Value::from(prepared.resolution.model_type));
    body.insert("mode".to_string(), Value::String(DEFAULT_MODE.to_string()));
    body.insert("permissionMode".to_string(), Value::String(PERMISSION_MODE.to_string()));
    body.insert("toolVersion".to_string(), Value::String(DEFAULT_TOOL_VERSION.to_string()));
    body.insert("toolConfigs".to_string(), Value::Array(selected_tools));
    body.insert("availableTools".to_string(), Value::Array(available));
    if let Some(system_prompt) = &prepared.system_prompt {
        body.insert(
            "systemPromptContext".to_string(),
            json!({ "systemPromptOverride": system_prompt }),
        );
    }
    if let Some(rules_message) = &prepared.rules_message {
        body.insert("rulesMessage".to_string(), Value::String(rules_message.clone()));
    }
    Ok(TurnBody { body: Value::Object(body), final_type })
}

/// round 的两种成功形态（决定调用方要不要重建指纹链）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RoundOutcome {
    /// 按判定结果提交（长会话增量 / 全新会话全量）
    Fresh,
    /// 自愈后**全量**重提交（conversation 也是新的）
    Healed,
}

/// round 提交 + 「会话正在执行中」的自愈重试（native 模块头差异 3）。
///
/// 只在**长会话新轮次**模式上重试，且只重试一次：失败消息里出现「执行中」
/// （上游原文 `会话正在执行中，无法创建新轮次`）时，说明会话记录记的
/// conversationId 在上游仍处于 running，而我们拿不到它的 turnRequestId
/// （插件换了实例、TTL 淘汰都会让它丢失）。此时把映射作废、改成**全新会话
/// 全量 round**，客户端这一次请求就能走通。
fn submit_round_with_self_heal(
    ctx: &TurnContext,
    prepared: &Prepared,
    guard: &mut FinishGuard,
    decision: &Decision,
) -> Result<RoundOutcome, CatPawError> {
    let round_messages = decision.round_messages.clone().unwrap_or_default();
    match submit_round(ctx, prepared, guard, &round_messages) {
        Ok(()) => Ok(RoundOutcome::Fresh),
        Err(error) if decision.mode == TurnMode::SessionRound && error.is_busy() => {
            super::logging::verbose("上一轮仍在上游执行中，作废会话映射并改为全新会话重试一次");
            super::registry::forget(&ctx.session_id);
            guard.conversation_id = super::ids::new_id();
            submit_round(ctx, prepared, guard, &prepared.messages).map(|()| RoundOutcome::Healed)
        }
        Err(error) => Err(error),
    }
}

/// 真正发一次 round（请求体见 UPSTREAM_PROTOCOL §3.1）
fn submit_round(
    ctx: &TurnContext,
    prepared: &Prepared,
    guard: &FinishGuard,
    round_messages: &[Value],
) -> Result<(), CatPawError> {
    let mut body = serde_json::Map::new();
    body.insert("conversationId".to_string(), Value::String(guard.conversation_id.clone()));
    body.insert("source".to_string(), Value::String(DEFAULT_SOURCE.to_string()));
    body.insert("messages".to_string(), Value::Array(round_messages.to_vec()));
    body.insert("modelType".to_string(), Value::from(prepared.resolution.model_type));
    body.insert("mode".to_string(), Value::String(DEFAULT_MODE.to_string()));
    body.insert("permissionMode".to_string(), Value::String(PERMISSION_MODE.to_string()));
    body.insert("toolVersion".to_string(), Value::String(DEFAULT_TOOL_VERSION.to_string()));
    if let Some(system_prompt) = &prepared.system_prompt {
        body.insert(
            "systemPromptContext".to_string(),
            json!({ "systemPromptOverride": system_prompt }),
        );
    }
    if let Some(rules_message) = &prepared.rules_message {
        body.insert("rulesMessage".to_string(), Value::String(rules_message.clone()));
    }
    let mut declarative = serde_json::Map::new();
    if let Some(effort) = &prepared.effort {
        declarative.insert("effort".to_string(), Value::String(effort.clone()));
    }
    if let Some(context) = &prepared.context {
        declarative.insert("context".to_string(), Value::String(context.clone()));
    }
    if !declarative.is_empty() {
        body.insert(
            "requestContext".to_string(),
            json!({ "modelParams": { "declarativeParams": Value::Object(declarative) } }),
        );
    }
    upstream::submit_round(&ctx.credentials, &Value::Object(body))?;
    super::logging::verbose(&format!(
        "round 完成 conversationId={} msgs={}",
        super::logging::short_id(&guard.conversation_id),
        round_messages.len(),
    ));
    Ok(())
}

/// 成功轮次要写回会话记录的指纹链（原实现 `catpaw-upstream-client.mjs` 第 529-533 行）。
///
/// 组成 = **旧链**（命中会话时它已有的）+ 本轮**实际提交**的消息指纹 +
/// 上游返回的那条消息指纹。
///
/// 「实际提交的」必须与发出去的一致：长会话只提交增量、工具续接只提交那条
/// tool 消息 —— 多算会让下一次 `locate_increment` 在客户端历史里定位到错误的
/// 位置（增量从错误的地方开始，上游看到的历史就断层了）。
pub struct HistoryFingerprints {
    prefix: Vec<String>,
    submitted: Vec<String>,
}

impl HistoryFingerprints {
    pub fn new(prefix: Vec<String>, submitted: Vec<String>) -> Self {
        Self { prefix, submitted }
    }

    /// 补上上游返回消息的指纹，得到最终要登记的链
    pub fn chain(&self, response_message: &Value) -> Vec<String> {
        let mut chain = self.prefix.clone();
        chain.extend(self.submitted.iter().cloned());
        chain.push(super::fingerprint::message_fingerprint(response_message));
        chain
    }
}

/// 成功轮次后的状态写回（native `write_back` 的逐条对齐）。
///
/// ── 四种组合（与原实现逐条对齐）──────────────────────────────
/// | 有没有工具调用 | 是不是长会话 | 写什么 |
/// |---|---|---|
/// | 有 | 任意 | 「等工具结果」记录（`pending_call_ids` → call 索引） |
/// | 无 | 长会话 | 覆盖登记长会话记录（指纹链前移、清空待响应） |
/// | 无 | 无状态/并发冲突 | **不登记** |
///
/// ── 为什么「无工具调用的无状态请求」一条都不写 ─────────────────
/// 无状态请求（客户端标题/摘要类）不读不写映射是 §9.3 的硬约束：写了会让主对话
/// 的下一次 round 拿到一份错误的历史。
pub fn write_back(
    ctx: &TurnContext,
    guard: &FinishGuard,
    history: &HistoryFingerprints,
    result: &super::openai::TurnResult,
) {
    // 一轮结果的元数据（只打长度不打正文：与注册表同一条隐私口径）
    super::logging::verbose(&format!(
        "轮次产出 content={} 字符 reasoning={} 字符 toolCalls={}",
        result.text.chars().count(),
        result.reasoning.chars().count(),
        result.tool_calls.len(),
    ));
    let pending = call_ids(&result.tool_calls);
    // 并发冲突时走的是独立 conversation：**不写映射**（写进去会让下一个同
    // session 请求错误地续接到这条并行历史），与无状态请求同待遇
    let session_id = if ctx.persistent { ctx.session_id.clone() } else { String::new() };
    if session_id.is_empty() && pending.is_empty() {
        return;
    }
    let now = sdk::now();
    let conversation_id = if result.conversation_id.is_empty() {
        guard.conversation_id.clone()
    } else {
        result.conversation_id.clone()
    };
    let record = super::registry::SessionRecord {
        conversation_id,
        fingerprints: history.chain(&result.message),
        model_type: ctx.model_type,
        account_id: ctx.account_id.clone(),
        uid: ctx.uid.clone(),
        session_id,
        pending_call_ids: pending,
        // 等工具结果时要带上「哪个 turn 在跑」：下一轮若发现会话仍在等待，
        // 要先 stop 掉它才能 round（§9.3 第二处 turn/stop 用途）
        turn_request_id: if call_ids(&result.tool_calls).is_empty() {
            None
        } else {
            Some(guard.turn_request_id.clone())
        },
        updated_at: now,
    };
    super::registry::save(&record);
}

/// tool_calls → 待响应 id 列表
fn call_ids(tool_calls: &[Value]) -> Vec<String> {
    tool_calls
        .iter()
        .filter_map(|call| call.get("id").and_then(Value::as_str))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_builds_messages_and_tools() {
        let body = json!({
            "model": "glm-5.3-flash",
            "messages": [
                { "role": "system", "content": "你是助手" },
                { "role": "user", "content": "你好" }
            ],
            "tools": [{ "type": "function", "function": { "name": "read", "parameters": {"type":"object"} } }],
            "tool_choice": "auto",
            "reasoning_effort": "high",
            "context_window": "500K"
        });
        let prepared = prepare(&body);
        // 失败原因带上错误文案（`assert` 本身就是测试的失败出口，不用 panic! / unwrap）
        assert!(
            prepared.is_ok(),
            "prepare 不应失败：{}",
            prepared.as_ref().err().map(|error| error.message.as_str()).unwrap_or("")
        );
        if let Ok(prepared) = prepared {
            assert_eq!(prepared.resolution.model_type, 91);
            assert_eq!(prepared.messages.len(), 1);
            assert_eq!(prepared.system_prompt.as_deref(), Some("你是助手"));
            assert_eq!(prepared.effort.as_deref(), Some("high"));
            assert_eq!(prepared.context.as_deref(), Some("512000"));
            assert_eq!(prepared.selected_tools.len(), 1);
            assert!(!prepared.synthetic_tail);
        }
    }

    #[test]
    fn prepare_appends_synthetic_tail_after_tool_history() {
        let body = json!({
            "model": "kimi-k3",
            "messages": [
                { "role": "user", "content": "查" },
                { "role": "assistant", "content": null, "tool_calls": [{"id":"c1","type":"function","function":{"name":"f","arguments":"{}"}}] },
                { "role": "tool", "tool_call_id": "c1", "content": "好" }
            ]
        });
        let prepared = prepare(&body);
        assert!(
            prepared.is_ok(),
            "prepare 不应失败：{}",
            prepared.as_ref().err().map(|error| error.message.as_str()).unwrap_or("")
        );
        if let Ok(prepared) = prepared {
            assert!(prepared.synthetic_tail);
            assert_eq!(prepared.messages.len(), 4);
            assert_eq!(prepared.messages.last().and_then(message_type), Some("user"));
        }
    }

    #[test]
    fn prepare_rejects_bad_inputs() {
        assert!(prepare(&json!({"model":"nope","messages":[{"role":"user","content":"a"}]})).is_err());
        assert!(prepare(&json!({"model":"kimi-k3","messages":[]})).is_err());
        assert!(prepare(&json!({"model":"kimi-k3","messages":[{"role":"user","content":"a"}],"parallel_tool_calls":"yes"})).is_err());
    }

    #[test]
    fn session_prefers_header_then_param() {
        let params = json!({ "headers": { "x-session-id": " s1 " }, "session": "s2" });
        assert_eq!(session_from_params(&params), "s1");
        let long = "x".repeat(300);
        let params = json!({ "headers": { "x-session-id": long }, "session": "s2" });
        assert_eq!(session_from_params(&params), "s2");
        let params = json!({ "headers": {}, "session": "s3" });
        assert_eq!(session_from_params(&params), "s3");
    }
}
