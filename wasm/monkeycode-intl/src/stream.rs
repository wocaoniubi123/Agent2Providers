//! MonkeyCode 任务流（WebSocket）的连接与驱动（会话转发的第二步）。
//!
//! 下行消息与 ACP 事件 → OpenAI 帧的翻译在 `translate.rs`；本文件管：
//! 握手（URL / 头）、自动审批设置、心跳回复的发送时机、无进展 / 总时长超时，
//! 以及收尾（关连接 + **停止上游任务**）。
//!
//! ── 上游长什么样（参考 `task-runner.ts` 与 `docs/04-websocket/*`）──────
//! ```text
//!   WS   wss://<站点>/api/v1/users/tasks/stream?id=<taskId>&mode=attach
//!   环境就绪后订阅首轮历史与实时输出，不重复提交已在创建请求中的 content；
//!   下行是 {type, kind?, data?, timestamp?} 的 JSON 文本帧；**`data` 一律是
//!   base64(JSON)**（见 `wire.rs` 的模块头）
//! ```
//!
//! ── 为什么必须有状态、为什么走 WS ──────────────────────────────
//! 一次客户端请求 = 「建任务 → 挂任务流 → 等轮次结束」，任务 id 由上游生成、
//! 事件由 VM 内的 coding agent 实时推送 —— 不是「一次 HTTP 请求一次回答」。
//!
//! ── 终态怎么判（不挂死的关键）─────────────────────────────────
//! 四个出口，**每个都会给下游一个收尾**（`finish` 帧 + `[DONE]`，或错误帧）：
//!   1. `task-ended` → 正常收尾；
//!   2. `task-error` / `error` → 异常收尾（错误帧）；
//!   3. 连接被关 / 传输错误（没等到 task-ended）→ 异常收尾；
//!   4. 无进展超时（默认 300 秒没有模型输出或执行进展，心跳不延后期限），
//!      或总时长超过 1 小时（与 `resource.life` 对齐）→ 异常收尾。
//! 参考在这几处是「静默 resolve、靠客户端等 EOF」；本包必须显式收尾 ——
//! 客户端的 SSE 解析器等的是 `[DONE]`，只断连接会被渲染成「回答被截断」。
//!
//! ── 收尾还要**停止上游任务**（10811 的根因，别漏）──────────────
//! 上游的并发额度按「`pending` + `processing` 的任务数」算（业务码 10811），
//! 而 `task-ended` **只结束本轮、不结束任务**。本包每个下游请求都新建任务，
//! 因此每条收尾路径都必须显式 `PUT /users/tasks/stop`（见 `client::stop_task`）。
//!
//! ── 自动批准 / 自动回复（MonkeyCode 能不能用的关键）──────────────
//!   - `auto-approve`：连接建立后立刻发一次（参考 `on("open")`）。Agent 的
//!     工具调用因此不再等用户确认 —— 不发这一条，任务会停在第一个工具调用；
//!   - 逐工具审批（`permission-req`）→ 自动回 `permission-resp`（双保险，见
//!     `translate.rs`）；
//!   - Agent 提问（`kind=acp_ask_user_question`）→ 自动回 `reply-question`。
//!
//! ── 与 native 的两处必要差异 ─────────────────────────────────
//! 1. **超时靠 `sdk::now()`**：`std::time::Instant` 在 `wasm32-unknown-unknown`
//!    上不可用（会 panic），时间一律用宿主的 `clock.now`。另外宿主 `ws.read`
//!    自身最长阻塞 20 秒（返回 `{"type":"pending"}`），所以「无进展」的判定
//!    精度是「每 20 秒一次」—— 对 300 秒的阈值没有实质影响。
//! 2. **没有 `StopOnDrop`**：native 在 future 被丢弃时用 `Drop` + `tokio::spawn`
//!    补一次停止；wasm 侧既没有异步 Drop，也不能在同步 Drop 里发网络请求。
//!    这里的兜底改成「下一次撞 10811 时自愈清理」（见 `task.rs`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，不持任何锁。

use agent2api_wasm_sdk::{self as sdk, json, websocket::WebSocket, Error, Result, Value};

use super::base64;
use super::credentials::Credentials;
use super::translate::{handle_message, Terminal, Translator, DONE_FRAME};
use super::{client, endpoints, inflight, logging};

/// 任务总时长上限：与建任务的 `resource.life`（1 小时）对齐。
///
/// 参考 `TASK_TIMEOUT_MS = 3600000`，注释原文「matches resource.life」——
/// 到点后上游 VM 本来也要回收，继续等只会挂死下游。
const TASK_TIMEOUT_MS: i64 = 60 * 60 * 1000;

/// 无进展等待的期限（网关 `DEFAULT_TIMEOUT_STREAM_IDLE_SECONDS = 300` 的同值）。
///
/// native 读 `timeouts::current().stream_idle_ms().max(MIN_IDLE_MS)`；wasm 侧
/// 没有读网关超时配置的宿主入口，因此钉死默认值（同 `startup.rs` 的说明）。
const IDLE_TIMEOUT_MS: i64 = 300_000;

/// 驱动出口：正常 / 上游异常 / 客户端断开（三者收尾动作不同）。
enum Outcome {
    Done(Terminal),
    ClientGone,
}

/// 连任务流（`mode=attach`：回放首轮历史 + 接收实时输出）。
///
/// ── 失败翻译 ────────────────────────────────────────────────
/// 握手被拒时宿主给的是「WebSocket 握手失败：HTTP 4xx/5xx」；401/403 按登录态
/// 失效报 401，其余按上游故障报 502（与 native 的码表同口径）。
pub fn connect(credentials: &Credentials, task_id: &str) -> Result<WebSocket> {
    let url = endpoints::stream_url(task_id, "attach");
    let socket = WebSocket::open(&url, endpoints::ws_headers(&credentials.session), &[])
        .map_err(|error| {
            let message = error.message;
            let unauthorized = message.contains("HTTP 401") || message.contains("HTTP 403");
            let status = if unauthorized { 401 } else { 502 };
            let mut mapped = Error::http(
                status,
                if unauthorized {
                    format!("MonkeyCode 任务流握手被拒（登录态失效）：请重新粘贴 session（{message}）")
                } else {
                    format!("MonkeyCode 任务流连接失败：{message}")
                },
            );
            mapped.code = if unauthorized { Some("token_expired".to_string()) } else { None };
            mapped
        })?;
    logging::verbose(&format!(
        "[MonkeyCode] 任务流已连接 task={}（mode=attach）",
        logging::short_id(task_id)
    ));
    Ok(socket)
}

/// 首轮输入已由创建请求提交，这里只设置后续工具审批策略。
pub fn start(socket: &WebSocket) -> Result<()> {
    socket
        .send_text(&json!({ "type": "auto-approve" }).to_string())
        .map_err(|error| Error::http(502, format!("MonkeyCode 任务流发送自动审批设置失败：{}", error.message)))?;
    logging::verbose("[MonkeyCode] 已连接首轮结果并设置 auto-approve");
    Ok(())
}

/// 驱动任务流直到终态，收尾时停止上游任务。
///
/// ── 返回值语义（与 `conversation.rs` 的分工）──────────────────
/// `Err` 只在**客户端已断开**（`stream_bytes` 失败）时返回 —— 那种情况下本次
/// 转发确实没完成。上游侧的失败已经转成流内错误帧 + `[DONE]` 推给客户端，
/// 不算 `Err`（HTTP 头早发出去了，网关只能看到一条已经收尾的流）。
pub fn drive(socket: WebSocket, mut translator: Translator, task_id: &str, session: &str) -> Result<()> {
    let mut pending: Vec<String> = Vec::new();
    if let Some(frame) = translator.role_frame() {
        pending.push(frame);
    }
    // 首帧就发不出去 = 客户端在报头之后立刻断开：直接收尾，不白跑一趟上游
    if !emit(&pending) {
        pending.clear();
        drop(socket);
        close_and_stop(task_id, session);
        return Err(Error::http(499, "客户端已断开，任务流转发停止"));
    }
    pending.clear();
    let started = sdk::now();
    let mut last_progress = started;
    let outcome = loop {
        let now = sdk::now();
        if now.saturating_sub(started) >= TASK_TIMEOUT_MS {
            break Outcome::Done(Terminal::Failed(
                "任务流超过 1 小时上限（与上游 resource.life 对齐）".to_string(),
            ));
        }
        if now.saturating_sub(last_progress) >= IDLE_TIMEOUT_MS {
            break Outcome::Done(Terminal::Failed(format!(
                "任务连续 {} 秒没有模型输出或执行进展（心跳不计入进展），已停止等待",
                IDLE_TIMEOUT_MS / 1000
            )));
        }
        let message = match socket.read() {
            Ok(value) => value,
            Err(error) => {
                break Outcome::Done(Terminal::Failed(format!("任务流读取失败：{}", error.message)))
            }
        };
        let text = match message.get("type").and_then(Value::as_str).unwrap_or("") {
            "text" => message
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            "binary" => {
                let raw = message.get("data").and_then(Value::as_str).unwrap_or("");
                match base64::decode(raw) {
                    Some(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    None => {
                        logging::verbose("[MonkeyCode] 忽略二进制帧（base64 解码失败）");
                        continue;
                    }
                }
            }
            // 宿主每 20 秒回一次 pending：没有事件不算进展，也不延长期限
            "pending" => continue,
            "close" => {
                break Outcome::Done(Terminal::Failed(
                    "任务流连接已关闭（未收到 task-ended）".to_string(),
                ))
            }
            _ => {
                break Outcome::Done(Terminal::Failed(
                    "任务流传输中断：连接返回了错误帧".to_string(),
                ))
            }
        };
        let handled = handle_message(&mut translator, &text);
        if handled.progress {
            last_progress = sdk::now();
        }
        pending.extend(handled.frames);
        if let Some(reply) = handled.reply {
            if let Err(error) = socket.send_text(&reply) {
                break Outcome::Done(Terminal::Failed(format!(
                    "任务流回复失败：{}",
                    error.message
                )));
            }
        }
        if let Some(next) = handled.terminal {
            break Outcome::Done(next);
        }
        if !pending.is_empty() {
            let frames = std::mem::take(&mut pending);
            if !emit(&frames) {
                break Outcome::ClientGone;
            }
        }
    };
    // ── 收尾：先把该发的帧发完，再关连接，最后停止上游任务 ────────
    match &outcome {
        Outcome::Done(Terminal::Ended) => {
            let frames = std::mem::take(&mut pending);
            let _ = emit(&frames);
            logging::verbose(&format!(
                "[MonkeyCode] 任务 {} 正常结束（{}）",
                logging::short_id(task_id),
                translator.summary()
            ));
        }
        Outcome::Done(Terminal::Failed(reason)) => {
            let message = format!("MonkeyCode {reason}");
            logging::warn(&format!("[MonkeyCode] ❌ {message}"));
            pending.push(translator.error_frame(&message));
            pending.push(DONE_FRAME.to_string());
            let frames = std::mem::take(&mut pending);
            let _ = emit(&frames);
        }
        // 客户端已经断开：它不收帧了，继续发没有意义（参考 abort 分支同）
        Outcome::ClientGone => {}
    }
    // 丢掉 socket 会向对端发一条 WebSocket close（宿主 `ws.close`）
    drop(socket);
    close_and_stop(task_id, session);
    match outcome {
        Outcome::ClientGone => Err(Error::http(499, "客户端已断开，任务流转发停止")),
        // 上游失败已经进流内收尾（头早发出去了），不算本次调用失败
        Outcome::Done(_) => Ok(()),
    }
}

/// 停止上游任务并注销在途登记。
///
/// 停止失败不影响本轮结论：`stop_task` 只返回 bool，不抛错。先注销再停止：
/// 自愈路径要能看到「这个任务已经不归任何人管了」—— 顺序其实两种都对（停止
/// 成功后任务本就不在运行中列表里），但先注销能覆盖「停止请求失败、任务仍占着
/// 槽位」的情况 —— 那时下一次自愈应该能把它当残留清掉。
fn close_and_stop(task_id: &str, session: &str) {
    inflight::unregister(task_id);
    client::stop_task(session, task_id);
}

/// 把待发帧交给下游；返回 false = 客户端已断开。
fn emit(frames: &[String]) -> bool {
    for frame in frames {
        // 背压在这里：窗口满时宿主的 stream.chunk 调用会挂起
        if sdk::stream_bytes(frame.as_bytes()).is_err() {
            return false;
        }
    }
    true
}
