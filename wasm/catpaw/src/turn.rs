//! CatPaw **轮次执行层**：turn 的 SSE 消费、翻译与收尾（native `turn_executor.rs`）。
//!
//! ── 与 `conversation.rs` 的分工 ──────────────────────────────
//! `conversation.rs` 管**决策与请求体**（轮次判定、round/turn 的 body 构造）；
//! 本文件管**执行与收尾**：
//!
//! ```text
//! conversation.rs                          turn.rs
//!   判定模式 → round → event(running)        读上游 SSE 分片
//!   → build turn body ────────────────────→  逐帧翻译（openai.rs）
//!                                            读到底（硬约束 2）
//!                                            写回 / 终态上报 / [DONE]
//! ```
//!
//! ── 两种边界的处理（与 atomcode 的 `chat.rs` 同一口径）────────
//!   - **尚未下发就出错**（`stream_head` 之前）：返回 `Err`，客户端拿到正常的
//!     OpenAI 错误体；
//!   - **已下发后出错**（`stream_head` 之后）：HTTP 头早发出去了，只能发一条
//!     流内错误帧（`error` 字段 + `finish_reason:"stop"`）再补 `[DONE]`，
//!     然后仍然返回 `Err` —— 宿主据此记一条失败，而不是一次「成功但空」。
//!
//! ── 失败要进记账旁路（native W5 修复的 wasm 等价物）────────────
//! 宿主侧只按「调用是否返回错误」判断这次请求成不成功，所以协议层在收尾前
//! 必须把失败返回出去（不是吞掉）。真实的上游/翻译失败与「客户端取消」分开：
//! 取消走 interrupt 且不当作上游故障。
//!
//! ── 为什么先攒帧再 flush ────────────────────────────────────
//! 翻译层的写入是同步的（一个上游事件可能产出多帧），而 `stream_bytes` 是
//! 逐次 RPC。统一在「处理完一个上游 chunk」之后 flush 一次，既有背压
//! （不丢帧），又不必把翻译层的签名变成异步。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, http, json, Value};

use super::conversation::{FinishGuard, HistoryFingerprints, TurnContext};
use super::errors::CatPawError;
use super::openai::{self, TurnResult, TurnTranslator, DONE_FRAME};
use super::sse::{is_done, Decoder};

/// 流式分支：把上游 SSE 翻译成 OpenAI chunk 交给客户端，读到底后收尾。
///
/// `prepared` 不进来：轮次素材（工具集 / 消息）在 `conversation.rs` 组装请求体时
/// 就已经用完了，执行层只看上游的流与收尾状态。
pub fn drive(
    ctx: &TurnContext,
    mut response: http::Response,
    guard: &mut FinishGuard,
    history: &HistoryFingerprints,
) -> Result<(), CatPawError> {
    // ── 先报头（此后一切错误都只能写进流里）─────────────────────
    // 网关的翻译机按 `UpstreamKind::Chat` 走（本家自己产 OpenAI 帧，
    // 与 Trae / Qoder 同一处置）。
    sdk::stream_head(200).map_err(|error| {
        CatPawError::upstream(format!("客户端已断开，未能下发响应头: {}", error.message))
    })?;

    let mut translator = TurnTranslator::new(
        ctx.chat_id.clone(),
        ctx.model_name.clone(),
        ctx.include_usage,
        ctx.choice.clone(),
    );
    // 首帧 role：客户端据此建立 assistant 消息（原实现进入事件循环前先发一次）
    let mut pending: Vec<String> = vec![translator.role_frame()];
    let mut downstream = true;
    flush(&mut pending, &mut downstream)?;

    let mut decoder = Decoder::default();
    let mut outcome: Result<TurnResult, CatPawError> =
        Err(CatPawError::upstream("上游没有返回消息"));
    let mut finished = false;
    while !finished {
        match response.read() {
            // HTTP EOF 是未发送 DONE 时的收尾兜底：残帧仍要处理
            Ok(None) => {
                if let Some(payload) = decoder.finish() {
                    match consume_payload(&mut translator, &payload, &mut pending) {
                        Ok(true) => {
                            outcome = translator.finish(&mut pending);
                            finished = true;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            outcome = Err(error);
                            finished = true;
                        }
                    }
                }
                if !finished {
                    outcome = translator.finish(&mut pending);
                    finished = true;
                }
            }
            Ok(Some(chunk)) => {
                let events = match decoder.push(&chunk) {
                    Ok(events) => events,
                    Err(message) => {
                        outcome = Err(CatPawError::upstream(message));
                        finished = true;
                        Vec::new()
                    }
                };
                for payload in events {
                    match consume_payload(&mut translator, &payload, &mut pending) {
                        Ok(true) => {
                            outcome = translator.finish(&mut pending);
                            finished = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(error) => {
                            outcome = Err(error);
                            finished = true;
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                if let Some(payload) = decoder.finish() {
                    // 残帧里的错误优先（它是上游真正说的话）
                    if let Err(inner) = consume_payload(&mut translator, &payload, &mut pending) {
                        outcome = Err(inner);
                    } else {
                        outcome = Err(CatPawError::upstream(format!(
                            "上游流式传输中断: {}",
                            error.message
                        )));
                    }
                } else {
                    outcome = Err(CatPawError::upstream(format!(
                        "上游流式传输中断: {}",
                        error.message
                    )));
                }
                finished = true;
            }
        }
        flush(&mut pending, &mut downstream)?;
        if !downstream {
            // ── wasm 侧与 native 的差异（见模块头差异 3）───────────
            // native 会继续把上游流读到底再收尾；wasm 里客户端断开意味着宿主
            // 已经不再收帧，继续读只会拖住这次调用。这里改成「立即打断上游轮次
            // 并回报 canceled」，仍然满足「上游不能停在执行中」。
            super::logging::verbose("客户端断开，打断上游轮次并回报 canceled");
            guard.interrupt();
            guard.close("canceled", None);
            return Ok(());
        }
    }
    finish(ctx, guard, history, outcome, &mut pending, &mut downstream)
}

/// 处理一条 SSE 数据帧。
///
/// 返回 `Ok(true)` 表示遇到完整 `[DONE]`（轮次在协议层结束）；
/// `Ok(false)` 表示正常消费；`Err` 表示上游/翻译错误。
fn consume_payload(
    translator: &mut TurnTranslator,
    payload: &str,
    pending: &mut Vec<String>,
) -> Result<bool, CatPawError> {
    if payload.trim().is_empty() {
        return Ok(false);
    }
    if is_done(payload) {
        return Ok(true);
    }
    // 无法解析的事件忽略（原实现 `parse_data` 同：上游偶发非 JSON 心跳）
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        super::logging::verbose("忽略无法解析的 SSE 事件");
        return Ok(false);
    };
    // `code != 0/200` 是上游业务错误（写在 200 的流里），必须当成失败
    let value = openai::unwrap_api_data(value)?;
    translator.consume(&value, pending)?;
    Ok(false)
}

/// 把攒下的帧发给客户端，发完的帧从缓冲里移出；发送失败说明客户端已经断开
/// （`downstream = false`，剩余帧全部丢弃）。
///
/// ── 为什么必须「发一帧移一帧」───────────────────────────────
/// 如果只遍历不清空，下一轮循环会把已经发出去的帧再发一遍 —— 客户端会看到
/// 重复的正文/工具参数增量。这是最容易写错的一处，所以清空与发送放在同一次
/// 借用里完成（先发、再按已发数 drain）。
fn flush(pending: &mut Vec<String>, downstream: &mut bool) -> Result<(), CatPawError> {
    if !*downstream {
        pending.clear();
        return Ok(());
    }
    let mut sent = 0_usize;
    let mut broken = false;
    for frame in pending.iter() {
        if !frame.is_empty() && sdk::stream_bytes(frame.as_bytes()).is_err() {
            broken = true;
            break;
        }
        sent += 1;
    }
    pending.drain(..sent);
    if broken {
        *downstream = false;
        pending.clear();
    }
    Ok(())
}

/// 收尾一条轮次：写回会话记录 + 终态上报 + `[DONE]` / 错误帧。
fn finish(
    ctx: &TurnContext,
    guard: &mut FinishGuard,
    history: &HistoryFingerprints,
    outcome: Result<TurnResult, CatPawError>,
    pending: &mut Vec<String>,
    downstream: &mut bool,
) -> Result<(), CatPawError> {
    // 每次 flush 后帧已发出，这里先清空再收尾追加（避免重复下发）
    pending.clear();
    match outcome {
        Ok(result) => {
            super::conversation::write_back(ctx, guard, history, &result);
            if result.tool_calls.is_empty() {
                // 轮次正常结束：必须回报 completed（硬约束 1），否则下一轮 round 被拒
                guard.close("completed", None);
            } else {
                // 例外：返回了工具调用 —— 这一轮在上游语义里**还没结束**（客户端
                // 马上带着 tool 结果回来续接），因此不报终态、只释放占用
                super::logging::verbose(&format!(
                    "轮次 {} 返回 {} 个工具调用，等待客户端续接（不报 completed）",
                    super::logging::short_id(&guard.conversation_id),
                    result.tool_calls.len(),
                ));
                guard.release();
            }
            pending.push(DONE_FRAME.to_string());
            flush(pending, downstream)?;
            Ok(())
        }
        Err(error) => {
            // 取消判定必须**先于**末尾的 flush：同一批次里的发送失败若在这里
            // 之后才被观察到，会把已经发生的上游错误误判成客户端断开
            let canceled = !*downstream;
            if canceled {
                // 客户端取消是用户行为、不是上游故障：打断上游轮次后回报 canceled
                guard.interrupt();
                guard.close("canceled", None);
                return Ok(());
            }
            // 已下发后出错：错误帧 + [DONE]，然后仍返回 Err（宿主据此记失败）
            pending.push(stream_error_frame(ctx, &error));
            pending.push(DONE_FRAME.to_string());
            let result = flush(pending, downstream);
            guard.close("failed", Some(&error));
            result?;
            Err(error)
        }
    }
}

/// 流内错误帧（原实现 `streamErrorChunk`：`delta:{}` + `finish_reason:"stop"`
/// + `error` 字段）—— HTTP 头早就发出去了，只能这样告诉客户端这次补全失败了。
fn stream_error_frame(ctx: &TurnContext, error: &CatPawError) -> String {
    let translator = TurnTranslator::new(
        ctx.chat_id.clone(),
        ctx.model_name.clone(),
        false,
        super::tools::ToolChoice::Auto,
    );
    translator.error_frame(&error.message, error.status)
}

/// 非流式响应的聚合体（native `completion_body`）。
///
/// ── 为什么 wasm 侧不用它 ────────────────────────────────────
/// 网关对 wasm 插件**恒发 `stream:true`**，非流式由网关自己把帧聚合成完整
/// JSON（`aggregate_frame_stream`，见 `plugin_host/rpc.rs` 的注释）。插件只写
/// 一条流式路径即可，不必再实现一份「聚合成本」—— 两份规则迟早会分叉。
///
/// 保留这个函数是因为 `openai.rs` 的 `TurnResult` 仍然产出非流式消息，
/// 排障（或将来宿主放开非流式入口）时要用。
#[allow(dead_code)]
pub fn completion_body(ctx: &TurnContext, result: &TurnResult) -> Value {
    json!({
        "id": ctx.chat_id,
        "object": "chat.completion",
        "created": super::now_seconds(),
        "model": ctx.model_name,
        "choices": [{
            "index": 0,
            "message": result.openai_message,
            "finish_reason": result.finish_reason(),
        }],
        "usage": result.final_usage(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_done_detection() {
        let mut translator = TurnTranslator::new("id", "m", false, super::super::tools::ToolChoice::Auto);
        let mut pending = Vec::new();
        assert!(consume_payload(&mut translator, "[DONE]", &mut pending).unwrap_or(false));
        assert!(!consume_payload(&mut translator, "not json", &mut pending).unwrap_or(true));
    }

    #[test]
    fn payload_business_error_is_failure() {
        let mut translator = TurnTranslator::new("id", "m", false, super::super::tools::ToolChoice::Auto);
        let mut pending = Vec::new();
        // 上游把业务码写在 200 的流里；`httpStatus` 决定透出的状态码
        let payload = r#"{"code":400,"msg":"会话正在执行中，无法创建新轮次","httpStatus":400}"#;
        let error = consume_payload(&mut translator, payload, &mut pending).err();
        assert_eq!(error.map(|error| error.status), Some(400));
        // 没给 httpStatus 时按下 502（与 native `unwrapApiData` 同口径）
        let payload = r#"{"code":500,"msg":"内部错误"}"#;
        let error = consume_payload(&mut translator, payload, &mut pending).err();
        assert_eq!(error.map(|error| error.status), Some(502));
    }
}
