//! MonkeyCode 会话转发入口（装配层）：建任务 → 连任务流 → 翻译成 OpenAI 流。
//!
//! ── 这一层解决什么问题 ──────────────────────────────────────
//! 一次客户端请求在上游是**多步会话**：
//! ```text
//!   ① 凭证快照（session + image_id；缺 image_id 直接报可读错误）
//!   ② 模型名 → 目录条目（upstreamId）                  models::resolve_task_model
//!   ③ OpenAI messages → prompt（system 单列）          task::build_prompt
//!   ④ POST /api/v1/users/tasks 建任务                  task::create_task
//!   ⑤ 等任务环境就绪                                startup::wait_ready
//!   ⑥ 连 wss://…/tasks/stream?id=&mode=attach           stream::connect
//!      首轮 content 已由上游自动执行，只设置 auto-approve
//!   ⑦ 消费 ACP 事件 → 本网关的 OpenAI 兼容流            stream::drive
//!   ⑧ PUT /api/v1/users/tasks/stop 收尾（**必须**）     client::stop_task
//! ```
//! 四 ~ 六步失败时**还没有给客户端任何字节**，因此按普通错误返回（带状态码，
//! 编排层照常换账号 / 透传）；七步之后头已发出，错误只能进流内（见 `stream.rs`）。
//!
//! ── 第八步为什么是必须的（10811 的根因）────────────────────────
//! 上游的任务状态只有 `pending` / `processing` / `finished` / `error`，而并发
//! 额度按「`pending` + `processing` 的任务数」算（业务码 **10811**）。关键语义：
//! **`task-ended` 只结束本轮，不结束任务** —— 任务会停在 `processing` 给多轮
//! 复用留窗口。本包每个下游请求都新建一个任务，因此每轮收尾都必须显式停止；
//! 否则账号槽位会被占到 VM 空闲回收（默认 3 天），第二次请求就稳定撞 10811。
//!
//! 停止动作覆盖的路径（漏一条就漏一个槽位）：
//!   - `stream.rs` 的四个终态出口 + 两处「客户端已断开」；
//!   - 本文件的 ⑤ / ⑥ / ⑦ 前置失败：任务已建出来但流没起来；
//!   - `task.rs::create_task_with_recovery`：撞 10811 时清理历史残留。
//!
//! ── 非流式怎么处理（与 native 的差异）────────────────────────
//! **不迁聚合分支**：`sdk::stream_head` 固定发 `text/event-stream`，非流式请求
//! 也按 SSE 下发，由网关聚合回 JSON。因此这里只有一条出口 —— 推 SSE 帧。
//!
//! ── 账号从哪来 ──────────────────────────────────────────────
//! `sdk::account()` 返回宿主动态绑定的那条记录（宿主 `context.rs` 用
//! `params["account"]` 绑定账号上下文），`secret` 里就是 `accounts.rs` 落库的
//! `accessToken` / `imageId`。因此本文件不再自己查账号库（wasm 插件没有那个权限）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic；持锁不跨 await
//! （本文件不持任何锁）。

use agent2api_wasm_sdk::{self as sdk, Error, Result, Value};

use super::translate::Translator;
use super::{client, credentials, inflight, logging, models, startup, stream, task};

/// 转发入口（`lib.rs` 的 `conversation` 转调）。
pub fn run(params: &Value) -> Result<()> {
    let body = &params["body"];
    let account_id = params["account"].as_str().unwrap_or("");
    let credentials = credentials::current()?;
    if !credentials.ready_for_task() {
        return Err(Error::http(
            400,
            format!(
                "MonkeyCode {} 账号缺少创建任务所需的 image_id（VM 镜像 UUID）：\
                 请在账号页编辑该账号填入（浏览器登录后，DevTools → Network → \
                 POST /api/v1/users/tasks 请求里的 image_id），或先在官网跑一个任务让网关自动发现",
                super::region::REGION_LABEL
            ),
        ));
    }
    let requested = body["model"]
        .as_str()
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            params["wire_model"]
                .as_str()
                .filter(|name| !name.trim().is_empty())
        })
        .unwrap_or("")
        .trim()
        .to_string();
    if requested.is_empty() {
        return Err(Error::http(400, "请求缺少 model"));
    }
    let target = models::resolve_task_model(&requested)
        .ok_or_else(|| models::missing_model_error(&requested))?;
    let prompt = task::build_prompt(body.get("messages").unwrap_or(&Value::Null))?;
    logging::verbose(&format!(
        "[MonkeyCode] 会话转发 model={} → upstream={} cli={} account={} region={}",
        requested,
        target.model,
        super::endpoints::TASK_CLI_NAME,
        if account_id.is_empty() { "(队首账号)" } else { account_id },
        super::region::REGION_ID,
    ));
    // ① 建任务（失败在返回前：错误带状态码，编排层照常换账号 / 透传）
    let task_id = task::create_task_with_recovery(&credentials, &target, &prompt)?;
    // 登记为「正在驱动」：10811 自愈时据此跳过，避免停掉并发请求正在用的任务
    inflight::register(&task_id);
    // ② 等环境就绪 + 连任务流 + 设置 auto-approve：这三步失败都还没下发任何
    //    字节，所以可以带状态码返回；但任务已经建出来（上游已分配并发槽位），
    //    必须先停止它，否则槽位会被占到 VM 空闲回收（默认 3 天），之后每次
    //    建任务都撞 10811。停止失败不改变本次结论（错误照常返回）。
    if let Err(error) = startup::wait_ready(&credentials, &task_id) {
        cleanup(&task_id, &credentials.session);
        return Err(error);
    }
    let socket = match stream::connect(&credentials, &task_id) {
        Ok(socket) => socket,
        Err(error) => {
            cleanup(&task_id, &credentials.session);
            return Err(error);
        }
    };
    if let Err(error) = stream::start(&socket) {
        drop(socket);
        cleanup(&task_id, &credentials.session);
        return Err(error);
    }
    let translator = Translator::new(
        format!("chatcmpl-{task_id}"),
        requested.clone(),
        include_usage(body),
    );
    // ③ 从这里开始只有 SSE 帧：头一到，后面就只剩 chunk（错误进流内）
    if let Err(error) = sdk::stream_head(200) {
        drop(socket);
        cleanup(&task_id, &credentials.session);
        return Err(error);
    }
    stream::drive(socket, translator, &task_id, &credentials.session)
}

/// 前置失败时的收尾：注销在途登记 + 停止上游任务。
fn cleanup(task_id: &str, session: &str) {
    inflight::unregister(task_id);
    client::stop_task(session, task_id);
}

/// `stream_options.include_usage === true`（只认布尔真值，与 catpaw 同口径：
/// 字符串 / 数字不算，少一帧比多一帧更容易被客户端发现）。
fn include_usage(body: &Value) -> bool {
    body.pointer("/stream_options/include_usage")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn include_usage_only_accepts_a_real_boolean() {
        assert!(include_usage(&json!({ "stream_options": { "include_usage": true } })));
        assert!(!include_usage(&json!({ "stream_options": { "include_usage": "true" } })));
        assert!(!include_usage(&json!({ "stream_options": { "include_usage": 1 } })));
        assert!(!include_usage(&json!({})));
    }
}
