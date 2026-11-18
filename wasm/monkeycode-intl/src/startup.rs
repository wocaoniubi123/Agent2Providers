//! 等上游任务环境就绪（会话转发的第三步）。
//!
//! 上游把「建任务」与「VM 就绪」分成两步：`POST /users/tasks` 返回 task id 时
//! 环境还在拉起，`status` 是 `pending`；等它变成 `processing` 之后，任务流
//! （mode=attach）才会把首轮历史与实时输出回放出来。
//!
//! ── 为什么先轮询再连 WS ────────────────────────────────────
//! 官方任务页也是先轮询到 processing 再连（参考 `task-runner.ts`）。环境没起来
//! 就 attach，会连上一个还没有任何事件可回放的流，白白占着下游的等待时间。
//!
//! ── 与 native 的差异：期限用固定值 ─────────────────────────────
//! native 读 `crate::timeouts::current().headers_ms()`（网关配置，默认 300 秒）。
//! wasm 侧**没有读网关超时配置的宿主入口**（`settings.get` 只认插件自己的设置
//! 命名空间），因此这里按网关默认值钉死 [`READY_TIMEOUT_MS`]，并在汇报里登记
//! 「用户改过超时设置时这条不会跟着变」这个缺口。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, Error, Result, Value};

use super::credentials::Credentials;
use super::{client, endpoints, logging};

/// 等环境就绪的总期限（与网关 `DEFAULT_TIMEOUT_HEADERS_SECONDS = 300` 同值）
const READY_TIMEOUT_MS: i64 = 300_000;

/// 轮询间隔（参考实现同款 2 秒）
const POLL_INTERVAL_MS: u64 = 2_000;

/// 轮询到任务环境就绪。
///
/// 只有 `processing` / `finished` 算就绪：**已完成的极短任务仍要 attach 回放
/// 结果**，不能因为「已经结束」就当成失败，也不能再次发起一轮。
pub fn wait_ready(credentials: &Credentials, task_id: &str) -> Result<()> {
    let deadline = sdk::now().saturating_add(READY_TIMEOUT_MS);
    let path = format!("{}/{task_id}", endpoints::TASKS_PATH);
    let mut previous = String::new();
    loop {
        if sdk::now() >= deadline {
            return Err(Error::http(
                504,
                format!(
                    "MonkeyCode 任务环境在 {} 秒内未准备完成，已停止等待；请在官网确认镜像和环境状态",
                    READY_TIMEOUT_MS / 1000
                ),
            ));
        }
        let payload = client::get_json(&path, &credentials.session, "MonkeyCode 查询任务环境")?;
        if client::business_code(&payload) != Some(client::SUCCESS_CODE) {
            let detail = client::upstream_message(&payload);
            return Err(Error::http(
                502,
                format!(
                    "MonkeyCode 查询任务环境失败：{}",
                    if detail.is_empty() { "上游未返回有效任务状态" } else { detail.as_str() }
                ),
            ));
        }
        let task = payload.get("data").unwrap_or(&payload);
        let status = task.get("status").and_then(Value::as_str).unwrap_or("");
        let condition = task
            .pointer("/virtualmachine/conditions")
            .and_then(Value::as_array)
            .and_then(|items| items.last());
        let condition_type = condition
            .and_then(|item| item.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let detail = condition
            .and_then(|item| item.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(300)
            .collect::<String>();
        if status == "error" || condition_type.eq_ignore_ascii_case("failed") {
            return Err(Error::http(
                502,
                format!(
                    "MonkeyCode 任务环境准备失败：{}",
                    if detail.is_empty() { "请在官网查看任务详情" } else { detail.as_str() }
                ),
            ));
        }
        match status {
            "processing" | "finished" => return Ok(()),
            "pending" => {}
            _ => {
                return Err(Error::http(
                    502,
                    "MonkeyCode 返回了无法识别的任务状态，已停止等待",
                ))
            }
        }
        let progress = format!("{status}/{condition_type}");
        if progress != previous {
            logging::verbose(&format!(
                "[MonkeyCode] 任务 {} 等待环境就绪（{progress}）",
                logging::short_id(task_id)
            ));
            previous = progress;
        }
        sdk::sleep(POLL_INTERVAL_MS)?;
    }
}
