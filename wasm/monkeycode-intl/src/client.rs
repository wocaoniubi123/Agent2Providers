//! MonkeyCode 出站请求的薄封装（Cookie 认证，统一超时与错误翻译）。
//!
//! ── 为什么收在一处 ──────────────────────────────────────────
//! 三处消费者（`login` 校验 / `models` 目录刷新 / 建任务与停止任务）共用同一套
//! 超时、错误翻译与「业务码 → 人话」口径；各写一份会让「哪个码算登录失效」
//! 这类判据分叉。
//!
//! ── 业务码口径（参考 `mvp/auth.py` / `mvp/models.py` + `docs/05-api`）──
//! 上游是 HTTP 状态码 + `{code, msg, data}` 双轨：
//!   - 成功：`code == 0`（`{"code":0,"msg":"success","data":{…}}`）；
//!   - 未授权：HTTP 401 / 403，或 body 里 `code` 为 401 / 403
//!     （`{"code":401,"message":"未授权 [trace_id:…]"}`）；
//!   - 其余：业务失败，`message` / `msg` 是上游文案。
//! 本模块只判「HTTP 层失败」与「登录态失效」，业务码的**语义**由调用方各自
//! 翻译（登录校验与目录刷新要的处置不同）。
//!
//! ── 与 native 的差异：超时只能靠错误码认 ──────────────────────
//! native 有 `reqwest::Error::is_timeout()`。wasm 侧 `sdk::http` 的错误只有
//! `code` / `message` / `status` 三个字段，宿主在「单请求总期限已到」时给的是
//! `code = "timeout"`（`script::HttpDeadline::error`）。因此这里的超时判据是
//! **错误码**，不是异常类型 —— 判不出的一律当 502（可重试的上游故障）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, Error, Result, Value};

use super::{endpoints, logging};

/// 普通 JSON 请求的响应上限（目录 / 任务详情都远小于它）
const RESPONSE_LIMIT: usize = 1024 * 1024;

/// 成功业务码（整数 `0`）
pub const SUCCESS_CODE: i64 = 0;

/// 读 body 里的业务码（整数；缺失时返回 None，调用方按「缺失即未知」处置）
pub fn business_code(payload: &Value) -> Option<i64> {
    payload.get("code").and_then(Value::as_i64)
}

/// 上游业务文案（`message` → `msg` 兜底）
pub fn upstream_message(payload: &Value) -> String {
    payload
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| payload.get("msg").and_then(Value::as_str))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 这个 HTTP 状态 / 业务码是不是「登录态失效」
pub fn is_auth_failure(status: u16, payload: &Value) -> bool {
    if status == 401 || status == 403 {
        return true;
    }
    matches!(business_code(payload), Some(401) | Some(403))
}

/// 传输层错误 → 网关错误（超时 504、其余 502）。
fn transport_error(what: &str, error: Error) -> Error {
    let timed_out = error.code.as_deref() == Some("timeout");
    let status = if timed_out { 504 } else { 502 };
    let suffix = if timed_out { "超时，请稍后重试" } else { "失败" };
    let mut mapped = Error::http(status, format!("{what}{suffix}：{}", error.message));
    mapped.code = error.code;
    mapped
}

/// 发一次带 cookie 的请求，返回解出的上游响应体。
///
/// 返回上游响应体。HTTP 层失败 / 超时翻译成网关错误；登录态失效统一翻成
/// `401`（文案指向「重新粘贴 session」）。业务码**不在这里判** —— 调用方各有
/// 各的处置。
pub fn request(method: &str, path: &str, session: &str, body: Option<&Value>, what: &str) -> Result<Value> {
    if session.trim().is_empty() {
        return Err(Error::http(401, "MonkeyCode 账号缺少 session，请重新粘贴登录态"));
    }
    let (status, payload) = call(method, &endpoints::url(path), session, body, what)?;
    if is_auth_failure(status, &payload) {
        return Err(Error::http(
            401,
            format!("{what}：MonkeyCode 登录态已失效，请重新粘贴 session（HTTP {status}）"),
        ));
    }
    if !(200..300).contains(&status) {
        let detail = upstream_message(&payload);
        let detail = if detail.is_empty() { String::new() } else { format!("：{detail}") };
        return Err(Error::http(status, format!("{what}返回 HTTP {status}{detail}")));
    }
    Ok(payload)
}

/// GET 便捷入口（校验 / 目录 / 任务列表共用）
pub fn get_json(path: &str, session: &str, what: &str) -> Result<Value> {
    request("GET", path, session, None, what)
}

/// 发一次请求并解出 `(状态码, body)`：**非 2xx 不报错**。
///
/// 停止任务用它：调用点都在「这一轮已经定局」的收尾路径上，需要看到状态码与
/// 业务码而不想抛错（见 `stop_task` 的说明）。
pub fn call(method: &str, url: &str, session: &str, body: Option<&Value>, what: &str) -> Result<(u16, Value)> {
    let headers = endpoints::authed_headers(session);
    let response = http::open(method, url, headers, body).map_err(|error| transport_error(what, error))?;
    let status = response.status;
    let bytes = response.bytes(RESPONSE_LIMIT).map_err(|error| transport_error(what, error))?;
    let payload = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    Ok((status, payload))
}

/// 停止一个上游任务（`PUT /api/v1/users/tasks/stop`，body `{"id": "<taskId>"}`）。
///
/// ── 为什么这件事必须做（本家最容易漏的一步）─────────────────
/// 上游的并发额度按「`pending` + `processing` 的任务数」算（业务码 10811），
/// 而**一轮对话结束不等于任务结束** —— `task-ended` 只结束本轮，任务仍停在
/// `processing`，那是给多轮复用留的窗口。本包每个下游请求都新建一个任务，
/// 因此每次收尾都必须显式停止；否则账号槽位会被一直占着（直到 VM 空闲回收，
/// 默认 3 天），第二次请求就稳定撞 10811。
///
/// ── 失败不上升为错误 ────────────────────────────────────────
/// 调用点全在「这一轮已经定局」的收尾路径上（成功 / 出错 / 客户端断开 /
/// 超时）。此时再报错既改不了结论，又会让真正的失败原因被淹没。因此这里只
/// 返回 `bool` 表示是否停成，由调用方记一行 verbose；网络错误 / 401 / 业务码
/// 非 0 一律按「没停成」处理，**不抛错**。
pub fn stop_task(session: &str, task_id: &str) -> bool {
    if task_id.trim().is_empty() || session.trim().is_empty() {
        return false;
    }
    let body = sdk::json!({ "id": task_id.trim() });
    match call("PUT", &endpoints::task_stop_url(), session, Some(&body), "停止任务") {
        Ok((status, payload)) => {
            // 成功形态是 `{"code":0,...}`；非 2xx 或业务码非 0 都算没停成
            let response_ok = (200..300).contains(&status);
            let business_ok = match business_code(&payload) {
                Some(code) => code == SUCCESS_CODE,
                None => response_ok,
            };
            let ok = response_ok && business_ok;
            logging::verbose(&format!(
                "[MonkeyCode] 停止任务 {} {}（HTTP {status}）",
                logging::short_id(task_id),
                if ok { "成功" } else { "未成功" }
            ));
            ok
        }
        Err(error) => {
            logging::verbose(&format!(
                "[MonkeyCode] 停止任务 {} 请求失败：{}",
                logging::short_id(task_id),
                error.message
            ));
            false
        }
    }
}

/// 列出该账号**正在运行**（`pending` / `processing`）的任务 id。
///
/// 用于建任务撞 10811 之后的自愈：把残留任务停掉再重试一次。取不到
/// （网络错 / 结构变化）返回空表 —— 调用方据此放弃自愈，把原始错误透传。
pub fn list_running_tasks(session: &str) -> Vec<String> {
    let path = format!(
        "{}{}",
        endpoints::TASKS_PATH,
        endpoints::TASKS_RUNNING_QUERY
    );
    let payload = match get_json(&path, session, "运行中任务列表查询") {
        Ok(payload) => payload,
        Err(error) => {
            logging::verbose(&format!(
                "[MonkeyCode] 运行中任务列表查询失败（放弃自愈）：{}",
                error.message
            ));
            return Vec::new();
        }
    };
    let data = payload.get("data").unwrap_or(&payload);
    let tasks = data
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut ids = Vec::new();
    for task in tasks {
        let status = task
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        // 只认这两种「占槽位」的状态（上游 `consts.TaskStatus*`）。上游已按
        // status 过滤，这里再判一次是因为过滤是上游的事：万一它忽略了 query
        // 参数，我们不能把 finished 的任务也去停一遍。
        if status != "pending" && status != "processing" {
            continue;
        }
        let id = task
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !id.is_empty() {
            ids.push(id.to_string());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_covers_http_and_business_codes() {
        assert!(is_auth_failure(401, &Value::Null));
        assert!(is_auth_failure(403, &Value::Null));
        assert!(is_auth_failure(200, &sdk::json!({ "code": 401 })));
        assert!(!is_auth_failure(200, &sdk::json!({ "code": 0 })));
        assert!(!is_auth_failure(500, &sdk::json!({ "code": 50000 })));
    }

    #[test]
    fn business_message_prefers_message_then_msg() {
        assert_eq!("甲", upstream_message(&sdk::json!({ "message": " 甲 " })));
        assert_eq!("乙", upstream_message(&sdk::json!({ "msg": "乙" })));
        assert_eq!("", upstream_message(&Value::Null));
        assert_eq!(Some(0), business_code(&sdk::json!({ "code": 0 })));
        assert_eq!(None, business_code(&Value::Null));
    }
}
