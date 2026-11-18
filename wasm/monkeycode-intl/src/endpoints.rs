//! MonkeyCode 国际版的上游端点与请求常量（cookie 名 / 路径 / 请求头 / URL 拼装）。
//!
//! ── 上游长什么样（依据 `Acankao/MonkeyCodeReverseEngineer`）──────
//! 单体 Web 应用，网页与 API 同域（本包是国际站 `https://monkeycode-ai.net`，
//! native `Region::Intl` 的 `site_origin()`）：
//!
//! ```text
//!   认证    GET  /api/v1/users/status      → {"code":0,"data":{"user":{...}}}
//!   目录    GET  /api/v1/users/models      → {"code":0,"data":{"models":[...]}}
//!   任务    POST /api/v1/users/tasks       （会话转发用；见 `task.rs`）
//!   任务流  WS   /api/v1/users/tasks/stream?id=&mode=（ACP 事件；见 `stream.rs`）
//! ```
//!
//! ── cookie 名与宿主机名**与国内版逐字相同**（native 没有地区分叉）──────
//! native `endpoints.rs` 的 `SESSION_COOKIE_NAME`（`monkeycode_ai_session`）与
//! `host_id()`（默认 `public_host`，只受 `MONKEYCODE_*_HOST_ID` 覆盖）都是全局
//! 常量，`Region` 只影响站点域名与登录窗口域。本包照此：cookie 名与 `host_id`
//! 不改，只把站点换到 `.net`。
//!
//! ── cookie 名（参考 `mvp/config.py` + `docs/02-auth/03-login-methods.md`）──
//! 普通用户 `monkeycode_ai_session`，团队管理员 `monkeycode_ai_team_session`；
//! TTL 30 天、HttpOnly + Secure + SameSite=Lax。本包只接**普通用户**这一路
//! （团队登录是另一套端点与另一套账号体系，不在本期范围）。
//!
//! ── 登录入口 ────────────────────────────────────────────────
//! 桌面端打开官方登录页，由用户完成验证码与第三方授权，宿主读取 HttpOnly
//! session 后交插件校验；纯网页面板继续使用粘贴 session。两条路径共用
//! GET /users/status 校验，不代解验证码。
//!
//! ── 与 native 的差异：请求头从 `Vec<(String, String)>` 变成 JSON 对象 ──
//! wasm 侧的 `sdk::http::open` / `sdk::websocket::WebSocket::open` 都收一个
//! **JSON 对象**当请求头（`host.rs` 的 `http.open` 把它原样交给宿主脚本传输层，
//! 并按名大小写不敏感地覆盖 `User-Agent`）。因此这里直接产出 `Value`，不再像
//! native 那样返回 `Vec`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Value};

use super::region;

/// 普通用户的 session cookie 名（`mvp/config.py::SESSION_COOKIE_NAME`）
pub const SESSION_COOKIE_NAME: &str = "monkeycode_ai_session";

/// 团队管理员的 session cookie 名（参考里同源；本包本期不接，仅登记以免
/// 将来有人把团队 cookie 当普通 cookie 用）
///
/// ── 为什么留着但没用到 ────────────────────────────────────
/// 团队账号的登录态可能是另一个 cookie 名，但参考资料里**没有**实测记录。
/// 留着它标注这个事实，避免后来者以为本家只认一个 cookie 名；真要支持团队
/// 账号时从这里接着做。
#[allow(dead_code)]
pub const TEAM_SESSION_COOKIE_NAME: &str = "monkeycode_ai_team_session";

/// 登录状态校验路径（`mvp/auth.py::check_status`，也是 `docs/05-api` 认证端点表里的那条）
pub const USER_STATUS_PATH: &str = "/api/v1/users/status";

/// 模型目录路径（`mvp/models.py::list_models`，`GET {base}/api/v1/users/models`）
pub const MODELS_PATH: &str = "/api/v1/users/models";

/// 任务列表路径（`discoverImageId` 用：从已有任务里取 `image.id`）
pub const TASKS_PATH: &str = "/api/v1/users/tasks";

/// 任务列表的查询串：`discoverImageId` 取最近 5 条任务（见 `login.rs`）
pub const TASKS_DISCOVER_QUERY: &str = "?page=1&size=5";

/// 任务列表路径的查询串形态（停止前发现残留任务时用：列出运行中的任务）。
///
/// 上游 `GET /api/v1/users/tasks?status=pending,processing`（`domain.TaskListReq`
/// 的 `status` 支持逗号分隔多值，见 `task.go::List`）。
pub const TASKS_RUNNING_QUERY: &str = "?page=1&size=20&status=pending,processing";

/// 任务创建路径（`task.rs::create_task` 用）
pub const TASK_CREATE_PATH: &str = "/api/v1/users/tasks";

/// 任务流 WebSocket 路径（`?id=<taskId>&mode=new|attach`，见 `stream_url`）
pub const TASK_STREAM_PATH: &str = "/api/v1/users/tasks/stream";

/// 停止任务路径（`PUT {base}/api/v1/users/tasks/stop`，body `{"id": "<taskId>"}`）。
///
/// 本包**每个下游请求都新建一个上游任务**（见 `conversation.rs`），而上游的任务
/// 状态只有 `pending` / `processing` / `finished` / `error` 四种，并发额度按
/// 「`pending` + `processing` 的任务数」算（上游 `entx.TaskConcurrencyHook`，
/// 业务码 10811）。一轮对话结束（`task-ended`）**不会**把任务置为 finished ——
/// 那是给多轮复用留的窗口。因此本包必须在每次转发收尾时显式停止任务，
/// 否则账号上的槽位会被一直占着，第二次请求就必然撞 10811。
pub const TASK_STOP_PATH: &str = "/api/v1/users/tasks/stop";

/// 建任务默认宿主机：公共主机（参考 `task-runner.ts::DEFAULT_HOST_ID`）。
///
/// 自建 / 私有云站点的宿主机名可能不是它，native 留了 `MONKEYCODE_INTL_HOST_ID`
/// 覆盖入口；wasm 沙箱里没有环境变量，而换掉的站址也过不了 `origins` 精确匹配
/// （见 `region.rs` 模块头），所以本包固定用公共主机。注意 `resource.life`
/// 在公共主机上最大 3 小时（`docs/protocol/llm-protocol-complete.md` §4.5），
/// 本家用的 1 小时在限额内。
pub const DEFAULT_HOST_ID: &str = "public_host";

/// 云任务使用 OpenCode；模型的 interface_type 只决定它调用模型的协议。
pub const TASK_CLI_NAME: &str = "opencode";

/// 出站 User-Agent（照抄客户端/参考实现的形态；上游对陌生 UA 会加风控）
pub const USER_AGENT: &str = "monkeycode-local-proxy";

/// `Cookie: monkeycode_ai_session=…` 请求头值
pub fn cookie_header(session: &str) -> String {
    format!("{SESSION_COOKIE_NAME}={session}")
}

/// 站内 JSON 请求的公共头：`Origin` / `Referer` 与站点自身的前端请求一致
/// （参考 `mkHeaders`），加一个可辨识的 UA。
///
/// ── `Content-Type` 必须手写（与 native 的一处关键差异）────────────
/// native 那边是全靠 `reqwest` 的 `.json(&body)` **自动补** `Content-Type:
/// application/json`；wasm 宿主只搬运插件给的字节与请求头，不会替你补
/// （`script/transport.rs` 只对 multipart 做特殊处理）。少这一条的表现是上游
/// 的 gin 绑定直接失败 —— 建任务稳定 400，而错误文案里看不出是头的问题。
pub fn json_headers() -> Value {
    let origin = region::SITE_ORIGIN;
    json!({
        "User-Agent": USER_AGENT,
        "Origin": origin,
        "Referer": format!("{origin}/"),
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
}

/// 在公共头后追加鉴权 cookie（调用方还会传 body 时由宿主补 `Content-Type`，
/// 这里不重复加）。
pub fn authed_headers(session: &str) -> Value {
    let mut headers = json_headers();
    if let Some(fields) = headers.as_object_mut() {
        fields.insert("Cookie".to_string(), json!(cookie_header(session)));
    }
    headers
}

/// WebSocket 握手头：站点自身前端发起的形态（参考 `browser-headers.ts::wsHeaders`
/// 的字段集）：Origin / Cookie / Accept-Language / Cache-Control / Pragma。
///
/// ── 与 native 的差异：不手写 WebSocket 握手专用头 ─────────────
/// native 那份由 tokio-tungstenite 在握手时自动补 `Sec-WebSocket-Version` /
/// `Sec-WebSocket-Key`；wasm 侧由宿主 `script/websocket.rs` 自己生成并派生
/// `sec-websocket-accept` 校验（它还会**丢弃**插件传来的同名保留头）。所以这里
/// 只给业务头，UA 用本家统一的出站 UA（与 REST 调用同一口径）。
pub fn ws_headers(session: &str) -> Value {
    json!({
        "User-Agent": USER_AGENT,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Origin": region::SITE_ORIGIN,
        "Cookie": cookie_header(session),
    })
}

/// 站点内路径 → 完整 URL（`path` 可带查询串）。
pub fn url(path: &str) -> String {
    format!("{}{path}", region::SITE_ORIGIN)
}

/// 任务列表（用于发现 image_id）的完整 URL
///
/// 插件里没有读者：`login::discover_image_id` 与 `client` 都收**路径**，由它们
/// 各自拼 base_url。留着它（与 native 同一取舍）是为了让「完整 URL 长什么样」
/// 在端点层一眼可见，排障时不必翻调用方。
#[allow(dead_code)]
pub fn tasks_discover_url() -> String {
    url(&format!("{TASKS_PATH}{TASKS_DISCOVER_QUERY}"))
}

/// 运行中任务列表的完整 URL（停止残留任务前用，见 `TASK_STOP_PATH` 的说明）
///
/// 插件里没有读者（同 `tasks_discover_url`：`client::list_running_tasks` 收路径）。
#[allow(dead_code)]
pub fn tasks_running_url() -> String {
    url(&format!("{TASKS_PATH}{TASKS_RUNNING_QUERY}"))
}

/// 停止任务接口的完整 URL（`PUT`，body `{"id": "<taskId>"}`）
pub fn task_stop_url() -> String {
    url(TASK_STOP_PATH)
}

/// 建任务接口的完整 URL
pub fn task_create_url() -> String {
    url(TASK_CREATE_PATH)
}

/// 单个任务的详情 URL（`GET /api/v1/users/tasks/{id}`，等环境就绪时轮询它）
///
/// 插件里没有读者（同 `tasks_discover_url`：`startup::wait_ready` 收路径）。
#[allow(dead_code)]
pub fn task_detail_url(task_id: &str) -> String {
    url(&format!("{TASK_CREATE_PATH}/{task_id}"))
}

/// 任务流 WebSocket 的完整 URL：`wss://<站点>/api/v1/users/tasks/stream?id=&mode=`。
///
/// scheme 按参考的 `httpToWs` 转换（https → wss）；本站只有 https 一种，
/// 因此直接拼 `wss://`。首轮输入已由创建请求提交，这里用 attach 回放并接收结果。
pub fn stream_url(task_id: &str, mode: &str) -> String {
    let host = region::SITE_ORIGIN
        .strip_prefix("https://")
        .unwrap_or(region::SITE_ORIGIN);
    let host = host.strip_prefix("http://").unwrap_or(host);
    format!("wss://{host}{TASK_STREAM_PATH}?id={task_id}&mode={mode}")
}

/// 建任务用的宿主机名（固定公共主机，见 `DEFAULT_HOST_ID` 的说明）
pub fn host_id() -> &'static str {
    DEFAULT_HOST_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_built_on_the_intl_origin_only() {
        assert_eq!("https://monkeycode-ai.net/api/v1/users/status", url(USER_STATUS_PATH));
        assert_eq!(
            "https://monkeycode-ai.net/api/v1/users/tasks?page=1&size=5",
            tasks_discover_url()
        );
        assert_eq!(
            "https://monkeycode-ai.net/api/v1/users/tasks?page=1&size=20&status=pending,processing",
            tasks_running_url()
        );
        // 任务流必须是 wss（宿主把 wss 折成 https 后再与 origins 比对）
        assert_eq!(
            "wss://monkeycode-ai.net/api/v1/users/tasks/stream?id=abc&mode=attach",
            stream_url("abc", "attach")
        );
        assert_eq!(
            "https://monkeycode-ai.net/api/v1/users/tasks/t-1",
            task_detail_url("t-1")
        );
    }

    #[test]
    fn cookie_header_is_the_reference_shape() {
        assert_eq!("monkeycode_ai_session=xyz", cookie_header("xyz"));
        assert_eq!("xyz", authed_headers("xyz")["Cookie"].as_str().unwrap_or("")
            .strip_prefix("monkeycode_ai_session=").unwrap_or(""));
        assert_eq!("xyz", ws_headers("xyz")["Cookie"].as_str().unwrap_or("")
            .strip_prefix("monkeycode_ai_session=").unwrap_or(""));
    }

    /// 宿主不会替插件补 `Content-Type`（native 那边是 reqwest `.json()` 自动补的）。
    #[test]
    fn json_headers_carry_content_type() {
        assert_eq!(
            "application/json",
            json_headers()["Content-Type"].as_str().unwrap_or("")
        );
        assert_eq!(
            "application/json",
            authed_headers("s")["Content-Type"].as_str().unwrap_or("")
        );
        assert_eq!("https://monkeycode-ai.net", json_headers()["Origin"].as_str().unwrap_or(""));
    }
}
