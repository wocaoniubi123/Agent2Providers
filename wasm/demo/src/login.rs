//! 登录：两种流程（native `login_start` / `login_poll`）。
//!
//! ── 协议里的两种形态 ────────────────────────────────────────
//!   * **设备授权型**（`login_ui` 里叫轮询型）：`login.start` 给一个 `url`
//!     与 `poll_interval_ms > 0`，宿主打开页面后按间隔问 `login.poll`；
//!   * **回调型**：`login.start` 给一个 `url` 且 `poll_interval_ms == 0`，
//!     宿主打开页面，用户完成后由 `login.callback` 带着一次性 code 收尾。
//! native 的示例把两种都摆了出来（`"browser"` 与 `"callback"` 两个分支）。
//!
//! ── wasm 侧的两条硬约束（都来自宿主代码，不是风格问题）────────
//! 1. **`flow` 必须是宿主分配的那个**。`wasm.json` 声明了
//!    `login.interaction.v1`，于是 `wasm/host.rs:428-432` 会比对
//!    `login.start` 返回的 `flow` 与 `params.flow`，不等就整条调用失败
//!    （「交互式登录必须使用主程序分配的流程标识」）。所以这里回显
//!    `params.flow`，自己拼一个只作为「宿主没给」时的兜底。
//! 2. **宿主固定把 `method` 传成 `"browser"`**（`rpc.rs:1610-1616`：旧契约
//!    只保证 `method` 与 `payload` 两个字段）。所以「用哪种流程」的判据落
//!    在 `payload` 上：这里读 `payload.mode`（`method` / `flowType` 两个别名
//!    也认），默认走设备授权型。
//!
//! ── 为什么示例不落登录状态 ──────────────────────────────────
//! native 用 `ctx` 内存保存「这一轮登录到哪一步了」。wasm 没有常驻内存，
//! 而是有 `sdk::state` / `sdk::session_*` 两条持久通道（`state` 的 Login
//! 作用域绑定当前 `flow`，见 `wasm/state.rs:121-132`）。示例的两条流程都
//! **当场就有结论**（设备授权型第一次轮询就成功、回调型拿到 code 就成功），
//! 落状态只会多一份要清理的东西 —— 所以这里保持 native 的「无状态示例」。
//! 真要落状态（轮询上游问「授权完了没」那种）照 `wasm/trae/src/login.rs`
//! 的写法：`state::get` 读快照 → `state::compare_exchange` 写回。
//!
//! ── 与 native 的一处身份修正 ────────────────────────────────
//! native 的 `login_poll` 给设备账号写死 `identity: "demo-device"`，而同一份
//! 令牌走 `account_identity()` 会算成 `demo-<hash>` —— 两条路对同一份凭证给
//! 出两个身份，去重时就会多出一条账号。示例这里统一成 `account::identity`
//! 算出来的那个值（也就是 `account.identity` 方法会回答的那一个）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account;

/// 设备授权型：宿主打开页面后按间隔轮询。
const MODE_BROWSER: &str = "browser";

/// 回调型：宿主等用户把回调 URL 回填。
const MODE_CALLBACK: &str = "callback";

/// 设备登录样例令牌（native 的同一份；示例没有真实上游）。
const DEVICE_TOKEN: &str = "demo-device-token";

/// 设备登录账号的有效期（native 的同一份：一天）。
const DEVICE_TTL_MS: i64 = 24 * 3600 * 1000;

/// 读「这一轮要哪种流程」。
///
/// 判据只在 `payload` / `params.mode` 上：宿主传的 `params.method` 恒为
/// `"browser"`（旧契约的固定值），拿它判流程会让回调型永远选不到。
fn mode_of(params: &Value) -> String {
    let payload = &params["payload"];
    let raw = payload
        .get("mode")
        .or_else(|| payload.get("method"))
        .or_else(|| payload.get("flowType"))
        .and_then(Value::as_str)
        .or_else(|| params.get("mode").and_then(Value::as_str))
        .unwrap_or("");
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "browser" | "web" | "device" => MODE_BROWSER.to_string(),
        "callback" | "manual" | "url" => MODE_CALLBACK.to_string(),
        other => other.to_string(),
    }
}

/// 设备登录产出的账号（`NormalizedAccount`，与 `account.normalize` 同形）。
fn device_account() -> Value {
    let expires_at = sdk::now() + DEVICE_TTL_MS;
    let secret = json!({
        "token": DEVICE_TOKEN,
        "expires_at": expires_at,
        "name": "示例账号（设备登录）",
        "desktop": false,
    });
    let identity = account::identity(&secret);
    json!({
        "secret": secret,
        "public": {
            "name": "示例账号（设备登录）",
            "uid": identity,
            "tokenTail": account::tail_of(DEVICE_TOKEN),
            "expiresAt": expires_at,
        },
        "identity": identity,
        "desktop": false,
    })
}

/// `LoginPoll::Done` 的形状。
fn done(account: Value) -> Value {
    json!({ "state": "done", "account": account })
}

/// `LoginPoll::Failed` 的形状（「这一轮没成」不是「网关坏了」）。
fn failed(message: impl Into<String>) -> Value {
    json!({ "state": "failed", "message": message.into() })
}

/// `login.start`：按 `payload.mode` 给两种流程之一的开场。
pub fn start(params: &Value) -> Result<Value> {
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("demo-{}", sdk::now()));
    match mode_of(params).as_str() {
        MODE_BROWSER => Ok(json!({
            "flow": flow,
            // 设备授权型：宿主打开页面，然后按间隔问 login.poll。
            "url": "https://example.com/demo-login",
            "instructions": "在打开的页面里完成登录",
            "poll_interval_ms": 3000,
            // 内嵌窗口即可：示例页面没有会拒绝 WebView 的地方。
            "external_browser": false,
            "allowed_hosts": ["example.com"],
        })),
        MODE_CALLBACK => Ok(json!({
            "flow": flow,
            // 回调型：`poll_interval_ms = 0` 就是「不要轮询」的信号。
            "url": "https://example.com/demo-oauth",
            "instructions": "完成后把地址栏里的整条回调 URL 回填",
            "poll_interval_ms": 0,
            // 回调落在系统浏览器：有些家的登录页会拒绝 WebView（示例照抄这个开关）。
            "external_browser": true,
            "allowed_hosts": ["example.com", "127.0.0.1"],
        })),
        other => Err(Error::http(
            400,
            format!("示例 provider 不认识的登录方式 {other}"),
        )),
    }
}

/// `login.poll`：示例**第一次轮询就成功**（native 的同一句注释）。
///
/// 真实 provider 在这里要真去问上游「授权完了没」，把「还在等」翻成
/// `pending`、把「被拒了」翻成 `failed`。
pub fn poll(_params: &Value) -> Result<Value> {
    Ok(done(device_account()))
}

/// `login.callback`：回调型流程的收尾。
///
/// native 的示例只演示了 `callback` 的开场形状，没有实现收尾（trait 的
/// `login_callback` 保持默认）。wasm 侧补上：拿到一次性 code 就直接给账号，
/// 让「两种登录流程」这一条在插件侧两端都是闭合的。
pub fn callback(params: &Value) -> Result<Value> {
    let code = params["code"]
        .as_str()
        .or_else(|| params["url"].as_str())
        .unwrap_or("")
        .trim();
    if code.is_empty() {
        // 回 `failed` 而不是把整条 RPC 变成错误：用户点完授权但页面没把
        // code 带回来，属于「这一轮没成」，重来一次即可。
        return Ok(failed("回调里没有授权码"));
    }
    Ok(done(device_account()))
}

/// `login.cancel`：取消一轮登录。
///
/// 示例没有落登录状态，所以这里只需要回一个空结果（宿主会自己清掉
/// `flow` 的代理记录与登录状态命名空间，见 `wasm/host.rs:24-30`）。
pub fn cancel(_params: &Value) -> Result<Value> {
    Ok(Value::Null)
}
