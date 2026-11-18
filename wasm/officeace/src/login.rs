//! `login.start` / `login.poll` / `login.cancel`：把 `oauth` 的九步包成网关认的三档。
//!
//! ── 为什么 `poll_interval_ms` 必须大于 0 ──────────────────
//! 授权回调在**云端**（`/v1/claw/auth/callback`）终结，永远不回到本机 —— 桌面端就是
//! 靠轮询取回授权码的。报成 0 会让网关去等一个不存在的回调，症状是「地址出来了、
//! 界面一直挂着」。
//!
//! ── 为什么失败走 `failed` 而不是 RPC 错误 ───────────────────
//! 网关对 `login.poll` 的 `failed` 有专门的呈现（账号页里就地显示原因）；抛成 RPC
//! 错误会变成一条笼统的调用失败，用户看不到「授权码已失效，请重新发起」这种能直接
//! 指导下一步的话术。所以这里与 native 一致：**任何**轮询失败都折成 `failed`。
//!
//! ── 华为云登录页走系统浏览器 ────────────────────────────────
//! `external_browser = true` + `allowed_hosts = ["auth.huaweicloud.com"]`：第三方登录
//! 在内嵌 WebView 里常被拒（白屏），桌面壳据此决定用哪个窗口。

use agent2api_wasm_sdk::{json, Result, Value};

use super::oauth;

/// 发起网页登录：向云端要 state、现造 PKCE + DPoP，拼出授权地址。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    if method != "browser" && !method.is_empty() {
        return Err(agent2api_wasm_sdk::Error::http(
            400,
            format!("OfficeAce 不支持这种登录方式：{method}"),
        ));
    }
    let (flow, url, interval) =
        oauth::start().map_err(|reason| agent2api_wasm_sdk::Error::http(502, reason))?;
    Ok(json!({
        "flow": flow,
        "url": url,
        "instructions": "在打开的页面里完成华为云登录；完成后回到这里，网关会自动取回凭证",
        "poll_interval_ms": interval,
        // 华为云登录页在系统浏览器里更稳（内嵌窗口里第三方登录常被拒）
        "external_browser": true,
        "allowed_hosts": ["auth.huaweicloud.com"],
    }))
}

/// 轮询一次「用户授权完了没」，完成时把凭据换成落库形态的账号。
pub fn poll(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("").trim().to_string();
    if flow.is_empty() {
        return Ok(json!({ "state": "failed", "message": "登录流程标识为空，请重新发起登录" }));
    }
    match oauth::poll(&flow) {
        Ok(None) => Ok(json!({ "state": "pending" })),
        Ok(Some(secret)) => Ok(json!({
            "state": "done",
            "account": super::credentials::normalized(secret),
        })),
        Err(error) => Ok(json!({ "state": "failed", "message": error.message })),
    }
}

/// 取消一轮登录（把会话里的待办删掉；cancel 本来就是幂等的）。
pub fn cancel(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("");
    oauth::cancel(flow);
    Ok(Value::Null)
}
