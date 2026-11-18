//! AStudio 的登录方式：粘贴 modelBearerToken（含可选网页会话材料）+ 本机导入。
//!
//! ── 为什么没有「浏览器登录」这一条 ──────────────────────────
//! native 的网页登录会自绑一个回环端口、把登录页**自己渲染**出来再收 Cookie
//! （`login_page.rs` + `auth.rs`）。wasm 没有 socket、也没有出站以外的入站
//! 通道，这条路走不通；于是按「本机导入 + 粘贴凭据」两条保留能力，并在方法
//! 清单里如实不列浏览器登录 —— 列了却打不开，比不列更糟。
//!
//! ── 本机导入的流程形状 ──────────────────────────────────────
//! `login.start` 读一次宿主提供的本机登录态并放进会话，`login.poll` 直接给
//! `done`（网关按 `poll_interval_ms` 来问）。流程标识**原样回传**网关给的
//! `params["flow"]`（规格第 17 节：自己编的串会让回调当场 502）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account;

/// 本机导入的会话键前缀。
const FLOW_KEY: &str = "astudio:login:";

/// 一次导入的有效期（两分钟，与网关的登录超时同档）。
const FLOW_TTL_MS: i64 = 120_000;

/// `admin.action = auth.methods`。
///
/// 每条 prompt 都带 `type:"text"`（缺了整份 502）；`desktop` 那条用
/// `localOnly:true` + `browserMode:"none"` + 空 prompts，且 requires 里
/// 必须有 `desktop.credentials.v1`。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "api",
            "label": "粘贴 modelBearerToken",
            "instructions": "粘贴 AStudio 的 modelBearerToken；填了网页会话材料才有余额与签到。",
            "prompts": [
                {
                    "key": "modelBearerToken",
                    "type": "text",
                    "label": "modelBearerToken",
                    "placeholder": "粘贴 modelBearerToken",
                    "secret": true,
                    "optional": false
                },
                {
                    "key": "uid",
                    "type": "text",
                    "label": "账号 uid（可选）",
                    "placeholder": "用于显示",
                    "optional": true
                },
                {
                    "key": "sessionToken",
                    "type": "text",
                    "label": "网页会话 token（可选）",
                    "placeholder": "astron-session.json 的 token；填了才有余额与签到",
                    "secret": true,
                    "optional": true
                },
                {
                    "key": "accountId",
                    "type": "text",
                    "label": "账号面 accountId（可选）",
                    "placeholder": "与 sessionToken 一起填",
                    "optional": true
                },
                {
                    "key": "ssoSessionId",
                    "type": "text",
                    "label": "ssoSessionId（可选）",
                    "placeholder": "Cookie 会话的补充材料",
                    "secret": true,
                    "optional": true
                }
            ],
            "browserMode": "choice",
            "localOnly": false,
            "manualCallback": false,
            "callbackInput": "url"
        },
        {
            "methodIndex": 1,
            "type": "desktop",
            "label": "导入 AStudio 本机登录态",
            "instructions": "读取运行网关的电脑上已登录的 AStudio（注册表 / ASTUDIO_HOME / ~/.acode），只保存引用，不修改官方客户端文件。",
            "prompts": [],
            "browserMode": "none",
            "localOnly": true,
            "manualCallback": false,
            "callbackInput": "url"
        }
    ] })
}

/// `login.start`。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    let index = params["methodIndex"].as_u64().unwrap_or(0);
    if method != "browser" && method != "" && method != "desktop" {
        return Err(Error::http(400, "AStudio 请使用本机导入或粘贴 modelBearerToken"));
    }
    if index == 0 {
        return Err(Error::http(400, "AStudio 粘贴凭据请直接在账号页填写，不需要登录流程"));
    }
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let secret = account::normalize(&json!({ "source": { "kind": "desktop" }, "name": "" }))?;
    sdk::session_put(&format!("{FLOW_KEY}{flow}"), secret, FLOW_TTL_MS)?;
    Ok(json!({
        "flow": flow,
        "url": "",
        "poll_interval_ms": 1000,
        "instructions": "已读取 AStudio 本机登录态，正在添加账号。",
    }))
}

/// `login.poll`。
pub fn poll(params: &Value) -> Result<Value> {
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let key = format!("{FLOW_KEY}{flow}");
    let account = match sdk::session_get(&key) {
        Ok(account) if account.is_object() => account,
        _ => return Ok(json!({ "state": "failed", "message": "AStudio 导入已失效，请重新发起" })),
    };
    let _ = sdk::session_remove(&key);
    Ok(json!({ "state": "done", "account": account }))
}

/// `login.cancel`。
pub fn cancel(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("").trim();
    if !flow.is_empty() {
        let _ = sdk::session_remove(&format!("{FLOW_KEY}{flow}"));
    }
    Ok(Value::Null)
}

/// `login.callback`：本机导入没有浏览器回调。
pub fn callback(_params: &Value) -> Result<Value> {
    Ok(json!({ "state": "pending", "hint": "AStudio 本机导入不需要回调，请等待轮询结果" }))
}
