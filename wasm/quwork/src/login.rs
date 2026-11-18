//! QuWork 的登录方式与「本机导入」流程。
//!
//! ── 两条入口（与 native `login::methods` 一一对应）──────────
//! ```text
//!   0  desktop  导入本机登录态（宿主 desktop.credentials.quwork.v1 读取）
//!   1  api      粘贴凭证 JSON / 模型凭证（可选登录令牌与设备标识）
//! ```
//!
//! ── 为什么本机导入也要走 `login.start` ──────────────────────
//! 网关的动态登录契约里，「一键导入」是一次**流程**而不是一次表单提交：
//! 面板点下去 → `login.start` → 网关按 `poll_interval_ms` 来问 `login.poll`。
//! 本机导入在这一步就已经拿到账号，所以 `start` 返回 pending、`poll` 立刻给
//! `done`（与 native 的 `start_local` + 2 分钟流程表同一行为）。
//!
//! ── 流程标识必须用网关给的那一个 ────────────────────────────
//! 申报了 `login.interaction.v1` 之后，宿主在 `login.start` 里分配 `flow`，
//! 并在 `login.callback` 时逐字比对。插件自己编的串等于让回调当场 502，
//! 所以这里**原样回传 `params["flow"]`**，自己的状态只以它为键。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account;

/// 本机导入的会话键前缀。
const FLOW_KEY: &str = "quwork:login:";

/// 一次导入的有效期（与 native 的 2 分钟同值）。
const FLOW_TTL_MS: i64 = 120_000;

/// `admin.action = auth.methods`。
///
/// 形状按网关 `LoginMethodsMetadata` 逐字段给：
///   · 0 号本机导入：`localOnly:true` + `browserMode:"none"` + 空 prompts
///     → 网关会把它识别成 `desktop`（要求 requires 有 `desktop.credentials.v1`）；
///   · 1 号粘贴凭证：每条 prompt 都带 `type:"text"`（缺了整份 502）。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "desktop",
            "label": "导入 QuWork 本机登录态",
            "instructions": "读取运行网关的电脑上已登录的 QuWork，只保存本机引用，不修改官方客户端文件；切换账号后需重新导入。",
            "prompts": [],
            "browserMode": "none",
            "localOnly": true,
            "manualCallback": false,
            "callbackInput": "url"
        },
        {
            "methodIndex": 1,
            "type": "api",
            "label": "QuWork 凭证",
            "instructions": "粘贴完整登录凭证 JSON，或只填模型凭证 llmToken。仅模型凭证可对话；积分、续期和奖励需要登录凭证 accessToken。",
            "prompts": [
                {
                    "key": "credentials",
                    "type": "text",
                    "label": "凭证 JSON 或模型凭证",
                    "placeholder": "{\"accessToken\":\"…\",\"llmToken\":\"…\"}",
                    "secret": true,
                    "optional": false
                },
                {
                    "key": "accessToken",
                    "type": "text",
                    "label": "登录凭证 accessToken",
                    "placeholder": "完整 JSON 已包含时无需填写",
                    "secret": true,
                    "optional": true
                },
                {
                    "key": "deviceIdentifier",
                    "type": "text",
                    "label": "QuWork 原设备标识",
                    "placeholder": "可选，仅远程兑换码激活需要；从官方客户端读取",
                    "secret": true,
                    "optional": true
                }
            ],
            "browserMode": "choice",
            "localOnly": false,
            "manualCallback": false,
            "callbackInput": "url"
        }
    ] })
}

/// `login.start`：本机导入一次读取，或回绝粘贴凭证（它走 `account.normalize`）。
pub fn start(params: &Value) -> Result<Value> {
    let method = params["method"].as_str().unwrap_or("browser");
    let index = params["methodIndex"].as_u64().unwrap_or(0);
    if method != "browser" && method != "" && method != "desktop" {
        return Err(Error::http(400, "QuWork 请使用本机导入或粘贴凭证"));
    }
    if index != 0 {
        return Err(Error::http(400, "QuWork 粘贴凭证请直接在账号页填写，不需要登录流程"));
    }
    // 网关分配的流程标识：原样回传（见模块头）。
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let secret = account::local_reference()?;
    let account = account::normalized(secret, None, true);
    sdk::session_put(&format!("{FLOW_KEY}{flow}"), account, FLOW_TTL_MS)?;
    Ok(json!({
        "flow": flow,
        "url": "",
        "poll_interval_ms": 1000,
        "instructions": "已读取 QuWork 本机登录态，正在添加账号。",
    }))
}

/// `login.poll`：本机导入已经把账号准备好了，直接给 done。
pub fn poll(params: &Value) -> Result<Value> {
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .ok_or_else(|| Error::http(400, "主程序未分配登录流程"))?;
    let key = format!("{FLOW_KEY}{flow}");
    let account = match sdk::session_get(&key) {
        Ok(account) if account.is_object() => account,
        _ => {
            return Ok(json!({ "state": "failed", "message": "QuWork 导入已失效，请重新发起" }));
        }
    };
    let _ = sdk::session_remove(&key);
    Ok(json!({ "state": "done", "account": account }))
}

/// `login.cancel`：清掉这一条（取消本来就幂等）。
pub fn cancel(params: &Value) -> Result<Value> {
    let flow = params["flow"].as_str().unwrap_or("").trim();
    if !flow.is_empty() {
        let _ = sdk::session_remove(&format!("{FLOW_KEY}{flow}"));
    }
    Ok(Value::Null)
}

/// `login.callback`：本机导入没有浏览器回调，如实回 pending。
pub fn callback(_params: &Value) -> Result<Value> {
    Ok(json!({ "state": "pending", "hint": "QuWork 本机导入不需要回调，请等待轮询结果" }))
}
