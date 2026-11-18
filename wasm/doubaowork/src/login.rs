//! 网页登录（`login.start` / `login.poll` / `login.callback` / `login.cancel`）。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/login.rs`。
//!
//! ── 流程形态：回调型（`poll_interval_ms = 0`）────────────────
//! native 打开官方页面，等窗口把 Cookie 当成一次性 code 交回来（`login.callback`），
//! 再用它跑一遍账号归一化。wasm 侧完全一样 —— 唯一的差别是 native 在进程内
//! 记一份 pending 表；wasm 每次调用都是新实例，所以这里不存任何状态：
//!   · 流程是否有效由宿主维护（`login.start` 时登记 flow，`poll` / `callback`
//!     进来时核对）；
//!   · 声明了 `login.interaction.v1` 时，宿主会给 `login.start` **分配**
//!     flow（`login_<32 字节十六进制>`），插件必须原样回传，否则宿主直接报
//!     「交互式登录必须使用主程序分配的流程标识」。
//!
//! ── 粘贴 Cookie 那条路 ─────────────────────────────────────
//! `login_methods` 里还有 `token` 形态：用户在界面上直接粘贴 Cookie 走
//! `account.normalize`，不经过本模块。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::{account, api, random};

const INSTRUCTIONS: &str =
    "在官方页面完成登录，窗口会自动读取 Cookie 并加入账号；网页面板请粘贴完整 Cookie。";

/// `admin.action = auth.methods`：添加账号面板里的登录方式清单。
///
/// ── 为什么必须由插件申报 ────────────────────────────────────
/// 网关对 wasm 包恒走动态通道（`api/session.rs` 的 `dynamic_login()` 恒为真），
/// 拿不到清单就回 501，添加账号面板整个打不开；它不会回退到 `metadata.json`
/// 的 `login_methods`。
///
/// ── 与 `metadata.json` 的对应（两条）────────────────────────
/// 0 号 = `kind: "browser"`（网页登录）、1 号 = `kind: "token"`（Cookie）。
///
/// `browserMode: "plugin"` 的依据是 `login.start` 的 `external_browser: false`：
/// 这条流程只在内嵌窗口里跑 —— Cookie 必须由宿主从窗口的 WebView 里读出来，
/// 交给系统浏览器就读不到，`login.callback` 永远等不到那份 `code`。
pub fn methods() -> Value {
    json!({ "methods": [
        {
            "methodIndex": 0, "type": "oauth", "label": "网页登录", "prompts": [],
            "browserMode": "plugin", "manualCallback": false,
            "instructions": "在官方页面登录，成功后自动保存完整 Cookie；网页面板可粘贴 Cookie。"
        },
        {
            "methodIndex": 1, "type": "api", "label": "Cookie", "prompts": [{
                "key": "token", "type": "text", "label": "Cookie",
                "placeholder": "sessionid=…; sessionid_ss=…（或 Cookie JSON）",
                "secret": true
            }],
            "instructions": "sessionid=…; sessionid_ss=…（或 Cookie JSON）"
        }
    ] })
}

pub fn start(params: &Value) -> Result<Value> {
    let flow = params["flow"]
        .as_str()
        .map(str::trim)
        .filter(|flow| !flow.is_empty())
        .map(str::to_string)
        .or_else(|| random::id("doubaowork_login").ok())
        .ok_or_else(|| Error::http(500, "无法生成登录流程标识"))?;
    Ok(json!({
        "flow": flow,
        "url": format!("{}/", api::BASE_URL),
        "instructions": INSTRUCTIONS,
        "poll_interval_ms": 0,
        "external_browser": false,
        "allowed_hosts": ["doubao.com", "feishu.cn", "larksuite.com"],
    }))
}

/// 回调型流程不轮询：宿主要问的时候一律回「还没完成」。
pub fn poll(_params: &Value) -> Result<Value> {
    Ok(json!({"state": "pending"}))
}

/// 一次性 code 就是完整 Cookie（窗口从官方域读出来的那份）。
pub fn callback(params: &Value) -> Result<Value> {
    let code = params["code"]
        .as_str()
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .ok_or_else(|| Error::http(400, "登录回调缺少 Cookie，请重新登录"))?;
    let normalized = account::normalize(&json!({
        "provider": "doubaowork",
        "source": {"kind": "manual", "payload": {"cookie": code}},
        "name": Value::Null,
    }))?;
    Ok(json!({"state": "done", "account": normalized}))
}

pub fn cancel(_params: &Value) -> Result<Value> {
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 形状必须与网关 `api/session.rs` 的 `LoginMethodsMetadata` 对得上：
    /// 索引唯一、`type` 在四个枚举内、`prompts` 恒为数组、oauth 带合法的
    /// `browserMode`。错一条的后果是整份 502（添加账号面板打不开）。
    #[test]
    fn methods_declare_the_gateway_contract() {
        let value = methods();
        let list = value["methods"].as_array().cloned().unwrap_or_default();
        assert_eq!(2, list.len());
        let mut seen: Vec<u64> = Vec::new();
        for method in &list {
            let index = method["methodIndex"].as_u64().unwrap_or(u64::MAX);
            assert!(!seen.contains(&index), "methodIndex 重复或缺失");
            seen.push(index);
            assert!(!method["label"].as_str().unwrap_or("").trim().is_empty());
            assert!(method["prompts"].is_array());
            match method["type"].as_str().unwrap_or("") {
                "oauth" => assert_eq!("plugin", method["browserMode"].as_str().unwrap_or("")),
                "api" => {
                    let prompts = method["prompts"].as_array().cloned().unwrap_or_default();
                    assert_eq!(1, prompts.len());
                    assert_eq!("token", prompts[0]["key"].as_str().unwrap_or(""));
                    assert_eq!(true, prompts[0]["secret"].as_bool().unwrap_or(false));
                }
                other => assert!(matches!(other, "sms" | "desktop")),
            }
        }
    }

    /// api 表单的字段名必须能被 `account.normalize` 认出来：网关把面板的
    /// `inputs` 原样透传，`pairs()` 对 `token` 当作 Cookie 头解析。
    #[test]
    fn pasted_cookie_field_is_the_one_normalize_reads() {
        let value = methods();
        let api = value["methods"]
            .as_array()
            .and_then(|list| list.iter().find(|method| method["type"].as_str() == Some("api")))
            .cloned()
            .unwrap_or(Value::Null);
        let key = api["prompts"][0]["key"].as_str().unwrap_or("");
        let mut inputs = serde_json::Map::new();
        inputs.insert(key.to_string(), json!("sessionid=abc123; sessionid_ss=def456"));
        let pairs = account::pairs(&Value::Object(inputs)).unwrap_or_default();
        assert!(pairs.contains_key("sessionid"));
        assert!(pairs.contains_key("sessionid_ss"));
    }
}
