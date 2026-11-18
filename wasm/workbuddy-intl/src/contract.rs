//! 请求头按官方链路分组：对话、请求框架、匿名登录与网页 Cookie 不混用。
//!
//! native 的 `contract.rs` 里还有 `proxy_of`（从账号记录解析出口代理）——
//! wasm 侧由宿主按账号绑定出网（SDK 的 `http.open` 没有代理参数），所以那一支
//! 不在这里。

use agent2api_wasm_sdk::{json, Value};

use crate::auth;
use crate::endpoints::{edition, user_agent_for_edition, WORKBUDDY_PLATFORM};
use crate::util;

/// 官方后台请求框架的头（计费 / 目录 / 账号 / 登录共用）。
///
/// `daemon = true` 用「带 CLI 段」的 UA（后台链路），`false` 用对话 UA ——
/// 这是 native 两处取值的原样分流。
pub fn framework_headers(session: &Value, daemon: bool) -> Vec<(String, String)> {
    let info = edition();
    let mut headers = vec![
        ("Accept".to_string(), "application/json, text/plain, */*".to_string()),
        ("X-Requested-With".to_string(), "XMLHttpRequest".to_string()),
        ("X-Request-ID".to_string(), util::new_message_id()),
        ("X-Product".to_string(), "SaaS".to_string()),
        (
            "User-Agent".to_string(),
            if daemon {
                user_agent_for_edition(Some(info.id))
            } else {
                info.chat_ua.to_string()
            },
        ),
    ];
    headers.extend(auth::build_auth_headers(session));
    headers
}

/// 匿名登录请求头：框架头 + 四个「跳过鉴权」+（可选）域名与渠道标记。
pub fn login_headers(authority: &str, state: bool) -> Vec<(String, String)> {
    let mut headers = framework_headers(&json!({}), true);
    for name in [
        "X-No-Authorization",
        "X-No-User-Id",
        "X-No-Enterprise-Id",
        "X-No-Department-Info",
    ] {
        headers.push((name.to_string(), "true".to_string()));
    }
    if state {
        headers.push(("X-Domain".to_string(), authority.to_string()));
        headers.push(("X-Custom-Channel-Id".to_string(), "unknown".to_string()));
    }
    headers
}

/// 官网（网页通道）的 origin。
///
/// 国际版的网页成长中心 / `console/as/conversations/` 都在 `www.workbuddy.ai` 上
/// （native `web_origin(Region::Intl)` 的同值）—— 与账号端点同域。
pub fn web_origin() -> &'static str {
    "https://www.workbuddy.ai"
}

/// 账号可选的网络策略。
///
/// native 这一位是**按地区分叉**的：`network_policy(Region::Intl) == Null`
/// （多址重试与 HTTPDNS 只对国内版那套腾讯域名有意义）。国际版返回 Null，
/// 与 native 逐字一致；函数保留是为了让 `contract.rs` 与 native 那份可逐行对照。
#[allow(dead_code)]
pub fn network_policy() -> Value {
    Value::Null
}

/// 鉴权 platform 参数（`auth/state?platform=`）。
pub fn platform() -> &'static str {
    WORKBUDDY_PLATFORM
}
