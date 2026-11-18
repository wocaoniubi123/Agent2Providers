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

/// 官网（网页成长中心）的 origin。
pub fn web_origin() -> &'static str {
    "https://www.workbuddy.cn"
}

/// 账号可选的网络策略（native 把它交给网关的网络层做多址重试）。
///
/// wasm 侧这条路走不通（出网由宿主统一做，插件拿不到地址族/HTTPDNS），但这份取值
/// 是「国内版上游有备用落点」这条知识的唯一记录，保留下来供对照。
#[allow(dead_code)]
pub fn network_policy() -> Value {
    json!({
        "trustedOrigins": ["https://www.workbuddy.cn", "https://copilot.tencent.com", "https://wb.tencentbuddy.com"],
        "backupOrigin": "https://wb.tencentbuddy.com",
        "retryStatuses": [408, 502, 503, 504], "addressStatuses": [408, 502, 503],
        "httpDns": { "token": "719980335", "bootstrapIps": ["119.29.29.99", "119.28.28.99"] },
        "fallbackAddresses": ["162.14.3.241"], "maxAttempts": 4,
    })
}

/// 鉴权 platform 参数（`auth/state?platform=`）。
pub fn platform() -> &'static str {
    WORKBUDDY_PLATFORM
}
