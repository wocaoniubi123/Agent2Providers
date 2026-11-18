//! 计费、签到与活跃请求共用官方后台请求框架头；不混入对话专属追踪头。

use agent2api_wasm_sdk::Value;

use crate::endpoints::{resolve_edition, user_agent_for_edition};

/// 计费请求头（`session` 是账号会话形态：`auth` + `account` 两个子对象）。
///
/// 除计费自身外，国际版的每日活跃探测也打同一批计费端点 —— 头集合必须同源，
/// 抄一份必然漂移。
pub fn build_headers(session: &Value, extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut headers = crate::contract::framework_headers(session, true);
    for (key, value) in extra {
        if let Some((_, current)) = headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
        {
            *current = value.clone();
        } else {
            headers.push((key.clone(), value.clone()));
        }
    }
    headers
}

/// 运营活动接口需要的客户端白名单头（网关 `whitelist_headers` 的副本）。
///
/// banner 缺这几个头会被上游白名单拦掉（返回空 data），所以它必须走这一套
/// 而不是框架头。
pub fn whitelist_headers(session: &Value) -> Vec<(String, String)> {
    let edition = session.get("edition").and_then(Value::as_str);
    let info = resolve_edition(edition);
    vec![
        ("User-Agent".to_string(), user_agent_for_edition(edition)),
        ("X-IDE-Type".to_string(), info.ua_platform.to_string()),
        ("X-IDE-Name".to_string(), info.product_name.to_string()),
        ("X-IDE-Version".to_string(), info.client_version.to_string()),
        ("X-Product".to_string(), info.product_name.to_string()),
    ]
}
