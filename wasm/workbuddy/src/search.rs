//! WorkBuddy 原生搜索：官方客户端的 `/agenttool/v1/search`，不经过聊天模型。
//!
//! ── 为什么是一个 admin 动作而不是具名方法 ────────────────────
//! 动作名（`web-search.capabilities` / `web-search.search`）由网关的
//! `native_search` 定义，取值域归提供商；别家没有原生搜索这条链路，塞进具名方法
//! 会让协议随长尾能力无限膨胀。
//!
//! ── 与 native 的差别 ────────────────────────────────────────
//! native 用 `flight::run`（同 key 单飞）+ `tokio::time::timeout`：
//! · 单飞表在 wasm 里没有进程内生命期，去掉（宿主按请求并发，重复搜索只是多打一次）；
//! · 整链超时改由宿主 http 的默认超时兜底（插件拿不到超时参数）。
//! 401 时的「续期后重试一次」保留 —— 那是这条链路唯一的自愈动作。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use crate::account;
use crate::errors;
use crate::httpio;
use crate::outbound;
use crate::util;

/// 搜索词上限（与 native 同值）。
const MAX_QUERY_CHARS: usize = 4000;
/// 结果条数上限（网关 `native_search::sources` 同口径）。
const MAX_SOURCES: usize = 50;

/// 动作名（网关 `native_search` 的同义常量）。
pub const CAPABILITIES: &str = "web-search.capabilities";
pub const SEARCH: &str = "web-search.search";

/// 能力自述。
pub fn capabilities() -> Value {
    json!({
        "version": 1, "search": true, "fetch": false,
        "max_query_chars": MAX_QUERY_CHARS,
    })
}

/// 分发一次搜索动作（`admin.action` 里在成长任务之前分流）。
pub fn dispatch(action: &str, payload: &Value) -> Result<Value> {
    if action == CAPABILITIES {
        return Ok(capabilities());
    }
    let query = payload
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if query.is_empty() || query.chars().count() > MAX_QUERY_CHARS {
        return Err(Error::http(
            400,
            format!("搜索词需为 1～{MAX_QUERY_CHARS} 个字符"),
        )
        .with_code("invalid_input"));
    }
    if payload
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .is_some_and(|timeout| !(5..=600).contains(&timeout))
    {
        return Err(Error::http(400, "搜索超时需为 5～600 秒").with_code("invalid_input"));
    }
    for attempt in 0..2 {
        match search_once(&query) {
            Err(error) if error.status == Some(401) && attempt == 0 => {
                // token 被拒：强制续期后重试一次（native 同口径）
                account::refresh()?;
            }
            outcome => return outcome,
        }
    }
    Err(rejected(401))
}

fn search_once(query: &str) -> Result<Value> {
    let secret = account::secret()?;
    if !secret.is_object() {
        return Err(rejected(401));
    }
    let token = account::ensure()?;
    let mut fresh = secret;
    fresh["accessToken"] = json!(token);
    let session = outbound::session_of_record(&fresh);
    let base = outbound::session_endpoint_of(&session);
    let url = format!("{}/agenttool/v1/search", base.trim_end_matches('/'));
    let headers = outbound::chat_headers(&session, Some("application/json"));
    let body = json!({ "query": query, "type": "text2text", "max_results": 5 });
    let response = httpio::send("POST", &url, &headers, Some(&body))
        .map_err(|_| rejected(502))?;
    let value = response.payload.clone().unwrap_or(Value::Null);
    let code = response.code();
    if code == Some(15001) {
        return Err(rejected(429));
    }
    if !(200..300).contains(&response.status) || code.is_some_and(|code| code != 0) {
        let class = errors::classify(response.status, &value);
        let status = match class["kind"].as_str() {
            Some("token_expired") => 401,
            Some("quota_limited") => 429,
            _ if (400..600).contains(&response.status) => response.status,
            _ => 502,
        };
        let mut error = rejected(status);
        error.upstream_code = code;
        return Err(error);
    }
    let items = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Error::http(502, "搜索提供商返回了无法识别的结果").with_code("provider_unavailable")
        })?;
    Ok(sources(items))
}

/// 结果行归一（只留 http(s)、有 host、无内嵌口令的 URL）。
fn sources(items: &[Value]) -> Value {
    let rows: Vec<Value> = items
        .iter()
        .take(MAX_SOURCES)
        .filter_map(|item| {
            let raw = item.get("url")?.as_str()?.trim();
            let (scheme, authority, path, query, fragment) = util::split_url(raw)?;
            if !matches!(scheme.as_str(), "http" | "https") || authority.is_empty() {
                return None;
            }
            // 带账号口令的 URL 一律丢弃（不把可能的凭据带给下游）
            if authority.contains('@') {
                return None;
            }
            let url = if query.is_empty() && fragment.is_empty() {
                format!("{scheme}://{authority}{path}")
            } else {
                let query = if query.is_empty() {
                    String::new()
                } else {
                    format!("?{query}")
                };
                let fragment = if fragment.is_empty() {
                    String::new()
                } else {
                    format!("#{fragment}")
                };
                format!("{scheme}://{authority}{path}{query}{fragment}")
            };
            let title = util::truncate_text(
                item.get("title").and_then(Value::as_str).unwrap_or(raw).trim(),
                300,
            );
            let content = util::truncate_text(
                item.get("snippet").and_then(Value::as_str).unwrap_or("").trim(),
                2000,
            );
            let date = item
                .get("publishedDate")
                .and_then(|value| {
                    if let Some(text) = value.as_str().filter(|text| !text.trim().is_empty()) {
                        return Some(util::truncate_text(text.trim(), 100));
                    }
                    let millis = value.as_i64().filter(|value| *value > 0)?;
                    chrono::DateTime::from_timestamp_millis(millis)
                        .map(|date| date.to_rfc3339())
                });
            Some(json!({
                "url": url, "title": title, "content": content, "publishedDate": date,
            }))
        })
        .collect();
    json!({ "sources": rows })
}

/// 搜索链路的拒绝文案（与网关 `native_search::rejected` 逐字一致）。
fn rejected(status: u16) -> Error {
    let (code, message) = match status {
        401 => ("invalid_provider_key", "搜索账号登录态已失效，请重新登录"),
        403 => ("provider_unavailable", "搜索服务拒绝了该账号，请检查账号权限"),
        402 | 429 => ("rate_limited", "搜索额度已用完或触发限流，请稍后重试"),
        _ => ("provider_unavailable", "搜索提供商暂不可用"),
    };
    Error::http(if status == 402 { 429 } else { status.max(400) }, message).with_code(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_keep_only_public_http_urls() {
        let value = sources(&[
            json!({ "url": "https://a.example.com/x?y=1", "title": "T", "snippet": "S" }),
            json!({ "url": "ftp://a.example.com/x" }),
            json!({ "url": "https://user:pass@a.example.com/x" }),
            json!({ "url": "not a url" }),
        ]);
        let rows = value["sources"].as_array().cloned().unwrap_or_default();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["url"], json!("https://a.example.com/x?y=1"));
        assert_eq!(rows[0]["title"], json!("T"));
    }

    #[test]
    fn capabilities_declare_the_query_limit() {
        let value = capabilities();
        assert_eq!(value["search"], json!(true));
        assert_eq!(value["fetch"], json!(false));
        assert_eq!(value["max_query_chars"], json!(MAX_QUERY_CHARS));
    }
}
