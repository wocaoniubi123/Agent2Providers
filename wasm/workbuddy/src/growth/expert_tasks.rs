//! 指定专家任务只发真实对话，任务完成与奖励仍由上游回读结果决定。
//! 任务链接只用于提取专家身份，不能作为携带账号凭证的请求地址。
//!
//! ── wasm 侧的两处替换 ───────────────────────────────────────
//! · native 用 `reqwest` 的流式响应读 SSE；这里用 `sdk::http::open` + 手写
//!   `SseDecoder`（同一份事件解码器，宿主提供的）。
//! · native 用 `tokio::time::timeout(45s)` 给整段对话兜底；wasm 的 http 没有超时
//!   参数，超时由宿主统一管（外层 `admin.action` 的转发超时仍在）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, http, json, sse::SseDecoder, Value};

use crate::util;

use super::spec::ObjectId;
use super::GrowthAccount;

const MODEL: &str = "fast-model";
const PROMPT: &str = "请用一句话介绍你的专长。";

/// 一次专家对话的读取上限（与 native 同值）。
const MAX_ANSWER_BYTES: usize = 1024 * 1024;

/// 解析任务指定的专家（只有 `resolve` 成功才允许发对话）。
pub fn resolve(
    account: &GrowthAccount,
    task: &Value,
) -> Result<ObjectId, String> {
    let link = task
        .get("jump_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let supplied_id = expert_id(link)?;
    let code = task.get("task_code").and_then(Value::as_str).unwrap_or("");
    let keyword = match code {
        "expert_use_maidehao" => "中国电商运营专家",
        "expert_use_douyinyin" => "抖音策略师",
        "expert_use_shangjia_xuanchuan" => "商家宣传页与海报设计师",
        "expert_use_bowangwang" => "直播电商教练",
        "WorkBuddy_Valorant" => "无畏契约拼豆专家",
        _ => return Err("未知的指定专家任务".to_string()),
    };
    if supplied_id.is_none() && code != "WorkBuddy_Valorant" {
        return Err("任务未提供有效的指定专家身份，请到官方客户端完成".to_string());
    }
    let experts = super::spec::fetch_market_experts(account, false, Some(keyword));
    let mut matches = experts.into_iter().filter(|expert| {
        if let Some(id) = &supplied_id {
            return &expert.id == id;
        }
        valid_id(&expert.id)
            && ["name", "profession"]
                .into_iter()
                .any(|key| text(&expert.meta, key) == keyword)
    });
    let expert = matches
        .next()
        .ok_or_else(|| "市场未返回任务指定的专家，无法确认身份".to_string())?;
    if matches.next().is_some() {
        return Err("专家市场存在多个同名专家，无法确认任务对象".to_string());
    }
    if text(&expert.meta, "displayName").is_empty() || text(&expert.meta, "profession").is_empty() {
        return Err("专家市场未返回完整的昵称和职业信息，无法确认使用记录".to_string());
    }
    Ok(expert)
}

/// 从任务跳转链接里取专家身份（`workbuddy://experts?expertId=ex_…`）。
fn expert_id(link: &str) -> Result<Option<String>, String> {
    if link.is_empty() {
        return Ok(None);
    }
    let (scheme, authority, path, query, fragment) =
        util::split_url(link).ok_or_else(|| "任务跳转链接格式无法识别".to_string())?;
    let mut scheme = scheme;
    let mut authority = authority;
    let mut path = path;
    let mut query = query;
    let fragment = fragment;
    if matches!(scheme.as_str(), "http" | "https") {
        if !["workbuddy.cn", "codebuddy.cn", "tencent.com"]
            .into_iter()
            .any(|domain| authority == domain || authority.ends_with(&format!(".{domain}")))
        {
            return Err("任务跳转链接不属于 WorkBuddy".to_string());
        }
        let links = util::query_values(&query, "deeplink");
        if links.is_empty() {
            return Ok(None);
        }
        if links.len() != 1 {
            return Err("任务跳转链接包含重复的专家入口".to_string());
        }
        let (inner_scheme, inner_authority, inner_path, inner_query, inner_fragment) =
            util::split_url(&links[0]).ok_or_else(|| "任务专家入口格式无法识别".to_string())?;
        scheme = inner_scheme;
        authority = inner_authority;
        path = inner_path;
        query = inner_query;
        let _ = inner_fragment;
    }
    if scheme != "workbuddy"
        || !matches!(authority.as_str(), "experts" | "expert")
        || !matches!(path.as_str(), "" | "/")
        || !fragment.is_empty()
    {
        return Err("任务未提供可识别的专家入口".to_string());
    }
    let ids = util::query_values(&query, "expertId");
    if ids.is_empty() {
        return Ok(None);
    }
    if ids.len() != 1 || !valid_id(&ids[0]) {
        return Err("任务指定的专家身份无效".to_string());
    }
    Ok(ids.into_iter().next())
}

/// 专家 id 的形态判据：`ex_` + 6~64 位字母数字。
fn valid_id(id: &str) -> bool {
    id.strip_prefix("ex_")
        .is_some_and(|suffix| {
            (6..=64).contains(&suffix.len()) && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

/// 与专家真实对话一次，然后上报使用记录。
pub fn use_expert(account: &GrowthAccount, expert: &ObjectId) -> Result<(), String> {
    if account.uid.trim().is_empty() || !valid_id(&expert.id) {
        return Err("账号或专家身份缺失，无法开始对话".to_string());
    }
    let session = json!({
        "account": { "uid": account.uid, "nickname": account.nick },
        "auth": { "accessToken": account.token, "domain": account.domain },
    });
    let mut headers = crate::outbound::chat_headers(&session, Some("text/event-stream"));
    headers.push(("X-Expert-Id".to_string(), expert.id.clone()));
    let conversation_id = headers
        .iter()
        .find(|(key, _)| key == "X-Conversation-ID")
        .map(|(_, value)| value.clone())
        .ok_or_else(|| "专家对话缺少会话身份".to_string())?;
    let body = json!({
        // 不带 `agent: "cli"`：那个字段让上游按 CLI agent 处理，返回的是一串
        // `tool_calls`（模型想执行 Bash 命令）而不是自然语言答复，实测 173 个
        // tool_calls 分片、content 为空、finish_reason 为 `tool_calls`。本任务要的
        // 是「与专家对话一次」，走普通 chat 形态。
        "model": MODEL, "stream": true, "max_tokens": 512,
        "stream_options": { "include_usage": true },
        "messages": [
            { "role": "system", "content": "请使用简体中文回答。" },
            { "role": "user", "content": PROMPT },
        ],
    });
    let url = crate::outbound::chat_completions_url(&session);
    let response = http::open(
        "POST",
        &url,
        util::headers_value(&headers),
        Some(&body),
    )
    .map_err(|error| format!("专家对话请求失败：{}", error.message))?;
    if !(200..300).contains(&response.status) {
        return Err(format!("专家对话返回 HTTP {}", response.status));
    }
    let answer = read_answer(response)?;
    let _ = sdk::sleep(super::GROWTH_WRITE_GAP_MS);
    report_use(account, expert, &conversation_id, &answer)
}

/// 读一次对话的 SSE，收集服务端消息身份 / 模型 / 用量与「是否拿到过非空正文」。
fn read_answer(mut response: http::Response) -> Result<Answer, String> {
    let mut decoder = SseDecoder::default();
    let mut received = 0_usize;
    let mut answer = Answer::default();
    while let Some(chunk) = response
        .read()
        .map_err(|error| format!("专家对话响应读取失败：{}", error.message))?
    {
        received = received.saturating_add(chunk.len());
        if received > MAX_ANSWER_BYTES {
            return Err("专家对话响应超过读取上限".to_string());
        }
        for event in decoder
            .push(&chunk)
            .map_err(|error| format!("专家对话流式事件无法解码：{}", error.message))?
        {
            answer.observe(&event)?;
        }
        if answer.done {
            break;
        }
    }
    // 完成判据只看「拿到过非空文本」：`finish_reason` 缺席（有的网关只在最后一帧
    // 给）不代表失败，但一个字的正文都没有则一定是没聊成。
    if !answer.content {
        return Err("专家对话未返回完整答复，本轮未确认完成".to_string());
    }
    if !valid_message_id(&answer.id) || answer.model.is_empty() {
        return Err("专家对话缺少服务端消息身份或模型信息，不上报使用记录".to_string());
    }
    Ok(answer)
}

#[derive(Default)]
struct Answer {
    id: String,
    model: String,
    usage: Value,
    content: bool,
    finish_reason: String,
    done: bool,
}

impl Answer {
    fn observe(&mut self, event: &str) -> Result<(), String> {
        if event.trim() == "[DONE]" {
            self.done = true;
            return Ok(());
        }
        let Ok(value) = serde_json::from_str::<Value>(event) else {
            return Err("专家对话返回无法识别的流数据".to_string());
        };
        if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
            return Err(format!("专家对话失败：{}", text(error, "message")));
        }
        if let Some(id) = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            if !self.id.is_empty() && self.id != id {
                return Err("专家对话响应混有不同的服务端消息身份".to_string());
            }
            self.id = id.to_string();
        }
        if let Some(model) = value
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.is_empty())
        {
            self.model = model.to_string();
        }
        if let Some(usage) = value.get("usage").filter(|value| value.is_object()) {
            self.usage = usage.clone();
        }
        for choice in value
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.content |= choice
                .pointer("/delta/content")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.trim().is_empty());
            // `finish_reason` 只做记录、不做否决：上游对同一条请求可能给
            // `stop` / `length` / `tool_calls` / `content_filter` 等多种值，早期把
            // 非 stop/length 一律判成失败，会让「模型正常答完但带了工具意图」的
            // 响应整条作废。真正的完成判据是「有文本内容」这一条。
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                if !reason.is_empty() {
                    self.finish_reason = reason.to_string();
                }
            }
        }
        Ok(())
    }
}

/// 上报「与专家对话过」的使用记录（桌面 6 连 + expert_actual_use）。
fn report_use(
    account: &GrowthAccount,
    expert: &ObjectId,
    conversation_id: &str,
    answer: &Answer,
) -> Result<(), String> {
    let name = text(&expert.meta, "displayName");
    let title = text(&expert.meta, "profession");
    let mut events =
        super::events::desktop_chat_sequence(account, conversation_id, &answer.id, &answer.id);
    for event in &mut events {
        if event.get("messageId").is_some() {
            event["messageId"] = json!(answer.id);
        }
        match text(event, "eventCode") {
            "agent_task_created" => {
                event["has_expert"] = json!(true);
                event["expert_id"] = json!(expert.id);
                event["expert_name"] = json!(name);
                event["expert_industry_id"] = json!(text(&expert.meta, "category"));
            }
            "chat_request_send" => {
                event["inputLength"] = json!(PROMPT.chars().count());
                event["expertId"] = json!(expert.id);
            }
            "chat_message_response" | "chat_request_response" => {
                if let Some(object) = event.as_object_mut() {
                    for key in [
                        "inputToken",
                        "outputToken",
                        "totalToken",
                        "cachedTokens",
                        "cachedWriteTokens",
                        "cachedMissTokens",
                    ] {
                        object.remove(key);
                    }
                }
                event["finishReason"] = json!(answer.finish_reason);
                if text(event, "eventCode") == "chat_message_response" {
                    event["messageId"] = json!(answer.id);
                    event["responseModelId"] = json!(answer.model);
                }
                if let Some(usage) = answer.usage.as_object() {
                    for (source, target) in [
                        ("prompt_tokens", "inputToken"),
                        ("completion_tokens", "outputToken"),
                        ("total_tokens", "totalToken"),
                    ] {
                        if let Some(value) = usage.get(source).filter(|value| value.as_u64().is_some())
                        {
                            event[target] = value.clone();
                        }
                    }
                }
            }
            _ => {}
        }
    }
    super::events::report_desktop_events(account, &events)?;
    let _ = sdk::sleep(super::GROWTH_WRITE_GAP_MS);
    let mut used = json!({
        "eventCode": "expert_actual_use", "timestamp": util::now_ms(), "reportDelay": 0,
        "mode": "LOCAL", "id": expert.id, "name": name, "expertTitle": title,
        "type": text(&expert.meta, "category"), "expertType": text(&expert.meta, "expertType"),
        "source": "builtin", "version": text(&expert.meta, "version"),
        "characterCount": PROMPT.chars().count(), "conversationId": conversation_id,
        "requestId": answer.id, "messageId": answer.id, "requestModelId": answer.model,
        "requestModelName": answer.model, "userId": account.uid,
    });
    if let Some(cost) = answer
        .usage
        .get("cost")
        .filter(|value| value.as_f64().is_some_and(|cost| cost.is_finite() && cost >= 0.0))
    {
        used["cost"] = cost.clone();
    }
    super::events::report_regular(account, &used)
}

/// 服务端消息 id 的形态判据。
///
/// 上游的 `id` 是纯 32 位小写 hex（uuid7 去掉连字符），实测形如
/// `01a16ec189bc78d583f7e808213b066f`。这里刻意**不要求** `cmb-` 前缀：那个前缀是
/// 早期凭猜测加的，上游从不发它，加上等于把所有真实响应判成「缺少服务端消息身份」
/// 而整条任务失败（实测 5 条专家任务全挂在这）。
fn valid_message_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expert_ids_follow_the_ex_prefix_rule() {
        assert!(valid_id("ex_2cvvUZQhDyeJ"));
        assert!(!valid_id("ex_abc")); // 太短
        assert!(!valid_id("2cvvUZQhDyeJ"));
        assert!(!valid_id("ex_2cvv-UZQh"));
    }

    #[test]
    fn deeplink_inside_a_web_url_is_followed() {
        let id = expert_id(
            "https://www.workbuddy.cn/expert?deeplink=workbuddy%3A%2F%2Fexperts%3FexpertId%3Dex_2cvvUZQhDyeJ",
        )
        .unwrap_or(None);
        assert_eq!(id.as_deref(), Some("ex_2cvvUZQhDyeJ"));
    }

    #[test]
    fn foreign_links_are_rejected() {
        assert!(expert_id("https://evil.example.com/x").is_err());
        assert!(expert_id("workbuddy://experts?expertId=bad").is_err());
        assert_eq!(expert_id("").unwrap_or(None), None);
    }

    #[test]
    fn message_ids_accept_plain_hex() {
        assert!(valid_message_id("01a16ec189bc78d583f7e808213b066f"));
        assert!(!valid_message_id(""));
    }
}
