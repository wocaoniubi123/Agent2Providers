//! MonkeyCode 建任务与输入侧翻译（会话转发的第一步）。
//!
//! ── 输入侧：OpenAI messages → 上游 prompt（参考 `api-routes.ts`）──
//! 与 `api-routes.ts::messagesToPrompt` 逐条对齐：
//!   - 第一条**非空** `system` 消息抽出来，单独走建任务的 `system_prompt`
//!     字段（参考是 `messages.find(role === "system")`，只取一条）；
//!   - 其余消息按角色加前缀：user → `[User]\n…`、assistant →
//!     `[Assistant]\n…`、其它角色原样，段间以 `\n\n` 连接；
//!   - `tools` / `tool_choice` **不透传**：MonkeyCode 的 Agent 在 VM 内自带
//!     工具循环（opencode / codex / claude），建任务接口没有接收客户端工具表的
//!     字段，参考实现同样忽略它们。不为此报错 —— 客户端带工具表是常态。
//!   - 多模态 `content` 数组只取 text / input_text 部件拼接（参考实现直接当
//!     字符串用，数组会变成 `[object Object]`；这里至少把文本挑出来）。
//!
//! ── 建任务请求体（逐字对照 `task-runner.ts::createTask`）──────────
//! ```jsonc
//! { "content": <prompt>, "host_id": "public_host", "image_id": <账号字段>,
//!   "model_id": <目录 upstreamId>, "cli_name": "opencode",
//!   "resource": {"core": 1, "memory": 1073741824, "life": 3600},
//!   "repo": {"repo_url": "", "branch": "master", "repo_filename": "", "zip_url": ""} }
//! ```
//! `system_prompt` 仅在客户端带了 system 消息时插入（参考的条件插入）。
//! `resource.life = 3600` 与任务流 1 小时总超时同一口径（参考注释原文：
//! "matches resource.life"）。
//!
//! ── 首轮任务的启动 ───────────────────────────────────────────
//! 创建请求的 content 会在环境就绪后由上游自动执行。官方任务页先轮询到
//! processing，再连接 mode=attach 回放首轮日志并接收实时结果。mode=new 与
//! user-input 是追加新一轮的协议，不能在首轮环境尚未就绪时重复发送。
//!
//! ── 建任务失败怎么变 `Error` ───────────────────────────────────
//!   - 传输层（连不上 / 超时）→ 502 / 504（见 `client::transport_error`）；
//!   - HTTP 401/403 → 401；402 → 402；404 → 404；409 → 409；429 → 429；
//!     其余非 2xx 原状态码透传（5xx 归一成 502 —— 那是上游故障，可重试）；
//!     码表在 `errors::status_error`；
//!   - HTTP 200 但 `code != 0`：`10811` → 409、`40100` → 401、
//!     `40002/40003/40004` → 403、`50000` → 502，其余 → 502 并把业务码带进
//!     `upstream_code`；码表在 `errors::business_error`。
//!
//! ── 与 native 的差异 ────────────────────────────────────────
//! 出站抓包（`telemetry.capture()`）不迁：插件的出站抓包由**网关侧**统一记，
//! 插件进程里没有 `RequestTelemetry`。建任务的 30 秒超时也不在这里设 ——
//! wasm 侧设置单请求期限要额外申报 `http.timeout.v1`，而本包按宿主给的默认
//! 期限走（宿主在调用级有总期限，超时会以 `code = "timeout"` 返回）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic；不持任何锁。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credentials::Credentials;
use super::models::TaskTarget;
use super::{client, endpoints, errors, inflight, logging};

/// 起始用户消息：`content`（建任务 content，与 WS `user-input` 同源）+
/// 可选的 `system_prompt`（单独字段，不进 content）。
pub struct TaskPrompt {
    pub content: String,
    pub system_prompt: Option<String>,
}

/// OpenAI messages → 上游 prompt（判据见模块头）。
pub fn build_prompt(messages: &Value) -> Result<TaskPrompt> {
    let Value::Array(items) = messages else {
        return Err(Error::http(400, "请求缺少 messages 数组"));
    };
    let mut system_prompt: Option<String> = None;
    let mut parts: Vec<String> = Vec::new();
    for message in items {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("user");
        let text = content_text(message).unwrap_or_default();
        if role == "system" {
            if system_prompt.is_none() && !text.trim().is_empty() {
                system_prompt = Some(text);
            }
            continue;
        }
        if text.trim().is_empty() {
            continue;
        }
        match role {
            "user" => parts.push(format!("[User]\n{text}")),
            "assistant" => parts.push(format!("[Assistant]\n{text}")),
            _ => parts.push(text),
        }
    }
    let content = parts.join("\n\n");
    if content.trim().is_empty() {
        return Err(Error::http(
            400,
            "messages 里没有可发送的文本内容：MonkeyCode 只接收文本提示词（图片 / 文件附件不在本期范围）",
        ));
    }
    Ok(TaskPrompt { content, system_prompt })
}

/// 取一条消息的可读文本（content 字符串，或部件数组里的 text / input_text）。
fn content_text(message: &Value) -> Option<String> {
    match message.get("content")? {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                let text = part
                    .get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("input_text").and_then(Value::as_str));
                if let Some(text) = text {
                    out.push_str(text);
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out)
            }
        }
        _ => None,
    }
}

/// 建任务请求体（逐字对照参考，见模块头）。
pub fn build_body(target: &TaskTarget, prompt: &TaskPrompt, image_id: &str) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("content".to_string(), json!(prompt.content));
    body.insert("host_id".to_string(), json!(endpoints::host_id()));
    body.insert("image_id".to_string(), json!(image_id));
    body.insert("model_id".to_string(), json!(target.model_id));
    body.insert("cli_name".to_string(), json!(endpoints::TASK_CLI_NAME));
    body.insert(
        "resource".to_string(),
        json!({ "core": 1, "memory": 1073741824, "life": 3600 }),
    );
    body.insert(
        "repo".to_string(),
        json!({
            "repo_url": "",
            "branch": "master",
            "repo_filename": "",
            "zip_url": "",
        }),
    );
    if let Some(system) = prompt
        .system_prompt
        .as_ref()
        .map(|text| text.trim())
        .filter(|text| !text.is_empty())
    {
        body.insert("system_prompt".to_string(), json!(system));
    }
    Value::Object(body)
}

/// 创建任务，返回上游 task id（UUID）。
pub fn create_task(credentials: &Credentials, target: &TaskTarget, prompt: &TaskPrompt) -> Result<String> {
    let body = build_body(target, prompt, &credentials.image_id);
    let (status, payload) = client::call(
        "POST",
        &endpoints::task_create_url(),
        &credentials.session,
        Some(&body),
        "MonkeyCode 建任务请求",
    )?;
    if !(200..300).contains(&status) {
        return Err(errors::status_error(status, &payload, ""));
    }
    if let Some(code) = client::business_code(&payload) {
        if code != client::SUCCESS_CODE {
            return Err(errors::business_error(code, &client::upstream_message(&payload)));
        }
    }
    let task_id = task_id_of(&payload)?;
    logging::verbose(&format!(
        "[MonkeyCode] 建任务成功 model={} cli={} task={} promptLen={} systemPrompt={}",
        target.model,
        endpoints::TASK_CLI_NAME,
        logging::short_id(&task_id),
        prompt.content.chars().count(),
        if prompt.system_prompt.is_some() { "有" } else { "无" },
    ));
    Ok(task_id)
}

/// 从建任务响应里取 task id（参考 `data.id || data.task_id`）。
fn task_id_of(payload: &Value) -> Result<String> {
    let data = payload.get("data").unwrap_or(payload);
    for key in ["id", "task_id", "ID"] {
        let value = data
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return Ok(value.to_string());
        }
    }
    Err(Error::http(
        502,
        "MonkeyCode 建任务响应里没有 task id（上游响应形态变化？）",
    ))
}

/// 建任务；撞上「已有运行中的任务」（code 10811）时**自愈一次**。
///
/// ── 为什么需要这一步（而不是直接报错给用户）────────────────────
/// 10811 的判定是「该账号 `pending` + `processing` 的任务数已达上限」。本包自己
/// 每轮都会停止任务（见 `stream.rs::close_and_stop`），所以 10811 的常见来源是
/// **没能停掉的历史残留**：
///   - 修复前版本的请求（那时根本不停止）；
///   - 插件实例被宿主回收 / 网关重启，收尾代码没跑完；
///   - 建任务成功但连 WS 失败这类路径（同样会留下任务）。
/// 这些都是**本账号自己的僵尸任务**，用户在官网手动点「停止」也能解决 ——
/// 与其让用户去点，不如在这里自动清理：列出运行中的任务 → 逐个停止 → 重试一次。
///
/// ── 边界（什么时候不自愈）────────────────────────────────────
///   - 只在**业务码恰好是 10811** 时触发（别的错误各有各的处置）；
///   - 只清理**列表里查到的**运行中任务；查不到（网络 / 结构变化）就原样报错，
///     不自作主张；
///   - 只重试**一次**。第二次仍 10811 说明不是残留问题（比如账号真在上限），
///     把上游原文透传出去，让用户自己判断。
pub fn create_task_with_recovery(
    credentials: &Credentials,
    target: &TaskTarget,
    prompt: &TaskPrompt,
) -> Result<String> {
    let first = create_task(credentials, target, prompt);
    let Err(error) = first else {
        return first;
    };
    // 只认 10811（见模块头的码表；`upstream_code` 由 `errors::business_error` 挂上）
    if error.upstream_code != Some(10811) {
        return Err(error);
    }
    let stale = client::list_running_tasks(&credentials.session);
    // 排除本进程正在驱动的任务：同一个账号上可能有别的请求在跑（并发转发），
    // 停掉它们等于把别人的流掐断（见 `inflight.rs` 的说明）。
    let stale: Vec<String> = stale
        .into_iter()
        .filter(|id| !inflight::contains(id))
        .collect();
    if stale.is_empty() {
        return Err(error);
    }
    logging::warn(&format!(
        "[MonkeyCode] 账号命中 10811（已有运行中的任务），自动清理 {} 个残留任务后重试：{}",
        stale.len(),
        stale
            .iter()
            .map(|id| logging::short_id(id))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut stopped = 0usize;
    for id in &stale {
        if client::stop_task(&credentials.session, id) {
            stopped += 1;
        }
    }
    if stopped == 0 {
        // 一个都没停成：残留清理失败，把原始 10811 报回去（别把「清理失败」
        // 表现为「重试失败」，用户要看到的是真正卡住的原因）
        return Err(error);
    }
    logging::verbose(&format!("[MonkeyCode] 已停止 {stopped}/{} 个残留任务，重试建任务", stale.len()));
    create_task(credentials, target, prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_splits_system_and_prefixes_roles() {
        let messages = json!([
            { "role": "system", "content": "你是助手" },
            { "role": "system", "content": "第二条 system 被忽略" },
            { "role": "user", "content": "你好" },
            { "role": "assistant", "content": "在" },
            { "role": "tool", "content": "工具输出" },
            { "role": "user", "content": "   " }
        ]);
        let prompt = build_prompt(&messages).unwrap_or_else(|_| TaskPrompt {
            content: String::new(),
            system_prompt: None,
        });
        assert_eq!(Some("你是助手".to_string()), prompt.system_prompt);
        assert_eq!("[User]\n你好\n\n[Assistant]\n在\n\n工具输出", prompt.content);
    }

    #[test]
    fn prompt_reads_multimodal_text_parts() {
        let messages = json!([
            { "role": "user", "content": [
                { "type": "text", "text": "看这段" },
                { "type": "image_url", "image_url": { "url": "https://x/1.png" } },
                { "type": "input_text", "input_text": "和这段" }
            ] }
        ]);
        let prompt = build_prompt(&messages).unwrap_or_else(|_| TaskPrompt {
            content: String::new(),
            system_prompt: None,
        });
        assert_eq!("[User]\n看这段和这段", prompt.content);
    }

    #[test]
    fn prompt_rejects_empty_or_missing_messages() {
        for messages in [json!(null), json!([]), json!([{ "role": "user", "content": "" }])] {
            assert!(build_prompt(&messages).is_err());
        }
    }

    #[test]
    fn body_matches_the_reference_shape() {
        let target = TaskTarget { model_id: "uuid-1".to_string(), model: "m".to_string() };
        let prompt = TaskPrompt {
            content: "hi".to_string(),
            system_prompt: Some("  sys  ".to_string()),
        };
        let body = build_body(&target, &prompt, "img-1");
        assert_eq!("hi", body["content"].as_str().unwrap_or(""));
        assert_eq!("public_host", body["host_id"].as_str().unwrap_or(""));
        assert_eq!("img-1", body["image_id"].as_str().unwrap_or(""));
        assert_eq!("uuid-1", body["model_id"].as_str().unwrap_or(""));
        assert_eq!("opencode", body["cli_name"].as_str().unwrap_or(""));
        assert_eq!(3600, body["resource"]["life"].as_i64().unwrap_or(0));
        assert_eq!(1, body["resource"]["core"].as_i64().unwrap_or(0));
        assert_eq!(1073741824, body["resource"]["memory"].as_i64().unwrap_or(0));
        assert_eq!("sys", body["system_prompt"].as_str().unwrap_or(""));
        assert_eq!("", body["repo"]["repo_url"].as_str().unwrap_or("x"));

        // 没有 system 时这个键根本不出现（参考的条件插入）
        let prompt = TaskPrompt { content: "hi".to_string(), system_prompt: None };
        let body = build_body(&target, &prompt, "img-1");
        assert!(body.get("system_prompt").is_none());
    }

    #[test]
    fn task_id_accepts_both_envelopes() {
        assert_eq!(
            "t-1",
            task_id_of(&json!({ "data": { "id": "t-1" } })).unwrap_or_default()
        );
        assert_eq!(
            "t-2",
            task_id_of(&json!({ "data": { "task_id": "t-2" } })).unwrap_or_default()
        );
        assert_eq!("t-3", task_id_of(&json!({ "ID": "t-3" })).unwrap_or_default());
        assert!(task_id_of(&json!({ "data": {} })).is_err());
    }
}
