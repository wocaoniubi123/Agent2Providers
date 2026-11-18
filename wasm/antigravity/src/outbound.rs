//! OpenAI Chat 请求 → Antigravity 的 v1internal 信封。
//!
//! ── 信封长什么样 ────────────────────────────────────────────
//! ```json
//! {
//!   "project": "<cloudaicompanionProject>",     // 空则不写
//!   "model": "<上游真名>",
//!   "userAgent": "antigravity" | "jetski",      // 企业账号用 jetski
//!   "requestId": "agent-<随机>",
//!   "request": {
//!     "systemInstruction": { "role": "user", "parts": [ { "text": "…" } ] },
//!     "tools": [ { "functionDeclarations": [ … ] } ],   // **单分组**
//!     "toolConfig": { "functionCallingConfig": { "mode": "VALIDATED" } },
//!     "generationConfig": { "temperature": 1.0, "topP": 1.0, "topK": 40,
//!                           "maxOutputTokens": …, "thinkingConfig": {…} },
//!     "sessionId": "…",
//!     "contents": [ { "role": "user" | "model", "parts": [ … ] } ]
//!   }
//! }
//! ```
//!
//! ── 为什么请求体要包一层 `request` ───────────────────────────
//! 网关的翻译层（`core::protocol::antigravity_stream`）按同样的形状读响应；
//! 请求侧包一层是这个协议的既定形态（两套参考实现一致）。

use agent2api_wasm_sdk::{json, Value};

use super::models;
use super::schema;

/// 一条空 user 的占位正文（上游不接受空 parts）。
const FALLBACK_USER_TEXT: &str = "Please proceed with the task.";
/// 首条不是 user 时补的开场白。
const LEADING_USER_TEXT: &str = "Begin.";

/// 一条 assistant 消息的思考块占位签名（Claude 家族要求历史轮以思考块开头）。
const SKIP_SIGNATURE_SENTINEL: &str = "skip_thought_signature_validator";

/// 请求转换失败的原因（调用方翻成 400）。
#[derive(Debug)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// 文本内容（字符串 / 内容块数组）。
fn content_text(content: &Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    let Some(parts) = content.as_array() else {
        return String::new();
    };
    parts
        .iter()
        .filter_map(|part| match part.get("type").and_then(Value::as_str) {
            Some("text" | "input_text" | "output_text") => part.get("text").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// system / developer 消息 → `systemInstruction`。
fn system_instruction(messages: &[Value]) -> Option<Value> {
    let texts: Vec<String> = messages
        .iter()
        .filter(|message| matches!(message.get("role").and_then(Value::as_str), Some("system" | "developer")))
        .map(|message| content_text(message.get("content").unwrap_or(&Value::Null)))
        .filter(|text| !text.trim().is_empty())
        .collect();
    if texts.is_empty() {
        return None;
    }
    Some(json!({ "role": "user", "parts": [{ "text": texts.join("\n\n") }] }))
}

/// 一条内容里的图片（`data:` 内联 base64 → `inlineData`）。
fn image_part(part: &Value) -> Option<Value> {
    let url = part
        .pointer("/image_url/url")
        .and_then(Value::as_str)
        .or_else(|| part.get("image_url").and_then(Value::as_str))?;
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    if !meta.contains(";base64") || data.is_empty() {
        return None;
    }
    let mime = meta.split(';').next().unwrap_or("image/png");
    Some(json!({ "inlineData": { "mimeType": mime, "data": data } }))
}

/// 一条内容 → parts。
fn content_parts(content: &Value) -> Vec<Value> {
    let mut parts: Vec<Value> = Vec::new();
    if let Some(text) = content.as_str() {
        if !text.is_empty() {
            parts.push(json!({ "text": text }));
        }
        return parts;
    }
    let Some(list) = content.as_array() else {
        return parts;
    };
    for part in list {
        match part.get("type").and_then(Value::as_str) {
            Some("text" | "input_text" | "output_text") => {
                if let Some(text) = part.get("text").and_then(Value::as_str).filter(|text| !text.is_empty()) {
                    parts.push(json!({ "text": text }));
                }
            }
            Some("image_url" | "input_image") => {
                if let Some(image) = image_part(part) {
                    parts.push(image);
                }
            }
            _ => {}
        }
    }
    parts
}

/// 工具参数：JSON 字符串 → 对象。
fn call_args(value: &Value) -> Value {
    if let Some(text) = value.as_str() {
        return serde_json::from_str::<Value>(text).unwrap_or_else(|_| json!({}));
    }
    if value.is_object() {
        value.clone()
    } else {
        json!({})
    }
}

/// 工具结果 → `functionResponse`。
fn tool_result_part(message: &Value) -> Value {
    let name = message
        .get("name")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("tool");
    let text = content_text(message.get("content").unwrap_or(&Value::Null));
    json!({
        "functionResponse": {
            "name": name,
            "response": { "result": if text.is_empty() { "(no output)".to_string() } else { text } },
        }
    })
}

/// 一条 assistant 的工具调用 → `functionCall` part（带客户端带回的签名）。
fn function_call_part(call: &Value) -> Option<Value> {
    let name = call.pointer("/function/name").and_then(Value::as_str).filter(|text| !text.is_empty())?;
    let mut part = json!({
        "functionCall": {
            "name": name,
            "args": call_args(call.pointer("/function/arguments").unwrap_or(&Value::Null)),
        }
    });
    // 签名优先取客户端带回的位置（Google 自家 OpenAI 兼容端点的字段）。
    let signature = call
        .pointer("/extra_content/google/thought_signature")
        .and_then(Value::as_str)
        .or_else(|| call.get("thoughtSignature").and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty());
    if let Some(signature) = signature {
        part["thoughtSignature"] = json!(signature);
    }
    Some(part)
}

/// 把 messages 折成 `contents`（相邻同角色合并）。
fn contents_of(messages: &[Value]) -> Vec<Value> {
    let mut contents: Vec<Value> = Vec::new();
    for message in messages {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("user");
        let mut parts: Vec<Value> = Vec::new();
        let target_role = match role {
            "system" | "developer" => continue,
            "assistant" => "model",
            "tool" => "user",
            _ => "user",
        };
        if role == "tool" {
            parts.push(tool_result_part(message));
        } else if role == "assistant" {
            let text = content_text(message.get("content").unwrap_or(&Value::Null));
            if !text.is_empty() {
                parts.push(json!({ "text": text }));
            }
            for call in message.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                if let Some(part) = function_call_part(call) {
                    parts.push(part);
                }
            }
        } else {
            parts = content_parts(message.get("content").unwrap_or(&Value::Null));
        }
        if parts.is_empty() {
            continue;
        }
        // 相邻同角色合并（上游要求 user / model 交替）。
        if let Some(last) = contents.last_mut() {
            if last.get("role").and_then(Value::as_str) == Some(target_role) {
                if let Some(list) = last.get_mut("parts").and_then(Value::as_array_mut) {
                    list.extend(parts);
                    continue;
                }
            }
        }
        contents.push(json!({ "role": target_role, "parts": parts }));
    }
    if contents.is_empty() {
        contents.push(json!({ "role": "user", "parts": [{ "text": FALLBACK_USER_TEXT }] }));
    }
    // 首条必须是 user。
    if contents.first().and_then(|entry| entry.get("role")).and_then(Value::as_str) == Some("model") {
        contents.insert(0, json!({ "role": "user", "parts": [{ "text": LEADING_USER_TEXT }] }));
    }
    contents
}

/// Claude 的历史轮要以思考块开头（该家族「服务端强制思考」）。
fn ensure_claude_thinking_leading(contents: &mut [Value]) -> usize {
    let mut added = 0;
    for entry in contents.iter_mut() {
        if entry.get("role").and_then(Value::as_str) != Some("model") {
            continue;
        }
        let Some(parts) = entry.get_mut("parts").and_then(Value::as_array_mut) else {
            continue;
        };
        let already = parts.first().is_some_and(|part| {
            part.get("thought").and_then(Value::as_bool) == Some(true)
                || part.get("thoughtSignature").is_some()
        });
        if already {
            continue;
        }
        parts.insert(
            0,
            json!({
                "text": "…",
                "thought": true,
                "thoughtSignature": SKIP_SIGNATURE_SENTINEL,
            }),
        );
        added += 1;
    }
    added
}

/// 工具声明（单分组 + schema 清洗）。
fn function_declarations(chat: &Value) -> Option<Vec<Value>> {
    let tools = chat.get("tools").and_then(Value::as_array)?;
    let mut declarations: Vec<Value> = Vec::new();
    for tool in tools {
        let function = tool.get("function").unwrap_or(tool);
        let Some(name) = function.get("name").and_then(Value::as_str).filter(|text| !text.is_empty()) else {
            continue;
        };
        let parameters = function
            .get("parameters")
            .or_else(|| function.get("input_schema"))
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
        declarations.push(json!({
            "name": name,
            "description": function.get("description").and_then(Value::as_str).unwrap_or(""),
            "parameters": schema::clean_schema(&parameters),
        }));
    }
    (!declarations.is_empty()).then_some(declarations)
}

/// 思考预算（客户端显式档位 → 预算）。
fn thinking_budget(chat: &Value, model: &str) -> Option<i64> {
    let effort = chat
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| chat.pointer("/reasoning/effort").and_then(Value::as_str))
        .unwrap_or("");
    let budget = match effort {
        "low" => 1_024,
        "medium" => 8_192,
        "high" => 24_576,
        "xhigh" | "max" => 32_768,
        _ => 0,
    };
    if budget > 0 {
        return Some(budget);
    }
    let explicit = chat
        .pointer("/thinking/budget_tokens")
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1_024, 32_768) as i64);
    if explicit.is_some() {
        return explicit;
    }
    if models::is_claude_model(model) {
        // Claude 家族默认开思考（上游强制），给一档保守预算。
        return Some(1_024);
    }
    None
}

/// `generationConfig`。
fn generation_config(chat: &Value, model: &str, image_gen: bool) -> Value {
    if image_gen {
        return json!({ "responseModalities": ["TEXT", "IMAGE"] });
    }
    let mut config = serde_json::Map::new();
    if let Some(temperature) = chat.get("temperature").and_then(Value::as_f64) {
        config.insert("temperature".to_string(), json!(temperature));
    } else {
        config.insert("temperature".to_string(), json!(1.0));
    }
    if let Some(top_p) = chat.get("top_p").and_then(Value::as_f64) {
        config.insert("topP".to_string(), json!(top_p));
    } else {
        config.insert("topP".to_string(), json!(1.0));
    }
    config.entry("topK".to_string()).or_insert_with(|| json!(40));
    let max = chat
        .get("max_completion_tokens")
        .and_then(Value::as_i64)
        .or_else(|| chat.get("max_tokens").and_then(Value::as_i64))
        .unwrap_or(32_768);
    if max > 0 {
        config.insert("maxOutputTokens".to_string(), json!(max.min(65_536)));
    }
    if let Some(budget) = thinking_budget(chat, model) {
        config.insert(
            "thinkingConfig".to_string(),
            json!({ "includeThoughts": true, "thinkingBudget": budget }),
        );
    }
    Value::Object(config)
}

/// 首条 user 的文本（sessionId 派生输入之一）。
fn first_user_text(contents: &[Value]) -> String {
    contents
        .iter()
        .find(|entry| entry.get("role").and_then(Value::as_str) == Some("user"))
        .and_then(|entry| entry.pointer("/parts/0/text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(512)
        .collect()
}

/// 派生 sessionId（同一次会话内稳定，跨会话不同）。
fn session_id(project: &str, model: &str, system: &str, first_user: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(project.as_bytes());
    hasher.update(b"\0");
    hasher.update(model.as_bytes());
    hasher.update(b"\0");
    hasher.update(system.as_bytes());
    hasher.update(b"\0");
    hasher.update(first_user.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(12).map(|byte| format!("{byte:02x}")).collect();
    format!("session-{hex}")
}

/// 请求 id。
fn request_id() -> String {
    let millis = agent2api_wasm_sdk::now();
    format!("agent-{millis:x}")
}

/// 构造请求体。
pub fn request_from_chat(chat: &Value, model: &str, project: &str, enterprise: bool) -> Result<Value, ConvertError> {
    let messages = chat
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| ConvertError("缺少 messages 数组".to_string()))?;
    let image_gen = models::is_image_model(model);
    let system = system_instruction(messages);
    let system_text = system
        .as_ref()
        .and_then(|value| value.pointer("/parts/0/text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut contents = contents_of(messages);
    if models::is_claude_model(model) {
        ensure_claude_thinking_leading(&mut contents);
    }
    let mut request = serde_json::Map::new();
    if !image_gen {
        if let Some(system) = system {
            request.insert("systemInstruction".to_string(), system);
        }
        if let Some(declarations) = function_declarations(chat) {
            request.insert("tools".to_string(), json!([{ "functionDeclarations": declarations }]));
            request.insert(
                "toolConfig".to_string(),
                json!({ "functionCallingConfig": { "mode": "VALIDATED" } }),
            );
        }
    }
    request.insert("generationConfig".to_string(), generation_config(chat, model, image_gen));
    let first_user = first_user_text(&contents);
    request.insert("sessionId".to_string(), json!(session_id(project, model, &system_text, &first_user)));
    request.insert("contents".to_string(), Value::Array(contents));

    let mut envelope = serde_json::Map::new();
    let project = project.trim();
    if !project.is_empty() {
        envelope.insert("project".to_string(), json!(project));
    }
    envelope.insert("model".to_string(), json!(model));
    envelope.insert("userAgent".to_string(), json!(if enterprise { "jetski" } else { "antigravity" }));
    envelope.insert("requestId".to_string(), json!(request_id()));
    envelope.insert("request".to_string(), Value::Object(request));
    Ok(Value::Object(envelope))
}
