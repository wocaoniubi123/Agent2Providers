//! CatPaw 内容块与工具字段的归一化（`messages.rs` 的下半层；
//! 移植来源 `catpaw-upstream-messages.mjs` 第 41-158 行的
//! `stringifyToolData` / `normalizeImageBlock` / `normalizeContentBlock` /
//! `messageContent` / `validateToolArguments` / `normalizeToolCalls` /
//! `toolResultContent`）。**纯函数，不持锁不做 IO。**
//!
//! ── 字段名映射（UPSTREAM_PROTOCOL §4 是唯一权威）────────────
//! | OpenAI 入站 | 上游块字段 |
//! |---|---|
//! | `image_url: {url, detail}` | `imageUrl: {url, detail}`（**蛇形→驼峰**） |
//! | `function.name` / `toolName` / `name` | `toolName` |
//! | `function.arguments` / `toolParams` / `arguments` | `toolParams`（JSON 文本） |
//! | `tool_call_id` / `toolCallId` | `toolCallId` |
//! | `reasoning_content` / `reasoningContent` | 挂在 text 块上的 `reasoningContent` |
//!
//! ── 为什么每个取值都分「真值判定」与「空值合并」两种 ──────────
//! 原实现是 JavaScript，`a || b`（真值）与 `a ?? b`（空值合并）语义不同：
//! `arguments: ""` 对 `||` 是假值会继续往后找，对 `??` 会**命中空串**；
//! `tool_calls: []` 空数组对 `||` 是**真值**。这些差异会改变归一化结果，
//! 进而改变发给上游的内容，所以每一处都按原实现的运算符选择对应写法。
//!
//! ── 迁移到 wasm 时改了什么 ────────────────────────────────
//! URL 校验从 `url::Url::parse` 换成手写判定（依赖限定四件，没有 url crate）。
//! 口径只覆盖本路径真正需要的部分：协议必须是 http/https、主机名非空、不带
//! 空白与控制字符 —— 上游只把 URL 当图片地址透传，不参与签名。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use serde_json::{json, Map, Value};

use super::errors::CatPawError;
use super::fingerprint::js_truthy;

/// 图片 URL / Data URL 的长度上限（照抄原实现 `MAX_IMAGE_URL_LENGTH`，8MB）。
///
/// 与 `proxy-chat-utils.mjs` 的 `MAX_DATA_URL_LENGTH` 是同一个数：
/// **在归一化阶段**就挡掉超大图片，避免把几十 MB 的 base64 搬进内存。
/// 真正的压缩由宿主在会话准备阶段完成（见 `conversation.rs` 模块头）。
const MAX_IMAGE_URL_LENGTH: usize = 8 * 1024 * 1024;

/// 允许的图片 detail 取值；其它一律回落 `auto`（原实现 `IMAGE_DETAILS`）
const IMAGE_DETAILS: &[&str] = &["auto", "low", "high"];

/// 消息 content → 上游内容块数组（原实现 `messageContent`）。
///
/// 三种形态：字符串（整条变一个 text 块）、`null` / 缺失（空数组）、
/// 数组（逐块归一化）。其它类型报 400。
pub fn message_content(object: &Map<String, Value>) -> Result<Vec<Value>, CatPawError> {
    match object.get("content") {
        Some(Value::String(text)) => Ok(vec![json!({ "type": "text", "text": text })]),
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(blocks)) => blocks.iter().map(normalize_content_block).collect(),
        Some(_) => Err(CatPawError::bad_request(
            "消息 content 必须是字符串、数组或 null",
        )),
    }
}

/// 单个内容块归一化（原实现 `normalizeContentBlock`）。
fn normalize_content_block(block: &Value) -> Result<Value, CatPawError> {
    if let Some(text) = block.as_str() {
        return Ok(json!({ "type": "text", "text": text }));
    }
    let Some(object) = block.as_object() else {
        return Err(CatPawError::bad_request("消息 content block 必须是对象或字符串"));
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") | Some("output_text") => {
            let Some(text) = object.get("text").and_then(Value::as_str) else {
                return Err(CatPawError::bad_request("文本消息缺少 text"));
            };
            let mut normalized = Map::new();
            normalized.insert("type".to_string(), Value::String("text".to_string()));
            normalized.insert("text".to_string(), Value::String(text.to_string()));
            // 原实现用对象展开、先驼峰后蛇形：两者都在时**蛇形覆盖驼峰**
            // （后写的赢）。顺序照抄。
            if let Some(value) = object.get("reasoningContent").and_then(Value::as_str) {
                normalized
                    .insert("reasoningContent".to_string(), Value::String(value.to_string()));
            }
            if let Some(value) = object.get("reasoning_content").and_then(Value::as_str) {
                normalized
                    .insert("reasoningContent".to_string(), Value::String(value.to_string()));
            }
            Ok(Value::Object(normalized))
        }
        Some("image_url") => normalize_image_block(object),
        other => Err(CatPawError::bad_request(format!(
            "不支持的消息内容类型: {}",
            other.unwrap_or_default()
        ))),
    }
}

/// 图片块归一化：`{type:"image_url", image_url:{url,detail}}` →
/// `{type:"image_url", imageUrl:{url,detail}}`（原实现 `normalizeImageBlock`）。
///
/// 校验规则（逐条对照原实现）：
///   - url 缺失 / 非字符串 / 全空白 → 400；
///   - 长度超过 8MB → 400（data URL 与远程 URL 同一个上限，与原实现一致）；
///   - `data:` 开头：必须是 `data:image/(png|jpeg|jpg|gif|webp|bmp);base64,`
///     且正文非空、只含 base64 字符集与空白；
///   - 其它：必须是 http/https 的 URL；
///   - `detail`：只从**对象形态**的 source 里取（裸字符串形态没有 detail），
///     不在 auto/low/high 里一律回落 `auto`。
fn normalize_image_block(object: &Map<String, Value>) -> Result<Value, CatPawError> {
    // `block.image_url || block.imageUrl`：原实现先蛇形后驼峰（真值判定）
    let source = object
        .get("image_url")
        .filter(|value| js_truthy(value))
        .or_else(|| object.get("imageUrl").filter(|value| js_truthy(value)));
    let url = match source {
        Some(Value::String(text)) => Some(text.as_str()),
        Some(Value::Object(nested)) => nested.get("url").and_then(Value::as_str),
        _ => None,
    };
    let Some(url) = url else {
        return Err(CatPawError::bad_request("图片消息缺少 image_url.url"));
    };
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CatPawError::bad_request("图片消息缺少 image_url.url"));
    }
    if trimmed.len() > MAX_IMAGE_URL_LENGTH {
        return Err(CatPawError::bad_request("图片 URL 或 Data URL 超过大小上限"));
    }
    // 前缀判定**大小写敏感**（原实现 `trimmed.startsWith('data:')`）：
    // `DATA:...` 会落到 URL 分支并被「仅支持 http/https」拒绝
    if trimmed.starts_with("data:") {
        if !is_base64_image_data_url(trimmed) {
            return Err(CatPawError::bad_request(
                "图片 Data URL 仅支持 png、jpeg、gif、webp、bmp 的 Base64 格式",
            ));
        }
    } else if !is_http_url(trimmed) {
        return Err(CatPawError::bad_request("图片 URL 仅支持 http/https 协议"));
    }
    let detail = match source {
        Some(Value::Object(nested)) => nested.get("detail").and_then(Value::as_str),
        _ => None,
    }
    .filter(|value| IMAGE_DETAILS.contains(value))
    .unwrap_or("auto");
    Ok(json!({
        "type": "image_url",
        "imageUrl": { "url": trimmed, "detail": detail },
    }))
}

/// `http(s)://<主机>...` 的手写判定（替代 native 的 `url::Url::parse`）。
///
/// 只拦「明显不是 http/https URL」的输入：协议前缀、主机段非空、协议与主机
/// 之间没空字符。更细的 URL 语法不在这里重复实现 —— 上游只把它当图片地址。
fn is_http_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("https://") {
        rest
    } else if let Some(rest) = lower.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty()
        && host
            .chars()
            .all(|ch| !ch.is_whitespace() && !ch.is_control())
}

/// `data:image/(png|jpeg|jpg|gif|webp|bmp);base64,<正文>` 判定（对应原实现正则
/// `/^data:image\/(png|jpe?g|gif|webp|bmp);base64,[a-z0-9+/=\s]+$/i`）。
///
/// 类型部分大小写不敏感（正则的 `i`）；正文由 base64 字符集 + 空白构成，
/// 且**不能为空**（正则的 `+`）。
fn is_base64_image_data_url(value: &str) -> bool {
    let Some((header, body)) = value.split_once(',') else {
        return false;
    };
    let Some(rest) = header.to_ascii_lowercase().strip_prefix("data:").map(str::to_owned) else {
        return false;
    };
    let Some(meta) = rest.strip_suffix(";base64") else {
        return false;
    };
    let Some(subtype) = meta.strip_prefix("image/") else {
        return false;
    };
    if !matches!(subtype, "png" | "jpeg" | "jpg" | "gif" | "webp" | "bmp") {
        return false;
    }
    !body.is_empty()
        && body.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '+'
                || character == '/'
                || character == '='
                || character.is_whitespace()
        })
}

/// 一次归一化后的工具调用（中间形态：id / name / arguments 文本）
pub struct NormalizedToolCall {
    /// 原样保留（**不 trim**，原实现直接取 `call.id`）
    pub id: String,
    pub name: String,
    /// 已规范化的 JSON 文本（原实现 `validateToolArguments` 的返回）
    pub arguments: String,
}

/// assistant 的 tool_calls 归一化（原实现 `normalizeToolCalls`）。
///
/// 同时兼容 `tool_calls` / `toolCalls` 两个字段名，以及三种调用形态：
///   - OpenAI 形态：`{id, type:"function", function:{name, arguments}}`
///   - 上游回显形态：`{toolCallId, toolName, toolParams}`
///   - 简写：`{id, name, arguments}`
///
/// `type` 只支持 `function`（缺失放行，其它值报 400）。
pub fn normalize_tool_calls(
    object: &Map<String, Value>,
) -> Result<Vec<NormalizedToolCall>, CatPawError> {
    // `message.tool_calls || message.toolCalls`（真值判定：空数组是真值 → 走数组分支）
    let calls = object
        .get("tool_calls")
        .filter(|value| js_truthy(value))
        .or_else(|| object.get("toolCalls").filter(|value| js_truthy(value)));
    let Some(calls) = calls else {
        return Ok(Vec::new());
    };
    let Some(calls) = calls.as_array() else {
        return Err(CatPawError::bad_request("assistant.tool_calls 必须是数组"));
    };
    let mut normalized = Vec::with_capacity(calls.len());
    for (call_index, call) in calls.iter().enumerate() {
        let call_object = call.as_object();
        // `call?.type !== undefined && call.type !== 'function'`：
        // 只有**字符串且不等于 function** 才报错（null 视为未给）
        if let Some(kind) = call_object
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
        {
            if kind != "function" {
                return Err(CatPawError::bad_request(format!(
                    "assistant.tool_calls[{call_index}].type 只支持 function"
                )));
            }
        }
        // `call?.id || call?.toolCallId`（真值判定）
        let id = call_object
            .and_then(|value| value.get("id").filter(|item| js_truthy(item)))
            .or_else(|| {
                call_object.and_then(|value| value.get("toolCallId").filter(|item| js_truthy(item)))
            })
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| CatPawError::bad_request("tool_call 缺少 id"))?;
        // `call?.function?.name || call?.toolName || call?.name`（真值判定）
        let name = call_object
            .and_then(|value| value.get("function"))
            .and_then(|value| value.get("name").filter(|item| js_truthy(item)))
            .or_else(|| {
                call_object.and_then(|value| value.get("toolName").filter(|item| js_truthy(item)))
            })
            .or_else(|| {
                call_object.and_then(|value| value.get("name").filter(|item| js_truthy(item)))
            })
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| CatPawError::bad_request("tool_call 缺少 function.name"))?;
        // `call?.function?.arguments ?? call?.toolParams ?? call?.arguments ?? ''`
        // —— **空值合并**：`arguments: ""` 命中空串（不再往后找），
        // 显式 `null` 跳过；三个都没有时是 `''`
        let raw_arguments = call_object
            .and_then(|value| value.get("function"))
            .and_then(|value| value.get("arguments"))
            .filter(|value| !value.is_null())
            .or_else(|| {
                call_object.and_then(|value| value.get("toolParams")).filter(|item| !item.is_null())
            })
            .or_else(|| {
                call_object.and_then(|value| value.get("arguments")).filter(|item| !item.is_null())
            })
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        normalized.push(NormalizedToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments: validate_tool_arguments(&raw_arguments, call_index)?,
        });
    }
    Ok(normalized)
}

/// 工具参数规范化（原实现 `validateToolArguments`）。
///
/// 契约：**必须是 JSON 对象**（字符串形态要先能 `JSON.parse` 成对象）。
/// 字符串输入**原样返回**（保留客户端的空白与键序 —— 它进 `toolParams`、
/// 也进指纹，重序列化会让两条本该相同的消息指纹不同）；
/// 对象输入序列化成紧凑 JSON 文本（原实现 `JSON.stringify(value)`）。
fn validate_tool_arguments(value: &Value, index: usize) -> Result<String, CatPawError> {
    match value {
        Value::String(text) => {
            let parsed: Value =
                match serde_json::from_str(if text.is_empty() { "{}" } else { text }) {
                    Ok(parsed) => parsed,
                    Err(_) => return Err(invalid_arguments(index)),
                };
            if !parsed.is_object() {
                return Err(invalid_arguments(index));
            }
            // 嵌套过深 / 危险键：原实现的 `validateJsonValue` 抛的是**它自己**的
            // 文案，但 `validateToolArguments` 里那一整段被 try/catch 包着，
            // 于是最终对外仍然是「必须是 JSON 对象字符串」—— 照抄这个结果。
            if validate_json_value(&parsed, index).is_err() {
                return Err(invalid_arguments(index));
            }
            Ok(text.clone())
        }
        Value::Object(_) => {
            // 对象形态没有 try/catch 包裹，所以嵌套/危险键的**具体文案**会透出来
            validate_json_value(value, index)?;
            serde_json::to_string(value).map_err(|_| invalid_arguments(index))
        }
        // `value ?? {}`：null / 缺失 → 空对象；其余类型（数字/数组/布尔）报错。
        Value::Null => Ok("{}".to_string()),
        _ => Err(CatPawError::bad_request(format!(
            "assistant.tool_calls[{index}].function.arguments 必须是 JSON 对象"
        ))),
    }
}

fn invalid_arguments(index: usize) -> CatPawError {
    CatPawError::bad_request(format!(
        "assistant.tool_calls[{index}].function.arguments 必须是 JSON 对象字符串"
    ))
}

/// 工具参数允许的最深嵌套（与 `tools.rs` 的 schema 校验同档：32）。
const MAX_ARGUMENTS_DEPTH: usize = 32;

/// 递归校验一个 JSON 值（原实现 `validateJsonValue`）：嵌套深度 ≤ 32，
/// 且不含 `__proto__` / `constructor` / `prototype` 这类危险键。
///
/// Rust 侧本来就没有原型污染问题，但**深嵌套与危险键在工具参数里没有正当
/// 用途**，而它们会被原样转发给上游模型；保持与原实现相同的拒绝口径，
/// 可以避免「Node 版拒绝、Rust 版放行」的行为漂移。
fn validate_json_value(value: &Value, index: usize) -> Result<(), CatPawError> {
    fn walk(value: &Value, depth: usize, index: usize) -> Result<(), CatPawError> {
        if depth > MAX_ARGUMENTS_DEPTH {
            return Err(CatPawError::bad_request(format!(
                "assistant.tool_calls[{index}].function.arguments 嵌套过深"
            )));
        }
        match value {
            Value::Array(items) => items.iter().try_for_each(|item| walk(item, depth + 1, index)),
            Value::Object(object) => {
                for (key, item) in object {
                    if matches!(key.as_str(), "__proto__" | "constructor" | "prototype") {
                        return Err(CatPawError::bad_request(format!(
                            "assistant.tool_calls[{index}].function.arguments 包含不允许的字段 {key}"
                        )));
                    }
                    walk(item, depth + 1, index)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(value, 0, index)
}

/// tool 消息的结果文本（原实现 `toolResultContent`）。
///
/// 取值优先级：`content` → `toolResult` → `result`（`??` 语义：
/// `content: ""` 命中空串；显式 null 跳过；三者都缺 → 空串）。
/// 数组形态：
///   - 空数组 → 空串；
///   - 全字符串 → `\n` 连接；
///   - 全是 text / output_text 块 → 取各块 `text` 后 `\n` 连接；
///   - 其它（或含非 text 块）→ 整体序列化成 JSON（`stringifyToolData`）。
pub fn tool_result_content(
    object: &Map<String, Value>,
    index: usize,
) -> Result<String, CatPawError> {
    let value = object
        .get("content")
        .filter(|item| !item.is_null())
        .or_else(|| object.get("toolResult").filter(|item| !item.is_null()))
        .or_else(|| object.get("result").filter(|item| !item.is_null()));
    let Some(value) = value else {
        return Ok(String::new());
    };
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Array(items) => {
            if items.is_empty() {
                return Ok(String::new());
            }
            if items.iter().all(Value::is_string) {
                return Ok(items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
            let all_text_blocks = items.iter().all(|item| {
                item.as_object().is_some_and(|block| {
                    matches!(
                        block.get("type").and_then(Value::as_str),
                        Some("text") | Some("output_text")
                    ) && block.get("text").and_then(Value::as_str).is_some()
                })
            });
            if all_text_blocks {
                return Ok(items
                    .iter()
                    .filter_map(|item| item.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
            stringify_tool_data(value, index)
        }
        // 非字符串标量（数字/布尔）：原实现 `stringifyToolData` 对它们抛 400
        _ => Err(CatPawError::bad_request(format!(
            "messages[{index}].content 必须是字符串或 JSON 结构"
        ))),
    }
}

/// 任意 JSON 结构 → 紧凑 JSON 文本（`stringifyToolData` 的对象/数组分支）
fn stringify_tool_data(value: &Value, index: usize) -> Result<String, CatPawError> {
    validate_json_value(value, index)?;
    serde_json::to_string(value).map_err(|_| {
        CatPawError::bad_request(format!("messages[{index}].content 无法序列化为 JSON"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_block_snake_to_camel() {
        let object = serde_json::from_value::<Map<String, Value>>(json!({
            "type": "image_url",
            "image_url": { "url": "data:image/png;base64,AAAA", "detail": "high" }
        }))
        .unwrap_or_default();
        let block = normalize_image_block(&object).unwrap_or(Value::Null);
        assert_eq!(block["imageUrl"]["url"], json!("data:image/png;base64,AAAA"));
        assert_eq!(block["imageUrl"]["detail"], json!("high"));
    }

    #[test]
    fn image_block_rejects_bad_scheme() {
        let object = serde_json::from_value::<Map<String, Value>>(json!({
            "type": "image_url",
            "image_url": "ftp://example.com/a.png"
        }))
        .unwrap_or_default();
        assert!(normalize_image_block(&object).is_err());
    }

    #[test]
    fn tool_arguments_keep_raw_string() {
        let text = "{ \"a\" : 1 }";
        assert_eq!(validate_tool_arguments(&Value::String(text.into()), 0).unwrap_or_default(), text);
        assert_eq!(validate_tool_arguments(&Value::Null, 0).unwrap_or_default(), "{}");
        assert!(validate_tool_arguments(&json!([1]), 0).is_err());
    }

    #[test]
    fn tool_result_content_prefers_content() {
        let object = serde_json::from_value::<Map<String, Value>>(json!({
            "content": [{"type":"text","text":"a"},{"type":"text","text":"b"}]
        }))
        .unwrap_or_default();
        assert_eq!(tool_result_content(&object, 0).unwrap_or_default(), "a\nb");
    }
}
