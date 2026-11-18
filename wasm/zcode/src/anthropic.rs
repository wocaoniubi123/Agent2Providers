//! Anthropic Messages 与 Chat Completions 的**双向转换**（本家套餐池通道那一段）。
//!
//! ── 为什么插件要自己折 ──────────────────────────────────────
//! native 侧 `plan.rs` 把请求报成 `UpstreamKind::Anthropic`，由**网关的翻译层**
//! 把请求翻成 Messages、把上游的 Anthropic SSE 折回 chat SSE。Wasm 插件没有
//! 这层翻译（`conversation` 通道要求插件自己吐出「已经是 chat SSE 形态」的
//! 字节），所以两份转换搬进插件：
//!
//!   - 去程：[`request_from_chat`]（chat 请求体 → Messages 请求体）
//!   - 回程：[`Stream`]（上游 Anthropic SSE → chat SSE 帧）
//!   - 降级：[`frames_from_message`]（上游回非流式 JSON 时的一次性折叠）
//!
//! 参考实现：本仓库 `wasm/loomy/src/anthropic.rs`（同一套协议、已被验证过的
//! 状态机结构）+ 网关 `core/protocol/anthropic_outbound.rs`（字段口径）。
//! 本文件在 loomy 那份的基础上**补回** native `zcode/anthropic_outbound.rs`
//! 多出来的三处：`cache_control` / `_wb_is_error` 内部字段的恢复、工具声明上的
//! 缓存断点、以及 `input_schema` 归一（三处都在注释里标了出处）。
//!
//! ── 与参考实现的删减（本家用不到，不是漏做）──────────────────
//!   - 服务端原生工具（`web_search_*`）的保真携带：那是网关方言层的东西，
//!     插件拿到的是定稿 chat 体，没有「目标协议是否与来源相同」可判。这里把
//!     非 function 形态的声明收起来**不发给上游**（发一个上游不认识的工具
//!     声明等于必然 400），留痕见 [`tool_to_anthropic`]。
//!   - `adaptive` 思考模式：本家上游只认 `budget_tokens`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! `panic = "abort"`：本文件零 `unwrap()` / `expect()`，解析失败一律「跳过该帧」。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{
    content_parts, content_text, is_truthy, json_text, new_uuid, parse_json_object, string_field,
    string_value,
};

/// Anthropic 的 `max_tokens` 缺省值（与网关 `protocol::anthropic::DEFAULT_MAX_TOKENS` 同值）。
///
/// Anthropic 官方**要求**这个字段必填；客户端漏填时给一个保守值而不是报错
/// （报错会让「只差一个字段」的请求整个失败，而 8192 对绝大多数对话够用）。
pub const DEFAULT_MAX_TOKENS: i64 = 8192;

/// 请求体里的内部暂存字段（与网关 `protocol::mod` 的同名常量逐字相同）：
/// 客户端没给、由**入口**按协议带来的「缓存断点」与「这条 tool_result 是错误」。
/// 它们不发上游，只在两个方向之间传递语义。
const FIELD_CACHE_CONTROL: &str = "_wb_cache_control";
const FIELD_IS_ERROR: &str = "_wb_is_error";

// ─── 去程：chat 请求体 → Anthropic Messages 请求体 ─────────────

/// Chat Completions 请求体 → Anthropic Messages 请求体。
///
/// ── 逐字段对着 `anthropic::chat_from_anthropic` 反推 ──────────
///   - `model`（由调用方给上游真名）
///   - `system` ← chat 的 system / developer 消息（多条空行拼接；带断点时用
///     块数组形态，`cache_control` 落在最后一块）
///   - `messages` ← 其余消息（tool 消息拆进 user 的 tool_result 块；
///     tool_calls 进 assistant 的 tool_use 块；连续同角色合并成一条 ——
///     Anthropic 要求 user / assistant 交替）
///   - `max_tokens` ← `max_tokens` / `max_completion_tokens`，缺省
///     [`DEFAULT_MAX_TOKENS`]（Anthropic 必填）
///   - `temperature` / `top_p` / `stop_sequences`（← chat `stop`）
///   - `tools`（chat 嵌套 function → `{name, description, input_schema}`）
///   - `tool_choice`（`required`→`any`、`{type:function,function:{name}}`
///     →`{type:"tool",name}`）
///   - `thinking` ← chat `reasoning_effort`（等级折算 budget，见
///     [`thinking_budget`]；同时可能抬高 max_tokens）
///
/// 注意：套餐池通道会在这一步之后再用 `reasoning::apply_to_anthropic` 覆盖
/// GLM-5.3 家族的预算装配（native `plan::build_request` 的同一顺序）。
pub fn request_from_chat(chat: &Value, model: &str) -> Result<Value> {
    let Some(messages_in) = chat.get("messages").and_then(Value::as_array) else {
        return Err(Error::http(400, "请求缺少 messages 数组"));
    };
    let mut system: Vec<String> = Vec::new();
    // system 上的缓存断点（任一条 system 消息带断点即生效 —— 断点标记的是
    // 「缓存前缀到此为止」，多段 system 拼接后断点落在整段末尾）
    let mut system_cache: Option<Value> = None;
    let mut messages: Vec<Value> = Vec::new();
    for message in messages_in {
        let role = {
            let raw = string_field(message, "role").to_lowercase();
            if raw == "developer" {
                "system".to_string()
            } else if raw.is_empty() {
                "user".to_string()
            } else {
                raw
            }
        };
        if role == "system" {
            let text = content_text(message.get("content").unwrap_or(&Value::Null));
            if !text.trim().is_empty() {
                system.push(text);
                if let Some(cache) = message
                    .get(FIELD_CACHE_CONTROL)
                    .filter(|value| value.is_object())
                {
                    system_cache = Some(cache.clone());
                }
            }
            continue;
        }
        let blocks = blocks_of(message, &role);
        if blocks.is_empty() {
            continue;
        }
        let target_role = if role == "assistant" { "assistant" } else { "user" };
        append_merged(&mut messages, target_role, blocks);
    }

    let mut out = serde_json::Map::new();
    out.insert("model".to_string(), Value::String(model.to_string()));
    out.insert("messages".to_string(), Value::Array(messages));
    out.insert(
        "stream".to_string(),
        Value::Bool(chat.get("stream").and_then(Value::as_bool).unwrap_or(false)),
    );
    if !system.is_empty() {
        match system_cache {
            Some(cache) => {
                // 带断点的 system 用块数组形态（Anthropic 两种都认），
                // cache_control 落在最后一块 —— 与入口暂存时的位置一致
                let mut blocks: Vec<Value> = system
                    .iter()
                    .map(|text| json!({ "type": "text", "text": text }))
                    .collect();
                if let Some(last) = blocks.last_mut() {
                    if let Some(object) = last.as_object_mut() {
                        object.insert("cache_control".to_string(), cache);
                    }
                }
                out.insert("system".to_string(), Value::Array(blocks));
            }
            None => {
                out.insert("system".to_string(), Value::String(system.join("\n\n")));
            }
        }
    }

    // thinking 先判定：它决定 max_tokens 的下限，也决定 temperature/top_p
    // 能不能带（Anthropic 拒绝采样参数与扩展思考并存，temperature 只允许 1）
    let thinking = chat
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .and_then(thinking_budget);
    let mut max_tokens = ["max_tokens", "max_completion_tokens"]
        .iter()
        .find_map(|key| chat.get(*key).and_then(Value::as_i64).filter(|value| *value > 0))
        .unwrap_or(DEFAULT_MAX_TOKENS);
    if let Some(budget) = thinking {
        // Anthropic 要求 budget_tokens < max_tokens；不够就抬到 budget 之上
        if max_tokens <= budget {
            max_tokens = budget + 1024;
        }
    }
    out.insert("max_tokens".to_string(), Value::from(max_tokens));
    match thinking {
        Some(budget) => {
            out.insert(
                "thinking".to_string(),
                json!({ "type": "enabled", "budget_tokens": budget }),
            );
        }
        None => {
            for key in ["temperature", "top_p"] {
                if let Some(value) = chat.get(key).filter(|value| !value.is_null()) {
                    out.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    // stop → stop_sequences（chat 允许字符串或数组，Anthropic 只认数组）
    if let Some(stop) = chat.get("stop").filter(|value| is_truthy(value)) {
        let list = match stop {
            Value::Array(items) => items.clone(),
            other => vec![other.clone()],
        };
        if !list.is_empty() {
            out.insert("stop_sequences".to_string(), Value::Array(list));
        }
    }
    // 工具声明：函数工具翻译成 Anthropic 形态；原生（服务端执行）声明剔除
    // 并留痕。静默剔除与硬塞给上游都是难查的形态，所以两件事分开做：
    // 返回的 payload 里没有它，日志在调用方（`plan`）按同一判据再记一条。
    if let Some(tools) = chat.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools.iter().filter_map(tool_to_anthropic).collect();
        if !converted.is_empty() {
            out.insert("tools".to_string(), Value::Array(converted));
        }
    }
    if let Some(choice) = chat.get("tool_choice").filter(|value| is_truthy(value)) {
        // 点名的工具被剔除时 `tool_choice` 一并撤掉：留着它上游会按
        // 「指定的工具不存在」报错，把一次「搜索不可用」升级成整轮 400
        if !is_native_choice(choice) {
            out.insert("tool_choice".to_string(), tool_choice_to_anthropic(choice));
        }
    }
    Ok(Value::Object(out))
}

/// 一条非 system 的 chat 消息 → Anthropic 内容块数组。
fn blocks_of(message: &Value, role: &str) -> Vec<Value> {
    // tool 消息 → tool_result 块（挂在 user 消息上；Anthropic 要求
    // tool_result 与 assistant 的 tool_use 成对，tool_use_id 必须指向真实存在
    // 的 id —— 缺 id 说明客户端数据本身缺配对，伪造一个只会让上游的配对校验
    // 指向更莫名其妙的块，所以原样发、让上游如实报错）
    if role == "tool" {
        let is_error = message.get(FIELD_IS_ERROR).and_then(Value::as_bool) == Some(true);
        let cache = message.get(FIELD_CACHE_CONTROL).filter(|value| value.is_object());
        let mut block = json!({
            "type": "tool_result",
            "tool_use_id": string_field(message, "tool_call_id"),
            "content": tool_result_content(message.get("content").unwrap_or(&Value::Null)),
        });
        if let Some(object) = block.as_object_mut() {
            if is_error {
                object.insert("is_error".to_string(), Value::Bool(true));
            }
            if let Some(cache) = cache {
                object.insert("cache_control".to_string(), cache.clone());
            }
        }
        return vec![block];
    }
    let mut blocks: Vec<Value> = Vec::new();
    if role == "assistant" {
        // 思考 → thinking 块（不带 signature：chat 侧没有签名概念）
        let reasoning = {
            let from_field = string_field(message, "reasoning_content");
            if from_field.is_empty() {
                string_field(message, "reasoning")
            } else {
                from_field
            }
        };
        if !reasoning.is_empty() {
            blocks.push(json!({ "type": "thinking", "thinking": reasoning }));
        }
    }
    // 正文：字符串 / 块数组（图片 → image 块）
    match message.get("content").unwrap_or(&Value::Null) {
        Value::String(text) => {
            if !text.is_empty() {
                blocks.push(json!({ "type": "text", "text": text }));
            }
        }
        content => {
            for part in content_parts(content) {
                if let Some(text) = part.as_str() {
                    if !text.is_empty() {
                        blocks.push(json!({ "type": "text", "text": text }));
                    }
                    continue;
                }
                let kind = string_field(part, "type").to_lowercase();
                match kind.as_str() {
                    "text" | "input_text" | "output_text" => {
                        let text = string_field(part, "text");
                        if !text.is_empty() {
                            blocks.push(json!({ "type": "text", "text": text }));
                        }
                    }
                    "image_url" | "input_image" if role != "assistant" => {
                        if let Some(image) = image_to_anthropic(part) {
                            blocks.push(image);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // 工具调用 → tool_use 块（input 必须是对象）
    if role == "assistant" {
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let id = {
                    let raw = string_field(call, "id");
                    if raw.is_empty() {
                        random_id("toolu")
                    } else {
                        raw
                    }
                };
                blocks.push(json!({
                    "type": "tool_use",
                    "id": id,
                    "name": call.pointer("/function/name").map(string_value).unwrap_or_default(),
                    "input": parse_json_object(
                        call.pointer("/function/arguments").unwrap_or(&Value::Null)
                    ),
                }));
            }
        }
    }
    // 消息级缓存断点 → 落回最后一个可挂载的块。Anthropic 不允许把
    // cache_control 挂在 thinking 块上，跳过；没有可挂的块时整段放弃
    // （给上游发一个非法位置的断点只会换来 400）
    if let Some(cache) = message.get(FIELD_CACHE_CONTROL).filter(|value| value.is_object()) {
        for block in blocks.iter_mut().rev() {
            let kind = string_field(block, "type");
            let mountable = matches!(kind.as_str(), "text" | "tool_use" | "tool_result" | "image");
            if mountable {
                if let Some(object) = block.as_object_mut() {
                    object.insert("cache_control".to_string(), cache.clone());
                }
                break;
            }
        }
    }
    blocks
}

/// 连续同角色的消息合并成一条（Anthropic 要求 user / assistant 交替，
/// 拆开的两条同角色消息会被上游拒）。
fn append_merged(messages: &mut Vec<Value>, role: &str, blocks: Vec<Value>) {
    if let Some(last) = messages.last_mut() {
        let same_role = last.get("role").and_then(Value::as_str) == Some(role);
        if same_role {
            if let Some(existing) = last.get_mut("content").and_then(Value::as_array_mut) {
                existing.extend(blocks);
                return;
            }
        }
    }
    messages.push(json!({ "role": role, "content": blocks }));
}

/// 工具结果 → Anthropic 的 `tool_result.content`。
///
/// ── 与入站方向相反的取舍（不是笔误）──────────────────────────
/// 入站（Anthropic → chat）图片**必须**挪出 tool 消息：Chat 不许 `tool` 角色带
/// 图片（OpenAI 直接 400），所以那边图片落到相邻的 user 消息上。出站这边不用
/// 搬 —— Anthropic 的 `tool_result.content` 本来就接受嵌套内容块（官方收
/// `text` / `image` / `document` / `search_result`），图片留在结果里才是保真形态。
///
/// 没有图片时保持字符串形态：字符串对各家上游最友好，也是原来就在发的形状。
fn tool_result_content(content: &Value) -> Value {
    let text_of_content = |content: &Value| -> String {
        let text = content_text(content);
        if text.is_empty() {
            let raw = json_text(content);
            if raw.is_empty() {
                "(empty)".to_string()
            } else {
                raw
            }
        } else {
            text
        }
    };
    let images: Vec<Value> = content_parts(content)
        .iter()
        .filter(|part| {
            matches!(
                string_field(part, "type").to_lowercase().as_str(),
                "image" | "image_url" | "input_image"
            )
        })
        .filter_map(|part| image_to_anthropic(part).or_else(|| part.as_object().map(|_| part.clone())))
        .collect();
    if images.is_empty() {
        return Value::String(text_of_content(content));
    }
    let mut blocks: Vec<Value> = Vec::new();
    let text = content_text(content);
    if !text.is_empty() {
        blocks.push(json!({ "type": "text", "text": text }));
    }
    blocks.extend(images);
    Value::Array(blocks)
}

/// Chat 的 image_url 块 → Anthropic 的 image 块。
///
/// 两个来源都要认：`data:` URI（解码出 media_type 与 base64 数据）→
/// `source:{type:"base64"}`；http(s) 外链 → `source:{type:"url"}`。
/// 其余形态（相对路径、非法 data URI）丢弃 —— 发一个上游读不懂的 source
/// 只会让整条请求 400。
fn image_to_anthropic(part: &Value) -> Option<Value> {
    // 已经是 Anthropic 形态的 image 块就原样带过去（工具结果里可能出现）
    if string_field(part, "type").eq_ignore_ascii_case("image") && part.get("source").is_some() {
        return Some(part.clone());
    }
    let source = part.get("image_url").unwrap_or(part);
    let url = match source {
        Value::String(text) => text.clone(),
        other => string_field(other, "url"),
    };
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    if let Some(rest) = url.strip_prefix("data:") {
        let (meta, data) = rest.split_once(',')?;
        // `data:<media_type>;base64,<data>`；没有 `;base64` 后缀的形态
        // （非 base64 编码）Anthropic 不接受，丢弃
        let media_type = meta.strip_suffix(";base64")?;
        if data.is_empty() {
            return None;
        }
        let media_type = if media_type.is_empty() {
            "image/png".to_string()
        } else {
            media_type.to_string()
        };
        return Some(json!({
            "type": "image",
            "source": { "type": "base64", "media_type": media_type, "data": data },
        }));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(json!({
            "type": "image",
            "source": { "type": "url", "url": url },
        }));
    }
    None
}

/// 一条工具声明是不是「原生（服务端执行）」形态。
///
/// 判据与网关 `native_tool::is_native` 的第一条一致：带 `_wb_` 来源标记，
/// 或类型不是 `function`（`web_search` / `mcp` 这类）。插件没有网关的
/// `_wb_origin` 上下文，所以只按「形态」判 —— 判错的方向是安全的（见模块头）。
fn is_native(tool: &Value) -> bool {
    if tool.get("_wb_origin").is_some() {
        return true;
    }
    match tool.get("type").and_then(Value::as_str) {
        None => false,
        Some(kind) => !kind.eq_ignore_ascii_case("function"),
    }
}

/// `tool_choice` 是否点名了一个原生工具（点到了就不发 tool_choice）。
fn is_native_choice(choice: &Value) -> bool {
    if choice.get("type").and_then(Value::as_str) == Some("function") {
        return false;
    }
    let name = {
        let nested = choice
            .pointer("/function/name")
            .map(string_value)
            .unwrap_or_default();
        if nested.is_empty() {
            string_field(choice, "name")
        } else {
            nested
        }
    };
    // 原生工具的名字在 chat 入口带上 `_wb_native:` 前缀（网关的留痕约定）；
    // 没有前缀时按「不是原生」处理，交给上游如实报错。
    name.starts_with("_wb_native:") || choice.get("type").and_then(Value::as_str) == Some("native")
}

/// Chat 工具声明 → Anthropic 工具（`input_schema` 形态）。
fn tool_to_anthropic(tool: &Value) -> Option<Value> {
    if is_native(tool) {
        return None;
    }
    // chat 侧只会有嵌套形态；裸 function 对象也容忍（两种形态等价）
    let function = tool.get("function").unwrap_or(tool);
    let name = string_field(function, "name");
    if name.is_empty() {
        return None;
    }
    let mut out = serde_json::Map::new();
    out.insert("name".to_string(), Value::String(name));
    if let Some(description) = function.get("description").filter(|value| is_truthy(value)) {
        out.insert("description".to_string(), description.clone());
    }
    let schema = function.get("parameters").unwrap_or(&Value::Null);
    out.insert("input_schema".to_string(), normalize_input_schema(schema));
    // 工具定义上的缓存断点随内部暂存字段恢复（工具清单大而稳定，是提示缓存
    // 收益最高的一段）
    if let Some(cache) = tool.get(FIELD_CACHE_CONTROL).filter(|value| value.is_object()) {
        out.insert("cache_control".to_string(), cache.clone());
    }
    Some(Value::Object(out))
}

/// `input_schema` 归一：Anthropic 要求顶层 `type:"object"`、`properties` 存在。
fn normalize_input_schema(schema: &Value) -> Value {
    let kind = string_field(schema, "type").to_lowercase();
    if !schema.is_object() || (!kind.is_empty() && kind != "object") {
        return json!({ "type": "object", "properties": {} });
    }
    let mut out = schema.as_object().cloned().unwrap_or_default();
    out.insert("type".to_string(), Value::String("object".to_string()));
    out.entry("properties".to_string()).or_insert_with(|| json!({}));
    Value::Object(out)
}

/// Chat 的 tool_choice → Anthropic 的 tool_choice（`required`↔`any`、
/// function↔tool）。
fn tool_choice_to_anthropic(choice: &Value) -> Value {
    if let Some(text) = choice.as_str() {
        return match text {
            "required" => json!({ "type": "any" }),
            "none" => json!({ "type": "none" }),
            // `auto` 与其余未识别的字符串都落到 auto（Anthropic 只认这四个形态；
            // 发一个它不认识的字符串是必然的 400）
            _ => json!({ "type": "auto" }),
        };
    }
    let name = {
        let nested = choice
            .pointer("/function/name")
            .map(string_value)
            .unwrap_or_default();
        if nested.is_empty() {
            string_field(choice, "name")
        } else {
            nested
        }
    };
    if name.is_empty() {
        return json!({ "type": "auto" });
    }
    json!({ "type": "tool", "name": name })
}

/// chat 的 `reasoning_effort` → Anthropic 的 `budget_tokens`。
///
/// 一档一个值，按通用档位表的强弱序折算；表外等级（自定义输入）没有可翻译的
/// 目标，返回 None（与 `model_rules` 的「表外值不参与转发」同一闸门）：
///
/// ```text
///   rank 0..1（minimal / low）→ 1024
///   rank 2    （medium）      → 4096
///   rank 3    （high）        → 10240
///   rank 4..5（xhigh / max）  → 32768
/// ```
///
/// 分档值与参考实现 `thinkingBudget` 对齐（它的 low/medium/high/max 四个值
/// 原样落在这四档上）。
fn thinking_budget(effort: &str) -> Option<i64> {
    let rank = super::reasoning::effort_rank(effort)?;
    Some(match rank {
        0 | 1 => 1024,
        2 => 4096,
        3 => 10240,
        _ => 32768,
    })
}

/// 生成一个带前缀的随机 id（`toolu_…` / `chatcmpl_…`）。
///
/// 取不到宿主随机源时回落到时间派生 —— 这类 id 只是「这一条消息 / 这一个工具
/// 调用」的关联标识，不需要密码学强度；而缺 id 会让上游的配对校验失败。
fn random_id(prefix: &str) -> String {
    let raw = new_uuid().unwrap_or_else(|| format!("{:x}", super::common::now_ms()));
    let compact: String = raw.chars().filter(|ch| *ch != '-').collect();
    let tail: String = compact.chars().take(24).collect();
    format!("{prefix}_{tail}")
}

// ─── 回程：Anthropic SSE → chat SSE ─────────────────────────

/// 组装一条 **chat** SSE 帧（`data: <JSON>\n\n`，不带 `event:` 行）。
fn chat_frame(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    format!("data: {text}\n\n")
}

/// 收尾帧标记（chat 协议的结束信号）
const DONE: &str = "data: [DONE]\n\n";

/// 上游 Anthropic SSE → 标准 chat SSE 帧（状态机）。
///
/// 事件折法（对照网关 `ChatFromAnthropicStream`，字段口径按 chat 侧收敛）：
///   - `message_start` → 首帧（role assistant）+ 记下 message.id 与 `message.usage`
///     （**按字段**吸收，见 [`Stream::absorb_usage`]）
///   - `content_block_start`（tool_use）→ `tool_calls` 宣告帧（id / name）
///   - `content_block_delta`：`text_delta` → `delta.content`；
///     `thinking_delta` → `delta.reasoning_content`；
///     `input_json_delta` → `delta.tool_calls[…]`；`signature_delta` 丢弃
///   - `content_block_stop` → 该工具块一个参数分片都没来过时补一个空对象帧
///   - `message_delta` → 记 stop_reason 与 usage（同样按字段吸收：真实的
///     `input_tokens` 只在这一帧出现）
///   - `message_stop` → 收尾帧 + usage 帧 + `data: [DONE]`
///   - `error` → 错误帧 + `data: [DONE]`，并把错误留给调用方决定是否抛出
///   - `ping` 与非帧行忽略
pub struct Stream {
    /// 输出帧的 model（发给上游的真名）
    model: String,
    id: String,
    created: i64,
    started: bool,
    finished: bool,
    /// tool_use 块（按上游 content_block 的 index 记）→ 是否已发过参数
    tools: Vec<(i64, bool)>,
    input_tokens: i64,
    cache_read: i64,
    cache_creation: i64,
    cache_unknown: bool,
    output_tokens: i64,
    /// 已映射成 chat 口径的 finish_reason（`message_delta` 里给）
    finish_reason: Option<String>,
    /// 上游 `error` 事件带来的失败（收尾后由调用方抛给主程序）
    failure: Option<Error>,
}

impl Stream {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            id: String::new(),
            created: super::common::now_ms() / 1000,
            started: false,
            finished: false,
            tools: Vec::new(),
            input_tokens: 0,
            cache_read: 0,
            cache_creation: 0,
            cache_unknown: false,
            output_tokens: 0,
            finish_reason: None,
            failure: None,
        }
    }

    /// 吃若干条 `data:` 载荷（已由 SSE 解码器切好），吐出要下发的 chat SSE 帧。
    pub fn push(&mut self, payloads: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for payload in payloads {
            if self.finished {
                break;
            }
            let Ok(event) = serde_json::from_str::<Value>(payload) else {
                // 解析失败只跳过这一帧：上游偶发的心跳 / 脏行不该打断整条流
                continue;
            };
            out.extend(self.consume(&event));
        }
        out
    }

    /// 上游流结束（没有 `message_stop` 时的兜底收尾）。
    pub fn finish(&mut self) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        self.complete()
    }

    /// 收尾后取走失败（`Some` = 这条流其实失败了，调用方应把它抛给主程序）。
    pub fn take_failure(&mut self) -> Option<Error> {
        self.failure.take()
    }

    /// 流是否已经收尾（`message_stop` / `error` 之后不再吃事件）。
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// 一个上游 Anthropic 事件 → 零到多个 chat 帧
    fn consume(&mut self, event: &Value) -> Vec<String> {
        let kind = string_field(event, "type").to_lowercase();
        match kind.as_str() {
            "ping" => Vec::new(),
            "error" => self.fail(event),
            "message_start" => {
                if let Some(id) = event
                    .pointer("/message/id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                {
                    self.id = id.to_string();
                }
                if let Some(usage) = event
                    .pointer("/message/usage")
                    .filter(|usage| usage.is_object())
                {
                    self.absorb_usage(usage);
                }
                self.start()
            }
            "content_block_start" => {
                let block = event.get("content_block").unwrap_or(&Value::Null);
                if string_field(block, "type").to_lowercase() != "tool_use" {
                    return Vec::new();
                }
                let index = event.get("index").and_then(Value::as_i64).unwrap_or(0);
                self.mark_tool(index, false);
                let mut out = self.start();
                let call_id = {
                    let raw = string_field(block, "id");
                    if raw.is_empty() {
                        random_id("toolu")
                    } else {
                        raw
                    }
                };
                out.push(self.delta_frame(json!({
                    "tool_calls": [{
                        "index": index,
                        "id": call_id,
                        "type": "function",
                        "function": { "name": string_field(block, "name"), "arguments": "" },
                    }],
                })));
                // `block.input` 已是完整对象时（部分上游不走 input_json_delta）
                // 直接作为首段参数下发
                if let Some(map) = block.get("input").and_then(Value::as_object) {
                    if !map.is_empty() {
                        self.mark_tool(index, true);
                        let arguments = json_text(&Value::Object(map.clone()));
                        out.push(self.arguments_frame(index, &arguments));
                    }
                }
                out
            }
            "content_block_delta" => {
                let delta = event.get("delta").unwrap_or(&Value::Null);
                let delta_kind = string_field(delta, "type").to_lowercase();
                match delta_kind.as_str() {
                    // 正文增量
                    "text_delta" => {
                        let text = string_field(delta, "text");
                        if text.is_empty() {
                            return Vec::new();
                        }
                        let mut out = self.start();
                        out.push(self.delta_frame(json!({ "content": text })));
                        out
                    }
                    // 思考增量 → reasoning_content（chat 侧承载思考的字段）
                    "thinking_delta" => {
                        let text = string_field(delta, "thinking");
                        if text.is_empty() {
                            return Vec::new();
                        }
                        let mut out = self.start();
                        out.push(self.delta_frame(json!({ "reasoning_content": text })));
                        out
                    }
                    // 工具参数增量（按 content_block 的 index 关联）
                    "input_json_delta" => {
                        let partial = string_field(delta, "partial_json");
                        if partial.is_empty() {
                            return Vec::new();
                        }
                        let index = event.get("index").and_then(Value::as_i64).unwrap_or(0);
                        // 没见到 content_block_start 的防御登记（上游事件残缺
                        // 时也让参数有槽位可挂）
                        self.mark_tool(index, true);
                        let mut out = self.start();
                        out.push(self.arguments_frame(index, &partial));
                        out
                    }
                    // 思考签名：chat 侧无处安放
                    "signature_delta" => Vec::new(),
                    _ => Vec::new(),
                }
            }
            // 块收尾：工具块一个参数分片都没来过时补一个空对象帧
            "content_block_stop" => {
                let index = event.get("index").and_then(Value::as_i64).unwrap_or(0);
                if self.tool_sent_arguments(index) == Some(false) {
                    self.mark_tool(index, true);
                    return vec![self.arguments_frame(index, "{}")];
                }
                Vec::new()
            }
            // 收尾前的最后一帧：stop_reason 与最终 usage（output_tokens）
            "message_delta" => {
                if let Some(reason) = event.pointer("/delta/stop_reason").map(string_value) {
                    let reason = reason.trim().to_lowercase();
                    if !reason.is_empty() {
                        self.finish_reason = Some(match reason.as_str() {
                            "max_tokens" => "length".to_string(),
                            "tool_use" => "tool_calls".to_string(),
                            // end_turn / stop_sequence / refusal 等：
                            // chat 侧没有对应值，归到 stop
                            _ => "stop".to_string(),
                        });
                    }
                }
                if let Some(usage) = event.get("usage").filter(|usage| usage.is_object()) {
                    self.absorb_usage(usage);
                }
                Vec::new()
            }
            "message_stop" => self.complete(),
            _ => Vec::new(),
        }
    }

    /// 吸收一帧 usage，**按字段**更新（这一帧没带的字段保留原值）。
    ///
    /// ── 为什么必须按字段而不是整组覆盖 ──────────────────────────
    /// 上游的两帧 usage 是**互补**的两次上报，谁都不是完整快照。参考实现实测
    /// （2026-09-30，流式）：
    ///
    /// ```text
    ///   message_start  → {"usage":{"input_tokens":0,"output_tokens":0}}
    ///   message_delta  → {"usage":{"input_tokens":13,"output_tokens":64,
    ///                              "cache_read_input_tokens":0,…}}
    /// ```
    ///
    /// 即开头那帧把 `input_tokens` 报成 **0 占位**，真实值只在收尾前那帧出现；
    /// 而 `output_tokens` 反过来只有收尾帧有效。用「最后一次快照整组覆盖」的
    /// 写法会把先到那帧真有的字段清零；只认 `output_tokens` 则输入与缓存恒为 0
    /// （编码场景输入远大于输出，丢掉输入等于账目少一个数量级）。
    ///
    /// 判据用「字段在不在」而不是「值是否非零」：0 是合法上报值（缓存未命中
    /// 就是 0），拿它当「没报」会让我们永远回落到一个更早的旧值。
    fn absorb_usage(&mut self, usage: &Value) {
        self.cache_unknown |= usage.get("magpie_cache_unknown").and_then(Value::as_bool) == Some(true);
        let take = |key: &str| -> Option<i64> {
            let value = usage.get(key)?;
            value.as_i64().or_else(|| {
                value
                    .as_f64()
                    .filter(|number| number.is_finite())
                    .map(|number| number as i64)
            })
        };
        if let Some(value) = take("input_tokens") {
            self.input_tokens = value;
        }
        if let Some(value) = take("cache_read_input_tokens") {
            self.cache_read = value;
        }
        if let Some(value) = take("cache_creation_input_tokens") {
            self.cache_creation = value;
        }
        if let Some(value) = take("output_tokens") {
            self.output_tokens = value;
        }
    }

    /// 首帧（role assistant），只发一次
    fn start(&mut self) -> Vec<String> {
        if self.started {
            return Vec::new();
        }
        self.started = true;
        if self.id.is_empty() {
            self.id = random_id("chatcmpl");
        }
        vec![self.delta_frame(json!({ "role": "assistant", "content": "" }))]
    }

    /// 收尾：finish_reason 帧 + usage 帧 + `[DONE]`（只做一次）
    fn complete(&mut self) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        if !self.started {
            // 心跳或无法识别的载荷不能在 EOF 时变成一次成功的空回答。
            return self.fail_message("上游未返回有效 Anthropic 消息", 502);
        }
        self.finished = true;
        let mut out = self.start();
        let finish_reason = self.finish_reason.clone().unwrap_or_else(|| {
            if self.tools.is_empty() {
                "stop".to_string()
            } else {
                "tool_calls".to_string()
            }
        });
        out.push(self.finish_frame(&finish_reason));
        // chat 的 prompt_tokens 包含缓存读写；cached_tokens 只表示命中，
        // 写入必须单独保留（与参考实现的账目口径一致）。
        let prompt_tokens = self
            .input_tokens
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_creation);
        out.push(chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": self.output_tokens,
                "total_tokens": prompt_tokens.saturating_add(self.output_tokens),
                "prompt_tokens_details": { "cached_tokens": self.cache_read },
                "cache_creation_input_tokens": self.cache_creation,
                "magpie_cache_unknown": self.cache_unknown,
            },
        })));
        out.push(DONE.to_string());
        out
    }

    /// 上游错误 → chat 错误帧 + `[DONE]`（只做一次），并记下错误本身。
    fn fail(&mut self, event: &Value) -> Vec<String> {
        let error = event.get("error").filter(|error| is_truthy(error));
        let message = match error {
            Some(error) => {
                let text = string_field(error, "message");
                if text.is_empty() {
                    string_value(error)
                } else {
                    text
                }
            }
            None => string_value(event),
        };
        let message = if message.trim().is_empty() {
            "上游流式返回错误".to_string()
        } else {
            message
        };
        // Anthropic 的 error.type → HTTP 状态码（与官方枚举一一对应）
        let status = match error
            .map(|error| string_field(error, "type").to_lowercase())
            .unwrap_or_default()
            .as_str()
        {
            "invalid_request_error" => 400,
            "authentication_error" => 401,
            "permission_error" => 403,
            "not_found_error" => 404,
            "request_too_large" => 413,
            "rate_limit_error" => 429,
            "timeout_error" => 504,
            "overloaded_error" => 529,
            _ => 500,
        };
        self.fail_message(&message, status)
    }

    /// 把一次流内失败折成标准 chat 错误帧（下游据此转 502/429 等）。
    fn fail_message(&mut self, message: &str, status: u16) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        self.failure = Some(
            Error::http(status, message.to_string()).with_code("zcode_stream_error"),
        );
        vec![
            chat_frame(&json!({
                "error": { "message": message, "type": "upstream_error", "status": status },
            })),
            DONE.to_string(),
        ]
    }

    /// 一个 delta 帧
    fn delta_frame(&self, delta: Value) -> String {
        chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": delta, "finish_reason": Value::Null }],
        }))
    }

    /// 工具参数帧（只带 index 与 function.arguments —— 增量形态，
    /// id / name 在宣告帧里已经给过）
    fn arguments_frame(&self, index: i64, arguments: &str) -> String {
        self.delta_frame(json!({
            "tool_calls": [{ "index": index, "function": { "arguments": arguments } }],
        }))
    }

    /// 收尾帧（空 delta + finish_reason）
    fn finish_frame(&self, finish_reason: &str) -> String {
        chat_frame(&json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{ "index": 0, "delta": {}, "finish_reason": finish_reason }],
        }))
    }

    /// 记一个工具块的「是否已发参数」状态（没有就插入）
    fn mark_tool(&mut self, index: i64, sent: bool) {
        if let Some(entry) = self.tools.iter_mut().find(|(slot, _)| *slot == index) {
            entry.1 = sent;
            return;
        }
        self.tools.push((index, sent));
    }

    /// 某个工具块是否已发过参数（没有登记 → None）
    fn tool_sent_arguments(&self, index: i64) -> Option<bool> {
        self.tools
            .iter()
            .find(|(slot, _)| *slot == index)
            .map(|(_, sent)| *sent)
    }
}

// ─── 降级：上游回非流式 JSON ────────────────────────────────

/// Anthropic 的 `message` 对象 → 一条 chat `chat.completion.chunk` 帧组。
///
/// ── 什么时候会走到这里 ──────────────────────────────────────
/// 上游偶尔忽略 `stream: true`、回一个完整 JSON（或客户端自己没要流式）。
/// 这时不能当 SSE 解：把整个 message 折成一帧 delta + 一帧 usage + `[DONE]`，
/// 下游聚合器按普通流拼出同样的回答 —— 与「流式一路跑完」的结果一致。
pub fn frames_from_message(message: &Value, model: &str) -> Vec<String> {
    let id = {
        let raw = string_field(message, "id");
        if raw.is_empty() {
            random_id("chatcmpl")
        } else {
            raw
        }
    };
    let created = super::common::now_ms() / 1000;
    let mut delta = serde_json::Map::new();
    // 思考块在前（与 Anthropic 官方顺序一致，chat 侧不区分顺序）
    let reasoning = content_parts(message.get("content").unwrap_or(&Value::Null))
        .iter()
        .filter(|part| {
            matches!(
                string_field(part, "type").to_lowercase().as_str(),
                "thinking" | "redacted_thinking"
            )
        })
        .map(|part| string_field(part, "thinking"))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if !reasoning.is_empty() {
        delta.insert("reasoning_content".to_string(), Value::String(reasoning));
    }
    let text = content_text(message.get("content").unwrap_or(&Value::Null));
    if !text.is_empty() {
        delta.insert("content".to_string(), Value::String(text));
    }
    let tool_calls: Vec<Value> = content_parts(message.get("content").unwrap_or(&Value::Null))
        .iter()
        .filter(|part| string_field(part, "type").eq_ignore_ascii_case("tool_use"))
        .enumerate()
        .map(|(index, part)| {
            let call_id = {
                let raw = string_field(part, "id");
                if raw.is_empty() {
                    random_id("toolu")
                } else {
                    raw
                }
            };
            json!({
                "index": index as i64,
                "id": call_id,
                "type": "function",
                "function": {
                    "name": string_field(part, "name"),
                    "arguments": json_text(part.get("input").unwrap_or(&Value::Null)),
                },
            })
        })
        .collect();
    if !tool_calls.is_empty() {
        delta.insert("tool_calls".to_string(), Value::Array(tool_calls));
    }

    let stop_reason = string_field(message, "stop_reason").to_lowercase();
    let finish_reason = match stop_reason.as_str() {
        "max_tokens" => "length",
        "tool_use" => "tool_calls",
        _ => "stop",
    };
    let usage = usage_to_chat(message.get("usage"));

    vec![
        chat_frame(&json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{ "index": 0, "delta": Value::Object(delta), "finish_reason": finish_reason }],
        })),
        chat_frame(&json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [],
            "usage": usage,
        })),
        DONE.to_string(),
    ]
}

/// Anthropic 的 usage → chat 的 usage（账目口径与流式收尾那帧一致）。
fn usage_to_chat(usage: Option<&Value>) -> Value {
    let take = |key: &str| -> i64 {
        usage
            .and_then(|usage| usage.get(key))
            .and_then(|value| {
                value.as_i64().or_else(|| {
                    value
                        .as_f64()
                        .filter(|number| number.is_finite())
                        .map(|number| number as i64)
                })
            })
            .unwrap_or(0)
    };
    let input = take("input_tokens");
    let cache_read = take("cache_read_input_tokens");
    let cache_creation = take("cache_creation_input_tokens");
    let output = take("output_tokens");
    let prompt = input.saturating_add(cache_read).saturating_add(cache_creation);
    json!({
        "prompt_tokens": prompt,
        "completion_tokens": output,
        "total_tokens": prompt.saturating_add(output),
        "prompt_tokens_details": { "cached_tokens": cache_read },
        "cache_creation_input_tokens": cache_creation,
    })
}

#[cfg(test)]
mod tests {
    use super::super::common::base64url_decode;
    use super::{frames_from_message, request_from_chat, Stream, Value};

    /// base64url 解码器的已知向量（自写的原语必须有测试：硬约束）
    #[test]
    fn base64url_decode_known_vectors() {
        assert_eq!(base64url_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(
            base64url_decode("eyJleHAiOjF9"),
            Some(b"{\"exp\":1}".to_vec())
        );
        assert_eq!(base64url_decode(""), Some(Vec::new()));
        // 非法字符 → None（不 panic）
        assert_eq!(base64url_decode("!!!"), None);
    }

    /// 把若干 JSON 事件喂给状态机，返回拼好的下发文本。
    fn run(events: &[Value]) -> String {
        let mut stream = Stream::new("glm-5.3");
        let payloads: Vec<String> = events.iter().map(|event| event.to_string()).collect();
        let mut out = String::new();
        for frame in stream.push(&payloads) {
            out.push_str(&frame);
        }
        for frame in stream.finish() {
            out.push_str(&frame);
        }
        out
    }

    fn event(kind: &str, extra: Value) -> Value {
        let mut object = match extra {
            Value::Object(object) => object,
            _ => serde_json::Map::new(),
        };
        object.insert("type".to_string(), Value::String(kind.to_string()));
        Value::Object(object)
    }

    #[test]
    fn text_stream_becomes_chat_chunks() {
        let text = run(&[
            event(
                "message_start",
                serde_json::json!({ "message": { "id": "msg_1", "usage": { "input_tokens": 0, "output_tokens": 0 } } }),
            ),
            event(
                "content_block_delta",
                serde_json::json!({ "index": 0, "delta": { "type": "text_delta", "text": "你好" } }),
            ),
            event(
                "message_delta",
                serde_json::json!({ "delta": { "stop_reason": "end_turn" }, "usage": { "input_tokens": 13, "output_tokens": 64 } }),
            ),
            event("message_stop", serde_json::json!({})),
        ]);
        assert!(text.contains("\"role\":\"assistant\""), "缺首帧: {text}");
        assert!(text.contains("\"content\":\"你好\""), "缺正文增量: {text}");
        assert!(text.contains("\"finish_reason\":\"stop\""), "缺收尾: {text}");
        assert!(text.contains("\"prompt_tokens\":13"), "输入 token 丢了: {text}");
        assert!(text.trim_end().ends_with("data: [DONE]"), "缺 [DONE]: {text}");
    }

    #[test]
    fn tool_use_becomes_tool_calls() {
        let text = run(&[
            event("message_start", serde_json::json!({ "message": { "id": "msg_2" } })),
            event(
                "content_block_start",
                serde_json::json!({ "index": 0, "content_block": { "type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {} } }),
            ),
            event(
                "content_block_delta",
                serde_json::json!({ "index": 0, "delta": { "type": "input_json_delta", "partial_json": "{\"path\":" } }),
            ),
            event("content_block_stop", serde_json::json!({ "index": 0 })),
            event("message_delta", serde_json::json!({ "delta": { "stop_reason": "tool_use" } })),
            event("message_stop", serde_json::json!({})),
        ]);
        assert!(text.contains("\"name\":\"read_file\""), "缺工具宣告: {text}");
        assert!(text.contains("{\\\"path\\\":"), "缺参数分片: {text}");
        assert!(text.contains("\"finish_reason\":\"tool_calls\""), "finish_reason 没映射: {text}");
    }

    #[test]
    fn upstream_error_becomes_error_frame_with_status() {
        let mut stream = Stream::new("glm-5.3");
        let payloads = vec![event(
            "error",
            serde_json::json!({ "error": { "type": "rate_limit_error", "message": "slow down" } }),
        )
        .to_string()];
        let text = stream.push(&payloads).join("");
        assert!(text.contains("\"status\":429"), "错误类型没映射成 429: {text}");
        assert_eq!(
            stream.take_failure().and_then(|error| error.status),
            Some(429)
        );
    }

    #[test]
    fn empty_stream_is_reported_as_failure() {
        let mut stream = Stream::new("glm-5.3");
        let text = stream.finish().join("");
        assert!(text.contains("上游未返回有效 Anthropic 消息"), "空流没报错: {text}");
        assert!(stream.take_failure().is_some());
    }

    #[test]
    fn non_stream_message_degrades_to_chunks() {
        let message = serde_json::json!({
            "id": "msg_5", "type": "message", "role": "assistant",
            "content": [
                { "type": "thinking", "thinking": "想一想" },
                { "type": "text", "text": "答案" },
                { "type": "tool_use", "id": "toolu_3", "name": "search", "input": { "q": "x" } }
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 5, "output_tokens": 7, "cache_read_input_tokens": 2 }
        });
        let text = frames_from_message(&message, "glm-5.3").join("");
        assert!(text.contains("\"reasoning_content\":\"想一想\""), "缺思考折叠: {text}");
        assert!(text.contains("\"content\":\"答案\""), "缺正文折叠: {text}");
        assert!(text.contains("\"prompt_tokens\":7"), "usage 账目不对: {text}");
    }

    #[test]
    fn request_moves_system_to_top_level_and_keeps_tool_pairs() {
        let chat = serde_json::json!({
            "messages": [
                { "role": "system", "content": "你是助手" },
                { "role": "user", "content": "帮我读文件" },
                { "role": "assistant", "content": null, "tool_calls": [
                    { "id": "call_1", "type": "function", "function": { "name": "read_file", "arguments": "{\"path\":\"a.txt\"}" } }
                ]},
                { "role": "tool", "tool_call_id": "call_1", "content": "内容" }
            ],
            "max_tokens": 100,
            "reasoning_effort": "high",
            "temperature": 0.3
        });
        let converted = request_from_chat(&chat, "glm-5.3");
        assert!(converted.is_ok(), "转换应成功");
        let Ok(out) = converted else { return };
        assert_eq!(out["system"], Value::String("你是助手".into()));
        assert_eq!(out["messages"].as_array().map(Vec::len), Some(3));
        assert_eq!(
            out["messages"][1]["content"][0]["type"],
            Value::String("tool_use".into())
        );
        // thinking 注入：high → budget 10240，且 max_tokens 必须抬到预算之上
        assert_eq!(out["thinking"]["budget_tokens"], Value::from(10240));
        assert_eq!(out["max_tokens"], Value::from(10240 + 1024));
        // thinking 开启时不得带 temperature（Anthropic 会拒）
        assert!(out.get("temperature").is_none());
    }
}
