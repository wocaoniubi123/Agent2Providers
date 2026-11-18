//! WorkBuddy 出站请求体归一化管线（对照 Sliverkiss/workbuddy2api 的
//! `internal/upstream/payload.go` + `cache_key.go` 移植）。
//!
//! ── 为什么需要这一层 ────────────────────────────────────────
//! 上游是「腾讯自己的 Go struct」，对请求体的宽容度远小于 OpenAI 规范：
//! role 白名单没有 `developer`、`tool_choice` 只认字符串、`image_url` 只认对象
//! 形态、输出上限只认 `max_tokens`。客户端（Codex / Claude Code / 各家 UI）按新
//! 规范发字段时上游直接 400，而**换任何账号都是同一个 400** —— 这不是账号问题、
//! 也不是重试能解决的问题，只能在出站前把字节改对。
//!
//! ── 与 system 兜底注入的顺序（不可调换）────────────────────────
//! `normalize_roles` 必须**先**把 `developer` 归一成 `system`，随后才调
//! [`crate::outbound::ensure_leading_system_message`] —— 客户端若用 `developer`
//! 打头，先归一成 `system` 才判得出「首条已是 system」，否则会多注入一条兜底
//! system（上游对多 system 的行为未实测，不引入这个变量）。
//!
//! ── 只管「让请求通过」，不管内容 ────────────────────────────
//! 本文件的每一步都是**形态转换**，不涉及语义改写：改 role 名（同义）、把对象
//! 拆成字符串（上游的等价表达）、把字符串包成对象（规范形态）、把别名译成上游
//! 认的键（同名语义）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Value};
use serde_json::Map;

/// 归一化做了什么（供调用方写一行详细日志）。
///
/// ── 为什么要有这份报告 ──────────────────────────────────────
/// 几个步骤是**静默修复**：修好了用户不会知道（请求从此不 400 了），但一旦出
/// 问题（role 没归一、max_tokens 没生效）就需要能回答「网关对我的请求动了什么」。
/// 字段只统计**值得解释的修复**，不统计常规注入（`prompt_cache_key` 几乎每次都
/// 会加，写进日志只是噪声）—— 唯一例外是它取不到账号 UID 的情形，那会让跨账号
/// 隔离失效，必须可见。
#[derive(Clone, Debug, Default)]
pub struct NormalizeReport {
    /// 归一成 system 的 developer 角色消息数
    pub roles_normalized: usize,
    /// 是否改写了 tool_choice（对象形态 → 上游认的字符串形态）
    pub tool_choice_rewritten: bool,
    /// 由字符串形态包装成对象形态的 image_url 数
    pub image_urls_wrapped: usize,
    /// 是否把 max_completion_tokens 译成了 max_tokens
    pub max_tokens_translated: bool,
    /// 缓存键是否**缺少账号隔离段**（取不到账号 UID）
    pub cache_key_unscoped: bool,
}

impl NormalizeReport {
    /// 是否有值得写进详细日志的修复（常规的缓存键注入不算）。
    ///
    /// wasm 侧没有 verbose 日志口（宿主的日志由宿主决定级别），保留它是为了让本文件
    /// 与 native 那份逐行可对照。
    #[allow(dead_code)]
    pub fn notable(&self) -> bool {
        self.roles_normalized > 0
            || self.tool_choice_rewritten
            || self.image_urls_wrapped > 0
            || self.max_tokens_translated
            || self.cache_key_unscoped
    }

    /// 一行可读的中文描述（宿主日志级别由宿主决定，这里只负责措辞）。
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.roles_normalized > 0 {
            parts.push(format!("developer→system {} 条", self.roles_normalized));
        }
        if self.tool_choice_rewritten {
            parts.push("tool_choice 归一为上游字符串形态".to_string());
        }
        if self.image_urls_wrapped > 0 {
            parts.push(format!("image_url 补对象形态 {} 处", self.image_urls_wrapped));
        }
        if self.max_tokens_translated {
            parts.push("max_completion_tokens→max_tokens".to_string());
        }
        if self.cache_key_unscoped {
            parts.push("警告：缓存键缺少账号隔离段（未取到账号 UID）".to_string());
        }
        parts.join("；")
    }
}

/// 归一化管线的总入口。
///
/// `account` 是与 `build_chat` 同源的账号会话对象（用于取 UID 做缓存键的账号
/// 隔离段）。返回归一后的新 body 与报告；body 不是 JSON 对象时**原样返回**且
/// 报告为空（坏 body 不在这里二次错误化：上游会给出比我们更准确的解析错误）。
pub fn normalize_outbound(body: &Value, account: &Value) -> (Value, NormalizeReport) {
    let Some(object) = body.as_object() else {
        return (body.clone(), NormalizeReport::default());
    };
    let mut report = NormalizeReport::default();
    let mut next = object.clone();
    normalize_roles(&mut next, &mut report);
    normalize_tool_choice(&mut next, &mut report);
    normalize_image_url(&mut next, &mut report);
    translate_max_completion_tokens(&mut next, &mut report);
    ensure_stream_options(&mut next);
    // tool 配对（重排 + 孤儿裁剪）**不在这里**：它已提升为所有上游共用的转发
    // 入口 sanitize，跑在本管线之前；两处都做同一件事只会漂移。
    inject_prompt_cache_key(&mut next, account, &mut report);
    (Value::Object(next), report)
}

/// 把 `developer` 角色归一为 `system`。
///
/// 上游对 messages 的 role 字段做白名单校验，`developer` 不在白名单内，命中即
/// HTTP 400。`developer` 是 OpenAI 新规范里 system 的别名（Codex / Cursor 等新
/// 客户端用它承载 system 级指令），改写不丢语义。
///
/// 只认 `developer` 这一个值：其余 role（system/user/assistant/tool/任意未知值）
/// 一律原样保留，**不合并、不重排、不删除**任何消息 —— 上游对多 system 的行为
/// 未实测，合并会引入新变量。
fn normalize_roles(object: &mut Map<String, Value>, report: &mut NormalizeReport) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(fields) = message.as_object_mut() else {
            continue;
        };
        let is_developer = fields
            .get("role")
            .and_then(Value::as_str)
            .map(|role| role.trim().eq_ignore_ascii_case("developer"))
            .unwrap_or(false);
        if is_developer {
            fields.insert("role".to_string(), Value::String("system".to_string()));
            report.roles_normalized += 1;
        }
    }
}

/// 按上游 Go struct（`tool_choice` 是 string 类型）改写 OpenAI 的 `tool_choice`。
///
/// 对象形态透传会让上游 400（cannot unmarshal object into string）。映射规则：
///   - `"none"` / `{"type":"none"}` → 删 `tool_choice` **并删 tools/functions**
///     （上游语义：不调用工具时连工具声明一起撤掉，否则仍可能触发工具调用）；
///   - `{"type":"auto"|"required"}` → 字符串 `"auto"` / `"required"`；
///   - `{"type":"function","function":{"name":"x"}}` → 字符串 `"x"`
///     （上游把指定函数表达成裸函数名）；
///   - 其余对象 / 非标量 → 删 `tool_choice`（宁可不指定，也不发一个必定 400 的值）。
fn normalize_tool_choice(object: &mut Map<String, Value>, report: &mut NormalizeReport) {
    let Some(choice) = object.get("tool_choice").cloned() else {
        return;
    };
    match choice {
        // 字符串形态上游本就认（auto/required/裸函数名），只在 none 时做撤除
        Value::String(text) => {
            if text.trim().eq_ignore_ascii_case("none") {
                object.remove("tool_choice");
                object.remove("tools");
                object.remove("functions");
                report.tool_choice_rewritten = true;
            }
        }
        Value::Object(fields) => {
            let kind = fields
                .get("type")
                .and_then(Value::as_str)
                .map(|text| text.trim().to_ascii_lowercase())
                .unwrap_or_default();
            match kind.as_str() {
                "none" => {
                    object.remove("tool_choice");
                    object.remove("tools");
                    object.remove("functions");
                }
                "auto" | "required" => {
                    object.insert("tool_choice".to_string(), Value::String(kind));
                }
                "function" => {
                    // 函数名可能在 function.name（规范形态）或顶层 name（部分客户端）
                    let name = fields
                        .get("function")
                        .and_then(Value::as_object)
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                        .or_else(|| fields.get("name").and_then(Value::as_str))
                        .map(str::trim)
                        .filter(|name| !name.is_empty());
                    match name {
                        Some(name) => {
                            object.insert("tool_choice".to_string(), Value::String(name.to_string()));
                        }
                        // 指定了 function 却没给名字：退回 auto 比删掉更接近意图
                        None => {
                            object.insert("tool_choice".to_string(), Value::String("auto".to_string()));
                        }
                    }
                }
                _ => {
                    object.remove("tool_choice");
                }
            }
            report.tool_choice_rewritten = true;
        }
        // 数字 / 数组 / null：不是上游认的任何形态，撤掉比发过去强
        _ => {
            object.remove("tool_choice");
            report.tool_choice_rewritten = true;
        }
    }
}

/// 兼容 OpenAI 多模态内容的两种 `image_url` 写法。
///
/// OpenAI Chat 规范用对象形态 `{"url":"...","detail":"..."}`，部分客户端（以及
/// Responses → Chat 转换器）会发字符串形态。上游只接受对象形态，字符串会 400
/// （cannot unmarshal string into ImageContent）。这里只做形状转换：字符串转
/// `{"url": 原值}`；已是对象、空串、字段缺失一律不动（让上游返回真实错误，
/// 而不是我们凭空补一个 url）。
fn normalize_image_url(object: &mut Map<String, Value>, report: &mut NormalizeReport) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        let Some(parts) = message
            .as_object_mut()
            .and_then(|fields| fields.get_mut("content"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        for part in parts.iter_mut() {
            let Some(fields) = part.as_object_mut() else {
                continue;
            };
            if fields.get("type").and_then(Value::as_str) != Some("image_url") {
                continue;
            }
            let Some(url) = fields
                .get("image_url")
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|url| !url.is_empty())
            else {
                continue;
            };
            fields.insert("image_url".to_string(), json!({ "url": url }));
            report.image_urls_wrapped += 1;
        }
    }
}

/// 把 OpenAI 别名 `max_completion_tokens` 翻译为上游认的 `max_tokens`。
///
/// OpenAI 规范里 `max_tokens` 已 deprecated、`max_completion_tokens` 是新字段
/// （o-series 起引入），新客户端只发别名。WorkBuddy 上游只认 `max_tokens` ——
/// 别名透传会被**静默忽略**后回落默认输出上限，长流任务被截断（不报错，比 400
/// 更难排查）。
///
/// 规则：显式 `max_tokens` 优先（别名只删不译）；别名值为 0/null/负数/非数值
/// 一律不翻译（0/null 语义是「未设置」，负数是非法值，翻译等于把垃圾搬过去）。
fn translate_max_completion_tokens(object: &mut Map<String, Value>, report: &mut NormalizeReport) {
    let Some(alias) = object.remove("max_completion_tokens") else {
        return;
    };
    if object.contains_key("max_tokens") {
        return; // 显式 max_tokens 优先：别名只删不译
    }
    let translated = alias
        .as_i64()
        .filter(|number| *number > 0)
        .or_else(|| {
            alias
                .as_f64()
                .filter(|number| *number > 0.0 && number.fract() == 0.0)
                .map(|number| number as i64)
        });
    if let Some(number) = translated {
        object.insert("max_tokens".to_string(), Value::from(number));
        report.max_tokens_translated = true;
    }
}

/// 仅在 body 未显式携带时补 `stream_options.include_usage = true`。
///
/// 官方 CLI 流式必发该字段，上游据此在**末帧**返回 usage 用量。我们本就在 SSE
/// 旁路里提取 usage 做请求统计，补上它能让统计拿到真实 token 数而不是 null。
///
/// **显式带则绝不覆盖**：客户端可能显式要 `include_usage: false`，那是它的选择。
fn ensure_stream_options(object: &mut Map<String, Value>) {
    if object.contains_key("stream_options") {
        return;
    }
    object.insert("stream_options".to_string(), json!({ "include_usage": true }));
}

/// 注入上游前缀缓存键 `prompt_cache_key`（费用优化）。
///
/// ── 为什么值得做（参考项目的实测结论）────────────────────────
/// 同一段 8k token 前缀：不带该字段 `prompt_cache_hit_tokens=0, credit≈0.34`；
/// 带上 `prompt_cache_hit_tokens=7808, credit≈0.02` —— **费用降约 17 倍**。
///
/// ── 为什么必须按账号隔离 ────────────────────────────────────
/// 键格式 `wb2a-<uid8>-<convHex>`：`uid8` 是账号 UID 前 8 字符，**跨账号绝不相同**。
/// 若两个账号共用同一 cache key，上游会命中**另一个账号**的前缀缓存 —— 那不只是
/// 计费错乱，更是对话内容泄露。因此 uid 是硬隔离因子，不是可选的熵来源。
/// 取不到 UID 时仍注入（段位用 `-` 占位）但标记 `cache_key_unscoped` 让调用方警告。
///
/// 优先级：客户端已带非空 `prompt_cache_key` → **原值保留，绝不覆盖**。
fn inject_prompt_cache_key(
    object: &mut Map<String, Value>,
    account: &Value,
    report: &mut NormalizeReport,
) {
    let existing = object
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty());
    if existing.is_some() {
        return; // 优先级 1：客户端自带 → 原样保留
    }
    let uid = account_uid(account);
    report.cache_key_unscoped = uid.is_empty();
    let conversation = conversation_key(object);
    object.insert(
        "prompt_cache_key".to_string(),
        Value::String(build_cache_key(&uid, &conversation)),
    );
}

/// 生成 `wb2a-<uid8>-<convHex>` 形态的稳定缓存键。
///
/// `convHex = sha256(uid + "|" + conversation)` 前 16 字节的十六进制，提供会话段
/// （同账号同会话稳定、不同会话不同）。会话源为空时 convHex 仍由 uid 单独哈希
/// 得到 —— 跨账号绝不碰撞，且同账号的同类请求稳定复用。
fn build_cache_key(uid: &str, conversation: &str) -> String {
    use sha2::{Digest, Sha256};

    let uid8: String = uid.chars().take(8).collect();
    let uid8 = if uid8.is_empty() {
        "-".to_string()
    } else {
        uid8
    };
    let mut hasher = Sha256::new();
    hasher.update(uid.as_bytes());
    hasher.update(b"|");
    hasher.update(conversation.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("wb2a-{uid8}-{hex}")
}

/// 从 body 里取会话标识（缓存键的会话段来源）。
///
/// 顺序与参考项目一致：顶层优先于 metadata，每级内 snake_case 优先于 camelCase。
fn conversation_key(object: &Map<String, Value>) -> String {
    let direct = non_empty_str(object.get("conversation_id"))
        .or_else(|| non_empty_str(object.get("conversationId")));
    if let Some(text) = direct {
        return text;
    }
    let Some(metadata) = object.get("metadata").and_then(Value::as_object) else {
        return String::new();
    };
    non_empty_str(metadata.get("conversation_id"))
        .or_else(|| non_empty_str(metadata.get("conversationId")))
        .unwrap_or_default()
}

/// 取账号 UID：账号会话对象里的 `account.uid`，取不到回落顶层 `uid`。
fn account_uid(account: &Value) -> String {
    account
        .pointer("/account/uid")
        .and_then(Value::as_str)
        .or_else(|| account.get("uid").and_then(Value::as_str))
        .map(str::trim)
        .filter(|uid| !uid.is_empty())
        .unwrap_or("")
        .to_string()
}

fn non_empty_str(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(body: Value) -> (Value, NormalizeReport) {
        normalize_outbound(&body, &json!({ "account": { "uid": "5877cabc-1" } }))
    }

    #[test]
    fn developer_role_becomes_system() {
        let (body, report) = normalize(json!({
            "messages": [{ "role": "developer", "content": "x" }, { "role": "user", "content": "y" }]
        }));
        assert_eq!(body["messages"][0]["role"], json!("system"));
        assert_eq!(report.roles_normalized, 1);
    }

    #[test]
    fn tool_choice_object_is_flattened() {
        let (body, _) = normalize(json!({ "tool_choice": { "type": "auto" } }));
        assert_eq!(body["tool_choice"], json!("auto"));
        let (body, _) = normalize(json!({
            "tool_choice": { "type": "function", "function": { "name": "lookup" } }
        }));
        assert_eq!(body["tool_choice"], json!("lookup"));
        let (body, _) = normalize(json!({ "tool_choice": { "type": "none" }, "tools": [1] }));
        assert!(body.get("tool_choice").is_none());
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn image_url_string_is_wrapped() {
        let (body, report) = normalize(json!({
            "messages": [{ "role": "user", "content": [
                { "type": "image_url", "image_url": "data:image/png;base64,AA" }
            ]}]
        }));
        assert_eq!(body["messages"][0]["content"][0]["image_url"]["url"], json!("data:image/png;base64,AA"));
        assert_eq!(report.image_urls_wrapped, 1);
    }

    #[test]
    fn max_completion_tokens_is_translated_once() {
        let (body, report) = normalize(json!({ "max_completion_tokens": 512 }));
        assert_eq!(body["max_tokens"], json!(512));
        assert!(body.get("max_completion_tokens").is_none());
        assert!(report.max_tokens_translated);
        // 显式 max_tokens 优先：别名只删不译
        let (body, report) = normalize(json!({ "max_tokens": 64, "max_completion_tokens": 512 }));
        assert_eq!(body["max_tokens"], json!(64));
        assert!(!report.max_tokens_translated);
        // 0 / 负数不译
        let (body, _) = normalize(json!({ "max_completion_tokens": 0 }));
        assert!(body.get("max_tokens").is_none());
    }

    #[test]
    fn cache_key_is_account_scoped_and_respects_client_value() {
        let (body, report) = normalize(json!({ "messages": [], "conversation_id": "c-1" }));
        let key = body["prompt_cache_key"].as_str().unwrap_or("");
        assert!(key.starts_with("wb2a-5877cabc-"), "{key}");
        assert!(!report.cache_key_unscoped);
        // 客户端自带的键绝不覆盖
        let (body, _) = normalize(json!({ "prompt_cache_key": "keep-me" }));
        assert_eq!(body["prompt_cache_key"], json!("keep-me"));
        // 取不到 uid 时仍注入，但标记为未隔离
        let (body, report) =
            normalize_outbound(&json!({ "messages": [] }), &json!({}));
        assert!(body["prompt_cache_key"].as_str().unwrap_or("").starts_with("wb2a--"));
        assert!(report.cache_key_unscoped);
    }
}
