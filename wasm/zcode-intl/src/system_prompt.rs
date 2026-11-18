//! 套餐池（Start Plan）的**系统提示词装配**、缓存断点与上下文前缀
//! （native `zcode/system_prompt.rs` 的移植）。
//!
//! ── 为什么必须逐字装配这三段 ────────────────────────────────
//! 上游按客户端形态校验这份报文：官方客户端发的是「身份句 + 稳定段 + 动态段」
//! 三块 `text`，各带 `cache_control: {type:"ephemeral"}`，并且**在消息最前面**
//! 插一条 `<system-reminder>Today's date is …</system-reminder>` 的 user 消息。
//! 少一块或顺序变了，上游的表现不是报错而是 3012（风控 / 兼容性拒绝）——
//! 那是本家最难查的一档（见 `errors::code_hint`）。
//!
//! ── 客户端正文放哪 ──────────────────────────────────────────
//! 客户端自己的系统正文**追加到动态段末尾**，保留系统角色，不增加第四块，
//! 也不会因此改成子代理。装配关闭时只发客户端正文（能否被接受取决于上游）。
//!
//! ── 与 native 的三处环境取值差异（Wasm 沙盒拿不到）───────────
//! 模板里的 `{cwd}` / `{shell}` / `{git}` 是「本机环境描述」。native 从
//! `current_dir()`、`SHELL`/`ComSpec`、`.git` 目录读；插件跑在 Wasm 沙盒里，
//! 这三样都读不到，因此**取 native 自己的兜底值**（`working_dir()` 的 `.`、
//! `shell_name()` 的 `unknown`、`gitNo`）—— 这三个值本来就是 native 在
//! 「读不到」时的取值，不是新编的。平台与架构改从宿主读
//! （`runtime.platform` / `runtime.architecture`），比编译期 `cfg!` 更准：
//! 插件是 wasm32，`cfg!(target_os)` 在它那里恒为 unknown。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! `panic = "abort"`：本文件零 unwrap/expect/panic；解析失败如实报错。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::common::{beijing_date, now_ms, string_field};
use super::request_context::RequestContext;

/// 官方提示词数据（逐字来自 native 同名文件，见 `source` 字段的出处）。
const SYSTEM_JSON: &str = include_str!("zcode_system.json");

/// 提示词说明（账号页「活动与套餐」那一栏的注脚；与 native 逐字一致）。
pub const OFFICIAL_PROMPT_NOTE: &str = "套餐池按三块装配：身份句、稳定段、动态段；客户端系统正文追加到动态段末尾，保留系统角色，不增加第四块，也不会因此改成子代理。套餐推理的客户端版本与模板一起更新，领取页的版本设置不会改变它。手动编辑的段优先于默认模板，未编辑的段随插件更新。关闭开关后只发送客户端正文，能否被接受取决于上游规则。3012 不等于额度耗尽，可能与请求兼容性或账号风控有关。";

/// 三段提示词（用户可逐段覆盖）。
#[derive(Clone, Debug, Default)]
pub struct GatewayBlocks {
    pub identity: String,
    pub stable: String,
    pub dynamic: String,
}

impl GatewayBlocks {
    pub const FIELDS: [&'static str; 3] = ["identity", "stable", "dynamic"];

    pub fn get(&self, field: &str) -> &str {
        match field {
            "identity" => &self.identity,
            "stable" => &self.stable,
            "dynamic" => &self.dynamic,
            _ => "",
        }
    }

    pub fn set(&mut self, field: &str, value: String) {
        match field {
            "identity" => self.identity = value,
            "stable" => self.stable = value,
            "dynamic" => self.dynamic = value,
            _ => {}
        }
    }
}

/// 解析一次提示词数据（每次调用都解：数据 5 KB，比维护一份跨调用缓存简单）。
fn system_data() -> Result<Value> {
    serde_json::from_str::<Value>(SYSTEM_JSON)
        .map_err(|_| Error::http(500, "内置的 ZCode 官方提示词资源不可用（解析失败）：请重新安装或升级插件"))
}

/// 模板里绑定的客户端版本（`clientVersion`）。
///
/// 这是**套餐推理**用的版本，与领取页的 `appVersion` 设置是两件事（模块头的
/// 注释：领取页的版本设置不会改变它）。
pub fn client_version() -> Option<String> {
    let data = system_data().ok()?;
    let version = text(&data, "clientVersion");
    let version = version.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

/// 官方三段模板（`prompt.info` 用）。
pub fn official_blocks_template() -> Option<GatewayBlocks> {
    let data = system_data().ok()?;
    Some(GatewayBlocks {
        identity: text(&data, "cliPrefix"),
        stable: stable_joined(&data),
        dynamic: dynamic_template(&data, false),
    })
}

/// 官方模板的字符数（同一模板更短时能提醒用户「是不是少了段」）。
pub fn official_prompt_approx_chars() -> usize {
    official_blocks_template()
        .map(|blocks| {
            blocks.identity.chars().count()
                + blocks.stable.chars().count()
                + blocks.dynamic.chars().count()
        })
        .unwrap_or(0)
}

/// 取一个模板字段（缺失 → 空串）。
fn text(data: &Value, key: &str) -> String {
    data.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn stable_joined(data: &Value) -> String {
    data.get("stableSections")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn dynamic_template(data: &Value, has_skill: bool) -> String {
    let mut sections = vec![text(data, "dynamicBehavior")];
    if has_skill {
        sections.push(text(data, "sessionGuidance"));
    }
    sections.extend([
        environment_template(data),
        text(data, "poweredBy"),
        text(data, "contextManagement"),
    ]);
    sections
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn environment_template(data: &Value) -> String {
    let env = data.get("environment").unwrap_or(&Value::Null);
    [
        text_of(env, "heading"),
        text_of(env, "invokedLine"),
        format!(" - {}: {{cwd}}", text_of(env, "cwdLabel")),
        format!(" - {}: {{git}}", text_of(env, "gitLabel")),
        format!(" - {}: {{platform}}", text_of(env, "platformLabel")),
        format!(" - {}: {{shell}}", text_of(env, "shellLabel")),
        format!(" - {}: {{os_version}}", text_of(env, "osVersionLabel")),
        format!(" - {}", text_of(env, "untrustedNote")),
    ]
    .into_iter()
    .filter(|line| !line.trim().is_empty())
    .collect::<Vec<_>>()
    .join("\n")
}

fn text_of(data: &Value, key: &str) -> String {
    data.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// 宿主平台（`runtime.platform` → native `os_platform()` 的字符串）。
///
/// 宿主回的是 `win` / `mac` / `linux` / `other`；native 用的是
/// `win32` / `darwin` / `linux`。取不到时给 `win32`（与 native 对未知平台的
/// 兜底一致：上游不校验这一格，但缺行会让动态段少一行）。
fn os_platform() -> String {
    match sdk::host("runtime.platform", json!({})).ok().and_then(|value| value.as_str().map(str::to_string)) {
        Some(value) if value == "mac" => "darwin".to_string(),
        Some(value) if value == "linux" => "linux".to_string(),
        Some(value) if value == "win" => "win32".to_string(),
        _ => "win32".to_string(),
    }
}

/// 宿主架构（`runtime.architecture` → native `os_arch()`）。
fn os_arch() -> String {
    match sdk::host("runtime.architecture", json!({}))
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
    {
        Some(value) if value == "x86_64" => "x64".to_string(),
        Some(value) if value == "aarch64" => "arm64".to_string(),
        Some(value) if !value.trim().is_empty() => value,
        _ => "unknown".to_string(),
    }
}

/// 模板变量表（顺序即替换顺序）。
fn template_values(data: &Value, model: &str) -> Vec<(&'static str, String)> {
    let git = text_of(data.get("environment").unwrap_or(&Value::Null), "gitNo");
    vec![
        // 三项「本机环境」取 native 的兜底值（见模块头最后一段）
        ("{cwd}", ".".to_string()),
        ("{git}", git),
        ("{platform}", os_platform()),
        ("{shell}", "unknown".to_string()),
        ("{os_version}", format!("{} {}", os_platform(), os_arch())),
        // 国际版的 provider 名（native `template_values` 的分支）
        ("{provider}", "zai-api".to_string()),
        ("{model}", model.to_string()),
    ]
}

fn substitute(text: &str, values: &[(&'static str, String)]) -> String {
    let mut out = text.to_string();
    for (token, value) in values {
        out = out.replace(token, value);
    }
    out
}

/// 三块 `text`，各带 `cache_control`（官方客户端的形状）。
fn system_blocks(texts: &GatewayBlocks) -> Vec<Value> {
    let ephemeral = json!({ "type": "ephemeral" });
    vec![
        text_block(texts.identity.clone(), Some(ephemeral.clone())),
        text_block(texts.stable.clone(), Some(ephemeral.clone())),
        text_block(format!("\n\n{}", texts.dynamic), Some(ephemeral)),
    ]
}

fn text_block(text: String, cache_control: Option<Value>) -> Value {
    let mut block = json!({ "type": "text", "text": text });
    if let Some(cache) = cache_control {
        block["cache_control"] = cache;
    }
    block
}

/// 客户端自己的系统正文（块数组 / 字符串两种形态都认）。
fn user_system_blocks(existing: Option<&Value>) -> Vec<Value> {
    let Some(existing) = existing else {
        return Vec::new();
    };
    let items = match existing {
        Value::String(text) => {
            return if text.trim().is_empty() {
                Vec::new()
            } else {
                vec![text_block(text.clone(), None)]
            }
        }
        Value::Array(items) => items,
        _ => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|item| {
            let text = item.as_str().or_else(|| {
                (item.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| item.get("text").and_then(Value::as_str))
                    .flatten()
            })?;
            (!text.trim().is_empty()).then(|| text_block(text.to_string(), None))
        })
        .collect()
}

fn custom_system_text(existing: Option<&Value>) -> Option<String> {
    let parts = user_system_blocks(existing);
    let text = parts
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n\n");
    (!text.is_empty()).then_some(text)
}

/// 用户改过哪几段就用哪几段（未改的段用默认模板，见 `merged_texts`）。
fn merged_texts(
    data: &Value,
    model: &str,
    override_blocks: Option<&GatewayBlocks>,
    has_skill: bool,
) -> GatewayBlocks {
    let values = template_values(data, model);
    let defaults = GatewayBlocks {
        identity: text(data, "cliPrefix"),
        stable: stable_joined(data),
        dynamic: substitute(&dynamic_template(data, has_skill), &values),
    };
    let Some(overrides) = override_blocks else {
        return defaults;
    };
    let pick = |field: &str| {
        let text = overrides.get(field);
        if text.trim().is_empty() {
            defaults.get(field).to_string()
        } else {
            substitute(text, &values)
        }
    };
    GatewayBlocks {
        identity: pick("identity"),
        stable: pick("stable"),
        dynamic: pick("dynamic"),
    }
}

/// 上下文前缀消息（官方客户端在消息最前面插的那条 `<system-reminder>`）。
fn context_prefix_message(data: &Value) -> Value {
    let context = data.get("context").unwrap_or(&Value::Null);
    let date = beijing_date(now_ms()).unwrap_or_default();
    let body = text_of(context, "currentDateLine").replace("{date}", &date);
    json!({
        "role": "user",
        "content": [{ "type": "text", "text": format!("<system-reminder>{body}</system-reminder>") }],
    })
}

/// 工具声明上的缓存断点一律剥掉（工具清单的断点由 `anthropic` 的转换层处理，
/// 这里剥的是客户端带进来的残留 —— 上游对工具块上的断点位置有额外校验）。
fn strip_tool_cache_control(object: &mut serde_json::Map<String, Value>) {
    if let Some(tools) = object.get_mut("tools").and_then(Value::as_array_mut) {
        for tool in tools {
            if let Some(tool) = tool.as_object_mut() {
                tool.remove("cache_control");
            }
        }
    }
}

/// 把缓存断点挂到**最后一条非 system 消息**的最后一个可挂块上。
///
/// Anthropic 的提示缓存按「前缀到此为止」工作：断点挂在最后一条消息上，
/// 前缀（三块 system + 全部历史）才被缓存。thinking 块上不允许挂断点，
/// 因此从后往前找第一个非 thinking 的块。
fn apply_cache_control(object: &mut serde_json::Map<String, Value>) {
    let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        if let Some(blocks) = message.get_mut("content").and_then(Value::as_array_mut) {
            for block in blocks {
                if let Some(block) = block.as_object_mut() {
                    block.remove("cache_control");
                }
            }
        }
    }
    for message in messages.iter_mut().rev() {
        if message.get("role").and_then(Value::as_str) == Some("system") {
            continue;
        }
        if let Some(Value::String(text)) = message.get("content") {
            message["content"] = Value::Array(vec![text_block(
                text.clone(),
                Some(json!({ "type": "ephemeral" })),
            )]);
        } else if let Some(blocks) = message.get_mut("content").and_then(Value::as_array_mut) {
            if let Some(block) = blocks
                .iter_mut()
                .rev()
                .find(|block| {
                    block
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind != "thinking" && kind != "redacted_thinking")
                })
                .and_then(Value::as_object_mut)
            {
                block.insert("cache_control".to_string(), json!({ "type": "ephemeral" }));
            }
        }
        return;
    }
}

/// 套餐池请求的系统提示词装配（native `apply_start_plan` 的移植）。
///
/// `official_prompt = false` 时只发客户端正文（把已有 system 归一成块数组），
/// 其余步骤（剥断点、挂断点、metadata）照做 —— 那是「客户端正文也要被当成
/// 官方形态发出去」的同一套要求。
pub fn apply_start_plan(
    payload: &mut Value,
    model: &str,
    device_mid: &str,
    official_prompt: bool,
    override_blocks: Option<&GatewayBlocks>,
    request_context: &RequestContext,
) -> Result<()> {
    let data = if official_prompt {
        Some(system_data()?)
    } else {
        None
    };
    // Skill 工具决定动态段要不要拼「会话指引」—— 必须在 `as_object_mut` 之前判
    // （之后 payload 被可变借用，读不到 `tools`）
    let has_skill = has_skill_tool(payload);
    let object = payload
        .as_object_mut()
        .ok_or_else(|| Error::http(500, "请求体形态异常（不是对象）"))?;
    if let Some(data) = data {
        let mut texts = merged_texts(&data, model, override_blocks, has_skill);
        if let Some(custom) = custom_system_text(object.get("system")) {
            texts.dynamic.push_str("\n\n");
            texts.dynamic.push_str(&custom);
        }
        object.insert("system".to_string(), Value::Array(system_blocks(&texts)));
        if let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) {
            if !messages.is_empty() {
                messages.insert(0, context_prefix_message(&data));
            }
        }
    } else if let Some(existing) = object.get("system") {
        let blocks = user_system_blocks(Some(existing));
        if blocks.is_empty() {
            object.remove("system");
        } else {
            object.insert("system".to_string(), Value::Array(blocks));
        }
    }
    strip_tool_cache_control(object);
    apply_cache_control(object);
    if let Some(user_id) = request_context.metadata_user_id(device_mid) {
        let mut metadata = object
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        metadata.insert("user_id".to_string(), Value::String(user_id));
        object.insert("metadata".to_string(), Value::Object(metadata));
    }
    Ok(())
}

/// 客户端请求体里是否带 Skill 工具（决定要不要拼会话指引那段）。
///
/// `merged_texts` 里用的是同一个判据（`tools[]` 里有没有 `name == "Skill"`），
/// 这里保留成函数是为了让调用点能单独问一次（排障 / 将来的记忆化）。
fn has_skill_tool(payload: &Value) -> bool {
    payload
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| string_field(tool, "name") == "Skill")
        })
}

/// `prompt.info` 的返回（与 native `admin::machine_action` 的同一形状）。
pub fn prompt_info() -> Value {
    let blocks = official_blocks_template().map(|blocks| {
        let mut map = serde_json::Map::new();
        for field in GatewayBlocks::FIELDS {
            map.insert(field.to_string(), Value::String(blocks.get(field).to_string()));
        }
        Value::Object(map)
    });
    json!({
        "gatewayNote": OFFICIAL_PROMPT_NOTE,
        "gatewayChars": official_prompt_approx_chars(),
        "gatewayBlocks": blocks,
    })
}

/// 网关自带提示词开关的默认值（缺键 = 装）。
pub fn prompt_enabled_default() -> bool {
    true
}

/// 读一条布尔设置（`gatewayPrompt`；读不到按默认「装」）。
pub fn prompt_enabled() -> bool {
    match sdk::settings::get("gatewayPrompt").ok() {
        Some(Value::Bool(flag)) => flag,
        _ => prompt_enabled_default(),
    }
}

/// 读用户改过的提示词正文（`{identity, stable, dynamic}`，只含改过的段）。
///
/// 形状不对 / 读不到一律回 `None`（= 全部用官方原文）：宁可用官方原文，也不要
/// 因为一次解析失败把三段拼成残缺的东西发上去 —— 上游按结构校验，残缺会 3012。
pub fn prompt_blocks() -> Option<GatewayBlocks> {
    let value = sdk::settings::get("gatewayPromptText").ok()?;
    let object = value.as_object()?;
    let mut blocks = GatewayBlocks::default();
    let mut touched = false;
    for field in GatewayBlocks::FIELDS {
        if let Some(text) = object.get(field).and_then(Value::as_str) {
            if !text.trim().is_empty() {
                blocks.set(field, text.to_string());
                touched = true;
            }
        }
    }
    touched.then_some(blocks)
}
