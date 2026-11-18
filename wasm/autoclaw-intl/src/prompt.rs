//! AutoClaw 出站 system 提示规范化：把客户端自己的 system 提示**包进**上游要求的
//! OpenClaw 身份前缀里（起因是上游 2026-09-22 起加的闸门）。
//!
//! ── 上游加了什么（逐条实测，国内版免费账号，2026-09-22）───────
//! `POST .../autoclaw-proxy/proxy/autoclaw/chat/completions` 对**系统提示词**做了
//! 检查。同一账号、同一请求，只改 system 一项的实测结论：
//!
//! ```text
//!   system 内容                                          结果
//!   ───────────────────────────────────────────────────  ──────────────────
//!   身份句 + `## Tooling` 段                             200
//!   上面那段 + 客户端自己的提示词（任意内容接在后面）     200
//!   只有身份句、没有 `## Tooling` 段                      403 pay-view
//!   中性句（You are a helpful assistant.）                406（空响应体）
//!   完全没有 system 消息                                  406（空响应体）
//!   身份句 + "You are ZCode…"                            406
//!   身份句 + "You are Claude Code…"                      406
//! ```
//!
//! 即：**必须**以身份句开头且带 `## Tooling` 段，同时**不能**出现外来 harness
//! 的身份句。黑名单是**字面**判定（`You are <产品名>` 形态）：把主语换掉的
//! "ZCode is an interactive coding agent." 实测放行，所以改写产品名后不再命中。
//!
//! ── 国际版实测（2026-09-24，issue #10）──────────────────────
//! 同一道闸门在**国际版**上被独立复现，形态与国内版一致 —— 同一账号、同一模型、
//! 只改 system 一句即 200 / 406 两分：
//!
//! ```text
//!   You are a helpful assistant.                               200
//!   You are an AI agent powered by DeepSeek Harness.           406（空响应体）
//!   同上，把 DeepSeek 里的 e 写成 E（大小写变体）               406
//!   You are Codex, based on GPT-5. You are running as a
//!     coding agent.                                            406
//!   上面那句放进 **user** 消息、system 用中性句                200
//! ```
//!
//! 三条结论，每一条都对应本表的一处设计：
//!   1. 闸门**只看 system / developer 消息** —— 同一句放进 user 消息不触发，
//!      所以改写只做在 system 上（见「边界」）；
//!   2. 黑名单是**字面匹配**，不是语义审核 —— 所以改写产品名后不再命中；
//!   3. 匹配**大小写不敏感** —— 所以本表的替换也必须忽略大小写，否则同一句
//!      指纹换个大小写就漏网。
//!
//! ── 本模块做什么（两条纯文本变换）──────────────────────────
//!   1. **前置** [`IDENTITY_PREFIX`]：首条 system / developer 消息的正文前面插入
//!      它，客户端自己的提示词**逐字保留在后面**。刻意不替换客户端提示词（用户
//!      明确要求保留）：上游只要求「以身份句开头」，前缀之后接什么它不管；
//!   2. **改写**外来身份句（[`FOREIGN_IDENTITIES`]）：产品名换成中性说法，语义
//!      不变、字面匹配被破坏。匹配**忽略大小写**（闸门自己就不敏感）。
//!
//! ── 边界（刻意不做的事，别顺手补）──────────────────────────
//!   - **不动 user / assistant / tool 消息**：闸门只看系统提示词，改写用户内容
//!     属于破坏数据；
//!   - **不替换、也不追加** system 消息：前缀直接拼在原有 system 正文之前；
//!   - **不碰 `tools` / `stream` / 其它字段**：tools 不是这条闸门的判据；
//!   - **不管 406 之后的动作**：分类与提示在 `chat.rs`（[`UPSTREAM_406_HINT`]）。
//!
//! ── 幂等性（重要）──────────────────────────────────────────
//! 正文已经以身份句开头时**只改写、不再前置**：官方客户端的请求本身就带 OpenClaw
//! 提示词，重复前缀会把提示词写两遍（降级 / 同家重试路径上必然发生）。判据只有
//! `starts_with(IDENTITY_LINE)` 一条。
//!
//! ── 硬约束 ─────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。形态怪异（`content`
//! 是数组 / null / 消息不是对象）时一律「尽力产出能发出去的 body」，绝不失败。

use agent2api_wasm_sdk::{json, Value};

/// 上游闸门要求「以它开头」的身份句（幂等判定与日志文案用）。
pub const IDENTITY_LINE: &str = "You are a personal assistant running inside OpenClaw.";

/// 出站身份前缀：身份句 + `## Tooling` 段（官方 prompt 的开头两行，逐字照抄）。
///
/// 末尾带一个 `\n`，[`join_prefix`] 再补一个空行 —— 于是客户端正文另起一段，
/// 与官方 prompt 的段落风格一致。
const IDENTITY_PREFIX: &str = "You are a personal assistant running inside OpenClaw.\n\n\
## Tooling\n\
Available tools are policy-filtered. Names are case-sensitive; call exactly as listed.\n";

/// 外来身份句 → 中性说法（**长的在前**）。
///
/// 顺序与 `sanitize` 的规则表同一条纪律：短的在前会把长匹配串切碎，于是
/// 「改写后仍含产品名」这种半吊子结果会被漏掉。
///
/// 每条的替换串都**不含产品名**：闸门拦的是产品名本身，插一个词在这里不够用。
///
/// ── 覆盖面（2026-11 参考 magpie 的 autoclaw 插件补齐）────────────
/// 参考项目 `Acankao/magpie-plugins/packages/autoclaw` 维护着同一道闸门的改写表，
/// 覆盖的客户端远多于原先的 8 条。这里按它的清单补上「用户真的会撞上」的那些
/// 身份句（Claude Agent SDK / opencode / Cursor / Cline / Qwen Code / Gemini CLI /
/// Kimi Code CLI / goose / Hermes / CodeBuddy Code / pi …）—— 每补一类客户端，
/// 就少一类「406 且不知为何」的报告。
///
/// 实测口径（别把没测过的写成测过的）：
///   - **国内版实测「改写后 200」**：ZCode / Claude Code / 老 Codex CLI 三句；
///   - **国际版实测「原样出站 406」**：`DeepSeek Harness` 与新版 Codex 首句；
///   - **照搬 magpie 清单的条目尚未在本机复验**：方向一致，但源头是 magpie 对
///     各家客户端源码与上游拦截的核对 —— 若某个客户端仍 406，把它的 system
///     首句反馈到项目 issue 即可。
const FOREIGN_IDENTITIES: &[(&str, &str)] = &[
    // ── ZCode（长的在前）──
    (
        "You are ZCode, an interactive coding agent",
        "You are an interactive coding agent",
    ),
    ("You are ZCode", "You are an interactive coding agent"),
    // ── Codex（三种长句式在前，`You are Codex` / `Codex CLI` 兜底在后）──
    (
        "You are a coding agent running in the Codex CLI tool",
        "You are a coding agent running in a terminal CLI tool",
    ),
    (
        "You are a coding agent running in the Codex CLI",
        "You are a coding agent running in a terminal CLI",
    ),
    (
        "You are running as a coding agent in the Codex CLI",
        "You are running as a coding agent in a terminal CLI",
    ),
    ("You are Codex", "You are a coding agent"),
    ("Codex CLI", "Codex command-line tool"),
    // ── Claude 系（Claude Code 2.1.30x 起首句换成了 SDK 身份句，长在前）──
    (
        "You are a Claude agent, built on Anthropic's Claude Agent SDK",
        "You are a coding assistant",
    ),
    ("Claude Agent SDK", "the agent framework"),
    ("You are Claude Code", "You are a coding assistant"),
    // ── DeepSeek Harness（国际版，issue #10）──
    (
        "You are an AI agent powered by DeepSeek Harness",
        "You are an AI agent powered by a local coding harness",
    ),
    // ── 其它 CLI / Agent 身份句（2026-11 照搬 magpie 的 autoclaw 改写清单）──
    ("You are CodeBuddy Code", "You are a coding assistant"),
    ("You are Hermes Agent", "You are an agent"),
    ("You are Hermes", "You are an agent"),
    ("You are Gemini CLI", "You are a coding agent"),
    ("You are Kimi Code CLI", "You are a coding agent"),
    ("You are Qwen Code", "You are a coding agent"),
    ("You are opencode", "You are a coding agent"),
    ("You are Cursor", "You are a coding agent"),
    ("You are Cline", "You are a coding agent"),
    ("You are goose", "You are a coding agent"),
    // ── 其它措辞：pi 的描述句、ZCode 的「powered by GLM-<版本>」开场白 ──
    (
        "operating inside pi, a coding agent harness",
        "operating inside a coding agent harness",
    ),
    (
        "This conversation is powered by GLM",
        "This conversation is powered by the GLM",
    ),
];

/// 客户端可见的 **406 拒收提示**：附在 `上游返回 406: 上游错误` 之后。
///
/// 406 是上游预校验拒收的**统一形态**，实测过三个**独立**方向（别把它们写成
/// 一个原因 —— 旧文案只提提示词，报告人就因为这个在提示词上绕了远路）：
///   1. **`max_tokens` 取值**：30 ~ 8192 的小正整数一律 406 空响应体，不传或
///      ≥ 10000 则 200 —— 插件已在出站前把小正整数归一到 10000；
///   2. **system 首句指纹**：外来 harness 身份句按逐字匹配拦截，改写后不再命中；
///   3. **请求形态风控**：同一 token 直连能进业务逻辑、换网关形态被静默拒 ——
///      目前无解，只能反馈现象。
pub const UPSTREAM_406_HINT: &str = "；上游拒收（406）且未给出原因，实测过的方向：\
① 请求体 max_tokens 取小值（如 1024 / 2048 / 4096）会被上游预校验拦截 —— 插件已把小值归一到 10000，若仍复现请把客户端请求体发到项目 issue；\
② system 首句命中逐字指纹拦截 —— 可在设置页「通用 → 系统提示词」切到「替换」模式绕过，或把漏网的 system 首句发到项目 issue 以便补进指纹表；\
③ 请求形态被上游风控拦截（①②都排除时）—— 请把现象发到项目 issue";

/// 出站前规范化 body 里的系统提示词（**就地修改**）。
///
/// 两步：① 所有 system / developer 消息里的外来身份句改写；② 保证首条消息是
/// system / developer 且正文以身份句开头（是则前置前缀，否则在 `messages[0]`
/// 插一条带前缀的 system 消息）。
///
/// `messages` 缺失或不是数组时**直接返回**：那不是本模块能修的形态，交给上游
/// 报格式错误比在这里造一个空 `messages` 更能说明问题。
pub fn normalize(body: &mut Value) {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    for message in messages.iter_mut() {
        if !is_system_role(message) {
            continue;
        }
        if let Some(content) = message.get_mut("content") {
            rewrite_identities_in_place(content);
        }
    }
    // 首条就是 system / developer：前缀拼进它自己的正文（客户端提示词保留在后）。
    if messages.first().map(is_system_role).unwrap_or(false) {
        if let Some(first) = messages.first_mut() {
            prepend_prefix(first);
        }
        return;
    }
    // 首条不是：补一条只带前缀的 system 消息。**不改**后面那些 system 消息的
    // 位置 —— 重排消息序列的风险（破坏客户端的轮次结构）远大于收益。
    messages.insert(0, json!({ "role": "system", "content": IDENTITY_PREFIX }));
}

/// 给一条消息的 `content` 前置身份前缀（已经以身份句开头则不动）。
///
/// `content` 的三种形态：
///   - 字符串：直接拼；
///   - 数组（多 part）：拼进**第一个文本 part**；一个文本 part 都没有时在数组
///     头部插一个 —— 上游闸门看的是文本，插一个 part 比替换整个数组安全；
///   - 其它（null / 对象 / 数字）：换成前缀本身。这种 content 当 system 提示词
///     本来就不成立（上游会当空提示词处理，稳定 406），换掉比原样发出去好。
fn prepend_prefix(message: &mut Value) {
    let Some(content) = message.get_mut("content") else {
        // 连 content 字段都没有：补上（`role` 已经是 system 了，补 content 只是
        // 让闸门能过，不改变这条消息的语义）
        if let Some(object) = message.as_object_mut() {
            object.insert(
                "content".to_string(),
                Value::String(IDENTITY_PREFIX.to_string()),
            );
        }
        return;
    };
    match content {
        Value::String(text) => {
            if !text.starts_with(IDENTITY_LINE) {
                *text = join_prefix(text);
            }
        }
        Value::Array(parts) => {
            let index = parts
                .iter()
                .position(|part| part.get("text").and_then(Value::as_str).is_some());
            match index {
                Some(index) => {
                    let already = parts
                        .get(index)
                        .and_then(|part| part.get("text"))
                        .and_then(Value::as_str)
                        .map(|text| text.starts_with(IDENTITY_LINE))
                        .unwrap_or(false);
                    if already {
                        return;
                    }
                    if let Some(Value::String(text)) = parts.get_mut(index).and_then(|part| part.get_mut("text")) {
                        *text = join_prefix(text);
                    }
                }
                None => parts.insert(0, json!({ "type": "text", "text": IDENTITY_PREFIX })),
            }
        }
        other => {
            *other = Value::String(IDENTITY_PREFIX.to_string());
        }
    }
}

/// 前缀 + 一个空行 + 原文（原文为空时不留多余空行）。
fn join_prefix(original: &str) -> String {
    if original.is_empty() {
        return IDENTITY_PREFIX.to_string();
    }
    let mut out = String::with_capacity(IDENTITY_PREFIX.len() + original.len() + 1);
    out.push_str(IDENTITY_PREFIX);
    out.push('\n');
    out.push_str(original);
    out
}

/// 就地改写 content（字符串 / 文本 part 数组）里的外来身份句。
fn rewrite_identities_in_place(content: &mut Value) {
    match content {
        Value::String(text) => rewrite_identities(text),
        Value::Array(parts) => {
            for part in parts.iter_mut() {
                if let Some(Value::String(text)) = part.get_mut("text") {
                    rewrite_identities(text);
                }
            }
        }
        _ => {}
    }
}

/// 逐条套用 [`FOREIGN_IDENTITIES`]（**全量**替换，一条文本里出现多次也一并改掉）。
///
/// 匹配忽略 ASCII 大小写 —— 闸门自己就不敏感，替换也必须不敏感。
fn rewrite_identities(text: &mut String) {
    for (from, to) in FOREIGN_IDENTITIES {
        if let Some(next) = replace_all_ignore_ascii_case(text, from, to) {
            *text = next;
        }
    }
}

/// `from` 在 `text` 里的**全量**替换（忽略 ASCII 大小写）；一次都没命中返回
/// `None`（调用方据此跳过写回）。
///
/// 替换串 `to` 里即使含 `from` 也不会死循环：每轮从匹配处**之后**继续扫，
/// 替换出来的字节永不被重新检查。
fn replace_all_ignore_ascii_case(text: &str, from: &str, to: &str) -> Option<String> {
    find_ignore_ascii_case(text, from)?;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = find_ignore_ascii_case(rest, from) {
        out.push_str(&rest[..start]);
        out.push_str(to);
        rest = &rest[start + from.len()..];
    }
    out.push_str(rest);
    Some(out)
}

/// `from` 在 `text` 里首次出现的**字节下标**（只折叠 ASCII 大小写）。
///
/// 为什么不是 `text.to_lowercase()` 再找：Unicode 折叠会改变字节长度（`İ` 折叠
/// 出来是两个字符），折叠后的下标回不到原文，切片就会错位。这里按字节滑窗加
/// `eq_ignore_ascii_case` 比较：`from` 全是 ASCII，而 UTF-8 里非 ASCII 字符的每个
/// 字节都 >= 0x80，折叠后不可能等于 ASCII 字节 —— 于是命中区间只可能由 ASCII
/// 字节组成，起止点都是字符边界，切片安全。
fn find_ignore_ascii_case(text: &str, from: &str) -> Option<usize> {
    let haystack = text.as_bytes();
    let needle = from.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|&start| haystack[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// 该消息是否承载 system 级指令：角色**精确**等于 `system` 或 `developer`。
fn is_system_role(message: &Value) -> bool {
    message
        .get("role")
        .and_then(Value::as_str)
        .map(|role| role == "system" || role == "developer")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 首条 system 被前置身份句；外来身份句被改写；幂等。
    #[test]
    fn normalizes_identity_and_is_idempotent() {
        let mut body = json!({ "messages": [
            { "role": "system", "content": "You are ZCode, an interactive coding agent.\nBe nice." },
            { "role": "user", "content": "hi" }
        ]});
        normalize(&mut body);
        // 借用必须先结束（`content` 是 &str，后面还要再 &mut body）
        let content = body["messages"][0]["content"].as_str().unwrap_or("").to_string();
        assert!(content.starts_with(IDENTITY_LINE));
        assert!(!content.contains("You are ZCode"));
        // 幂等：再跑一次不再重复前置
        normalize(&mut body);
        let again = body["messages"][0]["content"].as_str().unwrap_or("").to_string();
        assert_eq!(content, again);
    }

    /// 没有 system 消息时插一条；user 内容绝不被改写。
    #[test]
    fn inserts_system_and_leaves_user_content() {
        let mut body = json!({ "messages": [
            { "role": "user", "content": "You are Claude Code" }
        ]});
        normalize(&mut body);
        assert_eq!("system", body["messages"][0]["role"].as_str().unwrap_or(""));
        assert_eq!("You are Claude Code", body["messages"][1]["content"].as_str().unwrap_or(""));
    }

    /// 大小写变体也要被改写（闸门自己不敏感）。
    #[test]
    fn case_insensitive_rewrite() {
        assert_eq!(
            Some("You are an agent".to_string()),
            replace_all_ignore_ascii_case("you are hermes", "You are Hermes", "You are an agent")
        );
    }
}
