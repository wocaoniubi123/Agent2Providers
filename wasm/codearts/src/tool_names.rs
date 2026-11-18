//! CodeArts 的**函数名超限改写**：上游对 `tools[].function.name` 有 64 个字符的硬限。
//!
//! ── 这条限制长什么样（2026-10-10 在 dev 的一批 codearts 独占模型上量的）──
//! ```text
//! InferHub.001001017.413：Function name [<名字>] length over limit, maximum is 64
//! ```
//! 属于**收请求前**的预校验：被拒的那几发 token 计数全是 0，不消耗产出。
//! 实测 64 过 / 66 拒。撞上的真实形状就是 MCP 插件名：
//! `mcp__plugin_android-emulator_android-emulator__` 光前缀就 47 字符，插件里任何
//! 超过 17 字符的函数名必然超。
//!
//! ── 三条口径 ────────────────────────────────────────────────
//!   · **只在真需要时动手**：名单里没有一个超限名 ⇒ [`shorten`] 返回 `None`，
//!     请求体与响应流都逐字节原样走（改流的风险远大于「少改一次名」的收益）；
//!   · **纯截断不安全**：上游**不判重名** —— `tools` 里放两个完全同名的函数也回
//!     200，于是截断撞名不会报错，只会让模型无从区分。所以截短后补哈希后缀，
//!     并且对「客户端本来就有的名字」一起查重；
//!   · **只改 `tools` 定义，不改历史**：`messages` 里 assistant 的
//!     `tool_calls[].function.name` 给 71 字符照样 200，而模型回的是 `tools` 里
//!     那份短名 ⇒ 还原只需覆盖响应侧。
//!
//! ── 与 native 的一处**有意**差异 ────────────────────────────
//! native 用 `sha1` 生成后缀，本插件的依赖清单里没有 sha1（只有 sha2），所以改用
//! SHA-256 的前若干位十六进制。**短名只在一次请求内自洽**（发出去的名字与还原表
//! 同一份），换哈希算法不会让任何一侧认不出来 —— 只是同一份工具表在两次实现下
//! 得到不同的短名，这对客户端不可见。

use std::collections::{HashMap, HashSet};

use serde_json::Value;

/// 上游允许的函数名长度（字符数）。
pub const MAX_NAME_CHARS: usize = 64;
/// 哈希后缀的宽度序列：先试 7 位，撞上已有的名字就加长。
const HASH_WIDTHS: [usize; 3] = [7, 10, 14];

/// 把超限的函数名改短，返回**响应侧**的还原表；没有任何改动时返回 `None`。
pub fn shorten(body: &mut Value) -> Option<Restorer> {
    // 没有 tools 就直接不动
    let tools = body.get_mut("tools").and_then(Value::as_array_mut)?;
    // 判重的底账：客户端本来就有的名字一个都不许占用
    let mut taken: HashSet<String> = tools.iter().filter_map(function_name).map(str::to_owned).collect();
    let mut sent_to_original = HashMap::new();
    for tool in tools.iter_mut() {
        let Some(original) = function_name(tool).map(str::to_owned) else {
            continue;
        };
        if original.chars().count() <= MAX_NAME_CHARS {
            continue;
        }
        let Some(sent) = short_name(&original, &mut taken) else {
            // 三档哈希都没避开：**不改**它，让上游照旧拒这一发，
            // 比替客户端造一个可能错的名字安全
            continue;
        };
        if let Some(object) = tool.get_mut("function").and_then(Value::as_object_mut) {
            object.insert("name".to_string(), Value::String(sent.clone()));
        }
        sent_to_original.insert(sent, original);
    }
    (!sent_to_original.is_empty()).then_some(Restorer { sent_to_original })
}

/// `tools[i].function.name`（形状不对或空串就当没有）
fn function_name(tool: &Value) -> Option<&str> {
    tool.get("function")
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// 生成一个不与 `taken` 冲突的短名：`前缀 + '_' + 哈希`，正好 64 字符。
fn short_name(original: &str, taken: &mut HashSet<String>) -> Option<String> {
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(original.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for width in HASH_WIDTHS {
        // 前缀留出的字符数：上限减去「一个下划线 + width 位哈希」
        let head = MAX_NAME_CHARS.checked_sub(width + 1)?;
        let prefix: String = original.chars().take(head).collect();
        let candidate = format!("{prefix}_{}", &hex[..width]);
        if taken.insert(candidate.clone()) {
            return Some(candidate);
        }
    }
    None
}

/// 响应侧的名字还原器：`我们发出去的名字 -> 客户端原来的名字`。
pub struct Restorer {
    sent_to_original: HashMap<String, String>,
}

impl Restorer {
    /// 是否无事可做。
    pub fn idle(&self) -> bool {
        self.sent_to_original.is_empty()
    }

    /// 还原一个 chunk 里的工具名（流式 `delta.tool_calls[]` 与非流式
    /// `message.tool_calls[]` 两种形状都覆盖）。返回是否动过。
    pub fn apply(&self, chunk: &mut Value) -> bool {
        let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
            return false;
        };
        let mut touched = false;
        for choice in choices.iter_mut() {
            for slot in ["delta", "message"] {
                let Some(calls) = choice
                    .get_mut(slot)
                    .and_then(|part| part.get_mut("tool_calls"))
                    .and_then(Value::as_array_mut)
                else {
                    continue;
                };
                for call in calls.iter_mut() {
                    let Some(object) = call.get_mut("function").and_then(Value::as_object_mut) else {
                        continue;
                    };
                    // 先借出去查，拿到所有权再写回：同一处两次借用会打架
                    let original = object
                        .get("name")
                        .and_then(Value::as_str)
                        .and_then(|name| self.sent_to_original.get(name).cloned());
                    if let Some(original) = original {
                        object.insert("name".to_string(), Value::String(original));
                        touched = true;
                    }
                }
            }
        }
        touched
    }

    /// 还原一段 SSE 数据帧（已去掉 `data:` 前缀的 JSON 文本）。返回新的文本。
    pub fn apply_text(&self, data: &str) -> String {
        if self.idle() {
            return data.to_string();
        }
        let Ok(mut value) = serde_json::from_str::<Value>(data) else {
            return data.to_string();
        };
        if !self.apply(&mut value) {
            return data.to_string();
        }
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent2api_wasm_sdk::json;

    #[test]
    fn a_short_name_list_is_left_byte_for_byte_alone() {
        let mut body = json!({ "tools": [{ "type": "function", "function": { "name": "short_tool" } }] });
        assert!(shorten(&mut body).is_none(), "没超限就一个字节都不改");
        assert_eq!("short_tool", body["tools"][0]["function"]["name"]);
    }

    #[test]
    fn an_overlong_name_is_shortened_and_restored() {
        let original = "mcp__plugin_android-emulator_android-emulator__android_discover_project_extra_long_tail";
        assert!(original.chars().count() > MAX_NAME_CHARS);
        let mut body = json!({ "tools": [{ "type": "function", "function": { "name": original } }] });
        let restorer = match shorten(&mut body) {
            Some(restorer) => restorer,
            None => panic!("超限名必须被改写"),
        };
        let sent = body["tools"][0]["function"]["name"].as_str().unwrap_or_default().to_string();
        assert!(sent.chars().count() <= MAX_NAME_CHARS, "改写后必须落在 64 字符内：{sent}");
        assert!(sent.starts_with("mcp__plugin_android-emulator"), "前缀保留");
        // 响应侧还原
        let mut chunk = json!({ "choices": [{ "delta": { "tool_calls": [
            { "index": 0, "function": { "name": sent } }
        ] } }] });
        assert!(restorer.apply(&mut chunk));
        assert_eq!(original, chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["name"]);
    }

    #[test]
    fn generated_names_never_collide_with_existing_ones() {
        let long = "a".repeat(70);
        let mut body = json!({ "tools": [
            { "type": "function", "function": { "name": long } },
            { "type": "function", "function": { "name": long } },
        ] });
        let restorer = match shorten(&mut body) {
            Some(restorer) => restorer,
            None => panic!("两条都要改"),
        };
        assert!(!restorer.idle());
        let first = body["tools"][0]["function"]["name"].as_str().unwrap_or_default();
        let second = body["tools"][1]["function"]["name"].as_str().unwrap_or_default();
        assert_ne!(first, second, "同名输入也必须拿到两个不同的短名");
    }
}
