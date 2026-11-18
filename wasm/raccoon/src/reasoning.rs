//! 档位字段来自 1.1.5 Box-Agent 的 `_apply_thinking_params`；不覆盖客户端选择。
//!
//! ── 思考档位的通用口径跟着插件走 ────────────────────────────
//! native 侧的 `effort_rank` / `is_thinking_off` 来自 provider 侧 crate 的共用
//! 模块（网关的 `core::model_rules::reasoning` 里有同一份）。插件进程不认识
//! 网关的配置层，所以这份规则只能跟着插件走；wasm 目标不允许依赖那个 crate，
//! 因此**逐字复制**到本文件末尾 —— 口径必须与网关一致，否则同一份映射在
//! 搬家前后会给出不同的注入结果。

use agent2api_wasm_sdk::{json, Error, Result, Value};

fn model_name(model: &str) -> String {
    model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .trim()
        .to_ascii_lowercase()
}

/// 模型家族（决定思考字段怎么翻）。
///
/// 三档的来源是官方 1.1.5 客户端的 `_apply_thinking_params`：
///   - `thinking`：DeepSeek / 豆包系 —— 上游只认嵌套的
///     `extra_body.thinking = {type: enabled|disabled}`；
///   - `low_high`：GLM-5.3 / Kimi-K3 —— `reasoning_effort` 只有 low / high 两档；
///   - `effort`：SenseNova 与内部 `raccoon-*` —— 三档 low / medium / high。
fn family(model: &str) -> &'static str {
    let model = model_name(model);
    if model.starts_with("sn-deepseek-")
        || model.starts_with("deepseek-")
        || model.starts_with("sn-doubao-")
        || model.starts_with("doubao-")
    {
        "thinking"
    } else if model.starts_with("sn-glm-5-3") || model.starts_with("sn-kimi-k3") {
        "low_high"
    } else if model.starts_with("sn-sensenova-") || model.starts_with("raccoon-") {
        "effort"
    } else {
        ""
    }
}

/// 这个模型有没有已确认的思考参数（目录条目与静态兜底表都用它填
/// `supportThinking`）。
pub fn supported(model: &str) -> bool {
    !family(model).is_empty()
}

/// 客户端是否**已经显式**指定了思考参数（指定了就不覆盖）。
fn explicit(body: &Value) -> bool {
    [
        "reasoning_effort",
        "reasoningEffort",
        "reasoning",
        "thinking",
        "enable_thinking",
    ]
    .iter()
    .any(|key| body.get(*key).is_some_and(|value| !value.is_null()))
        || body.get("extra_body").is_some_and(|extra| {
            ["thinking", "reasoning_effort", "enable_thinking"]
                .iter()
                .any(|key| extra.get(*key).is_some_and(|value| !value.is_null()))
        })
}

/// 档位翻译（`reasoning_patch` 方法）。
///
/// 返回形态与 native 的 `proto::ReasoningPatch` 同一序列化：
/// `{action: "set", field, value}` / `{action: "skip", reason}`。
pub fn patch(level: &str, model: &str, body: &Value) -> Value {
    let skip = |reason: &str| json!({ "action": "skip", "reason": reason });
    if explicit(body) {
        return skip("客户端已指定思考参数，保留原值");
    }
    let Some(rank) = effort_rank(level) else {
        return skip("关闭思考或未知档位不注入绑定");
    };
    let (field, value) = match family(model) {
        "thinking" => {
            let mut extra = body
                .get("extra_body")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            extra.insert("thinking".to_string(), json!({ "type": "enabled" }));
            ("extra_body", Value::Object(extra))
        }
        "low_high" => (
            "reasoning_effort",
            json!(if rank <= 1 { "low" } else { "high" }),
        ),
        "effort" => (
            "reasoning_effort",
            json!(match rank {
                0 | 1 => "low",
                2 => "medium",
                _ => "high",
            }),
        ),
        _ => return skip("该小浣熊模型没有已确认的思考参数"),
    };
    json!({ "action": "set", "field": field, "value": value })
}

/// 客户端请求体 → 上游认识的思考字段（`build_chat` 的第一步）。
///
/// 只做「已确认」的翻译：`reasoningEffort` 改名为 `reasoning_effort`；
/// DeepSeek/豆包系把 thinking 折进 `extra_body`；GLM/Kimi 把三档压成两档。
/// 其余模型一律原样透传（改错字段比不改更糟）。
pub fn normalize(body: &Value, model: &str) -> Result<Value> {
    let mut body = body.clone();
    let Some(fields) = body.as_object_mut() else {
        return Err(Error::http(400, "小浣熊请求体必须是 JSON 对象"));
    };
    if !fields.contains_key("reasoning_effort") {
        if let Some(effort) = fields.remove("reasoningEffort") {
            fields.insert("reasoning_effort".to_string(), effort);
        }
    }
    match family(model) {
        "thinking" => normalize_thinking(fields)?,
        "low_high" => {
            let disabled = fields
                .get("thinking")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("disabled");
            if disabled {
                fields.remove("thinking");
                fields.insert("reasoning_effort".to_string(), json!("low"));
            } else if let Some(effort) = fields.get("reasoning_effort").and_then(Value::as_str) {
                let mapped = if is_thinking_off(effort)
                    || effort_rank(effort).is_some_and(|rank| rank <= 1)
                {
                    Some("low")
                } else if effort_rank(effort).is_some() {
                    Some("high")
                } else {
                    None
                };
                if let Some(mapped) = mapped {
                    fields.insert("reasoning_effort".to_string(), json!(mapped));
                }
            }
        }
        _ => {}
    }
    Ok(body)
}

fn normalize_thinking(fields: &mut serde_json::Map<String, Value>) -> Result<()> {
    if fields
        .get("extra_body")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err(Error::http(400, "小浣熊 extra_body 必须是 JSON 对象"));
    }
    let nested = fields
        .get("extra_body")
        .and_then(|extra| extra.get("thinking"))
        .filter(|value| !value.is_null())
        .cloned();
    let direct = fields
        .get("thinking")
        .filter(|value| !value.is_null())
        .cloned();
    let off = fields
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .is_some_and(is_thinking_off);
    let thinking = nested
        .or(direct)
        .or_else(|| off.then(|| json!({ "type": "disabled" })));
    if let Some(thinking) = thinking {
        if !fields.get("extra_body").is_some_and(Value::is_object) {
            fields.insert("extra_body".to_string(), json!({}));
        }
        if let Some(extra) = fields.get_mut("extra_body").and_then(Value::as_object_mut) {
            extra.insert("thinking".to_string(), thinking);
        }
        fields.remove("thinking");
        if off {
            fields.remove("reasoning_effort");
        }
    }
    Ok(())
}

/// 出站思考档位（native 的 `outbound_reasoning`：给遥测用的那一个值）。
///
/// ⚠️ 当前 wasm ABI **没有** `outbound_reasoning` 这条方法（方法表里没有它），
/// 所以这里没有调用方。函数原样保留（连同它的判据）：一旦宿主补上挂点，
/// 直接接上即可，不必再重新推一遍「哪些字段算档位」。
#[allow(dead_code)]
pub fn outbound(body: &Value) -> Option<String> {
    body.get("reasoning_effort")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            match body
                .pointer("/extra_body/thinking/type")
                .or_else(|| body.pointer("/thinking/type"))
                .and_then(Value::as_str)
            {
                Some("enabled") => Some("high".to_string()),
                Some("disabled") => Some("off".to_string()),
                _ => None,
            }
        })
}

// ─── 通用口径（逐字复制自网关的 model_rules::reasoning）──────────

/// 可以翻译给上游的正向档位（不含 `off` / `none`）。
///
/// 数组顺序 = 强弱顺序，[`effort_rank`] 直接拿它当下标用。
pub const EFFORT_LEVELS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max"];

/// 该等级是不是「关闭思考」两档（`off` / `none`），忽略大小写。
pub fn is_thinking_off(level: &str) -> bool {
    let trimmed = level.trim();
    trimmed.eq_ignore_ascii_case("off") || trimmed.eq_ignore_ascii_case("none")
}

/// 正向档位 → 序号（0 = 最弱，5 = 最强）。`off` / `none` / 表外值一律 None。
///
/// 返回 None 的含义是「**这个值不该被注入上游**」，不是「这个值不合法」。
pub fn effort_rank(level: &str) -> Option<usize> {
    let trimmed = level.trim();
    if trimmed.is_empty() {
        return None;
    }
    EFFORT_LEVELS
        .iter()
        .position(|known| trimmed.eq_ignore_ascii_case(known))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_are_recognised() {
        assert_eq!(family("sn-glm-5-3"), "low_high");
        assert_eq!(family("sn-kimi-k3"), "low_high");
        assert_eq!(family("sn-deepseek-v4-1-flash"), "thinking");
        assert_eq!(family("doubao-pro"), "thinking");
        assert_eq!(family("sn-sensenova-6-8-flash"), "effort");
        assert_eq!(family("raccoon-405a1c"), "effort");
        assert_eq!(family("unknown-model"), "");
        // 带账号前缀的名字要先剥前缀再判家族
        assert_eq!(family("acc-1/sn-kimi-k3"), "low_high");
    }

    #[test]
    fn patch_sets_the_family_specific_field() {
        // 没有 extra_body 时补一个，并把 thinking 折进去
        let set = patch("high", "sn-deepseek-v4-1-flash-1017", &json!({}));
        assert_eq!(set["action"], "set");
        assert_eq!(set["field"], "extra_body");
        assert_eq!(set["value"]["thinking"]["type"], "enabled");
        // 两档家族：弱档 → low，强档 → high
        assert_eq!(patch("minimal", "sn-glm-5-3", &json!({}))["value"], "low");
        assert_eq!(patch("max", "sn-glm-5-3", &json!({}))["value"], "high");
        // 三档家族
        assert_eq!(patch("medium", "raccoon-405a1c", &json!({}))["value"], "medium");
    }

    #[test]
    fn patch_skips_when_it_should() {
        // 客户端已显式指定 → 不动
        let skipped = patch("high", "sn-glm-5-3", &json!({ "reasoning_effort": "low" }));
        assert_eq!(skipped["action"], "skip");
        // 关闭思考 → 不注入
        assert_eq!(patch("off", "sn-kimi-k3", &json!({}))["action"], "skip");
        // 没有已确认参数的模型 → 不注入
        assert_eq!(patch("high", "unknown-model", &json!({}))["action"], "skip");
    }

    #[test]
    fn normalize_renames_and_folds_fields() {
        // 失败时给 Null，让后面的字段断言直接失败（测试里不用 expect）
        let renamed = normalize(&json!({ "reasoningEffort": "high" }), "sn-glm-5-3")
            .unwrap_or(Value::Null);
        assert_eq!(renamed["reasoning_effort"], "high");
        assert!(renamed.get("reasoningEffort").is_none());
        // thinking 家族：顶层 thinking 折进 extra_body
        let folded = normalize(
            &json!({ "thinking": { "type": "disabled" } }),
            "sn-deepseek-v4-1-flash-1017",
        )
        .unwrap_or(Value::Null);
        assert!(folded.get("thinking").is_none());
        assert_eq!(folded["extra_body"]["thinking"]["type"], "disabled");
        // 两档家族：thinking=disabled 折成 effort=low
        let folded = normalize(
            &json!({ "thinking": { "type": "disabled" } }),
            "sn-kimi-k3",
        )
        .unwrap_or(Value::Null);
        assert!(folded.get("thinking").is_none());
        assert_eq!(folded["reasoning_effort"], "low");
        // 非对象请求体 → 400
        assert!(normalize(&json!("x"), "sn-kimi-k3").is_err());
    }
}
