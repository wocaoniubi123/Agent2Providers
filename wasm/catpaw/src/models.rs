//! CatPaw 上游 `modelType` 映射表与入站参数解析。
//!
//! ── 模型表为什么是静态表而不是配置（native 同一条理由）─────────
//! 数字 `modelType` 是**上游的内部 ID**，写错一个不会报错，只会让请求打到
//! 另一个模型 —— 所以这里刻意保留「证据」注释，改动前必须回去核对源文件。
//!
//! 这张表**不是模型清单的唯一来源**：上游有远程目录
//! （`POST /api/agent/maas/model-types`，见 `catalog.rs`）。静态表留在原地的
//! 理由是它能提供远程条目给不出的两样东西：
//!   1. `host_model_id` —— 实测坐实的上游数字 ID（远程条目也带 `modelTypeId`，
//!      但只有表里这两个是逐条验证过能力与档位的）；
//!   2. `context_windows` / `default_context_window` —— `context` 参数的
//!      合法档位（远程把这些藏在 `parameterDefinitions` 的 ENUM 里）。
//!
//! ── 迁移到 wasm 后的取值顺序 ────────────────────────────────
//!   1. 静态表命中（最可靠：档位校验需要 `ModelSpec`）；
//!   2. 宿主保存的远程目录命中（用它自带的 `modelType`）；
//!   3. 纯数字 → 原样当上游 ID（`entry` 为 None，context 校验据此拒绝）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 纯函数：不发网络请求、不持锁、零 unwrap / expect / panic。

use serde_json::Value;

use super::errors::CatPawError;

/// 一个 CatPaw 模型的静态事实。
///
/// 只收录本路径真正消费的字段：原表还有 `reasoningEffort` / `thinkingType` /
/// `hostAdvertisedThinking` / `verified` 四项，它们在客户端的 Host 模式下参与
/// 能力判定；OpenAI 兼容路径只用下面这些。
#[derive(Clone, Copy, Debug)]
pub struct ModelSpec {
    /// 对外模型名（OpenAI 的 `model` 字段；也是聚合目录里的 id）
    pub id: &'static str,
    /// 展示名（原表 `name`，容忍 `GLM-5.3-Flash` 这类大小写/分隔符差异）
    pub name: &'static str,
    /// 上游 `modelType` 数字 ID
    pub host_model_id: i64,
    /// 是否支持图片输入（原表 `supportImage`；进清单的 `supports_images`）
    pub support_image: bool,
    /// 是否支持思考（原表 `supportThinking`；进清单的 `supports_reasoning`）
    pub support_thinking: bool,
    /// 该模型支持的 `context` 档位（空 = 不支持 context 参数）
    pub context_windows: &'static [&'static str],
    /// 未显式请求 context 时的默认档位（None = 不发送 context 字段）
    pub default_context_window: Option<&'static str>,
}

/// 模型注册表。
///
/// ── 每个数字 ID 的证据（原表头注释逐条对照，**不要凭名字猜**）──
///   - `83 = Kimi-K3`：长连接日志里 `model:83` 会话自述 Moonshot/Kimi，
///     且真实 Host 图片请求成功；
///   - `91 = GLM-5.3-Flash`：`model:91` 会话自述 Z.ai GLM、真实 Host 图片请求
///     成功，且桌面端持久化选择为
///     `{"modelId":91,"modelParams":{"context":"1024000","effort":"max"}}`。
///
/// 两个 ID 都经过 `agent_start`、图片与 `reasoningContent` 实测，不依据名称猜测。
/// `kimi-k3` 在原表里**没有** `contextWindows` 字段 ⇒ 不支持 context 参数
/// （传了就报 400），`glm-5.3-flash` 才有三档。
pub const MODELS: &[ModelSpec] = &[
    ModelSpec {
        id: "kimi-k3",
        name: "Kimi-K3",
        host_model_id: 83,
        support_image: true,
        support_thinking: true,
        context_windows: &[],
        default_context_window: None,
    },
    ModelSpec {
        id: "glm-5.3-flash",
        name: "GLM-5.3-Flash",
        host_model_id: 91,
        support_image: true,
        support_thinking: true,
        context_windows: &["204800", "512000", "1024000"],
        default_context_window: Some("1024000"),
    },
];

/// 本家接受的三个思考档位（**由弱到强**）。
///
/// `resolve_effort` 的硬校验与 [`effort_for_level`] 的归并都以这一份为准 ——
/// 上游枚举改了这里改一处。
pub const EFFORTS: &[&str] = &["low", "high", "max"];

/// 模型名归一化（原实现 `normalizeModelName`）：小写 + 空白/下划线/点 → 连字符。
///
/// 用途是容忍客户端写 `GLM 5.3 Flash` / `glm_5.3_flash` 这类变体。
pub fn normalize_model_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.trim().chars() {
        if ch.is_whitespace() || ch == '_' || ch == '.' {
            out.push('-');
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}

/// 按名字或数字找模型（原实现 `findModelEntry`）。
pub fn find_model_entry(model: &Value) -> Option<&'static ModelSpec> {
    match model {
        Value::Number(number) => {
            let id = number.as_i64()?;
            MODELS.iter().find(|entry| entry.host_model_id == id)
        }
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Ok(id) = trimmed.parse::<i64>() {
                return MODELS.iter().find(|entry| entry.host_model_id == id);
            }
            let normalized = normalize_model_name(trimmed);
            MODELS.iter().find(|entry| {
                normalize_model_name(entry.id) == normalized
                    || normalize_model_name(entry.name) == normalized
            })
        }
        _ => None,
    }
}

/// 一次请求最终使用的上游模型（对应原实现的 `{ modelId, displayName, entry }`）。
#[derive(Clone, Debug)]
pub struct ModelResolution {
    /// 上游 `modelType`（数字）
    pub model_type: i64,
    /// 客户端可见的模型名（原实现取 `entry.id`，表外数字 ID 则用请求原值）
    pub display_name: String,
    /// 命中的静态表条目（未命中为 None）
    pub entry: Option<&'static ModelSpec>,
}

/// 把客户端请求的 `model` 解析成上游数字 ID（原实现 `resolveModelRequest`
/// 在本网关语义下的裁剪版）。
///
/// ── 与原实现的两处裁剪（都是「网关侧不存在那个概念」）──────────
///   1. 没有 `--agent-model` 覆盖与 `requestedConfig.model` 回落：那两条来自
///      客户端的启动参数，网关进程里没有；
///   2. 表外名字**直接报 400**而不是回落成「不发 model 字段」：网关必须先知道
///      数字 ID 才能建 conversation；回落成「不带数字 ID」时上游会用它自己的
///      默认模型 —— 客户端要的模型与实际跑的不是一个，属于静默错答。
pub fn resolve_model_request(model: &Value) -> Result<ModelResolution, CatPawError> {
    let requested = match model {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_string(),
        _ => String::new(),
    };
    if let Some(entry) = find_model_entry(model) {
        return Ok(ModelResolution {
            model_type: entry.host_model_id,
            display_name: entry.id.to_string(),
            entry: Some(entry),
        });
    }
    // ── 第 2 档：宿主保存的远程目录 ─────────────────────────────
    // 没有这一档就会出现「`/v1/models` 里列着、请求却报 400」的自相矛盾。
    // `display_name` 取**目录里的规范 id**：客户端可能传的是展示名，而回写与
    // 日志该用规范名（与静态表分支 `entry.id` 的取向一致）。
    if !requested.is_empty() {
        if let Some(item) = super::catalog::find_remote(&requested) {
            if let Some(model_type) = item.get("modelType").and_then(Value::as_i64) {
                let canonical = item
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(&requested)
                    .to_string();
                return Ok(ModelResolution {
                    model_type,
                    display_name: canonical,
                    entry: None,
                });
            }
        }
    }
    // ── 第 3 档：纯数字（上游按数字识别模型）────────────────────
    if !requested.is_empty() && requested.chars().all(|ch| ch.is_ascii_digit()) {
        if let Ok(model_type) = requested.parse::<i64>() {
            return Ok(ModelResolution {
                model_type,
                display_name: requested,
                entry: None,
            });
        }
    }
    let names = super::catalog::known_ids().join("、");
    Err(CatPawError::bad_request(format!(
        "CatPaw 上游不支持模型 {}（可用: {names}）",
        if requested.is_empty() { "(未指定)" } else { &requested },
    )))
}

/// `reasoning_effort` → `declarativeParams.effort`（原实现 `resolveEffort`）。
///
/// 取值只允许 low / high / max（上游枚举），其余报 400 —— 静默忽略会让
/// 「客户端以为调了思考等级、实际没生效」无从发现。
pub fn resolve_effort(body: &Value) -> Result<Option<String>, CatPawError> {
    // `body.reasoning_effort ?? body.reasoningEffort ?? body.effort`：**空值合并**
    // （空串也会命中并报错，不会被跳过）
    let raw = body
        .get("reasoning_effort")
        .filter(|value| !value.is_null())
        .or_else(|| body.get("reasoningEffort").filter(|value| !value.is_null()))
        .or_else(|| body.get("effort").filter(|value| !value.is_null()));
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = value_text(raw).trim().to_ascii_lowercase();
    if !EFFORTS.iter().any(|known| *known == value) {
        return Err(CatPawError::bad_request("reasoning_effort 仅支持 low / high / max"));
    }
    Ok(Some(value))
}

/// 网关映射上绑的**通用思考等级** → 本家的档位（`None` = 不注入）。
///
/// ── 为什么必须归并（不能原样发）─────────────────────────────
/// `resolve_effort` 对三个枚举之外的值**当场 400**，而网关的通用表是 6 档
/// （`minimal` / `low` / `medium` / `high` / `xhigh` / `max`）—— 原样注入等于
/// 让 `medium` / `xhigh` 这种合法绑定把一条本来能用的请求打成 400。
/// 归并规则是**两两合流**（`rank / 2`，由弱到强保持单调）：
/// ```text
///   minimal | low   → low
///   medium  | high  → high
///   xhigh   | max   → max
/// ```
/// 表外的自定义等级返回 None：本家对未知值的反应是 400，而那条请求在绑定
/// 之前是能用的 —— 宁可这条绑定不生效，不可把请求弄坏。
pub fn effort_for_level(level: &str) -> Option<&'static str> {
    let rank = reasoning_rank(level)?;
    EFFORTS.get((rank / 2).min(EFFORTS.len() - 1)).copied()
}

/// 通用思考等级的序号（0..=5）。
///
/// native 用网关的 `crate::model_rules::reasoning_rank`；插件里没有那个模块，
/// 按同一张表写一份（顺序必须与网关一致，否则归并结果会漂）。
fn reasoning_rank(level: &str) -> Option<usize> {
    match level.trim().to_ascii_lowercase().as_str() {
        "minimal" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "xhigh" => Some(4),
        "max" => Some(5),
        _ => None,
    }
}

/// 上下文档位别名（原实现 `CONTEXT_WINDOW_ALIASES`）
const CONTEXT_WINDOW_ALIASES: &[(&str, &str)] = &[
    ("200k", "204800"),
    ("204800", "204800"),
    ("500k", "512000"),
    ("512000", "512000"),
    ("1m", "1024000"),
    ("1024k", "1024000"),
    ("1024000", "1024000"),
];

/// 解析 `context` 档位（原实现 `resolveContextWindow`）。
///
/// 顺序照抄原实现：**先取请求里的显式值**（候选字段里第一个非空），没有才用
/// 模型的默认档位；两者都没有就返回 None（不发 context 字段）。显式值必须在
/// 别名表里、且该模型支持这个档位，否则 400。
pub fn resolve_context_window(
    body: &Value,
    resolution: &ModelResolution,
) -> Result<Option<String>, CatPawError> {
    let candidates = [
        body.get("context_window"),
        body.get("contextWindow"),
        body.get("context_length"),
        body.get("contextLength"),
        body.pointer("/model_params/context"),
        body.pointer("/modelParams/context"),
        body.pointer("/request_context/modelParams/declarativeParams/context"),
        body.pointer("/requestContext/modelParams/declarativeParams/context"),
    ];
    let requested = candidates
        .into_iter()
        .flatten()
        .find(|value| !value.is_null() && !value_text(value).trim().is_empty());
    let raw = match requested {
        Some(value) => value_text(value),
        None => match resolution.entry.and_then(|entry| entry.default_context_window) {
            Some(default) => default.to_string(),
            None => return Ok(None),
        },
    };
    let text = raw.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Ok(None);
    }
    let Some((_, normalized)) = CONTEXT_WINDOW_ALIASES.iter().find(|(alias, _)| *alias == text)
    else {
        return Err(CatPawError::bad_request("context_window 仅支持 200K / 500K / 1M"));
    };
    let supported = resolution.entry.map(|entry| entry.context_windows).unwrap_or(&[]);
    if supported.is_empty() {
        return Err(CatPawError::bad_request(format!(
            "模型 {} 不支持 context_window 参数",
            resolution.display_name
        )));
    }
    if !supported.contains(normalized) {
        return Err(CatPawError::bad_request(format!(
            "模型 {} 不支持请求的上下文长度",
            resolution.display_name
        )));
    }
    Ok(Some(normalized.to_string()))
}

/// 值 → 字符串（原实现的 `String(value)`：数字给十进制、布尔给字面量）。
pub fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_name_variants_resolve_to_host_ids() {
        assert_eq!(find_model_entry(&Value::String("GLM 5.3 Flash".into())).map(|m| m.host_model_id), Some(91));
        assert_eq!(find_model_entry(&Value::String("glm_5.3_flash".into())).map(|m| m.host_model_id), Some(91));
        assert_eq!(find_model_entry(&Value::String("83".into())).map(|m| m.host_model_id), Some(83));
        assert!(find_model_entry(&Value::String("nope".into())).is_none());
    }

    #[test]
    fn effort_levels_merge_pairwise() {
        assert_eq!(effort_for_level("minimal"), Some("low"));
        assert_eq!(effort_for_level("low"), Some("low"));
        assert_eq!(effort_for_level("medium"), Some("high"));
        assert_eq!(effort_for_level("high"), Some("high"));
        assert_eq!(effort_for_level("xhigh"), Some("max"));
        assert_eq!(effort_for_level("max"), Some("max"));
        assert_eq!(effort_for_level("custom"), None);
    }

    #[test]
    fn context_window_alias_and_support() {
        let spec = find_model_entry(&Value::String("glm-5.3-flash".into()));
        let resolution = ModelResolution {
            model_type: 91,
            display_name: "glm-5.3-flash".to_string(),
            entry: spec,
        };
        let body = serde_json::json!({ "context_window": "500K" });
        assert_eq!(resolve_context_window(&body, &resolution).unwrap_or(None), Some("512000".into()));
        let bad = serde_json::json!({ "context_window": "128k" });
        assert!(resolve_context_window(&bad, &resolution).is_err());
        // kimi-k3 没有 context 档位 ⇒ 显式传就报错
        let kimi = ModelResolution {
            model_type: 83,
            display_name: "kimi-k3".to_string(),
            entry: find_model_entry(&Value::String("kimi-k3".into())),
        };
        assert!(resolve_context_window(&body, &kimi).is_err());
    }
}
