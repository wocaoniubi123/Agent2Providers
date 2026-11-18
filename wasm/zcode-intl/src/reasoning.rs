//! GLM 家族的**思考等级契约**（native `zcode/reasoning.rs` 的移植）。
//!
//! ── 为什么这家需要一份专门的契约 ────────────────────────────
//! GLM-5.3 / GLM-5.3-Flash 是**始终思考**的模型：关不掉。实测（2026-09-30，
//! 编码套餐端点）三种「关思考」的写法全部被上游拒掉：
//!
//! ```text
//!   thinking:{"type":"disabled"}   → 400 code 1210
//!   reasoning_effort:"none"        → 400 code 1210
//!   reasoning_effort:"minimal"     → 400 code 1210
//!   上游原文：该模型始终思考，不支持关闭思考；请使用 low、high 或 max。
//! ```
//!
//! 于是存在一个静默的失败形态：思考与正文**共用** `max_tokens` 这一个额度
//! （实测 `max_tokens=16` 时全被 `reasoning_content` 吃掉、`content` 是空串，
//! 而 HTTP 仍是 200、`finish_reason` 是 `length`）。官方客户端的做法是
//! **`max_tokens` 把思考预算加在上面**（`max_tokens += budget`，再按模型的
//! `maxOutputTokens` 截顶）—— 本模块照此实现（[`apply_to_anthropic`]）。
//!
//! ── 预算契约只对 5.3 家族生效 ───────────────────────────────
//! 预算数字（8000 / 16000 / 32000）来自官方目录 `agent/configs` 的
//! `builtinModels[].reasoning.levels`，**只有 GLM-5.3 与 GLM-5.3-Flash 有
//! 目录与实测依据**。glm-5 / 5.1 / 4.x 的档位表没有证据，因此原样走通用路径
//! —— 猜错的代价是给上游发一个它不认的预算。
//!
//! ── GLM-5.2：只归一、不做预算 ───────────────────────────────
//! 5.2 的依据是智谱开放文档「深度思考」页：`reasoning_effort` 对它接受
//! `none` / `minimal`（放弃思考）、`low` / `medium`（映射为 `high`）、`high`、
//! `xhigh`（映射为 `max`）、`max`（默认）。上游既然自己就会折出这套目标值，
//! 这里把它**提前到网关执行**（[`normalize_glm52`]），发出去的字节因此与日志
//! 里的等级一致。**但预算装配不适用于它**：5.2 可关思考、默认自适应，给它加
//! 预算没有实测依据。

use agent2api_wasm_sdk::{json, Value};

use super::common::string_field;

/// 思考等级在请求体里的**唯一**字段名。
///
/// 两条通道都认它：编码套餐通道由 [`apply_to_chat`] 原样归一后发上游；
/// 套餐池通道由 `plan` 从同一处读出来交给 [`apply_to_anthropic`] 折成
/// thinking 预算 + `output_config.effort`。映射绑定的默认档
/// （`reasoning_patch`）也写这个键 —— 三处读写同一个字面量。
pub const EFFORT_FIELD: &str = "reasoning_effort";

/// 可以翻译给上游的正向档位（不含 `off` / `none`，顺序 = 强弱顺序）。
pub const EFFORT_LEVELS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max"];

/// 正向档位 → 序号（0 = 最弱，5 = 最强）。`off` / `none` / 表外值一律 None。
pub fn effort_rank(level: &str) -> Option<usize> {
    let trimmed = level.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 32 {
        return None;
    }
    EFFORT_LEVELS
        .iter()
        .position(|known| trimmed.eq_ignore_ascii_case(known))
}

/// 合法思考等级（上游文档化的三档：low / high / max）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Low,
    High,
    Max,
}

impl Level {
    /// 发上游的等级字面量（同名的两个协议字段都用它）
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::Max => "max",
        }
    }

    /// 官方目录给这一档配的思考预算（`thinking.budget_tokens`）
    fn budget(self) -> i64 {
        match self {
            Self::Low => 8_000,
            Self::High => 16_000,
            Self::Max => 32_000,
        }
    }
}

/// 「短输出请求」的判据：客户端给的 `max_tokens` 低于它就按短输出处理。
///
/// 依据是实测的失败面：标题生成 / 摘要 / 单行补全这类请求要的正文极短，而
/// 思考一开就是几千 token —— 官方默认档（max = 32000）会把它们从「立刻返回」
/// 拖成「先思考三万个 token」。1024 是 Anthropic SDK 自己的思考预算地板值，
/// 也正好是「短输出」与「正常对话」的分界。
const SHORT_OUTPUT_TOKENS: i64 = 1024;

/// 短输出请求用的思考预算：SDK 地板值。
///
/// 实测该组合（low + 1024）下模型连思考块都不出、直接给正文
/// （"Reply with exactly: OK" 只花 3 个输出 token）—— 既满足「必须思考」
/// 的上游约束，又没有把额度浪费在思考上。
const FLOOR_BUDGET: i64 = 1_024;

/// 本模型是否属于某个 GLM 家族（`needle` 形如 `glm-5.3`，大小写不敏感）。
///
/// 尾随数字要排除（`glm-5.30` 不算 5.3 家族、`glm-5.25` 不算 5.2 家族）——
/// 参考实现用正则的负向前瞻表达这件事，Rust 的 `regex` 不支持前瞻，所以这里
/// 手写扫描。
fn is_family(model: &str, needle: &str) -> bool {
    let lower = model.trim().to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower.get(from..).and_then(|rest| rest.find(needle)) {
        let end = from + at + needle.len();
        let next_is_digit = lower
            .get(end..)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|next| next.is_ascii_digit());
        if !next_is_digit {
            return true;
        }
        from = end;
    }
    false
}

/// 本模型是否属于 GLM-5.3 家族（`glm-5.3` / `glm-5.3-flash`）。
pub fn is_glm53(model: &str) -> bool {
    is_family(model, "glm-5.3")
}

/// 本模型是否属于 GLM-5.2 家族。
pub fn is_glm52(model: &str) -> bool {
    is_family(model, "glm-5.2")
}

/// 客户端给的等级字面量 → 三档。`None` = 客户端没点名（空串与缺省同义）。
///
/// 映射表照抄参考实现的 `normalizeGlm53Effort`，包括三个刻意的取值：
///   · `none` / `minimal` 归到 `low` —— 上游不接受「不思考」，所以「尽量少想」
///     是这些取值唯一能落到的档位（直接透传会被 400 code 1210 拒掉）；
///   · `medium` 归到 `high`（**向上取整**，不是就近）；
///   · 认不出的取值给 `max`（官方目录的 `defaultLevel`），与「没点名」同档。
pub fn normalize(effort: Option<&str>) -> Option<Level> {
    let raw = effort.map(str::trim).filter(|text| !text.is_empty())?;
    Some(match raw.to_ascii_lowercase().as_str() {
        "none" | "minimal" | "light" | "low" => Level::Low,
        "medium" | "high" => Level::High,
        "xhigh" | "max" | "ultra" => Level::Max,
        _ => Level::Max,
    })
}

/// GLM-5.2 的等级归一（把上游的兼容映射提前到网关执行，见模块头）。
pub fn normalize_glm52(effort: Option<&str>) -> Option<&'static str> {
    let raw = effort.map(str::trim).filter(|text| !text.is_empty())?;
    Some(match raw.to_ascii_lowercase().as_str() {
        "off" | "none" | "minimal" => "minimal",
        "light" | "low" | "medium" | "high" => "high",
        "xhigh" | "max" | "ultra" => "max",
        _ => "max",
    })
}

/// 某模型下，等级字面量 → 发上游的目标档位字面量。
///
/// 非受管家族返回 `None`（调用方保持原样）：5.1 / 5 / 4.x 与两档视觉模型的
/// 档位表没有依据。三个消费方（`reasoning_patch` / `apply_to_chat` /
/// `apply_to_anthropic`）共用它，绑定注入与发送口径因此永远一致。
pub fn target_effort(model: &str, effort: Option<&str>) -> Option<&'static str> {
    if is_glm53(model) {
        normalize(effort).map(Level::as_str)
    } else if is_glm52(model) {
        normalize_glm52(effort)
    } else {
        None
    }
}

/// 定档：客户端点名优先，没点名时按输出额度推。
fn resolve(effort: Option<&str>, client_max_tokens: Option<i64>) -> (Level, i64) {
    if let Some(level) = normalize(effort) {
        return (level, level.budget());
    }
    match client_max_tokens {
        Some(value) if value < SHORT_OUTPUT_TOKENS => (Level::Low, FLOOR_BUDGET),
        // 没点名又不像短输出：按官方目录默认档（max）。
        _ => (Level::Max, Level::Max.budget()),
    }
}

/// 套餐池通道（Anthropic 协议）的思考装配。
///
/// 三件事一起做，缺一不可：
///   1. `thinking: {type:"enabled", budget_tokens}` —— 单给 `output_config.effort`
///      是无效的（实测：只发 effort 时上游照旧把额度耗在思考上、正文为空）；
///   2. `output_config: {effort}` —— 预算要与等级配对，只给预算会让上游落回
///      它自己的低默认；
///   3. `max_tokens = 客户端额度 + 预算`（按模型 `maxOutputTokens` 截顶）——
///      这一步是留出正文空间的关键，也是官方客户端的做法。
///
/// 开启思考时 `temperature` / `top_p` / `top_k` 一律删掉：上游拒绝采样参数与
/// 扩展思考并存（通用转换层已按同一口径处理过，这里再守一次是因为**本次**
/// 才真正决定要开思考 —— 客户端没点名等级时通用层什么都没注入）。
///
/// `client_max_tokens` 取**客户端原始请求**里的值（不是转换后的 payload：
/// 通用层可能已经按它自己的档位表抬过一次，那份额度不能当客户端的意图用）。
pub fn apply_to_anthropic(
    payload: &mut Value,
    model: &str,
    effort: Option<&str>,
    client_max_tokens: Option<i64>,
) {
    if !is_glm53(model) {
        return;
    }
    let (level, budget) = resolve(effort, client_max_tokens);
    // 额度基数：客户端给了就用它的，没给就用转换层已经填好的默认值
    // （Anthropic 协议必填 `max_tokens`，通用层填的是 DEFAULT_MAX_TOKENS）。
    let base = client_max_tokens
        .or_else(|| payload.get("max_tokens").and_then(Value::as_i64))
        .filter(|value| *value > 0)
        .unwrap_or(FLOOR_BUDGET);
    let ceiling = super::models::max_output(model).unwrap_or(base.saturating_add(budget));
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert(
        "thinking".to_string(),
        json!({ "type": "enabled", "budget_tokens": budget }),
    );
    object.insert(
        "output_config".to_string(),
        json!({ "effort": level.as_str() }),
    );
    for key in ["temperature", "top_p", "top_k"] {
        object.remove(key);
    }
    let total = base.saturating_add(budget).min(ceiling);
    object.insert("max_tokens".to_string(), Value::from(total));
}

/// 编码套餐通道（OpenAI 协议）的思考装配：只把等级归一化后注入。
///
/// 这条通道**不能**做「预算相加」：OpenAI 体里没有 budget 概念，
/// `reasoning_effort` 是唯一的旋钮（实测有效：同一条 prompt 下 `low` 只用 3 个
/// 思考 token，`max` 用 199 个）。同一条实测也给出了小额度场景的出路 —— 把等级
/// 压到 `low` 之后，16 个 token 的额度里也留得住正文，所以这里对「短输出且
/// 客户端没点名」的情形注 `low`。
///
/// 体里点名了就用它的档位；没点名又不像短输出则**不注入**（保持上游默认，
/// 实测约 100 个思考 token，属于正常量级）。
///
/// ── 5.2 与 5.3 的两点差别 ────────────────────────────────────
///   · 归一表不同：5.2 可关思考（`none` / `minimal` 落 `minimal`），5.3 只能落
///     `low`；
///   · **不做短输出注入**：5.2 可关、默认自适应，替它注一个默认档等于替用户
///     做决定 —— 没有实测依据的不做。
pub fn apply_to_chat(body: &mut Value, model: &str) {
    let is_53 = is_glm53(model);
    if !is_53 && !is_glm52(model) {
        return;
    }
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let effort = object
        .get(EFFORT_FIELD)
        .and_then(Value::as_str)
        .map(str::to_string);
    let target: Option<String> = if is_53 {
        let client_max = object
            .get("max_tokens")
            .or_else(|| object.get("max_completion_tokens"))
            .and_then(Value::as_i64)
            .filter(|value| *value > 0);
        match normalize(effort.as_deref()) {
            Some(level) => Some(level.as_str().to_string()),
            None if client_max.is_some_and(|value| value < SHORT_OUTPUT_TOKENS) => {
                Some(Level::Low.as_str().to_string())
            }
            None => None,
        }
    } else {
        normalize_glm52(effort.as_deref()).map(str::to_string)
    };
    if let Some(level) = target {
        object.insert(EFFORT_FIELD.to_string(), Value::String(level));
    }
}

/// 客户端请求体里是否已指定思考参数（`reasoning_effort` 或在场的 `thinking`）。
///
/// 判据是「键**在场**」而不是「值有效」：`apply_to_chat` 对认不出的值会按官方
/// 默认档发 `max`，此时再注映射上的绑定档会把用户的取值**悄悄换成另一个档位**，
/// 而请求照样成功、用户看不出区别。
fn client_specified(body: &Value) -> bool {
    if body.get(EFFORT_FIELD).is_some() {
        return true;
    }
    body.pointer("/thinking/type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("disabled"))
}

/// `reasoning_patch` 方法的实现（native `Provider::reasoning_patch` 的直译）。
///
/// 只接 GLM-5.2 / 5.3 家族：有依据的只有这两个家族，别的模型一律 Skip ——
/// 通用 8 档表里没有「它们也收这个字段」的证据，塞一个上游不认识的键不叫
/// 生效，只是把未知参数推给上游。
pub fn patch(params: &Value) -> Value {
    let level = params["level"].as_str().unwrap_or("").to_string();
    let model = string_field(&params["model"], "id");
    let model = if model.is_empty() {
        params["model"].as_str().unwrap_or("").to_string()
    } else {
        model
    };
    let body = &params["body"];
    if client_specified(body) {
        return json!({
            "action": "skip",
            "reason": "客户端请求体里已指定思考参数，绑定不覆盖",
        });
    }
    if !is_glm53(&model) && !is_glm52(&model) {
        return json!({
            "action": "skip",
            "reason": "该模型没有已确认的 ZCode 思考档位（目前只有 GLM-5.2 / 5.3 家族）",
        });
    }
    // 表外等级（界面的「自定义输入」）不注入：上游收不收没有证据。
    if effort_rank(&level).is_none() {
        return json!({
            "action": "skip",
            "reason": "该等级不在通用档位表内（自定义等级不参与转发）",
        });
    }
    match target_effort(&model, Some(&level)) {
        Some(value) => json!({ "action": "set", "field": EFFORT_FIELD, "value": value }),
        None => json!({
            "action": "skip",
            "reason": "该等级没有可翻译的 ZCode 目标值",
        }),
    }
}
