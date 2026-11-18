//! ZCode 的模型清单（**静态表**；native `zcode/models.rs` 的移植）。
//!
//! ── 为什么是静态表而不是远程目录 ────────────────────────────
//! 上游没有「列模型」的公开接口：编码套餐的可用模型由客户端内置目录决定。
//! 因此本模块不提供 `refresh`：`model_refresh: false`（见 `metadata.json`），
//! 界面不渲染「刷新模型清单」按钮 —— 假装刷了一次比不刷更糟。
//!
//! ── 只声明**有据可依**的键 ──────────────────────────────────
//! 出口只留两类：
//!   · **协议级事实**：`supportsToolCall`（编码套餐的客户端本身就是靠工具调用
//!     跑 agent 循环）；两档视觉模型的 `supportsReasoning: false`（目录里明确
//!     写着它们不支持思考）；
//!   · `EXTRAS` 里有注记的项（5.3 家族的档位来自官方目录、5.2 来自智谱公开
//!     文档、视频位逐条注明是否有依据）。
//! 上下限与图片能力一律不在这里声明：原先转录自参考实现的那批值已被证伪
//! （`glm-5.1` 的输出上限、`glm-5` 的窗口都对不上），**没有依据的声明比空着
//! 更糟** —— 下游会照它构造请求（按虚高的窗口堆历史）或据此拒绝能力。
//!
//! `max_output` 仍是本家思考预算截顶的**内部**上限（见 `reasoning`），不出口。

use agent2api_wasm_sdk::{json, Value};

/// 一个模型的静态规格。
struct Spec {
    /// 上游模型 id（**原样转发**，不做任何改名）
    id: &'static str,
    /// 展示名
    name: &'static str,
    /// 最大输出（内部用：思考预算截顶的上限，不直接出口）
    max_output: i64,
    /// 是否把「支持思考」声明给下游。`None` = 不声明。
    reasoning: Option<bool>,
}

/// 编码套餐的模型表（顺序 = 展示顺序：能力由强到弱、同代相邻）。
const MODELS: &[Spec] = &[
    Spec { id: "glm-5.3", name: "GLM-5.3", max_output: 128_000, reasoning: None },
    // `glm-5.3-flash` 的视觉位由目录给出（`capabilities.vision` 与实测一致：
    // 2026-09-30 发一张红色 4×4 PNG 它答「红色」；同一张图打 `glm-5.3` 被 400
    // 拒掉，原文是「messages.content.type 参数非法，取值范围 ['text']」）。
    Spec { id: "glm-5.3-flash", name: "GLM-5.3 Flash", max_output: 128_000, reasoning: None },
    Spec { id: "glm-5.2", name: "GLM-5.2", max_output: 128_000, reasoning: None },
    Spec { id: "glm-5.1", name: "GLM-5.1", max_output: 64_000, reasoning: None },
    Spec { id: "glm-5", name: "GLM-5", max_output: 64_000, reasoning: None },
    Spec { id: "glm-5-turbo", name: "GLM-5 Turbo", max_output: 64_000, reasoning: None },
    Spec { id: "glm-4.7", name: "GLM-4.7", max_output: 131_072, reasoning: None },
    Spec { id: "glm-4.6", name: "GLM-4.6", max_output: 131_072, reasoning: None },
    Spec { id: "glm-4.5-air", name: "GLM-4.5 Air", max_output: 98_304, reasoning: None },
    // 视觉两档**反对**思考：目录里明确写着它们不支持思考，且标错的方向是不
    // 对称的 —— 声明成 true 会让客户端按「支持思考」去发 thinking（上游直接
    // 400），声明成 false 只是让客户端不启用思考。
    Spec { id: "glm-4.6v", name: "GLM-4.6V", max_output: 32_768, reasoning: Some(false) },
    Spec { id: "glm-5v-turbo", name: "GLM-5V Turbo", max_output: 131_072, reasoning: Some(false) },
];

/// 一个模型的目录补充信息。
struct Extra {
    /// 上游模型 id（与 `Spec::id` 同一口径：小写）
    id: &'static str,
    /// 视频输入。`None` = 未声明（出口不出这个键）
    video: Option<bool>,
    /// 可配的思考档位（出口为 `reasoningLevels`；空 = 未声明）
    levels: &'static [&'static str],
    /// 默认思考档位
    default_level: &'static str,
}

/// 目录补充信息表：只有**有依据的家族**才在表里。
///
///   · 5.3：目录给每个档位写「往 `output_config.effort` 塞什么值」，
///     三个档位各一条（`low` / `high` / `max`），默认 `max`；
///   · 5.2：智谱开放文档的兼容映射（`minimal` 放弃思考、`low` / `medium` →
///     `high`、`xhigh` → `max`、默认 `max`），能落到的集合是
///     `minimal` / `high` / `max`。
const EXTRAS: &[Extra] = &[
    Extra { id: "glm-5.3", video: Some(false), levels: &["low", "high", "max"], default_level: "max" },
    Extra { id: "glm-5.3-flash", video: Some(true), levels: &["low", "high", "max"], default_level: "max" },
    // 5.2 的视频输入能力没有依据（目录里没有它的条目），如实不出 supportsVideo
    Extra { id: "glm-5.2", video: None, levels: &["minimal", "high", "max"], default_level: "max" },
];

/// 按 id 找规格（大小写不敏感；本文件唯一的比较口径）。
fn find(model: &str) -> Option<&'static Spec> {
    let needle = model.trim().to_ascii_lowercase();
    MODELS.iter().find(|spec| spec.id == needle)
}

/// 模型的最大输出额度（思考预算相加后的**截顶**用）。
///
/// `None` = 不认识这个模型 —— 调用方据此放弃截顶，而不是拿一个假上限去截。
pub fn max_output(model: &str) -> Option<i64> {
    find(model).map(|spec| spec.max_output)
}

/// 本家的模型清单（聚合目录认的形态）。
pub fn list() -> Value {
    let rows: Vec<Value> = MODELS
        .iter()
        .map(|spec| {
            let mut item = json!({
                "id": spec.id,
                "name": spec.name,
                "supportsToolCall": true,
            });
            if let Some(reasoning) = spec.reasoning {
                item["supportsReasoning"] = Value::Bool(reasoning);
            }
            if let Some(extra) = EXTRAS.iter().find(|extra| extra.id == spec.id) {
                if let Some(video) = extra.video {
                    item["supportsVideo"] = Value::Bool(video);
                }
                if !extra.levels.is_empty() {
                    item["reasoningLevels"] = Value::Array(
                        extra
                            .levels
                            .iter()
                            .map(|level| Value::String((*level).to_string()))
                            .collect(),
                    );
                    item["reasoningDefaultLevel"] = Value::String(extra.default_level.to_string());
                }
            }
            item
        })
        .collect();
    // 静态表：`meta.remote` 恒 false（界面据此不显示「远程刷新」的说明）
    json!({
        "models": rows,
        "meta": { "remote": false, "refreshed_at": 0 },
    })
}

/// 名称匹配（`wire_id` 用：客户端可能拿展示名当模型名）。
pub fn wire_id(requested: &str) -> String {
    let name = requested.trim();
    MODELS
        .iter()
        .find(|spec| spec.id.eq_ignore_ascii_case(name) || spec.name.eq_ignore_ascii_case(name))
        .map(|spec| spec.id.to_string())
        .unwrap_or_else(|| name.to_string())
}
