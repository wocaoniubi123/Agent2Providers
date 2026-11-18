//! 2026-11-01 的认证 model_catalog 快照；远程目录始终优先。
//!
//! ── 为什么要留一份静态兜底 ──────────────────────────────────
//! 目录接口需要登录与组织身份。冷启动（刚装插件、还没刷新过目录、或上游该
//! 接口临时 5xx）时没有远程清单可读，界面不能是空的 —— 这份表就是那时的答案。
//! 数值取自当时的认证目录响应，**只做展示与路由**：真正的价格与权益以远程
//! 目录为准。

use agent2api_wasm_sdk::{json, Value};

/// 静态兜底清单（`(id, 展示名, 上下文, 输出上限, 是否支持图片, 倍率, 能力级)`）。
pub fn models() -> Vec<Value> {
    let mut models: Vec<Value> = [
        (
            "raccoon-8c4485",
            "Raccoon-Work",
            1_000_000,
            100_000,
            true,
            1.0,
            3,
        ),
        (
            "raccoon-19b265",
            "Raccoon-Work-260817-A",
            1_000_000,
            100_000,
            false,
            1.0,
            3,
        ),
        (
            "raccoon-405a1c",
            "Raccoon-Work-260817-B",
            1_000_000,
            100_000,
            false,
            1.0,
            2,
        ),
        (
            "sn-sensenova-6-8-flash",
            "SenseNova-6.8-Flash",
            256_000,
            63_999,
            true,
            0.5,
            1,
        ),
        (
            "sn-sensenova-6-8-flash-lite",
            "SenseNova-6.8-Flash-Lite",
            256_000,
            63_999,
            true,
            0.5,
            1,
        ),
        ("sn-glm-5-3", "GLM-5-3", 1_000_000, 100_000, false, 0.75, 2),
        ("sn-kimi-k3", "Kimi-K3", 1_000_000, 100_000, true, 1.0, 2),
        (
            "sn-glm-5-3-flash",
            "GLM-5-3-Flash",
            1_000_000,
            100_000,
            true,
            0.2,
            2,
        ),
        (
            "sn-deepseek-v4-1-flash-1017",
            "DeepSeek-V4.1-Flash-1017",
            1_000_000,
            100_000,
            true,
            0.25,
            3,
        ),
    ]
    .into_iter()
    .map(
        |(id, display, context, output, vision, multiplier, ability)| {
            json!({
                "name": id,
                "displayName": display,
                "description": "",
                "contextWindow": context,
                "maxTokens": output,
                "supportImage": vision,
                "supportThinking": super::reasoning::supported(id),
                "abilityLevel": ability,
                "visible": !id.starts_with("raccoon-"),
                "visibility": if id.starts_with("raccoon-") { "hidden" } else { "shown" },
                "credits": format!("x{multiplier} credits"),
            })
        },
    )
    .collect();
    // 默认模型不在表里时补一条（只有名字与思考支持是已知的，其余留空 ——
    // 与 native 一样不给虚构的上下文窗口）。
    let default = super::upstream::default_model();
    if !models
        .iter()
        .any(|model| model.get("name").and_then(Value::as_str) == Some(default.as_str()))
    {
        models.push(json!({
            "name": default,
            "displayName": "Raccoon Custom Default",
            "supportThinking": super::reasoning::supported(&default),
        }));
    }
    models
}
