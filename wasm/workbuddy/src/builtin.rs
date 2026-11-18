//! WorkBuddy 的内置模型清单与准入过滤（从网关 `core::models` 搬来）。
//!
//! ── 内置清单什么时候被用到 ──────────────────────────────────
//! 只有「还没成功刷过 `/v3/config`」时才用：插件刚装上、或上游一直取不到。
//! 网关那份目录以它作为初始态，插件侧同样 —— 否则第一次远程刷新之前
//! `/v1/models` 是空的，客户端会以为这家没有模型。
//!
//! ── 准入过滤（`is_chat_model`）为什么在插件里 ────────────────
//! `/v3/config` 会下发补全 / 改写 / 内部工具 / 图像 / 视频 / 旧代条目，
//! **本文件只挑对话模型**。这套判据（九个排除前缀 + `supportsExtra` 真值 +
//! `maxOutputTokens >= 16000`）是**这一家上游的形态知识**，因此跟着 provider 走。
//!
//! ── 图像条目不在这里（本包的已知差异）───────────────────────
//! native 的 `builtin_filtered()` 尾部还会挂上图像模型的内置兜底，并让
//! `/v3/config` 里带 `text-to-image` / `image-to-image` 标签的条目走图片通道。
//! 本包**没有实现** `images.generate` / `images.edit`（wasm 侧那对方法的请求与
//! 回包契约在本仓库里没有可核对的实现，见 `lib.rs` 的 `images.capabilities`），
//! 所以图像条目既不进目录、也不申报能力 —— 宁可让界面看不见，也不给一个点了
//! 必然失败的入口。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Value};

/// 非对话模型的排除前缀（网关 `CHAT_MODEL_EXCLUDE_PREFIXES` 的逐字副本）。
///
/// `default-1.` 会把内置清单里的 `default-1.1` / `default-1.2` 一起排除 ——
/// 这是 Node 版的既有行为（那两个是 Claude 的内部 id），移植时保持一致。
const CHAT_MODEL_EXCLUDE_PREFIXES: &[&str] = &[
    "completion-",
    "codewise-",
    "hunyuan-image",
    "hunyuan-3b",
    "hunyuan-7b",
    "deepseek-r1-0528",
    "deepseek-v3-0324",
    "kimi-k2-instruct",
    "default-1.",
];

/// 下游可见模型白名单：空数组 = 不限制，全量放行。
pub const MODEL_ALLOWLIST: &[&str] = &[];

/// JS `String(x)`（`id` 这类字段的容错文本化）。
pub fn value_text(value: &Value) -> String {
    crate::util::string_value(value)
}

/// 对话模型判定：网关只服务对话模型，非对话项不进目录。
pub fn is_chat_model(model: &Value) -> bool {
    let id = model.get("id").map(value_text).unwrap_or_default();
    if CHAT_MODEL_EXCLUDE_PREFIXES
        .iter()
        .any(|prefix| id.starts_with(prefix))
    {
        return false;
    }
    if model.get("supportsExtra").map(crate::util::js_truthy).unwrap_or(false) {
        return false;
    }
    let Some(max_output) = model.get("maxOutputTokens").and_then(Value::as_f64) else {
        return false;
    };
    max_output >= 16_000.0
}

/// 目录准入过滤：对话模型判定 + 白名单（空白名单全量放行）。
pub fn apply_filters(models: Vec<Value>) -> Vec<Value> {
    models
        .into_iter()
        .filter(is_chat_model)
        .filter(|model| {
            if MODEL_ALLOWLIST.is_empty() {
                return true;
            }
            let id = model.get("id").map(value_text).unwrap_or_default();
            MODEL_ALLOWLIST.contains(&id.as_str())
        })
        .collect()
}

/// 内置模型目录（id → 元数据），逐字段照抄网关 `builtin_models()`。
///
/// `credits` 字段为桌面端展示的单价，仅作参考。
pub fn builtin_models() -> Vec<Value> {
    json!([
        { "id": "auto", "name": "Auto", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 168000, "supportsToolCall": true, "supportsImages": true, "isDefault": true, "descriptionZh": "平衡效果与速度" },
        { "id": "default", "name": "Default", "vendor": "v", "credits": "x2.00 credits", "maxOutputTokens": 24000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": false },

        { "id": "deepseek-v4-pro", "name": "Deepseek-V4-Pro", "vendor": "f", "credits": "x0.16 credits", "maxOutputTokens": 50000, "maxInputTokens": 1000000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true, "descriptionZh": "DeepSeek 旗舰模型，支持 1M 上下文窗口" },
        { "id": "deepseek-v4-flash", "name": "Deepseek-V4-Flash", "vendor": "f", "credits": "x0.06 credits", "maxOutputTokens": 50000, "maxInputTokens": 1000000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true, "descriptionZh": "DeepSeek 旗舰模型，支持 1M 上下文窗口" },
        { "id": "deepseek-v4.1-flash", "name": "Deepseek-V4.1-Flash", "vendor": "f", "credits": "x0.03 credits", "maxOutputTokens": 50000, "maxInputTokens": 1000000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true, "descriptionZh": "DeepSeek 快速模型，支持 1M 上下文窗口" },
        { "id": "deepseek-v3-2-volc", "name": "DeepSeek-V3.2", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 96000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },

        { "id": "glm-5.1", "name": "GLM-5.1", "vendor": "e", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "glm-5.0", "name": "GLM-5.0", "vendor": "f", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "glm-5.0-turbo", "name": "GLM-5.0-Turbo", "vendor": "e", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "glm-5v-turbo", "name": "GLM-5v-Turbo", "vendor": "e", "credits": "", "maxOutputTokens": 38000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "glm-4.7", "name": "GLM-4.7", "vendor": "f", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "glm-4.6", "name": "GLM-4.6", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 168000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true },
        { "id": "glm-4.6v", "name": "GLM-4.6V", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 128000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },

        { "id": "minimax-m2.5", "name": "MiniMax-M2.5", "vendor": "f", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "minimax-m2.7", "name": "MiniMax-M2.7", "vendor": "f", "credits": "", "maxOutputTokens": 48000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "minimax-m3-play", "name": "MiniMax-M3", "vendor": "f", "credits": "x0.25 credits", "maxOutputTokens": 48000, "maxInputTokens": 512000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true, "descriptionZh": "原生多模态，擅长代码、智能体任务" },

        { "id": "kimi-k2.6", "name": "Kimi-K2.6", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 256000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "kimi-k2.5", "name": "Kimi-K2.5", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 256000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "kimi-k2-thinking", "name": "Kimi-K2-Thinking", "vendor": "f", "credits": "", "maxOutputTokens": 32000, "maxInputTokens": 256000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "kimi-k2-instruct-taiji", "name": "Kimi-K2", "vendor": "f", "credits": "", "maxOutputTokens": 8192, "maxInputTokens": 31000, "supportsToolCall": true, "supportsImages": true },

        { "id": "hy3-preview", "name": "Hy3 preview", "vendor": "j", "credits": "", "maxOutputTokens": 64000, "maxInputTokens": 192000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "hy3-preview-agent", "name": "Hy3 preview", "vendor": "j", "credits": "x0.04 credits", "maxOutputTokens": 64000, "maxInputTokens": 192000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "hunyuan-chat", "name": "Hunyuan-Turbos", "vendor": "j", "credits": "", "maxOutputTokens": 8192, "maxInputTokens": 128000, "supportsToolCall": true, "supportsImages": true, "descriptionZh": "腾讯自研的轻量、快速的通用模型" },
        { "id": "hunyuan-2.0-instruct", "name": "Hunyuan-2.0-Instruct", "vendor": "j", "credits": "", "maxOutputTokens": 16000, "maxInputTokens": 128000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "hunyuan-2.0-thinking", "name": "Hunyuan-2.0-Thinking", "vendor": "e", "credits": "", "maxOutputTokens": 24000, "maxInputTokens": 128000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },

        { "id": "default-1.1", "name": "Claude-3.7-Sonnet", "vendor": "e", "credits": "", "maxOutputTokens": 8192, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true },
        { "id": "default-1.2", "name": "Claude-4.0-Sonnet", "vendor": "e", "credits": "", "maxOutputTokens": 24000, "maxInputTokens": 200000, "supportsToolCall": true, "supportsImages": true, "supportsReasoning": true, "onlyReasoning": true }
    ])
    .as_array()
    .cloned()
    .unwrap_or_default()
}

/// 内置清单经准入过滤（网关 `initial_state` 的兜底分支）。
pub fn builtin_filtered() -> Vec<Value> {
    apply_filters(builtin_models())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_drop_non_chat_entries() {
        let models = builtin_filtered();
        let ids: Vec<&str> = models.iter().filter_map(|m| m["id"].as_str()).collect();
        // 默认两个都在
        assert!(ids.contains(&"auto"));
        assert!(ids.contains(&"deepseek-v4-pro"));
        // Claude 内部 id 被 `default-1.` 前缀排除
        assert!(!ids.contains(&"default-1.1"));
        // 输出上限不足 16000 的被排除
        assert!(!ids.contains(&"kimi-k2-instruct-taiji"));
    }

    #[test]
    fn supports_extra_is_truthy_by_js_rules() {
        // JS 真值：0 / false / "" 为假（仍算对话模型），非空串为真（排除）
        assert!(is_chat_model(&json!({ "id": "x", "maxOutputTokens": 20000, "supportsExtra": 0 })));
        assert!(!is_chat_model(&json!({ "id": "x", "maxOutputTokens": 20000, "supportsExtra": "no" })));
        assert!(is_chat_model(&json!({ "id": "x", "maxOutputTokens": 20000, "supportsExtra": false })));
        // 缺字段 → 不排除
        assert!(is_chat_model(&json!({ "id": "x", "maxOutputTokens": 20000 })));
    }
}
