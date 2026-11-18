//! 图片生成 / 参考图编辑：native 有，这套 wasm ABI 没有对应的调用方法。
//!
//! ── native 侧是什么 ─────────────────────────────────────────
//! `image_generation.rs` 通过 trait 上的 `build_image` / `build_image_edit`
//! 交回一个 `ImagePlan`（JSON 打 `/images/gen`、multipart 打 `/images/edits`），
//! 并在 `models.rs` 的清单末尾补一条 `raccoon-image`。
//!
//! ── 为什么 wasm 侧没实现 ────────────────────────────────────
//! wasm ABI 的方法表里**没有**图片方法：`chat` / `conversation` / `token.*` /
//! `models.*` / `usage.query` / `checkin.claim` / `login.*` / `admin.action` …
//! 逐条读过，既没有 `images.generate` 也没有 `images.capabilities` 之外的东西
//! （atomcode 的 wasm 提供方也只申报了 `images.capabilities = {false, false}`）。
//! 插件无法凭空发明一个方法名 —— 名字对不上，宿主永远不会调用它。
//!
//! 所以这里只留两件事：
//!   ① `capabilities()` —— 如实申报「这家在 wasm 侧不提供图片」；
//!   ② `unsupported()` —— 若客户端仍然点名 `raccoon-image` 发对话请求，
//!      在**进上游之前**给出可读的中文错误，而不是让上游回一个看不懂的 400。
//!
//! 清单里因此也不再挂 `raccoon-image`：一个发不出去的模型比一个不存在的模型
//! 更难排查。等 ABI 补上图片方法，把 native 的两个构造函数搬过来即可。

use agent2api_wasm_sdk::{json, Error, Value};

/// native 侧的图片模型 id（`image_generation::MODEL_ID`）。
pub const MODEL_ID: &str = "raccoon-image";

/// 图片能力申报。
///
/// 与 atomcode 的 wasm 提供方同一形状：`{generation, editing}`。
/// 两个都报 false —— 只申报真的实现了的能力。
pub fn capabilities() -> Value {
    json!({ "generation": false, "editing": false })
}

/// 点名图片模型时的可读错误（`None` = 不是图片模型，照常转发）。
pub fn unsupported(model: &str) -> Option<Error> {
    if model.trim().eq_ignore_ascii_case(MODEL_ID) {
        Some(Error::http(
            400,
            "Wasm 版小浣熊插件暂不提供图片生成 / 参考图编辑（这套 ABI 还没有图片方法）。\
请在网关里改用 native 插件，或等插件补上该能力",
        ))
    } else {
        None
    }
}
