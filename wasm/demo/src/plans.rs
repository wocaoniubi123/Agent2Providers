//! 签到（native `checkin`）。
//!
//! ── 六种 outcome 各自对应什么处置（协议里定的，按本项目的语义读）──
//!   * `claimed`：刚签到成功，今天的记录写成「已领」；
//!   * `done`：今天已经签过了，同样记为「已领」，不再重试；
//!   * `ineligible`：这个账号不参与（访客、未验证邮箱），记为「不适用」；
//!   * `inactive`：当前没有可领的活动，记为「今日无活动」；
//!   * `captcha`：上游要验证码 —— 示例永远不去解，提示用户去官方 App；
//!   * `failed`：真失败，按重试策略再来。
//!
//! ── 示例为什么直接用 `claimed` ──────────────────────────────
//! native 的 `checkin()` 返回 `CheckinOutcome::Claimed` + 一条积分文案 +
//! `streak: 3`，用来演示「领到了什么」这一栏怎么填。真实 provider 要发请求、
//! 判「今天签过没有」、把上游的业务码翻成上面六档之一。
//!
//! ── 一个 wasm 侧的额外字段（本家没有用到）────────────────────
//! 网关会从签到返回值里读 `until`（活动截止时间）与 `details` / `catalog`
//! （`rpc.rs:1854-1861`）；本家不产生这些，所以这里只有协议规定的四个字段。

use agent2api_wasm_sdk::{json, Value};

/// `checkin.claim`：返回 `CheckinReport`（`outcome` 是 snake_case）。
pub fn claim() -> Value {
    json!({
        "outcome": "claimed",
        "credit": "+10 credits",
        "streak": 3,
        // `message` 是「给用户看的一句话」；领到了就留空。
        "message": Value::Null,
    })
}
