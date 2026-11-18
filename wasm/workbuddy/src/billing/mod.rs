//! WorkBuddy 的计费域：积分 / 额度查询、签到、运营活动。
//!
//! ── 这一层搬了什么（对照 native `billing/`）──────────────────
//! ```text
//!   usage.rs      积分查询与两种摊平形状（简报 / 逐份明细）—— 逐字保留
//!   ops.rs        签到状态 / 领取 / 一次性奖励 / banner / 大使 —— 逐字保留
//!   checkin.rs    国内版每日签到（协议层 `checkin.claim` 的执行体）
//!   commodity.rs  积分包商品码与套餐分类 —— 逐字保留
//!   tools.rs      JS 语义工具（Number() / parseTime / String(floor(n))）
//!   headers.rs    计费接口的头集合（与转发头**不同**）—— 逐字保留
//!   call.rs       一次计费调用（网关 call_billing 的插件侧等价物）
//!   resources.rs  积分包分页与企业额度
//! ```
//!
//! ── 输出形状为什么一字不改 ──────────────────────────────────
//! `{kind, unlimited, totalLeft, planLeft, bonusLeft}` 是账号页余额列的既有契约
//! （前端 `usageSummary` 与后端 `usage_records::extract_remaining` 都认
//! `totalLeft`）。把它包装成「统一钱包形状」会让那一格的显示退化。所以这里是
//! **加**不是换：五个既有键原样，另挂 `credits[]` 与 `subscription` 两项。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

pub mod call;
pub mod checkin;
pub mod commodity;
pub mod headers;
pub mod ops;
mod resources;
pub mod tools;
pub mod usage;

pub use usage::{credit_packs_from, credits_summary_from, query_usage, subscription_of};
