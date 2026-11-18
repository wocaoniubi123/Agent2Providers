//! 本包服务的**地区**：WorkBuddy 国际版（`workbuddy-intl`）。
//!
//! ── 为什么只剩一个取值 ──────────────────────────────────────
//! native 的 `region.rs` 是一个两值的 `enum Region { Cn, Intl }`：同一个 provider
//! 目录导出 `workbuddy` 与 `workbuddy-intl` 两个 id。本包只做**国际版** ——
//! 网关 `provenance.rs` 硬性要求 wasm 包的 `providers.len() == 1`，国内版由
//! **另一个包**（`wasm/workbuddy/`）负责。
//!
//! 于是这里保留的是「地区的**语义**」而不是那个枚举：provider id / 端点兜底 /
//! 客户端身份 / 版本 id 全都指向国际版。保留这层间接的好处在迁移期很实在 ——
//! 上层代码（`account` / `catalog` / `billing`）里 native 的
//! `Region::Intl.provider_id()` 这类调用点可以逐字保留。
//!
//! ── 国际版与国内版的差别（native `region.rs` 的全部差异）─────
//! ```text
//!   provider id   workbuddy-intl          （国内是 workbuddy）
//!   站点          https://www.workbuddy.ai（国内是 https://www.workbuddy.cn）
//!   platform      workbuddy-ai            （国内是 workbuddy）
//!   产品名        WorkBuddy AI            （国内是 WorkBuddy）
//!   客户端版本    5.8.4 / CLI 2.161.0     （国内是 5.9.3 / 2.165.0）
//!   对话 UA       WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0
//!   官网 origin   https://www.workbuddy.ai（国内是 www.workbuddy.cn）
//!   登录资料接口  /v2/plugin/login/account?state=（国内是 /v2/plugin/account）
//!   每日玩法      每日活跃保活（activity.run）；**没有**普通签到与成长任务中心
//! ```
//! 逐条取值都在 [`crate::endpoints`] 与 `Region` 的方法上，上层只读这里。
//!
//! ── provider id 与落盘契约 ──────────────────────────────────
//! 国际版用 id `"workbuddy-intl"`；存量国际版账号由 native 的
//! `account_store::migrate_startup` 原地归位（网关侧已做过），插件这边只要保证
//! 读写的是同一个 id。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use crate::endpoints::{self, EditionInfo};

/// WorkBuddy 国际版（唯一的地区）。
pub struct Region;

impl Region {
    /// 本地区的 provider id（`"workbuddy-intl"`）。
    pub fn provider_id() -> &'static str {
        endpoints::provider_id()
    }

    /// 本地区的版本配置（端点 / 前缀 / platform / UA 段 / 客户端版本）。
    pub fn edition() -> &'static EditionInfo {
        endpoints::edition()
    }

    /// 本地区的版本 id（`"intl"`）。
    pub fn id() -> &'static str {
        endpoints::edition().id
    }

    /// 与 [`Region::id`] 同义，名字更直白的那一个（`session_of_record` 用它写
    /// `edition` 字段）。
    pub fn edition_id() -> &'static str {
        Self::id()
    }

    /// 展示名（界面上跟在 `WorkBuddy` 后面的那一段）。
    pub fn label() -> &'static str {
        endpoints::edition().label
    }

    /// 本地区的默认端点（账号记录没写 `endpoint` 时的兜底）。
    pub fn default_endpoint() -> &'static str {
        endpoints::edition().endpoint
    }

    /// provider id 是否属于本包。
    pub fn from_provider_id(provider_id: &str) -> bool {
        provider_id == Self::provider_id()
    }

    /// 某个版本 id 是不是国际版（接受 intl 及常见别名，未知值按国际版处理 ——
    /// 与 native `resolve_edition` 在本包里的回落口径一致）。
    pub fn is_intl(edition: Option<&str>) -> bool {
        endpoints::resolve_edition(edition).id == "intl"
    }
}
