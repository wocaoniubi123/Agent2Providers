//! 本包服务的**地区**：WorkBuddy 国内版（`workbuddy`）。
//!
//! ── 为什么只剩一个取值 ──────────────────────────────────────
//! native 的 `region.rs` 是一个两值的 `enum Region { Cn, Intl }`：同一个 provider
//! 目录导出 `workbuddy` 与 `workbuddy-intl` 两个 id。本次迁移只做国内版 ——
//! 网关 `provenance.rs` 硬性要求 wasm 包的 `providers.len() == 1`，国际版由
//! **另一个包**（`wasm/workbuddy-intl/`）负责。
//!
//! 于是这里保留的是「地区的**语义**」而不是那个枚举：provider id / 端点兜底 /
//! 客户端身份 / 版本 id 全都指向国内版。保留这层间接的好处在迁移期很实在 ——
//! 上层代码（`account` / `catalog` / `growth` / `billing`）里 native 的
//! `Region::Cn.provider_id()` 这类调用点可以逐字保留，将来要补国际版时不用重写
//! 一遍取值链。
//!
//! ── provider id 与落盘契约 ──────────────────────────────────
//! 国内版**必须**保持 `"workbuddy"`：它是存量账号 `accounts.json` 里的落盘契约，
//! 改名会让那些账号升级后变成「未知 provider」而静默消失。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use crate::endpoints::{self, EditionInfo};

/// WorkBuddy 国内版（唯一的地区）。
pub struct Region;

impl Region {
    /// 本地区的 provider id（`"workbuddy"`）。
    pub fn provider_id() -> &'static str {
        endpoints::provider_id()
    }

    /// 本地区的版本配置（端点 / 前缀 / platform / UA 段 / 客户端版本）。
    pub fn edition() -> &'static EditionInfo {
        endpoints::edition()
    }

    /// 本地区的版本 id（`"cn"`）。
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

    /// 某个版本 id 是不是国内版（接受 cn 及常见别名，未知值按国内版处理 ——
    /// 与 native `resolve_edition` 的回落口径一致）。
    pub fn is_cn(edition: Option<&str>) -> bool {
        endpoints::resolve_edition(edition).id == "cn"
    }
}
