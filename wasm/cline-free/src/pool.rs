//! Cline 的两个额度池（`cline-free` / `cline-pass`）参数化。
//!
//! ── 这个目录被两个包共享 ────────────────────────────────────
//! `wasm/cline-free/src/` 是源码本体；`wasm/cline-pass/src/lib.rs` 用
//! `#[path = "../../cline-free/src/…"]` 引用同一批模块，只在自己的 `lib.rs`
//! 里注入 `Pool::Pass`。这样两个包各自满足网关「一个包只能声明一个 provider」
//! 的硬要求（`provenance.rs:90`），又不会把同一套实现抄两遍。
//!
//! ── 池只影响三件事 ──────────────────────────────────────────
//! ```text
//!   provider id     cline-free / cline-pass（= 账号归属、设置命名空间）
//!   模型 id 前缀    cline-free/… / cline-pass/…（**上游的计费通道选择器**）
//!   默认限流器      免费池没有（native 的 `default_limiters` 为空）
//! ```
//! **前缀绝不能剥**：它是上游用来选池的，剥了就是把订阅池的请求打到免费池上。

/// 两个额度池。
///
/// `Pass` 在 `cline-free` 那个包里不会被构造（那个包只服务免费池），
/// 但两边共享同一份源码，所以对整个枚举放开未用告警。
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pool {
    /// 免费池（`cline-free/...` 与免费组的裸 id）
    Free,
    /// ClinePass 订阅池（`cline-pass/...`）
    Pass,
}

#[allow(dead_code)]
impl Pool {
    /// 本池对应的 provider id（落盘契约）。
    pub fn provider_id(self) -> &'static str {
        match self {
            Pool::Free => "cline-free",
            Pool::Pass => "cline-pass",
        }
    }

    /// 界面上的显示名。
    pub fn label(self) -> &'static str {
        match self {
            Pool::Free => "Cline 免费池",
            Pool::Pass => "Cline 订阅池",
        }
    }

    /// 上游模型 id 的通道前缀。
    pub fn prefix(self) -> &'static str {
        match self {
            Pool::Free => "cline-free/",
            Pool::Pass => "cline-pass/",
        }
    }
}
