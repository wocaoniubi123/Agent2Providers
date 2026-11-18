//! 插件侧日志与短标识工具。
//!
//! ── 为什么这里没有真正的日志输出 ─────────────────────────────
//! 宿主**没有给 wasm 插件开日志通道**：`plugin_host/wasm/services.rs` 的方法表
//! 里只有 `clock` / `http` / `stream` / `state` 这些能力，没有任何 log / print
//! 入口；插件的 stdout 也不会被宿主采集。native 版那些 `logging::verbose("[CatPaw]", …)`
//! 调用点是排障经验的一部分，所以这里**保留调用点与文案**，落到一个可关的空实现：
//! 将来宿主补上日志通道时，只需要改这一个函数体。
//!
//! 需要排障信息时的替代手段（本包已落实）：
//!   - 错误文案带上来源与原因（客户端可见）；
//!   - 会话/轮次的关键标识用 [`short_id`] 截前缀进错误文案，不落全文。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic；本模块不做任何 IO。

/// 诊断日志（当前为空实现，见模块头）。
///
/// 参数带下划线前缀是本文件的局部约定：调用点保留完整文案，便于将来接通道时
/// 直接放开，且不会让编译器报「未使用参数」。
#[inline]
pub fn verbose(_message: &str) {}

/// 取前 8 个字符（日志/错误里只打 id 前缀：够区分、又不落完整标识）。
///
/// 空串给 `-`；不足 8 个字符给原值。按**字符**而不是字节切片，避免多字节
/// 边界 panic（release 是 panic=abort）。
pub fn short_id(value: &str) -> &str {
    if value.is_empty() {
        return "-";
    }
    match value.char_indices().nth(8) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_truncates_on_char_boundary() {
        assert_eq!(short_id(""), "-");
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id("0123456789"), "01234567");
        // 取前 8 个**字符**（不是 8 个字节），多字节字符不会被切成半个
        assert_eq!(short_id("中文标识符中文标识符"), "中文标识符中文标");
    }
}
