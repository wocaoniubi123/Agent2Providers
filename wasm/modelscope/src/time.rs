//! 北京时间（固定 UTC+8）—— 签到、魔粒流水与「次日恢复」对「今天」的唯一定义。
//!
//! ── 为什么插件里也要有这一层 ────────────────────────────────
//! native 侧 `crates/providers/src/beijing.rs` 与 `modelscope/errors.rs` 都用
//! 北京时间判断「今天」和「明天零点」：魔搭的一整套「当日」口径（签到、魔粒
//! 发放、日额度）都按北京时间算，而网关可能跑在 UTC 容器里 —— 跟着机器时区走
//! 会让「今天」的边界整体漂移 8 小时，签到会在错的那一天确认、冷却也会在错的
//! 时刻放行。
//!
//! ── 为什么是固定偏移而不是时区库 ─────────────────────────────
//! 中国标准时间没有夏令时，`Asia/Shanghai` 在 1970 年之后恒为 +08:00 ——
//! 一个固定偏移就够，且不依赖宿主机的 tzdata（wasm 沙箱里根本没有 tzdata）。

use chrono::{DateTime, FixedOffset, Offset};

use agent2api_wasm_sdk as sdk;

/// UTC+8 的固定偏移（秒）。
pub const OFFSET_SECONDS: i32 = 8 * 3600;

/// 一整天（毫秒）。
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// 固定 UTC+8 时区对象。
///
/// 8 小时恒在合法范围内；兜底给 UTC 偏移是为了守住「插件零 panic」的约定 ——
/// 这里若 unwrap，一个环境问题就会带走整个插件实例（`panic = "abort"`）。
pub fn offset() -> FixedOffset {
    FixedOffset::east_opt(OFFSET_SECONDS).unwrap_or_else(|| chrono::Utc.fix())
}

/// 毫秒时间戳 → 北京时间时刻；越界的非法时间戳给 None。
pub fn date_time_of_ms(ms: i64) -> Option<DateTime<FixedOffset>> {
    DateTime::from_timestamp_millis(ms).map(|utc| utc.with_timezone(&offset()))
}

/// 北京日期键 `YYYY-MM-DD`（定长，字典序即时间序）。
pub fn date_key(now: DateTime<FixedOffset>) -> String {
    now.format("%Y-%m-%d").to_string()
}

/// 毫秒时间戳落在北京时间的哪一天（`YYYY-MM-DD`）。
pub fn date_key_of_ms(ms: i64) -> Option<String> {
    date_time_of_ms(ms).map(date_key)
}

/// 北京时间的今天（`YYYY-MM-DD`）。
///
/// 宿主时钟读不到时 `sdk::now()` 给 0（1970-01-01），这里如实照算而不是另取
/// 本机时间：wasm 沙箱里没有第二种可信时钟，编一个只会让「今天」更不可信。
pub fn today_key() -> Option<String> {
    date_key_of_ms(sdk::now())
}

/// `now_ms` 之后最近的**北京时间零点**（毫秒时间戳，纯函数）。
///
/// 给「魔粒耗尽 / 账号未验证 ⇒ 冷却到明天」用：这两种状态在充值 / 完成验证
/// 之前一直不可用，而魔搭的日口径是北京零点 —— 跨过那个点再试一次，既不会
/// 在当天反复白撞，也不会把账号永久钉死。
///
/// 边界：恰好落在零点上时给**次日**零点。用 `div_euclid` 而不是 `/`：
/// 负数时刻（1970 前）在 Rust 里默认向零取整会算错整天边界。
pub fn next_day_boundary_ms(now_ms: i64) -> i64 {
    let shifted = now_ms.saturating_add(i64::from(OFFSET_SECONDS) * 1000);
    let start_of_today = shifted.div_euclid(DAY_MS) * DAY_MS;
    start_of_today
        .saturating_add(DAY_MS)
        .saturating_sub(i64::from(OFFSET_SECONDS) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 北京零点：UTC 16:00 是次日 00:00（+08:00）。
    #[test]
    fn the_next_boundary_is_the_beijing_midnight() {
        // 2026-11-19 10:00:00 UTC = 北京时间 18:00
        let now = 1_795_082_400_000;
        let reset = next_day_boundary_ms(now);
        // 次日北京零点 = 2026-11-19 16:00:00 UTC
        assert_eq!(1_795_104_000_000, reset);
        assert_eq!(Some("2026-11-20".to_string()), date_key_of_ms(reset));
    }

    /// 恰好落在零点上时给次日零点（不给自己那一天）。
    #[test]
    fn an_exact_midnight_moves_to_the_next_day() {
        let midnight = 1_795_104_000_000;
        assert_eq!(midnight + DAY_MS, next_day_boundary_ms(midnight));
        assert_eq!(Some("2026-11-20".to_string()), date_key_of_ms(midnight));
    }

    /// 1970 前的负数时刻也按整天取整（不能用 `/`：负数会向零取整算错边界）。
    #[test]
    fn a_negative_instant_still_lands_on_a_day_boundary() {
        // -1 ms = 北京时间 1970-01-01 07:59:59.999，次日零点应是 1970-01-02 00:00。
        let reset = next_day_boundary_ms(-1);
        assert_eq!(57_600_000, reset);
        assert_eq!(Some("1970-01-02".to_string()), date_key_of_ms(reset));
    }
}
