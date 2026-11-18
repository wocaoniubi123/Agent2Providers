//! **正在驱动**的上游任务表（task id 集合）。
//!
//! ── 为什么需要它 ────────────────────────────────────────────
//! 建任务撞 10811 时会做一次自愈：列出账号上运行中的任务、逐个停止、重试
//! （见 `task.rs::create_task_with_recovery`）。但那份列表是**账号级**的 ——
//! 同一个账号上可能还有别的请求正在跑的任务。不排除它们就会把别人正在用的任务
//! 停掉：那个请求的 WS 会立刻断，用户看到的是「任务流连接已关闭」。
//!
//! 因此这里维护一份「正在驱动」的 task id 集合：建任务成功后登记，收尾
//! （正常 / 出错 / 断开 / 停止）时注销；自愈时**跳过集合里的 id**，
//! 只清理真正的残留。
//!
//! ── 载体：宿主会话存储（与 native 的进程内表同一语义）─────────────
//! native 用 `OnceLock<Mutex<HashSet<String>>>`。wasm 实例**一次调用一个沙箱**，
//! 静态变量不跨请求，所以表放在 `sdk::session_*`（`sessions.v1`）里：键是全局的，
//! 同一个包的所有调用都能看到，与「进程内」等义。
//!
//! ── 边界（如实说明）────────────────────────────────────────
//!   - 会话条目有 TTL（本文件取 15 分钟，宿主上限）：过期即视为「已无人驱动」，
//!     这正是我们想要的 —— 那些任务的流早已没人读了；
//!   - 读-改-写不是原子的：两个并发请求登记时可能互相覆盖（后写者赢）。代价是
//!     自愈时可能漏排除一个正在跑的任务，或把一个已结束的任务当成残留再停一次
//!     （停已结束的任务是无害的空操作）。这张表本来就是「尽力而为」的提示，
//!     不是安全边界；
//!   - **插件实例被宿主回收时不会补做收尾**：native 的 `StopOnDrop` 依赖
//!     `Drop` 里 `tokio::spawn` 一次停止请求，wasm 侧既没有异步 Drop 也不能在
//!     同步 Drop 里发网络请求。这一条的兜底改为「下一次 10811 自愈时清理」
//!     （见 `task.rs`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use super::logging;

/// 会话存储里的键
const KEY: &str = "monkeycode:inflight";

/// 表里最多记多少个任务（防御性上限：并发 8 × 少量重试，32 足够）
const MAX_IDS: usize = 32;

/// 条目存活时长（毫秒）：15 分钟，宿主 `session.put` 的上限
const TTL_MS: i64 = 900_000;

/// 读表（读不到 / 结构不对 → 空表）。
fn load() -> Vec<String> {
    let Ok(value) = sdk::session_get(KEY) else {
        return Vec::new();
    };
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 写表（写失败不影响本次转发：最坏情况是自愈时多停一次已结束的任务）。
fn save(ids: &[String]) {
    let kept: Vec<Value> = ids.iter().take(MAX_IDS).map(|id| json!(id)).collect();
    let _ = sdk::session_put(KEY, Value::Array(kept), TTL_MS);
}

/// 登记一个正在驱动的任务（建任务成功后立刻调用）。
pub fn register(task_id: &str) {
    let id = task_id.trim();
    if id.is_empty() {
        return;
    }
    let mut ids = load();
    if ids.iter().any(|item| item == id) {
        return;
    }
    ids.push(id.to_string());
    logging::verbose(&format!("[MonkeyCode] 登记在途任务 {}", logging::short_id(id)));
    save(&ids);
}

/// 注销（收尾时调用；重复注销是幂等的）。
pub fn unregister(task_id: &str) {
    let id = task_id.trim();
    if id.is_empty() {
        return;
    }
    let mut ids = load();
    let before = ids.len();
    ids.retain(|item| item != id);
    if ids.len() == before {
        return;
    }
    logging::verbose(&format!("[MonkeyCode] 注销在途任务 {}", logging::short_id(id)));
    save(&ids);
}

/// 这个任务是不是正在被驱动（自愈时据此跳过）。
pub fn contains(task_id: &str) -> bool {
    let id = task_id.trim();
    if id.is_empty() {
        return false;
    }
    load().iter().any(|item| item == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表在宿主会话存储里，单元测试没有宿主 —— 这里只验证「不 panic」与
    /// 「空 id 不产生副作用」这两条边界（真正的跨请求行为要靠装包验证）。
    #[test]
    fn empty_ids_are_ignored() {
        register("");
        register("   ");
        unregister("");
        assert!(!contains(""));
        // 读不到会话时 `load` 必须给空表而不是 panic
        assert!(load().len() <= MAX_IDS);
    }
}
