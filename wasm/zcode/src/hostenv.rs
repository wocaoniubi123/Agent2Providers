//! 宿主运行环境（平台 / 架构）的查询与缓存。
//!
//! ── 为什么需要它 ────────────────────────────────────────────
//! native 全用编译期 `cfg!(target_os = …)` 判断平台。插件编译目标是
//! `wasm32-unknown-unknown`，那三个 `cfg!` 在它那里**全部为 false** —— 直接搬
//! 过来会让国内版的所有控制面请求都自称 `linux`，而实机是 Windows。宿主的
//! `runtime.platform` / `runtime.architecture`（能力 `runtime.platform.v1` /
//! `runtime.architecture.v1`）给的才是真实运行环境。
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! 这两个值在一次进程生命周期内不变，用 `OnceLock` 缓存（插件实例是长驻的）。
//! `OnceLock` 在 wasm32 单线程下可用（同仓库 `wasm/qoder` 已有先例）。
//! 取不到时按空串处理 —— 调用方各自回落（平台回落 `win32`，架构回落 `x64`）。

use std::sync::OnceLock;

use agent2api_wasm_sdk::{json, Value};

/// 宿主平台：`win` / `mac` / `linux` / `other`（取不到时空串）。
pub fn platform() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| query("runtime.platform"))
        .as_str()
}

/// 宿主架构：`x86_64` / `aarch64` / …（取不到时空串）。
pub fn architecture() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| query("runtime.architecture"))
        .as_str()
}

/// 问宿主一个标量。
fn query(method: &str) -> String {
    match agent2api_wasm_sdk::host(method, json!({})) {
        Ok(Value::String(text)) => text.trim().to_string(),
        Ok(other) => other.as_str().unwrap_or("").trim().to_string(),
        Err(_) => String::new(),
    }
}
