//! 余额 / 额度读数（native `usage`）。
//!
//! ── 这个形状是「可选集合」，不是强类型 ──────────────────────
//! 协议里 `UsageReport` 就是 `Value`：各家能读到的东西差别很大，网关把它
//! 原样交给界面，界面按已知键名渲染。已知键见 `crate::account::UsageReport`
//! 的文档：`plan`、`balance`、`credits`、`used`、`limit`、`until`、
//! `windows[]`、`error`。
//!
//! ── 示例为什么连上游都不问 ──────────────────────────────────
//! native 的 `usage()` 就是一段写死的读数（`Demo Plan` / `1000` / 一条每日
//! 窗口），用来演示「账号行点余额之后界面拿到什么」。真实 provider 在这里
//! 才去调上游的余额接口，并把币种 / 单位归一成上面那套键。

use agent2api_wasm_sdk::{json, Value};

/// `usage.query`：返回一份归一化后的读数。
///
/// `account` 是宿主绑定的账号 id（`params.account`）；示例把它回显成 `user`，
/// 好让验证脚本能确认「这一条读数属于哪个账号」。
pub fn query(account: &Value) -> Value {
    let user = account
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("示例账号")
        .to_string();
    json!({
        "plan": "Demo Plan",
        "balance": "1000",
        "user": user,
        "windows": [
            { "name": "每日", "used": 12.5, "limit": 100, "unit": "credits" }
        ],
    })
}
