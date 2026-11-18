//! 客户端版本解析：`X-LobsterAI-Client-Version` 要的是**日期式版本**（如 `2026.9.4`），
//! 不是插件自己的版本号。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/version.rs`。
//!
//! ── 从哪来 ──────────────────────────────────────────────────
//! 上游的更新接口（`CLIENT_VERSION_API`，第三方主机）报当前桌面端版本。
//! ⚠️ 它的响应**不是业务信封**：版本号在 `data.value.version`。
//!
//! ── 为什么要缓存 ────────────────────────────────────────────
//! 版本在每个请求上都要用（换码 / 续期 / 目录 / 签到 / 对话），而它一天也变不了
//! 几次；参考实现缓存 12 小时。取不到就退回已知可用的常量，**绝不发空版本头**
//! —— 空版本头会被服务端按「不认识的客户端」对待。
//!
//! ── 与 native 的两处差异 ────────────────────────────────────
//!   1. native 用进程级 `Mutex<Option<Cache>>` 存 12 小时缓存；wasm 没有可靠的
//!      进程级存储（实例会被回收重建），所以这里改用宿主会话缓存
//!      （`sdk::session_*`，TTL 上限 15 分钟）。多打几次版本接口无害，
//!      而「插件实例重建后版本头退化成兜底常量」正是 native 那条注里点名的故障。
//!   2. 允许用设置项 `clientVersion` **钉住**版本（跳过接口）：版本接口是第三方
//!      主机，偶尔不可达时用户需要一个不依赖它的出路。这也正是本包唯一读设置
//!      的地方 —— 沙箱里没有环境变量，`sdk::settings::get` 是唯一的配置入口。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use super::upstream::{self, CLIENT_VERSION_API, FALLBACK_CLIENT_VERSION, USER_AGENT};

/// 宿主会话缓存里的键（插件实例级，所有账号共用一份）
const CACHE_KEY: &str = "lobsterai:client-version";

/// 宿主会话 TTL 的上限是 15 分钟（`wasm/services.rs` 的 `session.put`：
/// `clamp(1000, 900_000)`），所以缓存最多能顶 15 分钟。
///
/// native 那份是 12 小时（`VERSION_CACHE_TTL_MS`），这里顶不满 —— 差别只是
/// 「一天多问上游十几次版本接口」，不影响正确性。
const SESSION_TTL_MS: i64 = 900_000;

/// 设置项键名：非空即钉住版本，跳过版本接口
const SETTING_KEY: &str = "clientVersion";

/// 从更新接口的响应里取版本号。
///
/// ⚠️ **路径是 `data.value.version`，不是 `data.value`** —— `value` 是个**对象**，
/// 版本号在它的 `version` 成员里（Go 参考 `version.go:57-71` 的
/// `parseClientVersionFromUpdateValue` 逐层 `asRecord`）。
///
/// 这一处 native 最初写成把 `data.value` 当标量读，而单测夹具又是照着自己的假设
/// 编的（于是测试全绿、代码全错，线上表现是版本头永远退化成兜底常量）。
/// 现在夹具按 Go 的路径编，形状对不对由它守。
///
/// 单独抽出来是为了能脱网单测：这一段是上游契约，改错就是整家发错版本头。
pub fn version_from_update_payload(payload: &Value) -> Option<String> {
    let value = payload.get("data")?.get("value")?;
    let version = value.get("version")?;
    let text = match version {
        Value::String(text) => text.trim().to_string(),
        other => other.to_string(),
    };
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// 用户钉住的版本（设置项非空即生效）。
fn pinned() -> Option<String> {
    let value = sdk::settings::get(SETTING_KEY).ok()?;
    let text = value.as_str().map(str::trim).unwrap_or("");
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// 宿主会话里的缓存（过期由宿主清掉，这里再判一次空串）。
fn cached() -> Option<String> {
    let value = sdk::session_get(CACHE_KEY).ok()?;
    let text = value.get("value").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// 真的打一次版本接口（失败返回空串，由调用方退回兜底常量）。
fn fetch() -> String {
    let headers = vec![
        ("accept".to_string(), "application/json".to_string()),
        ("user-agent".to_string(), USER_AGENT.to_string()),
    ];
    let reply = match upstream::send("GET", CLIENT_VERSION_API, &headers, None, 256 * 1024) {
        Ok(reply) => reply,
        Err(_) => return String::new(),
    };
    if !reply.ok() {
        return String::new();
    }
    reply
        .json()
        .as_ref()
        .and_then(version_from_update_payload)
        .unwrap_or_default()
}

/// 解析当前客户端版本（设置钉住 → 会话缓存 → 接口 → 兜底常量）。
pub fn resolve() -> String {
    if let Some(value) = pinned() {
        return value;
    }
    if let Some(value) = cached() {
        return value;
    }
    let resolved = fetch();
    if resolved.is_empty() {
        return FALLBACK_CLIENT_VERSION.to_string();
    }
    // 缓存写失败不影响本次结果：版本已经拿到了，宿主存不下只会让下次再问一遍。
    let _ = sdk::session_put(
        CACHE_KEY,
        json!({ "value": resolved.clone() }),
        SESSION_TTL_MS,
    );
    resolved
}

/// 兜底取值：给「已经拿着版本、只是要修空串」的场景用。
///
/// `resolve()` 内部已经把空串折成它；这个入口留给将来需要「只要常量」的调用点。
#[allow(dead_code)]
pub fn fallback() -> &'static str {
    FALLBACK_CLIENT_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_version_from_the_nested_object() {
        // 真实的更新接口形态：`data.value` 是对象，版本号在它的 `version` 里
        let payload = json!({
            "code": 0,
            "data": { "value": { "version": "2026.9.4", "url": "https://example.invalid" } }
        });
        assert_eq!(version_from_update_payload(&payload).as_deref(), Some("2026.9.4"));
    }

    #[test]
    fn rejects_the_scalar_shape_that_native_once_got_wrong() {
        // `data.value` 直接是标量 = **不是**这个接口的形态（native 曾照此写错过）。
        // 这里必须返回 None，让调用方退回兜底常量，而不是把整段对象当版本号发出去。
        let scalar = json!({ "data": { "value": "2026.9.4" } });
        assert_eq!(version_from_update_payload(&scalar), None);
        let missing = json!({ "data": {} });
        assert_eq!(version_from_update_payload(&missing), None);
        let empty = json!({ "data": { "value": { "version": "" } } });
        assert_eq!(version_from_update_payload(&empty), None);
        assert_eq!(version_from_update_payload(&Value::Null), None);
    }

    #[test]
    fn numeric_version_is_rendered_not_dropped() {
        // Go 那边也是逐层读值再转字符串（数字形态不丢）
        let payload = json!({ "data": { "value": { "version": 20260904 } } });
        assert_eq!(version_from_update_payload(&payload).as_deref(), Some("20260904"));
    }

    #[test]
    fn fallback_is_never_empty() {
        // 空版本头会被服务端按「不认识的客户端」对待，所以兜底必须是非空常量
        assert!(!fallback().trim().is_empty());
        assert_eq!(fallback(), "2026.9.4");
    }
}
