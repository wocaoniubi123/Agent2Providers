//! QuWork 登录会话续期：只换账号令牌，模型令牌独立。
//!
//! ── 与 native 的差别（迁移时改的）───────────────────────────
//! native 用单飞锁 `flight::run` + 进程内 `local_sessions` 缓存；wasm 没有
//! 线程也没有长驻进程，等价手段是宿主账号锁 + 会话状态：
//! ```text
//!   账号锁（sdk::AccountLock）  同一账号的并发刷新串行化
//!   比较再写（account.update）  期间用户重新粘贴凭证时不覆盖新值
//!   会话（sdk::session_put）    本机登录态刷新后的令牌短期复用（不写盘）
//! ```
//!
//! ── 为什么本机账号的刷新结果不写回账号 ──────────────────────
//! 本机登录态的 token 归官方客户端所有；宿主没有给 quwork 提供「写回本机」
//! 的 helper（`desktop.refresh.*` 只覆盖 kiro / autoclaw / cline），插件也
//! 没有文件系统。所以刷新结果只进会话缓存（两小时、随实例回收），账号里
//! 只更新 `expiresAt` 这一个读数。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::account;
use super::upstream;

/// 本机令牌在会话里的键前缀（按账号 id 区分）。
const LOCAL_KEY: &str = "quwork:local:";

/// 拿一份「现在能用」的 secret；临期就刷一次。
pub fn ensure(force: bool) -> Result<Value> {
    let secret = account::current()?;
    if !force && !account::expiring(&secret) {
        return Ok(secret);
    }
    refresh(force)
}

/// 刷新登录会话（`force = true` 时无视临期判定）。
pub fn refresh(force: bool) -> Result<Value> {
    let before = account::current()?;
    let Some(record) = sdk::account().ok() else {
        return Err(Error::http(500, "QuWork 账号读取失败"));
    };
    let id = record["id"].as_str().unwrap_or("").to_string();
    let local = record["secret"].get("source").and_then(Value::as_str) == Some("desktop");
    if local {
        if let Some(cached) = local_cached(&id) {
            if sdk::now() < cached.1 {
                return Ok(cached.0);
            }
        }
    }
    let access = account::require_login(&before)?;
    let _lock = AccountLock::acquire();
    // 锁内重读：前一轮已经刷好的结果直接复用。
    let current = account::current()?;
    if !force && !account::expiring(&current) && account::text(&current, &["accessToken"]) != access {
        return Ok(current);
    }
    let access = account::require_login(&current)?;
    let reply = upstream::request("GET", upstream::REFRESH_PATH, &access, None)?;
    let data = reply.data("登录续期")?;
    let next = account::token(&account::text(&data, &["token"]), "登录凭证")?;
    if next.is_empty() {
        return Err(Error::http(502, "QuWork 续期未返回登录凭证"));
    }
    let expiry = upstream::timestamp(data.get("expire"))
        .or_else(|| account::jwt_expiry(&next))
        .unwrap_or_else(|| sdk::now().saturating_add(2 * 60 * 60_000));
    let previous = upstream::timestamp(current.get("expiresAt")).unwrap_or(0);
    if next == access && expiry <= previous {
        return Err(Error::http(502, "QuWork 续期未更新凭证或有效期，请重新登录"));
    }
    let mut fresh = current.clone();
    fresh["accessToken"] = json!(next);
    fresh["expiresAt"] = json!(expiry);
    fresh["updatedAt"] = json!(sdk::now());
    // 1.6.0 的续期只换账号令牌；没有新的 llm_token 时保留原模型凭证。
    let llm = account::token(&account::text(&data, &["llm_token"]), "模型凭证")?;
    if !llm.is_empty() {
        fresh["llmToken"] = json!(llm);
    }
    if local {
        // 本机账号：token 归客户端所有，只把读数写回账号，令牌进会话缓存。
        let mut saved = record["secret"].clone();
        saved["expiresAt"] = json!(expiry);
        saved["updatedAt"] = json!(sdk::now());
        let _ = sdk::host(
            "account.update",
            json!({ "expect": record["secret"], "secret": saved, "public": account::public(&saved) }),
        );
        let _ = sdk::session_put(&format!("{LOCAL_KEY}{id}"), fresh.clone(), 2 * 60 * 60_000);
        return Ok(fresh);
    }
    let result = sdk::host(
        "account.update",
        json!({
            "expect": current,
            "secret": fresh,
            "public": account::public(&fresh),
        }),
    )?;
    if result["updated"] != true {
        // 账号在这期间被改过（重新粘贴 / 手工编辑）：用刷出来的令牌，但不覆盖记录。
        return account::current();
    }
    Ok(fresh)
}

/// 会话里的本机令牌（`(secret, 过期时刻)`）。
fn local_cached(id: &str) -> Option<(Value, i64)> {
    let value = sdk::session_get(&format!("{LOCAL_KEY}{id}")).ok()?;
    let expiry = account::expiry_of(&value).unwrap_or(0);
    if value.is_object() && !account::text(&value, &["llmToken"]).is_empty() {
        Some((value, expiry))
    } else {
        None
    }
}

/// 带登录会话地打一次账号面接口（401 时强刷一次再重试）。
pub fn protected(method: &str, path: &str, body: Option<&Value>) -> Result<upstream::Reply> {
    let secret = ensure(false)?;
    let access = account::require_login(&secret)?;
    let reply = upstream::request(method, path, &access, body)?;
    if !reply.unauthorized() {
        return Ok(reply);
    }
    let fresh = refresh(true)?;
    upstream::request(method, path, &account::require_login(&fresh)?, body)
}
