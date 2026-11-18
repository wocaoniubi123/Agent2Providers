//! 会话标识按调用方、账号和首轮输入隔离；工具续轮与重试复用同一轮次。
//!
//! ── 与 native 的差别：进程内表 → 宿主会话存储 ────────────────
//! native 侧用一张进程级 `HashMap`（空闲 7 天过期、会话 4096 / 轮次 16384 上
//! 限）。wasm 实例不保证跨调用存活（宿主在处理完一次调用后即回收实例），
//! 进程内表在那里等于每次请求都重新生成 id —— 那会让「同一轮的工具续轮」
//! 被上游看成不同会话。所以这里把那张表换成宿主的会话存储
//! （`session.get` / `session.put`，带 TTL），键仍是同一套 SHA-256 摘要：
//! 同样的输入 → 同样的键 → 取回同一个 id。
//!
//! ── 容量上限去哪了 ─────────────────────────────────────────
//! native 的 `MAX_SESSIONS` / `MAX_TURNS` 是为「进程内表不能无限长」设的；
//! 网关的会话存储按 TTL 自己回收，不再需要在插件里做淘汰。

use std::collections::BTreeMap;

use agent2api_wasm_sdk::{self as sdk, Result, Value};
use sha2::{Digest, Sha256};

/// 空闲多久算一轮结束（7 天，与 native 一致）。
const IDLE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// 一次转发请求要带的两个标识头。
pub fn headers(params: &Value, token: &str, org: &str) -> Result<Vec<(String, String)>> {
    let (session_key, turn_key) = keys(params, token, org);
    let session = resolve("session", &session_key)?;
    let turn = resolve("turn", &turn_key)?;
    Ok(vec![
        ("X-RACCOON-Session-ID".to_string(), session),
        ("X-RACCOON-Turn-ID".to_string(), turn),
    ])
}

/// 取回或分配一个标识（键是摘要，值是 `{id}`）。
fn resolve(kind: &str, key: &str) -> Result<String> {
    let slot = format!("raccoon-{kind}:{key}");
    if let Ok(value) = sdk::session_get(&slot) {
        if let Some(id) = value.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()) {
            return Ok(id.to_string());
        }
    }
    let id = new_id(kind, key);
    // 落不了盘不是致命错误：这一轮仍然能发（只是下一次同类请求会拿到新 id）。
    let _ = sdk::session_put(&slot, serde_json::json!({ "id": id }), IDLE_TTL_MS);
    Ok(id)
}

/// 生成一个 uuid v4 形态的标识。
///
/// ── 为什么不是真随机 ────────────────────────────────────────
/// wasm 侧没有随机源（SDK 不提供 `random`），而 native 的 `ids::uuid_v4()`
/// 也是「混入 RandomState 种子 + 单调计数 + 纳秒时间戳」的可预测实现。
/// 这里用「键的 SHA-256 + 当前毫秒」拼出同一形态：**同一键恒得同一 id**
/// 由会话表保证（先查后生成），这里只需要「不同键基本不撞」。
fn new_id(kind: &str, key: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(kind.as_bytes());
    hash.update(b":");
    hash.update(key.as_bytes());
    hash.update(b":");
    hash.update(sdk::now().to_string().as_bytes());
    let digest = format!("{:x}", hash.finalize());
    format!(
        "{}-{}-{}-{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    )
}

/// 会话键与轮次键（native 的同名函数逐条照搬，只是入参从 `ChatRequest`
/// 换成宿主传下来的同一份 JSON）。
fn keys(params: &Value, token: &str, org: &str) -> (String, String) {
    let body = &params["body"];
    let headers = header_map(params);
    let messages = body.get("messages").and_then(Value::as_array);
    let mut session = Sha256::new();
    field(&mut session, "provider", text(&params["provider"]).as_bytes());
    field(&mut session, "account", text(&params["account"]).as_bytes());
    field(&mut session, "org", org.as_bytes());
    let user = crate::jwt::decode_jwt_claims(token)
        .map(|claims| crate::jwt::extract_user_id(&claims))
        .filter(|user| !user.is_empty());
    field(
        &mut session,
        "identity",
        user.as_deref().unwrap_or(token).as_bytes(),
    );
    for name in ["authorization", "x-api-key", "x-client-id"] {
        if let Some(value) = headers.get(name) {
            field(&mut session, name, value.as_bytes());
        }
    }
    if let Some(user) = body.get("user") {
        field(&mut session, "user", user.to_string().as_bytes());
    }
    if let Some(explicit) = session_id(&headers, body) {
        field(&mut session, "session", explicit.as_bytes());
    } else {
        if let Some(agent) = headers.get("user-agent") {
            field(&mut session, "client", agent.as_bytes());
        }
        if let Some(first) = messages.and_then(|messages| messages.iter().find(|message| is_user(message))) {
            field(&mut session, "first-user", first.to_string().as_bytes());
        } else {
            field(&mut session, "request", body.to_string().as_bytes());
        }
    }
    let session = format!("{:x}", session.finalize());
    let mut turn = Sha256::new();
    field(&mut turn, "session", session.as_bytes());
    if let Some(explicit) = turn_id(&headers) {
        field(&mut turn, "turn", explicit.as_bytes());
    } else if let Some((messages, end)) = messages.and_then(|messages| {
        messages
            .iter()
            .rposition(is_user)
            .map(|end| (messages, end))
    }) {
        // 后续工具结果位于最后一条用户消息之后，不能改变这一轮的标识。
        for message in &messages[..=end] {
            field(&mut turn, "message", message.to_string().as_bytes());
        }
    } else {
        field(&mut turn, "request", body.to_string().as_bytes());
    }
    (session, format!("{:x}", turn.finalize()))
}

fn field(hash: &mut Sha256, name: &str, value: &[u8]) {
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name.as_bytes());
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

/// 入站头 → 小写键的表（宿主给的键本来就该是小写，这里再兜一次底）。
fn header_map(params: &Value) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(object) = params["headers"].as_object() {
        for (name, value) in object {
            if let Some(value) = value.as_str() {
                map.insert(name.to_ascii_lowercase(), value.to_string());
            }
        }
    }
    map
}

fn session_id(headers: &BTreeMap<String, String>, body: &Value) -> Option<String> {
    for name in [
        "x-raccoon-session-id",
        "x-conversation-id",
        "ah-thread-id",
        "x-opencode-session",
        "x-session-id",
        "x-session-affinity",
        "session_id",
        "session-id",
    ] {
        if let Some(value) = headers.get(name).and_then(|value| identifier(value)) {
            return Some(value);
        }
    }
    if let Some(value) = codex_metadata(headers, "session_id") {
        return Some(value);
    }
    for pointer in [
        "/session_id",
        "/conversation_id",
        "/metadata/session_id",
        "/metadata/conversation_id",
    ] {
        if let Some(value) = body.pointer(pointer).and_then(Value::as_str).and_then(identifier) {
            return Some(value);
        }
    }
    if let Some(value) = body
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .and_then(identifier)
    {
        return Some(value);
    }
    let metadata = body
        .pointer("/metadata/user_id")
        .and_then(Value::as_str)?
        .trim();
    if metadata.starts_with('{') {
        let data: Value = serde_json::from_str(metadata).ok()?;
        return data
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(identifier);
    }
    let (device, session) = metadata
        .strip_prefix("user_")?
        .split_once("_account__session_")?;
    (device.len() == 64 && device.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| identifier(session))
        .flatten()
}

fn turn_id(headers: &BTreeMap<String, String>) -> Option<String> {
    for name in [
        "x-raccoon-turn-id",
        "x-conversation-request-id",
        "ah-trace-id",
        "x-turn-id",
    ] {
        if let Some(value) = headers.get(name).and_then(|value| identifier(value)) {
            return Some(value);
        }
    }
    codex_metadata(headers, "turn_id")
}

fn codex_metadata(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    let raw = headers
        .get("x-codex-turn-metadata")
        .filter(|value| value.len() <= 16384)?;
    let value: Value = serde_json::from_str(raw).ok()?;
    value.get(name).and_then(Value::as_str).and_then(identifier)
}

/// 一个可安全塞进头的标识（非空、≤256、全可打印 ASCII）。
fn identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic()))
        .then(|| value.to_string())
}

fn is_user(message: &Value) -> bool {
    message.get("role").and_then(Value::as_str) == Some("user")
}
