//! CatPaw 会话注册表（native `registry/` 的 wasm 版）。
//!
//! ── 这张表存什么 ────────────────────────────────────────────
//! `x-session-id → { conversationId, 指纹链, modelType, 账号身份, 待响应工具调用 }`，
//! 外加一条 `tool_call_id → 会话` 的反向索引（工具续接判定要用）。
//!
//! ── 与 native 的最大差别：状态不在进程内存里 ─────────────────
//! native 的注册表是 `OnceLock<SessionRegistry>`（进程内内存表）。wasm 插件
//! 每次调用都可能落在不同实例上，**没有可依赖的进程内共享内存**，所以这里把
//! 记录写进宿主的会话存储（`sessions.v1` 的 `session.get` / `session.put`，
//! 按会话 id 隔离、带 TTL）。语义与 native 对齐的部分：
//!   - 指纹链与 `locate_increment` 的用法完全一致（`fingerprint.rs`）；
//!   - 记录带 `model_type` / `account_id` / `uid`，不一致就作废重建
//!     （换模型 / 换账号 / 桌面端换用户 —— native `resolve` 的三条失效判据）；
//!   - 长会话 TTL 2 小时，与 native `CLIENT_SESSION_TTL_MS` 同值。
//!
//! ── 明确没有搬过来的部分（如实记录）────────────────────────
//!   1. **容量上限 200 + LRU 淘汰**：宿主存储按 TTL 自净，插件侧读不到全表，
//!      也就无法淘汰「最久未活动的一条」。记录体积很小（一个 conversationId +
//!      指纹数组），没有 LRU 不会失控。
//!   2. **inflight 占用表**：native 用进程内集合做「同一 session 并发冲突」
//!      判定。这里退化成一条 `session.put` 标记，**不是原子占位** —— 两个
//!      真并发请求可能都认为自己拿到了占用。冲突时的行为与 native 相同
//!      （走独立 conversation、不写映射），只是判定本身弱一些。
//!   3. **身份旁表与账号级对账**：native 在旁表里记「account_id → uid」并在
//!      转发时对账。这里把 `uid` 直接放进会话记录，读到时比对一次即可，
//!      少一次存储往返、效果等价（不一致就作废）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic；只做存储读写，不发网络请求。

use agent2api_wasm_sdk::{self as sdk, json, Value};

/// 长会话 TTL：2 小时（native `CLIENT_SESSION_TTL_MS`）。
///
/// 为什么是 2 小时：用户对话的「连续感」窗口。超过这个时长没有新轮次，
/// 那条客户端会话基本结束了，保留 conversationId 只会占存储。
/// 过期后客户端再来就是全新会话（全量 round）—— 行为正确，只是多传一次历史。
pub const SESSION_TTL_MS: i64 = 2 * 60 * 60 * 1000;

/// 匿名工具会话 TTL：10 分钟（native `CLIENT_TOOL_SESSION_TTL_MS`）。
///
/// 比长会话短得多，因为「工具结果」是**紧接着**执行完就要提交的东西。
/// 客户端超过 10 分钟没把工具结果交回来，说明这一轮已经放弃，继续保留那条
/// 待响应记录会让下一次请求误判成「工具续接」。
pub const TOOL_TTL_MS: i64 = 10 * 60 * 1000;

/// 会话记录的存储键前缀（与工具索引、占用标记分开命名空间）
const SESSION_KEY: &str = "catpaw.session.";
const CALL_KEY: &str = "catpaw.call.";
const INFLIGHT_KEY: &str = "catpaw.inflight.";

/// 一条会话记录（对应 native `SessionRecord`，字段逐个对齐）。
#[derive(Clone, Debug, Default)]
pub struct SessionRecord {
    /// 上游 conversationId（本轮之后要复用的那个）
    pub conversation_id: String,
    /// 已同步消息的指纹链（`fingerprint::message_fingerprint` 的产物，按序）
    pub fingerprints: Vec<String>,
    /// 上游数字模型 ID（`modelType`）。与当前请求不一致 → 记录失效重建
    pub model_type: i64,
    /// 这条会话是**哪个账号**建的（换账号必须重建）
    pub account_id: String,
    /// 本次凭证里的用户标识（桌面端换用户必须重建；native 的身份旁表那一维）
    pub uid: String,
    /// 对应的客户端会话 id（`x-session-id`）。空串 = 匿名工具会话
    pub session_id: String,
    /// 待响应的工具调用 id（非空 ⇔ 这条会话在等工具结果）
    pub pending_call_ids: Vec<String>,
    /// 正在执行的那个 turn 的 id（`turn/stop` 要带上它）
    pub turn_request_id: Option<String>,
    /// 最后活动时间（毫秒）
    pub updated_at: i64,
}

/// 记录失效的原因（只用于日志，native `InvalidationReason` 的简化）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rebuild {
    /// 记录已过期
    Expired,
    /// 换了上游模型（不同模型不能续接同一 conversation）
    ModelMismatch,
    /// 换了账号记录
    AccountMismatch,
    /// 账号没变但用户换了（桌面端实时登录态在客户端侧换号）
    IdentityMismatch,
}

impl Rebuild {
    pub fn as_str(self) -> &'static str {
        match self {
            Rebuild::Expired => "expired",
            Rebuild::ModelMismatch => "model-mismatch",
            Rebuild::AccountMismatch => "account-mismatch",
            Rebuild::IdentityMismatch => "identity-mismatch",
        }
    }
}

/// 会话记录 → JSON（存储形态；键名短一些，省宿主存储空间）
fn encode(record: &SessionRecord) -> Value {
    json!({
        "c": record.conversation_id,
        "f": record.fingerprints,
        "m": record.model_type,
        "a": record.account_id,
        "u": record.uid,
        "s": record.session_id,
        "p": record.pending_call_ids,
        "t": record.turn_request_id,
        "at": record.updated_at,
    })
}

/// JSON → 会话记录（字段缺失按默认值处理，不 panic）
fn decode(value: &Value) -> SessionRecord {
    SessionRecord {
        conversation_id: value["c"].as_str().unwrap_or_default().to_string(),
        fingerprints: value["f"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        model_type: value["m"].as_i64().unwrap_or(0),
        account_id: value["a"].as_str().unwrap_or_default().to_string(),
        uid: value["u"].as_str().unwrap_or_default().to_string(),
        session_id: value["s"].as_str().unwrap_or_default().to_string(),
        pending_call_ids: value["p"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        turn_request_id: value["t"].as_str().map(str::to_string),
        updated_at: value["at"].as_i64().unwrap_or(0),
    }
}

/// 读一条会话记录（不做身份比对；比对在 [`resolve`]）。
pub fn load(session_id: &str) -> Option<SessionRecord> {
    if session_id.is_empty() {
        return None;
    }
    let value = sdk::session_get(&format!("{SESSION_KEY}{session_id}")).ok()?;
    if !value.is_object() {
        return None;
    }
    let record = decode(&value);
    if record.conversation_id.is_empty() {
        return None;
    }
    Some(record)
}

/// 写入/覆盖一条会话记录（TTL 按是否在等工具结果选）。
pub fn save(record: &SessionRecord) {
    if record.conversation_id.is_empty() || record.session_id.is_empty() {
        return;
    }
    let ttl = if record.pending_call_ids.is_empty() {
        SESSION_TTL_MS
    } else {
        // 等工具结果时用短 TTL：工具结果是「紧接着」要提交的东西
        TOOL_TTL_MS
    };
    let _ = sdk::session_put(
        &format!("{SESSION_KEY}{}", record.session_id),
        encode(record),
        ttl,
    );
    // 反向索引：每个待响应 tool_call_id 指向这条会话（工具续接判定用）
    for call_id in &record.pending_call_ids {
        if call_id.is_empty() {
            continue;
        }
        let _ = sdk::session_put(
            &format!("{CALL_KEY}{call_id}"),
            json!({ "s": record.session_id }),
            TOOL_TTL_MS,
        );
    }
}

/// 作废一条会话记录（连同它的工具索引与占用标记）。
///
/// ── 为什么必须连索引一起删 ──────────────────────────────────
/// 只删主记录会让工具索引指向一条不存在的会话：下一次工具续接请求会「命中」
/// 然后读到空记录，落成一个既不续接也不重建的悬空状态。
pub fn forget(session_id: &str) {
    if session_id.is_empty() {
        return;
    }
    if let Some(record) = load(session_id) {
        for call_id in &record.pending_call_ids {
            if !call_id.is_empty() {
                let _ = sdk::session_remove(&format!("{CALL_KEY}{call_id}"));
            }
        }
    }
    let _ = sdk::session_remove(&format!("{SESSION_KEY}{session_id}"));
    let _ = sdk::session_remove(&format!("{INFLIGHT_KEY}{session_id}"));
}

/// 按 `tool_call_id` 找会话记录（工具续接判定的唯一入口）。
///
/// 命中后仍要过 [`resolve`] 的同一套身份比对 —— 索引只说明「这条会话登记过
/// 这个 call_id」，不说明它现在还能用（可能已经换了账号）。
///
/// 返回值第二个元素：`None` = 记录可用；`Some(原因)` = 命中但已失效（调用方
/// 应作废并按全新会话重建）。用一个显式的 `Option` 而不是拿某个 `Rebuild`
/// 变体当哨兵，是为了让「可用」与「失效原因」在类型上分得开。
pub fn lookup_by_call(
    call_id: &str,
    model_type: i64,
    account_id: &str,
    uid: &str,
) -> Option<(SessionRecord, Option<Rebuild>)> {
    if call_id.is_empty() {
        return None;
    }
    let index = sdk::session_get(&format!("{CALL_KEY}{call_id}")).ok()?;
    let session_id = index["s"].as_str().filter(|id| !id.is_empty())?;
    let record = load(session_id)?;
    Some(match resolve(record, model_type, account_id, uid) {
        Ok(record) => (record, None),
        Err((record, reason)) => (record, Some(reason)),
    })
}

/// 校验一条记录是否可用于本次请求（native `SessionRegistry::resolve` 的判据）。
///
/// 三条失效判据（顺序照抄 native）：过期 → 换模型 → 换账号/换用户。
/// 返回 `Err((旧记录, 原因))` 表示「作废并按全新会话重建」。
pub fn resolve(
    record: SessionRecord,
    model_type: i64,
    account_id: &str,
    uid: &str,
) -> Result<SessionRecord, (SessionRecord, Rebuild)> {
    let now = sdk::now();
    let ttl = if record.pending_call_ids.is_empty() {
        SESSION_TTL_MS
    } else {
        TOOL_TTL_MS
    };
    if record.updated_at <= 0 || now >= record.updated_at.saturating_add(ttl) {
        return Err((record, Rebuild::Expired));
    }
    if record.model_type != model_type {
        return Err((record, Rebuild::ModelMismatch));
    }
    if record.account_id != account_id {
        return Err((record, Rebuild::AccountMismatch));
    }
    // 账号 id 没变但用户换了：桌面端实时登录态在客户端侧换号时就是这样。
    // 空 uid 只匹配空 uid（显式身份而不是通配，与 native 同口径）。
    if record.uid != uid {
        return Err((record, Rebuild::IdentityMismatch));
    }
    Ok(record)
}

/// 占一次并发占用标记；已在占用中返回 false。
///
/// ── 为什么不是原子操作（如实记录）───────────────────────────
/// 宿主会话存储没有 compare-and-swap 接口（`state.v1` 有，但本包没有申报
/// `state.v1` 的 CAS 语义给这条路径用）。这里退化成「先读后写」，两个真并发
/// 请求可能都成功。冲突的后果与 native 一致：各自走独立 conversation、
/// 不写会话映射；判定本身弱一些，但不会串台 —— 因为真正防串台的是
/// `conversation_id` 只从记录里取，而不是从占用表里推断。
pub fn mark_inflight(session_id: &str) -> bool {
    if session_id.is_empty() {
        return false;
    }
    let key = format!("{INFLIGHT_KEY}{session_id}");
    if sdk::session_get(&key).ok().is_some_and(|value| value == json!(true)) {
        return false;
    }
    sdk::session_put(&key, json!(true), SESSION_TTL_MS).is_ok()
}

/// 释放并发占用标记（幂等）。
pub fn release_inflight(session_id: &str) {
    if session_id.is_empty() {
        return;
    }
    let _ = sdk::session_remove(&format!("{INFLIGHT_KEY}{session_id}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SessionRecord {
        SessionRecord {
            conversation_id: "c1".into(),
            fingerprints: vec!["aa".into()],
            model_type: 91,
            account_id: "acct".into(),
            uid: "u1".into(),
            session_id: "s1".into(),
            pending_call_ids: vec![],
            turn_request_id: None,
            // 不能用 `sdk::now()`：单测里没有宿主（`clock.now` 调不到，取到 0），
            // 而 `updated_at <= 0` 会被判成「没有活动时间」→ 直接过期。
            updated_at: 1,
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = record();
        let decoded = decode(&encode(&original));
        assert_eq!(decoded.conversation_id, original.conversation_id);
        assert_eq!(decoded.fingerprints, original.fingerprints);
        assert_eq!(decoded.model_type, original.model_type);
        assert_eq!(decoded.account_id, original.account_id);
        assert_eq!(decoded.uid, original.uid);
    }

    #[test]
    fn resolve_rejects_model_account_and_identity_changes() {
        let original = record();
        assert!(resolve(original.clone(), 91, "acct", "u1").is_ok());
        assert_eq!(
            resolve(original.clone(), 83, "acct", "u1").err().map(|(_, reason)| reason),
            Some(Rebuild::ModelMismatch)
        );
        assert_eq!(
            resolve(original.clone(), 91, "other", "u1").err().map(|(_, reason)| reason),
            Some(Rebuild::AccountMismatch)
        );
        assert_eq!(
            resolve(original.clone(), 91, "acct", "u2").err().map(|(_, reason)| reason),
            Some(Rebuild::IdentityMismatch)
        );
        let mut expired = original;
        expired.updated_at = 1 - SESSION_TTL_MS - 1;
        assert_eq!(
            resolve(expired, 91, "acct", "u1").err().map(|(_, reason)| reason),
            Some(Rebuild::Expired)
        );
    }
}
