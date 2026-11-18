//! MonkeyCode 凭证：**只有一条来源** —— 账号记录里的登录 session（粘贴形态）。
//!
//! ── 与别家最大的不同：粘贴式登录、没有续期 ────────────────────
//! 本家的密码登录要 go-cap 验证码、OAuth 要百智云 SCaptcha + 短信（见
//! `endpoints.rs` 的模块头），两条都不适合网关代跑。参考给出的结论是：
//! 从浏览器复制 `monkeycode_ai_session` cookie 是最可靠的一条路。
//! 上游**没有 refresh 接口**（session 30 天硬限制，`docs/02-auth/03-login-methods.md`），
//! 过期只能重新粘贴 —— 因此 `capabilities.refresh = false`，本模块比别家薄：
//! 没有「续期单飞」、也不需要 `locks.v1`（同批有包因为漏申报 `locks.v1`
//! 导致续期失败；本家根本没有续期，所以那条坑不适用于本包）。
//!
//! ── image_id 为什么是账号字段 ────────────────────────────────
//! 创建任务（`task.rs` 的会话转发第一步）必须带 `image_id`（VM 镜像 UUID），
//! 而它**不在**登录响应里：参考实现 `discoverImageId` 从**已有任务列表**的
//! `task.image.id` 里取 —— 新用户一个任务都没有时取不到，必须手动填。因此本
//! 模块把它作为账号记录的一个字段（可为空串），并在 `login.rs` 里做一次
//! best-effort 自动发现。
//!
//! ── 与 native 的差异：记录从 `sdk::account()` 来 ───────────────
//! native 的 `from_record(record: Option<&Value>)` 由调用方从账号库取记录；
//! wasm 插件**没有账号库访问权**，只有 `sdk::account()` —— 它返回宿主绑定到
//! 本次调用的那条记录（含 `secret`），所以 `from_secret` 直接吃 `record["secret"]`。
//! 「没有记录」在两侧都落成同一个 401 文案。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, Error, Result, Value};

/// 会话有效期（`docs/02-auth/03-login-methods.md`：30 天硬限制）
pub const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

/// 临期窗口：到期前 1 天提示重新粘贴（上游无续期，只能重登）
pub const EXPIRY_MARGIN_MS: i64 = 24 * 3600 * 1000;

/// 一次转发 / 查询用的 MonkeyCode 凭证快照。
///
/// native 的结构还带 `id` / `region` / `user_id` / `name` 四个展示字段（网关
/// 账号层与日志读它们）。wasm 侧这三个值要么由宿主持有（账号 id）、要么由包
/// 身份决定（地区），要么只出现在公开视图里（`userId` / `name`），转发链路一个
/// 都不需要，因此不搬 —— 少一个字段就少一处「两份实现逐字对齐」的负担。
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// 登录 session（`monkeycode_ai_session` 的值）
    pub session: String,
    /// VM 镜像 UUID（创建任务必需；可能为空 —— 见模块头）
    pub image_id: String,
    /// 估算的过期时刻（毫秒；来自记录 `expiresAt`，缺失时用 `addedAt + 30 天`）
    pub expires_at: i64,
}

impl Credentials {
    /// 是否已过期或进入临期窗口（上游无续期手段，这个判定只用于提示重登）。
    pub fn expiring(&self) -> bool {
        self.expires_at > 0 && self.expires_at - EXPIRY_MARGIN_MS <= sdk::now()
    }

    /// 创建任务是否具备必要条件（session + image_id）。转发入口（`conversation.rs`）
    /// 用它在自己真正建任务前给出可读的错误，而不是把空 image_id 发给上游。
    pub fn ready_for_task(&self) -> bool {
        !self.session.trim().is_empty() && !self.image_id.trim().is_empty()
    }
}

/// 从一条取值链里挑第一个非空字符串（记录可能被手工编辑过，宽容读取）。
pub fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 从账号 `secret` 解析凭证。
///
/// 键名沿用网关那份账号记录的形态（`accessToken` / `imageId` / `expiresAt` /
/// `addedAt`），见 `accounts.rs::account_of` 的落库字段。
pub fn from_secret(secret: &Value) -> Result<Credentials> {
    let session = pick(secret, &["accessToken", "session", "token"]);
    if session.is_empty() {
        return Err(Error::http(401, "MonkeyCode 账号缺少 session，请重新粘贴登录态"));
    }
    let image_id = pick(secret, &["imageId", "image_id"]);
    let explicit_expiry = secret.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
    let added_at = secret.get("addedAt").and_then(Value::as_i64).unwrap_or(0);
    let expires_at = if explicit_expiry > 0 {
        explicit_expiry
    } else if added_at > 0 {
        added_at.saturating_add(SESSION_TTL_MS)
    } else {
        0
    };
    Ok(Credentials { session, image_id, expires_at })
}

/// 本次调用绑定的账号凭证（`token.ensure` / `conversation` / 目录刷新共用）。
pub fn current() -> Result<Credentials> {
    let record = sdk::account().map_err(|_| {
        Error::http(401, "没有可用的 MonkeyCode 账号：请在账号页粘贴 session 添加")
    })?;
    from_secret(&record["secret"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_session_is_a_401() {
        let error = from_secret(&json_empty()).err().unwrap_or_else(|| Error::new("必须报错"));
        assert_eq!(Some(401), error.status);
        assert!(error.message.contains("session"));
    }

    #[test]
    fn aliases_and_expiry_are_read() {
        // `accessToken` 是网关落库的键；`session` / `token` 是手工编辑后的兼容键
        let credentials = from_secret(&agent2api_wasm_sdk::json!({ "session": "s-1" }))
            .unwrap_or_default();
        assert_eq!("s-1", credentials.session);
        assert!(!credentials.ready_for_task());
        let credentials = agent2api_wasm_sdk::json!({
            "accessToken": "s-2", "imageId": "img-1", "addedAt": 1_000i64
        });
        let credentials = from_secret(&credentials).unwrap_or_default();
        assert!(credentials.ready_for_task());
        // 没有显式 expiresAt 时用 addedAt + 30 天
        assert_eq!(1_000 + SESSION_TTL_MS, credentials.expires_at);
    }

    fn json_empty() -> Value {
        agent2api_wasm_sdk::json!({})
    }
}
