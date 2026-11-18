//! LobsterAI 的账号面：凭证读取、令牌续期、账号视图、导入归一化。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/mod.rs`（trait 实现）+
//! `credentials.rs` 的视图部分。
//!
//! ── 与 native 的一处结构性差异 ──────────────────────────────
//! native 用 `crate::store::record(ctx, ID, account)` 从网关账号库取记录；
//! wasm 插件没有账号库访问权，只有 `sdk::account()` —— 它返回**宿主绑定到本次
//! 调用**的那条记录：`{id, provider, name, secret, public, identity}`。
//! 所以这里的每个入口都从 `record["secret"]` 起步（secret 本体，没有 native
//! 那层「摊平 + 补 id/provider/name」）。
//!
//! ── 续期：一定要把新令牌写回，且只改三个字段 ────────────────────
//! 续期**会轮换** refresh token：上游同时下发新 access 与新 refresh，旧 access
//! 立即失效。丢掉新的 refresh 等于让账号退化成必须重新登录，所以续期成功后必须
//! `account.update` 写回。
//!
//! ⚠️ **`latestKeyfrom` 绝不覆盖**：续期只回写 `accessToken` / `refreshToken` /
//! `expiresAt`，载荷件三件套（`uuid` / 两个 keyfrom）保持登录时那一份
//! （`credentials.rs` 的模块头是一手来源）。所以这里是「在旧 secret 上改三个键」，
//! 不是「拿新 secret 整份替换」。
//!
//! ── 并发：账号锁 + 复查 ─────────────────────────────────────
//! native 用 `flight::Table` 做单飞（键含两个令牌的指纹）。wasm 侧没有跨调用
//! 共享内存，改用宿主账号锁（`AccountLock`）：拿到锁后**复查一次** secret ——
//! 如果它已经变了，说明另一个并发调用刚续期成功，直接用那一份，不再打上游
//! （两个并发续期互相作废，后写覆盖前者，这是 native 注释里点名的故障）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::credentials::{self, Credentials};
use super::oauth;
use super::version;

/// 取当前账号记录（宿主绑定上下文；没有上下文时宿主会报错）。
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 记录里的 secret 本体（不是对象时按「没有可用账号」处理）。
pub fn secret_of(record: &Value) -> Result<Value> {
    match record.get("secret") {
        Some(secret) if secret.is_object() => Ok(secret.clone()),
        _ => Err(Error::http(
            401,
            "没有可用的 LobsterAI 账号：请在账号页用浏览器登录添加",
        )),
    }
}

/// 当前账号的 secret（`token.expiring` / `checkin.claim` 这类入口用）。
pub fn current_secret() -> Result<Value> {
    secret_of(&record()?)
}

/// 取访问令牌（**不发网络请求**）。
///
/// ⚠️ 本方法是取值口，且会在转发路径上被调：临期也不在这里续期，真正的续期由
/// 维护链路（`token.refresh`）与 401 后的强制刷新负责 —— 与 native
/// `ensure_token` 同一取舍（那里临期只记一行日志；wasm 侧没有日志通道，
/// 所以这段提示写在注释里而不是发一条宿主调用）。
pub fn ensure() -> Result<String> {
    let credentials = Credentials::from_secret(&current_secret()?)?;
    Ok(credentials.access_token)
}

/// 强制续期（401 之后 / 维护链路）：刷新并**把新令牌写回记录**。
pub fn refresh() -> Result<String> {
    let before = record()?;
    let _lock = AccountLock::acquire()?;
    let current = record()?;
    // 拿到锁后复查：另一个并发调用可能刚续期并写回，直接用那一份
    if current["secret"] != before["secret"] {
        return Ok(Credentials::from_secret(&secret_of(&current)?)?.access_token);
    }
    let secret = secret_of(&current)?;
    let credentials = Credentials::from_secret(&secret)?;
    if credentials.refresh_token.trim().is_empty() {
        return Err(Error::http(
            401,
            "LobsterAI 账号没有 refresh_token，无法续期，请重新登录",
        ));
    }
    if !credentials.can_refresh() {
        return Err(Error::http(
            401,
            "LobsterAI 账号缺少续期所需的载荷件（uuid / keyfrom 之一为空），请重新登录",
        ));
    }
    let client_version = version::resolve();
    let bundle = oauth::refresh(&credentials, &client_version)?;
    // 过期时刻：刚续期成功，以此刻为基准算（`expires_in` 缺失时退回读 JWT 的 exp）
    let expires_at = credentials::expires_at_from(
        sdk::now(),
        bundle.expires_in,
        &bundle.access_token,
    );
    // 轮换语义：refresh token 非空才算轮换（上游可能省略，那表示沿用旧的那一个）
    let rotated = !bundle.refresh_token.trim().is_empty();
    let next_refresh = if rotated {
        bundle.refresh_token.clone()
    } else {
        credentials.refresh_token.clone()
    };
    let mut next = secret.clone();
    if let Some(object) = next.as_object_mut() {
        object.insert(
            "accessToken".to_string(),
            Value::String(bundle.access_token.clone()),
        );
        object.insert(
            "refreshToken".to_string(),
            Value::String(next_refresh.clone()),
        );
        if expires_at > 0 {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
        // 载荷件三件套**不动**（`uuid` / `firstKeyfrom` / `latestKeyfrom`）
    }
    let written = sdk::host(
        "account.update",
        json!({
            "expect": secret,
            "secret": next,
            "public": credentials::account_view(&next),
        }),
    )?;
    if written["updated"] == true {
        return Ok(bundle.access_token);
    }
    // 比较失败 = 记录已被改动。若是别人刚续期成功，就直接用他写进去的那一份；
    // 否则如实报错（新令牌没落盘，账号下一次请求会 401，用户需要知道）。
    let latest = record()?;
    let latest_credentials = Credentials::from_secret(&secret_of(&latest)?)?;
    if latest_credentials.access_token != credentials.access_token {
        return Ok(latest_credentials.access_token);
    }
    Err(Error::http(
        502,
        "LobsterAI 续期成功但写回账号失败（账号记录已变）：请重试",
    ))
}

/// 临期判定（`token.expiring`）。
///
/// `secret` 由调用方给（网关把 secret 一起传过来），缺省时读当前账号。
///
/// ── 判据与 native 逐字一致：只看「有 refresh_token」+「进窗口」────────
/// **不**在这里追加「载荷件齐全」那一层：缺 keyfrom 的账号应当被送去 `refresh`
/// 一次，让上游/本插件把「缺少续期载荷件，请重新登录」这句话说出来；
/// 在这里判成「不临期」会让它静默滑到 401，用户看到的反而是含糊的登录态错误。
/// 续期入口（[`refresh`]）自己会先做那道判据。
pub fn expiring(params: &Value) -> bool {
    let secret = match params.get("secret").filter(|value| value.is_object()) {
        Some(secret) => secret.clone(),
        None => match current_secret() {
            Ok(secret) => secret,
            Err(_) => return false,
        },
    };
    match Credentials::from_secret(&secret) {
        Ok(credentials) => {
            !credentials.refresh_token.trim().is_empty() && credentials.expiring(sdk::now())
        }
        Err(_) => false,
    }
}

/// 手动添加：**如实拒绝**（与 native `normalize_account` 逐字一致）。
///
/// ── 为什么不能「尽力而为」──────────────────────────────────
/// 本家的续期要一整组身份载荷件（`uuid` + 两个 keyfrom），它们只在换码
/// 那一刻由上游下发 —— 用户从别处粘不出这三样。没有它们账号只能用到 access
/// 过期，之后必须重新登录。与其落一条看着正常、到期就废的记录，不如现在就说清
/// 只有网页登录一条路。
pub fn normalize(_params: &Value) -> Result<Value> {
    Err(Error::http(
        400,
        "LobsterAI 只能通过「网页登录」添加：它的续期需要换码时下发的 uuid 与 keyfrom，粘贴给不出这三项",
    ))
}

/// 账号公开视图（`account.view`）。
pub fn view(secret: &Value) -> Value {
    credentials::account_view(secret)
}

/// 账号稳定身份（`account.identity`）。
pub fn identity(secret: &Value) -> String {
    credentials::identity_of(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_of_rejects_missing_or_non_object() {
        let error = secret_of(&json!({ "id": "a1" }))
            .err()
            .unwrap_or_else(|| Error::new("缺 secret 时必须报错"));
        assert_eq!(error.status, Some(401));
        let error = secret_of(&json!({ "secret": "not-an-object" }))
            .err()
            .unwrap_or_else(|| Error::new("secret 非对象时必须报错"));
        assert_eq!(error.status, Some(401));
        let record = json!({ "id": "a1", "secret": { "accessToken": "t" } });
        let secret = secret_of(&record).unwrap_or(Value::Null);
        assert_eq!(secret["accessToken"], json!("t"));
    }

    #[test]
    fn normalize_refuses_pasted_credentials() {
        // 粘贴不出 uuid / keyfrom，所以这条路必须是明确的拒绝（不是「尽力而为」）
        let error = normalize(&json!({ "input": "whatever" }))
            .err()
            .unwrap_or_else(|| Error::new("粘贴凭据时必须被拒绝"));
        assert_eq!(error.status, Some(400));
        assert!(error.message.contains("网页登录"));
        assert!(error.message.contains("keyfrom"));
    }

    #[test]
    fn view_and_identity_delegate_to_credentials() {
        let secret = json!({
            "accessToken": "abcdefgh",
            "refreshToken": "r",
            "firstKeyfrom": "1",
            "latestKeyfrom": "2",
            "userId": "u-1",
            "name": "龙虾"
        });
        assert_eq!(view(&secret)["name"], json!("龙虾"));
        assert_eq!(identity(&secret), "u-1");
    }

    #[test]
    fn expiring_without_secret_never_panics() {
        // 没有账号上下文时 `current_secret()` 会失败 —— 这里必须回 false 而不是 panic
        let params = json!({});
        let _ = expiring(&params);
    }
}
