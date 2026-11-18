//! 小浣熊的凭证处理（移植来源 `raccoon-local-auth.mjs`）。
//!
//! ── 本文件负责什么 ──────────────────────────────────────────
//!   1. **凭证来源**：账号记录里的 token / refreshToken。native 侧还有第二条
//!      来源（桌面端 `~/.box-agent/config/auth.json` 实时读盘）—— wasm 没有
//!      文件系统，那条来源整体移除，见文件末尾「桌面端登录态」一节。
//!   2. **刷新与回写**：调鉴权 API；结果**比较再写**（账号锁 + 条件更新），
//!      被判定过期的结果改用最新快照，绝不把旧结果盖到新凭证上。
//!   JWT 解码（不验签，只读 exp/name/iss）在 `jwt.rs`，本文件只用它的结果。
//!
//! ── 为什么与 atomcode 的 account.rs 不共用 ──────────────────
//! 两者的凭证形态与刷新协议完全不同：atomcode 是「OAuth refresh_token」，
//! 小浣熊是「JWT + POST {authBase}/refresh 的 `{refresh_token}` body +
//! access_token/refresh_token 响应体」。共用的只有**不变量**：持锁期间绝不
//! 做网络请求之外的等待、绝不 unwrap/expect。
//!
//! ── 单飞表去哪了（与 native 的结构差异）────────────────────
//! native 侧用 `crate::flight::Table` 做进程内单飞（同一账号同一 refreshToken
//! 并发只发一次真实请求）。wasm 实例不保证跨调用存活，进程内的单飞表既
//! 拼不起来也留不住，所以这里改用两条**跨调用**的机制达到同一目的：
//!   ① 账号锁（`AccountLock`）—— 同一账号的刷新串行化；
//!   ② 进锁后**重读**账号记录 —— 前一轮刚写完的结果会被这一轮直接看到，
//!      于是不需要「等待别人的结果」这一步（等价于 native 的 Waiter 分支）。
//! 结果仍然只用于**本轮**的调用者：失败不会被缓存，`force = true` 的下一次
//! 一定重新发请求。
//!
//! ── 桌面端登录态（有意移除的部分）──────────────────────────
//! native 侧的 `CredentialOrigin::AuthFile` 那一整套（mtime 缓存、比较写回
//! `auth.json`、符号链接 / 大小防御、权限收紧、原子 rename）在 wasm 里**没有
//! 对应能力**：插件跑在宿主进程的沙箱里，读不到用户主目录。因此：
//!   - `snapshot` 只有「账号记录」一种来源；
//!   - `account.normalize` 的 `desktop` 来源返回一条可读的错误（见 `account.rs`）。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use crate::upstream;

pub const PROACTIVE_REFRESH_MARGIN_MS: f64 = 300_000.0;

/// 刷新结果被判定过期时的统一文案（比较写回的失败原因；调用方据此改用最新快照）
pub const STALE_REFRESH_MESSAGE: &str = "刷新结果已过期：凭证在此期间被更换（重新登录或重导入）";

/// 一份解析好的小浣熊凭证。
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// 账号 id（`user-<userId>`）
    pub id: String,
    pub token: String,
    pub refresh_token: String,
    /// 过期时间（毫秒）。JWT 解不出 exp 时为 None
    pub expires_at: Option<f64>,
    /// 用户 ID（JWT 的十六进制 id 约定，见 `jwt::extract_user_id`）
    pub user_id: String,
    pub org_code: String,
}

impl Credentials {
    /// 现在是否需要刷新（源实现 `isCredentialsExpiring`：expiresAt 缺失时
    /// 不刷新 —— 没有依据就说「临期」会让每个请求都去打一次刷新接口）。
    pub fn is_expiring(&self) -> bool {
        if crate::jwt::is_iam_token(&self.token) {
            return self
                .expires_at
                .is_some_and(|expires| expires <= sdk::now() as f64);
        }
        self.expires_at.is_some_and(|expires| {
            expires - PROACTIVE_REFRESH_MARGIN_MS <= sdk::now() as f64
        })
    }

    /// IAM 没有旧版 refresh grant，磁盘上残留的刷新令牌不能继续使用。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.is_empty() && !crate::jwt::is_iam_token(&self.token)
    }
}

/// 当前账号记录（宿主的 `account.get`）。
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 取当前账号的凭证快照。
///
/// ── 与 native 的差别 ────────────────────────────────────────
/// native 的 `snapshot(ctx, account_id)` 要区分「指定账号 / 未指定账号」，
/// 未指定且记录缺失时回落到本机登录态。wasm 侧宿主已经按调用上下文把
/// 账号选好了（`account.get` 就是这次调用承载的那个账号），所以这里只需要
/// 「读当前账号」一件事 —— 少了那层回落，也少了「拿另一个账号的凭证继续」
/// 这个隐患（native 的 `latest_credentials` 专门为此加了兜底）。
pub fn snapshot() -> Result<Credentials> {
    let record = record()?;
    let secret = record["secret"].clone();
    let id = record["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| crate::account::identity(&secret));
    let token = crate::account::pick(&secret, &["accessToken", "access_token", "token"]);
    if token.is_empty() {
        return Err(Error::http(
            401,
            format!(
                "账号 {} 没有可用凭证，请重新添加",
                if id.is_empty() { "(未知)" } else { &id }
            ),
        ));
    }
    let refresh_token = crate::account::pick(&secret, &["refreshToken", "refresh_token"]);
    let expires_at = secret
        .get("expiresAt")
        .and_then(Value::as_f64)
        .or_else(|| crate::jwt::jwt_expiry_ms(&token));
    Ok(Credentials {
        id,
        user_id: crate::account::pick(&secret, &["userId"]),
        org_code: crate::headers::org_code(&secret),
        token,
        refresh_token,
        expires_at,
    })
}

/// 一次请求的凭证与组织身份必须来自同一份快照。
///
/// ── 静态凭证优先于账号列表 ──────────────────────────────────
/// 仅在**没有指定账号**时才看设置里的静态凭证（`envToken`）—— 与 native
/// 「`RACCOON_TOKEN` 只在 account 为空时生效」逐字同义。这条链里的「没有
/// 指定账号」指的是**用户显式选中的账号**，宿主把账号传下来时它非空。
pub fn request_identity(account: &str) -> Result<(String, String)> {
    if account.is_empty() {
        if let Some(token) = upstream::env_token() {
            if crate::jwt::is_iam_token(&token) {
                crate::jwt::validate_iam_token(&token, &upstream::iam_issuer())?;
            }
            return Ok((token, String::new()));
        }
    }
    let credentials = snapshot()?;
    let refreshed = refresh(&credentials, false)?;
    Ok((refreshed.token, refreshed.org_code))
}

/// 刷新凭证（`force = false` 时只在**临期**才刷新）。
///
/// `force = true` 是 401 之后的强制刷新：被拒的 token 可能时间上还很新，
/// 只看临期窗口会拿回同一个坏 token。
pub fn refresh(previous: &Credentials, force: bool) -> Result<Credentials> {
    let issuer = upstream::iam_issuer();
    if crate::jwt::is_iam_token(&previous.token) {
        if force {
            let latest = latest(previous)?;
            if latest.token != previous.token {
                if crate::jwt::is_iam_token(&latest.token) {
                    crate::jwt::validate_iam_token(&latest.token, &issuer)?;
                }
                return Ok(latest);
            }
            return Err(Error::http(
                401,
                "小浣熊 IAM 登录态已被上游拒绝，不能用旧刷新接口续期，请重新登录该账号",
            ));
        }
        crate::jwt::validate_iam_token(&previous.token, &issuer)?;
        return Ok(previous.clone());
    }
    if !force && !previous.is_expiring() {
        return Ok(previous.clone());
    }
    if !previous.can_refresh() {
        return Err(Error::http(401, "该账号没有 refreshToken，无法刷新，请重新添加账号"));
    }
    // 账号锁：同一账号的刷新串行化（锁在 Drop 时归还，出网期间不持任何锁）。
    let _lock = AccountLock::acquire()?;
    // 进锁后重读：前一轮刚写完的结果在这里就能看到，不必等别人的结果。
    let current = snapshot()?;
    if current.token != previous.token
        || current.refresh_token != previous.refresh_token
        || current.org_code != previous.org_code
    {
        return Ok(current);
    }
    let next = crate::refresh_api::call(&current)?;
    apply(&current, &next)
}

/// 刷新结果落地：**比较-再写**，过期结果改用最新快照。
///
/// 三种结局（与 native 逐条一致）：
///   1. 写回成功 → 用刷新结果；
///   2. 发现凭证已被换掉（用户重导入 / 换号 / 另一轮刷新先落地）→ **不写**，
///      改用当前最新快照（读不到就明确失败）—— 绝不把旧结果盖到新凭证上；
///   3. 其它回写错误（权限、宿主拒绝…）→ 明确失败，不返回未保存的轮换令牌。
fn apply(previous: &Credentials, next: &Credentials) -> Result<Credentials> {
    let record = record()?;
    let stored = record["secret"].clone();
    if crate::account::pick(&stored, &["accessToken"]) != previous.token
        || crate::account::pick(&stored, &["refreshToken", "refresh_token"]) != previous.refresh_token
        || crate::headers::org_code(&stored) != previous.org_code
    {
        return stale_or_latest(previous);
    }
    let mut next_secret = with_fields(
        &stored,
        &[
            ("accessToken", Value::String(next.token.clone())),
            ("refreshToken", Value::String(next.refresh_token.clone())),
        ],
    );
    if crate::jwt::is_iam_token(&next.token) {
        if let Some(object) = next_secret.as_object_mut() {
            object.remove("refreshToken");
            object.remove("refresh_token");
        }
    }
    if let Some(expires_at) = next.expires_at {
        next_secret = with_fields(&next_secret, &[("expiresAt", json!(expires_at))]);
    }
    if !next.user_id.trim().is_empty() {
        next_secret = with_fields(&next_secret, &[("userId", json!(next.user_id.clone()))]);
    }
    let public = crate::account::view(&next_secret);
    let outcome = sdk::host(
        "account.update",
        json!({ "expect": stored, "secret": next_secret, "public": public }),
    )
    .map_err(|error| {
        Error::http(
            502,
            format!(
                "账号 {} 刷新结果回写失败: {}",
                previous.id, error.message
            ),
        )
    })?;
    if outcome["updated"] != true {
        return stale_or_latest(previous);
    }
    Ok(next.clone())
}

/// 「刷新结果已过期」的处置：改用最新快照（拿不到就明确失败）。
fn stale_or_latest(previous: &Credentials) -> Result<Credentials> {
    let latest = latest(previous).map_err(|error| {
        Error::http(
            error.status.unwrap_or(502),
            format!(
                "{}（刷新结果已过期，且读取最新凭证失败：{}）",
                STALE_REFRESH_MESSAGE, error.message
            ),
        )
    })?;
    if latest.token == previous.token
        && latest.refresh_token == previous.refresh_token
        && latest.org_code == previous.org_code
    {
        return Err(Error::http(
            409,
            "小浣熊续期结果未能落盘，请重新登录该账号",
        ));
    }
    Ok(latest)
}

/// 重新取当前凭证（比较写回判定过期后的兜底）。
///
/// 账号来源额外要求记录**仍然存在**：「账号已被用户删除」绝不能变成
/// 「拿另一个账号的凭证继续」。
fn latest(previous: &Credentials) -> Result<Credentials> {
    if previous.id.is_empty() {
        return Err(Error::http(
            401,
            "账号已被删除，本次刷新结果作废",
        ));
    }
    match snapshot() {
        Ok(latest) => Ok(latest),
        Err(_) => Err(Error::http(
            401,
            format!("账号 {} 已被删除，本次刷新结果作废", previous.id),
        )),
    }
}

/// 在 secret 上原地改几个字段（其余字段原样保留）。
///
/// ── 为什么不能整份替换 ──────────────────────────────────────
/// secret 里除了令牌还有 `userId` / `officeIdentity` / `expiresAt` 这些身份
/// 载荷件，整份替换会把它们一起清掉（native 的 `store::with_fields` 同理）。
pub fn with_fields(secret: &Value, fields: &[(&str, Value)]) -> Value {
    let Some(object) = secret.as_object() else {
        return secret.clone();
    };
    let mut next = object.clone();
    for (key, value) in fields {
        next.insert((*key).to_string(), value.clone());
    }
    Value::Object(next)
}
