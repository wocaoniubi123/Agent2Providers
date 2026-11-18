//! 控制面续期与调用：**一次性 refresh token 的串行化**在这里。
//!
//! ── 为什么续期必须在插件里 ──────────────────────────────────
//! 续期要 `oauth::refresh`：它用登录时那把 **DPoP 私钥**签一份新 proof 去打令牌
//! 端点。那套东西（PKCE、P-256、DPoP proof、STS 换凭据）是**上游协议细节** ——
//! 它留在网关，主仓库就仍然携带「怎么以官方客户端形态换凭据」的知识。
//!
//! ── 一次性 refresh token 的三条铁律 ─────────────────────────
//!   1. **串行**：同账号的续期必须互斥（本文件用宿主的账号锁）；
//!   2. **拿锁后回读**：并发的另一路可能刚做完续期并写回，直接覆盖会把新令牌冲掉；
//!   3. **比较再写 + 写完回读**：`account.update` 只在 `expect` 与当前 secret 相等时
//!      落盘；落盘后必须重新读一遍，否则在「别人抢先写了」的情况下会拿着自己那份
//!      推断值去签名 —— 而宿主要是拒写，那份凭据在上游根本不存在。
//!
//! ── 过期重试只做一次 ────────────────────────────────────────
//! `subscription_of` / `cloud_call` / `claim_bonus` 都是「撞到
//! `CONTROL_TOKEN_EXPIRED` ⇒ 续期 ⇒ 重发一次」。**不循环**：续期出来的凭据若还是被
//! 判过期，说明问题不在时间上（时钟、权限或上游状态），重试只会白烧 refresh token。

use agent2api_wasm_sdk::{json, AccountLock, Error, Result, Value};

use super::credentials::{self, OfficeAceCredential};
use super::signer::Algorithm;
use super::{oauth, subscription, upstream, util};

/// 当前账号的凭据（临期就**真续期**，返回可用的那一份）。
///
/// 这是所有控制面调用的统一入口：临时凭据只活约 2 小时，目录/余额/签到/开通四条
/// 链各自读盘上那份，闲置之后早就在上游 401 了 —— 而 401 在这些链路上只会显示成
/// 「失败」，看着像账号坏了。
pub fn credential_of() -> Result<OfficeAceCredential> {
    let (secret, credential) = credentials::current()?;
    if credential.control_plane_expiring() && credentials::can_refresh(&secret) {
        match refresh(Some(&credential)) {
            Ok(renewed) => Ok(renewed),
            // 续期失败但旧的还没过期：照旧用它（这是「续期比凭据先失败」的正常情形）
            Err(_) if credential.expires_at > util::now_ms() => Ok(credential),
            Err(error) => Err(error),
        }
    } else {
        Ok(credential)
    }
}

fn refresh_token_of(secret: &Value) -> String {
    util::text(secret, &["refreshToken", "refresh_token"])
}

/// 控制面四件材料是否一致（判断「期间有没有被别的路换掉」）。
fn same_control(left: &OfficeAceCredential, right: &OfficeAceCredential) -> bool {
    left.access_key_id == right.access_key_id
        && left.secret_access_key == right.secret_access_key
        && left.security_token == right.security_token
        && left.expires_at == right.expires_at
}

/// 在 secret 上写入若干字段（保留其余字段）——native `store::with_fields` 的等价物。
fn with_fields(secret: &Value, fields: &[(&str, Value)]) -> Value {
    let mut next = secret.clone();
    if let Some(object) = next.as_object_mut() {
        for (key, value) in fields {
            object.insert((*key).to_string(), value.clone());
        }
    }
    next
}

/// 续期：refresh token + DPoP 私钥 → 新的临时 AK/SK，写回账号记录。
///
/// `rejected` 是**被上游拒过**的那一份（`None` 表示「临期主动续」）。它参与
/// 「期间有没有被换掉」的判定：如果当前的凭据已经不是我这一份了，就不该再刷一次。
///
/// 返回新的凭据（已经落盘并被回读确认）。
pub fn refresh(rejected: Option<&OfficeAceCredential>) -> Result<OfficeAceCredential> {
    let (before_secret, before) = credentials::current()?;
    // 锁是宿主的跨调用互斥，`Drop` 自动释放
    let _lock = AccountLock::acquire()?;
    let (secret, current) = credentials::current()?;
    if !same_control(rejected.unwrap_or(&before), &current)
        || refresh_token_of(&before_secret) != refresh_token_of(&secret)
    {
        // 期间已经有人换过：直接交出当前那份（不要拿自己的旧结论覆盖）
        return Ok(current);
    }
    let refresh_token = refresh_token_of(&secret);
    if refresh_token.is_empty() {
        return Err(Error::http(
            400,
            "OfficeAce 账号没有 refresh token（手工只导入了网关凭据）：\
             控制面凭据无法续期，额度/签到需要重新登录一次",
        ));
    }
    let dpop = secret
        .get("dpopKeyPair")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            Error::http(400, "OfficeAce 账号缺少 DPoP 私钥上下文，无法续期：请重新登录一次")
        })?;
    let (renewed, expires_at, _user_name, next_refresh) =
        oauth::refresh(dpop, &refresh_token).map_err(|reason| {
            let hint = if reason.contains("refresh token has been used") {
                "；这份登录授权的刷新令牌已被使用，请重新网页登录获取独立授权，不要继续复用旧导入凭证"
            } else {
                ""
            };
            Error::http(401, format!("OfficeAce 续期失败：{reason}{hint}"))
        })?;
    let project_id = if renewed.project_id.is_empty() {
        current.project_id.clone()
    } else {
        renewed.project_id
    };
    let next = with_fields(
        &secret,
        &[
            ("accessKeyId", Value::String(renewed.access_key_id)),
            ("secretAccessKey", Value::String(renewed.secret_access_key)),
            ("securityToken", Value::String(renewed.security_token)),
            ("projectId", Value::String(project_id)),
            ("expiresAt", Value::from(expires_at)),
            ("refreshToken", Value::String(next_refresh.clone())),
        ],
    );
    // expect 必须是**原始 secret**，不能剥掉其中真实存在的 name 或其他凭证字段
    let saved = credentials::save(&secret, &next)?;
    let (latest_secret, latest) = credentials::current()?;
    let latest_refresh = refresh_token_of(&latest_secret);
    let expected = credentials::from_record(Some(&next))?;
    if latest_refresh == next_refresh && same_control(&expected, &latest) {
        return Ok(latest);
    }
    // 落盘没成功，但磁盘上的确是一份**新的**凭据（别人那一轮写的）：认它
    if !saved && !latest_refresh.is_empty() && latest_refresh != refresh_token
        && !same_control(&current, &latest)
    {
        return Ok(latest);
    }
    Err(Error::http(
        409,
        "OfficeAce 续期结果未能完整落盘，账号凭据已发生变化：请重新登录一次",
    ))
}

/// 读订阅快照；撞到「临时凭据过期」就续期再读一次。
pub fn subscription_of(credential: &mut OfficeAceCredential) -> Result<Value> {
    let project_id = credential.project_id.clone();
    match subscription::fetch_subscription(credential) {
        Err(error) if error.code.as_deref() == Some(upstream::CONTROL_TOKEN_EXPIRED) => {
            *credential = refresh(Some(credential))?;
            if credential.project_id.is_empty() {
                credential.project_id = project_id;
            }
            subscription::fetch_subscription(credential)
        }
        result => result,
    }
}

/// 调一次云端 `/v1/claw/*`（SDK 签名）；过期同样续期重试一次。
pub fn cloud_call(
    credential: &mut OfficeAceCredential,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let url = format!("{}{path}", oauth::CLOUD_BASE);
    let project_id = credential.project_id.clone();
    let request = upstream::call(credential, method, &url, Algorithm::Sdk, body.clone(), &[]);
    match request {
        Err(error) if error.code.as_deref() == Some(upstream::CONTROL_TOKEN_EXPIRED) => {
            *credential = refresh(Some(credential))?;
            if credential.project_id.is_empty() {
                credential.project_id = project_id;
            }
            upstream::call(credential, method, &url, Algorithm::Sdk, body, &[])
        }
        result => result,
    }
}

/// 补查 `project_id`：`GET {iam}/v3/projects` 里按 region 名匹配启用中的项目。
///
/// ── 为什么不创建 ────────────────────────────────────────────
/// 这个动作只是「问清楚账号落在哪个项目」，不是「准备资源」。查不到时如实报
/// 「区域尚未初始化，请先在官方客户端完成首次登录」—— 在华为云上建项目的后果
/// 远大于一次失败的查询。
pub fn resolve_project(credential: &mut OfficeAceCredential) -> Result<()> {
    if !credential.project_id.is_empty() {
        return Ok(());
    }
    let url = format!("{}/v3/projects", oauth::IAM_KEYSTONE_BASE);
    let fetch = |credential: &OfficeAceCredential| {
        upstream::call(credential, "GET", &url, Algorithm::Sdk, None, &[])
    };
    let result = match fetch(credential) {
        Err(error) if error.code.as_deref() == Some(upstream::CONTROL_TOKEN_EXPIRED) => {
            *credential = refresh(Some(credential))?;
            fetch(credential)?
        }
        result => result?,
    };
    let project = result
        .get("projects")
        .and_then(Value::as_array)
        .and_then(|projects| {
            projects.iter().find(|project| {
                project.get("name").and_then(Value::as_str) == Some(oauth::REGION)
                    && project.get("enabled").and_then(Value::as_bool) != Some(false)
            })
        })
        .and_then(|project| project.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Error::http(
                409,
                "果办所在区域尚未初始化，请先在官方客户端完成首次登录；这里不会创建云资源",
            )
        })?;
    credential.project_id = project.to_string();
    Ok(())
}

/// 领奖励积分；过期就续期重试一次。
pub fn claim_bonus(credential: &mut OfficeAceCredential) -> Result<Value> {
    let project_id = credential.project_id.clone();
    match subscription::claim_bonus(credential) {
        Err(error) if error.code.as_deref() == Some(upstream::CONTROL_TOKEN_EXPIRED) => {
            *credential = refresh(Some(credential))?;
            if credential.project_id.is_empty() {
                credential.project_id = project_id;
            }
            subscription::claim_bonus(credential)
        }
        result => result,
    }
}

/// 读一份台账（宿主按当前账号作用域存；读不到给 `Value::Null`）。
pub fn ledger_get(kind: &str) -> Value {
    agent2api_wasm_sdk::host("ledger.get", json!({ "kind": kind })).unwrap_or(Value::Null)
}

/// 写一份台账（失败返回错误，调用方据此决定要不要继续发写请求）。
pub fn ledger_put(kind: &str, value: &Value) -> Result<()> {
    agent2api_wasm_sdk::host("ledger.put", json!({ "kind": kind, "value": value })).map(|_| ())
}
