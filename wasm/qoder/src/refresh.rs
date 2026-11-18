//! 凭证续期：同一凭证只刷新一次，保存时确认账号未被重新导入或删除。
//!
//! 两条续期路径，都挂在 **openapi 主机**上、都不需要 COSY 签名：
//!   - 设备流凭据（`dt-` / `drt-`）→ `POST /api/v1/deviceToken/refresh`；
//!   - PAT 换来的作业令牌（`jt-` / `jrt-`）→ `POST /api/v1/jobToken/refresh`，
//!     或直接用 PAT 重新兑换（记录里带 PAT 时优先走这条）。
//!
//! **不要**改回 `{center}/algo/api/v3/user/refresh_token`：那条要求 appcode 签名，
//! 设备流凭据打过去只会被 WAF 以 `403 Request discarded` 丢掉（详见 `site.rs`
//! 里 `DEVICE_REFRESH_PATH` 的说明）。
//!
//! ── 单飞怎么做（与 native 的差别）───────────────────────────
//! native 用进程内的 `flight::Table` 合并同一凭证的并发续期。Wasm 里每次调用
//! 都是同一个实例上的同步执行，但宿主可能对同一账号并发发起多个调用 ——
//! 于是这里用宿主的**账号锁**（`lock.acquire`）做串行化：拿到锁后重读账号，
//! 若 secret 已经被别人换掉，直接用新的那份（不再刷第二次）。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::auth;
use super::credentials::{self, Credentials};
use super::site;

/// 取当前账号的 secret + 解析后的凭证。
pub fn snapshot() -> Result<(Value, Credentials)> {
    let account = sdk::account()?;
    if account.is_null() || account["secret"].is_null() {
        return Err(Error::http(404, "账号不存在，请先添加账号"));
    }
    let mut credentials = Credentials::from_payload(&account["secret"])?;
    credentials.set_seed(account["id"].as_str().unwrap_or(""));
    credentials.complete_identity()?;
    Ok((account, credentials))
}

/// 取一份现在能用的凭证（`force = false` 时只在临期窗口内真续期）。
pub fn ensure_fresh(force: bool) -> Result<Credentials> {
    let (account, credentials) = snapshot()?;
    if !force && !credentials.expiring() {
        return Ok(credentials);
    }
    if !credentials.can_refresh() {
        return Err(Error::http(400, "账号没有刷新凭证，请重新登录"));
    }
    let _lock = AccountLock::acquire()?;
    // 拿到锁后重读：并发的另一个刷新可能刚刚落盘
    let current = sdk::account()?;
    if current["secret"] != account["secret"] {
        let mut refreshed = Credentials::from_payload(&current["secret"])?;
        refreshed.set_seed(current["id"].as_str().unwrap_or(""));
        refreshed.complete_identity()?;
        return Ok(refreshed);
    }
    refresh_and_save(&current, &credentials)
}

fn refresh_and_save(account: &Value, credentials: &Credentials) -> Result<Credentials> {
    let mut fresh = match credentials.pat() {
        Some(pat) => {
            let mut fresh = auth::exchange_pat(pat)?;
            fresh.machine_id = credentials.machine_id.clone();
            fresh.complete_identity()?;
            fresh
        }
        None => refresh_via_open_api(credentials)?,
    };
    fresh.complete_identity()?;
    if fresh.user_id != credentials.user_id {
        return Err(Error::http(400, "续期返回了不同账号，旧凭证未被覆盖"));
    }
    // ── 写回（比较再写）─────────────────────────────────────────
    // `account.update` 的 `expect` 是读到时的那份 secret：宿主持有 CAS，
    // 只有它没变时才写。与 native `store::save` 同一语义。
    //
    // 空值不覆盖既有内容：刷新结果里缺某一项（上游没回过期时间）时不该把
    // 记录里仍然有效的值洗成空。
    let expect = account["secret"].clone();
    let next = merge_secret(&expect, &fresh.to_value());
    let public = super::account::view(&next);
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": public }),
    )?;
    if result["updated"] != true {
        // 期望值已变（另一个刷新先落盘 / 账号被重新导入）：重读一次再决定
        let (_, current) = snapshot()?;
        return Ok(current);
    }
    Ok(fresh)
}

/// 把刷新结果并进既有 secret（空值不覆盖）。
fn merge_secret(expect: &Value, fresh: &Value) -> Value {
    let mut next = expect.clone();
    let (Some(target), Some(source)) = (next.as_object_mut(), fresh.as_object()) else {
        return fresh.clone();
    };
    for (key, value) in source {
        if value.is_null() || matches!(value, Value::String(text) if text.is_empty()) {
            continue;
        }
        target.insert(key.clone(), value.clone());
    }
    next
}

/// 用刷新令牌换一组新凭据（**openapi 主机，无需签名**）。
///
/// 路径按刷新令牌前缀分派：`jrt-`（PAT 换来的作业刷新令牌）走
/// `/api/v1/jobToken/refresh`，**其余一律走设备端点** `/api/v1/deviceToken/refresh`。
/// 默认落在设备端点是刻意的 —— 我们的账号全部来自网页设备授权（`drt-`），
/// 未知格式大概率同族；而作业端点对 `drt-` 是硬拒（实测 400 `Bad request`）。
///
/// 上游**每次刷新都轮换**：返回新的访问令牌 + 新的刷新令牌，旧的立刻失效。
/// 因此新令牌必须整体回写（`refresh_token` 缺失时才退回旧值）。
fn refresh_via_open_api(credentials: &Credentials) -> Result<Credentials> {
    let refresh = credentials.oauth_refresh();
    if refresh.is_empty() {
        return Err(Error::http(400, "账号没有刷新凭证，请重新登录"));
    }
    let path = if refresh.starts_with("jrt-") {
        site::JOB_REFRESH_PATH
    } else {
        site::DEVICE_REFRESH_PATH
    };
    // 请求体：字段名是 snake_case 的 `refresh_token`（与取令牌时的 camelCase
    // `refreshToken` 不是同一套 —— 发错名字上游按缺参处理）。
    let response = auth::request(
        "POST",
        &site::open_api_url(path),
        Some(&json!({ "refresh_token": refresh })),
        &site::refresh_headers(),
    )?;
    // 401/403 在续期语义下只有一个含义：这把刷新令牌已经不能用了（过期、
    // 被轮换掉，或与所选站点不符 —— 各站令牌不通用）。给一句能照做的提示，
    // 而不是把上游的 `Request discarded` 原样透出去。
    if matches!(response.status, 401 | 403) {
        return Err(Error::http(401, "刷新令牌已失效或与所选站点不符，请重新登录该账号"));
    }
    let data = auth::payload(response, "凭证续期")?;
    // 响应带用户标识时先核对身份：把 A 账号的令牌写进 B 账号的记录，
    // 会让两个账号同时不可用，且从余额/模型列表上都看不出来。
    // **只认 `user_id` 这几个键**：设备响应的 `id` 是设备会话号而非账号。
    let returned_user = credentials::text(&data, &["user_id", "uid", "userId"]);
    if !returned_user.is_empty()
        && !credentials.user_id.is_empty()
        && returned_user != credentials.user_id
    {
        return Err(Error::http(502, "续期返回了不同账号，旧凭证未被覆盖"));
    }
    // 访问令牌的键名不固定：设备端点回 `device_token`，作业端点回 `token`。
    let token = credentials::secret(&data, &["device_token", "deviceToken", "token", "access_token"])?;
    if token.is_empty() {
        return Err(Error::http(502, "续期响应缺少令牌，旧凭证未被覆盖"));
    }
    let refresh_token = credentials::secret(&data, &["refresh_token", "refreshToken"])?;
    if refresh_token.contains('|') {
        return Err(Error::http(502, "续期响应的 refresh_token 格式无效"));
    }
    let mut fresh = credentials.clone();
    fresh.access_token = token;
    // 续期响应没带新刷新令牌时保留旧值：上游按「轮换」语义工作，此处只做兜底，
    // 免得把仍然有效的那一半洗成空（空刷新令牌会让账号再也刷不动）。
    fresh.refresh_token = format!(
        "{}|{}|{}",
        if refresh_token.is_empty() { refresh } else { &refresh_token },
        credentials.user_id,
        credentials.machine_id
    );
    // 只认绝对时间字段。**不要**回落到 `expires_in`：同一份协议里它的单位
    // 在两家参考实现中被分别当成秒和毫秒（实测设备端点回 2591999994，
    // 按毫秒算正好 30 天），猜错会写出一个几十年后的过期时间，让自动续期
    // 再也不触发。缺字段时按设备令牌的 30 天寿命兜底，宁可早刷一次。
    fresh.expires_at = Some(
        credentials::timestamp(data.get("expires_at"))
            .or_else(|| credentials::timestamp(data.get("expiresAt")))
            .or_else(|| credentials::timestamp(data.get("expire_time")))
            .or_else(|| credentials::timestamp(data.get("expireTime")))
            .unwrap_or_else(|| sdk::now() + 30 * 24 * 60 * 60 * 1000),
    );
    Ok(fresh)
}
