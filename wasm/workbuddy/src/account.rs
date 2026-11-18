//! 账号面：取 token（含临期单飞续期）、公开视图、稳定身份、账号规范化。
//!
//! 合并自 native 的 `auth.rs` + `refresh.rs` + `accounts.rs` 三块：
//! • 凭证读取与单飞续期（`ensure` / `refresh` / `expiring`）
//! • `account_view` / `identity_of` / `normalize`
//!
//! ── 续期为什么要单飞 + 比较再写 ────────────────────────────
//! refresh token 换发后旧值失效，只有新凭证已经落盘才能向等待者报告成功。
//! 写回冲突时保留最新的非鉴权字段；凭证已被替换则不覆盖新登录态。
//! wasm 侧没有进程内表（宿主每次调用后回收实例），所以用宿主的账号锁
//! （`lock.acquire`）+ `account.update` 的 CAS（`expect` 是读到时的那份 secret）。
//!
//! ── 默认登录态（native 的 `WORKBUDDY_TOKEN` 旁路）不迁 ─────────
//! native 允许「一个账号都没有时用环境变量 token 转发」。wasm 沙箱既没有
//! 环境变量，网关也**明文禁止** wasm 包申报隐式本机凭证
//! （`capabilities.anonymous_default_session` / `env_credentials` 必须为 false，
//! 见 `metadata.json`）。所以这里没有那条分支：没有账号就返回可读错误。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use crate::auth;
use crate::endpoints::Context;
use crate::outbound;
use crate::util;
use crate::{refresh_identity, Region};

/// 令牌长度上限（与账号存储的 `MAX_TOKEN_LENGTH` 同量级）
const MAX_TOKEN_LENGTH: usize = 32_768;
/// 身份字段长度上限
const MAX_IDENTITY_LENGTH: usize = 256;
/// 备注名长度上限
const MAX_NAME_LENGTH: usize = 100;

/// 当前账号的扁平 secret（没有账号时给空对象）。
pub fn secret() -> Result<Value> {
    let record = sdk::account()?;
    Ok(record.get("secret").cloned().unwrap_or(Value::Null))
}

/// 当前账号的完整记录（`{id, secret, public, ...}`）。
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 取 access token（含临期主动刷新并回写账号）。
///
/// - 有账号 → 该账号的 token；临期且可刷新时自动刷新。
///
/// 与 native 的差别：native 在 `account == ""` 时回落到「环境变量 token / 队首
/// 账号」；wasm 侧没有这两条路（见模块头），所以恒用宿主给出的当前账号。
pub fn ensure() -> Result<String> {
    let record = record()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    if !secret.is_object() {
        return Err(Error::http(401, "WorkBuddy 当前没有可用账号，请先完成登录"));
    }
    let session = outbound::session_of_record(&secret);
    let expires_at = session
        .pointer("/auth/expiresAt")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let refresh_token = util::pick(&secret, &["refreshToken"]);
    // 临期主动刷新（改造前 `auth::get_current_session` 的行为）
    if auth::is_token_expiring(expires_at) && !refresh_token.is_empty() {
        match refresh() {
            Ok(token) => return Ok(token),
            // 续期失败不阻断转发：拿现有的 token 试一次（编排层会在 401 时走
            // `token.refresh` 那条强制刷新）
            Err(_) => {}
        }
    }
    let token = util::pick(&secret, &["accessToken"]);
    if token.is_empty() {
        return Err(Error::http(401, "WorkBuddy 账号缺少 accessToken，请重新登录"));
    }
    Ok(token)
}

/// 401（token 被服务端拒绝）后的**强制**刷新：不看临期窗口，直接续期。
///
/// ── 为什么必须与 `ensure` 分开 ──────────────────────────────
/// `ensure` 只在「临期」时才刷新，而 401 完全可能发生在一个时间上还很新的 token
/// 上（服务端侧失效、账号被顶下线、refreshToken 轮换）。此时只调 ensure 会拿回
/// 同一个被拒的 token，编排层的「刷新后同账号重试一次」就退化成「用同一个坏
/// token 再打一次」。
pub fn refresh() -> Result<String> {
    let before = record()?;
    let previous = before.get("secret").cloned().unwrap_or(Value::Null);
    let refresh_token = util::pick(&previous, &["refreshToken"]);
    if refresh_token.is_empty() {
        return Err(Error::http(400, "缺少 refreshToken，无法续期，请重新登录"));
    }
    let _lock = AccountLock::acquire()?;
    let current = record()?;
    let current_secret = current.get("secret").cloned().unwrap_or(Value::Null);
    // 并发请求可能刚好在前一轮落盘后到达：凭证已被别人换掉就直接用新的
    if !same_auth(&previous, &current_secret) {
        return access_of(&current_secret);
    }
    let session = outbound::session_of_record(&current_secret);
    let mut auth_value = session.get("auth").cloned().unwrap_or(Value::Null);
    auth_value["account"] = session.get("account").cloned().unwrap_or(Value::Null);
    let context = Context::make(
        current_secret.get("endpoint").and_then(Value::as_str),
        current_secret.get("prefixPath").and_then(Value::as_str),
        current_secret.get("platform").and_then(Value::as_str),
        Some(Region::edition_id()),
    );
    let next = auth::refresh_session(&auth_value, &context)?;
    // 上游换发成功还必须能取回**同一个账号身份**才允许替换本地凭证
    let identity = refresh_identity::verify(&current_secret, &next, &session)?;
    let updated = with_refresh(&current_secret, &next, &identity);
    let result = sdk::host(
        "account.update",
        json!({ "expect": current_secret, "secret": updated, "public": view(&updated) }),
    )?;
    if result.get("updated").and_then(Value::as_bool) != Some(true) {
        // 别的轮次已经写过：以磁盘上那份为准
        return access_of(&secret()?);
    }
    Ok(next.access_token)
}

/// 临期判定（`token.expiring`）。
///
/// 取不到会话（账号不存在 / 已无凭证）时返回 false（判不出来就不刷）。
/// 没有 refreshToken 的账号刷不了 —— 同样判成「不临期」（与网关同口径）。
pub fn expiring() -> Result<bool> {
    let record = match record() {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    if util::pick(&secret, &["refreshToken"]).is_empty() {
        return Ok(false);
    }
    let session = outbound::session_of_record(&secret);
    let expires_at = session
        .pointer("/auth/expiresAt")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    Ok(auth::is_token_expiring(expires_at))
}

fn access_of(secret: &Value) -> Result<String> {
    let token = util::pick(secret, &["accessToken"]);
    if token.is_empty() {
        Err(Error::http(401, "WorkBuddy 账号缺少 accessToken，请重新登录"))
    } else {
        Ok(token)
    }
}

/// 参与「同一份凭证」判定的字段（refresh.rs 的 `AUTH_KEYS`）。
const AUTH_KEYS: &[&str] = &[
    "uid",
    "enterpriseId",
    "type",
    "departmentFullName",
    "oneidAccountId",
    "idp",
    "tokenType",
    "accessToken",
    "refreshToken",
    "domain",
    "endpoint",
    "prefixPath",
    "platform",
    "edition",
];

fn same_auth(left: &Value, right: &Value) -> bool {
    AUTH_KEYS
        .iter()
        .all(|key| left.get(*key) == right.get(*key))
}

/// 把续期结果摊回扁平 secret（只覆盖确实拿到了的字段）。
fn with_refresh(secret: &Value, next: &auth::RefreshedAuth, identity: &Value) -> Value {
    let mut merged = secret.as_object().cloned().unwrap_or_default();
    merged.insert("accessToken".into(), json!(next.access_token));
    merged.insert("tokenTail".into(), json!(util::token_tail(&next.access_token)));
    if let Some(token) = next
        .refresh_token
        .as_ref()
        .filter(|token| !token.is_empty())
    {
        merged.insert("refreshToken".into(), json!(token));
    }
    if let Some(value) = next.expires_at.filter(|value| *value > 0.0) {
        merged.insert("expiresAt".into(), json!(value));
    }
    if let Some(value) = next.refresh_expires_at.filter(|value| *value > 0.0) {
        merged.insert("refreshExpiresAt".into(), json!(value));
    }
    if let Some(identity) = identity.as_object() {
        for (key, value) in identity {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

// ─── 公开视图与身份 ─────────────────────────────────────────

/// 公开视图（界面账号卡读的那几个键）。
///
/// 键名与 native `accounts::account_view` 对齐 —— 前端按 provider 渲染列，
/// 少一个 `editionLabel` 会让这一家的版本徽章变成空白。
pub fn view(secret: &Value) -> Value {
    let uid = util::pick(secret, &["uid"]);
    let name = util::pick(secret, &["name"]);
    let nickname = util::pick(secret, &["nickname"]);
    let edition = util::pick(secret, &["edition"]);
    let edition = if edition.is_empty() {
        Region::edition()
    } else {
        crate::endpoints::resolve_edition(Some(&edition))
    };
    let mut view = json!({
        "uid": uid,
        "name": if name.is_empty() { nickname.clone() } else { name },
        "nickname": nickname,
        "type": util::pick(secret, &["type"]),
        "enterpriseId": util::pick(secret, &["enterpriseId"]),
        "enterpriseName": util::pick(secret, &["enterpriseName"]),
        "tokenTail": util::token_tail(&util::pick(secret, &["accessToken"])),
        "hasRefreshToken": !util::pick(secret, &["refreshToken"]).is_empty(),
        "edition": edition.id,
        "editionLabel": edition.label,
        "endpoint": util::pick(secret, &["endpoint"]),
        "prefixPath": util::pick(secret, &["prefixPath"]),
        "available": !util::pick(secret, &["accessToken"]).is_empty(),
    });
    let expires_at = secret.get("expiresAt").cloned().unwrap_or(Value::Null);
    if let Some(object) = view.as_object_mut() {
        object.insert("expiresAt".to_string(), expires_at);
        object.insert(
            "refreshTokenExpiresAt".to_string(),
            secret.get("refreshExpiresAt").cloned().unwrap_or(Value::Null),
        );
    }
    view
}

/// 稳定身份：`user-<uid>`（与内置 `add_account` 逐字一致）。
///
/// 口径分叉的代价很具体：同一个账号「重新导入 / 重新粘贴」会被当成新记录，
/// 而内置实现那边是就地更新 —— 用户会看到两份一模一样的账号。
pub fn identity(secret: &Value) -> String {
    let uid = util::pick(secret, &["uid"]);
    if uid.is_empty() {
        return String::new();
    }
    format!("user-{uid}")
}

// ─── 账号规范化（`account.normalize`）────────────────────────

/// 把各种来源统一成一条可落库的账号。
///
/// ── 三条来源（对照 native `accounts::normalize`）──────────────
/// ```text
///   manual      粘贴嵌套形 auth.json，或 wb2api 那种扁平形
///   file_text   用户手选的登录态文件（内容与 Desktop 那份同构）
///   desktop     读本机官方客户端目录 —— wasm 没有文件系统，给出可读错误
///   file_base64 不支持（登录态是文本 JSON）
/// ```
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let explicit_name = params["name"].as_str().map(str::trim).filter(|value| !value.is_empty());
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            // 表单提交的原始 JSON；宿主把输入框整包放在 `inputs` 里时先拆一层
            let payload = &source["payload"];
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        Some("file_text") => {
            let text = source["content"].as_str().unwrap_or("").trim();
            if text.is_empty() {
                return Err(Error::http(400, "凭证文件是空的"));
            }
            serde_json::from_str::<Value>(text)
                .map_err(|_| Error::http(400, "凭证文件不是合法 JSON（请选择官方客户端登录后生成的 .info 文件）"))?
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "Wasm 插件读不到本机登录态文件（宿主沙箱里没有文件系统）。\
                 请在官方客户端目录里找到 workbuddy-desktop.info，用「文件导入」或「粘贴」这一项导入",
            ))
        }
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "WorkBuddy 的登录态是文本 JSON，请用「文件导入」选择 .info 文件（不支持二进制）",
            ))
        }
        _ => return Err(Error::http(400, "未知的 WorkBuddy 账号来源")),
    };
    account_of(&payload, explicit_name)
}

/// payload（嵌套形或扁平形）→ 账号。字段口径与内置 `add_account` 对齐。
fn account_of(payload: &Value, explicit_name: Option<&str>) -> Result<Value> {
    let Some(object) = payload.as_object() else {
        return Err(Error::http(400, "账号内容必须是 JSON 对象"));
    };
    let auth = object.get("auth").and_then(Value::as_object);
    let account = object.get("account").and_then(Value::as_object);

    // 嵌套形优先（官方客户端 / wb2api 导出），没有 `auth` 壳再回退顶层
    let access_token = pick_nested(auth, object, &["accessToken", "token", "access_token"]);
    let refresh_token = pick_nested(auth, object, &["refreshToken", "refresh_token"]);
    if access_token.is_empty() {
        return Err(Error::http(400, "缺少 accessToken"));
    }
    if access_token.chars().count() > MAX_TOKEN_LENGTH
        || refresh_token.chars().count() > MAX_TOKEN_LENGTH
    {
        return Err(Error::http(400, "token 过长"));
    }
    let uid = {
        let nested = account
            .and_then(|map| map.get("uid"))
            .or_else(|| object.get("uid"));
        util::truncate_text(&nested.map(value_text).unwrap_or_default(), MAX_IDENTITY_LENGTH)
    };
    if uid.is_empty() {
        return Err(Error::http(400, "缺少 uid（无法标识账号）"));
    }

    let mut secret = serde_json::Map::new();
    secret.insert("uid".to_string(), Value::String(uid.clone()));
    secret.insert("accessToken".to_string(), Value::String(access_token.clone()));
    if !refresh_token.is_empty() {
        secret.insert("refreshToken".to_string(), Value::String(refresh_token));
    }
    // 展示与组织字段：`account` 子对象优先，其次顶层（扁平形 wb2api 只给令牌）
    for (key, nested_key) in [
        ("nickname", "nickname"),
        ("type", "type"),
        ("enterpriseId", "enterpriseId"),
        ("enterpriseName", "enterpriseName"),
        ("departmentFullName", "departmentFullName"),
        ("oneidAccountId", "oneidAccountId"),
        ("idp", "idp"),
    ] {
        let value = account
            .and_then(|map| map.get(nested_key))
            .or_else(|| object.get(key))
            .map(value_text)
            .unwrap_or_default();
        if !value.is_empty() {
            secret.insert(
                key.to_string(),
                Value::String(util::truncate_text(&value, MAX_IDENTITY_LENGTH)),
            );
        }
    }
    for (key, candidates) in [
        ("expiresAt", ["expiresAt", "expires_at"]),
        ("refreshExpiresAt", ["refreshExpiresAt", "refresh_expires_at"]),
    ] {
        let value = pick_number(auth, object, &candidates);
        if value > 0.0 {
            secret.insert(key.to_string(), json!(value));
        }
    }
    let domain = pick_nested(auth, object, &["domain"]);
    if !domain.is_empty() {
        secret.insert("domain".to_string(), Value::String(domain));
    }
    if let Some(value) = auth
        .and_then(|fields| fields.get("tokenType"))
        .or_else(|| object.get("tokenType"))
    {
        if value.is_string() {
            secret.insert("tokenType".into(), value.clone());
        }
    }
    // 端点 / 前缀 / 平台：payload 显式给了就用它（自建网关场景），否则按地区兜底。
    // 三项都**必须**落下来：转发链的 `session_endpoint_of` 从记录读它们，缺了会
    // 退到地区默认值 —— 对自建网关就是打错站点（症状是「刚加的账号不能用」）。
    let info = Region::edition();
    for (key, fallback) in [
        ("endpoint", info.endpoint),
        ("prefixPath", info.prefix_path),
        ("platform", info.platform),
    ] {
        let given = object.get(key).map(value_text).unwrap_or_default();
        secret.insert(
            key.to_string(),
            Value::String(if given.is_empty() {
                fallback.to_string()
            } else {
                given
            }),
        );
    }
    secret.insert(
        "edition".to_string(),
        Value::String(Region::edition_id().to_string()),
    );
    secret.insert(
        "tokenTail".to_string(),
        Value::String(util::token_tail(&access_token)),
    );

    // 名字：显式给的 > 账号昵称 > `账号 <uid 前 8 位>`（与内置同款兜底）
    let nickname = secret
        .get("nickname")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let name = explicit_name
        .map(|value| util::truncate_text(value, MAX_NAME_LENGTH))
        .filter(|value| !value.trim().is_empty())
        .or_else(|| Some(nickname).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| format!("账号 {}", util::truncate_text(&uid, 8)));
    secret.insert("name".to_string(), Value::String(name));

    let secret = Value::Object(secret);
    Ok(json!({
        "public": view(&secret),
        "identity": identity(&secret),
        "secret": secret,
        // 快照形态：凭证落在记录里，没有「转发时实时读」那一层
        "desktop": false,
    }))
}

/// 嵌套 `auth` 对象优先、顶层兜底，取第一个非空文本。
fn pick_nested(
    auth: Option<&serde_json::Map<String, Value>>,
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> String {
    for key in keys {
        if let Some(value) = auth.and_then(|map| map.get(*key)) {
            let text = value_text(value);
            if !text.is_empty() {
                return text;
            }
        }
    }
    for key in keys {
        if let Some(value) = object.get(*key) {
            let text = value_text(value);
            if !text.is_empty() {
                return text;
            }
        }
    }
    String::new()
}

/// 同上，取第一个正数（毫秒时间戳）。
fn pick_number(
    auth: Option<&serde_json::Map<String, Value>>,
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> f64 {
    let read = |value: &Value| -> f64 {
        match value {
            Value::Number(number) => number.as_f64().unwrap_or(0.0),
            Value::String(text) => text.trim().parse::<f64>().unwrap_or(0.0),
            _ => 0.0,
        }
    };
    for key in keys {
        if let Some(value) = auth.and_then(|map| map.get(*key)) {
            let number = read(value);
            if number > 0.0 {
                return number;
            }
        }
    }
    for key in keys {
        if let Some(value) = object.get(*key) {
            let number = read(value);
            if number > 0.0 {
                return number;
            }
        }
    }
    0.0
}

/// JSON 值的文本形态（字符串去空白、数字转字符串、其余空串）。
fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => number.to_string(),
        _ => String::new(),
    }
}
