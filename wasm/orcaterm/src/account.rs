//! OrcaTerm 凭证：解析 / 续期 / 账号快照 / 账号面。
//!
//! ── 凭证形态（2026-10-16 桌面客户端 1.6.4 实测）────────────────
//! 微信 OAuth 登录后客户端持有一枚 HS256 JWT（`oauth_access_token`，约
//! **2 小时**时效），payload 里有 `userId`（数字 uid，CGI 的 `uin` 参数）、
//! `provider`、`iat` / `exp`。**只解 payload、不验签** —— token 好不好用
//! 由上游说了算。
//!
//! ── 本机登录态：wasm 侧换了入口 ────────────────────────────
//! native 的 `importDesktop: true` 直接读
//! `%APPDATA%\com.orcaterm-desktop.app\data.bin`（Tauri store，**明文 JSON**）。
//! wasm 沙箱没有文件系统，所以这条入口改成「文件导入 / 粘贴」：用户把 data.bin
//! 选进来，内容以 `file_text` / `file_base64` 到达本模块 —— 解析口径与 native
//! 读文件那一段**完全一致**（同一份 JSON、同样的 `oauth_access_token` /
//! `oauth_expires_at` / `auth_identity` 取值顺序）。`desktop` 来源因此返回一条
//! 可读错误，而不是假装读到了文件。
//!
//! ── 续期（上游有真续期接口）─────────────────────────────────
//! `OAuthRefreshToken` 传旧 token 换新（实测通过），因此 `refresh = true`：
//! 临期主动刷 + 401 强制刷，结果回写账号记录（**不回写 data.bin**：那是桌面
//! 客户端自己的数据，它在线时随时可能覆盖）。
//!
//! ── 并发：native 的进程内单飞 → 宿主账号锁 + 锁后重读 ────────
//! native 用 `flight::run` 保证同一账号只刷一次。wasm 没有跨调用共享内存，
//! 等价纪律是 `AccountLock` + 拿锁后重读账号：排队期间别人已经换过一轮的话
//! 直接用落盘那份，**绝不再拿刚被换掉的旧串去打一次**。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::codec;
use super::upstream;

/// 临期窗口（10 分钟；JWT 实测 2 小时时效，留足一次对话的余量）。
const EXPIRY_WINDOW_SECONDS: i64 = 10 * 60;

/// 登录态文件的大小上限（data.bin 正常约 1.5 KB；超限视为异常文件）。
///
/// native 在读 `%APPDATA%` 那份之前先看 `symlink_metadata().len()`；wasm 侧文件
/// 内容由网关读好再交进来，同样要在解码/解析之前挡一道。
const MAX_DATA_FILE_SIZE: usize = 256 * 1024;

/// 凭证在账号 `secret` 里的键名。
///
/// ── 为什么这几个名字不能改 ──────────────────────────────────
/// `secret` 是本插件的**不透明 JSON**（网关不解析），但 `metadata.json` 的
/// `account_features.expiry / identifier` 已经把 `tokenExpireAt` 与 `uid`
/// 写成了对外契约（网关按这两个键读「什么时候过期」「这个人是谁」）。改名只会
/// 让账号页的有效期列一直显示「—」，不会有任何报错。
pub const SECRET_TOKEN: &str = "accessToken";
pub const SECRET_EXPIRES_AT: &str = "tokenExpireAt";
pub const SECRET_UID: &str = "uid";
pub const SECRET_NAME: &str = "loginName";

/// 备注名（用户添加账号时自己起的名字）。native 只把名字放进 `public`，续期
/// 回写后就退回 `loginName` —— 这里多存一份，账号页的备注名才不会在第一次
/// 自动续期后消失。
const SECRET_DISPLAY_NAME: &str = "name";

/// 一条 OrcaTerm 登录态。
#[derive(Clone, Debug)]
pub struct Credentials {
    /// OAuth access token（HS256 JWT，Bearer 头本体）。
    pub access_token: String,
    /// JWT `exp`（**秒**；解析不出给 0 —— 按「判不出」处理）。
    pub expires_at: i64,
    /// 数字用户 id（JWT `userId` / CGI 的 `uin` 参数）。
    pub user_id: String,
    /// 展示名（`auth_identity.nickName` / `GetUserInfo`，best-effort）。
    pub nickname: String,
}

impl Credentials {
    /// JWT 是否已过期或临期（`exp` 判不出 → false）。
    pub fn is_expiring(&self) -> bool {
        self.is_expiring_at(sdk::now())
    }

    /// 同上，时间由调用方给（便于用固定时钟验证边界）。
    pub fn is_expiring_at(&self, now_ms: i64) -> bool {
        if self.expires_at <= 0 {
            return false;
        }
        let now = now_ms / 1000;
        self.expires_at.saturating_sub(now) < EXPIRY_WINDOW_SECONDS
    }

    /// 脱敏尾段（展示用；按**字符**取，避免多字节令牌把索引切坏）。
    pub fn token_tail(&self) -> String {
        token_tail_of(&self.access_token)
    }
}

/// 取令牌末尾 8 个字符（不足 8 个给空串）。
fn token_tail_of(token: &str) -> String {
    let token = token.trim();
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= 8 {
        return String::new();
    }
    chars[chars.len() - 8..].iter().collect()
}

/// 归一化一个粘贴到的 token：剥 `ot_session=` / `Bearer ` 前缀与空白。
pub fn normalize_token(raw: &str) -> String {
    let mut token = raw.trim().to_string();
    if let Some(rest) = token.strip_prefix("ot_session=") {
        token = rest.trim().to_string();
    }
    if let Some(rest) = token.strip_prefix("Bearer ").or_else(|| token.strip_prefix("bearer ")) {
        token = rest.trim().to_string();
    }
    token
}

/// 解码 JWT 的 payload 段（base64url → JSON；失败返回 None）。
fn decode_jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    if payload.is_empty() {
        return None;
    }
    let bytes = codec::base64_url_decode(payload)?;
    let claims = serde_json::from_slice::<Value>(&bytes).ok()?;
    claims.is_object().then_some(claims)
}

/// 从 JWT 里解出（userId, exp 秒）。
fn claims_of(token: &str) -> (String, i64) {
    let Some(claims) = decode_jwt_claims(token) else {
        return (String::new(), 0);
    };
    let user_id = claims
        .get("userId")
        .map(|value| match value {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_default();
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    (user_id, exp)
}

/// 秒 / 毫秒混写的到期时刻统一成**秒**（< 1e11 的当秒用）。
fn expiry_seconds(raw: i64) -> i64 {
    if raw >= 100_000_000_000 {
        raw / 1000
    } else {
        raw
    }
}

/// 从粘贴的 payload 解析凭证。
///
/// 支持三种形态：裸 token / data.bin 的 JSON 对象 / 嵌套 `{accessToken: "…"}`。
pub fn credentials_from_payload(payload: &Value) -> Result<Credentials> {
    let token = match payload {
        Value::String(text) => normalize_token(text),
        Value::Object(object) => {
            let direct = ["accessToken", "token", "oauth_access_token"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str))
                .map(normalize_token)
                .unwrap_or_default();
            if direct.is_empty() {
                return Err(Error::http(
                    400,
                    "缺少 accessToken（粘贴 OrcaTerm 的 JWT，或整个 data.bin 的内容）",
                ));
            }
            direct
        }
        _ => String::new(),
    };
    if token.split('.').count() != 3 {
        return Err(Error::http(
            400,
            "这不是一个有效的 OrcaTerm accessToken（JWT 应为三段点分）",
        ));
    }
    let (user_id, expires_at) = claims_of(&token);
    Ok(Credentials { access_token: token, expires_at, user_id, nickname: String::new() })
}

/// data.bin 形态的补充字段：`oauth_expires_at` 兜底到期时刻、`auth_identity` 补昵称。
///
/// 逐条沿用 native `read_desktop_credentials`：
///   - JWT 的 `exp` 优先（它才是权威），文件里的过期时刻只在 JWT 解不出时用；
///     文件里那份可能写成秒也可能写成毫秒，`expiry_seconds` 统一归一到秒。
///   - 昵称来自**内嵌的 JSON 字符串** `auth_identity`（`{"nickName":"…"}`），
///     不是对象 —— 直接按对象读只会一直读到空串。
fn enrich_from_desktop_file(credentials: &mut Credentials, payload: &Value) {
    if credentials.expires_at <= 0 {
        if let Some(seconds) = payload["oauth_expires_at"].as_i64().filter(|value| *value > 0) {
            credentials.expires_at = expiry_seconds(seconds);
        }
    }
    if credentials.nickname.trim().is_empty() {
        if let Some(nickname) = payload["auth_identity"]
            .as_str()
            .and_then(|identity| serde_json::from_str::<Value>(identity).ok())
            .and_then(|identity| identity["nickName"].as_str().map(str::to_string))
            .filter(|nickname| !nickname.trim().is_empty())
        {
            credentials.nickname = nickname;
        }
    }
}

/// 从账号 `secret` 解析凭证。
pub fn credentials_of(secret: &Value) -> Result<Credentials> {
    let token = normalize_token(secret[SECRET_TOKEN].as_str().unwrap_or(""));
    if token.is_empty() {
        return Err(Error::http(
            401,
            "OrcaTerm 账号缺少 accessToken：请重新导入或重新粘贴该账号",
        ));
    }
    let (jwt_user_id, jwt_exp) = claims_of(&token);
    Ok(Credentials {
        access_token: token,
        expires_at: secret[SECRET_EXPIRES_AT]
            .as_i64()
            .filter(|value| *value > 0)
            .map(expiry_seconds)
            .unwrap_or(jwt_exp),
        user_id: secret[SECRET_UID]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or(jwt_user_id),
        nickname: secret[SECRET_NAME].as_str().unwrap_or("").to_string(),
    })
}

/// 回写用的 `secret` 形状（`tokenExpireAt` 统一为 Unix 秒）。
pub fn secret_of(credentials: &Credentials) -> Value {
    json!({
        SECRET_TOKEN: credentials.access_token,
        SECRET_EXPIRES_AT: credentials.expires_at,
        SECRET_UID: credentials.user_id,
        SECRET_NAME: credentials.nickname,
    })
}

/// 账号的稳定身份（去重用）：`orcaterm-<userId>`，判不出用 token 尾。
pub fn identity_of(secret: &Value) -> String {
    let uid = secret[SECRET_UID].as_str().unwrap_or("").trim();
    if !uid.is_empty() {
        return format!("orcaterm-{uid}");
    }
    match credentials_of(secret) {
        Ok(credentials) => format!("orcaterm-{}", credentials.token_tail()),
        Err(_) => String::new(),
    }
}

/// 账号展示名：备注名 → `loginName` → `OrcaTerm <令牌尾>`。
fn display_name(secret: &Value, tail: &str) -> String {
    for key in [SECRET_DISPLAY_NAME, SECRET_NAME] {
        let value = secret[key].as_str().unwrap_or("").trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    if tail.is_empty() {
        "OrcaTerm 账号".to_string()
    } else {
        format!("OrcaTerm {tail}")
    }
}

/// 界面用的公开视图（`account.view`）。
///
/// 只出三个键：`name` / `uid` / `tokenTail` —— 与 native 的 `public_view` 逐字
/// 一致（前端按这三个键渲染账号行）。这里**容错**而不是报错：一条坏记录不该
/// 让整个账号列表渲染失败。
pub fn view(secret: &Value) -> Value {
    let token = normalize_token(secret[SECRET_TOKEN].as_str().unwrap_or(""));
    let tail = token_tail_of(&token);
    json!({
        "name": display_name(secret, &tail),
        "uid": secret[SECRET_UID].as_str().unwrap_or(""),
        "tokenTail": tail,
    })
}

// ─── 账号快照 ───────────────────────────────────────────────

/// 当前账号记录（宿主的 `account.get`）。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if record.is_null() {
        return Err(Error::http(
            401,
            "OrcaTerm 没有可用的登录凭证：请在账号页添加账号（粘贴 accessToken 或导入 data.bin）",
        ));
    }
    Ok(record)
}

/// 从账号记录解析凭证。
pub fn snapshot(record: &Value) -> Result<Credentials> {
    credentials_of(&record["secret"]).map_err(|error| {
        if error.status == Some(401) {
            Error::http(
                401,
                "OrcaTerm 没有可用的登录凭证：请在账号页添加账号（粘贴 accessToken 或导入 data.bin）",
            )
        } else {
            error
        }
    })
}

// ─── 续期（账号锁 + 回写）───────────────────────────────────

/// 刷新 JWT（成功后回写账号记录）。
///
/// `force = false` 时只在临期才刷新；`force = true` 时无条件刷新
/// （401 之后的那条路）。账号记录在锁内**重新读一次**，所以调用方手里那份
/// `record` 不参与写回判断 —— 那份可能已经过期了。
pub fn renew(credentials: &Credentials, force: bool) -> Result<Credentials> {
    if !force && !credentials.is_expiring() {
        return Ok(credentials.clone());
    }
    let _guard = AccountLock::acquire()?;
    // 拿锁之后重读：并发的另一路可能刚做完续期并写回
    let current_record = sdk::account()?;
    let current = credentials_of(&current_record["secret"])?;
    if current.access_token != credentials.access_token && !current.is_expiring() {
        return Ok(current);
    }
    let next = call_refresh_api(&current)?;
    let expect = secret_snapshot(&current_record["secret"]);
    write_back(&current_record, &expect, &next)
}

/// 调 `OAuthRefreshToken` 换新 token。
fn call_refresh_api(credentials: &Credentials) -> Result<Credentials> {
    let response = upstream::cgi_action(
        credentials,
        "OAuthRefreshToken",
        json!({ "accessToken": credentials.access_token }),
    )?;
    let code = response["Code"].as_i64().unwrap_or(-1);
    if code != 0 {
        let message = response["Message"].as_str().unwrap_or("未知错误");
        return Err(Error::http(
            401,
            format!(
                "OrcaTerm 续期失败（code={code}：{message}）；请重新导入 data.bin 或重新粘贴 accessToken"
            ),
        ));
    }
    let token = normalize_token(response["AccessToken"].as_str().unwrap_or(""));
    if token.is_empty() {
        return Err(Error::http(502, "OrcaTerm 续期响应缺少 AccessToken"));
    }
    let (user_id, expires_at) = claims_of(&token);
    let expires_at = if expires_at > 0 {
        expires_at
    } else {
        response["ExpiresIn"]
            .as_i64()
            .filter(|value| *value > 0)
            .map(|seconds| (sdk::now() / 1000).saturating_add(seconds))
            .unwrap_or(0)
    };
    Ok(Credentials {
        access_token: token,
        expires_at,
        user_id: if user_id.is_empty() { credentials.user_id.clone() } else { user_id },
        nickname: credentials.nickname.clone(),
    })
}

/// 把 secret 拍成一份对象（回写时的 `expect`）。
fn secret_snapshot(secret: &Value) -> Value {
    match secret {
        Value::Object(object) => Value::Object(object.clone()),
        _ => json!({}),
    }
}

/// 把换发结果并进既有 `secret`（**空值不覆盖**）。
///
/// 手工粘贴的凭据常常只有一把 accessToken；这时 `tokenExpireAt` / `loginName`
/// 的空值不能写进已有记录，否则等于把上次登录/探活拿到的身份信息洗掉。
fn secret_with(expect: &Value, credentials: &Credentials) -> Value {
    let mut secret = match expect {
        Value::Object(object) => object.clone(),
        _ => serde_json::Map::new(),
    };
    let mut fields: Vec<(&str, Value)> = vec![
        (SECRET_TOKEN, Value::String(credentials.access_token.clone())),
        (SECRET_UID, Value::String(credentials.user_id.clone())),
    ];
    if credentials.expires_at > 0 {
        fields.push((SECRET_EXPIRES_AT, Value::from(credentials.expires_at)));
    }
    if !credentials.nickname.trim().is_empty() {
        fields.push((SECRET_NAME, Value::String(credentials.nickname.clone())));
    }
    for (key, value) in fields {
        secret.insert(key.to_string(), value);
    }
    Value::Object(secret)
}

/// 条件回写账号记录（`account.update` 的 `expect` 是读到时的那份 secret）。
fn write_back(record: &Value, expect: &Value, credentials: &Credentials) -> Result<Credentials> {
    let next = secret_with(expect, credentials);
    let result = sdk::host(
        "account.update",
        json!({ "expect": expect, "secret": next, "public": view(&next) }),
    )?;
    if result["updated"] == true {
        return Ok(credentials.clone());
    }
    // 期间被改过（并发登录 / 手工粘贴）：以落盘那份为准，不把这次换发结果硬写。
    let latest = sdk::account()?;
    let current = credentials_of(&latest["secret"])?;
    if current.access_token == credentials.access_token || !current.is_expiring() {
        return Ok(current);
    }
    let account = record["id"].as_str().unwrap_or("");
    Err(Error::http(
        409,
        format!("OrcaTerm 账号 {account} 的续期结果未能落盘（期间被改过），请稍后重试"),
    ))
}

/// `token.ensure`：临期则续期，返回可用的 accessToken。
pub fn ensure() -> Result<String> {
    let record = record()?;
    let credentials = snapshot(&record)?;
    Ok(renew(&credentials, false)?.access_token)
}

/// `token.refresh`：无条件续期一次。
pub fn refresh() -> Result<String> {
    let record = record()?;
    let credentials = snapshot(&record)?;
    Ok(renew(&credentials, true)?.access_token)
}

/// `token.expiring`：后台凭证维护问「这条账号是不是快到期了」。
///
/// 判不出来就 false：宁可漏刷，也不要凭猜测打上游。
pub fn expiring(secret: &Value) -> bool {
    match credentials_of(secret) {
        Ok(credentials) => credentials.is_expiring(),
        Err(_) => false,
    }
}

// ─── 账号规范化 ─────────────────────────────────────────────

/// `account.normalize`：把粘贴 / 导入的凭据变成一条可落库的账号。
///
/// ── 四条来源 ────────────────────────────────────────────────
/// ```text
///   manual       粘贴 accessToken（表单可能把它放在 inputs / accessToken / token 下）
///   file_text    用户选的 data.bin（明文 JSON），也接受裸 token
///   file_base64  同上，只是网关把文件字节转成了 base64
///   desktop      本机登录态 —— wasm 没有文件系统，给出可读错误
/// ```
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            // 表单提交的原始 JSON；宿主把输入框整包放在 `inputs` 里时先拆一层
            let payload = &source["payload"];
            let payload = if payload["inputs"].is_object() { payload["inputs"].clone() } else { payload.clone() };
            pick_token_payload(payload)
        }
        Some("file_text") => {
            let text = source["content"].as_str().unwrap_or("").trim();
            if text.is_empty() {
                return Err(Error::http(400, "凭证文件是空的"));
            }
            if text.len() > MAX_DATA_FILE_SIZE {
                return Err(Error::http(
                    400,
                    format!("客户端登录态文件异常过大（{} 字节），拒绝读取", text.len()),
                ));
            }
            // 粘进来的可能是裸 token，也可能是一整份 data.bin 的 JSON
            serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.to_string()))
        }
        Some("file_base64") => {
            let text = source["content"].as_str().unwrap_or("");
            let bytes = codec::base64_decode(text)
                .ok_or_else(|| Error::http(400, "文件内容不是合法 base64"))?;
            if bytes.len() > MAX_DATA_FILE_SIZE {
                return Err(Error::http(
                    400,
                    format!("客户端登录态文件异常过大（{} 字节），拒绝读取", bytes.len()),
                ));
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| Error::http(400, "data.bin 不是 UTF-8 文本"))?;
            serde_json::from_str::<Value>(text.trim())
                .map_err(|error| Error::http(400, format!("data.bin 不是合法 JSON：{error}")))?
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "Wasm 插件读不到本机登录态文件（宿主沙箱里没有文件系统）。\
                 请在 %APPDATA%\\com.orcaterm-desktop.app\\data.bin 上点「文件导入」，\
                 或直接粘贴 accessToken",
            ))
        }
        _ => return Err(Error::http(400, "未知的 OrcaTerm 账号来源")),
    };

    let mut credentials = credentials_from_payload(&payload)?;
    // data.bin 里那两个补充字段（JWT 解不出到期时刻 / 没有昵称时才用）
    enrich_from_desktop_file(&mut credentials, &payload);
    // ── 尽力补身份（不阻断添加）─────────────────────────────
    // 探活失败仍允许落库：token 可能刚过期而用户马上就要续期，或者上游临时
    // 抖动。真正不可用的凭证会在转发时给出准确文案。
    if let Ok((user_id, nickname)) = upstream::fetch_user_info(&credentials) {
        if !user_id.is_empty() {
            credentials.user_id = user_id;
        }
        if !nickname.is_empty() {
            credentials.nickname = nickname;
        }
    }
    let explicit_name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let tail = credentials.token_tail();
    let name = match &explicit_name {
        Some(name) => name.clone(),
        None => match credentials.nickname.trim() {
            "" => {
                if tail.is_empty() {
                    "OrcaTerm 账号".to_string()
                } else {
                    format!("OrcaTerm {tail}")
                }
            }
            nickname => nickname.to_string(),
        },
    };
    let mut secret = secret_of(&credentials);
    if let Some(name) = explicit_name {
        secret[SECRET_DISPLAY_NAME] = json!(name);
    }
    let identity = identity_of(&secret);
    let mut public = view(&secret);
    public["name"] = json!(name);
    Ok(json!({
        "secret": secret,
        "public": public,
        "identity": identity,
        "desktop": false,
    }))
}

/// 表单提交的那一包 JSON 里，令牌可能在三个键名中的任意一个上。
fn pick_token_payload(payload: Value) -> Value {
    if !payload.is_object() {
        return payload;
    }
    for key in ["accessToken", "token", "oauth_access_token"] {
        if let Some(value) = payload.get(key) {
            return value.clone();
        }
    }
    payload
}

/// `login.callback` 换到凭证后落库用的账号形状（与 `normalize` 的产出一致）。
pub fn account_of(credentials: &Credentials) -> Value {
    let secret = secret_of(credentials);
    json!({
        "secret": secret,
        "public": view(&secret),
        "identity": identity_of(&secret),
        "desktop": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JWT 声明的已知向量（只取 `userId` / `exp`，不验签）。
    fn sample_token() -> String {
        // {"userId":10001,"exp":1700000000}
        let payload = "eyJ1c2VySWQiOjEwMDAxLCJleHAiOjE3MDAwMDAwMDB9";
        format!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.c2ln")
    }

    #[test]
    fn normalizes_prefixes() {
        assert_eq!(normalize_token("  Bearer abc.def.ghi  "), "abc.def.ghi");
        assert_eq!(normalize_token("ot_session=abc.def.ghi"), "abc.def.ghi");
        assert_eq!(normalize_token("bearer x"), "x");
        assert_eq!(normalize_token(""), "");
    }

    #[test]
    fn reads_claims_without_verifying() {
        let token = sample_token();
        let (uid, exp) = claims_of(&token);
        assert_eq!(uid, "10001");
        assert_eq!(exp, 1_700_000_000);
    }

    #[test]
    fn rejects_non_jwt() {
        let error = credentials_from_payload(&json!("not-a-jwt")).err();
        assert_eq!(error.and_then(|error| error.status), Some(400));
        // data.bin 的整份 JSON 要认（取 oauth_access_token）
        let payload = json!({ "oauth_access_token": sample_token() });
        assert!(credentials_from_payload(&payload).is_ok());
        // 没有任何令牌键时报可读错误，而不是造一条空账号
        assert!(credentials_from_payload(&json!({ "foo": 1 })).is_err());
    }

    #[test]
    fn expiry_boundary() {
        let credentials = Credentials {
            access_token: "x".repeat(16),
            expires_at: 1_700_000_000,
            user_id: "10001".into(),
            nickname: String::new(),
        };
        // 到期前 10 分钟以内算临期
        assert!(credentials.is_expiring_at(1_700_000_000 * 1000 - 9 * 60 * 1000));
        assert!(!credentials.is_expiring_at(1_700_000_000 * 1000 - 11 * 60 * 1000));
        // 判不出到期时刻一律 false（不凭猜测打上游）
        let unknown = Credentials { expires_at: 0, ..credentials };
        assert!(!unknown.is_expiring_at(0));
    }

    #[test]
    fn identity_prefers_uid() {
        let secret = json!({ SECRET_UID: "10001", SECRET_TOKEN: sample_token() });
        assert_eq!(identity_of(&secret), "orcaterm-10001");
        let no_uid = json!({ SECRET_TOKEN: sample_token() });
        assert!(identity_of(&no_uid).starts_with("orcaterm-"));
    }

    #[test]
    fn secret_merge_keeps_existing_fields() {
        let credentials = Credentials {
            access_token: sample_token(),
            expires_at: 1_700_000_000,
            user_id: "10001".into(),
            nickname: String::new(),
        };
        let expect = json!({ "name": "我的账号", SECRET_TOKEN: "old" });
        let next = secret_with(&expect, &credentials);
        assert_eq!(next["name"], json!("我的账号"));
        assert_eq!(next[SECRET_TOKEN], json!(sample_token()));
        assert_eq!(next[SECRET_EXPIRES_AT], json!(1_700_000_000));
    }

    /// data.bin 里的补充字段：JWT 没有 `exp` 时用 `oauth_expires_at`（毫秒归一到秒），
    /// 昵称来自**内嵌字符串** `auth_identity`。
    #[test]
    fn desktop_file_fields_fill_gaps() {
        // {"userId":10001} —— 故意不带 exp
        let payload = json!({
            "oauth_access_token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEwMDAxfQ.c2ln",
            "oauth_expires_at": 1_794_758_400_000i64,
            "auth_identity": "{\"nickName\":\"一颗苹果\"}",
        });
        let parsed = credentials_from_payload(&payload);
        assert!(parsed.is_ok(), "整份 data.bin 应当能解析");
        if let Ok(mut credentials) = parsed {
            enrich_from_desktop_file(&mut credentials, &payload);
            assert_eq!(credentials.user_id, "10001");
            assert_eq!(credentials.expires_at, 1_794_758_400);
            assert_eq!(credentials.nickname, "一颗苹果");
        }
    }
}
