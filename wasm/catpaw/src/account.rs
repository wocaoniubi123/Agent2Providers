//! CatPaw 凭证与账号面（native `credentials.rs` + `accounts.rs` 的合体）。
//!
//! ── 凭证形态（架构文档 §9.1）───────────────────────────────
//! CatPaw 的凭证是 Cookie 形态的 `X-Passport-Token` 值，`uid` 是**独立请求头**
//! （它不在 token 里，不是 JWT），所以本模块的产出不是一个字符串，而是
//! [`Credentials`]（token + uid）。
//!
//! ── 没有刷新机制（native `credentials.rs` 模块头，原样保留）────
//! CatPaw 没有 refreshToken 概念：`X-Passport-Token` 过期后只能**在桌面端重新
//! 登录**（`~/.meituan-catpaw/auth.json` 会被客户端刷新，所以桌面端账号是
//! 「重新登录即恢复」的）。因此：
//!   - `token.ensure` **只做存在性校验**，不做任何续期尝试；
//!   - `token.refresh` 如实报「本家没有刷新机制」，不假装能续期；
//!   - `token.expiring` **恒 false** —— 没有可判断的到期时刻（会话 Cookie），
//!     报 true 会让编排层去做一次必然失败的刷新。
//! 这不是漏掉的分支，是正确行为（native `refresh: false` 同）。
//!
//! ── 三处凭证来源（原项目 `resolveCredentials` 的优先级）──────
//! ```text
//!   1. 账号记录（手动粘贴 / 旧数据导入）→ secret.accessToken + uid|loginName
//!   2. 桌面端实时登录态 → 宿主 desktop.credentials.read 读 auth.json
//!   3. 环境变量旁路（CATPAW_COOKIE）→ wasm 沙箱没有环境变量，**不再支持**
//! ```
//! 第 3 条在 wasm 侧物理上不存在（没有 `std::env`），所以本包不申报
//! `env_credentials`；脚本 / CI 用户改为「建一条账号记录」。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

/// 桌面端实时账号的固定 id（原项目 `DESKTOP_ACCOUNT_ID`，逐字一致）。
///
/// 账号 id 是落进账号库与前端列表的契约，沿用原值让从旧代理迁移过来的用户
/// 一眼能认出同一条记录；重复导入必然命中同一条，幂等。
pub const DESKTOP_ACCOUNT_ID: &str = "desktop-auth";

/// 备注名长度上限（原项目 `name.trim().slice(0, 100)`）
const MAX_NAME_LENGTH: usize = 100;

/// uid / loginName 的长度上限（原项目 `MAX_USER_UID_LENGTH = 256`）
const MAX_USER_UID_LENGTH: usize = 256;

/// 余额查询凭证的字段名（与 `usage.rs` 同值；两边各自声明同一个字面量，
/// 比互相 import 更能暴露「有人改了其中一个」）。
const BALANCE_TOKEN_FIELD: &str = "balanceToken";

/// 一条 CatPaw 登录态（token + uid）。
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    /// `accessToken`（进 `Cookie: X-Passport-Token=<token>`）
    pub token: String,
    /// `user-uid` 头的值（账号的 uid / loginName）
    pub uid: String,
}

impl Credentials {
    pub fn new(token: impl Into<String>, uid: impl Into<String>) -> Self {
        Self { token: token.into(), uid: uid.into() }
    }

    /// token 尾段（展示用；**只在足够长时**给，见 `account_view` 的注释）
    fn token_tail(&self) -> String {
        let chars: Vec<char> = self.token.chars().collect();
        if chars.len() <= 8 {
            // 太短的 token 尾部等于它本身：公开视图里出现它会被宿主判成
            // 「公开视图包含受保护内容」而整条账号被拒收，所以干脆不给。
            return String::new();
        }
        chars[chars.len() - 4..].iter().collect()
    }
}

/// 取对象里的第一个非空字符串（键名按顺序试）。
pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("")
        .to_string()
}

/// 值 → 字符串（JS `String(x)`：数字/布尔按字面量、null 给空串）
fn js_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// 去 `Bearer ` 前缀（大小写不敏感，只去一次）。
fn strip_bearer_prefix(value: &str) -> String {
    const PREFIX: &str = "bearer";
    if value.len() < PREFIX.len() {
        return value.to_string();
    }
    let head = value.get(..PREFIX.len()).unwrap_or("");
    if !head.eq_ignore_ascii_case(PREFIX) {
        return value.to_string();
    }
    value.get(PREFIX.len()..).unwrap_or("").trim_start().to_string()
}

/// 字段校验（原项目 `safeString`）：非空、不超长、不含 CR/LF/分号。
///
/// 为什么要拦 `[\r\n;]`：这些值最终进 HTTP 头（Cookie / user-uid），换行是头
/// 注入，分号会让 Cookie 串被解析成另一段 —— 原项目因此在这里直接拒绝。
fn safe_field(value: String, field: &str, max_length: usize) -> Result<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::http(400, format!("CatPaw 登录态缺少 {field}")));
    }
    if trimmed.chars().count() > max_length || trimmed.contains(['\r', '\n', ';']) {
        return Err(Error::http(
            400,
            format!("CatPaw 登录态中的 {field} 格式无效"),
        ));
    }
    Ok(trimmed)
}

/// 是否桌面端实时账号（记录带 `desktop` 标记，或 id 就是固定值）。
pub fn is_desktop(secret: &Value) -> bool {
    secret.get("desktop").and_then(Value::as_bool).unwrap_or(false)
        || secret.get("id").and_then(Value::as_str) == Some(DESKTOP_ACCOUNT_ID)
}

/// 读本机客户端登录态（`desktop` 来源）。
///
/// 宿主只在「用户明确选择本机导入」或「这条账号本来就是本机导入型」两种上下文
/// 里授权这次读取；其余上下文会直接拒绝（错误文案由宿主给，这里只转述）。
///
/// ── 为什么 wasm 侧必须走宿主 ────────────────────────────────
/// wasm 沙箱没有文件系统，读不到 `~/.meituan-catpaw/auth.json`。网关为 catpaw
/// 开了固定本机来源 `desktop.credentials.catpaw.v1`（`plugin_host/wasm/
/// desktop_credentials.rs` 的 `HELPER_CATPAW`），宿主替我们把那份 JSON 读完并
/// 归一成 `{accessToken, uid, loginName, loginType}`。
pub fn read_desktop() -> Result<Credentials> {
    let value = sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(
            503,
            format!("没有可用的 CatPaw 登录态：读取本机登录态失败（{}）", error.message),
        )
    })?;
    let token = text(&value, &["accessToken", "access_token", "token"]);
    if token.is_empty() {
        return Err(Error::http(503, "本机 CatPaw 客户端登录态里没有 accessToken"));
    }
    let uid = text(&value, &["uid", "userId"]);
    let login_name = text(&value, &["loginName"]);
    Ok(Credentials::new(token, if uid.is_empty() { login_name } else { uid }))
}

/// 从账号 secret 取凭证（账号记录形态）。
///
/// 桌面端记录**不落 token**（每次实时读），所以这里必须分流：桌面端记录 →
/// 宿主读取；普通记录 → `accessToken`。
pub fn credentials_of(secret: &Value) -> Result<Credentials> {
    if is_desktop(secret) {
        return read_desktop();
    }
    let token = text(secret, &["accessToken", "access_token", "token"]);
    if token.is_empty() {
        return Err(Error::http(
            401,
            "CatPaw 没有可用的登录凭证：请在账号页添加账号（粘贴登录态或导入本机登录态）",
        ));
    }
    let uid = text(secret, &["uid"]);
    let uid = if uid.is_empty() { text(secret, &["loginName"]) } else { uid };
    Ok(Credentials::new(token, uid))
}

/// 当前账号的凭证（宿主已按 `params.account` 选好号）。
pub fn current() -> Result<Credentials> {
    let record = sdk::account()?;
    credentials_of(&record["secret"])
}

/// `token.ensure`：取可用凭证，**只做存在性校验**（本家没有刷新机制）。
pub fn ensure() -> Result<String> {
    let credentials = current()?;
    if credentials.token.trim().is_empty() {
        return Err(Error::http(
            401,
            "CatPaw 没有可用的登录凭证：请在账号页添加账号（粘贴登录态或导入本机登录态）",
        ));
    }
    Ok(credentials.token)
}

/// `token.refresh`：如实报「本家没有刷新机制」。
///
/// 上层（编排层的 401 重试）不会为本家走到这里（`metadata.capabilities.refresh`
/// 是 false）；真被调到就是接口误用，给一条可操作的文案而不是静默返回旧 token。
pub fn refresh() -> Result<String> {
    Err(Error::http(
        401,
        "CatPaw 登录态没有刷新机制：X-Passport-Token 过期后请在桌面端重新登录，再重新导入登录态",
    ))
}

/// `token.expiring`：恒 false（见模块头）。
pub fn expiring(_secret: &Value) -> bool {
    false
}

/// 账号的稳定身份：`uid || loginName`，桌面端固定 `desktop-auth`。
pub fn identity_of(secret: &Value) -> String {
    if secret.get("id").and_then(Value::as_str) == Some(DESKTOP_ACCOUNT_ID) {
        return DESKTOP_ACCOUNT_ID.to_string();
    }
    let uid = text(secret, &["uid"]);
    if !uid.is_empty() {
        return uid;
    }
    text(secret, &["loginName"])
}

/// 账号公开视图（界面账号页读的那几个键，与网关 `to_catpaw_public_account` 对应）。
///
/// ── 桌面端账号为什么要实时读一次 ───────────────────────────
/// 那条记录的凭证不在库里（每次实时读文件），`tokenTail` / `uid` 在库里是
/// 「上次导入时的快照」。用户重新登录后客户端会改写 auth.json —— 不实时读
/// 就会显示一个已经不存在的令牌尾，而且「可用性」也无从判断。
///
/// 读不到时**不报错**：回落记录里的存量值并把 `available` 置 false，
/// 附一句 `reason`（前端据此提示「请先在 CatPaw 桌面端登录」）。
pub fn account_view(secret: &Value) -> Value {
    let desktop = is_desktop(secret);
    let mut token_tail = text(secret, &["tokenTail"]);
    let mut uid = text(secret, &["uid"]);
    let mut login_name = text(secret, &["loginName"]);
    let mut available = true;
    let mut reason = String::new();
    if desktop {
        match read_desktop() {
            Ok(credentials) => {
                token_tail = credentials.token_tail();
                if !credentials.uid.is_empty() {
                    uid = credentials.uid;
                }
                login_name = text(secret, &["loginName"]);
            }
            Err(error) => {
                available = false;
                reason = error.message;
            }
        }
    }
    let mut view = json!({
        "name": text(secret, &["name"]),
        "uid": uid,
        "loginName": login_name,
        "tokenTail": token_tail,
        "desktop": desktop,
        "source": text(secret, &["source"]),
        "available": available,
        // 余额凭证**只透出「配没配」**，绝不透出值本身：账号列表是会被截图 /
        // 贴出来排障的界面，而这一项是完整的会话凭证。
        "hasBalanceToken": !text(secret, &[BALANCE_TOKEN_FIELD]).is_empty(),
    });
    if !reason.is_empty() {
        if let Some(object) = view.as_object_mut() {
            object.insert("reason".to_string(), Value::String(reason));
        }
    }
    view
}

/// 一次归一化的产物（对应 `proto::NormalizedAccount`）。
fn account_of(
    user_key: &str,
    uid: &str,
    login_name: &str,
    token: &str,
    balance_token: Option<&str>,
    source: &str,
    explicit_name: Option<String>,
    desktop: bool,
) -> Value {
    let credentials = Credentials::new(token, if uid.is_empty() { login_name } else { uid });
    let mut secret = serde_json::Map::new();
    // id 用 `user_key`（uid 优先、loginName 兜底）—— 与网关 `add_catpaw_account` 一致
    secret.insert("id".to_string(), Value::String(user_key.to_string()));
    secret.insert("uid".to_string(), Value::String(uid.to_string()));
    secret.insert("loginName".to_string(), Value::String(login_name.to_string()));
    secret.insert("accessToken".to_string(), Value::String(token.to_string()));
    secret.insert(
        "tokenTail".to_string(),
        Value::String(credentials.token_tail()),
    );
    // 取不到就不出键 ——「未配置」是有意义的状态（前端据此提示去配置），
    // 写一个空串会让「配置了但填错」与「没配置」不可区分。
    if let Some(balance_token) = balance_token {
        secret.insert(
            BALANCE_TOKEN_FIELD.to_string(),
            Value::String(balance_token.to_string()),
        );
    }
    secret.insert("source".to_string(), Value::String(source.to_string()));
    secret.insert("desktop".to_string(), Value::Bool(desktop));
    // 备注名兜底照抄原项目：显式传入 → loginName → uid
    let name = explicit_name
        .or_else(|| Some(login_name.to_string()).filter(|value| !value.is_empty()))
        .or_else(|| Some(uid.to_string()).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| format!("账号 {user_key}"));
    secret.insert(
        "name".to_string(),
        Value::String(name.chars().take(MAX_NAME_LENGTH).collect()),
    );
    let secret = Value::Object(secret);
    json!({
        "secret": secret,
        "public": account_view(&secret),
        "identity": identity_of(&secret),
        "desktop": desktop,
    })
}

/// 桌面端实时账号：记录里**不落 token**，只写 `desktop: true` 与展示字段。
fn desktop_account() -> Result<Value> {
    let credentials = read_desktop()?;
    let mut secret = serde_json::Map::new();
    secret.insert("id".to_string(), Value::String(DESKTOP_ACCOUNT_ID.to_string()));
    secret.insert("desktop".to_string(), Value::Bool(true));
    secret.insert("source".to_string(), Value::String("desktop".to_string()));
    secret.insert("uid".to_string(), Value::String(credentials.uid.clone()));
    secret.insert("loginName".to_string(), Value::String(String::new()));
    secret.insert(
        "tokenTail".to_string(),
        Value::String(credentials.token_tail()),
    );
    secret.insert(
        "desktopMtime".to_string(),
        Value::Number(serde_json::Number::from(sdk::now())),
    );
    let default_name = if credentials.uid.is_empty() {
        "桌面端登录账号".to_string()
    } else {
        format!("桌面端登录账号（{}）", credentials.uid)
    };
    secret.insert("name".to_string(), Value::String(default_name));
    let secret = Value::Object(secret);
    Ok(json!({
        "secret": secret,
        "public": account_view(&secret),
        "identity": DESKTOP_ACCOUNT_ID,
        "desktop": true,
    }))
}

/// 取第一个非空文本并做 token 级校验（去 `Bearer ` 前缀、去空白）。
fn pick_first_text(candidates: &[Option<&Value>]) -> Result<String> {
    for value in candidates.iter().flatten() {
        let text = js_string(value);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        return safe_field(strip_bearer_prefix(trimmed), "token", 8192);
    }
    Err(Error::http(
        400,
        "缺少 CatPaw 登录凭证（token / accessToken / access_token）",
    ))
}

/// 取第一个非空文本（不校验，仅用于 uid / loginName / name 这类可选字段）
fn pick_first_optional(candidates: &[Option<&Value>]) -> String {
    for value in candidates.iter().flatten() {
        if value.is_null() {
            continue;
        }
        let text = js_string(value).trim().to_string();
        if !text.is_empty() {
            return text;
        }
    }
    String::new()
}

/// 从添加 payload 里取余额查询凭证（`balanceToken`，可选）。
///
/// 三种键名都认（顺序即优先级）：`balanceToken`、`token2`、`balanceCookie.token2`。
/// 校验失败时**跳过这一个候选**而不是让整条添加失败：余额凭证是可选字段，
/// 填错它不该把「添加账号」这个主流程堵死。
fn pick_balance_token(object: &serde_json::Map<String, Value>, auth: &serde_json::Map<String, Value>) -> Option<String> {
    let candidates: Vec<Option<&Value>> = vec![
        object.get("balanceToken"),
        object.get("token2"),
        auth.get("token2"),
        object.get("balanceCookie").and_then(|cookie| cookie.get("token2")),
    ];
    for value in candidates.into_iter().flatten() {
        let text = js_string(value).trim().to_string();
        if text.is_empty() {
            continue;
        }
        let trimmed = strip_bearer_prefix(&text);
        if let Ok(safe) = safe_field(trimmed, BALANCE_TOKEN_FIELD, 8192) {
            return Some(safe);
        }
    }
    None
}

/// 对象或空表（`payload.auth` / `payload.account` 可能缺失）
fn object_or_empty(value: Option<&Value>) -> serde_json::Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => serde_json::Map::new(),
    }
}

/// `account.normalize`：四条来源路径的入口。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    // 桌面端：记录里不落 token（每次实时读），只写引用与展示字段
    if kind == "desktop" {
        return desktop_account();
    }
    let payload = match kind {
        "manual" => {
            let payload = &source["payload"];
            // 前端把登录方式（browser / token / desktop）放在 `login` 里
            if payload["login"] == "desktop" {
                return desktop_account();
            }
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        "file_text" => serde_json::from_str(source["content"].as_str().unwrap_or(""))
            .map_err(|_| Error::http(
                400,
                "CatPaw 凭证文件不是合法 JSON，请选择 auth.json 或单账号 JSON 文件",
            ))?,
        "file_base64" => {
            return Err(Error::http(
                400,
                "CatPaw 不支持二进制凭证文件，请选择 auth.json 或单账号 JSON 文件",
            ))
        }
        other => {
            return Err(Error::http(
                400,
                format!("CatPaw 不认识的添加方式「{other}」：请粘贴登录态、导入本机登录态或选择 auth.json 文件"),
            ))
        }
    };
    let Some(object) = payload.as_object() else {
        return Err(Error::http(400, "上传内容必须是 JSON 对象"));
    };
    let auth = object_or_empty(object.get("auth"));
    let account = object_or_empty(object.get("account"));
    // 登录方式：auth.json 形态下必查（原项目同）；扁平形态通常没有这个字段
    let login_type = auth
        .get("loginType")
        .or_else(|| object.get("loginType"))
        .map(js_string)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    if !login_type.is_empty() && login_type != "passport" {
        return Err(Error::http(
            400,
            format!("暂不支持 CatPaw 登录方式 {login_type}（仅支持 passport）"),
        ));
    }
    let token = pick_first_text(&[
        object.get("token"),
        object.get("accessToken"),
        object.get("access_token"),
        object.get("auth_token"),
        auth.get("accessToken"),
        auth.get("token"),
        auth.get("access_token"),
    ])?;
    let uid_raw = pick_first_optional(&[
        object.get("uid"),
        object.get("userId"),
        account.get("uid"),
        account.get("userId"),
        // 原项目的账号记录：id 就是 uid 或 loginName（uid 缺失时才用它兜底）
        object.get("id"),
    ]);
    let login_name = pick_first_optional(&[object.get("loginName"), account.get("loginName")]);
    let user_key = if !uid_raw.trim().is_empty() {
        uid_raw.trim().to_string()
    } else {
        login_name.trim().to_string()
    };
    if user_key.is_empty() {
        return Err(Error::http(
            400,
            "CatPaw 登录态缺少 uid 或 loginName（无法标识账号）",
        ));
    }
    let user_key = safe_field(user_key, "uid", MAX_USER_UID_LENGTH)?;
    let uid = if uid_raw.trim().is_empty() {
        String::new()
    } else {
        safe_field(uid_raw, "uid", MAX_USER_UID_LENGTH)?
    };
    let login_name = if login_name.trim().is_empty() {
        String::new()
    } else {
        safe_field(login_name, "loginName", MAX_USER_UID_LENGTH)?
    };
    let balance_token = pick_balance_token(object, &auth);
    let payload_name = pick_first_optional(&[object.get("name"), account.get("name")]);
    let explicit_name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_NAME_LENGTH).collect::<String>());
    Ok(account_of(
        &user_key,
        &uid,
        &login_name,
        &token,
        balance_token.as_deref(),
        "manual",
        explicit_name.or_else(|| Some(payload_name).filter(|value| !value.is_empty())),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_flat_payload() {
        let params = json!({
            "source": { "kind": "manual", "payload": { "token": "tk-1234567890", "uid": "u1" } },
            "name": "我的号"
        });
        let account = normalize(&params).unwrap_or(Value::Null);
        assert_eq!(account["identity"], json!("u1"));
        assert_eq!(account["secret"]["accessToken"], json!("tk-1234567890"));
        assert_eq!(account["public"]["name"], json!("我的号"));
        assert_eq!(account["desktop"], json!(false));
    }

    #[test]
    fn normalize_auth_json_payload() {
        let params = json!({
            "source": { "kind": "manual", "payload": {
                "auth": { "loginType": "passport", "accessToken": "abcdefghijklmn" },
                "account": { "uid": "u2", "loginName": "二号" }
            }}
        });
        let account = normalize(&params).unwrap_or(Value::Null);
        assert_eq!(account["identity"], json!("u2"));
        assert_eq!(account["secret"]["loginName"], json!("二号"));
    }

    #[test]
    fn normalize_rejects_wrong_login_type_and_missing_identity() {
        let wrong = json!({
            "source": { "kind": "manual", "payload": {
                "auth": { "loginType": "wechat", "accessToken": "abcdefghijklmn" },
                "account": { "uid": "u" }
            }}
        });
        assert!(normalize(&wrong).is_err());
        let missing = json!({
            "source": { "kind": "manual", "payload": { "token": "abcdefghijklmn" } }
        });
        assert!(normalize(&missing).is_err());
    }

    #[test]
    fn view_hides_short_token_tail() {
        let secret = json!({ "id": "u", "accessToken": "short", "uid": "u", "source": "manual" });
        let view = account_view(&secret);
        assert_eq!(view["tokenTail"], json!(""));
        assert_eq!(view["available"], json!(true));
    }
}
