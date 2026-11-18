//! LobsterAI 登录与续期：**浏览器授权 + 回调带回一次性 code + 换码**。
//!
//! 迁移来源：`crates/providers/src/providers/lobsterai/oauth.rs`。
//!
//! ── 四步 ────────────────────────────────────────────────────
//! ```text
//!   1. 插件按 state 登记一轮登录，产出授权地址：
//!        {portal}/portal#/login?source=electron
//!                    &redirect_uri=<宿主给的回调地址>
//!                    &state=<flow>
//!   2. 用户在浏览器里授权（手机号 / 微信），门户 302 回那个回调地址
//!   3. POST {api}/api/auth/exchange   **不带 Authorization**
//!        体 { authCode, firstKeyfrom, latestKeyfrom, uuid, version }
//!   4. 落账号（把 uuid 与两个 keyfrom 一起存 —— 见 `credentials.rs` 的模块头）
//! ```
//!
//! ── 回调路径为什么不用 `-lobsterai` 后缀 ──────────────────────
//! 本仓其余几家自作主张的回调路径都带家名后缀（`/auth/callback-accio` 等），
//! 一眼能看出归属。这一家**例外**：授权地址里的 `redirect_uri` 是我们拼给门户的，
//! 门户会按它回落 —— 参考实现用的就是裸 `/auth/callback`（`lobsterai.ts:47`），
//! 而门户是否对回调路径有白名单**没有实测支撑**。所以这里跟随参考实现那条
//! 已验证的形状，不为了命名风格去赌一次未经验证的兼容性。
//!
//! ── 续期：**必须原样回传载荷件，且 `latestKeyfrom` 永不更新** ─────
//! `POST /api/auth/refresh` 同样**不带 Authorization**，体是
//! `{ firstKeyfrom, latestKeyfrom, version, [uuid], [userId], refreshToken }`。
//! 响应带新 `refreshToken` 时才轮换；`latestKeyfrom` **不覆盖**（照实测的形态，
//! 见 `credentials.rs` 的模块头）。
//!
//! ── 两种「成功状态下的失败」 ──────────────────────────────────
//!   1. 业务信封 `code != 0` → 按错误处理；
//!   2. 信封 `code == 0` 但 `data` 为 null → **令牌已失效**（参考实现实测）。
//!      这一条最容易漏：只看 HTTP 状态或只看 `code` 都会把它当成成功。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::credentials::Credentials;
use super::errors;
use super::upstream::{
    self, EXCHANGE_PATH, MAX_BODY_BYTES, REFRESH_PATH, USER_AGENT,
};

/// 一次令牌包的解析结果（换码与续期共用）
#[derive(Clone, Debug, Default)]
pub struct TokenBundle {
    /// `accessToken`
    pub access_token: String,
    /// `refreshToken`（可能为空：续期响应不带新 token 时保留旧的）
    pub refresh_token: String,
    /// `expiresIn`（秒）
    pub expires_in: i64,
    /// 上游用户 id（`user.id`）—— 账号 id 与 keyfrom 都要它
    pub uid: String,
    /// `user.userId`
    pub user_id: String,
    /// `user.nickname`
    pub nickname: String,
}

/// 解业务信封 `{code, msg, data}`。
///
/// `code == 0` 且 `data` **非 null** 才算成功 —— `data: null` 配 `code: 0`
/// 是「令牌子失效」的形态（参考实现实测），把它当成功会让上层拿空令牌去发请求。
pub fn unwrap_envelope(payload: &Value, what: &str) -> Result<Value> {
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    let message = payload
        .get("msg")
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if code != 0 {
        let detail = if message.is_empty() {
            format!("code={code}")
        } else {
            message.to_string()
        };
        return Err(Error::http(502, format!("LobsterAI {what}失败：{detail}")));
    }
    // `code == 0` 之后只剩「data 是 null / 缺失」这一种失败形态 ——
    // 判据走 `errors::envelope_reports_dead_session`（同一条规则只写一份）。
    if errors::envelope_reports_dead_session(payload) {
        return Err(Error::http(
            401,
            format!("LobsterAI {what}未返回数据（登录态可能已失效），请重新登录"),
        ));
    }
    payload
        .get("data")
        .cloned()
        .ok_or_else(|| Error::http(502, format!("LobsterAI {what}响应缺少 data")))
}

/// 从令牌信封的 `data` 里解出 [`TokenBundle`]。
pub fn parse_token_bundle(data: &Value) -> Result<TokenBundle> {
    let access_token = data
        .get("accessToken")
        .or_else(|| data.get("access_token"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        return Err(Error::http(502, "LobsterAI 换码响应缺少 accessToken"));
    }
    let user = data.get("user").cloned().unwrap_or(Value::Null);
    let str_of = |value: &Value, key: &str| -> String {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let refresh_token = {
        let token = str_of(data, "refreshToken");
        if token.is_empty() {
            str_of(data, "refresh_token")
        } else {
            token
        }
    };
    let expires_in = data
        .get("expiresIn")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(0);
    let uid = {
        let id = str_of(&user, "id");
        if id.is_empty() {
            str_of(&user, "yid")
        } else {
            id
        }
    };
    Ok(TokenBundle {
        access_token,
        refresh_token,
        expires_in,
        uid,
        user_id: str_of(&user, "userId"),
        nickname: str_of(&user, "nickname"),
    })
}

/// 用授权码换令牌（**不带 Authorization**）。
///
/// 体固定五个字段：`authCode` + 两个 keyfrom + `uuid` + `version`。
/// `uuid` 由调用方生成并**落盘**（续期要它）—— 它不是凭据，是这一台「客户端」的标识。
pub fn exchange(
    auth_code: &str,
    uuid: &str,
    first_keyfrom: &str,
    latest_keyfrom: &str,
    client_version: &str,
) -> Result<TokenBundle> {
    let body = json!({
        "authCode": auth_code,
        "firstKeyfrom": first_keyfrom,
        "latestKeyfrom": latest_keyfrom,
        "uuid": uuid,
        "version": client_version,
    });
    let payload = post_anonymous(EXCHANGE_PATH, &body, "换码")?;
    let data = unwrap_envelope(&payload, "换码")?;
    parse_token_bundle(&data)
}

/// 续期（**不带 Authorization**）：载荷件原样回传 + `refreshToken`。
pub fn refresh(credentials: &Credentials, client_version: &str) -> Result<TokenBundle> {
    if !credentials.can_refresh() {
        return Err(Error::http(
            401,
            "LobsterAI 账号缺少续期所需的载荷件（uuid / keyfrom 之一为空），请重新登录",
        ));
    }
    let mut body = serde_json::Map::new();
    for (key, value) in credentials.keyfrom_fields(client_version) {
        body.insert(key.to_string(), Value::String(value));
    }
    body.insert(
        "refreshToken".to_string(),
        Value::String(credentials.refresh_token.clone()),
    );
    let payload = post_anonymous(REFRESH_PATH, &Value::Object(body), "续期")?;
    let data = unwrap_envelope(&payload, "续期")?;
    parse_token_bundle(&data)
}

/// 发一次匿名 POST（换码与续期都不带 Authorization）。
fn post_anonymous(path: &str, body: &Value, what: &str) -> Result<Value> {
    let url = format!("{}{}", upstream::API_BASE, path);
    let headers = vec![
        ("accept".to_string(), "application/json".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("user-agent".to_string(), USER_AGENT.to_string()),
    ];
    let reply = upstream::send("POST", &url, &headers, Some(body), MAX_BODY_BYTES)?;
    // 401 / 403 直接归成登录态问题，别让信封里的文案把方向带偏
    if matches!(reply.status, 401 | 403) {
        return Err(Error::http(
            401,
            format!("LobsterAI {what}被拒（HTTP {}），请重新登录", reply.status),
        ));
    }
    if !reply.ok() {
        return Err(Error::http(
            reply.status,
            format!("LobsterAI {what}返回 HTTP {}", reply.status),
        ));
    }
    reply
        .json()
        .ok_or_else(|| Error::http(502, format!("LobsterAI {what}响应不是 JSON")))
}

/// 从回调的 query 里取 `(code, state)`。
///
/// 门户可能带回额外参数（微信授权那条链会挂 `scope` 之类），所以按键找而不是
/// 按位置切。缺任一项就是 `None`（这一轮回调不完整，别去换码）。
pub fn parse_callback(query: &str) -> Option<(String, String)> {
    let mut code = String::new();
    let mut state = String::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let decoded = urldecode(value);
        match key.trim() {
            "code" | "authCode" | "auth_code" => code = decoded,
            "state" => state = decoded,
            _ => {}
        }
    }
    if code.is_empty() {
        return None;
    }
    Some((code, state))
}

/// 极小的 query 解码（`+` 当空格，`%XX` 还原）。
///
/// 不引依赖：回调只有两三个参数，且值都是可见 ASCII 记号。
pub fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 授权地址：`{portal}/portal#/login?source=electron&redirect_uri=…&state=…`
pub fn build_authorize_url(return_url: &str, state: &str) -> String {
    format!(
        "{}/portal#/login?source=electron&redirect_uri={}&state={}",
        upstream::PORTAL_BASE,
        upstream::urlencode(return_url),
        upstream::urlencode(state)
    )
}

/// 从回调里取出授权码。
///
/// 两种入口给的东西不同：`login.callback` 的 `code` 可能已经是纯 code，也可能是
/// **整条回调 URL**（壳侧把地址栏那条原样交回来）。两种形态都要认。
pub fn callback_code(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return fallback.trim().to_string();
    }
    if !trimmed.contains('=') {
        return trimmed.to_string();
    }
    // 带 `?` 的取问号之后那段；不带 `?` 的（如 `code=…&state=…`）整条当 query
    let query = match trimmed.split_once('?') {
        Some((_, query)) => query,
        None => trimmed,
    };
    match parse_callback(query) {
        Some((code, _)) => code,
        // 解析不出（参数名不是我们认的那几个）→ 原样交给上游去判，别在这里猜
        None => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_requires_non_null_data() {
        let ok = json!({ "code": 0, "msg": "success", "data": { "accessToken": "t" } });
        assert!(unwrap_envelope(&ok, "换码").is_ok());
        // data:null + code:0 = 令牌失效，**不是**成功
        let dead = json!({ "code": 0, "data": Value::Null });
        let error = unwrap_envelope(&dead, "换码")
            .err()
            .unwrap_or_else(|| Error::new("data:null 时必须报错"));
        assert_eq!(error.status, Some(401));
        // code != 0 → 502，文案带上游 msg
        let failing = json!({ "code": 40100, "msg": "token rejected" });
        let error = unwrap_envelope(&failing, "换码")
            .err()
            .unwrap_or_else(|| Error::new("code!=0 时必须报错"));
        assert_eq!(error.status, Some(502));
        assert!(error.message.contains("token rejected"));
        // 没有 msg 时用 code 兜底
        let bare = json!({ "code": 7 });
        let error = unwrap_envelope(&bare, "续期")
            .err()
            .unwrap_or_else(|| Error::new("code!=0 时必须报错"));
        assert!(error.message.contains("code=7"));
    }

    #[test]
    fn token_bundle_reads_both_casings_and_user_block() {
        let data = json!({
            "accessToken": "a",
            "refreshToken": "r",
            "expiresIn": 2592000,
            "user": { "id": "u1", "userId": "s1", "nickname": "龙虾" }
        });
        let bundle = parse_token_bundle(&data).unwrap_or_default();
        assert_eq!(bundle.access_token, "a");
        assert_eq!(bundle.refresh_token, "r");
        assert_eq!(bundle.expires_in, 2592000);
        assert_eq!(bundle.uid, "u1");
        assert_eq!(bundle.user_id, "s1");
        assert_eq!(bundle.nickname, "龙虾");

        // 下划线形态 + user.yid 兜底
        let data = json!({
            "access_token": "a2",
            "refresh_token": "r2",
            "user": { "yid": "y1" }
        });
        let bundle = parse_token_bundle(&data).unwrap_or_default();
        assert_eq!(bundle.access_token, "a2");
        assert_eq!(bundle.refresh_token, "r2");
        assert_eq!(bundle.uid, "y1");
        assert_eq!(bundle.expires_in, 0);

        // 缺 accessToken → 502
        let error = parse_token_bundle(&json!({ "refreshToken": "r" }))
            .err()
            .unwrap_or_else(|| Error::new("缺 accessToken 时必须报错"));
        assert_eq!(error.status, Some(502));
    }

    #[test]
    fn callback_parser_finds_code_and_state() {
        let parsed = parse_callback("code=abc&state=xyz&scope=snsapi").unwrap_or_default();
        assert_eq!(parsed, ("abc".to_string(), "xyz".to_string()));
        // 编码过的值要还原
        let parsed = parse_callback("code=a%2Bb&state=s").unwrap_or_default();
        assert_eq!(parsed.0, "a+b");
        // 只有 code（没有 state）也是合法回调
        let parsed = parse_callback("code=only").unwrap_or_default();
        assert_eq!(parsed, ("only".to_string(), String::new()));
        // 没有 code → None（不能拿空 code 去换码）
        assert!(parse_callback("state=only").is_none());
        assert!(parse_callback("").is_none());
    }

    #[test]
    fn callback_code_accepts_bare_and_full_url() {
        // 纯 code
        assert_eq!(callback_code("abc", ""), "abc");
        // 整条 URL（壳侧回填的形态）
        assert_eq!(
            callback_code("http://127.0.0.1:3066/auth/callback?code=abc&state=s", ""),
            "abc"
        );
        // 只有 query 段
        assert_eq!(callback_code("code=abc&state=s", ""), "abc");
        // 空 raw → 回退到 fallback
        assert_eq!(callback_code("   ", "fb"), "fb");
        // 参数名不认识 → 原样交给上游
        assert_eq!(callback_code("weird=1", ""), "weird=1");
    }

    #[test]
    fn authorize_url_encodes_both_parameters() {
        let url = build_authorize_url("http://127.0.0.1:3066/auth/callback", "login_abc");
        assert!(url.starts_with("https://lobsterai.youdao.com/portal#/login?source=electron"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A3066%2Fauth%2Fcallback"));
        assert!(url.contains("state=login_abc"));
    }

    #[test]
    fn urldecode_handles_plus_and_percent() {
        assert_eq!(urldecode("a+b"), "a b");
        assert_eq!(urldecode("%E4%B8%AD"), "中");
        // 坏的百分号转义原样保留（不 panic、不丢字节）
        assert_eq!(urldecode("a%zz"), "a%zz");
        assert_eq!(urldecode("a%"), "a%");
    }
}
