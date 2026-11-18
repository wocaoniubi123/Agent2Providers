//! Accio **网页登录**：OAuth 2.0 授权码 + PKCE（S256）。
//!
//! ── 协议（依据桌面端实现 `AuthService`）────────────────────────
//! ```text
//! ① 生成 code_verifier（随机）/ code_challenge（SHA-256 → base64url）
//! ② 打开 {loginBase}/login?return_url=<本机回调>&state=<state>
//!        &code_challenge=<challenge>&code_challenge_method=S256&client_id=accio-work
//! ③ 用户登录完成 → 登录页把 ?code=…&state=… 拼到 return_url 上跳回来
//! ④ POST {gw}/api/oauth/token  {code, codeVerifier, clientId, redirectUri}
//!        → {accessToken, refreshToken, expiresAt}
//! ```
//! `client_id` 是桌面端常量（`accio-work`，两地共用）；`redirectUri` 必须与
//! 第 ② 步的 `return_url` **逐字相同**，因此它跟着登录状态一起存下来原样回传。
//!
//! ── 为什么 PKCE 与 state 都还要（回调已经改成手工回填了）────────
//! 回填的是用户从地址栏复制的那条 URL —— 它可能被别人发过来的链接替换。
//! 两道闸门各挡一类：
//!   - **state**：`← 这次回调是不是本进程刚发起的那一轮`。逐字比对，不匹配就
//!     拒绝 —— 否则别人可以拿自己那次的 code 把凭证写进你的账号库；
//!   - **code_verifier**：规范给的防换码能力（授权码被截获也换不出 token，
//!     因为换码请求要带上只有我们知道的那个原像）。
//!
//! ── 与 native 的差别：loopback 监听器 → 手工回填 ─────────────────
//! native 每轮登录会自己绑一个 loopback 端口收回调（`callback_server.rs`）；
//! wasm 没有 socket，这条链因此改成「用户把地址栏那条 URL 粘回来」
//! （`login.callback`）。`return_url` 仍写成 loopback 形态 —— 登录页需要一个
//! 合法的 `redirect_uri`，而桌面端白名单里的就是这一种形状。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件在登录链路上，绝不 unwrap/expect/panic。

use agent2api_wasm_sdk::{Error, Result};
use sha2::{Digest, Sha256};

use super::codec;
use super::credential::{self, Credential};
use super::region::{self, Region};
use super::upstream;

/// 本插件申报的回调地址。
///
/// ── 为什么端口是固定的 ──────────────────────────────────────
/// 上游对 `redirect_uri` 做白名单校验（桌面端自己用的就是
/// `http://127.0.0.1:<port>/auth/callback` 形态）。插件没有监听器，这个地址
/// **不会被真的访问**：浏览器跳到它上面会显示「无法访问」，用户从地址栏复制
/// 那条 URL 回填即可（与 Trae 的处置相同）。固定一个端口只为让 `redirect_uri`
/// 稳定、可复现，而不是每次登录都变。
pub const CALLBACK_REDIRECT: &str = "http://127.0.0.1:17892/auth/callback-accio";

/// 授权页地址（`{loginBase}/login?...`）。
pub fn build_authorize_url(region: Region, state: &str, challenge: &str, return_url: &str) -> String {
    // 两地的登录站点不同（国际 `.com` / 国内 `-ai.com`），这是孪生包唯一的
    // 域名差异；`loginBase` 设置可覆盖（预发用），见 `region::login_base`。
    let _ = region;
    format!(
        "{}/login?return_url={}&state={}&code_challenge={}&code_challenge_method=S256&client_id={}",
        region::login_base(),
        codec::urlencode(return_url),
        codec::urlencode(state),
        codec::urlencode(challenge),
        codec::urlencode(region::CLIENT_ID),
    )
}

/// 生成一轮 PKCE 参数：`(verifier, challenge)`。
pub fn new_pkce() -> (String, String) {
    let verifier = codec::random_token();
    let challenge = codec::base64_url_no_pad(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// 用授权码换凭证（`POST /api/oauth/token`）。
///
/// 返回的凭证已经补过身份：token 是不透明串，账号标识只能靠资料接口问一次；
/// 查询失败**不算失败**（id 走凭证指纹兜底、名字走备注名）。
pub fn exchange_code(
    region: Region,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Credential> {
    let body = serde_json::json!({
        "code": code,
        "codeVerifier": verifier,
        "clientId": region::CLIENT_ID,
        "redirectUri": redirect_uri,
    });
    let payload = upstream::post_json(region, region::OAUTH_TOKEN_PATH, &body, "授权码换令牌")?;
    let data = upstream::unwrap_data(payload);
    let access_token = credential::secret_text(&data, &["accessToken", "access_token", "token"])?;
    if access_token.is_empty() {
        return Err(Error::http(502, "Accio 换码响应缺少 accessToken"));
    }
    let mut credential = Credential {
        access_token,
        refresh_token: credential::secret_text(&data, &["refreshToken", "refresh_token"])?,
        expires_at: credential::timestamp(data.get("expiresAt").or_else(|| data.get("expires_at"))),
        user_id: String::new(),
        email: String::new(),
        name: String::new(),
        device_id: String::new(),
        // 桌面端的换码响应里带 `sgcookie`（浏览器会话的伴随标识）：
        // 推理请求有就带上，更接近真实客户端
        sgcookie: credential::sgcookie(&data),
    };
    credential.ensure_identity();
    // 换回来的 token 是不透明串，账号标识只能靠资料接口问一次
    if let Ok(profile) = upstream::fetch_profile(&credential.access_token) {
        upstream::apply_profile(&mut credential, &profile);
    }
    credential.ensure_identity();
    Ok(credential)
}

/// 从回调查询串里取 `code` / `state`（两个都必需）。
pub fn parse_callback(query: &[(String, String)]) -> Result<(String, String)> {
    let find = |key: &str| {
        query
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let error = find("error");
    if !error.trim().is_empty() {
        return Err(Error::http(400, format!("授权被拒绝（{error}）")));
    }
    let code = find("code");
    let state = find("state");
    if code.trim().is_empty() {
        return Err(Error::http(400, "回调没有携带授权码"));
    }
    if state.trim().is_empty() {
        return Err(Error::http(400, "回调没有携带 state，无法确认这次登录归属"));
    }
    if code.len() > 8192 || state.len() > 512 {
        return Err(Error::http(400, "回调参数超长，已拒绝"));
    }
    Ok((code.trim().to_string(), state.trim().to_string()))
}

/// 把用户粘贴的整条 URL 拆成查询串（没有 `?` 时按裸查询串处理）。
pub fn query_of(raw: &str) -> String {
    let text = raw.trim();
    match text.split_once('?') {
        Some((_, query)) => query.to_string(),
        None => text.trim_start_matches('?').to_string(),
    }
}

/// 回调 URL 里带 `?` 时也要能取出 query（登录页把参数拼在 redirect 后面）。
pub fn parse_callback_url(raw: &str) -> Result<(String, String)> {
    parse_callback(&codec::query_pairs(&query_of(raw)))
}
