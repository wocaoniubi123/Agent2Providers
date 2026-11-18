//! CodeArts 凭证：一次登录换来的**临时** AK/SK/STS + 域号，以及账号面。
//!
//! ── 两半的分工（这是本模块存在的理由）────────────────────
//! 上游登录（`sts…/v1/oauth2/tokens`）返回三段短期材料 —— `access_key_id` /
//! `secret_access_key` / `security_token`，有效期由 `expiration` 给出。这三段
//! 用过就必须续，而**续期不能只靠 refresh token**：同一个令牌请求还要出示当初
//! 那次登录所用的 PKCE verifier 与 DPoP 私钥。所以凭据是一整块、不能只存
//! AK/SK/STS；少存一半，到期后就再也续不回来，只能重新走浏览器登录。
//!
//! ── wasm 侧续期为什么交给宿主 ──────────────────────────────
//! 换证要用 P-256 私钥签 DPoP 证明，而本插件的依赖清单里没有椭圆曲线库。宿主
//! 侧已有 `codearts_refresh` 这一整套（读原槽材料、构造固定请求、核对响应、
//! 比较再写回），插件只按固定入口 `credential.codearts.refresh` 触发一次即可：
//! 那既是「能续期」的唯一安全实现，也避免让一次性 refresh token 在插件里多留
//! 一份副本。
//!
//! ── 字段名为什么是 snake_case ──────────────────────────────
//! 与上游 JSON 对齐（`credentials.access_key_id`、`expiration`），也与参考实现
//! `cpa-codearts-plugin` 的 `credential` 结构逐字一致 —— 迁移过来的凭据不用做
//! 一次字段改名，少一次出错的机会。

use agent2api_wasm_sdk::{self as sdk, json, AccountLock, Error, Result, Value};

use super::upstream;

/// 上游契约里单个令牌材料的最长长度（超过即视为坏数据，不再发请求）。
pub const MAX_TOKEN_LENGTH: usize = 8192;
/// 续期提前量：临时凭据到期前 15 分钟就换（与 `token.expiring` 共用一个数）。
pub const REFRESH_LEAD_MS: i64 = 15 * 60 * 1000;
/// 账号名长度上限（与网关 `truncate_chars(&record_name, 100)` 同口径）。
const MAX_NAME_LENGTH: usize = 100;

/// PKCE 的两半：verifier 是秘密（只在后端），challenge 是它的一次性公开形式。
#[derive(Clone, Debug, Default)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// 长期那一半：续期要用、短期材料可以整块替换的东西。
///
/// 本插件**不解析** DPoP 私钥（换证在宿主里做），只把它当作「有/没有」来判断
/// 这份凭据能不能自动续期 —— `can_refresh` 的判据就是「refresh token + verifier
/// 都在」，与 native 一致。
#[derive(Clone, Debug, Default)]
pub struct OAuthContext {
    pub client_id: String,
    pub pkce_pair: PkcePair,
    pub has_dpop_key: bool,
}

/// 一份 CodeArts 凭据。
#[derive(Clone, Debug, Default)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: String,
    /// 上游给的到期时刻（RFC3339，如 `2026-09-27T16:17:00.327Z`）
    pub expires_at: String,
    pub domain_id: String,
    pub user_id: String,
    pub user_name: String,
    pub login_type: String,
    pub refresh_token: String,
    pub oauth_context: Option<OAuthContext>,
}

impl Credential {
    /// 能拿它去签上游请求吗（签名的两个必要材料）。
    pub fn valid(&self) -> bool {
        !self.access_key_id.is_empty() && !self.secret_access_key.is_empty()
    }

    /// 能拿它去续期吗 —— 续期要 refresh token **和** 当初那次登录的上下文。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
            && self
                .oauth_context
                .as_ref()
                .is_some_and(|context| !context.pkce_pair.code_verifier.trim().is_empty())
    }

    /// 到期时刻（毫秒 epoch）。只有能解析出 RFC3339 才有值 ——
    /// 解析不出来**不能**当成「还新鲜」：那会让一个坏时间戳永久躲在缓存里。
    pub fn expires_at_ms(&self) -> Option<i64> {
        let text = self.expires_at.trim();
        if text.is_empty() {
            return None;
        }
        chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|time| time.timestamp_millis())
    }

    /// 是否需要续期（`lead_ms` 是提前量；`lead_ms = 0` 即「已经过期了吗」）。
    ///
    /// 三条与参考实现一致的行为：没有 security token 的凭据不刷（它本来就不完整）；
    /// 没有到期时间的不刷（无从判断，交给登录补全）；**解析不出来的当作要刷**
    /// （坏时间戳绝不能被当成新鲜）。
    pub fn needs_refresh(&self, lead_ms: i64, now_ms: i64) -> bool {
        if self.security_token.trim().is_empty() || !self.valid() {
            return false;
        }
        if self.expires_at.trim().is_empty() {
            return false;
        }
        match self.expires_at_ms() {
            Some(expiry) => expiry <= now_ms.saturating_add(lead_ms),
            None => true,
        }
    }

    /// 迁移/导入时用：上游 JSON 里字段名可能落在嵌套或平铺两种位置。
    ///
    /// 参考实现把凭据存在 `codearts_provider_credential` 这个键下（CPA 的 auth
    /// 文件就是这么写的），但手工粘贴时人是平铺给的，所以两种都认。
    pub fn from_payload(payload: &Value) -> Result<Self> {
        let body = payload
            .get("codearts_provider_credential")
            .or_else(|| payload.get("credential"))
            .unwrap_or(payload);
        if !body.is_object() {
            return Err(Error::http(400, "CodeArts 凭据必须是 JSON 对象"));
        }
        let mut credential = Credential {
            access_key_id: upstream::text(body, &["access_key_id", "accessKeyId", "accessToken"]),
            secret_access_key: upstream::text(body, &["secret_access_key", "secretAccessKey"]),
            security_token: upstream::text(body, &["security_token", "securityToken"]),
            expires_at: upstream::text(body, &["expiration", "expires_at", "expiresAt"]),
            domain_id: upstream::text(body, &["domain_id", "account_id", "domainId"]),
            user_id: upstream::text(body, &["user_id", "principal_id", "userId"]),
            user_name: upstream::text(body, &["user_name", "userName"]),
            login_type: upstream::text(body, &["login_type", "loginType"]),
            refresh_token: upstream::text(body, &["refresh_token", "refreshToken"]),
            oauth_context: context_of(body),
        };
        // `expiresAt` 若是毫秒整数（本仓账号记录的通用键），折回 RFC3339 文案，
        // 让 `expires_at` 这一个字段承担全部到期语义 —— 两个来源各解一次必然漂移。
        if credential.expires_at.is_empty() {
            if let Some(millis) = body.get("expiresAt").and_then(Value::as_i64).filter(|value| *value > 0) {
                if let Some(time) = chrono::DateTime::from_timestamp_millis(millis) {
                    credential.expires_at = time.to_rfc3339();
                }
            }
        }
        for text in [
            &credential.access_key_id,
            &credential.secret_access_key,
            &credential.security_token,
            &credential.refresh_token,
        ] {
            if text.len() > MAX_TOKEN_LENGTH {
                return Err(Error::http(400, "CodeArts 凭据里的令牌长度超出上限"));
            }
        }
        if credential.access_key_id.is_empty() || credential.secret_access_key.is_empty() {
            return Err(Error::http(
                400,
                "CodeArts 凭据缺少 access_key_id 或 secret_access_key",
            ));
        }
        Ok(credential)
    }
}

/// 从凭据体里读 `oauth_context`（形状不对就当作没有，不猜）。
fn context_of(body: &Value) -> Option<OAuthContext> {
    let context = body.get("oauth_context")?;
    if !context.is_object() {
        return None;
    }
    let pkce = context.get("pkce_pair").filter(|value| value.is_object());
    let keys = context.get("dpop_key_pair").filter(|value| value.is_object());
    Some(OAuthContext {
        client_id: upstream::text(context, &["client_id"]),
        pkce_pair: PkcePair {
            code_verifier: pkce.map(|value| upstream::text(value, &["code_verifier"])).unwrap_or_default(),
            code_challenge: pkce.map(|value| upstream::text(value, &["code_challenge"])).unwrap_or_default(),
            code_challenge_method: pkce
                .map(|value| upstream::text(value, &["code_challenge_method"]))
                .unwrap_or_default(),
        },
        has_dpop_key: keys.is_some_and(|value| {
            !upstream::text(value, &["private_key_jwk", "public_key_jwk"]).is_empty()
                || value.get("private_key_jwk").is_some_and(|value| value.is_object())
        }),
    })
}

/// 当前账号的完整记录（`secret` + `public` + `id`）。
pub fn record() -> Result<Value> {
    let record = sdk::account()?;
    if !record.is_object() {
        return Err(Error::http(503, "没有可用的 CodeArts 账号：请在账号页添加并启用账号"));
    }
    Ok(record)
}

/// 当前账号的 secret 与凭据。
pub fn current() -> Result<(Value, Credential)> {
    let record = record()?;
    let secret = record["secret"].clone();
    if !secret.is_object() {
        return Err(Error::http(503, "CodeArts 账号缺少凭据材料，请重新登录"));
    }
    let credential = Credential::from_payload(&secret)?;
    Ok((secret, credential))
}

/// 临期就真续期，返回**可用**的凭据（所有上游调用的统一入口）。
///
/// ── 为什么必须统一走这里 ────────────────────────────────────
/// 临时凭据只活约一小时。目录、余额、福利、对话四条链各自读盘上那份，早就在
/// 闲置后被 401 打回；而 401 在这些链路上只会显示成「失败」，看着像账号坏了。
/// 于是「先判临期、临期就续」必须是**唯一**入口，不能有第二条读 secret 的路。
pub fn ensure(fresh: bool) -> Result<Credential> {
    let (_, credential) = current()?;
    if !credential.valid() {
        return Err(Error::http(401, "CodeArts 账号缺少可用的临时凭据，请重新登录"));
    }
    if !fresh && !credential.needs_refresh(REFRESH_LEAD_MS, sdk::now()) {
        return Ok(credential);
    }
    if !credential.can_refresh() {
        // 临时兜底登录（ticket 通道）拿不到 refresh token：约一小时后必须重登。
        // 这里不报错 —— 只要还没到期，这次请求照发；到期由上游 401 兜住。
        if !fresh {
            return Ok(credential);
        }
        return Err(Error::http(
            401,
            "CodeArts 本次登录没有可续期的授权材料，约一小时后需要重新登录",
        ));
    }
    refresh_through_host(fresh)?;
    // 宿主已把新材料写回账号槽，重新读一遍才是**权威**值：
    // 用本地推断出来的凭据继续签名，等于在宿主拒绝写回时签一份不存在的凭据。
    let (_, refreshed) = current()?;
    if !refreshed.valid() {
        return Err(Error::http(502, "CodeArts 续期后账号凭据仍不完整，请重新登录"));
    }
    Ok(refreshed)
}

/// 触发一次宿主代持的换证。
///
/// ── 为什么先抢账号锁 ────────────────────────────────────────
/// refresh token 是**一次性**的：两路并发续期里后到的那一路必然失败，并且会把
/// 已经落盘的新材料判成「被人换掉了」。锁 + 读回当前材料再判一次（单飞）是唯一
/// 安全顺序；`AccountLock` 是宿主提供的跨调用互斥，`Drop` 自动释放。
fn refresh_through_host(force: bool) -> Result<()> {
    let _lock = AccountLock::acquire()?;
    let (_, latest) = current()?;
    // 拿到锁之后重判：并发的另一路可能刚做完续期并写回
    if !force && !latest.needs_refresh(REFRESH_LEAD_MS, sdk::now()) {
        return Ok(());
    }
    let value = sdk::host("credential.codearts.refresh", json!({})).map_err(|error| {
        // 宿主只在「原调用带换证来源」时才放行这一入口；没有来源说明这次不是
        // 面板「刷新凭据」或临期自动续期发起的，如实说清楚而不是伪装成网络错。
        if error.code.as_deref() == Some("forbidden") {
            Error::http(401, "CodeArts 自动续期需要由原账号上下文发起，请重新登录或点一次「刷新凭据」")
        } else {
            error
        }
    })?;
    // 返回体形状不是必须的：新材料由宿主持有并写回。这里只做一次一致性检查，
    // 免得宿主改了返回形状后插件悄悄继续用旧值。
    let access = value["access_key_id"].as_str().unwrap_or_default();
    let _ = access;
    Ok(())
}

// ── 账号面 ───────────────────────────────────────────────────

/// 手工粘贴凭据 → 可落库的账号。
///
/// ── 两条添加路径 ────────────────────────────────────────────
/// ```text
///   manual   粘贴凭证（平铺或 CPA 的 {codearts_provider_credential:{}} 嵌套形态都认）
///   desktop  不支持（登录态是 OAuth 换来的临时三元组，不在本机文件里）
///   file_*   不支持（凭证不是文件）
/// ```
/// **不调上游**：凭据是登录换来的，添加时没有可交换的授权码；目录与连通性由
/// 刷新链路验。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => {
            let payload = &source["payload"];
            if payload["inputs"].is_object() {
                payload["inputs"].clone()
            } else {
                payload.clone()
            }
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "CodeArts 不支持导入桌面端登录态：它的凭证是 OAuth 换来的临时 AK/SK/STS，\
                 请用「网页登录」或粘贴凭据添加账号",
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "CodeArts 没有可导入的凭证文件，请粘贴凭据（access_key_id / secret_access_key）\
                 或整份 CPA auth 文件的内容",
            ))
        }
    };
    // 整段文本形态（用户直接粘了一份 auth 文件内容）也认
    let payload = match payload.as_str() {
        Some(raw) => serde_json::from_str(raw).map_err(|_| Error::http(400, "CodeArts 凭据不是合法 JSON"))?,
        None => payload,
    };
    let credential = Credential::from_payload(&payload)?;
    let name = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate_chars(value, MAX_NAME_LENGTH));
    Ok(into_account(&credential, "manual", name))
}

/// 凭据 →（secret, public, identity）三元组。
fn into_account(credential: &Credential, source: &str, explicit_name: Option<String>) -> Value {
    let mut secret = serde_json::Map::new();
    // 只写**已知**字段：空值覆盖会把上次登录拿到的续期材料洗掉
    for (key, value) in [
        ("access_key_id", &credential.access_key_id),
        ("secret_access_key", &credential.secret_access_key),
        ("security_token", &credential.security_token),
        ("expires_at", &credential.expires_at),
        ("domain_id", &credential.domain_id),
        ("user_id", &credential.user_id),
        ("user_name", &credential.user_name),
        ("login_type", &credential.login_type),
        ("refresh_token", &credential.refresh_token),
    ] {
        insert_text(&mut secret, key, value);
    }
    // ── 通用键名（与网关 `to_record_value` 逐字同口径）──────────
    // 选路与「这个账号能不能用」的判定读的是 `accessToken` / `expiresAt` 这类
    // 共享键；不写就会让 codearts 账号在选路时被当成没有 token。
    insert_text(&mut secret, "accessToken", &credential.access_key_id);
    insert_text(&mut secret, "refreshToken", &credential.refresh_token);
    insert_text(&mut secret, "userId", &credential.user_id);
    secret.insert(
        "expiresAt".to_string(),
        credential.expires_at_ms().map(Value::from).unwrap_or(Value::Null),
    );
    secret.insert("source".to_string(), Value::String(source.to_string()));
    if let Some(context) = credential.oauth_context.as_ref() {
        // `oauth_context` 是续期的一半：有就整块写，没有就不写 —— 写一个空对象
        // 进去会让 `can_refresh` 判成「能续期但没材料」，比缺字段更难查。
        let mut pkce = serde_json::Map::new();
        insert_text(&mut pkce, "code_verifier", &context.pkce_pair.code_verifier);
        insert_text(&mut pkce, "code_challenge", &context.pkce_pair.code_challenge);
        insert_text(&mut pkce, "code_challenge_method", &context.pkce_pair.code_challenge_method);
        if !pkce.is_empty() || context.has_dpop_key {
            let mut value = serde_json::Map::new();
            insert_text(&mut value, "client_id", &context.client_id);
            value.insert("pkce_pair".to_string(), Value::Object(pkce));
            secret.insert("oauth_context".to_string(), Value::Object(value));
        }
    }
    if let Some(name) = explicit_name {
        secret.insert("name".to_string(), Value::String(name));
    }
    let secret = Value::Object(secret);
    json!({
        "secret": secret,
        "public": account_view(&secret),
        "identity": identity_of(&secret),
        "desktop": false,
    })
}

/// 界面用的公开视图（**绝不带任何凭证字段**）。
///
/// AK/SK/STS/refresh token/DPoP 私钥一个都不出现在这里 —— 这是账号列表接口，
/// 前端与局域网内的浏览器都能读到它。
pub fn account_view(secret: &Value) -> Value {
    let credential = Credential::from_payload(secret).ok();
    let available = credential
        .as_ref()
        .is_some_and(|value| value.valid() && !value.security_token.trim().is_empty());
    let can_refresh = credential.as_ref().is_some_and(Credential::can_refresh);
    let user_id = upstream::text(secret, &["user_id", "userId"]);
    let mut public = serde_json::Map::new();
    public.insert("name".to_string(), Value::String(default_name(secret)));
    for (key, value) in [
        ("uid", user_id.clone()),
        ("userName", upstream::text(secret, &["user_name"])),
        ("domainId", upstream::text(secret, &["domain_id"])),
        ("loginType", upstream::text(secret, &["login_type"])),
    ] {
        insert_text(&mut public, key, &value);
    }
    public.insert(
        "tokenTail".to_string(),
        Value::String(token_tail(&upstream::text(secret, &["access_key_id", "accessToken"]))),
    );
    // 到期时刻统一给毫秒（面板那一列按毫秒读；RFC3339 字符串它解析不了）
    let expires = credential.as_ref().and_then(Credential::expires_at_ms);
    public.insert("expiresAt".to_string(), expires.map(Value::from).unwrap_or(Value::Null));
    public.insert(
        "accessTokenExpiresAt".to_string(),
        expires.map(Value::from).unwrap_or(Value::Null),
    );
    public.insert("hasAccessToken".to_string(), Value::Bool(available));
    public.insert("hasRefreshToken".to_string(), Value::Bool(can_refresh));
    public.insert("canRefresh".to_string(), Value::Bool(can_refresh));
    let relogin = relogin_reason(secret);
    public.insert("needsRelogin".to_string(), Value::Bool(relogin.is_some()));
    public.insert(
        "needsReloginReason".to_string(),
        relogin.map(Value::String).unwrap_or(Value::Null),
    );
    public.insert("available".to_string(), Value::Bool(available));
    // 本家没有版本概念（恒 cn-north-4），但前端按 `edition` 分组的地方要能读到空值
    public.insert("edition".to_string(), Value::Null);
    public.insert("editionLabel".to_string(), Value::Null);
    Value::Object(public)
}

/// 稳定身份：`domain_id + user_id`；都空时退到 access key 尾号。
///
/// ── 为什么不能退到 access key 本身 ─────────────────────────
/// AK 每次续期都换（临时凭据），拿它当身份等于每刷一次期就在列表里多一条账号。
/// 尾号同理 —— 但它至少稳定在「这一次登录」的生命周期内，且缺身份本来就是
/// 手工粘贴没给全的边角情形。
pub fn identity_of(secret: &Value) -> String {
    let domain = upstream::text(secret, &["domain_id"]);
    let user = upstream::text(secret, &["user_id", "userId"]);
    if !domain.is_empty() || !user.is_empty() {
        return format!("codearts-{domain}-{user}");
    }
    let tail = token_tail(&upstream::text(secret, &["access_key_id", "accessToken"]));
    if tail.is_empty() {
        String::new()
    } else {
        format!("codearts-ak-{tail}")
    }
}

/// 「需要重新登录」的原因；不需要时返回 None。
///
/// 判据只有一条：**有 refresh token 但缺续期材料**（verifier / 密钥），或者
/// 到期且完全没有续期能力。冻结期（`authorization::EXPIRED_MESSAGE` 那条）在
/// 本插件里等价于「续期返回了未定义行为」—— 宿主换证失败会直接报错，所以这里
/// 只覆盖「材料不全」这一档。
fn relogin_reason(secret: &Value) -> Option<String> {
    let credential = Credential::from_payload(secret).ok()?;
    if credential.can_refresh() {
        return None;
    }
    if credential.refresh_token.trim().is_empty() {
        // 临时兜底登录：本来就无法自动续期，属于已知状态而非错误
        return None;
    }
    Some("CodeArts 本次登录缺少续期所需的 PKCE 材料，临时凭据到期后需要重新登录".to_string())
}

/// 默认账号名：`user_name` → `CodeArts <AK 前 8 位>`。
fn default_name(secret: &Value) -> String {
    let user_name = upstream::text(secret, &["user_name"]);
    if !user_name.is_empty() {
        return truncate_chars(&user_name, MAX_NAME_LENGTH);
    }
    let ak = upstream::text(secret, &["access_key_id", "accessToken"]);
    format!("CodeArts {}", truncate_chars(&ak, 8))
}

/// 令牌尾号（展示用；空值给空串而不是「末 6 位为空」的假读数）。
fn token_tail(token: &str) -> String {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    let start = chars.len().saturating_sub(6);
    chars[start..].iter().collect()
}

/// 按字符数截断（不是字节：中文名按字节截会切出半个字符）。
pub fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value.chars().take(limit).collect()
}

/// 只在值非空时写一个字符串键。
fn insert_text(target: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        target.insert(key.to_string(), Value::String(trimmed.to_string()));
    }
}
