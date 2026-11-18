//! QuWork 账号：凭证解析、公开视图、稳定身份、本机登录态引用。
//!
//! ── 两个令牌不能互换（上游 1.6.0 的硬边界）──────────────────
//! ```text
//!   accessToken  登录会话：积分查询、续期、每日奖励、权益兑换都要它
//!   llmToken     模型凭证：只有对话要用它；只导入模型凭证也能聊天
//! ```
//! native 的报错口径照搬：只给了模型凭证时，账号能对话，但积分/续期/奖励
//! 一律如实报「需要完整登录态」，不把 401 折叠成「余额为 0」。
//!
//! ── 本机登录态只存引用 ──────────────────────────────────────
//! wasm 没有文件系统：token 由宿主 `desktop.credentials.read` 现读（能力
//! `desktop.credentials.v1` + helper `desktop.credentials.quwork.v1`），
//! 账号里只留 `source:"desktop"` 与一串指纹/尾号。这样客户端切号后，
//! 下一次读取会因身份对不上而明确报错，而不是静默换了别人的额度。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::upstream;

/// 一份凭证允许的最大字节数。
pub const MAX_CREDENTIAL_BYTES: usize = 262_144;

/// 按顺序取第一个非空字符串。
pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
        })
        .unwrap_or("")
        .to_string()
}

/// 凭证串的格式闸门：去掉 `Bearer ` 前缀，只收可见 ASCII。
pub fn token(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    let value = value.strip_prefix("Bearer ").unwrap_or(value).trim();
    if value.len() > 16_384
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(Error::http(400, format!("QuWork {label}格式不正确")));
    }
    Ok(value.to_string())
}

/// 用户面投影（`uid/nickname/phone` 之类）。
pub fn user_view(user: &Value) -> Value {
    let mut public = json!({});
    for (target, keys) in [
        ("uid", &["id", "uid", "userId"][..]),
        ("username", &["username"][..]),
        ("nickname", &["display_name", "displayName", "nickname"][..]),
        ("phone", &["phone"][..]),
    ] {
        if let Some(value) = keys
            .iter()
            .find_map(|key| user.get(*key).filter(|value| value.is_string() || value.is_number()))
        {
            public[target] = if value.is_string() {
                value.clone()
            } else {
                json!(value.to_string())
            };
        }
    }
    public
}

/// 把一份（可能层层嵌套的）凭证折成 `{accessToken, llmToken, user, ...}`。
pub fn parse(value: &Value) -> Result<Value> {
    parse_inner(value, 0)
}

fn parse_inner(value: &Value, depth: usize) -> Result<Value> {
    if depth > 6 {
        return Err(Error::http(400, "QuWork 凭证嵌套过深"));
    }
    let mut input = value.clone();
    for key in ["secret", "session", "data"] {
        if let Some(nested) = input.get(key).filter(|value| value.is_object()) {
            input = nested.clone();
        }
    }
    let nested_llm = input
        .get("llmToken")
        .and_then(Value::as_str)
        .filter(|text| text.trim().starts_with('{'));
    let mut parsed = if let Some(content) = input.get("credentials").and_then(Value::as_str).or(nested_llm) {
        parse_text_inner(content, depth + 1)?
    } else {
        json!({})
    };
    let access = token(&text(&input, &["accessToken", "access_token", "token"]), "登录凭证")?;
    let llm = if nested_llm.is_some() {
        String::new()
    } else {
        token(&text(&input, &["llmToken", "llm_token", "apiKey", "key"]), "模型凭证")?
    };
    if !access.is_empty() {
        parsed["accessToken"] = json!(access);
    }
    if !llm.is_empty() && !llm.starts_with('{') {
        parsed["llmToken"] = json!(llm);
    }
    if let Some(user) = input.get("user").filter(|value| value.is_object()) {
        parsed["user"] = user_view(user);
    } else if input.get("uid").is_some() {
        parsed["user"] = user_view(&input);
    }
    let expires = upstream::timestamp(input.get("expiresAt"))
        .or_else(|| upstream::timestamp(input.get("expire")))
        .or_else(|| jwt_expiry(&text(&parsed, &["accessToken"])));
    if let Some(expires) = expires {
        parsed["expiresAt"] = json!(expires);
    }
    for key in ["name", "deviceIdentifier", "deviceUuid"] {
        let value = text(&input, &[key]);
        if !value.is_empty() {
            if value.len() > 256
                || value.chars().any(char::is_control)
                || (key == "deviceIdentifier"
                    && (value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())))
            {
                return Err(Error::http(400, "QuWork 账号字段格式不正确"));
            }
            parsed[key] = json!(value);
        }
    }
    if text(&parsed, &["llmToken"]).is_empty() {
        return Err(Error::http(
            400,
            "缺少 QuWork 模型凭证 llmToken；登录凭证不能代替模型凭证，请先在 QuWork 客户端完成登录",
        ));
    }
    Ok(parsed)
}

/// 解析文本形态：JSON / `.credentials.yaml` 片段 / 裸模型凭证。
pub fn parse_text(content: &str) -> Result<Value> {
    parse_text_inner(content, 0)
}

fn parse_text_inner(content: &str, depth: usize) -> Result<Value> {
    if depth > 6 {
        return Err(Error::http(400, "QuWork 凭证嵌套过深"));
    }
    if content.len() > MAX_CREDENTIAL_BYTES {
        return Err(Error::http(400, "QuWork 凭证内容超过大小限制"));
    }
    let content = content.trim().trim_start_matches('\u{feff}').trim();
    if content.starts_with('{') {
        let value: Value = serde_json::from_str(content)
            .map_err(|_| Error::http(400, "QuWork 凭证 JSON 格式不正确"))?;
        return parse_inner(&value, depth + 1);
    }
    if content
        .lines()
        .any(|line| line.trim_start().starts_with("QURIVS_LLM_API_KEY:"))
    {
        let raw = content
            .lines()
            .find_map(|line| line.trim().strip_prefix("QURIVS_LLM_API_KEY:"))
            .unwrap_or("")
            .trim();
        let value = if raw.starts_with('"') {
            serde_json::from_str::<String>(raw)
                .map_err(|_| Error::http(400, "QuWork 模型凭证格式不正确"))?
        } else {
            raw.trim_matches('\'').to_string()
        };
        return parse_inner(&json!({ "llmToken": value }), depth + 1);
    }
    parse_inner(&json!({ "llmToken": content }), depth + 1)
}

/// JWT 的 `exp`（秒 → 毫秒）。base64url 手写解码（本包不引 base64）。
pub fn jwt_expiry(value: &str) -> Option<i64> {
    let part = value.split('.').nth(1)?;
    let bytes = base64url_decode(part.trim_end_matches('='))?;
    let body: Value = serde_json::from_slice(&bytes).ok()?;
    upstream::timestamp(body.get("exp"))
}

/// `-`/`_` 变体的 base64（无填充）。
fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(output)
}

/// 稳定身份：有 uid 用 uid，否则按模型凭证指纹。
pub fn identity(secret: &Value) -> String {
    let user = secret.get("user").unwrap_or(&Value::Null);
    let uid = text(user, &["uid", "id"]);
    if !uid.is_empty() {
        return format!("quwork:{uid}");
    }
    let key = text(secret, &["llmToken", "modelFingerprint"]);
    if key.is_empty() {
        return String::new();
    }
    if secret.get("modelFingerprint").is_some() && secret.get("llmToken").is_none() {
        format!("quwork:key:{key}")
    } else {
        format!("quwork:key:{}", fingerprint(&key))
    }
}

/// 凭证指纹（sha256 十六进制，短取 32 位）。
pub fn fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.chars().take(32).collect()
}

/// 令牌尾 6 位（多字节安全）。
fn tail_of(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(6);
    chars[start..].iter().collect()
}

/// 公开视图（界面读的键名沿用 native 契约）。
pub fn public(secret: &Value) -> Value {
    let user = secret.get("user").unwrap_or(&Value::Null);
    let nickname = text(
        user,
        &["nickname", "display_name", "displayName", "username", "phone", "uid"],
    );
    let name = text(secret, &["name"]);
    let llm = text(secret, &["llmToken"]);
    let local = secret.get("source").and_then(Value::as_str) == Some("desktop");
    let has_login = !text(secret, &["accessToken"]).is_empty()
        || secret.get("hasLoginToken").and_then(Value::as_bool) == Some(true);
    let mut view = json!({
        "name": if name.is_empty() { if nickname.is_empty() { "QuWork" } else { &nickname } } else { &name },
        "uid": text(user, &["uid", "id"]),
        "nickname": nickname,
        "phone": text(user, &["phone"]),
        "hasToken": !llm.is_empty() || local,
        "available": !llm.is_empty() || local,
        "hasLoginToken": has_login,
        "hasAccessToken": has_login,
        "canRefresh": has_login,
        "tokenTail": if llm.is_empty() { text(secret, &["tokenTail"]) } else { tail_of(&llm) },
        "desktopAuth": local,
    });
    for key in ["expiresAt", "updatedAt"] {
        if let Some(value) = secret.get(key).filter(|value| value.is_number()) {
            view[key] = value.clone();
        }
    }
    view
}

/// 组装一条可落库的账号。
pub fn normalized(mut secret: Value, name: Option<&str>, local: bool) -> Value {
    if let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) {
        secret["name"] = json!(name.chars().take(128).collect::<String>());
    }
    json!({
        "identity": identity(&secret),
        "public": public(&secret),
        "secret": secret,
        "desktop": local,
    })
}

/// `account.normalize`：桌面导入 / 表单（含 `payload.inputs`）/ 文本文件。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let name = params["name"].as_str().map(str::to_string);
    let name = name.as_deref();
    let mut local = false;
    let mut secret = match kind {
        "desktop" => {
            local = true;
            local_reference()?
        }
        "manual" => {
            // 动态登录方式把表单整包放进 `payload.inputs`，旧入口是平铺字段。
            let payload = &source["payload"];
            let fields = payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload);
            let parsed = parse(fields)?;
            if text(&parsed, &["accessToken"]).is_empty() {
                parsed
            } else {
                let user = fetch_self(&text(&parsed, &["accessToken"]))?;
                let mut parsed = parsed;
                parsed["user"] = user;
                parsed
            }
        }
        "file_text" => {
            let content = source["content"].as_str().unwrap_or("");
            let parsed = parse_text(content)?;
            if text(&parsed, &["accessToken"]).is_empty() {
                parsed
            } else {
                let user = fetch_self(&text(&parsed, &["accessToken"]))?;
                let mut parsed = parsed;
                parsed["user"] = user;
                parsed
            }
        }
        "file_base64" => {
            return Err(Error::http(
                400,
                "QuWork 请使用本机导入、凭证 JSON 或 .credentials.yaml 文本，不接受二进制文件",
            ))
        }
        _ => return Err(Error::http(400, "QuWork 请使用本机导入或粘贴凭证")),
    };
    if !local {
        if text(&secret, &["name"]).is_empty() {
            secret["name"] = json!("QuWork");
        }
    }
    Ok(normalized(secret, name, local))
}

/// 查一次账号信息（`/api/user/self`），失败就报错（添加账号时用户需要知道）。
fn fetch_self(access: &str) -> Result<Value> {
    let reply = upstream::request("GET", upstream::SELF_PATH, access, None)?;
    let user = reply.data("账号查询")?;
    if !user.is_object() {
        return Err(Error::http(502, "QuWork 账号信息格式异常"));
    }
    Ok(user_view(&user))
}

/// 当前账号的 secret（桌面账号会现读一次本机登录态）。
pub fn current() -> Result<Value> {
    let record = sdk::account()?;
    let secret = record["secret"].clone();
    if secret.get("source").and_then(Value::as_str) != Some("desktop") {
        return Ok(secret);
    }
    // 桌面账号只存引用：模型凭证与登录凭证每次现读，避免拿旧 token 打上游。
    let live = local_secret()?;
    if identity(&live) != identity(&secret) {
        return Err(Error::http(
            409,
            "QuWork 客户端已切换账号，请重新导入；不会将原账号自动替换成其他账号",
        ));
    }
    Ok(live)
}

/// 读宿主提供的本机登录态（`desktop.credentials.read`）。
pub fn local_secret() -> Result<Value> {
    let raw = sdk::host("desktop.credentials.read", json!({})).map_err(|error| {
        Error::http(
            400,
            format!("读取 QuWork 本机登录态失败：{}（请先在官方客户端登录，或改为粘贴凭证）", error.message),
        )
    })?;
    // 宿主回的是 `{sourceRevision, content}`：content 里才是凭据 JSON。
    let content = raw
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| raw.get("credentials").map(|value| value.to_string()));
    let Some(content) = content else {
        return Err(Error::http(400, "QuWork 本机登录态内容为空，请改为粘贴凭证"));
    };
    parse_text(&content)
}

/// 桌面导入的引用形态（不含 token，只留指纹与尾号）。
pub fn local_reference() -> Result<Value> {
    let secret = local_secret()?;
    let llm = text(&secret, &["llmToken"]);
    let view = public(&secret);
    Ok(json!({
        "source": "desktop",
        "user": secret.get("user").cloned().unwrap_or(Value::Null),
        "modelFingerprint": fingerprint(&llm),
        "tokenTail": view.get("tokenTail").cloned().unwrap_or(Value::Null),
        "hasLoginToken": !text(&secret, &["accessToken"]).is_empty(),
        "expiresAt": secret.get("expiresAt").cloned().unwrap_or(Value::Null),
        "origin": secret.get("origin").cloned().unwrap_or(Value::Null),
    }))
}

/// 模型凭证（对话用）：桌面账号现读，其余读账号 secret。
pub fn model_token() -> Result<String> {
    let secret = current()?;
    let secret = if expiring(&secret) {
        // 账号服务不可用不应阻断仍有效的独立模型凭证。
        super::refresh::ensure(false).unwrap_or(secret)
    } else {
        secret
    };
    let token = text(&secret, &["llmToken"]);
    if token.is_empty() {
        Err(Error::http(401, "QuWork 缺少模型凭证，请重新导入账号"))
    } else {
        Ok(token)
    }
}

/// 登录会话是否临期（没有登录会话时恒 false）。
pub fn expiring(secret: &Value) -> bool {
    !text(secret, &["accessToken"]).is_empty()
        && upstream::timestamp(secret.get("expiresAt"))
            .is_some_and(|expiry| expiry <= sdk::now() + upstream::REFRESH_WINDOW_MS)
}

/// 必须有登录会话（积分/签到/兑换用）。
pub fn require_login(secret: &Value) -> Result<String> {
    let access = text(secret, &["accessToken"]);
    if access.is_empty() {
        return Err(Error::http(
            401,
            "QuWork 只提供了模型凭证，不能用于积分 / 续期 / 奖励；请重新导入完整登录态",
        ));
    }
    Ok(access)
}

/// 校验一个外部输入的时间戳字段（公开视图里的 `expiresAt`）。
pub fn expiry_of(value: &Value) -> Option<i64> {
    upstream::timestamp(value.get("expiresAt"))
}
