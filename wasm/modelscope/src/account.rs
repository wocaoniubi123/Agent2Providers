//! ModelScope 凭证：**只有一条来源** —— 账号记录里的 `ms-` 令牌。
//!
//! ── 为什么只要一个字段（实测依据，见 `upstream.rs` 的模块头）────────
//! 同一个 `ms-...` 令牌既作 `Authorization: Bearer` 调推理，又作
//! `Cookie: m_session_id=<key>` 调网页站接口 —— 两条链路实测都是 200。
//!
//! ── 没有续期 ────────────────────────────────────────────────
//! 魔搭的 `ms-` 令牌是**长期有效**的（上游没有任何 refresh / renew 接口）。
//! 因此 `refresh = false`，令牌失效只能重新去魔搭控制台复制一个。
//! `token.expiring` 恒回 false：判不出到期时刻的东西不该被批量维护链反复刷。
//!
//! ── 备份字段 ────────────────────────────────────────────────
//! `accessToken` 是网关的落盘名；粘贴形态另外兼容 `apiKey` / `token` /
//! `session` —— 用户从别处复制过来的 JSON 里字段名并不统一。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::{probe, upstream};

/// 账号名长度上限（与网关侧 `truncate_chars(&record_name, 100)` 同口径）。
const MAX_NAME_LENGTH: usize = 100;

/// 从一条取值链里挑第一个非空字符串（记录可能被手工编辑过，宽容读取）。
fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 从账号的 `secret` 里取令牌（**唯一入口**）。
pub fn token_of(secret: &Value) -> Result<String> {
    let token = token_from_payload(secret);
    if token.is_empty() {
        return Err(Error::http(
            401,
            "ModelScope 账号缺少令牌，请重新粘贴",
        ));
    }
    Ok(token)
}

/// 从**上传的 payload** 里取令牌（添加路径专用：先取出来去探活，再落账号）。
///
/// 与 [`token_of`] 的取值链**逐字相同** —— 两处口径分叉的话，「能探活成功
/// 却落不进账号」或反之都会变成难查的静默问题。
pub fn token_from_payload(payload: &Value) -> String {
    pick(payload, &["accessToken", "apiKey", "token", "session"])
}

/// 令牌尾 4 字符（公开形态与默认备注名用）。
///
/// 按 `char` 取而不按字节切：粘贴形态的输入框不做格式校验，一个带汉字的
/// 误粘贴就能让按字节回切落在多字节字符中间。
pub fn token_tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 账号备注名：记录里的 `name` → 默认「ModelScope 国内版 <尾 4 位>」。
///
/// `name` 在 `normalize` 时写进 `secret`（native 只放在 `public` 里）：
/// 公开视图要在**只拿得到 `secret`** 的 `account.view` 上也能重建出同一个名字，
/// 否则凭证更新一次，账号列表里那一行就会变回一堆看不懂的默认值。
pub fn display_name(secret: &Value) -> String {
    let name = pick(secret, &["name"]);
    if !name.is_empty() {
        return truncate_chars(&name, MAX_NAME_LENGTH);
    }
    let tail = token_tail(&token_from_payload(secret));
    if tail.is_empty() {
        format!("ModelScope {}", upstream::LABEL)
    } else {
        format!("ModelScope {} {tail}", upstream::LABEL)
    }
}

/// 把账号备注名按字符数截断（不是字节：中文名按字节截会切出半个字符）。
fn truncate_chars(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    value.chars().take(limit).collect()
}

/// `token.ensure`：当前账号有没有可用令牌。
///
/// 本家**没有续期**：这里只做「记录里有没有令牌」的检查，服务端拒了就是 401，
/// 网关会把它归成 `TokenExpired` 并在刷新失败后如实报给客户端
/// （「请重新粘贴令牌」）。
pub fn ensure() -> Result<String> {
    let record = sdk::account()?;
    token_of(&record["secret"])
}

/// `token.refresh`：本家没有续期接口，如实说清楚该怎么恢复。
pub fn refresh() -> Result<String> {
    Err(Error::http(
        401,
        "ModelScope 的 ms- 令牌长期有效、上游没有续期接口：请到魔搭控制台重新复制一个令牌，\
         在账号页重新粘贴",
    ))
}

/// `account.view`：界面用的公开视图（**绝不带令牌本体**）。
pub fn view(secret: &Value) -> Value {
    let user_id = pick(secret, &["userId", "havanaId", "havana_id"]);
    json!({
        "name": display_name(secret),
        "uid": user_id,
        "tokenTail": token_tail(&token_from_payload(secret)),
        // 地区由 provider id 直接表达，这里只留一列给人看的标签
        "edition": upstream::LABEL,
    })
}

/// `account.identity`：去重用的稳定身份。
///
/// 优先 `HavanaId`（上游给的稳定 id）；拿不到时用令牌尾号兜底 —— 那会退化成
/// 按凭证去重，同一个账号换一次令牌就会多一条记录，网关会就此提示用户。
pub fn identity(secret: &Value) -> String {
    let user_id = pick(secret, &["userId", "havanaId", "havana_id"]);
    if !user_id.is_empty() {
        return format!("{}{user_id}", upstream::ACCOUNT_PREFIX);
    }
    let tail = token_tail(&token_from_payload(secret));
    if tail.is_empty() {
        String::new()
    } else {
        format!("{}{tail}", upstream::ACCOUNT_PREFIX)
    }
}

/// `account.normalize`：把用户给的输入变成一条可落库的账号。
///
/// ── 为什么添加这一步要出网 ──────────────────────────────────
/// 魔搭的令牌**不携带任何可解析的身份**（它是一串不透明的 `ms-…`，不是 JWT）。
/// 不出网的话只能拿令牌尾号当账号 id —— 同一个账号换一次令牌就会变成**两条
/// 记录**，用户看到「我明明只有一个魔搭账号，怎么越加越多」。
/// 因此添加前先交换一次身份（见 `probe.rs`），用上游给的稳定 id 做记录 id。
/// 顺带把「令牌无效 / 不属于该站点」在添加的那一刻就说清楚，并且这次调用
/// **同时触发当日签到** —— 添加账号的人当天就把魔粒拿到手。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let (token, name) = match source["kind"].as_str() {
        Some("manual") => {
            // 表单可能把字段平铺，也可能包在 `inputs` 里（与 atomcode 同口径）
            let payload = &source["payload"];
            let payload = if payload["inputs"].is_object() {
                &payload["inputs"]
            } else {
                payload
            };
            let token = token_from_payload(payload);
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            (token, name)
        }
        Some("file_text") => {
            let content = source["content"].as_str().unwrap_or("");
            let trimmed = content.trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
                (token_from_payload(&parsed), None)
            } else {
                (trimmed.to_string(), None)
            }
        }
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "ModelScope 不支持二进制文件导入，请粘贴 ms- 令牌",
            ))
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "ModelScope 不支持导入桌面端登录态，请粘贴 ms- 令牌添加账号",
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "ModelScope 只支持粘贴 ms- 令牌添加账号",
            ))
        }
    };
    if token.is_empty() {
        return Err(Error::http(
            400,
            "缺少令牌（accessToken / apiKey / token / session）",
        ));
    }

    // 探活 + 取身份（同时也是当日签到，见 `probe.rs` 的模块头）
    let identity = probe::identify(&token)?;
    let user_id = identity.user_id.trim().to_string();
    let id = format!("{}{user_id}", upstream::ACCOUNT_PREFIX);
    let display = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(name)
        .or_else(|| {
            (!identity.display_name.is_empty()).then(|| identity.display_name.clone())
        })
        .unwrap_or_else(|| {
            format!(
                "ModelScope {} {}",
                upstream::LABEL,
                token_tail(&token)
            )
        });
    let display = truncate_chars(&display, MAX_NAME_LENGTH);

    let mut secret = json!({
        "accessToken": token,
        "userId": user_id,
    });
    // 名字写进 `secret`：`account.view` 只拿得到 secret（见 `display_name` 的说明）
    secret["name"] = json!(display);

    Ok(json!({
        "secret": secret,
        "public": {
            "name": display,
            "uid": user_id,
            "tokenTail": token_tail(&token),
            "edition": upstream::LABEL,
        },
        "identity": id,
        "desktop": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 四条取值链要在同一个顺序上，`token_of` 与 `token_from_payload` 不许分叉。
    #[test]
    fn both_token_readers_agree_on_the_same_chain() {
        for (payload, expect) in [
            (json!({ "accessToken": "ms-a" }), "ms-a"),
            (json!({ "apiKey": "ms-b" }), "ms-b"),
            (json!({ "token": "ms-c" }), "ms-c"),
            (json!({ "session": "ms-d" }), "ms-d"),
            (json!({ "session": "  " }), ""),
        ] {
            assert_eq!(expect, token_from_payload(&payload));
            match token_of(&payload) {
                Ok(token) => assert_eq!(expect, token),
                Err(_) => assert_eq!("", expect, "只有空值才算缺令牌"),
            }
        }
    }

    /// 尾号按字符取：带汉字的误粘贴不许把多字节字符切开。
    #[test]
    fn the_tail_is_measured_in_characters() {
        assert_eq!("cdef", token_tail("abcdef"));
        assert_eq!("搭令牌值", token_tail("魔搭令牌值"));
        assert_eq!("", token_tail(""));
    }

    /// 身份带前缀；缺 userId 时退到令牌尾号。
    #[test]
    fn the_identity_prefers_the_havana_id() {
        assert_eq!(
            "modelscope-12345",
            identity(&json!({ "userId": "12345", "accessToken": "ms-x" }))
        );
        assert_eq!(
            "modelscope-ms-x",
            identity(&json!({ "accessToken": "ms-x" }))
        );
        assert_eq!("", identity(&json!({})));
    }

    /// 视图里不许出现令牌本体，只给尾号。
    #[test]
    fn the_view_never_carries_the_token_itself() {
        let secret = json!({ "accessToken": "ms-secret-token", "userId": "42", "name": "我的魔搭" });
        let view = view(&secret);
        assert_eq!("我的魔搭", view["name"].as_str().unwrap_or_default());
        assert_eq!("42", view["uid"].as_str().unwrap_or_default());
        assert_eq!("oken", view["tokenTail"].as_str().unwrap_or_default());
        assert!(!view.to_string().contains("ms-secret-token"));
    }
}
