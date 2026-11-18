//! Command Code 凭证：**单个粘贴的 API Key**（无 OAuth、无设备码、无续期）。
//!
//! ── 上游的凭证形态 ──────────────────────────────────────────
//! 一个以 `user_` 开头的字符串，从 <https://commandcode.ai/studio> 或本机
//! `~/.commandcode/auth.json` 自取。插件侧只需要把它透传成
//! `Authorization: Bearer <key>`。
//!
//! ── 在插件架构里的落点（与网关版的一处实质差别）─────────────────
//! 网关版从 `store.commandcode_account_record()` 读记录；这里从
//! `sdk::account()` 读 —— 记录的 `secret` 是插件自己写进去的那份 JSON
//! （见 `account::normalize`），所以取值链只在 `secret` 里找。
//!
//! ── 校验：本地形态检查为主，线上探活是 best-effort ───────────────
//! 形态检查**必定执行**（本地、零网络），线上探活**尽力而为** —— 只有拿到
//! 401/403 才判无效，网络失败 / 5xx / 未知一律按「暂时判不出来」放行
//! （否则一次上游抖动就会让用户加不进账号）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{http, Value};

use super::endpoints;
use super::util;

/// Key 前缀（上游要求的唯一硬性形态）
pub const KEY_PREFIX: &str = "user_";

/// Key 字符集（`user_` 之后是 `[a-zA-Z0-9_-]+`）
fn is_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// 形态检查：以 `user_` 开头、其后至少一个合法字符、且整串都在字符集内。
pub fn shape_ok(key: &str) -> bool {
    let trimmed = key.trim();
    let Some(rest) = trimmed.strip_prefix(KEY_PREFIX) else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(is_key_char)
}

/// 展示用的脱敏形态（只露前缀与尾 4 位）。
pub fn masked(key: &str) -> String {
    let chars: Vec<char> = key.trim().chars().collect();
    if chars.len() <= 12 {
        return format!("{KEY_PREFIX}…");
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{KEY_PREFIX}…{tail}")
}

/// 从账号的 `secret` 里取 API Key（**唯一入口**）。
///
/// 字段兼容：`apiKey`（本插件落盘名）/ `accessToken` / `token` / `key` ——
/// 用户从别处粘过来的 JSON 里字段名并不统一，宽容读取比报错更实用。
pub fn api_key_of(secret: &Value) -> Result<String, String> {
    let api_key = util::pick(secret, &["apiKey", "accessToken", "token", "key"]);
    if api_key.is_empty() {
        return Err("Command Code 账号缺少 API Key，请重新粘贴（user_ 开头）".to_string());
    }
    if !shape_ok(&api_key) {
        return Err(format!(
            "Command Code API Key 形态不对（应为 user_ 开头、只含字母数字与 _ -，当前 {}）：\
             请在 commandcode.ai/studio 重新获取",
            masked(&api_key)
        ));
    }
    Ok(api_key)
}

/// 线上探活的结果
pub enum KeyCheck {
    /// 上游认这个 key（2xx）
    Valid,
    /// 上游明确拒绝（401/403）—— key 无效 / 已失效
    Invalid(String),
    /// 这次判不出来（网络失败 / 其他状态码）—— **按可用放行**
    Unknown(String),
}

/// `GET /alpha/billing/credits` 探活（401/403 即无效）。
///
/// 为什么用 billing 而不是随便一个需要鉴权的端点：`/alpha/generate` 会把
/// 一次**真实生成**的额度花掉；billing 是只读的额度查询，对账号零副作用。
pub fn probe_key(api_key: &str) -> KeyCheck {
    let mut headers = endpoints::cli_headers();
    headers.extend(endpoints::auth_headers(api_key));
    let response = match http::open(
        "GET",
        &endpoints::url(endpoints::BILLING_CREDITS_PATH),
        util::headers_value(&headers),
        None,
    ) {
        Ok(response) => response,
        Err(error) => return KeyCheck::Unknown(format!("探活请求失败：{}", error.message)),
    };
    let status = response.status;
    // 状态码已经拿到，响应体对本判定没有用处：读掉它以让连接走到 EOF
    // （`Response` 的 Drop 会关连接，但先读完可以让宿主少留一个半开的句柄）。
    let _ = response.bytes(64 * 1024);
    if status == 401 || status == 403 {
        KeyCheck::Invalid(format!("上游返回 HTTP {status}"))
    } else if (200..300).contains(&status) {
        KeyCheck::Valid
    } else {
        KeyCheck::Unknown(format!("上游返回 HTTP {status}"))
    }
}

/// 令牌尾 4 字符（公开形态用；按 `char` 取，多字节输入不得 panic）
pub fn tail_of(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// 粘贴归一化：剥引号 / 整行前缀 / 尾部杂字段，返回**裸 key**。
///
/// 认得的形态：裸 key、带成对引号、`Authorization: Bearer user_…`、
/// `x-api-key: user_…`、整行 `Cookie: …`、以及 key 后面还跟着别的字段
/// （`…user_xxx; Path=/` 之类）。做法是**扫描 `user_` 并取其后连续合法字符**
/// （正则 `user_[a-zA-Z0-9_-]+` 的手写形态）—— 这一步同时完成前缀剥离与
/// 尾部截断。扫不到 `user_` 时只剥引号与空白，交给形态检查给出可读的报错。
pub fn normalize_key(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ';'))
        .trim();
    if let Some(key) = extract_key(trimmed) {
        return key;
    }
    // 没有 `user_` 形态：仍把空白剥掉（key 里不含空白）
    trimmed.chars().filter(|ch| !ch.is_whitespace()).collect()
}

/// 扫描第一个 `user_` 并取其后连续合法字符
fn extract_key(text: &str) -> Option<String> {
    let start = text.find(KEY_PREFIX)?;
    let rest = &text[start + KEY_PREFIX.len()..];
    let body: String = rest.chars().take_while(|ch| is_key_char(*ch)).collect();
    if body.is_empty() {
        return None;
    }
    Some(format!("{KEY_PREFIX}{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_accepts_only_the_documented_alphabet() {
        assert!(shape_ok("user_abc-123_XYZ"));
        assert!(!shape_ok("sk-abc"));
        assert!(!shape_ok("user_"));
        assert!(!shape_ok("user_abc def"));
        assert!(!shape_ok("user_abc\ndef"));
    }

    #[test]
    fn normalization_strips_wrappers_and_trailers() {
        assert_eq!(normalize_key("\"user_abc\""), "user_abc");
        assert_eq!(normalize_key("Authorization: Bearer user_abc123"), "user_abc123");
        assert_eq!(normalize_key("x-api-key: user_abc; Path=/"), "user_abc");
        // 空白是 key 的终止符：`user_` 之后遇到空格就截断（CLI 的同款扫描规则）
        assert_eq!(normalize_key("  user_a b c  "), "user_a");
        // 扫不到前缀：只剥空白，交给形态检查报错
        assert_eq!(normalize_key(" Bearer nope "), "Bearernope");
    }

    #[test]
    fn masked_never_panics_on_short_or_multibyte_input() {
        assert_eq!(masked("user_"), "user_…");
        assert_eq!(masked("user_abcdefghijkl"), "user_…ijkl");
        // 多字节：按 char 计数，不得落在字符中间
        assert_eq!(masked("user_汉字汉字汉字汉字汉字"), "user_…汉字汉字");
        // 尾 4 位按 char 取，不按字节切
        assert_eq!(tail_of("user_汉字"), "r_汉字");
    }

    #[test]
    fn api_key_lookup_is_lenient_about_field_names() {
        assert_eq!(
            api_key_of(&serde_json::json!({ "token": "user_ok1" })),
            Ok("user_ok1".to_string())
        );
        assert!(api_key_of(&serde_json::json!({})).is_err());
        assert!(api_key_of(&serde_json::json!({ "apiKey": "bad" })).is_err());
    }
}
