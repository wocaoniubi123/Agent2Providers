//! JWT 声明解码（移植来源 `jwt-helper.mjs`，native 侧同名文件）。
//!
//! 小浣熊的登录 token 是标准 JWT（HS256 由服务端校验），**本地只解 payload、
//! 不验签**：网关需要的是 `exp`（临期判定）、`name`（缺省备注名）与十六进制
//! 用户 id（账号标识）。验签没有意义 —— 网关不做鉴权判定，token 好不好用
//! 由上游说了算。
//!
//! ── 为什么单独一个文件 ──────────────────────────────────────
//! 这些是**纯函数**（无 IO、无状态），与「读账号记录 / 调刷新接口」那件事
//! 天然分开；拆开之后 `credentials.rs` 只剩刷新编排，读起来是一张流程图。
//!
//! ── 绝不 panic ──────────────────────────────────────────────
//! 解析失败一律返回 None（源实现同样返回 null）——release 是 `panic=abort`，
//! 一条畸形 token（用户手改文件、复制时截断）不能带走整个插件实例。

use agent2api_wasm_sdk::{Error, Result, Value};

/// 解码 JWT 的 payload 段。
///
/// 与源实现 `decodeJwtClaims` 逐条对齐：去掉 `Bearer ` 前缀、按 `.` 切段、
/// 取第二段做 base64url → base64 的替换与填充、解析 JSON、根必须是对象。
pub fn decode_jwt_claims(token: &str) -> Option<Value> {
    let raw = strip_bearer(token);
    let mut parts = raw.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    if payload.is_empty() {
        return None;
    }
    let decoded = base64_url_to_bytes(payload)?;
    let text = String::from_utf8(decoded).ok()?;
    let claims = serde_json::from_str::<Value>(&text).ok()?;
    if claims.is_object() {
        Some(claims)
    } else {
        None
    }
}

/// IAM 的 issuer 以 `/iam` 结尾；这里只识别协议，签名仍由上游校验。
pub fn is_iam_token(token: &str) -> bool {
    decode_jwt_claims(token)
        .and_then(|claims| {
            claims
                .get("iss")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|issuer| issuer.ends_with("/iam"))
}

/// IAM 登录态的三条判据（issuer 命中、sub 非空、未过期）。
///
/// `expected_issuer` 由调用方给（native 侧是「环境变量 → 从鉴权基址反推」，
/// wasm 侧则是「settings 里的覆盖值 → 从鉴权基址反推」，见
/// [`crate::upstream::iam_issuer`]）。
pub fn validate_iam_token(token: &str, expected_issuer: &str) -> Result<()> {
    let claims = decode_jwt_claims(token).unwrap_or(Value::Null);
    let valid = claims.get("iss").and_then(Value::as_str) == Some(expected_issuer)
        && claims
            .get("sub")
            .and_then(Value::as_str)
            .is_some_and(|subject| !subject.trim().is_empty())
        && jwt_expiry_ms(token).is_some_and(|expires| expires > agent2api_wasm_sdk::now() as f64);
    if valid {
        Ok(())
    } else {
        Err(Error::http(
            401,
            "小浣熊 IAM 登录态无效或已过期，请在官方客户端重新登录后再导入",
        ))
    }
}

/// token 的过期时间（毫秒）；没有 `exp` 或 token 不可解析时 None
/// （源实现 `jwtExpiryMs`）。`exp` 是**秒**，这里换算成毫秒。
pub fn jwt_expiry_ms(token: &str) -> Option<f64> {
    let claims = decode_jwt_claims(token)?;
    let exp = claims.get("exp").and_then(number_value)?;
    if exp > 0.0 {
        Some(exp * 1000.0)
    } else {
        None
    }
}

/// 按小浣熊约定提取用户 ID（源实现 `extractRaccoonUserId`）：
/// 依次尝试 `sid`（十六进制）→ `iss`（十六进制）→ `sub` / `id` / `user_id`。
///
/// ── 本机实测（2026-09）─────────────────────────────────────
/// `sid` 形如 `web65aa393e65a6b6d446a51dde22c-a6d6-48e2`：它不是纯十六进制
/// （带 `w` 前缀与 `-`），所以十六进制那条返回空、**真正命中是 `iss`**
/// （如 `6d446a` → 十进制 `7160938`，与旧账号文件里的 userId 完全一致）。
/// 两条路径都必须实现：少了任何一条都会让一批账号的 userId 变成空串，
/// 而 userId 正是小浣熊账号的标识。
pub fn extract_user_id(claims: &Value) -> String {
    if claims
        .get("iss")
        .and_then(Value::as_str)
        .is_some_and(|issuer| issuer.ends_with("/iam"))
    {
        return claims
            .get("sub")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
    }
    for key in ["sid", "iss"] {
        if let Some(value) = claims.get(key).and_then(hex_id_to_decimal) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    for key in ["sub", "id", "user_id"] {
        let text = claims.get(key).map(js_text).unwrap_or_default();
        let text = text.trim();
        if !text.is_empty() {
            return text.to_string();
        }
    }
    String::new()
}

/// 展示用名字（JWT 的 `name`；账号缺省备注名从这里来）
pub fn display_name(claims: &Value) -> String {
    claims
        .get("name")
        .map(js_text)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 十六进制字符串 → 十进制字符串（源实现 `hexIdToDecimalString`）。
///
/// 手写转换而不是 `u64::from_str_radix`：`iss` 可能超出 u64，源实现用 BigInt
/// 无上限；这里用「十进制结果 × 16 + 当前位」的大数运算复刻同一语义。
fn hex_id_to_decimal(value: &Value) -> Option<String> {
    let raw = match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let normalized = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(&raw);
    if normalized.is_empty() || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let mut digits: Vec<u8> = vec![0];
    for ch in normalized.chars() {
        let mut carry = ch.to_digit(16)?;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 16 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let trimmed: String = digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect();
    let trimmed = trimmed.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    })
}

/// base64url → 字节（源实现的 `replace(/-/g,'+').replace(/_/g,'/')` + 补 `=`）
fn base64_url_to_bytes(input: &str) -> Option<Vec<u8>> {
    let mut normalized: String = input
        .chars()
        .map(|ch| match ch {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let remainder = normalized.len() % 4;
    if remainder != 0 {
        normalized.push_str(&"=".repeat(4 - remainder));
    }
    base64_decode(&normalized)
}

/// 标准 base64 解码（自己实现，避免为一个纯函数引进新依赖）。
///
/// 只处理 `A-Za-z0-9+/=`，遇非法字符返回 None —— JWT payload 就是这些字符，
/// 出现别的说明这不是 base64（宁可返回 None，也不做容错式猜测）。
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let table = |ch: char| -> Option<u8> {
        match ch {
            'A'..='Z' => Some(ch as u8 - b'A'),
            'a'..='z' => Some(ch as u8 - b'a' + 26),
            '0'..='9' => Some(ch as u8 - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    };
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let value = table(ch)?;
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// 去 `Bearer ` 前缀（大小写不敏感，至少一个空白），不匹配时原样返回
/// （与源实现 `String.replace(/^Bearer\s+/i, '')` 一致）
///
/// ── 为什么循环剥到底 ────────────────────────────────────────
/// 只剥一次时，存量脏值 `Bearer Bearer eyJ…`（旧版本原样落库的双前缀值）
/// 会剥成 `Bearer eyJ…`，调用方再拼一个就又是双前缀 —— 与没修一样。
/// `balance.rs` 正是「剥完再拼」的用法，所以这里必须剥干净。
pub fn strip_bearer(value: &str) -> String {
    const PREFIX: &str = "bearer";
    let prefix = PREFIX.as_bytes();
    let mut current = value.trim();
    loop {
        let bytes = current.as_bytes();
        if bytes.len() < prefix.len() {
            return current.to_string();
        }
        // 先按字节比较再切片：`split_at(6)` 在多字节字符上会切到非字符边界
        // 而 panic（native 侧同一段代码有这个隐患）。前缀本身是纯 ASCII，
        // 「比较通过」就等于「第 6 个字节是边界」，之后的切片一定安全。
        if !bytes[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return current.to_string();
        }
        let rest = &current[prefix.len()..];
        // 恰好等于 `Bearer`：只有前缀没有凭证，给空串
        if rest.is_empty() {
            return String::new();
        }
        if rest.trim_start().len() == rest.len() {
            // `Bearerxyz`：前缀后没有空白，不构成前缀
            return current.to_string();
        }
        current = rest.trim_start();
    }
}

/// JS `String(x)`（字符串原样、数字/布尔按字面量、null 给空串）
pub fn js_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// JS `Number(x)`（只给 JWT 的 exp 用；非有限值当没有）
fn number_value(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if number.is_finite() {
        Some(number)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base64url 编码（只给测试造 token 用）。
    fn b64url(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk[0] as u32;
            let second = *chunk.get(1).unwrap_or(&0) as u32;
            let third = *chunk.get(2).unwrap_or(&0) as u32;
            let value = (first << 16) | (second << 8) | third;
            out.push(TABLE[(value >> 18) as usize & 0x3f] as char);
            out.push(TABLE[(value >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(value >> 6) as usize & 0x3f] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[value as usize & 0x3f] as char);
            }
        }
        out
    }

    fn token_of(claims: &str) -> String {
        format!("{}.{}.sig", b64url(b"{\"alg\":\"HS256\"}"), b64url(claims.as_bytes()))
    }

    #[test]
    fn strip_bearer_strips_to_the_bottom() {
        assert_eq!(strip_bearer("  Bearer abc  "), "abc");
        // 存量脏值（双前缀）必须剥干净，否则调用方再拼一个又是双前缀
        assert_eq!(strip_bearer("bearer Bearer xyz"), "xyz");
        // 前缀后没有空白 → 不构成前缀
        assert_eq!(strip_bearer("Bearerxyz"), "Bearerxyz");
        // 只有前缀 → 空串
        assert_eq!(strip_bearer("Bearer"), "");
        // 多字节字符不能把这段剥前缀的逻辑打成 panic
        assert_eq!(strip_bearer("a中中"), "a中中");
    }

    /// 解不出 claims 时给一个空对象，让后面的断言以「字段对不上」的形式失败
    /// （测试里不用 `expect`/`unwrap`，与本 crate 的纪律一致）。
    fn claims_of(token: &str) -> Value {
        decode_jwt_claims(token).unwrap_or(Value::Null)
    }

    #[test]
    fn claims_decode_and_identity_extraction() {
        // iss 是十六进制 → 十进制（0x6d446a = 7160938）
        let token = token_of("{\"iss\":\"6d446a\",\"name\":\"浣熊\"}");
        let claims = claims_of(&token);
        assert!(claims.is_object());
        assert_eq!(extract_user_id(&claims), "7160938");
        assert_eq!(display_name(&claims), "浣熊");
        assert!(!is_iam_token(&token));
    }

    #[test]
    fn iam_token_uses_subject() {
        let token = token_of("{\"iss\":\"xiaohuanxiong.com/iam\",\"sub\":\"user-sub\",\"exp\":1700000000}");
        let claims = claims_of(&token);
        assert!(claims.is_object());
        assert!(is_iam_token(&token));
        assert_eq!(extract_user_id(&claims), "user-sub");
        // exp 是秒 → 毫秒
        assert_eq!(jwt_expiry_ms(&token), Some(1_700_000_000_000.0));
    }

    #[test]
    fn broken_tokens_return_none() {
        assert!(decode_jwt_claims("").is_none());
        assert!(decode_jwt_claims("not-a-jwt").is_none());
        assert!(decode_jwt_claims("a..c").is_none());
        assert!(jwt_expiry_ms("a.b.c").is_none());
    }
}
