//! 错误文本脱敏：上游的诊断体、以及任何会回给客户端/日志的原文，都可能夹带
//! 我们自己发出去的凭据（上游确实会把 `X-Security-Token` 回显在错误里）。
//!
//! ── 为什么要连「变形后的写法」一起盖 ────────────────────────
//! 同一段秘密会以三种形态出现在上游文本里：原样、URL 编码后（`%2B` / `%2F`）、
//! 以及表单口径（`+` / `%2F`）。只替换原样那种，另外两种等于没盖 —— 尤其是
//! STS token 里的 `+/=` 一定会被编码。
//!
//! ── 为什么截断之后还要再盖一遍 ──────────────────────────────
//! 截断可能把一段秘密切成**前缀**，那时原样匹配不到完整串。所以对「末尾正好是
//! 某个秘密前缀」这种情况再单独处理一次：宁可把半截也盖掉，也不要漏一段。

use super::credentials::Credential;

/// 被盖掉的位置放这个（可读，且一眼能看出是网关盖的而不是上游给的）。
pub const REDACTED: &str = "[REDACTED]";

/// 从凭据里取出所有需要盖掉的秘密。
fn secrets_of(credential: &Credential) -> Vec<String> {
    let mut secrets = vec![
        credential.access_key_id.clone(),
        credential.secret_access_key.clone(),
        credential.security_token.clone(),
        credential.refresh_token.clone(),
    ];
    if let Some(context) = credential.oauth_context.as_ref() {
        secrets.push(context.pkce_pair.code_verifier.clone());
        secrets.push(context.pkce_pair.code_challenge.clone());
    }
    secrets.retain(|value| !value.trim().is_empty());
    secrets
}

/// 一段秘密的全部写法：原样 / URL 编码 / 表单编码。
fn spellings(secret: &str) -> Vec<String> {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = vec![trimmed.to_string()];
    let encoded = super::signer::encode_component(trimmed.as_bytes());
    if encoded != trimmed {
        out.push(encoded);
    }
    let form = super::upstream::form_escape(trimmed);
    if form != trimmed && !out.contains(&form) {
        out.push(form);
    }
    out
}

/// 把报文里的秘密全部盖掉。
///
/// `truncated` 为真时额外处理「末尾是某个秘密的前缀」：截断点可能正好切在秘密中间。
pub fn redact(message: &str, credential: &Credential, truncated: bool) -> String {
    let mut secrets = secrets_of(credential);
    if truncated {
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
    }
    redact_values(message, &secrets, truncated)
}

/// 同上，但秘密由调用方给出（用于 `admin.action` 之类只拿到 secret 的路径）。
pub fn redact_values(message: &str, secrets: &[String], truncated: bool) -> String {
    let mut out = message.to_string();
    for secret in secrets {
        for spelling in spellings(secret) {
            if spelling.len() < 6 {
                // 太短的值（比如 "ab"）替换起来会把正常文本砸烂，且它也不构成秘密
                continue;
            }
            out = out.replace(&spelling, REDACTED);
        }
    }
    if truncated {
        // 末尾那段可能是某个秘密的前半截：从最短的 6 个字符起试，够长就盖
        if let Some(index) = find_partial(&out, secrets) {
            out.truncate(index);
            out.push_str(REDACTED);
        }
    }
    out
}

/// 找出「文本末尾正好是某个秘密前缀」的起点。找不到返回 None。
fn find_partial(text: &str, secrets: &[String]) -> Option<usize> {
    for size in (6..=64).rev() {
        if text.len() < size {
            continue;
        }
        let mut start = text.len() - size;
        while !text.is_char_boundary(start) {
            start -= 1;
        }
        let tail = &text[start..];
        if secrets.iter().any(|secret| {
            let secret = secret.trim();
            secret.len() > tail.len() && secret.starts_with(tail)
        }) {
            return Some(start);
        }
    }
    None
}
