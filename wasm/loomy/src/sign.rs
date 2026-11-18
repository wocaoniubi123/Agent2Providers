//! Loomy 账号（CAccount）请求签名：HMAC-SHA1（复刻客户端 `electron/xfyun/sign.js`）。
//!
//! ── 待签字符串（9 段，`\n` 连接，与客户端 `generateSignature` 逐字同构）──
//! ```text
//!   METHOD
//!   ESCAPED_PATH          RFC3986 §3.3（逐段编码后再替换 !'()* ）
//!   ESCAPED_QUERY         本项目所有账号接口都无 query，恒为空串
//!   CONTENT_MD5           base64(md5(body 字节串))；无 body 时为空串
//!   CONTENT_TYPE          "application/json"
//!   DATE                  UTC 的 `Tue, 07 Oct 2026 08:00:00 GMT` 形态
//!   NONCE                 UUID v4（带连字符）
//!   SIGNED_HEADERS        只列 `x-` 前缀头；本项目不带，恒为空串
//!   CANONICALIZED_HEADERS 同上，恒为空串
//! ```
//! 第二、九段的两处易错点：路径要有前导 `/` 且**不以 `/` 结尾**；末两段是
//! 空串，因此拼接结果在 nonce 之后以两个 `\n` 结尾 —— 这里用数组 join 而不是
//! 手写 format，正是为了让段数与分隔符数量不可能被写错。
//!
//! ── Content-MD5 必须覆盖**实际发出去的字节**──────────────────
//! 签名与出网层（`client::signed_post`）都走 `Value::to_string()`（紧凑序列化），
//! 两处必须保持同一序列化口径 —— 换任何一方都会让 MD5 对不上，上游报签名错误，
//! 而错误信息不会指出是哪个环节。
//!
//! ── HMAC-SHA1 不是安全边界 ──────────────────────────────────
//! 这是客户端指纹复刻（密钥随安装包分发），目标是与官方客户端行为一致，
//! 不是密码学意义上的完整性保证。

use agent2api_wasm_sdk::{self as sdk, Value};

use super::crypto;
use super::endpoints;
use super::ids;

/// 业务接口的 Content-Type（也是待签串第 5 段的取值）
const CONTENT_TYPE: &str = "application/json";

/// RFC3986 转义一个路径段。
///
/// 保留字符集：`A-Z a-z 0-9 - _ . ~`；其余一律 `%XX`（大写十六进制）。
/// 当前所有账号接口路径都只含字母与 `/`，转义结果与原串相同。
fn escape_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 构建 ESCAPED_PATH：逐段转义、以 `/` 连接；去掉尾部斜杠（客户端同款）。
fn build_escaped_path(path: &str) -> String {
    let mut clean = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if clean.len() > 1 && clean.ends_with('/') {
        clean.pop();
    }
    clean
        .split('/')
        .map(escape_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// UTC 时间字符串（对应 JS `new Date().toUTCString()`）：
/// `Sun, 06 Oct 2026 12:34:56 GMT`
///
/// ── 为什么不用 `Utc::now()` ──────────────────────────────────
/// `chrono::Utc::now()` 在 `wasm32-unknown-unknown` 上没有系统时钟可用，
/// 调用会 panic（而本 crate 是 `panic = "abort"`）。时间只能向主程序要，
/// 已有的毫秒戳再交给 chrono 格式化。
fn utc_date_string() -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(sdk::now())
        .single()
        .map(|time| time.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

/// base64(md5(字节串))；空串输入返回空串（对应客户端 `contentMD5('')`）
fn content_md5(body_string: &str) -> String {
    if body_string.is_empty() {
        return String::new();
    }
    crypto::base64_encode(&crypto::md5(body_string.as_bytes()))
}

/// 生成一次请求的签名头集合：`Authorization` / `Date` / `Nonce` / `Content-MD5`。
///
/// `body` 为 `None` 时按空 body 处理（MD5 段为空串）。序列化口径必须与出网层
/// 完全一致（`Value::to_string()`，见模块头）。
pub fn signed_headers(method: &str, path: &str, body: Option<&Value>) -> Vec<(String, String)> {
    let body_string = match body {
        Some(value) => value.to_string(),
        None => String::new(),
    };
    let md5 = content_md5(&body_string);
    let date = utc_date_string();
    let nonce = ids::uuid_v4();
    // 9 段，`\n` 连接（末两段恒为空串，见模块头）
    let string_to_sign = [
        method.to_uppercase(),
        build_escaped_path(path),
        String::new(),
        md5.clone(),
        CONTENT_TYPE.to_string(),
        date.clone(),
        nonce.clone(),
        String::new(),
        String::new(),
    ]
    .join("\n");

    let signature = crypto::hmac_sha1(
        endpoints::access_key_secret().as_bytes(),
        string_to_sign.as_bytes(),
    );

    let mut headers = vec![
        (
            "Authorization".to_string(),
            format!(
                "account {}:{}",
                endpoints::access_key_id(),
                crypto::base64_encode(&signature)
            ),
        ),
        ("Date".to_string(), date),
        ("Nonce".to_string(), nonce),
        ("Content-Type".to_string(), CONTENT_TYPE.to_string()),
    ];
    if !md5.is_empty() {
        headers.push(("Content-MD5".to_string(), md5));
    }
    headers
}

/// 把 `[(名称, 值)]` 转成 SDK 要的请求头对象。
pub fn header_object(headers: &[(String, String)]) -> Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(object)
}
