//! 华为云 **SDK-HMAC-SHA256** 请求签名（CodeArts Agent 上游那套 AK/SK/STS 签名）。
//!
//! ── 算法 ────────────────────────────────────────────────────
//! ```text
//! canonicalRequest = method \n canonicalURI \n canonicalQuery \n
//!                    canonicalHeaders \n signedHeaders \n payloadHash
//! stringToSign     = "SDK-HMAC-SHA256" \n X-Sdk-Date \n sha256hex(canonicalRequest)
//! signature        = hmacSHA256hex(secretKey, stringToSign)
//! Authorization    = SDK-HMAC-SHA256 Access=<AK>, SignedHeaders=<…>, Signature=<…>
//! ```
//!
//! ── 为什么这里有一整套 URL 解析，而不是直接用字符串切 ────────
//! 签名要对**字节**负责，而参考实现（`cpa-codearts-plugin` v0.1.18 `signer.go`）
//! 走的是 Go `net/url`：路径先按 `%` 解码、再由 `canonicalURI` 重编码（于是
//! `%2F` 会变成真分隔符），query 先按 `ParseQuery` 解码（于是 `+` 是空格、坏
//! `%` 让那一对键值整个丢掉）再重编码。照别的口径算出来的规范请求串与上游对不
//! 上就是 401，而且错得毫无提示。所以这里按 Go 的语义自己实现。
//!
//! ── 三条容易写错的细节 ───────────────────────────────────────
//!   1. `canonicalURI` **强制补尾斜杠**：`/api/v2/chat/completions` 签的是
//!      `/api/v2/chat/completions/`。少这个斜杠上游直接 401。
//!   2. 未保留字符集是 **JS `encodeURIComponent` 的那一组**，不是 RFC 3986 的
//!      `A-Za-z0-9-_.~`：`-_.!~*'()` 全留，**包括 `!'()` 这三个**。
//!   3. 参与签名的头集合 = 发出去的**全部**头（`X-Sdk-Date` / `X-Security-Token`
//!      / `X-Domain-Id` / 可选 `Host` 都在内），而 `Authorization` 本身不参与。
//!
//! ── 为什么 HMAC 是自己写的 ──────────────────────────────────
//! 本插件的依赖清单被钉死在 `agent2api-wasm-sdk` / `serde_json` / `sha2` /
//! `chrono` 四样，没有 `hmac` crate。HMAC-SHA256 是 RFC 2104 的 20 行固定流程
//! （ipad/opad + 两次 SHA-256），自己实现比为一个函数拉一个依赖更省事，且同样
//! 只用到 `sha2`。

use sha2::{Digest, Sha256};

const SIGNING_ALGORITHM: &str = "SDK-HMAC-SHA256";
const HEADER_XSDK_DATE: &str = "X-Sdk-Date";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_CONTENT_SHA256: &str = "X-Sdk-Content-Sha256";
const HEADER_SECURITY_TOKEN: &str = "X-Security-Token";
const HEADER_DOMAIN_ID: &str = "X-Domain-Id";
/// `sha256("")`，无体请求固定签这个
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// SHA-256 的分组长度（HMAC 的 block size）
const HMAC_BLOCK: usize = 64;

/// 已解析出的上游凭据：一次登录换来的临时 AK/SK + STS + 域号。
///
/// `security_token` / `domain_id` 为空时**完全不进**头集合（不是进一个空值），
/// 否则签名头集合与上游收到的不一致。
#[derive(Clone, Default)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: String,
    pub domain_id: String,
}

impl Credential {
    /// AK 与 SK 缺一即不可签（与参考实现的 `credential.valid()` 同口径）
    fn valid(&self) -> bool {
        !self.access_key_id.is_empty() && !self.secret_access_key.is_empty()
    }
}

/// RFC 2104 的 HMAC-SHA256：key 超长先哈希，再 `H(K^opad || H(K^ipad || m))`。
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        let hashed = Sha256::digest(key);
        block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut pad = [0u8; HMAC_BLOCK];
    for (slot, byte) in pad.iter_mut().zip(block.iter()) {
        *slot = byte ^ 0x36;
    }
    inner.update(pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    for (slot, byte) in pad.iter_mut().zip(block.iter()) {
        *slot = byte ^ 0x5c;
    }
    outer.update(pad);
    outer.update(inner);
    let finished = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&finished);
    output
}

/// 按 Go 的 `unhex` 把一个 hex 字符折成数值，非 hex 返回 None。
fn unhex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Go `net/url.unescape` 的 query 分量语义：`+` 当空格，`%XX` 解一个字节，
/// 转义坏了返回 None（调用方**丢弃这一对键值**而不是整条请求报错）。
fn query_unescape(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = unhex(bytes[index + 1])?;
                let low = unhex(bytes[index + 2])?;
                out.push(high << 4 | low);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    Some(out)
}

/// Go `net/url.unescape(…, encodePath)` 的语义：与 query 一样按 `%XX` 解字节，
/// 但 **`+` 是字面量**（不折成空格）。解出来的字节按原样保留，不做 UTF-8 校验。
fn path_unescape(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = unhex(bytes[index + 1])?;
                let low = unhex(bytes[index + 2])?;
                out.push(high << 4 | low);
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    Some(out)
}

/// JS `encodeURIComponent` 的未保留集（= 参考实现 `signer.go` 的 `unreserved`）：
/// 字母数字加上 `- _ . ! ~ * ' ( )`，其余按**字节**百分号编码、大写十六进制。
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')')
}

/// JS `encodeURIComponent` 的百分号编码。**签名与授权页地址共用这一份**：
/// 两处对「哪些字符不转义」的口径必须一致，否则登录 URL 与签名串会各说一套。
pub fn encode_component(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if unreserved(*byte) {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// 拆出 `scheme://authority` 之后的 path 与 raw query。
///
/// `authority` 供 `include_host` 注入 `Host` 头用；`path` 是**已解码**的字节串
/// （Go 的 `URL.Path`），`raw_query` 保持原样交给 [`query_pairs`]。
/// 路径里的坏转义在这里就报错（对应 `url.Parse` 失败），query 里的坏转义不报错。
struct ParsedUrl {
    authority: String,
    path: Vec<u8>,
    raw_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (_, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("上游地址缺少 scheme：{url}"))?;
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("上游地址缺少主机名：{url}"));
    }
    // 片段（fragment）不参与签名：Go 把它单独放在 URL.Fragment 里
    let (before_fragment, _) = tail.split_once('#').unwrap_or((tail, ""));
    let (raw_path, raw_query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, query),
        None => (before_fragment, ""),
    };
    Ok(ParsedUrl {
        authority: authority.to_string(),
        path: path_unescape(raw_path).ok_or_else(|| format!("上游地址路径转义非法：{raw_path}"))?,
        raw_query: raw_query.to_string(),
    })
}

/// `canonicalURI`：逐段按未保留集重编码，并**保证以 `/` 结尾**。
///
/// 空路径给 `/`。先按 `/` 切再逐段编码，所以解码进来的 `%2F`（一个真斜杠字节）
/// 在这里会被当成段边界 —— 与参考实现一致，不是 bug。
fn canonical_uri(path: &[u8]) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut segments = Vec::new();
    for segment in path.split(|byte| *byte == b'/') {
        segments.push(encode_component(segment));
    }
    let mut escaped = segments.join("/");
    if !escaped.ends_with('/') {
        escaped.push('/');
    }
    escaped
}

/// Go `net/url.ParseQuery` 的**逐对**语义：
///   · 按 `&` 切分；含 `;` 的那一对直接丢弃；
///   · 空串丢弃；
///   · 第一个 `=` 分键值，没有 `=` 则值为空（键可以空，`?=v` 会留下 `=v`）；
///   · 键或值解不开就丢掉这一对，继续处理后面的。
fn query_pairs(raw: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut pairs = Vec::new();
    for part in raw.split('&') {
        if part.is_empty() || part.contains(';') {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            Some((key, value)) => (key, value),
            None => (part, ""),
        };
        let Some(key) = query_unescape(key) else { continue };
        let Some(value) = query_unescape(value) else { continue };
        pairs.push((key, value));
    }
    pairs
}

/// `canonicalQueryString`：按键排序，同键的多值再按值排序，键与值都用未保留集编码。
fn canonical_query_string(raw: &str) -> String {
    let mut pairs = query_pairs(raw);
    if pairs.is_empty() {
        return String::new();
    }
    // Go 那边是 map[string][]string：同键的多个值被**合并**后排序。
    // 先把同键聚到一起，再整体按 (键, 值) 排 —— 与「键排序 + 组内值排序」等价；
    // 比较用的是**原始字节**（不是编码后的文本），与 native 实现逐字一致。
    pairs.sort_by(|a, b| {
        let key_a = encode_component(&a.0);
        let key_b = encode_component(&b.0);
        (&key_a, &a.1).cmp(&(&key_b, &b.1))
    });
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// 只有 PUT / PATCH / POST 被视为「带体」，其余恒签空体摘要。
fn request_carries_body(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "PUT" | "PATCH" | "POST")
}

/// 头集合：按插入顺序保名值，**同名（大小写无关）覆盖前值、位置不变**。
///
/// 参考实现用的是 Go 的 `map[string]string`，同名大小写并存时「谁最后进规范串」
/// 取决于随机的 map 迭代顺序 —— 那是参考实现自己的不确定性，不是要复刻的行为。
/// 这里取确定的一条规则：先到先得位置、后到覆盖值。
#[derive(Default)]
struct Headers {
    items: Vec<(String, String)>,
}

impl Headers {
    fn from_slice(input: &[(String, String)]) -> Self {
        let mut headers = Self::default();
        for (name, value) in input {
            headers.set(name, value);
        }
        headers
    }

    fn set(&mut self, name: &str, value: &str) {
        let lower = name.to_ascii_lowercase();
        for (existing, slot) in self.items.iter_mut() {
            if existing.to_ascii_lowercase() == lower {
                *slot = value.to_string();
                return;
            }
        }
        self.items.push((name.to_string(), value.to_string()));
    }

    fn contains_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.items.iter().any(|(existing, _)| existing.to_ascii_lowercase() == lower)
    }

    fn value_of(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.items
            .iter()
            .find(|(existing, _)| existing.to_ascii_lowercase() == lower)
            .map(|(_, value)| value.as_str())
    }
}

/// 给请求签名，返回**应当发出去**的头集合（入参头 + 注入项 + `Authorization`）。
///
/// * `headers` 是调用方已经要发的头（不含 `Authorization`）
/// * `body` 参与 `payloadHash`；用 `X-Sdk-Content-Sha256` 可以显式覆盖它
/// * `include_host` 决定是否把 `Host` 也纳入签名 —— 参考实现只对某些上游开
///   （福利网关要、snap-access 不要），别统一开
/// * 没给 `X-Sdk-Date` 时按当前 UTC 注入 `yyyyMMddTHHmmssZ`
pub fn sign(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    credential: &Credential,
    include_host: bool,
) -> Result<Vec<(String, String)>, String> {
    if !credential.valid() {
        return Err("凭据不完整：access key 与 secret key 都得有".to_string());
    }
    let parsed = parse_url(url)?;
    let mut out = Headers::from_slice(headers);
    if !credential.security_token.is_empty() {
        out.set(HEADER_SECURITY_TOKEN, &credential.security_token);
    }
    if !credential.domain_id.is_empty() {
        out.set(HEADER_DOMAIN_ID, &credential.domain_id);
    }
    if !out.contains_name(HEADER_XSDK_DATE) {
        out.set(HEADER_XSDK_DATE, &sdk_date_now());
    }
    if include_host && !out.contains_name("host") {
        out.set("Host", &parsed.authority);
    }
    let date = out.value_of(HEADER_XSDK_DATE).unwrap_or_default().to_string();

    // 规范头视图：名字转小写、值去空白、按名字排序
    let mut canonical: Vec<(String, String)> = out
        .items
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers = canonical
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let signed_headers = canonical
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let mut payload_hash = sha256_hex(body);
    let override_hash = canonical
        .iter()
        .find(|(name, _)| name == &HEADER_CONTENT_SHA256.to_ascii_lowercase())
        .map(|(_, value)| value.clone())
        .filter(|value| !value.is_empty());
    if let Some(value) = override_hash {
        payload_hash = value;
    } else if !request_carries_body(method) {
        payload_hash = EMPTY_BODY_SHA256.to_string();
    }

    let canonical_request = [
        method,
        &canonical_uri(&parsed.path),
        &canonical_query_string(&parsed.raw_query),
        &canonical_headers,
        &signed_headers,
        &payload_hash,
    ]
    .join("\n");
    let string_to_sign = [SIGNING_ALGORITHM, &date, &sha256_hex(canonical_request.as_bytes())].join("\n");
    // `[u8; 32]` 没有 LowerHex 实现，自己逐字节拼十六进制
    let digest = hmac_sha256(credential.secret_access_key.as_bytes(), string_to_sign.as_bytes());
    let signature: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    out.set(
        HEADER_AUTHORIZATION,
        &format!(
            "{SIGNING_ALGORITHM} Access={}, SignedHeaders={signed_headers}, Signature={signature}",
            credential.access_key_id
        ),
    );
    Ok(out.items)
}

/// `X-Sdk-Date` 的格式：UTC 的 `yyyyMMddTHHmmssZ`（Go 版式 `20060102T150405Z`）。
///
/// 用宿主时钟而非进程时钟：wasm 里没有系统时间，`sdk::now()` 是唯一可信来源；
/// 取不到（返回 0）时退回编译期之外的固定串会让签名必然过期，所以这里显式报
/// 一个可读错误，由调用方转成 500。
fn sdk_date_now() -> String {
    let now = agent2api_wasm_sdk::now();
    if now <= 0 {
        // 宿主时钟不可用时给一个空串：上游会以 401 拒绝，比签一个错时间更容易定位
        return String::new();
    }
    match chrono::DateTime::from_timestamp_millis(now) {
        Some(time) => time.format("%Y%m%dT%H%M%SZ").to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// RFC 4231 的第二个测试向量：独立来源，能证明「自己写的 HMAC」而不是
    /// 只证明「和另一段自己写的代码互相一致」。
    #[test]
    fn hmac_matches_rfc4231_case2() {
        assert_eq!(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "HMAC-SHA256 必须与 RFC 4231 向量逐字节一致"
        );
    }

    /// 超长密钥要先哈希到 32 字节再当 block key（RFC 2104）。
    #[test]
    fn hmac_hashes_an_oversized_key_first() {
        let key = vec![0xaa_u8; 131];
        let expected = {
            let hashed = Sha256::digest(&key);
            hmac_sha256(&hashed, b"Test Using Larger Than Block-Size Key - Hash Key First")
        };
        assert_eq!(
            hex(&expected),
            hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ))
        );
    }

    /// `canonicalURI` 必须补尾斜杠：少这个斜杠上游直接 401。
    #[test]
    fn canonical_uri_forces_a_trailing_slash() {
        assert_eq!("/api/v2/chat/completions/", canonical_uri(b"/api/v2/chat/completions"));
        assert_eq!("/", canonical_uri(b""));
        assert_eq!("/a/b/", canonical_uri(b"/a/b/"));
    }

    /// 未保留集是 JS `encodeURIComponent` 那一组：`!'()*` 都不转义，
    /// 空格与 `/` 要转义。
    #[test]
    fn unreserved_set_matches_encode_uri_component() {
        assert_eq!("a-b_c.d!e~f*g'h(i)j", encode_component(b"a-b_c.d!e~f*g'h(i)j"));
        assert_eq!("%20", encode_component(b" "));
        assert_eq!("%2F", encode_component(b"/"));
        assert_eq!("%2B", encode_component(b"+"));
    }

    /// 解码进来的 `%2F` 会被当成段边界 —— 与参考实现一致（不是 bug）。
    #[test]
    fn percent_encoded_slash_becomes_a_segment_boundary() {
        let parsed = match parse_url("https://h/api%2Fv2?b=2&a=1") {
            Ok(parsed) => parsed,
            Err(_) => panic!("地址应当能解析"),
        };
        assert_eq!("/api/v2/", canonical_uri(&parsed.path));
        assert_eq!("a=1&b=2", canonical_query_string(&parsed.raw_query), "按键排序");
    }

    /// query 里的 `+` 是空格、坏转义丢这一对 —— Go `ParseQuery` 的语义。
    #[test]
    fn query_uses_go_parse_query_semantics() {
        assert_eq!(
            "a=%20b",
            canonical_query_string("a=%20b"),
            "解码成空格后按未保留集重编码（空格 → %20，不是 +）"
        );
        assert_eq!(
            "a=b%20c",
            canonical_query_string("a=b+c"),
            "`+` 先折成空格，再编码回 %20"
        );
        assert_eq!("a=1", canonical_query_string("a=1&bad=%ZZ"), "坏转义的那一对整个丢掉");
        assert_eq!("", canonical_query_string("x;y=1"), "含分号的那一对丢弃");
    }
}
