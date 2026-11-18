//! OfficeAce（华为云果办 / OfficeClaw）的两套请求签名：**SDK-HMAC-SHA256** 与
//! **V11-HMAC-SHA256**。
//!
//! ── 为什么单独一份，不复用 `wasm/codearts/src/signer.rs` ─────
//! 两家同属华为云、算法同名，但**规范化规则有三处实测差异**（依据是 native
//! `officeace/signer.rs` 的模块头：那份由 `officeace2api` 的真实 `signV4`/`signV11`
//! 产出对拍过）。照抄 codearts 那份会在这三处算错、且上游只回 401：
//!
//!   1. **未保留集更严**：codearts（Go 侧 `unreserved`）把 `! ' ( ) *` 留在字面量里，
//!      而 OfficeAce 的 JS 签名器先 `encodeURIComponent`、再把这五个字符也转义
//!      （`quota.mjs` 的 `rfc3986`）。路径或查询里出现它们时两边签名不同。
//!   2. **查询串按 WHATWG 口径**：JS 走 `URL.searchParams`（键值先解码再重新编码、
//!      `+` 折成空格、按 `(键, 值)` 排序），不是 codearts 那份 Go `ParseQuery` 的
//!      「坏 `%` 丢一对」语义。
//!   3. **V11 的派生密钥按「小写十六进制字符串」参与 HMAC**，不是 32 字节原始 key。
//!      这一步两份 OfficeAce 实现（`officeace2api` 与 `opencode-officeace-auth`）
//!      写法一致，属于在这条链上必须复刻的既成事实。
//!
//! ── 为什么 HMAC 是自己写的 ──────────────────────────────────
//! 本插件的依赖清单被钉死在 `agent2api-wasm-sdk` / `serde_json` / `sha2` /
//! `chrono` 四样，没有 `hmac` crate。HMAC-SHA256 是 RFC 2104 的 20 行固定流程
//! （ipad/opad + 两次 SHA-256），自己实现比为一个函数拉一个依赖更省事，且同样
//! 只用到 `sha2`。`wasm/codearts/src/signer.rs` 已有同一份，测试向量也一样
//! （RFC 4231 第二例）—— 也就是说两条独立的实现互相印证。
//!
//! ── 算法 ────────────────────────────────────────────────────
//! ```text
//! canonicalRequest = METHOD \n canonicalURI \n canonicalQuery \n
//!                    canonicalHeaders \n signedHeaders \n payloadHash
//! SDK:  stringToSign = "SDK-HMAC-SHA256" \n X-Sdk-Date \n sha256hex(canonicalRequest)
//!       signature    = hmacSha256hex(secretKey, stringToSign)
//! V11:  scope        = <YYYYMMDD>/<region>/apic
//!       signingKey   = hmacSha256(hmacSha256(AK, SK), scope ++ 0x01)[..32] 的 **hex 串**
//!       stringToSign = "V11-HMAC-SHA256" \n X-Sdk-Date \n scope \n sha256hex(canonicalRequest)
//!       signature    = hmacSha256hex(signingKey_hex_string, stringToSign)
//! ```

use sha2::{Digest, Sha256};

const SDK_ALGORITHM: &str = "SDK-HMAC-SHA256";
const V11_ALGORITHM: &str = "V11-HMAC-SHA256";
/// APIG 的固定服务名（V11 的 CredentialScope 第三段）。
const SCOPE_SERVICE: &str = "apic";
const HEADER_XSDK_DATE: &str = "X-Sdk-Date";
const HEADER_SECURITY_TOKEN: &str = "X-Security-Token";
const HEADER_PROJECT_ID: &str = "X-Project-ID";
const HEADER_AUTHORIZATION: &str = "Authorization";

/// `sha256("")`，无体请求固定签这个。
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// SHA-256 的分组长度（HMAC 的 block size）。
const HMAC_BLOCK: usize = 64;

/// 网关（模型面）与控制面共用的默认区域（两边同为 cn-southwest-2）。
pub const DEFAULT_REGION: &str = "cn-southwest-2";

/// 一次登录/导入换来的凭据：临时 AK/SK/STS + 项目号。
///
/// `security_token` / `project_id` 为空时**完全不进**头集合（不是进空值），
/// 否则签名的头集合与上游收到的不一致。
#[derive(Clone, Debug, Default)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub security_token: String,
    pub project_id: String,
}

impl Credential {
    fn valid(&self) -> bool {
        !self.access_key_id.is_empty() && !self.secret_access_key.is_empty()
    }
}

/// 签名算法选择。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// 标准华为云签名（AK 直接做密钥）：控制面的 `/v1/claw/*`、IAM `/v3/projects` 用它。
    Sdk,
    /// APIG 区域作用域签名：额度 / 签到那几个 `/v1/subscription*` 用它。
    V11,
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
    let mut pad = [0u8; HMAC_BLOCK];
    let mut inner = Sha256::new();
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

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// OfficeAce 的未保留集：字母数字 + `- _ . ~`。
///
/// 与 codearts 那份的差别就在**这里**：`! ' ( ) *` 不再留在字面量
/// （它们会被转义成 `%21 %27 %28 %29 %2A`）。
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// `encodeURIComponent` + 「把 `!'()*` 也转义」的百分号编码（`quota.mjs` 的 `rfc3986`）。
fn encode_component(bytes: &[u8]) -> String {
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

/// 把一个十六进制字符折成数值。
fn unhex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// JS `decodeURIComponent` 的近似：按 `%XX` 解字节；`+` 保持字面量；坏转义原样留。
///
/// 与 codearts 那份的差别：这里**不丢**坏转义的那一对。native 的 JS 侧走
/// `URL.pathname`（拿到的已经是合法转义），所以这条分支只是防御 —— 保持
/// 「能解多少解多少」比「整对丢掉」更接近 JS 的行为（`decodeURIComponent` 抛异常，
/// 而 catch 之后仍然会拿原串继续）。
fn decode_component(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (unhex(bytes[index + 1]), unhex(bytes[index + 2])) {
                out.push(high << 4 | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// 路径按段解码再编码，末尾**强制补斜杠**。
fn canonical_uri(path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let escaped = path
        .split('/')
        .map(|segment| encode_component(&decode_component(segment)))
        .collect::<Vec<_>>()
        .join("/");
    if escaped.ends_with('/') {
        escaped
    } else {
        format!("{escaped}/")
    }
}

/// 表单分量的解码：`+` 折成空格，`%XX` 解字节（JS `URLSearchParams` 的语义）。
fn decode_form(input: &str) -> String {
    let bytes = decode_component(&input.replace('+', " "));
    String::from_utf8_lossy(&bytes).to_string()
}

/// 查询串按 WHATWG 口径：键值先按 `+`→空格、`%XX` 解码，再重新编码，按 `(键, 值)` 排序。
fn canonical_query(raw_query: &str) -> String {
    if raw_query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = match part.split_once('=') {
                Some((key, value)) => (key, value),
                None => (part, ""),
            };
            (decode_form(key), decode_form(value))
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                encode_component(key.as_bytes()),
                encode_component(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// 拆出 `scheme://host[:port]` 之后的 path 与 query（`#fragment` 丢掉，与 `new URL` 一致）。
fn split_path_query(url: &str) -> Result<(String, String), String> {
    let after_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| format!("地址缺少 scheme：{url}"))?;
    let without_fragment = after_scheme.split('#').next().unwrap_or(after_scheme);
    let path_query = match without_fragment.find('/') {
        Some(index) => &without_fragment[index..],
        None => "/",
    };
    let (path, query) = match path_query.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path_query, ""),
    };
    Ok((path.to_string(), query.to_string()))
}

/// `scheme://host[:port]`（`Host` 头要的值，不含 userinfo）。
fn authority_of(url: &str) -> Result<String, String> {
    let after_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| format!("地址缺少 scheme：{url}"))?;
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..host_end];
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    Ok(authority.to_string())
}

/// 头集合：大小写不敏感地设置（后到覆盖前值、位置不变），与 JS 的 `setHeader` 同口径。
#[derive(Default, Clone)]
struct Headers {
    items: Vec<(String, String)>,
}

impl Headers {
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

    fn contains(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.items
            .iter()
            .any(|(existing, _)| existing.to_ascii_lowercase() == lower)
    }
}

/// `X-Sdk-Date`：UTC 的 `yyyyMMddTHHmmssZ`。
///
/// 用宿主时钟而非进程时钟：wasm 里没有系统时间，`sdk::now()` 是唯一可信来源。
/// 取不到就直接报错 —— 签一个过期时间会以 401 失败，而 401 会把排查往「凭据过期」
/// 的方向带，与真实原因（宿主时钟不可用）差得很远。
fn sdk_date_now() -> Result<String, String> {
    let now = agent2api_wasm_sdk::now();
    if now <= 0 {
        return Err("宿主时钟不可用，无法生成请求签名".to_string());
    }
    chrono::DateTime::from_timestamp_millis(now)
        .map(|time| time.format("%Y%m%dT%H%M%SZ").to_string())
        .ok_or_else(|| "宿主时钟给出的时间戳越界，无法生成请求签名".to_string())
}

/// 签名所需的一切。
pub struct SignRequest<'a> {
    pub algorithm: Algorithm,
    pub method: &'a str,
    pub url: &'a str,
    /// 调用方已经要发的头（不含 `Authorization`）
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub credential: &'a Credential,
    pub region: &'a str,
}

/// 给请求签名，返回**应当发出去**的头集合（入参头 + 注入项 + `Authorization`）。
///
/// native 那份还有 `date_override`（测试对拍用）与 `Material`（把
/// `canonical_request` / `string_to_sign` / `signature` 都返回出来）。前者只在
/// native 的 `#[cfg(test)]` 里有调用方，后者在插件里**没有读取方** —— 两份都不搬，
/// 但算法一字未改，需要逐字段对账时按本文件的函数顺序重推即可。
///
/// 另有一处刻意的差异：native 在头集合已含 `User-Agent` 时用 `agent2api` 的 UA
/// 覆盖它。本家的控制面请求**本来就不带** `User-Agent`（`upstream::call` 的
/// `extra_headers` 恒为空），而 wasm 侧的出口 UA 由宿主决定、插件不可见 —— 所以
/// 那条分支在这里是空操作，不搬。
pub fn sign(request: &SignRequest<'_>) -> Result<Vec<(String, String)>, String> {
    if !request.credential.valid() {
        return Err("凭据不完整：access key 与 secret key 都得有".to_string());
    }
    let (path, raw_query) = split_path_query(request.url)?;
    let mut out = Headers::default();
    for (name, value) in request.headers {
        out.set(name, value);
    }
    if !request.credential.security_token.is_empty() {
        out.set(HEADER_SECURITY_TOKEN, &request.credential.security_token);
    }
    if !request.credential.project_id.is_empty() {
        out.set(HEADER_PROJECT_ID, &request.credential.project_id);
    }
    if !out.contains(HEADER_XSDK_DATE) {
        out.set(HEADER_XSDK_DATE, &sdk_date_now()?);
    }
    if !out.contains("host") {
        out.set("Host", &authority_of(request.url)?);
    }
    let date = out
        .items
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(HEADER_XSDK_DATE))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    // 规范头：名字转小写、值把内部连续空白折成一个空格（`normalizeHeaders` 的
    // `replace(/\s+/g, ' ')`，不是只 trim），按名字排序
    let mut canonical: Vec<(String, String)> = out
        .items
        .iter()
        .map(|(name, value)| {
            (
                name.to_ascii_lowercase(),
                value.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String = canonical
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = canonical
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let payload_hash = if request.body.is_empty() {
        EMPTY_BODY_SHA256.to_string()
    } else {
        sha256_hex(request.body)
    };

    let canonical_request = [
        request.method.to_ascii_uppercase(),
        canonical_uri(&path),
        canonical_query(&raw_query),
        canonical_headers,
        signed_headers.clone(),
        payload_hash,
    ]
    .join("\n");

    let authorization = match request.algorithm {
        Algorithm::Sdk => {
            let string_to_sign = [
                SDK_ALGORITHM,
                &date,
                &sha256_hex(canonical_request.as_bytes()),
            ]
            .join("\n");
            let signature = crate::util::hex_lower(&hmac_sha256(
                request.credential.secret_access_key.as_bytes(),
                string_to_sign.as_bytes(),
            ));
            format!(
                "{SDK_ALGORITHM} Access={}, SignedHeaders={signed_headers}, Signature={signature}",
                request.credential.access_key_id
            )
        }
        Algorithm::V11 => {
            let scope = format!(
                "{}/{}/{}",
                &date[..date.len().min(8)],
                request.region,
                SCOPE_SERVICE
            );
            let string_to_sign = [
                V11_ALGORITHM,
                &date,
                &scope,
                &sha256_hex(canonical_request.as_bytes()),
            ]
            .join("\n");
            let step1 = hmac_sha256(
                request.credential.access_key_id.as_bytes(),
                request.credential.secret_access_key.as_bytes(),
            );
            let mut seed = scope.clone().into_bytes();
            seed.push(1);
            let derived = &hmac_sha256(&step1, &seed)[..32];
            let signing_key_hex = crate::util::hex_lower(derived);
            // ⚠️ 按**十六进制字符串**当密钥（不是那 32 个字节）—— 见文件头第 3 条
            let signature = crate::util::hex_lower(&hmac_sha256(
                signing_key_hex.as_bytes(),
                string_to_sign.as_bytes(),
            ));
            format!(
                "{V11_ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                request.credential.access_key_id
            )
        }
    };

    out.set(HEADER_AUTHORIZATION, &authorization);
    Ok(out.items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::util::hex_lower(bytes)
    }

    /// RFC 4231 第二例：独立来源，能证明「自己写的 HMAC」而不是只证明
    /// 「和另一段自己写的代码互相一致」。
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
        let message = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hmac_sha256(&Sha256::digest(&key), message);
        assert_eq!(hex(&expected), hex(&hmac_sha256(&key, message)));
    }

    /// 未保留集：`!'()*` 要转义（与 codearts 那份相反）。
    #[test]
    fn unreserved_set_escapes_bang_quotes_parens_star() {
        assert_eq!("a-b_c.d~e", encode_component(b"a-b_c.d~e"));
        assert_eq!("%21%27%28%29%2A", encode_component(b"!'()*"));
        assert_eq!("%20", encode_component(b" "));
        assert_eq!("%2F", encode_component(b"/"));
    }

    /// `canonicalURI` 强制补尾斜杠：少这个斜杠上游直接 401。
    #[test]
    fn canonical_uri_forces_a_trailing_slash() {
        assert_eq!("/v1/subscription/", canonical_uri("/v1/subscription"));
        assert_eq!("/", canonical_uri(""));
        assert_eq!("/a/b/", canonical_uri("/a/b/"));
        // 段内的 `%2F` 解码成真斜杠字节，逐段编码时不会再变回 `%2F` 之外的形态
        assert_eq!("/a%2Fb/", canonical_uri("/a%2Fb"));
    }

    /// 查询串：`+` 折空格、按 (键, 值) 排序、坏转义按字面量再编码（WHATWG 口径）。
    #[test]
    fn canonical_query_follows_whatwg() {
        assert_eq!("a=1&b=2", canonical_query("b=2&a=1"), "按键排序");
        assert_eq!("a=b%20c", canonical_query("a=b+c"), "`+` 先折成空格再编码成 %20");
        assert_eq!("a=x%25y", canonical_query("a=x%25y"), "%25 解成 % 再编码回 %25");
        assert_eq!(
            "bad=%25ZZ",
            canonical_query("bad=%ZZ"),
            "坏转义解不开就保留原字符，重编码时 `%` 变成 `%25`（与 URLSearchParams 同口径）"
        );
        assert_eq!("a=1&a=2", canonical_query("a=2&a=1"), "同键按值排序");
    }

    #[test]
    fn split_path_and_query_drops_fragment() {
        let (path, query) = split_path_query("https://h/v1/subscription?x=1#frag").unwrap_or_default();
        assert_eq!(path, "/v1/subscription");
        assert_eq!(query, "x=1");
        let (path, query) = split_path_query("https://h").unwrap_or_default();
        assert_eq!(path, "/");
        assert_eq!(query, "");
    }

    #[test]
    fn authority_ignores_userinfo() {
        assert_eq!(authority_of("https://u:p@h:8443/x").unwrap_or_default(), "h:8443");
        assert_eq!(authority_of("https://iam.myhuaweicloud.com/v3").unwrap_or_default(), "iam.myhuaweicloud.com");
        assert_eq!(authority_of("没有 scheme").is_err(), true);
    }
}
