//! Qoder COSY 请求签名与请求体编码（native `cosy.rs` 的逐条移植）。
//!
//! ── 为什么不能只发 Bearer ───────────────────────────────────
//! Qoder 的推理网关（`/algo/...` 这一族）不认普通 Bearer 令牌，而是一套
//! **自签名**鉴权：
//!
//!   1. 组装用户身份 JSON（uid / security_oauth_token / name / email）；
//!   2. 生成一把一次性 AES 密钥，用它把身份 JSON 加密成 `info`；
//!   3. 用内置 RSA 公钥把该 AES 密钥加密成 `key`（服务端用私钥解开）；
//!   4. 把 {version, requestId, info, cosyVersion, ideVersion} 序列化后 base64，
//!      得到 `payload`；
//!   5. 对 `payload \n key \n 时间戳 \n 请求体 \n 签名路径` 求 MD5，得到签名；
//!   6. 拼成 `Authorization: Bearer COSY.<payload>.<签名>`，并附一组 `Cosy-*` 头。
//!
//! 签名路径要**去掉 `/algo` 前缀、不含查询串** —— 服务端按同一规则校验。
//! **请求体参与签名**，所以调用顺序不能颠倒：先编码（`encode_body`）再签名。
//!
//! ── 与 native 的差别只有随机源 ─────────────────────────────
//! native 走 `getrandom`；这里走 `crypto::random_bytes`（宿主 `random.v1`
//! 优先，退到混合流）。差别与后果写在 `crypto.rs` 的模块头。

use agent2api_wasm_sdk::{Error, Result};

use super::crypto;
use super::site;

/// 登录版本标识
pub const LOGIN_VERSION: &str = "v2";

/// 网关用它区分客户端形态（COSY 头 `Cosy-Machinetype`）
const MACHINE_TYPE: &str = "5";

/// `Cosy-Clientip`：本机回环（源实现写死该值）
const CLIENT_IP: &str = "127.0.0.1";

/// COSY 身份加密用的 RSA 公钥模数（1024 位，hex，无前导零）。
///
/// 这是**客户端内置的固定公钥**（源实现 `RSA_PUBLIC_KEY` 的 PEM 正文），
/// 只用于加密一次性 AES 密钥，不是机密材料。指数固定 65537。
///
/// 公钥 PEM 与这里的模数是同一份数据的两种形态；导出方式：
/// 对 PEM 正文做 base64 解码 → DER 里 `02 81 81` 之后的 128 字节即模数，
/// 紧随其后的 `02 03 01 00 01` 即指数。
const RSA_MODULUS_HEX: &str = "c0f22307e5cd362e296bb04470f6de8fbf935ce24e8fcf511a0e2701329769c4a76e499bb938036a52af1eaf818cf79a2600620e3ce87e371d2ca6d85803606a1b3fa5e874643c9ed2db7e85673ef7227fca56e2e7c08f0927609bb896a9f24be1782099a66016a5bfdc3f1ff756bfc9e88d7b5dc5be30bf45a0223a00ebcecf";

/// RSA 公钥指数（源 PEM 里的 `02 03 01 00 01`）
const RSA_EXPONENT: u32 = 65537;

/// 自定义替换字母表（与标准 base64 字母表逐字符对应）
const CUSTOM_ALPHABET: &[u8] = b"_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
/// 标准 base64 字母表
const STD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 一次签名所需的身份素材（对应源实现 `buildAuthHeaders` 的 creds 参数）。
pub struct CosyIdentity<'a> {
    /// 账号在 Qoder 侧的 uid（源实现 `uid`）
    pub user_id: &'a str,
    /// access token（源实现 `security_oauth_token`）
    pub auth_token: &'a str,
    /// 昵称（可为空）
    pub name: &'a str,
    /// 邮箱（可为空）
    pub email: &'a str,
    /// 机器标识（COSY 头里要带，且参与「同一账号不同设备」的判定）
    pub machine_id: &'a str,
}

/// 解析十六进制串（签名公钥模数用）
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        index += 2;
    }
    Some(out)
}

/// 构造一次请求所需的全部 COSY 头。
///
/// `body` 是**已编码**的请求体（GET 类请求传 `None`）。签名覆盖它，
/// 所以调用方必须先 `encode_body` 再调本函数 —— 顺序颠倒会得到一个
/// 「签名不匹配」的上游错误，且无法从错误里看出原因。
pub fn build_auth_headers(
    body: Option<&[u8]>,
    request_url: &str,
    identity: &CosyIdentity<'_>,
) -> Result<Vec<(String, String)>> {
    if identity.user_id.is_empty() {
        return Err(Error::http(400, "Qoder 账号缺少用户标识，无法签名"));
    }
    if identity.auth_token.is_empty() {
        return Err(Error::http(401, "Qoder 账号缺少访问令牌，请重新登录"));
    }

    // 一次性 AES 密钥：16 个 ASCII 字符（源实现在 UUID 去掉连字符后取前 16 位，
    // 这里取随机串的前 16 位 —— 同一语义）
    let secret = crypto::random_secret();
    let aes_key: String = secret.chars().take(16).collect();
    if aes_key.len() < 16 {
        return Err(Error::http(500, "无法生成 Qoder 签名密钥"));
    }

    // 身份 JSON：**键顺序照抄源实现**（uid / security_oauth_token / name / aid / email）。
    //
    // ── 为什么手写而不是 `json!`（这不是洁癖，是必须）──────────────
    // 本项目的 serde_json 未开 `preserve_order`，`Value::Object` 是**按键排序**的
    // BTreeMap：`json!` 出来的键序是 aid / email / name / security_oauth_token / uid。
    // 而这段 JSON 会被 AES 加密进 `info`、再被 base64 进 payload，整条字节串参与
    // 签名。上游虽然只是解密后按 JSON 语义读取（键序无关），但「与参考实现逐字节
    // 一致」是一条能靠对拍证伪的硬保证；键序漂移会让这条保证消失，将来任何一次
    // 签名问题都只能靠猜。各字段用 `to_string` 单独转义，拼出来仍是合法 JSON
    // （值里含引号/中文时也不会拼坏）。
    let user_info = format!(
        "{{\"uid\":{},\"security_oauth_token\":{},\"name\":{},\"aid\":\"\",\"email\":{}}}",
        site::json_text(identity.user_id),
        site::json_text(identity.auth_token),
        site::json_text(identity.name),
        site::json_text(identity.email),
    );
    let info = aes128_cbc_base64(&aes_key, user_info.as_bytes())?;
    let cosy_key = rsa_encrypt_base64(&aes_key)?;

    let request_id = random_uuid();
    let timestamp = (agent2api_wasm_sdk::now() / 1000).to_string();
    let cosy_version = site::COSY_VERSION;

    // payload 同样按源实现的键序手写（理由见上）：version / requestId / info /
    // cosyVersion / ideVersion。`info` 是 base64、requestId 是 UUID、版本是常量，
    // 都不需要转义。
    let payload_src = format!(
        "{{\"version\":\"v1\",\"requestId\":\"{request_id}\",\"info\":\"{info}\",\
         \"cosyVersion\":\"{cosy_version}\",\"ideVersion\":\"\"}}"
    );
    let payload = crypto::b64(payload_src.as_bytes());

    let sig_path = signature_path(request_url)?;
    let body_bytes = body.unwrap_or(&[]);

    // MD5(payload \n key \n 时间戳 \n 请求体 \n 签名路径)
    let mut signature_input = Vec::with_capacity(payload.len() + cosy_key.len() + body_bytes.len() + 64);
    signature_input.extend_from_slice(payload.as_bytes());
    signature_input.push(b'\n');
    signature_input.extend_from_slice(cosy_key.as_bytes());
    signature_input.push(b'\n');
    signature_input.extend_from_slice(timestamp.as_bytes());
    signature_input.push(b'\n');
    signature_input.extend_from_slice(body_bytes);
    signature_input.push(b'\n');
    signature_input.extend_from_slice(sig_path.as_bytes());
    let signature = crypto::md5_hex(&signature_input);
    let body_hash = crypto::md5_hex(body_bytes);

    Ok(vec![
        ("Authorization".to_string(), format!("Bearer COSY.{payload}.{signature}")),
        ("Cosy-Key".to_string(), cosy_key),
        ("Cosy-User".to_string(), identity.user_id.to_string()),
        ("Cosy-Date".to_string(), timestamp),
        ("Cosy-Version".to_string(), cosy_version.to_string()),
        ("Cosy-Machineid".to_string(), identity.machine_id.to_string()),
        ("Cosy-Machinetoken".to_string(), identity.machine_id.to_string()),
        ("Cosy-Machinetype".to_string(), MACHINE_TYPE.to_string()),
        ("Cosy-Machineos".to_string(), site::machine_os().to_string()),
        ("Cosy-Clienttype".to_string(), site::COSY_CLIENT_TYPE.to_string()),
        ("Cosy-Clientip".to_string(), CLIENT_IP.to_string()),
        ("Cosy-Bodyhash".to_string(), body_hash),
        ("Cosy-Bodylength".to_string(), body_bytes.len().to_string()),
        ("Cosy-Sigpath".to_string(), sig_path),
        ("Cosy-Data-Policy".to_string(), site::COSY_DATA_POLICY.to_string()),
        ("Cosy-Organization-Id".to_string(), String::new()),
        ("Cosy-Organization-Tags".to_string(), String::new()),
        ("Login-Version".to_string(), LOGIN_VERSION.to_string()),
        ("X-Request-Id".to_string(), request_id),
    ])
}

/// 请求体编码（源实现 `encodeBody`）：上游带 `Encode=1` 时请求体不是裸 JSON。
///
/// 三步都是**纯字节变换**，服务端按同一规则还原：
///   1. 对 JSON 字节做标准 base64，得到一段文本；
///   2. 把该文本按「尾段 / 中段 / 首段」重排（各段长度都是 ⌊n/3⌋，
///      余数留在中段，所以三段拼回来仍是原长）；
///   3. 逐字符做一次字母表替换（含把 `=` 换成 `$`）。
///
/// 签名算在**编码之后**的字节上（见 `build_auth_headers`）。
pub fn encode_body(payload: &[u8]) -> Vec<u8> {
    let standard = crypto::b64(payload);
    let bytes = standard.as_bytes();
    let length = bytes.len();
    let third = length / 3;

    let mut table = [0u8; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        *slot = index as u8;
    }
    for (index, ch) in STD_ALPHABET.iter().enumerate() {
        table[*ch as usize] = CUSTOM_ALPHABET[index];
    }
    // base64 的填充符也要换掉
    table[b'=' as usize] = b'$';

    let mut out = Vec::with_capacity(length);
    // 尾段 → 中段 → 首段
    for index in (length - third)..length {
        out.push(table[bytes[index] as usize]);
    }
    for index in third..(length - third) {
        out.push(table[bytes[index] as usize]);
    }
    for index in 0..third {
        out.push(table[bytes[index] as usize]);
    }
    out
}

/// 参与签名的路径：去掉 `/algo` 前缀、不含查询串（源实现 `sigPathOf`）。
///
/// 这里不用 `url` crate（依赖白名单里没有），按「`://` 之后第一个 `/` 起
/// 到第一个 `?` 或 `#` 为止」手工切。
pub fn signature_path(request_url: &str) -> Result<String> {
    let after_scheme = match request_url.find("://") {
        Some(index) => &request_url[index + 3..],
        None => return Err(Error::http(500, "Qoder 请求地址无效")),
    };
    let path_start = after_scheme.find('/');
    let path = match path_start {
        Some(index) => {
            let rest = &after_scheme[index..];
            let end = rest.find(['?', '#']).unwrap_or(rest.len());
            &rest[..end]
        }
        None => "/",
    };
    Ok(path.strip_prefix("/algo").map(str::to_string).unwrap_or_else(|| path.to_string()))
}

/// AES-128-CBC + PKCS#7，返回 base64 密文。
fn aes128_cbc_base64(key16: &str, plaintext: &[u8]) -> Result<String> {
    if key16.len() != 16 {
        return Err(Error::http(500, "Qoder 签名密钥长度无效"));
    }
    let cipher = crypto::aes128_cbc_pkcs7(key16.as_bytes(), plaintext)
        .ok_or_else(|| Error::http(500, "无法初始化 Qoder 签名算法"))?;
    Ok(crypto::b64(&cipher))
}

/// RSA 公钥加密（PKCS#1 v1.5），返回 base64 密文。
fn rsa_encrypt_base64(plaintext: &str) -> Result<String> {
    let modulus = hex_bytes(RSA_MODULUS_HEX)
        .ok_or_else(|| Error::http(500, "Qoder 签名公钥无效"))?;
    let cipher = crypto::rsa_pkcs1_encrypt(&modulus, RSA_EXPONENT, plaintext.as_bytes());
    if cipher.is_empty() {
        return Err(Error::http(500, "Qoder 签名内容过长或计算结果无效"));
    }
    Ok(crypto::b64(&cipher))
}

/// 生成一个不可猜测的 UUID v4（供会话/记录标识使用）。
pub fn random_uuid() -> String {
    crypto::uuid_v4()
}
