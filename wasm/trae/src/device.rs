//! 登录用的设备密钥对与一次性标识（PKCE / uuid / device id）。
//!
//! ── 为什么要专门生成一对密钥 ────────────────────────────────
//! 官方客户端每次登录都现生成一套 P-256，把 **SPKI 公钥 PEM** 塞进
//! `ExchangeToken` 的 `DeviceInfo.DevicePublicKey`，服务端把它与该次登录的
//! `DeviceID` / `MachineID` 绑在一起。native 侧记录的实测结论：**空值会被判成
//! HTTP 401 / 业务码 20405**（`2xxxx` 那族是凭据/设备绑定拒绝），所以这不是
//! "可选的元数据"，少了就登不进来。
//!
//! 私钥同样要落进凭据（`auth.devicePrivateKey`）：参考实现里它**只写不读**，
//! 但重建凭据时必须保住 —— 把它抹掉等于把这台设备的绑定关系弄断，而那条链上
//! 没有任何一处会告诉你为什么突然 401 了。
//!
//! PEM 的行宽按 Go `encoding/pem` 的 64 字符折行，两边产物可以直接对读。

use agent2api_wasm_sdk::{Error, Result};

use super::{codec, p256};

/// 一对设备密钥（公钥进请求，私钥进凭据）。
pub struct DeviceKeyPair {
    /// `-----BEGIN PUBLIC KEY-----`（SPKI / DER）
    pub public_pem: String,
    /// `-----BEGIN PRIVATE KEY-----`（PKCS#8 / DER）
    pub private_pem: String,
}

/// 生成一套新的设备密钥。
///
/// 标量取自宿主的随机源；落在 `[1, n-1]` 之外时**重取**（概率约 2^-32，
/// 但"取一次就假定成功"在密码学路径上是不允许的写法）。
pub fn key_pair() -> Result<DeviceKeyPair> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&codec::random_bytes(32));
        let Some(public) = p256::public_key_sec1(&bytes) else {
            continue;
        };
        return Ok(DeviceKeyPair {
            public_pem: pem("PUBLIC KEY", &p256::spki_der(&public)),
            private_pem: pem("PRIVATE KEY", &p256::pkcs8_der(&bytes, &public)),
        });
    }
    Err(Error::new("生成设备密钥对失败（随机源不可用或连续取到非法标量）"))
}

/// DER → Go `encoding/pem` 同格式的 PEM（64 字符折行，首尾各带换行）。
fn pem(label: &str, der: &[u8]) -> String {
    let encoded = codec::base64_encode(der);
    let mut out = String::with_capacity(encoded.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // base64 表全是 ASCII，分片不会切出非法 UTF-8 序列。
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// PKCE：48 随机字节 → base64url(无填充)；challenge = SHA-256(verifier) 同编码。
///
/// 方法是 `S256`（Trae 用官方 PKCE 名，不像 codearts 那边写的是 `SHA-256`）。
pub fn pkce_pair() -> Result<(String, String)> {
    use sha2::{Digest, Sha256};
    let verifier = base64_url(&codec::random_bytes(48));
    let challenge = base64_url(&Sha256::digest(verifier.as_bytes()));
    Ok((verifier, challenge))
}

/// base64url 无填充（PKCE 要求这一种编码，带 `=` 会被上游拒）。
fn base64_url(bytes: &[u8]) -> String {
    codec::base64_encode(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// RFC 4122 v4 形态的随机 id（`login_trace_id`、`machine_id`、
/// `X-Request-Id` 都用它）。
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&codec::random_bytes(16));
    // 版本位与变体位：少了这两处就不是 uuid-v4 的形状（上游按形状校验）。
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = codec::hex_lower(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// 纯数字的 `device_id`（官方客户端给的是 16 位数字串）。
///
/// 逐字节取模会偏向 0-5（256 不是 10 的整数倍），因此丢掉 250-255 这六个值
/// —— 设备号的空间是 10^16，分布歪了就是可被统计出来的画像特征
/// （native 的 `checkin.rs` 对签到设备号有同样一条，两处判据一致）。
pub fn random_digits(length: usize) -> String {
    let mut digits = String::with_capacity(length);
    while digits.len() < length {
        for byte in codec::random_bytes(32) {
            if byte < 250 {
                digits.push(char::from(b'0' + byte % 10));
                if digits.len() == length {
                    break;
                }
            }
        }
    }
    digits
}
