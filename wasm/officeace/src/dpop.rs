//! DPoP proof（RFC 9449 的 `DPoP` 头）：一个 ES256 的 JWS，头部嵌**公钥 JWK**，
//! 载荷声明「这个方法、这个地址、这个时刻、这个一次性 id」。
//!
//! ── 为什么插件里也要有这一层 ────────────────────────────────
//! 登录换证（`POST {sts}/v1/oauth2/tokens`）与续期都要递 `DPoP:` 头；上游用头里
//! 的公钥验签，**换一把就续不了**（与 PKCE verifier 同一条道理）。所以这里与
//! native `crates/providers/src/dpop.rs` 逐条同构，只把签名原语换成
//! [`crate::p256`]（没有 `p256` crate 可用）。
//!
//! ── 落盘形态不能改 ──────────────────────────────────────────
//! 密钥对直接以 JSON 存在账号 secret 的 `dpopKeyPair` 键里：
//! `{private_key_jwk:{kty,crv,x,y,d}, public_key_jwk:{kty,crv,x,y}}`。
//! 存量记录（内置版时代登录的账号）就是这个形状，改一个键名就会让那批账号
//! 续期时认不出私钥 —— 表现为「续期失败，请重新登录」。
//!
//! ── 三个容易写错的细节 ──────────────────────────────────────
//!   1. `x` / `y` 必须是**定长 32 字节**的 base64url。大整数的十进制形态去掉前导
//!      零会短一截，上游会把那个点判成非法。
//!   2. `iat` 是**秒**（毫秒除 1000），不是毫秒。
//!   3. 签名是 **JOSE 裸格式**（`r || s` 各 32 字节），不是 DER —— 用 DER 上游只回 401。

use agent2api_wasm_sdk::{json, Value};

use super::p256;
use super::util;

/// 上游只收这一种算法（与 CodeArts 那条同一个 STS）。
const ALG: &str = "ES256";
/// JWS 头的 `typ`。
const TYP: &str = "dpop+jwt";

/// 一份可用的 DPoP 密钥：私钥（签名）+ 公钥 JWK（嵌进 JWS 头）。
pub struct DpopKey {
    scalar: [u8; 32],
    public_jwk: Value,
}

impl DpopKey {
    /// 从落盘的 `{private_key_jwk, public_key_jwk}` 恢复。
    ///
    /// 只读私钥那一半（公钥由它推出）；落盘的公钥若存在且与私钥不符，说明凭据被
    /// 改坏了 —— 宁可报错，也不要签出一份「头里的公钥和签名的私钥对不上」的 proof
    /// 去打上游（那会是 401，且看起来像凭据过期）。
    pub fn from_json(pair: &Value) -> Result<Self, String> {
        let private = pair
            .get("private_key_jwk")
            .or_else(|| pair.get("privateKeyJwk"))
            .ok_or_else(|| "DPoP 私钥缺失（dpopKeyPair.private_key_jwk）".to_string())?;
        let kty = private.get("kty").and_then(Value::as_str).unwrap_or("");
        let crv = private.get("crv").and_then(Value::as_str).unwrap_or("");
        let scalar_text = private.get("d").and_then(Value::as_str).unwrap_or("");
        if kty != "EC" || crv != "P-256" || scalar_text.trim().is_empty() {
            return Err("DPoP 私钥不完整（需要 EC / P-256 / d）".to_string());
        }
        let bytes = util::base64url_decode(scalar_text.trim())
            .ok_or_else(|| "DPoP 私钥不是合法的 base64url".to_string())?;
        if bytes.len() != 32 || !p256::valid_scalar(&bytes) {
            return Err("DPoP 私钥不是合法的 P-256 标量".to_string());
        }
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&bytes);
        let public_jwk = public_jwk_of(&scalar)?;
        // 落盘的公钥若在，必须与私钥推出的一致
        if let Some(stored) = pair
            .get("public_key_jwk")
            .or_else(|| pair.get("publicKeyJwk"))
            .filter(|value| value.is_object())
        {
            let stored_x = stored.get("x").and_then(Value::as_str).unwrap_or("").trim();
            let stored_y = stored.get("y").and_then(Value::as_str).unwrap_or("").trim();
            let same = stored_x.is_empty()
                && stored_y.is_empty()
                || (stored_x == text_of(&public_jwk, "x") && stored_y == text_of(&public_jwk, "y"));
            if !same {
                return Err("DPoP 公私钥不一致，请重新登录".to_string());
            }
        }
        Ok(Self { scalar, public_jwk })
    }

    /// **新生成**一把 P-256 密钥，返回可直接落盘的那一份。
    ///
    /// 发起登录时用一次：这把私钥要跟着凭据存下来。随机源只认宿主的
    /// `random.bytes` —— 私钥的 `d` 可预测等于这把钥匙没锁（见 `p256` 模块头）。
    pub fn generate() -> Result<Value, String> {
        for _ in 0..8 {
            let raw = util::secure_random_bytes(32)
                .ok_or_else(|| "宿主未提供随机源（random.v1），无法生成 DPoP 密钥".to_string())?;
            if raw.len() != 32 || !p256::valid_scalar(&raw) {
                continue;
            }
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&raw);
            let public = public_jwk_of(&scalar)?;
            let mut private = public.clone();
            if let Some(object) = private.as_object_mut() {
                object.insert("d".to_string(), Value::String(util::base64url_encode(&scalar)));
            }
            return Ok(json!({
                "private_key_jwk": private,
                "public_key_jwk": public,
            }));
        }
        Err("无法生成本机 P-256 密钥，请重试".to_string())
    }

    /// 现签一份 proof。
    ///
    /// `method` 与 `endpoint` 必须与即将发出的请求**逐字**一致（上游会比对，对不上
    /// 就是 401）；`htu` 用完整地址，不带 fragment。
    pub fn proof(&self, method: &str, endpoint: &str, now_ms: i64) -> Result<String, String> {
        let header = json!({ "alg": ALG, "typ": TYP, "jwk": self.public_jwk });
        let header_json = serde_json::to_vec(&header)
            .map_err(|error| format!("DPoP 头部序列化失败：{error}"))?;
        // jti 用 32 字节随机数的十六进制（与参考实现的 randomHex(32) 同形状）。
        // 这里**可以**退到时间派生（它只是一次性标识），所以用 util 的普通随机源。
        let jti = util::random_hex(32);
        let payload = json!({
            "htm": method.to_ascii_uppercase(),
            "htu": endpoint,
            "iat": now_ms / 1000,
            "jti": jti,
        });
        let payload_json = serde_json::to_vec(&payload)
            .map_err(|error| format!("DPoP 载荷序列化失败：{error}"))?;
        let signing_input = format!(
            "{}.{}",
            util::base64url_encode(&header_json),
            util::base64url_encode(&payload_json)
        );
        let digest = p256::sha256(signing_input.as_bytes());
        let signature = p256::sign(&digest, &self.scalar)
            .ok_or_else(|| "DPoP 签名失败（随机源或私钥不可用），请重新登录".to_string())?;
        Ok(format!(
            "{signing_input}.{}",
            util::base64url_encode(&signature)
        ))
    }
}

/// 由私钥推出公钥 JWK；`x` / `y` 必须是 32 字节定长（见模块头第 1 条）。
fn public_jwk_of(scalar: &[u8; 32]) -> Result<Value, String> {
    let sec1 = p256::public_key_sec1(scalar)
        .ok_or_else(|| "DPoP 私钥不是合法的 P-256 标量".to_string())?;
    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": util::base64url_encode(&sec1[1..33]),
        "y": util::base64url_encode(&sec1[33..65]),
    }))
}

fn text_of(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

    /// 用固定私钥推出公钥，公钥的 x/y 必须与独立来源（同一条曲线上的公开点）一致。
    ///
    /// 私钥取 `1`：此时公钥就是生成元 G，x/y 是 NIST P-256 的公开常数 ——
    /// 这条断言把「JWK 的定长编码」与「标量乘」两头一起钉住了。
    #[test]
    fn jwk_for_generator_matches_public_constants() {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        let jwk = public_jwk_of(&scalar).unwrap_or(Value::Null);
        assert_eq!(jwk["kty"], json!("EC"));
        assert_eq!(jwk["crv"], json!("P-256"));
        let expected_x = util::hex_decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .unwrap_or_default();
        let expected_y = util::hex_decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .unwrap_or_default();
        assert_eq!(
            util::base64url_decode(jwk["x"].as_str().unwrap_or_default()).unwrap_or_default(),
            expected_x,
            "JWK 的 x 必须解码回 G.x 的 32 字节"
        );
        assert_eq!(
            util::base64url_decode(jwk["y"].as_str().unwrap_or_default()).unwrap_or_default(),
            expected_y,
            "JWK 的 y 必须解码回 G.y 的 32 字节"
        );
    }

    /// 生成的密钥对必须能被 `from_json` 原样读回（含公私钥一致性校验）。
    #[test]
    fn generated_pair_round_trips() {
        let pair = match DpopKey::generate() {
            Ok(pair) => pair,
            // 宿主随机源在单测里不存在（`random.bytes` 是宿主调用）——这条测试
            // 只在宿主侧有效，所以拿不到随机就跳过而不是失败。
            Err(_) => return,
        };
        let key = DpopKey::from_json(&pair);
        assert!(key.is_ok(), "生成的密钥对必须能被读回");
        // 改一个字节的公钥应当被判成不一致
        let mut tampered = pair.clone();
        tampered["public_key_jwk"]["x"] = json!("AAAA");
        assert!(DpopKey::from_json(&tampered).is_err());
    }

    #[test]
    fn rejects_incomplete_pair() {
        assert!(DpopKey::from_json(&json!({})).is_err());
        assert!(DpopKey::from_json(&json!({ "private_key_jwk": { "kty": "RSA" } })).is_err());
    }
}
