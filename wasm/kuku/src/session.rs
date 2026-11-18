//! KukuAI 会话三件套（`bdstoken` / `uinfo` / `uk`）的缓存与自愈。
//!
//! ── 为什么需要缓存（照 native `kuku/session.rs`）─────────────
//! 对话链路要求每次请求带 `bdstoken/uinfo/uk`（拼进 query），它们由
//! `GET /api/genflowpro/common/userreport` 用登录 Cookie 换来（kuku2api 实测）。
//! 每次对话都打一次 userreport 既没必要也加重上游负担 —— 参考实现缓存 600 秒，
//! 本模块同值。key 用凭证指纹（同一账号的 Cookie 不变，三件套可复用）。
//!
//! ── wasm 侧的缓存载体：宿主会话存储 ──────────────────────────
//! native 用进程级 `Mutex<HashMap>`。wasm 实例是「一次调用一个沙箱」的，
//! 进程内静态不可跨请求存活，所以改用宿主会话存储（`sdk::session_get/put`，
//! 能力 `sessions.v1`）。它本来就带 TTL（`ttl_ms`），语义与 native 的
//! `refreshed_at + TTL_MS` 判据一一对应。
//!
//! ── 会话自愈（2026-10-08 实测后加，与 native 同一条路径）───────
//! 凭证里的 STOKEN 可能是**通行证级**的（网页登录早期版本落库的账号）或已被
//! 后续登录轮换 —— 业务接口判「未登录」（errno=-6），而余额这类通用接口只看
//! BDUSS，所以用户看到的是「余额正常、模型拉不下」。只要 extras 里有 PTOKEN，
//! 就先向百度通行证换发一次 genflowpro STOKEN（`engine.rs`）再重试；换发失败
//! 保持原错误路径，行为与旧版一致。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::account::{self, KukuCredentials};
use super::engine;
use super::upstream;

/// 三件套的有效期（参考实现 600 秒，同值）
const TTL_MS: i64 = 600_000;

/// 会话缓存键前缀（后面接凭证指纹）
const KEY_PREFIX: &str = "kuku:triple:";

/// 会话三件套。
#[derive(Clone, Debug, Default)]
pub struct TokenTriple {
    pub bdstoken: String,
    pub uinfo: String,
    pub uk: String,
}

/// 取（必要时刷新）会话三件套。
///
/// `force = true` 跳过缓存直接刷新（添加账号验证时用，要的是「现在真的能用」）。
pub fn ensure(credentials: &KukuCredentials, force: bool) -> Result<TokenTriple> {
    let key = format!("{KEY_PREFIX}{}", credentials.fingerprint());
    if !force {
        if let Ok(value) = sdk::session_get(&key) {
            if let Some(triple) = triple_of(&value) {
                return Ok(triple);
            }
        }
    }
    let triple = fetch(credentials)?;
    // 写缓存失败不影响本次结果（下次再问一次上游而已）
    let _ = sdk::session_put(
        &key,
        json!({
            "bdstoken": triple.bdstoken,
            "uinfo": triple.uinfo,
            "uk": triple.uk,
        }),
        TTL_MS,
    );
    Ok(triple)
}

/// 缓存值还原成三件套（`bdstoken` 为空视为未命中）。
fn triple_of(value: &Value) -> Option<TokenTriple> {
    let bdstoken = value.get("bdstoken").and_then(Value::as_str).unwrap_or("").trim();
    if bdstoken.is_empty() {
        return None;
    }
    Some(TokenTriple {
        bdstoken: bdstoken.to_string(),
        uinfo: value.get("uinfo").and_then(Value::as_str).unwrap_or("").to_string(),
        uk: value.get("uk").and_then(Value::as_str).unwrap_or("").to_string(),
    })
}

/// 打一次 userreport 换三件套（带 PTOKEN 自愈）。
fn fetch(credentials: &KukuCredentials) -> Result<TokenTriple> {
    let url = format!(
        "{}/api/genflowpro/common/userreport?{}",
        upstream::BASE_URL,
        upstream::WEB_QUERY
    );
    let mut prepared = credentials.clone();
    let mut value = upstream::get_json(&url, &upstream::headers(&prepared.cookie_header()))?;
    let mut errno = errno_of(&value);
    if errno != 0 {
        if let Some(ptoken) = account::ptoken_of(&prepared.extras) {
            if let Ok(stoken) = engine::exchange_genflowpro_stoken(&prepared.bduss, &ptoken) {
                prepared.stoken = stoken;
                value = upstream::get_json(&url, &upstream::headers(&prepared.cookie_header()))?;
                errno = errno_of(&value);
            }
        }
    }
    if errno != 0 {
        let message = value
            .get("show_msg")
            .or_else(|| value.get("errmsg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        // 走到这里的 -6 已经过一次「换发业务令牌重试」仍然失败（2026-10-08 实测：
        // 换发成功即 errno=0），剩下的基本是凭证真失效（退出登录 / 换号）或
        // 上游临时风控限流。
        return Err(Error::http(
            401,
            format!(
                "KukuAI 会话校验未通过（userreport errno={errno}：{message}）——请重新登录该账号（或重新粘贴完整 Cookie）后再试；若账号无误，等 1-2 分钟再试"
            ),
        )
        .with_code("token_expired"));
    }
    let Some(data) = value.get("data") else {
        return Err(Error::http(
            502,
            "KukuAI userreport 返回缺少 data（上游响应异常）",
        ));
    };
    let text_of = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let triple = TokenTriple {
        bdstoken: text_of("bdstoken"),
        uinfo: text_of("uinfo"),
        // uk 可能是字符串也可能是数字（kuku2api 直接 `d["uk"]`，参考实现初始值就是 0）；
        // as_str 拿不到数字，回落转成字符串（实测 uk 空时 model/list 仍能通，但对话
        // 接口可能要求非空，两形态都收）。
        uk: {
            let raw = data.get("uk");
            raw.and_then(Value::as_str)
                .map(str::trim)
                .map(str::to_string)
                .filter(|text| !text.is_empty())
                .or_else(|| raw.and_then(Value::as_i64).map(|number| number.to_string()))
                .unwrap_or_default()
        },
    };
    if triple.bdstoken.is_empty() {
        return Err(Error::http(
            502,
            "KukuAI userreport 返回缺少 bdstoken（上游响应异常）",
        ));
    }
    Ok(triple)
}

/// 会话 query 段（拼在接口 query 后：`&bdstoken=…&uinfo=…&uk=…`）。
pub fn token_query(triple: &TokenTriple) -> String {
    format!(
        "&bdstoken={}&uinfo={}&uk={}",
        triple.bdstoken, triple.uinfo, triple.uk
    )
}

/// 读顶层 `errno`（缺失给 -1，与 native 同一判据）。
fn errno_of(value: &Value) -> i64 {
    value.get("errno").and_then(Value::as_i64).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_appended_with_leading_ampersand() {
        let triple = TokenTriple {
            bdstoken: "bt".to_string(),
            uinfo: "ui".to_string(),
            uk: "42".to_string(),
        };
        assert_eq!("&bdstoken=bt&uinfo=ui&uk=42", token_query(&triple));
    }

    #[test]
    fn cache_roundtrip_requires_bdstoken() {
        assert!(triple_of(&Value::Null).is_none());
        assert!(triple_of(&json!({ "uinfo": "x" })).is_none());
        let triple = triple_of(&json!({ "bdstoken": "bt", "uinfo": "ui", "uk": "7" }));
        let triple = match triple {
            Some(triple) => triple,
            None => TokenTriple::default(),
        };
        assert_eq!("bt", triple.bdstoken);
        assert_eq!("7", triple.uk);
    }

    #[test]
    fn errno_defaults_to_minus_one() {
        assert_eq!(-1, errno_of(&json!({})));
        assert_eq!(-6, errno_of(&json!({ "errno": -6 })));
        assert_eq!(0, errno_of(&json!({ "errno": 0 })));
    }
}
