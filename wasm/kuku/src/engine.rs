//! KukuAI 的「业务会话令牌」换发：BDUSS + PTOKEN → genflowpro 作用域的 STOKEN。
//!
//! ── 为什么需要换发（照 native `kuku/engine.rs` 模块头）──────────
//! KukuAI 的业务接口（`userreport` / `sendmsg` / `getchatcontent`）认的是
//! **按产品签发**的 STOKEN，而网页登录 Cookie 里那份是**通行证级**的 ——
//! 无论带多少 Cookie 都过不了校验（`errno=-6`）。症状很有欺骗性：余额接口只看
//! BDUSS，所以「余额正常、模型拉不下」。
//!
//! 换发材料是 `PTOKEN`（`account::ptoken_of`），端点：
//! `POST https://passport.baidu.com/v3/login/api/auth`
//!
//! ── 签名：纯算法，不加载任何原生模块 ────────────────────────
//! 官方客户端用 `genflowengine.dll` 的 `genflow_engine_get_login_auth_param`
//! 构造参数体，但它本质只是「六个字段拼串 + 内置密钥 + 一次 MD5」：
//!
//! ```text
//!   sig  = md5("appid=1&bduss=<BDUSS>&ptoken=<PTOKEN>&return_type=1&\
//!              tpl=genflowpro&tpl_list=genflowpro|netdisk&sign_key=<KEY>")
//!   body = "appid=1&bduss=<BDUSS>&ptoken=<PTOKEN>&return_type=1&\
//!           tpl=genflowpro&tpl_list=genflowpro|netdisk&sig=<sig>"
//! ```
//!
//! 密钥与公式由 `IKUNHEIHIE/kuku2api`（0BSD）用真实 DLL 对两组合成输入验证过、
//! 再以真实抓包复算过，见 `build_auth_param`。所以 wasm 插件**不需要**原生辅助
//! （`native.helpers.v1` 里没有这一项）、也不把 14MB 的原生引擎映射进宿主进程 ——
//! 与插件「一次调用一个沙箱实例」的模型一致。
//!
//! 缺 `sig` / 错 `sig` 上游回 `errno=110003`（另一种表现是 `-6`），
//! **不假装成功** —— 调用方按 `Err` 处理，回退到「用原 STOKEN 继续」
//! （与 native 的「换发失败只记日志、不阻断」取向一致；wasm 侧没有日志通道，
//! 失败原因随返回值交回调用方）。
//!
//! ── 影响面 ──────────────────────────────────────────────────
//! 只影响「网页登录 / 手粘 Cookie」的账号（其 Cookie 里那份是通行证级 STOKEN）；
//! 桌面端导入的账号 Cookies 里带的就是业务级 STOKEN，本不需要换发。
//! `ENGINE_SIGN_KEY` 是编译进官方客户端的常量，上游若更换需同步更新。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{http, json, Error, Result, Value};

use super::md5;
use super::upstream;

/// 换发端点（passport 的 v3 登录 API）
pub const PASSPORT_AUTH_URL: &str = "https://passport.baidu.com/v3/login/api/auth";

/// 官方引擎内置的签名密钥，编译进 `genflowengine.dll`（kuku2api 用真实 DLL
/// 与真实抓包双重验证）。上游更换时这里要跟着更新。
const ENGINE_SIGN_KEY: &str = "34868b316de55815273b2616954b0286";

/// 换发这一步对「客户端引擎 UA」敏感 —— 浏览器 UA 会被判成非客户端。
/// 取值与抓包到的 `/v3/login/api/auth` 请求逐字一致。
const ENGINE_UA: &str = "genflow;1.6.5;PC;PC-Windows;10.0.26200;GenFlowPro";

/// 换发响应体的读取上限（服务端只会回一个很小的 JSON）
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// 构造换发用的签名参数体（见模块头）。
///
/// 签名输入与发送体必须是**同一份、未做百分号编码**的字段串：服务端按收到的
/// `tpl_list` / `sign_key` 等字段逐字复算 MD5，两者不一致就回 `errno=110003`。
/// BDUSS 是 base64 风格、PTOKEN 是十六进制，都不含需要转义的字符，故与官方
/// 客户端一样直接拼串（`|` 在值里也不需要转义）。
///
/// ⚠️ 拼串里**不能有任何换行或缩进**：签名覆盖的就是这串字节，多一个空格
/// 服务端复算的结果就对不上（`auth_param_is_signed_without_whitespace` 钉住这一点）。
pub fn build_auth_param(bduss: &str, ptoken: &str) -> String {
    let signed = format!(
        "appid=1&bduss={bduss}&ptoken={ptoken}&return_type=1&tpl=genflowpro&tpl_list=genflowpro|netdisk&sign_key={ENGINE_SIGN_KEY}"
    );
    let signature = md5::hex(signed.as_bytes());
    format!(
        "appid=1&bduss={bduss}&ptoken={ptoken}&return_type=1&tpl=genflowpro&tpl_list=genflowpro|netdisk&sig={signature}"
    )
}

/// 用 BDUSS + PTOKEN 换发「genflowpro 作用域」的 STOKEN。
///
/// 成功返回新 STOKEN；失败（缺材料 / 被拒 / 网络异常）返回带可读原因的 `Err`，
/// 由调用方决定回退方式（本项目口径是「用原凭证继续」）。
pub fn exchange_genflowpro_stoken(bduss: &str, ptoken: &str) -> Result<String> {
    if bduss.trim().is_empty() || ptoken.trim().is_empty() {
        return Err(Error::http(
            400,
            "换发 KukuAI 会话令牌需要 BDUSS 与 PTOKEN（登录 Cookie 里缺 PTOKEN）",
        ));
    }
    // ── 参数体：六字段 + 内置密钥算出的 MD5 签名（见模块头）──────
    let body = build_auth_param(bduss, ptoken);
    // ── 为什么用 `open_raw` 而不是 `open` ──────────────────────
    // `open` 的 body 是 `Option<&Value>`，会按 JSON 发；passport 只认
    // `application/x-www-form-urlencoded`（发错编码的表现是 400 `invalid_request`，
    // 与「凭证不对」难以区分）。这里直发一次原始字节。
    let headers = json!({
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "referer": format!("{}/genflowpro", upstream::BASE_URL),
        "origin": upstream::BASE_URL,
        "user-agent": ENGINE_UA,
        "accept": "application/json, text/plain, */*",
    });
    let response = http::open_raw("POST", PASSPORT_AUTH_URL, headers, Some(body.as_bytes()))?;
    let status = response.status;
    if !(200..300).contains(&status) {
        return Err(Error::http(
            502,
            format!("换发 KukuAI 会话令牌失败（HTTP {status}）"),
        ));
    }
    let bytes = response.bytes(MAX_RESPONSE_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        Error::http(502, "换发 KukuAI 会话令牌响应异常：不是有效 JSON")
    })?;
    let errno = value.get("errno").and_then(Value::as_i64).unwrap_or(-1);
    if errno != 0 {
        let message = value
            .get("errmsg")
            .or_else(|| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(Error::http(
            502,
            format!("换发 KukuAI 会话令牌被拒（errno={errno}：{message}）"),
        ));
    }
    let stoken = value
        .pointer("/stoken_list/genflowpro")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if stoken.is_empty() {
        return Err(Error::http(
            502,
            "换发 KukuAI 会话令牌成功但响应缺少 genflowpro 令牌",
        ));
    }
    Ok(stoken)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 签名覆盖的是出门那串字节：多一个空白/换行，服务端复算就对不上
    /// （症状是上游 `errno=110003`，与「凭证不对」难以区分）。
    #[test]
    fn auth_param_is_signed_without_whitespace() {
        let body = build_auth_param("TEST-BDUSS-0123456789", "0123456789abcdef0123456789abcdef");
        assert!(!body.contains('\n'));
        assert!(!body.contains("  "));
        // 字段顺序与官方客户端逐字一致
        let expected_prefix = "appid=1&bduss=TEST-BDUSS-0123456789&ptoken=0123456789abcdef0123456789abcdef&return_type=1&tpl=genflowpro&tpl_list=genflowpro|netdisk&sig=";
        assert!(body.starts_with(expected_prefix), "实际：{body}");
        // 32 位十六进制小写摘要
        let signature = &body[expected_prefix.len()..];
        assert_eq!(32, signature.len());
        assert!(signature.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    /// 已知向量：同一组输入，签名必须逐字等于独立实现（.NET
    /// `System.Security.Cryptography.MD5`）算出的值。
    #[test]
    fn auth_param_matches_known_vector() {
        let body = build_auth_param("TEST-BDUSS-0123456789", "0123456789abcdef0123456789abcdef");
        assert!(
            body.ends_with("sig=c5f56328dc7106050ca01de48d53b223"),
            "实际：{body}"
        );
    }

    /// 缺材料时如实报错，不拿空串去签名。
    #[test]
    fn missing_material_is_an_error() {
        assert!(exchange_genflowpro_stoken("", "pt").is_err());
        assert!(exchange_genflowpro_stoken("bduss", "  ").is_err());
    }
}
