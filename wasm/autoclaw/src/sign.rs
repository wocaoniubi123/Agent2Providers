//! AutoClaw 的客户端指纹头（**全仓唯一一份**鉴权头实现）。
//!
//! ── 两条链路，两套头，刻意不一致 ────────────────────────────
//! ```text
//!   转发（/chat/completions）     品牌头 + X-Authorization，**不发** X-Harness-Type
//!   userapi（刷新 / 余额 / 签到 / 目录）  品牌头 + 签名头 + Bearer，**保留** X-Harness-Type
//! ```
//! 理由都在 native 的注释里，逐条搬来：
//!   - 上游自 2026-09-22 起对 `/chat/completions` 上的 `X-Harness-Type: zcode` 区别
//!     对待（稳定 `403 pay-view` / 406），所以转发**不发**这个头；
//!   - userapi 域当天实测带着它照常 200，而且它与 `X-Auth-Sign` 一起构成
//!     「官方客户端指纹」—— 在那条链路上做未经实测的删减，风险方向是签名失败
//!     （`code 400002`），收益是零。
//!
//! ── 签名怎么算 ──────────────────────────────────────────────
//! `X-Auth-Sign = MD5("{appId}&{X-Auth-TimeStamp}&{appKey}")`，时间戳单位是
//! **秒**（很容易和毫秒搞混 —— 写错就是稳定 400002）。appId/appKey 是客户端
//! 内嵌的固定指纹（不是我们的密钥），硬编码是正确的做法：换成可配置只会让
//! 签名对不上。
//!
//! ── 为什么签名只写一份 ──────────────────────────────────────
//! 刷新 / 余额 / 签到 / 目录四条链路都用 [`signed_headers`]。复制进各文件会让
//! appId/appKey、时间戳单位与品牌头各自演进，而签名一旦分叉就是稳定 400002，
//! 且只在某一条链路上暴露。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap / expect / panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use super::md5;
use super::region;

/// 签名用的 appId / appKey（源实现 `AUTH_APP_ID` / `AUTH_APP_KEY`）。
const AUTH_APP_ID: &str = "100003";
const AUTH_APP_KEY: &str = "38d2391985e2369a5fb8227d8e6cd5e5";

/// 平台标识（源实现 `platformTm()`）。
///
/// 上游只认官方桌面端存在的平台：`X-Tm: linux` 会被回 403（`{"message":
/// "forbidden"}`）。实测（固定请求体、只变「账号 × `X-Tm`」）：被上游绑为
/// Windows 的账号收到 `X-Tm: linux` 一律 403，而 `win` / `mac` / 不带均 200。
///
/// 插件进程跑在网关里（Windows / Linux 都可能），容器里不存在「真实平台」
/// 可选，且官方桌面端只有 Windows / macOS，故非 macOS 一律回 `win`。
fn platform_tm() -> &'static str {
    if cfg!(target_os = "macos") {
        "mac"
    } else {
        "win"
    }
}

/// 品牌头（源实现 `brandHeaders`，逐条照抄 —— **除了** `X-Harness-Type`）。
///
/// `x_trace_id` 的**下划线写法也是照抄**（源实现里就是这个键名，与后面那个
/// `X-Request-Id` 并存）。
pub fn brand_headers() -> Value {
    json!({
        "X-Product": "autoclaw",
        "X-Client-Type": "pc",
        "X-Tm": platform_tm(),
        "X-Version": region::DESKTOP_APP_VERSION,
        "X-Lang": region::CLIENT_LANG,
        "X-Channel": region::CLIENT_CHANNEL,
        "x_trace_id": "autoclaw-desktop",
    })
}

/// userapi 链路的签名头（刷新 / 余额 / 签到 / 模型目录共用）。
///
/// `token` 为空时只发匿名形态（登录链路上还没有 token）。
pub fn signed_headers(token: &str) -> Value {
    let timestamp = (sdk::now() / 1000).max(0).to_string();
    let sign = md5::hex(&format!("{AUTH_APP_ID}&{timestamp}&{AUTH_APP_KEY}"));
    let mut headers = json!({
        "Content-Type": "application/json",
        "Accept": "*/*",
        // 客户端版本门控：模型目录等 userapi 接口按它决定下发哪一档清单
        "X-Version": region::USERAPI_CLIENT_VERSION,
        "X-Product": "autoclaw",
        "X-Client-Type": "pc",
        // 见模块头：这里**保留** X-Harness-Type（与转发那条路刻意不一致）
        "X-Harness-Type": "zcode",
        "X-Tm": platform_tm(),
        "X-Lang": region::CLIENT_LANG,
        "X-Channel": region::CLIENT_CHANNEL,
        "X-Auth-Appid": AUTH_APP_ID,
        "X-Auth-TimeStamp": timestamp,
        "X-Auth-Sign": sign,
        "X-Trace-Id": super::codec::random_hex_id(),
    });
    if !token.is_empty() {
        // 必须剥一次前缀再拼（issue #386）：`Bearer Bearer eyJ…` 稳定 401
        let token = super::codec::strip_bearer(token);
        if !token.is_empty() {
            headers["authorization"] = json!(format!("Bearer {token}"));
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 签名头三件套必须齐全，且时间戳非空（测试环境里宿主时钟可能返回 0，
    /// 所以这里不断言位数，只断言形态与签名长度）。
    #[test]
    fn signed_headers_shape() {
        let headers = signed_headers("Bearer abc");
        assert_eq!(32, headers["X-Auth-Sign"].as_str().unwrap_or("").len());
        assert_eq!("100003", headers["X-Auth-Appid"].as_str().unwrap_or(""));
        let timestamp = headers["X-Auth-TimeStamp"].as_str().unwrap_or("");
        assert!(timestamp.bytes().all(|byte| byte.is_ascii_digit()) && !timestamp.is_empty());
        // Bearer 前缀必须被剥掉（不能出现 `Bearer Bearer`）
        assert_eq!("Bearer abc", headers["authorization"].as_str().unwrap_or(""));
    }

    /// 两个地区的品牌头逐字相同（appId/appKey 两地共用是实测结论）。
    #[test]
    fn brand_headers_are_region_agnostic() {
        let brand = brand_headers();
        assert_eq!("autoclaw", brand["X-Product"].as_str().unwrap_or(""));
        assert_eq!("win", brand["X-Tm"].as_str().unwrap_or(""));
    }
}
