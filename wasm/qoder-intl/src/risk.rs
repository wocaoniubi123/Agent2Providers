//! Qoder **设备风控身份**（`Cosy-MachineToken` / `Cosy-MachineCode` /
//! `Cosy-MachineType`）—— 国际版签到链路的唯一依赖。
//!
//! ── 为什么需要它（native `risk.rs` 的实测结论，issue #140）────────
//! 国际版服务端**只对带风控头的请求**下发「每天领 100 Credits」的活动：
//! 不带时 `GET /sash/api/v1/me/campaigns` 里永远只有 `VIEW_DETAILS` 促销 ——
//! 这正是本家旧注释「国际版没有签到计划」的真正原因（缺头，不是没活动）。
//! 中国版不需要风控头就能领，所以 `wasm/qoder` 里根本没有这个模块。
//!
//! ── native 怎么做，wasm 为什么不能照抄 ──────────────────────
//! native 自己发现并运行 Qoder 的 **UMID 程序**（`runtime-info`）：扫安装目录、
//! `~/.qoder/.bin/umid-*`、插件数据目录，起子进程、写 stdin、读首行 JSON；
//! Linux 上还会从 npm 包里提取 ELF 落地。这些动作（子进程 / 文件系统 / 网络
//! 下载 + 解包）**wasm 沙箱里全都没有**，硬做只能编出一个假实现。
//!
//! ── 所以走网关宿主通道（不是降级，是唯一正路）──────────────────
//! 网关已经有这条能力：`server/core/plugin_host/wasm/qoder_umid/`，注册的辅助
//! 程序 id 是 `desktop.qoder-umid.v1`，**只对 `provider == "qoder-intl"` 生效**
//! （`qoder_umid::candidate` 里的硬判据），三个操作：
//!
//!   - `status`   → `{available, componentAvailable, source, installSupported,
//!                   installing, authorized, message, dailyCampaignsReady}`
//!   - `install`  → 安装组件（仅 Linux 支持下载；Windows / macOS 走本机客户端）
//!   - `identity` → 入参 `{uid}`，出参 `{headers: {Cosy-MachineToken, …}, uid}`
//!
//! 宿主那一侧还替我们做了三件 native 里做过的事：先拿活动列表核对 `uid` 与
//! 凭证一致（防止把 A 账号的风控身份挂到 B 账号上）、把 `Cosy-MachineOS` 按真实
//! 宿主平台填好、组件版本填进 `Cosy-Version`。
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! native 缓存 50 分钟（客户端每 60±5 分钟轮换一次身份）。宿主不做缓存，每次
//! `identity` 都真跑一次组件（25 秒超时）—— 签到是「一天一次」的量级，但
//! `claim.status` 与 `checkin.claim` 会连着调，所以这里在**会话状态**里放
//! 50 分钟的快照（键按 uid + 凭证摘要），语义与 native 那张进程内表等价。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic；宿主返回的形状不信任（逐键校验后再用）。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::site;

/// 身份缓存时长（客户端 60±5 分钟轮换，保守取 50 分钟，与 native 同值）
const RISK_TTL_MS: i64 = 50 * 60 * 1000;
/// 会话状态里的键前缀（后缀是 uid + 凭证摘要）
const CACHE_KEY: &str = "qoder-intl-risk";

/// 组件状态（`admin.action` 的 `risk.status`，形状与网关既有接口逐键一致）。
///
/// 网关前端读的就是这几个键（`available` / `source` / `installSupported` /
/// `installing`），宿主原样给了它们，这里直接透传 —— 但**先把字段窄化一遍**：
/// 宿主是同一进程里的可信方，插件仍按「外部输入」对待，缺字段给安全缺省。
pub fn status() -> Result<Value> {
    let raw = sdk::native_call(site::UMID_HELPER, "status", json!({}))?;
    Ok(json!({
        "available": raw["available"].as_bool().unwrap_or(false),
        "componentAvailable": raw["componentAvailable"].as_bool().unwrap_or(false),
        "source": raw["source"].clone(),
        "installSupported": raw["installSupported"].as_bool().unwrap_or(false),
        "installing": raw["installing"].as_bool().unwrap_or(false),
        "authorized": raw["authorized"].as_bool().unwrap_or(false),
        "message": raw["message"].as_str().unwrap_or(""),
        "dailyCampaignsReady": raw["dailyCampaignsReady"].as_bool().unwrap_or(false),
    }))
}

/// 安装组件（`admin.action` 的 `risk.install`）。
///
/// 只有 Linux 需要下载（Windows / macOS 用户有 Qoder 客户端与 qodercli 两条
/// 现成路径）。平台判断在宿主，这里原样透传它的结论与错误文案。
pub fn install() -> Result<Value> {
    sdk::native_call(site::UMID_HELPER, "install", json!({}))
}

/// 一张风控身份头表（`Cosy-Machine*` 四到六项）。
///
/// `uid` 为空时直接给 `Err` —— 风控身份是**按账号**生成的，拿不到 uid 就无从
/// 生成（native 同样在 uid 为空时返回 None）。
fn identity_headers(uid: &str, credential_digest: &str) -> Result<Value> {
    let uid = uid.trim();
    if uid.is_empty() || uid.len() > 256 || uid.chars().any(char::is_control) {
        return Err(Error::http(502, "国际版签到缺账号 uid，无法生成设备风控身份"));
    }
    let cache_key = format!("{CACHE_KEY}:{uid}:{credential_digest}");
    if let Ok(cached) = sdk::session_get(&cache_key) {
        if cached.is_object() && cached["headers"].is_object() {
            return Ok(cached["headers"].clone());
        }
    }
    let raw = sdk::native_call(site::UMID_HELPER, "identity", json!({ "uid": uid }))?;
    let headers = raw["headers"]
        .as_object()
        .ok_or_else(|| Error::http(502, "设备风控组件未返回请求头，签到未发出"))?;
    // 只认 `Cosy-Machine*` 这几个键：宿主返回别的东西（未来扩展）也不该被
    // 原样塞进上游请求。
    let mut kept = serde_json::Map::new();
    for (key, value) in headers {
        if !key.to_ascii_lowercase().starts_with("cosy-") {
            continue;
        }
        if let Some(text) = value.as_str() {
            if !text.is_empty() && text.len() <= 4096 {
                kept.insert(key.clone(), Value::String(text.to_string()));
            }
        }
    }
    if !kept.contains_key("Cosy-MachineToken") {
        return Err(Error::http(502, "设备风控组件未给出 Cosy-MachineToken，签到未发出"));
    }
    let kept = Value::Object(kept);
    let _ = sdk::session_put(
        &cache_key,
        json!({ "headers": kept.clone() }),
        RISK_TTL_MS,
    );
    Ok(kept)
}

/// 凭证摘要（缓存键的一部分：换了令牌就重新取身份，不同账号互不串用）。
///
/// 摘要只进会话状态的键名，不落日志，也不回给调用方。
pub fn credential_digest(access_token: &str, user_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"qoder-intl-risk");
    hasher.update([0u8]);
    hasher.update(user_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(access_token.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

/// 签到头增强：在基础头（`sash_headers`）上叠加客户端身份与设备风控身份。
///
/// 返回 `(增强后的头, 风控不可用的原因)` —— 原因是**给用户看的**，会进签到
/// 结果文案（native 同口径）。缺风控三件套时上游不下发积分活动，它不抛错，
/// 所以这里也不把「缺组件」当失败，只把原因带回去。
///
/// 叠加的字段与 native `risk::augment_headers` 同一组：`Cosy-Version`（组件
/// 版本）→ `Cosy-MachineOS` → `Cosy-MachineId` → `Cosy-MachineHostname` →
/// 风控三件套（Token / Code / Type）。**整组由宿主的 `identity` 一次给出** ——
/// 组件版本、真实宿主主机名与平台都在宿主那一侧（插件既拿不到平台也读不到
/// 主机名），所以这里不做任何拼接、只把宿主给的键并进来。
pub fn augment_headers(
    mut headers: Vec<(String, String)>,
    access_token: &str,
    user_id: &str,
) -> (Vec<(String, String)>, Option<String>) {
    let digest = credential_digest(access_token, user_id);
    match identity_headers(user_id, &digest) {
        Ok(extra) => {
            if let Some(fields) = extra.as_object() {
                for (key, value) in fields {
                    if let Some(text) = value.as_str() {
                        headers.push((key.clone(), text.to_string()));
                    }
                }
            }
            (headers, None)
        }
        Err(error) => (headers, Some(error.message)),
    }
}
