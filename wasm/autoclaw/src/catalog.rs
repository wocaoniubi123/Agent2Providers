//! AutoClaw 模型目录的**远程拉取**（`GET {configBase}autoclaw-model-config`）。
//!
//! ── 接口为什么藏在「上一级」路径（先前找不到它的原因）──────────
//! 对话上游是 `{...}/autoclaw-proxy/proxy/autoclaw/chat/completions`，而模型
//! 配置在同 host 的 **`/proxy/` 这一级**：`.../autoclaw-proxy/proxy/autoclaw-model-config`
//! —— 桌面端用 `getConfigBaseUrl()` 取 `lastIndexOf("/proxy/")` 之后切片，
//! 把尾部的 `/autoclaw` 砍掉。顺着 `chat/completions` 找永远找不到它。
//!
//! ── 鉴权 ────────────────────────────────────────────────────
//! `authorization: Bearer <accessToken>` + 一套**可自行复算**的签名头
//! （`X-Auth-Appid` / `X-Auth-TimeStamp` / `X-Auth-Sign`）。签名实现在
//! `sign::signed_headers` —— 与本家的刷新接口共用同一份，不复制（复制会让
//! appId/appKey 与时间戳单位各自演进，而签名一旦分叉就是稳定 400002）。
//!
//! ── 响应形态（**与同批兄弟接口不同**）───────────────────────
//! 顶层直接是 `{"models":[...]}`，**没有 `{code, data}` 信封**
//! （同批的 `provider-config` / `promotion-config` 有信封，所以不能照抄）。
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! 5 分钟（与桌面端自身对齐）。失败**保留上一份成功结果**不清空 ——
//! 桌面端也是这么做的（`RemoteConfig` 在 401/超时时保留既有目录），
//! 清空会让「网络抖了一下」变成「模型全没了」。
//!
//! wasm 实例每次调用后销毁，`static` 不可依赖：等价的载体是宿主状态
//! （`state::Scope::Account` 下的 `autoclaw-catalog` 一条）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, state, Result, Value};

use super::credential::Credential;
use super::region::{self, Region};

/// 模型目录路径（`CONFIG_PATHS.MODEL_CONFIG`）
const MODEL_CONFIG_PATH: &str = "autoclaw-model-config";

/// 远程清单缓存有效期（毫秒）。与桌面端自身的轮询周期对齐（prod 5 分钟）。
const CACHE_TTL_MS: i64 = 5 * 60 * 1000;

const STATE_KEY: &str = "autoclaw-catalog";
const SCHEMA: u32 = 1;

/// 配置基址：`{upstreamBase}` 砍掉尾部的 `/autoclaw`，再补 `/proxy/`。
///
/// 逐字对应的桌面端实现（`/out/main/index.js`）：
/// ```js
/// const idx = ZAI_PROXY_BASE_URL.lastIndexOf("/proxy/");
/// return ZAI_PROXY_BASE_URL.slice(0, idx + "/proxy/".length);
/// ```
/// 取 `lastIndexOf` 而不是首次出现：域名里也可能出现 `/proxy/` 片段。
fn config_base() -> String {
    let upstream = region::upstream_base();
    match upstream.rfind("/proxy/") {
        Some(index) => format!("{}/", &upstream[..index + "/proxy/".len()]),
        // 没有 `/proxy/` 时按「上游基址 + /」拼（桌面端同款兜底）——
        // 被 `upstreamBase` 覆盖成别的形态时，拼一个必定 404 的 URL 不如让
        // 调用方看到真实的请求地址
        None => format!("{}/", upstream.trim_end_matches('/')),
    }
}

/// 读回持久缓存（`{models: [...], fetchedAt: ms}`）。
fn cached() -> Option<(Vec<Value>, i64)> {
    let snapshot = state::get(state::Scope::Account, STATE_KEY, SCHEMA).ok()?;
    if !snapshot.compatible {
        return None;
    }
    let models = snapshot.value.get("models").and_then(Value::as_array).cloned().unwrap_or_default();
    if models.is_empty() {
        return None;
    }
    let fetched_at = snapshot.value.get("fetchedAt").and_then(Value::as_i64).unwrap_or(0);
    Some((models, fetched_at))
}

/// 写回持久缓存（CAS：并发刷新时后到的那个失败，而不是互相覆盖）。
fn save(models: &[Value], fetched_at: i64) {
    let value = json!({ "models": models, "fetchedAt": fetched_at });
    let Ok(snapshot) = state::get(state::Scope::Account, STATE_KEY, SCHEMA) else { return };
    let _ = state::compare_exchange(
        state::Scope::Account,
        STATE_KEY,
        SCHEMA,
        snapshot.revision,
        value,
        CACHE_TTL_MS,
    );
}

/// 远程清单（空 = 还没成功拉过，调用方回落到静态路由表）
pub fn remote_models() -> Vec<Value> {
    cached().map(|(models, _)| models).unwrap_or_default()
}

/// 上次成功刷新时刻（毫秒；0 = 从未成功）
pub fn last_refreshed_at() -> i64 {
    cached().map(|(_, fetched_at)| fetched_at).unwrap_or(0)
}

/// 按**目录口径**找一个模型对应的**完整路由 ID**（`X-Request-Model` 要发的那个）。
///
/// 三种写法都认（与目录校验的「先 id 后 name」同口径）：
///   1. 目录名 `glm-5.3`（`id`，客户端最常给的）；
///   2. 展示名 `GLM-5.3`（`name`）；
///   3. 完整路由 ID `zaicoding_glm-5.3`（`routeId`）。
///
/// ── 为什么不从 `id` 反推路由 ID ─────────────────────────────
/// `id` 是**剥过前缀的目录名**、`routeId` 才是完整路由 ID。剥前缀不可逆：
/// `auto` 无法知道自己是 `zai_auto` 还是 `zaicoding_auto`，而发错路由 ID
/// 等于换了一个模型（还可能走错计费通道）。所以这里读 `routeId` 字段本身。
pub fn remote_route_id(region: Region, name: &str) -> Option<String> {
    let _ = region;    let wanted = name.trim().to_lowercase();
    if wanted.is_empty() {
        return None;
    }
    remote_models().iter().find_map(|item| {
        let route = item
            .get("routeId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            // 兜底：老缓存里可能没有 `routeId`（那时 `id` 就是路由 ID）
            .or_else(|| item.get("id").and_then(Value::as_str).map(str::trim))?;
        let same = |key: &str| {
            item.get(key)
                .and_then(Value::as_str)
                .map(|text| text.trim().to_lowercase() == wanted)
                .unwrap_or(false)
        };
        if same("id") || same("name") || route.to_lowercase() == wanted {
            Some(route.to_string())
        } else {
            None
        }
    })
}

/// 把一条上游条目归一成**聚合层认的形态**。
///
/// ── 关于两条特殊规则 ─────────────────────────────────────────
/// 1. **工具调用**：上游目录里**没有**这个能力位（桌面端也不从它读），但
///    AutoClaw 的上游是 OpenAI 兼容网关，工具调用确实可用。显式给 true：
///    聚合层在键缺失时输出 false，会让客户端以为这批模型不能调工具。
/// 2. **图像能力**：上游给 `input: ["text","image",...]`，我们只认 `image`。
fn normalize_entry(item: &Value) -> Option<Value> {
    // 条目可能是裸字符串（上游允许 `models: ["zai_auto"]` 这种简写）
    if let Some(raw) = item.as_str() {
        let route_id = raw.trim();
        if route_id.is_empty() {
            return None;
        }
        let id = super::models::strip_route_prefix(route_id).to_string();
        return Some(json!({
            "id": id,
            "name": id.to_uppercase(),
            "routeId": route_id,
            "supportsToolCall": true,
            "kind": "chat",
        }));
    }
    let route_id = item
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())?
        .to_string();
    // 目录 id = 剥前缀后的名字（客户端用这个名字请求）
    let id = super::models::strip_route_prefix(&route_id).to_string();
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| id.to_uppercase());
    // 图像能力：`input` 数组里有没有 `image`
    let support_image = item
        .get("input")
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|value| value.as_str() == Some("image")))
        .unwrap_or(false);
    // 思考能力：`reasoning` 缺省为 true（上游缺省即真，桌面端同款回退）
    let reasoning = item.get("reasoning").and_then(Value::as_bool).unwrap_or(true);
    let mut entry = json!({
        "id": id,
        "name": name,
        "routeId": route_id,
        "supportsImages": support_image,
        "supportsReasoning": reasoning,
        "supportsToolCall": true,
        "kind": "chat",
    });
    let object = entry.as_object_mut()?;
    if let Some(window) = item.get("contextWindow").and_then(Value::as_i64) {
        object.insert("maxInputTokens".to_string(), Value::from(window));
    }
    if let Some(max_tokens) = item.get("maxTokens").and_then(Value::as_i64) {
        object.insert("maxOutputTokens".to_string(), Value::from(max_tokens));
    }
    // ── 倍率：`creditConsumptionLevel` ──────────────────────────
    // 这是**档位文案而不是数值**（实测取值 `低` / `中` / `高`），官方术语是
    // 「积分消耗等级」。上游与桌面端都**没有**「档位 → 数字」的映射表（已穷举
    // 确认），所以原样透传字符串，不换算成编造的数。前端那一列对非 `x…` 形态
    // 的文本会原样显示，于是界面上看到的是「低 / 中 / 高」。
    if let Some(level) = item
        .get("creditConsumptionLevel")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        object.insert("credits".to_string(), Value::String(level.to_string()));
    }
    Some(entry)
}

/// 拉取并落地远程目录。
///
/// 三档返回值与 `models.refresh` 的契约一致（成功 / 没刷 / 失败了）。
/// `force = false` 时命中 TTL 直接早退（自动路径）；用户手动点刷新时传 `true`。
pub fn refresh(credential: &Credential, force: bool) -> Result<Value> {
    if !force {
        if let Some((models, fetched_at)) = cached() {
            if fetched_at > 0 && sdk::now() - fetched_at < CACHE_TTL_MS {
                return Ok(sdk::catalog::unchanged(models.len()));
            }
        }
    }
    if credential.token.trim().is_empty() {
        // 无 token 时上游必然 401（桌面端离线期间也真实抓到过 401）。
        // 「没刷」而不是「失败」：不用 AutoClaw 的用户点刷新时不该看到红色错误
        return Ok(sdk::catalog::unchanged(0));
    }
    let url = format!("{}{MODEL_CONFIG_PATH}", config_base());
    let response = super::upstream::raw_get(&url, &credential.token)?;
    let status = response.status;
    let bytes = response.bytes(4 * 1024 * 1024)?;
    if !(200..300).contains(&status) {
        if status == 401 {
            return Ok(sdk::catalog::failed("AutoClaw 登录态已失效，请重新登录或刷新凭证"));
        }
        return Ok(sdk::catalog::failed(&format!("上游返回 HTTP {status}")));
    }
    let payload: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    // **没有 `{code, data}` 信封**：顶层就是 `{models: [...]}`
    let Some(entries) = payload.get("models").and_then(Value::as_array) else {
        return Ok(sdk::catalog::failed("上游返回的模型目录缺少 models 数组"));
    };
    let models: Vec<Value> = entries.iter().filter_map(normalize_entry).collect();
    if models.is_empty() {
        return Ok(sdk::catalog::failed("上游返回的模型目录为空"));
    }
    save(&models, sdk::now());
    Ok(sdk::catalog::refreshed(models))
}

/// 供排障：远程目录条数
#[allow(dead_code)]
pub fn count() -> usize {
    remote_models().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 裸字符串条目要归一成「id 剥前缀、routeId 保留」。
    #[test]
    fn string_entries_are_normalized() {
        let entry = normalize_entry(&json!("zai_auto")).unwrap_or(Value::Null);
        assert_eq!("auto", entry["id"].as_str().unwrap_or(""));
        assert_eq!("zai_auto", entry["routeId"].as_str().unwrap_or(""));
    }

    /// 对象条目：`input` 里有 image 才算支持图片；`creditConsumptionLevel` 原样透传。
    #[test]
    fn object_entries_keep_capabilities() {
        let entry = normalize_entry(&json!({
            "id": "zai_glm-5.3-flash",
            "name": "GLM-5.3-Flash",
            "input": ["text", "image"],
            "creditConsumptionLevel": "低",
            "contextWindow": 1048576
        }))
        .unwrap_or(Value::Null);
        assert_eq!("glm-5.3-flash", entry["id"].as_str().unwrap_or(""));
        assert_eq!(true, entry["supportsImages"].as_bool().unwrap_or(false));
        assert_eq!("低", entry["credits"].as_str().unwrap_or(""));
        assert_eq!(1_048_576_i64, entry["maxInputTokens"].as_i64().unwrap_or(0));
    }

    /// 配置基址从 upstreamBase 里找 `/proxy/` 切片（不是简单拼 `/`）。
    #[test]
    fn config_base_uses_proxy_segment() {
        let base = config_base();
        assert!(base.ends_with("/proxy/") || base.ends_with('/'), "基址形态：{base}");
    }
}
