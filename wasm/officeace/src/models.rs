//! OfficeAce 模型目录：`GET {网关}/v1/models`（OpenAI 格式）+ 会话级缓存。
//!
//! ── 上游形态（依据：officeace2api 的 `server.mjs` 用同一凭据打
//! `{baseUrl}/models`；桌面端 `models.json` 里每条也带 `model_name`）──
//! 标准 OpenAI `{data:[{id, object, created, owned_by}]}`。**只要网关 Basic
//! 凭据**，不需要控制面签名（那套只服务额度/签到）。
//!
//! ── 实测口径：目录 ≠ 可用，而且目录 ≠ 官方展示 ─────────────────
//! officeace2api 实测：上游目录 34 个名，两个号实际只有 11 个能用，其余回
//! `81004`（没权限）/ `81009`（名字不认）。
//!
//! 但比「可用性」更要紧的一层是**官方客户端到底列哪些**：OfficeAce 桌面端
//! 把 `/v2/models` 的完整目录按一张硬编码白名单收窄后才渲染（依据见
//! [`OFFICIAL_WHITELIST`]）。实测这条通道上目录有 26 条、官方界面只列 5~6 条
//! —— 差额全是 `kimi-k3-test-1009` / `glm-5.2-zx` / `openpangu-2.0-pro` /
//! `deepseek-v4.1-flash-bnt` 这类内部灰度名。
//!
//! 本模块**按官方白名单收窄**（[`apply_whitelist`]）。这与「目录照收」是相反
//! 的取舍，理由：用户看到的是「这家官方客户端能用的模型」，把上游的内部实验
//! 名一并广告出去只会让人逐个试错（本仓的 `fatal` 分类不换家，一次点名到无
//! 权限模型就直接把上游错误透传给客户端）。白名单之外的名字**仍然点名可用**
//! —— 过滤只作用于清单，不改转发闸门。
//!
//! 白名单的代价是**要跟着上游改**：官方客户端每次发版都可能增删这几个名字。
//! 因此留了一条兜底：白名单一条都匹配不上时回落到完整目录并留痕（见
//! [`apply_whitelist`]）—— 上游整体换血时宁可多列几个，也不能把清单清空。
//!
//! ── 缓存放哪 ────────────────────────────────────────────────
//! native 用进程内一格（10 分钟 TTL）。插件换成宿主的 `session.put`（同一 TTL）：
//! 插件实例可能被换掉，静态变量会跟着消失 —— 表现是「刚刷完又变成空清单」。
//! **不落盘到账号记录**：目录缓存归网关（它拿 `models.refresh` 的返回值自己按
//! provider id 持久化）。
//!
//! ── 探测没迁过来（这条要写在明处）─────────────────────────
//! native 的 `probe.rs` 会在刷新后起一轮后台探测（`81004` 的模型隐藏、`81009`
//! 的标记 `upstreamStatus: undeployed`），它依赖 `tokio::spawn` 与
//! `notify_models_changed` 两个 **native 专有**能力 —— wasm 插件里没有后台任务
//! （实例用完即走），也没有「通知网关重读目录」的入口。所以本包只做白名单收窄，
//! 不做逐模型探测；要恢复那层结论得等宿主提供后台任务能力。

use agent2api_wasm_sdk::{http, json, Result, Value};

use super::credentials::OfficeAceCredential;
use super::{chat, subscription, util};

/// 自动路径的缓存 TTL（与各家同档）。
const TTL_MS: i64 = 10 * 60 * 1000;
/// 目录缓存键。
const CACHE_KEY: &str = "officeace.catalog";
/// 倍率读数缓存键（另一条链，寿命与目录不同）。
const RATES_KEY: &str = "officeace.rates";

/// 官方客户端展示的模型白名单（`id` 小写；比对时也按小写）。
///
/// ── 依据 ────────────────────────────────────────────────────
/// OfficeAce 桌面端 `packages/api/dist/chunk-UEENO6BL.js`（39.8.7 实测）里
/// 的 model-selection candidates 那条链：拉完 `/v2/models` 后逐条比对
/// `Ct = new Set(["GLM-5","GLM-5.1","GLM-5.2","GLM-5.3",
/// "DeepSeek-V4-Flash-0731","DeepSeek-V4.1-Flash"])`，不在集合里的直接丢。
/// 同一文件里还有两张小表：
///   · 三个 batch 名无条件剔除（本白名单天然不含它们，无需另写）；
///   · `-zx` 后缀在比对前剥掉，即 `glm-5.2-zx` 会按 `glm-5.2` 命中。
///     本模块照这个口径实现（见 [`canonical_id`]）。
///
/// ── 为什么是「名字」而不是「能力」──────────────────────────
/// 这张表是**官方产品的展示决策**，不是上游能力声明：`kimi-k3.1-pro` 很可能
/// 真的能打，只是官方客户端没打算让用户选它。所以这里只过滤清单，不做门禁。
const OFFICIAL_WHITELIST: &[&str] = &[
    "glm-5",
    "glm-5.1",
    "glm-5.2",
    "glm-5.3",
    "deepseek-v4-flash-0731",
    "deepseek-v4.1-flash",
];

/// 白名单的规范形态：剥掉 `-zx` 后缀（官方客户端 `_t()` 的同一处理）。
///
/// ── 为什么剥掉后缀之后要**真的改名**（而不是只用于比对）──────
/// 官方客户端 `_t()` 返回的是剥掉后缀的名字，`Et()` 直接把它当 `model` 用，
/// 随后还以这个名字为 key 做去重 —— 也就是 `glm-5.2-zx` 在官方眼里**就是**
/// `glm-5.2`，两者合并成一条。
///
/// 这个处理有独立的实测支撑：native 2026-10-23 的探测记录里，`glm-5.2-zx` 与
/// `glm-5.3-zx` 都被上游判成「模型级拒绝」（81004/81009），而同名的 `glm-5.2` /
/// `glm-5.3` 正常可用。也就是说 `-zx` 这个名字很可能上游不认 —— 只比对不改名会把
/// 一条打不通的名字广告出去。
///
/// 别的后缀（`-bnt` / `-harmony` / `-0930` / `-1017`）**不剥**：官方实现里只有
/// `-zx` 一个特判，其余是独立变体，归并会让两个不同的上游模型撞成一条。
fn canonical_id(id: &str) -> &str {
    let trimmed = id.trim();
    match trimmed.len().checked_sub(3) {
        Some(cut) if trimmed.to_ascii_lowercase().ends_with("-zx") => &trimmed[..cut],
        _ => trimmed,
    }
}

/// 按官方白名单收窄目录，并把 `-zx` 归并到主名。
///
/// ── 一条兜底：一条都匹配不上时**原样返回** ──────────────────
/// 白名单是外部事实（官方客户端的硬编码），上游换血时它会整体失效。那种情况下
/// 如果照白名单过滤，清单会变成空的 —— 而「这家一个模型都没有」在界面上与
/// 「插件坏了」无法区分。所以命中 0 条时退回完整目录（排查时能看出「白名单该
/// 更新了」，而不是以为上游真没模型）。
///
/// ── 去重顺序：主名优先 ──────────────────────────────────────
/// `glm-5.2` 与 `glm-5.2-zx` 归并后是同一条。目录里两者都在时保留**不带后缀**
/// 的那条（它带的是上游对外的正式字段）；只有 `-zx` 时就用归并后的主名顶上。
pub fn apply_whitelist(models: Vec<Value>) -> Vec<Value> {
    // 归并后的清单：(小写主名, 这条是不是 `-zx` 变体, 条目)。
    // 第三个字段单独记「来源是变体」—— 变体在下面会被改名成主名，改完之后
    // 光看 id 已经分不出它原本是 `glm-5.2` 还是 `glm-5.2-zx` 了。
    let mut kept: Vec<(String, bool, Value)> = Vec::new();
    for entry in models.iter() {
        let mut model = entry.clone();
        let id = model.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let canonical = canonical_id(&id).to_string();
        let key = canonical.to_ascii_lowercase();
        if !OFFICIAL_WHITELIST.iter().any(|name| *name == key) {
            continue;
        }
        let is_variant = canonical != id;
        if is_variant {
            // `-zx` 变体：改名到主名（见 `canonical_id` 的说明）。上游不认这个
            // 后缀名（实测回 81004/81009），广告出去只会让用户点到打不通的名字。
            if let Some(object) = model.as_object_mut() {
                object.insert("id".to_string(), Value::String(canonical.clone()));
                object.insert("name".to_string(), Value::String(canonical.clone()));
            }
        }
        match kept.iter().position(|(existing, _, _)| *existing == key) {
            // 已有同名条目：只有「已存的是变体、当前是主名」才顶替，其余丢掉。
            Some(index) => {
                if kept[index].1 && !is_variant {
                    kept[index] = (key, false, model);
                }
            }
            None => kept.push((key, is_variant, model)),
        }
    }
    if kept.is_empty() {
        return models;
    }
    kept.into_iter().map(|(_, _, model)| model).collect()
}

/// 把一个上游条目映成目录条目（保留上游给的字段，缺的补空）。
fn map_entry(entry: &Value) -> Option<Value> {
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if id.is_empty() {
        return None;
    }
    let mut out = json!({
        "name": id,
        "display_name": entry.get("display_name").and_then(Value::as_str).unwrap_or(id),
        "description": "",
        "context_length": entry.get("context_window").and_then(Value::as_i64).unwrap_or(0),
        // 目录不给输出上限（officeace2api 的 `/v1/models` 也没这个字段）；
        // 留 0 = 「未声明」，界面显示 `—`，不编造。
        "max_output_tokens": 0,
        "credit_display": "",
        "id": id,
    });
    if let Some(object) = out.as_object_mut() {
        // `owned_by` 原样透传（我们的目录形状里叫 `owned_by` 的不多，留着不碍事）
        if let Some(owner) = entry.get("owned_by").and_then(Value::as_str) {
            object.insert("owned_by".to_string(), Value::String(owner.to_string()));
        }
        // 能力位：上游这条链**不报**（officeace2api 的目录也不带 vision/tool 位），
        // 所以不写 `supportsImages` —— 缺席 = 「不知道」，闸门据此不拦。
        if let Some(developer) = entry.get("developer").and_then(Value::as_str) {
            object.insert("developer".to_string(), Value::String(developer.to_string()));
        }
    }
    Some(out)
}

/// 解析 `{data:[…]}` 或裸数组。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let rows = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

// ── 缓存 ─────────────────────────────────────────────────────

/// 缓存里的一份目录。
struct Cached {
    models: Vec<Value>,
    fetched_at: i64,
}

fn cached() -> Option<Cached> {
    let value = agent2api_wasm_sdk::session_get(CACHE_KEY).ok()?;
    let models = value.get("models").and_then(Value::as_array)?.clone();
    if models.is_empty() {
        return None;
    }
    let fetched_at = value.get("fetched_at").and_then(Value::as_i64).unwrap_or(0);
    Some(Cached { models, fetched_at })
}

fn store(models: &[Value], fetched_at: i64) {
    let payload = json!({ "models": models, "fetched_at": fetched_at });
    // 缓存是加速手段：写不进去只影响下一次要重拉，不影响本次结果
    let _ = agent2api_wasm_sdk::session_put(CACHE_KEY, payload, TTL_MS);
}

/// 每模型倍率的**最后一份非空读数**（`model_name` 小写 → `cost_coefficient`）。
///
/// 为什么要单独留一份，而不是「每次刷新都现取」：倍率走的是控制面那条 V11 签名链
/// （临时 AK/SK，约 2 小时过期），而模型目录走的是**不过期**的网关 Basic —— 两条
/// 链寿命不同。一过期就「取不到 ⇒ 清空」，会让已经有读数的列变成一片 `—`，看起来
/// 像「上游不给倍率」，而真实情况只是我们手上那把临时凭据到期了。宁可旧一点也不假空。
fn remembered_rates() -> Vec<(String, f64)> {
    agent2api_wasm_sdk::session_get(RATES_KEY)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let name = row.get("name").and_then(Value::as_str)?.to_string();
                    let value = row.get("rate").and_then(Value::as_f64)?;
                    Some((name, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 记下这份新读数并返回「本次该用哪一份」：**空表不许把已有读数抹掉**
/// （上游整个挂了与真的没有倍率，回的都是空数组，分不清就不该当"没有"处理）。
fn remember_rates(rows: Vec<(String, f64)>) -> Vec<(String, f64)> {
    if rows.is_empty() {
        return remembered_rates();
    }
    let payload = Value::Array(
        rows.iter()
            .map(|(name, rate)| json!({ "name": name, "rate": rate }))
            .collect(),
    );
    let _ = agent2api_wasm_sdk::session_put(RATES_KEY, payload, TTL_MS);
    rows
}

// ── 对外 ─────────────────────────────────────────────────────

/// 当前清单（`models.list` 的实现）。
pub fn list() -> Value {
    match cached() {
        Some(catalog) => json!({
            "models": catalog.models,
            "meta": { "remote": true, "refreshed_at": catalog.fetched_at },
        }),
        // 没刷过就是空清单：上层据此报「账号没有可用模型」。
        // **绝不**塞静态兜底（那会广告出一批"列出来但一调就 400"的幽灵模型）。
        None => json!({ "models": [], "meta": { "remote": false, "refreshed_at": 0 } }),
    }
}

/// 拉一次模型目录（`models.refresh` 的实现）。
pub fn refresh(force: bool) -> Result<Value> {
    if !force {
        if let Some(catalog) = cached() {
            let age = util::now_ms().saturating_sub(catalog.fetched_at);
            if age >= 0 && age < TTL_MS {
                return Ok(json!({ "refreshed": false, "count": catalog.models.len() }));
            }
        }
    }
    let (_, credential) = super::credentials::current()?;
    fetch(&credential)
}

/// 从凭证拉目录：解析 → 白名单收窄 → 合并倍率 → 落缓存。
fn fetch(credential: &OfficeAceCredential) -> Result<Value> {
    let url = format!("{}/models", chat::normalize_base(&credential.base_url));
    if url == "/models" {
        return Ok(json!({ "refreshed": false, "message": "OfficeAce 账号缺少模型网关基址" }));
    }
    let mut headers = serde_json::Map::new();
    headers.insert(
        "Authorization".to_string(),
        Value::String(chat::basic_authorization(
            &credential.model_app_key,
            &credential.model_app_secret,
        )),
    );
    headers.insert("Accept".to_string(), Value::String("application/json".to_string()));
    let response = match http::open("GET", &url, Value::Object(headers), None) {
        Ok(response) => response,
        Err(error) => {
            return Ok(json!({
                "refreshed": false,
                "message": format!(
                    "OfficeAce 模型目录查询失败：{}（如果是网络域被拒，检查本包 wasm.json 的 \
                     origins 是否覆盖账号的网关域名）",
                    error.message
                ),
            }))
        }
    };
    let status = response.status;
    if !(200..300).contains(&status) {
        return Ok(json!({
            "refreshed": false,
            "message": format!("OfficeAce 模型目录返回 HTTP {status}（网关不接受这条凭据？）"),
        }));
    }
    let payload = match response.json() {
        Ok(payload) => payload,
        Err(error) => {
            return Ok(json!({
                "refreshed": false,
                "message": format!("OfficeAce 模型目录不是有效 JSON：{}", error.message),
            }))
        }
    };
    let models = parse_models(&payload);
    if models.is_empty() {
        return Ok(json!({
            "refreshed": false,
            "message": "OfficeAce 模型目录为空或格式不认识（保留现有清单）",
        }));
    }
    // 按官方客户端那张白名单收窄（见 `apply_whitelist`）。收窄在**倍率合并之前**
    // 做：倍率表是另一条链给的，两边的集合本来就对不齐，先收窄能少算一轮无关条目。
    let models = apply_whitelist(models);
    // 倍率：另一条链（控制面签名），失败就沿用最后一份读数，别抹空（见 `remembered_rates`）
    let rates = match subscription::fetch_model_token_rates(credential) {
        Ok(payload) => remember_rates(subscription::parse_rates(&payload)),
        Err(_) => remembered_rates(),
    };
    let models = subscription::attach_rates(models, &rates);
    let count = models.len();
    let fetched_at = util::now_ms();
    store(&models, fetched_at);
    Ok(json!({
        "refreshed": true,
        "count": count,
        "models": models,
        "meta": { "remote": true, "refreshed_at": fetched_at },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_id_strips_only_the_zx_suffix() {
        assert_eq!(canonical_id("glm-5.2-zx"), "glm-5.2");
        assert_eq!(canonical_id("GLM-5.2-ZX"), "GLM-5.2");
        assert_eq!(canonical_id("glm-5.2-bnt"), "glm-5.2-bnt");
        assert_eq!(canonical_id("deepseek-v4.1-flash"), "deepseek-v4.1-flash");
        // 只剩后缀时剥成空串 —— 与 native 的 `checked_sub(3)` 口径逐字一致
        // （现实里不会出现：上游 id 至少 4 个字符，而且它也不在白名单里）
        assert_eq!(canonical_id("-zx"), "");
    }

    #[test]
    fn whitelist_keeps_the_official_six() {
        let models = vec![
            json!({ "id": "GLM-5", "name": "GLM-5" }),
            json!({ "id": "glm-5.2-zx", "name": "glm-5.2-zx" }),
            json!({ "id": "kimi-k3-test-1009", "name": "kimi-k3-test-1009" }),
            json!({ "id": "DeepSeek-V4.1-Flash", "name": "DeepSeek-V4.1-Flash" }),
        ];
        let kept = apply_whitelist(models);
        let ids: Vec<&str> = kept.iter().filter_map(|model| model["id"].as_str()).collect();
        assert_eq!(ids, vec!["GLM-5", "glm-5.2", "DeepSeek-V4.1-Flash"]);
    }

    #[test]
    fn whitelist_falls_back_to_the_full_catalog() {
        // 一条都不命中 ⇒ 原样返回（空清单在界面上与"插件坏了"无法区分）
        let models = vec![
            json!({ "id": "some-new-model", "name": "some-new-model" }),
            json!({ "id": "another", "name": "another" }),
        ];
        let kept = apply_whitelist(models.clone());
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn main_name_wins_over_the_variant() {
        let models = vec![
            json!({ "id": "glm-5.3-zx", "name": "glm-5.3-zx" }),
            json!({ "id": "glm-5.3", "name": "glm-5.3" }),
        ];
        let kept = apply_whitelist(models);
        assert_eq!(kept.len(), 1, "同名主名与变体只保留一条");
        assert_eq!(kept[0]["id"], json!("glm-5.3"));
        // 顺序反过来结论不变（主名后到也要顶替变体）
        let models = vec![
            json!({ "id": "glm-5.3", "name": "glm-5.3" }),
            json!({ "id": "glm-5.3-zx", "name": "glm-5.3-zx" }),
        ];
        let kept = apply_whitelist(models);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["id"], json!("glm-5.3"));
    }

    #[test]
    fn parse_models_accepts_data_and_bare_arrays() {
        let wrapped = json!({ "data": [
            { "id": "GLM-5", "owned_by": "officeace", "context_window": 128000 },
            { "id": "  " },
        ] });
        let entries = parse_models(&wrapped);
        assert_eq!(entries.len(), 1, "空 id 的条目丢掉");
        assert_eq!(entries[0]["id"], json!("GLM-5"));
        assert_eq!(entries[0]["owned_by"], json!("officeace"));
        assert_eq!(entries[0]["context_length"], json!(128000));
        let bare = json!([{ "id": "A" }]);
        assert_eq!(parse_models(&bare).len(), 1);
        assert!(parse_models(&json!({})).is_empty());
    }
}
