//! Trae 模型目录与按账号隔离的请求路由缓存。
//!
//! 批量获取 Agent、IDE 与旧 SOLO 通道；批量缺少的表分别补拉。
//! 对外模型和 function / model_name 路由来自同一次解析，刷新失败保留旧清单。
//!
//! ── 缓存放在宿主状态里（迁移时改的）─────────────────────────
//! native 用进程内的 `RwLock<HashMap<uid, Cache>>`；wasm 没有跨调用共享的
//! 内存（宿主可能每次 RPC 新建实例），所以整份目录（含**路由表**）落在
//! `state::Scope::Account` 下。只把模型清单交给 `catalog.v1` 是不够的：
//! 转发要按 function / model_name 选通道，那份数据只在路由表里。

use agent2api_wasm_sdk::{self as sdk, json, state, Result, Value};

use super::account::{self, Credential};
use super::catalog::{self, Catalog, Route, LEGACY_MAX_SUFFIX, LEGACY_SUFFIX, MAX_SUFFIX};
use super::headers::{solo_headers, HeaderIdentity, IDE_VERSION_CODE};
use super::upstream::{
    post_json, BATCH_MODELS_PATH, AGENT_BASE_URL, MODELS_PATH,
};

const CACHE_TTL_MS: i64 = 60 * 60 * 1000;
const STATE_KEY: &str = "catalog";
const SCHEMA: u32 = 1;

/// 一次目录快照：目录、抓取时刻、以及写回时要用的 revision。
#[derive(Clone)]
pub struct Cached {
    pub catalog: Catalog,
    pub fetched_at: i64,
    pub revision: u64,
}

/// 读当前账号的目录快照（没有就 None：没刷过 / 没账号）。
pub fn snapshot() -> Option<Cached> {
    let snapshot = state::get(state::Scope::Account, STATE_KEY, SCHEMA).ok()?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return None;
    }
    Some(Cached {
        catalog: Catalog::from_json(&snapshot.value),
        fetched_at: snapshot.value["fetched_at"].as_i64().unwrap_or(0),
        revision: snapshot.revision,
    })
}

/// 落一份新目录（CAS；并发刷新时后到的那个不覆盖先到的，缓存不值得争）。
fn save(catalog: &Catalog, fetched_at: i64, revision: Option<u64>) {
    let revision = match revision {
        Some(revision) => revision,
        None => match state::get(state::Scope::Account, STATE_KEY, SCHEMA) {
            Ok(snapshot) => snapshot.revision,
            Err(_) => return,
        },
    };
    let _ = state::compare_exchange(
        state::Scope::Account,
        STATE_KEY,
        SCHEMA,
        revision,
        catalog.to_json(fetched_at),
        0,
    );
}

/// `models.list`：当前账号的目录（没刷过时退回宿主目录缓存）。
pub fn list() -> Result<Value> {
    if let Some(cached) = snapshot() {
        if !cached.catalog.models.is_empty() {
            return Ok(json!({
                "models": cached.catalog.models,
                "meta": { "remote": true, "refreshed_at": cached.fetched_at }
            }));
        }
    }
    let mut host = sdk::catalog::cached()?;
    if !host.is_object() {
        host = json!({ "models": [], "meta": { "remote": false, "refreshed_at": 0 } });
    }
    if host.get("meta").is_none_or(Value::is_null) {
        let remote = host["models"].as_array().is_some_and(|models| !models.is_empty());
        host["meta"] = json!({ "remote": remote, "refreshed_at": 0 });
    }
    Ok(host)
}

/// `models.refresh`：真打一次上游目录。
///
/// 「没有账号」不是失败（与 native 同口径）：自动刷新每轮都会走到这里，
/// 把它算成失败会给用户还没配置的家记上一次失败并触发冷却退避。
pub fn refresh(force: bool) -> Result<Value> {
    let record = match account::record() {
        Ok(record) => record,
        Err(_) => return Ok(sdk::catalog::unchanged(0)),
    };
    let credential = account::credential(&record)?;
    if !credential.valid() {
        return Ok(sdk::catalog::unchanged(0));
    }
    if account::is_intl_variant(credential.variant()) {
        return Ok(sdk::catalog::failed(account::INTL_UNSUPPORTED));
    }
    let cached = snapshot();
    if !force {
        if let Some(cached) = &cached {
            if cached.fetched_at > 0 && sdk::now() - cached.fetched_at < CACHE_TTL_MS {
                return Ok(sdk::catalog::unchanged(cached.catalog.models.len()));
            }
        }
    }
    // 目录也认令牌：临期先续期，否则这一发只会拿到 401 的空表
    let credential = account::renew_if_due(&record, &credential)?;
    let fetched = match fetch(&credential) {
        Ok(catalog) => catalog,
        Err(reason) => return Ok(sdk::catalog::failed(&reason)),
    };
    save(&fetched, sdk::now(), cached.as_ref().map(|cached| cached.revision));
    Ok(sdk::catalog::refreshed(fetched.models))
}

/// 转发前取一份可用目录：缓存新鲜就用缓存，否则刷一次；刷新失败保留旧清单。
///
/// native 的 `forward` 也是这个顺序（`models::refresh(..., false)` 后
/// `routes_for`），所以行为一致：目录坏了不影响聊天，只是选错通道的风险由
/// 下面的兜底路由承担。
pub fn ensure(credential: &Credential) -> Option<Cached> {
    let cached = snapshot();
    if let Some(cached) = &cached {
        if !cached.catalog.is_empty() && sdk::now() - cached.fetched_at < CACHE_TTL_MS {
            return Some(cached.clone());
        }
    }
    match fetch(credential) {
        Ok(catalog) => {
            save(&catalog, sdk::now(), cached.as_ref().map(|cached| cached.revision));
            Some(Cached {
                catalog,
                fetched_at: sdk::now(),
                revision: cached.as_ref().map(|cached| cached.revision).unwrap_or(0),
            })
        }
        Err(_) => cached,
    }
}

/// 把历史 `<id>-solo` / `<id>-solo-max` 拆成基名与是否 Max。
/// 调用方必须先按原始 ID 精确查一次：上游真名恰好以 `-solo` 结尾时不能被改写。
pub fn legacy_target(model: &str) -> Option<(&str, bool)> {
    if let Some(base) = strip_suffix(model, LEGACY_MAX_SUFFIX) {
        return Some((base, true));
    }
    strip_suffix(model, LEGACY_SUFFIX).map(|base| (base, false))
}

fn strip_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let cut = name.len().checked_sub(suffix.len())?;
    let base = name.get(..cut)?;
    let tail = name.get(cut..)?;
    tail.eq_ignore_ascii_case(suffix).then_some(base)
}

pub fn routes_for(catalog: &Catalog, model: &str) -> Vec<Route> {
    let name = model.trim().to_lowercase();
    if let Some(routes) = catalog.routes.get(&name) {
        return routes.clone();
    }
    let Some((base, is_max)) = legacy_target(&name) else {
        return Vec::new();
    };
    if is_max {
        // 旧 `<id>-solo-max` 必须走这张表：`routes["<id>-max"]` 可能是另一条
        // 真实上游模型（Max ID 撞名时我们没有广告它）。
        if let Some(routes) = catalog.legacy_max_routes.get(base) {
            return routes.clone();
        }
        return catalog.routes.get(&format!("{base}{MAX_SUFFIX}")).cloned().unwrap_or_default();
    }
    catalog.routes.get(base).cloned().unwrap_or_default()
}

/// 记住"这条通道这次通了"，下次优先试它。
///
/// 目录里同一模型有多条通道，首包前撞 4001/4023 时才会换下一条 —— 把成功的
/// 那条挪到队首能省掉一次必定失败的请求。写不进去（并发刷新改过状态）就算了：
/// 这只是排序优化，不是正确性要求。
pub fn remember_route(model: &str, route: &Route) {
    let Some(cached) = snapshot() else { return };
    let mut catalog = cached.catalog.clone();
    let name = model.trim().to_lowercase();
    let bucket = bucket_mut(&mut catalog, &name);
    let Some(routes) = bucket else { return };
    if let Some(index) = routes.iter().position(|candidate| candidate == route) {
        let route = routes.remove(index);
        routes.insert(0, route);
        save(&catalog, cached.fetched_at, Some(cached.revision));
    }
}

fn bucket_mut<'a>(catalog: &'a mut Catalog, name: &str) -> Option<&'a mut Vec<Route>> {
    if catalog.routes.contains_key(name) {
        return catalog.routes.get_mut(name);
    }
    let (base, is_max) = legacy_target(name)?;
    if is_max {
        if catalog.legacy_max_routes.contains_key(base) {
            return catalog.legacy_max_routes.get_mut(base);
        }
        let max = format!("{base}{MAX_SUFFIX}");
        return catalog.routes.get_mut(&max);
    }
    catalog.routes.get_mut(base)
}

pub fn catalog_body(function: &str) -> Value {
    json!({
        "function": function,
        "config_names": Value::Null,
        "need_prompt": false,
        "current_config_info": Value::Null,
        "poly_prompt": true,
        "mode_type": Value::Null,
        "agent_type": Value::Null,
    })
}

pub fn batch_catalog_body() -> Value {
    json!({
        "functions": catalog::CHAT_FUNCTIONS,
        "agent_type": "",
        "current_config_info": { "config_name": "", "is_custom_model": false },
        "mode_type": 0,
        "access_type": 0,
        "ab_force_vids": "",
        "ab_autotest_advanced_mode": 0,
        "show_custom_model": true,
    })
}

/// 拉一次目录（批量优先，缺的 function 单独补）。
fn fetch(credential: &Credential) -> std::result::Result<Catalog, String> {
    let identity = HeaderIdentity {
        access_token: credential.access_token.trim(),
        uid: credential.uid.trim(),
        machine_id: credential.machine_id.trim(),
        device_id: credential.device_id.trim(),
    };
    let headers = solo_headers(&identity, false);
    let mut reasons: Vec<String> = Vec::new();
    let mut groups = match request_catalog(BATCH_MODELS_PATH, &batch_catalog_body(), "批量目录", &headers) {
        Ok(payload) => catalog::function_groups(&payload),
        Err((true, reason)) => return Err(reason),
        Err((false, reason)) => {
            reasons.push(reason);
            Vec::new()
        }
    };
    let listed: std::collections::HashSet<String> = groups
        .iter()
        .filter_map(|group| group.get("function").and_then(Value::as_str).map(str::to_string))
        .collect();
    let missing: Vec<&str> = catalog::CHAT_FUNCTIONS
        .into_iter()
        .filter(|function| !listed.contains(*function))
        .collect();
    for function in missing {
        let body = catalog_body(function);
        match request_catalog(MODELS_PATH, &body, &format!("目录 {function}"), &headers) {
            Ok(payload) => match catalog::single_entries(&payload) {
                Some(entries) => groups.push(json!({ "function": function, "config_info_list": entries })),
                None => reasons.push(format!("目录 {function} 缺少 config_info_list")),
            },
            Err((true, reason)) => return Err(reason),
            Err((false, reason)) => reasons.push(reason),
        }
    }
    let parsed = catalog::parse(&groups);
    if !parsed.models.is_empty() {
        return Ok(parsed);
    }
    reasons.push(format!("各聊天通道均没有可选模型（IdeVersionCode={IDE_VERSION_CODE}）"));
    Err(format!("未取到模型目录：{}", reasons.join("；")))
}

/// 一次目录请求。`Err((true, _))` = 凭据/限流级失败（该整体放弃），
/// `Err((false, _))` = 这一张表没拿到（继续补下一张）。
fn request_catalog(
    path: &str,
    body: &Value,
    which: &str,
    headers: &[(String, String)],
) -> std::result::Result<Value, (bool, String)> {
    let url = format!("{AGENT_BASE_URL}{path}");
    let reply = post_json(&url, body, headers)
        .map_err(|error| (false, format!("{which}请求失败：{}", error.message)))?;
    if reply.status >= 300 {
        return Err((
            matches!(reply.status, 401 | 403 | 429),
            describe_failure(which, reply.status, &reply.body),
        ));
    }
    let payload = reply.json().ok_or_else(|| (false, format!("{which}响应不是合法 JSON")))?;
    let error = payload.get("error").filter(|value| value.is_object()).unwrap_or(&payload);
    let code = error
        .get("code")
        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())))
        .unwrap_or(0);
    if code != 0 {
        let (_, message) = super::errors::error_event_fields(error);
        return Err((
            matches!(code, 1001 | 401 | 20101),
            format!("{which}业务错误 {code}：{message}"),
        ));
    }
    Ok(payload)
}

fn describe_failure(which: &str, status: u16, body: &str) -> String {
    let head: String = body.chars().take(120).collect();
    match status {
        401 | 403 => format!("{which} HTTP {status}（凭据可能已失效，请重新登录该账号）"),
        _ if head.is_empty() => format!("{which} HTTP {status}"),
        _ => format!("{which} HTTP {status}：{head}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_names_are_only_compat() {
        assert_eq!(legacy_target("glm-5.2-solo"), Some(("glm-5.2", false)));
        assert_eq!(legacy_target("glm-5.2-solo-max"), Some(("glm-5.2", true)));
        // 裸 `-max` 是上游真名的一部分，不能被当成历史后缀
        assert_eq!(legacy_target("glm-5.2-max"), None);
        assert_eq!(legacy_target("glm-5.2"), None);
    }

    #[test]
    fn routes_resolve_by_legacy_name() {
        let mut catalog = Catalog::default();
        catalog.routes.insert(
            "glm-5.2".to_string(),
            vec![Route::fallback("glm-5.2", "chat_v3")],
        );
        // 精确名字优先
        assert_eq!(routes_for(&catalog, "GLM-5.2").len(), 1);
        // 历史 `<id>-solo` 解析回基础名
        assert_eq!(routes_for(&catalog, "glm-5.2-solo").len(), 1);
        // 旧 `<id>-solo-max` 在目录里没有 Max 路由时给空（不能悄悄降级成基础档）
        assert!(routes_for(&catalog, "glm-5.2-solo-max").is_empty());
    }
}
