//! 模型目录：公共配置（`/v3/config`）与企业目录分别读取、合并；企业结果只授权
//! 当前账号。
//!
//! 合并自 native 的 `catalog.rs` + `catalog_state.rs` + `catalog_access.rs`。
//!
//! ── 目录缓存归宿主（与 native 的结构差异）────────────────────
//! native 侧插件自己拿一把 `Mutex<Option<ModelList>>` 存远程清单，并把它写进
//! 设置项 `modelCatalog` 做重启恢复。wasm 实例不保证跨调用存活，插件里存不住
//! 任何东西；而网关本来就会把 `models.list` 的应答落库（它有 `catalog.v1`）。
//! 所以这里的「当前清单」= 宿主的 `catalog.get`，插件只负责**拉取 + 归一**，
//! 刷新结果经 `catalog.refreshed(..)` 交回宿主。
//!
//! ── 企业授权为什么还要一份台账 ──────────────────────────────
//! 企业账号的模型清单只授权**它自己**：把企业条目并进公共目录会让个人账号看到
//! 并尝试调用它们（上游会 403，且排查起来像是「目录坏了」）。台账里除了清单还
//! 存了**当时的账号身份**（`authority`）：身份一变（换企业、换账号类型、换域名）
//! 旧清单立即作废，不能用「同名的另一个人」的授权去发请求。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use crate::builtin;
use crate::httpio;
use crate::outbound;
use crate::reasoning;
use crate::util;

/// 企业模型权限台账的 kind（宿主 `ledger.get` / `ledger.put`）。
const LEDGER: &str = "workbuddy-model-permissions";
/// 企业目录的信任期（30 分钟，与 native 同值）。
const TTL_MS: i64 = 30 * 60_000;
/// 请求上限（给宿主的提示，实际超时由宿主决定）。
const NO_SESSION: &str = "缺少登录态，使用内置模型目录";

/// 目录条目的展示处理：补思考档位三件（`reasoning::annotate`）。
fn decorate(mut models: Vec<Value>) -> Vec<Value> {
    for model in &mut models {
        reasoning::annotate(model);
    }
    models
}

/// 当前清单（`models.list`）。
///
/// 返回形态与 native 的 `proto::ModelList` 一致：`{models, meta}`
/// （`meta.remote` 表示这份清单是不是真拉过上游，`meta.refreshed_at` 是上次成功
/// 刷新的毫秒时刻，从未成功过为 0）。
pub fn list() -> Value {
    let catalog = sdk::catalog::cached().unwrap_or(Value::Null);
    let remote: Vec<Value> = catalog
        .get("models")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if remote.is_empty() {
        // 宿主还没有目录（冷启动）→ 内置清单，并如实标注 remote: false
        return json!({
            "models": decorate(builtin::builtin_filtered()),
            "meta": { "remote": false, "refreshed_at": 0 },
        });
    }
    let meta = if catalog.get("meta").is_some_and(Value::is_object) {
        catalog["meta"].clone()
    } else {
        json!({ "remote": true, "refreshed_at": 0 })
    };
    json!({ "models": decorate(remote), "meta": meta })
}

/// 按 id 找一条目录条目（大小写不敏感）。
pub fn model(id: &str) -> Option<Value> {
    list()["models"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|model| {
            model
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(id))
        })
        .cloned()
}

/// 刷新当前地区的模型目录（`GET /v3/config` 的 `data.models`）。
///
/// ── `force` 对本家无差别（有意）─────────────────────────────
/// workbuddy 的 `/v3/config` 拉取**没有缓存/TTL 早退**：每次调用都真打上游。
/// 因此 `force` 的「绕过缓存」语义在本家无事可绕 —— 自动路径与手动路径的行为
/// 逐字相同，直接忽略该参数（加了本地节流反而会让用户按下按钮后拿到一份没动的
/// 清单，那正是给 `force` 存在的理由）。
///
/// `force` 保留在签名里只是为了方法契约一致。
pub fn refresh(_force: bool) -> Result<Value> {
    let record = sdk::account()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    if !secret.is_object() {
        return Ok(sdk::catalog::failed(NO_SESSION));
    }
    let session = outbound::session_of_record(&secret);
    match refresh_session(&session) {
        Ok(models) => Ok(sdk::catalog::refreshed(decorate(models))),
        // 本家没有「TTL 跳过」这一档：没刷就是真没拿到（网络 / 空清单 /
        // 没有登录态），全部如实报成失败原因，界面据此显示「为什么没变」
        Err(reason) => Ok(sdk::catalog::failed(&reason)),
    }
}

/// 拉一次目录并交给宿主（企业账号额外拉企业目录）。
fn refresh_session(session: &Value) -> std::result::Result<Vec<Value>, String> {
    let base = outbound::session_endpoint_of(session);
    let headers = crate::contract::framework_headers(session, true);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        return Err(NO_SESSION.to_string());
    }
    let enterprise = enterprise(session);
    // native 用 `tokio::join!` 并发拉公共 / 企业两份；wasm 侧 SDK 是同步 http，
    // 只能顺序拉 —— 相差一次往返（企业账号才多这一趟），结果合并规则不变。
    let mut failures: Vec<String> = Vec::new();
    let mut models: Vec<Value> = Vec::new();
    let mut complete = true;
    match fetch(&format!("{base}/v3/config"), &headers, false) {
        Ok(rows) => models.extend(rows),
        Err(reason) => {
            complete = false;
            failures.push(reason);
        }
    }
    if enterprise {
        let id = session
            .pointer("/account/enterpriseId")
            .and_then(Value::as_str)
            .unwrap_or("");
        let encoded = util::encode_component(id);
        let url = format!("{base}/console/enterprises/{encoded}/config/models");
        match fetch(&url, &headers, true) {
            Ok(rows) => {
                let mut seen: Vec<String> = models
                    .iter()
                    .filter_map(|row| row.get("id").and_then(Value::as_str))
                    .map(str::to_ascii_lowercase)
                    .collect();
                for row in rows {
                    let id = row
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if !id.is_empty() && !seen.contains(&id) {
                        seen.push(id);
                        models.push(row);
                    }
                }
            }
            Err(reason) => {
                complete = false;
                failures.push(reason);
            }
        }
    }
    if models.is_empty() && !complete {
        return Err(if failures.is_empty() {
            "模型目录没有可用对话模型".into()
        } else {
            failures.join("；")
        });
    }
    if let Err(error) = save(session, &models, complete) {
        return Err(error.message);
    }
    Ok(models)
}

/// 拉一份目录（`enterprise = true` 时是企业条目）。
fn fetch(
    url: &str,
    headers: &[(String, String)],
    enterprise: bool,
) -> std::result::Result<Vec<Value>, String> {
    let response = httpio::send("GET", url, headers, None)
        .map_err(|error| httpio::transport_error("模型目录请求", error).message)?;
    let payload = response
        .payload
        .clone()
        .ok_or_else(|| "模型目录不是合法 JSON".to_string())?;
    if !response.ok
        || payload.get("code").is_some_and(|code| {
            code.as_i64()
                .or_else(|| code.as_str().and_then(|code| code.parse().ok()))
                .is_some_and(|code| code != 0)
        })
    {
        return Err(format!("模型目录请求失败（HTTP {}）", response.status));
    }
    let raw = if enterprise {
        payload.get("data")
    } else {
        payload.pointer("/data/models")
    }
    .and_then(Value::as_array)
    .ok_or_else(|| "模型目录缺少模型数组".to_string())?;
    let picker = if enterprise {
        None
    } else {
        picker_model_ids(&payload)
    };
    let allowed: Vec<Value> = raw
        .iter()
        .filter(|model| model.get("disabled").and_then(Value::as_bool) != Some(true))
        .filter(|model| {
            if !enterprise {
                return true;
            }
            // 企业目录只授权带 `chat` 标签的条目（图像条目在本包不申报能力，
            // 因此这里也只放行对话条目）
            model
                .get("tags")
                .and_then(Value::as_array)
                .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some("chat")))
        })
        .cloned()
        .collect();
    let mut models: Vec<Value> = builtin::apply_filters(allowed)
        .into_iter()
        .map(|mut model| {
            let id = model
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let auto = id.eq_ignore_ascii_case("auto");
            model["isDefault"] = json!(auto);
            model["modelType"] = json!(if auto {
                "auto"
            } else if enterprise {
                "custom"
            } else {
                "built-in"
            });
            if let Some(picker) = &picker {
                model["visibility"] = json!(if picker.iter().any(|name| name.eq_ignore_ascii_case(&id))
                {
                    "shown"
                } else {
                    "hidden"
                });
            }
            model
        })
        .collect();
    models.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(right.get("id").and_then(Value::as_str).unwrap_or(""))
    });
    Ok(models)
}

/// `/v3/config` 里官方客户端「模型选择器」可见的那一批 id。
fn picker_model_ids(payload: &Value) -> Option<Vec<String>> {
    let agents = payload.pointer("/data/agents")?;
    let cli = if let Some(rows) = agents.as_array() {
        rows.iter()
            .find(|row| row.get("name").and_then(Value::as_str) == Some("cli"))?
    } else {
        agents.get("cli")?
    };
    Some(
        cli.get("models")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

// ─── 企业模型授权（catalog_access.rs 的插件侧副本）────────────

/// 企业账号的授权身份（uid / 类型 / 企业 / 域名 / 端点）。
///
/// 台账里存的是它：身份一变旧目录立即作废，避免拿「同名的另一个人」的授权去
/// 发请求。
pub fn authority(session: &Value) -> Value {
    let mut value = serde_json::Map::new();
    for key in [
        "uid",
        "type",
        "enterpriseId",
        "oneidAccountId",
        "departmentFullName",
        "idp",
    ] {
        if let Some(field) = session.pointer(&format!("/account/{key}")) {
            value.insert(key.into(), field.clone());
        }
    }
    for key in ["domain", "tokenType"] {
        if let Some(field) = session.pointer(&format!("/auth/{key}")) {
            value.insert(key.into(), field.clone());
        }
    }
    value.insert("endpoint".into(), json!(outbound::session_endpoint_of(session)));
    value.insert("region".into(), json!(crate::Region::id()));
    Value::Object(value)
}

/// 是否企业账号（有 `enterpriseId`）。
pub fn enterprise(session: &Value) -> bool {
    session
        .pointer("/account/enterpriseId")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty())
}

/// 读台账（宿主 `ledger.get`），取不到就给空。
fn ledger() -> Value {
    sdk::host("ledger.get", json!({ "kind": LEDGER }))
        .ok()
        .filter(|value| value.is_object())
        .unwrap_or(Value::Null)
}

/// 保存企业目录 + 授权身份（宿主 `ledger.put`）。
fn save(session: &Value, models: &[Value], complete: bool) -> Result<()> {
    if !enterprise(session) {
        // 公共目录由宿主按 `models.refresh` 的返回值落库，不进这份台账
        return Ok(());
    }
    sdk::host(
        "ledger.put",
        json!({
            "kind": LEDGER,
            "value": {
                "authority": authority(session),
                "fetchedAt": util::now_ms(),
                "models": models,
                "complete": complete,
            },
        }),
    )
    .map(|_| ())
}

/// 取「当前账号自己那份」企业目录（身份 / 时间窗都校验过）。
fn load(session: &Value) -> Option<(Vec<Value>, bool)> {
    if !enterprise(session) {
        return None;
    }
    let saved = ledger();
    if !saved.is_object() {
        return None;
    }
    let now = util::now_ms();
    let fetched = saved.get("fetchedAt").and_then(Value::as_i64)?;
    if saved.get("authority") != Some(&authority(session))
        || fetched > now
        || now.saturating_sub(fetched) >= TTL_MS
    {
        return None;
    }
    Some((
        saved.get("models").and_then(Value::as_array)?.clone(),
        saved.get("complete").and_then(Value::as_bool).unwrap_or(false),
    ))
}

/// 发对话前的模型权限核对（`build_chat` 的守卫）。
///
/// 个人账号：只挡「仅在企业目录里出现过的模型」（那说明别的账号的授权不该被借用）。
/// 企业账号：必须先确认自己那份目录（缺失就现拉一次），目录里没有就 403。
pub fn check(session: &Value, requested: &str) -> Result<Option<Value>> {
    if !enterprise(session) {
        if model(requested).is_some_and(|model| {
            model
                .get("workbuddyAccountScoped")
                .and_then(Value::as_bool)
                == Some(true)
        }) {
            return Err(unavailable("该模型仅在企业账号目录中声明，当前个人账号没有授权"));
        }
        return Ok(model(requested));
    }
    let own = match load(session) {
        Some((models, complete)) => (models, complete),
        None => {
            if let Err(reason) = refresh_session(session) {
                let mut error = Error::http(503, "企业账号模型权限尚未确认，未发送对话请求")
                    .with_code("account_model_permissions_unknown");
                error.message = format!("{}（{}）", error.message, reason);
                return Err(error);
            }
            load(session).ok_or_else(|| unavailable("企业账号权限目录未能恢复"))?
        }
    };
    let (models, complete) = own;
    if let Some(hit) = models.into_iter().find(|entry| {
        entry
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.eq_ignore_ascii_case(requested))
    }) {
        return Ok(Some(hit));
    }
    Err(if complete {
        unavailable("当前企业账号目录没有这个模型，未将请求发给无授权账号")
    } else {
        Error::http(503, "企业目录只取得部分条目，目标模型权限未知")
            .with_code("account_model_permissions_unknown")
    })
}

fn unavailable(message: &str) -> Error {
    Error::http(403, message).with_code("account_model_unavailable")
}

/// 把网关给的名字折成上游认的 id（目录里按 id 或展示名都找一遍）。
pub fn wire_id(requested: &str, account_id: &str) -> String {
    let prefix = format!("{account_id}/");
    let name = requested.strip_prefix(&prefix).unwrap_or(requested).trim();
    list()["models"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|model| model["id"] == name || model["name"] == name)
        .and_then(|model| model["id"].as_str())
        .unwrap_or(name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_requires_a_non_empty_id() {
        assert!(!enterprise(&json!({ "account": {} })));
        assert!(!enterprise(&json!({ "account": { "enterpriseId": "  " } })));
        assert!(enterprise(&json!({ "account": { "enterpriseId": "e-1" } })));
    }

    #[test]
    fn authority_tracks_identity_fields() {
        let session = json!({
            "account": { "uid": "u-1", "enterpriseId": "e-1" },
            "auth": { "domain": "copilot.tencent.com" },
            "endpoint": "https://copilot.tencent.com",
        });
        let authority = authority(&session);
        assert_eq!(authority["uid"], json!("u-1"));
        assert_eq!(authority["enterpriseId"], json!("e-1"));
        assert_eq!(authority["endpoint"], json!("https://copilot.tencent.com"));
        assert_eq!(authority["region"], json!("cn"));
    }

    #[test]
    fn picker_ids_come_from_the_cli_agent() {
        let payload = json!({ "data": { "agents": [
            { "name": "web", "models": ["a"] },
            { "name": "cli", "models": ["auto", "glm-5.0"] }
        ]}});
        assert_eq!(
            picker_model_ids(&payload),
            Some(vec!["auto".to_string(), "glm-5.0".to_string()])
        );
        assert_eq!(picker_model_ids(&json!({})), None);
    }
}
