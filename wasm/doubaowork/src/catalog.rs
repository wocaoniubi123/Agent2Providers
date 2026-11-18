//! 模型目录：上游下发、缓存、按名字解析。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/catalog.rs`。
//!
//! ── 目录为什么必须来自两次控制面请求 ────────────────────────
//! 上游按 `pc_version` 下发菜单：先 `POST /alice/user/launch` 拿 `bot_id`，
//! 再 `POST /alice/slot/action_bar_v3/brief_list` 拿菜单。只有 `runtime_version`
//! 时会成功返回**空菜单**（native 踩过），所以 `clientVersion` 缺省时用
//! `api::Credential` 里那个默认版本。
//!
//! ── 缓存落哪儿 ──────────────────────────────────────────────
//! native 是进程内 `Mutex<BTreeMap>` + `ctx.ledger_put`；wasm 每次调用都是新实例，
//! 进程内存活不过一次调用，所以只保留台账（`ledger.get` / `ledger.put`，
//! 能力 `accounts.cas.v1`）。指纹用 Cookie 的 SHA-256：换了账号的 Cookie，
//! 缓存自动失效，不会把上一个账号的目录当成这一个人的。
//!
//! ── 生图条目是合成出来的 ────────────────────────────────────
//! 上游目录里没有「生图」这一条：出图是对话里派给 agent 的一次任务
//! （见 `images.rs` 模块头）。这条合成条目只在账号**真的**能跑任务模式时
//! 才露出 —— 能力位是网关派发图片请求的依据，列一条注定失败的模型
//! 等于给用户一个必然报错的选项。

use std::collections::BTreeMap;

use agent2api_wasm_sdk::{self as sdk, catalog, json, Error, Result, Value};
use sha2::{Digest, Sha256};

use super::api;

const TTL_MS: i64 = 5 * 60 * 1000;
const LEDGER: &str = "doubaowork-models";
/// 台账单条上限 64 KiB（宿主卡死这一条），留一点余量给外层结构。
const MAX_LEDGER: usize = 60 * 1024;

/// 下游认的图像条目 id（见 `images::MODEL_ID`，两处必须一致）。
pub const IMAGE_MODEL_ID: &str = "doubao-image";

#[derive(Clone)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub extra: Value,
    pub agent_mode: u64,
    pub mode_id: Option<String>,
    pub mode_name: Option<String>,
    pub deep_think: i64,
}

#[derive(Clone)]
pub struct Catalog {
    pub fetched_at: i64,
    pub credentials: String,
    pub bot: String,
    pub models: BTreeMap<String, Model>,
}

fn fingerprint(cookie: &str) -> String {
    let digest = Sha256::digest(cookie.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_ledger() -> Result<Option<Value>> {
    match sdk::host("ledger.get", json!({ "kind": LEDGER })) {
        Ok(value) if !value.is_null() => Ok(Some(value)),
        _ => Ok(None),
    }
}

fn write_ledger(value: &Value) -> Result<()> {
    sdk::host("ledger.put", json!({ "kind": LEDGER, "value": value }))?;
    Ok(())
}

fn decode(value: &Value) -> Option<Catalog> {
    let fetched_at = value["fetched_at"].as_i64()?;
    let credentials = value["credentials"].as_str()?.to_string();
    let bot = value["bot"].as_str()?.to_string();
    let table = value["models"].as_object()?;
    let mut models = BTreeMap::new();
    for (key, row) in table {
        let id = row["id"].as_str()?.to_string();
        let name = row["name"].as_str().unwrap_or(&id).to_string();
        let agent_mode = row["agent_mode"].as_u64().unwrap_or(0);
        let mode_id = row["mode_id"].as_str().map(str::to_string);
        let mode_name = row["mode_name"].as_str().map(str::to_string);
        let deep_think = row["deep_think"].as_i64().unwrap_or(0);
        models.insert(
            key.clone(),
            Model { id, name, extra: row["extra"].clone(), agent_mode, mode_id, mode_name, deep_think },
        );
    }
    Some(Catalog { fetched_at, credentials, bot, models })
}

fn encode(catalog: &Catalog, compact: bool) -> Option<Value> {
    let models: Vec<Value> = catalog
        .models
        .iter()
        .map(|(key, model)| {
            let extra = if compact {
                let mut trimmed = serde_json::Map::new();
                for field in ["context_window", "max_input_tokens", "provider_id"] {
                    if let Some(value) = model.extra.get(field).filter(|value| !value.is_null()) {
                        trimmed.insert(field.to_string(), value.clone());
                    }
                }
                Value::Object(trimmed)
            } else {
                model.extra.clone()
            };
            json!({
                "id": model.id,
                "name": model.name,
                "extra": extra,
                "agent_mode": model.agent_mode,
                "mode_id": model.mode_id,
                "mode_name": model.mode_name,
                "deep_think": model.deep_think,
                "key": key,
            })
        })
        .collect();
    let mut table = serde_json::Map::new();
    for row in models {
        let key = row["key"].as_str()?.to_string();
        let mut row = row;
        if let Some(object) = row.as_object_mut() {
            object.remove("key");
        }
        table.insert(key, row);
    }
    Some(json!({
        "fetched_at": catalog.fetched_at,
        "credentials": catalog.credentials,
        "bot": catalog.bot,
        "models": Value::Object(table),
    }))
}

fn model_row(row: &Value, mode: Option<&Value>) -> Option<Model> {
    let id = api::identifier(&row["model_item_key"]).or_else(|| api::identifier(&row["item_id"]))?;
    let name = row["name"]
        .as_str()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&id)
        .to_string();
    let extra = match &row["model_extra_params"] {
        Value::String(text) => serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone())),
        Value::Object(_) => row["model_extra_params"].clone(),
        _ => json!({}),
    };
    let agent_mode = match mode {
        Some(mode) => api::number(&mode["agent_mode"])?,
        None => api::number(&row["agent_mode"]).unwrap_or(0),
    };
    let mode_id = mode
        .and_then(|mode| api::identifier(&mode["mode_id"]))
        .or_else(|| api::identifier(&row["default_mode"]));
    let mode_name = mode
        .and_then(|mode| mode["name"].as_str())
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string);
    let mut deep_think = api::number(&row["menu_type"])
        .or_else(|| api::number(&row["item_id"]))
        .or_else(|| id.parse().ok())
        .unwrap_or(0) as i64;
    if mode_id.as_deref() == Some("2") && deep_think == 4 {
        deep_think = 3;
    }
    Some(Model { id, name, extra, agent_mode, mode_id, mode_name, deep_think })
}

fn mode_permits_model(row: &Value, mode: &Value) -> bool {
    let Some(mode_id) = api::identifier(&mode["mode_id"]) else {
        return false;
    };
    let id = api::identifier(&row["model_item_key"]).or_else(|| api::identifier(&row["item_id"]));
    row["conversation_mode_list"]
        .as_array()
        .map_or(true, |modes| {
            modes
                .iter()
                .any(|value| api::identifier(value).as_ref() == Some(&mode_id))
        })
        && mode["support_models"].as_array().map_or(true, |models| {
            models.iter().any(|value| {
                api::identifier(&value["model_item_key"])
                    .or_else(|| api::identifier(&value["item_id"]))
                    .or_else(|| api::identifier(value))
                    == id
            })
        })
}

fn directory(value: &Value) -> BTreeMap<String, Model> {
    let mut contexts: BTreeMap<String, Vec<Model>> = BTreeMap::new();
    let mut insert = |model: Model| {
        let variants = contexts.entry(model.id.clone()).or_default();
        if let Some(previous) = variants
            .iter_mut()
            .find(|previous| previous.mode_id == model.mode_id && previous.agent_mode == model.agent_mode)
        {
            *previous = model;
        } else {
            variants.push(model);
        }
    };
    for entry in value["data"]["entry_list"].as_array().into_iter().flatten() {
        let conf = &entry["active_switch_conf"];
        if conf["use_menu_conf_v2"] != true {
            for row in conf["menu_conf"]["item_list"].as_array().into_iter().flatten() {
                if let Some(model) = model_row(row, None) {
                    insert(model);
                }
            }
            continue;
        }
        let v2 = &conf["menu_conf_v2"];
        let modes = v2["mode_list"]["item_list"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        for row in v2["model_list"]["item_list"].as_array().into_iter().flatten() {
            let find = |id: Option<String>| {
                id.and_then(|id| {
                    modes.iter().find(|mode| {
                        api::identifier(&mode["mode_id"]).as_ref() == Some(&id)
                            && mode_permits_model(row, mode)
                    })
                })
            };
            let mode = find(api::identifier(&row["default_mode"]))
                .or_else(|| find(api::identifier(&v2["default_select_mode_map"]["new_chat"]["mode_id"])))
                .or_else(|| {
                    modes.iter().find(|mode| {
                        api::number(&mode["agent_mode"]) == Some(2) && mode_permits_model(row, mode)
                    })
                })
                .or_else(|| modes.iter().find(|mode| mode_permits_model(row, mode)));
            if !modes.is_empty() && mode.is_none() {
                continue;
            }
            if let Some(model) = model_row(row, mode) {
                insert(model);
            }
        }
        // 与客户端一致：模式内的元数据优先于同模式的全局条目。
        for mode in modes {
            for row in mode["model_list"]["item_list"].as_array().into_iter().flatten() {
                if let Some(model) = model_row(row, Some(mode)) {
                    insert(model);
                }
            }
        }
    }
    let mut result = BTreeMap::new();
    for (id, variants) in contexts {
        let scoped = variants.len() > 1;
        for mut model in variants {
            let key = if scoped {
                let mode_id = model
                    .mode_id
                    .clone()
                    .unwrap_or_else(|| format!("agent-{}", model.agent_mode));
                let mode_name = model.mode_name.as_deref().unwrap_or(&mode_id);
                model.name = format!("{} · {mode_name}", model.name);
                format!("{}::{}", api::encode(&mode_id), api::encode(&id))
            } else {
                id.clone()
            };
            result.insert(key, model);
        }
    }
    result
}

/// 挑一条能跑任务的模型：生图、以及任何「让 agent 干活」的任务都挂在通用任务
/// 模式上（客户端记录里 `ext.agent_name = Agent-GeneralTask`、`agent_mode = 1`）。
///
/// 判据只能看 `agent_mode`：优先 1（通用任务，实测即客户端这一路），其次 2，
/// 再次任何非 0 的模式 —— 上游换编号时至少还有一条兜底，而不是直接断掉。
fn agent_model(models: &BTreeMap<String, Model>) -> Option<Model> {
    let pick = |wanted: u64| models.values().find(|model| model.agent_mode == wanted).cloned();
    pick(1)
        .or_else(|| pick(2))
        .or_else(|| models.values().find(|model| model.agent_mode != 0).cloned())
}

/// 一条模型记录（对下游露出的形状）。
fn record(key: &str, model: &Model) -> Value {
    let mut value = json!({
        "id": key,
        "name": model.name,
        "supportsImages": true,
        "supportsReasoning": model.deep_think != 0 || model.mode_id.is_some(),
        "supportsToolCall": true,
        "toolCallEmulated": true,
    });
    if let Some(context) = model
        .extra
        .get("context_window")
        .or_else(|| model.extra.get("max_input_tokens"))
        .and_then(Value::as_u64)
    {
        value["maxInputTokens"] = json!(context);
    }
    value
}

fn records(catalog: &Catalog) -> Vec<Value> {
    let mut rows: Vec<Value> = catalog
        .models
        .iter()
        .map(|(key, model)| record(key, model))
        .collect();
    if agent_model(&catalog.models).is_some() {
        rows.push(super::images::model_row());
    }
    rows
}

/// 拉一次目录并落台账；`force=false` 时优先用新鲜缓存。
pub fn fetch(credentials: &api::Credential, force: bool) -> Result<(Catalog, bool)> {
    let fingerprint = fingerprint(&credentials.cookie);
    if !force {
        if let Some(cached) = read_ledger().ok().flatten().and_then(|value| decode(&value)) {
            if cached.credentials == fingerprint
                && sdk::now() - cached.fetched_at < TTL_MS
                && !cached.models.is_empty()
            {
                return Ok((cached, false));
            }
        }
    }
    let launch = api::post(credentials, "/alice/user/launch", &json!({}))?;
    let bot = api::identifier(&launch["data"]["assistant_bot_id"])
        .or_else(|| api::identifier(&launch["assistant_bot_id"]))
        .ok_or_else(|| Error::http(502, "豆包工作未返回助手 ID"))?;
    let value = api::post(
        credentials,
        "/alice/slot/action_bar_v3/brief_list",
        &json!({"language_code": "zh", "bot_id": bot}),
    )?;
    let models = directory(&value);
    if models.is_empty() {
        return Err(Error::http(
            502,
            "豆包工作返回的模型目录为空或格式已变化，保留已有清单",
        ));
    }
    let catalog = Catalog {
        fetched_at: sdk::now(),
        credentials: fingerprint,
        bot,
        models,
    };
    // 台账写失败不影响本次调用：目录已经拿到，下次再拉一次即可。
    if let Some(mut value) = encode(&catalog, false) {
        if value.to_string().len() > MAX_LEDGER {
            value = encode(&catalog, true).unwrap_or(Value::Null);
        }
        if value.is_object() {
            // 台账写失败不影响本次调用：目录已经拿到，下次再拉一次即可。
            let _ = write_ledger(&value);
        }
    }
    Ok((catalog, true))
}

/// `models.list`：只读台账（不在这里打上游）。
pub fn list() -> Result<Value> {
    let catalog = read_ledger().ok().flatten().and_then(|value| decode(&value));
    match catalog {
        Some(catalog) if !catalog.models.is_empty() => Ok(json!({
            "models": records(&catalog),
            "meta": { "remote": true, "refreshed_at": catalog.fetched_at },
        })),
        _ => Ok(json!({
            "models": [],
            "meta": { "remote": false, "refreshed_at": 0 },
        })),
    }
}

/// `models.refresh`：真的打一次上游（`force=false` 时可能命中缓存）。
pub fn refresh(credentials: &api::Credential, force: bool) -> Result<Value> {
    let (catalog, refreshed) = fetch(credentials, force)?;
    let models = records(&catalog);
    Ok(if refreshed {
        catalog::refreshed(models)
    } else {
        catalog::unchanged(models.len())
    })
}

/// 按下游模型名解析出上游目录条目。
pub fn resolve(credentials: &api::Credential, name: &str) -> Result<(String, Model)> {
    let (catalog, _) = fetch(credentials, false)?;
    let selected = catalog
        .models
        .get(name)
        .cloned()
        .or_else(|| {
            let mut matching = catalog.models.values().filter(|model| model.name == name);
            let first = matching.next()?.clone();
            matching.next().is_none().then_some(first)
        })
        .ok_or_else(|| {
            Error::http(
                400,
                "该模型不在当前豆包工作账号的在线目录中，请刷新模型或检查模型映射",
            )
            .with_code("model_not_found")
        })?;
    Ok((catalog.bot, selected))
}

/// 生图这类「让 agent 干活」的请求要用的模型：见 [`agent_model`]。
pub fn resolve_agent(credentials: &api::Credential) -> Result<(String, Model)> {
    let (catalog, _) = fetch(credentials, false)?;
    let selected = agent_model(&catalog.models).ok_or_else(|| {
        Error::http(
            400,
            "该豆包工作账号的在线目录里没有可跑任务的模式（生图需要它），\
             请刷新模型目录；若仍不出现，请在该账号的豆包工作客户端里确认「图像生成」可用",
        )
        .with_code("image_generation_not_supported")
    })?;
    Ok((catalog.bot, selected))
}
