//! ModelScope 模型目录：`GET {推理域}/models`（标准 OpenAI 形态）+ 10 分钟缓存。
//!
//! ── 上游形态（真实账号实测）────────────────────────────────
//! ```text
//! GET https://api-inference.modelscope.cn/v1/models     Authorization: Bearer <ms-令牌>
//!   → {"object":"list","data":[{"id":"Qwen/Qwen3.8-Flash-Next",
//!                               "object":"","owned_by":"system","created":1789…}, …]}
//! ```
//! **只有 `id`**：没有 `name`、没有 `capabilities`、没有上下文长度。
//!
//! ── 清单是**账号相关**的（这是不做静态兜底表的理由）────────────
//! 实测同一个令牌拉到的是 **36 条**，而不是魔搭全站的几千个模型 ——
//! 它给的是「这个账号在 API-Inference 上能调的模型」。编一份静态兜底表是
//! **有害的**：用户会看到一批自己其实调不通的模型。拉不到就如实报失败、
//! 保留旧清单。
//!
//! ── 清单里混着非对话模型（照实列出，不筛）────────────────────
//! 实测 36 条里含生图（`Qwen/Qwen-Image-Edit`）、基座（`PaddlePaddle/ERNIE-*-PT`）
//! 等并非 chat 用途的条目。上游给的就是它的清单，**不按 id 猜用途去过滤** ——
//! 猜错会把能用的模型藏起来。真调不通时，`classify` 会把上游的 400 如实透出。
//!
//! ── 缓存从进程内静态变量搬到了宿主状态 ────────────────────────
//! native 用 `static … OnceLock<Mutex<…>>` 两个槽（国内 / 国际各一）。wasm 没有
//! 跨调用共享的内存（宿主每次 RPC 都可能新建实例），所以整份目录落在
//! `state::Scope::Account` 下：这一家的清单本来就是**账号相关**的，按账号存
//! 比按 provider 存更准。

use agent2api_wasm_sdk::{self as sdk, json, state, Result, Value};

use super::{account, upstream};

/// 模型列表路径（相对推理域）。
pub const MODELS_PATH: &str = "/models";

/// 自动路径的缓存 TTL（与各家同档）。
const TTL_MS: i64 = 10 * 60 * 1000;
/// 目录缓存在账号状态里的键与结构版本。
const STATE_KEY: &str = "catalog";
const SCHEMA: u32 = 1;

/// 一次目录快照：清单、抓取时刻、以及写回时要用的 revision。
struct Cached {
    models: Vec<Value>,
    fetched_at: i64,
    revision: u64,
}

/// 读当前账号的目录快照（没有就 None：没刷过 / 没账号）。
fn snapshot() -> Option<Cached> {
    let snapshot = state::get(state::Scope::Account, STATE_KEY, SCHEMA).ok()?;
    if !snapshot.compatible || snapshot.value.is_null() {
        return None;
    }
    Some(Cached {
        models: snapshot
            .value
            .get("models")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        fetched_at: snapshot.value["fetched_at"].as_i64().unwrap_or(0),
        revision: snapshot.revision,
    })
}

/// 落一份新目录（CAS：并发刷新时后到的那个不覆盖先到的，缓存不值得争）。
///
/// `revision` 来自刚读到的快照；第一次写（没有快照）时现读一次 ——
/// 状态存储要求带上当前 revision 才能比较再写。
fn save(models: &[Value], fetched_at: i64, revision: Option<u64>) {
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
        json!({ "models": models, "fetched_at": fetched_at }),
        0,
    );
}

/// `models.list`：当前账号的目录（没刷过时退回宿主目录缓存）。
pub fn list() -> Result<Value> {
    if let Some(cached) = snapshot() {
        if !cached.models.is_empty() {
            return Ok(json!({
                "models": cached.models,
                "meta": { "remote": true, "refreshed_at": cached.fetched_at },
            }));
        }
    }
    let mut host = sdk::catalog::cached()?;
    if !host.is_object() {
        host = json!({ "models": [], "meta": { "remote": false, "refreshed_at": 0 } });
    }
    if host.get("meta").map_or(true, Value::is_null) {
        let remote = host["models"]
            .as_array()
            .is_some_and(|models| !models.is_empty());
        host["meta"] = json!({ "remote": remote, "refreshed_at": 0 });
    }
    Ok(host)
}

/// `models.refresh`：真打一次上游目录。
///
/// `force = false`（自动路径）时 10 分钟 TTL 内早退为 `unchanged()`；
/// `force = true`（用户手动刷新）真打上游 —— 复用自动路径会让界面显示
/// 「刷新成功」而清单一个字没变。
///
/// **没有账号不是失败**：那是「用户还没添加账号」的正常状态，返回
/// `unchanged(0)`（与网关版同口径：脚本 / CI 不该看到一个红色失败）。
pub fn refresh(force: bool) -> Result<Value> {
    let record = match sdk::account() {
        Ok(record) => record,
        Err(_) => return Ok(sdk::catalog::unchanged(0)),
    };
    let token = match account::token_of(&record["secret"]) {
        Ok(token) => token,
        Err(error) => return Ok(sdk::catalog::failed(&error.message)),
    };
    let cached = snapshot();
    if !force {
        if let Some(cached) = &cached {
            if !cached.models.is_empty() && sdk::now().saturating_sub(cached.fetched_at) < TTL_MS {
                return Ok(sdk::catalog::unchanged(cached.models.len()));
            }
        }
    }
    let payload = match upstream::inference_json(&token, MODELS_PATH, "模型目录查询") {
        Ok(payload) => payload,
        Err(error) => return Ok(sdk::catalog::failed(&error.message)),
    };
    let models = parse_models(&payload);
    if models.is_empty() {
        return Ok(sdk::catalog::failed(
            "ModelScope 模型目录为空或格式不认识（保留现有清单）",
        ));
    }
    save(&models, sdk::now(), cached.as_ref().map(|cached| cached.revision));
    // `refreshed()` 自己带 `count` 与 `meta.refreshed_at`：清单与元数据一起回，
    // 界面不会读到「清单已换、元数据还是上一次」的中间态
    Ok(sdk::catalog::refreshed(models))
}

/// 解析 `/models` 响应（OpenAI `{data:[...]}` 或裸数组）。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let rows = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

/// 把一个 OpenAI 目录条目映射成聚合层认的形态。
///
/// 上游只给 `id`，所以 `name` 就用 id 本身：魔搭的 id 是 `组织/模型名`，
/// 它本身就是可读的展示名，拆掉组织段反而会让同名模型（不同组织的同名条目）
/// 在界面上无法区分。
///
/// 工具位按 OpenAI 兼容网关的既有能力给 true。**思考位不给** —— 上游没有
/// 能力位、按 id 猜会猜错，交给模型规则层由用户显式绑定更诚实。
fn map_entry(row: &Value) -> Option<Value> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let mut model = json!({
        "id": id,
        "name": id,
        "supportsToolCall": true,
    });
    decorate(id, &mut model);
    Some(model)
}

/// 生图 / 编辑型号的标注（native `image_generation.rs` 的白名单，逐条照抄）。
///
/// ── 这两个位描述的是**上游型号**，不是本插件的能力 ─────────────
/// 本包没有实现 `images.generate` / `images.edit`（`images.capabilities` 如实
/// 报 false，理由见 `lib.rs`）。目录里的 `supports_image_generation` 仍然照
/// native 写：它回答的是「这个型号本身能不能生图」，界面据此把生图型号与对话
/// 型号分开列；能不能在本网关里点出图由 `images.capabilities` 决定。
fn decorate(id: &str, row: &mut Value) {
    if let Some((generation, editing)) = image_capabilities(id) {
        row["kind"] = json!("image");
        row["output_modalities"] = json!(["image"]);
        row["supports_image_generation"] = json!(generation);
        row["supports_image_editing"] = json!(editing);
        row["supportsToolCall"] = json!(false);
        row["supportsImages"] = json!(editing);
        row["supportsReasoning"] = json!(false);
    }
}

/// 只登记**文档和官方模型卡确认**的型号，不把整个模型市场当作账号可调用清单。
fn image_capabilities(id: &str) -> Option<(bool, bool)> {
    let generation = [
        "Qwen/Qwen-Image",
        "Qwen/Qwen-Image-2512",
        "Tongyi-MAI/Z-Image-Turbo",
        "Tongyi-MAI/Z-Image",
    ];
    let editing = [
        "Qwen/Qwen-Image-Edit",
        "Qwen/Qwen-Image-Edit-2509",
        "Qwen/Qwen-Image-Edit-2511",
    ];
    if generation
        .iter()
        .any(|model| model.eq_ignore_ascii_case(id))
    {
        Some((true, false))
    } else if editing.iter().any(|model| model.eq_ignore_ascii_case(id)) {
        Some((false, true))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有 id 的条目也要变成一条能显示的记录；空 id 丢掉。
    #[test]
    fn an_entry_with_only_an_id_is_enough() {
        let payload = json!({
            "object": "list",
            "data": [
                { "id": "Qwen/Qwen3.8-Flash-Next", "owned_by": "system" },
                { "id": "  " },
                { "name": "没有 id" }
            ]
        });
        let models = parse_models(&payload);
        assert_eq!(1, models.len());
        assert_eq!(
            "Qwen/Qwen3.8-Flash-Next",
            models[0]["name"].as_str().unwrap_or_default()
        );
        assert_eq!(true, models[0]["supportsToolCall"].as_bool().unwrap_or(false));
    }

    /// 裸数组形态也认（上游两种都给过）。
    #[test]
    fn a_bare_array_is_accepted() {
        let payload = json!([{ "id": "Qwen/Qwen3-Turbo" }]);
        assert_eq!(1, parse_models(&payload).len());
        assert!(parse_models(&json!({})).is_empty());
    }

    /// 生图型号要标出来，且不许再被当成会调工具的对话模型。
    #[test]
    fn image_models_are_marked_and_lose_the_tool_flag() {
        let payload = json!({ "data": [
            { "id": "Qwen/Qwen-Image-Edit" },
            { "id": "qwen/qwen-image" },
            { "id": "Qwen/Qwen3-Max" }
        ]});
        let models = parse_models(&payload);
        assert_eq!("image", models[0]["kind"].as_str().unwrap_or_default());
        assert_eq!(true, models[0]["supports_image_editing"].as_bool().unwrap_or(false));
        assert_eq!(false, models[0]["supportsToolCall"].as_bool().unwrap_or(true));
        // 大小写不敏感
        assert_eq!(true, models[1]["supports_image_generation"].as_bool().unwrap_or(false));
        // 普通对话型号不被标注
        assert!(models[2].get("kind").is_none());
    }
}
