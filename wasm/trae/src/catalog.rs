//! Trae 各聊天通道的目录归并与请求路由。
//!
//! 同一 config 在不同 function 下的物理模型、展示名、窗口与思考档位可能不同。
//! 目录与转发必须选同一条读数；基础模型走 dev 档，Max 另广告 `<id>-max`，
//! 只有显式选它才使用上游 `__max` 模型和更大的窗口。
//! 历史 `<id>-solo` / `<id>-solo-max` 仅用于兼容旧请求。

use std::collections::{BTreeMap, HashMap, HashSet};

use agent2api_wasm_sdk::{json, Value};

/// 历史对外名后缀：本网关曾给所有 Trae 模型加过一层 `-solo`。
/// 现在只用于解析旧客户端请求，不再写入对外清单。
pub const LEGACY_SUFFIX: &str = "-solo";
/// 历史 Max 变体后缀：`<config>-solo-max`，同样是本网关自造的 ID。
pub const LEGACY_MAX_SUFFIX: &str = "-solo-max";
/// 新 Max 变体后缀：`<config>-max`。基础模型保持 dev 档，Max 必须显式选择。
pub const MAX_SUFFIX: &str = "-max";

pub const CHAT_FUNCTIONS: [&str; 7] = [
    "chat_v3",
    "solo_work_lite",
    "solo_agent",
    "solo_agent_lite",
    "solo_coder",
    "solo_work_remote",
    "solo_agent_remote",
];

/// 一条目录路由：出站信封里的 `function` 与物理 `model_name`。
#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub config_name: String,
    pub function: String,
    pub model_name: Option<String>,
    pub max_tokens: Option<i64>,
    pub max_window: Option<i64>,
    pub reasoning: Vec<String>,
}

impl Route {
    pub fn fallback(config_name: &str, function: &str) -> Self {
        Self {
            config_name: config_name.to_string(),
            function: function.to_string(),
            model_name: None,
            max_tokens: None,
            max_window: None,
            reasoning: Vec::new(),
        }
    }

    pub fn reasoning_effort(&self, requested: &str) -> Option<&str> {
        let requested = requested.trim().to_lowercase();
        let alias = match requested.as_str() {
            "low" => "light",
            "light" => "low",
            "xhigh" => "extra_high",
            "extra_high" => "xhigh",
            other => other,
        };
        self.reasoning
            .iter()
            .find(|level| level.as_str() == requested)
            .or_else(|| self.reasoning.iter().find(|level| level.as_str() == alias))
            .map(String::as_str)
    }

    pub fn to_json(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("config_name".to_string(), json!(self.config_name));
        object.insert("function".to_string(), json!(self.function));
        if let Some(model_name) = &self.model_name {
            object.insert("model_name".to_string(), json!(model_name));
        }
        if let Some(max_tokens) = self.max_tokens {
            object.insert("max_tokens".to_string(), json!(max_tokens));
        }
        if let Some(max_window) = self.max_window {
            object.insert("max_window".to_string(), json!(max_window));
        }
        if !self.reasoning.is_empty() {
            object.insert("reasoning".to_string(), json!(self.reasoning));
        }
        Value::Object(object)
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            config_name: value["config_name"].as_str()?.to_string(),
            function: value["function"].as_str()?.to_string(),
            model_name: value["model_name"].as_str().map(str::to_string),
            max_tokens: value["max_tokens"].as_i64(),
            max_window: value["max_window"].as_i64(),
            reasoning: value["reasoning"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|level| level.as_str().map(str::to_string))
                .collect(),
        })
    }

    fn list_from_json(value: &Value) -> Vec<Route> {
        value.as_array().into_iter().flatten().filter_map(Route::from_json).collect()
    }
}

/// 一次目录解析的全部产出：对外清单 + 各模型的路由表。
#[derive(Clone, Default)]
pub struct Catalog {
    pub models: Vec<Value>,
    pub routes: BTreeMap<String, Vec<Route>>,
    /// 旧 `<config>-solo-max` 请求专用的 Max 路由；不进入对外清单。
    pub legacy_max_routes: BTreeMap<String, Vec<Route>>,
}

impl Catalog {
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// 存进宿主状态的那一形态（路由表比模型清单重要：转发靠它选通道）。
    pub fn to_json(&self, fetched_at: i64) -> Value {
        let routes: serde_json::Map<String, Value> = self
            .routes
            .iter()
            .map(|(key, list)| (key.clone(), Value::Array(list.iter().map(Route::to_json).collect())))
            .collect();
        let legacy: serde_json::Map<String, Value> = self
            .legacy_max_routes
            .iter()
            .map(|(key, list)| (key.clone(), Value::Array(list.iter().map(Route::to_json).collect())))
            .collect();
        json!({
            "fetched_at": fetched_at,
            "models": self.models,
            "routes": Value::Object(routes),
            "legacy_max_routes": Value::Object(legacy),
        })
    }

    pub fn from_json(value: &Value) -> Self {
        let mut routes = BTreeMap::new();
        if let Some(object) = value["routes"].as_object() {
            for (key, list) in object {
                routes.insert(key.clone(), Route::list_from_json(list));
            }
        }
        let mut legacy_max_routes = BTreeMap::new();
        if let Some(object) = value["legacy_max_routes"].as_object() {
            for (key, list) in object {
                legacy_max_routes.insert(key.clone(), Route::list_from_json(list));
            }
        }
        Self {
            models: value["models"].as_array().cloned().unwrap_or_default(),
            routes,
            legacy_max_routes,
        }
    }
}

struct Group<'a> {
    config_name: String,
    readings: Vec<(&'a str, &'a Value)>,
}

pub fn function_groups(payload: &Value) -> Vec<Value> {
    payload
        .get("function_configs")
        .or_else(|| payload.get("data").and_then(|data| data.get("function_configs")))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|group| {
            group
                .get("function")
                .and_then(Value::as_str)
                .is_some_and(|function| CHAT_FUNCTIONS.contains(&function))
                && group.get("config_info_list").is_some_and(Value::is_array)
        })
        .cloned()
        .collect()
}

pub fn single_entries(payload: &Value) -> Option<&Vec<Value>> {
    payload
        .get("config_info_list")
        .or_else(|| payload.get("data").and_then(|data| data.get("config_info_list")))
        .and_then(Value::as_array)
}

pub fn parse(groups: &[Value]) -> Catalog {
    let mut readings = Vec::new();
    for function in CHAT_FUNCTIONS {
        for group in groups.iter().filter(|group| text(group, "function") == function) {
            for entry in group.get("config_info_list").and_then(Value::as_array).into_iter().flatten() {
                readings.push((function, entry));
            }
        }
    }
    let groups = group_entries(readings);
    let mut catalog = Catalog::default();
    for group in &groups {
        let mut choices: Vec<_> = group.readings.iter().copied().filter(|(_, entry)| is_selectable(entry)).collect();
        let agreed = agreed_name(&choices);
        let name_readings = choices.clone();
        choices.sort_by_key(|(function, entry)| {
            std::cmp::Reverse((
                dev_detail(entry).is_some(),
                !misnamed(function, entry, &name_readings, &groups),
                !agreed.is_empty() && display_name(entry) == agreed,
                !reasoning_levels(entry).is_empty(),
            ))
        });
        let Some((_, entry)) = choices.first() else {
            continue;
        };
        let id = group.config_name.clone();
        let item = catalog_entry(&id, entry);
        let mut routes: Vec<Route> = Vec::new();
        for (function, entry) in &choices {
            let detail = dev_detail(entry);
            let route = route_for(&group.config_name, function, entry, detail, None);
            if !routes.iter().any(|other| other.function == route.function) {
                routes.push(route);
            }
        }
        let mut max_readings = group.readings.clone();
        max_readings.sort_by_key(|(_, entry)| (display_name(entry) != agreed, !is_selectable(entry)));
        let mut max_routes: Vec<Route> = Vec::new();
        for (function, entry) in &max_readings {
            if !is_selectable(entry) {
                continue;
            }
            let Some(detail) = max_detail(entry) else {
                continue;
            };
            let window = context_window(entry, "max").or_else(|| {
                max_readings.iter().find_map(|(_, other)| context_window(other, "max"))
            });
            let dev = context_window(entry, "dev")
                .or_else(|| max_readings.iter().find_map(|(_, other)| context_window(other, "dev")))
                .unwrap_or(0);
            let Some(window) = window.filter(|window| *window > dev) else {
                continue;
            };
            let route = route_for(&group.config_name, function, entry, Some(detail), Some(window));
            if !max_routes.contains(&route) {
                max_routes.push(route);
            }
        }
        let key = id.to_lowercase();
        catalog.models.push(item.clone());
        catalog.routes.insert(key.clone(), routes);
        if max_routes.is_empty() {
            continue;
        }
        // Max 权益按账号不同，不能把基础 ID 直接当成 Max：单独广告
        // `<id>-max`，只有显式选它才走 Max 路由。旧 `<id>-solo-max` 仍由
        // `legacy_max_routes` 解析。
        let max_id = format!("{id}{MAX_SUFFIX}");
        let taken = groups.iter().any(|other| other.config_name.eq_ignore_ascii_case(&max_id));
        if !taken {
            let route = &max_routes[0];
            let mut max = item;
            if let Some(object) = max.as_object_mut() {
                object.insert("id".to_string(), json!(max_id));
                object.insert("name".to_string(), json!(format!("{} (Max)", display_name(entry))));
                object.insert("maxInputTokens".to_string(), json!(route.max_window));
                // 网关用它确认 `<id>-max` 是本插件合成的 Max 档，而不是同名的
                // 真实上游模型（撞名时更安全）。
                object.insert("traeMax".to_string(), json!(true));
                match route.max_tokens {
                    Some(output) => {
                        object.insert("maxOutputTokens".to_string(), json!(output));
                    }
                    None => {
                        object.remove("maxOutputTokens");
                    }
                }
            }
            catalog.models.push(max);
            catalog.routes.insert(max_id.to_lowercase(), max_routes.clone());
        }
        catalog.legacy_max_routes.insert(key, max_routes);
    }
    catalog
}

fn group_entries<'a>(readings: Vec<(&'a str, &'a Value)>) -> Vec<Group<'a>> {
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut groups: Vec<Group<'a>> = Vec::new();
    for (function, entry) in readings {
        let config_name = text(entry, "config_name");
        if config_name.is_empty() {
            continue;
        }
        let key = config_name.to_lowercase();
        if let Some(index) = at.get(&key) {
            groups[*index].readings.push((function, entry));
        } else {
            at.insert(key, groups.len());
            groups.push(Group { config_name, readings: vec![(function, entry)] });
        }
    }
    groups
}

fn agreed_name(readings: &[(&str, &Value)]) -> String {
    let mut seen = HashSet::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (function, entry) in readings {
        let name = display_name(entry);
        if seen.insert((*function, name.clone())) {
            *counts.entry(name).or_default() += 1;
        }
    }
    let top = counts.values().copied().max().unwrap_or(0);
    let mut names = counts.into_iter().filter(|(_, count)| *count == top);
    let Some((name, _)) = names.next() else {
        return String::new();
    };
    if names.next().is_none() { name } else { String::new() }
}

fn misnamed(function: &str, entry: &Value, readings: &[(&str, &Value)], groups: &[Group<'_>]) -> bool {
    let name = display_name(entry);
    readings.iter().any(|(_, other)| display_name(other) != name)
        && groups.iter().any(|group| {
            !group.config_name.eq_ignore_ascii_case(&text(entry, "config_name"))
                && group.readings.iter().any(|(other_function, other)| {
                    *other_function == function && is_selectable(other) && display_name(other) == name
                })
        })
}

fn is_selectable(entry: &Value) -> bool {
    let id = text(entry, "config_name").to_lowercase();
    let display = embedded(entry.get("display_config"));
    if id.is_empty()
        || id.starts_with("custom_model")
        || id.starts_with("search_agent")
        || id.starts_with("fast_apply")
        || matches!(
            id.as_str(),
            "file_search_agent" | "summary" | "title_generation" | "input_optimization" | "laziness_detection"
        )
    {
        return false;
    }
    if ["hidden", "disabled", "is_invisible_to_user", "is_custom_model"]
        .iter()
        .any(|key| entry.get(*key).and_then(Value::as_bool) == Some(true))
        || entry.get("config_switch").and_then(Value::as_bool) == Some(false)
        || display.get("is_custom_model").and_then(Value::as_bool) == Some(true)
    {
        return false;
    }
    let usage = text(entry, "usage");
    usage.is_empty() || usage == "chat_completion"
}

fn route_for(config: &str, function: &str, entry: &Value, detail: Option<&Value>, max_window: Option<i64>) -> Route {
    Route {
        config_name: config.to_string(),
        function: function.to_string(),
        model_name: detail.map(|detail| text(detail, "model_name")).filter(|name| !name.is_empty()),
        max_tokens: detail
            .and_then(|detail| positive(detail.get("max_tokens")))
            .or_else(|| if max_window.is_none() { output_limit(entry) } else { None }),
        max_window,
        reasoning: reasoning_levels(entry),
    }
}

fn catalog_entry(id: &str, entry: &Value) -> Value {
    let extra = embedded(entry.get("extra_config"));
    let mut item = json!({
        "id": id,
        "name": display_name(entry),
        "supportsToolCall": extra.get("native_function_call").and_then(Value::as_bool).unwrap_or(true),
    });
    if let Some(object) = item.as_object_mut() {
        if let Some(context) = context_window(entry, "dev") {
            object.insert("maxInputTokens".to_string(), json!(context));
        }
        if let Some(output) = output_limit(entry) {
            object.insert("maxOutputTokens".to_string(), json!(output));
        }
        if let Some(reasoning) = supports_reasoning(entry) {
            object.insert("supportsReasoning".to_string(), json!(reasoning));
        }
        if let Some(images) = supports_images(entry) {
            object.insert("supportsImages".to_string(), json!(images));
        }
        if let Some(rate) = consumption_rate(entry) {
            object.insert("credits".to_string(), json!(credits_text(rate)));
        }
    }
    item
}

fn display_name(entry: &Value) -> String {
    let display = embedded(entry.get("display_config"));
    [
        text(&display, "display_name"),
        text(entry, "display_name"),
        text(entry, "display_model_name"),
        text(entry, "config_name"),
    ]
    .into_iter()
    .find(|name| !name.is_empty())
    .unwrap_or_default()
}

fn detail_tier(detail: &Value) -> Option<&str> {
    detail.get("model_name").and_then(Value::as_str)?.rsplit_once("__").map(|(_, tier)| tier)
}

fn dev_detail(entry: &Value) -> Option<&Value> {
    entry.get("model_detail_list").and_then(Value::as_array)?.iter().find(|detail| detail_tier(detail) == Some("dev"))
}

fn max_detail(entry: &Value) -> Option<&Value> {
    entry.get("model_detail_list").and_then(Value::as_array)?.iter().find(|detail| detail_tier(detail) == Some("max"))
}

fn context_window(entry: &Value, key: &str) -> Option<i64> {
    positive(entry.get("context_window_tokens").and_then(|window| window.get(key)))
}

fn output_limit(entry: &Value) -> Option<i64> {
    if let Some(detail) = dev_detail(entry) {
        return positive(detail.get("max_tokens"));
    }
    entry
        .get("model_detail_list")
        .and_then(Value::as_array)?
        .iter()
        .filter(|detail| detail_tier(detail) != Some("max"))
        .filter_map(|detail| positive(detail.get("max_tokens")))
        .min()
}

fn reasoning_levels(entry: &Value) -> Vec<String> {
    let display = embedded(entry.get("display_config"));
    let detail = dev_detail(entry);
    let config = embedded(
        entry
            .get("reasoning_effort_config")
            .or_else(|| display.get("reasoning_effort_config"))
            .or_else(|| detail.and_then(|detail| detail.get("reasoning_effort_config"))),
    );
    if entry.get("support_thinking").and_then(Value::as_bool) == Some(false)
        || display.get("support_thinking").and_then(Value::as_bool) == Some(false)
        || config.get("support_thinking").and_then(Value::as_bool) == Some(false)
    {
        return Vec::new();
    }
    config
        .get("options")
        .or_else(|| entry.get("reasoning_effort_options"))
        .or_else(|| detail.and_then(|detail| detail.get("reasoning_effort_options")))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|level| !level.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn supports_reasoning(entry: &Value) -> Option<bool> {
    let display = embedded(entry.get("display_config"));
    match text(&display, "model_capability").as_str() {
        "reasoning_model" => Some(true),
        "chat_model" => Some(false),
        _ if !reasoning_levels(entry).is_empty() => Some(true),
        _ => None,
    }
}

pub fn supports_images(entry: &Value) -> Option<bool> {
    let display = embedded(entry.get("display_config"));
    entry
        .get("multimodal")
        .and_then(Value::as_bool)
        .or_else(|| display.get("multimodal").and_then(Value::as_bool))
        .or_else(|| dev_detail(entry).and_then(|detail| detail.get("multimodal")).and_then(Value::as_bool))
}

fn consumption_rate(entry: &Value) -> Option<f64> {
    let config = embedded(entry.get("display_contact_config"));
    let rate = object_of(&config, &["consumption_rate", "ConsumptionRate"])?;
    if rate.get("enable").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let data = object_of(rate, &["data", "Data"])?;
    let value = number_of(data, &["rate", "Rate"])?;
    (value.is_finite() && value >= 0.0).then_some(value)
}

fn object_of<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|key| value.get(*key)).find(|found| found.is_object())
}

fn number_of(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| match value.get(*key) {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
        _ => None,
    })
}

fn credits_text(rate: f64) -> String {
    let rounded = (rate * 100.0).round() / 100.0;
    let plain = if (rounded - rounded.trunc()).abs() < 1e-9 {
        format!("{}", rounded.trunc() as i64)
    } else {
        format!("{rounded:.2}").trim_end_matches('0').trim_end_matches('.').to_string()
    };
    format!("x{plain} credits")
}

fn positive(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(number) => number.as_i64().or_else(|| number.as_f64().map(|number| number as i64)),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
    .filter(|value| *value > 0)
}

fn embedded(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or(Value::Null),
        Some(value) => value.clone(),
        None => Value::Null,
    }
}

fn text(object: &Value, key: &str) -> String {
    object.get(key).and_then(Value::as_str).unwrap_or_default().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, display: &str, dev: Option<&str>, max: Option<&str>) -> Value {
        let mut details = Vec::new();
        if let Some(model) = dev {
            details.push(json!({"model_name": model, "max_tokens": 8000}));
        }
        if let Some(model) = max {
            details.push(json!({"model_name": model, "max_tokens": 16000}));
        }
        json!({
            "config_name": name,
            "usage": "chat_completion",
            "display_config": {"display_name": display},
            "model_detail_list": details,
            "context_window_tokens": {"dev": 200000, "max": 400000},
            "reasoning_effort_config": {"options": ["low", "high"]},
        })
    }

    #[test]
    fn groups_merge_functions_into_one_model() {
        let groups = vec![
            json!({"function": "chat_v3", "config_info_list": [entry("glm-5.2", "GLM 5.2", Some("glm-5.2__dev"), None)]}),
            json!({"function": "solo_work_lite", "config_info_list": [entry("glm-5.2", "GLM 5.2", Some("glm-5.2__dev"), None)]}),
            // 非聊天 function（不在 CHAT_FUNCTIONS 里）整组丢弃
            json!({"function": "title_generation", "config_info_list": [entry("t", "T", None, None)]}),
        ];
        let catalog = parse(&groups);
        assert_eq!(catalog.models.len(), 1);
        assert_eq!(catalog.models[0]["id"], "glm-5.2");
        assert_eq!(catalog.models[0]["maxInputTokens"], 200000);
        assert_eq!(catalog.models[0]["supportsReasoning"], true);
        let routes = catalog.routes.get("glm-5.2").cloned().unwrap_or_default();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].model_name.as_deref(), Some("glm-5.2__dev"));
    }

    #[test]
    fn max_is_advertised_separately() {
        let groups = vec![json!({
            "function": "chat_v3",
            "config_info_list": [entry("glm-5.2", "GLM 5.2", Some("glm-5.2__dev"), Some("glm-5.2__max"))]
        })];
        let catalog = parse(&groups);
        let ids: Vec<&str> = catalog.models.iter().filter_map(|model| model["id"].as_str()).collect();
        assert_eq!(ids, vec!["glm-5.2", "glm-5.2-max"]);
        let max = catalog.routes.get("glm-5.2-max").cloned().unwrap_or_default();
        assert_eq!(max[0].max_window, Some(400000));
        assert_eq!(max[0].model_name.as_deref(), Some("glm-5.2__max"));
        // 基础模型仍然是 dev 档
        let base = catalog.routes.get("glm-5.2").cloned().unwrap_or_default();
        assert_eq!(base[0].max_window, None);
    }

    #[test]
    fn hidden_and_custom_models_are_not_selectable() {
        let mut hidden = entry("bad", "Bad", Some("bad__dev"), None);
        hidden["hidden"] = json!(true);
        let mut custom = entry("custom_model_1", "Custom", Some("c__dev"), None);
        custom["is_custom_model"] = json!(true);
        let groups = vec![json!({"function": "chat_v3", "config_info_list": [hidden, custom]})];
        let catalog = parse(&groups);
        assert!(catalog.models.is_empty());
    }
}
