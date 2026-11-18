//! Antigravity / Gemini v1internal 的**工具参数 JSON Schema 清洗**。
//!
//! ── 为什么必须清洗（不是洁癖）────────────────────────────────
//! Gemini 的 `Schema` proto **没有**这些 JSON Schema 关键字，出现一个就是
//! 上游 400「Unknown name …: Cannot find field」，整条请求被拒。
//!
//! ── 三遍的顺序有意义 ────────────────────────────────────────
//!   1. `merge_structure`：`type` 数组取第一个非 null（Gemini 只认单值）、
//!      **`type` 值转小写**、`const`→`enum`、`enum` 值转字符串并补 `type`、
//!      `anyOf`/`oneOf` 选最优分支、`allOf` 合并 properties/required；
//!   2. `strip_keys`：删掉 [`UNSUPPORTED_SCHEMA_KEYS`] 与 `x-` 前缀扩展；
//!   3. `finalize_structure`：有 `properties` 缺 `type` → `object`、
//!      `array` 必须有 `items`、`required` 只留 properties 里存在的键、
//!      空对象 schema 补 `reason` 占位（Antigravity 要求 parameters 非空）。
//!
//! ── 与参考实现的一处刻意差异 ─────────────────────────────────
//! 递归只进 **子 schema**（`properties` 的每个值、`items`），不进
//! `properties` 这个**容器本身**：JS 版在容器层也做键删除，于是工具参数里
//! 名叫 `format` / `title` / `default` 的属性会被误删。本包按「容器不是
//! schema」处理，那条误伤不存在。

use agent2api_wasm_sdk::{json, Value};

/// 上游不认的 JSON Schema 键（`x-` 前缀的厂商扩展也一律去掉）。
const UNSUPPORTED_SCHEMA_KEYS: &[&str] = &[
    "minLength",
    "maxLength",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minItems",
    "maxItems",
    "format",
    "multipleOf",
    "uniqueItems",
    "contains",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contentSchema",
    "prefixItems",
    "additionalItems",
    "default",
    "examples",
    "$schema",
    "$defs",
    "definitions",
    "const",
    "$ref",
    "$comment",
    "deprecated",
    "readOnly",
    "writeOnly",
    "additionalProperties",
    "propertyNames",
    "patternProperties",
    "enumDescriptions",
    "anyOf",
    "oneOf",
    "allOf",
    "not",
    "dependencies",
    "dependentSchemas",
    "dependentRequired",
    "title",
    "optional",
    "if",
    "then",
    "else",
    "contentMediaType",
    "contentEncoding",
    "cornerRadius",
    "fillColor",
    "fontFamily",
    "fontSize",
    "fontWeight",
    "gap",
    "padding",
    "strokeColor",
    "strokeThickness",
    "textColor",
];

/// 工具参数 schema 清洗：结构归并 → 去不支持键 → 补 Gemini 要求的形态。
pub fn clean_schema(schema: &Value) -> Value {
    let mut out = if schema.is_object() { schema.clone() } else { json!({}) };
    merge_structure(&mut out);
    strip_keys(&mut out);
    finalize_structure(&mut out);
    out
}

/// 递归进入一个 schema 的**子 schema**（`properties` 的值、`items`）。
fn for_each_child(object: &mut serde_json::Map<String, Value>, visit: &mut dyn FnMut(&mut Value)) {
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        for schema in properties.values_mut() {
            visit(schema);
        }
    }
    if let Some(items) = object.get_mut("items") {
        match items {
            Value::Object(_) => visit(items),
            Value::Array(list) => {
                for item in list {
                    visit(item);
                }
            }
            _ => {}
        }
    }
}

/// 值的字符串形态（数字/布尔转字面量，null → 空串）。
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => String::new(),
    }
}

fn merge_structure(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    // `type` 数组 → 第一个非 null；值转小写。
    if let Some(Value::Array(types)) = object.get("type") {
        let chosen = types
            .iter()
            .find(|value| value.as_str().is_none_or(|text| !text.eq_ignore_ascii_case("null")))
            .cloned();
        if let Some(chosen) = chosen {
            object.insert("type".to_string(), chosen);
        }
    }
    if let Some(Value::String(kind)) = object.get("type").cloned() {
        object.insert("type".to_string(), Value::String(kind.to_ascii_lowercase()));
    }
    // `const` → `enum`（单个值）。
    if let Some(constant) = object.remove("const") {
        object.insert("enum".to_string(), json!([text_of(&constant)]));
    }
    // `enum` 值转字符串并补 type。
    if let Some(Value::Array(values)) = object.get("enum").cloned() {
        let values: Vec<Value> = values.iter().map(|value| Value::String(text_of(value))).collect();
        object.insert("enum".to_string(), Value::Array(values));
        object
            .entry("type".to_string())
            .or_insert_with(|| Value::String("string".to_string()));
    }
    // anyOf / oneOf → 选最优分支（第一个不含 null 的对象分支）。
    for key in ["anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = object.get(key).cloned() else {
            continue;
        };
        object.remove(key);
        let chosen = branches
            .iter()
            .find(|branch| branch.is_object())
            .or_else(|| branches.first())
            .cloned();
        if let Some(chosen) = chosen {
            if let Some(chosen) = chosen.as_object() {
                for (name, value) in chosen {
                    object.entry(name.clone()).or_insert_with(|| value.clone());
                }
            }
        }
    }
    // allOf → 合并 properties / required。
    if let Some(Value::Array(branches)) = object.remove("allOf") {
        let mut properties = serde_json::Map::new();
        let mut required: Vec<Value> = Vec::new();
        for branch in &branches {
            if let Some(map) = branch.get("properties").and_then(Value::as_object) {
                for (name, value) in map {
                    properties.insert(name.clone(), value.clone());
                }
            }
            if let Some(list) = branch.get("required").and_then(Value::as_array) {
                for item in list {
                    if !required.contains(item) {
                        required.push(item.clone());
                    }
                }
            }
        }
        if !properties.is_empty() {
            object.insert("properties".to_string(), Value::Object(properties));
        }
        if !required.is_empty() {
            object.insert("required".to_string(), Value::Array(required));
        }
    }
    for_each_child(object, &mut |child| merge_structure(child));
}

fn strip_keys(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    object.retain(|key, _| {
        !UNSUPPORTED_SCHEMA_KEYS.iter().any(|bad| bad == key) && !key.starts_with("x-")
    });
    for_each_child(object, &mut |child| strip_keys(child));
}

fn finalize_structure(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if object.get("properties").is_some() && object.get("type").is_none() {
        object.insert("type".to_string(), Value::String("object".to_string()));
    }
    if object.get("type").and_then(Value::as_str) == Some("array") && object.get("items").is_none() {
        object.insert("items".to_string(), json!({ "type": "string" }));
    }
    if let Some(Value::Array(required)) = object.get("required").cloned() {
        let known: Vec<String> = object
            .get("properties")
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        let kept: Vec<Value> = required
            .into_iter()
            .filter(|item| item.as_str().is_some_and(|name| known.iter().any(|key| key == name)))
            .collect();
        if kept.is_empty() {
            object.remove("required");
        } else {
            object.insert("required".to_string(), Value::Array(kept));
        }
    }
    // 空对象 schema 补占位（Antigravity 要求 parameters 非空）。
    let empty_object = object.get("type").and_then(Value::as_str) == Some("object")
        && object
            .get("properties")
            .and_then(Value::as_object)
            .is_none_or(|map| map.is_empty());
    if empty_object {
        object.insert(
            "properties".to_string(),
            json!({ "reason": { "type": "string", "description": "Call reason." } }),
        );
    }
    for_each_child(object, &mut |child| finalize_structure(child));
}
