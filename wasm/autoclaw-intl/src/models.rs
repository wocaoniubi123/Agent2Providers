//! AutoClaw 模型路由表（移植来源 `autoclaw-local-proxy/autoclaw-models.mjs`）。
//!
//! ── 这不是「远程模型目录」────────────────────────────────────
//! 与 Accio 那种「拉一份远程清单」不同，AutoClaw 的模型集合是**静态映射表**
//! （AutoClaw 1.17.8 设置页目录 + model-provider-config 支持列表），外加远程
//! `autoclaw-model-config`（见 `catalog.rs`，实测 4 条）的两条回退规则。
//! 静态表是**纯数据 + 纯函数**：不读盘、不发请求。
//!
//! ── 两个模型标识（这是 AutoClaw 路由的核心）──────────────────
//! 上游代理用两个不同的标识定位模型（源实现模块头写得很清楚）：
//!
//!   - `X-Request-Model` **请求头**：完整**路由 ID**，带通道前缀
//!     （`zai_auto`、`zaicoding_glm-5.3`、`zai_glm-5.3-flash`）。
//!     路由前缀决定**计费通道**：
//!       `zai_`        → 会员 / 按量付费
//!       `zaicoding_`  → Coding Plan
//!       `zai_auto`    → 让服务端自动选型
//!   - `body.model` **请求体**：**剥掉路由前缀**后的模型 ID
//!     （`glm-5.3` 等）—— 这是 AutoClaw 主进程 Model Broker 的行为。
//!
//! 两者都必须发对：只发对一个，上游要么选错通道计费，要么认不出模型。
//!
//! ── 客户端给的名字可以是三种写法 ─────────────────────────────
//! [`resolve_model_route`] 接受（源实现 `resolveModelRoute`）：
//!   1. 目录条目：`glm-5.3`、`glm-5.3-flash`（目录 ID / 展示名 / 完整 routeId）；
//!   2. 显式路由前缀：`zaicoding_glm-5.3` 这类；
//!   3. 其它合法路由 ID（`x_yyy` 形态）直接透传。
//! 三者都不匹配时**回退默认路由** `zai_auto`（非严格模式）—— 这条回退是兜住
//! Anthropic 客户端那类会传 `claude-*` 的调用方的（源实现注释明说）。
//!
//! ── 目录匹配口径必须与聚合目录一致（一处关键修复）──────────────
//! 目录校验层先比 `id`、再比 `name`，两轮都是 `trim` + 忽略 ASCII 大小写 ——
//! 所以 `GLM-5.3`（展示名）、`Auto` 这类名字在那层是**放行**的。本模块必须用
//! 同一口径（先 id、再展示名、再完整 routeId），否则同一份清单在两个层给出
//! 不同判定：目录放行、路由层却因大小写差异静默回退 `zai_auto` —— 客户端请求
//! `GLM-5.3` 会被换成 `auto`（选错模型 + 走错计费通道）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Value};

use super::region::{self, Region};

/// 默认路由 ID（源实现 `DEFAULT_ROUTE`）。
///
/// lib 编译时没有别处直接读它（`region::default_route()` 才是运行时入口），
/// 测试与排障文档要用这个名字。
#[allow(dead_code)]
pub const DEFAULT_ROUTE: &str = "zai_auto";

/// 已知路由前缀（源实现 `KNOWN_ROUTE_PREFIXES`）。
///
/// **顺序有意义**：剥前缀时先试 `zaicoding_` 再试 `zai_`，
/// 反过来会把 `zaicoding_glm-5.3` 错剥成 `coding_glm-5.3`。
const KNOWN_ROUTE_PREFIXES: &[&str] = &["zaicoding_", "zai_"];

/// 合法路由 ID 的形态（源实现 `ROUTE_ID_PATTERN`）：
/// 小写字母开头 + 下划线 + 1..=127 个 `[A-Za-z0-9._:-]`。
///
/// 手写判定而不是引 regex 依赖：规则只有「开头、分隔符、字符集、长度」四项，
/// 一个纯函数足够。
fn is_route_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    // 首个 `_` 之前必须全是小写字母 / 数字（`[a-z][a-z0-9]*`）
    let mut prefix_len = 0usize;
    for &byte in rest {
        if byte == b'_' {
            break;
        }
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() {
            return false;
        }
        prefix_len += 1;
    }
    if prefix_len >= rest.len() || rest[prefix_len] != b'_' {
        return false;
    }
    let tail = &rest[prefix_len + 1..];
    if tail.is_empty() || tail.len() > 127 {
        return false;
    }
    tail.iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// 剥掉已知路由前缀：`zaicoding_glm-5.3` → `glm-5.3`；没有前缀原样返回。
pub fn strip_route_prefix(route_id: &str) -> &str {
    for prefix in KNOWN_ROUTE_PREFIXES {
        if let Some(rest) = route_id.strip_prefix(prefix) {
            return rest;
        }
    }
    route_id
}

/// 一次模型路由解析的结果（源实现 `resolveModelRoute` 的返回对象）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRoute {
    /// 完整路由 ID → 发进 `X-Request-Model` 请求头
    pub route_model_id: String,
    /// 剥前缀后的模型 ID → 填进 `body.model`
    pub body_model_id: String,
    /// 客户端原样请求的模型名（响应回写用）
    pub requested_model: String,
}

/// 模型目录条目（源实现 `MODELS` 的每一项）。
struct ModelEntry {
    /// 目录 ID（也是客户端最常给的那个名字）：`glm-5.3`
    id: &'static str,
    /// 完整路由 ID（带通道前缀）
    route_id: &'static str,
    /// 展示名：`GLM-5.3`
    name: &'static str,
    /// 是否支持思考/reasoning
    reasoning: bool,
    /// 是否支持图片输入
    support_image: bool,
    /// 上下文窗口（token）
    context_window: i64,
    /// 单次最大输出（token）
    max_tokens: i64,
}

/// 静态模型路由表（对齐**实际客户端软件当前提供的模型**）。
///
/// **顺序即 /v1/models 的展示顺序**，改动会直接反映到客户端看到的列表。
/// 源代理实现移植了 1.17.8 设置页目录的 9 个条目，但实际软件的模型选择器
/// 当前只提供 **GLM-5.3 与 GLM-5.3-Flash** 两个（其余条目在软件里已下架），
/// 这里按实际软件收敛为两个 —— 网关能广告与转发的模型不应比真实客户端更多。
///
/// 注意「目录条目」与「路由回退」是两回事：`zai_auto` 默认路由、显式路由
/// 前缀透传、`x_yyy` 形态识别都还在（见 [`resolve_model_route`]）。
const MODELS: &[ModelEntry] = &[
    ModelEntry {
        id: "glm-5.3",
        route_id: "zaicoding_glm-5.3",
        name: "GLM-5.3",
        reasoning: true,
        support_image: false,
        context_window: 1_048_576,
        max_tokens: 307_200,
    },
    ModelEntry {
        id: "glm-5.3-flash",
        route_id: "zai_glm-5.3-flash",
        name: "GLM-5.3-Flash",
        reasoning: true,
        support_image: true,
        context_window: 1_048_576,
        max_tokens: 131_072,
    },
];

/// 目录里按 id 查条目
fn entry_by_id(id: &str) -> Option<&'static ModelEntry> {
    MODELS.iter().find(|entry| entry.id == id)
}

/// 按**聚合目录的口径**认一个目录条目：先 `id`、再展示名 `name`、最后完整
/// `routeId`，三轮都是 `trim` + 忽略 ASCII 大小写。
///
/// 前两轮与目录校验逐字同口径（见模块头的「关键修复」）。
fn entry_by_catalog_name(name: &str) -> Option<&'static ModelEntry> {
    let same = |text: &str| text.eq_ignore_ascii_case(name);
    MODELS
        .iter()
        .find(|entry| same(entry.id))
        .or_else(|| MODELS.iter().find(|entry| same(entry.name)))
        .or_else(|| MODELS.iter().find(|entry| same(entry.route_id)))
}

/// 把客户端传入的 model 解析成上游路由。
///
/// 判定顺序（在源实现的顺序上只放宽「目录条目怎么认」，其余逐条对齐）：
///   1. 空值 → 默认路由（`requested_model` 也回落成默认路由名）；
///   2. 目录条目命中 → 用条目的规范 routeId 与剥前缀后的 body 模型 ID；
///   3. 远程目录命中 → 用它给的路由 ID（静态表里没有的 `zai_auto-fast` 这类）；
///   4. 已知前缀开头 → 原样当路由 ID，body 剥前缀（大小写原样保留）；
///   5. 合法路由 ID 形态 → 原样透传；
///   6. 都不中 → 默认路由（只兜真正未知的名字）。
///
/// `region` 决定默认路由的覆盖设置与远程目录读哪一格缓存。
pub fn resolve_model_route(region: Region, raw_model: &str) -> ModelRoute {
    let name = raw_model.trim();
    let fallback = default_route_for(region);
    if name.is_empty() {
        return ModelRoute {
            body_model_id: strip_route_prefix(&fallback).to_string(),
            requested_model: fallback.clone(),
            route_model_id: fallback,
        };
    }
    if let Some(entry) = entry_by_catalog_name(name) {
        return ModelRoute {
            route_model_id: entry.route_id.to_string(),
            body_model_id: strip_route_prefix(entry.route_id).to_string(),
            requested_model: name.to_string(),
        };
    }
    // 远程目录命中：用它给的路由 ID（静态表里没有的模型 —— 实测多出
    // `zai_auto` / `zai_auto-fast`）。**必须放在兜底之前**，否则这些模型会
    // 静默回退默认路由：客户端要 A 却跑了 B，而且日志上只看到一次「成功」。
    if let Some(route_id) = super::catalog::remote_route_id(region, name) {
        return ModelRoute {
            body_model_id: strip_route_prefix(&route_id).to_string(),
            requested_model: name.to_string(),
            route_model_id: route_id,
        };
    }
    for prefix in KNOWN_ROUTE_PREFIXES {
        if name.starts_with(prefix) {
            return ModelRoute {
                route_model_id: name.to_string(),
                body_model_id: strip_route_prefix(name).to_string(),
                requested_model: name.to_string(),
            };
        }
    }
    if is_route_id(name) {
        return ModelRoute {
            route_model_id: name.to_string(),
            body_model_id: strip_route_prefix(name).to_string(),
            requested_model: name.to_string(),
        };
    }
    // 兜底：清单里没有、也不像路由 ID 的名字 → 回落到默认路由 `zai_auto`。
    //
    // ── 与网关内置版的唯一分歧（有意，改之前先读）──────────────
    // 内置版这里前面还有一档 `model_rules::is_custom(provider, name)`（用户
    // 手动登记的自定义模型原样透传）。那个判据读的是**网关的用户配置**，
    // 插件进程拿不到 —— 插件不猜，一律走「回落默认路由」这条内置版的兜底。
    // 真正受影响的只有「既不在目录、也不是路由 ID 形态」的名字，那种名字
    // 透传给上游只会换一个「模型不存在」。
    ModelRoute {
        body_model_id: strip_route_prefix(&fallback).to_string(),
        requested_model: name.to_string(),
        route_model_id: fallback,
    }
}

/// 默认路由（带地区的设置覆盖）。
fn default_route_for(region: Region) -> String {
    let _ = region;
    region::default_route()
}

/// 模型清单（聚合层认的**上游原始形态**）。
///
/// ── 远程目录优先 ────────────────────────────────────────────
/// 上游有 `GET .../proxy/autoclaw-model-config`（见 [`super::catalog`]），
/// 实测返回 4 条，而静态表只有 2 条 —— 缺的 `zai_auto` 恰恰是本家
/// `default_route()` 的回退目标。远程不可用（未登录 / 网络不通）时回落静态表，
/// 于是 `/v1/models` 在两种状态下都非空。
pub fn list() -> Vec<Value> {
    let remote = super::catalog::remote_models();
    if !remote.is_empty() {
        return remote;
    }
    MODELS
        .iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "name": entry.name,
                "routeId": entry.route_id,
                "maxInputTokens": entry.context_window,
                "maxOutputTokens": entry.max_tokens,
                "supportsImages": entry.support_image,
                "supportsReasoning": entry.reasoning,
                // AutoClaw 的目录里没有工具调用能力位（源实现也没给），
                // 但上游是 OpenAI 兼容网关，工具调用可用 —— 与源
                // `modelListResponse` 不给该字段相比，这里显式给 true，
                // 因为聚合层的 `supports_tool_call` 缺失时会输出 false，
                // 会让客户端以为这批模型不能调工具
                "supportsToolCall": true,
            })
        })
        .collect()
}

/// AutoClaw 的**能力探测**：该模型是否支持图片输入。
///
/// 入参既可以是目录 id（`glm-5.3-flash`），也可以是带前缀的路由 ID
/// （`zai_glm-5.3-flash`）。目录外的名字返回 **false**（保守）。
/// 目录条目里的 `supportsImages` 已经由 [`list`] 直接给出（聚合层读它），
/// 本函数是给「按名字问一个纯函数答案」的排障口留的。
#[allow(dead_code)]
pub fn supports_image(name: &str) -> bool {
    let trimmed = name.trim();
    if let Some(entry) = entry_by_id(trimmed) {
        return entry.support_image;
    }
    for prefix in KNOWN_ROUTE_PREFIXES {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            if let Some(entry) = entry_by_id(rest) {
                return entry.support_image;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 目录名 / 展示名 / 完整路由 ID 三种写法都解析到同一条路由。
    #[test]
    fn catalog_names_resolve_to_canonical_route() {
        for name in ["glm-5.3", "GLM-5.3", "zaicoding_glm-5.3"] {
            let route = resolve_model_route(region::REGION, name);
            assert_eq!("zaicoding_glm-5.3", route.route_model_id);
            assert_eq!("glm-5.3", route.body_model_id);
        }
    }

    /// 未知名字回退默认路由；显式路由形态原样透传（大小写不改）。
    #[test]
    fn unknown_falls_back_and_route_ids_pass_through() {
        let route = resolve_model_route(region::REGION, "claude-3-5-sonnet");
        assert_eq!(DEFAULT_ROUTE, route.route_model_id);
        assert_eq!("auto", route.body_model_id);
        let route = resolve_model_route(region::REGION, "zai_glm-4.6v");
        assert_eq!("zai_glm-4.6v", route.route_model_id);
        assert_eq!("glm-4.6v", route.body_model_id);
    }

    /// 默认路由要能剥前缀（`zai_auto` → `auto`），否则 body.model 会带上通道名。
    #[test]
    fn default_route_is_stripped() {
        let route = resolve_model_route(region::REGION, "");
        assert_eq!("zai_auto", route.route_model_id);
        assert_eq!("auto", route.body_model_id);
    }
}
