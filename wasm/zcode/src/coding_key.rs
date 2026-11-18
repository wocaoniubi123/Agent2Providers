//! 编码套餐凭证换取：把 OAuth 登录拿到的 `access_token` 换成**能用于推理的
//! API Key**（native `zcode/coding_key.rs` 的移植）。
//!
//! ── 为什么必须有这一步（曾经漏掉的根因）─────────────────────
//! OAuth 轮询给的 `access_token` **不是**推理凭证：直接拿它去
//! `{openai_base}/chat/completions` 会被上游按「OAuth 令牌」那条路校验并回 401
//! （`token expired or incorrect` / `Authentication Failed`）。官方客户端与
//! 参考实现都先做一次换取，拿到的才是编码套餐的 API Key：
//!
//! ```text
//!   z/login（仅国际版）→ 查默认机构/项目 → 找或建名为 zcode-api-key 的密钥
//!     → 取 secretKey → 拼成 {apiKey}.{secret}
//! ```
//!
//! 国际版**拿不到 secretKey 就判登录失败**（理由是「宁可登录失败，也不要落一条
//! 永远签不了名、发出去必 401 的凭证」）；**国内版不这样** —— 拿不到 secret 时
//! 退回单段 `apiKey`，那一形态在开放平台同样可用。这是两地刻意保留的差异。
//!
//! ── 国内版与 native 的三处分支（都是 `Region::Cn` 那一侧）──
//!   1. **不**多那一步 `POST {host}/api/auth/z/login`：OAuth 令牌直接当 biz 令牌；
//!   2. 业务接口的 `Authorization` 头是**裸令牌**（国际版才是 `Bearer {bizToken}`）；
//!   3. 必须有 secretKey **不是**硬要求：拿不到就退回单段 `apiKey`。
//!
//! 三处照 native `coding_key::resolve` 的 `match region` 逐条搬过来 —— 这是
//! 两地最容易「看起来一样」却行为不同的一段。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! `panic = "abort"`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::common::{integer_of, path_encode, text_of};
use super::{http, region};

/// 网关在用户账号里认的密钥名（参考实现 `ZAI_API_KEY_NAME`）。
///
/// 它同时是「复用」的判据：同名密钥已存在就直接用，不存在才新建 —— 于是重复
/// 登录不会在用户账号里堆出一串同名密钥。
const KEY_NAME: &str = "zcode-api-key";

/// 默认机构 / 默认项目的名字片段（上游会返回该账号下的全部机构与项目，
/// 官方客户端用的是「默认机构 / 默认项目」那一个）。
const DEFAULT_ORG_MARKER: &str = "默认机构";
const DEFAULT_PROJECT_MARKER: &str = "默认项目";

/// 换取编码套餐凭证：成功返回**直接可用的**推理凭证串。
///
/// 国内版有两种落点：有 secretKey 时是 `{apiKey}.{secret}`，没有时是单段
/// `{apiKey}` —— 两者都直接进 `Authorization: Bearer <它>`。
///
/// 失败一律返回可读中文（带上游 `msg`），由调用方决定怎么落 —— 登录链上它是
/// 「登录失败」的原因，而不是一条静默的半成品账号。
pub fn resolve(access_token: &str) -> Result<String> {
    let oauth_token = access_token.trim();
    if oauth_token.is_empty() {
        return Err(Error::http(401, "ZCode 登录响应里没有可换取推理凭证的登录态"));
    }
    let host = region::BIZ_HOST;
    // 国内版：OAuth 令牌直接当 biz 令牌（没有 `/api/auth/z/login` 那一步）。
    let biz_token = oauth_token.to_string();
    // 国内版业务接口的 `Authorization` 是**裸令牌**，不套 `Bearer`
    // （native `Region::Cn => biz_token`；套上 Bearer 会被这一地的业务网关拒）。
    let authorization = biz_token;
    let (org_id, project_id) = customer_info(host, &authorization)?;
    let api_key = find_or_create_api_key(host, &authorization, &org_id, &project_id)?;
    let secret = copy_secret_key(host, &authorization, &org_id, &project_id, &api_key)?;
    // 国内版拿不到 secret 也能用（单段 API Key）：只有两段都在才拼
    // `{apiKey}.{secret}` —— 这与国际版「没 secret 就判登录失败」是**刻意的
    // 地区差异**（native `Region::Cn if secret.trim().is_empty() => Ok(api_key)`）。
    if secret.trim().is_empty() {
        return Ok(api_key);
    }
    Ok(format!("{api_key}.{secret}"))
}

// 国内版没有 `z_login`（`POST {host}/api/auth/z/login`）这一步：
// native 只在 `Region::Intl` 分支里调它，国内版直接把 OAuth 令牌当 biz 令牌。
// 那个接口的形状（`access_token` / `accessToken` / `data.access_token` 三种位置）
// 因此在国内版这条链上用不到，本文件不再保留它的实现 —— 保留一份没有调用方的
// 死代码，后来者会误以为国内版也要先换一次 biz 令牌。

/// 查默认机构与默认项目。
fn customer_info(host: &str, authorization: &str) -> Result<(String, String)> {
    let url = format!("{host}/api/biz/customer/getCustomerInfo");
    let payload = biz_request("GET", &url, authorization, None)?;
    let orgs = payload
        .get("organizations")
        .or_else(|| payload.get("orgs"))
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：该账号下没有可用机构"))?;
    let org = orgs
        .iter()
        .find(|item| {
            org_name(item)
                .map(|name| name.contains(DEFAULT_ORG_MARKER))
                .unwrap_or(false)
        })
        .or_else(|| orgs.first())
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：该账号下没有可用机构"))?;
    let org_id = pick_id(org, &["organizationId", "id", "orgId"])
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：机构缺少标识"))?;
    let projects = org
        .get("projects")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：默认机构下没有可用项目"))?;
    let project = projects
        .iter()
        .find(|item| {
            project_name(item)
                .map(|name| name.contains(DEFAULT_PROJECT_MARKER))
                .unwrap_or(false)
        })
        .or_else(|| projects.first())
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：默认机构下没有可用项目"))?;
    let project_id = pick_id(project, &["projectId", "id"])
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：项目缺少标识"))?;
    Ok((org_id, project_id))
}

/// 找同名密钥，没有就建一个（见 [`KEY_NAME`] 的说明）。
fn find_or_create_api_key(
    host: &str,
    authorization: &str,
    org_id: &str,
    project_id: &str,
) -> Result<String> {
    let url = format!("{host}/api/biz/v1/organization/{org_id}/projects/{project_id}/api_keys");
    // 列表失败不致命（参考实现同样是 `catch { /* will create */ }`）：没有列表
    // 权限但能建密钥的账号依然可用。真正的失败留给「建也失败」那一步。
    if let Ok(payload) = biz_request("GET", &url, authorization, None) {
        let found = payload
            .as_array()
            .into_iter()
            .flatten()
            .find(|item| {
                item.get("name").and_then(Value::as_str) == Some(KEY_NAME)
                    && item
                        .get("apiKey")
                        .and_then(Value::as_str)
                        .map(|key| !key.trim().is_empty())
                        .unwrap_or(false)
            })
            .and_then(|item| item.get("apiKey").and_then(Value::as_str))
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());
        if let Some(key) = found {
            return Ok(key);
        }
    }
    let body = json!({ "name": KEY_NAME });
    let created = biz_request("POST", &url, authorization, Some(&body))?;
    created
        .get("apiKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::http(502, "ZCode 登录换取失败：上游未返回新建密钥"))
}

/// 取密钥的 secret（`api_keys/copy/{apiKey}`）。
///
/// 失败与「没给 secret」在这里**同义**（都返回空串）：国内版于是退回单段
/// `apiKey`（见 [`resolve`]）—— 这样区分的是「地区要求」，而不是把上游的一次
/// 404 直接变成登录失败。
fn copy_secret_key(
    host: &str,
    authorization: &str,
    org_id: &str,
    project_id: &str,
    api_key: &str,
) -> Result<String> {
    let url = format!(
        "{host}/api/biz/v1/organization/{org_id}/projects/{project_id}/api_keys/copy/{}",
        path_encode(api_key)
    );
    let Ok(payload) = biz_request("GET", &url, authorization, None) else {
        return Ok(String::new());
    };
    Ok(payload
        .get("secretKey")
        .or_else(|| payload.get("secret_key"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string())
}

/// 一次业务接口调用：按参考实现 `requestBizApi` 的信封语义解包。
///
/// `authorization` 为空表示**不发这个头**。国内版这条链上没有匿名接口了
/// （`z/login` 那一步本包不调），但判据保留：发一个空的 `Authorization` 会让
/// 部分网关直接判 401，而不是当成没带。
fn biz_request(
    method: &str,
    url: &str,
    authorization: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let mut headers: Vec<(String, String)> = Vec::new();
    if !authorization.trim().is_empty() {
        headers.push(("Authorization".to_string(), authorization.to_string()));
    }
    let reply = http::send(method, url, &headers, body)
        .map_err(|error| http::transport_error("ZCode 登录换取失败", &error))?;
    // 信封判定与参考实现同序：`code` 缺失视为成功（有的接口直接回数据体），
    // 取值 0 / 200（数字或字符串）都算成功。
    if let Some(code) = reply
        .payload
        .get("code")
        .or_else(|| reply.payload.get("status"))
    {
        if !biz_code_ok(code) {
            let message = text_of(&reply.payload, &["msg", "message"]);
            return Err(Error::http(
                502,
                format!(
                    "ZCode 登录换取被拒：{}",
                    if message.is_empty() { "上游未说明原因" } else { &message }
                ),
            ));
        }
    }
    Ok(reply
        .payload
        .get("data")
        .cloned()
        .unwrap_or(reply.payload))
}

/// `code` 是不是成功值（0 / 200，数字与字符串两种写法都认）。
fn biz_code_ok(code: &Value) -> bool {
    if let Some(number) = integer_of(code) {
        return number == 0 || number == 200;
    }
    matches!(
        code.as_str().map(str::trim),
        Some("0") | Some("200") | Some("")
    )
}

/// 机构 / 项目的展示名（上游不同版本用过 `organizationName` / `name` 等）。
fn org_name(item: &Value) -> Option<&str> {
    item.get("organizationName")
        .or_else(|| item.get("name"))
        .and_then(Value::as_str)
}

fn project_name(item: &Value) -> Option<&str> {
    item.get("projectName")
        .or_else(|| item.get("name"))
        .and_then(Value::as_str)
}

/// 从候选键里取第一个非空字符串（上游的 id 字段名换过几轮）。
fn pick_id(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
