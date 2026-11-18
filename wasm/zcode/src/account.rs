//! ZCode 账号：凭证形态、公开视图、去重身份与取令牌（native `zcode/mod.rs`
//! 的账号段 + `credentials.rs` 的移植）。
//!
//! ── 这一家的凭证为什么是三个字段 ─────────────────────────────
//! 一次 OAuth 完成会同时拿到**两样东西**：
//!
//!   - `accessToken`：推理平面用的访问令牌（国内版打 `open.bigmodel.cn` 的
//!     编码套餐端点；国际版打 `api.z.ai`）
//!   - `jwt`：ZCode 套餐令牌（打 `zcode.z.ai` 的领取 / 余额接口）
//!
//! 两者**不能互相替代**：推理走开放平台的编码套餐端点，领取走 ZCode 自己的
//! billing 接口，各认各的。只存 accessToken 的话领取功能会直接不可用。
//!
//! 第三个字段 `deviceMid` 不是凭证，而是**上游的硬要求**：领取 / 余额接口都
//! 要求一个 UUID 形态的 `X-Device-Mid`，缺它会被以 biz 3001「参数错误」拒掉。
//! 它必须**跨请求稳定**（风控会把同一个设备标识的多次请求关联起来），因此
//! 生成一次就随凭证落盘，而不是每次请求现编一个。
//!
//! ── 「使用哪个套餐」是账号级设置 ─────────────────────────────
//! `zcodePlan` 只有两个取值（`coding-plan` 默认 / `start-plan`）。为什么必须
//! 让用户选：**编码套餐与套餐池是两份独立的额度**（编码套餐到期后走 OpenAI
//! 通道恒回 429「您的GLM Coding Plan套餐已到期」，而活动领到的额度只能从
//! `zcode.z.ai` 的 anthropic 端点花掉）。走错门的症状是业务拒绝而不是鉴权
//! 失败，所以它是设置项而不是自动探测。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::common::{new_uuid, secret_text, token_tail};
use super::region;

/// 账号记录上的「用哪条通道」字段名（界面读同一个名字）。
///
/// 带 `zcode` 前缀而不是光叫 `plan`：账号记录是各家共用的一张形状，`plan`
/// 这个词在别家都有各自含义，裸名迟早撞车。
pub const PLAN_FIELD: &str = "zcodePlan";

/// 编码套餐通道（默认值）：开放平台的 OpenAI 兼容端点 + `accessToken`
pub const PLAN_CODING: &str = "coding-plan";

/// 套餐池通道：`zcode.z.ai` 的 Anthropic 端点 + 套餐 `jwt`
pub const PLAN_START: &str = "start-plan";

/// 归一化通道取值：只认上面两个常量，其余（含空值）返回 None。
pub fn normalize_plan(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        PLAN_CODING => Some(PLAN_CODING),
        PLAN_START => Some(PLAN_START),
        _ => None,
    }
}

/// 账号用哪条通道。缺失 / 认不出 = [`PLAN_CODING`]（存量账号的默认）。
pub fn plan_of(secret: &Value) -> &'static str {
    secret
        .get(PLAN_FIELD)
        .and_then(Value::as_str)
        .and_then(normalize_plan)
        .unwrap_or(PLAN_CODING)
}

/// 通道的展示名（账号页下拉、变更提示与错误文案共用这一处措辞）。
///
/// Start Plan 这条叫「**套餐池**」而不是早期的「活动套餐」：那个池子里除了
/// 官方限时活动发放的额度，还有新注册用户的免费体验额度 —— 叫「活动套餐」
/// 会让恰恰最需要这条通道的用户以为与己无关。
pub fn plan_label(plan: &str) -> &'static str {
    match plan {
        PLAN_START => "套餐池（Start Plan）",
        _ => "编码套餐（Coding Plan）",
    }
}

/// 读当前账号记录（`{id, secret, public, identity, …}`）。
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 记录里的凭证原值。
pub fn secret() -> Result<Value> {
    let record = record()?;
    Ok(record.get("secret").cloned().unwrap_or(Value::Null))
}

/// 从记录里取访问令牌（编码套餐通道用）。
pub fn access_token(secret: &Value) -> String {
    secret_text(secret, &["accessToken", "access_token", "apiKey", "api_key"])
}

/// 从记录里取套餐 JWT（领取 / 余额通道用）。
pub fn jwt(secret: &Value) -> String {
    secret_text(secret, &["jwt", "token"])
}

/// 从记录里取设备标识。
pub fn device_mid(secret: &Value) -> String {
    secret_text(secret, &["deviceMid", "device_mid"])
}

/// 从记录里取上游用户 id。
pub fn user_id(secret: &Value) -> String {
    secret_text(secret, &["userId", "user_id"])
}

/// 取可用令牌（`token.ensure`）：按账号的通道分支，**不续期**。
///
/// 缺字段时的文案逐字照抄 native：说清是哪条通道缺哪个字段，而不是一句
/// 「凭证无效」—— 这个家的字段名（`jwt` / `accessToken`）是用户能自己去
/// 账号页核对的。
pub fn ensure_token() -> Result<String> {
    let secret = secret()?;
    if secret.is_null() {
        return Err(Error::http(401, "没有可用的 ZCode 账号，请先在账号页添加"));
    }
    let plan = plan_of(&secret);
    let token = match plan {
        PLAN_START => jwt(&secret),
        _ => access_token(&secret),
    };
    if token.is_empty() {
        let field = if plan == PLAN_START { "jwt" } else { "accessToken" };
        return Err(Error::http(
            400,
            format!(
                "ZCode 账号的 {} 凭据字段缺失（{field}）：请检查导入记录及存储形态；\
                 重新登录不能修复字段序列化错误",
                plan_label(plan)
            ),
        ));
    }
    Ok(token)
}

/// 401 后的强制刷新：本家尚未实现续期，如实报错让用户重新登录。
///
/// **不要**在这里回落到「再读一次账号」—— 那正是编排层已经做过的动作，返回
/// 同一个被拒的 token 会让「刷新后重试一次」退化成一次无意义的重复请求。
pub fn refresh_token() -> Result<String> {
    Err(Error::http(
        401,
        "ZCode 的登录态无法自动续期，请在账号页重新登录该账号",
    ))
}

/// 凭证是否「临期」（`token.expiring`）。
///
/// 恒 `false`：上游没有续期协议，也没有可信的到期时刻可用作主动刷新的判据
/// （JWT 的 `exp` 只当展示用）。声称临期会让网关每轮白刷一次。
pub fn expiring() -> bool {
    false
}

/// 从令牌里读出过期时刻（**毫秒**，账号页的「有效期」列）。
///
/// 取值链：`access_token` → `jwt`（上游给的访问令牌未必是 JWT，而套餐 JWT
/// 一定是）。都解不出时返回 None（那一列空着，比编一个假时间诚实）。
pub fn expires_at_ms(secret: &Value) -> Option<f64> {
    jwt_expires_at_ms(&access_token(secret)).or_else(|| jwt_expires_at_ms(&jwt(secret)))
}

/// 解一个 JWT 的 payload 段取 `exp`（秒 → 毫秒）。解不出返回 None。
///
/// 不校验签名：这里只读一个展示用的时间戳，而令牌是上游刚下发的。
fn jwt_expires_at_ms(token: &str) -> Option<f64> {
    let payload = token.trim().split('.').nth(1)?;
    let decoded = super::common::base64url_decode(payload.trim_end_matches('='))?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let exp = value.get("exp").and_then(Value::as_f64)?;
    // 上游若给的是毫秒（少数实现这么干），别再乘一次
    Some(if exp > 1e12 { exp } else { exp * 1000.0 })
}

/// 公开视图（账号页读的那几个键；键名与网关的既有约定一致）。
pub fn view(secret: &Value) -> Value {
    let access = access_token(secret);
    let token_jwt = jwt(secret);
    let id = user_id(secret);
    let email = secret_text(secret, &["email"]);
    let name = {
        let explicit = secret_text(secret, &["name"]);
        if !explicit.is_empty() {
            explicit
        } else if !email.is_empty() {
            email.clone()
        } else if !id.is_empty() {
            format!("ZCode {} · {id}", region::LABEL)
        } else {
            format!("ZCode {}", region::LABEL)
        }
    };
    let token = if !access.is_empty() { access.clone() } else { token_jwt.clone() };
    let plan = plan_of(secret);
    let mut view = json!({
        "name": name,
        "userId": id,
        "plan": plan,
        "planLabel": plan_label(plan),
        "tokenTail": token_tail(&token),
        "hasSession": !token.is_empty(),
        // 上游没有续期协议 —— 界面据此不渲染「刷新」按钮
        "canRefresh": false,
        "canClaim": !token_jwt.is_empty(),
    });
    if let Some(expires_at) = expires_at_ms(secret) {
        view["expiresAt"] = json!(expires_at);
    }
    if !email.is_empty() {
        view["email"] = json!(email);
    }
    view
}

/// 账号的稳定身份（去重用）：`<地区前缀><user_id>`。
///
/// 与网关 `ZcodeCredentials::account_id` 同一口径 —— 两地的记录天然不相交
/// （同一个人在两套系统里的 user_id 可能相同）。
///
/// ── 与 native 的一处差异（`accounts.identity.v1` 的硬要求）────
/// native 的 `identity_of` 在 `userId` 为空时返回**空串**（网关退化成按凭证
/// 内容去重）。宿主对声明了 `accounts.identity.v1` 的插件要求「稳定、非空的
/// 账号身份」—— 空串会被直接拒绝，于是手工粘贴 API Key 建的账号根本加不进来。
/// 因此这里对没有 `userId` 的账号用**凭证摘要**派生身份（`credential-<hex>`）：
/// 同一份凭证永远得到同一个 id（稳定），换一份凭证就是另一个账号（不同），
/// 正好满足「稳定且可区分」这条要求。
pub fn identity(secret: &Value) -> String {
    let id = user_id(secret);
    // 地区前缀由 `normalize` / 登录链拼在 secret 里（`idPrefix`）
    let prefix = secret_text(secret, &["idPrefix"]);
    if !id.is_empty() {
        return format!("{prefix}{id}");
    }
    let credential = {
        let access = access_token(secret);
        if access.is_empty() {
            jwt(secret)
        } else {
            access
        }
    };
    if credential.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(credential.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}credential-{hex}")
}

/// 把一条凭证对象归一成可落库的账号（`account.normalize`）。
///
/// 粘贴凭证的三种形态与网关 `api::accounts` 的 zcode 分支逐条对齐：
/// 手填 JSON / 文本文件两种收；二进制文件与本机登录态两种如实报错（本家没有
/// 对应的导入链路，静默当成空账号比报错更糟）。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let payload = match source["kind"].as_str() {
        Some("manual") => source["payload"].clone(),
        Some("file_text") => {
            let content = source["content"].as_str().unwrap_or("").trim();
            serde_json::from_str::<Value>(content).map_err(|_| {
                Error::http(400, "不是合法 JSON（请粘贴含 accessToken / jwt 的凭证对象）")
            })?
        }
        Some("file_base64") => {
            return Err(Error::http(
                400,
                "ZCode 不支持二进制凭证文件，请粘贴访问令牌或使用网页登录",
            ))
        }
        Some("desktop") => {
            return Err(Error::http(
                400,
                "ZCode 不支持导入本机登录态（CLI 登录态在登录链里完成），\
                 请用网页登录或粘贴访问令牌",
            ))
        }
        _ => source.clone(),
    };
    // 手填表单可能把令牌包在 `inputs` 里（前端表单的统一形态）
    let payload = if payload.get("inputs").is_some_and(Value::is_object) {
        payload["inputs"].clone()
    } else if let Some(raw) = payload.as_str() {
        json!({ "accessToken": raw })
    } else {
        payload
    };
    let access = secret_text(&payload, &["accessToken", "access_token", "apiKey", "api_key"]);
    let token_jwt = secret_text(&payload, &["jwt", "token"]);
    if access.is_empty() && token_jwt.is_empty() {
        return Err(Error::http(
            400,
            "请至少提供一项凭证：编码套餐的 accessToken，或套餐池的 jwt",
        ));
    }
    // 设备标识：用户给了就用（换设备号 = 换设备身份，是用户的选择），
    // 没给就现生成一个并随账号落盘
    let explicit_device = secret_text(&payload, &["deviceMid", "device_mid"]);
    let device_mid = if explicit_device.is_empty() {
        new_uuid().unwrap_or_default()
    } else {
        explicit_device
    };
    let plan = payload
        .get(PLAN_FIELD)
        .and_then(Value::as_str)
        .and_then(normalize_plan)
        .unwrap_or(PLAN_CODING);
    let mut secret = json!({
        "accessToken": access,
        "jwt": token_jwt,
        "deviceMid": device_mid,
        "userId": secret_text(&payload, &["userId", "user_id"]),
        "zcodePlan": plan,
        // 去重前缀（`identity` 读它）—— 与网关 account_id 的前缀同值
        "idPrefix": region::ACCOUNT_ID_PREFIX,
    });
    if let Some(name) = params["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        secret["name"] = Value::String(name.to_string());
    }
    Ok(json!({
        "public": view(&secret),
        "identity": identity(&secret),
        "secret": secret,
        "desktop": false,
    }))
}

/// 把新的 `secret` 写回账号（`account.update`，比较再写的 expect 语义）。
///
/// ── 为什么必须带 `expect` ────────────────────────────────────
/// 账号库是**共享**的：并发请求可能刚好在前一轮写完之后到达。`expect` 是插件
/// 刚读到的那个 secret，网关只在当前值仍等于它时才写入 —— 这是「比较再写」，
/// 防止两个并发路径互相覆盖。
pub fn update_secret(current: &Value, next: Value) -> Result<bool> {
    let result = sdk::host(
        "account.update",
        json!({
            "expect": current,
            "secret": next.clone(),
            "public": view(&next),
        }),
    )?;
    Ok(result["updated"] == true)
}

/// 设备标识：记录里有就用，没有就现场生成并**落盘**（native `device_mid_of`）。
///
/// 不要在调用点现编：每次现编等于「同一个账号天天换设备」，而风控据此关联
/// 同一设备的请求。
pub fn device_mid_or_create() -> Result<Option<String>> {
    let record = record()?;
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    if secret.is_null() {
        return Ok(None);
    }
    let existing = device_mid(&secret);
    if !existing.is_empty() {
        return Ok(Some(existing));
    }
    let Some(generated) = new_uuid() else {
        // 取不到随机源：如实不带这个头（会命中上游 3001，但比 panic 好）
        return Ok(None);
    };
    let mut next = secret.clone();
    if let Some(object) = next.as_object_mut() {
        object.insert("deviceMid".to_string(), Value::String(generated.clone()));
    }
    // 写失败不阻断本次请求：设备标识仍可临时用于这一次
    let _ = update_secret(&secret, next);
    Ok(Some(generated))
}

/// 数据面取令牌时顺带确认「账号存在」（native `session_access_token` 的判空）。
pub fn require_account() -> Result<Value> {
    let record = record()?;
    if record.get("secret").map(Value::is_null).unwrap_or(true) {
        return Err(Error::http(401, "没有可用的 ZCode 账号，请先在账号页添加"));
    }
    Ok(record)
}
