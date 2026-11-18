//! KukuAI 每日签到：优先「库库 30 天签到」，旧 freepoint 任务作兜底。
//!
//! ── 上游是什么（照 native `kuku/checkin.rs` 的实测记录）──────────
//! ```text
//! GET  /api/genflowpro/freepoint/homenew?{WEB_QUERY}
//!      → {errno, data:{activities:[{activity_key, activity_name, period_no,
//!         tabs:[{tasks:[{task_type, task_name, task_status, single_reward_point,
//!         claimable_point}]}]}]}}
//! POST /api/genflowpro/freepoint/taskComplete?{WEB_QUERY}
//!      body: task_type=LOGIN|CHAT        （x-www-form-urlencoded）
//!      → {errno, data:{complete_status, reward_point}}
//! ```
//! freepoint 的实测要点：
//!   - `homenew` 的任务状态 `FINISHED` / `UNFINISHED`，`claimable_point` 恒 0
//!     —— **不能拿它当领取门槛**（「完成一次对话」UNFINISHED 照样领到 +50）；
//!   - `taskComplete` **幂等**：重复领返回 `SUCCESS` + `reward_point=0`（或
//!     参考实现记录的 `BADGE_ALREADY_RECEIVED`），因此「已领过」不算失败；
//!   - 每日可自助完成的是 `LOGIN`（每日登录）与 `CHAT`（完成一次对话）；
//!     `INVITE_VISIT` / `INVITE_DOWNLOAD` 要真实受邀人，接口上强领只会失败，
//!     不进领取清单（参考实现同款取舍）。
//!
//! ── 2026-10-21 起的 30 天签到（主链路）──────────────────────
//! 旧 freepoint 活动结束后，上游主签到换成「库库 30 天签到」：
//! ```text
//! GET  /act/api/conf?conf_key=kukuSignConf
//!      → data[].conf_value.{activityTid, signPoint}
//! GET  /act/v2/kukuai30/homepage?tid=…
//!      → {signed_today, continuous_days, total_days, …}
//! GET  /operation/activitys/api/getJsToken
//!      → {jsToken: "function fn(a){…};fn(\"HEX\")"}（URL 编码）
//! POST /act/v2/kukuai30/signin?tid=…&jsToken=…&aid=15459
//!      → {continuous, signed_today:true}；已签返回 errno=10152
//! ```
//! 实测缺 `jsToken` 返回 8002、缺 `aid` 返回 8001，两者齐全即成功。
//! 签到只认网页 Cookie（不需要换发业务 STOKEN），所以放在 freepoint 之前。
//!
//! ── 为什么这条比普通「每日签到」复杂 ────────────────────────
//! 普通签到是「一个接口一次调用」。这里有**四步**、**两个成功判据**（`errno`
//! 与 `signed_today`）、**三种降级**（活动未配置 / 面板不可读 / 风控未通过），
//! 还要区分「今天已签」（done）与「没有活动」（inactive）—— 这三者的处置在
//! 编排层完全不同（写今日记录 / 不再重试 / 记为无活动）。
//!
//! ── 会话前提 ────────────────────────────────────────────────
//! freepoint 是业务接口，与 userreport 同一道会话门：调 `with_business_stoken`
//! 先换发 genflowpro STOKEN（`engine.rs`），老账号 / 通行证级 STOKEN 也能签。
//!
//! ── 返回形状 ────────────────────────────────────────────────
//! 协议里的 `CheckinReport`：`{outcome, credit, streak, message}`。outcome 只取
//! `claimed` / `done` / `inactive` / `failed` 四档（本家没有「不参与」与
//! 「要验证码」两种情形：签到只认 Cookie，不认账号类型）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::account;
use super::upstream;

/// 每日可自助完成的任务（类型，展示名）。展示名用于结果文案。
const DAILY_TASKS: [(&str, &str); 2] = [("LOGIN", "每日登录"), ("CHAT", "完成一次对话")];

/// 30 天签到活动配置（`conf_value.activityTid` / `signPoint`）。
const ACTIVITY_CONF_URL: &str = "/act/api/conf?conf_key=kukuSignConf";

/// 活动风控的 `aid`（活动配置 `dataApp.app_key`）。签到接口缺它会返回 8001。
const ACTIVITY_AID: i64 = 15459;

/// 每日签到积分的兜底值（配置里 `signPoint` 读不到时使用）。
const ACTIVITY_SIGN_POINT: u32 = 10;

/// 30 天签到链路的结果。
enum ThirtyDaySignin {
    Signed { continuous: u32, total: u32, point: u32 },
    Already { continuous: u32, total: u32 },
    /// 活动未配置 / 已结束 / 面板不可读：交给旧的 freepoint 链路。
    Unavailable,
    Failed(String),
}

/// `checkin.claim`：每日签到入口。
///
/// ── 顺序不能反（2026-10-21 起的实测结论）─────────────────────
/// 旧的「免费领积分」活动在部分账号上已经没有任务面板（`taskComplete` 恒 FAIL），
/// 先走新链路；只有新活动不可用时才回落到旧任务 —— 反过来会在旧活动已结束的
/// 账号上稳定报「签到失败」，而其实新活动签得好好的。
pub fn claim() -> Result<Value> {
    let credentials = account::current()?;
    match signin_thirty_days(&credentials) {
        ThirtyDaySignin::Signed {
            continuous,
            total,
            point,
        } => Ok(json!({
            "outcome": "claimed",
            "credit": format!("+{point} 积分"),
            "streak": continuous,
            "message": format!(
                "库库 30 天签到成功：+{point} 积分（连续 {continuous} 天，累计 {total} 天）"
            ),
        })),
        ThirtyDaySignin::Already { continuous, total } => Ok(json!({
            "outcome": "done",
            "credit": Value::Null,
            "streak": continuous,
            "message": format!("今日已签到（连续 {continuous} 天，累计 {total} 天）"),
        })),
        ThirtyDaySignin::Failed(message) => Ok(json!({
            "outcome": "failed",
            "credit": Value::Null,
            "streak": Value::Null,
            "message": format!("库库 30 天签到失败：{message}"),
        })),
        ThirtyDaySignin::Unavailable => freepoint_claim(&credentials),
    }
}

/// 30 天签到：读活动配置 → 看今日状态 → 取风控 token → 调签到。
///
/// 上游把「活动配置」和「签到接口」拆成了两个域：
/// - `/act/api/conf?conf_key=kukuSignConf` 给 `activityTid` 与每日积分；
/// - `/act/v2/kukuai30/homepage?tid=…` 给今日是否已签、连续天数；
/// - `/operation/activitys/api/getJsToken` 给风控 token（URL 编码的 JS 片段）；
/// - `/act/v2/kukuai30/signin?tid=…&jsToken=…&aid=15459` 真正签到。
///
/// 实测缺 `aid` 会返回 8001（账号异常），缺 `jsToken` 会返回 8002；
/// 两者齐全即成功。活动页地址固定，`aid` 是活动 `app_key`。
fn signin_thirty_days(credentials: &account::KukuCredentials) -> ThirtyDaySignin {
    let headers = upstream::activity_headers(&credentials.cookie_header());
    let conf_url = format!("{}{ACTIVITY_CONF_URL}", upstream::BASE_URL);
    let conf = match upstream::get_json(&conf_url, &headers) {
        Ok(value) => value,
        // 配置读不到：可能是活动未上线 / 账号无活动 / 网络问题。一律按「不可用」
        // 交给旧链路 —— 在这里报失败会让「旧活动还能领」的账号白丢一次机会。
        Err(_) => return ThirtyDaySignin::Unavailable,
    };
    let Some((tid, point)) = activity_config(&conf) else {
        return ThirtyDaySignin::Unavailable;
    };

    let home_url = format!("{}/act/v2/kukuai30/homepage?tid={tid}", upstream::BASE_URL);
    let home = match upstream::get_json(&home_url, &headers) {
        Ok(value) => value,
        Err(_) => return ThirtyDaySignin::Unavailable,
    };
    if home.get("errno").and_then(Value::as_i64).unwrap_or(-1) != 0 {
        // 151004 / -6 是上游的「无活动」；其它错误也按不可用处理，交给旧链路。
        return ThirtyDaySignin::Unavailable;
    }
    let data = home.get("data").cloned().unwrap_or(Value::Null);
    let continuous = data
        .get("continuous_days")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    let total = data
        .get("total_days")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    if data
        .get("signed_today")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return ThirtyDaySignin::Already { continuous, total };
    }

    let token_url = format!("{}/operation/activitys/api/getJsToken", upstream::BASE_URL);
    let token_value = match upstream::get_json(&token_url, &headers) {
        Ok(value) => value,
        Err(error) => {
            return ThirtyDaySignin::Failed(format!("签到凭证获取失败：{}", error.message))
        }
    };
    let Some(token) = token_value
        .get("data")
        .and_then(|inner| inner.get("jsToken"))
        .and_then(Value::as_str)
        .and_then(extract_js_token)
    else {
        return ThirtyDaySignin::Failed("签到凭证为空（jsToken 解析失败）".to_string());
    };

    let sign_url = format!(
        "{}/act/v2/kukuai30/signin?tid={tid}&jsToken={token}&aid={ACTIVITY_AID}",
        upstream::BASE_URL
    );
    let signed = match upstream::post_form(&sign_url, &headers, &[]) {
        Ok(value) => value,
        Err(error) => return ThirtyDaySignin::Failed(format!("签到请求失败：{}", error.message)),
    };
    let errno = signed.get("errno").and_then(Value::as_i64).unwrap_or(-1);
    if errno == 0 {
        let data = signed.get("data").cloned().unwrap_or(Value::Null);
        let continuous = data
            .get("continuous")
            .and_then(Value::as_u64)
            .unwrap_or(continuous as u64) as u32;
        let total = total.max(continuous);
        if data
            .get("signed_today")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            return ThirtyDaySignin::Signed {
                continuous,
                total,
                point,
            };
        }
        // 回包说成功、但 `signed_today` 没翻转：**不能**报「签到成功」——
        // 那会让界面亮绿、当日台账落库，而实际什么也没到账。
        return ThirtyDaySignin::Failed("上游未确认签到完成".to_string());
    }
    if errno == 10152 {
        return ThirtyDaySignin::Already { continuous, total };
    }
    let message = signed
        .get("show_msg")
        .or_else(|| signed.get("errmsg"))
        .and_then(Value::as_str)
        .unwrap_or("未知错误");
    if errno == 8001 || errno == 8002 {
        return ThirtyDaySignin::Failed(format!(
            "上游风控未通过（errno={errno}：{message}），请重新登录该账号后再试"
        ));
    }
    ThirtyDaySignin::Failed(format!("errno={errno}：{message}"))
}

/// 从活动配置里取 `activityTid` 与每日积分。
fn activity_config(value: &Value) -> Option<(String, u32)> {
    let rows = value.get("data")?.as_array()?;
    for row in rows {
        let Some(config) = row.get("conf_value") else {
            continue;
        };
        let Some(tid) = config.get("activityTid").and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
        }) else {
            continue;
        };
        let tid = tid.trim().to_string();
        if tid.is_empty() {
            continue;
        }
        let point = config
            .get("signPoint")
            .and_then(|value| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<u32>().ok())
                    .or_else(|| value.as_u64().map(|number| number as u32))
            })
            .unwrap_or(ACTIVITY_SIGN_POINT);
        return Some((tid, point));
    }
    None
}

/// 风控 token 是 URL 编码的 JS 片段：`function fn(a){...};fn("HEX")`。
/// 取最后一对引号里的值即可，不执行任何 JS。
fn extract_js_token(raw: &str) -> Option<String> {
    let decoded = percent_decode(raw);
    let end = decoded.rfind('"')?;
    let start = decoded[..end].rfind('"')?;
    let token = &decoded[start + 1..end];
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// 只解码 `%XX`（风控 token 片段只用到这一层编码）。
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 旧 freepoint 链路（30 天签到不可用时的兜底）。
fn freepoint_claim(credentials: &account::KukuCredentials) -> Result<Value> {
    let (prepared, _) = account::with_business_stoken(credentials);
    let headers = upstream::headers(&prepared.cookie_header());

    // 1) 任务面板：先探一次会话（freepoint 与 userreport 同一道门，-6 就是
    //    登录态问题），顺带确认活动面板可读。
    let panel_url = format!(
        "{}/api/genflowpro/freepoint/homenew?{}",
        upstream::BASE_URL,
        upstream::WEB_QUERY
    );
    let panel = upstream::get_json(&panel_url, &headers)?;
    let errno = panel.get("errno").and_then(Value::as_i64).unwrap_or(-1);
    if errno != 0 {
        let message = panel
            .get("show_msg")
            .or_else(|| panel.get("errmsg"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(Error::http(
            401,
            format!("KukuAI 签到失败（freepoint errno={errno}：{message}）——请重新登录该账号"),
        )
        .with_code("token_expired"));
    }

    // 旧活动已经结束 / 该账号没有活动时，面板是 `{activities: []}`。
    // 这时再打 taskComplete 只会拿到一组 FAIL，误报成「签到失败」；
    // 直接按「没有可领活动」返回。
    let activity_count = panel
        .get("data")
        .and_then(|data| data.get("activities"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if activity_count == 0 {
        return Ok(json!({
            "outcome": "inactive",
            "credit": Value::Null,
            "streak": Value::Null,
            "message": "当前没有可参加的「免费领积分」活动（活动可能已结束）",
        }));
    }

    // 2) 逐个领取。单个任务失败只记录继续（一个任务被风控不该拖垮另一个，
    //    与「个别账号查询失败不再拖垮整轮定时查询」同一取舍）。
    let mut newly: Vec<String> = Vec::new();
    let mut already_claimed = false;
    let mut total = 0i64;
    let mut failures: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    for (task_type, task_label) in DAILY_TASKS {
        let url = format!(
            "{}/api/genflowpro/freepoint/taskComplete?{}",
            upstream::BASE_URL,
            upstream::WEB_QUERY
        );
        let value = match upstream::post_form(&url, &headers, &[("task_type", task_type)]) {
            Ok(value) => value,
            Err(error) => {
                failures.push(format!("{task_label}：{}", error.message));
                continue;
            }
        };
        let errno = value.get("errno").and_then(Value::as_i64).unwrap_or(-1);
        if errno != 0 {
            let message = value
                .get("show_msg")
                .or_else(|| value.get("errmsg"))
                .and_then(Value::as_str)
                .unwrap_or("未知错误");
            failures.push(format!("{task_label}（errno={errno}：{message}）"));
            continue;
        }
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        let status = data
            .get("complete_status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let reward = data.get("reward_point").and_then(Value::as_i64);
        if let Some(reward) = reward.filter(|reward| *reward > 0 && status.eq_ignore_ascii_case("SUCCESS")) {
            newly.push(format!("{task_label}+{reward}"));
            total = total.saturating_add(reward);
        } else if (status.eq_ignore_ascii_case("SUCCESS") && reward == Some(0))
            || status.eq_ignore_ascii_case("BADGE_ALREADY_RECEIVED")
        {
            already_claimed = true;
        } else {
            unresolved.push(format!("{task_label}：上游未确认完成（{status}）"));
        }
    }

    let success = !newly.is_empty();
    let done = !success && already_claimed;
    let mut message = if success {
        format!("签到完成：{}（共 +{total}）", newly.join("、"))
    } else if done {
        "今日积分已领过（任务接口幂等，无新增）".to_string()
    } else if !failures.is_empty() {
        format!("每日任务领取失败：{}", failures.join("；"))
    } else {
        "本次没有已确认完成的每日任务".to_string()
    };
    if success || done {
        if !failures.is_empty() {
            message.push_str(&format!("；部分任务失败：{}", failures.join("；")));
        }
    }
    if !unresolved.is_empty() {
        message.push_str(&format!("；{}", unresolved.join("；")));
    }
    Ok(json!({
        "outcome": if success { "claimed" } else if done { "done" } else if failures.is_empty() { "inactive" } else { "failed" },
        "credit": if success { Value::from(format!("+{total}")) } else { Value::Null },
        "streak": Value::Null,
        "message": message,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_config_reads_string_and_number_tid() {
        let value = json!({
            "errno": 0,
            "data": [
                { "conf_key": "x", "conf_value": { "activityTid": 15459, "signPoint": "20" } }
            ]
        });
        assert_eq!(Some(("15459".to_string(), 20)), activity_config(&value));

        let value = json!({ "data": [ { "conf_value": { "activityTid": "  77  " } } ] });
        assert_eq!(Some(("77".to_string(), ACTIVITY_SIGN_POINT)), activity_config(&value));

        // 空 tid / 缺 conf_value / 缺 data 都不算配置
        assert!(activity_config(&json!({ "data": [ { "conf_value": { "activityTid": "" } } ] })).is_none());
        assert!(activity_config(&json!({ "data": [ {} ] })).is_none());
        assert!(activity_config(&json!({})).is_none());
    }

    /// 风控 token 是 URL 编码的 JS：解码后取最后一对引号之间的值，不执行 JS。
    #[test]
    fn js_token_is_extracted_from_the_last_quoted_literal() {
        let raw = "function%20fn(a)%7Breturn%20a%7D%3Bfn(%22ABCDEF0123%22)";
        assert_eq!(Some("ABCDEF0123".to_string()), extract_js_token(raw));
        // 未编码形态同样能取
        assert_eq!(
            Some("XY".to_string()),
            extract_js_token("function fn(a){return a};fn(\"XY\")")
        );
        assert!(extract_js_token("function fn(a){}").is_none());
        assert!(extract_js_token("fn(\"\")").is_none());
    }

    #[test]
    fn percent_decode_only_touches_percent_escapes() {
        assert_eq!("a b", percent_decode("a%20b"));
        // 非法转义原样保留（不吞字节、不报错）
        assert_eq!("%ZZ", percent_decode("%ZZ"));
        assert_eq!("%2", percent_decode("%2"));
        assert_eq!("AB", percent_decode("%41%42"));
    }
}
