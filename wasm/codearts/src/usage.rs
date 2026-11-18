//! 套餐统计与额度（`usage.query`）：总积分、分项积分、订阅信息。
//!
//! ── 上游给的是什么 ──────────────────────────────────────────
//! `GET {base}/snap-manager/v1/statistics/plugin` 返回一张混合表：
//!   · token 类指标只有 `usage_token_num` / `package_token_amount`；
//!   · 积分类指标只有 `package_credit_*`；
//!   · `value` 是**百分比**，`-1` 是「不适用」的哨兵（不是 0%）。
//!
//! ── 为什么这里要自己产展示串（`balanceView`）───────────────
//! 账号页的余额明细只认 `balanceView` / `balance` 两个键，而本家给的是两组互不
//! 相干的口径。不给展示串，那一列就会整排显示成「—」—— 明明读到了数，看着却像
//! 没读到。什么指标该说「已用 x / y token」、什么该说「剩 x / y 积分」，是上游
//! 这张表的知识，不是界面该猜的。

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::signer;
use super::upstream;

/// 订阅统计端点。
pub const STATISTICS_PATH: &str = "/snap-manager/v1/statistics/plugin";

/// 一个计量表。
#[derive(Clone, Debug, Default)]
pub struct Meter {
    pub name: String,
    pub label: String,
    pub used_tokens: i64,
    pub allowance_tokens: i64,
    pub credit_total: Option<f64>,
    pub credit_used: Option<f64>,
    pub credit_remaining: Option<f64>,
    /// 上游直接给的百分比；**只有 `>= 0` 才收**（-1 是「不适用」的哨兵）。
    pub used_percent: Option<f64>,
}

impl Meter {
    /// 这一行有没有可显示的东西。全零且没有任何 credit 字段的行是噪声。
    fn is_empty(&self) -> bool {
        self.used_percent.is_none()
            && self.used_tokens == 0
            && self.allowance_tokens == 0
            && self.credit_total.is_none()
            && self.credit_remaining.is_none()
    }

    /// 一行计量表 → 界面上那一段读数。
    fn view(&self) -> Option<String> {
        if let (Some(remaining), Some(total)) = (self.credit_remaining, self.credit_total) {
            return Some(format!("剩 {} / {} 积分", compact(remaining), compact(total)));
        }
        // 总量 >1 才当真配额：上游给过 `package_token_amount=1`（试用版账号周期内
        // 没下发过对话 token 包时的占位形状）—— 1 个 token 的「包」没有任何信息量，
        // 还会把「没额度」显示成「剩 0 / 1」的荒谬读数。
        if self.allowance_tokens > 1 {
            let percent = self
                .used_percent
                .map(|value| format!("（{}%）", compact(value)))
                .unwrap_or_default();
            return Some(format!(
                "已用 {} / {} token{}",
                self.used_tokens, self.allowance_tokens, percent
            ));
        }
        if self.used_tokens > 0 {
            return Some(format!("已用 {} token", self.used_tokens));
        }
        // 只有百分比没有量的行：0% 是**真信息**，不能又变回「—」
        self.used_percent.map(|value| format!("已用 {}%", compact(value)))
    }
}

/// 数值 → 去掉尾随的 `.0`（积分常是 `300.0`，界面上一眼看成像不精确的量）。
fn compact(value: f64) -> String {
    if value == value.trunc() && value.abs() < 1e15 {
        return format!("{}", value as i64);
    }
    format!("{value}")
}

/// 订阅统计文档里本模块要用的部分。
#[derive(Clone, Debug, Default)]
pub struct Statistics {
    pub reset_date: String,
    pub plan: String,
    pub plan_name: String,
    pub plan_url: String,
    pub meters: Vec<Meter>,
    /// 套餐特性开关（`package.features`）。native 也解析它但未输出到 `usage.query`，
    /// 这里保留原样做诊断用途，不再往下游传 —— 免得凭空多出一列没人消费的字段。
    #[allow(dead_code)]
    pub features: Vec<(String, bool)>,
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

fn number(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn float(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

/// 解析统计文档。字段名逐个照上游（`metrics[].usage_token_num` 这类拼写不能改）。
pub fn parse_statistics(body: &str) -> Result<Statistics> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|_| Error::http(502, "CodeArts 统计响应不是合法 JSON"))?;
    let mut meters = Vec::new();
    for metric in parsed.get("metrics").and_then(Value::as_array).into_iter().flatten() {
        let name = text(metric, "name");
        // `show:false` 是上游的「这行别显示」指令（退役指标带着 value:-1 走这条路）
        if name.is_empty() || !metric.get("show").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let mut meter = Meter {
            label: meter_label(&name).unwrap_or_else(|| name.clone()),
            used_tokens: number(metric, "usage_token_num"),
            allowance_tokens: number(metric, "package_token_amount"),
            credit_total: float(metric, "package_credit_amount"),
            credit_used: float(metric, "package_credit_used"),
            credit_remaining: float(metric, "package_credit_remain"),
            used_percent: None,
            name,
        };
        if let Some(value) = float(metric, "value") {
            if value >= 0.0 {
                meter.used_percent = Some(value);
            }
        }
        if meter.is_empty() {
            continue;
        }
        meters.push(meter);
    }
    let package = parsed.get("package").filter(|value| !value.is_null());
    let mut features = Vec::new();
    if let Some(package) = &package {
        for feature in package.get("features").and_then(Value::as_array).into_iter().flatten() {
            let name = text(feature, "name");
            if !name.is_empty() {
                features.push((name, feature.get("enable").and_then(Value::as_bool).unwrap_or(false)));
            }
        }
    }
    Ok(Statistics {
        reset_date: text(&parsed, "end_date"),
        plan: package.map(|value| text(value, "spec_code")).unwrap_or_default(),
        plan_name: package
            .map(|value| {
                let en = text(value, "package_name_en");
                if en.is_empty() {
                    text(value, "package_name_cn")
                } else {
                    en
                }
            })
            .unwrap_or_default(),
        plan_url: package.map(|value| text(value, "package_url")).unwrap_or_default(),
        meters,
        features,
    })
}

/// 计量表的中文标签 —— **逐字照参考实现那张表**（`quota.go` 的 `quotaMeterLabels`）。
///
/// 认不出来就回 None、由调用方回落上游原名。这里刻意**不猜**：第一版按「指标名
/// 大概长什么样」写过 `chat_token` / `code_completion` 三条，真跑一次才发现上游
/// 给的是 `usageTokenChatMessages` / `usageTotalPackageCredit` 那一族名字 ——
/// 三条全是死码。教训：这类对照表只能抄，不能推。
fn meter_label(name: &str) -> Option<String> {
    Some(
        match name {
            "usageDataCodeCompletions" => "代码补全额度",
            "usageDataChatMessages" => "对话消息额度",
            "usageTokenChatMessages" => "对话 token 额度",
            "usageTotalPackageCredit" => "套餐积分",
            "usageBasicPackageCredit" => "基础包积分",
            "usageOnDemandPackageCredit" => "按需付费积分",
            "usageBonusPackageCredit" => "赠送积分",
            _ => return None,
        }
        .to_string(),
    )
}

/// 套餐统计合成 `query_usage` 的归一化形状。
///
/// `available` 只在有积分数值时给数，Token 用量不计入总积分。
///
/// 「套餐积分」是**汇总口径**不是独立分账：`usageTotalPackageCredit` 的剩余等于
/// 各分项行之和（实测 trial 账号：5172.57 = 基础包 172.57 + 按需 0 + 赠送 5000）。
/// 合计时识别这种包含关系，命中就只取分项行 —— 用容差比较，上游数值走浮点。
///
/// 分项行**不点名**：按需付费行非零的账号，「基础包 + 赠送」两行之和 ≠ 汇总行，
/// 点名判据认不出包含关系、翻倍照旧 —— 所以分项取「除汇总行外所有带剩余积分的
/// 行」。认不出包含关系时不剔除：宁可照旧全加，也不凭猜丢掉一笔真实的钱。
pub fn usage_document(statistics: Option<&Statistics>) -> Value {
    let mut wallets = Vec::new();
    let mut credit_left: Option<f64> = None;
    if let Some(statistics) = statistics {
        let parts_sum = {
            let mut sum = 0.0;
            let mut any = false;
            for meter in &statistics.meters {
                if meter.name == "usageTotalPackageCredit" {
                    continue;
                }
                if let Some(left) = meter.credit_remaining {
                    sum += left;
                    any = true;
                }
            }
            any.then_some(sum)
        };
        for meter in &statistics.meters {
            if meter.credit_remaining.is_none()
                && meter.credit_total.is_none()
                && meter.credit_used.is_none()
            {
                continue;
            }
            wallets.push(json!({
                "type": format!("meter:{}", meter.name),
                "displayName": meter.label,
                "balanceView": meter.view(),
                "usedTokens": meter.used_tokens,
                "allowanceTokens": meter.allowance_tokens,
                "usedPercent": meter.used_percent,
                "creditTotal": meter.credit_total,
                "creditUsed": meter.credit_used,
                "creditRemaining": meter.credit_remaining,
            }));
            let Some(left) = meter.credit_remaining else { continue };
            let duplicated = meter.name == "usageTotalPackageCredit"
                && parts_sum.is_some_and(|sum| (sum - left).abs() <= f64::EPSILON.max(left.abs() * 1e-6));
            if !duplicated {
                credit_left = Some(credit_left.unwrap_or(0.0) + left);
            }
        }
    }
    json!({
        "available": credit_left,
        "unit": "积分",
        "wallets": wallets,
        "subscription": statistics.map(|statistics| json!({
            "planName": statistics.plan_name,
            "planCode": statistics.plan,
            "planUrl": statistics.plan_url,
            "resetDate": statistics.reset_date,
        })).unwrap_or(Value::Null),
    })
}

/// 拉一次订阅统计。
pub fn fetch(credential: &super::credentials::Credential) -> Result<Statistics> {
    let url = format!("{}{}", upstream::base(), STATISTICS_PATH);
    // 订阅统计签名只覆盖官方四件套，不增加 Content-Type 或 Agent-Type
    let headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("X-Language".to_string(), upstream::DEFAULT_LANGUAGE.to_string()),
        ("plugin-name".to_string(), upstream::DEFAULT_PLUGIN_NAME.to_string()),
        ("plugin-version".to_string(), upstream::DEFAULT_PLUGIN_VERSION.to_string()),
    ];
    let signing = signer::Credential {
        access_key_id: credential.access_key_id.clone(),
        secret_access_key: credential.secret_access_key.clone(),
        security_token: credential.security_token.clone(),
        domain_id: credential.domain_id.clone(),
    };
    let signed = signer::sign("GET", &url, &headers, b"", &signing, false)
        .map_err(|reason| Error::http(500, format!("CodeArts 余额请求签名失败：{reason}")))?;
    let (status, body) = upstream::read_body(
        upstream::get(&url, upstream::header_object(&signed))?,
        1024 * 1024,
    )?;
    if status != 200 {
        let excerpt = super::redact::redact(&String::from_utf8_lossy(&body), credential, false);
        let excerpt = super::credentials::truncate_chars(excerpt.trim(), 300);
        return Err(Error::http(
            status,
            format!("CodeArts 余额接口返回 HTTP {status}：{excerpt}"),
        ));
    }
    parse_statistics(&String::from_utf8_lossy(&body))
}

/// `usage.query` 的实现。
pub fn query() -> Result<Value> {
    let credential = super::credentials::ensure(false)?;
    let statistics = fetch(&credential)?;
    Ok(usage_document(Some(&statistics)))
}
