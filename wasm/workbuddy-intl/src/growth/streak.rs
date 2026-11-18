//! WorkBuddy **连登管家**（growth 域的 streak 子系统；从参考项目
//! `internal/upstream/streak.go` + `internal/upstream/blackcat.go` 的补签部分
//! + `internal/scheduler/streak.go` 移植）。
//!
//! ── 这是什么 ────────────────────────────────────────────────
//! 上游「成长中心」的连登玩法有三层，彼此依赖：
//!
//! ```text
//! 连续登录天数（streak.days）
//!   ├─ 7d / 14d / 28d 档位：解锁后兑换发 credit / energy / 补签卡 / 抽奖次数
//!   └─ 抽奖次数：**只能**从档位兑换获得，兑完立刻可抽
//! 补签卡：对漏签的某一天补上，保住连续天数（断了要重攒 7 天）
//! ```
//!
//! 三件事的共同点：**都没人愿意天天盯着**。所以它们被组织成「签到末尾跑一遍」
//! 的闭环（参考项目 `RunStreakBonusNow`）：
//!
//! ```text
//! ① 昨日漏签 + 有补签卡 → 补签
//! ② 拉连登完整状态 → 对每个 available 档位兑换
//! ③ 拉抽奖余额 → 抽完
//! ```
//!
//! ── 为什么幂等是硬要求 ──────────────────────────────────────
//! 这段每天都会跑（可能一天跑两次：定时签到 + 手动签到）。上游对三件事都是幂等
//! 的，因此**不做本地去重状态** —— 上游状态就是唯一事实源，本地记一份只会在多
//! 实例部署时与上游分叉。
//!
//! ── ⚠ 本 fork 的自用改动（逐字保留，勿改回）───────────────────
//! 档位判据认 `available`（上游实际值），修 7d/14d/28d 永不兑换 —— 见
//! [`Tier::redeemable`] 的长注释（提交 `cf213f9`）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Value};

use crate::util;

use super::{chat_call, GrowthAccount};

/// 连登兑换档位路径（growth 域）。
const REDEEM_PATH: &str = "/activity/growth/redeem";
/// 抽奖余额（GET）与抽奖（POST）。
const LOTTERY_SUMMARY_PATH: &str = "/activity/growth/lottery/summary";
const LOTTERY_DRAW_PATH: &str = "/activity/growth/lottery/draw";
/// 连登完整状态（含档位解锁状态与补签卡余额）。
const STREAK_PATH: &str = "/activity/growth/streak";
/// 热力图（判昨日是否漏签）。
const HEATMAP_PATH: &str = "/activity/growth/heatmap";
/// 使用补签卡。
const MAKEUP_USE_PATH: &str = "/activity/growth/makeup-cards/use";

/// 三个档位（顺序即兑换顺序：小的先兑，收益确定性更高）。
pub const TIERS: [&str; 3] = ["7d", "14d", "28d"];

/// 抽奖单轮护栏：一次闭环最多抽这么多次。上游的 chances 理论上不会超过兑换所得
/// （三档合计几次），给 20 是防御「上游返回一个离谱数字」把账号抽成筛子。
pub const MAX_DRAWS: usize = 20;

// ─── 读侧：连登完整状态 ─────────────────────────────────────

/// 一个档位的解锁状态与奖励内容。
#[derive(Clone, Debug, Default)]
pub struct Tier {
    pub tier: String,
    /// `locked` / `available` / `claimed`（上游原文，未识别的值原样保留）
    ///
    /// 2026-11-11 实测 33 个国内版账号：上游只会给这三个值，**`available`
    /// 才是「已解锁待领取」**（不是 `unlocked`）。
    pub status: String,
    pub credit: i64,
    pub energy: i64,
    pub cards: i64,
    pub chances: i64,
}

impl Tier {
    /// 可兑换：已解锁且未领取。
    ///
    /// ── 状态值以上游实测为准（2026-11-11，33 个账号逐个查）──────────
    /// 上游只给三种值：`locked`（未到天数）/ **`available`**（已解锁待领取）/
    /// `claimed`（已领取）。**从来不给 `unlocked`**。
    ///
    /// 此前这里只认 `unlocked`，后果是整条链路静默失效：33 个号里 7 个处于
    /// `available` 的 7d 档一次都没兑过 → 抽奖次数永远是 0 → 抽奖环节也无事
    /// 可做 → `run_once` 返回空 → `done==0 && failed==0` 按设计不进报告
    /// （见 `run_for_accounts`），所以日志里连一行都看不到。**症状就是
    /// 「连登管家好像从来没跑过」**。
    ///
    /// `unlocked` 保留是为了兼容上游可能的旧写法；不认识的值仍然跳过 ——
    /// 按「可兑换」去盲试会在上游加出新状态（如 `expired`）时稳定报错。
    pub fn redeemable(&self) -> bool {
        matches!(self.status.as_str(), "available" | "unlocked")
    }
}

/// 连登完整状态（`GET /activity/growth/streak` 的 `data` 段）。
#[derive(Clone, Debug, Default)]
pub struct StreakFull {
    /// 当前连登天数。
    ///
    /// 生产路径没人读：本模块只关心「哪些档位可兑换」与卡/抽奖余额，天数由
    /// `growth::growth_streak` 的轻量只读版取。字段留着是因为它就是上游 `data`
    /// 的完整投影 —— 删掉会让 [`StreakFull::from_data`] 的解析规则与上游形状错位。
    #[allow(dead_code)]
    pub days: i64,
    /// 补签卡余额（>0 才可能补签）
    pub makeup_cards: i64,
    pub tiers: Vec<Tier>,
}

impl StreakFull {
    fn from_data(data: &Value) -> Self {
        let days = data
            .get("streak")
            .and_then(|streak| streak.get("days"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let makeup_cards = data
            .get("makeup_cards")
            .and_then(|cards| cards.get("balance"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        // 档位清单在上游有两个来源：`redemption_status.tiers[]`（带奖励明细）
        // 与 `redemption_status.tier_7d_status` 三个扁平字段（只有状态）。
        // 优先用前者（兑换要 credit/energy 读数给界面）；它缺失时用后者补出
        // 「只有状态、没有奖励读数」的档位，至少让兑换能跑。
        let status = data.get("redemption_status").cloned().unwrap_or(Value::Null);
        let mut tiers: Vec<Tier> = status
            .get("tiers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let tier = item.get("tier").and_then(Value::as_str)?.to_string();
                        let tier_status = status
                            .get(format!("tier_{tier}_status"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        Some(Tier {
                            tier,
                            status: tier_status,
                            credit: item.get("credit").and_then(Value::as_i64).unwrap_or(0),
                            energy: item.get("energy").and_then(Value::as_i64).unwrap_or(0),
                            cards: item.get("cards").and_then(Value::as_i64).unwrap_or(0),
                            chances: item.get("chances").and_then(Value::as_i64).unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        if tiers.is_empty() {
            for tier in TIERS {
                let status_text = status
                    .get(format!("tier_{tier}_status"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if status_text.is_empty() {
                    continue;
                }
                tiers.push(Tier {
                    tier: tier.to_string(),
                    status: status_text,
                    ..Default::default()
                });
            }
        }
        Self {
            days,
            makeup_cards,
            tiers,
        }
    }
}

/// 拉连登完整状态。
pub fn streak_full(account: &GrowthAccount) -> std::result::Result<StreakFull, String> {
    let call = chat_call(account, "GET", STREAK_PATH, None, &[])?;
    if !call.ok() {
        return Err(format!(
            "连登状态查询失败（HTTP {} code={} {}）",
            call.status,
            call.code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            call.msg()
        ));
    }
    Ok(StreakFull::from_data(&call.data()))
}

/// 昨日是否漏签（`GET /activity/growth/heatmap` 的 cell.score == 0）。
///
/// 热力图里没有昨天那一格 = 「查不出」，返回 false（不补签）—— 宁可漏补也不要在
/// 拿不准的时候乱用补签卡（那是稀缺资源）。
pub fn yesterday_missed(account: &GrowthAccount) -> std::result::Result<bool, String> {
    let call = chat_call(account, "GET", HEATMAP_PATH, None, &[])?;
    if !call.ok() {
        return Err(format!("热力图查询失败（HTTP {}）", call.status));
    }
    let yesterday = util::yesterday_key();
    let missed = call
        .data()
        .get("cells")
        .and_then(Value::as_array)
        .map(|cells| {
            cells.iter().any(|cell| {
                let date = cell.get("date").and_then(Value::as_str).unwrap_or("");
                // 上游日期可能带时分秒（`2026-10-17T00:00:00`），只比前 10 位
                date.get(..10) == Some(yesterday.as_str())
                    && cell.get("score").and_then(Value::as_i64).unwrap_or(0) == 0
            })
        })
        .unwrap_or(false);
    Ok(missed)
}

// ─── 写侧：兑换 / 补签 / 抽奖 ───────────────────────────────

/// 幂等令牌（上游前端用 `randomUUID()`，语义是「同一次点击只兑一次」）。
///
/// 格式对齐 UUID v4 的字面形态（8-4-4-4-12 小写 hex）：上游把它当不透明串，
/// 但照着前端形状发最稳。wasm 里没有熵源，改用时间戳 + 计数的哈希派生
/// （见 `util::uuid_v4`）。
fn client_token() -> String {
    util::uuid_v4()
}

/// 兑换一个档位。未解锁（403）属预期，由调用方按状态跳过。
pub fn redeem_tier(account: &GrowthAccount, tier: &str) -> std::result::Result<(), String> {
    let call = chat_call(
        account,
        "POST",
        REDEEM_PATH,
        Some(&json!({ "tier": tier, "client_token": client_token() })),
        &[],
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!(
            "兑换 {tier} 失败（HTTP {} code={} {}）",
            call.status,
            call.code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            call.msg()
        ))
    }
}

/// 用补签卡补指定日期。
pub fn use_makeup_card(account: &GrowthAccount, date: &str) -> std::result::Result<(), String> {
    let call = chat_call(
        account,
        "POST",
        MAKEUP_USE_PATH,
        Some(&json!({ "target_date": date })),
        &[],
    )?;
    if call.ok() {
        Ok(())
    } else {
        Err(format!("补签 {date} 失败（HTTP {} {}）", call.status, call.msg()))
    }
}

/// 当前抽奖次数（`GET /activity/growth/lottery/summary`）。
pub fn lottery_chances(account: &GrowthAccount) -> std::result::Result<i64, String> {
    let call = chat_call(account, "GET", LOTTERY_SUMMARY_PATH, None, &[])?;
    if !call.ok() {
        return Err(format!("抽奖余额查询失败（HTTP {}）", call.status));
    }
    Ok(call.data().get("chances").and_then(Value::as_i64).unwrap_or(0))
}

/// 抽一次奖，返回奖品载荷原文（形状随活动期变化，透传给调用方）。
pub fn lottery_draw(account: &GrowthAccount) -> std::result::Result<Value, String> {
    let call = chat_call(
        account,
        "POST",
        LOTTERY_DRAW_PATH,
        Some(&json!({ "client_token": client_token() })),
        &[],
    )?;
    if !call.ok() {
        return Err(format!(
            "抽奖失败（HTTP {} code={} {}）",
            call.status,
            call.code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            call.msg()
        ));
    }
    Ok(call.data())
}

// ─── 闭环：单账号 ───────────────────────────────────────────

/// 单账号闭环的一步结果（界面与日志按行渲染）。
#[derive(Clone, Debug)]
pub struct StepReport {
    /// makeup / redeem / draw / skip / failed
    pub outcome: &'static str,
    pub message: String,
}

/// 单账号跑完「补签 → 兑换 → 抽奖」三件事。
///
/// 返回逐条报告（**空数组** = 三件事都无事可做，属正常态）。任何一步失败都不中断
/// 后续步骤：补签失败不该拖累兑换，兑换失败不该拖累抽奖 —— 三者在上游互不依赖，
/// 且都是幂等的，下一次还会重来。
pub fn run_once(account: &GrowthAccount) -> Vec<StepReport> {
    let mut reports: Vec<StepReport> = Vec::new();

    // ── ① 补签：昨日漏签 + 有卡才补 ──
    // 先查热力图而不是先查卡：漏签是最常见的「无事可做」态，热力图一次只读请求
    // 就能排除掉大部分轮次，不必再拉一次 streak。
    match yesterday_missed(account) {
        Ok(true) => match streak_full(account) {
            Ok(full) if full.makeup_cards > 0 => {
                let date = util::yesterday_key();
                match use_makeup_card(account, &date) {
                    Ok(()) => reports.push(StepReport {
                        outcome: "makeup",
                        message: format!("已用补签卡补签 {date}（保连登）"),
                    }),
                    Err(error) => reports.push(StepReport {
                        outcome: "failed",
                        message: error,
                    }),
                }
            }
            Ok(full) => {
                // 有漏签但没卡：如实记一条跳过（这是用户最该知道的一类）
                reports.push(StepReport {
                    outcome: "skip",
                    message: format!(
                        "昨日漏签但无补签卡（余额 {}），连登可能中断",
                        full.makeup_cards
                    ),
                });
            }
            Err(error) => reports.push(StepReport {
                outcome: "failed",
                message: error,
            }),
        },
        Ok(false) => {}
        Err(error) => {
            // 热力图失败不阻断后面的兑换 / 抽奖：那是两件独立的事
            reports.push(StepReport {
                outcome: "failed",
                message: error,
            });
        }
    }

    // ── ② 兑换：逐个已解锁档位 ──
    let full = match streak_full(account) {
        Ok(full) => Some(full),
        Err(error) => {
            reports.push(StepReport {
                outcome: "failed",
                message: error,
            });
            None
        }
    };
    if let Some(full) = &full {
        for tier in full.tiers.iter().filter(|tier| tier.redeemable()) {
            match redeem_tier(account, &tier.tier) {
                Ok(()) => reports.push(StepReport {
                    outcome: "redeem",
                    message: format!(
                        "兑换 {} 档（+{}c +{}e 补签卡×{} 抽奖×{}）",
                        tier.tier, tier.credit, tier.energy, tier.cards, tier.chances
                    ),
                }),
                Err(error) => reports.push(StepReport {
                    outcome: "failed",
                    message: error,
                }),
            }
        }
    }

    // ── ③ 抽奖：把 chances 抽空（兑换刚发的次数已在服务端累加）──
    match lottery_chances(account) {
        Ok(chances) if chances > 0 => {
            let limit = (chances as usize).min(MAX_DRAWS);
            let mut drawn = 0usize;
            for index in 0..limit {
                match lottery_draw(account) {
                    Ok(prize) => {
                        drawn += 1;
                        reports.push(StepReport {
                            outcome: "draw",
                            message: format!("第 {} 抽：{}", index + 1, compact_prize(&prize)),
                        });
                    }
                    Err(error) => {
                        // 抽奖失败即停（多半是次数耗尽或活动收摊），不再往下试
                        reports.push(StepReport {
                            outcome: "failed",
                            message: error,
                        });
                        break;
                    }
                }
            }
            if drawn > 0 {
                reports.push(StepReport {
                    outcome: "draw",
                    message: format!("抽奖完成 {drawn} 次"),
                });
            }
        }
        Ok(_) => {}
        Err(error) => reports.push(StepReport {
            outcome: "failed",
            message: error,
        }),
    }

    reports
}

/// 奖品载荷压成一行（日志与界面行都只要「抽到了什么」）。
///
/// 上游的 prize 形状随活动期变化（可能是对象、也可能是带嵌套奖励的数组），所以
/// 不解析结构、只取可读串并截断 —— 猜字段名会在活动换期时静默变成空。
fn compact_prize(prize: &Value) -> String {
    let text = match prize {
        Value::String(text) => text.clone(),
        Value::Null => "（空）".to_string(),
        other => other.to_string(),
    };
    let chars: Vec<char> = text.chars().take(160).collect();
    if chars.len() < text.chars().count() {
        format!("{}…", chars.into_iter().collect::<String>())
    } else {
        text
    }
}

// ─── 闭环：多账号 ───────────────────────────────────────────

/// 一个账号的闭环汇总（供签到结果行 / 日志使用）。
pub struct AccountStreakReport {
    pub account_id: String,
    pub name: String,
    /// 三件事里真正做成的（makeup / redeem / draw）
    pub done: usize,
    pub failed: usize,
    pub messages: Vec<String>,
}

/// 对**一个**账号跑闭环并汇总。
///
/// ── 与 native 的差别（宿主没有账号列表）────────────────────
/// native 的 `run_for_accounts` 自己 `store.list` 遍历全部账号；wasm 插件的 ABI
/// 里没有「列出本家账号」这一项，所以这里对**宿主给的当前账号**跑一趟，返回
/// 单元素数组。批量入口（`admin.action` 的 `growth.streak.batch`）因此变成
/// 「逐账号调用一次」—— 由网关的调度器驱动，账号间错峰也留在调度器那一层。
///
/// 门控照旧：企业账号没有个人成长体系（上游一律 403），跳过。
pub fn run_for_accounts(accounts: &[Value]) -> Vec<AccountStreakReport> {
    let mut reports: Vec<AccountStreakReport> = Vec::new();
    for account in accounts {
        let id = account.get("id").and_then(Value::as_str).unwrap_or("");
        let name = account
            .get("name")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .or_else(|| account.get("nickname").and_then(Value::as_str))
            .unwrap_or(id)
            .to_string();
        if id.is_empty() {
            continue;
        }
        // 门控：只服务 WorkBuddy 国内版的个人账号
        if !super::supports_growth(account) {
            continue;
        }
        if account
            .get("enterpriseId")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            continue;
        }
        // 账号记录是扁平 secret → 折成会话形状，再交给 `from_session`
        let Some(growth_account) = super::account_of(account) else {
            continue;
        };
        let steps = run_once(&growth_account);
        let done = steps
            .iter()
            .filter(|step| matches!(step.outcome, "makeup" | "redeem" | "draw"))
            .count();
        let failed = steps.iter().filter(|step| step.outcome == "failed").count();
        if done == 0 && failed == 0 {
            // 三件事都无事可做：不进报告（否则每轮几十条噪音）
            continue;
        }
        reports.push(AccountStreakReport {
            account_id: id.to_string(),
            name,
            done,
            failed,
            messages: steps.iter().map(|step| step.message.clone()).collect(),
        });
    }
    let _ = sdk::now();
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_redeemable_only_for_available() {
        // 上游实际给的是 `available`（2026-11-11 实测 33 个国内版账号），不是 `unlocked`
        let mut tier = Tier {
            tier: "7d".into(),
            status: "available".into(),
            ..Default::default()
        };
        assert!(tier.redeemable());
        // 旧写法仍兼容
        tier.status = "unlocked".into();
        assert!(tier.redeemable());
        tier.status = "locked".into();
        assert!(!tier.redeemable());
        tier.status = "claimed".into();
        assert!(!tier.redeemable());
        // 没见过的状态不当可兑换（避免稳定报错）
        tier.status = "expired".into();
        assert!(!tier.redeemable());
    }

    #[test]
    fn streak_full_reads_tiers_with_rewards() {
        let data = json!({
            "streak": { "days": 9 },
            "makeup_cards": { "balance": 2 },
            "redemption_status": {
                "tier_7d_status": "available",
                "tiers": [
                    { "tier": "7d", "credit": 100, "energy": 5, "cards": 1, "chances": 2 },
                    { "tier": "14d", "credit": 200, "energy": 8, "cards": 1, "chances": 3 }
                ]
            }
        });
        let full = StreakFull::from_data(&data);
        assert_eq!(full.days, 9);
        assert_eq!(full.makeup_cards, 2);
        assert_eq!(full.tiers.len(), 2);
        // 7d 的状态来自扁平字段，奖励读数来自 tiers 条目
        assert_eq!(full.tiers[0].status, "available");
        assert_eq!(full.tiers[0].credit, 100);
        assert_eq!(full.tiers[0].chances, 2);
        // 14d 没有对应的 tier_14d_status → 空状态，不可兑换
        assert_eq!(full.tiers[1].status, "");
        assert!(!full.tiers[1].redeemable());
    }

    #[test]
    fn streak_full_falls_back_to_flat_statuses() {
        let data = json!({
            "streak": { "days": 7 },
            "redemption_status": { "tier_7d_status": "claimed", "tier_28d_status": "locked" }
        });
        let full = StreakFull::from_data(&data);
        assert_eq!(full.tiers.len(), 2);
        assert_eq!(full.tiers[0].tier, "7d");
        assert_eq!(full.tiers[1].tier, "28d");
    }

    #[test]
    fn client_token_has_uuid_shape() {
        let token = client_token();
        let parts: Vec<&str> = token.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(parts[2].starts_with('4'));
        assert!(matches!(&parts[3][0..1], "8" | "9" | "a" | "b"));
        assert_ne!(token, client_token());
    }

    #[test]
    fn compact_prize_truncates_long_payloads() {
        let long = json!({ "name": "x".repeat(400) });
        let text = compact_prize(&long);
        assert!(text.chars().count() <= 161);
        assert!(text.ends_with('…'));
        assert_eq!(compact_prize(&json!(null)), "（空）");
    }
}
