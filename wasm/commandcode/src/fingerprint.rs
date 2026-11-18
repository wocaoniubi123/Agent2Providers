//! Command Code 的**设备指纹**（确定性派生）与两条预请求（握手）。
//!
//! ── 上游为什么要这两条预请求 ────────────────────────────────
//! `device_fingerprints` 表按 `(userId, thumbmark)` 建唯一索引。官方 CLI 每次
//! 启动上报一次「我在哪台机器上」，网关必须复刻同一件事：
//! ```text
//!   POST /alpha/fingerprint/record   {thumbmark, components{15 项}}
//!   POST /alpha/lifecycle-events     {eventType:"cli_session_exists", metadata{…}}
//! ```
//! 两条**并行发出**，每个 key 首次请求前 + 每 8h（+0~2h 抖动）一次；
//! **失败不阻塞生成**（只告警，下次请求再试）。
//!
//! ── 为什么指纹必须由 apiKey **确定性派生**（而不是随机 / 取模）───
//!   1. **随机**：进程重启、内存回收、多实例都会无故换机器 —— 设备身份漂移
//!      本身就是可疑信号；
//!   2. **取模分桶**：桶数就是熵上限，key 数一超过桶数必然出现多个 key 共用
//!      指纹，而上游那张表上「共用指纹 = 多账号同机」的直接证据；
//!   3. **本实现**：`sha256(salt\0apiKey\0字段)` 逐字段派生，每 key 都是独立设备
//!      （碰撞概率 2^-256），且**同一 key 每次得到同一个指纹** —— 不落盘也能
//!      重启一致。
//! 从候选池里挑一项用「打分取最大」而不是取模：往池里加候选只影响「新候选恰好
//! 胜出」的那部分 key，不会像取模那样因池长度变化让所有 key 一起换设备。
//!
//! ── 本机真实信息一个字都不出网 ─────────────────────────────────
//! 平台 / 架构 / 系统版本 / 项目目录全部用**设备档案**里的固定常量 ——
//! 同一个档案也供 `plan.rs` 的 `config` 块与 `x-project-slug` 使用，
//! 避免出现「指纹说 win32、环境说 linux」这类自相矛盾。
//!
//! ── TTL 状态放在哪（为什么不用进程内表）──────────────────────
//! 刷新周期是客户端侧约定（服务端不下发 TTL），而指纹本身是确定性派生的，
//! 重启后重算即同值。native 用一张进程内存表（`key 摘要 → 上次上报时刻`）；
//! **wasm 里那张表存不住**：宿主每次调用后回收实例（这条结论已在
//! `wasm/workbuddy` 的迁移里核实），`static` 在两次调用之间是空的，于是每个
//! 请求都会重新上报两条预请求 —— 量级从「每 8 小时一次」变成「每请求一次」。
//!
//! 因此这里改用宿主的账号级状态（`state.v1` 的 `account` 作用域）：它在网关侧
//! **落库**（`plugin_state_compare_exchange_strict`），跨调用、跨实例都有效，
//! 且天然按账号隔离。存的内容是 `{thumbmark, next_init_at}`：
//!   - 指纹变了（比如用户改了派生盐）→ 立即重新上报；
//!   - 未到期 → 零开销早退。
//! 并发首帧最坏只会重复上报一次（两条都是 upsert 语义，无副作用）——
//! native 的 `in_flight` 标记省掉的是这一次重复，代价是要有进程内表。
//!
//! ── wasm 侧与 native 的三处差别（都是平台约束，不是取舍）──────────
//!   1. **没有并行**：native 用 `futures::join!` 同时发两条；wasm 里 `http::open`
//!      是同步阻塞调用，只能顺序发。两条都是几十毫秒级的空 POST，顺序发的代价
//!      是每个刷新周期多一次往返 —— 不影响正确性，也不影响生成；
//!   2. **没有日志通道**：native 失败时 `log_info!` 告警；wasm SDK 没有日志方法，
//!      失败保持完全静默（`best-effort` 的语义不变：仍然不推进节流、下次再试）；
//!   3. **随机源走宿主**：`random.bytes`（`getrandom` 在 wasm 里没有实现），
//!      失败时回落「时间戳 + 计数」—— 只影响 `traceparent` 与 `sess_…` 这两个
//!      追踪串，不参与指纹派生。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::state::Scope;
use agent2api_wasm_sdk::{self as sdk, http, json, Value};
use sha2::{Digest, Sha256};

use super::endpoints;
use super::util;

/// CLI 的根盐（参与最终哈希，不可改）
pub const FP_SALT: &str = "command-code:device-fingerprint:v1";

/// 固定的设备档案：平台 / 架构 / 系统版本（**不读宿主真实平台**）
pub const DEVICE_PLATFORM: &str = "win32";
/// 见 [`DEVICE_PLATFORM`]
pub const DEVICE_ARCH: &str = "x64";
/// 见 [`DEVICE_PLATFORM`]（Windows 11 23H2 的版本串）
pub const DEVICE_OS_RELEASE: &str = "10.0.22631";

/// 固定的默认项目目录。
///
/// 为什么发固定值而不是宿主真实 cwd：真实路径会泄露用户名与目录结构。
pub const DEFAULT_DEVICE_PROJECT_DIR: &str = "C:\\Users\\dev\\projects\\app";

/// CPU 候选表（型号 + 物理核数 + 逻辑处理器数）。
///
/// `threads` 才是出网值；`cores` 只参与候选标签的构造 —— 标签必须与参考实现
/// 逐字一致（`model|cores`），否则同一个 key 会挑出不同的设备。
const CPUS: [(&str, i64, i64); 15] = [
    ("12th Gen Intel(R) Core(TM) i7-12650H", 10, 16),
    ("12th Gen Intel(R) Core(TM) i5-12400F", 6, 12),
    ("12th Gen Intel(R) Core(TM) i9-12900K", 16, 24),
    ("13th Gen Intel(R) Core(TM) i7-13700K", 16, 24),
    ("13th Gen Intel(R) Core(TM) i5-13600K", 14, 20),
    ("13th Gen Intel(R) Core(TM) i9-13900K", 24, 32),
    ("Intel(R) Core(TM) Ultra 7 155H", 16, 22),
    ("Intel(R) Core(TM) Ultra 9 285H", 16, 16),
    ("Intel(R) Core(TM) i9-14900K", 24, 32),
    ("Intel(R) Core(TM) i7-14700K", 20, 28),
    ("AMD Ryzen 7 7800X3D", 8, 16),
    ("AMD Ryzen 9 7950X", 16, 32),
    ("AMD Ryzen 5 7600", 6, 12),
    ("AMD Ryzen 9 7900X", 12, 24),
    ("AMD Ryzen 7 5800X3D", 8, 16),
];

/// 内存（GiB）候选
const MEMS: [i64; 6] = [8, 16, 24, 32, 48, 64];

/// 时区候选（本机 OS 时区语义，**不与出口 IP 绑定**）
const TIMEZONES: [&str; 15] = [
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "America/Toronto",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Paris",
    "Europe/Moscow",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Asia/Seoul",
    "Asia/Hong_Kong",
    "Australia/Sydney",
    "Pacific/Auckland",
];

/// MAC 地址条数候选（2~5）
const MAC_COUNTS: [i64; 4] = [2, 3, 4, 5];

/// 系统用户名候选
const OS_USERS: [&str; 6] = ["dev", "user", "admin", "coder", "engineer", "work"];

/// git 邮箱域名候选
const MAIL_DOMAINS: [&str; 4] = ["gmail.com", "outlook.com", "qq.com", "163.com"];

/// 指纹刷新周期（8 小时）
const INIT_REFRESH_MS: i64 = 8 * 60 * 60 * 1000;
/// 刷新抖动上限（0~2 小时随机）
const INIT_JITTER_MS: i64 = 2 * 60 * 60 * 1000;

/// 一次派生出的设备指纹
pub struct DeviceFingerprint {
    /// 设备指纹（64 位小写 hex；上游 `(userId, thumbmark)` 的唯一键）
    pub thumbmark: String,
    /// 15 项组件（出网的完整形状）
    pub components: Value,
}

impl DeviceFingerprint {
    /// `POST /alpha/fingerprint/record` 的请求体
    pub fn record_payload(&self) -> Value {
        json!({
            "thumbmark": self.thumbmark,
            "components": self.components,
        })
    }
}

/// 派生盐：设置项 `fingerprintSalt` 可覆盖。
///
/// 它**只影响「映射到哪台机器」**，不参与最终哈希。留空时派生是 apiKey 的
/// 纯函数（可被反推），因此建议设盐；多实例部署必须设同一个值。
pub fn fingerprint_salt() -> String {
    endpoints::setting("fingerprintSalt").unwrap_or_default()
}

/// 固定的项目目录：设置项 `deviceProjectDir` 可覆盖
pub fn device_project_dir() -> String {
    endpoints::setting("deviceProjectDir")
        .unwrap_or_else(|| DEFAULT_DEVICE_PROJECT_DIR.to_string())
}

/// CLI 的 slug 规则：整串小写、非字母数字折成 `-`、去首尾 `-`，空则 `root`。
pub fn slugify_project_path(path: &str) -> String {
    let lowered = path.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut pending_dash = false;
    for ch in lowered.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(ch);
        } else {
            pending_dash = true;
        }
    }
    if out.is_empty() {
        "root".to_string()
    } else {
        out
    }
}

/// `sha256("<salt>\0<apiKey>\0<field>")`（返回原始 32 字节）
fn fp_digest(api_key: &str, field: &str) -> [u8; 32] {
    let salt = fingerprint_salt();
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update([0u8]);
    hasher.update(api_key.as_bytes());
    hasher.update([0u8]);
    hasher.update(field.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

/// 从候选池里确定性地挑一项：`argmax_i digest(apiKey, "{field}\0{label_i}")`。
///
/// 比较是**词典序字节比较**（对齐参考实现的 `Buffer.compare`），不是取模。
fn fp_pick_index(api_key: &str, field: &str, labels: &[String]) -> usize {
    let mut best_index = 0usize;
    let mut best_score: Option<[u8; 32]> = None;
    for (index, label) in labels.iter().enumerate() {
        let score = fp_digest(api_key, &format!("{field}\0{label}"));
        if best_score.map(|best| score > best).unwrap_or(true) {
            best_score = Some(score);
            best_index = index;
        }
    }
    best_index
}

/// 小写 hex
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// CLI 的 `hashSignal`：`sha256(FP_SALT\0小写明文)` 的 hex。
///
/// 空值在参考实现里被丢弃（返回 undefined）。本模块的调用点传入的都是
/// 派生出来的非空值，因此这里对空输入给 None、并在组件里**不插入**该键。
fn fingerprint_hash(value: &str) -> Option<String> {
    let lowered = value.trim().to_lowercase();
    if lowered.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(FP_SALT.as_bytes());
    hasher.update([0u8]);
    hasher.update(lowered.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

/// 由 apiKey 确定性地派生一整套设备指纹。
pub fn generate(api_key: &str) -> DeviceFingerprint {
    // 候选标签必须与参考实现逐字一致（标签是派生输入的一部分）
    let cpu_labels: Vec<String> = CPUS
        .iter()
        .map(|(model, cores, _)| format!("{model}|{cores}"))
        .collect();
    let cpu = CPUS[fp_pick_index(api_key, "cpu", &cpu_labels)];
    let mem_labels: Vec<String> = MEMS.iter().map(|value| value.to_string()).collect();
    let mem_gib = MEMS[fp_pick_index(api_key, "mem", &mem_labels)];
    let tz_labels: Vec<String> = TIMEZONES.iter().map(|value| (*value).to_string()).collect();
    let timezone = TIMEZONES[fp_pick_index(api_key, "timezone", &tz_labels)];
    let mac_labels: Vec<String> = MAC_COUNTS.iter().map(|value| value.to_string()).collect();
    let mac_count = MAC_COUNTS[fp_pick_index(api_key, "macCount", &mac_labels)];
    let user_labels: Vec<String> = OS_USERS.iter().map(|value| (*value).to_string()).collect();
    let os_user = OS_USERS[fp_pick_index(api_key, "osUser", &user_labels)];
    let domain_labels: Vec<String> = MAIL_DOMAINS
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let mail_domain = MAIL_DOMAINS[fp_pick_index(api_key, "mailDomain", &domain_labels)];

    // 派生字段：hex(前 N 字节)
    let hex_field = |field: &str, bytes: usize| -> String {
        let digest = fp_digest(api_key, field);
        hex_of(&digest[..bytes.min(digest.len())])
    };
    // Windows MachineGuid 形状：8-4-4-4-12
    let mid = hex_field("machineId", 16);
    let machine_id = if mid.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &mid[0..8],
            &mid[8..12],
            &mid[12..16],
            &mid[16..20],
            &mid[20..32]
        )
    } else {
        mid.clone()
    };
    let mut macs: Vec<String> = Vec::new();
    for index in 0..mac_count.max(0) {
        let digest = fp_digest(api_key, &format!("mac{index}"));
        let parts: Vec<String> = digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        macs.push(parts.join(":"));
    }
    // CLI 对 MAC 去重后排序
    macs.sort();
    macs.dedup();
    let hostname = format!("DESKTOP-{}", hex_field("hostname", 4).to_uppercase());
    let git_email = format!("{os_user}.{}@{mail_domain}", hex_field("gitEmail", 3));

    // thumbmark：`sha256(FP_SALT + "\0machine\0" + join('|'))`；machineId 非空时
    // 不再拼 hostname / cpuModel（参考实现里 machineId 恒非空，走的就是这一支）
    let thumb_seed: Vec<String> = vec![
        machine_id.trim().to_string(),
        macs.join(","),
        if machine_id.trim().is_empty() {
            hostname.clone()
        } else {
            String::new()
        },
        if machine_id.trim().is_empty() {
            cpu.0.to_string()
        } else {
            String::new()
        },
    ]
    .into_iter()
    .filter(|value| !value.is_empty())
    .collect();
    let seed = if thumb_seed.is_empty() {
        "unknown".to_string()
    } else {
        thumb_seed.join("|")
    };
    let thumbmark = {
        let mut hasher = Sha256::new();
        hasher.update(FP_SALT.as_bytes());
        hasher.update(b"\0machine\0");
        hasher.update(seed.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    // 15 项组件：哈希字段走 fingerprint_hash（本实现里都非空），明文字段直接给
    let mut components = serde_json::Map::new();
    for (key, value) in [
        ("machineIdHash", machine_id.as_str()),
        ("osUserHash", os_user),
        ("hostnameHash", hostname.as_str()),
        ("gitEmailHash", git_email.as_str()),
    ] {
        if let Some(hashed) = fingerprint_hash(value) {
            components.insert(key.to_string(), Value::String(hashed));
        }
    }
    let mac_hashes: Vec<Value> = macs
        .iter()
        .filter_map(|mac| fingerprint_hash(mac).map(Value::String))
        .collect();
    if !mac_hashes.is_empty() {
        components.insert("macHashes".to_string(), Value::Array(mac_hashes));
    }
    components.insert(
        "platform".to_string(),
        Value::String(DEVICE_PLATFORM.to_string()),
    );
    components.insert("arch".to_string(), Value::String(DEVICE_ARCH.to_string()));
    components.insert(
        "osRelease".to_string(),
        Value::String(DEVICE_OS_RELEASE.to_string()),
    );
    components.insert("cpuModel".to_string(), Value::String(cpu.0.to_string()));
    // cpuCount 取 **threads**（逻辑处理器数）：CLI 的 gatherRawSignals 取
    // `os.cpus().length`，明文对会被服务端交叉核对
    components.insert("cpuCount".to_string(), Value::from(cpu.2));
    components.insert("memGiB".to_string(), Value::from(mem_gib));
    components.insert("isContainer".to_string(), Value::Bool(false));
    components.insert("timezone".to_string(), Value::String(timezone.to_string()));
    components.insert("runtime".to_string(), Value::String("cli".to_string()));
    components.insert("collectorVersion".to_string(), Value::from(1));

    DeviceFingerprint {
        thumbmark,
        components: Value::Object(components),
    }
}

/// 生成一个 W3C traceparent（`00-<32hex trace>-<16hex parent>-01`）
pub fn traceparent() -> String {
    format!("00-{}-{}-01", util::random_hex(16), util::random_hex(8))
}

/// lifecycle 事件的请求体（`cli_session_exists`）。
///
/// 形状**恰为** `{eventType, metadata{sessionId, cliVersion, mode, os}}` ——
/// 15 项组件之外一个字段都不能多（上游按形状核对）。
fn lifecycle_payload() -> Value {
    json!({
        "eventType": "cli_session_exists",
        "metadata": {
            // 每次上报一个随机 id（参考实现同款；它不是聊天会话 id）
            "sessionId": format!("sess_{}", util::random_hex(8)),
            "cliVersion": endpoints::protocol_version(),
            "mode": "interactive",
            "os": format!("{DEVICE_PLATFORM}-{DEVICE_ARCH}"),
        },
    })
}

/// 节流状态在宿主账号级状态里的 key（`state.v1` 的 `account` 作用域）
const STATE_KEY: &str = "fingerprint-init";
/// 状态格式版本（换结构就加一，旧值按不兼容处理）
const STATE_SCHEMA: u32 = 1;
/// 状态保留期（远大于 8h + 2h 抖动；账号级状态在网关侧是落库的，这只是一层保护）
const STATE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 0~2 小时的随机抖动（随机源不可用时给 0）
fn random_jitter() -> i64 {
    let hex = util::random_hex(4);
    u32::from_str_radix(&hex, 16)
        .map(|value| (value as i64) % (INIT_JITTER_MS + 1))
        .unwrap_or(0)
}

/// 确保「指纹已上报」（每 key 首次 + 每 8h+2h 抖动）—— **best-effort**。
///
/// 契约（与参考实现的 `ensureInitialized` 逐条对齐）：
///   - 未到期直接返回（零开销的快速路径）；
///   - 两条预请求发出，**任何失败都不影响生成**（wasm 侧静默，见模块头第 2 条）；
///   - `next_init_at` 只在**两条都拿到 HTTP 响应**时推进 —— 传输层失败
///     （连不上 / 超时）不推进，于是「下次请求再试」这一条成立；
///   - 指纹变了（换了派生盐）→ 立刻重新上报。
///
/// 调用点：`account::ensure`（每次转发前的凭证准备）与 `chat::forward` 的开头
/// （网关走会话式通道时**不会**先调 `token.ensure`，所以那一处必须自己兜一次；
/// 两处共用同一份宿主状态，不会真的报两遍）。
pub fn ensure_initialized(api_key: &str) {
    let key = api_key.trim();
    if key.is_empty() {
        return;
    }
    let fingerprint = generate(key);
    let now = util::now_ms();
    // 先读宿主状态（拿不到 = 没有节流能力，直接上报，语义仍是 best-effort）
    let (revision, stored) = match sdk::state::get(Scope::Account, STATE_KEY, STATE_SCHEMA) {
        Ok(snapshot) => (snapshot.revision, snapshot.value),
        Err(_) => (0, Value::Null),
    };
    let same_device = stored.get("thumbmark").and_then(Value::as_str)
        == Some(fingerprint.thumbmark.as_str());
    let next_init_at = stored.get("next_init_at").and_then(Value::as_i64).unwrap_or(0);
    if same_device && next_init_at > now {
        return;
    }

    let mut headers = endpoints::cli_headers();
    headers.extend(endpoints::auth_headers(key));
    let headers = util::headers_value(&headers);
    // 顺序发两条（native 的 futures::join! 在 wasm 单线程里没有对应物，见模块头）
    let fingerprint_result = http::open(
        "POST",
        &endpoints::url(endpoints::FINGERPRINT_PATH),
        headers.clone(),
        Some(&fingerprint.record_payload()),
    );
    let lifecycle_result = http::open(
        "POST",
        &endpoints::url(endpoints::LIFECYCLE_PATH),
        headers,
        Some(&lifecycle_payload()),
    );
    // 「两条都拿到了 HTTP 响应」才算这一轮走完（非 2xx 也算 —— 参考实现在
    // 那种情况下同样推进节流）
    let settled = fingerprint_result.is_ok() && lifecycle_result.is_ok();
    for result in [fingerprint_result, lifecycle_result] {
        if let Ok(response) = result {
            // 读掉响应体：状态码已经拿到，body 对这里没有意义，但读完能让宿主
            // 侧连接走到 EOF 而不是留一个半开的句柄。
            let _ = response.bytes(64 * 1024);
        }
    }
    if settled {
        // CAS 失败说明另一个并发调用刚写过 —— 无妨，两条预请求都是 upsert 语义
        let _ = sdk::state::compare_exchange(
            Scope::Account,
            STATE_KEY,
            STATE_SCHEMA,
            revision,
            json!({
                "thumbmark": fingerprint.thumbmark,
                "next_init_at": util::now_ms() + INIT_REFRESH_MS + random_jitter(),
            }),
            STATE_TTL_MS,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_matches_the_cli_rule() {
        assert_eq!(
            slugify_project_path(DEFAULT_DEVICE_PROJECT_DIR),
            "c-users-dev-projects-app"
        );
        assert_eq!(slugify_project_path(""), "root");
        assert_eq!(slugify_project_path("///"), "root");
        assert_eq!(slugify_project_path("/srv/App_v2/"), "srv-app-v2");
    }

    #[test]
    fn fingerprint_is_deterministic_and_complete() {
        let first = generate("user_alpha");
        let second = generate("user_alpha");
        assert_eq!(first.thumbmark, second.thumbmark);
        assert_eq!(first.thumbmark.len(), 64);
        let Some(components) = first.components.as_object() else {
            assert!(false, "components 必须是对象");
            return;
        };
        // 15 项：4 个哈希 + macHashes + 10 个明文字段
        assert_eq!(components.len(), 15);
        assert!(components.contains_key("machineIdHash"));
        assert!(components.contains_key("macHashes"));
        assert_eq!(components["platform"], json!("win32"));
        assert_eq!(components["arch"], json!("x64"));
        assert_eq!(components["runtime"], json!("cli"));
        assert_eq!(components["collectorVersion"], json!(1));
        assert_eq!(components["isContainer"], json!(false));
        // cpuCount 必须在候选表的 threads 列里（不是物理核数）
        let threads: Vec<i64> = CPUS.iter().map(|(_, _, threads)| *threads).collect();
        let chosen = components["cpuCount"].as_i64().unwrap_or(-1);
        assert!(threads.contains(&chosen), "cpuCount={chosen} 不在 threads 列里");
    }

    #[test]
    fn different_keys_get_different_devices() {
        let alpha = generate("user_alpha");
        let beta = generate("user_beta");
        assert_ne!(alpha.thumbmark, beta.thumbmark);
    }

    #[test]
    fn lifecycle_payload_has_exactly_the_four_metadata_keys() {
        let payload = lifecycle_payload();
        assert_eq!(payload["eventType"], json!("cli_session_exists"));
        let Some(metadata) = payload["metadata"].as_object() else {
            assert!(false, "metadata 必须是对象");
            return;
        };
        assert_eq!(metadata.len(), 4);
        assert!(metadata.contains_key("sessionId"));
        assert!(metadata.contains_key("cliVersion"));
        assert_eq!(metadata["mode"], json!("interactive"));
        assert_eq!(metadata["os"], json!("win32-x64"));
    }

    #[test]
    fn traceparent_shape_is_w3c() {
        let value = traceparent();
        let parts: Vec<&str> = value.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
        assert!(parts[1].chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}
