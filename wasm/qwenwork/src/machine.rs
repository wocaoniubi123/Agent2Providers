//! 千问办公的**设备标识**（native `machine.rs` 的单站点裁剪版）。
//!
//! ── native 怎么做 ──────────────────────────────────────────
//! 一份落盘文件（`{data_dir}/qwenwork-machine-id`），首次生成时优先沿用官方客户端
//! 目录里那份（`~/.qoderworkcn/.auth/machine_id`，已被证明能用于签名），取不到
//! 才随机生成。上游把它当作「这台设备」，并且**按设备聚合账号** —— 所以它必须
//! 跨重启稳定。
//!
//! ── 为什么必须与 Qoder 分开（native 模块头的结论）────────────
//! Qoder 与千问办公是两个产品、两套风控；共用一个设备标识等于把它们关联到同一台
//! 设备上。所以派生种子前缀用 `qwenwork-machine`（`wasm/qoder` 是 `qoder-machine`），
//! 两个包各自派生各自的。
//!
//! ── wasm 里怎么做（没有文件系统）─────────────────────────────
//! 按优先级取：
//!   1. 账号记录里的 `machineId`（native 写的记录带它，迁移过来的账号原样沿用）；
//!   2. `refreshToken` 的 `|userId|machineId` 后缀（同样来自 native 的打包形态）；
//!   3. 由**账号 id** 派生的稳定 UUID —— 同一账号每次重启都派生同一个值，
//!      因此不会变成「每次重启一台新设备」。派生而不是随机，是因为 wasm 插件
//!      拿不到持久化目录，而随机值会破坏上面那条聚合语义。
//! 登录（还没有账号时）用一次性随机 UUID，拿到账号后它会被写进记录。

use sha2::{Digest, Sha256};

use super::crypto;

/// 由种子派生一个稳定的 UUID v4 形态标识。
pub fn stable_id(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"qwenwork-machine");
    hasher.update([0u8]);
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = crypto::hex_lower(&bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// 本账号的设备标识：记录里没有时按 `seed`（账号 id）派生。
pub fn machine_id(record_machine_id: &str, seed: &str) -> String {
    let recorded = record_machine_id.trim();
    if !recorded.is_empty() {
        return recorded.to_string();
    }
    stable_id(seed)
}

/// 登录阶段（还没有账号）用的临时设备标识。
pub fn login_machine_id() -> String {
    crypto::uuid_v4()
}
