//! 随机标识生成：`conversationId` / `turnRequestId` / `messageId` /
//! `M-TRACEID` 都用同一个形态（native `crate::ids::new_conversation_id`）。
//!
//! ── 为什么走宿主随机（而不是自拼时间戳）───────────────────────
//! `conversationId` 一旦重复，上游会把两个客户端会话当成同一个对话 ——
//! 时序与历史全部串台，且没有任何报错。宿主提供 `random.bytes`
//! （`random.v1` 能力）是真正的密码学随机源，比「时间戳 + 计数器」可靠。
//! 随机源本身与降级规则收在 `codec.rs`（一处口径，见那边的模块头）。
//!
//! ── 为什么是 UUID v4 形态而不是裸十六进制 ──────────────────────
//! native 与原实现（客户端 `randomUUID()`）都用这个形态；上游对 id 只做
//! 非空与长度校验，但**保持与原实现同形**能让抓包对照时一眼认出同一个东西。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic。

/// 16 字节随机源（宿主随机；拿不到时由 `codec` 派生）。
fn random16() -> [u8; 16] {
    let bytes = crate::codec::random_bytes(16);
    let mut out = [0_u8; 16];
    let limit = out.len().min(bytes.len());
    out[..limit].copy_from_slice(&bytes[..limit]);
    out
}

/// 新 UUID v4（小写带连字符，与 `randomUUID()` 同形）。
pub fn new_id() -> String {
    let mut bytes = random16();
    // 版本位 4、变体位 10xxxxxx（RFC 4122）
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = crate::codec::hex_lower(&bytes);
    // hex 恒为 32 个 ASCII 字符，切片边界不会落在多字节字符中间
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `M-TRACEID`：去掉连字符的同一个随机串（native `replace('-', "")`）。
pub fn new_trace_id() -> String {
    new_id().replace('-', "")
}

/// 面向客户端的响应 id（`chatcmpl-` + 24 位，native `openai::new_chat_id`）。
pub fn new_chat_id() -> String {
    let plain = new_id().replace('-', "");
    let head: String = plain.chars().take(24).collect();
    format!("chatcmpl-{head}")
}
