//! SHA-1（FIPS 180-4）：只为本家的**会话派生**（`threadId`）服务。
//!
//! ── 为什么手写一份 ────────────────────────────────────────────
//! 本包的依赖白名单只有 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`，
//! 而 native 的 `plan.rs` 用的是 `sha1` crate。这处摘要**不参与任何安全判定**：
//! 它的唯一用途是把同一场对话映射到上游同一个线程（`threadId`），换一个值最多
//! 让上游换一次缓存前缀，不涉及凭证、签名或身份。因此按仓库先例手写：
//! `wasm/codearts/src/signer.rs` 手写 HMAC、`wasm/qoder/src/crypto.rs` 手写
//! MD5/AES/RSA、`wasm/trae/src/p256.rs` 手写 P-256。
//!
//! ── 正确性怎么钉住 ────────────────────────────────────────────
//! 文件尾的 `tests` 用 FIPS 180-4 附录 A / RFC 3174 的公开测试向量逐条比对：
//! 空串、`abc`、448 位边界、512 位边界、百万个 `a`，以及「分段喂入与一次喂入
//! 结果相同」这一条（`update` 的缓冲逻辑最容易在这里写错）。
//!
//! ── 硬约束 ────────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，也不做越界索引
//! （所有切片都先由长度判断保护）。

/// SHA-1 的初始链接值（FIPS 180-4 §5.3.1）
const H0: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// 分组长度（字节）
const BLOCK: usize = 64;

/// 流式 SHA-1（`update` 任意次，`finalize` 一次）。
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; BLOCK],
    filled: usize,
    /// 已喂入的**字节**数（换成位数时左移 3；`u64` 的 2^61 字节上限远超本用途）
    total: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: H0,
            block: [0u8; BLOCK],
            filled: 0,
            total: 0,
        }
    }

    /// 喂入一段字节。
    pub fn update(&mut self, data: &[u8]) {
        self.total = self.total.saturating_add(data.len() as u64);
        let mut rest = data;
        // 1) 先把上一次留下的半块填满
        if self.filled > 0 {
            let need = BLOCK - self.filled;
            let take = rest.len().min(need);
            self.block[self.filled..self.filled + take].copy_from_slice(&rest[..take]);
            self.filled += take;
            rest = &rest[take..];
            if self.filled == BLOCK {
                // `[u8; 64]` 是 `Copy`：先复制出来，避免同时借 `self.state` 与 `self.block`
                let block = self.block;
                compress(&mut self.state, &block);
                self.filled = 0;
            }
        }
        // 2) 整块直接压缩
        while rest.len() >= BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&rest[..BLOCK]);
            compress(&mut self.state, &block);
            rest = &rest[BLOCK..];
        }
        // 3) 余数留到下一次
        if !rest.is_empty() {
            self.block[..rest.len()].copy_from_slice(rest);
            self.filled = rest.len();
        }
    }

    /// 收尾：补 `0x80`、补零到 56 mod 64、追加 64 位大端位长。
    pub fn finalize(mut self) -> [u8; 20] {
        // 位长必须在补位之前算好：`update` 会继续累加 `total`
        let bits = self.total.saturating_mul(8);
        self.update(&[0x80]);
        // 一直补到 `filled == 56`。`filled` 在 0..63 之间循环，必然经过 56。
        while self.filled != 56 {
            self.update(&[0x00]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (index, word) in self.state.iter().enumerate() {
            let at = index * 4;
            out[at..at + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// 压缩一个 512 位分组（FIPS 180-4 §6.1.2）
fn compress(state: &mut [u32; 5], block: &[u8; BLOCK]) {
    let mut schedule = [0u32; 80];
    for (index, slot) in schedule.iter_mut().take(16).enumerate() {
        let at = index * 4;
        *slot = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
    }
    for index in 16..80 {
        let value = schedule[index - 3]
            ^ schedule[index - 8]
            ^ schedule[index - 14]
            ^ schedule[index - 16];
        schedule[index] = value.rotate_left(1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for (index, word) in schedule.iter().enumerate() {
        let (f, k) = match index {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// 一次性摘要（只给测试用：正式路径都走流式 `update`）
#[cfg(test)]
pub fn digest(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn empty_input_matches_fips_vector() {
        // FIPS 180-4 附录 A：SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(
            hex(&digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn abc_matches_rfc3174_vector() {
        // RFC 3174 §7.3 第二个向量
        assert_eq!(
            hex(&digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn two_block_message_matches_vector() {
        // FIPS 180-4 附录 A：448 位消息
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn long_message_matches_vector() {
        // FIPS 180-4 附录 A：896 位消息
        assert_eq!(
            hex(&digest(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "a49b2446a02c645bf419f995b67091253a04a259"
        );
    }

    #[test]
    fn million_a_matches_vector() {
        // FIPS 180-4 附录 A：1,000,000 个 'a'
        let mut hasher = Sha1::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hex(&hasher.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn segmented_updates_equal_single_update() {
        // 缓冲逻辑的边界：每段长度都跨过分组边界
        let message = b"the quick brown fox jumps over the lazy dog repeated a few times";
        let single = hex(&digest(message));
        for split in [0usize, 1, 7, 55, 56, 63, 64, 65, 127] {
            let (head, tail) = message.split_at(split.min(message.len()));
            let mut hasher = Sha1::new();
            hasher.update(head);
            hasher.update(tail);
            assert_eq!(hex(&hasher.finalize()), single, "split at {split}");
        }
    }
}
