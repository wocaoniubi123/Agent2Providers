//! 标准 base64（RFC 4648 §4，带 `=` 填充）的极简实现。
//!
//! ── 为什么自己写 ────────────────────────────────────────────
//! 本包只允许依赖 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`，
//! 没有 `base64` crate。而 MonkeyCode 的任务流**逐帧都要 base64**：
//! 下行 `data` 是 `base64(JSON)`、上行封帧同样是 `base64(JSON)`（见 `wire.rs`
//! 的模块头）。这里只做「标准字母表 + 填充」这一种，不做 URL-safe / 无填充变体
//! —— 上游用的是 Go 的 `encoding/json` 对 `[]byte` 的默认编码，就是这一种。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic，全部走 `Option`。

/// 标准字母表（索引即 6 位值）。
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 一个字节的 6 位值；非字母表字符返回 `None`。
fn value_of(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// 编码成标准 base64 文本（3 字节一组，末组按长度补 `=`）。
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((triple >> 18) & 63) as usize]));
        out.push(char::from(ALPHABET[((triple >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((triple >> 6) & 63) as usize]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(triple & 63) as usize]));
        } else {
            out.push('=');
        }
    }
    out
}

/// 解码标准 base64 文本。
///
/// 容错口径（都是「上游可能给、我们不能因此炸掉」的形态）：
///   - 两侧空白忽略；
///   - 缺末尾填充也接受（`data` 被人手改过时常见）；
///   - 任何非字母表字符、填充之后还有数据、末尾残留半个 6 位组 → 返回 `None`，
///     由调用方当成「这一帧解不出」处理，不猜内容。
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut output: Vec<u8> = Vec::with_capacity(text.len() / 4 * 3);
    let mut padded = false;
    for byte in text.trim().bytes() {
        if byte == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        let value = value_of(byte)?;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits) - 1;
        }
    }
    // 合法的末组只会剩 0 / 2 / 4 个补位；剩 6 位说明最后一个字符是孤立的。
    if bits >= 6 {
        return None;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 的官方向量（含三种末组长度与空输入）。
    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encoded, encode(plain.as_bytes()));
            assert_eq!(plain.as_bytes(), decode(encoded).unwrap_or_default().as_slice());
        }
    }

    /// 高位字节（0x80 以上）必须按无符号处理 —— 有符号转换会把 0xFF 变成负数。
    #[test]
    fn high_bytes_round_trip() {
        let bytes = [0x00u8, 0x7f, 0x80, 0xff, 0xfe, 0x01];
        let encoded = encode(&bytes);
        // 对照 .NET `Convert.ToBase64String` 的实测值
        assert_eq!("AH+A//4B", encoded);
        assert_eq!(bytes.to_vec(), decode(&encoded).unwrap_or_default());
    }

    /// 中文 JSON 的往返：上行封帧就是把 UTF-8 文本编码成 base64，解回来必须逐字相同。
    #[test]
    fn utf8_round_trip() {
        let text = r#"{"id":"任务-01","approved":true}"#;
        assert_eq!(text, String::from_utf8_lossy(&decode(&encode(text.as_bytes())).unwrap_or_default()));
    }

    #[test]
    fn tolerant_and_strict_inputs() {
        // 两侧空白忽略、缺填充接受
        assert_eq!(b"foo".to_vec(), decode("  Zm9v \n").unwrap_or_default());
        assert_eq!(b"foob".to_vec(), decode("Zm9vYg").unwrap_or_default());
        // 非法字符 / 填充后还有数据 / 孤立的末字符 → 明确失败
        assert!(decode("Zm9v!!!!").is_none());
        assert!(decode("Zg==Zg==").is_none());
        assert!(decode("Zm9vY").is_none());
    }
}
