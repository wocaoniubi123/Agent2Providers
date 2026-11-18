//! 编解码小工具：base64 解码与十六进制。
//!
//! ── 为什么自己写 ────────────────────────────────────────────
//! 本包只允许依赖 `agent2api-wasm-sdk` / `serde_json` / `sha2` / `chrono`，
//! 所以 base64 解码不能引 `base64` crate；这里只实现解码（宿主的
//! `random.bytes` 与图片 data URL 都是标准 base64 入参），编码交给 SDK。

/// 标准 base64 解码（容忍 `=` 填充与缺失填充；出现非法字符返回 `None`）。
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    let mut buffer: u32 = 0;
    let mut bits = 0_u32;
    for byte in bytes {
        if matches!(*byte, b'=' | b'\n' | b'\r' | b' ' | b'\t') {
            if *byte == b'=' {
                break;
            }
            continue;
        }
        let digit = value(*byte)?;
        buffer = (buffer << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(output)
}

/// 十六进制（小写）。
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 已知向量自检：手写解码最容易错的三种情况（填充、无填充、非法字符）。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_解码标准向量() {
        assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64_decode(""), Some(Vec::new()));
        assert_eq!(base64_decode("AAEC/w=="), Some(vec![0, 1, 2, 255]));
        assert_eq!(base64_decode("!!!"), None);
    }

    #[test]
    fn 十六进制小写() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
