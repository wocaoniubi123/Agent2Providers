//! AWS event stream 帧解析（Kiro 的响应格式）。
//!
//! ── 帧结构 ──────────────────────────────────────────────────
//! ```text
//!   [0..4)   total length（含所有字段）
//!   [4..8)   headers length
//!   [8..12)  prelude CRC（不校验）
//!   [12..12+headers)
//!   [..total-4) payload
//!   [total-4..total) message CRC（不校验）
//! ```
//!
//! 每个 header 是 `名称长度(1) 名称 类型(1) 值`：
//!   0=true / 1=false（无字节）、2=byte、3=short、4=int、5=long、8=timestamp、
//!   9=uuid、6=bytes（2 字节长度）、7=string（2 字节长度）。
//!
//! 我们只关心类型 7 的字符串：`:message-type`（event / exception / error）、
//! `:event-type`、`:exception-type`、`:error-code`。
//!
//! ── 为什么要自己解析 ────────────────────────────────────────
//! 网关的 `UpstreamKind` 是封闭枚举，没有 AWS event stream。走 `conversation`
//! 之后由插件自己读帧、自己推 chat SSE，是唯一不扩协议的路。

use agent2api_wasm_sdk::{Error, Result};

/// 一个解析出来的帧。
#[derive(Clone, Debug, Default)]
pub struct Frame {
    pub event_type: String,
    pub message_type: String,
    pub exception_type: String,
    pub error_code: String,
    pub payload: Vec<u8>,
}

impl Frame {
    /// 这一帧是不是错误（exception / error / 带错误码的事件）。
    pub fn is_error(&self) -> bool {
        self.message_type == "exception"
            || self.message_type == "error"
            || matches!(
                self.event_type.as_str(),
                "error" | "throttlingError" | "validationError" | "serviceUnavailableError" | "internalServerException"
            )
    }

    /// 错误的类型名（异常类型优先，其次事件名）。
    pub fn error_kind(&self) -> String {
        if !self.exception_type.is_empty() {
            self.exception_type.clone()
        } else if !self.error_code.is_empty() {
            self.error_code.clone()
        } else {
            self.event_type.clone()
        }
    }
}

/// 增量帧读取器（缓冲区 + 取帧）。
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl FrameReader {
    /// 追加一段上游字节。
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// 缓冲区里已经有一整帧就取出来（不足一帧返回 `Ok(None)`）。
    pub fn take(&mut self) -> Result<Option<Frame>> {
        if self.buffer.len() < 12 {
            return Ok(None);
        }
        let total = u32::from_be_bytes([self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]]) as usize;
        let header_length =
            u32::from_be_bytes([self.buffer[4], self.buffer[5], self.buffer[6], self.buffer[7]]) as usize;
        if total < 16 || total > (16 << 20) || header_length > total.saturating_sub(16) {
            return Err(Error::http(502, "Kiro 的事件流帧格式不对"));
        }
        if self.buffer.len() < total {
            return Ok(None);
        }
        let headers = parse_headers(&self.buffer[12..12 + header_length]);
        let payload = self.buffer[12 + header_length..total - 4].to_vec();
        self.buffer.drain(..total);
        Ok(Some(Frame {
            payload,
            event_type: headers.0,
            message_type: headers.1,
            exception_type: headers.2,
            error_code: headers.3,
        }))
    }

    /// 流结束时缓冲区还有残留 → 说明帧被截断。
    pub fn leftover(&self) -> usize {
        self.buffer.len()
    }
}

/// 解析 header 段，返回（event-type, message-type, exception-type, error-code）。
fn parse_headers(bytes: &[u8]) -> (String, String, String, String) {
    let mut event_type = String::new();
    let mut message_type = String::new();
    let mut exception_type = String::new();
    let mut error_code = String::new();
    let mut index = 0;
    while index < bytes.len() {
        let name_length = bytes[index] as usize;
        index += 1;
        if index + name_length + 1 > bytes.len() {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[index..index + name_length]).to_string();
        index += name_length;
        let kind = bytes[index];
        index += 1;
        match kind {
            0 | 1 => {
                if name == ":message-type" {
                    message_type = if kind == 0 { "event" } else { "error" }.to_string();
                }
            }
            2 | 3 | 4 | 5 | 8 | 9 => {
                let size = match kind {
                    2 => 1,
                    3 => 2,
                    4 => 4,
                    5 | 8 => 8,
                    _ => 16,
                };
                index += size;
            }
            6 | 7 => {
                if index + 2 > bytes.len() {
                    break;
                }
                let length = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
                index += 2;
                if index + length > bytes.len() {
                    break;
                }
                if kind == 7 {
                    let value = String::from_utf8_lossy(&bytes[index..index + length]).to_string();
                    match name.as_str() {
                        ":event-type" => event_type = value,
                        ":message-type" => message_type = value,
                        ":exception-type" => exception_type = value,
                        ":error-code" => error_code = value,
                        _ => {}
                    }
                }
                index += length;
            }
            _ => break,
        }
    }
    (event_type, message_type, exception_type, error_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工拼一帧：`assistantResponseEvent` + payload，验证头部解析与取帧。
    fn frame(event: &str, payload: &[u8]) -> Vec<u8> {
        let mut headers = Vec::new();
        let name = b":event-type";
        headers.push(name.len() as u8);
        headers.extend_from_slice(name);
        headers.push(7);
        headers.extend_from_slice(&(event.len() as u16).to_be_bytes());
        headers.extend_from_slice(event.as_bytes());
        let total = 12 + headers.len() + payload.len() + 4;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(total as u32).to_be_bytes());
        bytes.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&headers);
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    #[test]
    fn reads_a_whole_frame_in_two_pushes() {
        let bytes = frame("assistantResponseEvent", b"{\"content\":\"hi\"}");
        let split = bytes.len() / 2;
        let mut reader = FrameReader::default();
        reader.push(&bytes[..split]);
        // 半帧还在缓冲区里（没被解析出来）。
        assert_eq!(split, reader.leftover());
        assert!(reader.take().ok().flatten().is_none(), "半帧不该被解析出来");
        reader.push(&bytes[split..]);
        let Some(parsed) = reader.take().ok().flatten() else {
            assert!(false, "应当有一整帧");
            return;
        };
        assert_eq!("assistantResponseEvent", parsed.event_type);
        assert_eq!(b"{\"content\":\"hi\"}".to_vec(), parsed.payload);
        assert!(!parsed.is_error());
        assert_eq!(0, reader.leftover());
    }

    #[test]
    fn parses_exception_frame() {
        let bytes = frame("throttlingError", b"{}");
        let mut reader = FrameReader::default();
        reader.push(&bytes);
        let Some(parsed) = reader.take().ok().flatten() else {
            assert!(false, "应当有一整帧");
            return;
        };
        assert!(parsed.is_error());
        assert_eq!("throttlingError", parsed.error_kind());
    }
}
