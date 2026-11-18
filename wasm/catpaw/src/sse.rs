//! 上游 SSE 分帧（本 crate 自用；native 用 `crate::sse_events::DataEvents`）。
//!
//! ── 为什么不直接用 `sdk::sse::SseDecoder` ───────────────────
//! SDK 那个解码器**没有 `finish()`**：它只在遇到空行时派发数据帧，正常路径够用，
//! 但本家的收尾判据是「完整 DONE 或 HTTP EOF」（硬约束 2，见 `turn.rs`）——
//! EOF 时缓冲区里若还有一帧没有尾随空行，SDK 版本会把它丢掉。native 的实现
//! 有 `finish()`（`DataEvents::finish`），这里按同一语义补上：
//!   - `push`：按行切分，遇到空行派发累积的 `data:` 段；
//!   - `finish`：EOF 时把最后一段（若有）派发出去。
//!
//! ── SSE 分帧口径（与原实现 / 规范一致）────────────────────
//!   - `data:` 后可选一个空格；多行 `data:` 用 `\n` 连接；
//!   - 只有空行才派发；其它字段（`event:` / `id:` / `retry:`）本家不消费，忽略；
//!   - `\r\n` 与 `\n` 都认。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap / expect / panic；半行（被 TCP 分段切开）是**正常路径**。

/// 单帧最大长度（1 MiB）：与 SDK 解码器同档，防一条畸形帧吃满内存。
const MAX_FRAME: usize = 1024 * 1024;

/// SSE 分帧器。
#[derive(Default)]
pub struct Decoder {
    /// 当前未完成的行
    line: Vec<u8>,
    /// 当前帧累积的 data 段
    data: Vec<u8>,
    /// 上一个字节是 `\r` 时，吃掉紧随的 `\n`
    skip_lf: bool,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<String>, String> {
        let mut events = Vec::new();
        for byte in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            if matches!(*byte, b'\r' | b'\n') {
                self.end_line(&mut events)?;
                self.skip_lf = *byte == b'\r';
            } else {
                if self.line.len() + self.data.len() >= MAX_FRAME {
                    return Err("上游单个流式事件超过 1 MiB".to_string());
                }
                self.line.push(*byte);
            }
        }
        Ok(events)
    }

    /// EOF：把缓冲区里最后一段（没有尾随空行的帧）派发出去。
    pub fn finish(&mut self) -> Option<String> {
        if !self.line.is_empty() {
            // 末行没有换行符：按一行数据处理（`data:` 前缀仍要剥）
            let line = std::mem::take(&mut self.line);
            if let Some(value) = line.strip_prefix(b"data:") {
                let value = value.strip_prefix(b" ").unwrap_or(value);
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(value);
            }
        }
        if self.data.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.data);
        String::from_utf8(data).ok()
    }

    fn end_line(&mut self, events: &mut Vec<String>) -> Result<(), String> {
        if self.line.is_empty() {
            if !self.data.is_empty() {
                let data = std::mem::take(&mut self.data);
                events.push(String::from_utf8(data).map_err(|_| "上游流式事件不是有效 UTF-8".to_string())?);
            }
        } else if let Some(value) = self.line.strip_prefix(b"data:") {
            let value = value.strip_prefix(b" ").unwrap_or(value);
            if !self.data.is_empty() {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(value);
        } else {
            // 注释行（`: keep-alive`）与 `event:` / `id:` 等字段本家不消费。
            // 注意：SSE 规范里注释行不影响「当前帧」，所以这里只清行不清 data。
        }
        self.line.clear();
        Ok(())
    }
}

/// 一个 DONE 帧判定（`data: [DONE]`）。
pub fn is_done(payload: &str) -> bool {
    payload.trim() == "[DONE]"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_on_blank_line() {
        let mut decoder = Decoder::default();
        let events = decoder.push(b"data: {\"a\":1}\n\ndata: [DONE]\n\n").unwrap_or_default();
        assert_eq!(events, vec!["{\"a\":1}".to_string(), "[DONE]".to_string()]);
        assert!(decoder.finish().is_none());
    }

    #[test]
    fn keeps_half_line_until_next_chunk() {
        let mut decoder = Decoder::default();
        assert!(decoder.push(b"data: {\"a\"").unwrap_or_default().is_empty());
        let events = decoder.push(b":1}\n\n").unwrap_or_default();
        assert_eq!(events, vec!["{\"a\":1}".to_string()]);
    }

    #[test]
    fn finish_flushes_trailing_frame_without_blank_line() {
        let mut decoder = Decoder::default();
        assert!(decoder.push(b"data: tail\n").unwrap_or_default().is_empty());
        assert_eq!(decoder.finish(), Some("tail".to_string()));
    }

    #[test]
    fn join_multi_line_data() {
        let mut decoder = Decoder::default();
        let events = decoder.push(b"data: a\ndata: b\n\n").unwrap_or_default();
        assert_eq!(events, vec!["a\nb".to_string()]);
    }

    #[test]
    fn done_detection_trims() {
        assert!(is_done("  [DONE] "));
        assert!(!is_done("[DONE]x"));
    }
}
