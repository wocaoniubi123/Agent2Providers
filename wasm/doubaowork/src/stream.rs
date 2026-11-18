//! 上游 SSE 方言与内容块的解析。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/stream.rs`。
//!
//! ── 生图为什么也在这条流里 ──────────────────────────────────
//! 豆包工作**没有**「提交一次请求、返回图片地址」的图片接口：出图是对话里派给
//! agent 的一次 `image_gen` 任务，结果挂在同一条 SSE 流里（native 2026-11-03
//! 客户端抓包 + 本机复现）。实测两种块：
//!   · `10010` `content.gen_image_block.images[]` —— 交付结果，`uri` 给的是
//!     **带水印**的压缩预览（`~tplv-…-downsize_watermark…`）；
//!   · `10084` `content.rich_media_layout_block.media[].creation.image` —— 画布
//!     渲染，这里同时给了 `key`（对象键）与 `image_ori_raw`（**无水印原图**）。
//! 后者总在稍后到达 —— 所以图片**不随块即时发出**：先记下来，流末由
//! [`Decoder::drain_images`] 统一交出去，才交得到无水印那份。
//!
//! 同一张图会随进度重复下发，按对象键合并；一张只交一次。

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use agent2api_wasm_sdk::{json, Error, Result, Value};

use super::api;

const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_EVENT: usize = 2 * 1024 * 1024;

#[derive(Default)]
pub struct SseParser {
    pending: Vec<u8>,
}

impl SseParser {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<(String, String)>> {
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            let separator = [
                self.pending
                    .windows(2)
                    .position(|value| value == b"\n\n")
                    .map(|at| (at, 2)),
                self.pending
                    .windows(4)
                    .position(|value| value == b"\r\n\r\n")
                    .map(|at| (at, 4)),
            ]
            .into_iter()
            .flatten()
            .min_by_key(|(at, _)| *at);
            let Some((at, length)) = separator else {
                break;
            };
            if at > MAX_EVENT {
                return Err(Error::http(502, "豆包工作流式事件过大"));
            }
            let raw = self.pending.drain(..at + length).collect::<Vec<_>>();
            let block = std::str::from_utf8(&raw[..at])
                .map_err(|_| Error::http(502, "豆包工作流式事件不是有效 UTF-8"))?;
            let mut event = String::new();
            let mut data = Vec::new();
            for line in block.lines() {
                if let Some(value) = line.strip_prefix("event:") {
                    event = value.trim_start().to_string();
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value));
                }
            }
            if !data.is_empty() {
                frames.push((event, data.join("\n")));
            }
        }
        if self.pending.len() > MAX_EVENT {
            return Err(Error::http(502, "豆包工作流式事件过大"));
        }
        Ok(frames)
    }

    /// 连接结束时把缓冲里没带分隔符的尾巴按一行一帧处理。
    pub fn finish(&mut self) -> Option<(String, String)> {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return None;
        }
        let block = std::str::from_utf8(&pending).ok()?;
        let mut event = String::new();
        let mut data = Vec::new();
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event = value.trim_start().to_string();
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.strip_prefix(' ').unwrap_or(value));
            }
        }
        (!data.is_empty()).then(|| (event, data.join("\n")))
    }
}

const IMAGE_BLOCK: u64 = 10010;
const MEDIA_BLOCK: u64 = 10084;

/// 流里收到的一张图（同一张图两种块都会报，按对象键合并）。
#[derive(Default)]
struct Image {
    /// 对象键（`tos-cn-i-…/rc_gen_image/x.jpeg`）：两种块都用它标识同一张图。
    key: String,
    /// 无水印原图（`~tplv-…-image_raw.png`）。
    ///
    /// 实测同一张图：流里这份 `image_raw` 与官方
    /// `/creativity/resource/get_without_watermark` 返回的 `cgen_wm0` **字节完全
    /// 相同**（4624288 字节、同一 md5）。流里既然就有，就不必再发第二次请求。
    raw: Option<String>,
    /// 带水印的预览（`uri` / `thumb_url` / `image_ori`），拿不到原图时的兜底。
    preview: String,
}

/// 图片地址 → 对象键：`https://host/tos-cn-i-…/rc_gen_image/x.jpeg~tplv-…?…`
/// 的对象键是 `~` 之前、去掉协议与 host 的那一段。
fn object_key(url: &str) -> Option<String> {
    let without_query = url.split('?').next().unwrap_or(url);
    let path = without_query.split('~').next().unwrap_or(without_query);
    let key = path
        .strip_prefix("https://")
        .or_else(|| path.strip_prefix("http://"))
        .map(|rest| rest.split_once('/').map(|(_, path)| path).unwrap_or(""))
        .unwrap_or(path);
    (!key.is_empty()).then(|| key.to_string())
}

#[derive(Default)]
pub struct Decoder {
    pub text: String,
    pub reasoning: String,
    reasoning_blocks: BTreeSet<String>,
    blocks: BTreeMap<String, String>,
    images: Vec<Image>,
    pub done: bool,
    received: usize,
}

#[derive(Clone)]
pub enum Delta {
    Text(String),
    Reasoning(String),
}

impl Decoder {
    fn note_generated(&mut self, block: &Value) {
        for image in block["content"]["gen_image_block"]["images"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(url) = ["uri", "thumb_url"]
                .iter()
                .find_map(|key| image[*key].as_str().filter(|value| !value.trim().is_empty()))
            else {
                continue;
            };
            let key = object_key(url).unwrap_or_else(|| url.to_string());
            if let Some(known) = self.images.iter_mut().find(|known| known.key == key) {
                if known.preview.is_empty() {
                    known.preview = url.to_string();
                }
                continue;
            }
            self.images.push(Image { key, raw: None, preview: url.to_string() });
        }
    }

    /// 记下 `10084`（画布渲染）里的图片：这一份带着**无水印原图** [`Image::raw`]。
    /// 与 `10010` 按对象键合并：先到的是预览、后到的补上原图，两种先后顺序都成立。
    fn note_media(&mut self, block: &Value) {
        for image in block["content"]["rich_media_layout_block"]["media"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let image = &image["creation"]["image"];
            let key = image["key"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .or_else(|| {
                    ["image_ori", "image_preview", "image_thumb"]
                        .iter()
                        .find_map(|field| object_key(image[*field]["url"].as_str()?))
                });
            let Some(key) = key else { continue };
            let raw = image["image_ori_raw"]["url"]
                .as_str()
                .filter(|url| !url.trim().is_empty())
                .map(str::to_string);
            let preview = ["image_ori", "image_preview", "image_thumb"]
                .iter()
                .find_map(|field| image[*field]["url"].as_str())
                .filter(|url| !url.trim().is_empty())
                .map(str::to_string);
            if let Some(known) = self.images.iter_mut().find(|known| known.key == key) {
                if known.raw.is_none() {
                    known.raw = raw;
                }
                if known.preview.is_empty() {
                    known.preview = preview.unwrap_or_default();
                }
                continue;
            }
            self.images.push(Image { key, raw, preview: preview.unwrap_or_default() });
        }
    }

    pub fn has_images(&self) -> bool {
        !self.images.is_empty()
    }

    /// 把攒下来的图片交出去（流末调用一次）。
    ///
    /// 渲成 markdown 而不是图片内容块：网关这条对话流一路上都是**文本增量**，
    /// 塞一个 `image_url` 内容块会让多数客户端把整条 delta 一起丢掉。
    /// 首选无水印原图，没有才退回带水印的预览（旧账号可能不下发 `10084`）。
    pub fn drain_images(&mut self) -> Vec<Delta> {
        let mut output = Vec::new();
        for image in std::mem::take(&mut self.images) {
            let url = match image
                .raw
                .clone()
                .or_else(|| (!image.preview.is_empty()).then(|| image.preview.clone()))
            {
                Some(url) => url,
                None => continue,
            };
            let delta = format!("\n\n![图片]({url})\n\n");
            self.text.push_str(&delta);
            output.push(Delta::Text(delta));
        }
        output
    }

    /// 把攒下来的图片 URL 交出去（生图通道用：要的是地址，不是 markdown）。
    pub fn take_image_urls(&mut self) -> Vec<String> {
        std::mem::take(&mut self.images)
            .into_iter()
            .filter_map(|image| image.raw.or_else(|| (!image.preview.is_empty()).then_some(image.preview)))
            .collect()
    }

    fn blocks(&mut self, value: &Value, append: bool) -> Result<Vec<Delta>> {
        let mut output = Vec::new();
        for block in value.as_array().into_iter().flatten() {
            let kind = api::number(&block["block_type"]);
            if kind == Some(10040) {
                continue;
            }
            if kind == Some(IMAGE_BLOCK) {
                self.note_generated(block);
                continue;
            }
            if kind == Some(MEDIA_BLOCK) {
                self.note_media(block);
                continue;
            }
            if kind != Some(10000) {
                continue;
            }
            let Some(text) = block["content"]["text_block"]["text"].as_str() else {
                continue;
            };
            let id = api::identifier(&block["block_id"]);
            let icons = ["icon_url", "icon_url_dark"];
            let tagged = icons.iter().any(|key| {
                block["content"]["text_block"][*key]
                    .as_str()
                    .is_some_and(|icon| icon.to_ascii_lowercase().contains("deep_think"))
            });
            if let Some(id) = id.as_ref() {
                if tagged {
                    self.reasoning_blocks.insert(id.clone());
                } else if icons
                    .iter()
                    .any(|key| block["content"]["text_block"].get(*key).is_some())
                {
                    self.reasoning_blocks.remove(id);
                }
            }
            let reasoning = tagged
                || id
                    .as_ref()
                    .is_some_and(|id| self.reasoning_blocks.contains(id));
            let key = format!(
                "{}:{}",
                if reasoning { "reasoning" } else { "text" },
                id.unwrap_or_else(|| "default".into())
            );
            let prior = self.blocks.entry(key).or_default();
            let delta = if append {
                prior.push_str(text);
                text.to_string()
            } else if let Some(suffix) = text.strip_prefix(prior.as_str()) {
                let suffix = suffix.to_string();
                *prior = text.into();
                suffix
            } else if prior.is_empty() {
                *prior = text.into();
                text.to_string()
            } else {
                return Err(Error::http(502, "豆包工作替换了已发送的回答，无法安全继续流式响应"));
            };
            if delta.is_empty() {
                continue;
            }
            if reasoning {
                self.reasoning.push_str(&delta);
                output.push(Delta::Reasoning(delta));
            } else {
                self.text.push_str(&delta);
                output.push(Delta::Text(delta));
            }
            if self.text.len() > MAX_OUTPUT || self.reasoning.len() > MAX_OUTPUT {
                return Err(Error::http(502, "豆包工作输出超过大小限制"));
            }
        }
        Ok(output)
    }

    /// 解一帧上游事件；错误帧直接变成带状态的 [`Error`]。
    pub fn frame(&mut self, event: &str, raw: &str) -> Result<Vec<Delta>> {
        self.received = self.received.saturating_add(raw.len());
        if self.received > MAX_OUTPUT * 4 {
            return Err(Error::http(502, "豆包工作流式响应过大"));
        }
        let value: Value = serde_json::from_str(raw)
            .map_err(|_| Error::http(502, "豆包工作流式事件格式无效"))?;
        if event.contains("ERR")
            || event == "gateway-error"
            || event == "error"
            || value
                .get("error")
                .is_some_and(|error| !error.is_null() && error != &Value::Bool(false))
            || api::number(&value["code"]).is_some_and(|code| code != 0)
            || api::number(&value["error_code"]).is_some_and(|code| code != 0)
        {
            return Err(api::error(200, &value));
        }
        if self.done {
            return Ok(Vec::new());
        }
        match event {
            "SSE_REPLY_END" => {
                self.done = true;
                Ok(Vec::new())
            }
            "STREAM_MSG_NOTIFY" => self.blocks(&value["content"]["content_block"], true),
            "CHUNK_DELTA" if value["text"].is_string() => self.blocks(
                &json!([{
                    "block_id": "delta",
                    "block_type": 10000,
                    "content": {"text_block": {"text": value["text"]}},
                }]),
                true,
            ),
            "FULL_MSG_NOTIFY" if api::number(&value["message"]["user_type"]) == Some(2) => {
                self.blocks(&value["message"]["content_block"], false)
            }
            "STREAM_CHUNK" => {
                let mut deltas = Vec::new();
                for patch in value["patch_op"].as_array().into_iter().flatten() {
                    if api::number(&patch["patch_object"]) != Some(1) {
                        continue;
                    }
                    deltas.extend(
                        self.blocks(
                            &patch["patch_value"]["content_block"],
                            api::number(&patch["patch_type"]) == Some(1),
                        )?,
                    );
                }
                Ok(deltas)
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// 一帧一帧喂进去的驱动器（内部带着帧队列与「已读但未交出」的增量）。
#[derive(Default)]
pub struct FrameQueue {
    pub frames: VecDeque<(String, String)>,
    pub deltas: VecDeque<Delta>,
}

impl FrameQueue {
    pub fn push(&mut self, frames: Vec<(String, String)>) {
        self.frames.extend(frames);
    }

    /// 拿下一个增量；返回 `None` 表示当前缓冲里没有（调用方继续读流）。
    pub fn next(&mut self, decoder: &mut Decoder) -> Result<Option<Delta>> {
        loop {
            if let Some(delta) = self.deltas.pop_front() {
                return Ok(Some(delta));
            }
            if let Some((event, data)) = self.frames.pop_front() {
                self.deltas.extend(decoder.frame(&event, &data)?);
                continue;
            }
            return Ok(None);
        }
    }
}
