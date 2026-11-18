//! 豆包工作文生图：在对话里让 agent 跑一次 `image_gen` 任务，再下载无水印原图。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/image_generation.rs`。
//!
//! ── 上游没有独立的生图接口 ──────────────────────────────────
//! 豆包工作**没有**那种「提交一次请求、返回图片地址」的图片接口，出图就是
//! 「在对话里派一次任务」—— agent 自己调用 `image_gen` 技能，结果作为
//! `gen_image_block`（`block_type = 10010`）挂在 `/chat/completion` 那条 SSE 流里。
//! native 当年把「构造请求」交给宿主、把「从流里取图 + 换无水印原图」放在
//! 宿主侧；wasm 侧这条通道只剩一个入口（网关 `wasm/runtime.rs` 的
//! `invoke_doubao_image`，硬校验 `provider == "doubaowork"`），所以从构造到取图
//! 全在本模块里完成。
//!
//! ── 用哪条模型跑这次任务 ────────────────────────────────────
//! 生图能力挂在**通用任务模式**上，与目录里的对话模型不是一回事：客户端那份
//! 会话记录里 `ext.agent_name = Agent-GeneralTask`、`ext.agent_mode = 1`。
//! 所以这里不解析下游传的模型名，而是按 `catalog::resolve_agent` 挑一条能跑
//! 任务的模型。下游看到的 id 是 [`MODEL_ID`]，对应目录里那条 `kind = image`
//! 的条目 —— 能力位与 id 两边必须一致，否则网关不会把生图请求派到本家。
//!
//! ── 参数口径 ────────────────────────────────────────────────
//! `size` 翻成画面比例提示写进 prompt：豆包是从自然语言里读比例的。
//! `quality` / `style` / `background` / `moderation` 这些 OpenAI 专属字段上游
//! 没有对应物，**明确拒绝**而不是静默丢掉 —— 静默会让用户以为风格生效了。
//! `n` 只支持 1：一次任务出一张。
//!
//! ── 回包 ────────────────────────────────────────────────────
//! `sdk::images::response(images, usage)` 拼 `{created, data, usage}`；`data` 里
//! 每条只写 `{"resource": <id>}`，宿主的 `resources::materialize` 会把资源读成
//! `b64_json` 再交给下游 —— 插件不搬大块 base64。

use agent2api_wasm_sdk::{self as sdk, http, images as sdk_images, json, Error, Result, Value};

use super::catalog::{self, IMAGE_MODEL_ID};
use super::prompt;
use super::stream::{Decoder, FrameQueue, SseParser};
use super::{account, api};

/// 下游认的图像条目 id（目录里的 [`MODEL_ID`]，见 `catalog::IMAGE_MODEL_ID`）。
pub const MODEL_ID: &str = IMAGE_MODEL_ID;

/// 目录里那条图像条目：`kind = image` 让它进图像通道，
/// `supports_image_generation` 决定它出现在 `/v1/images/generations` 的可用模型里。
///
/// `supportsImages`（多模态**输入**）只对参考图那一类开 —— 本家不吃参考图，
/// 标成能吃会让客户端往上送图。
pub fn model_row() -> Value {
    json!({
        "id": MODEL_ID,
        "name": "豆包生图",
        "kind": "image",
        "output_modalities": ["image"],
        "supports_image_generation": true,
        "supports_image_editing": false,
        "supportsToolCall": false,
        "supportsImages": false,
        "supportsReasoning": false,
    })
}

/// 下游的 `size` 翻成豆包认的画面比例提示。
///
/// 只认常见比例，且**差得太远就不猜**（宁可不说，也不要给一个错的画面比例）——
/// 上游是从自然语言里读的，说错了它会照着错的画。
fn ratio(size: &str) -> Option<&'static str> {
    if size.eq_ignore_ascii_case("auto") {
        return None;
    }
    let (width, height) = size
        .trim()
        .split_once('x')
        .or_else(|| size.trim().split_once('X'))
        .map(|(width, height)| (width.trim(), height.trim()))?;
    let width: f64 = width.parse().ok()?;
    let height: f64 = height.parse().ok()?;
    if !(width.is_finite() && height.is_finite()) || width <= 0.0 || height <= 0.0 {
        return None;
    }
    let target = width / height;
    let table: [(f64, &'static str); 8] = [
        (1.0, "1:1"),
        (16.0 / 9.0, "16:9"),
        (9.0 / 16.0, "9:16"),
        (4.0 / 3.0, "4:3"),
        (3.0 / 4.0, "3:4"),
        (3.0 / 2.0, "3:2"),
        (2.0 / 3.0, "2:3"),
        (21.0 / 9.0, "21:9"),
    ];
    let (matched, name) = table
        .into_iter()
        .min_by(|left, right| (left.0 - target).abs().total_cmp(&(right.0 - target).abs()))?;
    ((matched - target).abs() / target <= 0.08).then_some(name)
}

/// 这次任务给 agent 的话：把「出图」这个要求说出来，并把画面比例一并交代。
/// 补一句「不要只给文字描述」是因为 agent 偶尔会先回一段画法说明。
fn instruction(prompt: &str, ratio: Option<&str>) -> String {
    match ratio {
        Some(ratio) => format!(
            "请直接用图片生成能力画出来，不要只给文字描述。画面比例 {ratio}，画面内容：{prompt}"
        ),
        None => format!("请直接用图片生成能力画出来，不要只给文字描述。画面内容：{prompt}"),
    }
}

fn rejected(field: &str) -> Error {
    Error::http(400, format!("豆包工作生图不支持 {field}，请把要求写进 prompt"))
}

/// 比例换算与参数口径的自检（这几条是「看起来成功但没生效」的高发区）。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 常见尺寸翻成画面比例() {
        assert_eq!(ratio("1024x1024"), Some("1:1"));
        assert_eq!(ratio("1792x1024"), Some("16:9"));
        assert_eq!(ratio("1024x1792"), Some("9:16"));
        assert_eq!(ratio("auto"), None);
        // 差得太远不猜（宁可不说，也不要给一个错的画面比例）。
        assert_eq!(ratio("1000x333"), None);
        assert_eq!(ratio("abc"), None);
        assert_eq!(ratio("0x100"), None);
    }

    #[test]
    fn 图像条目带生成能力位() {
        let row = model_row();
        assert_eq!(row["kind"], "image");
        assert_eq!(row["supports_image_generation"], true);
        assert_eq!(row["supports_image_editing"], false);
        assert_eq!(row["id"], MODEL_ID);
    }

    #[test]
    fn 指令把比例写进正文() {
        let text = instruction("一只猫", Some("9:16"));
        assert!(text.contains("9:16"));
        assert!(text.contains("一只猫"));
        assert!(!instruction("一只猫", None).contains("画面比例"));
    }
}

/// `images.generate`：参数全部来自 `params.body`（OpenAI 图片请求体）。
pub fn generate(params: &Value) -> Result<Value> {
    let body = &params["body"];
    if !body.is_object() {
        return Err(Error::http(400, "图片请求体必须是 JSON 对象"));
    }
    // 参考图：本家不吃图（`supports_image_editing = false`，网关不会把编辑请求
    // 派过来）。真收到了就说清楚，而不是拼一个没有图片的请求发上去。
    if ["images", "image", "mask", "input_fidelity"]
        .iter()
        .any(|field| body.get(*field).is_some_and(|value| !value.is_null()))
    {
        return Err(Error::http(
            400,
            "豆包工作生图不支持参考图，请改用支持图片编辑的模型",
        ));
    }
    if let Some(field) = ["quality", "style", "background", "moderation"]
        .into_iter()
        .find(|field| body.get(*field).is_some_and(|value| !value.is_null()))
    {
        return Err(rejected(field));
    }
    if body.get("n").and_then(Value::as_u64).unwrap_or(1) != 1 {
        return Err(Error::http(
            400,
            "豆包工作一次任务只出一张图，请把 n 设为 1（需要多张请让对话再生成一次）",
        ));
    }
    let prompt_text = body
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|prompt| !prompt.is_empty())
        .ok_or_else(|| Error::http(400, "图片请求缺少 prompt"))?;
    let hint = body.get("size").and_then(Value::as_str).and_then(ratio);
    let text = instruction(prompt_text, hint);

    let secret = account::current_secret()?;
    let credentials = account::credential(&secret)?;
    credentials.require_device()?;
    let (bot, model) = catalog::resolve_agent(&credentials)?;
    let payload = prompt::payload(&bot, &model, &text, Vec::new(), &json!({}))?;

    let mut response = http::open(
        "POST",
        &credentials.endpoint("/chat/completion"),
        credentials.headers(),
        Some(&payload),
    )?;
    let status = response.status;
    let sse = response
        .headers
        .get("content-type")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if !(200..300).contains(&status) || !sse {
        let bytes = response.bytes(1 << 20)?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(api::error(status, &value));
    }

    let mut decoder = Decoder::default();
    let mut parser = SseParser::default();
    let mut queue = FrameQueue::default();
    let mut received = 0_usize;
    while let Some(chunk) = response.read()? {
        received = received.saturating_add(chunk.len());
        if received > 64 * 1024 * 1024 {
            return Err(Error::http(502, "豆包工作生图响应超过大小限制"));
        }
        queue.push(parser.push(&chunk)?);
        while queue.next(&mut decoder)?.is_some() {}
        if decoder.done {
            break;
        }
    }
    if !decoder.done {
        if let Some(frame) = parser.finish() {
            queue.push(vec![frame]);
            while queue.next(&mut decoder)?.is_some() {}
        }
    }
    let urls = decoder.take_image_urls();
    // 无论取没取到图，本轮流都已经结束；先让宿主认下收尾（失败忽略）。
    api::finish_turn();
    if urls.is_empty() {
        return Err(Error::http(
            502,
            "豆包工作本次任务没有返回图片（可能是账号没有图像生成能力，或 agent 只回了文字）",
        ));
    }
    // 一次任务只出一张：多余的重复上报已在解码器里按对象键合并。
    let url = urls.first().cloned().unwrap_or_default();
    let fetched = sdk::host("resource.fetch_public", json!({ "url": url }))
        .map_err(|error| Error::http(502, format!("豆包工作图片下载失败：{}", error.message)))?;
    let id = fetched["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::http(502, "豆包工作图片下载未返回资源标识"))?
        .to_string();
    Ok(sdk_images::response(
        vec![json!({ "resource": id })],
        json!({}),
    ))
}
