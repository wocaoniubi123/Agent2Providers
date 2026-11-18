//! 对话图片输入的附件上传。
//!
//! ── 迁移来源 ────────────────────────────────────────────────
//! native `crates/providers/src/providers/doubaowork/upload.rs`。
//!
//! ── 为什么在 wasm 侧只剩「交给宿主」这一步 ──────────────────
//! native 自己算 ImageX 的 AWS4 签名、ApplyImageUpload / CommitImageUpload、
//! CRC32、图片尺寸探测（要 `image` + `flate2` + `hmac`）。wasm 侧这些都由宿主
//! 固定入口 `doubao.image.upload` 完成（同一份签名与域名白名单，在
//! `plugin_host/wasm/doubao_upload.rs`），插件只需要：
//!   1. 把 data URL 解成字节；
//!   2. 放进本次调用的资源（`resource.create` / `append` / `seal`）；
//!   3. 调 `doubao.image.upload`，拿回 `attachment_block` 要的那条记录。
//!
//! 宿主的 `resources.raw()` **只接受已封存**的资源，所以 `seal` 不能省。

use agent2api_wasm_sdk::images::Resource;
use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};

use super::codec;

const MAX_IMAGE: usize = 20 * 1024 * 1024;

fn unsupported(message: &str) -> Error {
    Error::http(400, message).with_code("unsupported_parameter")
}

/// data URL → 资源类型。宿主只认 PNG / JPEG / WebP，其余按二进制交上去让它拒。
fn mime(prefix: &str) -> &'static str {
    let lower = prefix.to_ascii_lowercase();
    if lower.starts_with("data:image/png") {
        "image/png"
    } else if lower.starts_with("data:image/jpeg") || lower.starts_with("data:image/jpg") {
        "image/jpeg"
    } else if lower.starts_with("data:image/webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

/// 上传一张对话输入图片，返回 `attachment_block` 里的那条记录。
pub fn image(data: &str) -> Result<Value> {
    let (prefix, encoded) = data
        .split_once(',')
        .ok_or_else(|| unsupported("无效的图片 data URL"))?;
    if !prefix.starts_with("data:image/") || !prefix.ends_with(";base64") {
        return Err(unsupported("图片 data URL 格式无效或超过 20 MiB"));
    }
    if encoded.len() > MAX_IMAGE * 4 / 3 + 4 {
        return Err(unsupported("图片 data URL 格式无效或超过 20 MiB"));
    }
    let bytes = codec::base64_decode(encoded).ok_or_else(|| unsupported("无效的图片 base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_IMAGE {
        return Err(unsupported("输入图片超过 20 MiB"));
    }
    let resource = Resource::create(mime(prefix))?;
    resource.append(&bytes)?;
    resource.seal()?;
    let value = sdk::host("doubao.image.upload", json!({ "resource": resource.id }))
        .map_err(|error| Error::http(502, format!("豆包工作图片上传失败：{}", error.message)))?;
    // 上传完成后这份字节不再需要，顺手把本次调用的资源预算还回去。
    let _ = resource.remove();
    if !value["image"]["uri"].is_string() {
        return Err(Error::http(502, "豆包工作未返回图片上传结果"));
    }
    Ok(value)
}
