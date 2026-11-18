//! 账号面：取 API Key、公开视图、稳定身份、粘贴式账号规范化。
//!
//! 合并自 native 的 `credentials.rs` 取值链 + `mod.rs` 的 `normalize_account`。
//!
//! ── 没有续期（如实声明，别照抄别家）─────────────────────────────
//! 本家是单个静态 API Key，上游**没有 refresh 接口**，所以：
//!   - `ensure()` 只做「记录里有没有 key、形态对不对」的检查；
//!   - `refresh()` 恒返回一条可读的 401 文案（网关据此提示「重贴」而不是
//!     「刷新失败」）；
//!   - `expiring()` 恒 false（`account_features.long_lived = true`）。
//!
//! ── 校验顺序（先本地、再线上）是刻意的 ──────────────────────
//! 本地形态不对时**一次网络都不发**（用户粘错了东西，探活没有意义）；
//! 线上探活失败**不阻断添加**（见 `credentials::probe_key` 的三档语义）。
//!
//! ── 为什么没有「默认登录态 / 环境变量」旁路 ──────────────────────
//! native 也没有。wasm 沙箱更没有：网关明文拒绝 wasm 包申报隐式本机凭证
//! （`capabilities.anonymous_default_session` / `env_credentials` 必须为 false）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! 零 unwrap/expect/panic。

use agent2api_wasm_sdk::{self as sdk, json, Error, Result, Value};
use sha2::{Digest, Sha256};

use super::{credentials, fingerprint};

/// 输入长度上限（超过这个长度的输入一定是粘错了东西）
const MAX_INPUT_CHARS: usize = 8192;

/// 当前账号的完整记录（`{id, secret, public, …}`）
pub fn record() -> Result<Value> {
    sdk::account()
}

/// 取可用 API Key（**唯一入口**）。
///
/// 没有账号与凭证形态不对都折成 401：两者对客户端都是「先补凭证」，
/// 而网关的 `TokenExpired` 处置正是「刷新一次（本家拿回同一个 key）再换账号」。
pub fn api_key() -> Result<String> {
    let record = match record() {
        Ok(record) => record,
        Err(error) => {
            return Err(Error::http(
                401,
                format!("Command Code 当前没有可用账号：{}", error.message),
            ))
        }
    };
    let secret = record.get("secret").cloned().unwrap_or(Value::Null);
    credentials::api_key_of(&secret).map_err(|reason| Error::http(401, reason))
}

/// 取可用 API Key，并在此之前确保**设备指纹已上报**（`token.ensure`）。
pub fn ensure() -> Result<String> {
    let api_key = api_key()?;
    // best-effort：失败只字不提，绝不影响生成（见 `fingerprint.rs` 模块头）
    fingerprint::ensure_initialized(&api_key);
    Ok(api_key)
}

/// 没有续期手段：单个静态 key，上游无 refresh 接口。
///
/// 返回 401 而不是 unsupported —— 网关对 `token.refresh` 的失败处置是
/// 「提示重贴凭证」，`unsupported` 会被当成「这家不支持刷新」而静默跳过。
pub fn refresh() -> Result<Value> {
    Err(Error::http(
        401,
        "Command Code 使用静态 API Key，上游没有续期接口：请在 commandcode.ai/studio 重新获取后重贴",
    )
    .with_code("token_not_refreshable"))
}

/// 令牌是否临期：静态 key 没有到期时刻，恒 false。
pub fn expiring() -> bool {
    false
}

/// 稳定身份 = key 的摘要前缀（上游没有 userId 可解析）
pub fn identity(secret: &Value) -> Result<String> {
    let api_key = credentials::api_key_of(secret).map_err(|reason| Error::http(401, reason))?;
    Ok(format!("commandcode-{}", short_hash(&api_key)))
}

/// 账号行的公开视图（`account.view`）
///
/// 与 native 的 `NormalizedAccount.public` 逐字段一致：只有 `name` 与
/// `tokenTail`。标识列显示的是 `identity`（`account_features.identifier = ["id"]`），
/// 由网关自己拼，不需要插件在这里再放一份。
pub fn view(secret: &Value) -> Value {
    let display = view_name(secret);
    let api_key = credentials::api_key_of(secret).unwrap_or_default();
    json!({
        "name": display,
        "tokenTail": if api_key.is_empty() { String::new() } else { credentials::tail_of(&api_key) },
    })
}

/// 可见名字：记录里写过就用它，否则 `Command Code <尾4位>`
fn view_name(secret: &Value) -> String {
    let stored = crate::util::pick(secret, &["name"]);
    if !stored.is_empty() {
        return stored;
    }
    let api_key = credentials::api_key_of(secret).unwrap_or_default();
    if api_key.is_empty() {
        "Command Code 账号".to_string()
    } else {
        format!("Command Code {}", credentials::tail_of(&api_key))
    }
}

/// 规范化一条账号（`account.normalize`）。
///
/// `source.kind` 是网关 `NormalizeSource` 的序列化形态（`tag = "kind"`、
/// snake_case）：`manual` / `file_text` / `file_base64` / `desktop`。
pub fn normalize(params: &Value) -> Result<Value> {
    let source = &params["source"];
    let kind = source["kind"].as_str().unwrap_or("");
    let (raw, payload_name) = match kind {
        "manual" => {
            // 表单字段可能平铺在 `payload` 下，也可能被包一层 `inputs`
            let payload = if source["payload"]["inputs"].is_object() {
                source["payload"]["inputs"].clone()
            } else {
                source["payload"].clone()
            };
            let raw = crate::util::pick(&payload, &["apiKey", "accessToken", "token", "key"]);
            let name = crate::util::pick(&payload, &["name"]);
            (raw, if name.is_empty() { None } else { Some(name) })
        }
        "file_text" => {
            // 文件可能是裸 key，也可能是 `{"apiKey": "user_..."}`
            let content = source["content"].as_str().unwrap_or("").trim();
            match serde_json::from_str::<Value>(content) {
                Ok(parsed) if parsed.is_object() => {
                    let raw = crate::util::pick(&parsed, &["apiKey", "accessToken", "token", "key"]);
                    if raw.is_empty() {
                        (content.to_string(), None)
                    } else {
                        (raw, None)
                    }
                }
                _ => (content.to_string(), None),
            }
        }
        "file_base64" => {
            return Err(Error::http(
                400,
                "Command Code 不支持二进制文件导入，请粘贴 API Key",
            ))
        }
        "desktop" => {
            return Err(Error::http(
                400,
                "Command Code 不支持导入桌面端登录态，请粘贴 API Key（user_ 开头）添加账号",
            ))
        }
        _ => {
            return Err(Error::http(
                400,
                "Command Code 请粘贴 API Key（user_ 开头）添加账号",
            ))
        }
    };
    if raw.trim().is_empty() {
        return Err(Error::http(
            400,
            format!(
                "请粘贴 Command Code 的 API Key（{} 开头）",
                credentials::KEY_PREFIX
            ),
        ));
    }
    if raw.chars().count() > MAX_INPUT_CHARS {
        return Err(Error::http(400, "粘贴的内容过长，请确认复制的是 API Key 本身"));
    }
    let api_key = credentials::normalize_key(&raw);
    if api_key.is_empty() {
        return Err(Error::http(
            400,
            format!(
                "请粘贴 Command Code 的 API Key（{} 开头）",
                credentials::KEY_PREFIX
            ),
        ));
    }
    if !credentials::shape_ok(&api_key) {
        return Err(Error::http(
            400,
            format!(
                "这不是 Command Code 的 API Key：应以 {} 开头、只含字母数字与 _ -；\
                 请在 commandcode.ai/studio（或本机 ~/.commandcode/auth.json）重新复制",
                credentials::KEY_PREFIX
            ),
        ));
    }
    // best-effort 探活：只有明确 401/403 才判无效
    match credentials::probe_key(&api_key) {
        credentials::KeyCheck::Valid => {}
        credentials::KeyCheck::Invalid(reason) => {
            return Err(Error::http(
                400,
                format!(
                    "Command Code API Key 无效或已失效（{reason}）：\
                     请在 commandcode.ai/studio 重新获取后粘贴"
                ),
            ))
        }
        // 判不出来就放行：一次上游抖动不该让用户加不进账号。
        // wasm 侧没有日志通道，`note` 在这里读一下只是为了与 native 的三档语义
        // 保持同一份结构（native 用它写告警日志）。
        credentials::KeyCheck::Unknown(note) => {
            let _ = note.trim();
        }
    }
    // 稳定身份 = key 的摘要前缀（上游没有 userId 可解析）
    let identity = format!("commandcode-{}", short_hash(&api_key));
    let requested = crate::util::pick(params, &["name"]);
    let display = if !requested.is_empty() {
        requested
    } else if let Some(name) = payload_name.filter(|name| !name.trim().is_empty()) {
        name.trim().to_string()
    } else {
        format!("Command Code {}", credentials::tail_of(&api_key))
    };
    // secret 里额外留一份 `name`：网关存的是 `secret` + `public`，而
    // `account.view` 只拿得到 `secret`（拿不到 public）—— 不留这一份，用户
    // 起的名字在账号行上就会退回成 `Command Code <尾4位>`。
    let secret = json!({ "apiKey": api_key.clone(), "name": display.clone() });
    Ok(json!({
        "secret": secret,
        "public": json!({
            "name": display,
            "tokenTail": credentials::tail_of(&api_key),
        }),
        "identity": identity,
        "desktop": false,
    }))
}

/// key 的短摘要（16 位 hex，用于账号 id；不可反推）
fn short_hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let hex = format!("{digest:x}");
    hex[..16.min(hex.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_prefixed() {
        let secret = json!({ "apiKey": "user_abcdef" });
        // `Error` 没有 PartialEq，比较前先折成文案
        let first = identity(&secret).map_err(|error| error.message);
        let second = identity(&secret).map_err(|error| error.message);
        assert_eq!(first, second);
        let Ok(value) = identity(&secret) else {
            assert!(false, "合法 key 必须能算出身份");
            return;
        };
        assert!(value.starts_with("commandcode-"));
        // 16 位 hex 摘要
        assert_eq!(value.len(), "commandcode-".len() + 16);
        assert!(!value.contains("user_abc"), "身份里不得出现明文 key");
        // 形态不对时明确报错，而不是给一个空身份
        assert!(identity(&json!({ "apiKey": "bad" })).is_err());
    }

    #[test]
    fn view_falls_back_to_a_readable_name() {
        let plain = view(&json!({ "apiKey": "user_abcdefgh" }));
        assert_eq!(plain["name"], json!("Command Code efgh"));
        assert_eq!(plain["tokenTail"], json!("efgh"));
        let named = view(&json!({ "apiKey": "user_abcdefgh", "name": "主力号" }));
        assert_eq!(named["name"], json!("主力号"));
        // 坏凭证不 panic，只给空尾巴
        let broken = view(&json!({ "apiKey": "bad" }));
        assert_eq!(broken["tokenTail"], json!(""));
    }

    #[test]
    fn normalize_rejects_binary_and_desktop_sources() {
        let binary = normalize(&json!({ "source": { "kind": "file_base64", "content": "AA==" } }));
        assert_eq!(binary.err().and_then(|error| error.status), Some(400));
        let desktop = normalize(&json!({ "source": { "kind": "desktop" } }));
        assert_eq!(desktop.err().and_then(|error| error.status), Some(400));
    }

    #[test]
    fn normalize_rejects_wrong_shapes_before_any_network_call() {
        let empty = normalize(&json!({ "source": { "kind": "manual", "payload": {} } }));
        assert_eq!(empty.err().and_then(|error| error.status), Some(400));
        let wrong = normalize(&json!({
            "source": { "kind": "manual", "payload": { "apiKey": "sk-nope" } }
        }));
        let error = wrong.err();
        let status = error.as_ref().and_then(|error| error.status);
        assert_eq!(status, Some(400));
        assert!(error
            .map(|error| error.message.contains("这不是 Command Code 的 API Key"))
            .unwrap_or(false));
        // 超长输入
        let long = "user_".to_string() + &"a".repeat(MAX_INPUT_CHARS);
        let too_long = normalize(&json!({
            "source": { "kind": "manual", "payload": { "apiKey": long } }
        }));
        assert_eq!(too_long.err().and_then(|error| error.status), Some(400));
    }

    #[test]
    fn normalize_extracts_from_manual_and_file_text() {
        // manual：Bearer 整行
        let manual = normalize(&json!({
            "source": {
                "kind": "manual",
                "payload": { "apiKey": "Authorization: Bearer user_manual123" }
            }
        }));
        let Ok(manual) = manual else {
            assert!(false, "manual 归一化必须成功");
            return;
        };
        assert_eq!(manual["secret"]["apiKey"], json!("user_manual123"));
        assert_eq!(manual["identity"].as_str().unwrap_or("").len(), "commandcode-".len() + 16);
        assert_eq!(manual["desktop"], json!(false));
        // "user_manual123" 的尾 4 个字符是 "l123"（按 char 取，不按字节）
        assert_eq!(manual["public"]["tokenTail"], json!("l123"));

        // file_text：JSON 包装
        let wrapped = normalize(&json!({
            "source": { "kind": "file_text", "content": "{\"apiKey\":\"user_file456\"}" }
        }));
        let Ok(wrapped) = wrapped else {
            assert!(false, "file_text 归一化必须成功");
            return;
        };
        assert_eq!(wrapped["secret"]["apiKey"], json!("user_file456"));

        // file_text：裸 key
        let bare = normalize(&json!({
            "source": { "kind": "file_text", "content": "user_bare789\n" }
        }));
        let Ok(bare) = bare else {
            assert!(false, "裸 key 必须被接受");
            return;
        };
        assert_eq!(bare["secret"]["apiKey"], json!("user_bare789"));

        // 用户指定的备注名优先
        let named = normalize(&json!({
            "name": "自定义名",
            "source": { "kind": "manual", "payload": { "apiKey": "user_named" } }
        }));
        let Ok(named) = named else {
            assert!(false, "带备注名的归一化必须成功");
            return;
        };
        assert_eq!(named["public"]["name"], json!("自定义名"));
    }

    #[test]
    fn refresh_is_a_readable_401() {
        let error = refresh().err();
        let error = match error {
            Some(error) => error,
            None => {
                assert!(false, "static key 不得声称刷新成功");
                return;
            }
        };
        assert_eq!(error.status, Some(401));
        assert_eq!(error.code.as_deref(), Some("token_not_refreshable"));
        assert!(error.message.contains("没有续期接口"));
    }

    #[test]
    fn static_keys_never_expire() {
        assert!(!expiring());
    }
}
