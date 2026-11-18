//! 组织身份、页面业务身份与外部头部覆盖。
//!
//! 组织身份取自同一份凭证；个人身份不发送 X-Org-Code。

use agent2api_wasm_sdk::{Error, Result, Value};

use crate::upstream;

/// 组织身份（`officeIdentity` / `office_identity`；个人身份给空串）。
pub fn org_code(record: &Value) -> String {
    let identity = crate::account::pick(record, &["officeIdentity", "office_identity"]);
    if identity == "personal" {
        String::new()
    } else {
        identity
    }
}

/// 往头部列表里追加 `X-Org-Code`。
///
/// ── 为什么要校验字符集再发 ────────────────────────────────
/// 这个值来自用户导入的登录态，直接拼进 HTTP 头会在出网层被拒（换行 / 控制
/// 字符），而报错点会跑到「请求发不出去」这种看不出根因的地方。在拼之前
/// 拦住，文案才能指向「重新导入登录态」。
pub fn append_org(headers: &mut Vec<(String, String)>, org_code: &str) -> Result<()> {
    if org_code.is_empty() || org_code == "personal" {
        return Ok(());
    }
    if !org_code.is_ascii() || org_code.bytes().any(|value| value < 32 || value == 127) {
        return Err(Error::http(400, "小浣熊组织身份无效，请重新导入登录态"));
    }
    headers.push(("X-Org-Code".to_string(), org_code.to_string()));
    Ok(())
}

/// 桌面端身份头（`setting_info` / 登录奖励这类「官方桌面客户端」链路带的那两个）。
///
/// native 侧平台值来自 `cfg!(target_os)`；wasm 目标恒为 unknown，改由设置提供，
/// 见 [`upstream::client_platform`] 的说明。
pub fn desktop_client_headers() -> Vec<(String, String)> {
    vec![
        ("X-Client-Name".to_string(), "raccoon-work".to_string()),
        (
            "X-Client-Platform".to_string(),
            upstream::client_platform(),
        ),
        ("X-Client-Version".to_string(), upstream::client_version()),
    ]
}

/// 合并外部头部覆盖表：同名（大小写不敏感）覆盖，其余追加。
///
/// native 侧每次请求都读 `/var/lib/agent2api/raccoon-headers.json`；
/// wasm 没有文件系统，同一份表由设置 `externalHeaders` 承载（见
/// [`upstream::external_headers`]）。不是 JSON 对象 / 值不是字符串 /
/// 名字与值含非法字符时整体跳过该项，不影响正常转发。
pub fn append_external(headers: &mut Vec<(String, String)>) {
    let Value::Object(object) = upstream::external_headers() else {
        return;
    };
    for (name, value) in object {
        let Some(value) = value.as_str() else {
            continue;
        };
        if !valid_header_name(&name) || !valid_header_value(value) {
            continue;
        }
        upsert(headers, name, value.to_string());
    }
}

/// HTTP 头名的合法字符集（RFC 9110 的 token：不含分隔符与控制字符）。
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// HTTP 头值：可见 ASCII 与制表符；其余字符会让整条请求被出网层拒绝。
fn valid_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn upsert(headers: &mut Vec<(String, String)>, name: String, value: String) {
    match headers
        .iter_mut()
        .find(|(key, _)| key.eq_ignore_ascii_case(name.as_str()))
    {
        Some((_, current)) => *current = value,
        None => headers.push((name, value)),
    }
}
