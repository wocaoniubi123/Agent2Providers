//! 极简 URL 工具：只覆盖本家真正用到的那三件事（百分号编码、查询串、主机名）。
//!
//! ── 为什么不引 `url` crate ─────────────────────────────────
//! wasm 目标的依赖被钉死在 `agent2api-wasm-sdk` / `serde_json` / `sha2` /
//! `chrono` 四个上（见 `Cargo.toml` 与迁移约束）。而本家需要的只有：
//!   ① 给授权页拼三个查询参数（`login_source` / `appname` / `state`）；
//!   ② 按官方固定形态逐项比对并解析 `office-raccoon://auth/callback` 回调；
//!   ③ 从鉴权基址里取出 host（IAM issuer 的兜底值要从它推）。
//! 三个函数换一个 crate 不划算，所以就地实现。
//!
//! ── 与 `url` crate 的口径必须一致的地方（逐条注明在函数上）────────
//! 回调解析是**安全判定**（state 校验链的一环）：宽松一点就等于放行
//! `office-raccoon://auth/callback@evil.com?…` 这类构造串。因此这里的
//! 比对是「scheme / host / path 三项分别相等」，不是前缀匹配。

/// 百分号编码一个查询参数（application/x-www-form-urlencoded 口径）。
///
/// 与 `url` crate 的 `query_pairs_mut().append_pair()` 逐字节同口径：
/// ASCII 字母数字原样，空格变 `+`，**其余一律 `%XX`**（大写十六进制）——
/// 注意这一档比 RFC 3986 的 unreserved 更严格（`-`、`.`、`_`、`*` 也会被编码），
/// 因为 `form_urlencoded` 用的就是这套集合。宁可多编码几个字符，
/// 也不要让上游页面拿到半个参数。
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(*byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 百分号解码（`+` 视作空格，同 `form_urlencoded`）。
///
/// 非法序列（`%` 后面不是两位十六进制）**按字面保留**——与 `percent-encoding`
/// 的 `percent_decode` 同一取舍：这里解的是上游回给我们的字符串，
/// 遇到畸形就少解几个字符，不能整条解析失败（那会让一次正常登录变成错误）。
pub fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_digit(bytes[index + 1]);
                let low = hex_digit(bytes[index + 2]);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 一条 URL 的解剖结果：`scheme`（小写）、`host`（原样，调用方决定要不要
/// 大小写不敏感比对）、`path`（原样）、`query`（不含 `?`）。
pub struct Parts {
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query: String,
}

/// 拆一条 URL。
///
/// ── 只支持本家用到的两种形态 ────────────────────────────────
///   - `https://host/path?query`
///   - `office-raccoon://auth/callback?query`（自定义协议，`//auth/callback`
///     里的 `auth` 是 host，与 `url` crate 读 `hostname` 同一含义）
///
/// 不做规范化的地方（都写在这里，免得以后有人以为是漏做）：
///   - userinfo（`user@host`）只影响 host 判定：这里**取 `@` 之后**那一段，
///     与 `url` crate 一致——但本家两个调用点都不该出现 userinfo，
///     取后者是为了让「构造串骗过前缀比对」这条路走不通；
///   - 端口保留在 host 里？**不**：host 只留主机名，端口单独丢弃（本家没有
///     用到端口的地方；IAM issuer 的端口另由 [`host_with_port`] 提供）。
pub fn split(raw: &str) -> Parts {
    let trimmed = raw.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        // 没有 `://`：整串当 path（绝对路径形态），scheme 留空
        None => (String::new(), trimmed),
    };
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let host = match authority.rsplit_once(':') {
        // `[::1]:8080` 这类带括号的 IPv6 不在本家的输入域里，保持原样即可
        Some((host, port)) if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            host.to_string()
        }
        _ => authority.to_string(),
    };
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path, query.split('#').next().unwrap_or("")),
        None => (tail.split('#').next().unwrap_or(""), ""),
    };
    Parts {
        scheme,
        host,
        path: path.to_string(),
        query: query.to_string(),
    }
}

/// 查询串里某个参数的值（已解码；取**第一个**同名参数，与 `url` crate 的
/// `query_pairs().find(..)` 一致）。
pub fn query_param(query: &str, name: &str) -> String {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        if decode(key) == name {
            return decode(value);
        }
    }
    String::new()
}

/// 主机名**带端口**（`host:port`；没有端口时只有主机名）。
///
/// IAM issuer 的兜底值就是这个形态（`{host}:{port}/iam`），所以端口不能像
/// 只取主机名那样丢掉。userinfo（`user@host`）按 `url` crate 的口径丢弃。
pub fn host_with_port(raw: &str) -> String {
    let trimmed = raw.trim();
    let rest = trimmed.split_once("://").map(|(_, rest)| rest).unwrap_or(trimmed);
    let authority = match rest.find(['/', '?', '#']) {
        Some(index) => &rest[..index],
        None => rest,
    };
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    authority.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_form_urlencoded() {
        // 字母数字原样；空格变 `+`；其余（含 `-` `.` `_`）一律 %XX 大写
        assert_eq!(encode("abz019"), "abz019");
        assert_eq!(encode("a b"), "a+b");
        assert_eq!(encode("办公"), "%E5%8A%9E%E5%85%AC");
        assert_eq!(encode("a-b_c.d"), "a%2Db%5Fc%2Ed");
    }

    #[test]
    fn decode_round_trips_and_keeps_bad_sequences() {
        assert_eq!(decode("a+b"), "a b");
        assert_eq!(decode("%E5%8A%9E"), "办");
        // 畸形序列按字面保留，不整条失败
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }

    #[test]
    fn split_reads_http_and_custom_scheme() {
        let parts = split("https://xiaohuanxiong.com/api/web/llm/v2?x=1");
        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.host, "xiaohuanxiong.com");
        assert_eq!(parts.path, "/api/web/llm/v2");
        assert_eq!(parts.query, "x=1");

        let parts = split("office-raccoon://auth/callback?code=abc&state=xyz");
        assert_eq!(parts.scheme, "office-raccoon");
        assert_eq!(parts.host, "auth");
        assert_eq!(parts.path, "/callback");
        assert_eq!(parts.query, "code=abc&state=xyz");
    }

    #[test]
    fn split_drops_port_and_userinfo() {
        assert_eq!(split("https://user@host.example:8443/x").host, "host.example");
        assert_eq!(host_with_port("https://host.example:8443/api"), "host.example:8443");
        assert_eq!(host_with_port("https://host.example/api"), "host.example");
    }

    #[test]
    fn query_param_takes_first_match() {
        assert_eq!(query_param("code=a&code=b", "code"), "a");
        assert_eq!(query_param("state=x%2Dy", "state"), "x-y");
        assert_eq!(query_param("code=a", "state"), "");
    }
}
