//! Binder-agnostic request/response types plus the XSS-neutralisation
//! spine.
//!
//! Mirrors the shape of [`solid_pod_rs_git::service::GitRequest`] so the
//! embedding server translates its native (actix/axum/hyper) types once,
//! at the edge, and the forge logic stays framework-free and testable.
//!
//! Security posture (cites JSS `forge` design notes, not code): every
//! byte the forge serves is neutralised by **content-type**, never by
//! trusting HTML sanitisation. Raw repository bytes go out as
//! `text/plain; charset=utf-8` or `application/octet-stream` with a
//! `Content-Disposition: attachment`, so a browser never renders a blob
//! as markup. The single [`esc`] helper HTML-escapes every value the
//! server-rendered views interpolate.

use bytes::Bytes;

/// Opaque HTTP request consumed by [`crate::ForgeService::handle`].
///
/// The caller percent-decodes `path` and strips the leading `?` from
/// `query` before constructing this, exactly as the git crate expects.
#[derive(Debug, Clone)]
pub struct ForgeRequest {
    /// Upper- or mixed-case HTTP method (`"GET"`, `"POST"`, `"OPTIONS"`).
    pub method: String,
    /// Percent-decoded URL path, including the forge prefix
    /// (`"/forge/alice/repo/issues"`).
    pub path: String,
    /// Raw query string with no leading `?` (`"state=open&page=2"`).
    pub query: String,
    /// All request headers as `(name, value)`. Names are matched
    /// case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Raw request body — kept as bytes so NIP-98 payload hashing sees
    /// the exact octets.
    pub raw_body: Bytes,
    /// Scheme + host (`"https://pod.example.com"`); used to reconstruct
    /// the URL a NIP-98 `u` tag must match and to render absolute links.
    pub host_url: Option<String>,
}

impl ForgeRequest {
    /// Case-insensitive header lookup returning the first match.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Reconstruct the canonical absolute URL (for NIP-98 `u`-tag checks).
    #[must_use]
    pub fn absolute_url(&self) -> String {
        let base = self
            .host_url
            .clone()
            .unwrap_or_else(|| "http://localhost".to_string());
        if self.query.is_empty() {
            format!("{base}{}", self.path)
        } else {
            format!("{base}{}?{}", self.path, self.query)
        }
    }

    /// Parse a single query parameter value (first occurrence),
    /// percent-decoding `+` to space. Returns `None` when absent.
    #[must_use]
    pub fn query_param(&self, key: &str) -> Option<String> {
        for pair in self.query.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            if k == key {
                let v = it.next().unwrap_or("");
                return Some(v.replace('+', " "));
            }
        }
        None
    }
}

/// Response returned from [`crate::ForgeService::handle`]; the server maps
/// it back to its native response type.
#[derive(Debug, Clone)]
pub struct ForgeResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Bytes,
}

impl ForgeResponse {
    /// Build a response with a single content-type header.
    #[must_use]
    pub fn with_type(status: u16, content_type: &str, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into(),
        }
    }

    /// Server-rendered HTML page. Callers must have `esc()`'d every
    /// interpolated value.
    #[must_use]
    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self::with_type(status, "text/html; charset=utf-8", Bytes::from(body.into()))
    }

    /// JSON response. `value` is any `serde_json::Value` or serialisable.
    #[must_use]
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self::with_type(status, "application/json", Bytes::from(body))
    }

    /// Raw repository bytes served defensively: text blobs as
    /// `text/plain`, everything else as an `octet-stream` attachment so
    /// no browser ever renders repository content as markup.
    #[must_use]
    pub fn raw_bytes(bytes: Bytes, is_text: bool, filename: &str) -> Self {
        if is_text {
            Self {
                status: 200,
                headers: vec![
                    ("content-type".into(), "text/plain; charset=utf-8".into()),
                    // Even text is served non-inline-executable.
                    ("x-content-type-options".into(), "nosniff".into()),
                ],
                body: bytes,
            }
        } else {
            let safe = sanitize_filename(filename);
            Self {
                status: 200,
                headers: vec![
                    ("content-type".into(), "application/octet-stream".into()),
                    (
                        "content-disposition".into(),
                        format!("attachment; filename=\"{safe}\""),
                    ),
                    ("x-content-type-options".into(), "nosniff".into()),
                ],
                body: bytes,
            }
        }
    }

    /// A 3xx redirect to `location`.
    #[must_use]
    pub fn redirect(status: u16, location: &str) -> Self {
        Self {
            status,
            headers: vec![("location".into(), location.to_string())],
            body: Bytes::new(),
        }
    }

    /// A JSON `{"error": msg}` body at `status`.
    #[must_use]
    pub fn error(status: u16, msg: impl Into<String>) -> Self {
        let v = serde_json::json!({ "error": msg.into() });
        Self::json(status, &v)
    }

    /// Append a header (used for CORS on `/blocktrails.json`, etc.).
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// HTML-escape the five significant characters. This is THE single
/// interpolation helper — every value rendered into a server view passes
/// through it. Ampersand is escaped first so a later `&lt;` is not
/// double-escaped into `&amp;lt;`.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Strip a filename down to a header-safe token: no quotes, no control
/// chars, no path separators. Prevents header-injection and traversal in
/// the `Content-Disposition` value.
#[must_use]
pub fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(200)
        .collect();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
}

/// Heuristic: does a byte slice look like UTF-8 text safe to serve inline
/// as `text/plain`? A NUL byte or invalid UTF-8 forces the attachment path.
#[must_use]
pub fn looks_textual(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return false;
    }
    std::str::from_utf8(bytes).is_ok()
}

/// Percent-decode a form/query token, mapping `+` to space and `%XX` to
/// its byte. Invalid escapes are passed through literally.
#[must_use]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `application/x-www-form-urlencoded` body into decoded pairs.
#[must_use]
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = percent_decode(it.next().unwrap_or(""));
        let v = percent_decode(it.next().unwrap_or(""));
        out.push((k, v));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_neutralises_script_payload() {
        let raw = r#"<script>alert('xss')</script>"#;
        let out = esc(raw);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert_eq!(out, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
    }

    #[test]
    fn esc_escapes_ampersand_once() {
        assert_eq!(esc("a & b < c"), "a &amp; b &lt; c");
        // No double-escaping: a literal `&lt;` in input becomes `&amp;lt;`.
        assert_eq!(esc("&lt;"), "&amp;lt;");
    }

    #[test]
    fn esc_escapes_quotes() {
        assert_eq!(esc(r#"say "hi""#), "say &quot;hi&quot;");
    }

    #[test]
    fn raw_bytes_binary_is_attachment() {
        let r = ForgeResponse::raw_bytes(Bytes::from_static(&[0u8, 1, 2]), false, "evil.html");
        let ct = r
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(ct, "application/octet-stream");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "content-disposition" && v.contains("attachment")));
    }

    #[test]
    fn raw_bytes_text_is_plain() {
        let r = ForgeResponse::raw_bytes(Bytes::from_static(b"hello"), true, "a.txt");
        let ct = r
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert!(ct.starts_with("text/plain"));
    }

    #[test]
    fn sanitize_filename_strips_path_and_quotes() {
        assert_eq!(sanitize_filename("../../etc/pa\"ss"), "pass");
        assert_eq!(sanitize_filename(""), "download");
        assert_eq!(sanitize_filename("a/b/c.tar.gz"), "c.tar.gz");
    }

    #[test]
    fn looks_textual_rejects_nul() {
        assert!(looks_textual(b"plain text"));
        assert!(!looks_textual(&[b'a', 0, b'b']));
    }

    #[test]
    fn query_param_parses_first_and_plus() {
        let req = ForgeRequest {
            method: "GET".into(),
            path: "/forge/a/b/issues".into(),
            query: "state=open&q=hello+world".into(),
            headers: vec![],
            raw_body: Bytes::new(),
            host_url: None,
        };
        assert_eq!(req.query_param("state").as_deref(), Some("open"));
        assert_eq!(req.query_param("q").as_deref(), Some("hello world"));
        assert_eq!(req.query_param("missing"), None);
    }

    #[test]
    fn percent_decode_and_form() {
        assert_eq!(percent_decode("a%2Fb+c"), "a/b c");
        assert_eq!(percent_decode("%zz"), "%zz");
        let pairs = parse_form("title=Fix+bug&resourceUrl=https%3A%2F%2Fp%2Fx.jsonld");
        assert_eq!(pairs[0], ("title".into(), "Fix bug".into()));
        assert_eq!(
            pairs[1],
            ("resourceUrl".into(), "https://p/x.jsonld".into())
        );
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let req = ForgeRequest {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            headers: vec![("Authorization".into(), "Nostr xyz".into())],
            raw_body: Bytes::new(),
            host_url: None,
        };
        assert_eq!(req.header("authorization"), Some("Nostr xyz"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Nostr xyz"));
    }
}
