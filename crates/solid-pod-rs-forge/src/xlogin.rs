//! The vendored `xlogin.js` login widget route and the page Content Security
//! Policy.
//!
//! `assets/xlogin.js` is a byte-for-byte copy of the file the JSS `forge`
//! plugin vendors from <https://github.com/melvincarvalho/xlogin> (version
//! 0.0.15, licence AGPL-3.0-or-later, compatible with this crate's
//! AGPL-3.0-only). It is data, not code authored here, and must not be
//! edited; re-vendor from upstream to update. [`xlogin_response`] serves it
//! at `<prefix>/xlogin.js` (JSS: the xlogin route in the forge dispatcher),
//! and [`build_csp`] builds the policy `handle` attaches to every HTML page
//! (JSS: `buildCsp`).
//!
//! # Content-Security-Policy tiers and residual risk
//!
//! No policy trusts `'self'` for scripts: a pod writer can store a `.js` file
//! on the same origin, so `'self'` would make it a valid script source for a
//! forge page. A page that loads the widget needs the [`build_csp`] policy
//! (`script-src 'nonce-<random>' https://esm.sh`), because the vendored widget
//! dynamically imports from that CDN and must not be edited; its script tag
//! carries the nonce. Every other page gets [`build_strict_csp`]
//! (`script-src 'nonce-<random>'`). A
//! handler opts a page into the weak tier with the internal
//! [`crate::WIDGET_PAGE_HEADER`] response header, never by page content. No
//! page sets it today. The residual risk is that any future widget page
//! carries the weak policy until the widget is vendored with its imports or
//! pinned with subresource integrity.

use bytes::Bytes;

use crate::request::ForgeResponse;

/// The vendored widget source, byte-identical to the upstream file.
pub static XLOGIN_JS: &[u8] = include_bytes!("../assets/xlogin.js");

/// Build the widget page `Content-Security-Policy`.
///
/// `script-src` is `'nonce-<nonce>' https://esm.sh`: only a script tag that
/// carries the response's nonce runs (the page's own `<script nonce=...
/// src="/forge/xlogin.js">`), and its dynamic `import()`s (governed by
/// `script-src`, not `connect-src`) may load from the CDN. There is no
/// `'self'` and no `'unsafe-inline'`, so a script a pod writer stored on the
/// same origin is not a valid source. `connect-src` is `'self'` plus the
/// operator's `csp_connect` origins that look like plain `http(s)` origins
/// (no whitespace, `;`, quotes), so external Solid IdP login stays blocked
/// unless opted in. `form-action 'self'` keeps the plain GET search forms
/// working. `nonce` must be unguessable and fresh per response; only
/// `[A-Za-z0-9+/=_-]` characters are kept.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::xlogin::build_csp;
///
/// let csp = build_csp(&[], "abc123");
/// assert!(csp.contains("script-src 'nonce-abc123' https://esm.sh;"));
/// assert!(!csp.contains("script-src 'self'"));
/// assert!(csp.contains("connect-src 'self';"));
///
/// let csp = build_csp(&["https://idp.example".into(), "javascript:evil".into(), "https://a b".into()], "n");
/// assert!(csp.contains("connect-src 'self' https://idp.example;"));
/// assert!(!csp.contains("evil"));
/// ```
#[must_use]
pub fn build_csp(csp_connect: &[String], nonce: &str) -> String {
    page_csp(
        csp_connect,
        &format!("'nonce-{}' https://esm.sh", clean(nonce)),
    )
}

/// Build the strict page `Content-Security-Policy` for pages that do **not**
/// load the login widget (security review M4).
///
/// Identical to [`build_csp`] except `script-src` is `'nonce-<nonce>'` alone:
/// no `'self'`, no `'unsafe-inline'` and no `https://esm.sh`, so neither an
/// HTML-injection bug nor a script a pod writer stored on the same origin can
/// run on such a page, and the third-party CDN is never trusted. No forge
/// page emits a script today; the nonce reserves the slot, so any future
/// script must carry it. `nonce` must be unguessable and fresh per response;
/// only `[A-Za-z0-9+/=_-]` characters are kept.
///
/// **Residual risk.** A page that loads [`XLOGIN_JS`] still needs the CDN in
/// `script-src` (see [`build_csp`]), because the vendored widget, which must
/// not be edited, dynamically imports from it, until the widget is vendored
/// with its imports or pinned with subresource integrity.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::xlogin::build_strict_csp;
///
/// let csp = build_strict_csp(&[], "abc123");
/// assert!(csp.contains("script-src 'nonce-abc123';"));
/// assert!(!csp.contains("'self' 'nonce") && !csp.contains("esm.sh"));
/// ```
#[must_use]
pub fn build_strict_csp(csp_connect: &[String], nonce: &str) -> String {
    page_csp(csp_connect, &format!("'nonce-{}'", clean(nonce)))
}

fn clean(nonce: &str) -> String {
    nonce
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'))
        .collect()
}

fn page_csp(csp_connect: &[String], script_src: &str) -> String {
    let mut connect = String::from("'self'");
    for o in csp_connect {
        let rest = o
            .strip_prefix("https://")
            .or_else(|| o.strip_prefix("http://"));
        let ok = rest.is_some_and(|r| {
            !r.is_empty()
                && !r
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, ';' | '\'' | '"'))
        });
        if ok {
            connect.push(' ');
            connect.push_str(o);
        }
    }
    format!(
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data:; \
script-src {script_src}; connect-src {connect}; \
base-uri 'none'; form-action 'self'"
    )
}

/// Serve the widget. Only `GET` / `HEAD` are allowed (`405` otherwise); the
/// response is immutable-cached and `nosniff`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::xlogin::{xlogin_response, XLOGIN_JS};
///
/// let r = xlogin_response("GET");
/// assert_eq!(r.status, 200);
/// assert_eq!(r.body.as_ref(), XLOGIN_JS);
/// assert_eq!(xlogin_response("POST").status, 405);
/// ```
#[must_use]
pub fn xlogin_response(method: &str) -> ForgeResponse {
    if !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) {
        return ForgeResponse {
            status: 405,
            headers: vec![("allow".into(), "GET, HEAD".into())],
            body: Bytes::new(),
        };
    }
    let body = if method.eq_ignore_ascii_case("HEAD") {
        Bytes::new()
    } else {
        Bytes::from_static(XLOGIN_JS)
    };
    ForgeResponse {
        status: 200,
        headers: vec![
            (
                "content-type".into(),
                "application/javascript; charset=utf-8".into(),
            ),
            (
                "cache-control".into(),
                "public, max-age=31536000, immutable".into(),
            ),
            ("x-content-type-options".into(), "nosniff".into()),
        ],
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // JSS test "xlogin.js is served byte-identical to the vendored file".
    #[test]
    fn served_bytes_are_identical_and_headers_match() {
        let r = xlogin_response("GET");
        assert_eq!(r.status, 200);
        assert_eq!(r.body.as_ref(), XLOGIN_JS);
        let h = |n: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert!(h("content-type").starts_with("application/javascript"));
        assert!(h("cache-control").contains("immutable"));
        assert_eq!(h("x-content-type-options"), "nosniff");
        assert!(String::from_utf8_lossy(XLOGIN_JS).contains("version 0.0.15"));
        assert_eq!(xlogin_response("HEAD").body.len(), 0);
        assert_eq!(xlogin_response("PUT").status, 405);
    }

    // JSS test "issues pages load the widget; CSP admits it and keeps connect-src 'self'".
    #[test]
    fn csp_admits_widget_and_keeps_connect_self() {
        let csp = build_csp(&[], "n0nce");
        assert!(csp.contains("script-src 'nonce-n0nce' https://esm.sh;"));
        assert!(!csp.contains("'self' https://esm.sh") && !csp.contains("unsafe-inline' "));
        assert!(csp.contains("connect-src 'self';"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.starts_with("default-src 'none';"));
    }

    #[test]
    fn strict_csp_has_no_inline_or_cdn_and_sanitises_the_nonce() {
        let csp = build_strict_csp(&[], "ab12'; script-src *");
        assert!(csp.contains("'nonce-ab12script-src'"), "{csp}");
        assert!(!csp.contains("esm.sh"));
        assert!(!csp.contains("script-src 'self'") && !csp.contains("'self' 'nonce"));
        assert!(
            csp.contains("style-src 'unsafe-inline'"),
            "styles unchanged"
        );
        assert!(csp.contains("connect-src 'self';"));
    }

    #[test]
    fn csp_connect_origins_are_filtered() {
        let csp = build_csp(
            &[
                "https://idp.example".into(),
                "http://localhost:3000".into(),
                "ftp://x".into(),
                "https://a;b".into(),
                "https://a'b".into(),
                "https://".into(),
            ],
            "n",
        );
        assert!(csp.contains("connect-src 'self' https://idp.example http://localhost:3000;"));
        assert!(!csp.contains("ftp"));
        assert!(!csp.contains("a;b"));
    }
}
