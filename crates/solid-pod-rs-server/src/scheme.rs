//! Externally visible request scheme, with proxy headers honoured only from
//! a trusted proxy.
//!
//! JSS derives the public scheme from `X-Forwarded-Proto` and, failing that,
//! the Cloudflare `cf-visitor: {"scheme":"https"}` header
//! (`src/ap/index.js` `getProtocol` 49-56 and `src/ap/routes/actor.js` 17-18).
//! Those headers are attacker-controlled unless a proxy that the operator
//! trusts overwrites them, and the scheme feeds the NIP-98 signed-URL check
//! and every absolute base URI the server mints. So here they are honoured
//! only when the operator sets the trusted-proxy flag
//! (`--trust-proxy` / `JSS_TRUST_PROXY`, default off). Without it the scheme
//! is the transport's own: `https` when the listener terminates TLS, else
//! `http`.

use actix_web::{web, HttpRequest};

use crate::AppState;

/// Parse a scheme value, accepting only `http` and `https`
/// (case-insensitive).
fn clean_scheme(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "https" => Some("https"),
        "http" => Some("http"),
        _ => None,
    }
}

/// Scheme named by the proxy headers, if any: `X-Forwarded-Proto` first
/// (first element of a comma list), else the `scheme` member of the
/// `cf-visitor` JSON object. An unusable `X-Forwarded-Proto` value falls
/// through to `cf-visitor`.
pub fn proxy_header_scheme(req: &HttpRequest) -> Option<&'static str> {
    if let Some(v) = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(s) = v.split(',').next().and_then(clean_scheme) {
            return Some(s);
        }
    }
    let cf = req.headers().get("cf-visitor")?.to_str().ok()?;
    if cf.len() > 256 {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(cf).ok()?;
    clean_scheme(parsed.get("scheme")?.as_str()?)
}

/// Scheme of the connection itself, ignoring every forwarding header.
fn transport_scheme(req: &HttpRequest) -> &'static str {
    if req.app_config().secure() {
        "https"
    } else {
        "http"
    }
}

/// The request scheme as the client sees it.
///
/// With `trust_proxy` set this is [`proxy_header_scheme`], falling back to
/// the transport scheme; otherwise forwarding headers are ignored.
///
/// ```
/// use actix_web::test::TestRequest;
/// use solid_pod_rs_server::scheme::effective_scheme_with;
///
/// let req = TestRequest::get()
///     .insert_header(("cf-visitor", r#"{"scheme":"https"}"#))
///     .to_http_request();
/// assert_eq!(effective_scheme_with(&req, true), "https");
/// assert_eq!(effective_scheme_with(&req, false), "http");
/// ```
pub fn effective_scheme_with(req: &HttpRequest, trust_proxy: bool) -> &'static str {
    if trust_proxy {
        if let Some(s) = proxy_header_scheme(req) {
            return s;
        }
    }
    transport_scheme(req)
}

/// [`effective_scheme_with`] using the server's configured trusted-proxy
/// flag (`false` when the request carries no [`AppState`]).
pub fn effective_scheme(req: &HttpRequest) -> &'static str {
    let trust = req
        .app_data::<web::Data<AppState>>()
        .map(|s| s.trust_proxy)
        .unwrap_or(false);
    effective_scheme_with(req, trust)
}

/// Reduce a configured public base URL to its origin (`scheme://authority`,
/// no path, no trailing slash). `None` when it is not an `http(s)` URL with a
/// usable authority.
///
/// ```
/// use solid_pod_rs_server::scheme::normalise_origin;
/// assert_eq!(normalise_origin("https://pod.example/base/"), Some("https://pod.example".into()));
/// assert_eq!(normalise_origin("ftp://pod.example"), None);
/// ```
pub fn normalise_origin(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = clean_scheme(scheme)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    valid_authority(authority).then(|| format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// `true` for a plausible `host[:port]` (letters, digits, `.`, `-`, `:`,
/// bracketed IPv6), so a forged header cannot smuggle a path, userinfo or
/// whitespace into a generated URL.
fn valid_authority(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 255
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Host named by the first hop of an `X-Forwarded-Host` list, else by the
/// `host=` parameter of the first `Forwarded` element.
fn proxy_header_host(req: &HttpRequest) -> Option<String> {
    let xfh = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim);
    if let Some(h) = xfh.filter(|h| valid_authority(h)) {
        return Some(h.to_string());
    }
    let fwd = req.headers().get("forwarded")?.to_str().ok()?;
    let first = fwd.split(',').next()?;
    first.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        let v = v.trim().trim_matches('"');
        (k.trim().eq_ignore_ascii_case("host") && valid_authority(v)).then(|| v.to_string())
    })
}

/// The `Host` header (or the HTTP/2 `:authority`) exactly as received.
fn raw_host(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| valid_authority(h))
        .map(str::to_string)
        .or_else(|| {
            req.uri()
                .authority()
                .map(|a| a.as_str().to_string())
                .filter(|a| valid_authority(a))
        })
}

/// The authority a request should be treated as addressed to, with the
/// configuration passed explicitly.
///
/// Order: the configured public origin; with `trust_proxy`, `X-Forwarded-Host`
/// then `Forwarded`; the plain `Host` header; the request URI authority; the
/// server's own bound address.
/// Without `trust_proxy` the forwarding headers are never read, so a client
/// cannot retarget NIP-98 URL matching or generated links by sending them.
///
/// ```
/// use actix_web::test::TestRequest;
/// use solid_pod_rs_server::scheme::host_with;
///
/// let req = TestRequest::get()
///     .insert_header(("host", "pod.example"))
///     .insert_header(("x-forwarded-host", "evil.example"))
///     .to_http_request();
/// assert_eq!(host_with(&req, None, false), "pod.example");
/// assert_eq!(host_with(&req, None, true), "evil.example");
/// assert_eq!(host_with(&req, Some("https://pod.example"), true), "pod.example");
/// ```
pub fn host_with(req: &HttpRequest, public_origin: Option<&str>, trust_proxy: bool) -> String {
    if let Some(o) = public_origin {
        if let Some((_, a)) = o.split_once("://") {
            return a.to_string();
        }
    }
    if trust_proxy {
        if let Some(h) = proxy_header_host(req) {
            return h;
        }
    }
    // Last resort: the server's own bound address (never client-controlled).
    raw_host(req).unwrap_or_else(|| req.app_config().host().to_string())
}

/// [`host_with`] using the server's configured public origin and
/// trusted-proxy flag.
///
/// ```
/// use actix_web::test::TestRequest;
/// use solid_pod_rs_server::scheme::request_host;
///
/// // No `AppState` is attached, so forwarding headers are ignored.
/// let req = TestRequest::get()
///     .insert_header(("host", "pod.example"))
///     .insert_header(("x-forwarded-host", "evil.example"))
///     .to_http_request();
/// assert_eq!(request_host(&req), "pod.example");
/// ```
pub fn request_host(req: &HttpRequest) -> String {
    match req.app_data::<web::Data<AppState>>() {
        Some(s) => host_with(req, s.public_origin().as_deref(), s.trust_proxy),
        None => host_with(req, None, false),
    }
}

/// `scheme://host` of the request. A configured public origin wins outright;
/// otherwise [`effective_scheme`] plus [`request_host`].
pub fn request_origin(req: &HttpRequest) -> String {
    if let Some(o) = req
        .app_data::<web::Data<AppState>>()
        .and_then(|s| s.public_origin())
    {
        return o;
    }
    format!("{}://{}", effective_scheme(req), request_host(req))
}

/// The absolute URL the client addressed (origin plus request target), the
/// value a NIP-98 `u` tag is signed over.
///
/// ```
/// use actix_web::test::TestRequest;
/// use solid_pod_rs_server::scheme::request_url;
///
/// let req = TestRequest::get()
///     .uri("/pod/file.ttl?x=1")
///     .insert_header(("host", "pod.example"))
///     .to_http_request();
/// assert_eq!(request_url(&req), "http://pod.example/pod/file.ttl?x=1");
/// ```
pub fn request_url(req: &HttpRequest) -> String {
    format!("{}{}", request_origin(req), req.uri())
}

/// `true` when `host` (a `host[:port]`) is permitted by `allowed`, an empty
/// list permitting everything. Entries match case-insensitively either the
/// whole authority or just the host part.
///
/// ```
/// use solid_pod_rs_server::scheme::host_allowed;
/// let allow = vec!["pod.example".to_string()];
/// assert!(host_allowed("POD.example:8443", &allow));
/// assert!(!host_allowed("evil.example", &allow));
/// assert!(host_allowed("anything", &[]));
/// ```
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let host = host.to_ascii_lowercase();
    let bare = match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host.as_str(),
    };
    allowed.iter().any(|a| {
        let a = a.trim().to_ascii_lowercase();
        a == host || a == bare
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn req(headers: &[(&'static str, &'static str)]) -> HttpRequest {
        let mut r = TestRequest::get().uri("/x");
        for h in headers {
            r = r.insert_header(*h);
        }
        r.to_http_request()
    }

    #[test]
    fn untrusted_headers_are_ignored() {
        let r = req(&[
            ("x-forwarded-proto", "https"),
            ("cf-visitor", r#"{"scheme":"https"}"#),
        ]);
        assert_eq!(effective_scheme_with(&r, false), "http");
    }

    #[test]
    fn trusted_forwarded_proto_wins_over_cf_visitor() {
        let r = req(&[
            ("x-forwarded-proto", "http"),
            ("cf-visitor", r#"{"scheme":"https"}"#),
        ]);
        assert_eq!(effective_scheme_with(&r, true), "http");
    }

    #[test]
    fn trusted_cf_visitor_used_when_no_forwarded_proto() {
        let r = req(&[("cf-visitor", r#"{"scheme":"https"}"#)]);
        assert_eq!(effective_scheme_with(&r, true), "https");
    }

    #[test]
    fn forwarded_proto_comma_list_takes_first_hop() {
        let r = req(&[("x-forwarded-proto", "https, http")]);
        assert_eq!(effective_scheme_with(&r, true), "https");
    }

    #[test]
    fn garbage_values_fall_back_to_transport() {
        for h in [
            ("x-forwarded-proto", "gopher"),
            ("cf-visitor", "not json"),
            ("cf-visitor", r#"{"scheme":"ftp"}"#),
            ("cf-visitor", r#"{"scheme":7}"#),
        ] {
            assert_eq!(effective_scheme_with(&req(&[h]), true), "http", "{h:?}");
        }
    }

    #[test]
    fn unusable_forwarded_proto_falls_through_to_cf_visitor() {
        let r = req(&[
            ("x-forwarded-proto", "bogus"),
            ("cf-visitor", r#"{"scheme":"https"}"#),
        ]);
        assert_eq!(effective_scheme_with(&r, true), "https");
    }

    #[test]
    fn forwarded_host_is_ignored_without_trust_proxy() {
        let r = req(&[
            ("host", "pod.example"),
            ("x-forwarded-host", "evil.example"),
        ]);
        assert_eq!(host_with(&r, None, false), "pod.example");
        let r = req(&[("host", "pod.example"), ("forwarded", "host=evil.example")]);
        assert_eq!(host_with(&r, None, false), "pod.example");
    }

    #[test]
    fn forwarded_host_is_honoured_behind_trust_proxy() {
        let r = req(&[
            ("host", "10.0.0.5"),
            ("x-forwarded-host", "pod.example, other"),
        ]);
        assert_eq!(host_with(&r, None, true), "pod.example");
        let r = req(&[
            ("host", "10.0.0.5"),
            ("forwarded", "for=1.2.3.4;host=\"pod.example\""),
        ]);
        assert_eq!(host_with(&r, None, true), "pod.example");
    }

    #[test]
    fn configured_origin_beats_every_header() {
        let r = req(&[
            ("host", "evil.example"),
            ("x-forwarded-host", "evil.example"),
        ]);
        assert_eq!(
            host_with(&r, Some("https://pod.example"), true),
            "pod.example"
        );
    }

    #[test]
    fn hostile_host_values_are_not_reflected() {
        for bad in ["a/b", "user@evil.example", "a b", "evil.example/path?x"] {
            let r = req(&[("x-forwarded-host", bad)]);
            assert_eq!(host_with(&r, None, true), r.app_config().host(), "{bad}");
        }
    }

    #[test]
    fn allow_list_matches_host_and_authority() {
        let a = vec!["pod.example".to_string(), "127.0.0.1:3000".to_string()];
        assert!(host_allowed("pod.example", &a));
        assert!(host_allowed("pod.example:8443", &a));
        assert!(host_allowed("127.0.0.1:3000", &a));
        assert!(!host_allowed("127.0.0.1:4000", &a));
        assert!(!host_allowed("evil.example", &a));
    }

    #[test]
    fn oversized_cf_visitor_is_ignored() {
        let big = format!(r#"{{"scheme":"https","pad":"{}"}}"#, "a".repeat(400));
        let r = TestRequest::get()
            .insert_header(("cf-visitor", big))
            .to_http_request();
        assert_eq!(effective_scheme_with(&r, true), "http");
    }
}
