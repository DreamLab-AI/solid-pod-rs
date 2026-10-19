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

/// `scheme://host` of the request, using [`effective_scheme`].
pub fn request_origin(req: &HttpRequest) -> String {
    let scheme = effective_scheme(req);
    let conn = req.connection_info();
    format!("{scheme}://{}", conn.host())
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
    fn oversized_cf_visitor_is_ignored() {
        let big = format!(r#"{{"scheme":"https","pad":"{}"}}"#, "a".repeat(400));
        let r = TestRequest::get()
            .insert_header(("cf-visitor", big))
            .to_http_request();
        assert_eq!(effective_scheme_with(&r, true), "http");
    }
}
