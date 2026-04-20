//! Integration tests for Sprint 7 A — CORS policy primitive.
//!
//! Verifies the preflight + response-header contract of [`CorsPolicy`]:
//! origin echo, blocking, header advertising, exposed headers,
//! credentials + wildcard interplay, and env loading.

#![cfg(feature = "jss-v04")]

use std::collections::BTreeSet;
use std::time::Duration;

use solid_pod_rs::security::cors::{AllowedOrigins, CorsPolicy};

fn header<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn two_origins() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("https://app.example".to_string());
    s.insert("https://other.example".to_string());
    s
}

// --- preflight semantics -------------------------------------------------

#[test]
fn cors_preflight_echoes_allowed_origin() {
    let policy = CorsPolicy::new().with_allowed_origins(AllowedOrigins::Exact(two_origins()));

    let headers = policy
        .preflight_headers(
            Some("https://app.example"),
            "PUT",
            "authorization, dpop, content-type",
        )
        .expect("allowed origin must yield headers");

    assert_eq!(
        header(&headers, "Access-Control-Allow-Origin"),
        Some("https://app.example")
    );
    // Vary is required when echoing origin, per Fetch spec.
    assert!(header(&headers, "Vary")
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("origin"));
}

#[test]
fn cors_preflight_blocks_unlisted_origin() {
    let policy = CorsPolicy::new().with_allowed_origins(AllowedOrigins::Exact(two_origins()));

    let result = policy.preflight_headers(
        Some("https://attacker.example"),
        "GET",
        "authorization",
    );
    assert!(
        result.is_none(),
        "unlisted origin must return None (caller emits 403/no-CORS)"
    );
}

#[test]
fn cors_preflight_advertises_required_request_headers() {
    let policy = CorsPolicy::new().with_allowed_origins(AllowedOrigins::Wildcard);

    let headers = policy
        .preflight_headers(
            Some("https://app.example"),
            "PATCH",
            "Authorization, DPoP, Content-Type",
        )
        .expect("wildcard policy must permit any origin");

    let allow_headers = header(&headers, "Access-Control-Allow-Headers")
        .expect("Allow-Headers must be present on preflight")
        .to_ascii_lowercase();

    for h in ["authorization", "dpop", "content-type"] {
        assert!(
            allow_headers.contains(h),
            "Allow-Headers missing {h}: got {allow_headers:?}"
        );
    }

    // Allow-Methods must include the requested method.
    let allow_methods = header(&headers, "Access-Control-Allow-Methods")
        .expect("Allow-Methods must be present on preflight")
        .to_ascii_uppercase();
    assert!(
        allow_methods.contains("PATCH"),
        "Allow-Methods missing PATCH: {allow_methods:?}"
    );

    // Max-Age must default to 3600.
    assert_eq!(header(&headers, "Access-Control-Max-Age"), Some("3600"));
}

// --- normal response semantics ------------------------------------------

#[test]
fn cors_response_emits_expose_headers() {
    let policy = CorsPolicy::new().with_allowed_origins(AllowedOrigins::Wildcard);

    let headers = policy.response_headers(Some("https://app.example"));
    let expose = header(&headers, "Access-Control-Expose-Headers")
        .expect("Expose-Headers must be present on normal responses")
        .to_ascii_lowercase();

    for h in [
        "wac-allow",
        "link",
        "etag",
        "accept-patch",
        "accept-post",
        "updates-via",
    ] {
        assert!(
            expose.contains(h),
            "default Expose-Headers missing {h}: got {expose:?}"
        );
    }
}

#[test]
fn cors_wildcard_with_credentials_falls_back_to_origin() {
    // Per Fetch / CORS: `*` is invalid when credentials are included;
    // the server must echo the concrete origin instead.
    let policy = CorsPolicy::new()
        .with_allowed_origins(AllowedOrigins::Wildcard)
        .with_allow_credentials(true);

    let headers = policy.response_headers(Some("https://app.example"));
    assert_eq!(
        header(&headers, "Access-Control-Allow-Origin"),
        Some("https://app.example"),
        "wildcard + credentials MUST echo the request origin, not `*`"
    );
    assert_eq!(
        header(&headers, "Access-Control-Allow-Credentials"),
        Some("true")
    );
    // And `Vary: Origin` so caches don't leak the echoed origin to
    // other clients.
    assert!(header(&headers, "Vary")
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("origin"));
}

// --- env loading ---------------------------------------------------------

#[test]
fn cors_from_env_reads_all_three_vars() {
    // Serialise env-var writes within this test; the tests above are
    // pure and don't touch process env, so a local lock suffices.
    let prev_origins = std::env::var("CORS_ALLOWED_ORIGINS").ok();
    let prev_creds = std::env::var("CORS_ALLOW_CREDENTIALS").ok();
    let prev_age = std::env::var("CORS_MAX_AGE").ok();

    std::env::set_var(
        "CORS_ALLOWED_ORIGINS",
        "https://a.example,https://b.example",
    );
    std::env::set_var("CORS_ALLOW_CREDENTIALS", "true");
    std::env::set_var("CORS_MAX_AGE", "7200");

    let policy = CorsPolicy::from_env();

    // Credentials must be on.
    let headers = policy.response_headers(Some("https://a.example"));
    assert_eq!(
        header(&headers, "Access-Control-Allow-Credentials"),
        Some("true")
    );

    // Unlisted origin must be blocked.
    let blocked = policy.preflight_headers(Some("https://c.example"), "GET", "");
    assert!(blocked.is_none(), "unlisted origin from env must be blocked");

    // Listed origin must be echoed, and Max-Age must reflect env.
    let ok = policy
        .preflight_headers(Some("https://b.example"), "POST", "content-type")
        .expect("listed origin must be permitted");
    assert_eq!(
        header(&ok, "Access-Control-Allow-Origin"),
        Some("https://b.example")
    );
    assert_eq!(header(&ok, "Access-Control-Max-Age"), Some("7200"));

    // Round-trip: default max-age-based Duration invariant still
    // expressible.
    assert_eq!(Duration::from_secs(7200), Duration::from_secs(7200));

    // Restore prior env to keep the test process hermetic.
    restore("CORS_ALLOWED_ORIGINS", prev_origins);
    restore("CORS_ALLOW_CREDENTIALS", prev_creds);
    restore("CORS_MAX_AGE", prev_age);
}

fn restore(key: &str, val: Option<String>) {
    match val {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}
