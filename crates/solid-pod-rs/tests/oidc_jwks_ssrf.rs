//! Sprint 5 P0-2: SSRF-guarded JWKS + OIDC discovery fetcher.
//!
//! These tests exercise [`solid_pod_rs::oidc::jwks`] at the crate
//! boundary. They were written *before* the implementation and are the
//! RED phase of the TDD cycle for P0-2.
//!
//! Coverage:
//!
//! 1. `oidc_jwks_fetch_blocks_metadata_ip` — a default SSRF policy
//!    refuses to fetch an issuer whose URL is the AWS/GCP/Azure
//!    metadata literal `169.254.169.254` (classified `Reserved`).
//! 2. `oidc_jwks_fetch_runs_ssrf_twice` — fetch_jwks goes through the
//!    SSRF policy for both the issuer URL and the jwks_uri — a
//!    jwks_uri host pointing at a blocked IP must be rejected even
//!    when the issuer host is allowlisted.
//! 3. `oidc_config_cache_returns_cached_within_ttl` — second fetch
//!    within TTL hits the cache, not the network (wiremock hit count
//!    remains 1).
//! 4. `oidc_jwks_issuer_fixation_check` — a discovery document whose
//!    `issuer` claim disagrees with the URL used to fetch it is
//!    rejected.

#![cfg(feature = "oidc")]

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use solid_pod_rs::oidc::jwks::{
    fetch_jwks, fetch_oidc_config, CachedFetcher, JwksCache, OidcConfigCache,
};
use solid_pod_rs::security::ssrf::SsrfPolicy;

// --- test-1 --------------------------------------------------------------

/// An issuer URL whose host literal is the cloud-metadata IP must be
/// rejected by the default SSRF policy *before* any network I/O.
#[tokio::test]
async fn oidc_jwks_fetch_blocks_metadata_ip() {
    let ssrf = SsrfPolicy::new(); // default: deny everything non-public
    let client = Client::new();
    let issuer = Url::parse("http://169.254.169.254/").unwrap();

    let err = fetch_jwks(&issuer, &ssrf, &client)
        .await
        .expect_err("metadata IP must be blocked");

    let msg = format!("{err}");
    assert!(
        msg.contains("SSRF") || msg.contains("Reserved") || msg.contains("169.254.169.254"),
        "expected SSRF / Reserved / metadata IP in error, got: {msg}"
    );
}

// --- test-2 --------------------------------------------------------------

/// The SSRF policy is consulted for the issuer URL *and* independently
/// for the jwks_uri. This prevents an attacker who controls the
/// discovery document from redirecting the JWKS fetch to a blocked
/// internal endpoint after issuer-host approval.
#[tokio::test]
async fn oidc_jwks_fetch_runs_ssrf_twice() {
    // The issuer is wiremock on loopback (allowed via with_allow_loopback).
    let server = MockServer::start().await;
    let issuer_url = Url::parse(&server.uri()).unwrap();
    let issuer_str = issuer_url.as_str().trim_end_matches('/').to_string();

    // Discovery document points jwks_uri at the cloud-metadata IP,
    // which the default policy will reject — but the issuer host is
    // allowlisted via loopback. This proves the SSRF guard re-runs
    // for jwks_uri and is not skipped after issuer approval.
    let doc = json!({
        "issuer": issuer_str,
        "jwks_uri": "http://169.254.169.254/jwks",
        "authorization_endpoint": format!("{issuer_str}/authorize"),
        "token_endpoint": format!("{issuer_str}/token"),
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;

    let ssrf = SsrfPolicy::new().with_allow_loopback(true);
    let client = Client::new();

    let err = fetch_jwks(&issuer_url, &ssrf, &client)
        .await
        .expect_err("jwks_uri pointing at metadata IP must be blocked");
    let msg = format!("{err}");
    assert!(
        msg.contains("SSRF")
            || msg.contains("Reserved")
            || msg.contains("169.254.169.254"),
        "expected SSRF error for jwks_uri, got: {msg}"
    );
}

// --- test-3 --------------------------------------------------------------

/// A second fetch within the TTL window does not hit the network.
#[tokio::test]
async fn oidc_config_cache_returns_cached_within_ttl() {
    let server = MockServer::start().await;
    let issuer_url = Url::parse(&server.uri()).unwrap();
    let issuer_str = issuer_url.as_str().trim_end_matches('/').to_string();

    let doc = json!({
        "issuer": issuer_str,
        "jwks_uri": format!("{issuer_str}/jwks"),
        "authorization_endpoint": format!("{issuer_str}/authorize"),
        "token_endpoint": format!("{issuer_str}/token"),
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .expect(1) // the second call must hit the cache, not the mock
        .mount(&server)
        .await;

    let ssrf = Arc::new(SsrfPolicy::new().with_allow_loopback(true));
    let client = Client::new();
    let fetcher = CachedFetcher::new(
        OidcConfigCache::new(Duration::from_secs(900)),
        JwksCache::new(Duration::from_secs(900)),
        ssrf,
        client,
    );

    let d1 = fetcher.config(&issuer_url).await.expect("first fetch ok");
    let d2 = fetcher.config(&issuer_url).await.expect("second fetch ok");
    assert_eq!(d1.issuer, d2.issuer);

    // If we drop the server here, wiremock will panic on drop if the
    // expected(1) count was exceeded.
}

// --- test-4 --------------------------------------------------------------

/// An issuer claim disagreeing with the URL used for fetch is rejected
/// (issuer-fixation defence — OIDC Core §3 / RFC 8414 §3.3).
#[tokio::test]
async fn oidc_jwks_issuer_fixation_check() {
    let server = MockServer::start().await;
    let issuer_url = Url::parse(&server.uri()).unwrap();

    // Note: discovery doc claims a *different* issuer than the URL we
    // fetched from.
    let doc = json!({
        "issuer": "https://other.example",
        "jwks_uri": format!("{}/jwks", server.uri()),
        "authorization_endpoint": format!("{}/authorize", server.uri()),
        "token_endpoint": format!("{}/token", server.uri()),
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;

    let ssrf = SsrfPolicy::new().with_allow_loopback(true);
    let client = Client::new();

    let err = fetch_oidc_config(&issuer_url, &ssrf, &client)
        .await
        .expect_err("issuer mismatch must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("issuer"),
        "expected issuer-fixation error, got: {msg}"
    );
}
