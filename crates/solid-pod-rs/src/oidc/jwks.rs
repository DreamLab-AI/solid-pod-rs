//! SSRF-guarded JWKS + OIDC discovery fetcher (Sprint 5 P0-2).
//!
//! Upstream hazard this module closes: `verify_access_token` currently
//! takes a caller-supplied HS256 secret. JSS parity requires the pod
//! to fetch the OP's signing keys via OIDC discovery — a *network*
//! operation touching attacker-influenceable URLs. Without an SSRF
//! guard on both the issuer URL and the indirected `jwks_uri`, a
//! malicious or mis-registered OP can pivot the fetch at cloud
//! metadata, internal services, or loopback.
//!
//! Defences layered here (all required for the module to be safe):
//!
//! 1. **`SsrfPolicy::resolve_and_check`** runs twice — once for the
//!    issuer URL and *again* for the jwks_uri returned by discovery.
//!    Approval of the issuer does not grant approval for the jwks_uri.
//! 2. **TCP pinning** via `reqwest::ClientBuilder::resolve` — the
//!    connect-time DNS lookup is replaced with the IP the policy
//!    approved, defeating DNS-rebinding between check and connect.
//! 3. **Issuer fixation** — the `issuer` field of the discovery
//!    document must equal the URL the pod fetched it from (modulo
//!    trailing-slash), matching OIDC Core §3 and RFC 8414 §3.3.
//! 4. **Bounded timeouts** — per-request 10s hard cap so a wedged OP
//!    cannot tie up the pod's request queue.
//! 5. **Cache with TTL** — successful discovery documents and JWKS
//!    are memoised for 900s (JSS parity), amortising the cost of the
//!    SSRF resolve+connect handshake across many verifications.
//!
//! This module is feature-gated behind `oidc`. The aggregate entry
//! point for callers is [`CachedFetcher`]; the bare [`fetch_oidc_config`]
//! / [`fetch_jwks`] functions are exposed for tests and specialised
//! call sites that manage their own caching strategy.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::error::PodError;
use crate::security::ssrf::SsrfPolicy;

/// Default fetch timeout. Chosen to match JSS upstream (10s) and to
/// stay well below typical HTTP handler budgets.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cache TTL for both discovery docs and JWKS, matching JSS.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(900);

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

/// Minimal deserialisation shape for the OP's
/// `/.well-known/openid-configuration` response. Only fields the pod
/// actually consults are strongly-typed; anything else an OP publishes
/// round-trips through `serde(flatten)` so we never reject on unknown
/// fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcDiscoveryDoc {
    pub issuer: String,
    pub jwks_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    /// Preserve OP-specific metadata the pod doesn't currently
    /// interpret. Keeps us forward-compatible with OP extensions.
    #[serde(flatten, default)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Caches
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CachedConfig {
    fetched: Instant,
    doc: OidcDiscoveryDoc,
}

#[derive(Clone)]
struct CachedJwks {
    fetched: Instant,
    set: JwkSet,
}

/// TTL cache keyed by issuer URL (as a string) holding
/// [`OidcDiscoveryDoc`] entries.
pub struct OidcConfigCache {
    ttl: Duration,
    inner: Arc<RwLock<HashMap<String, CachedConfig>>>,
}

impl OidcConfigCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the cached document if present and still fresh.
    pub fn get(&self, issuer: &str) -> Option<OidcDiscoveryDoc> {
        let guard = self.inner.read().ok()?;
        let entry = guard.get(issuer)?;
        if entry.fetched.elapsed() <= self.ttl {
            Some(entry.doc.clone())
        } else {
            None
        }
    }

    fn put(&self, issuer: String, doc: OidcDiscoveryDoc) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                issuer,
                CachedConfig {
                    fetched: Instant::now(),
                    doc,
                },
            );
        }
    }
}

impl Default for OidcConfigCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL)
    }
}

/// TTL cache keyed by issuer URL holding [`JwkSet`] entries.
pub struct JwksCache {
    ttl: Duration,
    inner: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

impl JwksCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the cached JwkSet if present and still fresh.
    pub fn get(&self, issuer: &str) -> Option<JwkSet> {
        let guard = self.inner.read().ok()?;
        let entry = guard.get(issuer)?;
        if entry.fetched.elapsed() <= self.ttl {
            Some(entry.set.clone())
        } else {
            None
        }
    }

    fn put(&self, issuer: String, set: JwkSet) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                issuer,
                CachedJwks {
                    fetched: Instant::now(),
                    set,
                },
            );
        }
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL)
    }
}

// ---------------------------------------------------------------------------
// Core fetch primitives
// ---------------------------------------------------------------------------

/// Normalise an issuer URL to its string form with no trailing slash,
/// for comparison against the `issuer` field of the discovery doc.
fn canonical_issuer(u: &Url) -> String {
    u.as_str().trim_end_matches('/').to_string()
}

/// Build a reqwest client whose DNS resolver for `host` is pinned to
/// `ip:port`. This defeats DNS rebinding between the SSRF check and
/// the subsequent TCP connect: the kernel connects to the approved IP
/// even if the OS resolver would now hand back a different address.
fn pinned_client(base: &Client, host: &str, ip: std::net::IpAddr, port: u16) -> reqwest::Result<Client> {
    // We deliberately build a fresh client rather than clone-and-mutate
    // `base` because reqwest's builder consumes itself. The base client
    // is retained so call sites can carry shared connection-pool
    // settings (e.g. tls configuration) — we mirror its timeout.
    let _ = base; // reserved for future shared config
    reqwest::Client::builder()
        .resolve(host, SocketAddr::new(ip, port))
        .timeout(FETCH_TIMEOUT)
        .build()
}

/// Fetch the OP's OIDC discovery document with SSRF enforcement and
/// issuer-fixation validation. The returned doc is *not* cached — call
/// [`CachedFetcher::config`] if you want caching.
pub async fn fetch_oidc_config(
    issuer: &Url,
    ssrf: &SsrfPolicy,
    client: &Client,
) -> Result<OidcDiscoveryDoc, PodError> {
    let approved_ip = ssrf
        .resolve_and_check(issuer)
        .await
        .map_err(|e| PodError::Nip98(format!("issuer SSRF: {e}")))?;

    let host = issuer
        .host_str()
        .ok_or_else(|| PodError::Nip98(format!("issuer URL missing host: {issuer}")))?
        .to_string();
    let port = issuer.port_or_known_default().unwrap_or(match issuer.scheme() {
        "https" => 443,
        _ => 80,
    });

    let pinned = pinned_client(client, &host, approved_ip, port)
        .map_err(|e| PodError::Backend(format!("reqwest client build failed: {e}")))?;

    // Build the `/.well-known/openid-configuration` URL by joining
    // against the issuer base. `Url::join` handles trailing slashes
    // correctly.
    let discovery_url = {
        // Ensure base has a trailing slash so `join` appends rather
        // than replaces the final segment.
        let base = if issuer.path().ends_with('/') {
            issuer.clone()
        } else {
            let mut u = issuer.clone();
            u.set_path(&format!("{}/", u.path()));
            u
        };
        base.join(".well-known/openid-configuration")?
    };

    let resp = pinned
        .get(discovery_url.clone())
        .send()
        .await
        .map_err(|e| PodError::Backend(format!("discovery fetch failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(PodError::Backend(format!(
            "discovery returned HTTP {}",
            resp.status()
        )));
    }
    let doc: OidcDiscoveryDoc = resp
        .json()
        .await
        .map_err(|e| PodError::Backend(format!("discovery parse failed: {e}")))?;

    // Issuer-fixation defence (OIDC Core §3, RFC 8414 §3.3). A
    // malicious OP that hijacks an issuer URL cannot substitute its
    // own identifier and get it accepted.
    let expected = canonical_issuer(issuer);
    let claimed = doc.issuer.trim_end_matches('/');
    if claimed != expected {
        return Err(PodError::Nip98(format!(
            "issuer fixation: discovery doc issuer '{claimed}' does not match fetch URL '{expected}'"
        )));
    }

    debug!(issuer = %expected, jwks_uri = %doc.jwks_uri, "fetched OIDC discovery doc");
    Ok(doc)
}

/// Fetch the JWKS for an issuer, running SSRF checks on *both* the
/// issuer URL and the indirected `jwks_uri`. The jwks_uri approval is
/// independent: an attacker who controls the discovery doc cannot
/// cause a second fetch to bypass policy by reusing the first
/// approval.
pub async fn fetch_jwks(
    issuer: &Url,
    ssrf: &SsrfPolicy,
    client: &Client,
) -> Result<JwkSet, PodError> {
    let doc = fetch_oidc_config(issuer, ssrf, client).await?;
    let jwks_url = Url::parse(&doc.jwks_uri)
        .map_err(|e| PodError::Nip98(format!("malformed jwks_uri '{}': {e}", doc.jwks_uri)))?;

    // Re-run the SSRF guard. DO NOT reuse the issuer approval; the
    // jwks_uri host may legitimately differ from the issuer host (and,
    // more importantly, an attacker may want it to).
    let approved_ip = ssrf
        .resolve_and_check(&jwks_url)
        .await
        .map_err(|e| PodError::Nip98(format!("jwks_uri SSRF: {e}")))?;

    let host = jwks_url
        .host_str()
        .ok_or_else(|| PodError::Nip98(format!("jwks_uri missing host: {jwks_url}")))?
        .to_string();
    let port = jwks_url
        .port_or_known_default()
        .unwrap_or(match jwks_url.scheme() {
            "https" => 443,
            _ => 80,
        });

    let pinned = pinned_client(client, &host, approved_ip, port)
        .map_err(|e| PodError::Backend(format!("reqwest client build failed: {e}")))?;

    let resp = pinned
        .get(jwks_url.clone())
        .send()
        .await
        .map_err(|e| PodError::Backend(format!("jwks fetch failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(PodError::Backend(format!(
            "jwks returned HTTP {}",
            resp.status()
        )));
    }
    let set: JwkSet = resp
        .json()
        .await
        .map_err(|e| PodError::Backend(format!("jwks parse failed: {e}")))?;

    debug!(issuer = %canonical_issuer(issuer), keys = set.keys.len(), "fetched JWKS");
    Ok(set)
}

// ---------------------------------------------------------------------------
// Aggregate cached fetcher
// ---------------------------------------------------------------------------

/// Caching wrapper around [`fetch_oidc_config`] and [`fetch_jwks`]. A
/// single instance is safe to share across tasks (all state is behind
/// `Arc`/`RwLock`). The struct owns its caches and the SSRF policy.
pub struct CachedFetcher {
    config_cache: OidcConfigCache,
    jwks_cache: JwksCache,
    ssrf: Arc<SsrfPolicy>,
    client: Client,
}

impl CachedFetcher {
    pub fn new(
        config_cache: OidcConfigCache,
        jwks_cache: JwksCache,
        ssrf: Arc<SsrfPolicy>,
        client: Client,
    ) -> Self {
        Self {
            config_cache,
            jwks_cache,
            ssrf,
            client,
        }
    }

    /// Construct a fetcher with default (900s) TTLs and a shared SSRF
    /// policy. Convenience for operator code that does not need fine
    /// control over cache sizes.
    pub fn with_defaults(ssrf: Arc<SsrfPolicy>, client: Client) -> Self {
        Self::new(
            OidcConfigCache::default(),
            JwksCache::default(),
            ssrf,
            client,
        )
    }

    /// Fetch the discovery document for `issuer`, consulting the cache
    /// first. A cache miss triggers a full SSRF-guarded fetch.
    pub async fn config(&self, issuer: &Url) -> Result<OidcDiscoveryDoc, PodError> {
        let key = canonical_issuer(issuer);
        if let Some(cached) = self.config_cache.get(&key) {
            return Ok(cached);
        }
        let doc = fetch_oidc_config(issuer, &self.ssrf, &self.client).await?;
        self.config_cache.put(key, doc.clone());
        Ok(doc)
    }

    /// Fetch the JWKS for `issuer`, consulting the cache first. A
    /// cache miss runs both SSRF checks (issuer + jwks_uri) and both
    /// network fetches.
    pub async fn jwks(&self, issuer: &Url) -> Result<JwkSet, PodError> {
        let key = canonical_issuer(issuer);
        if let Some(cached) = self.jwks_cache.get(&key) {
            return Ok(cached);
        }
        let set = fetch_jwks(issuer, &self.ssrf, &self.client).await?;
        self.jwks_cache.put(key, set.clone());
        Ok(set)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (fast, no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_issuer_strips_trailing_slash() {
        let u = Url::parse("https://op.example/").unwrap();
        assert_eq!(canonical_issuer(&u), "https://op.example");
        let u2 = Url::parse("https://op.example").unwrap();
        assert_eq!(canonical_issuer(&u2), "https://op.example");
    }

    #[test]
    fn config_cache_misses_when_empty() {
        let c = OidcConfigCache::new(Duration::from_secs(60));
        assert!(c.get("https://op.example").is_none());
    }

    #[test]
    fn config_cache_hits_within_ttl() {
        let c = OidcConfigCache::new(Duration::from_secs(60));
        let doc = OidcDiscoveryDoc {
            issuer: "https://op.example".into(),
            jwks_uri: "https://op.example/jwks".into(),
            authorization_endpoint: "https://op.example/authorize".into(),
            token_endpoint: "https://op.example/token".into(),
            registration_endpoint: None,
            scopes_supported: None,
            extra: HashMap::new(),
        };
        c.put("https://op.example".into(), doc);
        assert!(c.get("https://op.example").is_some());
    }

    #[test]
    fn config_cache_expires_after_ttl() {
        let c = OidcConfigCache::new(Duration::from_nanos(1));
        let doc = OidcDiscoveryDoc {
            issuer: "https://op.example".into(),
            jwks_uri: "https://op.example/jwks".into(),
            authorization_endpoint: "https://op.example/authorize".into(),
            token_endpoint: "https://op.example/token".into(),
            registration_endpoint: None,
            scopes_supported: None,
            extra: HashMap::new(),
        };
        c.put("https://op.example".into(), doc);
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get("https://op.example").is_none());
    }
}
