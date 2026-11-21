//! HTTP Signatures for ActivityPub federation.
//!
//! ActivityPub servers in the wild (Mastodon, Pleroma, Misskey,
//! GoToSocial) overwhelmingly use **draft-cavage-http-signatures-12**
//! with `rsa-sha256` as the signing algorithm. RFC 9421 is newer and
//! not yet widely deployed in the fediverse, so this module supports
//! both — verification auto-detects by header shape.
//!
//! Covered headers for AP:
//!   * `(request-target)` — method + path
//!   * `host`
//!   * `date`
//!   * `digest` — SHA-256 of body (inbound only; required for POST)
//!
//! References:
//!   * <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12>
//!   * <https://www.rfc-editor.org/rfc/rfc9421.html>
//!   * <https://docs.joinmastodon.org/spec/security/#http>

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::error::SigError;
use crate::ssrf::{resolve_ssrf_safe_with, SsrfGuard};

/// A raw inbound request awaiting signature verification.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub method: String,
    pub path: String,
    /// Lower-cased header name → value. Multi-valued headers are
    /// joined with ", " per RFC 7230 §3.2.2.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl SignedRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body,
        }
    }
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
        self
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// A request prepared for outbound delivery — signed headers to be
/// attached plus the body (unchanged).
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Verified actor — the keyId plus its fetched public-key PEM. Inbox
/// handlers use this to tie an activity to a known AP actor.
#[derive(Debug, Clone)]
pub struct VerifiedActor {
    pub key_id: String,
    pub actor_url: String,
    /// Delivery endpoint obtained from the verified actor document.
    pub inbox_url: Option<String>,
    pub public_key_pem: String,
}

/// Strategy for looking up an actor's public key from its `keyId`.
///
/// In production this is an HTTP fetch with cache (see
/// [`HttpActorKeyResolver`]); in tests it's a simple in-memory map.
#[async_trait]
pub trait ActorKeyResolver: Send + Sync {
    async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError>;

    /// Resolve again, bypassing any cache the resolver keeps, after a
    /// signature failed against the key [`Self::resolve`] gave (the actor may
    /// have rotated its key). A resolver that rate-limits this may return the
    /// same key. The default has no cache and simply resolves.
    async fn resolve_fresh(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        self.resolve(key_id).await
    }
}

/// How long a resolved actor key is reused before it is fetched again.
pub const KEY_CACHE_TTL: Duration = Duration::from_secs(300);

/// How long a failed key fetch is remembered, so a sender naming a dead or
/// hostile `keyId` over and over costs one fetch, not one per request.
pub const KEY_CACHE_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// Shortest time between two forced re-fetches of one key
/// ([`ActorKeyResolver::resolve_fresh`]); bounds the amplification a stream of
/// bad signatures under a valid `keyId` could otherwise cause.
pub const KEY_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Most keys (and failures) the resolver remembers; the oldest go first.
pub const KEY_CACHE_MAX_ENTRIES: usize = 1_024;

/// Cache sizes and lifetimes of an [`HttpActorKeyResolver`].
#[derive(Debug, Clone, Copy)]
pub struct KeyCachePolicy {
    /// Lifetime of a resolved key.
    pub ttl: Duration,
    /// Lifetime of a remembered failure.
    pub negative_ttl: Duration,
    /// Minimum gap between forced re-fetches of one key.
    pub min_refresh: Duration,
    /// Most entries kept.
    pub max_entries: usize,
}

impl Default for KeyCachePolicy {
    fn default() -> Self {
        Self {
            ttl: KEY_CACHE_TTL,
            negative_ttl: KEY_CACHE_NEGATIVE_TTL,
            min_refresh: KEY_REFRESH_MIN_INTERVAL,
            max_entries: KEY_CACHE_MAX_ENTRIES,
        }
    }
}

enum Cached {
    Key(VerifiedActor),
    Failed(String),
}

struct CacheEntry {
    value: Cached,
    fetched_at: std::time::Instant,
}

/// Largest actor document the resolver will read (bytes).
pub const MAX_ACTOR_DOC_BYTES: usize = 256 * 1024;

/// Whole-fetch time budget for an actor document.
pub const ACTOR_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP-backed resolver. Matches JSS's `fetchActor` behaviour: GET the
/// URL (with `#main-key` or similar fragment stripped), parse
/// `publicKey.publicKeyPem`.
///
/// Every fetch is attacker-reachable (the `keyId` of an unauthenticated
/// request names the host), so it is bounded: the address is checked and
/// pinned by an [`SsrfGuard`], redirects are not followed, the whole
/// exchange has a time limit and the body is read incrementally up to a
/// byte limit.
pub struct HttpActorKeyResolver {
    user_agent: String,
    guard: SsrfGuard,
    max_bytes: usize,
    timeout: Duration,
    policy: KeyCachePolicy,
    cache: std::sync::Mutex<std::collections::HashMap<String, CacheEntry>>,
}

impl Default for HttpActorKeyResolver {
    fn default() -> Self {
        Self {
            user_agent: "solid-pod-rs-activitypub/0.4.0".to_string(),
            guard: SsrfGuard::strict(),
            max_bytes: MAX_ACTOR_DOC_BYTES,
            timeout: ACTOR_FETCH_TIMEOUT,
            policy: KeyCachePolicy::default(),
            cache: std::sync::Mutex::default(),
        }
    }
}

impl HttpActorKeyResolver {
    /// A resolver with the strict guard and the default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the address guard (tests use
    /// `SsrfGuard::permit_loopback_for_tests` (feature `test-loopback`)).
    #[must_use]
    pub fn with_guard(mut self, guard: SsrfGuard) -> Self {
        self.guard = guard;
        self
    }

    /// Replace the body-size and whole-fetch time limits.
    #[must_use]
    pub fn with_limits(mut self, max_bytes: usize, timeout: Duration) -> Self {
        self.max_bytes = max_bytes;
        self.timeout = timeout;
        self
    }

    /// Replace the key-cache lifetimes and size.
    #[must_use]
    pub fn with_cache_policy(mut self, policy: KeyCachePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The cached outcome for `doc_url`, if it is still within its lifetime
    /// (or, when `force` is set, within the minimum re-fetch gap).
    fn cached(
        &self,
        doc_url: &str,
        key_id: &str,
        force: bool,
    ) -> Option<Result<VerifiedActor, SigError>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let e = cache.get(doc_url)?;
        let age = e.fetched_at.elapsed();
        let limit = match (&e.value, force) {
            (_, true) => self.policy.min_refresh,
            (Cached::Key(_), false) => self.policy.ttl,
            (Cached::Failed(_), false) => self.policy.negative_ttl,
        };
        if age >= limit {
            return None;
        }
        Some(match &e.value {
            Cached::Key(a) => Ok(VerifiedActor {
                key_id: key_id.to_string(),
                ..a.clone()
            }),
            Cached::Failed(m) => Err(SigError::ActorFetch(
                doc_url.to_string(),
                format!("recent failure: {m}"),
            )),
        })
    }

    fn remember(&self, doc_url: &str, outcome: &Result<VerifiedActor, SigError>) {
        let value = match outcome {
            Ok(a) => Cached::Key(a.clone()),
            Err(e) => Cached::Failed(e.to_string()),
        };
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= self.policy.max_entries && !cache.contains_key(doc_url) {
            let ttl = self.policy.ttl.max(self.policy.negative_ttl);
            cache.retain(|_, e| e.fetched_at.elapsed() < ttl);
            while cache.len() >= self.policy.max_entries {
                let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.fetched_at)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                cache.remove(&oldest);
            }
        }
        cache.insert(
            doc_url.to_string(),
            CacheEntry {
                value,
                fetched_at: std::time::Instant::now(),
            },
        );
    }

    /// Fetch and parse the JSON document at `url` under this resolver's
    /// guard and limits (also used to find a follow target's inbox).
    ///
    /// # Errors
    ///
    /// [`SigError::SsrfBlocked`] for a refused address,
    /// [`SigError::ActorFetch`] for any transport, status, size, time or
    /// parse failure.
    pub async fn fetch_document(&self, url: &str) -> Result<serde_json::Value, SigError> {
        let fail = |e: String| SigError::ActorFetch(url.to_string(), e);
        let (host, pinned) = resolve_ssrf_safe_with(url, self.guard).await?;
        let client = reqwest::Client::builder()
            // Never via an environment proxy: a proxy resolves and connects
            // itself, so the pinned address would not be the one used.
            .no_proxy()
            .user_agent(self.user_agent.clone())
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.timeout)
            .timeout(self.timeout)
            .resolve(&host, pinned)
            .build()
            .map_err(|e| fail(e.to_string()))?;
        let mut resp = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/activity+json")
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(fail(format!("status {}", resp.status())));
        }
        if resp
            .content_length()
            .is_some_and(|n| n > self.max_bytes as u64)
        {
            return Err(fail(format!(
                "document larger than {} bytes",
                self.max_bytes
            )));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| fail(e.to_string()))? {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(fail(format!(
                    "document larger than {} bytes",
                    self.max_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| fail(e.to_string()))
    }
}

#[async_trait]
impl ActorKeyResolver for HttpActorKeyResolver {
    /// The actor's key, from the cache when it is fresh (positive and negative
    /// results are both cached, keyed by the `keyId` document URL).
    async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        let doc_url = key_id.split('#').next().unwrap_or(key_id).to_string();
        if let Some(hit) = self.cached(&doc_url, key_id, false) {
            return hit;
        }
        let outcome = self.fetch_actor(key_id).await;
        self.remember(&doc_url, &outcome);
        outcome
    }

    /// Fetch the key again unless it was fetched within
    /// [`KeyCachePolicy::min_refresh`], in which case the cached outcome is
    /// returned unchanged.
    async fn resolve_fresh(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        let doc_url = key_id.split('#').next().unwrap_or(key_id).to_string();
        if let Some(hit) = self.cached(&doc_url, key_id, true) {
            return hit;
        }
        let outcome = self.fetch_actor(key_id).await;
        self.remember(&doc_url, &outcome);
        outcome
    }
}

impl HttpActorKeyResolver {
    async fn fetch_actor(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
        let actor_url = key_id
            .split_once('#')
            .map(|(u, _)| u.to_string())
            .unwrap_or_else(|| key_id.to_string());
        let doc = self.fetch_document(&actor_url).await?;
        let doc_url = actor_url.clone();
        // The actor's id is the document's `id`, which JSS-style actors give
        // with a fragment (`.../card.jsonld#me`) while the key is fetched
        // from the document URL. It is taken only when it names the very
        // document that was fetched; an `id` pointing anywhere else is
        // ignored, so a host can never present itself as another actor.
        let actor_url = match doc.get("id").and_then(|v| v.as_str()) {
            Some(id) if id.split('#').next() == Some(actor_url.as_str()) => id.to_string(),
            _ => actor_url,
        };
        let pem = doc
            .get("publicKey")
            .and_then(|k| k.get("publicKeyPem"))
            .and_then(|v| v.as_str())
            .ok_or(SigError::NoPublicKey)?;
        // The inbox we would deliver to: the shared inbox if there is one, else
        // the personal inbox. If either names another origin than the actor
        // document, that offending URL is reported instead, so the inbox
        // handler refuses a Follow from this actor (it cannot aim our
        // deliveries at a host it does not control).
        let shared = doc
            .get("endpoints")
            .and_then(|v| v.get("sharedInbox"))
            .and_then(|v| v.as_str());
        let personal = doc.get("inbox").and_then(|v| v.as_str());
        let inbox_url = [shared, personal]
            .into_iter()
            .flatten()
            .find(|u| !crate::inbox::same_origin(u, &doc_url))
            .or(shared.or(personal))
            .map(str::to_string);
        Ok(VerifiedActor {
            key_id: key_id.to_string(),
            actor_url,
            inbox_url,
            public_key_pem: pem.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Signature header parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct SignatureHeader {
    key_id: String,
    algorithm: String,
    headers: Vec<String>,
    signature_b64: String,
}

/// Parse a `Signature:` header in draft-cavage form:
/// `keyId="...",algorithm="...",headers="(request-target) host date digest",signature="..."`
fn parse_signature_header(raw: &str) -> Result<SignatureHeader, SigError> {
    let mut out = SignatureHeader::default();
    // Attribute parser — split on commas that are outside quoted values.
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut cur_key = String::new();
    let mut cur_val = String::new();
    let mut in_val = false;
    let mut in_quote = false;
    let mut expecting_eq = false;
    for ch in raw.chars() {
        if !in_val {
            match ch {
                '=' => {
                    in_val = true;
                    expecting_eq = false;
                }
                ',' | ' ' | '\t' if cur_key.is_empty() => { /* skip whitespace */ }
                c if c.is_ascii_whitespace() => {
                    expecting_eq = true;
                }
                _ if expecting_eq => {
                    // unexpected text after key with whitespace — part of next key
                    cur_key.push(ch);
                    expecting_eq = false;
                }
                _ => cur_key.push(ch),
            }
        } else {
            match ch {
                '"' => {
                    if in_quote {
                        // end of quoted value
                        attrs.push((
                            std::mem::take(&mut cur_key).to_ascii_lowercase(),
                            std::mem::take(&mut cur_val),
                        ));
                        in_quote = false;
                        in_val = false;
                    } else {
                        in_quote = true;
                    }
                }
                ',' if !in_quote => {
                    if !cur_key.is_empty() {
                        attrs.push((
                            std::mem::take(&mut cur_key).to_ascii_lowercase(),
                            std::mem::take(&mut cur_val),
                        ));
                    }
                    in_val = false;
                }
                _ => {
                    if in_quote || !ch.is_ascii_whitespace() {
                        cur_val.push(ch);
                    }
                }
            }
        }
    }
    if !cur_key.is_empty() && (in_val || !cur_val.is_empty()) {
        attrs.push((cur_key.to_ascii_lowercase(), cur_val));
    }

    for (k, v) in attrs {
        match k.as_str() {
            "keyid" => out.key_id = v,
            "algorithm" => out.algorithm = v.to_ascii_lowercase(),
            "headers" => {
                out.headers = v
                    .split_ascii_whitespace()
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
            }
            "signature" => out.signature_b64 = v,
            _ => {}
        }
    }
    if out.key_id.is_empty() {
        return Err(SigError::MissingKeyId);
    }
    if out.signature_b64.is_empty() {
        return Err(SigError::MalformedSignature(
            "missing signature= value".into(),
        ));
    }
    if out.algorithm.is_empty() {
        // Mastodon used to omit this — default to rsa-sha256 per
        // current AP fleet behaviour.
        out.algorithm = "rsa-sha256".to_string();
    }
    if out.headers.is_empty() {
        // Default per draft-cavage §2.1.6 — Date only. AP servers
        // should be stricter; we preserve the default for tolerance.
        out.headers = vec!["date".to_string()];
    }
    Ok(out)
}

/// Rebuild the signature base string for a draft-cavage `headers="..."`
/// list.
fn build_signature_base(req: &SignedRequest, header_list: &[String]) -> Result<String, SigError> {
    let mut lines = Vec::with_capacity(header_list.len());
    for h in header_list {
        match h.as_str() {
            "(request-target)" => {
                lines.push(format!(
                    "(request-target): {} {}",
                    req.method.to_ascii_lowercase(),
                    req.path
                ));
            }
            name => {
                let v = req.get(name).ok_or_else(|| {
                    SigError::VerifyFailed(format!("missing covered header: {name}"))
                })?;
                lines.push(format!("{name}: {v}"));
            }
        }
    }
    Ok(lines.join("\n"))
}

fn validate_covered_components(method: &str, headers: &[String]) -> Result<(), SigError> {
    let unique: std::collections::HashSet<&str> = headers.iter().map(String::as_str).collect();
    if unique.len() != headers.len() {
        return Err(SigError::MalformedSignature(
            "duplicate covered component".into(),
        ));
    }
    let mut required = vec!["(request-target)", "host", "date"];
    if method.eq_ignore_ascii_case("POST") {
        required.push("digest");
    }
    for component in required {
        if !unique.contains(component) {
            return Err(SigError::MalformedSignature(format!(
                "signature must cover {component}"
            )));
        }
    }
    Ok(())
}

/// Compute the canonical `Digest: SHA-256=...` header value for a body.
pub fn digest_header(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("SHA-256={}", B64.encode(digest))
}

/// Maximum age (in seconds) for the `Date` header — requests older
/// than this are rejected as potential replays.
const DATE_MAX_AGE_SECS: u64 = 300; // 5 minutes

/// Maximum clock skew into the future (in seconds) we tolerate.
const DATE_MAX_FUTURE_SECS: u64 = 30;

/// Validate that the `Date` header is within an acceptable freshness
/// window. Prevents replay attacks with captured old signatures.
fn check_date_freshness(date_str: &str) -> Result<(), SigError> {
    let parsed = httpdate::parse_http_date(date_str).map_err(|e| {
        SigError::DateNotFresh(format!("unparseable Date header '{}': {}", date_str, e))
    })?;
    let now = SystemTime::now();

    // Reject if the Date is too far in the past.
    if let Ok(age) = now.duration_since(parsed) {
        if age > Duration::from_secs(DATE_MAX_AGE_SECS) {
            return Err(SigError::DateNotFresh(format!(
                "Date '{}' is {} seconds old (max {})",
                date_str,
                age.as_secs(),
                DATE_MAX_AGE_SECS
            )));
        }
    }

    // Reject if the Date is too far in the future.
    if let Ok(ahead) = parsed.duration_since(now) {
        if ahead > Duration::from_secs(DATE_MAX_FUTURE_SECS) {
            return Err(SigError::DateNotFresh(format!(
                "Date '{}' is {} seconds in the future (max {})",
                date_str,
                ahead.as_secs(),
                DATE_MAX_FUTURE_SECS
            )));
        }
    }

    Ok(())
}

/// Verify an inbound signed request. Returns the [`VerifiedActor`] on
/// success so the caller can tie activity processing to the signing
/// identity.
pub async fn verify_request_signature(
    req: &SignedRequest,
    resolver: &dyn ActorKeyResolver,
) -> Result<VerifiedActor, SigError> {
    let sig_raw = req
        .get("signature")
        .ok_or(SigError::MissingHeader("signature"))?;
    let parsed = parse_signature_header(sig_raw)?;
    if parsed.algorithm != "rsa-sha256" && parsed.algorithm != "hs2019" {
        return Err(SigError::UnsupportedAlgorithm(parsed.algorithm));
    }
    validate_covered_components(&req.method, &parsed.headers)?;

    // P0-07: Date freshness check — reject stale or future-dated
    // requests to prevent replay attacks with captured signatures.
    if let Some(date_val) = req.get("date") {
        check_date_freshness(date_val)?;
    } else if parsed.headers.iter().any(|h| h == "date") {
        return Err(SigError::MissingHeader("date"));
    }

    // Digest check — if the covered set includes `digest`, the body
    // must hash to the header's value. This is mandatory for POST.
    if parsed.headers.iter().any(|h| h == "digest") {
        let received = req.get("digest").ok_or(SigError::MissingHeader("digest"))?;
        let computed = digest_header(&req.body);
        // Mastodon historically uses `SHA-256=...`; some servers use
        // the RFC 9530 `sha-256=:<b64>:` form. Tolerate both.
        if received != computed && !received.eq_ignore_ascii_case(&computed) {
            let rfc9530 = {
                let digest = Sha256::digest(&req.body);
                format!("sha-256=:{}:", B64.encode(digest))
            };
            if received != rfc9530 {
                return Err(SigError::DigestMismatch);
            }
        }
    }

    let base = build_signature_base(req, &parsed.headers)?;
    let sig_bytes = B64
        .decode(parsed.signature_b64.as_bytes())
        .map_err(|e| SigError::Base64(e.to_string()))?;
    let sig = RsaSignature::try_from(sig_bytes.as_slice())
        .map_err(|e| SigError::MalformedSignature(e.to_string()))?;
    let check = |actor: &VerifiedActor| -> Result<(), SigError> {
        let pub_key = RsaPublicKey::from_public_key_pem(&actor.public_key_pem)
            .map_err(|e| SigError::Rsa(e.to_string()))?;
        VerifyingKey::<Sha256>::new(pub_key)
            .verify(base.as_bytes(), &sig)
            .map_err(|e| SigError::VerifyFailed(e.to_string()))
    };

    let actor = resolver.resolve(&parsed.key_id).await?;
    match check(&actor) {
        Ok(()) => Ok(actor),
        // A cached key may be stale after a rotation: ask once for a fresh
        // one (the resolver rate-limits this) and accept only if it differs
        // from the key that just failed and verifies.
        Err(first @ (SigError::VerifyFailed(_) | SigError::Rsa(_))) => {
            let fresh = resolver.resolve_fresh(&parsed.key_id).await?;
            if fresh.public_key_pem == actor.public_key_pem {
                return Err(first);
            }
            check(&fresh)?;
            Ok(fresh)
        }
        Err(e) => Err(e),
    }
}

/// Sign an outbound AP delivery. The caller provides the pod's PEM
/// private key and its published `keyId` (e.g.
/// `https://pod.example/profile/card.jsonld#main-key`).
///
/// On return, `req.headers` carries `Host`, `Date`, `Digest` and
/// `Signature`.
pub fn sign_request(
    req: &mut OutboundRequest,
    private_key_pem: &str,
    key_id: &str,
) -> Result<(), SigError> {
    let url = url::Url::parse(&req.url).map_err(|e| SigError::Url(e.to_string()))?;
    // RFC 9110 section 7.2: the Host value carries the port unless it is the
    // scheme's default, and the verifier rebuilds the base from the header it
    // received, so the signed value must be exactly what is sent.
    let host = match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        (None, _) => return Err(SigError::Url("url has no host".into())),
    };
    let path = if let Some(q) = url.query() {
        format!("{}?{}", url.path(), q)
    } else {
        url.path().to_string()
    };
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let digest = digest_header(&req.body);

    // Covered headers and their values.
    let covered = vec!["(request-target)", "host", "date", "digest"];
    let mut base_lines: Vec<String> = Vec::new();
    for h in &covered {
        match *h {
            "(request-target)" => base_lines.push(format!(
                "(request-target): {} {}",
                req.method.to_ascii_lowercase(),
                path
            )),
            "host" => base_lines.push(format!("host: {host}")),
            "date" => base_lines.push(format!("date: {date}")),
            "digest" => base_lines.push(format!("digest: {digest}")),
            _ => {}
        }
    }
    let base = base_lines.join("\n");

    let sk =
        RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|e| SigError::Rsa(e.to_string()))?;
    let signer = SigningKey::<Sha256>::new(sk);
    let sig: RsaSignature = signer.sign(base.as_bytes());
    let sig_b64 = B64.encode(sig.to_bytes());

    let signature_header = format!(
        "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{headers}\",signature=\"{sig}\"",
        key_id = key_id,
        headers = covered.join(" "),
        sig = sig_b64,
    );

    // Append canonical headers — de-dup if already set.
    req.headers.retain(|(n, _)| {
        let ln = n.to_ascii_lowercase();
        ln != "host" && ln != "date" && ln != "digest" && ln != "signature"
    });
    req.headers.push(("Host".to_string(), host.to_string()));
    req.headers.push(("Date".to_string(), date));
    req.headers.push(("Digest".to_string(), digest));
    req.headers
        .push(("Signature".to_string(), signature_header));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct StaticResolver {
        pem: String,
    }

    #[async_trait]
    impl ActorKeyResolver for StaticResolver {
        async fn resolve(&self, key_id: &str) -> Result<VerifiedActor, SigError> {
            Ok(VerifiedActor {
                key_id: key_id.to_string(),
                actor_url: key_id.trim_end_matches("#main-key").to_string(),
                inbox_url: None,
                public_key_pem: self.pem.clone(),
            })
        }
    }

    fn fresh_keypair() -> (String, String) {
        crate::actor::generate_actor_keypair().unwrap()
    }

    fn build_signed_inbound(
        method: &str,
        path: &str,
        body: &[u8],
        priv_pem: &str,
        key_id: &str,
    ) -> SignedRequest {
        let host = "pod.example";
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let digest = digest_header(body);
        let base = format!(
            "(request-target): {} {}\nhost: {}\ndate: {}\ndigest: {}",
            method.to_ascii_lowercase(),
            path,
            host,
            date,
            digest
        );
        let sk = RsaPrivateKey::from_pkcs8_pem(priv_pem).unwrap();
        let signer = SigningKey::<Sha256>::new(sk);
        let sig: RsaSignature = signer.sign(base.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let sig_header = format!(
            "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{sig_b64}\""
        );

        SignedRequest::new(method, path, body.to_vec())
            .with_header("host", host)
            .with_header("date", date)
            .with_header("digest", digest)
            .with_header("signature", sig_header)
    }

    #[test]
    fn parse_signature_header_valid() {
        let raw = r#"keyId="https://a.example/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="ZmFrZQ==""#;
        let parsed = parse_signature_header(raw).unwrap();
        assert_eq!(parsed.key_id, "https://a.example/actor#main-key");
        assert_eq!(parsed.algorithm, "rsa-sha256");
        assert_eq!(
            parsed.headers,
            vec![
                "(request-target)".to_string(),
                "host".to_string(),
                "date".to_string(),
                "digest".to_string()
            ]
        );
        assert_eq!(parsed.signature_b64, "ZmFrZQ==");
    }

    #[test]
    fn parse_signature_header_rejects_missing_keyid() {
        let raw = r#"algorithm="rsa-sha256",signature="abc""#;
        assert!(matches!(
            parse_signature_header(raw),
            Err(SigError::MissingKeyId)
        ));
    }

    #[test]
    fn digest_header_is_mastodon_shape() {
        let d = digest_header(b"hello");
        assert!(d.starts_with("SHA-256="));
    }

    #[test]
    fn post_requires_every_security_critical_component() {
        let complete = ["(request-target)", "host", "date", "digest"];
        for omitted in complete {
            let covered = complete
                .iter()
                .filter(|component| **component != omitted)
                .map(|component| (*component).to_string())
                .collect::<Vec<_>>();
            assert!(
                validate_covered_components("POST", &covered).is_err(),
                "POST without {omitted} must be rejected"
            );
        }
    }

    #[test]
    fn duplicate_covered_components_are_rejected() {
        let covered = vec![
            "(request-target)".into(),
            "host".into(),
            "date".into(),
            "date".into(),
        ];
        assert!(validate_covered_components("GET", &covered).is_err());
    }

    #[tokio::test]
    async fn http_signature_verify_accepts_valid_request() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        let resolver = StaticResolver { pem: pub_pem };
        let actor = verify_request_signature(&req, &resolver).await.unwrap();
        assert_eq!(actor.key_id, key_id);
        assert_eq!(actor.actor_url, "https://remote.example/actor");
    }

    #[tokio::test]
    async fn http_signature_verify_rejects_tampered_body() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let mut req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        // Mutate body after signing → digest mismatch.
        req.body = b"{\"tampered\":true}".to_vec();
        let resolver = StaticResolver { pem: pub_pem };
        let res = verify_request_signature(&req, &resolver).await;
        assert!(matches!(res, Err(SigError::DigestMismatch)), "got {res:?}");
    }

    #[tokio::test]
    async fn http_signature_verify_rejects_wrong_key() {
        let (priv_pem, _pub_pem) = fresh_keypair();
        let (_, other_pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        let req = build_signed_inbound("POST", "/inbox", b"{}", &priv_pem, key_id);
        let resolver = StaticResolver { pem: other_pub_pem };
        let res = verify_request_signature(&req, &resolver).await;
        assert!(matches!(res, Err(SigError::VerifyFailed(_))));
    }

    #[tokio::test]
    async fn http_signature_verify_roundtrips_through_sign_request() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://pod.example/profile/card.jsonld#main-key";
        let body = br#"{"type":"Follow"}"#.to_vec();
        let mut out = OutboundRequest {
            method: "POST".into(),
            url: "https://remote.example/inbox".into(),
            headers: vec![("Content-Type".into(), "application/activity+json".into())],
            body: body.clone(),
        };
        sign_request(&mut out, &priv_pem, key_id).unwrap();

        // Convert to an inbound-shaped request and verify.
        let url = url::Url::parse(&out.url).unwrap();
        let path = url.path().to_string();
        let mut inbound = SignedRequest::new("POST", &path, body);
        for (k, v) in &out.headers {
            inbound.headers.insert(k.to_ascii_lowercase(), v.clone());
        }
        let resolver = StaticResolver { pem: pub_pem };
        let actor = verify_request_signature(&inbound, &resolver).await.unwrap();
        assert_eq!(actor.key_id, key_id);
    }

    // -- P0-07: Date freshness tests ----------------------------------------

    #[test]
    fn check_date_freshness_accepts_now() {
        let now = httpdate::fmt_http_date(SystemTime::now());
        assert!(check_date_freshness(&now).is_ok());
    }

    #[test]
    fn check_date_freshness_rejects_stale_date() {
        let old = SystemTime::now() - Duration::from_secs(600);
        let date = httpdate::fmt_http_date(old);
        let result = check_date_freshness(&date);
        assert!(
            matches!(result, Err(SigError::DateNotFresh(_))),
            "expected DateNotFresh for 10-minute-old Date, got {result:?}"
        );
    }

    #[test]
    fn check_date_freshness_rejects_future_date() {
        let future = SystemTime::now() + Duration::from_secs(120);
        let date = httpdate::fmt_http_date(future);
        let result = check_date_freshness(&date);
        assert!(
            matches!(result, Err(SigError::DateNotFresh(_))),
            "expected DateNotFresh for 2-minute-future Date, got {result:?}"
        );
    }

    #[test]
    fn check_date_freshness_accepts_slight_future() {
        // 10 seconds in the future should be accepted (within 30s window).
        let slight_future = SystemTime::now() + Duration::from_secs(10);
        let date = httpdate::fmt_http_date(slight_future);
        assert!(check_date_freshness(&date).is_ok());
    }

    #[test]
    fn check_date_freshness_rejects_garbage() {
        let result = check_date_freshness("not-a-date");
        assert!(
            matches!(result, Err(SigError::DateNotFresh(_))),
            "expected DateNotFresh for garbage date, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_stale_date_header() {
        let (priv_pem, pub_pem) = fresh_keypair();
        let key_id = "https://remote.example/actor#main-key";
        // Build a request with an old Date header (signed correctly).
        let host = "pod.example";
        let old_time = SystemTime::now() - Duration::from_secs(600);
        let date = httpdate::fmt_http_date(old_time);
        let body = b"{}";
        let digest = digest_header(body);
        let base = format!(
            "(request-target): post /inbox\nhost: {}\ndate: {}\ndigest: {}",
            host, date, digest
        );
        let sk = RsaPrivateKey::from_pkcs8_pem(&priv_pem).unwrap();
        let signer = SigningKey::<Sha256>::new(sk);
        let sig: RsaSignature = signer.sign(base.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let sig_header = format!(
            "keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\"{sig_b64}\""
        );
        let req = SignedRequest::new("POST", "/inbox", body.to_vec())
            .with_header("host", host)
            .with_header("date", &date)
            .with_header("digest", &digest)
            .with_header("signature", &sig_header);

        let resolver = StaticResolver { pem: pub_pem };
        let result = verify_request_signature(&req, &resolver).await;
        assert!(
            matches!(result, Err(SigError::DateNotFresh(_))),
            "expected DateNotFresh for stale request, got {result:?}"
        );
    }
}
