//! Interop / discovery helpers.
//!
//! This module rounds out the crate's public Solid surface with small,
//! framework-agnostic helpers for ecosystem discovery flows:
//!
//! - **`.well-known/solid`** — Solid Protocol §4.1.2 discovery document.
//! - **WebFinger** — RFC 7033, used to map acct: URIs to WebIDs.
//! - **NIP-05 verification** — Nostr pubkey ↔ DNS name binding.
//! - **Dev-mode session bypass** — consumer-crate helper for tests.
//!
//! None of these helpers perform network I/O on their own; they return
//! response bodies and signal objects that the consumer crate wires
//! into its HTTP server.

use serde::{Deserialize, Serialize};

use crate::error::PodError;

// ---------------------------------------------------------------------------
// .well-known/solid discovery document
// ---------------------------------------------------------------------------

/// Solid Protocol `.well-known/solid` discovery document. The doc
/// advertises the OIDC issuer, the pod URL, and the Notifications
/// endpoint. JSS parity: includes `api.accounts` URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidWellKnown {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,

    pub solid_oidc_issuer: String,

    pub notification_gateway: String,

    pub storage: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub webfinger: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<SolidWellKnownApi>,
}

/// JSS-compatible account management API pointers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidWellKnownApi {
    pub accounts: SolidWellKnownAccounts,
}

/// JSS-compatible account endpoint URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidWellKnownAccounts {
    pub new: String,
    pub recover: String,
    pub signin: String,
    pub signout: String,
}

/// Build the discovery document for a pod root.
pub fn well_known_solid(pod_base: &str, oidc_issuer: &str) -> SolidWellKnown {
    let base = pod_base.trim_end_matches('/');
    SolidWellKnown {
        context: serde_json::json!("https://www.w3.org/ns/solid/terms"),
        solid_oidc_issuer: oidc_issuer.trim_end_matches('/').to_string(),
        notification_gateway: format!("{base}/.notifications"),
        storage: format!("{base}/"),
        webfinger: Some(format!("{base}/.well-known/webfinger")),
        api: Some(SolidWellKnownApi {
            accounts: SolidWellKnownAccounts {
                new: format!("{base}/api/accounts/new"),
                recover: format!("{base}/api/accounts/recover"),
                signin: format!("{base}/login"),
                signout: format!("{base}/logout"),
            },
        }),
    }
}

// ---------------------------------------------------------------------------
// WebFinger (RFC 7033)
// ---------------------------------------------------------------------------

/// WebFinger JRD (JSON Resource Descriptor) response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFingerJrd {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<WebFingerLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFingerLink {
    pub rel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub content_type: Option<String>,
}

/// Produce a WebFinger JRD response pointing `acct:user@host` at the
/// user's WebID. Returns `None` if the resource is not recognised.
pub fn webfinger_response(resource: &str, pod_base: &str, webid: &str) -> Option<WebFingerJrd> {
    if !resource.starts_with("acct:") && !resource.starts_with("https://") {
        return None;
    }
    let base = pod_base.trim_end_matches('/');
    Some(WebFingerJrd {
        subject: resource.to_string(),
        aliases: vec![webid.to_string()],
        links: vec![
            WebFingerLink {
                rel: "http://openid.net/specs/connect/1.0/issuer".to_string(),
                href: Some(format!("{base}/")),
                content_type: None,
            },
            WebFingerLink {
                rel: "http://www.w3.org/ns/solid#webid".to_string(),
                href: Some(webid.to_string()),
                content_type: None,
            },
            WebFingerLink {
                rel: "http://www.w3.org/ns/pim/space#storage".to_string(),
                href: Some(format!("{base}/")),
                content_type: None,
            },
        ],
    })
}

// ---------------------------------------------------------------------------
// NIP-05 verification
// ---------------------------------------------------------------------------

/// NIP-05 response document (the JSON served at
/// `.well-known/nostr.json?name=<local>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip05Document {
    pub names: std::collections::HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relays: Option<std::collections::HashMap<String, Vec<String>>>,
}

/// Verify a NIP-05 identifier (`local@example.com`) against a fetched
/// NIP-05 document. Returns the resolved hex pubkey on success.
pub fn verify_nip05(identifier: &str, document: &Nip05Document) -> Result<String, PodError> {
    let (local, _domain) = identifier
        .split_once('@')
        .ok_or_else(|| PodError::Nip98(format!("invalid NIP-05 identifier: {identifier}")))?;
    let lookup = if local.is_empty() { "_" } else { local };
    let pubkey = document
        .names
        .get(lookup)
        .ok_or_else(|| PodError::NotFound(format!("NIP-05 name not found: {lookup}")))?;
    if pubkey.len() != 64 || hex::decode(pubkey).is_err() {
        return Err(PodError::Nip98(format!(
            "NIP-05 pubkey malformed for {identifier}"
        )));
    }
    Ok(pubkey.clone())
}

/// Build the NIP-05 document structure for a pod's own hosted names.
pub fn nip05_document(names: impl IntoIterator<Item = (String, String)>) -> Nip05Document {
    Nip05Document {
        names: names.into_iter().collect(),
        relays: None,
    }
}

// ---------------------------------------------------------------------------
// Dev-mode session bypass
// ---------------------------------------------------------------------------

/// Dev-mode session — ergonomic handle a consumer crate can plug into
/// its request-processing pipeline in place of NIP-98/OIDC verification
/// during tests or local development. The bypass is only constructable
/// via explicit allow, never through a header the client supplies.
#[derive(Debug, Clone)]
pub struct DevSession {
    pub webid: String,
    pub pubkey: Option<String>,
    pub is_admin: bool,
}

/// Build a dev-session bypass. Callers are expected to gate this on a
/// top-level `ENABLE_DEV_SESSION=1` or similar environment check —
/// the helper itself will not read env to avoid accidental activation.
pub fn dev_session(webid: impl Into<String>, is_admin: bool) -> DevSession {
    DevSession {
        webid: webid.into(),
        pubkey: None,
        is_admin,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// These unit tests sit next to the interop functions they cover; the
// did:nostr resolver and NodeInfo surfaces below were appended later. When
// `did-nostr` is cfg'd out (e.g. the oidc/s3 CI feature cells) this becomes a
// test module followed by items, which is intentional here.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_solid_advertises_oidc_and_storage() {
        let d = well_known_solid("https://pod.example/", "https://op.example/");
        assert_eq!(d.solid_oidc_issuer, "https://op.example");
        assert!(d.notification_gateway.ends_with(".notifications"));
        assert!(d.storage.ends_with('/'));
    }

    #[test]
    fn webfinger_returns_links_for_acct() {
        let j = webfinger_response(
            "acct:alice@pod.example",
            "https://pod.example",
            "https://pod.example/profile/card#me",
        )
        .unwrap();
        assert_eq!(j.subject, "acct:alice@pod.example");
        assert!(j
            .links
            .iter()
            .any(|l| l.rel == "http://www.w3.org/ns/solid#webid"));
    }

    #[test]
    fn webfinger_rejects_unknown_scheme() {
        assert!(webfinger_response("mailto:a@b", "https://p", "https://w").is_none());
    }

    #[test]
    fn nip05_verify_returns_pubkey() {
        let mut names = std::collections::HashMap::new();
        names.insert("alice".to_string(), "a".repeat(64));
        let doc = nip05_document(names);
        let pk = verify_nip05("alice@pod.example", &doc).unwrap();
        assert_eq!(pk, "a".repeat(64));
    }

    #[test]
    fn nip05_verify_rejects_malformed_pubkey() {
        let mut names = std::collections::HashMap::new();
        names.insert("alice".to_string(), "shortkey".to_string());
        let doc = nip05_document(names);
        assert!(verify_nip05("alice@p", &doc).is_err());
    }

    #[test]
    fn nip05_root_name_resolves_via_underscore() {
        let mut names = std::collections::HashMap::new();
        names.insert("_".to_string(), "b".repeat(64));
        let doc = nip05_document(names);
        assert!(verify_nip05("@pod.example", &doc).is_ok());
    }

    #[test]
    fn dev_session_stores_admin_flag() {
        let s = dev_session("https://me/profile#me", true);
        assert!(s.is_admin);
        assert_eq!(s.webid, "https://me/profile#me");
    }
}

// ---------------------------------------------------------------------------
// did:nostr resolver (Sprint 6 D)
// ---------------------------------------------------------------------------

/// did:nostr resolver — DID-Doc publication + bidirectional
/// `alsoKnownAs`/`owl:sameAs` verification.
///
/// Mirrors `JavaScriptSolidServer/src/auth/did-nostr.js`: given
/// `did:nostr:<pubkey>` hosted on an origin, fetch
/// `https://<origin>/.well-known/did/nostr/<pubkey>.json`, iterate the
/// `alsoKnownAs` entries, fetch each candidate WebID profile, and
/// verify it carries an `owl:sameAs` / `schema:sameAs` back-link to
/// `did:nostr:<pubkey>`. Only a verified WebID is returned.
///
/// Defence-in-depth: every outbound request (DID Doc + each WebID
/// candidate) runs through the configured [`SsrfPolicy`](crate::security::ssrf::SsrfPolicy) before
/// network I/O. A small in-memory TTL cache covers both success and
/// negative results so a dark origin does not hammer the downstream.
#[cfg(feature = "did-nostr")]
pub mod did_nostr {
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use url::Url;

    use crate::security::ssrf::SsrfPolicy;

    /// Compose the well-known DID Doc location for a Nostr pubkey
    /// hosted on a given origin. Mirrors JSS `did-nostr.js:79` where
    /// the resolver URL is `<base>/<pubkey>.json`.
    pub fn did_nostr_well_known_url(origin: &str, pubkey: &str) -> String {
        format!(
            "{}/.well-known/did/nostr/{}.json",
            origin.trim_end_matches('/'),
            pubkey
        )
    }

    /// Build the canonical `did:nostr` DID Doc for publication at the
    /// well-known URL (ADR-125 — supersedes ADR-074 §D2/§D3/§D4/§D13).
    ///
    /// The single published form: `@context`
    /// `["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1",
    /// "https://w3id.org/nostr/context"]` (did:nostr CG 0.1.1 — DID Core
    /// context first, as DID Core requires),
    /// top-level `type: "DIDNostr"`, a single `Multikey` verification method
    /// with `publicKeyMultibase: "fe70102<hex>"`, fragment `#key1`. Optional
    /// members are omitted when empty (no `service: []`), per the did:nostr CG
    /// spec (<https://nostrcg.github.io/did-nostr/>). The 2019 suite +
    /// `publicKeyHex` + `z`-base58 multibase are dropped. No dual-publish.
    ///
    /// Built from the hex identifier alone, so the parity byte is `02` (the
    /// even-y lift every resolver computes). A controller publishing from its
    /// full key may carry `03` instead — see
    /// `did_nostr_types::render_did_document_published` (nostrcg/did-nostr#145).
    ///
    /// `also_known_as` is surfaced as a top-level `alsoKnownAs` link when
    /// non-empty — the spec's canonical location for cross-platform identity
    /// (WebID / ActivityPub / AT-proto).
    ///
    /// NOTE: The canonical DID:nostr types (including `NostrPubkey`,
    /// `render_did_document`, `render_did_document_tier3`) live in
    /// [`crate::did_nostr_types`] (feature `did-nostr-types`). This
    /// convenience wrapper accepts a raw hex string and merges
    /// `also_known_as` into the canonical skeleton. New code should prefer
    /// the canonical types directly.
    pub fn did_nostr_document(pubkey: &str, also_known_as: &[String]) -> serde_json::Value {
        // Delegate to the canonical renderer when the pubkey parses cleanly;
        // fall back to inline JSON for malformed input (preserves
        // backward-compat — callers never saw an error here).
        #[cfg(feature = "did-nostr-types")]
        if let Ok(pk) = crate::did_nostr_types::NostrPubkey::from_hex(pubkey) {
            let mut doc = crate::did_nostr_types::render_did_document(&pk);
            if !also_known_as.is_empty() {
                doc["alsoKnownAs"] = serde_json::json!(also_known_as);
            }
            return doc;
        }

        // Fallback for malformed hex (D-1 fix, ADR-124 §7 / I2).
        //
        // A malformed pubkey cannot produce the `fe70102` framing, so we must
        // NEVER emit a `Multikey` verification method without its
        // `publicKeyMultibase` — a keyless `Multikey` is an I2 violation (the
        // VM would advertise a key type it cannot back). The signature is
        // infallible by contract (callers never saw an error here), so instead
        // of erroring we emit the canonical envelope with an EMPTY
        // `verificationMethod` (and, in lockstep, empty `authentication` /
        // `assertionMethod`, since `#key1` no longer resolves). The
        // `did:nostr:<pubkey>` body and the canonical context/type are
        // preserved verbatim. Well-formed input always takes the delegating
        // branch above and carries the full `Multikey` VM.
        let did = format!("did:nostr:{pubkey}");
        let mut doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://www.w3.org/ns/cid/v1",
                "https://w3id.org/nostr/context"
            ],
            "id": did,
            "type": "DIDNostr",
            "verificationMethod": [],
            "authentication": [],
            "assertionMethod": []
        });
        if !also_known_as.is_empty() {
            doc["alsoKnownAs"] = serde_json::json!(also_known_as);
        }
        doc
    }

    /// Parsed DID Doc. Only the subset of fields relevant to WebID
    /// resolution is typed; unknown fields are ignored.
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct DidNostrDoc {
        pub id: String,
        #[serde(default, rename = "alsoKnownAs")]
        pub also_known_as: Vec<String>,
    }

    /// TTL-cached `did:nostr:<pubkey>` → WebID resolver with per-hop
    /// SSRF enforcement.
    pub struct DidNostrResolver {
        ssrf: Arc<SsrfPolicy>,
        client: Client,
        cache: Arc<RwLock<HashMap<String, CachedEntry>>>,
        success_ttl: Duration,
        failure_ttl: Duration,
    }

    struct CachedEntry {
        fetched: Instant,
        web_id: Option<String>,
    }

    impl DidNostrResolver {
        /// Construct a resolver with the default HTTP client (10 s
        /// timeout) and TTLs matching JSS (5 min success, 1 min
        /// failure).
        pub fn new(ssrf: Arc<SsrfPolicy>) -> Self {
            // Redirects are refused: the SSRF check runs on the URL we
            // were given, and following a 30x would reach a host it never
            // vetted (JSS re-checks each hop and refuses cross-origin
            // redirects, `fetchWithRedirectGuard`).
            let client = Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new());
            Self {
                ssrf,
                client,
                cache: Arc::new(RwLock::new(HashMap::new())),
                success_ttl: Duration::from_secs(300),
                failure_ttl: Duration::from_secs(60),
            }
        }

        /// Override the default success / failure cache TTLs.
        pub fn with_ttls(mut self, success: Duration, failure: Duration) -> Self {
            self.success_ttl = success;
            self.failure_ttl = failure;
            self
        }

        /// Resolve `did:nostr:<pubkey>` against `origin` to a verified
        /// WebID. Returns `None` if:
        ///
        /// - SSRF policy denies the origin or any WebID candidate.
        /// - DID Doc fetch fails or the doc's `id` does not match
        ///   `did:nostr:<pubkey>`.
        /// - `alsoKnownAs` is empty.
        /// - No candidate WebID carries a back-link (`owl:sameAs` or
        ///   `schema:sameAs`) to the same `did:nostr:<pubkey>`.
        ///
        /// Both success and failure are cached; subsequent calls
        /// within the matching TTL are served from memory without
        /// network I/O.
        pub async fn resolve(&self, origin: &str, pubkey: &str) -> Option<String> {
            // The pubkey comes off a NIP-98 event and is interpolated into a
            // URL path and the cache key: enforce 64 hex characters (JSS
            // `resolveDidNostrToWebId` does the same) and lowercase it.
            if pubkey.len() != 64 || !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let pubkey = pubkey.to_ascii_lowercase();
            let pubkey = pubkey.as_str();
            let cache_key = format!("{origin}|{pubkey}");

            // Cache lookup (read lock).
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(&cache_key) {
                    let ttl = if entry.web_id.is_some() {
                        self.success_ttl
                    } else {
                        self.failure_ttl
                    };
                    if entry.fetched.elapsed() < ttl {
                        return entry.web_id.clone();
                    }
                }
            }

            let result =
                tokio::time::timeout(RESOLVE_DEADLINE, self.resolve_uncached(origin, pubkey))
                    .await
                    .unwrap_or(None);

            if let Ok(mut guard) = self.cache.write() {
                // Bounded like JSS (10k entries): pubkeys are attacker
                // supplied, so evict the oldest entry rather than grow.
                if guard.len() >= MAX_CACHE_ENTRIES {
                    if let Some(oldest) = guard
                        .iter()
                        .min_by_key(|(_, e)| e.fetched)
                        .map(|(k, _)| k.clone())
                    {
                        guard.remove(&oldest);
                    }
                }
                guard.insert(
                    cache_key,
                    CachedEntry {
                        fetched: Instant::now(),
                        web_id: result.clone(),
                    },
                );
            }

            result
        }

        /// A client that connects `url`'s host to `ip`, the address the SSRF
        /// policy approved, instead of resolving the name again (closes the
        /// DNS-rebinding window between check and connect). IP-literal hosts
        /// need no pin. Redirects stay off and the timeout is kept.
        fn pinned_client(&self, url: &Url, ip: std::net::IpAddr) -> Client {
            let Some(url::Host::Domain(host)) = url.host() else {
                return self.client.clone();
            };
            let port = url.port_or_known_default().unwrap_or(80);
            Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .resolve(host, std::net::SocketAddr::new(ip, port))
                .build()
                .unwrap_or_else(|_| self.client.clone())
        }

        async fn resolve_uncached(&self, origin: &str, pubkey: &str) -> Option<String> {
            // 1. SSRF check on origin.
            let origin_url = Url::parse(origin).ok()?;
            let origin_ip = self.ssrf.resolve_and_check(&origin_url).await.ok()?;

            // 2. Fetch DID Doc, connecting to the address the SSRF check
            // vetted (a second DNS lookup could answer differently).
            let url = did_nostr_well_known_url(origin, pubkey);
            let resp = self
                .pinned_client(&origin_url, origin_ip)
                .get(&url)
                .header("accept", "application/did+json, application/json")
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?;
            let doc: DidNostrDoc = serde_json::from_slice(&read_capped(resp).await?).ok()?;

            if doc.id != format!("did:nostr:{pubkey}") {
                return None;
            }

            // 3. Iterate candidates; return the first verified WebID.
            let did_iri = format!("did:nostr:{pubkey}");
            // The list comes from a remote document: bound the fetches.
            for candidate in doc.also_known_as.iter().take(MAX_CANDIDATES) {
                if let Some(web_id) = self.try_candidate(candidate, &did_iri).await {
                    return Some(web_id);
                }
            }
            None
        }

        async fn try_candidate(&self, candidate: &str, did_iri: &str) -> Option<String> {
            let url = Url::parse(candidate).ok()?;
            let ip = self.ssrf.resolve_and_check(&url).await.ok()?;
            let resp = self
                .pinned_client(&url, ip)
                .get(url.as_str())
                .header("accept", "text/turtle, application/ld+json")
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?;
            let body = read_capped(resp).await?;

            // Back-link check: the profile must itself assert, as a real
            // statement about the candidate WebID, an `owl:sameAs` /
            // `schema:sameAs` to this DID. A document that merely mentions
            // the DID somewhere does not count (one-way links are never
            // accepted).
            if backlink_present(&body, candidate, did_iri) {
                Some(candidate.to_string())
            } else {
                None
            }
        }
    }

    /// Most `alsoKnownAs` entries one resolution will fetch.
    pub const MAX_CANDIDATES: usize = 4;
    /// Wall-clock budget for one whole resolution (document plus candidates).
    const RESOLVE_DEADLINE: Duration = Duration::from_secs(15);
    /// Largest DID document / WebID profile body the resolver reads.
    const MAX_DOC_BYTES: usize = 512 * 1024;
    /// Resolver cache bound (JSS `CACHE_MAX_ENTRIES`).
    const MAX_CACHE_ENTRIES: usize = 10_000;

    const SAME_AS_IRIS: [&str; 4] = [
        "http://www.w3.org/2002/07/owl#sameAs",
        "https://schema.org/sameAs",
        "http://schema.org/sameAs",
        "https://schema.org/sameAs/",
    ];
    const SAME_AS_KEYS: [&str; 7] = [
        "owl:sameAs",
        "schema:sameAs",
        "sameAs",
        "http://www.w3.org/2002/07/owl#sameAs",
        "https://schema.org/sameAs",
        "http://schema.org/sameAs",
        "https://schema.org/sameAs/",
    ];

    async fn read_capped(mut resp: reqwest::Response) -> Option<Vec<u8>> {
        if resp
            .content_length()
            .is_some_and(|n| n as usize > MAX_DOC_BYTES)
        {
            return None;
        }
        let mut out = Vec::new();
        while let Some(chunk) = resp.chunk().await.ok()? {
            if out.len() + chunk.len() > MAX_DOC_BYTES {
                return None;
            }
            out.extend_from_slice(&chunk);
        }
        Some(out)
    }

    /// True when `body` (JSON-LD or Turtle) asserts
    /// `<candidate> owl:sameAs|schema:sameAs <did_iri>`.
    ///
    /// Exposed for tests; the resolver calls it with the fetched profile.
    pub fn backlink_present(body: &[u8], candidate: &str, did_iri: &str) -> bool {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            return json_backlink(&v, candidate, did_iri);
        }
        let doc_base = candidate.split('#').next().unwrap_or(candidate);
        match crate::rdf_input::parse_turtle(body, doc_base) {
            Ok(g) => g.triples().any(|t| {
                matches!(&t.subject, crate::ldp::Term::Iri(s) if s == candidate)
                    && matches!(&t.predicate, crate::ldp::Term::Iri(p) if SAME_AS_IRIS.contains(&p.as_str()))
                    && matches!(&t.object, crate::ldp::Term::Iri(o) if o == did_iri)
            }),
            Err(_) => false,
        }
    }

    fn json_backlink(v: &serde_json::Value, candidate: &str, did_iri: &str) -> bool {
        use serde_json::Value;
        let base = Url::parse(candidate).ok();
        let resolve = |id: &str| -> String {
            base.as_ref()
                .and_then(|b| b.join(id).ok())
                .map(|u| u.to_string())
                .unwrap_or_else(|| id.to_string())
        };
        let is_did = |x: &Value| match x {
            Value::String(s) => s == did_iri,
            Value::Object(m) => m.get("@id").and_then(Value::as_str) == Some(did_iri),
            _ => false,
        };
        fn walk(
            v: &Value,
            depth: usize,
            visit: &mut dyn FnMut(&serde_json::Map<String, Value>) -> bool,
        ) -> bool {
            if depth > 16 {
                return false;
            }
            match v {
                Value::Object(m) => visit(m) || m.values().any(|c| walk(c, depth + 1, visit)),
                Value::Array(a) => a.iter().any(|c| walk(c, depth + 1, visit)),
                _ => false,
            }
        }
        walk(v, 0, &mut |m| {
            let id = m.get("@id").or_else(|| m.get("id")).and_then(Value::as_str);
            let Some(id) = id else { return false };
            if resolve(id) != candidate {
                return false;
            }
            SAME_AS_KEYS.iter().any(|k| match m.get(*k) {
                Some(Value::Array(a)) => a.iter().any(is_did),
                Some(x) => is_did(x),
                None => false,
            })
        })
    }

    #[cfg(test)]
    mod pin_tests {
        use super::*;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// A hostname that cannot resolve is reachable only through the pin:
        /// proves the client connects to the vetted IP, not a fresh lookup.
        #[tokio::test]
        async fn pinned_client_connects_to_the_vetted_address() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;
            let port = server.address().port();
            let url = Url::parse(&format!("http://rebind.invalid:{port}/x")).unwrap();
            let r = DidNostrResolver::new(Arc::new(SsrfPolicy::new()));
            let unpinned = r.client.get(url.as_str()).send().await;
            assert!(unpinned.is_err(), "the name must not resolve by itself");
            let ok = r
                .pinned_client(&url, "127.0.0.1".parse().unwrap())
                .get(url.as_str())
                .send()
                .await
                .expect("pinned request reaches the vetted address");
            assert_eq!(ok.status(), 200);
        }
    }
}

// ---------------------------------------------------------------------------
// NodeInfo 2.1 (Sprint 7 C)
// ---------------------------------------------------------------------------

/// `/.well-known/nodeinfo` discovery document (JSON), per
/// nodeinfo.diaspora.software §6. Points clients at one or more
/// versioned NodeInfo docs.
pub fn nodeinfo_discovery(base_url: &str) -> serde_json::Value {
    serde_json::json!({
        "links": [
            {
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                "href": format!(
                    "{}/.well-known/nodeinfo/2.1",
                    base_url.trim_end_matches('/')
                )
            }
        ]
    })
}

/// `/.well-known/nodeinfo/2.1` content document, per
/// nodeinfo.diaspora.software §3 (schema 2.1).
pub fn nodeinfo_2_1(
    software_name: &str,
    software_version: &str,
    open_registrations: bool,
    total_users: u64,
) -> serde_json::Value {
    serde_json::json!({
        "version": "2.1",
        "software": {
            "name": software_name,
            "version": software_version,
            "repository": "https://github.com/dreamlab-ai/solid-pod-rs",
            "homepage": "https://github.com/dreamlab-ai/solid-pod-rs"
        },
        "protocols": ["solid", "activitypub"],
        "services": {
            "inbound": [],
            "outbound": []
        },
        "openRegistrations": open_registrations,
        "usage": {
            "users": {
                "total": total_users
            }
        },
        "metadata": {}
    })
}
