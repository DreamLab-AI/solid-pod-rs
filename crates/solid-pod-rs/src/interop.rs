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
/// endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidWellKnown {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,

    pub solid_oidc_issuer: String,

    pub notification_gateway: String,

    pub storage: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub webfinger: Option<String>,
}

/// Build the discovery document for a pod root.
pub fn well_known_solid(
    pod_base: &str,
    oidc_issuer: &str,
) -> SolidWellKnown {
    let base = pod_base.trim_end_matches('/');
    SolidWellKnown {
        context: serde_json::json!("https://www.w3.org/ns/solid/terms"),
        solid_oidc_issuer: oidc_issuer.trim_end_matches('/').to_string(),
        notification_gateway: format!("{base}/.notifications"),
        storage: format!("{base}/"),
        webfinger: Some(format!("{base}/.well-known/webfinger")),
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
pub fn webfinger_response(
    resource: &str,
    pod_base: &str,
    webid: &str,
) -> Option<WebFingerJrd> {
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
pub fn verify_nip05(
    identifier: &str,
    document: &Nip05Document,
) -> Result<String, PodError> {
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
pub fn nip05_document(
    names: impl IntoIterator<Item = (String, String)>,
) -> Nip05Document {
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
        assert!(j.links.iter().any(|l| l.rel == "http://www.w3.org/ns/solid#webid"));
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
/// candidate) runs through the configured [`SsrfPolicy`] before
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

    /// Build a minimal DID Doc for publication at the well-known URL.
    /// Tier-1 schema (matches JSS): `id`, `alsoKnownAs`, and a single
    /// `verificationMethod` entry of type `NostrSchnorrKey2024` derived
    /// from the x-only pubkey.
    pub fn did_nostr_document(pubkey: &str, also_known_as: &[String]) -> serde_json::Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": format!("did:nostr:{}", pubkey),
            "alsoKnownAs": also_known_as,
            "verificationMethod": [{
                "id": format!("did:nostr:{}#nostr-schnorr", pubkey),
                "type": "NostrSchnorrKey2024",
                "controller": format!("did:nostr:{}", pubkey),
                "publicKeyHex": pubkey,
            }]
        })
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
            let client = Client::builder()
                .timeout(Duration::from_secs(10))
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

            let result = self.resolve_uncached(origin, pubkey).await;

            if let Ok(mut guard) = self.cache.write() {
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

        async fn resolve_uncached(&self, origin: &str, pubkey: &str) -> Option<String> {
            // 1. SSRF check on origin.
            let origin_url = Url::parse(origin).ok()?;
            self.ssrf.resolve_and_check(&origin_url).await.ok()?;

            // 2. Fetch DID Doc.
            let url = did_nostr_well_known_url(origin, pubkey);
            let resp = self
                .client
                .get(&url)
                .header("accept", "application/did+json, application/json")
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?;
            let doc: DidNostrDoc = resp.json().await.ok()?;

            if doc.id != format!("did:nostr:{pubkey}") {
                return None;
            }

            // 3. Iterate candidates; return the first verified WebID.
            let did_iri = format!("did:nostr:{pubkey}");
            for candidate in &doc.also_known_as {
                if let Some(web_id) = self.try_candidate(candidate, &did_iri).await {
                    return Some(web_id);
                }
            }
            None
        }

        async fn try_candidate(&self, candidate: &str, did_iri: &str) -> Option<String> {
            let url = Url::parse(candidate).ok()?;
            self.ssrf.resolve_and_check(&url).await.ok()?;
            let resp = self
                .client
                .get(url.as_str())
                .header("accept", "text/turtle, application/ld+json")
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?;
            let body = resp.text().await.ok()?;

            // Back-link check — literal string match suffices for the
            // bidirectional guarantee because the DID IRI is by spec a
            // verbatim literal (no relativisation in either RDF flavour).
            let has_predicate = body.contains("owl:sameAs")
                || body.contains("schema:sameAs")
                || body.contains("http://www.w3.org/2002/07/owl#sameAs")
                || body.contains("https://schema.org/sameAs");
            if has_predicate && body.contains(did_iri) {
                Some(candidate.to_string())
            } else {
                None
            }
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
