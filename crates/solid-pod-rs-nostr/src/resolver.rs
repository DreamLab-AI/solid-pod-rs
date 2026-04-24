//! `did:nostr` ↔ WebID bidirectional resolver.
//!
//! Two directions are supported:
//!
//! - **WebID → did:nostr** ([`NostrWebIdResolver::resolve_webid_to_nostr`]):
//!   Fetch the WebID profile (JSON-LD / Turtle / HTML + JSON-LD island)
//!   and look for an `alsoKnownAs`, `sameAs`, or `owl:sameAs` pointing
//!   at a `did:nostr:<hex>` URI. Returns the first match.
//!
//! - **did:nostr → WebID** ([`NostrWebIdResolver::resolve_nostr_to_webid`]):
//!   Fetch the DID document at `<origin>/.well-known/did/nostr/<hex>.json`
//!   and return the first HTTP(S) `alsoKnownAs` entry.
//!
//! Both methods run the target URL through an [`SsrfCheck`] before any
//! outbound request, so default deployments refuse RFC 1918, loopback,
//! link-local, multicast, and cloud-metadata targets.
//!
//! Upstream parity: `JavaScriptSolidServer/src/auth/did-nostr.js` (WebID
//! → did:nostr direction, `alsoKnownAs` carrier) and
//! `JavaScriptSolidServer/src/did/resolver.js` (DID Doc publication).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::did::NostrPubkey;
use crate::error::ResolverError;

/// SSRF injection point — consumers pass their operator policy.
#[async_trait]
pub trait SsrfCheck: Send + Sync {
    /// Verify that the supplied `host` (bare hostname or `host:port`)
    /// resolves to an address permitted by the policy. Returns
    /// `Ok(())` on permit, or an error message on refuse.
    async fn verify_host(&self, host: &str) -> Result<(), String>;
}

/// Default SSRF check delegating to `solid_pod_rs::security::ssrf`.
///
/// Uses the restrictive defaults (no toggles, no lists) — identical to
/// the upstream library behaviour for `verifyHost` in JSS.
pub struct DefaultSsrfCheck;

#[async_trait]
impl SsrfCheck for DefaultSsrfCheck {
    async fn verify_host(&self, host: &str) -> Result<(), String> {
        solid_pod_rs::security::ssrf::resolve_and_check(host)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// A `did:nostr` ↔ WebID resolver.
///
/// The resolver is cheap to clone (internally `Arc`-shared); construct
/// once at startup and share across request handlers.
#[derive(Clone)]
pub struct NostrWebIdResolver {
    http: Client,
    ssrf: Arc<dyn SsrfCheck>,
}

impl NostrWebIdResolver {
    /// Build with the default SSRF guard and a 10 s HTTP timeout.
    pub fn new() -> Self {
        Self::with_ssrf(Arc::new(DefaultSsrfCheck))
    }

    /// Build with a custom SSRF guard.
    pub fn with_ssrf(ssrf: Arc<dyn SsrfCheck>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { http, ssrf }
    }

    /// Build with a custom HTTP client (test injection).
    pub fn with_http(http: Client, ssrf: Arc<dyn SsrfCheck>) -> Self {
        Self { http, ssrf }
    }

    /// Resolve a WebID URL to a `did:nostr` pubkey by inspecting the
    /// profile's `alsoKnownAs` / `sameAs` fields.
    ///
    /// Returns `Ok(None)` when the profile fetches successfully but
    /// contains no usable linkage.
    pub async fn resolve_webid_to_nostr(
        &self,
        webid: &str,
    ) -> Result<Option<NostrPubkey>, ResolverError> {
        let url = Url::parse(webid).map_err(|e| ResolverError::InvalidUrl(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| ResolverError::InvalidUrl("missing host".into()))?
            .to_string();
        self.ssrf
            .verify_host(&host)
            .await
            .map_err(ResolverError::Ssrf)?;

        let resp = self
            .http
            .get(url.as_str())
            .header("accept", "application/ld+json, application/json, text/turtle, text/html")
            .send()
            .await
            .map_err(|e| ResolverError::Http(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ResolverError::Http(format!("webid profile status {status}")));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp
            .text()
            .await
            .map_err(|e| ResolverError::Http(e.to_string()))?;

        Ok(extract_nostr_pubkey_from_profile(&body, &content_type))
    }

    /// Resolve a `did:nostr:<hex>` → WebID by fetching the DID document
    /// at `<origin>/.well-known/did/nostr/<hex>.json` and returning the
    /// first `alsoKnownAs` entry that is an HTTP(S) URL.
    pub async fn resolve_nostr_to_webid(
        &self,
        origin: &str,
        pk: &NostrPubkey,
    ) -> Result<Option<String>, ResolverError> {
        let doc_url = format!(
            "{}{}",
            origin.trim_end_matches('/'),
            crate::did::well_known_path(pk)
        );
        let parsed =
            Url::parse(&doc_url).map_err(|e| ResolverError::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| ResolverError::InvalidUrl("missing host".into()))?
            .to_string();
        self.ssrf
            .verify_host(&host)
            .await
            .map_err(ResolverError::Ssrf)?;

        let resp = self
            .http
            .get(parsed.as_str())
            .header("accept", "application/did+json, application/json")
            .send()
            .await
            .map_err(|e| ResolverError::Http(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ResolverError::Http(format!("DID doc status {status}")));
        }
        let doc: DidNostrDoc = resp
            .json()
            .await
            .map_err(|e| ResolverError::Malformed(e.to_string()))?;

        let expected = format!("did:nostr:{}", pk.to_hex());
        if doc.id.to_lowercase() != expected.to_lowercase() {
            return Err(ResolverError::Malformed(format!(
                "id mismatch: got {}, expected {}",
                doc.id, expected
            )));
        }

        Ok(doc
            .also_known_as
            .into_iter()
            .find(|u| u.starts_with("http://") || u.starts_with("https://")))
    }
}

impl Default for NostrWebIdResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct DidNostrDoc {
    id: String,
    #[serde(default, rename = "alsoKnownAs")]
    also_known_as: Vec<String>,
}

/// Extract a `did:nostr:<hex>` pubkey from a WebID profile body.
///
/// Recognises JSON / JSON-LD bodies via `sameAs` / `alsoKnownAs` /
/// `owl:sameAs`, and HTML bodies by scanning for an
/// `application/ld+json` data island.
pub(crate) fn extract_nostr_pubkey_from_profile(
    body: &str,
    content_type: &str,
) -> Option<NostrPubkey> {
    // JSON / JSON-LD.
    if content_type.contains("json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            return scan_json_for_did_nostr(&v);
        }
    }

    // HTML with JSON-LD data island.
    if content_type.contains("text/html") {
        if let Some(json) = extract_json_ld_island(body) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                return scan_json_for_did_nostr(&v);
            }
        }
    }

    // Turtle fallback — plain-text substring scan for the DID IRI.
    if content_type.contains("text/turtle") || content_type.contains("ld+json") || content_type.is_empty() {
        if let Some(found) = scan_text_for_did_nostr(body) {
            return Some(found);
        }
    }

    None
}

fn scan_json_for_did_nostr(v: &serde_json::Value) -> Option<NostrPubkey> {
    let keys = [
        "alsoKnownAs",
        "sameAs",
        "owl:sameAs",
        "schema:sameAs",
        "http://www.w3.org/2002/07/owl#sameAs",
        "https://schema.org/sameAs",
    ];
    for k in keys {
        if let Some(value) = v.get(k) {
            if let Some(pk) = extract_did_nostr_from_value(value) {
                return Some(pk);
            }
        }
    }
    // Recurse into nested objects / arrays (WebID profiles often wrap
    // subjects in `@graph`).
    match v {
        serde_json::Value::Array(a) => {
            for item in a {
                if let Some(pk) = scan_json_for_did_nostr(item) {
                    return Some(pk);
                }
            }
        }
        serde_json::Value::Object(o) => {
            for (_, v) in o {
                if let Some(pk) = scan_json_for_did_nostr(v) {
                    return Some(pk);
                }
            }
        }
        _ => {}
    }
    None
}

fn extract_did_nostr_from_value(value: &serde_json::Value) -> Option<NostrPubkey> {
    match value {
        serde_json::Value::String(s) => parse_did_nostr(s),
        serde_json::Value::Object(o) => o
            .get("@id")
            .and_then(|v| v.as_str())
            .and_then(parse_did_nostr),
        serde_json::Value::Array(a) => {
            for item in a {
                if let Some(pk) = extract_did_nostr_from_value(item) {
                    return Some(pk);
                }
            }
            None
        }
        _ => None,
    }
}

fn parse_did_nostr(s: &str) -> Option<NostrPubkey> {
    let s = s.trim();
    let hex = s.strip_prefix("did:nostr:")?;
    NostrPubkey::from_hex(&hex.to_lowercase()).ok()
}

fn scan_text_for_did_nostr(body: &str) -> Option<NostrPubkey> {
    // Minimal tokenisation — find `did:nostr:<64-hex>` anywhere in the
    // body; sufficient for Turtle which serialises the IRI verbatim.
    let bytes = body.as_bytes();
    let needle = b"did:nostr:";
    let mut i = 0usize;
    while i + needle.len() + 64 <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let hex_start = i + needle.len();
            let hex_end = hex_start + 64;
            if let Ok(candidate) = std::str::from_utf8(&bytes[hex_start..hex_end]) {
                if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(pk) = NostrPubkey::from_hex(&candidate.to_lowercase()) {
                        return Some(pk);
                    }
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    None
}

fn extract_json_ld_island(html: &str) -> Option<String> {
    // Find `<script type="application/ld+json">…</script>`. Case-insensitive
    // attribute match, tolerant of single/double quotes and whitespace.
    let lower = html.to_ascii_lowercase();
    let marker_ix = lower.find("application/ld+json")?;
    // Walk forward to the closing '>' of the opening tag.
    let after_marker = &html[marker_ix..];
    let open_end = after_marker.find('>')?;
    let body_start = marker_ix + open_end + 1;
    let after_open = &lower[body_start..];
    let close_ix = after_open.find("</script>")?;
    Some(html[body_start..body_start + close_ix].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn parse_did_nostr_accepts_lowercase_hex() {
        let s = format!("did:nostr:{PK}");
        let pk = parse_did_nostr(&s).unwrap();
        assert_eq!(pk.to_hex(), PK);
    }

    #[test]
    fn parse_did_nostr_rejects_bad_prefix() {
        assert!(parse_did_nostr("did:web:example").is_none());
    }

    #[test]
    fn scan_json_finds_nostr_in_same_as_string() {
        let v = serde_json::json!({
            "@id": "https://alice.example/card#me",
            "sameAs": format!("did:nostr:{PK}")
        });
        assert_eq!(scan_json_for_did_nostr(&v).unwrap().to_hex(), PK);
    }

    #[test]
    fn scan_json_finds_nostr_in_also_known_as_array_of_objects() {
        let v = serde_json::json!({
            "@id": "https://alice.example/card#me",
            "alsoKnownAs": [
                {"@id": format!("did:nostr:{PK}")},
                "https://alice.example/other"
            ]
        });
        assert_eq!(scan_json_for_did_nostr(&v).unwrap().to_hex(), PK);
    }

    #[test]
    fn scan_json_recurses_into_graph() {
        let v = serde_json::json!({
            "@graph": [{
                "@id": "https://alice.example/card#me",
                "owl:sameAs": format!("did:nostr:{PK}")
            }]
        });
        assert_eq!(scan_json_for_did_nostr(&v).unwrap().to_hex(), PK);
    }

    #[test]
    fn scan_text_extracts_from_turtle_literal() {
        let body = format!(
            "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n\
             <#me> owl:sameAs <did:nostr:{PK}> ."
        );
        assert_eq!(scan_text_for_did_nostr(&body).unwrap().to_hex(), PK);
    }

    #[test]
    fn scan_text_requires_full_64_hex() {
        let body = "did:nostr:deadbeef";
        assert!(scan_text_for_did_nostr(body).is_none());
    }

    #[test]
    fn extract_json_ld_island_finds_script_tag() {
        let html = format!(
            r#"<html><head>
               <script type="application/ld+json">
               {{"@id":"https://alice.example","sameAs":"did:nostr:{PK}"}}
               </script></head></html>"#
        );
        let island = extract_json_ld_island(&html).unwrap();
        assert!(island.contains(&format!("did:nostr:{PK}")));
    }

    #[test]
    fn extract_from_profile_with_html_island() {
        let html = format!(
            r#"<html><script type="application/ld+json">{{"sameAs":"did:nostr:{PK}"}}</script></html>"#
        );
        let pk = extract_nostr_pubkey_from_profile(&html, "text/html; charset=utf-8").unwrap();
        assert_eq!(pk.to_hex(), PK);
    }

    #[test]
    fn extract_from_profile_with_turtle() {
        let ttl = format!("<#me> <http://www.w3.org/2002/07/owl#sameAs> <did:nostr:{PK}> .");
        let pk = extract_nostr_pubkey_from_profile(&ttl, "text/turtle").unwrap();
        assert_eq!(pk.to_hex(), PK);
    }
}
