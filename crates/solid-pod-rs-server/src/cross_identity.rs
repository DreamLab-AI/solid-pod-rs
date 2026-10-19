//! did:nostr to WebID cross-identity for NIP-98 callers.
//!
//! JSS upgrades a verified Nostr pubkey to a WebID after NIP-98 verification
//! (`src/auth/nostr.js` 30 and 326-337), resolving through
//! `resolveDidNostrToWebId` (`src/auth/did-nostr.js` 171-345): the DID
//! document's `alsoKnownAs` names a WebID, and the WebID profile must link
//! back to the same `did:nostr`. A one-way link is never accepted.
//!
//! Here a verified link makes the caller present as BOTH identities, so an
//! ACL naming either `acl:agent <webid>` or `acl:agent <did:nostr:...>`
//! matches. (JSS replaces the did:nostr agent with the WebID; keeping both
//! is the deliberate superset the parity brief asks for.)
//!
//! Two sources, tried in order:
//!
//! 1. the pod's own profile card: the owner's `nostr:pubkey` triple, which
//!    this server's `/.well-known/did/nostr/<pk>.json` points back at, so the
//!    link is bidirectional by construction (no network);
//! 2. with feature `did-nostr`, remote DID-document origins configured by the
//!    operator, resolved by
//!    [`solid_pod_rs::interop::did_nostr::DidNostrResolver`] (SSRF policy,
//!    bounded TTL cache with negative caching, bidirectional back-link).

use std::sync::Arc;

use async_trait::async_trait;
use solid_pod_rs::storage::Storage;

/// Resolves a verified Nostr pubkey to the WebID bound to it, if any.
#[async_trait]
pub trait CrossIdentityResolver: Send + Sync {
    /// `pubkey` is 64 lowercase hex characters. Return `Some(webid)` only
    /// for a bidirectionally verified link.
    async fn linked_web_id(&self, pubkey: &str) -> Option<String>;
}

/// True for a 64-character lowercase hex string.
pub fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Default resolver: local profile card, then optional remote origins.
pub struct PodCrossIdentity {
    storage: Arc<dyn Storage>,
    base_url: String,
    #[cfg(feature = "did-nostr")]
    remote: Option<(
        solid_pod_rs::interop::did_nostr::DidNostrResolver,
        Vec<String>,
    )>,
}

impl PodCrossIdentity {
    /// Local-only resolver for the pod served at `base_url`.
    pub fn new(storage: Arc<dyn Storage>, base_url: impl Into<String>) -> Self {
        Self {
            storage,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            #[cfg(feature = "did-nostr")]
            remote: None,
        }
    }

    /// Also consult DID-document `origins` through `resolver`.
    #[cfg(feature = "did-nostr")]
    pub fn with_remote(
        mut self,
        resolver: solid_pod_rs::interop::did_nostr::DidNostrResolver,
        origins: Vec<String>,
    ) -> Self {
        self.remote = Some((resolver, origins));
        self
    }

    async fn local(&self, pubkey: &str) -> Option<String> {
        let (body, _) = self.storage.get("/profile/card").await.ok()?;
        let owner = solid_pod_rs::webid::extract_nostr_pubkey(&body)
            .ok()
            .flatten()?;
        if owner.eq_ignore_ascii_case(pubkey) {
            Some(format!("{}/profile/card#me", self.base_url))
        } else {
            None
        }
    }
}

#[async_trait]
impl CrossIdentityResolver for PodCrossIdentity {
    async fn linked_web_id(&self, pubkey: &str) -> Option<String> {
        if !is_hex_pubkey(pubkey) {
            return None;
        }
        if let Some(w) = self.local(pubkey).await {
            return Some(w);
        }
        #[cfg(feature = "did-nostr")]
        if let Some((resolver, origins)) = &self.remote {
            for origin in origins {
                if let Some(w) = resolver.resolve(origin, pubkey).await {
                    return Some(w);
                }
            }
        }
        None
    }
}

/// The identities a verified principal presents: the linked WebID(s) for a
/// `did:nostr:<hex>` agent, empty for anyone else. Never returns the agent
/// itself, and only `http(s)` URLs.
pub async fn linked_identities(
    resolver: Option<&Arc<dyn CrossIdentityResolver>>,
    agent_uri: Option<&str>,
) -> Vec<String> {
    let (Some(resolver), Some(agent)) = (resolver, agent_uri) else {
        return Vec::new();
    };
    let Some(pk) = agent.strip_prefix("did:nostr:") else {
        return Vec::new();
    };
    match resolver.linked_web_id(pk).await {
        Some(w) if (w.starts_with("https://") || w.starts_with("http://")) && w != agent => {
            vec![w]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use solid_pod_rs::storage::memory::MemoryBackend;

    const PK: &str = "abcd000000000000000000000000000000000000000000000000000000000001";

    #[tokio::test]
    async fn local_profile_link_resolves() {
        let st = Arc::new(MemoryBackend::new());
        let card = format!(
            r##"<html><script type="application/ld+json">{{"@id":"#me","nostr:pubkey":"{PK}"}}</script></html>"##
        );
        st.put("/profile/card", Bytes::from(card), "text/html")
            .await
            .unwrap();
        let r = PodCrossIdentity::new(st, "https://pod.example/");
        assert_eq!(
            r.linked_web_id(PK).await.as_deref(),
            Some("https://pod.example/profile/card#me")
        );
        let other = "ef".repeat(32);
        assert_eq!(r.linked_web_id(&other).await, None);
    }

    #[tokio::test]
    async fn malformed_pubkey_never_resolves() {
        let st = Arc::new(MemoryBackend::new());
        let r = PodCrossIdentity::new(st, "https://pod.example");
        assert_eq!(r.linked_web_id("../etc").await, None);
        assert_eq!(r.linked_web_id(&PK.to_uppercase()).await, None);
    }

    struct Fake(Option<&'static str>);
    #[async_trait]
    impl CrossIdentityResolver for Fake {
        async fn linked_web_id(&self, _pk: &str) -> Option<String> {
            self.0.map(String::from)
        }
    }

    #[tokio::test]
    async fn linked_identities_filters() {
        let did = format!("did:nostr:{PK}");
        let ok: Arc<dyn CrossIdentityResolver> = Arc::new(Fake(Some("https://a.example/me#i")));
        assert_eq!(
            linked_identities(Some(&ok), Some(&did)).await,
            vec!["https://a.example/me#i".to_string()]
        );
        // A WebID principal is never re-resolved.
        assert!(linked_identities(Some(&ok), Some("https://x.example/#me"))
            .await
            .is_empty());
        // Anonymous and no-resolver cases.
        assert!(linked_identities(Some(&ok), None).await.is_empty());
        assert!(linked_identities(None, Some(&did)).await.is_empty());
        // Non-http result (e.g. a hostile javascript: or did: value) is dropped.
        let bad: Arc<dyn CrossIdentityResolver> = Arc::new(Fake(Some("did:web:evil")));
        assert!(linked_identities(Some(&bad), Some(&did)).await.is_empty());
        let none: Arc<dyn CrossIdentityResolver> = Arc::new(Fake(None));
        assert!(linked_identities(Some(&none), Some(&did)).await.is_empty());
    }
}
