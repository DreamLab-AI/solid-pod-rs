//! ActivityPub Actor document (§4.1) + keypair management.
//!
//! JSS parity: mirrors the Accept-negotiated Actor document produced by
//! `src/server.js:238-259` and `src/ap/routes/actor.js`. The Rust
//! surface is framework-agnostic — consumers wire [`render_actor`] into
//! their HTTP layer (axum/actix/etc).
//!
//! The Actor's signing key is RSA-2048 for broad Mastodon/Pleroma
//! interop — these implementations historically validated only
//! `RSA-SHA256` and `rsa-sha256` HTTP Signatures (draft-cavage v12). A
//! forward-looking Ed25519 variant is trivial to add if/when upstream
//! AP fleets accept it. See
//! <https://docs.joinmastodon.org/spec/activitypub/#http-signatures>.

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

/// PEM-encoded public key embedded in the Actor document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey {
    pub id: String,
    pub owner: String,
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,
}

/// Sharedinbox / streams endpoints exposed under `endpoints`. Mastodon
/// probes this to discover the per-instance sharedInbox — the field is
/// optional but widely expected.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoints {
    #[serde(rename = "sharedInbox", skip_serializing_if = "Option::is_none")]
    pub shared_inbox: Option<String>,
}

/// ActivityPub Actor document (`type: Person`).
///
/// The serialisation preserves the JSON-LD contexts in insertion order
/// because several major fediverse servers parse the `@context` array
/// positionally rather than using a true JSON-LD processor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    #[serde(rename = "@context")]
    pub context: Vec<serde_json::Value>,
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: String,
    #[serde(rename = "preferredUsername")]
    pub preferred_username: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub inbox: String,
    pub outbox: String,
    pub followers: String,
    pub following: String,
    #[serde(rename = "publicKey")]
    pub public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Endpoints>,
    /// Optional `alsoKnownAs` — the SAND stack uses this to link the
    /// Actor to a did:nostr identifier.
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Vec::is_empty", default)]
    pub also_known_as: Vec<String>,
}

/// Generate a fresh RSA-2048 keypair and return PEM-encoded
/// `(private_key_pem, public_key_pem)` pair.
///
/// RSA-2048 is the Mastodon interop baseline — RSA-4096 works in
/// theory but causes timeout failures on several major servers that
/// hard-code a 4 s verification budget.
pub fn generate_actor_keypair() -> Result<(String, String), crate::error::SigError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| crate::error::SigError::Rsa(e.to_string()))?;
    let public_key = RsaPublicKey::from(&private_key);
    let priv_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| crate::error::SigError::Rsa(e.to_string()))?
        .to_string();
    let pub_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| crate::error::SigError::Rsa(e.to_string()))?;
    Ok((priv_pem, pub_pem))
}

/// Render an Actor document for the pod at `base_url`. `base_url` is
/// the scheme+host only (e.g. `https://pod.example`). The document
/// exposes endpoints relative to `/profile/card.jsonld`, matching JSS.
///
/// `preferred_username` is the WebFinger local-part; `display_name` is
/// the human-facing label. `pubkey_pem` must already be PEM-encoded
/// (either freshly generated via [`generate_actor_keypair`] or loaded
/// from disk).
pub fn render_actor(
    base_url: &str,
    preferred_username: &str,
    display_name: &str,
    summary: Option<&str>,
    pubkey_pem: &str,
) -> Actor {
    let base = base_url.trim_end_matches('/');
    let profile = format!("{base}/profile/card.jsonld");
    let actor_id = format!("{profile}#me");

    Actor {
        context: vec![
            serde_json::Value::String("https://www.w3.org/ns/activitystreams".to_string()),
            serde_json::Value::String("https://w3id.org/security/v1".to_string()),
        ],
        id: actor_id.clone(),
        actor_type: "Person".to_string(),
        preferred_username: preferred_username.to_string(),
        name: display_name.to_string(),
        summary: summary.map(|s| s.to_string()),
        inbox: format!("{profile}/inbox"),
        outbox: format!("{profile}/outbox"),
        followers: format!("{profile}/followers"),
        following: format!("{profile}/following"),
        public_key: PublicKey {
            id: format!("{profile}#main-key"),
            owner: actor_id,
            public_key_pem: pubkey_pem.to_string(),
        },
        endpoints: Some(Endpoints {
            shared_inbox: Some(format!("{base}/inbox")),
        }),
        also_known_as: Vec::new(),
    }
}

/// Attach a did:nostr identifier (or any URI) to the Actor's
/// `alsoKnownAs` set. Used to bind AP identities to NIP-01 pubkeys in
/// the SAND stack.
pub fn with_also_known_as(mut actor: Actor, also: impl IntoIterator<Item = String>) -> Actor {
    actor.also_known_as.extend(also);
    actor
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_document_shape() {
        let actor = render_actor(
            "https://pod.example",
            "alice",
            "Alice Example",
            Some("bio"),
            "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
        );
        assert_eq!(actor.id, "https://pod.example/profile/card.jsonld#me");
        assert_eq!(actor.actor_type, "Person");
        assert_eq!(actor.preferred_username, "alice");
        assert_eq!(actor.inbox, "https://pod.example/profile/card.jsonld/inbox");
        assert_eq!(
            actor.outbox,
            "https://pod.example/profile/card.jsonld/outbox"
        );
        assert_eq!(
            actor.followers,
            "https://pod.example/profile/card.jsonld/followers"
        );
        assert_eq!(
            actor.following,
            "https://pod.example/profile/card.jsonld/following"
        );
        assert_eq!(
            actor.public_key.id,
            "https://pod.example/profile/card.jsonld#main-key"
        );
        assert_eq!(actor.public_key.owner, actor.id);
        assert!(actor
            .public_key
            .public_key_pem
            .contains("BEGIN PUBLIC KEY"));
        assert_eq!(
            actor.endpoints.as_ref().and_then(|e| e.shared_inbox.as_deref()),
            Some("https://pod.example/inbox")
        );
    }

    #[test]
    fn actor_context_order_preserved_for_fediverse_compat() {
        let actor = render_actor(
            "https://pod.example",
            "bob",
            "Bob",
            None,
            "PEM",
        );
        // Several Mastodon/Pleroma releases positionally assume index 0
        // is activitystreams. Keep this assertion strict.
        assert_eq!(
            actor.context[0],
            serde_json::Value::String("https://www.w3.org/ns/activitystreams".to_string())
        );
        assert_eq!(
            actor.context[1],
            serde_json::Value::String("https://w3id.org/security/v1".to_string())
        );
    }

    #[test]
    fn actor_base_url_trailing_slash_normalised() {
        let a = render_actor("https://pod.example/", "x", "X", None, "PEM");
        let b = render_actor("https://pod.example", "x", "X", None, "PEM");
        assert_eq!(a.id, b.id);
        assert_eq!(a.inbox, b.inbox);
    }

    #[test]
    fn actor_serialises_with_jsonld_fields() {
        let actor = render_actor("https://pod.example", "alice", "Alice", None, "PEM");
        let j = serde_json::to_value(&actor).unwrap();
        assert!(j.get("@context").is_some());
        assert_eq!(j["type"], "Person");
        assert_eq!(j["preferredUsername"], "alice");
        assert!(j.get("publicKey").is_some());
    }

    #[test]
    fn also_known_as_appends() {
        let actor = render_actor("https://pod.example", "a", "A", None, "PEM");
        let linked = with_also_known_as(actor, ["did:nostr:abc".to_string()]);
        assert_eq!(linked.also_known_as, vec!["did:nostr:abc".to_string()]);
    }

    #[test]
    fn actor_keypair_generation_rsa2048() {
        let (priv_pem, pub_pem) = generate_actor_keypair().expect("keypair generates");
        assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        // Roundtrip through rsa crate to confirm decodability.
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        let sk = RsaPrivateKey::from_pkcs8_pem(&priv_pem).unwrap();
        let pk = RsaPublicKey::from_public_key_pem(&pub_pem).unwrap();
        assert_eq!(sk.size(), 256); // 2048 bits -> 256 bytes
        assert_eq!(RsaPublicKey::from(&sk), pk);
    }
}
