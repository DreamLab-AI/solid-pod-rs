//! Typestate wrappers for compile-time Schnorr verification enforcement.
//!
//! # Problem
//!
//! The raw [`Event`] struct exposes `.content` and `.tags` as public
//! fields. Nothing prevents a consumer from reading event payloads
//! without ever calling [`Event::verify`]. The verification contract is
//! documentation-only.
//!
//! # Solution: typestate pattern
//!
//! This module introduces two wrapper types that encode verification
//! status in the type system:
//!
//! - [`UncheckedEvent`] — wraps a raw `Event`. Exposes **routing
//!   metadata** (`id`, `pubkey`, `kind`, `created_at`) but **not** the
//!   content or tags. The only way to obtain the payload is to call
//!   [`UncheckedEvent::verify`], which performs full BIP-340 Schnorr
//!   signature validation.
//!
//! - [`VerifiedEvent`] — returned exclusively by
//!   [`UncheckedEvent::verify`]. Exposes the full event payload:
//!   `content()`, `tags()`, `d_tag()`, and `into_inner()`.
//!
//! The transition is one-way and consumes the input:
//!
//! ```text
//! UncheckedEvent ──verify()──▶ Result<VerifiedEvent, VerifyError>
//! ```
//!
//! # Backward compatibility
//!
//! The raw `Event` type and its `verify()` method remain public and
//! unchanged. Existing code continues to compile. The typestate wrappers
//! are the **recommended** API for new code that processes event
//! payloads.
//!
//! # Examples
//!
//! ```
//! # use solid_pod_rs_nostr::typestate::UncheckedEvent;
//! # use solid_pod_rs_nostr::relay::Event;
//! # fn example(raw: Event) {
//! let unchecked = UncheckedEvent::new(raw);
//!
//! // Routing metadata is available without verification:
//! let _kind = unchecked.kind();
//! let _pubkey = unchecked.pubkey();
//!
//! // Content is NOT accessible — this would be a compile error:
//! // let _content = unchecked.content();  // ERROR: no method `content`
//!
//! // Verify to unlock the payload:
//! match unchecked.verify() {
//!     Ok(verified) => {
//!         let content = verified.content();
//!         let tags = verified.tags();
//!         println!("verified content: {content}");
//!     }
//!     Err(e) => eprintln!("verification failed: {e}"),
//! }
//! # }
//! ```

use std::fmt;

use crate::error::RelayError;
use crate::relay::Event;

// ---------------------------------------------------------------------------
// VerifyError
// ---------------------------------------------------------------------------

/// Error returned when [`UncheckedEvent::verify`] fails.
///
/// Wraps the underlying [`RelayError`] variants that the BIP-340
/// verification pipeline can produce (id mismatch, bad signature,
/// structural invalidity).
#[derive(Debug)]
pub struct VerifyError {
    inner: RelayError,
}

impl VerifyError {
    /// Access the underlying relay error.
    pub fn inner(&self) -> &RelayError {
        &self.inner
    }

    /// Consume and return the underlying relay error.
    pub fn into_inner(self) -> RelayError {
        self.inner
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event verification failed: {}", self.inner)
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl From<RelayError> for VerifyError {
    fn from(e: RelayError) -> Self {
        Self { inner: e }
    }
}

// ---------------------------------------------------------------------------
// UncheckedEvent
// ---------------------------------------------------------------------------

/// A Nostr event whose signature has **not** been verified.
///
/// This wrapper intentionally hides the event payload (`content` and
/// `tags`). Consumers can inspect routing metadata — enough to decide
/// which relay, subscription, or handler should process the event —
/// but cannot access the business-logic payload until they call
/// [`verify`](UncheckedEvent::verify).
///
/// The type parameter-free design keeps the API simple: there is one
/// unchecked type and one verified type, with a consuming transition
/// between them.
pub struct UncheckedEvent {
    event: Event,
}

impl UncheckedEvent {
    /// Wrap a raw event as unchecked.
    ///
    /// No validation is performed at construction time. The event is
    /// opaque until [`verify`](UncheckedEvent::verify) is called.
    pub fn new(event: Event) -> Self {
        Self { event }
    }

    // -- routing metadata (safe to expose without verification) --

    /// The event's claimed id (hex-encoded SHA-256 of the canonical
    /// serialisation). Note: this is the *claimed* id; it has not been
    /// recomputed yet.
    pub fn id(&self) -> &str {
        &self.event.id
    }

    /// The event author's public key (64-char lowercase hex).
    pub fn pubkey(&self) -> &str {
        &self.event.pubkey
    }

    /// Unix timestamp of event creation.
    pub fn created_at(&self) -> u64 {
        self.event.created_at
    }

    /// NIP-01 event kind. Sufficient for routing (e.g. to determine
    /// whether the event is replaceable, ephemeral, or regular) without
    /// exposing the payload.
    pub fn kind(&self) -> u64 {
        self.event.kind
    }

    /// The event's claimed signature (128-char lowercase hex).
    pub fn sig(&self) -> &str {
        &self.event.sig
    }

    // -- transition: verify and unlock --

    /// Perform full BIP-340 Schnorr signature verification.
    ///
    /// On success, consumes `self` and returns a [`VerifiedEvent`] that
    /// grants access to the event payload. On failure, returns the
    /// original event inside the error so the caller can log or reject
    /// it.
    ///
    /// Verification checks (in order):
    /// 1. Structural validity (pubkey length, sig length, hex encoding).
    /// 2. Canonical id recomputation matches the claimed `id`.
    /// 3. BIP-340 Schnorr signature over the id bytes is valid for the
    ///    claimed `pubkey`.
    pub fn verify(self) -> Result<VerifiedEvent, VerifyError> {
        self.event.verify()?;
        Ok(VerifiedEvent { event: self.event })
    }

    /// Consume and return the inner raw `Event` without verifying.
    ///
    /// This escape hatch exists for backward-compatibility with code
    /// that manages its own verification pipeline. Prefer
    /// [`verify`](UncheckedEvent::verify) for new code.
    pub fn into_inner_unchecked(self) -> Event {
        self.event
    }
}

impl fmt::Debug for UncheckedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally omit content and tags from debug output to
        // reinforce the "payload is hidden" semantics.
        f.debug_struct("UncheckedEvent")
            .field("id", &self.event.id)
            .field("pubkey", &self.event.pubkey)
            .field("kind", &self.event.kind)
            .field("created_at", &self.event.created_at)
            .finish_non_exhaustive()
    }
}

impl From<Event> for UncheckedEvent {
    fn from(event: Event) -> Self {
        Self::new(event)
    }
}

// ---------------------------------------------------------------------------
// VerifiedEvent
// ---------------------------------------------------------------------------

/// A Nostr event whose BIP-340 Schnorr signature has been verified.
///
/// This type can only be constructed by calling
/// [`UncheckedEvent::verify`]. It grants full access to the event
/// payload.
///
/// `VerifiedEvent` is `Clone` (the underlying `Event` is `Clone`),
/// so consumers can cheaply share verified payloads across handler
/// boundaries.
#[derive(Clone)]
pub struct VerifiedEvent {
    event: Event,
}

impl VerifiedEvent {
    // -- routing metadata (same as UncheckedEvent) --

    /// The verified event id.
    pub fn id(&self) -> &str {
        &self.event.id
    }

    /// The verified event author's public key.
    pub fn pubkey(&self) -> &str {
        &self.event.pubkey
    }

    /// Unix timestamp of event creation.
    pub fn created_at(&self) -> u64 {
        self.event.created_at
    }

    /// NIP-01 event kind.
    pub fn kind(&self) -> u64 {
        self.event.kind
    }

    /// The verified signature.
    pub fn sig(&self) -> &str {
        &self.event.sig
    }

    // -- payload access (only available after verification) --

    /// The event content string.
    pub fn content(&self) -> &str {
        &self.event.content
    }

    /// The event's tag array.
    pub fn tags(&self) -> &[Vec<String>] {
        &self.event.tags
    }

    /// The `d` tag value, if present (NIP-33 parameterised replaceable
    /// events).
    pub fn d_tag(&self) -> Option<&str> {
        self.event.d_tag()
    }

    /// Look up the first tag with the given name and return its value
    /// (the second element of the tag array).
    pub fn get_tag(&self, name: &str) -> Option<&str> {
        self.event
            .tags
            .iter()
            .find(|t| t.first().map(|s| s.as_str()) == Some(name))
            .and_then(|t| t.get(1).map(|s| s.as_str()))
    }

    /// Consume and return the inner raw `Event`.
    ///
    /// The returned event has already been verified; the caller accepts
    /// responsibility for not re-verifying needlessly.
    pub fn into_inner(self) -> Event {
        self.event
    }

    /// Borrow the inner raw `Event`.
    pub fn as_inner(&self) -> &Event {
        &self.event
    }
}

impl fmt::Debug for VerifiedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedEvent")
            .field("id", &self.event.id)
            .field("pubkey", &self.event.pubkey)
            .field("kind", &self.event.kind)
            .field("created_at", &self.event.created_at)
            .field("content", &self.event.content)
            .field("tags", &self.event.tags)
            .finish()
    }
}

impl AsRef<Event> for VerifiedEvent {
    fn as_ref(&self) -> &Event {
        &self.event
    }
}

// ---------------------------------------------------------------------------
// Relay integration: verified ingest
// ---------------------------------------------------------------------------

impl crate::relay::Relay {
    /// Ingest a pre-verified event, skipping redundant signature checks.
    ///
    /// This is the typestate-aware counterpart of [`Relay::ingest`].
    /// Since the caller already holds a `VerifiedEvent`, the relay
    /// trusts the signature and proceeds directly to NIP-16
    /// classification and storage.
    pub fn ingest_verified(&self, verified: VerifiedEvent) -> Result<(), RelayError> {
        let event = verified.into_inner();

        if crate::relay::is_ephemeral(event.kind) {
            let _ = self.broadcast(&event);
            return Ok(());
        }

        if crate::relay::is_replaceable(event.kind) {
            let target_pubkey = event.pubkey.clone();
            let target_kind = event.kind;
            let replaced = self.store().replace_where(
                &move |e: &Event| e.pubkey == target_pubkey && e.kind == target_kind,
                event.clone(),
            );
            if !replaced {
                self.store().put(event.clone());
            }
            let _ = self.broadcast(&event);
            return Ok(());
        }

        if crate::relay::is_parameterised_replaceable(event.kind) {
            let target_pubkey = event.pubkey.clone();
            let target_kind = event.kind;
            let target_d = event.d_tag().map(|s| s.to_string());
            let replaced = self.store().replace_where(
                &move |e: &Event| {
                    e.pubkey == target_pubkey
                        && e.kind == target_kind
                        && e.d_tag().map(|s| s.to_string()) == target_d
                },
                event.clone(),
            );
            if !replaced {
                self.store().put(event.clone());
            }
            let _ = self.broadcast(&event);
            return Ok(());
        }

        // Regular event.
        self.store().put(event.clone());
        let _ = self.broadcast(&event);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Event, Relay};
    use k256::schnorr::{signature::Signer, SigningKey};

    fn test_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32]).expect("valid schnorr key")
    }

    fn make_signed_event(kind: u64, content: &str, tags: Vec<Vec<String>>) -> Event {
        let sk = test_sk();
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        let skeleton = Event {
            id: String::new(),
            pubkey: pubkey_hex.clone(),
            created_at: 1_700_000_000,
            kind,
            tags: tags.clone(),
            content: content.to_string(),
            sig: String::new(),
        };
        let id = skeleton.canonical_id();
        let id_bytes = hex::decode(&id).unwrap();
        let sig: k256::schnorr::Signature = sk.sign(&id_bytes);
        Event {
            id,
            pubkey: pubkey_hex,
            created_at: 1_700_000_000,
            kind,
            tags,
            content: content.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    fn make_bad_sig_event() -> Event {
        let mut ev = make_signed_event(1, "hello", vec![]);
        let mut sig_bytes = hex::decode(&ev.sig).unwrap();
        sig_bytes[0] ^= 0x01;
        ev.sig = hex::encode(sig_bytes);
        ev
    }

    // -- UncheckedEvent metadata access --

    #[test]
    fn unchecked_exposes_routing_metadata() {
        let ev = make_signed_event(1, "secret payload", vec![]);
        let unchecked = UncheckedEvent::new(ev.clone());
        assert_eq!(unchecked.id(), ev.id);
        assert_eq!(unchecked.pubkey(), ev.pubkey);
        assert_eq!(unchecked.kind(), 1);
        assert_eq!(unchecked.created_at(), 1_700_000_000);
        assert_eq!(unchecked.sig(), ev.sig);
    }

    #[test]
    fn unchecked_debug_omits_content() {
        let ev = make_signed_event(1, "secret payload", vec![vec!["t".into(), "tag".into()]]);
        let unchecked = UncheckedEvent::new(ev);
        let debug = format!("{:?}", unchecked);
        assert!(!debug.contains("secret payload"));
        assert!(!debug.contains("tag"));
        assert!(debug.contains("UncheckedEvent"));
    }

    // -- Verify happy path --

    #[test]
    fn verify_succeeds_for_valid_event() {
        let ev = make_signed_event(1, "hello world", vec![vec!["t".into(), "test".into()]]);
        let unchecked = UncheckedEvent::new(ev);
        let verified = unchecked.verify().expect("should verify");
        assert_eq!(verified.content(), "hello world");
        assert_eq!(verified.tags().len(), 1);
        assert_eq!(verified.tags()[0], vec!["t", "test"]);
        assert_eq!(verified.kind(), 1);
    }

    // -- Verify failure path --

    #[test]
    fn verify_fails_for_bad_signature() {
        let ev = make_bad_sig_event();
        let unchecked = UncheckedEvent::new(ev);
        let err = unchecked.verify().unwrap_err();
        assert!(err.to_string().contains("verification failed"));
        // Inner error should be a BadSignature.
        assert!(matches!(err.inner(), RelayError::BadSignature(_)));
    }

    #[test]
    fn verify_fails_for_tampered_content() {
        let mut ev = make_signed_event(1, "original", vec![]);
        ev.content = "tampered".to_string();
        let unchecked = UncheckedEvent::new(ev);
        let err = unchecked.verify().unwrap_err();
        assert!(matches!(err.inner(), RelayError::IdMismatch));
    }

    // -- VerifiedEvent payload access --

    #[test]
    fn verified_content_and_tags() {
        let tags = vec![
            vec!["e".into(), "abc123".into()],
            vec!["p".into(), "def456".into()],
            vec!["d".into(), "my-slot".into()],
        ];
        let ev = make_signed_event(30_000, r#"{"name":"alice"}"#, tags);
        let verified = UncheckedEvent::new(ev).verify().unwrap();

        assert_eq!(verified.content(), r#"{"name":"alice"}"#);
        assert_eq!(verified.tags().len(), 3);
        assert_eq!(verified.get_tag("e"), Some("abc123"));
        assert_eq!(verified.get_tag("p"), Some("def456"));
        assert_eq!(verified.get_tag("d"), Some("my-slot"));
        assert_eq!(verified.d_tag(), Some("my-slot"));
        assert_eq!(verified.get_tag("nonexistent"), None);
    }

    #[test]
    fn verified_into_inner_returns_event() {
        let ev = make_signed_event(1, "payload", vec![]);
        let original_id = ev.id.clone();
        let verified = UncheckedEvent::new(ev).verify().unwrap();
        let inner = verified.into_inner();
        assert_eq!(inner.id, original_id);
        assert_eq!(inner.content, "payload");
    }

    #[test]
    fn verified_as_ref_returns_event() {
        let ev = make_signed_event(1, "payload", vec![]);
        let verified = UncheckedEvent::new(ev).verify().unwrap();
        let inner: &Event = verified.as_ref();
        assert_eq!(inner.content, "payload");
    }

    #[test]
    fn verified_clone() {
        let ev = make_signed_event(1, "clonable", vec![]);
        let verified = UncheckedEvent::new(ev).verify().unwrap();
        let cloned = verified.clone();
        assert_eq!(cloned.content(), "clonable");
        assert_eq!(cloned.id(), verified.id());
    }

    // -- From<Event> conversion --

    #[test]
    fn from_event_to_unchecked() {
        let ev = make_signed_event(1, "test", vec![]);
        let unchecked: UncheckedEvent = ev.into();
        assert_eq!(unchecked.kind(), 1);
    }

    // -- into_inner_unchecked escape hatch --

    #[test]
    fn unchecked_escape_hatch() {
        let ev = make_signed_event(1, "escape", vec![]);
        let original_id = ev.id.clone();
        let unchecked = UncheckedEvent::new(ev);
        let raw = unchecked.into_inner_unchecked();
        assert_eq!(raw.id, original_id);
        assert_eq!(raw.content, "escape");
    }

    // -- VerifyError --

    #[test]
    fn verify_error_display() {
        let ev = make_bad_sig_event();
        let err = UncheckedEvent::new(ev).verify().unwrap_err();
        let display = err.to_string();
        assert!(display.starts_with("event verification failed:"));
    }

    #[test]
    fn verify_error_into_inner() {
        let ev = make_bad_sig_event();
        let err = UncheckedEvent::new(ev).verify().unwrap_err();
        let relay_err = err.into_inner();
        assert!(matches!(relay_err, RelayError::BadSignature(_)));
    }

    // -- Relay integration --

    #[test]
    fn relay_ingest_verified_stores_event() {
        let relay = Relay::in_memory();
        let ev = make_signed_event(1, "verified-ingest", vec![]);
        let verified = UncheckedEvent::new(ev.clone()).verify().unwrap();
        relay.ingest_verified(verified).unwrap();
        let snap = relay.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, ev.id);
        assert_eq!(snap[0].content, "verified-ingest");
    }

    #[test]
    fn relay_ingest_verified_replaces_nip16() {
        let relay = Relay::in_memory();
        let a = make_signed_event(0, r#"{"v":1}"#, vec![]);
        let b = make_signed_event(0, r#"{"v":2}"#, vec![]);
        let va = UncheckedEvent::new(a).verify().unwrap();
        let vb = UncheckedEvent::new(b.clone()).verify().unwrap();
        relay.ingest_verified(va).unwrap();
        relay.ingest_verified(vb).unwrap();
        let snap = relay.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].content, r#"{"v":2}"#);
    }

    #[test]
    fn relay_ingest_verified_ephemeral_not_stored() {
        let relay = Relay::in_memory();
        let mut rx = relay.subscribe();
        let ev = make_signed_event(20_001, "ephemeral", vec![]);
        let verified = UncheckedEvent::new(ev.clone()).verify().unwrap();
        relay.ingest_verified(verified).unwrap();
        assert_eq!(relay.snapshot().len(), 0);
        let received = rx.try_recv().unwrap();
        assert_eq!(received.id, ev.id);
    }

    #[test]
    fn relay_ingest_verified_parameterised_replaceable() {
        let relay = Relay::in_memory();
        let a = make_signed_event(
            30_000,
            "v1",
            vec![vec!["d".into(), "slot".into()]],
        );
        let b = make_signed_event(
            30_000,
            "v2",
            vec![vec!["d".into(), "slot".into()]],
        );
        let va = UncheckedEvent::new(a).verify().unwrap();
        let vb = UncheckedEvent::new(b).verify().unwrap();
        relay.ingest_verified(va).unwrap();
        relay.ingest_verified(vb).unwrap();
        let snap = relay.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].content, "v2");
    }
}
