//! In-memory Nostr relay implementing NIP-01, NIP-11, and NIP-16.
//!
//! - **NIP-01**: event envelope, canonical id, filter semantics,
//!   `EVENT` / `REQ` / `CLOSE` client→relay messages, `EVENT` /
//!   `EOSE` / `OK` / `NOTICE` relay→client messages.
//! - **NIP-11**: Relay Information Document (JSON) exposed via
//!   `GET /` with `Accept: application/nostr+json`.
//! - **NIP-16**: replaceable kinds (0, 3, 10000-19999) and
//!   parameterised replaceable kinds (30000-39999, keyed by `d` tag).
//!
//! The relay is storage-agnostic: plug in any [`EventStore`] — the
//! crate ships [`InMemoryEventStore`] out of the box and consumers can
//! back their own implementation with SQLite / postgres / FS.
//!
//! Upstream parity: `JavaScriptSolidServer/src/nostr/relay.js`.

use std::collections::HashMap;
use std::sync::Arc;

use std::sync::Mutex;

use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::error::RelayError;

// ---------------------------------------------------------------------------
// NIP-01: Event envelope
// ---------------------------------------------------------------------------

/// A NIP-01 signed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Canonical NIP-01 event id: `sha256(json([0, pubkey, created_at,
    /// kind, tags, content]))`, lowercase hex.
    pub fn canonical_id(&self) -> String {
        let canonical = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        let s = serde_json::to_string(&canonical).unwrap_or_default();
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    /// Verify the canonical id matches the claimed `id` and that `sig`
    /// is a valid BIP-340 Schnorr signature over the id bytes.
    pub fn verify(&self) -> Result<(), RelayError> {
        // Structural checks first.
        if self.pubkey.len() != 64 || hex::decode(&self.pubkey).is_err() {
            return Err(RelayError::InvalidEvent("pubkey not 32-byte hex".into()));
        }
        if self.sig.len() != 128 || hex::decode(&self.sig).is_err() {
            return Err(RelayError::InvalidEvent("sig not 64-byte hex".into()));
        }
        let computed = self.canonical_id();
        if computed.to_lowercase() != self.id.to_lowercase() {
            return Err(RelayError::IdMismatch);
        }
        let pk_bytes = hex::decode(&self.pubkey)
            .map_err(|e| RelayError::InvalidEvent(e.to_string()))?;
        let sig_bytes = hex::decode(&self.sig)
            .map_err(|e| RelayError::InvalidEvent(e.to_string()))?;
        let id_bytes = hex::decode(&computed)
            .map_err(|e| RelayError::InvalidEvent(e.to_string()))?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| RelayError::BadSignature(e.to_string()))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| RelayError::BadSignature(e.to_string()))?;
        vk.verify(&id_bytes, &sig)
            .map_err(|e| RelayError::BadSignature(e.to_string()))
    }

    /// Return the `d` tag value, if present. Used for NIP-33
    /// parameterised replaceable events.
    pub fn d_tag(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(|s| s.as_str()) == Some("d"))
            .and_then(|t| t.get(1).map(|s| s.as_str()))
    }
}

// ---------------------------------------------------------------------------
// NIP-01: Filters
// ---------------------------------------------------------------------------

/// A NIP-01 subscription filter.
///
/// Tag filters (`#e`, `#p`, …) are carried in the `tags` map keyed by
/// the single-letter tag name (without the leading `#`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Tag filters keyed by single-letter tag (e.g. `"e"`, `"p"`).
    #[serde(flatten)]
    pub tags: HashMap<String, serde_json::Value>,
}

impl Filter {
    /// Decode a raw filter JSON object, mapping `#X` keys into the tag
    /// filter slot.
    pub fn from_value(v: serde_json::Value) -> Result<Self, RelayError> {
        let mut filter: Filter = serde_json::from_value(v.clone())
            .map_err(|e| RelayError::BadMessage(format!("filter decode: {e}")))?;
        // `serde(flatten)` has scooped every non-recognised key into
        // `tags`. Retain only `#X` keys and strip the leading `#`.
        let mut normalised: HashMap<String, serde_json::Value> = HashMap::new();
        for (k, val) in filter.tags.drain() {
            if let Some(short) = k.strip_prefix('#') {
                if short.len() == 1 {
                    normalised.insert(short.to_string(), val);
                }
            }
        }
        filter.tags = normalised;
        Ok(filter)
    }

    /// Return `true` iff `event` passes every constraint in this filter.
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ids) = &self.ids {
            if !ids.iter().any(|i| i.eq_ignore_ascii_case(&event.id)) {
                return false;
            }
        }
        if let Some(authors) = &self.authors {
            if !authors
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&event.pubkey))
            {
                return false;
            }
        }
        if let Some(kinds) = &self.kinds {
            if !kinds.contains(&event.kind) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if event.created_at < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if event.created_at > until {
                return false;
            }
        }
        for (tag_name, values) in &self.tags {
            let Some(values) = values.as_array() else {
                return false;
            };
            let event_tag_values: Vec<&str> = event
                .tags
                .iter()
                .filter(|t| t.first().map(|s| s.as_str()) == Some(tag_name.as_str()))
                .filter_map(|t| t.get(1).map(|s| s.as_str()))
                .collect();
            let any = values.iter().any(|v| {
                v.as_str()
                    .map(|s| event_tag_values.contains(&s))
                    .unwrap_or(false)
            });
            if !any {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// NIP-16: replaceable kind classifiers
// ---------------------------------------------------------------------------

pub fn is_replaceable(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

pub fn is_ephemeral(kind: u64) -> bool {
    (20_000..30_000).contains(&kind)
}

pub fn is_parameterised_replaceable(kind: u64) -> bool {
    (30_000..40_000).contains(&kind)
}

// ---------------------------------------------------------------------------
// Event store trait
// ---------------------------------------------------------------------------

/// Event persistence abstraction — consumers may swap SQLite, Postgres,
/// or FS adapters. The trait is sync and operates on a bounded ring
/// buffer semantically; implementations are expected to cap growth.
pub trait EventStore: Send + Sync {
    /// Insert or replace an event (NIP-16 semantics applied by the caller).
    fn put(&self, event: Event);
    /// Remove an event by id (used by NIP-09 integrations).
    fn remove(&self, id: &str);
    /// Snapshot current contents for filter matching.
    fn snapshot(&self) -> Vec<Event>;
    /// Replace the event at the first index matching `predicate`.
    /// Returns `true` if a replacement was performed.
    fn replace_where(
        &self,
        predicate: &dyn Fn(&Event) -> bool,
        event: Event,
    ) -> bool;
    /// Current event count.
    fn len(&self) -> usize;
    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bounded in-memory ring-buffer store.
#[derive(Debug)]
pub struct InMemoryEventStore {
    inner: Mutex<Vec<Event>>,
    max_events: usize,
}

impl InMemoryEventStore {
    pub fn new(max_events: usize) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            max_events: max_events.max(1),
        }
    }
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl EventStore for InMemoryEventStore {
    fn put(&self, event: Event) {
        let mut guard = self.inner.lock().expect("event store lock poisoned");
        if guard.len() >= self.max_events {
            guard.remove(0);
        }
        guard.push(event);
    }

    fn remove(&self, id: &str) {
        let mut guard = self.inner.lock().expect("event store lock poisoned");
        guard.retain(|e| e.id != id);
    }

    fn snapshot(&self) -> Vec<Event> {
        self.inner
            .lock()
            .expect("event store lock poisoned")
            .clone()
    }

    fn replace_where(
        &self,
        predicate: &dyn Fn(&Event) -> bool,
        event: Event,
    ) -> bool {
        let mut guard = self.inner.lock().expect("event store lock poisoned");
        for slot in guard.iter_mut() {
            if predicate(slot) {
                *slot = event;
                return true;
            }
        }
        false
    }

    fn len(&self) -> usize {
        self.inner.lock().expect("event store lock poisoned").len()
    }
}

// ---------------------------------------------------------------------------
// NIP-11: relay info document
// ---------------------------------------------------------------------------

/// NIP-11 Relay Information Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub name: String,
    pub description: String,
    pub pubkey: String,
    pub contact: String,
    pub supported_nips: Vec<u64>,
    pub software: String,
    pub version: String,
}

impl RelayInfo {
    pub fn jss_compatible() -> Self {
        Self {
            name: "solid-pod-rs Nostr Relay".into(),
            description: "Embedded Nostr relay for solid-pod-rs pods".into(),
            pubkey: String::new(),
            contact: String::new(),
            supported_nips: vec![1, 11, 16],
            software: "https://github.com/dreamlab-ai/solid-pod-rs".into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Relay aggregate
// ---------------------------------------------------------------------------

/// Relay aggregate root — owns the event store, a broadcast channel for
/// live subscriptions, and the NIP-11 info document. Clone-cheap
/// (internally `Arc`-shared).
#[derive(Clone)]
pub struct Relay {
    store: Arc<dyn EventStore>,
    events_tx: broadcast::Sender<Event>,
    info: Arc<RelayInfo>,
}

impl Relay {
    /// Build a relay with the given store, info document, and broadcast
    /// channel capacity.
    pub fn new(
        store: Arc<dyn EventStore>,
        info: RelayInfo,
        broadcast_capacity: usize,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(broadcast_capacity.max(1));
        Self {
            store,
            events_tx,
            info: Arc::new(info),
        }
    }

    /// Convenience constructor: in-memory store, JSS-compatible info
    /// document, broadcast capacity 256.
    pub fn in_memory() -> Self {
        Self::new(
            Arc::new(InMemoryEventStore::default()),
            RelayInfo::jss_compatible(),
            256,
        )
    }

    /// Access the relay info document (for NIP-11 serialisation).
    pub fn info(&self) -> &RelayInfo {
        &self.info
    }

    /// Subscribe to the live-event broadcast.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events_tx.subscribe()
    }

    /// Return a snapshot of stored events — useful for history replay
    /// on `REQ`.
    pub fn snapshot(&self) -> Vec<Event> {
        self.store.snapshot()
    }

    /// Ingest a NIP-01 event.
    ///
    /// Pipeline:
    /// 1. Structural + Schnorr validation (`Event::verify`).
    /// 2. NIP-16 classification:
    ///    - **Ephemeral** — not stored, but broadcast.
    ///    - **Replaceable** — supersedes older same `(pubkey, kind)`.
    ///    - **Parameterised Replaceable** — keyed by `(pubkey, kind, d)`.
    ///    - **Regular** — appended.
    /// 3. Live broadcast to subscribers.
    pub fn ingest(&self, event: Event) -> Result<(), RelayError> {
        event.verify()?;

        if is_ephemeral(event.kind) {
            // Broadcast only, do not persist.
            let _ = self.events_tx.send(event);
            return Ok(());
        }

        if is_replaceable(event.kind) {
            let target_pubkey = event.pubkey.clone();
            let target_kind = event.kind;
            let replaced = self.store.replace_where(
                &move |e| e.pubkey == target_pubkey && e.kind == target_kind,
                event.clone(),
            );
            if !replaced {
                self.store.put(event.clone());
            }
            let _ = self.events_tx.send(event);
            return Ok(());
        }

        if is_parameterised_replaceable(event.kind) {
            let target_pubkey = event.pubkey.clone();
            let target_kind = event.kind;
            let target_d = event.d_tag().map(|s| s.to_string());
            let replaced = self.store.replace_where(
                &move |e| {
                    e.pubkey == target_pubkey
                        && e.kind == target_kind
                        && e.d_tag().map(|s| s.to_string()) == target_d
                },
                event.clone(),
            );
            if !replaced {
                self.store.put(event.clone());
            }
            let _ = self.events_tx.send(event);
            return Ok(());
        }

        // Regular event.
        self.store.put(event.clone());
        let _ = self.events_tx.send(event);
        Ok(())
    }

    /// Compute the initial history slice (pre-EOSE) for a set of filters.
    /// Applies each filter's `limit` independently, deduplicates by id.
    pub fn history(&self, filters: &[Filter]) -> Vec<Event> {
        let all = self.store.snapshot();
        let mut out: Vec<Event> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for filter in filters {
            let mut matched: Vec<Event> =
                all.iter().filter(|e| filter.matches(e)).cloned().collect();
            if let Some(lim) = filter.limit {
                if matched.len() > lim {
                    let start = matched.len() - lim;
                    matched = matched.split_off(start);
                }
            }
            for ev in matched {
                if seen.insert(ev.id.clone()) {
                    out.push(ev);
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests — schnorr path exercised via k256 SigningKey.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{signature::Signer, SigningKey};

    /// Deterministic signing key (seed = 0x42*32).
    fn test_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32]).expect("valid schnorr key")
    }

    fn make_event(kind: u64, created_at: u64, tags: Vec<Vec<String>>, content: &str) -> Event {
        let sk = test_sk();
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        let skeleton = Event {
            id: String::new(),
            pubkey: pubkey_hex.clone(),
            created_at,
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
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    #[test]
    fn verify_accepts_well_formed_signed_event() {
        let ev = make_event(1, 1_700_000_000, vec![], "hello");
        ev.verify().unwrap();
    }

    #[test]
    fn verify_rejects_tampered_content() {
        let mut ev = make_event(1, 1_700_000_000, vec![], "hello");
        ev.content = "tampered".into();
        assert!(matches!(ev.verify(), Err(RelayError::IdMismatch)));
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let mut ev = make_event(1, 1_700_000_000, vec![], "hello");
        // Flip a byte in the signature.
        let mut bytes = hex::decode(&ev.sig).unwrap();
        bytes[0] ^= 0x01;
        ev.sig = hex::encode(bytes);
        assert!(matches!(
            ev.verify(),
            Err(RelayError::BadSignature(_))
        ));
    }

    #[test]
    fn filter_matches_ids_and_authors() {
        let ev = make_event(1, 1_700_000_000, vec![], "hi");
        let filter = Filter {
            ids: Some(vec![ev.id.clone()]),
            authors: Some(vec![ev.pubkey.clone()]),
            kinds: Some(vec![1]),
            ..Default::default()
        };
        assert!(filter.matches(&ev));
    }

    #[test]
    fn filter_rejects_wrong_kind() {
        let ev = make_event(1, 1_700_000_000, vec![], "hi");
        let filter = Filter {
            kinds: Some(vec![7]),
            ..Default::default()
        };
        assert!(!filter.matches(&ev));
    }

    #[test]
    fn filter_matches_since_and_until() {
        let ev = make_event(1, 1_700_000_000, vec![], "hi");
        let ok = Filter {
            since: Some(1_699_999_000),
            until: Some(1_700_000_500),
            ..Default::default()
        };
        assert!(ok.matches(&ev));
        let late = Filter {
            since: Some(1_700_000_500),
            ..Default::default()
        };
        assert!(!late.matches(&ev));
    }

    #[test]
    fn filter_matches_tag_query_via_from_value() {
        let tags = vec![vec!["e".into(), "aaa".into()]];
        let ev = make_event(1, 1_700_000_000, tags, "hi");
        let v = serde_json::json!({"#e": ["aaa"]});
        let filter = Filter::from_value(v).unwrap();
        assert!(filter.matches(&ev));
    }

    #[test]
    fn filter_rejects_missing_tag() {
        let ev = make_event(1, 1_700_000_000, vec![], "hi");
        let v = serde_json::json!({"#p": ["xxx"]});
        let filter = Filter::from_value(v).unwrap();
        assert!(!filter.matches(&ev));
    }

    #[test]
    fn relay_accepts_nip01_event() {
        let relay = Relay::in_memory();
        let ev = make_event(1, 1_700_000_000, vec![], "hello");
        relay.ingest(ev.clone()).unwrap();
        let snap = relay.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, ev.id);
    }

    #[test]
    fn relay_rejects_bad_signature() {
        let relay = Relay::in_memory();
        let mut ev = make_event(1, 1_700_000_000, vec![], "hello");
        let mut sig = hex::decode(&ev.sig).unwrap();
        sig[1] ^= 0x01;
        ev.sig = hex::encode(sig);
        assert!(relay.ingest(ev).is_err());
    }

    #[test]
    fn replaceable_event_replaces_prior_nip16() {
        let relay = Relay::in_memory();
        // Kind 0 is metadata (replaceable).
        let a = make_event(0, 1_700_000_000, vec![], r#"{"name":"alice-v1"}"#);
        let b = make_event(0, 1_700_000_100, vec![], r#"{"name":"alice-v2"}"#);
        relay.ingest(a).unwrap();
        relay.ingest(b.clone()).unwrap();
        let snap = relay.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].content, r#"{"name":"alice-v2"}"#);
        assert_eq!(snap[0].id, b.id);
    }

    #[test]
    fn parameterised_replaceable_keyed_by_d_tag() {
        let relay = Relay::in_memory();
        let a = make_event(
            30_000,
            1_700_000_000,
            vec![vec!["d".into(), "slot-a".into()]],
            "v1",
        );
        let b = make_event(
            30_000,
            1_700_000_100,
            vec![vec!["d".into(), "slot-a".into()]],
            "v2",
        );
        let c = make_event(
            30_000,
            1_700_000_200,
            vec![vec!["d".into(), "slot-b".into()]],
            "other-slot",
        );
        relay.ingest(a).unwrap();
        relay.ingest(b.clone()).unwrap();
        relay.ingest(c.clone()).unwrap();
        let snap = relay.snapshot();
        // slot-a replaced; slot-b is a distinct entry.
        assert_eq!(snap.len(), 2);
        let slot_a = snap.iter().find(|e| e.d_tag() == Some("slot-a")).unwrap();
        assert_eq!(slot_a.content, "v2");
        let slot_b = snap.iter().find(|e| e.d_tag() == Some("slot-b")).unwrap();
        assert_eq!(slot_b.id, c.id);
    }

    #[test]
    fn ephemeral_event_not_stored_but_broadcast() {
        let relay = Relay::in_memory();
        let mut rx = relay.subscribe();
        // Kind 20000 is ephemeral.
        let ev = make_event(20_001, 1_700_000_000, vec![], "ephemeral");
        relay.ingest(ev.clone()).unwrap();
        assert_eq!(relay.snapshot().len(), 0);
        // try_recv because broadcast is sync-ish in tests.
        let received = rx.try_recv().unwrap();
        assert_eq!(received.id, ev.id);
    }

    #[test]
    fn history_applies_per_filter_limit() {
        let relay = Relay::in_memory();
        for i in 0..5 {
            let ev = make_event(1, 1_700_000_000 + i, vec![], &format!("msg-{i}"));
            relay.ingest(ev).unwrap();
        }
        let filter = Filter {
            kinds: Some(vec![1]),
            limit: Some(2),
            ..Default::default()
        };
        let hist = relay.history(&[filter]);
        assert_eq!(hist.len(), 2);
        // Latest events are retained at the tail.
        assert_eq!(hist[0].content, "msg-3");
        assert_eq!(hist[1].content, "msg-4");
    }

    #[test]
    fn in_memory_store_evicts_oldest_when_full() {
        let store = InMemoryEventStore::new(2);
        let a = make_event(1, 1_700_000_000, vec![], "a");
        let b = make_event(1, 1_700_000_001, vec![], "b");
        let c = make_event(1, 1_700_000_002, vec![], "c");
        store.put(a.clone());
        store.put(b.clone());
        store.put(c.clone());
        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, b.id);
        assert_eq!(snap[1].id, c.id);
    }

    #[test]
    fn classifiers_cover_spec_ranges() {
        assert!(is_replaceable(0));
        assert!(is_replaceable(3));
        assert!(is_replaceable(10_000));
        assert!(is_replaceable(19_999));
        assert!(!is_replaceable(20_000));

        assert!(is_ephemeral(20_000));
        assert!(is_ephemeral(29_999));
        assert!(!is_ephemeral(30_000));

        assert!(is_parameterised_replaceable(30_000));
        assert!(is_parameterised_replaceable(39_999));
        assert!(!is_parameterised_replaceable(40_000));
    }

    #[test]
    fn relay_info_is_jss_compatible() {
        let info = RelayInfo::jss_compatible();
        assert!(info.supported_nips.contains(&1));
        assert!(info.supported_nips.contains(&11));
        assert!(info.supported_nips.contains(&16));
    }
}
