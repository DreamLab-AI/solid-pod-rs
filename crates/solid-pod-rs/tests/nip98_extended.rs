//! Sprint 6 E — deepen NIP-98 coverage.
//!
//! The existing `auth::nip98` tests exercise structural rejects but
//! leave the skew-window boundary, the payload-hash mismatch at both
//! sides, and the method-tag mismatch uncovered in the integration
//! suite. This file fills those gaps by building real Schnorr-signed
//! events (the helper mirrors the in-module `valid_event` so the tests
//! run from the public API surface).
//!
//! Run with:
//! ```bash
//! cargo test -p solid-pod-rs --features nip98-schnorr,jss-v04 \
//!   --test nip98_extended
//! ```

#![cfg(feature = "nip98-schnorr")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use solid_pod_rs::auth::nip98::{
    authorization_header, compute_event_id, verify_at, Nip98Event,
};
use solid_pod_rs::PodError;

// TIMESTAMP_TOLERANCE is a private const in auth::nip98. The value (60s)
// is documented and stable — kept in sync here. If it ever moves, the
// tests below will fail fast with a clear "outside/inside window"
// assertion error.
const TIMESTAMP_TOLERANCE: u64 = 60;

// ---------------------------------------------------------------------------
// Helpers: build a canonically-hashed, Schnorr-signed event.
// Mirrors the private `valid_event` helper inside auth::nip98.
// ---------------------------------------------------------------------------

fn test_signing_key() -> (k256::schnorr::SigningKey, String) {
    let seed = [0x42u8; 32];
    let sk = k256::schnorr::SigningKey::from_bytes(&seed)
        .expect("deterministic seed produces valid Schnorr signing key");
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pubkey_hex)
}

fn encode_event(event: &serde_json::Value) -> String {
    BASE64.encode(serde_json::to_string(event).unwrap().as_bytes())
}

fn build_event(
    url: &str,
    method: &str,
    ts: u64,
    body: Option<&[u8]>,
) -> serde_json::Value {
    let (sk, pubkey) = test_signing_key();
    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(b) = body {
        tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(b))]);
    }
    let skeleton = Nip98Event {
        id: String::new(),
        pubkey: pubkey.clone(),
        created_at: ts,
        kind: 27235,
        tags: tags.clone(),
        content: String::new(),
        sig: String::new(),
    };
    let id = compute_event_id(&skeleton);
    let id_bytes: Vec<u8> = hex::decode(&id).expect("id is valid hex");
    let sig = {
        use k256::schnorr::signature::Signer;
        let signature: k256::schnorr::Signature = sk.sign(&id_bytes);
        hex::encode(signature.to_bytes())
    };
    serde_json::json!({
        "id": id,
        "pubkey": pubkey,
        "created_at": ts,
        "kind": 27235,
        "tags": tags,
        "content": "",
        "sig": sig,
    })
}

// ---------------------------------------------------------------------------
// 1. Skew window — event ts outside (TIMESTAMP_TOLERANCE + 1) is rejected.
// ---------------------------------------------------------------------------

#[test]
fn nip98_skew_window_enforced() {
    let ts_event = 1_700_000_000u64;
    let ev = build_event("https://a.example/r", "GET", ts_event, None);
    let hdr = authorization_header(&encode_event(&ev));

    // Now is (TIMESTAMP_TOLERANCE + 1) seconds ahead — strictly outside
    // the tolerance window → Err.
    let now_ahead = ts_event + TIMESTAMP_TOLERANCE + 1;
    let err =
        verify_at(&hdr, "https://a.example/r", "GET", None, now_ahead).unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(format!("{err}").contains("timestamp"));

    // Symmetric: now is (TIMESTAMP_TOLERANCE + 1) seconds behind → Err.
    let now_behind = ts_event - TIMESTAMP_TOLERANCE - 1;
    let err =
        verify_at(&hdr, "https://a.example/r", "GET", None, now_behind).unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
}

// ---------------------------------------------------------------------------
// 2. Skew window — event ts within (TIMESTAMP_TOLERANCE - 1) is accepted.
// ---------------------------------------------------------------------------

#[test]
fn nip98_skew_within_window_accepted() {
    let ts_event = 1_700_000_000u64;
    let ev = build_event("https://a.example/r", "GET", ts_event, None);
    let hdr = authorization_header(&encode_event(&ev));

    // +TIMESTAMP_TOLERANCE-1 → accepted.
    let now_ahead = ts_event + TIMESTAMP_TOLERANCE - 1;
    let v = verify_at(&hdr, "https://a.example/r", "GET", None, now_ahead)
        .expect("within window must accept");
    assert_eq!(v.url, "https://a.example/r");
    assert_eq!(v.method, "GET");

    // -TIMESTAMP_TOLERANCE+1 → also accepted.
    let now_behind = ts_event - (TIMESTAMP_TOLERANCE - 1);
    verify_at(&hdr, "https://a.example/r", "GET", None, now_behind)
        .expect("within window (past) must accept");
}

// ---------------------------------------------------------------------------
// 3. Payload hash required when present — tag matches body → accept,
//    tag mismatches → reject.
// ---------------------------------------------------------------------------

#[test]
fn nip98_payload_hash_required_when_present() {
    let ts = 1_700_000_000u64;
    let body = b"{\"hello\":\"world\"}" as &[u8];

    // (a) Event was built over `body`; request carries same body → OK
    //     + verified hash echoed.
    let ev = build_event("https://a.example/r", "POST", ts, Some(body));
    let hdr = authorization_header(&encode_event(&ev));
    let v = verify_at(&hdr, "https://a.example/r", "POST", Some(body), ts)
        .expect("matching body hash must accept");
    let expected_hash = hex::encode(Sha256::digest(body));
    assert_eq!(
        v.payload_hash.as_deref(),
        Some(expected_hash.as_str()),
        "verifier echoes the hash from the payload tag"
    );

    // (b) Event was built over `body`; request carries a DIFFERENT body
    //     of the same length → tag mismatch → reject with a Nip98 error.
    let tampered = b"{\"hello\":\"evil!\"}" as &[u8];
    assert_eq!(tampered.len(), body.len(), "same-length tamper stays out of length-guard");
    let err =
        verify_at(&hdr, "https://a.example/r", "POST", Some(tampered), ts).unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(
        format!("{err}").to_lowercase().contains("payload"),
        "error must identify the payload-hash mismatch: {err}"
    );
}

// ---------------------------------------------------------------------------
// 4. Method tag mismatch — event.tags[method]=GET but request is POST.
// ---------------------------------------------------------------------------

#[test]
fn nip98_method_tag_mismatch_rejected() {
    let ts = 1_700_000_000u64;
    // Event claims method=GET.
    let ev = build_event("https://a.example/r", "GET", ts, None);
    let hdr = authorization_header(&encode_event(&ev));
    // Server receives a POST for the same URL → method mismatch.
    let err = verify_at(&hdr, "https://a.example/r", "POST", None, ts).unwrap_err();
    assert!(matches!(err, PodError::Nip98(_)));
    assert!(
        format!("{err}").to_lowercase().contains("method"),
        "error must identify the method mismatch: {err}"
    );
}
