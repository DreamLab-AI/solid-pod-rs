//! NIP-98 structural-verification benchmarks.
//!
//! Measures the per-request amortised cost the pod pays when a client
//! sends an `Authorization: Nostr <base64-event>` header.
//!
//! Two scenarios:
//!
//! 1. **Valid** — a well-formed token with matching URL, method,
//!    timestamp, and (when a body is present) a matching payload hash.
//! 2. **Tampered body** — same token, but the body argument differs
//!    from the one the `payload` tag was computed over, so the
//!    verifier returns an error. Exercises the SHA-256 computation +
//!    hex compare.
//!
//! Run with:
//! ```bash
//! cargo bench -p solid-pod-rs --bench nip98_verify_bench
//! ```

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};
use solid_pod_rs::auth::nip98::{authorization_header, compute_event_id, verify_at, Nip98Event};

/// Deterministic keypair seed. Under `nip98-schnorr` this produces a
/// real BIP-340 signing key; without the feature the pubkey is the
/// legacy `"a".repeat(64)` placeholder and the sig is all zeros.
#[cfg(feature = "nip98-schnorr")]
fn bench_keypair() -> (k256::schnorr::SigningKey, String) {
    let seed = [0x42u8; 32];
    let sk = k256::schnorr::SigningKey::from_bytes(&seed)
        .expect("seed produces valid Schnorr signing key");
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, pubkey_hex)
}

#[cfg(not(feature = "nip98-schnorr"))]
fn bench_pubkey() -> String {
    "a".repeat(64)
}

#[cfg(feature = "nip98-schnorr")]
fn bench_pubkey() -> String {
    bench_keypair().1
}

fn build_header(url: &str, method: &str, ts: u64, body: Option<&[u8]>) -> String {
    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(b))]);
    }

    let pubkey = bench_pubkey();

    // Compute the canonical NIP-01 event id.
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

    // Sign when `nip98-schnorr` is enabled, otherwise use placeholder.
    let sig = {
        #[cfg(feature = "nip98-schnorr")]
        {
            let (sk, _) = bench_keypair();
            let id_bytes = hex::decode(&id).expect("id is valid hex");
            let signature: k256::schnorr::Signature =
                sk.sign_raw(&id_bytes, &[0u8; 32]).expect("sign_raw");
            hex::encode(signature.to_bytes())
        }
        #[cfg(not(feature = "nip98-schnorr"))]
        {
            "0".repeat(128)
        }
    };

    let event = serde_json::json!({
        "id":         id,
        "pubkey":     pubkey,
        "created_at": ts,
        "kind":       27235,
        "tags":       tags,
        "content":    "",
        "sig":        sig,
    });
    let b64 = BASE64.encode(serde_json::to_string(&event).unwrap());
    authorization_header(&b64)
}

fn bench_valid(c: &mut Criterion) {
    let url = "https://pod.example/public/thing.ttl";
    let ts = 1_700_000_000u64;
    let header = build_header(url, "GET", ts, None);

    c.bench_function("nip98_verify_valid_no_body", |b| {
        b.iter(|| {
            let r = verify_at(
                black_box(&header),
                black_box(url),
                black_box("GET"),
                black_box(None),
                black_box(ts),
            );
            debug_assert!(r.is_ok());
            black_box(r.ok());
        });
    });

    // With body — exercises the SHA-256 payload comparison.
    let body = b"@prefix ex: <https://ex.org/> . ex:a ex:p \"v\" .";
    let header_put = build_header(url, "PUT", ts, Some(body));
    c.bench_function("nip98_verify_valid_with_body", |b| {
        b.iter(|| {
            let r = verify_at(
                black_box(&header_put),
                black_box(url),
                black_box("PUT"),
                black_box(Some(body.as_slice())),
                black_box(ts),
            );
            debug_assert!(r.is_ok());
            black_box(r.ok());
        });
    });
}

fn bench_tampered(c: &mut Criterion) {
    let url = "https://pod.example/public/thing.ttl";
    let ts = 1_700_000_000u64;
    let original = b"@prefix ex: <https://ex.org/> . ex:a ex:p \"v\" .";
    let tampered = b"@prefix ex: <https://ex.org/> . ex:a ex:p \"EVIL\" .";
    let header = build_header(url, "PUT", ts, Some(original));

    c.bench_function("nip98_verify_tampered_body", |b| {
        b.iter(|| {
            let r = verify_at(
                black_box(&header),
                black_box(url),
                black_box("PUT"),
                black_box(Some(tampered.as_slice())),
                black_box(ts),
            );
            debug_assert!(r.is_err());
            black_box(r.err());
        });
    });
}

criterion_group!(benches, bench_valid, bench_tampered);
criterion_main!(benches);
