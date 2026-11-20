//! F5 (Sprint 4) — DPoP `jti` replay cache integration tests.
//!
//! Validates [`solid_pod_rs::oidc::replay::DpopReplayCache`] against
//! the Solid-OIDC §5.2 / RFC 9449 §4.3 replay requirements, plus the
//! `verify_dpop_proof` ↔ cache integration (backward compat with
//! `None`, detection with `Some`).
//!
//! Run with:
//! ```bash
//! cargo test -p solid-pod-rs --features dpop-replay-cache dpop_replay
//! ```

#![cfg(feature = "dpop-replay-cache")]

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::oidc::{
    replay::{DpopReplayCache, ReplayError, DEFAULT_MAX_SIZE, DEFAULT_TTL_SECS},
    verify_dpop_proof, DpopClaims, Jwk,
};

// ---------------------------------------------------------------------------
// Helpers — build HS256-signed DPoP proofs with arbitrary jti values.
// ---------------------------------------------------------------------------

fn test_jwk(secret: &[u8]) -> Jwk {
    Jwk {
        kty: "oct".into(),
        alg: Some("HS256".into()),
        kid: None,
        use_: None,
        crv: None,
        x: None,
        y: None,
        n: None,
        e: None,
        k: Some(BASE64_URL.encode(secret)),
    }
}

fn build_dpop_proof(secret: &[u8], jwk: &Jwk, htu: &str, htm: &str, iat: u64, jti: &str) -> String {
    // jsonwebtoken does not let us set `typ` + `jwk` object together
    // via the `Header` struct, so assemble the header + body manually
    // and sign with HMAC-SHA256 directly. (Pre-Sprint-5 this helper
    // spliced a signature produced from a *different* signing input,
    // which only worked because the pod never verified signatures.
    // P0-1 now requires the signature to cryptographically match.)
    let header_json = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "HS256",
        "jwk": jwk,
    });
    let header_b64 = BASE64_URL.encode(serde_json::to_string(&header_json).unwrap());

    let claims = DpopClaims {
        htu: htu.to_string(),
        htm: htm.to_string(),
        iat,
        jti: jti.to_string(),
        ath: None,
    };
    let body_b64 = BASE64_URL.encode(serde_json::to_string(&claims).unwrap());

    let signing_input = format!("{header_b64}.{body_b64}");
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = BASE64_URL.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

// ---------------------------------------------------------------------------
// F5a — first-seen jti accepted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5a_first_seen_jti_is_accepted() {
    let cache = DpopReplayCache::with_config(Duration::from_secs(60), 128);
    let jti = "jti-fresh-0001";
    cache
        .check_and_record(jti)
        .await
        .expect("first-seen jti must be accepted");
    assert_eq!(cache.len().await, 1);
}

// ---------------------------------------------------------------------------
// F5b — replay within TTL rejected with Replayed error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5b_replay_within_ttl_is_rejected() {
    let cache = DpopReplayCache::with_config(Duration::from_secs(60), 128);
    let jti = "jti-replay-0002";
    cache.check_and_record(jti).await.unwrap();

    let err = cache.check_and_record(jti).await.unwrap_err();
    match err {
        ReplayError::Replayed { ttl } => assert_eq!(ttl, Duration::from_secs(60)),
        other @ ReplayError::CapacityExhausted { .. } => panic!("unexpected: {other}"),
    }

    // Replay must NOT refresh the entry (size stays at 1).
    assert_eq!(cache.len().await, 1);
}

// ---------------------------------------------------------------------------
// F5c — replay after TTL expiry is accepted again
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5c_replay_after_ttl_is_accepted() {
    // 10ms TTL for test speed.
    let cache = DpopReplayCache::with_config(Duration::from_millis(10), 128);
    let jti = "jti-expire-0003";

    cache.check_and_record(jti).await.unwrap();
    // Wait past TTL.
    tokio::time::sleep(Duration::from_millis(25)).await;
    // Same jti — but first-seen is now expired, so accepted as fresh.
    cache
        .check_and_record(jti)
        .await
        .expect("post-TTL submission must be accepted");

    // Entry count is still 1 (overwrite, not append).
    assert_eq!(cache.len().await, 1);
}

// ---------------------------------------------------------------------------
// F5d — max_size: a full cache refuses new jtis; it never evicts a live one
// (AW1-05, the policy NIP-98 adopted in ADR-2006)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5d_full_cache_refuses_new_jti_and_keeps_every_live_one() {
    let max = 4usize;
    let cache = DpopReplayCache::with_config(Duration::from_secs(60), max);

    for i in 0..max {
        cache
            .check_and_record(&format!("jti-cap-{i:04}"))
            .await
            .unwrap();
    }

    // One more distinct jti: evicting the oldest would reopen its replay
    // window, so the newcomer is refused instead.
    let err = cache
        .check_and_record("jti-cap-overflow")
        .await
        .expect_err("a full cache of live entries must refuse, not evict");
    assert!(matches!(
        err,
        ReplayError::CapacityExhausted { capacity: 4, .. }
    ));
    assert_eq!(cache.len().await, max);

    // The oldest live jti is still remembered: replaying it is still caught.
    let replay = cache.check_and_record("jti-cap-0000").await.unwrap_err();
    assert!(matches!(replay, ReplayError::Replayed { .. }));
}

#[tokio::test]
async fn f5d_expired_entries_are_reclaimed_to_admit_a_new_jti() {
    let cache = DpopReplayCache::with_config(Duration::from_millis(10), 2);
    cache.check_and_record("a").await.unwrap();
    cache.check_and_record("b").await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    // Both are past TTL, so they can no longer be replayed and may go.
    cache
        .check_and_record("c")
        .await
        .expect("expired entries free their slots");
    assert!(cache.len().await <= 2);
}

// ---------------------------------------------------------------------------
// F5e — concurrent check_and_record with same jti: exactly one wins
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f5e_concurrent_same_jti_exactly_one_wins() {
    let cache = Arc::new(DpopReplayCache::with_config(Duration::from_secs(60), 1024));
    let jti = "jti-race-0005".to_string();

    // Spawn N tasks that all try to record the same jti.
    let n = 32usize;
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let c = Arc::clone(&cache);
        let j = jti.clone();
        handles.push(tokio::spawn(async move { c.check_and_record(&j).await }));
    }

    let mut ok_count = 0;
    let mut replay_count = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(()) => ok_count += 1,
            Err(ReplayError::Replayed { .. }) => replay_count += 1,
            Err(other) => panic!("unexpected: {other}"),
        }
    }

    assert_eq!(ok_count, 1, "exactly one winner in a race");
    assert_eq!(replay_count, n - 1, "all others see Replayed");
    assert_eq!(cache.len().await, 1);
}

// ---------------------------------------------------------------------------
// F5f — verify_dpop_proof with None replay_cache preserves pre-F5
//        behaviour (backward compat): no replay detection.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5f_verify_dpop_with_none_cache_is_pre_f5_behaviour() {
    let secret = b"dpop-f5f-secret";
    let jwk = test_jwk(secret);
    let jkt = jwk.thumbprint().unwrap();

    let htu = "https://pod.example/resource";
    let now = 1_700_000_000u64;
    let proof = build_dpop_proof(secret, &jwk, htu, "GET", now, "jti-f5f-unique");

    // First call: accepted.
    let v1 = verify_dpop_proof(&proof, htu, "GET", now, 60, None)
        .await
        .unwrap();
    assert_eq!(v1.jkt, jkt);
    assert_eq!(v1.jti, "jti-f5f-unique");

    // Second call with the SAME proof + None cache: still accepted —
    // replay detection is disabled. This is intentional backward
    // compatibility.
    let v2 = verify_dpop_proof(&proof, htu, "GET", now, 60, None)
        .await
        .unwrap();
    assert_eq!(v2.jti, "jti-f5f-unique");
}

// ---------------------------------------------------------------------------
// F5g — verify_dpop_proof with Some(cache) detects a replay on the
//        second call and returns an error.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn f5g_verify_dpop_with_cache_rejects_replay() {
    let secret = b"dpop-f5g-secret";
    let jwk = test_jwk(secret);

    let htu = "https://pod.example/resource";
    let now = 1_700_000_000u64;
    let proof = build_dpop_proof(secret, &jwk, htu, "POST", now, "jti-f5g-unique");

    let cache = DpopReplayCache::with_config(Duration::from_secs(60), 64);

    // First submission: accepted, recorded.
    let v1 = verify_dpop_proof(&proof, htu, "POST", now, 60, Some(&cache))
        .await
        .unwrap();
    assert_eq!(v1.jti, "jti-f5g-unique");
    assert_eq!(cache.len().await, 1);

    // Second submission: replay, rejected.
    let err = verify_dpop_proof(&proof, htu, "POST", now, 60, Some(&cache))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("replay"),
        "error must identify the replay: {msg}"
    );
    // Cache length unchanged — replay does not refresh.
    assert_eq!(cache.len().await, 1);
}

// ---------------------------------------------------------------------------
// Bonus — evict_expired purges stale entries eagerly.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evict_expired_removes_stale_entries() {
    let cache = DpopReplayCache::with_config(Duration::from_millis(10), 16);
    for i in 0..5 {
        cache
            .check_and_record(&format!("jti-sweep-{i}"))
            .await
            .unwrap();
    }
    assert_eq!(cache.len().await, 5);

    tokio::time::sleep(Duration::from_millis(25)).await;

    let removed = cache.evict_expired().await;
    assert_eq!(removed, 5);
    assert_eq!(cache.len().await, 0);
}

#[tokio::test]
async fn defaults_match_ddd_contract() {
    // Sanity: the public constants match the DDD-documented defaults.
    assert_eq!(DEFAULT_TTL_SECS, 60);
    assert_eq!(DEFAULT_MAX_SIZE, 10_000);
}
