//! ADR-2007 acceptance — mempool endpoint selection is explicit and recorded.
//!
//! The finding these tests close: the server picked a mempool base URL (and
//! therefore a Bitcoin network) from `JSS_PAY_MEMPOOL_URL`, silently falling
//! back to the testnet4 explorer, and recorded that choice nowhere. An operator
//! could not tell from a log or a manifest whether the pod was anchoring
//! against mainnet, testnet4, or an operator-supplied explorer.
//!
//! Two properties are covered here:
//!
//! 1. **Selection is a pure, inspectable value.** [`select_mempool_endpoint`]
//!    resolves URL + network + provenance without touching the environment or
//!    the network, and [`MempoolSelection::to_manifest_json`] renders it.
//! 2. **Unavailability stays distinguishable from a definite negative.**
//!    `transaction_exists` must keep returning `Ok(false)` only for an HTTP 404
//!    (the transaction is genuinely unknown) and `Err` for a 5xx/transport
//!    failure (ambiguous) — payment-intent recovery compensates a debit only on
//!    the former, so collapsing the two would refund against an unknown chain
//!    state. Driven against a local `wiremock` server; no real network access.
//!
//! No test here reads or writes `JSS_PAY_MEMPOOL_URL`: the pure
//! `Option<&str>`-driven selector is exercised instead, so these tests cannot
//! race any other test that manipulates process-wide environment variables.

use solid_pod_rs_server::mempool::{
    infer_network, select_mempool_endpoint, BitcoinNetwork, MempoolConfigSource, MempoolHttpClient,
    DEFAULT_MEMPOOL_URL,
};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A syntactically plausible txid for the mock paths (never broadcast).
const TXID: &str = "ab8f1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff";

// ── (a) Empty config → the testnet4 default, marked as defaulted ────────

#[tokio::test]
async fn absent_config_yields_defaulted_testnet4() {
    let sel = select_mempool_endpoint(None);
    assert_eq!(
        sel.base_url, DEFAULT_MEMPOOL_URL,
        "no configuration must fall back to the documented default"
    );
    assert_eq!(
        sel.source,
        MempoolConfigSource::Default,
        "the fallback must be recorded as defaulted, not passed off as a choice"
    );
    assert_eq!(
        sel.network,
        BitcoinNetwork::Testnet4,
        "the default explorer is testnet4 and must be labelled as such"
    );
}

#[tokio::test]
async fn whitespace_only_config_is_treated_as_absent() {
    let sel = select_mempool_endpoint(Some("  "));
    assert_eq!(sel.base_url, DEFAULT_MEMPOOL_URL);
    assert_eq!(sel.source, MempoolConfigSource::Default);
    assert_eq!(sel.network, BitcoinNetwork::Testnet4);

    // An empty string is the same case (the historical env filter behaviour).
    let empty = select_mempool_endpoint(Some(""));
    assert_eq!(empty, sel, "empty and whitespace-only must resolve alike");
}

// ── (b) Explicit config → trimmed base, Explicit source, inferred network ─

#[tokio::test]
async fn explicit_config_is_marked_explicit_and_trimmed() {
    let sel = select_mempool_endpoint(Some("https://explorer.example.org/testnet4"));
    assert_eq!(sel.base_url, "https://explorer.example.org/testnet4");
    assert_eq!(sel.source, MempoolConfigSource::Explicit);
    assert_eq!(sel.network, BitcoinNetwork::Testnet4);

    // A trailing slash must not change the base or the classification.
    let slashed = select_mempool_endpoint(Some("https://explorer.example.org/testnet4/"));
    assert_eq!(
        slashed, sel,
        "a trailing '/' must be trimmed so {{base}}/api/... joins cleanly"
    );

    // Surrounding whitespace is trimmed but does not make the value absent.
    let padded = select_mempool_endpoint(Some("  https://explorer.example.org/testnet4  "));
    assert_eq!(padded, sel);
}

#[tokio::test]
async fn explicit_default_url_is_still_explicit() {
    // Configuring the default URL by hand is a choice, not a fallback.
    let sel = select_mempool_endpoint(Some(DEFAULT_MEMPOOL_URL));
    assert_eq!(sel.base_url, DEFAULT_MEMPOOL_URL);
    assert_eq!(sel.network, BitcoinNetwork::Testnet4);
    assert_eq!(
        sel.source,
        MempoolConfigSource::Explicit,
        "an operator-supplied URL is Explicit even when it equals the default"
    );
}

#[tokio::test]
async fn infer_network_classifies_known_bases() {
    assert_eq!(
        infer_network("https://mempool.space"),
        BitcoinNetwork::Mainnet
    );
    assert_eq!(
        infer_network("https://mempool.space/"),
        BitcoinNetwork::Mainnet,
        "a bare host with a trailing slash is still mainnet"
    );
    assert_eq!(
        infer_network("https://mempool.space/testnet4"),
        BitcoinNetwork::Testnet4
    );
    assert_eq!(
        infer_network("https://mempool.space/testnet3"),
        BitcoinNetwork::Testnet3
    );
    assert_eq!(
        infer_network("https://mempool.space/testnet"),
        BitcoinNetwork::Testnet3,
        "the legacy '/testnet' path is testnet3"
    );
    assert_eq!(
        infer_network("https://mempool.space/signet"),
        BitcoinNetwork::Signet
    );
    // Case-insensitive on the trailing segment.
    assert_eq!(
        infer_network("https://mempool.space/TestNet4"),
        BitcoinNetwork::Testnet4
    );
}

#[tokio::test]
async fn infer_network_treats_loopback_as_regtest() {
    assert_eq!(
        infer_network("http://127.0.0.1:3006"),
        BitcoinNetwork::Regtest
    );
    assert_eq!(
        infer_network("http://localhost:3006"),
        BitcoinNetwork::Regtest
    );
    // ...unless the path names a network explicitly.
    assert_eq!(
        infer_network("http://localhost:3006/signet"),
        BitcoinNetwork::Signet,
        "an explicit network path must beat the loopback heuristic"
    );
}

#[tokio::test]
async fn infer_network_never_guesses_mainnet() {
    // An unrecognised operator explorer must NOT be assumed to be mainnet:
    // guessing here is exactly the silent-wrong-chain risk ADR-2007 closes.
    assert_eq!(
        infer_network("https://explorer.example.org"),
        BitcoinNetwork::Unknown
    );
    assert_eq!(
        infer_network("https://explorer.example.org/api/v2"),
        BitcoinNetwork::Unknown
    );
    assert_eq!(infer_network(""), BitcoinNetwork::Unknown);

    // And the selection carries that Unknown through unchanged.
    let sel = select_mempool_endpoint(Some("https://explorer.example.org/api/v2"));
    assert_eq!(sel.network, BitcoinNetwork::Unknown);
    assert_eq!(sel.source, MempoolConfigSource::Explicit);
}

// ── (c) Manifest shape ──────────────────────────────────────────────────

#[tokio::test]
async fn manifest_json_carries_url_network_and_source() {
    let defaulted = select_mempool_endpoint(None).to_manifest_json();
    assert_eq!(defaulted["base_url"], DEFAULT_MEMPOOL_URL);
    assert_eq!(defaulted["network"], "testnet4");
    assert_eq!(defaulted["source"], "default");

    let explicit = select_mempool_endpoint(Some("https://mempool.space/")).to_manifest_json();
    assert_eq!(explicit["base_url"], "https://mempool.space");
    assert_eq!(explicit["network"], "mainnet");
    assert_eq!(explicit["source"], "explicit");

    // Exactly the three documented keys, nothing else.
    let obj = explicit
        .as_object()
        .expect("manifest JSON must be an object");
    assert_eq!(
        obj.len(),
        3,
        "manifest keys: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
    for key in ["base_url", "network", "source"] {
        assert!(obj.contains_key(key), "manifest must contain {key}");
    }
}

#[tokio::test]
async fn client_records_its_selection() {
    // A client built against an explicit base exposes the same facts, and
    // base_url() keeps returning the trimmed string it always did.
    let client = MempoolHttpClient::new("https://mempool.space/signet/");
    assert_eq!(client.base_url(), "https://mempool.space/signet");
    let sel = client.selection();
    assert_eq!(sel.base_url, "https://mempool.space/signet");
    assert_eq!(sel.network, BitcoinNetwork::Signet);
    assert_eq!(sel.source, MempoolConfigSource::Explicit);
    assert_eq!(sel.to_manifest_json()["network"], "signet");
}

// ── (d)/(e)/(f) Unknown transaction vs ambiguous unavailability ──────────

/// Stand up a local mock explorer answering `GET /api/tx/{TXID}` with `status`,
/// and return a client pointed at it. No real network access.
async fn mock_explorer(status: u16) -> (MockServer, MempoolHttpClient) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/tx/{TXID}")))
        .respond_with(ResponseTemplate::new(status).set_body_string("{}"))
        .mount(&server)
        .await;
    let client = MempoolHttpClient::new(server.uri());
    (server, client)
}

#[tokio::test]
async fn service_unavailable_is_ambiguous_not_a_definite_negative() {
    let (_server, client) = mock_explorer(503).await;
    let outcome = client.transaction_exists(TXID).await;
    assert!(
        outcome.is_err(),
        "a 503 must surface as Err (ambiguous), never Ok(false): got {outcome:?}"
    );
}

#[tokio::test]
async fn not_found_is_a_definite_negative_but_server_error_is_not() {
    // The whole point of the 404/5xx split: only the 404 licenses a caller to
    // conclude the transaction does not exist and compensate a debit.
    let (_ok_server, ok_client) = mock_explorer(404).await;
    let unknown = ok_client.transaction_exists(TXID).await;
    assert_eq!(
        unknown.as_ref().ok(),
        Some(&false),
        "404 must be Ok(false) — the transaction is definitively unknown: got {unknown:?}"
    );

    let (_bad_server, bad_client) = mock_explorer(503).await;
    let ambiguous = bad_client.transaction_exists(TXID).await;
    assert!(
        ambiguous.is_err(),
        "503 must be Err — availability is unknown, so existence is unknown: got {ambiguous:?}"
    );

    // Stated as the invariant itself: the two outcomes must not collapse.
    assert_ne!(
        unknown.is_err(),
        ambiguous.is_err(),
        "a definitively-unknown transaction and an unreachable explorer must \
         not produce the same result"
    );
}

#[tokio::test]
async fn ok_response_reports_the_transaction_as_known() {
    let (_server, client) = mock_explorer(200).await;
    assert!(
        client
            .transaction_exists(TXID)
            .await
            .expect("a 200 must not error"),
        "200 ⇒ the transaction is known"
    );
}

#[tokio::test]
async fn unreachable_explorer_is_ambiguous() {
    // A refused connection on loopback (nothing listens on port 1) is a
    // transport failure, which must be Err rather than a silent Ok(false).
    // Loopback only — no real network access.
    let client = MempoolHttpClient::new("http://127.0.0.1:1");
    assert!(
        client.transaction_exists(TXID).await.is_err(),
        "a transport failure must be ambiguous (Err), never Ok(false)"
    );
}
