//! ADR-2003 acceptance — executable checks for the Solid-OIDC
//! compatibility matrix.
//!
//! ADR-2003 ("Hold the OIDC wire at Solid-OIDC 0.1 and defer the LWS10
//! delta") was closed on *source observations* — file:line citations
//! into `src/oidc/mod.rs` — rather than executable checks. Its
//! closeout extension asks for a versioned discovery/verifier
//! compatibility matrix plus tests that pin the advertised algorithms,
//! the unsupported identity shapes, and issuer/audience/token binding.
//!
//! This file is the executable half of that pair. Its prose half is
//! [`docs/reference/solid-oidc-compatibility-matrix.md`]; every row of
//! that matrix that can be asserted in-process is asserted here, so
//! the document cannot silently drift away from the code.
//!
//! Sections mirror the matrix document:
//!
//! - **A. Discovery** — issuer normalisation, the exact emitted field
//!   set, absolute endpoint URLs, and the advertised algorithm lists.
//! - **B. Issuer validation** — exact-match semantics, including the
//!   trailing-slash, case and prefix/suffix near-misses.
//! - **C. Audience** — the crate does *not* validate `aud`
//!   (`validate_aud = false`); `aud` is nevertheless a *required*
//!   member of `SolidOidcClaims`, so a token omitting it fails to
//!   deserialise. Both halves are pinned here.
//! - **D. Unsupported identity shapes** — one assertion per refused
//!   shape, checking the concrete [`PodError`] variant.
//! - **E. Expiry** — the `exp < now` boundary.
//!
//! No network access: every token is minted in-process with a
//! test-only symmetric secret, exactly as the existing OIDC tests do.
//!
//! ```bash
//! cargo test -p solid-pod-rs --features oidc --test oidc_compat_matrix
//! cargo test -p solid-pod-rs \
//!     --features oidc,dpop-replay-cache,jss-v04 --test oidc_compat_matrix
//! ```

#![cfg(feature = "oidc")]

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk as JwtJwk, JwkSet, KeyAlgorithm, PublicKeyUse,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

use solid_pod_rs::error::PodError;
use solid_pod_rs::oidc::{
    discovery_for, extract_webid, verify_access_token, DiscoveryDocument, Jwk, SolidOidcClaims,
    TokenVerifyKey,
};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// Test-only HMAC secret. Production tokens are asymmetric; the
/// symmetric path exists so integration tests can mint their own
/// tokens without a network round trip (see `TokenVerifyKey` docs).
const SECRET: &[u8] = b"adr-2003-compat-matrix-secret";

const ISSUER: &str = "https://op.example";
const WEBID: &str = "https://me.example/profile#me";

/// A clock value comfortably inside every non-expired fixture below.
const NOW: u64 = 1_700_000_000;

fn symmetric_keyset() -> TokenVerifyKey {
    TokenVerifyKey::Symmetric(SECRET.to_vec())
}

/// Mint an HS256 JWT over an arbitrary claim object. Taking a
/// `serde_json::Value` (rather than `SolidOidcClaims`) is deliberate:
/// section D needs claim sets that the strongly-typed struct cannot
/// express — a missing `aud`, a blank `webid`, a non-URL `sub`.
fn mint_hs256(claims: &serde_json::Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("HS256 token encodes")
}

/// The canonical, fully-populated Solid-OIDC 0.1 claim set. Callers
/// mutate one member to isolate the shape under test.
fn base_claims(jkt: &str, exp: u64) -> serde_json::Value {
    json!({
        "iss": ISSUER,
        "sub": WEBID,
        "aud": "solid",
        "exp": exp,
        "iat": exp.saturating_sub(3600),
        "webid": WEBID,
        "client_id": "client-adr2003",
        "cnf": { "jkt": jkt },
        "scope": "openid webid",
    })
}

/// Forge a `alg=none` JWT with an empty signature segment.
fn forge_alg_none(claims: &serde_json::Value) -> String {
    let header = json!({ "typ": "JWT", "alg": "none" });
    let h = BASE64_URL.encode(serde_json::to_string(&header).expect("header serialises"));
    let b = BASE64_URL.encode(serde_json::to_string(claims).expect("claims serialise"));
    format!("{h}.{b}.")
}

/// A deterministic P-256 public JWK, used only to prove that an HS256
/// token is refused against an asymmetric keyset.
fn es256_public_jwk() -> JwtJwk {
    JwtJwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::ES256),
            key_id: Some("compat-matrix-es256".into()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            // Values are never used: dispatch refuses HS256 against an
            // asymmetric keyset before any key is touched.
            x: BASE64_URL.encode([0x11u8; 32]),
            y: BASE64_URL.encode([0x22u8; 32]),
        }),
    }
}

/// The `kty=oct` JWK a DPoP proof would embed on the test-only
/// symmetric path. Its RFC 7638 thumbprint is the `jkt` the pod binds
/// `cnf.jkt` against.
fn oct_jwk(secret: &[u8]) -> Jwk {
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

/// Assert the error is a [`PodError::Nip98`] whose message contains
/// `needle` (lower-cased comparison), returning the message so callers
/// can assert further.
#[track_caller]
fn expect_nip98(err: PodError, needle: &str) -> String {
    match err {
        PodError::Nip98(msg) => {
            assert!(
                msg.to_lowercase().contains(&needle.to_lowercase()),
                "expected Nip98 error containing {needle:?}, got: {msg}"
            );
            msg
        }
        other => panic!("expected PodError::Nip98, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// A. Discovery matrix
// ---------------------------------------------------------------------------

/// The exact member set `discovery_for` serialises. The matrix
/// document lists these fourteen and no others; a field added or
/// removed without updating the document trips this test.
const DISCOVERY_FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "introspection_endpoint",
    "scopes_supported",
    "response_types_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "dpop_signing_alg_values_supported",
    "solid_oidc_supported",
    "id_token_signing_alg_values_supported",
];

#[test]
fn a1_discovery_emits_exactly_the_documented_field_set() {
    let doc = discovery_for(ISSUER);
    let value = serde_json::to_value(&doc).expect("DiscoveryDocument serialises");
    let emitted: BTreeSet<String> = value
        .as_object()
        .expect("discovery document is a JSON object")
        .keys()
        .cloned()
        .collect();
    let documented: BTreeSet<String> = DISCOVERY_FIELDS.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        emitted, documented,
        "discovery field set drifted from docs/reference/solid-oidc-compatibility-matrix.md"
    );
}

#[test]
fn a2_discovery_normalises_trailing_slashes_on_the_issuer() {
    // `trim_end_matches('/')` strips *every* trailing slash, not just one.
    for raw in [
        "https://op.example",
        "https://op.example/",
        "https://op.example///",
    ] {
        let doc = discovery_for(raw);
        assert_eq!(
            doc.issuer, "https://op.example",
            "issuer normalisation failed for {raw:?}"
        );
    }

    // Normalisation is trailing-slash only: no case folding, no
    // scheme/host canonicalisation, no path collapsing.
    assert_eq!(
        discovery_for("HTTPS://OP.example").issuer,
        "HTTPS://OP.example"
    );
    assert_eq!(
        discovery_for("https://op.example/tenant/a").issuer,
        "https://op.example/tenant/a"
    );

    // Non-URL input is passed through verbatim — `discovery_for` is a
    // pure string builder and performs no URL validation.
    assert_eq!(discovery_for("not-a-url").issuer, "not-a-url");
}

#[test]
fn a3_discovery_endpoints_are_absolute_and_issuer_prefixed() {
    let doc: DiscoveryDocument = discovery_for("https://op.example/tenant/a/");
    let base = "https://op.example/tenant/a";
    assert_eq!(doc.issuer, base);

    let endpoints = [
        (&doc.authorization_endpoint, "/authorize"),
        (&doc.token_endpoint, "/token"),
        (&doc.userinfo_endpoint, "/userinfo"),
        (&doc.jwks_uri, "/jwks"),
        (&doc.registration_endpoint, "/register"),
        (&doc.introspection_endpoint, "/introspect"),
    ];
    for (got, suffix) in endpoints {
        assert_eq!(
            got,
            &format!("{base}{suffix}"),
            "endpoint is not `{{issuer}}{suffix}`"
        );
        assert!(
            got.starts_with("https://"),
            "endpoint must be an absolute URL, got {got}"
        );
    }
}

#[test]
fn a4_discovery_advertises_the_adr2003_algorithm_lists() {
    let doc = discovery_for(ISSUER);

    // ADR-2003: the wire stays at Solid-OIDC 0.1. DPoP advertises
    // ES256/RS256 only, even though the verifier accepts a wider set.
    assert_eq!(
        doc.dpop_signing_alg_values_supported,
        vec!["ES256", "RS256"]
    );
    assert_eq!(
        doc.id_token_signing_alg_values_supported,
        vec!["RS256", "ES256"]
    );
    assert_eq!(
        doc.solid_oidc_supported,
        vec!["https://solidproject.org/TR/solid-oidc"]
    );
    assert_eq!(
        doc.scopes_supported,
        vec!["openid", "profile", "webid", "offline_access"]
    );
    assert_eq!(doc.response_types_supported, vec!["code", "id_token"]);
    assert_eq!(
        doc.grant_types_supported,
        vec!["authorization_code", "refresh_token", "client_credentials"]
    );
    assert_eq!(
        doc.token_endpoint_auth_methods_supported,
        vec![
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
        ]
    );

    // ADR-2003 deferral of LWS-10: none of the LWS-10 delta fields are
    // advertised. This is the executable form of the ADR's "no
    // `lws_supported`, no EdDSA, no `iss` response flag" claim.
    let value = serde_json::to_value(&doc).expect("serialises");
    let obj = value.as_object().expect("object");
    for absent in [
        "lws_supported",
        "authorization_response_iss_parameter_supported",
        "pushed_authorization_request_endpoint",
        "require_pushed_authorization_requests",
        "code_challenge_methods_supported",
    ] {
        assert!(
            !obj.contains_key(absent),
            "{absent} must stay unadvertised while LWS-10 is deferred"
        );
    }
    assert!(
        !doc.dpop_signing_alg_values_supported
            .iter()
            .any(|a| a == "EdDSA"),
        "discovery must not advertise EdDSA while LWS-10 is deferred"
    );
}

// ---------------------------------------------------------------------------
// B. Issuer validation
// ---------------------------------------------------------------------------

#[test]
fn b1_issuer_match_verifies() {
    let token = mint_hs256(&base_claims("JKT-B1", NOW + 3600));
    let verified = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-B1", NOW)
        .expect("matching issuer verifies");
    assert_eq!(verified.iss, ISSUER);
    assert_eq!(verified.webid, WEBID);
    assert_eq!(verified.jkt, "JKT-B1");
    assert_eq!(verified.client_id.as_deref(), Some("client-adr2003"));
    assert_eq!(verified.scope.as_deref(), Some("openid webid"));
    assert_eq!(verified.exp, NOW + 3600);
}

#[test]
fn b2_issuer_comparison_is_exact_string_equality() {
    let token = mint_hs256(&base_claims("JKT-B2", NOW + 3600));

    // Every one of these is a near-miss on `iss = "https://op.example"`.
    // `Validation::set_issuer` performs set membership over the raw
    // string, so none of them are treated as equivalent.
    let near_misses = [
        // Wholly different issuer.
        "https://other.example",
        // Trailing slash — NOT normalised by the verifier (unlike
        // `discovery_for`, which trims it on the way out).
        "https://op.example/",
        // Case difference in host.
        "https://OP.example",
        "https://op.EXAMPLE",
        // Suffix-extension / lookalike domain.
        "https://op.example.evil",
        // Prefix of the real issuer.
        "https://op.exampl",
        // Scheme downgrade.
        "http://op.example",
        // Path-suffixed tenant.
        "https://op.example/tenant/a",
        // Empty expectation.
        "",
    ];

    for expected in near_misses {
        let err = match verify_access_token(&token, &symmetric_keyset(), expected, "JKT-B2", NOW) {
            Ok(v) => panic!("near-miss issuer {expected:?} must be rejected, got {v:?}"),
            Err(e) => e,
        };
        let msg = expect_nip98(err, "access token decode failed");
        assert!(
            msg.to_lowercase().contains("issuer"),
            "rejection for {expected:?} should name the issuer, got: {msg}"
        );
    }
}

#[test]
fn b3_discovery_normalised_issuer_round_trips_into_the_verifier() {
    // The documented safe wiring: normalise once via `discovery_for`,
    // then use `doc.issuer` for both minting and verification.
    let doc = discovery_for("https://op.example/");
    let claims = json!({
        "iss": doc.issuer,
        "sub": WEBID,
        "aud": "solid",
        "exp": NOW + 3600,
        "iat": NOW,
        "webid": WEBID,
        "cnf": { "jkt": "JKT-B3" },
    });
    let token = mint_hs256(&claims);
    let verified = verify_access_token(&token, &symmetric_keyset(), &doc.issuer, "JKT-B3", NOW)
        .expect("normalised issuer verifies");
    assert_eq!(verified.iss, "https://op.example");
    // …and the un-normalised form of the same issuer does not.
    assert!(
        verify_access_token(
            &token,
            &symmetric_keyset(),
            "https://op.example/",
            "JKT-B3",
            NOW
        )
        .is_err(),
        "the verifier does not normalise trailing slashes"
    );
}

// ---------------------------------------------------------------------------
// C. Audience — pinning the ACTUAL behaviour
// ---------------------------------------------------------------------------

#[test]
fn c1_audience_is_not_validated() {
    // `verify_access_token` sets `validation.validate_aud = false`
    // ("Solid-OIDC allows arbitrary aud"). No expected-audience
    // parameter exists on the API, so ANY `aud` value verifies. This
    // is documented as a known gap in the matrix's verifier table, not
    // as a feature.
    let audiences = [
        json!("solid"),
        json!("https://some.other.pod.example"),
        json!(["https://a.example", "https://b.example"]),
        json!([]),
        json!(""),
        json!(12345),
        json!(null),
    ];
    for (i, aud) in audiences.iter().enumerate() {
        let mut claims = base_claims("JKT-C1", NOW + 3600);
        claims["aud"] = aud.clone();
        let token = mint_hs256(&claims);
        let verified = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-C1", NOW)
            .unwrap_or_else(|e| panic!("aud case {i} ({aud}) should verify, got: {e}"));
        assert_eq!(verified.webid, WEBID);
    }
}

#[test]
fn c2_audience_member_is_structurally_required() {
    // The flip side of C1: `SolidOidcClaims::aud` carries no
    // `#[serde(default)]`, so a token that OMITS `aud` entirely fails
    // to deserialise. Absence is rejected; content is unchecked.
    let mut claims = base_claims("JKT-C2", NOW + 3600);
    claims
        .as_object_mut()
        .expect("object")
        .remove("aud")
        .expect("aud present in the base fixture");
    let token = mint_hs256(&claims);

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-C2", NOW)
        .expect_err("a token without `aud` cannot be deserialised");
    expect_nip98(err, "access token decode failed");
}

// ---------------------------------------------------------------------------
// D. Unsupported identity shapes
// ---------------------------------------------------------------------------

#[test]
fn d1_missing_webid_claim_with_non_url_sub_is_refused() {
    let mut claims = base_claims("JKT-D1", NOW + 3600);
    let obj = claims.as_object_mut().expect("object");
    obj.remove("webid");
    obj.insert("sub".into(), json!("0xabc-opaque-subject"));
    let token = mint_hs256(&claims);

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D1", NOW)
        .expect_err("no WebID is derivable");
    expect_nip98(err, "no WebID present in access token");
}

#[test]
fn d2_blank_webid_claim_falls_back_to_a_url_shaped_sub() {
    // Documented actual behaviour (and a mild surprise): a blank or
    // otherwise non-URL `webid` claim is NOT an error — it is skipped,
    // and `sub` is consulted instead. Only when BOTH fail the
    // `http://` / `https://` prefix test is the token refused.
    for blank in ["", "   ", "not-a-url"] {
        let mut claims = base_claims("JKT-D2", NOW + 3600);
        claims["webid"] = json!(blank);
        let token = mint_hs256(&claims);
        let verified = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D2", NOW)
            .unwrap_or_else(|e| panic!("webid {blank:?} should fall back to sub, got: {e}"));
        assert_eq!(
            verified.webid, WEBID,
            "fallback must yield the URL-shaped sub"
        );
    }
}

#[test]
fn d3_blank_webid_and_non_url_sub_is_refused() {
    let mut claims = base_claims("JKT-D3", NOW + 3600);
    let obj = claims.as_object_mut().expect("object");
    obj.insert("webid".into(), json!(""));
    obj.insert("sub".into(), json!("0xabc"));
    let token = mint_hs256(&claims);

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D3", NOW)
        .expect_err("blank webid + opaque sub has no WebID");
    expect_nip98(err, "neither webid claim nor url-shaped sub");
}

#[test]
fn d4_non_http_identity_schemes_are_not_webids() {
    // `extract_webid` accepts a claim only if it starts with `http://`
    // or `https://`. DID / URN / mailto identities are therefore not
    // WebIDs at this layer, whichever member carries them.
    for scheme in [
        "did:nostr:deadbeef",
        "did:web:me.example",
        "urn:uuid:0f7a4f2e-0000-4000-8000-000000000000",
        "mailto:me@example.com",
        "//me.example/profile#me",
        "HTTPS://me.example/profile#me", // prefix test is case-sensitive
    ] {
        let claims = SolidOidcClaims {
            iss: ISSUER.into(),
            sub: scheme.into(),
            aud: json!("solid"),
            exp: NOW + 3600,
            iat: NOW,
            webid: Some(scheme.into()),
            client_id: None,
            cnf: None,
            scope: None,
        };
        let err = match extract_webid(&claims) {
            Ok(w) => panic!("{scheme:?} must not be accepted as a WebID, got {w:?}"),
            Err(e) => e,
        };
        expect_nip98(err, "no WebID present in access token");
    }
}

#[test]
fn d5_cnf_absent_is_refused() {
    let mut claims = base_claims("JKT-D5", NOW + 3600);
    claims
        .as_object_mut()
        .expect("object")
        .remove("cnf")
        .expect("cnf present in the base fixture");
    let token = mint_hs256(&claims);

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D5", NOW)
        .expect_err("an unbound bearer token must not verify");
    expect_nip98(err, "access token missing cnf");
}

#[test]
fn d6_cnf_jkt_must_equal_the_presented_dpop_key_thumbprint() {
    // The `jkt` the pod compares against is the RFC 7638 thumbprint of
    // the JWK carried in the DPoP proof header — derived here through
    // the very same `Jwk::thumbprint()` the verifier uses.
    let presented = oct_jwk(b"dpop-key-material-one");
    let other = oct_jwk(b"dpop-key-material-two");
    let presented_jkt = presented.thumbprint().expect("oct thumbprint");
    let other_jkt = other.thumbprint().expect("oct thumbprint");
    assert_ne!(presented_jkt, other_jkt);

    // Token bound to `other`, but `presented` is the key on the wire.
    let token = mint_hs256(&base_claims(&other_jkt, NOW + 3600));
    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, &presented_jkt, NOW)
        .expect_err("cnf.jkt / DPoP key mismatch must be refused");
    expect_nip98(err, "cnf.jkt does not match DPoP thumbprint");

    // Same token, correct key: verifies.
    let ok = verify_access_token(&token, &symmetric_keyset(), ISSUER, &other_jkt, NOW)
        .expect("matching cnf.jkt verifies");
    assert_eq!(ok.jkt, other_jkt);
}

#[test]
fn d7_unsupported_jwk_key_types_have_no_thumbprint() {
    // A `cnf.jkt` can only ever bind to a key type `Jwk::thumbprint`
    // supports: EC, RSA, OKP, oct. Anything else is `Unsupported`.
    let mut jwk = oct_jwk(b"whatever");
    jwk.kty = "X25519-unregistered".into();
    match jwk.thumbprint().expect_err("unknown kty has no thumbprint") {
        PodError::Unsupported(msg) => assert!(
            msg.contains("unsupported JWK kty"),
            "unexpected message: {msg}"
        ),
        other => panic!("expected PodError::Unsupported, got {other:?}"),
    }

    // A structurally incomplete key of a supported type is also
    // `Unsupported`, not a silently-empty thumbprint.
    let incomplete = Jwk {
        kty: "EC".into(),
        alg: None,
        kid: None,
        use_: None,
        crv: Some("P-256".into()),
        x: Some("only-x".into()),
        y: None,
        n: None,
        e: None,
        k: None,
    };
    match incomplete.thumbprint().expect_err("EC without y") {
        PodError::Unsupported(msg) => {
            assert!(
                msg.contains("EC JWK missing y"),
                "unexpected message: {msg}"
            )
        }
        other => panic!("expected PodError::Unsupported, got {other:?}"),
    }
}

#[test]
fn d8_alg_none_is_refused_under_every_keyset() {
    let token = forge_alg_none(&base_claims("JKT-D8", NOW + 3600));

    let sym_err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D8", NOW)
        .expect_err("alg=none must never verify");
    expect_nip98(sym_err, "access token header decode failed");

    let asym = TokenVerifyKey::Asymmetric(JwkSet {
        keys: vec![es256_public_jwk()],
    });
    let asym_err = verify_access_token(&token, &asym, ISSUER, "JKT-D8", NOW)
        .expect_err("alg=none must never verify");
    expect_nip98(asym_err, "access token header decode failed");
}

#[test]
fn d9_symmetric_alg_is_refused_against_an_asymmetric_keyset() {
    // The alg-confusion guard: HS256 is a test-only path and is
    // explicitly refused whenever the pod is configured with a real
    // (asymmetric) JWK set — i.e. in every production deployment.
    let token = mint_hs256(&base_claims("JKT-D9", NOW + 3600));
    let asym = TokenVerifyKey::Asymmetric(JwkSet {
        keys: vec![es256_public_jwk()],
    });

    let err = verify_access_token(&token, &asym, ISSUER, "JKT-D9", NOW)
        .expect_err("HS256 against a JwkSet is alg confusion");
    expect_nip98(err, "HS256 not permitted for external OIDC");
}

#[test]
fn d10_unsupported_asymmetric_algs_are_refused_by_dispatch() {
    // `verify_access_token` dispatches only RS256 / ES256 / EdDSA on
    // the asymmetric path. RS384, PS256, ES384 &c. fall through to the
    // catch-all reject arm — note the contrast with DPoP proofs, which
    // accept the wider RFC 9449 §5 set.
    let asym = TokenVerifyKey::Asymmetric(JwkSet {
        keys: vec![es256_public_jwk()],
    });
    for alg in [
        "RS384", "RS512", "PS256", "PS384", "PS512", "ES384", "HS384", "HS512",
    ] {
        let header = json!({ "typ": "JWT", "alg": alg, "kid": "compat-matrix-es256" });
        let h = BASE64_URL.encode(serde_json::to_string(&header).expect("header"));
        let b = BASE64_URL
            .encode(serde_json::to_string(&base_claims("JKT-D10", NOW + 3600)).expect("claims"));
        let token = format!("{h}.{b}.{}", BASE64_URL.encode([0u8; 64]));

        let err = match verify_access_token(&token, &asym, ISSUER, "JKT-D10", NOW) {
            Ok(v) => panic!("alg {alg} must not be accepted on the asymmetric path, got {v:?}"),
            Err(e) => e,
        };
        expect_nip98(err, "not permitted");
    }
}

#[test]
fn d11_asymmetric_token_against_a_symmetric_keyset_is_refused() {
    // The mirror image of D9: an RS256 token cannot be verified when
    // only the test-only shared secret is configured.
    let header = json!({ "typ": "JWT", "alg": "RS256", "kid": "attacker-kid" });
    let h = BASE64_URL.encode(serde_json::to_string(&header).expect("header"));
    let b =
        BASE64_URL.encode(serde_json::to_string(&base_claims("JKT-D11", NOW + 3600)).expect("c"));
    let token = format!("{h}.{b}.{}", BASE64_URL.encode([0u8; 256]));

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-D11", NOW)
        .expect_err("RS256 needs an asymmetric keyset");
    expect_nip98(err, "only a symmetric");
}

#[test]
fn d12_a_tampered_signature_is_refused() {
    // Belt and braces on the matrix's "signature verified" row.
    let token = mint_hs256(&base_claims("JKT-D12", NOW + 3600));
    let mut parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let forged_sig = BASE64_URL.encode([0xAAu8; 32]);
    parts[2] = &forged_sig;
    let tampered = parts.join(".");

    let err = verify_access_token(&tampered, &symmetric_keyset(), ISSUER, "JKT-D12", NOW)
        .expect_err("a forged MAC must not verify");
    expect_nip98(err, "access token decode failed");
}

// ---------------------------------------------------------------------------
// E. Expiry
// ---------------------------------------------------------------------------

#[test]
fn e1_expired_token_is_refused() {
    let token = mint_hs256(&base_claims("JKT-E1", NOW - 1));
    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-E1", NOW)
        .expect_err("expired token must not verify");
    expect_nip98(err, "access token expired");
}

#[test]
fn e2_expiry_boundary_is_exp_less_than_now() {
    // `exp == now` is still valid: the check is `claims.exp < now`.
    // There is no configurable leeway on the access-token path (unlike
    // the DPoP `iat` skew parameter).
    let at_boundary = mint_hs256(&base_claims("JKT-E2", NOW));
    verify_access_token(&at_boundary, &symmetric_keyset(), ISSUER, "JKT-E2", NOW)
        .expect("exp == now is inside the window");

    let one_past = mint_hs256(&base_claims("JKT-E2", NOW));
    let err = verify_access_token(&one_past, &symmetric_keyset(), ISSUER, "JKT-E2", NOW + 1)
        .expect_err("exp < now is expired");
    expect_nip98(err, "access token expired");
}

#[test]
fn e3_expiry_is_checked_before_the_cnf_binding() {
    // Ordering matters for the error a caller surfaces: an expired
    // token reports expiry even when its `cnf` is also wrong.
    let mut claims = base_claims("JKT-E3", NOW - 1);
    claims
        .as_object_mut()
        .expect("object")
        .remove("cnf")
        .expect("cnf present");
    let token = mint_hs256(&claims);

    let err = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-E3", NOW)
        .expect_err("expired");
    expect_nip98(err, "access token expired");
}

// ---------------------------------------------------------------------------
// F. Backwards-compatibility shim
// ---------------------------------------------------------------------------

#[test]
fn f1_deprecated_hs256_shim_delegates_to_the_dispatching_form() {
    #[allow(deprecated)]
    use solid_pod_rs::oidc::verify_access_token_hs256;

    let token = mint_hs256(&base_claims("JKT-F1", NOW + 3600));
    #[allow(deprecated)]
    let via_shim = verify_access_token_hs256(&token, SECRET, ISSUER, "JKT-F1", NOW)
        .expect("shim verifies exactly as the dispatching form does");
    let direct = verify_access_token(&token, &symmetric_keyset(), ISSUER, "JKT-F1", NOW)
        .expect("dispatching form verifies");

    assert_eq!(via_shim.webid, direct.webid);
    assert_eq!(via_shim.jkt, direct.jkt);
    assert_eq!(via_shim.iss, direct.iss);
    assert_eq!(via_shim.exp, direct.exp);
}

// ---------------------------------------------------------------------------
// G. DPoP proof → cnf.jkt stitch (only when the replay-cache feature,
//    and hence the async DPoP entry point, is compiled in).
// ---------------------------------------------------------------------------

#[cfg(feature = "dpop-replay-cache")]
mod dpop_stitch {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use solid_pod_rs::oidc::{verify_dpop_proof, verify_dpop_proof_with_ath, DpopClaims};

    /// Build an HS256+oct DPoP proof. This algorithm pairing is
    /// compiled only under the non-default `dpop-symmetric-test`
    /// feature (enabled for this crate's integration tests through the
    /// self dev-dependency); production builds reject it.
    fn build_dpop_proof(
        secret: &[u8],
        jwk: &Jwk,
        htu: &str,
        htm: &str,
        iat: u64,
        jti: &str,
        ath: Option<&str>,
    ) -> String {
        let header = json!({ "typ": "dpop+jwt", "alg": "HS256", "jwk": jwk });
        let header_b64 = BASE64_URL.encode(serde_json::to_string(&header).expect("header"));
        let claims = DpopClaims {
            htu: htu.into(),
            htm: htm.into(),
            iat,
            jti: jti.into(),
            ath: ath.map(str::to_string),
        };
        let body_b64 = BASE64_URL.encode(serde_json::to_string(&claims).expect("claims"));
        let signing_input = format!("{header_b64}.{body_b64}");
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            BASE64_URL.encode(mac.finalize().into_bytes())
        )
    }

    #[tokio::test]
    async fn g1_dpop_jkt_is_the_binding_the_access_token_must_carry() {
        let dpop_secret = b"dpop-proof-secret";
        let jwk = oct_jwk(dpop_secret);
        let htu = "https://pod.example/r";
        let proof = build_dpop_proof(
            dpop_secret,
            &jwk,
            htu,
            "GET",
            NOW,
            "jti-compat-matrix-g1",
            None,
        );

        let verified = verify_dpop_proof(&proof, htu, "GET", NOW, 60, None)
            .await
            .expect("DPoP proof verifies");
        assert_eq!(
            verified.jkt,
            jwk.thumbprint().expect("thumbprint"),
            "DpopVerified.jkt must be RFC 7638 over the header jwk"
        );

        // The access token bound to that thumbprint verifies…
        let token = mint_hs256(&base_claims(&verified.jkt, NOW + 3600));
        verify_access_token(&token, &symmetric_keyset(), ISSUER, &verified.jkt, NOW)
            .expect("token bound to the presented DPoP key verifies");

        // …and a token bound to any other key does not.
        let stolen = mint_hs256(&base_claims("SOME-OTHER-JKT", NOW + 3600));
        let err = verify_access_token(&stolen, &symmetric_keyset(), ISSUER, &verified.jkt, NOW)
            .expect_err("a token bound elsewhere must not ride this proof");
        expect_nip98(err, "cnf.jkt does not match DPoP thumbprint");
    }

    #[tokio::test]
    async fn g2_dpop_claims_htm_htu_iat_and_ath_are_enforced() {
        let dpop_secret = b"dpop-proof-secret-2";
        let jwk = oct_jwk(dpop_secret);
        let htu = "https://pod.example/r";
        let ath = "aGFzaC1vZi10aGUtYWNjZXNzLXRva2Vu";

        let proof = build_dpop_proof(
            dpop_secret,
            &jwk,
            htu,
            "GET",
            NOW,
            "jti-compat-matrix-g2",
            Some(ath),
        );

        // htm mismatch.
        let err = verify_dpop_proof(&proof, htu, "POST", NOW, 60, None)
            .await
            .expect_err("htm is enforced");
        expect_nip98(err, "DPoP htm mismatch");

        // htu mismatch.
        let err = verify_dpop_proof(&proof, "https://pod.example/other", "GET", NOW, 60, None)
            .await
            .expect_err("htu is enforced");
        expect_nip98(err, "DPoP htu mismatch");

        // htu comparison is trailing-slash- and case-insensitive.
        verify_dpop_proof(&proof, "HTTPS://POD.EXAMPLE/R/", "get", NOW, 60, None)
            .await
            .expect("htu/htm comparison normalises case and trailing slash");

        // iat outside the skew window, in both directions.
        for clock in [NOW + 61, NOW - 61] {
            let err = verify_dpop_proof(&proof, htu, "GET", clock, 60, None)
                .await
                .expect_err("iat skew is enforced in both directions");
            expect_nip98(err, "DPoP iat outside tolerance");
        }

        // ath binding: matching hash passes, mismatch fails.
        verify_dpop_proof_with_ath(&proof, htu, "GET", NOW, 60, Some(ath), None)
            .await
            .expect("matching ath");
        let err =
            verify_dpop_proof_with_ath(&proof, htu, "GET", NOW, 60, Some("not-the-hash"), None)
                .await
                .expect_err("ath mismatch is refused");
        expect_nip98(err, "DPoP ath does not match access-token hash");

        // A proof with no `ath` at all, where one was expected.
        let no_ath = build_dpop_proof(dpop_secret, &jwk, htu, "GET", NOW, "jti-g2-no-ath", None);
        let err = verify_dpop_proof_with_ath(&no_ath, htu, "GET", NOW, 60, Some(ath), None)
            .await
            .expect_err("missing ath is refused when a token is present");
        expect_nip98(err, "DPoP proof missing ath");
    }

    #[tokio::test]
    async fn g3_dpop_typ_must_be_dpop_jwt() {
        let dpop_secret = b"dpop-proof-secret-3";
        let jwk = oct_jwk(dpop_secret);
        let header = json!({ "typ": "JWT", "alg": "HS256", "jwk": jwk });
        let header_b64 = BASE64_URL.encode(serde_json::to_string(&header).expect("header"));
        let claims = DpopClaims {
            htu: "https://pod.example/r".into(),
            htm: "GET".into(),
            iat: NOW,
            jti: "jti-compat-matrix-g3".into(),
            ath: None,
        };
        let body_b64 = BASE64_URL.encode(serde_json::to_string(&claims).expect("claims"));
        let signing_input = format!("{header_b64}.{body_b64}");
        let mut mac = <Hmac<Sha256>>::new_from_slice(dpop_secret).expect("HMAC");
        mac.update(signing_input.as_bytes());
        let proof = format!(
            "{signing_input}.{}",
            BASE64_URL.encode(mac.finalize().into_bytes())
        );

        let err = verify_dpop_proof(&proof, "https://pod.example/r", "GET", NOW, 60, None)
            .await
            .expect_err("typ is enforced");
        expect_nip98(err, "DPoP typ must be dpop+jwt");
    }
}
