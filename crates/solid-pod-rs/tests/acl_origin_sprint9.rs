//! Sprint 9 row 51 — `acl:origin` enforcement using the current
//! `evaluate_access` shape. These tests cover the four corners the
//! Sprint-9 brief calls out:
//!
//!   * no origin constraint → allowed from any origin
//!   * matching origin → allowed
//!   * non-matching origin → denied
//!   * origin constraint set but request carries no origin → denied
//!
//! Gated behind the `acl-origin` feature (same as `acl_origin_test.rs`),
//! because the gate is only wired into `evaluate_access` under that flag.

#![cfg(feature = "acl-origin")]

use solid_pod_rs::wac::{
    evaluate_access, parse_turtle_acl, AccessMode, Origin,
};

fn doc_without_origin() -> solid_pod_rs::wac::AclDocument {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        <#public> a acl:Authorization ;
            acl:agentClass foaf:Agent ;
            acl:accessTo </open> ;
            acl:mode acl:Read .
    "#;
    parse_turtle_acl(ttl).unwrap()
}

fn doc_with_origin(origin: &str) -> solid_pod_rs::wac::AclDocument {
    let ttl = format!(
        r#"
            @prefix acl: <http://www.w3.org/ns/auth/acl#> .
            <#r> a acl:Authorization ;
                acl:agent <did:nostr:alice> ;
                acl:origin <{origin}> ;
                acl:accessTo </data> ;
                acl:mode acl:Read .
        "#,
    );
    parse_turtle_acl(&ttl).unwrap()
}

#[test]
fn authz_without_origin_constraint_allowed_anywhere() {
    let doc = doc_without_origin();
    // No origin, any origin — both must grant.
    assert!(evaluate_access(
        Some(&doc),
        None,
        "/open",
        AccessMode::Read,
        None,
    ));
    let o = Origin::parse("https://any.example").unwrap();
    assert!(evaluate_access(
        Some(&doc),
        None,
        "/open",
        AccessMode::Read,
        Some(&o),
    ));
}

#[test]
fn authz_with_matching_origin_allows() {
    let doc = doc_with_origin("https://app.example");
    let o = Origin::parse("https://app.example").unwrap();
    assert!(evaluate_access(
        Some(&doc),
        Some("did:nostr:alice"),
        "/data",
        AccessMode::Read,
        Some(&o),
    ));
}

#[test]
fn authz_with_non_matching_origin_denies() {
    let doc = doc_with_origin("https://app.example");
    let o = Origin::parse("https://evil.example").unwrap();
    assert!(!evaluate_access(
        Some(&doc),
        Some("did:nostr:alice"),
        "/data",
        AccessMode::Read,
        Some(&o),
    ));
}

#[test]
fn authz_with_origin_but_missing_request_origin_denies() {
    let doc = doc_with_origin("https://app.example");
    assert!(!evaluate_access(
        Some(&doc),
        Some("did:nostr:alice"),
        "/data",
        AccessMode::Read,
        None,
    ));
}
