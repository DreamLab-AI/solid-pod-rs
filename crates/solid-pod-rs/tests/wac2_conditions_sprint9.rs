//! Sprint 9 row 53-56 — WAC 2.0 `acl:condition` framework, parser
//! + evaluator + serializer round-trip + write-time validation.
//!
//! These tests complement `wac2_conditions.rs` (evaluator semantics
//! already covered there) by exercising:
//!
//!   * Turtle parsing of `acl:condition [ a acl:ClientCondition; … ]`
//!     and `acl:IssuerCondition` blank-node bodies.
//!   * Preservation of unknown `@type` IRIs via `Condition::Unknown {
//!     type_iri }` so write-time validation can 422 with the exact
//!     rejected IRI.
//!   * Fail-closed evaluation when any condition on an authorisation
//!     dispatches to `NotApplicable`.
//!   * Round-trip of conditions through the Turtle serialiser.

use solid_pod_rs::wac::{
    evaluate_access_ctx, parse_turtle_acl, serialize_turtle_acl, validate_acl_document,
    AccessMode, AclAuthorization, AclDocument, ClientConditionBody, Condition,
    ConditionRegistry, IdOrIds, IdRef, IssuerConditionBody, RequestContext,
    StaticGroupMembership,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn single_condition(doc: &AclDocument) -> &Condition {
    let graph = doc.graph.as_ref().expect("graph");
    let auth = graph.first().expect("authorization");
    let conds = auth.condition.as_ref().expect("conditions parsed");
    conds.first().expect("at least one condition")
}

fn doc_with_conditions(conds: Vec<Condition>) -> AclDocument {
    AclDocument {
        context: None,
        graph: Some(vec![AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: "did:nostr:alice".into(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef { id: "/r".into() })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef { id: "acl:Read".into() })),
            condition: Some(conds),
        }]),
    }
}

// ---------------------------------------------------------------------------
// Parser — ClientCondition with a single client IRI.
// ---------------------------------------------------------------------------
#[test]
fn parses_client_condition_with_single_client() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        <#r> a acl:Authorization ;
            acl:agent <did:nostr:alice> ;
            acl:accessTo </r> ;
            acl:mode acl:Read ;
            acl:condition [
                a acl:ClientCondition ;
                acl:client <https://app.example/webid#client>
            ] .
    "#;
    let doc = parse_turtle_acl(ttl).unwrap();
    match single_condition(&doc) {
        Condition::Client(body) => {
            let ids: Vec<&str> = match body.client.as_ref().unwrap() {
                IdOrIds::Single(r) => vec![r.id.as_str()],
                IdOrIds::Multiple(v) => v.iter().map(|r| r.id.as_str()).collect(),
            };
            assert_eq!(ids, vec!["https://app.example/webid#client"]);
        }
        other => panic!("expected Client, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Parser — IssuerCondition with multiple issuers.
// ---------------------------------------------------------------------------
#[test]
fn parses_issuer_condition_with_multiple_issuers() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        <#r> a acl:Authorization ;
            acl:agent <did:nostr:alice> ;
            acl:accessTo </r> ;
            acl:mode acl:Read ;
            acl:condition [
                a acl:IssuerCondition ;
                acl:issuer <https://idp-a.example/>, <https://idp-b.example/>
            ] .
    "#;
    let doc = parse_turtle_acl(ttl).unwrap();
    match single_condition(&doc) {
        Condition::Issuer(body) => {
            let ids: Vec<&str> = match body.issuer.as_ref().unwrap() {
                IdOrIds::Single(r) => vec![r.id.as_str()],
                IdOrIds::Multiple(v) => v.iter().map(|r| r.id.as_str()).collect(),
            };
            assert_eq!(
                ids,
                vec!["https://idp-a.example/", "https://idp-b.example/"],
            );
        }
        other => panic!("expected Issuer, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Parser — Unknown condition type is parsed and its IRI retained.
// ---------------------------------------------------------------------------
#[test]
fn unknown_condition_type_is_parsed_and_retained() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix ex: <https://example.org/vocab#> .
        <#r> a acl:Authorization ;
            acl:agent <did:nostr:alice> ;
            acl:accessTo </r> ;
            acl:mode acl:Read ;
            acl:condition [
                a ex:TimeOfDayCondition
            ] .
    "#;
    let doc = parse_turtle_acl(ttl).unwrap();
    match single_condition(&doc) {
        Condition::Unknown { type_iri } => {
            assert_eq!(type_iri, "https://example.org/vocab#TimeOfDayCondition");
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Evaluator — authorisation with unknown condition is skipped (fail-closed).
// ---------------------------------------------------------------------------
#[test]
fn authz_with_unknown_condition_is_skipped_fail_closed() {
    let doc = doc_with_conditions(vec![Condition::Unknown {
        type_iri: "https://example.org/vocab#MoonPhase".into(),
    }]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: None,
    };
    assert!(
        !evaluate_access_ctx(
            Some(&doc),
            &ctx,
            "/r",
            AccessMode::Read,
            None,
            &StaticGroupMembership::new(),
            &registry,
        ),
        "unknown condition must cause the authorisation to be skipped (fail-closed)",
    );
}

// ---------------------------------------------------------------------------
// Write-time — validate rejects a document whose condition type is
// unknown. Handler maps this to 422 Unprocessable Entity.
// ---------------------------------------------------------------------------
#[test]
fn validate_rejects_acl_with_unknown_condition() {
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/r"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{"@type": "https://example.org/vocab#TimeOfDay"}]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let err = validate_acl_document(&doc).expect_err("422 expected");
    assert_eq!(err.iri, "https://example.org/vocab#TimeOfDay");
}

// ---------------------------------------------------------------------------
// Evaluator — ClientCondition matches exact client id.
// ---------------------------------------------------------------------------
#[test]
fn client_condition_evaluation_matches_exact_client_id() {
    let cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let doc = doc_with_conditions(vec![cond]);
    let registry = ConditionRegistry::default_with_client_and_issuer();

    let matching_ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: None,
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &matching_ctx,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    let wrong_ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://evil.example/webid#client"),
        issuer: None,
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &wrong_ctx,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// Evaluator — IssuerCondition matches exact issuer.
// ---------------------------------------------------------------------------
#[test]
fn issuer_condition_evaluation_matches_exact_issuer() {
    let cond = Condition::Issuer(IssuerConditionBody {
        issuer: Some(IdOrIds::Single(IdRef {
            id: "https://trusted.idp/".into(),
        })),
        issuer_group: None,
        issuer_class: None,
    });
    let doc = doc_with_conditions(vec![cond]);
    let registry = ConditionRegistry::default_with_client_and_issuer();

    let ok = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: Some("https://trusted.idp/"),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ok,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    let wrong = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: Some("https://rogue.idp/"),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &wrong,
        "/r",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// Serializer round-trip: emit → parse → conditions equivalent.
// ---------------------------------------------------------------------------
#[test]
fn serializer_round_trip_preserves_conditions() {
    let client_cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let issuer_cond = Condition::Issuer(IssuerConditionBody {
        issuer: Some(IdOrIds::Single(IdRef {
            id: "https://trusted.idp/".into(),
        })),
        issuer_group: None,
        issuer_class: None,
    });
    let doc = doc_with_conditions(vec![client_cond, issuer_cond]);

    let ttl = serialize_turtle_acl(&doc);
    assert!(ttl.contains("acl:ClientCondition"), "ttl: {ttl}");
    assert!(ttl.contains("acl:IssuerCondition"), "ttl: {ttl}");
    assert!(ttl.contains("acl:client"), "ttl: {ttl}");
    assert!(ttl.contains("acl:issuer"), "ttl: {ttl}");

    let reparsed = parse_turtle_acl(&ttl).expect("re-parse");
    let auth = reparsed.graph.as_ref().unwrap().first().unwrap();
    let conds = auth.condition.as_ref().expect("conditions survive round-trip");
    assert_eq!(conds.len(), 2);
    assert!(matches!(conds[0], Condition::Client(_)));
    assert!(matches!(conds[1], Condition::Issuer(_)));
}
