//! WAC `acl:PaymentCondition` integration tests.
//!
//! Verifies:
//!
//! 1. JSON-LD parsing of PaymentCondition with numeric cost.
//! 2. JSON-LD parsing of PaymentCondition with string cost.
//! 3. Turtle parsing of PaymentCondition.
//! 4. Evaluation grants when balance >= cost.
//! 5. Evaluation denies when balance < cost.
//! 6. Evaluation denies when no payment context (402 path).
//! 7. PaymentCondition interacts correctly with Read/Write modes.
//! 8. Conjunctive: PaymentCondition + ClientCondition both required.
//! 9. Validate-for-write accepts PaymentCondition as known type.
//! 10. Turtle serializer round-trips PaymentCondition.

use solid_pod_rs::wac::{
    evaluate_access_ctx, parse_turtle_acl, serialize_turtle_acl, validate_acl_document, AccessMode,
    AclAuthorization, AclDocument, ClientConditionBody, Condition, ConditionRegistry, IdOrIds,
    IdRef, PaymentConditionBody, RequestContext, StaticGroupMembership,
};

fn doc_with(authzs: Vec<AclAuthorization>) -> AclDocument {
    AclDocument {
        context: None,
        graph: Some(authzs),
    }
}

fn payment_rule(
    agent: &str,
    path: &str,
    mode: &str,
    cost_sats: u64,
    extra_conds: Vec<Condition>,
) -> AclAuthorization {
    let mut conds = vec![Condition::Payment(PaymentConditionBody { cost_sats })];
    conds.extend(extra_conds);
    AclAuthorization {
        id: None,
        r#type: None,
        agent: Some(IdOrIds::Single(IdRef { id: agent.into() })),
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: Some(IdOrIds::Single(IdRef { id: path.into() })),
        default: None,
        mode: Some(IdOrIds::Single(IdRef { id: mode.into() })),
        condition: Some(conds),
    }
}

// ---------------------------------------------------------------------------
// 1. JSON-LD parsing with numeric cost
// ---------------------------------------------------------------------------

#[test]
fn parse_payment_condition_json_numeric_cost() {
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/premium/data"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{
                "@type": "acl:PaymentCondition",
                "acl:costSats": 100
            }]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let graph = doc.graph.as_ref().unwrap();
    let conds = graph[0].condition.as_ref().unwrap();
    assert_eq!(conds.len(), 1);
    match &conds[0] {
        Condition::Payment(body) => assert_eq!(body.cost_sats, 100),
        other => panic!("expected Payment condition, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 2. JSON-LD parsing with string cost
// ---------------------------------------------------------------------------

#[test]
fn parse_payment_condition_json_string_cost() {
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/premium/data"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{
                "@type": "acl:PaymentCondition",
                "acl:costSats": "250"
            }]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let graph = doc.graph.as_ref().unwrap();
    let conds = graph[0].condition.as_ref().unwrap();
    match &conds[0] {
        Condition::Payment(body) => assert_eq!(body.cost_sats, 250),
        other => panic!("expected Payment condition, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. Turtle parsing of PaymentCondition
// ---------------------------------------------------------------------------

#[test]
fn parse_payment_condition_turtle() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .

        <#paid-read> a acl:Authorization ;
            acl:agent <did:nostr:alice> ;
            acl:accessTo </premium/data> ;
            acl:mode acl:Read ;
            acl:condition [
                a acl:PaymentCondition ;
                acl:costSats 42
            ] .
    "#;
    let doc = parse_turtle_acl(ttl).expect("parse turtle");
    let graph = doc.graph.as_ref().unwrap();
    assert_eq!(graph.len(), 1);
    let conds = graph[0].condition.as_ref().unwrap();
    assert_eq!(conds.len(), 1);
    match &conds[0] {
        Condition::Payment(body) => assert_eq!(body.cost_sats, 42),
        other => panic!("expected Payment condition, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. Evaluation grants when balance >= cost
// ---------------------------------------------------------------------------

#[test]
fn payment_condition_grants_with_sufficient_balance() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        100,
        vec![],
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: None,
        payment_balance_sats: Some(100),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/premium/data",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 5. Evaluation denies when balance < cost
// ---------------------------------------------------------------------------

#[test]
fn payment_condition_denies_insufficient_balance() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        100,
        vec![],
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: None,
        payment_balance_sats: Some(50),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/premium/data",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 6. Evaluation denies when no payment context (HTTP 402 path)
// ---------------------------------------------------------------------------

#[test]
fn payment_condition_denies_without_payment_context() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        1,
        vec![],
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: None,
        payment_balance_sats: None,
    };
    assert!(
        !evaluate_access_ctx(
            Some(&doc),
            &ctx,
            "/premium/data",
            AccessMode::Read,
            None,
            &StaticGroupMembership::new(),
            &registry,
        ),
        "missing payment context must deny access (402 path)"
    );
}

// ---------------------------------------------------------------------------
// 7. Interaction with Read/Write modes
// ---------------------------------------------------------------------------

#[test]
fn payment_condition_on_write_mode() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/inbox",
        "acl:Write",
        500,
        vec![],
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();

    // Sufficient balance for write.
    let ctx_ok = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: None,
        payment_balance_sats: Some(500),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx_ok,
        "/premium/inbox",
        AccessMode::Write,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    // acl:Write implies acl:Append, so Append should also be gated.
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx_ok,
        "/premium/inbox",
        AccessMode::Append,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    // Read is not granted by this rule.
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx_ok,
        "/premium/inbox",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 8. Conjunctive: PaymentCondition + ClientCondition both required
// ---------------------------------------------------------------------------

#[test]
fn payment_plus_client_condition_conjunctive() {
    let client_cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        10,
        vec![client_cond],
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();

    // Both conditions satisfied.
    let ctx_ok = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/client"),
        issuer: None,
        payment_balance_sats: Some(100),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx_ok,
        "/premium/data",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    // Payment OK but client mismatch: deny.
    let ctx_bad_client = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://evil.example/client"),
        issuer: None,
        payment_balance_sats: Some(100),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx_bad_client,
        "/premium/data",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));

    // Client OK but payment insufficient: deny.
    let ctx_no_pay = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/client"),
        issuer: None,
        payment_balance_sats: Some(5),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx_no_pay,
        "/premium/data",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 9. Validate-for-write accepts PaymentCondition
// ---------------------------------------------------------------------------

#[test]
fn validate_for_write_accepts_payment_condition() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        42,
        vec![],
    )]);
    assert!(
        validate_acl_document(&doc).is_ok(),
        "PaymentCondition should be a known type, not rejected by validate_for_write"
    );
}

// ---------------------------------------------------------------------------
// 10. Turtle serializer round-trips PaymentCondition
// ---------------------------------------------------------------------------

#[test]
fn turtle_roundtrip_payment_condition() {
    let doc = doc_with(vec![payment_rule(
        "did:nostr:alice",
        "/premium/data",
        "acl:Read",
        999,
        vec![],
    )]);
    let ttl = serialize_turtle_acl(&doc);
    assert!(
        ttl.contains("acl:PaymentCondition"),
        "serialized Turtle should contain PaymentCondition type"
    );
    assert!(
        ttl.contains("acl:costSats 999"),
        "serialized Turtle should contain the cost: {ttl}"
    );

    // Parse back and verify.
    let parsed = parse_turtle_acl(&ttl).expect("re-parse serialized Turtle");
    let graph = parsed.graph.as_ref().unwrap();
    assert_eq!(graph.len(), 1);
    let conds = graph[0].condition.as_ref().unwrap();
    assert_eq!(conds.len(), 1);
    match &conds[0] {
        Condition::Payment(body) => assert_eq!(body.cost_sats, 999),
        other => panic!("expected Payment after round-trip, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 11. Full IRI variant of PaymentCondition
// ---------------------------------------------------------------------------

#[test]
fn parse_payment_condition_full_iri() {
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/premium/data"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{
                "@type": "http://www.w3.org/ns/auth/acl#PaymentCondition",
                "acl:costSats": 77
            }]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let conds = doc.graph.as_ref().unwrap()[0].condition.as_ref().unwrap();
    match &conds[0] {
        Condition::Payment(body) => assert_eq!(body.cost_sats, 77),
        other => panic!("expected Payment condition from full IRI, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 12. total_payment_cost helper
// ---------------------------------------------------------------------------

#[test]
fn total_payment_cost_extracts_from_authorization() {
    use solid_pod_rs::wac::total_payment_cost;

    let conditions = vec![
        Condition::Payment(PaymentConditionBody { cost_sats: 100 }),
        Condition::Client(ClientConditionBody::default()),
        Condition::Payment(PaymentConditionBody { cost_sats: 50 }),
    ];
    assert_eq!(total_payment_cost(&conditions), 150);
}
