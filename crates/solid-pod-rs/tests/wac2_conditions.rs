//! WAC 2.0 conditions framework tests.
//!
//! WAC 2.0 (https://webacl.org/secure-access-conditions/) extends the
//! WAC ontology with `acl:condition` triples. The tests below verify:
//!
//! 1. `acl:ClientCondition` grants when the client matches.
//! 2. `acl:ClientCondition` denies when the client does not match.
//! 3. `acl:IssuerCondition` grants via issuer group membership.
//! 4. Unknown condition types fail closed (NotApplicable, not Satisfied).
//! 5. Conjunctive AND semantics across multiple conditions.
//! 6. Monotonicity invariant — conditions can only restrict.
//! 7. `WAC-Allow` omits modes gated by unsatisfiable conditions.

use solid_pod_rs::wac::{
    evaluate_access_ctx, wac_allow_header_with_dispatcher, AccessMode, AclAuthorization,
    AclDocument, ClientConditionBody, Condition, ConditionOutcome, ConditionRegistry,
    IdOrIds, IdRef, IssuerConditionBody, RequestContext, StaticGroupMembership,
};

fn owner_rule_with_condition(
    agent: &str,
    path: &str,
    mode: &str,
    cond: Option<Vec<Condition>>,
) -> AclAuthorization {
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
        condition: cond,
    }
}

fn doc_with(authzs: Vec<AclAuthorization>) -> AclDocument {
    AclDocument {
        context: None,
        graph: Some(authzs),
    }
}

// ---------------------------------------------------------------------------
// 1. ClientCondition match → grant
// ---------------------------------------------------------------------------

#[test]
fn wac2_acl_condition_client_matches_permits() {
    let cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let doc = doc_with(vec![owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![cond]),
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: None,
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 2. ClientCondition mismatch → deny
// ---------------------------------------------------------------------------

#[test]
fn wac2_acl_condition_client_mismatch_denies() {
    let cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let doc = doc_with(vec![owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![cond]),
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://evil.example/webid#client"),
        issuer: None,
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 3. IssuerCondition with group membership → grant
// ---------------------------------------------------------------------------

#[test]
fn wac2_acl_condition_issuer_group_membership() {
    let cond = Condition::Issuer(IssuerConditionBody {
        issuer: None,
        issuer_group: Some(IdOrIds::Single(IdRef {
            id: "https://issuers.example/trusted".into(),
        })),
        issuer_class: None,
    });
    let doc = doc_with(vec![owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![cond]),
    )]);
    let mut groups = StaticGroupMembership::new();
    groups.add(
        "https://issuers.example/trusted",
        vec!["https://idp.example/".into()],
    );
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: None,
        issuer: Some("https://idp.example/"),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &groups,
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 4. Unknown condition type fails closed
// ---------------------------------------------------------------------------

#[test]
fn wac2_unknown_condition_type_fails_closed() {
    // Parse a JSON-LD doc that carries an unknown condition type.
    // serde(other) catches it → Condition::Unknown → NotApplicable.
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/private/note"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{
                "@type": "acl:UnknownCondition"
            }]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: Some("https://idp.example/"),
    };
    assert!(
        !evaluate_access_ctx(
            Some(&doc),
            &ctx,
            "/private/note",
            AccessMode::Read,
            None,
            &StaticGroupMembership::new(),
            &registry,
        ),
        "unknown condition type must fail closed (NotApplicable)"
    );
}

// ---------------------------------------------------------------------------
// 5. Conjunctive AND: Client OK + Issuer FAIL → deny
// ---------------------------------------------------------------------------

#[test]
fn wac2_conjunctive_conditions_and_gate() {
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
    let doc = doc_with(vec![owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![client_cond, issuer_cond]),
    )]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    // Client OK, issuer NOT OK → deny.
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: Some("https://untrusted.idp/"),
    };
    assert!(!evaluate_access_ctx(
        Some(&doc),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
    // Both OK → grant.
    let ctx_ok = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: Some("https://trusted.idp/"),
    };
    assert!(evaluate_access_ctx(
        Some(&doc),
        &ctx_ok,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    ));
}

// ---------------------------------------------------------------------------
// 6. Monotonicity invariant
// ---------------------------------------------------------------------------

#[test]
fn wac2_monotonicity_invariant() {
    // Rule WITHOUT conditions — always grants for matching agent/mode/path.
    let rule_plain = owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        None,
    );
    let doc_plain = doc_with(vec![rule_plain.clone()]);

    // Rule WITH always-true condition (client matches).
    let always_true = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let rule_true = owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![always_true]),
    );
    let doc_true = doc_with(vec![rule_true]);

    // Rule WITH always-false condition (client mismatch).
    let always_false = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://never-match.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let rule_false = owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        Some(vec![always_false]),
    );
    let doc_false = doc_with(vec![rule_false]);

    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://app.example/webid#client"),
        issuer: None,
    };

    let plain = evaluate_access_ctx(
        Some(&doc_plain),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    );
    let satisfied = evaluate_access_ctx(
        Some(&doc_true),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    );
    let denied = evaluate_access_ctx(
        Some(&doc_false),
        &ctx,
        "/private/note",
        AccessMode::Read,
        None,
        &StaticGroupMembership::new(),
        &registry,
    );

    // Plain grant.
    assert!(plain);
    // Satisfied condition == plain rule (no further restriction).
    assert_eq!(plain, satisfied, "satisfied condition must be identical to no condition");
    // Unsatisfiable condition strictly narrower.
    assert!(!denied, "unsatisfiable condition must strictly narrow the grant");
}

// ---------------------------------------------------------------------------
// 7. WAC-Allow header omits gated modes
// ---------------------------------------------------------------------------

#[test]
fn wac2_wac_allow_header_omits_gated_modes() {
    // Rule grants Write only if client matches. In a request where
    // the client mismatches, Write must NOT appear in user="...".
    let gated_write = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://only.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let rule_write = owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Write",
        Some(vec![gated_write]),
    );
    // Also grant ungated Read so user="" still has something.
    let rule_read = owner_rule_with_condition(
        "did:nostr:alice",
        "/private/note",
        "acl:Read",
        None,
    );
    let doc = doc_with(vec![rule_read, rule_write]);
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let ctx = RequestContext {
        web_id: Some("did:nostr:alice"),
        client_id: Some("https://not-the-one.example/webid#client"),
        issuer: None,
    };
    let hdr = wac_allow_header_with_dispatcher(
        Some(&doc),
        &ctx,
        "/private/note",
        &StaticGroupMembership::new(),
        &registry,
    );
    assert!(hdr.contains("user=\"read\""), "expected user=\"read\", got {hdr}");
    assert!(
        !hdr.contains("write"),
        "WAC-Allow must omit write gated by unsatisfied condition; got {hdr}"
    );
}

// Sanity: the `NotApplicable` outcome is distinct from `Satisfied`.
#[test]
fn condition_outcome_variants_are_distinct() {
    assert_ne!(ConditionOutcome::Satisfied, ConditionOutcome::NotApplicable);
    assert_ne!(ConditionOutcome::Satisfied, ConditionOutcome::Denied);
    assert_ne!(ConditionOutcome::NotApplicable, ConditionOutcome::Denied);
}
