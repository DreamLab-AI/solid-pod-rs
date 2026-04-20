//! WAC 2.0 write-side validation.
//!
//! When a client PUTs an ACL document, the server rejects it with
//! 422 Unprocessable Entity if the document contains `acl:condition`
//! triples whose `@type` is not recognised by the server's
//! `ConditionRegistry`. This prevents clients from writing ACLs that
//! would silently fail-closed at read time.

use solid_pod_rs::wac::{
    validate_for_write, AclAuthorization, AclDocument, ClientConditionBody, Condition,
    ConditionRegistry, IdOrIds, IdRef,
};

fn auth_with_condition(cond: Option<Vec<Condition>>) -> AclAuthorization {
    AclAuthorization {
        id: None,
        r#type: None,
        agent: Some(IdOrIds::Single(IdRef {
            id: "did:nostr:alice".into(),
        })),
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: Some(IdOrIds::Single(IdRef { id: "/".into() })),
        default: None,
        mode: Some(IdOrIds::Single(IdRef { id: "acl:Read".into() })),
        condition: cond,
    }
}

#[test]
fn wac_validate_for_write_accepts_known_conditions() {
    let client_cond = Condition::Client(ClientConditionBody {
        client: Some(IdOrIds::Single(IdRef {
            id: "https://app.example/webid#client".into(),
        })),
        client_group: None,
        client_class: None,
    });
    let doc = AclDocument {
        context: None,
        graph: Some(vec![auth_with_condition(Some(vec![client_cond]))]),
    };
    let registry = ConditionRegistry::default_with_client_and_issuer();
    assert!(validate_for_write(&doc, &registry).is_ok());
}

#[test]
fn wac_validate_for_write_rejects_unknown_with_iri() {
    // Parse JSON carrying an unknown condition type.
    let json = r##"{
        "@graph": [{
            "acl:agent": {"@id": "did:nostr:alice"},
            "acl:accessTo": {"@id": "/"},
            "acl:mode": {"@id": "acl:Read"},
            "acl:condition": [{
                "@type": "urn:unknown#X"
            }]
        }]
    }"##;
    let doc: AclDocument = serde_json::from_str(json).expect("parse");
    let registry = ConditionRegistry::default_with_client_and_issuer();
    let err = validate_for_write(&doc, &registry).expect_err("expected UnsupportedCondition");
    // The error must carry some marker (IRI or "unknown") for 422 response.
    let msg = err.to_string();
    assert!(
        msg.contains("unknown") || msg.contains("unsupported") || msg.contains("condition"),
        "error message should indicate an unsupported condition: {msg}"
    );
}

#[test]
fn wac_validate_for_write_accepts_no_conditions() {
    // No `acl:condition` at all — trivially valid.
    let doc = AclDocument {
        context: None,
        graph: Some(vec![auth_with_condition(None)]),
    };
    let registry = ConditionRegistry::default_with_client_and_issuer();
    assert!(validate_for_write(&doc, &registry).is_ok());

    // Empty document is valid.
    let empty = AclDocument {
        context: None,
        graph: None,
    };
    assert!(validate_for_write(&empty, &registry).is_ok());
}
