//! SP-PAR-273 follow-up: an agent holding `acl:Append` and nothing else can
//! only ever ADD to a resource. A PATCH from such an agent must leave every
//! stored byte and the stored content type alone, whatever `Host` it sends.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::rdf_input::parse_turtle;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const RESOURCE: &str = "/inbox/log";

const APPEND_ONLY_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#append> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Append .
"#;

const WRITE_ACL: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#write> a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo </> ;
    acl:default </> ;
    acl:mode acl:Read, acl:Write, acl:Append .
"#;

/// Relative IRIs, a prefix, a comment and no trailing newline on purpose.
const OWNER_TURTLE: &str = "# owner notes\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
<#me> foaf:knows <../x> .\n# trailing comment";

const N3_HEAD: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#> .\n";
const INSERT: &str = "<http://example.org/a> <http://example.org/p> \"new\"";

async fn pod(acl: &str, body: &[u8], ct: &str) -> Arc<MemoryBackend> {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(acl.to_string()), "text/turtle")
        .await
        .unwrap();
    storage
        .put(RESOURCE, Bytes::copy_from_slice(body), ct)
        .await
        .unwrap();
    storage
}

async fn send(state: AppState, uri: &str, host: &str, ct: &str, body: &str) -> (u16, String) {
    let app = test::init_service(build_app(state)).await;
    let req = test::TestRequest::patch()
        .uri(uri)
        .insert_header(("host", host))
        .insert_header(("content-type", ct))
        .set_payload(body.to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn sparql(storage: &Arc<MemoryBackend>, host: &str, body: &str) -> (u16, String) {
    send(
        AppState::new(storage.clone()),
        RESOURCE,
        host,
        "application/sparql-update",
        body,
    )
    .await
}

async fn stored(storage: &Arc<MemoryBackend>) -> (String, String) {
    let (body, meta) = storage.get(RESOURCE).await.unwrap();
    (String::from_utf8(body.to_vec()).unwrap(), meta.content_type)
}

#[actix_web::test]
async fn hostile_host_leaves_every_stored_byte_and_the_type_unchanged() {
    let storage = pod(APPEND_ONLY_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let (status, _) = sparql(
        &storage,
        "evil.example",
        &format!("INSERT DATA {{ {INSERT} }}"),
    )
    .await;
    assert_eq!(status, 204);
    let (now, ct) = stored(&storage).await;
    assert!(now.starts_with(OWNER_TURTLE), "stored bytes changed: {now}");
    assert!(!now.contains("evil.example"), "{now}");
    assert_eq!(ct, "text/turtle");
    // Old and new triples both survive and the document is still Turtle.
    let graph = parse_turtle(now.as_bytes(), "http://pod.example/inbox/log").unwrap();
    assert_eq!(graph.len(), 2, "{now}");
    assert!(now.contains("\"new\""));
}

#[actix_web::test]
async fn stored_content_type_parameters_are_kept_verbatim() {
    let storage = pod(
        APPEND_ONLY_ACL,
        OWNER_TURTLE.as_bytes(),
        "text/turtle; charset=utf-8",
    )
    .await;
    let (status, _) = sparql(
        &storage,
        "pod.example",
        &format!("INSERT DATA {{ {INSERT} }}"),
    )
    .await;
    assert_eq!(status, 204);
    let (now, ct) = stored(&storage).await;
    assert!(now.starts_with(OWNER_TURTLE));
    assert_eq!(ct, "text/turtle; charset=utf-8");
}

#[actix_web::test]
async fn a_relative_iri_in_an_n3_insert_is_refused_without_a_configured_origin() {
    let storage = pod(APPEND_ONLY_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:inserts {{ <#x> <http://example.org/p> \"v\" }} ."
    );
    let (status, _) = send(
        AppState::new(storage.clone()),
        RESOURCE,
        "evil.example",
        "text/n3",
        &body,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(stored(&storage).await.0, OWNER_TURTLE);
    // The refusal does not depend on whether the resource exists.
    let (absent, _) = send(
        AppState::new(storage.clone()),
        "/inbox/none",
        "evil.example",
        "text/n3",
        &body,
    )
    .await;
    assert_eq!(absent, 400);
}

#[actix_web::test]
async fn with_a_configured_origin_a_relative_iri_resolves_against_it_not_the_host() {
    let storage = pod(APPEND_ONLY_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let mut state = AppState::new(storage.clone());
    state.public_base_url = Some("https://pod.example".into());
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:inserts {{ <#x> <http://example.org/p> \"v\" }} ."
    );
    let (status, _) = send(state, RESOURCE, "evil.example", "text/n3", &body).await;
    assert_eq!(status, 204);
    let (now, _) = stored(&storage).await;
    assert!(now.starts_with(OWNER_TURTLE));
    assert!(now.contains("<https://pod.example/inbox/log#x>"), "{now}");
    assert!(!now.contains("evil.example"));
}

#[actix_web::test]
async fn a_stored_body_that_is_not_turtle_or_ntriples_is_refused_and_unchanged() {
    // Valid N-Triples text under a non-RDF type, and a blank body likewise.
    let nt = "<http://example.org/s> <http://example.org/p> <http://example.org/o> .\n";
    for (body, ct) in [
        (nt, "text/plain"),
        ("", "text/plain"),
        ("  \n", "application/octet-stream"),
        (nt, "application/ld+json"),
    ] {
        let storage = pod(APPEND_ONLY_ACL, body.as_bytes(), ct).await;
        let (status, _) = sparql(
            &storage,
            "pod.example",
            &format!("INSERT DATA {{ {INSERT} }}"),
        )
        .await;
        assert_eq!(status, 409, "{ct}");
        assert_eq!(stored(&storage).await, (body.to_string(), ct.to_string()));
    }
}

#[actix_web::test]
async fn the_refusal_does_not_reveal_whether_the_body_is_rdf_or_utf8() {
    let utf8 = pod(APPEND_ONLY_ACL, b"hello", "text/plain").await;
    let binary = pod(APPEND_ONLY_ACL, &[0xff, 0xfe, 0x00], "text/turtle; x=1").await;
    let binary_text_type = pod(APPEND_ONLY_ACL, &[0xff, 0xfe, 0x00], "text/turtle").await;
    let update = format!("INSERT DATA {{ {INSERT} }}");
    let a = sparql(&utf8, "pod.example", &update).await;
    let b = sparql(&binary, "pod.example", &update).await;
    let c = sparql(&binary_text_type, "pod.example", &update).await;
    assert_eq!(a.0, 409);
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[actix_web::test]
async fn an_empty_stored_turtle_body_takes_the_insert() {
    let storage = pod(APPEND_ONLY_ACL, b"", "text/turtle").await;
    let (status, _) = sparql(
        &storage,
        "pod.example",
        &format!("INSERT DATA {{ {INSERT} }}"),
    )
    .await;
    assert_eq!(status, 204);
    let (now, ct) = stored(&storage).await;
    assert_eq!(ct, "text/turtle");
    assert_eq!(
        parse_turtle(now.as_bytes(), "http://pod.example/x")
            .unwrap()
            .len(),
        1
    );
}

#[actix_web::test]
async fn inserted_blank_nodes_do_not_merge_with_stored_ones() {
    let old = "_:b0 <http://example.org/p> \"old\" .\n";
    let storage = pod(APPEND_ONLY_ACL, old.as_bytes(), "text/turtle").await;
    let (status, _) = sparql(
        &storage,
        "pod.example",
        "INSERT DATA { _:b0 <http://example.org/p> \"new\" }",
    )
    .await;
    assert_eq!(status, 204);
    let (now, _) = stored(&storage).await;
    assert!(now.starts_with(old));
    let graph = parse_turtle(now.as_bytes(), "http://pod.example/x").unwrap();
    assert_eq!(graph.len(), 2);
    let subjects: std::collections::BTreeSet<_> = graph
        .triples()
        .map(|t| format!("{:?}", t.subject))
        .collect();
    assert_eq!(subjects.len(), 2, "blank nodes merged: {now}");
}

#[actix_web::test]
async fn a_resource_that_does_not_exist_is_still_created() {
    let storage = pod(APPEND_ONLY_ACL, b"", "text/turtle").await;
    let (status, _) = send(
        AppState::new(storage.clone()),
        "/inbox/new",
        "pod.example",
        "application/sparql-update",
        &format!("INSERT DATA {{ {INSERT} }}"),
    )
    .await;
    assert_eq!(status, 201);
}

#[actix_web::test]
async fn a_relative_iri_in_sparql_needs_write_and_is_refused_for_append() {
    let storage = pod(APPEND_ONLY_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let (status, _) = sparql(
        &storage,
        "evil.example",
        "INSERT DATA { <#x> <http://example.org/p> \"v\" }",
    )
    .await;
    assert!(status == 401 || status == 403, "got {status}");
    assert_eq!(stored(&storage).await.0, OWNER_TURTLE);
}

#[actix_web::test]
async fn an_agent_with_write_keeps_the_rewriting_behaviour_but_not_the_host_rebase() {
    let storage = pod(WRITE_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let body = format!(
        "{N3_HEAD}_:p a solid:InsertDeletePatch ; solid:inserts {{ <#x> <http://example.org/p> \"v\" }} ."
    );
    let (status, _) = send(
        AppState::new(storage.clone()),
        RESOURCE,
        "pod.example",
        "text/n3",
        &body,
    )
    .await;
    assert_eq!(status, 204);
    let (now, ct) = stored(&storage).await;
    assert_eq!(ct, "text/turtle");
    // Re-serialised as N-Triples (comments and prefixes are dropped), with the
    // relative IRIs kept relative: the request origin is not written
    // (SP-PATCH-WRITE-REBASE).
    assert!(now.contains("<#x>"), "{now}");
    assert!(now.contains("<#me>"), "{now}");
    assert!(!now.contains("pod.example"), "{now}");
    assert!(!now.contains("# owner notes"));
}

// --- third-round review: the result must be the stored graph plus exactly
// the inserted triples, whatever the stored body looks like.

async fn assert_refused_and_unchanged(stored_body: &str, update: &str) {
    let storage = pod(APPEND_ONLY_ACL, stored_body.as_bytes(), "text/turtle").await;
    let (status, msg) = sparql(&storage, "pod.example", update).await;
    assert_eq!(status, 409, "{update}");
    assert_eq!(msg, "existing resource cannot be appended to");
    assert_eq!(
        stored(&storage).await,
        (stored_body.to_string(), "text/turtle".to_string())
    );
}

#[actix_web::test]
async fn a_body_truncated_inside_a_long_string_cannot_absorb_the_insert() {
    let open_single = "<http://e/s> <http://e/p> '''owner text";
    let open_double = "<http://e/s> <http://e/p> \"\"\"owner text";
    // Literal holding the closing delimiter, then ` .` and a comment marker.
    let lit = "INSERT DATA { <http://example.org/a> <http://example.org/p> \"x''' . #\" }";
    let iri = "INSERT DATA { <http://example.org/a'''.#x> <http://example.org/p> \"v\" }";
    let dq = "INSERT DATA { <http://example.org/a> <http://example.org/p> \"x\\\"\\\"\\\" . #\" }";
    for update in [
        lit,
        iri,
        dq,
        "INSERT DATA { <http://example.org/a> <http://example.org/p> \"v\" }",
    ] {
        assert_refused_and_unchanged(open_single, update).await;
        assert_refused_and_unchanged(open_double, update).await;
    }
}

#[actix_web::test]
async fn an_otherwise_invalid_stored_turtle_body_is_refused() {
    for body in ["this is not turtle {{{", "<http://e/s> <http://e/p> ."] {
        assert_refused_and_unchanged(
            body,
            "INSERT DATA { <http://example.org/a> <http://example.org/p> \"v\" }",
        )
        .await;
    }
}

#[actix_web::test]
async fn an_insert_holding_quote_characters_round_trips_exactly() {
    let storage = pod(APPEND_ONLY_ACL, OWNER_TURTLE.as_bytes(), "text/turtle").await;
    let (status, _) = sparql(
        &storage,
        "pod.example",
        "INSERT DATA { <http://example.org/a> <http://example.org/p> \"it's '''q''' \\\" \\\\ end\" }",
    )
    .await;
    assert_eq!(status, 204);
    let (now, _) = stored(&storage).await;
    assert!(now.starts_with(OWNER_TURTLE));
    let g = parse_turtle(now.as_bytes(), "http://pod.example/x").unwrap();
    assert_eq!(g.len(), 2, "{now}");
}

#[actix_web::test]
async fn appended_blank_node_labels_are_fresh_and_do_not_grow_the_scan() {
    let storage = pod(APPEND_ONLY_ACL, b"", "text/turtle").await;
    for _ in 0..3 {
        let (status, _) = sparql(
            &storage,
            "pod.example",
            "INSERT DATA { _:b <http://example.org/p> \"v\" }",
        )
        .await;
        assert_eq!(status, 204);
    }
    let (now, _) = stored(&storage).await;
    let g = parse_turtle(now.as_bytes(), "http://pod.example/x").unwrap();
    let subjects: std::collections::BTreeSet<_> =
        g.triples().map(|t| format!("{:?}", t.subject)).collect();
    assert_eq!(subjects.len(), 3, "{now}");
}
