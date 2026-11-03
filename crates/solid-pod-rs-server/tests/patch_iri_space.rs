//! RDF PATCH reads the stored body and the patch in one IRI space, refuses
//! to round-trip ACLs it cannot preserve, bounds `where` evaluation, and
//! requires Read for patches that inspect the resource.
//!
//! Findings from the independent review of the recovered JSS 0.0.224 parity
//! work (2026-11-03): the stored body was read leniently (relative IRIs kept
//! as written) while the patch was resolved against the resource URL, so a
//! delete or `where` naming a stored triple never matched; an ACL with a
//! blank-node condition does not survive the N-Triples write-back; an
//! all-variable `where` was an unbounded nested-loop join; and variables let
//! a writer without Read enumerate the resource.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const PREFIXES: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
                        @prefix acl: <http://www.w3.org/ns/auth/acl#>.\n";

/// Everyone may read, write and control everything.
const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Control .\n";

async fn open_storage() -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    s
}

macro_rules! patch {
    ($app:expr, $uri:expr, $body:expr) => {{
        let resp = test::call_service(
            $app,
            test::TestRequest::patch()
                .uri($uri)
                .insert_header(("content-type", "text/n3"))
                .set_payload(format!(
                    "{PREFIXES}_:p a solid:InsertDeletePatch; {}.",
                    $body
                ))
                .to_request(),
        )
        .await;
        let status = resp.status().as_u16();
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        (status, body)
    }};
}

async fn stored(storage: &Arc<dyn Storage>, path: &str) -> String {
    let (bytes, _) = storage.get(path).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// A triple PUT with relative IRIs can be deleted by a patch naming it with
/// the same relative IRIs.
#[actix_web::test]
async fn deleting_a_triple_put_with_relative_iris() {
    let storage = open_storage().await;
    storage
        .put(
            "/doc.ttl",
            Bytes::from("<#a> <#b> \"v1\" .\n"),
            "text/turtle",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let (st, body) = patch!(&app, "/doc.ttl", r#"solid:deletes { <#a> <#b> "v1" }"#);
    assert_eq!(st, 204, "delete of a stored relative triple: {body}");
    assert!(
        !stored(&storage, "/doc.ttl").await.contains("v1"),
        "triple still stored"
    );
}

/// A `where` clause binds against stored relative IRIs, and an insert does
/// not add an absolute twin of a relative triple already stored.
#[actix_web::test]
async fn where_and_insert_see_stored_relative_iris() {
    let storage = open_storage().await;
    storage
        .put(
            "/doc.ttl",
            Bytes::from("<#a> <#b> \"v1\" .\n"),
            "text/turtle",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let (st, body) = patch!(
        &app,
        "/doc.ttl",
        r#"solid:where { <#a> <#b> ?v }; solid:inserts { <#a> <#c> ?v }"#
    );
    assert_eq!(st, 204, "where over a stored relative triple: {body}");
    let (st, body) = patch!(&app, "/doc.ttl", r#"solid:inserts { <#a> <#b> "v1" }"#);
    assert_eq!(st, 204, "{body}");
    let text = stored(&storage, "/doc.ttl").await;
    assert_eq!(
        text.matches("\"v1\"").count(),
        2,
        "one <#b> and one <#c> triple, no twin: {text}"
    );
}

/// Two sequential ACL patches: the second deletes an `acl:accessTo` the
/// first stored in server-root path form.
#[actix_web::test]
async fn a_second_acl_patch_can_delete_a_stored_target() {
    let storage = open_storage().await;
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let (st, body) = patch!(
        &app,
        "/doc.acl",
        "solid:inserts { <#all> a acl:Authorization; \
           acl:agentClass <http://xmlns.com/foaf/0.1/Agent>; \
           acl:accessTo </doc>, </other>; acl:mode acl:Read, acl:Write, acl:Control }"
    );
    assert_eq!(st, 201, "create the ACL: {body}");
    let text = stored(&storage, "/doc.acl").await;
    assert!(
        text.contains("</doc>") && text.contains("</other>"),
        "{text}"
    );

    let (st, body) = patch!(
        &app,
        "/doc.acl",
        "solid:deletes { <#all> acl:accessTo </other> }"
    );
    assert_eq!(st, 204, "second ACL patch deleting a target: {body}");
    let text = stored(&storage, "/doc.acl").await;
    assert!(text.contains("</doc>"), "kept target lost: {text}");
    assert!(!text.contains("</other>"), "deleted target kept: {text}");
}

/// An ACL with a blank-node condition cannot survive the N-Triples
/// write-back (the WAC reader only understands inline `[ … ]` conditions),
/// so an RDF PATCH of it is refused and the stored ACL is untouched.
#[actix_web::test]
async fn patching_an_acl_with_a_condition_is_refused_not_degraded() {
    let storage = open_storage().await;
    let acl = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo </doc> ; acl:mode acl:Read, acl:Write, acl:Control .\n\
         <#paid> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo </doc> ; acl:mode acl:Read ;\n\
           acl:condition [ a acl:PaymentCondition ; acl:costSats 30 ] .\n";
    storage
        .put("/doc.acl", Bytes::from(acl), "text/turtle")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    let (st, body) = patch!(
        &app,
        "/doc.acl",
        "solid:inserts { <#friend> a acl:Authorization; \
           acl:agent <https://friend.example/#me>; acl:accessTo </doc>; acl:mode acl:Read }"
    );
    assert_eq!(st, 409, "conditional ACL patched: {body}");
    assert_eq!(stored(&storage, "/doc.acl").await, acl, "ACL changed");
}

/// An all-variable `where` over a large document is refused promptly
/// rather than enumerating n^k bindings.
#[actix_web::test]
async fn an_explosive_where_clause_is_refused_promptly() {
    let storage = open_storage().await;
    let mut body = String::new();
    for i in 0..1000 {
        body.push_str(&format!("<http://e/s{i}> <http://e/p> \"{i}\" .\n"));
    }
    storage
        .put("/big.ttl", Bytes::from(body), "text/turtle")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage))).await;

    let started = std::time::Instant::now();
    let (st, body) = patch!(
        &app,
        "/big.ttl",
        "solid:where { ?a ?b ?c . ?d ?e ?f . ?g ?h ?i }; solid:inserts { <http://e/x> <http://e/y> ?c }"
    );
    assert!(
        (400..500).contains(&st),
        "explosive where accepted: {st} {body}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}

/// A writer without Read cannot use `where` or `deletes` to probe the
/// resource (Solid Protocol §5.3.1: they need Read as well as Write).
#[actix_web::test]
async fn where_and_deletes_need_read() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let write_only = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#w> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo </> ; acl:default </> ; acl:mode acl:Write .\n";
    storage
        .put("/.acl", Bytes::from(write_only), "text/turtle")
        .await
        .unwrap();
    storage
        .put(
            "/box.ttl",
            Bytes::from("<http://e/s> <http://e/secret> \"guess\" .\n"),
            "text/turtle",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage.clone()))).await;

    for clause in [
        r#"solid:where { <http://e/s> <http://e/secret> "guess" }; solid:inserts { <http://e/a> <http://e/b> "c" }"#,
        r#"solid:deletes { <http://e/s> <http://e/secret> "guess" }"#,
    ] {
        let (st, body) = patch!(&app, "/box.ttl", clause);
        assert!(
            st == 401 || st == 403,
            "write-only agent inspected the resource ({st}): {clause} {body}"
        );
    }
    // Insert-only still works with Write.
    let (st, body) = patch!(
        &app,
        "/box.ttl",
        r#"solid:inserts { <http://e/a> <http://e/b> "c" }"#
    );
    assert_eq!(st, 204, "insert-only with Write: {body}");
    assert!(stored(&storage, "/box.ttl").await.contains("guess"));
}
