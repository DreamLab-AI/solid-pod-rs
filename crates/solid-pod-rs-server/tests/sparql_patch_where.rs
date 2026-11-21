//! SPARQL Update with `WHERE` over HTTP (row 41). The property to preserve:
//! a `WHERE` clause reads the resource, so a PATCH carrying one needs `acl:Read`
//! as well as `acl:Write`; a write-only or append-only agent cannot use it to
//! copy or probe content. Forms the evaluator cannot honour are refused, never
//! answered as a silent 204.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

fn acl(modes: &str) -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#w> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo </> ; acl:default </> ; acl:mode {modes} .\n"
    )
}

async fn setup(
    modes: &str,
) -> (
    Arc<dyn Storage>,
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
) {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(acl(modes)), "text/turtle")
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
    (storage, app)
}

async fn sparql(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
    update: &str,
) -> u16 {
    test::call_service(
        app,
        test::TestRequest::patch()
            .uri("/box.ttl")
            .insert_header(("content-type", "application/sparql-update"))
            .set_payload(update.to_string())
            .to_request(),
    )
    .await
    .status()
    .as_u16()
}

async fn stored(s: &Arc<dyn Storage>) -> String {
    let (b, _) = s.get("/box.ttl").await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

const COPY: &str =
    "INSERT { <http://e/leak> <http://e/v> ?o } WHERE { <http://e/s> <http://e/secret> ?o }";

#[actix_web::test]
async fn a_where_clause_needs_read_as_well_as_write() {
    let (storage, app) = setup("acl:Write").await;
    for update in [
        COPY,
        "DELETE WHERE { <http://e/s> <http://e/secret> ?o }",
        "DELETE { <http://e/s> <http://e/secret> ?o } WHERE { <http://e/s> <http://e/secret> ?o }",
    ] {
        let st = sparql(&app, update).await;
        assert!(
            st == 401 || st == 403,
            "write-only agent ran {update}: {st}"
        );
    }
    assert_eq!(
        stored(&storage).await,
        "<http://e/s> <http://e/secret> \"guess\" .\n",
        "nothing was copied or removed"
    );
    // INSERT DATA still needs only Write.
    let st = sparql(&app, "INSERT DATA { <http://e/a> <http://e/b> \"c\" }").await;
    assert_eq!(st, 204);
}

#[actix_web::test]
async fn an_append_only_agent_cannot_use_a_where_clause() {
    let (storage, app) = setup("acl:Append, acl:Read").await;
    let st = sparql(&app, COPY).await;
    assert!(
        st == 401 || st == 403,
        "append+read ran a WHERE update: {st}"
    );
    assert!(!stored(&storage).await.contains("leak"));
}

#[actix_web::test]
async fn read_and_write_may_rewrite_with_a_where_clause() {
    let (storage, app) = setup("acl:Read, acl:Write").await;
    let st = sparql(
        &app,
        "DELETE { ?s <http://e/secret> ?o } INSERT { ?s <http://e/secret> \"new\" } \
         WHERE { ?s <http://e/secret> ?o }",
    )
    .await;
    assert_eq!(st, 204);
    let body = stored(&storage).await;
    assert!(body.contains("new") && !body.contains("guess"), "{body}");
}

#[actix_web::test]
async fn an_unsupported_form_is_refused_not_answered_204() {
    let (storage, app) = setup("acl:Read, acl:Write").await;
    for update in [
        "DELETE { ?s <http://e/secret> ?o } WHERE { ?s <http://e/secret> ?o FILTER(?o = \"x\") }",
        "INSERT DATA { GRAPH <http://g> { <http://e/s> <http://e/p> \"1\" } }",
    ] {
        let st = sparql(&app, update).await;
        assert!(st >= 400 && st != 401 && st != 403, "{update}: {st}");
    }
    assert!(stored(&storage).await.contains("guess"));
}

#[actix_web::test]
async fn an_update_with_thousands_of_patterns_or_many_operations_is_refused() {
    let (storage, app) = setup("acl:Read, acl:Write").await;
    let before = stored(&storage).await;
    let many_patterns = format!(
        "DELETE WHERE {{ {} }}",
        (0..5000)
            .map(|i| format!("?s{i} <http://e/none> ?o{i} ."))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let many_ops = (0..40)
        .map(|i| format!("INSERT DATA {{ <http://e/s{i}> <http://e/p> \"v\" }}"))
        .collect::<Vec<_>>()
        .join(" ;\n");
    for update in [many_patterns, many_ops] {
        assert_eq!(sparql(&app, &update).await, 400);
    }
    assert_eq!(stored(&storage).await, before, "nothing was written");
}

#[actix_web::test]
async fn a_delete_data_that_matches_nothing_is_409_and_writes_nothing() {
    let (storage, app) = setup("acl:Read, acl:Write").await;
    let before = stored(&storage).await;
    let st = sparql(
        &app,
        "DELETE DATA { <http://e/s> <http://e/secret> \"not the value\" }",
    )
    .await;
    assert_eq!(st, 409);
    assert_eq!(stored(&storage).await, before);
    let st = sparql(
        &app,
        "DELETE DATA { <http://e/s> <http://e/secret> \"guess\" }",
    )
    .await;
    assert_eq!(st, 204);
}

#[actix_web::test]
async fn a_write_only_agent_cannot_probe_content_with_delete_data() {
    // 409 against 204 tells the caller whether the triple exists.
    let (storage, app) = setup("acl:Write").await;
    let before = stored(&storage).await;
    for update in [
        "DELETE DATA { <http://e/s> <http://e/secret> \"guess\" }",
        "DELETE DATA { <http://e/s> <http://e/secret> \"nope\" }",
    ] {
        let st = sparql(&app, update).await;
        assert!(
            st == 401 || st == 403,
            "write-only agent ran {update}: {st}"
        );
    }
    assert_eq!(stored(&storage).await, before);
    // An empty DELETE DATA reveals nothing and stays insert-only.
    assert_eq!(sparql(&app, "DELETE DATA { }").await, 204);
}
