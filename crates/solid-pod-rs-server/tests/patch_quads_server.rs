//! PATCH over HTTP with the quad-based N3 Patch engine, per-resource write
//! serialisation and conditional writes.
//!
//! Ported from JSS `test/patch.test.js` (PR #633, JSS `0.0.224`) and from the
//! 2026-11-01 parity audit's runtime findings
//! (`docs/reference/jss-parity-audit-2026-11-01/patch-runtime-evidence.log`):
//! JSS's own prefixed bodies used to get 400, non-ASCII literals were
//! re-encoded on every PATCH, concurrent inserts were lost while all
//! returned 204, and `If-Match` / `If-None-Match` were ignored on writes.
//! Parity checklist rows 269, 271, 274, 286 and the §27 defects.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const CHAT: &str = "/public/chat.ttl";
const PUBLIC_RW_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#public> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Append .\n";
const PREFIXES: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
                        @prefix sioc: <http://rdfs.org/sioc/ns#>.\n";

async fn public_storage() -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    s
}

fn n3(body: &str) -> String {
    format!("{PREFIXES}_:p a solid:InsertDeletePatch; {body}.")
}

macro_rules! send {
    ($app:expr, $req:expr) => {{
        let resp = test::call_service($app, $req.to_request()).await;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        (status, body, etag)
    }};
}

fn patch_req(uri: &str, body: &str) -> test::TestRequest {
    test::TestRequest::patch()
        .uri(uri)
        .insert_header(("content-type", "text/n3"))
        .set_payload(body.to_string())
}

#[actix_web::test]
async fn jss_chat_bodies_create_append_edit_and_conflict() {
    let app = test::init_service(build_app(AppState::new(public_storage().await))).await;

    let create = format!(
        "{PREFIXES}@prefix dct: <http://purl.org/dc/terms/>.\n\
         @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.\n\
         _:p a solid:InsertDeletePatch; solid:inserts {{\n\
           <#m1> dct:created \"2026-10-22T10:00:00Z\"^^xsd:dateTime;\n\
             sioc:content \"\"\"two lines; with a dot.\nand a \"quote\" end\"\"\".\n\
         }}."
    );
    let (st, body, _) = send!(&app, patch_req(CHAT, &create));
    assert_eq!(st, 201, "create: {body}");

    let (st, body, _) = send!(
        &app,
        patch_req(
            CHAT,
            &n3(r#"solid:inserts { <#m2> sioc:content "second" }"#)
        )
    );
    assert_eq!(st, 204, "append: {body}");

    let edit = n3(r#"solid:where { <#m2> sioc:content ?old };
                    solid:deletes { <#m2> sioc:content ?old };
                    solid:inserts { <#m2> sioc:content "second, edited" }"#);
    let (st, body, _) = send!(&app, patch_req(CHAT, &edit));
    assert_eq!(st, 204, "edit: {body}");

    let (_, stored, _) = send!(&app, test::TestRequest::get().uri(CHAT));
    assert!(stored.contains("second, edited"), "{stored}");
    assert!(!stored.contains("\"second\""), "{stored}");
    assert!(stored.contains("2026-10-22T10:00:00Z"), "{stored}");
    assert!(stored.contains("and a \\\"quote\\\" end"), "{stored}");

    let miss = n3(
        r#"solid:where { <#nope> sioc:content ?old }; solid:deletes { <#nope> sioc:content ?old }"#,
    );
    let (st, _, _) = send!(&app, patch_req(CHAT, &miss));
    assert_eq!(st, 409, "where miss");
    let absent = n3(r#"solid:deletes { <#m2> sioc:content "never" }"#);
    let (st, _, _) = send!(&app, patch_req(CHAT, &absent));
    assert_eq!(st, 409, "delete of an absent triple");
}

#[actix_web::test]
async fn non_ascii_text_survives_repeated_patches() {
    let app = test::init_service(build_app(AppState::new(public_storage().await))).await;
    let (st, _, _) = send!(
        &app,
        patch_req(CHAT, &n3("solid:inserts { <#u> sioc:content \"café 😀\" }"))
    );
    assert_eq!(st, 201);
    for i in 0..3 {
        let (st, _, _) = send!(
            &app,
            patch_req(
                CHAT,
                &n3(&format!("solid:inserts {{ <#n{i}> sioc:content \"x\" }}"))
            )
        );
        assert_eq!(st, 204);
    }
    let (_, stored, _) = send!(&app, test::TestRequest::get().uri(CHAT));
    assert!(
        stored.contains("\"café 😀\""),
        "non-ASCII text was re-encoded: {stored}"
    );
}

#[actix_web::test]
async fn a_resource_put_as_prefixed_turtle_can_be_patched_without_losing_triples() {
    let app = test::init_service(build_app(AppState::new(public_storage().await))).await;
    let turtle = "@prefix ex: <http://example.org/> .\n\
                  <#a> ex:p \"one\" ; ex:q \"two\" .\n<#b> ex:p \"three\" .\n";
    let (st, _, _) = send!(
        &app,
        test::TestRequest::put()
            .uri("/public/doc.ttl")
            .insert_header(("content-type", "text/turtle"))
            .set_payload(turtle)
    );
    assert!(st == 201 || st == 204, "PUT {st}");
    let (st, body, _) = send!(
        &app,
        patch_req(
            "/public/doc.ttl",
            &n3(r#"solid:inserts { <#c> <http://example.org/p> "four" }"#)
        )
    );
    assert_eq!(st, 204, "{body}");
    let (_, stored, _) = send!(&app, test::TestRequest::get().uri("/public/doc.ttl"));
    for v in ["one", "two", "three", "four"] {
        assert!(
            stored.contains(&format!("\"{v}\"")),
            "lost \"{v}\": {stored}"
        );
    }
}

#[actix_web::test]
async fn concurrent_inserts_are_all_kept() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    storage
        .put("/.acl", Bytes::from(PUBLIC_RW_ACL), "text/turtle")
        .await
        .unwrap();
    storage
        .put(CHAT, Bytes::from(""), "text/turtle")
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(storage))).await;

    const N: usize = 20;
    let requests = (0..N).map(|i| {
        let body = n3(&format!(
            "solid:inserts {{ <#c{i}> sioc:content \"message {i}\" }}"
        ));
        test::call_service(&app, patch_req(CHAT, &body).to_request())
    });
    let responses = futures_util::future::join_all(requests).await;
    for r in &responses {
        assert_eq!(r.status().as_u16(), 204);
    }
    let (_, stored, _) = send!(&app, test::TestRequest::get().uri(CHAT));
    let kept = (0..N)
        .filter(|i| stored.contains(&format!("#c{i}>")))
        .count();
    assert_eq!(kept, N, "lost updates: {stored}");
}

#[actix_web::test]
async fn stale_if_match_and_if_none_match_star_are_refused() {
    let app = test::init_service(build_app(AppState::new(public_storage().await))).await;
    // Each PUT writes a different body, so a successful write changes the ETag.
    let version = std::cell::Cell::new(0);
    let put = |etag_header: Option<(&'static str, String)>| {
        version.set(version.get() + 1);
        let mut r = test::TestRequest::put()
            .uri("/public/doc.ttl")
            .insert_header(("content-type", "text/turtle"))
            .set_payload(format!("<#a> <#b> \"v{}\" .\n", version.get()));
        if let Some(h) = etag_header {
            r = r.insert_header(h);
        }
        r
    };
    let (st, _, _) = send!(&app, put(None));
    assert_eq!(st, 201);
    let (_, _, etag) = send!(&app, test::TestRequest::get().uri("/public/doc.ttl"));
    let etag = etag.expect("GET returns an ETag");

    // A matching ETag is accepted, and changes the ETag.
    let (st, _, _) = send!(&app, put(Some(("if-match", etag.clone()))));
    assert!(
        st == 200 || st == 204 || st == 201,
        "matching If-Match on PUT: {st}"
    );

    // The old ETag is now stale on both PUT and PATCH.
    let (st, _, _) = send!(&app, put(Some(("if-match", etag.clone()))));
    assert_eq!(st, 412, "stale If-Match on PUT");
    let (st, _, _) = send!(
        &app,
        patch_req("/public/doc.ttl", &n3(r#"solid:inserts { <#x> <#y> "z" }"#))
            .insert_header(("if-match", etag))
    );
    assert_eq!(st, 412, "stale If-Match on PATCH");

    // `If-None-Match: *` only creates.
    let (st, _, _) = send!(&app, put(Some(("if-none-match", "*".to_string()))));
    assert_eq!(st, 412, "If-None-Match: * over an existing resource");
    let (st, _, _) = send!(
        &app,
        test::TestRequest::put()
            .uri("/public/new.ttl")
            .insert_header(("content-type", "text/turtle"))
            .insert_header(("if-none-match", "*"))
            .set_payload("<#a> <#b> \"v\" .\n")
    );
    assert_eq!(st, 201, "If-None-Match: * on an absent resource");
}
