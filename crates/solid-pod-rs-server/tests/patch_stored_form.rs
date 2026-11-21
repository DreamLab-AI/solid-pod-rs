//! SP-PATCH-WRITE-REBASE and SP-PAR-276: an RDF PATCH keeps every stored
//! relative IRI relative, whatever the request `Host` says, and reads and
//! writes a stored JSON-LD body in JSON-LD.
//!
//! The patch is read and applied in one fixed IRI space that no request
//! header chooses. A relative IRI (`<#a>`, `</doc>`) stored before the patch
//! is stored relative after it, so a writer who sends a hostile `Host` cannot
//! rebase the document onto another origin, with or without `public_base_url`.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const OPEN_ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#all> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ;\n\
       acl:mode acl:Read, acl:Write, acl:Control .\n";

const HOSTILE: &str = "evil.example";

async fn storage_with(path: &str, body: &str, ct: &str) -> Arc<dyn Storage> {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    s.put(path, Bytes::from(body.to_owned()), ct).await.unwrap();
    s
}

async fn patch(state: AppState, path: &str, host: &str, ct: &str, body: &str) -> (u16, String) {
    let app = test::init_service(build_app(state)).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::patch()
            .uri(path)
            .insert_header(("host", host))
            .insert_header(("content-type", ct))
            .set_payload(body.to_owned())
            .to_request(),
    )
    .await;
    let status = resp.status().as_u16();
    (
        status,
        String::from_utf8(test::read_body(resp).await.to_vec()).unwrap(),
    )
}

async fn stored(s: &Arc<dyn Storage>, path: &str) -> (String, String) {
    let (b, m) = s.get(path).await.unwrap();
    let text = String::from_utf8(b.to_vec()).unwrap();
    // The working base never reaches storage.
    assert!(!text.contains("patch-base.invalid"), "{text}");
    (text, m.content_type)
}

const N3_PREFIX: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n";

fn n3(inserts: &str) -> String {
    format!("{N3_PREFIX}_:p a solid:InsertDeletePatch; solid:inserts {{ {inserts} }}.")
}

#[actix_web::test]
async fn a_hostile_host_cannot_rebase_stored_relative_iris_through_sparql() {
    for base in [None, Some("https://pod.example")] {
        let s = storage_with("/doc.ttl", "<#a> <#b> \"v1\" .\n", "text/turtle").await;
        let mut state = AppState::new(s.clone());
        state.public_base_url = base.map(str::to_owned);
        let (st, body) = patch(
            state,
            "/doc.ttl",
            HOSTILE,
            "application/sparql-update",
            "INSERT DATA { <http://other.example/s> <http://other.example/p> \"n\" }",
        )
        .await;
        assert_eq!(st, 204, "{body}");
        let (text, _) = stored(&s, "/doc.ttl").await;
        assert!(
            !text.contains(HOSTILE),
            "rebased onto the Host ({base:?}): {text}"
        );
        assert!(
            text.contains("<#a>") && text.contains("<#b>"),
            "relative form lost ({base:?}): {text}"
        );
        assert!(text.contains("\"v1\"") && text.contains("\"n\""), "{text}");
    }
}

#[actix_web::test]
async fn a_hostile_host_cannot_rebase_through_an_n3_patch_either() {
    let s = storage_with("/doc.ttl", "<#a> <#b> \"v1\" .\n", "text/turtle").await;
    let (st, body) = patch(
        AppState::new(s.clone()),
        "/doc.ttl",
        HOSTILE,
        "text/n3",
        &n3("<#a> <#c> \"v2\" ."),
    )
    .await;
    assert_eq!(st, 204, "{body}");
    let (text, _) = stored(&s, "/doc.ttl").await;
    assert!(!text.contains(HOSTILE), "{text}");
    assert!(
        text.contains("<#a>") && text.contains("<#c>") && text.contains("<#b>"),
        "{text}"
    );
}

#[actix_web::test]
async fn the_same_patch_stores_the_same_bytes_whatever_the_host() {
    let mut seen = Vec::new();
    for host in ["pod.example", HOSTILE, "localhost:8080"] {
        let s = storage_with("/doc.ttl", "<#a> <#b> \"v1\" .\n", "text/turtle").await;
        let (st, _) = patch(
            AppState::new(s.clone()),
            "/doc.ttl",
            host,
            "text/n3",
            &n3("</other> <#c> \"v2\" ."),
        )
        .await;
        assert_eq!(st, 204);
        seen.push(stored(&s, "/doc.ttl").await.0);
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]), "{seen:?}");
}

#[actix_web::test]
async fn a_patch_that_creates_a_resource_does_not_use_the_host_either() {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    let (st, body) = patch(
        AppState::new(s.clone()),
        "/new.ttl",
        HOSTILE,
        "text/n3",
        &n3("<#a> <#b> \"v\" ."),
    )
    .await;
    assert_eq!(st, 201, "{body}");
    let (text, _) = stored(&s, "/new.ttl").await;
    assert!(!text.contains(HOSTILE) && text.contains("<#a>"), "{text}");
}

#[actix_web::test]
async fn an_acl_patch_keeps_path_form_targets_and_ignores_the_host() {
    let s: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(OPEN_ACL), "text/turtle")
        .await
        .unwrap();
    let acl = "<#all> a <http://www.w3.org/ns/auth/acl#Authorization>; \
         <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>; \
         <http://www.w3.org/ns/auth/acl#accessTo> </doc>; \
         <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, \
         <http://www.w3.org/ns/auth/acl#Control> .";
    let (st, body) = patch(
        AppState::new(s.clone()),
        "/doc.acl",
        HOSTILE,
        "text/n3",
        &n3(acl),
    )
    .await;
    assert_eq!(st, 201, "{body}");
    let (text, _) = stored(&s, "/doc.acl").await;
    assert!(text.contains("</doc>") && !text.contains(HOSTILE), "{text}");
}

// ---------------------------------------------------------------------------
// SP-PAR-276: a stored JSON-LD body is patched and written back as JSON-LD.
// ---------------------------------------------------------------------------

const JSONLD: &str = r##"{"@context":{"ex":"http://example.org/ns#"},
  "@graph":[{"@id":"#me","ex:name":"Alice","ex:knows":{"@id":"#you"}},
            {"@id":"http://other.example/x","ex:tag":"t"}]}"##;

#[actix_web::test]
async fn a_stored_json_ld_body_is_patched_and_stays_json_ld() {
    let s = storage_with("/card.jsonld", JSONLD, "application/ld+json").await;
    let (st, body) = patch(
        AppState::new(s.clone()),
        "/card.jsonld",
        HOSTILE,
        "text/n3",
        &format!(
            "{N3_PREFIX}_:p a solid:InsertDeletePatch; \
             solid:deletes {{ <#me> <http://example.org/ns#name> \"Alice\" . }}; \
             solid:inserts {{ <#me> <http://example.org/ns#name> \"Alicia\" ; \
                               <http://example.org/ns#age> 30 . }}."
        ),
    )
    .await;
    assert_eq!(st, 204, "{body}");
    let (text, ct) = stored(&s, "/card.jsonld").await;
    assert!(ct.starts_with("application/ld+json"), "{ct}");
    let v: serde_json::Value = serde_json::from_str(&text).expect("stored body is JSON");
    // Round trip through the graph: read it back with the JSON-LD reader.
    let g = solid_pod_rs::rdf_input::parse_jsonld(text.as_bytes(), "https://p.example/card.jsonld")
        .expect("valid JSON-LD");
    let nt = g.to_ntriples();
    assert!(nt.contains("\"Alicia\"") && nt.contains("\"30\""), "{nt}");
    assert!(!nt.contains("\"Alice\""), "deleted value kept: {nt}");
    assert!(
        nt.contains("https://p.example/card.jsonld#you"),
        "untouched triple lost: {nt}"
    );
    assert!(
        nt.contains("http://other.example/x"),
        "untouched node lost: {nt}"
    );
    // The document's own IRIs stay relative, not rebased onto the Host.
    assert!(!text.contains(HOSTILE), "{text}");
    assert!(text.contains("#me") && text.contains("#you"), "{text}");
    drop(v);
}

#[actix_web::test]
async fn a_json_ld_patch_that_cannot_round_trip_is_refused_and_nothing_changes() {
    // A named graph, a remote context and a relative predicate cannot be
    // read back, so the stored body is never replaced.
    for body in [
        r##"{"@id":"http://g.example/g","@graph":[{"@id":"http://a.example/s","http://a.example/p":"o"}]}"##,
        r##"{"@context":"https://remote.example/ctx.jsonld","@id":"http://a.example/s"}"##,
        "{not json",
    ] {
        let s = storage_with("/card.jsonld", body, "application/ld+json").await;
        let (st, msg) = patch(
            AppState::new(s.clone()),
            "/card.jsonld",
            "pod.example",
            "text/n3",
            &n3("<#a> <http://example.org/p> \"v\" ."),
        )
        .await;
        assert_eq!(st, 409, "{body}: {msg}");
        assert_eq!(stored(&s, "/card.jsonld").await.0, body, "{body}");
    }
}

#[actix_web::test]
async fn a_relative_predicate_cannot_be_written_into_json_ld() {
    let s = storage_with("/card.jsonld", JSONLD, "application/ld+json").await;
    let before = stored(&s, "/card.jsonld").await.0;
    let (st, msg) = patch(
        AppState::new(s.clone()),
        "/card.jsonld",
        "pod.example",
        "text/n3",
        &n3("<#me> <#rel> \"v\" ."),
    )
    .await;
    assert_eq!(st, 409, "{msg}");
    assert_eq!(stored(&s, "/card.jsonld").await.0, before);
}

#[actix_web::test]
async fn a_json_ld_acl_patch_is_checked_and_stays_json_ld() {
    let acl = r##"{"@context":{"acl":"http://www.w3.org/ns/auth/acl#","foaf":"http://xmlns.com/foaf/0.1/"},
      "@graph":[{"@id":"#all","@type":"acl:Authorization","acl:agentClass":{"@id":"foaf:Agent"},
        "acl:accessTo":{"@id":"/doc"},"acl:mode":[{"@id":"acl:Read"},{"@id":"acl:Control"}]}]}"##;
    let s = storage_with("/doc.acl", acl, "application/ld+json").await;
    // Adding a reader keeps Control for everyone: allowed.
    let (st, msg) = patch(
        AppState::new(s.clone()),
        "/doc.acl",
        "pod.example",
        "text/n3",
        &n3(
            "<#friend> a <http://www.w3.org/ns/auth/acl#Authorization>; \
             <http://www.w3.org/ns/auth/acl#agent> <https://friend.example/#me>; \
             <http://www.w3.org/ns/auth/acl#accessTo> </doc>; \
             <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .",
        ),
    )
    .await;
    assert_eq!(st, 204, "{msg}");
    let (text, ct) = stored(&s, "/doc.acl").await;
    assert!(ct.starts_with("application/ld+json"), "{ct}");
    // The result is still a readable ACL with both rules.
    let doc =
        solid_pod_rs::wac::parse_jsonld_acl_at(text.as_bytes(), "/doc.acl").expect("ACL reads");
    assert_eq!(doc.graph.as_ref().map(Vec::len), Some(2), "{text}");
}
