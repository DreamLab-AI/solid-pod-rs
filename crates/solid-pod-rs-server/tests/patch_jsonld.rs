//! SP-PAR-276: PATCH of stored JSON-LD and of an HTML page's JSON-LD island.
//!
//! Properties: the stored body and the patch are read in ONE IRI space, the
//! resource's real URL from the configured public origin and never a request
//! `Host`; without a configured origin the PATCH is refused (409), not guessed;
//! the result is written back in the stored form; a literal cannot break out of
//! an HTML island; a SPARQL patch is classified (needs Read) under the base it
//! is applied with.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const ORIGIN: &str = "https://pod.example";
const FOAF: &str = "http://xmlns.com/foaf/0.1/name";

fn acl(modes: &str) -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#p> a acl:Authorization ; acl:agentClass foaf:Agent ;\n  acl:accessTo </> ; acl:default </> ; acl:mode {modes} .\n"
    )
}

const DOC: &str =
    r##"{"@context":{"name":"http://xmlns.com/foaf/0.1/name"},"@id":"#me","name":"old"}"##;

async fn setup(origin: Option<&str>, modes: &str) -> (Arc<MemoryBackend>, AppState) {
    let s = Arc::new(MemoryBackend::new());
    s.put("/.acl", Bytes::from(acl(modes)), "text/turtle")
        .await
        .unwrap();
    s.put("/doc.jsonld", Bytes::from(DOC), "application/ld+json")
        .await
        .unwrap();
    let mut st = AppState::new(s.clone());
    st.public_base_url = origin.map(str::to_string);
    (s, st)
}

async fn patch(st: &AppState, uri: &str, ct: &str, body: &str) -> (u16, String) {
    let app = test::init_service(build_app(st.clone())).await;
    let r = test::call_service(
        &app,
        test::TestRequest::patch()
            .uri(uri)
            .insert_header(("host", "evil.example"))
            .insert_header(("content-type", ct))
            .set_payload(body.to_string())
            .to_request(),
    )
    .await;
    let status = r.status().as_u16();
    (
        status,
        String::from_utf8_lossy(&test::read_body(r).await).to_string(),
    )
}

const N3: &str = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix foaf: <http://xmlns.com/foaf/0.1/>.\n";

#[actix_web::test]
async fn without_a_configured_origin_a_json_ld_patch_is_refused() {
    let (s, st) = setup(None, "acl:Read, acl:Write").await;
    let body =
        format!("{N3}_:p a solid:InsertDeletePatch; solid:inserts {{ <#me> foaf:name \"new\" }}.");
    let (code, msg) = patch(&st, "/doc.jsonld", "text/n3", &body).await;
    assert_eq!(code, 409, "{msg}");
    assert!(msg.contains("public_base_url"), "{msg}");
    let sp = "INSERT DATA { <#me> <http://xmlns.com/foaf/0.1/name> \"new\" }";
    let (code, _) = patch(&st, "/doc.jsonld", "application/sparql-update", sp).await;
    assert_eq!(code, 409);
    assert_eq!(s.get("/doc.jsonld").await.unwrap().0, Bytes::from(DOC));
}

#[actix_web::test]
async fn n3_and_sparql_patch_read_and_write_one_iri_space_from_the_configured_origin() {
    let (s, st) = setup(Some(ORIGIN), "acl:Read, acl:Write").await;
    // N3: delete the old value, insert a new one, naming the subject relatively.
    let body = format!(
        "{N3}_:p a solid:InsertDeletePatch; solid:deletes {{ <#me> foaf:name \"old\" }}; solid:inserts {{ <#me> foaf:name \"new\" }}."
    );
    let (code, msg) = patch(&st, "/doc.jsonld", "text/n3", &body).await;
    assert_eq!(code, 204, "{msg}");
    let (bytes, meta) = s.get("/doc.jsonld").await.unwrap();
    assert_eq!(meta.content_type, "application/ld+json", "stored form kept");
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("https://pod.example/doc.jsonld#me"), "{text}");
    assert!(
        !text.contains("evil.example"),
        "the request Host is never used: {text}"
    );
    assert!(text.contains("new") && !text.contains("old"), "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v.is_array() || v.is_object());

    // SPARQL with relative IRIs, resolved against the same URL: replace the value.
    let sp = format!(
        "DELETE DATA {{ <#me> <{FOAF}> \"new\" }} ; INSERT DATA {{ <#me> <{FOAF}> \"newer\" }}"
    );
    let (code, msg) = patch(&st, "/doc.jsonld", "application/sparql-update", &sp).await;
    assert_eq!(code, 204, "{msg}");
    let text = String::from_utf8(s.get("/doc.jsonld").await.unwrap().0.to_vec()).unwrap();
    assert!(
        text.contains("newer") && !text.contains("\"new\""),
        "replace, not duplicate: {text}"
    );

    // The same delete by absolute URL names the same triple.
    let sp = format!("DELETE DATA {{ <{ORIGIN}/doc.jsonld#me> <{FOAF}> \"newer\" }}");
    let (code, _) = patch(&st, "/doc.jsonld", "application/sparql-update", &sp).await;
    assert_eq!(code, 204);
    let text = String::from_utf8(s.get("/doc.jsonld").await.unwrap().0.to_vec()).unwrap();
    assert!(!text.contains("newer"), "{text}");
}

/// A delete that names a triple the resource does not hold: an N3 patch is a
/// 409; a SPARQL `DELETE DATA` changes nothing and is a 204, which is what JSS
/// answers and what SPARQL 1.1 Update specifies (recorded in row 276).
#[actix_web::test]
async fn a_delete_matching_nothing_is_a_conflict_for_n3_and_ignored_for_sparql() {
    let (s, st) = setup(Some(ORIGIN), "acl:Read, acl:Write").await;
    let body = format!(
        "{N3}_:p a solid:InsertDeletePatch; solid:deletes {{ <#me> foaf:name \"absent\" }}."
    );
    let (code, _) = patch(&st, "/doc.jsonld", "text/n3", &body).await;
    assert_eq!(code, 409);
    let sp = format!("DELETE DATA {{ <#me> <{FOAF}> \"absent\" }}");
    let (code, _) = patch(&st, "/doc.jsonld", "application/sparql-update", &sp).await;
    assert_eq!(code, 204);
    let text = String::from_utf8(s.get("/doc.jsonld").await.unwrap().0.to_vec()).unwrap();
    assert!(text.contains("old"), "nothing was removed: {text}");
}

const PAGE: &str = "<!DOCTYPE html>\n<html><head><title>t</title></head>\n<body>\n<script>var keep = 1;</script>\n\
<script type=\"application/ld+json\">{\"@context\":{\"name\":\"http://xmlns.com/foaf/0.1/name\"},\"@id\":\"#me\",\"name\":\"old\"}</script>\n\
<p>kept</p>\n</body></html>\n";

#[actix_web::test]
async fn an_html_data_island_is_patched_in_place_and_cannot_be_broken_out_of() {
    let (s, st) = setup(Some(ORIGIN), "acl:Read, acl:Write").await;
    s.put("/page.html", Bytes::from(PAGE), "text/html")
        .await
        .unwrap();
    let evil = "</script><img src=x onerror=alert(1)>";
    let body = format!(
        "{N3}_:p a solid:InsertDeletePatch; solid:deletes {{ <#me> foaf:name \"old\" }}; solid:inserts {{ <#me> foaf:name \"{}\" }}.",
        evil.replace('"', "")
    );
    let (code, msg) = patch(&st, "/page.html", "text/n3", &body).await;
    assert_eq!(code, 204, "{msg}");
    let (bytes, meta) = s.get("/page.html").await.unwrap();
    assert_eq!(meta.content_type, "text/html");
    let page = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(page.starts_with("<!DOCTYPE html>\n<html><head><title>t</title></head>\n<body>\n<script>var keep = 1;</script>\n<script type=\"application/ld+json\">"));
    assert!(
        page.ends_with("</script>\n<p>kept</p>\n</body></html>\n"),
        "{page}"
    );
    assert_eq!(
        page.matches("</script").count(),
        2,
        "only the two original closings: {page}"
    );
    assert!(!page.contains("<img"), "{page}");
    assert!(page.contains("https://pod.example/page.html#me"), "{page}");
}

#[actix_web::test]
async fn html_without_an_island_and_plain_json_are_refused() {
    let (s, st) = setup(Some(ORIGIN), "acl:Read, acl:Write").await;
    s.put(
        "/plain.html",
        Bytes::from("<html><p>x</p></html>"),
        "text/html",
    )
    .await
    .unwrap();
    let body =
        format!("{N3}_:p a solid:InsertDeletePatch; solid:inserts {{ <#me> foaf:name \"n\" }}.");
    let (code, _) = patch(&st, "/plain.html", "text/n3", &body).await;
    assert_eq!(code, 409);
    assert_eq!(
        s.get("/plain.html").await.unwrap().0,
        Bytes::from("<html><p>x</p></html>")
    );
}

/// A SPARQL patch whose relative IRIs only parse against the resource URL is
/// still classified as inspecting the resource: a Write-only agent cannot use
/// it (the classifier and the applier share one base).
#[actix_web::test]
async fn a_relative_iri_where_clause_still_needs_read() {
    let (s, st) = setup(Some(ORIGIN), "acl:Write").await;
    let sp = format!("INSERT {{ <#leak> <http://e/v> ?o }} WHERE {{ <#me> <{FOAF}> ?o }}");
    let (code, _) = patch(&st, "/doc.jsonld", "application/sparql-update", &sp).await;
    assert!(
        code == 401 || code == 403,
        "write-only agent ran a relative-IRI WHERE: {code}"
    );
    assert_eq!(s.get("/doc.jsonld").await.unwrap().0, Bytes::from(DOC));
}

/// The Turtle path is unchanged: a Turtle resource still patches as Turtle.
#[actix_web::test]
async fn turtle_resources_are_still_patched_as_turtle() {
    let (s, st) = setup(Some(ORIGIN), "acl:Read, acl:Write").await;
    s.put(
        "/t.ttl",
        Bytes::from("<#me> <http://xmlns.com/foaf/0.1/name> \"old\" .\n"),
        "text/turtle",
    )
    .await
    .unwrap();
    let body =
        format!("{N3}_:p a solid:InsertDeletePatch; solid:inserts {{ <#me> foaf:name \"new\" }}.");
    let (code, msg) = patch(&st, "/t.ttl", "text/n3", &body).await;
    assert_eq!(code, 204, "{msg}");
    assert_eq!(s.get("/t.ttl").await.unwrap().1.content_type, "text/turtle");
}
