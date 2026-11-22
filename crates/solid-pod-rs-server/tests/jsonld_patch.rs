//! SP-PAR-276: PATCH of a stored JSON-LD document or an HTML page with one
//! JSON-LD data island, edited in place (the narrow third attempt).
//!
//! Properties, each with the test that fails if it is violated:
//!
//! * the base is the configured public origin, never `Host`/forwarding
//!   headers, and none configured means refusal;
//! * the stored bytes outside the edited values are unchanged, byte for byte;
//! * an unsupported shape, an unexpressible edit, a delete that names a triple
//!   the document does not hold (both dialects), a JSON-LD ACL, a document
//!   over the bounds: 409 with one message, and the stored bytes untouched;
//! * a remote `@context` is never fetched;
//! * Append-only agents never reach this path; Write is required, and Read
//!   when the patch inspects the document;
//! * a WebID profile card keeps what the readers see (issuer, key) after a
//!   rename, which is the regression for the withdrawn second attempt.

use std::net::TcpListener;
use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const ORIGIN: &str = "https://pod.example";
const FOAF: &str = "http://xmlns.com/foaf/0.1/";
const REFUSAL: &str = "refused: this stored document cannot be patched in place; PUT a replacement";

fn acl(modes: &str) -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#p> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo </> ; acl:default </> ; acl:mode {modes} .\n"
    )
}

struct Pod {
    storage: Arc<dyn Storage>,
}

async fn pod(modes: &str) -> Pod {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(acl(modes)), "text/turtle")
        .await
        .unwrap();
    Pod { storage }
}

fn state(p: &Pod, origin: Option<&str>) -> AppState {
    let mut st = AppState::new(p.storage.clone());
    st.public_base_url = origin.map(str::to_string);
    st
}

async fn put(p: &Pod, path: &str, body: &str, ct: &str) {
    p.storage
        .put(path, Bytes::from(body.to_string()), ct)
        .await
        .unwrap();
}

async fn stored(p: &Pod, path: &str) -> String {
    String::from_utf8(p.storage.get(path).await.unwrap().0.to_vec()).unwrap()
}

macro_rules! patch {
    ($app:expr, $uri:expr, $ct:expr, $body:expr) => {{
        let req = test::TestRequest::patch()
            .uri($uri)
            .insert_header(("content-type", $ct))
            .set_payload($body.to_string())
            .to_request();
        let rsp = test::call_service($app, req).await;
        let status = rsp.status().as_u16();
        let body = String::from_utf8(test::read_body(rsp).await.to_vec()).unwrap();
        (status, body)
    }};
}

fn sparql(del: &str, ins: &str) -> String {
    format!("DELETE DATA {{ {del} }} ; INSERT DATA {{ {ins} }}")
}

fn n3(del: &str, ins: &str) -> String {
    format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         _:p a solid:InsertDeletePatch; solid:deletes {{ {del} }}; solid:inserts {{ {ins} }}."
    )
}

const SPARQL: &str = "application/sparql-update";
const N3: &str = "text/n3";

/// A document laid out the way nobody's serialiser would: odd whitespace,
/// escapes, key order, a nested node, an integer, a language tag.
const ODD: &str = "{\t\"@context\" : {\"foaf\": \"http://xmlns.com/foaf/0.1/\", \"nick\": \"foaf:nick\"},\n\
  \"foaf:name\"\t: \"Old \\u00e9\\/x\",\n  \"@id\": \"#me\",\n\
  \"nick\": [ \"a\" ,\"b\" ],   \"foaf:age\": 42,\n\
  \"foaf:knows\": {\"@id\": \"#b\", \"foaf:name\": {\"@value\": \"Bee\", \"@language\": \"en\"}}\n}\n";

fn me(path: &str) -> String {
    format!("<{ORIGIN}{path}#me>")
}

// ---------------------------------------------------------------------------

#[actix_web::test]
async fn an_edit_changes_only_the_edited_bytes_in_both_dialects() {
    for (ct, make) in [
        (SPARQL, sparql as fn(&str, &str) -> String),
        (N3, n3 as fn(&str, &str) -> String),
    ] {
        let p = pod("acl:Read, acl:Write").await;
        put(&p, "/doc", ODD, "application/ld+json").await;
        let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
        let name = format!("{} <{FOAF}name>", me("/doc"));
        let (st, body) = patch!(
            &app,
            "/doc",
            ct,
            make(
                &format!("{name} \"Old \u{e9}/x\""),
                &format!("{name} \"New\"")
            )
        );
        assert_eq!(st, 204, "{ct}: {body}");
        assert_eq!(
            stored(&p, "/doc").await,
            ODD.replace("\"Old \\u00e9\\/x\"", "\"New\""),
            "{ct}: everything else must be byte-identical"
        );
        // And the nested node's own property, with a language tag, in place.
        let bee = format!("<{ORIGIN}/doc#b> <{FOAF}name>");
        let (st, body) = patch!(
            &app,
            "/doc",
            ct,
            make(&format!("{bee} \"Bee\"@en"), &format!("{bee} \"Bie\"@en"))
        );
        assert_eq!(st, 204, "{ct}: {body}");
        assert!(stored(&p, "/doc").await.contains("\"@value\": \"Bie\""));
    }
}

#[actix_web::test]
async fn an_absolute_delete_matches_a_relative_id() {
    for (ct, make) in [
        (SPARQL, sparql as fn(&str, &str) -> String),
        (N3, n3 as fn(&str, &str) -> String),
    ] {
        let p = pod("acl:Read, acl:Write").await;
        put(&p, "/doc", ODD, "application/ld+json").await;
        let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
        // The document says `"@id": "#me"`; the patch names the absolute IRI.
        let nick = format!("{} <{FOAF}nick>", me("/doc"));
        let (st, body) = patch!(&app, "/doc", ct, make(&format!("{nick} \"a\""), ""));
        assert_eq!(st, 204, "{ct}: {body}");
        assert_eq!(stored(&p, "/doc").await, ODD.replace("\"a\" ,", ""));
    }
}

#[actix_web::test]
async fn a_delete_that_names_an_absent_triple_is_409_in_both_dialects_and_writes_nothing() {
    for doc_ct in ["application/ld+json", "text/html"] {
        for (ct, make) in [
            (SPARQL, sparql as fn(&str, &str) -> String),
            (N3, n3 as fn(&str, &str) -> String),
        ] {
            let p = pod("acl:Read, acl:Write").await;
            let body = if doc_ct == "text/html" {
                island_page("{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@id\": \"#me\", \"foaf:name\": \"A\"}")
            } else {
                "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@id\": \"#me\", \"foaf:name\": \"A\"}".to_string()
            };
            put(&p, "/doc", &body, doc_ct).await;
            let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
            let name = format!("{} <{FOAF}name>", me("/doc"));
            // One present, one absent: fewer removed than named.
            let (st, _) = patch!(
                &app,
                "/doc",
                ct,
                make(
                    &format!("{name} \"A\" . {name} \"never\""),
                    &format!("{name} \"B\"")
                )
            );
            assert_eq!(st, 409, "{doc_ct} {ct}");
            assert_eq!(
                stored(&p, "/doc").await,
                body,
                "{doc_ct} {ct}: bytes changed"
            );
        }
    }
}

fn island_page(json: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <title>t &amp; u</title>\n  \
         <script type=\"application/ld+json\">\n{json}\n  </script>\n</head>\n\
         <body><!-- keep me --><p>hello <b>there</b></p></body>\n</html>"
    )
}

#[actix_web::test]
async fn every_refusal_answers_one_message_and_leaves_the_stored_bytes_identical() {
    let ctx = "\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}";
    let two = format!(
        "<script type=\"application/ld+json\">{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}</script>\
         <script type=\"application/ld+json\">{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}</script>"
    );
    let cases: Vec<(&str, &str, String)> = vec![
        ("array context", "application/ld+json", format!("{{\"@context\": [{{\"foaf\": \"{FOAF}\"}}], \"@id\": \"#me\", \"{FOAF}name\": \"A\"}}")),
        ("@list", "application/ld+json", format!("{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\", \"foaf:knows\": {{\"@list\": [{{\"@id\": \"#b\"}}]}}}}")),
        ("@reverse", "application/ld+json", format!("{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\", \"@reverse\": {{\"foaf:knows\": {{\"@id\": \"#b\"}}}}}}")),
        ("named graph", "application/ld+json", format!("{{{ctx}, \"@id\": \"#g\", \"@graph\": [{{\"@id\": \"#me\", \"foaf:name\": \"A\"}}]}}")),
        ("unmapped key", "application/ld+json", format!("{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\", \"extra\": 1}}")),
        ("blank node", "application/ld+json", format!("{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\", \"foaf:knows\": {{\"foaf:name\": \"x\"}}}}")),
        ("float", "application/ld+json", format!("{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\", \"foaf:age\": 1.5}}")),
        ("not JSON", "application/ld+json", "{not json".to_string()),
        ("no island", "text/html", "<html><body><p>x</p></body></html>".to_string()),
        ("two islands", "text/html", two),
        ("island in a comment", "text/html", format!("<!-- <script type=\"application/ld+json\">{{{ctx}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}</script> -->")),
    ];
    for (why, ct, body) in cases {
        for (pct, make) in [
            (SPARQL, sparql as fn(&str, &str) -> String),
            (N3, n3 as fn(&str, &str) -> String),
        ] {
            let p = pod("acl:Read, acl:Write").await;
            put(&p, "/doc", &body, ct).await;
            let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
            let name = format!("{} <{FOAF}name>", me("/doc"));
            let (st, msg) = patch!(&app, "/doc", pct, make("", &format!("{name} \"B\"")));
            assert_eq!(st, 409, "{why} {pct}: {msg}");
            assert_eq!(msg, REFUSAL, "{why} {pct}: one generic message");
            assert_eq!(stored(&p, "/doc").await, body, "{why} {pct}: bytes changed");
        }
    }
}

#[actix_web::test]
async fn an_insert_a_document_cannot_express_is_refused() {
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    for q in [
        // A new subject in a single-node document.
        format!("INSERT DATA {{ <{ORIGIN}/other> <{FOAF}name> \"x\" }}"),
        // A blank-node object.
        format!("INSERT DATA {{ {} <{FOAF}knows> _:b }}", me("/doc")),
    ] {
        let p = pod("acl:Read, acl:Write").await;
        put(&p, "/doc", &doc, "application/ld+json").await;
        let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
        let (st, msg) = patch!(&app, "/doc", SPARQL, q);
        assert_eq!(st, 409, "{q}: {msg}");
        assert_eq!(stored(&p, "/doc").await, doc);
    }
}

#[actix_web::test]
async fn with_no_public_base_url_the_patch_is_refused() {
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, None))).await;
    let name = format!("<http://localhost:8080/doc#me> <{FOAF}name>");
    let (st, msg) = patch!(
        &app,
        "/doc",
        SPARQL,
        sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
    );
    assert_eq!(st, 409, "{msg}");
    assert_eq!(msg, REFUSAL);
    assert_eq!(stored(&p, "/doc").await, doc);
}

#[actix_web::test]
async fn a_hostile_host_header_changes_nothing() {
    // The base is the configured origin. A caller who names the IRI under an
    // attacker-chosen Host gets 409 and no write; the configured IRI still works.
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let evil = "<http://evil.example/doc#me>";
    for hdrs in [
        vec![("host", "evil.example")],
        vec![
            ("x-forwarded-host", "evil.example"),
            ("x-forwarded-proto", "http"),
        ],
        vec![("forwarded", "host=evil.example;proto=http")],
    ] {
        for (subject, expect) in [(evil.to_string(), 409), (me("/doc"), 204)] {
            let mut req = test::TestRequest::patch()
                .uri("/doc")
                .insert_header(("content-type", SPARQL));
            for h in &hdrs {
                req = req.insert_header(*h);
            }
            let name = format!("{subject} <{FOAF}name>");
            let q = if expect == 204 {
                sparql(&format!("{name} \"A\""), &format!("{name} \"A\""))
            } else {
                sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
            };
            let rsp = test::call_service(&app, req.set_payload(q).to_request()).await;
            assert_eq!(rsp.status().as_u16(), expect, "{hdrs:?} {subject}");
            assert_eq!(stored(&p, "/doc").await, doc, "{hdrs:?}: bytes changed");
        }
    }
    // A relative `@id` in the stored document resolved against the evil host
    // would have been named by the evil IRI: it matched nothing above, and the
    // stored document still names `#me` relatively.
    assert!(stored(&p, "/doc").await.contains("\"@id\": \"#me\""));
}

#[actix_web::test]
async fn a_remote_context_is_never_fetched() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/ctx.jsonld", listener.local_addr().unwrap());
    let json = format!("{{\"@context\": \"{url}\", \"@id\": \"#me\", \"{FOAF}name\": \"A\"}}");
    for (ct, body) in [
        ("application/ld+json", json.clone()),
        ("text/html", island_page(&json)),
    ] {
        let p = pod("acl:Read, acl:Write").await;
        put(&p, "/doc", &body, ct).await;
        let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
        let name = format!("{} <{FOAF}name>", me("/doc"));
        let (st, _) = patch!(
            &app,
            "/doc",
            SPARQL,
            sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
        );
        assert_eq!(st, 409, "{ct}");
        assert_eq!(stored(&p, "/doc").await, body);
    }
    assert!(
        listener.accept().is_err(),
        "the server connected to the remote context URL"
    );
}

fn owner_did() -> String {
    let key = k256::schnorr::SigningKey::from_slice(&[0x11; 32]).unwrap();
    format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()))
}

fn nostr_auth(method: &str, path: &str, body: &[u8]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let t = solid_pod_rs::auth::nip98::mint_with_payload(
        &format!("{ORIGIN}{path}"),
        method,
        Some(body),
        &hex::encode([0x11u8; 32]),
        now,
    )
    .unwrap();
    format!("Nostr {t}")
}

#[actix_web::test]
async fn a_json_ld_acl_is_not_patchable() {
    // Even for the owner holding Control, and even when the edit is
    // expressible: a revocation must not "appear to succeed" on this path.
    let p = pod("acl:Read").await;
    put(
        &p,
        "/.acl",
        &format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n<#o> a acl:Authorization ; \
             acl:agent <{}> ; acl:accessTo </> ; acl:default </> ; \
             acl:mode acl:Read, acl:Write, acl:Control .\n",
            owner_did()
        ),
        "text/turtle",
    )
    .await;
    // The sidecar is the ACL of `/sub`: it must itself grant the owner Control
    // for the request to reach the PATCH handler at all.
    let acl_doc = format!(
        "{{\"@context\": {{\"acl\": \"http://www.w3.org/ns/auth/acl#\"}}, \
         \"@id\": \"#o\", \"@type\": \"acl:Authorization\", \
         \"acl:agent\": {{\"@id\": \"{}\"}}, \"acl:accessTo\": {{\"@id\": \"/sub\"}}, \
         \"acl:mode\": [{{\"@id\": \"acl:Read\"}}, {{\"@id\": \"acl:Control\"}}]}}",
        owner_did()
    );
    put(&p, "/sub.acl", &acl_doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let s = format!("<{ORIGIN}/sub.acl#o> <http://www.w3.org/ns/auth/acl#mode>");
    let body = sparql(&format!("{s} <http://www.w3.org/ns/auth/acl#Read>"), "");
    let req = test::TestRequest::patch()
        .uri("/sub.acl")
        .insert_header(("content-type", SPARQL))
        .insert_header((
            "authorization",
            nostr_auth("PATCH", "/sub.acl", body.as_bytes()),
        ))
        .set_payload(body)
        .to_request();
    let rsp = test::call_service(&app, req).await;
    let status = rsp.status().as_u16();
    let text = String::from_utf8(test::read_body(rsp).await.to_vec()).unwrap();
    assert_eq!(status, 409, "{text}");
    assert_eq!(text, REFUSAL, "refused by this path, not by authorisation");
    assert_eq!(stored(&p, "/sub.acl").await, acl_doc);
}

#[actix_web::test]
async fn an_append_only_agent_never_reaches_the_json_ld_path() {
    let p = pod("acl:Read, acl:Append").await;
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    put(&p, "/doc", &doc, "application/ld+json").await;
    let html = island_page(&doc);
    put(&p, "/page", &html, "text/html").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let name = format!("{} <{FOAF}name>", me("/doc"));
    for (path, orig) in [("/doc", &doc), ("/page", &html)] {
        let name = name.replace("/doc", path);
        let (st, msg) = patch!(
            &app,
            path,
            SPARQL,
            format!("INSERT DATA {{ {name} \"B\" }}")
        );
        assert_eq!(st, 409, "{path}: {msg}");
        assert_ne!(
            msg, REFUSAL,
            "{path}: refused by the append path, not this one"
        );
        assert_eq!(&stored(&p, path).await, orig);
    }
}

#[actix_web::test]
async fn write_is_required_and_read_too_when_the_patch_inspects_the_document() {
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    let name = format!("{} <{FOAF}name>", me("/doc"));
    // Read only: no write.
    let p = pod("acl:Read").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let (st, _) = patch!(&app, "/doc", SPARQL, sparql("", &format!("{name} \"B\"")));
    assert!(matches!(st, 401 | 403), "read-only agent: {st}");
    assert_eq!(stored(&p, "/doc").await, doc);
    // Write without Read: a delete that names triples inspects the document.
    let p = pod("acl:Write").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let (st, _) = patch!(
        &app,
        "/doc",
        SPARQL,
        sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
    );
    assert!(matches!(st, 401 | 403), "write-only agent deleting: {st}");
    assert_eq!(stored(&p, "/doc").await, doc);
    // Write with Read succeeds.
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let (st, _) = patch!(
        &app,
        "/doc",
        SPARQL,
        sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
    );
    assert_eq!(st, 204);
}

#[actix_web::test]
async fn a_patch_over_the_triple_bound_is_refused() {
    let doc = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/doc", &doc, "application/ld+json").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let subj = me("/doc");
    let many: String = (0..300)
        .map(|i| format!("{subj} <{FOAF}nick> \"n{i}\" . "))
        .collect();
    let (st, msg) = patch!(&app, "/doc", SPARQL, format!("INSERT DATA {{ {many} }}"));
    assert_eq!(st, 409, "{msg}");
    assert_eq!(stored(&p, "/doc").await, doc);
}

// ---------------------------------------------------------------------------
// HTML data islands
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_patch_that_would_grow_a_card_past_the_reader_bounds_is_409_and_writes_nothing() {
    // Property: a PATCH can never produce a page the readers (WebID, NIP-98
    // elevation, OIDC issuer check, NIP-05) would refuse to parse.
    use solid_pod_rs::html_island::{first_jsonld_island, MAX_HTML_BYTES};
    let json = format!(
        "{{\"@context\": {{\"foaf\": \"{FOAF}\"}}, \"@id\": \"#me\", \"foaf:name\": \"A\"}}"
    );
    let shell = island_page(&json);
    // Pad with a comment so the page sits just under the shared byte cap.
    let pad = "p".repeat(MAX_HTML_BYTES - shell.len() - 64);
    let page = shell.replace("<!-- keep me -->", &format!("<!-- {pad} -->"));
    assert!(page.len() < MAX_HTML_BYTES, "{}", page.len());
    assert!(first_jsonld_island(&page).unwrap().is_some());
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/card", &page, "text/html").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let name = format!("{} <{FOAF}name>", me("/card"));
    // A small edit that stays under the cap still works...
    let (st, msg) = patch!(
        &app,
        "/card",
        SPARQL,
        sparql(&format!("{name} \"A\""), &format!("{name} \"B\""))
    );
    assert_eq!(st, 204, "{msg}");
    let after_small = stored(&p, "/card").await;
    assert!(after_small.len() < MAX_HTML_BYTES);
    // ...one that would take the page over the cap is refused, untouched.
    let big = "y".repeat(256);
    let (st, msg) = patch!(
        &app,
        "/card",
        SPARQL,
        sparql("", &format!("{name} \"{big}\""))
    );
    assert_eq!(st, 409, "{msg}");
    assert_eq!(msg, REFUSAL);
    assert_eq!(
        stored(&p, "/card").await,
        after_small,
        "nothing was written"
    );
}

#[actix_web::test]
async fn an_island_is_edited_and_the_page_is_otherwise_byte_identical() {
    let json = format!(
        "{{\n  \"@context\": {{\"foaf\": \"{FOAF}\"}},\n  \"@id\": \"#me\",\n  \"foaf:name\": \"A\"\n}}"
    );
    let page = island_page(&json);
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/page", &page, "text/html; charset=utf-8").await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let name = format!("{} <{FOAF}name>", me("/page"));
    // The new value would close the script element if written raw.
    let (st, msg) = patch!(
        &app,
        "/page",
        SPARQL,
        sparql(
            &format!("{name} \"A\""),
            &format!("{name} \"</script><script>alert(1)</script>\"")
        )
    );
    assert_eq!(st, 204, "{msg}");
    let now = stored(&p, "/page").await;
    assert_eq!(
        now,
        page.replace(
            "\"A\"",
            "\"\\u003c/script>\\u003cscript>alert(1)\\u003c/script>\""
        )
    );
    assert_eq!(now.matches("<script").count(), 1, "no new element");
    // The stored content type is kept.
    assert_eq!(
        p.storage.get("/page").await.unwrap().1.content_type,
        "text/html; charset=utf-8"
    );
}

// ---------------------------------------------------------------------------
// The WebID profile card: the regression for the withdrawn second attempt
// ---------------------------------------------------------------------------

const PK: &str = "0000000000000000000000000000000000000000000000000000000000000001";

async fn provisioned_card(issuer: Option<&str>, keys: bool) -> (Pod, String, String) {
    use solid_pod_rs::provision::{provision_pod, ProvisionPlan};
    let p = pod("acl:Read, acl:Write").await;
    let mut plan = ProvisionPlan::new(PK, ORIGIN);
    plan.display_name = Some("Alice".into());
    provision_pod(&*p.storage, &plan).await.unwrap();
    if let Some(iss) = issuer {
        let html = solid_pod_rs::webid::generate_webid_html_with_issuer(
            PK,
            Some("Alice"),
            ORIGIN,
            Some(iss),
        );
        put(&p, "/profile/card", &html, "text/html").await;
    }
    let webid = format!("{ORIGIN}/pods/{PK}/profile/card#me");
    #[cfg(feature = "provision-keys")]
    if keys {
        solid_pod_rs_idp::key_provisioning::provision_pod_keys(
            &*p.storage,
            &solid_pod_rs_idp::key_provisioning::KeyProvisioningPlan {
                webid: webid.clone(),
                pod_base: format!("{ORIGIN}/pods/{PK}/"),
                deterministic_entropy: Some([7u8; 32]),
            },
        )
        .await
        .unwrap();
    }
    #[cfg(not(feature = "provision-keys"))]
    let _ = keys;
    let card = stored(&p, "/profile/card").await;
    (p, webid, card)
}

/// The rename, three ways: as SolidOS sends it (DELETE DATA + INSERT DATA), as
/// a `DELETE/INSERT ... WHERE`, and as an N3 Patch.
fn renames(webid: &str) -> Vec<(&'static str, String)> {
    let name = format!("<{webid}> <{FOAF}name>");
    vec![
        (SPARQL, sparql(&format!("{name} \"Alice\""), &format!("{name} \"Alicia\""))),
        (
            SPARQL,
            format!(
                "DELETE {{ <{webid}> <{FOAF}name> ?o }} INSERT {{ <{webid}> <{FOAF}name> \"Alicia\" }} \
                 WHERE {{ <{webid}> <{FOAF}name> ?o }}"
            ),
        ),
        (N3, n3(&format!("{name} \"Alice\""), &format!("{name} \"Alicia\""))),
    ]
}

async fn rename_keeps_readers(keys: bool) {
    use solid_pod_rs::did_nostr_types::webid_declares_pubkey;
    use solid_pod_rs::oidc::check_profile_declares_issuer;
    use solid_pod_rs::webid::{extract_nostr_pubkey, extract_oidc_issuer};

    const ISS: &str = "https://op.example";
    for q in 0..3 {
        let (p, webid, before) = provisioned_card(Some(ISS), keys).await;
        // Non-vacuous: the card really carries the values before the PATCH.
        assert_eq!(
            extract_oidc_issuer(before.as_bytes()).unwrap().as_deref(),
            Some(ISS)
        );
        check_profile_declares_issuer(before.as_bytes(), ISS).unwrap();
        let key = extract_nostr_pubkey(before.as_bytes()).unwrap();
        if keys {
            let key = key
                .as_deref()
                .expect("provision_pod_keys wrote nostr:pubkey");
            assert!(webid_declares_pubkey(before.as_bytes(), key));
        }

        let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
        // The card is served from the pod root here, so its resource URL is
        // `<ORIGIN>/profile/card`; the WebID inside the document is absolute.
        let (ct, body) = renames(&webid).remove(q);
        let (st, msg) = patch!(&app, "/profile/card", ct, body);
        assert_eq!(st, 204, "query {q}: {msg}");

        let after = stored(&p, "/profile/card").await;
        assert_eq!(
            extract_nostr_pubkey(after.as_bytes()).unwrap(),
            key,
            "query {q}"
        );
        assert_eq!(
            extract_oidc_issuer(after.as_bytes()).unwrap().as_deref(),
            Some(ISS)
        );
        check_profile_declares_issuer(after.as_bytes(), ISS).unwrap();
        if let Some(key) = &key {
            assert!(webid_declares_pubkey(after.as_bytes(), key), "query {q}");
        }
        // Only the name changed, anywhere in the page.
        assert_eq!(
            after,
            before.replacen("\"foaf:name\": \"Alice\"", "\"foaf:name\": \"Alicia\"", 1),
            "query {q}"
        );
    }
}

#[actix_web::test]
async fn a_provisioned_profile_card_keeps_its_issuer_after_a_rename() {
    rename_keeps_readers(false).await;
}

#[cfg(feature = "provision-keys")]
#[actix_web::test]
async fn a_key_provisioned_profile_card_keeps_issuer_and_key_after_a_rename() {
    rename_keeps_readers(true).await;
}

#[actix_web::test]
async fn a_card_without_an_issuer_is_edited_too() {
    let (p, webid, before) = provisioned_card(None, false).await;
    let app = test::init_service(build_app(state(&p, Some(ORIGIN)))).await;
    let name = format!("<{webid}> <{FOAF}name>");
    let (st, msg) = patch!(
        &app,
        "/profile/card",
        SPARQL,
        sparql(&format!("{name} \"Alice\""), &format!("{name} \"Al\""))
    );
    assert_eq!(st, 204, "{msg}");
    assert_eq!(
        stored(&p, "/profile/card").await,
        before.replacen("\"foaf:name\": \"Alice\"", "\"foaf:name\": \"Al\"", 1)
    );
}

// ---------------------------------------------------------------------------
// Unchanged neighbours
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_turtle_resource_is_still_patched_as_before() {
    let p = pod("acl:Read, acl:Write").await;
    put(&p, "/t.ttl", "<#a> <http://e/p> \"1\" .\n", "text/turtle").await;
    let app = test::init_service(build_app(state(&p, None))).await;
    let (st, msg) = patch!(
        &app,
        "/t.ttl",
        SPARQL,
        "INSERT DATA { <http://localhost:8080/t.ttl#a> <http://e/p> \"2\" }"
    );
    assert_eq!(st, 204, "{msg}");
    let now = stored(&p, "/t.ttl").await;
    assert!(now.contains("\"1\"") && now.contains("\"2\""), "{now}");
}
