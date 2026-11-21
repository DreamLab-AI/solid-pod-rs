//! SP-LDP-HTML-SANDBOX: stored active documents are sandboxed over LDP.
//!
//! Property: a stored HTML, XHTML, SVG, XML or JavaScript document is never
//! rendered with the pod origin's authority. By default every LDP `GET` and
//! `HEAD` of one (a plain resource, a container's `index.html`, a negotiated
//! representation) carries `Content-Security-Policy: default-src 'none';
//! sandbox` and is NOT forced to download, so it still renders. The operator
//! opt-out (`AppState::serve_active_content`) restores the old headers, never
//! under `/remotestorage/`, and never touches pages the server generates or
//! embeds (Mashlib wrapper, forge UI).

use std::sync::Arc;

use actix_web::http::header::HeaderMap;
use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs_server::{build_app, AppState};

const CSP: &str = "default-src 'none'; sandbox";

const PUBLIC_READ: &str = r#"
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
<#p> a acl:Authorization ; acl:agentClass foaf:Agent ;
    acl:accessTo </> ; acl:default </> ; acl:mode acl:Read .
"#;

async fn state(serve_active_content: bool) -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    let seed: [(&str, &str, &str); 9] = [
        ("/.acl", PUBLIC_READ, "text/turtle"),
        (
            "/site/page.html",
            "<p>hi</p><script>1</script>",
            "text/html",
        ),
        ("/site/upper.html", "<p>x</p>", "Text/HTML; charset=UTF-8"),
        (
            "/site/pic.svg",
            "<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>",
            "image/svg+xml",
        ),
        ("/site/x.xhtml", "<html/>", "application/xhtml+xml"),
        ("/site/app.js", "alert(1)", "text/javascript"),
        ("/site/notes.txt", "hello", "text/plain"),
        ("/site/data.ttl", "<#a> <#b> <#c> .", "text/turtle"),
        ("/app/index.html", "<h1>app</h1>", "text/html"),
    ];
    for (k, b, ct) in seed {
        storage.put(k, Bytes::from(b), ct).await.unwrap();
    }
    let mut st = AppState::new(storage);
    st.serve_active_content = serve_active_content;
    st
}

fn h<'a>(m: &'a HeaderMap, n: &str) -> Option<&'a str> {
    m.get(n).and_then(|v| v.to_str().ok())
}

async fn fetch(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    >,
    method: &str,
    uri: &str,
    accept: Option<&str>,
) -> (u16, HeaderMap) {
    let mut r = test::TestRequest::default()
        .method(method.parse().unwrap())
        .uri(uri);
    if let Some(a) = accept {
        r = r.insert_header(("accept", a));
    }
    let rsp = test::call_service(app, r.to_request()).await;
    (rsp.status().as_u16(), rsp.headers().clone())
}

#[actix_web::test]
async fn default_sandboxes_every_active_type_on_get_and_head_without_forcing_download() {
    let app = test::init_service(build_app(state(false).await)).await;
    for uri in [
        "/site/page.html",
        "/site/upper.html",
        "/site/pic.svg",
        "/site/x.xhtml",
        "/site/app.js",
    ] {
        for method in ["GET", "HEAD"] {
            let (s, hd) = fetch(&app, method, uri, None).await;
            assert_eq!(s, 200, "{method} {uri}");
            assert_eq!(
                h(&hd, "content-security-policy"),
                Some(CSP),
                "{method} {uri}"
            );
            assert_eq!(h(&hd, "x-content-type-options"), Some("nosniff"));
            assert!(
                h(&hd, "content-disposition").is_none(),
                "{method} {uri}: a stored page must stay viewable"
            );
        }
    }
}

#[actix_web::test]
async fn non_active_types_are_unaffected() {
    let app = test::init_service(build_app(state(false).await)).await;
    for uri in ["/site/notes.txt", "/site/data.ttl"] {
        for method in ["GET", "HEAD"] {
            let (s, hd) = fetch(&app, method, uri, None).await;
            assert_eq!(s, 200);
            assert!(
                h(&hd, "content-security-policy").is_none(),
                "{method} {uri}"
            );
            assert!(h(&hd, "content-disposition").is_none());
        }
    }
    // A container listing is generated RDF, not stored bytes.
    let (s, hd) = fetch(&app, "GET", "/site/", None).await;
    assert_eq!(s, 200);
    assert!(h(&hd, "content-security-policy").is_none());
}

#[actix_web::test]
async fn container_index_html_is_sandboxed_by_default_for_html_clients_only() {
    let app = test::init_service(build_app(state(false).await)).await;
    for method in ["GET", "HEAD"] {
        let (s, hd) = fetch(&app, method, "/app/", Some("text/html")).await;
        assert_eq!(s, 200);
        assert!(h(&hd, "content-type").unwrap().starts_with("text/html"));
        assert_eq!(h(&hd, "content-security-policy"), Some(CSP), "{method}");
        assert!(h(&hd, "content-disposition").is_none());
    }
    // A Solid client still gets the listing, which is not stored bytes.
    let (_, hd) = fetch(&app, "GET", "/app/", Some("text/turtle")).await;
    assert!(h(&hd, "content-security-policy").is_none());
}

#[actix_web::test]
async fn the_flag_restores_the_previous_headers() {
    let app = test::init_service(build_app(state(true).await)).await;
    for (uri, accept) in [
        ("/site/page.html", None),
        ("/site/pic.svg", None),
        ("/site/x.xhtml", None),
        ("/app/", Some("text/html")),
    ] {
        for method in ["GET", "HEAD"] {
            let (s, hd) = fetch(&app, method, uri, accept).await;
            assert_eq!(s, 200);
            assert!(
                h(&hd, "content-security-policy").is_none(),
                "{method} {uri}: opt-out restores the old headers"
            );
            assert!(h(&hd, "content-disposition").is_none());
            assert_eq!(h(&hd, "x-content-type-options"), Some("nosniff"));
        }
    }
}

#[actix_web::test]
async fn the_flag_defaults_off() {
    let st = AppState::new(Arc::new(MemoryBackend::new()));
    assert!(!st.serve_active_content);
}

#[actix_web::test]
async fn sandboxing_does_not_replace_the_headers_of_server_generated_pages() {
    // The Mashlib wrapper is generated by the server (not stored bytes) and
    // must keep its own `frame-ancestors` policy, with or without the flag.
    for serve in [false, true] {
        let mut st = state(serve).await;
        st.mashlib.enabled = true;
        let app = test::init_service(build_app(st)).await;
        let (s, hd) = fetch(&app, "GET", "/site/data.ttl", Some("text/html")).await;
        assert_eq!(s, 200);
        assert!(h(&hd, "content-type").unwrap().starts_with("text/html"));
        assert_eq!(
            h(&hd, "content-security-policy"),
            Some("frame-ancestors 'none'"),
            "serve={serve}"
        );
    }
}

#[cfg(feature = "forge")]
#[actix_web::test]
async fn the_embedded_forge_ui_keeps_its_own_headers() {
    // The forge UI is an asset embedded in the binary, not pod storage: its
    // page policy is the forge's, never the stored-document sandbox.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let fs = solid_pod_rs::storage::fs::FsBackend::new(root.clone())
        .await
        .unwrap();
    let mut st = AppState::new(Arc::new(fs));
    st.data_root = Some(root);
    let app = test::init_service(build_app(st)).await;
    let mut saw_page = false;
    for uri in ["/forge", "/forge/"] {
        let (s, hd) = fetch(&app, "GET", uri, Some("text/html")).await;
        let csp = h(&hd, "content-security-policy").unwrap_or("");
        assert_ne!(csp, CSP, "{uri} ({s}) got the stored-document sandbox");
        if h(&hd, "content-type").is_some_and(|c| c.starts_with("text/html")) {
            saw_page = true;
            assert!(csp.contains("script-src"), "{uri}: forge CSP lost: {csp:?}");
        }
    }
    assert!(saw_page, "the forge root served no HTML page");
}

// ---------------------------------------------------------------------------
// Passive allowlist (review item 1): the sandbox is skipped only for a
// Content-Type that is exactly one passive MIME type. Everything else
// (multi-valued, unparseable, missing, unlisted) is sandboxed.
// ---------------------------------------------------------------------------

/// Stored types a browser may render actively although the old deny-list
/// did not name them (or could not see them).
const HOSTILE: [(&str, &str); 9] = [
    ("/h/comma.txt", "text/plain, text/html"),
    ("/h/comma2.png", "image/png,text/html"),
    ("/h/mixed.bin", "multipart/x-mixed-replace; boundary=x"),
    ("/h/none.bin", ""),
    ("/h/junk.bin", "not a mime type"),
    ("/h/pdf.pdf", "application/pdf"),
    ("/h/unlisted.bin", "application/x-unlisted"),
    ("/h/quoted.txt", "text/plain; x=\"a,b\""),
    ("/h/svg.svg", "image/svg+xml"),
];

const PASSIVE: [(&str, &str); 12] = [
    ("/p/a.txt", "text/plain"),
    ("/p/b.ttl", "text/turtle"),
    ("/p/c.jsonld", "application/ld+json"),
    ("/p/d.json", "application/json"),
    ("/p/e.nt", "application/n-triples"),
    ("/p/f.png", "image/png"),
    ("/p/g.jpg", "image/jpeg"),
    ("/p/h.gif", "image/gif"),
    ("/p/i.webp", "image/webp"),
    ("/p/j.mp3", "audio/mpeg"),
    ("/p/k.mp4", "video/mp4"),
    ("/p/l.bin", "application/octet-stream"),
];

async fn typed_state(serve_active_content: bool) -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    storage
        .put("/.acl", Bytes::from(PUBLIC_READ), "text/turtle")
        .await
        .unwrap();
    for (k, ct) in HOSTILE.iter().chain(PASSIVE.iter()) {
        storage.put(k, Bytes::from("x"), ct).await.unwrap();
    }
    storage
        .put("/p/odd.txt", Bytes::from("x"), "TEXT/Plain ; Charset=UTF-8")
        .await
        .unwrap();
    let mut st = AppState::new(storage);
    st.serve_active_content = serve_active_content;
    st
}

#[actix_web::test]
async fn multi_valued_unparseable_missing_and_unlisted_types_are_sandboxed() {
    let app = test::init_service(build_app(typed_state(false).await)).await;
    for (uri, ct) in HOSTILE {
        for method in ["GET", "HEAD"] {
            let (s, hd) = fetch(&app, method, uri, None).await;
            assert_eq!(s, 200, "{method} {uri}");
            assert_eq!(
                h(&hd, "content-security-policy"),
                Some(CSP),
                "{method} {uri} stored as {ct:?} must be sandboxed"
            );
        }
    }
}

#[actix_web::test]
async fn each_passive_type_is_served_without_the_sandbox() {
    let app = test::init_service(build_app(typed_state(false).await)).await;
    for (uri, ct) in PASSIVE.iter().chain(&[("/p/odd.txt", "odd casing")]) {
        for method in ["GET", "HEAD"] {
            let (s, hd) = fetch(&app, method, uri, None).await;
            assert_eq!(s, 200, "{method} {uri}");
            assert!(
                h(&hd, "content-security-policy").is_none(),
                "{method} {uri} ({ct}) is passive and must not be sandboxed"
            );
            assert_eq!(h(&hd, "x-content-type-options"), Some("nosniff"));
        }
    }
}

#[actix_web::test]
async fn the_flag_still_restores_the_old_headers_for_hostile_types() {
    let app = test::init_service(build_app(typed_state(true).await)).await;
    for (uri, _) in HOSTILE {
        let (s, hd) = fetch(&app, "GET", uri, None).await;
        assert_eq!(s, 200, "{uri}");
        assert!(h(&hd, "content-security-policy").is_none(), "{uri}");
    }
}
