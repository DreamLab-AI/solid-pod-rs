//! SP-PAR-290: a container's ACL may be stored as `<container>.acl` (what this
//! server writes and advertises) or `<container>/.acl` (the reference
//! JavaScript server's layout). Properties:
//!
//! * exactly one present: it governs; neither: ascend; both: deny everyone;
//! * a read error on either key is `Unavailable`, never an ascent;
//! * the key actually read anchors relative IRIs (`./` is `/docs/` in
//!   `/docs/.acl`, `/` in `/docs.acl`);
//! * creating the second form while the first exists is refused (409);
//! * root, document-level ACLs and the `Link: rel="acl"` header are unchanged,
//!   and both forms need Control to read or write.

use std::sync::Arc;

use actix_web::{http::Method, test};
use async_trait::async_trait;
use bytes::Bytes;
use solid_pod_rs::storage::{memory::MemoryBackend, ResourceMeta, Storage, StorageEvent};
use solid_pod_rs::PodError;
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n";
const OWNER: &str = "did:nostr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn public_read(target: &str, default: bool) -> String {
    let d = if default {
        format!("acl:default <{target}> ;")
    } else {
        String::new()
    };
    format!("{ACL}<#p> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo <{target}> ; {d} acl:mode acl:Read .\n")
}
fn owner_only(target: &str) -> String {
    format!("{ACL}<#o> a acl:Authorization ; acl:agent <{OWNER}> ; acl:accessTo <{target}> ; acl:default <{target}> ; acl:mode acl:Read, acl:Write, acl:Control .\n")
}

async fn put(s: &dyn Storage, p: &str, body: &str) {
    let ct = if p.ends_with(".acl") {
        "text/turtle"
    } else {
        "text/plain"
    };
    s.put(p, Bytes::from(body.to_owned()), ct).await.unwrap();
}

async fn base() -> Arc<MemoryBackend> {
    let s = Arc::new(MemoryBackend::new());
    put(&*s, "/.acl", &public_read("/", true)).await;
    for p in ["/docs/a.txt", "/docs/sub/x", "/other/y"] {
        put(&*s, p, "data").await;
    }
    s
}

async fn get_status(s: Arc<dyn Storage>, path: &str) -> u16 {
    let app = test::init_service(build_app(AppState::new(s))).await;
    test::call_service(&app, test::TestRequest::get().uri(path).to_request())
        .await
        .status()
        .as_u16()
}

#[actix_web::test]
async fn a_private_in_container_acl_governs_instead_of_being_ignored() {
    let s = base().await;
    assert_eq!(
        get_status(s.clone(), "/docs/a.txt").await,
        200,
        "control: root is public"
    );
    put(&*s, "/docs/.acl", &owner_only("/docs/")).await;
    assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 401);
    assert_eq!(get_status(s.clone(), "/docs/sub/x").await, 401);
    assert_eq!(
        get_status(s.clone(), "/other/y").await,
        200,
        "siblings are untouched"
    );
}

#[actix_web::test]
async fn the_sidecar_form_still_governs() {
    let s = base().await;
    put(&*s, "/docs.acl", &owner_only("/docs/")).await;
    assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 401);
}

#[actix_web::test]
async fn both_forms_present_deny_everyone_whichever_says_public() {
    let s = base().await;
    // Identical twins are governed by the sidecar (see the H2 tests below);
    // differing ones deny everyone, whichever says public.
    put(&*s, "/docs.acl", &public_read("/docs/", true)).await;
    put(
        &*s,
        "/docs/.acl",
        &format!("{}# edited\n", public_read("/docs/", true)),
    )
    .await;
    assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 403);
    put(&*s, "/docs.acl", &owner_only("/docs/")).await;
    assert_ne!(get_status(s.clone(), "/docs/a.txt").await, 200);
    // The root has one key, so it can never be "both present".
    assert_eq!(get_status(s.clone(), "/other/y").await, 200);
}

#[actix_web::test]
async fn an_inherited_default_in_the_in_container_form_governs_descendants() {
    let s = base().await;
    // `./` in /docs/.acl means /docs/: a public default there, and a private
    // root default; /docs/sub/x must follow the nearer container ACL.
    put(&*s, "/.acl", &owner_only("/")).await;
    // Path form: Turtle needs an origin to resolve `./`; the relative form is
    // covered by the JSON-LD test below.
    put(&*s, "/docs/.acl", &public_read("/docs/", true)).await;
    assert_eq!(get_status(s.clone(), "/docs/sub/x").await, 200);
    assert_eq!(get_status(s.clone(), "/other/y").await, 401);
}

#[actix_web::test]
async fn relative_iris_resolve_against_the_key_actually_read() {
    // JSON-LD resolves `./` without an origin: `/docs/.acl` -> /docs/,
    // `/docs.acl` -> /.
    let jsonld = r##"{"@context":{"acl":"http://www.w3.org/ns/auth/acl#","foaf":"http://xmlns.com/foaf/0.1/"},
      "@graph":[{"@id":"#p","@type":"acl:Authorization","acl:agentClass":{"@id":"foaf:Agent"},
      "acl:default":{"@id":"./"},"acl:accessTo":{"@id":"./"},"acl:mode":{"@id":"acl:Read"}}]}"##;
    // In /docs/.acl the target is /docs/: /other/y is not covered (root is private).
    let s = base().await;
    put(&*s, "/.acl", &owner_only("/")).await;
    s.put("/docs/.acl", Bytes::from(jsonld), "application/ld+json")
        .await
        .unwrap();
    assert_eq!(get_status(s.clone(), "/docs/sub/x").await, 200);
    assert_eq!(get_status(s.clone(), "/other/y").await, 401);
    // The same text in /docs.acl means `/`: it covers the whole pod default,
    // but the nearer-container rule says /docs/ is governed by this document,
    // whose `./` is the root, so descendants of /docs/ are covered via default `/`.
    let s = base().await;
    put(&*s, "/.acl", &owner_only("/")).await;
    s.put("/docs.acl", Bytes::from(jsonld), "application/ld+json")
        .await
        .unwrap();
    assert_eq!(get_status(s.clone(), "/docs/sub/x").await, 200);
    assert_eq!(get_status(s.clone(), "/other/y").await, 401);
}

/// Storage that fails reads of one key with an I/O error.
struct FailingKey {
    inner: Arc<MemoryBackend>,
    key: &'static str,
}
#[async_trait]
impl Storage for FailingKey {
    async fn get(&self, p: &str) -> Result<(Bytes, ResourceMeta), PodError> {
        if p == self.key {
            return Err(PodError::Io(std::io::Error::other("disk on fire")));
        }
        self.inner.get(p).await
    }
    async fn put(&self, p: &str, b: Bytes, c: &str) -> Result<ResourceMeta, PodError> {
        self.inner.put(p, b, c).await
    }
    async fn delete(&self, p: &str) -> Result<(), PodError> {
        self.inner.delete(p).await
    }
    async fn list(&self, c: &str) -> Result<Vec<String>, PodError> {
        self.inner.list(c).await
    }
    async fn head(&self, p: &str) -> Result<ResourceMeta, PodError> {
        self.inner.head(p).await
    }
    async fn exists(&self, p: &str) -> Result<bool, PodError> {
        self.inner.exists(p).await
    }
    async fn watch(&self, p: &str) -> Result<tokio::sync::mpsc::Receiver<StorageEvent>, PodError> {
        self.inner.watch(p).await
    }
}

#[actix_web::test]
async fn a_read_error_on_either_form_does_not_ascend_to_a_public_parent() {
    for key in ["/docs.acl", "/docs/.acl"] {
        let inner = base().await; // public root
        let s: Arc<dyn Storage> = Arc::new(FailingKey { inner, key });
        let status = get_status(s, "/docs/a.txt").await;
        assert_ne!(
            status, 200,
            "{key}: a failed ACL read ascended to the public root"
        );
        assert!(
            status >= 500 || status == 401 || status == 403,
            "{key}: {status}"
        );
    }
}

#[actix_web::test]
async fn the_document_level_acl_and_root_are_unaffected() {
    let s = base().await;
    put(&*s, "/docs/a.txt.acl", &owner_only("/docs/a.txt")).await;
    assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 401);
    assert_eq!(get_status(s.clone(), "/docs/sub/x").await, 200);
    // Root ACL alone: governs, no false "both present".
    assert_eq!(get_status(s.clone(), "/other/y").await, 200);
    // Link rel=acl is unchanged: the sidecar form.
    let app = test::init_service(build_app(AppState::new(s))).await;
    let rsp = test::call_service(&app, test::TestRequest::get().uri("/docs/").to_request()).await;
    let link: Vec<_> = rsp
        .headers()
        .get_all("link")
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        link.iter().any(|l| l.contains("</docs.acl>; rel=\"acl\"")),
        "{link:?}"
    );
}

async fn send(
    s: Arc<dyn Storage>,
    method: &str,
    path: &str,
    ct: &str,
    body: &str,
    hdr: &[(&str, &str)],
) -> u16 {
    let mut st = AppState::new(s);
    st.public_base_url = None;
    let app = test::init_service(build_app(st)).await;
    let mut req = test::TestRequest::default()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(path)
        .insert_header(("content-type", ct))
        .set_payload(body.to_owned());
    for (k, v) in hdr {
        req = req.insert_header((*k, *v));
    }
    test::call_service(&app, req.to_request())
        .await
        .status()
        .as_u16()
}

/// An open pod so that Control is not the obstacle: only the twin rule is.
async fn open_pod() -> Arc<MemoryBackend> {
    let s = Arc::new(MemoryBackend::new());
    put(&*s, "/.acl", &format!("{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n")).await;
    put(&*s, "/docs/a.txt", "x").await;
    s
}

#[actix_web::test]
async fn creating_the_second_form_is_refused_in_both_directions() {
    let acl = format!("{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    for (first, second) in [("/docs.acl", "/docs/.acl"), ("/docs/.acl", "/docs.acl")] {
        // PUT
        let s = open_pod().await;
        put(&*s, first, &acl).await;
        assert_eq!(
            send(s.clone(), "PUT", second, "text/turtle", &acl, &[]).await,
            409,
            "PUT {second}"
        );
        assert!(!s.exists(second).await.unwrap());
        // PATCH (create-by-patch)
        let n3 = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n_:p a solid:InsertDeletePatch; solid:inserts { <#a> a acl:Authorization; acl:agentClass <http://xmlns.com/foaf/0.1/Agent>; acl:accessTo </docs/>; acl:mode acl:Read, acl:Write, acl:Control }.";
        assert_eq!(
            send(s.clone(), "PATCH", second, "text/n3", n3, &[]).await,
            409,
            "PATCH {second}"
        );
        assert!(!s.exists(second).await.unwrap());
        // COPY destination
        put(&*s, "/src.ttl", &acl).await;
        assert_eq!(
            send(s.clone(), "COPY", second, "", "", &[("source", "/src.ttl")]).await,
            409,
            "COPY {second}"
        );
        assert!(!s.exists(second).await.unwrap());
        // POST with a Slug naming the second form
        let (container, slug) = if second.ends_with("/.acl") {
            ("/docs/", ".acl")
        } else {
            ("/", "docs.acl")
        };
        // (`POST /` is not routed by this server: no root-container POST case.)
        if container != "/" {
            assert_eq!(
                send(
                    s.clone(),
                    "POST",
                    container,
                    "text/turtle",
                    &acl,
                    &[("slug", slug)]
                )
                .await,
                409,
                "POST {slug}"
            );
            assert!(!s.exists(second).await.unwrap());
        }
    }
}

#[actix_web::test]
async fn rewriting_the_form_that_exists_is_still_allowed() {
    let acl = format!("{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    let s = open_pod().await;
    put(&*s, "/docs/.acl", &acl).await;
    let st = send(s.clone(), "PUT", "/docs/.acl", "text/turtle", &acl, &[]).await;
    assert!((200..300).contains(&st), "{st}");
    // And the root, whose two forms coincide, is never a conflict.
    let root = format!("{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    let st = send(s, "PUT", "/.acl", "text/turtle", &root, &[]).await;
    assert!((200..300).contains(&st), "{st}");
}

#[actix_web::test]
async fn both_forms_need_control_to_write() {
    let s = base().await; // public READ only at root
    let acl = owner_only("/docs/");
    for p in ["/docs.acl", "/docs/.acl"] {
        assert_eq!(
            send(s.clone(), "PUT", p, "text/turtle", &acl, &[]).await,
            401,
            "{p}"
        );
        assert!(!s.exists(p).await.unwrap());
    }
}

// ---------------------------------------------------------------------------
// Review round 2, H1: an ACL or meta document has no children, and a key that
// is a directory is absent for that form (never a read error).
// ---------------------------------------------------------------------------

async fn fs_pod() -> (Arc<dyn Storage>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let fs = solid_pod_rs::storage::fs::FsBackend::new(tmp.path().to_path_buf())
        .await
        .unwrap();
    let s: Arc<dyn Storage> = Arc::new(fs);
    put(&*s, "/.acl", &public_read("/", true)).await;
    put(&*s, "/docs/a.txt", "data").await;
    (s, tmp)
}

#[actix_web::test]
async fn nothing_may_be_addressed_beneath_an_acl_or_meta_document() {
    let s = open_pod().await;
    let acl = format!("{ACL}<#a> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    for p in [
        "/docs/.acl/x",
        "/docs/.acl/",
        "/docs.acl/x",
        "/docs/a.txt.acl/x",
        "/docs/a.meta/x",
        "/docs/.meta/x",
        "/docs/%2eacl/x",
        "/docs/.acl/deep/er",
    ] {
        for m in ["PUT", "POST", "PATCH", "DELETE", "GET", "HEAD"] {
            let st = send(s.clone(), m, p, "text/plain", "x", &[("slug", "y")]).await;
            assert_eq!(st, 403, "{m} {p}");
        }
        // COPY: the path is the destination, and a Source beneath a document.
        let st = send(s.clone(), "COPY", p, "", "", &[("source", "/docs/a.txt")]).await;
        assert_eq!(st, 403, "COPY destination {p}");
        let st = send(s.clone(), "COPY", "/docs/ok.txt", "", "", &[("source", p)]).await;
        assert_eq!(st, 403, "COPY source {p}");
        assert!(!s.exists("/docs/ok.txt").await.unwrap(), "{p}");
        assert!(
            !s.exists(&p.replace("%2e", ".")).await.unwrap(),
            "{p} created"
        );
    }
    // Control: the documents themselves are still addressable.
    for p in ["/docs/.acl", "/docs.acl", "/docs/a.txt.acl", "/docs/a.meta"] {
        let st = send(s.clone(), "PUT", p, "text/turtle", &acl, &[]).await;
        assert_ne!(
            st, 403,
            "PUT {p} must not be refused by the sidecar-parent rule"
        );
    }
}

#[actix_web::test]
async fn a_write_only_agent_cannot_make_a_directory_where_an_acl_key_is_read() {
    let (s, tmp) = fs_pod().await;
    // Everyone may write under /docs/ (Write, no Control).
    put(
        &*s,
        "/docs.acl",
        &format!("{ACL}<#w> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write .\n"),
    )
    .await;
    let st = send(s.clone(), "PUT", "/docs/.acl/x", "text/plain", "x", &[]).await;
    assert_eq!(st, 403);
    assert!(
        !tmp.path().join("docs/.acl").exists(),
        "no directory was created"
    );
    assert_eq!(
        get_status(s.clone(), "/docs/a.txt").await,
        200,
        "the container is still readable"
    );
}

#[actix_web::test]
async fn a_directory_in_place_of_an_acl_key_is_absent_not_unavailable() {
    for planted in [
        vec!["docs/.acl"],
        vec!["docs.acl"],
        vec!["docs/.acl", "docs.acl"],
    ] {
        let (s, tmp) = fs_pod().await;
        for d in &planted {
            std::fs::create_dir_all(tmp.path().join(d).join("x")).unwrap();
        }
        // Exactly as if the keys were absent: the public root governs.
        assert_eq!(
            get_status(s.clone(), "/docs/a.txt").await,
            200,
            "{planted:?}"
        );
        // And an ACL written at the other form still governs normally.
        if planted == vec!["docs/.acl"] {
            put(&*s, "/docs.acl", &owner_only("/docs/")).await;
            assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 401);
        }
    }
}

#[actix_web::test]
async fn a_key_that_is_a_prefix_of_other_keys_is_absent_in_memory_storage() {
    let s = base().await;
    // Planted directly in storage, below the guard.
    put(&*s, "/docs/.acl/x", "junk").await;
    put(&*s, "/docs.acl/x", "junk").await;
    assert_eq!(get_status(s.clone(), "/docs/a.txt").await, 200);
}

// ---------------------------------------------------------------------------
// Review round 2, H2: both forms present.
// ---------------------------------------------------------------------------

use solid_pod_rs::auth::nip98;

fn key(b: u8) -> (String, String) {
    let k = k256::schnorr::SigningKey::from_slice(&[b; 32]).unwrap();
    (
        hex::encode(k.to_bytes()),
        format!("did:nostr:{}", hex::encode(k.verifying_key().to_bytes())),
    )
}

/// Anonymous (`None`) or signed-in GET status on `/docs/a.txt`.
async fn status_as(s: Arc<dyn Storage>, who: Option<&str>) -> u16 {
    static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let app = test::init_service(build_app(AppState::new(s))).await;
    let mut req = test::TestRequest::get()
        .uri("/docs/a.txt")
        .insert_header(("host", "pod.example"));
    if let Some(secret) = who {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 30;
        let token =
            nip98::mint_with_payload("http://pod.example/docs/a.txt", "GET", None, secret, now)
                .unwrap();
        req = req.insert_header(("authorization", nip98::authorization_header(&token)));
    }
    test::call_service(&app, req.to_request())
        .await
        .status()
        .as_u16()
}

#[actix_web::test]
async fn identical_twins_govern_exactly_as_the_sidecar_alone_did() {
    // A pod provisioned by v0.5.0-alpha.10..22 has the same bytes at
    // `<c>.acl` and `<c>/.acl`; those releases read only the sidecar. Upgrading
    // must not change anyone's access.
    let (owner_secret, owner) = key(0x61);
    let (other_secret, _other) = key(0x62);
    let acl = format!("{ACL}<#o> a acl:Authorization ; acl:agent <{owner}> ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    let who = [
        None,
        Some(owner_secret.as_str()),
        Some(other_secret.as_str()),
    ];

    let alone = base().await;
    put(&*alone, "/docs.acl", &acl).await;
    let mut expected = Vec::new();
    for w in who {
        expected.push(status_as(alone.clone(), w).await);
    }
    assert_eq!(expected, vec![401, 200, 403], "sanity: the sidecar alone");

    let twins = base().await;
    put(&*twins, "/docs.acl", &acl).await;
    put(&*twins, "/docs/.acl", &acl).await;
    let mut got = Vec::new();
    for w in who {
        got.push(status_as(twins.clone(), w).await);
    }
    assert_eq!(
        got, expected,
        "identical twins must behave as the sidecar alone"
    );
}

#[actix_web::test]
async fn identical_twins_are_governed_by_the_sidecar_key_for_relative_iris() {
    // The sidecar key anchors `./`: in `/docs.acl` it is `/`, so the twin pair
    // governs as the sidecar alone does (root-wide), not as `/docs/.acl` would.
    let jsonld = r##"{"@context":{"acl":"http://www.w3.org/ns/auth/acl#","foaf":"http://xmlns.com/foaf/0.1/"},
      "@graph":[{"@id":"#p","@type":"acl:Authorization","acl:agentClass":{"@id":"foaf:Agent"},
      "acl:default":{"@id":"./"},"acl:accessTo":{"@id":"./"},"acl:mode":{"@id":"acl:Read"}}]}"##;
    let make = |both: bool| async move {
        let s = base().await;
        put(&*s, "/.acl", &owner_only("/")).await;
        s.put("/docs.acl", Bytes::from(jsonld), "application/ld+json")
            .await
            .unwrap();
        if both {
            s.put("/docs/.acl", Bytes::from(jsonld), "application/ld+json")
                .await
                .unwrap();
        }
        s
    };
    let alone = make(false).await;
    let twins = make(true).await;
    for p in ["/docs/sub/x", "/docs/a.txt", "/other/y"] {
        assert_eq!(
            get_status(twins.clone(), p).await,
            get_status(alone.clone(), p).await,
            "{p}"
        );
    }
}

#[actix_web::test]
async fn differing_twins_deny_everyone() {
    let (owner_secret, owner) = key(0x61);
    let acl = format!("{ACL}<#o> a acl:Authorization ; acl:agent <{owner}> ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
    let s = base().await;
    put(&*s, "/docs.acl", &acl).await;
    // One byte different (a trailing comment).
    put(&*s, "/docs/.acl", &format!("{acl}# edited\n")).await;
    for w in [None, Some(owner_secret.as_str())] {
        let st = status_as(s.clone(), w).await;
        assert_ne!(st, 200, "{w:?}");
        assert!(st == 401 || st == 403, "{st}");
    }
}
