//! SP-PAR-290 security properties, in every layout.
//!
//! P1. Writing either ACL form of a container needs `acl:Control` on the
//!     container under the active layout, by every method (PUT, PATCH, POST
//!     with Slug, COPY, DELETE). A caller holding Control only through a
//!     parent's `acl:default`, and excluded by the container's own ACL, cannot
//!     plant a sidecar that would override it.
//! P2. Nothing can be created beneath an ACL or meta document, by HTTP or by
//!     the MCP tools; DELETE beneath stays possible so an operator can repair.
//! P3. A directory at an ACL key reads as absent; any other read failure still
//!     denies.

mod common;
use common::acl_harness::*;

use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs::wac::AclLayout;
use solid_pod_rs_server::AppState;
use std::sync::Arc;

const MODES: [AclLayout; 3] = [AclLayout::Sidecar, AclLayout::Inner, AclLayout::Both];

fn st(s: &Arc<solid_pod_rs::storage::memory::MemoryBackend>, l: AclLayout) -> AppState {
    let mut a = AppState::new(s.clone());
    a.acl_layout = l;
    a
}

fn grants_b(b: &Agent) -> String {
    turtle(&format!(
        "<#b> a acl:Authorization ; acl:agent <{}> ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
        b.id
    ))
}

/// P1: B holds Control on `/` through `acl:default` and is excluded by the
/// inner ACL of `/docs/`. Under `inner` and `both` every way of writing the
/// sidecar `/docs.acl` is refused; the default layout keeps what it always did.
#[actix_web::test]
async fn sidecar_form_writes_need_control_on_the_container() {
    let (o, b) = (agent(1), agent(2));
    for layout in [AclLayout::Inner, AclLayout::Both] {
        let s = storage(Disk::InnerOnly, &o, &b).await;
        let grant = grants_b(&b);
        let n3 = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix acl: <http://www.w3.org/ns/auth/acl#>.\n_:p a solid:InsertDeletePatch; solid:inserts { <#x> acl:agent <did:nostr:ff> }.";
        // PUT
        let (put, _) = call(st(&s, layout), Some(&b), "PUT", "/docs.acl", &grant).await;
        assert_eq!(put, 403, "{layout:?} PUT");
        // PATCH on an absent sidecar
        let mut a = st(&s, layout);
        a.conneg_enabled = true;
        let (patch, _) = call_ct(a, Some(&b), "PATCH", "/docs.acl", n3, "text/n3").await;
        assert_eq!(patch, 403, "{layout:?} PATCH");
        // POST with Slug
        let (post, _) = call_slug(st(&s, layout), Some(&b), "/docs/", "sub.acl", &grant).await;
        assert_eq!(post, 403, "{layout:?} POST Slug");
        // COPY onto it
        let (copy, _) = call_copy(st(&s, layout), Some(&b), "/docs/a.txt", "/docs.acl").await;
        assert!(copy == 403 || copy == 400, "{layout:?} COPY {copy}");
        // DELETE of one the owner wrote
        let owner_only = turtle(&format!(
            "<#o> a acl:Authorization ; acl:agent <{}> ; acl:accessTo </docs/> ; acl:default </docs/> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
            o.id
        ));
        s.put("/docs.acl", bytes::Bytes::from(owner_only), "text/turtle")
            .await
            .unwrap();
        let (del, _) = call(st(&s, layout), Some(&b), "DELETE", "/docs.acl", "").await;
        assert_eq!(del, 403, "{layout:?} DELETE");
        // Nothing B wrote governs /docs/, now or after switching to `both`.
        s.delete("/docs.acl").await.unwrap();
        assert!(!s.exists("/docs.acl").await.unwrap(), "{layout:?}");
        let (read, _) = call(st(&s, AclLayout::Both), Some(&b), "GET", "/docs/a.txt", "").await;
        assert_eq!(
            read, 403,
            "{layout:?}: B still excluded after switching to both"
        );
    }
    // Default layout: B holds Control on `/docs` through the root and the
    // sidecar IS the container ACL there, so the write is allowed as before.
    let s = storage(Disk::None, &o, &b).await;
    let (put, _) = call(
        st(&s, AclLayout::Sidecar),
        Some(&b),
        "PUT",
        "/docs.acl",
        &grants_b(&b),
    )
    .await;
    assert!(put == 201 || put == 204, "default layout PUT: {put}");
}

/// P1: the inner form needs Control on the container in every layout.
#[actix_web::test]
async fn inner_form_writes_need_control_on_the_container() {
    let (o, b) = (agent(1), agent(2));
    let w = agent(3);
    for layout in MODES {
        // W holds Write only, on the whole tree.
        let s = storage(Disk::None, &o, &b).await;
        let root = turtle(&format!(
            "<#w> a acl:Authorization ; acl:agent <{}> ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write .\n\
             <#o> a acl:Authorization ; acl:agent <{}> ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
            w.id, o.id
        ));
        s.put("/.acl", bytes::Bytes::from(root), "text/turtle")
            .await
            .unwrap();
        let grant = grants_b(&w);
        let (put, _) = call(st(&s, layout), Some(&w), "PUT", "/docs/.acl", &grant).await;
        assert_eq!(put, 403, "{layout:?} PUT inner by a Write-only agent");
        let (post, _) = call_slug(st(&s, layout), Some(&w), "/docs/", ".acl", &grant).await;
        assert_eq!(post, 403, "{layout:?} POST Slug .acl by a Write-only agent");
        assert!(!s.exists("/docs/.acl").await.unwrap(), "{layout:?}");
    }
}

/// P2 over HTTP, in every layout, by a caller who does hold Control.
#[actix_web::test]
async fn nothing_is_created_beneath_an_acl_or_meta_document() {
    let (o, b) = (agent(1), agent(2));
    for layout in MODES {
        let s = storage(Disk::None, &o, &b).await;
        for p in [
            "/docs.acl/x",
            "/docs/.acl/x",
            "/docs/a.txt.acl/x",
            "/docs.meta/x",
            "/docs/.meta/x",
            "/docs.ACL/x",
        ] {
            let (put, _) = call(st(&s, layout), Some(&o), "PUT", p, "<#a> <#b> <#c> .").await;
            // The upper-case spelling is refused earlier still, by the
            // dotfile policy's case-folded sidecar rule.
            assert!(
                put == 400 || (p.contains("ACL") && put == 403),
                "{layout:?} PUT {p}: {put}"
            );
            assert!(!s.exists(p).await.unwrap(), "{layout:?} {p}");
        }
        let (post, _) = call_slug(
            st(&s, layout),
            Some(&o),
            "/docs.acl/",
            "x",
            "<#a> <#b> <#c> .",
        )
        .await;
        assert!(
            post == 400 || post == 405,
            "{layout:?} POST beneath: {post}"
        );
    }
}

/// P2: DELETE beneath stays possible, so junk planted before the upgrade can
/// be removed over HTTP.
#[actix_web::test]
async fn existing_junk_beneath_an_acl_key_can_still_be_deleted() {
    let (o, b) = (agent(1), agent(2));
    let s = storage(Disk::None, &o, &b).await;
    // Plant it the way an earlier release allowed: straight into the store.
    let fs_dir = tempfile::tempdir().unwrap();
    let fs = Arc::new(FsBackend::new(fs_dir.path()).await.unwrap());
    let root = s.get("/.acl").await.unwrap().0;
    fs.put("/.acl", root, "text/turtle").await.unwrap();
    std::fs::create_dir_all(fs_dir.path().join("docs.acl")).unwrap();
    std::fs::write(fs_dir.path().join("docs.acl/x"), b"junk").unwrap();
    let mut a = AppState::new(fs.clone());
    a.acl_layout = AclLayout::Both;
    let (del, _) = call(a, Some(&o), "DELETE", "/docs.acl/x", "").await;
    assert!(del == 204 || del == 200, "DELETE junk: {del}");
    assert!(!fs_dir.path().join("docs.acl/x").exists());
}

/// P3: a directory at an ACL key reads as absent (the pre-existing lock-out
/// of `/docs.acl/` is closed) in every layout, on the filesystem backend, for
/// the sidecar key and for the inner key; an unreadable key still denies.
#[actix_web::test]
async fn a_directory_at_an_acl_key_is_absent_not_an_error() {
    let (o, b) = (agent(1), agent(2));
    for layout in MODES {
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(FsBackend::new(dir.path()).await.unwrap());
        let mem = storage(Disk::None, &o, &b).await;
        for k in ["/.acl", "/docs/a.txt"] {
            let (body, m) = mem.get(k).await.unwrap();
            fs.put(k, body, &m.content_type).await.unwrap();
        }
        // Directories at both ACL keys of `/docs/`, planted on disk.
        std::fs::create_dir_all(dir.path().join("docs.acl")).unwrap();
        std::fs::write(dir.path().join("docs.acl/x"), b"junk").unwrap();
        std::fs::create_dir_all(dir.path().join("docs/.acl")).unwrap();
        std::fs::write(dir.path().join("docs/.acl/x"), b"junk").unwrap();
        let mut a = AppState::new(fs.clone());
        a.acl_layout = layout;
        let (read, _) = call(a, Some(&o), "GET", "/docs/a.txt", "").await;
        assert_eq!(
            read, 200,
            "{layout:?}: the owner is not locked out by a directory at an ACL key"
        );
    }
}

/// P3: a read failure that is not a directory still denies (fails closed).
#[cfg(unix)]
#[actix_web::test]
async fn an_unreadable_acl_still_denies() {
    use std::os::unix::fs::PermissionsExt;
    let (o, b) = (agent(1), agent(2));
    let dir = tempfile::tempdir().unwrap();
    let fs = Arc::new(FsBackend::new(dir.path()).await.unwrap());
    let mem = storage(Disk::SidecarOnly, &o, &b).await;
    for k in ["/.acl", "/docs.acl", "/docs/a.txt"] {
        let (body, m) = mem.get(k).await.unwrap();
        fs.put(k, body, &m.content_type).await.unwrap();
    }
    let acl = dir.path().join("docs.acl");
    std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&acl).is_ok() {
        return; // running as root: permissions do not apply
    }
    let mut a = AppState::new(fs.clone());
    a.acl_layout = AclLayout::Both;
    let (read, _) = call(a, Some(&o), "GET", "/docs/a.txt", "").await;
    std::fs::set_permissions(&acl, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        read == 403 || read == 503,
        "an unreadable ACL must deny, got {read}"
    );
}

/// P2 through the MCP tools: they reach `Storage::put`, which refuses.
#[cfg(feature = "dev-bearer")]
mod mcp {
    use super::*;
    use actix_web::test;
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    use serde_json::{json, Value};
    use sha2::Sha256;

    const SECRET: &str = "01234567890123456789012345678901";
    const WRITER: &str = "https://writer.example/profile/card#me";

    fn bearer() -> String {
        std::env::set_var("TOKEN_SECRET", SECRET);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            json!({"webId": WRITER, "iat": now - 10, "exp": now + 3600, "aud": solid_pod_rs_server::DEV_BEARER_AUDIENCE})
                .to_string(),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(data.as_bytes());
        let sig =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("Bearer {data}.{sig}")
    }

    #[actix_web::test]
    async fn mcp_writes_beneath_an_acl_key_are_refused() {
        for layout in MODES {
            let s = Arc::new(solid_pod_rs::storage::memory::MemoryBackend::new());
            let acl = format!("@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n<#w> a acl:Authorization ; acl:agent <{WRITER}> ; acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n");
            s.put("/.acl", bytes::Bytes::from(acl), "text/turtle")
                .await
                .unwrap();
            let mut state = AppState::new(s.clone());
            state.mcp_enabled = true;
            state.acl_layout = layout;
            for (tool, args) in [
                (
                    "write_resource",
                    json!({"path": "/docs.acl/x", "content": "x"}),
                ),
                (
                    "write_resource",
                    json!({"path": "/docs/.acl/x", "content": "x"}),
                ),
                (
                    "write_resource",
                    json!({"path": "/docs.meta/x", "content": "x"}),
                ),
                (
                    "create_resource",
                    json!({"container": "/docs.acl/", "slug": "x", "content": "x"}),
                ),
            ] {
                let app = test::init_service(solid_pod_rs_server::build_app(state.clone())).await;
                let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}})).unwrap();
                let req = test::TestRequest::post()
                    .uri("/mcp")
                    .insert_header(("Authorization", bearer()))
                    .insert_header(("Content-Type", "application/json"))
                    .set_payload(body)
                    .to_request();
                let v: Value = test::read_body_json(test::call_service(&app, req).await).await;
                let r = v.get("result").unwrap_or(&v);
                assert!(
                    r["isError"].as_bool().unwrap_or(false),
                    "{layout:?} {tool}: {v}"
                );
            }
            for k in ["/docs.acl/x", "/docs/.acl/x", "/docs.meta/x", "/docs.acl/x"] {
                assert!(!s.exists(k).await.unwrap(), "{layout:?} {k}");
            }
        }
    }
}
