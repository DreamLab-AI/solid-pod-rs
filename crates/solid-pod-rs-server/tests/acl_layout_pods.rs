//! SP-PAR-290: pod creation follows the container-ACL layout. In `inner` mode
//! a new pod's ACLs are written inside their containers; if they were written
//! as siblings the resolver would ignore them and `private/` would inherit the
//! server root, which may be public (the row-287 regression). The admin
//! endpoint writes what it always wrote in `sidecar` and `both` mode and the
//! inner file only in `inner` mode.

use std::sync::Arc;

use actix_web::test;
use bytes::Bytes;
use solid_pod_rs::storage::fs::FsBackend;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs::storage::Storage;
use solid_pod_rs::wac::AclLayout;
use solid_pod_rs_server::{build_app, AppState};

const MODES: [AclLayout; 3] = [AclLayout::Sidecar, AclLayout::Inner, AclLayout::Both];

const PUBLIC_ROOT: &str = "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
     @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
     <#p> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
       acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write .\n";

#[actix_web::test]
async fn a_pod_created_through_pods_is_private_in_every_layout() {
    for layout in MODES {
        let s = Arc::new(MemoryBackend::new());
        s.put("/.acl", Bytes::from(PUBLIC_ROOT), "text/turtle")
            .await
            .unwrap();
        let mut st = AppState::new(s.clone());
        st.nodeinfo.open_registrations = true;
        st.acl_layout = layout;
        let app = test::init_service(build_app(st)).await;
        let rsp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/.pods")
                .set_json(serde_json::json!({"name": "alice"}))
                .to_request(),
        )
        .await;
        assert!(rsp.status().is_success(), "{layout:?}: {}", rsp.status());
        let inner = layout == AclLayout::Inner;
        assert_eq!(s.exists("/alice/.acl").await.unwrap(), inner, "{layout:?}");
        assert_eq!(s.exists("/alice.acl").await.unwrap(), !inner, "{layout:?}");
        assert!(
            !s.exists("/alice/private/.acl").await.unwrap(),
            "{layout:?}: private/ inherits the pod root"
        );
        // The pod's own ACL governs, not the public root.
        s.put("/alice/private/x", Bytes::from("secret"), "text/plain")
            .await
            .unwrap();
        for uri in ["/alice/private/x", "/alice/profile/card"] {
            let r = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            let want_private = uri.contains("private");
            if want_private {
                assert!(
                    r.status().as_u16() == 401 || r.status().as_u16() == 403,
                    "{layout:?} anonymous read of {uri}: {}",
                    r.status()
                );
            }
        }
        // And the public inbox/profile rules are in force: an anonymous write
        // to the private container is refused although the root allows it.
        let w = test::call_service(
            &app,
            test::TestRequest::put()
                .uri("/alice/private/y")
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert!(
            w.status().as_u16() == 401 || w.status().as_u16() == 403,
            "{layout:?} anonymous write: {}",
            w.status()
        );
    }
}

#[actix_web::test]
async fn admin_provision_writes_the_matching_form() {
    const KEY: &str = "psk-for-layout-tests";
    let pk = "ab".repeat(32);
    for layout in MODES {
        let tmp = tempfile::tempdir().unwrap();
        let fs = FsBackend::new(tmp.path().to_path_buf()).await.unwrap();
        let mut st = AppState::new(Arc::new(fs));
        st.data_root = Some(tmp.path().to_path_buf());
        st.admin_key = Some(KEY.into());
        st.acl_layout = layout;
        let app = test::init_service(build_app(st)).await;
        let rsp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/_admin/provision/{pk}"))
                .insert_header(("x-pod-admin-key", KEY))
                .to_request(),
        )
        .await;
        assert_eq!(rsp.status().as_u16(), 200, "{layout:?}");
        let sibling = tmp.path().join("pods").join(format!("{pk}.acl")).is_file();
        let inner = tmp.path().join("pods").join(&pk).join(".acl").is_file();
        match layout {
            // Exactly what the endpoint has always written.
            AclLayout::Sidecar | AclLayout::Both => assert!(sibling && inner, "{layout:?}"),
            AclLayout::Inner => assert!(!sibling && inner, "{layout:?}"),
        }
        // Whatever was written governs: an anonymous write is refused.
        let w = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&format!("/pods/{pk}/x"))
                .insert_header(("content-type", "text/plain"))
                .set_payload("x")
                .to_request(),
        )
        .await;
        assert!(
            w.status().as_u16() == 401 || w.status().as_u16() == 403,
            "{layout:?}: {}",
            w.status()
        );
    }
}
