//! A pod created through `POST /.pods` is usable by its owner.
//!
//! Before the fix, `provision_named_pod` wrote the containers and the
//! profile card but no ACL, so the new pod inherited whatever the operator's
//! root ACL granted: nothing at all on a fresh server (owner 403 on their own
//! pod), or the root's grants, public ones included, when a root ACL with
//! `acl:default` existed. JSS writes an owner ACL tree with the pod
//! (`createPodStructure`, `src/handlers/container.js:260-296`): owner full
//! control everywhere, public read on the pod root (not inherited),
//! `profile/` and `public/`, public append on `inbox/`, owner-only
//! `private/` and `settings/`. Parity checklist row 287.

#![cfg(feature = "dev-bearer")]

use std::sync::Arc;

use actix_web::test;
use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs_server::{build_app, AppState};

const SECRET: &str = "01234567890123456789012345678901";
const STRANGER: &str = "https://stranger.example/profile/card#me";

fn bearer(web_id: &str) -> String {
    std::env::set_var("TOKEN_SECRET", SECRET);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "webId": web_id,
            "iat": now - 10,
            "exp": now + 3600,
            "aud": solid_pod_rs_server::DEV_BEARER_AUDIENCE,
        })
        .to_string(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("Bearer {data}.{sig}")
}

/// Create `alice` through `POST /.pods` and return the app plus the owner WebID.
macro_rules! create_alice {
    ($storage:expr) => {{
        let mut state = AppState::new($storage.clone());
        state.nodeinfo.open_registrations = true;
        let app = test::init_service(build_app(state)).await;
        let req = test::TestRequest::post()
            .uri("/.pods")
            .insert_header(("content-type", "application/json"))
            .set_payload(r#"{"name":"alice"}"#)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201, "pod creation");
        let body: serde_json::Value = test::read_body_json(resp).await;
        let webid = body["webId"].as_str().expect("webId").to_string();
        (app, webid)
    }};
}

macro_rules! status {
    ($app:expr, $method:expr, $uri:expr, $who:expr) => {{
        let method: &str = $method;
        let who: Option<&str> = $who;
        let mut req = match method {
            "PUT" => test::TestRequest::put()
                .insert_header(("content-type", "text/turtle"))
                .set_payload("<#a> <#b> <#c> .\n"),
            "POST" => test::TestRequest::post()
                .insert_header(("content-type", "text/plain"))
                .set_payload("hello"),
            _ => test::TestRequest::get(),
        }
        .uri($uri);
        if let Some(w) = who {
            req = req.insert_header(("Authorization", bearer(w)));
        }
        test::call_service($app, req.to_request())
            .await
            .status()
            .as_u16()
    }};
}

fn ok(code: u16) -> bool {
    (200..300).contains(&code)
}

fn refused(code: u16) -> bool {
    code == 401 || code == 403
}

#[actix_web::test]
async fn owner_can_read_and_write_their_new_pod() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let (app, owner) = create_alice!(storage);

    for uri in ["/alice/", "/alice/private/", "/alice/settings/"] {
        let code = status!(&app, "GET", uri, Some(owner.as_str()));
        assert!(ok(code), "owner GET {uri} gave {code}");
    }
    for uri in [
        "/alice/public/x.ttl",
        "/alice/private/y.ttl",
        "/alice/z.ttl",
    ] {
        let code = status!(&app, "PUT", uri, Some(owner.as_str()));
        assert!(ok(code), "owner PUT {uri} gave {code}");
    }
}

#[actix_web::test]
async fn public_surfaces_match_jss_and_private_ones_stay_private() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let (app, owner) = create_alice!(storage);
    let _ = status!(
        &app,
        "PUT",
        "/alice/private/secret.ttl",
        Some(owner.as_str())
    );
    let _ = status!(&app, "PUT", "/alice/public/note.ttl", Some(owner.as_str()));

    // WebID verification needs the profile to be world-readable.
    let code = status!(&app, "GET", "/alice/profile/card", None);
    assert!(ok(code), "anonymous GET of the profile card gave {code}");
    let code = status!(&app, "GET", "/alice/public/note.ttl", None);
    assert!(ok(code), "anonymous GET under public/ gave {code}");
    // Root is publicly readable itself, but the grant is not inherited.
    let code = status!(&app, "GET", "/alice/", None);
    assert!(ok(code), "anonymous GET of the pod root gave {code}");

    for uri in [
        "/alice/private/secret.ttl",
        "/alice/private/",
        "/alice/settings/",
    ] {
        let code = status!(&app, "GET", uri, None);
        assert!(refused(code), "anonymous GET {uri} gave {code}");
        let code = status!(&app, "GET", uri, Some(STRANGER));
        assert!(refused(code), "stranger GET {uri} gave {code}");
    }
    for uri in [
        "/alice/public/hijack.ttl",
        "/alice/profile/card",
        "/alice/x.ttl",
    ] {
        let code = status!(&app, "PUT", uri, Some(STRANGER));
        assert!(refused(code), "stranger PUT {uri} gave {code}");
    }
}

#[actix_web::test]
async fn inbox_accepts_public_append_but_not_reads() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let (app, owner) = create_alice!(storage);

    let code = status!(&app, "POST", "/alice/inbox/", Some(STRANGER));
    assert!(ok(code), "stranger POST into inbox/ gave {code}");
    let code = status!(&app, "GET", "/alice/inbox/", Some(STRANGER));
    assert!(refused(code), "stranger GET of inbox/ gave {code}");
    let code = status!(&app, "GET", "/alice/inbox/", Some(owner.as_str()));
    assert!(ok(code), "owner GET of inbox/ gave {code}");
}

#[actix_web::test]
async fn an_operator_root_acl_granting_public_write_does_not_leak_into_new_pods() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    storage
        .put(
            "/.acl",
            Bytes::from(
                "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
                 @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
                 <#public> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
                   acl:accessTo </> ; acl:default </> ;\n\
                   acl:mode acl:Read, acl:Write .\n",
            ),
            "text/turtle",
        )
        .await
        .unwrap();
    let (app, owner) = create_alice!(storage);
    let _ = status!(
        &app,
        "PUT",
        "/alice/private/secret.ttl",
        Some(owner.as_str())
    );

    let code = status!(&app, "GET", "/alice/private/secret.ttl", None);
    assert!(refused(code), "anonymous GET of a private file gave {code}");
    let code = status!(&app, "PUT", "/alice/private/secret.ttl", None);
    assert!(
        refused(code),
        "anonymous PUT over a private file gave {code}"
    );
}

/// A provisioned ACL stores path-form targets (`</alice/public/>`), the form
/// the WAC evaluator matches. PATCH resolves IRIs against the resource URL,
/// so re-serialising the patched ACL must not turn them into absolute IRIs
/// that the evaluator can no longer match, which would lock the owner out.
#[actix_web::test]
async fn patching_a_provisioned_acl_keeps_the_owner_in() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let (app, owner) = create_alice!(storage);

    let grant = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
         @prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\
         _:p a solid:InsertDeletePatch; solid:inserts {{\n\
           <#friend> a acl:Authorization; acl:agent <{STRANGER}>;\n\
             acl:accessTo </alice/public/>; acl:mode acl:Read.\n\
         }}."
    );
    let req = test::TestRequest::patch()
        .uri("/alice/public.acl")
        .insert_header(("content-type", "text/n3"))
        .insert_header(("Authorization", bearer(&owner)))
        .set_payload(grant)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let code = resp.status().as_u16();
    let body = String::from_utf8_lossy(&test::read_body(resp).await).to_string();
    assert!(ok(code), "owner PATCH of their ACL gave {code}: {body}");

    let code = status!(&app, "PUT", "/alice/public/after.ttl", Some(owner.as_str()));
    assert!(ok(code), "owner PUT after patching the ACL gave {code}");
    let code = status!(&app, "GET", "/alice/public.acl", Some(owner.as_str()));
    assert!(ok(code), "owner GET of the patched ACL gave {code}");
    let code = status!(&app, "GET", "/alice/public/", Some(STRANGER));
    assert!(ok(code), "the new grant does not apply: {code}");
}

/// Storage whose existence probe for the `alice` pod root fails.
struct UnprobeablePodRoot(MemoryBackend);

#[async_trait::async_trait]
impl Storage for UnprobeablePodRoot {
    async fn get(
        &self,
        path: &str,
    ) -> Result<(Bytes, solid_pod_rs::storage::ResourceMeta), solid_pod_rs::PodError> {
        self.0.get(path).await
    }
    async fn put(
        &self,
        path: &str,
        body: Bytes,
        ct: &str,
    ) -> Result<solid_pod_rs::storage::ResourceMeta, solid_pod_rs::PodError> {
        self.0.put(path, body, ct).await
    }
    async fn delete(&self, path: &str) -> Result<(), solid_pod_rs::PodError> {
        self.0.delete(path).await
    }
    async fn list(&self, path: &str) -> Result<Vec<String>, solid_pod_rs::PodError> {
        self.0.list(path).await
    }
    async fn head(
        &self,
        path: &str,
    ) -> Result<solid_pod_rs::storage::ResourceMeta, solid_pod_rs::PodError> {
        self.0.head(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool, solid_pod_rs::PodError> {
        if path == "/alice/" {
            return Err(solid_pod_rs::PodError::Backend(
                "injected probe failure".into(),
            ));
        }
        self.0.exists(path).await
    }
    async fn watch(
        &self,
        path: &str,
    ) -> Result<
        tokio::sync::mpsc::Receiver<solid_pod_rs::storage::StorageEvent>,
        solid_pod_rs::PodError,
    > {
        self.0.watch(path).await
    }
}

/// A failed existence probe is not evidence the pod is free: provisioning
/// would overwrite an existing pod's ACL tree with a fresh one, so it is
/// refused and the stored ACL is untouched.
#[actix_web::test]
async fn pod_creation_refuses_when_the_existence_probe_fails() {
    const KEPT: &str = "<#kept> a <http://www.w3.org/ns/auth/acl#Authorization> .\n";
    let inner = MemoryBackend::new();
    inner
        .put("/alice.acl", Bytes::from(KEPT), "text/turtle")
        .await
        .unwrap();
    let storage: Arc<dyn Storage> = Arc::new(UnprobeablePodRoot(inner));
    let mut state = AppState::new(storage.clone());
    state.nodeinfo.open_registrations = true;
    let app = test::init_service(build_app(state)).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/.pods")
            .insert_header(("content-type", "application/json"))
            .set_payload(r#"{"name":"alice"}"#)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 500, "probe failure must refuse");
    let (acl, _) = storage.get("/alice.acl").await.unwrap();
    assert_eq!(&acl[..], KEPT.as_bytes(), "existing ACL was overwritten");
}

/// Concurrent creations of one pod name: exactly one wins, the rest are
/// told it exists, rather than each re-provisioning over the last.
#[actix_web::test]
async fn concurrent_creations_of_one_pod_name_admit_exactly_one() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn Storage> = Arc::new(
        solid_pod_rs::storage::fs::FsBackend::new(dir.path())
            .await
            .unwrap(),
    );
    let mut state = AppState::new(storage);
    state.nodeinfo.open_registrations = true;
    let app = test::init_service(build_app(state)).await;
    let requests = (0..8u8).map(|i| {
        test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/.pods")
                // Distinct peers, so the per-IP creation limiter admits all.
                .peer_addr(std::net::SocketAddr::from(([10, 0, 0, i + 1], 4000)))
                .insert_header(("content-type", "application/json"))
                .set_payload(r#"{"name":"alice"}"#)
                .to_request(),
        )
    });
    let codes: Vec<u16> = futures_util::future::join_all(requests)
        .await
        .iter()
        .map(|r| r.status().as_u16())
        .collect();
    assert_eq!(codes.iter().filter(|c| **c == 201).count(), 1, "{codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == 409).count(), 7, "{codes:?}");
}

/// Guarding the patched ACL under its stored content type must still refuse
/// a PATCH that removes the owner's own Control. A positive control first
/// shows deletes against the provisioned ACL do match (so the refusal is
/// the lockout guard, not a delete that found nothing).
#[actix_web::test]
async fn patching_away_the_owners_control_is_refused() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
    let (app, owner) = create_alice!(storage);
    let delete_mode = |mode: &str| {
        let body = format!(
            "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
             @prefix acl: <http://www.w3.org/ns/auth/acl#>.\n\
             _:p a solid:InsertDeletePatch; solid:deletes {{\n\
               <#owner> acl:mode acl:{mode}.\n\
             }}."
        );
        test::TestRequest::patch()
            .uri("/alice/public.acl")
            .insert_header(("content-type", "text/n3"))
            .insert_header(("Authorization", bearer(&owner)))
            .set_payload(body)
            .to_request()
    };

    let resp = test::call_service(&app, delete_mode("Write")).await;
    let code = resp.status().as_u16();
    let body = String::from_utf8_lossy(&test::read_body(resp).await).to_string();
    assert_eq!(code, 204, "removing another mode should apply: {body}");

    let (before, _) = storage.get("/alice/public.acl").await.unwrap();
    let resp = test::call_service(&app, delete_mode("Control")).await;
    let code = resp.status().as_u16();
    let body = String::from_utf8_lossy(&test::read_body(resp).await).to_string();
    assert_eq!(code, 409, "owner stripped their own Control: {body}");
    assert!(
        body.contains("would not grant Control"),
        "refused for another reason: {body}"
    );
    let (after, _) = storage.get("/alice/public.acl").await.unwrap();
    assert_eq!(before, after, "refused PATCH still changed the ACL");
}
