//! Candidate policies must preserve effective Control before any mutation.
use actix_web::{http::Method, test};
use bytes::Bytes;
use serde_json::json;
use solid_pod_rs::{
    auth::nip98,
    storage::{memory::MemoryBackend, Storage},
};
use solid_pod_rs_server::{build_app, AppState};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const RESOURCE: &str = "/private/document.bin";
const POLICY: &str = "/private/document.bin.acl";

struct Fixture {
    storage: Arc<MemoryBackend>,
    secret: String,
    owner: String,
    time: AtomicU64,
    linked: Option<String>,
}
impl Fixture {
    async fn new() -> Self {
        static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
        let mut secret_bytes = [0x41; 32];
        secret_bytes[0] = NEXT_KEY.fetch_add(1, Ordering::Relaxed) as u8;
        let key = k256::schnorr::SigningKey::from_slice(&secret_bytes).unwrap();
        let f = Self {
            storage: Arc::new(MemoryBackend::new()),
            secret: hex::encode(key.to_bytes()),
            linked: None,
            owner: format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes())),
            time: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        };
        f.storage.create_container("/private/").await.unwrap();
        f.storage
            .put("/.acl", Bytes::from(f.turtle("/", true)), "text/turtle")
            .await
            .unwrap();
        f.storage
            .put(
                RESOURCE,
                Bytes::from_static(b"private bytes"),
                "application/octet-stream",
            )
            .await
            .unwrap();
        f.storage
            .put(
                POLICY,
                Bytes::from(f.turtle(RESOURCE, false)),
                "text/turtle",
            )
            .await
            .unwrap();
        assert_eq!(f.call("GET", RESOURCE, "", "", &[]).await, 200);
        f
    }
    fn turtle(&self, target: &str, inherited: bool) -> String {
        format!("@prefix acl: <{ACL}> .\n<#owner> a acl:Authorization ; acl:agent <{}> ; acl:accessTo <{target}> ; {} acl:mode acl:Read, acl:Write, acl:Control .\n", self.owner, if inherited { format!("acl:default <{target}> ;") } else { String::new() })
    }
    fn json(&self, target: &str) -> serde_json::Value {
        json!({"@graph":[{"@id":"#owner", "@type":"acl:Authorization", "acl:agent":{"@id":self.owner}, "acl:accessTo":{"@id":target}, "acl:mode":[{"@id":"acl:Read"},{"@id":"acl:Write"},{"@id":"acl:Control"}]}]})
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        ct: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> u16 {
        let mut state = AppState::new(self.storage.clone());
        if let Some(webid) = &self.linked {
            state.cross_identity = Some(Arc::new(VerifiedLink(webid.clone())));
        }
        let app = test::init_service(build_app(state)).await;
        let now = self.time.fetch_add(1, Ordering::Relaxed);
        let token = nip98::mint_with_payload(
            &format!("http://pod.example{path}"),
            method,
            Some(body.as_bytes()),
            &self.secret,
            now,
        )
        .unwrap();
        let mut req = test::TestRequest::default()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(path)
            .insert_header(("host", "pod.example"))
            .insert_header(("authorization", nip98::authorization_header(&token)))
            .insert_header(("content-type", ct))
            .set_payload(body.to_owned());
        for (k, v) in headers {
            req = req.insert_header((*k, *v));
        }
        test::call_service(&app, req.to_request())
            .await
            .status()
            .as_u16()
    }
    async fn unchanged_and_usable(&self, before: &Bytes) {
        assert_eq!(&self.storage.get(POLICY).await.unwrap().0, before);
        assert_eq!(self.call("GET", RESOURCE, "", "", &[]).await, 200);
        assert_eq!(self.call("GET", POLICY, "", "", &[]).await, 200);
    }
}

#[actix_web::test]
async fn put_refuses_unparseable_and_misdirected_policies_without_lockout() {
    let f = Fixture::new().await;
    let before = f.storage.get(POLICY).await.unwrap().0;
    for (ct, body) in [
        ("application/ld+json", "{not json".to_owned()),
        ("application/ld+json", "[]".to_owned()),
        ("text/plain", "not an ACL".to_owned()),
        ("text/turtle", f.turtle("/elsewhere", false)),
    ] {
        assert_eq!(
            f.call("PUT", POLICY, ct, &body, &[]).await,
            409,
            "candidate: {body}"
        );
        f.unchanged_and_usable(&before).await;
    }
    assert_eq!(
        f.call(
            "PUT",
            POLICY,
            "application/ld+json",
            &f.json(RESOURCE).to_string(),
            &[]
        )
        .await,
        201
    );
    assert_eq!(f.call("GET", RESOURCE, "", "", &[]).await, 200);
}

#[actix_web::test]
async fn candidate_control_requires_satisfied_conditions() {
    let f = Fixture::new().await;
    let before = f.storage.get(POLICY).await.unwrap().0;
    let mut candidate = f.json(RESOURCE);
    candidate["@graph"][0]["acl:condition"] = json!([{"@type":"acl:ClientCondition", "acl:client":{"@id":"https://unavailable.example/client"}}]);
    assert_eq!(
        f.call(
            "PUT",
            POLICY,
            "application/ld+json",
            &candidate.to_string(),
            &[]
        )
        .await,
        409
    );
    f.unchanged_and_usable(&before).await;
}

#[actix_web::test]
async fn post_and_copy_refuse_invalid_acl_bodies_before_storage() {
    for method in ["POST", "COPY"] {
        let f = Fixture::new().await;
        let before = f.storage.get(POLICY).await.unwrap().0;
        let status = if method == "POST" {
            f.call(
                method,
                "/private/",
                "application/ld+json",
                "{not json",
                &[("slug", "document.bin.acl")],
            )
            .await
        } else {
            f.storage
                .put(
                    "/source.json",
                    Bytes::from_static(b"{not json"),
                    "application/ld+json",
                )
                .await
                .unwrap();
            f.call(method, POLICY, "", "", &[("source", "/source.json")])
                .await
        };
        assert_eq!(status, 409, "method {method}");
        f.unchanged_and_usable(&before).await;
    }
}

#[actix_web::test]
async fn json_patch_checks_resulting_acl_before_committing_it() {
    let f = Fixture::new().await;
    let original = f.json(RESOURCE).to_string();
    f.storage
        .put(POLICY, Bytes::from(original.clone()), "application/ld+json")
        .await
        .unwrap();
    let before = Bytes::from(original);
    assert_eq!(
        f.call(
            "PATCH",
            POLICY,
            "application/json-patch+json",
            r#"[{"op":"remove","path":"/@graph"}]"#,
            &[]
        )
        .await,
        409
    );
    f.unchanged_and_usable(&before).await;
    assert_eq!(
        f.call(
            "PATCH",
            POLICY,
            "application/json-patch+json",
            r#"[{"op":"add","path":"/label","value":"updated"}]"#,
            &[]
        )
        .await,
        204
    );
    assert_eq!(f.call("GET", RESOURCE, "", "", &[]).await, 200);
}

#[actix_web::test]
async fn copying_resource_does_not_install_a_policy_for_the_wrong_target() {
    let f = Fixture::new().await;
    let before = f.storage.get(POLICY).await.unwrap().0;
    f.storage
        .put(
            "/source.bin",
            Bytes::from_static(b"copied"),
            "application/octet-stream",
        )
        .await
        .unwrap();
    f.storage
        .put(
            "/source.bin.acl",
            Bytes::from(f.turtle("/source.bin", false)),
            "text/turtle",
        )
        .await
        .unwrap();
    assert_eq!(
        f.call("COPY", RESOURCE, "", "", &[("source", "/source.bin")])
            .await,
        201
    );
    f.unchanged_and_usable(&before).await;
    assert_eq!(
        f.storage.get(RESOURCE).await.unwrap().0,
        Bytes::from_static(b"copied")
    );
}

#[actix_web::test]
async fn ordinary_metadata_requires_control_but_is_not_an_acl_document() {
    let f = Fixture::new().await;
    assert_eq!(
        f.call(
            "PUT",
            "/private/document.bin.meta",
            "application/ld+json",
            r#"{"label":"metadata"}"#,
            &[]
        )
        .await,
        201
    );
    assert_eq!(
        f.storage.get("/private/document.bin.meta").await.unwrap().0,
        Bytes::from_static(br#"{"label":"metadata"}"#)
    );
}

// Admission trusts this resolver seam to supply an already verified identity.
struct VerifiedLink(String);
#[async_trait::async_trait]
impl solid_pod_rs_server::cross_identity::CrossIdentityResolver for VerifiedLink {
    async fn linked_web_id(&self, _pubkey: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

#[actix_web::test]
async fn candidate_control_preserves_a_verified_linked_identity() {
    let mut f = Fixture::new().await;
    let webid = "https://owner.example/profile#me";
    f.linked = Some(webid.into());
    let mut candidate = f.json(RESOURCE);
    candidate["@graph"][0]["acl:agent"] = json!({"@id":webid});
    assert_eq!(
        f.call(
            "PUT",
            POLICY,
            "application/ld+json",
            &candidate.to_string(),
            &[]
        )
        .await,
        201
    );
    assert_eq!(f.call("GET", RESOURCE, "", "", &[]).await, 200);
    assert_eq!(f.call("GET", POLICY, "", "", &[]).await, 200);
}

#[actix_web::test]
async fn copy_checks_turtle_syntax_even_with_a_recognisable_control_rule() {
    let f = Fixture::new().await;
    let before = f.storage.get(POLICY).await.unwrap().0;
    let malformed = format!("{}\nthis is invalid Turtle [", f.turtle(RESOURCE, false));
    f.storage
        .put("/source.ttl", Bytes::from(malformed), "text/turtle")
        .await
        .unwrap();
    assert_eq!(
        f.call("COPY", POLICY, "", "", &[("source", "/source.ttl")])
            .await,
        409
    );
    f.unchanged_and_usable(&before).await;
}

#[actix_web::test]
async fn following_the_container_acl_link_changes_actual_child_access() {
    let f = Fixture::new().await;
    let public = format!("{}\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n<#public> a acl:Authorization; acl:agentClass foaf:Agent; acl:accessTo </>; acl:default </>; acl:mode acl:Read .\n", f.turtle("/", true));
    f.storage
        .put("/.acl", Bytes::from(public), "text/turtle")
        .await
        .unwrap();
    f.storage.create_container("/shared/").await.unwrap();
    f.storage
        .put(
            "/shared/item.txt",
            Bytes::from_static(b"initially public"),
            "text/plain",
        )
        .await
        .unwrap();
    let app = test::init_service(build_app(AppState::new(f.storage.clone()))).await;
    let child = || {
        test::TestRequest::get()
            .uri("/shared/item.txt")
            .to_request()
    };
    assert_eq!(
        test::call_service(&app, child()).await.status().as_u16(),
        200
    );
    let response =
        test::call_service(&app, test::TestRequest::get().uri("/shared/").to_request()).await;
    assert_eq!(response.status().as_u16(), 200);
    let acl_link = response
        .headers()
        .get_all("link")
        .flat_map(|v| v.to_str().unwrap().split(','))
        .find(|v| v.contains("rel=\"acl\""))
        .unwrap();
    let target = acl_link
        .trim()
        .split('>')
        .next()
        .unwrap()
        .trim_start_matches('<');
    assert_eq!(
        f.call(
            "PUT",
            target,
            "text/turtle",
            &f.turtle("/shared/", true),
            &[]
        )
        .await,
        201
    );
    assert_eq!(
        test::call_service(&app, child()).await.status().as_u16(),
        401,
        "restrictive policy written to advertised target {target} must govern the child"
    );
    assert_eq!(f.call("GET", "/shared/item.txt", "", "", &[]).await, 200);
    assert_eq!(target, "/shared.acl");
}
