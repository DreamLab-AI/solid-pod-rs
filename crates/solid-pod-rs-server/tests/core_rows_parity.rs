//! Parity rows 35 (Turtle/N3 bodies), 60 (did:nostr to WebID cross-identity),
//! 177 (trusted-proxy scheme) and 178 (ActivityPub actor knobs).
//!
//! Row 35 oracle: JSS `src/rdf/conneg.js` 16, 25, 144-145 (Turtle and N3 are
//! accepted bodies only with conneg on). Row 177 oracle: JSS
//! `src/ap/routes/actor.js` 17-18. Row 178 oracle: JSS `src/ap/routes/actor.js`
//! 61-64 and `src/server.js` 134-135, 545-570.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::test;
use async_trait::async_trait;
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::cross_identity::CrossIdentityResolver;
use solid_pod_rs_server::{build_app, AppState};

const SK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const WEBID: &str = "https://alice.example/profile/card#me";

fn pubkey() -> String {
    let sk = hex::decode(SK_HEX).unwrap();
    let signing = k256::schnorr::SigningKey::from_slice(&sk).unwrap();
    hex::encode(signing.verifying_key().to_bytes())
}

fn token(method: &str, url: &str, body: Option<&[u8]>) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(30)
        + SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "Nostr {}",
        nip98::mint_with_payload(url, method, body, SK_HEX, now).unwrap()
    )
}

fn acl_for(target: &str, agent: &str, modes: &[&str]) -> String {
    let modes: Vec<String> = modes
        .iter()
        .map(|m| format!(r#"{{"@id": "acl:{m}"}}"#))
        .collect();
    format!(
        r##"{{
            "@context": {{"acl": "http://www.w3.org/ns/auth/acl#"}},
            "@graph": [{{
                "@id": "#r", "@type": "acl:Authorization",
                "acl:agent": {{"@id": "{agent}"}},
                "acl:accessTo": {{"@id": "{target}"}},
                "acl:mode": [{}]
            }}]
        }}"##,
        modes.join(",")
    )
}

fn public_write_acl(target: &str) -> String {
    format!(
        "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
         @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n\
         <#r> a acl:Authorization ; acl:agentClass foaf:Agent ;\n\
           acl:accessTo <{target}> ; acl:default <{target}> ;\n\
           acl:mode acl:Read, acl:Write, acl:Append .\n"
    )
}

async fn seed(state: &AppState, path: &str, body: &str, ct: &str) {
    state
        .storage
        .put(path, bytes::Bytes::from(body.to_string()), ct)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Row 35
// ---------------------------------------------------------------------------

async fn put_status(conneg: bool, ct: &str, body: &str) -> u16 {
    let mut st = AppState::new(Arc::new(MemoryBackend::new()));
    st.conneg_enabled = conneg;
    seed(&st, "/.acl", &public_write_acl("/"), "text/turtle").await;
    let app = test::init_service(build_app(st)).await;
    let req = test::TestRequest::put()
        .uri("/open/doc")
        .insert_header((header::CONTENT_TYPE, ct))
        .set_payload(body.to_string())
        .to_request();
    test::call_service(&app, req).await.status().as_u16()
}

#[actix_web::test]
async fn turtle_body_must_parse() {
    assert_eq!(
        put_status(false, "text/turtle", "<> <http://e/p> \"v\" .").await,
        201
    );
    assert_eq!(
        put_status(false, "text/turtle", "<> <http://e/p> .").await,
        400
    );
    // Non-RDF media types are untouched.
    assert_eq!(
        put_status(false, "text/plain", "<> <http://e/p> .").await,
        201
    );
}

#[actix_web::test]
async fn n3_body_needs_conneg_and_rejects_formulas() {
    let plain = "@prefix : <http://e/> . :a :b :c .";
    assert_eq!(put_status(false, "text/n3", plain).await, 415);
    assert_eq!(put_status(true, "text/n3", plain).await, 201);
    assert_eq!(
        put_status(
            true,
            "text/n3",
            "@prefix : <http://e/> . { :a :b :c } :says :x ."
        )
        .await,
        415
    );
    assert_eq!(
        put_status(true, "text/n3", "@prefix : <http://e/> . ?x :b :c .").await,
        415
    );
    assert_eq!(put_status(true, "text/n3", ":a :b").await, 400);
}

#[actix_web::test]
async fn post_turtle_is_validated_with_the_new_resource_as_base() {
    let st = AppState::new(Arc::new(MemoryBackend::new()));
    seed(&st, "/.acl", &public_write_acl("/"), "text/turtle").await;
    let storage = st.storage.clone();
    let app = test::init_service(build_app(st)).await;
    let bad = test::TestRequest::post()
        .uri("/open/")
        .insert_header((header::CONTENT_TYPE, "text/turtle"))
        .set_payload("not turtle")
        .to_request();
    assert_eq!(test::call_service(&app, bad).await.status().as_u16(), 400);
    let good = test::TestRequest::post()
        .uri("/open/")
        .insert_header((header::CONTENT_TYPE, "text/turtle"))
        .insert_header(("slug", "note"))
        .set_payload("<> a <http://e/Note> .")
        .to_request();
    assert_eq!(test::call_service(&app, good).await.status().as_u16(), 201);
    assert!(storage.exists("/open/note").await.unwrap());
}

#[actix_web::test]
async fn accept_post_lists_n3_only_with_conneg() {
    for (conneg, want) in [(false, false), (true, true)] {
        let mut st = AppState::new(Arc::new(MemoryBackend::new()));
        st.conneg_enabled = conneg;
        let app = test::init_service(build_app(st)).await;
        let req = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/open/")
            .to_request();
        let rsp = test::call_service(&app, req).await;
        let ap = rsp
            .headers()
            .get("accept-post")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(ap.contains("text/n3"), want, "{ap}");
    }
}

// ---------------------------------------------------------------------------
// Row 60
// ---------------------------------------------------------------------------

struct Fake(Option<&'static str>);

#[async_trait]
impl CrossIdentityResolver for Fake {
    async fn linked_web_id(&self, _pubkey: &str) -> Option<String> {
        self.0.map(String::from)
    }
}

async fn read_status(resolver: Option<Option<&'static str>>, acl_agent: &str) -> u16 {
    let mut st = AppState::new(Arc::new(MemoryBackend::new()));
    st.cross_identity = None;
    if let Some(r) = resolver {
        st.cross_identity = Some(Arc::new(Fake(r)));
    }
    seed(&st, "/secret.txt", "classified", "text/plain").await;
    seed(
        &st,
        "/secret.txt.acl",
        &acl_for("/secret.txt", acl_agent, &["Read"]),
        "application/ld+json",
    )
    .await;
    let app = test::init_service(build_app(st)).await;
    let req = test::TestRequest::get()
        .uri("/secret.txt")
        .insert_header((
            header::AUTHORIZATION,
            token("GET", "http://localhost:8080/secret.txt", None),
        ))
        .to_request();
    test::call_service(&app, req).await.status().as_u16()
}

#[actix_web::test]
async fn webid_acl_matches_a_nostr_caller_with_a_verified_link() {
    // Verified link: both ACL styles match.
    assert_eq!(read_status(Some(Some(WEBID)), WEBID).await, 200);
    assert_eq!(
        read_status(Some(Some(WEBID)), &format!("did:nostr:{}", pubkey())).await,
        200
    );
}

#[actix_web::test]
async fn webid_acl_does_not_match_without_a_link() {
    // No resolver, resolver finds nothing, or it links a different WebID.
    assert_eq!(read_status(None, WEBID).await, 403);
    assert_eq!(read_status(Some(None), WEBID).await, 403);
    assert_eq!(
        read_status(Some(Some("https://mallory.example/#me")), WEBID).await,
        403
    );
    // The did:nostr style keeps working with no resolver at all.
    assert_eq!(
        read_status(None, &format!("did:nostr:{}", pubkey())).await,
        200
    );
}

// ---------------------------------------------------------------------------
// Row 177
// ---------------------------------------------------------------------------

async fn proxied_status(trust_proxy: bool, headers: &[(&'static str, &'static str)]) -> u16 {
    let mut st = AppState::new(Arc::new(MemoryBackend::new()));
    st.trust_proxy = trust_proxy;
    seed(&st, "/secret.txt", "classified", "text/plain").await;
    seed(
        &st,
        "/secret.txt.acl",
        &acl_for("/secret.txt", &format!("did:nostr:{}", pubkey()), &["Read"]),
        "application/ld+json",
    )
    .await;
    let app = test::init_service(build_app(st)).await;
    let mut req = test::TestRequest::get().uri("/secret.txt").insert_header((
        header::AUTHORIZATION,
        // The client signed the public https URL.
        token("GET", "https://localhost:8080/secret.txt", None),
    ));
    for h in headers {
        req = req.insert_header(*h);
    }
    test::call_service(&app, req.to_request())
        .await
        .status()
        .as_u16()
}

#[actix_web::test]
async fn forwarded_proto_counts_only_behind_a_trusted_proxy() {
    let xfp = [("x-forwarded-proto", "https")];
    assert_eq!(proxied_status(true, &xfp).await, 200);
    assert_eq!(proxied_status(false, &xfp).await, 401);
}

#[actix_web::test]
async fn cf_visitor_counts_only_behind_a_trusted_proxy() {
    let cf = [("cf-visitor", r#"{"scheme":"https"}"#)];
    assert_eq!(proxied_status(true, &cf).await, 200);
    assert_eq!(proxied_status(false, &cf).await, 401);
}

// ---------------------------------------------------------------------------
// Row 178
// ---------------------------------------------------------------------------

#[cfg(feature = "activitypub")]
mod activitypub_actor {
    use super::*;
    use solid_pod_rs_server::activitypub::ApConfig;

    async fn app_state(ap: Option<ApConfig>) -> AppState {
        let mut st = AppState::new(Arc::new(MemoryBackend::new()));
        st.activitypub = ap.map(|a| Arc::new(a) as Arc<dyn solid_pod_rs_server::ActorDocument>);
        seed(
            &st,
            "/profile/card.jsonld",
            r##"{"@id":"#me"}"##,
            "application/ld+json",
        )
        .await;
        st
    }

    fn cfg() -> ApConfig {
        ApConfig::from_knobs(
            Some("alice"),
            Some("Alice"),
            Some("hello"),
            Some(&pubkey()),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".into(),
        )
        .unwrap()
    }

    #[actix_web::test]
    async fn actor_served_for_activity_json_accept() {
        let app = test::init_service(build_app(app_state(Some(cfg())).await)).await;
        let req = test::TestRequest::get()
            .uri("/profile/card.jsonld")
            .insert_header((header::ACCEPT, "application/activity+json"))
            .to_request();
        let rsp = test::call_service(&app, req).await;
        assert_eq!(rsp.status().as_u16(), 200);
        assert_eq!(
            rsp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/activity+json"
        );
        let v: serde_json::Value = test::read_body_json(rsp).await;
        assert_eq!(v["preferredUsername"], "alice");
        assert_eq!(v["name"], "Alice");
        assert_eq!(v["summary"], "<p>hello</p>");
        assert_eq!(v["alsoKnownAs"][0], format!("did:nostr:{}", pubkey()));
        assert_eq!(v["id"], "http://localhost:8080/profile/card.jsonld#me");
    }

    #[actix_web::test]
    async fn no_route_without_the_knob_and_normal_get_unchanged() {
        let app = test::init_service(build_app(app_state(None).await)).await;
        let req = test::TestRequest::get()
            .uri("/profile/card.jsonld")
            .insert_header((header::ACCEPT, "application/activity+json"))
            .to_request();
        let rsp = test::call_service(&app, req).await;
        assert_ne!(
            rsp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/activity+json")
        );
    }
}
