//! SP-PAR-288 / SP-PAR-289: `acl:accessTo`, `acl:default` and `acl:agent`
//! given as absolute or relative IRIs resolve against the configured pod
//! origin and the ACL document's own URL.
//!
//! The property under test is the negative one: an ACL naming another origin's
//! resource must never grant here (look-alike hosts, ports, schemes, case,
//! trailing slashes, percent-encoding). With no configured origin the
//! evaluator keeps failing closed, and a request `Host` never supplies the
//! origin.

use std::sync::Arc;

use actix_web::{http::Method, test};
use bytes::Bytes;
use solid_pod_rs::{
    auth::nip98,
    storage::{memory::MemoryBackend, Storage},
};
use solid_pod_rs_server::{build_app, AppState};

const BASE: &str = "https://pod.example";
const ACL: &str = "http://www.w3.org/ns/auth/acl#";

/// Anonymous and owner access against one in-memory pod.
struct Pod {
    storage: Arc<MemoryBackend>,
    base: Option<&'static str>,
    linked: Option<String>,
    secret: String,
    owner: String,
}

struct Link(String);
#[async_trait::async_trait]
impl solid_pod_rs_server::cross_identity::CrossIdentityResolver for Link {
    async fn linked_web_id(&self, _pubkey: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

impl Pod {
    async fn new(base: Option<&'static str>) -> Self {
        let key = k256::schnorr::SigningKey::from_slice(&[0x52; 32]).unwrap();
        let owner = format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes()));
        let storage = Arc::new(MemoryBackend::new());
        // Root ACL in path form: owner-only, so nothing else is public.
        storage
            .put(
                "/.acl",
                Bytes::from(format!(
                    "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{owner}> ; \
                     acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n"
                )),
                "text/turtle",
            )
            .await
            .unwrap();
        for p in [
            "/docs/a.txt",
            "/docs/sub/b.txt",
            "/docsx/c.txt",
            "/my%20dir/d.txt",
            "/other/e.txt",
        ] {
            storage
                .put(p, Bytes::from_static(b"data"), "text/plain")
                .await
                .unwrap();
        }
        Self {
            storage,
            base,
            linked: None,
            secret: hex::encode(key.to_bytes()),
            owner,
        }
    }

    async fn set_acl(&self, key: &str, turtle: &str) {
        self.storage
            .put(
                key,
                Bytes::from(format!("@prefix acl: <{ACL}> .\n@prefix foaf: <http://xmlns.com/foaf/0.1/> .\n{turtle}")),
                "text/turtle",
            )
            .await
            .unwrap();
    }

    fn state(&self) -> AppState {
        let mut state = AppState::new(self.storage.clone());
        state.public_base_url = self.base.map(str::to_owned);
        if let Some(w) = &self.linked {
            state.cross_identity = Some(Arc::new(Link(w.clone())));
        }
        state
    }

    /// Status of `GET path` with the given `Host`, anonymous or as the owner.
    async fn get(&self, path: &str, host: &str, as_owner: bool) -> u16 {
        let app = test::init_service(build_app(self.state())).await;
        let mut req = test::TestRequest::default()
            .method(Method::GET)
            .uri(path)
            .insert_header(("host", host));
        if as_owner {
            let url = format!(
                "{}{}",
                self.base.map_or(format!("http://{host}"), str::to_owned),
                path
            );
            // A distinct timestamp per call: the NIP-98 event id is single-use.
            static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 30;
            let token = nip98::mint_with_payload(&url, "GET", None, &self.secret, now).unwrap();
            req = req.insert_header(("authorization", nip98::authorization_header(&token)));
        }
        test::call_service(&app, req.to_request())
            .await
            .status()
            .as_u16()
    }
}

fn public_read(target: &str) -> String {
    format!(
        "<#r> a acl:Authorization ; acl:agentClass foaf:Agent ; acl:accessTo <{target}> ; \
         acl:default <{target}> ; acl:mode acl:Read .\n"
    )
}

#[actix_web::test]
async fn an_absolute_iri_on_the_configured_origin_grants() {
    let pod = Pod::new(Some(BASE)).await;
    pod.set_acl("/docs.acl", &public_read("https://pod.example/docs/"))
        .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 200);
    assert_eq!(pod.get("/docs/sub/b.txt", "pod.example", false).await, 200);
    // Control: the rule covers /docs/ and nothing else.
    assert_eq!(pod.get("/docsx/c.txt", "pod.example", false).await, 401);
    assert_eq!(pod.get("/other/e.txt", "pod.example", false).await, 401);
    // Default port and host case are the same origin.
    pod.set_acl("/docs.acl", &public_read("https://POD.example:443/docs/"))
        .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 200);
}

#[actix_web::test]
async fn another_origin_never_grants_even_with_a_matching_path() {
    let pod = Pod::new(Some(BASE)).await;
    for target in [
        "https://other.example/docs/",
        "https://pod.example.evil.example/docs/",
        "https://evil.example/pod.example/docs/",
        "https://pod.example@evil.example/docs/",
        "https://xpod.example/docs/",
        "https://pod.example:8443/docs/",
        "https://pod.example:80/docs/",
        "http://pod.example/docs/",
        "//evil.example/docs/",
        "https://pod.example/DOCS/",
        "https://pod.example/docs%2Fsub/",
        "https://pod.example/docs/?x=1",
        "https://pod.example/docs/#f",
        "https://user@pod.example/docs/",
    ] {
        pod.set_acl("/docs.acl", &public_read(target)).await;
        for path in ["/docs/a.txt", "/docs/sub/b.txt"] {
            assert_eq!(
                pod.get(path, "pod.example", false).await,
                401,
                "{target} must not grant {path}"
            );
        }
    }
}

#[actix_web::test]
async fn percent_encoded_targets_match_their_decoded_resource() {
    let pod = Pod::new(Some(BASE)).await;
    pod.set_acl(
        "/my%20dir.acl",
        &public_read("https://pod.example/my%20dir/"),
    )
    .await;
    assert_eq!(pod.get("/my%20dir/d.txt", "pod.example", false).await, 200);
}

#[actix_web::test]
async fn without_a_configured_origin_absolute_targets_still_deny() {
    let pod = Pod::new(None).await;
    pod.set_acl("/docs.acl", &public_read("https://pod.example/docs/"))
        .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 401);
    // A request Host never supplies the origin.
    assert_eq!(pod.get("/docs/a.txt", "other.example", false).await, 401);
    // Path form still works, as before.
    pod.set_acl("/docs.acl", &public_read("/docs/")).await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 200);
}

#[actix_web::test]
async fn a_hostile_host_header_does_not_move_the_origin() {
    let pod = Pod::new(Some(BASE)).await;
    pod.set_acl("/docs.acl", &public_read("https://evil.example/docs/"))
        .await;
    // The ACL names the attacker's origin; sending that Host must not make it ours.
    assert_eq!(pod.get("/docs/a.txt", "evil.example", false).await, 401);
}

#[actix_web::test]
async fn relative_targets_resolve_against_the_acl_document() {
    let pod = Pod::new(Some(BASE)).await;
    // ACL /docs/a.txt.acl: `./a.txt` and `a.txt` name /docs/a.txt.
    for target in ["./a.txt", "a.txt"] {
        pod.set_acl("/docs/a.txt.acl", &public_read(target)).await;
        assert_eq!(
            pod.get("/docs/a.txt", "pod.example", false).await,
            200,
            "{target}"
        );
    }
    // `../other/e.txt` from /docs/a.txt.acl names /other/e.txt, not /docs/a.txt.
    pod.set_acl("/docs/a.txt.acl", &public_read("../other/e.txt"))
        .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 401);
}

#[actix_web::test]
async fn a_relative_acl_agent_resolves_against_the_acl_document() {
    let mut pod = Pod::new(Some(BASE)).await;
    pod.linked = Some("https://pod.example/alice/profile/card#me".into());
    let owner = pod.owner.clone();
    let rule = |agent: &str| {
        format!(
            "<#r> a acl:Authorization ; acl:agent <{agent}> ; acl:accessTo </docs/a.txt> ; acl:mode acl:Read .\n\
             <#o> a acl:Authorization ; acl:agent <{owner}> ; acl:accessTo </docs/a.txt> ; acl:mode acl:Read, acl:Write, acl:Control .\n"
        )
    };
    // The caller is verifiably linked to the WebID `https://pod.example/alice/profile/card#me`.
    pod.set_acl("/docs/a.txt.acl", &rule("../alice/profile/card#me"))
        .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", false).await, 401);
    // As the linked caller, a relative agent that resolves to that WebID grants
    // (the owner's did:nostr identity is also valid, so remove it).
    pod.set_acl(
        "/docs/a.txt.acl",
        "<#r> a acl:Authorization ; acl:agent <../alice/profile/card#me> ; acl:accessTo </docs/a.txt> ; acl:mode acl:Read .\n",
    )
    .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", true).await, 200);
    // A relative agent that resolves to a different WebID does not.
    pod.set_acl(
        "/docs/a.txt.acl",
        "<#r> a acl:Authorization ; acl:agent <../bob/profile/card#me> ; acl:accessTo </docs/a.txt> ; acl:mode acl:Read .\n",
    )
    .await;
    assert_eq!(pod.get("/docs/a.txt", "pod.example", true).await, 403);
    // And with no configured origin the relative form matches nothing.
    let mut bare = Pod::new(None).await;
    bare.linked = pod.linked.clone();
    bare.set_acl(
        "/docs/a.txt.acl",
        "<#r> a acl:Authorization ; acl:agent <../alice/profile/card#me> ; acl:accessTo </docs/a.txt> ; acl:mode acl:Read .\n",
    )
    .await;
    assert_eq!(bare.get("/docs/a.txt", "pod.example", true).await, 403);
}
