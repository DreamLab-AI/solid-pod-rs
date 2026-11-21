//! The ACL fixtures JSS 0.0.224 ships for #631 (`test/wac.test.js`, the
//! "JSON-LD expansion" and "ACL PUT guard" suites), written out as Rust cases
//! against this evaluator and server (checklist row 268). Each case names the
//! JSS test it transcribes. The behaviour is read from those tests; nothing
//! is copied.
//!
//! Where this server answers differently the case asserts OUR status and says
//! why (rows 266 and 267): an ACL the writer could not keep Control through is
//! a 409 state conflict here, where JSS answers 400.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{http::Method, test};
use bytes::Bytes;
use serde_json::{json, Value};
use solid_pod_rs::auth::nip98;
use solid_pod_rs::storage::{memory::MemoryBackend, Storage};
use solid_pod_rs::wac::{parse_jsonld_acl_at, parse_turtle_acl};
use solid_pod_rs_server::{build_app, AppState};

const ACL: &str = "http://www.w3.org/ns/auth/acl#";
const WEBID: &str = "http://127.0.0.1:8732/me/profile/card.jsonld#me";
const TARGET: &str = "http://127.0.0.1:8732/me/public/doc.ttl";
const ACL_PATH: &str = "/me/public/doc.ttl.acl";

// ---------------------------------------------------------------- parser (6)

/// This evaluator's canonical AST abbreviates the two vocabularies it knows
/// (`acl:Read`, `foaf:Agent`); JSS normalises to full IRIs. Compare in full.
fn full(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("acl:") {
        format!("{ACL}{rest}")
    } else if let Some(rest) = s.strip_prefix("foaf:") {
        format!("http://xmlns.com/foaf/0.1/{rest}")
    } else {
        s.to_string()
    }
}

fn ids(v: &Value) -> Vec<String> {
    let out: Vec<String> = match v {
        Value::Null => vec![],
        Value::Array(a) => a
            .iter()
            .map(|x| x["@id"].as_str().unwrap().to_string())
            .collect(),
        one => vec![one["@id"].as_str().unwrap().to_string()],
    };
    let mut out: Vec<String> = out.iter().map(|s| full(s)).collect();
    out.sort();
    out
}

fn expect_owner(doc: &solid_pod_rs::wac::AclDocument) {
    let v = serde_json::to_value(doc).unwrap();
    let graph = v["@graph"].as_array().expect("a @graph");
    assert_eq!(graph.len(), 1, "one authorization, got {v}");
    let a = &graph[0];
    assert_eq!(ids(&a["acl:agent"]), vec![WEBID.to_string()]);
    assert_eq!(ids(&a["acl:accessTo"]), vec![TARGET.to_string()]);
    let mut modes = vec![
        format!("{ACL}Control"),
        format!("{ACL}Read"),
        format!("{ACL}Write"),
    ];
    modes.sort();
    assert_eq!(ids(&a["acl:mode"]), modes);
}

fn parse(v: &Value) -> solid_pod_rs::wac::AclDocument {
    parse_jsonld_acl_at(v.to_string().as_bytes(), ACL_PATH).unwrap()
}

/// JSS: "reads an ACL in expanded form (full IRIs, no @context)".
#[actix_web::test]
async fn reads_an_acl_in_expanded_form() {
    expect_owner(&parse(&json!([{
        "@id": "#owner",
        "@type": [format!("{ACL}Authorization")],
        format!("{ACL}agent"): [{"@id": WEBID}],
        format!("{ACL}accessTo"): [{"@id": TARGET}],
        format!("{ACL}mode"): [{"@id": format!("{ACL}Read")}, {"@id": format!("{ACL}Write")}, {"@id": format!("{ACL}Control")}]
    }])));
}

/// JSS: "reads an ACL that uses a different prefix than acl:".
#[actix_web::test]
async fn reads_an_acl_with_a_different_prefix() {
    expect_owner(&parse(&json!({
        "@context": {"wac": ACL},
        "@graph": [{
            "@id": "#owner", "@type": "wac:Authorization",
            "wac:agent": {"@id": WEBID}, "wac:accessTo": {"@id": TARGET},
            "wac:mode": [{"@id": "wac:Read"}, {"@id": "wac:Write"}, {"@id": "wac:Control"}]
        }]
    })));
}

/// JSS: "reads an ACL whose @context is an array with a remote entry". JSS
/// ignores the remote entry and reads the inline one. This server never
/// fetches a remote context and treats such a document as unreadable, which
/// denies (row 265): stricter, because a remote context could redefine any
/// term and is a fetch the ACL's author, not the pod owner, controls. The
/// same ACL without the remote entry is read.
#[actix_web::test]
async fn a_context_array_with_a_remote_entry_is_unreadable_here() {
    let with = |ctx: Value| {
        json!({"@context": ctx, "@graph": [{
            "@id": "#owner", "@type": "auth:Authorization",
            "auth:agent": {"@id": WEBID}, "auth:accessTo": {"@id": TARGET},
            "auth:mode": [{"@id": "auth:Read"}, {"@id": "auth:Write"}, {"@id": "auth:Control"}]
        }]})
    };
    expect_owner(&parse(&with(json!([{"auth": ACL}]))));
    let remote = with(json!(["https://www.w3.org/ns/solid/context", {"auth": ACL}]));
    assert!(
        parse_jsonld_acl_at(remote.to_string().as_bytes(), ACL_PATH).is_err(),
        "a remote @context is never fetched; the ACL is unreadable"
    );
}

/// JSS: "reads an ACL that relies on @vocab and term definitions". JSS reads
/// the bare modes (`"mode": ["Read", ...]` under `"@type": "@id"`) as the ACL
/// vocabulary. By the JSON-LD algorithm an `@id`-coerced value is resolved
/// against the document, not `@vocab`, so here `"Read"` is `/me/public/Read`,
/// not `acl:Read`, and the rule grants nothing. That fails closed, and this
/// server keeps it: reading a bare word as a mode would grant on a
/// document-relative IRI that happens to share a name. The agent and target
/// are read exactly as JSS reads them, and the same document with
/// `"@type": "@vocab"` on `mode` (the correct JSON-LD spelling) grants.
#[actix_web::test]
async fn vocab_and_term_definitions_read_but_a_bare_mode_under_id_coercion_grants_nothing() {
    let doc = |mode_type: &str| {
        parse(&json!({
            "@context": {
                "@vocab": ACL,
                "agent": {"@id": format!("{ACL}agent"), "@type": "@id"},
                "accessTo": {"@id": format!("{ACL}accessTo"), "@type": "@id"},
                "mode": {"@id": format!("{ACL}mode"), "@type": mode_type}
            },
            "@id": "#owner", "@type": "Authorization",
            "agent": WEBID, "accessTo": TARGET, "mode": ["Read", "Write", "Control"]
        }))
    };
    expect_owner(&doc("@vocab"));
    let v = serde_json::to_value(doc("@id")).unwrap();
    let modes = ids(&v["@graph"][0]["acl:mode"]);
    assert!(
        !modes.contains(&format!("{ACL}Read")) && !modes.contains(&format!("{ACL}Control")),
        "a document-relative IRI is not a mode: {modes:?}"
    );
    assert_eq!(ids(&v["@graph"][0]["acl:agent"]), vec![WEBID.to_string()]);
}

/// JSS: "reads a Turtle ACL that declares a non-acl prefix".
#[actix_web::test]
async fn reads_a_turtle_acl_with_a_non_acl_prefix() {
    let ttl = format!(
        "@prefix wac: <{ACL}> .\n<#owner> a wac:Authorization ;\n  wac:agent <{WEBID}> ;\n  \
         wac:accessTo <{TARGET}> ;\n  wac:mode wac:Read, wac:Write, wac:Control ."
    );
    expect_owner(&parse_turtle_acl(&ttl).unwrap());
}

/// JSS: "normalises agent classes to full IRIs".
#[actix_web::test]
async fn normalises_agent_classes_to_full_iris() {
    let doc = parse(&json!({
        "@context": {"wac": ACL, "people": "http://xmlns.com/foaf/0.1/"},
        "@id": "#public", "@type": "wac:Authorization",
        "wac:agentClass": {"@id": "people:Agent"},
        "wac:accessTo": {"@id": TARGET}, "wac:mode": {"@id": "wac:Read"}
    }));
    let v = serde_json::to_value(&doc).unwrap();
    assert_eq!(
        ids(&v["@graph"][0]["acl:agentClass"]),
        vec!["http://xmlns.com/foaf/0.1/Agent".to_string()]
    );
}

// ------------------------------------------------------------ PUT guard (6)

struct Owner {
    storage: Arc<MemoryBackend>,
    secret: String,
    id: String,
    clock: AtomicU64,
}

const RES: &str = "/aclguard/public/exp.jsonld";
const RES_ACL: &str = "/aclguard/public/exp.jsonld.acl";

impl Owner {
    async fn new() -> Self {
        static KEY: AtomicU64 = AtomicU64::new(100);
        let mut bytes = [0x51; 32];
        bytes[0] = KEY.fetch_add(1, Ordering::Relaxed) as u8;
        let key = k256::schnorr::SigningKey::from_slice(&bytes).unwrap();
        let o = Self {
            storage: Arc::new(MemoryBackend::new()),
            secret: hex::encode(key.to_bytes()),
            id: format!("did:nostr:{}", hex::encode(key.verifying_key().to_bytes())),
            clock: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        };
        let root = format!(
            "@prefix acl: <{ACL}> .\n<#o> a acl:Authorization ; acl:agent <{}> ;\n \
             acl:accessTo </> ; acl:default </> ; acl:mode acl:Read, acl:Write, acl:Control .\n",
            o.id
        );
        o.storage
            .put("/.acl", Bytes::from(root), "text/turtle")
            .await
            .unwrap();
        o
    }

    async fn call(&self, method: &str, path: &str, ct: &str, body: &str, auth: bool) -> u16 {
        let app = test::init_service(build_app(AppState::new(self.storage.clone()))).await;
        let mut req = test::TestRequest::default()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(path)
            .insert_header(("host", "pod.example"))
            .insert_header(("content-type", ct))
            .set_payload(body.to_owned());
        if auth {
            let now = self.clock.fetch_add(1, Ordering::Relaxed);
            let token = nip98::mint_with_payload(
                &format!("http://pod.example{path}"),
                method,
                Some(body.as_bytes()),
                &self.secret,
                now,
            )
            .unwrap();
            req = req.insert_header(("authorization", nip98::authorization_header(&token)));
        }
        test::call_service(&app, req.to_request())
            .await
            .status()
            .as_u16()
    }

    fn owner_acl(&self) -> Value {
        json!([{
            "@id": "#owner",
            "@type": [format!("{ACL}Authorization")],
            format!("{ACL}agent"): [{"@id": self.id}],
            format!("{ACL}accessTo"): [{"@id": RES}],
            format!("{ACL}mode"): [{"@id": format!("{ACL}Read")}, {"@id": format!("{ACL}Write")}, {"@id": format!("{ACL}Control")}]
        }])
    }

    /// PUT the resource and its expanded-form owner ACL (the first JSS case).
    async fn with_acl(&self) {
        let put = self
            .call("PUT", RES, "application/ld+json", r#"{"@id":""}"#, true)
            .await;
        assert!(put == 201 || put == 204, "PUT resource: {put}");
        let acl = self.owner_acl().to_string();
        let st = self
            .call("PUT", RES_ACL, "application/ld+json", &acl, true)
            .await;
        assert!(st == 201 || st == 204, "PUT acl: {st}");
    }

    async fn still_usable(&self) {
        assert_eq!(self.call("GET", RES, "", "", true).await, 200);
    }
}

/// JSS: "accepts an expanded-form ACL and the owner keeps access".
#[actix_web::test]
async fn accepts_an_expanded_form_acl_and_the_owner_keeps_access() {
    let o = Owner::new().await;
    o.with_acl().await;
    assert_eq!(o.call("GET", RES, "", "", true).await, 200);
    assert_eq!(o.call("GET", RES_ACL, "", "", true).await, 200);
    // The expanded ACL grants nothing to the public.
    assert_eq!(o.call("GET", RES, "", "", false).await, 401);
}

/// JSS: "rejects an ACL document that yields no authorizations" (400, the
/// previous ACL stays in place). 409 here: the document is well-formed but
/// leaves its author without Control (row 267).
#[actix_web::test]
async fn rejects_an_acl_that_yields_no_authorizations() {
    let o = Owner::new().await;
    o.with_acl().await;
    let before = o.storage.get(RES_ACL).await.unwrap().0;
    let body = json!({"@context": {"acl": ACL}, "@id": "#owner", "acl:agent": {"@id": "x"}});
    let st = o
        .call(
            "PUT",
            RES_ACL,
            "application/ld+json",
            &body.to_string(),
            true,
        )
        .await;
    assert_eq!(st, 409);
    assert_eq!(o.storage.get(RES_ACL).await.unwrap().0, before);
    o.still_usable().await;
}

/// JSS: "rejects an ACL whose authorizations name an agent but no mode" (400).
/// Here the document parses and would lock its author out, so it is a 409
/// state conflict (row 267: the writer must keep Control). Refused either way,
/// nothing stored.
#[actix_web::test]
async fn rejects_an_acl_with_an_agent_but_no_mode() {
    let o = Owner::new().await;
    o.with_acl().await;
    let before = o.storage.get(RES_ACL).await.unwrap().0;
    let body = json!({"@context": {"acl": ACL}, "@id": "#owner", "@type": "acl:Authorization",
        "acl:agent": {"@id": o.id}, "acl:accessTo": {"@id": RES}});
    let st = o
        .call(
            "PUT",
            RES_ACL,
            "application/ld+json",
            &body.to_string(),
            true,
        )
        .await;
    assert!(st == 400 || st == 409, "{st}");
    assert_eq!(st, 409, "ours is a conflict, not a syntax error");
    assert_eq!(o.storage.get(RES_ACL).await.unwrap().0, before);
    o.still_usable().await;
}

/// JSS: "rejects an ACL whose authorizations name a mode but no agent" (400);
/// 409 here for the same reason.
#[actix_web::test]
async fn rejects_an_acl_with_a_mode_but_no_agent() {
    let o = Owner::new().await;
    o.with_acl().await;
    let before = o.storage.get(RES_ACL).await.unwrap().0;
    let body = json!({"@context": {"acl": ACL}, "@id": "#owner", "@type": "acl:Authorization",
        "acl:accessTo": {"@id": RES}, "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Control"}]});
    let st = o
        .call(
            "PUT",
            RES_ACL,
            "application/ld+json",
            &body.to_string(),
            true,
        )
        .await;
    assert_eq!(st, 409);
    assert_eq!(o.storage.get(RES_ACL).await.unwrap().0, before);
    o.still_usable().await;
}

/// JSS: "rejects a PATCH that would leave the ACL granting nobody access" (409).
#[actix_web::test]
async fn rejects_a_patch_that_would_leave_the_acl_granting_nobody_access() {
    let o = Owner::new().await;
    o.with_acl().await;
    let single = json!({
        "@id": "#owner", "@type": format!("{ACL}Authorization"),
        format!("{ACL}agent"): {"@id": o.id},
        format!("{ACL}accessTo"): {"@id": RES},
        format!("{ACL}mode"): [{"@id": format!("{ACL}Read")}, {"@id": format!("{ACL}Write")}, {"@id": format!("{ACL}Control")}]
    });
    let st = o
        .call(
            "PUT",
            RES_ACL,
            "application/ld+json",
            &single.to_string(),
            true,
        )
        .await;
    assert!(st == 201 || st == 204, "{st}");
    let before = o.storage.get(RES_ACL).await.unwrap().0;
    let patch = format!(
        "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix acl: <{ACL}>.\n\
         _:patch a solid:InsertDeletePatch;\n  solid:deletes {{ <#owner> acl:agent <{}> }}.\n",
        o.id
    );
    let st = o.call("PATCH", RES_ACL, "text/n3", &patch, true).await;
    assert_eq!(st, 409);
    assert_eq!(o.storage.get(RES_ACL).await.unwrap().0, before);
    o.still_usable().await;
}

/// JSS: "rejects an ACL body that is not valid JSON" (400).
#[actix_web::test]
async fn rejects_an_acl_body_that_is_not_valid_json() {
    let o = Owner::new().await;
    o.with_acl().await;
    let before = o.storage.get(RES_ACL).await.unwrap().0;
    let st = o
        .call("PUT", RES_ACL, "application/ld+json", "{not json", true)
        .await;
    assert_eq!(st, 400);
    assert_eq!(o.storage.get(RES_ACL).await.unwrap().0, before);
}
