//! `<prefix>/api/hosted/<hex>/<uuid>`: a podless agent's words, hosted by the
//! forge.
//!
//! Follows the JSS `forge` `apiHosted` contract (cited by name only): `GET`
//! is public (like a public pod resource), `PUT` / `PATCH` (edit) and
//! `DELETE` (removal) are **author only**, meaning the same `did:nostr`
//! identity that wrote the body. An edit only ever changes `body` (and stamps
//! `edited`); every other field of the stored document is kept, so a signed
//! request cannot rewrite authorship or the `hosted` flag.

use serde_json::{json, Value};

use crate::api::{api_err, json_resp, read_json_body, unauthorised, JSON_BODY_CAP};
use crate::error::ForgeError;
use crate::hosted::HostedStore;
use crate::ownership::ForgeAgent;
use crate::request::{ForgeRequest, ForgeResponse};
use crate::ForgeService;
use solid_pod_rs::did_nostr_types::is_valid_hex_pubkey;

/// Largest hosted body, in bytes (JSS `ISSUE_BODY_CAP`).
pub const HOSTED_BODY_CAP: usize = 64 * 1024;

/// `Date#toISOString` for unix seconds (`1970-01-01T00:00:00.000Z`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::hosted_edit::iso8601;
/// assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
/// assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20.000Z");
/// assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00.000Z");
/// ```
#[must_use]
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (proleptic Gregorian), H. Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The document stored for a hosted issue or comment (JSS `ForgeIssue` /
/// `ForgeComment`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn hosted_doc(
    kind: &str,
    owner: &str,
    repo: &str,
    issue: Option<u64>,
    title: Option<&str>,
    body: &str,
    author: &str,
    now: u64,
) -> Value {
    let mut doc = json!({
        "type": kind,
        "repo": format!("{owner}/{repo}"),
        "body": body,
        "published": iso8601(now),
        "author": author,
        "hosted": true,
    });
    if let Some(n) = issue {
        doc["issue"] = json!(n);
    }
    if let Some(t) = title {
        doc["title"] = json!(t);
    }
    doc
}

impl ForgeService {
    /// Public URL of a `hosted:` ref: `<origin><prefix>/api/hosted/<hex>/<id>`
    /// (anything that is not a `hosted:` ref is returned unchanged).
    pub(crate) fn hosted_public_url(&self, req: &ForgeRequest, rref: &str) -> String {
        match HostedStore::parse_ref(rref) {
            Some((hex, id)) if rref.starts_with(crate::hosted::REF_SCHEME) => format!(
                "{}{}/api/hosted/{hex}/{id}",
                self.origin_of(req),
                self.prefix()
            ),
            _ => rref.to_string(),
        }
    }

    /// `GET|PUT|PATCH|DELETE /api/hosted/<hex>/<uuid>` (JSS `apiHosted`).
    pub(crate) async fn h_api_hosted(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        hex: &str,
        id: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if !is_valid_hex_pubkey(hex)
            || HostedStore::parse_ref(&format!("hosted:{hex}/{id}")).is_none()
        {
            return Ok(api_err(404, "not found"));
        }
        let m = req.method.to_ascii_uppercase();
        let is_author = matches!(agent, ForgeAgent::Nostr { pubkey_hex } if pubkey_hex == hex);
        match m.as_str() {
            "GET" | "HEAD" => {
                if self.cfg.private_repos {
                    if matches!(agent, ForgeAgent::Anonymous) {
                        return Ok(unauthorised());
                    }
                    // The UUID is not a credential: under `private_repos` only
                    // the author of a hosted body may read it back over HTTP
                    // (security review L6). Pages render bodies server-side.
                    if !is_author {
                        return Ok(api_err(403, "private forge"));
                    }
                }
                match self
                    .hosted
                    .read(hex, id, self.cfg.max_body_bytes.max(HOSTED_BODY_CAP))
                    .await?
                {
                    Some(bytes) => Ok(ForgeResponse {
                        status: 200,
                        headers: vec![
                            (
                                "content-type".into(),
                                "application/json; charset=utf-8".into(),
                            ),
                            ("x-content-type-options".into(), "nosniff".into()),
                            ("access-control-allow-origin".into(), "*".into()),
                        ],
                        body: bytes::Bytes::from(bytes),
                    }),
                    None => Ok(api_err(404, "not found")),
                }
            }
            "PUT" | "PATCH" => {
                let incoming = if req.raw_body.len() <= JSON_BODY_CAP {
                    read_json_body(req)
                } else {
                    None
                };
                if matches!(agent, ForgeAgent::Anonymous) {
                    return Ok(unauthorised());
                }
                if !is_author {
                    return Ok(api_err(403, "only the author may edit hosted content"));
                }
                let Some(existing) = self.hosted.read(hex, id, JSON_BODY_CAP).await? else {
                    return Ok(api_err(404, "not found"));
                };
                let Some(body) = incoming
                    .as_ref()
                    .and_then(|m| m.get("body"))
                    .and_then(Value::as_str)
                else {
                    return Ok(api_err(400, "body (string) required"));
                };
                if body.len() > HOSTED_BODY_CAP {
                    return Ok(api_err(413, "body too large"));
                }
                // Only `body` (and the `edited` stamp) change. A legacy bare
                // body (not a JSON object) is upgraded to a document that
                // records the author from the verified identity.
                let mut doc = match serde_json::from_slice::<Value>(&existing) {
                    Ok(v @ Value::Object(_)) => v,
                    _ => hosted_doc(
                        "ForgeComment",
                        "",
                        "",
                        None,
                        None,
                        "",
                        &agent.author_id(),
                        crate::now_secs(),
                    ),
                };
                doc["body"] = json!(body);
                doc["edited"] = json!(iso8601(crate::now_secs()));
                self.hosted
                    .replace(hex, id, &serde_json::to_vec(&doc)?)
                    .await?;
                tracing::info!("forge: hosted content {hex}/{id} edited by its author");
                Ok(json_resp(200, &json!({"edited": true})))
            }
            "DELETE" => {
                if matches!(agent, ForgeAgent::Anonymous) {
                    return Ok(unauthorised());
                }
                if !is_author {
                    return Ok(api_err(403, "only the author may delete hosted content"));
                }
                if !self.hosted.delete(hex, id).await? {
                    return Ok(api_err(404, "not found"));
                }
                tracing::info!("forge: hosted content {hex}/{id} deleted by its author");
                Ok(json_resp(200, &json!({"deleted": true})))
            }
            _ => Ok(api_err(405, "method not allowed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::rq;
    use crate::ForgeConfig;

    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn nostr(h: &str) -> ForgeAgent {
        ForgeAgent::Nostr {
            pubkey_hex: h.into(),
        }
    }

    async fn seed(svc: &ForgeService) -> (String, String) {
        let rref = svc
            .hosted
            .write_doc(
                HEX_A,
                &hosted_doc(
                    "ForgeIssue",
                    "a",
                    "nrepo",
                    Some(1),
                    Some("t"),
                    "signed with **schnorr**",
                    &format!("did:nostr:{HEX_A}"),
                    10,
                ),
            )
            .await
            .unwrap();
        HostedStore::parse_ref(&rref).unwrap()
    }

    async fn call(
        svc: &ForgeService,
        m: &str,
        hex: &str,
        id: &str,
        body: &str,
        a: ForgeAgent,
    ) -> ForgeResponse {
        svc.handle(rq(m, &format!("/forge/api/hosted/{hex}/{id}"), "", body), a)
            .await
            .unwrap()
    }

    fn svc() -> (tempfile::TempDir, ForgeService) {
        let td = tempfile::TempDir::new().unwrap();
        let s = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
        (td, s)
    }

    // JSS "another agent cannot edit someone else's hosted content (403)"
    #[tokio::test]
    async fn other_agents_cannot_edit() {
        let (_td, s) = svc();
        let (h, id) = seed(&s).await;
        let r = call(
            &s,
            "PUT",
            &h,
            &id,
            r#"{"body":"not my words"}"#,
            nostr(HEX_B),
        )
        .await;
        assert_eq!(r.status, 403);
        let r = call(
            &s,
            "PATCH",
            &h,
            &id,
            r#"{"body":"x"}"#,
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(r.status, 401);
        // a pod agent is not the did:nostr author either
        let pod = ForgeAgent::Pod {
            webid: "https://p/x#me".into(),
            username: HEX_A.into(),
        };
        assert_eq!(
            call(&s, "PATCH", &h, &id, r#"{"body":"x"}"#, pod)
                .await
                .status,
            403
        );
        let doc: Value = serde_json::from_slice(
            &call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .body,
        )
        .unwrap();
        assert!(
            doc["body"].as_str().unwrap().contains("**schnorr**"),
            "original untouched"
        );
    }

    // JSS "the author edits their hosted content -> only body changes, edited stamp added"
    #[tokio::test]
    async fn author_edit_changes_only_body() {
        let (_td, s) = svc();
        let (h, id) = seed(&s).await;
        for m in ["PUT", "PATCH"] {
            let body = json!({"body": format!("edited via {m}"), "author": format!("did:nostr:{HEX_B}"), "hosted": false}).to_string();
            let r = call(&s, m, &h, &id, &body, nostr(HEX_A)).await;
            assert_eq!(r.status, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&r.body).unwrap()["edited"],
                true
            );
            let doc: Value = serde_json::from_slice(
                &call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                    .await
                    .body,
            )
            .unwrap();
            assert_eq!(doc["body"], format!("edited via {m}"));
            assert_eq!(
                doc["author"],
                format!("did:nostr:{HEX_A}"),
                "author NOT rewritten"
            );
            assert_eq!(doc["hosted"], true, "hosted flag NOT rewritten");
            assert!(doc["edited"].as_str().unwrap().ends_with('Z'));
        }
        // validation
        assert_eq!(
            call(&s, "PUT", &h, &id, r#"{"nope":1}"#, nostr(HEX_A))
                .await
                .status,
            400
        );
        assert_eq!(
            call(&s, "PUT", &h, &id, "junk", nostr(HEX_A)).await.status,
            400
        );
        let big = json!({"body": "x".repeat(HOSTED_BODY_CAP + 1)}).to_string();
        assert_eq!(
            call(&s, "PUT", &h, &id, &big, nostr(HEX_A)).await.status,
            413
        );
        let missing = "11111111-1111-4111-8111-111111111111";
        assert_eq!(
            call(&s, "PUT", &h, missing, r#"{"body":"x"}"#, nostr(HEX_A))
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn legacy_raw_bodies_are_upgraded_on_edit() {
        let (_td, s) = svc();
        let rref = s.hosted.write(HEX_A, b"legacy words").await.unwrap();
        let (h, id) = HostedStore::parse_ref(&rref).unwrap();
        let r = call(
            &s,
            "PATCH",
            &h,
            &id,
            r#"{"body":"new words"}"#,
            nostr(HEX_A),
        )
        .await;
        assert_eq!(r.status, 200);
        let doc: Value = serde_json::from_slice(
            &call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .body,
        )
        .unwrap();
        assert_eq!(doc["body"], "new words");
        assert_eq!(doc["author"], format!("did:nostr:{HEX_A}"));
    }

    // JSS "another agent cannot delete ... (403)" and "the author deletes"
    #[tokio::test]
    async fn delete_is_author_only_and_returns_200_json() {
        let (_td, s) = svc();
        let (h, id) = seed(&s).await;
        assert_eq!(
            call(&s, "DELETE", &h, &id, "", nostr(HEX_B)).await.status,
            403
        );
        assert_eq!(
            call(&s, "DELETE", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .status,
            401
        );
        assert_eq!(
            call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .status,
            200,
            "still there"
        );
        let r = call(&s, "DELETE", &h, &id, "", nostr(HEX_A)).await;
        assert_eq!(r.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&r.body).unwrap()["deleted"],
            true
        );
        assert_eq!(
            call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .status,
            404,
            "the words are gone"
        );
        assert_eq!(
            call(&s, "DELETE", &h, &id, "", nostr(HEX_A)).await.status,
            404
        );
    }

    #[tokio::test]
    async fn bad_segments_and_methods() {
        let (_td, s) = svc();
        assert_eq!(
            call(&s, "GET", "short", "x", "", ForgeAgent::Anonymous)
                .await
                .status,
            404
        );
        assert_eq!(
            call(&s, "GET", HEX_A, "not a uuid!", "", ForgeAgent::Anonymous)
                .await
                .status,
            404
        );
        let (h, id) = seed(&s).await;
        assert_eq!(
            call(&s, "POST", &h, &id, "", nostr(HEX_A)).await.status,
            405
        );
    }

    #[tokio::test]
    async fn private_forge_hosted_get_needs_an_agent() {
        let td = tempfile::TempDir::new().unwrap();
        let cfg = ForgeConfig {
            private_repos: true,
            ..Default::default()
        };
        let s = ForgeService::new(cfg, td.path()).unwrap();
        let (h, id) = seed(&s).await;
        assert_eq!(
            call(&s, "GET", &h, &id, "", ForgeAgent::Anonymous)
                .await
                .status,
            401
        );
        // L6: another authenticated agent holding the UUID is refused; only
        // the author reads the body back over HTTP.
        assert_eq!(call(&s, "GET", &h, &id, "", nostr(HEX_B)).await.status, 403);
        assert_eq!(call(&s, "GET", &h, &id, "", nostr(HEX_A)).await.status, 200);
    }

    #[test]
    fn public_url_uses_base_url_override() {
        let td = tempfile::TempDir::new().unwrap();
        let cfg = ForgeConfig {
            base_url: Some("https://pub.example".into()),
            ..Default::default()
        };
        let s = ForgeService::new(cfg, td.path()).unwrap();
        let id = "0b9f3f0e-1111-4222-8333-444455556666";
        let r = rq("GET", "/forge/x", "", "");
        assert_eq!(
            s.hosted_public_url(&r, &format!("hosted:{HEX_A}/{id}")),
            format!("https://pub.example/forge/api/hosted/{HEX_A}/{id}")
        );
        assert_eq!(
            s.hosted_public_url(&r, "https://pod/x.jsonld"),
            "https://pod/x.jsonld"
        );
    }
}
