//! The issues JSON API: list, thread, create, comment, close / reopen,
//! retitle and label assignment.
//!
//! Follows the JSS `forge` `apiIssuesHandler` family (`apiIssueList`,
//! `apiIssueGet`, `apiIssueCreate`, `apiIssueComment`, `apiIssueState`,
//! `apiIssueRetitle`), cited by name only.
//!
//! Moderation rule (JSS `mayModerate`): close, reopen, retitle and label
//! changes are index-only operations allowed to the **repo owner or the
//! issue's author**. Every spine write runs under the per-repo issue lock
//! ([`crate::locks`]); the lock is never held across the pod-body
//! verification fetch.
//!
//! Divergence from JSS: a *pod* agent must hand a `resourceUrl` pointer (the
//! body is PUT into its own pod by the client). JSS can also write the body
//! into the pod itself with a forwarded bearer; the Rust forge has no
//! loopback write, so that variant answers `422`. Podless `did:nostr` agents
//! post the body inline and the forge hosts it, exactly as in JSS.

use serde_json::{json, Value};

use crate::api::{api_err, json_resp, read_json_body, unauthorised};
use crate::bodies::{self, BodyOutcome};
use crate::error::ForgeError;
use crate::guard::ok_owner;
use crate::hosted_edit::hosted_doc;
use crate::labels::{effective_labels, resolve_labels, ItemKind};
use crate::markdown::{render_with, MdCtx};
use crate::ownership::ForgeAgent;
use crate::request::{percent_decode, ForgeRequest, ForgeResponse};
use crate::spine::issues::{
    load_issue_index, save_issue_index, IssueEntry, IssueState, ThreadPointer,
};
use crate::{gitmark, hosted::HostedStore, ForgeService};

/// Issues per page (JSS `ISSUES_PER_PAGE`).
pub const ISSUES_PER_PAGE: usize = 25;
/// Issue title cap in characters (JSS `ISSUE_TITLE_CAP`).
pub const ISSUE_TITLE_CAP: usize = 256;
/// Issue / comment body cap in bytes (JSS `ISSUE_BODY_CAP`).
pub const ISSUE_BODY_CAP: usize = 64 * 1024;

/// JSS `ISSUE_NUM_RE`: `^[1-9][0-9]{0,8}$`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::api_issues::parse_issue_number;
/// assert_eq!(parse_issue_number("42"), Some(42));
/// assert_eq!(parse_issue_number("0"), None);
/// assert_eq!(parse_issue_number("007"), None);
/// assert_eq!(parse_issue_number("1234567890"), None);
/// ```
#[must_use]
pub fn parse_issue_number(s: &str) -> Option<u64> {
    let ok =
        (1..=9).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0');
    if ok {
        s.parse().ok()
    } else {
        None
    }
}

/// Pod username (or hostname label) of a WebID, mirroring JSS
/// `ownerFromAgent` for non-`did:nostr` agents.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::api_issues::owner_from_webid;
/// assert_eq!(owner_from_webid("https://pod.example/casey/profile/card#me").as_deref(), Some("casey"));
/// assert_eq!(owner_from_webid("https://alice.pod.example/profile/card#me").as_deref(), Some("alice"));
/// assert_eq!(owner_from_webid("did:web:example.com"), None);
/// ```
#[must_use]
pub fn owner_from_webid(webid: &str) -> Option<String> {
    let rest = webid
        .strip_prefix("https://")
        .or_else(|| webid.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.rsplit('@').next().unwrap_or(host);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let name = if segs.len() >= 2 && segs[0] != "profile" {
        segs[0].to_string()
    } else {
        host.split(':')
            .next()
            .unwrap_or("")
            .split('.')
            .next()
            .unwrap_or("")
            .to_string()
    };
    (ok_owner(&name)).then_some(name)
}

/// `npub1…` (NIP-19) for a 64-hex public key.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::api_issues::npub_encode;
/// // BIP-173 / NIP-19 canonical vector
/// assert_eq!(
///     npub_encode("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d").as_deref(),
///     Some("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")
/// );
/// assert_eq!(npub_encode("nothex"), None);
/// ```
#[must_use]
pub fn npub_encode(hex_pub: &str) -> Option<String> {
    let bytes = hex::decode(hex_pub).ok().filter(|b| b.len() == 32)?;
    let hrp = bech32::Hrp::parse("npub").ok()?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).ok()
}

/// Additive author metadata for the JSON API (JSS `authorMeta`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::api_issues::author_meta;
/// let hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
/// let m = author_meta(&format!("did:nostr:{hex}"));
/// assert_eq!(m["kind"], "nostr");
/// assert_eq!(m["displayName"], "did:nostr:3bf0c63f…");
/// assert_eq!(m["npub"], "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6");
/// let w = author_meta("https://pod.example/casey/profile/card#me");
/// assert_eq!(w["kind"], "webid");
/// assert_eq!(w["displayName"], "casey");
/// ```
#[must_use]
pub fn author_meta(agent: &str) -> Value {
    if let Some(hex) = agent
        .strip_prefix("did:nostr:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    {
        return json!({
            "id": agent,
            "displayName": gitmark::did_short(hex),
            "npub": npub_encode(hex),
            "kind": "nostr",
        });
    }
    json!({
        "id": agent,
        "displayName": owner_from_webid(agent).unwrap_or_else(|| agent.to_string()),
        "kind": "webid",
    })
}

fn state_str(s: IssueState) -> &'static str {
    match s {
        IssueState::Open => "open",
        IssueState::Closed => "closed",
        IssueState::Merged => "merged",
    }
}

impl ForgeService {
    /// JSS `mayModerate`: the repo owner or the item's author.
    fn may_moderate(agent: &ForgeAgent, owner: &str, author: &str) -> bool {
        agent.owner() == Some(owner) || agent.author_id() == author
    }

    /// `/api/repos/<o>/<r>/issues[/…]` (JSS `apiIssuesHandler`).
    pub(crate) async fn h_api_issues(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        let m = req.method.to_ascii_uppercase();
        let read = m == "GET" || m == "HEAD";
        let Some(first) = tail.first() else {
            return match m.as_str() {
                "POST" => self.api_issue_create(req, agent, owner, repo).await,
                _ if read => self.api_issue_list(req, owner, repo).await,
                _ => Ok(api_err(405, "method not allowed")),
            };
        };
        let Some(number) = parse_issue_number(first) else {
            return Ok(api_err(404, "not found"));
        };
        match (tail.len(), tail.get(1).map(String::as_str)) {
            (1, _) if read => self.api_issue_get(req, owner, repo, number).await,
            (1, _) if m == "PATCH" => {
                self.api_issue_retitle(req, agent, owner, repo, number)
                    .await
            }
            (1, _) => Ok(api_err(405, "method not allowed")),
            (2, Some("labels")) if m == "PUT" => {
                self.put_item_labels(req, agent, owner, repo, number, ItemKind::Issue)
                    .await
            }
            (2, Some("labels")) => Ok(api_err(405, "method not allowed")),
            (2, Some("comments" | "close" | "reopen")) if m != "POST" => {
                Ok(api_err(405, "method not allowed"))
            }
            (2, Some("comments")) => {
                self.api_issue_comment(req, agent, owner, repo, number)
                    .await
            }
            (2, Some(verb @ ("close" | "reopen"))) => {
                let state = if verb == "close" {
                    IssueState::Closed
                } else {
                    IssueState::Open
                };
                self.api_issue_state(agent, owner, repo, number, state)
                    .await
            }
            _ => Ok(api_err(404, "not found")),
        }
    }

    async fn api_issue_list(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let mut all: Vec<&IssueEntry> = idx.issues.values().collect();
        all.sort_by_key(|i| std::cmp::Reverse(i.number));
        let open_count = all.iter().filter(|i| i.state == IssueState::Open).count();
        let state = if req.query_param("state").as_deref() == Some("closed") {
            IssueState::Closed
        } else {
            IssueState::Open
        };
        let label: Option<String> = req
            .query_param("label")
            .map(|l| percent_decode(&l).chars().take(50).collect::<String>())
            .filter(|l| !l.is_empty());
        let page = req
            .query_param("page")
            .and_then(|p| p.trim().parse::<i64>().ok())
            .unwrap_or(1)
            .clamp(1, 10000) as usize;
        let defs = effective_labels(&idx);
        let filtered: Vec<&&IssueEntry> = all
            .iter()
            .filter(|i| {
                i.state == state
                    && label
                        .as_ref()
                        .is_none_or(|l| i.labels.iter().any(|x| x == l))
            })
            .collect();
        let rows: Vec<Value> = filtered
            .iter()
            .skip((page - 1) * ISSUES_PER_PAGE)
            .take(ISSUES_PER_PAGE)
            .map(|i| {
                json!({
                    "number": i.number,
                    "title": i.title,
                    "state": state_str(i.state),
                    "author": i.author,
                    "authorInfo": author_meta(&i.author),
                    "createdAt": i.created_at,
                    "labels": resolve_labels(&i.labels, &defs),
                    "comments": i.thread.len().saturating_sub(1),
                })
            })
            .collect();
        Ok(json_resp(
            200,
            &json!({
                "state": state_str(state),
                "page": page,
                "perPage": ISSUES_PER_PAGE,
                "hasMore": filtered.len() > page * ISSUES_PER_PAGE,
                "openCount": open_count,
                "closedCount": all.len() - open_count,
                "issues": rows,
            }),
        ))
    }

    async fn api_issue_get(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        let idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let Some(issue) = idx.issues.get(&number) else {
            return Ok(api_err(404, "not found"));
        };
        let hosted: std::sync::Arc<dyn bodies::HostedReader> = self.hosted.clone();
        let rendered = bodies::render_thread(
            &issue.thread,
            self.loopback.clone(),
            Some(hosted),
            &self.cfg,
        )
        .await;
        let base = format!("{}/{owner}/{repo}", self.prefix());
        let ctx = MdCtx {
            raw_base: format!("{base}/raw/HEAD"),
            blob_base: format!("{base}/blob/HEAD"),
        };
        let thread: Vec<Value> = issue
            .thread
            .iter()
            .zip(rendered)
            .map(|(p, r)| {
                let (body, removed) = match &r.body {
                    BodyOutcome::Present(t) => (
                        Some(t.chars().take(ISSUE_BODY_CAP).collect::<String>()),
                        false,
                    ),
                    _ => (None, true),
                };
                json!({
                    "author": p.author,
                    "at": p.at,
                    "resourceUrl": self.hosted_public_url(req, &p.resource_url),
                    "hosted": p.hosted,
                    "body": body,
                    "removed": removed,
                    "authorInfo": author_meta(&p.author),
                    "html": body.as_deref().map(|b| render_with(b, &ctx)),
                })
            })
            .collect();
        Ok(json_resp(
            200,
            &json!({
                "number": issue.number,
                "title": issue.title,
                "state": state_str(issue.state),
                "author": issue.author,
                "authorInfo": author_meta(&issue.author),
                "createdAt": issue.created_at,
                "labels": resolve_labels(&issue.labels, &effective_labels(&idx)),
                "thread": thread,
            }),
        ))
    }

    /// Build the thread pointer for a create / comment call. Hosted ref for
    /// nostr agents, verified pod pointer for pod agents. `Err` carries the
    /// JSON error response to send.
    #[allow(clippy::too_many_arguments)]
    async fn api_pointer(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        kind: &str,
        issue: Option<u64>,
        title: Option<&str>,
        body: &str,
        resource_url: Option<&str>,
    ) -> Result<ThreadPointer, ForgeResponse> {
        let backend = |e: ForgeError| ForgeResponse::error(e.status_code(), e.to_string());
        match agent {
            ForgeAgent::Anonymous => Err(unauthorised()),
            ForgeAgent::Nostr { pubkey_hex } => {
                let doc = hosted_doc(
                    kind,
                    owner,
                    repo,
                    issue,
                    title,
                    body,
                    &agent.author_id(),
                    crate::now_secs(),
                );
                let rref = self
                    .hosted
                    .write_doc(pubkey_hex, &doc)
                    .await
                    .map_err(backend)?;
                Ok(ThreadPointer {
                    author: agent.author_id(),
                    resource_url: rref,
                    at: crate::now_secs(),
                    hosted: true,
                })
            }
            ForgeAgent::Pod { .. } => match resource_url.filter(|u| !u.is_empty()) {
                Some(url) => self
                    .verify_pod_pointer(req, agent, owner, repo, url)
                    .await
                    .map_err(backend),
                None => Err(api_err(
                    422,
                    "resourceUrl required: write the body into your own pod and pass its URL",
                )),
            },
        }
    }

    async fn api_issue_create(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let p = read_json_body(req);
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        let Some(p) = p else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let title = p.get("title").and_then(Value::as_str).map_or("", str::trim);
        let body = p.get("body").and_then(Value::as_str).unwrap_or("");
        let n = title.chars().count();
        if n == 0 || n > ISSUE_TITLE_CAP {
            return Ok(api_err(
                422,
                &format!("title required (1-{ISSUE_TITLE_CAP} chars)"),
            ));
        }
        if body.len() > ISSUE_BODY_CAP {
            return Ok(api_err(422, "body too large"));
        }
        // The next number is allocated under the lock; the hosted doc embeds
        // it, so peek, write, then re-check under the lock.
        let peek = load_issue_index(self.spine.as_ref(), owner, repo)
            .await?
            .next;
        let rurl = p.get("resourceUrl").and_then(Value::as_str);
        let pointer = match self
            .api_pointer(
                req,
                agent,
                owner,
                repo,
                "ForgeIssue",
                Some(peek),
                Some(title),
                body,
                rurl,
            )
            .await
        {
            Ok(ptr) => ptr,
            Err(resp) => return Ok(resp),
        };
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let number = idx.allocate(IssueEntry {
            number: 0,
            title: title.to_string(),
            state: IssueState::Open,
            author: agent.author_id(),
            created_at: crate::now_secs(),
            thread: vec![pointer.clone()],
            labels: Vec::new(),
        });
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        let mut out = json!({
            "number": number,
            "url": format!("{}/{owner}/{repo}/issues/{number}", self.prefix()),
            "resourceUrl": self.hosted_public_url(req, &pointer.resource_url),
        });
        if pointer.hosted {
            out["hosted"] = json!(true);
        }
        Ok(json_resp(201, &out))
    }

    async fn api_issue_comment(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        let p = read_json_body(req);
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        let Some(p) = p else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let body = p.get("body").and_then(Value::as_str).unwrap_or("");
        let rurl = p
            .get("resourceUrl")
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty() && matches!(agent, ForgeAgent::Pod { .. }));
        if rurl.is_none() && body.trim().is_empty() {
            return Ok(api_err(422, "body required"));
        }
        if body.len() > ISSUE_BODY_CAP {
            return Ok(api_err(422, "body too large"));
        }
        // Fail fast before hosting anything for a missing issue.
        if !load_issue_index(self.spine.as_ref(), owner, repo)
            .await?
            .issues
            .contains_key(&number)
        {
            return Ok(api_err(404, "not found"));
        }
        let pointer = match self
            .api_pointer(
                req,
                agent,
                owner,
                repo,
                "ForgeComment",
                Some(number),
                None,
                body,
                rurl,
            )
            .await
        {
            Ok(ptr) => ptr,
            Err(resp) => return Ok(resp),
        };
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let verdict = match idx.issues.get_mut(&number) {
            None => Some(api_err(404, "not found")),
            Some(issue) if issue.thread.len() >= self.cfg.thread_cap => {
                Some(api_err(422, "thread is full"))
            }
            Some(issue) => {
                issue.thread.push(pointer.clone());
                None
            }
        };
        if let Some(resp) = verdict {
            // Do not leave an orphaned hosted body behind.
            if let Some((hex, id)) = pointer
                .hosted
                .then(|| HostedStore::parse_ref(&pointer.resource_url))
                .flatten()
            {
                let _ = self.hosted.delete(&hex, &id).await;
            }
            return Ok(resp);
        }
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        let comments = idx.issues.get(&number).map_or(0, |i| i.thread.len() - 1);
        let mut out = json!({
            "number": number,
            "comments": comments,
            "resourceUrl": self.hosted_public_url(req, &pointer.resource_url),
        });
        if pointer.hosted {
            out["hosted"] = json!(true);
        }
        Ok(json_resp(201, &out))
    }

    async fn api_issue_state(
        &self,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        number: u64,
        state: IssueState,
    ) -> Result<ForgeResponse, ForgeError> {
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let Some(issue) = idx.issues.get(&number) else {
            return Ok(api_err(404, "not found"));
        };
        if !Self::may_moderate(agent, owner, &issue.author) {
            return Ok(api_err(
                403,
                "only the repo owner or the issue author may do that",
            ));
        }
        idx.set_state(number, state);
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        Ok(json_resp(
            200,
            &json!({"number": number, "state": state_str(state)}),
        ))
    }

    async fn api_issue_retitle(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<ForgeResponse, ForgeError> {
        let p = read_json_body(req);
        if matches!(agent, ForgeAgent::Anonymous) {
            return Ok(unauthorised());
        }
        let Some(p) = p else {
            return Ok(api_err(400, "invalid JSON body"));
        };
        let title = p.get("title").and_then(Value::as_str).map_or("", str::trim);
        let n = title.chars().count();
        if n == 0 || n > ISSUE_TITLE_CAP {
            return Ok(api_err(
                422,
                &format!("title required (1-{ISSUE_TITLE_CAP} chars)"),
            ));
        }
        let _g = self.locks.issues.lock(owner, repo).await;
        let mut idx = load_issue_index(self.spine.as_ref(), owner, repo).await?;
        let Some(issue) = idx.issues.get_mut(&number) else {
            return Ok(api_err(404, "not found"));
        };
        if !Self::may_moderate(agent, owner, &issue.author) {
            return Ok(api_err(
                403,
                "only the repo owner or the issue author may do that",
            ));
        }
        issue.title = title.to_string();
        save_issue_index(self.spine.as_ref(), owner, repo, &idx).await?;
        Ok(json_resp(200, &json!({"number": number, "title": title})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{casey, dana, fixture, get_json, rq};
    use crate::ForgeConfig;

    const HEX_A: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BASE: &str = "/forge/api/repos/casey/demo";

    fn nostr(h: &str) -> ForgeAgent {
        ForgeAgent::Nostr {
            pubkey_hex: h.into(),
        }
    }

    async fn call(
        svc: &ForgeService,
        m: &str,
        path: &str,
        body: &str,
        a: ForgeAgent,
    ) -> (u16, Value) {
        let r = svc.handle(rq(m, path, "", body), a).await.unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    /// Seed issues straight into the spine (pod-body creation needs a loopback
    /// server; the state / retitle / label rules do not).
    async fn seed(svc: &ForgeService) {
        let mut idx = load_issue_index(svc.spine.as_ref(), "casey", "demo")
            .await
            .unwrap();
        for (title, author) in [
            ("Clone fails on Windows", casey().author_id()),
            ("Second", casey().author_id()),
        ] {
            idx.allocate(IssueEntry {
                number: 0,
                title: title.into(),
                state: IssueState::Open,
                author,
                created_at: 5,
                thread: vec![ThreadPointer {
                    author: casey().author_id(),
                    resource_url: "hosted:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/00000000-0000-4000-8000-000000000000".into(),
                    at: 5,
                    hosted: true,
                }],
                labels: vec![],
            });
        }
        save_issue_index(svc.spine.as_ref(), "casey", "demo", &idx)
            .await
            .unwrap();
    }

    // JSS "dana cannot close casey's issue (403); anonymous close is 401"
    // + "casey (owner) closes; the list filters split open/closed correctly"
    #[tokio::test]
    async fn close_reopen_rules_and_list_split() {
        let (_td, svc, _) = fixture();
        seed(&svc).await;
        let close = |a: ForgeAgent| {
            let svc = svc.clone();
            async move { call(&svc, "POST", &format!("{BASE}/issues/1/close"), "", a).await }
        };
        assert_eq!(close(dana()).await.0, 403);
        assert_eq!(close(ForgeAgent::Anonymous).await.0, 401);
        let (_, t) = get_json(&svc, &format!("{BASE}/issues/1"), "", ForgeAgent::Anonymous).await;
        assert_eq!(t["state"], "open", "still open");
        let (st, v) = close(casey()).await;
        assert_eq!(st, 200);
        assert_eq!(v, json!({"number": 1, "state": "closed"}));
        let (_, open) = get_json(
            &svc,
            &format!("{BASE}/issues"),
            "state=open",
            ForgeAgent::Anonymous,
        )
        .await;
        let nums: Vec<u64> = open["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["number"].as_u64().unwrap())
            .collect();
        assert_eq!(nums, vec![2]);
        assert_eq!(open["openCount"], 1);
        assert_eq!(open["closedCount"], 1);
        let (_, closed) = get_json(
            &svc,
            &format!("{BASE}/issues"),
            "state=closed",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(closed["issues"][0]["number"], 1);
        assert_eq!(closed["issues"][0]["comments"], 0);
        let (st, re) = call(
            &svc,
            "POST",
            &format!("{BASE}/issues/1/reopen"),
            "",
            casey(),
        )
        .await;
        assert_eq!((st, re), (200, json!({"number": 1, "state": "open"})));
        assert_eq!(
            call(
                &svc,
                "POST",
                &format!("{BASE}/issues/99/close"),
                "",
                casey()
            )
            .await
            .0,
            404
        );
        assert_eq!(
            call(&svc, "GET", &format!("{BASE}/issues/1/close"), "", casey())
                .await
                .0,
            405
        );
    }

    // JSS "reopen + retitle work for owner/author; a third party gets 403"
    #[tokio::test]
    async fn retitle_rules() {
        let (_td, svc, _) = fixture();
        seed(&svc).await;
        let url = format!("{BASE}/issues/1");
        let (st, _) = call(
            &svc,
            "PATCH",
            &url,
            r#"{"title":"Clone fails on Windows 11"}"#,
            casey(),
        )
        .await;
        assert_eq!(st, 200);
        let (_, t) = get_json(&svc, &url, "", ForgeAgent::Anonymous).await;
        assert_eq!(t["title"], "Clone fails on Windows 11");
        assert_eq!(
            call(&svc, "PATCH", &url, r#"{"title":"hijack"}"#, dana())
                .await
                .0,
            403
        );
        assert_eq!(
            call(
                &svc,
                "PATCH",
                &url,
                r#"{"title":"x"}"#,
                ForgeAgent::Anonymous
            )
            .await
            .0,
            401
        );
        assert_eq!(
            call(&svc, "PATCH", &url, r#"{"title":"  "}"#, casey())
                .await
                .0,
            422
        );
        let long = json!({"title": "t".repeat(257)}).to_string();
        assert_eq!(call(&svc, "PATCH", &url, &long, casey()).await.0, 422);
        assert_eq!(call(&svc, "PATCH", &url, "nope", casey()).await.0, 400);
        assert_eq!(call(&svc, "DELETE", &url, "", casey()).await.0, 405);
    }

    // JSS "a non-owner issue author can close their own issue" + numbering keeps counting
    #[tokio::test]
    async fn issue_author_may_moderate_without_owning_the_repo() {
        let (_td, svc, _) = fixture();
        seed(&svc).await;
        // a podless dana-equivalent: nostr agent creates, then closes its own issue
        let (st, v) = call(
            &svc,
            "POST",
            &format!("{BASE}/issues"),
            r#"{"title":"Docs typo","body":"in the README"}"#,
            nostr(HEX_B),
        )
        .await;
        assert_eq!(st, 201);
        assert_eq!(v["number"], 3, "numbering keeps counting");
        assert_eq!(v["hosted"], true);
        assert_eq!(v["url"], "/forge/casey/demo/issues/3");
        let (st, _) = call(
            &svc,
            "POST",
            &format!("{BASE}/issues/3/close"),
            "",
            nostr(HEX_B),
        )
        .await;
        assert_eq!(
            st, 200,
            "the issue author may close, without owning the repo"
        );
        assert_eq!(
            call(
                &svc,
                "POST",
                &format!("{BASE}/issues/3/reopen"),
                "",
                nostr(HEX_A)
            )
            .await
            .0,
            403
        );
    }

    // JSS "issue list pagination shape"
    #[tokio::test]
    async fn list_pagination_shape() {
        let (_td, svc, _) = fixture();
        seed(&svc).await;
        let (_, p1) = get_json(&svc, &format!("{BASE}/issues"), "", ForgeAgent::Anonymous).await;
        assert_eq!(p1["state"], "open");
        assert_eq!(p1["page"], 1);
        assert_eq!(p1["perPage"], 25);
        assert_eq!(p1["hasMore"], false);
        let (_, p9) = get_json(
            &svc,
            &format!("{BASE}/issues"),
            "page=9",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(p9["issues"], json!([]));
        assert_eq!(p9["hasMore"], false);
        let (_, junk) = get_json(
            &svc,
            &format!("{BASE}/issues"),
            "page=abc",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(junk["page"], 1);
    }

    // JSS nostr-agent beat: hosted issue, second key comments, thread carries hosted + nostr author fields
    #[tokio::test]
    async fn nostr_issue_comment_and_thread_json() {
        let td = tempfile::TempDir::new().unwrap();
        let cfg = ForgeConfig {
            base_url: Some("https://forge.example".into()),
            ..Default::default()
        };
        let svc = ForgeService::new(cfg, td.path()).unwrap();
        let bare = td.path().join(format!("repos/{HEX_A}/nrepo.git"));
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        crate::gitrun::testutil::git(
            td.path(),
            &["init", "--bare", "--quiet", bare.to_str().unwrap()],
        );
        let base = format!("/forge/api/repos/{HEX_A}/nrepo");
        let (st, j) = call(
            &svc,
            "POST",
            &format!("{base}/issues"),
            r#"{"title":"Nostr-born issue","body":"signed with **schnorr**"}"#,
            nostr(HEX_A),
        )
        .await;
        assert_eq!(st, 201);
        assert_eq!(j["number"], 1);
        assert_eq!(j["hosted"], true);
        let url = j["resourceUrl"].as_str().unwrap().to_string();
        assert!(
            url.starts_with(&format!("https://forge.example/forge/api/hosted/{HEX_A}/")),
            "{url}"
        );
        // the hosted doc is publicly fetchable
        let path = url.strip_prefix("https://forge.example").unwrap();
        let doc = call(&svc, "GET", path, "", ForgeAgent::Anonymous).await.1;
        assert_eq!(doc["author"], format!("did:nostr:{HEX_A}"));
        assert_eq!(doc["hosted"], true);
        assert!(doc["body"].as_str().unwrap().contains("**schnorr**"));
        assert_eq!(doc["type"], "ForgeIssue");
        // second key comments
        let (st, c) = call(
            &svc,
            "POST",
            &format!("{base}/issues/1/comments"),
            r#"{"body":"confirmed from another key"}"#,
            nostr(HEX_B),
        )
        .await;
        assert_eq!(st, 201);
        assert_eq!(c["comments"], 1);
        assert!(c["resourceUrl"]
            .as_str()
            .unwrap()
            .contains(&format!("/forge/api/hosted/{HEX_B}/")));
        let t = call(
            &svc,
            "GET",
            &format!("{base}/issues/1"),
            "",
            ForgeAgent::Anonymous,
        )
        .await
        .1;
        assert_eq!(t["author"], format!("did:nostr:{HEX_A}"));
        assert_eq!(
            t["authorInfo"],
            json!({"id": format!("did:nostr:{HEX_A}"), "displayName": format!("did:nostr:{}…", &HEX_A[..8]),
                   "npub": "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6", "kind": "nostr"})
        );
        assert_eq!(t["thread"][0]["hosted"], true);
        assert!(t["thread"][0]["html"]
            .as_str()
            .unwrap()
            .contains("<strong>schnorr</strong>"));
        assert_eq!(t["thread"][1]["authorInfo"]["kind"], "nostr");
        // the author deletes the comment: removed placeholder, pointer remains
        let cpath = c["resourceUrl"]
            .as_str()
            .unwrap()
            .strip_prefix("https://forge.example")
            .unwrap()
            .to_string();
        assert_eq!(call(&svc, "DELETE", &cpath, "", nostr(HEX_B)).await.0, 200);
        let t = call(
            &svc,
            "GET",
            &format!("{base}/issues/1"),
            "",
            ForgeAgent::Anonymous,
        )
        .await
        .1;
        assert_eq!(t["thread"][1]["removed"], true);
        assert!(t["thread"][1]["body"].is_null());
        assert!(t["thread"][1]["html"].is_null());
        assert_eq!(
            t["thread"][1]["author"],
            format!("did:nostr:{HEX_B}"),
            "the pointer (who/when) remains"
        );
        // an edit shows up re-rendered
        let (st, _) = call(
            &svc,
            "PUT",
            path,
            r#"{"body":"edited: now with *more* schnorr"}"#,
            nostr(HEX_A),
        )
        .await;
        assert_eq!(st, 200);
        let t = call(
            &svc,
            "GET",
            &format!("{base}/issues/1"),
            "",
            ForgeAgent::Anonymous,
        )
        .await
        .1;
        assert!(t["thread"][0]["html"]
            .as_str()
            .unwrap()
            .contains("<em>more</em>"));
    }

    #[tokio::test]
    async fn create_and_comment_validation() {
        let (_td, svc, _) = fixture();
        seed(&svc).await;
        let url = format!("{BASE}/issues");
        assert_eq!(
            call(
                &svc,
                "POST",
                &url,
                r#"{"title":"x"}"#,
                ForgeAgent::Anonymous
            )
            .await
            .0,
            401
        );
        assert_eq!(call(&svc, "POST", &url, "junk", nostr(HEX_A)).await.0, 400);
        assert_eq!(
            call(&svc, "POST", &url, r#"{"title":""}"#, nostr(HEX_A))
                .await
                .0,
            422
        );
        let big = json!({"title":"t","body":"x".repeat(ISSUE_BODY_CAP + 1)}).to_string();
        assert_eq!(call(&svc, "POST", &url, &big, nostr(HEX_A)).await.0, 422);
        // a pod agent without a pointer cannot have the forge write into its pod
        assert_eq!(
            call(&svc, "POST", &url, r#"{"title":"t","body":"b"}"#, dana())
                .await
                .0,
            422
        );
        // pod pointers outside the caller's own forge area are refused (SSRF guard)
        let evil = r#"{"title":"t","resourceUrl":"http://169.254.169.254/dana/public/forge/casey--demo/x.jsonld"}"#;
        assert_eq!(call(&svc, "POST", &url, evil, dana()).await.0, 403);
        let c = format!("{BASE}/issues/1/comments");
        assert_eq!(
            call(&svc, "POST", &c, r#"{"body":"  "}"#, nostr(HEX_A))
                .await
                .0,
            422
        );
        assert_eq!(
            call(
                &svc,
                "POST",
                &format!("{BASE}/issues/77/comments"),
                r#"{"body":"x"}"#,
                nostr(HEX_A)
            )
            .await
            .0,
            404
        );
        assert_eq!(
            call(&svc, "POST", &c, r#"{"body":"x"}"#, ForgeAgent::Anonymous)
                .await
                .0,
            401
        );
        // unknown / malformed numbers and verbs
        assert_eq!(
            call(&svc, "GET", &format!("{BASE}/issues/0"), "", dana())
                .await
                .0,
            404
        );
        assert_eq!(
            call(&svc, "GET", &format!("{BASE}/issues/1/nope"), "", dana())
                .await
                .0,
            404
        );
        assert_eq!(call(&svc, "PUT", &url, "", dana()).await.0, 405);
    }

    #[tokio::test]
    async fn thread_cap_leaves_no_orphan_body() {
        let td = tempfile::TempDir::new().unwrap();
        let cfg = ForgeConfig {
            thread_cap: 1,
            ..Default::default()
        };
        let svc = ForgeService::new(cfg, td.path()).unwrap();
        crate::gitrun::testutil::demo_repo(td.path());
        seed(&svc).await;
        let r = call(
            &svc,
            "POST",
            &format!("{BASE}/issues/1/comments"),
            r#"{"body":"x"}"#,
            nostr(HEX_A),
        )
        .await;
        assert_eq!(r.0, 422);
        let dir = td.path().join("hosted").join(HEX_A);
        let left = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(left, 0, "hosted body removed again");
    }

    #[test]
    fn helpers() {
        assert_eq!(
            owner_from_webid("https://pod.example/profile/card#me").as_deref(),
            Some("pod")
        );
        assert_eq!(owner_from_webid("ftp://x/y"), None);
        assert_eq!(author_meta("anon")["displayName"], "anon");
    }
}
