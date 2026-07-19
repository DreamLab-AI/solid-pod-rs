//! Two-phase pod-write coordinator.
//!
//! Issue/PR/comment bodies live in the author's own pod. The write is
//! two-phase (cites JSS `forge` Tier 2 behaviour by name only):
//!
//! 1. The browser signs a proof bound to *its own* pod and PUTs the
//!    JSON-LD body into its forge area
//!    (`<pod>/public/forge/<owner>--<repo>/…jsonld`), then POSTs only the
//!    `resourceUrl` pointer to the forge.
//! 2. The forge validates the URL is inside the caller's **own** forge
//!    area ([`own_area_ok`] — this is also the SSRF guard: it pins the
//!    loopback to our own origin), unauthenticated-GETs it once to
//!    confirm public readability, and stores only the pointer.
//!
//! Bodies are re-fetched at read time, bounded: `fetch_concurrency`-way
//! parallel, `fetch_timeout_secs` each, `thread_cap` pointers max,
//! `max_body_bytes` per body. A deleted pod resource renders as
//! "content removed by its author".

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::ForgeConfig;
use crate::error::ForgeError;
use crate::request::looks_textual;
use crate::spine::issues::ThreadPointer;

/// Result of an unauthenticated body fetch.
#[derive(Debug, Clone)]
pub enum FetchResult {
    /// The body bytes (already bounded to `max_bytes` by the fetcher).
    Body(Vec<u8>),
    /// The resource returned 404/410 — its author deleted it.
    Removed,
    /// The resource exceeded `max_bytes`.
    TooLarge,
    /// A network/timeout/other error (the message is for diagnostics).
    Error(String),
}

/// Unauthenticated loopback GET against the server's own origin. The
/// server injects a reqwest-backed implementation that reuses its vetted
/// HTTP client + SSRF posture; tests inject an in-memory mock.
#[async_trait]
pub trait LoopbackFetch: Send + Sync {
    /// GET `url` with no credentials, bounding the body to `max_bytes`
    /// and the request to `timeout_secs`.
    async fn get(&self, url: &str, max_bytes: usize, timeout_secs: u64) -> FetchResult;
}

/// Reader for forge-hosted bodies (podless `did:nostr` agents). Wired in
/// the tokens phase; kept here so the read-time coordinator signature is
/// stable across phases.
#[async_trait]
pub trait HostedReader: Send + Sync {
    /// Read a hosted body identified by its `resource_url` ref.
    async fn read_hosted(&self, resource_ref: &str, max_bytes: usize) -> FetchResult;
}

/// The forge-area URL prefix a caller's body must live under. The body
/// lives in the **caller's own** pod (`caller`), namespaced by the target
/// repo (`repo_owner--repo`). For issue creation the caller *is* the repo
/// owner; for a comment the caller is the commenter (a different pod).
#[must_use]
pub fn forge_area_prefix(host: &str, caller: &str, repo_owner: &str, repo: &str) -> String {
    let host = host.trim_end_matches('/');
    format!("{host}/{caller}/public/forge/{repo_owner}--{repo}/")
}

/// Validate that `resource_url` is inside the caller's own forge area:
/// same origin (`host`), under `/<caller>/public/forge/<repo_owner>--<repo>/`,
/// no `..` traversal, and a JSON-LD/JSON leaf. This is the two-phase
/// write's SSRF guard — it guarantees the subsequent loopback GET only
/// ever hits our own origin and the caller's own namespace.
pub fn own_area_ok(
    resource_url: &str,
    host: &str,
    caller: &str,
    repo_owner: &str,
    repo: &str,
) -> Result<(), ForgeError> {
    let prefix = forge_area_prefix(host, caller, repo_owner, repo);
    if !resource_url.starts_with(&prefix) {
        return Err(ForgeError::Forbidden(format!(
            "resourceUrl must be under {prefix}"
        )));
    }
    if resource_url.contains("..") {
        return Err(ForgeError::PathTraversal(resource_url.to_string()));
    }
    // The leaf must be an author body document, never an arbitrary path.
    if !(resource_url.ends_with(".jsonld") || resource_url.ends_with(".json")) {
        return Err(ForgeError::BadRequest(
            "resourceUrl must be a .jsonld/.json body".into(),
        ));
    }
    Ok(())
}

/// The rendered outcome for one thread pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyOutcome {
    /// The re-fetched (textual) body.
    Present(String),
    /// The author deleted the pod resource.
    Removed,
    /// The body exceeded the size cap.
    TooLarge,
    /// A fetch/config error (no resolver, network failure, …).
    Unavailable(String),
}

/// A thread comment ready to render: author + timestamp + body outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedThread {
    /// Author id.
    pub author: String,
    /// Unix seconds recorded.
    pub at: u64,
    /// The re-fetched body (or a deletion/error placeholder).
    pub body: BodyOutcome,
}

fn to_outcome(res: FetchResult) -> BodyOutcome {
    match res {
        FetchResult::Body(bytes) => {
            if looks_textual(&bytes) {
                BodyOutcome::Present(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                BodyOutcome::Unavailable("non-textual body".into())
            }
        }
        FetchResult::Removed => BodyOutcome::Removed,
        FetchResult::TooLarge => BodyOutcome::TooLarge,
        FetchResult::Error(e) => BodyOutcome::Unavailable(e),
    }
}

async fn resolve_one(
    p: &ThreadPointer,
    loopback: Option<&Arc<dyn LoopbackFetch>>,
    hosted: Option<&Arc<dyn HostedReader>>,
    max_bytes: usize,
    timeout_secs: u64,
) -> BodyOutcome {
    if p.hosted {
        match hosted {
            Some(h) => to_outcome(h.read_hosted(&p.resource_url, max_bytes).await),
            None => BodyOutcome::Unavailable("hosted store unavailable".into()),
        }
    } else {
        match loopback {
            Some(lb) => to_outcome(lb.get(&p.resource_url, max_bytes, timeout_secs).await),
            None => BodyOutcome::Unavailable("loopback fetch unavailable".into()),
        }
    }
}

/// Re-fetch every thread body, bounded per [`ForgeConfig`], preserving
/// pointer order. Pointers beyond `thread_cap` are dropped (the caller
/// should surface a "truncated" notice — see the handler).
pub async fn render_thread(
    pointers: &[ThreadPointer],
    loopback: Option<Arc<dyn LoopbackFetch>>,
    hosted: Option<Arc<dyn HostedReader>>,
    cfg: &ForgeConfig,
) -> Vec<RenderedThread> {
    let n = pointers.len().min(cfg.thread_cap);
    if n == 0 {
        return Vec::new();
    }
    let sem = Arc::new(Semaphore::new(cfg.fetch_concurrency.max(1)));
    let mut set: JoinSet<(usize, RenderedThread)> = JoinSet::new();

    for (i, p) in pointers.iter().take(n).enumerate() {
        let sem = sem.clone();
        let p = p.clone();
        let loopback = loopback.clone();
        let hosted = hosted.clone();
        let max = cfg.max_body_bytes;
        let to = cfg.fetch_timeout_secs;
        set.spawn(async move {
            // Bound concurrency; a closed semaphore never happens here.
            let _permit = sem.acquire_owned().await.ok();
            let outcome = resolve_one(&p, loopback.as_ref(), hosted.as_ref(), max, to).await;
            (
                i,
                RenderedThread {
                    author: p.author.clone(),
                    at: p.at,
                    body: outcome,
                },
            )
        });
    }

    let mut slots: Vec<Option<RenderedThread>> = (0..n).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, rt)) = joined {
            slots[i] = Some(rt);
        }
    }
    slots.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn own_area_accepts_valid_and_rejects_others() {
        let host = "https://pod.example";
        // Repo owner alice opening an issue in her own repo.
        let ok = "https://pod.example/alice/public/forge/alice--demo/issue-1.jsonld";
        assert!(own_area_ok(ok, host, "alice", "alice", "demo").is_ok());

        // A commenter (bob) commenting on alice/demo — body in bob's pod,
        // namespaced by the repo. Legitimate.
        let comment = "https://pod.example/bob/public/forge/alice--demo/comment-1.jsonld";
        assert!(own_area_ok(comment, host, "bob", "alice", "demo").is_ok());

        // Caller claims bob's pod but is authenticated as alice → rejected.
        assert!(matches!(
            own_area_ok(comment, host, "alice", "alice", "demo"),
            Err(ForgeError::Forbidden(_))
        ));

        // Different origin (SSRF attempt to an internal service).
        let ssrf = "http://169.254.169.254/alice/public/forge/alice--demo/x.jsonld";
        assert!(own_area_ok(ssrf, host, "alice", "alice", "demo").is_err());

        // Traversal out of the area.
        let trav = "https://pod.example/alice/public/forge/alice--demo/../../secret.jsonld";
        assert!(matches!(
            own_area_ok(trav, host, "alice", "alice", "demo"),
            Err(ForgeError::PathTraversal(_))
        ));

        // Not a body document.
        let notbody = "https://pod.example/alice/public/forge/alice--demo/index.html";
        assert!(matches!(
            own_area_ok(notbody, host, "alice", "alice", "demo"),
            Err(ForgeError::BadRequest(_))
        ));
    }

    /// In-memory loopback returning canned bodies; a missing key = Removed.
    struct MockLoopback {
        map: Mutex<HashMap<String, FetchResult>>,
    }
    impl MockLoopback {
        fn new(pairs: &[(&str, FetchResult)]) -> Self {
            let mut m = HashMap::new();
            for (k, v) in pairs {
                m.insert((*k).to_string(), v.clone());
            }
            Self { map: Mutex::new(m) }
        }
    }
    #[async_trait]
    impl LoopbackFetch for MockLoopback {
        async fn get(&self, url: &str, _max: usize, _to: u64) -> FetchResult {
            self.map
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .unwrap_or(FetchResult::Removed)
        }
    }

    fn ptr(url: &str) -> ThreadPointer {
        ThreadPointer {
            author: "did:nostr:abc".into(),
            resource_url: url.into(),
            at: 10,
            hosted: false,
        }
    }

    #[tokio::test]
    async fn render_thread_fetches_present_and_removed_in_order() {
        let lb: Arc<dyn LoopbackFetch> = Arc::new(MockLoopback::new(&[
            ("u1", FetchResult::Body(b"first body".to_vec())),
            ("u3", FetchResult::Body(b"third body".to_vec())),
            // u2 absent → Removed.
        ]));
        let cfg = ForgeConfig::default();
        let pointers = vec![ptr("u1"), ptr("u2"), ptr("u3")];
        let out = render_thread(&pointers, Some(lb), None, &cfg).await;
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].body, BodyOutcome::Present("first body".into()));
        assert_eq!(out[1].body, BodyOutcome::Removed);
        assert_eq!(out[2].body, BodyOutcome::Present("third body".into()));
    }

    #[tokio::test]
    async fn render_thread_without_resolver_is_unavailable() {
        let cfg = ForgeConfig::default();
        let out = render_thread(&[ptr("u1")], None, None, &cfg).await;
        assert!(matches!(out[0].body, BodyOutcome::Unavailable(_)));
    }

    #[tokio::test]
    async fn render_thread_honours_thread_cap() {
        let lb: Arc<dyn LoopbackFetch> = Arc::new(MockLoopback::new(&[(
            "u",
            FetchResult::Body(b"x".to_vec()),
        )]));
        let cfg = ForgeConfig {
            thread_cap: 2,
            ..Default::default()
        };
        let pointers = vec![ptr("u"), ptr("u"), ptr("u"), ptr("u")];
        let out = render_thread(&pointers, Some(lb), None, &cfg).await;
        assert_eq!(out.len(), 2, "must cap at thread_cap");
    }

    #[tokio::test]
    async fn too_large_and_error_map_through() {
        let lb: Arc<dyn LoopbackFetch> = Arc::new(MockLoopback::new(&[
            ("big", FetchResult::TooLarge),
            ("err", FetchResult::Error("boom".into())),
        ]));
        let cfg = ForgeConfig::default();
        let out = render_thread(&[ptr("big"), ptr("err")], Some(lb), None, &cfg).await;
        assert_eq!(out[0].body, BodyOutcome::TooLarge);
        assert_eq!(out[1].body, BodyOutcome::Unavailable("boom".into()));
    }
}
