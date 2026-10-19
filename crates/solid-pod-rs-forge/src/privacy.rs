//! `private_repos`: every read (git, HTML, JSON) becomes owner-only.
//!
//! Follows the JSS `forge` dispatcher with `privateRepos: true` (cited by
//! name only), enforced centrally on the **path segments** rather than per
//! route so a route added later is fail-closed by default:
//!
//! * `<prefix>/` and `/api/repos`: anonymous `401` (`WWW-Authenticate: Basic`),
//!   otherwise the listing is filtered to the caller's own namespace.
//! * Anything under `<owner>/…` or `/api/repos/<owner>/…`: anonymous `401`,
//!   another owner's namespace `403`. The owner check runs before the
//!   repository-exists check, so existence cannot be probed.
//! * Git smart-HTTP (read **and** write): anonymous `401`, foreign namespace
//!   `403 this namespace belongs to <owner>`.
//!
//! Exempt: `xlogin.js` (static widget code), `api/token` (the mint does its
//! own authentication) and `api/hosted/…` (its handler requires an agent for
//! reads under `private_repos`).

use crate::api::{api_err, RepoSummary};
use crate::error::ForgeError;
use crate::ownership::ForgeAgent;
use crate::request::{percent_decode, ForgeRequest, ForgeResponse};
use crate::router::Route;
use crate::{html, ForgeService};

const BASIC_CHALLENGE: &str = "Basic realm=\"jss-forge\", charset=\"UTF-8\"";

fn text(status: u16, msg: &str) -> ForgeResponse {
    ForgeResponse::with_type(
        status,
        "text/plain; charset=utf-8",
        bytes::Bytes::from(msg.to_string()),
    )
}

fn challenge(api: bool) -> ForgeResponse {
    let r = if api {
        api_err(401, "authentication required")
    } else {
        text(401, "authentication required\n")
    };
    r.with_header("www-authenticate", BASIC_CHALLENGE)
}

impl ForgeService {
    /// The owner-only gate. `rel` is the prefix-stripped path. Returns the
    /// refusal to send, or `None` to proceed. Only consulted when
    /// `private_repos` is set.
    pub(crate) fn private_gate(
        &self,
        rel: &str,
        route: &Route,
        agent: &ForgeAgent,
    ) -> Option<ForgeResponse> {
        let path = rel.split('?').next().unwrap_or(rel);
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs == ["xlogin.js"] {
            return None;
        }
        // A git smart-HTTP path is judged as git even when its first segment
        // looks like the API namespace (`/api/<name>.git/info/refs`).
        let git = matches!(route, Route::GitSmart { .. });
        let api = !git && segs.first() == Some(&"api");
        if api && matches!(segs.get(1), Some(&"token" | &"hosted")) {
            return None;
        }
        let me = agent.owner();
        if matches!(agent, ForgeAgent::Anonymous) {
            return Some(challenge(api));
        }
        // The namespace the request addresses (None for the root listings).
        // The parsed route's owner is what will be served, so it decides;
        // the raw segments are only a fail-closed fallback for routes that
        // carry no owner.
        let target = route.owner().or(if api {
            if segs.get(1) == Some(&"repos") {
                segs.get(2).copied()
            } else {
                None
            }
        } else {
            segs.first().copied()
        });
        let Some(me) = me else {
            return Some(if api {
                api_err(403, "no pod namespace for this agent")
            } else {
                text(403, "private forge\n")
            });
        };
        match target {
            Some(t) if t != me => Some(if matches!(route, Route::GitSmart { .. }) {
                text(403, &format!("this namespace belongs to {t}\n"))
            } else if api {
                api_err(403, "private forge")
            } else {
                text(403, "private forge\n")
            }),
            _ => None,
        }
    }

    /// `GET <prefix>/` with the `?q=` filter and, under `private_repos`, the
    /// caller's own namespace only (JSS `indexPage`).
    pub(crate) async fn h_index_filtered(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
    ) -> Result<ForgeResponse, ForgeError> {
        let owner_filter = if self.cfg.private_repos {
            agent.owner().map(str::to_string)
        } else {
            None
        };
        let q: String = req
            .query_param("q")
            .map(|v| percent_decode(&v).trim().chars().take(256).collect())
            .unwrap_or_default();
        let mut rows: Vec<RepoSummary> = self.summaries(owner_filter.as_deref()).await;
        let had_any = !rows.is_empty();
        if !q.is_empty() {
            let needle = q.to_lowercase();
            rows.retain(|r| {
                format!("{}/{}", r.owner, r.name)
                    .to_lowercase()
                    .contains(&needle)
                    || r.description.to_lowercase().contains(&needle)
            });
        }
        let page =
            html::index_page_full(&self.prefix(), &rows, &q, had_any, self.cfg.private_repos);
        let pairs: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.owner.clone(), r.name.clone()))
            .collect();
        Ok(ForgeResponse::html(
            200,
            self.decorate_listing(&page, &pairs),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{casey, dana, rq};
    use crate::gitrun::testutil::demo_repo;
    use crate::ForgeConfig;

    fn private_svc() -> (tempfile::TempDir, ForgeService) {
        let td = tempfile::TempDir::new().unwrap();
        demo_repo(td.path()); // casey/demo
        let cfg = ForgeConfig {
            private_repos: true,
            ..Default::default()
        };
        let svc = ForgeService::new(cfg, td.path()).unwrap();
        (td, svc)
    }

    async fn status(svc: &ForgeService, m: &str, p: &str, q: &str, a: ForgeAgent) -> ForgeResponse {
        svc.handle(rq(m, p, q, ""), a).await.unwrap()
    }

    // JSS "privateRepos: true flips every read (git, HTML, JSON) to owner-only"
    #[tokio::test]
    async fn html_reads_are_owner_only() {
        let (_td, svc) = private_svc();
        let anon = status(&svc, "GET", "/forge/casey/demo", "", ForgeAgent::Anonymous).await;
        assert_eq!(anon.status, 401);
        assert!(anon
            .headers
            .iter()
            .any(|(k, v)| k == "www-authenticate" && v.starts_with("Basic")));
        assert_eq!(
            status(&svc, "GET", "/forge/casey/demo", "", dana())
                .await
                .status,
            403
        );
        assert_eq!(
            status(&svc, "GET", "/forge/casey/demo", "", casey())
                .await
                .status,
            200
        );
        // every browse lane is gated, existing repo or not (no existence probe)
        for p in [
            "/forge/casey",
            "/forge/casey/demo/tree/main",
            "/forge/casey/demo/blob/main/README.md",
            "/forge/casey/demo/raw/main/README.md",
            "/forge/casey/demo/commits/main",
            "/forge/casey/demo/branches",
            "/forge/casey/demo/issues",
            "/forge/casey/demo/search",
            "/forge/casey/demo/releases",
            "/forge/casey/demo/archive/main.zip",
            "/forge/casey/nope",
        ] {
            assert_eq!(
                status(&svc, "GET", p, "", ForgeAgent::Anonymous)
                    .await
                    .status,
                401,
                "{p}"
            );
            assert_eq!(status(&svc, "GET", p, "", dana()).await.status, 403, "{p}");
        }
        assert_eq!(
            status(&svc, "GET", "/forge/casey/nope", "", casey())
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn git_reads_are_owner_only() {
        let (_td, svc) = private_svc();
        let p = "/forge/casey/demo.git/info/refs";
        let q = "service=git-upload-pack";
        let anon = status(&svc, "GET", p, q, ForgeAgent::Anonymous).await;
        assert_eq!(anon.status, 401);
        assert!(anon.headers.iter().any(|(k, _)| k == "www-authenticate"));
        let other = status(&svc, "GET", p, q, dana()).await;
        assert_eq!(other.status, 403);
        assert!(String::from_utf8_lossy(&other.body).contains("belongs to casey"));
        let own = status(&svc, "GET", p, q, casey()).await;
        assert_ne!(own.status, 401);
        assert_ne!(own.status, 403);
        let pack = status(
            &svc,
            "POST",
            "/forge/casey/demo.git/git-upload-pack",
            "",
            dana(),
        )
        .await;
        assert_eq!(pack.status, 403);
    }

    #[tokio::test]
    async fn json_reads_are_owner_only_and_the_index_is_filtered() {
        let (_td, svc) = private_svc();
        assert_eq!(
            status(&svc, "GET", "/forge/api/repos", "", ForgeAgent::Anonymous)
                .await
                .status,
            401
        );
        let own = status(&svc, "GET", "/forge/api/repos", "", casey()).await;
        let v: serde_json::Value = serde_json::from_slice(&own.body).unwrap();
        assert!(v["repos"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["owner"] == "casey"));
        assert_eq!(v["repos"].as_array().unwrap().len(), 1);
        // dana sees an empty list, not casey's repos
        let other = status(&svc, "GET", "/forge/api/repos", "", dana()).await;
        let v: serde_json::Value = serde_json::from_slice(&other.body).unwrap();
        assert_eq!(v["repos"].as_array().unwrap().len(), 0);
        assert_eq!(
            status(&svc, "GET", "/forge/api/repos/casey/demo", "", dana())
                .await
                .status,
            403
        );
        assert_eq!(
            status(
                &svc,
                "GET",
                "/forge/api/repos/casey/demo/tree/main",
                "",
                dana()
            )
            .await
            .status,
            403
        );
        assert_eq!(
            status(&svc, "GET", "/forge/api/repos/casey/demo", "", casey())
                .await
                .status,
            200
        );
        assert_eq!(
            status(&svc, "GET", "/forge/api/repos/casey", "", dana())
                .await
                .status,
            403
        );
        // the HTML index is filtered the same way
        let idx = status(&svc, "GET", "/forge", "", dana()).await;
        assert_eq!(idx.status, 200);
        assert!(!String::from_utf8_lossy(&idx.body).contains("/forge/casey/demo"));
        assert_eq!(
            status(&svc, "GET", "/forge", "", ForgeAgent::Anonymous)
                .await
                .status,
            401
        );
        let mine = status(&svc, "GET", "/forge", "", casey()).await;
        assert!(String::from_utf8_lossy(&mine.body).contains("/forge/casey/demo"));
    }

    #[tokio::test]
    async fn xlogin_and_token_are_exempt() {
        let (_td, svc) = private_svc();
        assert_eq!(
            status(&svc, "GET", "/forge/xlogin.js", "", ForgeAgent::Anonymous)
                .await
                .status,
            200
        );
        // the token mint authenticates itself: anonymous gets its own 401, not the gate's challenge
        let r = status(&svc, "POST", "/forge/api/token", "", ForgeAgent::Anonymous).await;
        assert_eq!(r.status, 401);
        assert!(!r
            .headers
            .iter()
            .any(|(k, v)| k == "www-authenticate" && v.starts_with("Basic")));
    }

    #[tokio::test]
    async fn public_forge_is_unchanged() {
        let td = tempfile::TempDir::new().unwrap();
        demo_repo(td.path());
        let svc = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
        assert_eq!(
            status(&svc, "GET", "/forge/casey/demo", "", ForgeAgent::Anonymous)
                .await
                .status,
            200
        );
        assert_eq!(
            status(&svc, "GET", "/forge/api/repos", "", ForgeAgent::Anonymous)
                .await
                .status,
            200
        );
    }

    // Security review L5: `/api/<name>.git/...` is git smart-HTTP to the
    // router but looked like the API namespace to the gate, so any
    // authenticated agent passed it. The git owner is now judged, and the
    // route words are not usable as owner names at all.
    #[tokio::test]
    async fn api_prefixed_git_path_is_gated_as_git() {
        let (_td, svc) = private_svc();
        for p in [
            "/forge/api/x.git/info/refs",
            "/forge/api/x.git/git-upload-pack",
            "/forge/xlogin.js/x.git/info/refs",
        ] {
            let r = status(&svc, "GET", p, "service=git-upload-pack", dana()).await;
            assert_eq!(r.status, 403, "{p}");
            let r = status(
                &svc,
                "GET",
                p,
                "service=git-upload-pack",
                ForgeAgent::Anonymous,
            )
            .await;
            assert_eq!(r.status, 401, "{p}");
        }
        assert!(!crate::guard::ok_owner("api"));
        assert!(!crate::guard::ok_owner("Api"));
        assert!(!crate::guard::ok_owner("xlogin.js"));
        assert!(!crate::compare::valid_owner("api"));
    }

    // JSS "the repo list ?q= filter is a plain server-side GET form (no JS)"
    #[tokio::test]
    async fn repo_list_q_filters_by_name_and_description() {
        let td = tempfile::TempDir::new().unwrap();
        demo_repo(td.path());
        let other = td.path().join("repos/aaa/nrepo.git");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        crate::gitrun::testutil::git(
            td.path(),
            &["init", "--bare", "--quiet", other.to_str().unwrap()],
        );
        let svc = ForgeService::new(ForgeConfig::default(), td.path()).unwrap();
        std::fs::write(
            td.path().join("repos/casey/demo.git/description"),
            "A demo repo with <angle> brackets\n",
        )
        .unwrap();
        let page = |q: &str| {
            let svc = svc.clone();
            let q = q.to_string();
            async move {
                let r = svc
                    .handle(
                        rq("GET", "/forge/", &format!("q={q}"), ""),
                        ForgeAgent::Anonymous,
                    )
                    .await
                    .unwrap();
                String::from_utf8_lossy(&r.body).into_owned()
            }
        };
        let h = page("nrepo").await;
        assert!(h.contains("name=\"q\""));
        assert!(h.contains("/nrepo"));
        assert!(!h.contains("/forge/casey/demo\""));
        let h = page("angle").await;
        assert!(h.contains("/forge/casey/demo"));
        assert!(
            h.contains("A demo repo with &lt;angle&gt; brackets"),
            "description on the repo list, escaped"
        );
        assert!(page("zzz-nothing-here")
            .await
            .contains("No repositories match"));
    }
}
