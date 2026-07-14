//! Pure route dispatch — maps `(method, path)` to a [`Route`].
//!
//! The parser is deliberately side-effect free so the whole dispatch
//! table is unit-testable without a filesystem or a git binary. The
//! embedding [`crate::ForgeService::handle`] strips the configured prefix,
//! calls [`parse_route`], and switches on the result.

/// A resolved forge route. Method-specific behaviour (GET list vs POST
/// create) is decided by the handler from [`crate::ForgeRequest::method`];
/// this enum captures only the addressed resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `GET /` — global repo list.
    Index,
    /// `GET /<owner>` — a single owner's repo list.
    OwnerIndex {
        /// Owner namespace segment.
        owner: String,
    },
    /// Any git smart-HTTP path (`…/<owner>/<repo>.git/{info/refs,
    /// git-upload-pack,git-receive-pack}`). The full prefix-stripped path
    /// is forwarded verbatim to the git CGI service.
    GitSmart {
        /// Path relative to the repos root (leading `/`).
        rel_path: String,
    },
    /// `GET /<owner>/<repo>` — repo overview (branches + tree + README).
    RepoOverview {
        /// Owner namespace.
        owner: String,
        /// Repository name (without the on-disk `.git` suffix).
        repo: String,
    },
    /// `GET /<owner>/<repo>/tree/<ref>[/<path>]` — directory listing.
    Tree {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Git ref (branch/tag/sha).
        rev: String,
        /// Repo-relative sub-path (may be empty for the root).
        path: String,
    },
    /// `GET /<owner>/<repo>/blob/<ref>/<path>` — rendered file view.
    Blob {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Git ref.
        rev: String,
        /// Repo-relative file path.
        path: String,
    },
    /// `GET /<owner>/<repo>/raw/<ref>/<path>` — defended raw bytes.
    Raw {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Git ref.
        rev: String,
        /// Repo-relative file path.
        path: String,
    },
    /// `GET /<owner>/<repo>/commits/<ref>` — paginated commit log.
    Commits {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Git ref.
        rev: String,
    },
    /// `GET /<owner>/<repo>/commit/<sha>` — single-commit view.
    Commit {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Commit sha (any rev git accepts).
        sha: String,
    },
    /// `GET /<owner>/<repo>/branches`.
    Branches {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// `GET /<owner>/<repo>/tags`.
    Tags {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// `GET/POST /<owner>/<repo>/issues` — list or create.
    Issues {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// `GET /<owner>/<repo>/issues/new` — new-issue form.
    IssueNew {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// `GET/POST /<owner>/<repo>/issues/<num>` — thread view / comment.
    IssueDetail {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
        /// Issue number.
        num: u64,
    },
    /// `POST /api/token` — mint a forge push token.
    ApiToken,
    /// `GET/DELETE /api/hosted/<hex>/<uuid>` — podless body store.
    ApiHosted {
        /// 64-hex owner pubkey.
        hex: String,
        /// Body uuid.
        id: String,
    },
    /// `GET /api/repos` — JSON repo list.
    ApiReposList,
    /// `GET /api/repos/<owner>/<repo>` — JSON repo model.
    ApiRepo {
        /// Owner namespace.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// Unmatched — the handler returns 404.
    NotFound,
}

/// Git smart-HTTP suffixes that identify a CGI request.
const GIT_SUFFIXES: &[&str] = &["/info/refs", "/git-upload-pack", "/git-receive-pack"];

/// Strip `prefix` from `path`. Returns the remainder with a guaranteed
/// leading `/` (or `"/"` for an exact-prefix match). Returns `None` when
/// `path` is not under `prefix`.
#[must_use]
pub fn strip_prefix<'a>(prefix: &str, path: &'a str) -> Option<std::borrow::Cow<'a, str>> {
    if prefix.is_empty() {
        return Some(std::borrow::Cow::Borrowed(path));
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        if rest.is_empty() {
            Some(std::borrow::Cow::Borrowed("/"))
        } else if rest.starts_with('/') {
            Some(std::borrow::Cow::Borrowed(rest))
        } else {
            // e.g. prefix "/forge" vs path "/forgery" — not a real match.
            None
        }
    } else {
        None
    }
}

/// Parse a prefix-stripped `path` into a [`Route`]. `rel` must have a
/// leading slash (as produced by [`strip_prefix`]).
#[must_use]
pub fn parse_route(rel: &str) -> Route {
    // Split query defensively (callers pass path only, but be robust).
    let rel = rel.split('?').next().unwrap_or(rel);

    if rel.is_empty() || rel == "/" {
        return Route::Index;
    }

    // Git smart-HTTP: any path ending in a git service suffix.
    for suffix in GIT_SUFFIXES {
        if rel.ends_with(suffix) {
            return Route::GitSmart {
                rel_path: rel.to_string(),
            };
        }
    }

    let segs: Vec<&str> = rel.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return Route::Index;
    }

    // API namespace.
    if segs[0] == "api" {
        return parse_api(&segs[1..]);
    }

    match segs.as_slice() {
        [owner] => Route::OwnerIndex {
            owner: (*owner).to_string(),
        },
        [owner, repo] => Route::RepoOverview {
            owner: (*owner).to_string(),
            repo: strip_git_suffix(repo),
        },
        [owner, repo, verb, rest @ ..] => parse_repo_verb(owner, repo, verb, rest),
        _ => Route::NotFound,
    }
}

fn parse_repo_verb(owner: &str, repo: &str, verb: &str, rest: &[&str]) -> Route {
    let owner = owner.to_string();
    let repo = strip_git_suffix(repo);
    match verb {
        "tree" | "blob" | "raw" => {
            if rest.is_empty() {
                return Route::NotFound;
            }
            let rev = rest[0].to_string();
            let path = rest[1..].join("/");
            match verb {
                "tree" => Route::Tree { owner, repo, rev, path },
                "blob" => Route::Blob { owner, repo, rev, path },
                _ => Route::Raw { owner, repo, rev, path },
            }
        }
        "commits" => {
            let rev = rest.first().map(|s| (*s).to_string()).unwrap_or_default();
            if rev.is_empty() {
                return Route::NotFound;
            }
            Route::Commits { owner, repo, rev }
        }
        "commit" => {
            let sha = rest.first().map(|s| (*s).to_string()).unwrap_or_default();
            if sha.is_empty() {
                return Route::NotFound;
            }
            Route::Commit { owner, repo, sha }
        }
        "branches" if rest.is_empty() => Route::Branches { owner, repo },
        "tags" if rest.is_empty() => Route::Tags { owner, repo },
        "issues" => match rest {
            [] => Route::Issues { owner, repo },
            ["new"] => Route::IssueNew { owner, repo },
            [num] => match num.parse::<u64>() {
                Ok(n) => Route::IssueDetail { owner, repo, num: n },
                Err(_) => Route::NotFound,
            },
            _ => Route::NotFound,
        },
        _ => Route::NotFound,
    }
}

fn parse_api(segs: &[&str]) -> Route {
    match segs {
        ["token"] => Route::ApiToken,
        ["hosted", hex, id] => Route::ApiHosted {
            hex: (*hex).to_string(),
            id: (*id).to_string(),
        },
        ["repos"] => Route::ApiReposList,
        ["repos", owner, repo] => Route::ApiRepo {
            owner: (*owner).to_string(),
            repo: strip_git_suffix(repo),
        },
        _ => Route::NotFound,
    }
}

/// Remove a trailing `.git` from a repo name so the browse URL `<n>` and
/// the clone URL `<n>.git` address the same repository.
#[must_use]
pub fn strip_git_suffix(repo: &str) -> String {
    repo.strip_suffix(".git").unwrap_or(repo).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_prefix_variants() {
        assert_eq!(strip_prefix("/forge", "/forge").as_deref(), Some("/"));
        assert_eq!(
            strip_prefix("/forge", "/forge/alice/repo").as_deref(),
            Some("/alice/repo")
        );
        assert_eq!(strip_prefix("/forge", "/forgery").as_deref(), None);
        assert_eq!(strip_prefix("/forge", "/other").as_deref(), None);
        // Empty prefix (root mount) passes everything through.
        assert_eq!(strip_prefix("", "/alice/repo").as_deref(), Some("/alice/repo"));
    }

    #[test]
    fn index_route() {
        assert_eq!(parse_route("/"), Route::Index);
        assert_eq!(parse_route(""), Route::Index);
    }

    #[test]
    fn git_smart_routes_take_priority() {
        assert_eq!(
            parse_route("/alice/repo.git/info/refs"),
            Route::GitSmart {
                rel_path: "/alice/repo.git/info/refs".into()
            }
        );
        assert_eq!(
            parse_route("/alice/repo.git/git-receive-pack"),
            Route::GitSmart {
                rel_path: "/alice/repo.git/git-receive-pack".into()
            }
        );
    }

    #[test]
    fn owner_and_repo_overview() {
        assert_eq!(
            parse_route("/alice"),
            Route::OwnerIndex { owner: "alice".into() }
        );
        assert_eq!(
            parse_route("/alice/myrepo"),
            Route::RepoOverview {
                owner: "alice".into(),
                repo: "myrepo".into()
            }
        );
        // `.git` suffix on the browse URL is normalised away.
        assert_eq!(
            parse_route("/alice/myrepo.git"),
            Route::RepoOverview {
                owner: "alice".into(),
                repo: "myrepo".into()
            }
        );
    }

    #[test]
    fn tree_blob_raw_split_rev_and_path() {
        assert_eq!(
            parse_route("/alice/repo/tree/main/src/lib.rs"),
            Route::Tree {
                owner: "alice".into(),
                repo: "repo".into(),
                rev: "main".into(),
                path: "src/lib.rs".into()
            }
        );
        assert_eq!(
            parse_route("/alice/repo/tree/main"),
            Route::Tree {
                owner: "alice".into(),
                repo: "repo".into(),
                rev: "main".into(),
                path: String::new()
            }
        );
        assert_eq!(
            parse_route("/alice/repo/raw/main/bin/data"),
            Route::Raw {
                owner: "alice".into(),
                repo: "repo".into(),
                rev: "main".into(),
                path: "bin/data".into()
            }
        );
    }

    #[test]
    fn commit_and_commits() {
        assert_eq!(
            parse_route("/alice/repo/commits/main"),
            Route::Commits {
                owner: "alice".into(),
                repo: "repo".into(),
                rev: "main".into()
            }
        );
        assert_eq!(
            parse_route("/alice/repo/commit/deadbeef"),
            Route::Commit {
                owner: "alice".into(),
                repo: "repo".into(),
                sha: "deadbeef".into()
            }
        );
    }

    #[test]
    fn issues_routes() {
        assert_eq!(
            parse_route("/alice/repo/issues"),
            Route::Issues {
                owner: "alice".into(),
                repo: "repo".into()
            }
        );
        assert_eq!(
            parse_route("/alice/repo/issues/new"),
            Route::IssueNew {
                owner: "alice".into(),
                repo: "repo".into()
            }
        );
        assert_eq!(
            parse_route("/alice/repo/issues/42"),
            Route::IssueDetail {
                owner: "alice".into(),
                repo: "repo".into(),
                num: 42
            }
        );
        assert_eq!(parse_route("/alice/repo/issues/notanum"), Route::NotFound);
    }

    #[test]
    fn api_routes() {
        assert_eq!(parse_route("/api/token"), Route::ApiToken);
        assert_eq!(parse_route("/api/repos"), Route::ApiReposList);
        assert_eq!(
            parse_route("/api/repos/alice/repo"),
            Route::ApiRepo {
                owner: "alice".into(),
                repo: "repo".into()
            }
        );
        assert_eq!(
            parse_route("/api/hosted/abc/xyz"),
            Route::ApiHosted {
                hex: "abc".into(),
                id: "xyz".into()
            }
        );
    }

    #[test]
    fn unknown_is_not_found() {
        assert_eq!(parse_route("/alice/repo/bogusverb/x"), Route::NotFound);
        assert_eq!(parse_route("/api/unknown"), Route::NotFound);
    }
}
