//! In-repo code search: a bounded, unindexed `git grep` over the default
//! branch, plus path-name matches.
//!
//! Follows the JSS `forge` `searchData` / `searchPage` / `apiSearch`
//! behaviour (cited by name only). The query is a literal, case-insensitive
//! substring (`git grep -I -n -i -F -z -e <q>`): argv only, never a shell,
//! never a regex, and the query always follows `-e` so it cannot be read as
//! an option. Bounds: query 256 chars, 100 hits, 100 path matches, 5 hits per
//! file, 200-char excerpts.

use std::path::Path;

use serde::Serialize;
use serde_json::json;

use crate::api::{api_err, json_resp};
use crate::error::ForgeError;
use crate::guard::ok_ref;
use crate::request::{percent_decode, ForgeRequest, ForgeResponse};
use crate::{gitrun, html, ForgeService};

/// Maximum query length in characters.
pub const SEARCH_QUERY_CAP: usize = 256;
/// Maximum returned grep hits.
pub const SEARCH_HIT_CAP: usize = 100;
/// Maximum returned path matches.
pub const SEARCH_PATH_CAP: usize = 100;
/// `git grep --max-count` per file.
pub const SEARCH_PER_FILE_CAP: usize = 5;
/// Characters kept of each matching line.
pub const SEARCH_EXCERPT_CAP: usize = 200;
/// Ceiling on `git grep` output we are willing to buffer.
const GREP_OUTPUT_CAP: usize = 8 * 1024 * 1024;

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchMatch {
    /// Repo-relative file path.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// The line, cut to [`SEARCH_EXCERPT_CAP`] characters.
    pub text: String,
}

/// The result of one search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchResult {
    /// The query as searched.
    pub q: String,
    /// The branch searched.
    #[serde(rename = "ref")]
    pub rev: String,
    /// File paths whose name contains the query.
    pub paths: Vec<String>,
    /// Matching lines.
    pub matches: Vec<SearchMatch>,
    /// `true` when a cap cut the result short.
    pub truncated: bool,
}

/// Parse the NUL-framed `git grep -z -n` output (`<tree>:<path>\0<line>\0<text>\n`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::search::parse_grep;
///
/// let (m, truncated) = parse_grep("main:docs/a:b.txt\u{0}3\u{0}hello\nmain:x\u{0}1\u{0}y\n");
/// assert_eq!(m[0].path, "docs/a:b.txt");
/// assert_eq!(m[0].line, 3);
/// assert_eq!(m[1].text, "y");
/// assert!(!truncated);
/// ```
#[must_use]
pub fn parse_grep(raw: &str) -> (Vec<SearchMatch>, bool) {
    let mut out = Vec::new();
    for line in raw.split('\n') {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\0');
        let tree_path = parts.next().unwrap_or("");
        let Some(line_no) = parts.next() else {
            continue;
        };
        if out.len() >= SEARCH_HIT_CAP {
            return (out, true);
        }
        let text: Vec<&str> = parts.collect();
        let text = text.join("\0");
        let path = tree_path
            .split_once(':')
            .map_or(tree_path, |(_, p)| p)
            .to_string();
        out.push(SearchMatch {
            path,
            line: line_no.parse().unwrap_or(0),
            text: text.chars().take(SEARCH_EXCERPT_CAP).collect(),
        });
    }
    (out, false)
}

/// Run a search over `branch` of the bare repo at `dir`.
///
/// # Errors
///
/// [`ForgeError::Io`] / [`ForgeError::Unsupported`] when git cannot be run.
/// An empty repository or no match is an empty result, not an error.
pub async fn search_data(dir: &Path, branch: &str, q: &str) -> Result<SearchResult, ForgeError> {
    let mut res = SearchResult {
        q: q.to_string(),
        rev: branch.to_string(),
        paths: Vec::new(),
        matches: Vec::new(),
        truncated: false,
    };
    if !ok_ref(branch) {
        return Ok(res);
    }
    let needle = q.to_lowercase();
    if let Ok(o) = gitrun::run(
        dir,
        &["ls-tree", "-r", "--name-only", "-z", branch],
        32 * 1024 * 1024,
    )
    .await
    {
        if o.code == Some(0) {
            for p in String::from_utf8_lossy(&o.stdout).split('\0') {
                if p.is_empty() || !p.to_lowercase().contains(&needle) {
                    continue;
                }
                if res.paths.len() >= SEARCH_PATH_CAP {
                    res.truncated = true;
                    break;
                }
                res.paths.push(p.to_string());
            }
        }
    }
    let max = format!("--max-count={SEARCH_PER_FILE_CAP}");
    let mut args = vec![
        "grep",
        "-I",
        "-n",
        "-i",
        "-F",
        "-z",
        max.as_str(),
        "-e",
        q,
        branch,
        "--",
    ];
    let mut o = gitrun::run_heavy(dir, &args, GREP_OUTPUT_CAP).await?;
    if o.code.is_some_and(|c| c >= 2) && o.stderr.contains("max-count") {
        // git older than 2.38: no per-file cap, the total cap still holds.
        args.remove(6);
        o = gitrun::run_heavy(dir, &args, GREP_OUTPUT_CAP).await?;
    }
    // Exit 1 is "no match": an empty result, not an error. Anything else
    // (empty repo, unknown branch) is also an empty result.
    if o.code == Some(0) || o.truncated {
        let (matches, cut) = parse_grep(&String::from_utf8_lossy(&o.stdout));
        res.matches = matches;
        res.truncated |= cut || o.truncated;
    }
    Ok(res)
}

/// Normalise a raw query value: percent-decode, trim.
fn clean_query(req: &ForgeRequest) -> String {
    req.query_param("q")
        .map(|v| percent_decode(&v).trim().to_string())
        .unwrap_or_default()
}

impl ForgeService {
    /// `GET /api/repos/<o>/<r>/search?q=` (JSS `apiSearch`).
    pub(crate) async fn api_search(
        &self,
        req: &ForgeRequest,
        dir: &Path,
    ) -> Result<ForgeResponse, ForgeError> {
        let q = clean_query(req);
        if q.is_empty() {
            return Ok(api_err(422, "q required"));
        }
        if q.chars().count() > SEARCH_QUERY_CAP {
            return Ok(api_err(
                422,
                &format!("q too long (max {SEARCH_QUERY_CAP} chars)"),
            ));
        }
        if q.contains('\0') {
            return Ok(api_err(422, "q contains an invalid character"));
        }
        let branch = crate::repo::browse::default_branch(dir).await;
        let r = search_data(dir, &branch, &q).await?;
        Ok(json_resp(200, &json!(r)))
    }

    /// `GET /<owner>/<repo>/search?q=` (JSS `searchPage`).
    pub(crate) async fn h_search_page(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let q: String = clean_query(req)
            .chars()
            .filter(|c| *c != '\0')
            .take(SEARCH_QUERY_CAP)
            .collect();
        let branch = crate::repo::browse::default_branch(&dir).await;
        let data = if q.is_empty() {
            None
        } else {
            Some(search_data(&dir, &branch, &q).await?)
        };
        Ok(ForgeResponse::html(
            200,
            html::search_page(&self.prefix(), owner, repo, &branch, &q, data.as_ref()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::{fixture, get_json, rq};
    use crate::ownership::ForgeAgent;

    #[test]
    fn grep_parser_caps_hits_and_excerpts() {
        let long = "x".repeat(500);
        let mut raw = String::new();
        for i in 0..150 {
            raw.push_str(&format!("main:f{i}.txt\u{0}{i}\u{0}{long}\n"));
        }
        let (m, truncated) = parse_grep(&raw);
        assert_eq!(m.len(), SEARCH_HIT_CAP);
        assert!(truncated);
        assert_eq!(m[0].text.chars().count(), SEARCH_EXCERPT_CAP);
        // multibyte text is cut on a char boundary, not a byte boundary
        let uni = "é".repeat(300);
        let (m, _) = parse_grep(&format!("main:f\u{0}1\u{0}{uni}\n"));
        assert_eq!(m[0].text.chars().count(), SEARCH_EXCERPT_CAP);
    }

    // JSS "in-repo search greps the default branch: path + line + excerpt, bounded shape"
    #[tokio::test]
    async fn api_search_finds_line_and_path() {
        let (_td, svc, _) = fixture();
        let (st, s) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=subdir",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(s["q"], "subdir");
        assert_eq!(s["ref"], "main");
        assert_eq!(s["truncated"], false);
        assert!(s["paths"].is_array());
        let hit = s["matches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["path"] == "docs/notes.txt")
            .expect("known string found");
        assert_eq!(hit["line"], 1);
        assert!(hit["text"]
            .as_str()
            .unwrap()
            .contains("notes live in a subdir"));
        let (_, p) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=notes",
            ForgeAgent::Anonymous,
        )
        .await;
        assert!(p["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "docs/notes.txt"));
        let (st, _) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 422, "q is required on the api");
    }

    // JSS "search misses cleanly"
    #[tokio::test]
    async fn search_miss_is_empty_not_error() {
        let (_td, svc, _) = fixture();
        let (st, m) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=zqxjkwv",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(m["paths"], json!([]));
        assert_eq!(m["matches"], json!([]));
        let r = svc
            .handle(
                rq("GET", "/forge/casey/demo/search", "q=zqxjkwv", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&r.body).contains("No results"));
    }

    #[tokio::test]
    async fn query_is_literal_bounded_and_option_safe() {
        let (_td, svc, _) = fixture();
        // a regex metacharacter is a literal: `.*` matches nothing here
        let (_, m) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=.*",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(m["matches"], json!([]));
        // an option-looking query is just text
        let (st, m) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=--open-files-in-pager%3Ctouch%20x%3E",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(m["matches"], json!([]));
        let (st, _) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            &format!("q={}", "a".repeat(257)),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 422);
        let (st, _) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            "q=a%00b",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 422);
        let (st, ok) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/search",
            &format!("q={}", "a".repeat(256)),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(ok["matches"], json!([]));
    }

    // JSS HTML search page: line-anchored links, escaped query and excerpts
    #[tokio::test]
    async fn html_search_page_is_escaped_and_line_anchored() {
        let (_td, svc, _) = fixture();
        let page = |q: &str| {
            let svc = svc.clone();
            let q = q.to_string();
            async move {
                let r = svc
                    .handle(
                        rq("GET", "/forge/casey/demo/search", &format!("q={q}"), ""),
                        ForgeAgent::Anonymous,
                    )
                    .await
                    .unwrap();
                String::from_utf8_lossy(&r.body).into_owned()
            }
        };
        let h = page("subdir").await;
        assert!(h.contains("docs/notes.txt"));
        assert!(h.contains("#L1"));
        assert!(h.contains("notes live in a subdir"));
        let evil = page("%3Cscript%3Ealert(9)%3C%2Fscript%3E").await;
        assert!(!evil.contains("<script>alert(9)"));
        assert!(evil.contains("&lt;script&gt;alert(9)"));
        let x = page("%3Cscript%3E").await;
        assert!(
            x.contains("&lt;script&gt;"),
            "matching excerpt visible, escaped"
        );
        assert!(!x.contains("<script>alert"));
        let empty = page("").await;
        assert!(empty.contains("name=\"q\""));
    }

    #[tokio::test]
    async fn empty_repo_search_is_empty() {
        let td = tempfile::TempDir::new().unwrap();
        let svc = ForgeService::new(crate::ForgeConfig::default(), td.path()).unwrap();
        let bare = td.path().join("repos/casey/blank.git");
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        crate::gitrun::testutil::git(
            td.path(),
            &["init", "--bare", "--quiet", bare.to_str().unwrap()],
        );
        let (st, m) = get_json(
            &svc,
            "/forge/api/repos/casey/blank/search",
            "q=x",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(m["matches"], json!([]));
    }
}
