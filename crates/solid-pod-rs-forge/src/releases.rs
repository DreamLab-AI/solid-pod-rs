//! Releases (every tag, newest first) and `git archive` downloads.
//!
//! Follows the JSS `forge` `listReleases`, `releasesPage`, `apiReleases` and
//! `archiveResp` behaviour (cited by name only). The archive ref is validated
//! with [`crate::guard`] and resolved to a commit **before** anything is sent,
//! so a bogus ref is a clean `404`; the archive command is argv-only.
//!
//! Divergence from JSS: [`crate::ForgeResponse`] carries a [`bytes::Bytes`]
//! body, so the archive is buffered (up to [`ARCHIVE_CAP`]) rather than piped
//! through; larger archives are refused with `413`.

use std::path::Path;

use serde::Serialize;
use serde_json::json;

use crate::api::{api_err, json_resp};
use crate::error::ForgeError;
use crate::guard::{is_sha, ok_ref};
use crate::request::{ForgeRequest, ForgeResponse};
use crate::{gitrun, html, ForgeService};

/// Largest archive the forge will buffer into one response.
pub const ARCHIVE_CAP: usize = 256 * 1024 * 1024;

/// One release (a tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Release {
    /// Tag name.
    pub tag: String,
    /// The commit the tag points at (peeled for annotated tags).
    pub sha: String,
    /// Creator date, unix seconds.
    pub at: i64,
    /// `true` for an annotated tag.
    pub annotated: bool,
    /// First line of the tag message (annotated tags only).
    pub message: Option<String>,
    /// Relative `tar.gz` download URL.
    pub tarball: String,
    /// Relative `zip` download URL.
    pub zipball: String,
}

/// Parse the NUL-delimited `for-each-ref` rows (`tag, objecttype, creatordate,
/// objectname, peeled objectname, subject`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::releases::parse_releases;
///
/// let raw = "v2.0\u{0}tag\u{0}200\u{0}tagobj\u{0}commitsha\u{0}Second release\nv1.0\u{0}commit\u{0}100\u{0}c1\u{0}\u{0}old\n";
/// let r = parse_releases(raw, "/forge/casey/demo");
/// assert_eq!(r[0].sha, "commitsha");
/// assert_eq!(r[0].message.as_deref(), Some("Second release"));
/// assert!(!r[1].annotated && r[1].message.is_none());
/// assert_eq!(r[1].tarball, "/forge/casey/demo/archive/v1.0.tar.gz");
/// ```
#[must_use]
pub fn parse_releases(raw: &str, base: &str) -> Vec<Release> {
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut f = l.split('\0');
            let tag = f.next().unwrap_or("").to_string();
            let otype = f.next().unwrap_or("");
            let at = f.next().and_then(|n| n.parse().ok()).unwrap_or(0);
            let oname = f.next().unwrap_or("");
            let peeled = f.next().unwrap_or("");
            let subject = f.next().unwrap_or("");
            let annotated = otype == "tag";
            Release {
                sha: if annotated && !peeled.is_empty() {
                    peeled.to_string()
                } else {
                    oname.to_string()
                },
                at,
                annotated,
                message: annotated.then(|| subject.to_string()),
                tarball: format!("{base}/archive/{tag}.tar.gz"),
                zipball: format!("{base}/archive/{tag}.zip"),
                tag,
            }
        })
        .collect()
}

/// Every tag of the bare repo at `dir`, newest first.
///
/// # Errors
///
/// Git failures other than "no tags" bubble up.
pub async fn list_releases(dir: &Path, base: &str) -> Result<Vec<Release>, ForgeError> {
    let out = gitrun::text(
        dir,
        &[
            "for-each-ref",
            "--sort=-creatordate",
            "refs/tags",
            "--format=%(refname:short)%00%(objecttype)%00%(creatordate:unix)%00%(objectname)%00%(*objectname)%00%(contents:subject)",
        ],
    )
    .await?;
    Ok(parse_releases(&out, base))
}

/// Split `<ref>.tar.gz` / `<ref>.zip` into `(ref, format, extension)`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::releases::split_archive_spec;
/// assert_eq!(split_archive_spec("v2.0.tar.gz"), Some(("v2.0", "tar.gz", ".tar.gz")));
/// assert_eq!(split_archive_spec("feature/x.zip"), Some(("feature/x", "zip", ".zip")));
/// assert_eq!(split_archive_spec("v2.0.rar"), None);
/// ```
#[must_use]
pub fn split_archive_spec(spec: &str) -> Option<(&str, &'static str, &'static str)> {
    if let Some(r) = spec.strip_suffix(".tar.gz") {
        Some((r, "tar.gz", ".tar.gz"))
    } else {
        spec.strip_suffix(".zip").map(|r| (r, "zip", ".zip"))
    }
}

impl ForgeService {
    pub(crate) async fn api_releases(
        &self,
        _req: &ForgeRequest,
        owner: &str,
        repo: &str,
        dir: &Path,
    ) -> Result<ForgeResponse, ForgeError> {
        let base = format!("{}/{owner}/{repo}", self.prefix());
        let rels = list_releases(dir, &base).await?;
        Ok(json_resp(200, &json!({ "releases": rels })))
    }

    /// `GET /<owner>/<repo>/releases` (JSS `releasesPage`).
    pub(crate) async fn h_releases_page(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let base = format!("{}/{owner}/{repo}", self.prefix());
        let rels = list_releases(&dir, &base).await.unwrap_or_default();
        Ok(ForgeResponse::html(
            200,
            html::releases_page(&self.prefix(), owner, repo, &rels),
        ))
    }

    /// `GET /<owner>/<repo>/archive/<ref>.tar.gz|.zip` (JSS `archiveResp`).
    pub(crate) async fn h_archive(
        &self,
        owner: &str,
        repo: &str,
        spec: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let Some((rev, format, ext)) = split_archive_spec(spec) else {
            return Err(ForgeError::NotFound("archive".into()));
        };
        if !ok_ref(rev) && !is_sha(rev) {
            return Err(ForgeError::NotFound("archive ref".into()));
        }
        let commit = format!("{rev}^{{commit}}");
        let resolved =
            gitrun::run(&dir, &["rev-parse", "--verify", "--quiet", &commit], 1024).await?;
        if resolved.code != Some(0) {
            return Err(ForgeError::NotFound("archive ref".into()));
        }
        let flat = rev.replace('/', "-");
        let prefix_arg = format!("--prefix={repo}-{flat}/");
        let fmt_arg = format!("--format={format}");
        let o =
            gitrun::run_heavy(&dir, &["archive", &fmt_arg, &prefix_arg, rev], ARCHIVE_CAP).await?;
        if o.truncated {
            return Ok(api_err(413, "archive too large"));
        }
        if o.code != Some(0) {
            tracing::warn!(
                "forge: git archive {owner}/{repo} {rev} exited {:?}: {}",
                o.code,
                o.stderr.trim()
            );
            return Err(ForgeError::NotFound("archive".into()));
        }
        let ct = if format == "zip" {
            "application/zip"
        } else {
            "application/gzip"
        };
        Ok(
            ForgeResponse::with_type(200, ct, bytes::Bytes::from(o.stdout))
                .with_header(
                    "content-disposition",
                    &format!("attachment; filename=\"{repo}-{flat}{ext}\""),
                )
                .with_header("x-content-type-options", "nosniff"),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::api::tests::{fixture, get_json, rq};
    use crate::gitrun::testutil::git;
    use crate::ownership::ForgeAgent;

    fn tag_v2(td: &tempfile::TempDir) {
        // annotated tag created in the bare repo itself
        let bare = td.path().join("repos/casey/demo.git");
        git(
            &bare,
            &[
                "tag",
                "-a",
                "v2.0",
                "-m",
                "Second release with search",
                "main",
            ],
        );
    }

    // JSS "releases: every tag newest first, annotated message shown, download links"
    #[tokio::test]
    async fn releases_list_newest_first_with_links() {
        let (td, svc, _) = fixture();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        tag_v2(&td);
        let (st, v) = get_json(
            &svc,
            "/forge/api/repos/casey/demo/releases",
            "",
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(st, 200);
        let rels = v["releases"].as_array().unwrap();
        let tags: Vec<&str> = rels.iter().map(|r| r["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, vec!["v2.0", "v1.0"]);
        assert_eq!(rels[0]["annotated"], true);
        assert_eq!(rels[0]["message"], "Second release with search");
        assert_eq!(rels[1]["annotated"], false);
        assert!(rels[1]["message"].is_null());
        let sha = rels[0]["sha"].as_str().unwrap();
        assert!(
            sha.len() >= 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
            "peeled to the commit sha"
        );
        assert_eq!(rels[0]["tarball"], "/forge/casey/demo/archive/v2.0.tar.gz");
        assert_eq!(rels[0]["zipball"], "/forge/casey/demo/archive/v2.0.zip");
        let page = svc
            .handle(
                rq("GET", "/forge/casey/demo/releases", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        let h = String::from_utf8_lossy(&page.body).into_owned();
        assert!(h.contains("v2.0") && h.contains("Second release with search"));
        assert!(h.contains("archive/v2.0.tar.gz") && h.contains("archive/v1.0.zip"));
        let tags = svc
            .handle(
                rq("GET", "/forge/casey/demo/tags", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&tags.body).contains("href=\"/forge/casey/demo/releases\""));
    }

    // JSS "archive tar.gz streams, and a real tar round-trips a known file"
    #[tokio::test]
    async fn tar_gz_archive_round_trips_a_file() {
        let (td, svc, _) = fixture();
        tag_v2(&td);
        let r = svc
            .handle(
                rq("GET", "/forge/casey/demo/archive/v2.0.tar.gz", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let hv = |n: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert!(hv("content-type").starts_with("application/gzip"));
        assert!(hv("content-disposition").contains("attachment; filename=\"demo-v2.0.tar.gz\""));
        let tarball = td.path().join("demo-v2.0.tar.gz");
        std::fs::write(&tarball, &r.body).unwrap();
        let out = td.path().join("extract");
        std::fs::create_dir_all(&out).unwrap();
        let st = std::process::Command::new("tar")
            .args([
                "-xzf",
                tarball.to_str().unwrap(),
                "-C",
                out.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(st.success());
        assert_eq!(
            std::fs::read_to_string(out.join("demo-v2.0/docs/notes.txt")).unwrap(),
            "notes live in a subdir\n"
        );
    }

    // JSS "archive zip has the right content-type and disposition; bogus refs are 404"
    #[tokio::test]
    async fn zip_headers_and_bogus_refs() {
        let (_td, svc, _) = fixture();
        let r = svc
            .handle(
                rq("GET", "/forge/casey/demo/archive/main.zip", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v.starts_with("application/zip")));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "content-disposition" && v.contains("filename=\"demo-main.zip\"")));
        assert_eq!(&r.body[..2], b"PK");
        for (p, want) in [
            ("/forge/casey/demo/archive/nosuchtag.tar.gz", 404),
            ("/forge/casey/demo/archive/v1.0.rar", 404),
            ("/forge/casey/demo/archive/--output=x.tar.gz", 404),
        ] {
            let r = svc
                .handle(rq("GET", p, "", ""), ForgeAgent::Anonymous)
                .await
                .unwrap();
            assert_eq!(r.status, want, "{p}");
        }
        let evil = svc
            .handle(
                rq("GET", "/forge/casey/demo/archive/..%2fmain.tar.gz", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert!((400..500).contains(&evil.status));
        let dots = svc
            .handle(
                rq("GET", "/forge/casey/demo/archive/../main.tar.gz", "", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert!((400..500).contains(&dots.status));
    }
}
