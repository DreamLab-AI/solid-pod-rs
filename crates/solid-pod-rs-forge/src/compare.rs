//! Compare: resolve a base and a (possibly cross-fork) head, then report
//! ahead/behind counts, the commit list and a structured diff.
//!
//! Behaviour follows the JSS forge `compareData`, `resolveHead`,
//! `parseHeadSpec`, `parsePatch` and `renderDiff` (cited by name only). A head
//! is either a branch of the same repository (`feature`) or `<owner>:<ref>`, a
//! branch of the named owner's same-named repository. A cross-repository head
//! is path-fetched into the base repository under the hidden, reusable ref
//! `refs/forge/heads/<owner>/<ref>`; both ends of the fetch are forge-owned
//! paths and no user-supplied URL is ever fetched.

use std::path::Path;

use serde::Serialize;

use crate::error::ForgeError;
use crate::forks;
use crate::html::{agent_label, crumbs, page};
use crate::prgit;
use crate::repo;
use crate::request::{esc, percent_decode};
use crate::{ForgeRequest, ForgeResponse, ForgeService};

/// Commits per page in compare and pull commit lists (JSS `PER_PAGE`).
pub const COMMITS_PER_PAGE: usize = 30;

/// Longest accepted head spec (`owner:ref`), as in JSS `parseHeadSpec`.
const HEAD_SPEC_MAX: usize = 320;

/// JSS `OWNER_NAME`: alphanumeric first, then `[A-Za-z0-9._-]`, at most 64.
#[must_use]
pub fn valid_owner(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !s.contains("..")
}

/// JSS `REPO_NAME` (at most 128) tightened to the crate's 100-character
/// directory limit, with no `..` and no `.git` suffix.
#[must_use]
pub fn valid_repo(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 100
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && !s.contains("..")
        && !s.ends_with(".git")
}

/// JSS `okRef`: alphanumeric first, then `[A-Za-z0-9._/-]` (at most 201), no
/// `..`, no `//`, no trailing `/`. Additionally refuses a trailing `.lock` or
/// `.`, which git itself would reject, so a branch name can never address a
/// lock file. A leading `-` is impossible, so it can never be read as an option.
#[must_use]
pub fn valid_ref(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 201
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        && !s.contains("..")
        && !s.contains("//")
        && !s.ends_with('/')
        && !s.ends_with('.')
        && !s.ends_with(".lock")
        && !s.contains("/.")
        && !s.contains(".lock/")
}

/// JSS `SHA_RE`: 4 to 64 lowercase hexadecimal characters.
#[must_use]
pub fn valid_sha(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse `ref` or `owner:ref` against the base owner. `None` when invalid.
#[must_use]
pub fn parse_head_spec(base_owner: &str, spec: &str) -> Option<(String, String)> {
    if spec.len() > HEAD_SPEC_MAX {
        return None;
    }
    let (owner, r) = match spec.split_once(':') {
        Some((o, r)) => (o, r),
        None => (base_owner, spec),
    };
    if !valid_owner(owner) || !valid_ref(r) {
        return None;
    }
    Some((owner.to_string(), r.to_string()))
}

/// A resolved compare/PR head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadRef {
    /// Owner namespace of the head repository.
    pub owner: String,
    /// Head repository name (always the base repository's name).
    pub repo: String,
    /// Branch name.
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// Resolved commit id.
    pub sha: String,
}

/// One commit in a compare/PR list (JSS `commitLog` shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommitSummary {
    /// Full object id.
    pub sha: String,
    /// Abbreviated id.
    pub short: String,
    /// Author name.
    pub author: String,
    /// Author email.
    pub email: String,
    /// Author time, Unix seconds.
    pub at: i64,
    /// Subject line.
    pub subject: String,
}

/// Kind of one diff line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LineKind {
    /// Added line.
    Add,
    /// Deleted line.
    Del,
    /// Context line.
    Ctx,
    /// `\ No newline at end of file` marker.
    Meta,
}

/// One diff line with its old/new numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    /// Line kind.
    #[serde(rename = "type")]
    pub kind: LineKind,
    /// Line number in the old file.
    pub old_line: Option<u64>,
    /// Line number in the new file.
    pub new_line: Option<u64>,
    /// Text without the leading marker.
    pub text: String,
}

/// One `@@` hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hunk {
    /// The `@@ -a,b +c,d @@` header line.
    pub header: String,
    /// Lines of the hunk.
    pub lines: Vec<DiffLine>,
}

/// One file of a structured diff (JSS `parsePatch` shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffFile {
    /// New path (old path for a deletion).
    pub name: Option<String>,
    /// `true` for a binary change.
    pub binary: bool,
    /// Added line count.
    pub adds: u64,
    /// Deleted line count.
    pub dels: u64,
    /// Hunks.
    pub hunks: Vec<Hunk>,
}

fn parse_hunk_header(line: &str) -> Option<(u64, u64, u64, u64)> {
    let rest = line.strip_prefix("@@ -")?;
    let (old, rest) = rest.split_once(" +")?;
    let (new, _) = rest.split_once(" @@")?;
    let pair = |s: &str| -> Option<(u64, u64)> {
        match s.split_once(',') {
            Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
            None => Some((s.parse().ok()?, 1)),
        }
    };
    let (os, oc) = pair(old)?;
    let (ns, nc) = pair(new)?;
    Some((os, oc, ns, nc))
}

/// Parse unified `git diff` output into a structured per-file form, as JSS
/// `parsePatch` does. Unlike the JSS parser, hunk bodies are consumed by the
/// line counts in their `@@` header, so a content line that happens to start
/// with `+++ ` or `--- ` is classified as content, not as a file header.
#[must_use]
pub fn parse_patch(patch: &str) -> Vec<DiffFile> {
    let mut files: Vec<DiffFile> = Vec::new();
    let (mut old_left, mut new_left) = (0u64, 0u64);
    let (mut old_n, mut new_n) = (0u64, 0u64);
    for line in patch.split('\n') {
        let in_hunk = old_left > 0 || new_left > 0;
        if !in_hunk && line.starts_with("diff --git ") {
            let name = line
                .strip_prefix("diff --git a/")
                .and_then(|r| r.rsplit_once(" b/"))
                .map(|(_, b)| b.to_string());
            files.push(DiffFile {
                name,
                binary: false,
                adds: 0,
                dels: 0,
                hunks: Vec::new(),
            });
            continue;
        }
        let Some(cur) = files.last_mut() else {
            continue;
        };
        if in_hunk {
            let hunk = cur.hunks.last_mut().expect("hunk open");
            if let Some(t) = line.strip_prefix('+') {
                hunk.lines.push(DiffLine {
                    kind: LineKind::Add,
                    old_line: None,
                    new_line: Some(new_n),
                    text: t.to_string(),
                });
                new_n += 1;
                new_left = new_left.saturating_sub(1);
                cur.adds += 1;
            } else if let Some(t) = line.strip_prefix('-') {
                hunk.lines.push(DiffLine {
                    kind: LineKind::Del,
                    old_line: Some(old_n),
                    new_line: None,
                    text: t.to_string(),
                });
                old_n += 1;
                old_left = old_left.saturating_sub(1);
                cur.dels += 1;
            } else if let Some(t) = line.strip_prefix(' ') {
                hunk.lines.push(DiffLine {
                    kind: LineKind::Ctx,
                    old_line: Some(old_n),
                    new_line: Some(new_n),
                    text: t.to_string(),
                });
                old_n += 1;
                new_n += 1;
                old_left = old_left.saturating_sub(1);
                new_left = new_left.saturating_sub(1);
            } else if line.starts_with('\\') {
                hunk.lines.push(DiffLine {
                    kind: LineKind::Meta,
                    old_line: None,
                    new_line: None,
                    text: line.to_string(),
                });
            }
            continue;
        }
        if let Some(n) = line.strip_prefix("+++ ") {
            if n != "/dev/null" {
                cur.name = Some(n.strip_prefix("b/").unwrap_or(n).to_string());
            }
        } else if let Some(n) = line.strip_prefix("--- ") {
            if cur.name.is_none() && n != "/dev/null" {
                cur.name = Some(n.strip_prefix("a/").unwrap_or(n).to_string());
            }
        } else if line.starts_with("Binary files") {
            cur.binary = true;
        } else if let Some((os, oc, ns, nc)) = parse_hunk_header(line) {
            old_n = os;
            new_n = ns;
            old_left = oc;
            new_left = nc;
            cur.hunks.push(Hunk {
                header: line.to_string(),
                lines: Vec::new(),
            });
        } else if line.starts_with('\\') {
            if let Some(h) = cur.hunks.last_mut() {
                h.lines.push(DiffLine {
                    kind: LineKind::Meta,
                    old_line: None,
                    new_line: None,
                    text: line.to_string(),
                });
            }
        }
    }
    files
}

/// Render a structured diff as escaped HTML tables (JSS `renderDiff`).
#[must_use]
pub fn render_diff(files: &[DiffFile]) -> String {
    if files.is_empty() {
        return "<p class=\"muted\">No changes.</p>".to_string();
    }
    let mut out = String::new();
    for f in files {
        let name = esc(f.name.as_deref().unwrap_or("(unknown)"));
        out.push_str(&format!(
            "<details class=\"dfile\" open><summary class=\"dhead\"><span class=\"fname\">{name}</span>\
<span class=\"counts\"><span class=\"adds\">+{}</span> <span class=\"dels\">&minus;{}</span></span></summary>",
            f.adds, f.dels
        ));
        if f.binary {
            out.push_str("<div class=\"dbinary muted\">Binary file not shown.</div>");
        } else {
            out.push_str("<table class=\"diff\">");
            for h in &f.hunks {
                out.push_str(&format!(
                    "<tr class=\"hunk\"><td class=\"num\" colspan=\"2\"></td><td class=\"code\">{}</td></tr>",
                    esc(&h.header)
                ));
                for l in &h.lines {
                    let num = |n: Option<u64>| n.map(|v| v.to_string()).unwrap_or_default();
                    match l.kind {
                        LineKind::Meta => out.push_str(&format!(
                            "<tr class=\"ctx\"><td class=\"num\" colspan=\"2\"></td><td class=\"code muted\">{}</td></tr>",
                            esc(&l.text)
                        )),
                        k => {
                            let (cls, sign) = match k {
                                LineKind::Add => ("add", '+'),
                                LineKind::Del => ("del", '-'),
                                _ => ("ctx", ' '),
                            };
                            out.push_str(&format!(
                                "<tr class=\"{cls}\"><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"code\">{sign}{}</td></tr>",
                                num(l.old_line),
                                num(l.new_line),
                                esc(&l.text)
                            ));
                        }
                    }
                }
            }
            out.push_str("</table>");
        }
        out.push_str("</details>\n");
    }
    out
}

/// Commits in `range` (a `base..head` range of two validated object ids),
/// newest first, with a `has_more` flag for the page boundary.
pub(crate) async fn commit_range(
    dir: &Path,
    base_sha: &str,
    head_sha: &str,
) -> Result<(Vec<CommitSummary>, bool), ForgeError> {
    if !valid_sha(base_sha) || !valid_sha(head_sha) {
        return Err(ForgeError::BadRequest(
            "range ends must be object ids".into(),
        ));
    }
    let range = format!("{base_sha}..{head_sha}");
    let n = format!("-n{}", COMMITS_PER_PAGE + 1);
    let out = prgit::text(
        dir,
        &[
            "log",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            &n,
            "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s",
            &range,
        ],
    )
    .await?;
    let fields: Vec<&str> = out.split('\0').collect();
    let mut commits = Vec::new();
    let mut i = 0;
    while i + 5 < fields.len() {
        commits.push(CommitSummary {
            sha: fields[i].trim_start_matches('\n').to_string(),
            short: fields[i + 1].to_string(),
            author: fields[i + 2].to_string(),
            email: fields[i + 3].to_string(),
            at: fields[i + 4].parse().unwrap_or(0),
            subject: fields[i + 5].to_string(),
        });
        i += 6;
    }
    let more = commits.len() > COMMITS_PER_PAGE;
    commits.truncate(COMMITS_PER_PAGE);
    Ok((commits, more))
}

/// Structured diff between `merge_base` (or `base_sha`) and `head_sha`.
pub(crate) async fn diff_files(
    dir: &Path,
    merge_base: Option<&str>,
    base_sha: &str,
    head_sha: &str,
) -> Vec<DiffFile> {
    let from = merge_base.unwrap_or(base_sha);
    if !valid_sha(from) || !valid_sha(head_sha) {
        return Vec::new();
    }
    let patch = prgit::text(
        dir,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            from,
            head_sha,
        ],
    )
    .await
    .unwrap_or_default();
    parse_patch(&patch)
}

/// Everything a compare view needs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Compare {
    /// Base ref as requested.
    pub base_ref: String,
    /// Base commit id.
    pub base_sha: String,
    /// Resolved head.
    pub head: HeadRef,
    /// Commits in head not in base.
    pub ahead_by: u64,
    /// Commits in base not in head.
    pub behind_by: u64,
    /// Merge base, when the histories are related.
    pub merge_base: Option<String>,
    /// First page of ahead commits.
    pub commits: Vec<CommitSummary>,
    /// More commits than one page.
    pub has_more: bool,
    /// Structured diff.
    pub files: Vec<DiffFile>,
}

impl ForgeService {
    /// Resolve a compare/PR head (JSS `resolveHead`). `Ok(None)` for any
    /// invalid, missing or unfetchable head; the caller answers 404 or 422.
    pub(crate) async fn resolve_head(
        &self,
        base_owner: &str,
        name: &str,
        spec: &str,
    ) -> Result<Option<HeadRef>, ForgeError> {
        let Some((owner, r)) = parse_head_spec(base_owner, spec) else {
            return Ok(None);
        };
        if !valid_repo(name) {
            return Ok(None);
        }
        let dir = repo::repo_git_dir(&self.repo_root, base_owner, name)?;
        let make = |sha: String| HeadRef {
            owner: owner.clone(),
            repo: name.to_string(),
            ref_name: r.clone(),
            sha,
        };
        if owner == base_owner {
            return Ok(prgit::rev_parse(&dir, &format!("refs/heads/{r}"))
                .await
                .map(make));
        }
        let Ok(head_dir) = repo::repo_git_dir(&self.repo_root, &owner, name) else {
            return Ok(None);
        };
        if !tokio::fs::metadata(&head_dir)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let local = format!("refs/forge/heads/{owner}/{r}");
        let refspec = format!("+refs/heads/{r}:{local}");
        let head_path = head_dir.to_string_lossy().into_owned();
        let _g = prgit::fetch_locks()
            .lock(&format!("{base_owner}/{name}"))
            .await;
        // Lazy heal for repositories that predate the hidden-refs config.
        forks::ensure_forge_refs_hidden(&dir).await;
        let fetched = prgit::run(
            &dir,
            &[
                "-c",
                "fetch.fsckObjects=true",
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--",
                &head_path,
                &refspec,
            ],
        )
        .await?;
        if !fetched.ok() {
            return Ok(None);
        }
        Ok(prgit::rev_parse(&dir, &local).await.map(make))
    }

    /// Resolve the base ref: branch, then tag, then a hex sha.
    pub(crate) async fn resolve_base(&self, dir: &Path, base_ref: &str) -> Option<String> {
        if !valid_ref(base_ref) {
            return None;
        }
        if let Some(s) = prgit::rev_parse(dir, &format!("refs/heads/{base_ref}")).await {
            return Some(s);
        }
        if let Some(s) = prgit::rev_parse(dir, &format!("refs/tags/{base_ref}^{{commit}}")).await {
            return Some(s);
        }
        if valid_sha(base_ref) {
            return prgit::rev_parse(dir, &format!("{base_ref}^{{commit}}")).await;
        }
        None
    }

    /// JSS `compareData`: `Ok(None)` when the base or head does not resolve.
    pub(crate) async fn compare_data(
        &self,
        owner: &str,
        name: &str,
        base_ref: &str,
        head_spec: &str,
    ) -> Result<Option<Compare>, ForgeError> {
        let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
        let Some(base_sha) = self.resolve_base(&dir, base_ref).await else {
            return Ok(None);
        };
        let Some(head) = self.resolve_head(owner, name, head_spec).await? else {
            return Ok(None);
        };
        let counts = prgit::text(
            &dir,
            &[
                "rev-list",
                "--left-right",
                "--count",
                &format!("{base_sha}...{}", head.sha),
            ],
        )
        .await?;
        let mut it = counts.split_whitespace();
        let behind_by: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let ahead_by: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let merge_base = prgit::text(&dir, &["merge-base", &base_sha, &head.sha])
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let (commits, has_more) = commit_range(&dir, &base_sha, &head.sha).await?;
        let files = diff_files(&dir, merge_base.as_deref(), &base_sha, &head.sha).await;
        Ok(Some(Compare {
            base_ref: base_ref.to_string(),
            base_sha,
            head,
            ahead_by,
            behind_by,
            merge_base,
            commits,
            has_more,
            files,
        }))
    }

    /// `GET api/repos/<o>/<n>/compare/<base>...<head>` (JSS `apiCompare`).
    pub(crate) async fn h_api_compare(
        &self,
        owner: &str,
        repo_name: &str,
        spec: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo_name).await?;
        let not_found = || Ok(ForgeResponse::error(404, "not found"));
        let Some((b, h)) = split_spec(spec) else {
            return not_found();
        };
        let Some(c) = self.compare_data(owner, repo_name, b, h).await? else {
            return not_found();
        };
        Ok(ForgeResponse::json(
            200,
            &serde_json::json!({
                "base": {"ref": c.base_ref, "sha": c.base_sha},
                "head": {"owner": c.head.owner, "repo": c.head.repo, "ref": c.head.ref_name, "sha": c.head.sha},
                "aheadBy": c.ahead_by,
                "behindBy": c.behind_by,
                "mergeBase": c.merge_base,
                "hasMore": c.has_more,
                "commits": c.commits,
                "files": c.files,
            }),
        ))
    }

    /// `GET <owner>/<repo>/compare/<base>...<head>` (JSS `comparePage`).
    pub(crate) async fn h_compare_page(
        &self,
        owner: &str,
        repo_name: &str,
        spec: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_repo(owner, repo_name).await?;
        let Some((b, h)) = split_spec(spec) else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let Some(c) = self.compare_data(owner, repo_name, b, h).await? else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        let prefix = self.prefix();
        let base = format!("{prefix}/{owner}/{repo_name}");
        let head_label = format!("{}:{}", agent_label(&c.head.owner), c.head.ref_name);
        let enc = |s: &str| {
            s.bytes()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                        (c as char).to_string()
                    } else {
                        format!("%{c:02X}")
                    }
                })
                .collect::<String>()
        };
        let pr_href = format!("{base}/pulls/new?base={}&head={}", enc(b), enc(h));
        let mut body = crumbs(&[
            ("forge", Some(prefix.clone())),
            (&agent_label(owner), Some(format!("{prefix}/{owner}"))),
            (repo_name, Some(base.clone())),
            ("compare", None),
        ]);
        body.push_str(&format!(
            "<h1>Comparing <code>{}...{}</code></h1>\
<p><span class=\"badge\">{} ahead, {} behind {}</span> {}</p>",
            esc(b),
            esc(&head_label),
            c.ahead_by,
            c.behind_by,
            esc(b),
            if c.ahead_by > 0 {
                format!("<a href=\"{}\">Open pull request</a>", esc(&pr_href))
            } else {
                "<span class=\"muted\">Nothing to compare: the base contains the head.</span>"
                    .to_string()
            }
        ));
        body.push_str(&commit_rows(&base, &c.commits, c.has_more));
        body.push_str(&render_diff(&c.files));
        Ok(ForgeResponse::html(
            200,
            page(
                &format!("Comparing {b}...{head_label} - {owner}/{repo_name}"),
                &body,
            ),
        ))
    }
}

/// Split `<base>...<head>` at the first `...` (the base must be non-empty).
fn split_spec(spec: &str) -> Option<(&str, &str)> {
    let i = spec.find("...")?;
    (i >= 1).then(|| (&spec[..i], &spec[i + 3..]))
}

/// A commit list as an escaped table.
pub(crate) fn commit_rows(base: &str, commits: &[CommitSummary], has_more: bool) -> String {
    let mut out = format!(
        "<h3>{}{} commit{}</h3>",
        commits.len(),
        if has_more { "+" } else { "" },
        if commits.len() == 1 { "" } else { "s" }
    );
    if commits.is_empty() {
        out.push_str("<p class=\"muted\">No commits.</p>");
        return out;
    }
    out.push_str("<table><tbody>");
    for c in commits {
        out.push_str(&format!(
            "<tr><td><a href=\"{b}/commit/{sha}\">{subj}</a><div class=\"muted\">{who}</div></td>\
<td><a href=\"{b}/commit/{sha}\"><code>{short}</code></a></td></tr>",
            b = esc(base),
            sha = esc(&c.sha),
            subj = esc(&c.subject),
            who = esc(&c.author),
            short = esc(&c.short),
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// Percent-decode a query value for the new-PR form (`head=dana%3Afeature`).
pub(crate) fn query_decoded(req: &ForgeRequest, key: &str) -> String {
    req.query
        .split('&')
        .find_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k == key).then(|| percent_decode(v))
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_match_jss_rules() {
        assert!(valid_owner("dana"));
        assert!(valid_owner(&"a".repeat(64)));
        assert!(!valid_owner(&"a".repeat(65)));
        assert!(!valid_owner("-x"));
        assert!(!valid_owner(".x"));
        assert!(!valid_owner("a..b"));
        assert!(valid_ref("feature/x"));
        assert!(!valid_ref("--upload-pack=x"));
        assert!(!valid_ref("-x"));
        assert!(!valid_ref("bad..ref"));
        assert!(!valid_ref("a//b"));
        assert!(!valid_ref("a/"));
        assert!(!valid_ref("a.lock"));
        assert!(!valid_ref("a/.b"));
        assert!(!valid_ref("--output=x"));
        assert!(!valid_ref("a b"));
        assert!(valid_sha("deadbeef"));
        assert!(!valid_sha("abc"));
        assert!(!valid_sha("DEADBEEF"));
        assert!(!valid_sha("--help"));
    }

    #[test]
    fn head_spec_parsing() {
        assert_eq!(
            parse_head_spec("casey", "dana:feature"),
            Some(("dana".into(), "feature".into()))
        );
        assert_eq!(
            parse_head_spec("casey", "feature"),
            Some(("casey".into(), "feature".into()))
        );
        for bad in [
            "dana:--upload-pack=x",
            "-x:feature",
            "dana:bad..ref",
            "dana:a//b",
            "dana:a/",
            "",
            "dana:",
            ":x",
        ] {
            assert_eq!(parse_head_spec("casey", bad), None, "{bad}");
        }
        assert_eq!(
            parse_head_spec("casey", &format!("dana:{}", "a".repeat(400))),
            None
        );
    }

    #[test]
    fn spec_split() {
        assert_eq!(
            split_spec("main...dana:feature"),
            Some(("main", "dana:feature"))
        );
        assert_eq!(split_spec("main"), None);
        assert_eq!(split_spec("...x"), None);
    }

    const PATCH: &str = "diff --git a/CONTRIBUTING.md b/CONTRIBUTING.md\n\
new file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/CONTRIBUTING.md\n\
@@ -0,0 +1,3 @@\n+# Contributing\n+\n+Please be kind.\n\
diff --git a/src/a.txt b/src/a.txt\nindex 1..2 100644\n--- a/src/a.txt\n+++ b/src/a.txt\n\
@@ -1,2 +1,2 @@\n keep\n-old\n+new\n\\ No newline at end of file\n\
diff --git a/img.bin b/img.bin\nBinary files a/img.bin and b/img.bin differ\n";

    #[test]
    fn parses_files_hunks_and_counts() {
        let f = parse_patch(PATCH);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].name.as_deref(), Some("CONTRIBUTING.md"));
        assert_eq!((f[0].adds, f[0].dels), (3, 0));
        assert_eq!(f[0].hunks[0].lines[0].new_line, Some(1));
        assert_eq!(f[1].name.as_deref(), Some("src/a.txt"));
        assert_eq!((f[1].adds, f[1].dels), (1, 1));
        let kinds: Vec<_> = f[1].hunks[0].lines.iter().map(|l| l.kind).collect();
        assert_eq!(
            kinds,
            vec![LineKind::Ctx, LineKind::Del, LineKind::Add, LineKind::Meta]
        );
        assert_eq!(f[1].hunks[0].lines[1].old_line, Some(2));
        assert!(f[2].binary);
        assert_eq!(f[2].name.as_deref(), Some("img.bin"));
    }

    #[test]
    fn content_that_looks_like_a_header_stays_content() {
        let p = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n--- not a header\n+++ also content\n";
        let f = parse_patch(p);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name.as_deref(), Some("x"));
        assert_eq!((f[0].adds, f[0].dels), (1, 1));
    }

    #[test]
    fn render_escapes_and_marks_rows() {
        let f =
            parse_patch("diff --git a/<x> b/<x>\n--- a/<x>\n+++ b/<x>\n@@ -1 +1 @@\n-<b>\n+<i>\n");
        let h = render_diff(&f);
        assert!(h.contains("&lt;x&gt;"));
        assert!(!h.contains("<b>"));
        assert!(h.contains("<tr class=\"add\">"));
        assert!(h.contains("<tr class=\"del\">"));
        assert!(render_diff(&[]).contains("No changes."));
    }
}
