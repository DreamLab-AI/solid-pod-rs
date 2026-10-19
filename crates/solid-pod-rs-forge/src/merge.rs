//! Real merges of pull requests: `git merge-tree --write-tree`, fast-forward
//! when possible, otherwise a two-parent commit, a compare-and-swap ref
//! update, and the git version gate.
//!
//! Follows the JSS forge `apiPullMerge`, `mergeTreeOf`, `isAncestor`,
//! `pullMergeInfo` and the `mergeTreeOk` start-up check (cited by name only).
//! A merge writes the target repository's branch, so it is owner-only exactly
//! as in JSS: the authenticated caller's owner id must equal the repository
//! owner. Everything else about a merge (the conflict verdict, the stale-base
//! guard, the ref update) is decided by git on validated object ids.
//!
//! # Examples
//!
//! ```
//! use solid_pod_rs_forge::merge::{merge_tree_supported, parse_git_version};
//!
//! assert_eq!(parse_git_version("git version 2.43.0"), Some((2, 43)));
//! assert!(merge_tree_supported("git version 2.38.0"));
//! assert!(!merge_tree_supported("git version 2.37.9"));
//! ```

use std::sync::OnceLock;

use async_trait::async_trait;

use crate::compare::{parse_head_spec, valid_ref, valid_sha, HeadAccess};
use crate::error::ForgeError;
use crate::html::agent_label;
use crate::prgit;
use crate::pulls::{self, MergeRecord, PullEntry};
use crate::repo;
use crate::spine::issues::IssueState;
use crate::{ForgeAgent, ForgeResponse, ForgeService};

/// Integration point for the anchoring tier: called after a merge moved a
/// branch of `<owner>/<repo>`, exactly where JSS calls `recordTip`.
///
/// The default [`NoopTipRecorder`] does nothing. The anchoring implementation
/// compares the default-branch tip with the last mark and returns without
/// effect when the default branch did not move, so this hook is called after
/// every successful merge. Failures are the implementation's to log; they never
/// fail the merge (JSS `recordTipSafe`).
#[async_trait]
pub trait TipRecorder: Send + Sync {
    /// A merge into `<owner>/<repo>` completed.
    async fn record_tip(&self, owner: &str, repo: &str);
}

/// The default [`TipRecorder`]: does nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopTipRecorder;

#[async_trait]
impl TipRecorder for NoopTipRecorder {
    async fn record_tip(&self, _owner: &str, _repo: &str) {}
}

/// Parse `git version 2.43.0` (or `2.43.0.windows.1`) into `(major, minor)`.
#[must_use]
pub fn parse_git_version(s: &str) -> Option<(u32, u32)> {
    let v = s.trim().strip_prefix("git version ").unwrap_or(s.trim());
    let mut it = v.split(|c: char| !c.is_ascii_digit());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

/// `true` when `version` is at least git 2.38 (`merge-tree --write-tree`).
#[must_use]
pub fn merge_tree_supported(version: &str) -> bool {
    matches!(parse_git_version(version), Some(v) if v >= (2, 38))
}

/// The installed git's `--version` line, detected once per process.
#[must_use]
pub fn detected_git_version() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| {
        solid_pod_rs_git::hardened_git()
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    })
}

/// Result of `git merge-tree --write-tree`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeTree {
    /// `true` when the merge is clean.
    pub clean: bool,
    /// The merged tree (clean merges only).
    pub tree: Option<String>,
    /// Conflicted paths (deduplicated, in git's order).
    pub conflicts: Vec<String>,
}

/// Parse the NUL-separated (`-z`) `merge-tree --write-tree --name-only`
/// output: the tree id, then conflicted names up to an empty field.
#[must_use]
pub fn parse_merge_tree(stdout: &str, clean: bool) -> MergeTree {
    let mut it = stdout.split('\0');
    let tree = it.next().unwrap_or("").trim().to_string();
    let mut conflicts: Vec<String> = Vec::new();
    if !clean {
        for f in it {
            if f.is_empty() {
                break;
            }
            if !conflicts.iter().any(|c| c == f) {
                conflicts.push(f.to_string());
            }
        }
    }
    MergeTree {
        clean,
        tree: clean.then_some(tree),
        conflicts,
    }
}

/// JSS `mergeTreeOf`: compute the merged tree without a worktree. Exit 0 is a
/// clean merge, exit 1 a conflict; anything else is an error (for instance
/// unrelated histories). Both arguments must be object ids.
pub(crate) async fn merge_tree_of(
    dir: &std::path::Path,
    base_sha: &str,
    head_sha: &str,
) -> Result<MergeTree, ForgeError> {
    if !valid_sha(base_sha) || !valid_sha(head_sha) {
        return Err(ForgeError::BadRequest(
            "merge ends must be object ids".into(),
        ));
    }
    let out = prgit::run(
        dir,
        &[
            "merge-tree",
            "--write-tree",
            "--name-only",
            "-z",
            base_sha,
            head_sha,
        ],
    )
    .await?;
    match out.code {
        Some(0) => Ok(parse_merge_tree(&out.text(), true)),
        Some(1) => Ok(parse_merge_tree(&out.text(), false)),
        _ => Err(ForgeError::Backend(format!(
            "git merge-tree: {}",
            out.stderr.trim()
        ))),
    }
}

/// Live mergeability of an open pull request (JSS `pullMergeInfo`).
#[derive(Debug, Clone, Default)]
pub struct MergeInfo {
    /// Current base tip.
    pub base_sha: Option<String>,
    /// Current head tip.
    pub head_sha: Option<String>,
    /// `None` when an end is gone or merge-tree is unavailable.
    pub mergeable: Option<bool>,
    /// Conflicted paths.
    pub conflicts: Vec<String>,
    /// The merge would be a fast-forward.
    pub fast_forward: bool,
    /// The base already contains the head.
    pub up_to_date: bool,
}

/// Keep a git identity field to printable characters without `<`, `>`.
fn ident(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control() && *c != '<' && *c != '>')
        .collect();
    let t = t.trim();
    if t.is_empty() {
        "agent".to_string()
    } else {
        t.to_string()
    }
}

fn json(status: u16, v: &serde_json::Value) -> ForgeResponse {
    ForgeResponse::json(status, v)
}

impl ForgeService {
    /// Is `merge-tree --write-tree` available on this host?
    #[must_use]
    pub fn merge_tree_ok(&self) -> bool {
        self.pr.merge_tree_ok
    }

    /// Pin the git version string used for the 2.38 gate (the default is the
    /// installed git, detected once at start-up). Operators and tests use this
    /// to force the "git too old" path.
    #[must_use]
    pub fn with_git_version(mut self, version: &str) -> Self {
        self.pr.merge_tree_ok = merge_tree_supported(version);
        self.pr.git_version = version.to_string();
        self
    }

    /// Install the [`TipRecorder`] called after every successful merge.
    #[must_use]
    pub fn with_tip_recorder(mut self, rec: std::sync::Arc<dyn TipRecorder>) -> Self {
        self.pr.tip = rec;
        self
    }

    /// Resolve both ends of an open pull request and decide mergeability.
    pub(crate) async fn pull_merge_info(
        &self,
        owner: &str,
        name: &str,
        pr: &PullEntry,
    ) -> Result<MergeInfo, ForgeError> {
        let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
        let mut info = MergeInfo::default();
        if !valid_ref(&pr.base) {
            return Ok(info);
        }
        info.base_sha = prgit::rev_parse(&dir, &format!("refs/heads/{}", pr.base)).await;
        let access = if pr.state == crate::spine::issues::IssueState::Open {
            HeadAccess::ExistingPr
        } else {
            HeadAccess::Cached
        };
        let head = self
            .resolve_head(owner, name, &pr.head_spec(), access)
            .await?;
        info.head_sha = head.as_ref().map(|h| h.sha.clone());
        let (Some(base), Some(head)) = (info.base_sha.clone(), head) else {
            return Ok(info);
        };
        if prgit::is_ancestor(&dir, &head.sha, &base).await {
            info.mergeable = Some(false);
            info.up_to_date = true;
            return Ok(info);
        }
        if prgit::is_ancestor(&dir, &base, &head.sha).await {
            info.mergeable = Some(true);
            info.fast_forward = true;
            return Ok(info);
        }
        if !self.pr.merge_tree_ok {
            return Ok(info);
        }
        if let Ok(mt) = merge_tree_of(&dir, &base, &head.sha).await {
            info.mergeable = Some(mt.clean);
            info.conflicts = mt.conflicts;
        }
        Ok(info)
    }

    /// `POST .../pulls/<n>/merge` (JSS `apiPullMerge`): a real merge on the
    /// bare repository, repository owner only.
    ///
    /// Order of checks: 401 (anonymous), 403 (not the owner), 501 (git too
    /// old), then under the repository's pull lock 404, 422 (not open), 409
    /// (`expected_base` no longer matches), 422 (nothing to merge), the
    /// fast-forward or `merge-tree` decision (409 with the conflicted paths),
    /// and finally `update-ref <ref> <new> <old>`, whose old-value guard turns
    /// a racing push into a 409.
    pub(crate) async fn merge_pull(
        &self,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
        number: u64,
        expected_base: Option<&str>,
    ) -> Result<ForgeResponse, ForgeError> {
        let Some(who) = agent.owner() else {
            return Ok(ForgeResponse::error(401, "authentication required"));
        };
        if who != owner {
            return Ok(ForgeResponse::error(403, "only the repo owner may merge"));
        }
        if !self.pr.merge_tree_ok {
            return Ok(ForgeResponse::error(
                501,
                format!(
                    "merging needs git >= 2.38 (merge-tree --write-tree); this server has \"{}\"",
                    self.pr.git_version
                ),
            ));
        }
        self.resolve_repo(owner, name).await?;
        let _g = prgit::pull_locks().lock(&format!("{owner}/{name}")).await;
        let mut idx = pulls::load_pull_index(self.spine.as_ref(), owner, name).await?;
        let Some(pr) = idx.pulls.get(&number).cloned() else {
            return Ok(ForgeResponse::error(404, "not found"));
        };
        if pr.state != IssueState::Open {
            return Ok(ForgeResponse::error(
                422,
                format!("pull request is {}", pulls::state_str(pr.state)),
            ));
        }
        let dir = repo::repo_git_dir(&self.repo_root, owner, name)?;
        // The index is on-disk data: re-validate before anything reaches argv.
        if !valid_ref(&pr.base) || parse_head_spec(owner, &pr.head_spec()).is_none() {
            return Ok(ForgeResponse::error(422, "pull request refs are invalid"));
        }
        let Some(base_sha) = prgit::rev_parse(&dir, &format!("refs/heads/{}", pr.base)).await
        else {
            return Ok(ForgeResponse::error(
                422,
                format!("base branch {} no longer exists", pr.base),
            ));
        };
        if let Some(exp) = expected_base {
            if !valid_sha(exp) {
                return Ok(ForgeResponse::error(422, "expectedBase must be a sha"));
            }
            if !base_sha.starts_with(exp) {
                return Ok(json(
                    409,
                    &serde_json::json!({
                        "error": format!(
                            "the base branch has moved since the diff you saw (now at {}), review and retry",
                            &base_sha[..7.min(base_sha.len())]
                        ),
                        "baseSha": base_sha,
                    }),
                ));
            }
        }
        let Some(head) = self
            .resolve_head(owner, name, &pr.head_spec(), HeadAccess::ExistingPr)
            .await?
        else {
            return Ok(ForgeResponse::error(
                422,
                "the head branch no longer exists",
            ));
        };
        if head.sha == base_sha || prgit::is_ancestor(&dir, &head.sha, &base_sha).await {
            return Ok(ForgeResponse::error(
                422,
                "nothing to merge: the base already contains the head",
            ));
        }
        let fast_forward = prgit::is_ancestor(&dir, &base_sha, &head.sha).await;
        let merged_sha = if fast_forward {
            head.sha.clone()
        } else {
            let mt = match merge_tree_of(&dir, &base_sha, &head.sha).await {
                Ok(mt) => mt,
                Err(e) => {
                    tracing::warn!("forge: merge-tree {owner}/{name} #{number}: {e}");
                    return Ok(ForgeResponse::error(422, "these branches cannot be merged"));
                }
            };
            let Some(tree) = mt.tree.filter(|_| mt.clean) else {
                return Ok(json(
                    409,
                    &serde_json::json!({"error": "merge conflict", "conflicts": mt.conflicts}),
                ));
            };
            if !valid_sha(&tree) {
                return Err(ForgeError::Backend(
                    "merge-tree returned a bad tree id".into(),
                ));
            }
            // Honest authorship: author = the merging agent, committer = forge.
            let author = ident(&agent_label(who));
            let email = format!("{}@forge.invalid", ident(who).replace(' ', "-"));
            let msg = format!("Merge pull request #{} from {}", pr.number, pr.head_spec());
            let c = prgit::run_at(
                &dir,
                Some(&dir),
                &[
                    "commit-tree",
                    &tree,
                    "-p",
                    &base_sha,
                    "-p",
                    &head.sha,
                    "-m",
                    &msg,
                ],
                &[
                    ("GIT_AUTHOR_NAME", &author),
                    ("GIT_AUTHOR_EMAIL", &email),
                    ("GIT_COMMITTER_NAME", "forge"),
                    ("GIT_COMMITTER_EMAIL", "forge@forge.invalid"),
                ],
            )
            .await?;
            let sha = c.text().trim().to_string();
            if !c.ok() || !valid_sha(&sha) {
                return Err(ForgeError::Backend(format!(
                    "git commit-tree: {}",
                    c.stderr.trim()
                )));
            }
            sha
        };
        // Compare-and-swap: update-ref's old-value guard rejects the write if
        // the base moved between our read and now (a racing push).
        let refname = format!("refs/heads/{}", pr.base);
        let upd = prgit::run(&dir, &["update-ref", &refname, &merged_sha, &base_sha]).await?;
        if !upd.ok() {
            return Ok(json(
                409,
                &serde_json::json!({"error": "the base branch moved during the merge, retry"}),
            ));
        }
        if let Some(p) = idx.pulls.get_mut(&number) {
            p.state = IssueState::Merged;
            p.merged = Some(MergeRecord {
                sha: merged_sha.clone(),
                merged_by: agent.author_id(),
                at: crate::now_secs(),
                base_sha: Some(base_sha),
                head_sha: Some(head.sha),
                fast_forward,
            });
        }
        pulls::save_pull_index(self.spine.as_ref(), owner, name, &idx).await?;
        self.release_head_ref(owner, name, &idx, &pr).await;
        tracing::info!(
            "forge: merged PR #{number} into {owner}/{name}@{} ({}{})",
            pr.base,
            &merged_sha[..7.min(merged_sha.len())],
            if fast_forward { ", ff" } else { "" }
        );
        self.pr.tip.record_tip(owner, name).await;
        // Forge-held anchoring: a merge moves the default branch, so the
        // trail's tip is re-read (the hook above is for embedders; this is
        // the built-in recorder and a no-op without the feature).
        #[cfg(feature = "anchoring")]
        if let Ok(dir) = self.resolve_repo(owner, name).await {
            let branch = repo::browse::default_branch(&dir).await;
            if let Err(e) = self.record_tip(owner, name, &branch, &merged_sha).await {
                tracing::warn!("forge: recording the anchor tip after merge failed: {e}");
            }
        }
        Ok(json(
            200,
            &serde_json::json!({
                "number": number,
                "state": "merged",
                "sha": merged_sha,
                "fastForward": fast_forward,
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_and_gate() {
        assert_eq!(parse_git_version("git version 2.55.0"), Some((2, 55)));
        assert_eq!(
            parse_git_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(parse_git_version("git version 10.0.1"), Some((10, 0)));
        assert_eq!(parse_git_version("garbage"), None);
        assert!(merge_tree_supported("git version 2.38.0"));
        assert!(merge_tree_supported("git version 3.0.0"));
        assert!(!merge_tree_supported("git version 2.37.9"));
        assert!(!merge_tree_supported("git version 1.99.0"));
        assert!(!merge_tree_supported("unknown"));
    }

    #[test]
    fn merge_tree_output_parsing() {
        let clean = parse_merge_tree("abc123\0", true);
        assert!(clean.clean);
        assert_eq!(clean.tree.as_deref(), Some("abc123"));
        let bad = parse_merge_tree(
            "abc\0src/main.js\0src/main.js\0a b.txt\0\0Auto-merging x\0",
            false,
        );
        assert!(!bad.clean);
        assert_eq!(bad.tree, None);
        assert_eq!(bad.conflicts, vec!["src/main.js", "a b.txt"]);
    }

    #[test]
    fn identity_is_sanitised() {
        assert_eq!(ident("a<b>\nc"), "abc");
        assert_eq!(ident("<>"), "agent");
    }
}
