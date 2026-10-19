//! Forks: `git clone --local --bare` into the caller's namespace, lineage in
//! the fork's own git config, bounded fork counts, and the hidden
//! `refs/forge/*` namespace.
//!
//! Follows the JSS forge `apiForkCreate`, `readForkParent`, `countForks` and
//! `ensureForgeRefsHidden` (cited by name only). Lineage is the single line
//! `forge.parent = <owner>/<name>` in the fork's bare-repository config; it is
//! read with a plain file read, not a git spawn, so repository lists and fork
//! counts stay cheap.
//!
//! # Examples
//!
//! ```
//! use solid_pod_rs_forge::forks::parse_fork_parent;
//!
//! let conf = "[core]\n\tbare = true\n[forge]\n\tparent = casey/demo\n";
//! let p = parse_fork_parent(conf).unwrap();
//! assert_eq!(p.full(), "casey/demo");
//! assert!(parse_fork_parent("[forge]\n\tparent = ../x/y\n").is_none());
//! ```

use std::path::Path;

use serde::Serialize;

use crate::compare::{valid_owner, valid_repo};
use crate::error::ForgeError;
use crate::html::agent_label;
use crate::prgit;
use crate::repo;
use crate::request::esc;
use crate::{ForgeAgent, ForgeRequest, ForgeResponse, ForgeService};

/// How many repositories a fork-count scan visits at most (JSS: 400).
pub const FORK_SCAN_CAP: usize = 400;

/// The ref namespace for internal compare refs.
pub const FORGE_REFS: &str = "refs/forge/";

/// The parent a fork was made from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkParent {
    /// Parent owner namespace.
    pub owner: String,
    /// Parent repository name.
    pub name: String,
}

impl ForkParent {
    /// `owner/name`.
    #[must_use]
    pub fn full(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// `(section, key, value)` triples of a git config file (section and key
/// lowercased).
fn config_entries(conf: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for raw in conf.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(h) = line.strip_prefix('[') {
            let name = h.split(']').next().unwrap_or("");
            section = name
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push((
                section.clone(),
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    out
}

/// Parse `forge.parent` out of a bare repository's config text. The value
/// must be exactly `<owner>/<name>` with both parts passing the name rules
/// (JSS `readForkParent`).
#[must_use]
pub fn parse_fork_parent(conf: &str) -> Option<ForkParent> {
    let (_, _, v) = config_entries(conf)
        .into_iter()
        .find(|(s, k, _)| s == "forge" && k == "parent")?;
    let mut it = v.split('/');
    let (o, n, extra) = (it.next()?, it.next()?, it.next());
    if extra.is_some() || !valid_owner(o) || !valid_repo(n) {
        return None;
    }
    Some(ForkParent {
        owner: o.to_string(),
        name: n.to_string(),
    })
}

/// Read the lineage of `<owner>/<name>` from its config file, if it is a fork.
#[must_use]
pub fn read_fork_parent(repo_root: &Path, owner: &str, name: &str) -> Option<ForkParent> {
    let dir = repo::repo_git_dir(repo_root, owner, name).ok()?;
    let conf = std::fs::read_to_string(dir.join("config")).ok()?;
    parse_fork_parent(&conf)
}

/// Count repositories naming `<owner>/<name>` as `forge.parent`, scanning at
/// most [`FORK_SCAN_CAP`] repositories (JSS `countForks`).
pub async fn count_forks(repo_root: &Path, owner: &str, name: &str) -> usize {
    let target = format!("{owner}/{name}");
    let all = repo::list_all(repo_root).await;
    all.iter()
        .take(FORK_SCAN_CAP)
        .filter(|(o, n)| {
            read_fork_parent(repo_root, o, n)
                .map(|p| p.full() == target)
                .unwrap_or(false)
        })
        .count()
}

/// `(uploadpack, transfer)`: does the config already hide `refs/forge/` under
/// each `hideRefs` key?
fn forge_refs_hidden(conf: &str) -> (bool, bool) {
    let mut up = false;
    let mut tr = false;
    for (s, k, v) in config_entries(conf) {
        if k == "hiderefs" && v == FORGE_REFS {
            match s.as_str() {
                "uploadpack" => up = true,
                "transfer" => tr = true,
                _ => {}
            }
        }
    }
    (up, tr)
}

/// Keep `refs/forge/*` out of `ls-remote` and push advertisements (JSS
/// `ensureForgeRefsHidden`, extended to `transfer.hideRefs`, which also stops
/// a push from touching the namespace). Idempotent and cheap: a file read
/// short-circuits once both settings exist. Existing `hideRefs` entries (for
/// instance a mirror's) are preserved because the value is appended.
pub async fn ensure_forge_refs_hidden(dir: &Path) {
    let conf = std::fs::read_to_string(dir.join("config")).unwrap_or_default();
    let (up, tr) = forge_refs_hidden(&conf);
    for (have, key) in [(up, "uploadpack.hideRefs"), (tr, "transfer.hideRefs")] {
        if have {
            continue;
        }
        match prgit::run(dir, &["config", "--add", key, FORGE_REFS]).await {
            Ok(o) if o.ok() => {}
            Ok(o) => tracing::warn!("forge: could not set {key}: {}", o.stderr.trim()),
            Err(e) => tracing::warn!("forge: could not set {key}: {e}"),
        }
    }
}

/// Insert `html` after the first `</h1>` of a rendered page (unchanged when
/// there is none).
#[must_use]
pub fn inject_after_h1(page: &str, html: &str) -> String {
    match page.find("</h1>") {
        Some(i) => {
            let at = i + "</h1>".len();
            format!("{}{}{}", &page[..at], html, &page[at..])
        }
        None => page.to_string(),
    }
}

/// The lineage banner for a repository home: "forked from" and a fork count.
#[must_use]
pub fn lineage_banner(prefix: &str, parent: Option<&ForkParent>, forks: usize) -> String {
    let mut out = String::new();
    if let Some(p) = parent {
        out.push_str(&format!(
            "<p class=\"muted\">forked from <a href=\"{}/{}/{}\">{}/{}</a></p>",
            esc(prefix),
            esc(&p.owner),
            esc(&p.name),
            esc(&agent_label(&p.owner)),
            esc(&p.name)
        ));
    }
    if forks > 0 {
        out.push_str(&format!(
            "<p><span class=\"badge\">{forks} fork{}</span></p>",
            if forks == 1 { "" } else { "s" }
        ));
    }
    out
}

/// Append "forked from owner/name" to the rows of a rendered repository list
/// ([`crate::html::index_page`] or [`crate::html::owner_page`]) for every
/// `(owner, repo)` that is a fork.
#[must_use]
pub fn annotate_listing(
    page: &str,
    prefix: &str,
    root: &Path,
    repos: &[(String, String)],
) -> String {
    let mut out = page.to_string();
    for (o, r) in repos {
        let Some(p) = read_fork_parent(root, o, r) else {
            continue;
        };
        let anchor = format!("<a href=\"{}\">", esc(&format!("{prefix}/{o}/{r}")));
        let Some(start) = out.find(&anchor) else {
            continue;
        };
        let Some(rel) = out[start..].find("</a>") else {
            continue;
        };
        let at = start + rel + "</a>".len();
        let note = format!(
            " <span class=\"muted\">forked from {}/{}</span>",
            esc(&agent_label(&p.owner)),
            esc(&p.name)
        );
        out.insert_str(at, &note);
    }
    out
}

impl ForgeService {
    /// Decorate a rendered repository home with lineage, the fork count and
    /// the pull-request tab.
    pub(crate) async fn decorate_overview(&self, page: String, owner: &str, name: &str) -> String {
        let parent = read_fork_parent(&self.repo_root, owner, name);
        let forks = count_forks(&self.repo_root, owner, name).await;
        let mut extra = lineage_banner(&self.prefix(), parent.as_ref(), forks);
        extra.push_str(&self.pulls_tab(owner, name).await);
        inject_after_h1(&page, &extra)
    }

    /// Decorate a rendered repository list with lineage.
    pub(crate) fn decorate_listing(&self, page: &str, repos: &[(String, String)]) -> String {
        annotate_listing(page, &self.prefix(), &self.repo_root, repos)
    }

    /// `POST api/repos/<o>/<n>/fork` (JSS `apiForkCreate`): clone into the
    /// caller's own namespace, record lineage, answer 201. The target
    /// namespace is never taken from the request, so a fork can only ever be
    /// written under the authenticated caller's own owner id.
    pub(crate) async fn h_api_fork(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        name: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        if !req.method.eq_ignore_ascii_case("POST") {
            return Ok(ForgeResponse::error(405, "method not allowed"));
        }
        let Some(caller) = agent.owner() else {
            return Ok(ForgeResponse::error(401, "authentication required"));
        };
        if !valid_owner(caller) {
            return Ok(ForgeResponse::error(403, "no namespace for this agent"));
        }
        let src = self.resolve_repo(owner, name).await?;
        let mut target = name.to_string();
        if !req.raw_body.is_empty() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.raw_body) {
                if let Some(n) = v.get("name") {
                    match n.as_str() {
                        Some(s) if valid_repo(s) => target = s.to_string(),
                        _ => return Ok(ForgeResponse::error(422, "invalid fork name")),
                    }
                }
            }
        }
        let dest = repo::repo_git_dir(&self.repo_root, caller, &target)?;
        if tokio::fs::metadata(&dest).await.is_ok() {
            return Ok(ForgeResponse::error(
                409,
                format!("{caller}/{target} already exists"),
            ));
        }
        let owner_dir = self.repo_root.join(caller);
        tokio::fs::create_dir_all(&owner_dir).await?;
        // Build next to the destination under a non-listed name, then rename.
        let tmp = owner_dir.join(format!(".fork-{}.tmp", uuid::Uuid::new_v4()));
        if let Err(e) = self.build_fork(&src, &tmp, owner, name).await {
            let _ = tokio::fs::remove_dir_all(&tmp).await;
            return Err(e);
        }
        if tokio::fs::metadata(&dest).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&tmp).await;
            return Ok(ForgeResponse::error(
                409,
                format!("{caller}/{target} already exists"),
            ));
        }
        if let Err(e) = tokio::fs::rename(&tmp, &dest).await {
            let _ = tokio::fs::remove_dir_all(&tmp).await;
            return Err(ForgeError::Io(e));
        }
        tracing::info!(
            "forge: {} forked {owner}/{name} -> {caller}/{target}",
            agent.author_id()
        );
        let prefix = self.prefix();
        let clone_url = match req.host_url.as_deref() {
            Some(h) => format!("{}{prefix}/{caller}/{target}.git", h.trim_end_matches('/')),
            None => format!("{prefix}/{caller}/{target}.git"),
        };
        Ok(ForgeResponse::json(
            201,
            &serde_json::json!({
                "owner": caller,
                "name": target,
                "parent": format!("{owner}/{name}"),
                "url": format!("{prefix}/{caller}/{target}"),
                "cloneUrl": clone_url,
            }),
        ))
    }

    /// Clone `src` into `tmp` and write the fork's configuration.
    async fn build_fork(
        &self,
        src: &Path,
        tmp: &Path,
        owner: &str,
        name: &str,
    ) -> Result<(), ForgeError> {
        let (s, t) = (src.to_string_lossy(), tmp.to_string_lossy());
        let c = prgit::run_at(
            &self.repo_root,
            None,
            &["clone", "--local", "--bare", "--quiet", "--", &s, &t],
            &[],
        )
        .await?;
        if !c.ok() {
            return Err(ForgeError::Backend(format!(
                "fork clone failed: {}",
                c.stderr.trim()
            )));
        }
        let lineage = format!("{owner}/{name}");
        for args in [
            vec!["config", "http.receivepack", "true"],
            vec!["config", "--add", "uploadpack.hideRefs", FORGE_REFS],
            vec!["config", "--add", "transfer.hideRefs", FORGE_REFS],
            vec!["config", "forge.parent", lineage.as_str()],
        ] {
            let o = prgit::run(tmp, &args).await?;
            if !o.ok() {
                return Err(ForgeError::Backend(format!(
                    "fork config failed: {}",
                    o.stderr.trim()
                )));
            }
        }
        // The clone's origin is an internal filesystem path: drop it.
        let _ = prgit::run(tmp, &["remote", "remove", "origin"]).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html;

    #[test]
    fn parent_parsing_is_strict() {
        assert_eq!(
            parse_fork_parent("[forge]\n\tparent = casey/demo\n")
                .unwrap()
                .full(),
            "casey/demo"
        );
        for bad in [
            "[forge]\n\tparent = a/b/c\n",
            "[forge]\n\tparent = ../x\n",
            "[forge]\n\tparent = -x/y\n",
            "[other]\n\tparent = a/b\n",
            "[forge]\n\tparent = a\n",
            "",
        ] {
            assert!(parse_fork_parent(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn hidden_check_needs_both_sections() {
        let both = "[uploadpack]\n\thideRefs = refs/forge/\n[transfer]\n\thideRefs = refs/forge/\n";
        assert_eq!(forge_refs_hidden(both), (true, true));
        assert_eq!(
            forge_refs_hidden("[uploadpack]\n\thideRefs = refs/forge/\n"),
            (true, false)
        );
        assert_eq!(
            forge_refs_hidden("[receive]\n\thideRefs = refs/forge/\n"),
            (false, false)
        );
    }

    #[test]
    fn injection_and_banner() {
        let b = lineage_banner(
            "/forge",
            Some(&ForkParent {
                owner: "casey".into(),
                name: "demo".into(),
            }),
            2,
        );
        assert!(b.contains("forked from"));
        assert!(b.contains("href=\"/forge/casey/demo\""));
        assert!(b.contains("2 forks"));
        assert!(lineage_banner("/forge", None, 1).contains("1 fork<"));
        assert_eq!(
            inject_after_h1("<h1>x</h1><p>y</p>", "<i/>"),
            "<h1>x</h1><i/><p>y</p>"
        );
        assert_eq!(inject_after_h1("no heading", "<i/>"), "no heading");
    }

    #[tokio::test]
    async fn listing_annotation_matches_real_index_markup() {
        let td = tempfile::TempDir::new().unwrap();
        let root = td.path();
        let fork = root.join("dana/demo.git");
        std::fs::create_dir_all(&fork).unwrap();
        std::fs::write(fork.join("config"), "[forge]\n\tparent = casey/demo\n").unwrap();
        std::fs::create_dir_all(root.join("casey/demo.git")).unwrap();
        let repos = repo::list_all(root).await;
        let page = html::index_page("/forge", &repos);
        let out = annotate_listing(&page, "/forge", root, &repos);
        assert!(out.contains("forked from casey/demo"), "{out}");
        assert_eq!(count_forks(root, "casey", "demo").await, 1);
        assert_eq!(count_forks(root, "dana", "demo").await, 0);
    }
}
