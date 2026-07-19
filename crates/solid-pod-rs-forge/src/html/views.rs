//! Concrete page renderers. Phase 0 ships the index shell; browse and
//! issue views are layered on in later phases.

use crate::html::{crumbs, page};
use crate::request::esc;

/// The global landing page listing `(owner, repo)` pairs. Each row links
/// to the repo overview. An empty list renders an explanatory note.
#[must_use]
pub fn index_page(prefix: &str, repos: &[(String, String)]) -> String {
    let mut body = String::from("<h1>Repositories</h1>");
    if repos.is_empty() {
        body.push_str("<p class=\"muted\">No repositories yet. Push to <code>");
        body.push_str(&esc(prefix));
        body.push_str("/&lt;owner&gt;/&lt;repo&gt;.git</code> to create one.</p>");
    } else {
        body.push_str("<table><tbody>");
        for (owner, repo) in repos {
            let href = format!("{prefix}/{owner}/{repo}");
            body.push_str(&format!(
                "<tr><td><a href=\"{}\">{}/{}</a></td></tr>",
                esc(&href),
                esc(owner),
                esc(repo)
            ));
        }
        body.push_str("</tbody></table>");
    }
    page("forge", &body)
}

/// A single owner's repo list.
#[must_use]
pub fn owner_page(prefix: &str, owner: &str, repos: &[String]) -> String {
    let mut body = crumbs(&[("forge", Some(prefix.to_string())), (owner, None)]);
    body.push_str(&format!("<h1>{}</h1>", esc(owner)));
    if repos.is_empty() {
        body.push_str("<p class=\"muted\">No repositories.</p>");
    } else {
        body.push_str("<table><tbody>");
        for repo in repos {
            let href = format!("{prefix}/{owner}/{repo}");
            body.push_str(&format!(
                "<tr><td><a href=\"{}\">{}</a></td></tr>",
                esc(&href),
                esc(repo)
            ));
        }
        body.push_str("</tbody></table>");
    }
    page(&format!("{owner} \u{2013} forge"), &body)
}

// ---------------------------------------------------------------------------
// Tier 1 browse views
// ---------------------------------------------------------------------------

use crate::repo::browse::{EntryKind, TreeEntry};
use solid_pod_rs_git::api::CommitEntry;

/// Join a listing base path with an entry name for a child URL segment.
fn child_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}/{name}")
    }
}

/// A repo-scoped tab bar (overview / commits / branches / tags).
fn repo_tabs(prefix: &str, owner: &str, repo: &str, rev: &str) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    format!(
        "<nav class=\"crumbs\">\
<a href=\"{b}\">code</a> \u{b7} \
<a href=\"{b}/commits/{r}\">commits</a> \u{b7} \
<a href=\"{b}/branches\">branches</a> \u{b7} \
<a href=\"{b}/tags\">tags</a></nav>",
        b = esc(&base),
        r = esc(rev)
    )
}

fn repo_header(prefix: &str, owner: &str, repo: &str, rev: &str) -> String {
    let mut h = crumbs(&[
        ("forge", Some(prefix.to_string())),
        (owner, Some(format!("{prefix}/{owner}"))),
        (repo, Some(format!("{prefix}/{owner}/{repo}"))),
    ]);
    h.push_str(&format!("<h1>{}/{}</h1>", esc(owner), esc(repo)));
    h.push_str(&repo_tabs(prefix, owner, repo, rev));
    h
}

/// Render a directory listing table for `entries` at `<rev>:<path>`.
fn tree_table(
    prefix: &str,
    owner: &str,
    repo: &str,
    rev: &str,
    path: &str,
    entries: &[TreeEntry],
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut out = String::from("<table><tbody>");
    // Parent-dir row when not at the repo root.
    if !path.is_empty() {
        let parent = match path.rsplit_once('/') {
            Some((p, _)) => p.to_string(),
            None => String::new(),
        };
        out.push_str(&format!(
            "<tr><td><a href=\"{}/tree/{}/{}\">..</a></td><td></td></tr>",
            esc(&base),
            esc(rev),
            esc(&parent)
        ));
    }
    for e in entries {
        let cp = child_path(path, &e.name);
        let (verb, glyph) = match e.kind {
            EntryKind::Dir => ("tree", "\u{1f4c1}"),
            EntryKind::Submodule => ("tree", "\u{1f517}"),
            EntryKind::Symlink => ("blob", "\u{1f517}"),
            EntryKind::File => ("blob", "\u{1f4c4}"),
        };
        let size = e.size.map(|s| s.to_string()).unwrap_or_default();
        out.push_str(&format!(
            "<tr><td>{} <a href=\"{}/{}/{}/{}\">{}</a></td><td class=\"muted\">{}</td></tr>",
            glyph,
            esc(&base),
            verb,
            esc(rev),
            esc(&cp),
            esc(&e.name),
            esc(&size)
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// Repo overview: header, root tree at `rev`, and an optional README.
#[must_use]
pub fn repo_overview_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    rev: &str,
    entries: &[TreeEntry],
    readme: Option<&str>,
) -> String {
    let mut body = repo_header(prefix, owner, repo, rev);
    if entries.is_empty() {
        body.push_str("<p class=\"muted\">This repository is empty.</p>");
    } else {
        body.push_str(&tree_table(prefix, owner, repo, rev, "", entries));
    }
    if let Some(text) = readme {
        body.push_str("<h2>README</h2><pre>");
        body.push_str(&esc(text));
        body.push_str("</pre>");
    }
    page(&format!("{owner}/{repo}"), &body)
}

/// A subdirectory listing view.
#[must_use]
pub fn tree_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    rev: &str,
    path: &str,
    entries: &[TreeEntry],
) -> String {
    let mut body = repo_header(prefix, owner, repo, rev);
    body.push_str(&format!(
        "<p class=\"muted\">{} @ {}</p>",
        esc(path),
        esc(rev)
    ));
    body.push_str(&tree_table(prefix, owner, repo, rev, path, entries));
    page(&format!("{owner}/{repo}: {path}"), &body)
}

/// A blob (file) view. `content` is `Some(text)` for a textual blob or
/// `None` for a binary one (a download link is shown instead).
#[must_use]
pub fn blob_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    rev: &str,
    path: &str,
    content: Option<&str>,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, rev);
    body.push_str(&format!(
        "<p class=\"muted\">{} @ {} \u{b7} <a href=\"{}/raw/{}/{}\">raw</a></p>",
        esc(path),
        esc(rev),
        esc(&base),
        esc(rev),
        esc(path)
    ));
    match content {
        Some(text) => {
            body.push_str("<pre>");
            body.push_str(&esc(text));
            body.push_str("</pre>");
        }
        None => {
            body.push_str(&format!(
                "<p>Binary file \u{2014} <a href=\"{}/raw/{}/{}\">download</a>.</p>",
                esc(&base),
                esc(rev),
                esc(path)
            ));
        }
    }
    page(&format!("{owner}/{repo}: {path}"), &body)
}

/// Paginated commit log view.
#[must_use]
pub fn commits_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    rev: &str,
    commits: &[CommitEntry],
    page_num: u32,
    has_next: bool,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, rev);
    if commits.is_empty() {
        body.push_str("<p class=\"muted\">No commits.</p>");
    } else {
        body.push_str("<table><tbody>");
        for c in commits {
            body.push_str(&format!(
                "<tr><td><a href=\"{}/commit/{}\"><code>{}</code></a></td>\
<td>{}</td><td class=\"muted\">{} \u{b7} {}</td></tr>",
                esc(&base),
                esc(&c.hash),
                esc(&c.short_hash),
                esc(&c.message),
                esc(&c.author),
                esc(&c.date_relative)
            ));
        }
        body.push_str("</tbody></table>");
        // Pager.
        body.push_str("<p>");
        if page_num > 1 {
            body.push_str(&format!(
                "<a href=\"{}/commits/{}?page={}\">\u{2190} newer</a> ",
                esc(&base),
                esc(rev),
                page_num - 1
            ));
        }
        if has_next {
            body.push_str(&format!(
                "<a href=\"{}/commits/{}?page={}\">older \u{2192}</a>",
                esc(&base),
                esc(rev),
                page_num + 1
            ));
        }
        body.push_str("</p>");
    }
    page(&format!("{owner}/{repo}: commits"), &body)
}

/// Single-commit view: metadata + the unified-diff patch in a `<pre>`.
#[must_use]
pub fn commit_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    meta: &solid_pod_rs_git::api::ResolvedCommit,
    patch: &str,
) -> String {
    let mut body = repo_header(prefix, owner, repo, &meta.hash);
    body.push_str(&format!(
        "<h2><code>{}</code></h2><p>{}</p>\
<p class=\"muted\">{} &lt;{}&gt;</p>",
        esc(&meta.hash),
        esc(&meta.subject),
        esc(&meta.author_name),
        esc(&meta.author_email)
    ));
    if let Some(parent) = &meta.parent {
        body.push_str(&format!(
            "<p class=\"muted\">parent <a href=\"{p}/{o}/{r}/commit/{par}\"><code>{par}</code></a></p>",
            p = esc(prefix),
            o = esc(owner),
            r = esc(repo),
            par = esc(parent)
        ));
    }
    body.push_str("<pre>");
    body.push_str(&esc(patch));
    body.push_str("</pre>");
    page(&format!("{owner}/{repo}: commit"), &body)
}

/// A ref list (branches or tags). `link_verb` is `"commits"` for branches
/// (link to the branch log) or `"tree"` for tags.
#[must_use]
pub fn refs_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    title: &str,
    current: Option<&str>,
    names: &[String],
    link_verb: &str,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, current.unwrap_or("HEAD"));
    body.push_str(&format!("<h2>{}</h2>", esc(title)));
    if names.is_empty() {
        body.push_str("<p class=\"muted\">None.</p>");
    } else {
        body.push_str("<table><tbody>");
        for n in names {
            let marker = if Some(n.as_str()) == current {
                " <span class=\"badge\">default</span>"
            } else {
                ""
            };
            body.push_str(&format!(
                "<tr><td><a href=\"{}/{}/{}\">{}</a>{}</td></tr>",
                esc(&base),
                link_verb,
                esc(n),
                esc(n),
                marker
            ));
        }
        body.push_str("</tbody></table>");
    }
    page(&format!("{owner}/{repo}: {title}"), &body)
}

// ---------------------------------------------------------------------------
// Tier 2 issue views
// ---------------------------------------------------------------------------

use crate::bodies::{BodyOutcome, RenderedThread};
use crate::spine::issues::{IssueEntry, IssueState};

fn state_badge(state: IssueState) -> &'static str {
    match state {
        IssueState::Open => "<span class=\"badge state-open\">open</span>",
        IssueState::Closed => "<span class=\"badge state-closed\">closed</span>",
        IssueState::Merged => "<span class=\"badge state-merged\">merged</span>",
    }
}

/// The issues list, with an open/closed filter and a "new issue" link.
#[must_use]
pub fn issues_list_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    filter: IssueState,
    open_count: usize,
    closed_count: usize,
    issues: &[&IssueEntry],
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, "HEAD");
    body.push_str(&format!(
        "<p><a href=\"{b}/issues?state=open\">{o} open</a> \u{b7} \
<a href=\"{b}/issues?state=closed\">{c} closed</a> \u{b7} \
<a href=\"{b}/issues/new\">new issue</a></p>",
        b = esc(&base),
        o = open_count,
        c = closed_count
    ));
    let _ = filter;
    if issues.is_empty() {
        body.push_str("<p class=\"muted\">No issues.</p>");
    } else {
        body.push_str("<table><tbody>");
        for e in issues {
            body.push_str(&format!(
                "<tr><td>{} <a href=\"{}/issues/{}\">#{} {}</a></td>\
<td class=\"muted\">{}</td></tr>",
                state_badge(e.state),
                esc(&base),
                e.number,
                e.number,
                esc(&e.title),
                esc(&e.author)
            ));
        }
        body.push_str("</tbody></table>");
    }
    page(&format!("{owner}/{repo}: issues"), &body)
}

/// The new-issue form. The body document is PUT to the author's pod by
/// the client first; this form submits the resulting `resourceUrl`
/// pointer plus a title. (Podless agents submit the body inline — Tier
/// 2.5.) Server-rendered, no script.
#[must_use]
pub fn issue_new_page(prefix: &str, owner: &str, repo: &str) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, "HEAD");
    body.push_str(&format!(
        "<h2>New issue</h2>\
<form method=\"post\" action=\"{b}/issues\">\
<p><label>Title<br><input name=\"title\" required></label></p>\
<p><label>Body resource URL (in your pod's forge area)<br>\
<input name=\"resourceUrl\" size=\"70\" placeholder=\"{b_esc}/public/forge/...\"></label></p>\
<p><button type=\"submit\">Create</button></p>\
</form>",
        b = esc(&base),
        b_esc = esc(&base)
    ));
    page(&format!("{owner}/{repo}: new issue"), &body)
}

fn render_body_outcome(out: &BodyOutcome) -> String {
    match out {
        BodyOutcome::Present(text) => format!("<pre>{}</pre>", esc(text)),
        BodyOutcome::Removed => {
            "<p class=\"muted\"><em>content removed by its author</em></p>".to_string()
        }
        BodyOutcome::TooLarge => {
            "<p class=\"muted\"><em>body too large to display</em></p>".to_string()
        }
        BodyOutcome::Unavailable(_) => {
            "<p class=\"muted\"><em>body currently unavailable</em></p>".to_string()
        }
    }
}

/// A single issue thread view: title/state header plus each re-fetched
/// body. `truncated` warns when the thread exceeded the read cap.
#[must_use]
pub fn issue_detail_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    entry: &IssueEntry,
    threads: &[RenderedThread],
    truncated: bool,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = repo_header(prefix, owner, repo, "HEAD");
    body.push_str(&format!(
        "<nav class=\"crumbs\"><a href=\"{}/issues\">issues</a></nav>",
        esc(&base)
    ));
    body.push_str(&format!(
        "<h2>{} #{} {}</h2>",
        state_badge(entry.state),
        entry.number,
        esc(&entry.title)
    ));
    for (i, t) in threads.iter().enumerate() {
        let role = if i == 0 { "opened" } else { "commented" };
        body.push_str(&format!(
            "<div><p class=\"muted\">{} {} \u{b7} {}</p>{}</div>",
            esc(&t.author),
            role,
            t.at,
            render_body_outcome(&t.body)
        ));
    }
    if truncated {
        body.push_str("<p class=\"muted\"><em>thread truncated at the read cap</em></p>");
    }
    // Comment form (points to the same POST endpoint as the detail route).
    body.push_str(&format!(
        "<h3>Comment</h3>\
<form method=\"post\" action=\"{b}/issues/{n}\">\
<p><label>Body resource URL<br><input name=\"resourceUrl\" size=\"70\"></label></p>\
<p><button type=\"submit\">Comment</button></p>\
</form>",
        b = esc(&base),
        n = entry.number
    ));
    page(&format!("{owner}/{repo}: #{}", entry.number), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_empty_shows_hint() {
        let p = index_page("/forge", &[]);
        assert!(p.contains("No repositories yet"));
    }

    #[test]
    fn index_lists_repos_escaped() {
        let repos = vec![("alice".to_string(), "<b>".to_string())];
        let p = index_page("/forge", &repos);
        assert!(p.contains("/forge/alice/&lt;b&gt;"));
        assert!(!p.contains("/forge/alice/<b>"));
    }

    #[test]
    fn owner_page_renders() {
        let p = owner_page("/forge", "alice", &["r1".into(), "r2".into()]);
        assert!(p.contains("<h1>alice</h1>"));
        assert!(p.contains("/forge/alice/r1"));
    }
}
