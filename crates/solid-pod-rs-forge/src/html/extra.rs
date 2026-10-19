//! Views for the read features: the filterable repository index, the in-repo
//! search page, the releases page, and small fragments injected into the
//! existing browse pages (description, search box, open-issue count).
//!
//! Every interpolated value passes through [`crate::request::esc`].

use crate::api::RepoSummary;
use crate::html::{agent_label, crumbs, page};
use crate::releases::Release;
use crate::request::esc;
use crate::search::{SearchResult, SEARCH_HIT_CAP, SEARCH_PATH_CAP};

/// The repository index with a plain server-side `?q=` GET filter (no JS),
/// descriptions, and the public / private badge (JSS `indexPage`).
///
/// `had_any` says whether any repository exists before filtering, so an
/// empty filter result reads "No repositories match" rather than "No
/// repositories yet".
#[must_use]
pub fn index_page_full(
    prefix: &str,
    repos: &[RepoSummary],
    q: &str,
    had_any: bool,
    private: bool,
) -> String {
    let mut body = String::from("<h1>Repositories</h1>");
    body.push_str(&format!(
        "<form class=\"searchform\" method=\"get\" action=\"{}/\" style=\"margin-bottom:1rem\">\
<input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Find a repository&hellip;\" aria-label=\"Find a repository\">\
<button type=\"submit\">Search</button></form>",
        esc(prefix),
        esc(q)
    ));
    if repos.is_empty() {
        if !q.is_empty() && had_any {
            body.push_str(&format!(
                "<p><strong>No repositories match</strong></p><p class=\"muted\">Nothing named or described like <code>{}</code>.</p>",
                esc(q)
            ));
        } else {
            body.push_str(&format!(
                "<p class=\"muted\">No repositories yet. Push to <code>{}/&lt;owner&gt;/&lt;repo&gt;.git</code> to create one.</p>",
                esc(prefix)
            ));
        }
    } else {
        let badge = if private { "Private" } else { "Public" };
        for r in repos {
            body.push_str(&format!(
                "<div class=\"repocard\"><h3><a href=\"{p}/{o}\">{ol}</a>/<a href=\"{p}/{o}/{n}\"><b>{n}</b></a> <span class=\"badge\">{badge}</span></h3>{desc}</div>",
                p = esc(prefix),
                o = esc(&r.owner),
                ol = esc(&agent_label(&r.owner)),
                n = esc(&r.name),
                desc = if r.description.is_empty() {
                    String::new()
                } else {
                    format!("<div class=\"muted\">{}</div>", esc(&r.description))
                },
            ));
        }
    }
    page("forge", &body)
}

/// Fragment shown under the repo header on the overview: description, the
/// search box (a plain GET form to `<repo>/search`), and links to releases
/// and the open-issue count.
#[must_use]
pub fn repo_extras(
    prefix: &str,
    owner: &str,
    repo: &str,
    description: &str,
    open_issues: usize,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut out = String::new();
    if !description.is_empty() {
        out.push_str(&format!(
            "<p class=\"repo-description\">{}</p>",
            esc(description)
        ));
    }
    out.push_str(&format!(
        "<form class=\"searchform\" method=\"get\" action=\"{b}/search\">\
<input type=\"search\" name=\"q\" placeholder=\"Search this repository&hellip;\" aria-label=\"Search this repository\">\
<button type=\"submit\">Search</button></form>\
<p class=\"muted\"><a href=\"{b}/issues\">Issues <span class=\"badge\">{open_issues}</span></a> \u{b7} \
<a href=\"{b}/releases\">Releases</a></p>",
        b = esc(&base),
    ));
    out
}

/// A link from the Tags page to the Releases page.
#[must_use]
pub fn releases_link(prefix: &str, owner: &str, repo: &str) -> String {
    format!(
        "<p><a href=\"{}/{}/{}/releases\">Releases</a> with downloads</p>",
        esc(prefix),
        esc(owner),
        esc(repo)
    )
}

/// Insert `fragment` right after the shared page header. `fragment` must
/// already be escaped.
#[must_use]
pub fn inject_after_header(page_html: &str, fragment: &str) -> String {
    page_html.replacen("</header>", &format!("</header>{fragment}"), 1)
}

/// The in-repo search page (JSS `searchPage`): a GET form, then either a hint,
/// the results, or "No results".
#[must_use]
pub fn search_page(
    prefix: &str,
    owner: &str,
    repo: &str,
    branch: &str,
    q: &str,
    data: Option<&SearchResult>,
) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = crumbs(&[
        ("forge", Some(prefix.to_string())),
        (&agent_label(owner), Some(format!("{prefix}/{owner}"))),
        (repo, Some(base.clone())),
        ("search", None),
    ]);
    body.push_str("<h1>Search</h1>");
    body.push_str(&format!(
        "<form class=\"searchform\" method=\"get\" action=\"{}/search\">\
<input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Search this repository&hellip;\" aria-label=\"Search this repository\">\
<button type=\"submit\">Search</button></form>",
        esc(&base),
        esc(q)
    ));
    match data {
        None => body.push_str(&format!(
            "<p class=\"muted\">Greps the default branch (<b>{}</b>) for a literal, case-insensitive substring: bounded, no index.</p>",
            esc(branch)
        )),
        Some(d) if d.matches.is_empty() && d.paths.is_empty() => body.push_str(&format!(
            "<h3>No results</h3><p class=\"muted\">Nothing on <b>{}</b> matches <code>{}</code>.</p>",
            esc(branch),
            esc(q)
        )),
        Some(d) => {
            if !d.matches.is_empty() {
                body.push_str(&format!(
                    "<h3>{}{} code match{}</h3><table><tbody>",
                    d.matches.len(),
                    if d.truncated { "+" } else { "" },
                    if d.matches.len() == 1 { "" } else { "es" }
                ));
                for m in &d.matches {
                    body.push_str(&format!(
                        "<tr><td><a class=\"mono\" href=\"{b}/blob/{br}/{p}#L{l}\">{p}:{l}</a><pre>{t}</pre></td></tr>",
                        b = esc(&base),
                        br = esc(branch),
                        p = esc(&m.path),
                        l = m.line,
                        t = esc(&m.text)
                    ));
                }
                body.push_str("</tbody></table>");
            }
            if !d.paths.is_empty() {
                body.push_str(&format!(
                    "<h3>{} matching file path{}</h3><table><tbody>",
                    d.paths.len(),
                    if d.paths.len() == 1 { "" } else { "s" }
                ));
                for p in &d.paths {
                    body.push_str(&format!(
                        "<tr><td><a href=\"{}/blob/{}/{}\">{}</a></td></tr>",
                        esc(&base),
                        esc(branch),
                        esc(p),
                        esc(p)
                    ));
                }
                body.push_str("</tbody></table>");
            }
            if d.truncated {
                body.push_str(&format!(
                    "<p class=\"muted\">Results are capped ({SEARCH_HIT_CAP} code matches, {SEARCH_PATH_CAP} paths); narrow the query for the rest.</p>"
                ));
            }
        }
    }
    page(&format!("Search \u{b7} {owner}/{repo}"), &body)
}

/// The releases page (JSS `releasesPage`): one card per tag with downloads.
#[must_use]
pub fn releases_page(prefix: &str, owner: &str, repo: &str, rels: &[Release]) -> String {
    let base = format!("{prefix}/{owner}/{repo}");
    let mut body = crumbs(&[
        ("forge", Some(prefix.to_string())),
        (&agent_label(owner), Some(format!("{prefix}/{owner}"))),
        (repo, Some(base.clone())),
        ("releases", None),
    ]);
    body.push_str("<h1>Releases <span class=\"muted\">every tag, newest first</span></h1>");
    if rels.is_empty() {
        body.push_str("<p><strong>No releases yet</strong></p><p class=\"muted\">Push a tag and it appears here with tarball and zip downloads.</p>");
    }
    for r in rels {
        body.push_str(&format!(
            "<div class=\"repocard\"><h3><a href=\"{b}/tree/{t}\">{t}</a>{light}</h3>{msg}\
<div class=\"muted\"><a href=\"{b}/commit/{s}\">{short}</a></div>\
<p><a href=\"{b}/archive/{t}.tar.gz\">tar.gz</a> \u{b7} <a href=\"{b}/archive/{t}.zip\">zip</a></p></div>",
            b = esc(&base),
            t = esc(&r.tag),
            s = esc(&r.sha),
            short = esc(&r.sha.chars().take(7).collect::<String>()),
            light = if r.annotated { "" } else { " <span class=\"badge\">lightweight</span>" },
            msg = r
                .message
                .as_deref()
                .filter(|m| !m.is_empty())
                .map_or_else(String::new, |m| format!("<div>{}</div>", esc(m))),
        ));
    }
    page(&format!("Releases \u{b7} {owner}/{repo}"), &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(o: &str, n: &str, d: &str) -> RepoSummary {
        RepoSummary {
            owner: o.into(),
            name: n.into(),
            description: d.into(),
            last_push: None,
        }
    }

    #[test]
    fn index_filter_states_and_escaping() {
        let h = index_page_full(
            "/forge",
            &[s("casey", "demo", "A <b>demo</b>")],
            "",
            true,
            false,
        );
        assert!(h.contains("name=\"q\""));
        assert!(h.contains("/forge/casey/demo"));
        assert!(h.contains("A &lt;b&gt;demo&lt;/b&gt;"));
        assert!(h.contains("Public"));
        let h = index_page_full("/forge", &[], "zzz<", true, true);
        assert!(h.contains("No repositories match"));
        assert!(h.contains("zzz&lt;"));
        let h = index_page_full("/forge", &[], "", false, false);
        assert!(h.contains("No repositories yet"));
        assert!(index_page_full("/forge", &[s("a", "b", "")], "", true, true).contains("Private"));
    }

    #[test]
    fn injection_lands_after_header_once() {
        let p = page("t", "<p>x</p>");
        let out = inject_after_header(&p, "<i>frag</i>");
        assert!(out.contains("</header><i>frag</i><p>x</p>"));
        assert_eq!(out.matches("<i>frag</i>").count(), 1);
    }

    #[test]
    fn repo_extras_has_search_box_description_and_badge() {
        let h = repo_extras(
            "/forge",
            "casey",
            "demo",
            "A demo repo with <angle> brackets",
            3,
        );
        assert!(h.contains("A demo repo with &lt;angle&gt; brackets"));
        assert!(h.contains("action=\"/forge/casey/demo/search\""));
        assert!(h.contains("<span class=\"badge\">3</span>"));
    }
}
