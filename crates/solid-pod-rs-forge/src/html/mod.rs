//! Server-rendered HTML views — zero framework, inline CSS, every
//! interpolation passed through [`crate::request::esc`].
//!
//! There is no templating engine and no client-side JS in the rendered
//! markup: the forge is server-rendered by construction, and the XSS
//! spine is content-type + `esc()` (see [`crate::request`]).

use crate::request::esc;

mod extra;
mod views;
pub use extra::*;
pub use views::*;

/// Minimal inline stylesheet shared by every page. Kept tiny and inline
/// so the forge serves without any external asset dependency.
const STYLE: &str = "\
:root{color-scheme:light dark}\
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\
max-width:60rem;margin:1.5rem auto;padding:0 1rem;line-height:1.5}\
a{color:#3573b3;text-decoration:none}a:hover{text-decoration:underline}\
header.forge{border-bottom:1px solid #8884;margin-bottom:1rem;padding-bottom:.5rem}\
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}\
pre{background:#8881;padding:.75rem;border-radius:6px;overflow-x:auto}\
table{border-collapse:collapse;width:100%}\
td,th{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #8883}\
.muted{color:#8888}.badge{font-size:.8rem;padding:.1rem .45rem;border-radius:10px;background:#8882}\
.state-open{background:#2c9e4b33;color:#2c9e4b}.state-closed{background:#b5433933;color:#b54339}\
.state-merged{background:#8250df33;color:#8250df}\
nav.crumbs{font-size:.95rem;margin-bottom:.75rem}\
.label-chip{display:inline-block;font-size:.75rem;font-weight:500;line-height:1.4;padding:0 .6em;border-radius:2em}\
.repocard{border:1px solid #8884;border-radius:8px;padding:.5rem 1rem;margin-bottom:.75rem}\
";

/// Wrap `body_html` in a full HTML document with a shared header and the
/// inline stylesheet. `title` is escaped; `body_html` must already be
/// composed of `esc()`'d values.
#[must_use]
pub fn page(title: &str, body_html: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{}</title><style>{}</style></head><body>\
<header class=\"forge\"><strong>\u{2692} forge</strong></header>{}</body></html>",
        esc(title),
        STYLE,
        body_html
    )
}

/// The label to *show* for an owner or author: a `did:nostr` agent (a bare
/// 64-hex public key, or `did:nostr:` plus one) is shown shortened with
/// [`crate::gitmark::did_short`] and never as an `npub`; anything else is shown
/// as it is. Display only: hrefs, ids and API fields keep the canonical hex.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::html::agent_label;
///
/// let hex = format!("4a578b54{}", "ab".repeat(28));
/// assert_eq!(agent_label(&hex), "did:nostr:4a578b54…");
/// assert_eq!(agent_label(&format!("did:nostr:{hex}")), "did:nostr:4a578b54…");
/// assert_eq!(agent_label("alice"), "alice");
/// ```
#[must_use]
pub fn agent_label(agent: &str) -> String {
    let hex = agent.strip_prefix("did:nostr:").unwrap_or(agent);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        crate::gitmark::did_short(hex)
    } else {
        agent.to_string()
    }
}

/// Render a breadcrumb nav bar from `(label, href)` pairs. The last
/// entry is rendered as plain (non-link) text.
#[must_use]
pub fn crumbs(items: &[(&str, Option<String>)]) -> String {
    let mut out = String::from("<nav class=\"crumbs\">");
    for (i, (label, href)) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(" / ");
        }
        match href {
            Some(h) => out.push_str(&format!("<a href=\"{}\">{}</a>", esc(h), esc(label))),
            None => out.push_str(&esc(label)),
        }
    }
    out.push_str("</nav>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_escapes_title() {
        let p = page("<x>", "<p>ok</p>");
        assert!(p.contains("<title>&lt;x&gt;</title>"));
        assert!(p.contains("<p>ok</p>"));
        assert!(p.starts_with("<!doctype html>"));
    }

    #[test]
    fn agent_label_shortens_only_nostr_keys() {
        let hex = format!("4a578b54{}", "cd".repeat(28));
        assert_eq!(agent_label(&hex), "did:nostr:4a578b54…");
        assert_eq!(agent_label(&hex.to_uppercase()), "did:nostr:4A578B54…");
        // a 63-character string is not a key
        assert_eq!(agent_label(&hex[1..]), hex[1..]);
        assert_eq!(agent_label("did:web:example.com"), "did:web:example.com");
    }

    #[test]
    fn crumbs_last_is_plain_text() {
        let c = crumbs(&[
            ("home", Some("/forge".into())),
            ("alice", Some("/forge/alice".into())),
            ("repo", None),
        ]);
        assert!(c.contains("<a href=\"/forge\">home</a>"));
        assert!(c.contains(" / repo</nav>"));
        // The final crumb is not a link.
        assert!(!c.contains(">repo</a>"));
    }
}
