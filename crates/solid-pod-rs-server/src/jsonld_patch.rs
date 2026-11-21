//! PATCH of a stored JSON-LD resource, or of the JSON-LD data island of a
//! stored HTML page (SP-PAR-276).
//!
//! The stored body is read into a graph against the resource's real URL and
//! written back in the form it was stored in. Relative IRIs only mean
//! something against a known URL, so the caller refuses this path unless a
//! public origin is configured: the base is never taken from a request `Host`.
//!
//! An HTML page keeps everything outside the first
//! `<script type="application/ld+json">` element byte for byte; the new JSON
//! is written with `<` escaped as `<`, so no literal in the graph can
//! close the script element and inject markup.

use solid_pod_rs::ldp::Graph;

/// How a resource that can be patched as JSON-LD is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredForm {
    /// The whole body is the JSON-LD document.
    Document,
    /// An HTML page whose first JSON-LD `<script>` element is the document;
    /// `before` and `after` are the page text around its content.
    HtmlIsland {
        /// Everything up to and including the opening tag's `>`.
        before: String,
        /// Everything from the closing `</script` onwards.
        after: String,
    },
}

/// Recognise a stored JSON-LD document or HTML data island: the form and the
/// JSON text of the document. `None` for anything else (Turtle, N-Triples,
/// plain JSON, HTML without an island).
#[must_use]
pub fn detect(body: &[u8], content_type: &str) -> Option<(StoredForm, Vec<u8>)> {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    if ct.eq_ignore_ascii_case("application/ld+json") {
        return Some((StoredForm::Document, body.to_vec()));
    }
    if !ct.eq_ignore_ascii_case("text/html") {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<script") {
        let start = from + rel;
        let tag_end = start + lower[start..].find('>')?;
        let tag = &lower[start..tag_end];
        // `<script` must be followed by whitespace or `>`: not `<scripted`.
        let after_name = tag.as_bytes().get("<script".len()).copied();
        let is_script = matches!(after_name, None | Some(b' ' | b'\t' | b'\n' | b'\r' | b'/'));
        if is_script && tag.contains("application/ld+json") {
            let content_start = tag_end + 1;
            let close = content_start + lower[content_start..].find("</script")?;
            return Some((
                StoredForm::HtmlIsland {
                    before: text[..content_start].to_string(),
                    after: text[close..].to_string(),
                },
                text[content_start..close].as_bytes().to_vec(),
            ));
        }
        from = tag_end + 1;
    }
    None
}

/// Write `graph` back in `form`: its JSON-LD (expanded form, absolute IRIs),
/// inside the page for an island. Returns the new body and its content type.
#[must_use]
pub fn render(form: &StoredForm, graph: &Graph) -> (Vec<u8>, &'static str) {
    let json = serde_json::to_string_pretty(&graph.to_jsonld())
        .unwrap_or_else(|_| "[]".to_string())
        // `<` as a JSON escape: valid JSON, and never a `</script` in the page.
        .replace('<', "\\u003c");
    match form {
        StoredForm::Document => (json.into_bytes(), "application/ld+json"),
        StoredForm::HtmlIsland { before, after } => (
            format!("{before}\n{json}\n{after}").into_bytes(),
            "text/html",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_documents_and_islands() {
        assert!(matches!(
            detect(b"{}", "application/ld+json; charset=utf-8"),
            Some((StoredForm::Document, _))
        ));
        assert!(detect(b"{}", "application/json").is_none());
        assert!(detect(b"<a> <b> <c> .", "text/turtle").is_none());
        let page = br##"<!DOCTYPE html><html><body><script>x()</script>
<SCRIPT TYPE="application/ld+json">{"@id":"#a"}</SCRIPT><p>after</p></body></html>"##;
        let (form, json) = detect(page, "text/html").unwrap();
        assert_eq!(json, br##"{"@id":"#a"}"##);
        let StoredForm::HtmlIsland { before, after } = form else {
            panic!("island")
        };
        assert!(before.ends_with('>') && after.starts_with("</SCRIPT"));
        assert!(detect(
            b"<html><scripted type=\"application/ld+json\">{}</scripted></html>",
            "text/html"
        )
        .is_none());
        assert!(detect(b"<html><p>no island</p></html>", "text/html").is_none());
    }

    #[test]
    fn render_never_closes_the_script_element() {
        let mut g = Graph::new();
        g.insert(solid_pod_rs::ldp::Triple::new(
            solid_pod_rs::ldp::Term::Iri("http://e/s".into()),
            solid_pod_rs::ldp::Term::Iri("http://e/p".into()),
            solid_pod_rs::ldp::Term::literal("</script><img src=x onerror=alert(1)>"),
        ));
        let form = StoredForm::HtmlIsland {
            before: "<html><script type=\"application/ld+json\">".into(),
            after: "</script></html>".into(),
        };
        let (bytes, ct) = render(&form, &g);
        let page = String::from_utf8(bytes).unwrap();
        assert_eq!(ct, "text/html");
        assert_eq!(
            page.to_ascii_lowercase().matches("</script").count(),
            1,
            "{page}"
        );
        assert!(!page.contains("<img"), "{page}");
        // And it is still the same JSON.
        let (_, json) = detect(page.as_bytes(), "text/html").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(v.to_string().contains("</script>"));
    }
}
