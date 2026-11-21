//! Locate the JSON-LD data island of an HTML document with a real HTML parser.
//!
//! A WebID profile card (and any HTML resource that carries linked data) holds
//! its data in a `<script type="application/ld+json">` element. This module is
//! the one place that finds it: [`crate::webid`] reads through
//! [`first_jsonld_island`], and the PATCH write path edits through
//! [`sole_jsonld_island`] and [`SoleIsland::replace`], so a reader and a writer
//! can never disagree about which element is "the" island.
//!
//! The HTML parser (`html5ever`, the WHATWG algorithm) decides what is an
//! element and what is text, so an island that sits in a comment, an attribute
//! value, a `<textarea>` or a `<title>` is not an island. The `type` attribute
//! matches when its essence is `application/ld+json`, ASCII case-insensitive,
//! parameters (`; profile=...`) allowed.
//!
//! # Writing
//!
//! The parser reports no source offsets, so the writer does not trust a search:
//! [`SoleIsland::replace`] splices the new text into the original bytes at each
//! place the parsed text occurs, re-parses the whole result, and accepts the
//! splice only if the new tree is the old tree with exactly the island's text
//! changed (doctype, comments, attributes, template contents, every other text
//! node). Anything else is refused, and the caller writes nothing.
//!
//! # Example
//!
//! ```
//! use solid_pod_rs::html_island::{first_jsonld_island, sole_jsonld_island};
//!
//! let html = "<!DOCTYPE html><title>x</title>\n\
//!     <script type=\"Application/LD+JSON; charset=utf-8\">{\"@id\": \"a\"}</script>";
//! assert_eq!(first_jsonld_island(html).unwrap().unwrap(), "{\"@id\": \"a\"}");
//!
//! let island = sole_jsonld_island(html).unwrap();
//! let out = island.replace(html, "{\"@id\": \"b\"}").unwrap();
//! assert!(out.contains("{\"@id\": \"b\"}") && out.starts_with("<!DOCTYPE html>"));
//! ```

use std::fmt::Write as _;
use std::rc::Rc;

use html5ever::tendril::TendrilSink;
use html5ever::{parse_document, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};

/// Largest HTML document this module will parse, in bytes. Matches
/// [`crate::rdf_input::MAX_RDF_INPUT_BYTES`]: a document that cannot be read as
/// RDF at that size is not parsed as HTML either.
pub const MAX_HTML_BYTES: usize = crate::rdf_input::MAX_RDF_INPUT_BYTES;

/// Most places the island's text may occur as a script element's whole
/// content before [`SoleIsland::replace`] refuses (each costs a full parse).
const MAX_SPLICE_CANDIDATES: usize = 8;

/// Why an island could not be located or replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IslandError {
    /// The document is larger than [`MAX_HTML_BYTES`].
    TooLarge,
    /// The document has no JSON-LD data island.
    NoIsland,
    /// The document has more than one JSON-LD data island.
    SeveralIslands,
    /// The document contains a carriage return or NUL, which the HTML input
    /// stage rewrites, so source bytes cannot be mapped to the parsed text.
    Unlocatable,
    /// The island's source bytes could not be found unambiguously, or the
    /// spliced document did not re-parse to the original tree with only the
    /// island's text changed.
    Altered,
}

impl std::fmt::Display for IslandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "HTML document is too large",
            Self::NoIsland => "no JSON-LD data island",
            Self::SeveralIslands => "more than one JSON-LD data island",
            Self::Unlocatable => "the island cannot be located byte for byte",
            Self::Altered => "the island could not be replaced without altering the document",
        })
    }
}

impl std::error::Error for IslandError {}

fn parse(html: &str) -> Result<RcDom, IslandError> {
    if html.len() > MAX_HTML_BYTES {
        return Err(IslandError::TooLarge);
    }
    Ok(parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .one(html.as_bytes()))
}

fn is_island_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .eq_ignore_ascii_case("application/ld+json")
}

fn is_html_script(node: &Handle) -> bool {
    matches!(&node.data, NodeData::Element { name, .. }
        if &*name.ns == "http://www.w3.org/1999/xhtml" && &*name.local == "script")
}

fn is_island(node: &Handle) -> bool {
    match &node.data {
        NodeData::Element { attrs, .. } if is_html_script(node) => attrs
            .borrow()
            .iter()
            .any(|a| &*a.name.local == "type" && a.name.ns.is_empty() && is_island_type(&a.value)),
        _ => false,
    }
}

/// Children of `node` in document order, template contents included (a
/// `<template>` element's children live in a separate fragment).
fn children_of(node: &Handle) -> Vec<Handle> {
    let mut v: Vec<Handle> = Vec::new();
    if let NodeData::Element {
        template_contents, ..
    } = &node.data
    {
        if let Some(t) = template_contents.borrow().as_ref() {
            v.push(t.clone());
        }
    }
    v.extend(node.children.borrow().iter().cloned());
    v
}

/// Every island element in document order. Iterative: the tree can be as
/// deep as the input allows.
fn islands(dom: &RcDom) -> Vec<Handle> {
    let mut out = Vec::new();
    let mut stack = vec![dom.document.clone()];
    while let Some(n) = stack.pop() {
        if is_island(&n) {
            out.push(n.clone());
        }
        let mut kids = children_of(&n);
        kids.reverse();
        stack.extend(kids);
    }
    out
}

fn text_of(node: &Handle) -> String {
    let mut s = String::new();
    for c in node.children.borrow().iter() {
        if let NodeData::Text { contents } = &c.data {
            s.push_str(&contents.borrow());
        }
    }
    s
}

/// The text of the first JSON-LD data island in `html`, in document order, or
/// `None` when there is none. This is what readers use.
///
/// # Errors
///
/// [`IslandError::TooLarge`] over [`MAX_HTML_BYTES`].
pub fn first_jsonld_island(html: &str) -> Result<Option<String>, IslandError> {
    let dom = parse(html)?;
    Ok(islands(&dom).first().map(text_of))
}

/// The one JSON-LD data island of a document, with enough to replace its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoleIsland {
    /// The element's text exactly as the parser sees it (raw text: no entity
    /// decoding).
    pub text: String,
}

/// Locate the only JSON-LD island of `html`.
///
/// # Errors
///
/// [`IslandError::NoIsland`] / [`IslandError::SeveralIslands`] unless there
/// is exactly one, [`IslandError::Unlocatable`] when the source holds a
/// carriage return or NUL, [`IslandError::TooLarge`] over [`MAX_HTML_BYTES`].
pub fn sole_jsonld_island(html: &str) -> Result<SoleIsland, IslandError> {
    let dom = parse(html)?;
    let found = islands(&dom);
    match found.as_slice() {
        [] => Err(IslandError::NoIsland),
        [one] => {
            if html.bytes().any(|b| b == b'\r' || b == 0) {
                return Err(IslandError::Unlocatable);
            }
            Ok(SoleIsland { text: text_of(one) })
        }
        _ => Err(IslandError::SeveralIslands),
    }
}

impl SoleIsland {
    /// Replace the island's text with `new_text` in `html` (the same document
    /// [`sole_jsonld_island`] read), leaving every other byte as it was.
    ///
    /// A `new_text` that could end the element early or open another one
    /// (`</script>`, `<script`) is caught by the whole-tree comparison below
    /// and refused; callers that write JSON should escape `<` as `\u003c`
    /// anyway.
    ///
    /// # Errors
    ///
    /// [`IslandError::Altered`] when the island text is not found exactly once
    /// in a position that verifies, or when the re-parsed result is not the original tree with only the island's text
    /// changed.
    pub fn replace(&self, html: &str, new_text: &str) -> Result<String, IslandError> {
        if self.text.is_empty() {
            return Err(IslandError::Altered);
        }
        let old_dom = parse(html)?;
        let old_islands = islands(&old_dom);
        let [old_island] = old_islands.as_slice() else {
            return Err(IslandError::Altered);
        };
        if text_of(old_island) != self.text {
            return Err(IslandError::Altered);
        }
        let want = canon(&old_dom.document, old_island, Some(new_text));

        let bytes = html.as_bytes();
        let t = self.text.as_bytes();
        // Every place the parsed text sits between a `>` and a `</script`.
        // Each candidate costs one full parse, so a page that offers more
        // than a handful is refused rather than tried.
        let mut candidates: Vec<usize> = Vec::new();
        let mut from = 0;
        while let Some(rel) = html[from..].find(self.text.as_str()) {
            let at = from + rel;
            from = at + 1;
            while !html.is_char_boundary(from) {
                from += 1;
            }
            let end = at + t.len();
            let closes = bytes
                .get(end..end + 8)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"</script"));
            if at > 0 && bytes[at - 1] == b'>' && closes {
                candidates.push(at);
                if candidates.len() > MAX_SPLICE_CANDIDATES {
                    return Err(IslandError::Altered);
                }
            }
        }
        let mut accepted: Option<String> = None;
        for at in candidates {
            let end = at + t.len();
            let mut out = String::with_capacity(html.len() - t.len() + new_text.len());
            out.push_str(&html[..at]);
            out.push_str(new_text);
            out.push_str(&html[end..]);
            if out.len() > MAX_HTML_BYTES {
                continue;
            }
            let new_dom = parse(&out)?;
            let new_islands = islands(&new_dom);
            let [new_island] = new_islands.as_slice() else {
                continue;
            };
            if text_of(new_island) == new_text && canon(&new_dom.document, new_island, None) == want
            {
                if accepted.is_some() {
                    return Err(IslandError::Altered);
                }
                accepted = Some(out);
            }
        }
        accepted.ok_or(IslandError::Altered)
    }
}

/// A canonical, unambiguous rendering of a whole tree (doctype, comments,
/// processing instructions, elements with namespace and attributes in source
/// order, text, template contents) in which `island`'s text is `override_text`
/// when given. Length-prefixed so two different trees never render alike.
fn canon(root: &Handle, island: &Handle, override_text: Option<&str>) -> String {
    enum Step {
        Enter(Handle),
        Exit,
    }
    fn put(out: &mut String, tag: char, s: &str) {
        let _ = write!(out, "{tag}{}:{s};", s.len());
    }
    let mut out = String::new();
    let mut stack = vec![Step::Enter(root.clone())];
    while let Some(step) = stack.pop() {
        let node = match step {
            Step::Exit => {
                out.push(')');
                continue;
            }
            Step::Enter(n) => n,
        };
        match &node.data {
            NodeData::Document => out.push('D'),
            NodeData::Doctype {
                name,
                public_id,
                system_id,
            } => {
                put(&mut out, 'T', name);
                put(&mut out, 'p', public_id);
                put(&mut out, 's', system_id);
            }
            NodeData::Text { contents } => put(&mut out, 'x', &contents.borrow()),
            NodeData::Comment { contents } => put(&mut out, 'c', contents),
            NodeData::ProcessingInstruction { target, contents } => {
                put(&mut out, 'i', target);
                put(&mut out, 'j', contents);
            }
            NodeData::Element { name, attrs, .. } => {
                put(&mut out, 'e', &name.ns);
                put(&mut out, 'n', &name.local);
                for a in attrs.borrow().iter() {
                    put(&mut out, 'a', &a.name.ns);
                    put(&mut out, 'k', &a.name.local);
                    put(&mut out, 'v', &a.value);
                }
            }
        }
        out.push('(');
        stack.push(Step::Exit);
        if Rc::ptr_eq(&node, island) {
            let text = override_text.map_or_else(|| text_of(&node), str::to_string);
            put(&mut out, 'x', &text);
            continue;
        }
        let mut kids = children_of(&node);
        kids.reverse();
        stack.extend(kids.into_iter().map(Step::Enter));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "<!DOCTYPE html>\n<html><head><title>t</title>\n\
        <script type=\"application/ld+json\">\n{\"@id\": \"a\"}\n</script>\n</head>\n\
        <body><p>hi</p></body></html>";

    #[test]
    fn finds_the_island_and_replaces_only_its_text() {
        let isl = sole_jsonld_island(DOC).unwrap();
        assert_eq!(isl.text, "\n{\"@id\": \"a\"}\n");
        let out = isl.replace(DOC, "\n{\"@id\": \"b\"}\n").unwrap();
        assert_eq!(out, DOC.replace("\"a\"", "\"b\""));
    }

    #[test]
    fn type_matches_case_insensitively_with_parameters() {
        for t in [
            "application/ld+json",
            "APPLICATION/LD+JSON",
            " application/ld+json ; profile=\"x\"",
        ] {
            let h = format!("<script type=\"{t}\">{{}}</script>");
            assert_eq!(
                first_jsonld_island(&h).unwrap().as_deref(),
                Some("{}"),
                "{t}"
            );
        }
        for t in ["application/json", "application/ld+json5", "text/ld+json"] {
            let h = format!("<script type=\"{t}\">{{}}</script>");
            assert_eq!(first_jsonld_island(&h).unwrap(), None, "{t}");
        }
    }

    #[test]
    fn markup_that_only_looks_like_an_island_is_not_one() {
        for h in [
            "<!-- <script type=\"application/ld+json\">{}</script> -->",
            "<p title='<script type=\"application/ld+json\">{}</script>'>x</p>",
            "<textarea><script type=\"application/ld+json\">{}</script></textarea>",
            "<title><script type=\"application/ld+json\">{}</script></title>",
            "<noscript><script type=\"application/ld+json\">{}</script></noscript>",
            "<svg><script type=\"application/ld+json\">{}</script></svg>",
        ] {
            assert_eq!(first_jsonld_island(h).unwrap(), None, "{h}");
        }
    }

    #[test]
    fn zero_or_several_islands_are_not_sole() {
        assert_eq!(sole_jsonld_island("<p>x</p>"), Err(IslandError::NoIsland));
        let two = "<script type=\"application/ld+json\">{}</script>\
                   <script type=\"application/ld+json\">{}</script>";
        assert_eq!(sole_jsonld_island(two), Err(IslandError::SeveralIslands));
        // A second island hidden in a template still counts.
        let tpl = "<script type=\"application/ld+json\">{}</script>\
                   <template><script type=\"application/ld+json\">{}</script></template>";
        assert_eq!(sole_jsonld_island(tpl), Err(IslandError::SeveralIslands));
        // Readers take the first in document order.
        assert_eq!(first_jsonld_island(two).unwrap().as_deref(), Some("{}"));
    }

    #[test]
    fn carriage_returns_and_oversize_are_refused() {
        let h = "<script type=\"application/ld+json\">{}\r\n</script>";
        assert_eq!(sole_jsonld_island(h), Err(IslandError::Unlocatable));
        let big = format!("<p>{}</p>", "x".repeat(MAX_HTML_BYTES));
        assert_eq!(first_jsonld_island(&big), Err(IslandError::TooLarge));
    }

    #[test]
    fn a_replacement_that_could_open_markup_is_refused() {
        let isl = sole_jsonld_island(DOC).unwrap();
        for bad in [
            "</script><script>x</script>",
            "x</script><p>y</p><script>",
            "</SCRIPT ><b>",
        ] {
            assert_eq!(isl.replace(DOC, bad), Err(IslandError::Altered), "{bad}");
        }
        // Markup-looking text that stays inside the element is fine.
        let ok = isl.replace(DOC, "{\"a\": \"<b>&amp;</b>\"}").unwrap();
        assert_eq!(
            sole_jsonld_island(&ok).unwrap().text,
            "{\"a\": \"<b>&amp;</b>\"}"
        );
    }

    #[test]
    fn many_look_alike_scripts_are_refused_not_parsed_one_by_one() {
        let decoys = "<script type=\"text/plain\">{}</script>".repeat(50);
        let h = format!("{decoys}<script type=\"application/ld+json\">{{}}</script>");
        let isl = sole_jsonld_island(&h).unwrap();
        assert_eq!(isl.replace(&h, "{\"a\": 1}"), Err(IslandError::Altered));
    }

    #[test]
    fn the_same_text_elsewhere_is_not_confused_with_the_island() {
        // The island text also appears in an earlier attribute and a comment.
        let h = "<!-- {} --><p title=\"{}\">{}</p>\
                 <script type=\"application/ld+json\">{}</script>";
        let isl = sole_jsonld_island(h).unwrap();
        let out = isl.replace(h, "{\"a\": 1}").unwrap();
        assert_eq!(
            out,
            "<!-- {} --><p title=\"{}\">{}</p>\
             <script type=\"application/ld+json\">{\"a\": 1}</script>"
        );
    }
}
