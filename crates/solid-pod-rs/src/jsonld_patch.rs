//! In-place PATCH write-back for a stored JSON-LD document or an HTML data
//! island (parity row 276).
//!
//! # What it does
//!
//! A PATCH is evaluated by the ordinary patch engine on the document's graph
//! `G0`, giving `G1`. This module turns the difference (`G0 ∖ G1` deleted,
//! `G1 ∖ G0` inserted) into **byte-range edits of the original text**: a value
//! is removed, a value is added to an existing key, or a key is appended to an
//! existing node object. Every byte outside an edited range is kept as stored
//! (key order, whitespace, escapes, number forms, untouched values), and for an
//! HTML document everything outside the island's text is kept byte for byte
//! (see [`crate::html_island`]).
//!
//! The graph is never serialised back. Nothing is regenerated, so nothing that
//! the writer does not understand can be dropped or reshaped.
//!
//! # Supported shape
//!
//! The server refuses (with [`Refusal`]) any document outside this shape:
//!
//! * the JSON-LD text is one object, at most 4 MiB, nested at most 32 deep,
//!   without duplicate keys;
//! * its `@context`, if present, is **one inline object** of term definitions
//!   (never a string, so no remote context is ever fetched). A term is
//!   `"name": "<iri or compact iri>"` or `"name": {"@id": "...", "@type":
//!   "@id" | "<datatype>", "@container": "@set"}`. No `@vocab`, `@base`,
//!   `@language`, `@version`, `@protected`, `@import`, `@prefix`, `@reverse`,
//!   `@nest`, `@index`, `@list` container, null term, or scoped context;
//! * the root is **either** a single node object (with an `@id`) **or** an
//!   object holding only `@context` and `@graph`, whose value is a flat array
//!   of node objects (each with an `@id`; no named graph);
//! * a node object has `@id`, optionally `@type`, and keys that expand to an
//!   IRI (a context term, a compact IRI whose prefix is a context term, or an
//!   absolute IRI). A key that maps to no IRI is refused, never skipped.
//!   A node may nest further node objects (each with an `@id`); node ids are
//!   unique in the document;
//! * values are strings (read through the term's coercion), booleans, integers,
//!   `{"@id": ...}` references, `{"@value": <string>, "@type"|"@language":
//!   ...}`, nested node objects, or arrays of these. No `@list`, `@set`
//!   object, `@reverse`, `@included`, `@json`, float, `null`, blank node;
//! * the document has no blank nodes and reads to the same graph by this
//!   module's own reader and by `oxjsonld`.
//!
//! "Round-trip exactly" is **checked** when a document is opened
//! ([`StoredDocument::open`]): the writer deletes every non-structural triple
//! of `G0` and writes it back with the document's own context, the result is
//! re-parsed, and it must equal `G0` with the root `@context` text and the
//! root's shape unchanged. A document that fails is refused.
//!
//! # Limits of an edit
//!
//! An insert can only add to a node object that already exists in the
//! document (a new subject is refused), cannot add a blank node, and cannot
//! delete a nested node object. At most [`MAX_DELTA_TRIPLES`] triples change.
//! After editing, the result is re-parsed by `oxjsonld` and must equal `G1`
//! exactly; otherwise the edit is refused and nothing is written.
//!
//! # Example
//!
//! ```
//! use solid_pod_rs::jsonld_patch::StoredDocument;
//! use solid_pod_rs::ldp::{apply_sparql_patch};
//!
//! let text = r##"{
//!   "@context": {"foaf": "http://xmlns.com/foaf/0.1/"},
//!   "@id": "#me",
//!   "foaf:name": "Old"
//! }"##;
//! let base = "https://pod.example/profile/card";
//! let doc = StoredDocument::open(text.as_bytes(), "application/ld+json", base).unwrap();
//! let out = apply_sparql_patch(
//!     doc.graph().clone(),
//!     r#"DELETE DATA { <https://pod.example/profile/card#me>
//!                      <http://xmlns.com/foaf/0.1/name> "Old" } ;
//!        INSERT DATA { <https://pod.example/profile/card#me>
//!                      <http://xmlns.com/foaf/0.1/name> "New" }"#,
//! )
//! .unwrap();
//! let bytes = doc.write_back(&out.graph).unwrap();
//! assert_eq!(String::from_utf8(bytes).unwrap(), text.replace("Old", "New"));
//! ```

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::ops::Range;

use crate::html_island;
use crate::ldp::{Graph, Term, Triple};
use crate::rdf_input::{parse_jsonld, MAX_RDF_INPUT_BYTES};

/// Most triples one PATCH may add and delete together on this path.
pub const MAX_DELTA_TRIPLES: usize = 256;

/// Most triples a patchable document may hold.
pub const MAX_DOCUMENT_TRIPLES: usize = 5_000;

const MAX_DEPTH: usize = 32;
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";

/// The stored document cannot be patched in place. The reason is for logs and
/// tests; a server answers every refusal with one generic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not patchable in place: {}", self.0)
    }
}

impl std::error::Error for Refusal {}

type R<T> = Result<T, Refusal>;

fn no<T>(why: &'static str) -> R<T> {
    Err(Refusal(why))
}

// ---------------------------------------------------------------------------
// A JSON scanner that keeps byte spans
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Val {
    span: Range<usize>,
    kind: Kind,
}

#[derive(Debug, Clone)]
enum Kind {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Arr(Vec<Val>),
    Obj(Vec<Member>),
}

#[derive(Debug, Clone)]
struct Member {
    key: String,
    key_span: Range<usize>,
    val: Val,
}

struct Scanner<'a> {
    text: &'a str,
    b: &'a [u8],
    at: usize,
}

impl<'a> Scanner<'a> {
    fn ws(&mut self) {
        while self.at < self.b.len() && matches!(self.b[self.at], b' ' | b'\t' | b'\n' | b'\r') {
            self.at += 1;
        }
    }

    fn string(&mut self) -> R<(Range<usize>, String)> {
        let start = self.at;
        if self.b.get(self.at) != Some(&b'"') {
            return no("malformed JSON");
        }
        self.at += 1;
        while let Some(&c) = self.b.get(self.at) {
            match c {
                b'\\' => self.at += 2,
                b'"' => {
                    self.at += 1;
                    let span = start..self.at;
                    let s: String = serde_json::from_str(&self.text[span.clone()])
                        .map_err(|_| Refusal("malformed JSON string"))?;
                    return Ok((span, s));
                }
                _ => self.at += 1,
            }
        }
        no("malformed JSON")
    }

    fn value(&mut self, depth: usize) -> R<Val> {
        if depth > MAX_DEPTH {
            return no("document nested too deeply");
        }
        self.ws();
        let start = self.at;
        let kind =
            match self.b.get(self.at) {
                Some(b'{') => {
                    self.at += 1;
                    let mut members: Vec<Member> = Vec::new();
                    loop {
                        self.ws();
                        if self.b.get(self.at) == Some(&b'}') {
                            self.at += 1;
                            break;
                        }
                        if !members.is_empty() {
                            if self.b.get(self.at) != Some(&b',') {
                                return no("malformed JSON");
                            }
                            self.at += 1;
                            self.ws();
                        }
                        let (key_span, key) = self.string()?;
                        if members.iter().any(|m| m.key == key) {
                            return no("duplicate key");
                        }
                        self.ws();
                        if self.b.get(self.at) != Some(&b':') {
                            return no("malformed JSON");
                        }
                        self.at += 1;
                        let val = self.value(depth + 1)?;
                        members.push(Member { key, key_span, val });
                    }
                    Kind::Obj(members)
                }
                Some(b'[') => {
                    self.at += 1;
                    let mut items: Vec<Val> = Vec::new();
                    loop {
                        self.ws();
                        if self.b.get(self.at) == Some(&b']') {
                            self.at += 1;
                            break;
                        }
                        if !items.is_empty() {
                            if self.b.get(self.at) != Some(&b',') {
                                return no("malformed JSON");
                            }
                            self.at += 1;
                        }
                        items.push(self.value(depth + 1)?);
                    }
                    Kind::Arr(items)
                }
                Some(b'"') => Kind::Str(self.string()?.1),
                Some(b't') if self.text[self.at..].starts_with("true") => {
                    self.at += 4;
                    Kind::Bool(true)
                }
                Some(b'f') if self.text[self.at..].starts_with("false") => {
                    self.at += 5;
                    Kind::Bool(false)
                }
                Some(b'n') if self.text[self.at..].starts_with("null") => {
                    self.at += 4;
                    Kind::Null
                }
                Some(c) if c.is_ascii_digit() || *c == b'-' => {
                    while self.b.get(self.at).is_some_and(|c| {
                        matches!(c, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                    }) {
                        self.at += 1;
                    }
                    Kind::Number(self.text[start..self.at].to_string())
                }
                _ => return no("malformed JSON"),
            };
        Ok(Val {
            span: start..self.at,
            kind,
        })
    }
}

fn scan(text: &str) -> R<Val> {
    // The scanner is lenient; serde_json is the judge of validity.
    serde_json::from_str::<serde::de::IgnoredAny>(text).map_err(|_| Refusal("not valid JSON"))?;
    let mut s = Scanner {
        text,
        b: text.as_bytes(),
        at: 0,
    };
    let v = s.value(0)?;
    s.ws();
    if s.at != text.len() {
        return no("trailing content");
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// The document's own context
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Coerce {
    Id,
    Datatype(String),
}

#[derive(Debug, Clone)]
struct TermDef {
    name: String,
    iri: String,
    coerce: Option<Coerce>,
    set: bool,
    /// A plain string definition: may serve as a compact-IRI prefix.
    simple: bool,
}

/// Most terms a patchable context may define.
const MAX_CONTEXT_TERMS: usize = 1_000;

#[derive(Debug, Default)]
struct Ctx {
    terms: Vec<TermDef>,
    index: HashMap<String, usize>,
}

fn is_absolute(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    !rest.is_empty()
        && !s.starts_with("_:")
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn ends_gen_delim(s: &str) -> bool {
    s.ends_with([':', '/', '?', '#', '[', ']', '@'])
}

struct RawDef {
    id: String,
    ty: Option<String>,
    set: bool,
    simple: bool,
}

impl Ctx {
    fn term(&self, name: &str) -> Option<&TermDef> {
        self.index.get(name).map(|&i| &self.terms[i])
    }

    fn from_value(v: Option<&Val>) -> R<Ctx> {
        let Some(v) = v else {
            return Ok(Ctx::default());
        };
        let Kind::Obj(members) = &v.kind else {
            return no("@context is not one inline object");
        };
        if members.len() > MAX_CONTEXT_TERMS {
            return no("the @context defines too many terms");
        }
        let mut raw: Vec<(String, RawDef)> = Vec::new();
        for m in members {
            if m.key.starts_with('@') || m.key.is_empty() || m.key.contains(':') {
                return no("unsupported context entry");
            }
            let def = match &m.val.kind {
                Kind::Str(s) => RawDef {
                    id: s.clone(),
                    ty: None,
                    set: false,
                    simple: true,
                },
                Kind::Obj(d) => {
                    let mut id = None;
                    let mut ty = None;
                    let mut set = false;
                    for e in d {
                        match (e.key.as_str(), &e.val.kind) {
                            ("@id", Kind::Str(s)) => id = Some(s.clone()),
                            ("@type", Kind::Str(s)) => ty = Some(s.clone()),
                            ("@container", Kind::Str(s)) if s == "@set" => set = true,
                            _ => return no("unsupported term definition"),
                        }
                    }
                    let Some(id) = id else {
                        return no("term definition without @id");
                    };
                    RawDef {
                        id,
                        ty,
                        set,
                        simple: false,
                    }
                }
                _ => return no("unsupported term definition"),
            };
            raw.push((m.key.clone(), def));
        }
        let lookup: HashMap<&str, &RawDef> = raw.iter().map(|(k, d)| (k.as_str(), d)).collect();
        let mut ctx = Ctx::default();
        for (name, d) in &raw {
            let Some(iri) = expand_context_iri(&lookup, &d.id, 0) else {
                return no("a term does not expand to an IRI");
            };
            let coerce = match d.ty.as_deref() {
                None => None,
                Some("@id") => Some(Coerce::Id),
                Some(t) if t.starts_with('@') => return no("unsupported @type coercion"),
                Some(t) => match expand_context_iri(&lookup, t, 0) {
                    Some(dt) => Some(Coerce::Datatype(dt)),
                    None => return no("a datatype does not expand to an IRI"),
                },
            };
            ctx.index.insert(name.clone(), ctx.terms.len());
            ctx.terms.push(TermDef {
                name: name.clone(),
                iri,
                coerce,
                set: d.set,
                simple: d.simple,
            });
        }
        Ok(ctx)
    }

    /// Expand a property key: a term, a compact IRI, or an absolute IRI.
    fn expand_key(&self, key: &str) -> Option<(String, Option<&TermDef>)> {
        if key.starts_with('@') {
            return None;
        }
        if let Some(t) = self.term(key) {
            return Some((t.iri.clone(), Some(t)));
        }
        self.expand_iri(key, false).map(|i| (i, None))
    }

    /// Expand a compact or absolute IRI; with `vocab`, a bare term too.
    fn expand_iri(&self, s: &str, vocab: bool) -> Option<String> {
        if vocab {
            if let Some(t) = self.term(s) {
                return Some(t.iri.clone());
            }
        }
        if let Some((prefix, suffix)) = s.split_once(':') {
            if !suffix.starts_with("//") {
                if let Some(p) = self.term(prefix) {
                    if p.simple && ends_gen_delim(&p.iri) {
                        return Some(format!("{}{suffix}", p.iri));
                    }
                }
            }
            if is_absolute(s) {
                return Some(s.to_string());
            }
        }
        None
    }

    /// The shortest honest spelling of `iri` for a `@type` value or a datatype:
    /// a term, else a compact IRI, else the IRI. Checked by expanding it again.
    fn compact_vocab(&self, iri: &str) -> String {
        for t in &self.terms {
            if t.iri == iri && t.coerce.is_none() && !t.set {
                return t.name.clone();
            }
        }
        for t in &self.terms {
            if t.simple && ends_gen_delim(&t.iri) {
                if let Some(rest) = iri.strip_prefix(&t.iri) {
                    let cand = format!("{}:{rest}", t.name);
                    if !rest.is_empty()
                        && !rest.starts_with("//")
                        && self.term(&cand).is_none()
                        && self.expand_iri(&cand, true).as_deref() == Some(iri)
                    {
                        return cand;
                    }
                }
            }
        }
        iri.to_string()
    }
}

fn expand_context_iri(raw: &HashMap<&str, &RawDef>, s: &str, depth: usize) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if let Some(d) = raw.get(s) {
        return expand_context_iri(raw, &d.id, depth + 1);
    }
    let (prefix, suffix) = s.split_once(':')?;
    if !suffix.starts_with("//") {
        if let Some(p) = raw.get(prefix) {
            if p.simple {
                let base = expand_context_iri(raw, &p.id, depth + 1)?;
                if ends_gen_delim(&base) {
                    return Some(format!("{base}{suffix}"));
                }
            }
        }
    }
    is_absolute(s).then(|| s.to_string())
}

// ---------------------------------------------------------------------------
// The model: nodes, keys, entries
// ---------------------------------------------------------------------------

/// How to reach an object from the root: member indices and array indices.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Member(usize),
    Item(usize),
}

#[derive(Debug, Clone)]
struct Entry {
    span: Range<usize>,
    term: Term,
    /// This entry is a nested node object, whose own members are separate.
    nested: bool,
}

#[derive(Debug, Clone)]
struct KeyInfo {
    /// Index of the member in the node object.
    member: usize,
    iri: String,
    def: Option<TermDef>,
    entries: Vec<Entry>,
    was_array: bool,
    /// Span of the `[` ... `]` interior when the value is an array.
    value_span: Range<usize>,
}

#[derive(Debug, Clone)]
struct NodeInfo {
    id: String,
    path: Vec<Step>,
    keys: Vec<KeyInfo>,
    /// The `@type` member: entries are the type IRIs.
    types: Option<KeyInfo>,
}

struct Model {
    nodes: Vec<NodeInfo>,
    by_id: HashMap<String, usize>,
}

struct Reader<'a> {
    text: &'a str,
    ctx: &'a Ctx,
    base: &'a url::Url,
    nodes: Vec<NodeInfo>,
}

impl Reader<'_> {
    fn resolve(&self, s: &str) -> R<String> {
        if s.starts_with("_:") {
            return no("blank node");
        }
        if let Some(i) = self.ctx.expand_iri(s, false) {
            return Ok(i);
        }
        if s.contains(':') && is_absolute(s) {
            return Ok(s.to_string());
        }
        if s.is_empty() {
            return Ok(self.base.as_str().to_string());
        }
        self.base
            .join(s)
            .map(String::from)
            .map_err(|_| Refusal("an @id does not resolve"))
    }

    fn node(&mut self, obj: &Val, path: Vec<Step>, depth: usize) -> R<usize> {
        let Kind::Obj(members) = &obj.kind else {
            return no("a node is not an object");
        };
        let mut id = None;
        let mut keys = Vec::new();
        let mut types = None;
        for (mi, m) in members.iter().enumerate() {
            match m.key.as_str() {
                "@id" => {
                    let Kind::Str(s) = &m.val.kind else {
                        return no("@id is not a string");
                    };
                    id = Some(self.resolve(s)?);
                }
                "@type" => {
                    if matches!(&m.val.kind, Kind::Arr(a) if a.is_empty()) {
                        return no("an empty array");
                    }
                    let items: Vec<&Val> = match &m.val.kind {
                        Kind::Arr(a) => a.iter().collect(),
                        _ => vec![&m.val],
                    };
                    let mut entries = Vec::new();
                    for it in items {
                        let Kind::Str(s) = &it.kind else {
                            return no("@type is not a string");
                        };
                        let Some(iri) = self.ctx.expand_iri(s, true) else {
                            return no("@type does not expand to an IRI");
                        };
                        entries.push(Entry {
                            span: it.span.clone(),
                            term: Term::Iri(iri),
                            nested: false,
                        });
                    }
                    types = Some(KeyInfo {
                        member: mi,
                        iri: RDF_TYPE.to_string(),
                        def: None,
                        entries,
                        was_array: matches!(m.val.kind, Kind::Arr(_)),
                        value_span: m.val.span.clone(),
                    });
                }
                "@context" if path.is_empty() => {}
                k if k.starts_with('@') => return no("unsupported keyword in a node"),
                k => {
                    let Some((iri, def)) = self.ctx.expand_key(k) else {
                        return no("a key does not map to an IRI");
                    };
                    let def = def.cloned();
                    let was_array = matches!(m.val.kind, Kind::Arr(_));
                    if matches!(&m.val.kind, Kind::Arr(a) if a.is_empty()) {
                        return no("an empty array");
                    }
                    let items: Vec<(usize, &Val)> = match &m.val.kind {
                        Kind::Arr(a) => a.iter().enumerate().collect(),
                        _ => vec![(0, &m.val)],
                    };
                    let mut entries = Vec::new();
                    for (ii, it) in items {
                        let mut p = path.clone();
                        p.push(Step::Member(mi));
                        if was_array {
                            p.push(Step::Item(ii));
                        }
                        entries.push(self.entry(it, def.as_ref(), p, depth)?);
                    }
                    keys.push(KeyInfo {
                        member: mi,
                        iri,
                        def,
                        entries,
                        was_array,
                        value_span: m.val.span.clone(),
                    });
                }
            }
        }
        let Some(id) = id else {
            return no("a node without @id");
        };
        let idx = self.nodes.len();
        self.nodes.push(NodeInfo {
            id,
            path,
            keys,
            types,
        });
        Ok(idx)
    }

    fn entry(&mut self, v: &Val, def: Option<&TermDef>, path: Vec<Step>, depth: usize) -> R<Entry> {
        let span = v.span.clone();
        let plain = |term| Entry {
            span: span.clone(),
            term,
            nested: false,
        };
        match &v.kind {
            Kind::Str(s) => Ok(plain(match def.and_then(|d| d.coerce.as_ref()) {
                Some(Coerce::Id) => Term::Iri(self.resolve(s)?),
                Some(Coerce::Datatype(dt)) if dt != XSD_STRING => {
                    Term::typed_literal(s.clone(), dt.clone())
                }
                _ => Term::literal(s.clone()),
            })),
            Kind::Bool(b) => Ok(plain(Term::typed_literal(b.to_string(), XSD_BOOLEAN))),
            Kind::Number(n) => {
                let digits = n.strip_prefix('-').unwrap_or(n);
                let canonical = !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && (digits == "0" && n == "0" || !digits.starts_with('0'));
                if !canonical {
                    return no("a number the writer would change");
                }
                Ok(plain(Term::typed_literal(n.clone(), XSD_INTEGER)))
            }
            Kind::Obj(m) => {
                let keys: BTreeSet<&str> = m.iter().map(|e| e.key.as_str()).collect();
                if keys == BTreeSet::from(["@id"]) {
                    let Kind::Str(s) = &m[0].val.kind else {
                        return no("@id is not a string");
                    };
                    return Ok(plain(Term::Iri(self.resolve(s)?)));
                }
                if keys.contains("@value") {
                    if !keys
                        .iter()
                        .all(|k| matches!(*k, "@value" | "@type" | "@language"))
                    {
                        return no("unsupported value object");
                    }
                    let get = |k: &str| m.iter().find(|e| e.key == k).map(|e| &e.val.kind);
                    let Some(Kind::Str(value)) = get("@value") else {
                        return no("a value object whose @value is not a string");
                    };
                    return Ok(plain(match (get("@type"), get("@language")) {
                        (None, None) => Term::literal(value.clone()),
                        (Some(Kind::Str(t)), None) => {
                            let Some(dt) = self.ctx.expand_iri(t, true) else {
                                return no("a datatype does not expand to an IRI");
                            };
                            if dt == XSD_STRING {
                                Term::literal(value.clone())
                            } else {
                                Term::typed_literal(value.clone(), dt)
                            }
                        }
                        (None, Some(Kind::Str(l))) => Term::lang_literal(value.clone(), l.clone()),
                        _ => return no("unsupported value object"),
                    }));
                }
                // A nested node object.
                if depth + 1 > MAX_DEPTH {
                    return no("document nested too deeply");
                }
                let idx = self.node(v, path, depth + 1)?;
                Ok(Entry {
                    span,
                    term: Term::Iri(self.nodes[idx].id.clone()),
                    nested: true,
                })
            }
            Kind::Null | Kind::Arr(_) => no("a value form the writer would change"),
        }
    }
}

/// Everything a document says, found by this module's own reader.
struct Doc {
    text: String,
    root: Val,
    ctx: Ctx,
    ctx_text: Option<String>,
    model: Model,
    base: url::Url,
}

fn open_doc(text: &str, base: &str) -> R<Doc> {
    if text.len() > MAX_RDF_INPUT_BYTES {
        return no("document too large");
    }
    let base_url = url::Url::parse(base).map_err(|_| Refusal("the base is not an absolute IRI"))?;
    let root = scan(text)?;
    let Kind::Obj(members) = &root.kind else {
        return no("the root is not an object");
    };
    let ctx_member = members.iter().find(|m| m.key == "@context");
    let ctx = Ctx::from_value(ctx_member.map(|m| &m.val))?;
    let ctx_text = ctx_member.map(|m| text[m.val.span.clone()].to_string());
    let mut reader = Reader {
        text,
        ctx: &ctx,
        base: &base_url,
        nodes: Vec::new(),
    };
    let _ = reader.text;
    match members.iter().find(|m| m.key == "@graph") {
        Some(g) => {
            if members
                .iter()
                .any(|m| m.key != "@context" && m.key != "@graph")
            {
                return no("the root mixes @graph with other keys");
            }
            let Kind::Arr(items) = &g.val.kind else {
                return no("@graph is not an array");
            };
            let gi = members.iter().position(|m| m.key == "@graph").unwrap_or(0);
            for (i, it) in items.iter().enumerate() {
                if !matches!(&it.kind, Kind::Obj(_)) {
                    return no("a @graph entry is not a node object");
                }
                reader.node(it, vec![Step::Member(gi), Step::Item(i)], 1)?;
            }
        }
        None => {
            reader.node(&root, Vec::new(), 0)?;
        }
    }
    let nodes = reader.nodes;
    let mut by_id = HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        if by_id.insert(n.id.clone(), i).is_some() {
            return no("two node objects share an @id");
        }
    }
    Ok(Doc {
        text: text.to_string(),
        root,
        ctx,
        ctx_text,
        model: Model { nodes, by_id },
        base: base_url,
    })
}

impl Doc {
    /// The graph this module's reader finds in the document.
    fn model_graph(&self) -> Graph {
        let mut g = Graph::new();
        for n in &self.model.nodes {
            let s = Term::iri(n.id.clone());
            if let Some(t) = &n.types {
                for e in &t.entries {
                    g.insert(Triple::new(s.clone(), Term::iri(RDF_TYPE), e.term.clone()));
                }
            }
            for k in &n.keys {
                for e in &k.entries {
                    g.insert(Triple::new(
                        s.clone(),
                        Term::iri(k.iri.clone()),
                        e.term.clone(),
                    ));
                }
            }
        }
        g
    }

    fn at_path(&self, path: &[Step]) -> Option<&Val> {
        let mut cur = &self.root;
        for s in path {
            cur = match (s, &cur.kind) {
                (Step::Member(i), Kind::Obj(m)) => &m.get(*i)?.val,
                (Step::Item(i), Kind::Arr(a)) => a.get(*i)?,
                _ => return None,
            };
        }
        Some(cur)
    }
}

// ---------------------------------------------------------------------------
// Edits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Edit {
    start: usize,
    end: usize,
    text: String,
}

/// JSON string literal for text this module writes. `<` and the two JS line
/// separators are escaped, so what is written can never open markup inside an
/// HTML `<script>` element or break a script-embedded literal.
fn json_str(s: &str) -> String {
    let mut out = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    if out.contains(['<', '\u{2028}', '\u{2029}']) {
        out = out
            .replace('<', "\\u003c")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
    }
    out
}

/// Render one object term as a JSON value for a key with `def`.
fn render_entry(term: &Term, def: Option<&TermDef>, ctx: &Ctx) -> R<String> {
    Ok(match term {
        Term::Iri(i) => match def.and_then(|d| d.coerce.as_ref()) {
            Some(Coerce::Id) => json_str(i),
            _ => format!("{{\"@id\": {}}}", json_str(i)),
        },
        Term::BlankNode(_) => return no("a blank node cannot be written"),
        Term::Literal {
            value,
            datatype,
            language,
        } => match (datatype, language) {
            (None, None) => {
                if def.is_some_and(|d| d.coerce.is_some()) {
                    format!("{{\"@value\": {}}}", json_str(value))
                } else {
                    json_str(value)
                }
            }
            (Some(dt), None) => {
                if matches!(def.and_then(|d| d.coerce.as_ref()), Some(Coerce::Datatype(d)) if d == dt)
                {
                    json_str(value)
                } else {
                    format!(
                        "{{\"@value\": {}, \"@type\": {}}}",
                        json_str(value),
                        json_str(&ctx.compact_vocab(dt))
                    )
                }
            }
            (None, Some(l)) => format!(
                "{{\"@value\": {}, \"@language\": {}}}",
                json_str(value),
                json_str(l)
            ),
            (Some(_), Some(_)) => return no("a literal with a datatype and a language"),
        },
    })
}

fn render_type(iri: &str, ctx: &Ctx) -> String {
    json_str(&ctx.compact_vocab(iri))
}

/// The text between two byte offsets, for copying a document's own layout.
fn gap(text: &str, a: usize, b: usize) -> &str {
    text.get(a..b).unwrap_or("")
}

/// Value text for a key after edits: `kept` are original entry texts, `new`
/// freshly rendered. `None` means the key is now empty and its member goes.
fn render_value(
    doc: &Doc,
    key: &KeyInfo,
    kept: Vec<String>,
    new: Vec<String>,
    force_array: bool,
) -> Option<String> {
    let all: Vec<String> = kept.into_iter().chain(new).collect();
    if all.is_empty() {
        return None;
    }
    if all.len() == 1 && !key.was_array && !force_array {
        return Some(all.into_iter().next().unwrap_or_default());
    }
    let (lead, sep, trail) = if key.was_array {
        // Copy the original array's layout.
        let inner = &doc.text[key.value_span.clone()];
        let lead_len = inner[1..].len() - inner[1..].trim_start().len();
        let lead = inner[1..1 + lead_len].to_string();
        let trail_src = &inner[..inner.len() - 1];
        let trail_len = trail_src.len() - trail_src.trim_end().len();
        let trail = trail_src[trail_src.len() - trail_len..].to_string();
        let sep = match key.entries.as_slice() {
            [a, b, ..] => gap(&doc.text, a.span.end, b.span.start).to_string(),
            _ => format!(",{lead}"),
        };
        (lead, sep, trail)
    } else {
        (String::new(), ", ".to_string(), String::new())
    };
    Some(format!("[{lead}{}{trail}]", all.join(&sep)))
}

/// Remove the members `gone` of `obj` in one pass. A removed member that has a
/// member after it goes with the text up to that member; a removed member in
/// the tail goes with the text back to the end of the member before it, so
/// neighbouring removals abut and never overlap.
fn remove_members(obj: &Val, gone: &BTreeSet<usize>) -> R<Vec<Edit>> {
    let Kind::Obj(members) = &obj.kind else {
        return no("internal: not an object");
    };
    let n = members.len();
    let mut out = Vec::new();
    for &i in gone {
        let kept_after = (i + 1..n).any(|j| !gone.contains(&j));
        let (start, end) = if kept_after {
            (members[i].key_span.start, members[i + 1].key_span.start)
        } else if i == 0 {
            return no("a node object cannot lose every member");
        } else {
            (members[i - 1].val.span.end, members[i].val.span.end)
        };
        out.push(Edit {
            start,
            end,
            text: String::new(),
        });
    }
    Ok(out)
}

fn append_members(doc: &Doc, obj: &Val, members_text: &[(String, String)]) -> R<Edit> {
    let Kind::Obj(members) = &obj.kind else {
        return no("internal: not an object");
    };
    let (Some(first), Some(last)) = (members.first(), members.last()) else {
        return no("a node object without members");
    };
    let lead = gap(&doc.text, obj.span.start + 1, first.key_span.start);
    let colon = gap(&doc.text, first.key_span.end, first.val.span.start);
    let mut text = String::new();
    for (k, v) in members_text {
        let _ = write!(text, ",{lead}{}{colon}{v}", json_str(k));
    }
    Ok(Edit {
        start: last.val.span.end,
        end: last.val.span.end,
        text,
    })
}

fn apply_edits(text: &str, mut edits: Vec<Edit>) -> R<String> {
    edits.sort_by_key(|e| (e.start, e.end));
    for w in edits.windows(2) {
        if w[0].end > w[1].start || (w[0].start == w[1].start && w[0].end == w[1].end) {
            return no("two edits overlap");
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for e in &edits {
        if !(text.is_char_boundary(e.start) && text.is_char_boundary(e.end)) || e.end > text.len() {
            return no("internal: edit off a character boundary");
        }
        out.push_str(&text[at..e.start]);
        out.push_str(&e.text);
        at = e.end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}

fn term_is_ok(t: &Term) -> bool {
    !matches!(t, Term::BlankNode(_))
}

/// Compute the edited text for a delta against the document.
fn edit(doc: &Doc, deletes: &[Triple], inserts: &[Triple]) -> R<String> {
    if deletes.len() + inserts.len() > MAX_DELTA_TRIPLES.max(MAX_DOCUMENT_TRIPLES * 2) {
        return no("too many triples");
    }
    // Group by (subject node, predicate).
    type GroupKey = (usize, String);
    let mut groups: std::collections::BTreeMap<GroupKey, (Vec<&Term>, Vec<&Term>)> =
        std::collections::BTreeMap::new();
    for (is_insert, set) in [(false, deletes), (true, inserts)] {
        for t in set {
            let (Term::Iri(s), Term::Iri(p)) = (&t.subject, &t.predicate) else {
                return no("a blank node or non-IRI subject or predicate");
            };
            if !term_is_ok(&t.object) {
                return no("a blank node object");
            }
            let Some(&ni) = doc.model.by_id.get(s) else {
                return no("a subject that is not a node of the document");
            };
            let g = groups.entry((ni, p.clone())).or_default();
            if is_insert {
                g.1.push(&t.object);
            } else {
                g.0.push(&t.object);
            }
        }
    }

    let mut edits: Vec<Edit> = Vec::new();
    // New members per node, appended together.
    let mut appended: std::collections::BTreeMap<usize, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    let mut removals: std::collections::BTreeMap<usize, BTreeSet<usize>> =
        std::collections::BTreeMap::new();

    for ((ni, pred), (dels, ins)) in &groups {
        let node = &doc.model.nodes[*ni];
        let obj = doc
            .at_path(&node.path)
            .ok_or(Refusal("internal: a node is not where it was found"))?;
        if pred == RDF_TYPE {
            // `@type`.
            let key = node.types.as_ref();
            let mut kept: Vec<String> = Vec::new();
            if let Some(k) = key {
                for e in &k.entries {
                    if !dels.contains(&&e.term) {
                        kept.push(doc.text[e.span.clone()].to_string());
                    }
                }
                let removed = k.entries.len() - kept.len();
                let want: BTreeSet<&Term> = dels.iter().copied().collect();
                let found: BTreeSet<&Term> = k
                    .entries
                    .iter()
                    .map(|e| &e.term)
                    .filter(|t| want.contains(t))
                    .collect();
                if found.len() != want.len() || (removed == 0 && !dels.is_empty()) {
                    return no("a type to delete is not written in the document");
                }
            } else if !dels.is_empty() {
                return no("a type to delete is not written in the document");
            }
            let mut new = Vec::new();
            for t in ins {
                let Term::Iri(i) = t else {
                    return no("a literal type");
                };
                new.push(render_type(i, &doc.ctx));
            }
            match key {
                Some(k) => {
                    let Kind::Obj(members) = &obj.kind else {
                        return no("internal: not an object");
                    };
                    let _ = members;
                    match render_value(doc, k, kept, new, false) {
                        Some(text) => edits.push(Edit {
                            start: k.value_span.start,
                            end: k.value_span.end,
                            text,
                        }),
                        None => {
                            removals.entry(*ni).or_default().insert(k.member);
                        }
                    }
                }
                None => {
                    let text = if new.len() == 1 {
                        new[0].clone()
                    } else {
                        format!("[{}]", new.join(", "))
                    };
                    appended
                        .entry(*ni)
                        .or_default()
                        .push(("@type".to_string(), text));
                }
            }
            continue;
        }

        // An ordinary property.
        let existing: Vec<&KeyInfo> = node.keys.iter().filter(|k| &k.iri == pred).collect();
        // Deletes: every named object must be found, and removed from every
        // spelling that holds it.
        let mut remove_per_key: Vec<(usize, BTreeSet<usize>)> = Vec::new();
        for d in dels {
            let mut found = false;
            for (ki, k) in existing.iter().enumerate() {
                for (ei, e) in k.entries.iter().enumerate() {
                    if &e.term == *d {
                        if e.nested {
                            return no("a nested node object cannot be deleted");
                        }
                        found = true;
                        match remove_per_key.iter_mut().find(|(i, _)| *i == ki) {
                            Some((_, s)) => {
                                s.insert(ei);
                            }
                            None => remove_per_key.push((ki, BTreeSet::from([ei]))),
                        }
                    }
                }
            }
            if !found {
                return no("a triple to delete is not written in the document");
            }
        }
        // Inserts go to the first existing key for this predicate, else a new one.
        let target_def = existing.first().and_then(|k| k.def.clone());
        let mut inserted_texts: Vec<String> = Vec::new();
        if !ins.is_empty() {
            let def_for_new: Option<TermDef>;
            let new_key: Option<String>;
            if existing.is_empty() {
                let (key, def) = choose_new_key(&doc.ctx, pred)?;
                if doc_has_member(obj, &key) {
                    return no("the chosen key already exists with another meaning");
                }
                def_for_new = def;
                new_key = Some(key);
            } else {
                def_for_new = target_def;
                new_key = None;
            }
            for t in ins {
                inserted_texts.push(render_entry(t, def_for_new.as_ref(), &doc.ctx)?);
            }
            if let Some(key) = new_key {
                let force_array = def_for_new.as_ref().is_some_and(|d| d.set);
                let text = if inserted_texts.len() == 1 && !force_array {
                    inserted_texts[0].clone()
                } else {
                    format!("[{}]", inserted_texts.join(", "))
                };
                appended.entry(*ni).or_default().push((key, text));
                inserted_texts.clear();
            }
        }
        for (ki, k) in existing.iter().enumerate() {
            let removed: BTreeSet<usize> = remove_per_key
                .iter()
                .find(|(i, _)| *i == ki)
                .map(|(_, s)| s.clone())
                .unwrap_or_default();
            let adds = if ki == 0 {
                std::mem::take(&mut inserted_texts)
            } else {
                Vec::new()
            };
            if removed.is_empty() && adds.is_empty() {
                continue;
            }
            let kept: Vec<String> = k
                .entries
                .iter()
                .enumerate()
                .filter(|(i, _)| !removed.contains(i))
                .map(|(_, e)| doc.text[e.span.clone()].to_string())
                .collect();
            let force = k.def.as_ref().is_some_and(|d| d.set) && k.was_array;
            match render_value(doc, k, kept, adds, force) {
                Some(text) => edits.push(Edit {
                    start: k.value_span.start,
                    end: k.value_span.end,
                    text,
                }),
                None => {
                    removals.entry(*ni).or_default().insert(k.member);
                }
            }
        }
    }

    for (ni, gone) in &removals {
        let node = &doc.model.nodes[*ni];
        let obj = doc
            .at_path(&node.path)
            .ok_or(Refusal("internal: a node is not where it was found"))?;
        edits.extend(remove_members(obj, gone)?);
    }
    // An append lands at the end of the node's last member. When that member
    // was removed the two edits abut (removal ends where the append starts).
    for (ni, members) in &appended {
        let node = &doc.model.nodes[*ni];
        let obj = doc
            .at_path(&node.path)
            .ok_or(Refusal("internal: a node is not where it was found"))?;
        edits.push(append_members(doc, obj, members)?);
    }
    apply_edits(&doc.text, edits)
}

fn doc_has_member(obj: &Val, key: &str) -> bool {
    matches!(&obj.kind, Kind::Obj(m) if m.iter().any(|e| e.key == key))
}

/// The key to write a new property under: a context term for the predicate,
/// else a compact IRI under a context prefix, else the full IRI. Whatever is
/// chosen is expanded again and must give the predicate back.
fn choose_new_key(ctx: &Ctx, pred: &str) -> R<(String, Option<TermDef>)> {
    for t in &ctx.terms {
        if t.iri == pred {
            return Ok((t.name.clone(), Some(t.clone())));
        }
    }
    for t in &ctx.terms {
        if t.simple && ends_gen_delim(&t.iri) {
            if let Some(rest) = pred.strip_prefix(&t.iri) {
                let cand = format!("{}:{rest}", t.name);
                if !rest.is_empty()
                    && !rest.starts_with("//")
                    && ctx.term(&cand).is_none()
                    && ctx.expand_key(&cand).map(|(i, _)| i).as_deref() == Some(pred)
                {
                    return Ok((cand, None));
                }
            }
        }
    }
    if ctx.term(pred).is_none() && ctx.expand_key(pred).map(|(i, _)| i).as_deref() == Some(pred) {
        return Ok((pred.to_string(), None));
    }
    no("no key can name the predicate")
}

// ---------------------------------------------------------------------------
// The public face
// ---------------------------------------------------------------------------

fn same_graph(a: &Graph, b: &Graph) -> bool {
    a.len() == b.len() && a.triples().all(|t| b.contains(t))
}

fn has_blank(g: &Graph) -> bool {
    g.triples()
        .any(|t| matches!(t.subject, Term::BlankNode(_)) || matches!(t.object, Term::BlankNode(_)))
}

/// Where the JSON-LD lives in the stored bytes.
#[derive(Debug, Clone)]
enum Container {
    /// The whole body.
    Plain,
    /// The text of the one data island of an HTML document: leading and
    /// trailing whitespace of the island, kept as stored.
    Island {
        lead: String,
        trail: String,
        island: html_island::SoleIsland,
    },
}

/// A stored JSON-LD document, or an HTML document with one JSON-LD island,
/// opened for in-place patching. See the [module documentation](self).
#[derive(Debug)]
pub struct StoredDocument {
    html: Option<String>,
    container: Container,
    json: String,
    base: String,
    graph: Graph,
    content_type: String,
}

impl StoredDocument {
    /// Open `body` (stored as `content_type`) for patching, with relative IRIs
    /// resolved against `base`, which must be an absolute IRI the caller
    /// controls (never a request header).
    ///
    /// Accepts `application/ld+json` (the whole body is the document) and
    /// `text/html` with exactly one `<script type="application/ld+json">`
    /// element. Checks that the document is in the supported shape and that it
    /// round-trips exactly (see the module documentation).
    ///
    /// # Errors
    ///
    /// [`Refusal`] for anything else.
    pub fn open(body: &[u8], content_type: &str, base: &str) -> Result<Self, Refusal> {
        let text = std::str::from_utf8(body).map_err(|_| Refusal("not UTF-8"))?;
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let (html, container, json) = match essence.as_str() {
            "application/ld+json" => (None, Container::Plain, text.to_string()),
            "text/html" => {
                let island = html_island::sole_jsonld_island(text)
                    .map_err(|_| Refusal("not exactly one JSON-LD data island"))?;
                let t = island.text.clone();
                let trimmed = t.trim_matches(|c: char| c.is_ascii_whitespace());
                if trimmed.is_empty() {
                    return no("an empty data island");
                }
                let lead = t[..t.len()
                    - t.trim_start_matches(|c: char| c.is_ascii_whitespace())
                        .len()]
                    .to_string();
                let trail =
                    t[t.trim_end_matches(|c: char| c.is_ascii_whitespace()).len()..].to_string();
                (
                    Some(text.to_string()),
                    Container::Island {
                        lead,
                        trail,
                        island,
                    },
                    trimmed.to_string(),
                )
            }
            _ => return no("neither JSON-LD nor HTML"),
        };
        let g0 =
            parse_jsonld(json.as_bytes(), base).map_err(|_| Refusal("not readable JSON-LD"))?;
        if has_blank(&g0) {
            return no("the document has blank nodes");
        }
        if g0.len() > MAX_DOCUMENT_TRIPLES {
            return no("too many triples");
        }
        let doc = open_doc(&json, base)?;
        if !same_graph(&doc.model_graph(), &g0) {
            return no("this writer reads the document differently from a JSON-LD processor");
        }
        let me = Self {
            html,
            container,
            json,
            base: base.to_string(),
            graph: g0,
            content_type: essence,
        };
        me.check_round_trip(&doc)?;
        Ok(me)
    }

    /// The document's graph, `G0`, with relative IRIs resolved against the
    /// base given to [`StoredDocument::open`].
    #[must_use]
    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    /// The writer reproduces the whole graph: delete every triple that is not
    /// a nested-node link and write it back with the document's own context,
    /// then re-parse. The result must be the same graph, with the root
    /// `@context` text and the root's shape as stored.
    fn check_round_trip(&self, doc: &Doc) -> R<()> {
        let nested: BTreeSet<(String, String)> = doc
            .model
            .nodes
            .iter()
            .flat_map(|n| {
                n.keys.iter().flat_map(move |k| {
                    k.entries
                        .iter()
                        .filter(|e| e.nested)
                        .filter_map(move |e| match &e.term {
                            Term::Iri(o) => Some((format!("{}\u{0}{}", n.id, k.iri), o.clone())),
                            _ => None,
                        })
                })
            })
            .collect();
        let all: Vec<Triple> = self
            .graph
            .triples()
            .filter(|t| match (&t.subject, &t.predicate, &t.object) {
                (Term::Iri(s), Term::Iri(p), Term::Iri(o)) => {
                    !nested.contains(&(format!("{s}\u{0}{p}"), o.clone()))
                }
                _ => true,
            })
            .cloned()
            .collect();
        let rewritten = edit(doc, &all, &all)?;
        self.verify(doc, &rewritten, &self.graph)
            .map_err(|_| Refusal("the writer does not reproduce this document exactly"))
    }

    /// The edited document must read back (by the JSON-LD processor and by this
    /// module's reader) to exactly `want`, with the root `@context` text and
    /// the node ids as stored.
    fn verify(&self, old: &Doc, new_json: &str, want: &Graph) -> R<()> {
        let got = parse_jsonld(new_json.as_bytes(), &self.base)
            .map_err(|_| Refusal("the edited document does not parse"))?;
        if !same_graph(&got, want) {
            return no("the edited document does not read back to the expected graph");
        }
        let new_doc = open_doc(new_json, &self.base)?;
        if !same_graph(&new_doc.model_graph(), want) {
            return no("the edited document reads differently by the writer's own reader");
        }
        if new_doc.ctx_text != old.ctx_text {
            return no("the @context changed");
        }
        let ids = |d: &Doc| -> Vec<String> { d.model.nodes.iter().map(|n| n.id.clone()).collect() };
        let (mut a, mut b) = (ids(old), ids(&new_doc));
        a.sort();
        b.sort();
        if a != b {
            return no("the set of node objects changed");
        }
        let _ = &new_doc.base;
        Ok(())
    }

    /// Edit the stored bytes so that the document reads as `g1`, the graph the
    /// patch engine produced from [`StoredDocument::graph`].
    ///
    /// Returns the complete new body (for HTML, the whole page with only the
    /// island's text changed). An unchanged graph returns the stored bytes.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the change cannot be expressed in the document in
    /// place, or the result does not read back to exactly `g1`.
    pub fn write_back(&self, g1: &Graph) -> Result<Vec<u8>, Refusal> {
        if has_blank(g1) {
            return no("the patch introduces a blank node");
        }
        if g1.len() > MAX_DOCUMENT_TRIPLES {
            return no("too many triples");
        }
        let deletes: Vec<Triple> = self
            .graph
            .triples()
            .filter(|t| !g1.contains(t))
            .cloned()
            .collect();
        let inserts: Vec<Triple> = g1
            .triples()
            .filter(|t| !self.graph.contains(t))
            .cloned()
            .collect();
        if deletes.len() + inserts.len() > MAX_DELTA_TRIPLES {
            return no("too many triples changed");
        }
        if deletes.is_empty() && inserts.is_empty() {
            return Ok(self.stored_bytes());
        }
        let doc = open_doc(&self.json, &self.base)?;
        let new_json = edit(&doc, &deletes, &inserts)?;
        self.verify(&doc, &new_json, g1)?;
        match (&self.container, &self.html) {
            (Container::Plain, _) => Ok(new_json.into_bytes()),
            (
                Container::Island {
                    lead,
                    trail,
                    island,
                },
                Some(html),
            ) => {
                let new_text = format!("{lead}{new_json}{trail}");
                let out = island.replace(html, &new_text).map_err(|_| {
                    Refusal("the HTML page could not be edited without altering it")
                })?;
                // The page must still hold exactly one island, holding `new_json`.
                let again = html_island::sole_jsonld_island(&out)
                    .map_err(|_| Refusal("the edited page lost its single island"))?;
                if again.text != new_text {
                    return no("the edited page holds different island text");
                }
                Ok(out.into_bytes())
            }
            _ => no("internal: island without page"),
        }
    }

    fn stored_bytes(&self) -> Vec<u8> {
        match (&self.container, &self.html) {
            (Container::Island { .. }, Some(h)) => h.clone().into_bytes(),
            _ => self.json.clone().into_bytes(),
        }
    }

    /// `application/ld+json` or `text/html`: the type the document is stored as.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldp::apply_sparql_patch;

    const BASE: &str = "https://pod.example/profile/card";

    fn open(text: &str) -> StoredDocument {
        StoredDocument::open(text.as_bytes(), "application/ld+json", BASE).unwrap()
    }

    fn sparql(doc: &StoredDocument, q: &str) -> Result<String, Refusal> {
        let out = apply_sparql_patch(doc.graph().clone(), q).unwrap();
        doc.write_back(&out.graph)
            .map(|b| String::from_utf8(b).unwrap())
    }

    const ME: &str = "https://pod.example/profile/card#me";
    const NAME: &str = "http://xmlns.com/foaf/0.1/name";

    #[test]
    fn a_value_is_replaced_in_place_and_everything_else_is_byte_identical() {
        // Odd layout on purpose: tabs, escapes, key order, a number form.
        let text =
            "{\t\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\", \"n\": \"foaf:nick\"},\n\
            \"z\\u0061\": 1,\n  \"@id\": \"#me\",\n \"foaf:name\" : \"Old \\u00e9\\/x\",\n\
            \"n\": [\"a\",   \"b\"], \"foaf:knows\": {\"@id\": \"https://x.example/a\"}\n}\n";
        // `zа` is not a term: refused, as a key that maps to no IRI.
        assert!(StoredDocument::open(text.as_bytes(), "application/ld+json", BASE).is_err());
        let text = text.replace("\"z\\u0061\": 1,\n  ", "");
        let doc = open(&text);
        let out = sparql(
            &doc,
            &format!(
                "DELETE DATA {{ <{ME}> <{NAME}> \"Old \u{e9}/x\" }} ; INSERT DATA {{ <{ME}> <{NAME}> \"New\" }}"
            ),
        )
        .unwrap();
        assert_eq!(out, text.replace("\"Old \\u00e9\\/x\"", "\"New\""));
    }

    #[test]
    fn insert_uses_the_documents_own_term_and_appends_a_key() {
        let text = "{\n  \"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\", \"nick\": \"foaf:nick\"},\n  \"@id\": \"#me\",\n  \"foaf:name\": \"A\"\n}";
        let doc = open(text);
        let out = sparql(
            &doc,
            &format!("INSERT DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/nick> \"al\" }}"),
        )
        .unwrap();
        assert_eq!(
            out,
            text.replace("\"A\"\n}", "\"A\",\n  \"nick\": \"al\"\n}")
        );
        // A predicate with no term: a compact IRI under the foaf prefix.
        let out = sparql(
            &doc,
            &format!("INSERT DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/age> \"3\" }}"),
        )
        .unwrap();
        assert!(out.contains("\"foaf:age\": \"3\""), "{out}");
        // Neither: the full IRI.
        let out = sparql(
            &doc,
            &format!("INSERT DATA {{ <{ME}> <http://other.example/p> \"3\" }}"),
        )
        .unwrap();
        assert!(out.contains("\"http://other.example/p\": \"3\""), "{out}");
    }

    #[test]
    fn a_second_value_turns_a_scalar_into_an_array_and_deleting_one_keeps_the_rest() {
        let text = "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@id\": \"#me\", \"foaf:nick\": [\"a\", \"b\", \"c\"]}";
        let doc = open(text);
        let out = sparql(
            &doc,
            &format!("DELETE DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/nick> \"b\" }}"),
        )
        .unwrap();
        assert_eq!(out, text.replace("\"b\", ", ""));
        let out = sparql(
            &doc,
            &format!(
                "INSERT DATA {{ <{ME}> <{NAME}> \"x\" }} ; INSERT DATA {{ <{ME}> <{NAME}> \"y\" }}"
            ),
        )
        .unwrap();
        assert!(out.contains("\"foaf:name\": [\"x\", \"y\"]"), "{out}");
    }

    #[test]
    fn deleting_the_last_value_drops_the_key() {
        let text = "{\n  \"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"},\n  \"@id\": \"#me\",\n  \"foaf:name\": \"A\",\n  \"foaf:nick\": \"b\"\n}";
        let doc = open(text);
        let out = sparql(
            &doc,
            &format!("DELETE DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/nick> \"b\" }}"),
        )
        .unwrap();
        assert_eq!(out, text.replace(",\n  \"foaf:nick\": \"b\"", ""));
        let out = sparql(&doc, &format!("DELETE DATA {{ <{ME}> <{NAME}> \"A\" }}")).unwrap();
        assert_eq!(out, text.replace("\"foaf:name\": \"A\",\n  ", ""));
    }

    #[test]
    fn an_absolute_delete_matches_a_relative_id_and_a_graph_document_is_edited() {
        let text = "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@graph\": [{\"@id\": \"#me\", \"foaf:name\": \"A\"}, {\"@id\": \"#you\", \"foaf:name\": \"B\"}]}";
        let doc = open(text);
        let out = sparql(
            &doc,
            &format!("DELETE DATA {{ <https://pod.example/profile/card#you> <{NAME}> \"B\" }} ; INSERT DATA {{ <https://pod.example/profile/card#you> <{NAME}> \"C\" }}"),
        )
        .unwrap();
        assert_eq!(out, text.replace("\"B\"", "\"C\""));
    }

    #[test]
    fn types_literals_and_references_are_written_in_the_documents_forms() {
        let text = "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\", \"Person\": \"foaf:Person\", \"knows\": {\"@id\": \"foaf:knows\", \"@type\": \"@id\"}}, \"@id\": \"#me\", \"@type\": \"Person\"}";
        let doc = open(text);
        let out = sparql(
            &doc,
            &format!(
                "INSERT DATA {{ <{ME}> a <http://xmlns.com/foaf/0.1/Agent> ; \
                 <http://xmlns.com/foaf/0.1/knows> <https://x.example/a> ; \
                 <{NAME}> \"chat\"@fr, \"5\"^^<http://www.w3.org/2001/XMLSchema#integer> }}"
            ),
        )
        .unwrap();
        assert!(
            out.contains("\"@type\": [\"Person\", \"foaf:Agent\"]"),
            "{out}"
        );
        assert!(out.contains("\"knows\": \"https://x.example/a\""), "{out}");
        assert!(
            out.contains("{\"@value\": \"chat\", \"@language\": \"fr\"}"),
            "{out}"
        );
        assert!(
            out.contains("\"@type\": \"http://www.w3.org/2001/XMLSchema#integer\""),
            "{out}"
        );
    }

    #[test]
    fn anything_the_writer_could_not_reproduce_is_refused_to_open() {
        let ctx = "\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}";
        for (why, doc) in [
            ("remote context", "{\"@context\": \"https://example.org/ctx\", \"@id\": \"#a\"}".to_string()),
            ("array context", "{\"@context\": [{}], \"@id\": \"#a\"}".to_string()),
            ("@vocab", "{\"@context\": {\"@vocab\": \"http://v/\"}, \"@id\": \"#a\", \"p\": 1}".to_string()),
            ("@list", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:knows\": {{\"@list\": [\"x\"]}}}}")),
            ("@reverse", format!("{{{ctx}, \"@id\": \"#a\", \"@reverse\": {{\"foaf:knows\": {{\"@id\": \"#b\"}}}}}}")),
            ("@included", format!("{{{ctx}, \"@id\": \"#a\", \"@included\": []}}")),
            ("@nest", format!("{{{ctx}, \"@id\": \"#a\", \"@nest\": {{}}}}")),
            ("named graph", format!("{{{ctx}, \"@id\": \"#g\", \"@graph\": [{{\"@id\": \"#a\", \"foaf:name\": \"x\"}}]}}")),
            ("unmapped key", format!("{{{ctx}, \"@id\": \"#a\", \"nope\": \"x\"}}")),
            ("blank node", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:knows\": {{\"foaf:name\": \"x\"}}}}")),
            ("float", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:age\": 1.5}}")),
            ("null", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:age\": null}}")),
            ("duplicate key", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:name\": \"x\", \"foaf:name\": \"y\"}}")),
            ("no id", format!("{{{ctx}, \"foaf:name\": \"x\"}}")),
            ("top-level array", "[{\"@id\": \"http://e/a\"}]".to_string()),
            ("empty array", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:knows\": []}}")),
            ("scoped context", "{\"@context\": {\"p\": {\"@id\": \"http://e/p\", \"@context\": {}}}, \"@id\": \"#a\"}".to_string()),
            ("nested @graph", format!("{{{ctx}, \"@id\": \"#a\", \"foaf:knows\": {{\"@id\": \"#b\", \"@graph\": []}}}}")),
        ] {
            assert!(
                StoredDocument::open(doc.as_bytes(), "application/ld+json", BASE).is_err(),
                "{why} must be refused"
            );
        }
    }

    #[test]
    fn a_new_subject_a_blank_node_and_a_nested_delete_are_refused_and_change_nothing() {
        let text = "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@id\": \"#me\", \"foaf:knows\": {\"@id\": \"#b\", \"foaf:name\": \"B\"}}";
        let doc = open(text);
        for q in [
            format!("INSERT DATA {{ <https://pod.example/other> <{NAME}> \"x\" }}"),
            format!("INSERT DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/knows> _:b }}"),
            format!("DELETE DATA {{ <{ME}> <http://xmlns.com/foaf/0.1/knows> <https://pod.example/profile/card#b> }}"),
        ] {
            assert!(sparql(&doc, &q).is_err(), "{q}");
        }
        // A property of the nested node is editable.
        let out = sparql(
            &doc,
            &format!("DELETE DATA {{ <https://pod.example/profile/card#b> <{NAME}> \"B\" }} ; INSERT DATA {{ <https://pod.example/profile/card#b> <{NAME}> \"C\" }}"),
        )
        .unwrap();
        assert_eq!(out, text.replace("\"B\"", "\"C\""));
    }

    #[test]
    fn html_islands_are_edited_in_place_and_escape_markup() {
        let html = "<!DOCTYPE html>\n<html><head><title>t &amp; u</title>\n  <script type=\"application/ld+json\">\n{\n  \"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"},\n  \"@id\": \"#me\",\n  \"foaf:name\": \"Old\"\n}\n  </script>\n</head><body><!-- keep --><p>hi</p></body></html>";
        let doc = StoredDocument::open(html.as_bytes(), "text/html; charset=utf-8", BASE).unwrap();
        let out = apply_sparql_patch(
            doc.graph().clone(),
            &format!(
                "DELETE DATA {{ <{ME}> <{NAME}> \"Old\" }} ; INSERT DATA {{ <{ME}> <{NAME}> \"</script><b>x\" }}"
            ),
        )
        .unwrap();
        let bytes = doc.write_back(&out.graph).unwrap();
        let new = String::from_utf8(bytes).unwrap();
        assert_eq!(
            new,
            html.replace("\"Old\"", "\"\\u003c/script>\\u003cb>x\"")
        );
        assert_eq!(new.matches("<script").count(), 1);
    }

    // The regression for the defect that withdrew attempt two: a PATCH of a
    // provisioned WebID card must leave what the readers read untouched.
    #[test]
    fn a_provisioned_profile_card_keeps_its_issuer_and_pubkey_after_a_rename() {
        let pk = "ab".repeat(32);
        let html = crate::webid::generate_webid_html_with_issuer(
            &pk,
            Some("Alice"),
            "https://pod.example",
            Some("https://op.example"),
        );
        let base = format!("https://pod.example/pods/{pk}/profile/card");
        let webid = format!("{base}#me");
        let doc = StoredDocument::open(html.as_bytes(), "text/html", &base).unwrap();
        let out = apply_sparql_patch(
            doc.graph().clone(),
            &format!(
                "DELETE DATA {{ <{webid}> <{NAME}> \"Alice\" }} ; INSERT DATA {{ <{webid}> <{NAME}> \"Alicia\" }}"
            ),
        )
        .unwrap();
        let new = String::from_utf8(doc.write_back(&out.graph).unwrap()).unwrap();
        // Only the island's value changed; the HTML around it is untouched.
        assert_eq!(
            new,
            html.replacen("\"foaf:name\": \"Alice\"", "\"foaf:name\": \"Alicia\"", 1)
        );
        assert_eq!(
            crate::webid::extract_oidc_issuer(new.as_bytes())
                .unwrap()
                .as_deref(),
            Some("https://op.example")
        );
        assert_eq!(
            crate::webid::extract_oidc_issuer(new.as_bytes()),
            crate::webid::extract_oidc_issuer(html.as_bytes())
        );
        assert_eq!(
            crate::webid::extract_cid_openid_provider(new.as_bytes()),
            crate::webid::extract_cid_openid_provider(html.as_bytes())
        );
        crate::oidc::check_profile_declares_issuer(new.as_bytes(), "https://op.example").unwrap();
    }

    #[test]
    fn an_oversized_context_is_refused_before_it_costs_anything() {
        let terms: Vec<String> = (0..=MAX_CONTEXT_TERMS)
            .map(|i| format!("\"t{i}\": \"http://e/p{i}\""))
            .collect();
        let doc = format!(
            "{{\"@context\": {{{}}}, \"@id\": \"#a\", \"t1\": \"x\"}}",
            terms.join(", ")
        );
        assert!(StoredDocument::open(doc.as_bytes(), "application/ld+json", BASE).is_err());
    }

    #[test]
    fn no_op_patch_returns_the_stored_bytes() {
        let text = "{\"@context\": {\"foaf\": \"http://xmlns.com/foaf/0.1/\"}, \"@id\": \"#me\", \"foaf:name\": \"A\"}";
        let doc = open(text);
        assert_eq!(doc.write_back(doc.graph()).unwrap(), text.as_bytes());
    }
}
