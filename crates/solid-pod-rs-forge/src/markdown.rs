//! A small, bounded, escape-first Markdown renderer.
//!
//! Behaviour follows the JSS `forge` `lib/markdown.js` (`renderMarkdown`)
//! grammar, cited by name only; the code is original and uses no regex
//! engine. The design is structurally XSS-safe: the raw source is
//! HTML-escaped with [`crate::request::esc`] *before* any tag is introduced,
//! there is no HTML passthrough, and link / image targets are screened by
//! [`safe_href`] (no `javascript:`, `data:`, protocol-relative or traversing
//! targets).
//!
//! Blocks: `#`..`######` headings, fenced code, `>` quotes, `-`/`*` and `1.`
//! lists, GFM tables with per-column alignment, paragraphs. Inline: code
//! spans, `**strong**`, `*em*` / `_em_`, `[text](href)` and `![alt](src)`.
//! No nesting.
//!
//! # Examples
//!
//! ```
//! use solid_pod_rs_forge::markdown::render;
//!
//! let html = render("# Hi\n\nsome **bold** and `code`\n\n<script>x</script>");
//! assert!(html.contains("<h1>Hi</h1>"));
//! assert!(html.contains("<strong>bold</strong>"));
//! assert!(html.contains("&lt;script&gt;"));
//! assert!(!html.contains("<script>"));
//! ```

use crate::request::esc;

/// Columns rendered per table (defence in depth).
const TABLE_COL_CAP: usize = 100;
/// Body rows rendered per table.
const TABLE_ROW_CAP: usize = 1000;

/// Link bases for relative targets: images resolve against `raw_base`, links
/// against `blob_base` (JSS passes `…/raw/<ref>` and `…/blob/<ref>`).
#[derive(Debug, Clone, Default)]
pub struct MdCtx {
    /// Prefix for relative image sources.
    pub raw_base: String,
    /// Prefix for relative link targets.
    pub blob_base: String,
}

/// Render `src` with empty link bases.
///
/// # Examples
///
/// ```
/// assert!(solid_pod_rs_forge::markdown::render("- a\n- b").contains("<ul><li>a</li><li>b</li></ul>"));
/// ```
#[must_use]
pub fn render(src: &str) -> String {
    render_with(src, &MdCtx::default())
}

/// Screen a link / image target. Absolute `http(s)` and `#fragment` targets
/// pass; protocol-relative and any other scheme are refused; a relative path
/// with an empty or `..` segment (or a leading `/`) is refused, otherwise it
/// is joined onto `base`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::markdown::safe_href;
/// assert_eq!(safe_href("https://x.test/a", "/b").as_deref(), Some("https://x.test/a"));
/// assert_eq!(safe_href("docs/n.txt", "/blob").as_deref(), Some("/blob/docs/n.txt"));
/// assert_eq!(safe_href("javascript:alert(1)", "/b"), None);
/// assert_eq!(safe_href("../x", "/b"), None);
/// assert_eq!(safe_href("//evil.test/x", "/b"), None);
/// ```
#[must_use]
pub fn safe_href(url: &str, base: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") || url.starts_with('#') {
        return Some(url.to_string());
    }
    if url.starts_with("//") {
        return None;
    }
    if has_scheme(url) {
        return None;
    }
    let rel = url.strip_prefix("./").unwrap_or(url);
    if rel.starts_with('/') || rel.split('/').any(|s| s == ".." || s.is_empty()) {
        return None;
    }
    Some(format!("{base}/{rel}"))
}

/// `^[a-z][a-z0-9+.-]*:`
fn has_scheme(url: &str) -> bool {
    let mut it = url.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for c in it {
        if c == ':' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
            return false;
        }
    }
    false
}

fn code_spans(s: &str) -> (String, Vec<String>) {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut codes = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '`' {
            if let Some(rel) = c[i + 1..].iter().position(|&x| x == '`') {
                if rel > 0 {
                    codes.push(c[i + 1..i + 1 + rel].iter().collect::<String>());
                    out.push_str(&format!("\u{1}{}\u{1}", codes.len() - 1));
                    i += rel + 2;
                    continue;
                }
            }
        }
        out.push(c[i]);
        i += 1;
    }
    (out, codes)
}

/// `[text](url)` / `![alt](url)` with `text` free of `]` and `url` free of
/// whitespace and `)`. Unsafe targets leave the source text unchanged.
fn bracket_pass(s: &str, image: bool, base: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        let start = if image {
            (c[i] == '!' && c.get(i + 1) == Some(&'[')).then_some(i + 2)
        } else {
            (c[i] == '[').then_some(i + 1)
        };
        if let Some(ts) = start {
            if let Some(rel) = c[ts..].iter().position(|&x| x == ']') {
                let te = ts + rel;
                let text_ok = image || te > ts;
                if text_ok && c.get(te + 1) == Some(&'(') {
                    let us = te + 2;
                    let mut ue = us;
                    while ue < c.len() && c[ue] != ')' && !c[ue].is_whitespace() {
                        ue += 1;
                    }
                    if ue > us && c.get(ue) == Some(&')') {
                        let text: String = c[ts..te].iter().collect();
                        let url: String = c[us..ue].iter().collect();
                        if let Some(h) = safe_href(&url, base) {
                            if image {
                                out.push_str(&format!("<img src=\"{h}\" alt=\"{text}\">"));
                            } else {
                                out.push_str(&format!("<a href=\"{h}\">{text}</a>"));
                            }
                        } else {
                            out.extend(&c[i..=ue]);
                        }
                        i = ue + 1;
                        continue;
                    }
                }
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn strong_pass(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '*' && c.get(i + 1) == Some(&'*') {
            let mut j = i + 2;
            while j < c.len() && c[j] != '*' {
                j += 1;
            }
            if j > i + 2 && c.get(j) == Some(&'*') && c.get(j + 1) == Some(&'*') {
                out.push_str("<strong>");
                out.extend(&c[i + 2..j]);
                out.push_str("</strong>");
                i = j + 2;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn em_star_pass(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '*' {
            if let Some(&f) = c.get(i + 1) {
                if f != '*' && !f.is_whitespace() {
                    let mut j = i + 2;
                    while j < c.len() && c[j] != '*' {
                        j += 1;
                    }
                    if j < c.len() {
                        out.push_str("<em>");
                        out.extend(&c[i + 1..j]);
                        out.push_str("</em>");
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn em_underscore_pass(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        let boundary = i == 0 || c[i - 1].is_whitespace();
        if c[i] == '_' && boundary {
            if let Some(rel) = c[i + 1..].iter().position(|&x| x == '_') {
                let j = i + 1 + rel;
                let followed = c.get(j + 1).is_none_or(|n| n.is_whitespace());
                if rel > 0 && followed {
                    out.push_str("<em>");
                    out.extend(&c[i + 1..j]);
                    out.push_str("</em>");
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn inline(escaped: &str, ctx: &MdCtx) -> String {
    let (s, codes) = code_spans(escaped);
    let s = bracket_pass(&s, true, &ctx.raw_base);
    let s = bracket_pass(&s, false, &ctx.blob_base);
    let s = strong_pass(&s);
    let s = em_star_pass(&s);
    let s = em_underscore_pass(&s);
    // Restore code spans.
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '\u{1}' {
            if let Some(rel) = c[i + 1..].iter().position(|&x| x == '\u{1}') {
                let digits: String = c[i + 1..i + 1 + rel].iter().collect();
                if let Ok(n) = digits.parse::<usize>() {
                    out.push_str("<code>");
                    out.push_str(codes.get(n).map_or("", String::as_str));
                    out.push_str("</code>");
                    i += rel + 2;
                    continue;
                }
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn split_row(line: &str) -> Vec<String> {
    let mut t = line.trim();
    t = t.strip_prefix('|').unwrap_or(t);
    let t = t.trim_end();
    let t = t.strip_suffix('|').unwrap_or(t);
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut prev_backslash = false;
    for ch in t.chars() {
        if ch == '|' && !prev_backslash {
            cells.push(cur.trim().replace("\\|", "|"));
            cur.clear();
        } else {
            cur.push(ch);
        }
        prev_backslash = ch == '\\';
    }
    cells.push(cur.trim().replace("\\|", "|"));
    cells
}

fn is_table_delim(line: &str) -> bool {
    let cells = split_row(line);
    !cells.is_empty()
        && cells.iter().all(|c| {
            let core = c.strip_prefix(':').unwrap_or(c);
            let core = core.strip_suffix(':').unwrap_or(core);
            !core.is_empty() && core.bytes().all(|b| b == b'-')
        })
}

fn align_of(cell: &str) -> &'static str {
    match (cell.starts_with(':'), cell.ends_with(':')) {
        (true, true) => "center",
        (false, true) => "right",
        (true, false) => "left",
        _ => "",
    }
}

/// Render `src` to HTML with link bases from `ctx`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::markdown::{render_with, MdCtx};
/// let ctx = MdCtx { raw_base: "/raw".into(), blob_base: "/blob".into() };
/// let html = render_with("[doc](docs/notes.txt)", &ctx);
/// assert!(html.contains("<a href=\"/blob/docs/notes.txt\">doc</a>"));
/// ```
#[must_use]
pub fn render_with(src: &str, ctx: &MdCtx) -> String {
    let cleaned: String = src.chars().filter(|&c| c != '\0' && c != '\u{1}').collect();
    let cleaned = cleaned.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = cleaned.split('\n').collect();
    let mut out: Vec<String> = Vec::new();
    let mut para: Vec<String> = Vec::new();
    let mut list: Option<(&str, Vec<String>)> = None;
    let mut quote: Vec<String> = Vec::new();

    fn flush_para(out: &mut Vec<String>, para: &mut Vec<String>, ctx: &MdCtx) {
        if !para.is_empty() {
            out.push(format!("<p>{}</p>", inline(&esc(&para.join(" ")), ctx)));
            para.clear();
        }
    }
    fn flush_list(out: &mut Vec<String>, list: &mut Option<(&str, Vec<String>)>) {
        if let Some((tag, items)) = list.take() {
            let lis: String = items.iter().map(|i| format!("<li>{i}</li>")).collect();
            out.push(format!("<{tag}>{lis}</{tag}>"));
        }
    }
    fn flush_quote(out: &mut Vec<String>, quote: &mut Vec<String>, ctx: &MdCtx) {
        if !quote.is_empty() {
            out.push(format!(
                "<blockquote><p>{}</p></blockquote>",
                inline(&esc(&quote.join(" ")), ctx)
            ));
            quote.clear();
        }
    }

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.starts_with("```") {
            flush_para(&mut out, &mut para, ctx);
            flush_list(&mut out, &mut list);
            flush_quote(&mut out, &mut quote, ctx);
            let mut code = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].starts_with("```") {
                code.push(lines[i]);
                i += 1;
            }
            out.push(format!("<pre><code>{}</code></pre>", esc(&code.join("\n"))));
            i += 1;
            continue;
        }
        if line.contains('|') && i + 1 < lines.len() && is_table_delim(lines[i + 1]) {
            flush_para(&mut out, &mut para, ctx);
            flush_list(&mut out, &mut list);
            flush_quote(&mut out, &mut quote, ctx);
            let header: Vec<String> = split_row(line).into_iter().take(TABLE_COL_CAP).collect();
            let aligns: Vec<&str> = split_row(lines[i + 1])
                .iter()
                .map(|c| align_of(c))
                .collect();
            let mut rows = Vec::new();
            let mut j = i + 2;
            while j < lines.len()
                && lines[j].contains('|')
                && !lines[j].trim().is_empty()
                && rows.len() < TABLE_ROW_CAP
            {
                rows.push(split_row(lines[j]));
                j += 1;
            }
            let cell = |txt: &str, tag: &str, al: &str| {
                let style = if al.is_empty() {
                    String::new()
                } else {
                    format!(" style=\"text-align:{al}\"")
                };
                format!("<{tag}{style}>{}</{tag}>", inline(&esc(txt), ctx))
            };
            let al = |k: usize| aligns.get(k).copied().unwrap_or("");
            let thead: String = header
                .iter()
                .enumerate()
                .map(|(k, c)| cell(c, "th", al(k)))
                .collect();
            let tbody: String = rows
                .iter()
                .map(|r| {
                    let tds: String = (0..header.len())
                        .map(|k| cell(r.get(k).map_or("", String::as_str), "td", al(k)))
                        .collect();
                    format!("<tr>{tds}</tr>")
                })
                .collect();
            out.push(format!(
                "<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>"
            ));
            i = j;
            continue;
        }
        if let Some((level, text)) = heading(line) {
            flush_para(&mut out, &mut para, ctx);
            flush_list(&mut out, &mut list);
            flush_quote(&mut out, &mut quote, ctx);
            out.push(format!(
                "<h{level}>{}</h{level}>",
                inline(&esc(text.trim()), ctx)
            ));
            i += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix('>') {
            flush_para(&mut out, &mut para, ctx);
            flush_list(&mut out, &mut list);
            quote.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            i += 1;
            continue;
        }
        if let Some(item) = bullet(line) {
            flush_para(&mut out, &mut para, ctx);
            flush_quote(&mut out, &mut quote, ctx);
            if list.as_ref().is_none_or(|(t, _)| *t != "ul") {
                flush_list(&mut out, &mut list);
                list = Some(("ul", Vec::new()));
            }
            if let Some((_, items)) = list.as_mut() {
                items.push(inline(&esc(item), ctx));
            }
            i += 1;
            continue;
        }
        if let Some(item) = numbered(line) {
            flush_para(&mut out, &mut para, ctx);
            flush_quote(&mut out, &mut quote, ctx);
            if list.as_ref().is_none_or(|(t, _)| *t != "ol") {
                flush_list(&mut out, &mut list);
                list = Some(("ol", Vec::new()));
            }
            if let Some((_, items)) = list.as_mut() {
                items.push(inline(&esc(item), ctx));
            }
            i += 1;
            continue;
        }
        if line.trim().is_empty() {
            flush_para(&mut out, &mut para, ctx);
            flush_list(&mut out, &mut list);
            flush_quote(&mut out, &mut quote, ctx);
            i += 1;
            continue;
        }
        flush_list(&mut out, &mut list);
        flush_quote(&mut out, &mut quote, ctx);
        para.push(line.trim().to_string());
        i += 1;
    }
    flush_para(&mut out, &mut para, ctx);
    flush_list(&mut out, &mut list);
    flush_quote(&mut out, &mut quote, ctx);
    out.join("\n")
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let n = line.bytes().take_while(|&b| b == b'#').count();
    if !(1..=6).contains(&n) {
        return None;
    }
    let rest = &line[n..];
    let first = rest.chars().next()?;
    first.is_whitespace().then(|| (n, rest.trim_start()))
}

fn bullet(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let rest = t.strip_prefix('-').or_else(|| t.strip_prefix('*'))?;
    let first = rest.chars().next()?;
    first.is_whitespace().then(|| rest.trim_start())
}

fn numbered(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = t[digits..].strip_prefix('.')?;
    let first = rest.chars().next()?;
    first.is_whitespace().then(|| rest.trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> MdCtx {
        MdCtx {
            raw_base: "/raw".into(),
            blob_base: "/blob".into(),
        }
    }

    // JSS test.js "renders a table with header row, per-column alignment ..."
    #[test]
    fn table_with_alignment_and_inline_cells() {
        let md = "| Name | Score |\n| :--- | ---: |\n| **a** | `9` |\n| b | 10 |";
        let html = render_with(md, &ctx());
        assert!(html.contains("<table><thead>"));
        assert!(html.contains("<th style=\"text-align:left\">Name</th>"));
        assert!(html.contains("<th style=\"text-align:right\">Score</th>"));
        assert!(html.contains("<td style=\"text-align:left\"><strong>a</strong></td>"));
        assert!(html.contains("<td style=\"text-align:right\"><code>9</code></td>"));
        assert!(html.contains("<td style=\"text-align:right\">10</td>"));
        assert!(!html.contains("<p>| Name"));
    }

    // JSS "is escape-first: HTML in a cell is neutralized"
    #[test]
    fn table_cells_are_escaped() {
        let html = render_with("| x |\n| - |\n| <img src=x onerror=alert(1)> |", &ctx());
        assert!(html.contains("&lt;img src=x"));
        assert!(!html.contains("<img src=x"));
    }

    // JSS "honors escaped pipes inside cells"
    #[test]
    fn escaped_pipes_in_cells() {
        let html = render_with("| a | b |\n| - | - |\n| x \\| y | z |", &ctx());
        assert!(html.contains("<td>x | y</td>"), "{html}");
    }

    #[test]
    fn readme_fixture_renders_heading_code_and_escapes_script() {
        let md = "# Demo Project\n\nA demo with **bold**, `inline code`, and a [doc](docs/notes.txt).\n\n```js\nconsole.log('hi');\n```\n\n<script>alert(1)</script>\n";
        let html = render_with(md, &ctx());
        assert!(html.contains("<h1>Demo Project</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<code>inline code</code>"));
        assert!(html.contains("<a href=\"/blob/docs/notes.txt\">doc</a>"));
        assert!(html.contains("<pre><code>console.log(&#x27;hi&#x27;);</code></pre>"));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn hostile_targets_are_refused() {
        let html = render_with("[x](javascript:alert(1)) ![y](data:text/html,a)", &ctx());
        assert!(!html.contains("<a href"));
        assert!(!html.contains("<img"));
        let html = render_with("[x](../../etc/passwd) [z](//evil.test/x)", &ctx());
        assert!(!html.contains("<a href"));
    }

    #[test]
    fn lists_quotes_and_emphasis() {
        assert_eq!(render("- a\n- b"), "<ul><li>a</li><li>b</li></ul>");
        assert_eq!(render("1. a\n2. b"), "<ol><li>a</li><li>b</li></ol>");
        assert_eq!(
            render("> hi\n> there"),
            "<blockquote><p>hi there</p></blockquote>"
        );
        assert_eq!(
            render("*em* and _em2_ ok"),
            "<p><em>em</em> and <em>em2</em> ok</p>"
        );
        assert_eq!(render("snake_case_name"), "<p>snake_case_name</p>");
        assert_eq!(render("####### seven"), "<p>####### seven</p>");
    }

    #[test]
    fn nul_and_control_markers_are_stripped() {
        assert_eq!(render("a\u{0}b\u{1}c"), "<p>abc</p>");
    }
}
