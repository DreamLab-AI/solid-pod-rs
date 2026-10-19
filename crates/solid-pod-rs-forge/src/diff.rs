//! Structured unified-diff parser: one parse feeds the JSON API's
//! `files[] -> hunks[] -> lines[]` shape (and, later, the compare and pull
//! request views).
//!
//! Follows the JSS `forge` `parsePatch` contract by name: each file is
//! `{name, binary, adds, dels, hunks}`; each hunk `{header, lines}`; each line
//! `{type: add|del|ctx|meta, oldLine, newLine, text}`.

use serde::Serialize;

/// Kind of a diff line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LineKind {
    /// Added line (`+`).
    Add,
    /// Removed line (`-`).
    Del,
    /// Context line (` `).
    Ctx,
    /// `\ No newline at end of file` style marker.
    Meta,
}

/// One line of a hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    /// Line kind (`type` in the JSON).
    #[serde(rename = "type")]
    pub kind: LineKind,
    /// Line number in the old file, when the line exists there.
    pub old_line: Option<u64>,
    /// Line number in the new file, when the line exists there.
    pub new_line: Option<u64>,
    /// Text without the leading diff sign.
    pub text: String,
}

/// A `@@ -a,b +c,d @@` hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hunk {
    /// The raw `@@` header line.
    pub header: String,
    /// The hunk's lines.
    pub lines: Vec<DiffLine>,
}

/// One file of a patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDiff {
    /// New-side file name (old-side for deletions).
    pub name: Option<String>,
    /// `true` for a `Binary files … differ` entry.
    pub binary: bool,
    /// Added line count.
    pub adds: u64,
    /// Removed line count.
    pub dels: u64,
    /// The hunks.
    pub hunks: Vec<Hunk>,
}

fn parse_hunk_header(line: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix("@@ -")?;
    let (old, rest) = rest.split_once(' ')?;
    let new = rest.strip_prefix('+')?;
    let (new, tail) = new.split_once(' ')?;
    if !tail.starts_with("@@") {
        return None;
    }
    let start = |s: &str| s.split(',').next().and_then(|n| n.parse::<u64>().ok());
    Some((start(old)?, start(new)?))
}

/// Parse a `git show --patch` / `git diff` unified patch.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::diff::{parse_patch, LineKind};
///
/// let patch = "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,2 @@\n keep\n-old\n+new\n";
/// let files = parse_patch(patch);
/// assert_eq!(files[0].name.as_deref(), Some("f.txt"));
/// assert_eq!((files[0].adds, files[0].dels), (1, 1));
/// let lines = &files[0].hunks[0].lines;
/// assert_eq!(lines[2].kind, LineKind::Add);
/// assert_eq!(lines[2].new_line, Some(2));
/// ```
#[must_use]
pub fn parse_patch(patch: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let (mut old_n, mut new_n) = (0u64, 0u64);
    for line in patch.split('\n') {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let mut f = FileDiff {
                name: None,
                binary: false,
                adds: 0,
                dels: 0,
                hunks: Vec::new(),
            };
            // `a/<x> b/<y>`: the new-side name is everything after the last " b/".
            if let Some(idx) = rest.rfind(" b/") {
                if rest.starts_with("a/") {
                    f.name = Some(rest[idx + 3..].to_string());
                }
            }
            files.push(f);
            continue;
        }
        let Some(cur) = files.last_mut() else {
            continue;
        };
        if let (true, Some(n)) = (cur.hunks.is_empty(), line.strip_prefix("+++ ")) {
            if n != "/dev/null" {
                cur.name = Some(n.strip_prefix("b/").unwrap_or(n).to_string());
            }
            continue;
        }
        if let (true, Some(n)) = (cur.hunks.is_empty(), line.strip_prefix("--- ")) {
            if cur.name.is_none() && n != "/dev/null" {
                cur.name = Some(n.strip_prefix("a/").unwrap_or(n).to_string());
            }
            continue;
        }
        if line.starts_with("Binary files") {
            cur.binary = true;
            continue;
        }
        if let Some((o, n)) = parse_hunk_header(line) {
            old_n = o;
            new_n = n;
            cur.hunks.push(Hunk {
                header: line.to_string(),
                lines: Vec::new(),
            });
            continue;
        }
        let Some(hunk) = cur.hunks.last_mut() else {
            continue;
        };
        if let Some(t) = line.strip_prefix('+') {
            hunk.lines.push(DiffLine {
                kind: LineKind::Add,
                old_line: None,
                new_line: Some(new_n),
                text: t.to_string(),
            });
            new_n += 1;
            cur.adds += 1;
        } else if let Some(t) = line.strip_prefix('-') {
            hunk.lines.push(DiffLine {
                kind: LineKind::Del,
                old_line: Some(old_n),
                new_line: None,
                text: t.to_string(),
            });
            old_n += 1;
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
        } else if line.starts_with('\\') {
            hunk.lines.push(DiffLine {
                kind: LineKind::Meta,
                old_line: None,
                new_line: None,
                text: line.to_string(),
            });
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modify_add_delete_and_binary() {
        let patch = "diff --git a/src/main.js b/src/main.js\nindex 1..2 100644\n--- a/src/main.js\n+++ b/src/main.js\n@@ -1,3 +1,3 @@\n function main() {\n-  return 1;\n+  return 2;\n }\ndiff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+hi\n\\ No newline at end of file\ndiff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\ndiff --git a/b.bin b/b.bin\nBinary files a/b.bin and b/b.bin differ\n";
        let f = parse_patch(patch);
        assert_eq!(f.len(), 4);
        assert_eq!(f[0].name.as_deref(), Some("src/main.js"));
        assert_eq!((f[0].adds, f[0].dels), (1, 1));
        let l = &f[0].hunks[0].lines;
        assert_eq!(l[1].kind, LineKind::Del);
        assert_eq!((l[1].old_line, l[1].new_line), (Some(2), None));
        assert_eq!(l[2].new_line, Some(2));
        assert!(l
            .iter()
            .all(|x| x.kind != LineKind::Add || x.new_line.is_some()));
        assert_eq!(f[1].name.as_deref(), Some("new.txt"));
        assert_eq!(f[1].hunks[0].lines[1].kind, LineKind::Meta);
        assert_eq!(f[2].name.as_deref(), Some("gone.txt"));
        assert_eq!(f[2].dels, 1);
        assert!(f[3].binary && f[3].hunks.is_empty());
    }

    #[test]
    fn empty_patch_and_preamble_are_ignored() {
        assert!(parse_patch("").is_empty());
        assert!(parse_patch("commit abc\nAuthor: x\n").is_empty());
    }

    #[test]
    fn json_shape_uses_type_and_camel_case() {
        let f = parse_patch("diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n");
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v[0]["hunks"][0]["lines"][0]["type"], "del");
        assert_eq!(v[0]["hunks"][0]["lines"][1]["newLine"], 1);
    }
}
