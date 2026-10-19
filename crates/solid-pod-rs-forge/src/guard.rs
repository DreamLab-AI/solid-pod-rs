//! Request-path guards: the percent-encoding refusal and the owner / repo /
//! ref / path validators the JSON API and the HTML lanes share.
//!
//! Cites the JSS `forge` dispatcher (the `%2e|%2f|%5c|%00` refusal ahead of
//! routing) and `helpers.js` (`okSegment`, `okPath`, `okRef`) by name only.

use crate::error::ForgeError;

/// Refuse a request path that still carries a percent-form of `.`, `/`, `\`
/// or NUL, or a literal NUL, backslash or control character.
///
/// [`crate::ForgeRequest::path`] is documented as already percent-decoded by
/// the embedding server, so a surviving `%2e`, `%2f`, `%5c` or `%00` means the
/// client double-encoded it, and a decoded NUL or backslash means it single
/// encoded one. Neither names a real object in the forge, so both are refused
/// with `400` rather than guessed at (JSS dispatcher behaviour). A server that
/// passes the still-encoded path is caught by the same test.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::percent_guard;
///
/// assert!(percent_guard("/alice/repo/blob/main/src/lib.rs").is_ok());
/// assert!(percent_guard("/alice/repo/blob/main/%2e%2e/x").is_err());
/// assert!(percent_guard("/alice/repo/blob/main/a%2Fb").is_err());
/// assert!(percent_guard("/alice/repo/a\\b").is_err());
/// assert!(percent_guard("/me/../victim/demo.git/info/refs").is_err());
/// assert!(percent_guard("/alice/repo?q=a/../b").is_ok());
/// ```
pub fn percent_guard(path: &str) -> Result<(), ForgeError> {
    if path.chars().any(|c| c == '\\' || c.is_control()) {
        return Err(ForgeError::BadRequest("bad path".into()));
    }
    // `.` and `..` segments never name a forge object. git's CGI refuses an
    // aliased path today, but relying on that is brittle (security review).
    let target = path.split(['?', '#']).next().unwrap_or(path);
    if target.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(ForgeError::BadRequest("bad path".into()));
    }
    let b = path.as_bytes();
    for i in 0..b.len().saturating_sub(2) {
        if b[i] == b'%' {
            let hex = [b[i + 1].to_ascii_lowercase(), b[i + 2].to_ascii_lowercase()];
            if matches!(&hex, b"2e" | b"2f" | b"5c" | b"00") {
                return Err(ForgeError::BadRequest("bad path".into()));
            }
        }
    }
    Ok(())
}

/// JSS `OWNER_NAME`: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, no `..`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::ok_owner;
/// assert!(ok_owner("casey"));
/// assert!(!ok_owner("a..b"));
/// assert!(!ok_owner(".hidden"));
/// ```
#[must_use]
pub fn ok_owner(s: &str) -> bool {
    name_ok(s, 64) && !s.contains("..") && !reserved_owner(s)
}

/// First path segments the router gives a meaning of its own. An owner with
/// one of these names would be routed one way and gated another (for example
/// `/api/<name>.git/info/refs` is smart-HTTP git but looks like the API
/// namespace to a path-segment check), so they can never be owner names.
pub const RESERVED_OWNERS: &[&str] = &["api", "xlogin.js"];

/// `true` when `s` is a [`RESERVED_OWNERS`] word (ASCII case-insensitive).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::{ok_owner, reserved_owner};
/// assert!(reserved_owner("API"));
/// assert!(!ok_owner("api"));
/// assert!(ok_owner("apiary"));
/// ```
#[must_use]
pub fn reserved_owner(s: &str) -> bool {
    RESERVED_OWNERS.iter().any(|r| r.eq_ignore_ascii_case(s))
}

/// JSS `REPO_NAME`: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, no `..`, no `.git`
/// suffix.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::ok_repo;
/// assert!(ok_repo("demo"));
/// assert!(!ok_repo("demo.git"));
/// ```
#[must_use]
pub fn ok_repo(s: &str) -> bool {
    name_ok(s, 128) && !s.contains("..") && !s.ends_with(".git")
}

fn name_ok(s: &str, max: usize) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= max && it.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// JSS `okSegment`: a non-empty path segment of at most 255 bytes that does
/// not start with `.`, contain `..`, a backslash, a control character or a
/// percent-form of `. / \`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::ok_segment;
/// assert!(ok_segment("main.rs"));
/// assert!(!ok_segment(".git"));
/// assert!(!ok_segment("a%2fb"));
/// ```
#[must_use]
pub fn ok_segment(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 || s.starts_with('.') || s.contains("..") {
        return false;
    }
    percent_guard(s).is_ok()
}

/// JSS `okRef`: `^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$` without `..`, a
/// trailing `/` or `//`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::ok_ref;
/// assert!(ok_ref("feature/x"));
/// assert!(!ok_ref("-bad"));
/// assert!(!ok_ref("a..b"));
/// ```
#[must_use]
pub fn ok_ref(s: &str) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= 201
        && it.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        && !s.contains("..")
        && !s.ends_with('/')
        && !s.contains("//")
}

/// JSS `SHA_RE`: `^[0-9a-f]{4,64}$`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::guard::is_sha;
/// assert!(is_sha("deadbeef"));
/// assert!(!is_sha("xyz1"));
/// ```
#[must_use]
pub fn is_sha(s: &str) -> bool {
    (4..=64).contains(&s.len()) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Segment-wise [`ok_segment`] over a path split.
#[must_use]
pub fn ok_path(segs: &[String]) -> bool {
    segs.iter().all(|s| ok_segment(s))
}

#[cfg(test)]
mod tests {
    #[test]
    fn dot_segments_are_refused_but_dotted_names_are_not() {
        use super::percent_guard;
        for bad in [
            "/a/./b",
            "/a/../b",
            "/..",
            "/me/../victim/demo.git/info/refs",
        ] {
            assert!(percent_guard(bad).is_err(), "{bad}");
        }
        for ok in ["/a/.b", "/a/b.c/d", "/a/...x", "/a/b?x=/../y"] {
            assert!(percent_guard(ok).is_ok(), "{ok}");
        }
    }

    use super::*;

    #[test]
    fn percent_forms_are_refused_case_insensitively() {
        for p in [
            "/a/%2e%2e/x",
            "/a/%2E/x",
            "/a/b%2Fc",
            "/a/b%5Cc",
            "/a/b%5cc",
            "/a/b%00c",
            "/a/b%2f",
        ] {
            assert!(percent_guard(p).is_err(), "{p}");
        }
    }

    #[test]
    fn decoded_nul_backslash_and_controls_are_refused() {
        assert!(percent_guard("/a/b\0c").is_err());
        assert!(percent_guard("/a/b\\c").is_err());
        assert!(percent_guard("/a/b\nc").is_err());
    }

    #[test]
    fn ordinary_paths_and_other_escapes_pass() {
        assert!(percent_guard("/a/b/c.txt").is_ok());
        assert!(percent_guard("/a/100%/x").is_ok());
        assert!(percent_guard("/a/%41/x").is_ok());
        assert!(percent_guard("/").is_ok());
        assert!(percent_guard("").is_ok());
        assert!(percent_guard("/a/%2").is_ok());
    }

    #[test]
    fn validators_mirror_jss() {
        assert!(ok_owner("casey") && ok_owner(&"a".repeat(64)));
        assert!(!ok_owner(&"a".repeat(65)) && !ok_owner("") && !ok_owner("a/b"));
        assert!(ok_repo("my.repo_1") && !ok_repo("x.git") && !ok_repo("a..b"));
        assert!(ok_ref("v1.0") && ok_ref("feature/x") && !ok_ref("a//b") && !ok_ref("a/"));
        assert!(!ok_ref("--upload-pack=x"));
        assert!(is_sha("abcd") && !is_sha("abc") && !is_sha("ABCD"));
        assert!(ok_segment("README.md") && !ok_segment("..") && !ok_segment(""));
        assert!(!ok_segment("a%5Cb") && !ok_segment("a\tb"));
        assert!(ok_path(&["src".to_string(), "lib.rs".to_string()]));
        assert!(!ok_path(&["src".to_string(), ".git".to_string()]));
    }
}
