//! Path-traversal guard — mirrors JSS `src/handlers/git.js` lines
//! 31-62 (`extractRepoPath` + `isPathWithinDataRoot`).
//!
//! JSS iteratively strips `..` segments (multi-pass, to defeat
//! `....//` bypass) and then asserts the resolved absolute path still
//! starts with the data-root prefix. We do the same, plus an explicit
//! rejection of absolute paths and of any remaining `..` component
//! after canonicalisation.

use std::path::{Component, Path, PathBuf};

use crate::error::GitError;

/// Strip the Git service suffixes (`/info/refs`, `/git-upload-pack`,
/// `/git-receive-pack`) from the incoming URL path to recover the
/// repository-relative slug.
#[must_use]
pub fn extract_repo_slug(url_path: &str) -> String {
    // Keep in sync with JSS extractRepoPath (lines 31-50).
    let mut clean = url_path.to_string();

    // Strip query string if present (belt-and-braces — callers should
    // split on '?' first, but this is cheap).
    if let Some(q) = clean.find('?') {
        clean.truncate(q);
    }

    for suffix in ["/info/refs", "/git-upload-pack", "/git-receive-pack"] {
        if let Some(idx) = clean.rfind(suffix) {
            // Must be at end (or immediately followed by '/')
            if idx + suffix.len() == clean.len() {
                clean.truncate(idx);
                break;
            }
        }
    }

    // Strip leading '/'.
    clean = clean.trim_start_matches('/').to_string();

    // Multi-pass `..` removal, mirroring JSS's do/while loop. This is
    // a string-level guard on top of the component-level guard below,
    // identical in spirit to JSS.
    loop {
        let stripped = clean.replace("..", "");
        if stripped == clean {
            break;
        }
        clean = stripped;
    }

    if clean.is_empty() {
        ".".into()
    } else {
        clean
    }
}

/// Resolve `requested` against `repo_root` and assert the result
/// stays inside the root. Rejects:
/// - absolute `requested` paths,
/// - any `Component::ParentDir` (`..`),
/// - resolved paths that don't share the root prefix.
///
/// Does **not** require the path to exist on disk — callers handle the
/// existence check separately so a missing repo becomes a `404`
/// rather than a `400`.
pub fn path_safe(repo_root: &Path, requested: &str) -> Result<PathBuf, GitError> {
    let req = Path::new(requested);
    if req.is_absolute() {
        return Err(GitError::PathTraversal(format!(
            "absolute path rejected: {requested}"
        )));
    }

    // Component-level check — reject any ParentDir segment. Belt and
    // braces with the string-level pass in `extract_repo_slug`.
    for component in req.components() {
        if matches!(component, Component::ParentDir) {
            return Err(GitError::PathTraversal(format!(
                "`..` component rejected: {requested}"
            )));
        }
    }

    // Canonicalise the root (must exist), then join. We deliberately
    // do NOT canonicalise the full path (the leaf may not yet exist),
    // so we rely on component-level filtering above.
    let root_canon = repo_root
        .canonicalize()
        .map_err(|e| GitError::PathTraversal(format!("root canonicalize: {e}")))?;
    let candidate = root_canon.join(req);

    // Final prefix check. Use starts_with on canonical root; the join
    // result is guaranteed to start with root_canon unless req had an
    // absolute component, which we've already rejected.
    if !candidate.starts_with(&root_canon) {
        return Err(GitError::PathTraversal(format!(
            "resolved path escapes root: {}",
            candidate.display()
        )));
    }

    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn extract_slug_strips_info_refs() {
        assert_eq!(extract_repo_slug("/alice/repo/info/refs"), "alice/repo");
    }

    #[test]
    fn extract_slug_strips_upload_pack() {
        assert_eq!(
            extract_repo_slug("/alice/repo/git-upload-pack"),
            "alice/repo"
        );
    }

    #[test]
    fn extract_slug_strips_receive_pack() {
        assert_eq!(
            extract_repo_slug("/alice/repo/git-receive-pack"),
            "alice/repo"
        );
    }

    #[test]
    fn extract_slug_empty_returns_dot() {
        assert_eq!(extract_repo_slug("/info/refs"), ".");
    }

    #[test]
    fn extract_slug_removes_parent_dirs() {
        // Multi-pass: `....//` becomes `//` then normal component
        // filtering denies the absolute-ish path.
        let slug = extract_repo_slug("/..%2F..%2Fetc/info/refs");
        // The % is not decoded by us — by design: we receive a
        // decoded path from the HTTP layer. Test with raw `..`:
        let slug2 = extract_repo_slug("/../../etc/info/refs");
        assert!(!slug2.contains(".."), "slug still has `..`: {slug2}");
        // `%2F` is an opaque char at this layer; not our job:
        assert!(slug.contains('%'), "slug={slug}");
    }

    #[test]
    fn path_safe_accepts_child() {
        let td = TempDir::new().unwrap();
        let result = path_safe(td.path(), "alice/repo").unwrap();
        assert!(result.starts_with(td.path().canonicalize().unwrap()));
    }

    #[test]
    fn path_safe_rejects_absolute() {
        let td = TempDir::new().unwrap();
        let err = path_safe(td.path(), "/etc/passwd").unwrap_err();
        assert!(matches!(err, GitError::PathTraversal(_)));
    }

    #[test]
    fn path_safe_rejects_parent_dir() {
        let td = TempDir::new().unwrap();
        let err = path_safe(td.path(), "../etc").unwrap_err();
        assert!(matches!(err, GitError::PathTraversal(_)));
    }

    #[test]
    fn path_safe_rejects_nested_parent() {
        let td = TempDir::new().unwrap();
        let err = path_safe(td.path(), "alice/../../etc").unwrap_err();
        assert!(matches!(err, GitError::PathTraversal(_)));
    }
}
