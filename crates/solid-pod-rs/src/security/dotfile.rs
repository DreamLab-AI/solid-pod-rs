//! Dotfile allowlist (F2).
//!
//! Rejects any inbound request whose path contains a component starting
//! with `.` unless that component is explicitly allowlisted. Default
//! allowlist mirrors JSS: `.acl` and `.meta` — the standard Solid
//! metadata sidecars.
//!
//! Upstream parity: `JavaScriptSolidServer/src/server.js:265-281`.
//! Design context: `docs/design/jss-parity/01-security-primitives-context.md`.

use std::path::{Component, Path};

use thiserror::Error;

use crate::metrics::SecurityMetrics;

/// Environment variable: comma-separated dotfile names permitted by the
/// allowlist. Each entry may or may not include the leading `.`; the
/// allowlist stores them normalised (leading `.` present).
pub const ENV_DOTFILE_ALLOWLIST: &str = "DOTFILE_ALLOWLIST";

/// Default allowlist entries. Matches JSS behaviour for standard Solid
/// metadata sidecars and the IdP login endpoint (JSS commit 32c0db2).
pub const DEFAULT_ALLOWED: &[&str] = &[".acl", ".meta", ".account"];

/// Reason a path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum DotfileError {
    /// Path contained a dotfile component not on the allowlist.
    #[error("dotfile path component is not on the allowlist")]
    NotAllowed,
}

/// Dotfile allowlist (aggregate root).
///
/// Immutable after construction. Matching is by exact component
/// equality, but segments that would collide with a guarded name on a
/// case-insensitive filesystem (`doc.ACL`, `X.META.JSON`) are refused:
/// see `is_non_canonical_guarded` (private helper).
#[derive(Debug, Clone)]
pub struct DotfileAllowlist {
    allowed: Vec<String>,
    metrics: Option<SecurityMetrics>,
}

impl DotfileAllowlist {
    /// Load from `DOTFILE_ALLOWLIST` (comma-separated). Falls back to
    /// the default allowlist (`.acl`, `.meta`) when unset or empty.
    pub fn from_env() -> Self {
        match std::env::var(ENV_DOTFILE_ALLOWLIST) {
            Ok(raw) => {
                let parsed = parse_csv(&raw);
                if parsed.is_empty() {
                    Self::with_defaults()
                } else {
                    Self {
                        allowed: parsed,
                        metrics: None,
                    }
                }
            }
            Err(_) => Self::with_defaults(),
        }
    }

    /// Construct the default allowlist: `.acl`, `.meta`, `.account`.
    pub fn with_defaults() -> Self {
        Self {
            allowed: DEFAULT_ALLOWED.iter().map(|s| (*s).to_string()).collect(),
            metrics: None,
        }
    }

    /// Construct with an explicit allowlist. Each entry is normalised
    /// to include the leading `.`.
    pub fn new(entries: Vec<String>) -> Self {
        let allowed = entries
            .into_iter()
            .map(|e| normalise_entry(&e))
            .filter(|e| !e.is_empty() && e != ".")
            .collect();
        Self {
            allowed,
            metrics: None,
        }
    }

    /// Attach a metrics sink; counter is incremented on every deny.
    pub fn with_metrics(mut self, metrics: SecurityMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Return the current allowlist entries (normalised; each begins
    /// with `.`).
    pub fn entries(&self) -> &[String] {
        &self.allowed
    }

    /// Returns `false` if ANY path component starts with `.` AND is
    /// not on the allowlist. Returns `true` if the path is free of
    /// dotfile components, or if every dotfile component present is
    /// on the allowlist.
    ///
    /// `.` and `..` navigation components are always rejected
    /// (callers MUST normalise paths before reaching this primitive,
    /// but we defend in depth).
    pub fn is_allowed(&self, path: &Path) -> bool {
        for component in path.components() {
            match component {
                Component::Normal(os) => {
                    let s = match os.to_str() {
                        Some(s) => s,
                        // Non-UTF-8: refuse (Solid paths are UTF-8).
                        None => {
                            self.record_deny();
                            return false;
                        }
                    };
                    if s.starts_with('.') && !self.allowed.iter().any(|a| a == s) {
                        self.record_deny();
                        return false;
                    }
                    // Reserve the internal storage-sidecar namespace. The fs
                    // backend stores each resource's content-type in a
                    // `<name>.meta.json` sidecar; because that name does not
                    // start with `.` it slips the dotfile rule above. A direct
                    // HTTP write to `/foo.meta.json` would hide `/foo` from
                    // container listings AND poison the Content-Type served
                    // for a sibling (a stored-XSS vector). These are never
                    // directly addressable over HTTP.
                    if fold_case(s).ends_with(".meta.json") || is_non_canonical_guarded(s) {
                        self.record_deny();
                        return false;
                    }
                }
                Component::CurDir | Component::ParentDir => {
                    // Defensive: reject navigation components even
                    // though callers should have normalised the path.
                    self.record_deny();
                    return false;
                }
                Component::Prefix(_) | Component::RootDir => {
                    // Scheme prefix / leading `/`: no dotfile concern.
                }
            }
        }
        true
    }

    fn record_deny(&self) {
        if let Some(m) = &self.metrics {
            m.record_dotfile_deny();
        }
    }
}

impl Default for DotfileAllowlist {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// --- Sprint 9: row 115 free-function primitive ---------------------------
//
// The JSS-parity row 115 deliverable is a plain string-path allowlist used
// at framework-agnostic call sites (middleware, route guards, provision
// dry-runs) where an owning `DotfileAllowlist` is not wired up. Semantics
// are a superset of the default allowlist: Solid metadata sidecars
// (`.acl`, `.meta`), the service container (`.well-known`), quota
// sidecars (`.quota.json`), and resource-specific ACL/meta trailers
// (`foo.acl`, `foo.meta`) are permitted. Every other leading-dot segment
// blocks the whole path. `..` traversal is refused as defence-in-depth.

/// Dotfile allowlist errors used by the row-115 free primitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum DotfilePathError {
    /// A path segment started with `.` and was not on the allowlist.
    #[error("dotfile segment '{segment}' not allowed in path '{path}'")]
    NotAllowed { segment: String, path: String },

    /// A `..` (parent) segment was encountered — rejected as defence
    /// in depth against directory traversal.
    #[error("parent-directory traversal segment '..' not allowed in path '{0}'")]
    ParentTraversal(String),

    /// A non-UTF-8 or otherwise malformed segment (Solid paths are
    /// UTF-8). Currently unreachable from `&str` but kept for
    /// forward-compat with OsStr-keyed callers.
    #[error("malformed path segment in '{0}'")]
    Malformed(String),
}

const STATIC_ALLOWED_DOTFILES: &[&str] = &[
    ".acl",
    ".meta",
    ".well-known",
    ".quota.json",
    // `.acl.meta` — meta sidecar for an ACL; authorised by the union of
    // the two rules above but spelled out here so the match is O(1)
    // without a trailing-suffix check on the main path.
    ".acl.meta",
    // `.account` — IdP login endpoint. JSS commit 32c0db2 allows this
    // through the dotfile filter so that the local identity provider can
    // serve account-related resources (login, registration, password
    // reset) at `/.account/…`.
    ".account",
];

/// Decide whether `path` may be served, purely by inspecting its
/// segments. Returns `Ok(())` when every segment is admissible.
///
/// A segment is admissible when any of the following hold:
///   - it does not start with `.`
///   - it is one of the statically-allowed dotfiles (`.acl`, `.meta`,
///     `.well-known`, `.quota.json`)
///
/// Resource-specific ACL/metadata sidecars like `foo.acl` / `foo.meta`
/// are admissible because their segment does not start with `.`; the
/// trailing-suffix form is therefore handled implicitly by the
/// first rule above.
///
/// Explicitly blocked:
///   - `.env`, `.git`, `.ssh`, any other leading-dot name
///   - `..` (parent-dir traversal) anywhere in the path
///
/// The check is applied to every segment: a blocked segment anywhere in
/// the path fails the whole path (e.g. `/pod/.git/HEAD` is blocked).
///
/// Empty segments and `.` (current-dir) are ignored — they carry no
/// authorisation information. Leading `/` is honoured as the root.
///
/// Upstream parity: `JavaScriptSolidServer/src/server.js:265-281` +
/// Solid §Identity Provider service container rules.
pub fn is_path_allowed(path: &str) -> Result<(), DotfilePathError> {
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(DotfilePathError::ParentTraversal(path.to_string()));
        }
        // Reserve the internal storage-sidecar namespace (`<name>.meta.json`):
        // it does not start with `.`, so without this it would slip the
        // dotfile rule below and let an HTTP writer hide or content-type-
        // poison a sibling resource. See `DotfileAllowlist::is_allowed`.
        if fold_case(segment).ends_with(".meta.json") || is_non_canonical_guarded(segment) {
            return Err(DotfilePathError::NotAllowed {
                segment: segment.to_string(),
                path: path.to_string(),
            });
        }
        if !segment.starts_with('.') {
            continue;
        }
        if STATIC_ALLOWED_DOTFILES.contains(&segment) {
            continue;
        }
        return Err(DotfilePathError::NotAllowed {
            segment: segment.to_string(),
            path: path.to_string(),
        });
    }
    Ok(())
}

// --- helpers -------------------------------------------------------------

/// `true` when `segment` is *not* spelled in its canonical (Unicode
/// lower-case) form but its folded form is a guarded sidecar name
/// (`*.acl`, `*.meta`, `*.meta.json`, or any allowlisted dotfile).
///
/// On case-insensitive filesystems (default macOS/APFS, Windows/NTFS)
/// `doc.ACL` and `doc.acl` are the same file, so a guard keyed on the
/// canonical spelling would be bypassed by a variant one. Folding uses
/// [`fold_case`].
/// Canonical spellings are unaffected: `doc.acl` is still an ordinary
/// sidecar name.
fn is_non_canonical_guarded(segment: &str) -> bool {
    let folded = fold_case(segment);
    if folded == segment {
        return false;
    }
    folded.ends_with(".acl")
        || folded.ends_with(".meta")
        || folded.ends_with(".meta.json")
        || STATIC_ALLOWED_DOTFILES.contains(&folded.as_str())
}

/// Fold `s` for comparison against a guarded name, the way a case-insensitive
/// filesystem would.
///
/// [`str::to_lowercase`] is Unicode *simple* lower-casing, which already maps
/// the Kelvin sign U+212A to `k`. Full case folding also maps a few characters
/// to ASCII that lower-casing leaves alone: the long s U+017F to `s`, the sharp
/// s to `ss`, and the Latin ligatures (U+FB00 to U+FB06) to their letters. A
/// guard built on lower-casing alone let `x.meta.j\u{17F}on` through.
///
/// ```
/// use solid_pod_rs::security::dotfile::fold_case;
/// assert_eq!(fold_case("X.META.J\u{17F}ON"), "x.meta.json");
/// assert_eq!(fold_case("to\u{212A}en"), "token");
/// assert_eq!(fold_case("\u{FB01}le"), "file");
/// ```
#[must_use]
pub fn fold_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\u{017F}' => out.push('s'),
            '\u{00DF}' | '\u{1E9E}' => out.push_str("ss"),
            '\u{FB00}' => out.push_str("ff"),
            '\u{FB01}' => out.push_str("fi"),
            '\u{FB02}' => out.push_str("fl"),
            '\u{FB03}' => out.push_str("ffi"),
            '\u{FB04}' => out.push_str("ffl"),
            '\u{FB05}' | '\u{FB06}' => out.push_str("st"),
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

fn parse_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(normalise_entry)
        .filter(|s| !s.is_empty() && s != ".")
        .collect()
}

fn normalise_entry(entry: &str) -> String {
    let trimmed = entry.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with('.') {
        trimmed.to_string()
    } else {
        format!(".{trimmed}")
    }
}

// --- unit tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn case_variants_of_guarded_names_are_refused() {
        let al = DotfileAllowlist::default();
        for bad in [
            "/p/doc.ACL",
            "/p/doc.Acl",
            "/p/doc.META",
            "/p/X.META.JSON",
            "/p/x.Meta.Json",
            "/p/.ACL",
            "/p/.Meta",
        ] {
            assert!(!al.is_allowed(&PathBuf::from(bad)), "{bad}");
            assert!(is_path_allowed(bad).is_err(), "{bad}");
        }
        // Kelvin sign folds to ASCII `k`; make sure the fold is Unicode-aware.
        assert_eq!("\u{212A}".to_lowercase(), "k");
        // Lower-casing leaves the long s alone; folding must not.
        assert!(is_path_allowed("/x.meta.j\u{17F}on").is_err());
        assert!(
            is_path_allowed("/doc.\u{17F}cl").is_ok(),
            "not a guarded name"
        );
        assert!(is_path_allowed("/doc.ACL").is_err());
        for ok in ["/p/doc.acl", "/p/doc.meta", "/p/Readme.TXT", "/p/Photo.JPG"] {
            assert!(al.is_allowed(&PathBuf::from(ok)), "{ok}");
            assert!(is_path_allowed(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn default_permits_acl_and_meta() {
        let al = DotfileAllowlist::default();
        assert!(al.is_allowed(&PathBuf::from("/resource/.acl")));
        assert!(al.is_allowed(&PathBuf::from("/resource/.meta")));
    }

    #[test]
    fn default_blocks_env() {
        let al = DotfileAllowlist::default();
        assert!(!al.is_allowed(&PathBuf::from("/.env")));
        assert!(!al.is_allowed(&PathBuf::from("/x/y/.env")));
    }

    #[test]
    fn explicit_allowlist_accepts_listed_entries() {
        let al = DotfileAllowlist::new(vec![".env".into(), ".config".into()]);
        assert!(al.is_allowed(&PathBuf::from("/.env")));
        assert!(al.is_allowed(&PathBuf::from("/.config")));
        assert!(!al.is_allowed(&PathBuf::from("/.secret")));
    }

    #[test]
    fn entry_without_dot_prefix_is_normalised() {
        let al = DotfileAllowlist::new(vec!["notifications".into()]);
        assert!(al.is_allowed(&PathBuf::from("/.notifications")));
    }

    #[test]
    fn nested_dotfile_rejected() {
        let al = DotfileAllowlist::default();
        assert!(!al.is_allowed(&PathBuf::from("foo/.secret/bar")));
    }

    #[test]
    fn path_without_dotfiles_accepted() {
        let al = DotfileAllowlist::default();
        assert!(al.is_allowed(&PathBuf::from("/a/b/c/file.ttl")));
    }

    #[test]
    fn parent_dir_rejected() {
        let al = DotfileAllowlist::default();
        assert!(!al.is_allowed(&PathBuf::from("foo/..")));
    }

    // ----- Sprint 9 row 115: free-function primitive --------------------

    #[test]
    fn allows_acl_file() {
        assert!(is_path_allowed("/.acl").is_ok());
        assert!(is_path_allowed("/pod/.acl").is_ok());
        assert!(is_path_allowed("/pod/container/.acl").is_ok());
    }

    #[test]
    fn allows_meta_file() {
        assert!(is_path_allowed("/.meta").is_ok());
        assert!(is_path_allowed("/pod/.meta").is_ok());
        assert!(is_path_allowed("/pod/container/.meta").is_ok());
    }

    #[test]
    fn allows_well_known_subtree() {
        assert!(is_path_allowed("/.well-known").is_ok());
        assert!(is_path_allowed("/.well-known/openid-configuration").is_ok());
        assert!(is_path_allowed("/.well-known/solid").is_ok());
        assert!(is_path_allowed("/pod/.well-known/nested").is_ok());
    }

    #[test]
    fn allows_quota_sidecar() {
        assert!(is_path_allowed("/.quota.json").is_ok());
        assert!(is_path_allowed("/pod/.quota.json").is_ok());
        assert!(is_path_allowed("/pod/container/.quota.json").is_ok());
    }

    #[test]
    fn allows_resource_specific_acl() {
        // Resource-specific ACLs per Solid WAC: `foo.acl` is the ACL
        // for `foo`. Segment does not start with `.` so admissible
        // without consulting the dotfile allowlist.
        assert!(is_path_allowed("/foo.acl").is_ok());
        assert!(is_path_allowed("/foo.meta").is_ok());
        assert!(is_path_allowed("/pod/data.ttl.acl").is_ok());
        assert!(is_path_allowed("/pod/image.jpg.meta").is_ok());
    }

    #[test]
    fn allows_normal_path() {
        assert!(is_path_allowed("/foo/bar.ttl").is_ok());
        assert!(is_path_allowed("/").is_ok());
        assert!(is_path_allowed("/pod/data/doc.ttl").is_ok());
        assert!(is_path_allowed("").is_ok());
    }

    #[test]
    fn blocks_env_file() {
        match is_path_allowed("/.env") {
            Err(DotfilePathError::NotAllowed { segment, .. }) => assert_eq!(segment, ".env"),
            other => panic!("expected NotAllowed for /.env, got {other:?}"),
        }
        assert!(is_path_allowed("/pod/.env").is_err());
        assert!(is_path_allowed("/deep/path/.env").is_err());
    }

    #[test]
    fn blocks_git_dir() {
        match is_path_allowed("/pod/.git/config") {
            Err(DotfilePathError::NotAllowed { segment, .. }) => assert_eq!(segment, ".git"),
            other => panic!("expected NotAllowed for /pod/.git/config, got {other:?}"),
        }
        assert!(is_path_allowed("/.git").is_err());
        assert!(is_path_allowed("/.git/HEAD").is_err());
        assert!(is_path_allowed("/.ssh/id_rsa").is_err());
    }

    #[test]
    fn blocks_hidden_file_anywhere() {
        assert!(is_path_allowed("/foo/.hidden/bar.ttl").is_err());
        assert!(is_path_allowed("/a/b/c/.secret").is_err());
        assert!(is_path_allowed("/.DS_Store").is_err());
        assert!(is_path_allowed("/pod/.npmrc").is_err());
    }

    #[test]
    fn blocks_double_dot() {
        match is_path_allowed("/pod/../etc/passwd") {
            Err(DotfilePathError::ParentTraversal(_)) => {}
            other => panic!("expected ParentTraversal for /pod/../etc/passwd, got {other:?}"),
        }
        assert!(matches!(
            is_path_allowed(".."),
            Err(DotfilePathError::ParentTraversal(_))
        ));
        assert!(matches!(
            is_path_allowed("/a/../b"),
            Err(DotfilePathError::ParentTraversal(_))
        ));
    }

    // ----- Sprint 12: `.account` in dotfile allowlist (JSS 32c0db2) ------

    #[test]
    fn default_permits_account() {
        let al = DotfileAllowlist::default();
        assert!(
            al.is_allowed(&PathBuf::from("/.account")),
            ".account must be on default allowlist"
        );
        assert!(
            al.is_allowed(&PathBuf::from("/pod/.account")),
            ".account nested under pod must pass"
        );
    }

    #[test]
    fn allows_account_path_free_function() {
        assert!(
            is_path_allowed("/.account").is_ok(),
            ".account must pass the free-function check"
        );
        assert!(
            is_path_allowed("/.account/login").is_ok(),
            ".account subtree must pass"
        );
        assert!(
            is_path_allowed("/pod/.account/register").is_ok(),
            ".account under pod must pass"
        );
    }

    #[test]
    fn account_in_default_allowed_constant() {
        assert!(
            DEFAULT_ALLOWED.contains(&".account"),
            "DEFAULT_ALLOWED must include .account"
        );
    }
}
