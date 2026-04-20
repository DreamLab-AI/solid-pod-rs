//! Pod resolution from request host (Sprint 7 §6.3, ADR-057).
//!
//! JSS parity: `src/utils/url.js::urlToPathWithPod` and the
//! `subdomainsEnabled && podName` branch in `getPathFromRequest`.
//! We lift the policy ("which pod owns this request?") out of the
//! URL-to-filesystem mapper so that call sites (LDP, WAC, quota) can
//! consult it uniformly without each re-parsing the Host header.
//!
//! # Model
//!
//! - [`PathResolver`] — default single-tenant behaviour. The URL path
//!   is the storage path verbatim and `pod` is `None`.
//! - [`SubdomainResolver`] — `<pod>.<base_domain>` maps the first label
//!   to a pod identifier; bare `<base_domain>` returns the root pod
//!   (`pod: None`). Anything else (unknown subdomain tree) falls back
//!   to path-based semantics.
//!
//! # Security
//!
//! Pod labels are scrubbed of `..` sequences with the same **double-pass**
//! algorithm JSS uses in `urlToPathWithPod` (`..` is replaced until the
//! string stops changing, defeating the `....//` bypass). Any resulting
//! empty or path-containing label is rejected by falling back to path
//! mode with `pod: None`.

/// Result of resolving a request to a pod + storage path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Pod identifier, or `None` for single-tenant / root pod.
    pub pod: Option<String>,
    /// Storage path relative to the pod root (or global root when
    /// `pod` is `None`). Verbatim from the URL — no percent-decoding
    /// here; callers handle encoding via their storage trait.
    pub storage_path: String,
}

/// Policy that maps `(host, url_path)` onto a [`ResolvedPath`].
pub trait PodResolver: Send + Sync {
    fn resolve(&self, host: &str, url_path: &str) -> ResolvedPath;
}

// ---------------------------------------------------------------------------
// PathResolver — single-tenant pass-through.
// ---------------------------------------------------------------------------

/// Single-tenant / path-based resolver. Equivalent to JSS's
/// `subdomainsEnabled=false` mode: the URL path *is* the storage path
/// and there is no notion of a per-host pod.
pub struct PathResolver;

impl PodResolver for PathResolver {
    fn resolve(&self, _host: &str, url_path: &str) -> ResolvedPath {
        ResolvedPath {
            pod: None,
            storage_path: url_path.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// SubdomainResolver — `<pod>.<base_domain>` → pod = first label.
// ---------------------------------------------------------------------------

/// Subdomain-based resolver. Matches hosts of the form
/// `<pod>.<base_domain>` and yields `pod = Some(<pod>)`. The bare
/// base domain yields `pod = None` (root pod). Hosts outside the base
/// domain tree fall back to path-based semantics.
pub struct SubdomainResolver {
    /// Authoritative base domain (e.g. `"example.org"`). Port is
    /// ignored at match time; see [`strip_port`].
    pub base_domain: String,
}

impl PodResolver for SubdomainResolver {
    fn resolve(&self, host: &str, url_path: &str) -> ResolvedPath {
        let host_no_port = strip_port(host);
        let base = self.base_domain.trim().to_ascii_lowercase();
        let host_lc = host_no_port.to_ascii_lowercase();

        // Bare base domain → root pod.
        if host_lc == base {
            return ResolvedPath {
                pod: None,
                storage_path: url_path.to_string(),
            };
        }

        // `<pod>.<base_domain>` — peel the suffix. Require the
        // separator dot so `fooexample.org` doesn't match `example.org`.
        let suffix = format!(".{base}");
        if let Some(stripped) = host_lc.strip_suffix(&suffix) {
            // Scrub `..` *first* (JSS double-pass) so that a label
            // like `al..ice` normalises to `alice` before we decide
            // whether it is a multi-label subdomain.
            let safe = scrub_dotdot(stripped);
            // Only accept single-label subdomains after scrubbing;
            // multi-level subdomains (`a.b.example.org`) fall back to
            // path mode so we don't accidentally promote DNS labels to
            // pod names. Reject labels containing `/` or any residual
            // `..` that somehow survived scrubbing.
            if !safe.is_empty()
                && !safe.contains('.')
                && !safe.contains('/')
                && !safe.contains("..")
            {
                return ResolvedPath {
                    pod: Some(safe),
                    storage_path: url_path.to_string(),
                };
            }
        }

        // Fallback policy: unknown host → path-based semantics. This
        // mirrors JSS's `subdomainsEnabled && podName` guard: when no
        // pod can be derived the server still serves from the shared
        // root instead of rejecting.
        ResolvedPath {
            pod: None,
            storage_path: url_path.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip an optional `:<port>` suffix. IPv6 literals (which include
/// colons) are not currently supported in subdomain mode — operators
/// running IPv6-native setups should prefer [`PathResolver`].
fn strip_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(i) => &host[..i],
        None => host,
    }
}

/// Double-pass `..` scrub (JSS parity: `urlToPathWithPod` lines 62-66
/// and 70-74). Repeats until the string stops shrinking, defeating the
/// `....//` bypass.
fn scrub_dotdot(s: &str) -> String {
    let mut cur = s.to_string();
    loop {
        let next = cur.replace("..", "");
        if next == cur {
            return next;
        }
        cur = next;
    }
}

// ---------------------------------------------------------------------------
// Unit tests — exercise helpers; integration coverage lives in
// `tests/tenancy_subdomain.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_handles_missing_port() {
        assert_eq!(strip_port("example.org"), "example.org");
        assert_eq!(strip_port("example.org:8080"), "example.org");
    }

    #[test]
    fn scrub_dotdot_is_double_pass() {
        assert_eq!(scrub_dotdot("al..ice"), "alice");
        // `....` would become `..` after a single pass; second pass
        // must strip it completely.
        assert_eq!(scrub_dotdot("al....ice"), "alice");
        assert_eq!(scrub_dotdot("safe"), "safe");
    }

    #[test]
    fn path_resolver_ignores_host() {
        let r = PathResolver;
        let a = r.resolve("anything", "/x");
        let b = r.resolve("", "/x");
        assert_eq!(a, b);
        assert_eq!(a.pod, None);
    }
}
