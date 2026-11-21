//! Resolution of the IRIs inside an ACL document against the pod's own origin.
//!
//! WAC names the resource a rule covers (`acl:accessTo`, `acl:default`) and
//! the agents it grants (`acl:agent`) with IRIs that may be absolute
//! (`https://pod.example/a/`), relative to the ACL document
//! (`./b`, `../`, `#me`) or root-relative (`/a/`). The evaluator itself
//! compares server-root paths. [`AclBase`] bridges the two: it holds the pod's
//! **configured** origin and rewrites an [`AclDocument`] so that every target
//! on that origin becomes a path and every relative agent becomes an absolute
//! WebID, resolved against the ACL document's own URL.
//!
//! # Safety property
//!
//! A target is converted to a path only when, after RFC 3986 resolution, its
//! origin (scheme, host, port, with the default port and host case
//! normalised) is *exactly* the configured origin. Every other target is
//! rewritten to a value that matches nothing, so an ACL naming another
//! origin's resource never grants on this one. The origin is configuration
//! (`public_base_url`), never a request `Host`. Without a configured origin
//! nothing here runs and absolute targets keep failing closed.
//!
//! A target is also refused (matches nothing) when it carries userinfo, a
//! query or a fragment (each names a different resource), or when its path
//! holds an encoded separator or control byte (`%2f`, `%5c`, `%00`), which
//! would name a different resource once decoded. The resulting path keeps the
//! percent-encoded spelling requests use, so it is compared exactly as a
//! root-relative path always was.

use crate::wac::document::{get_ids, ids_of, AclAuthorization, AclDocument, IdOrIds};

/// A target value no request path can equal (a path never contains NUL).
const NEVER: &str = "\u{0}never";

/// The pod's configured origin, used to resolve the IRIs of an ACL document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclBase {
    origin: url::Origin,
}

impl AclBase {
    /// Build from the configured public base URL (`scheme://authority`).
    ///
    /// Returns `None`, leaving the evaluator fail-closed, unless the value is
    /// an `http` or `https` URL with a host and no userinfo, query, fragment
    /// or path beyond `/`.
    ///
    /// ```
    /// use solid_pod_rs::wac::AclBase;
    /// assert!(AclBase::new("https://pod.example").is_some());
    /// assert!(AclBase::new("https://pod.example/").is_some());
    /// assert!(AclBase::new("https://pod.example/sub/").is_none());
    /// assert!(AclBase::new("ftp://pod.example").is_none());
    /// assert!(AclBase::new("not a url").is_none());
    /// ```
    #[must_use]
    pub fn new(public_base_url: &str) -> Option<Self> {
        let u = url::Url::parse(public_base_url).ok()?;
        let plain = matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/";
        plain.then(|| Self { origin: u.origin() })
    }

    /// The configured origin as `scheme://host[:port]`.
    #[must_use]
    pub fn origin(&self) -> String {
        self.origin.ascii_serialization()
    }

    /// URL of the ACL document stored under `acl_key`. Storage keys and
    /// request paths use the percent-encoded spelling of the request target,
    /// so the key is already URL path syntax.
    fn document_url(&self, acl_key: &str) -> Option<url::Url> {
        let key = if acl_key.starts_with('/') {
            acl_key.to_string()
        } else {
            format!("/{acl_key}")
        };
        url::Url::parse(&format!("{}{}", self.origin(), key)).ok()
    }

    /// Rewrite `doc`, which was read from the storage key `acl_key`.
    ///
    /// `acl:accessTo` / `acl:default` targets become server-root paths when
    /// they resolve onto the configured origin and match nothing otherwise;
    /// relative `acl:agent` IRIs become absolute against the ACL's own URL.
    /// A document that cannot be placed (an unusable `acl_key`) has every
    /// target replaced by a non-matching value.
    #[must_use]
    pub fn resolve_document(&self, doc: &AclDocument, acl_key: &str) -> AclDocument {
        let base = self.document_url(acl_key);
        let mut out = doc.clone();
        if let Some(graph) = out.graph.as_mut() {
            for auth in graph.iter_mut() {
                self.resolve_authorization(auth, base.as_ref());
            }
        }
        out
    }

    fn resolve_authorization(&self, auth: &mut AclAuthorization, base: Option<&url::Url>) {
        auth.access_to = map_ids(&auth.access_to, |t| self.target_path(t, base));
        auth.default = map_ids(&auth.default, |t| self.target_path(t, base));
        auth.agent = map_ids(&auth.agent, |a| Some(resolve_agent(a, base)));
    }

    /// The server-root path `target` names on this origin, or `None`.
    fn target_path(&self, target: &str, base: Option<&url::Url>) -> Option<String> {
        // A root-relative path is today's accepted form; keep it verbatim.
        if target.starts_with('/') && !target.starts_with("//") {
            return Some(target.to_string());
        }
        let resolved = url::Url::options().base_url(base).parse(target).ok()?;
        if resolved.origin() != self.origin
            || !resolved.username().is_empty()
            || resolved.password().is_some()
            || resolved.query().is_some()
            || resolved.fragment().is_some()
        {
            return None;
        }
        request_form_path(resolved.path())
    }
}

/// Apply `f` to every id; `None` becomes the non-matching value, so a rule
/// never gains a match from a target that was refused.
fn map_ids(ids: &Option<IdOrIds>, mut f: impl FnMut(&str) -> Option<String>) -> Option<IdOrIds> {
    ids.as_ref()?;
    let mapped: Vec<String> = get_ids(ids)
        .into_iter()
        .map(|id| f(id).unwrap_or_else(|| NEVER.to_string()))
        .collect();
    Some(ids_of(mapped))
}

/// Absolute `agent` unchanged; a relative one resolved against the ACL URL.
fn resolve_agent(agent: &str, base: Option<&url::Url>) -> String {
    if url::Url::parse(agent).is_ok() {
        return agent.to_string();
    }
    match base {
        Some(base) => base
            .join(agent)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| agent.to_string()),
        None => agent.to_string(),
    }
}

/// The path of a resolved target in the spelling requests use (the
/// percent-encoded request target), or `None` when it contains an encoded
/// separator, NUL or control byte: those would name a different resource once
/// decoded, so no rule may rest on them.
fn request_form_path(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return None;
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let v = u8::from_str_radix(path.get(i + 1..i + 3)?, 16).ok()?;
            if matches!(v, 0..=0x1f | 0x7f) {
                return None;
            }
            i += 3;
        } else {
            if bytes[i] <= 0x1f || bytes[i] == 0x7f || bytes[i] == b'\\' {
                return None;
            }
            i += 1;
        }
    }
    Some(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wac::{evaluate_access, parse_turtle_acl, AccessMode};

    const BASE: &str = "https://pod.example";

    fn doc(turtle: &str) -> AclDocument {
        parse_turtle_acl(&format!(
            "@prefix acl: <http://www.w3.org/ns/auth/acl#> .\n\
             @prefix foaf: <http://xmlns.com/foaf/0.1/> .\n{turtle}"
        ))
        .unwrap()
    }

    fn grants(base: Option<&AclBase>, acl_key: &str, turtle: &str, who: &str, path: &str) -> bool {
        let d = doc(turtle);
        let d = match base {
            Some(b) => b.resolve_document(&d, acl_key),
            None => d,
        };
        evaluate_access(Some(&d), Some(who), path, AccessMode::Read, None)
    }

    fn rule(target: &str, agent: &str) -> String {
        format!(
            "<#r> a acl:Authorization ; acl:agent <{agent}> ; acl:accessTo <{target}> ; \
             acl:default <{target}> ; acl:mode acl:Read ."
        )
    }

    const ME: &str = "https://alice.example/card#me";

    #[test]
    fn absolute_targets_on_the_configured_origin_match() {
        let b = AclBase::new(BASE).unwrap();
        for target in [
            "https://pod.example/a/",
            "https://pod.example:443/a/",
            "https://POD.EXAMPLE/a/",
            "https://pod.example/a",
        ] {
            assert!(
                grants(Some(&b), "/a.acl", &rule(target, ME), ME, "/a/x"),
                "{target}"
            );
        }
    }

    #[test]
    fn relative_targets_resolve_against_the_acl_document() {
        let b = AclBase::new(BASE).unwrap();
        assert!(grants(Some(&b), "/a/b.acl", &rule("./b", ME), ME, "/a/b"));
        assert!(grants(Some(&b), "/a/b.acl", &rule("b", ME), ME, "/a/b"));
        assert!(grants(Some(&b), "/a/c/d.acl", &rule("../", ME), ME, "/a/x"));
        // Resolved against the ACL, not against the root.
        assert!(!grants(Some(&b), "/a/b.acl", &rule("./c", ME), ME, "/c"));
    }

    #[test]
    fn another_origin_never_grants() {
        let b = AclBase::new(BASE).unwrap();
        for target in [
            // Another host, a look-alike host, a suffix and a userinfo trick.
            "https://other.example/a/",
            "https://pod.example.evil.example/a/",
            "https://evil.example/pod.example/a/",
            "https://pod.example@evil.example/a/",
            "https://xpod.example/a/",
            "https://pod.example.:8443/a/",
            // Another port, another scheme.
            "https://pod.example:8443/a/",
            "http://pod.example/a/",
            "https://pod.example:80/a/",
            // Network-path reference to another host.
            "//evil.example/a/",
            // Userinfo, query and fragment name a different resource.
            "https://user@pod.example/a/",
            "https://pod.example/a/?x=1",
            "https://pod.example/a/#frag",
            // Encoded separators and dot segments cannot reshape the path.
            "https://pod.example/a%2Fb/",
            "https://pod.example/a%5Cb/",
            "https://pod.example/a%00/",
        ] {
            for path in ["/a/x", "/a/", "/x", "/a%2Fb/x"] {
                assert!(
                    !grants(Some(&b), "/a.acl", &rule(target, ME), ME, path),
                    "{target} must not grant {path}"
                );
            }
        }
    }

    #[test]
    fn case_trailing_slash_and_default_port_follow_the_path_rules() {
        let b = AclBase::new(BASE).unwrap();
        // The path is case-sensitive.
        assert!(!grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/A/", ME),
            ME,
            "/a/x"
        ));
        // A trailing slash on the target does not change what it covers.
        assert!(grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/a", ME),
            ME,
            "/a/x"
        ));
        assert!(grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/a/", ME),
            ME,
            "/a/x"
        ));
        // A sibling that shares a prefix is not covered.
        assert!(!grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/a/", ME),
            ME,
            "/ab/x"
        ));
    }

    #[test]
    fn percent_encoding_is_compared_in_the_request_spelling() {
        let b = AclBase::new(BASE).unwrap();
        assert!(grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/my%20dir/", ME),
            ME,
            "/my%20dir/x"
        ));
        assert!(grants(
            Some(&b),
            "/a.acl",
            &rule("https://pod.example/my dir/", ME),
            ME,
            "/my%20dir/x"
        ));
        // `%2e%2e` is a dot segment: normalised away, never traversed.
        assert!(!grants(
            Some(&b),
            "/a/b.acl",
            &rule("https://pod.example/a/%2e%2e/secret/", ME),
            ME,
            "/a/x"
        ));
    }

    #[test]
    fn without_a_configured_origin_absolute_targets_still_deny() {
        for target in ["https://pod.example/a/", "./b", "b"] {
            assert!(
                !grants(None, "/a.acl", &rule(target, ME), ME, "/a/x"),
                "{target}"
            );
        }
        // Today's accepted form is unchanged.
        assert!(grants(None, "/a.acl", &rule("/a/", ME), ME, "/a/x"));
    }

    #[test]
    fn an_unusable_base_url_is_no_base() {
        for bad in [
            "",
            "pod.example",
            "https://",
            "https://pod.example/sub/",
            "https://u:p@pod.example",
            "https://pod.example/?q",
            "file:///srv/pod",
            "javascript:alert(1)",
        ] {
            assert!(AclBase::new(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn relative_agents_resolve_against_the_acl_document() {
        let b = AclBase::new(BASE).unwrap();
        let who = "https://pod.example/alice/profile/card#me";
        // ACL at /alice/b.acl, agent `profile/card#me`.
        assert!(grants(
            Some(&b),
            "/alice/b.acl",
            &rule("/alice/b", "profile/card#me"),
            who,
            "/alice/b"
        ));
        assert!(grants(
            Some(&b),
            "/alice/b.acl",
            &rule("/alice/b", "../alice/profile/card#me"),
            who,
            "/alice/b"
        ));
        // A relative agent is not another origin's WebID.
        assert!(!grants(
            Some(&b),
            "/alice/b.acl",
            &rule("/alice/b", "profile/card#me"),
            "https://evil.example/alice/profile/card#me",
            "/alice/b"
        ));
        // Absolute agents, did:nostr and class IRIs are untouched.
        assert!(grants(
            Some(&b),
            "/alice/b.acl",
            &rule("/alice/b", "did:nostr:abc"),
            "did:nostr:abc",
            "/alice/b"
        ));
        // Unresolved, the relative form matches nothing.
        assert!(!grants(
            None,
            "/alice/b.acl",
            &rule("/alice/b", "profile/card#me"),
            who,
            "/alice/b"
        ));
    }

    #[test]
    fn root_relative_paths_are_unchanged_and_network_paths_are_not_paths() {
        let b = AclBase::new(BASE).unwrap();
        assert!(grants(Some(&b), "/a.acl", &rule("/a/", ME), ME, "/a/x"));
        assert!(!grants(
            Some(&b),
            "/a.acl",
            &rule("//pod.example.evil/a/", ME),
            ME,
            "/a/x"
        ));
    }
}
