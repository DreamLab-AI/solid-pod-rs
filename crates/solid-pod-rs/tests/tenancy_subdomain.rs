//! Sprint 7 — multi-tenancy pod resolution (JSS parity
//! `src/utils/url.js::urlToPathWithPod`).

use solid_pod_rs::multitenant::{PathResolver, PodResolver, ResolvedPath, SubdomainResolver};

#[test]
fn path_resolver_passes_through() {
    let r = PathResolver;
    let out = r.resolve("example.org", "/foo/bar");
    assert_eq!(
        out,
        ResolvedPath {
            pod: None,
            storage_path: "/foo/bar".into()
        }
    );
}

#[test]
fn subdomain_resolver_maps_alice_example_org() {
    let r = SubdomainResolver {
        base_domain: "example.org".into(),
    };
    let out = r.resolve("alice.example.org", "/public/file.txt");
    assert_eq!(
        out,
        ResolvedPath {
            pod: Some("alice".into()),
            storage_path: "/public/file.txt".into()
        }
    );
}

#[test]
fn subdomain_resolver_root_when_host_equals_base() {
    let r = SubdomainResolver {
        base_domain: "example.org".into(),
    };
    let out = r.resolve("example.org", "/shared/readme");
    assert_eq!(
        out,
        ResolvedPath {
            pod: None,
            storage_path: "/shared/readme".into()
        }
    );
}

#[test]
fn subdomain_resolver_rejects_dotdot_in_pod() {
    let r = SubdomainResolver {
        base_domain: "example.org".into(),
    };
    // A pod label containing `..` (after percent-decoding style noise)
    // must be scrubbed. JSS double-pass: `..a..` → remove → `a` → safe.
    // We still accept the request but strip the `..` sequences.
    let out = r.resolve("al..ice.example.org", "/foo");
    // `..` scrubbed → "alice" is the safe pod; storage_path untouched.
    assert_eq!(out.pod.as_deref(), Some("alice"));
    assert_eq!(out.storage_path, "/foo");
}

#[test]
fn subdomain_resolver_strips_port() {
    let r = SubdomainResolver {
        base_domain: "example.org".into(),
    };
    let out = r.resolve("alice.example.org:8443", "/foo");
    assert_eq!(out.pod.as_deref(), Some("alice"));

    let out2 = r.resolve("example.org:8443", "/foo");
    assert_eq!(out2.pod, None);
}

/// Policy choice: unknown subdomain (host not under base_domain) falls
/// back to **path-based** semantics — pod=None, storage_path verbatim.
/// This mirrors JSS's `subdomainsEnabled && podName` check: when the
/// subdomain can't be resolved to a pod, we degrade to path mode rather
/// than reject, so clients hitting `other.test` instead of
/// `other.example.org` still get a useful 404 from LDP, not a 400
/// rejection here.
#[test]
fn subdomain_resolver_unknown_subdomain_falls_back_to_path() {
    let r = SubdomainResolver {
        base_domain: "example.org".into(),
    };
    let out = r.resolve("foo.other.test", "/bar");
    assert_eq!(out.pod, None);
    assert_eq!(out.storage_path, "/bar");
}
