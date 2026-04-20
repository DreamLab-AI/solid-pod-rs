//! JSS parity: container-vs-resource branching in OPTIONS + 404 headers.
//!
//! * `Accept-Ranges: none` for containers, `bytes` for resources.
//! * `not_found_headers` must emit enough discovery headers to drive a
//!   PUT-to-create flow — containers advertise `Accept-Post`, resources
//!   do not. DELETE is NOT offered on a missing resource.
//! * `Vary` must include `Accept` when content negotiation is enabled.

use solid_pod_rs::ldp::{not_found_headers, options_for, vary_header};

#[test]
fn accept_ranges_container_is_none() {
    let o = options_for("/photos/");
    assert_eq!(o.accept_ranges, "none");
}

#[test]
fn accept_ranges_resource_is_bytes() {
    let o = options_for("/photos/cat.jpg");
    assert_eq!(o.accept_ranges, "bytes");
}

#[test]
fn not_found_headers_container_includes_accept_post() {
    let h = not_found_headers("/new-container/", true);
    let joined = format_headers(&h);
    assert!(joined.contains("Accept-Post"), "missing Accept-Post: {joined}");
    assert!(
        joined.contains("text/turtle"),
        "Accept-Post should include text/turtle: {joined}"
    );
}

#[test]
fn not_found_headers_resource_omits_accept_post() {
    let h = not_found_headers("/missing.txt", true);
    let joined = format_headers(&h);
    assert!(!joined.contains("Accept-Post"), "unexpected Accept-Post: {joined}");
}

#[test]
fn not_found_headers_include_allow_without_delete() {
    let h = not_found_headers("/missing.txt", true);
    let allow = h.iter().find(|(k, _)| *k == "Allow").map(|(_, v)| v.as_str()).unwrap();
    assert!(allow.contains("PUT"), "Allow missing PUT: {allow}");
    assert!(allow.contains("PATCH"), "Allow missing PATCH: {allow}");
    assert!(!allow.contains("DELETE"), "Allow must not advertise DELETE on 404: {allow}");
}

#[test]
fn not_found_headers_include_acl_link() {
    let h = not_found_headers("/missing.txt", true);
    let joined = format_headers(&h);
    assert!(
        joined.contains("/missing.txt.acl") && joined.contains("rel=\"acl\""),
        "missing ACL Link: {joined}"
    );
}

#[test]
fn vary_conneg_on_includes_accept() {
    let v = vary_header(true);
    assert!(v.contains("Accept"), "expected Accept in Vary: {v}");
    assert!(v.contains("Authorization"), "expected Authorization in Vary: {v}");
}

#[test]
fn vary_conneg_off_omits_accept() {
    let v = vary_header(false);
    assert!(!v.contains("Accept"), "expected no Accept in Vary: {v}");
    assert!(v.contains("Authorization"), "expected Authorization in Vary: {v}");
}

fn format_headers(h: &[(&'static str, String)]) -> String {
    let mut s = String::new();
    for (k, v) in h {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push('\n');
    }
    s
}
