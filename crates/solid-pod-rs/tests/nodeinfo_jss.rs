//! NodeInfo 2.1 JSS parity tests (Sprint 7 C).
//!
//! Validates the two helper functions that produce the response bodies
//! for `/.well-known/nodeinfo` (discovery) and
//! `/.well-known/nodeinfo/2.1` (content doc), per
//! https://nodeinfo.diaspora.software/protocol.html. JSS exposes the
//! same pair under the same paths — we keep the shapes byte-compatible
//! so the notifications/ActivityPub tooling can consume either server
//! interchangeably.

use solid_pod_rs::interop::{nodeinfo_2_1, nodeinfo_discovery};

#[test]
fn nodeinfo_discovery_emits_link_to_2_1() {
    let doc = nodeinfo_discovery("https://pod.example");
    let links = doc.get("links").and_then(|v| v.as_array()).unwrap();
    assert_eq!(links.len(), 1, "discovery must carry exactly one link: {doc}");
    let first = &links[0];
    assert_eq!(
        first.get("rel").and_then(|v| v.as_str()),
        Some("http://nodeinfo.diaspora.software/ns/schema/2.1"),
    );
    assert_eq!(
        first.get("href").and_then(|v| v.as_str()),
        Some("https://pod.example/.well-known/nodeinfo/2.1"),
    );
}

#[test]
fn nodeinfo_discovery_strips_trailing_slash() {
    // Trailing slash on the base URL must not double up in href.
    let doc = nodeinfo_discovery("https://pod.example/");
    let href = doc
        .pointer("/links/0/href")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(href, "https://pod.example/.well-known/nodeinfo/2.1");
    assert!(!href.contains("//.well-known"), "double slash in href: {href}");
}

#[test]
fn nodeinfo_2_1_advertises_solid_protocol() {
    let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", false, 0);
    let protocols = doc.get("protocols").and_then(|v| v.as_array()).unwrap();
    assert!(
        protocols.iter().any(|v| v.as_str() == Some("solid")),
        "protocols must advertise solid: {doc}",
    );
}

#[test]
fn nodeinfo_2_1_advertises_activitypub_protocol() {
    // Forward-compat guarantee for the ActivityPub crate — the doc
    // already claims the protocol before the implementation lands so
    // clients can discover the endpoint once mounted.
    let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", false, 0);
    let protocols = doc.get("protocols").and_then(|v| v.as_array()).unwrap();
    assert!(
        protocols.iter().any(|v| v.as_str() == Some("activitypub")),
        "protocols must advertise activitypub: {doc}",
    );
}

#[test]
fn nodeinfo_2_1_software_name_and_version_round_trip() {
    let doc = nodeinfo_2_1("my-pod", "9.9.9", false, 0);
    assert_eq!(
        doc.pointer("/software/name").and_then(|v| v.as_str()),
        Some("my-pod"),
    );
    assert_eq!(
        doc.pointer("/software/version").and_then(|v| v.as_str()),
        Some("9.9.9"),
    );
}

#[test]
fn nodeinfo_2_1_user_count_in_usage() {
    let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", true, 42);
    assert_eq!(
        doc.pointer("/usage/users/total").and_then(|v| v.as_u64()),
        Some(42),
    );
}

#[test]
fn nodeinfo_2_1_open_registrations_flag_round_trips() {
    // Both boolean states must serialise verbatim.
    let open = nodeinfo_2_1("solid-pod-rs", "0.4.0", true, 0);
    assert_eq!(
        open.get("openRegistrations").and_then(|v| v.as_bool()),
        Some(true),
    );
    let closed = nodeinfo_2_1("solid-pod-rs", "0.4.0", false, 0);
    assert_eq!(
        closed.get("openRegistrations").and_then(|v| v.as_bool()),
        Some(false),
    );
}
