//! Fediverse discovery: NodeInfo 2.1 + WebFinger passthrough.
//!
//! JSS parity: mirrors `src/ap/index.js` lines 129-166 for the two
//! `/.well-known/nodeinfo` routes.
//!
//! WebFinger is intentionally a thin re-export of
//! `solid_pod_rs::interop::webfinger_response` — the core crate
//! already emits the JRD shape required for both Solid-OIDC and
//! ActivityPub discovery.

pub use solid_pod_rs::interop::{webfinger_response, WebFingerJrd, WebFingerLink};

use serde_json::json;

/// Render the `/.well-known/nodeinfo` pointer document — a NodeInfo
/// discovery index that advertises the 2.1 endpoint.
pub fn nodeinfo_wellknown(base_url: &str) -> serde_json::Value {
    let base = base_url.trim_end_matches('/');
    json!({
        "links": [
            {
                "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                "href": format!("{base}/.well-known/nodeinfo/2.1")
            }
        ]
    })
}

/// Render the NodeInfo 2.1 body. `user_count` should be the number of
/// local pod accounts; `local_posts` is the outbox size.
///
/// Reference: <http://nodeinfo.diaspora.software/ns/schema/2.1>
pub fn nodeinfo_2_1(
    software_name: &str,
    software_version: &str,
    user_count: u64,
    local_posts: u64,
) -> serde_json::Value {
    json!({
        "version": "2.1",
        "software": {
            "name": software_name,
            "version": software_version,
            "repository": "https://github.com/dreamlab-ai/solid-pod-rs"
        },
        "protocols": ["activitypub", "solid"],
        "services": {"inbound": [], "outbound": []},
        "usage": {
            "users": {
                "total": user_count,
                "activeMonth": user_count,
                "activeHalfyear": user_count
            },
            "localPosts": local_posts
        },
        "openRegistrations": true,
        "metadata": {
            "nodeName": "solid-pod-rs",
            "nodeDescription": "SAND Stack: Solid + ActivityPub + Nostr + DID"
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodeinfo_wellknown_points_to_2_1() {
        let doc = nodeinfo_wellknown("https://pod.example");
        let links = doc["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(
            links[0]["rel"],
            "http://nodeinfo.diaspora.software/ns/schema/2.1"
        );
        assert_eq!(
            links[0]["href"],
            "https://pod.example/.well-known/nodeinfo/2.1"
        );
    }

    #[test]
    fn nodeinfo_wellknown_trims_trailing_slash() {
        let a = nodeinfo_wellknown("https://pod.example/");
        let b = nodeinfo_wellknown("https://pod.example");
        assert_eq!(a, b);
    }

    #[test]
    fn nodeinfo_2_1_body_matches_spec() {
        let doc = nodeinfo_2_1("solid-pod-rs", "0.4.0", 1, 42);
        assert_eq!(doc["version"], "2.1");
        assert_eq!(doc["software"]["name"], "solid-pod-rs");
        assert_eq!(doc["software"]["version"], "0.4.0");
        let protocols = doc["protocols"].as_array().unwrap();
        let protocol_strs: Vec<&str> =
            protocols.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(protocol_strs.contains(&"activitypub"));
        assert!(protocol_strs.contains(&"solid"));
        assert_eq!(doc["usage"]["users"]["total"], 1);
        assert_eq!(doc["usage"]["localPosts"], 42);
        assert!(doc["services"].get("inbound").is_some());
        assert!(doc["services"].get("outbound").is_some());
    }

    #[test]
    fn webfinger_reexport_is_callable() {
        let j = webfinger_response(
            "acct:alice@pod.example",
            "https://pod.example",
            "https://pod.example/profile/card#me",
        )
        .unwrap();
        assert_eq!(j.subject, "acct:alice@pod.example");
    }
}
