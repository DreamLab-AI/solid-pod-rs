//! Linked Data Platform (LDP) resource and container semantics.

use async_trait::async_trait;
use serde::Serialize;

use crate::error::PodError;
use crate::storage::Storage;

pub mod iri {
    pub const LDP_RESOURCE: &str = "http://www.w3.org/ns/ldp#Resource";
    pub const LDP_CONTAINER: &str = "http://www.w3.org/ns/ldp#Container";
    pub const LDP_BASIC_CONTAINER: &str = "http://www.w3.org/ns/ldp#BasicContainer";
    pub const LDP_NS: &str = "http://www.w3.org/ns/ldp#";
    pub const DCTERMS_NS: &str = "http://purl.org/dc/terms/";
}

/// Return whether a path addresses an LDP container.
pub fn is_container(path: &str) -> bool {
    path == "/" || path.ends_with('/')
}

/// Return whether a path addresses an ACL sidecar.
pub fn is_acl_path(path: &str) -> bool {
    path.ends_with(".acl")
}

/// Build a vector of `Link` header values for a resource or
/// container.
pub fn link_headers(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    if is_container(path) {
        out.push(format!("<{}>; rel=\"type\"", iri::LDP_BASIC_CONTAINER));
        out.push(format!("<{}>; rel=\"type\"", iri::LDP_CONTAINER));
        out.push(format!("<{}>; rel=\"type\"", iri::LDP_RESOURCE));
    } else {
        out.push(format!("<{}>; rel=\"type\"", iri::LDP_RESOURCE));
    }
    if !is_acl_path(path) {
        let acl_target = format!("{path}.acl");
        out.push(format!("<{acl_target}>; rel=\"acl\""));
    }
    out
}

/// Resolve the target path when POSTing to a container.
pub fn resolve_slug(container: &str, slug: Option<&str>) -> String {
    let name = slug
        .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains(".."))
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if container.ends_with('/') {
        format!("{container}{name}")
    } else {
        format!("{container}/{name}")
    }
}

#[derive(Debug, Serialize)]
pub struct ContainerMember {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@type")]
    pub types: Vec<&'static str>,
}

/// Render a container as a JSON-LD document given a list of member
/// relative paths as produced by `Storage::list`.
pub fn render_container(container_path: &str, members: &[String]) -> serde_json::Value {
    let base = if container_path.ends_with('/') {
        container_path.to_string()
    } else {
        format!("{container_path}/")
    };
    let contains: Vec<ContainerMember> = members
        .iter()
        .map(|m| {
            let is_dir = m.ends_with('/');
            ContainerMember {
                id: format!("{base}{m}"),
                types: if is_dir {
                    vec![iri::LDP_BASIC_CONTAINER, iri::LDP_CONTAINER, iri::LDP_RESOURCE]
                } else {
                    vec![iri::LDP_RESOURCE]
                },
            }
        })
        .collect();
    serde_json::json!({
        "@context": {
            "ldp": iri::LDP_NS,
            "dcterms": iri::DCTERMS_NS,
            "contains": { "@id": "ldp:contains", "@type": "@id" },
        },
        "@id": container_path,
        "@type": [ "ldp:Container", "ldp:BasicContainer", "ldp:Resource" ],
        "ldp:contains": contains,
    })
}

#[async_trait]
pub trait LdpContainerOps: Storage {
    async fn container_representation(
        &self,
        path: &str,
    ) -> Result<serde_json::Value, PodError> {
        let children = self.list(path).await?;
        Ok(render_container(path, &children))
    }
}

impl<T: Storage + ?Sized> LdpContainerOps for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_container_detects_trailing_slash() {
        assert!(is_container("/"));
        assert!(is_container("/media/"));
        assert!(!is_container("/file.txt"));
    }

    #[test]
    fn link_headers_include_acl_ref() {
        let hdrs = link_headers("/profile/card");
        assert!(hdrs.iter().any(|h| h.contains("rel=\"type\"")));
        assert!(hdrs.iter().any(|h| h.contains("rel=\"acl\"")));
        assert!(hdrs.iter().any(|h| h.contains("/profile/card.acl")));
    }

    #[test]
    fn link_headers_skip_acl_on_acl() {
        let hdrs = link_headers("/profile/card.acl");
        assert!(!hdrs.iter().any(|h| h.contains("rel=\"acl\"")));
    }

    #[test]
    fn link_headers_container_lists_all_types() {
        let hdrs = link_headers("/");
        let joined = hdrs.join(",");
        assert!(joined.contains("BasicContainer"));
        assert!(joined.contains("Container"));
        assert!(joined.contains("Resource"));
    }

    #[test]
    fn slug_uses_valid_value() {
        let out = resolve_slug("/photos/", Some("cat.jpg"));
        assert_eq!(out, "/photos/cat.jpg");
    }

    #[test]
    fn slug_rejects_slashes() {
        let out = resolve_slug("/photos/", Some("a/b"));
        assert!(!out.contains("a/b"));
    }

    #[test]
    fn render_container_shapes_jsonld() {
        let members = vec!["one.txt".to_string(), "sub/".to_string()];
        let v = render_container("/docs/", &members);
        assert!(v.get("@context").is_some());
        assert!(v.get("ldp:contains").unwrap().as_array().unwrap().len() == 2);
    }
}
