//! ACL resolver — locates the effective ACL document for a given path.
//!
//! `find_effective_acl` walks the storage tree from the resource path
//! up to the root, returning the first `*.acl` sibling that parses as
//! JSON-LD or Turtle.

use async_trait::async_trait;

use crate::error::PodError;
use crate::storage::Storage;
use crate::wac::document::AclDocument;
use crate::wac::parse_jsonld_acl;
use crate::wac::parser::parse_turtle_acl;

/// Resolves the effective ACL document for a resource using the WAC walk-up-the-tree algorithm.
///
/// Starting at the resource path, the resolver looks for an `.acl` sidecar at each ancestor
/// container up to the root. The first parseable ACL document found (JSON-LD or Turtle) is
/// returned. If no ACL is found at any level, returns `Ok(None)` -- callers must deny access
/// when no ACL exists (deny-by-default).
#[async_trait]
pub trait AclResolver: Send + Sync {
    /// Locate the nearest ACL document that governs `resource_path`.
    async fn find_effective_acl(
        &self,
        resource_path: &str,
    ) -> Result<Option<AclDocument>, PodError>;
}

/// `AclResolver` backed by a [`Storage`] implementation.
pub struct StorageAclResolver<S: Storage> {
    storage: std::sync::Arc<S>,
}

impl<S: Storage> StorageAclResolver<S> {
    /// Wrap a shared storage handle in a resolver.
    pub fn new(storage: std::sync::Arc<S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S: Storage> AclResolver for StorageAclResolver<S> {
    /// Walk from `resource_path` toward `/`, returning the first valid `.acl` sidecar found.
    async fn find_effective_acl(
        &self,
        resource_path: &str,
    ) -> Result<Option<AclDocument>, PodError> {
        let mut path = resource_path.to_string();
        loop {
            let acl_key = if path == "/" {
                "/.acl".to_string()
            } else {
                format!("{}.acl", path.trim_end_matches('/'))
            };
            if let Ok((body, meta)) = self.storage.get(&acl_key).await {
                // JSON-LD first (with bounded parser). A body that
                // exceeds byte or depth caps returns BadRequest or
                // PayloadTooLarge and bubbles up so the caller can
                // reject with 400/413.
                match parse_jsonld_acl(&body) {
                    Ok(doc) => return Ok(Some(doc)),
                    Err(PodError::BadRequest(_)) => {
                        return Err(PodError::BadRequest(
                            "ACL document exceeds bounds".into(),
                        ));
                    }
                    Err(PodError::PayloadTooLarge(msg)) => {
                        return Err(PodError::PayloadTooLarge(msg));
                    }
                    Err(_) => {}
                }
                let ct = meta.content_type.to_ascii_lowercase();
                let looks_turtle = ct.starts_with("text/turtle")
                    || ct.starts_with("application/turtle")
                    || ct.starts_with("application/x-turtle");
                let text = std::str::from_utf8(&body).unwrap_or("");
                if looks_turtle || text.contains("@prefix") || text.contains("acl:Authorization") {
                    if let Ok(doc) = parse_turtle_acl(text) {
                        return Ok(Some(doc));
                    }
                }
            }
            if path == "/" || path.is_empty() {
                break;
            }
            let trimmed = path.trim_end_matches('/');
            path = match trimmed.rfind('/') {
                Some(0) => "/".to_string(),
                Some(pos) => trimmed[..pos].to_string(),
                None => "/".to_string(),
            };
        }
        Ok(None)
    }
}
