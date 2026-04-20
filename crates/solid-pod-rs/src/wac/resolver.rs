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

#[async_trait]
pub trait AclResolver: Send + Sync {
    async fn find_effective_acl(
        &self,
        resource_path: &str,
    ) -> Result<Option<AclDocument>, PodError>;
}

pub struct StorageAclResolver<S: Storage> {
    storage: std::sync::Arc<S>,
}

impl<S: Storage> StorageAclResolver<S> {
    pub fn new(storage: std::sync::Arc<S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S: Storage> AclResolver for StorageAclResolver<S> {
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
                // exceeds byte or depth caps returns BadRequest and
                // bubbles up so the caller can reject with 400.
                match parse_jsonld_acl(&body) {
                    Ok(doc) => return Ok(Some(doc)),
                    Err(PodError::BadRequest(_)) => {
                        return Err(PodError::BadRequest(
                            "ACL document exceeds bounds".into(),
                        ));
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
