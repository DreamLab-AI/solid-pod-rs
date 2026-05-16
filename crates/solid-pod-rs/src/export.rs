//! Pod data export — JSON-LD time-chain bundle for agent-friendly
//! archival, attestation, and migration.
//!
//! Tracks JSS v0.0.190 (May 2026, issue #437):
//!
//! - HTTP surface: `GET /api/exports/all`.
//! - Body: a single JSON-LD document — an ordered list of every pod
//!   resource (LDP-resource + `*.acl` + container metadata) serialised
//!   alongside its representation, sorted ascending by the resource's
//!   server-managed timestamp. The ordering is what makes it a
//!   "time-chain" — replay-friendly for downstream archives.
//! - Default exclusion: `/private/*` is omitted from the bundle.
//! - Opt-in inclusion: `?include_private=true` adds the private
//!   container but requires the caller to present an owner WAC
//!   credential. The handler is responsible for verifying the
//!   credential before flipping [`ExportOptions::include_private`];
//!   this module just reflects the option.
//!
//! Parity row **198**. Smoke test:
//! [`tests/export_jsonld_smoke.rs`](../../tests/export_jsonld_smoke.rs).
//!
//! ## Type contract (stable)
//!
//! [`PodExportBundle`], [`PodExportEntry`], and [`ExportOptions`] are
//! the wire formats consumed by NRF and dreamlab-overlay; treat their
//! field shapes as ABI.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PodError;
use crate::storage::Storage;

/// JSON-LD `@context` URI emitted on every export bundle.
pub const EXPORT_JSONLD_CONTEXT: &str = "https://solid-pod-rs.dev/ns/export/v1";

/// MIME type written into the `Content-Type` response header by the
/// server route.
pub const EXPORT_CONTENT_TYPE: &str = "application/ld+json";

/// Default-skipped container prefix. `/private/*` is excluded from the
/// bundle unless [`ExportOptions::include_private`] is `true`.
pub const PRIVATE_CONTAINER_PREFIX: &str = "/private/";

/// One resource in a pod export bundle.
///
/// Carries the resource's path, its representation (raw bytes,
/// base64-encoded for binary safety), and the server-managed
/// timestamps that drive the time-chain ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodExportEntry {
    /// Storage-relative path (e.g. `/profile/card`).
    pub path: String,
    /// Resource content type as recorded in `ResourceMeta`.
    pub content_type: String,
    /// Strong ETag (hex SHA-256) of the representation at export time.
    pub etag: String,
    /// `dct:created` timestamp. Backends that don't track creation
    /// separately mirror `modified` into this field — first-write
    /// equals creation.
    pub created: DateTime<Utc>,
    /// `dct:modified` timestamp (server-managed).
    pub modified: DateTime<Utc>,
    /// Resource representation, base64-encoded (standard alphabet,
    /// with padding) for binary-safe inclusion in JSON.
    pub body_base64: String,
}

/// Top-level pod export bundle. Serialises to JSON-LD per
/// [`EXPORT_JSONLD_CONTEXT`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodExportBundle {
    /// JSON-LD `@context` — emitted as a string URL.
    #[serde(rename = "@context")]
    pub context: String,
    /// Pod root URL (e.g. `https://pod.example.com/alice/`).
    pub pod_base: String,
    /// Timestamp when the bundle was generated.
    pub generated_at: DateTime<Utc>,
    /// Whether `/private/*` was included. Drives the `dct:audience`
    /// gate on the receiving side.
    pub includes_private: bool,
    /// Ordered ascending by `created`.
    pub entries: Vec<PodExportEntry>,
}

/// Options controlling export behaviour.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExportOptions {
    /// Caller has presented an owner WAC credential — include
    /// `/private/*` in the bundle. The route layer is responsible for
    /// verifying the credential before flipping this flag; the
    /// function itself is unauthenticated.
    #[serde(default)]
    pub include_private: bool,
}

// ---------------------------------------------------------------------------
// Recursive container walker.
//
// The Storage trait exposes `list(container)` which returns paths
// relative to the container, with trailing `/` for sub-containers. We
// walk depth-first and collect absolute paths.
//
// To keep the recursion friendly to async drop and to stay clippy-clean
// on `clippy::async_recursion`, the walker uses an explicit stack
// instead of recursive calls.
// ---------------------------------------------------------------------------

fn join(parent: &str, child: &str) -> String {
    let mut joined = String::with_capacity(parent.len() + child.len() + 1);
    joined.push_str(parent);
    if !parent.ends_with('/') {
        joined.push('/');
    }
    joined.push_str(child);
    joined
}

async fn walk_resources<S: Storage + ?Sized>(
    storage: &S,
    include_private: bool,
) -> Result<Vec<String>, PodError> {
    let mut stack: Vec<String> = vec!["/".to_string()];
    let mut resources: Vec<String> = Vec::new();

    while let Some(container) = stack.pop() {
        // Skip the private container subtree unless the caller has
        // opted in (with credential already verified upstream).
        if !include_private && container.starts_with(PRIVATE_CONTAINER_PREFIX) {
            continue;
        }
        let children = match storage.list(&container).await {
            Ok(v) => v,
            Err(PodError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        for child in children {
            let abs = join(&container, &child);
            if !include_private && abs.starts_with(PRIVATE_CONTAINER_PREFIX) {
                continue;
            }
            if abs.ends_with('/') {
                stack.push(abs);
            } else {
                resources.push(abs);
            }
        }
    }

    Ok(resources)
}

/// Build a [`PodExportBundle`] by walking the pod's storage tree.
///
/// JSS v0.0.190 Phase 1 (issue #437) parity row 198.
///
/// # Parameters
///
/// - `storage`: backend over which to walk the pod tree. Any
///   [`Storage`] implementation works (FS, S3, memory).
/// - `pod_base`: pod root URL stamped into the bundle envelope.
/// - `options`: callsite-controlled inclusion toggles.
///
/// # Ordering
///
/// `entries` is sorted ascending by `created`. Backends that don't
/// distinguish create- from modify-time mirror `modified` into the
/// `created` slot, so the ordering is stable as `modified` ascending
/// in that case.
///
/// # Errors
///
/// Returns [`PodError`] on storage errors. Resources whose
/// representation cannot be read are propagated; the caller decides
/// whether to retry.
pub async fn export_pod_jsonld<S: Storage + ?Sized>(
    storage: &S,
    pod_base: &str,
    options: ExportOptions,
) -> Result<PodExportBundle, PodError> {
    let paths = walk_resources(storage, options.include_private).await?;

    let mut entries: Vec<PodExportEntry> = Vec::with_capacity(paths.len());
    for path in paths {
        let (body, meta) = match storage.get(&path).await {
            Ok(v) => v,
            // Race condition: resource deleted between list and get.
            // Skip rather than abort the whole bundle.
            Err(PodError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        entries.push(PodExportEntry {
            path,
            content_type: meta.content_type,
            etag: meta.etag,
            // Backends don't track `created` separately from
            // `modified` (the Storage trait only exposes `modified`),
            // so we mirror it. First-write timestamp == creation.
            created: meta.modified,
            modified: meta.modified,
            body_base64: BASE64_STANDARD.encode(&body),
        });
    }

    // Time-chain ordering: ascending by `created`. Stable sort keeps
    // ties (same timestamp) in walker-discovery order, which is
    // deterministic across runs for a given storage backend.
    entries.sort_by(|a, b| a.created.cmp(&b.created));

    Ok(PodExportBundle {
        context: EXPORT_JSONLD_CONTEXT.to_string(),
        pod_base: pod_base.to_string(),
        generated_at: Utc::now(),
        includes_private: options.include_private,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_handles_trailing_slash() {
        assert_eq!(join("/", "foo"), "/foo");
        assert_eq!(join("/dir/", "foo"), "/dir/foo");
        assert_eq!(join("/dir", "foo"), "/dir/foo");
        assert_eq!(join("/dir/", "sub/"), "/dir/sub/");
    }
}
