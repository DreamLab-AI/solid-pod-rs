//! Sprint 12 security regression tests.
//!
//! Covers size-capped ACL parsing, dotfile enforcement, and path
//! traversal sanitization. These are integration tests exercising the
//! public API surface.

use std::path::PathBuf;

use solid_pod_rs::error::PodError;
use solid_pod_rs::security::dotfile::DotfilePathError;
use solid_pod_rs::wac::{parse_jsonld_acl_with_limits, parse_turtle_acl_with_limit, MAX_ACL_BYTES};
use solid_pod_rs::{is_path_allowed, DotfileAllowlist};

// =========================================================================
// Size-capped ACL parsing (row 169)
// =========================================================================

/// The default ACL byte limit is 1 MiB.
#[test]
fn acl_max_bytes_is_one_mib() {
    assert_eq!(MAX_ACL_BYTES, 1_048_576);
}

/// Oversized Turtle ACL (> limit) returns PayloadTooLarge.
#[test]
fn turtle_acl_oversized_returns_payload_too_large() {
    let oversized = " ".repeat(MAX_ACL_BYTES + 1);
    let result = parse_turtle_acl_with_limit(&oversized, MAX_ACL_BYTES);
    assert!(result.is_err());
    match result.unwrap_err() {
        PodError::PayloadTooLarge(msg) => {
            assert!(
                msg.contains("exceeds") || msg.contains("too large"),
                "error should mention size: {msg}"
            );
        }
        other => panic!("expected PayloadTooLarge, got: {other:?}"),
    }
}

/// Exactly-at-limit Turtle ACL passes the size check.
#[test]
fn turtle_acl_exactly_at_limit_passes() {
    // A string of exactly `limit` bytes. Not valid Turtle, but the parser
    // is forgiving and the size check passes first.
    let at_limit = "a".repeat(100);
    let result = parse_turtle_acl_with_limit(&at_limit, 100);
    assert!(
        result.is_ok(),
        "exactly at limit should not be rejected: {:?}",
        result.unwrap_err()
    );
}

/// One byte over the limit is rejected.
#[test]
fn turtle_acl_one_byte_over_limit_rejected() {
    let over_limit = "a".repeat(101);
    assert!(
        parse_turtle_acl_with_limit(&over_limit, 100).is_err(),
        "one byte over limit must be rejected"
    );
}

/// Oversized JSON-LD ACL (> limit) returns PayloadTooLarge.
#[test]
fn jsonld_acl_oversized_returns_payload_too_large() {
    let body = vec![b' '; MAX_ACL_BYTES + 1];
    let result = parse_jsonld_acl_with_limits(&body, MAX_ACL_BYTES, 32);
    assert!(result.is_err());
    match result.unwrap_err() {
        PodError::PayloadTooLarge(msg) => {
            assert!(
                msg.contains("exceeds") || msg.contains("too large"),
                "error should mention size: {msg}"
            );
        }
        other => panic!("expected PayloadTooLarge, got: {other:?}"),
    }
}

/// Valid small Turtle ACL parses correctly within limits.
#[test]
fn turtle_acl_valid_within_limits_parses() {
    let ttl = r#"
        @prefix acl: <http://www.w3.org/ns/auth/acl#> .
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .

        <#public> a acl:Authorization ;
            acl:agentClass foaf:Agent ;
            acl:accessTo </> ;
            acl:mode acl:Read .
    "#;
    let doc = parse_turtle_acl_with_limit(ttl, MAX_ACL_BYTES).unwrap();
    assert!(
        doc.graph.is_some(),
        "valid ACL should produce a non-empty graph"
    );
}

// =========================================================================
// Dotfile filter (row 172 — .account; row 115 — .env blocked)
// =========================================================================

/// Dotfile filter blocks `.env`.
#[test]
fn dotfile_filter_blocks_env() {
    let al = DotfileAllowlist::with_defaults();
    assert!(
        !al.is_allowed(&PathBuf::from("/.env")),
        ".env must be blocked by default allowlist"
    );
}

/// Dotfile filter allows `.account` (Sprint 12, JSS commit 32c0db2).
#[test]
fn dotfile_filter_allows_account() {
    let al = DotfileAllowlist::with_defaults();
    assert!(
        al.is_allowed(&PathBuf::from("/.account")),
        ".account must be allowed by default allowlist"
    );
}

/// Dotfile filter allows `.acl` and `.meta` (standard Solid sidecars).
#[test]
fn dotfile_filter_allows_solid_sidecars() {
    let al = DotfileAllowlist::with_defaults();
    assert!(al.is_allowed(&PathBuf::from("/.acl")));
    assert!(al.is_allowed(&PathBuf::from("/.meta")));
}

/// Free-function `is_path_allowed` blocks `.env`.
#[test]
fn free_function_blocks_env() {
    match is_path_allowed("/.env") {
        Err(DotfilePathError::NotAllowed { segment, .. }) => {
            assert_eq!(segment, ".env");
        }
        other => panic!("expected NotAllowed for /.env, got {other:?}"),
    }
}

/// Free-function `is_path_allowed` permits `.account`.
#[test]
fn free_function_allows_account() {
    assert!(
        is_path_allowed("/.account").is_ok(),
        ".account must pass the free-function check"
    );
    assert!(
        is_path_allowed("/.account/login").is_ok(),
        ".account subtree must pass"
    );
}

// =========================================================================
// Path traversal sanitization (row 170)
// =========================================================================

/// `..` traversal in paths is rejected by the dotfile primitive as
/// defence-in-depth, regardless of the allowlist.
#[test]
fn dotdot_traversal_rejected_by_dotfile_allowlist() {
    let al = DotfileAllowlist::with_defaults();
    assert!(
        !al.is_allowed(&PathBuf::from("foo/..")),
        "parent-dir traversal must be rejected"
    );
    assert!(
        !al.is_allowed(&PathBuf::from("foo/../../etc/passwd")),
        "double parent-dir traversal must be rejected"
    );
}

/// The `....//` bypass attempt (JSS commit 2569811) is handled: the
/// dotfile free-function detects `..` segments and rejects them.
#[test]
fn dotdot_bypass_attempt_rejected_by_free_function() {
    // The path `/pod/../etc/passwd` should be rejected because it contains
    // a `..` segment.
    match is_path_allowed("/pod/../etc/passwd") {
        Err(DotfilePathError::ParentTraversal(_)) => {}
        other => panic!("expected ParentTraversal for /pod/../etc/passwd, got {other:?}"),
    }
}

/// Nested dotfile segments are rejected even deep in the path.
#[test]
fn nested_hidden_file_blocked() {
    assert!(
        is_path_allowed("/a/b/.git/HEAD").is_err(),
        ".git nested deep in path must be blocked"
    );
    assert!(
        is_path_allowed("/pod/.ssh/id_rsa").is_err(),
        ".ssh must be blocked"
    );
}

/// Empty path and root path are always allowed.
#[test]
fn empty_and_root_paths_allowed() {
    assert!(is_path_allowed("").is_ok());
    assert!(is_path_allowed("/").is_ok());
}
