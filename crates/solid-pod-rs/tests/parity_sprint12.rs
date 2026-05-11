//! Sprint 12 parity verification — type-level feature existence tests.
//!
//! Each test confirms that a Sprint 12 deliverable exists and is
//! accessible through the public API. These are compile-time + runtime
//! shape checks, not behavioural integration tests.
//!
//! Tests for sibling-crate features (IDP `validate_password_length`,
//! AP `negotiate_actor_format` / `handle_outbox_post`) live in their
//! respective crate test directories:
//!   - `crates/solid-pod-rs-idp/tests/sprint12_password.rs`
//!   - `crates/solid-pod-rs-activitypub/tests/sprint12_ap_features.rs`

use solid_pod_rs::error::PodError;
use solid_pod_rs::security::dotfile::DEFAULT_ALLOWED;
use solid_pod_rs::wac::{parse_turtle_acl_with_limit, MAX_ACL_BYTES};
use solid_pod_rs::{is_path_allowed, DotfileAllowlist};

// =========================================================================
// PodError::PayloadTooLarge variant exists (row 169)
// =========================================================================

#[test]
fn pod_error_payload_too_large_variant_exists() {
    let err = PodError::PayloadTooLarge("test".into());
    let msg = err.to_string();
    assert!(
        msg.contains("payload too large"),
        "PayloadTooLarge Display should contain 'payload too large', got: {msg}"
    );
}

// =========================================================================
// parse_turtle_acl_with_limit exists and rejects oversized input (row 169)
// =========================================================================

#[test]
fn parse_turtle_acl_with_limit_exists_and_rejects_oversized() {
    let big = "x".repeat(200);
    let result = parse_turtle_acl_with_limit(&big, 100);
    assert!(result.is_err(), "oversized input must be rejected");
    let err = result.unwrap_err();
    match &err {
        PodError::PayloadTooLarge(msg) => {
            assert!(
                msg.contains("100"),
                "error message should mention the limit: {msg}"
            );
        }
        other => panic!("expected PayloadTooLarge, got: {other:?}"),
    }
}

// =========================================================================
// DotfileAllowlist::with_defaults() includes .account (row 172)
// =========================================================================

#[test]
fn dotfile_allowlist_with_defaults_includes_account() {
    let al = DotfileAllowlist::with_defaults();
    let entries = al.entries();
    assert!(
        entries.iter().any(|e| e == ".account"),
        "with_defaults() must include .account, got: {entries:?}"
    );
}

#[test]
fn default_allowed_constant_includes_account() {
    assert!(
        DEFAULT_ALLOWED.contains(&".account"),
        "DEFAULT_ALLOWED must include .account"
    );
}

// =========================================================================
// MAX_ACL_BYTES is 1 MiB (1_048_576) (row 169)
// =========================================================================

#[test]
fn max_acl_bytes_is_one_mib() {
    assert_eq!(MAX_ACL_BYTES, 1_048_576, "MAX_ACL_BYTES must be 1 MiB");
}

// =========================================================================
// is_path_allowed exists as a free function (row 115/172)
// =========================================================================

#[test]
fn is_path_allowed_function_exists() {
    assert!(is_path_allowed("/foo/bar.ttl").is_ok());
    assert!(is_path_allowed("/.env").is_err());
}
