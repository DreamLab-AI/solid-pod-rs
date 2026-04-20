//! JSS parity: `Slug` header validation for POST-to-container.
//!
//! Current behaviour silently falls back to UUID on any invalid slug.
//! JSS rejects with `400 Bad Request` for path-traversal, oversize, and
//! disallowed characters so clients learn about the mistake instead of
//! silently creating a random resource.

use solid_pod_rs::error::PodError;
use solid_pod_rs::ldp::resolve_slug;

#[test]
fn slug_with_slash_returns_bad_request() {
    let err = resolve_slug("/photos/", Some("a/b")).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
}

#[test]
fn slug_over_255_bytes_returns_bad_request() {
    let long = "a".repeat(256);
    let err = resolve_slug("/photos/", Some(&long)).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
}

#[test]
fn slug_with_dotdot_returns_bad_request() {
    let err = resolve_slug("/photos/", Some("..")).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
    let err = resolve_slug("/photos/", Some("..foo")).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
}

#[test]
fn slug_with_null_byte_returns_bad_request() {
    let err = resolve_slug("/photos/", Some("ab\0cd")).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
}

#[test]
fn slug_absent_falls_back_to_uuid() {
    let out = resolve_slug("/photos/", None).unwrap();
    assert!(out.starts_with("/photos/"));
    let tail = out.strip_prefix("/photos/").unwrap();
    // UUID-v4 string is 36 chars with 4 dashes.
    assert_eq!(tail.len(), 36, "expected UUID, got {tail}");
    assert_eq!(tail.matches('-').count(), 4, "expected UUID, got {tail}");
}

#[test]
fn slug_empty_falls_back_to_uuid() {
    // Empty slug treated as absent per the existing contract.
    let out = resolve_slug("/photos/", Some("")).unwrap();
    let tail = out.strip_prefix("/photos/").unwrap();
    assert_eq!(tail.len(), 36);
}

#[test]
fn slug_valid_lowercase_preserved() {
    let out = resolve_slug("/photos/", Some("cat.jpg")).unwrap();
    assert_eq!(out, "/photos/cat.jpg");
}

#[test]
fn slug_valid_allows_dot_underscore_dash() {
    let out = resolve_slug("/x/", Some("a_b-c.d")).unwrap();
    assert_eq!(out, "/x/a_b-c.d");
}

#[test]
fn slug_rejects_non_ascii_whitespace() {
    // Whitespace is not in the allowlist.
    let err = resolve_slug("/x/", Some("a b")).unwrap_err();
    assert!(matches!(err, PodError::BadRequest(_)), "got {err:?}");
}
