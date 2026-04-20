//! Sprint 7 — `parse_size` helper (JSS parity `src/config.js:177-185`).
//!
//! The task spec mandates **decimal (1000-based)** multipliers for KB/MB/GB/TB
//! so `1.5GB → 1_500_000_000`. This intentionally diverges from JSS's
//! actual `1024-based` implementation; see `config/sources.rs::parse_size`
//! for the documented deviation note.

use solid_pod_rs::config::sources::parse_size;

#[test]
fn parse_size_bytes_no_suffix() {
    assert_eq!(parse_size("12345").unwrap(), 12_345u64);
}

#[test]
fn parse_size_kb() {
    // 10KB → 10 * 1000 = 10_000 (decimal / SI)
    assert_eq!(parse_size("10KB").unwrap(), 10_000u64);
    // Case-insensitive + whitespace tolerance.
    assert_eq!(parse_size(" 10 kb ").unwrap(), 10_000u64);
}

#[test]
fn parse_size_mb() {
    // 50MB → 50 * 1000^2 = 50_000_000
    assert_eq!(parse_size("50MB").unwrap(), 50_000_000u64);
}

#[test]
fn parse_size_gb() {
    // 1GB → 1 * 1000^3
    assert_eq!(parse_size("1GB").unwrap(), 1_000_000_000u64);
}

#[test]
fn parse_size_decimal_gb() {
    // Task spec: 1.5GB → 1_500_000_000
    assert_eq!(parse_size("1.5GB").unwrap(), 1_500_000_000u64);
}

#[test]
fn parse_size_invalid_returns_err() {
    assert!(parse_size("").is_err());
    assert!(parse_size("abc").is_err());
    assert!(parse_size("12XB").is_err());
    assert!(parse_size("-5MB").is_err());
    assert!(parse_size("1.2.3MB").is_err());
}
