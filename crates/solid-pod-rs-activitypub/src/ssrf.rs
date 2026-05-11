//! SSRF (Server-Side Request Forgery) protection for the ActivityPub layer.
//!
//! This module is a thin wrapper around the comprehensive SSRF validation in
//! [`solid_pod_rs::security::ssrf`]. All IP classification, IPv4-compat/6to4
//! bypass detection, cloud-metadata blocking, and policy enforcement are
//! delegated to the core crate. This module adds only the AP-specific
//! concerns:
//!
//! - **Scheme restriction**: only `http` and `https` are permitted.
//! - **Error mapping**: core [`SsrfError`] is mapped to AP-layer
//!   [`SigError::SsrfBlocked`] for ergonomic use in signature verification
//!   and delivery code paths.
//!
//! Covered ranges (via core):
//!   * RFC 1918 private, RFC 4193 ULA, loopback, link-local, multicast
//!   * Cloud metadata (169.254.169.254, fd00:ec2::254)
//!   * IPv4-mapped (::ffff:x.x.x.x), IPv4-compatible (::x.x.x.x)
//!   * 6to4 (2002::/16) with embedded IPv4 classification
//!   * CGNAT, benchmarking, documentation, IETF-reserved ranges
//!
//! See [`solid_pod_rs::security::ssrf`] for the canonical implementation.

use std::net::{IpAddr, ToSocketAddrs};

use solid_pod_rs::security::ssrf::{IpClass, SsrfPolicy};

use crate::error::SigError;

/// Returns `true` if the given IP address is non-public per core's
/// classification. Delegates to [`SsrfPolicy::classify`] and treats
/// every class except [`IpClass::Public`] as private/dangerous.
fn is_private_ip(ip: IpAddr) -> bool {
    !matches!(SsrfPolicy::classify(ip), IpClass::Public)
}

/// Validate that a URL is safe to fetch (not targeting internal
/// infrastructure). Resolves the hostname via DNS and rejects any
/// address in a private/reserved range.
///
/// Returns `Ok(())` on success or `Err(SigError::SsrfBlocked(..))` if
/// the URL targets a forbidden address.
///
/// This is a thin wrapper around the core SSRF validation in
/// [`solid_pod_rs::security::ssrf`], adding AP-specific scheme
/// restriction and error mapping.
pub fn assert_ssrf_safe(url: &str) -> Result<(), SigError> {
    let parsed = url::Url::parse(url).map_err(|e| SigError::Url(e.to_string()))?;

    // Only allow http/https schemes (AP-specific restriction).
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(SigError::SsrfBlocked(format!(
                "scheme '{}' is not allowed",
                other
            )));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| SigError::SsrfBlocked("URL has no host".into()))?;

    // Default port for the scheme.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{host}:{port}");

    // Resolve hostname to IP addresses.
    let addrs: Vec<std::net::SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| SigError::SsrfBlocked(format!("DNS resolution failed for '{}': {}", host, e)))?
        .collect();

    if addrs.is_empty() {
        return Err(SigError::SsrfBlocked(format!(
            "DNS resolution returned no addresses for '{}'",
            host
        )));
    }

    // Every resolved address must be routable — delegate to core classifier.
    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(SigError::SsrfBlocked(format!(
                "resolved address {} for '{}' is in a private/reserved range",
                addr.ip(),
                host
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -- Low-level classification tests (delegate to core) --------------------

    #[test]
    fn rejects_loopback_ipv4() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn rejects_link_local() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
    }

    #[test]
    fn allows_routable_ipv4() {
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_ipv6_link_local() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn allows_routable_ipv6() {
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    // ----- IPv4-compatible IPv6 bypass (core handles these) ------------------

    #[test]
    fn rejects_ipv4_compatible_loopback() {
        let addr: Ipv6Addr = "::127.0.0.1".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "::127.0.0.1 must be detected as private (loopback)"
        );
    }

    #[test]
    fn rejects_ipv4_compatible_private() {
        let addr: Ipv6Addr = "::10.0.0.1".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "::10.0.0.1 must be detected as private"
        );
    }

    #[test]
    fn rejects_ipv4_compatible_metadata() {
        let addr: Ipv6Addr = "::169.254.169.254".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "::169.254.169.254 must be detected as private (link-local metadata)"
        );
    }

    #[test]
    fn allows_ipv4_compatible_public() {
        let addr: Ipv6Addr = "::8.8.8.8".parse().unwrap();
        assert!(
            !is_private_ip(IpAddr::V6(addr)),
            "::8.8.8.8 should not be flagged as private"
        );
    }

    #[test]
    fn rejects_6to4_private() {
        let addr: Ipv6Addr = "2002:c0a8:0101::".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "2002:c0a8:0101:: (6to4 embedding 192.168.1.1) must be private"
        );
    }

    #[test]
    fn rejects_6to4_loopback() {
        let addr: Ipv6Addr = "2002:7f00:0001::".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "2002:7f00:0001:: (6to4 embedding 127.0.0.1) must be private"
        );
    }

    #[test]
    fn rejects_6to4_metadata() {
        let addr: Ipv6Addr = "2002:a9fe:a9fe::".parse().unwrap();
        assert!(
            is_private_ip(IpAddr::V6(addr)),
            "2002:a9fe:a9fe:: (6to4 embedding 169.254.169.254) must be private"
        );
    }

    #[test]
    fn allows_6to4_public() {
        let addr: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
        assert!(
            !is_private_ip(IpAddr::V6(addr)),
            "2002:0808:0808:: (6to4 embedding 8.8.8.8) should not be private"
        );
    }

    // ----- Integration-level assert_ssrf_safe tests --------------------------

    #[test]
    fn assert_ssrf_safe_rejects_localhost() {
        let result = assert_ssrf_safe("http://127.0.0.1/latest/meta-data");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_metadata_endpoint() {
        let result = assert_ssrf_safe("http://169.254.169.254/latest/meta-data");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_private_10() {
        let result = assert_ssrf_safe("http://10.0.0.1/admin");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_private_172() {
        let result = assert_ssrf_safe("http://172.16.0.1/internal");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_private_192() {
        let result = assert_ssrf_safe("http://192.168.1.1/router");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_ftp_scheme() {
        let result = assert_ssrf_safe("ftp://example.com/file");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }

    #[test]
    fn assert_ssrf_safe_rejects_file_scheme() {
        let result = assert_ssrf_safe("file:///etc/passwd");
        assert!(matches!(result, Err(SigError::SsrfBlocked(_))));
    }
}
