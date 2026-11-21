//! The one `htu` comparison every self-signed or DPoP-style JWT verifier uses.

/// Compare an `htu` claim with the URI the server expects, per RFC 9449
/// section 4.3: the query and fragment are ignored and the scheme and host
/// compare case-insensitively (the `url` parser lower-cases both and drops a
/// default port). The path is compared exactly: it is case-sensitive, and a
/// trailing slash names a different LDP resource (`/r` a document, `/r/` its
/// container), so a proof minted for one must not authorise the other.
/// Either side failing to parse as an absolute URL never matches.
///
/// # Examples
///
/// ```
/// use solid_pod_rs::auth::htu::htu_matches;
///
/// assert!(htu_matches("HTTPS://A.example/r?x=1#f", "https://a.example/r"));
/// assert!(!htu_matches("https://a.example/r/", "https://a.example/r"));
/// assert!(!htu_matches("https://a.example/R", "https://a.example/r"));
/// ```
#[must_use]
pub fn htu_matches(claimed: &str, expected: &str) -> bool {
    fn canonical(raw: &str) -> Option<url::Url> {
        let mut u = url::Url::parse(raw).ok()?;
        u.set_query(None);
        u.set_fragment(None);
        Some(u)
    }
    matches!((canonical(claimed), canonical(expected)), (Some(a), Some(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::htu_matches;

    #[test]
    fn rfc_9449_vectors() {
        assert!(htu_matches("https://a.example/r", "https://a.example/r"));
        assert!(htu_matches(
            "https://A.EXAMPLE:443/r",
            "https://a.example/r"
        ));
        assert!(htu_matches(
            "https://a.example/r?q=1",
            "https://a.example/r#x"
        ));
        assert!(!htu_matches("https://a.example/r/", "https://a.example/r"));
        assert!(!htu_matches(
            "https://a.example/Private",
            "https://a.example/private"
        ));
        assert!(!htu_matches("http://a.example/r", "https://a.example/r"));
        assert!(!htu_matches("/r", "https://a.example/r"));
    }
}
