//! OIDC discovery document (row 76).
//!
//! Mirrors `JavaScriptSolidServer/src/idp/index.js:203-237` — the
//! `/.well-known/openid-configuration` handler.
//!
//! This is deliberately *not* a re-export of
//! `solid_pod_rs::oidc::DiscoveryDocument` because the JSS profile
//! publishes a richer field set (notably `end_session_endpoint`,
//! `code_challenge_methods_supported`,
//! `authorization_response_iss_parameter_supported`) that Solid
//! clients expect.

use serde::{Deserialize, Serialize};

/// Discovery document per the Solid-OIDC profile (superset of OIDC
/// Discovery 1.0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// Issuer URL (always terminated with `/` for CTH compat, per
    /// JSS line 205).
    pub issuer: String,
    /// Authorisation endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// UserInfo endpoint URL (`/me` in JSS).
    pub userinfo_endpoint: String,
    /// JWKS URI (`/.well-known/jwks.json` in JSS).
    pub jwks_uri: String,
    /// Dynamic Client Registration endpoint.
    pub registration_endpoint: String,
    /// Token introspection endpoint (RFC 7662).
    pub introspection_endpoint: String,
    /// Token revocation endpoint.
    pub revocation_endpoint: String,
    /// End-session / RP-initiated logout endpoint.
    pub end_session_endpoint: String,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported response modes.
    pub response_modes_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported subject types.
    pub subject_types_supported: Vec<String>,
    /// Algorithms supported for id-token signing.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Token endpoint auth methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Claims that may be returned.
    pub claims_supported: Vec<String>,
    /// PKCE methods supported.
    pub code_challenge_methods_supported: Vec<String>,
    /// DPoP signing algorithms supported.
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// RFC 9207 authorisation-response `iss` parameter advertised.
    pub authorization_response_iss_parameter_supported: bool,
    /// Solid-OIDC profile URL. JSS returns a string; we surface the
    /// same as `Vec<String>` so downstream libs that treat this as a
    /// conformance list don't break. Serde renames preserve wire.
    pub solid_oidc_supported: String,
}

/// Build the discovery document for a given issuer.
///
/// The `issuer` URL is normalised so that `issuer` in the output
/// always terminates with `/` (matches JSS line 205 —
/// `normalizedIssuer`), while the endpoint URLs are built from the
/// trailing-slash-stripped base (matches JSS line 207 — `baseUrl`).
pub fn build_discovery(issuer: &str) -> DiscoveryDocument {
    let normalised_issuer = if issuer.ends_with('/') {
        issuer.to_string()
    } else {
        format!("{issuer}/")
    };
    let base = issuer.trim_end_matches('/');

    DiscoveryDocument {
        issuer: normalised_issuer,
        authorization_endpoint: format!("{base}/idp/auth"),
        token_endpoint: format!("{base}/idp/token"),
        userinfo_endpoint: format!("{base}/idp/me"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        registration_endpoint: format!("{base}/idp/reg"),
        introspection_endpoint: format!("{base}/idp/token/introspection"),
        revocation_endpoint: format!("{base}/idp/token/revocation"),
        end_session_endpoint: format!("{base}/idp/session/end"),
        scopes_supported: vec![
            "openid".into(),
            "webid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ],
        response_types_supported: vec!["code".into()],
        response_modes_supported: vec![
            "query".into(),
            "fragment".into(),
            "form_post".into(),
        ],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
        ],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["ES256".into()],
        token_endpoint_auth_methods_supported: vec![
            "none".into(),
            "client_secret_basic".into(),
            "client_secret_post".into(),
        ],
        claims_supported: vec![
            "sub".into(),
            "webid".into(),
            "name".into(),
            "email".into(),
            "email_verified".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
        dpop_signing_alg_values_supported: vec!["ES256".into()],
        authorization_response_iss_parameter_supported: true,
        solid_oidc_supported: "https://solidproject.org/TR/solid-oidc".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_contains_required_fields() {
        let d = build_discovery("https://pod.example");
        assert_eq!(d.issuer, "https://pod.example/");
        assert_eq!(d.authorization_endpoint, "https://pod.example/idp/auth");
        assert_eq!(d.token_endpoint, "https://pod.example/idp/token");
        assert_eq!(d.jwks_uri, "https://pod.example/.well-known/jwks.json");
        assert_eq!(
            d.registration_endpoint,
            "https://pod.example/idp/reg"
        );

        // Solid-OIDC profile MUST: webid scope.
        assert!(d.scopes_supported.iter().any(|s| s == "webid"));
        // Public clients ("none" auth) are supported.
        assert!(d
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|s| s == "none"));
        // Authorisation code is the core Solid-OIDC grant.
        assert!(d.grant_types_supported.iter().any(|s| s == "authorization_code"));
        // DPoP advertisement must be non-empty.
        assert!(!d.dpop_signing_alg_values_supported.is_empty());
        // PKCE S256 is required for public clients.
        assert!(d.code_challenge_methods_supported.iter().any(|s| s == "S256"));
        // Solid-OIDC marker.
        assert!(d.solid_oidc_supported.contains("solid-oidc"));
    }

    #[test]
    fn discovery_normalises_issuer_trailing_slash() {
        let a = build_discovery("https://pod.example");
        let b = build_discovery("https://pod.example/");
        assert_eq!(a.issuer, b.issuer);
        assert_eq!(a.issuer, "https://pod.example/");
        // But endpoints must not gain double slashes.
        assert_eq!(a.authorization_endpoint, b.authorization_endpoint);
        assert!(!a.authorization_endpoint.contains("//idp"));
    }
}
