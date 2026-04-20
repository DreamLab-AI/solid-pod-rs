//! CORS policy primitive (Sprint 7 §6.2, ADR-057).
//!
//! Transport-agnostic CORS rules. Consumers (actix-web, axum) call
//! [`CorsPolicy::preflight_headers`] from their `OPTIONS` handler and
//! [`CorsPolicy::response_headers`] from the normal-response path; this
//! crate never mounts routes itself.
//!
//! ## Semantics
//!
//! - **Allowed origins.** Either [`AllowedOrigins::Wildcard`] (any
//!   origin) or [`AllowedOrigins::Exact`] (explicit allowlist). An
//!   unlisted origin yields `None` from the preflight path — the caller
//!   MUST emit a no-CORS response (typically 403 or the un-augmented
//!   200).
//! - **Credentials + wildcard.** Per the Fetch spec, `Access-Control-
//!   Allow-Origin: *` is invalid when credentials are included. When
//!   both are configured, the policy degrades to echoing the concrete
//!   request origin and emits `Vary: Origin` so caches do not leak.
//! - **Exposed headers.** Default set targets Solid interop (WAC-Allow,
//!   Link, ETag, Accept-Patch, Accept-Post, Updates-Via). Operators
//!   override via [`CorsPolicy::with_expose_headers`].
//! - **Preflight advertising.** `Access-Control-Allow-Headers` echoes
//!   the `Access-Control-Request-Headers` value verbatim (after
//!   whitespace normalisation), matching JSS behaviour — consumers need
//!   not maintain an allowlist of request headers.

use std::collections::BTreeSet;
use std::time::Duration;

/// Environment variable: comma-separated list of allowed origins, or
/// `*` for wildcard.
pub const ENV_CORS_ALLOWED_ORIGINS: &str = "CORS_ALLOWED_ORIGINS";

/// Environment variable: `true`/`1` to enable credentials.
pub const ENV_CORS_ALLOW_CREDENTIALS: &str = "CORS_ALLOW_CREDENTIALS";

/// Environment variable: preflight max-age in seconds.
pub const ENV_CORS_MAX_AGE: &str = "CORS_MAX_AGE";

/// Default Max-Age for preflight caching.
pub const DEFAULT_MAX_AGE_SECS: u64 = 3_600;

/// Default headers exposed to the browser — tuned for Solid / LDP
/// interoperability.
pub const DEFAULT_EXPOSE_HEADERS: &[&str] = &[
    "WAC-Allow",
    "Link",
    "ETag",
    "Accept-Patch",
    "Accept-Post",
    "Updates-Via",
];

/// Origin-matching strategy.
#[derive(Debug, Clone)]
pub enum AllowedOrigins {
    /// Any origin is permitted. Combined with credentials, the policy
    /// degrades to echo-concrete-origin mode (see module docs).
    Wildcard,
    /// Only origins present in the set are permitted. Comparison is
    /// case-sensitive (RFC 6454 origins are ASCII).
    Exact(BTreeSet<String>),
}

/// CORS policy aggregate root. Immutable after construction.
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    allowed_origins: AllowedOrigins,
    allow_credentials: bool,
    expose_headers: Vec<String>,
    max_age: Duration,
}

impl CorsPolicy {
    /// Maximally permissive default: wildcard origins, no credentials,
    /// default expose headers, 3600 s preflight cache.
    pub fn new() -> Self {
        Self {
            allowed_origins: AllowedOrigins::Wildcard,
            allow_credentials: false,
            expose_headers: DEFAULT_EXPOSE_HEADERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_age: Duration::from_secs(DEFAULT_MAX_AGE_SECS),
        }
    }

    /// Load from env. Missing variables fall back to defaults; present
    /// but unparseable values also fall back (ignored).
    ///
    /// - `CORS_ALLOWED_ORIGINS` — comma-separated list, or `*`.
    /// - `CORS_ALLOW_CREDENTIALS` — `true`/`1`/`yes`/`on` enables.
    /// - `CORS_MAX_AGE` — decimal seconds.
    pub fn from_env() -> Self {
        let allowed_origins = match std::env::var(ENV_CORS_ALLOWED_ORIGINS) {
            Ok(raw) => parse_origins(&raw),
            Err(_) => AllowedOrigins::Wildcard,
        };
        let allow_credentials = std::env::var(ENV_CORS_ALLOW_CREDENTIALS)
            .ok()
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false);
        let max_age = std::env::var(ENV_CORS_MAX_AGE)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_MAX_AGE_SECS));

        Self {
            allowed_origins,
            allow_credentials,
            expose_headers: DEFAULT_EXPOSE_HEADERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_age,
        }
    }

    /// Replace the origin strategy.
    pub fn with_allowed_origins(mut self, origins: AllowedOrigins) -> Self {
        self.allowed_origins = origins;
        self
    }

    /// Enable (or disable) credentialed requests.
    pub fn with_allow_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    /// Override the exposed-headers list.
    pub fn with_expose_headers(mut self, headers: Vec<String>) -> Self {
        self.expose_headers = headers;
        self
    }

    /// Override the preflight cache duration.
    pub fn with_max_age(mut self, duration: Duration) -> Self {
        self.max_age = duration;
        self
    }

    /// Current preflight cache duration.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Build the header set for a preflight (`OPTIONS`) response.
    ///
    /// Returns `None` when the request origin is not permitted; the
    /// caller MUST emit a no-CORS response (typically plain 403 or an
    /// un-augmented 200).
    ///
    /// `req_method` is the value of `Access-Control-Request-Method`.
    /// `req_headers` is the verbatim `Access-Control-Request-Headers`
    /// value (comma-separated); passing an empty string is valid and
    /// yields an empty `Access-Control-Allow-Headers`.
    pub fn preflight_headers(
        &self,
        origin: Option<&str>,
        req_method: &str,
        req_headers: &str,
    ) -> Option<Vec<(&'static str, String)>> {
        let echoed_origin = self.echo_origin(origin)?;

        let mut out: Vec<(&'static str, String)> = Vec::with_capacity(8);
        out.push(("Access-Control-Allow-Origin", echoed_origin.clone()));

        // Vary: Origin is mandatory when echoing; harmless when
        // emitting `*` (caches already key on it).
        out.push(("Vary", "Origin".to_string()));

        if self.allow_credentials {
            out.push(("Access-Control-Allow-Credentials", "true".to_string()));
        }

        // Methods — echo the single requested method. Servers MAY
        // advertise the full method list here; we keep it minimal to
        // match JSS + Fetch spec §4.9.
        let methods = if req_method.trim().is_empty() {
            default_methods()
        } else {
            req_method.trim().to_ascii_uppercase()
        };
        out.push(("Access-Control-Allow-Methods", methods));

        // Headers — echo the request header list verbatim (trimmed).
        // This is the JSS approach and sidesteps maintaining an
        // allow-list of request headers on the server.
        let normalised = normalise_header_list(req_headers);
        out.push(("Access-Control-Allow-Headers", normalised));

        // Max-Age for preflight cache.
        out.push((
            "Access-Control-Max-Age",
            self.max_age.as_secs().to_string(),
        ));

        Some(out)
    }

    /// Build the header set for a normal (non-preflight) response.
    ///
    /// Always emits `Access-Control-Expose-Headers` plus — when the
    /// origin is permitted — `Access-Control-Allow-Origin` and `Vary:
    /// Origin`.
    pub fn response_headers(&self, origin: Option<&str>) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::with_capacity(4);

        if let Some(echoed) = self.echo_origin(origin) {
            out.push(("Access-Control-Allow-Origin", echoed));
            out.push(("Vary", "Origin".to_string()));
            if self.allow_credentials {
                out.push(("Access-Control-Allow-Credentials", "true".to_string()));
            }
        }

        if !self.expose_headers.is_empty() {
            out.push((
                "Access-Control-Expose-Headers",
                self.expose_headers.join(", "),
            ));
        }

        out
    }

    /// Compute the value to emit in `Access-Control-Allow-Origin`.
    ///
    /// Returns `None` when the origin is not permitted. For wildcard +
    /// credentials, echoes the concrete request origin; for wildcard
    /// without credentials, returns `*`; for `Exact`, returns the
    /// matched origin verbatim.
    fn echo_origin(&self, origin: Option<&str>) -> Option<String> {
        match &self.allowed_origins {
            AllowedOrigins::Wildcard => {
                if self.allow_credentials {
                    // RFC: `*` is invalid with credentials; must echo
                    // the concrete origin. If the caller did not send
                    // an Origin header, we cannot safely emit `*`, so
                    // return None and let the caller drop CORS headers.
                    origin.map(|o| o.to_string())
                } else {
                    Some(origin.map(|o| o.to_string()).unwrap_or_else(|| "*".into()))
                }
            }
            AllowedOrigins::Exact(set) => {
                let o = origin?;
                if set.contains(o) {
                    Some(o.to_string())
                } else {
                    None
                }
            }
        }
    }
}

impl Default for CorsPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// --- helpers -------------------------------------------------------------

fn parse_origins(raw: &str) -> AllowedOrigins {
    let trimmed = raw.trim();
    if trimmed == "*" {
        return AllowedOrigins::Wildcard;
    }
    let set: BTreeSet<String> = trimmed
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if set.is_empty() {
        AllowedOrigins::Wildcard
    } else {
        AllowedOrigins::Exact(set)
    }
}

fn default_methods() -> String {
    "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS".to_string()
}

fn normalise_header_list(raw: &str) -> String {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

// --- unit tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wildcard_no_credentials_emits_star() {
        let policy = CorsPolicy::new();
        let echoed = policy.echo_origin(Some("https://x.example")).unwrap();
        assert_eq!(echoed, "https://x.example");

        let without = policy.echo_origin(None).unwrap();
        assert_eq!(without, "*");
    }

    #[test]
    fn wildcard_with_credentials_falls_back_to_origin() {
        let policy = CorsPolicy::new().with_allow_credentials(true);
        assert_eq!(
            policy.echo_origin(Some("https://x.example")).unwrap(),
            "https://x.example"
        );
        assert!(policy.echo_origin(None).is_none());
    }

    #[test]
    fn exact_rejects_unlisted_origin() {
        let mut s = BTreeSet::new();
        s.insert("https://good.example".to_string());
        let policy = CorsPolicy::new().with_allowed_origins(AllowedOrigins::Exact(s));
        assert!(policy.echo_origin(Some("https://bad.example")).is_none());
        assert_eq!(
            policy.echo_origin(Some("https://good.example")).unwrap(),
            "https://good.example"
        );
    }

    #[test]
    fn normalise_header_list_collapses_whitespace() {
        assert_eq!(
            normalise_header_list("  authorization ,dpop,   content-type "),
            "authorization, dpop, content-type"
        );
    }

    #[test]
    fn parse_origins_wildcard_and_list() {
        match parse_origins("*") {
            AllowedOrigins::Wildcard => {}
            _ => panic!("expected wildcard"),
        }
        match parse_origins("https://a,https://b") {
            AllowedOrigins::Exact(set) => {
                assert!(set.contains("https://a"));
                assert!(set.contains("https://b"));
            }
            _ => panic!("expected exact"),
        }
    }
}
