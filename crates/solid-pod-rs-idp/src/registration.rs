//! Dynamic Client Registration + Client Identifier Documents (rows 75, 78).
//!
//! JSS parity: `src/idp/provider.js:22-85` (the `fetchClientDocument`
//! helper) plus the `registration` feature in oidc-provider's config
//! (`src/idp/provider.js:147-156`).
//!
//! Two modes:
//!
//! 1. **Opaque client id (RFC 7591)** — caller POSTs registration
//!    metadata, server mints a `client_id` of the form
//!    `client_<base36-timestamp>_<random>` (matches JSS
//!    `idFactory` in `provider.js:150-153`).
//!
//! 2. **Client Identifier Document (Solid-OIDC §5.1)** — caller
//!    supplies the URL of a JSON-LD document containing
//!    `client_id` + `redirect_uris`. The server fetches it (SSRF-
//!    guarded), verifies the document's `client_id` equals the URL,
//!    and caches the resolved metadata for
//!    [`CLIENT_CACHE_TTL`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use solid_pod_rs::security::ssrf::is_safe_url;

/// JSS mirrors this with `CLIENT_CACHE_TTL = 5 * 60 * 1000` in
/// `src/idp/provider.js:14`.
pub const CLIENT_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Incoming registration body (RFC 7591 §2). Also used to re-render
/// fetched Client Identifier Documents.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistrationRequest {
    /// Opaque-registration path leaves this unset. CID-document path
    /// sets this to the fetched URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
}

/// Registered client record (post-registration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDocument {
    /// Opaque id or document URL.
    pub client_id: String,
    /// `None` for public clients (`token_endpoint_auth_method=none`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Unix seconds of registration.
    pub client_id_issued_at: u64,
    /// Redirect URIs (at minimum 1 required for code flow).
    pub redirect_uris: Vec<String>,
    /// Free-form display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Grant types this client is authorised to use.
    pub grant_types: Vec<String>,
    /// Response types (Solid-OIDC always `["code"]`).
    pub response_types: Vec<String>,
    /// Auth method at `/token`.
    pub token_endpoint_auth_method: String,
    /// Application type — `"web"` or `"native"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    /// Requested scope string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// If this client was registered from a Client Identifier
    /// Document, the URL at which the source document lives. Used
    /// by `/reg` to return a deep link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_document_url: Option<String>,
}

impl ClientDocument {
    fn now_secs() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Errors emitted by the registration surface.
#[derive(Debug, Error)]
pub enum RegError {
    /// Caller passed a bad request body.
    #[error("invalid registration: {0}")]
    InvalidRequest(String),

    /// Client Identifier Document fetch blocked by SSRF policy.
    #[error("SSRF-blocked: {0}")]
    Ssrf(String),

    /// HTTP fetch of the CID document failed.
    #[error("fetch failed: {0}")]
    Fetch(String),

    /// The CID document is malformed.
    #[error("invalid client document: {0}")]
    InvalidDocument(String),
}

/// In-memory store of registered clients.
///
/// `find_by_id` is used by the `/auth` and `/token` endpoints. When
/// the id looks like a URL and isn't known, the store will attempt
/// to fetch a Client Identifier Document (SSRF-guarded) and cache
/// the result for [`CLIENT_CACHE_TTL`].
#[derive(Clone)]
pub struct ClientStore {
    inner: Arc<RwLock<ClientStoreInner>>,
    http: Option<HttpClient>,
    /// When `true`, [`ClientStore::fetch_client_document`] skips the
    /// SSRF pre-flight. Only for tests / local dev fixtures that
    /// need to resolve `http://127.0.0.1:PORT/...` URLs to a
    /// wiremock server. Production deployments MUST leave this off.
    allow_unsafe_urls: bool,
}

impl Default for ClientStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct ClientStoreInner {
    /// Explicitly-registered clients (opaque id path).
    registered: HashMap<String, ClientDocument>,
    /// Cache of fetched Client Identifier Documents, keyed by URL.
    cache: HashMap<String, (ClientDocument, Instant)>,
}

impl ClientStore {
    /// Construct a store with the default reqwest HTTP client. Use
    /// [`ClientStore::with_http`] to supply a custom client (timeout,
    /// proxy, rustls roots, etc.).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ClientStoreInner::default())),
            http: HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .ok(),
            allow_unsafe_urls: false,
        }
    }

    /// Use a caller-supplied HTTP client (e.g. with custom SSRF-aware
    /// transport).
    pub fn with_http(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Test-only escape hatch: disable the SSRF pre-flight on CID
    /// document fetches so unit tests can resolve wiremock URLs
    /// (`http://127.0.0.1:PORT/...`). Production deployments MUST
    /// NOT call this.
    #[doc(hidden)]
    pub fn allow_unsafe_urls_for_testing(mut self) -> Self {
        self.allow_unsafe_urls = true;
        self
    }

    /// Explicitly insert a registered client (test / boot-time).
    pub fn insert(&self, client: ClientDocument) {
        let mut inner = self.inner.write();
        inner.registered.insert(client.client_id.clone(), client);
    }

    /// Look up a client by id. If the id is a URL and not locally
    /// registered, attempt to resolve it as a Client Identifier
    /// Document.
    pub async fn find(&self, client_id: &str) -> Result<Option<ClientDocument>, RegError> {
        // Registered (opaque) client hit.
        if let Some(doc) = self.inner.read().registered.get(client_id).cloned() {
            return Ok(Some(doc));
        }

        // Cache hit.
        {
            let inner = self.inner.read();
            if let Some((doc, ts)) = inner.cache.get(client_id) {
                if ts.elapsed() < CLIENT_CACHE_TTL {
                    return Ok(Some(doc.clone()));
                }
            }
        }

        // URL shape? → try Client Identifier Document path.
        if client_id.starts_with("http://") || client_id.starts_with("https://") {
            let doc = self.fetch_client_document(client_id).await?;
            let mut inner = self.inner.write();
            inner
                .cache
                .insert(client_id.to_string(), (doc.clone(), Instant::now()));
            return Ok(Some(doc));
        }

        Ok(None)
    }

    async fn fetch_client_document(&self, url: &str) -> Result<ClientDocument, RegError> {
        // SSRF pre-flight — mirrors JSS's `validateExternalUrl` call
        // (provider.js:32). The DNS-level check in core is
        // stricter than JSS's IP-literal-only guard. Tests may
        // disable this via `allow_unsafe_urls_for_testing`.
        if !self.allow_unsafe_urls {
            is_safe_url(url).map_err(|e| RegError::Ssrf(e.to_string()))?;
        }

        // Parse the URL so we can assert it's a valid HTTPS target
        // before spending any bytes on the wire.
        let parsed = Url::parse(url)
            .map_err(|e| RegError::InvalidDocument(format!("URL parse: {e}")))?;
        // JSS's `validateExternalUrl` also enforces `requireHttps:true`;
        // we drop that to http-or-https since the SSRF check catches
        // the RFC1918 case anyway, and some Solid test rigs use plain
        // HTTP for localhost fixtures. Still keep a guard for weird
        // schemes.
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(RegError::InvalidDocument(format!(
                "unsupported scheme: {}",
                parsed.scheme()
            )));
        }

        let http = self
            .http
            .as_ref()
            .ok_or_else(|| RegError::Fetch("no HTTP client configured".into()))?;
        let resp = http
            .get(url)
            .header("Accept", "application/ld+json, application/json")
            .send()
            .await
            .map_err(|e| RegError::Fetch(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(RegError::Fetch(format!(
                "HTTP {} from {url}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| RegError::InvalidDocument(format!("JSON parse: {e}")))?;

        // JSS check (provider.js:55-58): if the document declares a
        // client_id, it MUST equal the URL we fetched from.
        if let Some(declared) = body.get("client_id").and_then(|v| v.as_str()) {
            if declared != url {
                return Err(RegError::InvalidDocument(format!(
                    "client_id mismatch: document says {declared}, URL is {url}"
                )));
            }
        }

        // Redirect URIs are mandatory for Solid-OIDC clients
        // (authorization-code flow won't work without at least one).
        let redirect_uris: Vec<String> = body
            .get("redirect_uris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        if redirect_uris.is_empty() {
            return Err(RegError::InvalidDocument(
                "Client Identifier Document is missing redirect_uris".into(),
            ));
        }

        let client_name = body
            .get("client_name")
            .and_then(|v| v.as_str())
            .or_else(|| body.get("name").and_then(|v| v.as_str()))
            .map(str::to_string);

        let scope = body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| Some("openid webid".into()));

        Ok(ClientDocument {
            client_id: url.to_string(),
            client_secret: None,
            client_id_issued_at: ClientDocument::now_secs(),
            redirect_uris,
            client_name,
            // Solid-OIDC code-flow defaults (mirror JSS
            // `src/idp/provider.js:64-75`).
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "none".into(),
            application_type: Some("web".into()),
            scope,
            client_id_document_url: Some(url.to_string()),
        })
    }
}

/// Register a client by opaque id. Returns the server-assigned
/// [`ClientDocument`] and persists it into `store`.
///
/// JSS parity: `provider.js:147-156` (the `registration.idFactory`
/// block) — format matches `client_<base36-ts>_<random-b36>`.
pub async fn register_client(
    store: &ClientStore,
    req: RegistrationRequest,
) -> Result<ClientDocument, RegError> {
    // If the caller supplied a URL client_id, delegate to the CID
    // path (fetch + cache) — this keeps the `register_client` entry
    // point uniform even when the underlying mechanism differs.
    if let Some(id) = req.client_id.as_deref() {
        if id.starts_with("http://") || id.starts_with("https://") {
            // Reuse the ClientStore fetch logic; cache it on hit.
            if let Some(doc) = store.find(id).await? {
                return Ok(doc);
            }
            return Err(RegError::InvalidDocument(
                "Client Identifier Document fetch returned no document".into(),
            ));
        }
    }

    if req.redirect_uris.is_empty() {
        return Err(RegError::InvalidRequest(
            "redirect_uris is required for authorization-code flow".into(),
        ));
    }

    // Mirror JSS idFactory shape: `client_<ts36>_<rand36>`.
    let id_ts = u128::from(ClientDocument::now_secs()).max(1);
    let ts36 = to_base36(id_ts);
    let rand_tail: String = rand_base36(8);
    let client_id = format!("client_{ts36}_{rand_tail}");

    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".into());
    let client_secret = if auth_method == "none" {
        None
    } else {
        Some(format!("secret-{}", uuid::Uuid::new_v4()))
    };

    let grant_types = if req.grant_types.is_empty() {
        vec!["authorization_code".into(), "refresh_token".into()]
    } else {
        req.grant_types.clone()
    };
    let response_types = if req.response_types.is_empty() {
        vec!["code".into()]
    } else {
        req.response_types.clone()
    };

    let doc = ClientDocument {
        client_id,
        client_secret,
        client_id_issued_at: ClientDocument::now_secs(),
        redirect_uris: req.redirect_uris,
        client_name: req.client_name,
        grant_types,
        response_types,
        token_endpoint_auth_method: auth_method,
        application_type: req.application_type.or_else(|| Some("web".into())),
        scope: req.scope.or_else(|| Some("openid webid".into())),
        client_id_document_url: None,
    };
    store.insert(doc.clone());
    Ok(doc)
}

fn to_base36(mut n: u128) -> String {
    if n == 0 {
        return "0".into();
    }
    const ALPHA: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while n > 0 {
        out.push(ALPHA[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    // Safe: bytes are pure ASCII from ALPHA.
    String::from_utf8(out).unwrap_or_default()
}

fn rand_base36(len: usize) -> String {
    use rand::Rng;
    const ALPHA: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHA[rng.gen_range(0..36)] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn opaque_registration_assigns_prefixed_client_id() {
        let store = ClientStore::new();
        let req = RegistrationRequest {
            redirect_uris: vec!["https://app.example/cb".into()],
            client_name: Some("App".into()),
            ..Default::default()
        };
        let doc = register_client(&store, req).await.unwrap();
        assert!(doc.client_id.starts_with("client_"));
        // Public clients (default `none`) must not be issued a secret.
        assert!(doc.client_secret.is_none());
        // Round-trip through the store.
        let again = store.find(&doc.client_id).await.unwrap().unwrap();
        assert_eq!(again.client_id, doc.client_id);
    }

    #[tokio::test]
    async fn registration_without_redirect_uris_is_rejected() {
        let store = ClientStore::new();
        let err = register_client(
            &store,
            RegistrationRequest {
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RegError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn client_identifier_document_is_fetched_and_cached() {
        let server = MockServer::start().await;
        let cid_url = format!("{}/client#id", server.uri());

        let body = serde_json::json!({
            "@context": "https://www.w3.org/ns/solid/oidc-context.jsonld",
            "client_id": cid_url,
            "client_name": "Federated App",
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid webid profile"
        });

        Mock::given(method("GET"))
            .and(path("/client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .expect(1) // Must be fetched exactly once — cache must work.
            .mount(&server)
            .await;

        let store = ClientStore::new().allow_unsafe_urls_for_testing();
        let doc = store.find(&cid_url).await.unwrap().unwrap();
        assert_eq!(doc.client_id, cid_url);
        assert_eq!(doc.redirect_uris, vec!["https://app.example/cb".to_string()]);
        assert_eq!(doc.client_name.as_deref(), Some("Federated App"));
        assert_eq!(doc.client_id_document_url.as_deref(), Some(cid_url.as_str()));

        // Second lookup MUST be cache-served (mock `.expect(1)` above).
        let _ = store.find(&cid_url).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_identifier_document_rejects_id_mismatch() {
        let server = MockServer::start().await;
        let cid_url = format!("{}/client", server.uri());

        Mock::given(method("GET"))
            .and(path("/client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "client_id": "https://malicious.example/evil",
                "redirect_uris": ["https://malicious.example/cb"]
            })))
            .mount(&server)
            .await;

        let store = ClientStore::new().allow_unsafe_urls_for_testing();
        let err = store.find(&cid_url).await.unwrap_err();
        assert!(matches!(err, RegError::InvalidDocument(_)));
    }

    #[tokio::test]
    async fn client_identifier_document_rejects_private_ip() {
        // No wiremock involvement — SSRF guard MUST trip before any
        // HTTP request is attempted.
        let store = ClientStore::new();
        let err = store.find("http://127.0.0.1/client").await.unwrap_err();
        assert!(matches!(err, RegError::Ssrf(_)));
    }

    #[tokio::test]
    async fn client_identifier_document_requires_redirect_uris() {
        let server = MockServer::start().await;
        let cid_url = format!("{}/client", server.uri());

        Mock::given(method("GET"))
            .and(path("/client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "client_id": cid_url,
                "client_name": "Incomplete"
            })))
            .mount(&server)
            .await;

        let store = ClientStore::new().allow_unsafe_urls_for_testing();
        let err = store.find(&cid_url).await.unwrap_err();
        assert!(matches!(err, RegError::InvalidDocument(_)));
    }

    #[test]
    fn base36_encode_sanity() {
        assert_eq!(to_base36(0), "0");
        assert_eq!(to_base36(35), "z");
        assert_eq!(to_base36(36), "10");
    }
}
