//! OIDC provider surface: `/auth` + `/token` + `/me` (rows 74, 76, 77).
//!
//! JSS parity: `src/idp/provider.js:92-455` — the `createProvider`
//! factory. JSS wraps the `oidc-provider` npm package; we implement
//! the same state machine directly because the Rust ecosystem
//! doesn't have a drop-in equivalent and the Solid-OIDC profile is
//! narrow enough (authorization-code + PKCE + DPoP, public clients
//! by default) to code up in ~400 LOC.
//!
//! ## What IS implemented here
//!
//! - Authorization-code flow (public clients, PKCE S256 mandatory).
//! - DPoP-bound access tokens at `/token`.
//! - Client lookup via [`ClientStore`], including Client Identifier
//!   Documents.
//! - User info via the session's account record.
//!
//! ## What is NOT implemented here (deliberately)
//!
//! - **Login UI.** `/auth` returns an `AuthorizeResponse::NeedsLogin`
//!   that the consumer must render however they wish (JSS drives an
//!   interaction UID through the oidc-provider interaction tables;
//!   we surface the raw "please authenticate" state to the caller).
//! - **Consent prompt.** JSS auto-approves via `loadExistingGrant`
//!   (`provider.js:266-304`); we mirror that — every successful
//!   login implies consent.
//! - **Refresh tokens.** Sprint 10 ships access tokens only. A
//!   follow-up sprint can extend [`TokenResponse`] with
//!   `refresh_token` and extend [`SessionStore`] with refresh
//!   records.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use solid_pod_rs::oidc::verify_dpop_proof;

use crate::error::ProviderError;
use crate::jwks::Jwks;
use crate::registration::ClientStore;
use crate::session::{AuthCodeRecord, SessionStore};
use crate::tokens::{issue_access_token, AccessToken};
use crate::user_store::UserStore;

/// Provider configuration.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Issuer URL — must match the discovery document.
    pub issuer: String,
    /// Access-token TTL in seconds. Default 3600 (JSS matches).
    pub access_token_ttl_secs: u64,
    /// DPoP `iat` tolerance, seconds. Default 60.
    pub dpop_skew_secs: u64,
}

impl ProviderConfig {
    /// Reasonable Solid-OIDC defaults.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            access_token_ttl_secs: 3600,
            dpop_skew_secs: 60,
        }
    }
}

/// Opaque provider — holds all the stores and dispatches requests.
#[derive(Clone)]
pub struct Provider {
    config: ProviderConfig,
    client_store: ClientStore,
    session_store: SessionStore,
    user_store: Arc<dyn UserStore>,
    jwks: Jwks,
}

impl Provider {
    /// Construct a provider.
    pub fn new(
        config: ProviderConfig,
        client_store: ClientStore,
        session_store: SessionStore,
        user_store: Arc<dyn UserStore>,
        jwks: Jwks,
    ) -> Self {
        Self {
            config,
            client_store,
            session_store,
            user_store,
            jwks,
        }
    }

    /// Access the JWKS (for serving `/.well-known/jwks.json`).
    pub fn jwks(&self) -> &Jwks {
        &self.jwks
    }

    /// Access the configuration.
    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// Access the client store (for dynamic client registration
    /// endpoint).
    pub fn client_store(&self) -> &ClientStore {
        &self.client_store
    }

    /// Access the session store (for credentials-flow, logout, etc).
    pub fn session_store(&self) -> &SessionStore {
        &self.session_store
    }

    /// Access the underlying [`UserStore`] through a trait object.
    /// Used by the optional axum binder to share one user store
    /// across the /credentials handler and the /auth handler.
    pub fn user_store_trait_object(&self) -> &dyn UserStore {
        self.user_store.as_ref()
    }

    /// Render the discovery document for the configured issuer.
    pub fn discovery_document(&self) -> crate::discovery::DiscoveryDocument {
        crate::discovery::build_discovery(&self.config.issuer)
    }

    /// Start the authorization-code flow.
    ///
    /// Returns [`AuthorizeResponse::Redirect`] on success (a code
    /// has been minted and the client should receive a 302 to
    /// `redirect_uri?code=<code>&state=<state>`), or
    /// [`AuthorizeResponse::NeedsLogin`] when there is no active
    /// session for the current request.
    pub async fn authorize(
        &self,
        req: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, ProviderError> {
        // 1. Validate client.
        let client = self
            .client_store
            .find(&req.client_id)
            .await
            .map_err(|e| ProviderError::ClientDocument(e.to_string()))?
            .ok_or_else(|| ProviderError::InvalidClient(format!("unknown: {}", req.client_id)))?;

        // 2. response_type MUST be "code".
        if req.response_type != "code" {
            return Err(ProviderError::InvalidRequest(format!(
                "response_type must be 'code', got '{}'",
                req.response_type
            )));
        }

        // 3. Validate redirect_uri against the registered set.
        if !client.redirect_uris.iter().any(|r| r == &req.redirect_uri) {
            return Err(ProviderError::InvalidRequest(format!(
                "redirect_uri not registered: {}",
                req.redirect_uri
            )));
        }

        // 4. PKCE is mandatory for public clients under Solid-OIDC.
        //    We enforce it for everyone to match JSS
        //    (`provider.js:346 — pkce.required = () => true`).
        if req.code_challenge_method.as_deref() != Some("S256") {
            return Err(ProviderError::InvalidRequest(
                "PKCE S256 is required (code_challenge_method)".into(),
            ));
        }
        if req.code_challenge.is_none() {
            return Err(ProviderError::InvalidRequest(
                "code_challenge is required".into(),
            ));
        }

        // 5. Session gate. If we have one, we can mint a code now.
        match req.session_account_id {
            None => Ok(AuthorizeResponse::NeedsLogin {
                client_id: req.client_id,
                redirect_uri: req.redirect_uri,
                state: req.state,
                code_challenge: req.code_challenge,
                scope: req.scope,
            }),
            Some(account_id) => {
                let code = self.session_store.issue_code(
                    &client.client_id,
                    account_id,
                    &req.redirect_uri,
                    req.code_challenge.clone(),
                    req.scope.clone(),
                );
                Ok(AuthorizeResponse::Redirect {
                    redirect_uri: req.redirect_uri,
                    code: code.code,
                    state: req.state,
                    iss: self.config.issuer.clone(),
                })
            }
        }
    }

    /// Exchange an authorization code at `/token`.
    ///
    /// Requires a valid DPoP proof whose `htu` / `htm` match
    /// `POST {issuer}/idp/token`. The returned access token is
    /// bound to the proof's JWK thumbprint (`cnf.jkt`).
    pub async fn token(&self, req: TokenRequest<'_>) -> Result<TokenResponse, ProviderError> {
        if req.grant_type != "authorization_code" {
            return Err(ProviderError::InvalidRequest(format!(
                "grant_type must be 'authorization_code', got '{}'",
                req.grant_type
            )));
        }

        // Verify DPoP proof first — this is a REQUIRED header for
        // Solid-OIDC /token. Without it we won't bind cnf.jkt.
        let dpop_proof = req
            .dpop_proof
            .ok_or_else(|| ProviderError::InvalidDpop("missing DPoP header".into()))?;

        let expected_htu = format!(
            "{}/idp/token",
            self.config.issuer.trim_end_matches('/')
        );
        let verified = verify_dpop_proof(
            dpop_proof,
            &expected_htu,
            "POST",
            req.now_unix,
            self.config.dpop_skew_secs,
            None, // replay cache: consumer can plumb this later
        )
        .await
        .map_err(|e| ProviderError::InvalidDpop(e.to_string()))?;
        let jkt = verified.jkt;

        // Consume the code (single-use).
        let code: AuthCodeRecord = self
            .session_store
            .take_code(req.code)
            .ok_or_else(|| ProviderError::InvalidGrant("code expired or unknown".into()))?;

        // Client + redirect_uri binding checks.
        if code.client_id != req.client_id {
            return Err(ProviderError::InvalidGrant(
                "code issued to different client_id".into(),
            ));
        }
        if code.redirect_uri != req.redirect_uri {
            return Err(ProviderError::InvalidGrant(
                "redirect_uri mismatch".into(),
            ));
        }

        // PKCE check — the challenge stored at /auth must match
        // SHA256(verifier) base64url-noPad.
        if let Some(challenge) = &code.code_challenge {
            let verifier = req.code_verifier.ok_or_else(|| {
                ProviderError::InvalidRequest("code_verifier required for PKCE".into())
            })?;
            let computed = pkce_s256(verifier);
            if &computed != challenge {
                return Err(ProviderError::InvalidGrant(
                    "PKCE verifier mismatch".into(),
                ));
            }
        }

        // Resolve the account → webid.
        let user = self
            .user_store
            .find_by_id(&code.account_id)
            .await
            .map_err(|e| ProviderError::UserStore(e.to_string()))?
            .ok_or_else(|| ProviderError::InvalidGrant("account not found".into()))?;

        // Sign the access token.
        let key = self.jwks.active_key();
        let token: AccessToken = issue_access_token(
            &key,
            &self.config.issuer,
            &user.webid,
            &user.id,
            &code.client_id,
            code.requested_scope.as_deref().unwrap_or("openid webid"),
            Some(&jkt),
            req.now_unix,
            self.config.access_token_ttl_secs,
        )
        .map_err(|e| ProviderError::Crypto(e.to_string()))?;

        debug!(client_id = %code.client_id, webid = %user.webid, "issued DPoP-bound access token");

        Ok(TokenResponse {
            access_token: token.jwt,
            token_type: "DPoP".into(),
            expires_in: self.config.access_token_ttl_secs,
            scope: token.payload.scope,
            webid: Some(user.webid),
        })
    }

    /// Resolve a bearer-authenticated request to [`UserInfo`].
    /// Verifies the access token (ES256 signed by our JWKS) and
    /// matches its `cnf.jkt` against the supplied DPoP thumbprint.
    pub async fn userinfo(
        &self,
        access_token: &str,
        dpop_jkt: &str,
        now_unix: u64,
    ) -> Result<UserInfo, ProviderError> {
        // Build an asymmetric JwkSet from our published JWKS so we
        // can route back through the core verifier. This is a little
        // roundabout (we just signed the token ourselves) but using
        // the same verification path the resource server would use
        // catches sign/verify drift.
        let keyset = build_jwk_set(&self.jwks);
        let v = solid_pod_rs::oidc::verify_access_token(
            access_token,
            &solid_pod_rs::oidc::TokenVerifyKey::Asymmetric(keyset),
            &self.config.issuer,
            dpop_jkt,
            now_unix,
        )
        .map_err(|e| ProviderError::InvalidDpop(e.to_string()))?;

        Ok(UserInfo {
            webid: v.webid.clone(),
            sub: v.webid,
            client_id: v.client_id,
            scope: v.scope,
        })
    }
}

/// Convert our internal [`Jwks`] to the `jsonwebtoken::jwk::JwkSet`
/// shape the core verifier expects.
fn build_jwk_set(jwks: &Jwks) -> jsonwebtoken::jwk::JwkSet {
    let doc = jwks.public_document();
    let keys: Vec<jsonwebtoken::jwk::Jwk> = doc
        .keys
        .iter()
        .filter_map(|k| serde_json::to_value(k).ok())
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    jsonwebtoken::jwk::JwkSet { keys }
}

/// Base64url-noPad SHA256 — PKCE S256 (`RFC 7636 §4.6`).
fn pkce_s256(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    B64.encode(hash)
}

/// Input to [`Provider::authorize`].
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    /// OAuth2 client id (opaque or Client Identifier Document URL).
    pub client_id: String,
    /// Always `"code"` for Solid-OIDC.
    pub response_type: String,
    /// Callback URL. Must be one of the client's registered
    /// `redirect_uris`.
    pub redirect_uri: String,
    /// OAuth2 state (echoed back in the redirect).
    pub state: Option<String>,
    /// PKCE code challenge (`S256` hash of the verifier).
    pub code_challenge: Option<String>,
    /// PKCE method — must be `"S256"`.
    pub code_challenge_method: Option<String>,
    /// Requested scope string (e.g. `"openid webid"`).
    pub scope: Option<String>,
    /// Account id from the caller's session cookie. `None` means
    /// no active session → the consumer must render a login page
    /// and re-call `authorize` with `session_account_id = Some(...)`.
    pub session_account_id: Option<String>,
}

/// Output of [`Provider::authorize`].
#[derive(Debug, Clone)]
pub enum AuthorizeResponse {
    /// Session already authenticated — emit a 302 to the redirect
    /// URI with the returned `code` + optional `state`.
    Redirect {
        /// Target redirect URI (verbatim from the request).
        redirect_uri: String,
        /// Single-use authorisation code.
        code: String,
        /// OAuth2 `state` parameter, echoed back.
        state: Option<String>,
        /// RFC 9207 `iss` response parameter.
        iss: String,
    },
    /// Consumer must render a login page and re-submit.
    NeedsLogin {
        /// Echo of the `/auth` params so the consumer can bundle
        /// them into the login form and re-enter `authorize` after
        /// the user authenticates.
        client_id: String,
        /// Callback URL.
        redirect_uri: String,
        /// OAuth2 state.
        state: Option<String>,
        /// PKCE code challenge.
        code_challenge: Option<String>,
        /// Requested scope.
        scope: Option<String>,
    },
}

/// Input to [`Provider::token`].
#[derive(Debug, Clone)]
pub struct TokenRequest<'a> {
    /// Always `"authorization_code"` for Sprint-10 scope.
    pub grant_type: String,
    /// Single-use code returned by `/auth`.
    pub code: &'a str,
    /// Redirect URI that was used at `/auth` (must match).
    pub redirect_uri: String,
    /// Client id.
    pub client_id: String,
    /// PKCE code verifier (required when challenge was set).
    pub code_verifier: Option<&'a str>,
    /// Raw DPoP proof JWT (the `DPoP:` request header value).
    pub dpop_proof: Option<&'a str>,
    /// Current Unix-seconds timestamp (injected for tests).
    pub now_unix: u64,
}

/// `/token` response body — RFC 6749 §5.1 shape plus Solid-OIDC
/// `webid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Signed JWT access token.
    pub access_token: String,
    /// Always `"DPoP"` today.
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Granted scope.
    pub scope: String,
    /// Convenience copy of the authenticated WebID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webid: Option<String>,
}

/// Response shape for `/idp/me` (JSS parity —
/// `userinfo_endpoint`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Subject WebID.
    pub sub: String,
    /// Duplicate of `sub` for Solid-OIDC clients that look for a
    /// `webid` claim by name.
    pub webid: String,
    /// Client id that minted the active token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// OAuth2 scope string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}


#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rand::Rng;
    use serde_json::json;

    use crate::registration::{register_client, ClientDocument, RegistrationRequest};
    use crate::user_store::InMemoryUserStore;

    async fn seed_provider() -> (Provider, InMemoryUserStore, ClientDocument, String) {
        let store = Arc::new(InMemoryUserStore::new());
        store
            .insert_user(
                "acct-1",
                "alice@example.com",
                "https://alice.example/profile#me",
                None,
                "hunter2",
            )
            .unwrap();
        let jwks = Jwks::generate_es256().unwrap();
        let clients = ClientStore::new();
        let client = register_client(
            &clients,
            RegistrationRequest {
                redirect_uris: vec!["https://app.example/cb".into()],
                client_name: Some("TestApp".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let sessions = SessionStore::new();
        let cfg = ProviderConfig::new("https://pod.example/");
        let provider = Provider::new(cfg, clients, sessions, store.clone() as Arc<dyn UserStore>, jwks);

        let verifier: String = (0..43)
            .map(|_| {
                let c = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
                c[rand::thread_rng().gen_range(0..c.len())] as char
            })
            .collect();

        (provider, InMemoryUserStore::new(), client, verifier)
    }

    fn s256(s: &str) -> String {
        use sha2::{Digest, Sha256};
        B64.encode(Sha256::digest(s.as_bytes()))
    }

    /// Build an HS256-signed DPoP proof with `kty=oct` — the core
    /// DPoP verifier has an explicit test path for this (see
    /// `solid-pod-rs/src/oidc/mod.rs:553-563`).
    fn test_dpop_proof(htu: &str, htm: &str, iat: u64) -> String {
        // oct JWK — 32 random bytes, base64url-noPad.
        let mut sec = [0u8; 32];
        rand::thread_rng().fill(&mut sec);
        let k = B64.encode(sec);
        let jwk = json!({
            "kty": "oct",
            "k": k,
        });
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(serde_json::from_value(jwk).unwrap());
        let claims = json!({
            "htu": htu,
            "htm": htm,
            "iat": iat,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        encode(&header, &claims, &EncodingKey::from_secret(&sec)).unwrap()
    }

    #[tokio::test]
    async fn authorize_needs_login_without_session() {
        let (p, _, client, _) = seed_provider().await;
        let req = AuthorizeRequest {
            client_id: client.client_id.clone(),
            response_type: "code".into(),
            redirect_uri: "https://app.example/cb".into(),
            state: Some("xyz".into()),
            code_challenge: Some(s256("verifier-1")),
            code_challenge_method: Some("S256".into()),
            scope: Some("openid webid".into()),
            session_account_id: None,
        };
        match p.authorize(req).await.unwrap() {
            AuthorizeResponse::NeedsLogin { client_id, .. } => {
                assert_eq!(client_id, client.client_id);
            }
            other => panic!("expected NeedsLogin, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_issues_code_when_logged_in() {
        let (p, _, client, verifier) = seed_provider().await;
        let challenge = s256(&verifier);
        let req = AuthorizeRequest {
            client_id: client.client_id.clone(),
            response_type: "code".into(),
            redirect_uri: "https://app.example/cb".into(),
            state: Some("state-1".into()),
            code_challenge: Some(challenge),
            code_challenge_method: Some("S256".into()),
            scope: Some("openid webid".into()),
            session_account_id: Some("acct-1".into()),
        };
        match p.authorize(req).await.unwrap() {
            AuthorizeResponse::Redirect {
                redirect_uri,
                code,
                state,
                iss,
            } => {
                assert_eq!(redirect_uri, "https://app.example/cb");
                assert!(!code.is_empty());
                assert_eq!(state.as_deref(), Some("state-1"));
                assert!(iss.contains("pod.example"));
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_rejects_unregistered_redirect_uri() {
        let (p, _, client, verifier) = seed_provider().await;
        let req = AuthorizeRequest {
            client_id: client.client_id.clone(),
            response_type: "code".into(),
            redirect_uri: "https://evil.example/steal".into(),
            state: None,
            code_challenge: Some(s256(&verifier)),
            code_challenge_method: Some("S256".into()),
            scope: Some("openid".into()),
            session_account_id: Some("acct-1".into()),
        };
        let err = p.authorize(req).await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn authorize_rejects_without_pkce() {
        let (p, _, client, _) = seed_provider().await;
        let req = AuthorizeRequest {
            client_id: client.client_id.clone(),
            response_type: "code".into(),
            redirect_uri: "https://app.example/cb".into(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            scope: Some("openid".into()),
            session_account_id: Some("acct-1".into()),
        };
        let err = p.authorize(req).await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn token_endpoint_rejects_without_dpop() {
        let (p, _, client, verifier) = seed_provider().await;
        // First mint a code.
        let auth = p
            .authorize(AuthorizeRequest {
                client_id: client.client_id.clone(),
                response_type: "code".into(),
                redirect_uri: "https://app.example/cb".into(),
                state: None,
                code_challenge: Some(s256(&verifier)),
                code_challenge_method: Some("S256".into()),
                scope: Some("openid webid".into()),
                session_account_id: Some("acct-1".into()),
            })
            .await
            .unwrap();
        let code = match auth {
            AuthorizeResponse::Redirect { code, .. } => code,
            _ => panic!(),
        };

        let err = p
            .token(TokenRequest {
                grant_type: "authorization_code".into(),
                code: &code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: client.client_id.clone(),
                code_verifier: Some(&verifier),
                dpop_proof: None,
                now_unix: 1_700_000_000,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidDpop(_)));
    }

    #[tokio::test]
    async fn token_endpoint_rejects_dpop_with_wrong_htu() {
        let (p, _, client, verifier) = seed_provider().await;
        let auth = p
            .authorize(AuthorizeRequest {
                client_id: client.client_id.clone(),
                response_type: "code".into(),
                redirect_uri: "https://app.example/cb".into(),
                state: None,
                code_challenge: Some(s256(&verifier)),
                code_challenge_method: Some("S256".into()),
                scope: Some("openid webid".into()),
                session_account_id: Some("acct-1".into()),
            })
            .await
            .unwrap();
        let code = match auth {
            AuthorizeResponse::Redirect { code, .. } => code,
            _ => panic!(),
        };

        let wrong_htu = "https://evil.example/idp/token";
        let proof = test_dpop_proof(wrong_htu, "POST", 1_700_000_000);
        let err = p
            .token(TokenRequest {
                grant_type: "authorization_code".into(),
                code: &code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: client.client_id.clone(),
                code_verifier: Some(&verifier),
                dpop_proof: Some(&proof),
                now_unix: 1_700_000_000,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidDpop(_)));
    }

    #[tokio::test]
    async fn authorization_code_flow_end_to_end() {
        let (p, _, client, verifier) = seed_provider().await;

        let auth = p
            .authorize(AuthorizeRequest {
                client_id: client.client_id.clone(),
                response_type: "code".into(),
                redirect_uri: "https://app.example/cb".into(),
                state: Some("s-1".into()),
                code_challenge: Some(s256(&verifier)),
                code_challenge_method: Some("S256".into()),
                scope: Some("openid webid".into()),
                session_account_id: Some("acct-1".into()),
            })
            .await
            .unwrap();
        let code = match auth {
            AuthorizeResponse::Redirect { code, .. } => code,
            _ => panic!(),
        };

        let proof = test_dpop_proof("https://pod.example/idp/token", "POST", 1_700_000_000);
        let tok = p
            .token(TokenRequest {
                grant_type: "authorization_code".into(),
                code: &code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: client.client_id.clone(),
                code_verifier: Some(&verifier),
                dpop_proof: Some(&proof),
                now_unix: 1_700_000_000,
            })
            .await
            .unwrap();
        assert_eq!(tok.token_type, "DPoP");
        assert!(tok.access_token.contains('.'));
        assert_eq!(tok.expires_in, 3600);
        assert_eq!(tok.webid.as_deref(), Some("https://alice.example/profile#me"));

        // Second redemption must fail — code is single-use.
        let proof2 = test_dpop_proof("https://pod.example/idp/token", "POST", 1_700_000_000);
        let err = p
            .token(TokenRequest {
                grant_type: "authorization_code".into(),
                code: &code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: client.client_id.clone(),
                code_verifier: Some(&verifier),
                dpop_proof: Some(&proof2),
                now_unix: 1_700_000_000,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidGrant(_)));
    }

    #[tokio::test]
    async fn token_endpoint_rejects_pkce_verifier_mismatch() {
        let (p, _, client, verifier) = seed_provider().await;
        let auth = p
            .authorize(AuthorizeRequest {
                client_id: client.client_id.clone(),
                response_type: "code".into(),
                redirect_uri: "https://app.example/cb".into(),
                state: None,
                code_challenge: Some(s256(&verifier)),
                code_challenge_method: Some("S256".into()),
                scope: Some("openid webid".into()),
                session_account_id: Some("acct-1".into()),
            })
            .await
            .unwrap();
        let code = match auth {
            AuthorizeResponse::Redirect { code, .. } => code,
            _ => panic!(),
        };
        let proof = test_dpop_proof("https://pod.example/idp/token", "POST", 1_700_000_000);
        let err = p
            .token(TokenRequest {
                grant_type: "authorization_code".into(),
                code: &code,
                redirect_uri: "https://app.example/cb".into(),
                client_id: client.client_id.clone(),
                code_verifier: Some("totally-wrong-verifier"),
                dpop_proof: Some(&proof),
                now_unix: 1_700_000_000,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::InvalidGrant(_)));
    }
}
