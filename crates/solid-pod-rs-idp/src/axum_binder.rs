//! Optional axum Router factory (feature: `axum-binder`).
//!
//! Wires [`Provider`] + [`Jwks`] into a minimal axum Router covering
//! the always-on endpoints:
//!
//! | Path                              | Method | Purpose                              |
//! |-----------------------------------|--------|--------------------------------------|
//! | `/.well-known/openid-configuration` | GET    | Discovery document                   |
//! | `/.well-known/jwks.json`            | GET    | Public JWKS                          |
//! | `/idp/reg`                          | POST   | Dynamic Client Registration          |
//! | `/idp/credentials`                  | POST   | Email+password login                 |
//! | `/idp/credentials`                  | PUT    | Self-service password change         |
//! | `/idp/account`                      | DELETE | Self-service account deletion        |
//!
//! `/auth` and `/token` are deliberately NOT mounted here because
//! their request shape is richer than what a generic binder can
//! express (session cookies, form-encoded bodies with redirects,
//! etc). Consumers wire those two endpoints against their own
//! session / CSRF middleware and call [`Provider::authorize`] /
//! [`Provider::token`] directly.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::Deserialize;
use solid_pod_rs::security::rate_limit::RateLimiter;

use crate::account_delete::{
    delete_account, AccountDeleteError, AccountDeleteRequest, AccountDeleteResponse,
};
use crate::credentials::{login, CredentialsResponse, LoginError};
use crate::discovery::build_discovery;
use crate::jwks::JwksDocument;
use crate::password_change::{
    change_password, PasswordChangeError, PasswordChangeRequest, PasswordChangeResponse,
};
use crate::provider::Provider;
use crate::registration::{register_client, ClientDocument, RegistrationRequest};

/// Shared state for the bundled Axum Router.
#[derive(Clone)]
pub struct IdpState {
    /// The provider.
    pub provider: Provider,
    /// Rate limiter for `/idp/credentials`.
    pub limiter: Arc<dyn RateLimiter>,
}

/// Build an axum Router with the always-on routes.
pub fn router(state: IdpState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery_handler))
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/idp/reg", post(registration_handler))
        .route(
            "/idp/credentials",
            post(credentials_handler).put(password_change_handler),
        )
        .route("/idp/account", delete(account_delete_handler))
        .with_state(state)
}

async fn discovery_handler(
    State(st): State<IdpState>,
) -> Json<crate::discovery::DiscoveryDocument> {
    Json(build_discovery(&st.provider.config().issuer))
}

async fn jwks_handler(State(st): State<IdpState>) -> Json<JwksDocument> {
    Json(st.provider.jwks().public_document())
}

async fn registration_handler(
    State(st): State<IdpState>,
    Json(req): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<ClientDocument>), AxumErr> {
    let doc = register_client(st.provider.client_store(), req)
        .await
        .map_err(|e| AxumErr(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(doc)))
}

/// `/idp/credentials` request body (JSON only for this binder; form
/// decoding is the consumer's job if they need it).
#[derive(Debug, Deserialize)]
struct CredentialsBody {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
    password: String,
}

async fn credentials_handler(
    State(st): State<IdpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<CredentialsBody>,
) -> Result<Json<CredentialsResponse>, AxumErr> {
    let email = body.email.or(body.username).unwrap_or_default();
    let ip: IpAddr = peer.ip();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let resp = login(
        &email,
        &body.password,
        // This binder requires the consumer to share their user store
        // via a trait-object stored on the provider. In Sprint 10 we
        // expose it via the provider; see
        // `Provider::user_store_trait_object` below if you need it.
        st.provider.user_store_trait_object(),
        st.provider.jwks(),
        &st.provider.config().issuer,
        None,
        st.limiter.as_ref(),
        ip,
        now,
        3600,
    )
    .await
    .map_err(|e| match e {
        LoginError::RateLimited { retry_after_secs } => AxumErr(
            StatusCode::TOO_MANY_REQUESTS,
            format!("retry after {retry_after_secs}s"),
        ),
        LoginError::InvalidGrant => AxumErr(StatusCode::UNAUTHORIZED, "invalid_grant".into()),
        LoginError::InvalidRequest(m) => AxumErr(StatusCode::BAD_REQUEST, m),
        LoginError::PasswordTooShort { min_length } => AxumErr(
            StatusCode::BAD_REQUEST,
            format!("password must be at least {min_length} characters"),
        ),
        other => AxumErr(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;

    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// PUT /idp/credentials — self-service password change
// ---------------------------------------------------------------------------

/// Request body for `PUT /idp/credentials`.
///
/// Authentication is validated via the `Authorization` header by the
/// transport layer before this handler runs; the handler receives the
/// authenticated user id from the header (see `extract_user_id_header`).
#[derive(Debug, Deserialize)]
struct PasswordChangeBody {
    current_password: String,
    new_password: String,
}

/// Extract the authenticated user id from the `X-Authenticated-User`
/// header. The transport layer is responsible for populating this after
/// validating the access token or session. This decouples the binder
/// from a particular auth middleware.
fn extract_user_id_header(headers: &axum::http::HeaderMap) -> Result<String, AxumErr> {
    headers
        .get("X-Authenticated-User")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AxumErr(StatusCode::UNAUTHORIZED, "authentication required".into()))
}

async fn password_change_handler(
    State(st): State<IdpState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> Result<Json<PasswordChangeResponse>, AxumErr> {
    let user_id = extract_user_id_header(&headers)?;
    let ip: IpAddr = peer.ip();

    let req = PasswordChangeRequest {
        current_password: body.current_password,
        new_password: body.new_password,
    };

    change_password(
        &user_id,
        &req,
        st.provider.user_store_trait_object(),
        st.limiter.as_ref(),
        ip,
    )
    .await
    .map(Json)
    .map_err(|e| match e {
        PasswordChangeError::RateLimited { retry_after_secs } => AxumErr(
            StatusCode::TOO_MANY_REQUESTS,
            format!("retry after {retry_after_secs}s"),
        ),
        PasswordChangeError::InvalidCurrentPassword => {
            AxumErr(StatusCode::UNAUTHORIZED, "invalid current password".into())
        }
        PasswordChangeError::PasswordTooShort { min_length } => AxumErr(
            StatusCode::BAD_REQUEST,
            format!("new password must be at least {min_length} characters"),
        ),
        PasswordChangeError::InvalidRequest(m) => AxumErr(StatusCode::BAD_REQUEST, m),
        other => AxumErr(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })
}

// ---------------------------------------------------------------------------
// DELETE /idp/account — self-service account deletion
// ---------------------------------------------------------------------------

/// Request body for `DELETE /idp/account`.
#[derive(Debug, Deserialize)]
struct AccountDeleteBody {
    confirmation: String,
}

async fn account_delete_handler(
    State(st): State<IdpState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AccountDeleteBody>,
) -> Result<Json<AccountDeleteResponse>, AxumErr> {
    let user_id = extract_user_id_header(&headers)?;

    let req = AccountDeleteRequest {
        confirmation: body.confirmation,
    };

    delete_account(&user_id, &req, st.provider.user_store_trait_object())
        .await
        .map(Json)
        .map_err(|e| match e {
            AccountDeleteError::ConfirmationMismatch { expected } => AxumErr(
                StatusCode::BAD_REQUEST,
                format!("confirmation must be exactly \"{expected}\""),
            ),
            AccountDeleteError::NotFound => AxumErr(StatusCode::NOT_FOUND, "user not found".into()),
            AccountDeleteError::NotImplemented => AxumErr(
                StatusCode::NOT_IMPLEMENTED,
                "account deletion not supported".into(),
            ),
            other => AxumErr(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })
}

// ---------------------------------------------------------------------------

struct AxumErr(StatusCode, String);

impl IntoResponse for AxumErr {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}
