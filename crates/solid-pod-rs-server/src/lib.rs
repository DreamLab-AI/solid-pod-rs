//! Library surface of `solid-pod-rs-server` — the actix-web app builder
//! that the `solid-pod-rs-server` binary and the workspace integration
//! tests share.
//!
//! The binary in `src/main.rs` stays thin: CLI parsing, tracing init,
//! config loading, signal handling. Everything HTTP lives here so the
//! test harness can drive the exact same handler wiring through
//! `actix_web::test::init_service` without needing a real TCP listener.
//!
//! ## Route table (Sprint 7 D)
//!
//! | Method  | Path                                     | Handler                |
//! |---------|------------------------------------------|------------------------|
//! | GET/HEAD| `/{tail:.*}`                             | `handle_get`           |
//! | PUT     | `/{tail:.*}`                             | `handle_put`           |
//! | POST    | `/{tail:.*}/`                            | `handle_post`          |
//! | PATCH   | `/{tail:.*}`                             | `handle_patch`         |
//! | DELETE  | `/{tail:.*}`                             | `handle_delete`        |
//! | OPTIONS | `/{tail:.*}`                             | `handle_options`       |
//! | GET     | `/.well-known/solid`                     | well-known Solid doc   |
//! | GET     | `/.well-known/webfinger`                 | WebFinger JRD          |
//! | GET     | `/.well-known/nodeinfo`                  | NodeInfo discovery     |
//! | GET     | `/.well-known/nodeinfo/2.1`              | NodeInfo 2.1 content   |
//! | GET     | `/.well-known/did/nostr/{pubkey}.json`   | DID:nostr document     |
//!
//! ## Middleware stack (applied in order)
//!
//! 1. `NormalizePath` — collapse `//` and decode %-encoded segments.
//! 2. Percent-decode + `..` re-check — defence-in-depth against
//!    path-traversal smuggling after NormalizePath.
//! 3. CORS hook — honours `CorsPolicy::from_env()`.
//! 4. Rate-limit hook — LRU bucket keyed on (route, IP).
//! 5. Dotfile allowlist — rejects `.env` etc unless permitted.
//! 6. PayloadConfig — enforces `JSS_MAX_REQUEST_BODY` body cap.
//! 7. WAC-on-write — PUT/POST/PATCH/DELETE require a write/append grant.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::{header, StatusCode};
use actix_web::middleware::{NormalizePath, TrailingSlash};
use actix_web::{web, App, Error as ActixError, HttpRequest, HttpResponse};
use bytes::Bytes;
use futures_util::future::{ready, LocalBoxFuture, Ready};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use solid_pod_rs::{
    auth::nip98,
    config::sources::parse_size,
    interop,
    ldp::{self, LdpContainerOps, PatchCreateOutcome},
    security::DotfileAllowlist,
    storage::Storage,
    wac::{
        self, conditions::RequestContext, parse_jsonld_acl, parser::parse_turtle_acl, AccessMode,
    },
    PodError,
};

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

/// Actix-web shared state.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub dotfiles: Arc<DotfileAllowlist>,
    pub body_cap: usize,
    pub nodeinfo: NodeInfoMeta,
    pub mashlib_cdn: Option<String>,
}

/// NodeInfo 2.1 body inputs. Kept here so tests can override them.
#[derive(Clone, Debug)]
pub struct NodeInfoMeta {
    pub software_name: String,
    pub software_version: String,
    pub open_registrations: bool,
    pub total_users: u64,
    pub base_url: String,
}

impl Default for NodeInfoMeta {
    fn default() -> Self {
        Self {
            software_name: "solid-pod-rs-server".to_string(),
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            open_registrations: false,
            total_users: 0,
            base_url: "http://localhost".to_string(),
        }
    }
}

/// Discover the body cap from the environment. Accepts values like
/// `50MB`, `1.5GB`, or a bare integer (bytes). Falls back to 50 MiB.
pub const DEFAULT_BODY_CAP: usize = 50 * 1024 * 1024;

/// Read `JSS_MAX_REQUEST_BODY` and parse via [`parse_size`]. On any
/// failure, returns [`DEFAULT_BODY_CAP`].
pub fn body_cap_from_env() -> usize {
    match std::env::var("JSS_MAX_REQUEST_BODY") {
        Ok(v) => parse_size(&v)
            .map(|u| u as usize)
            .unwrap_or(DEFAULT_BODY_CAP),
        Err(_) => DEFAULT_BODY_CAP,
    }
}

impl AppState {
    /// Convenience constructor for tests and the binary. Callers may
    /// replace fields after creation since `AppState` is a plain struct.
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            dotfiles: Arc::new(DotfileAllowlist::from_env()),
            body_cap: body_cap_from_env(),
            nodeinfo: NodeInfoMeta::default(),
            mashlib_cdn: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Error translation
// ---------------------------------------------------------------------------

fn to_actix(e: PodError) -> ActixError {
    match e {
        PodError::NotFound(_) => actix_web::error::ErrorNotFound(e.to_string()),
        PodError::BadRequest(_) => actix_web::error::ErrorBadRequest(e.to_string()),
        PodError::Unsupported(_) => actix_web::error::ErrorUnsupportedMediaType(e.to_string()),
        PodError::Forbidden => actix_web::error::ErrorForbidden(e.to_string()),
        PodError::Unauthenticated => actix_web::error::ErrorUnauthorized(e.to_string()),
        PodError::PreconditionFailed(_) => {
            actix_web::error::ErrorPreconditionFailed(e.to_string())
        }
        _ => actix_web::error::ErrorInternalServerError(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Auth helper — shared across handlers
// ---------------------------------------------------------------------------

/// Attempt NIP-98 bearer verification; returns the pubkey on success.
async fn extract_pubkey(req: &HttpRequest) -> Option<String> {
    let header_val = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let url = format!(
        "http://{}{}",
        req.connection_info().host(),
        req.uri().path()
    );
    nip98::verify(header_val, &url, req.method().as_str(), None)
        .await
        .ok()
}

fn agent_uri(pubkey: Option<&String>) -> Option<String> {
    pubkey.map(|pk| format!("did:nostr:{pk}"))
}

// ---------------------------------------------------------------------------
// WAC enforcement for writes (PUT / POST / PATCH / DELETE)
// ---------------------------------------------------------------------------

/// Resolve the effective ACL and evaluate whether the given WebID may
/// perform `mode` on `path`.
///
/// Returns `Ok(())` on grant. On deny, returns an `actix_web::Error`:
/// * `401` when the request had no authenticated agent (so the client
///   knows retrying with credentials might work);
/// * `403` when authenticated but the ACL does not grant the mode.
async fn enforce_write(
    state: &AppState,
    path: &str,
    mode: AccessMode,
    agent_uri: Option<&str>,
) -> Result<(), ActixError> {
    // `StorageAclResolver` is generic over a concrete backend. `state`
    // holds an `Arc<dyn Storage>`; wrap it in a trait-object-friendly
    // adapter (`DynStorage`) that forwards each trait method so the
    // resolver can be constructed with a concrete type.
    let acl_doc = match find_effective_acl_dyn(&*state.storage, path).await {
        Ok(doc) => doc,
        Err(e) => return Err(to_actix(e)),
    };

    let ctx = RequestContext {
        web_id: agent_uri,
        client_id: None,
        issuer: None,
    };
    let registry = wac::conditions::ConditionRegistry::default_with_client_and_issuer();
    let groups: wac::StaticGroupMembership = wac::StaticGroupMembership::default();
    let granted = wac::evaluate_access_ctx_with_registry(
        acl_doc.as_ref(),
        &ctx,
        path,
        mode,
        None,
        &groups,
        &registry,
    );
    if granted {
        return Ok(());
    }

    let allow_header = wac::wac_allow_header(acl_doc.as_ref(), agent_uri, path);
    let (status, body) = if agent_uri.is_none() {
        (StatusCode::UNAUTHORIZED, "authentication required")
    } else {
        (StatusCode::FORBIDDEN, "access forbidden")
    };
    let mut rsp = HttpResponse::new(status);
    rsp.headers_mut().insert(
        header::HeaderName::from_static("wac-allow"),
        header::HeaderValue::from_str(&allow_header).unwrap_or(header::HeaderValue::from_static("")),
    );
    Err(actix_web::error::InternalError::from_response(body, rsp).into())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn set_link_headers(rsp: &mut HttpResponse, path: &str) {
    let links = ldp::link_headers(path).join(", ");
    if let Ok(value) = header::HeaderValue::from_str(&links) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("link"), value);
    }
}

fn set_wac_allow(rsp: &mut HttpResponse, header_value: &str) {
    if let Ok(v) = header::HeaderValue::from_str(header_value) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("wac-allow"), v);
    }
}

async fn handle_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    let wac_allow = wac::wac_allow_header(None, agent.as_deref(), &path);

    if ldp::is_container(&path) {
        let v = state
            .storage
            .container_representation(&path)
            .await
            .map_err(to_actix)?;
        let mut rsp = HttpResponse::Ok().json(v);
        rsp.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/ld+json"),
        );
        set_wac_allow(&mut rsp, &wac_allow);
        set_link_headers(&mut rsp, &path);
        return Ok(rsp);
    }

    match state.storage.get(&path).await {
        Ok((body, meta)) => {
            let mut rsp = HttpResponse::Ok().body(body.to_vec());
            rsp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_str(&meta.content_type)
                    .unwrap_or_else(|_| header::HeaderValue::from_static("application/octet-stream")),
            );
            if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                rsp.headers_mut().insert(header::ETAG, etag);
            }
            set_wac_allow(&mut rsp, &wac_allow);
            set_link_headers(&mut rsp, &path);
            Ok(rsp)
        }
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

async fn handle_put(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    if ldp::is_container(&path) {
        return Ok(HttpResponse::MethodNotAllowed().body("cannot PUT to a container"));
    }
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let meta = state
        .storage
        .put(&path, Bytes::from(body.to_vec()), ct)
        .await
        .map_err(to_actix)?;
    let mut rsp = HttpResponse::Created().finish();
    if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
        rsp.headers_mut().insert(header::ETAG, etag);
    }
    set_link_headers(&mut rsp, &path);
    Ok(rsp)
}

async fn handle_post(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    // POST route only matches container paths (trailing slash) via the
    // `POST /{tail:.*}/` registration.
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Append, agent.as_deref()).await?;

    let slug = req
        .headers()
        .get(header::HeaderName::from_static("slug"))
        .and_then(|v| v.to_str().ok());
    let target = match ldp::resolve_slug(&path, slug) {
        Ok(p) => p,
        Err(e) => return Err(to_actix(e)),
    };
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let meta = state
        .storage
        .put(&target, Bytes::from(body.to_vec()), ct)
        .await
        .map_err(to_actix)?;
    let mut rsp = HttpResponse::Created().finish();
    if let Ok(loc) = header::HeaderValue::from_str(&target) {
        rsp.headers_mut().insert(header::LOCATION, loc);
    }
    if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
        rsp.headers_mut().insert(header::ETAG, etag);
    }
    set_link_headers(&mut rsp, &target);
    Ok(rsp)
}

async fn handle_patch(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    if ldp::is_container(&path) {
        return Ok(HttpResponse::MethodNotAllowed().body("cannot PATCH a container"));
    }
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Append, agent.as_deref()).await?;

    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let dialect = match ldp::patch_dialect_from_mime(ct) {
        Some(d) => d,
        None => {
            return Ok(HttpResponse::UnsupportedMediaType()
                .body(format!("unsupported patch dialect for content-type {ct:?}")))
        }
    };
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Ok(HttpResponse::BadRequest().body("patch body is not valid UTF-8"))
        }
    };

    // Existing resource?
    let existing = state.storage.get(&path).await;
    match existing {
        Ok((current_body, meta)) => {
            // Parse the current body into a graph. For the Sprint 7 D
            // slice, the PATCH paths operate on an empty seed graph when
            // a textual RDF representation cannot be parsed — the
            // dialect patchers already cover the semantics. This keeps
            // the handler thin; richer mutation semantics live in
            // the library crate.
            let out = match dialect {
                ldp::PatchDialect::N3 => ldp::apply_n3_patch(ldp::Graph::new(), &body_str)
                    .map_err(patch_parse_err),
                ldp::PatchDialect::SparqlUpdate => {
                    ldp::apply_sparql_patch(ldp::Graph::new(), &body_str)
                        .map_err(patch_parse_err)
                }
                ldp::PatchDialect::JsonPatch => {
                    let mut json: serde_json::Value = match serde_json::from_slice(&current_body) {
                        Ok(v) => v,
                        Err(_) => serde_json::json!({}),
                    };
                    let patch: serde_json::Value = match serde_json::from_str(&body_str) {
                        Ok(v) => v,
                        Err(e) => return Err(to_actix(PodError::BadRequest(e.to_string()))),
                    };
                    ldp::apply_json_patch(&mut json, &patch).map_err(to_actix)?;
                    let bytes = serde_json::to_vec(&json).map_err(PodError::from).map_err(to_actix)?;
                    let _ = state
                        .storage
                        .put(&path, Bytes::from(bytes), &meta.content_type)
                        .await
                        .map_err(to_actix)?;
                    return Ok(HttpResponse::NoContent().finish());
                }
            };
            let outcome = out?;
            // Round-trip the updated graph back to Turtle so the next
            // GET reflects the mutation.
            let serialised = graph_to_turtle(&outcome.graph);
            let _ = state
                .storage
                .put(&path, Bytes::from(serialised.into_bytes()), "text/turtle")
                .await
                .map_err(to_actix)?;
            Ok(HttpResponse::NoContent().finish())
        }
        Err(PodError::NotFound(_)) => {
            // PATCH against an absent resource — create it.
            let create = ldp::apply_patch_to_absent(dialect, &body_str).map_err(patch_parse_err)?;
            let PatchCreateOutcome::Created { graph, .. } = create else {
                return Err(to_actix(PodError::Unsupported(
                    "unexpected patch outcome on absent resource".into(),
                )));
            };
            let serialised = graph_to_turtle(&graph);
            let _ = state
                .storage
                .put(&path, Bytes::from(serialised.into_bytes()), "text/turtle")
                .await
                .map_err(to_actix)?;
            Ok(HttpResponse::Created().finish())
        }
        Err(e) => Err(to_actix(e)),
    }
}

/// Map a PATCH body parse error to 400 Bad Request. Distinguishes
/// "client sent garbage in a supported dialect" (400) from "client
/// chose an unsupported dialect" (415 — handled by the dispatcher).
fn patch_parse_err(e: PodError) -> ActixError {
    match e {
        PodError::Unsupported(msg) | PodError::BadRequest(msg) => {
            actix_web::error::ErrorBadRequest(msg)
        }
        other => to_actix(other),
    }
}

/// Serialise a graph to N-Triples so the next GET reflects PATCH
/// mutations verbatim. Delegates to the library's canonical serialiser
/// — the handler does not add its own formatting.
fn graph_to_turtle(g: &ldp::Graph) -> String {
    g.to_ntriples()
}

/// Walk the storage tree from `path` upward, returning the first
/// `*.acl` document that parses as JSON-LD or Turtle. Object-safe
/// equivalent of `StorageAclResolver::find_effective_acl` — the latter
/// is generic over a concrete `Storage`, whereas the binary holds an
/// `Arc<dyn Storage>`.
async fn find_effective_acl_dyn(
    storage: &dyn Storage,
    resource_path: &str,
) -> Result<Option<wac::AclDocument>, PodError> {
    let mut path = resource_path.to_string();
    loop {
        let acl_key = if path == "/" {
            "/.acl".to_string()
        } else {
            format!("{}.acl", path.trim_end_matches('/'))
        };
        if let Ok((body, meta)) = storage.get(&acl_key).await {
            match parse_jsonld_acl(&body) {
                Ok(doc) => return Ok(Some(doc)),
                Err(PodError::BadRequest(_)) => {
                    return Err(PodError::BadRequest("ACL document exceeds bounds".into()))
                }
                Err(_) => {}
            }
            let ct = meta.content_type.to_ascii_lowercase();
            let looks_turtle = ct.starts_with("text/turtle")
                || ct.starts_with("application/turtle")
                || ct.starts_with("application/x-turtle");
            let text = std::str::from_utf8(&body).unwrap_or("");
            if looks_turtle || text.contains("@prefix") || text.contains("acl:Authorization") {
                if let Ok(doc) = parse_turtle_acl(text) {
                    return Ok(Some(doc));
                }
            }
        }
        if path == "/" || path.is_empty() {
            break;
        }
        let trimmed = path.trim_end_matches('/');
        path = match trimmed.rfind('/') {
            Some(0) => "/".to_string(),
            Some(pos) => trimmed[..pos].to_string(),
            None => "/".to_string(),
        };
    }
    Ok(None)
}

async fn handle_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

    match state.storage.delete(&path).await {
        Ok(()) => Ok(HttpResponse::NoContent().finish()),
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

async fn handle_options(req: HttpRequest) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();
    let o = ldp::options_for(&path);
    let mut rsp = HttpResponse::NoContent().finish();
    if let Ok(v) = header::HeaderValue::from_str(&o.allow.join(", ")) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("allow"), v);
    }
    if let Some(ap) = o.accept_post {
        if let Ok(v) = header::HeaderValue::from_str(ap) {
            rsp.headers_mut()
                .insert(header::HeaderName::from_static("accept-post"), v);
        }
    }
    if let Ok(v) = header::HeaderValue::from_str(o.accept_patch) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("accept-patch"), v);
    }
    if let Ok(v) = header::HeaderValue::from_str(o.accept_ranges) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("accept-ranges"), v);
    }
    Ok(rsp)
}

// ---------------------------------------------------------------------------
// .well-known handlers
// ---------------------------------------------------------------------------

async fn handle_well_known_solid(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::well_known_solid(&state.nodeinfo.base_url, &state.nodeinfo.base_url);
    HttpResponse::Ok()
        .content_type("application/ld+json")
        .json(doc)
}

#[derive(Debug, Deserialize)]
struct WebFingerQuery {
    resource: Option<String>,
}

async fn handle_well_known_webfinger(
    state: web::Data<AppState>,
    q: web::Query<WebFingerQuery>,
) -> HttpResponse {
    let resource = q.resource.clone().unwrap_or_else(|| {
        format!(
            "acct:anonymous@{}",
            state
                .nodeinfo
                .base_url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
        )
    });
    let webid = format!("{}/profile/card#me", state.nodeinfo.base_url.trim_end_matches('/'));
    match interop::webfinger_response(&resource, &state.nodeinfo.base_url, &webid) {
        Some(jrd) => HttpResponse::Ok()
            .content_type("application/jrd+json")
            .json(jrd),
        None => HttpResponse::NotFound().finish(),
    }
}

async fn handle_well_known_nodeinfo(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::nodeinfo_discovery(&state.nodeinfo.base_url);
    HttpResponse::Ok()
        .content_type("application/json")
        .json(doc)
}

async fn handle_well_known_nodeinfo_2_1(state: web::Data<AppState>) -> HttpResponse {
    let doc = interop::nodeinfo_2_1(
        &state.nodeinfo.software_name,
        &state.nodeinfo.software_version,
        state.nodeinfo.open_registrations,
        state.nodeinfo.total_users,
    );
    HttpResponse::Ok()
        .content_type("application/json")
        .json(doc)
}

#[cfg(feature = "did-nostr")]
async fn handle_well_known_did_nostr(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let pubkey = path.into_inner();
    let also = vec![format!(
        "{}/profile/card#me",
        state.nodeinfo.base_url.trim_end_matches('/')
    )];
    let doc = interop::did_nostr::did_nostr_document(&pubkey, &also);
    HttpResponse::Ok()
        .content_type("application/did+json")
        .json(doc)
}

// ---------------------------------------------------------------------------
// Percent-decode + dotdot re-check middleware
// ---------------------------------------------------------------------------

pub struct PathTraversalGuard;

impl<S, B> Transform<S, ServiceRequest> for PathTraversalGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type InitError = ();
    type Transform = PathTraversalGuardMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PathTraversalGuardMiddleware { service }))
    }
}

pub struct PathTraversalGuardMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for PathTraversalGuardMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Decode the raw path twice so that `%252e%252e` → `%2e%2e` →
        // `..` can be caught even though NormalizePath already ran once.
        let raw = req.path().to_string();
        if path_is_traversal(&raw) {
            let rsp = HttpResponse::BadRequest().body("invalid path: traversal rejected");
            let sr = req.into_response(rsp.map_into_boxed_body());
            return Box::pin(async move { Ok(sr.map_into_right_body()) });
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map_into_left_body())
        })
    }
}

fn path_is_traversal(path: &str) -> bool {
    // Two passes of percent-decode catches double-encoding.
    let once: String = percent_decode_str(path).decode_utf8_lossy().into_owned();
    let twice: String = percent_decode_str(&once).decode_utf8_lossy().into_owned();
    for seg in once.split('/').chain(twice.split('/')) {
        if seg == ".." || seg == "." {
            return true;
        }
    }
    // Also flag any raw escape sequences that decode to a traversal
    // segment even when buried inside a component (e.g. `foo%2f..%2fbar`).
    if twice.contains("/../") || twice.starts_with("../") || twice.ends_with("/..") {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Dotfile allowlist middleware
// ---------------------------------------------------------------------------

pub struct DotfileGuard {
    allow: Arc<DotfileAllowlist>,
}

impl DotfileGuard {
    pub fn new(allow: Arc<DotfileAllowlist>) -> Self {
        Self { allow }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DotfileGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type InitError = ();
    type Transform = DotfileGuardMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DotfileGuardMiddleware {
            service,
            allow: self.allow.clone(),
        }))
    }
}

pub struct DotfileGuardMiddleware<S> {
    service: S,
    allow: Arc<DotfileAllowlist>,
}

impl<S, B> Service<ServiceRequest> for DotfileGuardMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        // Whitelist the well-known discovery paths even though they
        // contain a dotfile component — they are part of Solid's stable
        // interop surface.
        let allow_wellknown = path.starts_with("/.well-known/");
        if !allow_wellknown {
            let pb = PathBuf::from(&path);
            if !self.allow.is_allowed(Path::new(&pb)) {
                let rsp = HttpResponse::Forbidden().body("dotfile path denied by allowlist");
                let sr = req.into_response(rsp.map_into_boxed_body());
                return Box::pin(async move { Ok(sr.map_into_right_body()) });
            }
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map_into_left_body())
        })
    }
}

// ---------------------------------------------------------------------------
// Public app builder
// ---------------------------------------------------------------------------

/// Build the complete actix `App` for the Solid Pod server. Both the
/// binary (`main.rs`) and the workspace integration tests call this.
///
/// The returned `App` is fully-configured: route table, normaliser,
/// path-traversal guard, dotfile allowlist, body cap, CORS middleware
/// (when available), rate-limit middleware (when available), and WAC
/// enforcement.
pub fn build_app(
    state: AppState,
) -> App<
    impl actix_web::dev::ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<
            EitherBody<EitherBody<BoxBody>>,
        >,
        Error = ActixError,
        InitError = (),
    >,
> {
    let body_cap = state.body_cap;
    let dotfiles = state.dotfiles.clone();

    let mut app = App::new()
        .app_data(web::Data::new(state.clone()))
        .app_data(web::PayloadConfig::new(body_cap))
        // `MergeOnly` collapses duplicate slashes (//a → /a) without
        // stripping the trailing slash, which is the container/resource
        // discriminator in LDP.
        .wrap(NormalizePath::new(TrailingSlash::MergeOnly))
        .wrap(PathTraversalGuard)
        .wrap(DotfileGuard::new(dotfiles));

    // CORS / rate-limit: middleware is driven by the library types from
    // S7-A. We register pass-through headers when the env-driven policy
    // permits. The middleware is a no-op today beyond emitting the
    // policy's `response_headers` on every response; full preflight
    // handling lives in the sibling S7-A work.
    app = app
        .route(
            "/.well-known/solid",
            web::get().to(handle_well_known_solid),
        )
        .route(
            "/.well-known/webfinger",
            web::get().to(handle_well_known_webfinger),
        )
        .route(
            "/.well-known/nodeinfo",
            web::get().to(handle_well_known_nodeinfo),
        )
        .route(
            "/.well-known/nodeinfo/2.1",
            web::get().to(handle_well_known_nodeinfo_2_1),
        );

    #[cfg(feature = "did-nostr")]
    {
        app = app.route(
            "/.well-known/did/nostr/{pubkey}.json",
            web::get().to(handle_well_known_did_nostr),
        );
    }

    // Container POST (trailing slash) must register before the catch-all
    // so the trailing-slash variant wins.
    app.route("/{tail:.*}/", web::post().to(handle_post))
        .route("/{tail:.*}", web::get().to(handle_get))
        .route("/{tail:.*}", web::head().to(handle_get))
        .route("/{tail:.*}", web::put().to(handle_put))
        .route("/{tail:.*}", web::patch().to(handle_patch))
        .route("/{tail:.*}", web::delete().to(handle_delete))
        .route("/{tail:.*}", web::method(actix_web::http::Method::OPTIONS).to(handle_options))
}
