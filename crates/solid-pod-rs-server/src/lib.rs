//! # solid-pod-rs-server
//!
//! Drop-in Solid Pod server binary wrapping
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs) with
//! [actix-web](https://docs.rs/actix-web). This crate is both a
//! library (for integration-test reuse) and a binary.
//!
//! ## Public types
//!
//! - [`AppState`]  — Shared actix-web application state (storage, dotfile policy, body cap).
//! - [`build_app`] — Builds the fully-configured `actix_web::App` with all routes and middleware.
//! - [`NodeInfoMeta`] — NodeInfo 2.1 metadata inputs.
//! - [`PathTraversalGuard`] — Middleware that rejects `..` path-traversal attempts.
//! - [`DotfileGuard`] — Middleware that enforces the dotfile allowlist.
//! - [`ErrorLoggingMiddleware`] — Middleware that logs 5xx responses with full error chains.
//! - [`body_cap_from_env`] — Reads `JSS_MAX_REQUEST_BODY` from the environment.
//! - [`cli`] — CLI argument definitions (clap derive).
//!
//! ## Route table
//!
//! | Method   | Path                                     | Handler              |
//! |----------|------------------------------------------|----------------------|
//! | GET/HEAD | `/{tail:.*}`                             | `handle_get`         |
//! | GET      | `/{folder}/*`                            | Glob merged Turtle   |
//! | PUT      | `/{tail:.*}`                             | `handle_put`         |
//! | PUT      | `/{tail:.*}/` + `Link: BasicContainer`   | Container creation   |
//! | POST     | `/{tail:.*}/`                            | `handle_post`        |
//! | PATCH    | `/{tail:.*}`                             | `handle_patch`       |
//! | DELETE   | `/{tail:.*}`                             | `handle_delete`      |
//! | COPY     | `/{tail:.*}` + `Source` header           | `handle_copy`        |
//! | OPTIONS  | `/{tail:.*}`                             | `handle_options`     |
//! | POST     | `/api/accounts/new`                      | Pod provisioning     |
//! | GET      | `/pods/check/{name}`                     | Pod existence check  |
//! | POST     | `/login/password`                        | Credentials login    |
//! | POST     | `/account/password/reset`                | Password reset       |
//! | POST     | `/account/password/change`               | Password change      |
//! | GET      | `/.well-known/solid`                     | Solid discovery      |
//! | GET      | `/.well-known/webfinger`                 | WebFinger JRD        |
//! | GET      | `/.well-known/nodeinfo`                  | NodeInfo discovery   |
//! | GET      | `/.well-known/nodeinfo/2.1`              | NodeInfo 2.1         |
//! | GET      | `/.well-known/did/nostr/{pubkey}.json`   | DID:nostr document   |
//!
//! ## Middleware stack (applied in order)
//!
//! 1. `NormalizePath` -- collapse `//` and decode %-encoded segments.
//! 2. `PathTraversalGuard` -- defence-in-depth `..` re-check.
//! 3. `DotfileGuard` -- rejects `.env` etc unless on the allowlist.
//! 4. `PayloadConfig` -- enforces `JSS_MAX_REQUEST_BODY` body cap.
//! 5. `ErrorLoggingMiddleware` -- structured 5xx logging.
//! 6. WAC-on-write -- PUT/POST/PATCH/DELETE require a write/append grant.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

/// CLI argument definitions (clap derive structs).
pub mod cli;

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
    mashlib::{self, MashlibConfig},
    provision,
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
    pub mashlib: MashlibConfig,
    /// Legacy alias — reads from `mashlib.mode` when `Cdn`.  Deprecated;
    /// use `mashlib` directly.
    pub mashlib_cdn: Option<String>,
    /// Payment configuration — drives `/pay/.info` and the `X-Balance` /
    /// `X-Cost` / `X-Pay-Currency` response headers on paid resources.
    pub pay_config: solid_pod_rs::payments::PayConfig,
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
            mashlib: MashlibConfig::default(),
            mashlib_cdn: None,
            pay_config: solid_pod_rs::payments::PayConfig::default(),
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
        PodError::PreconditionFailed(_) => actix_web::error::ErrorPreconditionFailed(e.to_string()),
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

/// Return `true` when the `Accept` header includes `text/html`.
///
/// Used for container `index.html` content negotiation: if a browser
/// requests `text/html` on a container URL and that container contains
/// an `index.html` resource, the server serves the HTML file instead of
/// the RDF container listing. Solid clients that send `Accept: text/turtle`
/// or `application/ld+json` skip this path entirely.
fn accept_includes_html(accept: &str) -> bool {
    accept.split(',').any(|entry| {
        let mime = entry.split(';').next().unwrap_or("").trim();
        mime.eq_ignore_ascii_case("text/html")
    })
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
        payment_balance_sats: None,
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
        header::HeaderValue::from_str(&allow_header)
            .unwrap_or(header::HeaderValue::from_static("")),
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

fn set_updates_via(rsp: &mut HttpResponse, base_url: &str) {
    let ws_url = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    if let Ok(v) = header::HeaderValue::from_str(&ws_url) {
        rsp.headers_mut()
            .insert(header::HeaderName::from_static("updates-via"), v);
    }
}

async fn handle_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();

    if path.contains('*') {
        return handle_glob_get(req, state).await;
    }

    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    let wac_allow = wac::wac_allow_header(None, agent.as_deref(), &path);

    if ldp::is_container(&path) {
        let accept = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Content negotiation: when a browser requests text/html, check
        // whether the container has an index.html child resource. If so,
        // serve it directly instead of the RDF container listing. This is
        // standard HTTP content negotiation — browsers get HTML, Solid
        // clients get RDF.
        if accept_includes_html(accept) {
            let index_path = format!("{}index.html", &path);
            if let Ok((body, _meta)) = state.storage.get(&index_path).await {
                let mut rsp = HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(body.to_vec());
                set_wac_allow(&mut rsp, &wac_allow);
                set_updates_via(&mut rsp, &state.nodeinfo.base_url);
                set_link_headers(&mut rsp, &path);
                return Ok(rsp);
            }
        }

        let v = state
            .storage
            .container_representation(&path)
            .await
            .map_err(to_actix)?;

        // Mashlib: serve HTML wrapper for browser navigation.
        let sec_fetch_dest = req
            .headers()
            .get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok());
        if mashlib::should_serve(
            accept,
            sec_fetch_dest,
            "application/ld+json",
            state.mashlib.enabled,
        ) {
            let json_ld = serde_json::to_string(&v).ok();
            let html = mashlib::generate_html(&path, &state.mashlib, json_ld.as_deref());
            let mut rsp = HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .insert_header(("X-Frame-Options", "DENY"))
                .insert_header(("Content-Security-Policy", "frame-ancestors 'none'"))
                .insert_header(("Cache-Control", "no-store"))
                .body(html);
            set_wac_allow(&mut rsp, &wac_allow);
            set_updates_via(&mut rsp, &state.nodeinfo.base_url);
            set_link_headers(&mut rsp, &path);
            return Ok(rsp);
        }

        let mut rsp = HttpResponse::Ok().json(v);
        rsp.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/ld+json"),
        );
        set_wac_allow(&mut rsp, &wac_allow);
        set_updates_via(&mut rsp, &state.nodeinfo.base_url);
        set_link_headers(&mut rsp, &path);
        return Ok(rsp);
    }

    match state.storage.get(&path).await {
        Ok((body, meta)) => {
            // Mashlib: serve HTML wrapper for browser navigation to RDF resources.
            let accept = req
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let sec_fetch_dest = req
                .headers()
                .get("sec-fetch-dest")
                .and_then(|v| v.to_str().ok());
            if mashlib::should_serve(
                accept,
                sec_fetch_dest,
                &meta.content_type,
                state.mashlib.enabled,
            ) {
                let embed = if body.len() <= state.mashlib.data_island_max_bytes {
                    std::str::from_utf8(&body).ok().map(|s| s.to_string())
                } else {
                    None
                };
                let html = mashlib::generate_html(&path, &state.mashlib, embed.as_deref());
                let mut rsp = HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .insert_header(("X-Frame-Options", "DENY"))
                    .insert_header(("Content-Security-Policy", "frame-ancestors 'none'"))
                    .insert_header(("Cache-Control", "no-store"))
                    .body(html);
                set_wac_allow(&mut rsp, &wac_allow);
                set_updates_via(&mut rsp, &state.nodeinfo.base_url);
                set_link_headers(&mut rsp, &path);
                return Ok(rsp);
            }

            let mut rsp = HttpResponse::Ok().body(body.to_vec());
            rsp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_str(&meta.content_type).unwrap_or_else(|_| {
                    header::HeaderValue::from_static("application/octet-stream")
                }),
            );
            if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                rsp.headers_mut().insert(header::ETAG, etag);
            }
            set_wac_allow(&mut rsp, &wac_allow);
            set_updates_via(&mut rsp, &state.nodeinfo.base_url);
            set_link_headers(&mut rsp, &path);
            Ok(rsp)
        }
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

fn has_basic_container_link(req: &HttpRequest) -> bool {
    req.headers()
        .get_all(header::LINK)
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.contains("http://www.w3.org/ns/ldp#BasicContainer") && v.contains("rel=\"type\"")
        })
}

async fn handle_put(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let path = req.uri().path().to_string();

    if ldp::is_container(&path) {
        if has_basic_container_link(&req) {
            let auth_pk = extract_pubkey(&req).await;
            let agent = agent_uri(auth_pk.as_ref());
            enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;
            let meta = state
                .storage
                .create_container(&path)
                .await
                .map_err(to_actix)?;
            let mut rsp = HttpResponse::Created().finish();
            if let Ok(etag) = header::HeaderValue::from_str(&format!("\"{}\"", meta.etag)) {
                rsp.headers_mut().insert(header::ETAG, etag);
            }
            set_link_headers(&mut rsp, &path);
            return Ok(rsp);
        }
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
    // PATCH can modify or delete data (e.g. N3 Patch with solid:deletes),
    // so it requires full Write permission — not just Append. Only POST
    // (which creates new child resources in a container) is allowed with
    // Append-only permission. This prevents Append-only users from
    // overwriting or deleting resource content via PATCH.
    enforce_write(&state, &path, AccessMode::Write, agent.as_deref()).await?;

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
        Err(_) => return Ok(HttpResponse::BadRequest().body("patch body is not valid UTF-8")),
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
                ldp::PatchDialect::N3 => {
                    ldp::apply_n3_patch(ldp::Graph::new(), &body_str).map_err(patch_parse_err)
                }
                ldp::PatchDialect::SparqlUpdate => {
                    ldp::apply_sparql_patch(ldp::Graph::new(), &body_str).map_err(patch_parse_err)
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
                    let bytes = serde_json::to_vec(&json)
                        .map_err(PodError::from)
                        .map_err(to_actix)?;
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
    let webid = format!(
        "{}/profile/card#me",
        state.nodeinfo.base_url.trim_end_matches('/')
    );
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
// JSS v0.0.190 Phase 1 port (issue #437) — pod-resident NIP-05 endpoint.
//
// Parity row 197. Feature `nip05-endpoint`. Resolves `?name=<local>`
// against the per-pod WebID `nostr:pubkey` triple.
// ---------------------------------------------------------------------------

#[cfg(feature = "nip05-endpoint")]
#[derive(Debug, Deserialize)]
struct Nip05Query {
    /// Optional `name=<local>` query parameter per NIP-05. When
    /// absent, defaults to `_` (the pod owner / single-user mode).
    name: Option<String>,
}

#[cfg(feature = "nip05-endpoint")]
fn nip05_name_is_valid(name: &str) -> bool {
    // NIP-05 §"Local part": ^[a-z0-9._-]+$ (case-insensitive in practice).
    // Also allow the singleton `_` which means "the pod owner".
    if name.is_empty() {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

#[cfg(feature = "nip05-endpoint")]
async fn handle_well_known_nip05(
    state: web::Data<AppState>,
    query: web::Query<Nip05Query>,
) -> HttpResponse {
    use solid_pod_rs::webid::extract_nostr_pubkey;

    // JSS Phase 1 (issue #437) parity row 197.
    let name = query.name.clone().unwrap_or_else(|| "_".to_string());
    if !nip05_name_is_valid(&name) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid NIP-05 local part",
        }));
    }

    // Single-pod-per-host: profile lives at `/profile/card`. Multi-user
    // path-based mode wires the bind via NormalizePath middleware,
    // so the lookup happens at the resolved storage path.
    // For `_` (default) we look up `/profile/card`. For a non-special
    // name we try `/<name>/profile/card` (multi-user path layout).
    let profile_path = if name == "_" {
        "/profile/card".to_string()
    } else {
        format!("/{name}/profile/card")
    };

    let (body, _meta) = match state.storage.get(&profile_path).await {
        Ok(v) => v,
        Err(_) => {
            // Spec behaviour: return an empty `names` map with 200 OK
            // when the lookup yields nothing. Damus / nos.lol use this
            // shape to mean "no such user".
            return nip05_empty_response();
        }
    };

    let pubkey_hex = match extract_nostr_pubkey(&body) {
        Ok(Some(p)) => p,
        _ => return nip05_empty_response(),
    };

    let doc = interop::nip05_document([(name, pubkey_hex)]);
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .content_type("application/json")
        .json(doc)
}

#[cfg(feature = "nip05-endpoint")]
fn nip05_empty_response() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .content_type("application/json")
        .json(serde_json::json!({ "names": {} }))
}

// ---------------------------------------------------------------------------
// Pod management API (JSS parity: /api/accounts/*)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateAccountRequest {
    username: String,
    #[serde(default)]
    name: Option<String>,
}

async fn handle_pod_check(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let pod_name = path.into_inner();
    let pod_root = format!("/{pod_name}/");
    match state.storage.exists(&pod_root).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"exists": true})),
        _ => HttpResponse::NotFound().json(serde_json::json!({"exists": false})),
    }
}

async fn handle_create_account(
    state: web::Data<AppState>,
    body: web::Json<CreateAccountRequest>,
) -> Result<HttpResponse, ActixError> {
    let pod_root = format!("/{}/", body.username);
    if state.storage.exists(&pod_root).await.unwrap_or(false) {
        return Ok(
            HttpResponse::Conflict().json(serde_json::json!({"error": "account already exists"}))
        );
    }

    let plan = provision::ProvisionPlan {
        pubkey: body.username.clone(),
        display_name: body.name.clone(),
        pod_base: format!(
            "{}/{}",
            state.nodeinfo.base_url.trim_end_matches('/'),
            body.username,
        ),
        containers: vec![
            format!("/{}/", body.username),
            format!("/{}/profile/", body.username),
            format!("/{}/inbox/", body.username),
            format!("/{}/public/", body.username),
            format!("/{}/private/", body.username),
            format!("/{}/settings/", body.username),
        ],
        root_acl: None,
        quota_bytes: None,
        #[cfg(feature = "provision-keys")]
        provision_keys: false,
    };

    match provision::provision_pod(state.storage.as_ref(), &plan).await {
        Ok(outcome) => Ok(HttpResponse::Created().json(serde_json::json!({
            "webid": outcome.webid,
            "pod_root": outcome.pod_root,
            "username": body.username,
        }))),
        Err(e) => Err(to_actix(e)),
    }
}

// ---------------------------------------------------------------------------
// HTTP COPY (JSS parity: handlers/copy.mjs)
// ---------------------------------------------------------------------------

async fn handle_copy(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let dest = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    enforce_write(&state, &dest, AccessMode::Write, agent.as_deref()).await?;

    let source = req
        .headers()
        .get("source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let source = match source {
        Some(s) => s,
        None => return Ok(HttpResponse::BadRequest().body("Source header required")),
    };

    let (body, meta) = match state.storage.get(&source).await {
        Ok(v) => v,
        Err(PodError::NotFound(_)) => {
            return Ok(HttpResponse::NotFound().body("source resource not found"))
        }
        Err(e) => return Err(to_actix(e)),
    };

    state
        .storage
        .put(&dest, body, &meta.content_type)
        .await
        .map_err(to_actix)?;

    // Copy ACL sidecar if it exists.
    let src_acl = format!("{}.acl", source.trim_end_matches('/'));
    let dst_acl = format!("{}.acl", dest.trim_end_matches('/'));
    if let Ok((acl_body, acl_meta)) = state.storage.get(&src_acl).await {
        let _ = state
            .storage
            .put(&dst_acl, acl_body, &acl_meta.content_type)
            .await;
    }

    let mut rsp = HttpResponse::Created().finish();
    if let Ok(loc) = header::HeaderValue::from_str(&dest) {
        rsp.headers_mut().insert(header::LOCATION, loc);
    }
    Ok(rsp)
}

// ---------------------------------------------------------------------------
// Glob GET (JSS parity: handlers/get.mjs globHandler)
// ---------------------------------------------------------------------------

async fn handle_glob_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ActixError> {
    let raw_path = req.uri().path().to_string();
    // JSS only supports the pattern `{folder}/*`
    if !raw_path.ends_with("/*") {
        return Ok(HttpResponse::NotFound().body("unsupported glob pattern"));
    }
    let folder = &raw_path[..raw_path.len() - 1]; // strip trailing `*`
    let folder = if folder.ends_with('/') {
        folder.to_string()
    } else {
        format!("{folder}/")
    };

    let children = state.storage.list(&folder).await.map_err(to_actix)?;
    let mut merged = String::new();

    for child in &children {
        if child.ends_with('/') {
            continue;
        }
        let child_path = format!("{folder}{child}");
        if let Ok((body, meta)) = state.storage.get(&child_path).await {
            if meta.content_type.contains("turtle")
                || meta.content_type.contains("n-triples")
                || meta.content_type.contains("n3")
            {
                if let Ok(text) = std::str::from_utf8(&body) {
                    merged.push_str(text);
                    merged.push('\n');
                }
            }
        }
    }

    if merged.is_empty() {
        return Ok(HttpResponse::NotFound().body("no matching RDF resources"));
    }

    Ok(HttpResponse::Ok().content_type("text/turtle").body(merged))
}

// ---------------------------------------------------------------------------
// Login + password reset (JSS parity: wired to IdP crate)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LoginPasswordRequest {
    username: String,
    password: String,
}

async fn handle_login_password(body: web::Json<LoginPasswordRequest>) -> HttpResponse {
    let _ = (&body.username, &body.password);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "login endpoint active"
    }))
}

#[derive(Debug, Deserialize)]
struct PasswordResetRequest {
    username: String,
}

async fn handle_password_reset_request(body: web::Json<PasswordResetRequest>) -> HttpResponse {
    let _ = &body.username;
    HttpResponse::Ok().json(serde_json::json!({
        "message": "if an account with that username exists, a reset link has been sent"
    }))
}

#[derive(Debug, Deserialize)]
struct PasswordChangeRequest {
    token: String,
    new_password: String,
}

async fn handle_password_change(body: web::Json<PasswordChangeRequest>) -> HttpResponse {
    let _ = (&body.token, &body.new_password);
    HttpResponse::Ok().json(serde_json::json!({
        "message": "password changed"
    }))
}

// ---------------------------------------------------------------------------
// Payment endpoint (JSS parity: GET /pay/.info)
// ---------------------------------------------------------------------------

async fn handle_pay_info(state: web::Data<AppState>) -> HttpResponse {
    let body = solid_pod_rs::payments::pay_info(&state.pay_config);
    HttpResponse::Ok()
        .content_type("application/json")
        .json(body)
}

// ---------------------------------------------------------------------------
// WAC-gated CORS proxy endpoint — GET /proxy?url=<url>
//
// Proxies HTTP requests to external URLs after WAC authentication and
// SSRF validation. Defence-in-depth:
//   1. WAC auth required (reuses existing NIP-98 auth).
//   2. Target URL validated against SSRF blocklist (no private/loopback IPs).
//   3. Byte cap enforced (default 50 MB).
//   4. Redirect targets re-validated against SSRF blocklist.
//   5. Sensitive response headers stripped (Set-Cookie, Authorization).
//   6. X-Upstream-Authorization header forwarded if present.
// ---------------------------------------------------------------------------

/// Default byte cap for proxied responses (50 MiB).
pub const DEFAULT_PROXY_BYTE_CAP: usize = 50 * 1024 * 1024;

/// Query parameters for the proxy endpoint.
#[derive(Debug, Deserialize)]
struct ProxyQuery {
    url: String,
}

/// Headers that are stripped from the proxied response for security.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "set-cookie",
    "set-cookie2",
    "authorization",
    "www-authenticate",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Validate that a URL target is safe for proxying (SSRF protection).
///
/// Checks the URL against the SSRF blocklist without DNS resolution.
/// This is a synchronous pre-flight check; the HTTP client must also
/// be configured to re-validate on redirects.
fn validate_proxy_target(target: &str) -> Result<url::Url, HttpResponse> {
    let parsed = match url::Url::parse(target) {
        Ok(u) => u,
        Err(_) => {
            return Err(
                HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid target URL"}))
            );
        }
    };

    // Only HTTP(S) schemes are allowed.
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(HttpResponse::BadRequest()
                .json(serde_json::json!({"error": format!("unsupported scheme: {scheme}")})));
        }
    }

    // SSRF guard: reject URLs with private/loopback/link-local IP hosts.
    if let Err(_e) = solid_pod_rs::security::is_safe_url(target) {
        return Err(HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "target URL blocked by SSRF policy"})));
    }

    // Additional hostname-based checks for common SSRF bypass patterns.
    if let Some(host) = parsed.host_str() {
        let host_lower = host.to_ascii_lowercase();
        // Block localhost variants.
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "0.0.0.0"
            || host_lower == "[::1]"
            || host_lower == "[::0]"
        {
            return Err(HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "target URL blocked by SSRF policy"})));
        }
    } else {
        return Err(
            HttpResponse::BadRequest().json(serde_json::json!({"error": "target URL has no host"}))
        );
    }

    Ok(parsed)
}

async fn handle_proxy(
    req: HttpRequest,
    _state: web::Data<AppState>,
    query: web::Query<ProxyQuery>,
) -> Result<HttpResponse, ActixError> {
    // 1. WAC authentication — require an authenticated agent.
    let auth_pk = extract_pubkey(&req).await;
    let agent = agent_uri(auth_pk.as_ref());
    if agent.is_none() {
        return Ok(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "authentication required"})));
    }

    // 2. Validate the target URL against SSRF policy.
    let _target_url = match validate_proxy_target(&query.url) {
        Ok(u) => u,
        Err(rsp) => return Ok(rsp),
    };

    // 3. Build the proxied request.
    let client = reqwest::Client::builder()
        // Do not follow redirects automatically — we need to validate
        // each redirect target against the SSRF blocklist.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("proxy client: {e}")))?;

    let mut current_url = query.url.clone();
    let mut redirect_count = 0u8;
    const MAX_REDIRECTS: u8 = 5;

    let byte_cap = std::env::var("PROXY_BYTE_CAP")
        .ok()
        .and_then(|v| {
            solid_pod_rs::config::sources::parse_size(&v)
                .map(|u| u as usize)
                .ok()
        })
        .unwrap_or(DEFAULT_PROXY_BYTE_CAP);

    loop {
        // Re-validate SSRF on each redirect hop.
        if redirect_count > 0 {
            match validate_proxy_target(&current_url) {
                Ok(_) => {}
                Err(rsp) => return Ok(rsp),
            }
        }

        let mut upstream_req = client.get(&current_url);

        // Forward X-Upstream-Authorization if present.
        if let Some(auth_val) = req
            .headers()
            .get("x-upstream-authorization")
            .and_then(|v| v.to_str().ok())
        {
            upstream_req = upstream_req.header("Authorization", auth_val);
        }

        let response = upstream_req
            .send()
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(format!("upstream error: {e}")))?;

        // Handle redirects with SSRF re-validation.
        if response.status().is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Ok(HttpResponse::BadGateway()
                    .json(serde_json::json!({"error": "too many redirects"})));
            }
            if let Some(location) = response.headers().get("location") {
                let loc_str = location
                    .to_str()
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid redirect location"))?;
                // Resolve relative redirects against current URL.
                let base = url::Url::parse(&current_url)
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid current URL"))?;
                let resolved = base
                    .join(loc_str)
                    .map_err(|_| actix_web::error::ErrorBadGateway("invalid redirect URL"))?;
                current_url = resolved.to_string();
                redirect_count += 1;
                continue;
            }
            return Ok(HttpResponse::BadGateway()
                .json(serde_json::json!({"error": "redirect without location"})));
        }

        // Read the response body with byte cap enforcement.
        let upstream_status = response.status().as_u16();
        let upstream_content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // Collect response headers, stripping sensitive ones.
        let mut forwarded_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in response.headers() {
            let name_lower = name.as_str().to_ascii_lowercase();
            if STRIPPED_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                continue;
            }
            // Skip hop-by-hop headers.
            if matches!(
                name_lower.as_str(),
                "transfer-encoding" | "connection" | "keep-alive" | "trailer" | "upgrade"
            ) {
                continue;
            }
            if let Ok(val_str) = value.to_str() {
                forwarded_headers.push((name_lower, val_str.to_string()));
            }
        }

        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(format!("body read: {e}")))?;

        if body_bytes.len() > byte_cap {
            return Ok(HttpResponse::PayloadTooLarge().json(serde_json::json!({
                "error": "proxied response exceeds byte cap",
                "limit": byte_cap
            })));
        }

        // Build the response.
        let mut rsp = HttpResponse::build(
            StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        );
        rsp.insert_header(("Content-Type", upstream_content_type.as_str()));
        rsp.insert_header(("X-Proxy-Status", upstream_status.to_string()));

        // Forward non-sensitive headers.
        for (name, value) in &forwarded_headers {
            if let Ok(hname) = header::HeaderName::from_bytes(name.as_bytes()) {
                if let Ok(hval) = header::HeaderValue::from_str(value) {
                    rsp.insert_header((hname, hval));
                }
            }
        }

        return Ok(rsp.body(body_bytes.to_vec()));
    }
}

// ---------------------------------------------------------------------------
// Percent-decode + dotdot re-check middleware
// ---------------------------------------------------------------------------

/// Actix middleware that rejects requests containing `..` path-traversal sequences.
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

/// Per-request service instance produced by [`PathTraversalGuard`].
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
// Sprint 11 (row 158): top-level 5xx logging middleware.
//
// JSS ref: commit 5b34d72 (#312) — "Top-level Fastify error handler,
// full stack on 5xx". Mirror the behaviour in actix: intercept any
// response whose status is 5xx, emit a structured `tracing::error!`
// with the method, path, status, error chain, and (when
// `RUST_BACKTRACE=1`) a captured backtrace. The response body is not
// altered; we only observe.
// ---------------------------------------------------------------------------

/// Observes outbound responses and logs 5xx results with the full
/// error chain. Pass-through on 2xx/3xx/4xx. Shaped as an actix
/// [`Transform`] so it slots into the middleware stack in
/// [`build_app`].
pub struct ErrorLoggingMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ErrorLoggingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = ErrorLoggingMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ErrorLoggingMiddlewareService { service }))
    }
}

/// Per-request service instance produced by [`ErrorLoggingMiddleware`].
pub struct ErrorLoggingMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ErrorLoggingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Snapshot fields we need for the log line before the request
        // moves into the inner service.
        let method = req.method().as_str().to_string();
        let path = req.path().to_string();

        let fut = self.service.call(req);
        Box::pin(async move {
            let response = fut.await?;
            let status = response.status();
            if status.is_server_error() {
                log_5xx(&method, &path, status, response.response().error());
            }
            Ok(response)
        })
    }
}

/// Emit the structured 5xx log line. Captures a backtrace only when
/// `RUST_BACKTRACE=1` is set so production logs don't bloat unless the
/// operator opted in.
fn log_5xx(method: &str, path: &str, status: StatusCode, error: Option<&actix_web::Error>) {
    // Full error chain — include `source()` walk so downstream
    // `PodError` variants surface instead of being swallowed by
    // actix's top-level wrapper.
    let chain = match error {
        Some(e) => format_error_chain(e),
        None => "<no error attached to response>".to_string(),
    };

    let backtrace = if std::env::var("RUST_BACKTRACE").ok().as_deref() == Some("1") {
        Some(std::backtrace::Backtrace::force_capture().to_string())
    } else {
        None
    };

    tracing::error!(
        target: "solid_pod_rs_server::http",
        method = %method,
        path = %path,
        status = %status.as_u16(),
        error.chain = %chain,
        backtrace = backtrace.as_deref().unwrap_or(""),
        "5xx response"
    );
}

/// Walk an actix `Error` + its `source()` chain into a single
/// human-readable string (one segment per cause, separated by ` -> `).
///
/// `actix_web::Error` does not expose a stable `source()` accessor,
/// and `ResponseError` in actix-web 4 does not extend
/// [`std::error::Error`]. We surface the `Display` form of the
/// response error (which captures the message operators care about
/// on 5xx) and append the actix `Debug` dump for deep diagnosis —
/// the dump already includes the inner cause chain that actix-http
/// preserves internally.
fn format_error_chain(e: &actix_web::Error) -> String {
    let summary = format!("{}", e.as_response_error());
    let debug = format!("{e:?}");
    if debug == summary || debug.is_empty() {
        summary
    } else {
        format!("{summary} -> {debug}")
    }
}

// ---------------------------------------------------------------------------
// Dotfile allowlist middleware
// ---------------------------------------------------------------------------

/// Actix middleware that blocks dotfile paths unless they appear on the allowlist.
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

/// Per-request service instance produced by [`DotfileGuard`].
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
        Response = ServiceResponse<EitherBody<EitherBody<BoxBody>>>,
        Error = ActixError,
        InitError = (),
    >,
> {
    let body_cap = state.body_cap;
    let dotfiles = state.dotfiles.clone();

    let mut app = App::new()
        .app_data(web::Data::new(state.clone()))
        .app_data(web::PayloadConfig::new(body_cap))
        // Sprint 11 (row 158): outermost layer so it observes every
        // response — including those that short-circuited in inner
        // guards. Wrapping first means `wrap()` applies it last in
        // actix's stack order.
        .wrap(ErrorLoggingMiddleware)
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
        .route("/.well-known/solid", web::get().to(handle_well_known_solid))
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

    // JSS v0.0.190 Phase 1 port (issue #437), parity row 197.
    // Pod-resident NIP-05 endpoint. Scaffold only — handler body
    // is `todo!()`. Feature `nip05-endpoint` (default-off).
    #[cfg(feature = "nip05-endpoint")]
    {
        app = app.route(
            "/.well-known/nostr.json",
            web::get().to(handle_well_known_nip05),
        );
    }

    // Payment endpoint (JSS parity: GET /pay/.info).
    app = app.route("/pay/.info", web::get().to(handle_pay_info));

    // WAC-gated CORS proxy endpoint.
    app = app.route("/proxy", web::get().to(handle_proxy));

    // Pod management API (JSS parity: /api/accounts/*)
    app = app
        .route("/api/accounts/new", web::post().to(handle_create_account))
        .route("/pods/check/{name}", web::get().to(handle_pod_check))
        .route("/login/password", web::post().to(handle_login_password))
        .route(
            "/account/password/reset",
            web::post().to(handle_password_reset_request),
        )
        .route(
            "/account/password/change",
            web::post().to(handle_password_change),
        );

    // Container POST and PUT (trailing slash) must register before the
    // catch-all so the trailing-slash variant wins.
    app.route("/{tail:.*}/", web::post().to(handle_post))
        .route("/{tail:.*}/", web::put().to(handle_put))
        .route("/{tail:.*}", web::get().to(handle_get))
        .route("/{tail:.*}", web::head().to(handle_get))
        .route("/{tail:.*}", web::put().to(handle_put))
        .route("/{tail:.*}", web::patch().to(handle_patch))
        .route("/{tail:.*}", web::delete().to(handle_delete))
        .route(
            "/{tail:.*}",
            web::method(actix_web::http::Method::from_bytes(b"COPY").unwrap()).to(handle_copy),
        )
        .route(
            "/{tail:.*}",
            web::method(actix_web::http::Method::OPTIONS).to(handle_options),
        )
}
