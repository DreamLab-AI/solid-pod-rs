//! Middleware guard integration tests — PathTraversalGuard, DotfileGuard,
//! body_cap_from_env, AppState construction, and NodeInfoMeta defaults.
//!
//! Tests drive the middleware stack through `build_app` + `actix_web::test`
//! so the full middleware chain (NormalizePath -> PathTraversalGuard ->
//! DotfileGuard) is exercised end-to-end.

use std::sync::{Arc, Mutex, OnceLock};

use solid_pod_rs::storage::memory::MemoryBackend;
use solid_pod_rs_server::{body_cap_from_env, build_app, AppState, NodeInfoMeta, DEFAULT_BODY_CAP};

/// Build a fresh `AppState` backed by an in-memory storage.
fn make_state() -> AppState {
    let storage = Arc::new(MemoryBackend::new());
    AppState::new(storage)
}

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

// ---------------------------------------------------------------------------
// PathTraversalGuard — blocks `../` paths
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn traversal_guard_blocks_dot_dot_slash() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // NormalizePath may resolve `../` before the traversal guard fires,
    // so the request may be rejected by a later guard (403) or the
    // traversal guard itself (400). Either way it must not succeed.
    let req = actix_web::test::TestRequest::get()
        .uri("/foo/../etc/passwd")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert!(
        rsp.status().is_client_error(),
        "path with `../` must be rejected (got {})",
        rsp.status().as_u16(),
    );
}

#[actix_web::test]
async fn traversal_guard_blocks_encoded_dot_dot() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // %2e%2e decodes to `..`
    let req = actix_web::test::TestRequest::get()
        .uri("/foo/%2e%2e/bar")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        400,
        "percent-encoded `..` (%2e%2e) must be rejected"
    );
}

#[actix_web::test]
async fn traversal_guard_blocks_double_encoded_dot_dot() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // %252e%252e -> first decode: %2e%2e -> second decode: ..
    let req = actix_web::test::TestRequest::get()
        .uri("/foo/%252e%252e/bar")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        400,
        "double-encoded `..` (%252e%252e) must be rejected"
    );
}

#[actix_web::test]
async fn traversal_guard_allows_normal_paths() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // A normal path with no traversal — should reach the handler (404
    // because the resource does not exist in memory, but NOT 400).
    let req = actix_web::test::TestRequest::get()
        .uri("/alice/docs/readme.txt")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_ne!(
        rsp.status().as_u16(),
        400,
        "normal path must not be rejected by traversal guard"
    );
}

#[actix_web::test]
async fn traversal_guard_allows_root() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get().uri("/").to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    // Root is a container — should get 200 (empty container listing)
    // or any non-400 status, proving the guard did not block it.
    assert_ne!(
        rsp.status().as_u16(),
        400,
        "root path must not be rejected by traversal guard"
    );
}

/// No allowlist configured (dev/wildcard mode): the response must NOT reflect
/// an arbitrary origin while allowing credentials (that lets any site read
/// authenticated responses). It emits `*` and omits the credentials header.
#[actix_web::test]
async fn cors_wildcard_mode_does_not_reflect_origin_with_credentials() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/")
        .insert_header(("origin", "https://app.example"))
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    let headers = rsp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "wildcard mode must not reflect the request origin"
    );
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "credentials must not be advertised with a wildcard origin"
    );
    let expose = headers
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(expose.contains("Updates-Via"), "Expose-Headers = {expose}");
    assert!(expose.contains("WAC-Allow"), "Expose-Headers = {expose}");
}

/// Allowlist configured + origin present in it: the response reflects that
/// exact origin AND may allow credentials (the intended cross-origin case).
#[actix_web::test]
async fn cors_allowlisted_origin_gets_reflection_and_credentials() {
    let mut state = make_state();
    state.allowed_origins = vec!["https://app.example".to_string()];
    let app = actix_web::test::init_service(build_app(state)).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/")
        .insert_header(("origin", "https://app.example"))
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    let headers = rsp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example")
    );
    assert_eq!(
        headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "an allowlisted origin may carry credentials"
    );
}

/// Allowlist configured + origin NOT in it: no CORS headers at all (blocked).
#[actix_web::test]
async fn cors_non_allowlisted_origin_gets_no_headers() {
    let mut state = make_state();
    state.allowed_origins = vec!["https://app.example".to_string()];
    let app = actix_web::test::init_service(build_app(state)).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/")
        .insert_header(("origin", "https://evil.example"))
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    let headers = rsp.headers();
    assert!(
        headers.get("access-control-allow-origin").is_none(),
        "a non-allowlisted origin must receive no ACAO header"
    );
    assert!(headers.get("access-control-allow-credentials").is_none());
}

// ---------------------------------------------------------------------------
// DotfileGuard — blocks .env but allows .acl, .meta, .account
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn dotfile_guard_blocks_env_path() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/.env")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        403,
        "dotfile path `/.env` must be rejected as 403"
    );
}

#[actix_web::test]
async fn dotfile_guard_blocks_git_path() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/.git/config")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        403,
        "dotfile path `/.git/config` must be rejected as 403"
    );
}

#[actix_web::test]
async fn dotfile_guard_allows_acl_path() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/resource/.acl")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    // .acl is on the default allowlist — should pass through the
    // dotfile guard. The resource won't exist, so 404 is expected.
    assert_ne!(
        rsp.status().as_u16(),
        403,
        "`.acl` is on the allowlist and must not be blocked"
    );
}

#[actix_web::test]
async fn dotfile_guard_allows_meta_path() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/resource/.meta")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_ne!(
        rsp.status().as_u16(),
        403,
        "`.meta` is on the allowlist and must not be blocked"
    );
}

#[actix_web::test]
async fn dotfile_guard_allows_account_path() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // Sprint 12: `.account` added to default allowlist (JSS 32c0db2).
    let req = actix_web::test::TestRequest::get()
        .uri("/.account/login")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_ne!(
        rsp.status().as_u16(),
        403,
        "`.account` is on the default allowlist (Sprint 12) and must not be blocked"
    );
}

#[actix_web::test]
async fn dotfile_guard_allows_well_known_paths() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    // .well-known paths are explicitly whitelisted in the middleware
    // (bypass dotfile check entirely).
    let req = actix_web::test::TestRequest::get()
        .uri("/.well-known/solid")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_ne!(
        rsp.status().as_u16(),
        403,
        "`.well-known/solid` must be allowed through the dotfile guard"
    );
    assert!(
        rsp.status().is_success(),
        "`.well-known/solid` should return 200"
    );
}

#[actix_web::test]
async fn dotfile_guard_blocks_nested_dotfile() {
    let app = actix_web::test::init_service(build_app(make_state())).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/pod/.secret/data.txt")
        .to_request();
    let rsp = actix_web::test::call_service(&app, req).await;
    assert_eq!(
        rsp.status().as_u16(),
        403,
        "nested dotfile `.secret` must be blocked"
    );
}

// ---------------------------------------------------------------------------
// body_cap_from_env
// ---------------------------------------------------------------------------

#[test]
fn body_cap_default_is_50mb() {
    assert_eq!(DEFAULT_BODY_CAP, 50 * 1024 * 1024);
}

#[test]
fn body_cap_from_env_returns_default_on_missing_var() {
    let _guard = env_lock();
    std::env::remove_var("JSS_MAX_REQUEST_BODY");
    let cap = body_cap_from_env();
    assert_eq!(
        cap, DEFAULT_BODY_CAP,
        "missing env var must fall back to default"
    );
}

#[test]
fn body_cap_from_env_parses_valid_value() {
    let _guard = env_lock();
    std::env::set_var("JSS_MAX_REQUEST_BODY", "10MB");
    let cap = body_cap_from_env();
    // body_cap_from_env uses SI (decimal) MB: 10 * 1_000_000.
    assert_eq!(cap, 10_000_000, "10MB must parse to 10000000 bytes (SI)");
    std::env::remove_var("JSS_MAX_REQUEST_BODY");
}

#[test]
fn body_cap_from_env_falls_back_on_invalid_value() {
    let _guard = env_lock();
    std::env::set_var("JSS_MAX_REQUEST_BODY", "not-a-size");
    let cap = body_cap_from_env();
    std::env::remove_var("JSS_MAX_REQUEST_BODY");
    assert_eq!(
        cap, DEFAULT_BODY_CAP,
        "invalid env var must fall back to default"
    );
}

// ---------------------------------------------------------------------------
// NodeInfoMeta defaults
// ---------------------------------------------------------------------------

#[test]
fn nodeinfo_meta_default_values() {
    let meta = NodeInfoMeta::default();
    assert_eq!(meta.software_name, "solid-pod-rs-server");
    assert!(
        !meta.software_version.is_empty(),
        "version must not be empty"
    );
    assert!(
        !meta.open_registrations,
        "default must be closed registrations"
    );
    assert_eq!(meta.total_users, 0);
    assert_eq!(meta.base_url, "http://localhost");
}

// ---------------------------------------------------------------------------
// AppState construction
// ---------------------------------------------------------------------------

#[test]
fn app_state_new_sets_defaults() {
    let _guard = env_lock();
    std::env::remove_var("JSS_MAX_REQUEST_BODY");
    let storage = Arc::new(MemoryBackend::new());
    let state = AppState::new(storage);
    assert_eq!(state.body_cap, DEFAULT_BODY_CAP);
    assert!(state.mashlib_cdn.is_none());
    assert_eq!(state.nodeinfo.software_name, "solid-pod-rs-server");
    // The dotfile allowlist should contain .acl, .meta, .account.
    let entries = state.dotfiles.entries();
    assert!(
        entries.iter().any(|e| e == ".acl"),
        "default dotfiles must include .acl"
    );
    assert!(
        entries.iter().any(|e| e == ".meta"),
        "default dotfiles must include .meta"
    );
    assert!(
        entries.iter().any(|e| e == ".account"),
        "default dotfiles must include .account"
    );
}
