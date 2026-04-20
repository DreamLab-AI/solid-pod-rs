//! Minimal standalone Solid pod server over actix-web.
//!
//! Run with:
//! ```bash
//! cargo run --example standalone -p solid-pod-rs
//! ```
//!
//! Serves pod data from a temporary directory. Demonstrates the
//! Storage trait + LDP Link headers + WAC-Allow header.

use std::sync::Arc;

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use bytes::Bytes;
use solid_pod_rs::{
    auth::nip98,
    ldp::{self, LdpContainerOps},
    storage::{fs::FsBackend, Storage},
    wac,
    PodError,
};

#[derive(Clone)]
struct AppState {
    storage: Arc<dyn Storage>,
}

fn set_link_headers(rsp: &mut HttpResponse, path: &str) {
    let links = ldp::link_headers(path).join(", ");
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&links) {
        rsp.headers_mut().insert(
            actix_web::http::header::HeaderName::from_static("link"),
            value,
        );
    }
}

async fn handle_get(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let path = req.uri().path().to_string();
    let auth_pk = extract_pubkey(&req).await;
    let agent_uri = auth_pk.as_ref().map(|pk| format!("did:nostr:{pk}"));

    let wac_allow = wac::wac_allow_header(None, agent_uri.as_deref(), &path);

    if ldp::is_container(&path) {
        let v = state
            .storage
            .container_representation(&path)
            .await
            .map_err(to_actix)?;
        let mut rsp = HttpResponse::Ok().json(v);
        rsp.headers_mut().insert(
            actix_web::http::header::CONTENT_TYPE,
            actix_web::http::header::HeaderValue::from_static("application/ld+json"),
        );
        if let Ok(v) = actix_web::http::header::HeaderValue::from_str(&wac_allow) {
            rsp.headers_mut().insert(
                actix_web::http::header::HeaderName::from_static("wac-allow"),
                v,
            );
        }
        set_link_headers(&mut rsp, &path);
        return Ok(rsp);
    }
    match state.storage.get(&path).await {
        Ok((body, meta)) => {
            let mut rsp = HttpResponse::Ok().body(body.to_vec());
            rsp.headers_mut().insert(
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::HeaderValue::from_str(&meta.content_type)
                    .unwrap_or_else(|_| {
                        actix_web::http::header::HeaderValue::from_static(
                            "application/octet-stream",
                        )
                    }),
            );
            if let Ok(etag) = actix_web::http::header::HeaderValue::from_str(&format!(
                "\"{}\"",
                meta.etag
            )) {
                rsp.headers_mut()
                    .insert(actix_web::http::header::ETAG, etag);
            }
            if let Ok(v) = actix_web::http::header::HeaderValue::from_str(&wac_allow) {
                rsp.headers_mut().insert(
                    actix_web::http::header::HeaderName::from_static("wac-allow"),
                    v,
                );
            }
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
) -> Result<HttpResponse, actix_web::Error> {
    let path = req.uri().path().to_string();
    if ldp::is_container(&path) {
        return Ok(HttpResponse::MethodNotAllowed().body("cannot PUT to a container"));
    }
    let ct = req
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let meta = state
        .storage
        .put(&path, Bytes::from(body.to_vec()), ct)
        .await
        .map_err(to_actix)?;
    let mut rsp = HttpResponse::Created().finish();
    if let Ok(etag) =
        actix_web::http::header::HeaderValue::from_str(&format!("\"{}\"", meta.etag))
    {
        rsp.headers_mut()
            .insert(actix_web::http::header::ETAG, etag);
    }
    set_link_headers(&mut rsp, &path);
    Ok(rsp)
}

async fn handle_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let path = req.uri().path().to_string();
    match state.storage.delete(&path).await {
        Ok(()) => Ok(HttpResponse::NoContent().finish()),
        Err(PodError::NotFound(_)) => Ok(HttpResponse::NotFound().finish()),
        Err(e) => Err(to_actix(e)),
    }
}

async fn extract_pubkey(req: &HttpRequest) -> Option<String> {
    let header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let url = format!(
        "http://{}{}",
        req.connection_info().host(),
        req.uri().path()
    );
    nip98::verify(header, &url, req.method().as_str(), None)
        .await
        .ok()
}

fn to_actix(e: PodError) -> actix_web::Error {
    actix_web::error::ErrorInternalServerError(e.to_string())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let tmp = std::env::temp_dir().join("solid-pod-rs-example");
    let storage = FsBackend::new(&tmp)
        .await
        .expect("init FS backend");
    let state = AppState {
        storage: Arc::new(storage),
    };

    eprintln!(
        "solid-pod-rs example running on http://127.0.0.1:8765 (root: {})",
        tmp.display()
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/{tail:.*}", web::get().to(handle_get))
            .route("/{tail:.*}", web::head().to(handle_get))
            .route("/{tail:.*}", web::put().to(handle_put))
            .route("/{tail:.*}", web::delete().to(handle_delete))
    })
    .bind(("127.0.0.1", 8765))?
    .run()
    .await
}
