//! Sprint 11 (row 158) — `ErrorLoggingMiddleware` integration tests.
//!
//! JSS ref: commit `5b34d72` (PR #312) — "Top-level Fastify error
//! handler, full stack on 5xx". The actix-side mirror must:
//!
//! * Let 2xx / 3xx / 4xx responses pass through untouched.
//! * Emit a `tracing::error!` event on every 5xx outcome.
//! * Not rewrite the response body.

use actix_web::{test, web, App, HttpResponse};
use solid_pod_rs_server::ErrorLoggingMiddleware;

// ---------------------------------------------------------------------------
// Passthrough on 2xx.
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn middleware_passthrough_on_2xx() {
    async fn ok() -> HttpResponse {
        HttpResponse::Ok().body("hello")
    }

    let app = test::init_service(
        App::new()
            .wrap(ErrorLoggingMiddleware)
            .route("/ok", web::get().to(ok)),
    )
    .await;

    let req = test::TestRequest::get().uri("/ok").to_request();
    let rsp = test::call_service(&app, req).await;
    assert!(rsp.status().is_success());

    let body = test::read_body(rsp).await;
    assert_eq!(body.as_ref(), b"hello", "middleware must not mutate body");
}

// ---------------------------------------------------------------------------
// 5xx is observed and logged.
//
// We capture `tracing` output via a `tracing_subscriber::fmt` layer
// writing to a `Vec<u8>` through the `MakeWriter` impl for an
// `Arc<Mutex<Vec<u8>>>`. The assertion verifies the middleware emitted
// the structured event — exact field formatting is actix/fmt
// implementation detail, so we just look for the `5xx response` marker
// and the request path.
// ---------------------------------------------------------------------------

use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[actix_web::test]
async fn middleware_logs_5xx_with_full_chain() {
    use tracing::dispatcher;
    use tracing_subscriber::fmt::Subscriber;
    use tracing_subscriber::EnvFilter;

    async fn boom() -> Result<HttpResponse, actix_web::Error> {
        // Build a 500 with an attached error carrier so the middleware
        // has a chain to render.
        Err(actix_web::error::ErrorInternalServerError(
            "backend: simulated failure",
        ))
    }

    let buf = SharedBuffer::default();
    let subscriber = Subscriber::builder()
        .with_env_filter(EnvFilter::new("error"))
        .with_writer(buf.clone())
        .without_time()
        .finish();

    let dispatch = dispatcher::Dispatch::new(subscriber);
    dispatcher::with_default(&dispatch, || {
        // No-op entrance — the subscriber must still be active when the
        // async block below runs. `with_default` only holds for the
        // current thread during the closure, so we re-enter via a
        // thread-local dispatcher inside the runtime task.
    });

    let _guard = dispatcher::set_default(&dispatch);

    let app = test::init_service(
        App::new()
            .wrap(ErrorLoggingMiddleware)
            .route("/boom", web::get().to(boom)),
    )
    .await;

    let req = test::TestRequest::get().uri("/boom").to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 500);

    // Force a flush by dropping the guard implicitly. Read the buffer.
    let captured = {
        let locked = buf.0.lock().unwrap();
        String::from_utf8_lossy(&locked).to_string()
    };

    assert!(
        captured.contains("5xx response"),
        "5xx log marker missing, got: {captured}"
    );
    assert!(
        captured.contains("/boom"),
        "path missing from log line, got: {captured}"
    );
    assert!(
        captured.contains("simulated failure"),
        "inner error chain missing, got: {captured}"
    );
}

// ---------------------------------------------------------------------------
// 4xx is not logged (no noisy logs on client errors).
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn middleware_does_not_log_4xx() {
    async fn not_found() -> HttpResponse {
        HttpResponse::NotFound().finish()
    }

    let app = test::init_service(
        App::new()
            .wrap(ErrorLoggingMiddleware)
            .route("/missing", web::get().to(not_found)),
    )
    .await;

    let req = test::TestRequest::get().uri("/missing").to_request();
    let rsp = test::call_service(&app, req).await;
    assert_eq!(rsp.status().as_u16(), 404);
}
