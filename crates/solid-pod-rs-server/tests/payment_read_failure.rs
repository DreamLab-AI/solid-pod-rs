use async_trait::async_trait;
use bytes::Bytes;
use solid_pod_rs::{
    storage::{memory::MemoryBackend, ResourceMeta, Storage, StorageEvent},
    PodError,
};
use solid_pod_rs_server::{build_app, AppState};
use std::sync::Arc;

struct FailedCanonicalRead(MemoryBackend);

#[async_trait]
impl Storage for FailedCanonicalRead {
    async fn get(&self, path: &str) -> Result<(Bytes, ResourceMeta), PodError> {
        if path == "/.well-known/webledgers/state.json" {
            return Err(PodError::Backend(
                "injected unavailable canonical state".into(),
            ));
        }
        self.0.get(path).await
    }
    async fn put(&self, path: &str, body: Bytes, ct: &str) -> Result<ResourceMeta, PodError> {
        self.0.put(path, body, ct).await
    }
    async fn delete(&self, path: &str) -> Result<(), PodError> {
        self.0.delete(path).await
    }
    async fn list(&self, path: &str) -> Result<Vec<String>, PodError> {
        self.0.list(path).await
    }
    async fn head(&self, path: &str) -> Result<ResourceMeta, PodError> {
        self.0.head(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool, PodError> {
        self.0.exists(path).await
    }
    async fn watch(
        &self,
        path: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<StorageEvent>, PodError> {
        self.0.watch(path).await
    }
}

#[actix_web::test]
async fn unavailable_canonical_state_does_not_become_an_empty_legacy_book() {
    let app = actix_web::test::init_service(build_app(AppState::new(Arc::new(
        FailedCanonicalRead(MemoryBackend::new()),
    ))))
    .await;
    let rsp = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/pay/.offers")
            .to_request(),
    )
    .await;
    assert_eq!(
        rsp.status().as_u16(),
        500,
        "failed canonical read must not return stale or empty offers"
    );
    let app =
        actix_web::test::init_service(build_app(AppState::new(Arc::new(MemoryBackend::new()))))
            .await;
    let rsp = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/pay/.offers")
            .to_request(),
    )
    .await;
    assert_eq!(
        rsp.status().as_u16(),
        200,
        "a genuinely absent canonical state may bootstrap legacy state"
    );
}
