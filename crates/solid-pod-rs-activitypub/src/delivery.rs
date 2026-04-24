//! Background federated-delivery worker.
//!
//! Pulls items from `delivery_queue`, signs each POST per
//! draft-cavage HTTP Signatures (see [`crate::http_sig::sign_request`])
//! and ships it to the target inbox over HTTPS.
//!
//! Retry policy (mirrors `solid_pod_rs::notifications::WebhookChannelManager`):
//!   * 2xx → drop from queue, mark outbox delivered.
//!   * 4xx (except 408/429) → permanent failure — drop, log.
//!   * 5xx/408/429/network → exponential backoff (30s, 2m, 10m, 1h, 6h, 24h).
//!
//! The worker is cooperative: it polls the queue on a tick. Consumers
//! can also trigger a one-shot tick via [`DeliveryWorker::drain_once`]
//! which is how the test-suite exercises the retry logic.

use std::sync::Arc;
use std::time::Duration;

use crate::{
    http_sig::{sign_request, OutboundRequest},
    store::Store,
};

/// Retry backoff schedule in seconds. Index = attempt count prior to
/// this attempt; we cap at the final step.
const BACKOFF_SECONDS: &[i64] = &[30, 120, 600, 3_600, 21_600, 86_400];

/// Maximum attempts before we give up and drop the queue entry.
const MAX_ATTEMPTS: i64 = BACKOFF_SECONDS.len() as i64;

/// Outcome of a single delivery attempt — exposed for tests + metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    /// Permanent — no more retries. Either 4xx or max attempts.
    Dropped,
    /// Transient — will retry after `next_retry_secs`.
    Rescheduled { next_retry_secs: i64 },
    /// Nothing was due.
    Idle,
}

/// Static delivery config — the pod's signing key and Actor key_id
/// (which is published in the Actor document).
#[derive(Clone)]
pub struct DeliveryConfig {
    pub private_key_pem: String,
    pub key_id: String,
}

/// Background worker. Hold an `Arc<DeliveryWorker>` to share between
/// the HTTP task and any admin endpoints that manually flush the
/// queue.
pub struct DeliveryWorker {
    store: Store,
    config: DeliveryConfig,
    http: reqwest::Client,
}

impl DeliveryWorker {
    pub fn new(store: Store, config: DeliveryConfig) -> Self {
        Self {
            store,
            config,
            http: reqwest::Client::builder()
                .user_agent("solid-pod-rs-activitypub/0.4")
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client builds"),
        }
    }

    /// Pop the next due delivery (if any) and attempt it exactly once.
    /// Returns the outcome so tests and observability surfaces can
    /// assert on the transition.
    pub async fn drain_once(&self) -> Result<DeliveryOutcome, crate::error::OutboxError> {
        let Some(item) = self.store.next_due_delivery().await? else {
            return Ok(DeliveryOutcome::Idle);
        };
        let Some(activity) = self.store.load_activity(&item.activity_id).await? else {
            // Orphaned queue row — the activity is gone. Drop.
            self.store.drop_delivery(item.queue_id).await?;
            return Ok(DeliveryOutcome::Dropped);
        };

        let body =
            serde_json::to_vec(&activity).map_err(|e| crate::error::OutboxError::Delivery(e.to_string()))?;
        let mut req = OutboundRequest {
            method: "POST".into(),
            url: item.inbox_url.clone(),
            headers: vec![(
                "Content-Type".into(),
                "application/activity+json".into(),
            )],
            body,
        };
        sign_request(&mut req, &self.config.private_key_pem, &self.config.key_id)?;

        let request = self.http.post(&req.url);
        let request = req
            .headers
            .iter()
            .fold(request, |b, (k, v)| b.header(k, v))
            .body(req.body.clone());

        match request.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    self.store.drop_delivery(item.queue_id).await?;
                    self.store
                        .mark_outbox_state(&item.activity_id, "delivered")
                        .await?;
                    Ok(DeliveryOutcome::Delivered)
                } else if status.is_client_error()
                    && status.as_u16() != 408
                    && status.as_u16() != 429
                {
                    self.store.drop_delivery(item.queue_id).await?;
                    self.store
                        .mark_outbox_state(&item.activity_id, "failed")
                        .await?;
                    Ok(DeliveryOutcome::Dropped)
                } else {
                    let next_attempt = item.attempts + 1;
                    if next_attempt >= MAX_ATTEMPTS {
                        self.store.drop_delivery(item.queue_id).await?;
                        self.store
                            .mark_outbox_state(&item.activity_id, "failed")
                            .await?;
                        return Ok(DeliveryOutcome::Dropped);
                    }
                    let idx = item.attempts.max(0) as usize;
                    let delay = BACKOFF_SECONDS[idx.min(BACKOFF_SECONDS.len() - 1)];
                    self.store
                        .reschedule_delivery(
                            item.queue_id,
                            delay,
                            &format!("HTTP {}", status.as_u16()),
                        )
                        .await?;
                    Ok(DeliveryOutcome::Rescheduled {
                        next_retry_secs: delay,
                    })
                }
            }
            Err(e) => {
                let next_attempt = item.attempts + 1;
                if next_attempt >= MAX_ATTEMPTS {
                    self.store.drop_delivery(item.queue_id).await?;
                    self.store
                        .mark_outbox_state(&item.activity_id, "failed")
                        .await?;
                    return Ok(DeliveryOutcome::Dropped);
                }
                let idx = item.attempts.max(0) as usize;
                let delay = BACKOFF_SECONDS[idx.min(BACKOFF_SECONDS.len() - 1)];
                self.store
                    .reschedule_delivery(item.queue_id, delay, &e.to_string())
                    .await?;
                Ok(DeliveryOutcome::Rescheduled {
                    next_retry_secs: delay,
                })
            }
        }
    }

    /// Long-running poller. Ticks every `tick` and calls
    /// [`Self::drain_once`] until the queue is empty, then sleeps.
    pub async fn run(self: Arc<Self>, tick: Duration) {
        loop {
            loop {
                match self.drain_once().await {
                    Ok(DeliveryOutcome::Idle) => break,
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::warn!(error = %e, "delivery worker tick failed");
                        break;
                    }
                }
            }
            tokio::time::sleep(tick).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::{generate_actor_keypair, render_actor};
    use crate::outbox::handle_outbox;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn scaffold() -> (Store, DeliveryConfig) {
        let store = Store::in_memory().await.unwrap();
        let (priv_pem, _pub_pem) = generate_actor_keypair().unwrap();
        let config = DeliveryConfig {
            private_key_pem: priv_pem,
            key_id: "https://pod.example/profile/card.jsonld#main-key".into(),
        };
        (store, config)
    }

    #[tokio::test]
    async fn delivery_succeeds_and_drops_queue_item() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        let inbox_url = format!("{}/inbox", server.uri());
        store
            .add_follower(&actor.id, "follower-a", Some(&inbox_url))
            .await
            .unwrap();
        handle_outbox(
            &store,
            &actor,
            serde_json::json!({
                "type": "Create",
                "object": {"type": "Note", "content": "hi"}
            }),
        )
        .await
        .unwrap();

        let worker = DeliveryWorker::new(store.clone(), config);
        let outcome = worker.drain_once().await.unwrap();
        assert_eq!(outcome, DeliveryOutcome::Delivered);
        assert_eq!(
            worker.drain_once().await.unwrap(),
            DeliveryOutcome::Idle
        );
    }

    #[tokio::test]
    async fn delivery_retries_on_5xx() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let inbox_url = format!("{}/inbox", server.uri());
        store
            .add_follower(&actor.id, "fa", Some(&inbox_url))
            .await
            .unwrap();
        handle_outbox(
            &store,
            &actor,
            serde_json::json!({"type": "Create", "object": {"type": "Note", "content": "x"}}),
        )
        .await
        .unwrap();

        let worker = DeliveryWorker::new(store.clone(), config);
        match worker.drain_once().await.unwrap() {
            DeliveryOutcome::Rescheduled { next_retry_secs } => {
                assert_eq!(next_retry_secs, BACKOFF_SECONDS[0]);
            }
            other => panic!("expected Rescheduled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delivery_drops_on_4xx() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let inbox_url = format!("{}/inbox", server.uri());
        store
            .add_follower(&actor.id, "fa", Some(&inbox_url))
            .await
            .unwrap();
        handle_outbox(
            &store,
            &actor,
            serde_json::json!({"type": "Create", "object": {"type": "Note", "content": "x"}}),
        )
        .await
        .unwrap();

        let worker = DeliveryWorker::new(store.clone(), config);
        assert_eq!(worker.drain_once().await.unwrap(), DeliveryOutcome::Dropped);
    }

    #[tokio::test]
    async fn delivery_idle_when_queue_empty() {
        let (store, config) = scaffold().await;
        let worker = DeliveryWorker::new(store, config);
        assert_eq!(worker.drain_once().await.unwrap(), DeliveryOutcome::Idle);
    }
}
