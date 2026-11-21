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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::{
    http_sig::{sign_request, OutboundRequest},
    ssrf::{resolve_ssrf_safe_with, SsrfGuard},
    store::{host_of, DeliveryItem, Store},
};

/// Retry backoff schedule in seconds. Index = attempt count prior to
/// this attempt; we cap at the final step.
const BACKOFF_SECONDS: &[i64] = &[30, 120, 600, 3_600, 21_600, 86_400];

/// Deliveries attempted at once across all hosts.
pub const MAX_CONCURRENT_DELIVERIES: usize = 8;

/// Deliveries attempted at once to one host (by hostname, not port), so a slow
/// host holds at most this many of the [`MAX_CONCURRENT_DELIVERIES`] slots.
pub const MAX_INFLIGHT_PER_HOST: usize = 2;

/// Consecutive failed attempts to a host before its circuit opens.
pub const BREAKER_THRESHOLD: u32 = 5;

/// How long a freshly opened circuit stays open; each further failure doubles
/// it, up to [`BREAKER_MAX_OPEN`]. After it lapses one attempt is let through.
pub const BREAKER_BASE_OPEN: Duration = Duration::from_secs(30);

/// Longest a circuit stays open.
pub const BREAKER_MAX_OPEN: Duration = Duration::from_secs(3_600);

/// Maximum attempts before we give up and drop the queue entry.
const MAX_ATTEMPTS: i64 = BACKOFF_SECONDS.len() as i64;

/// Outcome of a single delivery attempt — exposed for tests + metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    /// Permanent — no more retries. Either 4xx or max attempts.
    Dropped,
    /// Transient — will retry after `next_retry_secs`.
    Rescheduled {
        next_retry_secs: i64,
    },
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
    /// When true, skip SSRF validation. Only intended for tests where
    /// the mock server binds to 127.0.0.1.
    skip_ssrf_check: bool,
    /// Address classes a delivery may reach (strict unless a test says so).
    guard: SsrfGuard,
    /// Global bound on concurrent attempts made by [`Self::run`].
    slots: Arc<Semaphore>,
    /// In-flight rows and per-host health, shared by the attempts.
    hosts: Mutex<HostState>,
}

/// What the concurrent runner knows about hosts: rows being attempted (so two
/// tasks never take one row), per-host in-flight counts and circuit breakers.
#[derive(Default)]
struct HostState {
    inflight_ids: HashSet<i64>,
    inflight_per_host: HashMap<String, usize>,
    health: HashMap<String, Health>,
}

#[derive(Default)]
struct Health {
    failures: u32,
    open_until: Option<Instant>,
}

impl DeliveryWorker {
    pub fn new(store: Store, config: DeliveryConfig) -> Self {
        Self {
            store,
            config,
            http: reqwest::Client::builder()
                .user_agent("solid-pod-rs-activitypub/0.4.0")
                .timeout(Duration::from_secs(30))
                // Never auto-follow a 3xx from a target inbox: that is the
                // redirect leg of the SSRF chain. The production path builds
                // a per-request pinned client (also redirect-none) in
                // `drain_once`; this shared client is the test fallback.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds"),
            skip_ssrf_check: false,
            guard: SsrfGuard::strict(),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
            hosts: Mutex::default(),
        }
    }

    /// Replace the address guard. Tests federating two local servers pass
    /// [`SsrfGuard::permit_loopback_for_tests`]; the default is strict.
    #[must_use]
    pub fn with_guard(mut self, guard: SsrfGuard) -> Self {
        self.guard = guard;
        self
    }

    /// Create a worker that skips SSRF checks. **Only for tests** where
    /// the target is a localhost mock server.
    #[cfg(test)]
    fn new_without_ssrf_check(store: Store, config: DeliveryConfig) -> Self {
        Self {
            store,
            config,
            http: reqwest::Client::builder()
                .user_agent("solid-pod-rs-activitypub/0.4.0")
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds"),
            skip_ssrf_check: true,
            guard: SsrfGuard::strict(),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
            hosts: Mutex::default(),
        }
    }

    /// Pop the next due delivery (if any) and attempt it exactly once.
    /// Returns the outcome so tests and observability surfaces can
    /// assert on the transition.
    pub async fn drain_once(&self) -> Result<DeliveryOutcome, crate::error::OutboxError> {
        let Some(item) = self.store.next_due_delivery().await? else {
            return Ok(DeliveryOutcome::Idle);
        };
        self.attempt_tracked(item).await
    }

    /// One attempt, then the host's circuit breaker is updated from its outcome.
    async fn attempt_tracked(
        &self,
        item: DeliveryItem,
    ) -> Result<DeliveryOutcome, crate::error::OutboxError> {
        let host = host_of(&item.inbox_url);
        let outcome = self.attempt(item).await?;
        self.record_health(&host, &outcome);
        Ok(outcome)
    }

    fn record_health(&self, host: &str, outcome: &DeliveryOutcome) {
        let mut st = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        match outcome {
            DeliveryOutcome::Delivered => {
                st.health.remove(host);
            }
            DeliveryOutcome::Rescheduled { .. } => {
                let h = st.health.entry(host.to_string()).or_default();
                h.failures = h.failures.saturating_add(1);
                if h.failures >= BREAKER_THRESHOLD {
                    let doublings = (h.failures - BREAKER_THRESHOLD).min(16);
                    let open = BREAKER_BASE_OPEN
                        .saturating_mul(1u32 << doublings)
                        .min(BREAKER_MAX_OPEN);
                    h.open_until = Some(Instant::now() + open);
                }
            }
            DeliveryOutcome::Dropped | DeliveryOutcome::Idle => {}
        }
    }

    /// Hosts the runner must not pick work for right now: at their in-flight
    /// limit or with an open circuit; plus the rows already being attempted.
    fn blocked(&self) -> (Vec<i64>, Vec<String>) {
        let st = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut hosts: Vec<String> = st
            .inflight_per_host
            .iter()
            .filter(|(_, n)| **n >= MAX_INFLIGHT_PER_HOST)
            .map(|(h, _)| h.clone())
            .collect();
        hosts.extend(
            st.health
                .iter()
                .filter(|(_, h)| h.open_until.is_some_and(|t| t > now))
                .map(|(h, _)| h.clone()),
        );
        (st.inflight_ids.iter().copied().collect(), hosts)
    }

    fn claim(&self, id: i64, host: &str) {
        let mut st = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        st.inflight_ids.insert(id);
        *st.inflight_per_host.entry(host.to_string()).or_insert(0) += 1;
    }

    fn release(&self, id: i64, host: &str) {
        let mut st = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        st.inflight_ids.remove(&id);
        if let Some(n) = st.inflight_per_host.get_mut(host) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.inflight_per_host.remove(host);
            }
        }
    }

    /// Start as many due deliveries as the concurrency bounds allow.
    async fn dispatch(
        self: &Arc<Self>,
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), crate::error::OutboxError> {
        loop {
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                return Ok(());
            };
            let (skip_ids, skip_hosts) = self.blocked();
            let Some(item) = self
                .store
                .next_due_delivery_excluding(&skip_ids, &skip_hosts)
                .await?
            else {
                return Ok(());
            };
            let host = host_of(&item.inbox_url);
            self.claim(item.queue_id, &host);
            let me = Arc::clone(self);
            tasks.spawn(async move {
                let _permit = permit;
                let id = item.queue_id;
                if let Err(e) = me.attempt_tracked(item).await {
                    tracing::warn!(error = %e, "delivery attempt failed");
                }
                me.release(id, &host);
            });
        }
    }

    /// Make exactly one delivery attempt for `item`.
    async fn attempt(
        &self,
        item: DeliveryItem,
    ) -> Result<DeliveryOutcome, crate::error::OutboxError> {
        let Some(activity) = self.store.load_activity(&item.activity_id).await? else {
            // Orphaned queue row — the activity is gone. Drop.
            self.store.drop_delivery(item.queue_id).await?;
            return Ok(DeliveryOutcome::Dropped);
        };

        // P0-09 + TOCTOU: reject delivery to private/internal IPs before
        // the outbound POST, and PIN the connection to the validated IP so
        // a rebinding DNS record cannot swap in an internal address between
        // this check and the connect. `resolve_ssrf_safe` returns the
        // routable address; the per-request client resolves the host to
        // exactly it, with redirects disabled.
        let http = if self.skip_ssrf_check {
            self.http.clone()
        } else {
            let (host, pinned) = match resolve_ssrf_safe_with(&item.inbox_url, self.guard).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        inbox_url = %item.inbox_url,
                        error = %e,
                        "SSRF blocked: dropping delivery to private/internal address"
                    );
                    self.store.drop_delivery(item.queue_id).await?;
                    self.store
                        .mark_outbox_state(&item.activity_id, "failed")
                        .await?;
                    return Ok(DeliveryOutcome::Dropped);
                }
            };
            reqwest::Client::builder()
                .user_agent("solid-pod-rs-activitypub/0.4.0")
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .resolve(&host, pinned)
                .build()
                .map_err(|e| crate::error::OutboxError::Delivery(e.to_string()))?
        };

        let body = serde_json::to_vec(&activity)
            .map_err(|e| crate::error::OutboxError::Delivery(e.to_string()))?;
        let mut req = OutboundRequest {
            method: "POST".into(),
            url: item.inbox_url.clone(),
            headers: vec![("Content-Type".into(), "application/activity+json".into())],
            body,
        };
        sign_request(&mut req, &self.config.private_key_pem, &self.config.key_id)?;

        let request = http.post(&req.url);
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

    /// Enqueue delivery of `activity_id` to an explicit list of inbox
    /// URLs. This is the fan-out entry point used by outbox POST and
    /// matches the JSS v0.0.67 `deliverToFollowers` pattern.
    ///
    /// Returns the number of inboxes enqueued.
    pub async fn enqueue_to_inboxes(
        &self,
        activity_id: &str,
        inboxes: &[String],
    ) -> Result<usize, crate::error::OutboxError> {
        for inbox in inboxes {
            self.store
                .enqueue_delivery(activity_id, inbox)
                .await
                .map_err(crate::error::OutboxError::Storage)?;
        }
        Ok(inboxes.len())
    }

    /// Long-running poller. Every `tick` (or as soon as an attempt finishes) it
    /// starts the due deliveries the bounds allow: at most
    /// [`MAX_CONCURRENT_DELIVERIES`] at once, at most [`MAX_INFLIGHT_PER_HOST`]
    /// per host, none for a host whose circuit is open. A host that never
    /// answers therefore holds at most its own share of slots for its timeout
    /// and never delays another host's rows.
    pub async fn run(self: Arc<Self>, tick: Duration) {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            if let Err(e) = self.dispatch(&mut tasks).await {
                tracing::warn!(error = %e, "delivery worker tick failed");
            }
            if tasks.is_empty() {
                tokio::time::sleep(tick).await;
            } else {
                tokio::select! {
                    _ = tasks.join_next() => {}
                    () = tokio::time::sleep(tick) => {}
                }
            }
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

        let worker = DeliveryWorker::new_without_ssrf_check(store.clone(), config);
        let outcome = worker.drain_once().await.unwrap();
        assert_eq!(outcome, DeliveryOutcome::Delivered);
        assert_eq!(worker.drain_once().await.unwrap(), DeliveryOutcome::Idle);
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

        let worker = DeliveryWorker::new_without_ssrf_check(store.clone(), config);
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

        let worker = DeliveryWorker::new_without_ssrf_check(store.clone(), config);
        assert_eq!(worker.drain_once().await.unwrap(), DeliveryOutcome::Dropped);
    }

    #[tokio::test]
    async fn delivery_idle_when_queue_empty() {
        let (store, config) = scaffold().await;
        let worker = DeliveryWorker::new(store, config);
        assert_eq!(worker.drain_once().await.unwrap(), DeliveryOutcome::Idle);
    }

    #[tokio::test]
    async fn delivery_does_not_follow_redirects() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");
        let server = MockServer::start().await;
        // A 302 pointing at the metadata endpoint must NOT be followed.
        Mock::given(method("POST"))
            .and(path("/inbox"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data"),
            )
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

        let worker = DeliveryWorker::new_without_ssrf_check(store.clone(), config);
        // With redirects disabled the 302 is a non-2xx transient outcome
        // (rescheduled), not a followed hop to the metadata endpoint.
        match worker.drain_once().await.unwrap() {
            DeliveryOutcome::Rescheduled { .. } => {}
            other => panic!("expected Rescheduled (redirect not followed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delivery_drops_ssrf_to_private_ip() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");

        // Enqueue delivery to a private RFC-1918 address.
        let inbox_url = "http://192.168.1.1/inbox";
        store
            .add_follower(&actor.id, "evil-follower", Some(inbox_url))
            .await
            .unwrap();
        handle_outbox(
            &store,
            &actor,
            serde_json::json!({"type": "Create", "object": {"type": "Note", "content": "ssrf test"}}),
        )
        .await
        .unwrap();

        // Use production worker (SSRF checks enabled).
        let worker = DeliveryWorker::new(store.clone(), config);
        let outcome = worker.drain_once().await.unwrap();
        assert_eq!(
            outcome,
            DeliveryOutcome::Dropped,
            "delivery to private IP should be dropped by SSRF filter"
        );
    }

    #[tokio::test]
    async fn delivery_drops_ssrf_to_metadata_endpoint() {
        let (store, config) = scaffold().await;
        let actor = render_actor("https://pod.example", "me", "Me", None, "PEM");

        // Enqueue delivery to the AWS metadata endpoint.
        let inbox_url = "http://169.254.169.254/latest/meta-data";
        store
            .add_follower(&actor.id, "cloud-attacker", Some(inbox_url))
            .await
            .unwrap();
        handle_outbox(
            &store,
            &actor,
            serde_json::json!({"type": "Create", "object": {"type": "Note", "content": "ssrf test"}}),
        )
        .await
        .unwrap();

        let worker = DeliveryWorker::new(store.clone(), config);
        let outcome = worker.drain_once().await.unwrap();
        assert_eq!(
            outcome,
            DeliveryOutcome::Dropped,
            "delivery to link-local/metadata IP should be dropped by SSRF filter"
        );
    }
}
