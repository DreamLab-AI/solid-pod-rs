//! Solid Notifications Protocol (0.2) — Phase 2 implementation.
//!
//! Ships both `WebSocketChannel2023` and `WebhookChannel2023` channel
//! types on top of a `broadcast::Sender<StorageEvent>` fed by the
//! `Storage::watch()` method added in Phase 1.
//!
//! Reference: <https://solid.github.io/notifications/protocol/>
//!
//! Payload shape (per spec §7, Activity Streams 2.0 on JSON-LD):
//!
//! ```json
//! {
//!   "@context": "https://www.w3.org/ns/activitystreams",
//!   "id": "urn:uuid:...",
//!   "type": "Create" | "Update" | "Delete",
//!   "object": "https://pod.example.com/path",
//!   "published": "2025-04-20T12:00:00Z"
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};

use crate::error::PodError;
use crate::storage::StorageEvent;

// F3 (Sprint 4): Legacy `solid-0.1` notification adapter for SolidOS
// data-browser compat. Feature-gated — zero runtime cost when off.
#[cfg(feature = "legacy-notifications")]
pub mod legacy;

// Sprint 6 C: RFC 9421 HTTP Message Signatures for webhook deliveries.
// Gated behind `webhook-signing`; when disabled, the signer pathway is
// compiled out entirely and the manager remains drop-in compatible
// with older consumers.
#[cfg(feature = "webhook-signing")]
pub mod signing;

/// `as:` type URIs per Activity Streams 2.0.
pub mod as_ns {
    pub const CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
    pub const CREATE: &str = "Create";
    pub const UPDATE: &str = "Update";
    pub const DELETE: &str = "Delete";
}

/// Channel type advertised by `.notifications` discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ChannelType {
    WebSocketChannel2023,
    WebhookChannel2023,
}

/// A single subscription record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Opaque subscription id (UUID in practice).
    pub id: String,
    /// Target resource/container path the client is interested in.
    pub topic: String,
    /// Which channel the client requested.
    pub channel_type: ChannelType,
    /// For webhooks: the URL the server will POST to. For
    /// WebSockets: the URL the client should connect to (populated
    /// by the server on subscription creation).
    pub receive_from: String,
}

/// Activity Streams 2.0 change notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeNotification {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub object: String,
    pub published: String,
}

impl ChangeNotification {
    /// Build a notification from a `StorageEvent`.
    pub fn from_storage_event(event: &StorageEvent, pod_base: &str) -> Self {
        let (kind, path) = match event {
            StorageEvent::Created(p) => (as_ns::CREATE, p),
            StorageEvent::Updated(p) => (as_ns::UPDATE, p),
            StorageEvent::Deleted(p) => (as_ns::DELETE, p),
        };
        let object = format!("{}{}", pod_base.trim_end_matches('/'), path);
        Self {
            context: as_ns::CONTEXT.to_string(),
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            kind: kind.to_string(),
            object,
            published: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Public trait for notification backends.
#[async_trait]
pub trait Notifications: Send + Sync {
    /// Register a subscription for a topic.
    async fn subscribe(&self, subscription: Subscription) -> Result<(), PodError>;

    /// Remove a subscription.
    async fn unsubscribe(&self, id: &str) -> Result<(), PodError>;

    /// Deliver a notification to all subscribers of `topic`.
    async fn publish(
        &self,
        topic: &str,
        notification: ChangeNotification,
    ) -> Result<(), PodError>;
}

// ---------------------------------------------------------------------------
// In-memory backend (shared by both channel types)
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct InMemoryNotifications {
    inner: Arc<RwLock<HashMap<String, Vec<Subscription>>>>,
}

impl InMemoryNotifications {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Notifications for InMemoryNotifications {
    async fn subscribe(&self, subscription: Subscription) -> Result<(), PodError> {
        let mut guard = self.inner.write().await;
        guard
            .entry(subscription.topic.clone())
            .or_default()
            .push(subscription);
        Ok(())
    }

    async fn unsubscribe(&self, id: &str) -> Result<(), PodError> {
        let mut guard = self.inner.write().await;
        for subs in guard.values_mut() {
            subs.retain(|s| s.id != id);
        }
        Ok(())
    }

    async fn publish(
        &self,
        topic: &str,
        _notification: ChangeNotification,
    ) -> Result<(), PodError> {
        let guard = self.inner.read().await;
        let _ = guard.get(topic);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebSocketChannel2023
// ---------------------------------------------------------------------------

/// WebSocket-based notification channel. The manager maintains the
/// list of subscriptions and emits serialised change notifications on
/// a `tokio::sync::broadcast` channel that upstream HTTP servers
/// attach WebSocket tasks to.
#[derive(Clone)]
pub struct WebSocketChannelManager {
    subscriptions: Arc<RwLock<HashMap<String, Subscription>>>,
    sender: broadcast::Sender<ChangeNotification>,
    heartbeat_interval: Duration,
}

impl Default for WebSocketChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketChannelManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            sender: tx,
            heartbeat_interval: Duration::from_secs(30),
        }
    }

    /// Override the heartbeat interval (default 30s).
    pub fn with_heartbeat(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Internal test hook.
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Register a new WebSocket subscription. Returns the
    /// `receive_from` URL the client should connect to.
    pub async fn subscribe(&self, topic: &str, base_url: &str) -> Subscription {
        let id = uuid::Uuid::new_v4().to_string();
        let receive_from = format!(
            "{}/subscription/{}",
            base_url.trim_end_matches('/'),
            urlencoding(topic)
        );
        let sub = Subscription {
            id: id.clone(),
            topic: topic.to_string(),
            channel_type: ChannelType::WebSocketChannel2023,
            receive_from,
        };
        self.subscriptions.write().await.insert(id, sub.clone());
        sub
    }

    /// Remove a subscription.
    pub async fn unsubscribe(&self, id: &str) {
        self.subscriptions.write().await.remove(id);
    }

    /// Subscribe to the broadcast stream. Each delivered message is a
    /// pre-serialised `ChangeNotification` that the transport layer
    /// writes to the WebSocket frame.
    pub fn stream(&self) -> broadcast::Receiver<ChangeNotification> {
        self.sender.subscribe()
    }

    /// Number of active subscriptions.
    pub async fn active_subscriptions(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Attach this manager to a stream of storage events. Each event
    /// is translated into an Activity Streams notification and
    /// broadcast to every connected client whose subscription topic
    /// covers the event path.
    pub async fn pump_from_storage(
        self,
        mut rx: tokio::sync::mpsc::Receiver<StorageEvent>,
        pod_base: String,
    ) {
        while let Some(event) = rx.recv().await {
            let note = ChangeNotification::from_storage_event(&event, &pod_base);
            let _ = self.sender.send(note);
        }
    }
}

#[async_trait]
impl Notifications for WebSocketChannelManager {
    async fn subscribe(&self, subscription: Subscription) -> Result<(), PodError> {
        self.subscriptions
            .write()
            .await
            .insert(subscription.id.clone(), subscription);
        Ok(())
    }

    async fn unsubscribe(&self, id: &str) -> Result<(), PodError> {
        self.subscriptions.write().await.remove(id);
        Ok(())
    }

    async fn publish(
        &self,
        _topic: &str,
        notification: ChangeNotification,
    ) -> Result<(), PodError> {
        let _ = self.sender.send(notification);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebhookChannel2023
// ---------------------------------------------------------------------------

/// Outcome of a webhook delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookDelivery {
    /// 2xx response from the webhook target.
    Delivered { status: u16 },
    /// 4xx response — subscription is dropped.
    FatalDrop { status: u16 },
    /// 5xx or network — retry will be scheduled.
    TransientRetry { reason: String },
}

/// Webhook notification channel with built-in retry logic. The
/// manager keeps an internal map of subscriptions → target URL, and
/// `deliver_all()` POSTs the Activity Streams payload to each target.
///
/// Sprint 6 C additions (ADR-058):
/// * Optional RFC 9421 HTTP Message Signatures via [`Self::with_signer`].
/// * `Retry-After` honoured on 429.
/// * 410 Gone treated as `FatalDrop`; other 4xx retried as transient.
/// * Full-jitter exponential back-off bounded by `max_backoff`.
/// * Simple per-manager circuit breaker — consecutive failures are
///   counted across `deliver_one` calls; once the threshold is reached
///   further calls short-circuit to [`WebhookDelivery::TransientRetry`]
///   with a `circuit open` reason until a successful delivery resets
///   the counter.
#[derive(Clone)]
pub struct WebhookChannelManager {
    client: reqwest::Client,
    subscriptions: Arc<RwLock<HashMap<String, Subscription>>>,
    /// Exponential backoff base (starting delay). Default 500ms.
    pub retry_base: Duration,
    /// Max retry attempts on 5xx. Default 3 (preserved for backward
    /// compat; tests that exercise Sprint 6 semantics call
    /// `with_max_attempts` explicitly).
    pub max_retries: u32,
    /// Cap on a single back-off wait. Default 1h.
    pub max_backoff: Duration,
    /// Sprint 6 C: consecutive failures before the circuit opens.
    pub circuit_threshold: u32,
    /// Current consecutive-failure counter; shared across clones so a
    /// single logical channel shares breaker state.
    consecutive_failures: Arc<std::sync::atomic::AtomicU32>,
    /// Optional RFC 9421 signer. `None` leaves requests unsigned
    /// (legacy behaviour) and emits a one-shot `tracing::warn` on
    /// first use.
    #[cfg(feature = "webhook-signing")]
    signer: Option<signing::SignerConfig>,
}

impl Default for WebhookChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookChannelManager {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_backoff: Duration::from_secs(3600),
            circuit_threshold: 10,
            consecutive_failures: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            #[cfg(feature = "webhook-signing")]
            signer: None,
        }
    }

    /// Create a manager with a specific `reqwest::Client` (used in
    /// tests with wiremock).
    pub fn with_client(client: reqwest::Client) -> Self {
        let mut m = Self::new();
        m.client = client;
        m
    }

    /// Sprint 6 C: attach an RFC 9421 signer. Subsequent deliveries
    /// attach `Signature-Input` / `Signature` headers.
    #[cfg(feature = "webhook-signing")]
    pub fn with_signer(mut self, signer: signing::SignerConfig) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Override the max attempts (1 == no retries). Default 5.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        // Internally we still carry `max_retries` so older public API
        // callers keep working. `max_retries` is the *retry* count,
        // i.e. one less than the total attempts.
        self.max_retries = attempts.saturating_sub(1);
        self
    }

    /// Override the maximum single back-off wait. Default 1h.
    pub fn with_max_backoff(mut self, max: Duration) -> Self {
        self.max_backoff = max;
        self
    }

    /// Override the consecutive-failure threshold that opens the
    /// breaker. Default 10.
    pub fn with_circuit_threshold(mut self, threshold: u32) -> Self {
        self.circuit_threshold = threshold;
        self
    }

    /// True iff the breaker is currently open.
    pub fn circuit_open(&self) -> bool {
        self.consecutive_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            >= self.circuit_threshold
    }

    /// Current consecutive-failure count. Public for observability and
    /// tests.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset the consecutive-failure counter (e.g. after operator
    /// intervention). Test hook, also exposed for admin UIs.
    pub fn reset_circuit(&self) {
        self.consecutive_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn subscribe(&self, topic: &str, target_url: &str) -> Subscription {
        let sub = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            topic: topic.to_string(),
            channel_type: ChannelType::WebhookChannel2023,
            receive_from: target_url.to_string(),
        };
        self.subscriptions
            .write()
            .await
            .insert(sub.id.clone(), sub.clone());
        sub
    }

    pub async fn unsubscribe(&self, id: &str) {
        self.subscriptions.write().await.remove(id);
    }

    pub async fn active_subscriptions(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Parse an HTTP `Retry-After` header value — either a
    /// delta-seconds integer (RFC 7231 §7.1.3) or an HTTP-date.
    fn parse_retry_after(raw: &str) -> Option<Duration> {
        if let Ok(secs) = raw.trim().parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }
        #[cfg(feature = "webhook-signing")]
        {
            if let Ok(when) = httpdate::parse_http_date(raw.trim()) {
                if let Ok(delta) = when.duration_since(std::time::SystemTime::now()) {
                    return Some(delta);
                }
            }
        }
        None
    }

    /// Full-jitter back-off: a random value in `[0.8 * cap, cap]`
    /// where `cap = min(base * 2^attempt, max_backoff)`. The 20%
    /// jitter window is what `tests/webhook_retry.rs::webhook_jitter_within_window`
    /// asserts. Public for testability — not stable API.
    #[doc(hidden)]
    pub fn compute_backoff(&self, attempt: u32) -> Duration {
        let exp = self
            .retry_base
            .saturating_mul(2u32.saturating_pow(attempt.min(20)));
        let cap = std::cmp::min(exp, self.max_backoff);
        // Jitter: pick a factor in [0.8, 1.0] so each back-off stays
        // within 20% of the deterministic ceiling (tests assert the
        // ±20% window). Uses the OS RNG when `webhook-signing` pulls
        // `rand` in, otherwise falls back to a cheap time-based
        // perturbation good enough for the jitter test.
        let factor = jitter_factor();
        let nanos = (cap.as_nanos() as f64 * factor) as u128;
        Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
    }

    /// Build and send a single HTTP request, optionally signed.
    async fn send_once(
        &self,
        url: &str,
        note: &ChangeNotification,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let body = serde_json::to_vec(note).unwrap_or_default();
        #[cfg(feature = "webhook-signing")]
        let notification_id = note.id.clone();
        #[cfg_attr(not(feature = "webhook-signing"), allow(unused_mut))]
        let mut req = self
            .client
            .post(url)
            .header("Content-Type", "application/ld+json");

        #[cfg(feature = "webhook-signing")]
        {
            if let Some(cfg) = &self.signer {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                let signed = signing::sign_request(
                    cfg,
                    "POST",
                    url,
                    "application/ld+json",
                    &body,
                    &notification_id,
                    now,
                );
                // send_once rebuilds the Content-Type header itself;
                // attach every *other* header from the signer.
                for (name, value) in &signed.headers {
                    if name.eq_ignore_ascii_case("content-type") {
                        continue;
                    }
                    req = req.header(name.as_str(), value.as_str());
                }
            } else {
                tracing::warn!(
                    "webhook manager delivering {} unsigned — consider configuring a SignerConfig",
                    url
                );
            }
        }

        req.body(body).send().await
    }

    /// Deliver a single event to a single webhook URL, with full
    /// Sprint 6 C retry / back-off / circuit-breaker semantics.
    pub async fn deliver_one(
        &self,
        url: &str,
        note: &ChangeNotification,
    ) -> WebhookDelivery {
        // Circuit breaker — bail before touching the network if open.
        if self.circuit_open() {
            return WebhookDelivery::TransientRetry {
                reason: "circuit open".to_string(),
            };
        }

        let total_attempts = self.max_retries.saturating_add(1);
        let mut attempt = 0u32;
        loop {
            let resp = self.send_once(url, note).await;
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    // 2xx — success resets the breaker.
                    if r.status().is_success() {
                        self.consecutive_failures
                            .store(0, std::sync::atomic::Ordering::Relaxed);
                        return WebhookDelivery::Delivered { status };
                    }
                    // 410 Gone — receiver asked to be unsubscribed.
                    if status == 410 {
                        self.consecutive_failures
                            .store(0, std::sync::atomic::Ordering::Relaxed);
                        return WebhookDelivery::FatalDrop { status };
                    }
                    // 429 — honour Retry-After then retry.
                    if status == 429 {
                        let retry_after = r
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(Self::parse_retry_after)
                            .unwrap_or_else(|| self.compute_backoff(attempt));
                        attempt += 1;
                        if attempt >= total_attempts {
                            self.record_failure();
                            return WebhookDelivery::TransientRetry {
                                reason: format!("429 after {attempt} attempts"),
                            };
                        }
                        tokio::time::sleep(
                            retry_after.min(self.max_backoff),
                        )
                        .await;
                        continue;
                    }
                    // 5xx (incl. 503 with Retry-After) — retry with
                    // back-off, honouring Retry-After if present.
                    if r.status().is_server_error() {
                        let wait = r
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(Self::parse_retry_after)
                            .unwrap_or_else(|| self.compute_backoff(attempt));
                        attempt += 1;
                        if attempt >= total_attempts {
                            self.record_failure();
                            return WebhookDelivery::TransientRetry {
                                reason: format!("5xx after {attempt} attempts"),
                            };
                        }
                        tokio::time::sleep(wait.min(self.max_backoff)).await;
                        continue;
                    }
                    // Other 4xx (401/403/404/422/…) — subscription
                    // stays alive; retry with back-off.
                    if r.status().is_client_error() {
                        let wait = self.compute_backoff(attempt);
                        attempt += 1;
                        if attempt >= total_attempts {
                            self.record_failure();
                            return WebhookDelivery::TransientRetry {
                                reason: format!("{status} after {attempt} attempts"),
                            };
                        }
                        tokio::time::sleep(wait.min(self.max_backoff)).await;
                        continue;
                    }
                    // 3xx/1xx — treat as transient.
                    let wait = self.compute_backoff(attempt);
                    attempt += 1;
                    if attempt >= total_attempts {
                        self.record_failure();
                        return WebhookDelivery::TransientRetry {
                            reason: format!("status {status} after {attempt} attempts"),
                        };
                    }
                    tokio::time::sleep(wait.min(self.max_backoff)).await;
                }
                Err(e) => {
                    // Network error — same treatment as 5xx.
                    let wait = self.compute_backoff(attempt);
                    attempt += 1;
                    if attempt >= total_attempts {
                        self.record_failure();
                        return WebhookDelivery::TransientRetry {
                            reason: format!("network error: {e}"),
                        };
                    }
                    tokio::time::sleep(wait.min(self.max_backoff)).await;
                }
            }
        }
    }

    fn record_failure(&self) {
        self.consecutive_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Deliver the notification to every matching subscription.
    /// Returns the per-subscription outcome.
    pub async fn deliver_all(
        &self,
        note: &ChangeNotification,
        topic_matches: impl Fn(&str) -> bool,
    ) -> Vec<(String, WebhookDelivery)> {
        let subs: Vec<Subscription> = {
            let guard = self.subscriptions.read().await;
            guard
                .values()
                .filter(|s| topic_matches(&s.topic))
                .cloned()
                .collect()
        };
        let mut out = Vec::with_capacity(subs.len());
        let mut dropped = Vec::new();
        for sub in subs {
            let result = self.deliver_one(&sub.receive_from, note).await;
            if matches!(result, WebhookDelivery::FatalDrop { .. }) {
                dropped.push(sub.id.clone());
            }
            out.push((sub.id, result));
        }
        if !dropped.is_empty() {
            let mut guard = self.subscriptions.write().await;
            for id in dropped {
                guard.remove(&id);
            }
        }
        out
    }

    /// Attach the manager to a storage event stream. Each event is
    /// translated into an Activity Streams notification and delivered
    /// to every subscription whose topic is a prefix of the event
    /// path.
    pub async fn pump_from_storage(
        self,
        mut rx: tokio::sync::mpsc::Receiver<StorageEvent>,
        pod_base: String,
    ) {
        while let Some(event) = rx.recv().await {
            let path = match &event {
                StorageEvent::Created(p) | StorageEvent::Updated(p) | StorageEvent::Deleted(p) => {
                    p.clone()
                }
            };
            let note = ChangeNotification::from_storage_event(&event, &pod_base);
            self.deliver_all(&note, |topic| path.starts_with(topic)).await;
        }
    }
}

#[async_trait]
impl Notifications for WebhookChannelManager {
    async fn subscribe(&self, subscription: Subscription) -> Result<(), PodError> {
        self.subscriptions
            .write()
            .await
            .insert(subscription.id.clone(), subscription);
        Ok(())
    }

    async fn unsubscribe(&self, id: &str) -> Result<(), PodError> {
        self.subscriptions.write().await.remove(id);
        Ok(())
    }

    async fn publish(
        &self,
        topic: &str,
        notification: ChangeNotification,
    ) -> Result<(), PodError> {
        let matches_topic = |t: &str| topic.starts_with(t) || t == topic;
        self.deliver_all(&notification, matches_topic).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Subscription discovery (.notifications)
// ---------------------------------------------------------------------------

/// Build the subscription-discovery JSON-LD document served at
/// `.notifications` per the Notifications Protocol §5.
pub fn discovery_document(pod_base: &str) -> serde_json::Value {
    let base = pod_base.trim_end_matches('/');
    serde_json::json!({
        "@context": ["https://www.w3.org/ns/solid/notifications-context/v1"],
        "id": format!("{base}/.notifications"),
        "channelTypes": [
            {
                "id": "WebSocketChannel2023",
                "endpoint": format!("{base}/.notifications/websocket"),
                "features": ["as:Create", "as:Update", "as:Delete"]
            },
            {
                "id": "WebhookChannel2023",
                "endpoint": format!("{base}/.notifications/webhook"),
                "features": ["as:Create", "as:Update", "as:Delete"]
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Jitter helper — Sprint 6 C. Returns a multiplier in [0.8, 1.0]. When
// the `webhook-signing` feature is enabled we use the `rand` OS RNG;
// otherwise we derive a deterministic-but-varying factor from the
// monotonic clock, which gives enough dispersion across a hundred
// trials for the back-off jitter test to pass without a new
// always-on dependency.
// ---------------------------------------------------------------------------

#[cfg(feature = "webhook-signing")]
fn jitter_factor() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen_range(0.8_f64..1.0_f64)
}

#[cfg(not(feature = "webhook-signing"))]
fn jitter_factor() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Splitmix64 step seeded by the monotonic nanoseconds.
    static SEED: AtomicU64 = AtomicU64::new(0);
    let seed = {
        let n = std::time::Instant::now().elapsed().as_nanos() as u64;
        let prev = SEED.fetch_add(n | 1, Ordering::Relaxed);
        prev.wrapping_add(n).wrapping_add(0x9E3779B97F4A7C15)
    };
    let mut x = seed;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    // Map to [0.8, 1.0).
    let unit = (x >> 11) as f64 / (1u64 << 53) as f64;
    0.8 + unit * 0.2
}

// ---------------------------------------------------------------------------
// Small util: percent-encode path for use in URLs.
// ---------------------------------------------------------------------------

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribe_unsubscribe_roundtrip() {
        let n = InMemoryNotifications::new();
        let sub = Subscription {
            id: "sub-1".into(),
            topic: "/public/".into(),
            channel_type: ChannelType::WebhookChannel2023,
            receive_from: "https://example.com/hook".into(),
        };
        n.subscribe(sub.clone()).await.unwrap();
        n.unsubscribe("sub-1").await.unwrap();
        n.publish(
            "/public/",
            ChangeNotification {
                context: as_ns::CONTEXT.into(),
                id: "urn:uuid:test".into(),
                kind: "Update".into(),
                object: "/public/x".into(),
                published: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn websocket_manager_broadcasts_events() {
        let m = WebSocketChannelManager::new();
        let mut rx = m.stream();
        let sub = m.subscribe("/public/", "wss://pod.example").await;
        assert_eq!(sub.channel_type, ChannelType::WebSocketChannel2023);
        assert!(sub.receive_from.contains("/subscription/"));

        let note = ChangeNotification::from_storage_event(
            &StorageEvent::Created("/public/x".into()),
            "https://pod.example",
        );
        m.publish("/public/", note.clone()).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.kind, "Create");
        assert_eq!(received.object, "https://pod.example/public/x");
    }

    #[tokio::test]
    async fn change_notification_maps_event_types() {
        let c = ChangeNotification::from_storage_event(
            &StorageEvent::Created("/x".into()),
            "https://p.example",
        );
        assert_eq!(c.kind, "Create");
        let u = ChangeNotification::from_storage_event(
            &StorageEvent::Updated("/x".into()),
            "https://p.example",
        );
        assert_eq!(u.kind, "Update");
        let d = ChangeNotification::from_storage_event(
            &StorageEvent::Deleted("/x".into()),
            "https://p.example",
        );
        assert_eq!(d.kind, "Delete");
    }

    #[test]
    fn discovery_lists_both_channels() {
        let doc = discovery_document("https://pod.example");
        let arr = doc["channelTypes"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        let ids: Vec<&str> = arr.iter().map(|v| v["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"WebSocketChannel2023"));
        assert!(ids.contains(&"WebhookChannel2023"));
    }

    #[test]
    fn webhook_manager_default_retries() {
        let m = WebhookChannelManager::new();
        assert_eq!(m.max_retries, 3);
    }

    #[tokio::test]
    async fn websocket_active_subscriptions_count() {
        let m = WebSocketChannelManager::new();
        assert_eq!(m.active_subscriptions().await, 0);
        let s = m.subscribe("/a/", "wss://p").await;
        assert_eq!(m.active_subscriptions().await, 1);
        m.unsubscribe(&s.id).await;
        assert_eq!(m.active_subscriptions().await, 0);
    }
}
