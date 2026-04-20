//! Legacy `solid-0.1` WebSocket notifications adapter (F3, Sprint 4).
//!
//! Bridges the existing `WebSocketChannelManager` broadcast stream to
//! SolidOS / old JSS clients which speak the pre-standardised
//! `solid-0.1` wire format. Text-framed over a WebSocket, one line
//! per frame, e.g.:
//!
//! ```text
//! protocol solid-0.1
//! sub https://pod.example.com/foo/
//! ack https://pod.example.com/foo/
//! pub https://pod.example.com/foo/bar
//! unsub https://pod.example.com/foo/
//! ```
//!
//! Reference: `JavaScriptSolidServer/src/notifications/websocket.js`.
//! Domain doc: `docs/design/jss-parity/02-notifications-compat-context.md`.
//!
//! ## Coexistence with Notifications 0.2
//!
//! Both the legacy adapter and `WebSocketChannel2023` subscribe to the
//! same upstream `StorageEvent` broadcast. A single storage event
//! produces both a JSON-LD Activity Streams 2.0 frame (modern clients)
//! and a bare `pub <uri>` line (legacy clients). Neither protocol's
//! failure affects the other.
//!
//! ## Binding to an HTTP server
//!
//! This module is transport-agnostic. A consumer mounts the handler
//! (see [`crate::handlers::legacy_notifications`]) at the path they
//! choose — typically `/ws/solid-0.1`. The adapter consumes inbound
//! `sub` / `unsub` text lines, emits outbound `ack` / `pub` / `err`
//! lines, and pings with a blank line every 30 s (matches JSS).
//!
//! The F7 library-server boundary applies: this crate never mounts
//! itself into an HTTP router. The example binders in
//! `examples/embed_in_actix.rs` show the consumer wiring.
//!
//! ## Subscription authorisation (Sprint 5, P0-3 / CVE-NOTIF-001)
//!
//! [`LegacyNotificationChannel::subscribe`] refuses a subscription
//! unless **both**
//!
//! 1. the target URL's origin matches the configured
//!    [`with_server_origin`](LegacyNotificationChannel::with_server_origin)
//!    (if set), **and**
//! 2. the configured [`SubscriptionAuthorizer`] returns `Ok(())`.
//!
//! The default authorizer is [`DenyAllAuthorizer`] — **fail-closed**.
//! A channel constructed with no explicit authorizer will reject every
//! `sub` frame with `err <uri> forbidden`. Consumers that want
//! anonymous-accessible notifications (public demo pods, tests) must
//! opt in explicitly by calling
//! [`with_authorizer`](LegacyNotificationChannel::with_authorizer) with
//! [`AllowAllAuthorizer`] or their own policy object.
//!
//! Production deployments should wire a
//! [`SubscriptionAuthorizer`] that calls
//! `crate::wac::evaluate_access(..., AccessMode::Read)` against the
//! resolved target URI, using the WebID supplied via
//! [`with_web_id`](LegacyNotificationChannel::with_web_id). That mirrors
//! JSS' `WebSocketHandler#authorize` hook (see
//! `JavaScriptSolidServer/src/notifications/websocket.js`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::{error::RecvError, Receiver};

use crate::storage::StorageEvent;

/// Default per-connection subscription cap (matches JSS).
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 100;

/// Default target-URL cap in bytes (matches JSS `MAX_URL_LENGTH`).
pub const MAX_URL_LENGTH: usize = 2048;

/// Default heartbeat interval. JSS does not heartbeat; SolidOS data-
/// browser is happy without one, but intermediaries (nginx, Cloudflare)
/// usually idle-timeout idle WebSockets after ~60 s. Emitting a blank
/// line every 30 s keeps the connection warm without poisoning the
/// legacy parser (blank lines are ignored by SolidOS).
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Protocol greeting sent on connect.
pub const PROTOCOL_GREETING: &str = "protocol solid-0.1";

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// One of the five `solid-0.1` opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SolidZeroOp {
    /// Client → server: subscribe to `<uri>`.
    Sub,
    /// Server → client: subscribe acknowledged for `<uri>`.
    Ack,
    /// Server → client: error for `<uri>` (e.g. WAC denied).
    Err,
    /// Server → client: resource at `<uri>` changed.
    Pub,
    /// Client → server: unsubscribe from `<uri>`.
    Unsub,
}

impl SolidZeroOp {
    /// Opcode as it appears on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            SolidZeroOp::Sub => "sub",
            SolidZeroOp::Ack => "ack",
            SolidZeroOp::Err => "err",
            SolidZeroOp::Pub => "pub",
            SolidZeroOp::Unsub => "unsub",
        }
    }
}

// ---------------------------------------------------------------------------
// SubscriptionAuthorizer — WAC read enforcement hook (P0-3, Sprint 5)
// ---------------------------------------------------------------------------

/// Reason a [`SubscriptionAuthorizer`] refused a target. Mapped to the
/// single JSS-recognised wire token `forbidden` on the way out — JSS
/// clients (SolidOS mashlib) only decode that one denial keyword, so
/// new dashed tokens would be silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// WAC evaluation denied read access to the target resource.
    Forbidden,
    /// The target's origin did not match the server origin. Reported
    /// separately from [`Forbidden`] so callers can log or meter
    /// cross-origin attack traffic distinctly.
    CrossOrigin,
}

/// Policy object consulted by
/// [`LegacyNotificationChannel::subscribe`] before a subscription is
/// accepted. Implementations should call
/// `crate::wac::evaluate_access(target, subject, AccessMode::Read)` and
/// translate the result to `Ok(())` or `Err(DenyReason::Forbidden)`.
///
/// Sync, by deliberate design: the `subscribe` call path is sync (the
/// broadcast layer above it is sync), and the WAC evaluator is
/// in-memory. Implementations that need async (e.g. fetching remote
/// ACL docs) should block on their runtime's `block_on` or precompute
/// an access matrix at connection-upgrade time and hand this trait a
/// read-only cache.
pub trait SubscriptionAuthorizer: Send + Sync {
    /// Decide whether `subject` (the resolved WebID, or `None` for an
    /// anonymous WebSocket connection) may read — and therefore
    /// subscribe to change events on — `target` (absolute URL of the
    /// resource whose fan-out the client is asking for).
    fn check(&self, target: &str, subject: Option<&str>) -> Result<(), DenyReason>;
}

/// Permissive authorizer. Use only for explicit "no auth" deployments
/// (e.g. public demo pods that want to broadcast change events to
/// anyone) or in tests where the WAC surface is out of scope. **Never
/// the default.**
pub struct AllowAllAuthorizer;

impl SubscriptionAuthorizer for AllowAllAuthorizer {
    fn check(&self, _: &str, _: Option<&str>) -> Result<(), DenyReason> {
        Ok(())
    }
}

/// Fail-closed authorizer — denies everything. This is the default
/// installed by [`LegacyNotificationChannel::new`] to guarantee that a
/// mis-configured server never silently broadcasts change events to
/// un-authorised clients. Production deployments MUST replace this
/// with a real WAC-backed authorizer via
/// [`LegacyNotificationChannel::with_authorizer`].
pub struct DenyAllAuthorizer;

impl SubscriptionAuthorizer for DenyAllAuthorizer {
    fn check(&self, _: &str, _: Option<&str>) -> Result<(), DenyReason> {
        Err(DenyReason::Forbidden)
    }
}

// ---------------------------------------------------------------------------
// LegacyNotificationChannel
// ---------------------------------------------------------------------------

/// Per-connection legacy adapter. One instance per upgraded WebSocket.
///
/// Owns the subscription set for that socket and a broadcast receiver
/// of upstream `StorageEvent`s. The aggregate is short-lived: created
/// on WS upgrade, dropped on close/error. Fan-out is lossy-by-design:
/// if the consumer's per-socket outbound queue saturates, older events
/// are dropped (matches JSS; prevents a slow client from back-
/// pressuring the storage layer).
///
/// # Example
///
/// ```ignore
/// use tokio::sync::broadcast;
/// use solid_pod_rs::notifications::legacy::LegacyNotificationChannel;
/// use solid_pod_rs::storage::StorageEvent;
///
/// let (tx, rx) = broadcast::channel::<StorageEvent>(1024);
/// let mut chan = LegacyNotificationChannel::new(rx);
///
/// // Client sent "sub https://pod.example.com/foo/":
/// if let Some(target) = LegacyNotificationChannel::parse_subscribe("sub https://pod.example.com/foo/") {
///     chan.subscribe(target);
/// }
///
/// // Upstream storage fan-out:
/// let _ = tx.send(StorageEvent::Updated("/foo/bar.ttl".into()));
///
/// // Would produce `pub https://pod.example.com/foo/bar.ttl` if the
/// // consumer normalises paths against the pod base URL; see
/// // [`LegacyNotificationChannel::matches_subscription`].
/// ```
pub struct LegacyNotificationChannel {
    storage_events: Receiver<StorageEvent>,
    subscriptions: HashSet<String>,
    url_cap_bytes: usize,
    max_subs_per_conn: usize,
    heartbeat_interval: Duration,
    /// Authorizer consulted on every `subscribe`. Default:
    /// [`DenyAllAuthorizer`] (fail-closed). See module docs.
    authorizer: Arc<dyn SubscriptionAuthorizer>,
    /// Server origin (`<scheme>://<host>[:<port>]`). When `Some`, the
    /// target URL's origin must match exactly or the subscription is
    /// rejected with `forbidden`. `None` disables the same-origin
    /// check (intended for embedded test pods only).
    server_origin: Option<String>,
    /// Resolved WebID of the upstream WebSocket connection, passed to
    /// the authorizer. `None` = anonymous.
    web_id: Option<String>,
}

impl LegacyNotificationChannel {
    /// New channel bound to an upstream broadcast of storage events.
    ///
    /// The authorizer defaults to [`DenyAllAuthorizer`] — the returned
    /// channel will reject every subscription until the caller swaps
    /// in a real policy via [`with_authorizer`](Self::with_authorizer).
    /// This is deliberate: a fresh channel must never broadcast change
    /// events to un-authenticated clients.
    pub fn new(storage_events: Receiver<StorageEvent>) -> Self {
        Self {
            storage_events,
            subscriptions: HashSet::new(),
            url_cap_bytes: MAX_URL_LENGTH,
            max_subs_per_conn: MAX_SUBSCRIPTIONS_PER_CONNECTION,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            authorizer: Arc::new(DenyAllAuthorizer),
            server_origin: None,
            web_id: None,
        }
    }

    /// Override the heartbeat interval. Primarily for tests.
    pub fn with_heartbeat(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Override the URL length cap. Primarily for tests.
    pub fn with_url_cap(mut self, cap: usize) -> Self {
        self.url_cap_bytes = cap;
        self
    }

    /// Override the subscription cap. Primarily for tests.
    pub fn with_subscription_cap(mut self, cap: usize) -> Self {
        self.max_subs_per_conn = cap;
        self
    }

    /// Install the [`SubscriptionAuthorizer`] consulted on every
    /// `subscribe`. Production deployments MUST call this with a
    /// WAC-backed policy; the default is [`DenyAllAuthorizer`].
    pub fn with_authorizer(mut self, authorizer: Arc<dyn SubscriptionAuthorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    /// Configure the server origin for the same-origin check. Pass the
    /// canonical `<scheme>://<host>[:<port>]` form — e.g.
    /// `"https://pod.example.org"` or `"http://localhost:3000"`.
    /// Any `subscribe` target whose parsed origin differs is rejected
    /// with `forbidden` before the authorizer is even consulted.
    pub fn with_server_origin(mut self, origin: String) -> Self {
        self.server_origin = Some(origin);
        self
    }

    /// Set the WebID associated with this connection. Passed to the
    /// authorizer as the `subject` argument. `None` = anonymous (the
    /// authorizer decides whether public access is allowed).
    pub fn with_web_id(mut self, web_id: Option<String>) -> Self {
        self.web_id = web_id;
        self
    }

    /// Current heartbeat interval.
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Current URL length cap.
    pub fn url_cap(&self) -> usize {
        self.url_cap_bytes
    }

    /// Current subscription count.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Attempt to register a subscription for `target`. Returns `Err`
    /// (the wire-format `err` line payload) if the target violates any
    /// invariant.
    ///
    /// Checks run in this order:
    ///
    /// 1. URL byte-length cap — `err <truncated> url-too-long`.
    /// 2. Same-origin check (if [`with_server_origin`](Self::with_server_origin)
    ///    was set) — `err <uri> forbidden`.
    /// 3. Per-connection subscription cap — `err <uri> subscription-limit`.
    /// 4. [`SubscriptionAuthorizer::check`] — `err <uri> forbidden`.
    ///
    /// The denial token `forbidden` is the only one JSS clients
    /// (SolidOS mashlib) recognise, so both same-origin and WAC
    /// denials collapse to the same wire frame. `url-too-long` and
    /// `subscription-limit` are JSS-divergent by inheritance (see
    /// Sprint 4 notifications inspector finding); they are preserved
    /// here to keep existing tests green and will be revisited in
    /// Sprint 6.
    pub fn subscribe(&mut self, target: String) -> Result<(), String> {
        // 1) URL cap.
        if target.len() > self.url_cap_bytes {
            return Err(format!("err {} url-too-long", truncate(&target, 64)));
        }

        // 2) Same-origin check. Only enforced when `server_origin` is
        //    set; embedded test pods may leave it off. A parse failure
        //    on the target is treated as a cross-origin refusal — an
        //    un-parseable URL cannot prove same-origin.
        if let Some(server_origin) = &self.server_origin {
            match url::Url::parse(&target) {
                Ok(parsed) => {
                    let host = parsed.host_str().unwrap_or("");
                    let port_suffix = parsed
                        .port()
                        .map(|p| format!(":{p}"))
                        .unwrap_or_default();
                    let target_origin =
                        format!("{}://{}{}", parsed.scheme(), host, port_suffix);
                    if &target_origin != server_origin {
                        return Err(format!("err {target} forbidden"));
                    }
                }
                Err(_) => {
                    return Err(format!("err {target} forbidden"));
                }
            }
        }

        // 3) Per-connection subscription cap.
        if self.subscriptions.len() >= self.max_subs_per_conn
            && !self.subscriptions.contains(&target)
        {
            return Err(format!("err {} subscription-limit", target));
        }

        // 4) WAC / authorizer check. Fail-closed default
        //    ([`DenyAllAuthorizer`]) means a freshly-constructed
        //    channel rejects everything here.
        match self.authorizer.check(&target, self.web_id.as_deref()) {
            Ok(()) => {}
            Err(DenyReason::Forbidden | DenyReason::CrossOrigin) => {
                return Err(format!("err {target} forbidden"));
            }
        }

        self.subscriptions.insert(target);
        Ok(())
    }

    /// Remove a subscription. No-op if not present.
    pub fn unsubscribe(&mut self, target: &str) {
        self.subscriptions.remove(target);
    }

    /// True if any subscription covers the given resource URI (either
    /// exact match or prefix-match on a container URL ending in `/`).
    pub fn matches_subscription(&self, resource_uri: &str) -> bool {
        for sub in &self.subscriptions {
            if sub == resource_uri {
                return true;
            }
            if sub.ends_with('/') && resource_uri.starts_with(sub.as_str()) {
                return true;
            }
        }
        false
    }

    /// Await the next upstream storage event. Returns `None` on
    /// broadcast close. Lossy: if the receiver lagged, the skipped
    /// events are dropped rather than propagated (matches JSS).
    pub async fn next_event(&mut self) -> Option<StorageEvent> {
        loop {
            match self.storage_events.recv().await {
                Ok(ev) => return Some(ev),
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    }

    // -----------------------------------------------------------------
    // Pure codec — static, no `self` state. Testable in isolation.
    // -----------------------------------------------------------------

    /// Convert a modern `StorageEvent` to a legacy wire-format line.
    ///
    /// All three event kinds map to `pub <uri>` — the legacy protocol
    /// does not distinguish Create / Update / Delete, and clients poll
    /// on `pub` to detect the new state. Returns `None` if the event
    /// cannot be expressed (currently: never; kept as `Option` so
    /// future event kinds can opt out without breaking the signature).
    ///
    /// The emitted URI is exactly the path carried by the event. If
    /// the consumer needs an absolute URL, they should map the path
    /// against their pod base URL before calling this function, or
    /// bind against a `StorageEvent` stream whose paths are already
    /// absolute. Kept as the wire-exact shape so callers are in
    /// control of URL canonicalisation.
    pub fn to_legacy_line(event: &StorageEvent) -> Option<String> {
        let uri = match event {
            StorageEvent::Created(p) | StorageEvent::Updated(p) | StorageEvent::Deleted(p) => p,
        };
        Some(format!("{} {}", SolidZeroOp::Pub.as_str(), uri))
    }

    /// Parse an inbound `sub <uri>` line. Returns the target URI with
    /// surrounding whitespace trimmed. Returns `None` for any line
    /// that does not match the `sub ` prefix followed by a non-empty
    /// target.
    pub fn parse_subscribe(line: &str) -> Option<String> {
        parse_prefixed(line, "sub ")
    }

    /// Parse an inbound `unsub <uri>` line. Returns the target URI.
    pub fn parse_unsubscribe(line: &str) -> Option<String> {
        parse_prefixed(line, "unsub ")
    }

    /// Build an `ack <uri>` line.
    pub fn ack_line(target: &str) -> String {
        format!("{} {}", SolidZeroOp::Ack.as_str(), target)
    }

    /// Build an `err <uri> <reason>` line.
    pub fn err_line(target: &str, reason: &str) -> String {
        format!("{} {} {}", SolidZeroOp::Err.as_str(), target, reason)
    }
}

/// Parse a line with `prefix` followed by a non-empty trimmed payload.
fn parse_prefixed(line: &str, prefix: &str) -> Option<String> {
    let trimmed = line.trim_end_matches(['\r', '\n']).trim_start();
    let rest = trimmed.strip_prefix(prefix)?;
    let target = rest.trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

/// Truncate a string to at most `max` bytes, for safe inclusion in
/// error frames (avoids echoing multi-kilobyte hostile URLs).
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        // Find the largest char boundary ≤ max.
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

// ---------------------------------------------------------------------------
// Tests — unit-level codec round-trips. Integration behaviour
// (subscription fan-out, heartbeat timing against a broadcast source)
// lives in `tests/legacy_notifications_test.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    #[test]
    fn parse_subscribe_valid() {
        let got = LegacyNotificationChannel::parse_subscribe("sub https://pod.example.com/x");
        assert_eq!(got, Some("https://pod.example.com/x".to_string()));
    }

    #[test]
    fn parse_subscribe_trims_whitespace_and_crlf() {
        let got = LegacyNotificationChannel::parse_subscribe("sub https://pod.example.com/x\r\n");
        assert_eq!(got, Some("https://pod.example.com/x".to_string()));
        let got = LegacyNotificationChannel::parse_subscribe("  sub   https://pod.example.com/x   ");
        assert_eq!(got, Some("https://pod.example.com/x".to_string()));
    }

    #[test]
    fn parse_subscribe_rejects_malformed() {
        assert!(LegacyNotificationChannel::parse_subscribe("sub").is_none());
        assert!(LegacyNotificationChannel::parse_subscribe("sub  ").is_none());
        assert!(LegacyNotificationChannel::parse_subscribe("subscribe foo").is_none());
        assert!(LegacyNotificationChannel::parse_subscribe("pub foo").is_none());
        assert!(LegacyNotificationChannel::parse_subscribe("").is_none());
    }

    #[test]
    fn parse_unsubscribe_valid() {
        let got = LegacyNotificationChannel::parse_unsubscribe("unsub https://p/x");
        assert_eq!(got, Some("https://p/x".to_string()));
    }

    #[test]
    fn to_legacy_line_created() {
        let ev = StorageEvent::Created("https://pod.example.com/x".into());
        assert_eq!(
            LegacyNotificationChannel::to_legacy_line(&ev),
            Some("pub https://pod.example.com/x".to_string())
        );
    }

    #[test]
    fn to_legacy_line_updated_and_deleted_also_map_to_pub() {
        let u = StorageEvent::Updated("https://pod.example.com/x".into());
        let d = StorageEvent::Deleted("https://pod.example.com/x".into());
        assert_eq!(
            LegacyNotificationChannel::to_legacy_line(&u),
            Some("pub https://pod.example.com/x".to_string())
        );
        assert_eq!(
            LegacyNotificationChannel::to_legacy_line(&d),
            Some("pub https://pod.example.com/x".to_string())
        );
    }

    #[test]
    fn subscription_cap_rejects_over_limit() {
        let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
        // Explicit AllowAll preserves pre-P0-3 semantics for this cap
        // test — the fail-closed default would otherwise swallow every
        // `subscribe` with `forbidden` before the cap is hit.
        let mut chan = LegacyNotificationChannel::new(rx)
            .with_authorizer(Arc::new(AllowAllAuthorizer))
            .with_subscription_cap(2);
        assert!(chan.subscribe("https://p/a".into()).is_ok());
        assert!(chan.subscribe("https://p/b".into()).is_ok());
        let err = chan.subscribe("https://p/c".into()).unwrap_err();
        assert!(err.starts_with("err "));
        assert!(err.contains("subscription-limit"));
        assert_eq!(chan.subscription_count(), 2);
    }

    #[test]
    fn url_cap_rejects_over_limit() {
        let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
        let mut chan = LegacyNotificationChannel::new(rx)
            .with_authorizer(Arc::new(AllowAllAuthorizer))
            .with_url_cap(16);
        let err = chan
            .subscribe("https://pod.example.com/really/long/path".into())
            .unwrap_err();
        assert!(err.contains("url-too-long"));
        assert_eq!(chan.subscription_count(), 0);
    }

    #[test]
    fn matches_subscription_prefix_and_exact() {
        let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
        let mut chan =
            LegacyNotificationChannel::new(rx).with_authorizer(Arc::new(AllowAllAuthorizer));
        chan.subscribe("https://pod.example.com/foo/".into()).unwrap();
        chan.subscribe("https://pod.example.com/bar.ttl".into()).unwrap();
        assert!(chan.matches_subscription("https://pod.example.com/foo/"));
        assert!(chan.matches_subscription("https://pod.example.com/foo/deep/nested"));
        assert!(chan.matches_subscription("https://pod.example.com/bar.ttl"));
        assert!(!chan.matches_subscription("https://pod.example.com/other"));
        // Non-container subscription does NOT match a different path.
        assert!(!chan.matches_subscription("https://pod.example.com/bar.ttl.backup"));
    }

    #[test]
    fn unsubscribe_removes_target() {
        let (_tx, rx) = broadcast::channel::<StorageEvent>(16);
        let mut chan =
            LegacyNotificationChannel::new(rx).with_authorizer(Arc::new(AllowAllAuthorizer));
        chan.subscribe("https://p/x".into()).unwrap();
        chan.unsubscribe("https://p/x");
        assert_eq!(chan.subscription_count(), 0);
        chan.unsubscribe("https://p/y"); // no-op
    }

    #[test]
    fn ack_and_err_lines() {
        assert_eq!(
            LegacyNotificationChannel::ack_line("https://p/x"),
            "ack https://p/x"
        );
        assert_eq!(
            LegacyNotificationChannel::err_line("https://p/x", "forbidden"),
            "err https://p/x forbidden"
        );
    }

    #[test]
    fn opcode_wire_names() {
        assert_eq!(SolidZeroOp::Sub.as_str(), "sub");
        assert_eq!(SolidZeroOp::Ack.as_str(), "ack");
        assert_eq!(SolidZeroOp::Err.as_str(), "err");
        assert_eq!(SolidZeroOp::Pub.as_str(), "pub");
        assert_eq!(SolidZeroOp::Unsub.as_str(), "unsub");
    }
}
