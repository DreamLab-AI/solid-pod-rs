//! `GET /.notifications`: the `solid-0.1` WebSocket notification route
//! (SP-PAR-279).
//!
//! The wire protocol and per-connection state machine are the library's
//! [`LegacyWebSocketSession`]; this module owns only the transport and the
//! authorisation it is wired to.
//!
//! # Authorisation
//!
//! * **Per subscription.** `sub <url>` is acknowledged only if the caller
//!   currently holds WAC `acl:Read` on that resource. The URL must be on this
//!   server's own origin; any other URL is refused as `forbidden`, so the
//!   route is no oracle for other origins.
//! * **On every delivery.** A change is delivered as `pub <url>` only after
//!   the same Read check passes on the *changed* resource, at delivery time.
//!   A subscriber who lost access, or who subscribed to a readable ancestor
//!   container, never learns that something they cannot read changed: a
//!   denied delivery is dropped, not announced (the library's
//!   `err <url> forbidden` fan-out frame would disclose the changed path, so
//!   it is not forwarded).
//! * Resources whose rule carries a payment condition are refused rather than
//!   billed per notification.
//! * `acl:origin` rules see the WebSocket handshake's `Origin` header, and a
//!   browser `Origin` outside a non-empty `allowed_origins` list is refused
//!   before the upgrade.
//!
//! The caller is anonymous unless the upgrade request carries a valid NIP-98
//! `Authorization` header (browsers cannot set one on a `WebSocket`).
//!
//! # Events
//!
//! One shared [`NotifyHub`] watches the storage root once and fans each
//! [`StorageEvent`] out to every connection, so a connection costs a channel
//! receiver, not a filesystem watcher.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::Message;
use async_trait::async_trait;
use futures_util::StreamExt;
use solid_pod_rs::notifications::legacy::{
    LegacyFrame, LegacyWacRead, LegacyWebSocketSession, PROTOCOL_GREETING,
};
use solid_pod_rs::storage::{Storage, StorageEvent};
use tokio::sync::{broadcast, mpsc, oneshot, OnceCell};

use crate::{agent_uri, enforce_read_inner, extract_pubkey, req_origin, scheme, AppState};

/// Most simultaneous notification sockets one server accepts.
pub const MAX_CONNECTIONS: usize = 1024;
/// Largest inbound frame: `unsub ` plus the 2 KiB URL cap, with headroom.
const MAX_FRAME_BYTES: usize = 4096;
/// Idle keep-alive interval (WebSocket ping).
const HEARTBEAT: Duration = Duration::from_secs(30);
/// Events buffered per connection before the slowest are dropped.
const EVENT_BUFFER: usize = 256;

/// Shared fan-out of storage change events to notification sockets.
#[derive(Debug)]
pub struct NotifyHub {
    tx: broadcast::Sender<StorageEvent>,
    started: OnceCell<()>,
    connections: AtomicUsize,
}

impl NotifyHub {
    /// A hub with no watcher yet; the first connection starts it.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: broadcast::channel(EVENT_BUFFER).0,
            started: OnceCell::new(),
            connections: AtomicUsize::new(0),
        })
    }

    /// Open connections right now.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Watch the storage root once and relay its events. Idempotent.
    async fn ensure_started(
        &self,
        storage: &Arc<dyn Storage>,
    ) -> Result<(), solid_pod_rs::PodError> {
        self.started
            .get_or_try_init(|| async {
                let mut rx = storage.watch("/").await?;
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    while let Some(ev) = rx.recv().await {
                        // No receivers is fine: nobody is connected.
                        let _ = tx.send(ev);
                    }
                });
                Ok::<(), solid_pod_rs::PodError>(())
            })
            .await
            .map(|_| ())
    }
}

/// Releases a connection slot on every exit path.
struct Slot(Arc<NotifyHub>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One Read question for the connection's checker task.
struct ReadQuery {
    webid: Option<String>,
    uri: String,
    reply: oneshot::Sender<bool>,
}

/// WAC Read check the session consults on every `sub` and every delivery.
///
/// The server's admission code holds non-`Send` futures, while the library's
/// `LegacyWacRead` future must be `Send`. This type is the `Send` side: it
/// forwards each question to [`run_checker`], a task on the connection's own
/// (local) runtime, and awaits the answer. A dead checker answers `false`.
struct ServerRead {
    queries: mpsc::UnboundedSender<ReadQuery>,
}

#[async_trait]
impl LegacyWacRead for ServerRead {
    async fn can_read(&self, webid: Option<&str>, resource_uri: &str) -> bool {
        let (reply, answer) = oneshot::channel();
        let query = ReadQuery {
            webid: webid.map(str::to_owned),
            uri: resource_uri.to_owned(),
            reply,
        };
        if self.queries.send(query).is_err() {
            return false;
        }
        answer.await.unwrap_or(false)
    }
}

/// The request path `uri` names on `origin`, or `None`.
fn local_path(origin: &url::Origin, uri: &str) -> Option<String> {
    let u = url::Url::parse(uri).ok()?;
    if &u.origin() != origin
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return None;
    }
    let path = u.path();
    // The same spelling rules requests are held to: no dot segments, no
    // encoded separators or control bytes.
    crate::canonical_pod_path(path)?;
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return None;
    }
    Some(path.to_string())
}

/// Answer Read questions for one connection until its session drops.
async fn run_checker(
    state: web::Data<AppState>,
    origin: url::Origin,
    request_origin: Option<String>,
    mut queries: mpsc::UnboundedReceiver<ReadQuery>,
) {
    while let Some(q) = queries.recv().await {
        let allowed = match local_path(&origin, &q.uri) {
            // `charge = false`: a payment-gated read is refused, never debited.
            Some(path) => enforce_read_inner(
                &state,
                &path,
                q.webid.as_deref(),
                request_origin.as_deref(),
                false,
            )
            .await
            .is_ok(),
            None => false,
        };
        let _ = q.reply.send(allowed);
    }
}

/// `GET /.notifications`: upgrade to a `solid-0.1` WebSocket.
pub(crate) async fn handle_notifications(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(hub) = state.notifications.clone() else {
        return Ok(HttpResponse::NotFound().finish());
    };
    // A browser page on a foreign origin must not be able to open this socket
    // with the visitor's ambient credentials.
    if let Some(origin) = req_origin(&req) {
        if !state.allowed_origins.is_empty() && !state.allowed_origins.iter().any(|a| a == origin) {
            return Ok(HttpResponse::Forbidden().body("origin not allowed"));
        }
    }
    if hub.connections.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
        hub.connections.fetch_sub(1, Ordering::Relaxed);
        return Ok(HttpResponse::ServiceUnavailable().body("too many notification connections"));
    }
    let slot = Slot(hub.clone());
    if hub.ensure_started(&state.storage).await.is_err() {
        return Ok(HttpResponse::ServiceUnavailable().body("notifications unavailable"));
    }
    let Ok(origin) = url::Url::parse(&scheme::request_origin(&req)).map(|u| u.origin()) else {
        return Ok(HttpResponse::BadRequest().body("bad origin"));
    };
    let agent = agent_uri(extract_pubkey(&req).await.as_ref());
    let events = hub.tx.subscribe();
    let origin_text = origin.ascii_serialization();
    let (queries, query_rx) = mpsc::unbounded_channel();
    actix_web::rt::spawn(run_checker(
        state.clone(),
        origin,
        req_origin(&req).map(str::to_owned),
        query_rx,
    ));
    let wac = Arc::new(ServerRead { queries });

    let (response, mut session, stream) = actix_ws::handle(&req, body)?;
    let mut stream = stream.max_frame_size(MAX_FRAME_BYTES);
    actix_web::rt::spawn(async move {
        let _slot = slot;
        let mut proto = LegacyWebSocketSession::new(wac, agent);
        let mut events = events;
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.tick().await;
        if session.text(PROTOCOL_GREETING).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        for frame in proto.handle_message(&text).await.frames {
                            if session.text(frame.to_wire()).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if session.pong(&p).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(reason))) => {
                        let _ = session.close(reason).await;
                        return;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return,
                },
                ev = events.recv() => match ev {
                    Ok(ev) => {
                        let path = match &ev {
                            StorageEvent::Created(p)
                            | StorageEvent::Updated(p)
                            | StorageEvent::Deleted(p) => p,
                        };
                        let changed = format!("{origin_text}{path}");
                        for frame in proto.on_resource_change(&changed).await {
                            // Only an authorised `pub` leaves the server: the
                            // fan-out `err <changed-url> forbidden` frame
                            // would name a resource the subscriber cannot read.
                            if let LegacyFrame::Pub(_) = frame {
                                if session.text(frame.to_wire()).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    // Lossy by design under back-pressure.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = tick.tick() => {
                    if session.ping(b"").await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Ok(response)
}
