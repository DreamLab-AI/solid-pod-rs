//! WebRTC signalling relay (SP-PAR-282). Off unless `--webrtc` is given.
//!
//! A bounded WebSocket relay of signalling messages between authenticated
//! peers, as JSS `src/webrtc/index.js` does for identity-based signalling. The
//! media and data flow directly between the peers; this server only
//! introduces them. It has no access to pod storage and reads no pod state.
//!
//! # Protocol
//!
//! `GET <path>` with `Upgrade: websocket` and an `Authorization` header (a
//! NIP-98 token for that URL; a browser `WebSocket` cannot set it, so the
//! relay serves native clients). A peer is its `did:nostr:<pubkey>`. Text
//! frames of JSON:
//!
//! * `{"type": "offer"|"answer"|"candidate"|"hangup", "to": "<did>",
//!   "sdp": "...", "candidate": {...}}` is relayed to that peer as
//!   `{"type": ..., "from": "<sender did>", ...}`. `from` is always the
//!   authenticated sender; a `from` sent by the client is ignored. Only
//!   `type`, `sdp` (a string) and `candidate` (an object) are copied.
//! * `{"type": "error", "message": ...}` comes back for malformed input (bad
//!   JSON, unknown type, missing `to`, an oversized `sdp`, signalling
//!   yourself). Nothing comes back about the peer: a well-formed message to a
//!   peer that is online, offline, busy or unknown gets the same response (none),
//!   so the relay cannot be used to probe whether a pubkey is online. A client
//!   learns the peer is not there the way it does in any signalling protocol,
//!   by getting no answer.
//!
//! # Bounds
//!
//! At most [`MAX_CONNECTIONS`] sockets in all, [`MAX_PER_IP`] per client
//! address (configurable with `--webrtc-max-per-ip`; the socket peer, or with
//! `--trust-proxy` the address the reverse proxy forwarded, see
//! [`client_ip_with`](crate::scheme::client_ip_with)) and one per identity (a new connection
//! replaces the old one); frames of at most [`MAX_FRAME_BYTES`]; a socket that
//! sends nothing for [`IDLE_TIMEOUT`] is closed, and no socket lives longer than
//! [`MAX_SESSION`] however active (a client's pings reset the idle timer but not
//! the session limit); at most [`RATE_MESSAGES`] frames of any kind (text,
//! binary, ping, pong) per [`RATE_WINDOW`] per socket (then closed); at most
//! [`QUEUE_DEPTH`] messages waiting for a slow peer, of which one sender may
//! hold at most [`PER_SENDER_QUEUE`]; messages over either bound are dropped
//! without a reply.
//!
//! # Differences from JSS
//!
//! Unauthenticated content-addressed announce and the WebTorrent tracker
//! protocol are not provided (they let any anonymous client relay to
//! arbitrary groups), and the peer list and join/leave broadcasts are not
//! sent (they let any peer enumerate who is online). The default path is
//! `/webrtc`: the dotfile guard owns `/.webrtc`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::{CloseCode, CloseReason, Message};
use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::AppState;

/// Default mount path.
pub const DEFAULT_PATH: &str = "/webrtc";
/// Most simultaneous sockets.
pub const MAX_CONNECTIONS: usize = 128;
/// Largest frame accepted (bytes).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// A socket silent for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Messages one socket may send per [`RATE_WINDOW`].
pub const RATE_MESSAGES: usize = 60;
/// The rate-limit window.
pub const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Messages queued for one peer.
pub const QUEUE_DEPTH: usize = 32;
/// Default for the sockets one client address may hold
/// (`--webrtc-max-per-ip`). The address is the socket peer, or with
/// `--trust-proxy` the one the reverse proxy forwarded; without the flag every
/// client behind a proxy shares the proxy's single budget.
pub const MAX_PER_IP: usize = 8;
/// Longest a socket lives, however busy: a client that keeps pinging cannot
/// hold a slot for ever.
pub const MAX_SESSION: Duration = Duration::from_secs(3600);
/// Messages one sender may have waiting in one recipient's queue (of
/// [`QUEUE_DEPTH`]), so no single sender can fill a recipient's queue.
pub const PER_SENDER_QUEUE: usize = 8;
const MAX_SDP_BYTES: usize = 32 * 1024;
const MAX_ID_BYTES: usize = 256;
const HEARTBEAT: Duration = Duration::from_secs(30);

/// Tunable bounds (tests lower them).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most sockets in all.
    pub max_connections: usize,
    /// Idle limit.
    pub idle: Duration,
    /// Frames (of any kind) per window.
    pub rate_messages: usize,
    /// Most sockets from one client address.
    pub max_per_ip: usize,
    /// Longest a socket lives, however active.
    pub max_session: Duration,
    /// Most messages one sender may have waiting in one recipient's queue.
    pub per_sender_queue: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            idle: IDLE_TIMEOUT,
            rate_messages: RATE_MESSAGES,
            max_per_ip: MAX_PER_IP,
            max_session: MAX_SESSION,
            per_sender_queue: PER_SENDER_QUEUE,
        }
    }
}

/// Messages waiting in one recipient's queue, by sender.
type Pending = Arc<Mutex<HashMap<String, usize>>>;

/// A frame waiting for a recipient, remembering who queued it.
struct Queued {
    from: String,
    frame: String,
}

struct Peer {
    generation: u64,
    tx: mpsc::Sender<Queued>,
    pending: Pending,
}

/// Return one unit of `from`'s budget in a recipient's queue.
fn release(pending: &Pending, from: &str) {
    let mut map = pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(n) = map.get_mut(from) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(from);
        }
    }
}

/// A mounted relay.
pub struct WebRtcMount {
    path: String,
    limits: Limits,
    peers: Mutex<HashMap<String, Peer>>,
    connections: AtomicUsize,
    per_ip: Mutex<HashMap<std::net::IpAddr, usize>>,
    next_generation: AtomicU64,
}

impl std::fmt::Debug for WebRtcMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcMount")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl WebRtcMount {
    /// A relay at `path` with the default bounds.
    ///
    /// # Errors
    ///
    /// A message when `path` is not a safe mount path.
    pub fn new(path: &str) -> Result<Arc<Self>, String> {
        Self::with_limits(path, Limits::default())
    }

    /// A relay with explicit bounds.
    ///
    /// # Errors
    ///
    /// A message when `path` is not a safe mount path.
    pub fn with_limits(path: &str, limits: Limits) -> Result<Arc<Self>, String> {
        let path = crate::nostr_mount::validate_path(path)
            .map_err(|e| e.replace("nostr path", "webrtc path"))?;
        Ok(Arc::new(Self {
            path,
            limits,
            peers: Mutex::new(HashMap::new()),
            connections: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
        }))
    }

    /// The normalised mount path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<String, Peer>> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One socket's claim on the global and per-address counts, returned on drop.
struct Slot(Arc<WebRtcMount>, Option<std::net::IpAddr>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
        if let Some(ip) = self.1 {
            let mut map = self
                .0
                .per_ip
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(n) = map.get_mut(&ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&ip);
                }
            }
        }
    }
}

/// `GET <path>`: the WebSocket upgrade, for an authenticated peer.
pub(crate) async fn handle_webrtc(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(mount) = state.webrtc.clone() else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let is_upgrade = req
        .headers()
        .get(actix_web::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
    if !is_upgrade {
        return Ok(HttpResponse::NotFound().body("not found"));
    }
    // Authentication happens before any socket or slot is taken.
    let Some(did) = crate::agent_uri(crate::extract_pubkey(&req).await.as_ref()) else {
        return Ok(HttpResponse::Unauthorized()
            .insert_header(("www-authenticate", "Nostr"))
            .body("authentication required"));
    };
    if mount.connections.fetch_add(1, Ordering::Relaxed) >= mount.limits.max_connections {
        mount.connections.fetch_sub(1, Ordering::Relaxed);
        return Ok(HttpResponse::ServiceUnavailable().body("too many connections"));
    }
    // The per-address count is taken while holding the global slot, so both
    // are returned together when the socket ends.
    let ip = crate::scheme::client_ip_with(&req, state.trust_proxy);
    if let Some(ip) = ip {
        let mut map = mount
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = map.entry(ip).or_insert(0);
        if *n >= mount.limits.max_per_ip {
            drop(map);
            mount.connections.fetch_sub(1, Ordering::Relaxed);
            return Ok(
                HttpResponse::ServiceUnavailable().body("too many connections from this address")
            );
        }
        *n += 1;
    }
    let slot = Slot(mount.clone(), ip);
    let (response, mut session, stream) = actix_ws::handle(&req, body)?;
    let mut stream = stream.max_frame_size(MAX_FRAME_BYTES);

    let generation = mount.next_generation.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Queued>(QUEUE_DEPTH);
    let pending: Pending = Pending::default();
    // A new connection for the same identity replaces the old one: dropping
    // the old sender ends the old task.
    mount.peers().insert(
        did.clone(),
        Peer {
            generation,
            tx,
            pending: pending.clone(),
        },
    );

    actix_web::rt::spawn(async move {
        let _slot = slot;
        let mut recent: VecDeque<Instant> = VecDeque::new();
        let mut last_seen = Instant::now();
        let mut tick = tokio::time::interval(HEARTBEAT.min(mount.limits.idle));
        tick.tick().await;
        // However active the client is, the socket ends at the session limit.
        let session_end = tokio::time::sleep(mount.limits.max_session);
        tokio::pin!(session_end);
        let reason = loop {
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(frame)) => {
                        // Every frame the client sends is metered, whatever
                        // its kind: pings and binary frames cost the server
                        // too.
                        let now = Instant::now();
                        recent.push_back(now);
                        while recent.front().is_some_and(|t| now.duration_since(*t) > RATE_WINDOW) {
                            recent.pop_front();
                        }
                        if recent.len() > mount.limits.rate_messages {
                            break Some(CloseReason::from((CloseCode::Policy, "rate limit")));
                        }
                        match frame {
                            Message::Text(text) => {
                                last_seen = now;
                                if let Some(err) = relay(&mount, &did, &text) {
                                    if session.text(err).await.is_err() {
                                        break None;
                                    }
                                }
                            }
                            Message::Ping(p) => {
                                last_seen = now;
                                if session.pong(&p).await.is_err() {
                                    break None;
                                }
                            }
                            Message::Close(r) => break r,
                            Message::Binary(_) => {
                                let sent = session.text(error_frame("binary frames not accepted")).await;
                                if sent.is_err() {
                                    break None;
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Err(_)) | None => break None,
                },
                out = rx.recv() => match out {
                    Some(queued) => {
                        release(&pending, &queued.from);
                        if session.text(queued.frame).await.is_err() {
                            break None;
                        }
                    }
                    // Replaced by a newer connection for this identity.
                    None => break Some(CloseReason::from((CloseCode::Normal, "replaced"))),
                },
                () = &mut session_end => {
                    break Some(CloseReason::from((CloseCode::Away, "session limit")));
                },
                _ = tick.tick() => {
                    if last_seen.elapsed() >= mount.limits.idle {
                        break Some(CloseReason::from((CloseCode::Away, "idle")));
                    }
                    if session.ping(b"").await.is_err() {
                        break None;
                    }
                }
            }
        };
        {
            let mut peers = mount.peers();
            if peers.get(&did).is_some_and(|p| p.generation == generation) {
                peers.remove(&did);
            }
        }
        let _ = session.close(reason).await;
    });
    Ok(response)
}

fn error_frame(message: &str) -> String {
    serde_json::json!({"type": "error", "message": message}).to_string()
}

/// Handle one text frame from `from`; the return value, if any, is an error
/// frame for the sender.
fn relay(mount: &WebRtcMount, from: &str, text: &str) -> Option<String> {
    let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) else {
        return Some(error_frame("invalid JSON"));
    };
    let kind = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(kind, "offer" | "answer" | "candidate" | "hangup") {
        return Some(error_frame("unknown type"));
    }
    let Some(to) = msg
        .get("to")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty() && t.len() <= MAX_ID_BYTES)
    else {
        return Some(error_frame("missing \"to\""));
    };
    if to == from {
        return Some(error_frame("cannot signal yourself"));
    }
    // Only whitelisted fields are copied; `from` is the authenticated sender.
    let mut out = serde_json::Map::new();
    out.insert("type".into(), kind.into());
    out.insert("from".into(), from.into());
    if let Some(sdp) = msg.get("sdp").and_then(|v| v.as_str()) {
        if sdp.len() > MAX_SDP_BYTES {
            return Some(error_frame("sdp too large"));
        }
        out.insert("sdp".into(), sdp.into());
    }
    if let Some(c) = msg.get("candidate").filter(|c| c.is_object()) {
        out.insert("candidate".into(), c.clone());
    }
    let frame = serde_json::Value::Object(out).to_string();
    // Whatever the peer's state, the sender is told nothing about it: absent,
    // present, busy and over-budget all end the same way.
    let target = mount
        .peers()
        .get(to)
        .map(|p| (p.tx.clone(), p.pending.clone()));
    let (tx, pending) = target?;
    {
        let mut map = pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = map.entry(from.to_string()).or_insert(0);
        if *held >= mount.limits.per_sender_queue {
            return None;
        }
        *held += 1;
    }
    let queued = Queued {
        from: from.to_string(),
        frame,
    };
    if tx.try_send(queued).is_err() {
        release(&pending, from);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount() -> Arc<WebRtcMount> {
        WebRtcMount::new("/webrtc").unwrap()
    }

    fn add(m: &WebRtcMount, did: &str) -> mpsc::Receiver<Queued> {
        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        m.peers().insert(
            did.into(),
            Peer {
                generation: 1,
                tx,
                pending: Pending::default(),
            },
        );
        rx
    }

    /// What the connection task does on receiving: take the frame and return
    /// the sender's budget.
    fn recv(m: &WebRtcMount, rx: &mut mpsc::Receiver<Queued>, did: &str) -> Option<String> {
        let q = rx.try_recv().ok()?;
        let pending = m.peers().get(did).map(|p| p.pending.clone())?;
        release(&pending, &q.from);
        Some(q.frame)
    }

    #[test]
    fn the_sender_is_the_authenticated_identity_and_only_known_fields_pass() {
        let m = mount();
        let mut rx = add(&m, "did:nostr:b");
        let err = relay(
            &m,
            "did:nostr:a",
            r#"{"type":"offer","to":"did:nostr:b","from":"did:nostr:evil","sdp":"v=0","extra":1,"candidate":[1]}"#,
        );
        assert!(err.is_none());
        let got: serde_json::Value =
            serde_json::from_str(&recv(&m, &mut rx, "did:nostr:b").unwrap()).unwrap();
        assert_eq!(got["from"], "did:nostr:a");
        assert_eq!(got["sdp"], "v=0");
        assert!(got.get("extra").is_none());
        assert!(
            got.get("candidate").is_none(),
            "an array is not a candidate"
        );
    }

    #[test]
    fn bad_input_gets_an_error_frame() {
        let m = mount();
        for bad in [
            "not json",
            r#"{"type":"announce","to":"x"}"#,
            r#"{"type":"offer"}"#,
            r#"{"type":"offer","to":"did:nostr:a"}"#,
        ] {
            let e = relay(&m, "did:nostr:a", bad).unwrap();
            assert!(e.contains("\"error\""), "{bad}: {e}");
        }
    }

    /// Property: what a sender is told never depends on whether the named peer
    /// is online, nor on how full that peer's queue is.
    #[test]
    fn the_reply_does_not_depend_on_the_peers_state() {
        let m = mount();
        let msg = r#"{"type":"hangup","to":"did:nostr:b"}"#;
        // Absent peer.
        let absent = relay(&m, "did:nostr:a", msg);
        // Present peer, queue with room, then driven to its limit.
        let _rx = add(&m, "did:nostr:b");
        let mut replies = vec![absent];
        for _ in 0..QUEUE_DEPTH + 5 {
            replies.push(relay(&m, "did:nostr:a", msg));
        }
        assert!(replies.iter().all(Option::is_none), "{replies:?}");
    }

    /// Property: one sender cannot fill a recipient's queue; another sender
    /// can still reach the recipient, and the recipient's queue stays bounded.
    #[test]
    fn one_sender_cannot_fill_a_recipients_queue() {
        let m = mount();
        let mut rx = add(&m, "did:nostr:b");
        let msg = |from: &str| (from.to_string(), r#"{"type":"hangup","to":"did:nostr:b"}"#);
        let (a, text) = msg("did:nostr:a");
        for _ in 0..QUEUE_DEPTH * 2 {
            let _ = relay(&m, &a, text);
        }
        let mut from_a = 0;
        while rx.try_recv().is_ok() {
            from_a += 1;
        }
        assert_eq!(from_a, m.limits.per_sender_queue);
        // The recipient's queue is no longer the flooder's to fill: a second
        // sender still gets through while the first one is at its budget.
        let (c, text) = msg("did:nostr:c");
        let _ = relay(&m, &c, text);
        let got = recv(&m, &mut rx, "did:nostr:b").expect("c reached b");
        assert!(got.contains("did:nostr:c"), "{got}");
    }

    #[test]
    fn paths_are_validated() {
        assert!(WebRtcMount::new("/.webrtc").is_err());
        assert!(WebRtcMount::new("/a/../b").is_err());
        assert_eq!(WebRtcMount::new("/rtc/").unwrap().path(), "/rtc");
    }
}
