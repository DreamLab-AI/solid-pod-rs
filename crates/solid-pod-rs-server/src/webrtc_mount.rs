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
//! * `{"type": "error", "message": ...}` comes back for bad input or an
//!   offline peer.
//!
//! # Bounds
//!
//! At most [`MAX_CONNECTIONS`] sockets in all and one per identity (a new
//! connection replaces the old one); frames of at most [`MAX_FRAME_BYTES`]; a
//! socket that sends nothing for [`IDLE_TIMEOUT`] is closed; at most
//! [`RATE_MESSAGES`] messages per [`RATE_WINDOW`] per socket (then closed);
//! at most [`QUEUE_DEPTH`] messages waiting for a slow peer (further ones are
//! refused with an error to the sender).
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
    /// Messages per window.
    pub rate_messages: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            idle: IDLE_TIMEOUT,
            rate_messages: RATE_MESSAGES,
        }
    }
}

struct Peer {
    generation: u64,
    tx: mpsc::Sender<String>,
}

/// A mounted relay.
pub struct WebRtcMount {
    path: String,
    limits: Limits,
    peers: Mutex<HashMap<String, Peer>>,
    connections: AtomicUsize,
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

struct Slot(Arc<WebRtcMount>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
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
    let slot = Slot(mount.clone());
    let (response, mut session, stream) = actix_ws::handle(&req, body)?;
    let mut stream = stream.max_frame_size(MAX_FRAME_BYTES);

    let generation = mount.next_generation.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<String>(QUEUE_DEPTH);
    // A new connection for the same identity replaces the old one: dropping
    // the old sender ends the old task.
    mount.peers().insert(did.clone(), Peer { generation, tx });

    actix_web::rt::spawn(async move {
        let _slot = slot;
        let mut recent: VecDeque<Instant> = VecDeque::new();
        let mut last_seen = Instant::now();
        let mut tick = tokio::time::interval(HEARTBEAT.min(mount.limits.idle));
        tick.tick().await;
        let reason = loop {
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        last_seen = Instant::now();
                        let now = Instant::now();
                        recent.push_back(now);
                        while recent.front().is_some_and(|t| now.duration_since(*t) > RATE_WINDOW) {
                            recent.pop_front();
                        }
                        if recent.len() > mount.limits.rate_messages {
                            break Some(CloseReason::from((CloseCode::Policy, "rate limit")));
                        }
                        if let Some(err) = relay(&mount, &did, &text) {
                            if session.text(err).await.is_err() {
                                break None;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        last_seen = Instant::now();
                        if session.pong(&p).await.is_err() {
                            break None;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(r))) => break r,
                    Some(Ok(Message::Binary(_))) => {
                        if session.text(error_frame("binary frames not accepted")).await.is_err() {
                            break None;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break None,
                },
                out = rx.recv() => match out {
                    Some(frame) => {
                        if session.text(frame).await.is_err() {
                            break None;
                        }
                    }
                    // Replaced by a newer connection for this identity.
                    None => break Some(CloseReason::from((CloseCode::Normal, "replaced"))),
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
    let tx = mount.peers().get(to).map(|p| p.tx.clone());
    match tx {
        None => Some(error_frame("peer not online")),
        Some(tx) => match tx.try_send(frame) {
            Ok(()) => None,
            Err(_) => Some(error_frame("peer busy or gone")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount() -> Arc<WebRtcMount> {
        WebRtcMount::new("/webrtc").unwrap()
    }

    fn add(m: &WebRtcMount, did: &str) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        m.peers().insert(did.into(), Peer { generation: 1, tx });
        rx
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
        let got: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(got["from"], "did:nostr:a");
        assert_eq!(got["sdp"], "v=0");
        assert!(got.get("extra").is_none());
        assert!(
            got.get("candidate").is_none(),
            "an array is not a candidate"
        );
    }

    #[test]
    fn bad_input_and_offline_peers_get_an_error_frame() {
        let m = mount();
        for bad in [
            "not json",
            r#"{"type":"announce","to":"x"}"#,
            r#"{"type":"offer"}"#,
            r#"{"type":"offer","to":"did:nostr:a"}"#,
            r#"{"type":"offer","to":"did:nostr:nobody"}"#,
        ] {
            let e = relay(&m, "did:nostr:a", bad).unwrap();
            assert!(e.contains("\"error\""), "{bad}: {e}");
        }
    }

    #[test]
    fn a_full_queue_refuses_instead_of_growing() {
        let m = mount();
        let _rx = add(&m, "did:nostr:b");
        let mut refused = 0;
        for _ in 0..QUEUE_DEPTH + 5 {
            if relay(&m, "did:nostr:a", r#"{"type":"hangup","to":"did:nostr:b"}"#).is_some() {
                refused += 1;
            }
        }
        assert_eq!(refused, 5);
    }

    #[test]
    fn paths_are_validated() {
        assert!(WebRtcMount::new("/.webrtc").is_err());
        assert!(WebRtcMount::new("/a/../b").is_err());
        assert_eq!(WebRtcMount::new("/rtc/").unwrap().path(), "/rtc");
    }
}
