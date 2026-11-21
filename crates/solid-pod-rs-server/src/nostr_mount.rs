//! The embedded Nostr relay, mounted on the pod server (SP-PAR-278,
//! SP-PAR-280). Off unless `--nostr` is given.
//!
//! The relay itself is `solid-pod-rs-nostr`'s [`Relay`] (NIP-01, NIP-11,
//! NIP-16, bounded in-memory store); this module is the actix transport.
//!
//! # Routes
//!
//! With the relay mounted at `P` (default `/relay`):
//!
//! * `GET P` with `Upgrade: websocket` speaks NIP-01 over a WebSocket.
//! * `GET P` with `Accept: application/nostr+json` returns the NIP-11 relay
//!   information document (`200`, `Content-Type: application/nostr+json`,
//!   `Access-Control-Allow-Origin: *`).
//! * Any other `GET P` is `404`. `OPTIONS P` answers the CORS preflight a
//!   browser sends before the NIP-11 request.
//! * `GET P/info` is an alias of the information document.
//!
//! # Relationship to WAC
//!
//! The relay is not pod content: its routes are registered ahead of the pod
//! handlers, so a request to exactly `P` or `P/info` never reaches the WAC
//! gate. That exemption is by **whole path segment**: only those two exact
//! paths are the relay's. `/relayx`, `/relay/other` and `/relay.txt` are not,
//! and stay ordinary pod paths under WAC. A pod resource stored at `P` or
//! `P/info` is shadowed while the relay is mounted.
//!
//! The relay is open by design (it is a public relay): anyone may publish and
//! subscribe. `--nostr-max-events` bounds what it keeps, each frame and
//! subscription is bounded by the relay's own limits, and sockets are capped
//! at [`MAX_CONNECTIONS`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::Message;
use futures_util::StreamExt;
use solid_pod_rs_nostr::{
    dispatch_message_with_limits, Filter, InMemoryEventStore, Relay, RelayInfo, RelayLimits,
};
use tokio::sync::broadcast;

use crate::AppState;

/// Default mount path (JSS `--nostr-path`).
pub const DEFAULT_PATH: &str = "/relay";
/// Default bound on stored events (JSS `--nostr-max-events`).
pub const DEFAULT_MAX_EVENTS: usize = 1000;
/// Most simultaneous relay sockets.
pub const MAX_CONNECTIONS: usize = 256;
/// `Content-Type` of the NIP-11 document.
const NIP11_TYPE: &str = "application/nostr+json";
const HEARTBEAT: Duration = Duration::from_secs(30);

/// A mounted relay.
#[derive(Clone)]
pub struct NostrMount {
    relay: Arc<Relay>,
    path: String,
    connections: Arc<AtomicUsize>,
}

impl std::fmt::Debug for NostrMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrMount")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl NostrMount {
    /// A relay at `path` keeping at most `max_events` events.
    ///
    /// # Errors
    ///
    /// A message when `path` is not a safe mount path (see [`validate_path`]).
    pub fn new(path: &str, max_events: usize) -> Result<Self, String> {
        let path = validate_path(path)?;
        let relay = Relay::new(
            Arc::new(InMemoryEventStore::new(max_events)),
            RelayInfo::jss_compatible(),
            256,
        );
        Ok(Self {
            relay: Arc::new(relay),
            path,
            connections: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The normalised mount path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The relay, for embedding code that wants to publish or inspect.
    #[must_use]
    pub fn relay(&self) -> &Arc<Relay> {
        &self.relay
    }
}

/// Validate and normalise a mount path: absolute, one or more plain segments
/// (`[A-Za-z0-9_-]`, not starting with `.`), no empty or dot segments, no
/// percent-encoding or query, and not the root. A trailing `/` is dropped.
///
/// # Errors
///
/// A message naming what is wrong.
pub fn validate_path(path: &str) -> Result<String, String> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let Some(rest) = trimmed.strip_prefix('/') else {
        return Err(format!("nostr path {path:?} must start with '/'"));
    };
    if rest.is_empty() {
        return Err("nostr path must not be the pod root".into());
    }
    for seg in rest.split('/') {
        let ok = !seg.is_empty()
            && !seg.starts_with('.')
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        if !ok {
            return Err(format!(
                "nostr path segment {seg:?} must be non-empty letters, digits, '-' or '_'"
            ));
        }
    }
    Ok(trimmed.to_string())
}

fn accepts_nip11(req: &HttpRequest) -> bool {
    req.headers()
        .get(actix_web::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| {
            a.split(',').any(|m| {
                m.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case(NIP11_TYPE)
            })
        })
}

fn is_upgrade(req: &HttpRequest) -> bool {
    req.headers()
        .get(actix_web::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
}

fn info_response(mount: &NostrMount) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(NIP11_TYPE)
        .insert_header(("access-control-allow-origin", "*"))
        .insert_header(("access-control-allow-headers", "Accept"))
        .insert_header(("access-control-allow-methods", "GET, OPTIONS"))
        .json(mount.relay.info())
}

/// `GET P`: WebSocket upgrade, NIP-11 document, or `404`.
pub(crate) async fn handle_relay(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(mount) = state.nostr.clone() else {
        return Ok(HttpResponse::NotFound().finish());
    };
    if is_upgrade(&req) {
        return upgrade(&req, body, &mount);
    }
    if accepts_nip11(&req) {
        return Ok(info_response(&mount));
    }
    Ok(HttpResponse::NotFound().body("not found"))
}

/// `GET P/info`: the information document, whatever `Accept` says.
pub(crate) async fn handle_relay_info(state: web::Data<AppState>) -> HttpResponse {
    match &state.nostr {
        Some(mount) => info_response(mount),
        None => HttpResponse::NotFound().finish(),
    }
}

/// `OPTIONS P` and `OPTIONS P/info`: the CORS preflight for the NIP-11 fetch.
pub(crate) async fn handle_relay_preflight() -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header(("access-control-allow-origin", "*"))
        .insert_header(("access-control-allow-headers", "Accept"))
        .insert_header(("access-control-allow-methods", "GET, OPTIONS"))
        .finish()
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn upgrade(
    req: &HttpRequest,
    body: web::Payload,
    mount: &NostrMount,
) -> Result<HttpResponse, actix_web::Error> {
    if mount.connections.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
        mount.connections.fetch_sub(1, Ordering::Relaxed);
        return Ok(HttpResponse::ServiceUnavailable().body("too many relay connections"));
    }
    let slot = Slot(mount.connections.clone());
    let limits = RelayLimits::default();
    let (response, mut session, stream) = actix_ws::handle(req, body)?;
    let mut stream = stream.max_frame_size(limits.max_text_frame_bytes);
    let relay = mount.relay.clone();
    actix_web::rt::spawn(async move {
        let _slot = slot;
        let mut subscriptions: HashMap<String, Vec<Filter>> = HashMap::new();
        let mut live = relay.subscribe();
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.tick().await;
        loop {
            tokio::select! {
                msg = stream.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        let out = dispatch_message_with_limits(
                            &relay, &mut subscriptions, &text, &limits,
                        );
                        for frame in out {
                            if session.text(frame).await.is_err() {
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
                    Some(Ok(Message::Binary(_))) => {
                        let _ = session
                            .text(r#"["NOTICE","binary frames not accepted"]"#)
                            .await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return,
                },
                ev = live.recv() => match ev {
                    Ok(event) => {
                        for (sub_id, filters) in &subscriptions {
                            if filters.iter().any(|f| f.matches(&event)) {
                                let frame = serde_json::json!(["EVENT", sub_id, event]).to_string();
                                if session.text(frame).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::validate_path;

    #[test]
    fn mount_paths_are_whole_plain_segments() {
        assert_eq!(validate_path("/relay").unwrap(), "/relay");
        assert_eq!(validate_path("/relay/").unwrap(), "/relay");
        assert_eq!(validate_path("/a/b-c_d").unwrap(), "/a/b-c_d");
        for bad in [
            "",
            "/",
            "relay",
            "//",
            "/relay//x",
            "/.well-known",
            "/relay/..",
            "/relay/.",
            "/re lay",
            "/relay?x=1",
            "/relay#f",
            "/rel%61y",
            "/relay/%2e%2e",
            "/relay\\x",
            "/a/./b",
        ] {
            assert!(validate_path(bad).is_err(), "{bad:?}");
        }
    }
}
