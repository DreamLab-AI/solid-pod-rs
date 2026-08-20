//! WebSocket wire handler for the Nostr relay.
//!
//! NIP-01 client→relay messages accepted:
//! - `["EVENT", <event>]`
//! - `["REQ", <sub_id>, <filter1>, <filter2>, ...]`
//! - `["CLOSE", <sub_id>]`
//!
//! Relay→client messages emitted:
//! - `["EVENT", <sub_id>, <event>]`
//! - `["EOSE", <sub_id>]`
//! - `["OK", <event_id>, <bool>, <msg>]`
//! - `["NOTICE", <msg>]`
//!
//! The handler is wire-only — it takes an `impl` stream and pumps
//! messages. Consumers wire this into their HTTP stack (axum, actix,
//! warp, etc.) through `tokio_tungstenite::WebSocketStream`.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::relay::{Event, Filter, Relay};

/// Conservative per-connection limits for a public relay endpoint.
#[derive(Clone, Debug)]
pub struct RelayLimits {
    pub max_text_frame_bytes: usize,
    pub max_event_bytes: usize,
    pub max_subscriptions: usize,
    pub max_filters_per_subscription: usize,
    pub max_filter_bytes: usize,
    pub max_history_events: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_text_frame_bytes: 256 * 1024,
            max_event_bytes: 128 * 1024,
            max_subscriptions: 32,
            max_filters_per_subscription: 8,
            max_filter_bytes: 16 * 1024,
            max_history_events: 500,
        }
    }
}

/// Run the WebSocket handshake loop over an already-upgraded stream.
///
/// This is the recommended entry point for tests and custom bindings —
/// most consumers will call [`serve_relay_ws`] on a fresh TCP stream
/// after their HTTP upgrade.
#[allow(clippy::collapsible_match)]
pub async fn serve_relay_ws_stream<S>(relay: Arc<Relay>, ws: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_relay_ws_stream_with_limits(relay, ws, RelayLimits::default()).await;
}

/// Serve an upgraded stream with explicit application-level limits.
pub async fn serve_relay_ws_stream_with_limits<S>(
    relay: Arc<Relay>,
    mut ws: WebSocketStream<S>,
    limits: RelayLimits,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Subscriptions owned by this socket: subscription_id → filters.
    let mut subscriptions: HashMap<String, Vec<Filter>> = HashMap::new();
    // Live-event broadcast subscribe.
    let mut live = relay.subscribe();

    loop {
        tokio::select! {
            // Inbound wire message.
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let response = dispatch_message_with_limits(
                            &relay,
                            &mut subscriptions,
                            &text,
                            &limits,
                        );
                        for out in response {
                            if ws.send(Message::Text(out)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {
                        let _ = ws
                            .send(Message::Text(notice("binary frames not accepted")))
                            .await;
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if ws.send(Message::Pong(p)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Err(_)) => return,
                    _ => {}
                }
            }
            // Live event from the relay broadcast.
            Ok(event) = live.recv() => {
                for (sub_id, filters) in &subscriptions {
                    if filters.iter().any(|f| f.matches(&event)) {
                        let frame = json!([
                            "EVENT",
                            sub_id,
                            serde_json::to_value(&event).unwrap_or(Value::Null),
                        ])
                        .to_string();
                        if ws.send(Message::Text(frame)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Convenience alias — most consumers wire their HTTP stack directly
/// to `serve_relay_ws_stream`. This free function is retained for the
/// public surface declared in the plan.
pub async fn serve_relay_ws<S>(relay: Arc<Relay>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = RelayLimits::default();
    let config = WebSocketConfig {
        max_message_size: Some(limits.max_text_frame_bytes),
        max_frame_size: Some(limits.max_text_frame_bytes),
        ..WebSocketConfig::default()
    };
    if let Ok(ws) = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await {
        serve_relay_ws_stream_with_limits(relay, ws, limits).await;
    }
}

/// Parse a text frame and produce the responses to send back.
///
/// Pure: takes no network I/O. Exposed for unit-testing the wire
/// protocol independently of tungstenite.
pub fn dispatch_message(
    relay: &Relay,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    text: &str,
) -> Vec<String> {
    dispatch_message_with_limits(relay, subscriptions, text, &RelayLimits::default())
}

/// Dispatch a frame under explicit resource limits.
pub fn dispatch_message_with_limits(
    relay: &Relay,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    text: &str,
    limits: &RelayLimits,
) -> Vec<String> {
    if text.len() > limits.max_text_frame_bytes {
        return vec![notice("frame too large")];
    }
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return vec![notice(&format!("bad JSON: {e}"))],
    };
    let arr = match parsed.as_array() {
        Some(a) => a.clone(),
        None => return vec![notice("wire frame must be a JSON array")],
    };
    let head = match arr.first().and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return vec![notice("empty or malformed wire frame")],
    };

    match head.as_str() {
        "EVENT" => handle_event(relay, &arr, limits),
        "REQ" => handle_req(relay, subscriptions, &arr, limits),
        "CLOSE" => handle_close(subscriptions, &arr),
        other => vec![notice(&format!("unknown frame type: {other}"))],
    }
}

fn handle_event(relay: &Relay, arr: &[Value], limits: &RelayLimits) -> Vec<String> {
    use crate::typestate::UncheckedEvent;

    let Some(event_value) = arr.get(1) else {
        return vec![notice("EVENT frame missing event payload")];
    };
    if serde_json::to_vec(event_value)
        .map(|bytes| bytes.len() > limits.max_event_bytes)
        .unwrap_or(true)
    {
        return vec![ok_frame("", false, "invalid: event too large")];
    }
    let event: Event = match serde_json::from_value(event_value.clone()) {
        Ok(e) => e,
        Err(e) => {
            let id = event_value
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return vec![ok_frame(&id, false, &format!("invalid: {e}"))];
        }
    };

    // Typestate path: wrap as UncheckedEvent, verify the Schnorr
    // signature, then ingest the VerifiedEvent. This avoids the
    // double-verification that `relay.ingest()` would perform and
    // demonstrates the recommended API pattern.
    let unchecked = UncheckedEvent::new(event);
    let id = unchecked.id().to_string();
    match unchecked.verify() {
        Ok(verified) => match relay.ingest_verified(verified) {
            Ok(()) => vec![ok_frame(&id, true, "")],
            Err(e) => vec![ok_frame(&id, false, &e.to_string())],
        },
        Err(e) => vec![ok_frame(&id, false, &e.to_string())],
    }
}

fn handle_req(
    relay: &Relay,
    subscriptions: &mut HashMap<String, Vec<Filter>>,
    arr: &[Value],
    limits: &RelayLimits,
) -> Vec<String> {
    let Some(sub_id) = arr.get(1).and_then(|v| v.as_str()) else {
        return vec![notice("REQ frame missing subscription id")];
    };
    if sub_id.len() > 64 {
        return vec![notice("subscription id too long")];
    }
    let sub_id = sub_id.to_string();
    let raw_filters = &arr[2..];
    if raw_filters.is_empty() || raw_filters.len() > limits.max_filters_per_subscription {
        return vec![notice("too many filters")];
    }
    if !subscriptions.contains_key(&sub_id) && subscriptions.len() >= limits.max_subscriptions {
        return vec![notice("too many subscriptions")];
    }
    let mut filters = Vec::with_capacity(raw_filters.len());
    for raw in raw_filters {
        if serde_json::to_vec(raw)
            .map(|bytes| bytes.len() > limits.max_filter_bytes)
            .unwrap_or(true)
        {
            return vec![notice("filter too large")];
        }
        match Filter::from_value(raw.clone()) {
            Ok(f) => filters.push(f),
            Err(e) => {
                return vec![notice(&format!("invalid filter: {e}"))];
            }
        }
    }
    let result_limit = filters
        .iter()
        .filter_map(|filter| filter.limit)
        .max()
        .unwrap_or(limits.max_history_events)
        .min(limits.max_history_events);
    let history = relay.history(&filters);
    subscriptions.insert(sub_id.clone(), filters);
    let mut out = Vec::with_capacity(result_limit.saturating_add(1));
    for ev in history.into_iter().take(result_limit) {
        let frame = json!([
            "EVENT",
            sub_id,
            serde_json::to_value(ev).unwrap_or(Value::Null)
        ])
        .to_string();
        out.push(frame);
    }
    out.push(json!(["EOSE", sub_id]).to_string());
    out
}

fn handle_close(subscriptions: &mut HashMap<String, Vec<Filter>>, arr: &[Value]) -> Vec<String> {
    let Some(sub_id) = arr.get(1).and_then(|v| v.as_str()) else {
        return vec![notice("CLOSE frame missing subscription id")];
    };
    subscriptions.remove(sub_id);
    Vec::new()
}

fn notice(msg: &str) -> String {
    json!(["NOTICE", msg]).to_string()
}

fn ok_frame(event_id: &str, accepted: bool, msg: &str) -> String {
    json!(["OK", event_id, accepted, msg]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;

    fn test_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32]).expect("valid schnorr key")
    }

    fn make_event(kind: u64, content: &str) -> Event {
        let sk = test_sk();
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        let skeleton = Event {
            id: String::new(),
            pubkey: pubkey_hex.clone(),
            created_at: 1_700_000_000,
            kind,
            tags: vec![],
            content: content.to_string(),
            sig: String::new(),
        };
        let id = skeleton.canonical_id();
        let id_bytes = hex::decode(&id).unwrap();
        let sig = sk
            .sign_raw(&id_bytes, &[0u8; 32])
            .expect("schnorr sign_raw");
        Event {
            id,
            pubkey: pubkey_hex,
            created_at: 1_700_000_000,
            kind,
            tags: vec![],
            content: content.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    #[test]
    fn dispatch_event_returns_ok_true() {
        let relay = Relay::in_memory();
        let mut subs = HashMap::new();
        let ev = make_event(1, "hello");
        let frame = json!(["EVENT", serde_json::to_value(&ev).unwrap()]).to_string();
        let out = dispatch_message(&relay, &mut subs, &frame);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("\"OK\""));
        assert!(out[0].contains("true"));
    }

    #[test]
    fn dispatch_event_with_bad_signature_returns_ok_false() {
        let relay = Relay::in_memory();
        let mut subs = HashMap::new();
        let mut ev = make_event(1, "hello");
        let mut sig = hex::decode(&ev.sig).unwrap();
        sig[0] ^= 0x01;
        ev.sig = hex::encode(sig);
        let frame = json!(["EVENT", serde_json::to_value(&ev).unwrap()]).to_string();
        let out = dispatch_message(&relay, &mut subs, &frame);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("\"OK\""));
        assert!(out[0].contains("false"));
    }

    #[test]
    fn req_returns_history_and_eose() {
        let relay = Relay::in_memory();
        let mut subs: HashMap<String, Vec<Filter>> = HashMap::new();
        let ev = make_event(1, "stored");
        relay.ingest(ev.clone()).unwrap();
        let frame = json!(["REQ", "sub1", {"kinds": [1]}]).to_string();
        let out = dispatch_message(&relay, &mut subs, &frame);
        assert_eq!(out.len(), 2); // one EVENT + one EOSE
        assert!(out[0].contains("\"EVENT\""));
        assert!(out[0].contains(&ev.id));
        assert!(out[1].contains("\"EOSE\""));
        assert!(subs.contains_key("sub1"));
    }

    #[test]
    fn close_removes_subscription() {
        let relay = Relay::in_memory();
        let mut subs: HashMap<String, Vec<Filter>> = HashMap::new();
        subs.insert("sub1".into(), vec![]);
        let frame = json!(["CLOSE", "sub1"]).to_string();
        let out = dispatch_message(&relay, &mut subs, &frame);
        assert!(out.is_empty());
        assert!(!subs.contains_key("sub1"));
    }

    #[test]
    fn invalid_json_yields_notice() {
        let relay = Relay::in_memory();
        let mut subs = HashMap::new();
        let out = dispatch_message(&relay, &mut subs, "not json");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("\"NOTICE\""));
    }

    #[test]
    fn unknown_frame_type_yields_notice() {
        let relay = Relay::in_memory();
        let mut subs = HashMap::new();
        let out = dispatch_message(&relay, &mut subs, "[\"PING\"]");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("\"NOTICE\""));
    }

    #[test]
    fn limits_bound_frames_subscriptions_filters_and_history() {
        let relay = Relay::in_memory();
        for i in 0..4 {
            relay.ingest(make_event(1, &format!("event-{i}"))).unwrap();
        }
        let limits = RelayLimits {
            max_text_frame_bytes: 100,
            max_event_bytes: 80,
            max_subscriptions: 1,
            max_filters_per_subscription: 1,
            max_filter_bytes: 32,
            max_history_events: 2,
        };
        let mut subs = HashMap::new();

        let out = dispatch_message_with_limits(
            &relay,
            &mut subs,
            r#"["REQ","one",{"kinds":[1]}]"#,
            &limits,
        );
        assert_eq!(out.len(), 3, "two history events plus EOSE");

        let out = dispatch_message_with_limits(
            &relay,
            &mut subs,
            r#"["REQ","two",{"kinds":[1]}]"#,
            &limits,
        );
        assert!(out[0].contains("too many subscriptions"));

        let oversized = "x".repeat(101);
        let out = dispatch_message_with_limits(&relay, &mut subs, &oversized, &limits);
        assert!(out[0].contains("frame too large"));
    }

    #[tokio::test]
    async fn websocket_subscription_receives_matching_events() {
        use tokio::io::duplex;
        use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

        let relay = Arc::new(Relay::in_memory());
        // Pre-populate one event so history is non-empty.
        let ev_history = make_event(1, "past");
        relay.ingest(ev_history.clone()).unwrap();

        let (server_side, client_side) = duplex(4096);
        let server_ws = WebSocketStream::from_raw_socket(server_side, Role::Server, None).await;
        let client_ws = WebSocketStream::from_raw_socket(client_side, Role::Client, None).await;

        let relay_task = relay.clone();
        let server = tokio::spawn(async move {
            serve_relay_ws_stream(relay_task, server_ws).await;
        });

        let (mut write, mut read) = client_ws.split();

        // Subscribe.
        let req = json!(["REQ", "sub-x", {"kinds": [1]}]).to_string();
        write.send(Message::Text(req)).await.unwrap();

        // Expect the historical event then EOSE.
        let msg1 = read.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(msg1.contains(&ev_history.id));
        let msg2 = read.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(msg2.contains("EOSE"));

        // Now ingest a new event directly; the subscriber should receive it.
        let ev_new = make_event(1, "live");
        relay.ingest(ev_new.clone()).unwrap();
        let msg3 = read.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(msg3.contains(&ev_new.id));

        // Close the subscription and the socket.
        write
            .send(Message::Text(json!(["CLOSE", "sub-x"]).to_string()))
            .await
            .unwrap();
        write.send(Message::Close(None)).await.ok();
        drop(write);
        let _ = server.await;
    }
}
