//! The NIP-34 relay publisher (JSS `publishToRelay` and `publishEvent`).
//!
//! One signed event goes to each configured relay over a WebSocket: connect,
//! send `["EVENT", <event>]`, wait for the relay's `["OK", <id>, <accepted>,
//! <message>]` for **that** event id and report it. Every relay gets one
//! shared budget (five seconds by default) covering connect, send and the
//! answer, relays are contacted in parallel, and a failing relay never fails
//! the others: each yields a [`RelayResult`].
//!
//! # Security posture
//!
//! * Only `ws://` and `wss://` URLs without whitespace, `;`, `'` or `"` are
//!   used ([`valid_relay_url`]); anything else is reported, never dialled.
//! * The relay host passes an injected [`SsrfCheck`] before any connection.
//!   The workspace default ([`solid_pod_rs_nostr::DefaultSsrfCheck`]) refuses
//!   loopback, private and metadata space. The socket resolves the name
//!   itself, so the check narrows the target but does not pin the address (a
//!   residual DNS-rebinding window that the JSS publisher also has; relays
//!   are operator-configured, not caller-supplied).
//! * Inbound frames are size-bounded and only the matching `OK` is read.
//!
//! # Example
//!
//! ```
//! use solid_pod_rs_forge::publish::valid_relay_url;
//!
//! assert!(valid_relay_url("wss://relay.example"));
//! assert!(valid_relay_url("ws://r2.example:7777"));
//! assert!(!valid_relay_url("https://relay.example"));
//! assert!(!valid_relay_url("wss://relay example"));
//! ```

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use solid_pod_rs_nostr::Event;
pub use solid_pod_rs_nostr::SsrfCheck;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

/// Default budget for one relay, covering connect, send and the `OK`
/// (JSS `NOSTR_RELAY_TIMEOUT_MS`).
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest relay frame accepted, in bytes. A larger frame ends the session.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// What happened when one event was offered to one relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayResult {
    /// The relay URL as configured.
    pub relay: String,
    /// `true` when the relay answered `["OK", <id>, true, ...]`.
    pub ok: bool,
    /// Why it was not accepted: `timeout`, `closed before OK`, the relay's
    /// own rejection message, a refusal or a transport error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RelayResult {
    fn accepted(relay: &str) -> Self {
        Self {
            relay: relay.to_string(),
            ok: true,
            error: None,
        }
    }

    fn failed(relay: &str, error: impl Into<String>) -> Self {
        Self {
            relay: relay.to_string(),
            ok: false,
            error: Some(error.into()),
        }
    }
}

/// An SSRF policy for operator-configured relays: a host that is exactly one
/// of the relays the operator listed (host and port) is admitted without
/// resolution, which is what lets a loopback or private-network relay (the
/// embedded relay of an agent container) be named; every other host gets the
/// workspace default, so a relay URL taken from anywhere else is still
/// screened.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::publish::OperatorRelays;
/// use solid_pod_rs_nostr::SsrfCheck;
///
/// # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
/// # rt.block_on(async {
/// let policy = OperatorRelays::new(&["ws://127.0.0.1:7777".to_string()]);
/// assert!(policy.verify_host("127.0.0.1:7777").await.is_ok());
/// assert!(policy.verify_host("127.0.0.1:9999").await.is_err());
/// # });
/// ```
#[derive(Debug, Clone, Default)]
pub struct OperatorRelays {
    allowed: Vec<String>,
}

impl OperatorRelays {
    /// Build the allow-list from relay URLs (`ws://host[:port]/…`); malformed
    /// entries are skipped.
    #[must_use]
    pub fn new(relays: &[String]) -> Self {
        let allowed = relays
            .iter()
            .filter_map(|r| url::Url::parse(r).ok())
            .filter_map(|u| {
                let host = u.host_str()?.to_ascii_lowercase();
                let port = u.port_or_known_default()?;
                Some(format!("{host}:{port}"))
            })
            .collect();
        Self { allowed }
    }
}

#[async_trait::async_trait]
impl SsrfCheck for OperatorRelays {
    async fn verify_host(&self, host: &str) -> Result<Option<std::net::IpAddr>, String> {
        let h = host.to_ascii_lowercase();
        // A bare host means the scheme's default port.
        let bare = (!h.contains(':')).then(|| [format!("{h}:80"), format!("{h}:443")]);
        if self
            .allowed
            .iter()
            .any(|a| *a == h || bare.as_ref().is_some_and(|b| b.contains(a)))
        {
            return Ok(None);
        }
        solid_pod_rs_nostr::DefaultSsrfCheck.verify_host(host).await
    }
}

/// Is `s` a relay URL this publisher will dial: `ws://` or `wss://` (any
/// case) followed by at least one character, none of them whitespace, `;`,
/// `'` or `"` (JSS `announceRelays` filter).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::publish::valid_relay_url;
///
/// assert!(valid_relay_url("WSS://Relay.Example/path"));
/// assert!(!valid_relay_url("ws://"));
/// assert!(!valid_relay_url("wss://a;b"));
/// ```
#[must_use]
pub fn valid_relay_url(s: &str) -> bool {
    let rest = if s.len() >= 6 && s.is_char_boundary(6) && s[..6].eq_ignore_ascii_case("wss://") {
        &s[6..]
    } else if s.len() >= 5 && s.is_char_boundary(5) && s[..5].eq_ignore_ascii_case("ws://") {
        &s[5..]
    } else {
        return false;
    };
    !rest.is_empty()
        && !rest
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, ';' | '\'' | '"'))
}

/// The `host[:port]` an SSRF policy should judge for `relay`, or why the URL
/// is unusable.
fn ssrf_target(relay: &str) -> Result<String, String> {
    let parsed = url::Url::parse(relay).map_err(|e| format!("bad relay URL: {e}"))?;
    let host = parsed.host_str().ok_or("relay URL has no host")?;
    Ok(match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// Offer `event` to one `relay` and report the outcome. Never panics and
/// never returns an error: every failure is a [`RelayResult`] with
/// `ok == false`.
///
/// The relay URL must satisfy [`valid_relay_url`] and its host must pass
/// `ssrf`; otherwise nothing is dialled. `timeout` bounds the whole exchange.
///
/// # Examples
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// use solid_pod_rs_forge::publish::publish_to_relay;
/// use solid_pod_rs_nostr::{DefaultSsrfCheck, Event};
/// use std::time::Duration;
///
/// let ev = Event {
///     id: "0".repeat(64), pubkey: "1".repeat(64), created_at: 1, kind: 30617,
///     tags: vec![], content: String::new(), sig: "2".repeat(128),
/// };
/// // A loopback relay is refused by the default policy before any connection.
/// let r = publish_to_relay(&ev, "ws://127.0.0.1:1", Duration::from_secs(1), &DefaultSsrfCheck).await;
/// assert!(!r.ok);
/// assert!(r.error.unwrap().starts_with("relay host refused"));
/// # });
/// ```
pub async fn publish_to_relay(
    event: &Event,
    relay: &str,
    timeout: Duration,
    ssrf: &dyn SsrfCheck,
) -> RelayResult {
    if !valid_relay_url(relay) {
        return RelayResult::failed(relay, "invalid relay URL");
    }
    let target = match ssrf_target(relay) {
        Ok(t) => t,
        Err(e) => return RelayResult::failed(relay, e),
    };
    if let Err(why) = ssrf.verify_host(&target).await {
        return RelayResult::failed(relay, format!("relay host refused: {why}"));
    }
    match tokio::time::timeout(timeout, exchange(event, relay)).await {
        Ok(result) => result,
        Err(_) => RelayResult::failed(relay, "timeout"),
    }
}

/// Connect, send the event, read frames until the matching `OK`.
async fn exchange(event: &Event, relay: &str) -> RelayResult {
    let limits = WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..WebSocketConfig::default()
    };
    let mut ws =
        match tokio_tungstenite::connect_async_with_config(relay, Some(limits), false).await {
            Ok((ws, _)) => ws,
            Err(e) => return RelayResult::failed(relay, e.to_string()),
        };
    let frame = json!(["EVENT", event]).to_string();
    if let Err(e) = ws.send(Message::text(frame)).await {
        return RelayResult::failed(relay, e.to_string());
    }
    let result = loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                if let Some(r) = read_ok(&text, &event.id, relay) {
                    break r;
                }
            }
            Some(Ok(Message::Close(_))) | None => {
                break RelayResult::failed(relay, "closed before OK");
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => break RelayResult::failed(relay, e.to_string()),
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(250), ws.close(None)).await;
    result
}

/// Interpret one text frame: the `OK` for `event_id`, or `None` for anything
/// else (other events' `OK`s, `NOTICE`, malformed JSON).
fn read_ok(text: &str, event_id: &str, relay: &str) -> Option<RelayResult> {
    let msg: Value = serde_json::from_str(text).ok()?;
    let arr = msg.as_array()?;
    if arr.first()?.as_str()? != "OK" || arr.get(1)?.as_str()? != event_id {
        return None;
    }
    if arr.get(2).is_some_and(|v| v.as_bool() == Some(true)) {
        return Some(RelayResult::accepted(relay));
    }
    let reason = match arr.get(3) {
        None | Some(Value::Null) => "rejected".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    Some(RelayResult::failed(relay, reason))
}

/// Offer `event` to every relay in parallel and return one [`RelayResult`]
/// per relay, in the order given. An empty list yields an empty result and
/// opens no connection (emission is opt-in).
///
/// # Examples
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// use solid_pod_rs_forge::publish::{publish_event, RELAY_TIMEOUT};
/// use solid_pod_rs_nostr::{DefaultSsrfCheck, Event};
///
/// let ev = Event {
///     id: "0".repeat(64), pubkey: "1".repeat(64), created_at: 1, kind: 30618,
///     tags: vec![], content: String::new(), sig: "2".repeat(128),
/// };
/// assert!(publish_event(&ev, &[], RELAY_TIMEOUT, &DefaultSsrfCheck).await.is_empty());
/// # });
/// ```
pub async fn publish_event(
    event: &Event,
    relays: &[String],
    timeout: Duration,
    ssrf: &dyn SsrfCheck,
) -> Vec<RelayResult> {
    futures_util::future::join_all(
        relays
            .iter()
            .map(|relay| publish_to_relay(event, relay, timeout, ssrf)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    struct AllowAll;
    #[async_trait::async_trait]
    impl SsrfCheck for AllowAll {
        async fn verify_host(&self, _host: &str) -> Result<Option<std::net::IpAddr>, String> {
            Ok(None)
        }
    }

    fn event(id: &str) -> Event {
        Event {
            id: id.to_string(),
            pubkey: "1".repeat(64),
            created_at: 1,
            kind: 30617,
            tags: vec![vec!["d".into(), "a/b".into()]],
            content: String::new(),
            sig: "2".repeat(128),
        }
    }

    /// How the stub relay answers an `EVENT`.
    #[derive(Clone, Copy)]
    enum Behaviour {
        Accept,
        Reject(&'static str),
        RejectSilently,
        NoiseThenAccept,
        Silent,
        CloseAtOnce,
    }

    /// A one-connection relay; returns its URL and the events it received.
    async fn stub_relay(b: Behaviour) -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            if matches!(b, Behaviour::CloseAtOnce) {
                let _ = ws.close(None).await;
                return;
            }
            while let Some(Ok(Message::Text(t))) = ws.next().await {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v[0] != "EVENT" {
                    continue;
                }
                let id = v[1]["id"].as_str().unwrap().to_string();
                sink.lock().unwrap().push(v[1].clone());
                let reply = |m: Value| Message::text(m.to_string());
                match b {
                    Behaviour::Accept => {
                        let _ = ws.send(reply(json!(["OK", id, true, ""]))).await;
                    }
                    Behaviour::Reject(why) => {
                        let _ = ws.send(reply(json!(["OK", id, false, why]))).await;
                    }
                    Behaviour::RejectSilently => {
                        let _ = ws.send(reply(json!(["OK", id, false]))).await;
                    }
                    Behaviour::NoiseThenAccept => {
                        let _ = ws.send(reply(json!(["NOTICE", "hello"]))).await;
                        let _ = ws.send(Message::text("not json")).await;
                        let _ = ws
                            .send(reply(json!(["OK", "f".repeat(64), true, ""])))
                            .await;
                        let _ = ws.send(reply(json!(["OK", id, true, ""]))).await;
                    }
                    Behaviour::Silent | Behaviour::CloseAtOnce => {}
                }
            }
        });
        (url, seen)
    }

    #[test]
    fn relay_url_filter_matches_the_jss_pattern() {
        for ok in [
            "wss://relay.example",
            "ws://r.example:7777/x",
            "WS://X",
            "ws://x",
            "wss://[::1]:8080",
        ] {
            assert!(valid_relay_url(ok), "{ok}");
        }
        for bad in [
            "",
            "ws://",
            "wss://",
            "http://relay.example",
            "https://relay.example",
            "wss:/relay",
            "wss://a b",
            "wss://a\tb",
            "wss://a;b",
            "wss://a'b",
            "wss://a\"b",
            "wss://a\nb",
            "wss://é\u{3000}",
            " wss://a",
            "wss://a ",
        ] {
            assert!(!valid_relay_url(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn an_accepted_event_is_delivered_and_the_ok_parsed() {
        let (url, seen) = stub_relay(Behaviour::Accept).await;
        let ev = event(&"a".repeat(64));
        let r = publish_to_relay(&ev, &url, RELAY_TIMEOUT, &AllowAll).await;
        assert_eq!(r, RelayResult::accepted(&url));
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["id"], ev.id);
        assert_eq!(got[0]["kind"], 30617);
    }

    #[tokio::test]
    async fn a_rejection_carries_the_relay_message_or_rejected() {
        let (url, _) = stub_relay(Behaviour::Reject("blocked: spam")).await;
        let r = publish_to_relay(&event(&"a".repeat(64)), &url, RELAY_TIMEOUT, &AllowAll).await;
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("blocked: spam"));

        let (url, _) = stub_relay(Behaviour::RejectSilently).await;
        let r = publish_to_relay(&event(&"a".repeat(64)), &url, RELAY_TIMEOUT, &AllowAll).await;
        assert_eq!(r.error.as_deref(), Some("rejected"));
    }

    #[tokio::test]
    async fn only_the_ok_for_this_event_counts() {
        let (url, _) = stub_relay(Behaviour::NoiseThenAccept).await;
        let r = publish_to_relay(&event(&"a".repeat(64)), &url, RELAY_TIMEOUT, &AllowAll).await;
        assert!(r.ok, "{r:?}");
    }

    #[tokio::test]
    async fn a_silent_relay_times_out() {
        let (url, _) = stub_relay(Behaviour::Silent).await;
        let r = publish_to_relay(
            &event(&"a".repeat(64)),
            &url,
            Duration::from_millis(300),
            &AllowAll,
        )
        .await;
        assert_eq!(r, RelayResult::failed(&url, "timeout"));
    }

    #[tokio::test]
    async fn a_relay_that_closes_first_is_reported() {
        let (url, _) = stub_relay(Behaviour::CloseAtOnce).await;
        let r = publish_to_relay(&event(&"a".repeat(64)), &url, RELAY_TIMEOUT, &AllowAll).await;
        assert!(!r.ok);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn a_refused_port_is_a_failure_not_a_panic() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        drop(l);
        let r = publish_to_relay(&event(&"a".repeat(64)), &url, RELAY_TIMEOUT, &AllowAll).await;
        assert!(!r.ok);
        assert!(r.error.is_some());
    }

    #[tokio::test]
    async fn the_default_ssrf_policy_refuses_private_relays_without_connecting() {
        // A live listener proves nothing connects: it must see no connection.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let ev = event(&"a".repeat(64));
        let r = publish_to_relay(
            &ev,
            &url,
            RELAY_TIMEOUT,
            &solid_pod_rs_nostr::DefaultSsrfCheck,
        )
        .await;
        assert!(!r.ok);
        assert!(
            r.error
                .as_deref()
                .unwrap()
                .starts_with("relay host refused"),
            "{r:?}"
        );
        let accepted = tokio::time::timeout(Duration::from_millis(200), l.accept()).await;
        assert!(accepted.is_err(), "the forge must not have dialled");
        for private in [
            "ws://[::1]:9",
            "ws://10.0.0.5",
            "ws://169.254.169.254/latest",
            "ws://192.168.1.1:7000",
        ] {
            let r = publish_to_relay(
                &ev,
                private,
                RELAY_TIMEOUT,
                &solid_pod_rs_nostr::DefaultSsrfCheck,
            )
            .await;
            assert!(
                r.error
                    .as_deref()
                    .unwrap()
                    .starts_with("relay host refused"),
                "{private}: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn non_websocket_and_malformed_urls_are_never_dialled() {
        let ev = event(&"a".repeat(64));
        for bad in ["http://127.0.0.1:1", "wss://a b", "file:///etc/passwd", ""] {
            let r = publish_to_relay(&ev, bad, RELAY_TIMEOUT, &AllowAll).await;
            assert_eq!(r, RelayResult::failed(bad, "invalid relay URL"), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn relays_are_contacted_in_parallel_and_one_failure_does_not_fail_the_rest() {
        let (good, _) = stub_relay(Behaviour::Accept).await;
        let (bad, _) = stub_relay(Behaviour::Reject("no")).await;
        let ev = event(&"a".repeat(64));
        let rs = publish_event(
            &ev,
            &[good.clone(), "http://nope".into(), bad.clone()],
            RELAY_TIMEOUT,
            &AllowAll,
        )
        .await;
        assert_eq!(rs.len(), 3);
        assert!(rs[0].ok && rs[0].relay == good);
        assert!(!rs[1].ok);
        assert_eq!(rs[2].error.as_deref(), Some("no"));
        assert!(publish_event(&ev, &[], RELAY_TIMEOUT, &AllowAll)
            .await
            .is_empty());
    }

    #[test]
    fn relay_result_serialises_without_an_absent_error() {
        let ok = serde_json::to_value(RelayResult::accepted("wss://r")).unwrap();
        assert_eq!(ok, json!({"relay": "wss://r", "ok": true}));
        let bad = serde_json::to_value(RelayResult::failed("wss://r", "timeout")).unwrap();
        assert_eq!(
            bad,
            json!({"relay": "wss://r", "ok": false, "error": "timeout"})
        );
    }
}
