//! ActivityPub actor endpoint wiring (cargo feature `activitypub`).
//!
//! Mirrors the JSS single-user ActivityPub plugin: `src/ap/index.js` builds a
//! config from `username` / `displayName` / `summary` / `nostrPubkey`
//! (defaults `me` and `Anonymous`, server.js 134-135), and the dedicated
//! `GET /profile/card.jsonld` route in `src/server.js` 545-570 answers an
//! `Accept: application/activity+json` request with the actor document built
//! by `src/ap/routes/actor.js`, delegating everything else to the normal
//! resource handler. A configured Nostr pubkey is linked as
//! `alsoKnownAs: ["did:nostr:<pk>"]` (actor.js 61-64).
//!
//! Operator knobs: `--ap-username`, `--ap-display-name`, `--ap-summary`,
//! `--ap-nostr-pubkey` (env `JSS_AP_*`, config `extras.ap_*`).
//!
//! Divergence from JSS: the summary is HTML-escaped before it is wrapped in
//! `<p>`; JSS interpolates it raw, which lets a misconfigured summary inject
//! markup into every remote timeline that renders the actor.

use std::path::Path;
use std::sync::Arc;

use actix_web::http::{header, StatusCode};
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use solid_pod_rs_activitypub::{
    generate_actor_keypair, handle_inbox, handle_outbox_post as handle_outbox_post_lib,
    render_actor, verify_request_signature, with_also_known_as, Actor, DeliveryConfig,
    DeliveryWorker, HttpActorKeyResolver, InboxError, InboxOutcome, OutboxError, SignedRequest,
    SsrfGuard, Store,
};
use tokio::sync::Semaphore;

/// Fully resolved ActivityPub actor configuration.
#[derive(Debug, Clone)]
pub struct ApConfig {
    /// WebFinger local part and `preferredUsername`.
    pub username: String,
    /// Human-facing `name`.
    pub display_name: String,
    /// Plain-text bio (escaped on output). Empty means none.
    pub summary: String,
    /// Lowercase hex Nostr pubkey linked through `alsoKnownAs`.
    pub nostr_pubkey: Option<String>,
    /// PEM public key published in the actor document.
    pub public_key_pem: String,
}

fn valid_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl ApConfig {
    /// Build a config from the operator knobs, applying the JSS defaults:
    /// username `me`; display name = display name, else the username as
    /// given, else `Anonymous`.
    ///
    /// Rejects a username outside `[A-Za-z0-9_.-]{1,64}` and a pubkey that
    /// is not 64 hex characters.
    pub fn from_knobs(
        username: Option<&str>,
        display_name: Option<&str>,
        summary: Option<&str>,
        nostr_pubkey: Option<&str>,
        public_key_pem: String,
    ) -> Result<Self, String> {
        fn non_empty(o: Option<&str>) -> Option<&str> {
            o.map(str::trim).filter(|s| !s.is_empty())
        }
        let given_username = non_empty(username);
        if let Some(u) = given_username {
            if !valid_username(u) {
                return Err(format!("invalid ActivityPub username {u:?}"));
            }
        }
        let nostr_pubkey = match non_empty(nostr_pubkey) {
            Some(pk) => {
                let pk = pk.to_ascii_lowercase();
                if !crate::cross_identity::is_hex_pubkey(&pk) {
                    return Err("ActivityPub nostr pubkey must be 64 hex characters".into());
                }
                Some(pk)
            }
            None => None,
        };
        Ok(Self {
            username: given_username.unwrap_or("me").to_string(),
            display_name: non_empty(display_name)
                .or(given_username)
                .unwrap_or("Anonymous")
                .to_string(),
            summary: non_empty(summary).unwrap_or("").to_string(),
            nostr_pubkey,
            public_key_pem,
        })
    }

    /// The actor document for the site at `base_url` (`scheme://host`).
    pub fn actor_json(&self, base_url: &str) -> serde_json::Value {
        let summary = if self.summary.is_empty() {
            String::new()
        } else {
            format!("<p>{}</p>", html_escape(&self.summary))
        };
        let mut actor = render_actor(
            base_url,
            &self.username,
            &self.display_name,
            Some(&summary),
            &self.public_key_pem,
        );
        if let Some(pk) = &self.nostr_pubkey {
            actor = with_also_known_as(actor, [format!("did:nostr:{pk}")]);
        }
        serde_json::to_value(actor).unwrap_or(serde_json::Value::Null)
    }
}

impl crate::ActorDocument for ApConfig {
    fn actor_json(&self, base_url: &str) -> serde_json::Value {
        ApConfig::actor_json(self, base_url)
    }
}

/// Escape the five HTML-significant characters.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Load the actor's public key PEM from `<data_root>/.ap/keys.json`, or
/// generate an RSA-2048 pair and persist it there (mode 0600 on Unix).
/// Without a data root the pair lives only for this process. Mirrors JSS
/// `src/ap/keys.js` `loadOrCreateKeypair`, which stores `data/ap-keys.json`.
///
/// Creation is atomic and race-safe (security review L8): the pair is written
/// to a uniquely named 0600 temp file and then published with `hard_link`,
/// which fails rather than replaces if another process got there first, in
/// which case the winner's key is read back. A crash can therefore never leave
/// a half-written `keys.json`, and two processes starting together agree on
/// one key. An empty `keys.json` left by the earlier, non-atomic writer is
/// discarded and regenerated.
pub fn load_or_create_public_key(data_root: Option<&Path>) -> Result<String, String> {
    load_or_create_keypair(data_root).map(|(_, public)| public)
}

/// The actor's `(private, public)` PEM pair, loaded from or created in
/// `<data_root>/.ap/keys.json` exactly as [`load_or_create_public_key`] does.
/// Without a data root a fresh pair is generated for this call only, so the
/// caller must keep and share it. The private half signs deliveries; it is
/// never logged and never leaves the process except in that file.
pub fn load_or_create_keypair(data_root: Option<&Path>) -> Result<(String, String), String> {
    let file = data_root.map(|r| r.join(".ap").join("keys.json"));
    let Some(f) = &file else {
        return generate_actor_keypair().map_err(|e| e.to_string());
    };
    for _ in 0..4 {
        if let Some(pair) = read_keypair(f)? {
            return Ok(pair);
        }
        let (private_pem, public_pem) = generate_actor_keypair().map_err(|e| e.to_string())?;
        if let Some(dir) = f.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let body = serde_json::json!({"publicKey": public_pem, "privateKey": private_pem});
        match publish_private(f, body.to_string().as_bytes()) {
            Ok(()) => return Ok((private_pem, public_pem)),
            // Another process published first: use its key.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", f.display())),
        }
    }
    Err(format!("{}: could not settle on a key file", f.display()))
}

/// The stored pair, `None` when the file is absent or empty (a crashed
/// legacy writer; the empty file is removed so it can be recreated).
fn read_keypair(f: &Path) -> Result<Option<(String, String)>, String> {
    let text = match std::fs::read_to_string(f) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", f.display())),
    };
    if text.trim().is_empty() {
        let _ = std::fs::remove_file(f);
        return Ok(None);
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
    let field = |name: &str| {
        v.get(name)
            .and_then(|p| p.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("{}: missing {name}", f.display()))
    };
    Ok(Some((field("privateKey")?, field("publicKey")?)))
}

/// Write `bytes` to a fresh 0600 temp file beside `path`, then link it into
/// place without replacing anything (`AlreadyExists` if `path` is taken).
fn publish_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = path.with_extension(format!(
        "{}.{}.{nanos}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    let linked = written.and_then(|()| std::fs::hard_link(&tmp, path));
    let _ = std::fs::remove_file(&tmp);
    linked
}

// ---------------------------------------------------------------------------
// Federation: inbox, outbox, collections, delivery (SP-PAR-281)
// ---------------------------------------------------------------------------

/// Largest inbox or outbox request body accepted (bytes). The app-wide body
/// cap is far larger and is not what protects these routes.
pub const MAX_ACTIVITY_BYTES: usize = 256 * 1024;
/// Inbox requests handled at once; one more is answered `503`.
pub const MAX_CONCURRENT_INBOX: usize = 16;
/// Most items a collection or outbox page lists.
pub const PAGE_LIMIT: i64 = 20;
/// Delivery queue poll interval in production.
pub const DELIVERY_TICK: std::time::Duration = std::time::Duration::from_secs(5);

const AS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
const AS_PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";
const AP_TYPE: &str = "application/activity+json";

/// The federation mounted on `state`, if any.
pub(crate) fn federation(state: &crate::AppState) -> Option<Arc<Federation>> {
    state
        .ap_federation
        .clone()
        .and_then(|any| any.downcast::<Federation>().ok())
}

/// The mounted federation: the actor, its store, the key that signs
/// deliveries, and the bounded outbound machinery.
///
/// Built by [`Federation::start`]; reachable as `AppState::ap_federation`.
/// Every identifier it mints (actor id, key id, collection ids) is derived
/// from `base_url`, which the operator configures as `public_base_url`; a
/// request's `Host` is never used to name the actor.
pub struct Federation {
    store: Store,
    actor: Actor,
    base_url: String,
    authority: String,
    resolver: HttpActorKeyResolver,
    inbox_slots: Semaphore,
    worker: Arc<DeliveryWorker>,
    delivery_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Federation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation")
            .field("actor", &self.actor.id)
            .finish_non_exhaustive()
    }
}

impl Drop for Federation {
    fn drop(&mut self) {
        self.delivery_task.abort();
    }
}

impl Federation {
    /// Open the store, build the actor and start the delivery worker.
    ///
    /// `base_url` must be a bare `scheme://authority`. `store` holds
    /// followers, activities and the delivery queue (a file under
    /// `<data_root>/.ap/` in the binary). `private_pem` signs deliveries and
    /// must be the pair of the `public_pem` the actor document publishes.
    /// `guard` limits every outbound address: the binary passes
    /// [`SsrfGuard::strict`]; only tests federating two local servers pass
    /// anything else. The worker polls every `tick`.
    ///
    /// # Errors
    ///
    /// A message when `base_url` is not a bare origin.
    pub fn start(
        config: &ApConfig,
        private_pem: String,
        base_url: &str,
        store: Store,
        guard: SsrfGuard,
        tick: std::time::Duration,
    ) -> Result<Arc<Self>, String> {
        let origin = crate::scheme::normalise_origin(base_url).ok_or_else(|| {
            format!("federation needs a bare scheme://host base URL, got {base_url:?}")
        })?;
        let authority = origin
            .split_once("://")
            .map_or(origin.as_str(), |(_, a)| a)
            .to_ascii_lowercase();
        let summary = config.actor_json(&origin)["summary"]
            .as_str()
            .map(str::to_string);
        let actor = render_actor(
            &origin,
            &config.username,
            &config.display_name,
            summary.as_deref(),
            &config.public_key_pem,
        );
        let worker = Arc::new(
            DeliveryWorker::new(
                store.clone(),
                DeliveryConfig {
                    private_key_pem: private_pem,
                    key_id: actor.public_key.id.clone(),
                },
            )
            .with_guard(guard),
        );
        let delivery_task = tokio::spawn(worker.clone().run(tick));
        Ok(Arc::new(Self {
            store,
            actor,
            base_url: origin,
            authority,
            resolver: HttpActorKeyResolver::default().with_guard(guard),
            inbox_slots: Semaphore::new(MAX_CONCURRENT_INBOX),
            worker,
            delivery_task,
        }))
    }

    /// The local actor's id (`<base>/profile/card.jsonld#me`).
    #[must_use]
    pub fn actor_id(&self) -> &str {
        &self.actor.id
    }

    /// The store, for embedding code and tests.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The delivery worker, so a test can drain the queue deterministically.
    #[must_use]
    pub fn worker(&self) -> &Arc<DeliveryWorker> {
        &self.worker
    }

    /// The `scheme://authority` every identifier is minted under.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Whether `host` (a `Host` header value) names this server.
    fn is_our_host(&self, host: &str) -> bool {
        host.trim().eq_ignore_ascii_case(&self.authority)
    }

    fn profile(&self) -> String {
        format!("{}/profile/card.jsonld", self.base_url)
    }
}

fn ap_json(status: StatusCode, body: &serde_json::Value) -> HttpResponse {
    HttpResponse::build(status)
        .content_type(AP_TYPE)
        .body(body.to_string())
}

fn plain(status: StatusCode, msg: &str) -> HttpResponse {
    HttpResponse::build(status).body(msg.to_string())
}

/// Read a request body of at most `cap` bytes, or say why not.
async fn read_capped(
    req: &HttpRequest,
    mut payload: web::Payload,
    cap: usize,
) -> Result<Vec<u8>, (StatusCode, &'static str)> {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > cap) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| (StatusCode::BAD_REQUEST, "unreadable body"))?;
        if body.len() + chunk.len() > cap {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The header map the signature verifier wants: lower-cased names, repeated
/// headers joined with `, `.
fn signed_request(req: &HttpRequest, body: Vec<u8>) -> SignedRequest {
    let path = req.uri().path_and_query().map_or_else(
        || req.uri().path().to_string(),
        |pq| pq.as_str().to_string(),
    );
    let mut out = SignedRequest::new(req.method().as_str(), path, body);
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, value) in req.headers() {
        let Ok(v) = value.to_str() else { continue };
        seen.entry(name.as_str().to_ascii_lowercase())
            .and_modify(|e| {
                e.push_str(", ");
                e.push_str(v);
            })
            .or_insert_with(|| v.to_string());
    }
    for (k, v) in seen {
        out = out.with_header(k, v);
    }
    out
}

/// `POST /inbox` and `POST /profile/card.jsonld/inbox`.
///
/// Nothing is parsed into the store before the request is proven to come
/// from the actor it names: signature (covering host, date, digest and the
/// request target), digest of the exact body, a fresh `Date`, and the
/// activity's `actor` equal to the signer. Anything else is `401`/`403`
/// with the store untouched.
pub(crate) async fn handle_inbox_post(
    req: HttpRequest,
    payload: web::Payload,
    state: web::Data<crate::AppState>,
) -> HttpResponse {
    let Some(fed) = federation(&state) else {
        return HttpResponse::NotFound().finish();
    };
    let host = if state.trust_proxy {
        req.headers().get("x-forwarded-host")
    } else {
        None
    }
    .or_else(|| req.headers().get(header::HOST))
    .and_then(|v| v.to_str().ok())
    .unwrap_or("");
    if !fed.is_our_host(host) {
        return plain(StatusCode::MISDIRECTED_REQUEST, "wrong host");
    }
    let Ok(_slot) = fed.inbox_slots.try_acquire() else {
        return HttpResponse::ServiceUnavailable()
            .insert_header((header::RETRY_AFTER, "5"))
            .body("inbox busy");
    };
    let body = match read_capped(&req, payload, MAX_ACTIVITY_BYTES).await {
        Ok(b) => b,
        Err((status, msg)) => return plain(status, msg),
    };
    let mut signed = signed_request(&req, body.clone());
    if state.trust_proxy {
        // The remote signed the public host; a proxy may have rewritten it.
        signed = signed.with_header("host", host);
    }
    let verified = match verify_request_signature(&signed, &fed.resolver).await {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(error = %e, "inbox request refused: signature");
            return plain(StatusCode::UNAUTHORIZED, "signature verification failed");
        }
    };
    let Ok(activity) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return plain(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    match handle_inbox(&fed.store, &fed.actor.id, &verified, &activity).await {
        Ok(InboxOutcome::FollowAccepted {
            follower_inbox,
            accept_object,
            ..
        }) => {
            if let Some(inbox) = follower_inbox {
                let queued = async {
                    let id = fed
                        .store
                        .record_outbox(&fed.actor.id, &accept_object)
                        .await?;
                    fed.store.enqueue_delivery(&id, &inbox).await
                };
                if let Err(e) = queued.await {
                    tracing::warn!(error = %e, "could not queue the Accept");
                }
            }
            HttpResponse::Accepted().finish()
        }
        Ok(_) => HttpResponse::Accepted().finish(),
        Err(InboxError::MissingType | InboxError::InvalidJson(_)) => {
            plain(StatusCode::BAD_REQUEST, "invalid activity")
        }
        Err(InboxError::ActorMismatch(_)) => plain(StatusCode::FORBIDDEN, "actor mismatch"),
        Err(InboxError::Limit(_)) => plain(StatusCode::TOO_MANY_REQUESTS, "limit reached"),
        Err(InboxError::Signature(_)) => plain(StatusCode::UNAUTHORIZED, "signature error"),
        Err(InboxError::Storage(e)) => {
            tracing::error!(error = %e, "inbox storage failure");
            plain(StatusCode::INTERNAL_SERVER_ERROR, "storage failure")
        }
    }
}

/// Activity types the owner may post. Everything else (for instance `Undo`,
/// `Accept`, `Block`) is refused rather than broadcast to followers, which
/// is not what those mean.
const OUTBOX_TYPES: &[&str] = &[
    "Note", "Create", "Follow", "Update", "Delete", "Announce", "Like",
];

/// `POST /profile/card.jsonld/outbox`: the pod owner posts an activity.
///
/// Authorised only by a NIP-98 token bound to this exact body whose signer
/// holds `acl:Control` on the pod root (the owner gate the export route
/// uses): `401` anonymous, `403` anyone else. The activity's `actor` is
/// always the pod's own, and a `Follow` target's inbox is read from the
/// target's actor document through the guarded, bounded fetch, never taken
/// from the request.
pub(crate) async fn handle_outbox_post(
    req: HttpRequest,
    payload: web::Payload,
    state: web::Data<crate::AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(fed) = federation(&state) else {
        return Ok(HttpResponse::NotFound().finish());
    };
    let body = match read_capped(&req, payload, MAX_ACTIVITY_BYTES).await {
        Ok(b) => b,
        Err((status, msg)) => return Ok(plain(status, msg)),
    };
    let agent = crate::agent_uri(
        crate::extract_pubkey_with_body(&req, Some(&body))
            .await
            .as_ref(),
    );
    crate::enforce_write_ctx(
        &state,
        "/",
        crate::AccessMode::Control,
        agent.as_deref(),
        crate::req_origin(&req),
    )
    .await?;

    let Ok(mut activity) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Ok(plain(StatusCode::BAD_REQUEST, "invalid JSON"));
    };
    let Some(object) = activity.as_object_mut() else {
        return Ok(plain(
            StatusCode::BAD_REQUEST,
            "activity must be a JSON object",
        ));
    };
    object.remove("targetInbox");
    let kind = object.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let implicit_note = kind.is_empty() && object.contains_key("content");
    if !implicit_note && !OUTBOX_TYPES.contains(&kind) {
        return Ok(plain(StatusCode::BAD_REQUEST, "unsupported activity type"));
    }
    if kind == "Follow" {
        let Some(target) = object
            .get("object")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            return Ok(plain(StatusCode::BAD_REQUEST, "Follow needs an object URL"));
        };
        let inbox = match fed.resolver.fetch_document(&target).await {
            Ok(doc) => doc
                .get("inbox")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            Err(e) => {
                tracing::info!(error = %e, "follow target not fetchable");
                return Ok(plain(
                    StatusCode::BAD_GATEWAY,
                    "cannot fetch the target actor",
                ));
            }
        };
        let Some(inbox) = inbox else {
            return Ok(plain(StatusCode::BAD_GATEWAY, "target actor has no inbox"));
        };
        object.insert("targetInbox".into(), serde_json::Value::String(inbox));
    }

    match handle_outbox_post_lib(&fed.store, &fed.actor, activity).await {
        Ok(d) => {
            let location = d
                .activity
                .pointer("/object/id")
                .and_then(|v| v.as_str())
                .unwrap_or(&d.activity_id)
                .to_string();
            Ok(HttpResponse::Created()
                .content_type(AP_TYPE)
                .insert_header((header::LOCATION, location))
                .body(d.activity.to_string()))
        }
        Err(OutboxError::InvalidActivity(m)) => Ok(plain(StatusCode::BAD_REQUEST, &m)),
        Err(e) => {
            tracing::error!(error = %e, "outbox failure");
            Ok(plain(StatusCode::INTERNAL_SERVER_ERROR, "outbox failure"))
        }
    }
}

/// `GET /profile/card.jsonld/outbox`: the newest public `Create` activities.
pub(crate) async fn handle_outbox_get(state: web::Data<crate::AppState>) -> HttpResponse {
    let Some(fed) = federation(&state) else {
        return HttpResponse::NotFound().finish();
    };
    let rows = match fed.store.recent_outbox(&fed.actor.id, 200).await {
        Ok(r) => r,
        Err(_) => return plain(StatusCode::INTERNAL_SERVER_ERROR, "storage failure"),
    };
    let is_public = |a: &serde_json::Value| {
        ["to", "cc"].iter().any(|k| match a.get(*k) {
            Some(serde_json::Value::Array(xs)) => xs.iter().any(|x| x == AS_PUBLIC),
            Some(serde_json::Value::String(x)) => x == AS_PUBLIC,
            _ => false,
        })
    };
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| r.activity)
        .filter(|a| a.get("type").and_then(|t| t.as_str()) == Some("Create") && is_public(a))
        .take(PAGE_LIMIT as usize)
        .collect();
    ap_json(
        StatusCode::OK,
        &serde_json::json!({
            "@context": AS_CONTEXT,
            "type": "OrderedCollection",
            "id": fed.actor.outbox,
            "totalItems": items.len(),
            "orderedItems": items,
        }),
    )
}

/// `GET /profile/card.jsonld/followers` and `.../following`.
pub(crate) async fn handle_collection(
    state: web::Data<crate::AppState>,
    followers: bool,
) -> HttpResponse {
    let Some(fed) = federation(&state) else {
        return HttpResponse::NotFound().finish();
    };
    let id = &fed.actor.id;
    let listed = if followers {
        let items = fed.store.list_followers(id, PAGE_LIMIT).await;
        let total = fed.store.follower_count(id).await;
        items.and_then(|i| total.map(|t| (i, t)))
    } else {
        let items = fed.store.list_following(id, PAGE_LIMIT).await;
        let total = fed.store.following_count(id).await;
        items.and_then(|i| total.map(|t| (i, t)))
    };
    let Ok((items, total)) = listed else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "storage failure");
    };
    ap_json(
        StatusCode::OK,
        &serde_json::json!({
            "@context": AS_CONTEXT,
            "type": "OrderedCollection",
            "id": if followers { &fed.actor.followers } else { &fed.actor.following },
            "totalItems": total,
            "orderedItems": items,
        }),
    )
}

pub(crate) async fn handle_followers(state: web::Data<crate::AppState>) -> HttpResponse {
    handle_collection(state, true).await
}

pub(crate) async fn handle_following(state: web::Data<crate::AppState>) -> HttpResponse {
    handle_collection(state, false).await
}

impl Federation {
    /// The WebFinger `self` link for the actor, or `None` when `resource`
    /// does not name this actor (`acct:<username>@<host>` or the actor or
    /// profile URL).
    #[must_use]
    pub fn webfinger_actor_link(
        &self,
        resource: &str,
    ) -> Option<solid_pod_rs::interop::WebFingerLink> {
        let acct = format!("acct:{}@{}", self.actor.preferred_username, self.authority);
        let ours = resource.eq_ignore_ascii_case(&acct)
            || resource == self.actor.id
            || resource == self.profile();
        ours.then(|| solid_pod_rs::interop::WebFingerLink {
            rel: "self".into(),
            href: Some(self.actor.id.clone()),
            content_type: Some(AP_TYPE.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "abcd000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn jss_defaults() {
        let c = ApConfig::from_knobs(None, None, None, None, "PEM".into()).unwrap();
        assert_eq!(c.username, "me");
        assert_eq!(c.display_name, "Anonymous");
        let j = c.actor_json("https://pod.example");
        assert_eq!(j["preferredUsername"], "me");
        assert_eq!(j["name"], "Anonymous");
        assert_eq!(j["summary"], "");
        assert!(j.get("alsoKnownAs").is_none());
        assert_eq!(j["id"], "https://pod.example/profile/card.jsonld#me");
    }

    #[test]
    fn display_name_falls_back_to_given_username() {
        let c = ApConfig::from_knobs(Some("alice"), None, None, None, "P".into()).unwrap();
        assert_eq!(c.display_name, "alice");
    }

    #[test]
    fn nostr_pubkey_links_also_known_as_and_summary_is_escaped() {
        let c = ApConfig::from_knobs(
            Some("alice"),
            Some("Alice"),
            Some("hi <script>x</script> & co"),
            Some(&PK.to_uppercase()),
            "P".into(),
        )
        .unwrap();
        let j = c.actor_json("https://pod.example");
        assert_eq!(j["alsoKnownAs"][0], format!("did:nostr:{PK}"));
        assert_eq!(
            j["summary"],
            "<p>hi &lt;script&gt;x&lt;/script&gt; &amp; co</p>"
        );
    }

    #[test]
    fn bad_knobs_are_rejected() {
        assert!(ApConfig::from_knobs(Some("a b"), None, None, None, "P".into()).is_err());
        assert!(ApConfig::from_knobs(Some("a/../b"), None, None, None, "P".into()).is_err());
        assert!(ApConfig::from_knobs(None, None, None, Some("nothex"), "P".into()).is_err());
    }

    #[test]
    fn keypair_persists_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_public_key(Some(dir.path())).unwrap();
        let b = load_or_create_public_key(Some(dir.path())).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("BEGIN PUBLIC KEY"));
    }

    /// L8: an empty `keys.json` (a crash under the old writer) is replaced
    /// rather than failing every boot.
    #[test]
    fn empty_key_file_is_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".ap")).unwrap();
        std::fs::write(dir.path().join(".ap/keys.json"), b"").unwrap();
        let pem = load_or_create_public_key(Some(dir.path())).unwrap();
        assert!(pem.contains("PUBLIC KEY"));
        assert_eq!(load_or_create_public_key(Some(dir.path())).unwrap(), pem);
    }

    /// L8: processes (threads here) starting together settle on one key and
    /// leave no temp files behind.
    #[test]
    fn racing_creators_agree_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let r = root.clone();
                std::thread::spawn(move || load_or_create_public_key(Some(&r)).unwrap())
            })
            .collect();
        let keys: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]), "one key for all");
        let names: Vec<_> = std::fs::read_dir(dir.path().join(".ap"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["keys.json".to_string()], "no temp files left");
    }
}
