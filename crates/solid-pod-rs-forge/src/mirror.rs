//! Mirror repositories on their agent's NIP-34 kind-30618 state.
//!
//! `git mark announce` (the gitmark CLI) publishes a kind-30618 *repository
//! state* after every mark: `d` is the repository name, `HEAD` the symbolic
//! head, one `refs/heads/<branch>` tag per branch carries its commit, and
//! the latest mark rides along as `chain`, `txo` and `commit` tags. The
//! event is replaceable, so the newest one from the agent's key says where
//! the repository is now. A forge that *follows* that key pulls when the
//! state changes, instead of polling: one small event per announce, one
//! `git fetch` per real change.
//!
//! A branch moves only to a commit the fetch brought and, when the state
//! carries a mark, whose `blocktrails.json` lists the marked commit. The
//! forge talks to relays and git remotes only; the mark itself is checked
//! by the reader against the chain, never here.
//!
//! The module is **off unless configured** (feature `mirror`, then a
//! [`MirrorConfig`] that names relays and followed repositories). It follows
//! the behaviour of the JSS `forge` plugin's mirror (`parseMirrorConfig`,
//! `verifyEvent`, `readState`, `readClones`, `planMirror`, `trailLists`,
//! `branchVerdict`, and the plugin's mirror driver) by function name only;
//! the code is original.
//!
//! # Layers
//!
//! 1. **Pure decisions** (no I/O): [`parse_mirror_config`],
//!    [`followed_entry`], [`verify_event`], [`read_state`], [`read_clones`],
//!    [`plan_mirror`], [`trail_lists`], [`branch_verdict`].
//! 2. **The engine**: [`Mirror`] applies one verified event to one followed
//!    repository through the [`MirrorGit`] seam (so it is tested with fakes
//!    and with a real git), serialises work per repository, and keeps a
//!    [`MirrorRecord`] in a [`MirrorStore`].
//! 3. **Transport**: [`GitCli`] is the `git` adapter (argv only, hardened
//!    environment), and [`Mirror::start`] runs one relay session per relay
//!    with a reconnect backoff that resets when a relay *answers*.
//!
//! # Security posture
//!
//! * Relay URLs, repository names, clone URLs and ref names are validated
//!   before they reach a socket or a `git` command line; `git` is spawned
//!   with an argv, never a shell, and option injection is refused.
//! * A clone URL learnt from a remote kind-30617 must be `http(s)`; only an
//!   operator-configured clone may be `file://`.
//! * Relay and remote clone hosts pass the injected
//!   [`SsrfCheck`] (the workspace default refuses private, loopback and
//!   metadata space) before any connection. `git` and the websocket client
//!   resolve names themselves, so the check narrows but cannot pin the
//!   connection (a residual DNS-rebinding window).
//! * Inbound frames are size-bounded, signatures are BIP-340 verified by
//!   [`solid_pod_rs_nostr::Event::verify`], and fetches are rate-limited per
//!   repository by [`MirrorConfig::min_interval_ms`].
//!
//! # Example
//!
//! ```
//! use serde_json::json;
//! use solid_pod_rs_forge::mirror::parse_mirror_config;
//!
//! let pubkey = "a".repeat(64);
//! let cfg = parse_mirror_config(&json!({
//!     "relays": ["wss://relay.example", "http://not-a-relay"],
//!     "follow": [{ "pubkey": pubkey, "name": "agent" }],
//! }))
//! .expect("a relay and a followed repository turn the mirror on");
//! assert_eq!(cfg.relays, vec!["wss://relay.example".to_string()]);
//! assert_eq!(cfg.min_interval_ms, 30_000);
//! assert!(parse_mirror_config(&json!({})).is_none());
//! ```

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solid_pod_rs_nostr::{DefaultSsrfCheck, Event, SsrfCheck};
use tokio::sync::{watch, Mutex};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::ownership::valid_name_segment;
use crate::sizecap::dir_size;

/// NIP-34 repository announcement kind.
pub const KIND_ANNOUNCE: u64 = 30617;
/// NIP-34 repository state kind.
pub const KIND_STATE: u64 = 30618;
/// How far ahead of the local clock a state's `created_at` may be, in seconds.
pub const MAX_FUTURE_SKEW_SECS: u64 = 600;
/// Most followed `(pubkey, name)` pairs one forge will mirror.
pub const MAX_FOLLOW: usize = 50;
/// Default floor between two fetches of one repository, in milliseconds.
pub const MIN_FETCH_INTERVAL_MS: u64 = 30_000;
/// Largest relay frame accepted, in bytes. Larger frames drop the session.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
/// Most tags an inbound event may carry before it is ignored.
pub const MAX_EVENT_TAGS: usize = 512;
/// Largest `blocktrails.json` read from a fetched commit, in bytes.
pub const MAX_TRAIL_BYTES: u64 = 1024 * 1024;
/// Wall-clock budget for one `git fetch`.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest a mirrored repository may grow on disk, in bytes. A fetch that
/// pushes it past this is killed and its refs and objects dropped.
pub const MAX_REPO_BYTES: u64 = 512 * 1024 * 1024;
/// Fetches that may run at once across all followed repositories.
pub const MAX_CONCURRENT_FETCHES: usize = 4;
/// Longest the failure backoff stretches the fetch floor to, in milliseconds.
pub const MAX_BACKOFF_MS: u64 = 3_600_000;
/// The relay subscription id this module uses.
pub const SUBSCRIPTION_ID: &str = "forge-mirror";
/// The trail document a marked commit must list.
pub const TRAIL_FILE: &str = "blocktrails.json";

// ---------------------------------------------------------------------------
// Validation helpers (pure)
// ---------------------------------------------------------------------------

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_sha40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A followed repository name: starts alphanumeric, then `[A-Za-z0-9._-]`,
/// at most 100 bytes, and safe as a single path segment.
fn is_repo_name(s: &str) -> bool {
    let first_ok = s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    first_ok && valid_name_segment(s)
}

/// A relay URL: `ws://` or `wss://`, no whitespace, `;`, `'` or `"`.
fn is_relay_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("ws://") || lower.starts_with("wss://"))
        && s.len() > 6
        && !s
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, ';' | '\'' | '"'))
}

fn clean_url_chars(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ';' | '\'' | '"'))
}

/// A clone URL the *operator* may configure: `http`, `https` or `file`.
fn is_operator_clone(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("file://"))
        && clean_url_chars(s)
}

/// A clone URL a *remote* event may supply: `http` or `https` only.
fn is_remote_clone(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && s.len() > 8
        && clean_url_chars(s)
}

/// A remote clone URL in the form git is given: `http`/`https` only, no
/// userinfo, no backslash or non-ASCII (the `url` crate and libcurl can read
/// those differently), a host present. Returns the *normalised* URL together
/// with the host, port and default-port so the caller can pin DNS to it.
fn normalise_remote_clone(s: &str) -> Option<(String, String, u16)> {
    if !is_remote_clone(s) || !s.is_ascii() || s.contains('\\') {
        return None;
    }
    let u = url::Url::parse(s).ok()?;
    if !matches!(u.scheme(), "http" | "https")
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return None;
    }
    let host = u.host_str()?.to_string();
    let port = u.port_or_known_default()?;
    Some((u.as_str().to_string(), host, port))
}

/// The floor between fetches after `failures` consecutive failures: the
/// configured floor, doubled for each, capped at [`MAX_BACKOFF_MS`].
#[must_use]
pub fn backoff_interval(base_ms: u64, failures: u32) -> u64 {
    base_ms
        .saturating_mul(1u64 << failures.min(10))
        .min(MAX_BACKOFF_MS.max(base_ms))
}

/// A branch ref: `refs/heads/` plus a conservative name. Stricter than
/// git's own rules in the ways that matter: no `..`, `//`, `@{`, trailing
/// `/`, `.lock` or dot-leading component, and nothing outside
/// `[A-Za-z0-9._/-]`.
fn is_branch_ref(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("refs/heads/") else {
        return false;
    };
    if rest.is_empty() || rest.len() > 200 || rest.contains("..") || rest.contains("//") {
        return false;
    }
    if rest.ends_with('/') || rest.ends_with(".lock") || rest.ends_with('.') {
        return false;
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
    {
        return false;
    }
    if !rest
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric())
    {
        return false;
    }
    rest.split('/')
        .all(|seg| !seg.starts_with('.') && !seg.ends_with(".lock"))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// One followed repository: the agent key that signs the state and the `d`
/// tag it uses. Keyed by the pair, never by the name alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowEntry {
    /// Agent public key, 64 lowercase hex characters.
    pub pubkey: String,
    /// Repository name (the state's `d` tag).
    pub name: String,
    /// Operator-configured clone URL, if any. Otherwise the newest
    /// kind-30617 from the same key supplies one.
    pub clone: Option<String>,
}

/// A parsed mirror configuration. Absent means the mirror is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorConfig {
    /// Relays to subscribe on (`ws://` or `wss://`).
    pub relays: Vec<String>,
    /// Followed repositories, at most [`MAX_FOLLOW`].
    pub follow: Vec<FollowEntry>,
    /// Floor between two fetches of one repository, in milliseconds.
    pub min_interval_ms: u64,
}

/// Parse the `mirror` configuration object. Returns `None` (the mirror is
/// off) unless at least one valid relay and one well-formed follow entry
/// survive. Malformed relays and entries are dropped, duplicates collapse,
/// a clone URL with a disallowed scheme is dropped while the entry is kept,
/// and the list is capped at [`MAX_FOLLOW`].
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use solid_pod_rs_forge::mirror::parse_mirror_config;
///
/// let pk = "b".repeat(64);
/// let cfg = parse_mirror_config(&json!({
///     "relays": ["wss://r.example"],
///     "follow": [
///         { "pubkey": pk.to_uppercase(), "name": "x", "clone": "https://e.org/x.git" },
///         { "pubkey": pk, "name": "x" },                  // duplicate
///         { "pubkey": pk, "name": "../etc" },             // bad name
///         { "pubkey": pk, "name": "z", "clone": "ssh://nope" },
///     ],
///     "minIntervalMs": 0,
/// }))
/// .unwrap();
/// assert_eq!(cfg.follow.len(), 2);
/// assert_eq!(cfg.follow[1].clone, None);
/// assert_eq!(cfg.min_interval_ms, 0);
/// ```
#[must_use]
pub fn parse_mirror_config(cfg: &Value) -> Option<MirrorConfig> {
    let obj = cfg.as_object()?;
    let relays: Vec<String> = obj
        .get("relays")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter(|r| is_relay_url(r))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut follow: Vec<FollowEntry> = Vec::new();
    for f in obj
        .get("follow")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(f) = f.as_object() else { continue };
        let pubkey = f
            .get("pubkey")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let name = f.get("name").and_then(Value::as_str).unwrap_or_default();
        if !is_hex64(&pubkey) || !is_repo_name(name) {
            continue;
        }
        let clone = f
            .get("clone")
            .and_then(Value::as_str)
            .filter(|c| is_operator_clone(c))
            .map(str::to_string);
        if !follow.iter().any(|x| x.pubkey == pubkey && x.name == name) {
            follow.push(FollowEntry {
                pubkey,
                name: name.to_string(),
                clone,
            });
        }
        if follow.len() >= MAX_FOLLOW {
            break;
        }
    }
    if relays.is_empty() || follow.is_empty() {
        return None;
    }
    let min_interval_ms = obj
        .get("minIntervalMs")
        .and_then(Value::as_u64)
        .unwrap_or(MIN_FETCH_INTERVAL_MS);
    Some(MirrorConfig {
        relays,
        follow,
        min_interval_ms,
    })
}

/// The followed entry a `(pubkey, d)` pair names, or `None`. Never matches
/// on the name alone.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::{followed_entry, FollowEntry};
///
/// let pk = "c".repeat(64);
/// let follow = vec![FollowEntry { pubkey: pk.clone(), name: "x".into(), clone: None }];
/// assert!(followed_entry(&follow, &pk, "x").is_some());
/// assert!(followed_entry(&follow, &"d".repeat(64), "x").is_none());
/// assert!(followed_entry(&follow, &pk, "y").is_none());
/// ```
#[must_use]
pub fn followed_entry<'a>(
    follow: &'a [FollowEntry],
    pubkey: &str,
    d: &str,
) -> Option<&'a FollowEntry> {
    follow.iter().find(|f| f.pubkey == pubkey && f.name == d)
}

// ---------------------------------------------------------------------------
// Events (pure)
// ---------------------------------------------------------------------------

/// NIP-01 check: the id is the hash of the canonical form and the
/// signature is a valid BIP-340 Schnorr signature over it. The check is
/// [`Event::verify`] (the workspace's single implementation); on top of it
/// the event must carry a lowercase 64-hex id and pubkey, and no more than
/// [`MAX_EVENT_TAGS`] tags.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::verify_event;
/// use solid_pod_rs_nostr::Event;
///
/// let forged = Event {
///     id: "0".repeat(64),
///     pubkey: "1".repeat(64),
///     created_at: 1,
///     kind: 30618,
///     tags: vec![],
///     content: String::new(),
///     sig: "f".repeat(128),
/// };
/// assert!(!verify_event(&forged));
/// ```
#[must_use]
pub fn verify_event(ev: &Event) -> bool {
    is_hex64(&ev.id)
        && is_hex64(&ev.pubkey)
        && ev.tags.len() <= MAX_EVENT_TAGS
        && ev.verify().is_ok()
}

fn tag_value<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    ev.tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some(name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// The mark a state carries: the latest on-chain anchor of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorMark {
    /// Chain name from the `chain` tag (for example `txbt4`).
    pub chain: String,
    /// TXO URI from the `txo` tag.
    pub txo: String,
    /// The marked commit (40 lowercase hex) from the `commit` tag.
    pub commit: String,
}

/// What a kind-30618 event says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    /// The `d` tag.
    pub d: String,
    /// Symbolic `HEAD` (`refs/heads/<branch>`), if declared and valid.
    pub head: Option<String>,
    /// Every well-formed branch ref with its full sha.
    pub refs: BTreeMap<String, String>,
    /// The mark, only when all of `chain`, `txo` and `commit` are present.
    pub mark: Option<MirrorMark>,
    /// The event's `created_at` (seconds).
    pub created_at: u64,
    /// The event id.
    pub id: String,
}

/// Read a kind-30618 event: its `d`, the symbolic `HEAD`, every
/// well-formed branch ref (`refs/heads/*` with a 40-hex sha; anything else,
/// such as `refs/tags/*` or a short sha, is ignored) and the mark when all
/// three mark tags are present. `None` when there is no `d` tag.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::read_state;
/// use solid_pod_rs_nostr::Event;
///
/// let sha = "a".repeat(40);
/// let ev = Event {
///     id: "0".repeat(64), pubkey: "1".repeat(64), created_at: 7, kind: 30618,
///     tags: vec![
///         vec!["d".into(), "x".into()],
///         vec!["HEAD".into(), "ref: refs/heads/main".into()],
///         vec!["refs/heads/main".into(), sha.clone()],
///         vec!["refs/heads/dev".into(), "short".into()],
///     ],
///     content: String::new(), sig: String::new(),
/// };
/// let st = read_state(&ev).unwrap();
/// assert_eq!(st.head.as_deref(), Some("refs/heads/main"));
/// assert_eq!(st.refs.len(), 1);
/// assert!(st.mark.is_none());
/// ```
#[must_use]
pub fn read_state(ev: &Event) -> Option<RepoState> {
    let d = tag_value(ev, "d")?.to_string();
    let mut refs = BTreeMap::new();
    for t in &ev.tags {
        let (Some(name), Some(sha)) = (t.first(), t.get(1)) else {
            continue;
        };
        let sha = sha.to_ascii_lowercase();
        if is_branch_ref(name) && is_sha40(&sha) {
            refs.insert(name.clone(), sha);
        }
    }
    let head = tag_value(ev, "HEAD")
        .and_then(|h| h.strip_prefix("ref: "))
        .filter(|h| is_branch_ref(h))
        .map(str::to_string);
    let (chain, txo, commit) = (
        tag_value(ev, "chain"),
        tag_value(ev, "txo"),
        tag_value(ev, "commit").map(str::to_ascii_lowercase),
    );
    let mark = match (
        chain.filter(|c| !c.is_empty()),
        txo.filter(|c| !c.is_empty()),
        commit.clone(),
    ) {
        (Some(chain), Some(txo), Some(commit)) if is_sha40(&commit) => Some(MirrorMark {
            chain: chain.to_string(),
            txo: txo.to_string(),
            commit,
        }),
        _ => None,
    };
    // A state that tries to carry a mark but gets it wrong is not "a state
    // with no mark": reading it that way would let a garbled `commit` tag
    // switch the trail check off. It is unusable, so nothing moves.
    if mark.is_none() && (chain.is_some() || txo.is_some() || commit.is_some()) {
        return None;
    }
    Some(RepoState {
        d,
        head,
        refs,
        mark,
        created_at: ev.created_at,
        id: ev.id.clone(),
    })
}

/// The clone URLs a kind-30617 offers, in order, `http(s)` only. A
/// `file://` or `ssh` URL from a remote event is never accepted.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::read_clones;
/// use solid_pod_rs_nostr::Event;
///
/// let ev = Event {
///     id: "0".repeat(64), pubkey: "1".repeat(64), created_at: 1, kind: 30617,
///     tags: vec![
///         vec!["clone".into(), "https://a.example/x.git".into(), "git@a.example:x.git".into()],
///         vec!["clone".into(), "file:///tmp/x".into()],
///         vec!["clone".into(), "http://b.example/x.git".into()],
///     ],
///     content: String::new(), sig: String::new(),
/// };
/// assert_eq!(read_clones(&ev), ["https://a.example/x.git", "http://b.example/x.git"]);
/// ```
#[must_use]
pub fn read_clones(ev: &Event) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in &ev.tags {
        if t.first().map(String::as_str) != Some("clone") {
            continue;
        }
        for u in t.iter().skip(1) {
            if is_remote_clone(u) && !out.contains(u) {
                out.push(u.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Plan and verdict (pure)
// ---------------------------------------------------------------------------

/// Whether to fetch for a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanAction {
    /// Run a `git fetch`.
    Fetch,
    /// Do nothing for this state.
    Skip,
}

/// The decision for one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorPlan {
    /// Fetch or skip.
    pub action: PlanAction,
    /// A human-readable reason, stored in the record.
    pub reason: String,
    /// The branches the state would move: `(ref, sha)` pairs.
    pub changed: Vec<(String, String)>,
}

/// Inputs to [`plan_mirror`].
#[derive(Debug, Clone)]
pub struct PlanInput<'a> {
    /// The parsed state, or `None` when the event was not a state.
    pub state: Option<&'a RepoState>,
    /// `refs/heads/<b>` to sha the mirror has now.
    pub local: &'a BTreeMap<String, String>,
    /// `created_at` (seconds) of the last state acted on; `0` for none.
    pub last_seen_at: u64,
    /// Millisecond clock of the last fetch; `0` for none.
    pub last_fetch_at: u64,
    /// Millisecond clock now.
    pub now: u64,
    /// Floor between two fetches, in milliseconds.
    pub min_interval_ms: u64,
}

/// Whether to fetch for a state, and which branches it would move. Skips
/// a state that is not newer than the last one acted on, one that names no
/// branch, one the mirror already matches, and one inside the rate limit.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use solid_pod_rs_forge::mirror::{plan_mirror, PlanAction, PlanInput, RepoState};
///
/// let (a, b) = ("a".repeat(40), "b".repeat(40));
/// let state = RepoState {
///     d: "x".into(), head: None, mark: None, created_at: 100, id: String::new(),
///     refs: BTreeMap::from([("refs/heads/main".to_string(), b.clone())]),
/// };
/// let local = BTreeMap::from([("refs/heads/main".to_string(), a)]);
/// let plan = plan_mirror(&PlanInput {
///     state: Some(&state), local: &local, last_seen_at: 0, last_fetch_at: 0,
///     now: 1_000_000, min_interval_ms: 30_000,
/// });
/// assert_eq!(plan.action, PlanAction::Fetch);
/// assert_eq!(plan.changed, vec![("refs/heads/main".to_string(), b)]);
/// ```
#[must_use]
pub fn plan_mirror(input: &PlanInput<'_>) -> MirrorPlan {
    let skip = |reason: &str, changed: Vec<(String, String)>| MirrorPlan {
        action: PlanAction::Skip,
        reason: reason.to_string(),
        changed,
    };
    let Some(state) = input.state else {
        return skip("not a repository state", Vec::new());
    };
    if state.created_at <= input.last_seen_at {
        return skip("not newer than the last state acted on", Vec::new());
    }
    let changed: Vec<(String, String)> = state
        .refs
        .iter()
        .filter(|(r, sha)| input.local.get(*r) != Some(*sha))
        .map(|(r, sha)| (r.clone(), sha.clone()))
        .collect();
    if state.refs.is_empty() {
        return skip("the state names no branch", Vec::new());
    }
    if changed.is_empty() {
        return skip("already at this state", Vec::new());
    }
    let since = input.now.saturating_sub(input.last_fetch_at);
    if since < input.min_interval_ms {
        let wait = input.min_interval_ms - since;
        return skip(
            &format!(
                "fetched {} s ago; next in {} s",
                (since + 500) / 1000,
                wait.div_ceil(1000)
            ),
            changed,
        );
    }
    let n = changed.len();
    MirrorPlan {
        action: PlanAction::Fetch,
        reason: format!("{n} branch{} moved", if n == 1 { "" } else { "es" }),
        changed,
    }
}

/// Does a gitmark trail document list this commit among its states? False
/// for anything that is not a `profile: "gitmark"` document with a `states`
/// array.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::trail_lists;
///
/// let c = "a".repeat(40);
/// let doc = format!(r#"{{"profile":"gitmark","states":["{c}"]}}"#);
/// assert!(trail_lists(&doc, &c));
/// assert!(!trail_lists("not json", &c));
/// ```
#[must_use]
pub fn trail_lists(raw: &str, commit: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    if doc.get("profile").and_then(Value::as_str) != Some("gitmark") {
        return false;
    }
    doc.get("states")
        .and_then(Value::as_array)
        .is_some_and(|s| {
            s.iter()
                .filter_map(Value::as_str)
                .any(|x| x.eq_ignore_ascii_case(commit))
        })
}

/// Whether a committed trail belongs to `pubkey`: its `pubkeyBase` (a
/// compressed point, `02`/`03` plus x, or a bare x) has the agent's x-only
/// key. Without this a trail copied from anyone else's repository, listing
/// the marked commit, would satisfy [`trail_lists`].
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::trail_key_matches;
///
/// let x = "ab".repeat(32);
/// let doc = format!(r#"{{"profile":"gitmark","pubkeyBase":"02{x}"}}"#);
/// assert!(trail_key_matches(&doc, &x));
/// assert!(!trail_key_matches(&doc, &"cd".repeat(32)));
/// assert!(!trail_key_matches(r#"{"profile":"gitmark"}"#, &x));
/// ```
#[must_use]
pub fn trail_key_matches(raw: &str, pubkey: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    let Some(base) = doc.get("pubkeyBase").and_then(Value::as_str) else {
        return false;
    };
    let x = match base.len() {
        66 if base.starts_with("02") || base.starts_with("03") => &base[2..],
        64 => base,
        _ => return false,
    };
    x.eq_ignore_ascii_case(pubkey)
}

/// The verdict for one branch after the fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchVerdict {
    /// Whether the branch moves to the state's commit.
    #[serde(rename = "moved")]
    pub move_branch: bool,
    /// Why, in words.
    pub verdict: String,
}

/// The verdict for one branch: an unfetched commit never moves; with no
/// mark the fetched commit moves; with a mark the trail at the commit must
/// exist, belong to `pubkey` and list the marked commit, and the marked
/// commit must be reachable from the commit the state names. The chain is
/// not consulted: this says "the agent's own file lists the mark", not that
/// the mark is on-chain.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::{branch_verdict, MirrorMark};
///
/// let key = "ab".repeat(32);
/// assert!(!branch_verdict(false, None, None, &key, true).move_branch);
/// assert!(branch_verdict(true, None, None, &key, true).move_branch);
/// let mark = MirrorMark { chain: "txbt4".into(), txo: "txo:x".into(), commit: "a".repeat(40) };
/// assert!(!branch_verdict(true, Some(&mark), None, &key, true).move_branch);
/// ```
#[must_use]
pub fn branch_verdict(
    fetched: bool,
    mark: Option<&MirrorMark>,
    trail: Option<&str>,
    pubkey: &str,
    mark_reachable: bool,
) -> BranchVerdict {
    let v = |m: bool, s: String| BranchVerdict {
        move_branch: m,
        verdict: s,
    };
    if !fetched {
        return v(
            false,
            "the remote does not have the commit the state names".into(),
        );
    }
    let Some(mark) = mark else {
        return v(true, "fetched; the state carries no mark".into());
    };
    let short = &mark.commit[..8.min(mark.commit.len())];
    match trail {
        None => v(
            false,
            "the state carries a mark but the commit has no trail file".into(),
        ),
        Some(t) if !trail_lists(t, &mark.commit) => v(
            false,
            format!("the trail at the commit does not list the marked commit {short}"),
        ),
        Some(t) if !trail_key_matches(t, pubkey) => v(
            false,
            "the trail at the commit is not the followed agent's (its pubkeyBase differs)".into(),
        ),
        Some(_) if !mark_reachable => v(
            false,
            format!("the marked commit {short} is not in the history of the commit the state names"),
        ),
        Some(_) => v(
            true,
            format!(
                "fetched; the agent's committed trail lists mark {short} on {} (the chain itself is not checked)",
                mark.chain
            ),
        ),
    }
}

/// Reconnect delay after `attempt` consecutive failures: one second
/// doubling to a minute.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use solid_pod_rs_forge::mirror::backoff_delay;
///
/// assert_eq!(backoff_delay(0), Duration::from_secs(1));
/// assert_eq!(backoff_delay(3), Duration::from_secs(8));
/// assert_eq!(backoff_delay(40), Duration::from_secs(60));
/// ```
#[must_use]
pub fn backoff_delay(attempt: u32) -> Duration {
    Duration::from_millis((1000u64 << attempt.min(6)).min(60_000))
}

/// What one relay frame means for the mirror.
#[derive(Debug, Default)]
pub struct RelayFrame {
    /// The relay answered the REQ (an `EOSE` or any `EVENT`): this
    /// connection counts, so the backoff starts over. Resetting on *open*
    /// would let a relay that accepts and drops be redialled every second.
    pub answered: bool,
    /// An event for [`SUBSCRIPTION_ID`], not yet verified.
    pub event: Option<Event>,
    /// A `CLOSED` or `NOTICE` text to log.
    pub notice: Option<String>,
}

/// Classify one inbound relay frame. Oversized or malformed frames yield
/// an empty [`RelayFrame`].
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::mirror::classify_relay_frame;
///
/// assert!(classify_relay_frame(r#"["EOSE","forge-mirror"]"#).answered);
/// let n = classify_relay_frame(r#"["NOTICE","slow down"]"#);
/// assert_eq!(n.notice.as_deref(), Some("NOTICE slow down"));
/// assert!(!classify_relay_frame("garbage").answered);
/// ```
#[must_use]
pub fn classify_relay_frame(text: &str) -> RelayFrame {
    let mut out = RelayFrame::default();
    if text.len() > MAX_FRAME_BYTES {
        return out;
    }
    let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(text) else {
        return out;
    };
    match msg.first().and_then(Value::as_str) {
        Some("EOSE") => out.answered = true,
        Some("EVENT") => {
            out.answered = true;
            if msg.get(1).and_then(Value::as_str) == Some(SUBSCRIPTION_ID) {
                out.event = msg
                    .get(2)
                    .and_then(|e| serde_json::from_value::<Event>(e.clone()).ok());
            }
        }
        Some(kind @ ("CLOSED" | "NOTICE")) => {
            let last = msg.last().and_then(Value::as_str).unwrap_or_default();
            out.notice = Some(format!("{kind} {last}"));
        }
        _ => {}
    }
    out
}

// ---------------------------------------------------------------------------
// Record and store
// ---------------------------------------------------------------------------

/// What the mirror did with the latest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeenAction {
    /// Nothing to do (or nothing possible); see the reason.
    Skip,
    /// The fetch failed.
    FetchFailed,
    /// At least one branch moved.
    Moved,
    /// Fetched, but no branch passed its verdict.
    Held,
}

/// The latest state seen for a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSeen {
    /// Event id.
    pub id: String,
    /// Event `created_at` (seconds).
    #[serde(rename = "created_at")]
    pub created_at: u64,
    /// Millisecond clock when the event was handled.
    pub at: u64,
    /// What happened.
    pub action: SeenAction,
    /// Why, in words.
    pub reason: String,
}

/// A reference to the last state acted on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRef {
    /// Event id.
    pub id: String,
    /// Event `created_at` (seconds).
    #[serde(rename = "created_at")]
    pub created_at: u64,
}

/// One branch's outcome in the last fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchOutcome {
    /// The sha the state named.
    pub sha: String,
    /// Whether the branch moved.
    pub moved: bool,
    /// Why, in words.
    pub verdict: String,
}

/// The last fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastFetch {
    /// Millisecond clock of the fetch.
    pub at: u64,
    /// The clone URL used.
    pub clone: String,
    /// Per-branch outcomes, keyed by ref.
    pub branches: BTreeMap<String, BranchOutcome>,
    /// How many branches moved.
    pub moved: usize,
    /// The mark the state carried, if any.
    pub mark: Option<MirrorMark>,
}

/// The durable record of one mirrored repository. Serialised to
/// `<plugin_dir>/mirror/<pubkey>/<name>.json` in camelCase, the shape the
/// JSS forge serves at `api/repos/<owner>/<name>/mirror`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorRecord {
    /// Agent key.
    pub pubkey: String,
    /// Repository name.
    pub name: String,
    /// Clone URL from the newest kind-30617 (or the configured one).
    pub clone: Option<String>,
    /// States counted for this repository.
    pub events: u64,
    /// The latest state seen.
    pub last_seen: Option<LastSeen>,
    /// The last state acted on (advances only after a fetch).
    pub last_event: Option<EventRef>,
    /// Millisecond clock of the last fetch attempt.
    pub last_fetch_at: Option<u64>,
    /// The last completed fetch.
    pub last_fetch: Option<LastFetch>,
    /// `created_at` of the newest kind-30617 used for the clone URL.
    pub announce_at: Option<u64>,
    /// Every clone URL the newest kind-30617 offered.
    #[serde(default)]
    pub clones: Vec<String>,
    /// `created_at` of the newest verified state seen, acted on or not. A
    /// state older than this is a replay and is dropped; one equal to it is
    /// the catch-up resend of a state that was rate-limited, and is kept.
    #[serde(default)]
    pub newest_seen_at: u64,
    /// Event id of the state that set [`Self::newest_seen_at`]. Two states with
    /// the same `created_at` are ordered by id (NIP-01: the lowest id wins), so
    /// a sibling that loses the tie-break is dropped.
    #[serde(default)]
    pub newest_seen_id: String,
    /// Consecutive failed fetches. The floor between fetches doubles for each,
    /// up to [`MAX_BACKOFF_MS`], and a success resets it.
    #[serde(default)]
    pub failures: u32,
    /// Millisecond clock at which a state held back by the rate limit is
    /// worth applying again, when one is waiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<u64>,
}

impl MirrorRecord {
    fn new(pubkey: &str, name: &str, clone: Option<String>) -> Self {
        Self {
            pubkey: pubkey.to_string(),
            name: name.to_string(),
            clone,
            events: 0,
            last_seen: None,
            last_event: None,
            last_fetch_at: None,
            last_fetch: None,
            announce_at: None,
            clones: Vec::new(),
            newest_seen_at: 0,
            newest_seen_id: String::new(),
            failures: 0,
            retry_at: None,
        }
    }
}

/// Reads and writes [`MirrorRecord`] files under a directory.
#[derive(Debug, Clone)]
pub struct MirrorStore {
    dir: PathBuf,
}

impl MirrorStore {
    /// A store rooted at `plugin_dir/mirror`.
    #[must_use]
    pub fn new(plugin_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: plugin_dir.as_ref().join("mirror"),
        }
    }

    fn file(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        Some(self.dir.join(owner).join(format!("{name}.json")))
    }

    /// The record for `(owner, name)`, or `None` when the repository is not
    /// a mirror or the file is unreadable.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::mirror::MirrorStore;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let store = MirrorStore::new(dir.path());
    /// assert!(store.read(&"a".repeat(64), "nobody").is_none());
    /// ```
    #[must_use]
    pub fn read(&self, owner: &str, name: &str) -> Option<MirrorRecord> {
        let bytes = std::fs::read(self.file(owner, name)?).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Save a record atomically (write a temporary file, then rename).
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidInput` when the owner or name is unsafe as
    /// a path segment.
    pub fn save(&self, rec: &MirrorRecord) -> std::io::Result<()> {
        let path = self.file(&rec.pubkey, &rec.name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe mirror key")
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(rec)?)?;
        std::fs::rename(tmp, path)
    }
}

// ---------------------------------------------------------------------------
// The git seam and the real adapter
// ---------------------------------------------------------------------------

/// The address a clone host was checked against, handed to git so it connects
/// to exactly that address instead of resolving the name again (closing the
/// DNS-rebinding window between the SSRF check and the fetch). Needs git 2.37
/// or later; an older git ignores the setting and the window stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClonePin {
    /// The host name in the URL.
    pub host: String,
    /// The port in effect (explicit, or the scheme's default).
    pub port: u16,
    /// The address the SSRF policy approved.
    pub ip: std::net::IpAddr,
}

/// The git operations the engine needs. [`GitCli`] is the real adapter;
/// tests substitute fakes. Every method takes the already-validated
/// `(owner, name)` pair; implementations must still treat the strings as
/// untrusted.
#[async_trait]
pub trait MirrorGit: Send + Sync {
    /// Whether a bare repository exists for `(owner, name)`.
    async fn exists(&self, owner: &str, name: &str) -> bool;
    /// `refs/heads/<b>` to sha for the mirror; empty when none.
    async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String>;
    /// Create the empty bare repository.
    ///
    /// # Errors
    ///
    /// A human-readable reason.
    async fn materialise(&self, owner: &str, name: &str) -> Result<(), String>;
    /// Fetch every branch of `clone` into `refs/mirror/*`. `operator` is
    /// `true` when the URL came from operator configuration (and so may be
    /// `file://`), `false` when a remote event supplied it.
    ///
    /// # Errors
    ///
    /// A human-readable reason (first line of git's stderr).
    async fn fetch(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
        pin: Option<&ClonePin>,
    ) -> Result<(), String>;
    /// Whether the commit is present after the fetch.
    async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool;
    /// Whether `ancestor` is `descendant` or in its history.
    async fn is_ancestor(&self, owner: &str, name: &str, ancestor: &str, descendant: &str) -> bool;
    /// The [`TRAIL_FILE`] at `sha`, if present and within [`MAX_TRAIL_BYTES`].
    async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String>;
    /// Point a branch ref at a commit.
    ///
    /// # Errors
    ///
    /// A human-readable reason.
    async fn update_ref(
        &self,
        owner: &str,
        name: &str,
        git_ref: &str,
        sha: &str,
    ) -> Result<(), String>;
    /// Point `HEAD` at a branch.
    ///
    /// # Errors
    ///
    /// A human-readable reason.
    async fn set_head(&self, owner: &str, name: &str, git_ref: &str) -> Result<(), String>;
}

/// A millisecond clock, injected so decisions are deterministic in tests.
pub trait MirrorClock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl MirrorClock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// The `git` command-line adapter. Bare repositories live at
/// `<repo_root>/<owner>/<name>.git`, the layout the forge already uses, so
/// a mirrored repository browses like any pushed one.
///
/// Every spawn goes through [`solid_pod_rs_git::hardened_git_async`] (no
/// hooks, no ambient config, no prompts) with an argv; the clone URL is
/// passed after `--`, and `GIT_ALLOW_PROTOCOL` restricts transports to
/// `http`/`https` (plus `file` only for an operator-configured clone).
/// Remote clones also refuse HTTP redirects.
#[derive(Debug, Clone)]
pub struct GitCli {
    repo_root: PathBuf,
}

impl GitCli {
    /// Keep `refs/mirror/*` out of what the forge serves. The fetch lands
    /// every branch of the remote there *before* any verdict, so advertising
    /// them would let a client fetch content the engine held back.
    async fn drop_mirror_refs_and_gc(&self, dir: &Path) {
        if let Ok(bytes) = self
            .run(
                dir,
                &["for-each-ref", "--format=%(refname)", "refs/mirror"],
                None,
                Duration::from_secs(15),
            )
            .await
        {
            for r in String::from_utf8_lossy(&bytes).lines() {
                let _ = self
                    .run(dir, &["update-ref", "-d", r], None, Duration::from_secs(15))
                    .await;
            }
        }
        let _ = self
            .run(
                dir,
                &["gc", "--quiet", "--prune=now"],
                None,
                Duration::from_secs(120),
            )
            .await;
    }

    async fn hide_mirror_refs(&self, dir: &Path) -> Result<(), String> {
        for key in ["uploadpack.hideRefs", "transfer.hideRefs"] {
            self.run(
                dir,
                &["config", "--replace-all", key, "refs/mirror"],
                None,
                Duration::from_secs(15),
            )
            .await?;
        }
        Ok(())
    }

    /// An adapter over `repo_root` (the forge's `plugin_dir/repos`).
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    fn dir(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        Some(self.repo_root.join(owner).join(format!("{name}.git")))
    }

    async fn run(
        &self,
        dir: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.run_capped(dir, args, allow, timeout, None).await
    }

    /// Run git in its own process group so a timeout or an over-size repo can
    /// take down the helpers it spawned (`git-remote-https`, `index-pack`) and
    /// not only `git` itself. With `cap`, the repository directory is polled
    /// while git runs and the group is killed when it grows past the cap.
    async fn run_capped(
        &self,
        dir: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
        cap: Option<u64>,
    ) -> Result<Vec<u8>, String> {
        self.run_capped_with(dir, args, allow, timeout, cap, dir_size)
            .await
    }

    /// [`Self::run_capped`] with the directory measurement injectable. The
    /// walk runs on its own task and only signals when the cap is passed, so a
    /// slow walk of a huge repository can neither stall the draining of git's
    /// pipes nor delay the deadline (security review L4).
    async fn run_capped_with(
        &self,
        dir: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
        cap: Option<u64>,
        measure: fn(&Path) -> u64,
    ) -> Result<Vec<u8>, String> {
        let mut cmd = solid_pod_rs_git::hardened_git_async();
        cmd.args(args)
            .current_dir(dir)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        if let Some(a) = allow {
            cmd.env("GIT_ALLOW_PROTOCOL", a);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("git could not start: {e}"))?;
        let pid = child.id();
        let waited = child.wait_with_output();
        tokio::pin!(waited);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let (tx, mut grew) = tokio::sync::oneshot::channel::<()>();
        let watcher = cap.map(|limit| {
            let d = dir.to_path_buf();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let d2 = d.clone();
                    let size = tokio::task::spawn_blocking(move || measure(&d2))
                        .await
                        .unwrap_or(0);
                    if size > limit {
                        let _ = tx.send(());
                        return;
                    }
                }
            })
        });
        let outcome = tokio::select! {
            out = &mut waited => Ok(out),
            () = &mut deadline => Err("git timed out".to_string()),
            Ok(()) = &mut grew => Err("repository grew past the size cap".to_string()),
        };
        if let Some(w) = watcher {
            w.abort();
        }
        let out = match outcome {
            Ok(out) => out.map_err(|e| format!("git failed: {e}"))?,
            Err(why) => {
                kill_group(pid).await;
                return Err(why);
            }
        };
        if out.status.success() {
            Ok(out.stdout)
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(err.lines().next().unwrap_or("git failed").to_string())
        }
    }
}

/// Kill a process group by leader pid. `kill -KILL -- -<pid>` through the
/// system `kill`, because `unsafe` is forbidden here; a no-op where there is
/// no pid or no `kill`.
async fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = tokio::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
}

#[async_trait]
impl MirrorGit for GitCli {
    async fn exists(&self, owner: &str, name: &str) -> bool {
        match self.dir(owner, name) {
            Some(d) => tokio::fs::metadata(d).await.is_ok_and(|m| m.is_dir()),
            None => false,
        }
    }

    async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let Some(dir) = self.dir(owner, name) else {
            return out;
        };
        let args = [
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/heads",
        ];
        if let Ok(bytes) = self.run(&dir, &args, None, Duration::from_secs(15)).await {
            for line in String::from_utf8_lossy(&bytes).lines() {
                if let Some((r, sha)) = line.split_once('\0') {
                    out.insert(r.to_string(), sha.to_string());
                }
            }
        }
        out
    }

    async fn materialise(&self, owner: &str, name: &str) -> Result<(), String> {
        let dir = self.dir(owner, name).ok_or("unsafe repository key")?;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| e.to_string())?;
        self.run(
            &dir,
            &["init", "--bare", "--quiet", "--initial-branch=main", "."],
            None,
            Duration::from_secs(15),
        )
        .await?;
        self.hide_mirror_refs(&dir).await
    }

    async fn fetch(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
        pin: Option<&ClonePin>,
    ) -> Result<(), String> {
        let dir = self.dir(owner, name).ok_or("unsafe repository key")?;
        let permitted = if operator {
            is_operator_clone(clone)
        } else {
            is_remote_clone(clone)
        };
        if !permitted || clone.starts_with('-') {
            return Err("clone URL refused".into());
        }
        // Idempotent: also covers a repository that existed before the mirror.
        self.hide_mirror_refs(&dir).await?;
        let mut args: Vec<&str> = vec![
            "-c",
            "transfer.fsckObjects=true",
            "-c",
            "fetch.unpackLimit=1",
        ];
        if !operator {
            args.extend(["-c", "http.followRedirects=false"]);
        }
        let resolve;
        if let Some(p) = pin {
            // Connect to the address the SSRF policy approved; do not resolve
            // the name again (git 2.37+, ignored by older git).
            resolve = format!("http.curloptResolve={}:{}:{}", p.host, p.port, p.ip);
            args.extend(["-c", &resolve]);
        }
        args.extend([
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--",
            clone,
            "+refs/heads/*:refs/mirror/*",
        ]);
        let allow = if operator {
            "http:https:file"
        } else {
            "http:https"
        };
        let ran = self
            .run_capped(
                &dir,
                &args,
                Some(allow),
                FETCH_TIMEOUT,
                Some(MAX_REPO_BYTES),
            )
            .await;
        let over = tokio::task::spawn_blocking({
            let d = dir.clone();
            move || dir_size(&d) > MAX_REPO_BYTES
        })
        .await
        .unwrap_or(false);
        if over || ran.is_err() {
            // A killed or oversize fetch leaves objects nothing references
            // once refs/mirror is gone; drop both so the size cannot ratchet.
            self.drop_mirror_refs_and_gc(&dir).await;
        }
        if over {
            return Err("repository grew past the size cap".into());
        }
        ran.map(|_| ())
    }

    async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool {
        let Some(dir) = self.dir(owner, name) else {
            return false;
        };
        if !is_sha40(sha) {
            return false;
        }
        let spec = format!("{sha}^{{commit}}");
        self.run(
            &dir,
            &["cat-file", "-e", &spec],
            None,
            Duration::from_secs(15),
        )
        .await
        .is_ok()
    }

    async fn is_ancestor(&self, owner: &str, name: &str, ancestor: &str, descendant: &str) -> bool {
        let Some(dir) = self.dir(owner, name) else {
            return false;
        };
        if !is_sha40(ancestor) || !is_sha40(descendant) {
            return false;
        }
        self.run(
            &dir,
            &["merge-base", "--is-ancestor", ancestor, descendant],
            None,
            Duration::from_secs(15),
        )
        .await
        .is_ok()
    }

    async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String> {
        let dir = self.dir(owner, name)?;
        if !is_sha40(sha) {
            return None;
        }
        let spec = format!("{sha}:{TRAIL_FILE}");
        let size = self
            .run(
                &dir,
                &["cat-file", "-s", &spec],
                None,
                Duration::from_secs(15),
            )
            .await
            .ok()?;
        let size: u64 = String::from_utf8_lossy(&size).trim().parse().ok()?;
        if size > MAX_TRAIL_BYTES {
            return None;
        }
        let bytes = self
            .run(
                &dir,
                &["cat-file", "blob", &spec],
                None,
                Duration::from_secs(15),
            )
            .await
            .ok()?;
        String::from_utf8(bytes).ok()
    }

    async fn update_ref(
        &self,
        owner: &str,
        name: &str,
        git_ref: &str,
        sha: &str,
    ) -> Result<(), String> {
        let dir = self.dir(owner, name).ok_or("unsafe repository key")?;
        if !is_branch_ref(git_ref) || !is_sha40(sha) {
            return Err("ref or sha refused".into());
        }
        self.run(
            &dir,
            &["update-ref", git_ref, sha],
            None,
            Duration::from_secs(15),
        )
        .await
        .map(|_| ())
    }

    async fn set_head(&self, owner: &str, name: &str, git_ref: &str) -> Result<(), String> {
        let dir = self.dir(owner, name).ok_or("unsafe repository key")?;
        if !is_branch_ref(git_ref) {
            return Err("ref refused".into());
        }
        self.run(
            &dir,
            &["symbolic-ref", "HEAD", git_ref],
            None,
            Duration::from_secs(15),
        )
        .await
        .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The mirror engine: one verified event in, one record out, with per-
/// repository serialisation. Cheap to share behind an [`Arc`].
pub struct Mirror {
    cfg: MirrorConfig,
    store: MirrorStore,
    git: Arc<dyn MirrorGit>,
    clock: Arc<dyn MirrorClock>,
    ssrf: Arc<dyn SsrfCheck>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Newest verified-by-filter event per `(repo, kind)` waiting for a worker.
    /// Bounded by construction: at most two entries per followed repository.
    inbox: std::sync::Mutex<HashMap<String, Event>>,
    /// Repositories that have a worker draining the inbox.
    busy: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Caps fetches running at once across all repositories.
    permits: Arc<tokio::sync::Semaphore>,
}

/// Releases a repository's `busy` slot on every exit path of
/// [`Mirror::drain`], including a panic in `on_event` or a closed permit
/// semaphore. Without it the key stayed in `busy` for ever and the repository
/// stopped updating until restart. When work is still queued the worker is
/// restarted, so nothing that arrived meanwhile is stranded.
struct BusyGuard {
    mirror: Arc<Mirror>,
    key: String,
    /// Set by the normal exit, which has already removed the key.
    released: bool,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let m = &self.mirror;
        let mut busy = m
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        busy.remove(&self.key);
        let prefix = format!("{}#", self.key);
        let more = m
            .inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .any(|k| k.starts_with(&prefix));
        if more && !m.permits.is_closed() {
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                busy.insert(self.key.clone());
                let me = Arc::clone(m);
                let key = self.key.clone();
                h.spawn(async move { me.drain(key).await });
            }
        }
    }
}

impl std::fmt::Debug for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mirror")
            .field("relays", &self.cfg.relays)
            .field("follow", &self.cfg.follow.len())
            .finish_non_exhaustive()
    }
}

impl Mirror {
    /// An engine over `git`, `store`, the wall clock and the workspace's
    /// default SSRF policy ([`DefaultSsrfCheck`]).
    #[must_use]
    pub fn new(cfg: MirrorConfig, store: MirrorStore, git: Arc<dyn MirrorGit>) -> Self {
        Self::with_parts(
            cfg,
            store,
            git,
            Arc::new(SystemClock),
            Arc::new(DefaultSsrfCheck),
        )
    }

    /// An engine with every collaborator supplied (tests, or an operator
    /// SSRF policy that allows an internal relay).
    #[must_use]
    pub fn with_parts(
        cfg: MirrorConfig,
        store: MirrorStore,
        git: Arc<dyn MirrorGit>,
        clock: Arc<dyn MirrorClock>,
        ssrf: Arc<dyn SsrfCheck>,
    ) -> Self {
        Self {
            cfg,
            store,
            git,
            clock,
            ssrf,
            locks: Mutex::new(HashMap::new()),
            inbox: std::sync::Mutex::new(HashMap::new()),
            busy: std::sync::Mutex::new(std::collections::HashSet::new()),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FETCHES)),
        }
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &MirrorConfig {
        &self.cfg
    }

    /// The record store (for serving `api/repos/<o>/<n>/mirror`).
    #[must_use]
    pub fn store(&self) -> &MirrorStore {
        &self.store
    }

    async fn lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().await;
        Arc::clone(map.entry(key.to_string()).or_default())
    }

    async fn host_allowed(&self, url: &str) -> Result<Option<std::net::IpAddr>, String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("bad URL: {e}"))?;
        let host = parsed.host_str().ok_or("URL has no host")?;
        let target = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        self.ssrf.verify_host(&target).await
    }

    /// Handle one relay event: verify it, keep only kinds 30617/30618 from
    /// a followed `(pubkey, d)`, record a 30617's clone URL, and apply a
    /// 30618. Returns the updated record when the event changed one.
    pub async fn on_event(&self, ev: &Event) -> Option<MirrorRecord> {
        let entry = self.wanted(ev)?;
        // The signature check is the expensive step; everything cheap came first.
        if !verify_event(ev) {
            return None;
        }
        let key = format!("{}/{}", entry.pubkey, entry.name);
        let lock = self.lock_for(&key).await;
        let _guard = lock.lock().await;
        if ev.kind == KIND_ANNOUNCE {
            return self.on_announce(&entry, ev);
        }
        Some(self.apply(&entry, ev).await)
    }

    /// The followed entry an event is for, judged by the cheap fields alone
    /// (kind, size, `d` tag, author) before any signature work.
    fn wanted(&self, ev: &Event) -> Option<FollowEntry> {
        if ev.kind != KIND_ANNOUNCE && ev.kind != KIND_STATE {
            return None;
        }
        if ev.tags.len() > MAX_EVENT_TAGS {
            return None;
        }
        let d = tag_value(ev, "d")?;
        followed_entry(&self.cfg.follow, &ev.pubkey, d).cloned()
    }

    /// Queue an event from a relay for a per-repository worker, keeping only
    /// the newest per `(repo, kind)`, so the socket loop never waits on git.
    fn enqueue(self: &Arc<Self>, ev: Event) {
        let Some(entry) = self.wanted(&ev) else {
            return;
        };
        let key = format!("{}/{}", entry.pubkey, entry.name);
        let slot = format!("{key}#{}", ev.kind);
        {
            let mut inbox = self
                .inbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A far-future stamp must not squat the slot and shadow honest
            // events (L3), and a tie at the same second keeps the lowest id.
            if ev.created_at > self.clock.now_ms() / 1000 + MAX_FUTURE_SKEW_SECS {
                return;
            }
            match inbox.get(&slot) {
                Some(have)
                    if have.created_at > ev.created_at
                        || (have.created_at == ev.created_at && have.id <= ev.id) =>
                {
                    return
                }
                _ => {
                    inbox.insert(slot, ev);
                }
            }
        }
        let start = {
            let mut busy = self
                .busy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            busy.insert(key.clone())
        };
        if start {
            let me = Arc::clone(self);
            tokio::spawn(async move { me.drain(key).await });
        }
    }

    /// Worker: apply queued events for one repository until none are left,
    /// holding a fetch permit while it works, and re-apply a state the rate
    /// limit held back once its wait is over.
    async fn drain(self: Arc<Self>, key: String) {
        let mut guard = BusyGuard {
            mirror: Arc::clone(&self),
            key: key.clone(),
            released: false,
        };
        loop {
            let next = {
                let mut inbox = self
                    .inbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                [KIND_ANNOUNCE, KIND_STATE]
                    .iter()
                    .find_map(|k| inbox.remove(&format!("{key}#{k}")))
            };
            let Some(ev) = next else {
                let mut busy = self
                    .busy
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // A racing enqueue may have added work between the take and here.
                let more = self
                    .inbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .keys()
                    .any(|k| k.starts_with(&format!("{key}#")));
                if !more {
                    busy.remove(&key);
                    guard.released = true;
                    return;
                }
                continue;
            };
            let Ok(_permit) = Arc::clone(&self.permits).acquire_owned().await else {
                return;
            };
            let rec = self.on_event(&ev).await;
            drop(_permit);
            if let Some(wait) = rec
                .and_then(|r| r.retry_at)
                .map(|at| at.saturating_sub(self.clock.now_ms()))
            {
                tokio::time::sleep(Duration::from_millis(wait.min(MAX_BACKOFF_MS) + 50)).await;
                let slot = format!("{key}#{}", ev.kind);
                let mut inbox = self
                    .inbox
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Put the held state back unless something newer arrived.
                inbox.entry(slot).or_insert(ev);
            }
        }
    }

    fn on_announce(&self, entry: &FollowEntry, ev: &Event) -> Option<MirrorRecord> {
        let clones = read_clones(ev);
        if clones.is_empty() {
            return None;
        }
        let mut rec = self
            .store
            .read(&entry.pubkey, &entry.name)
            .unwrap_or_else(|| MirrorRecord::new(&entry.pubkey, &entry.name, entry.clone.clone()));
        if rec.announce_at.is_some_and(|a| a >= ev.created_at) {
            return None;
        }
        rec.clone = Some(clones[0].clone());
        rec.announce_at = Some(ev.created_at);
        rec.clones = clones;
        self.save(&rec);
        Some(rec)
    }

    /// Check the clone host and fetch from it. A remote URL is normalised
    /// first and the address the SSRF policy approves is pinned into git;
    /// an operator `file://` clone is neither resolved nor pinned.
    async fn fetch_checked(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
    ) -> Result<(), String> {
        if clone.to_ascii_lowercase().starts_with("file://") {
            return self.git.fetch(owner, name, clone, operator, None).await;
        }
        let (url, host, port) = if operator {
            let u = url::Url::parse(clone).map_err(|e| format!("bad URL: {e}"))?;
            (
                u.as_str().to_string(),
                u.host_str().ok_or("URL has no host")?.to_string(),
                u.port_or_known_default().ok_or("URL has no port")?,
            )
        } else {
            normalise_remote_clone(clone).ok_or_else(|| "clone URL refused".to_string())?
        };
        let ip = self
            .host_allowed(&url)
            .await
            .map_err(|why| format!("clone host refused: {why}"))?;
        let pin = ip.map(|ip| ClonePin { host, port, ip });
        self.git
            .fetch(owner, name, &url, operator, pin.as_ref())
            .await
    }

    fn save(&self, rec: &MirrorRecord) {
        if let Err(e) = self.store.save(rec) {
            tracing::warn!(pubkey = %rec.pubkey, name = %rec.name, error = %e, "forge: mirror record not saved");
        }
    }

    /// Apply one verified kind-30618 to one followed repository: plan,
    /// fetch into `refs/mirror/*`, give each changed branch its verdict,
    /// move what passes, and save the record.
    pub async fn apply(&self, entry: &FollowEntry, ev: &Event) -> MirrorRecord {
        let (owner, name) = (entry.pubkey.as_str(), entry.name.as_str());
        let state = read_state(ev);
        let mut rec = self
            .store
            .read(owner, name)
            .unwrap_or_else(|| MirrorRecord::new(owner, name, entry.clone.clone()));
        let local = if self.git.exists(owner, name).await {
            self.git.local_heads(owner, name).await
        } else {
            BTreeMap::new()
        };
        let now = self.clock.now_ms();
        if let Some(st) = state.as_ref() {
            if st.created_at > now / 1000 + MAX_FUTURE_SKEW_SECS {
                // A state stamped far ahead would otherwise freeze the replay
                // clock and make every honest state look old.
                rec.events += 1;
                rec.last_seen = Some(LastSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    at: now,
                    action: SeenAction::Skip,
                    reason: "created_at is too far in the future".into(),
                });
                self.save(&rec);
                return rec;
            }
            let loses_tie = st.created_at == rec.newest_seen_at
                && !rec.newest_seen_id.is_empty()
                && ev.id != rec.newest_seen_id
                && ev.id > rec.newest_seen_id;
            if st.created_at < rec.newest_seen_at || loses_tie {
                // A validly signed but older state: a relay replaying history.
                // Moving branches back to it would be a rollback.
                rec.events += 1;
                rec.last_seen = Some(LastSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    at: now,
                    action: SeenAction::Skip,
                    reason: if loses_tie {
                        "same time as a state already seen, which has the lower id (replay)"
                    } else {
                        "older than a state already seen (replay)"
                    }
                    .into(),
                });
                self.save(&rec);
                return rec;
            }
            rec.newest_seen_at = st.created_at;
            rec.newest_seen_id = ev.id.clone();
        }
        let plan = plan_mirror(&PlanInput {
            state: state.as_ref(),
            local: &local,
            last_seen_at: rec.last_event.as_ref().map_or(0, |e| e.created_at),
            last_fetch_at: rec.last_fetch_at.unwrap_or(0),
            now,
            min_interval_ms: backoff_interval(self.cfg.min_interval_ms, rec.failures),
        });
        rec.events += 1;
        rec.retry_at = None;
        let mut seen = LastSeen {
            id: ev.id.clone(),
            created_at: ev.created_at,
            at: now,
            action: if plan.action == PlanAction::Skip {
                SeenAction::Skip
            } else {
                SeenAction::Held
            },
            reason: plan.reason.clone(),
        };
        let (Some(state), PlanAction::Fetch) = (state, plan.action) else {
            if !plan.changed.is_empty() {
                // Held by the rate limit, not by being stale or in sync: ask
                // for it again once the floor has passed.
                let floor = backoff_interval(self.cfg.min_interval_ms, rec.failures);
                rec.retry_at = Some(rec.last_fetch_at.unwrap_or(now) + floor);
            }
            rec.last_seen = Some(seen);
            self.save(&rec);
            return rec;
        };
        // An operator-configured clone wins; otherwise the newest 30617's.
        let (clone, operator) = match (&entry.clone, &rec.clone) {
            (Some(c), _) => (c.clone(), true),
            (None, Some(c)) if is_remote_clone(c) => (c.clone(), false),
            _ => {
                seen.action = SeenAction::Skip;
                seen.reason =
                    "no clone URL: none configured and no 30617 from this key seen yet".into();
                rec.last_seen = Some(seen);
                self.save(&rec);
                return rec;
            }
        };
        if !self.git.exists(owner, name).await {
            if let Err(e) = self.git.materialise(owner, name).await {
                seen.action = SeenAction::FetchFailed;
                seen.reason = format!("could not create the mirror: {e}");
                rec.last_seen = Some(seen);
                self.save(&rec);
                return rec;
            }
        }
        rec.last_fetch_at = Some(now);
        let fetched = self.fetch_checked(owner, name, &clone, operator).await;
        if fetched.is_ok() {
            rec.failures = 0;
        }
        if let Err(why) = fetched {
            rec.failures = rec.failures.saturating_add(1);
            seen.action = SeenAction::FetchFailed;
            seen.reason = why;
            tracing::warn!(pubkey = %owner, name = %name, reason = %seen.reason, "forge: mirror fetch failed");
            rec.last_seen = Some(seen);
            self.save(&rec);
            return rec;
        }
        let mut branches = BTreeMap::new();
        let mut moved = 0usize;
        for (git_ref, sha) in &plan.changed {
            let present = self.git.has_commit(owner, name, sha).await;
            let trail = if present && state.mark.is_some() {
                self.git.read_trail(owner, name, sha).await
            } else {
                None
            };
            let reachable = match &state.mark {
                Some(m) if present => self.git.is_ancestor(owner, name, &m.commit, sha).await,
                _ => true,
            };
            let v = branch_verdict(
                present,
                state.mark.as_ref(),
                trail.as_deref(),
                owner,
                reachable,
            );
            let mut did_move = v.move_branch;
            if did_move {
                match self.git.update_ref(owner, name, git_ref, sha).await {
                    Ok(()) => moved += 1,
                    Err(e) => {
                        tracing::warn!(pubkey = %owner, name = %name, error = %e, "forge: mirror ref not updated");
                        did_move = false;
                    }
                }
            }
            branches.insert(
                git_ref.clone(),
                BranchOutcome {
                    sha: sha.clone(),
                    moved: did_move,
                    verdict: v.verdict,
                },
            );
        }
        if let Some(head) = state.head.as_deref() {
            if moved > 0 && branches.get(head).is_some_and(|b| b.moved) {
                let _ = self.git.set_head(owner, name, head).await;
            }
        }
        rec.last_event = Some(EventRef {
            id: ev.id.clone(),
            created_at: ev.created_at,
        });
        rec.last_fetch = Some(LastFetch {
            at: now,
            clone,
            branches,
            moved,
            mark: state.mark.clone(),
        });
        seen.action = if moved > 0 {
            SeenAction::Moved
        } else {
            SeenAction::Held
        };
        seen.reason = if moved > 0 {
            format!("{moved} of {} moved", plan.changed.len())
        } else {
            "nothing passed".into()
        };
        tracing::info!(pubkey = %owner, name = %name, reason = %seen.reason, "forge: mirror applied a state");
        rec.last_seen = Some(seen);
        self.save(&rec);
        rec
    }

    /// Start one relay session task per configured relay. Each reconnects
    /// with [`backoff_delay`], which starts over once a relay answers, and
    /// re-sends its REQ on every connect (the REQ *is* the catch-up).
    /// Drop or [`MirrorHandle::stop`] the handle to end them.
    #[must_use]
    pub fn start(self: &Arc<Self>) -> MirrorHandle {
        let (tx, rx) = watch::channel(false);
        let tasks = self
            .cfg
            .relays
            .iter()
            .map(|relay| {
                let me = Arc::clone(self);
                let relay = relay.clone();
                let rx = rx.clone();
                tokio::spawn(async move { me.relay_loop(relay, rx).await })
            })
            .collect();
        MirrorHandle { stop: tx, tasks }
    }

    async fn relay_loop(self: Arc<Self>, relay: String, mut stop: watch::Receiver<bool>) {
        let mut attempt: u32 = 0;
        while !*stop.borrow() {
            let why = self.relay_session(&relay, &mut attempt, &mut stop).await;
            if *stop.borrow() {
                return;
            }
            if attempt == 0 {
                tracing::warn!(relay = %relay, reason = %why, "forge: mirror relay lost; reconnecting");
            }
            let delay = backoff_delay(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = stop.changed() => {}
            }
        }
    }

    async fn relay_session(
        self: &Arc<Self>,
        relay: &str,
        attempt: &mut u32,
        stop: &mut watch::Receiver<bool>,
    ) -> String {
        if let Err(why) = self.host_allowed(&relay.replacen("ws", "http", 1)).await {
            return format!("relay host refused: {why}");
        }
        let limits = WebSocketConfig {
            max_message_size: Some(MAX_FRAME_BYTES),
            max_frame_size: Some(MAX_FRAME_BYTES),
            ..WebSocketConfig::default()
        };
        let connect = tokio_tungstenite::connect_async_with_config(relay, Some(limits), false);
        let mut ws = match tokio::time::timeout(Duration::from_secs(15), connect).await {
            Ok(Ok((ws, _))) => ws,
            Ok(Err(e)) => return e.to_string(),
            Err(_) => return "connect timed out".into(),
        };
        let mut authors: Vec<&str> = self.cfg.follow.iter().map(|f| f.pubkey.as_str()).collect();
        authors.sort_unstable();
        authors.dedup();
        let req = json!(["REQ", SUBSCRIPTION_ID, { "kinds": [KIND_ANNOUNCE, KIND_STATE], "authors": authors }]);
        if let Err(e) = ws.send(Message::text(req.to_string())).await {
            return e.to_string();
        }
        loop {
            let msg = tokio::select! {
                m = ws.next() => m,
                _ = stop.changed() => {
                    let _ = ws.close(None).await;
                    return "stopped".into();
                }
            };
            match msg {
                Some(Ok(Message::Text(text))) => {
                    let frame = classify_relay_frame(&text);
                    if frame.answered {
                        *attempt = 0;
                    }
                    if let Some(note) = frame.notice {
                        tracing::warn!(relay = %relay, "forge: mirror relay: {note}");
                    }
                    if let Some(ev) = frame.event {
                        self.enqueue(ev);
                    }
                }
                Some(Ok(Message::Close(_))) | None => return "closed".into(),
                Some(Ok(_)) => {}
                Some(Err(e)) => return e.to_string(),
            }
        }
    }
}

/// Owns the relay session tasks started by [`Mirror::start`].
#[derive(Debug)]
pub struct MirrorHandle {
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl MirrorHandle {
    /// Ask every session to close and wait for them.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;

    // --- helpers -----------------------------------------------------------

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn pubhex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    fn sign(sk: &SigningKey, kind: u64, tags: Vec<Vec<String>>, created_at: u64) -> Event {
        let mut ev = Event {
            id: String::new(),
            pubkey: pubhex(sk),
            created_at,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = ev.canonical_id();
        let sig = sk
            .sign_raw(&hex::decode(&ev.id).unwrap(), &[0u8; 32])
            .unwrap();
        ev.sig = hex::encode(sig.to_bytes());
        ev
    }

    fn tags(items: &[&[&str]]) -> Vec<Vec<String>> {
        items
            .iter()
            .map(|t| t.iter().map(|s| (*s).to_string()).collect())
            .collect()
    }

    struct AllowAll;
    #[async_trait]
    impl SsrfCheck for AllowAll {
        async fn verify_host(&self, _host: &str) -> Result<Option<std::net::IpAddr>, String> {
            Ok(None)
        }
    }

    // --- the six library tests (forge mirror library (pure)) ---------------

    #[test]
    fn config_off_unless_relays_and_follow_capped_keyed_by_pubkey_and_name() {
        let pubk = pubhex(&key(1));
        assert!(parse_mirror_config(&Value::Null).is_none());
        assert!(parse_mirror_config(&json!({})).is_none());
        assert!(parse_mirror_config(&json!({"relays":["wss://r.example"],"follow":[]})).is_none());
        assert!(
            parse_mirror_config(&json!({"relays":[],"follow":[{"pubkey":pubk,"name":"x"}]}))
                .is_none(),
            "no relays, no mirror"
        );
        let m = parse_mirror_config(&json!({
            "relays": ["wss://r.example", "http://not-a-relay", "ws://127.0.0.1:1"],
            "follow": [
                { "pubkey": pubk.to_uppercase(), "name": "x", "clone": "https://example.org/x.git" },
                { "pubkey": pubk, "name": "x" },
                { "pubkey": "nothex", "name": "y" },
                { "pubkey": pubk, "name": "../etc" },
                { "pubkey": pubk, "name": "z", "clone": "ssh://nope" },
            ],
        }))
        .unwrap();
        assert_eq!(m.relays, ["wss://r.example", "ws://127.0.0.1:1"]);
        assert_eq!(
            m.follow,
            vec![
                FollowEntry {
                    pubkey: pubk.clone(),
                    name: "x".into(),
                    clone: Some("https://example.org/x.git".into())
                },
                FollowEntry {
                    pubkey: pubk.clone(),
                    name: "z".into(),
                    clone: None
                },
            ]
        );
        assert_eq!(m.min_interval_ms, 30_000);
        let many: Vec<Value> = (0..80)
            .map(|i| json!({"pubkey": pubk, "name": format!("r{i}")}))
            .collect();
        let capped = parse_mirror_config(&json!({"relays":["wss://r"],"follow":many})).unwrap();
        assert_eq!(capped.follow.len(), MAX_FOLLOW);
    }

    #[test]
    fn verify_event_id_and_signature_must_check_out_and_a_tampered_tag_fails() {
        let sk = key(2);
        let (sha1, sha2) = ("a".repeat(40), "b".repeat(40));
        let ev = sign(
            &sk,
            KIND_STATE,
            tags(&[&["d", "x"], &["refs/heads/main", &sha1]]),
            1_760_000_000,
        );
        assert!(verify_event(&ev));
        let mut tampered = ev.clone();
        tampered.tags = tags(&[&["d", "x"], &["refs/heads/main", &sha2]]);
        assert!(!verify_event(&tampered));
        let mut bad_sig = ev.clone();
        bad_sig.sig = "f".repeat(128);
        assert!(!verify_event(&bad_sig));
        let mut huge = ev;
        huge.tags = (0..=MAX_EVENT_TAGS)
            .map(|i| vec!["t".into(), i.to_string()])
            .collect();
        assert!(
            !verify_event(&huge),
            "tag count is bounded before the signature is checked"
        );
    }

    #[test]
    fn read_state_d_head_branch_refs_and_the_mark_only_with_all_three_tags() {
        let sk = key(3);
        let (sha1, sha2) = ("a".repeat(40), "b".repeat(40));
        let txo = format!("txo:txbt4:{}:0", "c".repeat(64));
        let ev = sign(
            &sk,
            KIND_STATE,
            tags(&[
                &["d", "x"],
                &["HEAD", "ref: refs/heads/main"],
                &["refs/heads/main", &sha1],
                &["refs/heads/dev", "short"],
                &["refs/tags/v1", &sha2],
                &["chain", "txbt4"],
                &["txo", &txo],
                &["commit", &sha1],
            ]),
            1_760_000_000,
        );
        let st = read_state(&ev).unwrap();
        assert_eq!(
            st.refs,
            BTreeMap::from([("refs/heads/main".to_string(), sha1.clone())])
        );
        assert_eq!(st.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            st.mark,
            Some(MirrorMark {
                chain: "txbt4".into(),
                txo,
                commit: sha1
            })
        );
        let no_mark = read_state(&sign(&sk, KIND_STATE, tags(&[&["d", "x"]]), 1)).unwrap();
        assert!(no_mark.mark.is_none());
        assert!(
            read_state(&sign(
                &sk,
                KIND_STATE,
                tags(&[&["d", "x"], &["chain", "txbt4"]]),
                1
            ))
            .is_none(),
            "a partial mark makes the state unusable, not markless"
        );
        assert!(
            read_state(&sign(&sk, KIND_STATE, vec![], 1)).is_none(),
            "no d, no state"
        );
    }

    #[test]
    fn read_clones_http_s_in_order_and_file_never() {
        let ev = sign(
            &key(4),
            KIND_ANNOUNCE,
            tags(&[
                &["d", "x"],
                &["clone", "https://a.example/x.git", "git@a.example:x.git"],
                &["clone", "file:///tmp/x"],
                &["clone", "http://b.example/x.git"],
            ]),
            1,
        );
        assert_eq!(
            read_clones(&ev),
            ["https://a.example/x.git", "http://b.example/x.git"]
        );
    }

    #[test]
    fn plan_mirror_skips_older_in_sync_and_rate_limited_otherwise_names_moved_branches() {
        let (sha1, sha2) = ("a".repeat(40), "b".repeat(40));
        let state = RepoState {
            d: "x".into(),
            head: None,
            mark: None,
            created_at: 100,
            id: String::new(),
            refs: BTreeMap::from([
                ("refs/heads/main".to_string(), sha2.clone()),
                ("refs/heads/dev".to_string(), sha1.clone()),
            ]),
        };
        let local = BTreeMap::from([
            ("refs/heads/main".to_string(), sha1.clone()),
            ("refs/heads/dev".to_string(), sha1.clone()),
        ]);
        let base = PlanInput {
            state: Some(&state),
            local: &local,
            last_seen_at: 0,
            last_fetch_at: 0,
            now: 1_000_000,
            min_interval_ms: 30_000,
        };
        let older = plan_mirror(&PlanInput {
            last_seen_at: 100,
            ..base.clone()
        });
        assert_eq!(older.action, PlanAction::Skip);
        assert_eq!(older.reason, "not newer than the last state acted on");
        let in_sync = plan_mirror(&PlanInput {
            local: &state.refs,
            ..base.clone()
        });
        assert_eq!(in_sync.reason, "already at this state");
        let limited = plan_mirror(&PlanInput {
            last_fetch_at: 990_000,
            ..base.clone()
        });
        assert_eq!(limited.reason, "fetched 10 s ago; next in 20 s");
        let p = plan_mirror(&base);
        assert_eq!(p.action, PlanAction::Fetch);
        assert_eq!(p.changed, vec![("refs/heads/main".to_string(), sha2)]);
        let empty = RepoState {
            refs: BTreeMap::new(),
            ..state.clone()
        };
        assert_eq!(
            plan_mirror(&PlanInput {
                state: Some(&empty),
                ..base.clone()
            })
            .reason,
            "the state names no branch"
        );
        assert_eq!(
            plan_mirror(&PlanInput {
                state: None,
                ..base
            })
            .reason,
            "not a repository state"
        );
    }

    #[test]
    fn remote_clone_urls_are_normalised_and_stripped_of_ambiguity() {
        let ok = normalise_remote_clone("https://Example.com/a/b.git").unwrap();
        assert_eq!(
            ok,
            (
                "https://example.com/a/b.git".into(),
                "example.com".into(),
                443
            )
        );
        let ok = normalise_remote_clone("http://example.com:8080/x").unwrap();
        assert_eq!((ok.1.as_str(), ok.2), ("example.com", 8080));
        for bad in [
            "https://user:pw@example.com/x",
            "https://user@example.com/x",
            "https://example.com\\@evil.example/x",
            "https://exämple.com/x",
            "https://example.com/x#frag",
            "file:///etc/passwd",
            "ssh://example.com/x",
            "https://",
            "-https://example.com/x",
        ] {
            assert!(normalise_remote_clone(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn backoff_interval_doubles_and_caps() {
        assert_eq!(backoff_interval(30_000, 0), 30_000);
        assert_eq!(backoff_interval(30_000, 1), 60_000);
        assert_eq!(backoff_interval(30_000, 3), 240_000);
        assert_eq!(backoff_interval(30_000, 30), MAX_BACKOFF_MS);
        // a floor already above the cap is left alone
        assert_eq!(backoff_interval(7_200_000, 5), 7_200_000);
    }

    #[test]
    fn dir_size_sums_files_and_ignores_symlinks() {
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join("a")).unwrap();
        std::fs::write(td.path().join("a/x"), vec![0u8; 1000]).unwrap();
        std::fs::write(td.path().join("y"), vec![0u8; 24]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", td.path().join("link")).unwrap();
        assert_eq!(dir_size(td.path()), 1024);
    }

    #[tokio::test]
    async fn a_fetch_past_the_size_cap_is_killed_and_the_mirror_cleaned() {
        // A tiny sleep wrapper stands in for a slow, large fetch: the watchdog
        // is what ends it, not the 60 s budget.
        let td = tempfile::tempdir().unwrap();
        let git = GitCli::new(td.path());
        let owner = "ab".repeat(32);
        git.materialise(&owner, "agent").await.unwrap();
        let dir = td.path().join(&owner).join("agent.git");
        std::fs::write(dir.join("objects").join("bloat"), vec![0u8; 4096]).unwrap();
        let started = std::time::Instant::now();
        let r = git
            .run_capped(
                &dir,
                &["-c", "alias.nap=!sleep 30", "nap"],
                None,
                Duration::from_secs(30),
                Some(1024),
            )
            .await;
        assert!(r.unwrap_err().contains("size cap"));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "killed promptly"
        );
    }

    #[tokio::test]
    async fn a_materialised_mirror_hides_refs_mirror_from_upload_pack() {
        let td = tempfile::tempdir().unwrap();
        let git = GitCli::new(td.path());
        let owner = "ab".repeat(32);
        git.materialise(&owner, "agent").await.unwrap();
        let dir = td.path().join(&owner).join("agent.git");
        let cfg = |key: &str| {
            let out = std::process::Command::new("git")
                .args(["config", "--get-all", key])
                .current_dir(&dir)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(cfg("uploadpack.hideRefs"), "refs/mirror");
        assert_eq!(cfg("transfer.hideRefs"), "refs/mirror");
    }

    #[test]
    fn a_garbled_mark_makes_the_state_unusable_not_markless() {
        let sha = "a".repeat(40);
        let mk = |tags: Vec<Vec<String>>| Event {
            id: "0".repeat(64),
            pubkey: "1".repeat(64),
            created_at: 7,
            kind: 30618,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        let base = vec![
            vec!["d".to_string(), "x".to_string()],
            vec!["refs/heads/main".to_string(), sha.clone()],
        ];
        assert!(
            read_state(&mk(base.clone())).is_some(),
            "no mark tags: fine"
        );
        for bad in [
            vec![vec!["commit".to_string(), "not-a-sha".to_string()]],
            vec![
                vec!["chain".to_string(), "txbt4".to_string()],
                vec!["txo".to_string(), "txo:x".to_string()],
            ],
            vec![
                vec!["chain".to_string(), "txbt4".to_string()],
                vec!["txo".to_string(), "txo:x".to_string()],
                vec!["commit".to_string(), "zz".repeat(20)],
            ],
        ] {
            let mut tags = base.clone();
            tags.extend(bad);
            assert!(read_state(&mk(tags)).is_none());
        }
    }

    #[test]
    fn branch_verdict_unfetched_never_moves_no_mark_moves_a_mark_needs_a_listing_trail() {
        let (sha1, sha2) = ("a".repeat(40), "b".repeat(40));
        let key = "ab".repeat(32);
        let trail = json!({"@type":"Blocktrail","profile":"gitmark","pubkeyBase":format!("02{key}"),"states":[sha1]})
            .to_string();
        assert!(!branch_verdict(false, None, None, &key, true).move_branch);
        assert!(branch_verdict(true, None, None, &key, true).move_branch);
        let mark = MirrorMark {
            chain: "txbt4".into(),
            txo: "txo:…".into(),
            commit: sha1.clone(),
        };
        assert!(!branch_verdict(true, Some(&mark), None, &key, true).move_branch);
        assert!(branch_verdict(true, Some(&mark), Some(&trail), &key, true).move_branch);
        // a trail copied from another agent's repository does not count
        let theirs = "cd".repeat(32);
        let v = branch_verdict(true, Some(&mark), Some(&trail), &theirs, true);
        assert!(!v.move_branch, "{}", v.verdict);
        // the marked commit must be in the history of the commit being moved to
        let v = branch_verdict(true, Some(&mark), Some(&trail), &key, false);
        assert!(!v.move_branch, "{}", v.verdict);
        let other = MirrorMark {
            commit: sha2,
            ..mark
        };
        assert!(!branch_verdict(true, Some(&other), Some(&trail), &key, true).move_branch);
        assert!(!trail_lists("not json", &sha1));
        assert!(!trail_lists(
            r#"{"profile":"monochrome","states":[]}"#,
            &sha1
        ));
    }

    // --- hardening and framing --------------------------------------------

    #[test]
    fn branch_refs_and_clone_urls_refuse_injection() {
        for bad in [
            "refs/heads/../x",
            "refs/heads/a//b",
            "refs/heads/-f",
            "refs/heads/a.lock",
            "refs/heads/a b",
            "refs/heads/.hidden",
            "refs/heads/a@{1}",
            "refs/heads/",
            "main",
            "refs/heads/a;b",
        ] {
            assert!(!is_branch_ref(bad), "{bad}");
        }
        assert!(is_branch_ref("refs/heads/feature/x-1.2"));
        for bad in [
            "--upload-pack=x",
            "ext::sh -c x",
            "ssh://h/x",
            "git://h/x",
            "https://h/x y",
            "https://h/x;y",
        ] {
            assert!(!is_operator_clone(bad) && !is_remote_clone(bad), "{bad}");
        }
        assert!(is_operator_clone("file:///srv/x") && !is_remote_clone("file:///srv/x"));
    }

    #[test]
    fn frames_backoff_resets_on_answer_and_notices_are_logged() {
        assert!(classify_relay_frame(r#"["EOSE","forge-mirror"]"#).answered);
        assert!(classify_relay_frame(r#"["EVENT","other",{}]"#).answered);
        assert!(classify_relay_frame(r#"["EVENT","other",{}]"#)
            .event
            .is_none());
        let closed = classify_relay_frame(r#"["CLOSED","forge-mirror","auth-required: nope"]"#);
        assert!(!closed.answered);
        assert_eq!(closed.notice.as_deref(), Some("CLOSED auth-required: nope"));
        assert!(
            classify_relay_frame(&format!("[\"NOTICE\",\"{}\"]", "x".repeat(MAX_FRAME_BYTES)))
                .notice
                .is_none()
        );
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(
            backoff_delay(6),
            Duration::from_secs(60).min(Duration::from_secs(64))
        );
        assert_eq!(backoff_delay(99), Duration::from_secs(60));
    }

    // --- the integration tests (in-process relay, local upstream) ---------

    fn git_ok(cwd: &Path, home: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=Agent",
                "-c",
                "user.email=agent@example.org",
            ])
            .args(args)
            .current_dir(cwd)
            .env("HOME", home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    struct Relay {
        url: String,
        events: Arc<std::sync::Mutex<Vec<Event>>>,
        live: broadcast::Sender<Event>,
        reqs: Arc<AtomicUsize>,
    }

    impl Relay {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let events: Arc<std::sync::Mutex<Vec<Event>>> = Arc::default();
            let (live, _) = broadcast::channel(64);
            let reqs = Arc::new(AtomicUsize::new(0));
            let (ev2, live2, reqs2) = (events.clone(), live.clone(), reqs.clone());
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (ev3, mut rx, reqs3) = (ev2.clone(), live2.subscribe(), reqs2.clone());
                    tokio::spawn(async move {
                        let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        let mut sub = None::<String>;
                        loop {
                            tokio::select! {
                                m = ws.next() => {
                                    let Some(Ok(Message::Text(t))) = m else { return };
                                    let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(&t) else { continue };
                                    if msg.first().and_then(Value::as_str) == Some("REQ") {
                                        reqs3.fetch_add(1, Ordering::SeqCst);
                                        let id = msg[1].as_str().unwrap().to_string();
                                        let filter = msg[2].clone();
                                        let stored = ev3.lock().unwrap().clone();
                                        for e in stored {
                                            let kinds = filter["kinds"].as_array().unwrap();
                                            let authors = filter["authors"].as_array().unwrap();
                                            if kinds.iter().any(|k| k.as_u64() == Some(e.kind))
                                                && authors.iter().any(|a| a.as_str() == Some(&e.pubkey))
                                            {
                                                let _ = ws.send(Message::text(json!(["EVENT", id, e]).to_string())).await;
                                            }
                                        }
                                        let _ = ws.send(Message::text(json!(["EOSE", id]).to_string())).await;
                                        sub = Some(id);
                                    }
                                }
                                e = rx.recv() => {
                                    if let (Ok(e), Some(id)) = (e, sub.as_ref()) {
                                        let _ = ws.send(Message::text(json!(["EVENT", id, e]).to_string())).await;
                                    }
                                }
                            }
                        }
                    });
                }
            });
            Self {
                url,
                events,
                live,
                reqs,
            }
        }

        fn push(&self, ev: Event) {
            self.events.lock().unwrap().push(ev.clone());
            let _ = self.live.send(ev);
        }
    }

    async fn until<T, F, Fut>(what: &str, mut f: F) -> T
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let t0 = std::time::Instant::now();
        loop {
            if let Some(v) = f().await {
                return v;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn state_event(
        sk: &SigningKey,
        name: &str,
        refs: &[(&str, &str)],
        mark: Option<(&str, &str, &str)>,
        at: u64,
    ) -> Event {
        let mut t = tags(&[&["d", name], &["HEAD", "ref: refs/heads/main"]]);
        t.extend(
            refs.iter()
                .map(|(r, s)| vec![(*r).to_string(), (*s).to_string()]),
        );
        if let Some((chain, txo, commit)) = mark {
            t.extend(tags(&[
                &["chain", chain],
                &["txo", txo],
                &["commit", commit],
            ]));
        }
        sign(sk, KIND_STATE, t, at)
    }

    fn engine(tmp: &Path, cfg: MirrorConfig) -> Arc<Mirror> {
        Arc::new(Mirror::with_parts(
            cfg,
            MirrorStore::new(tmp),
            Arc::new(GitCli::new(tmp.join("repos"))),
            Arc::new(SystemClock),
            Arc::new(AllowAll),
        ))
    }

    #[tokio::test]
    async fn mirrors_a_repo_on_its_agents_state_through_a_relay() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let up = home.join("up");
        std::fs::create_dir(&up).unwrap();
        git_ok(&up, &home, &["init", "--quiet", "-b", "main"]);
        std::fs::write(up.join("README.md"), "# up\n").unwrap();
        git_ok(&up, &home, &["add", "-A"]);
        git_ok(&up, &home, &["commit", "--quiet", "-m", "first"]);
        let head = |p: &Path| git_ok(p, &home, &["rev-parse", "HEAD"]);

        let (sk, other) = (key(7), key(8));
        let pubk = pubhex(&sk);
        let relay = Relay::start().await;
        let mut t = 1_760_000_000u64;
        let mut next = || {
            t += 1;
            t
        };
        // A state already on the relay before the mirror starts: catch-up.
        let c1 = head(&up);
        relay.push(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &c1)],
            None,
            next(),
        ));

        let cfg = MirrorConfig {
            relays: vec![relay.url.clone()],
            follow: vec![FollowEntry {
                pubkey: pubk.clone(),
                name: "up".into(),
                clone: Some(format!("file://{}", up.display())),
            }],
            min_interval_ms: 0,
        };
        let m = engine(tmp.path(), cfg);
        let handle = m.start();
        let mirror_dir = tmp.path().join("repos").join(&pubk).join("up.git");
        let mirror_head = || git_ok(&mirror_dir, &home, &["rev-parse", "refs/heads/main"]);
        let record = || m.store().read(&pubk, "up");

        // 1. one REQ, and the catch-up state is pulled
        let rec = until("the first fetch", || async {
            record().filter(|r| r.last_fetch.is_some())
        })
        .await;
        assert!(relay.reqs.load(Ordering::SeqCst) >= 1, "a REQ was sent");
        let lf = rec.last_fetch.unwrap();
        assert_eq!(lf.moved, 1);
        assert_eq!(lf.branches["refs/heads/main"].sha, c1);
        assert_eq!(rec.last_seen.unwrap().action, SeenAction::Moved);
        assert_eq!(mirror_head(), c1);

        // 2. a marked state moves only when the trail lists the marked commit
        let txo = format!("txo:txbt4:{}:0", "c".repeat(64));
        std::fs::write(
            up.join("blocktrails.json"),
            json!({"@type":"Blocktrail","profile":"gitmark","chain":"txbt4","pubkeyBase":format!("02{pubk}"),"states":[c1],"txo":[txo]}).to_string(),
        )
        .unwrap();
        git_ok(&up, &home, &["add", "-A"]);
        git_ok(
            &up,
            &home,
            &["commit", "--quiet", "-m", "trail: first mark"],
        );
        let c2 = head(&up);
        relay.push(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &c2)],
            Some(("txbt4", &txo, &c1)),
            next(),
        ));
        let rec = until("the marked state", || async {
            record().filter(|r| {
                r.last_fetch
                    .as_ref()
                    .is_some_and(|f| f.branches["refs/heads/main"].sha == c2)
            })
        })
        .await;
        let b = &rec.last_fetch.as_ref().unwrap().branches["refs/heads/main"];
        assert!(
            b.moved && b.verdict.contains("trail lists mark"),
            "{}",
            b.verdict
        );
        assert_eq!(mirror_head(), c2);

        // a mark the trail does not list: fetched, held, nothing moves
        std::fs::write(up.join("NOTES.md"), "more\n").unwrap();
        git_ok(&up, &home, &["add", "-A"]);
        git_ok(&up, &home, &["commit", "--quiet", "-m", "unmarked work"]);
        let c3 = head(&up);
        relay.push(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &c3)],
            Some(("txbt4", &txo, &"d".repeat(40))),
            next(),
        ));
        let held = until("the held state", || async {
            record().filter(|r| {
                r.last_seen
                    .as_ref()
                    .is_some_and(|s| s.action == SeenAction::Held)
            })
        })
        .await;
        assert_eq!(held.last_fetch.as_ref().unwrap().moved, 0);
        assert!(
            held.last_fetch.as_ref().unwrap().branches["refs/heads/main"]
                .verdict
                .contains("does not list the marked commit dddddddd")
        );
        assert_eq!(
            mirror_head(),
            c2,
            "the branch stayed where the last verified state put it"
        );

        // 3. another key's state (same d) and an older state are ignored
        let events_before = record().unwrap().events;
        relay.push(state_event(
            &other,
            "up",
            &[("refs/heads/main", &"e".repeat(40))],
            None,
            next(),
        ));
        relay.push(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &"f".repeat(40))],
            None,
            1_760_000_000,
        ));
        let rec = until("the old state to be counted", || async {
            record().filter(|r| r.events == events_before + 1)
        })
        .await;
        let seen = rec.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::Skip);
        assert!(seen.reason.contains("older than a state already seen"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            record().unwrap().events,
            events_before + 1,
            "the other key's state was never counted"
        );

        // 4. a repository that is not a mirror has no record
        assert!(m.store().read(&"9".repeat(64), "none").is_none());
        handle.stop().await;
    }

    #[tokio::test]
    async fn a_followed_repo_without_a_clone_url_still_records_why() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(9);
        let pubk = pubhex(&sk);
        let cfg = MirrorConfig {
            relays: vec!["ws://127.0.0.1:1".into()],
            follow: vec![FollowEntry {
                pubkey: pubk.clone(),
                name: "noclone".into(),
                clone: None,
            }],
            min_interval_ms: 0,
        };
        let m = engine(tmp.path(), cfg);
        let ev = state_event(
            &sk,
            "noclone",
            &[("refs/heads/main", &"a".repeat(40))],
            None,
            1_760_000_100,
        );
        let rec = m.on_event(&ev).await.unwrap();
        let seen = rec.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::Skip);
        assert!(seen.reason.contains("no clone URL"));
        assert!(
            !tmp.path()
                .join("repos")
                .join(&pubk)
                .join("noclone.git")
                .exists(),
            "no bare repo was made"
        );
        assert!(
            m.store().read(&pubk, "noclone").is_some(),
            "the record is served so the reason is visible"
        );
    }

    #[tokio::test]
    async fn a_30617_supplies_the_clone_url_and_a_forged_event_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(10);
        let pubk = pubhex(&sk);
        let cfg = MirrorConfig {
            relays: vec!["ws://127.0.0.1:1".into()],
            follow: vec![FollowEntry {
                pubkey: pubk.clone(),
                name: "x".into(),
                clone: None,
            }],
            min_interval_ms: 0,
        };
        let m = engine(tmp.path(), cfg);
        let ann = sign(
            &sk,
            KIND_ANNOUNCE,
            tags(&[
                &["d", "x"],
                &["clone", "file:///etc", "https://h.example/x.git"],
            ]),
            50,
        );
        let rec = m.on_event(&ann).await.unwrap();
        assert_eq!(
            rec.clone.as_deref(),
            Some("https://h.example/x.git"),
            "file:// from a remote is never taken"
        );
        assert!(
            m.on_event(&ann).await.is_none(),
            "an announcement that is not newer changes nothing"
        );
        let mut forged = sign(
            &sk,
            KIND_ANNOUNCE,
            tags(&[&["d", "x"], &["clone", "https://evil.example/x.git"]]),
            99,
        );
        forged.sig = "0".repeat(128);
        assert!(m.on_event(&forged).await.is_none());
        assert_eq!(
            m.store().read(&pubk, "x").unwrap().clone.as_deref(),
            Some("https://h.example/x.git")
        );
    }

    #[tokio::test]
    async fn the_default_ssrf_policy_refuses_a_loopback_clone_from_a_remote_announcement() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(11);
        let pubk = pubhex(&sk);
        let cfg = MirrorConfig {
            relays: vec!["ws://127.0.0.1:1".into()],
            follow: vec![FollowEntry {
                pubkey: pubk.clone(),
                name: "x".into(),
                clone: None,
            }],
            min_interval_ms: 0,
        };
        let m = Arc::new(Mirror::new(
            cfg,
            MirrorStore::new(tmp.path()),
            Arc::new(GitCli::new(tmp.path().join("repos"))),
        ));
        m.on_event(&sign(
            &sk,
            KIND_ANNOUNCE,
            tags(&[&["d", "x"], &["clone", "http://127.0.0.1:9/x.git"]]),
            50,
        ))
        .await;
        let rec = m
            .on_event(&state_event(
                &sk,
                "x",
                &[("refs/heads/main", &"a".repeat(40))],
                None,
                60,
            ))
            .await
            .unwrap();
        let seen = rec.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::FetchFailed);
        assert!(
            seen.reason.contains("clone host refused"),
            "{}",
            seen.reason
        );
    }

    #[test]
    fn records_round_trip_in_the_camel_case_shape_the_jss_forge_serves() {
        let tmp = tempfile::tempdir().unwrap();
        let store = MirrorStore::new(tmp.path());
        let pubk = "a".repeat(64);
        let mut rec = MirrorRecord::new(&pubk, "x", None);
        rec.last_seen = Some(LastSeen {
            id: "i".into(),
            created_at: 5,
            at: 6,
            action: SeenAction::FetchFailed,
            reason: "r".into(),
        });
        store.save(&rec).unwrap();
        let raw: Value = serde_json::from_slice(
            &std::fs::read(tmp.path().join("mirror").join(&pubk).join("x.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(raw["lastSeen"]["action"], "fetch-failed");
        assert_eq!(raw["lastSeen"]["created_at"], 5);
        assert_eq!(store.read(&pubk, "x").unwrap(), rec);
        assert!(store.read("../..", "x").is_none());
        assert!(store.save(&MirrorRecord::new("../x", "y", None)).is_err());
    }

    // ---- security review L2 / L3 -----------------------------------------

    fn entry_for(sk: &SigningKey) -> FollowEntry {
        FollowEntry {
            pubkey: pubhex(sk),
            name: "up".into(),
            clone: None,
        }
    }

    fn quiet_engine(tmp: &Path, sk: &SigningKey) -> Arc<Mirror> {
        engine(
            tmp,
            MirrorConfig {
                relays: vec![],
                follow: vec![entry_for(sk)],
                min_interval_ms: 0,
            },
        )
    }

    /// L3: a state stamped hours ahead must not raise the replay clock.
    #[tokio::test]
    async fn far_future_state_is_refused_and_does_not_freeze_the_clock() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(21);
        let m = quiet_engine(tmp.path(), &sk);
        let entry = entry_for(&sk);
        let sha = "a".repeat(40);
        let now = SystemClock.now_ms() / 1000;
        let future = state_event(&sk, "up", &[("refs/heads/main", &sha)], None, now + 7200);
        let rec = m.apply(&entry, &future).await;
        assert_eq!(rec.newest_seen_at, 0, "clock untouched");
        let seen = rec.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::Skip);
        assert!(seen.reason.contains("future"), "{}", seen.reason);
        // An honest state afterwards is not mistaken for a replay.
        let honest = state_event(&sk, "up", &[("refs/heads/main", &sha)], None, now);
        let rec = m.apply(&entry, &honest).await;
        assert!(
            !rec.last_seen.unwrap().reason.contains("replay"),
            "honest state wrongly treated as a replay"
        );
        assert_eq!(rec.newest_seen_at, now);
    }

    /// L3: two states at the same second are ordered by id; the higher id,
    /// arriving second, is dropped, and the same id again is the catch-up
    /// resend and is kept.
    #[tokio::test]
    async fn equal_timestamps_resolve_by_event_id() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(22);
        let m = quiet_engine(tmp.path(), &sk);
        let entry = entry_for(&sk);
        let at = SystemClock.now_ms() / 1000 - 30;
        let mut pair = [
            state_event(&sk, "up", &[("refs/heads/main", &"a".repeat(40))], None, at),
            state_event(&sk, "up", &[("refs/heads/main", &"b".repeat(40))], None, at),
        ];
        pair.sort_by(|x, y| x.id.cmp(&y.id));
        let [low, high] = pair;
        let rec = m.apply(&entry, &low).await;
        assert!(!rec.last_seen.unwrap().reason.contains("replay"));
        let rec = m.apply(&entry, &high).await;
        let seen = rec.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::Skip);
        assert!(seen.reason.contains("replay"), "{}", seen.reason);
        let rec = m.apply(&entry, &low).await;
        assert!(
            !rec.last_seen.unwrap().reason.contains("replay"),
            "the same state resent is a catch-up, not a replay"
        );
    }

    /// L2: when the worker cannot take a fetch permit it used to return with
    /// the repository still marked busy, so later events never started a
    /// worker. The guard must release the slot.
    #[tokio::test]
    async fn drain_releases_the_busy_slot_when_it_cannot_run() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(23);
        let m = quiet_engine(tmp.path(), &sk);
        m.permits.close();
        let sha = "c".repeat(40);
        let at = SystemClock.now_ms() / 1000 - 5;
        m.enqueue(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &sha)],
            None,
            at,
        ));
        until("the busy slot to be released", || async {
            m.busy.lock().unwrap().is_empty().then_some(())
        })
        .await;
    }

    /// L3: the inbox itself refuses a far-future event, so it cannot shadow an
    /// honest one while a worker is busy.
    #[tokio::test]
    async fn enqueue_drops_far_future_events() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = key(24);
        let m = quiet_engine(tmp.path(), &sk);
        m.permits.close();
        let sha = "d".repeat(40);
        let now = SystemClock.now_ms() / 1000;
        m.enqueue(state_event(
            &sk,
            "up",
            &[("refs/heads/main", &sha)],
            None,
            now + 7200,
        ));
        assert!(m.inbox.lock().unwrap().is_empty());
    }

    /// L4: a size walk that takes far longer than the deadline must not
    /// delay the deadline (it used to be awaited inside the `select!`).
    #[tokio::test]
    async fn slow_size_walk_cannot_starve_the_deadline() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        fn slow(_: &Path) -> u64 {
            std::thread::sleep(Duration::from_secs(4));
            0
        }
        let tmp = tempfile::tempdir().unwrap();
        let m = GitCli::new(tmp.path().join("repos"));
        let started = std::time::Instant::now();
        let r = m
            .run_capped_with(
                tmp.path(),
                &["-c", "alias.nap=!sleep 20", "nap"],
                None,
                Duration::from_millis(1700),
                Some(1),
                slow,
            )
            .await;
        assert_eq!(r.unwrap_err(), "git timed out");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }
}
