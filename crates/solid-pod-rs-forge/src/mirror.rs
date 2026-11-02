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
//! The fetch lands in a private *candidate* store outside the served tree,
//! and the verdict is reached there. Only approved commits are then pushed,
//! by SHA, into the *served* store every reader uses (see [`GitCli`] for the
//! layout). Publishing an approved commit publishes its whole history, as
//! git must: every ancestor of an approved tip becomes readable by SHA. A
//! *held* commit is one not reachable from any approved tip; such a commit
//! is never readable through the forge. A held commit that a later approved
//! tip descends from is published with that tip, and a commit once approved
//! stays readable after a later approved move leaves it behind.
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
//!    environment, candidate and served stores kept apart, publication by
//!    one leased atomic push), and [`Mirror::start`] runs one relay session per relay
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
pub use crate::PUBLICATION_MARKER;

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
/// pushes the candidate store past this is killed and the candidate removed;
/// a publication that grows the served store by more than this is killed.
pub const MAX_REPO_BYTES: u64 = 512 * 1024 * 1024;
/// The admission threshold for publication, in bytes: a served store
/// already larger than this (receive-pack quarantine directories not
/// counted) refuses publication before any push starts. It is not a hard
/// cap on the total: an admitted publication may still grow the store by
/// up to [`MAX_REPO_BYTES`] past it, and that growth is measured by polling
/// (every 500 ms), so a push can finish between two measurements. Served
/// never shrinks (commits orphaned by approved force moves stay). A refusal
/// is not retried: it needs an operator, or a newer state once the store
/// has been pruned.
pub const MAX_SERVED_BYTES: u64 = 4 * MAX_REPO_BYTES;
/// Fetches that may run at once across all followed repositories.
pub const MAX_CONCURRENT_FETCHES: usize = 4;
/// Longest the failure backoff stretches the fetch floor to, in milliseconds.
pub const MAX_BACKOFF_MS: u64 = 3_600_000;
/// Timeouts of the newest state (fetch, publication, or examining the
/// store) and failed DNS lookups of its clone host, after which it is no
/// longer retried: a remote or store that keeps outrunning its budget needs
/// a newer state or an operator, not another identical attempt.
///
/// The count lives in the saved [`MirrorRecord`]. A repository followed for
/// the first time whose existing store could not be examined has no record
/// yet (none is saved beside an unprepared store), so its retries are
/// bounded only by the backoff floor until the store can be examined, a
/// newer state arrives, or the process restarts.
pub const MAX_TIMEOUTS: u32 = 3;
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
    /// Consecutive failed applies: a store that could not be examined, or a
    /// failed materialise, fetch or publication.
    /// The floor between fetches doubles for each, up to [`MAX_BACKOFF_MS`],
    /// and only a completed apply resets it.
    #[serde(default)]
    pub failures: u32,
    /// Millisecond clock at which the latest state is worth applying again:
    /// set when the rate limit held it back, or when examining its store, or
    /// its materialise, fetch or publication, failed in a way that may pass
    /// on a retry (never sooner
    /// than [`backoff_delay`] of [`Self::failures`] after the failure).
    /// Unset when nothing is waiting, or when the refusal will not pass on a
    /// retry: a fetch past the size cap, a refused clone URL or address, a
    /// terminal [`PublishError`], or [`MAX_TIMEOUTS`] timeouts of the state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<u64>,
    /// Whether this record was first written under publication isolation.
    /// A record without it predates this release, so its served store may
    /// hold content the old shared layout fetched but never approved.
    #[serde(default)]
    pub isolated: bool,
    /// Whether the served store was found in the pre-isolation layout and
    /// waits for migration. Persisted so the store is examined once, not on
    /// every event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub awaits_migration: bool,
    /// Timeouts of the newest state seen, in its fetch, its publication or
    /// the examination of its store, and failed DNS lookups of its clone
    /// host; at [`MAX_TIMEOUTS`] the state is no longer retried. Reset only
    /// when a newer state arrives or an apply completes, not by another
    /// kind of failure in between (security I5). Counted only once a record
    /// is saved; see [`MAX_TIMEOUTS`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub timeouts: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
fn is_zero(n: &u32) -> bool {
    *n == 0
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
            isolated: true,
            awaits_migration: false,
            timeouts: 0,
        }
    }
}

/// Reads and writes [`MirrorRecord`] files under a directory.
#[derive(Debug, Clone)]
pub struct MirrorStore {
    dir: PathBuf,
}

/// What [`MirrorStore::load`] found at a record path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredRecord {
    /// No record file: the repository is not (yet) a mirror.
    Missing,
    /// A record file exists but cannot be read or parsed. The repository is
    /// still a mirror: readers refuse it, and the engine leaves the file in
    /// place and treats the store as awaiting migration. The reason names
    /// no path.
    Unreadable(String),
    /// A valid record.
    Valid(Box<MirrorRecord>),
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

    /// `plugin_dir/mirror-work/locks/<owner>/<name>.lock`, the cross-process
    /// advisory lock for one repository (design §3).
    fn lock_file(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        Some(
            self.dir
                .parent()?
                .join("mirror-work")
                .join("locks")
                .join(owner)
                .join(format!("{name}.lock")),
        )
    }

    /// The record for `(owner, name)` when it is present and valid; `None`
    /// when it is missing *or* cannot be read or parsed. Use [`Self::load`]
    /// to tell those apart: an unreadable record still marks a mirror.
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
        match self.load(owner, name) {
            StoredRecord::Valid(rec) => Some(*rec),
            StoredRecord::Missing | StoredRecord::Unreadable(_) => None,
        }
    }

    /// The record for `(owner, name)`, telling a missing file from one that
    /// exists but cannot be read or parsed. An owner or name that is not a
    /// safe record key (a 64-hex owner, a valid repository name) has no
    /// record path, so no record can exist for it: [`StoredRecord::Missing`],
    /// as the reader gate's own path check also finds. Otherwise `Missing`
    /// means no directory entry exists; a symlink at the path, dangling or
    /// not, is [`StoredRecord::Unreadable`].
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::mirror::{MirrorStore, StoredRecord};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let store = MirrorStore::new(dir.path());
    /// let owner = "a".repeat(64);
    /// assert!(matches!(store.load(&owner, "x"), StoredRecord::Missing));
    /// assert!(matches!(store.load("alice", "x"), StoredRecord::Missing));
    /// std::fs::create_dir_all(dir.path().join("mirror").join(&owner)).unwrap();
    /// std::fs::write(dir.path().join("mirror").join(&owner).join("x.json"), b"{").unwrap();
    /// assert!(matches!(store.load(&owner, "x"), StoredRecord::Unreadable(_)));
    /// ```
    #[must_use]
    pub fn load(&self, owner: &str, name: &str) -> StoredRecord {
        let Some(path) = self.file(owner, name) else {
            return StoredRecord::Missing;
        };
        // Missing only when no directory entry exists. An entry that is a
        // symlink, dangling or not, is not a record this store wrote.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return StoredRecord::Unreadable("is a symbolic link".into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoredRecord::Missing,
            Err(e) => return StoredRecord::Unreadable(format!("cannot be read: {}", e.kind())),
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            // The entry existed a moment ago: not "no record".
            Err(e) => return StoredRecord::Unreadable(format!("cannot be read: {}", e.kind())),
        };
        match serde_json::from_slice(&bytes) {
            Ok(rec) => StoredRecord::Valid(Box::new(rec)),
            Err(e) => StoredRecord::Unreadable(format!("is not a valid record: {e}")),
        }
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

/// One approved branch move handed to [`MirrorGit::publish`].
///
/// [`Mirror::apply`] builds these only from branches whose
/// [`branch_verdict`] passed; a held branch never becomes a `RefUpdate`.
/// Publishing `sha` publishes its whole history: "held" means not reachable
/// from any approved tip, not "never served" (a held tip that is an ancestor
/// of an approved one is served with it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// The branch, `refs/heads/<name>`.
    pub git_ref: String,
    /// The approved commit the branch moves to (40 lowercase hex).
    pub sha: String,
    /// The served sha the move was planned against, or `None` when the
    /// branch must not exist yet. Publication fails if served has moved.
    ///
    /// The lease gives atomicity, not preservation: a stale lease is a
    /// retryable failure, and the retry leases on the value served then has,
    /// so a branch moved behind the engine (a merge or web edit on the
    /// served store) is overwritten by the retry. Upstream is authoritative
    /// for a mirror.
    pub expected: Option<String>,
}

/// What [`MirrorGit::prepare`] found in an existing served store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepared {
    /// Absent, or marked with [`PUBLICATION_MARKER`]: ready to be followed.
    Ready,
    /// The pre-isolation layout (`refs/mirror`, or `hideRefs` of them), a
    /// store borrowing objects through alternates, or a store with mirror
    /// history from before this release holding an object no branch or tag
    /// reaches. It stays unmarked, so every reader refuses it, and
    /// [`Mirror::apply`] neither fetches for it nor retries it until
    /// migration rebuilds it; the verdict is kept in
    /// [`MirrorRecord::awaits_migration`]. Only positive evidence gives this
    /// verdict; a check that could not be made is an error instead.
    AwaitsMigration,
}

/// Why [`MirrorGit::publish`] failed. On any failure no branch has moved.
///
/// A stale lease is retryable: the retry leases on served's current value,
/// so a branch moved behind the engine is overwritten then (see
/// [`RefUpdate::expected`]). A push killed by the growth cap, an unmarked
/// or unreadable served store, and a store past [`MAX_SERVED_BYTES`] are
/// terminal.
///
/// ```
/// use solid_pod_rs_forge::mirror::PublishError;
///
/// let e = PublishError::terminal("the served repository is past its size ceiling");
/// assert!(!e.retryable);
/// assert!(PublishError::from("git timed out".to_string()).retryable);
/// assert_eq!(e.to_string(), e.reason);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError {
    /// A human-readable reason, free of store and plugin paths: it is saved
    /// in the public mirror record.
    pub reason: String,
    /// Whether the same publication may succeed if tried again (a ref lock,
    /// a timeout, a stale lease). [`Mirror::apply`] schedules a retry only
    /// for these; a refusal that cannot change without an operator (a store
    /// awaiting migration, or one past [`MAX_SERVED_BYTES`]) waits for a
    /// newer state instead.
    pub retryable: bool,
    /// Whether the push ran out of its time budget (120 s). A timeout is
    /// retryable, but [`Mirror::apply`] stops retrying one state after
    /// [`MAX_TIMEOUTS`] of its timeouts.
    pub timed_out: bool,
}

impl PublishError {
    /// A failure that cannot change by trying the same publication again.
    #[must_use]
    pub fn terminal(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            retryable: false,
            timed_out: false,
        }
    }
}

/// A plain reason is a transient failure.
impl From<String> for PublishError {
    fn from(reason: String) -> Self {
        Self {
            reason,
            retryable: true,
            timed_out: false,
        }
    }
}

/// A plain reason is a transient failure.
impl From<&str> for PublishError {
    fn from(reason: &str) -> Self {
        reason.to_string().into()
    }
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for PublishError {}

/// The git operations the engine needs. [`GitCli`] is the real adapter;
/// tests substitute fakes. Every method takes the already-validated
/// `(owner, name)` pair; implementations must still treat the strings as
/// untrusted.
///
/// Two stores stand behind each pair. The *served* store is what every
/// forge reader (raw, HTML, JSON, archive, smart-HTTP) sees, and it only
/// ever gains approved commits. The private *candidate* store takes the
/// fetch and answers the verdict reads ([`Self::has_commit`],
/// [`Self::is_ancestor`], [`Self::read_trail`]); nothing reaches served
/// except through [`Self::publish`].
#[async_trait]
pub trait MirrorGit: Send + Sync {
    /// Whether the served bare repository exists for `(owner, name)`.
    async fn exists(&self, owner: &str, name: &str) -> bool;
    /// `refs/heads/<b>` to sha in the served repository; empty when none.
    /// [`Mirror::apply`] reads this once and leases publication on it.
    async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String>;
    /// Create the empty served repository (marked with
    /// [`PUBLICATION_MARKER`]) and the private candidate store.
    ///
    /// # Errors
    ///
    /// A human-readable reason.
    async fn materialise(&self, owner: &str, name: &str) -> Result<(), String>;
    /// Make an existing served store ready to be followed, before any record
    /// for it is saved. [`GitCli`] marks a clean store (no `refs/mirror`, no
    /// `hideRefs` of them, no alternates) with [`PUBLICATION_MARKER`] and the
    /// fixed served config, and reports one in the pre-isolation layout as
    /// [`Prepared::AwaitsMigration`]; that store stays unmarked and so
    /// refused (503) by every reader until it is migrated. With `scan`,
    /// which [`Mirror`] sets only for a store whose record predates this
    /// release, a store holding any object no branch or tag reaches is
    /// reported the same way; an owner's store is never scanned.
    /// [`Mirror`] calls this under the repository lock for an existing
    /// served store before a first record is saved beside it, and otherwise
    /// once an event has passed the replay check and no awaits-migration
    /// verdict is recorded, so a followed clean repository is not gated by
    /// its own record. There is deliberately no default: an adapter that did nothing
    /// here would leave every followed clean repository at 503.
    ///
    /// # Errors
    ///
    /// A human-readable reason when the store could not be examined (a git
    /// timeout, a config or refs read that failed, an alternates check that
    /// failed, a scan that could not complete). That is not a verdict: the
    /// store is left as it was, unmarked, and [`Mirror`] retries it with the
    /// backoff instead of recording [`Prepared::AwaitsMigration`].
    async fn prepare(&self, owner: &str, name: &str, scan: bool) -> Result<Prepared, String>;
    /// Fetch every branch of `clone` into the private candidate store's
    /// `refs/mirror/*`; the served store is not touched. `operator` is
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
    /// Whether the commit is present in the candidate after the fetch.
    async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool;
    /// Whether `ancestor` is `descendant` or in its history, judged in the
    /// candidate.
    async fn is_ancestor(&self, owner: &str, name: &str, ancestor: &str, descendant: &str) -> bool;
    /// The [`TRAIL_FILE`] at `sha` in the candidate, if present and within
    /// [`MAX_TRAIL_BYTES`].
    async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String>;
    /// Publish exactly these approved commits, with their whole history, into
    /// the served store, atomically (every branch moves or none does), each
    /// leased on its [`RefUpdate::expected`]; then point `HEAD` at `head` if
    /// it was among them. Nothing else from the candidate may reach served:
    /// no object outside the history of `updates`, on any path, including a
    /// failure after receive-pack has migrated its quarantine (objects of
    /// that history may then land unreferenced). An ancestor of an approved
    /// commit is published with it, whatever its own verdict was.
    ///
    /// # Errors
    ///
    /// A [`PublishError`]: its reason is free of store and plugin paths (it
    /// is saved in the public mirror record), and it says whether trying the
    /// same publication again could succeed. On error no branch has moved.
    async fn publish(
        &self,
        owner: &str,
        name: &str,
        updates: &[RefUpdate],
        head: Option<&str>,
    ) -> Result<(), PublishError>;
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

/// The `--receive-pack` command publication runs on the served side.
///
/// Local transport strips the pusher's `-c` options before receive-pack
/// starts, so this string (with the served store's own config) is the hook
/// boundary. Git runs it through a shell: it is a fixed literal, equal to
/// `solid_pod_rs_git::hardened::HARDENED_CONFIG` plus the receive keys
/// (pinned by `receive_pack_command_is_a_fixed_hardened_constant`). Never
/// interpolate a path, name or sha into it; that would be shell injection.
const RECEIVE_PACK: &str = "git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
-c core.sshCommand=false -c commit.gpgSign=false -c receive.fsckObjects=true \
-c receive.denyDeletes=true receive-pack";

/// The reason recorded for a served store in the pre-isolation layout.
const AWAITS_MIGRATION: &str =
    "the served repository predates publication isolation and awaits migration";

/// Whether an SSRF check refused a host because its name did not resolve
/// (a lookup failure, or no addresses), not because of where it pointed.
/// [`SsrfCheck`] reports only a string, so this matches the text of
/// `solid_pod_rs::security::ssrf::SsrfError`'s two resolution variants, as
/// [`DefaultSsrfCheck`] renders them; a test pins that text. Any other
/// refusal, from any check, is a policy refusal.
fn resolution_failed(why: &str) -> bool {
    why.starts_with("DNS resolution failed for host ")
        || why.starts_with("DNS resolution returned no addresses for host ")
}

/// Whether `git config --list -z` output sets `uploadpack.hideRefs` or
/// `transfer.hideRefs` to a value naming `refs/mirror`. Each entry is
/// `key\nvalue\0`; git prints section and variable names in lower case.
fn hides_mirror_refs(list_z: &[u8]) -> bool {
    list_z.split(|b| *b == 0).any(|entry| {
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = entry.split_once('\n').unwrap_or((&entry, ""));
        let key = key.to_ascii_lowercase();
        (key == "uploadpack.hiderefs" || key == "transfer.hiderefs")
            && value.contains("refs/mirror")
    })
}

/// The refusal of a clone URL that is not one the mirror may fetch. Both
/// the engine and [`GitCli`]'s own check return exactly this, so it is
/// classified terminal on either path (security S5).
const CLONE_URL_REFUSED: &str = "clone URL refused";

/// Wall-clock budget for one publication push.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(120);

/// [`GitCli::run_in`]'s error when git outran its deadline.
const GIT_TIMED_OUT: &str = "git timed out";
/// [`GitCli::run_in`]'s (and the fetch's) error when a store grew past its
/// size cap.
const GREW_PAST_CAP: &str = "repository grew past the size cap";

/// How a failed publication push is classified: a growth-cap kill is
/// terminal (the same push grows the same way again), a timeout is
/// retryable and flagged, and anything else (a stale lease, a receiver ref
/// lock) is retryable.
fn push_failure(reason: String) -> PublishError {
    if reason == GREW_PAST_CAP {
        PublishError::terminal(reason)
    } else if reason == GIT_TIMED_OUT {
        PublishError {
            reason,
            retryable: true,
            timed_out: true,
        }
    } else {
        PublishError::from(reason)
    }
}

/// Config every served store carries, written when it is created or first
/// marked: no hooks, objects checked on receipt, no ref deletion.
const SERVED_CONFIG: [(&str, &str); 3] = [
    ("core.hooksPath", "/dev/null"),
    ("receive.fsckObjects", "true"),
    ("receive.denyDeletes", "true"),
];

/// The `git` command-line adapter, rooted at `repo_root`, which must be the
/// forge's `plugin_dir/repos` (the root the Git CGI and every reader
/// serve). The other stores are derived from its parent:
///
/// ```text
/// plugin_dir/repos/<owner>/<name>.git                       served: approved closure only, marker inside
/// plugin_dir/mirror-work/candidates/<owner>/<name>.git      private fetch and validation store
/// plugin_dir/mirror-work/staging/<owner>/<name>.git.<uuid>  a new served store under construction
/// plugin_dir/mirror-work/locks/<owner>/<name>.lock          cross-process lock, held across Mirror::apply
/// ```
///
/// Nothing private may live under `repos/`: the CGI exports every bare
/// repository below it, so a candidate or staging store there could be
/// cloned anonymously. A mirrored repository browses like any pushed one.
///
/// Every spawn goes through [`solid_pod_rs_git::hardened_git_async`] (no
/// hooks, no ambient config, no prompts) with an argv; the clone URL is
/// passed after `--`, and `GIT_ALLOW_PROTOCOL` restricts transports to
/// `http`/`https` (plus `file` only for an operator-configured clone and
/// the local publication push). Remote clones also refuse HTTP redirects.
#[derive(Debug, Clone)]
pub struct GitCli {
    repo_root: PathBuf,
    /// `plugin_dir/mirror-work`; `None` when `repo_root` has no parent, in
    /// which case every candidate operation fails closed.
    work_root: Option<PathBuf>,
    /// Test seam: run on the served path just before the publication push
    /// starts, to stand in for a concurrent owner push.
    #[cfg(test)]
    during_push: Option<fn(&Path)>,
    /// Test seam: the size measure the publication watcher polls, in place
    /// of the real directory walk.
    #[cfg(test)]
    push_measure: Option<DirMeasure>,
    /// Test seam: the arguments of the legacy check's config read, in place
    /// of the real ones, to make that read fail.
    #[cfg(test)]
    config_args: Option<&'static [&'static str]>,
}

impl GitCli {
    /// An adapter over `repo_root`, which must be the forge's
    /// `plugin_dir/repos`; the candidate, staging and lock paths are derived
    /// from its parent. A relative root is made absolute here, because
    /// publication runs git in one store and names the other by path.
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        let raw = repo_root.into();
        let repo_root = std::path::absolute(&raw).unwrap_or(raw);
        let work_root = repo_root.parent().map(|p| p.join("mirror-work"));
        Self {
            repo_root,
            work_root,
            #[cfg(test)]
            during_push: None,
            #[cfg(test)]
            push_measure: None,
            #[cfg(test)]
            config_args: None,
        }
    }

    /// The served store.
    fn dir(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        Some(self.repo_root.join(owner).join(format!("{name}.git")))
    }

    /// The private candidate store, outside `repos/`.
    fn candidate(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        let work = self.work_root.as_ref()?;
        Some(
            work.join("candidates")
                .join(owner)
                .join(format!("{name}.git")),
        )
    }

    /// A fresh staging path for a new served store, outside `repos/`.
    fn staging(&self, owner: &str, name: &str) -> Option<PathBuf> {
        if !is_hex64(owner) || !is_repo_name(name) {
            return None;
        }
        let work = self.work_root.as_ref()?;
        let unique = uuid::Uuid::new_v4().simple();
        Some(
            work.join("staging")
                .join(owner)
                .join(format!("{name}.git.{unique}")),
        )
    }

    async fn init_bare(&self, dir: &Path) -> Result<(), String> {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| e.to_string())?;
        self.run(
            dir,
            &["init", "--bare", "--quiet", "--initial-branch=main", "."],
            None,
            Duration::from_secs(15),
        )
        .await
        .map(|_| ())
    }

    /// The candidate store, created empty when absent (first use, or after
    /// a failed fetch removed it) and rebuilt whole when it is present but
    /// not a repository (`HEAD`, `objects/` or `refs/` missing, as after a
    /// removal that failed part-way; security review L1).
    async fn ensure_candidate(&self, owner: &str, name: &str) -> Result<PathBuf, String> {
        let dir = self
            .candidate(owner, name)
            .ok_or("no candidate store location")?;
        if is_bare_store(&dir).await {
            return Ok(dir);
        }
        remove_store(&dir).await;
        if let Err(e) = self.init_bare(&dir).await {
            remove_store(&dir).await;
            return Err(e);
        }
        Ok(dir)
    }

    async fn write_served_config(&self, dir: &Path) -> Result<(), String> {
        for (key, value) in SERVED_CONFIG {
            self.run(
                dir,
                &["config", "--local", key, value],
                None,
                Duration::from_secs(15),
            )
            .await?;
        }
        Ok(())
    }

    /// Init, configure and mark a served store in `staging`, then rename it
    /// into place, so `repos/` never shows a half-built store.
    async fn build_served(&self, staging: &Path, served: &Path) -> Result<(), String> {
        self.init_bare(staging).await?;
        self.write_served_config(staging).await?;
        write_marker(staging).await?;
        if let Some(parent) = served.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        tokio::fs::rename(staging, served)
            .await
            .map_err(|e| format!("could not place the served repository: {e}"))
    }

    /// Whether the store holds any object that no branch or tag reaches
    /// (Codex High 2). Such an object (a held blob left by the old shared
    /// layout, a dangling commit) is readable by SHA. Only run for a store
    /// with mirror history from before publication isolation (see
    /// [`MirrorGit::prepare`]); an owner's own store is never scanned.
    ///
    /// The roots are `refs/heads/*` and `refs/tags/*` only. `HEAD` is not a
    /// root (a detached `HEAD` would otherwise vouch for any commit), nor is
    /// any other namespace: `refs/mirror/*`, `refs/forge/heads/*` (pull
    /// request heads), `refs/notes/*`, `refs/stash` and the rest. So a
    /// detached `HEAD`, or any ref outside branches and tags, counts as
    /// holding such an object; then `git fsck --unreachable --no-reflogs
    /// --connectivity-only` (whose roots are `HEAD` and every ref, here
    /// exactly the branches and tags) must report nothing. Every command is
    /// streamed and stops at the first line that decides it, so nothing is
    /// buffered whole (security R1).
    async fn holds_unreachable_objects(&self, served: &Path) -> Result<bool, String> {
        let slow = Duration::from_secs(120);
        // `symbolic-ref -q` exits 1, silently, for a detached HEAD: that is
        // evidence. Any other failure (a timeout, git not starting, a fatal
        // exit) is not, and is returned so the store is retried, not judged
        // (security S6).
        let head = self
            .run_output(
                served,
                served,
                &["symbolic-ref", "-q", "HEAD"],
                None,
                Duration::from_secs(15),
                None,
            )
            .await?;
        match head.status.code() {
            Some(0) => {
                if !String::from_utf8_lossy(&head.stdout)
                    .trim()
                    .starts_with("refs/heads/")
                {
                    return Ok(true);
                }
            }
            Some(1) => return Ok(true),
            _ => {
                let err = String::from_utf8_lossy(&head.stderr);
                return Err(err
                    .lines()
                    .next()
                    .unwrap_or("git symbolic-ref failed")
                    .to_string());
            }
        }
        let other_ref = self
            .first_line(
                served,
                &["for-each-ref", "--format=%(refname)"],
                slow,
                |l| !(l.starts_with("refs/heads/") || l.starts_with("refs/tags/")),
            )
            .await?;
        if other_ref.is_some() {
            return Ok(true);
        }
        let unreachable = self
            .first_line(
                served,
                &[
                    "fsck",
                    "--unreachable",
                    "--no-reflogs",
                    "--connectivity-only",
                    "--no-progress",
                ],
                slow,
                |l| l.starts_with("unreachable ") || l.starts_with("dangling "),
            )
            .await?;
        Ok(unreachable.is_some())
    }

    /// Run git on the store at `git_dir` and read its stdout line by line,
    /// returning the first line `pick` accepts (git is then killed), or
    /// `None` once git has exited successfully without one. stderr is
    /// discarded; a failure is reported as `git <command> failed`.
    async fn first_line(
        &self,
        git_dir: &Path,
        args: &[&str],
        timeout: Duration,
        pick: impl Fn(&str) -> bool,
    ) -> Result<Option<String>, String> {
        use tokio::io::AsyncBufReadExt;
        let mut explicit = std::ffi::OsString::from("--git-dir=");
        explicit.push(git_dir);
        let mut cmd = solid_pod_rs_git::hardened_git_async();
        cmd.arg(explicit)
            .args(args)
            .current_dir(git_dir)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("git could not start: {e}"))?;
        let pid = child.id();
        let what = args.first().copied().unwrap_or("git");
        let stdout = child.stdout.take().ok_or("git has no stdout")?;
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let read = async {
            while let Some(line) = lines
                .next_line()
                .await
                .map_err(|e| format!("git {what} output unreadable: {e}"))?
            {
                if pick(&line) {
                    return Ok(Some(line));
                }
            }
            Ok(None)
        };
        let started = tokio::time::Instant::now();
        match tokio::time::timeout(timeout, read).await {
            Err(_) => {
                kill_group(pid).await;
                Err(GIT_TIMED_OUT.to_string())
            }
            Ok(Ok(None)) => {
                let left = timeout.saturating_sub(started.elapsed());
                match tokio::time::timeout(left, child.wait()).await {
                    Ok(Ok(st)) if st.success() => Ok(None),
                    Ok(_) => Err(format!("git {what} failed")),
                    Err(_) => {
                        kill_group(pid).await;
                        Err(GIT_TIMED_OUT.to_string())
                    }
                }
            }
            Ok(found) => {
                kill_group(pid).await;
                found
            }
        }
    }

    /// Whether the store shows the old shared layout: `refs/mirror/*`, or
    /// `hideRefs` naming them.
    ///
    /// # Errors
    ///
    /// Any failure to read the refs or the local config, so that a store
    /// whose layout could not be checked is never marked (security S2.1).
    /// The config is read whole (`--list`, which has no "unset" outcome),
    /// so no exit status is taken to mean "no hideRefs".
    async fn legacy_traces(&self, served: &Path) -> Result<bool, String> {
        let quick = Duration::from_secs(15);
        let mirror_refs = self
            .run(
                served,
                &[
                    "for-each-ref",
                    "--count=1",
                    "--format=%(refname)",
                    "refs/mirror",
                ],
                None,
                quick,
            )
            .await?;
        if !mirror_refs.is_empty() {
            return Ok(true);
        }
        let args: &[&str] = &["config", "--local", "--list", "-z"];
        #[cfg(test)]
        let args = self.config_args.unwrap_or(args);
        let config = self.run(served, args, None, quick).await?;
        Ok(hides_mirror_refs(&config))
    }

    /// Locked decision 3, as revised in round 5: a served store without the
    /// marker is marked (with the fixed config) unless it shows the old
    /// shared layout. Refused (left unmarked and gated until migration):
    /// one that borrows objects through alternates; one that has
    /// `refs/mirror` or hides them; and, only when `scan` is set (the store
    /// has mirror history from before this release), one holding any object
    /// no branch or tag reaches ([`Self::holds_unreachable_objects`]). An
    /// owner's store first followed under publication isolation is not
    /// scanned: its unreachable objects (a force push, a deleted branch)
    /// are the owner's own (security R1, overturning locked decision 13).
    async fn mark_clean_store(&self, served: &Path, scan: bool) -> Result<Prepared, String> {
        if tokio::fs::metadata(served.join(PUBLICATION_MARKER))
            .await
            .is_ok_and(|m| m.is_file())
        {
            return Ok(Prepared::Ready);
        }
        if has_alternates(served).await? {
            return Ok(Prepared::AwaitsMigration);
        }
        if self.legacy_traces(served).await?
            || (scan && self.holds_unreachable_objects(served).await?)
        {
            return Ok(Prepared::AwaitsMigration);
        }
        self.write_served_config(served).await?;
        write_marker(served).await?;
        Ok(Prepared::Ready)
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

    /// [`Self::run_capped`] with the directory measurement injectable.
    async fn run_capped_with(
        &self,
        dir: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
        cap: Option<u64>,
        measure: fn(&Path) -> u64,
    ) -> Result<Vec<u8>, String> {
        let cap = cap.map(|limit| (limit, measure));
        self.run_in(dir, dir, args, allow, timeout, cap).await
    }

    /// Run git on the store at `git_dir`, named with an explicit
    /// `--git-dir` so git never searches upward: a store missing `HEAD`,
    /// `objects/` or `refs/` fails instead of resolving to whatever
    /// repository encloses it (security review L1). `watch` is git's
    /// working directory and, with `cap = (limit, measure)`, the directory
    /// measured: it is measured at once and then every 500 ms while git
    /// runs, and the group is killed once it is past `limit`. The walk runs
    /// on its own task and only signals when the cap is passed, so a slow
    /// walk of a huge repository can neither stall the draining of git's
    /// pipes nor delay the deadline (security review L4).
    async fn run_in(
        &self,
        git_dir: &Path,
        watch: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
        cap: Option<(u64, DirMeasure)>,
    ) -> Result<Vec<u8>, String> {
        let out = self
            .run_output(git_dir, watch, args, allow, timeout, cap)
            .await?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(err.lines().next().unwrap_or("git failed").to_string())
        }
    }

    /// [`Self::run_in`] without the exit-status check: git's whole output,
    /// for a caller that must tell one non-zero status from another.
    /// `Err` only when git could not be run to completion (it could not
    /// start, it timed out, the cap killed it).
    async fn run_output(
        &self,
        git_dir: &Path,
        watch: &Path,
        args: &[&str],
        allow: Option<&str>,
        timeout: Duration,
        cap: Option<(u64, DirMeasure)>,
    ) -> Result<std::process::Output, String> {
        let mut explicit = std::ffi::OsString::from("--git-dir=");
        explicit.push(git_dir);
        let mut cmd = solid_pod_rs_git::hardened_git_async();
        cmd.arg(explicit)
            .args(args)
            .current_dir(watch)
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
        let watcher = cap.map(|(limit, measure)| {
            let d = watch.to_path_buf();
            tokio::spawn(async move {
                loop {
                    let d2 = d.clone();
                    let size = tokio::task::spawn_blocking(move || measure(&d2))
                        .await
                        .unwrap_or(0);
                    if size > limit {
                        let _ = tx.send(());
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            })
        });
        let outcome = tokio::select! {
            out = &mut waited => Ok(out),
            () = &mut deadline => Err(GIT_TIMED_OUT.to_string()),
            Ok(()) = &mut grew => Err(GREW_PAST_CAP.to_string()),
        };
        if let Some(w) = watcher {
            w.abort();
        }
        match outcome {
            Ok(out) => out.map_err(|e| format!("git failed: {e}")),
            Err(why) => {
                kill_group(pid).await;
                Err(why)
            }
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

/// Write [`PUBLICATION_MARKER`] into a served store: a temporary file, then
/// a rename, so a reader never sees a partial marker.
async fn write_marker(dir: &Path) -> Result<(), String> {
    let tmp = dir.join(format!("{PUBLICATION_MARKER}.tmp"));
    tokio::fs::write(&tmp, format!("{PUBLICATION_MARKER}\n"))
        .await
        .map_err(|e| format!("could not write the publication marker: {e}"))?;
    tokio::fs::rename(&tmp, dir.join(PUBLICATION_MARKER))
        .await
        .map_err(|e| format!("could not write the publication marker: {e}"))
}

/// Remove a private store whole (a failed, oversize or half-built
/// candidate, or a staging store). It is recreated on next use, so this is
/// cheaper and stronger than `gc --prune=now`, and its size cannot ratchet.
async fn remove_store(dir: &Path) {
    if let Err(e) = tokio::fs::remove_dir_all(dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(dir = %dir.display(), error = %e, "forge: mirror store not removed");
        }
    }
}

/// How a capped git run measures the directory it watches (injectable so
/// tests can stand in a slow or fixed measurement).
type DirMeasure = fn(&Path) -> u64;

/// Whether `dir` looks like a bare repository to git (`HEAD`, `objects/`
/// and `refs/` present). Anything less is rebuilt, never handed to git.
async fn is_bare_store(dir: &Path) -> bool {
    tokio::fs::metadata(dir.join("HEAD"))
        .await
        .is_ok_and(|m| m.is_file())
        && tokio::fs::metadata(dir.join("objects"))
            .await
            .is_ok_and(|m| m.is_dir())
        && tokio::fs::metadata(dir.join("refs"))
            .await
            .is_ok_and(|m| m.is_dir())
}

/// Whether a store borrows objects from elsewhere: `objects/info/alternates`
/// or `objects/info/http-alternates` is present. Objects reached that way
/// are readable through served but live outside it, so neither marking nor
/// publication can vouch for them. A path that cannot be checked (any
/// error but "not found") is returned as `Err`: neither presence nor
/// absence, so the caller neither marks the store nor records a verdict.
async fn has_alternates(served: &Path) -> Result<bool, String> {
    let info = served.join("objects").join("info");
    for file in ["alternates", "http-alternates"] {
        match tokio::fs::symlink_metadata(info.join(file)).await {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Not evidence of alternates, and not their absence either: the
            // caller does not mark the store (security S6).
            Err(e) => return Err(format!("the alternates check failed: {}", e.kind())),
        }
    }
    Ok(false)
}

/// The prefix receive-pack gives its quarantine directory in `objects/`.
const QUARANTINE_PREFIX: &str = "tmp_objdir-incoming-";

/// The receive-pack quarantine directories (`objects/tmp_objdir-incoming-*`)
/// in a served store.
async fn quarantines_in(served: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(served.join("objects")).await else {
        return out;
    };
    while let Ok(Some(e)) = entries.next_entry().await {
        if e.file_name()
            .to_string_lossy()
            .starts_with(QUARANTINE_PREFIX)
            && e.file_type().await.is_ok_and(|t| t.is_dir())
        {
            out.push(e.path());
        }
    }
    out
}

/// The newest modification time of a quarantine directory, its entries and
/// theirs (receive-pack writes into `pack/` below it). `None` when any part
/// of that scan cannot be read: an incomplete scan gives no age, so the
/// sweep treats the directory as fresh rather than judging it by the
/// entries it happened to see (Codex round 3).
async fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest = tokio::fs::symlink_metadata(dir)
        .await
        .ok()?
        .modified()
        .ok()?;
    let mut level = vec![dir.to_path_buf()];
    for _ in 0..2 {
        let mut next = Vec::new();
        for d in level {
            let mut entries = tokio::fs::read_dir(&d).await.ok()?;
            while let Some(e) = entries.next_entry().await.ok()? {
                // `DirEntry::metadata` does not follow symlinks.
                let m = e.metadata().await.ok()?;
                newest = newest.max(m.modified().ok()?);
                if m.is_dir() {
                    next.push(e.path());
                }
            }
        }
        level = next;
    }
    Some(newest)
}

/// Remove the quarantine directories in a served store that are leftovers
/// of a killed push (timeout, size cap, crash): those last written more than
/// [`PUBLISH_TIMEOUT`] ago. receive-pack removes its own on every graceful
/// exit, and a publication's push is killed at that timeout, so a younger
/// one may belong to a push still in flight (an owner push in the window
/// before the first mirror record exists) and is left alone (security delta
/// N3). It holds approved objects only and no reader looks inside it, but it
/// counts against the store's size. Called under the repository lock,
/// before a publication; it is the only sweep, so what a failed publication
/// leaves is removed by a later one once it is stale.
///
/// Age is a heuristic, not proof that a push has stopped: an owner push
/// stalled for longer than [`PUBLISH_TIMEOUT`] may lose its quarantine and
/// fail. That costs availability only; nothing is exposed.
async fn sweep_stale_quarantines(served: &Path) {
    let now = SystemTime::now();
    for path in quarantines_in(served).await {
        let stale = newest_mtime(&path)
            .await
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > PUBLISH_TIMEOUT);
        if stale {
            remove_store(&path).await;
        }
    }
}

/// The first update `git push --porcelain` did not report as accepted.
/// Lines are `<flag>\t<from>:<to>\t<summary>`; `!` is a rejection.
fn porcelain_rejection(out: &str, updates: &[RefUpdate]) -> Option<String> {
    for u in updates {
        let line = out.lines().find(|l| {
            l.split('\t')
                .nth(1)
                .and_then(|spec| spec.rsplit_once(':'))
                .is_some_and(|(_, to)| to == u.git_ref)
        });
        match line {
            Some(l) if !l.starts_with('!') => {}
            Some(l) => {
                let why = l.split('\t').nth(2).unwrap_or("rejected");
                return Some(format!("{} {why}", u.git_ref));
            }
            None => return Some(format!("{} not reported by the push", u.git_ref)),
        }
    }
    None
}

impl GitCli {
    /// `msg` with this repository's store paths and the adapter's two roots
    /// replaced by placeholders (`<served>`, `<candidate>`,
    /// `<plugin>/mirror-work`, `<plugin>/repos`). Adapter errors are saved
    /// into the mirror record, which the forge serves publicly (security
    /// review L2). The specific paths go first, so a root does not leave half
    /// of one behind. The bare plugin directory is never replaced, and every
    /// replacement sits at a path boundary, so a short root such as `/data`
    /// does not garble unrelated text like a URL (code delta D2).
    fn redact(&self, owner: &str, name: &str, msg: &str) -> String {
        let mut out = msg.to_string();
        for (path, tag) in [
            (self.dir(owner, name), "<served>"),
            (self.candidate(owner, name), "<candidate>"),
            (self.work_root.clone(), "<plugin>/mirror-work"),
            (Some(self.repo_root.clone()), "<plugin>/repos"),
        ] {
            if let Some(p) = path.as_deref().and_then(Path::to_str) {
                out = replace_path(&out, p, tag);
            }
        }
        out
    }
}

/// `hay` with each occurrence of the absolute path `path` that stands as a
/// whole path (or a prefix of one, followed by `/`) replaced by `tag`. The
/// character before it must not be part of a path segment, and the one after
/// must not continue the last segment, so `/d/repos` is found in
/// `'/d/repos/x'` but not in `https://host/d/repos` or `/d/repository`.
fn replace_path(hay: &str, path: &str, tag: &str) -> String {
    let segment = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '~');
    if path.len() < 2 {
        return hay.to_string();
    }
    let mut out = String::with_capacity(hay.len());
    let mut rest = 0;
    for (at, _) in hay.match_indices(path) {
        if at < rest {
            continue;
        }
        let end = at + path.len();
        let before = hay[..at].chars().next_back();
        let after = hay[end..].chars().next();
        if before.is_some_and(segment) || after.is_some_and(segment) {
            continue;
        }
        out.push_str(&hay[rest..at]);
        out.push_str(tag);
        rest = end;
    }
    out.push_str(&hay[rest..]);
    out
}

/// The bodies behind the [`MirrorGit`] methods whose errors can name a
/// store path; the trait methods redact them (see [`GitCli::redact`]).
impl GitCli {
    async fn materialise_inner(&self, owner: &str, name: &str) -> Result<(), String> {
        let served = self.dir(owner, name).ok_or("unsafe repository key")?;
        let staging = self
            .staging(owner, name)
            .ok_or("no staging store location")?;
        let built = self.build_served(&staging, &served).await;
        if built.is_err() {
            remove_store(&staging).await;
        }
        built?;
        self.ensure_candidate(owner, name).await.map(|_| ())
    }

    async fn fetch_inner(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
        pin: Option<&ClonePin>,
    ) -> Result<(), String> {
        let permitted = if operator {
            is_operator_clone(clone)
        } else {
            is_remote_clone(clone)
        };
        if !permitted || clone.starts_with('-') {
            return Err(CLONE_URL_REFUSED.into());
        }
        // Into the private candidate only: served is untouched until publish.
        let dir = self.ensure_candidate(owner, name).await?;
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
            // Branches deleted upstream must not pin objects for ever.
            "--prune",
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
            // A killed, failed or oversize fetch: drop the whole candidate so
            // its size cannot ratchet. It is private and rebuilt on next use.
            remove_store(&dir).await;
        }
        if over {
            return Err(GREW_PAST_CAP.into());
        }
        ran.map(|_| ())
    }

    /// Publication invariant: the refspecs are exactly `updates`, each an
    /// approved SHA (never a candidate ref name, never `refs/mirror/*`, never
    /// a wider refspec), so pack generation sends only the approved closure
    /// and that is the most that can reach served on any failure path,
    /// including a receiver-side ref failure after quarantine migration.
    async fn publish_inner(
        &self,
        owner: &str,
        name: &str,
        updates: &[RefUpdate],
        head: Option<&str>,
    ) -> Result<(), PublishError> {
        let served = self
            .dir(owner, name)
            .ok_or_else(|| PublishError::terminal("unsafe repository key"))?;
        let candidate = self
            .candidate(owner, name)
            .ok_or_else(|| PublishError::terminal("no candidate store location"))?;
        // A push with no refspec falls back to `push.default`: a wider set
        // than approved. Nothing to publish is not an error.
        if updates.is_empty() {
            return Ok(());
        }
        let mut refs = std::collections::BTreeSet::new();
        for u in updates {
            let lease_ok = u.expected.as_deref().is_none_or(is_sha40);
            if !is_branch_ref(&u.git_ref) || !is_sha40(&u.sha) || !lease_ok {
                return Err(PublishError::terminal("ref, sha or lease refused"));
            }
            if !refs.insert(u.git_ref.as_str()) {
                return Err(PublishError::terminal("a branch appears twice"));
            }
        }
        if !tokio::fs::metadata(&served).await.is_ok_and(|m| m.is_dir()) {
            return Err("no served repository".into());
        }
        // Publication neither scans nor marks: it has no record to tell an
        // owner's store from one with mirror history, and `prepare` has
        // already marked every store the engine publishes into. An unmarked
        // store here is refused, and so is any error checking it (security
        // R2: none of these passes on a retry).
        if !tokio::fs::metadata(served.join(PUBLICATION_MARKER))
            .await
            .is_ok_and(|m| m.is_file())
        {
            if self
                .legacy_traces(&served)
                .await
                .map_err(PublishError::terminal)?
            {
                return Err(PublishError::terminal(AWAITS_MIGRATION));
            }
            return Err(PublishError::terminal(
                "the served repository is not marked for publication",
            ));
        }
        // A marked store that has since gained alternates serves objects
        // from outside itself; publishing into it would vouch for them.
        if has_alternates(&served)
            .await
            .map_err(PublishError::terminal)?
        {
            return Err(PublishError::terminal(
                "the served repository borrows objects through alternates",
            ));
        }
        let served_s = served
            .to_str()
            .ok_or_else(|| PublishError::terminal("non-UTF-8 store path"))?;
        let mut args: Vec<String> = ["push", "--porcelain", "--atomic", "--no-verify"]
            .map(String::from)
            .into();
        // The served side's hook boundary: a fixed constant, see RECEIVE_PACK.
        args.push(format!("--receive-pack={RECEIVE_PACK}"));
        // One explicit lease per ref against the `local_heads` snapshot (empty
        // = must not exist yet). The refspecs below carry no `+`: a forced
        // refspec overrides a stale lease and would land the objects.
        for u in updates {
            let expect = u.expected.as_deref().unwrap_or("");
            args.push(format!("--force-with-lease={}:{expect}", u.git_ref));
        }
        args.push("--".into());
        args.push(served_s.into());
        args.extend(updates.iter().map(|u| format!("{}:{}", u.sha, u.git_ref)));
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        // Leftovers of a killed push count against the size; clear them, then
        // cap what this push may add: served never shrinks (commits orphaned
        // by approved force moves stay), so a cap on its total would stall
        // every publish once it had passed the cap (security review M2). The
        // total is bounded by the ceiling instead, checked before any push
        // starts, so a store past it is refused rather than killed mid-push
        // on every try (security delta N1).
        sweep_stale_quarantines(&served).await;
        // Quarantines are left out of the ceiling (security R5: young
        // leftovers of killed pushes would otherwise refuse publication for
        // content the store does not hold), but not out of the growth
        // watcher, which measures the whole store the push writes into.
        let quarantines = quarantines_in(&served).await;
        let (full, quarantined) = tokio::task::spawn_blocking({
            let d = served.clone();
            move || {
                let q = quarantines
                    .iter()
                    .map(|p| dir_size(p))
                    .fold(0u64, u64::saturating_add);
                (dir_size(&d), q)
            }
        })
        .await
        .unwrap_or((0, 0));
        let baseline = full.saturating_sub(quarantined);
        if baseline > MAX_SERVED_BYTES {
            return Err(PublishError::terminal(format!(
                "the served repository is past its size ceiling ({MAX_SERVED_BYTES} bytes)"
            )));
        }
        let limit = full.saturating_add(MAX_REPO_BYTES);
        #[cfg(test)]
        if let Some(f) = self.during_push {
            f(&served);
        }
        #[cfg(test)]
        let measure: DirMeasure = self.push_measure.unwrap_or(dir_size);
        #[cfg(not(test))]
        let measure: DirMeasure = dir_size;
        // git pushes from the candidate (`--git-dir`); the watcher measures
        // served, the store the push writes into.
        let pushed = self
            .run_in(
                &candidate,
                &served,
                &argv,
                Some("file"),
                PUBLISH_TIMEOUT,
                Some((limit, measure)),
            )
            .await
            .and_then(
                |out| match porcelain_rejection(&String::from_utf8_lossy(&out), updates) {
                    Some(why) => Err(why),
                    None => Ok(()),
                },
            );
        // A failed push's leftover quarantine is not swept here: nothing
        // tells it apart from a concurrent owner push's (Codex round 3). The
        // stale sweep removes it on a later publication. Until then the
        // ceiling leaves it out (it is a quarantine) and the growth limit is
        // measured from a size that includes it.
        pushed.map_err(push_failure)?;
        // HEAD only after a successful push, and only to a ref that was in
        // it. A failure here is logged and does not undo the publication.
        if let Some(h) = head.filter(|h| updates.iter().any(|u| u.git_ref == *h)) {
            if let Err(e) = self
                .run(
                    &served,
                    &["symbolic-ref", "HEAD", h],
                    None,
                    Duration::from_secs(15),
                )
                .await
            {
                tracing::warn!(pubkey = %owner, name = %name, error = %e, "forge: mirror HEAD not set");
            }
        }
        Ok(())
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
        // Served, not the candidate: this snapshot is the publication lease.
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
        self.materialise_inner(owner, name)
            .await
            .map_err(|e| self.redact(owner, name, &e))
    }

    async fn prepare(&self, owner: &str, name: &str, scan: bool) -> Result<Prepared, String> {
        let served = self.dir(owner, name).ok_or("unsafe repository key")?;
        if !tokio::fs::metadata(&served).await.is_ok_and(|m| m.is_dir()) {
            return Ok(Prepared::Ready);
        }
        self.mark_clean_store(&served, scan)
            .await
            .map_err(|e| self.redact(owner, name, &e))
    }

    async fn fetch(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
        pin: Option<&ClonePin>,
    ) -> Result<(), String> {
        self.fetch_inner(owner, name, clone, operator, pin)
            .await
            .map_err(|e| self.redact(owner, name, &e))
    }

    async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool {
        let Some(dir) = self.candidate(owner, name) else {
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
        let Some(dir) = self.candidate(owner, name) else {
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
        let dir = self.candidate(owner, name)?;
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

    async fn publish(
        &self,
        owner: &str,
        name: &str,
        updates: &[RefUpdate],
        head: Option<&str>,
    ) -> Result<(), PublishError> {
        self.publish_inner(owner, name, updates, head)
            .await
            .map_err(|e| PublishError {
                reason: self.redact(owner, name, &e.reason),
                ..e
            })
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
    /// Signalled whenever the inbox gains an event, so a worker waiting out
    /// a retry can take a newer state at once (security delta N2).
    wake: tokio::sync::Notify,
}

/// The shortest wait before the worker re-applies a held state, in
/// milliseconds, whatever `retry_at` says.
const MIN_REQUEUE_MS: u64 = 1_000;

/// Whether a failed attempt at the newest state may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    /// The same attempt would fail the same way.
    No,
    /// It may pass; retried with the backoff.
    Yes,
    /// It may pass, but counts towards [`MAX_TIMEOUTS`]: a timeout, or a
    /// host name that did not resolve.
    Counted,
}

/// `reason`, saying so when [`MAX_TIMEOUTS`] stopped the retry.
fn with_limit(reason: String, gave_up: bool, timeouts: u32) -> String {
    if gave_up {
        format!("{reason} ({timeouts} timeouts of this state; not retried)")
    } else {
        reason
    }
}

/// The `created_at` the planner compares a state against: the last state
/// acted on, except that a lower-id state at the same second (the NIP-01
/// winner of the tie) counts as newer than it, the order the replay check
/// and [`supersedes`] use (Codex C5).
fn acted_on_at(last: Option<&EventRef>, ev: &Event) -> u64 {
    match last {
        Some(l) if l.created_at == ev.created_at && ev.id < l.id => l.created_at.saturating_sub(1),
        Some(l) => l.created_at,
        None => 0,
    }
}

/// Whether state `new` is newer than state `old` in the order the inbox and
/// the replay check use: later `created_at`, or the same second and the lower
/// id (NIP-01).
fn supersedes(new: &Event, old: &Event) -> bool {
    new.created_at > old.created_at || (new.created_at == old.created_at && new.id < old.id)
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
            wake: tokio::sync::Notify::new(),
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

    /// Take the repository's cross-process advisory lock (design §3). The
    /// blocking `File::lock` runs on the blocking pool, never on the async
    /// runtime; the returned file holds the lock until it is dropped.
    async fn lock_repo(&self, owner: &str, name: &str) -> std::io::Result<std::fs::File> {
        let path = self.store.lock_file(owner, name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsafe mirror key")
        })?;
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            file.lock()?;
            Ok(file)
        })
        .await
        .map_err(std::io::Error::other)?
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
    ///
    /// Both kinds save the record, so both run under the per-repository
    /// in-process mutex and then the cross-process lock (security review M1),
    /// and both [`MirrorGit::prepare`] an existing served store after their
    /// replay check (before it, for a first record). A 30617 that cannot
    /// take the lock is dropped unsaved.
    pub async fn on_event(&self, ev: &Event) -> Option<MirrorRecord> {
        let entry = self.wanted(ev)?;
        // The signature check is the expensive step; everything cheap came first.
        if !verify_event(ev) {
            return None;
        }
        let key = format!("{}/{}", entry.pubkey, entry.name);
        let lock = self.lock_for(&key).await;
        let _guard = lock.lock().await;
        let repo_lock = self.lock_repo(&entry.pubkey, &entry.name).await;
        if ev.kind == KIND_ANNOUNCE {
            // Held to the end of this block: dropping the file releases it.
            let _repo_lock = match repo_lock {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(pubkey = %entry.pubkey, name = %entry.name, error = %e, "forge: mirror lock not taken; announcement dropped");
                    return None;
                }
            };
            return self.on_announce(&entry, ev).await;
        }
        Some(self.apply_locked(&entry, ev, repo_lock).await)
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
    /// Only a verified event is queued, so only a verified event can take a
    /// slot or replace a worker's pending retry.
    fn enqueue(self: &Arc<Self>, ev: Event) {
        let Some(entry) = self.wanted(&ev) else {
            return;
        };
        let key = format!("{}/{}", entry.pubkey, entry.name);
        let slot = format!("{key}#{}", ev.kind);
        // A far-future stamp must not squat the slot and shadow honest
        // events (L3).
        if ev.created_at > self.clock.now_ms() / 1000 + MAX_FUTURE_SKEW_SECS {
            return;
        }
        // Only a verified event may take the slot, and so displace a queued
        // or pending verified one (Codex C1): a relay's forgery would
        // otherwise cancel a pending retry and then fail `on_event`.
        if !verify_event(&ev) {
            return;
        }
        {
            let mut inbox = self
                .inbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A tie at the same second keeps the lowest id.
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
        // Wake any worker waiting out a retry; each checks its own key.
        self.wake.notify_waiters();
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
    /// limit or a failed publication held back once its `retry_at` is due.
    ///
    /// While it waits for a retry the worker holds no permit and no lock,
    /// and it wakes for any new event for its repository: a newer (and, like
    /// everything in the inbox, verified) state replaces the pending retry
    /// and is applied at once, and an announcement is applied without giving
    /// the retry up. When the timer fires, the pending state goes back into
    /// its slot unless the slot holds one that supersedes it.
    async fn drain(self: Arc<Self>, key: String) {
        let mut guard = BusyGuard {
            mirror: Arc::clone(&self),
            key: key.clone(),
            released: false,
        };
        let state_slot = format!("{key}#{KIND_STATE}");
        // The state waiting for its retry, and when it is due.
        let mut pending: Option<(Event, tokio::time::Instant)> = None;
        loop {
            // Registered before the inbox is read, so an enqueue between the
            // read and the wait below still wakes this worker.
            let woken = self.wake.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
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
                if let Some((_, due)) = &pending {
                    let due = *due;
                    tokio::select! {
                        () = tokio::time::sleep_until(due) => {
                            if let Some((ev, _)) = pending.take() {
                                // Back into the slot unless it already holds
                                // a state that supersedes it (or is it): an
                                // older one there must not displace the retry
                                // (Codex C2, security R3).
                                let mut inbox = self
                                    .inbox
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let keep = inbox
                                    .get(&state_slot)
                                    .is_some_and(|have| !supersedes(&ev, have));
                                if !keep {
                                    inbox.insert(state_slot.clone(), ev);
                                }
                            }
                        }
                        () = &mut woken => {}
                    }
                    continue;
                }
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
            if ev.kind == KIND_STATE {
                if let Some((held, _)) = &pending {
                    if !supersedes(&ev, held) {
                        // An older state (or the same one again) never
                        // displaces the retry; apply would refuse it anyway.
                        continue;
                    }
                }
                pending = None;
            }
            let Ok(_permit) = Arc::clone(&self.permits).acquire_owned().await else {
                return;
            };
            let rec = self.on_event(&ev).await;
            drop(_permit);
            if ev.kind != KIND_STATE {
                continue;
            }
            // A record's `retry_at` belongs to the newest state seen: a replay
            // or a skip hands back the persisted one, which must not arm a
            // retry of this event. The floor keeps a `retry_at` already in
            // the past (or a lock that keeps failing) from spinning.
            if let Some(wait) = rec
                .filter(|r| r.newest_seen_id == ev.id)
                .and_then(|r| r.retry_at)
                .map(|at| at.saturating_sub(self.clock.now_ms()))
            {
                let wait = Duration::from_millis(wait.clamp(MIN_REQUEUE_MS, MAX_BACKOFF_MS) + 50);
                pending = Some((ev, tokio::time::Instant::now() + wait));
            }
        }
    }

    /// Record a 30617's clone URLs. The replay check comes first, so a
    /// replayed announcement costs no store examination; then the served
    /// store is prepared, before a first record is saved beside it.
    async fn on_announce(&self, entry: &FollowEntry, ev: &Event) -> Option<MirrorRecord> {
        let clones = read_clones(ev);
        if clones.is_empty() {
            return None;
        }
        let existing = match self.store.load(&entry.pubkey, &entry.name) {
            StoredRecord::Valid(r) => Some(*r),
            StoredRecord::Missing => None,
            // Left in place for the operator and migration (security S2.2).
            StoredRecord::Unreadable(why) => {
                tracing::warn!(pubkey = %entry.pubkey, name = %entry.name, why = %why, "forge: mirror record unreadable; announcement not recorded");
                return None;
            }
        };
        if existing
            .as_ref()
            .is_some_and(|r| r.announce_at.is_some_and(|a| a >= ev.created_at))
        {
            return None;
        }
        let mut rec = existing
            .clone()
            .unwrap_or_else(|| MirrorRecord::new(&entry.pubkey, &entry.name, entry.clone.clone()));
        match self
            .prepare_served(&entry.pubkey, &entry.name, existing.as_ref())
            .await
        {
            Ok(Prepared::AwaitsMigration) => rec.awaits_migration = true,
            Ok(Prepared::Ready) => {}
            // A first record beside an unprepared store would gate it.
            Err(_) if existing.is_none() => return None,
            Err(_) => {}
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
    ///
    /// Errors carry whether the same fetch may pass on a retry: a git
    /// failure may (the network), and so may a timeout or a host name that
    /// did not resolve, within [`MAX_TIMEOUTS`]; a fetch past the size cap,
    /// or a clone URL or address the policy refuses, does not.
    async fn fetch_checked(
        &self,
        owner: &str,
        name: &str,
        clone: &str,
        operator: bool,
    ) -> Result<(), (String, Retry)> {
        let refused = |why: String| (why, Retry::No);
        let git = |why: String| {
            let retry = if why == GREW_PAST_CAP || why == CLONE_URL_REFUSED {
                Retry::No
            } else if why == GIT_TIMED_OUT {
                Retry::Counted
            } else {
                Retry::Yes
            };
            (why, retry)
        };
        if clone.to_ascii_lowercase().starts_with("file://") {
            return self
                .git
                .fetch(owner, name, clone, operator, None)
                .await
                .map_err(git);
        }
        let (url, host, port) = if operator {
            let u = url::Url::parse(clone).map_err(|e| refused(format!("bad URL: {e}")))?;
            (
                u.as_str().to_string(),
                u.host_str()
                    .ok_or_else(|| refused("URL has no host".into()))?
                    .to_string(),
                u.port_or_known_default()
                    .ok_or_else(|| refused("URL has no port".into()))?,
            )
        } else {
            normalise_remote_clone(clone).ok_or_else(|| refused(CLONE_URL_REFUSED.into()))?
        };
        let ip = self.host_allowed(&url).await.map_err(|why| {
            if resolution_failed(&why) {
                (format!("clone host not resolved: {why}"), Retry::Counted)
            } else {
                refused(format!("clone host refused: {why}"))
            }
        })?;
        let pin = ip.map(|ip| ClonePin { host, port, ip });
        self.git
            .fetch(owner, name, &url, operator, pin.as_ref())
            .await
            .map_err(git)
    }

    /// Let the adapter prepare an existing served store (mark a clean one)
    /// before a first record for it is saved, so following a clean
    /// repository never gates it. `rec` is the record already on disk:
    ///
    /// - a persisted awaits-migration verdict is returned without looking
    ///   at the store again;
    /// - a record from before this release (not [`MirrorRecord::isolated`])
    ///   asks for the unreachable-object scan; a store first followed now is
    ///   an owner's store and is not scanned;
    /// - a store that could not be examined (a scan that failed, any
    ///   other check that failed) is an error, not a verdict: it is not
    ///   marked and not recorded as awaiting migration, and the state is
    ///   retried (security S6, S7).
    async fn prepare_served(
        &self,
        owner: &str,
        name: &str,
        rec: Option<&MirrorRecord>,
    ) -> Result<Prepared, String> {
        if rec.is_some_and(|r| r.awaits_migration) {
            return Ok(Prepared::AwaitsMigration);
        }
        if !self.git.exists(owner, name).await {
            return Ok(Prepared::Ready);
        }
        let scan = rec.is_some_and(|r| !r.isolated);
        match self.git.prepare(owner, name, scan).await {
            Ok(Prepared::AwaitsMigration) => {
                tracing::warn!(pubkey = %owner, name = %name, "forge: mirror store awaits migration; not followed");
                Ok(Prepared::AwaitsMigration)
            }
            Ok(Prepared::Ready) => Ok(Prepared::Ready),
            Err(e) => {
                tracing::warn!(pubkey = %owner, name = %name, error = %e, "forge: mirror store not prepared");
                Err(e)
            }
        }
    }

    /// Schedule a retry of the newest state after a failure that may pass:
    /// the backoff floor, never less than [`backoff_delay`] of the failure
    /// count, counted from a clock reading taken now, after the failure
    /// (Codex C4), not from when the attempt started.
    fn schedule_retry(&self, rec: &mut MirrorRecord) {
        let floor = backoff_interval(self.cfg.min_interval_ms, rec.failures);
        let least = u64::try_from(backoff_delay(rec.failures).as_millis()).unwrap_or(u64::MAX);
        rec.retry_at = Some(self.clock.now_ms().saturating_add(floor.max(least)));
    }

    /// After a failure of the newest state: count it towards the backoff,
    /// count it towards [`MAX_TIMEOUTS`] when it is `Counted`, and schedule
    /// the retry unless it is `No` or the state has reached the limit (by
    /// this failure or an earlier one). Returns whether the limit stopped
    /// the retry.
    fn failed(&self, rec: &mut MirrorRecord, retry: Retry) -> bool {
        rec.failures = rec.failures.saturating_add(1);
        if retry == Retry::Counted {
            rec.timeouts = rec.timeouts.saturating_add(1);
        }
        // Once the state has reached the limit it stays given up, whatever
        // kind of failure comes next (Codex round 6).
        let gave_up = retry != Retry::No && rec.timeouts >= MAX_TIMEOUTS;
        if retry != Retry::No && !gave_up {
            self.schedule_retry(rec);
        }
        gave_up
    }

    fn save(&self, rec: &MirrorRecord) {
        if let Err(e) = self.store.save(rec) {
            tracing::warn!(pubkey = %rec.pubkey, name = %rec.name, error = %e, "forge: mirror record not saved");
        }
    }

    /// Apply one verified kind-30618 to one followed repository: check it is
    /// not stamped far ahead or a replay, prepare an existing served store
    /// ([`MirrorGit::prepare`]; for a first record this comes before the
    /// checks, so no record is saved beside an unprepared store), plan,
    /// fetch into the
    /// private candidate store, give each changed branch its verdict there,
    /// then publish only the approved commits into the served store in one
    /// atomic, leased push ([`MirrorGit::publish`]), and save the record.
    ///
    /// Publishing an approved commit publishes its whole history: every
    /// ancestor becomes readable by SHA. A *held* commit is one not reachable
    /// from any approved tip; it never reaches served. A held commit that is
    /// an ancestor of a later approved tip is served with that tip.
    ///
    /// If publication fails, no branch moves, every approved verdict records
    /// why, the failure counts towards the backoff, and the state is not
    /// marked as acted on: `retry_at` asks the worker to apply the same
    /// state again once the backoff has passed.
    ///
    /// The whole apply runs under the repository's cross-process lock
    /// (`plugin_dir/mirror-work/locks/<owner>/<name>.lock`), taken here;
    /// [`Self::on_event`] takes the same lock for announcements too. Two
    /// server instances on one plugin directory therefore neither share a
    /// candidate nor race any read-modify-write of the record.
    pub async fn apply(&self, entry: &FollowEntry, ev: &Event) -> MirrorRecord {
        let repo_lock = self.lock_repo(&entry.pubkey, &entry.name).await;
        self.apply_locked(entry, ev, repo_lock).await
    }

    /// [`Self::apply`] with the repository lock already taken (or its
    /// failure to be recorded). The lock is `flock`, per open file: taking
    /// it twice in one process would deadlock, so callers take it once.
    async fn apply_locked(
        &self,
        entry: &FollowEntry,
        ev: &Event,
        repo_lock: std::io::Result<std::fs::File>,
    ) -> MirrorRecord {
        let (owner, name) = (entry.pubkey.as_str(), entry.name.as_str());
        // Held to the end of this function: dropping the file releases it.
        let _repo_lock = match repo_lock {
            Ok(f) => f,
            Err(e) => {
                // Without the lock the shared record must not be written.
                tracing::warn!(pubkey = %owner, name = %name, error = %e, "forge: mirror lock not taken");
                let mut rec = self
                    .store
                    .read(owner, name)
                    .unwrap_or_else(|| MirrorRecord::new(owner, name, entry.clone.clone()));
                rec.last_seen = Some(LastSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    at: self.clock.now_ms(),
                    action: SeenAction::FetchFailed,
                    reason: format!("could not lock the repository: {e}"),
                });
                return rec;
            }
        };
        let existing = match self.store.load(owner, name) {
            StoredRecord::Valid(r) => Some(*r),
            StoredRecord::Missing => None,
            StoredRecord::Unreadable(why) => {
                // Not "no record": the store may hold pre-release history, so
                // it is neither examined nor marked, and the file is left for
                // the operator and migration (security S2.2, Codex High 1).
                tracing::warn!(pubkey = %owner, name = %name, why = %why, "forge: mirror record unreadable; awaiting migration");
                let mut rec = MirrorRecord::new(owner, name, entry.clone.clone());
                rec.awaits_migration = true;
                rec.last_seen = Some(LastSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    at: self.clock.now_ms(),
                    action: SeenAction::Skip,
                    reason: format!("the mirror record {why}; {AWAITS_MIGRATION}"),
                });
                return rec;
            }
        };
        // A first record is saved only once its store is prepared: a record
        // beside an unmarked store gates it (503). Otherwise preparation
        // waits for the replay check, so a replay costs no examination.
        let early = if existing.is_none() {
            Some(self.prepare_served(owner, name, None).await)
        } else {
            None
        };
        let state = read_state(ev);
        let mut rec = existing
            .clone()
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
            if rec.newest_seen_id != ev.id {
                rec.timeouts = 0;
            }
            rec.newest_seen_at = st.created_at;
            rec.newest_seen_id = ev.id.clone();
        }
        let prepared = match early {
            Some(p) => p,
            None => self.prepare_served(owner, name, existing.as_ref()).await,
        };
        let prepared = match prepared {
            Ok(p) => p,
            Err(e) => {
                // Not a verdict (security S6, S7): the store stays unmarked
                // and gated, nothing is recorded as awaiting migration, and
                // the state is retried with the backoff; a timeout counts
                // towards MAX_TIMEOUTS, so a scan that keeps timing out on a
                // large store is not rerun for ever.
                rec.events += 1;
                rec.retry_at = None;
                let retry = if e == GIT_TIMED_OUT {
                    Retry::Counted
                } else {
                    Retry::Yes
                };
                let gave_up = self.failed(&mut rec, retry);
                rec.last_seen = Some(LastSeen {
                    id: ev.id.clone(),
                    created_at: ev.created_at,
                    at: now,
                    action: SeenAction::Skip,
                    reason: with_limit(
                        format!("the served repository could not be examined: {e}"),
                        gave_up,
                        rec.timeouts,
                    ),
                });
                if existing.is_some() {
                    self.save(&rec);
                }
                return rec;
            }
        };
        if prepared == Prepared::AwaitsMigration {
            rec.awaits_migration = true;
            // Nothing can be published into it, so do not fetch for it, and
            // do not retry: the same state redelivered after migration still
            // passes the replay check above. `last_event` stays unset.
            rec.events += 1;
            rec.retry_at = None;
            rec.last_seen = Some(LastSeen {
                id: ev.id.clone(),
                created_at: ev.created_at,
                at: now,
                action: SeenAction::Skip,
                reason: AWAITS_MIGRATION.into(),
            });
            self.save(&rec);
            return rec;
        }
        let plan = plan_mirror(&PlanInput {
            state: state.as_ref(),
            local: &local,
            last_seen_at: acted_on_at(rec.last_event.as_ref(), ev),
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
                self.failed(&mut rec, Retry::Yes);
                seen.action = SeenAction::FetchFailed;
                seen.reason = format!("could not create the mirror: {e}");
                rec.last_seen = Some(seen);
                self.save(&rec);
                return rec;
            }
        }
        rec.last_fetch_at = Some(now);
        // `failures` is reset only once the state is fully applied (below):
        // a good fetch followed by a failed publish is still a failure.
        let fetched = self.fetch_checked(owner, name, &clone, operator).await;
        if let Err((why, retry)) = fetched {
            // A network error may pass (Codex C3); so may a timeout or a host
            // that did not resolve, up to MAX_TIMEOUTS (security S4). A fetch
            // past the size cap or a refused clone URL or address will not.
            let gave_up = self.failed(&mut rec, retry);
            seen.action = SeenAction::FetchFailed;
            seen.reason = with_limit(why, gave_up, rec.timeouts);
            tracing::warn!(pubkey = %owner, name = %name, reason = %seen.reason, "forge: mirror fetch failed");
            rec.last_seen = Some(seen);
            self.save(&rec);
            return rec;
        }
        // Verdicts first, all read from the candidate; served is untouched.
        let mut judged = Vec::with_capacity(plan.changed.len());
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
            judged.push((git_ref.clone(), sha.clone(), v));
        }
        // Publication invariant: exactly the SHAs that passed their verdict
        // in this apply, each leased on the `local` snapshot taken above (the
        // served heads this plan was made against; `None` = new branch).
        let updates: Vec<RefUpdate> = judged
            .iter()
            .filter(|(_, _, v)| v.move_branch)
            .map(|(git_ref, sha, _)| RefUpdate {
                git_ref: git_ref.clone(),
                sha: sha.clone(),
                expected: local.get(git_ref).cloned(),
            })
            .collect();
        let head = state
            .head
            .as_deref()
            .filter(|h| updates.iter().any(|u| u.git_ref == *h));
        // One atomic publish: every approved branch moves, or none does.
        let publish_error = if updates.is_empty() {
            None
        } else {
            self.git.publish(owner, name, &updates, head).await.err()
        };
        let retryable = publish_error.as_ref().is_some_and(|e| e.retryable);
        if let Some(e) = &publish_error {
            tracing::warn!(pubkey = %owner, name = %name, error = %e, "forge: mirror publication failed");
        }
        let moved = if publish_error.is_none() {
            updates.len()
        } else {
            0
        };
        let mut branches = BTreeMap::new();
        for (git_ref, sha, v) in judged {
            let verdict = match &publish_error {
                Some(e) if v.move_branch => format!("{}; publish failed: {e}", v.verdict),
                _ => v.verdict,
            };
            branches.insert(
                git_ref,
                BranchOutcome {
                    sha,
                    moved: v.move_branch && publish_error.is_none(),
                    verdict,
                },
            );
        }
        rec.last_fetch = Some(LastFetch {
            at: now,
            clone,
            branches,
            moved,
            mark: state.mark.clone(),
        });
        if let Some(e) = publish_error {
            // Not acted on: `last_event` stays, so the same state plans again.
            // A transient failure has the worker requeue it after the backoff,
            // which never drops below `backoff_delay` (code delta D1: with no
            // rate limit the fetch floor is 0, and the retry would spin). A
            // terminal refusal waits for a newer state instead.
            let retry = match (retryable, e.timed_out) {
                (false, _) => Retry::No,
                (true, true) => Retry::Counted,
                (true, false) => Retry::Yes,
            };
            let gave_up = self.failed(&mut rec, retry);
            seen.action = SeenAction::FetchFailed;
            seen.reason = with_limit(format!("publish failed: {e}"), gave_up, rec.timeouts);
        } else {
            // Applied (published, or nothing passed): the state is done.
            rec.failures = 0;
            rec.timeouts = 0;
            rec.last_event = Some(EventRef {
                id: ev.id.clone(),
                created_at: ev.created_at,
            });
            if moved > 0 {
                seen.action = SeenAction::Moved;
                seen.reason = format!("{moved} of {} moved", plan.changed.len());
            } else {
                seen.action = SeenAction::Held;
                seen.reason = "nothing passed".into();
            }
        }
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
        // Rooted at `<tmp>/repos` like the forge: the candidate and staging
        // stores are derived from the root's parent (design §1).
        let td = tempfile::tempdir().unwrap();
        let git = GitCli::new(td.path().join("repos"));
        let owner = "ab".repeat(32);
        git.materialise(&owner, "agent").await.unwrap();
        let dir = td.path().join("repos").join(&owner).join("agent.git");
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

    /// Inverted for publication isolation (Locked decision 10): served used
    /// to hide `refs/mirror`; now it never has them. A materialised mirror is
    /// a clean served store with the fixed config and the marker, and the
    /// fetch store is the candidate under `mirror-work/`, outside `repos/`.
    #[tokio::test]
    async fn a_materialised_mirror_is_a_clean_served_store_beside_its_candidate() {
        let td = tempfile::tempdir().unwrap();
        let repos = td.path().join("repos");
        let git = GitCli::new(&repos);
        let owner = "ab".repeat(32);
        git.materialise(&owner, "agent").await.unwrap();
        let dir = repos.join(&owner).join("agent.git");
        let cfg = |key: &str| {
            let out = std::process::Command::new("git")
                .args(["config", "--get-all", key])
                .current_dir(&dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(cfg("core.hooksPath"), "/dev/null");
        assert_eq!(cfg("receive.fsckObjects"), "true");
        assert_eq!(cfg("receive.denyDeletes"), "true");
        assert!(
            dir.join("mirror-publication-v1").is_file(),
            "served store has no publication marker"
        );
        assert!(!dir.join("refs").join("mirror").exists());
        let candidate = td
            .path()
            .join("mirror-work")
            .join("candidates")
            .join(&owner)
            .join("agent.git");
        assert!(
            candidate.is_dir(),
            "no candidate at {}",
            candidate.display()
        );
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
    async fn held_mirror_commit_is_not_published_through_raw_route() {
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("upstream");
        std::fs::create_dir(&up).unwrap();
        git_ok(&up, tmp.path(), &["init", "--quiet", "-b", "main"]);
        std::fs::write(up.join("public.txt"), "synthetic-approved\n").unwrap();
        git_ok(&up, tmp.path(), &["add", "-A"]);
        git_ok(&up, tmp.path(), &["commit", "--quiet", "-m", "approved"]);
        let approved = git_ok(&up, tmp.path(), &["rev-parse", "HEAD"]);
        let sk = key(17);
        let owner = pubhex(&sk);
        let entry = FollowEntry {
            pubkey: owner.clone(),
            name: "sample".into(),
            clone: Some(format!("file://{}", up.display())),
        };
        let mirror = engine(
            tmp.path(),
            MirrorConfig {
                relays: vec![],
                follow: vec![entry],
                min_interval_ms: 0,
            },
        );
        let first = mirror
            .on_event(&state_event(
                &sk,
                "sample",
                &[("refs/heads/main", &approved)],
                None,
                1_760_000_001,
            ))
            .await
            .unwrap();
        assert_eq!(first.last_fetch.unwrap().moved, 1);

        std::fs::write(up.join("held.txt"), "synthetic-held-mirror-content\n").unwrap();
        git_ok(&up, tmp.path(), &["add", "-A"]);
        git_ok(&up, tmp.path(), &["commit", "--quiet", "-m", "held"]);
        let held = git_ok(&up, tmp.path(), &["rev-parse", "HEAD"]);
        let txo = format!("txo:txbt4:{}:0", "c".repeat(64));
        let second = mirror
            .on_event(&state_event(
                &sk,
                "sample",
                &[("refs/heads/main", &held)],
                Some(("txbt4", &txo, &approved)),
                1_760_000_002,
            ))
            .await
            .unwrap();
        assert_eq!(second.last_seen.unwrap().action, SeenAction::Held);
        let fetched = second.last_fetch.unwrap();
        assert_eq!(fetched.moved, 0);
        assert!(fetched.branches["refs/heads/main"]
            .verdict
            .contains("no trail file"));
        let served = tmp.path().join("repos").join(&owner).join("sample.git");
        assert_eq!(
            git_ok(&served, tmp.path(), &["rev-parse", "refs/heads/main"]),
            approved
        );

        let forge = crate::ForgeService::new(crate::ForgeConfig::default(), tmp.path()).unwrap();
        let request = |sha: &str, file: &str| crate::ForgeRequest {
            method: "GET".into(),
            path: format!("/forge/{owner}/sample/raw/{sha}/{file}"),
            query: String::new(),
            headers: vec![],
            raw_body: bytes::Bytes::new(),
            host_url: None,
        };
        let public = forge
            .handle(
                request(&approved, "public.txt"),
                crate::ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert_eq!(public.status, 200);
        assert_eq!(public.body.as_ref(), b"synthetic-approved\n");
        let hidden = forge
            .handle(request(&held, "held.txt"), crate::ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert_eq!(
            hidden.status,
            404,
            "held verdict still served bytes: {}",
            String::from_utf8_lossy(&hidden.body)
        );
    }

    // --- publication isolation (design §8, Commit A) ------------------------
    //
    // Real git through `GitCli` throughout: a fake `MirrorGit` cannot show
    // what lands in an object store, what a receive-pack quarantine keeps or
    // what a lease refuses. Held commits sit on a side branch, off the
    // approved lineage, so nothing approved legitimately carries them.

    const APPROVED_BYTES: &str = "synthetic-approved\n";
    const APPROVED_SUBJECT: &str = "synthetic-approved-subject";
    const HELD_BYTES: &str = "synthetic-held-mirror-content\n";
    const HELD_SUBJECT: &str = "synthetic-held-subject";
    /// The served-store marker, spelt out so the on-disk tests compile
    /// against today's API; `publication_api` pins the public constant.
    const MARKER_FILE: &str = "mirror-publication-v1";

    /// Whether git succeeds; for steps that are expected to fail.
    fn git_succeeds(cwd: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn commit_file(up: &Path, home: &Path, file: &str, body: &str, subject: &str) -> String {
        std::fs::write(up.join(file), body).unwrap();
        git_ok(up, home, &["add", "-A"]);
        git_ok(up, home, &["commit", "--quiet", "-m", subject]);
        git_ok(up, home, &["rev-parse", "HEAD"])
    }

    fn new_upstream(home: &Path) -> PathBuf {
        let up = home.join("upstream");
        std::fs::create_dir(&up).unwrap();
        git_ok(&up, home, &["init", "--quiet", "-b", "main"]);
        up
    }

    /// `plugin_dir/repos/<owner>/sample.git`: what every reader serves.
    fn served_of(plugin: &Path, owner: &str) -> PathBuf {
        plugin.join("repos").join(owner).join("sample.git")
    }

    /// `plugin_dir/mirror-work/candidates/<owner>/sample.git`: the private
    /// fetch and validation store (design §1).
    fn candidate_of(plugin: &Path, owner: &str) -> PathBuf {
        plugin
            .join("mirror-work")
            .join("candidates")
            .join(owner)
            .join("sample.git")
    }

    /// Every ref and every object id in a store, for before/after equality.
    fn store_snapshot(dir: &Path, home: &Path) -> (String, String) {
        let refs = git_ok(
            dir,
            home,
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        );
        let objects = git_ok(
            dir,
            home,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        );
        (refs, objects)
    }

    fn has_object(dir: &Path, spec: &str) -> bool {
        git_succeeds(dir, &["cat-file", "-e", spec])
    }

    fn blob_id(home: &Path, body: &str) -> String {
        let f = home.join("blob-probe");
        std::fs::write(&f, body).unwrap();
        git_ok(home, home, &["hash-object", f.to_str().unwrap()])
    }

    fn mark_txo() -> String {
        format!("txo:txbt4:{}:0", "c".repeat(64))
    }

    /// A trail the verdict accepts for `mark` from the agent `owner`.
    fn trail_for(owner: &str, mark: &str) -> String {
        json!({"@type":"Blocktrail","profile":"gitmark","chain":"txbt4","pubkeyBase":format!("02{owner}"),"states":[mark],"txo":[mark_txo()]}).to_string()
    }

    fn follow_sample(owner: &str, up: &Path) -> FollowEntry {
        FollowEntry {
            pubkey: owner.to_string(),
            name: "sample".into(),
            clone: Some(format!("file://{}", up.display())),
        }
    }

    fn quiet_cfg(entry: &FollowEntry) -> MirrorConfig {
        MirrorConfig {
            relays: vec![],
            follow: vec![entry.clone()],
            min_interval_ms: 0,
        }
    }

    fn forge_at(plugin: &Path) -> crate::ForgeService {
        crate::ForgeService::new(crate::ForgeConfig::default(), plugin).unwrap()
    }

    fn forge_req(method: &str, path: String, query: &str) -> crate::ForgeRequest {
        crate::ForgeRequest {
            method: method.into(),
            path,
            query: query.into(),
            headers: vec![],
            raw_body: bytes::Bytes::new(),
            host_url: None,
        }
    }

    async fn get(forge: &crate::ForgeService, path: String) -> crate::ForgeResponse {
        forge
            .handle(forge_req("GET", path, ""), crate::ForgeAgent::Anonymous)
            .await
            .unwrap()
    }

    fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// The single file in a `.tar.gz`, via the system `tar`.
    fn untar_single(bytes: &[u8]) -> String {
        use std::io::Write;
        let mut child = Command::new("tar")
            .args(["-xzOf", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "tar could not read the archive");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    async fn apply_state(
        m: &Mirror,
        entry: &FollowEntry,
        sk: &SigningKey,
        refs: &[(&str, &str)],
        mark: Option<&str>,
        at: u64,
    ) -> MirrorRecord {
        let txo = mark_txo();
        let ev = state_event(
            sk,
            "sample",
            refs,
            mark.map(|c| ("txbt4", txo.as_str(), c)),
            at,
        );
        m.apply(entry, &ev).await
    }

    /// Approved `main` (state 1, no mark) is published; then a held commit on
    /// a side branch off it is fetched and judged (state 2, marked, the side
    /// tip has no trail) and must not be published.
    struct Side {
        tmp: tempfile::TempDir,
        owner: String,
        approved: String,
        held: String,
    }

    async fn side_fixture(seed: u8) -> Side {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(seed);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        let first = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved)],
            None,
            1_760_000_001,
        )
        .await;
        assert_eq!(
            first.last_fetch.map(|f| f.moved),
            Some(1),
            "approved state 1 moved"
        );
        git_ok(&up, home, &["checkout", "--quiet", "-b", "side"]);
        let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);
        git_ok(&up, home, &["checkout", "--quiet", "main"]);
        let second = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved), ("refs/heads/side", &held)],
            Some(&approved),
            1_760_000_002,
        )
        .await;
        let fetched = second.last_fetch.expect("the held state was fetched");
        assert_eq!(fetched.moved, 0, "nothing in state 2 passes");
        assert!(
            fetched.branches["refs/heads/side"]
                .verdict
                .contains("no trail file"),
            "{}",
            fetched.branches["refs/heads/side"].verdict
        );
        Side {
            tmp,
            owner,
            approved,
            held,
        }
    }

    /// Row 1: every reader still serves the approved commit, byte for byte,
    /// while a held side branch sits in the candidate.
    #[tokio::test]
    async fn approved_mirror_commit_is_served_on_every_reader() {
        let s = side_fixture(30).await;
        let forge = forge_at(s.tmp.path());
        let (o, a) = (&s.owner, &s.approved);

        let raw = get(&forge, format!("/forge/{o}/sample/raw/{a}/public.txt")).await;
        assert_eq!(
            (raw.status, raw.body.as_ref()),
            (200, APPROVED_BYTES.as_bytes()),
            "raw"
        );

        let blob = get(&forge, format!("/forge/{o}/sample/blob/{a}/public.txt")).await;
        assert_eq!(blob.status, 200, "blob HTML");
        assert!(
            contains_bytes(&blob.body, b"synthetic-approved"),
            "blob HTML body"
        );

        let commit = get(&forge, format!("/forge/{o}/sample/commit/{a}")).await;
        assert_eq!(commit.status, 200, "commit HTML");
        assert!(
            contains_bytes(&commit.body, APPROVED_SUBJECT.as_bytes()),
            "commit HTML body"
        );

        let tree = get(&forge, format!("/forge/{o}/sample/tree/{a}")).await;
        assert_eq!(tree.status, 200, "tree HTML");
        assert!(contains_bytes(&tree.body, b"public.txt"), "tree HTML body");

        let api_commit = get(&forge, format!("/forge/api/repos/{o}/sample/commit/{a}")).await;
        assert_eq!(api_commit.status, 200, "API commit");
        let v: Value = serde_json::from_slice(&api_commit.body).unwrap();
        assert_eq!(v["sha"], a.as_str());
        assert_eq!(v["message"], APPROVED_SUBJECT);

        let api_tree = get(&forge, format!("/forge/api/repos/{o}/sample/tree/{a}")).await;
        assert_eq!(api_tree.status, 200, "API tree");
        let v: Value = serde_json::from_slice(&api_tree.body).unwrap();
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["name"].as_str())
            .collect();
        assert_eq!(names, ["public.txt"]);

        let api_blob = get(
            &forge,
            format!("/forge/api/repos/{o}/sample/blob/{a}/public.txt"),
        )
        .await;
        assert_eq!(api_blob.status, 200, "API blob");
        let v: Value = serde_json::from_slice(&api_blob.body).unwrap();
        assert_eq!(v["content"], APPROVED_BYTES);

        let archive = get(&forge, format!("/forge/{o}/sample/archive/{a}.tar.gz")).await;
        assert_eq!(archive.status, 200, "archive");
        assert_eq!(untar_single(&archive.body), APPROVED_BYTES);
    }

    /// Row 3: the held side commit is refused by every HTML, JSON and
    /// archive reader, and none of its bytes appear in any response.
    #[tokio::test]
    async fn held_side_commit_is_denied_on_html_json_and_archive_readers() {
        let s = side_fixture(31).await;
        let forge = forge_at(s.tmp.path());
        let (o, h) = (&s.owner, &s.held);
        let paths = [
            format!("/forge/{o}/sample/raw/{h}/held.txt"),
            format!("/forge/{o}/sample/blob/{h}/held.txt"),
            format!("/forge/{o}/sample/tree/{h}"),
            format!("/forge/{o}/sample/commit/{h}"),
            format!("/forge/{o}/sample/commits/{h}"),
            format!("/forge/api/repos/{o}/sample/commit/{h}"),
            format!("/forge/api/repos/{o}/sample/tree/{h}"),
            format!("/forge/api/repos/{o}/sample/blob/{h}/held.txt"),
            format!("/forge/api/repos/{o}/sample/commits/{h}"),
            format!("/forge/{o}/sample/archive/{h}.tar.gz"),
            format!("/forge/{o}/sample/archive/{h}.zip"),
        ];
        let mut leaks = Vec::new();
        for p in paths {
            let r = get(&forge, p.clone()).await;
            let bytes_leak = contains_bytes(&r.body, HELD_BYTES.trim_end().as_bytes())
                || contains_bytes(&r.body, HELD_SUBJECT.as_bytes());
            if (200..300).contains(&r.status) || bytes_leak {
                leaks.push(format!(
                    "{p} -> {} (held bytes in body: {bytes_leak})",
                    r.status
                ));
            }
        }
        assert!(
            leaks.is_empty(),
            "held commit served:\n{}",
            leaks.join("\n")
        );
    }

    /// Row 4: the served object store holds nothing of the held commit and
    /// borrows nothing from the candidate.
    #[tokio::test]
    async fn served_store_holds_no_held_objects_and_no_alternates() {
        let s = side_fixture(32).await;
        let home = s.tmp.path();
        let served = served_of(home, &s.owner);
        assert!(
            has_object(&served, &s.approved),
            "control: approved is in served"
        );
        assert_eq!(
            git_ok(&served, home, &["rev-parse", "refs/heads/main"]),
            s.approved
        );
        let held_blob = blob_id(home, HELD_BYTES);
        let present: Vec<&str> = [
            s.held.as_str(),
            &format!("{}:held.txt", s.held),
            held_blob.as_str(),
        ]
        .into_iter()
        .filter(|spec| has_object(&served, spec))
        .map(|spec| {
            if spec == s.held {
                "held commit"
            } else if spec == held_blob {
                "held blob"
            } else {
                "held tree path"
            }
        })
        .collect();
        assert!(present.is_empty(), "served store holds {present:?}");
        assert!(
            !served.join("objects/info/alternates").exists(),
            "served must never borrow objects through alternates"
        );
    }

    /// Row 4, layout half: the fetch went to the private candidate under
    /// `mirror-work/`, and served carries no `refs/mirror` and the marker.
    #[tokio::test]
    async fn fetched_refs_live_in_the_candidate_under_mirror_work_not_in_served() {
        let s = side_fixture(33).await;
        let home = s.tmp.path();
        let served = served_of(home, &s.owner);
        let candidate = candidate_of(home, &s.owner);
        assert!(
            candidate.is_dir(),
            "no candidate at {}",
            candidate.display()
        );
        assert!(
            has_object(&candidate, &s.held),
            "the candidate holds the fetched held commit"
        );
        assert_eq!(
            git_ok(
                &served,
                home,
                &["for-each-ref", "--format=%(refname)", "refs/mirror"]
            ),
            "",
            "served carries refs/mirror"
        );
        assert!(
            served.join(MARKER_FILE).is_file(),
            "served store has no publication marker"
        );
    }

    fn http_backend() -> Option<PathBuf> {
        let out = Command::new("git").arg("--exec-path").output().ok()?;
        let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()).join("git-http-backend");
        p.is_file().then_some(p)
    }

    fn upload_pack_want(sha: &str) -> bytes::Bytes {
        let want = format!("want {sha}\n");
        bytes::Bytes::from(format!("{:04x}{want}00000009done\n", want.len() + 4))
    }

    /// Row 5: smart-HTTP neither advertises the held commit nor sends it when
    /// asked for by id. Needs `git-http-backend`, and fails without it.
    ///
    /// Defence in depth, not proof of publication isolation: this also
    /// passes on the pre-isolation code, because the earlier Git HTTP fix
    /// already refuses wants for unadvertised objects (upload-pack answers
    /// `ERR upload-pack: not our ref`). The object-store tests (rows 4, 7,
    /// 8) are the evidence that held objects are absent from served.
    #[tokio::test]
    async fn held_side_commit_is_not_fetchable_over_smart_http() {
        let backend = http_backend().expect(
            "git-http-backend not found under `git --exec-path`; this test needs it and does not skip",
        );
        let s = side_fixture(34).await;
        let mut forge = forge_at(s.tmp.path());
        forge.git = Arc::new(
            solid_pod_rs_git::service::GitHttpService::new(s.tmp.path().join("repos"))
                .with_backend_path(backend),
        );
        let base = format!("/forge/{}/sample.git", s.owner);
        let adv = forge
            .handle(
                forge_req(
                    "GET",
                    format!("{base}/info/refs"),
                    "service=git-upload-pack",
                ),
                crate::ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&adv.body).into_owned();
        assert_eq!(adv.status, 200, "{text}");
        assert!(
            text.contains(&s.approved),
            "control: approved main advertised: {text}"
        );
        assert!(!text.contains(&s.held), "held advertised: {text}");
        assert!(
            !text.contains("refs/mirror"),
            "refs/mirror advertised: {text}"
        );

        let fetch = |sha: &str| {
            let mut req = forge_req("POST", format!("{base}/git-upload-pack"), "");
            req.headers = vec![(
                "content-type".into(),
                "application/x-git-upload-pack-request".into(),
            )];
            req.raw_body = upload_pack_want(sha);
            req
        };
        let ok = forge
            .handle(fetch(&s.approved), crate::ForgeAgent::Anonymous)
            .await
            .unwrap();
        assert!(
            contains_bytes(&ok.body, b"PACK"),
            "control: approved want returns a pack"
        );
        let r = forge
            .handle(fetch(&s.held), crate::ForgeAgent::Anonymous)
            .await
            .expect("the held want request itself failed");
        assert!(
            !contains_bytes(&r.body, b"PACK"),
            "upload-pack sent a pack for the held commit (status {})",
            r.status
        );
    }

    /// Row 6: between the fetch and publication the served store is
    /// untouched, so a reader at that instant sees the held commit as 404
    /// and approved as 200. The fetch is driven directly through `GitCli`
    /// (the engine's own fetch step) and the readers run once it has fully
    /// completed: objects only accumulate during a fetch, so this instant is
    /// the superset of every mid-fetch instant.
    #[tokio::test]
    async fn reads_between_fetch_and_publish_never_see_the_fetched_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(35);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        let first = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved)],
            None,
            1_760_000_001,
        )
        .await;
        assert_eq!(first.last_fetch.map(|f| f.moved), Some(1));
        let served = served_of(home, &owner);
        let before = store_snapshot(&served, home);
        git_ok(&up, home, &["checkout", "--quiet", "-b", "side"]);
        let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);

        GitCli::new(home.join("repos"))
            .fetch(
                &owner,
                "sample",
                &format!("file://{}", up.display()),
                true,
                None,
            )
            .await
            .unwrap();

        let forge = forge_at(home);
        let h = get(&forge, format!("/forge/{owner}/sample/raw/{held}/held.txt")).await;
        assert_eq!(
            h.status,
            404,
            "held readable mid-validation: {}",
            String::from_utf8_lossy(&h.body)
        );
        let a = get(
            &forge,
            format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
        )
        .await;
        assert_eq!(
            (a.status, a.body.as_ref()),
            (200, APPROVED_BYTES.as_bytes())
        );
        assert_eq!(
            store_snapshot(&served, home),
            before,
            "fetch wrote into served"
        );
    }

    /// Row 7: one state, two branches, two verdicts. `main` carries a trail
    /// listing the mark and moves; `side` has none and is held; only `main`'s
    /// closure reaches served.
    #[tokio::test]
    async fn a_mixed_state_publishes_the_approved_branch_and_withholds_the_held_one() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let base = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(36);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &base)],
            None,
            1_760_000_001,
        )
        .await;
        let main2 = commit_file(
            &up,
            home,
            TRAIL_FILE,
            &trail_for(&owner, &base),
            "trail: mark base",
        );
        git_ok(&up, home, &["checkout", "--quiet", "-b", "side", &base]);
        let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);
        git_ok(&up, home, &["checkout", "--quiet", "main"]);

        let rec = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &main2), ("refs/heads/side", &held)],
            Some(&base),
            1_760_000_002,
        )
        .await;
        let f = rec.last_fetch.unwrap();
        assert!(
            f.branches["refs/heads/main"].moved,
            "{}",
            f.branches["refs/heads/main"].verdict
        );
        assert!(
            !f.branches["refs/heads/side"].moved,
            "{}",
            f.branches["refs/heads/side"].verdict
        );
        let served = served_of(home, &owner);
        assert_eq!(
            git_ok(&served, home, &["rev-parse", "refs/heads/main"]),
            main2
        );
        assert!(!git_succeeds(
            &served,
            &["rev-parse", "--verify", "--quiet", "refs/heads/side"]
        ));
        assert!(
            !has_object(&served, &held),
            "held side commit entered served"
        );
        assert!(
            !has_object(&served, &blob_id(home, HELD_BYTES)),
            "held blob entered served"
        );
    }

    /// Row 8: approved, then held on a side branch, then an approved
    /// non-fast-forward move of `main` onto another line. Served follows the
    /// approved moves exactly and never gains the held objects.
    #[tokio::test]
    async fn repeated_updates_with_a_non_fast_forward_move_never_publish_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let root = commit_file(&up, home, "base.txt", "base\n", "root");
        let approved1 = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(37);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        let served = served_of(home, &owner);

        let r1 = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved1)],
            None,
            1_760_000_001,
        )
        .await;
        assert_eq!(r1.last_fetch.map(|f| f.moved), Some(1));

        git_ok(
            &up,
            home,
            &["checkout", "--quiet", "-b", "side", &approved1],
        );
        let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);
        let r2 = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved1), ("refs/heads/side", &held)],
            Some(&approved1),
            1_760_000_002,
        )
        .await;
        assert_eq!(r2.last_fetch.map(|f| f.moved), Some(0));
        assert!(
            !has_object(&served, &held),
            "held entered served after state 2"
        );

        git_ok(&up, home, &["checkout", "--quiet", "-b", "line2", &root]);
        let approved2 = commit_file(&up, home, "line2.txt", "line two\n", "another line");
        assert!(
            !git_succeeds(
                &up,
                &["merge-base", "--is-ancestor", &approved1, &approved2]
            ),
            "control: the third move is not a fast-forward"
        );
        let r3 = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved2)],
            None,
            1_760_000_003,
        )
        .await;
        let f3 = r3.last_fetch.unwrap();
        assert!(
            f3.branches["refs/heads/main"].moved,
            "{}",
            f3.branches["refs/heads/main"].verdict
        );

        let heads = GitCli::new(home.join("repos"))
            .local_heads(&owner, "sample")
            .await;
        assert_eq!(
            heads,
            BTreeMap::from([("refs/heads/main".to_string(), approved2.clone())])
        );
        assert_eq!(
            git_ok(&served, home, &["symbolic-ref", "HEAD"]),
            "refs/heads/main"
        );
        assert!(
            !has_object(&served, &held),
            "held entered served after state 3"
        );
        assert!(
            !has_object(&served, &blob_id(home, HELD_BYTES)),
            "held blob entered served"
        );
    }

    /// Row 9: hooks planted in served (in `hooks/` and through a served
    /// `core.hooksPath`) never run when the mirror publishes into it.
    #[tokio::test]
    async fn publication_never_runs_hooks_planted_in_the_served_store() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved1 = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(38);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved1)],
            None,
            1_760_000_001,
        )
        .await;
        let served = served_of(home, &owner);

        let sentinel = home.join("hook-ran");
        let script = format!(
            "#!/bin/sh\necho \"$0\" >> '{}'\nexit 0\n",
            sentinel.display()
        );
        let planted = home.join("planted-hooks");
        let names = [
            "pre-receive",
            "update",
            "post-receive",
            "post-update",
            "reference-transaction",
            "proc-receive",
        ];
        for dir in [served.join("hooks"), planted.clone()] {
            std::fs::create_dir_all(&dir).unwrap();
            for n in names {
                let p = dir.join(n);
                std::fs::write(&p, &script).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
        }
        git_ok(
            &served,
            home,
            &["config", "core.hooksPath", planted.to_str().unwrap()],
        );
        // Control: the planted hooks are live and do write the sentinel.
        assert!(Command::new(served.join("hooks/update"))
            .status()
            .unwrap()
            .success());
        assert!(
            sentinel.exists(),
            "control: a planted hook writes the sentinel"
        );
        std::fs::remove_file(&sentinel).unwrap();

        let approved2 = commit_file(&up, home, "more.txt", "more\n", "approved two");
        let r = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved2)],
            None,
            1_760_000_002,
        )
        .await;
        assert_eq!(
            r.last_fetch.map(|f| f.moved),
            Some(1),
            "the publication happened"
        );
        assert_eq!(
            git_ok(&served, home, &["rev-parse", "refs/heads/main"]),
            approved2
        );
        assert!(
            !sentinel.exists(),
            "a served hook ran: {}",
            std::fs::read_to_string(&sentinel).unwrap_or_default()
        );
    }

    /// Moves served `main` the first time the engine reads the clock. `apply`
    /// reads it exactly once, straight after the `local_heads` snapshot that
    /// leases publication (mirror.rs `apply`), so the move lands between plan
    /// and publish. If that ordering changes, so must this seam.
    struct RaceClock {
        armed: std::sync::atomic::AtomicBool,
        served: PathBuf,
        home: PathBuf,
        moved_to: std::sync::Mutex<Option<String>>,
    }

    impl MirrorClock for RaceClock {
        fn now_ms(&self) -> u64 {
            if self.armed.swap(false, Ordering::SeqCst) {
                let x = move_served_main_behind_the_engine(&self.served, &self.home);
                *self.moved_to.lock().unwrap() = Some(x);
            }
            SystemClock.now_ms()
        }
    }

    /// A new commit made *in served* on top of its `main`, and `main` moved
    /// to it: someone else's write the engine did not plan against.
    fn move_served_main_behind_the_engine(served: &Path, home: &Path) -> String {
        let base = git_ok(served, home, &["rev-parse", "refs/heads/main"]);
        let tree = git_ok(served, home, &["rev-parse", "refs/heads/main^{tree}"]);
        let x = git_ok(
            served,
            home,
            &[
                "commit-tree",
                &tree,
                "-p",
                &base,
                "-m",
                "moved behind the engine",
            ],
        );
        git_ok(served, home, &["update-ref", "refs/heads/main", &x, &base]);
        x
    }

    /// Row 10 through the engine: a served ref moved between the plan and
    /// the publish makes publication fail; nothing is overwritten and the
    /// new commit's objects stay out of served.
    #[tokio::test]
    async fn a_ref_moved_behind_the_engine_before_publish_is_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved1 = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(39);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let served = served_of(home, &owner);
        let clock = Arc::new(RaceClock {
            armed: std::sync::atomic::AtomicBool::new(false),
            served: served.clone(),
            home: home.to_path_buf(),
            moved_to: std::sync::Mutex::new(None),
        });
        let m = Mirror::with_parts(
            quiet_cfg(&entry),
            MirrorStore::new(home),
            Arc::new(GitCli::new(home.join("repos"))),
            clock.clone(),
            Arc::new(AllowAll),
        );
        let r1 = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved1)],
            None,
            1_760_000_001,
        )
        .await;
        assert_eq!(r1.last_fetch.map(|f| f.moved), Some(1));

        let lease_bytes = "synthetic-lease-candidate\n";
        let approved2 = commit_file(&up, home, "lease.txt", lease_bytes, "approved two");
        clock.armed.store(true, Ordering::SeqCst);
        let r2 = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved2)],
            None,
            1_760_000_002,
        )
        .await;
        let x = clock
            .moved_to
            .lock()
            .unwrap()
            .clone()
            .expect("control: the race fired");

        let main = &r2.last_fetch.unwrap().branches["refs/heads/main"];
        assert!(
            !main.moved,
            "a stale lease still published: {}",
            main.verdict
        );
        assert_eq!(
            git_ok(&served, home, &["rev-parse", "refs/heads/main"]),
            x,
            "the concurrent write was overwritten"
        );
        assert!(
            !has_object(&served, &approved2),
            "the refused commit landed in served"
        );
        assert!(
            !has_object(&served, &blob_id(home, lease_bytes)),
            "the refused blob landed in served"
        );
    }

    /// Row 15, failure: a fetch that fails removes the candidate, and served
    /// keeps exactly its refs and objects.
    #[tokio::test]
    async fn a_failed_fetch_removes_the_candidate_and_leaves_served_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(40);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved)],
            None,
            1_760_000_001,
        )
        .await;
        let (served, candidate) = (served_of(home, &owner), candidate_of(home, &owner));
        assert!(
            candidate.is_dir(),
            "no candidate at {} after a good fetch",
            candidate.display()
        );
        let before = store_snapshot(&served, home);

        std::fs::rename(&up, home.join("upstream-gone")).unwrap();
        let r = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &"e".repeat(40))],
            None,
            1_760_000_002,
        )
        .await;
        assert_eq!(r.last_seen.unwrap().action, SeenAction::FetchFailed);
        assert!(!candidate.exists(), "the failed candidate was kept");
        assert_eq!(
            store_snapshot(&served, home),
            before,
            "served changed on a failed fetch"
        );
    }

    /// Row 15, oversize: a candidate past [`MAX_REPO_BYTES`] fails the fetch,
    /// is removed whole, and served keeps exactly its refs and objects. The
    /// cap is tripped with a sparse file (`dir_size` sums `metadata.len`).
    #[tokio::test]
    async fn an_oversize_candidate_is_removed_and_served_is_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let up = new_upstream(home);
        let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
        let sk = key(41);
        let owner = pubhex(&sk);
        let entry = follow_sample(&owner, &up);
        let m = engine(home, quiet_cfg(&entry));
        apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &approved)],
            None,
            1_760_000_001,
        )
        .await;
        let (served, candidate) = (served_of(home, &owner), candidate_of(home, &owner));
        assert!(
            candidate.is_dir(),
            "no candidate at {} after a good fetch",
            candidate.display()
        );
        let before = store_snapshot(&served, home);
        std::fs::File::create(candidate.join("objects").join("bloat"))
            .unwrap()
            .set_len(MAX_REPO_BYTES + 1)
            .unwrap();

        let next = commit_file(&up, home, "next.txt", "next\n", "next");
        let r = apply_state(
            &m,
            &entry,
            &sk,
            &[("refs/heads/main", &next)],
            None,
            1_760_000_002,
        )
        .await;
        let seen = r.last_seen.unwrap();
        assert_eq!(seen.action, SeenAction::FetchFailed, "{}", seen.reason);
        assert!(seen.reason.contains("size cap"), "{}", seen.reason);
        assert!(!candidate.exists(), "the oversize candidate was kept");
        assert_eq!(
            store_snapshot(&served, home),
            before,
            "served changed on an oversize fetch"
        );
    }

    /// Rows 10, 15 and 17 parts that name the post-repair API (`RefUpdate`,
    /// `MirrorGit::publish`, `PUBLICATION_MARKER`, `RECEIVE_PACK`). Kept in
    /// one module so the compile errors before the repair are few and
    /// obvious.
    mod publication_api {
        use super::*;

        #[test]
        fn publication_marker_is_the_documented_file_name() {
            assert_eq!(PUBLICATION_MARKER, MARKER_FILE);
        }

        /// Row 17: the `--receive-pack` command is a compile-time constant
        /// made of exactly `git`, `-c k=v` for every hardened pair plus the
        /// receive keys, and `receive-pack`. Git runs it through a shell, so
        /// nothing may be interpolated into it.
        #[test]
        fn receive_pack_command_is_a_fixed_hardened_constant() {
            const RP: &str = RECEIVE_PACK;
            let mut want: Vec<String> = solid_pod_rs_git::hardened::HARDENED_CONFIG
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            want.push("receive.fsckObjects=true".into());
            want.push("receive.denyDeletes=true".into());
            for bad in [
                '{', '}', '$', '`', '\'', '"', ';', '&', '|', '<', '>', '\\', '\n', '*', '?',
            ] {
                assert!(!RP.contains(bad), "{bad:?} in {RP:?}");
            }
            let toks: Vec<&str> = RP.split(' ').collect();
            assert_eq!(toks.first(), Some(&"git"), "{RP:?}");
            assert_eq!(toks.last(), Some(&"receive-pack"), "{RP:?}");
            let middle = &toks[1..toks.len() - 1];
            assert_eq!(middle.len() % 2, 0, "{RP:?}");
            let mut got: Vec<String> = middle
                .chunks(2)
                .map(|c| {
                    assert_eq!(c[0], "-c", "{RP:?}");
                    c[1].to_string()
                })
                .collect();
            got.sort();
            want.sort();
            assert_eq!(got, want, "{RP:?}");
        }

        /// Served `main` at `approved1`, a candidate holding `approved2` (a
        /// child of it), straight through the real adapter.
        async fn fetched_ahead(seed: u8) -> (tempfile::TempDir, String, String, String, GitCli) {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().to_path_buf();
            let up = new_upstream(&home);
            let approved1 = commit_file(&up, &home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(seed);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let m = engine(&home, quiet_cfg(&entry));
            apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &approved1)],
                None,
                1_760_000_001,
            )
            .await;
            let approved2 = commit_file(
                &up,
                &home,
                "lease.txt",
                "synthetic-lease-candidate\n",
                "approved two",
            );
            let git = GitCli::new(home.join("repos"));
            git.fetch(
                &owner,
                "sample",
                &format!("file://{}", up.display()),
                true,
                None,
            )
            .await
            .unwrap();
            assert!(
                git.has_commit(&owner, "sample", &approved2).await,
                "control: fetched"
            );
            (tmp, owner, approved1, approved2, git)
        }

        fn main_to(sha: &str, expected: Option<&str>) -> RefUpdate {
            RefUpdate {
                git_ref: "refs/heads/main".into(),
                sha: sha.into(),
                expected: expected.map(str::to_string),
            }
        }

        /// Control for the two refusals below: a current lease publishes.
        #[tokio::test]
        async fn publish_with_a_current_lease_moves_the_branch() {
            let (tmp, owner, approved1, approved2, git) = fetched_ahead(50).await;
            git.publish(
                &owner,
                "sample",
                &[main_to(&approved2, Some(&approved1))],
                Some("refs/heads/main"),
            )
            .await
            .unwrap();
            let served = served_of(tmp.path(), &owner);
            assert_eq!(
                git_ok(&served, tmp.path(), &["rev-parse", "refs/heads/main"]),
                approved2
            );
        }

        /// Row 10 at the adapter: a lease that no longer matches is refused
        /// by the real argv; no ref moves and no object lands.
        #[tokio::test]
        async fn publish_with_a_stale_lease_moves_nothing_and_lands_no_objects() {
            let (tmp, owner, approved1, approved2, git) = fetched_ahead(51).await;
            let served = served_of(tmp.path(), &owner);
            let x = move_served_main_behind_the_engine(&served, tmp.path());
            let r = git
                .publish(
                    &owner,
                    "sample",
                    &[main_to(&approved2, Some(&approved1))],
                    Some("refs/heads/main"),
                )
                .await;
            assert!(r.is_err(), "a stale lease published");
            assert_eq!(
                git_ok(&served, tmp.path(), &["rev-parse", "refs/heads/main"]),
                x
            );
            assert!(
                !has_object(&served, &approved2),
                "the refused commit landed in served"
            );
        }

        /// An empty lease means "must not exist yet"; it refuses an existing
        /// branch (Locked decision 1).
        #[tokio::test]
        async fn publish_with_an_empty_lease_refuses_a_branch_that_exists() {
            let (tmp, owner, approved1, approved2, git) = fetched_ahead(52).await;
            let r = git
                .publish(
                    &owner,
                    "sample",
                    &[main_to(&approved2, None)],
                    Some("refs/heads/main"),
                )
                .await;
            assert!(r.is_err(), "an empty lease overwrote an existing branch");
            let served = served_of(tmp.path(), &owner);
            assert_eq!(
                git_ok(&served, tmp.path(), &["rev-parse", "refs/heads/main"]),
                approved1
            );
            assert!(
                !has_object(&served, &approved2),
                "the refused commit landed in served"
            );
        }

        /// The real adapter, parked after its fetch until the test drops the
        /// `apply` future.
        struct ParkAfterFetch {
            inner: GitCli,
            armed: std::sync::atomic::AtomicBool,
            fetched: Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl MirrorGit for ParkAfterFetch {
            async fn exists(&self, owner: &str, name: &str) -> bool {
                self.inner.exists(owner, name).await
            }
            async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String> {
                self.inner.local_heads(owner, name).await
            }
            async fn materialise(&self, owner: &str, name: &str) -> Result<(), String> {
                self.inner.materialise(owner, name).await
            }
            async fn prepare(
                &self,
                owner: &str,
                name: &str,
                scan: bool,
            ) -> Result<Prepared, String> {
                self.inner.prepare(owner, name, scan).await
            }
            async fn fetch(
                &self,
                owner: &str,
                name: &str,
                clone: &str,
                operator: bool,
                pin: Option<&ClonePin>,
            ) -> Result<(), String> {
                let r = self.inner.fetch(owner, name, clone, operator, pin).await;
                if self.armed.load(Ordering::SeqCst) {
                    self.fetched.notify_one();
                    std::future::pending::<()>().await;
                }
                r
            }
            async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool {
                self.inner.has_commit(owner, name, sha).await
            }
            async fn is_ancestor(&self, owner: &str, name: &str, a: &str, d: &str) -> bool {
                self.inner.is_ancestor(owner, name, a, d).await
            }
            async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String> {
                self.inner.read_trail(owner, name, sha).await
            }
            async fn publish(
                &self,
                owner: &str,
                name: &str,
                updates: &[RefUpdate],
                head: Option<&str>,
            ) -> Result<(), PublishError> {
                self.inner.publish(owner, name, updates, head).await
            }
        }

        /// Row 15, cancellation: an `apply` dropped after its fetch leaves
        /// served with exactly its refs and objects. (A cancelled candidate
        /// may stay; design §4 reuses it, so its removal is not asserted.)
        #[tokio::test]
        async fn an_apply_cancelled_after_fetch_leaves_served_untouched() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().to_path_buf();
            let up = new_upstream(&home);
            let approved = commit_file(&up, &home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(53);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let fetched = Arc::new(tokio::sync::Notify::new());
            let git = Arc::new(ParkAfterFetch {
                inner: GitCli::new(home.join("repos")),
                armed: std::sync::atomic::AtomicBool::new(false),
                fetched: fetched.clone(),
            });
            let m = Arc::new(Mirror::with_parts(
                quiet_cfg(&entry),
                MirrorStore::new(&home),
                git.clone(),
                Arc::new(SystemClock),
                Arc::new(AllowAll),
            ));
            apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &approved)],
                None,
                1_760_000_001,
            )
            .await;
            let served = served_of(&home, &owner);
            let before = store_snapshot(&served, &home);

            let next = commit_file(&up, &home, "next.txt", HELD_BYTES, HELD_SUBJECT);
            git.armed.store(true, Ordering::SeqCst);
            let (m2, sk2, entry2, next2) = (m.clone(), sk.clone(), entry.clone(), next.clone());
            let task = tokio::spawn(async move {
                apply_state(
                    &m2,
                    &entry2,
                    &sk2,
                    &[("refs/heads/main", &next2)],
                    None,
                    1_760_000_002,
                )
                .await
            });
            tokio::time::timeout(Duration::from_secs(30), fetched.notified())
                .await
                .expect("the fetch finished");
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());

            assert_eq!(
                store_snapshot(&served, &home),
                before,
                "served changed under a cancelled apply"
            );
            assert!(
                !has_object(&served, &next),
                "the unpublished commit is in served"
            );
        }
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
        // Inverted (Locked decision 10): the fetch lands in the private
        // candidate under mirror-work/, never in the served store.
        assert_eq!(
            git_ok(
                &mirror_dir,
                &home,
                &["for-each-ref", "--format=%(refname)", "refs/mirror"]
            ),
            "",
            "served carries refs/mirror"
        );
        assert!(
            tmp.path()
                .join("mirror-work/candidates")
                .join(&pubk)
                .join("up.git")
                .is_dir(),
            "no candidate under mirror-work/"
        );

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
            !tmp.path()
                .join("mirror-work/candidates")
                .join(&pubk)
                .join("noclone.git")
                .exists(),
            "no candidate was made either"
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

    /// Commit A fix round: the code and security review findings and the
    /// cross-vendor audit's coverage gaps, each through real git and the
    /// real `GitCli` and forge readers. The plugin directory sits beside
    /// the upstream (`<tmp>/plugin`, `<tmp>/upstream`) where a test asserts
    /// on paths, so the operator's own clone URL never masks a leak.
    mod fix_a {
        use super::*;

        const T1: u64 = 1_760_000_001;
        const T2: u64 = 1_760_000_002;
        const T3: u64 = 1_760_000_003;
        const T4: u64 = 1_760_000_004;
        const T5: u64 = 1_760_000_005;

        /// A served store its owner pushed `main` into directly: no marker,
        /// no mirror config, no `refs/mirror`. A clean repository that the
        /// operator then follows (Locked decision 2's scenario).
        fn owner_pushed(plugin: &Path, owner: &str, up: &Path, home: &Path) -> PathBuf {
            let served = served_of(plugin, owner);
            std::fs::create_dir_all(served.parent().unwrap()).unwrap();
            let s = served.to_str().unwrap();
            git_ok(home, home, &["init", "--bare", "--quiet", "-b", "main", s]);
            git_ok(up, home, &["push", "--quiet", s, "main:main"]);
            served
        }

        fn record_file(plugin: &Path, owner: &str) -> PathBuf {
            plugin.join("mirror").join(owner).join("sample.json")
        }

        fn rev(dir: &Path, home: &Path, r: &str) -> String {
            git_ok(dir, home, &["rev-parse", r])
        }

        /// Served `main` published at an approved commit by a first state,
        /// with the plugin directory apart from the upstream.
        struct Published {
            tmp: tempfile::TempDir,
            plugin: PathBuf,
            up: PathBuf,
            sk: SigningKey,
            owner: String,
            entry: FollowEntry,
            m: Arc<Mirror>,
            approved: String,
        }

        impl Published {
            fn home(&self) -> &Path {
                self.tmp.path()
            }
            fn served(&self) -> PathBuf {
                served_of(&self.plugin, &self.owner)
            }
            fn url(&self) -> String {
                format!("file://{}", self.up.display())
            }
        }

        async fn published(seed: u8) -> Published {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().to_path_buf();
            let plugin = home.join("plugin");
            std::fs::create_dir(&plugin).unwrap();
            let up = new_upstream(&home);
            let approved = commit_file(&up, &home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(seed);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert_eq!(
                r.last_fetch.map(|f| f.moved),
                Some(1),
                "control: state 1 published"
            );
            Published {
                tmp,
                plugin,
                up,
                sk,
                owner,
                entry,
                m,
                approved,
            }
        }

        /// A `refs/heads/main.lock` in served: receive-pack cannot take the
        /// ref lock, so the ref transaction fails after the quarantine has
        /// been migrated (design §2, receiver-side failure).
        fn plant_ref_lock(served: &Path) -> PathBuf {
            let lock = served.join("refs").join("heads").join("main.lock");
            std::fs::write(&lock, "").unwrap();
            lock
        }

        // --- item 1: a followed clean store is marked ----------------------

        /// Code review 1 / security I1: a clean owner-pushed repository
        /// whose first state is already in sync saves a record and never
        /// publishes. It must still be marked, or every reader 503s.
        #[tokio::test]
        async fn a_followed_in_sync_owner_pushed_repo_is_marked_and_served() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(60);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert_eq!(
                r.last_seen.unwrap().reason,
                "already at this state",
                "control: the first state is in sync"
            );
            assert!(
                record_file(&plugin, &owner).is_file(),
                "control: the record exists"
            );
            assert!(
                served.join(MARKER_FILE).is_file(),
                "a clean followed store was left unmarked"
            );
            let forge = forge_at(&plugin);
            let a = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(
                (a.status, a.body.as_ref()),
                (200, APPROVED_BYTES.as_bytes()),
                "{}",
                String::from_utf8_lossy(&a.body)
            );
        }

        /// The same with a first state whose only change is held: nothing
        /// publishes, the store is still marked, approved serves and held
        /// does not.
        #[tokio::test]
        async fn a_followed_owner_pushed_repo_whose_first_state_is_all_held_is_served() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(61);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            git_ok(&up, home, &["checkout", "--quiet", "-b", "side"]);
            let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);
            git_ok(&up, home, &["checkout", "--quiet", "main"]);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &approved), ("refs/heads/side", &held)],
                Some(&approved),
                T1,
            )
            .await;
            let f = r.last_fetch.expect("control: the state was fetched");
            assert_eq!(f.moved, 0, "control: nothing passes");
            assert!(
                f.branches["refs/heads/side"]
                    .verdict
                    .contains("no trail file"),
                "control: {}",
                f.branches["refs/heads/side"].verdict
            );
            assert!(
                served.join(MARKER_FILE).is_file(),
                "a clean followed store was left unmarked"
            );
            let forge = forge_at(&plugin);
            let a = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(
                (a.status, a.body.as_ref()),
                (200, APPROVED_BYTES.as_bytes()),
                "{}",
                String::from_utf8_lossy(&a.body)
            );
            let h = get(&forge, format!("/forge/{owner}/sample/raw/{held}/held.txt")).await;
            assert_eq!(h.status, 404, "{}", String::from_utf8_lossy(&h.body));
        }

        // --- items 2 and 3: backoff and retry -----------------------------

        /// Code review 2: a publish that keeps failing escalates the
        /// failure count; a successful fetch on its own does not reset it.
        /// Each state is strictly newer, so the same-state retry plays no
        /// part. A later successful publish resets it.
        #[tokio::test]
        async fn repeated_publish_failures_escalate_the_failure_count() {
            let p = published(62).await;
            let home = p.home();
            let lock = plant_ref_lock(&p.served());
            for (i, at) in [(1u32, T2), (2, T3), (3, T4)] {
                let next = commit_file(&p.up, home, &format!("n{i}.txt"), "n\n", &format!("n{i}"));
                let r = apply_state(
                    &p.m,
                    &p.entry,
                    &p.sk,
                    &[("refs/heads/main", &next)],
                    None,
                    at,
                )
                .await;
                let seen = r.last_seen.unwrap();
                assert!(
                    seen.reason.contains("publish failed"),
                    "control: {}",
                    seen.reason
                );
                assert_eq!(r.failures, i, "failures after {i} failed publishes");
            }
            std::fs::remove_file(lock).unwrap();
            let last = commit_file(&p.up, home, "last.txt", "last\n", "last");
            let r = apply_state(
                &p.m,
                &p.entry,
                &p.sk,
                &[("refs/heads/main", &last)],
                None,
                T5,
            )
            .await;
            assert_eq!(r.last_fetch.map(|f| f.moved), Some(1));
            assert_eq!(r.failures, 0, "a successful publish resets the count");
        }

        /// Code review 3: a transient publish failure is retried for the
        /// same state by the worker, with no newer event. The failed state
        /// is not recorded as acted on, and a retry is scheduled.
        #[tokio::test]
        async fn a_transiently_failed_publish_is_retried_for_the_same_state() {
            let p = published(63).await;
            let home = p.home().to_path_buf();
            let served = p.served();
            let lock = plant_ref_lock(&served);
            let approved2 = commit_file(&p.up, &home, "two.txt", "two\n", "approved two");
            let ev = state_event(
                &p.sk,
                "sample",
                &[("refs/heads/main", &approved2)],
                None,
                T2,
            );
            p.m.enqueue(ev.clone());
            let store = MirrorStore::new(&p.plugin);
            let failed = until("the publish to fail", || {
                let r = store.read(&p.owner, "sample").filter(|r| {
                    r.last_seen
                        .as_ref()
                        .is_some_and(|s| s.reason.contains("publish failed"))
                });
                async move { r }
            })
            .await;
            assert!(failed.retry_at.is_some(), "no retry was scheduled");
            assert_ne!(
                failed.last_event.as_ref().map(|e| e.id.as_str()),
                Some(ev.id.as_str()),
                "the failed state was recorded as acted on"
            );
            std::fs::remove_file(&lock).unwrap();
            until("the same state to publish on retry", || {
                let main = rev(&served, &home, "refs/heads/main");
                let want = approved2.clone();
                async move { (main == want).then_some(()) }
            })
            .await;
            let done = until("the retried record", || {
                let r = store
                    .read(&p.owner, "sample")
                    .filter(|r| r.last_event.as_ref().is_some_and(|e| e.id == ev.id));
                async move { r }
            })
            .await;
            assert_eq!(done.failures, 0);
            assert_eq!(done.last_fetch.map(|f| f.moved), Some(1));
        }

        // --- item 4: announcements take the repository lock ---------------

        /// Security M1 / code review 4: a 30617 updates the record only
        /// under the cross-process lock, and (item 1) marks a clean store
        /// before the record it saves can gate it.
        #[tokio::test]
        async fn an_announcement_waits_for_the_repository_lock_and_marks_a_clean_store() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(64);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let lock_path = plugin
                .join("mirror-work")
                .join("locks")
                .join(&owner)
                .join("sample.lock");
            std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
            let other = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .unwrap();
            other.lock().unwrap();
            let clone = "https://example.org/sample.git";
            let ann = sign(
                &sk,
                KIND_ANNOUNCE,
                tags(&[&["d", "sample"], &["clone", clone]]),
                T1,
            );
            let m2 = m.clone();
            let task = tokio::spawn(async move { m2.on_event(&ann).await });
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(
                !task.is_finished(),
                "the announcement updated the record without the repository lock"
            );
            other.unlock().unwrap();
            drop(other);
            let rec = tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .expect("the announcement finished once the lock was free")
                .unwrap()
                .expect("the announcement changed the record");
            assert_eq!(rec.clone.as_deref(), Some(clone));
            assert!(
                served.join(MARKER_FILE).is_file(),
                "an announcement left a clean followed store unmarked"
            );
            let a = get(
                &forge_at(&plugin),
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(a.status, 200, "{}", String::from_utf8_lossy(&a.body));
        }

        // --- item 5: the publish cap and quarantine leftovers -------------

        /// Security M2 / code review 5: the cap bounds what one publish adds,
        /// not the store's total. Served is already past the cap (a sparse
        /// file; `dir_size` sums lengths), and a small approved publish
        /// still lands.
        #[tokio::test]
        async fn a_small_publish_succeeds_into_a_served_store_already_over_the_cap() {
            let p = published(65).await;
            let served = p.served();
            std::fs::File::create(served.join("objects").join("bloat"))
                .unwrap()
                .set_len(MAX_REPO_BYTES + 1)
                .unwrap();
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let r = apply_state(
                &p.m,
                &p.entry,
                &p.sk,
                &[("refs/heads/main", &approved2)],
                None,
                T2,
            )
            .await;
            let f = r.last_fetch.unwrap();
            assert!(
                f.branches["refs/heads/main"].moved,
                "{}",
                f.branches["refs/heads/main"].verdict
            );
            assert_eq!(rev(&served, p.home(), "refs/heads/main"), approved2);
        }

        fn plant_quarantine(served: &Path) {
            let q = served
                .join("objects")
                .join("tmp_objdir-incoming-planted")
                .join("pack");
            std::fs::create_dir_all(&q).unwrap();
            std::fs::write(q.join("leftover"), b"x").unwrap();
            // Old enough to be a killed push's leftover (round 3, N3).
            let old = std::time::SystemTime::now() - PUBLISH_TIMEOUT - Duration::from_secs(60);
            for path in [
                q.join("leftover"),
                q.clone(),
                q.parent().unwrap().to_path_buf(),
            ] {
                std::fs::File::open(&path)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
        }

        fn quarantines(served: &Path) -> Vec<String> {
            std::fs::read_dir(served.join("objects"))
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("tmp_objdir-incoming-"))
                .collect()
        }

        /// A killed receive-pack leaves `objects/tmp_objdir-incoming-*` in
        /// served. Publication sweeps those older than its push timeout
        /// before it pushes, so a stale leftover is gone after a failed and
        /// after a successful publish alike.
        #[tokio::test]
        async fn publication_leaves_no_receive_quarantine_behind() {
            let p = published(66).await;
            let served = p.served();
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let git = GitCli::new(p.plugin.join("repos"));
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            let to = |expected: &str| RefUpdate {
                git_ref: "refs/heads/main".into(),
                sha: approved2.clone(),
                expected: Some(expected.to_string()),
            };

            plant_quarantine(&served);
            let failed = git
                .publish(&p.owner, "sample", &[to(&"0".repeat(40))], None)
                .await;
            assert!(failed.is_err(), "control: a stale lease fails");
            assert_eq!(
                quarantines(&served),
                Vec::<String>::new(),
                "a failed publish left a quarantine"
            );

            plant_quarantine(&served);
            git.publish(&p.owner, "sample", &[to(&p.approved)], None)
                .await
                .unwrap();
            assert_eq!(rev(&served, p.home(), "refs/heads/main"), approved2);
            assert_eq!(
                quarantines(&served),
                Vec::<String>::new(),
                "a successful publish left a quarantine"
            );
        }

        // --- item 6: an explicit git dir ----------------------------------

        /// Security L1: a candidate that lost `objects/` is not a repository,
        /// and git must not go looking above it. With a repository planted
        /// over `mirror-work/`, the fetch must rebuild the candidate and
        /// write nothing into that parent.
        #[tokio::test]
        async fn a_candidate_missing_its_objects_is_rebuilt_not_resolved_to_a_parent_repo() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let owner = pubhex(&key(67));
            let work = plugin.join("mirror-work");
            std::fs::create_dir_all(&work).unwrap();
            git_ok(&work, home, &["init", "--quiet"]);
            let git = GitCli::new(plugin.join("repos"));
            git.materialise(&owner, "sample").await.unwrap();
            let url = format!("file://{}", up.display());
            git.fetch(&owner, "sample", &url, true, None).await.unwrap();
            let candidate = candidate_of(&plugin, &owner);
            std::fs::remove_dir_all(candidate.join("objects")).unwrap();

            let r = git.fetch(&owner, "sample", &url, true, None).await;
            assert_eq!(
                git_ok(&work, home, &["for-each-ref", "--format=%(refname)"]),
                "",
                "a broken candidate let git write into the parent repository"
            );
            assert!(r.is_ok(), "{r:?}");
            assert!(candidate.join("objects").is_dir(), "candidate not rebuilt");
            assert!(git.has_commit(&owner, "sample", &approved).await);
        }

        // --- item 7: redaction --------------------------------------------

        /// Security L2 / code review 6: an error that names a store path
        /// (here receive-pack's "Unable to create '<served>/./refs/heads/
        /// main.lock'") reaches the public record without the plugin
        /// directory in it. The trigger is a planted ref lock rather than a
        /// read-only directory, which root would ignore (code delta D3).
        #[tokio::test]
        async fn a_failed_publication_keeps_the_plugin_path_out_of_the_saved_record() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(68);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            let approved2 = commit_file(&up, home, "two.txt", "two\n", "approved two");
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            plant_ref_lock(&served);
            let r = apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &approved2)],
                None,
                T1,
            )
            .await;
            let seen = r.last_seen.unwrap();
            assert_eq!(
                seen.action,
                SeenAction::FetchFailed,
                "control: {}",
                seen.reason
            );
            assert!(
                seen.reason.contains("publish failed") && seen.reason.contains("<served>"),
                "control: the failure names the (redacted) served path: {}",
                seen.reason
            );
            let saved = std::fs::read_to_string(record_file(&plugin, &owner)).unwrap();
            let p = plugin.to_str().unwrap();
            assert!(
                !saved.contains(p),
                "the plugin path is in the public record: {saved}"
            );
        }

        /// The same at the adapter: a publish whose candidate is gone fails
        /// with an error that names no store path.
        #[tokio::test]
        async fn an_adapter_error_names_no_store_path() {
            let p = published(69).await;
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let git = GitCli::new(p.plugin.join("repos"));
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            std::fs::remove_dir_all(candidate_of(&p.plugin, &p.owner)).unwrap();
            let e = git
                .publish(
                    &p.owner,
                    "sample",
                    &[RefUpdate {
                        git_ref: "refs/heads/main".into(),
                        sha: approved2,
                        expected: Some(p.approved.clone()),
                    }],
                    None,
                )
                .await
                .unwrap_err();
            let plugin = p.plugin.to_str().unwrap();
            assert!(!e.reason.contains(plugin), "a store path leaked: {e}");
        }

        // --- item 8: the marker gate covers every reader ------------------

        /// A commit with fixed author and committer dates.
        fn commit_at(up: &Path, home: &Path, file: &str, subject: &str, epoch: u64) -> String {
            std::fs::write(up.join(file), subject).unwrap();
            git_ok(up, home, &["add", "-A"]);
            let date = format!("{epoch} +0000");
            let out = Command::new("git")
                .args([
                    "-c",
                    "user.name=Agent",
                    "-c",
                    "user.email=agent@example.org",
                    "commit",
                    "--quiet",
                    "-m",
                    subject,
                ])
                .current_dir(up)
                .env("HOME", home)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            git_ok(up, home, &["rev-parse", "HEAD"])
        }

        const OLD: u64 = 1_700_000_000;
        const NEW: u64 = 1_750_000_000;

        /// A served store in the pre-isolation shape: `main` at an approved
        /// commit (dated [`OLD`]) and, with `record`, a mirror record, no
        /// marker, and a newer held tip (dated [`NEW`]) under `refs/mirror`.
        fn store_with_hidden_tip(
            plugin: &Path,
            owner: &str,
            home: &Path,
            record: bool,
        ) -> (PathBuf, String) {
            let up = home.join(format!("up-{}", &owner[..8]));
            std::fs::create_dir(&up).unwrap();
            git_ok(&up, home, &["init", "--quiet", "-b", "main"]);
            let approved = commit_at(&up, home, "public.txt", "approved", OLD);
            git_ok(&up, home, &["checkout", "--quiet", "-b", "side"]);
            let held = commit_at(&up, home, "held.txt", "held", NEW);
            git_ok(&up, home, &["checkout", "--quiet", "main"]);
            let served = owner_pushed(plugin, owner, &up, home);
            let s = served.to_str().unwrap();
            git_ok(
                &up,
                home,
                &["push", "--quiet", s, &format!("{held}:refs/mirror/main")],
            );
            if record {
                MirrorStore::new(plugin)
                    .save(&MirrorRecord::new(owner, "sample", None))
                    .unwrap();
            }
            (served, approved)
        }

        fn rows(body: &[u8]) -> Vec<Value> {
            let v: Value = serde_json::from_slice(body).unwrap();
            v["repos"].as_array().unwrap().clone()
        }

        /// Security L3: an unmarked mirror's summary is refused (503), and the
        /// listing neither lists it nor reveals its held tip's date.
        #[tokio::test]
        async fn an_unmarked_mirror_is_refused_on_its_summary_and_left_out_of_the_listing() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let owner = pubhex(&key(70));
            store_with_hidden_tip(&plugin, &owner, home, true);
            let forge = forge_at(&plugin);
            let one = get(&forge, format!("/forge/api/repos/{owner}/sample")).await;
            assert_eq!(one.status, 503, "{}", String::from_utf8_lossy(&one.body));
            let all = get(&forge, "/forge/api/repos".into()).await;
            assert_eq!(all.status, 200);
            let body = String::from_utf8_lossy(&all.body).into_owned();
            assert!(
                !body.contains(&NEW.to_string()),
                "held tip date listed: {body}"
            );
            assert!(
                !rows(&all.body).iter().any(|r| r["owner"] == owner.as_str()),
                "an unmarked mirror is listed: {body}"
            );
        }

        /// Security L3: a repository's last push is read from branches and
        /// tags only, never from refs such as `refs/mirror`.
        #[tokio::test]
        async fn last_push_is_read_from_branches_and_tags_only() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let owner = pubhex(&key(71));
            store_with_hidden_tip(&plugin, &owner, home, false);
            let all = get(&forge_at(&plugin), "/forge/api/repos".into()).await;
            let rows = rows(&all.body);
            let row = rows
                .iter()
                .find(|r| r["owner"] == owner.as_str())
                .expect("control: the plain repository is listed");
            assert_eq!(row["lastPush"], OLD, "{row}");
        }

        /// Security L3: a compare whose head names a same-named unmarked
        /// mirror must not fetch that mirror's refs into the base.
        #[tokio::test]
        async fn a_compare_never_reads_a_head_from_an_unmarked_mirror() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let base_owner = pubhex(&key(72));
            let mirror_owner = pubhex(&key(73));
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let base = owner_pushed(&plugin, &base_owner, &up, home);
            store_with_hidden_tip(&plugin, &mirror_owner, home, true);
            let agent = crate::ForgeAgent::Nostr {
                pubkey_hex: mirror_owner.clone(),
            };
            let r = forge_at(&plugin)
                .handle(
                    forge_req(
                        "GET",
                        format!("/forge/api/repos/{base_owner}/sample/compare/main...{mirror_owner}:main"),
                        "",
                    ),
                    agent,
                )
                .await
                .unwrap();
            assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
            assert_eq!(
                git_ok(
                    &base,
                    home,
                    &["for-each-ref", "--format=%(refname)", "refs/forge"]
                ),
                "",
                "the unmarked mirror's head was fetched into the base"
            );
        }

        // --- item 11: cancellation and readers during a running fetch -----

        /// A clone host that accepts and never answers: a fetch from it
        /// stays in flight until it is killed. `accepted` fires once git has
        /// connected, so the fetch is provably running.
        async fn silent_host() -> (
            String,
            Arc<tokio::sync::Notify>,
            tokio::task::JoinHandle<()>,
        ) {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/sample.git", l.local_addr().unwrap());
            let accepted = Arc::new(tokio::sync::Notify::new());
            let a2 = accepted.clone();
            let host = tokio::spawn(async move {
                let mut open = Vec::new();
                while let Ok((s, _)) = l.accept().await {
                    open.push(s);
                    a2.notify_one();
                }
            });
            (url, accepted, host)
        }

        /// The side fixture (held commit in the candidate, approved in
        /// served), then a third state whose fetch hangs on a silent host.
        struct InFlight {
            s: Side,
            before: (String, String),
            task: tokio::task::JoinHandle<MirrorRecord>,
            host: tokio::task::JoinHandle<()>,
        }

        async fn fetch_in_flight(seed: u8) -> InFlight {
            let s = side_fixture(seed).await;
            let home = s.tmp.path();
            let before = store_snapshot(&served_of(home, &s.owner), home);
            assert!(
                has_object(&candidate_of(home, &s.owner), &s.held),
                "control: the candidate holds the held commit"
            );
            let (url, accepted, host) = silent_host().await;
            let entry = FollowEntry {
                pubkey: s.owner.clone(),
                name: "sample".into(),
                clone: Some(url),
            };
            let m = engine(home, quiet_cfg(&entry));
            let (sk, held) = (key(seed), s.held.clone());
            let task = tokio::spawn(async move {
                apply_state(&m, &entry, &sk, &[("refs/heads/main", &held)], None, T3).await
            });
            tokio::time::timeout(Duration::from_secs(30), accepted.notified())
                .await
                .expect("the fetch reached the clone host");
            assert!(!task.is_finished(), "control: the fetch is still running");
            InFlight {
                s,
                before,
                task,
                host,
            }
        }

        fn assert_served_unchanged(s: &Side, before: &(String, String)) {
            let home = s.tmp.path();
            let served = served_of(home, &s.owner);
            assert_eq!(&store_snapshot(&served, home), before, "served changed");
            assert!(!has_object(&served, &s.held), "held commit in served");
            assert!(
                !has_object(&served, &blob_id(home, HELD_BYTES)),
                "held blob in served"
            );
        }

        /// Codex gap 2: an `apply` aborted while its fetch is running (git
        /// connected to the clone host, no answer yet) leaves served exactly
        /// as it was, and the held commit in the candidate stays unreadable.
        #[tokio::test]
        async fn an_apply_aborted_while_its_fetch_runs_leaves_served_untouched() {
            let InFlight {
                s,
                before,
                task,
                host,
            } = fetch_in_flight(74).await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_served_unchanged(&s, &before);
            let forge = forge_at(s.tmp.path());
            let h = get(
                &forge,
                format!("/forge/{}/sample/raw/{}/held.txt", s.owner, s.held),
            )
            .await;
            assert_eq!(h.status, 404, "{}", String::from_utf8_lossy(&h.body));
            host.abort();
        }

        /// Codex gap 2: readers running while a fetch is in flight see served
        /// only: approved 200, the candidate's held commit 404, and served's
        /// refs and objects unchanged.
        #[tokio::test]
        async fn readers_during_an_in_flight_fetch_see_only_served() {
            let f = fetch_in_flight(75).await;
            let forge = forge_at(f.s.tmp.path());
            let (o, a, h) = (&f.s.owner, &f.s.approved, &f.s.held);
            let held = get(&forge, format!("/forge/{o}/sample/raw/{h}/held.txt")).await;
            assert_eq!(held.status, 404, "{}", String::from_utf8_lossy(&held.body));
            let commit = get(&forge, format!("/forge/{o}/sample/commit/{h}")).await;
            assert_eq!(
                commit.status,
                404,
                "{}",
                String::from_utf8_lossy(&commit.body)
            );
            let ok = get(&forge, format!("/forge/{o}/sample/raw/{a}/public.txt")).await;
            assert_eq!(
                (ok.status, ok.body.as_ref()),
                (200, APPROVED_BYTES.as_bytes())
            );
            assert!(!f.task.is_finished(), "control: the reads ran mid-fetch");
            assert_served_unchanged(&f.s, &f.before);
            f.task.abort();
            f.host.abort();
        }

        // --- item 12: atomic and receiver-side failures --------------------

        /// Codex gap 3: two approved branches in one publish, one lease
        /// stale. `--atomic` refuses both: neither ref moves and no new
        /// object lands in served.
        #[tokio::test]
        async fn an_atomic_two_branch_publish_with_one_stale_lease_moves_neither() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let a1 = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            git_ok(&up, home, &["checkout", "--quiet", "-b", "side"]);
            let s1 = commit_file(&up, home, "side.txt", "side one\n", "side one");
            let sk = key(76);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &a1), ("refs/heads/side", &s1)],
                None,
                T1,
            )
            .await;
            assert_eq!(
                r.last_fetch.map(|f| f.moved),
                Some(2),
                "control: both published"
            );
            let s2 = commit_file(&up, home, "side.txt", "side two\n", "side two");
            git_ok(&up, home, &["checkout", "--quiet", "main"]);
            let a2 = commit_file(&up, home, "main.txt", "main two\n", "main two");
            let git = GitCli::new(plugin.join("repos"));
            git.fetch(
                &owner,
                "sample",
                &format!("file://{}", up.display()),
                true,
                None,
            )
            .await
            .unwrap();
            let served = served_of(&plugin, &owner);
            let x = move_served_main_behind_the_engine(&served, home);
            let before = store_snapshot(&served, home);
            let r = git
                .publish(
                    &owner,
                    "sample",
                    &[
                        RefUpdate {
                            git_ref: "refs/heads/main".into(),
                            sha: a2.clone(),
                            expected: Some(a1.clone()),
                        },
                        RefUpdate {
                            git_ref: "refs/heads/side".into(),
                            sha: s2.clone(),
                            expected: Some(s1.clone()),
                        },
                    ],
                    Some("refs/heads/main"),
                )
                .await;
            assert!(r.is_err(), "a publish with a stale lease succeeded");
            assert_eq!(rev(&served, home, "refs/heads/main"), x);
            assert_eq!(
                rev(&served, home, "refs/heads/side"),
                s1,
                "the branch with a current lease moved alone"
            );
            assert_eq!(store_snapshot(&served, home), before, "served changed");
            assert!(!has_object(&served, &a2), "refused main commit in served");
            assert!(!has_object(&served, &s2), "refused side commit in served");
        }

        /// Codex gap 3: a receiver-side ref-lock failure. receive-pack has
        /// already migrated its quarantine when the ref transaction fails, so
        /// objects may land; they must be approved history only. The error
        /// is recorded, `main` stays put, and the held side commit is absent.
        #[tokio::test]
        async fn a_receiver_ref_lock_failure_is_recorded_and_lands_only_approved_history() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let base = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(77);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            apply_state(&m, &entry, &sk, &[("refs/heads/main", &base)], None, T1).await;
            let main2 = commit_file(
                &up,
                home,
                TRAIL_FILE,
                &trail_for(&owner, &base),
                "trail: mark base",
            );
            git_ok(&up, home, &["checkout", "--quiet", "-b", "side", &base]);
            let held = commit_file(&up, home, "held.txt", HELD_BYTES, HELD_SUBJECT);
            git_ok(&up, home, &["checkout", "--quiet", "main"]);
            let served = served_of(&plugin, &owner);
            assert_eq!(
                git_ok(&served, home, &["rev-parse", "--show-ref-format"]),
                "files",
                "control: a planted .lock only blocks the files ref backend"
            );
            plant_ref_lock(&served);

            let rec = apply_state(
                &m,
                &entry,
                &sk,
                &[("refs/heads/main", &main2), ("refs/heads/side", &held)],
                Some(&base),
                T2,
            )
            .await;
            let seen = rec.last_seen.unwrap();
            assert_eq!(seen.action, SeenAction::FetchFailed, "{}", seen.reason);
            assert!(seen.reason.contains("publish failed"), "{}", seen.reason);
            let f = rec.last_fetch.unwrap();
            let main = &f.branches["refs/heads/main"];
            assert!(
                !main.moved && main.verdict.contains("publish failed"),
                "{}",
                main.verdict
            );
            assert!(!f.branches["refs/heads/side"].moved);
            assert_eq!(rev(&served, home, "refs/heads/main"), base);
            assert!(!has_object(&served, &held), "held side commit in served");
            assert!(
                !has_object(&served, &blob_id(home, HELD_BYTES)),
                "held blob in served"
            );
            // The failure was the receiver's ref lock, after the quarantine
            // was migrated, not an earlier step that would satisfy the
            // negative assertions above by never pushing at all.
            assert!(seen.reason.contains("cannot lock ref"), "{}", seen.reason);
            assert!(
                has_object(&served, &main2),
                "the approved commit did not land: the push never reached the ref transaction"
            );
        }

        // --- round 2 -------------------------------------------------------

        const T6: u64 = 1_760_000_006;

        /// Code delta D1: with no rate limit (`minIntervalMs: 0`, a supported
        /// setting) a failed publish must still wait before its retry, or
        /// the worker refetches and re-pushes in a hot loop.
        #[tokio::test]
        async fn a_failed_publish_waits_before_its_retry_even_with_no_rate_limit() {
            let p = published(71).await;
            plant_ref_lock(&p.served());
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let r = apply_state(
                &p.m,
                &p.entry,
                &p.sk,
                &[("refs/heads/main", &approved2)],
                None,
                T2,
            )
            .await;
            let seen = r.last_seen.clone().unwrap();
            assert!(
                seen.reason.contains("publish failed"),
                "control: {}",
                seen.reason
            );
            let at = r.retry_at.expect("a transient publish failure is retried");
            assert!(
                at >= seen.at + 1000,
                "retry scheduled {} ms after the failure",
                at.saturating_sub(seen.at)
            );
        }

        /// Code delta D1 (optional) / security delta N2: a store in the
        /// pre-isolation layout is refused by `prepare` and stays refused
        /// until migration. The state is not fetched (no candidate, no
        /// fetch record), not retried, and not recorded as acted on.
        #[tokio::test]
        async fn a_legacy_store_is_neither_fetched_nor_retried() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let sk = key(72);
            let owner = pubhex(&sk);
            let (served, approved) = store_with_hidden_tip(&plugin, &owner, home, false);
            let up = home.join(format!("up-{}", &owner[..8]));
            let next = commit_file(&up, home, "next.txt", "next\n", "next");
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &next)], None, T1).await;
            let seen = r.last_seen.clone().unwrap();
            assert!(seen.reason.contains("awaits migration"), "{}", seen.reason);
            assert_eq!(seen.action, SeenAction::Skip, "{}", seen.reason);
            assert_eq!(
                r.retry_at, None,
                "a permanent refusal was scheduled for retry"
            );
            assert!(r.last_fetch.is_none(), "a legacy store was fetched");
            assert!(
                r.last_event.is_none(),
                "the refused state was recorded as acted on"
            );
            assert!(
                !candidate_of(&plugin, &owner).exists(),
                "a candidate was built for a legacy store"
            );
            assert_eq!(rev(&served, home, "refs/heads/main"), approved);
            assert!(
                !served.join(MARKER_FILE).exists(),
                "a legacy store was marked"
            );
        }

        /// Security delta N2: a worker waiting out a publish retry wakes for
        /// a newer state of the same repository instead of sleeping through
        /// the backoff. Four failures put the retry at least 16 s out; the
        /// newer state must land well before that.
        #[tokio::test]
        async fn a_newer_state_wakes_a_worker_waiting_to_retry() {
            let p = published(73).await;
            let home = p.home().to_path_buf();
            let served = p.served();
            let lock = plant_ref_lock(&served);
            for (i, at) in [(1u32, T2), (2, T3), (3, T4)] {
                let next = commit_file(&p.up, &home, &format!("n{i}.txt"), "n\n", &format!("n{i}"));
                let r = apply_state(
                    &p.m,
                    &p.entry,
                    &p.sk,
                    &[("refs/heads/main", &next)],
                    None,
                    at,
                )
                .await;
                assert_eq!(r.failures, i, "control: failure {i}");
            }
            let fourth = commit_file(&p.up, &home, "n4.txt", "n\n", "n4");
            let ev = state_event(&p.sk, "sample", &[("refs/heads/main", &fourth)], None, T5);
            p.m.enqueue(ev.clone());
            let store = MirrorStore::new(&p.plugin);
            let failed = until("the fourth publish to fail", || {
                let r = store.read(&p.owner, "sample").filter(|r| {
                    r.failures == 4 && r.last_seen.as_ref().is_some_and(|s| s.id == ev.id)
                });
                async move { r }
            })
            .await;
            let wait = failed
                .retry_at
                .unwrap()
                .saturating_sub(failed.last_seen.unwrap().at);
            assert!(wait >= 16_000, "control: the retry is only {wait} ms out");
            std::fs::remove_file(&lock).unwrap();
            let newest = commit_file(&p.up, &home, "n5.txt", "n\n", "n5");
            let t0 = std::time::Instant::now();
            p.m.enqueue(state_event(
                &p.sk,
                "sample",
                &[("refs/heads/main", &newest)],
                None,
                T6,
            ));
            until("the newer state to publish", || {
                let main = rev(&served, &home, "refs/heads/main");
                let want = newest.clone();
                async move { (main == want).then_some(()) }
            })
            .await;
            assert!(
                t0.elapsed() < Duration::from_secs(8),
                "the newer state waited {:?} behind the retry",
                t0.elapsed()
            );
        }

        /// Security delta N1: the per-publish cap bounds growth, and a hard
        /// ceiling bounds the total. A served store already past the
        /// ceiling refuses publication with a reason, before any push, and
        /// the refusal is not retried.
        #[tokio::test]
        async fn a_served_store_past_the_ceiling_refuses_publication_without_retry() {
            let p = published(74).await;
            let served = p.served();
            std::fs::File::create(served.join("objects").join("bloat"))
                .unwrap()
                .set_len(MAX_SERVED_BYTES + 1)
                .unwrap();
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let r = apply_state(
                &p.m,
                &p.entry,
                &p.sk,
                &[("refs/heads/main", &approved2)],
                None,
                T2,
            )
            .await;
            let seen = r.last_seen.clone().unwrap();
            assert!(seen.reason.contains("ceiling"), "{}", seen.reason);
            assert!(
                !seen.reason.contains("grew past"),
                "a push was started: {}",
                seen.reason
            );
            assert_eq!(
                r.retry_at, None,
                "a permanent refusal was scheduled for retry"
            );
            assert_eq!(rev(&served, p.home(), "refs/heads/main"), p.approved);
        }

        /// Security delta T1: while a newer state S2 waits to be retried
        /// after a failed publish, an older owner-signed state S1.5 is a
        /// replay and is refused (no rollback); S2 itself still lands.
        #[tokio::test]
        async fn an_older_state_during_a_publish_retry_is_refused_as_a_replay() {
            let p = published(75).await;
            let home = p.home().to_path_buf();
            let served = p.served();
            let lock = plant_ref_lock(&served);
            let mid = commit_file(&p.up, &home, "mid.txt", "mid\n", "mid");
            let two = commit_file(&p.up, &home, "two.txt", "two\n", "two");
            let s2 = state_event(&p.sk, "sample", &[("refs/heads/main", &two)], None, T3);
            let r = p.m.apply(&p.entry, &s2).await;
            assert!(
                r.last_seen.unwrap().reason.contains("publish failed"),
                "control: S2 fails"
            );
            std::fs::remove_file(&lock).unwrap();
            let r = apply_state(
                &p.m,
                &p.entry,
                &p.sk,
                &[("refs/heads/main", &mid)],
                None,
                T2,
            )
            .await;
            let seen = r.last_seen.unwrap();
            assert!(
                seen.reason.contains("older than a state already seen"),
                "{}",
                seen.reason
            );
            assert_eq!(
                rev(&served, &home, "refs/heads/main"),
                p.approved,
                "rolled to S1.5"
            );
            let r = p.m.apply(&p.entry, &s2).await;
            assert_eq!(
                r.last_fetch.map(|f| f.moved),
                Some(1),
                "S2 did not land on retry"
            );
            assert_eq!(rev(&served, &home, "refs/heads/main"), two);
        }

        /// A record's persisted `retry_at` belongs to the newest state seen.
        /// An older state skipped as a replay hands that record back, and
        /// must not arm the worker's retry with it: a past `retry_at` would
        /// requeue the replay every 50 ms for ever.
        #[tokio::test]
        async fn a_replay_does_not_inherit_the_newest_state_retry() {
            let p = published(76).await;
            let home = p.home().to_path_buf();
            plant_ref_lock(&p.served());
            let two = commit_file(&p.up, &home, "two.txt", "two\n", "two");
            let s2 = state_event(&p.sk, "sample", &[("refs/heads/main", &two)], None, T3);
            let r = p.m.apply(&p.entry, &s2).await;
            assert!(r.retry_at.is_some(), "control: S2 is due a retry");
            let store = MirrorStore::new(&p.plugin);
            let mut stale = store.read(&p.owner, "sample").unwrap();
            stale.retry_at = Some(1);
            store.save(&stale).unwrap();
            let mid = commit_file(&p.up, &home, "mid.txt", "mid\n", "mid");
            p.m.enqueue(state_event(
                &p.sk,
                "sample",
                &[("refs/heads/main", &mid)],
                None,
                T2,
            ));
            let key = format!("{}/sample", p.owner);
            until("the worker to go idle after the replay", || {
                let idle =
                    !p.m.busy
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .contains(&key);
                async move { idle.then_some(()) }
            })
            .await;
            let events = store.read(&p.owner, "sample").unwrap().events;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                store.read(&p.owner, "sample").unwrap().events,
                events,
                "the replay is still being re-applied"
            );
        }

        // --- round 3 -------------------------------------------------------

        fn json_req(method: &str, path: String, body: &serde_json::Value) -> crate::ForgeRequest {
            crate::ForgeRequest {
                method: method.into(),
                path,
                query: String::new(),
                headers: vec![("content-type".into(), "application/json".into())],
                raw_body: bytes::Bytes::from(body.to_string()),
                host_url: Some("https://pod.example".into()),
            }
        }

        fn pod_agent(user: &str) -> crate::ForgeAgent {
            crate::ForgeAgent::Pod {
                webid: format!("https://pod.example/{user}/profile/card#me"),
                username: user.to_string(),
            }
        }

        /// `repos/dana/sample.git`, owned by the caller `dana`, with a
        /// `feature` branch whose commit carries a blob found nowhere else.
        /// Returns the blob id.
        fn caller_head_repo(plugin: &Path, home: &Path, seed: u8) -> String {
            let work = home.join(format!("dana-work-{seed}"));
            std::fs::create_dir(&work).unwrap();
            git_ok(&work, home, &["init", "--quiet", "-b", "feature"]);
            let body = format!("dana-injected-{seed}\n");
            commit_file(&work, home, "dana.txt", &body, "dana's head");
            let bare = plugin.join("repos").join("dana").join("sample.git");
            std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
            let b = bare.to_str().unwrap();
            git_ok(home, home, &["init", "--bare", "--quiet", b]);
            git_ok(&work, home, &["push", "--quiet", b, "feature:feature"]);
            blob_id(home, &body)
        }

        fn forge_heads(served: &Path, home: &Path) -> String {
            git_ok(
                served,
                home,
                &["for-each-ref", "--format=%(refname)", "refs/forge/heads/"],
            )
        }

        /// Codex High 1: a compare whose head is another repository the
        /// caller owns would fetch that head into the base's served store.
        /// For a mirror that plants the caller's objects in served, readable
        /// by SHA. Refused (409), and nothing is fetched.
        #[tokio::test]
        async fn a_compare_into_a_mirror_never_fetches_a_foreign_head() {
            let p = published(80).await;
            let blob = caller_head_repo(&p.plugin, p.home(), 80);
            let forge = forge_at(&p.plugin);
            let r = forge
                .handle(
                    forge_req(
                        "GET",
                        format!(
                            "/forge/api/repos/{}/sample/compare/main...dana:feature",
                            p.owner
                        ),
                        "",
                    ),
                    pod_agent("dana"),
                )
                .await
                .unwrap();
            assert!(
                !has_object(&p.served(), &blob),
                "a foreign blob reached served"
            );
            assert_eq!(
                forge_heads(&p.served(), p.home()),
                "",
                "a foreign head ref was written"
            );
            assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
        }

        /// Codex High 1, the pull request path: opening a pull request on a
        /// mirror with a foreign head is refused before the head is fetched.
        #[tokio::test]
        async fn a_pull_request_into_a_mirror_never_fetches_a_foreign_head() {
            let p = published(81).await;
            let blob = caller_head_repo(&p.plugin, p.home(), 81);
            let forge = forge_at(&p.plugin);
            let body = serde_json::json!({
                "title": "inject",
                "base": "main",
                "head": "dana:feature",
                "resourceUrl": "https://pod.example/dana/pr.jsonld",
            });
            let r = forge
                .handle(
                    json_req(
                        "POST",
                        format!("/forge/api/repos/{}/sample/pulls", p.owner),
                        &body,
                    ),
                    pod_agent("dana"),
                )
                .await
                .unwrap();
            assert!(
                !has_object(&p.served(), &blob),
                "a foreign blob reached served"
            );
            assert_eq!(
                forge_heads(&p.served(), p.home()),
                "",
                "a foreign head ref was written"
            );
            assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
        }

        /// Codex High 1, other writers: a web edit by the mirror's own key
        /// would commit into served outside publication. Refused (409).
        #[tokio::test]
        async fn a_web_edit_into_a_mirror_is_refused() {
            let p = published(82).await;
            let objects_before = object_set(&p.served(), p.home());
            let forge = forge_at(&p.plugin);
            let body = serde_json::json!({"path": "edit.txt", "content": "edited\n"});
            let r = forge
                .handle(
                    json_req(
                        "POST",
                        format!("/forge/api/repos/{}/sample/edit", p.owner),
                        &body,
                    ),
                    crate::ForgeAgent::Nostr {
                        pubkey_hex: p.owner.clone(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
            assert_eq!(rev(&p.served(), p.home(), "refs/heads/main"), p.approved);
            assert_eq!(
                object_set(&p.served(), p.home()),
                objects_before,
                "a refused web edit wrote objects into served"
            );
        }

        /// Codex High 1, other writers: a pull request opened before the
        /// repository became a mirror cannot be merged into it (the merge
        /// commit would be written into served outside publication).
        #[tokio::test]
        async fn a_pull_request_cannot_be_merged_into_a_mirror() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(83);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            git_ok(&up, home, &["checkout", "--quiet", "-b", "feature"]);
            commit_file(&up, home, "feature.txt", "feature\n", "feature");
            git_ok(
                &up,
                home,
                &[
                    "push",
                    "--quiet",
                    served.to_str().unwrap(),
                    "feature:feature",
                ],
            );
            let main = rev(&served, home, "refs/heads/main");
            let forge = forge_at(&plugin);
            let agent = || crate::ForgeAgent::Nostr {
                pubkey_hex: owner.clone(),
            };
            let body = serde_json::json!({
                "title": "feature", "base": "main", "head": "feature", "body": "please merge",
            });
            let r = forge
                .handle(
                    json_req(
                        "POST",
                        format!("/forge/api/repos/{owner}/sample/pulls"),
                        &body,
                    ),
                    agent(),
                )
                .await
                .unwrap();
            assert_eq!(
                r.status,
                201,
                "control: {}",
                String::from_utf8_lossy(&r.body)
            );
            // It becomes a followed, marked mirror.
            MirrorStore::new(&plugin)
                .save(&MirrorRecord::new(&owner, "sample", None))
                .unwrap();
            std::fs::write(served.join(MARKER_FILE), "").unwrap();
            let objects_before = object_set(&served, home);
            let r = forge
                .handle(
                    json_req(
                        "POST",
                        format!("/forge/api/repos/{owner}/sample/pulls/1/merge"),
                        &serde_json::json!({}),
                    ),
                    agent(),
                )
                .await
                .unwrap();
            assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
            assert_eq!(
                rev(&served, home, "refs/heads/main"),
                main,
                "the merge moved main"
            );
            assert_eq!(
                object_set(&served, home),
                objects_before,
                "a refused merge wrote objects into served"
            );
        }

        /// Codex High 2: a store with no `refs/mirror` and no `hideRefs`, but
        /// holding an object no ref reaches (here a held blob), may still
        /// serve it by SHA. It is not marked, and readers keep refusing it.
        /// The same layout without the extra object is marked.
        #[tokio::test]
        async fn a_store_holding_an_unreachable_object_is_not_marked() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let git = GitCli::new(plugin.join("repos"));

            let dirty = pubhex(&key(84));
            let served = owner_pushed(&plugin, &dirty, &up, home);
            let loose = home.join("held-blob.txt");
            std::fs::write(&loose, HELD_BYTES).unwrap();
            let held = git_ok(
                &served,
                home,
                &["hash-object", "-w", loose.to_str().unwrap()],
            );
            assert!(
                has_object(&served, &held),
                "control: the held blob is in served"
            );
            MirrorStore::new(&plugin)
                .save(&MirrorRecord::new(&dirty, "sample", None))
                .unwrap();
            assert_eq!(
                git.prepare(&dirty, "sample", true).await,
                Ok(Prepared::AwaitsMigration)
            );
            assert!(
                !served.join(MARKER_FILE).exists(),
                "a store with an unreachable object was marked"
            );
            let forge = forge_at(&plugin);
            let r = get(
                &forge,
                format!("/forge/{dirty}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));

            let clean = pubhex(&key(85));
            let served = owner_pushed(&plugin, &clean, &up, home);
            MirrorStore::new(&plugin)
                .save(&MirrorRecord::new(&clean, "sample", None))
                .unwrap();
            assert_eq!(
                git.prepare(&clean, "sample", true).await,
                Ok(Prepared::Ready)
            );
            assert!(
                served.join(MARKER_FILE).is_file(),
                "control: a clean store is marked"
            );
        }

        /// Security delta N3: the sweep removes only quarantines old enough
        /// to be leftovers of a killed push. A fresh one (a concurrent push
        /// in flight) survives the sweep before a publish and the sweep after
        /// a failed one; an old one is removed.
        #[tokio::test]
        async fn a_fresh_quarantine_survives_a_failed_and_a_later_publish_and_an_old_one_does_not()
        {
            let p = published(86).await;
            let served = p.served();
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let git = GitCli::new(p.plugin.join("repos"));
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            let fresh = served.join("objects").join("tmp_objdir-incoming-fresh");
            // A concurrent owner push whose quarantine appears while the
            // failing publication runs (round 4: after any snapshot it took).
            fn owner_push_starts(served: &Path) {
                let pack = served
                    .join("objects")
                    .join("tmp_objdir-incoming-fresh")
                    .join("pack");
                std::fs::create_dir_all(&pack).unwrap();
                std::fs::write(pack.join("partial"), b"x").unwrap();
            }
            let failing = GitCli {
                during_push: Some(owner_push_starts),
                ..git.clone()
            };
            plant_quarantine(&served);
            let to = |expected: &str| RefUpdate {
                git_ref: "refs/heads/main".into(),
                sha: approved2.clone(),
                expected: Some(expected.to_string()),
            };
            let failed = failing
                .publish(&p.owner, "sample", &[to(&"0".repeat(40))], None)
                .await;
            assert!(failed.is_err(), "control: a stale lease fails");
            assert_eq!(
                quarantines(&served),
                vec!["tmp_objdir-incoming-fresh".to_string()],
                "after a failed publish"
            );
            git.publish(&p.owner, "sample", &[to(&p.approved)], None)
                .await
                .unwrap();
            assert_eq!(
                quarantines(&served),
                vec!["tmp_objdir-incoming-fresh".to_string()],
                "after a successful publish"
            );
            assert!(fresh.join("pack").join("partial").is_file());
        }

        /// Code delta D2: a short plugin root is not replaced inside
        /// unrelated text (here a URL); the store roots are.
        #[test]
        fn redaction_leaves_unrelated_text_alone_under_a_short_plugin_root() {
            let git = GitCli::new("/d/repos");
            let owner = "a".repeat(64);
            for text in [
                "unable to access 'https://host/d/x.git': 404",
                "unable to access 'https://host/d/repos/x.git': 404",
                "no such file /d/repository",
            ] {
                assert_eq!(git.redact(&owner, "sample", text), text);
            }
            let served = format!("could not lock config file /d/repos/{owner}/sample.git/config");
            assert_eq!(
                git.redact(&owner, "sample", &served),
                "could not lock config file <served>/config"
            );
            let lock = "unable to open /d/mirror-work/locks/x.lock";
            assert_eq!(
                git.redact(&owner, "sample", lock),
                "unable to open <plugin>/mirror-work/locks/x.lock"
            );
        }

        // --- round 4 -------------------------------------------------------

        /// Every object in a store, as `cat-file --batch-all-objects
        /// --batch-check` lists them (round 4, item 5).
        fn object_set(dir: &Path, home: &Path) -> String {
            git_ok(
                dir,
                home,
                &["cat-file", "--batch-all-objects", "--batch-check"],
            )
        }

        /// Round 4 item 1: a mirror record path that cannot be read (here
        /// its parent is a file, so `stat` fails with ENOTDIR; no reliance
        /// on modes, which root ignores) is not "no record". Writers refuse,
        /// and the reader gate stays closed for an unmarked store.
        #[tokio::test]
        async fn an_unreadable_record_path_refuses_writes_and_keeps_the_gate_closed() {
            let p = published(90).await;
            let served = p.served();
            let owner_dir = p.plugin.join("mirror").join(&p.owner);
            std::fs::remove_dir_all(&owner_dir).unwrap();
            std::fs::write(&owner_dir, b"not a directory").unwrap();
            let objects_before = object_set(&served, p.home());
            let forge = forge_at(&p.plugin);
            let body = serde_json::json!({"path": "edit.txt", "content": "edited\n"});
            let r = forge
                .handle(
                    json_req(
                        "POST",
                        format!("/forge/api/repos/{}/sample/edit", p.owner),
                        &body,
                    ),
                    crate::ForgeAgent::Nostr {
                        pubkey_hex: p.owner.clone(),
                    },
                )
                .await
                .unwrap();
            assert!(
                matches!(r.status, 409 | 503),
                "a write went ahead with an unreadable record: {} {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
            assert_eq!(rev(&served, p.home(), "refs/heads/main"), p.approved);
            assert_eq!(object_set(&served, p.home()), objects_before);

            std::fs::remove_file(served.join(MARKER_FILE)).unwrap();
            let raw = get(
                &forge,
                format!("/forge/{}/sample/raw/{}/public.txt", p.owner, p.approved),
            )
            .await;
            assert_eq!(
                raw.status,
                503,
                "the gate opened on an unreadable record: {}",
                String::from_utf8_lossy(&raw.body)
            );
        }

        /// Round 4 item 2: `HEAD` is not a root. A detached `HEAD` at a
        /// commit no branch or tag reaches leaves the store unmarked.
        #[tokio::test]
        async fn a_detached_head_at_an_unreferenced_commit_is_not_marked() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let owner = pubhex(&key(91));
            let served = owner_pushed(&plugin, &owner, &up, home);
            let tree = git_ok(&served, home, &["rev-parse", "refs/heads/main^{tree}"]);
            let stray = git_ok(
                &served,
                home,
                &[
                    "-c",
                    "user.name=Agent",
                    "-c",
                    "user.email=agent@example.org",
                    "commit-tree",
                    &tree,
                    "-m",
                    "stray",
                ],
            );
            git_ok(&served, home, &["update-ref", "--no-deref", "HEAD", &stray]);
            MirrorStore::new(&plugin)
                .save(&MirrorRecord::new(&owner, "sample", None))
                .unwrap();
            let git = GitCli::new(plugin.join("repos"));
            assert_eq!(
                git.prepare(&owner, "sample", true).await,
                Ok(Prepared::AwaitsMigration)
            );
            assert!(!served.join(MARKER_FILE).exists(), "marked");
        }

        /// Round 4 item 3: a store that borrows objects through alternates
        /// (local or HTTP) is not marked, since what it serves is not
        /// confined to its own object store.
        #[tokio::test]
        async fn a_store_with_alternates_is_not_marked() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let git = GitCli::new(plugin.join("repos"));
            let elsewhere = up.join(".git").join("objects");
            for (seed, file, line) in [
                (92u8, "alternates", elsewhere.to_str().unwrap().to_string()),
                (
                    95u8,
                    "http-alternates",
                    "https://example.invalid/objects".into(),
                ),
            ] {
                let owner = pubhex(&key(seed));
                let served = owner_pushed(&plugin, &owner, &up, home);
                let info = served.join("objects").join("info");
                std::fs::create_dir_all(&info).unwrap();
                std::fs::write(info.join(file), format!("{line}\n")).unwrap();
                MirrorStore::new(&plugin)
                    .save(&MirrorRecord::new(&owner, "sample", None))
                    .unwrap();
                assert_eq!(
                    git.prepare(&owner, "sample", true).await,
                    Ok(Prepared::AwaitsMigration),
                    "{file}"
                );
                assert!(!served.join(MARKER_FILE).exists(), "{file}: marked");
            }
        }

        /// Round 4 item 3: a marked store that later gains an alternates
        /// file is refused publication, terminally, and nothing moves.
        #[tokio::test]
        async fn a_marked_store_that_gains_alternates_refuses_publication() {
            let p = published(93).await;
            let served = p.served();
            let approved2 = commit_file(&p.up, p.home(), "two.txt", "two\n", "approved two");
            let git = GitCli::new(p.plugin.join("repos"));
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            let info = served.join("objects").join("info");
            std::fs::create_dir_all(&info).unwrap();
            let elsewhere = p.up.join(".git").join("objects");
            std::fs::write(
                info.join("alternates"),
                format!("{}\n", elsewhere.display()),
            )
            .unwrap();
            let r = git
                .publish(
                    &p.owner,
                    "sample",
                    &[RefUpdate {
                        git_ref: "refs/heads/main".into(),
                        sha: approved2.clone(),
                        expected: Some(p.approved.clone()),
                    }],
                    None,
                )
                .await;
            let e = r.expect_err("published into a store with alternates");
            assert!(!e.retryable, "{}", e.reason);
            assert_eq!(rev(&served, p.home(), "refs/heads/main"), p.approved);
        }

        /// Round 4 item 4: a quarantine whose scan cannot be completed (an
        /// unreadable `pack/`) has no age (so the sweep treats it as fresh),
        /// instead of being judged by the entries that could be read. Needs a non-root user: root reads
        /// through mode 000, so the test reports that and returns.
        #[cfg(unix)]
        #[tokio::test]
        async fn a_quarantine_that_cannot_be_scanned_has_no_age() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let served = tmp.path().join("served.git");
            std::fs::create_dir_all(served.join("objects")).unwrap();
            plant_quarantine(&served);
            let q = served.join("objects").join("tmp_objdir-incoming-planted");
            let pack = q.join("pack");
            std::fs::set_permissions(&pack, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read_dir(&pack).is_ok() {
                std::fs::set_permissions(&pack, std::fs::Permissions::from_mode(0o755)).unwrap();
                eprintln!("NOT RUN a_quarantine_that_cannot_be_scanned_has_no_age: mode 000 is readable (root)");
                return;
            }
            // Asked of the age scan itself: the sweep's removal would also
            // fail on the unreadable directory, which would hide the verdict.
            let seen = newest_mtime(&q).await;
            std::fs::set_permissions(&pack, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                seen, None,
                "a quarantine that could not be fully scanned was given an age"
            );
        }

        // --- round 5 -------------------------------------------------------

        /// Wait until the record shows `ev` failed and scheduled a retry.
        async fn until_retry_scheduled(p: &Published, ev: &Event) -> MirrorRecord {
            let store = MirrorStore::new(&p.plugin);
            let id = ev.id.clone();
            until("the state to fail with a retry scheduled", || {
                let r = store.read(&p.owner, "sample").filter(|r| {
                    r.retry_at.is_some() && r.last_seen.as_ref().is_some_and(|s| s.id == id)
                });
                async move { r }
            })
            .await
        }

        async fn until_main_is(p: &Published, want: &str, what: &str) {
            let served = p.served();
            let home = p.home().to_path_buf();
            until(what, || {
                let main = rev(&served, &home, "refs/heads/main");
                let ok = main == want;
                async move { ok.then_some(()) }
            })
            .await;
        }

        /// Item 1 (Codex C1): a forged newer state (its tags tampered after
        /// signing) neither cancels the pending retry nor takes its place;
        /// the retry still fires and publishes.
        #[tokio::test]
        async fn a_forged_newer_state_does_not_cancel_a_pending_retry() {
            let p = published(100).await;
            let lock = plant_ref_lock(&p.served());
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let ev2 = state_event(&p.sk, "sample", &[("refs/heads/main", &s2)], None, T2);
            p.m.enqueue(ev2.clone());
            until_retry_scheduled(&p, &ev2).await;
            let mut forged = state_event(
                &p.sk,
                "sample",
                &[("refs/heads/main", &"f".repeat(40))],
                None,
                T3,
            );
            forged.tags.push(vec!["x".into(), "tampered".into()]);
            assert!(
                !verify_event(&forged),
                "control: the forgery fails verification"
            );
            p.m.enqueue(forged);
            std::fs::remove_file(&lock).unwrap();
            until_main_is(&p, &s2, "the pending retry of S2 to publish").await;
        }

        /// Item 2 (Codex C2, security R3): when the retry timer fires while
        /// the slot holds an older state (here placed without a wake), the
        /// pending newer state is put back over it, not dropped.
        #[tokio::test]
        async fn a_pending_retry_is_not_lost_to_an_older_state_in_the_slot() {
            let p = published(101).await;
            let lock = plant_ref_lock(&p.served());
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let ev2 = state_event(&p.sk, "sample", &[("refs/heads/main", &s2)], None, T3);
            p.m.enqueue(ev2.clone());
            until_retry_scheduled(&p, &ev2).await;
            let older = state_event(
                &p.sk,
                "sample",
                &[("refs/heads/main", &p.approved)],
                None,
                T2,
            );
            p.m.inbox
                .lock()
                .unwrap()
                .insert(format!("{}/sample#{KIND_STATE}", p.owner), older);
            std::fs::remove_file(&lock).unwrap();
            until_main_is(&p, &s2, "the pending retry of S2 to publish").await;
        }

        /// Item 3 (Codex C3, security R4): a fetch that fails for a reason
        /// that can pass (here the upstream is briefly gone) is retried by
        /// the worker once it is back, with no new event.
        #[tokio::test]
        async fn a_transiently_failed_fetch_is_retried() {
            let p = published(102).await;
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let away = p.home().join("upstream-away");
            std::fs::rename(&p.up, &away).unwrap();
            let ev2 = state_event(&p.sk, "sample", &[("refs/heads/main", &s2)], None, T2);
            p.m.enqueue(ev2.clone());
            let failed = until_retry_scheduled(&p, &ev2).await;
            assert_eq!(
                failed.last_seen.as_ref().unwrap().action,
                SeenAction::FetchFailed,
                "control: {}",
                failed.last_seen.as_ref().unwrap().reason
            );
            std::fs::rename(&away, &p.up).unwrap();
            until_main_is(&p, &s2, "the retried fetch to publish S2").await;
        }

        /// Item 3: a materialise failure (the owner directory under `repos/`
        /// is a file) schedules a retry too.
        #[tokio::test]
        async fn a_failed_materialise_schedules_a_retry() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(103);
            let owner = pubhex(&sk);
            std::fs::create_dir_all(plugin.join("repos")).unwrap();
            std::fs::write(plugin.join("repos").join(&owner), b"in the way").unwrap();
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            let seen = r.last_seen.clone().unwrap();
            assert!(
                seen.reason.contains("could not create"),
                "control: {}",
                seen.reason
            );
            assert!(r.retry_at.is_some(), "a failed materialise was not retried");
        }

        /// A test clock that moves on by `step` ms at every reading.
        struct StepClock {
            at: std::sync::atomic::AtomicU64,
            step: u64,
        }

        impl MirrorClock for StepClock {
            fn now_ms(&self) -> u64 {
                self.at.fetch_add(self.step, Ordering::SeqCst)
            }
        }

        /// Item 4 (Codex C4): the retry floor counts from when the attempt
        /// failed, not from when it started. With a clock that advances at
        /// every reading, the attempt takes at least one step.
        #[tokio::test]
        async fn the_retry_floor_counts_from_the_failure() {
            let p = published(104).await;
            plant_ref_lock(&p.served());
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let step = 5_000;
            let m = Mirror::with_parts(
                quiet_cfg(&p.entry),
                MirrorStore::new(&p.plugin),
                Arc::new(GitCli::new(p.plugin.join("repos"))),
                Arc::new(StepClock {
                    at: std::sync::atomic::AtomicU64::new(SystemClock.now_ms()),
                    step,
                }),
                Arc::new(AllowAll),
            );
            let r = apply_state(&m, &p.entry, &p.sk, &[("refs/heads/main", &s2)], None, T2).await;
            assert_eq!(r.failures, 1, "control: {:?}", r.last_seen);
            let started = r.last_fetch_at.unwrap();
            let gap = r.retry_at.unwrap().saturating_sub(started);
            assert!(
                gap >= step + 2_000,
                "the retry is {gap} ms after the attempt started, not 2000 ms after the failure"
            );
        }

        /// Item 5 (Codex C5): two states at the same second are ordered by
        /// id for "acted on" as for "seen". After the higher-id sibling is
        /// applied, the lower-id one (the NIP-01 winner) is applied too.
        #[tokio::test]
        async fn a_lower_id_sibling_of_an_applied_state_is_applied() {
            let p = published(105).await;
            let a = commit_file(&p.up, p.home(), "a.txt", "a\n", "a");
            let b = commit_file(&p.up, p.home(), "b.txt", "b\n", "b");
            let ea = state_event(&p.sk, "sample", &[("refs/heads/main", &a)], None, T2);
            let eb = state_event(&p.sk, "sample", &[("refs/heads/main", &b)], None, T2);
            let ((hi, hi_sha), (lo, lo_sha)) = if ea.id > eb.id {
                ((ea, a), (eb, b))
            } else {
                ((eb, b), (ea, a))
            };
            let r = p.m.apply(&p.entry, &hi).await;
            assert_eq!(
                rev(&p.served(), p.home(), "refs/heads/main"),
                hi_sha,
                "control: {:?}",
                r.last_seen
            );
            let r = p.m.apply(&p.entry, &lo).await;
            assert_eq!(
                rev(&p.served(), p.home(), "refs/heads/main"),
                lo_sha,
                "the lower-id sibling was not applied: {:?}",
                r.last_seen
            );
            assert_eq!(r.last_event.map(|e| e.id), Some(lo.id));
        }

        fn fetched_cli(p: &Published) -> GitCli {
            GitCli::new(p.plugin.join("repos"))
        }

        fn main_to(p: &Published, sha: &str) -> RefUpdate {
            RefUpdate {
                git_ref: "refs/heads/main".into(),
                sha: sha.to_string(),
                expected: Some(p.approved.clone()),
            }
        }

        /// Item 6 (Codex C6, security R2): a push killed by the growth cap is
        /// terminal for the state. The measure seam reports a huge store at
        /// the first poll, so the kill does not depend on timing.
        #[tokio::test]
        async fn a_push_killed_by_the_growth_cap_is_terminal() {
            let p = published(106).await;
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let git = fetched_cli(&p);
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            fn huge(_: &Path) -> u64 {
                u64::MAX
            }
            let capped = GitCli {
                push_measure: Some(huge),
                ..git.clone()
            };
            let e = capped
                .publish(&p.owner, "sample", &[main_to(&p, &s2)], None)
                .await
                .expect_err("control: the capped push fails");
            assert!(e.reason.contains("size cap"), "control: {}", e.reason);
            assert!(!e.retryable, "a growth-cap kill was classed retryable");
            assert_eq!(rev(&p.served(), p.home(), "refs/heads/main"), p.approved);
        }

        /// Item 6: a served store that git cannot read (its `refs/` is gone)
        /// fails publication's store check terminally, not as a retry.
        #[tokio::test]
        async fn a_store_check_error_in_publish_is_terminal() {
            let p = published(107).await;
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let git = fetched_cli(&p);
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            let served = p.served();
            std::fs::remove_file(served.join(MARKER_FILE)).unwrap();
            std::fs::remove_dir_all(served.join("refs")).unwrap();
            let e = git
                .publish(&p.owner, "sample", &[main_to(&p, &s2)], None)
                .await
                .expect_err("control: publication into a broken store fails");
            assert!(
                !e.retryable,
                "a store check error was classed retryable: {}",
                e.reason
            );
        }

        /// A `MirrorGit` over [`GitCli`] that counts `prepare` calls and can
        /// make every publication time out.
        struct Spy {
            inner: GitCli,
            prepares: std::sync::atomic::AtomicU32,
            time_out: bool,
        }

        #[async_trait]
        impl MirrorGit for Spy {
            async fn exists(&self, owner: &str, name: &str) -> bool {
                self.inner.exists(owner, name).await
            }
            async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String> {
                self.inner.local_heads(owner, name).await
            }
            async fn materialise(&self, owner: &str, name: &str) -> Result<(), String> {
                self.inner.materialise(owner, name).await
            }
            async fn prepare(
                &self,
                owner: &str,
                name: &str,
                scan: bool,
            ) -> Result<Prepared, String> {
                self.prepares.fetch_add(1, Ordering::SeqCst);
                self.inner.prepare(owner, name, scan).await
            }
            async fn fetch(
                &self,
                owner: &str,
                name: &str,
                clone: &str,
                operator: bool,
                pin: Option<&ClonePin>,
            ) -> Result<(), String> {
                self.inner.fetch(owner, name, clone, operator, pin).await
            }
            async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool {
                self.inner.has_commit(owner, name, sha).await
            }
            async fn is_ancestor(&self, owner: &str, name: &str, a: &str, d: &str) -> bool {
                self.inner.is_ancestor(owner, name, a, d).await
            }
            async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String> {
                self.inner.read_trail(owner, name, sha).await
            }
            async fn publish(
                &self,
                owner: &str,
                name: &str,
                updates: &[RefUpdate],
                head: Option<&str>,
            ) -> Result<(), PublishError> {
                if self.time_out {
                    return Err(PublishError {
                        reason: "git timed out".into(),
                        retryable: true,
                        timed_out: true,
                    });
                }
                self.inner.publish(owner, name, updates, head).await
            }
        }

        fn spy_engine(
            plugin: &Path,
            entry: &FollowEntry,
            time_out: bool,
        ) -> (Arc<Mirror>, Arc<Spy>) {
            let spy = Arc::new(Spy {
                inner: GitCli::new(plugin.join("repos")),
                prepares: std::sync::atomic::AtomicU32::new(0),
                time_out,
            });
            let m = Arc::new(Mirror::with_parts(
                quiet_cfg(entry),
                MirrorStore::new(plugin),
                spy.clone(),
                Arc::new(SystemClock),
                Arc::new(AllowAll),
            ));
            (m, spy)
        }

        /// Item 6: publish timeouts of one state stop being retried after
        /// [`MAX_TIMEOUTS`] in a row.
        #[tokio::test]
        async fn repeated_timeouts_of_one_state_become_terminal() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(108);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let (m, _) = spy_engine(&plugin, &entry, true);
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            for i in 1..MAX_TIMEOUTS {
                let r = m.apply(&entry, &ev).await;
                assert!(
                    r.retry_at.is_some(),
                    "control: timeout {i} is retried: {:?}",
                    r.last_seen
                );
            }
            let r = m.apply(&entry, &ev).await;
            let seen = r.last_seen.clone().unwrap();
            assert!(
                seen.reason.contains("timed out"),
                "control: {}",
                seen.reason
            );
            assert_eq!(
                r.retry_at, None,
                "timeout {MAX_TIMEOUTS} of the same state was retried"
            );
        }

        /// Item 7 (security R1): an owner-pushed repository holding a commit
        /// a force push left behind is followed, marked and stays readable:
        /// its unreachable objects are the owner's own.
        #[tokio::test]
        async fn an_owner_repo_with_a_force_pushed_away_commit_is_followed_and_served() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let first = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(109);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            git_ok(&up, home, &["checkout", "--quiet", "--orphan", "rewrite"]);
            let second = commit_file(&up, home, "public.txt", APPROVED_BYTES, "rewritten");
            let s = served.to_str().unwrap();
            git_ok(
                &up,
                home,
                &["push", "--quiet", "--force", s, "rewrite:main"],
            );
            assert!(
                has_object(&served, &first),
                "control: the old commit is still in served"
            );
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &second)], None, T1).await;
            let seen = r.last_seen.clone().unwrap();
            assert!(!seen.reason.contains("awaits migration"), "{}", seen.reason);
            assert!(
                served.join(MARKER_FILE).is_file(),
                "not marked: {}",
                seen.reason
            );
            let forge = forge_at(&plugin);
            let raw = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{second}/public.txt"),
            )
            .await;
            assert_eq!(raw.status, 200, "{}", String::from_utf8_lossy(&raw.body));
        }

        /// A served store with a mirror record written before this release
        /// (no `isolated` field), unmarked and holding an object no branch or
        /// tag reaches: the shape the old shared layout may leave.
        fn legacy_record_store(
            plugin: &Path,
            home: &Path,
            seed: u8,
        ) -> (String, SigningKey, PathBuf, PathBuf, String) {
            let up = home.join(format!("up-{seed}"));
            std::fs::create_dir(&up).unwrap();
            git_ok(&up, home, &["init", "--quiet", "-b", "main"]);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(seed);
            let owner = pubhex(&sk);
            let served = owner_pushed(plugin, &owner, &up, home);
            let loose = home.join(format!("held-{seed}.txt"));
            std::fs::write(&loose, HELD_BYTES).unwrap();
            git_ok(
                &served,
                home,
                &["hash-object", "-w", loose.to_str().unwrap()],
            );
            let mut v = serde_json::to_value(MirrorRecord::new(&owner, "sample", None)).unwrap();
            v.as_object_mut().unwrap().remove("isolated");
            let dir = plugin.join("mirror").join(&owner);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("sample.json"), v.to_string()).unwrap();
            (owner, sk, served, up, approved)
        }

        /// Item 7: a legacy-style store (a pre-release record, unmarked,
        /// with an unreachable object) still waits for migration.
        #[tokio::test]
        async fn a_legacy_record_store_with_an_unreachable_object_awaits_migration() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let (owner, sk, served, up, approved) = legacy_record_store(&plugin, home, 110);
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            let seen = r.last_seen.clone().unwrap();
            assert!(seen.reason.contains("awaits migration"), "{}", seen.reason);
            assert!(!served.join(MARKER_FILE).exists(), "marked");
            let forge = forge_at(&plugin);
            let raw = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(raw.status, 503, "{}", String::from_utf8_lossy(&raw.body));
        }

        /// Item 7: the store is examined once. A replayed (older) state and
        /// a newer state after the verdict do not call `prepare` again.
        #[tokio::test]
        async fn the_store_is_examined_once_and_never_for_a_replay() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let (owner, sk, _, up, approved) = legacy_record_store(&plugin, home, 111);
            let entry = follow_sample(&owner, &up);
            let (m, spy) = spy_engine(&plugin, &entry, false);
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T2).await;
            assert!(
                r.last_seen.unwrap().reason.contains("awaits migration"),
                "control"
            );
            let after_first = spy.prepares.load(Ordering::SeqCst);
            assert_eq!(after_first, 1, "control: one examination");
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert!(r.last_seen.unwrap().reason.contains("replay"), "control");
            assert_eq!(
                spy.prepares.load(Ordering::SeqCst),
                1,
                "a replay examined the store"
            );
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T3).await;
            assert!(
                r.last_seen.unwrap().reason.contains("awaits migration"),
                "control"
            );
            assert_eq!(
                spy.prepares.load(Ordering::SeqCst),
                1,
                "the persisted verdict was not used"
            );
        }

        /// Item 8 (security R5): quarantine directories do not count towards
        /// the ceiling (a young one larger than the ceiling does not refuse
        /// publication), and the growth watcher still measures from the full
        /// size, so it does not kill the push either.
        #[tokio::test]
        async fn young_quarantines_do_not_count_towards_the_ceiling() {
            let p = published(112).await;
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let git = fetched_cli(&p);
            git.fetch(&p.owner, "sample", &p.url(), true, None)
                .await
                .unwrap();
            let q = p.served().join("objects").join("tmp_objdir-incoming-young");
            std::fs::create_dir_all(&q).unwrap();
            std::fs::File::create(q.join("big"))
                .unwrap()
                .set_len(MAX_SERVED_BYTES + 1)
                .unwrap();
            git.publish(&p.owner, "sample", &[main_to(&p, &s2)], None)
                .await
                .unwrap();
            assert_eq!(rev(&p.served(), p.home(), "refs/heads/main"), s2);
        }

        /// Item 3: a fetch past the size cap is not retried (the same fetch
        /// would grow the same way). Both cap paths report [`GREW_PAST_CAP`].
        #[tokio::test]
        async fn an_oversize_fetch_is_not_retried() {
            let p = published(113).await;
            let candidate = candidate_of(&p.plugin, &p.owner);
            assert!(candidate.is_dir(), "control: a candidate after state 1");
            std::fs::File::create(candidate.join("objects").join("bloat"))
                .unwrap()
                .set_len(MAX_REPO_BYTES + 1)
                .unwrap();
            let s2 = commit_file(&p.up, p.home(), "s2.txt", "s2\n", "s2");
            let r = apply_state(&p.m, &p.entry, &p.sk, &[("refs/heads/main", &s2)], None, T2).await;
            let seen = r.last_seen.clone().unwrap();
            assert_eq!(seen.reason, GREW_PAST_CAP, "control");
            assert_eq!(
                r.retry_at, None,
                "an oversize fetch was scheduled for retry"
            );
        }

        /// A pre-release-record store whose only extra object is a commit
        /// `reach` (run in served with that commit) makes reachable.
        async fn scan_with_extra_root(
            seed: u8,
            reach: impl Fn(&Path, &Path, &str),
        ) -> Result<Prepared, String> {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let (owner, _, served, _, _) = {
                let up = home.join(format!("up-{seed}"));
                std::fs::create_dir(&up).unwrap();
                git_ok(&up, home, &["init", "--quiet", "-b", "main"]);
                let approved =
                    commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
                let sk = key(seed);
                let owner = pubhex(&sk);
                let served = owner_pushed(&plugin, &owner, &up, home);
                (owner, sk, served, up, approved)
            };
            let tree = git_ok(&served, home, &["rev-parse", "refs/heads/main^{tree}"]);
            let stray = git_ok(
                &served,
                home,
                &[
                    "-c",
                    "user.name=Agent",
                    "-c",
                    "user.email=agent@example.org",
                    "commit-tree",
                    &tree,
                    "-m",
                    "held",
                ],
            );
            reach(&served, home, &stray);
            GitCli::new(plugin.join("repos"))
                .prepare(&owner, "sample", true)
                .await
        }

        /// Item 7: `FETCH_HEAD` (which the old shared layout's fetches into
        /// served could leave naming a held tip) is not a root of the scan.
        #[tokio::test]
        async fn fetch_head_is_not_a_root_of_the_scan() {
            let r = scan_with_extra_root(114, |served, _, stray| {
                std::fs::write(
                    served.join("FETCH_HEAD"),
                    format!("{stray}\t\tbranch 'side' of /elsewhere\n"),
                )
                .unwrap();
            })
            .await;
            assert_eq!(r, Ok(Prepared::AwaitsMigration));
        }

        /// Item 7: a ref outside branches and tags is not a root either.
        #[tokio::test]
        async fn a_notes_ref_is_not_a_root_of_the_scan() {
            let r = scan_with_extra_root(115, |served, home, stray| {
                git_ok(served, home, &["update-ref", "refs/notes/x", stray]);
            })
            .await;
            assert_eq!(r, Ok(Prepared::AwaitsMigration));
        }

        /// Control for the two above: with no extra root the commit is
        /// unreachable, and a store with nothing extra is marked.
        #[tokio::test]
        async fn the_scan_marks_a_store_with_nothing_unreachable() {
            let r = scan_with_extra_root(116, |served, home, stray| {
                git_ok(served, home, &["update-ref", "refs/heads/kept", stray]);
            })
            .await;
            assert_eq!(r, Ok(Prepared::Ready));
        }

        /// Item 6: the real push classification, as `run_in` reports.
        #[test]
        fn push_failures_are_classified() {
            let t = push_failure(GIT_TIMED_OUT.to_string());
            assert!(t.retryable && t.timed_out, "{t:?}");
            let g = push_failure(GREW_PAST_CAP.to_string());
            assert!(!g.retryable && !g.timed_out, "{g:?}");
            let l = push_failure("refs/heads/main stale info".to_string());
            assert!(l.retryable && !l.timed_out, "{l:?}");
        }

        // --- round 6 -----------------------------------------------------

        /// A `MirrorGit` whose prepare, fetch and publish can be scripted to
        /// fail; everything else is the real adapter.
        struct Scripted {
            inner: GitCli,
            prepare_err: std::sync::Mutex<Option<String>>,
            fetch_err: std::sync::Mutex<Option<String>>,
            publish_errs: std::sync::Mutex<std::collections::VecDeque<PublishError>>,
        }

        #[async_trait]
        impl MirrorGit for Scripted {
            async fn exists(&self, owner: &str, name: &str) -> bool {
                self.inner.exists(owner, name).await
            }
            async fn local_heads(&self, owner: &str, name: &str) -> BTreeMap<String, String> {
                self.inner.local_heads(owner, name).await
            }
            async fn materialise(&self, owner: &str, name: &str) -> Result<(), String> {
                self.inner.materialise(owner, name).await
            }
            async fn prepare(
                &self,
                owner: &str,
                name: &str,
                scan: bool,
            ) -> Result<Prepared, String> {
                if let Some(e) = self.prepare_err.lock().unwrap().clone() {
                    return Err(e);
                }
                self.inner.prepare(owner, name, scan).await
            }
            async fn fetch(
                &self,
                owner: &str,
                name: &str,
                clone: &str,
                operator: bool,
                pin: Option<&ClonePin>,
            ) -> Result<(), String> {
                if let Some(e) = self.fetch_err.lock().unwrap().clone() {
                    return Err(e);
                }
                self.inner.fetch(owner, name, clone, operator, pin).await
            }
            async fn has_commit(&self, owner: &str, name: &str, sha: &str) -> bool {
                self.inner.has_commit(owner, name, sha).await
            }
            async fn is_ancestor(&self, owner: &str, name: &str, a: &str, d: &str) -> bool {
                self.inner.is_ancestor(owner, name, a, d).await
            }
            async fn read_trail(&self, owner: &str, name: &str, sha: &str) -> Option<String> {
                self.inner.read_trail(owner, name, sha).await
            }
            async fn publish(
                &self,
                owner: &str,
                name: &str,
                updates: &[RefUpdate],
                head: Option<&str>,
            ) -> Result<(), PublishError> {
                if let Some(e) = self.publish_errs.lock().unwrap().pop_front() {
                    return Err(e);
                }
                self.inner.publish(owner, name, updates, head).await
            }
        }

        fn scripted_engine(
            plugin: &Path,
            entry: &FollowEntry,
            ssrf: Arc<dyn SsrfCheck>,
        ) -> (Arc<Mirror>, Arc<Scripted>) {
            let git = Arc::new(Scripted {
                inner: GitCli::new(plugin.join("repos")),
                prepare_err: std::sync::Mutex::new(None),
                fetch_err: std::sync::Mutex::new(None),
                publish_errs: std::sync::Mutex::new(std::collections::VecDeque::new()),
            });
            let m = Arc::new(Mirror::with_parts(
                quiet_cfg(entry),
                MirrorStore::new(plugin),
                git.clone(),
                Arc::new(SystemClock),
                ssrf,
            ));
            (m, git)
        }

        const CORRUPT_RECORD: &[u8] = b"{\"pubkey\": \"trunc";

        /// Gives a directory its permissions back on drop, so the tempdir
        /// can be removed whatever the test did.
        struct Restore(PathBuf);

        impl Drop for Restore {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }

        /// Round 6 item 1 (S2.2, Codex High 1): a record that exists but
        /// does not parse is not "no record". The store it sits beside is
        /// not marked (its unreachable object would otherwise be served by
        /// SHA), the file is left as it was, and nothing is retried.
        #[tokio::test]
        async fn an_unreadable_record_awaits_migration_and_is_left_in_place() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let (owner, sk, served, up, approved) = legacy_record_store(&plugin, home, 120);
            std::fs::write(record_file(&plugin, &owner), CORRUPT_RECORD).unwrap();
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let ann = sign(
                &sk,
                KIND_ANNOUNCE,
                tags(&[&["d", "sample"], &["clone", "https://h.example/x.git"]]),
                T1,
            );
            assert!(
                m.on_event(&ann).await.is_none(),
                "an announcement was recorded over an unreadable record"
            );
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T2).await;
            assert_eq!(
                std::fs::read(record_file(&plugin, &owner)).unwrap(),
                CORRUPT_RECORD,
                "the unreadable record was overwritten"
            );
            assert!(
                !served.join(MARKER_FILE).exists(),
                "a store beside an unreadable record was marked"
            );
            let seen = r.last_seen.clone().unwrap();
            assert!(seen.reason.contains("awaits migration"), "{}", seen.reason);
            assert_eq!(r.retry_at, None, "an unreadable record was retried");
            let forge = forge_at(&plugin);
            let raw = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(raw.status, 503, "{}", String::from_utf8_lossy(&raw.body));
        }

        /// Round 6 item 1: every reader treats an unreadable record as a
        /// mirror. The record API answers 503, not "not a mirror".
        #[tokio::test]
        async fn the_record_api_refuses_an_unreadable_record() {
            let tmp = tempfile::tempdir().unwrap();
            let plugin = tmp.path().join("plugin");
            let owner = pubhex(&key(121));
            let f = record_file(&plugin, &owner);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, CORRUPT_RECORD).unwrap();
            let forge = forge_at(&plugin);
            let r = get(&forge, format!("/forge/api/repos/{owner}/sample/mirror")).await;
            assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
        }

        /// Round 6 item 2 (S2.1): a config read that fails for any reason
        /// but "unset" is not read as "no hideRefs". The store is not
        /// marked.
        #[tokio::test]
        async fn a_failed_config_read_is_not_read_as_no_hidden_refs() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let owner = pubhex(&key(122));
            let served = owner_pushed(&plugin, &owner, &up, home);
            let git = GitCli {
                config_args: Some(&["config", "--local", "--no-such-option"]),
                ..GitCli::new(plugin.join("repos"))
            };
            let r = git.prepare(&owner, "sample", false).await;
            assert!(r.is_err(), "a failed config read let the store pass: {r:?}");
            assert!(!served.join(MARKER_FILE).exists(), "marked");
        }

        /// Round 6 item 2: `hideRefs` naming `refs/mirror`, with no
        /// `refs/mirror` ref left, is a legacy trace on its own, whatever the
        /// case of the key and under either key. A `hideRefs` of something
        /// else is not.
        #[tokio::test]
        async fn hide_refs_alone_is_a_legacy_trace() {
            for (i, (config_key, value, legacy)) in [
                ("uploadpack.hideRefs", "refs/mirror", true),
                ("Transfer.HIDEREFS", "refs/mirror/", true),
                ("uploadpack.hideRefs", "refs/pull", false),
            ]
            .into_iter()
            .enumerate()
            {
                let tmp = tempfile::tempdir().unwrap();
                let home = tmp.path();
                let plugin = home.join("plugin");
                let up = new_upstream(home);
                commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
                let owner = pubhex(&key(130 + u8::try_from(i).unwrap()));
                let served = owner_pushed(&plugin, &owner, &up, home);
                git_ok(&served, home, &["config", "--add", config_key, value]);
                let r = GitCli::new(plugin.join("repos"))
                    .prepare(&owner, "sample", false)
                    .await;
                let want = if legacy {
                    Prepared::AwaitsMigration
                } else {
                    Prepared::Ready
                };
                assert_eq!(r, Ok(want), "{config_key} = {value}");
            }
        }

        /// Round 6 item 3 (S4): fetch timeouts of one state stop being
        /// retried after [`MAX_TIMEOUTS`].
        #[tokio::test]
        async fn repeated_fetch_timeouts_of_one_state_become_terminal() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(123);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let (m, git) = scripted_engine(&plugin, &entry, Arc::new(AllowAll));
            *git.fetch_err.lock().unwrap() = Some(GIT_TIMED_OUT.to_string());
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            for i in 1..MAX_TIMEOUTS {
                let r = m.apply(&entry, &ev).await;
                assert!(
                    r.retry_at.is_some(),
                    "control: fetch timeout {i} is retried: {:?}",
                    r.last_seen
                );
            }
            let r = m.apply(&entry, &ev).await;
            assert!(
                r.last_seen.as_ref().unwrap().reason.contains("timed out"),
                "control: {:?}",
                r.last_seen
            );
            assert_eq!(r.retry_at, None, "fetch timeout {MAX_TIMEOUTS} was retried");
        }

        /// Round 6 item 4 (S5): the adapter's own clone URL refusal is
        /// terminal, like the engine's.
        #[tokio::test]
        async fn the_adapters_clone_url_refusal_is_terminal() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(124);
            let owner = pubhex(&sk);
            let entry = FollowEntry {
                clone: Some("ftp://h.example/x.git".into()),
                ..follow_sample(&owner, &up)
            };
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            let seen = r.last_seen.clone().unwrap();
            assert_eq!(seen.reason, CLONE_URL_REFUSED, "control");
            assert_eq!(r.retry_at, None, "a refused clone URL was retried");
        }

        /// An SSRF check that answers as the default one does for a host
        /// whose resolution failed, or for one it refuses.
        struct Answers(String);

        #[async_trait]
        impl SsrfCheck for Answers {
            async fn verify_host(&self, _host: &str) -> Result<Option<std::net::IpAddr>, String> {
                Err(self.0.clone())
            }
        }

        fn dns_failure() -> String {
            solid_pod_rs::security::ssrf::SsrfError::DnsFailure {
                host: "h.example".into(),
                source: std::io::Error::other("temporary failure in name resolution"),
            }
            .to_string()
        }

        fn policy_refusal() -> String {
            solid_pod_rs::security::ssrf::SsrfError::BlockedClass {
                host: "h.example".into(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                class: solid_pod_rs::security::ssrf::IpClass::Loopback,
            }
            .to_string()
        }

        /// Round 6 item 5 (Codex C3/R4): a failed DNS lookup inside the SSRF
        /// check is retried, within the timeout limit; an address the
        /// policy refuses is not.
        #[tokio::test]
        async fn a_dns_failure_is_retried_within_the_limit_and_a_refusal_is_not() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(125);
            let owner = pubhex(&sk);
            let entry = FollowEntry {
                clone: Some("https://h.example/x.git".into()),
                ..follow_sample(&owner, &up)
            };
            let (m, _) = scripted_engine(&plugin, &entry, Arc::new(Answers(dns_failure())));
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            for i in 1..MAX_TIMEOUTS {
                let r = m.apply(&entry, &ev).await;
                assert!(
                    r.retry_at.is_some(),
                    "DNS failure {i} was not retried: {:?}",
                    r.last_seen
                );
            }
            let r = m.apply(&entry, &ev).await;
            assert_eq!(r.retry_at, None, "DNS failure {MAX_TIMEOUTS} was retried");

            let plugin2 = home.join("plugin2");
            let (m2, _) = scripted_engine(&plugin2, &entry, Arc::new(Answers(policy_refusal())));
            let r = m2.apply(&entry, &ev).await;
            assert!(
                r.last_seen
                    .as_ref()
                    .unwrap()
                    .reason
                    .contains("clone host refused"),
                "control: {:?}",
                r.last_seen
            );
            assert_eq!(r.retry_at, None, "a policy refusal was retried");
        }

        /// The DNS classification against the real error text.
        #[test]
        fn resolution_failures_are_told_from_policy_refusals() {
            assert!(resolution_failed(&dns_failure()));
            assert!(resolution_failed(
                &solid_pod_rs::security::ssrf::SsrfError::NoAddresses {
                    host: "h.example".into()
                }
                .to_string()
            ));
            assert!(!resolution_failed(&policy_refusal()));
            assert!(!resolution_failed("URL has no host component: x"));
        }

        /// Round 6 item 6 (S6): a scan that fails is not a verdict. Nothing
        /// is persisted, a retry is scheduled, and once the scan can run its
        /// real finding is persisted.
        #[tokio::test]
        async fn a_failed_scan_is_retried_and_not_persisted() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let (owner, sk, served, up, approved) = legacy_record_store(&plugin, home, 126);
            let obj = served.join("objects").join(&approved[..2]);
            std::fs::set_permissions(&obj, std::fs::Permissions::from_mode(0o000)).unwrap();
            let _restore = Restore(obj.clone());
            if std::fs::read_dir(&obj).is_ok() {
                eprintln!("SKIP a_failed_scan_is_retried_and_not_persisted: running as root");
                return;
            }
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert!(
                !r.awaits_migration,
                "a failed scan became a verdict: {:?}",
                r.last_seen
            );
            assert!(
                !MirrorStore::new(&plugin)
                    .read(&owner, "sample")
                    .unwrap()
                    .awaits_migration,
                "a failed scan was persisted as a verdict"
            );
            assert!(r.retry_at.is_some(), "a failed scan was not retried");
            assert!(!served.join(MARKER_FILE).exists(), "marked");
            std::fs::set_permissions(&obj, std::fs::Permissions::from_mode(0o755)).unwrap();
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert!(r.awaits_migration, "control: {:?}", r.last_seen);
        }

        /// Round 6 item 6 (S6): an alternates check that cannot be made is
        /// not evidence of alternates. No first record is saved beside the
        /// unprepared store, and a retry is scheduled.
        #[tokio::test]
        async fn an_alternates_check_error_is_retried_and_not_persisted() {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(127);
            let owner = pubhex(&sk);
            let served = owner_pushed(&plugin, &owner, &up, home);
            let info = served.join("objects").join("info");
            std::fs::create_dir_all(&info).unwrap();
            std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o000)).unwrap();
            let _restore = Restore(info.clone());
            if std::fs::read_dir(&info).is_ok() {
                eprintln!(
                    "SKIP an_alternates_check_error_is_retried_and_not_persisted: running as root"
                );
                return;
            }
            let entry = follow_sample(&owner, &up);
            let m = engine(&plugin, quiet_cfg(&entry));
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert!(
                !record_file(&plugin, &owner).exists(),
                "a record was saved: {:?}",
                MirrorStore::new(&plugin).read(&owner, "sample")
            );
            assert!(r.retry_at.is_some(), "not retried: {:?}", r.last_seen);
            std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o755)).unwrap();
            let r = apply_state(&m, &entry, &sk, &[("refs/heads/main", &approved)], None, T1).await;
            assert!(
                served.join(MARKER_FILE).exists(),
                "control: {:?}",
                r.last_seen
            );
        }

        /// Round 6 item 7 (S7): a prepare error is retried; repeated
        /// prepare timeouts stop at [`MAX_TIMEOUTS`].
        #[tokio::test]
        async fn a_prepare_error_is_retried_and_its_timeouts_are_bounded() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(128);
            let owner = pubhex(&sk);
            owner_pushed(&plugin, &owner, &up, home);
            // A saved record carries the counts between applies; a first
            // record is not saved beside an unprepared store (see report).
            MirrorStore::new(&plugin)
                .save(&MirrorRecord::new(&owner, "sample", None))
                .unwrap();
            let entry = follow_sample(&owner, &up);
            let (m, git) = scripted_engine(&plugin, &entry, Arc::new(AllowAll));
            *git.prepare_err.lock().unwrap() = Some("fatal: unable to read config".into());
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            let r = m.apply(&entry, &ev).await;
            assert!(
                r.retry_at.is_some(),
                "a prepare error was not retried: {:?}",
                r.last_seen
            );
            *git.prepare_err.lock().unwrap() = Some(GIT_TIMED_OUT.to_string());
            for i in 1..MAX_TIMEOUTS {
                let r = m.apply(&entry, &ev).await;
                assert!(r.retry_at.is_some(), "prepare timeout {i} was not retried");
            }
            let r = m.apply(&entry, &ev).await;
            assert_eq!(
                r.retry_at, None,
                "prepare timeout {MAX_TIMEOUTS} was retried"
            );
        }

        /// Round 7 item 1: a record path that is a symlink, dangling or
        /// not, is a directory entry, so it is not "no record".
        #[cfg(unix)]
        #[tokio::test]
        async fn a_record_symlink_is_unreadable_not_missing() {
            let tmp = tempfile::tempdir().unwrap();
            let plugin = tmp.path().join("plugin");
            let owner = pubhex(&key(140));
            let f = record_file(&plugin, &owner);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(tmp.path().join("nowhere.json"), &f).unwrap();
            let store = MirrorStore::new(&plugin);
            assert!(
                matches!(store.load(&owner, "sample"), StoredRecord::Unreadable(_)),
                "a dangling record symlink loaded as {:?}",
                store.load(&owner, "sample")
            );
            let forge = forge_at(&plugin);
            let r = get(&forge, format!("/forge/api/repos/{owner}/sample/mirror")).await;
            assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
            let real = tmp.path().join("real.json");
            std::fs::write(
                &real,
                serde_json::to_vec(&MirrorRecord::new(&owner, "sample", None)).unwrap(),
            )
            .unwrap();
            std::fs::remove_file(&f).unwrap();
            std::os::unix::fs::symlink(&real, &f).unwrap();
            assert!(
                matches!(store.load(&owner, "sample"), StoredRecord::Unreadable(_)),
                "a record symlink to a valid file was followed"
            );
        }

        /// Round 7 item 1: the reader gate also counts a dangling record
        /// symlink as a record, so the unmarked store beside it stays shut.
        #[cfg(unix)]
        #[tokio::test]
        async fn a_dangling_record_symlink_keeps_the_gate_closed() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let owner = pubhex(&key(141));
            owner_pushed(&plugin, &owner, &up, home);
            let f = record_file(&plugin, &owner);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(home.join("nowhere.json"), &f).unwrap();
            let forge = forge_at(&plugin);
            let raw = get(
                &forge,
                format!("/forge/{owner}/sample/raw/{approved}/public.txt"),
            )
            .await;
            assert_eq!(raw.status, 503, "{}", String::from_utf8_lossy(&raw.body));
        }

        /// Round 7 item 2: a `symbolic-ref` that fails (here: not a
        /// repository) is an error, not a detached HEAD.
        #[tokio::test]
        async fn a_failed_head_check_is_an_error_not_evidence() {
            let tmp = tempfile::tempdir().unwrap();
            let not_a_repo = tmp.path().join("plain");
            std::fs::create_dir_all(&not_a_repo).unwrap();
            let git = GitCli::new(tmp.path().join("repos"));
            let r = git.holds_unreachable_objects(&not_a_repo).await;
            assert!(
                r.is_err(),
                "a failed HEAD check was taken as evidence: {r:?}"
            );
        }

        /// Round 7 item 2, control: a detached HEAD is still evidence.
        #[tokio::test]
        async fn a_detached_head_is_still_evidence() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let owner = pubhex(&key(142));
            let served = owner_pushed(&plugin, &owner, &up, home);
            git_ok(
                &served,
                home,
                &["update-ref", "--no-deref", "HEAD", &approved],
            );
            let git = GitCli::new(plugin.join("repos"));
            assert_eq!(git.holds_unreachable_objects(&served).await, Ok(true));
        }

        /// Round 7 item 3: once a state has reached [`MAX_TIMEOUTS`], a later
        /// failure of another retryable kind does not re-arm its retries.
        #[tokio::test]
        async fn a_state_that_gave_up_stays_given_up() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(143);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let (m, git) = scripted_engine(&plugin, &entry, Arc::new(AllowAll));
            {
                let mut q = git.publish_errs.lock().unwrap();
                for _ in 0..MAX_TIMEOUTS {
                    q.push_back(PublishError {
                        reason: GIT_TIMED_OUT.into(),
                        retryable: true,
                        timed_out: true,
                    });
                }
                q.push_back(PublishError::from(
                    "refs/heads/main: stale info".to_string(),
                ));
            }
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            let mut r = None;
            for _ in 0..MAX_TIMEOUTS {
                r = Some(m.apply(&entry, &ev).await);
            }
            assert_eq!(r.unwrap().retry_at, None, "control: the limit was reached");
            let r = m.apply(&entry, &ev).await;
            assert!(
                r.last_seen.as_ref().unwrap().reason.contains("stale info"),
                "control: {:?}",
                r.last_seen
            );
            assert_eq!(r.retry_at, None, "a state past the limit was re-armed");
        }

        /// The limit is per state: after one state gives up, a newer state
        /// starts its own count and is still retried, so three timeouts
        /// never stop a mirror for good.
        #[tokio::test]
        async fn a_newer_state_is_retried_after_an_older_one_gave_up() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(147);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let (m, git) = scripted_engine(&plugin, &entry, Arc::new(AllowAll));
            {
                let mut q = git.publish_errs.lock().unwrap();
                for _ in 0..=MAX_TIMEOUTS {
                    q.push_back(PublishError {
                        reason: GIT_TIMED_OUT.into(),
                        retryable: true,
                        timed_out: true,
                    });
                }
            }
            let s1 = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            let mut r = None;
            for _ in 0..MAX_TIMEOUTS {
                r = Some(m.apply(&entry, &s1).await);
            }
            assert_eq!(
                r.unwrap().retry_at,
                None,
                "control: the first state gave up"
            );
            let s2 = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T2);
            let r = m.apply(&entry, &s2).await;
            assert_eq!(r.timeouts, 1, "the newer state did not start its own count");
            assert!(
                r.retry_at.is_some(),
                "a newer state was not retried after an older one gave up"
            );
        }

        /// Round 6 item 8 (I5): another failure between timeouts of one
        /// state does not reset the count.
        #[tokio::test]
        async fn other_failures_between_timeouts_do_not_reset_the_count() {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let plugin = home.join("plugin");
            let up = new_upstream(home);
            let approved = commit_file(&up, home, "public.txt", APPROVED_BYTES, APPROVED_SUBJECT);
            let sk = key(129);
            let owner = pubhex(&sk);
            let entry = follow_sample(&owner, &up);
            let (m, git) = scripted_engine(&plugin, &entry, Arc::new(AllowAll));
            let timeout = || PublishError {
                reason: GIT_TIMED_OUT.into(),
                retryable: true,
                timed_out: true,
            };
            let lease = || PublishError::from("refs/heads/main: stale info".to_string());
            {
                let mut q = git.publish_errs.lock().unwrap();
                for _ in 1..MAX_TIMEOUTS {
                    q.push_back(timeout());
                    q.push_back(lease());
                }
                q.push_back(timeout());
            }
            let ev = state_event(&sk, "sample", &[("refs/heads/main", &approved)], None, T1);
            let mut last = None;
            for _ in 0..(2 * MAX_TIMEOUTS - 1) {
                last = Some(m.apply(&entry, &ev).await);
            }
            let r = last.unwrap();
            assert!(
                r.last_seen.as_ref().unwrap().reason.contains("timed out"),
                "control: {:?}",
                r.last_seen
            );
            assert_eq!(
                r.retry_at, None,
                "timeout {MAX_TIMEOUTS} of the state was retried after interleaved failures"
            );
        }
    }
}
