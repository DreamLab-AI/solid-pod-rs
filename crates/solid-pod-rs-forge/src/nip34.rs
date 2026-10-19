//! NIP-34 emission: the repository announcement (kind 30617), the repository
//! state (kind 30618), the forge-instance announce key and the routes and
//! hooks that publish them (feature `announce`).
//!
//! This is the emitting half of the JSS `forge` plugin's discovery layer
//! (`buildRepoEvent`, `buildStateEvent`, `signAnnounceEvent`, `anchorTags`,
//! `apiNostr`, `apiAnnounce`, `announceRepo`); the reading half is
//! [`crate::mirror`]. The relay client is [`crate::publish`].
//!
//! # What is built
//!
//! * **30617** carries, in order: `d` (`<owner>/<name>`), `name`,
//!   `description`, `web`, `clone`, `relays` (when relays are configured),
//!   `maintainers` (when the owner is itself a 64-hex nostr key) and, for an
//!   anchored repository, the anchor tags `r`, `anchor`, `chain`, `txo`,
//!   `commit` ([`crate::gitmark::anchor_tags`]). Its content is the
//!   description.
//! * **30618** carries `d`, one `refs/heads/<branch>` tag per local branch
//!   with its full object id (default branch first), `HEAD` as
//!   `ref: refs/heads/<default>`, then the same anchor tags. Its content is
//!   empty.
//!
//! Both are replaceable (NIP-33), keyed by the same `d`, and signed with the
//! forge-instance key: the forge states "this instance hosts these clone
//! URLs", not "the maintainer says so".
//!
//! # The announce key
//!
//! [`AnnounceSigner::load_or_create`] uses the configured
//! [`crate::ForgeConfig::announce_key`] when it is 32-byte hex, otherwise the
//! key persisted at `plugin_dir/announce-key` (mode `0600`, created with the
//! operating system's random number generator, stable across restarts). The
//! secret is never logged or serialised; [`AnnounceSigner`]'s `Debug` shows
//! the public key only.
//!
//! # Anchoring
//!
//! A repository is anchored when it carries a Blocktrails trail with an
//! on-chain mark. A **repo-held** trail (a committed `blocktrails.json`) is
//! read directly. A **forge-held** trail (stored by the forge itself) is
//! reached through the [`ForgeTrailSource`] hook, which takes precedence and
//! has three answers ([`TrailState`]): nothing (fall back to the repository),
//! a trail with nothing on-chain yet (no anchor tags, no fallback), or the
//! anchor facts.
//!
//! # Example
//!
//! ```
//! use solid_pod_rs_forge::nip34::{build_repo_event, AnnounceSigner, RepoFacts};
//!
//! let signer = AnnounceSigner::from_secret_hex(&"11".repeat(32)).unwrap();
//! let facts = RepoFacts {
//!     owner: "casey".into(),
//!     name: "demo".into(),
//!     description: "A demo".into(),
//!     base: "https://forge.example/forge/casey/demo".into(),
//!     relays: vec![],
//!     default_branch: "main".into(),
//!     heads: vec![],
//!     anchor: None,
//! };
//! let ev = build_repo_event(&signer, &facts, 1_760_000_000).unwrap();
//! assert_eq!(ev.kind, 30617);
//! assert_eq!(ev.content, "A demo");
//! assert!(ev.verify().is_ok());
//! ```

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use k256::schnorr::SigningKey;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use solid_pod_rs_nostr::{DefaultSsrfCheck, Event, SsrfCheck};

use crate::config::{AnnounceKey, ForgeConfig};
use crate::error::ForgeError;
use crate::gitmark::{anchor_tags, did_short, read_repo_trail, AnchorFacts, TRAIL_FILE};
use crate::ownership::valid_name_segment;
use crate::publish::{publish_event, valid_relay_url, RelayResult, RELAY_TIMEOUT};
use crate::repo::browse::{self, EntryKind};
use crate::request::{ForgeRequest, ForgeResponse};
use crate::{ForgeAgent, ForgeService};

/// NIP-34 repository announcement.
pub const KIND_REPO: u64 = 30617;
/// NIP-34 repository state.
pub const KIND_STATE: u64 = 30618;
/// Longest description carried in a 30617 (JSS `DESCRIPTION_CAP`), in
/// characters.
pub const DESCRIPTION_CAP: usize = 512;
/// Longest description derived from a README's first line, in characters.
pub const README_LINE_CAP: usize = 160;
/// Largest README the description derivation will read, in bytes.
pub const README_RENDER_CAP: u64 = 512 * 1024;
/// File name of the persisted announce key inside the plugin directory.
pub const ANNOUNCE_KEY_FILE: &str = "announce-key";
/// Largest `description` file read from a repository, in bytes.
const DESCRIPTION_FILE_CAP: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a NIP-01 event with a BIP-340 Schnorr key.
///
/// The id is the canonical NIP-01 hash ([`Event::canonical_id`]) and the
/// signature is a BIP-340 Schnorr signature over those 32 bytes with fresh
/// operating-system randomness as the auxiliary nonce input. It is the same
/// primitive [`crate::mirror::verify_event`] checks (`Event::verify`).
///
/// # Errors
///
/// [`ForgeError::Backend`] if the signing primitive refuses the message
/// (it does not for a well-formed 32-byte id).
///
/// # Examples
///
/// ```
/// use k256::schnorr::SigningKey;
/// use solid_pod_rs_forge::nip34::sign_event;
///
/// let sk = SigningKey::from_bytes(&[7u8; 32]).unwrap();
/// let ev = sign_event(&sk, 30617, vec![vec!["d".into(), "a/b".into()]], "hi", 42).unwrap();
/// assert_eq!(ev.pubkey, hex::encode(sk.verifying_key().to_bytes()));
/// assert!(ev.verify().is_ok());
/// ```
pub fn sign_event(
    sk: &SigningKey,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: &str,
    created_at: u64,
) -> Result<Event, ForgeError> {
    let mut ev = Event {
        id: String::new(),
        pubkey: hex::encode(sk.verifying_key().to_bytes()),
        created_at,
        kind,
        tags,
        content: content.to_string(),
        sig: String::new(),
    };
    ev.id = ev.canonical_id();
    let id = hex::decode(&ev.id).map_err(|e| ForgeError::Backend(format!("event id: {e}")))?;
    let mut aux = [0u8; 32];
    OsRng.fill_bytes(&mut aux);
    let sig = sk
        .sign_raw(&id, &aux)
        .map_err(|e| ForgeError::Backend(format!("schnorr sign: {e}")))?;
    ev.sig = hex::encode(sig.to_bytes());
    Ok(ev)
}

/// The forge-instance NIP-34 identity: a BIP-340 key that signs every event
/// the forge emits.
#[derive(Clone)]
pub struct AnnounceSigner {
    key: SigningKey,
    pubkey: String,
}

impl std::fmt::Debug for AnnounceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnounceSigner")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl AnnounceSigner {
    fn from_key(key: SigningKey) -> Self {
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        Self { key, pubkey }
    }

    /// Build a signer from a 32-byte secret key in hex (either case).
    /// `None` when it is not 64 hex characters or not a valid scalar.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::nip34::AnnounceSigner;
    ///
    /// assert!(AnnounceSigner::from_secret_hex(&"11".repeat(32)).is_some());
    /// assert!(AnnounceSigner::from_secret_hex("nope").is_none());
    /// assert!(AnnounceSigner::from_secret_hex(&"00".repeat(32)).is_none());
    /// ```
    #[must_use]
    pub fn from_secret_hex(secret_hex: &str) -> Option<Self> {
        let bytes = hex::decode(secret_hex.trim()).ok()?;
        SigningKey::from_bytes(&bytes).ok().map(Self::from_key)
    }

    /// A fresh key from the operating system's random number generator.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_key(SigningKey::random(&mut OsRng))
    }

    /// Resolve the forge's announce identity (JSS key initialisation).
    ///
    /// A `configured` key that is valid 32-byte hex wins. Otherwise
    /// `plugin_dir/announce-key` is read; when it is absent or not a valid
    /// key, a new random key is generated and written there with mode
    /// `0600` (set when the file is created, not afterwards). An existing
    /// key file with looser permissions is tightened to `0600`.
    ///
    /// # Errors
    ///
    /// Any I/O error reading or writing the key file.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::nip34::AnnounceSigner;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let first = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
    /// let again = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
    /// assert_eq!(first.pubkey_hex(), again.pubkey_hex(), "stable across restarts");
    /// ```
    pub fn load_or_create(
        plugin_dir: &Path,
        configured: Option<&AnnounceKey>,
    ) -> std::io::Result<Self> {
        if let Some(signer) = configured
            .and_then(AnnounceKey::valid_hex)
            .and_then(|h| Self::from_secret_hex(&h))
        {
            return Ok(signer);
        }
        let path = plugin_dir.join(ANNOUNCE_KEY_FILE);
        for _ in 0..3 {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let t = text.trim();
                    let lowercase_hex =
                        t.len() == 64 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                    if let Some(s) = lowercase_hex.then(|| Self::from_secret_hex(t)).flatten() {
                        tighten_permissions(&path);
                        return Ok(s);
                    }
                    std::fs::remove_file(&path)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let fresh = Self::generate();
            match write_new_key_file(&path, &hex::encode(fresh.key.to_bytes())) {
                Ok(()) => return Ok(fresh),
                // Another process created it first: read theirs.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other(
            "announce key file kept changing while it was being created",
        ))
    }

    /// The x-only public key, 64 lowercase hex characters.
    #[must_use]
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey
    }

    /// The public key as a NIP-19 `npub1...` string.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::nip34::AnnounceSigner;
    ///
    /// let s = AnnounceSigner::from_secret_hex(&"11".repeat(32)).unwrap();
    /// assert!(s.npub().starts_with("npub1"));
    /// ```
    #[must_use]
    pub fn npub(&self) -> String {
        let bytes = self.key.verifying_key().to_bytes();
        match bech32::Hrp::parse("npub") {
            Ok(hrp) => bech32::encode::<bech32::Bech32>(hrp, &bytes).unwrap_or_default(),
            Err(_) => String::new(),
        }
    }

    /// Sign `kind`, `tags` and `content` at `created_at` with this identity.
    ///
    /// # Errors
    ///
    /// See [`sign_event`].
    pub fn sign(
        &self,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: &str,
        created_at: u64,
    ) -> Result<Event, ForgeError> {
        sign_event(&self.key, kind, tags, content, created_at)
    }
}

/// Create `path` exclusively with mode `0600` and write `hex` and a newline.
fn write_new_key_file(path: &Path, hex: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(format!("{hex}\n").as_bytes())?;
    f.flush()
}

/// Remove group and other access from an existing key file.
fn tighten_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

// ---------------------------------------------------------------------------
// Pure builders
// ---------------------------------------------------------------------------

/// Everything the two events are built from. Gathering it needs git and the
/// trail; building from it is pure, so event ids are reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoFacts {
    /// Owner namespace (a pod username or a 64-hex nostr key).
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// The description (already derived; capped again at
    /// [`DESCRIPTION_CAP`] characters when the event is built).
    pub description: String,
    /// Public browse URL of the repository, `<origin><prefix>/<owner>/<name>`
    /// with no trailing slash. The `web`, `clone` and trail URLs derive from it.
    pub base: String,
    /// The configured relays, already filtered to valid `ws(s)` URLs.
    pub relays: Vec<String>,
    /// The default branch (what `HEAD` points at).
    pub default_branch: String,
    /// Every local branch as `(full refname, full object id)`, any order.
    pub heads: Vec<(String, String)>,
    /// The anchor facts when the repository is anchored.
    pub anchor: Option<AnchorFacts>,
}

fn cap_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The tags of the kind-30617 announcement, in JSS order.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::nip34::{repo_tags, RepoFacts};
///
/// let facts = RepoFacts {
///     owner: "casey".into(), name: "demo".into(), description: "d".into(),
///     base: "https://f.example/forge/casey/demo".into(), relays: vec!["wss://r".into()],
///     default_branch: "main".into(), heads: vec![], anchor: None,
/// };
/// let tags = repo_tags(&facts);
/// assert_eq!(tags[0], ["d", "casey/demo"]);
/// assert_eq!(tags[4], ["clone", "https://f.example/forge/casey/demo.git"]);
/// assert_eq!(tags[5], ["relays", "wss://r"]);
/// ```
#[must_use]
pub fn repo_tags(f: &RepoFacts) -> Vec<Vec<String>> {
    let description = cap_chars(&f.description, DESCRIPTION_CAP);
    let mut tags = vec![
        vec!["d".to_string(), format!("{}/{}", f.owner, f.name)],
        vec!["name".to_string(), f.name.clone()],
        vec!["description".to_string(), description],
        vec!["web".to_string(), f.base.clone()],
        vec!["clone".to_string(), format!("{}.git", f.base)],
    ];
    if !f.relays.is_empty() {
        let mut t = vec!["relays".to_string()];
        t.extend(f.relays.iter().cloned());
        tags.push(t);
    }
    if is_lower_hex64(&f.owner) {
        tags.push(vec!["maintainers".to_string(), f.owner.clone()]);
    }
    if let Some(a) = &f.anchor {
        tags.extend(anchor_tags(a));
    }
    tags
}

/// The tags of the kind-30618 state event, in JSS order: `d`, every branch
/// (default first, the rest in byte order), `HEAD`, then the anchor tags.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::nip34::{state_tags, RepoFacts};
///
/// let sha = "a".repeat(40);
/// let facts = RepoFacts {
///     owner: "casey".into(), name: "demo".into(), description: String::new(),
///     base: "https://f.example/forge/casey/demo".into(), relays: vec![],
///     default_branch: "main".into(),
///     heads: vec![("refs/heads/dev".into(), sha.clone()), ("refs/heads/main".into(), sha.clone())],
///     anchor: None,
/// };
/// let tags = state_tags(&facts);
/// assert_eq!(tags[1][0], "refs/heads/main");
/// assert_eq!(tags[2][0], "refs/heads/dev");
/// assert_eq!(tags[3], ["HEAD", "ref: refs/heads/main"]);
/// ```
#[must_use]
pub fn state_tags(f: &RepoFacts) -> Vec<Vec<String>> {
    let default_ref = format!("refs/heads/{}", f.default_branch);
    let mut heads = f.heads.clone();
    heads.sort_by(|a, b| match (a.0 == default_ref, b.0 == default_ref) {
        (true, _) => std::cmp::Ordering::Less,
        (_, true) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(&b.0),
    });
    let mut tags = vec![vec!["d".to_string(), format!("{}/{}", f.owner, f.name)]];
    for (refname, sha) in heads {
        tags.push(vec![refname, sha]);
    }
    tags.push(vec!["HEAD".to_string(), format!("ref: {default_ref}")]);
    if let Some(a) = &f.anchor {
        tags.extend(anchor_tags(a));
    }
    tags
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Build and sign the kind-30617 repository announcement (JSS
/// `buildRepoEvent`). The content is the (capped) description.
///
/// # Errors
///
/// See [`sign_event`].
pub fn build_repo_event(
    signer: &AnnounceSigner,
    facts: &RepoFacts,
    created_at: u64,
) -> Result<Event, ForgeError> {
    let content = cap_chars(&facts.description, DESCRIPTION_CAP);
    signer.sign(KIND_REPO, repo_tags(facts), &content, created_at)
}

/// Build and sign the kind-30618 repository state (JSS `buildStateEvent`).
/// The content is empty.
///
/// # Errors
///
/// See [`sign_event`].
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::nip34::{build_state_event, AnnounceSigner, RepoFacts};
///
/// let signer = AnnounceSigner::from_secret_hex(&"22".repeat(32)).unwrap();
/// let facts = RepoFacts {
///     owner: "casey".into(), name: "demo".into(), description: String::new(),
///     base: "https://f.example/forge/casey/demo".into(), relays: vec![],
///     default_branch: "main".into(), heads: vec![], anchor: None,
/// };
/// let ev = build_state_event(&signer, &facts, 1).unwrap();
/// assert_eq!(ev.kind, 30618);
/// assert_eq!(ev.content, "");
/// ```
pub fn build_state_event(
    signer: &AnnounceSigner,
    facts: &RepoFacts,
    created_at: u64,
) -> Result<Event, ForgeError> {
    signer.sign(KIND_STATE, state_tags(facts), "", created_at)
}

// ---------------------------------------------------------------------------
// Gathering
// ---------------------------------------------------------------------------

/// What a forge-held trail says about anchoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrailState {
    /// The forge holds no trail for this repository: fall back to a
    /// repo-held `blocktrails.json`.
    Absent,
    /// The forge holds a trail but nothing is on-chain yet: no anchor tags,
    /// and the repository is **not** consulted (JSS does not fall through).
    Unanchored,
    /// The forge holds a trail whose genesis mark is on-chain.
    Anchored(AnchorFacts),
}

/// The seam through which forge-held trail storage tells the announcer about
/// anchoring (the repo-held model needs no hook). Implemented by the
/// forge-held anchoring tier.
#[async_trait]
pub trait ForgeTrailSource: Send + Sync {
    /// The forge-held trail state of `owner/name`. `trail_url` is where the
    /// forge serves that repository's `blocktrails.json`; the implementation
    /// puts it in [`AnchorFacts::trail_url`].
    async fn trail_state(&self, owner: &str, name: &str, trail_url: &str) -> TrailState;
}

/// `true` for a README file name: `readme`, optionally `.md`, `.markdown` or
/// `.txt`, in any case.
fn is_readme(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "readme" | "readme.md" | "readme.markdown" | "readme.txt"
    )
}

/// The first non-blank line of a README with leading `#`s stripped, trimmed
/// and cut to [`README_LINE_CAP`] characters.
fn readme_summary(text: &str) -> Option<String> {
    let first = text.split('\n').find(|l| !l.trim().is_empty())?;
    let stripped = first
        .trim_start_matches('#')
        .trim_start_matches(char::is_whitespace);
    Some(cap_chars(stripped.trim(), README_LINE_CAP))
}

/// Derive the repository description (JSS `repoSummary`): the bare
/// repository's own `description` file unless it is git's placeholder
/// ("Unnamed repository..."), else the first line of a README at the root of
/// the default branch (under [`README_RENDER_CAP`], not binary), else empty.
pub async fn derive_description(git_dir: &Path, default_branch: &str) -> String {
    if let Some(d) = read_description_file(git_dir).await {
        return d;
    }
    if !browse::has_commits(git_dir).await {
        return String::new();
    }
    let Ok(entries) = browse::list_tree(git_dir, default_branch, "").await else {
        return String::new();
    };
    let readme = entries.iter().find(|e| {
        matches!(e.kind, EntryKind::File | EntryKind::Symlink)
            && is_readme(&e.name)
            && e.size.is_some_and(|s| s < README_RENDER_CAP)
    });
    let Some(readme) = readme else {
        return String::new();
    };
    let Ok(bytes) =
        browse::read_blob(git_dir, default_branch, &readme.name, README_RENDER_CAP).await
    else {
        return String::new();
    };
    if bytes.iter().take(8000).any(|b| *b == 0) {
        return String::new();
    }
    readme_summary(&String::from_utf8_lossy(&bytes)).unwrap_or_default()
}

async fn read_description_file(git_dir: &Path) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(git_dir.join("description"))
        .await
        .ok()?;
    let mut buf = Vec::new();
    file.take(DESCRIPTION_FILE_CAP)
        .read_to_end(&mut buf)
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&buf);
    let d = text.trim();
    (!d.is_empty() && !d.starts_with("Unnamed repository")).then(|| d.to_string())
}

/// Read a repository's state into [`RepoFacts`] (JSS `buildRepoEvent` and
/// `buildStateEvent` inputs): description, default branch, branches and the
/// anchor facts. `base` is the public browse URL
/// (`<origin><prefix>/<owner>/<name>`); `relays` must already be filtered
/// with [`valid_relay_url`]. `trails` is the forge-held trail hook.
///
/// # Errors
///
/// [`ForgeError::PathTraversal`] for an unsafe owner or name; a git failure
/// listing the branches of a repository that has some.
pub async fn gather_facts(
    git_dir: &Path,
    owner: &str,
    name: &str,
    base: &str,
    relays: &[String],
    trails: Option<&dyn ForgeTrailSource>,
) -> Result<RepoFacts, ForgeError> {
    if !valid_name_segment(owner) || !valid_name_segment(name) {
        return Err(ForgeError::PathTraversal(format!("{owner}/{name}")));
    }
    let default_branch = browse::default_branch(git_dir).await;
    let description = derive_description(git_dir, &default_branch).await;
    // An empty or unborn repository has no heads yet; the HEAD tag still
    // names the default branch.
    let heads = browse::list_heads_full(git_dir).await.unwrap_or_default();
    let trail_url = format!("{base}/{TRAIL_FILE}");
    let anchor = match trails {
        Some(source) => match source.trail_state(owner, name, &trail_url).await {
            TrailState::Anchored(facts) => Some(facts),
            TrailState::Unanchored => None,
            TrailState::Absent => repo_held_anchor(git_dir, &default_branch, &trail_url).await,
        },
        None => repo_held_anchor(git_dir, &default_branch, &trail_url).await,
    };
    Ok(RepoFacts {
        owner: owner.to_string(),
        name: name.to_string(),
        description,
        base: base.to_string(),
        relays: relays.to_vec(),
        default_branch,
        heads,
        anchor,
    })
}

async fn repo_held_anchor(git_dir: &Path, branch: &str, trail_url: &str) -> Option<AnchorFacts> {
    read_repo_trail(git_dir, branch)
        .await
        .and_then(|t| t.anchor_facts(trail_url))
}

// ---------------------------------------------------------------------------
// The service side
// ---------------------------------------------------------------------------

/// Announce state held by a [`ForgeService`]: the identity, the opted-in
/// relays and the injected policies.
#[derive(Clone)]
pub(crate) struct Announcer {
    pub(crate) signer: AnnounceSigner,
    pub(crate) relays: Vec<String>,
    pub(crate) ssrf: Arc<dyn SsrfCheck>,
    pub(crate) trails: Option<Arc<dyn ForgeTrailSource>>,
}

impl Announcer {
    /// Resolve the identity and filter the relays (JSS activation).
    pub(crate) fn new(cfg: &ForgeConfig, plugin_dir: &Path) -> Result<Self, ForgeError> {
        let signer = AnnounceSigner::load_or_create(plugin_dir, cfg.announce_key.as_ref())?;
        let relays: Vec<String> = cfg
            .announce_relays
            .iter()
            .filter(|r| valid_relay_url(r))
            .cloned()
            .collect();
        tracing::info!(
            "forge: nostr announce identity {} - {}",
            did_short(signer.pubkey_hex()),
            if relays.is_empty() {
                "emission DISABLED (set announce_relays to opt in)".to_string()
            } else {
                format!("NIP-34 emission to {} relay(s)", relays.len())
            }
        );
        Ok(Self {
            signer,
            relays,
            ssrf: Arc::new(DefaultSsrfCheck),
            trails: None,
        })
    }
}

/// The two events built for one repository.
#[derive(Debug, Clone)]
pub struct AnnounceEvents {
    /// The kind-30617 announcement.
    pub event: Event,
    /// The kind-30618 state.
    pub state: Event,
}

/// The result of [`ForgeService::announce_repo`].
#[derive(Debug, Clone)]
pub struct AnnounceOutcome {
    /// `false` when no relays are configured (nothing was built or sent).
    pub published: bool,
    /// The events, when `published`.
    pub events: Option<AnnounceEvents>,
    /// Per-relay outcome of the 30617.
    pub relays: Vec<RelayResult>,
    /// Per-relay outcome of the 30618.
    pub state_relays: Vec<RelayResult>,
}

fn event_view(e: &Event) -> Value {
    json!({ "id": e.id, "pubkey": e.pubkey, "kind": e.kind, "tags": e.tags })
}

fn relay_views(rs: &[RelayResult]) -> Value {
    serde_json::to_value(rs).unwrap_or(Value::Null)
}

fn tally(rs: &[RelayResult]) -> String {
    format!("{}/{}", rs.iter().filter(|r| r.ok).count(), rs.len())
}

fn repo_base(origin: &str, prefix: &str, owner: &str, name: &str) -> String {
    let origin = origin.strip_suffix('/').unwrap_or(origin);
    format!("{origin}{prefix}/{owner}/{name}")
}

impl ForgeService {
    /// Replace the SSRF policy applied to relay hosts before they are
    /// dialled. The default ([`DefaultSsrfCheck`]) refuses private,
    /// loopback and metadata address space.
    #[must_use]
    pub fn with_announce_ssrf(mut self, ssrf: Arc<dyn SsrfCheck>) -> Self {
        let mut a = (*self.announcer).clone();
        a.ssrf = ssrf;
        self.announcer = Arc::new(a);
        self
    }

    /// Install the forge-held trail source consulted when building anchor
    /// tags (see [`ForgeTrailSource`]).
    #[must_use]
    pub fn with_trail_source(mut self, source: Arc<dyn ForgeTrailSource>) -> Self {
        let mut a = (*self.announcer).clone();
        a.trails = Some(source);
        self.announcer = Arc::new(a);
        self
    }

    /// The forge-instance announce public key (64 lowercase hex).
    #[must_use]
    pub fn announce_pubkey(&self) -> &str {
        self.announcer.signer.pubkey_hex()
    }

    /// The opted-in relays that passed the `ws(s)` filter.
    #[must_use]
    pub fn announce_relays(&self) -> &[String] {
        &self.announcer.relays
    }

    /// Build and sign the 30617 and 30618 events for `owner/name` as they
    /// would be published now. `origin` is the public scheme and host
    /// (`https://forge.example`), used for the `web`, `clone` and trail URLs.
    ///
    /// # Errors
    ///
    /// [`ForgeError::NotFound`] for an unknown repository,
    /// [`ForgeError::PathTraversal`] for an unsafe name, or a git or signing
    /// failure.
    pub async fn build_announce_events(
        &self,
        owner: &str,
        name: &str,
        origin: &str,
    ) -> Result<AnnounceEvents, ForgeError> {
        let git_dir = self.resolve_repo(owner, name).await?;
        let base = repo_base(origin, &self.prefix(), owner, name);
        let a = &self.announcer;
        let facts =
            gather_facts(&git_dir, owner, name, &base, &a.relays, a.trails.as_deref()).await?;
        let now = crate::now_secs();
        Ok(AnnounceEvents {
            event: build_repo_event(&a.signer, &facts, now)?,
            state: build_state_event(&a.signer, &facts, now)?,
        })
    }

    /// Publish the repository's 30617 then its 30618 to every configured
    /// relay (JSS `announceRepo`). With no relays configured this builds and
    /// sends nothing and returns `published: false`.
    ///
    /// This is the hook other tiers call after the repository changes (a web
    /// edit, a recorded mark transaction).
    ///
    /// # Errors
    ///
    /// As [`Self::build_announce_events`]. Relay failures are not errors:
    /// they are in the per-relay results.
    pub async fn announce_repo(
        &self,
        owner: &str,
        name: &str,
        origin: &str,
    ) -> Result<AnnounceOutcome, ForgeError> {
        if self.announcer.relays.is_empty() {
            return Ok(AnnounceOutcome {
                published: false,
                events: None,
                relays: Vec::new(),
                state_relays: Vec::new(),
            });
        }
        let events = self.build_announce_events(owner, name, origin).await?;
        let a = &self.announcer;
        let relays = publish_event(&events.event, &a.relays, RELAY_TIMEOUT, a.ssrf.as_ref()).await;
        let state_relays =
            publish_event(&events.state, &a.relays, RELAY_TIMEOUT, a.ssrf.as_ref()).await;
        Ok(AnnounceOutcome {
            published: true,
            events: Some(events),
            relays,
            state_relays,
        })
    }

    /// Fire-and-forget [`Self::announce_repo`] on the Tokio runtime
    /// (JSS `announceRepoSafe`): the result is logged, an error never
    /// escapes and the caller is never delayed. A no-op without relays.
    pub fn announce_repo_in_background(&self, owner: &str, name: &str, origin: &str) {
        if self.announcer.relays.is_empty() {
            return;
        }
        let svc = self.clone();
        let (owner, name, origin) = (owner.to_string(), name.to_string(), origin.to_string());
        tokio::spawn(async move {
            match svc.announce_repo(&owner, &name, &origin).await {
                Ok(o) => {
                    if let Some(e) = &o.events {
                        tracing::info!(
                            "forge: announced {owner}/{name} (NIP-34 30617 {}... + 30618 state {}...) to {} relay(s)",
                            &e.event.id[..8],
                            &e.state.id[..8],
                            tally(&o.relays)
                        );
                    }
                }
                Err(e) => tracing::warn!("forge: announce {owner}/{name} failed: {e}"),
            }
        });
    }

    /// `GET api/repos/<o>/<n>/nostr`: the freshly built, signed events that
    /// would be published, with the announce identity and relays (JSS
    /// `apiNostr`). Public, like the rest of the read API.
    pub(crate) async fn h_api_nostr(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_known_repo(owner, repo).await?;
        if !matches!(req.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
            return Ok(ForgeResponse::error(405, "method not allowed"));
        }
        let origin = req.host_url.as_deref().unwrap_or("");
        let events = self.build_announce_events(owner, repo, origin).await?;
        let a = &self.announcer;
        Ok(ForgeResponse::json(
            200,
            &json!({
                "pubkey": a.signer.pubkey_hex(),
                "npub": a.signer.npub(),
                "relays": a.relays,
                "relaysConfigured": !a.relays.is_empty(),
                "event": events.event,
                "state": events.state,
                "events": [events.event, events.state],
            }),
        ))
    }

    /// `POST api/repos/<o>/<n>/announce` (owner only): build both events and
    /// publish them (JSS `apiAnnounce`). With no relays this is a clear
    /// no-op that still returns the events for inspection.
    pub(crate) async fn h_api_announce(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        self.resolve_known_repo(owner, repo).await?;
        if !req.method.eq_ignore_ascii_case("POST") {
            return Ok(ForgeResponse::error(405, "method not allowed"));
        }
        let Some(agent_owner) = agent.owner() else {
            return Ok(ForgeResponse::error(401, "authentication required")
                .with_header("www-authenticate", "Bearer realm=\"forge\""));
        };
        if agent_owner != owner {
            return Err(ForgeError::Forbidden(
                "only the repo owner may announce this repository".into(),
            ));
        }
        let origin = req.host_url.as_deref().unwrap_or("");
        let events = self.build_announce_events(owner, repo, origin).await?;
        let a = &self.announcer;
        if a.relays.is_empty() {
            return Ok(ForgeResponse::json(
                200,
                &json!({
                    "published": false,
                    "reason": "no relays configured; set announce_relays to publish (NIP-34 emission is opt-in)",
                    "event": event_view(&events.event),
                    "state": event_view(&events.state),
                    "relays": [],
                }),
            ));
        }
        let relays = publish_event(&events.event, &a.relays, RELAY_TIMEOUT, a.ssrf.as_ref()).await;
        let state_relays =
            publish_event(&events.state, &a.relays, RELAY_TIMEOUT, a.ssrf.as_ref()).await;
        tracing::info!(
            "forge: {owner}/{repo} announced on demand (30617 {}... + 30618 {}...) to {} relay(s)",
            &events.event.id[..8],
            &events.state.id[..8],
            tally(&relays)
        );
        Ok(ForgeResponse::json(
            200,
            &json!({
                "published": true,
                "event": event_view(&events.event),
                "state": event_view(&events.state),
                "relays": relay_views(&relays),
                "stateRelays": relay_views(&state_relays),
            }),
        ))
    }

    /// 404 (not 400) for an unsafe or unknown owner/name, as the JSS API
    /// answers an address it does not recognise.
    async fn resolve_known_repo(&self, owner: &str, repo: &str) -> Result<(), ForgeError> {
        match self.resolve_repo(owner, repo).await {
            Ok(_) => Ok(()),
            Err(ForgeError::PathTraversal(_)) => Err(ForgeError::NotFound("not found".into())),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> RepoFacts {
        RepoFacts {
            owner: "casey".into(),
            name: "demo".into(),
            description: "Demo".into(),
            base: "https://forge.example/forge/casey/demo".into(),
            relays: vec![],
            default_branch: "main".into(),
            heads: vec![("refs/heads/main".into(), "a".repeat(40))],
            anchor: None,
        }
    }

    fn anchor() -> AnchorFacts {
        AnchorFacts {
            chain: "tbtc4".into(),
            genesis_txid: "a".repeat(64),
            frontier_txid: "b".repeat(64),
            frontier_vout: 1,
            frontier_commit: "c".repeat(40),
            trail_url: "https://forge.example/forge/casey/demo/blocktrails.json".into(),
        }
    }

    fn val<'a>(tags: &'a [Vec<String>], k: &str) -> Vec<&'a str> {
        tags.iter()
            .find(|t| t[0] == k)
            .map(|t| t[1..].iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    // JSS forge/test.js "GET /nostr returns a valid signed kind-30617 with
    // the required tags (d/name/web/clone/description)".
    #[test]
    fn jss_test_kind_30617_required_tags_and_a_valid_signature() {
        let signer = AnnounceSigner::from_secret_hex(&"11".repeat(32)).unwrap();
        let ev = build_repo_event(&signer, &facts(), 1_760_000_000).unwrap();
        assert_eq!(ev.kind, 30617);
        assert_eq!(ev.pubkey, signer.pubkey_hex());
        assert_eq!(
            ev.id,
            ev.canonical_id(),
            "id = sha256 of the canonical serialisation"
        );
        assert!(ev.verify().is_ok(), "schnorr sig verifies against the id");
        assert_eq!(val(&ev.tags, "d"), ["casey/demo"]);
        assert_eq!(val(&ev.tags, "name"), ["demo"]);
        assert_eq!(
            val(&ev.tags, "web"),
            ["https://forge.example/forge/casey/demo"]
        );
        assert_eq!(
            val(&ev.tags, "clone"),
            ["https://forge.example/forge/casey/demo.git"]
        );
        assert_eq!(
            ev.content,
            val(&ev.tags, "description")[0],
            "content = description"
        );
        for absent in ["relays", "maintainers", "anchor", "r"] {
            assert!(
                !ev.tags.iter().any(|t| t[0] == absent),
                "{absent} must be absent for an unconfigured, unanchored WebID-owned repo"
            );
        }
    }

    // JSS "an anchored repo carries the blocktrails.json (r) and anchor
    // (chain, genesis-txid) tags" (and the 30618 twin).
    #[test]
    fn jss_test_anchored_repo_carries_r_anchor_chain_txo_commit_on_both_events() {
        let mut f = facts();
        f.anchor = Some(anchor());
        let signer = AnnounceSigner::generate();
        for ev in [
            build_repo_event(&signer, &f, 1).unwrap(),
            build_state_event(&signer, &f, 1).unwrap(),
        ] {
            assert_eq!(
                val(&ev.tags, "r"),
                ["https://forge.example/forge/casey/demo/blocktrails.json"]
            );
            assert_eq!(val(&ev.tags, "anchor"), ["tbtc4", &"a".repeat(64)]);
            assert_eq!(val(&ev.tags, "chain"), ["tbtc4"]);
            assert_eq!(
                val(&ev.tags, "txo"),
                [format!("txo:tbtc4:{}:1", "b".repeat(64))]
            );
            assert_eq!(val(&ev.tags, "commit"), ["c".repeat(40)]);
        }
    }

    // JSS "GET /nostr also returns a valid signed kind-30618 repo-state".
    #[test]
    fn jss_test_kind_30618_head_and_default_branch_ref_with_empty_content() {
        let signer = AnnounceSigner::generate();
        let st = build_state_event(&signer, &facts(), 5).unwrap();
        assert_eq!(st.kind, 30618);
        assert_eq!(st.pubkey, signer.pubkey_hex(), "same key as the 30617");
        assert!(st.verify().is_ok());
        assert_eq!(st.content, "");
        let announce = build_repo_event(&signer, &facts(), 5).unwrap();
        assert_eq!(
            val(&st.tags, "d"),
            val(&announce.tags, "d"),
            "30617 and 30618 share the d"
        );
        assert_eq!(val(&st.tags, "HEAD"), ["ref: refs/heads/main"]);
        assert_eq!(val(&st.tags, "refs/heads/main"), ["a".repeat(40)]);
        assert!(!st.tags.iter().any(|t| t[0] == "anchor" || t[0] == "r"));
    }

    // JSS "a nostr-owned repo names the owner pubkey in a maintainers tag".
    #[test]
    fn jss_test_nostr_owned_repo_names_the_owner_as_maintainer() {
        let pk = "ab".repeat(32);
        let mut f = facts();
        f.owner = pk.clone();
        f.relays = vec!["wss://relay.example".into()];
        let tags = repo_tags(&f);
        assert_eq!(val(&tags, "maintainers"), [pk.as_str()]);
        assert_eq!(val(&tags, "relays"), ["wss://relay.example"]);
        // maintainers comes after relays, before any anchor tag
        let pos = |k: &str| tags.iter().position(|t| t[0] == k).unwrap();
        assert!(pos("relays") < pos("maintainers"));
        // a name that merely looks like a pubkey does not qualify
        for not_hex in [&"AB".repeat(32), &"ab".repeat(31), &"zz".repeat(32)] {
            let mut g = facts();
            g.owner = not_hex.clone();
            assert!(!repo_tags(&g).iter().any(|t| t[0] == "maintainers"));
        }
    }

    #[test]
    fn state_heads_put_the_default_first_then_byte_order() {
        let sha = |c: char| c.to_string().repeat(40);
        let mut f = facts();
        f.default_branch = "trunk".into();
        f.heads = vec![
            ("refs/heads/b".into(), sha('1')),
            ("refs/heads/trunk".into(), sha('2')),
            ("refs/heads/a".into(), sha('3')),
        ];
        let names: Vec<_> = state_tags(&f).iter().map(|t| t[0].clone()).collect();
        assert_eq!(
            names,
            [
                "d",
                "refs/heads/trunk",
                "refs/heads/a",
                "refs/heads/b",
                "HEAD"
            ]
        );
        f.heads.clear();
        let tags = state_tags(&f);
        assert_eq!(tags.len(), 2, "an empty repo has the d and HEAD tags only");
        assert_eq!(tags[1], ["HEAD", "ref: refs/heads/trunk"]);
    }

    #[test]
    fn description_is_capped_in_tag_and_content() {
        let mut f = facts();
        f.description = "x".repeat(600);
        let signer = AnnounceSigner::generate();
        let ev = build_repo_event(&signer, &f, 1).unwrap();
        assert_eq!(ev.content.chars().count(), DESCRIPTION_CAP);
        assert_eq!(val(&ev.tags, "description")[0], ev.content);
    }

    #[test]
    fn readme_summary_strips_headings_and_caps() {
        assert_eq!(
            readme_summary("\n\n## Title here  \nbody").as_deref(),
            Some("Title here")
        );
        assert_eq!(readme_summary("#\tTabbed").as_deref(), Some("Tabbed"));
        assert_eq!(readme_summary("plain").as_deref(), Some("plain"));
        assert_eq!(readme_summary(" \n\t\n"), None);
        let long = format!("# {}", "y".repeat(300));
        assert_eq!(
            readme_summary(&long).unwrap().chars().count(),
            README_LINE_CAP
        );
        assert!(is_readme("README") && is_readme("Readme.MD") && is_readme("readme.txt"));
        assert!(!is_readme("README.rst") && !is_readme("readme.md.bak") && !is_readme("notes"));
    }

    #[test]
    fn sign_roundtrip_verifies_and_a_tampered_event_does_not() {
        let sk = SigningKey::from_bytes(&[9u8; 32]).unwrap();
        let ev = sign_event(
            &sk,
            30618,
            vec![vec!["d".into(), "x/y".into()]],
            "",
            1_760_000_000,
        )
        .unwrap();
        assert!(ev.verify().is_ok());
        let mut bad = ev.clone();
        bad.tags.push(vec!["extra".into()]);
        assert!(bad.verify().is_err());
        let mut bad_sig = ev;
        bad_sig.sig = "0".repeat(128);
        assert!(bad_sig.verify().is_err());
    }

    #[cfg(feature = "mirror")]
    #[test]
    fn signed_events_pass_the_mirror_reader_verifier() {
        let sk = SigningKey::from_bytes(&[3u8; 32]).unwrap();
        let ev = sign_event(
            &sk,
            KIND_STATE,
            vec![
                vec!["d".into(), "x".into()],
                vec!["refs/heads/main".into(), "a".repeat(40)],
            ],
            "",
            1_760_000_000,
        )
        .unwrap();
        assert!(crate::mirror::verify_event(&ev));
    }

    #[test]
    fn signatures_are_randomised_but_ids_are_deterministic() {
        let sk = SigningKey::from_bytes(&[5u8; 32]).unwrap();
        let a = sign_event(&sk, 1, vec![], "same", 7).unwrap();
        let b = sign_event(&sk, 1, vec![], "same", 7).unwrap();
        assert_eq!(a.id, b.id);
        assert_ne!(a.sig, b.sig, "BIP-340 aux randomness differs per signature");
        assert!(a.verify().is_ok() && b.verify().is_ok());
    }

    // JSS "the announce key is generated once and persisted 0600".
    #[test]
    fn jss_test_announce_key_is_generated_once_and_persisted_0600() {
        let dir = tempfile::tempdir().unwrap();
        let first = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
        let path = dir.path().join(ANNOUNCE_KEY_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), 64);
        assert!(text
            .trim()
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert!(text.ends_with('\n'));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // the persisted secret derives the announced pubkey
        let derived = AnnounceSigner::from_secret_hex(text.trim()).unwrap();
        assert_eq!(derived.pubkey_hex(), first.pubkey_hex());
        let again = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
        assert_eq!(again.pubkey_hex(), first.pubkey_hex(), "stable identity");
    }

    #[test]
    fn configured_key_wins_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AnnounceKey::new("11".repeat(32).to_ascii_uppercase());
        let s = AnnounceSigner::load_or_create(dir.path(), Some(&cfg)).unwrap();
        assert_eq!(
            s.pubkey_hex(),
            AnnounceSigner::from_secret_hex(&"11".repeat(32))
                .unwrap()
                .pubkey_hex()
        );
        assert!(!dir.path().join(ANNOUNCE_KEY_FILE).exists());
    }

    #[test]
    fn a_malformed_configured_or_persisted_key_falls_back_silently() {
        let dir = tempfile::tempdir().unwrap();
        let bad = AnnounceKey::new("not-hex");
        let s = AnnounceSigner::load_or_create(dir.path(), Some(&bad)).unwrap();
        assert!(dir.path().join(ANNOUNCE_KEY_FILE).exists());
        // corrupt the file: it is replaced, not trusted
        std::fs::write(dir.path().join(ANNOUNCE_KEY_FILE), "garbage\n").unwrap();
        let s2 = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
        assert_ne!(s.pubkey_hex(), s2.pubkey_hex());
        let text = std::fs::read_to_string(dir.path().join(ANNOUNCE_KEY_FILE)).unwrap();
        assert_eq!(
            AnnounceSigner::from_secret_hex(text.trim())
                .unwrap()
                .pubkey_hex(),
            s2.pubkey_hex()
        );
        // an all-zero scalar is not a key
        std::fs::write(
            dir.path().join(ANNOUNCE_KEY_FILE),
            format!("{}\n", "0".repeat(64)),
        )
        .unwrap();
        let s3 = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
        assert_ne!(s3.pubkey_hex(), s2.pubkey_hex());
    }

    #[cfg(unix)]
    #[test]
    fn a_loose_existing_key_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANNOUNCE_KEY_FILE);
        std::fs::write(&path, format!("{}\n", "11".repeat(32))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = AnnounceSigner::load_or_create(dir.path(), None).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn the_secret_is_never_printed() {
        let secret = "5a".repeat(32);
        let s = AnnounceSigner::from_secret_hex(&secret).unwrap();
        let shown = format!("{s:?}");
        assert!(!shown.contains(&secret) && shown.contains(s.pubkey_hex()));
        let cfg = ForgeConfig {
            announce_key: Some(AnnounceKey::new(secret.clone())),
            ..Default::default()
        };
        assert!(!format!("{cfg:?}").contains(&secret));
    }

    #[test]
    fn npub_is_bech32_of_the_pubkey() {
        let s = AnnounceSigner::from_secret_hex(&"11".repeat(32)).unwrap();
        let (hrp, data) = bech32::decode(&s.npub()).unwrap();
        assert_eq!(hrp.as_str(), "npub");
        assert_eq!(hex::encode(data), s.pubkey_hex());
    }

    #[test]
    fn repo_base_trims_one_trailing_slash_and_allows_a_missing_origin() {
        assert_eq!(
            repo_base("https://f.example/", "/forge", "a", "b"),
            "https://f.example/forge/a/b"
        );
        assert_eq!(repo_base("", "/forge", "a", "b"), "/forge/a/b");
        assert_eq!(
            repo_base("https://f.example", "", "a", "b"),
            "https://f.example/a/b"
        );
    }
}
