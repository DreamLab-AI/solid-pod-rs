//! The forge-held Blocktrails trail: store, key custody, per-repo lock and the
//! tip recorder (feature `anchoring`).
//!
//! This is the Rust counterpart of the JSS `forge` plugin's tier 3.5:
//! `apiMarksEnable`, `apiMarkTxo`, `recordTip`, `appendMark`,
//! `loadTrail`/`saveTrail`, `withMarkLock`, the `sparseMarks` branch of
//! `recordTip`, `blocktrailsResp` and `anchorTags`, over the pure maths of
//! `lib/blocktrails.js` (`markStateHash`, `trailProgram`, `trailAddress`).
//! JSS is cited by function name only; the code is original, and the BIP-341
//! `TapTweak` walk is `solid_pod_rs::mrc20`'s ([`bt_trail_outputs`]).
//!
//! ## The model
//!
//! A repository's owner may *enable* anchoring. The forge mints a fresh
//! secp256k1 key, keeps it, and derives a chain of taproot addresses from it:
//! one **mark** per default-branch tip, each chained over the one before. A
//! mark's state is the JSON record `{"commit","repo","branch"}`; its hash is
//! the SHA-256 of that text, so the addresses match JSS byte for byte (the
//! differential vectors in this module's tests were produced by running
//! `forge/lib/blocktrails.js`).
//!
//! **The forge never broadcasts, spends or verifies.** It derives addresses
//! and *records* the `txid:vout:amount` a funded client posts back
//! (`POST .../marks/<i>/txo`). Independent verification is the hosted
//! verifier's job, client-side. A mark is `pending` until a transaction is
//! recorded for it, and transactions are recorded strictly in order, because a
//! trail is a linear spend chain.
//!
//! ## Custody
//!
//! The trail key sits in the trail file, `<plugin_dir>/marks/<owner>/<repo>.json`,
//! created `0600` through an atomic rename, with a freshly generated key from
//! the operating system's RNG. It is testnet-grade custody by design (the
//! chain guard in [`crate::ForgeConfig::validate_chain`] refuses mainnet unless
//! the operator opts in). The key never appears in a `Debug` rendering
//! ([`TrailKey`]), an API response, a page or a log line.
//!
//! The on-disk shape is JSS's (`v`, `chain`, `privkey`, `pubkeyBase`,
//! `createdAt`, `marks[]`), so a plugin directory is interchangeable.
//!
//! ## Hooks
//!
//! [`ForgeService::record_tip`] is the one advance beat. The git push path
//! calls it after a successful `git-receive-pack`; a later merge or web-edit
//! path calls it after writing to the default branch. [`ForgeTrailSource`] lets
//! the NIP-34 builder ask for the forge-held anchor facts.
//!
//! ## Example
//!
//! ```
//! use solid_pod_rs_forge::trail::{MarkState, mark_state_hash};
//!
//! let state = MarkState {
//!     commit: "cf97baba489e88c1ffbe6758c0fe8c18ff83d17d".into(),
//!     repo: "casey/demo".into(),
//!     branch: "main".into(),
//! };
//! // sha256(JSON.stringify({commit, repo, branch})), the JSS `markStateHash`
//! assert_eq!(
//!     mark_state_hash(&state),
//!     "98684a6cfc3fedfd405a20b66a96305b2834a86208fca16164fae7cdd395dfcf"
//! );
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use bech32::Hrp;
use k256::elliptic_curve::sec1::ToSec1Point;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solid_pod_rs::mrc20::{bt_trail_outputs, sha256_hex};

use crate::config::{chain_hrp, ForgeConfig};
use crate::error::ForgeError;
use crate::gitmark::AnchorFacts;
use crate::ownership::valid_name_segment;
use crate::repo::browse;
use crate::request::{parse_form, ForgeRequest, ForgeResponse};
use crate::{now_secs, ForgeAgent, ForgeService};

/// Most marks one trail may hold (JSS `MARKS_CAP`). Each default-branch advance
/// stacks one, so the cap bounds the file and the cost of a derivation.
pub const MARKS_CAP: usize = 500;

/// Largest amount a recorded transaction may claim, in satoshis: 21 million BTC
/// (JSS `SATS_CAP`).
pub const SATS_CAP: u64 = 2_100_000_000_000_000;

/// Largest output index a recorded transaction may claim (`0x7fffffff`).
pub const MAX_VOUT: u64 = 0x7fff_ffff;

/// A secret key as lowercase hex, which can never be printed by accident.
///
/// It serialises transparently (the trail file needs it) but its [`Debug`]
/// output is a fixed redaction, and the type offers no `Display`. Public API
/// views are built from [`PublicMark`] and never carry it.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::trail::TrailKey;
///
/// let key: TrailKey = serde_json::from_str("\"11\"").unwrap();
/// assert_eq!(format!("{key:?}"), "TrailKey(<redacted>)");
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrailKey(String);

impl std::fmt::Debug for TrailKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrailKey(<redacted>)")
    }
}

/// The state a mark commits to: the default-branch tip of one repository.
///
/// Field order is the JSS `JSON.stringify({ commit, repo, branch })` order and
/// is load-bearing: the state hash is the SHA-256 of [`MarkState::json`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkState {
    /// The commit id (40 or 64 lowercase hex).
    pub commit: String,
    /// `<owner>/<repo>`.
    pub repo: String,
    /// The branch the commit is the tip of.
    pub branch: String,
}

impl MarkState {
    /// The compact JSON text that is hashed, in `commit, repo, branch` order.
    #[must_use]
    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// The canonical mark state hash: SHA-256, as lowercase hex, of the state's
/// JSON text (JSS `markStateHash`).
#[must_use]
pub fn mark_state_hash(state: &MarkState) -> String {
    sha256_hex(&state.json())
}

/// Whether a mark has a recorded transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MarkStatus {
    /// Derived, with no transaction recorded.
    Pending,
    /// A funded client has recorded where the mark landed on-chain.
    Marked,
}

/// One mark of a forge-held trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mark {
    /// Position in the trail, from 0.
    pub index: usize,
    /// The state this mark commits to.
    pub state: MarkState,
    /// SHA-256 hex of the state's JSON.
    pub state_hash: String,
    /// The 32-byte witness program (x-only output key) as hex.
    pub program: String,
    /// The P2TR (bech32m) address of the program on the trail's chain.
    pub address: String,
    /// Pending until a transaction is recorded.
    pub status: MarkStatus,
    /// Unix seconds at which the mark was derived (or last re-targeted).
    pub at: u64,
    /// Recorded transaction id (marked marks only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Recorded output index (marked marks only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vout: Option<u32>,
    /// Recorded amount in satoshis (marked marks only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Unix seconds at which the transaction was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked_at: Option<u64>,
}

/// A mark as served over every API surface: everything but the key (which is
/// on the [`Trail`], not the mark) and nothing that was never recorded.
pub type PublicMark = Mark;

/// A forge-held trail, as persisted.
///
/// [`Debug`] never shows the key (see [`TrailKey`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trail {
    /// File format version (1).
    pub v: u32,
    /// The chain token the trail lives on, lowercase.
    pub chain: String,
    /// The forge-held secret key (hex). Never served.
    pub privkey: TrailKey,
    /// The base public key, a compressed point (`02`/`03` plus x).
    pub pubkey_base: String,
    /// Unix seconds of enabling.
    pub created_at: u64,
    /// The marks, oldest first.
    pub marks: Vec<Mark>,
}

impl Trail {
    /// The marked prefix of the trail. Transactions are recorded in order, so
    /// the marked marks are always a prefix; this stops at the first pending.
    #[must_use]
    pub fn marked_prefix(&self) -> &[Mark] {
        let n = self
            .marks
            .iter()
            .take_while(|m| m.status == MarkStatus::Marked)
            .count();
        &self.marks[..n]
    }

    /// The `txo:` URI of a marked mark, in the shape the `git mark` verifier
    /// parses (JSS `txoUriOf`). `None` for a pending mark.
    #[must_use]
    pub fn txo_uri(&self, m: &Mark) -> Option<String> {
        Some(format!(
            "txo:{}:{}:{}?amount={}&commit={}&pubkey={}",
            self.chain,
            m.txid.as_deref()?,
            m.vout?,
            m.amount?,
            m.state.commit,
            m.program
        ))
    }

    /// The verifier-compatible trail document (JSS `blocktrailsResp`): `states`
    /// and `txo` hold only the marked prefix (the verifier walks the spend
    /// chain, and a pending mark has nothing on-chain), while the full list,
    /// pending marks included, rides in the additive `marks` field. No key.
    #[must_use]
    pub fn document(&self) -> Value {
        let marked = self.marked_prefix();
        let mut doc = serde_json::Map::new();
        if let Some(uri) = marked.first().and_then(|m| self.txo_uri(m)) {
            doc.insert("@id".into(), json!(uri));
        }
        doc.insert("@type".into(), json!("Blocktrail"));
        doc.insert("version".into(), json!("0.0.3"));
        doc.insert("profile".into(), json!("gitmark"));
        doc.insert("pubkeyBase".into(), json!(self.pubkey_base));
        doc.insert("chain".into(), json!(self.chain));
        doc.insert(
            "derivation".into(),
            json!("blocktrails-v0.2 chained BIP-341 TapTweak"),
        );
        doc.insert(
            "stateHash".into(),
            json!("sha256(JSON.stringify({commit,repo,branch}))"),
        );
        doc.insert(
            "states".into(),
            json!(marked.iter().map(|m| &m.state.commit).collect::<Vec<_>>()),
        );
        doc.insert(
            "txo".into(),
            json!(marked
                .iter()
                .filter_map(|m| self.txo_uri(m))
                .collect::<Vec<_>>()),
        );
        doc.insert(
            "marks".into(),
            serde_json::to_value(&self.marks).unwrap_or(Value::Null),
        );
        Value::Object(doc)
    }

    /// The anchor facts for the NIP-34 events (JSS `anchorTags`, forge-held
    /// branch): present only once mark 0 is on-chain, naming the genesis txid
    /// and the latest marked mark. `trail_url` is where the document is served.
    #[must_use]
    pub fn anchor_facts(&self, trail_url: &str) -> Option<AnchorFacts> {
        let marked = self.marked_prefix();
        let genesis = marked.first()?;
        let frontier = marked.last()?;
        Some(AnchorFacts {
            chain: self.chain.clone(),
            genesis_txid: genesis.txid.clone()?,
            frontier_txid: frontier.txid.clone()?,
            frontier_vout: frontier.vout?,
            frontier_commit: frontier.state.commit.clone(),
            trail_url: trail_url.to_string(),
        })
    }
}

/// What [`ForgeService::record_tip`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipOutcome {
    /// The repository has no forge-held trail.
    NotEnabled,
    /// The branch is not the repository's default branch.
    NotDefaultBranch,
    /// The tip is already the last mark's state.
    Unchanged,
    /// A new pending mark was derived at this index.
    Appended(usize),
    /// Sparse marking re-targeted the trailing pending mark at this index.
    Retargeted(usize),
    /// The trail is at [`MARKS_CAP`] and the tip was not recorded.
    CapReached,
}

/// The anchor facts of a repository's forge-held trail, for the NIP-34
/// builder (JSS `anchorTags`).
///
/// The builder asks [`has_forge_trail`](Self::has_forge_trail) first: JSS
/// emits **no** anchor tags for a repository whose forge-held trail has
/// nothing on-chain yet, and does not fall back to a repo-held trail then.
pub trait ForgeTrailSource: Send + Sync {
    /// Whether `owner/repo` has a forge-held trail at all (enabled).
    fn has_forge_trail(&self, owner: &str, repo: &str) -> bool;

    /// The anchor facts once mark 0 is recorded on-chain, else `None`.
    /// `trail_url` is the absolute URL of the repository's
    /// `blocktrails.json`.
    fn anchor_facts(&self, owner: &str, repo: &str, trail_url: &str) -> Option<AnchorFacts>;
}

/// The trail store: files, chain policy and the per-repo mark lock.
///
/// One per [`ForgeService`]. Cheap to share behind an [`Arc`].
pub struct TrailStore {
    dir: PathBuf,
    chain: String,
    allow_mainnet: bool,
    sparse: bool,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for TrailStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrailStore")
            .field("dir", &self.dir)
            .field("chain", &self.chain)
            .field("sparse", &self.sparse)
            .finish()
    }
}

fn anchoring_err(msg: impl Into<String>) -> ForgeError {
    ForgeError::Backend(msg.into())
}

/// The bech32m address of a witness-v1 `program` under `hrp`.
fn encode_address(hrp: &str, program: &[u8; 32]) -> Result<String, ForgeError> {
    let hrp = Hrp::parse(hrp).map_err(|e| anchoring_err(format!("bad hrp: {e}")))?;
    bech32::segwit::encode_v1(hrp, program)
        .map_err(|e| anchoring_err(format!("bech32m encode: {e}")))
}

/// The witness program and address of the **last** state of `states`, chained
/// over every earlier one from `pubkey_base`.
fn derive_head(
    pubkey_base: &str,
    chain: &str,
    states: &[MarkState],
) -> Result<(String, String), ForgeError> {
    let hrp = chain_hrp(chain)
        .ok_or_else(|| ForgeError::BadRequest(format!("unknown chain \"{chain}\"")))?;
    let texts: Vec<String> = states.iter().map(MarkState::json).collect();
    let outputs = bt_trail_outputs(pubkey_base, &texts)
        .map_err(|e| anchoring_err(format!("trail derivation refused: {e}")))?;
    let last = outputs
        .last()
        .ok_or_else(|| anchoring_err("trail derivation needs at least one state"))?;
    Ok((hex::encode(last), encode_address(hrp, last)?))
}

/// A fresh trail key from the operating system's RNG: the secret (hex, kept)
/// and its compressed public point (hex).
fn new_key() -> (TrailKey, String) {
    let secret = <k256::SecretKey as k256::elliptic_curve::Generate>::generate();
    let public = secret.public_key().to_sec1_point(true);
    (
        TrailKey(hex::encode(secret.to_bytes())),
        hex::encode(public.as_bytes()),
    )
}

fn is_commit_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl TrailStore {
    /// Build the store under `<plugin_dir>/marks`.
    ///
    /// # Errors
    ///
    /// The chain guard of [`ForgeConfig::validate_chain`], or an I/O failure
    /// creating the directory.
    pub fn new(cfg: &ForgeConfig, plugin_dir: &Path) -> Result<Self, ForgeError> {
        cfg.validate_chain()?;
        let dir = plugin_dir.join("marks");
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            chain: cfg.default_chain.to_ascii_lowercase(),
            allow_mainnet: cfg.allow_mainnet,
            sparse: cfg.sparse_marks,
            locks: Mutex::new(HashMap::new()),
        })
    }

    /// The chain new trails are minted on.
    #[must_use]
    pub fn chain(&self) -> &str {
        &self.chain
    }

    fn path_of(&self, owner: &str, repo: &str) -> Result<PathBuf, ForgeError> {
        if !valid_name_segment(owner) {
            return Err(ForgeError::PathTraversal(format!("owner: {owner}")));
        }
        if !valid_name_segment(repo) {
            return Err(ForgeError::PathTraversal(format!("repo: {repo}")));
        }
        Ok(self.dir.join(owner).join(format!("{repo}.json")))
    }

    /// Whether anchoring is enabled (a trail file exists).
    #[must_use]
    pub fn is_enabled(&self, owner: &str, repo: &str) -> bool {
        self.path_of(owner, repo).is_ok_and(|p| p.is_file())
    }

    /// Load a trail: `Ok(None)` when anchoring is not enabled.
    ///
    /// # Errors
    ///
    /// A trail file that exists but cannot be read or parsed is an error, never
    /// "not enabled": treating it as absent would let the next enable overwrite
    /// a key someone may have funded. The message carries no file content.
    pub fn load(&self, owner: &str, repo: &str) -> Result<Option<Trail>, ForgeError> {
        let path = self.path_of(owner, repo)?;
        let raw = match std::fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ForgeError::Io(e)),
        };
        serde_json::from_str::<Trail>(&raw)
            .map(Some)
            .map_err(|_| anchoring_err(format!("trail file for {owner}/{repo} is unreadable")))
    }

    /// Persist atomically: a `0600` temporary file in the same directory, then
    /// a rename. The key is inside, hence the mode from creation, not after.
    fn save(&self, owner: &str, repo: &str, trail: &Trail) -> Result<(), ForgeError> {
        use std::io::Write;
        let path = self.path_of(owner, repo)?;
        let parent = path
            .parent()
            .ok_or_else(|| anchoring_err("trail path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let body = serde_json::to_vec(trail)?;
        let written = (|| {
            let mut f = opts.open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()
        })();
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(ForgeError::Io(e));
        }
        Ok(())
    }

    /// The per-repo mark lock (JSS `withMarkLock`): every read-modify-write of
    /// a trail holds it, so two pushes cannot both derive "mark N+1".
    async fn lock(&self, owner: &str, repo: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = {
            let mut map = self
                .locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Drop entries nobody holds, so the map follows live repos.
            map.retain(|_, v| Arc::strong_count(v) > 1);
            Arc::clone(
                map.entry(format!("{owner}/{repo}"))
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        m.lock_owned().await
    }

    /// The mainnet guard for a *stored* trail: a trail on a mainnet chain is not
    /// extended while the operator has not opted in.
    fn check_chain(&self, trail: &Trail) -> Result<(), ForgeError> {
        let cfg = ForgeConfig {
            allow_mainnet: self.allow_mainnet,
            ..ForgeConfig::default()
        };
        if !cfg.chain_allowed(&trail.chain) {
            return Err(ForgeError::Forbidden(format!(
                "this trail is on mainnet chain \"{}\" and allow_mainnet is off",
                trail.chain
            )));
        }
        Ok(())
    }

    fn append(trail: &mut Trail, state: MarkState) -> Result<usize, ForgeError> {
        let mut states: Vec<MarkState> = trail.marks.iter().map(|m| m.state.clone()).collect();
        states.push(state.clone());
        let (program, address) = derive_head(&trail.pubkey_base, &trail.chain, &states)?;
        let index = trail.marks.len();
        trail.marks.push(Mark {
            index,
            state_hash: mark_state_hash(&state),
            state,
            program,
            address,
            status: MarkStatus::Pending,
            at: now_secs(),
            txid: None,
            vout: None,
            amount: None,
            marked_at: None,
        });
        Ok(index)
    }

    /// Enable anchoring (genesis, JSS `apiMarksEnable`): mint a key and derive
    /// mark 0 from the current default-branch `tip`. The caller has already
    /// authorised the owner.
    ///
    /// # Errors
    ///
    /// [`ForgeError::Conflict`] when already enabled (never a key rotation),
    /// [`ForgeError::BadRequest`] for a malformed commit, or an I/O error.
    pub async fn enable(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        tip: &str,
    ) -> Result<Trail, ForgeError> {
        if !is_commit_id(tip) {
            return Err(ForgeError::BadRequest("tip is not a commit id".into()));
        }
        let _guard = self.lock(owner, repo).await;
        if self.load(owner, repo)?.is_some() {
            return Err(ForgeError::Conflict(
                "anchoring is already enabled for this repository".into(),
            ));
        }
        let (privkey, pubkey_base) = new_key();
        let mut trail = Trail {
            v: 1,
            chain: self.chain.clone(),
            privkey,
            pubkey_base,
            created_at: now_secs(),
            marks: Vec::new(),
        };
        Self::append(
            &mut trail,
            MarkState {
                commit: tip.to_string(),
                repo: format!("{owner}/{repo}"),
                branch: branch.to_string(),
            },
        )?;
        self.save(owner, repo, &trail)?;
        tracing::info!(
            "forge: anchoring enabled for {owner}/{repo} on {} (trail key is FORGE-HELD in \
             plugin_dir/marks; testnet custody)",
            trail.chain
        );
        Ok(trail)
    }

    /// Record where a mark landed on-chain (JSS `apiMarkTxo`). The shape is
    /// the caller's to validate; this enforces the ordering rules. Recorded,
    /// never verified: the forge fetches nothing from any chain.
    ///
    /// # Errors
    ///
    /// [`ForgeError::NotFound`] (not enabled, or no such mark) and
    /// [`ForgeError::Conflict`] (already marked, or out of order).
    pub async fn record_txo(
        &self,
        owner: &str,
        repo: &str,
        index: usize,
        txid: &str,
        vout: u32,
        amount: u64,
    ) -> Result<Mark, ForgeError> {
        let _guard = self.lock(owner, repo).await;
        let mut trail = self.load(owner, repo)?.ok_or_else(|| {
            ForgeError::NotFound("anchoring is not enabled for this repository".into())
        })?;
        let status_of = |i: usize| trail.marks.get(i).map(|m| m.status);
        match status_of(index) {
            None => return Err(ForgeError::NotFound("no such mark".into())),
            Some(MarkStatus::Marked) => {
                return Err(ForgeError::Conflict(
                    "this mark already has a recorded transaction".into(),
                ))
            }
            Some(MarkStatus::Pending) => {}
        }
        if index > 0 && status_of(index - 1) != Some(MarkStatus::Marked) {
            return Err(ForgeError::Conflict(
                "record marks in order: the trail is a linear spend chain (mark N spends mark N-1)"
                    .into(),
            ));
        }
        let mark = &mut trail.marks[index];
        mark.txid = Some(txid.to_string());
        mark.vout = Some(vout);
        mark.amount = Some(amount);
        mark.status = MarkStatus::Marked;
        mark.marked_at = Some(now_secs());
        let out = mark.clone();
        self.save(owner, repo, &trail)?;
        tracing::info!(
            "forge: mark #{index} of {owner}/{repo} recorded as {}:{vout} (claim recorded, not verified)",
            &txid[..10]
        );
        Ok(out)
    }

    /// The one advance beat (JSS `recordTip`): compare `tip`, the tip of the
    /// default branch `branch`, to the last mark and append a pending mark for
    /// it, or re-target the trailing pending mark under sparse marking.
    ///
    /// The caller has established that `branch` is the default branch and that
    /// `tip` is its real tip.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`ForgeError::Forbidden`] when the stored trail is
    /// on a mainnet chain the operator has not allowed.
    pub async fn record_tip(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        tip: &str,
    ) -> Result<TipOutcome, ForgeError> {
        if !is_commit_id(tip) {
            return Err(ForgeError::BadRequest("tip is not a commit id".into()));
        }
        if !self.is_enabled(owner, repo) {
            return Ok(TipOutcome::NotEnabled);
        }
        let _guard = self.lock(owner, repo).await;
        let Some(mut trail) = self.load(owner, repo)? else {
            return Ok(TipOutcome::NotEnabled);
        };
        self.check_chain(&trail)?;
        let state = MarkState {
            commit: tip.to_string(),
            repo: format!("{owner}/{repo}"),
            branch: branch.to_string(),
        };
        if let Some(last) = trail.marks.last() {
            if last.state.commit == tip && last.state.branch == branch {
                return Ok(TipOutcome::Unchanged);
            }
            if self.sparse && last.status == MarkStatus::Pending {
                // Sparse: the trailing mark is unfunded, so re-target it at the
                // new tip, chaining the same MARKED prefix, rather than stack.
                let mut states: Vec<MarkState> = trail.marks[..trail.marks.len() - 1]
                    .iter()
                    .map(|m| m.state.clone())
                    .collect();
                states.push(state.clone());
                let (program, address) = derive_head(&trail.pubkey_base, &trail.chain, &states)?;
                let index = trail.marks.len() - 1;
                let m = &mut trail.marks[index];
                m.state_hash = mark_state_hash(&state);
                m.state = state;
                m.program = program;
                m.address = address;
                m.at = now_secs();
                self.save(owner, repo, &trail)?;
                tracing::info!(
                    "forge: mark #{index} re-targeted (sparse) for {owner}/{repo}@{branch}"
                );
                return Ok(TipOutcome::Retargeted(index));
            }
        }
        if trail.marks.len() >= MARKS_CAP {
            tracing::warn!(
                "forge: {owner}/{repo} hit the {MARKS_CAP}-mark cap, not recording {tip}"
            );
            return Ok(TipOutcome::CapReached);
        }
        let index = Self::append(&mut trail, state)?;
        self.save(owner, repo, &trail)?;
        tracing::info!("forge: mark #{index} pending for {owner}/{repo}@{branch}");
        Ok(TipOutcome::Appended(index))
    }
}

impl ForgeTrailSource for TrailStore {
    fn has_forge_trail(&self, owner: &str, repo: &str) -> bool {
        self.is_enabled(owner, repo)
    }

    fn anchor_facts(&self, owner: &str, repo: &str, trail_url: &str) -> Option<AnchorFacts> {
        self.load(owner, repo)
            .ok()
            .flatten()
            .and_then(|t| t.anchor_facts(trail_url))
    }
}

impl ForgeTrailSource for ForgeService {
    fn has_forge_trail(&self, owner: &str, repo: &str) -> bool {
        self.trails.has_forge_trail(owner, repo)
    }

    fn anchor_facts(&self, owner: &str, repo: &str, trail_url: &str) -> Option<AnchorFacts> {
        self.trails.anchor_facts(owner, repo, trail_url)
    }
}

// ---- git: the default-branch tip -----------------------------------------

/// The commit at the tip of `refs/heads/<branch>`, or `None` when the branch
/// has none. The branch is validated before it reaches git and the argument
/// always begins `refs/`, so it can never be read as a flag.
async fn branch_tip(git_dir: &Path, branch: &str) -> Option<String> {
    if !browse::valid_rev(branch) {
        return None;
    }
    let out = solid_pod_rs_git::hardened_git_async()
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}^{{commit}}"),
        ])
        .current_dir(git_dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let tip = String::from_utf8(out.stdout).ok()?.trim().to_string();
    is_commit_id(&tip).then_some(tip)
}

// ---- the service surface -------------------------------------------------

/// A mark index in the route: `0` or a non-zero-led number of at most six
/// digits (JSS `MARK_INDEX_RE`).
fn parse_mark_index(s: &str) -> Option<usize> {
    let ok = !s.is_empty()
        && s.len() <= 6
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if ok {
        s.parse().ok()
    } else {
        None
    }
}

/// An integral JSON number (JS `Number.isInteger`), as an `i64`.
fn json_integer(v: &Value) -> Option<i64> {
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    if let Some(u) = v.as_u64() {
        return i64::try_from(u).ok();
    }
    let f = v.as_f64()?;
    // 2^53: the largest range in which every integer is exact.
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_992.0).then_some(f as i64)
}

fn is_form(req: &ForgeRequest) -> bool {
    req.header("content-type")
        .is_some_and(|c| c.contains("application/x-www-form-urlencoded"))
}

impl ForgeService {
    /// The trail store, for embedders that wire [`ForgeTrailSource`] elsewhere.
    #[must_use]
    pub fn trails(&self) -> &Arc<TrailStore> {
        &self.trails
    }

    /// The one advance beat for the default branch (JSS `recordTip`), called
    /// after a **successful** write to a repository's default branch: the git
    /// push path calls it after `git-receive-pack`, and a merge or web-edit
    /// path calls it after its `update-ref`.
    ///
    /// `commit` is the tip the caller just wrote. It is a hint: the forge
    /// re-reads the real tip of `refs/heads/<branch>` and records that, so a
    /// stale or forged hint cannot put a state on the trail that the branch
    /// never had. A write to any other branch is a no-op, as is a repository
    /// without a forge-held trail.
    ///
    /// # Errors
    ///
    /// [`ForgeError::BadRequest`] for a malformed branch or commit,
    /// [`ForgeError::NotFound`] for a missing repository, and storage or
    /// chain-guard failures from [`TrailStore::record_tip`].
    pub async fn record_tip(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        commit: &str,
    ) -> Result<TipOutcome, ForgeError> {
        if !browse::valid_rev(branch) {
            return Err(ForgeError::BadRequest(format!("invalid branch: {branch}")));
        }
        if !is_commit_id(commit) {
            return Err(ForgeError::BadRequest("commit is not a commit id".into()));
        }
        if !self.trails.is_enabled(owner, repo) {
            return Ok(TipOutcome::NotEnabled);
        }
        let dir = self.resolve_repo(owner, repo).await?;
        if browse::default_branch(&dir).await != branch {
            return Ok(TipOutcome::NotDefaultBranch);
        }
        let Some(tip) = branch_tip(&dir, branch).await else {
            return Ok(TipOutcome::NotEnabled);
        };
        self.trails.record_tip(owner, repo, branch, &tip).await
    }

    /// After a successful `git-receive-pack`: record the default-branch tip.
    /// Failures are logged, never raised into the push response (JSS
    /// `recordTipSafe`).
    pub(crate) async fn record_pushed_tip(&self, owner: &str, repo: &str) {
        if !self.trails.is_enabled(owner, repo) {
            return;
        }
        let Ok(dir) = self.resolve_repo(owner, repo).await else {
            return;
        };
        let branch = browse::default_branch(&dir).await;
        let Some(tip) = branch_tip(&dir, &branch).await else {
            return;
        };
        if let Err(e) = self.record_tip(owner, repo, &branch, &tip).await {
            tracing::warn!("forge: recordTip {owner}/{repo} failed: {e}");
        }
    }

    /// `api/repos/<owner>/<repo>/marks[/...]`: list, enable and record a
    /// transaction (JSS `apiMarksHandler`). `tail` is what follows `marks`.
    pub(crate) async fn h_api_marks(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        tail: &[String],
    ) -> Result<ForgeResponse, ForgeError> {
        let method = req.method.to_ascii_uppercase();
        let get = method == "GET" || method == "HEAD";
        let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
        match tail.as_slice() {
            [] if get => self.marks_list(owner, repo),
            [] | ["enable"] if method == "POST" => self.marks_enable(req, agent, owner, repo).await,
            [i, "txo"] if parse_mark_index(i).is_some() => {
                if method != "POST" {
                    return Ok(ForgeResponse::error(405, "method not allowed"));
                }
                let index = parse_mark_index(i).unwrap_or(0);
                self.marks_txo(req, agent, owner, repo, index).await
            }
            [] | ["enable"] => Ok(ForgeResponse::error(405, "method not allowed")),
            _ => Err(ForgeError::NotFound("not found".into())),
        }
    }

    /// Owner-only: anonymous is 401, any other agent 403.
    fn require_owner(agent: &ForgeAgent, owner: &str, what: &str) -> Result<(), ForgeError> {
        match agent {
            ForgeAgent::Anonymous => {
                Err(ForgeError::Unauthorised("authentication required".into()))
            }
            a if a.can_write_namespace(owner) => Ok(()),
            _ => Err(ForgeError::Forbidden(format!(
                "only the repo owner may {what}"
            ))),
        }
    }

    fn marks_list(&self, owner: &str, repo: &str) -> Result<ForgeResponse, ForgeError> {
        let v = match self.trails.load(owner, repo)? {
            None => json!({ "enabled": false, "chain": self.trails.chain() }),
            Some(t) => json!({
                "enabled": true,
                "chain": t.chain,
                "pubkeyBase": t.pubkey_base,
                "marks": t.marks,
            }),
        };
        Ok(ForgeResponse::json(200, &v))
    }

    async fn marks_enable(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        Self::require_owner(agent, owner, "enable anchoring")?;
        let dir = self.resolve_repo(owner, repo).await?;
        let branch = browse::default_branch(&dir).await;
        let Some(tip) = branch_tip(&dir, &branch).await else {
            return Ok(ForgeResponse::error(
                422,
                "anchoring needs a commit on the default branch: push first",
            ));
        };
        let trail = self.trails.enable(owner, repo, &branch, &tip).await?;
        if is_form(req) {
            return Ok(ForgeResponse::redirect(
                303,
                &self.marks_page_url(owner, repo),
            ));
        }
        let mark = trail.marks.first().cloned();
        Ok(ForgeResponse::json(
            201,
            &json!({
                "enabled": true,
                "chain": trail.chain,
                "pubkeyBase": trail.pubkey_base,
                "mark": mark,
            }),
        ))
    }

    fn marks_page_url(&self, owner: &str, repo: &str) -> String {
        format!("{}/{owner}/{repo}/marks", self.prefix())
    }

    async fn marks_txo(
        &self,
        req: &ForgeRequest,
        agent: &ForgeAgent,
        owner: &str,
        repo: &str,
        index: usize,
    ) -> Result<ForgeResponse, ForgeError> {
        Self::require_owner(agent, owner, "record a mark transaction")?;
        // The body is read after authorisation, like JSS (body before auth only
        // so NIP-98 payload tags verify, which the caller has already done).
        let (txid_v, vout_v, amount_v) = if is_form(req) {
            let pairs = parse_form(&String::from_utf8_lossy(&req.raw_body));
            let field = |k: &str| {
                pairs
                    .iter()
                    .find(|(kk, _)| kk == k)
                    .map(|(_, v)| v.trim().to_string())
            };
            let num = |k: &str| field(k).and_then(|s| s.parse::<i64>().ok());
            (
                field("txid").map(Value::from).unwrap_or(Value::Null),
                num("vout").map(Value::from).unwrap_or(Value::Null),
                num("amount").map(Value::from).unwrap_or(Value::Null),
            )
        } else {
            let p: Value = serde_json::from_slice(&req.raw_body)
                .ok()
                .filter(Value::is_object)
                .ok_or_else(|| ForgeError::BadRequest("invalid JSON body".into()))?;
            (
                p.get("txid").cloned().unwrap_or(Value::Null),
                p.get("vout").cloned().unwrap_or(Value::Null),
                p.get("amount").cloned().unwrap_or(Value::Null),
            )
        };
        let txid = txid_v.as_str().unwrap_or("").to_ascii_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Ok(ForgeResponse::error(422, "txid must be 64 hex chars"));
        }
        let Some(vout) = json_integer(&vout_v)
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v <= MAX_VOUT)
        else {
            return Ok(ForgeResponse::error(
                422,
                "vout must be a non-negative integer",
            ));
        };
        let Some(amount) = json_integer(&amount_v)
            .and_then(|v| u64::try_from(v).ok())
            .filter(|a| (1..=SATS_CAP).contains(a))
        else {
            return Ok(ForgeResponse::error(
                422,
                "amount must be a positive integer (satoshis)",
            ));
        };
        let mark = self
            .trails
            .record_txo(
                owner,
                repo,
                index,
                &txid,
                u32::try_from(vout).unwrap_or(u32::MAX),
                amount,
            )
            .await?;
        if is_form(req) {
            return Ok(ForgeResponse::redirect(
                303,
                &self.marks_page_url(owner, repo),
            ));
        }
        Ok(ForgeResponse::json(
            200,
            &json!({
                "index": mark.index,
                "status": "marked",
                "txid": txid,
                "vout": vout,
                "amount": amount,
            }),
        ))
    }

    /// `GET /<owner>/<repo>/marks`: the Anchors page.
    pub(crate) async fn h_marks_page(
        &self,
        req: &ForgeRequest,
        owner: &str,
        repo: &str,
    ) -> Result<ForgeResponse, ForgeError> {
        let dir = self.resolve_repo(owner, repo).await?;
        let branch = browse::default_branch(&dir).await;
        let ctx = crate::marks_ui::MarksCtx {
            prefix: &self.prefix(),
            owner,
            repo,
            branch: &branch,
            chain: self.trails.chain(),
            origin: req.host_url.as_deref().unwrap_or(""),
        };
        let html = if let Some(trail) = self.trails.load(owner, repo)? {
            crate::marks_ui::forge_held_page(&ctx, &trail)
        } else if let Some(rt) = crate::gitmark::read_repo_trail(&dir, &branch).await {
            crate::marks_ui::repo_held_page(&ctx, &rt)
        } else {
            crate::marks_ui::pitch_page(&ctx)
        };
        Ok(ForgeResponse::html(200, html))
    }

    /// `GET /<owner>/<repo>/blocktrails.json` for a forge-held trail: the
    /// verifier document with the full mark list riding additively, or `None`
    /// when the repository has no forge-held trail (JSS `blocktrailsResp`).
    pub(crate) fn forge_blocktrails_json(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Option<String>, ForgeError> {
        Ok(self.trails.load(owner, repo)?.map(|t| {
            serde_json::to_string_pretty(&t.document()).unwrap_or_else(|_| "{}".to_string())
        }))
    }

    /// Show the Anchors tab on a rendered repository page when `anchoring_ui`
    /// is on or the repository carries a trail (forge-held or repo-held).
    pub(crate) async fn decorate_repo_page(
        &self,
        owner: &str,
        repo: &str,
        mut resp: ForgeResponse,
    ) -> ForgeResponse {
        let is_html = resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.starts_with("text/html"));
        if resp.status != 200 || !is_html {
            return resp;
        }
        let Ok(html) = std::str::from_utf8(&resp.body) else {
            return resp;
        };
        let prefix = self.prefix();
        if !crate::marks_ui::has_tab_slot(html, &prefix, owner, repo) {
            return resp;
        }
        let show = self.cfg.anchoring_ui || self.trails.is_enabled(owner, repo) || {
            match self.resolve_repo(owner, repo).await {
                Ok(dir) => {
                    let branch = browse::default_branch(&dir).await;
                    crate::gitmark::read_repo_trail(&dir, &branch)
                        .await
                        .is_some()
                }
                Err(_) => false,
            }
        };
        if show {
            let out = crate::marks_ui::add_anchors_tab(html, &prefix, owner, repo);
            resp.body = bytes::Bytes::from(out);
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Differential vectors: generated by RUNNING the JSS forge
    // `lib/blocktrails.js` (plugins@63a16cb: `markStateHash`, `trailProgram`,
    // `trailAddress`) under node, over the fixed inputs below. Throwaway key.
    const PUB: &str = "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
    const PUB3: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const C0: &str = "cf97baba489e88c1ffbe6758c0fe8c18ff83d17d";
    const C1: &str = "31047bb51136850de3ac531d0a207710db5d6173";

    fn states() -> Vec<MarkState> {
        let st = |c: &str, b: &str| MarkState {
            commit: c.into(),
            repo: "casey/demo".into(),
            branch: b.into(),
        };
        vec![
            st(C0, "main"),
            st(C1, "main"),
            st(&"1".repeat(40), "feature/x\"y"),
        ]
    }

    #[test]
    fn state_hash_and_json_match_jss() {
        let s = states();
        assert_eq!(
            s[0].json(),
            format!(r#"{{"commit":"{C0}","repo":"casey/demo","branch":"main"}}"#)
        );
        // an embedded quote is escaped as JSON.stringify does
        assert_eq!(
            s[2].json(),
            r#"{"commit":"1111111111111111111111111111111111111111","repo":"casey/demo","branch":"feature/x\"y"}"#
        );
        assert_eq!(
            mark_state_hash(&s[0]),
            "98684a6cfc3fedfd405a20b66a96305b2834a86208fca16164fae7cdd395dfcf"
        );
        assert_eq!(
            mark_state_hash(&s[1]),
            "dea42db8f8280b406a4c77c7a3ff94988dc59c830c9c834ebe04866b20b667b4"
        );
        assert_eq!(
            mark_state_hash(&s[2]),
            "c976a6d56d1f797d6b95de28cf9cea3e0ee886c4ff0999c1bf37b4bd0b3c0a9f"
        );
    }

    #[test]
    fn derivation_matches_jss_for_every_hrp_and_key() {
        // (base, chain, expected [program, address] per prefix length 1..=3)
        #[allow(clippy::type_complexity)]
        let table: &[(&str, &str, [(&str, &str); 3])] = &[
            (
                PUB,
                "tbtc4",
                [
                    (
                        "5dfeea53351d80fac6ebb4f5e057e4b2c8ddae3129310d87ba775bccdae50ff3",
                        "tb1pthlw55e4rkq043htkn67q4lyktydmt339ycsmpa6waduekh9pleshcpx8q",
                    ),
                    (
                        "0e874a35a09afae38938dc9649be2ec68029d9139b7bd35a9541599b0f86730d",
                        "tb1pp6r55ddqntaw8zfcmjtyn03wc6qznkgnndaaxk54g9vekruxwvxs9vm96j",
                    ),
                    (
                        "4dc42cf73d05ec827eb15794e9c5f76ee003b3ff0f1ace39325d242913747945",
                        "tb1pfhzzeaeaqhkgyl43272wn30hdmsq8vllpudvuwfjt5jzjym509zs9f0err",
                    ),
                ],
            ),
            (
                PUB,
                "xbt",
                [
                    (
                        "5dfeea53351d80fac6ebb4f5e057e4b2c8ddae3129310d87ba775bccdae50ff3",
                        "bc1pthlw55e4rkq043htkn67q4lyktydmt339ycsmpa6waduekh9plesqshfa0",
                    ),
                    (
                        "0e874a35a09afae38938dc9649be2ec68029d9139b7bd35a9541599b0f86730d",
                        "bc1pp6r55ddqntaw8zfcmjtyn03wc6qznkgnndaaxk54g9vekruxwvxsjyd2qa",
                    ),
                    (
                        "4dc42cf73d05ec827eb15794e9c5f76ee003b3ff0f1ace39325d242913747945",
                        "bc1pfhzzeaeaqhkgyl43272wn30hdmsq8vllpudvuwfjt5jzjym509zsjpekev",
                    ),
                ],
            ),
            (
                PUB,
                "regtest",
                [
                    (
                        "5dfeea53351d80fac6ebb4f5e057e4b2c8ddae3129310d87ba775bccdae50ff3",
                        "bcrt1pthlw55e4rkq043htkn67q4lyktydmt339ycsmpa6waduekh9ples6ptqj6",
                    ),
                    (
                        "0e874a35a09afae38938dc9649be2ec68029d9139b7bd35a9541599b0f86730d",
                        "bcrt1pp6r55ddqntaw8zfcmjtyn03wc6qznkgnndaaxk54g9vekruxwvxsg43r0g",
                    ),
                    (
                        "4dc42cf73d05ec827eb15794e9c5f76ee003b3ff0f1ace39325d242913747945",
                        "bcrt1pfhzzeaeaqhkgyl43272wn30hdmsq8vllpudvuwfjt5jzjym509zsgs9lke",
                    ),
                ],
            ),
            (
                PUB3,
                "signet",
                [
                    (
                        "cbfefaf2dbaeefe8e87cba2d9f34f0c6c2228dab3aa53949b60659038b52d4da",
                        "tb1pe0l04ukm4mh736ruhgke7d8scmpz9rdt82jnjjdkqevs8z6j6ndqnu7nyg",
                    ),
                    (
                        "1e043a435dba94d6878c59be200c4c67c4c14be58617fd9a9a1d13eade4ec8c3",
                        "tb1prczr5s6ah22ddpuvtxlzqrzvvlzvzjl9sctlmx56r5f74hjwerpsjxvu7t",
                    ),
                    (
                        "cf551bd134de972b151766c1669de39e3e09edc64e1f31951450e652fc7d2e3f",
                        "tb1pea23h5f5m6tjk9ghvmqkd80rnclqnmwxfc0nr9g52rn99lra9cls7ldp4e",
                    ),
                ],
            ),
            (
                PUB3,
                "btc",
                [
                    (
                        "cbfefaf2dbaeefe8e87cba2d9f34f0c6c2228dab3aa53949b60659038b52d4da",
                        "bc1pe0l04ukm4mh736ruhgke7d8scmpz9rdt82jnjjdkqevs8z6j6ndqy5gu78",
                    ),
                    (
                        "1e043a435dba94d6878c59be200c4c67c4c14be58617fd9a9a1d13eade4ec8c3",
                        "bc1prczr5s6ah22ddpuvtxlzqrzvvlzvzjl9sctlmx56r5f74hjwerps9w6nyy",
                    ),
                    (
                        "cf551bd134de972b151766c1669de39e3e09edc64e1f31951450e652fc7d2e3f",
                        "bc1pea23h5f5m6tjk9ghvmqkd80rnclqnmwxfc0nr9g52rn99lra9clsfhmw0k",
                    ),
                ],
            ),
        ];
        let s = states();
        for (base, chain, expect) in table {
            for (n, (program, address)) in expect.iter().enumerate() {
                let (p, a) = derive_head(base, chain, &s[..=n]).unwrap();
                assert_eq!(&p, program, "{chain} program #{n}");
                assert_eq!(&a, address, "{chain} address #{n}");
            }
        }
    }

    #[test]
    fn derivation_is_deterministic_and_chained() {
        let s = states();
        assert_eq!(
            derive_head(PUB, "tbtc4", &s[..2]).unwrap(),
            derive_head(PUB, "tbtc4", &s[..2]).unwrap()
        );
        assert_ne!(
            derive_head(PUB, "tbtc4", &s[..1]).unwrap().1,
            derive_head(PUB, "tbtc4", &s[..2]).unwrap().1,
            "each state derives a NEW address"
        );
        assert!(derive_head(PUB, "dogecoin", &s).is_err());
        assert!(derive_head("not a key", "tbtc4", &s).is_err());
    }

    fn store(sparse: bool) -> (tempfile::TempDir, TrailStore) {
        let td = tempfile::tempdir().unwrap();
        let cfg = ForgeConfig {
            sparse_marks: sparse,
            ..Default::default()
        };
        let st = TrailStore::new(&cfg, td.path()).unwrap();
        (td, st)
    }

    fn id(c: char) -> String {
        c.to_string().repeat(40)
    }

    #[tokio::test]
    async fn enable_derives_genesis_and_refuses_a_second_enable() {
        let (_td, st) = store(false);
        let t = st.enable("casey", "trail", "main", &id('a')).await.unwrap();
        assert_eq!(t.chain, "tbtc4", "testnet4 is the default chain");
        assert_eq!(t.marks.len(), 1);
        let m = &t.marks[0];
        assert_eq!(m.state.commit, id('a'));
        assert_eq!(m.state_hash, sha256_hex(&m.state.json()));
        assert_eq!(m.status, MarkStatus::Pending);
        assert!(m.address.starts_with("tb1p"));
        // the program re-derives from the served pubkeyBase
        let again = derive_head(&t.pubkey_base, &t.chain, std::slice::from_ref(&m.state)).unwrap();
        assert_eq!((m.program.clone(), m.address.clone()), again);
        assert!(t.pubkey_base.len() == 66 && t.pubkey_base.starts_with(['0']));
        assert!(matches!(
            st.enable("casey", "trail", "main", &id('a')).await,
            Err(ForgeError::Conflict(_))
        ));
        assert!(matches!(
            st.enable("casey", "x", "main", "nothex").await,
            Err(ForgeError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn trail_key_is_0600_unique_and_never_in_debug_or_the_document() {
        let (td, st) = store(false);
        let t1 = st.enable("casey", "a", "main", &id('a')).await.unwrap();
        let t2 = st.enable("casey", "b", "main", &id('a')).await.unwrap();
        assert_ne!(t1.privkey, t2.privkey, "each trail gets a fresh key");
        assert_ne!(t1.pubkey_base, t2.pubkey_base);

        let file = td.path().join("marks/casey/a.json");
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let key = on_disk["privkey"].as_str().unwrap().to_string();
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
        // the key matches the base pubkey (it is the key the addresses derive from)
        let sk = k256::SecretKey::from_slice(&hex::decode(&key).unwrap()).unwrap();
        assert_eq!(
            hex::encode(sk.public_key().to_sec1_point(true).as_bytes()),
            t1.pubkey_base
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the trail file holds the key: 0600");
            let dmode = std::fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700);
        }
        // no stray temp files left behind
        let names: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| n.ends_with(".json")), "{names:?}");

        // never in Debug, in the verifier document, or in the public mark list
        assert!(!format!("{t1:?}").contains(&key));
        assert!(format!("{t1:?}").contains("<redacted>"));
        assert!(!t1.document().to_string().contains(&key));
        assert!(!t1.document().to_string().contains("privkey"));
        assert!(!serde_json::to_string(&t1.marks)
            .unwrap()
            .contains("privkey"));
        assert!(!format!("{st:?}").contains(&key));
    }

    #[tokio::test]
    async fn a_corrupt_trail_file_is_an_error_not_not_enabled() {
        let (td, st) = store(false);
        st.enable("casey", "trail", "main", &id('a')).await.unwrap();
        let file = td.path().join("marks/casey/trail.json");
        std::fs::write(&file, b"{ not json").unwrap();
        assert!(st.load("casey", "trail").is_err());
        // and enabling does not overwrite what may be a funded key
        assert!(st.enable("casey", "trail", "main", &id('b')).await.is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"{ not json");
    }

    #[test]
    fn hostile_owner_and_repo_never_reach_the_filesystem() {
        let (_td, st) = store(false);
        for bad in ["..", "../x", "a/b", ".hidden", "", "a\0b"] {
            assert!(st.load(bad, "r").is_err(), "owner {bad:?}");
            assert!(st.load("o", bad).is_err(), "repo {bad:?}");
            assert!(!st.is_enabled(bad, "r"));
        }
    }

    #[tokio::test]
    async fn record_tip_stacks_pending_marks_chained_over_the_last() {
        let (_td, st) = store(false);
        assert_eq!(
            st.record_tip("casey", "trail", "main", &id('a'))
                .await
                .unwrap(),
            TipOutcome::NotEnabled
        );
        st.enable("casey", "trail", "main", &id('a')).await.unwrap();
        assert_eq!(
            st.record_tip("casey", "trail", "main", &id('a'))
                .await
                .unwrap(),
            TipOutcome::Unchanged
        );
        assert_eq!(
            st.record_tip("casey", "trail", "main", &id('b'))
                .await
                .unwrap(),
            TipOutcome::Appended(1)
        );
        let t = st.load("casey", "trail").unwrap().unwrap();
        assert_eq!(t.marks.len(), 2);
        assert_ne!(t.marks[1].address, t.marks[0].address);
        let states: Vec<MarkState> = t.marks.iter().map(|m| m.state.clone()).collect();
        assert_eq!(
            derive_head(&t.pubkey_base, &t.chain, &states).unwrap().0,
            t.marks[1].program,
            "mark 1 chains its tweak over mark 0"
        );
        assert!(st.record_tip("casey", "trail", "main", "zz").await.is_err());
    }

    #[tokio::test]
    async fn sparse_marks_retarget_the_trailing_pending_mark() {
        // Transcribed from forge/test.js 'forge sparse marking'.
        let (_td, st) = store(true);
        st.enable("sparsey", "r", "main", &id('a')).await.unwrap();
        // while genesis is pending, a new tip re-targets mark 0 itself
        assert_eq!(
            st.record_tip("sparsey", "r", "main", &id('b'))
                .await
                .unwrap(),
            TipOutcome::Retargeted(0)
        );
        assert_eq!(st.load("sparsey", "r").unwrap().unwrap().marks.len(), 1);
        // fund genesis
        st.record_txo("sparsey", "r", 0, &"a".repeat(64), 0, 100_000)
            .await
            .unwrap();
        assert_eq!(
            st.record_tip("sparsey", "r", "main", &id('c'))
                .await
                .unwrap(),
            TipOutcome::Appended(1)
        );
        let m1 = st.load("sparsey", "r").unwrap().unwrap().marks[1].clone();
        assert_eq!(m1.state.commit, id('c'));
        assert_eq!(
            st.record_tip("sparsey", "r", "main", &id('d'))
                .await
                .unwrap(),
            TipOutcome::Retargeted(1)
        );
        let t = st.load("sparsey", "r").unwrap().unwrap();
        assert_eq!(
            t.marks.len(),
            2,
            "still genesis + ONE pending: re-targeted, not stacked"
        );
        assert_ne!(
            t.marks[1].address, m1.address,
            "the pending address moved to the new tip"
        );
        assert_eq!(t.marks[1].state.commit, id('d'));
        assert_eq!(t.marks[1].status, MarkStatus::Pending);
        assert_eq!(
            t.marks[0].status,
            MarkStatus::Marked,
            "the funded genesis is untouched"
        );
        // the re-derived head equals a fresh derivation over the marked prefix
        let states = vec![t.marks[0].state.clone(), t.marks[1].state.clone()];
        assert_eq!(
            derive_head(&t.pubkey_base, &t.chain, &states).unwrap().1,
            t.marks[1].address
        );
    }

    #[tokio::test]
    async fn txo_ordering_and_conflicts() {
        let (_td, st) = store(false);
        st.enable("casey", "trail", "main", &id('a')).await.unwrap();
        st.record_tip("casey", "trail", "main", &id('b'))
            .await
            .unwrap();
        st.record_tip("casey", "trail", "main", &id('c'))
            .await
            .unwrap();
        let txid = "f".repeat(64);
        // out of order: the trail is a linear spend chain
        assert!(matches!(
            st.record_txo("casey", "trail", 1, &txid, 0, 1000).await,
            Err(ForgeError::Conflict(_))
        ));
        assert!(matches!(
            st.record_txo("casey", "trail", 9, &txid, 0, 1000).await,
            Err(ForgeError::NotFound(_))
        ));
        assert!(matches!(
            st.record_txo("casey", "missing", 0, &txid, 0, 1000).await,
            Err(ForgeError::NotFound(_))
        ));
        let m = st
            .record_txo("casey", "trail", 0, &txid, 0, 250_000)
            .await
            .unwrap();
        assert_eq!(m.status, MarkStatus::Marked);
        // recording twice is refused: a mark is one spend
        assert!(matches!(
            st.record_txo("casey", "trail", 0, &"e".repeat(64), 1, 1)
                .await,
            Err(ForgeError::Conflict(_))
        ));
        st.record_txo("casey", "trail", 1, &"e".repeat(64), 1, 9)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn marks_cap_is_enforced() {
        let (td, st) = store(false);
        st.enable("casey", "cap", "main", &id('a')).await.unwrap();
        // fill the file to the cap directly (500 derivations through the API
        // would only slow the suite), then ask for one more
        let file = td.path().join("marks/casey/cap.json");
        let mut t: Trail = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let first = t.marks[0].clone();
        while t.marks.len() < MARKS_CAP {
            let mut m = first.clone();
            m.index = t.marks.len();
            t.marks.push(m);
        }
        std::fs::write(&file, serde_json::to_vec(&t).unwrap()).unwrap();
        assert_eq!(
            st.record_tip("casey", "cap", "main", &id('f'))
                .await
                .unwrap(),
            TipOutcome::CapReached
        );
        assert_eq!(
            st.load("casey", "cap").unwrap().unwrap().marks.len(),
            MARKS_CAP
        );
    }

    #[tokio::test]
    async fn a_stored_mainnet_trail_is_not_extended_without_allow_mainnet() {
        // The guard also covers a trail minted while the operator allowed
        // mainnet and read back after they stopped.
        let td = tempfile::tempdir().unwrap();
        let open = ForgeConfig {
            default_chain: "btc".into(),
            allow_mainnet: true,
            ..Default::default()
        };
        let st = TrailStore::new(&open, td.path()).unwrap();
        let t = st.enable("casey", "m", "main", &id('a')).await.unwrap();
        assert_eq!(t.chain, "btc");
        assert!(t.marks[0].address.starts_with("bc1p"));
        assert_eq!(
            st.record_tip("casey", "m", "main", &id('b')).await.unwrap(),
            TipOutcome::Appended(1)
        );
        let closed = TrailStore::new(&ForgeConfig::default(), td.path()).unwrap();
        assert!(matches!(
            closed.record_tip("casey", "m", "main", &id('c')).await,
            Err(ForgeError::Forbidden(_))
        ));
        assert_eq!(closed.load("casey", "m").unwrap().unwrap().marks.len(), 2);
        // and a store cannot even be built for a mainnet chain by default
        let bad = ForgeConfig {
            default_chain: "xbt".into(),
            ..Default::default()
        };
        assert!(TrailStore::new(&bad, td.path()).is_err());
    }

    #[tokio::test]
    async fn concurrent_advances_serialise_under_the_mark_lock() {
        let (_td, st) = store(false);
        let st = Arc::new(st);
        st.enable("casey", "race", "main", &id('0')).await.unwrap();
        let mut tasks = Vec::new();
        for i in 1..=8u8 {
            let st = Arc::clone(&st);
            tasks.push(tokio::spawn(async move {
                st.record_tip("casey", "race", "main", &format!("{i:040x}"))
                    .await
                    .unwrap()
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let t = st.load("casey", "race").unwrap().unwrap();
        assert_eq!(t.marks.len(), 9, "no lost update, no duplicate index");
        let idx: Vec<_> = t.marks.iter().map(|m| m.index).collect();
        assert_eq!(idx, (0..9).collect::<Vec<_>>());
        // the chain is internally consistent end to end
        let states: Vec<MarkState> = t.marks.iter().map(|m| m.state.clone()).collect();
        assert_eq!(
            derive_head(&t.pubkey_base, &t.chain, &states).unwrap().1,
            t.marks[8].address
        );
    }

    #[tokio::test]
    async fn document_is_verifier_compatible_with_pendings_additive() {
        // Transcribed from forge/test.js 'blocktrails.json is verifier-compatible'.
        let (_td, st) = store(false);
        let tip0 = id('a');
        st.enable("casey", "trail", "main", &tip0).await.unwrap();
        st.record_tip("casey", "trail", "main", &id('b'))
            .await
            .unwrap();
        st.record_tip("casey", "trail", "main", &id('c'))
            .await
            .unwrap();
        let txid = "d".repeat(64);
        st.record_txo("casey", "trail", 0, &txid, 0, 250_000)
            .await
            .unwrap();
        let t = st.load("casey", "trail").unwrap().unwrap();
        let doc = t.document();
        assert_eq!(doc["@type"], "Blocktrail");
        assert_eq!(doc["profile"], "gitmark");
        assert_eq!(doc["version"], "0.0.3");
        assert_eq!(doc["chain"], "tbtc4");
        assert_eq!(
            doc["states"],
            json!([tip0]),
            "states = the marked marks' commits"
        );
        let uri = format!(
            "txo:tbtc4:{txid}:0?amount=250000&commit={tip0}&pubkey={}",
            t.marks[0].program
        );
        assert_eq!(
            doc["txo"],
            json!([uri]),
            "pending marks have nothing on-chain yet"
        );
        assert_eq!(doc["@id"], json!(uri), "identified by its genesis txo");
        let marks = doc["marks"].as_array().unwrap();
        assert_eq!(marks.len(), 3);
        let statuses: Vec<_> = marks
            .iter()
            .map(|m| m["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, ["marked", "pending", "pending"]);
        // pending marks carry no transaction fields
        assert!(marks[1].get("txid").is_none());
        // the verifier's own parse regex shape
        let re_ok = uri.starts_with("txo:tbtc4:") && uri.contains("&commit=");
        assert!(re_ok);
        // facts for NIP-34
        let f = t.anchor_facts("https://x/blocktrails.json").unwrap();
        assert_eq!(f.genesis_txid, txid);
        assert_eq!(f.frontier_txid, txid);
        assert_eq!(f.frontier_commit, tip0);
        // no marked genesis, no facts
        let (_td2, st2) = store(false);
        st2.enable("casey", "fresh", "main", &id('a'))
            .await
            .unwrap();
        assert!(st2.anchor_facts("casey", "fresh", "u").is_none());
        assert!(st2.has_forge_trail("casey", "fresh"));
        assert!(!st2.has_forge_trail("casey", "none"));
        assert!(st.anchor_facts("casey", "trail", "u").is_some());
        // an unenabled trail has no marked prefix and no @id
        let mut t0 = t.clone();
        t0.marks.clear();
        assert!(t0.document().get("@id").is_none());
    }

    #[test]
    fn mark_index_and_json_integer_parsing() {
        assert_eq!(parse_mark_index("0"), Some(0));
        assert_eq!(parse_mark_index("12"), Some(12));
        for bad in ["", "01", "-1", "1x", "1234567", "9\0", "+1"] {
            assert_eq!(parse_mark_index(bad), None, "{bad:?}");
        }
        assert_eq!(json_integer(&json!(3)), Some(3));
        assert_eq!(json_integer(&json!(3.0)), Some(3));
        assert_eq!(json_integer(&json!(0.5)), None);
        assert_eq!(json_integer(&json!("3")), None);
        assert_eq!(json_integer(&json!(null)), None);
        assert_eq!(json_integer(&json!(u64::MAX)), None);
    }
}

#[cfg(test)]
mod service_tests {
    //! Route-level tests, transcribed from the JSS `forge/test.js` anchoring
    //! suite (enable, record tip, txo, caps, UI) against a real bare repo.
    use super::*;
    use bytes::Bytes;
    use tempfile::TempDir;

    fn git(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "git {args:?}");
    }

    fn commit(work: &Path, file: &str, text: &str) -> String {
        std::fs::write(work.join(file), text).unwrap();
        git(work, &["add", "-A"]);
        git(
            work,
            &[
                "-c",
                "user.email=t@e.st",
                "-c",
                "user.name=T",
                "commit",
                "-qm",
                "c",
            ],
        );
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(work)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    struct Fx {
        td: TempDir,
        svc: ForgeService,
        work: PathBuf,
        bare: PathBuf,
        tip0: String,
    }

    fn fx(cfg: ForgeConfig) -> Fx {
        let td = TempDir::new().unwrap();
        let svc = ForgeService::new(cfg, td.path()).unwrap();
        let work = td.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        let tip0 = commit(&work, "ledger.txt", "genesis\n");
        let bare = td.path().join("repos/casey/trail.git");
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        git(
            td.path(),
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        Fx {
            td,
            svc,
            work,
            bare,
            tip0,
        }
    }

    impl Fx {
        fn push(&self, branch: &str) {
            git(
                &self.work,
                &["push", "-q", self.bare.to_str().unwrap(), branch],
            );
        }
    }

    fn agent(name: &str) -> ForgeAgent {
        ForgeAgent::Pod {
            webid: format!("https://pod.example/{name}/profile/card#me"),
            username: name.into(),
        }
    }

    fn rq(method: &str, path: &str, body: &str) -> ForgeRequest {
        ForgeRequest {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: vec![("content-type".into(), "application/json".into())],
            raw_body: Bytes::from(body.to_string()),
            host_url: Some("https://forge.example".into()),
        }
    }

    async fn call(svc: &ForgeService, req: ForgeRequest, who: ForgeAgent) -> (u16, String) {
        let r = svc.handle(req, who).await.unwrap();
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    }

    const API: &str = "/forge/api/repos/casey/trail/marks";

    fn parse(body: &str) -> Value {
        serde_json::from_str(body).unwrap()
    }

    async fn list(f: &Fx) -> Value {
        parse(
            &call(&f.svc, rq("GET", API, ""), ForgeAgent::Anonymous)
                .await
                .1,
        )
    }

    async fn enable(f: &Fx) -> (u16, String) {
        call(
            &f.svc,
            rq("POST", &format!("{API}/enable"), "{}"),
            agent("casey"),
        )
        .await
    }

    #[tokio::test]
    async fn enable_authorisation_and_genesis() {
        let f = fx(ForgeConfig::default());
        let en = format!("{API}/enable");
        // anonymous 401, non-owner 403, and nothing was created
        assert_eq!(
            call(&f.svc, rq("POST", &en, "{}"), ForgeAgent::Anonymous)
                .await
                .0,
            401
        );
        assert_eq!(
            call(&f.svc, rq("POST", &en, "{}"), agent("rival")).await.0,
            403
        );
        let nostr = ForgeAgent::Nostr {
            pubkey_hex: "c".repeat(64),
        };
        assert_eq!(call(&f.svc, rq("POST", &en, "{}"), nostr).await.0, 403);
        assert!(!f.svc.trails().is_enabled("casey", "trail"));
        assert_eq!(list(&f).await, json!({"enabled": false, "chain": "tbtc4"}));

        let (s, b) = enable(&f).await;
        assert_eq!(s, 201);
        let v = parse(&b);
        assert_eq!(v["enabled"], true);
        assert_eq!(v["chain"], "tbtc4");
        let pk = v["pubkeyBase"].as_str().unwrap();
        assert!(pk.len() == 66 && (pk.starts_with("02") || pk.starts_with("03")));
        let m = &v["mark"];
        assert_eq!(m["index"], 0);
        assert_eq!(
            m["state"],
            json!({"commit": f.tip0, "repo": "casey/trail", "branch": "main"})
        );
        assert_eq!(
            m["stateHash"],
            sha256_hex(&format!(
                r#"{{"commit":"{}","repo":"casey/trail","branch":"main"}}"#,
                f.tip0
            ))
        );
        assert_eq!(m["status"], "pending");
        assert!(m["address"].as_str().unwrap().starts_with("tb1p"));
        assert!(!b.contains("privkey"));
        // enabling twice is a 409, not a key rotation; the collection alias too
        assert_eq!(enable(&f).await.0, 409);
        assert_eq!(
            call(&f.svc, rq("POST", API, "{}"), agent("casey")).await.0,
            409
        );
        // other methods and unknown tails are refused
        assert_eq!(
            call(&f.svc, rq("DELETE", API, ""), agent("casey")).await.0,
            405
        );
        assert_eq!(
            call(&f.svc, rq("GET", &en, ""), agent("casey")).await.0,
            405
        );
        assert_eq!(
            call(
                &f.svc,
                rq("GET", &format!("{API}/nope"), ""),
                agent("casey")
            )
            .await
            .0,
            404
        );
    }

    #[tokio::test]
    async fn enable_needs_a_commit_and_an_existing_repo() {
        let f = fx(ForgeConfig::default());
        let empty = f.td.path().join("repos/casey/empty.git");
        std::fs::create_dir_all(empty.parent().unwrap()).unwrap();
        git(
            f.td.path(),
            &[
                "init",
                "-q",
                "--bare",
                "-b",
                "main",
                empty.to_str().unwrap(),
            ],
        );
        let (s, _) = call(
            &f.svc,
            rq("POST", "/forge/api/repos/casey/empty/marks/enable", "{}"),
            agent("casey"),
        )
        .await;
        assert_eq!(s, 422, "anchoring needs a commit on the default branch");
        let (s, _) = call(
            &f.svc,
            rq("POST", "/forge/api/repos/casey/ghost/marks/enable", "{}"),
            agent("casey"),
        )
        .await;
        assert_eq!(s, 404);
        // hostile namespaces never touch the filesystem
        let (s, _) = call(
            &f.svc,
            rq("GET", "/forge/api/repos/../x/marks", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn push_to_the_default_branch_stacks_a_pending_mark() {
        let f = fx(ForgeConfig::default());
        enable(&f).await;

        // the push-completion hook (what h_git_smart calls after receive-pack)
        let tip1 = commit(&f.work, "ledger.txt", "entry 1\n");
        f.push("main");
        f.svc.record_pushed_tip("casey", "trail").await;
        let v = list(&f).await;
        let ms = v["marks"].as_array().unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[1]["state"]["commit"], tip1);
        assert_eq!(ms[1]["status"], "pending");
        assert_ne!(
            ms[1]["address"], ms[0]["address"],
            "each state derives a NEW address"
        );
        let t = f.svc.trails().load("casey", "trail").unwrap().unwrap();
        let states: Vec<_> = t.marks.iter().map(|m| m.state.clone()).collect();
        assert_eq!(
            derive_head(&t.pubkey_base, &t.chain, &states).unwrap().0,
            ms[1]["program"]
        );

        // a non-default-branch push does NOT advance the trail
        git(&f.work, &["checkout", "-q", "-b", "scratch"]);
        let side = commit(&f.work, "ledger.txt", "side note\n");
        f.push("scratch");
        f.svc.record_pushed_tip("casey", "trail").await;
        assert_eq!(
            f.svc
                .record_tip("casey", "trail", "scratch", &side)
                .await
                .unwrap(),
            TipOutcome::NotDefaultBranch
        );
        assert_eq!(list(&f).await["marks"].as_array().unwrap().len(), 2);

        // the public hook records the REAL tip, whatever hint the caller passes
        git(&f.work, &["checkout", "-q", "main"]);
        let tip2 = commit(&f.work, "ledger.txt", "entry 2\n");
        f.push("main");
        let out = f
            .svc
            .record_tip("casey", "trail", "main", &"9".repeat(40))
            .await
            .unwrap();
        assert_eq!(out, TipOutcome::Appended(2));
        let t = f.svc.trails().load("casey", "trail").unwrap().unwrap();
        assert_eq!(t.marks[2].state.commit, tip2);
        // malformed input is refused before git
        assert!(f
            .svc
            .record_tip("casey", "trail", "--upload-pack=x", &tip2)
            .await
            .is_err());
        assert!(f
            .svc
            .record_tip("casey", "trail", "main", "HEAD")
            .await
            .is_err());
        // a repo without a trail is a no-op
        assert_eq!(
            f.svc
                .record_tip("casey", "other", "main", &tip2)
                .await
                .unwrap(),
            TipOutcome::NotEnabled
        );
    }

    #[tokio::test]
    async fn txo_recording_rules() {
        let f = fx(ForgeConfig::default());
        enable(&f).await;
        commit(&f.work, "ledger.txt", "entry 1\n");
        f.push("main");
        f.svc.record_pushed_tip("casey", "trail").await;

        let good = json!({"txid": "f".repeat(64), "vout": 0, "amount": 1000});
        let post = |i: usize, body: Value, who: ForgeAgent| {
            let r = rq("POST", &format!("{API}/{i}/txo"), &body.to_string());
            let svc = f.svc.clone();
            async move { call(&svc, r, who).await }
        };
        assert_eq!(post(0, good.clone(), ForgeAgent::Anonymous).await.0, 401);
        assert_eq!(post(0, good.clone(), agent("rival")).await.0, 403);
        let c = agent("casey");
        let t = "f".repeat(64);
        for (what, body) in [
            (
                "txid shape",
                json!({"txid": "nothex", "vout": 0, "amount": 1000}),
            ),
            (
                "txid length",
                json!({"txid": "f".repeat(63), "vout": 0, "amount": 1000}),
            ),
            (
                "vout negative",
                json!({"txid": t, "vout": -1, "amount": 1000}),
            ),
            (
                "vout fractional",
                json!({"txid": t, "vout": 0.5, "amount": 1000}),
            ),
            (
                "vout range",
                json!({"txid": t, "vout": 0x8000_0000_u64, "amount": 1000}),
            ),
            (
                "vout string",
                json!({"txid": t, "vout": "0", "amount": 1000}),
            ),
            ("amount zero", json!({"txid": t, "vout": 0, "amount": 0})),
            (
                "amount negative",
                json!({"txid": t, "vout": 0, "amount": -5}),
            ),
            (
                "amount over cap",
                json!({"txid": t, "vout": 0, "amount": SATS_CAP + 1}),
            ),
            (
                "amount fractional",
                json!({"txid": t, "vout": 0, "amount": 1.5}),
            ),
            ("amount missing", json!({"txid": t, "vout": 0})),
        ] {
            assert_eq!(post(0, body, c.clone()).await.0, 422, "{what}");
        }
        let bad_json = call(
            &f.svc,
            rq("POST", &format!("{API}/0/txo"), "{nope"),
            c.clone(),
        )
        .await;
        assert_eq!(bad_json.0, 400);
        assert_eq!(
            post(1, good.clone(), c.clone()).await.0,
            409,
            "marks are recorded in order"
        );
        assert_eq!(
            post(9, good.clone(), c.clone()).await.0,
            404,
            "no such mark"
        );
        let lead0 = call(
            &f.svc,
            rq("POST", &format!("{API}/01/txo"), &good.to_string()),
            c.clone(),
        )
        .await;
        assert_eq!(lead0.0, 404, "leading-zero index is not a mark route");
        assert_eq!(
            list(&f).await["marks"][0]["status"],
            "pending",
            "nothing was recorded"
        );

        // the amount cap itself is accepted; an uppercase txid is lowercased
        let capped = json!({"txid": "AB".repeat(32), "vout": 7, "amount": SATS_CAP});
        let (s, b) = post(0, capped, c.clone()).await;
        assert_eq!(s, 200);
        assert_eq!(
            parse(&b),
            json!({"index": 0, "status": "marked", "txid": "ab".repeat(32), "vout": 7, "amount": SATS_CAP})
        );
        // twice is a 409: a mark is one spend
        assert_eq!(post(0, good.clone(), c.clone()).await.0, 409);
        assert_eq!(post(1, good, c).await.0, 200);
    }

    #[tokio::test]
    async fn form_posts_redirect_back_to_the_page() {
        let f = fx(ForgeConfig::default());
        let form = |path: &str, body: &str| {
            let mut r = rq("POST", path, body);
            r.headers = vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )];
            r
        };
        let r = f
            .svc
            .handle(form(&format!("{API}/enable"), ""), agent("casey"))
            .await
            .unwrap();
        assert_eq!(r.status, 303);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "location" && v == "/forge/casey/trail/marks"));
        let body = format!("txid={}&vout=1&amount=500", "a".repeat(64));
        let r = f
            .svc
            .handle(form(&format!("{API}/0/txo"), &body), agent("casey"))
            .await
            .unwrap();
        assert_eq!(r.status, 303);
        let t = f.svc.trails().load("casey", "trail").unwrap().unwrap();
        assert_eq!((t.marks[0].vout, t.marks[0].amount), (Some(1), Some(500)));
        // and a form post by a non-owner is still refused
        let r = f
            .svc
            .handle(form(&format!("{API}/0/txo"), &body), agent("rival"))
            .await
            .unwrap();
        assert_eq!(r.status, 403);
    }

    #[tokio::test]
    async fn blocktrails_json_pages_and_no_key_on_any_surface() {
        let f = fx(ForgeConfig::default());
        let hdr = |r: &ForgeResponse, k: &str| {
            r.headers
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        // not enabled: honest 404 with CORS
        let off = f
            .svc
            .handle(
                rq("GET", "/forge/casey/trail/blocktrails.json", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert_eq!(off.status, 404);
        assert_eq!(
            hdr(&off, "access-control-allow-origin").as_deref(),
            Some("*")
        );

        enable(&f).await;
        commit(&f.work, "ledger.txt", "entry 1\n");
        f.push("main");
        f.svc.record_pushed_tip("casey", "trail").await;
        let txid = "d".repeat(64);
        let body = json!({"txid": txid, "vout": 0, "amount": 250_000}).to_string();
        call(
            &f.svc,
            rq("POST", &format!("{API}/0/txo"), &body),
            agent("casey"),
        )
        .await;

        let res = f
            .svc
            .handle(
                rq("GET", "/forge/casey/trail/blocktrails.json", ""),
                ForgeAgent::Anonymous,
            )
            .await
            .unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(
            hdr(&res, "access-control-allow-origin").as_deref(),
            Some("*")
        );
        assert!(hdr(&res, "content-type")
            .unwrap()
            .starts_with("application/json"));
        let doc: Value = serde_json::from_slice(&res.body).unwrap();
        assert_eq!(doc["@type"], "Blocktrail");
        assert_eq!(doc["states"], json!([f.tip0]));
        assert_eq!(doc["txo"].as_array().unwrap().len(), 1);
        assert_eq!(
            doc["marks"].as_array().unwrap().len(),
            2,
            "pendings ride additively"
        );

        // the key exists on disk but crosses no API surface
        let file = f.td.path().join("marks/casey/trail.json");
        let on_disk: Value = parse(&std::fs::read_to_string(file).unwrap());
        let key = on_disk["privkey"].as_str().unwrap().to_string();
        for url in [
            API,
            "/forge/casey/trail/blocktrails.json",
            "/forge/casey/trail/marks",
            "/forge/casey/trail",
        ] {
            let (_, text) = call(&f.svc, rq("GET", url, ""), agent("casey")).await;
            assert!(!text.contains(&key), "{url} leaks the trail key");
            if url.ends_with(".json") || url == API {
                assert!(!text.contains("privkey"), "{url} mentions privkey");
            }
        }

        // the page: chips, frontier, verifier hand-off, the first pending address
        let (s, html) = call(
            &f.svc,
            rq("GET", "/forge/casey/trail/marks", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(s, 200);
        assert!(html.contains("chip-marked") && html.contains("chip-pending"));
        assert!(html.contains(&format!("https://mempool.space/testnet4/tx/{txid}")));
        let trail_url = "https://forge.example/forge/casey/trail/blocktrails.json";
        assert!(html.contains(&crate::marks_ui::uri_component(trail_url)));
        assert!(html.contains("250,000 <span class=\"unit\">sat</span>"));
        let t = f.svc.trails().load("casey", "trail").unwrap().unwrap();
        assert!(html.contains(&t.marks[1].address));
        // the Anchors tab is on the enabled repo
        let (_, home) = call(
            &f.svc,
            rq("GET", "/forge/casey/trail", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert!(
            home.contains("href=\"/forge/casey/trail/marks\">Anchors</a>"),
            "Anchors tab when enabled"
        );
        // the JSON surfaces were not decorated
        assert!(!call(&f.svc, rq("GET", API, ""), ForgeAgent::Anonymous)
            .await
            .1
            .contains("Anchors"));
    }

    #[tokio::test]
    async fn anchoring_ui_shows_the_tab_and_the_pitch_everywhere() {
        // Transcribed from 'forge anchoringUi' and 'a not-enabled repo's marks page'.
        let off = fx(ForgeConfig::default());
        let (_, home) = call(
            &off.svc,
            rq("GET", "/forge/casey/trail", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert!(
            !home.contains("/forge/casey/trail/marks\""),
            "no Anchors tab when not enabled"
        );

        let on = fx(ForgeConfig {
            anchoring_ui: true,
            ..Default::default()
        });
        let (_, home) = call(
            &on.svc,
            rq("GET", "/forge/casey/trail", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert!(home.contains("class=\"tab\" href=\"/forge/casey/trail/marks\">Anchors</a>"));
        let (s, pitch) = call(
            &on.svc,
            rq("GET", "/forge/casey/trail/marks", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(s, 200);
        assert!(pitch.contains("Anchoring is not enabled"));
        assert!(pitch.contains("id=\"do-enable\""));
        let (s, _) = call(
            &on.svc,
            rq("GET", "/forge/casey/missing/marks", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(s, 404);
    }

    #[tokio::test]
    async fn a_repo_held_trail_shows_its_page_and_tab() {
        let f = fx(ForgeConfig::default());
        let (c0, c1) = ("1".repeat(40), "2".repeat(40));
        let doc = json!({
            "@type": "Blocktrail", "version": "0.0.3", "profile": "gitmark",
            "pubkeyBase": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            "chain": "txbt4", "states": [c0, c1],
            "txo": [format!("txo:txbt4:{}:0?amount=9700&commit={c0}", "ab".repeat(32))],
        });
        commit(&f.work, "blocktrails.json", &doc.to_string());
        f.push("main");
        let (s, html) = call(
            &f.svc,
            rq("GET", "/forge/casey/trail/marks", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(s, 200);
        assert!(html.contains("repo-held"));
        // addresses re-derived (vector of gitmark.rs, from JSS `trailAddress`)
        assert!(html.contains("tb1p786w9g3gn7lm4ch46y8g542dwaayfjta64vnmd7lj3av79qc2v4sf843nu"));
        assert!(html.contains("https://mempool.guide/testnet4/tx/"));
        let (_, home) = call(
            &f.svc,
            rq("GET", "/forge/casey/trail", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert!(home.contains("/forge/casey/trail/marks\">Anchors</a>"));
        let (_, bt) = call(
            &f.svc,
            rq("GET", "/forge/casey/trail/blocktrails.json", ""),
            ForgeAgent::Anonymous,
        )
        .await;
        assert_eq!(parse(&bt)["profile"], "gitmark");
    }

    #[test]
    fn mainnet_and_unknown_chains_refuse_to_build_the_service() {
        // Transcribed from 'a mainnet chain without allowMainnet refuses to activate'.
        for chain in ["btc", "mainnet", "bitcoin", "xbt"] {
            let td = TempDir::new().unwrap();
            let cfg = ForgeConfig {
                default_chain: chain.into(),
                ..Default::default()
            };
            let e = ForgeService::new(cfg, td.path()).unwrap_err().to_string();
            assert!(
                e.contains("MAINNET") && e.contains("allow_mainnet"),
                "{chain}: {e}"
            );
            assert!(
                !td.path().join("repos").exists(),
                "refused before anything was created"
            );
        }
        let td = TempDir::new().unwrap();
        let cfg = ForgeConfig {
            default_chain: "dogecoin".into(),
            ..Default::default()
        };
        assert!(ForgeService::new(cfg, td.path())
            .unwrap_err()
            .to_string()
            .contains("unknown config.chain"));
        let cfg = ForgeConfig {
            default_chain: "btc".into(),
            allow_mainnet: true,
            ..Default::default()
        };
        assert!(ForgeService::new(cfg, td.path()).is_ok());
    }

    #[tokio::test]
    async fn the_forge_trail_source_feeds_nip34_anchor_facts() {
        let f = fx(ForgeConfig::default());
        let src: &dyn ForgeTrailSource = &f.svc;
        assert!(!src.has_forge_trail("casey", "trail"));
        enable(&f).await;
        assert!(src.has_forge_trail("casey", "trail"));
        assert!(
            src.anchor_facts("casey", "trail", "u").is_none(),
            "nothing on-chain yet"
        );
        let txid = "c".repeat(64);
        let body = json!({"txid": txid, "vout": 2, "amount": 9}).to_string();
        call(
            &f.svc,
            rq("POST", &format!("{API}/0/txo"), &body),
            agent("casey"),
        )
        .await;
        let facts = src
            .anchor_facts("casey", "trail", "https://f/x/blocktrails.json")
            .unwrap();
        assert_eq!(facts.genesis_txid, txid);
        assert_eq!(facts.frontier_vout, 2);
        assert_eq!(facts.frontier_commit, f.tip0);
        let tags = crate::gitmark::anchor_tags(&facts);
        assert_eq!(tags[1], ["anchor", "tbtc4", txid.as_str()]);
    }
}
