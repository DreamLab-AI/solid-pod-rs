//! Blocktrails trails as a verifier reads them.
//!
//! A *trail* is an ordered list of states, each committed to by one *mark*: a
//! Bitcoin output whose key is the trail's base key tweaked by every state so
//! far (Blocktrails Core, "the rule as it is", blocktrails/spec ef54a08). The
//! marks spend one another in order, so the trail is *anchored*: each state is
//! timestamped by the block that confirms its mark, and nobody can rewrite the
//! history without spending a mark again.
//!
//! This module holds three things:
//!
//! - [`Blocktrail`]: the `blocktrails.json` shape, as the git-mark profile
//!   (blocktrails/spec, profiles/gitmark §5.2) and blocktrails/git-mark
//!   b852d7d `trail()` write it: `@type`, `version`, `profile`, `pubkeyBase`,
//!   `chain`, `states`, and `txo`, a list of TXO URIs. It also reads the
//!   earlier shape this crate wrote (`@id`, `genesis` and `txo` entries of the
//!   form `{outpoint, blockheight}`), and writes such entries back unchanged,
//!   so no file already on disk is rewritten.
//! - [`BlocktrailTxo`]: one TXO URI,
//!   `txo:<chain>:<txid>:<vout>?amount=<sats>&commit=<hash>[&pubkey=<x>]`,
//!   parsed and formatted as blocktrails/git-mark `parseTxoUri` /
//!   `formatTxoUri` do.
//! - With feature `mrc20`, the per-link verification blocktrails/verify
//!   043e7af runs: every mark's output key is recomputed from the base key and
//!   the states (`walk_blocktrail`); then each mark's transaction must
//!   exist, carry the recomputed key, be confirmed, match its recorded amount
//!   and spend the previous mark (`verify_blocktrail`). The verdict is
//!   *verified* when every commitment was checked and holds, *confirmed* when
//!   the marks are on-chain but the commitments could not be checked (no base
//!   key, say), and *partial* otherwise. `verify_anchor_chain` runs the same
//!   checks from a single head outpoint backwards, for trails that keep only
//!   their head (the MRC20 trails this crate issues).
//!
//! Every link is checked, not the head alone. A head UTXO at the derived
//! address shows only that someone paid that key; it says nothing about the
//! marks before it, which could be missing, pay other keys, or not be spent in
//! order. Only the walk shows that each state was committed, and timestamped,
//! when its mark was made.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::provenance::ProvenanceError;

/// The `@type` every trail carries.
pub const BLOCKTRAIL_TYPE: &str = "Blocktrail";
/// The `version` blocktrails/git-mark b852d7d writes in `blocktrails.json`.
pub const BLOCKTRAIL_VERSION: &str = "0.0.3";
/// The git-mark profile: each state is a git commit hash, hashed as its text.
pub const GITMARK_PROFILE: &str = "gitmark";
/// The profile a trail with no `profile` is read as (blocktrails/verify).
pub const DEFAULT_PROFILE: &str = "monochrome";
/// The network name whose addresses use the `gm` human-readable part: the
/// sidestr git-mark chain (`NETWORK_CHAIN.gitmark = 'sidestr:gitmark'` in
/// blocktrails/git-mark b852d7d).
pub const GITMARK_NETWORK: &str = "gitmark";

// ---------------------------------------------------------------------------
// Chain names
// ---------------------------------------------------------------------------

/// The chain token a TXO URI uses for one of this crate's network names.
///
/// This crate names networks as the mempool explorers do (`testnet4`,
/// `mainnet`); TXO URIs and `blocktrails.json` use blocktrails/git-mark's
/// tokens (`tbtc4`, `mainnet`, `signet`, `regtest`, `gitmark`). A name with no
/// mapping is returned as it is.
///
/// # Examples
///
/// ```
/// use solid_pod_rs::blocktrail::txo_chain_for_network;
///
/// assert_eq!(txo_chain_for_network("testnet4"), "tbtc4");
/// assert_eq!(txo_chain_for_network("mainnet"), "mainnet");
/// assert_eq!(txo_chain_for_network("gitmark"), "gitmark");
/// ```
#[must_use]
pub fn txo_chain_for_network(network: &str) -> String {
    match network {
        "testnet4" => "tbtc4".into(),
        "testnet" | "testnet3" => "tbtc3".into(),
        "bitcoin" | "btc" => "mainnet".into(),
        other => other.into(),
    }
}

/// The network name (as `mrc20::bt_address` takes it) for a TXO URI
/// chain token; the inverse of [`txo_chain_for_network`].
///
/// blocktrails/verify reads `tbtc4` as testnet4, `tbtc3` and `tbtc` as the
/// earlier testnet, and `btc`, `bitcoin` and `mainnet` as mainnet.
///
/// # Examples
///
/// ```
/// use solid_pod_rs::blocktrail::network_for_txo_chain;
///
/// assert_eq!(network_for_txo_chain("tbtc4"), "testnet4");
/// assert_eq!(network_for_txo_chain("btc"), "mainnet");
/// assert_eq!(network_for_txo_chain("gitmark"), "gitmark");
/// ```
#[must_use]
pub fn network_for_txo_chain(chain: &str) -> String {
    match chain {
        "tbtc4" => "testnet4".into(),
        "tbtc3" | "tbtc" => "testnet".into(),
        "btc" | "bitcoin" => "mainnet".into(),
        other => other.into(),
    }
}

/// Whether `commit` is a git commit hash a git-mark trail accepts as a state:
/// 40 lowercase hex characters (blocktrails/git-mark `validateCommitHash`),
/// or 64 for a repository using SHA-256 object names (and for an epoch Merkle
/// root this crate anchors in a commit's place).
///
/// # Examples
///
/// ```
/// use solid_pod_rs::blocktrail::is_gitmark_commit;
///
/// assert!(is_gitmark_commit("9adc596cfd1100333393a12f2f41b2d820f16d0b"));
/// assert!(!is_gitmark_commit("9ADC596CFD1100333393A12F2F41B2D820F16D0B"));
/// assert!(!is_gitmark_commit("9adc596c"));
/// ```
#[must_use]
pub fn is_gitmark_commit(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64)
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// TXO URIs
// ---------------------------------------------------------------------------

/// A TXO URI that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxoUriError(pub String);

impl fmt::Display for TxoUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid TXO URI: {}", self.0)
    }
}

impl std::error::Error for TxoUriError {}

/// One mark of a trail: the output that commits to a state.
///
/// Written as a TXO URI,
/// `txo:<chain>:<txid>:<vout>?amount=<sats>&commit=<hash>[&pubkey=<x>]`
/// (blocktrails/spec gitmark profile §3; blocktrails/git-mark b852d7d
/// `formatTxoUri`, which writes `amount`, then `pubkey`, then `commit`, each
/// only when it is set). `chain` is `None` only for an entry read from the
/// earlier `{outpoint, blockheight}` form, which carries no chain and is
/// written back in that form.
///
/// # Examples
///
/// ```
/// use solid_pod_rs::blocktrail::BlocktrailTxo;
///
/// let uri = "txo:tbtc4:51d87101b7cbb01cc5a68785bf3141ec6fd00894d71ab1168d4daa20420eeacf:0\
///            ?amount=999700&commit=9adc596cfd1100333393a12f2f41b2d820f16d0b";
/// let txo: BlocktrailTxo = uri.parse().unwrap();
/// assert_eq!(txo.chain.as_deref(), Some("tbtc4"));
/// assert_eq!(txo.vout, 0);
/// assert_eq!(txo.amount, Some(999_700));
/// assert_eq!(txo.to_string(), uri);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocktrailTxo {
    /// The chain token (`tbtc4`, `mainnet`, `gitmark`, …); `None` for an entry
    /// in the earlier `{outpoint, blockheight}` form.
    pub chain: Option<String>,
    /// The transaction id, 64 hex characters.
    pub txid: String,
    /// The output index within `txid`.
    pub vout: u32,
    /// The output's value in sats, when recorded.
    pub amount: Option<u64>,
    /// The state this mark commits to, for a git-mark trail its commit hash.
    pub commit: Option<String>,
    /// The output's x-only key (64 hex), when recorded. A verifier recomputes
    /// it from the base key and the states, so it is optional.
    pub pubkey: Option<String>,
    /// The confirmation height, kept only by the earlier entry form; a TXO URI
    /// carries no height (a verifier reads it from the chain).
    pub blockheight: Option<u64>,
}

impl BlocktrailTxo {
    /// A mark at `txid:vout` on `chain`, with nothing else recorded.
    #[must_use]
    pub fn new(chain: impl Into<String>, txid: impl Into<String>, vout: u32) -> Self {
        Self {
            chain: Some(chain.into()),
            txid: txid.into(),
            vout,
            amount: None,
            commit: None,
            pubkey: None,
            blockheight: None,
        }
    }

    /// This mark with its output value recorded.
    #[must_use]
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// This mark with the state it commits to recorded (`commit=`).
    #[must_use]
    pub fn with_commit(mut self, commit: impl Into<String>) -> Self {
        self.commit = Some(commit.into());
        self
    }

    /// `<txid>:<vout>`.
    #[must_use]
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    /// Whether this entry was read from the earlier `{outpoint, blockheight}`
    /// form (it has no chain).
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.chain.is_none()
    }

    /// The TXO URI, or `None` for an entry with no chain.
    #[must_use]
    pub fn to_uri(&self) -> Option<String> {
        let chain = self.chain.as_deref()?;
        let mut uri = format!("txo:{chain}:{}:{}", self.txid, self.vout);
        let mut params = Vec::new();
        if let Some(a) = self.amount {
            params.push(format!("amount={a}"));
        }
        if let Some(p) = self.pubkey.as_deref().filter(|p| !p.is_empty()) {
            params.push(format!("pubkey={p}"));
        }
        if let Some(c) = self.commit.as_deref().filter(|c| !c.is_empty()) {
            params.push(format!("commit={c}"));
        }
        if !params.is_empty() {
            uri.push('?');
            uri.push_str(&params.join("&"));
        }
        Some(uri)
    }

    /// Parse a TXO URI.
    ///
    /// The chain is letters and digits and the txid 64 hex characters, as
    /// blocktrails/verify requires; the vout a non-negative integer. Query
    /// parameters are read as blocktrails/git-mark reads them: `amount` as an
    /// integer, `commit` and `pubkey` as given (percent-decoded), an empty
    /// value as absent; any other parameter is ignored.
    ///
    /// # Errors
    ///
    /// [`TxoUriError`] for a URI that does not start with `txo:`, lacks the
    /// chain, txid or vout, or has a malformed one of them or of `amount`.
    pub fn parse_uri(uri: &str) -> Result<Self, TxoUriError> {
        let body = uri
            .strip_prefix("txo:")
            .ok_or_else(|| TxoUriError("must start with txo:".into()))?;
        let (path, query) = match body.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (body, None),
        };
        let mut parts = path.split(':');
        let (Some(chain), Some(txid), Some(vout), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TxoUriError("expected txo:<chain>:<txid>:<vout>".into()));
        };
        if chain.is_empty() || !chain.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(TxoUriError(format!("bad chain {chain:?}")));
        }
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TxoUriError("the txid must be 64 hex characters".into()));
        }
        if vout.is_empty() || !vout.bytes().all(|b| b.is_ascii_digit()) {
            return Err(TxoUriError(format!("bad vout {vout:?}")));
        }
        let vout: u32 = vout
            .parse()
            .map_err(|_| TxoUriError(format!("vout {vout} out of range")))?;

        let mut txo = Self::new(chain, txid, vout);
        for pair in query.unwrap_or_default().split('&') {
            let Some((key, raw)) = pair.split_once('=') else {
                continue;
            };
            let value = percent_decode(raw)?;
            if value.is_empty() {
                continue;
            }
            match key {
                "amount" => {
                    txo.amount = Some(
                        value
                            .parse()
                            .map_err(|_| TxoUriError(format!("bad amount {value:?}")))?,
                    );
                }
                "commit" => txo.commit = Some(value),
                "pubkey" => txo.pubkey = Some(value),
                _ => {}
            }
        }
        Ok(txo)
    }

    fn from_legacy(outpoint: &str, blockheight: Option<u64>) -> Result<Self, TxoUriError> {
        let (txid, vout) = outpoint
            .rsplit_once(':')
            .ok_or_else(|| TxoUriError(format!("outpoint {outpoint:?} is not <txid>:<vout>")))?;
        let vout = vout
            .parse()
            .map_err(|_| TxoUriError(format!("bad vout in outpoint {outpoint:?}")))?;
        Ok(Self {
            chain: None,
            txid: txid.to_string(),
            vout,
            amount: None,
            commit: None,
            pubkey: None,
            blockheight,
        })
    }
}

/// `%XX` decoding of a query value (what `decodeURIComponent` does for the
/// ASCII values a TXO URI carries).
fn percent_decode(raw: &str) -> Result<String, TxoUriError> {
    if !raw.contains('%') {
        return Ok(raw.to_string());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| TxoUriError(format!("bad percent escape in {raw:?}")))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| TxoUriError(format!("{raw:?} is not UTF-8")))
}

impl FromStr for BlocktrailTxo {
    type Err = TxoUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_uri(s)
    }
}

impl fmt::Display for BlocktrailTxo {
    /// The TXO URI, or `<txid>:<vout>` for an entry with no chain.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_uri() {
            Some(uri) => f.write_str(&uri),
            None => f.write_str(&self.outpoint()),
        }
    }
}

#[derive(Serialize)]
struct LegacyTxoOut<'a> {
    outpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blockheight: &'a Option<u64>,
}

#[derive(Deserialize)]
struct LegacyTxoIn {
    outpoint: String,
    #[serde(default)]
    blockheight: Option<u64>,
}

impl Serialize for BlocktrailTxo {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.to_uri() {
            Some(uri) => s.serialize_str(&uri),
            None => LegacyTxoOut {
                outpoint: self.outpoint(),
                blockheight: &self.blockheight,
            }
            .serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for BlocktrailTxo {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Value::deserialize(d)? {
            Value::String(uri) => Self::parse_uri(&uri).map_err(D::Error::custom),
            obj @ Value::Object(_) => {
                let legacy: LegacyTxoIn = serde_json::from_value(obj).map_err(D::Error::custom)?;
                Self::from_legacy(&legacy.outpoint, legacy.blockheight).map_err(D::Error::custom)
            }
            other => Err(D::Error::custom(format!(
                "a txo entry is a TXO URI or {{outpoint, blockheight}}, not {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// blocktrails.json
// ---------------------------------------------------------------------------

/// A trail as `blocktrails.json` carries it: what a verifier reads.
///
/// The shape is blocktrails/spec gitmark profile §5.2, the one the live trails
/// use and blocktrails/git-mark b852d7d `trail()` writes:
///
/// ```json
/// {
///   "@type": "Blocktrail",
///   "version": "0.0.3",
///   "profile": "gitmark",
///   "pubkeyBase": "02…",
///   "chain": "tbtc4",
///   "states": ["<genesis_commit>", "<hash>"],
///   "txo": ["txo:tbtc4:…:0?amount=…&commit=…", "txo:tbtc4:…"]
/// }
/// ```
///
/// `pubkeyBase` is the base key as a full compressed point (02/03 + x), so a
/// verifier has nothing to guess. `states` holds one state per mark, in order:
/// a string state (a git-mark commit) is hashed as its text, an object state
/// as its JCS. A git-mark trail may leave `states` empty; the commits are then
/// read from the TXO URIs.
///
/// The earlier shape this crate wrote, with `@id`, `genesis` and `txo`
/// entries `{outpoint, blockheight}` and no base key, still parses: its
/// fields are kept in [`id`](Self::id) and [`genesis`](Self::genesis) and its
/// entries as legacy [`BlocktrailTxo`]s, and it serialises back as it was
/// read. A trail built here ([`Blocktrail::gitmark`]) has neither field.
///
/// # Examples
///
/// ```
/// use solid_pod_rs::blocktrail::{Blocktrail, BlocktrailTxo};
///
/// let commit = "9adc596cfd1100333393a12f2f41b2d820f16d0b";
/// let txid = "51d87101b7cbb01cc5a68785bf3141ec6fd00894d71ab1168d4daa20420eeacf";
/// let trail = Blocktrail::gitmark(
///     "0273c7f6cf0f135a63bc95a2e676bcf0a592c8b508fae8697e43f778c74e232b24",
///     "tbtc4",
///     vec![commit.to_string()],
///     vec![BlocktrailTxo::new("tbtc4", txid, 0).with_amount(999_700).with_commit(commit)],
/// );
/// let json: serde_json::Value = serde_json::from_str(&trail.to_blocktrails_json().unwrap()).unwrap();
/// assert_eq!(json["@type"], "Blocktrail");
/// assert_eq!(json["profile"], "gitmark");
/// assert_eq!(json["txo"][0], format!("txo:tbtc4:{txid}:0?amount=999700&commit={commit}"));
/// assert!(json.get("@id").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocktrail {
    /// The earlier shape's `@id` (`gitmark:<first-commit>:0`); `None` in the
    /// §5.2 shape.
    #[serde(rename = "@id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Always [`BLOCKTRAIL_TYPE`].
    #[serde(rename = "@type")]
    pub type_: String,
    /// The schema version ([`BLOCKTRAIL_VERSION`] for a trail built here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The profile (`gitmark`, or a plain profile id); a trail with none is
    /// read as [`DEFAULT_PROFILE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The base key as a full compressed point (02/03 + x).
    #[serde(
        rename = "pubkeyBase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pubkey_base: Option<String>,
    /// The chain token the marks live on (`tbtc4`, `mainnet`, `gitmark`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// The earlier shape's `genesis` (`gitmark:<first-commit>:0`); `None` in
    /// the §5.2 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<String>,
    /// One state per mark, in order.
    #[serde(default)]
    pub states: Vec<Value>,
    /// The marks, in order.
    #[serde(default)]
    pub txo: Vec<BlocktrailTxo>,
}

impl Blocktrail {
    /// A git-mark trail in the §5.2 shape: `pubkey_base` as a full compressed
    /// point, the marks on `chain`, the commits as its states.
    #[must_use]
    pub fn gitmark(
        pubkey_base: impl Into<String>,
        chain: impl Into<String>,
        commits: Vec<String>,
        txo: Vec<BlocktrailTxo>,
    ) -> Self {
        Self {
            id: None,
            type_: BLOCKTRAIL_TYPE.to_string(),
            version: Some(BLOCKTRAIL_VERSION.to_string()),
            profile: Some(GITMARK_PROFILE.to_string()),
            pubkey_base: Some(pubkey_base.into()),
            chain: Some(chain.into()),
            genesis: None,
            states: commits.into_iter().map(Value::String).collect(),
            txo,
        }
    }

    /// The profile, lower-cased, or [`DEFAULT_PROFILE`] when none is set (as
    /// blocktrails/verify reads it).
    #[must_use]
    pub fn profile_name(&self) -> String {
        self.profile
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or(DEFAULT_PROFILE)
            .to_lowercase()
    }

    /// Whether this is a git-mark trail.
    #[must_use]
    pub fn is_gitmark(&self) -> bool {
        self.profile_name() == GITMARK_PROFILE
    }

    /// Whether the trail carries anything of the earlier shape (`@id`,
    /// `genesis`, or a `{outpoint, blockheight}` entry).
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.id.is_some() || self.genesis.is_some() || self.txo.iter().any(|t| t.is_legacy())
    }

    /// The states, one per mark, as the strings that are hashed: a string
    /// state as its text, an object state as its JCS
    /// ([`crate::mrc20::bt_state_string`]). A git-mark trail with no states
    /// takes them from its TXO URIs' `commit`s, as blocktrails/verify does.
    ///
    /// # Errors
    ///
    /// The message blocktrails/verify gives: `the trail has M marks and S
    /// states` when the counts differ, `mark i has no state` for a null state.
    pub fn state_strings(&self) -> Result<Vec<String>, String> {
        let from_txo: Vec<Value>;
        let states: &[Value] = if self.states.is_empty() && self.is_gitmark() {
            from_txo = self
                .txo
                .iter()
                .map(|t| t.commit.clone().map_or(Value::Null, Value::String))
                .collect();
            &from_txo
        } else {
            &self.states
        };
        if states.len() != self.txo.len() {
            return Err(format!(
                "the trail has {} marks and {} states",
                self.txo.len(),
                states.len()
            ));
        }
        states
            .iter()
            .enumerate()
            .map(|(i, s)| match s {
                Value::Null => Err(format!("mark {i} has no state")),
                other => Ok(crate::mrc20::bt_state_string(other)),
            })
            .collect()
    }

    /// Serialise to `blocktrails.json` text (pretty-printed).
    ///
    /// # Errors
    ///
    /// [`ProvenanceError::Store`] if serialisation fails.
    pub fn to_blocktrails_json(&self) -> Result<String, ProvenanceError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ProvenanceError::Store(format!("blocktrails.json serialise: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Verification reports
// ---------------------------------------------------------------------------

/// What a verifier found for one mark.
///
/// [`as_str`](Self::as_str) gives blocktrails/verify's label for each outcome
/// it has; [`BrokenLink`](Self::BrokenLink) is this crate's addition (see
/// there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkStatus {
    /// Confirmed, the amount matches, and the output is the recomputed key.
    Verified,
    /// Confirmed and the amount matches, but the commitment was not checked
    /// (the trail could not be walked, or the output could not be read).
    Confirmed,
    /// The output is not the key the states derive: the mark does not commit
    /// to its state.
    WrongKey,
    /// Confirmed, but the output does not carry the amount the trail records.
    AmountMismatch,
    /// In the mempool, not yet in a block.
    Unconfirmed,
    /// The transaction is not on the chain (or could not be reached).
    NotFound,
    /// The mark does not spend the previous mark. blocktrails/verify 043e7af
    /// shows this ("chain link ✗") but still labels such a mark verified; this
    /// crate counts it as a failure, since its README states that a verified
    /// trail has its mark chain intact.
    BrokenLink,
}

impl MarkStatus {
    /// blocktrails/verify's label (`verified`, `confirmed`, `wrong key`,
    /// `amount mismatch`, `unconfirmed`, `not found`), or `broken link`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Confirmed => "confirmed",
            Self::WrongKey => "wrong key",
            Self::AmountMismatch => "amount mismatch",
            Self::Unconfirmed => "unconfirmed",
            Self::NotFound => "not found",
            Self::BrokenLink => "broken link",
        }
    }

    /// Counted as good: [`Verified`](Self::Verified) or
    /// [`Confirmed`](Self::Confirmed).
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Verified | Self::Confirmed)
    }

    /// Counted as pending: [`Unconfirmed`](Self::Unconfirmed).
    #[must_use]
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Unconfirmed)
    }

    /// Counted as a failure: every other status.
    #[must_use]
    pub fn is_bad(self) -> bool {
        !self.is_ok() && !self.is_pending()
    }
}

impl fmt::Display for MarkStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The summary verdict over a whole trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrailVerdict {
    /// Every mark is confirmed with its amount, and every output is the key
    /// its state derives.
    Verified,
    /// Every mark is confirmed with its amount, but the commitments were not
    /// checked (the trail could not be walked): confirmation only.
    Confirmed,
    /// Anything less: some mark is pending, failed, or unchecked.
    Partial,
}

impl TrailVerdict {
    /// `verified`, `confirmed` or `partial`, blocktrails/verify's summary pill.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Confirmed => "confirmed",
            Self::Partial => "partial",
        }
    }
}

impl fmt::Display for TrailVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a verifier found for one mark, with the evidence behind its status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkReport {
    /// The mark's position in the trail (0 is the genesis mark).
    pub index: usize,
    /// The mark's transaction id; empty when a backward walk could not reach
    /// this mark.
    pub txid: String,
    /// The mark's output index.
    pub vout: u32,
    /// The outcome.
    pub status: MarkStatus,
    /// Whether the transaction is in a block.
    pub confirmed: bool,
    /// The confirming block's height, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    /// The output's value on-chain, when the output was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// The amount the trail records for the mark, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Whether the output is the recomputed key: `None` when the commitment
    /// was not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<bool>,
    /// Whether the transaction spends the previous mark: `None` for the
    /// genesis mark and for a mark not found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links_to_prev: Option<bool>,
    /// The recomputed x-only output key (64 hex), when the trail was walked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_output: Option<String>,
}

/// The result of verifying a trail: one [`MarkReport`] per mark and a
/// [`TrailVerdict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrailReport {
    /// Per-mark results, in trail order.
    pub marks: Vec<MarkReport>,
    /// Whether the output keys were recomputed (the trail could be walked).
    pub commitments_checked: bool,
    /// Why the commitments could not be checked, when they were not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_error: Option<String>,
    /// The summary verdict.
    pub verdict: TrailVerdict,
}

impl TrailReport {
    #[cfg_attr(not(feature = "mrc20"), allow(dead_code))]
    fn new(marks: Vec<MarkReport>, walk_error: Option<String>) -> Self {
        let commitments_checked = walk_error.is_none();
        let n = marks.len();
        let ok = marks.iter().filter(|m| m.status.is_ok()).count();
        let commit_ok = marks.iter().filter(|m| m.commits == Some(true)).count();
        // blocktrails/verify: allOK = okCount === n && (!walked || commitOK === n).
        // An empty trail verifies nothing, so it is never more than partial.
        let verdict = if n > 0 && ok == n && (!commitments_checked || commit_ok == n) {
            if commitments_checked {
                TrailVerdict::Verified
            } else {
                TrailVerdict::Confirmed
            }
        } else {
            TrailVerdict::Partial
        };
        Self {
            marks,
            commitments_checked,
            walk_error,
            verdict,
        }
    }

    /// Marks counted as good ([`MarkStatus::is_ok`]).
    #[must_use]
    pub fn ok_count(&self) -> usize {
        self.marks.iter().filter(|m| m.status.is_ok()).count()
    }

    /// Marks still pending ([`MarkStatus::is_pending`]).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.marks.iter().filter(|m| m.status.is_pending()).count()
    }

    /// Marks that failed ([`MarkStatus::is_bad`]).
    #[must_use]
    pub fn bad_count(&self) -> usize {
        self.marks.iter().filter(|m| m.status.is_bad()).count()
    }

    /// Outputs found to be the recomputed key.
    #[must_use]
    pub fn commit_ok_count(&self) -> usize {
        self.marks
            .iter()
            .filter(|m| m.commits == Some(true))
            .count()
    }

    /// Outputs found not to be the recomputed key.
    #[must_use]
    pub fn commit_bad_count(&self) -> usize {
        self.marks
            .iter()
            .filter(|m| m.commits == Some(false))
            .count()
    }

    /// Whether the verdict is [`TrailVerdict::Verified`].
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verdict == TrailVerdict::Verified
    }

    /// Whether every mark was found, commits to its state and spends its
    /// predecessor, with no failure anywhere: a [verified](Self::is_verified)
    /// trail, or one whose newest marks are still in the mempool.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.commitments_checked
            && !self.marks.is_empty()
            && self
                .marks
                .iter()
                .all(|m| m.commits == Some(true) && !m.status.is_bad())
    }

    /// The first mark that is not good, if any.
    #[must_use]
    pub fn first_failure(&self) -> Option<&MarkReport> {
        self.marks.iter().find(|m| !m.status.is_ok())
    }
}

/// The status blocktrails/verify gives a mark, from what was found (with the
/// spend link added, see [`MarkStatus::BrokenLink`]).
#[cfg_attr(not(feature = "mrc20"), allow(dead_code))]
fn mark_status(
    found: bool,
    confirmed: bool,
    amount_ok: bool,
    commits: Option<bool>,
    links_to_prev: Option<bool>,
) -> MarkStatus {
    if !found {
        MarkStatus::NotFound
    } else if commits == Some(false) {
        MarkStatus::WrongKey
    } else if links_to_prev == Some(false) {
        MarkStatus::BrokenLink
    } else if !confirmed {
        MarkStatus::Unconfirmed
    } else if !amount_ok {
        MarkStatus::AmountMismatch
    } else if commits == Some(true) {
        MarkStatus::Verified
    } else {
        MarkStatus::Confirmed
    }
}

// ---------------------------------------------------------------------------
// The walk and the per-link verification (feature: mrc20)
// ---------------------------------------------------------------------------

#[cfg(feature = "mrc20")]
mod walk {
    use super::*;
    use crate::mrc20::{bt_base_point, bt_trail_outputs, MempoolLookup, TxInfo};
    use crate::payments::PaymentError;

    /// How a trail's `pubkeyBase` was read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BaseReading {
        /// A full compressed point (02/03 + x): nothing guessed.
        FullPoint,
        /// A bare x, read as the even-y (02) point.
        BareX,
        /// A `did:nostr` identifier or Multikey, read by
        /// [`bt_base_point`](crate::mrc20::bt_base_point) (this crate's
        /// addition; blocktrails/verify reads only the two forms above).
        Identifier,
    }

    /// The expected output of every mark, recomputed from a trail's base key
    /// and states.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TrailWalk {
        /// `x(P_i)` for every mark `i`.
        pub expected: Vec<[u8; 32]>,
        /// The profile the trail was read as (lower-case).
        pub profile: String,
        /// How the base key was read.
        pub base: BaseReading,
    }

    /// Recompute every mark's output key from a trail's base key and its
    /// states, as blocktrails/verify 043e7af's `walk` does.
    ///
    /// The base key is `pubkeyBase`: a full compressed point as it is, a bare x
    /// as the even-y point (and, beyond blocktrails/verify, a `did:nostr`
    /// identifier or Multikey). The states are [`Blocktrail::state_strings`]:
    /// a string state hashed as its text, an object state as its JCS, a
    /// git-mark trail's commits read from its TXO URIs when it lists no
    /// states. Each tweak is added to the full point, never its even-y lift.
    ///
    /// # Errors
    ///
    /// Why the trail cannot be walked, in blocktrails/verify's words where it
    /// has them: `the trail names no base key (pubkeyBase): nothing to
    /// recompute from`, `the trail has M marks and S states`, `mark i has no
    /// state`; or a base key off the curve, or a zero tweak.
    pub fn walk_blocktrail(trail: &Blocktrail) -> Result<TrailWalk, String> {
        let profile = trail.profile_name();
        let state_strings = trail.state_strings()?;
        let raw = trail.pubkey_base.as_deref().unwrap_or("").to_lowercase();
        let is_hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
        let (base_hex, base) = if raw.len() == 66
            && (raw.starts_with("02") || raw.starts_with("03"))
            && is_hex(&raw)
        {
            (raw, BaseReading::FullPoint)
        } else if raw.len() == 64 && is_hex(&raw) {
            (format!("02{raw}"), BaseReading::BareX)
        } else {
            match bt_base_point(&raw) {
                Ok(point) if !raw.is_empty() => (hex::encode(point), BaseReading::Identifier),
                _ => {
                    return Err("the trail names no base key (pubkeyBase): nothing to \
                                    recompute from"
                        .into())
                }
            }
        };
        let expected = bt_trail_outputs(&base_hex, &state_strings).map_err(|e| e.to_string())?;
        Ok(TrailWalk {
            expected,
            profile,
            base,
        })
    }

    fn output_spk(tx: &TxInfo, vout: u32) -> Option<(&str, u64)> {
        tx.vout
            .get(vout as usize)
            .map(|o| (o.scriptpubkey.as_deref().unwrap_or(""), o.value))
    }

    fn commits_to(spk: &str, expected: &[u8; 32]) -> Option<bool> {
        (!spk.is_empty())
            .then(|| spk.eq_ignore_ascii_case(&format!("5120{}", hex::encode(expected))))
    }

    /// Verify a trail mark by mark, as blocktrails/verify 043e7af does.
    ///
    /// First the commitment, with no network: every mark's output key is
    /// recomputed ([`walk_blocktrail`]). Then for each mark in `txo`, through
    /// `mempool`:
    ///
    /// - the transaction exists ([`MarkStatus::NotFound`] otherwise),
    /// - its output is the recomputed key ([`MarkStatus::WrongKey`]),
    /// - it spends the previous mark ([`MarkStatus::BrokenLink`]; see there
    ///   for how this differs from blocktrails/verify),
    /// - it is confirmed ([`MarkStatus::Unconfirmed`]),
    /// - its output carries the amount the trail records
    ///   ([`MarkStatus::AmountMismatch`]).
    ///
    /// A trail that cannot be walked is still checked for confirmation and
    /// amounts, and its verdict is at best [`TrailVerdict::Confirmed`], with
    /// the reason in [`TrailReport::walk_error`]. A trail with no marks is
    /// [`TrailVerdict::Partial`].
    pub async fn verify_blocktrail(trail: &Blocktrail, mempool: &dyn MempoolLookup) -> TrailReport {
        let (walked, walk_error) = match walk_blocktrail(trail) {
            Ok(w) => (Some(w), None),
            Err(e) => (None, Some(e)),
        };
        let walk_error = if trail.txo.is_empty() {
            Some(walk_error.unwrap_or_else(|| "the trail has no marks".into()))
        } else {
            walk_error
        };
        let mut marks = Vec::with_capacity(trail.txo.len());
        for (i, t) in trail.txo.iter().enumerate() {
            let expected = walked.as_ref().map(|w| w.expected[i]);
            let mut report = MarkReport {
                index: i,
                txid: t.txid.clone(),
                vout: t.vout,
                status: MarkStatus::NotFound,
                confirmed: false,
                block_height: None,
                value: None,
                amount: t.amount,
                commits: None,
                links_to_prev: None,
                expected_output: expected.map(hex::encode),
            };
            if let Ok(tx) = mempool.tx(&t.txid).await {
                let out = output_spk(&tx, t.vout);
                let amount_ok = t.amount.is_none() || out.map(|(_, v)| v) == t.amount;
                let links = (i > 0).then(|| {
                    let prev = &trail.txo[i - 1].txid;
                    tx.vin.iter().any(|v| &v.txid == prev)
                });
                let commits = match (expected, out) {
                    (Some(want), Some((spk, _))) => commits_to(spk, &want),
                    _ => None,
                };
                report.status = mark_status(true, tx.confirmed, amount_ok, commits, links);
                report.confirmed = tx.confirmed;
                report.block_height = tx.block_height;
                report.value = out.map(|(_, v)| v);
                report.commits = commits;
                report.links_to_prev = links;
            }
            marks.push(report);
        }
        TrailReport::new(marks, walk_error)
    }

    /// Verify a trail that keeps only its head, by walking back from it.
    ///
    /// `head_txid:head_vout` is the newest mark; each mark's predecessor is the
    /// output its transaction spends (with several inputs, the one whose
    /// output is the previous recomputed key, else the first). Every mark is
    /// checked as [`verify_blocktrail`] checks it, except the amount, which
    /// such a trail does not record. The genesis mark's own input is not
    /// checked: it is the funding, not part of the trail.
    ///
    /// The issued MRC20 trails keep `pubkeyBase`, their state strings and the
    /// head outpoint only, so this is how their every link is checked.
    ///
    /// # Errors
    ///
    /// [`PaymentError::InvalidState`] when the base key cannot be read, there
    /// are no states, or a tweak is zero. A mark that cannot be found is
    /// reported, not raised.
    pub async fn verify_anchor_chain(
        pubkey_base: &str,
        state_strings: &[String],
        head_txid: &str,
        head_vout: u32,
        mempool: &dyn MempoolLookup,
    ) -> Result<TrailReport, PaymentError> {
        if state_strings.is_empty() {
            return Err(PaymentError::InvalidState(
                "an anchor chain needs at least one state".into(),
            ));
        }
        let expected = bt_trail_outputs(pubkey_base, state_strings)?;
        let k = expected.len();
        let mut marks: Vec<Option<MarkReport>> = vec![None; k];
        let mut cursor = Some((head_txid.to_string(), head_vout));
        let mut cached: Option<TxInfo> = None;

        for i in (0..k).rev() {
            let blank = |txid: String, vout: u32| MarkReport {
                index: i,
                txid,
                vout,
                status: MarkStatus::NotFound,
                confirmed: false,
                block_height: None,
                value: None,
                amount: None,
                commits: None,
                links_to_prev: None,
                expected_output: Some(hex::encode(expected[i])),
            };
            let Some((txid, vout)) = cursor.take() else {
                marks[i] = Some(blank(String::new(), 0));
                continue;
            };
            let tx = match cached.take() {
                Some(t) if t.txid == txid => Ok(t),
                _ => mempool.tx(&txid).await,
            };
            let Ok(tx) = tx else {
                marks[i] = Some(blank(txid, vout));
                continue;
            };
            let out = output_spk(&tx, vout);
            let commits = out.and_then(|(spk, _)| commits_to(spk, &expected[i]));
            let links = if i == 0 {
                None
            } else if tx.vin.is_empty() {
                Some(false)
            } else {
                let mut chosen = None;
                if tx.vin.len() > 1 {
                    for v in &tx.vin {
                        if let Ok(prev) = mempool.tx(&v.txid).await {
                            let hit = output_spk(&prev, v.vout)
                                .and_then(|(spk, _)| commits_to(spk, &expected[i - 1]))
                                == Some(true);
                            if hit {
                                chosen = Some((v.txid.clone(), v.vout));
                                cached = Some(prev);
                                break;
                            }
                        }
                    }
                }
                let (ptxid, pvout) =
                    chosen.unwrap_or_else(|| (tx.vin[0].txid.clone(), tx.vin[0].vout));
                cursor = Some((ptxid, pvout));
                Some(true)
            };
            let mut report = blank(txid, vout);
            report.status = mark_status(true, tx.confirmed, true, commits, links);
            report.confirmed = tx.confirmed;
            report.block_height = tx.block_height;
            report.value = out.map(|(_, v)| v);
            report.commits = commits;
            report.links_to_prev = links;
            marks[i] = Some(report);
        }
        Ok(TrailReport::new(
            marks
                .into_iter()
                .map(|m| m.expect("every mark visited"))
                .collect(),
            None,
        ))
    }
}

#[cfg(feature = "mrc20")]
pub use walk::{verify_anchor_chain, verify_blocktrail, walk_blocktrail, BaseReading, TrailWalk};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TXID: &str = "51d87101b7cbb01cc5a68785bf3141ec6fd00894d71ab1168d4daa20420eeacf";
    const COMMIT: &str = "9adc596cfd1100333393a12f2f41b2d820f16d0b";

    #[test]
    fn txo_uri_round_trips_in_git_mark_order() {
        let uri = format!(
            "txo:tbtc4:{TXID}:0?amount=999700&pubkey={}&commit={COMMIT}",
            "ab".repeat(32)
        );
        let t: BlocktrailTxo = uri.parse().unwrap();
        assert_eq!(t.pubkey.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(t.to_string(), uri);
        // commit before amount reads the same and is written in git-mark's order
        let reordered: BlocktrailTxo = format!("txo:gitmark:{TXID}:3?commit={COMMIT}&amount=5")
            .parse()
            .unwrap();
        assert_eq!(
            reordered.to_string(),
            format!("txo:gitmark:{TXID}:3?amount=5&commit={COMMIT}")
        );
        // no query at all
        assert_eq!(
            BlocktrailTxo::parse_uri(&format!("txo:mainnet:{TXID}:1"))
                .unwrap()
                .to_string(),
            format!("txo:mainnet:{TXID}:1")
        );
    }

    #[test]
    fn txo_uri_rejects_malformed() {
        for bad in [
            format!("btc:mainnet:{TXID}:0"),
            format!("txo:{TXID}:0"),
            format!("txo:tbtc4:{}:0", &TXID[..60]),
            format!("txo:tbtc4:{TXID}:-1"),
            format!("txo:tbtc4:{TXID}:x"),
            format!("txo:tb-tc:{TXID}:0"),
            format!("txo:tbtc4:{TXID}:0:9"),
            format!("txo:tbtc4:{TXID}:0?amount=lots"),
            format!("txo:tbtc4:{TXID}:0?commit=%zz"),
        ] {
            assert!(BlocktrailTxo::parse_uri(&bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn txo_uri_empty_values_are_absent_and_percent_decoded() {
        let t =
            BlocktrailTxo::parse_uri(&format!("txo:tbtc4:{TXID}:0?amount=&commit=%61b&x=1&flag"))
                .unwrap();
        assert_eq!(t.amount, None);
        assert_eq!(t.commit.as_deref(), Some("ab"));
    }

    #[test]
    fn legacy_entry_round_trips_as_written() {
        let v = json!({"outpoint": format!("{TXID}:2"), "blockheight": 840000});
        let t: BlocktrailTxo = serde_json::from_value(v.clone()).unwrap();
        assert!(t.is_legacy());
        assert_eq!(
            (t.txid.as_str(), t.vout, t.blockheight),
            (TXID, 2, Some(840_000))
        );
        assert_eq!(serde_json::to_value(&t).unwrap(), v);
        let no_height = json!({"outpoint": "t0:0"});
        let t: BlocktrailTxo = serde_json::from_value(no_height.clone()).unwrap();
        assert_eq!(serde_json::to_value(&t).unwrap(), no_height);
        assert!(serde_json::from_value::<BlocktrailTxo>(json!(7)).is_err());
        assert!(serde_json::from_value::<BlocktrailTxo>(json!({"outpoint": "nocolon"})).is_err());
    }

    #[test]
    fn state_strings_follow_blocktrails_verify() {
        let txo = BlocktrailTxo::new("tbtc4", TXID, 0).with_commit(COMMIT);
        let mut t = Blocktrail::gitmark("02aa", "tbtc4", vec![], vec![txo.clone()]);
        // a git-mark trail with no states reads them from the TXO URIs
        assert_eq!(t.state_strings().unwrap(), vec![COMMIT.to_string()]);
        // an object state is its JCS, a string its text
        t.profile = Some("mono.mrc20.v0.1".into());
        t.states = vec![json!({"b": 1, "a": 2})];
        assert_eq!(
            t.state_strings().unwrap(),
            vec![r#"{"a":2,"b":1}"#.to_string()]
        );
        t.states = vec![];
        assert_eq!(
            t.state_strings().unwrap_err(),
            "the trail has 1 marks and 0 states"
        );
        t.states = vec![Value::Null];
        assert_eq!(t.state_strings().unwrap_err(), "mark 0 has no state");
        // no profile reads as monochrome
        t.profile = None;
        assert_eq!(t.profile_name(), DEFAULT_PROFILE);
        t.profile = Some("GitMark".into());
        assert!(t.is_gitmark());
    }

    #[test]
    fn verdicts_follow_blocktrails_verify() {
        let mark = |status, commits| MarkReport {
            index: 0,
            txid: TXID.into(),
            vout: 0,
            status,
            confirmed: true,
            block_height: None,
            value: None,
            amount: None,
            commits,
            links_to_prev: None,
            expected_output: None,
        };
        let r = TrailReport::new(vec![mark(MarkStatus::Verified, Some(true))], None);
        assert!(r.is_verified() && r.is_intact());
        let r = TrailReport::new(
            vec![mark(MarkStatus::Confirmed, None)],
            Some("no base".into()),
        );
        assert_eq!(r.verdict, TrailVerdict::Confirmed);
        assert!(!r.is_intact());
        // walked but an output unreadable: good mark, unchecked commitment: partial
        let r = TrailReport::new(vec![mark(MarkStatus::Confirmed, None)], None);
        assert_eq!(r.verdict, TrailVerdict::Partial);
        let r = TrailReport::new(vec![mark(MarkStatus::Unconfirmed, Some(true))], None);
        assert_eq!(r.verdict, TrailVerdict::Partial);
        assert!(r.is_intact(), "a pending head is intact");
        assert_eq!(
            TrailReport::new(vec![], None).verdict,
            TrailVerdict::Partial
        );
        assert_eq!(
            mark_status(true, true, true, Some(true), Some(false)),
            MarkStatus::BrokenLink
        );
        assert_eq!(
            mark_status(true, false, false, Some(false), None),
            MarkStatus::WrongKey
        );
    }

    #[test]
    fn chain_names_map_both_ways() {
        for (net, chain) in [
            ("testnet4", "tbtc4"),
            ("mainnet", "mainnet"),
            ("signet", "signet"),
            ("regtest", "regtest"),
            ("gitmark", "gitmark"),
        ] {
            assert_eq!(txo_chain_for_network(net), chain);
            assert_eq!(network_for_txo_chain(chain), net);
        }
        assert_eq!(network_for_txo_chain("tbtc3"), "testnet");
        assert!(is_gitmark_commit(&"a".repeat(64)));
        assert!(!is_gitmark_commit(&"g".repeat(40)));
    }
}
