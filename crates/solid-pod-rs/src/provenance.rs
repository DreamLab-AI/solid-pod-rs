//! Provenance primitives — composable, cost-tiered traceability for pod writes.
//!
//! Implements the data model and traits from
//! [`docs/design/provenance-upgrade-master-plan.md`](../../docs/design/provenance-upgrade-master-plan.md)
//! §2 and [ADR-059](../../docs/adr/ADR-059-provenance-primitives-block-trails-git-marks.md)
//! (D1, D2, D4, D6). Two tiers compose into one chain:
//!
//! - **git-mark** (cheap, always-on): every pod write becomes a git commit;
//!   the commit SHA is captured as a [`GitMark`]. Content-addressed,
//!   append-only, tamper-evident ordering for free. The native implementation
//!   of [`GitMarker`] lives in `solid-pod-rs-git::mark` (it shells to `git`);
//!   wasm consumers compile against a no-op marker.
//! - **block-trail anchor** (expensive, opt-in): a Bitcoin-anchored MRC20 state
//!   whose taproot UTXO externally timestamps a record ([`BlockTrailAnchor`]).
//!   Reserved for high-value records. The [`BlockAnchorer`] trait is defined
//!   here; a real implementation lands in Phase 4 (`bitcoin_tx.rs` + mempool).
//!
//! A [`ProvenanceMark`] always carries a [`GitMark`] and *optionally* a
//! [`BlockTrailAnchor`]. The anchor's `state_hash` commits to the git SHA (or an
//! epoch Merkle root over many commits), binding both tiers into one chain.
//!
//! ## wasm32 safety
//!
//! Everything in this module — the types and [`prov_ttl`] — is pure logic and
//! compiles for `wasm32-unknown-unknown`. The traits are `?Send` (matching the
//! crate's existing [`crate::payments::PaymentStore`] pattern) so a wasm
//! single-threaded executor can implement them. No `tokio`, no process spawning,
//! no I/O leaks into this surface.

use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data model (§2.1)
// ---------------------------------------------------------------------------

/// A provenance mark over a pod resource write.
///
/// Always carries a git commit ([`GitMark`]); optionally upgraded with a
/// Bitcoin block-trail anchor ([`BlockTrailAnchor`]) for high-value records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMark {
    /// Pod-relative path of the resource the write targeted.
    pub resource: String,
    /// The git commit the write produced — **always present** (cheap tier).
    pub git: GitMark,
    /// Optional Bitcoin block-trail anchor — **opt-in** (expensive tier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<BlockTrailAnchor>,
    /// `did:nostr` of the writer (NIP-98 authenticated principal), or an
    /// anonymous marker when the write was unauthenticated.
    pub agent_did: String,
    /// Unix seconds at which the mark was produced.
    pub created: u64,
}

/// The cheap-tier git commit captured for a pod write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMark {
    /// Git SHA-1 of the commit the write produced.
    pub commit_sha: String,
    /// Pod repo slug (the pod's first path segment / pubkey).
    pub repo: String,
    /// Branch the commit landed on. Pinned to `"main"` by `init.rs`.
    pub branch: String,
    /// Prior commit SHA (the append-only chain link), or `None` for the
    /// genesis commit of a freshly-initialised repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// The expensive-tier Bitcoin anchor for a record.
///
/// Reuses the existing [`crate::mrc20`] crypto (`Mrc20State`, `bt_address`,
/// `verify_mrc20_anchor`) — no crypto is re-implemented here. The
/// `state_strings` carry the portable, independently-verifiable proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTrailAnchor {
    /// Trail ticker / identifier.
    pub ticker: String,
    /// `sha256_hex(jcs(state))` — links into the MRC20 trail and commits to
    /// the git SHA (or an epoch Merkle root).
    pub state_hash: String,
    /// Bitcoin transaction id of the anchoring UTXO.
    pub txid: String,
    /// Output index of the anchoring UTXO.
    pub vout: u32,
    /// Derived P2TR address (`mrc20::bt_address`).
    pub address: String,
    /// `"testnet4"` | `"mainnet"` (or any network the operator configures).
    pub network: String,
    /// Confirmation height; `None` until the anchoring tx confirms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u64>,
    /// Portable, independently-verifiable proof — the serialised states.
    #[serde(default)]
    pub state_strings: Vec<String>,
    /// Issuer's compressed pubkey (66-char hex). Together with
    /// `state_strings` it re-derives the taproot `address` via
    /// `mrc20::bt_address` — the read-side check
    /// ([`BlockAnchorer::verify`](crate::provenance::BlockAnchorer::verify))
    /// needs it to confirm `address` was not forged. `None` on legacy /
    /// partially-populated anchors (verify then has nothing to re-derive
    /// against and reports `false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures surfaced by the provenance primitives.
///
/// Hand-rolled (no `thiserror` derive) so the type compiles on `wasm32`
/// without pulling proc-macro evaluation into the pure surface; the variants
/// mirror the crate's error-message style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The underlying git operation failed (spawn, commit, rev-parse, …).
    Git(String),
    /// The Bitcoin anchor operation failed (mempool, tx-build, verify, …).
    Anchor(String),
    /// The resource path was rejected (traversal, sidecar suffix, …).
    InvalidPath(String),
    /// Persisting or emitting the mark failed.
    Store(String),
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceError::Git(m) => write!(f, "git-mark: {m}"),
            ProvenanceError::Anchor(m) => write!(f, "block-anchor: {m}"),
            ProvenanceError::InvalidPath(m) => write!(f, "invalid provenance path: {m}"),
            ProvenanceError::Store(m) => write!(f, "provenance store: {m}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

// ---------------------------------------------------------------------------
// Traits (§2.2)
// ---------------------------------------------------------------------------

/// Cheap tier. Implemented by `solid-pod-rs-git` (shells to `git`).
///
/// `?Send` for wasm32-safety, matching the crate's [`crate::payments::PaymentStore`]
/// pattern. The wasm `core` consumer compiles against a no-op marker.
#[async_trait::async_trait(?Send)]
pub trait GitMarker: Send + Sync {
    /// Stage `path` and commit it, returning the resulting [`GitMark`].
    ///
    /// `repo` is the absolute filesystem path to the (non-bare) pod repo;
    /// `path` is the repo-relative path written; `agent_did` is recorded as
    /// the commit author email; `message` is the commit subject. When there
    /// is nothing to commit the implementation returns a mark referencing the
    /// current HEAD without erroring.
    async fn mark_write(
        &self,
        repo: &Path,
        path: &str,
        agent_did: &str,
        message: &str,
    ) -> Result<GitMark, ProvenanceError>;

    /// Return the current HEAD commit SHA, or `None` for an unborn branch.
    async fn head(&self, repo: &Path) -> Result<Option<String>, ProvenanceError>;
}

/// Expensive tier. Server-side (mempool + Bitcoin TX), behind feature `mrc20`.
///
/// Defined here; a real implementation lands in Phase 4 (`bitcoin_tx.rs`).
#[async_trait::async_trait(?Send)]
pub trait BlockAnchorer: Send + Sync {
    /// Anchor `state_hash` under `ticker` on `network`, returning the produced
    /// [`BlockTrailAnchor`].
    // implemented in Phase 4
    async fn anchor(
        &self,
        ticker: &str,
        state_hash: &str,
        network: &str,
    ) -> Result<BlockTrailAnchor, ProvenanceError>;

    /// Verify a previously-produced anchor against the chain / fixtures.
    // implemented in Phase 4 (verify-side wired in Phase 3)
    async fn verify(&self, anchor: &BlockTrailAnchor) -> Result<bool, ProvenanceError>;
}

// ---------------------------------------------------------------------------
// PROV-O serialiser (§2.3 step 3, D7)
// ---------------------------------------------------------------------------

/// Escape a string for inclusion inside a Turtle double-quoted literal
/// (RDF 1.1 Turtle §2.5.3 / §6.4 string escapes).
fn ttl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Render `secs` (Unix seconds) as an `xsd:dateTime` literal in UTC.
///
/// Pure, allocation-light, and wasm-safe — avoids dragging `chrono`'s
/// formatting into the pure surface (the crate already depends on `chrono`
/// but we keep this self-contained and deterministic for the golden test).
fn xsd_datetime(secs: u64) -> String {
    // Civil-from-days (Howard Hinnant's algorithm) — exact, no leap tables.
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Produce a minimal, correct PROV-O Turtle sidecar for a [`ProvenanceMark`].
///
/// The mark is modelled as a `prov:Activity` (the write) that
/// `prov:generated` the resource entity, was performed by the agent
/// (`prov:wasAssociatedWith`), and is identified by its git commit SHA. The
/// resource entity records `prov:wasGeneratedBy` the activity. When a
/// block-trail anchor is present it is emitted as an associated entity bearing
/// the txid/state-hash so the sidecar carries both tiers.
///
/// Kept deliberately small: stable prefix block, one activity, one entity, one
/// agent, optional anchor entity. Round-trip-safe with the unit tests below.
pub fn prov_ttl(mark: &ProvenanceMark) -> String {
    let sha = &mark.git.commit_sha;
    let resource = ttl_escape(&mark.resource);
    let agent = ttl_escape(&mark.agent_did);
    let branch = ttl_escape(&mark.git.branch);
    let repo = ttl_escape(&mark.git.repo);
    let when = xsd_datetime(mark.created);

    let mut ttl = String::new();
    ttl.push_str("@prefix prov: <http://www.w3.org/ns/prov#> .\n");
    ttl.push_str("@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .\n");
    ttl.push_str("@prefix git:  <https://w3id.org/git#> .\n");
    ttl.push_str("@prefix bt:   <https://blocktrails.org/ns#> .\n\n");

    // Activity: the write, identified by the commit it produced.
    ttl.push_str(&format!("<urn:git:commit:{sha}> a prov:Activity ;\n"));
    ttl.push_str(&format!("    prov:generated <{resource}> ;\n"));
    ttl.push_str(&format!("    prov:wasAssociatedWith <{agent}> ;\n"));
    ttl.push_str(&format!("    prov:endedAtTime \"{when}\"^^xsd:dateTime ;\n"));
    ttl.push_str(&format!("    git:commit \"{sha}\" ;\n"));
    ttl.push_str(&format!("    git:branch \"{branch}\" ;\n"));
    ttl.push_str(&format!("    git:repo \"{repo}\" "));
    if let Some(parent) = &mark.git.parent {
        let parent = ttl_escape(parent);
        ttl.push_str(&format!(";\n    git:parent \"{parent}\" .\n"));
    } else {
        ttl.push_str(".\n");
    }

    // Entity: the generated resource.
    ttl.push('\n');
    ttl.push_str(&format!("<{resource}> a prov:Entity ;\n"));
    ttl.push_str(&format!(
        "    prov:wasGeneratedBy <urn:git:commit:{sha}> ;\n"
    ));
    ttl.push_str(&format!(
        "    prov:wasAttributedTo <{agent}> .\n"
    ));

    // Agent.
    ttl.push('\n');
    ttl.push_str(&format!("<{agent}> a prov:Agent .\n"));

    // Optional anchor entity (expensive tier).
    if let Some(a) = &mark.anchor {
        let txid = ttl_escape(&a.txid);
        let ticker = ttl_escape(&a.ticker);
        let state_hash = ttl_escape(&a.state_hash);
        let network = ttl_escape(&a.network);
        ttl.push('\n');
        ttl.push_str(&format!("<urn:bt:tx:{txid}:{}> a prov:Entity ;\n", a.vout));
        ttl.push_str(&format!(
            "    prov:wasDerivedFrom <urn:git:commit:{sha}> ;\n"
        ));
        ttl.push_str(&format!("    bt:ticker \"{ticker}\" ;\n"));
        ttl.push_str(&format!("    bt:stateHash \"{state_hash}\" ;\n"));
        ttl.push_str(&format!("    bt:network \"{network}\" ;\n"));
        ttl.push_str(&format!("    bt:txid \"{txid}\" ;\n"));
        ttl.push_str(&format!("    bt:vout \"{}\"^^xsd:integer ", a.vout));
        if let Some(h) = a.blockheight {
            ttl.push_str(&format!(";\n    bt:blockheight \"{h}\"^^xsd:integer .\n"));
        } else {
            ttl.push_str(".\n");
        }
    }

    ttl
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_git() -> GitMark {
        GitMark {
            commit_sha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334".into(),
            repo: "deadbeef".into(),
            branch: "main".into(),
            parent: Some("00112233445566778899aabbccddeeff00112233".into()),
        }
    }

    fn sample_mark() -> ProvenanceMark {
        ProvenanceMark {
            resource: "/notes/hello.ttl".into(),
            git: sample_git(),
            anchor: None,
            agent_did: "did:nostr:abcdef".into(),
            created: 1_750_000_000,
        }
    }

    #[test]
    fn git_mark_round_trips() {
        let g = sample_git();
        let json = serde_json::to_string(&g).unwrap();
        let back: GitMark = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn provenance_mark_round_trips_without_anchor() {
        let m = sample_mark();
        let json = serde_json::to_string(&m).unwrap();
        // `anchor: None` must be omitted by skip_serializing_if.
        assert!(!json.contains("anchor"));
        let back: ProvenanceMark = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn provenance_mark_round_trips_with_anchor() {
        let mut m = sample_mark();
        m.anchor = Some(BlockTrailAnchor {
            ticker: "PROV".into(),
            state_hash: "ff".repeat(32),
            txid: "ab".repeat(32),
            vout: 1,
            address: "tb1pexample".into(),
            network: "testnet4".into(),
            blockheight: Some(840_000),
            state_strings: vec!["{\"seq\":0}".into(), "{\"seq\":1}".into()],
            pubkey: Some("02".to_string() + &"ab".repeat(32)),
        });
        let json = serde_json::to_string(&m).unwrap();
        let back: ProvenanceMark = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn block_trail_anchor_defaults_state_strings() {
        // state_strings missing in JSON must deserialise to an empty vec.
        let json = r#"{
            "ticker":"PROV","state_hash":"00","txid":"00","vout":0,
            "address":"tb1p","network":"testnet4"
        }"#;
        let a: BlockTrailAnchor = serde_json::from_str(json).unwrap();
        assert!(a.state_strings.is_empty());
        assert!(a.blockheight.is_none());
    }

    #[test]
    fn prov_ttl_contains_core_triples() {
        let ttl = prov_ttl(&sample_mark());
        assert!(ttl.contains("@prefix prov: <http://www.w3.org/ns/prov#> ."));
        assert!(ttl.contains("a prov:Activity"));
        assert!(ttl.contains("prov:wasGeneratedBy"));
        assert!(ttl.contains("prov:wasAssociatedWith <did:nostr:abcdef>"));
        assert!(ttl.contains("a prov:Agent"));
        // Commit sha appears as the activity id + git:commit literal.
        assert!(ttl.contains("<urn:git:commit:a1b2c3d4e5f60718293a4b5c6d7e8f9001122334>"));
        assert!(ttl.contains("git:commit \"a1b2c3d4e5f60718293a4b5c6d7e8f9001122334\""));
        assert!(ttl.contains("git:branch \"main\""));
        assert!(ttl.contains("git:parent \"00112233445566778899aabbccddeeff00112233\""));
        // The generated entity is the resource.
        assert!(ttl.contains("<urn:git:commit:a1b2c3d4e5f60718293a4b5c6d7e8f9001122334> a prov:Activity"));
        assert!(ttl.contains("prov:generated </notes/hello.ttl>"));
    }

    #[test]
    fn prov_ttl_omits_parent_when_absent() {
        let mut m = sample_mark();
        m.git.parent = None;
        let ttl = prov_ttl(&m);
        assert!(!ttl.contains("git:parent"));
        // Must still be a well-terminated activity block.
        assert!(ttl.contains("git:repo \"deadbeef\" .\n"));
    }

    #[test]
    fn prov_ttl_emits_anchor_block_when_present() {
        let mut m = sample_mark();
        m.anchor = Some(BlockTrailAnchor {
            ticker: "PROV".into(),
            state_hash: "deadbeef".into(),
            txid: "cafebabe".into(),
            vout: 2,
            address: "tb1pexample".into(),
            network: "testnet4".into(),
            blockheight: Some(840_000),
            state_strings: vec![],
            pubkey: None,
        });
        let ttl = prov_ttl(&m);
        assert!(ttl.contains("<urn:bt:tx:cafebabe:2> a prov:Entity"));
        assert!(ttl.contains("bt:ticker \"PROV\""));
        assert!(ttl.contains("bt:stateHash \"deadbeef\""));
        assert!(ttl.contains("bt:blockheight \"840000\"^^xsd:integer"));
        assert!(ttl.contains("prov:wasDerivedFrom <urn:git:commit:"));
    }

    #[test]
    fn prov_ttl_escapes_quotes_and_backslashes() {
        let mut m = sample_mark();
        m.agent_did = "did:nostr:\"weird\\did".into();
        let ttl = prov_ttl(&m);
        // The raw quote/backslash must be escaped inside the literal.
        assert!(ttl.contains("did:nostr:\\\"weird\\\\did"));
    }

    #[test]
    fn xsd_datetime_known_epoch() {
        // 1_750_000_000 == 2025-06-15T15:06:40Z (verified against `date -u -d @1750000000`).
        assert_eq!(xsd_datetime(1_750_000_000), "2025-06-15T15:06:40Z");
        // Unix epoch.
        assert_eq!(xsd_datetime(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn provenance_error_display() {
        assert_eq!(
            ProvenanceError::Git("boom".into()).to_string(),
            "git-mark: boom"
        );
        assert_eq!(
            ProvenanceError::InvalidPath("/x.acl".into()).to_string(),
            "invalid provenance path: /x.acl"
        );
    }
}
