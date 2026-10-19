//! Repo-held git-mark trails and the NIP-34 anchor tags they feed.
//!
//! A repository can carry its own Blocktrails trail: the agent that owns the
//! repo marks each commit with the `git mark` CLI, using the repo's own key,
//! and commits the resulting `blocktrails.json` (profile `gitmark`). The forge
//! then holds no key and records nothing. It reads the file at the default
//! branch tip, re-derives every mark's taproot address from the base key and
//! the commits, links each mark to its chain's explorer, serves the committed
//! document, and names the latest on-chain mark in its NIP-34 events.
//!
//! This is the Rust counterpart of the JSS `forge` plugin's repo-held trail
//! path (`repoTrail`, `gitmarkStateHash`, `anchorTags`, `blocktrailsResp`) and
//! `didShort`. JSS is cited by function name only; the implementation is
//! original, built on [`solid_pod_rs::blocktrail`] and
//! `solid_pod_rs::mrc20`.
//!
//! ## State bytes
//!
//! A git-mark trail hashes each state as `SHA-256(commit hash as text)`. The
//! forge's own marks hash a JSON record instead. Both use the same chained
//! BIP-341 `TapTweak` walk, so the walk is `solid_pod_rs::mrc20`'s and only
//! the state strings differ: here they are the commits, verbatim.
//!
//! ## Features
//!
//! Reading, validating and tagging a trail needs nothing optional. Re-deriving
//! the per-mark addresses needs the Bitcoin stack and so the `anchoring`
//! feature; without it [`RepoMark::address`] and [`RepoMark::program`] are
//! `None`.

use std::path::Path;

use serde_json::Value;
use solid_pod_rs::blocktrail::BlocktrailTxo;

use crate::repo::browse;

/// The trail document's name at the repository root.
pub const TRAIL_FILE: &str = "blocktrails.json";

/// Largest `blocktrails.json` the forge will read, in bytes. A trail gains one
/// short line per mark, so this admits thousands of marks while bounding the
/// work a hostile push can ask of a page render.
pub const MAX_TRAIL_BYTES: u64 = 512 * 1024;

/// Shorten a `did:nostr` public key for display: `did:nostr:` plus the first
/// eight characters and an ellipsis. The hex stays canonical in every path and
/// identifier; this is for rendering only (JSS `didShort`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::did_short;
///
/// let hex = format!("4a578b54{}", "ab".repeat(28));
/// assert_eq!(did_short(&hex), "did:nostr:4a578b54…");
/// // shorter input is shown whole, never padded
/// assert_eq!(did_short("abc"), "did:nostr:abc…");
/// ```
#[must_use]
pub fn did_short(hex: &str) -> String {
    let head: String = hex.chars().take(8).collect();
    format!("did:nostr:{head}…")
}

/// The explorer web base for a chain token, for links a *person* clicks.
///
/// Covers every chain the `git mark` CLI knows: Bitcoin mainnet and the public
/// testnets on mempool.space, `txbt4` on mempool.guide and `xbt` on Kilombino.
/// `None` for a chain with no public explorer (for example `regtest`), where a
/// page should show the txid as plain text.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::explorer_web;
///
/// assert_eq!(explorer_web("tbtc4"), Some("https://mempool.space/testnet4"));
/// assert_eq!(explorer_web("txbt4"), Some("https://mempool.guide/testnet4"));
/// assert_eq!(explorer_web("xbt"), Some("https://mempool.kilombino.com"));
/// assert_eq!(explorer_web("regtest"), None);
/// ```
#[must_use]
pub fn explorer_web(chain: &str) -> Option<&'static str> {
    match chain {
        "btc" | "mainnet" | "bitcoin" => Some("https://mempool.space"),
        "tbtc4" => Some("https://mempool.space/testnet4"),
        "tbtc3" => Some("https://mempool.space/testnet"),
        "signet" => Some("https://mempool.space/signet"),
        "txbt4" => Some("https://mempool.guide/testnet4"),
        "xbt" => Some("https://mempool.kilombino.com"),
        _ => None,
    }
}

/// The explorer page for one transaction, or `None` when the chain has no
/// public explorer or `txid` is not 64 lowercase-or-uppercase hex characters.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::explorer_tx_url;
///
/// let txid = "cd".repeat(32);
/// assert_eq!(
///     explorer_tx_url("txbt4", &txid).unwrap(),
///     format!("https://mempool.guide/testnet4/tx/{txid}")
/// );
/// assert!(explorer_tx_url("txbt4", "not-a-txid").is_none());
/// ```
#[must_use]
pub fn explorer_tx_url(chain: &str, txid: &str) -> Option<String> {
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    explorer_web(chain).map(|web| format!("{web}/tx/{txid}"))
}

/// The network name `solid_pod_rs::mrc20::bt_address` takes for a chain
/// token, or `None` for a chain whose address prefix the encoder does not
/// know (`regtest` uses `bcrt`, which it does not emit).
///
/// Mainnet tokens (`btc`, `mainnet`, `bitcoin`, `xbt`) give `bc1p…`; the
/// public testnets and `txbt4` give `tb1p…`; `gitmark` gives `gm1p…`.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::network_for_chain;
///
/// assert_eq!(network_for_chain("tbtc4"), Some("testnet4"));
/// assert_eq!(network_for_chain("xbt"), Some("mainnet"));
/// assert_eq!(network_for_chain("gitmark"), Some("gitmark"));
/// assert_eq!(network_for_chain("regtest"), None);
/// ```
#[must_use]
pub fn network_for_chain(chain: &str) -> Option<&'static str> {
    match chain {
        "btc" | "mainnet" | "bitcoin" | "xbt" => Some("mainnet"),
        "tbtc4" | "tbtc3" | "signet" | "txbt4" => Some("testnet4"),
        "gitmark" => Some("gitmark"),
        _ => None,
    }
}

/// One mark of a repo-held trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoMark {
    /// Position in the trail, from 0.
    pub index: usize,
    /// The commit this mark commits to, exactly as the file spells it.
    pub commit: String,
    /// The mark's 32-byte witness program as hex, re-derived from the base key
    /// and the commits so far. `None` without the `anchoring` feature, or for
    /// a base key that is not a valid point.
    pub program: Option<String>,
    /// The mark's taproot address on the trail's chain, re-derived. `None`
    /// when `program` is, or when the chain's address prefix is unknown.
    pub address: Option<String>,
    /// The mark's on-chain output, when the file's `txo` entry parses.
    pub txo: Option<BlocktrailTxo>,
    /// The file's `txo` entry for this mark, verbatim.
    pub txo_uri: Option<String>,
}

/// A git-mark trail committed to a repository, read and re-derived.
#[derive(Debug, Clone, PartialEq)]
pub struct RepoTrail {
    /// The committed document, as parsed.
    pub doc: Value,
    /// The branch it was read from.
    pub branch: String,
    /// The chain token the marks live on.
    pub chain: String,
    /// The base key as a full compressed point (`02`/`03` plus x).
    pub pubkey_base: String,
    /// The marks, one per well-formed commit in `states`.
    pub marks: Vec<RepoMark>,
}

/// The facts a NIP-34 event needs to name a trail's on-chain frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorFacts {
    /// The chain token.
    pub chain: String,
    /// The transaction id of the first on-chain mark (the genesis anchor).
    pub genesis_txid: String,
    /// The transaction id of the latest on-chain mark.
    pub frontier_txid: String,
    /// The output index of the latest on-chain mark.
    pub frontier_vout: u32,
    /// The commit the latest on-chain mark commits to.
    pub frontier_commit: String,
    /// Absolute URL of the served trail document.
    pub trail_url: String,
}

impl RepoTrail {
    /// The base key's x-only form (64 lowercase hex), which is the agent's
    /// `did:nostr` public key.
    #[must_use]
    pub fn xonly(&self) -> String {
        self.pubkey_base[2..].to_ascii_lowercase()
    }

    /// The anchor facts for the NIP-34 events, or `None` while no mark has an
    /// on-chain output. `trail_url` is where the forge serves the document.
    #[must_use]
    pub fn anchor_facts(&self, trail_url: &str) -> Option<AnchorFacts> {
        let first = self.marks.iter().find_map(|m| m.txo.as_ref())?;
        let (last_mark, last) = self
            .marks
            .iter()
            .rev()
            .find_map(|m| m.txo.as_ref().map(|t| (m, t)))?;
        Some(AnchorFacts {
            chain: self.chain.clone(),
            genesis_txid: first.txid.to_ascii_lowercase(),
            frontier_txid: last.txid.to_ascii_lowercase(),
            frontier_vout: last.vout,
            frontier_commit: last_mark.commit.clone(),
            trail_url: trail_url.to_string(),
        })
    }

    /// The trail document as the hosted verifier wants it: pretty-printed JSON.
    #[must_use]
    pub fn document_json(&self) -> String {
        serde_json::to_string_pretty(&self.doc).unwrap_or_else(|_| "{}".to_string())
    }
}

/// The NIP-34 anchor tags both repository events (kinds 30617 and 30618)
/// carry once a repository is anchored, in emission order.
///
/// `r` (the trail document) and `anchor` (chain and genesis txid) are the
/// forge's own; `chain`, `txo` and `commit` name the **latest** on-chain mark
/// the way `git mark announce` does, so one consumer reads forge-anchored and
/// agent-announced repositories alike (JSS `anchorTags`).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::{anchor_tags, AnchorFacts};
///
/// let facts = AnchorFacts {
///     chain: "txbt4".into(),
///     genesis_txid: "ab".repeat(32),
///     frontier_txid: "cd".repeat(32),
///     frontier_vout: 0,
///     frontier_commit: "2".repeat(40),
///     trail_url: "https://forge.example/forge/casey/agent/blocktrails.json".into(),
/// };
/// let tags = anchor_tags(&facts);
/// assert_eq!(tags[1], ["anchor", "txbt4", &"ab".repeat(32)]);
/// assert_eq!(tags[3], ["txo", &format!("txo:txbt4:{}:0", "cd".repeat(32))]);
/// ```
#[must_use]
pub fn anchor_tags(facts: &AnchorFacts) -> Vec<Vec<String>> {
    vec![
        vec!["r".into(), facts.trail_url.clone()],
        vec![
            "anchor".into(),
            facts.chain.clone(),
            facts.genesis_txid.clone(),
        ],
        vec!["chain".into(), facts.chain.clone()],
        vec![
            "txo".into(),
            format!(
                "txo:{}:{}:{}",
                facts.chain, facts.frontier_txid, facts.frontier_vout
            ),
        ],
        vec!["commit".into(), facts.frontier_commit.clone()],
    ]
}

fn is_base_point(s: &str) -> bool {
    s.len() == 66
        && (s.starts_with("02") || s.starts_with("03"))
        && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A commit a git-mark trail can name: 40 hex characters (JSS keeps the file's
/// spelling, so a trail is re-derived from exactly what was committed).
fn is_commit(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a committed `blocktrails.json` as a repo-held git-mark trail.
///
/// Accepts only `@type` `Blocktrail` with profile `gitmark`, a base key that is
/// a full compressed point and a string `chain`; anything else is `None`, as
/// is input over [`MAX_TRAIL_BYTES`]. States that are not 40-hex commits are
/// dropped, as the JSS reader does; `txo` entries that do not parse leave
/// [`RepoMark::txo`] empty rather than failing the trail.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitmark::parse_repo_trail;
///
/// let raw = serde_json::json!({
///     "@type": "Blocktrail", "version": "0.0.3", "profile": "gitmark",
///     "pubkeyBase": "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
///     "chain": "txbt4",
///     "states": ["1".repeat(40)],
///     "txo": [format!("txo:txbt4:{}:0?amount=9700&commit={}", "ab".repeat(32), "1".repeat(40))],
/// })
/// .to_string();
/// let trail = parse_repo_trail(&raw, "main").unwrap();
/// assert_eq!(trail.marks.len(), 1);
/// assert_eq!(trail.marks[0].txo.as_ref().unwrap().amount, Some(9700));
/// // a forge-held style document is not a repo-held trail
/// assert!(parse_repo_trail(r#"{"@type":"Blocktrail","profile":"monochrome"}"#, "main").is_none());
/// ```
#[must_use]
pub fn parse_repo_trail(raw: &str, branch: &str) -> Option<RepoTrail> {
    if raw.len() as u64 > MAX_TRAIL_BYTES {
        return None;
    }
    let doc: Value = serde_json::from_str(raw).ok()?;
    if doc.get("@type")?.as_str()? != "Blocktrail" || doc.get("profile")?.as_str()? != "gitmark" {
        return None;
    }
    let pubkey_base = doc.get("pubkeyBase")?.as_str()?.to_string();
    if !is_base_point(&pubkey_base) {
        return None;
    }
    let chain = doc.get("chain")?.as_str()?.to_string();
    let commits: Vec<String> = doc
        .get("states")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter(|c| is_commit(c))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let txo_uris: Vec<Option<String>> = doc
        .get("txo")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let (programs, addresses) = derive(&pubkey_base, &chain, &commits);
    let marks = commits
        .into_iter()
        .enumerate()
        .map(|(index, commit)| {
            let txo_uri = txo_uris.get(index).cloned().flatten();
            let txo = txo_uri
                .as_deref()
                .and_then(|u| BlocktrailTxo::parse_uri(u).ok());
            RepoMark {
                index,
                commit,
                program: programs.get(index).cloned(),
                address: addresses.get(index).cloned(),
                txo,
                txo_uri,
            }
        })
        .collect();
    Some(RepoTrail {
        doc,
        branch: branch.to_string(),
        chain,
        pubkey_base,
        marks,
    })
}

/// Re-derive every mark's witness program and address (one walk, linear in the
/// number of marks). Empty when the `anchoring` feature is off or the key or
/// state is refused; the address list is empty alone for an unknown chain.
#[cfg(feature = "anchoring")]
fn derive(pubkey_base: &str, chain: &str, commits: &[String]) -> (Vec<String>, Vec<String>) {
    use solid_pod_rs::mrc20::{bt_trail_addresses, bt_trail_outputs};
    let Ok(outputs) = bt_trail_outputs(pubkey_base, commits) else {
        return (Vec::new(), Vec::new());
    };
    let programs = outputs.iter().map(hex::encode).collect();
    let addresses = network_for_chain(chain)
        .and_then(|net| bt_trail_addresses(pubkey_base, commits, net).ok())
        .unwrap_or_default();
    (programs, addresses)
}

#[cfg(not(feature = "anchoring"))]
fn derive(_pubkey_base: &str, _chain: &str, _commits: &[String]) -> (Vec<String>, Vec<String>) {
    (Vec::new(), Vec::new())
}

/// Read the repo-held trail at the tip of `branch` in a bare repository, or
/// `None` when the repository has no valid `blocktrails.json` there.
///
/// The ref and path are validated by [`browse::read_blob`] before they reach
/// git, and the blob is size-checked before it is read.
///
/// Every failure (missing file, oversized blob, bad ref, unparsable JSON) means
/// "this repository does not carry a trail", so there is no error to report.
pub async fn read_repo_trail(git_dir: &Path, branch: &str) -> Option<RepoTrail> {
    let rev = format!("refs/heads/{branch}");
    let bytes = browse::read_blob(git_dir, &rev, TRAIL_FILE, MAX_TRAIL_BYTES)
        .await
        .ok()?;
    parse_repo_trail(std::str::from_utf8(&bytes).ok()?, branch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Vectors generated by running the JSS `forge/lib/blocktrails.js`
    // (`gitmarkStateHash`, `trailProgram`, `trailAddress`, `didShort`) at
    // plugins@63a16cb with base key = secp256k1 pubkey of 0x11*32.
    const BASE: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const C0: &str = "1111111111111111111111111111111111111111";
    const C1: &str = "2222222222222222222222222222222222222222";
    #[cfg(feature = "anchoring")]
    const P0: &str = "f1f4e2a2289fbfbae2f5d10e8a554d777a44c97dd5593db7df947acf1418532b";
    #[cfg(feature = "anchoring")]
    const P1: &str = "4e3706f136ba546fe29bbb93c5a20903cbdfbf71f6ff81f611501dae7bf84743";
    #[cfg(feature = "anchoring")]
    const A0_TB: &str = "tb1p786w9g3gn7lm4ch46y8g542dwaayfjta64vnmd7lj3av79qc2v4sf843nu";
    #[cfg(feature = "anchoring")]
    const A1_TB: &str = "tb1pfcmsdufkhf2xlc5mhwfutgsfq09al0m37mlcras32qw6u7lcgapslzrkyu";
    #[cfg(feature = "anchoring")]
    const A0_BC: &str = "bc1p786w9g3gn7lm4ch46y8g542dwaayfjta64vnmd7lj3av79qc2v4s70r7fn";

    fn txid_a() -> String {
        "ab".repeat(32)
    }
    fn txid_b() -> String {
        "cd".repeat(32)
    }

    fn doc(chain: &str) -> String {
        json!({
            "@type": "Blocktrail", "version": "0.0.3", "profile": "gitmark",
            "pubkeyBase": BASE, "chain": chain,
            "states": [C0, C1],
            "txo": [
                format!("txo:{chain}:{}:0?amount=9700&commit={C0}", txid_a()),
                format!("txo:{chain}:{}:0?amount=9400&commit={C1}", txid_b()),
            ],
        })
        .to_string()
    }

    #[test]
    fn did_short_is_eight_chars_and_an_ellipsis() {
        let hex = format!("4a578b54{}", "ab".repeat(28));
        assert_eq!(did_short(&hex), "did:nostr:4a578b54…");
    }

    #[test]
    fn explorer_table_matches_the_git_mark_chains() {
        assert_eq!(explorer_web("btc"), Some("https://mempool.space"));
        assert_eq!(explorer_web("tbtc3"), Some("https://mempool.space/testnet"));
        assert_eq!(explorer_web("signet"), Some("https://mempool.space/signet"));
        assert_eq!(explorer_web("regtest"), None);
        assert_eq!(
            explorer_tx_url("txbt4", &txid_b()).unwrap(),
            format!("https://mempool.guide/testnet4/tx/{}", txid_b())
        );
        assert!(explorer_tx_url("txbt4", &txid_b()[..10]).is_none());
        assert!(explorer_tx_url("regtest", &txid_b()).is_none());
    }

    #[test]
    fn parses_the_committed_document() {
        let t = parse_repo_trail(&doc("txbt4"), "main").unwrap();
        assert_eq!(t.chain, "txbt4");
        assert_eq!(t.branch, "main");
        assert_eq!(t.marks.len(), 2);
        assert_eq!(t.marks[1].commit, C1);
        let txo = t.marks[1].txo.as_ref().unwrap();
        assert_eq!((txo.vout, txo.amount), (0, Some(9400)));
        assert_eq!(txo.txid, txid_b());
        assert_eq!(t.xonly(), &BASE[2..]);
        // The served document is the committed one, nothing added.
        let served: Value = serde_json::from_str(&t.document_json()).unwrap();
        assert_eq!(served["profile"], "gitmark");
        assert_eq!(served["states"], json!([C0, C1]));
        assert_eq!(served["pubkeyBase"], BASE);
    }

    #[test]
    fn refuses_what_is_not_a_repo_held_gitmark_trail() {
        for bad in [
            "not json".to_string(),
            r#"{"@type":"Blocktrail","profile":"monochrome","pubkeyBase":"x","chain":"tbtc4"}"#
                .to_string(),
            json!({"@type":"Other","profile":"gitmark","pubkeyBase":BASE,"chain":"tbtc4"})
                .to_string(),
            // x-only is not a full point: the file must publish parity
            json!({"@type":"Blocktrail","profile":"gitmark","pubkeyBase":&BASE[2..],"chain":"tbtc4"})
                .to_string(),
            json!({"@type":"Blocktrail","profile":"gitmark","pubkeyBase":BASE}).to_string(),
        ] {
            assert!(parse_repo_trail(&bad, "main").is_none(), "{bad}");
        }
        let huge = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_TRAIL_BYTES as usize));
        assert!(parse_repo_trail(&huge, "main").is_none());
    }

    #[test]
    fn drops_malformed_states_and_tolerates_bad_txo_entries() {
        let raw = json!({
            "@type": "Blocktrail", "profile": "gitmark", "pubkeyBase": BASE, "chain": "tbtc4",
            "states": [C0, "short", 7, C1],
            "txo": ["garbage", null],
        })
        .to_string();
        let t = parse_repo_trail(&raw, "main").unwrap();
        assert_eq!(t.marks.len(), 2, "only the two commits survive");
        assert!(t.marks.iter().all(|m| m.txo.is_none()));
        assert_eq!(t.marks[0].txo_uri.as_deref(), Some("garbage"));
        assert!(t.anchor_facts("https://x/blocktrails.json").is_none());
    }

    #[cfg(feature = "anchoring")]
    #[test]
    fn re_derives_addresses_with_gitmark_state_bytes() {
        let t = parse_repo_trail(&doc("tbtc4"), "main").unwrap();
        assert_eq!(t.marks[0].program.as_deref(), Some(P0));
        assert_eq!(t.marks[1].program.as_deref(), Some(P1));
        assert_eq!(t.marks[0].address.as_deref(), Some(A0_TB));
        assert_eq!(t.marks[1].address.as_deref(), Some(A1_TB));
        // txbt4 is a testnet-style chain, xbt a mainnet-style one
        let t = parse_repo_trail(&doc("txbt4"), "main").unwrap();
        assert_eq!(t.marks[0].address.as_deref(), Some(A0_TB));
        let t = parse_repo_trail(&doc("xbt"), "main").unwrap();
        assert_eq!(t.marks[0].address.as_deref(), Some(A0_BC));
        // The forge-held state convention hashes a JSON record: other bytes,
        // other address.
        let t = parse_repo_trail(&doc("tbtc4"), "main").unwrap();
        let forge_held = solid_pod_rs::mrc20::bt_address(
            BASE,
            &[format!(
                r#"{{"commit":"{C0}","repo":"casey/agent","branch":"main"}}"#
            )],
            "testnet4",
        )
        .unwrap();
        assert_ne!(t.marks[0].address.as_deref(), Some(forge_held.as_str()));
    }

    #[cfg(feature = "anchoring")]
    #[test]
    fn unknown_chain_has_programs_but_no_address() {
        let t = parse_repo_trail(&doc("regtest"), "main").unwrap();
        assert_eq!(t.marks[0].program.as_deref(), Some(P0));
        assert!(t.marks.iter().all(|m| m.address.is_none()));
    }

    #[cfg(not(feature = "anchoring"))]
    #[test]
    fn without_anchoring_nothing_is_derived() {
        let t = parse_repo_trail(&doc("tbtc4"), "main").unwrap();
        assert!(t
            .marks
            .iter()
            .all(|m| m.program.is_none() && m.address.is_none()));
    }

    #[test]
    fn anchor_tags_name_the_latest_mark_and_the_genesis() {
        let t = parse_repo_trail(&doc("txbt4"), "main").unwrap();
        let url = "https://forge.example/forge/casey/agent/blocktrails.json";
        let tags = anchor_tags(&t.anchor_facts(url).unwrap());
        let val = |k: &str| tags.iter().find(|t| t[0] == k).unwrap()[1..].to_vec();
        assert_eq!(val("chain"), ["txbt4"]);
        assert_eq!(
            val("txo"),
            [format!("txo:txbt4:{}:0", txid_b())],
            "the latest mark, not the genesis"
        );
        assert_eq!(val("commit"), [C1]);
        assert_eq!(val("anchor"), ["txbt4".to_string(), txid_a()]);
        assert_eq!(val("r"), [url]);
    }

    #[test]
    fn a_trail_with_no_onchain_mark_names_no_anchor() {
        let raw = json!({
            "@type": "Blocktrail", "profile": "gitmark", "pubkeyBase": BASE, "chain": "tbtc4",
            "states": [C0], "txo": [],
        })
        .to_string();
        let t = parse_repo_trail(&raw, "main").unwrap();
        assert!(t.anchor_facts("https://x").is_none());
    }

    #[tokio::test]
    async fn reads_the_trail_from_a_bare_repository_and_ignores_its_absence() {
        use std::process::Command;
        let git_ok = Command::new("git").arg("--version").output().is_ok();
        if !git_ok {
            return;
        }
        let td = tempfile::tempdir().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("agent.git");
        let run = |dir: &Path, args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
        };
        std::fs::create_dir(&work).unwrap();
        run(&work, &["init", "--quiet", "-b", "main"]);
        std::fs::write(work.join("a.txt"), "first\n").unwrap();
        run(&work, &["add", "-A"]);
        run(&work, &["commit", "--quiet", "-m", "first"]);
        run(
            td.path(),
            &[
                "clone",
                "--quiet",
                "--bare",
                work.to_str().unwrap(),
                "agent.git",
            ],
        );
        // no trail file yet
        assert!(read_repo_trail(&bare, "main").await.is_none());

        std::fs::write(work.join(TRAIL_FILE), doc("txbt4")).unwrap();
        run(&work, &["add", "-A"]);
        run(&work, &["commit", "--quiet", "-m", "trail"]);
        run(&work, &["push", "--quiet", bare.to_str().unwrap(), "main"]);
        let t = read_repo_trail(&bare, "main").await.unwrap();
        assert_eq!(t.marks.len(), 2);
        // a hostile branch name never reaches git
        assert!(read_repo_trail(&bare, "--output=/etc/x").await.is_none());
    }
}
