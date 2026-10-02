//! MRC20 trail persistence — the server-side load/save for a token's
//! Bitcoin-anchored state chain (ADR-059 Phase 4; JSS `token.js:189-208`).
//!
//! A trail lives at `/.well-known/token/{ticker}.json` in pod storage. JSS
//! persists the issuer **private key** straight inside the trail JSON
//! (`token.js:294`) so `transferToken` can re-sign the next state. We keep the
//! same on-disk shape but model it as a [`StoredTrail`](crate::trail_store::StoredTrail) = the public
//! [`Mrc20Trail`](solid_pod_rs::mrc20::Mrc20Trail) plus a `privkey` (and a `date_created` the library type does
//! not carry), so the secret never leaks onto the shared `Mrc20Trail` type that
//! flows through wasm/core and the portable proof.
//!
//! Native-only: it uses `Arc<dyn Storage>` (the pod's filesystem/cloud
//! backend). wasm consumers never compile this.

use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use solid_pod_rs::blocktrail::{network_for_txo_chain, Blocktrail};
use solid_pod_rs::mrc20::{Mrc20State, Mrc20Trail};
use solid_pod_rs::payments::PaymentError;
use solid_pod_rs::storage::Storage;

/// Pod-storage path of a trail file (JSS `token.js:194-196`). Ticker is
/// lower-cased so `PROV` and `prov` resolve to one file.
#[must_use]
pub fn trail_path(ticker: &str) -> String {
    format!("/.well-known/token/{}.json", ticker.to_lowercase())
}

/// The persisted trail — the public [`Mrc20Trail`] plus the issuer secret and
/// creation timestamp (JSS stores all of these in one JSON blob,
/// `token.js:290-303`). Serialises with camelCase keys to match the JSS file
/// format byte-for-byte so a JSS-written trail loads here and vice versa.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTrail {
    pub ticker: String,
    pub name: String,
    pub supply: u64,
    /// Issuer private key (64-char hex). **Secret** — never placed on the
    /// public `Mrc20Trail` nor in any portable proof.
    pub privkey: String,
    pub pubkey_base: String,
    pub states: Vec<Mrc20State>,
    pub state_strings: Vec<String>,
    pub current_txid: String,
    pub current_vout: u32,
    pub current_amount: u64,
    pub network: String,
    #[serde(default)]
    pub date_created: String,
}

impl StoredTrail {
    /// Project to the public [`Mrc20Trail`] (drops the secret `privkey`).
    #[must_use]
    pub fn to_public(&self) -> Mrc20Trail {
        Mrc20Trail {
            ticker: self.ticker.clone(),
            name: self.name.clone(),
            supply: self.supply,
            pubkey_base: self.pubkey_base.clone(),
            states: self.states.clone(),
            state_strings: self.state_strings.clone(),
            current_txid: self.current_txid.clone(),
            current_vout: self.current_vout,
            current_amount: self.current_amount,
            network: self.network.clone(),
            date_created: self.date_created.clone(),
        }
    }

    /// Re-absorb a public [`Mrc20Trail`] (e.g. the appended trail returned by a
    /// transfer/anchor) while keeping this trail's secret `privkey`.
    pub fn merge_public(&mut self, public: &Mrc20Trail) {
        self.states = public.states.clone();
        self.state_strings = public.state_strings.clone();
        self.current_txid = public.current_txid.clone();
        self.current_vout = public.current_vout;
        self.current_amount = public.current_amount;
        self.supply = public.supply;
    }
}

/// Load a trail for `ticker`, or `None` if it does not exist (JSS
/// `loadTrail`, `token.js:198-203` — a read failure is "no trail", not an
/// error).
pub async fn load_trail(
    storage: &Arc<dyn Storage>,
    ticker: &str,
) -> Result<Option<StoredTrail>, PaymentError> {
    match storage.get(&trail_path(ticker)).await {
        Ok((bytes, _meta)) => {
            let trail: StoredTrail = serde_json::from_slice(&bytes)
                .map_err(|e| PaymentError::Store(format!("malformed trail {ticker}: {e}")))?;
            Ok(Some(trail))
        }
        Err(_) => Ok(None),
    }
}

/// Persist a trail (JSS `saveTrail`, `token.js:205-208`). Pretty-printed to
/// match the JSS `JSON.stringify(trail, null, 2)` file format.
pub async fn save_trail(
    storage: &Arc<dyn Storage>,
    trail: &StoredTrail,
) -> Result<(), PaymentError> {
    let body = serde_json::to_vec_pretty(trail)
        .map_err(|e| PaymentError::Store(format!("serialise trail: {e}")))?;
    storage
        .put(
            &trail_path(&trail.ticker),
            Bytes::from(body),
            "application/json",
        )
        .await
        .map_err(|e| PaymentError::Store(format!("save trail: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Git-mark trails (new trails' profile)
// ---------------------------------------------------------------------------

/// The trail name a pod anchors under when nothing names one.
pub const DEFAULT_GITMARK_TRAIL: &str = "prov";

/// Pod-storage path of a git-mark trail file (with its base secret). The name
/// is lower-cased, as [`trail_path`] does for tickers.
#[must_use]
pub fn gitmark_trail_path(name: &str) -> String {
    format!("/.well-known/gitmark/{}.json", name.to_lowercase())
}

/// Pod-storage path of a git-mark trail's public `blocktrails.json` (no
/// secret), the file a verifier reads.
#[must_use]
pub fn gitmark_blocktrails_path(name: &str) -> String {
    format!(
        "/.well-known/gitmark/{}/blocktrails.json",
        name.to_lowercase()
    )
}

/// A persisted git-mark trail: the public [`Blocktrail`] (§5.2 shape) plus
/// the base key's secret, which spends each mark to the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredGitmarkTrail {
    /// The trail's name (what an anchor's `ticker` names).
    pub name: String,
    /// The base key's secret (64-char hex). **Secret**: never in the public
    /// `blocktrails.json`.
    pub privkey: String,
    /// The trail as a verifier reads it.
    pub trail: Blocktrail,
    /// Creation timestamp, set by the caller.
    #[serde(default)]
    pub date_created: String,
}

impl StoredGitmarkTrail {
    /// The network name of the trail's chain (`testnet4` for `tbtc4`), as
    /// [`solid_pod_rs::mrc20::bt_address`] takes it; empty when it names none.
    #[must_use]
    pub fn network(&self) -> String {
        self.trail
            .chain
            .as_deref()
            .map(network_for_txo_chain)
            .unwrap_or_default()
    }
}

/// Load the git-mark trail `name`, or `None` if there is none.
pub async fn load_gitmark_trail(
    storage: &Arc<dyn Storage>,
    name: &str,
) -> Result<Option<StoredGitmarkTrail>, PaymentError> {
    match storage.get(&gitmark_trail_path(name)).await {
        Ok((bytes, _meta)) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| PaymentError::Store(format!("malformed git-mark trail {name}: {e}"))),
        Err(_) => Ok(None),
    }
}

/// Persist a git-mark trail and publish its `blocktrails.json` beside it.
pub async fn save_gitmark_trail(
    storage: &Arc<dyn Storage>,
    stored: &StoredGitmarkTrail,
) -> Result<(), PaymentError> {
    let body = serde_json::to_vec_pretty(stored)
        .map_err(|e| PaymentError::Store(format!("serialise git-mark trail: {e}")))?;
    storage
        .put(
            &gitmark_trail_path(&stored.name),
            Bytes::from(body),
            "application/json",
        )
        .await
        .map_err(|e| PaymentError::Store(format!("save git-mark trail: {e}")))?;
    let public = serde_json::to_vec_pretty(&stored.trail)
        .map_err(|e| PaymentError::Store(format!("serialise blocktrails.json: {e}")))?;
    storage
        .put(
            &gitmark_blocktrails_path(&stored.name),
            Bytes::from(public),
            "application/json",
        )
        .await
        .map_err(|e| PaymentError::Store(format!("save blocktrails.json: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solid_pod_rs::mrc20::MRC20_PROFILE;
    use solid_pod_rs::storage::memory::MemoryBackend;

    fn genesis() -> Mrc20State {
        Mrc20State {
            profile: MRC20_PROFILE.into(),
            prev: "0".repeat(64),
            seq: 0,
            ticker: Some("PROV".into()),
            name: Some("Prov".into()),
            decimals: Some(0),
            supply: Some(1000),
            balances: Some(std::collections::BTreeMap::from([("02ab".into(), 1000)])),
            ops: vec![],
            anchor: None,
        }
    }

    fn sample() -> StoredTrail {
        StoredTrail {
            ticker: "PROV".into(),
            name: "Prov".into(),
            supply: 1000,
            privkey: "07".repeat(32),
            pubkey_base: "02".to_string() + &"ab".repeat(32),
            states: vec![genesis()],
            state_strings: vec!["{\"seq\":0}".into()],
            current_txid: "ab".repeat(32),
            current_vout: 0,
            current_amount: 9700,
            network: "testnet4".into(),
            date_created: "2026-06-13T00:00:00Z".into(),
        }
    }

    #[test]
    fn trail_path_lowercases() {
        assert_eq!(trail_path("PROV"), "/.well-known/token/prov.json");
        assert_eq!(trail_path("prov"), "/.well-known/token/prov.json");
    }

    #[test]
    fn to_public_drops_privkey() {
        let t = sample();
        let public = t.to_public();
        // The public type has no privkey field; round-trip its JSON and assert
        // the secret is absent.
        let json = serde_json::to_string(&public).unwrap();
        assert!(
            !json.contains(&t.privkey),
            "privkey must not appear in public trail"
        );
        assert_eq!(public.ticker, "PROV");
        assert_eq!(public.current_amount, 9700);
    }

    #[test]
    fn stored_trail_uses_camelcase_keys() {
        // JSS file-format parity: keys are camelCase (pubkeyBase, stateStrings…).
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains("\"pubkeyBase\""));
        assert!(json.contains("\"stateStrings\""));
        assert!(json.contains("\"currentTxid\""));
        assert!(json.contains("\"dateCreated\""));
    }

    #[tokio::test]
    async fn load_missing_trail_is_none() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
        let got = load_trail(&storage, "NOPE").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn save_then_load_round_trips() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
        save_trail(&storage, &sample()).await.unwrap();
        let got = load_trail(&storage, "PROV")
            .await
            .unwrap()
            .expect("trail present");
        assert_eq!(got.ticker, "PROV");
        assert_eq!(got.privkey, "07".repeat(32));
        assert_eq!(got.states.len(), 1);
        // Lower-cased lookup also resolves.
        assert!(load_trail(&storage, "prov").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn merge_public_keeps_secret() {
        let mut t = sample();
        let secret = t.privkey.clone();
        let mut public = t.to_public();
        public.current_txid = "ff".repeat(32);
        public.current_amount = 9400;
        public.states.push(genesis()); // simulate an appended state
        t.merge_public(&public);
        assert_eq!(t.privkey, secret, "secret retained across merge");
        assert_eq!(t.current_txid, "ff".repeat(32));
        assert_eq!(t.current_amount, 9400);
        assert_eq!(t.states.len(), 2);
    }

    #[tokio::test]
    async fn gitmark_trail_round_trips_and_publishes_no_secret() {
        use solid_pod_rs::blocktrail::BlocktrailTxo;
        let storage: Arc<dyn Storage> = Arc::new(MemoryBackend::new());
        let commit = "9adc596cfd1100333393a12f2f41b2d820f16d0b";
        let stored = StoredGitmarkTrail {
            name: "Prov".into(),
            privkey: "07".repeat(32),
            trail: Blocktrail::gitmark(
                "02".to_string() + &"ab".repeat(32),
                "tbtc4",
                vec![commit.into()],
                vec![BlocktrailTxo::new("tbtc4", "cd".repeat(32), 0).with_commit(commit)],
            ),
            date_created: "2026-10-02T00:00:00Z".into(),
        };
        assert_eq!(stored.network(), "testnet4");
        save_gitmark_trail(&storage, &stored).await.unwrap();
        let back = load_gitmark_trail(&storage, "prov").await.unwrap().unwrap();
        assert_eq!(back.trail, stored.trail);
        assert_eq!(back.privkey, stored.privkey);
        let (public, _) = storage
            .get(&gitmark_blocktrails_path("PROV"))
            .await
            .unwrap();
        let public = String::from_utf8(public.to_vec()).unwrap();
        assert!(
            !public.contains(&stored.privkey),
            "the secret is never published"
        );
        let parsed: Blocktrail = serde_json::from_str(&public).unwrap();
        assert_eq!(parsed, stored.trail);
        assert!(load_gitmark_trail(&storage, "none")
            .await
            .unwrap()
            .is_none());
    }
}
