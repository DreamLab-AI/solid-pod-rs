//! Forge configuration and the chain/mainnet policy guard.
//!
//! Field defaults mirror the JSS `forge` plugin config surface
//! (README §Configuration) — cited by name only. All bounds that keep
//! the read-time body fetch cheap and DoS-resistant live here.

use crate::error::ForgeError;

/// All tunables for a [`crate::ForgeService`].
#[derive(Debug, Clone)]
pub struct ForgeConfig {
    /// URL prefix the forge is mounted under (default `/forge`). No
    /// trailing slash.
    pub prefix: String,
    /// Time-to-live for a minted forge push token, in seconds.
    pub token_ttl_secs: u64,
    /// Per-body byte cap when re-fetching pod-hosted issue/PR bodies
    /// (default 64 KiB).
    pub max_body_bytes: usize,
    /// Parallelism for the read-time body fetch (default 8).
    pub fetch_concurrency: usize,
    /// Per-body fetch timeout, seconds (default 8).
    pub fetch_timeout_secs: u64,
    /// Hard cap on thread pointers materialised in one read (default 500).
    pub thread_cap: usize,
    /// Bitcoin chain the mark trail targets. `"tbtc4"` (testnet4) by
    /// default; mainnet (`"btc"`/`"mainnet"`) is refused unless
    /// [`ForgeConfig::allow_mainnet`] is set.
    pub default_chain: String,
    /// Fail-closed mainnet guard. When `false`, [`Self::chain_allowed`] rejects
    /// any mainnet chain string. Mark custody here is testnet-grade.
    pub allow_mainnet: bool,
    /// Opt-in relays the NIP-34 announcement is published to. Empty =
    /// build/sign only, never publish. Only `ws://` and `wss://` entries
    /// are used (JSS `announceRelays`).
    pub announce_relays: Vec<String>,
    /// The forge-instance NIP-34 signing key (JSS `announceKey`): 32-byte
    /// hex. When unset or malformed the key persisted at
    /// `plugin_dir/announce-key` is used, generated once. Its `Debug`
    /// output is redacted.
    pub announce_key: Option<AnnounceKey>,
    /// Show the Anchors tab on every repository page, not only on
    /// repositories that already carry a trail (JSS `anchoringUi`). The
    /// `/marks` page then carries the Enable pitch where anchoring is off.
    /// Default `false`. Needs the `anchoring` feature to link anywhere.
    pub anchoring_ui: bool,
    /// Sparse marking (JSS `sparseMarks`): a trailing *unfunded* mark is
    /// re-targeted at each new default-branch tip instead of stacking a new
    /// one, so anchoring HEAD costs one transaction however many commits
    /// landed. Default `false`.
    pub sparse_marks: bool,
    /// JSS `privateRepos`: when `true` every read (git, HTML, JSON) is
    /// owner-only. Default `false`.
    pub private_repos: bool,
    /// JSS `baseUrl`: public origin used for absolute clone and hosted-body
    /// URLs (reverse-proxy override). `None` falls back to the request's
    /// `host_url`.
    pub base_url: Option<String>,
    /// JSS `loopbackUrl`: origin of the host's own HTTP surface for pod
    /// body reads. Informational for embedders that build a
    /// [`crate::LoopbackFetch`]; `None` means "derive it".
    pub loopback_url: Option<String>,
    /// JSS `cspConnect`: extra `http(s)` origins admitted into the
    /// `connect-src` of the page CSP (see [`crate::xlogin::build_csp`]).
    pub csp_connect: Vec<String>,
    /// JSS `openEdit`: when `true`, the web-edit and preview endpoints
    /// (`POST api/repos/<o>/<n>/edit` and `/preview`) accept **anonymous**
    /// callers on **any** repository. Demo use only; default `false`, and
    /// [`crate::ForgeService::new`] logs a loud warning when it is on.
    pub open_edit: bool,
}

/// A 32-byte hex secret key supplied through configuration.
///
/// The value is held verbatim and is never printed: `Debug` redacts it, so a
/// logged [`ForgeConfig`] cannot leak the forge's NIP-34 identity.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::config::AnnounceKey;
///
/// let key = AnnounceKey::new("11".repeat(32));
/// assert!(!format!("{key:?}").contains("1111"));
/// assert_eq!(key.valid_hex(), Some("11".repeat(32)));
/// assert_eq!(AnnounceKey::new("not hex").valid_hex(), None);
/// ```
#[derive(Clone)]
pub struct AnnounceKey(String);

impl AnnounceKey {
    /// Wrap a configured key string (validated later by [`Self::valid_hex`]).
    #[must_use]
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// The key as lowercase 64-character hex, or `None` when it is not
    /// exactly 32 bytes of hex (JSS then falls back to the persisted key).
    #[must_use]
    pub fn valid_hex(&self) -> Option<String> {
        let lc = self.0.to_ascii_lowercase();
        (lc.len() == 64 && lc.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(lc)
    }
}

impl std::fmt::Debug for AnnounceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnnounceKey(<redacted>)")
    }
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            prefix: "/forge".to_string(),
            token_ttl_secs: 3600,
            max_body_bytes: 64 * 1024,
            fetch_concurrency: 8,
            fetch_timeout_secs: 8,
            thread_cap: 500,
            default_chain: "tbtc4".to_string(),
            allow_mainnet: false,
            announce_relays: Vec::new(),
            announce_key: None,
            anchoring_ui: false,
            sparse_marks: false,
            private_repos: false,
            base_url: None,
            loopback_url: None,
            open_edit: false,
            csp_connect: Vec::new(),
        }
    }
}

/// Chain strings this build treats as Bitcoin mainnet (custody refused
/// unless explicitly allowed).
///
/// The JSS `MAINNET_CHAINS` set is `btc`, `mainnet`, `bitcoin` and `xbt`;
/// `main` is kept as an extra fail-closed spelling (it is not a *known* chain,
/// so [`chain_hrp`] refuses it anyway).
const MAINNET_ALIASES: &[&str] = &["btc", "bitcoin", "mainnet", "xbt", "main"];

/// The bech32 human-readable part of a chain token's P2TR addresses, or
/// `None` for a chain this forge does not know (JSS `CHAIN_HRP`).
///
/// Matching is case-insensitive.
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::config::chain_hrp;
///
/// assert_eq!(chain_hrp("tbtc4"), Some("tb"));
/// assert_eq!(chain_hrp("XBT"), Some("bc"));
/// assert_eq!(chain_hrp("regtest"), Some("bcrt"));
/// assert_eq!(chain_hrp("dogecoin"), None);
/// ```
#[must_use]
pub fn chain_hrp(chain: &str) -> Option<&'static str> {
    match chain.to_ascii_lowercase().as_str() {
        "btc" | "mainnet" | "bitcoin" | "xbt" => Some("bc"),
        "tbtc4" | "tbtc3" | "signet" | "txbt4" => Some("tb"),
        "regtest" => Some("bcrt"),
        _ => None,
    }
}

/// The chain tokens [`chain_hrp`] knows, for error messages.
pub const KNOWN_CHAINS: &[&str] = &[
    "btc", "mainnet", "bitcoin", "tbtc4", "tbtc3", "signet", "regtest", "txbt4", "xbt",
];

impl ForgeConfig {
    /// Normalise the configured prefix: ensure a single leading slash and
    /// no trailing slash. `""` and `"/"` both normalise to `""` (root
    /// mount).
    #[must_use]
    pub fn normalized_prefix(&self) -> String {
        let trimmed = self.prefix.trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("/{trimmed}")
        }
    }

    /// Is `chain` permitted under the current mainnet policy? Mainnet
    /// aliases are refused unless [`allow_mainnet`](Self::allow_mainnet).
    #[must_use]
    pub fn chain_allowed(&self, chain: &str) -> bool {
        let lc = chain.to_ascii_lowercase();
        if MAINNET_ALIASES.contains(&lc.as_str()) {
            self.allow_mainnet
        } else {
            true
        }
    }

    /// Check [`Self::default_chain`] the way JSS `activate` does, before any
    /// other work: a mainnet chain is an error unless
    /// [`allow_mainnet`](Self::allow_mainnet), and a chain with no known
    /// address prefix is an error too (no address beats a wrong-network
    /// address someone might fund).
    ///
    /// # Errors
    ///
    /// [`ForgeError::BadRequest`] naming the stakes (`MAINNET`, `allow_mainnet`)
    /// or the unknown chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use solid_pod_rs_forge::ForgeConfig;
    ///
    /// assert!(ForgeConfig::default().validate_chain().is_ok());
    /// let mainnet = ForgeConfig { default_chain: "xbt".into(), ..Default::default() };
    /// assert!(mainnet.validate_chain().unwrap_err().to_string().contains("MAINNET"));
    /// let unknown = ForgeConfig { default_chain: "dogecoin".into(), ..Default::default() };
    /// assert!(unknown.validate_chain().unwrap_err().to_string().contains("unknown"));
    /// ```
    pub fn validate_chain(&self) -> Result<(), ForgeError> {
        let chain = &self.default_chain;
        if !self.chain_allowed(chain) {
            return Err(ForgeError::BadRequest(format!(
                "forge: config.chain \"{chain}\" is Bitcoin MAINNET: refusing to derive mainnet \
anchor addresses. The forge holds the trail key server-side (testnet posture) and never \
verifies or broadcasts; set allow_mainnet only if you accept that custody"
            )));
        }
        if chain_hrp(chain).is_none() {
            return Err(ForgeError::BadRequest(format!(
                "forge: unknown config.chain \"{chain}\" (supported: {})",
                KNOWN_CHAINS.join(", ")
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_testnet_and_bounded() {
        let c = ForgeConfig::default();
        assert_eq!(c.prefix, "/forge");
        assert_eq!(c.default_chain, "tbtc4");
        assert!(!c.allow_mainnet);
        assert_eq!(c.max_body_bytes, 64 * 1024);
        assert_eq!(c.thread_cap, 500);
        assert_eq!(c.fetch_concurrency, 8);
    }

    #[test]
    fn mainnet_guard_fails_closed() {
        let c = ForgeConfig::default();
        for m in ["btc", "BTC", "Bitcoin", "mainnet", "main", "xbt", "XBT"] {
            assert!(!c.chain_allowed(m), "{m} must be refused by default");
        }
        assert!(c.chain_allowed("tbtc4"));
        assert!(c.chain_allowed("testnet"));
        assert!(c.chain_allowed("signet"));
    }

    #[test]
    fn mainnet_guard_opens_when_allowed() {
        let c = ForgeConfig {
            allow_mainnet: true,
            ..Default::default()
        };
        assert!(c.chain_allowed("btc"));
        assert!(c.chain_allowed("mainnet"));
    }

    #[test]
    fn validate_chain_refuses_mainnet_and_unknown_like_jss_activate() {
        // Transcribed from forge/test.js 'a mainnet chain without allowMainnet
        // refuses to activate, loudly' (plus xbt, which JSS also treats as mainnet).
        for chain in ["btc", "mainnet", "bitcoin", "xbt"] {
            let c = ForgeConfig {
                default_chain: chain.into(),
                ..Default::default()
            };
            let e = c.validate_chain().unwrap_err().to_string();
            assert!(e.contains("MAINNET"), "{e}");
            assert!(e.contains("allow_mainnet"), "{e}");
        }
        let unknown = ForgeConfig {
            default_chain: "dogecoin".into(),
            ..Default::default()
        };
        assert!(unknown
            .validate_chain()
            .unwrap_err()
            .to_string()
            .contains("unknown config.chain"));
        // with the override the gate opens
        let open = ForgeConfig {
            default_chain: "btc".into(),
            allow_mainnet: true,
            ..Default::default()
        };
        assert!(open.validate_chain().is_ok());
        // every testnet token is fine
        for chain in ["tbtc4", "tbtc3", "signet", "regtest", "txbt4"] {
            let c = ForgeConfig {
                default_chain: chain.into(),
                ..Default::default()
            };
            assert!(c.validate_chain().is_ok(), "{chain}");
        }
    }

    #[test]
    fn chain_hrp_table_matches_jss() {
        assert_eq!(chain_hrp("btc"), Some("bc"));
        assert_eq!(chain_hrp("xbt"), Some("bc"));
        assert_eq!(chain_hrp("txbt4"), Some("tb"));
        assert_eq!(chain_hrp("regtest"), Some("bcrt"));
        assert_eq!(chain_hrp("testnet"), None);
    }

    #[test]
    fn new_anchoring_keys_default_off() {
        let c = ForgeConfig::default();
        assert!(!c.anchoring_ui);
        assert!(!c.sparse_marks);
    }

    #[test]
    fn prefix_normalisation() {
        let mk = |p: &str| ForgeConfig {
            prefix: p.to_string(),
            ..Default::default()
        };
        assert_eq!(mk("/forge").normalized_prefix(), "/forge");
        assert_eq!(mk("forge").normalized_prefix(), "/forge");
        assert_eq!(mk("/forge/").normalized_prefix(), "/forge");
        assert_eq!(mk("/git/forge/").normalized_prefix(), "/git/forge");
        assert_eq!(mk("/").normalized_prefix(), "");
        assert_eq!(mk("").normalized_prefix(), "");
    }
}
