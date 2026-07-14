//! Forge configuration and the chain/mainnet policy guard.
//!
//! Field defaults mirror the JSS `forge` plugin config surface
//! (README §Configuration) — cited by name only. All bounds that keep
//! the read-time body fetch cheap and DoS-resistant live here.

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
    /// Fail-closed mainnet guard. When `false`, [`chain_allowed`] rejects
    /// any mainnet chain string. Mark custody here is testnet-grade.
    pub allow_mainnet: bool,
    /// Opt-in relays the NIP-34 announcement is published to. Empty =
    /// build/sign only, never publish.
    pub announce_relays: Vec<String>,
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
        }
    }
}

/// Chain strings this build treats as Bitcoin mainnet (custody refused
/// unless explicitly allowed).
const MAINNET_ALIASES: &[&str] = &["btc", "bitcoin", "mainnet", "main"];

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
        for m in ["btc", "BTC", "Bitcoin", "mainnet", "main"] {
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
