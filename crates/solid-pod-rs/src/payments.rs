//! HTTP 402 Payment Required — Web Ledgers + multi-chain TXO deposits.
//!
//! Implements the JSS payment architecture: per-identity satoshi
//! balances tracked via the Web Ledgers spec, multi-chain TXO deposit
//! verification, HTTP 402 negotiation, and payment-store abstraction.
//!
//! MRC20 state-chain token types ([`Mrc20Op`], [`Mrc20State`],
//! [`verify_state_link`]) are re-exported from [`crate::mrc20`] for
//! backward compatibility. The full MRC20 implementation — JCS
//! canonicalization, BIP-341 taproot key chaining, and state-chain
//! verification — lives in [`crate::mrc20`].
//!
//! All identities are `did:nostr:<hex-pubkey>` — users and agents are
//! indistinguishable at the protocol level, enabling user↔user,
//! user↔agent, and agent↔agent payments.
//!
//! Storage is abstracted via [`PaymentStore`] (`?Send` futures for
//! wasm32 compat) so CF Workers consumers back it with KV/DO while
//! native servers use filesystem or database backends.
//!
//! This module is always-compiled (part of the `core` surface). On
//! wasm32, timestamps use `js_sys::Date::now()`; on native, `SystemTime`.
//!
//! @see <https://webledgers.org>
//! @see JSS `src/handlers/pay.js`, `src/webledger.js`

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Web Ledger types (webledgers.org spec)
// ---------------------------------------------------------------------------

/// A single balance entry in the Web Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Agent URI: `did:nostr:<hex-pubkey>`.
    pub url: String,
    /// Balance — string integer (JSS compat) or multi-currency array.
    pub amount: LedgerAmount,
}

/// Balance representation — mirrors JSS's flexible amount field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LedgerAmount {
    Simple(String),
    Multi(Vec<CurrencyAmount>),
}

impl LedgerAmount {
    pub fn sats(&self) -> u64 {
        match self {
            LedgerAmount::Simple(s) => s.parse().unwrap_or(0),
            LedgerAmount::Multi(v) => v
                .iter()
                .find(|a| a.currency == "satoshi" || a.currency == "sat")
                .map(|a| a.value.parse().unwrap_or(0))
                .unwrap_or(0),
        }
    }

    pub fn set_sats(&mut self, amount: u64) {
        match self {
            LedgerAmount::Simple(s) => *s = amount.to_string(),
            LedgerAmount::Multi(v) => {
                if let Some(entry) = v
                    .iter_mut()
                    .find(|a| a.currency == "satoshi" || a.currency == "sat")
                {
                    entry.value = amount.to_string();
                } else {
                    v.push(CurrencyAmount {
                        currency: "satoshi".into(),
                        value: amount.to_string(),
                    });
                }
            }
        }
    }

    pub fn chain_balance(&self, chain: &str) -> u64 {
        match self {
            LedgerAmount::Simple(_) => 0,
            LedgerAmount::Multi(v) => v
                .iter()
                .find(|a| a.currency == chain)
                .map(|a| a.value.parse().unwrap_or(0))
                .unwrap_or(0),
        }
    }
}

/// A single currency amount within a multi-currency balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencyAmount {
    pub currency: String,
    pub value: String,
}

/// The full Web Ledger document at `/.well-known/webledgers/webledgers.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebLedger {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "type")]
    pub ledger_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(rename = "defaultCurrency")]
    pub default_currency: String,
    pub created: u64,
    pub updated: u64,
    pub entries: Vec<LedgerEntry>,
}

impl WebLedger {
    pub fn new(name: &str) -> Self {
        let now = now_secs();
        Self {
            context: "https://w3id.org/webledgers".into(),
            ledger_type: "WebLedger".into(),
            id: None,
            name: name.into(),
            description: "Paid API balance ledger".into(),
            default_currency: "satoshi".into(),
            created: now,
            updated: now,
            entries: Vec::new(),
        }
    }

    pub fn get_balance(&self, did: &str) -> u64 {
        self.entries
            .iter()
            .find(|e| e.url == did)
            .map(|e| e.amount.sats())
            .unwrap_or(0)
    }

    pub fn credit(&mut self, did: &str, amount: u64) {
        self.updated = now_secs();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.url == did) {
            let current = entry.amount.sats();
            entry.amount.set_sats(current.saturating_add(amount));
        } else {
            self.entries.push(LedgerEntry {
                entry_type: "Entry".into(),
                url: did.into(),
                amount: LedgerAmount::Simple(amount.to_string()),
            });
        }
    }

    pub fn debit(&mut self, did: &str, amount: u64) -> Result<u64, PaymentError> {
        self.updated = now_secs();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.url == did)
            .ok_or(PaymentError::InsufficientBalance {
                balance: 0,
                cost: amount,
            })?;
        let current = entry.amount.sats();
        if current < amount {
            return Err(PaymentError::InsufficientBalance {
                balance: current,
                cost: amount,
            });
        }
        entry.amount.set_sats(current - amount);
        Ok(current - amount)
    }
}

// ---------------------------------------------------------------------------
// Payment configuration
// ---------------------------------------------------------------------------

/// Pod payment configuration (mirrors JSS `--pay-*` flags).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayConfig {
    pub enabled: bool,
    pub cost_sats: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chains: Vec<ChainConfig>,
}

impl Default for PayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cost_sats: 1,
            token: None,
            chains: Vec::new(),
        }
    }
}

/// MRC20 token configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub ticker: String,
    pub rate: u64,
    pub supply: u64,
    pub issuer: String,
}

/// Chain configuration for multi-chain deposits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub id: String,
    pub unit: String,
    pub name: String,
    pub explorer_api: String,
}

impl ChainConfig {
    pub fn bitcoin_mainnet() -> Self {
        Self {
            id: "btc".into(),
            unit: "sat".into(),
            name: "Bitcoin".into(),
            explorer_api: "https://mempool.space/api".into(),
        }
    }

    pub fn bitcoin_testnet3() -> Self {
        Self {
            id: "tbtc3".into(),
            unit: "tbtc3".into(),
            name: "Bitcoin Testnet3".into(),
            explorer_api: "https://mempool.space/testnet/api".into(),
        }
    }

    pub fn bitcoin_testnet4() -> Self {
        Self {
            id: "tbtc4".into(),
            unit: "tbtc4".into(),
            name: "Bitcoin Testnet4".into(),
            explorer_api: "https://mempool.space/testnet4/api".into(),
        }
    }

    pub fn bitcoin_signet() -> Self {
        Self {
            id: "signet".into(),
            unit: "signet".into(),
            name: "Bitcoin Signet".into(),
            explorer_api: "https://mempool.space/signet/api".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP 402 response + /pay/.info
// ---------------------------------------------------------------------------

/// HTTP 402 Payment Required response body.
pub fn payment_required_body(balance: u64, cost: u64) -> serde_json::Value {
    serde_json::json!({
        "error": "Payment Required",
        "balance": balance,
        "cost": cost,
        "unit": "sat",
        "deposit": "/pay/.deposit",
        "balance_endpoint": "/pay/.balance",
        "spec": "https://webledgers.org"
    })
}

/// GET /pay/.info response body.
pub fn pay_info(config: &PayConfig) -> serde_json::Value {
    let mut info = serde_json::json!({
        "cost": config.cost_sats,
        "unit": "sat",
        "deposit": "/pay/.deposit",
        "balance": "/pay/.balance"
    });
    if let Some(ref token) = config.token {
        info["token"] = serde_json::json!({
            "ticker": token.ticker,
            "rate": token.rate,
            "buy": "/pay/.buy",
            "withdraw": "/pay/.withdraw",
            "supply": token.supply,
            "issuer": token.issuer
        });
    }
    if !config.chains.is_empty() {
        info["chains"] = serde_json::json!(
            config.chains.iter().map(|c| serde_json::json!({
                "id": c.id,
                "unit": c.unit,
                "name": c.name
            })).collect::<Vec<_>>()
        );
        info["pool"] = serde_json::json!("/pay/.pool");
    }
    info
}

/// Response headers attached to successful paid requests.
///
/// JSS parity: on every response that consumed balance, the server adds
/// `X-Balance`, `X-Cost`, and `X-Pay-Currency` headers so the client
/// can track spend without a separate `/pay/.balance` call.
///
/// Returns a `Vec<(header_name, header_value)>` that the transport layer
/// appends to the HTTP response. Framework-agnostic — actix-web, axum,
/// and Worker consumers each adapt these to their header type.
pub fn payment_response_headers(balance: u64, cost: u64, currency: &str) -> Vec<(&'static str, String)> {
    vec![
        ("X-Balance", balance.to_string()),
        ("X-Cost", cost.to_string()),
        ("X-Pay-Currency", currency.to_string()),
    ]
}

/// GET /pay/.balance response body.
pub fn balance_response(did: &str, balance: u64, cost: u64) -> serde_json::Value {
    serde_json::json!({
        "did": did,
        "balance": balance,
        "cost": cost,
        "unit": "sat"
    })
}

/// Web Ledgers discovery document.
pub fn webledgers_discovery(pod_base: &str) -> serde_json::Value {
    serde_json::json!({
        "@context": "https://w3id.org/webledgers",
        "type": "WebLedger",
        "name": "Pod Credits",
        "description": "Satoshi-denominated micropayments for pod resource access",
        "defaultCurrency": "satoshi",
        "endpoints": {
            "info": "/pay/.info",
            "balance": "/pay/.balance",
            "deposit": "/pay/.deposit",
            "ledger": "/.well-known/webledgers/webledgers.json"
        },
        "verification": {
            "method": "mempool-api",
            "url": "https://mempool.space/api/"
        },
        "server": pod_base
    })
}

// ---------------------------------------------------------------------------
// TXO deposit parsing
// ---------------------------------------------------------------------------

/// Parsed TXO deposit URI.
#[derive(Debug, Clone)]
pub struct TxoDeposit {
    pub chain: Option<String>,
    pub txid: String,
    pub vout: u32,
}

/// Parse a TXO URI: `txid:vout`, `txo:chain:txid:vout`, or `bitcoin:txid:vout`.
pub fn parse_txo_uri(input: &str) -> Result<TxoDeposit, PaymentError> {
    let trimmed = input.trim();

    // Try `txo:<chain>:<txid>:<vout>` first
    if let Some(rest) = trimmed.strip_prefix("txo:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            let chain = parts[0].to_lowercase();
            let txid = parts[1];
            let vout: u32 = parts[2]
                .parse()
                .map_err(|_| PaymentError::InvalidTxo("bad vout".into()))?;
            validate_txid(txid)?;
            return Ok(TxoDeposit {
                chain: Some(chain),
                txid: txid.to_string(),
                vout,
            });
        }
    }

    // Try `bitcoin:txid:vout`
    let cleaned = trimmed.strip_prefix("bitcoin:").unwrap_or(trimmed);
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() != 2 {
        return Err(PaymentError::InvalidTxo(
            "expected txid:vout format".into(),
        ));
    }
    let txid = parts[0];
    let vout: u32 = parts[1]
        .parse()
        .map_err(|_| PaymentError::InvalidTxo("bad vout".into()))?;
    validate_txid(txid)?;
    Ok(TxoDeposit {
        chain: None,
        txid: txid.to_string(),
        vout,
    })
}

fn validate_txid(txid: &str) -> Result<(), PaymentError> {
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PaymentError::InvalidTxo(
            "txid must be 64 hex chars".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MRC20 state chain types — re-exported from `crate::mrc20`.
// ---------------------------------------------------------------------------

/// Backward-compatibility re-exports. The canonical definitions and full
/// implementation (JCS, BIP-341, state-chain verification) live in
/// [`crate::mrc20`]. These re-exports let existing consumers that import
/// MRC20 types from `payments` continue to compile without changes.
pub use crate::mrc20::{Mrc20Op, Mrc20State, verify_state_link};

// ---------------------------------------------------------------------------
// Payment store trait (storage abstraction)
// ---------------------------------------------------------------------------

/// Abstract payment storage — backends implement this for KV/DO/FS.
#[async_trait::async_trait(?Send)]
pub trait PaymentStore: Send + Sync {
    async fn read_ledger(&self) -> Result<WebLedger, PaymentError>;
    async fn write_ledger(&self, ledger: &WebLedger) -> Result<(), PaymentError>;
    async fn check_replay(&self, key: &str) -> Result<bool, PaymentError>;
    async fn record_replay(&self, key: &str) -> Result<(), PaymentError>;
}

// ---------------------------------------------------------------------------
// DID:nostr identity helpers
// ---------------------------------------------------------------------------

/// Convert a hex pubkey to `did:nostr:<hex>`.
pub fn pubkey_to_did(pubkey: &str) -> String {
    format!("did:nostr:{pubkey}")
}

/// Extract hex pubkey from `did:nostr:<hex>`.
pub fn did_to_pubkey(did: &str) -> Option<&str> {
    did.strip_prefix("did:nostr:")
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Payment-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("insufficient balance: have {balance}, need {cost}")]
    InsufficientBalance { balance: u64, cost: u64 },

    #[error("invalid TXO: {0}")]
    InvalidTxo(String),

    #[error("invalid MRC20 state: {0}")]
    InvalidState(String),

    #[error("replay detected: {0}")]
    Replay(String),

    #[error("payment store: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ledger_empty() {
        let ledger = WebLedger::new("Test");
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.default_currency, "satoshi");
        assert_eq!(ledger.context, "https://w3id.org/webledgers");
    }

    #[test]
    fn credit_creates_entry() {
        let mut ledger = WebLedger::new("Test");
        ledger.credit("did:nostr:abc123", 1000);
        assert_eq!(ledger.get_balance("did:nostr:abc123"), 1000);
    }

    #[test]
    fn debit_reduces_balance() {
        let mut ledger = WebLedger::new("Test");
        ledger.credit("did:nostr:abc123", 1000);
        let remaining = ledger.debit("did:nostr:abc123", 100).unwrap();
        assert_eq!(remaining, 900);
        assert_eq!(ledger.get_balance("did:nostr:abc123"), 900);
    }

    #[test]
    fn debit_rejects_insufficient() {
        let mut ledger = WebLedger::new("Test");
        ledger.credit("did:nostr:abc123", 50);
        let err = ledger.debit("did:nostr:abc123", 100).unwrap_err();
        assert!(matches!(
            err,
            PaymentError::InsufficientBalance {
                balance: 50,
                cost: 100
            }
        ));
    }

    #[test]
    fn debit_rejects_unknown_did() {
        let mut ledger = WebLedger::new("Test");
        let err = ledger.debit("did:nostr:unknown", 1).unwrap_err();
        assert!(matches!(
            err,
            PaymentError::InsufficientBalance {
                balance: 0,
                cost: 1
            }
        ));
    }

    #[test]
    fn credit_accumulates() {
        let mut ledger = WebLedger::new("Test");
        ledger.credit("did:nostr:abc", 100);
        ledger.credit("did:nostr:abc", 200);
        assert_eq!(ledger.get_balance("did:nostr:abc"), 300);
    }

    #[test]
    fn agent_agent_payment() {
        let mut ledger = WebLedger::new("Test");
        let agent_a = "did:nostr:aaaa";
        let agent_b = "did:nostr:bbbb";
        ledger.credit(agent_a, 500);
        ledger.debit(agent_a, 100).unwrap();
        ledger.credit(agent_b, 100);
        assert_eq!(ledger.get_balance(agent_a), 400);
        assert_eq!(ledger.get_balance(agent_b), 100);
    }

    #[test]
    fn parse_txo_bare() {
        let txid = "a".repeat(64);
        let uri = format!("{txid}:0");
        let txo = parse_txo_uri(&uri).unwrap();
        assert!(txo.chain.is_none());
        assert_eq!(txo.txid, txid);
        assert_eq!(txo.vout, 0);
    }

    #[test]
    fn parse_txo_with_chain() {
        let txid = "b".repeat(64);
        let uri = format!("txo:tbtc4:{txid}:1");
        let txo = parse_txo_uri(&uri).unwrap();
        assert_eq!(txo.chain.as_deref(), Some("tbtc4"));
        assert_eq!(txo.txid, txid);
        assert_eq!(txo.vout, 1);
    }

    #[test]
    fn parse_txo_bitcoin_prefix() {
        let txid = "c".repeat(64);
        let uri = format!("bitcoin:{txid}:2");
        let txo = parse_txo_uri(&uri).unwrap();
        assert!(txo.chain.is_none());
        assert_eq!(txo.vout, 2);
    }

    #[test]
    fn parse_txo_rejects_short_txid() {
        assert!(parse_txo_uri("abc123:0").is_err());
    }

    #[test]
    fn pay_info_basic() {
        let config = PayConfig::default();
        let info = pay_info(&config);
        assert_eq!(info["cost"], 1);
        assert_eq!(info["unit"], "sat");
        assert!(info.get("token").is_none());
    }

    #[test]
    fn pay_info_with_token() {
        let config = PayConfig {
            enabled: true,
            cost_sats: 2,
            token: Some(TokenConfig {
                ticker: "PODS".into(),
                rate: 10,
                supply: 10000,
                issuer: "025e60b6".into(),
            }),
            chains: vec![ChainConfig::bitcoin_testnet4()],
        };
        let info = pay_info(&config);
        assert_eq!(info["token"]["ticker"], "PODS");
        assert!(info["chains"].as_array().is_some());
    }

    #[test]
    fn ledger_serialization_roundtrip() {
        let mut ledger = WebLedger::new("Test");
        ledger.credit("did:nostr:abc", 42);
        let json = serde_json::to_string(&ledger).unwrap();
        let parsed: WebLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get_balance("did:nostr:abc"), 42);
    }

    #[test]
    fn pubkey_did_roundtrip() {
        let pk = "abc123def456";
        let did = pubkey_to_did(pk);
        assert_eq!(did, "did:nostr:abc123def456");
        assert_eq!(did_to_pubkey(&did), Some(pk));
    }

    #[test]
    fn multi_currency_balance() {
        let entry = LedgerEntry {
            entry_type: "Entry".into(),
            url: "did:nostr:abc".into(),
            amount: LedgerAmount::Multi(vec![
                CurrencyAmount {
                    currency: "satoshi".into(),
                    value: "100".into(),
                },
                CurrencyAmount {
                    currency: "tbtc4".into(),
                    value: "50".into(),
                },
            ]),
        };
        assert_eq!(entry.amount.sats(), 100);
        assert_eq!(entry.amount.chain_balance("tbtc4"), 50);
        assert_eq!(entry.amount.chain_balance("ltc"), 0);
    }

    #[test]
    fn default_config_disabled() {
        let config = PayConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.cost_sats, 1);
    }

    #[test]
    fn payment_response_headers_returns_three_headers() {
        let headers = super::payment_response_headers(950, 50, "sat");
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], ("X-Balance", "950".to_string()));
        assert_eq!(headers[1], ("X-Cost", "50".to_string()));
        assert_eq!(headers[2], ("X-Pay-Currency", "sat".to_string()));
    }

    #[test]
    fn payment_response_headers_zero_balance() {
        let headers = super::payment_response_headers(0, 1, "sat");
        assert_eq!(headers[0].1, "0");
    }
}
