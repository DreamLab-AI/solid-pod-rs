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

/// The fixed fields a ledger is born with (solidpayorg/teller `newLedger`).
///
/// A ledger's identity is `sha256(JCS(genesis))`, never a hash of the moving
/// balances: two documents with the same genesis are the same ledger at
/// different moments, and a document whose `hash` is not the hash of its
/// genesis is not that ledger ([`WebLedger::check_genesis`]).
///
/// ```
/// use solid_pod_rs::payments::LedgerGenesis;
///
/// let operator = format!("did:nostr:{}", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
/// let genesis = LedgerGenesis::new(&operator, "Pod Credits", "satoshi", 1_759_300_000, 1).unwrap();
/// // The value solidpayorg/teller 7c00cea computes for the same genesis.
/// assert_eq!(
///     genesis.hash(),
///     "6edef538d26a824df5cad902ffd2d767639dddec256af206f4fafb2777cb78fe"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerGenesis {
    /// The operator's account, `did:nostr:<64 hex>`.
    pub operator: String,
    /// The ledger's name, 1 to 80 characters.
    pub name: String,
    /// The ledger's unit (its `defaultCurrency`).
    pub currency: String,
    /// Creation time, Unix seconds.
    pub created: u64,
    /// Confirmations a deposit needs before it is credited.
    pub confirmations: u64,
}

impl LedgerGenesis {
    /// Build a genesis, normalising `operator` to `did:nostr:<x>` and
    /// refusing an empty name or one longer than 80 characters (teller
    /// `newLedger`).
    pub fn new(
        operator: &str,
        name: &str,
        currency: &str,
        created: u64,
        confirmations: u64,
    ) -> Result<Self, PaymentError> {
        let genesis = Self {
            operator: account_of(operator)?,
            name: name.to_string(),
            currency: currency.to_string(),
            created,
            confirmations,
        };
        genesis.validate()?;
        Ok(genesis)
    }

    fn validate(&self) -> Result<(), PaymentError> {
        let chars = self.name.chars().count();
        if chars == 0 || chars > 80 {
            return Err(PaymentError::InvalidState(
                "a ledger has a name of up to 80 characters".into(),
            ));
        }
        Ok(())
    }

    /// The ledger hash: lowercase hex `sha256(JCS(genesis))`.
    pub fn hash(&self) -> String {
        let value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        crate::mrc20::sha256_hex(&crate::mrc20::jcs(&value))
    }
}

/// A deposit's receipt: the outpoint that paid it (teller `credit`).
///
/// An outpoint credits its account once; [`WebLedger::credit_by_outpoint`]
/// refuses a second credit for an outpoint already recorded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositReceipt {
    /// `<txid>:<vout>`, lowercase hex txid.
    pub outpoint: String,
    /// The credited account, `did:nostr:<64 hex>`.
    pub account: String,
    /// The credited amount in `currency` units.
    pub value: u64,
    /// Block height of the paying output, when known.
    #[serde(default)]
    pub height: Option<u64>,
    /// Unix seconds at which the credit was applied.
    pub at: u64,
    /// The unit credited when it is not the ledger's own (an MRC20 ticker).
    /// Absent for the ledger's default currency, as teller writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

/// A payout's receipt: the debit a withdrawal made (teller `debit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutReceipt {
    /// The payout id the debit is applied once by (here, its txid).
    pub id: String,
    /// The debited account, `did:nostr:<64 hex>`.
    pub account: String,
    /// The debited amount in satoshis.
    pub value: u64,
    /// Where the payout went, when recorded.
    #[serde(default)]
    pub to: Option<String>,
    /// The payout transaction id.
    #[serde(default)]
    pub txid: Option<String>,
    /// Unix seconds at which the debit was applied.
    pub at: u64,
}

/// Whether a receipt-keyed ledger operation changed the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptOutcome {
    /// The operation was applied and its receipt recorded.
    Applied,
    /// The receipt was already recorded; nothing changed (teller
    /// `{applied: false}`).
    AlreadyApplied,
}

/// A spend taken by [`WebLedger::charge`]; [`WebLedger::refund`] gives it
/// back. It cannot be built, cloned or deserialised outside this crate, so a
/// refund only ever returns an amount a charge actually took.
#[derive(Debug, PartialEq, Eq)]
pub struct Charge {
    account: String,
    amount: u64,
}

impl Charge {
    /// The account charged.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The amount charged, in satoshis.
    pub fn amount(&self) -> u64 {
        self.amount
    }
}

/// The full Web Ledger document at `/.well-known/webledgers/webledgers.json`.
///
/// Balances change only through receipt-keyed operations:
/// [`credit_by_outpoint`](Self::credit_by_outpoint) (the outpoint is the
/// receipt) and [`debit_by_payout`](Self::debit_by_payout) (the payout id is
/// the receipt), as in solidpayorg/teller. [`reverse_payout`](Self::reverse_payout),
/// [`charge`](Self::charge) and [`refund`](Self::refund) serve the pod's
/// broadcast recovery and access fees; none of them can raise a balance
/// beyond what a recorded deposit put there.
///
/// A ledger built with [`with_genesis`](Self::with_genesis) carries teller's
/// identity, `id = urn:webledgers:<sha256(JCS(genesis))>`; documents written
/// before the genesis existed still load, without one.
///
/// The receipt-less mutators are crate-private. Outside this crate none of
/// these compile:
///
/// ```compile_fail
/// let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
/// ledger.credit("did:nostr:aaaa", 1_000);
/// ```
///
/// ```compile_fail
/// let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
/// let _ = ledger.debit("did:nostr:aaaa", 1);
/// ```
///
/// ```compile_fail
/// let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
/// ledger.credit_currency("did:nostr:aaaa", "PODS", 1_000);
/// ```
///
/// ```compile_fail
/// let mut ledger = solid_pod_rs::payments::WebLedger::new("Pod Credits");
/// ledger.entries.clear();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebLedger {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "type")]
    pub ledger_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "defaultCurrency")]
    pub default_currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) genesis: Option<LedgerGenesis>,
    #[serde(default)]
    pub created: u64,
    pub updated: u64,
    pub(crate) entries: Vec<LedgerEntry>,
    #[serde(default)]
    pub(crate) deposits: Vec<DepositReceipt>,
    #[serde(default)]
    pub(crate) applied: Vec<String>,
    #[serde(default)]
    pub(crate) payouts: Vec<PayoutReceipt>,
}

impl WebLedger {
    /// A new, empty ledger without a genesis (the pre-teller shape).
    pub fn new(name: &str) -> Self {
        let now = now_secs();
        Self {
            context: "https://w3id.org/webledgers".into(),
            ledger_type: "WebLedger".into(),
            id: None,
            hash: None,
            name: name.into(),
            description: "Paid API balance ledger".into(),
            default_currency: "satoshi".into(),
            genesis: None,
            created: now,
            updated: now,
            entries: Vec::new(),
            deposits: Vec::new(),
            applied: Vec::new(),
            payouts: Vec::new(),
        }
    }

    /// A new, empty ledger born with `genesis` (teller `newLedger`): its
    /// `hash` is `sha256(JCS(genesis))`, its `id` `urn:webledgers:<hash>`,
    /// its name and `defaultCurrency` those of the genesis.
    pub fn with_genesis(genesis: LedgerGenesis) -> Result<Self, PaymentError> {
        genesis.validate()?;
        let hash = genesis.hash();
        let mut ledger = Self::new(&genesis.name);
        ledger.id = Some(format!("urn:webledgers:{hash}"));
        ledger.hash = Some(hash);
        ledger.default_currency = genesis.currency.clone();
        ledger.created = genesis.created;
        ledger.updated = genesis.created;
        ledger.genesis = Some(genesis);
        Ok(ledger)
    }

    /// The ledger's `id`, when it has one.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The ledger hash recorded in the document, when it has a genesis.
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    /// The genesis the ledger was born with, if any.
    pub fn genesis(&self) -> Option<&LedgerGenesis> {
        self.genesis.as_ref()
    }

    /// The ledger hash recomputed from the genesis (teller `ledgerHash`).
    pub fn ledger_hash(&self) -> Option<String> {
        self.genesis.as_ref().map(LedgerGenesis::hash)
    }

    /// Teller `checkLedger`: a document with a genesis must record the hash
    /// of that genesis. Documents without a genesis (written before it
    /// existed) pass; a genesis without a matching hash does not.
    pub fn check_genesis(&self) -> Result<(), PaymentError> {
        let Some(genesis) = &self.genesis else {
            return Ok(());
        };
        if self.hash.as_deref() != Some(genesis.hash().as_str()) {
            return Err(PaymentError::InvalidState(
                "the ledger's hash is not the hash of its genesis".into(),
            ));
        }
        Ok(())
    }

    /// The balance entries, one per account.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Every deposit credited, by outpoint.
    pub fn deposits(&self) -> &[DepositReceipt] {
        &self.deposits
    }

    /// Every payout debited, by payout id.
    pub fn payouts(&self) -> &[PayoutReceipt] {
        &self.payouts
    }

    /// Whether `outpoint` (`<txid>:<vout>`) has already credited an account.
    pub fn has_deposit(&self, txid: &str, vout: u32) -> bool {
        let key = format!("{txid}:{vout}");
        self.deposits.iter().any(|d| d.outpoint == key)
    }

    /// Whether `currency` names this ledger's satoshi balance: `satoshi`,
    /// `sat`, or the ledger's own `defaultCurrency`.
    pub fn is_sats_unit(&self, currency: &str) -> bool {
        currency == "satoshi" || currency == "sat" || currency == self.default_currency
    }

    /// The satoshi balance of `did` (exact key match).
    pub fn get_balance(&self, did: &str) -> u64 {
        self.entries
            .iter()
            .find(|e| e.url == did)
            .map(|e| e.amount.sats())
            .unwrap_or(0)
    }

    /// Credit a deposit seen on-chain, once: the outpoint is the receipt
    /// (solidpayorg/teller `credit`, `lib/teller.mjs:40-44`).
    ///
    /// `currency` is the unit credited: the ledger's satoshi balance when
    /// [`is_sats_unit`](Self::is_sats_unit) holds, otherwise that unit's own
    /// balance (an MRC20 deposit credits its ticker, never sats). `account`
    /// is normalised as teller reads it (`did:nostr:<x>`, a bare x, or a
    /// Multikey's x). The txid must be 64 lowercase hex digits and `value` a
    /// whole number no greater than 21 million coins in satoshis.
    ///
    /// A second credit for an outpoint already recorded changes nothing and
    /// returns [`ReceiptOutcome::AlreadyApplied`], whatever its account or
    /// unit.
    ///
    /// ```
    /// use solid_pod_rs::payments::{ReceiptOutcome, WebLedger};
    ///
    /// let alice = format!("did:nostr:{}", "a".repeat(64));
    /// let txid = "ab".repeat(32);
    /// let mut ledger = WebLedger::new("Pod Credits");
    /// assert_eq!(
    ///     ledger.credit_by_outpoint(&alice, "satoshi", &txid, 0, 50_000).unwrap(),
    ///     ReceiptOutcome::Applied
    /// );
    /// assert_eq!(
    ///     ledger.credit_by_outpoint(&alice, "satoshi", &txid, 0, 50_000).unwrap(),
    ///     ReceiptOutcome::AlreadyApplied
    /// );
    /// assert_eq!(ledger.get_balance(&alice), 50_000);
    /// ```
    pub fn credit_by_outpoint(
        &mut self,
        account: &str,
        currency: &str,
        txid: &str,
        vout: u32,
        value: u64,
    ) -> Result<ReceiptOutcome, PaymentError> {
        let account = account_of(account)?;
        if txid.len() != 64 || !txid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(PaymentError::InvalidTxo(
                "a deposit is an outpoint txid:vout".into(),
            ));
        }
        if currency.is_empty() {
            return Err(PaymentError::InvalidState(
                "a deposit names its unit".into(),
            ));
        }
        check_amount(value)?;
        if self.has_deposit(txid, vout) {
            return Ok(ReceiptOutcome::AlreadyApplied);
        }
        let sats = self.is_sats_unit(currency);
        if sats {
            self.credit(&account, value);
        } else {
            self.credit_currency(&account, currency, value);
        }
        let now = now_secs();
        self.deposits.push(DepositReceipt {
            outpoint: format!("{txid}:{vout}"),
            account,
            value,
            height: None,
            at: now,
            currency: (!sats).then(|| currency.to_string()),
        });
        self.touch(now);
        Ok(ReceiptOutcome::Applied)
    }

    /// Debit a withdrawal of `amount` satoshis, once: the payout's txid is
    /// the receipt (solidpayorg/teller `debit`, `lib/teller.mjs:53-58`).
    ///
    /// Fails with [`PaymentError::InsufficientBalance`] when the account
    /// holds less than `amount`. A second debit with a payout id already
    /// applied changes nothing and returns
    /// [`ReceiptOutcome::AlreadyApplied`]. Unlike teller, no 546-sat
    /// minimum applies here: the pod's payouts include token transfers
    /// whose satoshi cost is not itself an on-chain output.
    pub fn debit_by_payout(
        &mut self,
        account: &str,
        amount: u64,
        txid: &str,
    ) -> Result<ReceiptOutcome, PaymentError> {
        let account = account_of(account)?;
        if txid.len() != 64 || !txid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(PaymentError::InvalidTxo(
                "a payout is identified by its 64-hex txid".into(),
            ));
        }
        check_amount(amount)?;
        if self.applied.iter().any(|id| id == txid) {
            return Ok(ReceiptOutcome::AlreadyApplied);
        }
        self.debit(&account, amount)?;
        let now = now_secs();
        self.applied.push(txid.to_string());
        self.payouts.push(PayoutReceipt {
            id: txid.to_string(),
            account,
            value: amount,
            to: None,
            txid: Some(txid.to_string()),
            at: now,
        });
        self.touch(now);
        Ok(ReceiptOutcome::Applied)
    }

    /// Undo a recorded payout whose transaction never reached the chain:
    /// its amount goes back to its account and its receipt is removed.
    /// Returns the amount restored, or `None` when no payout with that id is
    /// recorded (nothing changes).
    pub fn reverse_payout(&mut self, txid: &str) -> Option<u64> {
        let index = self.payouts.iter().position(|p| p.id == txid)?;
        let payout = self.payouts.remove(index);
        self.applied.retain(|id| id != txid);
        self.credit(&payout.account, payout.value);
        Some(payout.value)
    }

    /// Spend `amount` satoshis from `did` for an access fee (a paid request
    /// or an anchor). Fails closed with
    /// [`PaymentError::InsufficientBalance`]; the returned [`Charge`] is the
    /// only way to [`refund`](Self::refund) it.
    pub fn charge(&mut self, did: &str, amount: u64) -> Result<Charge, PaymentError> {
        self.debit(did, amount)?;
        Ok(Charge {
            account: did.to_string(),
            amount,
        })
    }

    /// Give back a [`Charge`] whose service was not delivered.
    pub fn refund(&mut self, charge: Charge) {
        self.credit(&charge.account, charge.amount);
    }

    fn touch(&mut self, now: u64) {
        self.updated = self.updated.max(now);
    }

    pub(crate) fn credit(&mut self, did: &str, amount: u64) {
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

    pub(crate) fn debit(&mut self, did: &str, amount: u64) -> Result<u64, PaymentError> {
        self.updated = now_secs();
        let entry = self.entries.iter_mut().find(|e| e.url == did).ok_or(
            PaymentError::InsufficientBalance {
                balance: 0,
                cost: amount,
            },
        )?;
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

/// Teller `accountOf`: a `did:nostr:<64 hex>` from a did, a bare x, or a
/// Multikey's x (`fe70102`/`fe70103` prefix), lowercased.
pub fn account_of(id: &str) -> Result<String, PaymentError> {
    let s = id.trim().to_ascii_lowercase();
    let is_x = |x: &str| x.len() == 64 && x.bytes().all(|b| b.is_ascii_hexdigit());
    let x = s
        .strip_prefix("did:nostr:")
        .filter(|x| is_x(x))
        .or_else(|| Some(s.as_str()).filter(|x| is_x(x)))
        .or_else(|| {
            s.strip_prefix("fe70102")
                .or_else(|| s.strip_prefix("fe70103"))
                .filter(|x| is_x(x))
        })
        .ok_or_else(|| {
            PaymentError::InvalidState(
                "an account is a did:nostr identifier (did:nostr:<64 hex>)".into(),
            )
        })?;
    Ok(format!("did:nostr:{x}"))
}

/// Teller `sats`: a whole amount never beyond 21 million coins in satoshis.
fn check_amount(value: u64) -> Result<(), PaymentError> {
    const MAX: u64 = 2_100_000_000_000_000;
    if value > MAX {
        return Err(PaymentError::InvalidState(
            "an amount is a whole number of satoshis".into(),
        ));
    }
    Ok(())
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
    /// The pod's issuer key (66-hex compressed): its token trail's base key
    /// and the key deposit addresses derive from.
    pub issuer: String,
    /// Further trail issuer keys whose `ticker` trails this pod accepts as
    /// deposits, besides `issuer` itself. Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_issuers: Vec<String>,
}

impl TokenConfig {
    /// Whether an MRC20 trail anchored on `pubkey` is this pod's token: the
    /// configured `issuer` or one of `accepted_issuers` (hex compared
    /// case-insensitively, keys never empty).
    pub fn accepts_issuer(&self, pubkey: &str) -> bool {
        let pubkey = pubkey.trim();
        !pubkey.is_empty()
            && std::iter::once(&self.issuer)
                .chain(self.accepted_issuers.iter())
                .any(|k| !k.is_empty() && k.trim().eq_ignore_ascii_case(pubkey))
    }
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
        info["chains"] = serde_json::json!(config
            .chains
            .iter()
            .map(|c| serde_json::json!({
                "id": c.id,
                "unit": c.unit,
                "name": c.name
            }))
            .collect::<Vec<_>>());
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
pub fn payment_response_headers(
    balance: u64,
    cost: u64,
    currency: &str,
) -> Vec<(&'static str, String)> {
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
        return Err(PaymentError::InvalidTxo("expected txid:vout format".into()));
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
        return Err(PaymentError::InvalidTxo("txid must be 64 hex chars".into()));
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
pub use crate::mrc20::{verify_state_link, Mrc20Op, Mrc20State};

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

    const ALICE: &str =
        "did:nostr:4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    fn txid(byte: &str) -> String {
        byte.repeat(32)
    }

    #[test]
    fn credit_by_outpoint_credits_once() {
        let mut ledger = WebLedger::new("Test");
        let t = txid("ab");
        assert_eq!(
            ledger
                .credit_by_outpoint(ALICE, "satoshi", &t, 0, 50_000)
                .unwrap(),
            ReceiptOutcome::Applied
        );
        assert_eq!(
            ledger
                .credit_by_outpoint(ALICE, "satoshi", &t, 0, 50_000)
                .unwrap(),
            ReceiptOutcome::AlreadyApplied
        );
        // Same outpoint, another account or unit: still the same coin.
        let bob = format!("did:nostr:{}", "b".repeat(64));
        assert_eq!(
            ledger.credit_by_outpoint(&bob, "PODS", &t, 0, 9).unwrap(),
            ReceiptOutcome::AlreadyApplied
        );
        assert_eq!(ledger.get_balance(ALICE), 50_000);
        assert_eq!(ledger.get_currency_balance(&bob, "PODS"), 0);
        assert_eq!(ledger.deposits().len(), 1);
        assert_eq!(ledger.deposits()[0].outpoint, format!("{t}:0"));
        assert!(ledger.has_deposit(&t, 0));
        assert!(!ledger.has_deposit(&t, 1));
        // Another vout of the same transaction is another coin.
        assert_eq!(
            ledger
                .credit_by_outpoint(ALICE, "satoshi", &t, 1, 1)
                .unwrap(),
            ReceiptOutcome::Applied
        );
        assert_eq!(ledger.get_balance(ALICE), 50_001);
    }

    #[test]
    fn token_credit_lands_in_its_ticker_never_sats() {
        let mut ledger = WebLedger::new("Test");
        ledger
            .credit_by_outpoint(ALICE, "satoshi", &txid("01"), 0, 777)
            .unwrap();
        ledger
            .credit_by_outpoint(ALICE, "PODS", &txid("02"), 3, 100)
            .unwrap();
        assert_eq!(ledger.get_balance(ALICE), 777, "sats unchanged");
        assert_eq!(ledger.get_currency_balance(ALICE, "PODS"), 100);
        assert_eq!(ledger.deposits()[1].currency.as_deref(), Some("PODS"));
        assert_eq!(ledger.deposits()[0].currency, None);
    }

    #[test]
    fn credit_by_outpoint_reads_accounts_as_teller_does() {
        let x = &ALICE["did:nostr:".len()..];
        let mut ledger = WebLedger::new("Test");
        ledger
            .credit_by_outpoint(&x.to_uppercase(), "satoshi", &txid("03"), 0, 5)
            .unwrap();
        ledger
            .credit_by_outpoint(&format!("fe70102{x}"), "sat", &txid("04"), 0, 5)
            .unwrap();
        assert_eq!(ledger.get_balance(ALICE), 10);
        for bad in ["did:nostr:alice", "npub1x", ""] {
            assert!(ledger
                .credit_by_outpoint(bad, "satoshi", &txid("05"), 0, 1)
                .is_err());
        }
    }

    #[test]
    fn credit_by_outpoint_refuses_bad_outpoints_and_amounts() {
        let mut ledger = WebLedger::new("Test");
        assert!(ledger
            .credit_by_outpoint(ALICE, "satoshi", &"AB".repeat(32), 0, 1)
            .is_err());
        assert!(ledger
            .credit_by_outpoint(ALICE, "satoshi", "abcd", 0, 1)
            .is_err());
        assert!(ledger
            .credit_by_outpoint(ALICE, "satoshi", &txid("ab"), 0, 2_100_000_000_000_001)
            .is_err());
        assert!(ledger
            .credit_by_outpoint(ALICE, "", &txid("ab"), 0, 1)
            .is_err());
        assert!(ledger.entries().is_empty() && ledger.deposits().is_empty());
    }

    #[test]
    fn debit_by_payout_applies_once_and_reverses() {
        let mut ledger = WebLedger::new("Test");
        ledger
            .credit_by_outpoint(ALICE, "satoshi", &txid("ab"), 0, 1_000)
            .unwrap();
        let payout = txid("cd");
        assert_eq!(
            ledger.debit_by_payout(ALICE, 400, &payout).unwrap(),
            ReceiptOutcome::Applied
        );
        assert_eq!(
            ledger.debit_by_payout(ALICE, 400, &payout).unwrap(),
            ReceiptOutcome::AlreadyApplied
        );
        assert_eq!(ledger.get_balance(ALICE), 600);
        assert!(matches!(
            ledger.debit_by_payout(ALICE, 601, &txid("ce")),
            Err(PaymentError::InsufficientBalance {
                balance: 600,
                cost: 601
            })
        ));
        assert!(ledger.debit_by_payout(ALICE, 1, "not-a-txid").is_err());
        assert_eq!(ledger.payouts().len(), 1);

        assert_eq!(ledger.reverse_payout(&payout), Some(400));
        assert_eq!(ledger.reverse_payout(&payout), None, "reversed once");
        assert_eq!(ledger.get_balance(ALICE), 1_000);
        assert!(ledger.payouts().is_empty());
        assert_eq!(ledger.reverse_payout(&txid("ef")), None);
        assert_eq!(ledger.get_balance(ALICE), 1_000, "no receipt, no credit");
    }

    #[test]
    fn charge_and_refund() {
        let mut ledger = WebLedger::new("Test");
        ledger
            .credit_by_outpoint(ALICE, "satoshi", &txid("ab"), 0, 100)
            .unwrap();
        let charge = ledger.charge(ALICE, 30).unwrap();
        assert_eq!((charge.account(), charge.amount()), (ALICE, 30));
        assert_eq!(ledger.get_balance(ALICE), 70);
        ledger.refund(charge);
        assert_eq!(ledger.get_balance(ALICE), 100);
        assert!(matches!(
            ledger.charge(ALICE, 101),
            Err(PaymentError::InsufficientBalance {
                balance: 100,
                cost: 101
            })
        ));
    }

    #[test]
    fn genesis_identity() {
        let genesis =
            LedgerGenesis::new(ALICE, "Pod Credits", "satoshi", 1_759_300_000, 1).unwrap();
        let ledger = WebLedger::with_genesis(genesis.clone()).unwrap();
        assert_eq!(ledger.hash(), Some(genesis.hash().as_str()));
        assert_eq!(
            ledger.id().unwrap(),
            format!("urn:webledgers:{}", genesis.hash())
        );
        ledger.check_genesis().unwrap();
        assert!(WebLedger::new("Legacy").check_genesis().is_ok());
        assert!(LedgerGenesis::new(ALICE, "", "satoshi", 0, 1).is_err());
        assert!(LedgerGenesis::new(ALICE, &"n".repeat(81), "satoshi", 0, 1).is_err());
        assert!(LedgerGenesis::new("did:nostr:alice", "x", "satoshi", 0, 1).is_err());

        // A legacy document (no genesis, no receipts) still loads.
        let legacy = r#"{"@context":"https://w3id.org/webledgers","type":"WebLedger","name":"Pod Credits","description":"d","defaultCurrency":"satoshi","created":1,"updated":2,"entries":[{"type":"Entry","url":"did:nostr:x","amount":"5"}]}"#;
        let ledger: WebLedger = serde_json::from_str(legacy).unwrap();
        assert_eq!(ledger.get_balance("did:nostr:x"), 5);
        assert!(ledger.genesis().is_none() && ledger.check_genesis().is_ok());
    }

    #[test]
    fn token_config_accepts_its_issuers_only() {
        let mut token = TokenConfig {
            ticker: "PODS".into(),
            rate: 1,
            supply: 1,
            issuer: "02AA".into(),
            accepted_issuers: Vec::new(),
        };
        assert!(token.accepts_issuer("02aa"));
        assert!(!token.accepts_issuer("02bb"));
        assert!(!token.accepts_issuer(""));
        token.accepted_issuers.push("02bb".into());
        assert!(token.accepts_issuer("02BB"));
        token.issuer.clear();
        token.accepted_issuers.clear();
        assert!(!token.accepts_issuer(""));
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
                accepted_issuers: Vec::new(),
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
