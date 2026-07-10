//! Peer-to-peer trading and AMM constant-product pool.
//!
//! Implements the exchange surface documented in Melvin Carvalho's
//! *Practical Guide to Solid*, parts 8–9:
//! <https://melvin.me/public/solid/>
//!
//! - **Order book** (`/pay/.sell`, `/pay/.offers`, `/pay/.swap`): sellers
//!   post sell orders specifying amount, currency pair, and price; buyers
//!   execute atomic swaps against the order book.
//! - **AMM pool** (`/pay/.pool`): constant-product `x * y = k` liquidity
//!   pool with configurable fee (default 30 bps / 0.3%).
//!
//! All balance mutations delegate to [`WebLedger`] — this module never
//! owns or persists balances directly. Integer-only arithmetic with
//! `u128` intermediates prevents overflow on multiply-before-divide.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::payments::{PaymentError, WebLedger};

// ---------------------------------------------------------------------------
// WebLedger multi-currency extensions
// ---------------------------------------------------------------------------

/// Extension methods on [`WebLedger`] for currency-specific operations.
///
/// The base `WebLedger` API (`credit`, `debit`, `get_balance`) operates on
/// the default satoshi balance. Trading requires per-currency balances, so
/// these helpers work through the `LedgerAmount::Multi` representation.
impl WebLedger {
    /// Get a DID's balance in a specific currency.
    pub fn get_currency_balance(&self, did: &str, currency: &str) -> u64 {
        self.entries
            .iter()
            .find(|e| e.url == did)
            .map(|e| e.amount.chain_balance(currency))
            .unwrap_or(0)
    }

    /// Credit a DID in a specific currency.
    pub fn credit_currency(&mut self, did: &str, currency: &str, amount: u64) {
        use crate::payments::{CurrencyAmount, LedgerAmount, LedgerEntry};

        self.updated = now_secs();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.url == did) {
            match &mut entry.amount {
                LedgerAmount::Simple(s) => {
                    // Upgrade Simple → Multi, preserving the satoshi balance.
                    let sat_val = s.parse::<u64>().unwrap_or(0);
                    let mut currencies = vec![CurrencyAmount {
                        currency: "satoshi".into(),
                        value: sat_val.to_string(),
                    }];
                    currencies.push(CurrencyAmount {
                        currency: currency.into(),
                        value: amount.to_string(),
                    });
                    entry.amount = LedgerAmount::Multi(currencies);
                }
                LedgerAmount::Multi(v) => {
                    if let Some(ca) = v.iter_mut().find(|a| a.currency == currency) {
                        let current: u64 = ca.value.parse().unwrap_or(0);
                        ca.value = current.saturating_add(amount).to_string();
                    } else {
                        v.push(CurrencyAmount {
                            currency: currency.into(),
                            value: amount.to_string(),
                        });
                    }
                }
            }
        } else {
            self.entries.push(LedgerEntry {
                entry_type: "Entry".into(),
                url: did.into(),
                amount: LedgerAmount::Multi(vec![CurrencyAmount {
                    currency: currency.into(),
                    value: amount.to_string(),
                }]),
            });
        }
    }

    /// Debit a DID in a specific currency.
    pub fn debit_currency(
        &mut self,
        did: &str,
        currency: &str,
        amount: u64,
    ) -> Result<u64, PaymentError> {
        let current = self.get_currency_balance(did, currency);
        if current < amount {
            return Err(PaymentError::InsufficientBalance {
                balance: current,
                cost: amount,
            });
        }
        self.updated = now_secs();
        // Entry must exist since get_currency_balance returned > 0.
        let entry = self.entries.iter_mut().find(|e| e.url == did).unwrap();
        match &mut entry.amount {
            crate::payments::LedgerAmount::Multi(v) => {
                if let Some(ca) = v.iter_mut().find(|a| a.currency == currency) {
                    let cur: u64 = ca.value.parse().unwrap_or(0);
                    let new_val = cur - amount;
                    ca.value = new_val.to_string();
                    Ok(new_val)
                } else {
                    Err(PaymentError::InsufficientBalance {
                        balance: 0,
                        cost: amount,
                    })
                }
            }
            crate::payments::LedgerAmount::Simple(_) => Err(PaymentError::InsufficientBalance {
                balance: 0,
                cost: amount,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Swap result
// ---------------------------------------------------------------------------

/// Result of executing a trade (either order-book or AMM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResult {
    pub amount_in: u64,
    pub amount_out: u64,
    pub fee: u64,
    pub new_balance_in: u64,
    pub new_balance_out: u64,
}

// ---------------------------------------------------------------------------
// Sell orders + order book
// ---------------------------------------------------------------------------

/// A sell order on the order book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SellOrder {
    pub id: String,
    /// Seller identity: `did:nostr:<hex-pubkey>`.
    pub seller: String,
    /// Currency the seller is offering (e.g. `"tbtc4"`).
    pub sell_currency: String,
    /// Amount of `sell_currency` offered.
    pub sell_amount: u64,
    /// Currency the seller wants in return (e.g. `"tbtc3"`).
    pub buy_currency: String,
    /// Price: `buy_currency` units per `sell_currency` unit.
    pub price: u64,
    /// Unix timestamp when the order was created.
    pub created_at: u64,
}

/// Order book for peer-to-peer trades.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    orders: Vec<SellOrder>,
    next_id: u64,
}

impl OrderBook {
    pub fn new() -> Self {
        Self {
            orders: Vec::new(),
            next_id: 1,
        }
    }

    /// Create a new sell order and add it to the book.
    ///
    /// Returns the created order. The caller must ensure the seller has
    /// sufficient balance before listing — the order book does not escrow.
    pub fn create_order(
        &mut self,
        seller: &str,
        sell_currency: &str,
        sell_amount: u64,
        buy_currency: &str,
        price: u64,
    ) -> SellOrder {
        let order = SellOrder {
            id: self.next_id.to_string(),
            seller: seller.into(),
            sell_currency: sell_currency.into(),
            sell_amount,
            buy_currency: buy_currency.into(),
            price,
            created_at: now_secs(),
        };
        self.next_id += 1;
        self.orders.push(order.clone());
        order
    }

    /// List all active orders, optionally filtered by currency pair.
    ///
    /// When `currency_pair` is `Some((sell, buy))`, only orders matching
    /// that exact pair are returned.
    pub fn list_offers(&self, currency_pair: Option<(&str, &str)>) -> Vec<&SellOrder> {
        match currency_pair {
            None => self.orders.iter().collect(),
            Some((sell, buy)) => self
                .orders
                .iter()
                .filter(|o| o.sell_currency == sell && o.buy_currency == buy)
                .collect(),
        }
    }

    /// Cancel an order. Only the original seller can cancel.
    pub fn cancel_order(&mut self, id: &str, seller: &str) -> Result<SellOrder, PaymentError> {
        let idx = self
            .orders
            .iter()
            .position(|o| o.id == id)
            .ok_or_else(|| PaymentError::InvalidTxo(format!("order {id} not found")))?;

        if self.orders[idx].seller != seller {
            return Err(PaymentError::InvalidTxo(format!(
                "order {id} belongs to {}, not {seller}",
                self.orders[idx].seller
            )));
        }

        Ok(self.orders.remove(idx))
    }

    /// Execute a swap against an existing sell order.
    ///
    /// Atomic: debits the buyer in `buy_currency`, credits the seller in
    /// `buy_currency`, debits the seller in `sell_currency`, credits the
    /// buyer in `sell_currency`, then removes the order.
    pub fn execute_swap(
        &mut self,
        id: &str,
        buyer: &str,
        ledger: &mut WebLedger,
    ) -> Result<SwapResult, PaymentError> {
        let idx = self
            .orders
            .iter()
            .position(|o| o.id == id)
            .ok_or_else(|| PaymentError::InvalidTxo(format!("order {id} not found")))?;

        let order = &self.orders[idx];

        // total_cost = sell_amount * price (what the buyer pays)
        let total_cost = order
            .sell_amount
            .checked_mul(order.price)
            .ok_or_else(|| PaymentError::InvalidTxo("price overflow".into()))?;

        // Verify buyer can afford it.
        let buyer_balance = ledger.get_currency_balance(buyer, &order.buy_currency);
        if buyer_balance < total_cost {
            return Err(PaymentError::InsufficientBalance {
                balance: buyer_balance,
                cost: total_cost,
            });
        }

        // Verify seller still has the tokens to sell.
        let seller_balance = ledger.get_currency_balance(&order.seller, &order.sell_currency);
        if seller_balance < order.sell_amount {
            return Err(PaymentError::InsufficientBalance {
                balance: seller_balance,
                cost: order.sell_amount,
            });
        }

        // Clone what we need before mutating.
        let sell_amount = order.sell_amount;
        let sell_currency = order.sell_currency.clone();
        let buy_currency = order.buy_currency.clone();
        let seller = order.seller.clone();

        // Atomic settlement:
        // 1. Debit buyer in buy_currency.
        ledger.debit_currency(buyer, &buy_currency, total_cost)?;
        // 2. Credit seller in buy_currency.
        ledger.credit_currency(&seller, &buy_currency, total_cost);
        // 3. Debit seller in sell_currency.
        ledger.debit_currency(&seller, &sell_currency, sell_amount)?;
        // 4. Credit buyer in sell_currency.
        ledger.credit_currency(buyer, &sell_currency, sell_amount);

        // Remove the filled order.
        self.orders.remove(idx);

        let new_balance_in = ledger.get_currency_balance(buyer, &buy_currency);
        let new_balance_out = ledger.get_currency_balance(buyer, &sell_currency);

        Ok(SwapResult {
            amount_in: total_cost,
            amount_out: sell_amount,
            fee: 0,
            new_balance_in,
            new_balance_out,
        })
    }
}

impl Default for OrderBook {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AMM constant-product liquidity pool
// ---------------------------------------------------------------------------

/// AMM constant-product liquidity pool (`x * y = k`).
///
/// Supports add/remove liquidity and swaps with a configurable fee
/// (default 30 basis points = 0.3%). All arithmetic uses `u128`
/// intermediates to prevent overflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmmPool {
    pub currency_a: String,
    pub currency_b: String,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub total_shares: u64,
    /// Fee in basis points (100 bps = 1%). Default 30 (0.3%).
    pub fee_bps: u64,
    /// Per-provider share balances.
    shares: HashMap<String, u64>,
}

impl AmmPool {
    /// Default fee: 30 bps (0.3%), matching Uniswap V2.
    pub const DEFAULT_FEE_BPS: u64 = 30;

    pub fn new(currency_a: &str, currency_b: &str, fee_bps: u64) -> Self {
        Self {
            currency_a: currency_a.into(),
            currency_b: currency_b.into(),
            reserve_a: 0,
            reserve_b: 0,
            total_shares: 0,
            fee_bps,
            shares: HashMap::new(),
        }
    }

    /// Add liquidity to the pool.
    ///
    /// The first provider sets the initial ratio. Subsequent providers
    /// must provide amounts in the same ratio as the current reserves
    /// (within integer rounding). Returns the number of LP shares issued.
    pub fn add_liquidity(
        &mut self,
        provider: &str,
        amount_a: u64,
        amount_b: u64,
        ledger: &mut WebLedger,
    ) -> Result<u64, PaymentError> {
        if amount_a == 0 || amount_b == 0 {
            return Err(PaymentError::InvalidTxo(
                "liquidity amounts must be non-zero".into(),
            ));
        }

        // Debit provider.
        ledger.debit_currency(provider, &self.currency_a, amount_a)?;
        ledger.debit_currency(provider, &self.currency_b, amount_b)?;

        let shares = if self.total_shares == 0 {
            // First provider: shares = sqrt(amount_a * amount_b) using
            // integer square root to stay in u64 land.
            let product = (amount_a as u128) * (amount_b as u128);
            isqrt_u128(product) as u64
        } else {
            // Proportional to existing reserves: min(a/A, b/B) * total.
            let share_a =
                (amount_a as u128) * (self.total_shares as u128) / (self.reserve_a as u128);
            let share_b =
                (amount_b as u128) * (self.total_shares as u128) / (self.reserve_b as u128);
            share_a.min(share_b) as u64
        };

        if shares == 0 {
            return Err(PaymentError::InvalidTxo(
                "liquidity too small to issue shares".into(),
            ));
        }

        self.reserve_a = self.reserve_a.saturating_add(amount_a);
        self.reserve_b = self.reserve_b.saturating_add(amount_b);
        self.total_shares = self.total_shares.saturating_add(shares);
        *self.shares.entry(provider.into()).or_insert(0) += shares;

        Ok(shares)
    }

    /// Remove liquidity from the pool.
    ///
    /// Withdraws proportional amounts of both currencies based on the
    /// share count. Returns `(amount_a, amount_b)` credited back.
    pub fn remove_liquidity(
        &mut self,
        provider: &str,
        shares: u64,
        ledger: &mut WebLedger,
    ) -> Result<(u64, u64), PaymentError> {
        let provider_shares = self.shares.get(provider).copied().unwrap_or(0);

        if provider_shares < shares {
            return Err(PaymentError::InsufficientBalance {
                balance: provider_shares,
                cost: shares,
            });
        }

        if self.total_shares == 0 {
            return Err(PaymentError::InvalidTxo("pool has no shares".into()));
        }

        // Proportional withdrawal.
        let amount_a =
            ((self.reserve_a as u128) * (shares as u128) / (self.total_shares as u128)) as u64;
        let amount_b =
            ((self.reserve_b as u128) * (shares as u128) / (self.total_shares as u128)) as u64;

        self.reserve_a = self.reserve_a.saturating_sub(amount_a);
        self.reserve_b = self.reserve_b.saturating_sub(amount_b);
        self.total_shares = self.total_shares.saturating_sub(shares);

        let entry = self.shares.get_mut(provider).unwrap();
        *entry -= shares;
        if *entry == 0 {
            self.shares.remove(provider);
        }

        // Credit provider.
        ledger.credit_currency(provider, &self.currency_a, amount_a);
        ledger.credit_currency(provider, &self.currency_b, amount_b);

        Ok((amount_a, amount_b))
    }

    /// Execute a constant-product swap.
    ///
    /// Formula (with fee):
    /// ```text
    /// amount_out = (reserve_out * amount_in * (10000 - fee_bps))
    ///            / (reserve_in * 10000 + amount_in * (10000 - fee_bps))
    /// ```
    ///
    /// All intermediate arithmetic uses `u128` to prevent overflow.
    pub fn swap(
        &mut self,
        trader: &str,
        from_currency: &str,
        amount_in: u64,
        ledger: &mut WebLedger,
    ) -> Result<SwapResult, PaymentError> {
        if amount_in == 0 {
            return Err(PaymentError::InvalidTxo(
                "swap amount must be non-zero".into(),
            ));
        }

        let (reserve_in, reserve_out, to_currency) = if from_currency == self.currency_a {
            (self.reserve_a, self.reserve_b, self.currency_b.clone())
        } else if from_currency == self.currency_b {
            (self.reserve_b, self.reserve_a, self.currency_a.clone())
        } else {
            return Err(PaymentError::InvalidTxo(format!(
                "currency {from_currency} not in pool ({}/{})",
                self.currency_a, self.currency_b
            )));
        };

        if reserve_in == 0 || reserve_out == 0 {
            return Err(PaymentError::InvalidTxo("pool is empty".into()));
        }

        // Constant-product with fee, using u128 intermediates.
        let fee_factor = 10_000u128 - (self.fee_bps as u128);
        let numerator = (reserve_out as u128) * (amount_in as u128) * fee_factor;
        let denominator = (reserve_in as u128) * 10_000u128 + (amount_in as u128) * fee_factor;

        let amount_out = (numerator / denominator) as u64;

        if amount_out == 0 {
            return Err(PaymentError::InvalidTxo(
                "swap output rounds to zero".into(),
            ));
        }

        // Fee retained in pool = amount_in - effective_input.
        // effective_input = amount_in * fee_factor / 10000
        let effective_input = ((amount_in as u128) * fee_factor / 10_000u128) as u64;
        let fee = amount_in - effective_input;

        // Debit trader's input currency, credit output currency.
        ledger.debit_currency(trader, from_currency, amount_in)?;
        ledger.credit_currency(trader, &to_currency, amount_out);

        // Update reserves.
        if from_currency == self.currency_a {
            self.reserve_a = self.reserve_a.saturating_add(amount_in);
            self.reserve_b = self.reserve_b.saturating_sub(amount_out);
        } else {
            self.reserve_b = self.reserve_b.saturating_add(amount_in);
            self.reserve_a = self.reserve_a.saturating_sub(amount_out);
        }

        let new_balance_in = ledger.get_currency_balance(trader, from_currency);
        let new_balance_out = ledger.get_currency_balance(trader, &to_currency);

        Ok(SwapResult {
            amount_in,
            amount_out,
            fee,
            new_balance_in,
            new_balance_out,
        })
    }

    /// Pool info as a JSON value (for `/pay/.pool` response).
    pub fn pool_info(&self) -> serde_json::Value {
        serde_json::json!({
            "currency_a": self.currency_a,
            "currency_b": self.currency_b,
            "reserve_a": self.reserve_a,
            "reserve_b": self.reserve_b,
            "total_shares": self.total_shares,
            "fee_bps": self.fee_bps,
            "invariant_k": (self.reserve_a as u128) * (self.reserve_b as u128),
            "providers": self.shares.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Exchange (combined order book + AMM pools)
// ---------------------------------------------------------------------------

/// Combined exchange state: order book + AMM pool registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exchange {
    pub order_book: OrderBook,
    pub pools: HashMap<String, AmmPool>,
}

impl Exchange {
    pub fn new() -> Self {
        Self {
            order_book: OrderBook::new(),
            pools: HashMap::new(),
        }
    }

    /// Get or create a pool for the given currency pair.
    ///
    /// Pool keys are canonically sorted so `("tbtc3", "tbtc4")` and
    /// `("tbtc4", "tbtc3")` resolve to the same pool.
    pub fn get_or_create_pool(
        &mut self,
        currency_a: &str,
        currency_b: &str,
        fee_bps: u64,
    ) -> &mut AmmPool {
        let key = pool_key(currency_a, currency_b);
        self.pools
            .entry(key)
            .or_insert_with(|| AmmPool::new(currency_a, currency_b, fee_bps))
    }

    /// Look up an existing pool (immutable).
    pub fn get_pool(&self, currency_a: &str, currency_b: &str) -> Option<&AmmPool> {
        let key = pool_key(currency_a, currency_b);
        self.pools.get(&key)
    }
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonical pool key: sorted pair joined by `/`.
fn pool_key(a: &str, b: &str) -> String {
    if a <= b {
        format!("{a}/{b}")
    } else {
        format!("{b}/{a}")
    }
}

/// Integer square root of a `u128` via Newton's method.
fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Platform-aware current time in seconds.
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
    use crate::payments::WebLedger;

    /// Helper: create a ledger and fund two DIDs in two currencies.
    fn setup_ledger() -> WebLedger {
        let mut ledger = WebLedger::new("Test Exchange");
        ledger.credit_currency("did:nostr:alice", "tbtc4", 10_000);
        ledger.credit_currency("did:nostr:alice", "tbtc3", 5_000);
        ledger.credit_currency("did:nostr:bob", "tbtc4", 8_000);
        ledger.credit_currency("did:nostr:bob", "tbtc3", 12_000);
        ledger
    }

    // -- Order book tests --------------------------------------------------

    #[test]
    fn test_order_create_and_list() {
        let mut book = OrderBook::new();
        book.create_order("did:nostr:alice", "tbtc4", 100, "tbtc3", 2);
        book.create_order("did:nostr:bob", "tbtc3", 50, "tbtc4", 1);
        book.create_order("did:nostr:alice", "tbtc4", 200, "tbtc3", 3);

        // List all.
        assert_eq!(book.list_offers(None).len(), 3);

        // Filter by pair.
        let filtered = book.list_offers(Some(("tbtc4", "tbtc3")));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|o| o.sell_currency == "tbtc4"));

        // Different pair.
        let filtered2 = book.list_offers(Some(("tbtc3", "tbtc4")));
        assert_eq!(filtered2.len(), 1);
        assert_eq!(filtered2[0].seller, "did:nostr:bob");
    }

    #[test]
    fn test_order_cancel_by_seller() {
        let mut book = OrderBook::new();
        let order = book.create_order("did:nostr:alice", "tbtc4", 100, "tbtc3", 2);

        // Non-seller cannot cancel.
        let err = book.cancel_order(&order.id, "did:nostr:bob").unwrap_err();
        assert!(
            format!("{err}").contains("belongs to"),
            "Expected ownership error, got: {err}"
        );

        // Seller can cancel.
        let cancelled = book.cancel_order(&order.id, "did:nostr:alice").unwrap();
        assert_eq!(cancelled.id, order.id);
        assert_eq!(book.list_offers(None).len(), 0);
    }

    #[test]
    fn test_order_execute_swap() {
        let mut ledger = setup_ledger();
        let mut book = OrderBook::new();

        // Alice sells 100 tbtc4 at 2 tbtc3 each (buyer pays 200 tbtc3).
        let order = book.create_order("did:nostr:alice", "tbtc4", 100, "tbtc3", 2);

        // Bob buys (pays 200 tbtc3, receives 100 tbtc4).
        let result = book
            .execute_swap(&order.id, "did:nostr:bob", &mut ledger)
            .unwrap();

        assert_eq!(result.amount_in, 200); // Bob paid 200 tbtc3
        assert_eq!(result.amount_out, 100); // Bob received 100 tbtc4
        assert_eq!(result.fee, 0); // No fee on order book

        // Verify balances.
        assert_eq!(
            ledger.get_currency_balance("did:nostr:bob", "tbtc3"),
            12_000 - 200
        );
        assert_eq!(
            ledger.get_currency_balance("did:nostr:bob", "tbtc4"),
            8_000 + 100
        );
        assert_eq!(
            ledger.get_currency_balance("did:nostr:alice", "tbtc3"),
            5_000 + 200
        );
        assert_eq!(
            ledger.get_currency_balance("did:nostr:alice", "tbtc4"),
            10_000 - 100
        );

        // Order removed.
        assert_eq!(book.list_offers(None).len(), 0);
    }

    #[test]
    fn test_order_swap_insufficient_balance() {
        let mut ledger = setup_ledger();
        let mut book = OrderBook::new();

        // Alice sells 100 tbtc4 at price 200 tbtc3 each — total cost 20_000.
        let order = book.create_order("did:nostr:alice", "tbtc4", 100, "tbtc3", 200);

        // Bob only has 12_000 tbtc3.
        let err = book
            .execute_swap(&order.id, "did:nostr:bob", &mut ledger)
            .unwrap_err();
        assert!(matches!(err, PaymentError::InsufficientBalance { .. }));

        // Order still present.
        assert_eq!(book.list_offers(None).len(), 1);
    }

    // -- AMM pool tests ----------------------------------------------------

    #[test]
    fn test_amm_add_liquidity_first() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", AmmPool::DEFAULT_FEE_BPS);

        let shares = pool
            .add_liquidity("did:nostr:alice", 1_000, 2_000, &mut ledger)
            .unwrap();

        // shares = isqrt(1000 * 2000) = isqrt(2_000_000) = 1414
        assert_eq!(shares, isqrt_u128(2_000_000) as u64);
        assert_eq!(pool.reserve_a, 1_000);
        assert_eq!(pool.reserve_b, 2_000);
        assert_eq!(pool.total_shares, shares);

        // Provider balance debited.
        assert_eq!(
            ledger.get_currency_balance("did:nostr:alice", "tbtc4"),
            10_000 - 1_000
        );
        assert_eq!(
            ledger.get_currency_balance("did:nostr:alice", "tbtc3"),
            5_000 - 2_000
        );
    }

    #[test]
    fn test_amm_add_liquidity_subsequent() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", AmmPool::DEFAULT_FEE_BPS);

        let shares_alice = pool
            .add_liquidity("did:nostr:alice", 1_000, 2_000, &mut ledger)
            .unwrap();

        // Bob adds proportional liquidity (same 1:2 ratio).
        let shares_bob = pool
            .add_liquidity("did:nostr:bob", 500, 1_000, &mut ledger)
            .unwrap();

        // Bob's shares should be proportional: 500/1000 * alice_shares = alice_shares / 2
        // (exact within integer rounding).
        assert_eq!(shares_bob, shares_alice / 2);
        assert_eq!(pool.reserve_a, 1_500);
        assert_eq!(pool.reserve_b, 3_000);
        assert_eq!(pool.total_shares, shares_alice + shares_bob);
    }

    #[test]
    fn test_amm_swap_constant_product() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", 0); // Zero fee for k verification.

        pool.add_liquidity("did:nostr:alice", 5_000, 5_000, &mut ledger)
            .unwrap();

        let k_before = (pool.reserve_a as u128) * (pool.reserve_b as u128);

        // Bob swaps 1_000 tbtc4 → tbtc3.
        let result = pool
            .swap("did:nostr:bob", "tbtc4", 1_000, &mut ledger)
            .unwrap();

        let k_after = (pool.reserve_a as u128) * (pool.reserve_b as u128);

        // With zero fee, k must not decrease (rounding can only increase it).
        assert!(k_after >= k_before, "k decreased: {k_before} → {k_after}");

        // Verify output: out = 5000 * 1000 * 10000 / (5000 * 10000 + 1000 * 10000)
        //                    = 5_000_000_000 / 60_000_000 = 833
        assert_eq!(result.amount_out, 833);
        assert_eq!(result.amount_in, 1_000);

        // Reserves updated.
        assert_eq!(pool.reserve_a, 6_000);
        assert_eq!(pool.reserve_b, 5_000 - 833);
    }

    #[test]
    fn test_amm_swap_fee_collection() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", 30); // 0.3% fee.

        pool.add_liquidity("did:nostr:alice", 5_000, 5_000, &mut ledger)
            .unwrap();

        let k_before = (pool.reserve_a as u128) * (pool.reserve_b as u128);

        // Bob swaps 1_000 tbtc4 → tbtc3.
        let result = pool
            .swap("did:nostr:bob", "tbtc4", 1_000, &mut ledger)
            .unwrap();

        let k_after = (pool.reserve_a as u128) * (pool.reserve_b as u128);

        // With fee, k must strictly increase (fee retained in reserves).
        assert!(
            k_after > k_before,
            "k should increase with fee: {k_before} → {k_after}"
        );

        // Fee is 0.3% of 1000 = 3.
        assert_eq!(result.fee, 3);

        // Output should be slightly less than zero-fee case (833).
        // out = 5000 * 1000 * 9970 / (5000 * 10000 + 1000 * 9970)
        //     = 49_850_000_000 / 59_970_000 = 831
        assert_eq!(result.amount_out, 831);
    }

    #[test]
    fn test_amm_remove_liquidity() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", 30);

        let shares = pool
            .add_liquidity("did:nostr:alice", 2_000, 4_000, &mut ledger)
            .unwrap();

        // Do a swap to generate fees.
        pool.swap("did:nostr:bob", "tbtc4", 500, &mut ledger)
            .unwrap();

        // Alice removes all her shares.
        let (got_a, got_b) = pool
            .remove_liquidity("did:nostr:alice", shares, &mut ledger)
            .unwrap();

        // Alice gets back more than she put in because fees accrued.
        // She deposited 2000 tbtc4 and 4000 tbtc3. The swap added
        // 500 tbtc4 to reserves and removed some tbtc3.
        assert!(
            got_a > 2_000 || got_b > 4_000 || (got_a >= 2_000 && got_b >= 3_500),
            "Expected fee accrual: got ({got_a}, {got_b}) vs deposited (2000, 4000)"
        );

        // Pool is empty after full withdrawal.
        assert_eq!(pool.reserve_a, 0);
        assert_eq!(pool.reserve_b, 0);
        assert_eq!(pool.total_shares, 0);
    }

    #[test]
    fn test_amm_swap_empty_pool() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", 30);

        let err = pool
            .swap("did:nostr:bob", "tbtc4", 100, &mut ledger)
            .unwrap_err();
        assert!(
            format!("{err}").contains("empty"),
            "Expected empty pool error, got: {err}"
        );
    }

    #[test]
    fn test_exchange_multi_pool() {
        let mut ledger = setup_ledger();
        // Add a third currency.
        ledger.credit_currency("did:nostr:alice", "signet", 10_000);

        let mut exchange = Exchange::new();

        let pool1 = exchange.get_or_create_pool("tbtc4", "tbtc3", AmmPool::DEFAULT_FEE_BPS);
        pool1
            .add_liquidity("did:nostr:alice", 1_000, 1_000, &mut ledger)
            .unwrap();

        let pool2 = exchange.get_or_create_pool("tbtc4", "signet", AmmPool::DEFAULT_FEE_BPS);
        pool2
            .add_liquidity("did:nostr:alice", 1_000, 2_000, &mut ledger)
            .unwrap();

        assert_eq!(exchange.pools.len(), 2);

        // Both pools have independent reserves.
        let p1 = exchange.get_pool("tbtc4", "tbtc3").unwrap();
        assert_eq!(p1.reserve_a, 1_000);

        let p2 = exchange.get_pool("tbtc4", "signet").unwrap();
        assert_eq!(p2.reserve_b, 2_000);

        // Canonical key order: get_pool("signet", "tbtc4") also works.
        let p2_alt = exchange.get_pool("signet", "tbtc4").unwrap();
        assert_eq!(p2_alt.reserve_b, 2_000);
    }

    #[test]
    fn test_integer_overflow_safety() {
        let mut ledger = WebLedger::new("Overflow Test");
        let large = u64::MAX / 2;
        ledger.credit_currency("did:nostr:whale", "tbtc4", large);
        ledger.credit_currency("did:nostr:whale", "tbtc3", large);

        let mut pool = AmmPool::new("tbtc4", "tbtc3", 30);

        // Add large liquidity.
        let shares = pool
            .add_liquidity("did:nostr:whale", large, large, &mut ledger)
            .unwrap();
        assert!(shares > 0);
        assert_eq!(pool.reserve_a, large);
        assert_eq!(pool.reserve_b, large);

        // Fund a trader with a smaller amount.
        ledger.credit_currency("did:nostr:trader", "tbtc4", 1_000_000);

        // Swap should not panic from overflow.
        let result = pool
            .swap("did:nostr:trader", "tbtc4", 1_000_000, &mut ledger)
            .unwrap();
        assert!(result.amount_out > 0);
        assert!(result.amount_out < 1_000_000); // Output < input due to large reserves + fee.

        // Verify k didn't decrease.
        let k = (pool.reserve_a as u128) * (pool.reserve_b as u128);
        let k_original = (large as u128) * (large as u128);
        assert!(k >= k_original);
    }

    // -- Serialization roundtrip -------------------------------------------

    #[test]
    fn test_exchange_serialization_roundtrip() {
        let mut exchange = Exchange::new();
        exchange
            .order_book
            .create_order("did:nostr:alice", "tbtc4", 100, "tbtc3", 2);
        exchange.get_or_create_pool("tbtc4", "tbtc3", 30);

        let json = serde_json::to_string(&exchange).unwrap();
        let parsed: Exchange = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.order_book.list_offers(None).len(), 1);
        assert_eq!(parsed.pools.len(), 1);
    }

    // -- Pool info ---------------------------------------------------------

    #[test]
    fn test_pool_info() {
        let mut ledger = setup_ledger();
        let mut pool = AmmPool::new("tbtc4", "tbtc3", 30);
        pool.add_liquidity("did:nostr:alice", 1_000, 2_000, &mut ledger)
            .unwrap();

        let info = pool.pool_info();
        assert_eq!(info["currency_a"], "tbtc4");
        assert_eq!(info["reserve_a"], 1_000);
        assert_eq!(info["reserve_b"], 2_000);
        assert_eq!(info["fee_bps"], 30);
        assert_eq!(info["invariant_k"], 2_000_000u64);
        assert_eq!(info["providers"], 1);
    }

    // -- isqrt helper ------------------------------------------------------

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(4), 2);
        assert_eq!(isqrt_u128(9), 3);
        assert_eq!(isqrt_u128(10), 3);
        assert_eq!(isqrt_u128(2_000_000), 1414);
        // Large value: sqrt(u64::MAX * u64::MAX) = u64::MAX.
        let max = u64::MAX as u128;
        assert_eq!(isqrt_u128(max * max), max);
    }
}
