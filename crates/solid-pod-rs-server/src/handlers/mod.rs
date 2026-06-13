//! HTTP handler submodules.
//!
//! Currently hosts the payment routing layer ([`pay`]) that wires the
//! orphaned `solid-pod-rs` order-book/AMM/ledger logic onto actix-web
//! routes with JSS-parity request/response JSON.

pub mod pay;
