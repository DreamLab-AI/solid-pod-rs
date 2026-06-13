//! HTTP handler submodules.
//!
//! Hosts the payment routing layer ([`pay`]) that wires the orphaned
//! `solid-pod-rs` order-book/AMM/ledger logic onto actix-web routes with
//! JSS-parity request/response JSON, and the provenance `_prov` API
//! ([`prov`], git-gated) that composes git-marks + block-trail anchors
//! (ADR-059 Phase 5).

pub mod pay;

/// Provenance `_prov` routes + the composition wiring for the LDP write hook.
/// Git-gated: it shells to `git` (commit resolution) and depends on the
/// git-only repo-path helpers.
#[cfg(feature = "git")]
pub mod prov;
