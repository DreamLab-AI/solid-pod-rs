//! `acl:ProvenanceAnchor` — flag a resource as **anchor-worthy** (high-value).
//!
//! A `ProvenanceAnchor` condition does not gate access. It is a *marker*:
//! when a write targets a resource whose ACL carries one, the server's
//! provenance write hook escalates the [`AnchorPolicy`](crate::provenance::AnchorPolicy)
//! for that write from the default `Never` (cheap git-mark only) to
//! `HighValue` or `Epoch` (master-plan §2.3, ADR-059 D1/D5) — so the git
//! commit is additionally notarised on Bitcoin (inline, or batched into an
//! epoch Merkle root).
//!
//! It parses and dispatches through the same WAC 2.0 conditions framework as
//! [`PaymentCondition`](crate::wac::payment) ([`conditions`](crate::wac::conditions)),
//! and — crucially — it is a **recognised** type, so it never trips the
//! unknown-condition fail-closed 422 path. Because it is orthogonal to
//! authorisation, its evaluator always returns
//! [`Satisfied`](ConditionOutcome::Satisfied): carrying a `ProvenanceAnchor`
//! must never *block* a write, only change how the write is recorded.
//!
//! The body carries one optional hint:
//!
//! - `acl:anchorMode` — `"epoch"` (default) batches the commit into an epoch
//!   Merkle root (one Bitcoin tx per epoch — the bounded-cost default); any
//!   other value (`"always"`/`"inline"`/`"highValue"`) anchors the write
//!   inline. The hook maps this onto an [`AnchorPolicy`](crate::provenance::AnchorPolicy).

use serde::{Deserialize, Serialize};

use crate::wac::conditions::{ConditionOutcome, RequestContext};

/// How a `ProvenanceAnchor`-flagged write should be anchored. Mirrors the
/// expensive-tier variants of [`AnchorPolicy`](crate::provenance::AnchorPolicy),
/// minus `Never` (a `ProvenanceAnchor` by definition anchors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnchorMode {
    /// Batch the commit into the current epoch; anchor the root once on close.
    /// The bounded-cost default (master-plan §5: "ACL writes epoch-only").
    #[default]
    Epoch,
    /// Anchor this write inline (its own Bitcoin state). Settlement receipts,
    /// elevation/ACSP decisions where each record needs its own timestamp.
    Inline,
}

/// Body of an `acl:ProvenanceAnchor` condition.
///
/// Both fields are optional; an empty body (`{"@type":"acl:ProvenanceAnchor"}`)
/// flags the resource as high-value with the default [`AnchorMode::Epoch`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProvenanceAnchorBody {
    /// Anchoring mode hint. `"epoch"` (default) or `"always"`/`"inline"`.
    /// Parsed case-insensitively; unknown strings fall back to `Epoch`.
    #[serde(
        rename = "acl:anchorMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub anchor_mode: Option<String>,

    /// Optional trail ticker override. When absent the pod's configured
    /// pay-token trail is used. Carried verbatim for the hook.
    #[serde(
        rename = "acl:anchorTicker",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ticker: Option<String>,
}

impl ProvenanceAnchorBody {
    /// Resolve the parsed [`AnchorMode`] (epoch unless the body explicitly asks
    /// for inline/always). Case-insensitive; unknown → `Epoch`.
    #[must_use]
    pub fn mode(&self) -> AnchorMode {
        match self.anchor_mode.as_deref().map(str::trim) {
            Some(m)
                if m.eq_ignore_ascii_case("always")
                    || m.eq_ignore_ascii_case("inline")
                    || m.eq_ignore_ascii_case("highvalue")
                    || m.eq_ignore_ascii_case("high-value") =>
            {
                AnchorMode::Inline
            }
            _ => AnchorMode::Epoch,
        }
    }
}

/// Default evaluator for `acl:ProvenanceAnchor`.
///
/// Stateless and **always [`Satisfied`](ConditionOutcome::Satisfied)** — the
/// condition flags provenance handling, it does not gate access, so it must
/// never deny a write. The write hook reads its *presence* (and `mode()`) to
/// pick the [`AnchorPolicy`](crate::provenance::AnchorPolicy); authorisation is
/// decided by the other conditions / the classic ACL triad.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProvenanceAnchorEvaluator;

impl ProvenanceAnchorEvaluator {
    /// Always [`Satisfied`](ConditionOutcome::Satisfied): a provenance marker
    /// never blocks authorisation.
    #[must_use]
    pub fn evaluate(
        &self,
        _body: &ProvenanceAnchorBody,
        _ctx: &RequestContext<'_>,
    ) -> ConditionOutcome {
        ConditionOutcome::Satisfied
    }
}

/// Scan a list of conditions for a `ProvenanceAnchor` marker and, if present,
/// return its resolved [`AnchorMode`]. Used by the server write hook to escalate
/// the [`AnchorPolicy`](crate::provenance::AnchorPolicy) for high-value writes.
///
/// Returns the FIRST `ProvenanceAnchor`'s mode (a resource carrying more than
/// one is degenerate); `None` when no anchor marker is present (the write stays
/// git-mark-only).
#[must_use]
pub fn anchor_mode_of(conditions: &[crate::wac::conditions::Condition]) -> Option<AnchorMode> {
    conditions.iter().find_map(|c| match c {
        crate::wac::conditions::Condition::ProvenanceAnchor(body) => Some(body.mode()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestContext<'static> {
        RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: None,
        }
    }

    #[test]
    fn evaluator_always_satisfied_even_anonymous() {
        let anon = RequestContext {
            web_id: None,
            client_id: None,
            issuer: None,
            payment_balance_sats: None,
        };
        assert_eq!(
            ProvenanceAnchorEvaluator.evaluate(&ProvenanceAnchorBody::default(), &anon),
            ConditionOutcome::Satisfied,
            "a provenance marker must never block a write"
        );
        assert_eq!(
            ProvenanceAnchorEvaluator.evaluate(&ProvenanceAnchorBody::default(), &ctx()),
            ConditionOutcome::Satisfied
        );
    }

    #[test]
    fn mode_defaults_to_epoch() {
        assert_eq!(ProvenanceAnchorBody::default().mode(), AnchorMode::Epoch);
        let b = ProvenanceAnchorBody {
            anchor_mode: Some("epoch".into()),
            ticker: None,
        };
        assert_eq!(b.mode(), AnchorMode::Epoch);
    }

    #[test]
    fn mode_inline_synonyms() {
        for s in [
            "always",
            "ALWAYS",
            "inline",
            "Inline",
            "highValue",
            "high-value",
        ] {
            let b = ProvenanceAnchorBody {
                anchor_mode: Some(s.into()),
                ticker: None,
            };
            assert_eq!(b.mode(), AnchorMode::Inline, "mode {s} ⇒ inline");
        }
    }

    #[test]
    fn mode_unknown_falls_back_to_epoch() {
        let b = ProvenanceAnchorBody {
            anchor_mode: Some("frobnicate".into()),
            ticker: None,
        };
        assert_eq!(b.mode(), AnchorMode::Epoch);
    }

    #[test]
    fn deserialize_from_json_empty_body() {
        let json = r#"{"@type":"acl:ProvenanceAnchor"}"#;
        let body: ProvenanceAnchorBody = serde_json::from_str(json).unwrap();
        assert!(body.anchor_mode.is_none());
        assert_eq!(body.mode(), AnchorMode::Epoch);
    }

    #[test]
    fn deserialize_from_json_with_mode_and_ticker() {
        let json = r#"{"@type":"acl:ProvenanceAnchor","acl:anchorMode":"always","acl:anchorTicker":"RCPT"}"#;
        let body: ProvenanceAnchorBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.mode(), AnchorMode::Inline);
        assert_eq!(body.ticker.as_deref(), Some("RCPT"));
    }

    #[test]
    fn serialize_roundtrip() {
        let body = ProvenanceAnchorBody {
            anchor_mode: Some("epoch".into()),
            ticker: Some("PROV".into()),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("acl:anchorMode"));
        let back: ProvenanceAnchorBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode(), AnchorMode::Epoch);
        assert_eq!(back.ticker.as_deref(), Some("PROV"));
    }

    #[test]
    fn anchor_mode_of_finds_marker() {
        use crate::wac::conditions::Condition;
        let conds = vec![
            Condition::Payment(crate::wac::payment::PaymentConditionBody { cost_sats: 10 }),
            Condition::ProvenanceAnchor(ProvenanceAnchorBody {
                anchor_mode: Some("inline".into()),
                ticker: None,
            }),
        ];
        assert_eq!(anchor_mode_of(&conds), Some(AnchorMode::Inline));
    }

    #[test]
    fn anchor_mode_of_absent_is_none() {
        use crate::wac::conditions::Condition;
        let conds = vec![Condition::Payment(
            crate::wac::payment::PaymentConditionBody { cost_sats: 10 },
        )];
        assert_eq!(anchor_mode_of(&conds), None);
    }
}
