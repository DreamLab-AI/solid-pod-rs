//! `acl:PaymentCondition` -- gate authorisation on payment proof.
//!
//! A `PaymentCondition` is satisfied when the request context carries
//! a `payment_balance_sats` value that is greater than or equal to the
//! declared `acl:costSats`. This enables per-resource payment gating
//! via `.acl.json` files, beyond the global `/pay/` prefix.
//!
//! The condition body carries a single mandatory field:
//!
//! - `acl:costSats` -- cost in satoshis to access the guarded resource.
//!
//! The evaluator does not perform the actual debit; it only checks
//! whether the caller has sufficient balance. The handler layer is
//! responsible for debiting the ledger after a successful WAC grant
//! that included a PaymentCondition.

use serde::{Deserialize, Serialize};

use crate::wac::conditions::{ConditionOutcome, RequestContext};

/// Body of an `acl:PaymentCondition`.
///
/// Specifies the cost in satoshis required for access. The WAC evaluator
/// checks `RequestContext::payment_balance_sats >= cost_sats` and returns
/// `Satisfied` or `Denied` accordingly.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PaymentConditionBody {
    /// Cost in satoshis to access the guarded resource.
    #[serde(
        rename = "acl:costSats",
        default,
        deserialize_with = "deserialize_cost_sats"
    )]
    pub cost_sats: u64,
}

/// Deserialize `acl:costSats` from either a number or a string integer.
/// JSON-LD documents may represent integers as strings in some
/// serialisation modes.
fn deserialize_cost_sats<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
    let v: serde_json::Value = Deserialize::deserialize(de)?;
    match &v {
        serde_json::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("acl:costSats must be a non-negative integer")),
        serde_json::Value::String(s) => s
            .parse::<u64>()
            .map_err(|_| serde::de::Error::custom("acl:costSats string must parse as u64")),
        _ => Err(serde::de::Error::custom(
            "acl:costSats must be a number or string",
        )),
    }
}

/// Default evaluator for `acl:PaymentCondition`.
///
/// Stateless: checks `RequestContext::payment_balance_sats` against
/// the declared cost. Does not perform debiting -- that is the
/// handler's responsibility.
#[derive(Debug, Default, Clone, Copy)]
pub struct PaymentConditionEvaluator;

impl PaymentConditionEvaluator {
    /// Evaluate whether the caller has sufficient balance.
    ///
    /// Returns `Satisfied` when `balance >= cost_sats`, `Denied` otherwise.
    /// When `payment_balance_sats` is `None` (no payment context), the
    /// condition is denied -- callers without a ledger entry cannot pass
    /// payment gates.
    pub fn evaluate(
        &self,
        body: &PaymentConditionBody,
        ctx: &RequestContext<'_>,
    ) -> ConditionOutcome {
        match ctx.payment_balance_sats {
            Some(balance) if balance >= body.cost_sats => ConditionOutcome::Satisfied,
            _ => ConditionOutcome::Denied,
        }
    }
}

/// Extract the total payment cost from a list of conditions. Used by
/// handler layers to determine how many sats to debit after a
/// successful WAC evaluation.
pub fn total_payment_cost(conditions: &[crate::wac::conditions::Condition]) -> u64 {
    conditions
        .iter()
        .filter_map(|c| match c {
            crate::wac::conditions::Condition::Payment(body) => Some(body.cost_sats),
            _ => None,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluator_satisfied_when_balance_sufficient() {
        let body = PaymentConditionBody { cost_sats: 100 };
        let ctx = RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: Some(100),
        };
        assert_eq!(
            PaymentConditionEvaluator.evaluate(&body, &ctx),
            ConditionOutcome::Satisfied
        );
    }

    #[test]
    fn evaluator_satisfied_when_balance_exceeds_cost() {
        let body = PaymentConditionBody { cost_sats: 50 };
        let ctx = RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: Some(1000),
        };
        assert_eq!(
            PaymentConditionEvaluator.evaluate(&body, &ctx),
            ConditionOutcome::Satisfied
        );
    }

    #[test]
    fn evaluator_denied_when_balance_insufficient() {
        let body = PaymentConditionBody { cost_sats: 100 };
        let ctx = RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: Some(50),
        };
        assert_eq!(
            PaymentConditionEvaluator.evaluate(&body, &ctx),
            ConditionOutcome::Denied
        );
    }

    #[test]
    fn evaluator_denied_when_no_payment_context() {
        let body = PaymentConditionBody { cost_sats: 1 };
        let ctx = RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: None,
        };
        assert_eq!(
            PaymentConditionEvaluator.evaluate(&body, &ctx),
            ConditionOutcome::Denied
        );
    }

    #[test]
    fn evaluator_zero_cost_always_satisfied() {
        let body = PaymentConditionBody { cost_sats: 0 };
        let ctx = RequestContext {
            web_id: Some("did:nostr:alice"),
            client_id: None,
            issuer: None,
            payment_balance_sats: Some(0),
        };
        assert_eq!(
            PaymentConditionEvaluator.evaluate(&body, &ctx),
            ConditionOutcome::Satisfied
        );
    }

    #[test]
    fn total_payment_cost_sums_conditions() {
        use crate::wac::conditions::Condition;

        let conditions = vec![
            Condition::Payment(PaymentConditionBody { cost_sats: 100 }),
            Condition::Client(crate::wac::client::ClientConditionBody::default()),
            Condition::Payment(PaymentConditionBody { cost_sats: 50 }),
        ];
        assert_eq!(total_payment_cost(&conditions), 150);
    }

    #[test]
    fn total_payment_cost_zero_when_no_payment_conditions() {
        use crate::wac::conditions::Condition;

        let conditions = vec![Condition::Client(
            crate::wac::client::ClientConditionBody::default(),
        )];
        assert_eq!(total_payment_cost(&conditions), 0);
    }

    #[test]
    fn deserialize_from_json() {
        let json = r#"{"@type": "acl:PaymentCondition", "acl:costSats": 42}"#;
        let body: PaymentConditionBody =
            serde_json::from_str(json).expect("deserialize PaymentConditionBody");
        assert_eq!(body.cost_sats, 42);
    }

    #[test]
    fn deserialize_cost_as_string() {
        let json = r#"{"@type": "acl:PaymentCondition", "acl:costSats": "100"}"#;
        let body: PaymentConditionBody =
            serde_json::from_str(json).expect("deserialize from string cost");
        assert_eq!(body.cost_sats, 100);
    }

    #[test]
    fn serialize_roundtrip() {
        let body = PaymentConditionBody { cost_sats: 500 };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("500"));
        let parsed: PaymentConditionBody = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cost_sats, 500);
    }
}
