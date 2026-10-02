//! Oracle: solidpayorg/teller 7c00cea's Web Ledger identity and receipts.
//!
//! `tests/fixtures/teller/ledger-7c00cea.json` was produced by running
//! teller's own `lib/teller.mjs` (see `fixtures/teller/README.md`): a ledger
//! born with a genesis, one deposit credited twice by the same outpoint
//! (applied once), and one payout. The Rust ledger must compute the same
//! `sha256(JCS(genesis))`, read teller's cache document as it stands, and
//! apply the same receipts with the same results.

use serde_json::Value;
use solid_pod_rs::payments::{LedgerGenesis, ReceiptOutcome, WebLedger};

const FIXTURE: &str = include_str!("fixtures/teller/ledger-7c00cea.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture is JSON")
}

#[test]
fn ledger_hash_matches_teller() {
    let f = fixture();
    let genesis: LedgerGenesis = serde_json::from_value(f["document"]["genesis"].clone()).unwrap();
    assert_eq!(
        solid_pod_rs::mrc20::jcs(&serde_json::to_value(&genesis).unwrap()),
        f["genesisJcs"].as_str().unwrap()
    );
    assert_eq!(genesis.hash(), f["ledgerHash"].as_str().unwrap());

    // Built from its parts, the same genesis gives the same identity.
    let built = LedgerGenesis::new(
        &genesis.operator,
        &genesis.name,
        &genesis.currency,
        genesis.created,
        genesis.confirmations,
    )
    .unwrap();
    let ledger = WebLedger::with_genesis(built).unwrap();
    assert_eq!(ledger.hash(), f["ledgerHash"].as_str());
    assert_eq!(ledger.id(), f["document"]["id"].as_str());
    assert_eq!(ledger.default_currency, genesis.currency);
}

#[test]
fn teller_cache_document_reads_and_checks() {
    let f = fixture();
    let ledger: WebLedger = serde_json::from_value(f["document"].clone()).unwrap();
    ledger.check_genesis().unwrap();
    assert_eq!(ledger.ledger_hash().as_deref(), f["ledgerHash"].as_str());
    let alice = f["document"]["entries"][0]["url"].as_str().unwrap();
    assert_eq!(ledger.get_balance(alice), f["balance"].as_u64().unwrap());
    assert_eq!(ledger.deposits().len(), 1);
    assert_eq!(ledger.payouts().len(), 1);

    // Round-trip keeps every teller field teller reads back.
    let again = serde_json::to_value(&ledger).unwrap();
    for key in [
        "id", "hash", "genesis", "deposits", "applied", "payouts", "entries",
    ] {
        assert_eq!(
            again[key], f["document"][key],
            "{key} survives a round trip"
        );
    }

    // A tampered genesis is caught, as teller's checkLedger catches it.
    let mut tampered = f["document"].clone();
    tampered["genesis"]["name"] = "Table 8".into();
    let tampered: WebLedger = serde_json::from_value(tampered).unwrap();
    assert!(tampered.check_genesis().is_err());
}

#[test]
fn receipts_apply_as_teller_applies_them() {
    let f = fixture();
    let doc = &f["document"];
    let genesis: LedgerGenesis = serde_json::from_value(doc["genesis"].clone()).unwrap();
    let mut ledger = WebLedger::with_genesis(genesis).unwrap();
    let deposit = &doc["deposits"][0];
    let (txid, vout) = deposit["outpoint"]
        .as_str()
        .unwrap()
        .split_once(':')
        .unwrap();
    let account = deposit["account"].as_str().unwrap();
    let value = deposit["value"].as_u64().unwrap();
    let currency = doc["defaultCurrency"].as_str().unwrap();
    let vout: u32 = vout.parse().unwrap();

    assert_eq!(
        ledger
            .credit_by_outpoint(account, currency, txid, vout, value)
            .unwrap(),
        ReceiptOutcome::Applied
    );
    // teller: {applied: false, why: 'already credited'}.
    assert_eq!(f["results"]["secondCredit"]["applied"], false);
    assert_eq!(
        ledger
            .credit_by_outpoint(account, currency, txid, vout, value)
            .unwrap(),
        ReceiptOutcome::AlreadyApplied
    );

    let payout = &doc["payouts"][0];
    let payout_txid = payout["txid"].as_str().unwrap();
    assert_eq!(
        ledger
            .debit_by_payout(account, payout["value"].as_u64().unwrap(), payout_txid)
            .unwrap(),
        ReceiptOutcome::Applied
    );
    assert_eq!(
        ledger
            .debit_by_payout(account, payout["value"].as_u64().unwrap(), payout_txid)
            .unwrap(),
        ReceiptOutcome::AlreadyApplied
    );

    assert_eq!(ledger.get_balance(account), f["balance"].as_u64().unwrap());
    let ours = serde_json::to_value(&ledger).unwrap();
    assert_eq!(ours["entries"], doc["entries"]);
    assert_eq!(ours["applied"], doc["applied"]);
    assert_eq!(ours["hash"], doc["hash"]);
    assert_eq!(ours["genesis"], doc["genesis"]);
    assert_eq!(ours["deposits"][0]["outpoint"], deposit["outpoint"]);
    assert_eq!(ours["payouts"][0]["id"], payout["id"]);
}
