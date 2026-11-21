//! SP-PAR-290: the opt-in `--acl-layout inner|both` modes. The default
//! (`sidecar`) is pinned by `acl_layout_golden.rs` and must not move.

mod common;
use common::acl_harness::*;

use solid_pod_rs::wac::AclLayout;
use solid_pod_rs_server::AppState;

fn state(
    s: &std::sync::Arc<solid_pod_rs::storage::memory::MemoryBackend>,
    l: AclLayout,
) -> AppState {
    let mut st = AppState::new(s.clone());
    st.acl_layout = l;
    st
}

async fn table(layout: AclLayout) -> String {
    let (owner, b) = (agent(1), agent(2));
    let mut t = Vec::new();
    for disk in ALL {
        let s = storage(disk, &owner, &b).await;
        let r = row(|| state(&s, layout), &owner, &b).await;
        t.push(format!("{disk:?} => {r}"));
    }
    t.join("\n")
}

#[actix_web::test]
async fn inner_layout_decision_matrix() {
    let got = table(AclLayout::Inner).await;
    println!("MATRIX-INNER\n{got}");
    assert_eq!(
        got,
        include_str!("fixtures/acl_layout_inner.txt").trim_end()
    );
}

#[actix_web::test]
async fn both_layout_decision_matrix() {
    let got = table(AclLayout::Both).await;
    println!("MATRIX-BOTH\n{got}");
    assert_eq!(got, include_str!("fixtures/acl_layout_both.txt").trim_end());
}
