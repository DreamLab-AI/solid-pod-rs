//! Regression guard: CI must run this crate's doctests.
//!
//! The ledger's compile gate (`WebLedger::credit`/`debit` are
//! `pub(crate)`, enforced by `compile_fail` doctests on `WebLedger`) and
//! the teller genesis-hash doctest on `LedgerGenesis` only execute under
//! `cargo test --doc`; `cargo test --all-targets` skips doctests. This
//! test fails if the workflow stops running them. It is skipped when the
//! crate is built outside the repository (for example from a published
//! tarball), where the workflow file is absent.

use std::path::Path;

/// The run lines of `ci.yml`, trimmed, for steps that invoke `cargo test`.
fn cargo_test_runs(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("run:"))
        .map(str::trim)
        .filter(|r| r.starts_with("cargo test"))
        .collect()
}

#[test]
fn ci_runs_core_and_workspace_doctests() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    let Ok(workflow) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not present", path.display());
        return;
    };
    let runs = cargo_test_runs(&workflow);
    let doc_runs: Vec<&&str> = runs
        .iter()
        .filter(|r| r.split_whitespace().any(|w| w == "--doc"))
        .collect();
    assert!(
        doc_runs
            .iter()
            .any(|r| r.contains("${{ matrix.features.flags }}") && !r.contains("--workspace")),
        "the core-crate matrix must run `cargo test --doc` per feature set; runs: {runs:?}"
    );
    assert!(
        doc_runs.iter().any(|r| r.contains("--workspace")),
        "the workspace job must run `cargo test --workspace --doc`; runs: {runs:?}"
    );
    for r in &doc_runs {
        assert!(
            !r.contains("--all-targets"),
            "`--all-targets` disables doctests: {r}"
        );
    }
}
