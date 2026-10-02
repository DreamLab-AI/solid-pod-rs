//! The Blocktrails vocabulary in the crates' documentation: a trail is made of
//! marks and anchored on Bitcoin. "Single-use seal" is not this project's term
//! (Blocktrails commits states to output keys; it does not use seals), so it
//! must not appear in any crate's rustdoc or README.

use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `single-use seal`, `single use seal`, `single-use-seal`, any case.
fn mentions_seal(text: &str) -> bool {
    let norm: String = text
        .to_lowercase()
        .chars()
        .map(|c| if c == '-' || c == '_' { ' ' } else { c })
        .collect();
    norm.contains("single use seal")
}

#[test]
fn no_crate_documents_single_use_seals() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ directory");
    let mut checked = Vec::new();
    for krate in std::fs::read_dir(crates).unwrap().flatten() {
        let root = krate.path();
        files(&root.join("src"), &mut checked);
        let readme = root.join("README.md");
        if readme.is_file() {
            checked.push(readme);
        }
    }
    assert!(checked.len() > 20, "found only {} files", checked.len());
    let offenders: Vec<String> = checked
        .iter()
        .filter(|p| mentions_seal(&std::fs::read_to_string(p).unwrap_or_default()))
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "'single-use seal' in crate docs: {offenders:?}"
    );
}

#[test]
fn the_check_sees_every_spelling() {
    for s in [
        "Single-use seal",
        "single use seal",
        "SINGLE-USE-SEAL",
        "single_use_seal",
    ] {
        assert!(mentions_seal(s), "{s}");
    }
    assert!(!mentions_seal("a mark on a trail, anchored"));
}
