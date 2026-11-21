//! `--acl-layout-report` scan: lists inner ACLs, both forms (and whether they
//! differ) and sidecar-only containers, skips `.git`, and changes nothing.

use std::collections::BTreeMap;
use std::path::Path;

use solid_pod_rs_server::acl_layout_report::{render, scan, Finding};

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn go(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().display().to_string();
            if p.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                go(&p, root, out);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    let mut m = BTreeMap::new();
    go(root, root, &mut m);
    m
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

#[test]
fn lists_every_form_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, ".acl", "root");
    // inner only
    write(r, "a/.acl", "inner");
    write(r, "a/f.txt", "x");
    // both, identical
    write(r, "b/.acl", "same");
    write(r, "b.acl", "same");
    // both, differing
    write(r, "c/.acl", "one");
    write(r, "c.acl", "two");
    // sidecar only
    write(r, "d/f.txt", "x");
    write(r, "d.acl", "side");
    // nested inner
    write(r, "a/sub/.acl", "inner2");
    // never listed: .git, and a plain container
    write(r, ".git/.acl", "git");
    write(r, "plain/f.txt", "x");

    let before = snapshot(r);
    let found = scan(r);
    let text = render(&found);
    assert_eq!(snapshot(r), before, "the report is read-only");

    assert_eq!(
        found,
        vec![
            Finding::Inner("/a/".into()),
            Finding::Inner("/a/sub/".into()),
            Finding::BothIdentical("/b/".into()),
            Finding::BothDiffer("/c/".into()),
            Finding::SidecarOnly("/d/".into()),
        ]
    );
    assert!(text.contains("both-differ\t/c/"));
    assert!(!text.contains(".git"));
}

#[test]
fn an_empty_root_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert!(render(&scan(dir.path())).contains("no container ACLs"));
}
