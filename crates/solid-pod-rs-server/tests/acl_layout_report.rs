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

use solid_pod_rs_server::acl_layout_report::has_errors;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn running_as_root() -> bool {
        // Root ignores mode bits, so an unreadable file cannot be made.
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::read(&f).is_ok()
    }

    #[test]
    fn two_unreadable_acls_are_an_error_not_both_identical() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        write(r, "c/.acl", "one");
        write(r, "c.acl", "two");
        for f in ["c/.acl", "c.acl"] {
            std::fs::set_permissions(r.join(f), std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let found = scan(r);
        assert!(has_errors(&found), "{found:?}");
        assert!(
            !found
                .iter()
                .any(|f| matches!(f, Finding::BothIdentical(_) | Finding::BothDiffer(_))),
            "an unreadable pair must not be classified: {found:?}"
        );
        let text = render(&found);
        assert!(text.contains("error\t/c/"), "{text}");
    }

    #[test]
    fn an_unreadable_directory_is_reported() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        write(r, "locked/inner/.acl", "x");
        std::fs::set_permissions(r.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let found = scan(r);
        std::fs::set_permissions(r.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(has_errors(&found), "{found:?}");
        assert!(render(&found).contains("error\t/locked/"));
    }

    #[test]
    fn symlinked_acl_files_are_listed_as_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        write(r, "real.txt", "x");
        write(r, "a/f", "x");
        symlink(r.join("real.txt"), r.join("a/.acl")).unwrap();
        write(r, "b/f", "x");
        symlink(r.join("real.txt"), r.join("b.acl")).unwrap();
        let found = scan(r);
        assert!(found.contains(&Finding::SymlinkNotFollowed("/a/.acl".into())));
        assert!(found.contains(&Finding::SymlinkNotFollowed("/b.acl".into())));
        // Not classified as inner / sidecar-only: the report does not follow them.
        assert!(!found
            .iter()
            .any(|f| matches!(f, Finding::Inner(_) | Finding::SidecarOnly(_))));
        assert!(!has_errors(&found));
    }

    /// What the server itself does with a symlinked ACL file, which the help
    /// text states: a relative link that stays inside the data root is read
    /// through (the filesystem backend resolves links beneath the root); an
    /// absolute target, or one pointing outside it, is refused.
    #[actix_web::test]
    async fn the_server_reads_a_symlinked_acl_only_inside_the_root() {
        use solid_pod_rs::storage::{fs::FsBackend, Storage};
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let r = dir.path();
        write(r, "real.acl", "inside");
        write(outside.path(), "x.acl", "outside");
        symlink("real.acl", r.join("in.acl")).unwrap();
        symlink(r.join("real.acl"), r.join("abs.acl")).unwrap();
        symlink(outside.path().join("x.acl"), r.join("out.acl")).unwrap();
        let fs = FsBackend::new(r).await.unwrap();
        assert_eq!(fs.get("/in.acl").await.unwrap().0.as_ref(), b"inside");
        // An absolute target is refused even when it lies inside the root.
        assert!(fs.get("/abs.acl").await.is_err());
        assert!(fs.get("/out.acl").await.is_err());
    }
}

#[test]
fn a_directory_at_an_acl_key_is_listed() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    write(r, "x.acl/inside.txt", "x");
    write(r, "c/.acl/inside.txt", "x");
    let found = scan(r);
    assert!(found.contains(&Finding::DirectoryAtAclKey("/x.acl/".into())));
    assert!(found.contains(&Finding::DirectoryAtAclKey("/c/.acl/".into())));
    assert!(render(&found).contains("directory-at-acl-key\t/x.acl/"));
    assert!(!has_errors(&found));
}

#[test]
fn depth_is_bounded_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = String::new();
    for _ in 0..200 {
        p.push_str("d/");
    }
    write(dir.path(), &format!("{p}f"), "x");
    let found = scan(dir.path());
    assert!(
        has_errors(&found),
        "an over-deep tree is an error: {found:?}"
    );
    assert!(render(&found).contains("depth"));
}
