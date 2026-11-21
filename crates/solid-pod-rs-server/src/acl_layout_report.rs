//! Read-only review of a data root before opting in to `--acl-layout`
//! (SP-PAR-290).
//!
//! In early releases an inner `<container>/.acl` file could be created by a
//! caller who did not hold `acl:Control`, so an operator should look at every
//! one before honouring them. The report lists, for a filesystem data root:
//!
//! * `inner`: a container holding `.acl` and no sibling `<container>.acl`;
//!   `--acl-layout inner` or `both` would start honouring it;
//! * `both-identical` / `both-differ`: a container holding both forms, and
//!   whether the bytes differ (under `both` the sidecar wins);
//! * `sidecar-only`: a container whose ACL is the sibling only; switching to
//!   `inner` would drop it and widen access to the parent's grant.
//!
//! It only reads: it never creates, writes or removes anything, does not
//! follow symbolic links, and skips `.git` directories. The pod root's
//! `/.acl` is the same key in every layout and is not listed.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// One finding, with the container path relative to the data root (`/a/b/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Only the inner `<container>/.acl` exists.
    Inner(String),
    /// Both forms exist with identical bytes.
    BothIdentical(String),
    /// Both forms exist and differ.
    BothDiffer(String),
    /// Only the sibling `<container>.acl` exists.
    SidecarOnly(String),
}

fn is_plain_file(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<Finding>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        let path = e.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || name == ".git" {
            continue;
        }
        let container = format!("{rel}{name}/");
        let inner = path.join(".acl");
        let sidecar = dir.join(format!("{name}.acl"));
        match (is_plain_file(&inner), is_plain_file(&sidecar)) {
            (true, false) => out.push(Finding::Inner(container.clone())),
            (false, true) => out.push(Finding::SidecarOnly(container.clone())),
            (true, true) => {
                if fs::read(&inner).ok() == fs::read(&sidecar).ok() {
                    out.push(Finding::BothIdentical(container.clone()));
                } else {
                    out.push(Finding::BothDiffer(container.clone()));
                }
            }
            (false, false) => {}
        }
        walk(&path, &container, out);
    }
}

/// Scan `root` and return the findings, ordered by path.
#[must_use]
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    walk(root, "/", &mut out);
    out
}

/// Render the findings as the text the `--acl-layout-report` flag prints.
#[must_use]
pub fn render(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        let (kind, path) = match f {
            Finding::Inner(p) => ("inner", p),
            Finding::BothIdentical(p) => ("both-identical", p),
            Finding::BothDiffer(p) => ("both-differ", p),
            Finding::SidecarOnly(p) => ("sidecar-only", p),
        };
        let _ = writeln!(s, "{kind}\t{path}");
    }
    if findings.is_empty() {
        s.push_str("no container ACLs other than the pod root\n");
    }
    s
}
