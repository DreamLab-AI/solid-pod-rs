//! Read-only review of a data root before opting in to `--acl-layout`
//! (SP-PAR-290).
//!
//! In early releases an inner `<container>/.acl` file could be created by a
//! caller who did not hold `acl:Control`, and `inner` and `both` honour every
//! such file. So the report must be reviewed before opting in. It lists, for a
//! filesystem data root:
//!
//! * `inner`: a container holding `.acl` and no sibling `<container>.acl`;
//!   `--acl-layout inner` or `both` would start honouring it;
//! * `both-identical` / `both-differ`: a container holding both forms, and
//!   whether the bytes differ (under `both` the sidecar wins);
//! * `sidecar-only`: a container whose ACL is the sibling only; switching to
//!   `inner` would drop it and widen access to the parent's grant;
//! * `directory-at-acl-key`: a directory sitting at an ACL key (`x.acl/` or
//!   `<c>/.acl/`). The server reads a directory at an ACL key as absent, so
//!   the subtree beneath it now inherits its parent's ACL; before that
//!   hardening the read failed and everything beneath answered an error;
//! * `acl-key-is-symlink`: an ACL key that is a symbolic link. The report
//!   does not follow it and does not classify the container by it. The server
//!   does read a relative link that stays inside the data root (the filesystem
//!   backend resolves links beneath the root) and refuses an absolute target or
//!   one that points outside it (an unreadable ACL denies), so review the
//!   link's target by hand;
//! * `symlinked-directory`: a container that is a symbolic link to a
//!   directory. The report does not descend into it, but the server follows a
//!   relative link beneath the root, so an ACL inside the target also governs
//!   the link's path. The report is incomplete for that subtree and the
//!   command exits non-zero;
//! * `error`: something could not be read (a directory, or an ACL file), or
//!   the tree is deeper than [`MAX_DEPTH`]. The report is then incomplete and
//!   the command exits non-zero.
//!
//! It only reads: it never creates, writes or removes anything, and skips
//! `.git` directories. The pod root's `/.acl` is the same key in every layout
//! and is not listed.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// Deepest directory level the scan descends to; deeper is reported as an
/// error rather than followed.
pub const MAX_DEPTH: usize = 64;

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
    /// A directory sits at an ACL key (path ends with `/`).
    DirectoryAtAclKey(String),
    /// An ACL key is a symbolic link (the key's path); not followed.
    SymlinkNotFollowed(String),
    /// A container is a symbolic link to a directory (path ends with `/`); not
    /// descended into, so the report is incomplete beneath it.
    SymlinkedDirectory(String),
    /// A read failed or the depth bound was hit: the path and the reason.
    Error(String, String),
}

fn is_acl_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".acl")
}

/// What is at `p`: `Some(Ok(true))` plain file, `Some(Err(..))` unreadable
/// metadata, `None` absent.
enum Kind {
    Absent,
    File,
    Symlink,
    Dir,
    Other,
    Failed(String),
}

fn kind(p: &Path) -> Kind {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_symlink() => Kind::Symlink,
        Ok(m) if m.is_file() => Kind::File,
        Ok(m) if m.is_dir() => Kind::Dir,
        Ok(_) => Kind::Other,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Kind::Absent,
        Err(e) => Kind::Failed(e.to_string()),
    }
}

fn walk(dir: &Path, rel: &str, depth: usize, out: &mut Vec<Finding>) {
    if depth > MAX_DEPTH {
        out.push(Finding::Error(
            rel.to_string(),
            format!("depth limit {MAX_DEPTH} reached; not scanned below here"),
        ));
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            out.push(Finding::Error(
                rel.to_string(),
                format!("unreadable directory: {e}"),
            ));
            return;
        }
    };
    let mut entries = Vec::new();
    for e in rd {
        match e {
            Ok(e) => entries.push(e),
            Err(e) => out.push(Finding::Error(
                rel.to_string(),
                format!("unreadable entry: {e}"),
            )),
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        let path = e.path();
        match kind(&path) {
            Kind::Symlink if is_acl_name(&name) => {
                out.push(Finding::SymlinkNotFollowed(format!("{rel}{name}")));
                continue;
            }
            Kind::Symlink => {
                // Not descended into (a link can loop or leave the root), but
                // the server follows a relative link beneath the root, so say
                // that this subtree was not reviewed.
                if fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                    out.push(Finding::SymlinkedDirectory(format!("{rel}{name}/")));
                }
                continue;
            }
            Kind::Failed(err) => {
                out.push(Finding::Error(format!("{rel}{name}"), err));
                continue;
            }
            Kind::Dir => {}
            _ => continue,
        }
        if name == ".git" {
            continue;
        }
        let container = format!("{rel}{name}/");
        if is_acl_name(&name) {
            out.push(Finding::DirectoryAtAclKey(container.clone()));
        }
        classify(dir, &path, &name, &container, out);
        walk(&path, &container, depth + 1, out);
    }
}

fn classify(dir: &Path, path: &Path, name: &str, container: &str, out: &mut Vec<Finding>) {
    let inner = path.join(".acl");
    let sidecar = dir.join(format!("{name}.acl"));
    let parent = container.trim_end_matches(&format!("{name}/")).to_string();
    let (ki, ks) = (kind(&inner), kind(&sidecar));
    // Keys that are not plain files are reported on their own and the
    // container is not classified by them.
    let mut plain = |k: &Kind, key: String| match k {
        Kind::File => true,
        Kind::Symlink => {
            out.push(Finding::SymlinkNotFollowed(key));
            false
        }
        Kind::Failed(e) => {
            out.push(Finding::Error(key, e.clone()));
            false
        }
        _ => false,
    };
    let (pi, ps) = (
        plain(&ki, format!("{container}.acl")),
        plain(&ks, format!("{parent}{name}.acl")),
    );
    match (pi, ps) {
        (true, false) if matches!(ks, Kind::Absent | Kind::Dir | Kind::Other) => {
            out.push(Finding::Inner(container.to_string()));
        }
        (false, true) if matches!(ki, Kind::Absent | Kind::Dir | Kind::Other) => {
            out.push(Finding::SidecarOnly(container.to_string()));
        }
        (true, true) => match (fs::read(&inner), fs::read(&sidecar)) {
            (Ok(a), Ok(b)) if a == b => out.push(Finding::BothIdentical(container.to_string())),
            (Ok(_), Ok(_)) => out.push(Finding::BothDiffer(container.to_string())),
            (a, b) => {
                // A failed read is never "identical": say which one failed.
                for (key, r) in [
                    (format!("{container}.acl"), a),
                    (format!("{parent}{name}.acl"), b),
                ] {
                    if let Err(e) = r {
                        out.push(Finding::Error(key, format!("unreadable ACL: {e}")));
                    }
                }
            }
        },
        _ => {}
    }
}

/// Scan `root` and return the findings, ordered by path.
#[must_use]
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    walk(root, "/", 0, &mut out);
    out
}

/// True when the scan could not read something, hit the depth bound, or met a
/// symlinked directory it did not descend into, so the report is incomplete
/// and the command must exit non-zero.
#[must_use]
pub fn has_errors(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| matches!(f, Finding::Error(..) | Finding::SymlinkedDirectory(_)))
}

/// Render the findings as the text the `--acl-layout-report` flag prints.
#[must_use]
pub fn render(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        match f {
            Finding::Inner(p) => writeln!(s, "inner\t{p}"),
            Finding::BothIdentical(p) => writeln!(s, "both-identical\t{p}"),
            Finding::BothDiffer(p) => writeln!(s, "both-differ\t{p}"),
            Finding::SidecarOnly(p) => writeln!(s, "sidecar-only\t{p}"),
            Finding::DirectoryAtAclKey(p) => writeln!(s, "directory-at-acl-key\t{p}"),
            Finding::SymlinkNotFollowed(p) => writeln!(s, "acl-key-is-symlink\t{p}"),
            Finding::SymlinkedDirectory(p) => writeln!(s, "symlinked-directory\t{p}"),
            Finding::Error(p, why) => writeln!(s, "error\t{p}\t{why}"),
        }
        .ok();
    }
    if findings.is_empty() {
        s.push_str("no container ACLs other than the pod root\n");
    }
    s
}
