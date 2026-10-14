//! Pre-receive path guard for `git push`.
//!
//! The pod repository uses `receive.denyCurrentBranch=updateInstead`, so every
//! path a push adds, changes or deletes on the checked-out branch is written
//! straight into the pod working tree, bypassing the REST/MCP path rules. This
//! module inspects a `git-receive-pack` request **before** the CGI sees it and
//! refuses the whole push (nothing is unpacked, no ref moves, nothing is
//! checked out) if any path it changes is refused by the embedder's classifier.
//!
//! # What is checked
//!
//! * the pushed pack is indexed into a throw-away quarantine object directory
//!   (backed by the real object store as an alternate), so nothing reaches the
//!   repository unless the CGI later accepts the same bytes;
//! * every commit the push introduces (`rev-list <new> --not --all`) is diffed
//!   against each of its parents (renames are split into delete + add, so both
//!   sides are seen), covering delete-then-recreate sequences and commits that
//!   are not on the tip;
//! * for the ref that `HEAD` points at (the only ref `updateInstead` checks
//!   out) the new tip is additionally diffed against the current `HEAD`, which
//!   covers objects pushed earlier to another ref and then promoted;
//! * every changed path (added, modified, deleted, type-changed) goes through
//!   the embedder-supplied [`PushPathGuard`]; paths that are not UTF-8, are
//!   absolute, or contain `.`, `..`, empty, backslash or NUL components are
//!   refused outright;
//! * a new tree entry of mode `120000` (symlink) or `160000` (submodule) is
//!   refused outright.
//!
//! # Limits
//!
//! The work is bounded: a request body above [`MAX_PUSH_BODY_BYTES`], more than
//! [`MAX_PUSH_COMMITS`] new commits, more than [`MAX_PUSH_PATHS`] changed
//! paths, or a check that exceeds [`PUSH_CHECK_TIMEOUT`] is refused rather than
//! left to hang. Requests are serialised per repository so `HEAD` cannot move
//! between the check and the CGI run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::Duration;

use crate::service::{git_cors_header_pairs, GitResponse};

/// Classifier for pushed paths. Receives a repository-relative path with a
/// leading `/` (for example `/.well-known/token/x.json`) and returns `true`
/// when a push must not change it.
pub type PushPathGuard = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Largest `git-receive-pack` request body that is inspected (64 MiB). Larger
/// pushes are refused.
pub const MAX_PUSH_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Most new commits one push may introduce.
pub const MAX_PUSH_COMMITS: usize = 5_000;
/// Most changed paths one push may carry, summed over all inspected diffs.
pub const MAX_PUSH_PATHS: usize = 20_000;
/// Most ref updates one push may carry.
pub const MAX_PUSH_COMMANDS: usize = 256;
/// Wall-clock budget for the whole inspection.
pub const PUSH_CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_GIT_OUTPUT: usize = 16 * 1024 * 1024;

/// A refused push: the client-facing reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRefusal(pub String);

impl PushRefusal {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

struct RefUpdate {
    new: String,
    refname: String,
}

struct Parsed {
    commands: Vec<RefUpdate>,
    caps: Vec<String>,
    pack_start: usize,
}

fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_zero(s: &str) -> bool {
    s.bytes().all(|b| b == b'0')
}

/// Read one pkt-line at `pos`; `Ok(None)` is a flush packet.
fn pkt_line(body: &[u8], pos: &mut usize) -> Result<Option<Vec<u8>>, PushRefusal> {
    let bad = || PushRefusal::new("malformed receive-pack request");
    let hdr = body.get(*pos..*pos + 4).ok_or_else(bad)?;
    let len = usize::from_str_radix(std::str::from_utf8(hdr).map_err(|_| bad())?, 16)
        .map_err(|_| bad())?;
    if len == 0 {
        *pos += 4;
        return Ok(None);
    }
    if len < 4 {
        return Err(bad());
    }
    let data = body.get(*pos + 4..*pos + len).ok_or_else(bad)?.to_vec();
    *pos += len;
    Ok(Some(data))
}

fn parse_request(body: &[u8]) -> Result<Parsed, PushRefusal> {
    let bad = || PushRefusal::new("malformed receive-pack request");
    let mut pos = 0;
    let mut commands = Vec::new();
    let mut caps: Vec<String> = Vec::new();
    while let Some(line) = pkt_line(body, &mut pos)? {
        let line = String::from_utf8(line).map_err(|_| bad())?;
        let (line, line_caps) = match line.split_once('\0') {
            Some((l, c)) => (l, Some(c)),
            None => (line.as_str(), None),
        };
        if let Some(c) = line_caps {
            if caps.is_empty() {
                caps = c.split_whitespace().map(str::to_owned).collect();
            }
        }
        let line = line.trim_end_matches('\n');
        if line.starts_with("shallow ") {
            continue;
        }
        if line.starts_with("push-cert") {
            return Err(PushRefusal::new("signed pushes are not supported"));
        }
        let mut it = line.split(' ');
        let (Some(old), Some(new), Some(refname), None) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(bad());
        };
        if !is_oid(old) || !is_oid(new) || old.len() != new.len() || !refname.starts_with("refs/") {
            return Err(bad());
        }
        commands.push(RefUpdate {
            new: new.to_owned(),
            refname: refname.to_owned(),
        });
        if commands.len() > MAX_PUSH_COMMANDS {
            return Err(PushRefusal::new("push carries too many ref updates"));
        }
    }
    if caps.iter().any(|c| c == "push-options") {
        while pkt_line(body, &mut pos)?.is_some() {}
    }
    Ok(Parsed {
        commands,
        caps,
        pack_start: pos,
    })
}

/// Reason text safe to put in a pkt-line: printable ASCII only, bounded.
fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(160)
        .collect()
}

/// Builtin path rules, then the embedder's classifier. Returns the reason.
fn check_path(raw: &[u8], guard: &PushPathGuard) -> Result<(), PushRefusal> {
    let refuse =
        |p: &str| PushRefusal::new(format!("path is reserved by the pod: {}", sanitise(p)));
    let Ok(path) = std::str::from_utf8(raw) else {
        return Err(PushRefusal::new("path is not valid UTF-8"));
    };
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(refuse(path));
    }
    let rooted = format!("/{path}");
    // Judge the lower-cased spelling too: the check must not depend on the
    // case sensitivity of whatever filesystem later receives the file.
    if guard(&rooted) || guard(&rooted.to_ascii_lowercase()) {
        return Err(refuse(path));
    }
    Ok(())
}

/// Scan `git diff-tree -z --raw` output; `count` accumulates changed paths.
fn scan_raw(out: &[u8], guard: &PushPathGuard, count: &mut usize) -> Result<(), PushRefusal> {
    let mut toks = out.split(|b| *b == 0);
    while let Some(tok) = toks.next() {
        if tok.first() != Some(&b':') {
            continue; // commit id header
        }
        let meta = std::str::from_utf8(tok).map_err(|_| PushRefusal::new("unreadable diff"))?;
        let mut f = meta[1..].split(' ');
        let (_old_mode, new_mode) = (f.next(), f.next());
        let path = toks
            .next()
            .ok_or_else(|| PushRefusal::new("unreadable diff"))?;
        *count += 1;
        if *count > MAX_PUSH_PATHS {
            return Err(PushRefusal::new("push changes too many paths"));
        }
        if matches!(new_mode, Some("120000" | "160000")) {
            return Err(PushRefusal::new(
                "symbolic links and submodules cannot be pushed",
            ));
        }
        check_path(path, guard)?;
    }
    Ok(())
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    cap: usize,
) -> Result<Vec<u8>, PushRefusal> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = r
            .read(&mut chunk)
            .await
            .map_err(|_| PushRefusal::new("push inspection failed"))?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > cap {
            return Err(PushRefusal::new("push is too large to inspect"));
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

struct Repo<'a> {
    git_dir: &'a Path,
    quarantine: &'a Path,
}

impl Repo<'_> {
    /// Run `git <args>` against the repository with the quarantine layered on
    /// top. Returns `(success, stdout)`.
    async fn git(
        &self,
        args: &[&str],
        stdin: Option<Bytes>,
    ) -> Result<(bool, Vec<u8>), PushRefusal> {
        let fail = |_| PushRefusal::new("push inspection failed");
        let mut cmd = Command::new("git");
        cmd.args(args)
            .env_clear()
            .env("GIT_DIR", self.git_dir)
            .env("GIT_OBJECT_DIRECTORY", self.quarantine.join("objects"))
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                self.git_dir.join("objects"),
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        let mut child = cmd.spawn().map_err(fail)?;
        if let Some(data) = stdin {
            if let Some(mut si) = child.stdin.take() {
                tokio::spawn(async move {
                    let _ = si.write_all(&data).await;
                });
            }
        }
        let mut stdout = child.stdout.take().expect("stdout piped");
        let out = read_capped(&mut stdout, MAX_GIT_OUTPUT).await?;
        let status = child.wait().await.map_err(fail)?;
        Ok((status.success(), out))
    }
}

struct Quarantine(PathBuf);

impl Quarantine {
    fn create(git_dir: &Path) -> std::io::Result<Self> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = git_dir.join(format!(
            "solid-pod-quarantine-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("objects").join("pack"))?;
        Ok(Self(dir))
    }
}

impl Drop for Quarantine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Inspect a `git-receive-pack` request body. `Ok(())` means every path the
/// push would change is acceptable to `guard`.
pub(crate) async fn check_push(
    git_dir: &Path,
    body: &Bytes,
    guard: &PushPathGuard,
) -> Result<(), PushRefusal> {
    match tokio::time::timeout(PUSH_CHECK_TIMEOUT, check_push_inner(git_dir, body, guard)).await {
        Ok(r) => r,
        Err(_) => Err(PushRefusal::new("push inspection timed out")),
    }
}

async fn check_push_inner(
    git_dir: &Path,
    body: &Bytes,
    guard: &PushPathGuard,
) -> Result<(), PushRefusal> {
    if body.len() > MAX_PUSH_BODY_BYTES {
        return Err(PushRefusal::new("push is too large to inspect"));
    }
    let parsed = parse_request(body)?;
    let news: Vec<&RefUpdate> = parsed
        .commands
        .iter()
        .filter(|c| !is_zero(&c.new))
        .collect();
    if news.is_empty() {
        return Ok(()); // pure deletions change no tree
    }
    let quarantine =
        Quarantine::create(git_dir).map_err(|_| PushRefusal::new("push inspection failed"))?;
    let repo = Repo {
        git_dir,
        quarantine: &quarantine.0,
    };

    let pack = &body[parsed.pack_start..];
    if !pack.is_empty() {
        let (ok, _) = repo
            .git(
                &["index-pack", "--stdin", "--fix-thin"],
                Some(Bytes::copy_from_slice(pack)),
            )
            .await?;
        if !ok {
            return Err(PushRefusal::new("malformed pack"));
        }
    }

    let mut count = 0usize;

    // Every commit the push introduces, diffed against each parent.
    let mut args = vec![
        "rev-list".to_owned(),
        format!("--max-count={}", MAX_PUSH_COMMITS + 1),
    ];
    args.extend(news.iter().map(|c| c.new.clone()));
    args.extend(["--not".to_owned(), "--all".to_owned()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, commits) = repo.git(&argv, None).await?;
    if !ok {
        return Err(PushRefusal::new(
            "push references objects that are not commits",
        ));
    }
    let n_commits = commits
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    if n_commits > MAX_PUSH_COMMITS {
        return Err(PushRefusal::new("push carries too many commits"));
    }
    if n_commits > 0 {
        let (ok, raw) = repo
            .git(
                &[
                    "diff-tree",
                    "--stdin",
                    "-r",
                    "-z",
                    "--raw",
                    "--no-renames",
                    "-m",
                    "--root",
                    "--no-abbrev",
                ],
                Some(Bytes::from(commits)),
            )
            .await?;
        if !ok {
            return Err(PushRefusal::new("push inspection failed"));
        }
        scan_raw(&raw, guard, &mut count)?;
    }

    // The checked-out branch: diff the new tip against the current HEAD.
    let (ok, head_ref) = repo.git(&["symbolic-ref", "-q", "HEAD"], None).await?;
    if ok {
        let head_ref = String::from_utf8_lossy(&head_ref).trim().to_owned();
        let (has_head, head) = repo
            .git(&["rev-parse", "-q", "--verify", "HEAD^{commit}"], None)
            .await?;
        let base = if has_head {
            String::from_utf8_lossy(&head).trim().to_owned()
        } else {
            // Unborn branch: everything in the new tip is new to the tree.
            let (ok, empty) = repo
                .git(
                    &["hash-object", "-t", "tree", "--stdin"],
                    Some(Bytes::new()),
                )
                .await?;
            if !ok {
                return Err(PushRefusal::new("push inspection failed"));
            }
            String::from_utf8_lossy(&empty).trim().to_owned()
        };
        if !is_oid(&base) {
            return Err(PushRefusal::new("push inspection failed"));
        }
        for c in news.iter().filter(|c| c.refname == head_ref) {
            let (ok, raw) = repo
                .git(
                    &[
                        "diff-tree",
                        "-r",
                        "-z",
                        "--raw",
                        "--no-renames",
                        "--no-abbrev",
                        &base,
                        &c.new,
                    ],
                    None,
                )
                .await?;
            if !ok {
                return Err(PushRefusal::new("push inspection failed"));
            }
            scan_raw(&raw, guard, &mut count)?;
        }
    }
    Ok(())
}

fn pkt(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    out.extend_from_slice(payload);
}

/// The `git-receive-pack` result a client understands as "rejected": an
/// `unpack ok` line and an `ng` line per ref update, side-band wrapped when the
/// client asked for it. Falls back to a plain 403 when the client did not
/// request `report-status`.
pub(crate) fn refusal_response(
    body: &[u8],
    reason: &PushRefusal,
) -> Result<GitResponse, PushRefusal> {
    let Ok(parsed) = parse_request(body) else {
        return Err(reason.clone());
    };
    let caps = &parsed.caps;
    if !caps
        .iter()
        .any(|c| c == "report-status" || c == "report-status-v2")
    {
        return Err(reason.clone());
    }
    let refs: Vec<&str> = parsed.commands.iter().map(|c| c.refname.as_str()).collect();
    let why = sanitise(&format!("push refused: {}", reason.0));
    let mut report = Vec::new();
    pkt(&mut report, b"unpack ok\n");
    for r in &refs {
        pkt(
            &mut report,
            format!("ng {} {why}\n", sanitise(r)).as_bytes(),
        );
    }
    report.extend_from_slice(b"0000");
    let payload = if caps
        .iter()
        .any(|c| c == "side-band-64k" || c == "side-band")
    {
        let mut wrapped = Vec::new();
        let mut band = vec![1u8];
        band.extend_from_slice(&report);
        pkt(&mut wrapped, &band);
        wrapped.extend_from_slice(b"0000");
        wrapped
    } else {
        report
    };
    let mut headers = vec![
        (
            "Content-Type".to_owned(),
            "application/x-git-receive-pack-result".to_owned(),
        ),
        ("Cache-Control".to_owned(), "no-cache".to_owned()),
    ];
    headers.extend(git_cors_header_pairs());
    Ok(GitResponse {
        status: 200,
        headers,
        body: Bytes::from(payload),
    })
}

/// One async lock per git directory, so `HEAD` cannot move between the check
/// and the CGI run.
pub(crate) fn repo_lock(git_dir: &Path) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut map = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.entry(git_dir.to_path_buf()).or_default().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_path_rules_hold_even_when_the_guard_allows_everything() {
        let allow: PushPathGuard = Arc::new(|_| false);
        for bad in [
            &b"a/../b"[..],
            b"..",
            b"./a",
            b"a//b",
            b"/abs",
            b"a\\b",
            b"a\0b",
            b"",
            b"caf\xe9",
        ] {
            assert!(check_path(bad, &allow).is_err(), "{bad:?}");
        }
        assert!(check_path(b"docs/a.txt", &allow).is_ok());
    }

    #[test]
    fn the_guard_sees_rooted_and_lower_cased_spellings() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let g: PushPathGuard = Arc::new(move |p| {
            s.lock().unwrap().push(p.to_owned());
            false
        });
        check_path(b"A/B", &g).unwrap();
        assert_eq!(*seen.lock().unwrap(), ["/A/B", "/a/b"]);
    }

    #[test]
    fn request_parser_reads_commands_caps_and_pack_offset() {
        let z = "0".repeat(40);
        let n = "1".repeat(40);
        let line = format!("{z} {n} refs/heads/main\0 report-status side-band-64k\n");
        let mut body = format!("{:04x}{line}0000", line.len() + 4).into_bytes();
        body.extend(b"PACK");
        let p = parse_request(&body).unwrap();
        assert_eq!(p.commands.len(), 1);
        assert_eq!(p.commands[0].refname, "refs/heads/main");
        assert_eq!(p.caps, ["report-status", "side-band-64k"]);
        assert_eq!(&body[p.pack_start..], b"PACK");
        assert!(parse_request(b"0004").is_err());
        assert!(parse_request(b"zzzz").is_err());
    }
}
