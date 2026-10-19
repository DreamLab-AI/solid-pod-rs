//! Argv-only, hardened `git` runner for the read features (JSON API, search,
//! releases, archive).
//!
//! Every invocation goes through [`solid_pod_rs_git::hardened_git_async`]
//! (no hooks, no system/global config, no prompts), runs with the bare repo
//! as the working directory, takes arguments as an argv slice (never a
//! shell), has no stdin, no inherited `HOME`, and a hard stdout cap. Callers
//! validate refs and paths with [`crate::guard`] before they get here.

use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

use crate::error::ForgeError;

/// Result of one git run.
#[derive(Debug)]
pub struct GitOut {
    /// Exit code (`None` when killed by a signal).
    pub code: Option<i32>,
    /// Captured stdout, at most the requested cap.
    pub stdout: Vec<u8>,
    /// `true` when stdout hit the cap and the child was killed.
    pub truncated: bool,
    /// Captured stderr (lossy UTF-8, bounded to 64 KiB).
    pub stderr: String,
}

impl GitOut {
    /// Did git exit zero without truncation?
    #[must_use]
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.truncated
    }
}

/// Run `git <args>` in `git_dir`, capturing at most `cap` bytes of stdout.
///
/// # Errors
///
/// [`ForgeError::Unsupported`] when no `git` binary exists, otherwise
/// [`ForgeError::Io`] on spawn or read failures. A non-zero exit is **not**
/// an error here: inspect [`GitOut::code`] (`git grep` exits 1 on no match).
pub async fn run(git_dir: &Path, args: &[&str], cap: usize) -> Result<GitOut, ForgeError> {
    run_within(git_dir, args, cap, GIT_TIMEOUT).await
}

/// Wall-clock budget for one read-side git invocation. Dropping the future
/// on expiry kills the child (`kill_on_drop`), so a `git grep` over a huge
/// branch cannot hold a CPU for longer than this.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// [`run`] with an explicit wall-clock `limit`.
///
/// # Errors
///
/// As [`run`], plus [`ForgeError::Backend`] (`timed out`) when git outlives
/// `limit`; the child is killed.
pub async fn run_within(
    git_dir: &Path,
    args: &[&str],
    cap: usize,
    limit: Duration,
) -> Result<GitOut, ForgeError> {
    let sub = args.first().copied().unwrap_or("");
    match tokio::time::timeout(limit, run_unbounded(git_dir, args, cap)).await {
        Ok(r) => r,
        Err(_) => Err(ForgeError::Backend(format!("git {sub}: timed out"))),
    }
}

/// Permits for the expensive read operations (`git grep`, `git archive`).
const HEAVY_PERMITS: usize = 4;

/// How long a heavy request waits for a permit before a 503.
const HEAVY_WAIT: Duration = Duration::from_secs(5);

fn heavy() -> &'static Semaphore {
    static S: OnceLock<Semaphore> = OnceLock::new();
    S.get_or_init(|| Semaphore::new(HEAVY_PERMITS))
}

/// [`run`] for operations that can burn real CPU or memory (search, archive):
/// at most four run at once process-wide, and a request that
/// cannot get a permit within a few seconds is [`ForgeError::Busy`] (503).
///
/// # Examples
///
/// ```
/// use solid_pod_rs_forge::gitrun::run_heavy;
///
/// # async fn demo(repo: &std::path::Path) -> Result<(), solid_pod_rs_forge::error::ForgeError> {
/// let out = run_heavy(repo, &["grep", "-F", "-i", "-e", "needle", "HEAD"], 1 << 20).await?;
/// // `git grep` exits 1 when nothing matches; that is not an error.
/// assert!(out.code == Some(0) || out.code == Some(1));
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// As [`run`], plus [`ForgeError::Busy`].
pub async fn run_heavy(git_dir: &Path, args: &[&str], cap: usize) -> Result<GitOut, ForgeError> {
    run_gated(heavy(), HEAVY_WAIT, git_dir, args, cap).await
}

async fn run_gated(
    gate: &Semaphore,
    wait: Duration,
    git_dir: &Path,
    args: &[&str],
    cap: usize,
) -> Result<GitOut, ForgeError> {
    let _permit = tokio::time::timeout(wait, gate.acquire())
        .await
        .map_err(|_| ForgeError::Busy("too many search or archive requests, retry shortly".into()))?
        .map_err(|_| ForgeError::Busy("search is shutting down".into()))?;
    run(git_dir, args, cap).await
}

async fn run_unbounded(git_dir: &Path, args: &[&str], cap: usize) -> Result<GitOut, ForgeError> {
    let mut cmd = solid_pod_rs_git::hardened_git_async();
    cmd.args(args)
        .current_dir(git_dir)
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ForgeError::Unsupported("git binary not found in PATH".into())
        } else {
            ForgeError::Io(e)
        }
    })?;
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(e) = err.as_mut() {
            let _ = e.take(64 * 1024).read_to_end(&mut buf).await;
        }
        String::from_utf8_lossy(&buf).into_owned()
    });
    let mut stdout = Vec::new();
    let mut truncated = false;
    if let Some(o) = out.as_mut() {
        let n = o.take(cap as u64 + 1).read_to_end(&mut stdout).await?;
        if n > cap {
            stdout.truncate(cap);
            truncated = true;
            let _ = child.start_kill();
        }
    }
    let status = child.wait().await?;
    let stderr = stderr_task.await.unwrap_or_default();
    Ok(GitOut {
        code: status.code(),
        stdout,
        truncated,
        stderr,
    })
}

/// Run and return stdout as lossy UTF-8; any failure (non-zero exit,
/// truncation) is [`ForgeError::NotFound`] when git complains about an
/// unknown object, else [`ForgeError::Backend`].
pub async fn text(git_dir: &Path, args: &[&str]) -> Result<String, ForgeError> {
    let o = run(git_dir, args, 64 * 1024 * 1024).await?;
    if o.ok() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(map_failure(args, &o))
    }
}

/// Run and return raw stdout bytes with the same failure mapping as [`text`].
pub async fn bytes(git_dir: &Path, args: &[&str], cap: usize) -> Result<Vec<u8>, ForgeError> {
    let o = run(git_dir, args, cap).await?;
    if o.ok() {
        Ok(o.stdout)
    } else {
        Err(map_failure(args, &o))
    }
}

fn map_failure(args: &[&str], o: &GitOut) -> ForgeError {
    let s = &o.stderr;
    if s.contains("unknown revision")
        || s.contains("bad revision")
        || s.contains("Not a valid object")
        || s.contains("does not exist")
        || s.contains("exists on disk, but not in")
        || s.contains("bad object")
        || s.contains("not a tree object")
        || s.contains("invalid object name")
    {
        ForgeError::NotFound(s.trim().to_string())
    } else if o.truncated {
        ForgeError::BadRequest("output too large".into())
    } else {
        ForgeError::Backend(format!(
            "git {}: {}",
            args.first().copied().unwrap_or(""),
            s.trim()
        ))
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Fixture helpers shared by the unit tests of the git-backed modules.

    use std::path::{Path, PathBuf};

    /// Run a plain git command for fixture set-up (panics on failure).
    pub fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Casey Coder",
                "-c",
                "user.email=casey@example.org",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// The JSS test fixture: README with a `<script>` line, `src/main.js`
    /// (two commits), `docs/notes.txt`, a binary and an `.html` file, tag
    /// `v1.0`. Returns the bare repo at `<root>/repos/casey/demo.git` and the
    /// second commit's sha.
    pub fn demo_repo(root: &Path) -> (PathBuf, String) {
        let work = root.join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::create_dir_all(work.join("docs")).unwrap();
        std::fs::write(
            work.join("README.md"),
            "# Demo Project\n\nA demo with **bold**, `inline code`, and a [doc](docs/notes.txt).\n\n```js\nconsole.log('hi');\n```\n\n<script>alert(1)</script>\n",
        )
        .unwrap();
        std::fs::write(
            work.join("src/main.js"),
            "function main() {\n  return 1;\n}\n",
        )
        .unwrap();
        std::fs::write(work.join("docs/notes.txt"), "notes live in a subdir\n").unwrap();
        std::fs::write(
            work.join("blob.bin"),
            [0u8, 1, 2, 3, 0, 0xff, 0xfe, 0, 0x89, 0x50],
        )
        .unwrap();
        std::fs::write(work.join("evil.html"), "<script>alert(\"xss\")</script>\n").unwrap();
        git(&work, &["init", "--quiet"]);
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "--quiet", "-m", "initial import"]);
        std::fs::write(
            work.join("src/main.js"),
            "function main() {\n  return 2;\n}\n",
        )
        .unwrap();
        git(&work, &["commit", "--quiet", "-am", "tweak main"]);
        git(&work, &["tag", "v1.0"]);
        let sha2 = git(&work, &["rev-parse", "HEAD"]);
        let bare = root.join("repos/casey/demo.git");
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        git(
            root,
            &[
                "clone",
                "--bare",
                "--quiet",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        (bare, sha2)
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// A git process that outlives its budget is abandoned with a timeout
    /// error instead of holding the request (and a CPU) indefinitely.
    #[tokio::test]
    async fn slow_git_is_cut_off_by_the_wall_clock() {
        let td = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        let r = run_within(
            td.path(),
            &["-c", "alias.slow=!sleep 20", "slow"],
            1024,
            Duration::from_millis(200),
        )
        .await;
        match r {
            Err(ForgeError::Backend(m)) => assert!(m.contains("timed out"), "{m}"),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn gated_runs_fail_busy_when_every_permit_is_taken() {
        let gate = Semaphore::new(1);
        let _held = gate.acquire().await.unwrap();
        let td = tempfile::tempdir().unwrap();
        let r = run_gated(
            &gate,
            Duration::from_millis(100),
            td.path(),
            &["--version"],
            1024,
        )
        .await;
        assert!(matches!(r, Err(ForgeError::Busy(_))), "{r:?}");
    }
}
