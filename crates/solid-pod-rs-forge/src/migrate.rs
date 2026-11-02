//! Boot migration of pre-release served stores, and the served-store
//! plumbing it shares with the mirror engine. Kept outside the `mirror`
//! feature: a plugin directory that was mirrored once must be migrated even
//! when it is now served without the feature.
//!
//! # Shared plumbing
//!
//! The fixed `--receive-pack` command ([`RECEIVE_PACK`]), the fixed served
//! config ([`SERVED_CONFIG`]), the cross-process lock path ([`lock_path`]),
//! the legacy-config probe and the hardened, process-group `git` runner.
//!
//! # Migration
//!
//! [`crate::ForgeService::new`] runs it before returning. A mirror-class
//! store (a 64-hex owner) is migrated when it has no
//! [`crate::PUBLICATION_MARKER`] and shows any pre-release signal, each
//! checked on its own: a mirror record that is flagged, pre-release or
//! unreadable; `refs/mirror/*`; `hideRefs` naming them; alternates; or an
//! earlier migration report. A check that fails with nothing positive found
//! gates the store instead (a `detection-error` journal, removed only once a
//! later boot examines every signal and finds them negative). If the pass
//! cannot list every journal and served store, or cannot gate a store, it
//! reports itself incomplete and the forge refuses every mirror-class store
//! (and every fork).
//! Walks and the push run with replacements and grafts off. Under the
//! store's lock (waited for at most
//! 600 s), with a journal ([`journal_path`]) recording each step:
//!
//! 1. the attempt is counted and a fresh store initialised in
//!    `plugin_dir/mirror-work/staging/`;
//! 2. the roots (branches and tags with safe names) are pushed into it by
//!    SHA, under the [`MAX_REPO_BYTES`] cap, with every other ref whose
//!    closure lies inside theirs; `refs/mirror/*`, pull request heads,
//!    `refs/replace/*`, unsafe or non-UTF-8 names and refs outside the roots
//!    are dropped and reported;
//! 3. it is verified at object level (no object any ref reaches outside the
//!    roots, nothing outside the roots' closure, no alternates, no object file
//!    shared with the old store), then given its [`MIGRATION_ID_FILE`] and
//!    marked;
//! 4. a report naming the migration id is written beside the recovery path
//!    (`<name>.git.<ts>.migration.json`, `.held`, `.dropped`), never over an
//!    existing one;
//! 5. the old store is renamed to `plugin_dir/mirror-recovery/<owner>/<name>.git.<ts>`
//!    and the new one into `repos/`;
//! 6. the record's awaits-migration flag is removed, the candidate wiped and
//!    the journal deleted.
//!
//! Journal, report and lists are `fsync`ed before the renames that depend on
//! them. A crash is resumed at the next boot: a rebuilt store already in
//! `repos/` carrying the journal's migration id is finished, never rebuilt;
//! otherwise the store is rebuilt from the old store, read from recovery
//! once it has moved. Every journal, in any state, keeps every reader
//! refusing the store (503) until it is deleted. A failure leaves a `failed`
//! journal; after [`MAX_ATTEMPTS`] attempts, crashes
//! included, boot stops retrying. Recovery copies are never deleted
//! automatically and must never be served: do not add `.forge` to the pod's
//! dotfile allowlist.
//!
//! # Forks
//!
//! After the mirror-class stores, the same machinery sweeps forks of them
//! (any owner): every served repository's `forge.parent` is read (a config
//! that cannot be read makes the pass incomplete, and the forge then also
//! refuses every fork), each fork's lineage is walked to its root, and a
//! fork holding any object of a migrated ancestor's `.dropped` set is
//! rebuilt. It keeps every ref but `refs/mirror/*` and `refs/replace/*`,
//! except a ref reaching an object in the ancestors' `.held` sets, which is
//! dropped and reported. A fork whose ancestor is still behind a journal is
//! gated. Stale `repos/<owner>/.fork-*.tmp` directories are moved to
//! recovery. See the `migrate_fork` source for the details.
//!
//! # Example
//!
//! ```
//! use std::path::Path;
//! use solid_pod_rs_forge::migrate::lock_path;
//!
//! let owner = "a".repeat(64);
//! let lock = lock_path(Path::new("/srv/forge"), &owner, "sample");
//! assert_eq!(
//!     lock,
//!     Some(Path::new("/srv/forge/mirror-work/locks").join(&owner).join("sample.lock"))
//! );
//! assert_eq!(lock_path(Path::new("/srv/forge"), "..", "sample"), None);
//! ```

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mirror_record::{is_hex64, is_repo_name, MirrorStore, StoredRecord};
use crate::ownership::valid_name_segment;

/// The `--receive-pack` command every push into a served store runs on the
/// receiving side.
///
/// Local transport strips the pusher's `-c` options before receive-pack
/// starts, so this string (with the served store's own config) is the hook
/// boundary. Git runs it through a shell: it is a fixed literal, equal to
/// `solid_pod_rs_git::hardened::HARDENED_CONFIG` plus the receive keys.
/// Never interpolate a path, name or sha into it; that would be shell
/// injection.
pub const RECEIVE_PACK: &str = "git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
-c core.sshCommand=false -c commit.gpgSign=false -c receive.fsckObjects=true \
-c receive.denyDeletes=true receive-pack";

/// Config every served store carries, written when it is created or first
/// marked: no hooks, objects checked on receipt, no ref deletion.
pub const SERVED_CONFIG: [(&str, &str); 3] = [
    ("core.hooksPath", "/dev/null"),
    ("receive.fsckObjects", "true"),
    ("receive.denyDeletes", "true"),
];

/// Largest a mirrored repository may grow on disk, in bytes. A fetch that
/// pushes the candidate store past this is killed and the candidate removed;
/// a publication that grows the served store by more than this is killed;
/// and a boot migration whose staging store grows past it during the push
/// fails, leaving the old store gated.
pub const MAX_REPO_BYTES: u64 = 512 * 1024 * 1024;

/// The camelCase key of the mirror record's awaits-migration flag, as it is
/// written to `plugin_dir/mirror/<owner>/<name>.json`.
pub const AWAITS_MIGRATION_KEY: &str = "awaitsMigration";

/// The runner's error when git outran its deadline.
pub(crate) const GIT_TIMED_OUT: &str = "git timed out";

/// The runner's (and the mirror fetch's) error when a store grew past its
/// size cap.
pub(crate) const GREW_PAST_CAP: &str = "repository grew past the size cap";

/// How a capped git run measures the directory it watches (injectable so
/// tests can stand in a slow or fixed measurement).
pub(crate) type DirMeasure = fn(&Path) -> u64;

/// When a capped run measures the directory it watches: the delay before the
/// first measurement, then the interval between measurements.
type SizePoll = (Duration, Duration);

/// The size watcher's timing outside tests: measure at once, then every
/// 500 ms.
const SIZE_POLL: SizePoll = (Duration::ZERO, Duration::from_millis(500));

/// `plugin_dir/mirror-work/locks/<owner>/<name>.lock`: the cross-process
/// advisory lock for one served repository, shared by the mirror engine and
/// boot migration so that each excludes the other, across server instances
/// too.
///
/// `None` unless both `owner` and `name` are single safe path segments
/// ([`crate::ownership::valid_name_segment`]). For a 64-hex owner the path is
/// the one the mirror engine has always locked.
#[must_use]
pub fn lock_path(plugin_dir: &Path, owner: &str, name: &str) -> Option<PathBuf> {
    if !valid_name_segment(owner) || !valid_name_segment(name) {
        return None;
    }
    Some(
        plugin_dir
            .join("mirror-work")
            .join("locks")
            .join(owner)
            .join(format!("{name}.lock")),
    )
}

#[path = "migrate_fork.rs"]
mod fork;

/// How a store is rebuilt: as a mirror-class store, or as a fork of one or
/// more migrated mirror-class stores (the fork sweep, [`fork`]).
#[derive(Debug, Clone)]
enum Kind {
    Mirror,
    Fork(fork::Plan),
}

impl Kind {
    /// The journal and report `class`.
    fn class(&self) -> &'static str {
        match self {
            Self::Mirror => "mirror",
            Self::Fork(_) => "fork",
        }
    }

    /// Whether the rebuilt store gets the mirror's served config and the
    /// marker (a mirror-class store, or a followed fork).
    fn mirror_config(&self) -> bool {
        match self {
            Self::Mirror => true,
            Self::Fork(plan) => plan.followed(),
        }
    }
}

/// Whether `git config --list -z` output sets `uploadpack.hideRefs` or
/// `transfer.hideRefs` to a value naming `refs/mirror`. Each entry is
/// `key\nvalue\0`; git prints section and variable names in lower case.
pub(crate) fn hides_mirror_refs(list_z: &[u8]) -> bool {
    list_z.split(|b| *b == 0).any(|entry| {
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = entry.split_once('\n').unwrap_or((&entry, ""));
        let key = key.to_ascii_lowercase();
        (key == "uploadpack.hiderefs" || key == "transfer.hiderefs")
            && value.contains("refs/mirror")
    })
}

/// Create `dir` and initialise an empty bare repository in it, with `main`
/// as the initial branch.
pub(crate) async fn init_bare(dir: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| e.to_string())?;
    run_in(
        dir,
        dir,
        &["init", "--bare", "--quiet", "--initial-branch=main", "."],
        None,
        Duration::from_secs(15),
        None,
    )
    .await
    .map(|_| ())
}

/// Write [`SERVED_CONFIG`] into the local config of the store at `dir`.
pub(crate) async fn write_served_config(dir: &Path) -> Result<(), String> {
    for (key, value) in SERVED_CONFIG {
        run_in(
            dir,
            dir,
            &["config", "--local", key, value],
            None,
            Duration::from_secs(15),
            None,
        )
        .await?;
    }
    Ok(())
}

/// Run git on the store at `git_dir`, named with an explicit `--git-dir` so
/// git never searches upward: a store missing `HEAD`, `objects/` or `refs/`
/// fails instead of resolving to whatever repository encloses it. `watch` is
/// git's working directory and, with `cap = (limit, measure)`, the directory
/// measured: it is measured at once and then every 500 ms while git runs,
/// and the group is killed once it is past `limit`. The walk runs on its own
/// task and only signals when the cap is passed, so a slow walk of a huge
/// repository can neither stall the draining of git's pipes nor delay the
/// deadline.
///
/// Returns stdout on success, or the first line of stderr.
pub(crate) async fn run_in(
    git_dir: &Path,
    watch: &Path,
    args: &[&str],
    allow: Option<&str>,
    timeout: Duration,
    cap: Option<(u64, DirMeasure)>,
) -> Result<Vec<u8>, String> {
    let out = run_output(git_dir, watch, args, allow, timeout, cap).await?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err.lines().next().unwrap_or("git failed").to_string())
    }
}

/// The hardened `git` command every runner here spawns: an explicit
/// `--git-dir` (git never searches upward),
/// [`solid_pod_rs_git::hardened_git_async`] (no hooks, no ambient config, no
/// prompts), an argv, `HOME` and `XDG_CONFIG_HOME` removed, stdin closed,
/// stdout and stderr piped, killed on drop, and (on Unix) its own process
/// group so a timeout can take down the helpers it spawned.
fn git_command(git_dir: &Path, cwd: &Path, args: &[&str]) -> tokio::process::Command {
    let mut explicit = std::ffi::OsString::from("--git-dir=");
    explicit.push(git_dir);
    let mut cmd = solid_pod_rs_git::hardened_git_async();
    cmd.arg(explicit)
        .args(args)
        .current_dir(cwd)
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    cmd
}

/// [`run_in`] without the exit-status check: git's whole output, for a
/// caller that must tell one non-zero status from another. `Err` only when
/// git could not be run to completion (it could not start, it timed out, the
/// cap killed it).
///
/// Every spawn goes through [`solid_pod_rs_git::hardened_git_async`] (no
/// hooks, no ambient config, no prompts) with an argv, in its own process
/// group, with `HOME` and `XDG_CONFIG_HOME` removed. `allow`, when set,
/// becomes `GIT_ALLOW_PROTOCOL`.
pub(crate) async fn run_output(
    git_dir: &Path,
    watch: &Path,
    args: &[&str],
    allow: Option<&str>,
    timeout: Duration,
    cap: Option<(u64, DirMeasure)>,
) -> Result<std::process::Output, String> {
    run_output_env(git_dir, watch, args, allow, timeout, cap, SIZE_POLL, &[]).await
}

/// [`run_output`] with `env` added to git's environment and the size
/// watcher's timing given by `poll`.
#[allow(clippy::too_many_arguments)]
async fn run_output_env(
    git_dir: &Path,
    watch: &Path,
    args: &[&str],
    allow: Option<&str>,
    timeout: Duration,
    cap: Option<(u64, DirMeasure)>,
    poll: SizePoll,
    env: &[(&str, &str)],
) -> Result<std::process::Output, String> {
    let mut cmd = git_command(git_dir, watch, args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(a) = allow {
        cmd.env("GIT_ALLOW_PROTOCOL", a);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("git could not start: {e}"))?;
    let pid = child.id();
    note_group(pid);
    let waited = child.wait_with_output();
    tokio::pin!(waited);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let (tx, mut grew) = tokio::sync::oneshot::channel::<()>();
    let watcher = cap.map(|(limit, measure)| {
        let d = watch.to_path_buf();
        tokio::spawn(async move {
            tokio::time::sleep(poll.0).await;
            loop {
                let d2 = d.clone();
                let size = tokio::task::spawn_blocking(move || measure(&d2))
                    .await
                    .unwrap_or(0);
                if size > limit {
                    let _ = tx.send(());
                    return;
                }
                tokio::time::sleep(poll.1).await;
            }
        })
    });
    let outcome = tokio::select! {
        out = &mut waited => Ok(out),
        () = &mut deadline => Err(GIT_TIMED_OUT.to_string()),
        Ok(()) = &mut grew => Err(GREW_PAST_CAP.to_string()),
    };
    if let Some(w) = watcher {
        w.abort();
    }
    match outcome {
        Ok(out) => {
            forget_group(pid);
            out.map_err(|e| format!("git failed: {e}"))
        }
        Err(why) => {
            kill_group(pid).await;
            forget_group(pid);
            Err(why)
        }
    }
}

/// Run git on the store at `git_dir` and read its stdout line by line,
/// returning the first line `pick` accepts (git is then killed), or `None`
/// once git has exited successfully without one. stderr is discarded; a
/// failure is reported as `git <command> failed`.
#[cfg(feature = "mirror")]
pub(crate) async fn first_line(
    git_dir: &Path,
    args: &[&str],
    timeout: Duration,
    pick: impl Fn(&str) -> bool,
) -> Result<Option<String>, String> {
    use tokio::io::AsyncBufReadExt;
    let mut cmd = git_command(git_dir, git_dir, args);
    cmd.stderr(std::process::Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("git could not start: {e}"))?;
    let pid = child.id();
    let what = args.first().copied().unwrap_or("git");
    let stdout = child.stdout.take().ok_or("git has no stdout")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let read = async {
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| format!("git {what} output unreadable: {e}"))?
        {
            if pick(&line) {
                return Ok(Some(line));
            }
        }
        Ok(None)
    };
    let started = tokio::time::Instant::now();
    match tokio::time::timeout(timeout, read).await {
        Err(_) => {
            kill_group(pid).await;
            Err(GIT_TIMED_OUT.to_string())
        }
        Ok(Ok(None)) => {
            let left = timeout.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, child.wait()).await {
                Ok(Ok(st)) if st.success() => Ok(None),
                Ok(_) => Err(format!("git {what} failed")),
                Err(_) => {
                    kill_group(pid).await;
                    Err(GIT_TIMED_OUT.to_string())
                }
            }
        }
        Ok(found) => {
            kill_group(pid).await;
            found
        }
    }
}

/// Kill a process group by leader pid. `kill -KILL -- -<pid>` through the
/// system `kill`, because `unsafe` is forbidden here; a no-op where there is
/// no pid or no `kill`.
pub(crate) async fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = tokio::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
}

// ---------------------------------------------------------------------------
// Boot migration of pre-release served stores
// ---------------------------------------------------------------------------

/// How many migration attempts of one store boot makes. An attempt counts
/// when it starts, so a crash mid-build counts too. After this many the
/// store is no longer retried at boot; its journal stays and every reader
/// refuses it (503) until an operator acts.
pub const MAX_ATTEMPTS: u32 = 3;

/// Wall-clock budget for migrating one store, and the longest boot waits
/// for one store's lock.
const STORE_BUDGET: Duration = Duration::from_secs(600);

/// Most refspecs in one push, to stay inside argv limits.
const PUSH_BATCH: usize = 512;

/// Most object ids one in-memory set of a store may hold (about 50 bytes
/// each): the held set, and the staging objects checked against the roots.
/// A store past it fails closed: it is not migrated and stays gated behind
/// its journal.
const MAX_HELD_IDS: usize = 16_000_000;

/// The file at the root of a rebuilt store that names the migration (the
/// journal id) that built it. Resume and the finish-only path compare it
/// with the journal and the report, so a store that is not this migration's
/// is never published or finished as if it were.
pub const MIGRATION_ID_FILE: &str = "migration-id";

/// The reason prefix of a gate journal written because detection could not
/// examine a store. Only a journal with this prefix is removed when a later
/// boot examines the store and finds it clean.
const DETECTION_ERROR: &str = "detection-error";

/// The limits one boot pass applies, per plugin directory (tests shorten
/// them through [`test_hooks`]).
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Longest the pass waits for one store's lock.
    lock_wait: Duration,
    /// Wall-clock budget for building one store.
    store_budget: Duration,
    /// Largest the staging store may grow during the push, in bytes.
    size_cap: u64,
    /// The push's size watcher timing.
    size_poll: SizePoll,
}

impl Limits {
    fn for_plugin(plugin: &Path) -> Self {
        let base = Self {
            lock_wait: STORE_BUDGET,
            store_budget: STORE_BUDGET,
            size_cap: MAX_REPO_BYTES,
            size_poll: SIZE_POLL,
        };
        #[cfg(test)]
        {
            test_hooks::limits(plugin, base)
        }
        #[cfg(not(test))]
        {
            let _ = plugin;
            base
        }
    }
}

/// Test-only fault and limit injection, keyed by the absolute plugin
/// directory (tests run in parallel, so nothing here is process-wide).
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    /// What a test injects for one plugin directory.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct Hooks {
        pub(crate) lock_wait: Option<Duration>,
        pub(crate) store_budget: Option<Duration>,
        pub(crate) size_cap: Option<u64>,
        /// Delay the push's size watcher by this long, and measure only this
        /// often (a fast push then finishes before any measurement).
        pub(crate) size_poll: Option<Duration>,
        /// Panic on the migration thread before anything is migrated.
        pub(crate) panic_at_boot: bool,
        /// `std::process::abort()` once the `building` journal is written
        /// (a crash mid-build; only ever set in a child process).
        pub(crate) abort_in_build: bool,
        /// Run, inside the build, a git alias that backgrounds
        /// `sleep <token>` in git's process group and waits on it.
        pub(crate) slow_child: Option<String>,
    }

    static HOOKS: Mutex<Vec<(PathBuf, Hooks)>> = Mutex::new(Vec::new());

    fn key(plugin: &Path) -> PathBuf {
        std::path::absolute(plugin).unwrap_or_else(|_| plugin.to_path_buf())
    }

    /// Install `h` for `plugin`, replacing any earlier hooks for it.
    pub(crate) fn set(plugin: &Path, h: Hooks) {
        let k = key(plugin);
        let mut all = HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|(p, _)| *p != k);
        all.push((k, h));
    }

    /// Remove the hooks for `plugin`.
    pub(crate) fn clear(plugin: &Path) {
        let k = key(plugin);
        HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(p, _)| *p != k);
    }

    /// The hooks for `plugin` (all off when none are installed).
    pub(crate) fn get(plugin: &Path) -> Hooks {
        let k = key(plugin);
        HOOKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(p, _)| *p == k)
            .map(|(_, h)| h.clone())
            .unwrap_or_default()
    }

    pub(super) fn limits(plugin: &Path, base: super::Limits) -> super::Limits {
        let h = get(plugin);
        super::Limits {
            lock_wait: h.lock_wait.unwrap_or(base.lock_wait),
            store_budget: h.store_budget.unwrap_or(base.store_budget),
            size_cap: h.size_cap.unwrap_or(base.size_cap),
            size_poll: h.size_poll.map_or(base.size_poll, |d| (d, d)),
        }
    }
}

/// `plugin_dir/mirror-work/migrations/<owner>/<name>.json`: the migration
/// journal of one served repository.
///
/// While any entry exists at this path the repository is being migrated,
/// or its migration failed: every forge reader refuses it (503), the mirror
/// engine neither creates nor prepares the store, smart-HTTP refuses a push
/// into it and a fork onto its name is refused. `None` unless both segments are safe
/// ([`crate::ownership::valid_name_segment`]).
#[must_use]
pub fn journal_path(plugin_dir: &Path, owner: &str, name: &str) -> Option<PathBuf> {
    if !valid_name_segment(owner) || !valid_name_segment(name) {
        return None;
    }
    Some(
        plugin_dir
            .join("mirror-work")
            .join("migrations")
            .join(owner)
            .join(format!("{name}.json")),
    )
}

/// The stage a migration reached, as its journal records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Stage {
    /// Staging is being built.
    Building,
    /// Staging passed verification and is marked.
    Verified,
    /// The old store is in recovery; the rebuilt store is about to be (or
    /// has just been) renamed into `repos/`.
    Moved,
    /// The rebuilt store is in `repos/`; the record flag, the candidate and
    /// the journal remain to be cleared.
    Published,
    /// The last attempt failed, or the store is gated without one (a
    /// detection error, a lock not taken); see the reason.
    Failed,
}

/// The migration journal of one store (see [`journal_path`]). Paths are
/// relative to the plugin directory and are checked before any use
/// ([`contained`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    id: String,
    ts: u64,
    class: String,
    state: Stage,
    /// Whether the old store has been renamed to `recovery`. Once set, the
    /// old store is only ever read from there.
    #[serde(default)]
    moved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staging: Option<String>,
    recovery: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// A fork's `forge.parent` (`<owner>/<name>`), so a resumed fork
    /// migration knows its lineage while its store is in recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
}

/// What is at a journal path.
enum JournalRead {
    /// Nothing ("not found").
    Absent,
    /// A regular file holding a journal.
    Present(Journal),
    /// Anything else: a symlink, a directory, a file that cannot be read or
    /// parsed, a check that failed. It gates, and is never acted on.
    Bad(String),
}

/// Read `path` only if it is a regular file, not a symlink: `lstat`, open,
/// then `fstat`, refusing a file whose identity changed in between.
fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let mut file = std::fs::File::open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "changed while being read",
            ));
        }
    }
    if !after.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

/// Read the journal at `path` (see [`JournalRead`]).
fn read_journal(path: &Path) -> JournalRead {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return JournalRead::Absent,
        Err(e) => return JournalRead::Bad(format!("cannot be checked: {}", e.kind())),
        Ok(m) if !m.file_type().is_file() => {
            return JournalRead::Bad("not a regular file".into());
        }
        Ok(_) => {}
    }
    match read_regular(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(j) => JournalRead::Present(j),
            Err(e) => JournalRead::Bad(format!("not a journal: {e}")),
        },
        Err(e) => JournalRead::Bad(format!("cannot be read: {e}")),
    }
}

/// Whether a reader must refuse `<owner>/<name>` because of its migration
/// journal: anything at the journal path gates, in any state, `published`
/// included, and whatever its file type. "Not found" is the only answer
/// that lets the reader go on (decision 21). A migrated store is briefly
/// refused between the `published` write and [`finish`], which removes the
/// journal.
pub(crate) async fn journal_gates(plugin_dir: &Path, owner: &str, name: &str) -> bool {
    let Some(path) = journal_path(plugin_dir, owner, name) else {
        return false;
    };
    !matches!(
        tokio::task::spawn_blocking(move || read_journal(&path)).await,
        Ok(JournalRead::Absent)
    )
}

/// Whether any entry exists at the migration journal path of
/// `<owner>/<name>`, in any state and of any file type (the tombstone). An
/// entry that cannot be checked counts as present.
pub(crate) fn journal_exists(plugin_dir: &Path, owner: &str, name: &str) -> bool {
    let Some(path) = journal_path(plugin_dir, owner, name) else {
        return false;
    };
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Migrate every pre-release served store under `plugin_dir`, synchronously.
/// Returns whether the pass ran to completion.
///
/// Runs on a dedicated thread with its own current-thread `tokio` runtime and
/// joins it, so it behaves the same from plain synchronous code, from inside
/// actix's current-thread runtime and from a `#[tokio::test]`: no
/// `block_in_place`, no nested `block_on` on the caller's thread. A failure to
/// migrate one store is logged and leaves that store gated behind its
/// journal; it never fails the caller. `false` (the runtime could not be
/// built, the thread panicked, or a store could not be gated by a journal)
/// tells the caller to refuse every mirror-class store instead.
pub(crate) fn run_at_boot(plugin_dir: &Path) -> bool {
    let plugin = std::path::absolute(plugin_dir).unwrap_or_else(|_| plugin_dir.to_path_buf());
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            #[cfg(test)]
            assert!(
                !test_hooks::get(&plugin).panic_at_boot,
                "test hook: the migration thread panics"
            );
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(run(&plugin)),
                Err(e) => {
                    tracing::error!(error = %e, "forge: migration runtime not built; every mirror-class store is refused");
                    false
                }
            }
        });
        if let Ok(complete) = worker.join() {
            complete
        } else {
            tracing::error!(
                "forge: the migration thread panicked; every mirror-class store is refused"
            );
            false
        }
    })
}

/// One boot pass: resume every journal, then migrate every store detected as
/// needing it (or that detection could not examine). Serial, one lock at a
/// time. Returns `false` if any store could not be gated by a journal, or
/// the journals or stores could not all be listed.
async fn run(plugin: &Path) -> bool {
    let started = std::time::Instant::now();
    let mut outcomes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let (journals, journals_listed) = journaled(plugin);
    for (owner, name) in journals {
        seen.insert((owner.clone(), name.clone()));
        if journal_class(plugin, &owner, &name).as_deref() == Some("fork") {
            // A fork migration: resumed by the fork pass below.
            continue;
        }
        outcomes.push(migrate_one(plugin, &owner, &name).await);
    }
    let (stores, stores_listed) = served_stores(plugin);
    for (owner, name) in stores {
        if seen.contains(&(owner.clone(), name.clone())) {
            continue;
        }
        if matches!(
            detect(plugin, &owner, &name).await,
            Detected::Skip | Detected::Clean
        ) {
            continue;
        }
        outcomes.push(migrate_one(plugin, &owner, &name).await);
    }
    // Forks of migrated mirror-class stores, after every mirror-class store
    // (each lock released before the next is taken: never two at once).
    let mirror_complete = journals_listed && stores_listed && !outcomes.contains(&Outcome::Ungated);
    let forks = fork::sweep(plugin, mirror_complete).await;
    outcomes.extend(forks.outcomes);
    let count = |want: Outcome| outcomes.iter().filter(|o| **o == want).count();
    let (done, failed, ungated) = (
        count(Outcome::Migrated),
        count(Outcome::Failed),
        count(Outcome::Ungated),
    );
    if done + failed + ungated > 0 {
        tracing::info!(
            migrated = done,
            failed,
            ungated,
            ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "forge: legacy served stores migrated"
        );
    }
    if ungated > 0 {
        tracing::error!(
            ungated,
            "forge: a store could not be gated by a journal; every mirror-class store is refused"
        );
    }
    if !(journals_listed && stores_listed && forks.listed) {
        tracing::error!(
            "forge: the stores could not all be listed or read; every mirror-class store and every fork is refused"
        );
    }
    ungated == 0 && journals_listed && stores_listed && forks.listed
}

/// The `class` of the journal of `<owner>/<name>`, if one is there and
/// readable.
fn journal_class(plugin: &Path, owner: &str, name: &str) -> Option<String> {
    match read_journal(&journal_path(plugin, owner, name)?) {
        JournalRead::Present(j) => Some(j.class),
        _ => None,
    }
}

/// What one store's pass came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Migrated,
    /// Not migrated; a journal gates the store.
    Failed,
    /// Not migrated, and no journal could be written to gate it: the caller
    /// must gate it another way.
    Ungated,
    Skipped,
}

/// The names in directory `dir`, or an error. "Not found" is no names.
fn names_in(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("a directory could not be listed: {}", e.kind())),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("a directory entry could not be read: {}", e.kind()))?;
        out.push((e.file_name().to_string_lossy().into_owned(), e.path()));
    }
    Ok(out)
}

/// Every `(owner, name)` with an entry at its journal path, and whether the
/// listing was complete (every directory listed, every entry read).
fn journaled(plugin: &Path) -> (Vec<(String, String)>, bool) {
    let mut out = Vec::new();
    let mut complete = true;
    let root = plugin.join("mirror-work").join("migrations");
    let owners = names_in(&root).unwrap_or_else(|e| {
        tracing::error!(error = %e, "forge: migration journals not listed");
        complete = false;
        Vec::new()
    });
    for (owner, path) in owners {
        if !valid_name_segment(&owner) {
            continue;
        }
        match dir_state(&path) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::error!(owner = %owner, error = %e, "forge: migration journals not listed");
                complete = false;
                continue;
            }
        }
        match names_in(&path) {
            Ok(files) => {
                for (file, _) in files {
                    if let Some(name) = file.strip_suffix(".json") {
                        if valid_name_segment(name) {
                            out.push((owner.clone(), name.to_string()));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(owner = %owner, error = %e, "forge: migration journals not listed");
                complete = false;
            }
        }
    }
    out.sort();
    (out, complete)
}

/// Every served `(owner, name)` under `repos/` (directories `<name>.git`,
/// symlinks followed, as the readers do), and whether the listing was
/// complete. Unlike [`crate::repo::list_all`], an error listing a
/// directory, reading an entry or checking an entry's type is reported, never
/// taken for absence: a store the pass cannot see is a store it cannot
/// examine.
fn served_stores(plugin: &Path) -> (Vec<(String, String)>, bool) {
    let mut out = Vec::new();
    let mut complete = true;
    let repos = plugin.join("repos");
    let owners = names_in(&repos).unwrap_or_else(|e| {
        tracing::error!(error = %e, "forge: served repositories not listed");
        complete = false;
        Vec::new()
    });
    for (owner, path) in owners {
        if !valid_name_segment(&owner) {
            continue;
        }
        match dir_state(&path) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::error!(owner = %owner, error = %e, "forge: served repositories not listed");
                complete = false;
                continue;
            }
        }
        let repos = match names_in(&path) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(owner = %owner, error = %e, "forge: served repositories not listed");
                complete = false;
                continue;
            }
        };
        for (file, entry) in repos {
            let Some(name) = file.strip_suffix(".git") else {
                continue;
            };
            if !valid_name_segment(name) {
                continue;
            }
            match dir_state(&entry) {
                Ok(true) => out.push((owner.clone(), name.to_string())),
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(owner = %owner, name = %name, error = %e, "forge: served repository not checked");
                    complete = false;
                }
            }
        }
    }
    out.sort();
    (out, complete)
}

/// What detection found for one store.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Detected {
    /// Out of scope, or not examined: not a mirror-class name, no store, or
    /// a marked store whose record is not flagged. Nothing to do, but not
    /// proof the store is clean.
    Skip,
    /// Examined: an unmarked store, every signal checked successfully and
    /// found negative. The only answer that removes a `detection-error`
    /// journal.
    Clean,
    /// A legacy store: rebuild it.
    Rebuild,
    /// Rebuilt and marked by a migration whose report names the store's
    /// migration id, but the record still carries the flag (a crash after
    /// the journal was removed, or an engine write in between): finish only.
    Finish,
    /// A check could not be made and nothing positive was found: gate it.
    Error(String),
}

/// Paths of one store under the plugin directory.
struct Paths {
    served: PathBuf,
    staging_dir: PathBuf,
    recovery_dir: PathBuf,
    journal: PathBuf,
    lock: PathBuf,
    candidate: PathBuf,
}

impl Paths {
    fn of(plugin: &Path, owner: &str, name: &str) -> Option<Self> {
        Some(Self {
            served: plugin.join("repos").join(owner).join(format!("{name}.git")),
            staging_dir: plugin.join("mirror-work").join("staging").join(owner),
            recovery_dir: plugin.join("mirror-recovery").join(owner),
            journal: journal_path(plugin, owner, name)?,
            lock: lock_path(plugin, owner, name)?,
            candidate: plugin
                .join("mirror-work")
                .join("candidates")
                .join(owner)
                .join(format!("{name}.git")),
        })
    }
}

/// Whether `p` is a directory, following symlinks as the readers do (an
/// operator may symlink a store to another disk). "Not found" is `false`;
/// any other error is an error, never taken for absence.
fn dir_state(p: &Path) -> Result<bool, String> {
    match std::fs::metadata(p) {
        Ok(m) => Ok(m.is_dir()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!(
            "a store directory could not be checked: {}",
            e.kind()
        )),
    }
}

/// [`dir_state`], an error counting as present (fail closed: a path that
/// cannot be checked is never treated as free).
fn is_dir(p: &Path) -> bool {
    dir_state(p).unwrap_or(true)
}

/// Whether `ts` is a non-empty run of ASCII digits.
fn all_digits(ts: &str) -> bool {
    !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit())
}

/// The migration reports (`<name>.git.<ts>.migration.json`, regular files)
/// in recovery. "Not found" is no reports; any other error is an error.
fn reports(recovery_dir: &Path, name: &str) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(recovery_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("the recovery directory: {}", e.kind())),
    };
    let prefix = format!("{name}.git.");
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("the recovery directory: {}", e.kind()))?;
        let f = e.file_name();
        let f = f.to_string_lossy();
        let is_report = f
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(".migration.json"))
            .is_some_and(all_digits);
        if is_report {
            out.push(e.path());
        }
    }
    Ok(out)
}

/// The `id` a report names, if it is a regular file holding one.
fn report_id(path: &Path) -> Option<String> {
    let bytes = read_regular(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("id")?.as_str().map(str::to_string)
}

/// The migration id a store carries ([`MIGRATION_ID_FILE`]), if it is a
/// regular file.
fn store_migration_id(store: &Path) -> Option<String> {
    let bytes = read_regular(&store.join(MIGRATION_ID_FILE)).ok()?;
    let id = String::from_utf8(bytes).ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| id.to_string())
}

/// Whether `served` carries migration id `id` (and, when `marked`, the
/// marker as a regular file): the store this migration built is in place. A
/// fork that had no marker is rebuilt without one, so only its id is
/// checked.
fn served_is_ours(served: &Path, id: &str, marked: bool) -> bool {
    (!marked
        || std::fs::symlink_metadata(served.join(crate::PUBLICATION_MARKER))
            .is_ok_and(|m| m.is_file()))
        && store_migration_id(served).is_some_and(|got| got == id)
}

/// Legacy detection for a mirror-class store (64-hex owner). Every
/// pre-release signal is evaluated independently: any positive is
/// `Rebuild`, whatever the others' errors; if none is positive and a check
/// failed, the answer is `Error` (the store is then gated, never left
/// served).
async fn detect(plugin: &Path, owner: &str, name: &str) -> Detected {
    if !is_hex64(owner) || !is_repo_name(name) {
        return Detected::Skip;
    }
    let Some(p) = Paths::of(plugin, owner, name) else {
        return Detected::Skip;
    };
    match dir_state(&p.served) {
        Ok(true) => {}
        Ok(false) => return Detected::Skip,
        Err(e) => return Detected::Error(e),
    }
    let record = MirrorStore::new(plugin).load(owner, name);
    let marked = match std::fs::symlink_metadata(p.served.join(crate::PUBLICATION_MARKER)) {
        Ok(m) => m.is_file(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Detected::Error(format!("the marker check failed: {}", e.kind())),
    };
    if marked {
        if !matches!(&record, StoredRecord::Valid(r) if r.awaits_migration) {
            return Detected::Skip;
        }
        // Flagged but marked: finish only if a report names this store's
        // migration id; otherwise the marker proves nothing, rebuild.
        let Some(id) = store_migration_id(&p.served) else {
            return Detected::Rebuild;
        };
        return match reports(&p.recovery_dir, name) {
            Ok(found) if found.iter().any(|r| report_id(r).as_deref() == Some(&id)) => {
                Detected::Finish
            }
            Ok(_) => Detected::Rebuild,
            Err(e) => Detected::Error(e),
        };
    }
    match &record {
        StoredRecord::Valid(r) if r.awaits_migration || !r.isolated => return Detected::Rebuild,
        StoredRecord::Unreadable(_) => return Detected::Rebuild,
        StoredRecord::Valid(_) | StoredRecord::Missing => {}
    }
    let mut error = None;
    for signal in legacy_traces(&p.served).await {
        match signal {
            Ok(true) => return Detected::Rebuild,
            Ok(false) => {}
            Err(e) => error = error.or(Some(e)),
        }
    }
    match reports(&p.recovery_dir, name) {
        Ok(found) if !found.is_empty() => return Detected::Rebuild,
        Ok(_) => {}
        Err(e) => error = error.or(Some(e)),
    }
    error.map_or(Detected::Clean, Detected::Error)
}

/// The pre-release signals of a store, each evaluated on its own:
/// alternates, `refs/mirror/*`, and `hideRefs` naming them.
async fn legacy_traces(served: &Path) -> Vec<Result<bool, String>> {
    let quick = Duration::from_secs(15);
    let info = served.join("objects").join("info");
    let mut alternates = Ok(false);
    for file in ["alternates", "http-alternates"] {
        match tokio::fs::symlink_metadata(info.join(file)).await {
            Ok(_) => {
                alternates = Ok(true);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => alternates = Err(format!("the alternates check failed: {}", e.kind())),
        }
    }
    let refs = run_in(
        served,
        served,
        &[
            "for-each-ref",
            "--count=1",
            "--format=%(refname)",
            "refs/mirror",
        ],
        None,
        quick,
        None,
    )
    .await
    .map(|out| !out.is_empty());
    let config = run_in(
        served,
        served,
        &["config", "--local", "--list", "-z"],
        None,
        quick,
        None,
    )
    .await
    .map(|out| hides_mirror_refs(&out));
    vec![alternates, refs, config]
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `fsync` a directory, so the entries just created, renamed or removed in
/// it survive a machine crash.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Write `bytes` to `path` and `fsync` it.
fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Write a journal durably: a temporary file, `fsync`, rename, `fsync` the
/// directory.
fn write_journal(path: &Path, j: &Journal) -> Result<(), String> {
    let parent = path.parent().ok_or("no journal directory")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("journal directory: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(j).map_err(|e| e.to_string())?;
    write_synced(&tmp, &bytes).map_err(|e| format!("journal not written: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("journal not written: {e}"))?;
    sync_dir(parent).map_err(|e| format!("journal not synced: {e}"))
}

/// Create `path` holding `bytes`, durably, only if nothing is there: a
/// temporary file, `fsync`, `hard_link` (which, unlike rename, never
/// replaces), `fsync` the directory. `Ok(false)` when an entry already
/// exists (it is left as it is).
fn create_exclusive(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    let parent = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("directory: {e}"))?;
    let tmp = with_suffix(path, &format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    write_synced(&tmp, bytes).map_err(|e| format!("not written: {e}"))?;
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            sync_dir(parent).map_err(|e| format!("not synced: {e}"))?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(format!("not written: {e}")),
    }
}

/// Take the store's cross-process lock, polling `try_lock` (off the
/// runtime) for at most `wait`.
async fn take_lock(path: PathBuf, wait: Duration) -> std::io::Result<std::fs::File> {
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        let deadline = std::time::Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "another process held it past the deadline",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
        }
    })
    .await
    .map_err(std::io::Error::other)?
}

/// A fresh recovery stem `<name>.git.<ts>` that names nothing yet.
fn fresh_recovery(plugin: &Path, p: &Paths, name: &str) -> (u64, String) {
    let mut ts = now_secs();
    loop {
        let stem = format!("{name}.git.{ts}");
        let taken = std::fs::symlink_metadata(p.recovery_dir.join(&stem)).is_ok()
            || std::fs::symlink_metadata(p.recovery_dir.join(format!("{stem}.migration.json")))
                .is_ok();
        if !taken {
            return (ts, relative(plugin, &p.recovery_dir.join(&stem)));
        }
        ts += 1;
    }
}

/// A new journal in `state` with a fresh id and recovery stem.
fn new_journal(
    plugin: &Path,
    p: &Paths,
    name: &str,
    state: Stage,
    reason: Option<String>,
    kind: &Kind,
) -> Journal {
    let (ts, recovery) = fresh_recovery(plugin, p, name);
    Journal {
        id: uuid::Uuid::new_v4().simple().to_string(),
        ts,
        class: kind.class().into(),
        state,
        moved: false,
        staging: None,
        recovery,
        attempts: 0,
        reason,
        parent: match kind {
            Kind::Mirror => None,
            Kind::Fork(plan) => Some(plan.parent().to_string()),
        },
    }
}

/// Gate a store with a `failed` journal holding `reason` and no attempt
/// counted, created exclusively (an existing journal is never replaced, and
/// already gates). `Ungated` when nothing could be written.
fn gate(plugin: &Path, p: &Paths, owner: &str, name: &str, reason: &str, kind: &Kind) -> Outcome {
    let j = new_journal(
        plugin,
        p,
        name,
        Stage::Failed,
        Some(redact(plugin, reason)),
        kind,
    );
    let written = serde_json::to_vec_pretty(&j)
        .map_err(|e| e.to_string())
        .and_then(|bytes| create_exclusive(&p.journal, &bytes));
    match written {
        Ok(_) => {
            tracing::error!(owner = %owner, name = %name, reason = %redact(plugin, reason), "forge: store gated without migrating");
            Outcome::Failed
        }
        Err(e) => {
            tracing::error!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: gate journal not written");
            Outcome::Ungated
        }
    }
}

/// The journal's recovery (and staging) path, if each lies where it must:
/// `mirror-recovery/<owner>/<name>.git.<digits>` and
/// `mirror-work/staging/<owner>/<name>.git.<alphanumerics>`, as plain
/// relative components, with the parent directory (when it exists)
/// canonicalising to the same place under the canonical plugin directory.
fn contained(plugin: &Path, owner: &str, name: &str, j: &Journal) -> Result<PathBuf, String> {
    fn check(
        plugin: &Path,
        rel: &str,
        base: &[&str],
        owner: &str,
        leaf_ok: impl Fn(&str) -> bool,
    ) -> Result<PathBuf, String> {
        use std::path::Component;
        let parts: Vec<&str> = Path::new(rel)
            .components()
            .map(|c| match c {
                Component::Normal(s) => s.to_str().ok_or(()),
                _ => Err(()),
            })
            .collect::<Result<_, _>>()
            .map_err(|()| format!("journal path {rel:?} is not plain"))?;
        let ok = parts.len() == base.len() + 2
            && parts[..base.len()] == *base
            && parts[base.len()] == owner
            && leaf_ok(parts[base.len() + 1]);
        if !ok {
            return Err(format!(
                "journal path {rel:?} is outside {}",
                base.join("/")
            ));
        }
        let parent: PathBuf = base
            .iter()
            .fold(plugin.to_path_buf(), |d, s| d.join(s))
            .join(owner);
        if let Ok(real) = std::fs::canonicalize(&parent) {
            let root =
                std::fs::canonicalize(plugin).map_err(|e| format!("plugin directory: {e}"))?;
            let want = base.iter().fold(root, |d, s| d.join(s)).join(owner);
            if real != want {
                return Err(format!(
                    "journal path {rel:?} resolves outside {}",
                    base.join("/")
                ));
            }
        }
        Ok(plugin.join(rel))
    }
    let stem = format!("{name}.git.");
    let recovery = check(plugin, &j.recovery, &["mirror-recovery"], owner, |leaf| {
        leaf.strip_prefix(&stem).is_some_and(all_digits)
    })?;
    if let Some(s) = &j.staging {
        check(plugin, s, &["mirror-work", "staging"], owner, |leaf| {
            leaf.strip_prefix(&stem)
                .is_some_and(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_alphanumeric()))
        })?;
    }
    Ok(recovery)
}

/// Migrate (or resume, or finish) one store under its lock.
async fn migrate_one(plugin: &Path, owner: &str, name: &str) -> Outcome {
    migrate_store(plugin, owner, name, &Kind::Mirror).await
}

/// What detection says about `<owner>/<name>` for a store of `kind`.
async fn detect_for(plugin: &Path, owner: &str, name: &str, kind: &Kind) -> Detected {
    match kind {
        Kind::Mirror => detect(plugin, owner, name).await,
        Kind::Fork(plan) => fork::detect(plugin, owner, name, plan).await,
    }
}

/// Migrate (or resume, or finish) one store of `kind` under its lock.
async fn migrate_store(plugin: &Path, owner: &str, name: &str, kind: &Kind) -> Outcome {
    let Some(p) = Paths::of(plugin, owner, name) else {
        return Outcome::Skipped;
    };
    let limits = Limits::for_plugin(plugin);
    let _lock = match take_lock(p.lock.clone(), limits.lock_wait).await {
        Ok(f) => f,
        // No lock: still gate the store (decision 21; a journal only adds
        // denial), never replacing a journal that is there.
        Err(e) => {
            return gate(
                plugin,
                &p,
                owner,
                name,
                &format!("the migration lock was not taken: {e}"),
                kind,
            );
        }
    };
    // Re-read everything under the lock: another instance may have finished.
    let journal = match read_journal(&p.journal) {
        JournalRead::Present(j) if j.class != kind.class() => {
            // Another pass owns it (a mirror journal seen by the fork pass,
            // or the reverse): it gates, and is left alone here.
            tracing::warn!(owner = %owner, name = %name, class = %j.class, "forge: migration journal of another class; store stays gated");
            return Outcome::Failed;
        }
        JournalRead::Present(j) => j,
        JournalRead::Bad(e) => {
            tracing::error!(owner = %owner, name = %name, error = %e, "forge: migration journal unusable; store stays gated");
            return Outcome::Failed;
        }
        JournalRead::Absent => match detect_for(plugin, owner, name, kind).await {
            Detected::Skip | Detected::Clean => return Outcome::Skipped,
            Detected::Finish => return finished(plugin, &p, owner, name),
            Detected::Error(e) => {
                return gate(
                    plugin,
                    &p,
                    owner,
                    name,
                    &format!("{DETECTION_ERROR}: {e}"),
                    kind,
                );
            }
            Detected::Rebuild => {
                // Persist the journal before any branch below can refuse
                // the store: every `Failed` from here on relies on a
                // journal on disk to gate it.
                let j = new_journal(plugin, &p, name, Stage::Building, None, kind);
                if let Err(e) = write_journal(&p.journal, &j) {
                    tracing::error!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: migration journal not written; store not migrated");
                    return Outcome::Ungated;
                }
                j
            }
        },
    };
    let recovery = match contained(plugin, owner, name, &journal) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: migration journal refused; store stays gated");
            return Outcome::Failed;
        }
    };
    if journal.state == Stage::Failed
        && journal
            .reason
            .as_deref()
            .is_some_and(|r| r.starts_with(DETECTION_ERROR))
    {
        // A store gated because it could not be examined: examine it again.
        match detect_for(plugin, owner, name, kind).await {
            Detected::Clean => {
                return match std::fs::remove_file(&p.journal) {
                    Ok(()) => {
                        let _ = p.journal.parent().map(sync_dir);
                        tracing::info!(owner = %owner, name = %name, "forge: store examined and clean; gate removed");
                        Outcome::Skipped
                    }
                    Err(e) => {
                        tracing::error!(owner = %owner, name = %name, error = %e, "forge: gate journal not removed");
                        Outcome::Failed
                    }
                };
            }
            Detected::Error(e) => {
                tracing::warn!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: store still cannot be examined; stays gated");
                return Outcome::Failed;
            }
            Detected::Skip => {
                tracing::warn!(owner = %owner, name = %name, "forge: store not examined; its gate stays");
                return Outcome::Failed;
            }
            Detected::Finish => return finished(plugin, &p, owner, name),
            Detected::Rebuild => {}
        }
    }
    if let Kind::Fork(plan) = kind {
        if let Some(why) = plan.gate() {
            // The fork's ancestors are not all known: with no complete held
            // set to filter against, a rebuild could publish a ref reaching
            // held, and a rebuilt store already in place is not published
            // either (it was verified against ancestors that may since have
            // changed). The journal is on disk and gates.
            tracing::warn!(owner = %owner, name = %name, reason = %redact(plugin, why), "forge: fork not rebuilt; its ancestors cannot be checked; store stays gated");
            return Outcome::Failed;
        }
    }
    if served_is_ours(&p.served, &journal.id, kind.mirror_config()) {
        // The rebuilt store is in place (a crash after the second rename,
        // or after the `published` write): publish and finish, never
        // rebuild it. A journal in any state, `published` included, whose
        // id the served store does not carry is never finished.
        return publish(plugin, &p, owner, name, journal);
    }
    // Once the journal reached `moved` the old store is only ever read
    // from recovery, whatever the `moved` field says.
    let was_moved = journal.moved || matches!(journal.state, Stage::Moved | Stage::Published);
    if journal.attempts >= MAX_ATTEMPTS {
        tracing::warn!(owner = %owner, name = %name, attempts = journal.attempts, "forge: migration gave up; store stays gated");
        return Outcome::Failed;
    }
    let (served_present, recovery_present) = match (dir_state(&p.served), dir_state(&recovery)) {
        (Ok(s), Ok(r)) => (s, r),
        (Err(e), _) | (_, Err(e)) => {
            // The journal stays and gates; nothing is moved or rebuilt.
            tracing::error!(owner = %owner, name = %name, error = %e, "forge: migration paths not checked; store stays gated");
            return Outcome::Failed;
        }
    };
    let moved = match (served_present, recovery_present) {
        (true, true) => {
            // Something created the store in the gap despite the tombstone:
            // never overwrite it, never read it as the old store. Set
            // staging aside and leave the journal.
            if let Some(s) = journal.staging.as_deref().map(|s| plugin.join(s)) {
                if is_dir(&s) {
                    let _ = std::fs::rename(&s, with_suffix(&recovery, ".rebuilt"));
                }
            }
            tracing::error!(owner = %owner, name = %name, "forge: a store appeared during migration; left for the operator");
            return Outcome::Failed;
        }
        (true, false) if was_moved => {
            return fail(
                plugin,
                &p,
                owner,
                name,
                journal,
                "the old store was moved but its recovery copy is gone",
            );
        }
        (true, false) => false,
        (false, true) => true,
        (false, false) => {
            return fail(
                plugin,
                &p,
                owner,
                name,
                journal,
                "neither the served store nor its recovery copy exists",
            );
        }
    };
    rebuild(
        plugin, &p, owner, name, journal, &recovery, moved, limits, kind,
    )
    .await
}

/// `finish`, logged.
fn finished(plugin: &Path, p: &Paths, owner: &str, name: &str) -> Outcome {
    match finish(plugin, p, owner, name) {
        Ok(()) => Outcome::Migrated,
        Err(e) => {
            tracing::error!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: migration not finished");
            gated_or_ungated(plugin, owner, name)
        }
    }
}

/// `Failed` when a journal is on disk to gate the store, else `Ungated`
/// (the caller must gate it another way).
fn gated_or_ungated(plugin: &Path, owner: &str, name: &str) -> Outcome {
    if journal_exists(plugin, owner, name) {
        Outcome::Failed
    } else {
        Outcome::Ungated
    }
}

/// The rebuilt store is in `repos/`: journal `published`, then finish.
fn publish(plugin: &Path, p: &Paths, owner: &str, name: &str, mut j: Journal) -> Outcome {
    if j.state != Stage::Published {
        j.state = Stage::Published;
        if let Err(e) = write_journal(&p.journal, &j) {
            tracing::error!(owner = %owner, name = %name, error = %redact(plugin, &e), "forge: migration journal not written");
        }
    }
    finished(plugin, p, owner, name)
}

/// `p` relative to the plugin directory, for the journal.
fn relative(plugin: &Path, p: &Path) -> String {
    p.strip_prefix(plugin)
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

/// `msg` with the plugin directory replaced by `<plugin>`.
fn redact(plugin: &Path, msg: &str) -> String {
    match plugin.to_str() {
        Some(s) if s.len() > 1 => msg.replace(s, "<plugin>"),
        _ => msg.to_string(),
    }
}

/// `base` with `suffix` appended to its last component.
fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Record a failed attempt in the journal (the attempt was counted when it
/// started); the store stays gated.
fn fail(plugin: &Path, p: &Paths, owner: &str, name: &str, mut j: Journal, why: &str) -> Outcome {
    let why = redact(plugin, why);
    j.state = Stage::Failed;
    j.reason = Some(why.clone());
    if let Err(e) = write_journal(&p.journal, &j) {
        tracing::error!(owner = %owner, name = %name, error = %e, "forge: migration journal not written");
    }
    tracing::error!(owner = %owner, name = %name, attempts = j.attempts, error = %why, "forge: migration failed; store stays gated");
    gated_or_ungated(plugin, owner, name)
}

/// Remove every staging store of `<name>` (`<name>.git.<alphanumerics>`;
/// safe under the lock: the engine builds staging under the same lock).
async fn clear_staging(staging_dir: &Path, name: &str) {
    let Ok(mut entries) = tokio::fs::read_dir(staging_dir).await else {
        return;
    };
    let prefix = format!("{name}.git.");
    while let Ok(Some(e)) = entries.next_entry().await {
        let f = e.file_name().to_string_lossy().into_owned();
        let ours = f
            .strip_prefix(&prefix)
            .is_some_and(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_alphanumeric()));
        if ours {
            if let Err(err) = tokio::fs::remove_dir_all(e.path()).await {
                tracing::warn!(error = %err, "forge: stale staging store not removed");
            }
        }
    }
}

tokio::task_local! {
    /// The process groups (leader pids) a migration build has spawned and
    /// not yet seen finish, so a budget timeout can kill all of them.
    static GROUPS: std::sync::Arc<std::sync::Mutex<Vec<u32>>>;
}

/// Note a spawned process group, inside a build.
fn note_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = GROUPS.try_with(|g| {
            g.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(pid);
        });
    }
}

/// Forget a process group that finished normally, inside a build.
fn forget_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = GROUPS.try_with(|g| {
            g.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|p| *p != pid);
        });
    }
}

/// Rebuild one store from its old store (`source`: in `repos/`, or already
/// moved to `recovery`), verify, report, swap and finish.
#[allow(clippy::too_many_arguments)]
async fn rebuild(
    plugin: &Path,
    p: &Paths,
    owner: &str,
    name: &str,
    mut j: Journal,
    recovery: &Path,
    moved: bool,
    limits: Limits,
    kind: &Kind,
) -> Outcome {
    let started = std::time::Instant::now();
    let source = if moved {
        recovery.to_path_buf()
    } else {
        p.served.clone()
    };
    clear_staging(&p.staging_dir, name).await;
    let staging = p
        .staging_dir
        .join(format!("{name}.git.{}", uuid::Uuid::new_v4().simple()));
    // The attempt counts now, before anything can crash.
    j.attempts = j.attempts.saturating_add(1);
    j.state = Stage::Building;
    j.moved = moved;
    j.reason = None;
    j.staging = Some(relative(plugin, &staging));
    if let Err(e) = write_journal(&p.journal, &j) {
        tracing::error!(owner = %owner, name = %name, error = %e, "forge: migration journal not written; store not migrated");
        // A journal may already gate the store; if none does, the caller
        // must gate it another way.
        return gated_or_ungated(plugin, owner, name);
    }
    #[cfg(test)]
    if test_hooks::get(plugin).abort_in_build {
        std::process::abort();
    }
    let record_bytes = match MirrorStore::new(plugin).load(owner, name) {
        StoredRecord::Unreadable(_) => MirrorStore::new(plugin)
            .file(owner, name)
            .map(|f| read_regular(&f).map_err(|e| e.kind().to_string())),
        _ => None,
    };
    let groups = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let attempt = GROUPS.scope(
        std::sync::Arc::clone(&groups),
        tokio::time::timeout(
            limits.store_budget,
            build(
                plugin,
                &source,
                &staging,
                limits.size_cap,
                limits.size_poll,
                kind,
            ),
        ),
    );
    let built = match attempt.await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            remove_dir(&staging).await;
            return fail(plugin, p, owner, name, j, &e);
        }
        Err(_) => {
            let left: Vec<u32> = std::mem::take(
                &mut *groups
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            for pid in left {
                kill_group(Some(pid)).await;
            }
            remove_dir(&staging).await;
            return fail(
                plugin,
                p,
                owner,
                name,
                j,
                "the migration ran past its time budget",
            );
        }
    };
    // The marker: always for a mirror-class store and a followed fork; for a
    // fork, only if the old fork had one.
    let marker = kind.mirror_config()
        || std::fs::symlink_metadata(source.join(crate::PUBLICATION_MARKER))
            .is_ok_and(|m| m.is_file());
    if let Err(e) = seal(&staging, &j.id, marker) {
        remove_dir(&staging).await;
        return fail(plugin, p, owner, name, j, &e);
    }
    j.state = Stage::Verified;
    if let Err(e) = write_journal(&p.journal, &j) {
        remove_dir(&staging).await;
        return fail(plugin, p, owner, name, j, &e);
    }
    if let Err(e) = write_report(
        plugin,
        recovery,
        owner,
        name,
        &j.id,
        &built,
        record_bytes,
        kind,
    ) {
        remove_dir(&staging).await;
        return fail(plugin, p, owner, name, j, &e);
    }
    if !moved {
        let renamed = std::fs::create_dir_all(&p.recovery_dir)
            .and_then(|()| std::fs::rename(&p.served, recovery))
            .and_then(|()| sync_dir(&p.recovery_dir))
            .and_then(|()| p.served.parent().map_or(Ok(()), sync_dir));
        if let Err(e) = renamed {
            if is_dir(&p.served) {
                remove_dir(&staging).await;
                return fail(
                    plugin,
                    p,
                    owner,
                    name,
                    j,
                    &format!("the old store was not moved: {e}"),
                );
            }
            tracing::error!(owner = %owner, name = %name, error = %e, "forge: old store moved but not synced");
        }
    }
    // Written before the second rename on every path (normal and resumed):
    // a crash after it is resolved by the store's migration id.
    j.state = Stage::Moved;
    j.moved = true;
    if let Err(e) = write_journal(&p.journal, &j) {
        tracing::error!(owner = %owner, name = %name, error = %e, "forge: migration journal not written");
    }
    let placed = p
        .served
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::rename(&staging, &p.served))
        .and_then(|()| p.served.parent().map_or(Ok(()), sync_dir));
    if let Err(e) = placed {
        if !served_is_ours(&p.served, &j.id, kind.mirror_config()) {
            return fail(
                plugin,
                p,
                owner,
                name,
                j,
                &format!("the rebuilt store was not placed: {e}"),
            );
        }
    }
    let outcome = publish(plugin, p, owner, name, j);
    if outcome == Outcome::Migrated {
        tracing::info!(
            owner = %owner,
            name = %name,
            ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            copied = built.copied.len(),
            dropped = built.dropped.len(),
            held = built.held.len(),
            "forge: migrated"
        );
    }
    outcome
}

/// Write the migration id, then (when `marked`) the marker, into staging,
/// durably.
fn seal(staging: &Path, id: &str, marked: bool) -> Result<(), String> {
    let marker = crate::PUBLICATION_MARKER;
    write_synced(
        &staging.join(MIGRATION_ID_FILE),
        format!("{id}\n").as_bytes(),
    )
    .map_err(|e| format!("could not write the migration id: {e}"))?;
    if !marked {
        return sync_dir(staging).map_err(|e| format!("could not sync staging: {e}"));
    }
    let tmp = staging.join(format!("{marker}.tmp"));
    write_synced(&tmp, format!("{marker}\n").as_bytes())
        .and_then(|()| std::fs::rename(&tmp, staging.join(marker)))
        .and_then(|()| sync_dir(staging))
        .map_err(|e| format!("could not write the publication marker: {e}"))
}

async fn remove_dir(dir: &Path) {
    if let Err(e) = tokio::fs::remove_dir_all(dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "forge: staging store not removed");
        }
    }
}

/// Steps 10 to 12: clear the record's awaits-migration flag (editing the
/// JSON, every other field unchanged), wipe the candidate, delete the
/// journal. An unreadable record is left as it is.
fn finish(plugin: &Path, p: &Paths, owner: &str, name: &str) -> Result<(), String> {
    let store = MirrorStore::new(plugin);
    if let StoredRecord::Valid(r) = store.load(owner, name) {
        if r.awaits_migration {
            let file = store.file(owner, name).ok_or("unsafe record key")?;
            let bytes = read_regular(&file).map_err(|e| format!("record not read: {e}"))?;
            let mut v: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| format!("record not parsed: {e}"))?;
            if let Some(o) = v.as_object_mut() {
                o.remove(AWAITS_MIGRATION_KEY);
            }
            let tmp = file.with_extension("json.tmp");
            let out = serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?;
            write_synced(&tmp, &out).map_err(|e| format!("record not written: {e}"))?;
            std::fs::rename(&tmp, &file).map_err(|e| format!("record not written: {e}"))?;
            if let Some(dir) = file.parent() {
                sync_dir(dir).map_err(|e| format!("record not synced: {e}"))?;
            }
        }
    }
    if let Err(e) = std::fs::remove_dir_all(&p.candidate) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(owner = %owner, name = %name, error = %e, "forge: candidate not removed after migration");
        }
    }
    match std::fs::remove_file(&p.journal) {
        Ok(()) => {
            let _ = p.journal.parent().map(sync_dir);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("journal not removed: {e}")),
    }
}

/// A ref left out of the rebuilt store, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DroppedRef {
    /// The name, lossily decoded when it is not UTF-8 (such a ref is never
    /// copied).
    #[serde(rename = "ref")]
    name: String,
    sha: String,
    reason: &'static str,
}

/// What [`build`] made.
#[derive(Debug, Default)]
struct Built {
    /// Refs copied into staging, by name.
    copied: BTreeMap<String, String>,
    /// Refs left out.
    dropped: Vec<DroppedRef>,
    /// The held set, sorted.
    held: Vec<String>,
    /// Every object of the source absent from staging, sorted.
    dropped_objects: Vec<String>,
    /// The `HEAD` set in staging.
    head: Option<String>,
}

/// Whether `r` is a ref name safe on a push command line. The names come from
/// `for-each-ref`, so git already accepted them; this refuses anything that
/// could be read as an option or a refspec modifier all the same.
fn safe_ref(r: &str) -> bool {
    r.starts_with("refs/")
        && r.len() <= 1024
        && !r.ends_with('/')
        && !r.ends_with('.')
        && !r.ends_with(".lock")
        && !r.contains("..")
        && !r.contains("//")
        && !r.contains("/.")
        && !r.contains("@{")
        && r.bytes().all(|b| {
            b > b' ' && b != 0x7f && !matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn is_sha40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `r` is a root: a branch or a tag.
fn is_root(r: &str) -> bool {
    r.starts_with("refs/heads/") || r.starts_with("refs/tags/")
}

/// One `for-each-ref` line, `<sha> <name>`: the name `None` when it is not
/// UTF-8.
fn parse_ref_line(line: &[u8]) -> Option<(String, Option<String>, String)> {
    let at = line.iter().position(|b| *b == b' ')?;
    let sha = String::from_utf8_lossy(&line[..at]).into_owned();
    let raw = &line[at + 1..];
    let name = std::str::from_utf8(raw).ok().map(str::to_string);
    Some((sha, name, String::from_utf8_lossy(raw).into_owned()))
}

/// `^<sha>` lines for `rev-list --stdin`: the roots, excluded.
fn exclude_input(roots: &[String]) -> Vec<u8> {
    let mut input = Vec::with_capacity(roots.len() * 42);
    for sha in roots {
        input.push(b'^');
        input.extend_from_slice(sha.as_bytes());
        input.push(b'\n');
    }
    input
}

/// Steps 3 to 7 and the dropped set: initialise staging (the fixed served
/// config for a mirror-class store or a followed fork, an allow-list of the
/// old config for a fork), choose the refs, push them by SHA from `source`
/// under the size cap, set `HEAD`, verify, and list what was left behind.
///
/// Mirror class: the roots R are the branches and tags that will be copied
/// (safe names, valid SHAs). The held set H is every object any ref of
/// `source` reaches that R does not ([`held_set`]). A ref outside R is
/// copied only if it reaches nothing in H, so the copy holds R's closure and
/// nothing else. A followed fork first drops any root that reaches the
/// inherited held set (the union of its mirror-class ancestors' `.held`
/// files). A fork copies every ref but `refs/mirror/*` and
/// `refs/replace/*`, each one only if it reaches nothing in the inherited
/// held set beyond the ancestors' roots it holds; every copied ref is then a
/// root of the rebuild.
async fn build(
    plugin: &Path,
    source: &Path,
    staging: &Path,
    size_cap: u64,
    size_poll: SizePoll,
    kind: &Kind,
) -> Result<Built, String> {
    init_bare(staging).await?;
    if kind.mirror_config() {
        write_served_config(staging).await?;
        keep_parent(source, staging).await?;
    }
    #[cfg(test)]
    if let Some(token) = test_hooks::get(plugin).slow_child {
        let alias = format!("alias.b1slow=!sleep {token} & sleep {token}");
        run_in(
            source,
            source,
            &["-c", &alias, "b1slow"],
            None,
            STORE_BUDGET,
            None,
        )
        .await?;
    }
    #[cfg(not(test))]
    let _ = plugin;
    let listing = run_in(
        source,
        source,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
        None,
        STORE_BUDGET,
        None,
    )
    .await?;
    let refs: Vec<(String, Option<String>, String)> = listing
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(parse_ref_line)
        .collect();
    let mut built = Built::default();
    // What verification checks staging against: the objects that must be
    // absent, and the roots whose closure staging must lie within.
    let (check_held, roots) = match kind {
        Kind::Mirror => select_mirror(source, refs, &mut built, None).await?,
        Kind::Fork(plan) => {
            let inherited = fork::inherited_held(plan)?;
            let ancestor_roots = fork::present_roots(source, plan).await?;
            if plan.followed() {
                let (own, roots) = select_mirror(
                    source,
                    refs,
                    &mut built,
                    Some((&inherited, &ancestor_roots)),
                )
                .await?;
                (own.union(&inherited).cloned().collect(), roots)
            } else {
                fork::select(source, refs, &mut built, &inherited, &ancestor_roots).await?;
                let mut roots: Vec<String> = built.copied.values().cloned().collect();
                roots.sort();
                roots.dedup();
                (inherited, roots)
            }
        }
    };
    push_refs(source, staging, &built.copied, size_cap, size_poll).await?;
    if !kind.mirror_config() {
        // After the push: the fork's `transfer.hideRefs = refs/forge/` would
        // make receive-pack refuse its pull-request heads.
        fork::write_fork_config(source, staging).await?;
    }
    built.head = choose_head(source, &built.copied).await?;
    if let Some(h) = &built.head {
        run_in(
            staging,
            staging,
            &["symbolic-ref", "HEAD", h],
            None,
            Duration::from_secs(15),
            None,
        )
        .await?;
    }
    verify_with_roots(source, staging, &built.copied, &check_held, &roots).await?;
    built.dropped_objects = dropped_objects(source, staging).await?;
    let mut held: Vec<String> = match kind {
        Kind::Mirror => check_held.into_iter().collect(),
        // A fork's report lists the held objects it actually left behind.
        Kind::Fork(_) => built
            .dropped_objects
            .iter()
            .filter(|id| check_held.contains(*id))
            .cloned()
            .collect(),
    };
    held.sort();
    built.held = held;
    Ok(built)
}

/// Mirror-class ref selection into `built`: roots (branches and tags) are
/// copied, `refs/mirror/*`, pull-request heads and replacements never, and
/// any other ref only if it reaches nothing held. With `inherited` (a
/// followed fork: the inherited held set and the ancestors' roots present in
/// `source`), a root that reaches an inherited held object is dropped first.
/// Returns the held set and the copied roots.
async fn select_mirror(
    source: &Path,
    refs: Vec<(String, Option<String>, String)>,
    built: &mut Built,
    inherited: Option<(&HashSet<String>, &[String])>,
) -> Result<(HashSet<String>, Vec<String>), String> {
    let mut roots = Vec::new();
    let mut others = Vec::new();
    for (sha, name, lossy) in refs {
        let reason = match name.as_deref() {
            None => Some("unsafe-name"),
            Some(r) if !safe_ref(r) || !is_sha40(&sha) => Some("unsafe-name"),
            Some(r) if r.starts_with("refs/mirror/") => Some("mirror"),
            Some(r) if r.starts_with("refs/forge/heads/") => Some("pull-request-head"),
            // A replacement names its target, which may be held, and means
            // nothing without it: never copied.
            Some(r) if r.starts_with("refs/replace/") => Some("outside-roots"),
            Some(r) if is_root(r) => {
                if let Some((held, ancestor_roots)) = inherited {
                    if reaches_held(source, &sha, ancestor_roots, held).await? {
                        built.dropped.push(DroppedRef {
                            name: r.to_string(),
                            sha,
                            reason: "reaches-held",
                        });
                        continue;
                    }
                }
                roots.push(sha.clone());
                built.copied.insert(r.to_string(), sha);
                continue;
            }
            Some(r) => {
                others.push((r.to_string(), sha));
                continue;
            }
        };
        if let Some(reason) = reason {
            built.dropped.push(DroppedRef {
                name: lossy,
                sha,
                reason,
            });
        }
    }
    roots.sort();
    roots.dedup();
    let held = held_set(source, &roots).await?;
    for (r, sha) in others {
        if reaches_held(source, &sha, &roots, &held).await? {
            built.dropped.push(DroppedRef {
                name: r,
                sha,
                reason: "outside-roots",
            });
        } else {
            built.copied.insert(r, sha);
        }
    }
    Ok((held, roots))
}

/// Carry the old store's `forge.parent` (validated) into staging, so a
/// followed fork keeps its lineage through a mirror-class rebuild.
async fn keep_parent(source: &Path, staging: &Path) -> Result<(), String> {
    use crate::forks::StoredLineage;
    let lineage = crate::forks::read_lineage_checked(source)
        .map_err(|e| format!("the old config could not be read: {}", e.kind()))?;
    let value = match lineage {
        StoredLineage::None => None,
        StoredLineage::Parent(p) => Some(p.full()),
        // Kept as read: dropping it would make the store a root, and its
        // descendants' checks would stop there.
        StoredLineage::Unknown(raw) => Some(raw),
    };
    if let Some(value) = value {
        run_in(
            staging,
            staging,
            &["config", "--local", "forge.parent", &value],
            None,
            Duration::from_secs(15),
            None,
        )
        .await?;
    }
    Ok(())
}

/// The held set of a store: every object any ref reaches
/// (`rev-list --objects --all`) outside the full closure of the roots. The
/// closure is subtracted in a second pass because `--not <roots>` only
/// marks the boundary commits' trees uninteresting: a blob the held history
/// shares with deeper root history (C16) would otherwise count as held.
async fn held_set(source: &Path, roots: &[String]) -> Result<HashSet<String>, String> {
    let mut held = HashSet::new();
    let cap = |set: &HashSet<String>| {
        if set.len() >= MAX_HELD_IDS {
            Err(format!("the held set passed {MAX_HELD_IDS} objects"))
        } else {
            Ok(())
        }
    };
    for_each_line(
        source,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            "--all",
            "--stdin",
        ],
        Some(exclude_input(roots)),
        STORE_BUDGET,
        |id| {
            cap(&held)?;
            held.insert(id.to_string());
            Ok(Flow::Go)
        },
    )
    .await?;
    if held.is_empty() || roots.is_empty() {
        return Ok(held);
    }
    let mut input = Vec::with_capacity(roots.len() * 41);
    for sha in roots {
        input.extend_from_slice(sha.as_bytes());
        input.push(b'\n');
    }
    for_each_line(
        source,
        &["rev-list", "--objects", "--no-object-names", "--stdin"],
        Some(input),
        STORE_BUDGET,
        |id| {
            held.remove(id);
            Ok(Flow::Go)
        },
    )
    .await?;
    Ok(held)
}

/// Whether anything `sha` reaches beyond the roots is held.
async fn reaches_held(
    source: &Path,
    sha: &str,
    roots: &[String],
    held: &HashSet<String>,
) -> Result<bool, String> {
    let mut hit = false;
    for_each_line(
        source,
        &["rev-list", "--objects", "--no-object-names", sha, "--stdin"],
        Some(exclude_input(roots)),
        STORE_BUDGET,
        |id| {
            if held.contains(id) {
                hit = true;
                return Ok(Flow::Stop);
            }
            Ok(Flow::Go)
        },
    )
    .await?;
    Ok(hit)
}

/// Push exactly `refs` (name to SHA) from `source` into the empty `staging`,
/// by SHA, in batches, with the fixed receive-pack and no hooks, killing
/// the push once staging grows past `size_cap`.
async fn push_refs(
    source: &Path,
    staging: &Path,
    refs: &BTreeMap<String, String>,
    size_cap: u64,
    size_poll: SizePoll,
) -> Result<(), String> {
    let target = staging.to_str().ok_or("non-UTF-8 staging path")?;
    let specs: Vec<String> = refs.iter().map(|(r, sha)| format!("{sha}:{r}")).collect();
    let receive = format!("--receive-pack={RECEIVE_PACK}");
    let cap: Option<(u64, DirMeasure)> = Some((size_cap, crate::sizecap::dir_size));
    for batch in specs.chunks(PUSH_BATCH) {
        let mut args: Vec<&str> = vec![
            "-c",
            "push.gpgSign=false",
            "-c",
            "push.followTags=false",
            "-c",
            "push.recurseSubmodules=no",
            "push",
            "--porcelain",
            "--no-verify",
            &receive,
            "--",
            target,
        ];
        args.extend(batch.iter().map(String::as_str));
        let out = run_output_env(
            source,
            staging,
            &args,
            Some("file"),
            STORE_BUDGET,
            cap,
            size_poll,
            &MIGRATION_ENV,
        )
        .await?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let lines: Vec<&str> = err
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with("hint:"))
                .take(4)
                .collect();
            return Err(format!("push into staging failed: {}", lines.join(" | ")));
        }
        // The push can finish between two measurements: measure the
        // completed staging store once more.
        let d = staging.to_path_buf();
        let size = tokio::task::spawn_blocking(move || crate::sizecap::dir_size(&d))
            .await
            .map_err(|e| format!("staging not measured: {e}"))?;
        if size > size_cap {
            return Err(GREW_PAST_CAP.to_string());
        }
    }
    Ok(())
}

/// `HEAD` for the rebuilt store: the source's symbolic `HEAD` if it names a
/// copied branch, else `refs/heads/main` if copied, else the first copied
/// branch, else none.
async fn choose_head(
    source: &Path,
    copied: &BTreeMap<String, String>,
) -> Result<Option<String>, String> {
    let out = run_output(
        source,
        source,
        &["symbolic-ref", "-q", "HEAD"],
        None,
        Duration::from_secs(15),
        None,
    )
    .await?;
    let named = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && named.starts_with("refs/heads/") && copied.contains_key(&named) {
        return Ok(Some(named));
    }
    if copied.contains_key("refs/heads/main") {
        return Ok(Some("refs/heads/main".into()));
    }
    Ok(copied
        .keys()
        .find(|r| r.starts_with("refs/heads/"))
        .cloned())
}

/// Step 7, failing closed on any miss: every staging ref is exactly the one
/// chosen; no object of `held` is present (checked whatever `held` holds);
/// every object in staging lies in the closure, in `source`, of the chosen
/// branches and tags; nothing is borrowed through alternates; and no object
/// file is shared with the source.
#[cfg(test)]
pub(crate) async fn verify(
    source: &Path,
    staging: &Path,
    want: &BTreeMap<String, String>,
    held: &HashSet<String>,
) -> Result<(), String> {
    let mut roots: Vec<String> = want
        .iter()
        .filter(|(r, _)| is_root(r))
        .map(|(_, sha)| sha.clone())
        .collect();
    roots.sort();
    roots.dedup();
    verify_with_roots(source, staging, want, held, &roots).await
}

/// [`verify`] with the roots given: every object in staging must lie in the
/// closure of `roots` in `source` (a fork's roots are every ref it copies).
async fn verify_with_roots(
    source: &Path,
    staging: &Path,
    want: &BTreeMap<String, String>,
    held: &HashSet<String>,
    roots: &[String],
) -> Result<(), String> {
    let listing = run_in(
        staging,
        staging,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
        None,
        STORE_BUDGET,
        None,
    )
    .await?;
    let text = String::from_utf8(listing).map_err(|_| "a rebuilt store ref is not UTF-8")?;
    let got: BTreeMap<String, String> = text
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(r, sha)| (r.to_string(), sha.to_string()))
        .collect();
    if &got != want {
        return Err("the rebuilt store's refs differ from the refs chosen".into());
    }
    let present = present_count(staging, held).await?;
    if present > 0 {
        return Err(format!("{present} held objects reached the rebuilt store"));
    }
    let outside = outside_roots(source, staging, roots).await?;
    if outside > 0 {
        return Err(format!(
            "{outside} objects in the rebuilt store lie outside the roots"
        ));
    }
    let info = staging.join("objects").join("info");
    for file in ["alternates", "http-alternates"] {
        match std::fs::symlink_metadata(info.join(file)) {
            Ok(_) => return Err("the rebuilt store borrows objects through alternates".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("the alternates check failed: {}", e.kind())),
        }
    }
    let (s, t) = (source.to_path_buf(), staging.to_path_buf());
    let shared = tokio::task::spawn_blocking(move || shares_inodes(&s, &t))
        .await
        .map_err(|e| e.to_string())??;
    if shared {
        return Err("the rebuilt store shares object files with the old store".into());
    }
    Ok(())
}

/// How many objects in `staging` the closure of `roots` in `source` does not
/// reach.
async fn outside_roots(source: &Path, staging: &Path, roots: &[String]) -> Result<usize, String> {
    let mut staged = HashSet::new();
    for_each_line(
        staging,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
        None,
        STORE_BUDGET,
        |id| {
            if staged.len() >= MAX_HELD_IDS {
                return Err(format!("the rebuilt store passed {MAX_HELD_IDS} objects"));
            }
            staged.insert(id.to_string());
            Ok(Flow::Go)
        },
    )
    .await?;
    if staged.is_empty() || roots.is_empty() {
        return Ok(staged.len());
    }
    let mut input = Vec::with_capacity(roots.len() * 41);
    for sha in roots {
        input.extend_from_slice(sha.as_bytes());
        input.push(b'\n');
    }
    for_each_line(
        source,
        &["rev-list", "--objects", "--no-object-names", "--stdin"],
        Some(input),
        STORE_BUDGET,
        |id| {
            staged.remove(id);
            Ok(if staged.is_empty() {
                Flow::Stop
            } else {
                Flow::Go
            })
        },
    )
    .await?;
    Ok(staged.len())
}
/// How many of `ids` the store at `git_dir` holds (`cat-file --batch-check`).
async fn present_count(git_dir: &Path, ids: &HashSet<String>) -> Result<usize, String> {
    let mut input = Vec::with_capacity(ids.len() * 41);
    for id in ids {
        input.extend_from_slice(id.as_bytes());
        input.push(b'\n');
    }
    let out = run_with_input(
        git_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        input,
        STORE_BUDGET,
    )
    .await?;
    if !out.status.success() {
        return Err("git cat-file --batch-check failed".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.ends_with(" missing"))
        .count())
}

/// Whether any regular file under `staging/objects` is the same inode as a
/// file under `source/objects` (a hardlink, as `clone --local` makes).
#[cfg(unix)]
fn shares_inodes(source: &Path, staging: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    fn walk(dir: &Path, out: &mut Vec<std::fs::Metadata>) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("object directory not read: {}", e.kind())),
        };
        for e in entries {
            let e = e.map_err(|e| e.to_string())?;
            let m = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
            if m.is_dir() {
                walk(&e.path(), out)?;
            } else if m.is_file() {
                out.push(m);
            }
        }
        Ok(())
    }
    let mut staged = Vec::new();
    walk(&staging.join("objects"), &mut staged)?;
    let linked: HashSet<(u64, u64)> = staged
        .iter()
        .filter(|m| m.nlink() > 1)
        .map(|m| (m.dev(), m.ino()))
        .collect();
    if linked.is_empty() {
        return Ok(false);
    }
    let mut old = Vec::new();
    walk(&source.join("objects"), &mut old)?;
    Ok(old.iter().any(|m| linked.contains(&(m.dev(), m.ino()))))
}

#[cfg(not(unix))]
fn shares_inodes(_source: &Path, _staging: &Path) -> Result<bool, String> {
    Ok(false)
}

/// Every object id in `source` that `staging` does not hold, sorted.
async fn dropped_objects(source: &Path, staging: &Path) -> Result<Vec<String>, String> {
    let all = [
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname)",
    ];
    let mut kept = HashSet::new();
    for_each_line(staging, &all, None, STORE_BUDGET, |id| {
        kept.insert(id.to_string());
        Ok(Flow::Go)
    })
    .await?;
    let mut dropped = Vec::new();
    for_each_line(source, &all, None, STORE_BUDGET, |id| {
        if !kept.contains(id) {
            dropped.push(id.to_string());
        }
        Ok(Flow::Go)
    })
    .await?;
    dropped.sort();
    Ok(dropped)
}

/// Step 8: `<recovery>.held`, `<recovery>.dropped` and, last,
/// `<recovery>.migration.json` (naming migration `id`) beside the recovery
/// path, each `fsync`ed, then the directory. A report already there is
/// never replaced: if it names this migration it stands (a resumed build
/// of the same old store), and if it names another the migration fails
/// closed.
#[allow(clippy::too_many_arguments)]
fn write_report(
    plugin: &Path,
    recovery: &Path,
    owner: &str,
    name: &str,
    id: &str,
    built: &Built,
    record_bytes: Option<Result<Vec<u8>, String>>,
    kind: &Kind,
) -> Result<(), String> {
    use base64::Engine as _;
    let dir = recovery.parent().ok_or("no recovery directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("recovery directory: {e}"))?;
    let path = with_suffix(recovery, ".migration.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            return if report_id(&path).as_deref() == Some(id) {
                Ok(())
            } else {
                Err("a report for this recovery path names another migration".into())
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("the report check failed: {}", e.kind())),
    }
    let stem = recovery
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or("no recovery name")?;
    let lines = |ids: &[String]| {
        let mut s = String::with_capacity(ids.len() * 41);
        for id in ids {
            s.push_str(id);
            s.push('\n');
        }
        s
    };
    write_synced(
        &with_suffix(recovery, ".held"),
        lines(&built.held).as_bytes(),
    )
    .map_err(|e| format!("held list not written: {e}"))?;
    write_synced(
        &with_suffix(recovery, ".dropped"),
        lines(&built.dropped_objects).as_bytes(),
    )
    .map_err(|e| format!("dropped list not written: {e}"))?;
    let record = match record_bytes {
        None => serde_json::Value::Null,
        Some(Ok(b)) => serde_json::json!({
            "unreadable": true,
            "bytesBase64": base64::engine::general_purpose::STANDARD.encode(b),
        }),
        Some(Err(why)) => serde_json::json!({ "unreadable": true, "bytesNotRead": why }),
    };
    let copied: Vec<serde_json::Value> = built
        .copied
        .iter()
        .map(|(r, sha)| serde_json::json!({ "ref": r, "sha": sha }))
        .collect();
    let mut report = serde_json::json!({
        "id": id,
        "owner": owner,
        "name": name,
        "class": kind.class(),
        "recovery": relative(plugin, recovery),
        "head": built.head,
        "copied": copied,
        "dropped": built.dropped,
        "held": { "file": format!("{stem}.held"), "count": built.held.len() },
        "droppedObjects": { "file": format!("{stem}.dropped"), "count": built.dropped_objects.len() },
        "record": record,
    });
    if let (Kind::Fork(plan), Some(o)) = (kind, report.as_object_mut()) {
        o.insert("parent".into(), plan.parent().into());
        o.insert("followed".into(), plan.followed().into());
        o.insert("ancestors".into(), plan.report_ids().into());
    }
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    match create_exclusive(&path, &bytes) {
        Ok(true) => Ok(()),
        Ok(false) => Err("a report for this recovery path appeared meanwhile".into()),
        Err(e) => Err(format!("report {e}")),
    }
}
/// Write [`crate::PUBLICATION_MARKER`] into a store: a temporary file, then
/// a rename, so a reader never sees a partial marker.
#[cfg(feature = "mirror")]
pub(crate) async fn write_marker(dir: &Path) -> Result<(), String> {
    let marker = crate::PUBLICATION_MARKER;
    let tmp = dir.join(format!("{marker}.tmp"));
    tokio::fs::write(&tmp, format!("{marker}\n"))
        .await
        .map_err(|e| format!("could not write the publication marker: {e}"))?;
    tokio::fs::rename(&tmp, dir.join(marker))
        .await
        .map_err(|e| format!("could not write the publication marker: {e}"))
}

/// [`git_command`] for the migration's object walks and checks, with
/// [`MIGRATION_ENV`]: `rev-list` and `cat-file` otherwise walk an owner's
/// `refs/replace/*` graph while a push sends the original objects, and both
/// follow a legacy `info/grafts`, so the closures the filter and the
/// verification compute would not be the store's history.
fn migration_command(git_dir: &Path, args: &[&str]) -> tokio::process::Command {
    let mut cmd = git_command(git_dir, git_dir, args);
    for (k, v) in MIGRATION_ENV {
        cmd.env(k, v);
    }
    cmd
}

/// The environment of the migration's walks, checks and push: replacements
/// off, and legacy `info/grafts` neutralised (an empty graft file), so the
/// closures computed and the objects sent are the store's real history.
/// Advice is off, so git's graft-deprecation hints do not crowd the real
/// error out of a failure reason.
const MIGRATION_ENV: [(&str, &str); 3] = [
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_GRAFT_FILE", "/dev/null"),
    ("GIT_ADVICE", "0"),
];

/// Whether [`for_each_line`] reads on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Go,
    /// Enough read: stop git and return `Ok`.
    Stop,
}

/// Run git on the store at `git_dir`, with `input` (if any) on its stdin,
/// and hand every stdout line to `each`, streaming (nothing is buffered
/// whole). `Flow::Stop` stops git early with `Ok`; an error from `each`, a
/// timeout or a failing exit stops git and is returned.
async fn for_each_line(
    git_dir: &Path,
    args: &[&str],
    input: Option<Vec<u8>>,
    timeout: Duration,
    each: impl FnMut(&str) -> Result<Flow, String>,
) -> Result<(), String> {
    let input = input.map_or(Input::None, Input::Bytes);
    for_each_line_input(git_dir, args, input, timeout, each).await
}

/// What a streamed git run reads on stdin.
enum Input {
    None,
    Bytes(Vec<u8>),
    /// Files, each a regular file (not a symlink), streamed in order and
    /// never read whole.
    Files(Vec<PathBuf>),
}

/// Stream the regular files `files` into `out`, in order.
async fn copy_files(
    files: Vec<PathBuf>,
    out: &mut tokio::process::ChildStdin,
) -> std::io::Result<()> {
    for f in files {
        let m = tokio::fs::symlink_metadata(&f).await?;
        if !m.file_type().is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        let mut file = tokio::fs::File::open(&f).await?;
        tokio::io::copy(&mut file, out).await?;
    }
    Ok(())
}

/// [`for_each_line`] with any [`Input`].
async fn for_each_line_input(
    git_dir: &Path,
    args: &[&str],
    input: Input,
    timeout: Duration,
    mut each: impl FnMut(&str) -> Result<Flow, String>,
) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut cmd = migration_command(git_dir, args);
    cmd.stderr(std::process::Stdio::null());
    if !matches!(input, Input::None) {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("git could not start: {e}"))?;
    let pid = child.id();
    note_group(pid);
    let what = args.first().copied().unwrap_or("git");
    let writer = match (input, child.stdin.take()) {
        (Input::Bytes(bytes), Some(mut stdin)) => Some(tokio::spawn(async move {
            let wrote = stdin.write_all(&bytes).await;
            drop(stdin);
            wrote
        })),
        (Input::Files(files), Some(mut stdin)) => Some(tokio::spawn(async move {
            let wrote = copy_files(files, &mut stdin).await;
            drop(stdin);
            wrote
        })),
        _ => None,
    };
    let stdout = child.stdout.take().ok_or("git has no stdout")?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let work = async {
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| format!("git {what} output unreadable: {e}"))?
        {
            if each(&line)? == Flow::Stop {
                return Ok(Flow::Stop);
            }
        }
        match child.wait().await {
            Ok(st) if st.success() => Ok(Flow::Go),
            _ => Err(format!("git {what} failed")),
        }
    };
    let outcome = tokio::time::timeout(timeout, work).await;
    let wrote = match writer {
        Some(w) if !matches!(outcome, Ok(Ok(Flow::Go))) => {
            w.abort();
            None
        }
        Some(w) => Some(w.await),
        None => None,
    };
    match outcome {
        Ok(Ok(Flow::Go)) => {
            forget_group(pid);
            match wrote {
                None | Some(Ok(Ok(()))) => Ok(()),
                Some(_) => Err(format!("git {what}'s input was not written")),
            }
        }
        Ok(Ok(Flow::Stop)) => {
            kill_group(pid).await;
            forget_group(pid);
            Ok(())
        }
        Ok(Err(e)) => {
            kill_group(pid).await;
            forget_group(pid);
            Err(e)
        }
        Err(_) => {
            kill_group(pid).await;
            forget_group(pid);
            Err(GIT_TIMED_OUT.to_string())
        }
    }
}

/// Run git on the store at `git_dir` with `input` on its stdin, and return
/// its whole output.
async fn run_with_input(
    git_dir: &Path,
    args: &[&str],
    input: Vec<u8>,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    use tokio::io::AsyncWriteExt;
    let mut cmd = migration_command(git_dir, args);
    cmd.stdin(std::process::Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("git could not start: {e}"))?;
    let pid = child.id();
    note_group(pid);
    let mut stdin = child.stdin.take().ok_or("git has no stdin")?;
    let writer = tokio::spawn(async move {
        let wrote = stdin.write_all(&input).await;
        drop(stdin);
        wrote
    });
    let waited = tokio::time::timeout(timeout, child.wait_with_output()).await;
    let wrote = writer.await;
    match waited {
        Ok(Ok(out)) => {
            forget_group(pid);
            if !matches!(wrote, Ok(Ok(()))) {
                return Err("git's input was not written".into());
            }
            Ok(out)
        }
        Ok(Err(e)) => {
            forget_group(pid);
            Err(format!("git failed: {e}"))
        }
        Err(_) => {
            kill_group(pid).await;
            forget_group(pid);
            Err(GIT_TIMED_OUT.to_string())
        }
    }
}
