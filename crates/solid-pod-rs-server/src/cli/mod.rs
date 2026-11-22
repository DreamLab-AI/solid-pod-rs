//! Operator CLI subcommands — Sprint 11 rows 138, 163, 168.
//!
//! Three thin wrappers over library primitives:
//!
//! | Subcommand                           | JSS ref                | Primitive                          |
//! |--------------------------------------|------------------------|------------------------------------|
//! | `quota reconcile <pod>` / `--all`    | `bin/jss.js quota reconcile` | [`solid_pod_rs::quota::QuotaPolicy::reconcile`] |
//! | `account create/delete/list/export`  | JSS #292 (`d9e56d8`)   | `FileUserStore` (`<root>/.server/accounts.json`) |
//! | `invite create -u N [--expires-in]`  | JSS #304 (`6578ab9`)   | [`solid_pod_rs_idp::InviteStore`]  |
//!
//! Every runner is async and takes an already-constructed store so
//! the test harness can drive them with an in-memory double rather
//! than a real filesystem / database.

use clap::{Args, Subcommand};

mod install;
pub use install::{parse_app_spec, run_install, AppSpec, InstallArgs};

mod account_store;
pub use account_store::{CreateError, FileUserStore};
mod invite_store;
pub use invite_store::{Consume, FileInviteStore, InviteRow};

// ---------------------------------------------------------------------------
// Public CLI surface
// ---------------------------------------------------------------------------

/// Operator subcommands. The binary entry point in `main.rs` parses
/// this via `#[command(subcommand)]` alongside the existing
/// server-run flags.
#[derive(Debug, Subcommand)]
pub enum OperatorCommand {
    /// Quota operations — currently only `reconcile`.
    #[command(subcommand)]
    Quota(QuotaCommand),

    /// Account lifecycle: `create`, `delete`, `list`, `export`. Accounts
    /// persist in `<root>/.server/accounts.json`.
    Account {
        /// Data directory holding `.server/accounts.json` (JSS `-r, --root`).
        #[arg(
            short = 'r',
            long,
            global = true,
            env = "JSS_STORAGE_ROOT",
            default_value = "./data"
        )]
        root: std::path::PathBuf,
        /// The account operation.
        #[command(subcommand)]
        cmd: AccountCommand,
    },

    /// Invite-token operations: `create`, `list`, `revoke` (JSS
    /// `bin/jss.js` 457-540). Invites persist in
    /// `<root>/.server/invites.json`.
    Invite {
        /// Data directory holding `.server/invites.json` (JSS `-r, --root`).
        #[arg(
            short = 'r',
            long,
            global = true,
            env = "JSS_STORAGE_ROOT",
            default_value = "./data"
        )]
        root: std::path::PathBuf,
        /// The invite operation.
        #[command(subcommand)]
        cmd: InviteCommand,
    },

    /// Clone Solid apps and push them into a pod over git (JSS `install`).
    Install(InstallArgs),
}

// ---------------------------------------------------------------------------
// `quota` — row 138
// ---------------------------------------------------------------------------

/// `quota` subcommands.
#[derive(Debug, Subcommand)]
pub enum QuotaCommand {
    /// Walk the pod's storage tree, recompute used bytes, rewrite the
    /// `.quota.json` sidecar. Pass `--all` to reconcile every pod
    /// directly under `--root`.
    Reconcile(QuotaReconcileArgs),
}

/// Arguments for `quota reconcile`.
#[derive(Debug, Args, Clone)]
pub struct QuotaReconcileArgs {
    /// Pod directory name under `--root`. Mutually exclusive with
    /// `--all`; clap enforces the requirement at parse time.
    #[arg(required_unless_present = "all")]
    pub pod_id: Option<String>,

    /// Reconcile every immediate subdirectory of `--root`.
    #[arg(long, conflicts_with = "pod_id")]
    pub all: bool,

    /// Filesystem root containing pod directories. Falls back to the
    /// `JSS_STORAGE_ROOT` env var, then `./data`.
    #[arg(long, env = "JSS_STORAGE_ROOT", default_value = "./data")]
    pub root: std::path::PathBuf,

    /// Default quota cap applied when a sidecar is absent or has
    /// `limit_bytes == 0`. Bytes. `0` means "no cap".
    #[arg(long, default_value_t = 0)]
    pub default_limit: u64,
}

// ---------------------------------------------------------------------------
// `account delete` — row 168
// ---------------------------------------------------------------------------

/// `account` subcommands.
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Create an account. The username is also the pod name, so it must
    /// pass the registration name check (names the server serves itself,
    /// such as `remotestorage`, are refused). The password is read from
    /// stdin, never from the command line, with echo off when stdin is a
    /// terminal.
    Create(AccountCreateArgs),

    /// Remove a user from the account store. (The pod's files are not
    /// touched.)
    Delete(AccountDeleteArgs),

    /// List accounts (no password hashes).
    List,

    /// Print one account as JSON (no password hash).
    Export(AccountExportArgs),
}

/// Arguments for `account create`.
#[derive(Debug, Args, Clone)]
pub struct AccountCreateArgs {
    /// Username, also the pod name (`[A-Za-z0-9_-]`).
    pub username: String,

    /// Email address (unique, case-insensitive).
    #[arg(long)]
    pub email: String,

    /// Display name.
    #[arg(long)]
    pub name: Option<String>,

    /// Public base URL of the server; the WebID is
    /// `<base-url>/<username>/profile/card#me`.
    #[arg(long = "base-url", env = "JSS_BASE_URL")]
    pub base_url: String,
}

/// Arguments for `account export`.
#[derive(Debug, Args, Clone)]
pub struct AccountExportArgs {
    /// Stable internal user id.
    pub user_id: String,
}

/// Arguments for `account delete`.
#[derive(Debug, Args, Clone)]
pub struct AccountDeleteArgs {
    /// Stable internal user id (the one stored on the `User` row).
    pub user_id: String,

    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

// ---------------------------------------------------------------------------
// `invite create` — row 163
// ---------------------------------------------------------------------------

/// `invite` subcommands.
#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// Mint an opaque invite token, store it, print the invite URL.
    Create(InviteCreateArgs),

    /// List every stored invite (JSS `invite list`).
    List,

    /// Delete an invite so it can no longer be redeemed (JSS
    /// `invite revoke <code>`). Exits non-zero if the token is unknown.
    Revoke(InviteRevokeArgs),
}

/// Arguments for `invite revoke`.
#[derive(Debug, Args, Clone)]
pub struct InviteRevokeArgs {
    /// The invite token to revoke (case-sensitive). Tokens are base64url, so
    /// about one in 64 begins with `-`; that must not be read as a flag.
    #[arg(allow_hyphen_values = true)]
    pub token: String,
}

/// Arguments for `invite create`.
#[derive(Debug, Args, Clone)]
pub struct InviteCreateArgs {
    /// Maximum redemptions. Omit for unlimited uses.
    #[arg(short = 'u', long = "uses")]
    pub uses: Option<u32>,

    /// Optional expiry, as `30s` / `5m` / `2h` / `7d` / `1w`, or a
    /// bare integer (seconds).
    #[arg(long = "expires-in")]
    pub expires_in: Option<String>,

    /// Base URL used to build the final invite URL. Defaults to an
    /// operator-conventional `https://pod.invalid` so the CLI is
    /// usable in non-interactive pipelines; production deployments
    /// override this with their public origin.
    #[arg(long = "base-url", default_value = "https://pod.invalid")]
    pub base_url: String,
}

// ---------------------------------------------------------------------------
// Runners — pure library surface, unit-testable without a process
// ---------------------------------------------------------------------------

/// Reconcile result — returned by the quota runner so integration
/// tests can assert on post-state rather than parsing stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Pod dir name.
    pub pod: String,
    /// Recomputed used bytes.
    pub used_bytes: u64,
    /// Effective limit (may be the default-limit fallback).
    pub limit_bytes: u64,
}

/// Run `quota reconcile`. Returns one outcome per reconciled pod.
///
/// Requires the `quota` Cargo feature on `solid-pod-rs` to be active
/// transitively — this function is only compiled when the `quota`
/// feature is on at this crate's level too (see `[features]` in
/// `Cargo.toml`). Without that feature the binary falls back to
/// the lower-case message runner below.
#[cfg(feature = "quota")]
pub async fn run_quota_reconcile(
    args: &QuotaReconcileArgs,
) -> anyhow::Result<Vec<ReconcileOutcome>> {
    use solid_pod_rs::quota::{FsQuotaStore, QuotaPolicy};

    // Resolve the pod set. `--all` iterates immediate subdirs of
    // `--root`; otherwise we use the single positional pod id.
    let pods: Vec<String> = if args.all {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&args.root).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!("storage root does not exist: {}", args.root.display());
            }
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    // Skip hidden dotfiles (`.git`, `.cache`, etc).
                    if !name.starts_with('.') {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    } else {
        vec![args
            .pod_id
            .clone()
            .expect("clap guarantees pod_id or --all")]
    };

    let store = FsQuotaStore::new(args.root.clone(), args.default_limit);
    let mut outcomes = Vec::with_capacity(pods.len());
    for pod in pods {
        let usage = store
            .reconcile(&pod)
            .await
            .map_err(|e| anyhow::anyhow!("reconcile {pod}: {e}"))?;
        outcomes.push(ReconcileOutcome {
            pod,
            used_bytes: usage.used_bytes,
            limit_bytes: usage.limit_bytes,
        });
    }
    Ok(outcomes)
}

/// Fallback runner compiled when the `quota` feature is off at this
/// crate's level. Surfaces the actionable error rather than a cryptic
/// `command not found`.
#[cfg(not(feature = "quota"))]
pub async fn run_quota_reconcile(
    _args: &QuotaReconcileArgs,
) -> anyhow::Result<Vec<ReconcileOutcome>> {
    anyhow::bail!(
        "`quota reconcile` requires the `quota` cargo feature. Rebuild with \
         `--features solid-pod-rs-server/quota`."
    )
}

/// Input reader trait so tests can feed confirmation text without
/// touching real stdin.
pub trait Prompt: Send {
    /// Emit a prompt line and read the user's answer. Returns
    /// `Ok(None)` when stdin is closed (EOF).
    fn ask(&mut self, prompt: &str) -> std::io::Result<Option<String>>;

    /// Like [`Prompt::ask`], for a secret: an implementation that talks to a
    /// person must not echo what is typed. The default is [`Prompt::ask`],
    /// which suits scripted input.
    fn ask_secret(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        self.ask(prompt)
    }
}

/// Stdin-backed [`Prompt`] used by the real binary.
pub struct StdinPrompt;

impl Prompt for StdinPrompt {
    /// On a terminal, read with echo off (restored afterwards, also on error);
    /// when stdin is piped or redirected there is nothing to hide, so read the
    /// line as [`Prompt::ask`] does.
    fn ask_secret(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            read_hidden(prompt, rpassword::ConfigBuilder::new().build()).map(Some)
        } else {
            self.ask(prompt)
        }
    }

    fn ask(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        use std::io::{BufRead, Write};
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        write!(handle, "{prompt}")?;
        handle.flush()?;
        let stdin = std::io::stdin();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(line.trim_end_matches(['\r', '\n']).to_string())),
            Err(e) => Err(e),
        }
    }
}

/// Print `prompt` and read one line with the terminal's echo switched off.
fn read_hidden(prompt: &str, config: rpassword::Config) -> std::io::Result<String> {
    rpassword::prompt_password_with_config(prompt, config)
}

/// Run `account delete`. Returns `Ok(true)` when a row was actually
/// removed, `Ok(false)` when the user id was unknown, and `Err(..)`
/// when the caller skipped confirmation without `--yes`.
pub async fn run_account_delete<S, P>(
    args: &AccountDeleteArgs,
    store: &S,
    prompt: &mut P,
) -> anyhow::Result<bool>
where
    S: solid_pod_rs_idp::UserStore + ?Sized,
    P: Prompt,
{
    if !args.yes {
        let banner = format!(
            "About to delete user {user} and every associated pod + WebID profile.\n\
             Type the user id to confirm: ",
            user = args.user_id
        );
        let answer = prompt
            .ask(&banner)?
            .ok_or_else(|| anyhow::anyhow!("account delete aborted: stdin closed without --yes"))?;
        if answer.trim() != args.user_id {
            anyhow::bail!(
                "account delete aborted: confirmation {answer:?} did not match {user:?}",
                user = args.user_id
            );
        }
    }
    let deleted = store
        .delete(&args.user_id)
        .await
        .map_err(|e| anyhow::anyhow!("user store delete: {e}"))?;
    Ok(deleted)
}

/// Run `account create`: read the password from `prompt` (stdin in the
/// binary) and create the account in `store`. The name goes through the same
/// pod-name and reserved-name check as `POST /api/accounts/new`.
pub async fn run_account_create<P: Prompt>(
    args: &AccountCreateArgs,
    store: &FileUserStore,
    prompt: &mut P,
) -> anyhow::Result<solid_pod_rs_idp::User> {
    // Refuse a bad name before asking for a secret.
    if !crate::valid_pod_name(&args.username) {
        anyhow::bail!(
            "account create: {:?} is not a valid account name (use [A-Za-z0-9_-]; names the \
             server serves itself are reserved)",
            args.username
        );
    }
    let password = prompt
        .ask_secret("Password: ")?
        .ok_or_else(|| anyhow::anyhow!("account create aborted: no password on stdin"))?;
    store
        .create(
            &args.username,
            &args.email,
            &password,
            args.name.as_deref(),
            &args.base_url,
        )
        .await
        .map_err(|e| anyhow::anyhow!("account create: {e}"))
}

/// Run an `account` subcommand against the file store under `root`.
pub async fn run_account_command(
    root: &std::path::Path,
    cmd: AccountCommand,
) -> anyhow::Result<()> {
    let store = FileUserStore::new(root);
    match cmd {
        AccountCommand::Create(args) => {
            let mut prompt = StdinPrompt;
            let user = run_account_create(&args, &store, &mut prompt).await?;
            println!("created account {} ({})", user.id, user.webid);
            Ok(())
        }
        AccountCommand::Delete(args) => {
            let mut prompt = StdinPrompt;
            if run_account_delete(&args, &store, &mut prompt).await? {
                println!("deleted user {}", args.user_id);
                Ok(())
            } else {
                anyhow::bail!("no such user {}", args.user_id)
            }
        }
        AccountCommand::List => {
            let rows = store
                .list()
                .await
                .map_err(|e| anyhow::anyhow!("account store: {e}"))?;
            if rows.is_empty() {
                println!("No accounts found.");
            }
            for r in rows {
                println!(
                    "{}  {}  {}",
                    r["id"].as_str().unwrap_or(""),
                    r["username"].as_str().unwrap_or(""),
                    r["webid"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        AccountCommand::Export(args) => {
            match store
                .export(&args.user_id)
                .await
                .map_err(|e| anyhow::anyhow!("account store: {e}"))?
            {
                Some(v) => {
                    println!("{}", serde_json::to_string_pretty(&v)?);
                    Ok(())
                }
                None => anyhow::bail!("no such user {}", args.user_id),
            }
        }
    }
}

/// Run `invite create`. Returns the minted invite *and* the final
/// invite URL so the binary can print both in one step and tests can
/// assert on the URL's shape.
pub async fn run_invite_create<S>(
    args: &InviteCreateArgs,
    store: &S,
) -> anyhow::Result<(solid_pod_rs_idp::Invite, String)>
where
    S: solid_pod_rs_idp::InviteStore + ?Sized,
{
    let expires_at = match args.expires_in.as_deref() {
        Some(spec) => {
            let dur = solid_pod_rs_idp::parse_invite_duration(spec)
                .map_err(|e| anyhow::anyhow!("--expires-in {spec:?}: {e}"))?;
            let chrono_dur = chrono::Duration::from_std(dur)
                .map_err(|e| anyhow::anyhow!("--expires-in {spec:?} out of range: {e}"))?;
            Some(chrono::Utc::now() + chrono_dur)
        }
        None => None,
    };
    let token = solid_pod_rs_idp::mint_invite_token();
    let invite = solid_pod_rs_idp::Invite {
        token: token.clone(),
        max_uses: args.uses,
        expires_at,
    };
    store
        .insert(invite.clone())
        .await
        .map_err(|e| anyhow::anyhow!("invite store insert: {e}"))?;
    let base = args.base_url.trim_end_matches('/');
    let url = format!("{base}/invite?token={token}");
    Ok((invite, url))
}

// ---------------------------------------------------------------------------
// Binary-layer glue
// ---------------------------------------------------------------------------

/// Dispatch an [`OperatorCommand`] against real stores. The binary in
/// `main.rs` calls this, tests skip it and drive the `run_*`
/// functions directly.
pub async fn dispatch(cmd: OperatorCommand) -> anyhow::Result<()> {
    match cmd {
        OperatorCommand::Quota(QuotaCommand::Reconcile(args)) => {
            let outcomes = run_quota_reconcile(&args).await?;
            for out in &outcomes {
                println!(
                    "reconciled pod={} used_bytes={} limit_bytes={}",
                    out.pod, out.used_bytes, out.limit_bytes
                );
            }
            if outcomes.is_empty() {
                println!("no pods found under {}", args.root.display());
            }
            Ok(())
        }
        OperatorCommand::Account { root, cmd } => run_account_command(&root, cmd).await,
        OperatorCommand::Invite { root, cmd } => run_invite_command(&root, cmd).await,
        OperatorCommand::Install(args) => run_install(&args).await,
    }
}

/// Run an `invite` subcommand against the file store under `root`.
pub async fn run_invite_command(root: &std::path::Path, cmd: InviteCommand) -> anyhow::Result<()> {
    let store = FileInviteStore::new(root);
    match cmd {
        InviteCommand::List => {
            let rows = store
                .list()
                .await
                .map_err(|e| anyhow::anyhow!("invite store: {e}"))?;
            if rows.is_empty() {
                println!("No invite codes found.");
                return Ok(());
            }
            println!("ID  USES  CREATED  EXPIRES");
            for r in rows {
                let cap = r
                    .max_uses
                    .map_or("unlimited".to_string(), |n| n.to_string());
                let exp = r.expires_at.map_or("never".to_string(), |t| t.to_rfc3339());
                println!(
                    "{}  {}/{}  {}  {}",
                    r.id,
                    r.uses,
                    cap,
                    r.created.format("%Y-%m-%d"),
                    exp
                );
            }
            Ok(())
        }
        InviteCommand::Revoke(args) => {
            let removed = store
                .revoke(&args.token)
                .await
                .map_err(|e| anyhow::anyhow!("invite store: {e}"))?;
            if removed {
                println!("Revoked invite code: {}", args.token);
                Ok(())
            } else {
                anyhow::bail!("Invite code not found: {}", args.token)
            }
        }
        InviteCommand::Create(args) => {
            let (invite, url) = run_invite_create(&args, &store).await?;
            println!("token: {}", invite.token);
            match invite.max_uses {
                Some(n) => println!("max_uses: {n}"),
                None => println!("max_uses: unlimited"),
            }
            match invite.expires_at {
                Some(t) => println!("expires_at: {}", t.to_rfc3339()),
                None => println!("expires_at: never"),
            }
            println!("url: {url}");
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::fs::{open, Mode, OFlags};
    use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
    use rustix::termios::{tcgetattr, LocalModes};
    use std::io::Write;

    /// Property: a password typed at a terminal is never echoed. A real
    /// pseudo-terminal stands in for the person: while the reader is waiting
    /// the line discipline has ECHO off, the typed text comes back intact, and
    /// ECHO is restored afterwards. (There is no fail-before for this test:
    /// the previous code read stdin with echo on and had no entry point that
    /// could be pointed at a pty.)
    #[test]
    fn a_secret_is_read_with_echo_off_and_the_terminal_is_restored() {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap();
        let echo = |fd: &rustix::fd::OwnedFd| {
            tcgetattr(fd)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        };
        assert!(echo(&slave), "a fresh terminal echoes");
        let mut typist = std::fs::File::from(master);
        let slave_for_typist = rustix::io::dup(&slave).unwrap();
        let typed = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let echoing_while_waiting = echo(&slave_for_typist);
            typist.write_all(b"hunter2\n").unwrap();
            (echoing_while_waiting, typist)
        });
        let config = rpassword::ConfigBuilder::new()
            .input_file_path(name.to_str().unwrap())
            .output_discard()
            .build();
        let got = read_hidden("Password: ", config).unwrap();
        let (echoing_while_waiting, _master) = typed.join().unwrap();
        assert_eq!(got, "hunter2");
        assert!(!echoing_while_waiting, "ECHO was on while reading a secret");
        assert!(echo(&slave), "the terminal was left with echo off");
    }

    struct Scripted(Vec<&'static str>);
    impl Prompt for Scripted {
        fn ask(&mut self, _: &str) -> std::io::Result<Option<String>> {
            Ok(self.0.pop().map(str::to_string))
        }
    }

    #[test]
    fn a_scripted_prompt_answers_a_secret_through_ask() {
        let mut p = Scripted(vec!["pw"]);
        assert_eq!(p.ask_secret("x").unwrap().as_deref(), Some("pw"));
    }
}
