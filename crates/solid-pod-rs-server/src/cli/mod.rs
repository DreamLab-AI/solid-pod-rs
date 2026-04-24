//! Operator CLI subcommands — Sprint 11 rows 138, 163, 168.
//!
//! Three thin wrappers over library primitives:
//!
//! | Subcommand                           | JSS ref                | Primitive                          |
//! |--------------------------------------|------------------------|------------------------------------|
//! | `quota reconcile <pod>` / `--all`    | `bin/jss.js quota reconcile` | [`solid_pod_rs::quota::FsQuotaStore::reconcile`] |
//! | `account delete <user-id>`           | JSS #292 (`d9e56d8`)   | [`solid_pod_rs_idp::UserStore::delete`] |
//! | `invite create -u N [--expires-in]`  | JSS #304 (`6578ab9`)   | [`solid_pod_rs_idp::InviteStore`]  |
//!
//! Every runner is async and takes an already-constructed store so
//! the test harness can drive them with an in-memory double rather
//! than a real filesystem / database.

use clap::{Args, Subcommand};

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

    /// Account lifecycle — currently only `delete`.
    #[command(subcommand)]
    Account(AccountCommand),

    /// Invite-token operations — currently only `create`.
    #[command(subcommand)]
    Invite(InviteCommand),
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
    /// Remove a user, their pods, and their WebID profile.
    Delete(AccountDeleteArgs),
}

/// Arguments for `account delete`.
#[derive(Debug, Args, Clone)]
pub struct AccountDeleteArgs {
    /// Stable internal user id (the one stored on the [`User`] row).
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
}

/// Stdin-backed [`Prompt`] used by the real binary.
pub struct StdinPrompt;

impl Prompt for StdinPrompt {
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
        OperatorCommand::Account(AccountCommand::Delete(args)) => {
            // The binary ships with the in-memory UserStore by default;
            // operators wiring a persistent store plug their own
            // dispatch in place of this one. The default keeps the
            // subcommand callable in dev without a configured DB.
            let store = solid_pod_rs_idp::InMemoryUserStore::new();
            let mut prompt = StdinPrompt;
            let deleted = run_account_delete(&args, &store, &mut prompt).await?;
            if deleted {
                println!("deleted user {}", args.user_id);
            } else {
                println!("no such user {}", args.user_id);
            }
            Ok(())
        }
        OperatorCommand::Invite(InviteCommand::Create(args)) => {
            let store = solid_pod_rs_idp::InMemoryInviteStore::new();
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
