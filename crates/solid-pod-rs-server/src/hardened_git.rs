//! Hardened `git` constructor for the server's own subprocess sites.
//!
//! Mirrors `solid_pod_rs_git::hardened_git`, duplicated here because the
//! `solid-pod-rs-git` dependency is optional (`git` feature) while the
//! `install` CLI is always built. Repo-local hooks, fsmonitor and ambient
//! git config are disabled; `core.sshCommand` is deliberately left alone so
//! `install` can still clone over ssh URLs the operator supplies.

use std::process::Command;

/// A `git` command with hooks and ambient config neutralised.
#[must_use]
pub(crate) fn hardened_git() -> Command {
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgSign=false",
    ])
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

/// Tokio flavour of [`hardened_git`].
#[cfg(feature = "git")]
#[must_use]
pub(crate) fn hardened_git_async() -> tokio::process::Command {
    tokio::process::Command::from(hardened_git())
}
