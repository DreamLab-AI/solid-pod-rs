//! Hardened `git` subprocess constructors.
//!
//! Pod repositories live in user-writable data trees, so a repository's own
//! `.git/config` and `.git/hooks` are attacker-influenced. Every production
//! `git` spawn in the workspace goes through [`hardened_git`] (std) or
//! [`hardened_git_async`] (tokio) so that:
//!
//! * repo-local hooks never run (`core.hooksPath=/dev/null`),
//! * `core.fsmonitor` cannot name a program (`core.fsmonitor=false`),
//! * `core.sshCommand` and `commit.gpgSign` cannot spawn helpers,
//! * system and global config are ignored (`GIT_CONFIG_NOSYSTEM=1`,
//!   `GIT_CONFIG_GLOBAL=/dev/null`),
//! * git never blocks on a credential prompt (`GIT_TERMINAL_PROMPT=0`).
//!
//! # Example
//!
//! ```
//! let mut cmd = solid_pod_rs_git::hardened_git();
//! cmd.arg("--version");
//! # let _ = cmd;
//! ```

use std::process::Command;

/// `-c key=value` overrides applied before any caller arguments.
pub const HARDENED_CONFIG: [(&str, &str); 4] = [
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.sshCommand", "false"),
    ("commit.gpgSign", "false"),
];

/// Environment variables applied to every hardened invocation.
pub const HARDENED_ENV: [(&str, &str); 3] = [
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
];

/// Build a `git` [`std::process::Command`] with hooks, fsmonitor, ssh/gpg
/// helpers and ambient config disabled. Append the subcommand and arguments
/// as usual.
#[must_use]
pub fn hardened_git() -> Command {
    let mut cmd = Command::new("git");
    for (k, v) in HARDENED_CONFIG {
        cmd.arg("-c").arg(format!("{k}={v}"));
    }
    for (k, v) in HARDENED_ENV {
        cmd.env(k, v);
    }
    cmd
}

/// Tokio flavour of [`hardened_git`].
#[must_use]
pub fn hardened_git_async() -> tokio::process::Command {
    tokio::process::Command::from(hardened_git())
}

/// Environment entries that harden an externally-spawned git program (the
/// `git-http-backend` CGI) whose environment is built by hand. Uses git's
/// `GIT_CONFIG_COUNT` mechanism because the CGI cannot take `-c` flags.
#[must_use]
pub fn hardened_cgi_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = HARDENED_ENV
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    env.push(("GIT_CONFIG_COUNT".into(), HARDENED_CONFIG.len().to_string()));
    for (i, (k, v)) in HARDENED_CONFIG.iter().enumerate() {
        env.push((format!("GIT_CONFIG_KEY_{i}"), (*k).to_string()));
        env.push((format!("GIT_CONFIG_VALUE_{i}"), (*v).to_string()));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn git_ok(dir: &std::path::Path, args: &[&str]) -> bool {
        hardened_git()
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn repo_local_hooks_do_not_fire() {
        let td = tempfile::TempDir::new().unwrap();
        let repo = td.path();
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        assert!(git_ok(repo, &["init", "-q", "-b", "main"]));
        let marker = repo.join("HOOK_FIRED");
        for name in ["pre-commit", "post-checkout", "post-commit"] {
            let hook = repo.join(".git/hooks").join(name);
            std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::fs::write(repo.join("f.txt"), "x").unwrap();
        assert!(git_ok(repo, &["add", "f.txt"]));
        assert!(git_ok(
            repo,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-q",
                "-m",
                "m"
            ]
        ));
        assert!(git_ok(repo, &["checkout", "-q", "-b", "other"]));
        assert!(!marker.exists(), "a repo-local hook fired");

        // Control: the plain constructor does fire the hook (proves the hook
        // is genuinely executable, so the assertion above is meaningful).
        let ok = Command::new("git")
            .args(["checkout", "-q", "main"])
            .current_dir(repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap()
            .success();
        assert!(ok);
        #[cfg(unix)]
        assert!(marker.exists(), "control: plain git should fire the hook");
    }

    #[test]
    fn repo_local_fsmonitor_is_neutralised() {
        let td = tempfile::TempDir::new().unwrap();
        let repo = td.path();
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        assert!(git_ok(repo, &["init", "-q"]));
        let marker = repo.join("FSMON_FIRED");
        let script = repo.join("fsmon.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(Command::new("git")
            .args(["config", "--local", "core.fsmonitor"])
            .arg(script.display().to_string())
            .current_dir(repo)
            .status()
            .unwrap()
            .success());
        assert!(git_ok(repo, &["status"]));
        assert!(!marker.exists(), "repo-local fsmonitor fired");
    }

    #[test]
    fn cgi_env_has_matching_count() {
        let env = hardened_cgi_env();
        let count: usize = env
            .iter()
            .find(|(k, _)| k == "GIT_CONFIG_COUNT")
            .unwrap()
            .1
            .parse()
            .unwrap();
        assert_eq!(count, HARDENED_CONFIG.len());
        assert!(env
            .iter()
            .any(|(k, v)| k == "GIT_CONFIG_KEY_1" && v == "core.hooksPath"));
    }
}
