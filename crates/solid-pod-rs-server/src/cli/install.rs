//! `install` operator subcommand — clone a Solid app and push it into a
//! pod over the git smart protocol, authenticated with a single NIP-98
//! token.
//!
//! Mirrors JSS `src/cli/install.js`. The app-spec grammar, the GitHub
//! shorthands, the `#ref` pin / `=rename` suffixes, and the dual
//! `HEAD:main` + `HEAD:gh-pages` push all match JSS. Authentication uses
//! the pod's own NIP-98 scheme: a token minted by
//! [`solid_pod_rs::auth::nip98::mint`] over the destination repo URL with
//! method `*`, injected via git's `http.extraHeader` so it covers every
//! request of the multi-step smart protocol (the server accepts this with
//! [`MatchPolicy::GitLenient`](solid_pod_rs::auth::nip98::MatchPolicy)).
//!
//! NIP-98 minting requires the `install` cargo feature
//! (`solid-pod-rs/nip98-schnorr`); without it the `--nostr-privkey` path
//! returns an actionable error and only `--token` (bearer) remains.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;

/// Arguments for `install`.
#[derive(Debug, Args, Clone)]
pub struct InstallArgs {
    /// One or more app specs. Each is a bare app name
    /// (`https://github.com/solid-apps/<name>`), an `org/repo`
    /// shorthand (`https://github.com/org/repo`), or a full git URL.
    /// Append `#<ref>` to pin a branch/tag/commit and `=<dest>` to
    /// rename the pod directory. Example:
    /// `solid-apps/profile#v2=me-profile`.
    #[arg(required = true)]
    pub apps: Vec<String>,

    /// Target pod base URL.
    #[arg(long, env = "JSS_POD", default_value = "http://localhost:4443")]
    pub pod: String,

    /// 64-hex Nostr secret key used to mint NIP-98 push tokens.
    /// Required unless `--token` is supplied.
    #[arg(long, env = "NOSTR_PRIVKEY")]
    pub nostr_privkey: Option<String>,

    /// Bearer token alternative to NIP-98 (for IdP-authenticated,
    /// non-Nostr deployments).
    #[arg(long, env = "JSS_BEARER_TOKEN")]
    pub token: Option<String>,

    /// Destination branches that `HEAD` is pushed to. JSS publishes both
    /// `main` (data) and `gh-pages` (static hosting).
    #[arg(long, value_delimiter = ',', default_value = "main,gh-pages")]
    pub branches: Vec<String>,

    /// Resolve and clone, print the push plan, but do not push.
    #[arg(long)]
    pub dry_run: bool,
}

/// A parsed app spec: the resolved git source, the pod destination
/// directory, and an optional git ref to check out before pushing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSpec {
    /// Fully-resolved clone source (a git URL).
    pub source_url: String,
    /// Destination directory name under the pod root.
    pub dest: String,
    /// Optional branch / tag / commit to clone.
    pub git_ref: Option<String>,
}

/// Resolve a raw app spec into an [`AppSpec`]. Mirrors JSS `parseAppSpec`.
///
/// Grammar (suffixes are optional and order-independent here, parsed
/// rename-first then ref): `<source>[#<ref>][=<dest>]`.
///
/// `<source>` resolution:
/// - full URL (`http(s)://`, `git@`, `ssh://`) → used verbatim
/// - `org/repo` → `https://github.com/org/repo`
/// - bare `name` → `https://github.com/solid-apps/name`
pub fn parse_app_spec(spec: &str) -> anyhow::Result<AppSpec> {
    let (left, rename) = match spec.split_once('=') {
        Some((l, r)) if !r.is_empty() => (l, Some(r.to_string())),
        _ => (spec, None),
    };
    let (source, git_ref) = match left.split_once('#') {
        Some((s, r)) if !r.is_empty() => (s, Some(r.to_string())),
        _ => (left, None),
    };
    let source = source.trim();
    if source.is_empty() {
        anyhow::bail!("empty app spec: {spec:?}");
    }

    let source_url = if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
        || source.starts_with("ssh://")
    {
        source.to_string()
    } else if source.contains('/') {
        format!("https://github.com/{source}")
    } else {
        format!("https://github.com/solid-apps/{source}")
    };

    let dest = match rename {
        Some(d) => d,
        None => source_url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("app")
            .trim_end_matches(".git")
            .to_string(),
    };
    if dest.is_empty() {
        anyhow::bail!("could not derive destination name from {spec:?}");
    }

    Ok(AppSpec {
        source_url,
        dest,
        git_ref,
    })
}

/// Build the `Authorization` header value injected via
/// `http.extraHeader`. Prefers NIP-98 (minted from `--nostr-privkey`),
/// falling back to a bearer `--token`.
fn build_auth_header(dest_url: &str, args: &InstallArgs) -> anyhow::Result<String> {
    if let Some(privkey) = args.nostr_privkey.as_deref() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Method `*` + repo base URL: one token, every smart-protocol
        // request. The server verifies it under MatchPolicy::GitLenient.
        let token = solid_pod_rs::auth::nip98::mint(dest_url, "*", privkey, now).map_err(|e| {
            anyhow::anyhow!(
                "mint NIP-98 token: {e}. Rebuild the binary with \
                 `--features solid-pod-rs-server/install` to enable signing."
            )
        })?;
        Ok(format!("Nostr {token}"))
    } else if let Some(bearer) = args.token.as_deref() {
        Ok(format!("Bearer {bearer}"))
    } else {
        anyhow::bail!("install needs either --nostr-privkey or --token")
    }
}

fn run_git(cmd: &mut Command) -> anyhow::Result<()> {
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("spawn git: {e} (is `git` on PATH?)"))?;
    if !status.success() {
        anyhow::bail!("git exited with {status}");
    }
    Ok(())
}

fn temp_checkout_dir(dest: &str) -> PathBuf {
    let unique = format!(
        "solid-install-{}-{}-{dest}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    std::env::temp_dir().join(unique)
}

/// Clone one app and push it to the pod. Cleans up the temp checkout on
/// both success and failure.
fn install_one(spec: &AppSpec, args: &InstallArgs) -> anyhow::Result<()> {
    let pod = args.pod.trim_end_matches('/');
    let dest_url = format!("{pod}/{}", spec.dest);
    let workdir = temp_checkout_dir(&spec.dest);

    let result = install_into(spec, args, &dest_url, &workdir);
    // Best-effort cleanup regardless of outcome.
    let _ = std::fs::remove_dir_all(&workdir);
    result
}

fn install_into(
    spec: &AppSpec,
    args: &InstallArgs,
    dest_url: &str,
    workdir: &Path,
) -> anyhow::Result<()> {
    println!("→ {} → {dest_url}", spec.source_url);

    let mut clone = Command::new("git");
    clone.arg("clone").arg("--quiet");
    if let Some(git_ref) = &spec.git_ref {
        clone.arg("--branch").arg(git_ref);
    }
    clone.arg(&spec.source_url).arg(workdir);
    run_git(&mut clone)?;

    let header = build_auth_header(dest_url, args)?;

    let mut push = Command::new("git");
    push.arg("-C").arg(workdir);
    push.arg("-c")
        .arg(format!("http.extraHeader=Authorization: {header}"));
    push.arg("push").arg("--quiet").arg(dest_url);
    for branch in &args.branches {
        push.arg(format!("HEAD:refs/heads/{branch}"));
    }

    if args.dry_run {
        let scheme = header.split_whitespace().next().unwrap_or("");
        println!(
            "  dry-run: would push HEAD to [{}] on {dest_url} (auth: {scheme})",
            args.branches.join(", ")
        );
        return Ok(());
    }

    run_git(&mut push)?;
    println!("  pushed HEAD to [{}]", args.branches.join(", "));
    Ok(())
}

/// Run `install` for every spec in `args.apps`. Validates that at least
/// one auth method is present, then clones+pushes each app in order.
pub async fn run_install(args: &InstallArgs) -> anyhow::Result<()> {
    if args.nostr_privkey.is_none() && args.token.is_none() {
        anyhow::bail!(
            "install requires authentication: pass --nostr-privkey (NIP-98, env NOSTR_PRIVKEY) \
             or --token (bearer, env JSS_BEARER_TOKEN)"
        );
    }
    for raw in &args.apps {
        let spec = parse_app_spec(raw)?;
        install_one(&spec, args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_resolves_to_solid_apps_org() {
        let s = parse_app_spec("profile").unwrap();
        assert_eq!(s.source_url, "https://github.com/solid-apps/profile");
        assert_eq!(s.dest, "profile");
        assert_eq!(s.git_ref, None);
    }

    #[test]
    fn org_repo_resolves_to_github() {
        let s = parse_app_spec("acme/widgets").unwrap();
        assert_eq!(s.source_url, "https://github.com/acme/widgets");
        assert_eq!(s.dest, "widgets");
    }

    #[test]
    fn full_url_is_verbatim_and_strips_dot_git() {
        let s = parse_app_spec("https://example.com/x/cool-app.git").unwrap();
        assert_eq!(s.source_url, "https://example.com/x/cool-app.git");
        assert_eq!(s.dest, "cool-app");
    }

    #[test]
    fn ref_pin_and_rename_parse() {
        let s = parse_app_spec("solid-apps/profile#v2=me-profile").unwrap();
        assert_eq!(s.source_url, "https://github.com/solid-apps/profile");
        assert_eq!(s.git_ref.as_deref(), Some("v2"));
        assert_eq!(s.dest, "me-profile");
    }

    #[test]
    fn ref_only_keeps_default_dest() {
        let s = parse_app_spec("widgets#main").unwrap();
        assert_eq!(s.source_url, "https://github.com/solid-apps/widgets");
        assert_eq!(s.git_ref.as_deref(), Some("main"));
        assert_eq!(s.dest, "widgets");
    }

    #[test]
    fn empty_spec_errors() {
        assert!(parse_app_spec("").is_err());
        assert!(parse_app_spec("#ref").is_err());
    }
}
