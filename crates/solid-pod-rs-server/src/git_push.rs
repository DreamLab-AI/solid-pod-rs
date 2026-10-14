//! Pre-receive path policy for `git push` to a pod repository.
//!
//! The pod repo is checked out by `receive.denyCurrentBranch=updateInstead`, so
//! a pushed path is written into the pod working tree. This module hands the
//! git service a classifier built from the **same** rules REST and MCP use
//! ([`guarded_acl_target`], [`canonical_pod_path`], the trail-store state
//! predicates and the [`DotfileAllowlist`]) so the two cannot drift.
//!
//! Policy: a push is refused if it touches any path that has a component
//! starting with `.` (this covers `.acl`, `.meta`, `.account`, `.well-known`,
//! `.git` and `.solid-pod-tmp-*`, whatever the dotfile allowlist says), a
//! storage sidecar (`*.acl`, `*.meta`, `*.meta.json`), the server-managed
//! `/.well-known/{token,gitmark,prov,webledgers}/` state, or any path that
//! cannot be canonicalised. Case variants are judged in lower case as well.
//! Nobody, including a principal with `acl:Control` on the pod root, may change
//! these through git: ACLs have a lock-out guard and validation on the REST
//! path that a raw push would skip, so they are edited over REST/MCP only.

use std::path::Path;
use std::sync::Arc;

use solid_pod_rs::{security::DotfileAllowlist, wac::AccessMode};
use solid_pod_rs_git::GitHttpService;

use crate::{canonical_pod_path, guarded_acl_target};

fn forbidden_one(dotfiles: &DotfileAllowlist, path: &str) -> bool {
    let Some(canon) = canonical_pod_path(path) else {
        return true;
    };
    canon
        .split('/')
        .any(|s| s.starts_with('.') || s.contains(".solid-pod-tmp-"))
        || !dotfiles.is_allowed(Path::new(&canon))
        || guarded_acl_target(&canon, AccessMode::Write) != (canon.clone(), AccessMode::Write)
}

/// `true` when a push must not change `rel`, a repository-relative path with a
/// leading `/`.
pub(crate) fn push_path_forbidden(dotfiles: &DotfileAllowlist, rel: &str) -> bool {
    forbidden_one(dotfiles, rel) || forbidden_one(dotfiles, &rel.to_ascii_lowercase())
}

/// The git service for a pod repository, with the push path guard installed.
pub(crate) fn pod_git_service(
    repo_root: std::path::PathBuf,
    dotfiles: Arc<DotfileAllowlist>,
) -> GitHttpService {
    GitHttpService::new(repo_root)
        .with_push_guard(Arc::new(move |rel| push_path_forbidden(&dotfiles, rel)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forbidden(rel: &str) -> bool {
        push_path_forbidden(&DotfileAllowlist::with_defaults(), rel)
    }

    #[test]
    fn guarded_classes_match_the_rest_and_mcp_rules() {
        for bad in [
            "/.well-known/token/x.json",
            "/.well-known/token/x/intent.json",
            "/.well-known/gitmark/p/blocktrails.json",
            "/.well-known/gitmark/p.json",
            "/.well-known/prov/epoch.json",
            "/.well-known/webledgers/webledgers.json",
            "/.well-known/webledgers/state.json",
            "/.WELL-KNOWN/Webledgers/x",
            "/.well-known/%74oken/x",
            "/%2ewell-known/webledgers/x",
            "/a/.acl",
            "/.acl",
            "/a/.meta",
            "/a/foo.acl",
            "/a/FOO.ACL",
            "/a/foo.meta",
            "/a/foo.meta.json",
            "/a/.account/x",
            "/.git/config",
            "/a/.git/hooks/pre-commit",
            "/a/.x.solid-pod-tmp-1",
            "/a/b.solid-pod-tmp-1",
            "/a/../b",
            "/a/./b",
            "/a\\b",
            "/a/%2e%2e/b",
            "/a/%00",
            "/.hidden",
            // Not rooted at a pod root: still a dot component.
            "/pod/.well-known/token/x",
        ] {
            assert!(forbidden(bad), "{bad} must be refused");
        }
    }

    #[test]
    fn ordinary_paths_are_allowed() {
        for ok in [
            "/index.html",
            "/docs/a.txt",
            "/well-known/token/x",
            "/tokens/x.json",
            "/a/b.ttl",
            "/a/metadata.json",
            "/a/acl.txt",
        ] {
            assert!(!forbidden(ok), "{ok} must be allowed");
        }
    }

    #[test]
    fn a_wider_dotfile_allowlist_does_not_open_the_state_or_sidecars() {
        let wide = DotfileAllowlist::new(vec![
            ".well-known".into(),
            ".acl".into(),
            ".meta".into(),
            ".git".into(),
        ]);
        for bad in [
            "/.well-known/token/x",
            "/a/.acl",
            "/a/.meta",
            "/.git/config",
        ] {
            assert!(push_path_forbidden(&wide, bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_push_through_the_pod_service_is_checked_with_the_shared_classifier() {
        use std::process::Command;
        let exec = Command::new("git").arg("--exec-path").output().unwrap();
        let backend = std::path::PathBuf::from(String::from_utf8_lossy(&exec.stdout).trim())
            .join("git-http-backend");
        assert!(backend.exists());
        let git = |dir: &Path, args: &[&str]| {
            let o = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(o.status.success(), "{args:?}");
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let push = |files: &[(&str, &str)]| {
            let c = tempfile::tempdir().unwrap();
            git(c.path(), &["init", "-q", "-b", "main"]);
            git(c.path(), &["config", "user.email", "t@e.com"]);
            git(c.path(), &["config", "user.name", "T"]);
            for (p, b) in files {
                let f = c.path().join(p);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(f, b).unwrap();
            }
            git(c.path(), &["add", "-A"]);
            git(c.path(), &["commit", "-qm", "c"]);
            let new = git(c.path(), &["rev-parse", "HEAD"]);
            let pack = Command::new("git")
                .args(["pack-objects", "--stdout", "-q", "--revs"])
                .current_dir(c.path())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut pack = pack;
            std::io::Write::write_all(
                &mut pack.stdin.take().unwrap(),
                format!("{new}\n").as_bytes(),
            )
            .unwrap();
            let pack = pack.wait_with_output().unwrap().stdout;
            let line = format!("{} {new} refs/heads/main\0 report-status\n", "0".repeat(40));
            let mut body = format!("{:04x}{line}0000", line.len() + 4).into_bytes();
            body.extend(pack);
            body
        };

        #[derive(Debug)]
        struct Allow;
        #[async_trait::async_trait]
        impl solid_pod_rs_git::GitAuth for Allow {
            async fn authorise(
                &self,
                _: &solid_pod_rs_git::GitRequest,
            ) -> Result<String, solid_pod_rs_git::AuthError> {
                Ok("t".into())
            }
        }

        let run = |body: Vec<u8>| {
            let backend = backend.clone();
            async move {
                let td = tempfile::tempdir().unwrap();
                std::fs::create_dir(td.path().join("pod")).unwrap();
                let svc = pod_git_service(
                    td.path().to_path_buf(),
                    Arc::new(DotfileAllowlist::with_defaults()),
                )
                .with_backend_path(backend.clone())
                .with_auth(Allow);
                let r = svc
                    .handle(solid_pod_rs_git::GitRequest {
                        method: "POST".into(),
                        path: "/pod/git-receive-pack".into(),
                        query: String::new(),
                        headers: vec![(
                            "content-type".into(),
                            "application/x-git-receive-pack-request".into(),
                        )],
                        body: bytes::Bytes::from(body),
                        host_url: None,
                    })
                    .await
                    .unwrap();
                (String::from_utf8_lossy(&r.body).into_owned(), td)
            }
        };

        // The path the lead's probe used: the Web Ledger.
        let (report, td) = run(push(&[(".well-known/webledgers/webledgers.json", "{}")])).await;
        assert!(report.contains("push refused"), "{report}");
        assert!(!td.path().join("pod/.well-known").exists());
        let (report, td) = run(push(&[("docs/a.txt", "a")])).await;
        assert!(report.contains("ok refs/heads/main"), "{report}");
        assert!(td.path().join("pod/docs/a.txt").exists());
    }
}
