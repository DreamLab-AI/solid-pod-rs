//! Repository materialisation and filesystem layout.
//!
//! Bare repositories live at `plugin_dir/repos/<owner>/<name>.git`.
//! The browse URL addresses `<owner>/<name>` (no `.git`); this module
//! bridges the two and enumerates repos for the index views.

pub mod browse;

use std::path::{Path, PathBuf};

use crate::error::ForgeError;
use crate::ownership::valid_name_segment;

/// Absolute path to a bare repo dir: `<repo_root>/<owner>/<name>.git`.
/// Validates both segments to prevent traversal before touching disk.
pub fn repo_git_dir(repo_root: &Path, owner: &str, name: &str) -> Result<PathBuf, ForgeError> {
    if !valid_name_segment(owner) {
        return Err(ForgeError::PathTraversal(format!("owner: {owner}")));
    }
    if !valid_name_segment(name) {
        return Err(ForgeError::PathTraversal(format!("repo: {name}")));
    }
    Ok(repo_root.join(owner).join(format!("{name}.git")))
}

/// `true` when a bare repo directory exists for `<owner>/<name>`.
pub async fn repo_exists(repo_root: &Path, owner: &str, name: &str) -> bool {
    match repo_git_dir(repo_root, owner, name) {
        Ok(p) => tokio::fs::metadata(&p)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Enumerate every `<owner>/<name>` repo under `repo_root`, sorted.
/// Silently skips entries that fail validation or are not directories.
pub async fn list_all(repo_root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(mut owners) = tokio::fs::read_dir(repo_root).await else {
        return out;
    };
    while let Ok(Some(owner_entry)) = owners.next_entry().await {
        let owner = owner_entry.file_name().to_string_lossy().into_owned();
        if !valid_name_segment(&owner) {
            continue;
        }
        if !owner_entry.path().is_dir() {
            continue;
        }
        for repo in list_owner(repo_root, &owner).await {
            out.push((owner.clone(), repo));
        }
    }
    out.sort();
    out
}

/// List the repo names owned by `owner` (the `.git` suffix stripped),
/// sorted.
pub async fn list_owner(repo_root: &Path, owner: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !valid_name_segment(owner) {
        return out;
    }
    let dir = repo_root.join(owner);
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".git") {
            if valid_name_segment(stem) {
                out.push(stem.to_string());
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn repo_git_dir_appends_dot_git() {
        let root = Path::new("/srv/repos");
        let p = repo_git_dir(root, "alice", "myrepo").unwrap();
        assert!(p.ends_with("alice/myrepo.git"));
    }

    #[test]
    fn repo_git_dir_rejects_traversal() {
        let root = Path::new("/srv/repos");
        assert!(repo_git_dir(root, "..", "x").is_err());
        assert!(repo_git_dir(root, "alice", "../etc").is_err());
        assert!(repo_git_dir(root, "alice", ".git").is_err());
    }

    #[tokio::test]
    async fn list_all_scans_two_levels() {
        let td = TempDir::new().unwrap();
        let root = td.path();
        tokio::fs::create_dir_all(root.join("alice/r1.git"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("alice/r2.git"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("bob/proj.git"))
            .await
            .unwrap();
        // A non-.git dir is ignored.
        tokio::fs::create_dir_all(root.join("alice/notarepo"))
            .await
            .unwrap();

        let all = list_all(root).await;
        assert_eq!(
            all,
            vec![
                ("alice".to_string(), "r1".to_string()),
                ("alice".to_string(), "r2".to_string()),
                ("bob".to_string(), "proj".to_string()),
            ]
        );

        let alice = list_owner(root, "alice").await;
        assert_eq!(alice, vec!["r1".to_string(), "r2".to_string()]);

        assert!(repo_exists(root, "bob", "proj").await);
        assert!(!repo_exists(root, "bob", "missing").await);
    }
}
