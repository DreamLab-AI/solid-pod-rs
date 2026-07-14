//! Issue spine: the on-disk pointer index at
//! `pluginDir/issues/<owner>/<repo>.json`.
//!
//! Field names serialise `camelCase` so an existing JSS forge's issue
//! files parse unchanged (JSS README §Data Model — cited by shape only).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ForgeError;
use crate::spine::SpineStore;

/// The `issues` spine kind (also the on-disk subdirectory name).
pub const KIND: &str = "issues";

/// Lifecycle state of an issue or pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IssueState {
    /// Open and active.
    #[default]
    Open,
    /// Closed without merge.
    Closed,
    /// Merged (pulls only).
    Merged,
}

/// A colour-tagged label. Materialised lazily on first write (Phase 5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Label {
    /// Label name (unique within a repo).
    pub name: String,
    /// Hex colour (`"d73a4a"`), no leading `#`.
    pub color: String,
}

/// A pointer into a thread body — a pod resource URL, or a hosted ref for
/// podless `did:nostr` agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreadPointer {
    /// Author id (WebID or `did:nostr:<hex>`).
    pub author: String,
    /// Loopback pod URL, or (when `hosted`) a `pluginDir/hosted/<hex>/<uuid>.json` ref.
    pub resource_url: String,
    /// Unix seconds the pointer was recorded.
    pub at: u64,
    /// `true` → the body lives in forge-hosted storage, not a pod.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hosted: bool,
}

/// One issue's spine entry (title + state + author + thread pointers).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssueEntry {
    /// Allocated issue number.
    pub number: u64,
    /// Human title (kept in the spine for cheap listing/search).
    pub title: String,
    /// Lifecycle state.
    pub state: IssueState,
    /// Author id (WebID or `did:nostr:<hex>`).
    pub author: String,
    /// Unix seconds of creation.
    pub created_at: u64,
    /// Ordered thread pointers (the opening body is index 0).
    pub thread: Vec<ThreadPointer>,
}

/// The issue index for one repo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IssueIndex {
    /// Next number to allocate.
    pub next: u64,
    /// Repo labels, materialised on first write (Phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<Label>>,
    /// Issues keyed by number.
    #[serde(default)]
    pub issues: BTreeMap<u64, IssueEntry>,
}

impl Default for IssueIndex {
    fn default() -> Self {
        Self {
            next: 1,
            labels: None,
            issues: BTreeMap::new(),
        }
    }
}

impl IssueIndex {
    /// Allocate the next issue number, appending `entry` (its `number`
    /// field is overwritten with the allocated value). Returns the number.
    pub fn allocate(&mut self, mut entry: IssueEntry) -> u64 {
        let n = self.next;
        entry.number = n;
        self.issues.insert(n, entry);
        self.next = n + 1;
        n
    }

    /// Issues filtered by state, newest-number first.
    #[must_use]
    pub fn by_state(&self, state: IssueState) -> Vec<&IssueEntry> {
        let mut v: Vec<&IssueEntry> = self
            .issues
            .values()
            .filter(|e| e.state == state)
            .collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.number));
        v
    }

    /// Count of issues in `state`.
    #[must_use]
    pub fn count(&self, state: IssueState) -> usize {
        self.issues.values().filter(|e| e.state == state).count()
    }

    /// Mutate an issue's state, returning `true` if it existed.
    pub fn set_state(&mut self, number: u64, state: IssueState) -> bool {
        match self.issues.get_mut(&number) {
            Some(e) => {
                e.state = state;
                true
            }
            None => false,
        }
    }
}

/// Load an issue index (default when absent). A present-but-corrupt file
/// surfaces an error rather than silently resetting the repo's history.
pub async fn load_issue_index(
    store: &dyn SpineStore,
    owner: &str,
    repo: &str,
) -> Result<IssueIndex, ForgeError> {
    match store.load(KIND, owner, repo).await? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            ForgeError::Backend(format!("corrupt issue index {owner}/{repo}: {e}"))
        }),
        None => Ok(IssueIndex::default()),
    }
}

/// Persist an issue index atomically (pretty-printed for on-disk
/// legibility and JSS parity).
pub async fn save_issue_index(
    store: &dyn SpineStore,
    owner: &str,
    repo: &str,
    idx: &IssueIndex,
) -> Result<(), ForgeError> {
    let bytes = serde_json::to_vec_pretty(idx)?;
    store.store(KIND, owner, repo, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spine::FsSpineStore;
    use tempfile::TempDir;

    fn entry(title: &str) -> IssueEntry {
        IssueEntry {
            number: 0,
            title: title.to_string(),
            state: IssueState::Open,
            author: "did:nostr:abc".to_string(),
            created_at: 100,
            thread: vec![ThreadPointer {
                author: "did:nostr:abc".to_string(),
                resource_url: "https://pod/x.jsonld".to_string(),
                at: 100,
                hosted: false,
            }],
        }
    }

    #[test]
    fn allocate_is_sequential_and_sets_number() {
        let mut idx = IssueIndex::default();
        assert_eq!(idx.allocate(entry("first")), 1);
        assert_eq!(idx.allocate(entry("second")), 2);
        assert_eq!(idx.next, 3);
        assert_eq!(idx.issues.get(&1).unwrap().number, 1);
        assert_eq!(idx.issues.get(&2).unwrap().title, "second");
    }

    #[test]
    fn by_state_and_count() {
        let mut idx = IssueIndex::default();
        idx.allocate(entry("a"));
        idx.allocate(entry("b"));
        idx.allocate(entry("c"));
        assert!(idx.set_state(2, IssueState::Closed));
        assert!(!idx.set_state(99, IssueState::Closed));
        assert_eq!(idx.count(IssueState::Open), 2);
        assert_eq!(idx.count(IssueState::Closed), 1);
        // Newest-first ordering.
        let open = idx.by_state(IssueState::Open);
        assert_eq!(open[0].number, 3);
        assert_eq!(open[1].number, 1);
    }

    #[test]
    fn state_serialises_camel_case() {
        let j = serde_json::to_string(&IssueState::Merged).unwrap();
        assert_eq!(j, "\"merged\"");
        let s: IssueState = serde_json::from_str("\"closed\"").unwrap();
        assert_eq!(s, IssueState::Closed);
    }

    #[test]
    fn thread_pointer_hosted_flag_omitted_when_false() {
        let p = ThreadPointer {
            author: "a".into(),
            resource_url: "u".into(),
            at: 1,
            hosted: false,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(!j.contains("hosted"), "false hosted must be omitted: {j}");
        let p2 = ThreadPointer { hosted: true, ..p };
        let j2 = serde_json::to_string(&p2).unwrap();
        assert!(j2.contains("\"hosted\":true"));
    }

    #[tokio::test]
    async fn persist_roundtrip_via_store() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        let mut idx = IssueIndex::default();
        idx.allocate(entry("hello"));
        save_issue_index(&store, "alice", "demo", &idx).await.unwrap();

        let loaded = load_issue_index(&store, "alice", "demo").await.unwrap();
        assert_eq!(loaded, idx);
        // Absent repo → default.
        let empty = load_issue_index(&store, "alice", "other").await.unwrap();
        assert_eq!(empty, IssueIndex::default());
    }

    #[tokio::test]
    async fn corrupt_index_surfaces_error() {
        let td = TempDir::new().unwrap();
        let store = FsSpineStore::new(td.path());
        store.store(KIND, "a", "r", b"not json{").await.unwrap();
        let res = load_issue_index(&store, "a", "r").await;
        assert!(matches!(res, Err(ForgeError::Backend(_))));
    }
}
