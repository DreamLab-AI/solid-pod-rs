//! # solid-pod-rs-git
//!
//! Git HTTP smart-protocol backend for
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs).
//!
//! ## Modules
//!
//! - [`service`] — Framework-agnostic [`GitHttpService`] that speaks `git-http-backend` CGI.
//! - [`auth`]    — `Basic nostr:<token>` and NIP-98 bearer auth extractors.
//! - [`guard`]   — Path-traversal rejection and repo-slug extraction.
//! - [`config`]  — Git repository config helpers (`receive.denyCurrentBranch`, etc.).
//! - [`error`]   — [`GitError`] enum with HTTP status-code mapping.
//!
//! ## Quick start
//!
//! ```no_run
//! use std::path::PathBuf;
//! use solid_pod_rs_git::{GitHttpService, BasicNostrExtractor};
//!
//! # async fn run() {
//! // Create the service rooted at a pod's data directory.
//! let service = GitHttpService::new(PathBuf::from("/var/pods/alice"))
//!     .with_auth(BasicNostrExtractor::new());
//!
//! // In your HTTP router, translate framework types to GitRequest and call:
//! // let response = service.handle(git_request).await;
//! # }
//! ```
//!
//! ## Feature flags
//!
//! | Flag              | Purpose                                         |
//! |-------------------|-------------------------------------------------|
//! | `with-git-binary` | Enable integration tests that need the `git` CLI and `git-http-backend` CGI binary. Unit tests always run. |
//!
//! ## Architecture
//!
//! The crate is framework-agnostic: [`GitHttpService`] consumes a
//! [`GitRequest`] and produces a [`GitResponse`]. The embedding HTTP
//! server (axum, actix-web, hyper, ...) translates between its native
//! types and these. Internally the service spawns `git http-backend`
//! (path overridable via `GIT_HTTP_BACKEND_PATH`) and shuttles bytes.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod api;
pub mod auth;
pub mod config;
pub mod error;
pub mod guard;
pub mod init;
pub mod service;

pub use api::{
    git_add, git_branches, git_commit, git_create_branch, git_diff, git_discard, git_log,
    git_status, git_unstage, BranchInfo, ChangeType, CommitEntry, CommitResult, FileStatus,
    StatusReport,
};
pub use auth::{AuthError, BasicNostrExtractor, GitAuth};
pub use config::{find_git_dir, GitDir};
pub use error::GitError;
pub use guard::{extract_repo_slug, path_safe};
pub use init::GitAutoInit;
pub use service::{GitHttpService, GitRequest, GitResponse, DEFAULT_GIT_HTTP_BACKEND};
