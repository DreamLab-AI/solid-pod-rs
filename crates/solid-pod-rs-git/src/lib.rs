//! # solid-pod-rs-git
//!
//! Git HTTP smart-protocol backend for
//! [`solid-pod-rs`](https://crates.io/crates/solid-pod-rs). Brings
//! PARITY-CHECKLIST rows 69 (Basic-over-NIP-98 auth) and 100 (Git
//! HTTP with `receive.denyCurrentBranch=updateInstead`) to feature
//! parity with JavaScriptSolidServer's
//! [`src/handlers/git.js`](https://github.com/solid/solid-nextgraph/blob/main/src/handlers/git.js).
//!
//! ## Architecture
//!
//! The crate is binder-agnostic: the top-level [`GitHttpService`]
//! consumes a [`GitRequest`] and produces a [`GitResponse`], and the
//! embedding HTTP server (axum, actix-web, hyper raw, …) translates
//! between its native types and these. Internally the service spawns
//! the system `git http-backend` CGI binary (default path
//! `/usr/lib/git-core/git-http-backend`, overridable via the
//! `GIT_HTTP_BACKEND_PATH` env var) and shuttles bytes between it
//! and the HTTP layer.
//!
//! ## Routes covered
//!
//! | JSS route                         | Method | Auth  |
//! |-----------------------------------|--------|-------|
//! | `/:repo/info/refs?service=…`      | GET    | no    |
//! | `/:repo/git-upload-pack`          | POST   | no    |
//! | `/:repo/git-receive-pack`         | POST   | **yes** (NIP-98 or Basic-nostr) |
//!
//! ## Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use solid_pod_rs_git::{GitHttpService, BasicNostrExtractor};
//!
//! # async fn run() {
//! let service = GitHttpService::new(PathBuf::from("/var/pods/alice"))
//!     .with_auth(BasicNostrExtractor::new());
//! // … hand `service.handle(req)` from your HTTP router.
//! # }
//! ```
//!
//! ## Feature flags
//!
//! | Flag              | Purpose                                         |
//! |-------------------|-------------------------------------------------|
//! | `with-git-binary` | Enable integration tests that require the `git` CLI + `git-http-backend` CGI to be installed. Unit tests always run. |
//!
//! ## JSS source map
//!
//! * [`auth`] ← JSS `Basic nostr:<token>` bridge in `src/handlers/git.js` + `src/auth/nip98.js`
//! * [`guard`] ← JSS `extractRepoPath` + `isPathWithinDataRoot` (`src/handlers/git.js:31-62`)
//! * [`config`] ← JSS `git config` mutators (`src/handlers/git.js:133-150`)
//! * [`service`] ← JSS `handleGit` (`src/handlers/git.js:95-268`)

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod auth;
pub mod config;
pub mod error;
pub mod guard;
pub mod service;

pub use auth::{AuthError, BasicNostrExtractor, GitAuth};
pub use config::{find_git_dir, GitDir};
pub use error::GitError;
pub use guard::{extract_repo_slug, path_safe};
pub use service::{GitHttpService, GitRequest, GitResponse, DEFAULT_GIT_HTTP_BACKEND};
