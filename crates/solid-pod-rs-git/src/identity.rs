//! Pod-git-root agent identity writer (ADR-124 §5.3 / Defect-3 NEW).
//!
//! Melvin Carvalho's `create-agent` design treats each per-user pod as a
//! **full git repository** whose ROOT carries two identity artefacts:
//!
//! 1. `agent.did.json` — the canonical `did:nostr` DID document
//!    (ADR-125 / §1: two-context, top-level `DIDNostr`, single `Multikey`
//!    verification method with `publicKeyMultibase: "fe70102<hex>"`,
//!    `#key1`, `service: []`).
//! 2. `git config nostr.privkey <hex>` — the agent's BIP-340 secret key,
//!    stored in the pod-repo's *local* git config (never committed).
//!
//! This module is the solid-pod-rs analogue of create-agent's identity
//! bootstrap. It is **net-new** (Defect-3): the pre-pivot bootstrap wrote a
//! 2019-shape `did-nostr.json` and an `identity.env`; neither
//! `agent.did.json` nor `git config nostr.privkey` existed. The canonical
//! DID doc is rendered by [`solid_pod_rs::did_nostr_types::render_did_document`],
//! so the on-disk doc is byte-identical to every other emitter in the
//! ecosystem.
//!
//! ## Invariants
//!
//! - **I1** — the `did:nostr:<hex>` identity string is unchanged; the
//!   pubkey is the canonical x-only hex.
//! - **I2** — `publicKeyMultibase == "fe70102" + <x-only-hex>`, produced by
//!   the canonical renderer; no key bytes change.
//! - **I3** — this writer is *provisioning only*. It never participates in
//!   the NIP-98 auth path; the privkey it git-configs is the signing key, not
//!   an authentication oracle.

use std::path::Path;

use solid_pod_rs::did_nostr_types::{render_did_document, NostrPubkey};

use crate::config::{find_git_dir, run_git_config};
use crate::error::GitError;

/// Filename of the canonical DID document at the pod-git root.
pub const AGENT_DID_FILE: &str = "agent.did.json";

/// The git-config key under which the agent's BIP-340 secret key (hex) is
/// stored in the pod-repo's local config (create-agent parity).
pub const NOSTR_PRIVKEY_KEY: &str = "nostr.privkey";

/// Result of writing the pod-git-root identity artefacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentityWritten {
    /// Absolute path of the `agent.did.json` written.
    pub did_path: std::path::PathBuf,
    /// The `did:nostr:<hex>` identity string (I1 — unchanged).
    pub did: String,
    /// `true` if `git config nostr.privkey` succeeded; `false` if it was
    /// skipped (no privkey supplied) or the git binary was unavailable
    /// (best-effort, mirroring [`crate::config::apply_write_config`]).
    pub privkey_configured: bool,
}

/// Write the canonical `agent.did.json` to `pod_root` and, when a secret
/// key is supplied, run `git config --local nostr.privkey <privkey_hex>`
/// in the pod repo.
///
/// `pubkey_hex` is the 32-byte BIP-340 x-only public key in lowercase hex
/// (the canonical identity, I1). `privkey_hex`, when `Some`, is the matching
/// 32-byte secret key in hex; it is stored ONLY in the repo-local git config
/// (never written to `agent.did.json`, never committed).
///
/// The DID document is rendered by the canonical
/// [`render_did_document`] — identical bytes to every other ecosystem
/// emitter. `agent.did.json` is written to the repo root so it is a
/// first-class, committable file (the deploy ritual: edit → validate →
/// commit → git-mark → push).
///
/// # Errors
///
/// - [`GitError::PathTraversal`] if `pubkey_hex` is not a valid 32-byte
///   x-only hex pubkey (cannot render the canonical doc — refuse rather than
///   emit a keyless / malformed document, mirroring the interop D-1 rule).
/// - [`GitError::Io`] if the doc cannot be written to disk.
///
/// The `git config nostr.privkey` step is **best-effort**: a missing git
/// binary or a non-repo `pod_root` is logged and reported as
/// `privkey_configured: false`, never an error — identity provisioning must
/// not be blocked by a transient git-config failure (the privkey can be
/// re-set on the next provisioning pass).
pub async fn write_agent_identity(
    pod_root: &Path,
    pubkey_hex: &str,
    privkey_hex: Option<&str>,
) -> Result<AgentIdentityWritten, GitError> {
    // I2/I1: render the canonical DID doc from the parsed x-only pubkey.
    // Refuse malformed input rather than emit a non-conformant document.
    let pk = NostrPubkey::from_hex(pubkey_hex)
        .map_err(|e| GitError::PathTraversal(format!("agent.did.json: invalid pubkey: {e}")))?;
    let doc = render_did_document(&pk);
    let did = doc["id"].as_str().unwrap_or_default().to_string();

    let body = serde_json::to_string_pretty(&doc)
        .map_err(|e| GitError::MalformedCgi(format!("agent.did.json serialise: {e}")))?;

    let did_path = pod_root.join(AGENT_DID_FILE);
    tokio::fs::write(&did_path, body.as_bytes())
        .await
        .map_err(GitError::Io)?;

    // git config nostr.privkey <hex> — best-effort, repo-local.
    let mut privkey_configured = false;
    if let Some(sk_hex) = privkey_hex {
        match find_git_dir(pod_root) {
            Ok(Some(git_dir)) => {
                match run_git_config(pod_root, &git_dir.git_dir, NOSTR_PRIVKEY_KEY, sk_hex).await {
                    Ok(()) => privkey_configured = true,
                    Err(e) => tracing::debug!(
                        target: "solid_pod_rs_git::identity",
                        "git config {NOSTR_PRIVKEY_KEY} skipped (non-fatal): {e}"
                    ),
                }
            }
            _ => tracing::debug!(
                target: "solid_pod_rs_git::identity",
                "pod_root {} is not a git repo; nostr.privkey not configured",
                pod_root.display()
            ),
        }
    }

    Ok(AgentIdentityWritten {
        did_path,
        did,
        privkey_configured,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::process::Command;

    const PK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[tokio::test]
    async fn writes_canonical_agent_did_json() {
        let td = TempDir::new().unwrap();
        let out = write_agent_identity(td.path(), PK_HEX, None)
            .await
            .unwrap();

        // I1: did string unchanged.
        assert_eq!(out.did, format!("did:nostr:{PK_HEX}"));
        assert!(!out.privkey_configured, "no privkey supplied");

        // On-disk doc is the canonical §1 shape.
        let written = std::fs::read_to_string(out.did_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["type"], "DIDNostr");
        assert_eq!(v["@context"][0], "https://w3id.org/did");
        assert_eq!(v["@context"][1], "https://w3id.org/nostr/context");
        let vm = &v["verificationMethod"][0];
        assert_eq!(vm["type"], "Multikey");
        // I2: publicKeyMultibase == fe70102 + same x-only hex.
        assert_eq!(vm["publicKeyMultibase"], format!("fe70102{PK_HEX}"));
        assert!(vm.get("publicKeyHex").is_none(), "2019 publicKeyHex dropped");
        assert_eq!(v["authentication"][0], "#key1");
        assert!(v["service"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_malformed_pubkey() {
        let td = TempDir::new().unwrap();
        let res = write_agent_identity(td.path(), "not-hex", None).await;
        assert!(res.is_err(), "malformed pubkey must be refused, not written");
        // No file leaked.
        assert!(!td.path().join(AGENT_DID_FILE).exists());
    }

    /// Only runs when the git binary is available; git-configs the privkey
    /// into a real pod repo and reads it back.
    #[tokio::test]
    async fn configures_nostr_privkey_in_repo() {
        let td = TempDir::new().unwrap();
        let repo = td.path();
        let status = Command::new("git")
            .arg("init")
            .arg(repo)
            .output()
            .await;
        let status = match status {
            Ok(o) => o.status,
            Err(_) => return, // no git binary — skip.
        };
        assert!(status.success());

        let sk_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let out = write_agent_identity(repo, PK_HEX, Some(sk_hex))
            .await
            .unwrap();
        assert!(out.privkey_configured, "privkey must be git-configured in a repo");

        // Read it back — and confirm it is NOT in the committed doc.
        let gd = find_git_dir(repo).unwrap().unwrap();
        let read = Command::new("git")
            .arg("config")
            .arg("--local")
            .arg(NOSTR_PRIVKEY_KEY)
            .current_dir(repo)
            .env("GIT_DIR", &gd.git_dir)
            .output()
            .await
            .unwrap();
        assert!(read.status.success());
        assert_eq!(String::from_utf8_lossy(&read.stdout).trim(), sk_hex);

        let doc = std::fs::read_to_string(out.did_path).unwrap();
        assert!(
            !doc.contains(sk_hex),
            "privkey must NEVER appear in agent.did.json"
        );
    }
}
