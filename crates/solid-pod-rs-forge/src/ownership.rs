//! Caller identity + repository-owner resolution and the namespace-write
//! guard.
//!
//! An owner is one of two shapes: a **pod username** (an authenticated
//! agent's local account) or a **64-hex `did:nostr` pubkey** (a podless
//! nostr agent). The forge's write rule is simple and fail-closed: an
//! agent may only create/push into a namespace whose first path segment
//! equals its own owner id. Pushing to another agent's namespace is a
//! `403` (JSS forge "namespace guard"), cited by behaviour only.

use solid_pod_rs::did_nostr_types::is_valid_hex_pubkey;

/// The resolved caller identity, produced by the server's WAC/auth layer
/// or by [`crate::auth`]. Mirrors the design's `ForgeAgent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeAgent {
    /// A pod-backed agent. `owner = username`; author id = the WebID.
    Pod {
        /// The agent's WebID URI (used as the author id in the spine).
        webid: String,
        /// The agent's pod username — the namespace it owns.
        username: String,
    },
    /// A podless nostr agent identified by a 64-hex x-only pubkey.
    Nostr {
        /// Lowercase 64-hex BIP-340 x-only pubkey.
        pubkey_hex: String,
    },
    /// No credential resolved.
    Anonymous,
}

impl ForgeAgent {
    /// The namespace this agent owns (its first-path-segment identity),
    /// or `None` when anonymous.
    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            ForgeAgent::Pod { username, .. } => Some(username),
            ForgeAgent::Nostr { pubkey_hex } => Some(pubkey_hex),
            ForgeAgent::Anonymous => None,
        }
    }

    /// The stable author id recorded in spine entries and thread
    /// pointers: a WebID for pod agents, `did:nostr:<hex>` for nostr
    /// agents, `"anonymous"` otherwise.
    #[must_use]
    pub fn author_id(&self) -> String {
        match self {
            ForgeAgent::Pod { webid, .. } => webid.clone(),
            ForgeAgent::Nostr { pubkey_hex } => format!("did:nostr:{pubkey_hex}"),
            ForgeAgent::Anonymous => "anonymous".to_string(),
        }
    }

    /// `true` for a podless nostr agent (bodies live in forge-hosted
    /// storage rather than a pod).
    #[must_use]
    pub fn is_nostr(&self) -> bool {
        matches!(self, ForgeAgent::Nostr { .. })
    }

    /// May this agent write (create/push/comment) into the namespace
    /// owned by `owner_segment`? True only when the agent's own owner id
    /// matches the target namespace exactly. Anonymous always fails.
    #[must_use]
    pub fn can_write_namespace(&self, owner_segment: &str) -> bool {
        match self.owner() {
            Some(o) => o == owner_segment,
            None => false,
        }
    }
}

/// Kind of an owner segment, derived from its shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    /// A pod username (anything that is not a 64-hex pubkey).
    PodUsername,
    /// A 64-hex `did:nostr` pubkey namespace.
    NostrHex,
}

/// Classify an owner path segment. A 64-char lowercase hex string is a
/// nostr namespace; everything else is treated as a pod username.
#[must_use]
pub fn classify_owner(segment: &str) -> OwnerKind {
    if is_valid_hex_pubkey(segment) {
        OwnerKind::NostrHex
    } else {
        OwnerKind::PodUsername
    }
}

/// Validate that an owner/repo path segment is well-formed: non-empty,
/// no path separators or `..`, and only characters git and the
/// filesystem tolerate in a bare-repo directory name. Rejects leading
/// dots (dotfiles) and control characters.
#[must_use]
pub fn valid_name_segment(seg: &str) -> bool {
    if seg.is_empty() || seg.len() > 100 {
        return false;
    }
    if seg == "." || seg == ".." || seg.starts_with('.') {
        return false;
    }
    if seg.contains("..") {
        return false;
    }
    seg.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64() -> String {
        "a".repeat(64)
    }

    #[test]
    fn pod_agent_owner_and_author() {
        let a = ForgeAgent::Pod {
            webid: "https://pod.example/alice/profile/card#me".into(),
            username: "alice".into(),
        };
        assert_eq!(a.owner(), Some("alice"));
        assert_eq!(a.author_id(), "https://pod.example/alice/profile/card#me");
        assert!(!a.is_nostr());
    }

    #[test]
    fn nostr_agent_owner_and_author() {
        let a = ForgeAgent::Nostr {
            pubkey_hex: hex64(),
        };
        assert_eq!(a.owner(), Some(hex64().as_str()));
        assert_eq!(a.author_id(), format!("did:nostr:{}", hex64()));
        assert!(a.is_nostr());
    }

    #[test]
    fn anonymous_cannot_write() {
        let a = ForgeAgent::Anonymous;
        assert_eq!(a.owner(), None);
        assert!(!a.can_write_namespace("alice"));
        assert_eq!(a.author_id(), "anonymous");
    }

    #[test]
    fn namespace_guard_matches_own_namespace_only() {
        let alice = ForgeAgent::Pod {
            webid: "w".into(),
            username: "alice".into(),
        };
        assert!(alice.can_write_namespace("alice"));
        assert!(!alice.can_write_namespace("bob"));
    }

    #[test]
    fn classify_distinguishes_hex_from_username() {
        assert_eq!(classify_owner(&hex64()), OwnerKind::NostrHex);
        assert_eq!(classify_owner("alice"), OwnerKind::PodUsername);
        // 63 or 65 hex chars is NOT a valid pubkey → treated as username.
        assert_eq!(classify_owner(&"a".repeat(63)), OwnerKind::PodUsername);
    }

    #[test]
    fn name_segment_validation() {
        assert!(valid_name_segment("my-repo"));
        assert!(valid_name_segment("repo_2"));
        assert!(valid_name_segment("v0.5.0"));
        assert!(!valid_name_segment(""));
        assert!(!valid_name_segment(".."));
        assert!(!valid_name_segment(".hidden"));
        assert!(!valid_name_segment("a/b"));
        assert!(!valid_name_segment("a..b"));
        assert!(!valid_name_segment("space bar"));
        assert!(!valid_name_segment(&"x".repeat(101)));
    }
}
