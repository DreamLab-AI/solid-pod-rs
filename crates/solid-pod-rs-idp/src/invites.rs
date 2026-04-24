//! Sprint-11 row 163 — invite-token storage.
//!
//! Mirrors JSS commit `6578ab9` (#304): operators mint opaque invite
//! tokens with an optional max-uses counter and optional expiry. The
//! token is surfaced as a URL the operator can hand to a prospective
//! user; consumption (decrementing `remaining_uses`) is the IdP's
//! job and lives outside this trait. This module owns the
//! *creation + persistence* half only, which is all the
//! `invite create` CLI subcommand needs.
//!
//! Storage is pluggable via [`InviteStore`]; the built-in
//! [`InMemoryInviteStore`] covers tests and single-node dev. Production
//! deployments ship their own store (SQL, Redis, etc.).

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// Persisted invite record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Opaque bearer token. URL-safe base64.
    pub token: String,
    /// Hard cap on redemptions. `None` means unlimited — matching
    /// JSS's "no `-u`" semantic.
    pub max_uses: Option<u32>,
    /// Optional expiry timestamp. `None` means no expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Errors surfaced by [`InviteStore`].
#[derive(Debug, Error)]
pub enum InviteStoreError {
    /// Backend-specific failure (DB down, etc).
    #[error("backend: {0}")]
    Backend(String),
}

/// Storage contract for invite tokens.
///
/// Implementations need only persist + round-trip the [`Invite`]; the
/// CLI and IdP handle token minting and URL construction.
#[async_trait]
pub trait InviteStore: Send + Sync + 'static {
    /// Insert an invite. Idempotent on the token: if the token already
    /// exists the call is a no-op that returns `Ok(())`. The token is
    /// caller-supplied so the CLI can echo it back to the operator
    /// without a second round-trip.
    async fn insert(&self, invite: Invite) -> Result<(), InviteStoreError>;

    /// Fetch an invite by its token.
    async fn get(&self, token: &str) -> Result<Option<Invite>, InviteStoreError>;
}

/// Reference in-memory implementation.
#[derive(Default)]
pub struct InMemoryInviteStore {
    inner: RwLock<HashMap<String, Invite>>,
}

impl InMemoryInviteStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow every invite for inspection. Test-only, kept `pub` so
    /// downstream crates can introspect their own in-memory store in
    /// integration tests.
    pub fn snapshot(&self) -> Vec<Invite> {
        self.inner.read().values().cloned().collect()
    }
}

#[async_trait]
impl InviteStore for InMemoryInviteStore {
    async fn insert(&self, invite: Invite) -> Result<(), InviteStoreError> {
        self.inner
            .write()
            .entry(invite.token.clone())
            .or_insert(invite);
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<Invite>, InviteStoreError> {
        Ok(self.inner.read().get(token).cloned())
    }
}

/// Mint a cryptographically-random 32-byte opaque token, base64url
/// without padding. Matches JSS `generateInviteToken()` shape.
pub fn mint_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Parse a human-friendly duration like `7d`, `12h`, `30m`, `45s`.
///
/// Single-unit only — we do not accept `1d12h`. Unknown units return
/// an error string. Empty input is an error (the CLI layer uses
/// `Option<String>` so a missing flag never reaches this function).
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_string());
    }
    // Plain-integer seconds fall-through.
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(Duration::from_secs(n));
    }
    let (num_part, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("no unit suffix in {trimmed:?}"))?,
    );
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid number {num_part:?}: {e}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3_600),
        "d" => n.saturating_mul(86_400),
        "w" => n.saturating_mul(604_800),
        other => return Err(format!("unknown duration unit {other:?}")),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inmemory_store_round_trips() {
        let s = InMemoryInviteStore::new();
        let inv = Invite {
            token: "tok-1".into(),
            max_uses: Some(3),
            expires_at: None,
        };
        s.insert(inv.clone()).await.unwrap();
        let got = s.get("tok-1").await.unwrap().unwrap();
        assert_eq!(got, inv);
        assert!(s.get("missing").await.unwrap().is_none());
    }

    #[test]
    fn mint_token_is_base64url_and_uniqueish() {
        let a = mint_token();
        let b = mint_token();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // 32 raw bytes => 43 base64url chars (no padding).
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn parse_duration_accepts_common_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7_200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("1w").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_rejects_bad_input() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("1y").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
