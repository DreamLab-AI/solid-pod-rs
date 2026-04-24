//! Opaque-token session store.
//!
//! JSS parity: the cookie-signed session state in
//! `src/idp/provider.js:104-122`. We skip the cookie framing (that's
//! the consumer's transport decision) and expose a token-keyed
//! lookup. Sessions hold the authenticated account id + an
//! authorisation-code buffer for in-flight code-flow exchanges.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::RngCore;
use thiserror::Error;

/// Errors from [`SessionStore`].
#[derive(Debug, Error)]
pub enum SessionError {
    /// Session id not found.
    #[error("unknown session")]
    Unknown,
    /// Session expired.
    #[error("session expired")]
    Expired,
}

/// Opaque session identifier (32 bytes, base16-encoded).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh cryptographically-random session id.
    pub fn generate() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self(hex::encode(buf))
    }

    /// Borrow the underlying string (for logging / cookie value
    /// emission).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct from a raw string (e.g. a cookie value). Callers are
    /// responsible for length/charset validation upstream.
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// A single authorisation code issued during the `/auth` flow.
#[derive(Debug, Clone)]
pub struct AuthCodeRecord {
    /// Opaque code (base16 random).
    pub code: String,
    /// Client who requested the code.
    pub client_id: String,
    /// Account id that authenticated.
    pub account_id: String,
    /// Redirect URI passed at `/auth` time (must match at `/token`).
    pub redirect_uri: String,
    /// PKCE code challenge (`S256` only).
    pub code_challenge: Option<String>,
    /// Issue time.
    pub issued_at: Instant,
    /// PKCE required?
    pub requested_scope: Option<String>,
}

/// Session record.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Logged-in account id.
    pub account_id: String,
    /// Creation time.
    pub created_at: Instant,
    /// Last touched; extended on every lookup.
    pub last_access: Instant,
}

impl SessionRecord {
    fn new(account_id: String) -> Self {
        Self {
            account_id,
            created_at: Instant::now(),
            last_access: Instant::now(),
        }
    }
}

/// In-memory session + authorisation-code store.
#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<RwLock<Inner>>,
    /// Session TTL. JSS uses 14 days (`provider.js:109`).
    session_ttl: Duration,
    /// Authorisation-code TTL. JSS uses 10 minutes
    /// (`provider.js:127`).
    code_ttl: Duration,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, SessionRecord>,
    codes: HashMap<String, AuthCodeRecord>,
}

impl SessionStore {
    /// Default TTLs: 14-day session, 10-minute code.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            session_ttl: Duration::from_secs(14 * 24 * 3600),
            code_ttl: Duration::from_secs(10 * 60),
        }
    }

    /// Override TTLs.
    pub fn with_ttls(mut self, session_ttl: Duration, code_ttl: Duration) -> Self {
        self.session_ttl = session_ttl;
        self.code_ttl = code_ttl;
        self
    }

    /// Create a fresh session for `account_id` and return its id.
    pub fn create_session(&self, account_id: impl Into<String>) -> SessionId {
        let id = SessionId::generate();
        self.inner
            .write()
            .sessions
            .insert(id.as_str().to_string(), SessionRecord::new(account_id.into()));
        id
    }

    /// Look up a session by id. Extends `last_access` on hit.
    pub fn lookup(&self, id: &SessionId) -> Result<SessionRecord, SessionError> {
        let mut inner = self.inner.write();
        let entry = inner
            .sessions
            .get_mut(id.as_str())
            .ok_or(SessionError::Unknown)?;
        if entry.last_access.elapsed() > self.session_ttl {
            inner.sessions.remove(id.as_str());
            return Err(SessionError::Expired);
        }
        entry.last_access = Instant::now();
        Ok(entry.clone())
    }

    /// Revoke a session (log out).
    pub fn revoke(&self, id: &SessionId) {
        self.inner.write().sessions.remove(id.as_str());
    }

    /// Issue an opaque authorisation code. Returns the new record.
    pub fn issue_code(
        &self,
        client_id: impl Into<String>,
        account_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        code_challenge: Option<String>,
        requested_scope: Option<String>,
    ) -> AuthCodeRecord {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let code = hex::encode(buf);
        let rec = AuthCodeRecord {
            code: code.clone(),
            client_id: client_id.into(),
            account_id: account_id.into(),
            redirect_uri: redirect_uri.into(),
            code_challenge,
            issued_at: Instant::now(),
            requested_scope,
        };
        self.inner.write().codes.insert(code, rec.clone());
        rec
    }

    /// Consume (single-use) a previously-issued code. `None` if the
    /// code doesn't exist or has expired. JSS's oidc-provider also
    /// drops a code after a single redemption attempt; we match that.
    pub fn take_code(&self, code: &str) -> Option<AuthCodeRecord> {
        let mut inner = self.inner.write();
        let rec = inner.codes.remove(code)?;
        if rec.issued_at.elapsed() > self.code_ttl {
            return None;
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_unique() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(a.as_str().len(), 64); // hex(32 bytes)
    }

    #[test]
    fn session_create_lookup_revoke_roundtrip() {
        let s = SessionStore::new();
        let id = s.create_session("acct-1");
        let rec = s.lookup(&id).unwrap();
        assert_eq!(rec.account_id, "acct-1");
        s.revoke(&id);
        assert!(matches!(s.lookup(&id), Err(SessionError::Unknown)));
    }

    #[test]
    fn session_expiry_is_enforced() {
        let s = SessionStore::new().with_ttls(Duration::from_millis(1), Duration::from_secs(60));
        let id = s.create_session("acct-2");
        std::thread::sleep(Duration::from_millis(10));
        let err = s.lookup(&id).unwrap_err();
        assert!(matches!(err, SessionError::Expired));
    }

    #[test]
    fn auth_code_is_single_use() {
        let s = SessionStore::new();
        let rec = s.issue_code("c-1", "acct-3", "https://app/cb", None, None);
        let a = s.take_code(&rec.code).unwrap();
        assert_eq!(a.account_id, "acct-3");
        // Second redemption must fail.
        assert!(s.take_code(&rec.code).is_none());
    }

    #[test]
    fn auth_code_expires() {
        let s = SessionStore::new()
            .with_ttls(Duration::from_secs(60), Duration::from_millis(1));
        let rec = s.issue_code("c-1", "acct-4", "https://app/cb", None, None);
        std::thread::sleep(Duration::from_millis(10));
        assert!(s.take_code(&rec.code).is_none());
    }
}
