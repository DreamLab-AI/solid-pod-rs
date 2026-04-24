//! SQLite-backed persistence for followers, following, inbox, outbox
//! and the federated delivery queue.
//!
//! LINE-FOR-LINE `jss/src/ap/store.js`:
//!
//! * followers(id PRIMARY KEY, actor, inbox, created_at)
//! * following(id PRIMARY KEY, actor, accepted, created_at)
//! * activities(id PRIMARY KEY, type, actor, object, raw, created_at)
//! * posts(id PRIMARY KEY, content, in_reply_to, published)
//! * actors(id PRIMARY KEY, data, fetched_at)
//!
//! We diverge in three ways:
//!   1. The primary key on `inbox` is the activity `id` — JSS's
//!      `activities` table conflates inbox + outbox; we split them for
//!      clarity and per-kind indexing.
//!   2. A dedicated `delivery_queue` table feeds the background worker
//!      in [`crate::delivery`]. JSS does in-process retry; we do
//!      durable retry across restarts.
//!   3. The `followers` row's primary key is `(actor_id, follower_id)`
//!      so we can model multi-user pods without hashing the pair into
//!      a surrogate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

/// Opaque store handle. Clone freely — the underlying pool is
/// reference-counted.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

/// Outbox row representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxRow {
    pub id: String,
    pub actor_id: String,
    pub activity: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub delivery_state: String,
}

/// Inbox row representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxRow {
    pub id: String,
    pub actor_id: String,
    pub activity: serde_json::Value,
    pub received_at: DateTime<Utc>,
}

/// A single queued delivery awaiting transmission.
#[derive(Debug, Clone)]
pub struct DeliveryItem {
    pub queue_id: i64,
    pub activity_id: String,
    pub inbox_url: String,
    pub attempts: i64,
    pub last_error: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS followers (
    actor_id TEXT NOT NULL,
    follower_id TEXT NOT NULL,
    inbox TEXT,
    accepted_at DATETIME,
    PRIMARY KEY (actor_id, follower_id)
);
CREATE TABLE IF NOT EXISTS following (
    actor_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    requested_at DATETIME NOT NULL,
    accepted BOOLEAN NOT NULL DEFAULT 0,
    PRIMARY KEY (actor_id, target_id)
);
CREATE TABLE IF NOT EXISTS inbox (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    activity TEXT NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    activity TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivery_state TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS delivery_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_id TEXT NOT NULL,
    inbox_url TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

impl Store {
    /// Connect to an arbitrary SQLite URL (use `sqlite::memory:` for
    /// tests). Runs the schema idempotently.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await?;
        sqlx::query(SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
    }

    /// In-memory store — useful for tests.
    pub async fn in_memory() -> Result<Self, sqlx::Error> {
        // The `sqlite::memory:` URL creates a fresh DB per connection,
        // which breaks pooling. Use a shared in-memory URL instead.
        Self::connect("sqlite::memory:?cache=shared").await
    }

    /// Expose the pool for advanced callers. Prefer the typed helpers
    /// below where possible.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // -------------------------- followers --------------------------------

    pub async fn add_follower(
        &self,
        actor_id: &str,
        follower_id: &str,
        inbox: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(
            "INSERT OR REPLACE INTO followers (actor_id, follower_id, inbox, accepted_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(actor_id)
        .bind(follower_id)
        .bind(inbox)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_follower(
        &self,
        actor_id: &str,
        follower_id: &str,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "DELETE FROM followers WHERE actor_id = ?1 AND follower_id = ?2",
        )
        .bind(actor_id)
        .bind(follower_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn is_follower(
        &self,
        actor_id: &str,
        follower_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM followers WHERE actor_id = ?1 AND follower_id = ?2",
        )
        .bind(actor_id)
        .bind(follower_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn follower_inboxes(&self, actor_id: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT inbox FROM followers WHERE actor_id = ?1 AND inbox IS NOT NULL",
        )
        .bind(actor_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    pub async fn follower_count(&self, actor_id: &str) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM followers WHERE actor_id = ?1")
                .bind(actor_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(n)
    }

    // -------------------------- following --------------------------------

    pub async fn add_following(
        &self,
        actor_id: &str,
        target_id: &str,
    ) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(
            "INSERT OR REPLACE INTO following (actor_id, target_id, requested_at, accepted) \
             VALUES (?1, ?2, ?3, 0)",
        )
        .bind(actor_id)
        .bind(target_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn accept_following(
        &self,
        actor_id: &str,
        target_id: &str,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE following SET accepted = 1 WHERE actor_id = ?1 AND target_id = ?2",
        )
        .bind(actor_id)
        .bind(target_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn is_following(
        &self,
        actor_id: &str,
        target_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT accepted FROM following WHERE actor_id = ?1 AND target_id = ?2",
        )
        .bind(actor_id)
        .bind(target_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(matches!(row, Some((1,))))
    }

    // --------------------------- inbox -----------------------------------

    /// Record an inbox activity. Idempotent on activity `id`.
    pub async fn record_inbox(
        &self,
        actor_id: &str,
        activity: &serde_json::Value,
    ) -> Result<bool, sqlx::Error> {
        let id = activity
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            return Ok(false);
        }
        let body = serde_json::to_string(activity).unwrap_or_else(|_| "{}".into());
        let res = sqlx::query(
            "INSERT OR IGNORE INTO inbox (id, actor_id, activity, received_at) \
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&id)
        .bind(actor_id)
        .bind(&body)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_inbox(&self, id: &str) -> Result<Option<InboxRow>, sqlx::Error> {
        let row: Option<(String, String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, actor_id, activity, received_at FROM inbox WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, actor_id, activity, received_at)| InboxRow {
            id,
            actor_id,
            activity: serde_json::from_str(&activity).unwrap_or(serde_json::Value::Null),
            received_at,
        }))
    }

    pub async fn inbox_count(&self) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM inbox")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    // --------------------------- outbox ----------------------------------

    pub async fn record_outbox(
        &self,
        actor_id: &str,
        activity: &serde_json::Value,
    ) -> Result<String, sqlx::Error> {
        let id = activity
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        let body = serde_json::to_string(activity).unwrap_or_else(|_| "{}".into());
        sqlx::query(
            "INSERT OR REPLACE INTO outbox (id, actor_id, activity, created_at, delivery_state) \
             VALUES (?1, ?2, ?3, ?4, 'pending')",
        )
        .bind(&id)
        .bind(actor_id)
        .bind(&body)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn mark_outbox_state(
        &self,
        id: &str,
        state: &str,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("UPDATE outbox SET delivery_state = ?1 WHERE id = ?2")
            .bind(state)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn outbox_count(&self) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM outbox")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    // ----------------------- delivery queue ------------------------------

    pub async fn enqueue_delivery(
        &self,
        activity_id: &str,
        inbox_url: &str,
    ) -> Result<i64, sqlx::Error> {
        let res = sqlx::query(
            "INSERT INTO delivery_queue (activity_id, inbox_url, attempts, next_retry) \
             VALUES (?1, ?2, 0, ?3)",
        )
        .bind(activity_id)
        .bind(inbox_url)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    pub async fn next_due_delivery(&self) -> Result<Option<DeliveryItem>, sqlx::Error> {
        let row: Option<(i64, String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT id, activity_id, inbox_url, attempts, last_error FROM delivery_queue \
             WHERE next_retry <= ?1 ORDER BY id ASC LIMIT 1",
        )
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(queue_id, activity_id, inbox_url, attempts, last_error)| DeliveryItem {
                queue_id,
                activity_id,
                inbox_url,
                attempts,
                last_error,
            },
        ))
    }

    pub async fn drop_delivery(&self, queue_id: i64) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("DELETE FROM delivery_queue WHERE id = ?1")
            .bind(queue_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn reschedule_delivery(
        &self,
        queue_id: i64,
        delay_secs: i64,
        error: &str,
    ) -> Result<u64, sqlx::Error> {
        let next_retry =
            Utc::now() + chrono::Duration::seconds(delay_secs.max(0));
        let res = sqlx::query(
            "UPDATE delivery_queue \
             SET attempts = attempts + 1, next_retry = ?1, last_error = ?2 \
             WHERE id = ?3",
        )
        .bind(next_retry)
        .bind(error)
        .bind(queue_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn load_activity(
        &self,
        activity_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT activity FROM outbox WHERE id = ?1")
                .bind(activity_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(s,)| serde_json::from_str(&s).ok()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh() -> Store {
        Store::in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn followers_roundtrip() {
        let s = fresh().await;
        s.add_follower("me", "them", Some("https://them/inbox"))
            .await
            .unwrap();
        assert!(s.is_follower("me", "them").await.unwrap());
        assert_eq!(s.follower_count("me").await.unwrap(), 1);
        let inboxes = s.follower_inboxes("me").await.unwrap();
        assert_eq!(inboxes, vec!["https://them/inbox".to_string()]);
        s.remove_follower("me", "them").await.unwrap();
        assert!(!s.is_follower("me", "them").await.unwrap());
    }

    #[tokio::test]
    async fn following_lifecycle() {
        let s = fresh().await;
        s.add_following("me", "https://other/actor").await.unwrap();
        assert!(!s.is_following("me", "https://other/actor").await.unwrap());
        s.accept_following("me", "https://other/actor")
            .await
            .unwrap();
        assert!(s.is_following("me", "https://other/actor").await.unwrap());
    }

    #[tokio::test]
    async fn inbox_insert_is_idempotent_by_id() {
        let s = fresh().await;
        let act = serde_json::json!({"id": "https://a/1", "type": "Create"});
        assert!(s.record_inbox("me", &act).await.unwrap());
        assert!(!s.record_inbox("me", &act).await.unwrap());
        assert_eq!(s.inbox_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn outbox_records_and_updates_state() {
        let s = fresh().await;
        let act = serde_json::json!({"id": "https://me/out/1", "type": "Create"});
        let id = s.record_outbox("me", &act).await.unwrap();
        assert_eq!(id, "https://me/out/1");
        assert_eq!(s.outbox_count().await.unwrap(), 1);
        let updated = s.mark_outbox_state(&id, "delivered").await.unwrap();
        assert_eq!(updated, 1);
    }

    #[tokio::test]
    async fn delivery_queue_roundtrip() {
        let s = fresh().await;
        let qid = s
            .enqueue_delivery("https://me/out/1", "https://them/inbox")
            .await
            .unwrap();
        let item = s.next_due_delivery().await.unwrap().unwrap();
        assert_eq!(item.queue_id, qid);
        assert_eq!(item.inbox_url, "https://them/inbox");
        s.reschedule_delivery(qid, 0, "transient").await.unwrap();
        let again = s.next_due_delivery().await.unwrap().unwrap();
        assert_eq!(again.attempts, 1);
        assert_eq!(again.last_error.as_deref(), Some("transient"));
        s.drop_delivery(qid).await.unwrap();
        assert!(s.next_due_delivery().await.unwrap().is_none());
    }
}
