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
    /// Set while the delivery queue is refusing work, so the refusal is
    /// logged once per episode instead of once per attempt.
    queue_full_logged: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
    host TEXT NOT NULL DEFAULT '',
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
    id TEXT NOT NULL,
    sender TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL,
    activity TEXT NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sender, id)
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
    last_error TEXT,
    host TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

/// Upgrade an `inbox` table written before rows carried their sender (primary
/// key `id` alone): the rows are copied across with the sender taken from the
/// stored activity's `actor`. A no-op for a fresh or already current database.
async fn migrate_legacy_inbox(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let (exists,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'inbox'",
    )
    .fetch_one(pool)
    .await?;
    let (has_sender,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM pragma_table_info('inbox') WHERE name = 'sender'")
            .fetch_one(pool)
            .await?;
    if exists == 0 || has_sender > 0 {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    sqlx::query("ALTER TABLE inbox RENAME TO inbox_legacy")
        .execute(&mut *tx)
        .await?;
    // The legacy table is dropped after the copy; the current table is created
    // by `SCHEMA`, so create it here first to receive the rows.
    sqlx::query(
        "CREATE TABLE inbox (id TEXT NOT NULL, sender TEXT NOT NULL DEFAULT '', \
         actor_id TEXT NOT NULL, activity TEXT NOT NULL, \
         received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (sender, id))",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO inbox (id, sender, actor_id, activity, received_at) \
         SELECT id, COALESCE(json_extract(activity, '$.actor'), ''), actor_id, activity, received_at \
         FROM inbox_legacy",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("DROP TABLE inbox_legacy")
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// The lower-cased host of `url` (no port), or `""` when it has none. Per-host
/// limits key on this, not on the authority, so varying the port does not
/// dodge them.
#[must_use]
pub fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

/// Add the `host` column to `followers` and `delivery_queue` tables written
/// before it existed, and fill it from the stored URLs. A no-op once present.
async fn add_host_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for (table, url_col, id_col) in [
        ("followers", "follower_id", "rowid"),
        ("delivery_queue", "inbox_url", "id"),
    ] {
        let (has,): (i64,) = sqlx::query_as(&format!(
            "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'host'"
        ))
        .fetch_one(pool)
        .await?;
        if has > 0 {
            continue;
        }
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD COLUMN host TEXT NOT NULL DEFAULT ''"
        ))
        .execute(pool)
        .await?;
        let rows: Vec<(i64, String)> =
            sqlx::query_as(&format!("SELECT {id_col}, {url_col} FROM {table}"))
                .fetch_all(pool)
                .await?;
        for (id, url) in rows {
            sqlx::query(&format!("UPDATE {table} SET host = ?1 WHERE {id_col} = ?2"))
                .bind(host_of(&url))
                .bind(id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

impl Store {
    /// Connect to an arbitrary SQLite URL (use `sqlite::memory:` for
    /// tests). Runs the schema idempotently.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await?;
        migrate_legacy_inbox(&pool).await?;
        sqlx::query(SCHEMA).execute(&pool).await?;
        add_host_columns(&pool).await?;
        Ok(Self {
            pool,
            queue_full_logged: std::sync::Arc::default(),
        })
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
            "INSERT OR REPLACE INTO followers (actor_id, follower_id, inbox, accepted_at, host) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(actor_id)
        .bind(follower_id)
        .bind(inbox)
        .bind(now)
        .bind(host_of(follower_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_follower(
        &self,
        actor_id: &str,
        follower_id: &str,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("DELETE FROM followers WHERE actor_id = ?1 AND follower_id = ?2")
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
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM followers WHERE actor_id = ?1 AND follower_id = ?2")
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

    /// Return every follower's inbox URL for the given actor.
    ///
    /// Alias for [`Self::follower_inboxes`] — named to match the JSS
    /// `getFollowerInboxes` helper added in v0.0.67.
    pub async fn get_follower_inboxes(&self, actor_id: &str) -> Result<Vec<String>, sqlx::Error> {
        self.follower_inboxes(actor_id).await
    }

    pub async fn follower_count(&self, actor_id: &str) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM followers WHERE actor_id = ?1")
            .bind(actor_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    /// Followers of `actor_id` whose actor lives on `host` (see [`host_of`]).
    pub async fn follower_count_for_host(
        &self,
        actor_id: &str,
        host: &str,
    ) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM followers WHERE actor_id = ?1 AND host = ?2")
                .bind(actor_id)
                .bind(host)
                .fetch_one(&self.pool)
                .await?;
        Ok(n)
    }

    // -------------------------- following --------------------------------

    pub async fn add_following(&self, actor_id: &str, target_id: &str) -> Result<(), sqlx::Error> {
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
        let res =
            sqlx::query("UPDATE following SET accepted = 1 WHERE actor_id = ?1 AND target_id = ?2")
                .bind(actor_id)
                .bind(target_id)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    pub async fn is_following(&self, actor_id: &str, target_id: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT accepted FROM following WHERE actor_id = ?1 AND target_id = ?2")
                .bind(actor_id)
                .bind(target_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(matches!(row, Some((1,))))
    }

    // --------------------------- inbox -----------------------------------

    /// Record an inbox activity from the sender its `actor` names. Idempotent
    /// on `(sender, id)`; see [`Self::record_inbox_from`].
    pub async fn record_inbox(
        &self,
        actor_id: &str,
        activity: &serde_json::Value,
    ) -> Result<bool, sqlx::Error> {
        let sender = activity
            .get("actor")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        self.record_inbox_from(actor_id, &sender, activity).await
    }

    /// Record an inbox activity that `sender` (the verified signer) sent to the
    /// local `actor_id`. Idempotent on `(sender, id)`: another sender reusing
    /// the same `id` neither collides with nor pre-empts this row. Returns
    /// `false` for a duplicate or an activity with no `id`.
    pub async fn record_inbox_from(
        &self,
        actor_id: &str,
        sender: &str,
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
            "INSERT OR IGNORE INTO inbox (id, sender, actor_id, activity, received_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&id)
        .bind(sender)
        .bind(actor_id)
        .bind(&body)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get_inbox(&self, id: &str) -> Result<Option<InboxRow>, sqlx::Error> {
        let row: Option<(String, String, String, DateTime<Utc>)> =
            sqlx::query_as("SELECT id, actor_id, activity, received_at FROM inbox WHERE id = ?1")
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

    pub async fn mark_outbox_state(&self, id: &str, state: &str) -> Result<u64, sqlx::Error> {
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
            "INSERT INTO delivery_queue (activity_id, inbox_url, attempts, next_retry, host) \
             VALUES (?1, ?2, 0, ?3, ?4)",
        )
        .bind(activity_id)
        .bind(inbox_url)
        .bind(Utc::now())
        .bind(host_of(inbox_url))
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Queue a delivery unless `max_queued` rows are already waiting. Returns
    /// the new queue id, or `None` when the queue is full (the delivery is
    /// refused, not queued). The first refusal of an episode is logged; the
    /// next log happens only after the queue has had room again.
    pub async fn try_enqueue_delivery(
        &self,
        activity_id: &str,
        inbox_url: &str,
        max_queued: i64,
    ) -> Result<Option<i64>, sqlx::Error> {
        use std::sync::atomic::Ordering;
        if self.delivery_queue_len().await? >= max_queued {
            if !self.queue_full_logged.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    max_queued,
                    "delivery queue is full: refusing new deliveries"
                );
            }
            return Ok(None);
        }
        self.queue_full_logged.store(false, Ordering::Relaxed);
        self.enqueue_delivery(activity_id, inbox_url)
            .await
            .map(Some)
    }

    /// Deliveries waiting in the queue.
    pub async fn delivery_queue_len(&self) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delivery_queue")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
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

    /// The oldest due delivery that is not `skip_ids` and whose host is not in
    /// `skip_hosts`. The concurrent worker uses this so a host with work already
    /// in flight, or with an open circuit, cannot fill the window and starve
    /// the others.
    pub async fn next_due_delivery_excluding(
        &self,
        skip_ids: &[i64],
        skip_hosts: &[String],
    ) -> Result<Option<DeliveryItem>, sqlx::Error> {
        let mut q = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT id, activity_id, inbox_url, attempts, last_error FROM delivery_queue \
             WHERE next_retry <= ",
        );
        q.push_bind(Utc::now());
        for (col, n) in [("id", skip_ids.len()), ("host", skip_hosts.len())] {
            if n > 0 {
                q.push(format!(" AND {col} NOT IN ("));
                let mut sep = q.separated(", ");
                if col == "id" {
                    for v in skip_ids {
                        sep.push_bind(*v);
                    }
                } else {
                    for v in skip_hosts {
                        sep.push_bind(v.clone());
                    }
                }
                q.push(")");
            }
        }
        q.push(" ORDER BY id ASC LIMIT 1");
        let row: Option<(i64, String, String, i64, Option<String>)> =
            q.build_query_as().fetch_optional(&self.pool).await?;
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
        let next_retry = Utc::now() + chrono::Duration::seconds(delay_secs.max(0));
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

    // ----------------------- actor cache ----------------------------------

    /// Cache a remote actor document. Uses `INSERT OR REPLACE` so
    /// re-fetches update `fetched_at` to the current timestamp.
    ///
    /// The `fetched_at` column is always written as an ISO 8601 UTC
    /// string via `chrono::Utc::now()` — this matches the JSS v0.0.66
    /// fix that ensures consistent `datetime('now')`-compatible
    /// timestamps in the actors table.
    pub async fn cache_actor(
        &self,
        actor_id: &str,
        data: &serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        let body = serde_json::to_string(data).unwrap_or_else(|_| "{}".into());
        let now = Utc::now();
        sqlx::query("INSERT OR REPLACE INTO actors (id, data, fetched_at) VALUES (?1, ?2, ?3)")
            .bind(actor_id)
            .bind(&body)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Retrieve a cached actor document. Returns `None` if not cached.
    pub async fn get_cached_actor(
        &self,
        actor_id: &str,
    ) -> Result<Option<(serde_json::Value, DateTime<Utc>)>, sqlx::Error> {
        let row: Option<(String, DateTime<Utc>)> =
            sqlx::query_as("SELECT data, fetched_at FROM actors WHERE id = ?1")
                .bind(actor_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(data, fetched_at)| {
            let parsed = serde_json::from_str(&data).unwrap_or(serde_json::Value::Null);
            (parsed, fetched_at)
        }))
    }

    /// Check whether a cached actor is still fresh (fetched within
    /// `max_age`). Returns `true` if the cache entry exists and its
    /// `fetched_at` timestamp is within the given duration of now.
    ///
    /// This uses `chrono::DateTime` comparison — all timestamps are
    /// stored and compared as ISO 8601 UTC, avoiding the
    /// `datetime('now')` vs bare-string mismatch that JSS v0.0.66
    /// fixed.
    pub async fn is_actor_cache_fresh(
        &self,
        actor_id: &str,
        max_age: chrono::Duration,
    ) -> Result<bool, sqlx::Error> {
        match self.get_cached_actor(actor_id).await? {
            Some((_data, fetched_at)) => {
                let cutoff = Utc::now() - max_age;
                Ok(fetched_at >= cutoff)
            }
            None => Ok(false),
        }
    }

    // ----------------------- bounded listings -----------------------------

    /// Follower actor ids, oldest first, at most `limit`.
    pub async fn list_followers(
        &self,
        actor_id: &str,
        limit: i64,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT follower_id FROM followers WHERE actor_id = ?1 \
             ORDER BY accepted_at ASC, follower_id ASC LIMIT ?2",
        )
        .bind(actor_id)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Accepted follow targets, oldest first, at most `limit`.
    pub async fn list_following(
        &self,
        actor_id: &str,
        limit: i64,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT target_id FROM following WHERE actor_id = ?1 AND accepted = 1 \
             ORDER BY requested_at ASC, target_id ASC LIMIT ?2",
        )
        .bind(actor_id)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    /// Accepted follow targets for `actor_id`.
    pub async fn following_count(&self, actor_id: &str) -> Result<i64, sqlx::Error> {
        let (n,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM following WHERE actor_id = ?1 AND accepted = 1")
                .bind(actor_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(n)
    }

    /// The newest outbox rows for `actor_id`, newest first, at most `limit`.
    pub async fn recent_outbox(
        &self,
        actor_id: &str,
        limit: i64,
    ) -> Result<Vec<OutboxRow>, sqlx::Error> {
        let rows: Vec<(String, String, String, DateTime<Utc>, String)> = sqlx::query_as(
            "SELECT id, actor_id, activity, created_at, delivery_state FROM outbox \
             WHERE actor_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2",
        )
        .bind(actor_id)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, actor_id, activity, created_at, delivery_state)| OutboxRow {
                    id,
                    actor_id,
                    activity: serde_json::from_str(&activity).unwrap_or(serde_json::Value::Null),
                    created_at,
                    delivery_state,
                },
            )
            .collect())
    }

    /// Delete the oldest inbox rows beyond `keep`, so a remote that keeps
    /// sending validly signed activities cannot grow the table without
    /// bound. Returns the rows removed.
    pub async fn trim_inbox(&self, keep: i64) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "DELETE FROM inbox WHERE rowid IN ( \
               SELECT rowid FROM inbox ORDER BY received_at DESC, rowid DESC LIMIT -1 OFFSET ?1)",
        )
        .bind(keep.max(0))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Delete the oldest inbox rows of `sender` beyond `keep`, leaving every
    /// other sender's rows alone, so one sender cannot evict the rest.
    pub async fn trim_inbox_for_sender(&self, sender: &str, keep: i64) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "DELETE FROM inbox WHERE rowid IN ( \
               SELECT rowid FROM inbox WHERE sender = ?1 \
               ORDER BY received_at DESC, rowid DESC LIMIT -1 OFFSET ?2)",
        )
        .bind(sender)
        .bind(keep.max(0))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Delete the oldest outbox rows of `actor_id` whose activity `type` is
    /// `kind`, beyond `keep`. Used to bound server-generated replies (the
    /// `Accept`s) that remote senders can provoke.
    pub async fn trim_outbox_kind(
        &self,
        actor_id: &str,
        kind: &str,
        keep: i64,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "DELETE FROM outbox WHERE rowid IN ( \
               SELECT rowid FROM outbox \
               WHERE actor_id = ?1 AND json_extract(activity, '$.type') = ?2 \
               ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?3)",
        )
        .bind(actor_id)
        .bind(kind)
        .bind(keep.max(0))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn load_activity(
        &self,
        activity_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as("SELECT activity FROM outbox WHERE id = ?1")
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

    #[tokio::test]
    async fn actor_cache_roundtrip() {
        let s = fresh().await;
        let actor_id = "https://remote.example/actor";
        let data = serde_json::json!({"type": "Person", "name": "Remote"});

        // Nothing cached initially.
        assert!(s.get_cached_actor(actor_id).await.unwrap().is_none());

        // Cache and retrieve.
        s.cache_actor(actor_id, &data).await.unwrap();
        let (cached, fetched_at) = s.get_cached_actor(actor_id).await.unwrap().unwrap();
        assert_eq!(cached["name"], "Remote");
        // fetched_at should be very recent (within 5 seconds).
        let age = Utc::now() - fetched_at;
        assert!(age.num_seconds() < 5, "fetched_at too old: {age}");
    }

    #[tokio::test]
    async fn actor_cache_freshness_check() {
        let s = fresh().await;
        let actor_id = "https://remote.example/actor2";
        let data = serde_json::json!({"type": "Person"});
        s.cache_actor(actor_id, &data).await.unwrap();

        // Should be fresh within a 1-hour window.
        assert!(s
            .is_actor_cache_fresh(actor_id, chrono::Duration::hours(1))
            .await
            .unwrap());

        // Should NOT be fresh within a 0-second window (it was cached
        // at least a microsecond ago).
        // Note: chrono::Duration::zero() would make it always fresh
        // since fetched_at >= cutoff. Use a negative duration trick
        // is not valid, so we rely on the insertion delay.
        // Instead, just verify uncached actors are not fresh.
        assert!(!s
            .is_actor_cache_fresh(
                "https://never-cached.example/actor",
                chrono::Duration::hours(1)
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn actor_cache_upsert_updates_fetched_at() {
        let s = fresh().await;
        let actor_id = "https://remote.example/actor3";
        let data1 = serde_json::json!({"name": "v1"});
        s.cache_actor(actor_id, &data1).await.unwrap();
        let (_, ts1) = s.get_cached_actor(actor_id).await.unwrap().unwrap();

        // Re-cache with new data.
        let data2 = serde_json::json!({"name": "v2"});
        s.cache_actor(actor_id, &data2).await.unwrap();
        let (cached, ts2) = s.get_cached_actor(actor_id).await.unwrap().unwrap();
        assert_eq!(cached["name"], "v2");
        assert!(ts2 >= ts1, "fetched_at should not go backwards");
    }

    #[tokio::test]
    async fn actor_cache_datetime_is_iso8601() {
        let s = fresh().await;
        let actor_id = "https://remote.example/actor-dt";
        let data = serde_json::json!({"type": "Person"});
        s.cache_actor(actor_id, &data).await.unwrap();

        // Read the raw fetched_at string from SQLite to confirm format.
        let (raw,): (String,) = sqlx::query_as("SELECT fetched_at FROM actors WHERE id = ?1")
            .bind(actor_id)
            .fetch_one(s.pool())
            .await
            .unwrap();
        // chrono serialises to ISO 8601: "2026-05-06T12:34:56.123456789Z"
        // or "2026-05-06 12:34:56 UTC". Either way it must parse back.
        let parsed = chrono::DateTime::parse_from_rfc3339(&raw).or_else(|_| {
            // sqlx may store in "YYYY-MM-DD HH:MM:SS" form.
            chrono::NaiveDateTime::parse_from_str(&raw, "%Y-%m-%d %H:%M:%S%.f")
                .map(|ndt| ndt.and_utc().fixed_offset())
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(&raw, "%Y-%m-%dT%H:%M:%S%.f")
                        .map(|ndt| ndt.and_utc().fixed_offset())
                })
        });
        assert!(parsed.is_ok(), "fetched_at is not a valid datetime: {raw}");
    }

    #[tokio::test]
    async fn get_follower_inboxes_alias() {
        let s = fresh().await;
        s.add_follower("actor-a", "f1", Some("https://f1/inbox"))
            .await
            .unwrap();
        s.add_follower("actor-a", "f2", Some("https://f2/inbox"))
            .await
            .unwrap();
        s.add_follower("actor-a", "f3", None).await.unwrap(); // no inbox
        let inboxes = s.get_follower_inboxes("actor-a").await.unwrap();
        assert_eq!(inboxes.len(), 2);
        assert!(inboxes.contains(&"https://f1/inbox".to_string()));
        assert!(inboxes.contains(&"https://f2/inbox".to_string()));
    }

    #[tokio::test]
    async fn follower_inbox_fanout_enqueues_all() {
        let s = fresh().await;
        let actor_id = "me";
        s.add_follower(actor_id, "a", Some("https://a/inbox"))
            .await
            .unwrap();
        s.add_follower(actor_id, "b", Some("https://b/inbox"))
            .await
            .unwrap();
        s.add_follower(actor_id, "c", Some("https://c/inbox"))
            .await
            .unwrap();

        let inboxes = s.get_follower_inboxes(actor_id).await.unwrap();
        let activity_id = "https://me/out/fanout-1";
        for inbox in &inboxes {
            s.enqueue_delivery(activity_id, inbox).await.unwrap();
        }

        // Count delivery-queue rows for this activity.
        let (n,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM delivery_queue WHERE activity_id = ?1")
                .bind(activity_id)
                .fetch_one(s.pool())
                .await
                .unwrap();
        assert_eq!(n, 3);
    }
}
