//! Embedded per-site metadata store (SQLite via rusqlite).
//!
//! Each site owns a local SQLite file; cross-site convergence is an LWW fact
//! log layered on top.
//!
//! Every mutating row carries an `updated_at` micros timestamp from the cluster
//! clock. Writes are last-write-wins: an incoming write only wins if its
//! timestamp is newer than what is stored. This is the same ordering Scylla's
//! `USING TIMESTAMP` gave us, made explicit so the replication log (Phase 2) can
//! merge peer facts with identical semantics.
//!
//! rusqlite is synchronous; the methods stay `async` to remain a drop-in for the
//! old `Db`, doing their (fast, local) work under a single connection mutex. For
//! an embedded store this is fine — there is no network round-trip to
//! overlap.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::clock::ClusterClock;
use crate::db::{Policy, ReplicationEntry, REPLICATION_STUCK_ATTEMPTS};
use crate::hashing::prefix_key_range;

// Replication retry backoff: 1 minute base, doubling per attempt, capped at 6h.
// (Mirrors the old db.rs schedule; reimplemented here so store.rs stands alone.)
const REPLICATION_BACKOFF_BASE_MS: i64 = 60_000;
const REPLICATION_BACKOFF_CAP_MS: i64 = 6 * 60 * 60 * 1000;
const REPLICATION_DRAIN_PAGE: i64 = 500;

fn replication_backoff_ms(attempts: i32) -> i64 {
    if attempts <= 0 {
        return REPLICATION_BACKOFF_BASE_MS;
    }
    let shift = attempts.min(40) as u32;
    REPLICATION_BACKOFF_BASE_MS
        .checked_shl(shift)
        .unwrap_or(REPLICATION_BACKOFF_CAP_MS)
        .min(REPLICATION_BACKOFF_CAP_MS)
}

/// One replicated metadata mutation. Every variant is a non-conflicting CRDT
/// operation resolved by the accompanying `ts` (last-write-wins): object manifests
/// and the user table are LWW registers, block announcements are a grow-only set,
/// and deletes are LWW tombstones. There is no operation here that two sites can
/// "disagree" about — that is the whole reason this is a fact log and not a
/// consensus log. Hashes/fids travel hex-encoded so the payload is plain JSON.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", content = "data")]
pub enum Fact {
    ObjectPut {
        bucket: String,
        key: String,
        blocks: Vec<String>, // hex block hashes, in order
        size: i64,
        etag: String,
    },
    ObjectDelete {
        bucket: String,
        key: String,
    },
    BlockAnnounce {
        hash: String, // hex
        location_id: String,
        fid: String, // hex-encoded fid bytes
        size: i64,
    },
    UserPut {
        access_key: String,
        secret_key: String,
        policy: serde_json::Value,
    },
}

impl Fact {
    fn kind_str(&self) -> &'static str {
        match self {
            Fact::ObjectPut { .. } => "object_put",
            Fact::ObjectDelete { .. } => "object_delete",
            Fact::BlockAnnounce { .. } => "block_announce",
            Fact::UserPut { .. } => "user_put",
        }
    }
}

/// A fact as served to peers: its origin-local sequence number, its LWW timestamp,
/// and the fact itself. Peers track the high-water `seq` they've consumed per peer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FactRecord {
    pub seq: i64,
    pub ts: i64,
    #[serde(flatten)]
    pub fact: Fact,
}

/// Local health snapshot for `shardscape status`.
pub struct StoreStats {
    pub live_objects: i64,
    pub local_blocks: i64,
    pub local_block_bytes: i64,
    pub pending_deletions: i64,
    pub pending_pulls: i64,
    pub fact_count: i64,
}

/// Embedded metadata store. Cloneable (shares one connection behind a mutex).
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    pub local_location_id: String,
    pub clock: Arc<ClusterClock>,
}

impl Store {
    /// Opens (and migrates) the SQLite store at `path`. Use `:memory:` for tests.
    pub async fn new(
        path: impl AsRef<Path>,
        local_location_id: String,
        clock: Arc<ClusterClock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("Opening embedded metadata store at {}", path.display());
        let conn = if path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        // WAL: concurrent readers alongside the single writer, and durable across
        // crashes. NORMAL sync is the standard WAL pairing — fsync at checkpoint,
        // not every commit. Foreign keys on for referential cleanup.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            local_location_id,
            clock,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            -- Object manifests. The namespace; LWW by updated_at. shard_id is kept
            -- for parity with callers but listing no longer needs it (one ordered
            -- index over (bucket, key) replaces the 64-shard k-way merge).
            CREATE TABLE IF NOT EXISTS objects (
                bucket     TEXT NOT NULL,
                key        TEXT NOT NULL,
                blocks     BLOB NOT NULL,   -- concat of 32-byte block hashes
                size       INTEGER NOT NULL,
                etag       TEXT NOT NULL,
                shard_id   INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                -- LWW tombstone: a delete keeps the row (deleted=1) with its ts so
                -- a late-arriving older put can't resurrect it. GC purges old
                -- tombstones later. Reads/lists filter deleted=0.
                deleted    INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (bucket, key)
            );

            -- Block metadata: size + per-block LWW timestamp.
            CREATE TABLE IF NOT EXISTS blocks (
                hash       BLOB PRIMARY KEY,
                size       INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- Where each block physically lives: one row per (block, site).
            CREATE TABLE IF NOT EXISTS block_locations (
                hash        BLOB NOT NULL,
                location_id TEXT NOT NULL,
                fid         BLOB NOT NULL,
                updated_at  INTEGER NOT NULL,
                PRIMARY KEY (hash, location_id)
            );

            -- GC sweep state: blocks observed orphaned (not in the live set),
            -- with the earliest time they may be physically reaped. Derived from
            -- the manifests by the mark-and-sweep reaper, not a refcount.
            CREATE TABLE IF NOT EXISTS pending_deletions (
                hash       BLOB PRIMARY KEY,
                not_before INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                access_key TEXT PRIMARY KEY,
                secret_key TEXT NOT NULL,
                policy     TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS multipart_uploads (
                bucket    TEXT NOT NULL,
                upload_id TEXT NOT NULL,
                key       TEXT NOT NULL,
                PRIMARY KEY (bucket, upload_id)
            );

            CREATE TABLE IF NOT EXISTS parts (
                bucket      TEXT NOT NULL,
                upload_id   TEXT NOT NULL,
                part_number INTEGER NOT NULL,
                blocks      BLOB NOT NULL,
                size        INTEGER NOT NULL,
                etag        TEXT NOT NULL,
                PRIMARY KEY (bucket, upload_id, part_number)
            );

            CREATE TABLE IF NOT EXISTS nodes (
                location_id    TEXT PRIMARY KEY,
                api_url        TEXT NOT NULL,
                last_heartbeat INTEGER NOT NULL
            );

            -- Pending block replication to a peer site. One row per (target, hash);
            -- next_attempt_at drives backoff ordering, attempts drives the schedule.
            CREATE TABLE IF NOT EXISTS replication_queue (
                target_location_id TEXT NOT NULL,
                hash               BLOB NOT NULL,
                next_attempt_at    INTEGER NOT NULL,
                attempts           INTEGER NOT NULL,
                enqueued_at        INTEGER NOT NULL,
                PRIMARY KEY (target_location_id, hash)
            );
            CREATE INDEX IF NOT EXISTS replication_queue_ready
                ON replication_queue (target_location_id, next_attempt_at);

            -- The LWW fact log: this site's OWN-originated metadata mutations, in
            -- order. Peers pull facts after a cursor and apply them with LWW merge
            -- (they do NOT re-log applied facts — every site pulls from every other
            -- site directly, so a small mesh converges without gossip fan-out).
            CREATE TABLE IF NOT EXISTS fact_log (
                seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      INTEGER NOT NULL,   -- cluster-clock micros; the LWW timestamp
                kind    TEXT NOT NULL,
                payload TEXT NOT NULL       -- JSON, kind-specific
            );

            -- How far we have consumed each peer's fact_log (by their seq).
            CREATE TABLE IF NOT EXISTS replication_cursors (
                peer_location_id TEXT PRIMARY KEY,
                last_seq         INTEGER NOT NULL
            );
            "#,
        )?;
        // Best-effort migrations for stores created before these columns existed.
        // Pre-release, so a duplicate-column error just means we're already current.
        let _ = conn.execute("ALTER TABLE objects ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0", []);
        let _ = conn.execute("ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0", []);
        Ok(())
    }

    fn now_micros(&self) -> i64 {
        self.clock.now_micros()
    }

    fn now_millis(&self) -> i64 {
        self.now_micros() / 1000
    }

    // ── block hash list (de)serialization ────────────────────────────────────
    // A manifest is an ordered list of 32-byte block hashes. We store it as the
    // raw concatenation: every block hash is exactly blake3's 32 bytes, so the
    // list splits cleanly without a length prefix. Robust to a stray non-32
    // multiple (truncates the tail) rather than panicking.

    fn encode_blocks(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::with_capacity(blocks.len() * 32);
        for b in blocks {
            out.extend_from_slice(b);
        }
        out
    }

    fn decode_blocks(raw: &[u8]) -> Vec<Vec<u8>> {
        raw.chunks_exact(32).map(|c| c.to_vec()).collect()
    }

    // ── blocks ───────────────────────────────────────────────────────────────

    pub async fn get_block_fids(&self, hash: &[u8]) -> Result<Option<HashMap<String, Vec<u8>>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT location_id, fid FROM block_locations WHERE hash = ?1")?;
        let rows = stmt.query_map(params![hash], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (loc, fid) = row?;
            map.insert(loc, fid);
        }
        Ok(if map.is_empty() { None } else { Some(map) })
    }

    /// Metadata sizes for a list of block hashes, in the same order. Missing rows
    /// yield 0. Lets the GET path resolve a Range to block boundaries without
    /// fetching any block bodies.
    pub async fn block_sizes(&self, hashes: &[Vec<u8>]) -> Result<Vec<i64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT size FROM blocks WHERE hash = ?1")?;
        let mut out = Vec::with_capacity(hashes.len());
        for h in hashes {
            let size: i64 = stmt
                .query_row(params![h], |r| r.get(0))
                .optional()?
                .unwrap_or(0);
            out.push(size);
        }
        Ok(out)
    }

    pub async fn get_local_block_fid(&self, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let fid = conn
            .query_row(
                "SELECT fid FROM block_locations WHERE hash = ?1 AND location_id = ?2",
                params![hash, self.local_location_id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(fid)
    }

    /// Upserts the block + this site's location. LWW: only advances on a newer ts.
    fn upsert_block_location(
        conn: &Connection,
        hash: &[u8],
        location_id: &str,
        fid: &[u8],
        size: i64,
        ts: i64,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO blocks (hash, size, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(hash) DO UPDATE SET size = excluded.size, updated_at = excluded.updated_at
             WHERE excluded.updated_at > blocks.updated_at",
            params![hash, size, ts],
        )?;
        conn.execute(
            "INSERT INTO block_locations (hash, location_id, fid, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(hash, location_id) DO UPDATE SET fid = excluded.fid, updated_at = excluded.updated_at
             WHERE excluded.updated_at > block_locations.updated_at",
            params![hash, location_id, fid, ts],
        )?;
        Ok(())
    }

    #[allow(dead_code)] // API symmetry; store_local_block is the hot path
    pub async fn insert_block(&self, hash: &[u8], fid: &[u8], size: i64) -> Result<()> {
        let ts = self.now_micros();
        let conn = self.conn.lock().unwrap();
        Self::upsert_block_location(&conn, hash, &self.local_location_id, fid, size, ts)
    }

    /// Appends a fact to this site's own fact_log within an existing transaction.
    fn append_fact_tx(conn: &Connection, ts: i64, fact: &Fact) -> Result<()> {
        let payload = serde_json::to_string(fact)?;
        conn.execute(
            "INSERT INTO fact_log (ts, kind, payload) VALUES (?1, ?2, ?3)",
            params![ts, fact.kind_str(), payload],
        )?;
        Ok(())
    }

    /// Records a block now held locally and announces it to the cluster via the
    /// fact log. Atomic in one local transaction — no batchlog, no availability
    /// cost. Peers learn the block's location by replaying the announce; each
    /// peer then decides for itself whether to pull a copy (see `apply_fact`).
    pub async fn store_local_block(&self, hash: &[u8], fid: &[u8], size: i64) -> Result<()> {
        let ts = self.now_micros();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        Self::upsert_block_location(&tx, hash, &self.local_location_id, fid, size, ts)?;
        Self::append_fact_tx(
            &tx,
            ts,
            &Fact::BlockAnnounce {
                hash: hex::encode(hash),
                location_id: self.local_location_id.clone(),
                fid: hex::encode(fid),
                size,
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    #[allow(dead_code)] // store_local_block is the live path; kept for direct location upserts
    pub async fn add_block_location(&self, hash: &[u8], location_id: &str, fid: &[u8]) -> Result<()> {
        let ts = self.now_micros();
        let conn = self.conn.lock().unwrap();
        // size unknown here; preserve any existing size, else 0. The block row is
        // created by whoever first knows the size; a location-only announce keeps
        // it untouched if present.
        let size: i64 = conn
            .query_row("SELECT size FROM blocks WHERE hash = ?1", params![hash], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0);
        Self::upsert_block_location(&conn, hash, location_id, fid, size, ts)
    }

    // ── objects ──────────────────────────────────────────────────────────────

    /// Buckets are implicit (no bucket table), so we derive them from live
    /// objects and use the earliest object's `updated_at` (micros) as a stand-in
    /// creation date — anything is better than the epoch-0 that made every bucket
    /// display as 1969.
    pub async fn list_buckets(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT bucket, MIN(updated_at) FROM objects WHERE deleted = 0 \
             GROUP BY bucket ORDER BY bucket",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub async fn insert_object(
        &self,
        bucket: &str,
        shard_id: i32,
        key: &str,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<()> {
        let ts = self.now_micros();
        let encoded = Self::encode_blocks(&blocks);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        Self::put_object_row(&tx, bucket, key, &encoded, size, etag, shard_id, false, ts)?;
        Self::append_fact_tx(
            &tx,
            ts,
            &Fact::ObjectPut {
                bucket: bucket.to_string(),
                key: key.to_string(),
                blocks: blocks.iter().map(hex::encode).collect(),
                size,
                etag: etag.to_string(),
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// LWW upsert of one object row (no fact logged). `deleted` carries the
    /// tombstone flag; a row only advances when the incoming ts is newer, so a
    /// put and a delete race resolves to whichever has the later timestamp.
    #[allow(clippy::too_many_arguments)]
    fn put_object_row(
        conn: &Connection,
        bucket: &str,
        key: &str,
        encoded_blocks: &[u8],
        size: i64,
        etag: &str,
        shard_id: i32,
        deleted: bool,
        ts: i64,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO objects (bucket, key, blocks, size, etag, shard_id, updated_at, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(bucket, key) DO UPDATE SET
                blocks = excluded.blocks, size = excluded.size, etag = excluded.etag,
                shard_id = excluded.shard_id, updated_at = excluded.updated_at,
                deleted = excluded.deleted
             WHERE excluded.updated_at > objects.updated_at",
            params![bucket, key, encoded_blocks, size, etag, shard_id, ts, deleted as i64],
        )?;
        Ok(())
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<Vec<u8>>, i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT blocks, size, etag FROM objects
                 WHERE bucket = ?1 AND key = ?2 AND deleted = 0",
                params![bucket, key],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(raw, size, etag)| (Self::decode_blocks(&raw), size, etag)))
    }

    /// LWW delete: writes a tombstone (deleted=1) stamped with the current time
    /// and announces it, rather than removing the row. A concurrent older put
    /// then loses on timestamp instead of resurrecting the key. The block list is
    /// cleared — a tombstone references no blocks, freeing them for GC.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let ts = self.now_micros();
        let shard_id = crate::hashing::compute_shard_id(key);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        Self::put_object_row(&tx, bucket, key, &[], 0, "", shard_id, true, ts)?;
        Self::append_fact_tx(
            &tx,
            ts,
            &Fact::ObjectDelete {
                bucket: bucket.to_string(),
                key: key.to_string(),
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Globally-sorted, paginated listing. One ordered index over (bucket, key)
    /// — no sharding, no k-way merge. `is_truncated` over-reports rather than
    /// under-reports (a spurious empty trailing page beats data loss), matching
    /// the old contract: we fetch one extra row to detect more.
    pub async fn list_objects(
        &self,
        bucket: &str,
        after: Option<&str>,
        prefix: Option<&str>,
        page_size: usize,
    ) -> Result<(Vec<(String, i64, String)>, bool)> {
        let prefix_range: Option<(String, Option<String>)> = prefix.map(prefix_key_range);
        // Lower bound: the larger of `after` (exclusive) and the prefix lower
        // (inclusive). We use a single ">" query with a synthesized exclusive
        // lower bound, plus an optional "<" upper for the prefix.
        let limit = page_size as i64 + 1;

        let conn = self.conn.lock().unwrap();
        // Build the query by cases so bound params stay parameterized.
        let mut rows: Vec<(String, i64, String)> = Vec::new();
        {
            let lower = prefix_range.as_ref().map(|(l, _)| l.clone());
            let upper = prefix_range.as_ref().and_then(|(_, u)| u.clone());

            // Exclusive cursor: keys strictly greater than `after`. The prefix
            // lower bound is inclusive, so when there is no cursor we emulate
            // ">=" by passing a value that sorts just below it is unnecessary —
            // SQLite has no "key >= ?" mixing here, so handle inclusivity via the
            // query text.
            let mut sql = String::from(
                "SELECT key, size, etag FROM objects WHERE bucket = ?1 AND deleted = 0",
            );
            // params: 1=bucket, then appended in order.
            let mut idx = 2;
            let mut after_param = after.map(|s| s.to_string());
            // If there is a cursor, always exclusive ">". If no cursor but a
            // prefix lower bound, inclusive ">=".
            if after_param.is_some() {
                sql.push_str(&format!(" AND key > ?{idx}"));
                idx += 1;
            } else if let Some(l) = &lower {
                sql.push_str(&format!(" AND key >= ?{idx}"));
                after_param = Some(l.clone());
                idx += 1;
            }
            let mut upper_param: Option<String> = None;
            if let Some(u) = &upper {
                sql.push_str(&format!(" AND key < ?{idx}"));
                upper_param = Some(u.clone());
                idx += 1;
            }
            sql.push_str(&format!(" ORDER BY key ASC LIMIT ?{idx}"));

            let mut stmt = conn.prepare(&sql)?;
            // Assemble params dynamically.
            let mut p: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(bucket.to_string())];
            if let Some(a) = after_param {
                p.push(Box::new(a));
            }
            if let Some(u) = upper_param {
                p.push(Box::new(u));
            }
            p.push(Box::new(limit));
            let refs: Vec<&dyn rusqlite::ToSql> = p.iter().map(|b| b.as_ref()).collect();
            let mapped = stmt.query_map(refs.as_slice(), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in mapped {
                rows.push(row?);
            }
        }

        let is_truncated = rows.len() as i64 > page_size as i64;
        rows.truncate(page_size);
        Ok((rows, is_truncated))
    }

    // ── mark-and-sweep GC ────────────────────────────────────────────────────
    //
    // No delta refcounting. The set of *referenced* blocks is recomputed from the
    // manifests themselves (objects + in-progress multipart parts). Because
    // manifests replicate via the fact log, this live set is GLOBAL: a block
    // absent from it here is absent from every converged site's view too. The
    // grace period (which must exceed worst-case replication lag) closes the only
    // remaining gap — a manifest that references the block but hasn't arrived yet.
    // After grace, an orphan is genuinely unreferenced cluster-wide, which is what
    // makes deleting even a last copy safe (achieved structurally rather than
    // by a distributed refcount).

    /// The set of block hashes referenced by any live manifest: non-tombstoned
    /// objects plus all in-progress multipart parts. Recomputed each sweep.
    pub async fn compute_live_block_set(&self) -> Result<std::collections::HashSet<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut live = std::collections::HashSet::new();
        let mut stmt = conn.prepare("SELECT blocks FROM objects WHERE deleted = 0")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        for raw in rows {
            for h in Self::decode_blocks(&raw?) {
                live.insert(h);
            }
        }
        let mut stmt = conn.prepare("SELECT blocks FROM parts")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        for raw in rows {
            for h in Self::decode_blocks(&raw?) {
                live.insert(h);
            }
        }
        Ok(live)
    }

    /// Hashes of blocks physically held at this site.
    pub async fn list_local_block_hashes(&self) -> Result<Vec<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT hash FROM block_locations WHERE location_id = ?1")?;
        let rows = stmt.query_map(params![self.local_location_id], |r| r.get::<_, Vec<u8>>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub async fn add_pending_deletion(&self, hash: &[u8], not_before: SystemTime) -> Result<()> {
        let ms = not_before
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis() as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pending_deletions (hash, not_before) VALUES (?1, ?2)
             ON CONFLICT(hash) DO UPDATE SET not_before = excluded.not_before",
            params![hash, ms],
        )?;
        Ok(())
    }

    pub async fn get_pending_deletions(&self) -> Result<Vec<(Vec<u8>, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash, not_before FROM pending_deletions")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub async fn remove_pending_deletion(&self, hash: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_deletions WHERE hash = ?1", params![hash])?;
        Ok(())
    }

    /// Unconditionally removes this site's location entry for a block and, if no
    /// location entries remain anywhere, drops the block metadata row. The GC
    /// reaper is responsible for only calling this on a confirmed orphan (not in
    /// the live set, past grace); the store does not second-guess that decision.
    /// Returns true if a local entry was actually removed.
    pub async fn delete_local_block(&self, hash: &[u8]) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let removed = conn.execute(
            "DELETE FROM block_locations WHERE hash = ?1 AND location_id = ?2",
            params![hash, self.local_location_id],
        )?;
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM block_locations WHERE hash = ?1",
            params![hash],
            |r| r.get(0),
        )?;
        if remaining == 0 {
            conn.execute("DELETE FROM blocks WHERE hash = ?1", params![hash])?;
        }
        Ok(removed > 0)
    }

    // ── multipart ────────────────────────────────────────────────────────────

    /// Backs the `ObjectStore::create_multipart_upload` trait method.
    pub async fn insert_multipart(&self, bucket: &str, upload_id: Uuid, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO multipart_uploads (bucket, upload_id, key) VALUES (?1, ?2, ?3)
             ON CONFLICT(bucket, upload_id) DO UPDATE SET key = excluded.key",
            params![bucket, upload_id.to_string(), key],
        )?;
        Ok(())
    }

    /// Backs the `ObjectStore::get_multipart_upload_key` trait method.
    pub async fn get_multipart_key(&self, bucket: &str, upload_id: Uuid) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let key = conn
            .query_row(
                "SELECT key FROM multipart_uploads WHERE bucket = ?1 AND upload_id = ?2",
                params![bucket, upload_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(key)
    }

    pub async fn delete_multipart_upload(&self, bucket: &str, upload_id: Uuid) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM multipart_uploads WHERE bucket = ?1 AND upload_id = ?2",
            params![bucket, upload_id.to_string()],
        )?;
        conn.execute(
            "DELETE FROM parts WHERE bucket = ?1 AND upload_id = ?2",
            params![bucket, upload_id.to_string()],
        )?;
        Ok(())
    }

    pub async fn insert_part(
        &self,
        bucket: &str,
        upload_id: Uuid,
        part_number: i32,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<()> {
        let encoded = Self::encode_blocks(&blocks);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO parts (bucket, upload_id, part_number, blocks, size, etag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(bucket, upload_id, part_number) DO UPDATE SET
                blocks = excluded.blocks, size = excluded.size, etag = excluded.etag",
            params![bucket, upload_id.to_string(), part_number, encoded, size, etag],
        )?;
        Ok(())
    }

    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: Uuid,
    ) -> Result<Vec<(i32, Vec<Vec<u8>>, i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT part_number, blocks, size, etag FROM parts
             WHERE bucket = ?1 AND upload_id = ?2 ORDER BY part_number ASC",
        )?;
        let rows = stmt.query_map(params![bucket, upload_id.to_string()], |r| {
            Ok((
                r.get::<_, i32>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (n, raw, size, etag) = row?;
            out.push((n, Self::decode_blocks(&raw), size, etag));
        }
        Ok(out)
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        key_marker: Option<&str>,
        max_uploads: usize,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut query = String::from(
            "SELECT key, upload_id FROM multipart_uploads WHERE bucket = ?1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(bucket.to_string())];
        let mut idx = 2;

        if let Some(pfx) = prefix {
            query.push_str(&format!(" AND key LIKE ?{idx}"));
            param_values.push(Box::new(format!("{}%", pfx)));
            idx += 1;
        }
        if let Some(marker) = key_marker {
            query.push_str(&format!(" AND key > ?{idx}"));
            param_values.push(Box::new(marker.to_string()));
            idx += 1;
        }
        let _ = idx;
        query.push_str(" ORDER BY key ASC, upload_id ASC LIMIT ?");
        param_values.push(Box::new((max_uploads + 1) as i64));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    #[allow(dead_code)] // delete_multipart_upload cleans parts inline; kept standalone too
    pub async fn delete_parts(&self, bucket: &str, upload_id: Uuid) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM parts WHERE bucket = ?1 AND upload_id = ?2",
            params![bucket, upload_id.to_string()],
        )?;
        Ok(())
    }

    // ── nodes / peers ────────────────────────────────────────────────────────

    /// Records this node's own advertised internal address in the local registry.
    pub async fn register_node(&self, api_url: &str) -> Result<()> {
        let id = self.local_location_id.clone();
        self.upsert_node(&id, api_url).await
    }

    /// Records a peer's address (idempotent; ignores attempts to record self with
    /// a different address — self is owned by register_node). Used by the join
    /// handshake and the membership-gossip merge so the mesh discovers itself.
    pub async fn record_peer(&self, location_id: &str, api_url: &str) -> Result<()> {
        if location_id == self.local_location_id {
            return Ok(());
        }
        self.upsert_node(location_id, api_url).await
    }

    async fn upsert_node(&self, location_id: &str, api_url: &str) -> Result<()> {
        let now = self.now_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO nodes (location_id, api_url, last_heartbeat) VALUES (?1, ?2, ?3)
             ON CONFLICT(location_id) DO UPDATE SET api_url = excluded.api_url,
                last_heartbeat = excluded.last_heartbeat",
            params![location_id, api_url, now],
        )?;
        Ok(())
    }

    /// Every known node including self, as (location_id, api_url). Served to peers
    /// so membership gossips to convergence (a leaf learns other leaves via the
    /// node it joined).
    pub async fn all_nodes(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT location_id, api_url FROM nodes")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All known peers (excluding self) as (location_id, api_url).
    pub async fn get_peers(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .all_nodes()
            .await?
            .into_iter()
            .filter(|(id, _)| id != &self.local_location_id)
            .collect())
    }

    /// Known peers (excluding self) as location_id -> api_url. No liveness filter:
    /// in the per-site model peer liveness isn't tracked centrally, so we attempt
    /// all known peers and let connect failures / replication backoff handle the
    /// dead ones gracefully.
    pub async fn get_peers_with_urls(&self) -> Result<HashMap<String, String>> {
        Ok(self.get_peers().await?.into_iter().collect())
    }

    // ── replication queue ────────────────────────────────────────────────────

    pub async fn enqueue_replication(&self, hash: &[u8], target_ids: &[String]) -> Result<()> {
        let now_ms = self.now_millis();
        let conn = self.conn.lock().unwrap();
        for target in target_ids {
            conn.execute(
                "INSERT INTO replication_queue
                    (target_location_id, hash, next_attempt_at, attempts, enqueued_at)
                 VALUES (?1, ?2, 0, 0, ?3)
                 ON CONFLICT(target_location_id, hash) DO NOTHING",
                params![target, hash, now_ms],
            )?;
        }
        Ok(())
    }

    /// Ready/overdue entries for this site (next_attempt_at <= now), time-ordered.
    pub async fn get_replication_queue(&self) -> Result<Vec<ReplicationEntry>> {
        let now = self.now_millis();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hash, next_attempt_at, attempts, enqueued_at FROM replication_queue
             WHERE target_location_id = ?1 AND next_attempt_at <= ?2
             ORDER BY next_attempt_at ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![self.local_location_id, now, REPLICATION_DRAIN_PAGE],
            |r| {
                Ok(ReplicationEntry {
                    hash: r.get::<_, Vec<u8>>(0)?,
                    next_attempt_at: r.get::<_, i64>(1)?,
                    attempts: r.get::<_, i32>(2)?,
                    enqueued_at: r.get::<_, i64>(3)?,
                })
            },
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub async fn dequeue_replication(&self, hash: &[u8], _next_attempt_at: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM replication_queue WHERE target_location_id = ?1 AND hash = ?2",
            params![self.local_location_id, hash],
        )?;
        Ok(())
    }

    /// Reschedules a failed entry with exponential backoff (in place — no
    /// delete+reinsert dance, since SQLite gives us a real transaction).
    pub async fn defer_replication(&self, entry: &ReplicationEntry) -> Result<()> {
        let new_next = self.now_millis() + replication_backoff_ms(entry.attempts);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE replication_queue SET next_attempt_at = ?1, attempts = attempts + 1
             WHERE target_location_id = ?2 AND hash = ?3",
            params![new_next, self.local_location_id, entry.hash],
        )?;
        Ok(())
    }

    /// Blocks queued for this site that have failed >= REPLICATION_STUCK_ATTEMPTS.
    pub async fn get_stuck_replications(&self) -> Result<Vec<(Vec<u8>, i32, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hash, attempts, enqueued_at FROM replication_queue
             WHERE target_location_id = ?1 AND attempts >= ?2",
        )?;
        let rows = stmt.query_map(
            params![self.local_location_id, REPLICATION_STUCK_ATTEMPTS],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i32>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // ── fact log (LWW replication) ───────────────────────────────────────────

    /// This site's own-originated facts with `seq > after`, in order, bounded.
    /// Served to peers, who replay them into their own stores.
    pub async fn facts_since(&self, after: i64, limit: i64) -> Result<Vec<FactRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, ts, payload FROM fact_log WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![after, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, ts, payload) = row?;
            let fact: Fact = serde_json::from_str(&payload)?;
            out.push(FactRecord { seq, ts, fact });
        }
        Ok(out)
    }

    /// Last consumed seq for a peer's fact_log; 0 if never synced.
    pub async fn get_cursor(&self, peer: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let seq = conn
            .query_row(
                "SELECT last_seq FROM replication_cursors WHERE peer_location_id = ?1",
                params![peer],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        Ok(seq.unwrap_or(0))
    }

    /// Advances a peer's cursor (monotonic — never moves backward).
    pub async fn set_cursor(&self, peer: &str, last_seq: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO replication_cursors (peer_location_id, last_seq) VALUES (?1, ?2)
             ON CONFLICT(peer_location_id) DO UPDATE SET last_seq = excluded.last_seq
             WHERE excluded.last_seq > replication_cursors.last_seq",
            params![peer, last_seq],
        )?;
        Ok(())
    }

    /// Applies a peer-originated fact with LWW merge. Does NOT append to our own
    /// fact_log (each site pulls from every other site directly, so re-logging
    /// would fan out duplicates). For an announcement of a block we don't yet
    /// hold, enqueues a self-pull so the drainer fetches a local copy — this is
    /// the "mirror everything" behaviour the multi-site design wants.
    pub async fn apply_fact(&self, rec: &FactRecord) -> Result<()> {
        let ts = rec.ts;
        match &rec.fact {
            Fact::ObjectPut { bucket, key, blocks, size, etag } => {
                let decoded: Vec<Vec<u8>> = blocks
                    .iter()
                    .map(|h| hex::decode(h))
                    .collect::<std::result::Result<_, _>>()?;
                let encoded = Self::encode_blocks(&decoded);
                let shard_id = crate::hashing::compute_shard_id(key);
                let conn = self.conn.lock().unwrap();
                Self::put_object_row(&conn, bucket, key, &encoded, *size, etag, shard_id, false, ts)?;
            }
            Fact::ObjectDelete { bucket, key } => {
                let shard_id = crate::hashing::compute_shard_id(key);
                let conn = self.conn.lock().unwrap();
                Self::put_object_row(&conn, bucket, key, &[], 0, "", shard_id, true, ts)?;
            }
            Fact::BlockAnnounce { hash, location_id, fid, size } => {
                let hash_b = hex::decode(hash)?;
                let fid_b = hex::decode(fid)?;
                let need_pull = {
                    let conn = self.conn.lock().unwrap();
                    Self::upsert_block_location(&conn, &hash_b, location_id, &fid_b, *size, ts)?;
                    let have_local: Option<i64> = conn
                        .query_row(
                            "SELECT 1 FROM block_locations WHERE hash = ?1 AND location_id = ?2",
                            params![hash_b, self.local_location_id],
                            |r| r.get(0),
                        )
                        .optional()?;
                    have_local.is_none() && location_id != &self.local_location_id
                };
                if need_pull {
                    self.enqueue_replication(&hash_b, std::slice::from_ref(&self.local_location_id))
                        .await?;
                }
            }
            Fact::UserPut { access_key, secret_key, policy } => {
                let policy_json = serde_json::to_string(policy)?;
                let conn = self.conn.lock().unwrap();
                Self::put_user_row(&conn, access_key, secret_key, &policy_json, ts)?;
            }
        }
        Ok(())
    }

    fn local_block_bytes_locked(conn: &Connection, location_id: &str) -> Result<i64> {
        Ok(conn.query_row(
            "SELECT COALESCE(SUM(b.size), 0) FROM block_locations bl \
             JOIN blocks b ON bl.hash = b.hash \
             WHERE bl.location_id = ?1",
            params![location_id],
            |r| r.get(0),
        )?)
    }

    /// Total bytes of blocks held locally (sum of block sizes for this site's
    /// locations). Used by the disk guard to enforce the `max_bytes` quota.
    pub async fn local_block_bytes(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Self::local_block_bytes_locked(&conn, &self.local_location_id)
    }

    /// A snapshot of local counts for `shardscape status`.
    pub async fn stats(&self) -> Result<StoreStats> {
        let conn = self.conn.lock().unwrap();
        Ok(StoreStats {
            live_objects: conn.query_row("SELECT COUNT(*) FROM objects WHERE deleted = 0", [], |r| r.get(0))?,
            local_blocks: conn.query_row(
                "SELECT COUNT(*) FROM block_locations WHERE location_id = ?1",
                params![self.local_location_id],
                |r| r.get(0),
            )?,
            local_block_bytes: Self::local_block_bytes_locked(&conn, &self.local_location_id)?,
            pending_deletions: conn.query_row("SELECT COUNT(*) FROM pending_deletions", [], |r| r.get(0))?,
            fact_count: conn.query_row("SELECT COUNT(*) FROM fact_log", [], |r| r.get(0))?,
            pending_pulls: conn.query_row(
                "SELECT COUNT(*) FROM replication_queue WHERE target_location_id = ?1",
                params![self.local_location_id],
                |r| r.get(0),
            )?,
        })
    }

    // ── users ────────────────────────────────────────────────────────────────

    pub async fn create_user(&self, access_key: &str, secret_key: &str, policy: &Policy) -> Result<()> {
        let ts = self.now_micros();
        let policy_value = serde_json::to_value(policy)?;
        let policy_json = serde_json::to_string(policy)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        Self::put_user_row(&tx, access_key, secret_key, &policy_json, ts)?;
        Self::append_fact_tx(
            &tx,
            ts,
            &Fact::UserPut {
                access_key: access_key.to_string(),
                secret_key: secret_key.to_string(),
                policy: policy_value,
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    /// LWW upsert of one user row (no fact logged).
    fn put_user_row(
        conn: &Connection,
        access_key: &str,
        secret_key: &str,
        policy_json: &str,
        ts: i64,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO users (access_key, secret_key, policy, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(access_key) DO UPDATE SET
                secret_key = excluded.secret_key, policy = excluded.policy,
                updated_at = excluded.updated_at
             WHERE excluded.updated_at > users.updated_at",
            params![access_key, secret_key, policy_json, ts],
        )?;
        Ok(())
    }

    pub async fn get_user(&self, access_key: &str) -> Result<Option<(String, Policy)>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT secret_key, policy FROM users WHERE access_key = ?1",
                params![access_key],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        match row {
            Some((secret, policy_json)) => {
                let policy = serde_json::from_str(&policy_json)?;
                Ok(Some((secret, policy)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> Store {
        store_with("site-a", 0).await
    }

    /// A store with a chosen location id and clock offset. The offset lets tests
    /// make one site's writes deterministically newer (LWW) without sleeping.
    async fn store_with(id: &str, offset_ms: i64) -> Store {
        let clock = Arc::new(ClusterClock::new(offset_ms));
        Store::new(":memory:", id.to_string(), clock).await.unwrap()
    }

    /// Pulls all of `src`'s new facts into `dst` and advances the cursor — the
    /// in-process equivalent of the background peer-sync task.
    async fn pump(src: &Store, dst: &Store) {
        let after = dst.get_cursor(&src.local_location_id).await.unwrap();
        let facts = src.facts_since(after, 1000).await.unwrap();
        let mut max = after;
        for f in &facts {
            dst.apply_fact(f).await.unwrap();
            max = max.max(f.seq);
        }
        dst.set_cursor(&src.local_location_id, max).await.unwrap();
    }

    fn h(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[tokio::test]
    async fn fact_sync_converges_object_and_delete() {
        let a = store_with("site-a", 0).await;
        let b = store_with("site-b", 0).await;

        // A put propagates to B.
        a.insert_object("bk", 0, "k", vec![h(1), h(2)], 99, "e1").await.unwrap();
        pump(&a, &b).await;
        let got = b.get_object("bk", "k").await.unwrap().unwrap();
        assert_eq!(got.0, vec![h(1), h(2)]);
        assert_eq!(got.2, "e1");

        // A delete (tombstone) propagates: the key disappears on B.
        a.delete_object("bk", "k").await.unwrap();
        pump(&a, &b).await;
        assert!(b.get_object("bk", "k").await.unwrap().is_none());

        // Cursor is monotonic — a second pump with no new facts is a no-op.
        let before = b.get_cursor("site-a").await.unwrap();
        pump(&a, &b).await;
        assert_eq!(b.get_cursor("site-a").await.unwrap(), before);
    }

    #[tokio::test]
    async fn lww_newer_clock_wins_regardless_of_apply_order() {
        // site-b's clock runs 60s ahead, so its writes always carry a newer ts.
        let a = store_with("site-a", 0).await;
        let b = store_with("site-b", 60_000).await;

        a.insert_object("bk", 0, "k", vec![h(1)], 1, "from-a").await.unwrap();
        b.insert_object("bk", 0, "k", vec![h(2)], 2, "from-b").await.unwrap();

        // Exchange both ways; both must converge to B's (newer) value.
        pump(&a, &b).await;
        pump(&b, &a).await;
        assert_eq!(a.get_object("bk", "k").await.unwrap().unwrap().2, "from-b");
        assert_eq!(b.get_object("bk", "k").await.unwrap().unwrap().2, "from-b");
    }

    #[tokio::test]
    async fn tombstone_not_resurrected_by_older_put() {
        // a (newer clock) deletes; b (older) put. The delete must win.
        let a = store_with("site-a", 60_000).await;
        let b = store_with("site-b", 0).await;

        b.insert_object("bk", 0, "k", vec![h(1)], 1, "older").await.unwrap();
        a.delete_object("bk", "k").await.unwrap();

        pump(&b, &a).await; // a sees b's older put — loses to the tombstone
        assert!(a.get_object("bk", "k").await.unwrap().is_none());
        pump(&a, &b).await; // b sees a's newer tombstone — key removed
        assert!(b.get_object("bk", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn block_announce_enqueues_self_pull() {
        let a = store_with("site-a", 0).await;
        let b = store_with("site-b", 0).await;

        // A stores a block locally and announces it.
        a.store_local_block(&h(5), b"3,abc", 10).await.unwrap();
        pump(&a, &b).await;

        // B now knows site-a holds it...
        let locs = b.get_block_fids(&h(5)).await.unwrap().unwrap();
        assert!(locs.contains_key("site-a"));
        // ...and has queued a self-pull so the drainer fetches a local copy.
        let q = b.get_replication_queue().await.unwrap();
        assert!(q.iter().any(|e| e.hash == h(5)));

        // Applying the same announce again is idempotent (no duplicate queue row).
        pump(&a, &b).await;
        let q2 = b.get_replication_queue().await.unwrap();
        assert_eq!(q2.iter().filter(|e| e.hash == h(5)).count(), 1);
    }

    #[tokio::test]
    async fn object_round_trip_and_lww() {
        let s = store().await;
        let blocks = vec![h(1), h(2)];
        s.insert_object("b", 0, "k", blocks.clone(), 100, "etag1").await.unwrap();
        let got = s.get_object("b", "k").await.unwrap().unwrap();
        assert_eq!(got.0, blocks);
        assert_eq!(got.1, 100);
        assert_eq!(got.2, "etag1");

        // A newer write wins; the manifest and etag update.
        s.insert_object("b", 0, "k", vec![h(3)], 50, "etag2").await.unwrap();
        let got = s.get_object("b", "k").await.unwrap().unwrap();
        assert_eq!(got.0, vec![h(3)]);
        assert_eq!(got.2, "etag2");
    }

    #[tokio::test]
    async fn delete_object_removes_it() {
        let s = store().await;
        s.insert_object("b", 0, "k", vec![h(1)], 1, "e").await.unwrap();
        s.delete_object("b", "k").await.unwrap();
        assert!(s.get_object("b", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_is_globally_sorted_and_paginates() {
        let s = store().await;
        for key in ["c", "a", "b", "e", "d"] {
            s.insert_object("b", 0, key, vec![h(1)], 1, "e").await.unwrap();
        }
        let (page, truncated) = s.list_objects("b", None, None, 3).await.unwrap();
        let keys: Vec<_> = page.iter().map(|(k, _, _)| k.clone()).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
        assert!(truncated);

        let (page2, truncated2) = s.list_objects("b", Some("c"), None, 3).await.unwrap();
        let keys2: Vec<_> = page2.iter().map(|(k, _, _)| k.clone()).collect();
        assert_eq!(keys2, vec!["d", "e"]);
        assert!(!truncated2);
    }

    #[tokio::test]
    async fn list_prefix_filters() {
        let s = store().await;
        for key in ["app/1", "app/2", "zoo/1"] {
            s.insert_object("b", 0, key, vec![h(1)], 1, "e").await.unwrap();
        }
        let (page, _) = s.list_objects("b", None, Some("app/"), 10).await.unwrap();
        let keys: Vec<_> = page.iter().map(|(k, _, _)| k.clone()).collect();
        assert_eq!(keys, vec!["app/1", "app/2"]);
    }

    #[tokio::test]
    async fn live_set_tracks_manifests_and_tombstones() {
        let s = store().await;
        s.store_local_block(&h(1), b"3,01", 10).await.unwrap();
        s.store_local_block(&h(2), b"3,02", 10).await.unwrap();

        // Both blocks held locally; neither referenced yet → live set empty.
        assert_eq!(s.list_local_block_hashes().await.unwrap().len(), 2);
        assert!(s.compute_live_block_set().await.unwrap().is_empty());

        // An object referencing h(1) puts it in the live set; h(2) stays orphan.
        s.insert_object("b", 0, "k", vec![h(1)], 10, "e").await.unwrap();
        let live = s.compute_live_block_set().await.unwrap();
        assert!(live.contains(&h(1)));
        assert!(!live.contains(&h(2)));

        // Deleting the object (tombstone) drops h(1) from the live set.
        s.delete_object("b", "k").await.unwrap();
        assert!(s.compute_live_block_set().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_local_block_drops_row_when_last_copy() {
        let s = store().await;
        s.store_local_block(&h(1), b"3,01", 10).await.unwrap();
        // A peer also holds it → not the last copy: row survives.
        s.add_block_location(&h(1), "site-b", b"9,xx").await.unwrap();
        assert!(s.delete_local_block(&h(1)).await.unwrap());
        assert!(s.get_local_block_fid(&h(1)).await.unwrap().is_none());
        assert!(s.get_block_fids(&h(1)).await.unwrap().is_some()); // site-b entry remains

        // Now remove the only remaining (foreign) copy bookkeeping → row gone.
        let s2 = store_with("site-b", 0).await;
        s2.store_local_block(&h(3), b"1,a", 5).await.unwrap();
        assert!(s2.delete_local_block(&h(3)).await.unwrap());
        assert!(s2.get_block_fids(&h(3)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replication_queue_drain_for_local_target() {
        let clock = Arc::new(ClusterClock::new(0));
        let s = Store::new(":memory:", "site-b".to_string(), clock).await.unwrap();
        // site-a wrote a block targeting site-b; here we ARE site-b, enqueue to self.
        s.enqueue_replication(&h(7), &["site-b".to_string()]).await.unwrap();
        let q = s.get_replication_queue().await.unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].hash, h(7));

        // Defer pushes it into the future, so it drops out of the ready set.
        s.defer_replication(&q[0]).await.unwrap();
        assert!(s.get_replication_queue().await.unwrap().is_empty());

        // Dequeue removes it entirely.
        s.enqueue_replication(&h(8), &["site-b".to_string()]).await.unwrap();
        s.dequeue_replication(&h(8), 0).await.unwrap();
        let remaining: Vec<_> = s.get_replication_queue().await.unwrap();
        assert!(remaining.iter().all(|e| e.hash != h(8)));
    }

    #[tokio::test]
    async fn user_round_trip() {
        let s = store().await;
        let policy = Policy {
            statements: vec![crate::db::PolicyStatement {
                effect: "Allow".into(),
                actions: vec!["s3:*".into()],
                resources: vec!["*".into()],
            }],
        };
        s.create_user("AK", "SK", &policy).await.unwrap();
        let (secret, got) = s.get_user("AK").await.unwrap().unwrap();
        assert_eq!(secret, "SK");
        assert!(got.is_allowed("s3:GetObject", "arn:ss:bucket:::b/k"));
        assert!(s.get_user("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn peer_registry_records_peers_and_excludes_self() {
        let s = store().await;
        s.register_node("http://a:8015").await.unwrap();
        s.record_peer("site-b", "http://b:8015").await.unwrap();
        // record_peer ignores attempts to overwrite self.
        s.record_peer("site-a", "http://evil:9999").await.unwrap();

        let peers = s.get_peers_with_urls().await.unwrap();
        assert_eq!(peers.get("site-b").map(|s| s.as_str()), Some("http://b:8015"));
        assert!(!peers.contains_key("site-a"), "self excluded from peers");

        // all_nodes includes self.
        let all = s.all_nodes().await.unwrap();
        assert!(all.iter().any(|(id, url)| id == "site-a" && url == "http://a:8015"));
        assert!(all.iter().any(|(id, _)| id == "site-b"));
    }

    // Regression: the `ObjectStore` trait methods `create_multipart_upload` and
    // `get_multipart_upload_key` used to delegate to a same-named method on
    // `self`, which resolved back to the trait method itself — unbounded async
    // recursion that overflowed the stack and SIGABRT'd the node on any
    // multipart PUT. This exercises the trait surface (not the inherent methods)
    // so a re-introduction of the self-recursion overflows the test stack.
    #[tokio::test]
    async fn multipart_trait_delegation_round_trips_without_recursing() {
        use crate::storage::ObjectStore;
        let s = store().await;
        let upload_id = Uuid::new_v4();

        // create → get key (this call is what overflowed before the fix).
        ObjectStore::create_multipart_upload(&s, "test", "big.bin", upload_id).await.unwrap();
        let key = ObjectStore::get_multipart_upload_key(&s, "test", upload_id).await.unwrap();
        assert_eq!(key.as_deref(), Some("big.bin"));

        // Unknown upload id yields None rather than an error.
        assert!(ObjectStore::get_multipart_upload_key(&s, "test", Uuid::new_v4()).await.unwrap().is_none());

        // Parts round-trip through the trait surface too.
        ObjectStore::insert_part(&s, "test", upload_id, 1, vec![vec![1u8; 32]], 32, "e1").await.unwrap();
        ObjectStore::insert_part(&s, "test", upload_id, 2, vec![vec![2u8; 32]], 32, "e2").await.unwrap();
        let parts = ObjectStore::list_parts(&s, "test", upload_id).await.unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].0, 1);
        assert_eq!(parts[1].0, 2);

        // Abort/complete cleanup removes the upload and its parts.
        ObjectStore::delete_multipart_upload(&s, "test", upload_id).await.unwrap();
        assert!(ObjectStore::get_multipart_upload_key(&s, "test", upload_id).await.unwrap().is_none());
        assert!(ObjectStore::list_parts(&s, "test", upload_id).await.unwrap().is_empty());
    }
}
