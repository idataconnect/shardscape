use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use reqwest::Client;
use s3s::{
    dto::*,
    S3Request, S3Response, S3Result, S3, S3Error, S3ErrorCode,
    auth::*,
};
use std::sync::Arc;
use futures_util::stream::StreamExt;
use tracing::info;
use http_body_util::StreamBody;
use http_body::Frame;

use md5::{Md5, Digest};
use crate::db::Db;
use crate::hashing::compute_shard_id;
use crate::config::Config;
use crate::chunking::ChunkingStrategy;

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn insert_object(
        &self,
        bucket: &str,
        shard_id: i32,
        key: &str,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<(), anyhow::Error>;

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<Vec<u8>>, i64, String)>, anyhow::Error>;

    /// Metadata sizes (bytes) for a list of block hashes, in the same order.
    /// Used to resolve Range requests to block boundaries without fetching the
    /// block bodies. A hash with no size row yields 0.
    async fn block_sizes(&self, hashes: &[Vec<u8>]) -> Result<Vec<i64>, anyhow::Error>;

    /// Returns each bucket with the earliest-known object timestamp (micros since
    /// the Unix epoch) as a stand-in creation date. Buckets are implicit (derived
    /// from live objects), so there is no true creation record.
    async fn list_buckets(&self) -> Result<Vec<(String, i64)>, anyhow::Error>;

    async fn list_objects(
        &self,
        bucket: &str,
        start_after: Option<&str>,
        prefix: Option<&str>,
        page_size: usize,
    ) -> Result<(Vec<(String, i64, String)>, bool), anyhow::Error>;

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), anyhow::Error>;

    async fn create_multipart_upload(&self, bucket: &str, key: &str, upload_id: uuid::Uuid) -> Result<(), anyhow::Error>;

    async fn get_multipart_upload_key(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<Option<String>, anyhow::Error>;

    async fn insert_part(
        &self,
        bucket: &str,
        upload_id: uuid::Uuid,
        part_number: i32,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<(), anyhow::Error>;

    async fn list_parts(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<Vec<(i32, Vec<Vec<u8>>, i64, String)>, anyhow::Error>;

    async fn delete_multipart_upload(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<(), anyhow::Error>;

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        key_marker: Option<&str>,
        max_uploads: usize,
    ) -> Result<Vec<(String, String)>, anyhow::Error>;
}

#[async_trait]
pub trait BlockStore: Send + Sync {
    async fn store_block(&self, block_data: Bytes, size: i64, ref_id: &str) -> Result<Vec<u8>, anyhow::Error>;
    async fn get_block(&self, hash: &[u8]) -> Result<Bytes, anyhow::Error>;
    async fn add_usage(&self, hash: &[u8], ref_id: &str) -> Result<(), anyhow::Error>;
    async fn remove_reference(&self, hash: &[u8], ref_id: &str) -> Result<(), anyhow::Error>;
    async fn promote_local(&self, hash: &[u8], data: Bytes) -> Result<(), anyhow::Error>;
    async fn fetch_from_peer(&self, peer_url: &str, hash: &[u8]) -> Result<Bytes, anyhow::Error>;
    /// Physically delete a local block's bytes (called by GC after the metadata
    /// location entry is removed). `fid` is the location token recorded at write.
    async fn delete_block(&self, hash: &[u8], fid: &[u8]) -> Result<(), anyhow::Error>;
}

/// Physical block persistence — the only part that differs between a local
/// filesystem CAS and an external SeaweedFS cluster. The distributed logic
/// (announce, cross-site fetch, GC) lives once in `DistributedBlockStore`.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Persist `data` for `hash`; return an opaque location token ("fid") to
    /// record in block metadata. Idempotent re-writes are fine.
    async fn put(&self, hash: &[u8], data: Bytes) -> Result<Vec<u8>, anyhow::Error>;
    /// Read the bytes for `hash` given its stored token.
    async fn get(&self, hash: &[u8], fid: &[u8]) -> Result<Bytes, anyhow::Error>;
    /// Best-effort physical delete.
    async fn delete(&self, hash: &[u8], fid: &[u8]) -> Result<(), anyhow::Error>;
}

#[derive(Clone)]
pub struct StorageBackend {
    pub objects: Arc<dyn ObjectStore>,
    pub blocks: Arc<dyn BlockStore>,
    pub chunker: Arc<dyn ChunkingStrategy>,
    pub config: Config,
    pub db: Option<Arc<Db>>,
    /// Refuses new writes when free disk falls below the configured reserve.
    pub disk_guard: crate::disk::DiskGuard,
}

/// The distributed block store: one implementation of `BlockStore` over any
/// `BlobStore` backend. Handles content-addressing, fact-log announcements,
/// cross-site fetch + read-repair, and physical delete delegation.
struct DistributedBlockStore {
    db: Arc<Db>,
    config: Config,
    blob: Arc<dyn BlobStore>,
    noise_private_key: Vec<u8>,
    noise_psk: [u8; 32],
}

/// Local filesystem content-addressed store: each block is a file at
/// `root/aa/bb/<full-hex>`, sharded by the first two hash bytes so no directory
/// holds the whole corpus. No external daemon — this is the single-binary default.
struct LocalBlob {
    root: std::path::PathBuf,
}

impl LocalBlob {
    fn path_for(&self, hash: &[u8]) -> std::path::PathBuf {
        let hex = hex::encode(hash);
        // hash is always 32 bytes → hex is 64 chars; the slices are safe.
        self.root.join(&hex[0..2]).join(&hex[2..4]).join(&hex)
    }
}

#[async_trait]
impl BlobStore for LocalBlob {
    async fn put(&self, hash: &[u8], data: Bytes) -> Result<Vec<u8>, anyhow::Error> {
        let path = self.path_for(hash);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Write to a temp file then rename, so a reader never sees a partial block
        // (content-addressed: the final name implies complete, verified bytes).
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, &data).await?;
        tokio::fs::rename(&tmp, &path).await?;
        // The path is derived from the hash, so the token is unused on read; store
        // a stable marker for observability/back-compat with the fid column.
        Ok(b"local".to_vec())
    }

    async fn get(&self, hash: &[u8], _fid: &[u8]) -> Result<Bytes, anyhow::Error> {
        let data = tokio::fs::read(self.path_for(hash)).await?;
        Ok(Bytes::from(data))
    }

    async fn delete(&self, hash: &[u8], _fid: &[u8]) -> Result<(), anyhow::Error> {
        match tokio::fs::remove_file(self.path_for(hash)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// SeaweedFS backend: the master assigns a fid, the volume server holds the bytes.
struct SeaweedBlob {
    client: Client,
    master_url: String,
    volume_url: String,
}

#[async_trait]
impl BlobStore for SeaweedBlob {
    async fn put(&self, _hash: &[u8], data: Bytes) -> Result<Vec<u8>, anyhow::Error> {
        let assign = format!("{}/dir/assign", self.master_url);
        let res = self.client.get(&assign).send().await?.json::<serde_json::Value>().await?;
        let fid = res
            .get("fid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("SeaweedFS /dir/assign returned no fid"))?
            .to_string();
        let url = format!("{}/{}", self.volume_url, fid);
        let res = self.client.put(&url).body(data).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("SeaweedFS upload failed: {}", res.status());
        }
        Ok(fid.into_bytes())
    }

    async fn get(&self, _hash: &[u8], fid: &[u8]) -> Result<Bytes, anyhow::Error> {
        let fid = std::str::from_utf8(fid)?;
        let url = format!("{}/{}", self.volume_url, fid);
        let res = self.client.get(&url).send().await?;
        if res.status().is_success() {
            Ok(res.bytes().await?)
        } else {
            anyhow::bail!("SeaweedFS download failed: {}", res.status());
        }
    }

    async fn delete(&self, _hash: &[u8], fid: &[u8]) -> Result<(), anyhow::Error> {
        let fid = std::str::from_utf8(fid)?;
        let url = format!("{}/{}", self.volume_url, fid);
        let _ = self.client.delete(&url).send().await;
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for Db {
    async fn insert_object(
        &self,
        bucket: &str,
        shard_id: i32,
        key: &str,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<(), anyhow::Error> {
        self.insert_object(bucket, shard_id, key, blocks, size, etag).await
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<Vec<u8>>, i64, String)>, anyhow::Error> {
        self.get_object(bucket, key).await
    }

    async fn block_sizes(&self, hashes: &[Vec<u8>]) -> Result<Vec<i64>, anyhow::Error> {
        self.block_sizes(hashes).await
    }

    async fn list_buckets(&self) -> Result<Vec<(String, i64)>, anyhow::Error> {
        self.list_buckets().await
    }

    async fn list_objects(
        &self,
        bucket: &str,
        start_after: Option<&str>,
        prefix: Option<&str>,
        page_size: usize,
    ) -> Result<(Vec<(String, i64, String)>, bool), anyhow::Error> {
        self.list_objects(bucket, start_after, prefix, page_size).await
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), anyhow::Error> {
        self.delete_object(bucket, key).await
    }

    async fn create_multipart_upload(&self, bucket: &str, key: &str, upload_id: uuid::Uuid) -> Result<(), anyhow::Error> {
        // The inherent method is named `insert_multipart` (args: bucket, upload_id,
        // key). Calling `self.create_multipart_upload(..)` here resolved back to
        // THIS trait method — unbounded async recursion that overflowed the stack
        // and SIGABRT'd the whole node on any multipart PUT (aws switches to
        // multipart above 8MB).
        self.insert_multipart(bucket, upload_id, key).await
    }

    async fn get_multipart_upload_key(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<Option<String>, anyhow::Error> {
        // Inherent method is `get_multipart_key`; same self-recursion bug as above.
        self.get_multipart_key(bucket, upload_id).await
    }

    async fn insert_part(
        &self,
        bucket: &str,
        upload_id: uuid::Uuid,
        part_number: i32,
        blocks: Vec<Vec<u8>>,
        size: i64,
        etag: &str,
    ) -> Result<(), anyhow::Error> {
        self.insert_part(bucket, upload_id, part_number, blocks, size, etag).await
    }

    async fn list_parts(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<Vec<(i32, Vec<Vec<u8>>, i64, String)>, anyhow::Error> {
        self.list_parts(bucket, upload_id).await
    }

    async fn delete_multipart_upload(&self, bucket: &str, upload_id: uuid::Uuid) -> Result<(), anyhow::Error> {
        self.delete_multipart_upload(bucket, upload_id).await
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        key_marker: Option<&str>,
        max_uploads: usize,
    ) -> Result<Vec<(String, String)>, anyhow::Error> {
        self.list_multipart_uploads(bucket, prefix, key_marker, max_uploads).await
    }
}

impl DistributedBlockStore {
    /// Persists `data` via the blob backend and announces the new local copy via
    /// the fact log so peers learn this site now holds the block. Idempotent: if
    /// the block is already local, does nothing.
    async fn promote_block_locally(&self, hash: &[u8], data: Bytes) -> Result<(), anyhow::Error> {
        if self.db.get_local_block_fid(hash).await?.is_some() {
            return Ok(());
        }
        let size = data.len() as i64;
        let fid = self.blob.put(hash, data).await?;
        self.db.store_local_block(hash, &fid, size).await?;
        info!("Read-repair: promoted block {} to local storage", hex::encode(hash));
        Ok(())
    }
}

#[async_trait]
impl BlockStore for DistributedBlockStore {
    async fn store_block(&self, block_data: Bytes, size: i64, _ref_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        let hash: Vec<u8> = blake3::hash(&block_data).as_bytes().to_vec();

        // No usage bookkeeping: a block is "referenced" iff a live manifest names
        // it, and the GC reaper recomputes that set directly. Writing the object
        // manifest (the caller's next step) is what protects this block from GC,
        // and the grace period covers the window in between.
        if self.db.get_local_block_fid(&hash).await?.is_none() {
            // Persist bytes, then record + announce via the fact log. Peers learn
            // of the block by replaying the announce and each decides whether to
            // pull a copy — no cross-site write needed at write time.
            let fid = self.blob.put(&hash, block_data).await?;
            self.db.store_local_block(&hash, &fid, size).await?;
        }
        Ok(hash)
    }

    async fn get_block(&self, hash: &[u8]) -> Result<Bytes, anyhow::Error> {
        if let Some(fid_bytes) = self.db.get_local_block_fid(hash).await? {
            return self.blob.get(hash, &fid_bytes).await;
        }

        // Cross-site fetch
        let locations = self.db.get_block_fids(hash).await?
            .ok_or_else(|| anyhow::anyhow!("Block {} not found in cluster", hex::encode(hash)))?;

        let peers = self.db.get_peers_with_urls().await?;
        let any_holder_live = locations.keys().any(|loc| peers.contains_key(loc));
        for (peer_id, peer_url) in &peers {
            if locations.contains_key(peer_id) {
                info!("Fetching block {} from remote site {}", hex::encode(hash), peer_id);
                match self.noise_fetch_block(peer_url, hash).await {
                    Ok(data) => {
                        if let Err(e) = self.promote_block_locally(hash, data.clone()).await {
                            tracing::warn!("Read-repair promotion failed for block {}: {}", hex::encode(hash), e);
                            // Don't leave the block remote-only: queue it so the
                            // replication drainer retries the promotion in the
                            // background instead of re-fetching cross-site on
                            // every future read.
                            if let Err(qe) = self.db
                                .enqueue_replication(hash, std::slice::from_ref(&self.db.local_location_id))
                                .await
                            {
                                tracing::warn!("Failed to re-queue block {} for replication: {}", hex::encode(hash), qe);
                            }
                        }
                        return Ok(data);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch block from {}: {}", peer_id, e);
                    }
                }
            }
        }

        // The metadata says this block exists, but we couldn't obtain it. In the
        // fast-PUT durability model this is the accepted (and now LOUD) failure
        // window: a block was acknowledged on a single site that became
        // unreachable before the replication drainer copied it elsewhere.
        // Distinguish "all holders are down" (the durability-window case, may
        // recover when a site returns) from "holders are live but fetch failed"
        // (a transient network/fetch error worth retrying).
        let holders: Vec<&String> = locations.keys().collect();
        if any_holder_live {
            tracing::error!(
                "Block {} unavailable: holder site(s) {:?} are live but every fetch failed (transient?)",
                hex::encode(hash), holders
            );
        } else {
            tracing::error!(
                "Block {} unavailable: all holder site(s) {:?} are currently down. If this block was just \
                 written and never replicated, it may be permanently lost (single-site fast-PUT window).",
                hex::encode(hash), holders
            );
        }
        Err(anyhow::anyhow!("Block {} missing at all reachable locations", hex::encode(hash)))
    }

    async fn add_usage(&self, _hash: &[u8], _ref_id: &str) -> Result<(), anyhow::Error> {
        // No-op under mark-and-sweep GC: references are derived from manifests,
        // not tracked incrementally. Kept on the trait for call-site symmetry.
        Ok(())
    }

    async fn promote_local(&self, hash: &[u8], data: Bytes) -> Result<(), anyhow::Error> {
        self.promote_block_locally(hash, data).await
    }

    async fn fetch_from_peer(&self, peer_url: &str, hash: &[u8]) -> Result<Bytes, anyhow::Error> {
        self.noise_fetch_block(peer_url, hash).await
    }

    async fn remove_reference(&self, _hash: &[u8], _ref_id: &str) -> Result<(), anyhow::Error> {
        // No-op under mark-and-sweep GC. Overwriting or deleting an object changes
        // its manifest (or writes a tombstone); the now-unreferenced blocks simply
        // stop appearing in the recomputed live set and the reaper collects them
        // after the grace period. Kept on the trait for call-site symmetry.
        Ok(())
    }

    async fn delete_block(&self, hash: &[u8], fid: &[u8]) -> Result<(), anyhow::Error> {
        self.blob.delete(hash, fid).await
    }
}

impl StorageBackend {
    /// Recomputable mark-and-sweep GC. The scheduled sweep honours the grace
    /// period; pass `force = true` for the operator-triggered stop-the-world
    /// sweep (disk pressure) which reaps confirmed orphans immediately. Never
    /// deletes a block that is in the live set, regardless of `force`.
    pub async fn reap_orphaned_blocks(&self) -> Result<(), anyhow::Error> {
        self.sweep_orphaned_blocks(false).await
    }

    /// Operator-triggered immediate reclaim: same safety (live-set check) but no
    /// grace wait. Intended to be fanned out to every member by the CLI when a
    /// site is under disk pressure.
    pub async fn force_sweep_orphaned_blocks(&self) -> Result<(), anyhow::Error> {
        self.sweep_orphaned_blocks(true).await
    }

    async fn sweep_orphaned_blocks(&self, force: bool) -> Result<(), anyhow::Error> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };

        // MARK: recompute the global live set from the manifests, then diff it
        // against what we physically hold. This is the whole GC decision — no
        // refcount, no per-delete bookkeeping.
        let live = db.compute_live_block_set().await?;
        let local = db.list_local_block_hashes().await?;
        let pending: std::collections::HashMap<Vec<u8>, i64> =
            db.get_pending_deletions().await?.into_iter().collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let grace_ms = (self.config.storage.gc_grace_period_seconds as i64) * 1000;

        for hash in &local {
            if live.contains(hash) {
                // Referenced again (or never orphaned): cancel any pending reap.
                if pending.contains_key(hash) {
                    let _ = db.remove_pending_deletion(hash).await;
                }
                continue;
            }

            // Orphan. On the first sighting, record when it becomes reapable.
            let reap_at = match pending.get(hash) {
                Some(&t) => t,
                None => {
                    let _ = db
                        .add_pending_deletion(hash, std::time::SystemTime::now() + std::time::Duration::from_secs(self.config.storage.gc_grace_period_seconds))
                        .await;
                    now + grace_ms
                }
            };
            if !force && now < reap_at {
                continue; // still inside the grace window
            }

            // SWEEP: confirmed orphan past grace (or forced). Delete the local
            // physical copy and drop our location entry; the block row vanishes
            // once the last site has done the same.
            if let Some(fid_bytes) = db.get_local_block_fid(hash).await? {
                if db.delete_local_block(hash).await? {
                    let _ = self.blocks.delete_block(hash, &fid_bytes).await;
                    info!(
                        "GC{}: deleted local block {}",
                        if force { " (forced)" } else { "" },
                        hex::encode(hash),
                    );
                }
            }
            let _ = db.remove_pending_deletion(hash).await;
        }

        // Drop pending entries for blocks we no longer hold (e.g. already reaped
        // on a prior cycle) so the table doesn't accumulate stale rows.
        for (hash, _) in &pending {
            if !local.iter().any(|h| h == hash) {
                let _ = db.remove_pending_deletion(hash).await;
            }
        }
        Ok(())
    }

    pub async fn drain_replication_queue(&self) -> Result<(), anyhow::Error> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };

        // Disk guard: when writes are refused (low free space or over quota),
        // don't pull more block bytes. Try to reclaim orphans first (GC is exempt
        // — it frees space), then skip this cycle. Queue entries are durable, so
        // we simply fall behind and catch up once space frees / usage drops.
        // Metadata sync and reads (cross-site fetch) continue.
        if let Some(trip) = self.disk_guard.check() {
            let reason = match trip {
                crate::disk::GuardTrip::LowFreeSpace => format!(
                    "low disk ({} free, reserve {})",
                    crate::disk::format_bytes(self.disk_guard.free_bytes()),
                    crate::disk::format_bytes(self.disk_guard.min_free_bytes()),
                ),
                crate::disk::GuardTrip::OverQuota => format!(
                    "over quota ({} used, cap {})",
                    crate::disk::format_bytes(self.disk_guard.local_usage()),
                    crate::disk::format_bytes(self.disk_guard.max_bytes()),
                ),
            };
            tracing::warn!(
                "Replication paused: {reason}. Reclaiming orphans; will resume when space frees.",
            );
            if let Err(e) = self.force_sweep_orphaned_blocks().await {
                tracing::warn!("Forced GC under disk pressure failed: {e}");
            }
            self.disk_guard.refresh();
            if let Ok(bytes) = db.local_block_bytes().await {
                self.disk_guard.set_local_usage(bytes as u64);
            }
            return Ok(());
        }

        let entries = db.get_replication_queue().await?;
        if entries.is_empty() {
            return Ok(());
        }

        let peers = db.get_peers_with_urls().await?;

        for entry in entries {
            let hash = &entry.hash;

            let locations = db.get_block_fids(hash).await?.unwrap_or_default();

            // Decide, from metadata alone, what this entry needs before doing any
            // network I/O. The decision is a pure function so its branching is
            // unit-testable without a live DB or peers.
            let candidates = match plan_replication(&entry, &locations, &db.local_location_id, &peers) {
                ReplicationPlan::Drop => {
                    // Block is gone globally, or we already hold it locally.
                    db.dequeue_replication(hash, entry.next_attempt_at).await?;
                    continue;
                }
                ReplicationPlan::Defer => {
                    // No reachable source holds it; back off and retry later.
                    self.defer_entry(db, &entry, "no reachable source holds the block").await;
                    continue;
                }
                ReplicationPlan::FetchFrom(candidates) => candidates,
            };

            // Try each candidate source in turn until one yields the block.
            let mut fetched: Option<bytes::Bytes> = None;
            for (peer_id, peer_url) in &candidates {
                match self.blocks.fetch_from_peer(peer_url, hash).await {
                    Ok(data) => { fetched = Some(data); break; }
                    Err(e) => tracing::warn!("Replication fetch from {} failed: {}", peer_id, e),
                }
            }

            // On any failure (all sources unreachable, or promotion failed),
            // reschedule with backoff. The entry is never evicted, so it
            // converges once a source becomes reachable.
            let outcome = match fetched {
                Some(data) => self.blocks.promote_local(hash, data).await,
                None => Err(anyhow::anyhow!("all candidate sources unreachable")),
            };

            match outcome {
                Ok(()) => {
                    db.dequeue_replication(hash, entry.next_attempt_at).await?;
                }
                Err(e) => {
                    self.defer_entry(db, &entry, &e.to_string()).await;
                }
            }
        }

        // Surface persistently-stuck blocks so a long outage is visible rather
        // than silently lagging. Cheap relative to the drain itself and only
        // logs when something is actually stuck.
        match db.get_stuck_replications().await {
            Ok(stuck) if !stuck.is_empty() => {
                let sample: Vec<String> = stuck.iter().take(5)
                    .map(|(h, a, _)| format!("{}(×{a})", hex::encode(h)))
                    .collect();
                tracing::warn!(
                    "Replication: {} block(s) stuck (≥{} attempts) for site {}; sample: {}",
                    stuck.len(), crate::db::REPLICATION_STUCK_ATTEMPTS, db.local_location_id, sample.join(", ")
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to query stuck replications: {}", e),
        }

        Ok(())
    }

    /// Logs and reschedules a queue entry with backoff. A failure to reschedule
    /// is itself logged but not fatal — the entry stays in the queue at its old
    /// schedule and will be retried next cycle.
    async fn defer_entry(&self, db: &Db, entry: &crate::db::ReplicationEntry, reason: &str) {
        tracing::warn!(
            "Replication deferred for block {} (attempt {}): {}",
            hex::encode(&entry.hash), entry.attempts + 1, reason
        );
        if let Err(de) = db.defer_replication(entry).await {
            tracing::warn!("Failed to reschedule block {}: {}", hex::encode(&entry.hash), de);
        }
    }
}

/// What the drainer should do with one queue entry, decided from metadata alone
/// (no network I/O). Keeping this pure makes the drain loop's branching testable.
#[derive(Debug, PartialEq, Eq)]
enum ReplicationPlan {
    /// Remove the entry: the block is gone globally, or we already hold it.
    Drop,
    /// No reachable peer holds the block; back off and retry later.
    Defer,
    /// Attempt to fetch from these `(location_id, url)` candidates, in order.
    FetchFrom(Vec<(String, String)>),
}

/// Pure decision for one replication entry.
///
/// * `Drop`  — the block has no locations (deleted), or `local_id` already
///   appears in its locations (we hold it).
/// * `FetchFrom` — at least one live peer is listed in the block's locations;
///   returns those peers as fetch candidates.
/// * `Defer` — the block exists elsewhere but no *live* peer holds it (the
///   source site is down or not in the peer set), so retry later.
fn plan_replication(
    _entry: &crate::db::ReplicationEntry,
    locations: &std::collections::HashMap<String, Vec<u8>>,
    local_id: &str,
    peers: &std::collections::HashMap<String, String>,
) -> ReplicationPlan {
    if locations.is_empty() || locations.contains_key(local_id) {
        return ReplicationPlan::Drop;
    }
    let candidates: Vec<(String, String)> = peers
        .iter()
        .filter(|(peer_id, _)| locations.contains_key(*peer_id))
        .map(|(id, url)| (id.clone(), url.clone()))
        .collect();
    if candidates.is_empty() {
        ReplicationPlan::Defer
    } else {
        ReplicationPlan::FetchFrom(candidates)
    }
}

pub struct ShardscapeAuth {
    pub db: Arc<Db>,
}

#[async_trait]
impl S3Auth for ShardscapeAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        match self.db.get_user(access_key).await {
            Ok(Some((secret, _))) => Ok(SecretKey::from(secret)),
            Ok(None) => Err(S3Error::new(S3ErrorCode::InvalidAccessKeyId)),
            Err(e) => {
                tracing::error!("Auth DB error: {}", e);
                Err(S3Error::new(S3ErrorCode::InternalError))
            }
        }
    }
}

/// Cap on establishing a peer connection: TCP connect + Noise handshake + HTTP/1
/// handshake. Short because these are LAN/WAN control-plane round trips.
const PEER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Cap on the request/response phase (send + collect the whole body). Larger
/// because block bodies can be multi-MB, but still bounded so a peer that goes
/// to sleep mid-read cannot wedge the caller forever.
const PEER_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

impl DistributedBlockStore {
    /// Fetch a block from a peer's internal port over a Noise-encrypted connection.
    ///
    /// Every phase is bounded by a timeout. Before these were added, a peer that
    /// fell asleep mid-read left every await here pending forever; because the
    /// replication-queue drainer processes entries sequentially in one task, a
    /// single hung fetch silently froze ALL replication (observed: 16h stall).
    /// On timeout we return an error so the normal defer/backoff path runs.
    async fn noise_fetch_block(&self, peer_url: &str, hash: &[u8]) -> Result<bytes::Bytes, anyhow::Error> {
        use hyper::Request;
        use http_body_util::{BodyExt, Empty};
        use tokio::net::TcpStream;
        use tokio::time::timeout;

        let host_port = peer_url
            .trim_end_matches('/')
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        let stream = timeout(PEER_CONNECT_TIMEOUT, TcpStream::connect(host_port))
            .await
            .map_err(|_| anyhow::anyhow!("TCP connect to {host_port} timed out after {PEER_CONNECT_TIMEOUT:?}"))??;
        let noise_stream = timeout(
            PEER_CONNECT_TIMEOUT,
            crate::noise_transport::NoiseStream::connect(stream, &self.noise_private_key, &self.noise_psk),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Noise handshake with {host_port} timed out after {PEER_CONNECT_TIMEOUT:?}"))??;
        let io = hyper_util::rt::TokioIo::new(noise_stream);
        let (mut sender, conn) = timeout(
            PEER_CONNECT_TIMEOUT,
            hyper::client::conn::http1::handshake::<_, Empty<bytes::Bytes>>(io),
        )
        .await
        .map_err(|_| anyhow::anyhow!("HTTP handshake with {host_port} timed out after {PEER_CONNECT_TIMEOUT:?}"))??;
        // Drive the connection in the background for the lifetime of this one
        // request. The task ends when `sender` is dropped at the end of this
        // function; we don't pool the connection, so no join handle is kept.
        tokio::spawn(conn);

        let path = format!("/internal/blocks/{}", hex::encode(hash));
        let req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("Host", host_port)
            .header("X-Shardscape-Secret", &self.config.server.cluster_secret)
            .body(Empty::<bytes::Bytes>::new())?;

        // Send + collect under one overall deadline so a stall at any point in
        // the response (headers or body) is bounded.
        let data = timeout(PEER_FETCH_TIMEOUT, async {
            let res = sender.send_request(req).await?;
            if !res.status().is_success() {
                anyhow::bail!("Peer returned {}", res.status());
            }
            Ok::<_, anyhow::Error>(BodyExt::collect(res.into_body()).await?.to_bytes())
        })
        .await
        .map_err(|_| anyhow::anyhow!("Block fetch from {host_port} timed out after {PEER_FETCH_TIMEOUT:?}"))??;
        Ok(data)
    }
}

/// Collapse keys under `prefix` whose remainder contains `delimiter` into a
/// single common prefix (everything up to and including the first delimiter past
/// `prefix`). `objects` must be sorted ascending by key. Returns the kept
/// contents (keys with no further delimiter) and the deduped, ordered common
/// prefixes — the ListObjectsV2 delimiter semantics, factored out as a pure
/// function so the grouping is unit-testable without a live store.
impl StorageBackend {
    async fn authorize<T>(&self, req: &S3Request<T>, action: &str, bucket: Option<&str>, key: Option<&str>) -> S3Result<()> {
        // When there is no backing DB (e.g. unit tests with mock stores), skip auth.
        let db = match self.db.as_ref() {
            Some(db) => db,
            None => return Ok(()),
        };

        let creds = match &req.credentials {
            Some(c) => c,
            None => return Err(S3Error::new(S3ErrorCode::AccessDenied)),
        };

        let (_, policy) = match db.get_user(&creds.access_key).await {
            Ok(Some(u)) => u,
            Ok(None) => return Err(S3Error::new(S3ErrorCode::AccessDenied)),
            Err(e) => {
                tracing::error!("Auth DB error: {}", e);
                return Err(S3Error::new(S3ErrorCode::InternalError));
            }
        };

        let resource = match (bucket, key) {
            (Some(b), Some(k)) => format!("arn:ss:bucket:::{}/{}", b, k),
            (Some(b), None) => format!("arn:ss:bucket:::{}", b),
            _ => "*".to_string(), // Root operations like ListBuckets
        };

        if policy.is_allowed(action, &resource) {
            Ok(())
        } else {
            Err(S3Error::new(S3ErrorCode::AccessDenied))
        }
    }

    pub fn new(db: Arc<Db>, config: Config) -> Self {
        let objects = Arc::clone(&db) as Arc<dyn ObjectStore>;
        // The key is generated and persisted before the backend is ever built
        // (see main). An empty/invalid key here means a real misconfiguration,
        // and silently substituting an all-zero key would only surface later as
        // an opaque handshake failure on the first cross-site fetch — so fail loudly.
        let noise_private_key = crate::noise_transport::decode_private_key(&config.server.noise_private_key)
            .expect("noise_private_key must be initialised before StorageBackend::new");
        let noise_psk = crate::noise_transport::derive_psk(&config.server.cluster_secret);

        let blob: Arc<dyn BlobStore> = match &config.storage.backend {
            crate::config::BlockBackend::Local { path } => {
                Arc::new(LocalBlob { root: std::path::PathBuf::from(path) })
            }
            crate::config::BlockBackend::Seaweed { master_url, volume_url } => {
                Arc::new(SeaweedBlob {
                    client: Client::new(),
                    master_url: master_url.clone(),
                    volume_url: volume_url.clone(),
                })
            }
        };

        let blocks = Arc::new(DistributedBlockStore {
            db: Arc::clone(&db),
            config: config.clone(),
            blob,
            noise_private_key,
            noise_psk,
        }) as Arc<dyn BlockStore>;

        let chunker: Arc<dyn ChunkingStrategy> = match config.storage.chunking {
            crate::config::ChunkingConfig::Cdc { min_block_size, avg_block_size, max_block_size } => {
                Arc::new(crate::chunking::DynamicCDCStrategy {
                    min_size: min_block_size,
                    avg_size: avg_block_size,
                    max_size: max_block_size,
                })
            }
            crate::config::ChunkingConfig::Fixed { max_block_size } => {
                Arc::new(crate::chunking::FixedSizeStrategy {
                    chunk_size: max_block_size,
                })
            }
        };

        let disk_guard = crate::disk::DiskGuard::from_config(&config);

        Self {
            objects,
            blocks,
            chunker,
            config,
            db: Some(db),
            disk_guard,
        }
    }

    /// Returns a 503 if the disk guard has tripped, so local S3 writes are
    /// rejected cleanly (the client retries later / against the write master)
    /// rather than the node marching the volume into ENOSPC.
    fn check_writable(&self) -> S3Result<()> {
        if let Some(trip) = self.disk_guard.check() {
            let msg = match trip {
                crate::disk::GuardTrip::LowFreeSpace => format!(
                    "node is low on disk space ({} free, reserve {}); write rejected",
                    crate::disk::format_bytes(self.disk_guard.free_bytes()),
                    crate::disk::format_bytes(self.disk_guard.min_free_bytes()),
                ),
                crate::disk::GuardTrip::OverQuota => format!(
                    "node has reached storage quota ({} used, cap {}); write rejected",
                    crate::disk::format_bytes(self.disk_guard.local_usage()),
                    crate::disk::format_bytes(self.disk_guard.max_bytes()),
                ),
            };
            return Err(S3Error::with_message(S3ErrorCode::ServiceUnavailable, msg));
        }
        Ok(())
    }
}

/// Collapse keys under `prefix` whose remainder contains `delimiter` into a
/// single common prefix (everything up to and including the first delimiter past
/// `prefix`). `objects` must be sorted ascending by key. Returns the kept
/// contents (keys with no further delimiter) and the deduped, ordered common
/// prefixes — the ListObjectsV2 delimiter semantics, factored out as a pure
/// function so the grouping is unit-testable without a live store.
fn group_by_delimiter(
    objects: Vec<(String, i64, String)>,
    prefix: &str,
    delimiter: &str,
) -> (Vec<(String, i64, String)>, Vec<String>) {
    let mut contents = Vec::new();
    let mut common: Vec<String> = Vec::new();
    for (key, size, etag) in objects {
        // A key that doesn't start with the prefix shouldn't reach here (the
        // store already filters), but if it did we keep it as a plain content.
        let rest = match key.strip_prefix(prefix) {
            Some(r) => r,
            None => { contents.push((key, size, etag)); continue; }
        };
        match rest.find(delimiter) {
            Some(idx) => {
                let cp = format!("{}{}{}", prefix, &rest[..idx], delimiter);
                // Keys are sorted, so members of a common prefix are contiguous;
                // check the tail first, fall back to a full scan for safety.
                if common.last().map(String::as_str) != Some(cp.as_str()) && !common.contains(&cp) {
                    common.push(cp);
                }
            }
            None => contents.push((key, size, etag)),
        }
    }
    (contents, common)
}

/// Resolve an HTTP Range against a known object size into an inclusive
/// `[start, end]` byte range. Returns None when the range is unsatisfiable (the
/// caller maps that to 416 InvalidRange). Pure, so it's unit-testable.
fn resolve_range(range: &Range, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    match *range {
        Range::Int { first, last } => {
            if first >= size {
                return None;
            }
            let end = last.unwrap_or(size - 1).min(size - 1);
            if end < first {
                return None;
            }
            Some((first, end))
        }
        Range::Suffix { length } => {
            if length == 0 {
                return None;
            }
            let len = length.min(size);
            Some((size - len, size - 1))
        }
    }
}

/// Given ordered block sizes and an inclusive byte range `[start, end]`, returns
/// the blocks that overlap the range as (block_index, skip_front, take_len).
/// Blocks entirely outside the range are omitted so they are never fetched.
/// Pure, so the boundary math is unit-testable.
fn slice_blocks_for_range(sizes: &[i64], start: u64, end: u64) -> Vec<(usize, u64, u64)> {
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    for (i, &sz) in sizes.iter().enumerate() {
        let sz = sz.max(0) as u64;
        let block_start = offset;
        let block_end = offset + sz; // exclusive
        offset = block_end;
        if sz == 0 || block_end <= start || block_start > end {
            continue;
        }
        let s = start.max(block_start) - block_start;
        let e = end.min(block_end - 1) - block_start; // inclusive within block
        out.push((i, s, e - s + 1));
    }
    out
}

/// Slice already-fetched block bytes for a range request. `Bytes::slice` is
/// O(1) (shared refcount), so this doesn't copy.
fn slice_block_bytes(data: Bytes, skip: u64, take: Option<u64>) -> Bytes {
    let skip = (skip as usize).min(data.len());
    let data = data.slice(skip..);
    match take {
        Some(t) => data.slice(..(t as usize).min(data.len())),
        None => data,
    }
}

/// Merge grouped contents and common prefixes into a single key-ordered result
/// truncated to `max_keys` (both counting toward the cap, per S3). Returns
/// (kept_contents, kept_common_prefixes, is_truncated, next_continuation_token).
fn merge_and_truncate(
    contents: Vec<(String, i64, String)>,
    common: Vec<String>,
    max_keys: usize,
) -> (Vec<(String, i64, String)>, Vec<String>, bool, Option<String>) {
    enum Item { Obj((String, i64, String)), Prefix(String) }
    let mut merged: Vec<(String, Item)> = Vec::with_capacity(contents.len() + common.len());
    for o in contents { merged.push((o.0.clone(), Item::Obj(o))); }
    for p in common { merged.push((p.clone(), Item::Prefix(p))); }
    merged.sort_by(|a, b| a.0.cmp(&b.0));

    let is_truncated = merged.len() > max_keys;
    merged.truncate(max_keys);
    let next_token = if is_truncated {
        merged.last().map(|(k, _)| k.clone())
    } else {
        None
    };

    let mut kept_contents = Vec::new();
    let mut kept_common = Vec::new();
    for (_, item) in merged {
        match item {
            Item::Obj(o) => kept_contents.push(o),
            Item::Prefix(p) => kept_common.push(p),
        }
    }
    (kept_contents, kept_common, is_truncated, next_token)
}

#[async_trait]
impl S3 for StorageBackend {
    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        self.check_writable()?;
        let input = req.input;
        let bucket = input.bucket;
        let key = input.key;
        let shard_id = compute_shard_id(&key);

        let mut body = input.body.ok_or_else(|| {
            S3Error::with_message(S3ErrorCode::InvalidRequest, "Missing body")
        })?;

        let mut block_hashes: Vec<Vec<u8>> = Vec::new();
        let mut total_size: i64 = 0;

        // Use a reasonable buffer capacity based on config
        let initial_capacity = match self.config.storage.chunking {
            crate::config::ChunkingConfig::Fixed { max_block_size } => max_block_size,
            crate::config::ChunkingConfig::Cdc { max_block_size, .. } => max_block_size,
        };

        let mut current_chunk = BytesMut::with_capacity(initial_capacity);
        let mut md5 = Md5::new();

        while let Some(res) = body.next().await {
            let chunk = res.map_err(|e: Box<dyn std::error::Error + Send + Sync + 'static>| {
                S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
            })?;
            md5.update(&chunk);
            current_chunk.extend_from_slice(&chunk);

            for block_data in self.chunker.process(&mut current_chunk) {
                let len = block_data.len() as i64;
                total_size += len;
                let ref_id = format!("obj:{}:{}", bucket, key);
                let hash = self.blocks.store_block(block_data, len, &ref_id).await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                block_hashes.push(hash);
            }
        }

        if let Some(block_data) = self.chunker.finalize(&mut current_chunk) {
            let len = block_data.len() as i64;
            total_size += len;
            let ref_id = format!("obj:{}:{}", bucket, key);
            let hash = self.blocks.store_block(block_data, len, &ref_id).await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
            block_hashes.push(hash);
        }

        let etag = hex::encode(md5.finalize());
        info!(bucket, key, shard_id, total_size, etag, "PutObject");

        // Handle overwrite ref-counting
        if let Ok(Some((old_blocks, _, _))) = self.objects.get_object(&bucket, &key).await {
            let ref_id = format!("obj:{}:{}", bucket, key);
            for hash in old_blocks {
                let _ = self.blocks.remove_reference(&hash, &ref_id).await;
            }
        }

        self.objects.insert_object(&bucket, shard_id, &key, block_hashes, total_size, &etag).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = PutObjectOutput{
            e_tag: Some(format!("\"{}\"", etag)),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.authorize(&req, "s3:GetObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let bucket = input.bucket;
        let key = input.key;

        let (blocks, size, etag) = self.objects.get_object(&bucket, &key).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "Not found"))?;

        // Build the ordered plan of (block hash, skip_front, take_len) to stream.
        // For a full GET that's every block whole (take=None). For a Range GET we
        // resolve the byte range to block boundaries (via block metadata sizes, no
        // body fetches) so only overlapping blocks are read, and the first/last are
        // sliced. `aws s3 cp` downloads large objects with ranged GETs; before this
        // the Range header was ignored and every ranged request returned the WHOLE
        // object, which the client stitched into a corrupted, oversized file.
        let mut content_length = size;
        let mut content_range: Option<String> = None;
        let plan: Vec<(Vec<u8>, u64, Option<u64>)> = match &input.range {
            None => blocks.into_iter().map(|h| (h, 0u64, None)).collect(),
            Some(range) => {
                let (start, end) = resolve_range(range, size as u64).ok_or_else(|| {
                    S3Error::with_message(S3ErrorCode::InvalidRange, "Requested range not satisfiable")
                })?;
                let sizes = self.objects.block_sizes(&blocks).await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                content_length = (end - start + 1) as i64;
                content_range = Some(format!("bytes {start}-{end}/{size}"));
                slice_blocks_for_range(&sizes, start, end)
                    .into_iter()
                    .map(|(i, skip, take)| (blocks[i].clone(), skip, Some(take)))
                    .collect()
            }
        };

        // Commit-before-serve hazard: once we return a 200 with Content-Length,
        // s3s writes headers and starts draining the body stream. If a block then
        // fails to fetch (e.g. it lives only on a sleeping peer), the stream aborts
        // mid-body and the client sees IncompleteRead(0/N) — a truncated 200 that
        // masquerades as a retriable network error. To avoid that, eagerly fetch
        // the FIRST block here so an unavailable object surfaces as a proper S3
        // error BEFORE the response status is sent. The remaining blocks stream
        // lazily; a mid-stream failure on a later block is unavoidable with a
        // streaming body, but the common case (whole object unavailable) is fixed.
        let blocks_store = Arc::clone(&self.blocks);
        let mut plan_iter = plan.into_iter();
        let first = match plan_iter.next() {
            Some((hash_bytes, skip, take)) => {
                let data = blocks_store.get_block(&hash_bytes).await.map_err(|e| {
                    // 503 SlowDown: retriable, signals the client to back off rather
                    // than treat this as a hard/permanent failure.
                    S3Error::with_message(S3ErrorCode::SlowDown, format!("block unavailable: {e}"))
                })?;
                Some(Ok(Frame::data(slice_block_bytes(data, skip, take))))
            }
            None => None, // zero-block object, or a range that covers no bytes
        };

        let rest = futures_util::stream::iter(plan_iter)
            .map(move |(hash_bytes, skip, take)| {
                let store = Arc::clone(&blocks_store);
                async move {
                    store.get_block(&hash_bytes).await
                        .map(|data| Frame::data(slice_block_bytes(data, skip, take)))
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))
                }
            })
            .buffered(2);

        // Prepend the already-fetched first frame ahead of the lazily-streamed rest.
        let frame_stream = futures_util::stream::iter(first).chain(rest);
        let body = s3s::Body::http_body_unsync(StreamBody::new(frame_stream));

        let output = GetObjectOutput{
            body: Some(StreamingBlob::from(body)),
            content_length: Some(content_length),
            content_range,
            accept_ranges: Some("bytes".to_string()),
            e_tag: Some(format!("\"{}\"", etag)),
            last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn list_buckets(
        &self,
        req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        self.authorize(&req, "s3:ListAllMyBuckets", None, None).await?;
        let names = self.objects.list_buckets().await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
        let buckets: Vec<Bucket> = names
            .into_iter()
            .map(|(name, created_micros)| {
                let created = std::time::UNIX_EPOCH
                    + std::time::Duration::from_micros(created_micros.max(0) as u64);
                Bucket {
                    name: Some(name),
                    creation_date: Some(Timestamp::from(created)),
                    ..Default::default()
                }
            })
            .collect();
        let output = ListBucketsOutput {
            buckets: Some(buckets),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn create_bucket(
        &self,
        _req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        self.authorize(&_req, "s3:CreateBucket", Some(&_req.input.bucket), None).await?;
        Ok(S3Response::new(CreateBucketOutput::default()))
    }

    async fn delete_bucket(
        &self,
        _req: S3Request<DeleteBucketInput>,
    ) -> S3Result<S3Response<DeleteBucketOutput>> {
        self.authorize(&_req, "s3:DeleteBucket", Some(&_req.input.bucket), None).await?;
        Ok(S3Response::new(DeleteBucketOutput::default()))
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.authorize(&req, "s3:DeleteObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;

        if let Ok(Some((blocks, _, _))) = self.objects.get_object(&input.bucket, &input.key).await {
            let ref_id = format!("obj:{}:{}", input.bucket, input.key);
            for hash in blocks {
                let _ = self.blocks.remove_reference(&hash, &ref_id).await;
            }
        }

        self.objects.delete_object(&input.bucket, &input.key).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }

    async fn delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        self.authorize(&req, "s3:DeleteObject", Some(&req.input.bucket), None).await?;
        let input = req.input;
        let mut deleted = Vec::new();
        let mut errors = Vec::new();

        for object in input.delete.objects {
            if let Ok(Some((blocks, _, _))) = self.objects.get_object(&input.bucket, &object.key).await {
                let ref_id = format!("obj:{}:{}", input.bucket, object.key);
                for hash in blocks {
                    let _ = self.blocks.remove_reference(&hash, &ref_id).await;
                }
            }

            match self.objects.delete_object(&input.bucket, &object.key).await {
                Ok(_) => {
                    deleted.push(DeletedObject {
                        key: Some(object.key),
                        ..Default::default()
                    });
                }
                Err(e) => {
                    errors.push(Error {
                        key: Some(object.key),
                        message: Some(e.to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        let output = DeleteObjectsOutput {
            deleted: Some(deleted),
            errors: Some(errors),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.authorize(&req, "s3:HeadObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let bucket = input.bucket;
        let key = input.key;

        let (_blocks, size, etag) = self.objects.get_object(&bucket, &key).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "Not found"))?;

        let output = HeadObjectOutput{
            content_length: Some(size),
            e_tag: Some(format!("\"{}\"", etag)),
            last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        self.authorize(&req, "s3:ListBucket", Some(&req.input.bucket), None).await?;
        let input = req.input;
        let bucket = input.bucket;
        let prefix = input.prefix.as_deref();
        // continuation_token takes precedence over start_after per S3 spec.
        let start_after = input.continuation_token.as_deref()
            .or(input.start_after.as_deref());
        let max_keys = input.max_keys.unwrap_or(1000).max(1) as usize;
        let delimiter = input.delimiter.as_deref();

        let (kept, common_prefixes, is_truncated, next_token) = match delimiter {
            // No delimiter: one page straight from the store (fast path).
            None => {
                let (objects, is_truncated) = self.objects
                    .list_objects(&bucket, start_after, prefix, max_keys)
                    .await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                let next_token = if is_truncated {
                    objects.last().map(|(k, _, _)| k.clone())
                } else {
                    None
                };
                (objects, Vec::new(), is_truncated, next_token)
            }
            // With a delimiter, keys sharing a path segment collapse into one
            // CommonPrefix, so a single store page could over-report truncation.
            // Scan the prefix range (bounded) and group, then truncate the merged
            // result to max_keys — CommonPrefixes and Contents both count toward it.
            Some(delim) => {
                const SCAN_CAP: usize = 100_000;
                let mut gathered: Vec<(String, i64, String)> = Vec::new();
                let mut cursor = start_after.map(|s| s.to_string());
                loop {
                    let (page, more) = self.objects
                        .list_objects(&bucket, cursor.as_deref(), prefix, 1000)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    let last = page.last().map(|(k, _, _)| k.clone());
                    gathered.extend(page);
                    match last {
                        Some(k) if more && gathered.len() < SCAN_CAP => cursor = Some(k),
                        _ => break,
                    }
                }
                let (contents, common) = group_by_delimiter(gathered, prefix.unwrap_or(""), delim);
                merge_and_truncate(contents, common, max_keys)
            }
        };

        let contents: Vec<Object> = kept
            .into_iter()
            .map(|(key, size, etag)| {
                Object{
                    key: Some(key),
                    size: Some(size),
                    e_tag: Some(format!("\"{}\"", etag)),
                    last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                    ..Default::default()
                }
            })
            .collect();

        // KeyCount counts both returned keys and common prefixes.
        let key_count = (contents.len() + common_prefixes.len()) as i32;
        let common_prefixes: Vec<CommonPrefix> = common_prefixes
            .into_iter()
            .map(|p| CommonPrefix { prefix: Some(p) })
            .collect();

        let output = ListObjectsV2Output{
            name: Some(bucket),
            prefix: prefix.map(|p| p.to_string()),
            delimiter: delimiter.map(|d| d.to_string()),
            contents: Some(contents),
            common_prefixes: if common_prefixes.is_empty() { None } else { Some(common_prefixes) },
            is_truncated: Some(is_truncated),
            key_count: Some(key_count),
            max_keys: Some(max_keys as i32),
            next_continuation_token: next_token,
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        self.authorize(&req, "s3:ListBucket", Some(&req.input.bucket), None).await?;
        Ok(S3Response::new(HeadBucketOutput::default()))
    }

    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        self.authorize(&req, "s3:ListBucket", Some(&req.input.bucket), None).await?;
        let input = req.input;
        let bucket = input.bucket;
        let prefix = input.prefix.as_deref();
        let marker = input.marker.as_deref();
        let max_keys = input.max_keys.unwrap_or(1000).max(1) as usize;
        let delimiter = input.delimiter.as_deref();

        let (kept, common_prefixes, is_truncated, next_marker) = match delimiter {
            None => {
                let (objects, is_truncated) = self.objects
                    .list_objects(&bucket, marker, prefix, max_keys)
                    .await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                let next_marker = if is_truncated {
                    objects.last().map(|(k, _, _)| k.clone())
                } else {
                    None
                };
                (objects, Vec::new(), is_truncated, next_marker)
            }
            Some(delim) => {
                const SCAN_CAP: usize = 100_000;
                let mut gathered: Vec<(String, i64, String)> = Vec::new();
                let mut cursor = marker.map(|s| s.to_string());
                loop {
                    let (page, more) = self.objects
                        .list_objects(&bucket, cursor.as_deref(), prefix, 1000)
                        .await
                        .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                    let last = page.last().map(|(k, _, _)| k.clone());
                    gathered.extend(page);
                    match last {
                        Some(k) if more && gathered.len() < SCAN_CAP => cursor = Some(k),
                        _ => break,
                    }
                }
                let (contents, common) = group_by_delimiter(gathered, prefix.unwrap_or(""), delim);
                merge_and_truncate(contents, common, max_keys)
            }
        };

        let contents: Vec<Object> = kept
            .into_iter()
            .map(|(key, size, etag)| Object {
                key: Some(key),
                size: Some(size),
                e_tag: Some(format!("\"{}\"", etag)),
                last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            })
            .collect();

        let common_prefixes: Vec<CommonPrefix> = common_prefixes
            .into_iter()
            .map(|p| CommonPrefix { prefix: Some(p) })
            .collect();

        let output = ListObjectsOutput {
            name: Some(bucket),
            prefix: prefix.map(|p| p.to_string()),
            delimiter: delimiter.map(|d| d.to_string()),
            marker: marker.map(|m| m.to_string()),
            contents: Some(contents),
            common_prefixes: if common_prefixes.is_empty() { None } else { Some(common_prefixes) },
            is_truncated: Some(is_truncated),
            max_keys: Some(max_keys as i32),
            next_marker,
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn copy_object(
        &self,
        req: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let (src_bucket, src_key) = match &input.copy_source {
            CopySource::Bucket { bucket, key, .. } => (bucket.to_string(), key.to_string()),
            CopySource::AccessPoint { .. } => {
                return Err(S3Error::with_message(S3ErrorCode::NotImplemented, "AccessPoint copy source not supported"));
            }
        };

        let (blocks, size, etag) = self.objects.get_object(&src_bucket, &src_key).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "Source object not found"))?;

        let dest_bucket = input.bucket;
        let dest_key = input.key;
        let shard_id = compute_shard_id(&dest_key);

        let dest_ref_id = format!("obj:{}:{}", dest_bucket, dest_key);
        if let Ok(Some((old_blocks, _, _))) = self.objects.get_object(&dest_bucket, &dest_key).await {
            for hash in old_blocks {
                let _ = self.blocks.remove_reference(&hash, &dest_ref_id).await;
            }
        }

        for hash in &blocks {
            let _ = self.blocks.add_usage(hash, &dest_ref_id).await;
        }

        self.objects.insert_object(&dest_bucket, shard_id, &dest_key, blocks, size, &etag).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = CopyObjectOutput {
            copy_object_result: Some(CopyObjectResult {
                e_tag: Some(format!("\"{}\"", etag)),
                last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn list_parts(
        &self,
        req: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        self.authorize(&req, "s3:ListMultipartUploadParts", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let upload_id = uuid::Uuid::parse_str(&input.upload_id)
            .map_err(|_| S3Error::with_message(S3ErrorCode::InvalidRequest, "Invalid upload id"))?;

        let _key = self.objects.get_multipart_upload_key(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

        let parts = self.objects.list_parts(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let part_number_marker = input.part_number_marker.as_deref()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);
        let max_parts = input.max_parts.unwrap_or(1000).max(1) as usize;

        let filtered: Vec<_> = parts.into_iter()
            .filter(|(n, _, _, _)| *n > part_number_marker)
            .collect();
        let is_truncated = filtered.len() > max_parts;

        let result_parts: Vec<Part> = filtered.into_iter()
            .take(max_parts)
            .map(|(num, _blocks, size, etag)| Part {
                part_number: Some(num),
                size: Some(size),
                e_tag: Some(format!("\"{}\"", etag)),
                last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            })
            .collect();

        let next_marker = if is_truncated {
            result_parts.last().and_then(|p| p.part_number).map(|n| n.to_string())
        } else {
            None
        };

        let output = ListPartsOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(input.upload_id),
            parts: Some(result_parts),
            max_parts: Some(max_parts as i32),
            is_truncated: Some(is_truncated),
            next_part_number_marker: next_marker,
            part_number_marker: input.part_number_marker,
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<ListMultipartUploadsOutput>> {
        self.authorize(&req, "s3:ListBucketMultipartUploads", Some(&req.input.bucket), None).await?;
        let input = req.input;
        let max_uploads = input.max_uploads.unwrap_or(1000).max(1) as usize;

        let rows = self.objects.list_multipart_uploads(
            &input.bucket,
            input.prefix.as_deref(),
            input.key_marker.as_deref(),
            max_uploads,
        ).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let is_truncated = rows.len() > max_uploads;
        let uploads: Vec<MultipartUpload> = rows.into_iter()
            .take(max_uploads)
            .map(|(key, upload_id)| MultipartUpload {
                key: Some(key),
                upload_id: Some(upload_id),
                initiated: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            })
            .collect();

        let next_key_marker = if is_truncated {
            uploads.last().and_then(|u| u.key.clone())
        } else {
            None
        };

        let output = ListMultipartUploadsOutput {
            bucket: Some(input.bucket),
            prefix: input.prefix,
            key_marker: input.key_marker,
            max_uploads: Some(max_uploads as i32),
            is_truncated: Some(is_truncated),
            uploads: if uploads.is_empty() { None } else { Some(uploads) },
            next_key_marker,
            delimiter: input.delimiter,
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<UploadPartCopyInput>,
    ) -> S3Result<S3Response<UploadPartCopyOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        self.check_writable()?;
        let input = req.input;
        let upload_id = uuid::Uuid::parse_str(&input.upload_id)
            .map_err(|_| S3Error::with_message(S3ErrorCode::InvalidRequest, "Invalid upload id"))?;

        let _key = self.objects.get_multipart_upload_key(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

        let (src_bucket, src_key) = match &input.copy_source {
            CopySource::Bucket { bucket, key, .. } => (bucket.to_string(), key.to_string()),
            CopySource::AccessPoint { .. } => {
                return Err(S3Error::with_message(S3ErrorCode::NotImplemented, "AccessPoint copy source not supported"));
            }
        };

        let (src_blocks, src_size, _src_etag) = self.objects.get_object(&src_bucket, &src_key).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "Source object not found"))?;

        let (range_start, range_end) = if let Some(ref range_str) = input.copy_source_range {
            let range_str = range_str.strip_prefix("bytes=").unwrap_or(range_str);
            let parts: Vec<&str> = range_str.splitn(2, '-').collect();
            if parts.len() != 2 {
                return Err(S3Error::with_message(S3ErrorCode::InvalidArgument, "Invalid copy source range"));
            }
            let start: u64 = parts[0].parse().map_err(|_| S3Error::with_message(S3ErrorCode::InvalidArgument, "Invalid range start"))?;
            let end: u64 = parts[1].parse().map_err(|_| S3Error::with_message(S3ErrorCode::InvalidArgument, "Invalid range end"))?;
            (start, end)
        } else {
            (0u64, (src_size as u64).saturating_sub(1))
        };

        let sizes = self.objects.block_sizes(&src_blocks).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
        let slices = slice_blocks_for_range(&sizes, range_start, range_end);

        let mut block_hashes: Vec<Vec<u8>> = Vec::new();
        let mut total_size: i64 = 0;
        let mut md5 = Md5::new();
        let ref_id = format!("upload:{}:{}", input.bucket, input.upload_id);

        let initial_capacity = match self.config.storage.chunking {
            crate::config::ChunkingConfig::Fixed { max_block_size } => max_block_size,
            crate::config::ChunkingConfig::Cdc { max_block_size, .. } => max_block_size,
        };
        let mut current_chunk = BytesMut::with_capacity(initial_capacity);

        for (i, skip, take) in slices {
            let data = self.blocks.get_block(&src_blocks[i]).await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
            let sliced = slice_block_bytes(data, skip, Some(take));
            md5.update(&sliced);
            current_chunk.extend_from_slice(&sliced);

            for block_data in self.chunker.process(&mut current_chunk) {
                let len = block_data.len() as i64;
                total_size += len;
                let hash = self.blocks.store_block(block_data, len, &ref_id).await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                block_hashes.push(hash);
            }
        }

        if let Some(block_data) = self.chunker.finalize(&mut current_chunk) {
            let len = block_data.len() as i64;
            total_size += len;
            let hash = self.blocks.store_block(block_data, len, &ref_id).await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
            block_hashes.push(hash);
        }

        let etag = hex::encode(md5.finalize());
        self.objects.insert_part(&input.bucket, upload_id, input.part_number, block_hashes, total_size, &etag).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = UploadPartCopyOutput {
            copy_part_result: Some(CopyPartResult {
                e_tag: Some(format!("\"{}\"", etag)),
                last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let upload_id = uuid::Uuid::new_v4();

        self.objects.create_multipart_upload(&input.bucket, &input.key, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload_id.to_string()),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        self.check_writable()?;
        let input = req.input;
        let upload_id = uuid::Uuid::parse_str(&input.upload_id)
            .map_err(|_| S3Error::with_message(S3ErrorCode::InvalidRequest, "Invalid upload id"))?;

        // Verify upload exists and get key
        let _key = self.objects.get_multipart_upload_key(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

        let mut body = input.body.ok_or_else(|| {
            S3Error::with_message(S3ErrorCode::InvalidRequest, "Missing body")
        })?;

        let mut block_hashes: Vec<Vec<u8>> = Vec::new();
        let mut total_size: i64 = 0;

        let initial_capacity = match self.config.storage.chunking {
            crate::config::ChunkingConfig::Fixed { max_block_size } => max_block_size,
            crate::config::ChunkingConfig::Cdc { max_block_size, .. } => max_block_size,
        };

        let mut current_chunk = BytesMut::with_capacity(initial_capacity);
        let mut md5 = Md5::new();

        while let Some(res) = body.next().await {
            let chunk = res.map_err(|e: Box<dyn std::error::Error + Send + Sync + 'static>| {
                S3Error::with_message(S3ErrorCode::InternalError, e.to_string())
            })?;
            md5.update(&chunk);
            current_chunk.extend_from_slice(&chunk);

            for block_data in self.chunker.process(&mut current_chunk) {
                let len = block_data.len() as i64;
                total_size += len;
                let ref_id = format!("upload:{}:{}", input.bucket, input.upload_id);
                let hash = self.blocks.store_block(block_data, len, &ref_id).await
                    .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
                block_hashes.push(hash);
            }
        }

        if let Some(block_data) = self.chunker.finalize(&mut current_chunk) {
            let len = block_data.len() as i64;
            total_size += len;
            let ref_id = format!("upload:{}:{}", input.bucket, input.upload_id);
            let hash = self.blocks.store_block(block_data, len, &ref_id).await
                .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;
            block_hashes.push(hash);
        }

        let etag = hex::encode(md5.finalize());
        self.objects.insert_part(&input.bucket, upload_id, input.part_number, block_hashes, total_size, &etag).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = UploadPartOutput{
            e_tag: Some(format!("\"{}\"", etag)),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.authorize(&req, "s3:PutObject", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let upload_id = uuid::Uuid::parse_str(&input.upload_id)
            .map_err(|_| S3Error::with_message(S3ErrorCode::InvalidRequest, "Invalid upload id"))?;

        let stored_key = self.objects.get_multipart_upload_key(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?
            .ok_or_else(|| S3Error::with_message(S3ErrorCode::NoSuchUpload, "Upload not found"))?;

        if stored_key != input.key {
            return Err(S3Error::with_message(S3ErrorCode::InvalidRequest, "Key in request does not match key for this upload"));
        }
        let key = input.key.clone();

        let mut parts = self.objects.list_parts(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        // Sort parts by part number
        parts.sort_by_key(|(num, _, _, _)| *num);

        let mut all_block_hashes = Vec::new();
        let mut total_size: i64 = 0;

        // S3 ETag for multipart is often <combined-md5>-<num-parts>
        // But for simplicity and consistency with our HeadObject, we'll recompute MD5 if possible,
        // or just use a synthetic one. Real S3 re-hashes the ETag of each part.
        let mut etag_md5 = Md5::new();

        for (_num, blocks, size, etag) in parts {
            all_block_hashes.extend(blocks);
            total_size += size;
            let etag_bytes = hex::decode(etag.trim_matches('"'))
                .map_err(|_| S3Error::with_message(S3ErrorCode::InternalError, "Invalid part etag"))?;
            etag_md5.update(&etag_bytes);
        }

        let final_etag = format!("{}-{}", hex::encode(etag_md5.finalize()), all_block_hashes.len());
        let shard_id = crate::hashing::compute_shard_id(&key);

        let obj_ref_id = format!("obj:{}:{}", input.bucket, key);
        let up_ref_id = format!("upload:{}:{}", input.bucket, input.upload_id);

        // Handle overwrite ref-counting
        if let Ok(Some((old_blocks, _, _))) = self.objects.get_object(&input.bucket, &key).await {
            for hash in old_blocks {
                let _ = self.blocks.remove_reference(&hash, &obj_ref_id).await;
            }
        }

        for hash in &all_block_hashes {
            // Swap upload reference for object reference
            let _ = self.blocks.add_usage(hash, &obj_ref_id).await;
            let _ = self.blocks.remove_reference(hash, &up_ref_id).await;
        }

        self.objects.insert_object(&input.bucket, shard_id, &key, all_block_hashes, total_size, &final_etag).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        self.objects.delete_multipart_upload(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        let output = CompleteMultipartUploadOutput{
            bucket: Some(input.bucket),
            key: Some(key),
            e_tag: Some(format!("\"{}\"", final_etag)),
            ..Default::default()
        };
        Ok(S3Response::new(output))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.authorize(&req, "s3:AbortMultipartUpload", Some(&req.input.bucket), Some(&req.input.key)).await?;
        let input = req.input;
        let upload_id = uuid::Uuid::parse_str(&input.upload_id)
            .map_err(|_| S3Error::with_message(S3ErrorCode::InvalidRequest, "Invalid upload id"))?;

        self.objects.delete_multipart_upload(&input.bucket, upload_id).await
            .map_err(|e| S3Error::with_message(S3ErrorCode::InternalError, e.to_string()))?;

        Ok(S3Response::new(AbortMultipartUploadOutput::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::FixedSizeStrategy;
    use crate::db::ReplicationEntry;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use s3s::Body;

    // ── plan_replication: the drain loop's pure decision ──────────────────────

    fn entry() -> ReplicationEntry {
        ReplicationEntry { hash: vec![0xAB; 32], next_attempt_at: 0, attempts: 0, enqueued_at: 0 }
    }

    fn locations(ids: &[&str]) -> HashMap<String, Vec<u8>> {
        ids.iter().map(|id| (id.to_string(), vec![1, 2, 3])).collect()
    }

    fn peers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(id, url)| (id.to_string(), url.to_string())).collect()
    }

    fn kv(keys: &[&str]) -> Vec<(String, i64, String)> {
        keys.iter().map(|k| (k.to_string(), 0i64, "etag".to_string())).collect()
    }

    #[test]
    fn delimiter_groups_root_prefixes() {
        // Root listing with "/" collapses each top-level segment into one prefix.
        let (contents, common) = group_by_delimiter(
            kv(&["datasets/a.txt", "datasets/b/c.txt", "notes/x", "top.txt"]),
            "",
            "/",
        );
        assert_eq!(common, vec!["datasets/".to_string(), "notes/".to_string()]);
        // Only the key with no delimiter past the prefix stays in Contents.
        assert_eq!(contents.iter().map(|(k, _, _)| k.clone()).collect::<Vec<_>>(), vec!["top.txt"]);
    }

    #[test]
    fn delimiter_groups_under_prefix() {
        // prefix=datasets/ delimiter=/ rolls up the next segment.
        let (contents, common) = group_by_delimiter(
            kv(&[
                "datasets/knob_flame_v3/a.xml",
                "datasets/knob_flame_v3/b.xml",
                "datasets/other/z",
                "datasets/top.txt",
            ]),
            "datasets/",
            "/",
        );
        assert_eq!(common, vec!["datasets/knob_flame_v3/".to_string(), "datasets/other/".to_string()]);
        assert_eq!(contents.iter().map(|(k, _, _)| k.clone()).collect::<Vec<_>>(), vec!["datasets/top.txt"]);
    }

    #[test]
    fn delimiter_no_match_keeps_all_contents() {
        // No key contains the delimiter past the prefix → no common prefixes.
        let (contents, common) = group_by_delimiter(kv(&["a.txt", "b.txt"]), "", "/");
        assert!(common.is_empty());
        assert_eq!(contents.len(), 2);
    }

    #[test]
    fn merge_and_truncate_counts_prefixes_and_contents() {
        let (contents, common, truncated, next) = merge_and_truncate(
            kv(&["a.txt", "z.txt"]),
            vec!["m/".to_string(), "n/".to_string()],
            3,
        );
        // 4 items, max 3 → truncated at the 3rd in key order (a.txt, m/, n/).
        assert!(truncated);
        assert_eq!(contents.iter().map(|(k, _, _)| k.clone()).collect::<Vec<_>>(), vec!["a.txt"]);
        assert_eq!(common, vec!["m/".to_string(), "n/".to_string()]);
        assert_eq!(next.as_deref(), Some("n/"));
    }

    #[test]
    fn merge_and_truncate_not_truncated_when_within_max() {
        let (_c, _p, truncated, next) = merge_and_truncate(kv(&["a"]), vec!["b/".to_string()], 10);
        assert!(!truncated);
        assert_eq!(next, None);
    }

    #[test]
    fn resolve_range_int_and_suffix() {
        // Explicit start-end (inclusive).
        assert_eq!(resolve_range(&Range::Int { first: 0, last: Some(9) }, 100), Some((0, 9)));
        // Open-ended start → to EOF.
        assert_eq!(resolve_range(&Range::Int { first: 50, last: None }, 100), Some((50, 99)));
        // last past EOF clamps.
        assert_eq!(resolve_range(&Range::Int { first: 90, last: Some(999) }, 100), Some((90, 99)));
        // Suffix: last N bytes.
        assert_eq!(resolve_range(&Range::Suffix { length: 20 }, 100), Some((80, 99)));
        // Suffix longer than object → whole object.
        assert_eq!(resolve_range(&Range::Suffix { length: 500 }, 100), Some((0, 99)));
        // Unsatisfiable: start beyond EOF, or empty object.
        assert_eq!(resolve_range(&Range::Int { first: 100, last: None }, 100), None);
        assert_eq!(resolve_range(&Range::Int { first: 0, last: None }, 0), None);
    }

    #[test]
    fn slice_blocks_for_range_spans_and_boundaries() {
        // Three blocks of 10 bytes each: [0,10) [10,20) [20,30).
        let sizes = [10i64, 10, 10];
        // A range fully inside the middle block.
        assert_eq!(slice_blocks_for_range(&sizes, 12, 15), vec![(1, 2, 4)]);
        // A range spanning all three blocks with partial first/last.
        assert_eq!(slice_blocks_for_range(&sizes, 5, 24), vec![(0, 5, 5), (1, 0, 10), (2, 0, 5)]);
        // Exactly on a block boundary.
        assert_eq!(slice_blocks_for_range(&sizes, 10, 19), vec![(1, 0, 10)]);
        // Whole object.
        assert_eq!(slice_blocks_for_range(&sizes, 0, 29), vec![(0, 0, 10), (1, 0, 10), (2, 0, 10)]);
        // Last byte only.
        assert_eq!(slice_blocks_for_range(&sizes, 29, 29), vec![(2, 9, 1)]);
    }

    #[test]
    fn slice_block_bytes_skips_and_takes() {
        let b = Bytes::from_static(b"0123456789");
        assert_eq!(slice_block_bytes(b.clone(), 0, None), Bytes::from_static(b"0123456789"));
        assert_eq!(slice_block_bytes(b.clone(), 2, Some(3)), Bytes::from_static(b"234"));
        assert_eq!(slice_block_bytes(b.clone(), 8, Some(50)), Bytes::from_static(b"89"));
        assert_eq!(slice_block_bytes(b, 20, None), Bytes::from_static(b""));
    }

    #[test]
    fn plan_drops_when_block_has_no_locations() {
        // Block was deleted globally before replication ran.
        let plan = plan_replication(&entry(), &locations(&[]), "site-a", &peers(&[("site-b", "u")]));
        assert_eq!(plan, ReplicationPlan::Drop);
    }

    #[test]
    fn plan_drops_when_we_already_hold_it_locally() {
        // local_id is among the block's locations — nothing to replicate.
        let plan = plan_replication(&entry(), &locations(&["site-a", "site-b"]), "site-a", &peers(&[("site-b", "u")]));
        assert_eq!(plan, ReplicationPlan::Drop);
    }

    #[test]
    fn plan_defers_when_no_live_peer_holds_it() {
        // The block lives only on site-c, which is NOT in the live peer set
        // (it's down / evicted by heartbeat). Must back off, not drop.
        let plan = plan_replication(&entry(), &locations(&["site-c"]), "site-a", &peers(&[("site-b", "u")]));
        assert_eq!(plan, ReplicationPlan::Defer);
    }

    #[test]
    fn plan_defers_when_peer_set_is_empty() {
        let plan = plan_replication(&entry(), &locations(&["site-b"]), "site-a", &peers(&[]));
        assert_eq!(plan, ReplicationPlan::Defer);
    }

    #[test]
    fn plan_fetches_from_the_live_peer_that_holds_it() {
        let plan = plan_replication(
            &entry(),
            &locations(&["site-b"]),
            "site-a",
            &peers(&[("site-b", "http://b:8115"), ("site-c", "http://c:8115")]),
        );
        match plan {
            ReplicationPlan::FetchFrom(c) => {
                assert_eq!(c, vec![("site-b".to_string(), "http://b:8115".to_string())]);
            }
            other => panic!("expected FetchFrom, got {other:?}"),
        }
    }

    #[test]
    fn plan_fetch_candidates_exclude_peers_that_dont_hold_the_block() {
        // site-c is live but doesn't hold the block; only site-b is a candidate.
        let plan = plan_replication(
            &entry(),
            &locations(&["site-b", "site-d"]),
            "site-a",
            &peers(&[("site-b", "ub"), ("site-c", "uc")]),
        );
        match plan {
            ReplicationPlan::FetchFrom(c) => {
                assert_eq!(c.len(), 1);
                assert_eq!(c[0].0, "site-b");
            }
            other => panic!("expected FetchFrom, got {other:?}"),
        }
    }

    #[test]
    fn plan_local_presence_takes_precedence_over_fetchable_peers() {
        // Even though site-b (live) holds it, we already have it locally → Drop.
        let plan = plan_replication(
            &entry(),
            &locations(&["site-a", "site-b"]),
            "site-a",
            &peers(&[("site-b", "u")]),
        );
        assert_eq!(plan, ReplicationPlan::Drop);
    }

    // ── Shared mock infrastructure ────────────────────────────────────────────

    type ExistingObject = Option<(Vec<Vec<u8>>, i64, String)>;

    /// Tracks all insert_object calls and optionally holds pre-seeded objects
    /// for get_object (used to test overwrite / delete ref-counting paths).
    struct MockObjectStore {
        inserted: Mutex<Option<(String, String, i64, String)>>,
        existing: Mutex<ExistingObject>,
        delete_calls: Mutex<Vec<(String, String)>>,
    }

    impl MockObjectStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inserted: Mutex::new(None),
                existing: Mutex::new(None),
                delete_calls: Mutex::new(vec![]),
            })
        }

        fn with_existing(blocks: Vec<Vec<u8>>, size: i64, etag: &str) -> Arc<Self> {
            let store = Self::new();
            *store.existing.lock().unwrap() = Some((blocks, size, etag.to_string()));
            store
        }
    }

    #[async_trait]
    impl ObjectStore for MockObjectStore {
        async fn insert_object(&self, bucket: &str, _shard_id: i32, key: &str, _blocks: Vec<Vec<u8>>, size: i64, etag: &str) -> Result<(), anyhow::Error> {
            *self.inserted.lock().unwrap() = Some((bucket.to_string(), key.to_string(), size, etag.to_string()));
            Ok(())
        }
        async fn get_object(&self, _b: &str, _k: &str) -> Result<Option<(Vec<Vec<u8>>, i64, String)>, anyhow::Error> {
            Ok(self.existing.lock().unwrap().clone())
        }
        async fn block_sizes(&self, hashes: &[Vec<u8>]) -> Result<Vec<i64>, anyhow::Error> {
            Ok(vec![0; hashes.len()])
        }
        async fn list_buckets(&self) -> Result<Vec<(String, i64)>, anyhow::Error> {
            Ok(vec![])
        }
        async fn list_objects(&self, _b: &str, _s: Option<&str>, _p: Option<&str>, _ps: usize) -> Result<(Vec<(String, i64, String)>, bool), anyhow::Error> {
            Ok((vec![], false))
        }
        async fn delete_object(&self, b: &str, k: &str) -> Result<(), anyhow::Error> {
            self.delete_calls.lock().unwrap().push((b.to_string(), k.to_string()));
            Ok(())
        }
        async fn create_multipart_upload(&self, _b: &str, _k: &str, _u: uuid::Uuid) -> Result<(), anyhow::Error> { Ok(()) }
        async fn get_multipart_upload_key(&self, _b: &str, _u: uuid::Uuid) -> Result<Option<String>, anyhow::Error> {
            // Return "k" to match the key used in complete_input().
            Ok(Some("k".to_string()))
        }
        async fn insert_part(&self, _b: &str, _u: uuid::Uuid, _n: i32, _bl: Vec<Vec<u8>>, _s: i64, _e: &str) -> Result<(), anyhow::Error> { Ok(()) }
        async fn list_parts(&self, _b: &str, _u: uuid::Uuid) -> Result<Vec<(i32, Vec<Vec<u8>>, i64, String)>, anyhow::Error> {
            // Return two small parts for multipart tests.
            Ok(vec![
                (1, vec![vec![0u8; 32]], 10, "aabbccdd".to_string()),
                (2, vec![vec![1u8; 32]], 10, "eeff0011".to_string()),
            ])
        }
        async fn delete_multipart_upload(&self, _b: &str, _u: uuid::Uuid) -> Result<(), anyhow::Error> { Ok(()) }
        async fn list_multipart_uploads(&self, _b: &str, _p: Option<&str>, _k: Option<&str>, _m: usize) -> Result<Vec<(String, String)>, anyhow::Error> {
            Ok(vec![])
        }
    }

    /// Tracks store/remove calls and the ref_ids seen so we can verify
    /// overwrite ref-counting behaviour.
    struct MockBlockStore {
        stored_count: Mutex<usize>,
        removed_refs: Mutex<Vec<String>>,
        added_usages: Mutex<Vec<String>>,
        // data returned by get_block
        block_data: Mutex<Bytes>,
    }

    impl MockBlockStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                stored_count: Mutex::new(0),
                removed_refs: Mutex::new(vec![]),
                added_usages: Mutex::new(vec![]),
                block_data: Mutex::new(Bytes::new()),
            })
        }

        fn with_data(data: Bytes) -> Arc<Self> {
            let s = Self::new();
            *s.block_data.lock().unwrap() = data;
            s
        }
    }

    #[async_trait]
    impl BlockStore for MockBlockStore {
        async fn store_block(&self, _data: Bytes, _size: i64, _ref_id: &str) -> Result<Vec<u8>, anyhow::Error> {
            *self.stored_count.lock().unwrap() += 1;
            Ok(vec![0u8; 32])
        }
        async fn get_block(&self, _hash: &[u8]) -> Result<Bytes, anyhow::Error> {
            Ok(self.block_data.lock().unwrap().clone())
        }
        async fn add_usage(&self, _hash: &[u8], ref_id: &str) -> Result<(), anyhow::Error> {
            self.added_usages.lock().unwrap().push(ref_id.to_string());
            Ok(())
        }
        async fn remove_reference(&self, _hash: &[u8], ref_id: &str) -> Result<(), anyhow::Error> {
            self.removed_refs.lock().unwrap().push(ref_id.to_string());
            Ok(())
        }
        async fn promote_local(&self, _hash: &[u8], _data: Bytes) -> Result<(), anyhow::Error> {
            Ok(())
        }
        async fn fetch_from_peer(&self, _peer_url: &str, _hash: &[u8]) -> Result<Bytes, anyhow::Error> {
            Ok(Bytes::new())
        }
        async fn delete_block(&self, _hash: &[u8], _fid: &[u8]) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    fn make_config() -> Config {
        Config {
            server: crate::config::ServerConfig {
                log_format: "text".to_string(),
                s3_bind_addr: "0.0.0.0:8014".to_string(),
                internal_bind_addr: "0.0.0.0:8015".to_string(),
                advertise_addr: "http://localhost:8014".to_string(),
                cluster_secret: "test-secret".to_string(),
                clock_offset_ms: 0,
                noise_private_key: crate::noise_transport::generate_private_key()
                    .expect("generate test noise key"),
            },
            database: crate::config::DatabaseConfig {
                db_path: ":memory:".to_string(),
            },
            storage: crate::config::StorageConfig {
                local_location_id: "test-site".to_string(),
                backend: crate::config::BlockBackend::Local { path: "/tmp/ss-test-blocks".to_string() },
                min_free_bytes: None,
                max_bytes: None,
                chunking: crate::config::ChunkingConfig::Fixed { max_block_size: 1024 * 1024 },
                gc_grace_period_seconds: 300,
                gc_interval_seconds: 60,
            },
        }
    }

    fn make_backend(
        objects: Arc<dyn ObjectStore>,
        blocks: Arc<dyn BlockStore>,
        chunk_size: usize,
    ) -> StorageBackend {
        StorageBackend {
            objects,
            blocks,
            chunker: Arc::new(FixedSizeStrategy { chunk_size }),
            config: make_config(),
            db: None,
            disk_guard: crate::disk::DiskGuard::disabled(),
        }
    }

    /// A backend backed by a real in-memory store, for exercising the GC reaper
    /// (which reads/writes the store directly). The block backend is a mock, so
    /// physical delete is a no-op — we assert on the metadata effects.
    async fn gc_backend(grace_secs: u64) -> (StorageBackend, Arc<Db>) {
        let clock = Arc::new(crate::clock::ClusterClock::new(0));
        let store = Arc::new(
            crate::store::Store::new(":memory:", "test-site".to_string(), clock)
                .await
                .unwrap(),
        );
        let mut config = make_config();
        config.storage.gc_grace_period_seconds = grace_secs;
        let backend = StorageBackend {
            objects: store.clone(),
            blocks: MockBlockStore::new(),
            chunker: Arc::new(FixedSizeStrategy { chunk_size: 1024 }),
            config,
            db: Some(store.clone()),
            disk_guard: crate::disk::DiskGuard::disabled(),
        };
        (backend, store)
    }

    fn gh(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[tokio::test]
    async fn local_blob_round_trip_and_sharded_path() {
        let root = std::env::temp_dir().join("ss-localblob-test-rt");
        let _ = std::fs::remove_dir_all(&root);
        let blob = LocalBlob { root: root.clone() };
        let hash = gh(0xAB);
        let data = Bytes::from_static(b"hello shardscape");

        blob.put(&hash, data.clone()).await.unwrap();
        // Sharded into aa/bb/<hex> by the first two hash bytes.
        let hex = hex::encode(&hash);
        let expected = root.join(&hex[0..2]).join(&hex[2..4]).join(&hex);
        assert!(expected.exists(), "block file should exist at sharded path");

        let got = blob.get(&hash, b"local").await.unwrap();
        assert_eq!(got, data);

        blob.delete(&hash, b"local").await.unwrap();
        assert!(!expected.exists());
        // Deleting a missing block is a harmless no-op.
        blob.delete(&hash, b"local").await.unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn gc_never_reaps_a_referenced_block() {
        let (backend, store) = gc_backend(0).await;
        store.store_local_block(&gh(1), b"3,01", 10).await.unwrap();
        store.insert_object("b", 0, "k", vec![gh(1)], 10, "e").await.unwrap();

        backend.reap_orphaned_blocks().await.unwrap(); // grace 0, but referenced
        assert!(
            store.get_local_block_fid(&gh(1)).await.unwrap().is_some(),
            "referenced block must survive GC"
        );
    }

    #[tokio::test]
    async fn gc_reaps_orphan_past_grace() {
        let (backend, store) = gc_backend(0).await;
        store.store_local_block(&gh(2), b"3,02", 10).await.unwrap();
        // No manifest references gh(2): it is an orphan. Grace 0 → reaped now.
        backend.reap_orphaned_blocks().await.unwrap();
        assert!(
            store.get_local_block_fid(&gh(2)).await.unwrap().is_none(),
            "orphan past grace must be reaped"
        );
    }

    #[tokio::test]
    async fn gc_respects_grace_then_force_overrides() {
        let (backend, store) = gc_backend(3600).await; // 1h grace
        store.store_local_block(&gh(3), b"3,03", 10).await.unwrap();

        // First sweep: orphan recorded but inside grace → still present.
        backend.reap_orphaned_blocks().await.unwrap();
        assert!(store.get_local_block_fid(&gh(3)).await.unwrap().is_some());

        // Forced sweep ignores grace and reaps the confirmed orphan.
        backend.force_sweep_orphaned_blocks().await.unwrap();
        assert!(store.get_local_block_fid(&gh(3)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn gc_cancels_pending_when_block_becomes_referenced_again() {
        let (backend, store) = gc_backend(3600).await;
        store.store_local_block(&gh(4), b"3,04", 10).await.unwrap();
        backend.reap_orphaned_blocks().await.unwrap(); // marks pending (within grace)
        assert_eq!(store.get_pending_deletions().await.unwrap().len(), 1);

        // A new object references it → next sweep cancels the pending reap.
        store.insert_object("b", 0, "k4", vec![gh(4)], 10, "e").await.unwrap();
        backend.reap_orphaned_blocks().await.unwrap();
        assert!(store.get_pending_deletions().await.unwrap().is_empty());
        assert!(store.get_local_block_fid(&gh(4)).await.unwrap().is_some());
    }

    fn put_input(bucket: &str, key: &str, data: Vec<u8>) -> PutObjectInput {
        PutObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            body: Some(StreamingBlob::from(Body::from(data))),
            acl: None, cache_control: None, content_disposition: None,
            content_encoding: None, content_language: None, content_length: None,
            content_md5: None, content_type: None, checksum_algorithm: None,
            checksum_crc32: None, checksum_crc32c: None, checksum_sha1: None,
            checksum_sha256: None, expires: None, grant_full_control: None,
            grant_read: None, grant_read_acp: None, grant_write_acp: None,
            metadata: None, server_side_encryption: None, storage_class: None,
            website_redirect_location: None, sse_customer_algorithm: None,
            sse_customer_key: None, sse_customer_key_md5: None,
            ssekms_key_id: None, ssekms_encryption_context: None,
            bucket_key_enabled: None, request_payer: None, tagging: None,
            object_lock_mode: None, object_lock_retain_until_date: None,
            object_lock_legal_hold_status: None, expected_bucket_owner: None,
            checksum_crc64nvme: None, if_match: None, if_none_match: None,
            write_offset_bytes: None,
        }
    }

    // ── disk guard ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn put_object_refused_when_disk_guard_tripped() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let mut backend = make_backend(objects.clone(), blocks.clone(), 10);
        backend.disk_guard = crate::disk::DiskGuard::tripped();

        let err = match backend
            .put_object(S3Request::new(put_input("b", "k", vec![0x41u8; 25])))
            .await
        {
            Ok(_) => panic!("write should be refused under disk pressure"),
            Err(e) => e,
        };
        assert_eq!(*err.code(), S3ErrorCode::ServiceUnavailable);
        // Nothing was written.
        assert_eq!(*blocks.stored_count.lock().unwrap(), 0);
        assert!(objects.inserted.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn put_object_refused_when_over_quota() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let mut backend = make_backend(objects.clone(), blocks.clone(), 10);
        backend.disk_guard = crate::disk::DiskGuard::over_quota();

        let err = match backend
            .put_object(S3Request::new(put_input("b", "k", vec![0x41u8; 25])))
            .await
        {
            Ok(_) => panic!("write should be refused when over quota"),
            Err(e) => e,
        };
        assert_eq!(*err.code(), S3ErrorCode::ServiceUnavailable);
        assert!(err.to_string().contains("quota"));
        assert_eq!(*blocks.stored_count.lock().unwrap(), 0);
        assert!(objects.inserted.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn put_object_allowed_when_guard_disabled() {
        // Sanity: the default test backend (disabled guard) still writes.
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);
        backend.put_object(S3Request::new(put_input("b", "k", vec![1, 2, 3]))).await.unwrap();
        assert!(objects.inserted.lock().unwrap().is_some());
    }

    // ── put_object ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn put_object_25_bytes_produces_3_blocks_and_correct_etag() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);

        let data = vec![0x41u8; 25]; // 'A' * 25
        let res = backend.put_object(S3Request::new(put_input("b", "k", data))).await.unwrap();

        assert_eq!(*blocks.stored_count.lock().unwrap(), 3); // 10 + 10 + 5
        let inserted = objects.inserted.lock().unwrap();
        let (bucket, key, size, etag) = inserted.as_ref().unwrap();
        assert_eq!(bucket, "b");
        assert_eq!(key, "k");
        assert_eq!(*size, 25);
        assert_eq!(etag, "1995da96cd16a48cebcbc08424f6f945");
        assert_eq!(res.output.e_tag.unwrap(), "\"1995da96cd16a48cebcbc08424f6f945\"");
    }

    #[tokio::test]
    async fn put_object_empty_body_produces_zero_blocks_and_stored() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);

        let res = backend.put_object(S3Request::new(put_input("b", "empty", vec![]))).await.unwrap();

        // No blocks to store.
        assert_eq!(*blocks.stored_count.lock().unwrap(), 0);
        let inserted = objects.inserted.lock().unwrap();
        let (_, _, size, _) = inserted.as_ref().unwrap();
        assert_eq!(*size, 0);
        // MD5 of empty string
        assert_eq!(res.output.e_tag.unwrap(), "\"d41d8cd98f00b204e9800998ecf8427e\"");
    }

    #[tokio::test]
    async fn put_object_single_byte() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);

        let res = backend.put_object(S3Request::new(put_input("b", "one", vec![0x61]))).await.unwrap();

        assert_eq!(*blocks.stored_count.lock().unwrap(), 1);
        let inserted = objects.inserted.lock().unwrap();
        let (_, _, size, _) = inserted.as_ref().unwrap();
        assert_eq!(*size, 1);
        // MD5 of a single byte 0x61 ('a') = 0cc175b9c0f1b6a831c399e269772661
        assert_eq!(res.output.e_tag.unwrap(), "\"0cc175b9c0f1b6a831c399e269772661\"");
    }

    #[tokio::test]
    async fn put_object_exact_chunk_boundary() {
        // Exactly 20 bytes with chunk_size=10 → 2 blocks, nothing in finalize.
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);

        backend.put_object(S3Request::new(put_input("b", "k", vec![0xBBu8; 20]))).await.unwrap();
        assert_eq!(*blocks.stored_count.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn put_object_overwrite_removes_old_block_references() {
        // Seed an existing object with one "block" hash.
        let old_hash = vec![0xAAu8; 32];
        let objects = MockObjectStore::with_existing(vec![old_hash.clone()], 10, "old-etag");
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 10);

        backend.put_object(S3Request::new(put_input("b", "k", vec![0x42u8; 5]))).await.unwrap();

        // remove_reference must have been called with the old ref_id.
        let removed = blocks.removed_refs.lock().unwrap();
        assert!(
            removed.iter().any(|r| r == "obj:b:k"),
            "expected remove_reference called with obj:b:k, got: {removed:?}"
        );
    }

    #[tokio::test]
    async fn put_object_etag_is_quoted_in_response() {
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        let res = backend.put_object(S3Request::new(put_input("b", "k", vec![1, 2, 3]))).await.unwrap();
        let etag = res.output.e_tag.unwrap();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "ETag must be quoted: {etag}");
    }

    // ── get_object ────────────────────────────────────────────────────────────

    fn get_input(bucket: &str, key: &str) -> GetObjectInput {
        GetObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            checksum_mode: None, expected_bucket_owner: None, if_match: None,
            if_modified_since: None, if_none_match: None, if_unmodified_since: None,
            part_number: None, range: None, request_payer: None,
            response_cache_control: None, response_content_disposition: None,
            response_content_encoding: None, response_content_language: None,
            response_content_type: None, response_expires: None,
            sse_customer_algorithm: None, sse_customer_key: None,
            sse_customer_key_md5: None, version_id: None,
        }
    }

    #[tokio::test]
    async fn get_object_returns_correct_size_and_etag() {
        let objects = MockObjectStore::with_existing(vec![vec![0u8; 32]], 42, "myetag");
        let blocks = MockBlockStore::with_data(Bytes::from(vec![0xCCu8; 42]));
        let backend = make_backend(objects, blocks, 64);

        let res = backend.get_object(S3Request::new(get_input("b", "k"))).await.unwrap();
        assert_eq!(res.output.content_length, Some(42));
        assert_eq!(res.output.e_tag, Some("\"myetag\"".to_string()));
    }

    #[tokio::test]
    async fn get_object_missing_key_returns_no_such_key() {
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        match backend.get_object(S3Request::new(get_input("b", "missing"))).await {
            Err(e) => assert_eq!(e.code(), &S3ErrorCode::NoSuchKey),
            Ok(_) => panic!("expected NoSuchKey error"),
        }
    }

    // ── delete_object ─────────────────────────────────────────────────────────

    fn delete_input(bucket: &str, key: &str) -> DeleteObjectInput {
        DeleteObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            bypass_governance_retention: None, expected_bucket_owner: None,
            if_match: None, if_match_last_modified_time: None, if_match_size: None,
            mfa: None, request_payer: None, version_id: None,
        }
    }

    #[tokio::test]
    async fn delete_object_removes_block_references() {
        let hash = vec![0xDDu8; 32];
        let objects = MockObjectStore::with_existing(vec![hash.clone()], 5, "e");
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 64);

        backend.delete_object(S3Request::new(delete_input("b", "k"))).await.unwrap();

        let removed = blocks.removed_refs.lock().unwrap();
        assert!(removed.iter().any(|r| r == "obj:b:k"), "remove_reference not called: {removed:?}");

        let deleted = objects.delete_calls.lock().unwrap();
        assert_eq!(deleted.as_slice(), &[("b".to_string(), "k".to_string())]);
    }

    #[tokio::test]
    async fn delete_object_missing_key_still_succeeds() {
        let objects = MockObjectStore::new();
        let backend = make_backend(objects.clone(), MockBlockStore::new(), 64);

        backend.delete_object(S3Request::new(delete_input("b", "ghost"))).await.unwrap();

        let deleted = objects.delete_calls.lock().unwrap();
        assert_eq!(deleted.as_slice(), &[("b".to_string(), "ghost".to_string())]);
    }

    // ── delete_objects (batch) ────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_objects_batch_all_succeed() {
        let objects = MockObjectStore::new();
        let backend = make_backend(objects.clone(), MockBlockStore::new(), 64);

        let input = DeleteObjectsInput {
            bucket: "b".to_string(),
            delete: Delete {
                objects: vec![
                    ObjectIdentifier { key: "k1".to_string(), e_tag: None, last_modified_time: None, size: None, version_id: None },
                    ObjectIdentifier { key: "k2".to_string(), e_tag: None, last_modified_time: None, size: None, version_id: None },
                ],
                quiet: None,
            },
            bypass_governance_retention: None, checksum_algorithm: None,
            expected_bucket_owner: None, mfa: None, request_payer: None,
        };
        let res = backend.delete_objects(S3Request::new(input)).await.unwrap();
        let deleted = res.output.deleted.unwrap_or_default();
        assert_eq!(deleted.len(), 2);
        let errors = res.output.errors.unwrap_or_default();
        assert!(errors.is_empty());
    }

    // ── head_object ───────────────────────────────────────────────────────────

    fn head_input(bucket: &str, key: &str) -> HeadObjectInput {
        HeadObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            checksum_mode: None, expected_bucket_owner: None, if_match: None,
            if_modified_since: None, if_none_match: None, if_unmodified_since: None,
            part_number: None, range: None, request_payer: None,
            response_cache_control: None, response_content_disposition: None,
            response_content_encoding: None, response_content_language: None,
            response_content_type: None, response_expires: None,
            sse_customer_algorithm: None, sse_customer_key: None,
            sse_customer_key_md5: None, version_id: None,
        }
    }

    #[tokio::test]
    async fn head_object_returns_size_and_etag_without_body() {
        let objects = MockObjectStore::with_existing(vec![vec![0u8; 32]], 99, "headetag");
        let backend = make_backend(objects, MockBlockStore::new(), 64);

        let res = backend.head_object(S3Request::new(head_input("b", "k"))).await.unwrap();
        assert_eq!(res.output.content_length, Some(99));
        assert_eq!(res.output.e_tag, Some("\"headetag\"".to_string()));
    }

    #[tokio::test]
    async fn head_object_missing_returns_no_such_key() {
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        match backend.head_object(S3Request::new(head_input("b", "gone"))).await {
            Err(e) => assert_eq!(e.code(), &S3ErrorCode::NoSuchKey),
            Ok(_) => panic!("expected NoSuchKey error"),
        }
    }

    // ── list_objects_v2 ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_objects_v2_empty_bucket() {
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        let input = ListObjectsV2Input {
            bucket: "b".to_string(),
            continuation_token: None, delimiter: None, encoding_type: None,
            expected_bucket_owner: None, fetch_owner: None, max_keys: None,
            optional_object_attributes: vec![],
            prefix: None, request_payer: None, start_after: None,
        };
        let res = backend.list_objects_v2(S3Request::new(input)).await.unwrap();
        assert_eq!(res.output.key_count, Some(0));
        assert_eq!(res.output.is_truncated, Some(false));
    }

    // ── complete_multipart_upload ─────────────────────────────────────────────

    fn complete_input(bucket: &str, key: &str, upload_id: &str) -> CompleteMultipartUploadInput {
        CompleteMultipartUploadInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            multipart_upload: Some(CompletedMultipartUpload {
                parts: Some(vec![
                    CompletedPart { part_number: Some(1), e_tag: Some("\"aabbccdd\"".to_string()), checksum_crc32: None, checksum_crc32c: None, checksum_crc64nvme: None, checksum_sha1: None, checksum_sha256: None },
                    CompletedPart { part_number: Some(2), e_tag: Some("\"eeff0011\"".to_string()), checksum_crc32: None, checksum_crc32c: None, checksum_crc64nvme: None, checksum_sha1: None, checksum_sha256: None },
                ]),
            }),
            checksum_crc32: None, checksum_crc32c: None, checksum_crc64nvme: None,
            checksum_sha1: None, checksum_sha256: None, checksum_type: None,
            expected_bucket_owner: None, if_match: None, if_none_match: None,
            mpu_object_size: None, request_payer: None, sse_customer_algorithm: None,
            sse_customer_key: None, sse_customer_key_md5: None,
        }
    }

    #[tokio::test]
    async fn complete_multipart_upload_assembles_parts_and_stores_object() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 64);

        let upload_id = uuid::Uuid::new_v4();
        let res = backend.complete_multipart_upload(S3Request::new(
            complete_input("b", "k", &upload_id.to_string())
        )).await.unwrap();

        assert!(res.output.e_tag.is_some(), "expected an ETag in the response");
        assert!(objects.inserted.lock().unwrap().is_some(), "insert_object was never called");
    }

    #[tokio::test]
    async fn complete_multipart_upload_swaps_upload_ref_for_object_ref() {
        let objects = MockObjectStore::new();
        let blocks = MockBlockStore::new();
        let backend = make_backend(objects.clone(), blocks.clone(), 64);

        let upload_id = uuid::Uuid::new_v4();
        backend.complete_multipart_upload(S3Request::new(
            complete_input("b", "k", &upload_id.to_string())
        )).await.unwrap();

        let added = blocks.added_usages.lock().unwrap();
        let removed = blocks.removed_refs.lock().unwrap();

        assert!(added.iter().any(|r| r == "obj:b:k"), "obj ref not added: {added:?}");
        assert!(
            removed.iter().any(|r| r == &format!("upload:b:{upload_id}")),
            "upload ref not removed: {removed:?}"
        );
    }

    #[tokio::test]
    async fn complete_multipart_upload_rejects_key_mismatch() {
        // The stored key is "k" (from the mock) but the request says "different-key".
        // This should be rejected to prevent auth bypass.
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        let upload_id = uuid::Uuid::new_v4();
        let mut input = complete_input("b", "different-key", &upload_id.to_string());
        input.key = "different-key".to_string();
        match backend.complete_multipart_upload(S3Request::new(input)).await {
            Err(e) => assert_eq!(e.code(), &S3ErrorCode::InvalidRequest),
            Ok(_) => panic!("expected InvalidRequest error for key mismatch"),
        }
    }

    // ── abort_multipart_upload ────────────────────────────────────────────────

    #[tokio::test]
    async fn abort_multipart_upload_succeeds() {
        let backend = make_backend(MockObjectStore::new(), MockBlockStore::new(), 64);
        let upload_id = uuid::Uuid::new_v4();
        let input = AbortMultipartUploadInput {
            bucket: "b".to_string(),
            key: "k".to_string(),
            upload_id: upload_id.to_string(),
            expected_bucket_owner: None, if_match_initiated_time: None, request_payer: None,
        };
        backend.abort_multipart_upload(S3Request::new(input)).await.unwrap();
    }

    // ── deterministic ETag across chunk strategies ────────────────────────────

    #[tokio::test]
    async fn put_object_etag_independent_of_chunk_size() {
        // MD5 is computed on the raw bytes, not the chunks, so different
        // chunk sizes must produce the same ETag.
        let data = vec![0x42u8; 100];

        async fn etag_for_chunk_size(data: Vec<u8>, chunk: usize) -> String {
            let b = make_backend(MockObjectStore::new(), MockBlockStore::new(), chunk);
            let res = b.put_object(S3Request::new(put_input("b", "k", data))).await.unwrap();
            res.output.e_tag.unwrap()
        }

        let e1 = etag_for_chunk_size(data.clone(), 10).await;
        let e2 = etag_for_chunk_size(data.clone(), 50).await;
        let e3 = etag_for_chunk_size(data.clone(), 200).await;
        assert_eq!(e1, e2);
        assert_eq!(e2, e3);
    }
}
