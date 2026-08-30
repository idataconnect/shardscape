use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub log_format: String,
    pub s3_bind_addr: String,
    #[serde(default = "default_internal_bind_addr")]
    pub internal_bind_addr: String,
    pub advertise_addr: String,
    pub cluster_secret: String,
    #[serde(default)]
    pub clock_offset_ms: i64,
    /// Base64-encoded 32-byte Curve25519 private key. Generated on first boot.
    #[serde(default)]
    pub noise_private_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// Filesystem path to this site's embedded metadata store (SQLite).
    pub db_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageConfig {
    pub local_location_id: String,
    /// Where block bytes physically live. Defaults to a local filesystem CAS so
    /// the single-binary deployment needs no external daemon; SeaweedFS remains
    /// available for deployments that want volume packing / compaction.
    #[serde(default = "default_block_backend")]
    pub backend: BlockBackend,
    /// Refuse new writes once the data volume has less than this much free space,
    /// to keep the node off the OS out-of-disk (ENOSPC) cliff. Accepts sizes like
    /// "10Gi", "500Mi", "1Ti", or a plain byte count. Omit/empty to disable.
    /// The reserve doubles as the headroom that keeps SQLite and GC working while
    /// the node is refusing data, so it can always reclaim and recover.
    #[serde(default)]
    pub min_free_bytes: Option<String>,
    /// Hard cap on total block bytes stored locally. Once local usage reaches this
    /// limit, new writes and replication pulls are refused (503) until deletes or
    /// GC bring usage back under the cap. Accepts "500Gi", "1Ti", etc. Omit to
    /// disable (no cap).
    #[serde(default)]
    pub max_bytes: Option<String>,
    pub chunking: ChunkingConfig,
    pub gc_grace_period_seconds: u64,
    pub gc_interval_seconds: u64,
}

/// Physical block-storage backend.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum BlockBackend {
    /// Content-addressed files in a sharded directory tree on local disk.
    #[serde(rename = "local")]
    Local { path: String },
    /// External SeaweedFS cluster (master assigns fids; volume holds bytes).
    #[serde(rename = "seaweed")]
    Seaweed {
        master_url: String,
        volume_url: String,
    },
}

fn default_block_backend() -> BlockBackend {
    BlockBackend::Local { path: "blocks".to_string() }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ChunkingConfig {
    #[serde(rename = "fixed")]
    Fixed {
        max_block_size: usize,
    },
    #[serde(rename = "cdc")]
    Cdc {
        min_block_size: usize,
        avg_block_size: usize,
        max_block_size: usize,
    },
}

fn default_internal_bind_addr() -> String {
    "0.0.0.0:8015".to_string()
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read config file")?;
        let config = toml::from_str(&content).context("Failed to parse TOML config")?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;
        fs::write(path, content).context("Failed to write config file")?;
        Ok(())
    }

    pub fn default() -> Self {
        Self {
            server: ServerConfig {
                log_format: "text".to_string(),
                s3_bind_addr: "0.0.0.0:8014".to_string(),
                internal_bind_addr: default_internal_bind_addr(),
                advertise_addr: "http://localhost:8014".to_string(),
                cluster_secret: "default-cluster-secret".to_string(),
                clock_offset_ms: 0,
                noise_private_key: String::new(),
            },
            database: DatabaseConfig {
                db_path: "shardscape.db".to_string(),
            },
            storage: StorageConfig {
                local_location_id: "default".to_string(),
                backend: default_block_backend(),
                min_free_bytes: Some("10Gi".to_string()),
                max_bytes: None,
                chunking: ChunkingConfig::Fixed {
                    max_block_size: 10 * 1024 * 1024,
                },
                gc_grace_period_seconds: 300, // 5 minutes
                gc_interval_seconds: 60,      // 1 minute
            },
        }
    }
}
