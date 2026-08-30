//! Disk-space write guard.
//!
//! A safety floor that keeps the node off the OS out-of-disk (`ENOSPC`) cliff.
//! When the data volume drops below `min_free_bytes` free, the node:
//!   - refuses local S3 writes (the S3 layer returns 503), and
//!   - pauses pulling replicated blocks (the drainer skips a cycle).
//!
//! It does NOT pause metadata application or GC — that's the point of a *reserve*
//! rather than a hard stop: the headroom keeps SQLite's WAL, fact application,
//! and the GC reaper working, so the node can always reclaim space and recover.
//! A node that trips the guard falls *behind* (it still knows every object via
//! metadata, and reads fall back to cross-site fetch); it never corrupts, and it
//! catches up once space frees.
//!
//! Free space is sampled with `statvfs` and cached in an atomic, refreshed by a
//! background task, so the hot write path is a single atomic load.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::warn;

use crate::config::Config;

/// Parses a human size like "10Gi", "500Mi", "1Ti", "2GB", or a plain byte count.
/// Binary units (Ki/Mi/Gi/Ti) are powers of 1024; decimal (K/M/G/T, KB/MB/…) are
/// powers of 1000; a bare number (or "B") is bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty size");
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid number in size '{s}'"))?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "ki" | "kib" => 1024.0,
        "m" | "mb" => 1e6,
        "mi" | "mib" => 1024f64.powi(2),
        "g" | "gb" => 1e9,
        "gi" | "gib" => 1024f64.powi(3),
        "t" | "tb" => 1e12,
        "ti" | "tib" => 1024f64.powi(4),
        other => anyhow::bail!("unknown size unit '{other}' in '{s}'"),
    };
    Ok((n * mult) as u64)
}

/// Human-readable byte count (binary units), e.g. "9.7Gi".
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "Ki", "Mi", "Gi", "Ti"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes}{}", UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[u])
    }
}

/// Bytes free for unprivileged users on the filesystem containing `path`.
fn statvfs_free(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `c` is a valid NUL-terminated path; `s` is fully initialised by a
    // successful statvfs before we read it.
    unsafe {
        let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if libc::statvfs(c.as_ptr(), s.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let s = s.assume_init();
        Ok(s.f_bavail * s.f_frsize)
    }
}

/// Why writes are currently refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardTrip {
    /// Free disk space fell below the configured reserve.
    LowFreeSpace,
    /// Local block usage exceeds the configured cap.
    OverQuota,
}

/// Write guard over the data volume. Cheap to clone (shares the cached reading).
#[derive(Clone)]
pub struct DiskGuard {
    path: PathBuf,
    min_free_bytes: u64, // 0 = disabled
    free: Arc<AtomicU64>,
    max_bytes: u64,      // 0 = disabled
    local_usage: Arc<AtomicU64>,
}

impl DiskGuard {
    /// Builds the guard from config: parses `min_free_bytes` and `max_bytes`,
    /// watching the filesystem holding the metadata DB (which, for the local
    /// block backend, is the same volume the blocks live on). A bad size string
    /// disables that limiter with a warning rather than blocking the node.
    pub fn from_config(config: &Config) -> Self {
        let min = match config.storage.min_free_bytes.as_deref() {
            None | Some("") => 0,
            Some(s) => match parse_size(s) {
                Ok(v) => v,
                Err(e) => {
                    warn!("invalid storage.min_free_bytes '{s}': {e}; disabling disk write guard");
                    0
                }
            },
        };
        let max = match config.storage.max_bytes.as_deref() {
            None | Some("") => 0,
            Some(s) => match parse_size(s) {
                Ok(v) => v,
                Err(e) => {
                    warn!("invalid storage.max_bytes '{s}': {e}; disabling usage cap");
                    0
                }
            },
        };
        let path = Path::new(&config.database.db_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let guard = Self {
            path,
            min_free_bytes: min,
            free: Arc::new(AtomicU64::new(u64::MAX)),
            max_bytes: max,
            local_usage: Arc::new(AtomicU64::new(0)),
        };
        guard.refresh();
        guard
    }

    /// A disabled guard (no limit) — for tests and the no-DB code paths.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            path: PathBuf::from("."),
            min_free_bytes: 0,
            free: Arc::new(AtomicU64::new(u64::MAX)),
            max_bytes: 0,
            local_usage: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A guard tripped by low free space — test helper.
    #[cfg(test)]
    pub fn tripped() -> Self {
        Self {
            path: PathBuf::from("."),
            min_free_bytes: u64::MAX,
            free: Arc::new(AtomicU64::new(0)),
            max_bytes: 0,
            local_usage: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A guard tripped by exceeding the usage quota — test helper.
    #[cfg(test)]
    pub fn over_quota() -> Self {
        Self {
            path: PathBuf::from("."),
            min_free_bytes: 0,
            free: Arc::new(AtomicU64::new(u64::MAX)),
            max_bytes: 100,
            local_usage: Arc::new(AtomicU64::new(200)),
        }
    }

    /// Re-sample free space. On error keeps the last reading (fail-open).
    pub fn refresh(&self) {
        if self.min_free_bytes > 0 {
            match statvfs_free(&self.path) {
                Ok(f) => self.free.store(f, Ordering::Relaxed),
                Err(e) => tracing::debug!("statvfs({}) failed: {e}", self.path.display()),
            }
        }
    }

    /// Update the cached local block usage (called by the background refresher
    /// with a value computed from the DB).
    pub fn set_local_usage(&self, bytes: u64) {
        self.local_usage.store(bytes, Ordering::Relaxed);
    }

    /// Spawns a background task that refreshes the free-space reading on an
    /// interval. Usage refresh is driven separately (it needs a DB query).
    pub fn spawn_refresher(&self, interval: Duration) {
        if !self.enabled() {
            return;
        }
        let g = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                g.refresh();
            }
        });
    }

    pub fn enabled(&self) -> bool {
        self.min_free_bytes > 0 || self.max_bytes > 0
    }

    pub fn free_space_enabled(&self) -> bool {
        self.min_free_bytes > 0
    }

    pub fn quota_enabled(&self) -> bool {
        self.max_bytes > 0
    }

    pub fn min_free_bytes(&self) -> u64 {
        self.min_free_bytes
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Last sampled free bytes (cached).
    pub fn free_bytes(&self) -> u64 {
        self.free.load(Ordering::Relaxed)
    }

    /// Last sampled local block usage (cached).
    pub fn local_usage(&self) -> u64 {
        self.local_usage.load(Ordering::Relaxed)
    }

    /// If writes are refused, returns the reason. `None` means writes are allowed.
    pub fn check(&self) -> Option<GuardTrip> {
        if self.min_free_bytes > 0 && self.free_bytes() < self.min_free_bytes {
            return Some(GuardTrip::LowFreeSpace);
        }
        if self.max_bytes > 0 && self.local_usage() >= self.max_bytes {
            return Some(GuardTrip::OverQuota);
        }
        None
    }

    /// Whether new data may be written. Always true when both limits are disabled.
    #[allow(dead_code)]
    pub fn writes_allowed(&self) -> bool {
        self.check().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
        assert_eq!(parse_size("10Gi").unwrap(), 10 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("500Mi").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_size("1Ti").unwrap(), 1024u64.pow(4));
        assert_eq!(parse_size("2GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_size("1.5Gi").unwrap(), (1.5 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert!(parse_size("").is_err());
        assert!(parse_size("10Xy").is_err());
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn format_bytes_is_human() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.0Ki");
        assert_eq!(format_bytes(10 * 1024 * 1024 * 1024), "10.0Gi");
    }

    #[test]
    fn disabled_guard_always_allows() {
        let g = DiskGuard::disabled();
        assert!(!g.enabled());
        assert!(g.writes_allowed());
        assert_eq!(g.check(), None);
    }

    #[test]
    fn guard_trips_below_reserve() {
        let g = DiskGuard {
            path: PathBuf::from("."),
            min_free_bytes: 1u64 << 60,
            free: Arc::new(AtomicU64::new(0)),
            max_bytes: 0,
            local_usage: Arc::new(AtomicU64::new(0)),
        };
        g.refresh();
        assert!(g.enabled());
        assert!(!g.writes_allowed(), "guard should trip when free < reserve");
        assert_eq!(g.check(), Some(GuardTrip::LowFreeSpace));

        g.free.store(u64::MAX, Ordering::Relaxed);
        assert!(g.writes_allowed());
    }

    #[test]
    fn guard_trips_over_quota() {
        let g = DiskGuard::over_quota();
        assert!(g.enabled());
        assert!(!g.writes_allowed());
        assert_eq!(g.check(), Some(GuardTrip::OverQuota));

        g.set_local_usage(50);
        assert!(g.writes_allowed());
        assert_eq!(g.check(), None);
    }

    #[test]
    fn guard_free_space_checked_first() {
        let g = DiskGuard {
            path: PathBuf::from("."),
            min_free_bytes: 1u64 << 60,
            free: Arc::new(AtomicU64::new(0)),
            max_bytes: 100,
            local_usage: Arc::new(AtomicU64::new(200)),
        };
        assert_eq!(g.check(), Some(GuardTrip::LowFreeSpace));
    }
}
