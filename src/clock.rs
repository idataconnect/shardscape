use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A clock that tracks an offset relative to the cluster leader to ensure
/// causal consistency across locations even with system clock drift.
pub struct ClusterClock {
    offset_ms: AtomicI64,
}

impl ClusterClock {
    pub fn new(offset_ms: i64) -> Self {
        Self {
            offset_ms: AtomicI64::new(offset_ms),
        }
    }

    /// Updates the local clock offset relative to the cluster leader.
    /// Offset = (LeaderTime - LocalTime)
    pub fn set_offset(&self, offset_ms: i64) {
        self.offset_ms.store(offset_ms, Ordering::Relaxed);
    }

    pub fn get_offset(&self) -> i64 {
        self.offset_ms.load(Ordering::Relaxed)
    }

    /// Returns the current cluster-synchronized time in microseconds. This is the
    /// LWW timestamp stamped onto every mutating row and replicated fact.
    pub fn now_micros(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| e.duration())
            .as_micros() as i64;
        now + (self.offset_ms.load(Ordering::Relaxed) * 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_offset_returns_approx_unix_micros() {
        let clock = ClusterClock::new(0);
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let t = clock.now_micros();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        assert!(t >= before, "clock went backwards vs before");
        assert!(t <= after, "clock jumped ahead of after");
    }

    #[test]
    fn positive_offset_shifts_time_forward() {
        let clock = ClusterClock::new(1000); // +1 second
        let now_raw = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let t = clock.now_micros();
        // Should be roughly now + 1_000_000 µs; allow 100 ms slop.
        assert!(t >= now_raw + 900_000);
        assert!(t <= now_raw + 1_100_000);
    }

    #[test]
    fn negative_offset_shifts_time_backward() {
        let clock = ClusterClock::new(-1000); // -1 second
        let now_raw = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let t = clock.now_micros();
        assert!(t >= now_raw - 1_100_000);
        assert!(t <= now_raw - 900_000);
    }

    #[test]
    fn set_offset_updates_immediately() {
        let clock = ClusterClock::new(0);
        assert_eq!(clock.get_offset(), 0);
        clock.set_offset(500);
        assert_eq!(clock.get_offset(), 500);
        clock.set_offset(-200);
        assert_eq!(clock.get_offset(), -200);
    }

    #[test]
    fn now_micros_is_monotone_under_zero_offset() {
        // Without artificial delays, two sequential calls should be non-decreasing.
        let clock = ClusterClock::new(0);
        let t1 = clock.now_micros();
        let t2 = clock.now_micros();
        assert!(t2 >= t1);
    }

    #[test]
    fn large_positive_offset() {
        // 86_400_000 ms = 1 day; make sure arithmetic doesn't overflow.
        let clock = ClusterClock::new(86_400_000);
        let t = clock.now_micros();
        assert!(t > 0);
    }

    #[test]
    fn now_micros_reflects_updated_offset() {
        let clock = ClusterClock::new(0);
        let t0 = clock.now_micros();
        clock.set_offset(10_000); // +10 seconds
        let t1 = clock.now_micros();
        // t1 should be at least 9.9 s ahead of t0.
        assert!(t1 - t0 >= 9_900_000, "offset change not reflected: t1={t1}, t0={t0}");
    }
}
