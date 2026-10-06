//! Token buckets, in memory, one per key.
//!
//! Synchronous and allocation-light on purpose: `check` runs inside
//! `NostrConnectSignerActions::approve`, which may not await and may not do I/O.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

use serde::Deserialize;

/// Upper bound on tracked keys. Beyond it, idle keys are forgotten; if none are idle, new
/// keys are refused — memory stays bounded even under a flood of fresh caller keys.
const MAX_TRACKED: usize = 10_000;

/// `burst` requests at once, then `per_second` sustained.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateConfig {
    pub burst: u32,
    pub per_second: f64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
pub struct RateLimiter<K> {
    burst: f64,
    per_second: f64,
    max_tracked: usize,
    buckets: Mutex<HashMap<K, Bucket>>,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    pub fn new(config: RateConfig) -> Self {
        Self::with_max_tracked(config, MAX_TRACKED)
    }

    fn with_max_tracked(config: RateConfig, max_tracked: usize) -> Self {
        Self {
            burst: f64::from(config.burst),
            per_second: config.per_second,
            max_tracked,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `key`. `false` means the request must be refused.
    pub fn check(&self, key: &K) -> bool {
        self.check_at(key, Instant::now())
    }

    /// Same as `check`, with the clock injected so tests are deterministic.
    fn check_at(&self, key: &K, now: Instant) -> bool {
        // A panic elsewhere must not switch rate limiting off: recover the guard.
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        if buckets.len() >= self.max_tracked && !buckets.contains_key(key) {
            let (burst, rate) = (self.burst, self.per_second);
            // A bucket that has refilled to the brim carries no information: forgetting
            // it is indistinguishable from keeping it.
            buckets.retain(|_, b| level(b, now, rate) < burst);
            if buckets.len() >= self.max_tracked {
                return false;
            }
        }

        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        bucket.tokens = level(bucket, now, self.per_second).min(self.burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Tokens in `b` at `now`, before capping.
fn level(b: &Bucket, now: Instant, per_second: f64) -> f64 {
    b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * per_second
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn limiter(burst: u32, per_second: f64) -> RateLimiter<u32> {
        RateLimiter::new(RateConfig { burst, per_second })
    }

    #[test]
    fn allows_the_burst_then_refuses() {
        let l = limiter(3, 1.0);
        let t = Instant::now();
        assert!(l.check_at(&1, t));
        assert!(l.check_at(&1, t));
        assert!(l.check_at(&1, t));
        assert!(!l.check_at(&1, t));
    }

    #[test]
    fn refills_at_the_configured_rate() {
        let l = limiter(1, 2.0);
        let t = Instant::now();
        assert!(l.check_at(&1, t));
        assert!(!l.check_at(&1, t));
        // 2 tokens per second: half a second gives one back.
        assert!(l.check_at(&1, t + Duration::from_millis(500)));
    }

    #[test]
    fn never_refills_beyond_the_burst() {
        let l = limiter(2, 100.0);
        let t = Instant::now();
        let later = t + Duration::from_secs(3600);
        assert!(l.check_at(&1, later));
        assert!(l.check_at(&1, later));
        assert!(!l.check_at(&1, later));
    }

    #[test]
    fn keys_do_not_share_a_bucket() {
        let l = limiter(1, 0.001);
        let t = Instant::now();
        assert!(l.check_at(&1, t));
        assert!(!l.check_at(&1, t));
        assert!(l.check_at(&2, t));
    }

    #[test]
    fn idle_keys_are_forgotten_when_the_table_is_full() {
        let l = RateLimiter::with_max_tracked(
            RateConfig {
                burst: 1,
                per_second: 1.0,
            },
            2,
        );
        let t = Instant::now();
        assert!(l.check_at(&1, t));
        assert!(l.check_at(&2, t));
        // Both buckets are full again ten seconds later, so key 3 evicts them.
        assert!(l.check_at(&3, t + Duration::from_secs(10)));
    }

    #[test]
    fn a_full_table_of_active_keys_refuses_newcomers() {
        let l = RateLimiter::with_max_tracked(
            RateConfig {
                burst: 1,
                per_second: 0.001,
            },
            2,
        );
        let t = Instant::now();
        assert!(l.check_at(&1, t));
        assert!(l.check_at(&2, t));
        // Nobody has refilled: evicting would erase live state, so the newcomer is refused.
        assert!(!l.check_at(&3, t));
    }
}
