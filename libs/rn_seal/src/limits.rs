use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 每个来源 IP 每秒允许的数据报数。
pub const PER_IP_PER_SEC: u32 = 20;
/// 来源 IP 表的容量上限，超过后按最早过期项清理。
const BUCKET_CAP: usize = 8192;
/// 一次清理视为过期的窗口。
const STALE_WINDOW: Duration = Duration::from_secs(60);

struct Bucket {
    window: Instant,
    count: u32,
}

/// 简单的每 IP 令牌桶。`mac1` 校验通过之后才计数。
pub struct RateLimiter {
    buckets: HashMap<IpAddr, Bucket>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// 一秒钟窗口内计数。超限返回 `false`。
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    pub fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.buckets.len() >= BUCKET_CAP && !self.buckets.contains_key(&ip) {
            self.buckets
                .retain(|_, bucket| now.duration_since(bucket.window) < STALE_WINDOW);
            // 桶表是硬上限：清理后仍然满就不接受新来源 IP。
            if self.buckets.len() >= BUCKET_CAP {
                return false;
            }
        }
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            window: now,
            count: 0,
        });
        if now.duration_since(bucket.window) >= Duration::from_secs(1) {
            bucket.window = now;
            bucket.count = 0;
        }
        if bucket.count >= PER_IP_PER_SEC {
            return false;
        }
        bucket.count += 1;
        true
    }
}

/// 在途握手计数。上限是工作线程数的两倍。
pub struct Inflight {
    active: usize,
    cap: usize,
}

impl Inflight {
    pub fn new(workers: usize) -> Self {
        Self {
            active: 0,
            cap: (workers.max(1)) * 2,
        }
    }

    pub fn try_acquire(&mut self) -> bool {
        if self.active >= self.cap {
            return false;
        }
        self.active += 1;
        true
    }

    pub fn release(&mut self) {
        self.active = self.active.saturating_sub(1);
    }

    pub fn active(&self) -> usize {
        self.active
    }

    pub fn cap(&self) -> usize {
        self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_limit_resets_after_one_second() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..PER_IP_PER_SEC {
            assert!(limiter.allow_at(ip, now));
        }
        assert!(!limiter.allow_at(ip, now));
        assert!(limiter.allow_at(ip, now + Duration::from_secs(1)));
    }

    #[test]
    fn bucket_table_is_a_hard_cap() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();
        for index in 0..BUCKET_CAP {
            let ip: IpAddr = format!("10.1.{}.{}", index / 256, index % 256)
                .parse()
                .unwrap();
            assert!(limiter.allow_at(ip, now));
        }
        let fresh: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(!limiter.allow_at(fresh, now));
        // 窗口过期后腾出位置。
        assert!(limiter.allow_at(fresh, now + STALE_WINDOW));
    }
}
