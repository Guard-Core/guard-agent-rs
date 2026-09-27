//! Local client-side send rate limiter.
//!
//! Mirrors the Python agent's `RateLimiter` (`guard_agent/utils.py:309-337`)
//! and its pre-check in the retry loop
//! (`guard_agent/_transport_send.py:197-203`): a sliding-window limiter that
//! gates every outgoing POST so a misbehaving endpoint cannot absorb unbounded
//! request volume. The transport defaults to 100 calls per 60-second window,
//! matching the TypeScript and PHP agents. Unlike the server-side 429 path,
//! a local limiter rejection is not an error: the caller sleeps the reported
//! `retry_after` and re-enters the retry loop.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window rate limiter for agent sends.
///
/// `acquire` admits a call and records its timestamp when the number of calls
/// inside the window is below `max_calls`; `retry_after` reports how long
/// until the oldest recorded call leaves the window.
pub struct RateLimiter {
    max_calls: usize,
    time_window: Duration,
    calls: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    /// Builds a limiter admitting `max_calls` per `time_window`.
    #[must_use]
    pub const fn new(max_calls: usize, time_window: Duration) -> Self {
        Self {
            max_calls,
            time_window,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Checks whether an operation is allowed under the rate limit,
    /// recording the call when it is admitted.
    pub fn acquire(&self) -> bool {
        let now = Instant::now();
        let mut calls = self.calls.lock().expect("rate limiter lock poisoned");
        calls.retain(|call_time| now.duration_since(*call_time) < self.time_window);
        if calls.len() < self.max_calls {
            calls.push(now);
            true
        } else {
            false
        }
    }

    /// Returns the seconds to wait before the next call is allowed; zero
    /// when nothing has been recorded.
    pub fn retry_after(&self) -> f64 {
        let calls = self.calls.lock().expect("rate limiter lock poisoned");
        let Some(&oldest) = calls.iter().min() else {
            return 0.0;
        };
        let elapsed = oldest.elapsed().as_secs_f64();
        (self.time_window.as_secs_f64() - elapsed).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(max_calls: usize, window_secs: u64) -> RateLimiter {
        RateLimiter::new(max_calls, Duration::from_secs(window_secs))
    }

    #[tokio::test]
    async fn admits_up_to_max_calls_then_blocks() {
        let limiter = limiter(3, 60);
        assert!(limiter.acquire());
        assert!(limiter.acquire());
        assert!(limiter.acquire());
        assert!(!limiter.acquire(), "call past the cap must be rejected");
    }

    #[tokio::test]
    async fn window_slide_re_admits_calls() {
        let limiter = limiter(1, 1);
        assert!(limiter.acquire());
        assert!(!limiter.acquire());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(limiter.acquire(), "call leaves the window and re-admits");
    }

    #[tokio::test]
    async fn retry_after_is_zero_when_idle_and_bounded_by_window() {
        let limiter = limiter(2, 60);
        assert!(limiter.retry_after().abs() < f64::EPSILON, "idle limiter");
        assert!(limiter.acquire());
        let wait = limiter.retry_after();
        assert!(wait > 0.0 && wait <= 60.0, "wait {wait} out of range");
    }

    #[tokio::test]
    async fn retry_after_never_goes_negative() {
        let limiter = limiter(1, 1);
        assert!(limiter.acquire());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(limiter.retry_after().abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn rejected_calls_are_not_recorded() {
        let limiter = limiter(1, 1);
        assert!(limiter.acquire());
        assert!(!limiter.acquire());
        // The rejected call must not extend the window: after it expires the
        // retry-after is zero again.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(limiter.retry_after().abs() < f64::EPSILON);
        assert!(limiter.acquire());
    }
}
