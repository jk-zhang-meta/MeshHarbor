//! macOS privacy probes are expensive on the input path. Keep a positive grant
//! for this process and retry a negative result at most once per second.
use std::time::{Duration, Instant};

pub(crate) struct GrantCache {
    granted: bool,
    checked: Option<Instant>,
}

impl GrantCache {
    pub(crate) const fn new() -> Self {
        Self {
            granted: false,
            checked: None,
        }
    }

    pub(crate) fn query(&mut self, now: Instant, probe: impl FnOnce() -> bool) -> bool {
        if self.granted {
            return true;
        }
        if self
            .checked
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
        {
            return false;
        }
        self.checked = Some(now);
        self.granted = probe();
        self.granted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denied_grants_are_rate_limited_and_positive_grants_are_cached() {
        let mut cache = GrantCache::new();
        let start = Instant::now();
        assert!(!cache.query(start, || false));
        for millis in [1, 8, 16, 500, 999] {
            assert!(
                !cache.query(start + Duration::from_millis(millis), || panic!(
                    "hot-path probe"
                ))
            );
        }
        assert!(cache.query(start + Duration::from_secs(1), || true));
        assert!(cache.query(start + Duration::from_secs(60), || panic!(
            "a positive grant is cached"
        )));
    }
}
