// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `ctl_dns` — the daemon's OWN names (the coordination server behind the
//! control WS and DERP, the STUN/TURN hosts), resolved so that no caller ever
//! waits on a resolver that has stopped answering for a name it has resolved
//! before (#2187).
//!
//! Those names resolve through the OS resolver, and while an exit's DNS steer
//! is in force that means THROUGH the exit. When the exit's DNS stops answering
//! but its carrier stays up, nothing tears the exit down, and every lookup waits
//! out the resolver's whole retry schedule (~11 s per query on Windows). Field:
//! a direct-plane rebuild held the overlay loop for 48 s, and a control WS that
//! dropped could not reconnect at all, because resolving the server went through
//! the same dead exit.
//!
//! Every one of these names resolves at least once before any steer exists (the
//! control WS connects before the overlay comes up), so the fix is a memory, not
//! a second resolver: every success is kept, a remembered name is answered at
//! once and refreshed behind the caller, and only a name never resolved waits,
//! and only [`FIRST_LOOKUP_BOUND`].
//!
//! FR-48 still holds: within [`TTL`] nothing is looked up at all. Each lookup is
//! a blocking `getaddrinfo` on tokio's pool, and glibc keeps its resolver socket
//! in that thread's state for the life of the process; one lookup in flight per
//! name keeps an outage from piling them up.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{debug, info};

/// How long an answer is trusted before a refresh is attempted (FR-48).
pub const TTL: Duration = Duration::from_secs(300);
/// The longest a caller waits for a name with nothing remembered.
pub const FIRST_LOOKUP_BOUND: Duration = Duration::from_secs(5);
/// After a refresh fails, how long the last good answer is trusted before the
/// next refresh, so an outage costs one lookup a minute per name.
pub const RETRY_AFTER: Duration = Duration::from_secs(60);

type LookupFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
type LookupFn = Arc<dyn Fn(String) -> LookupFuture + Send + Sync>;
/// `None` while the lookup runs; `Some(addrs)` once settled (empty = failed).
type Outcome = watch::Receiver<Option<Vec<SocketAddr>>>;

struct Entry {
    addrs: Vec<SocketAddr>,
    /// Answered from memory, without a lookup, until then.
    until: Instant,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    in_flight: HashMap<String, Outcome>,
}

/// The cache, with its lookup injectable for tests. The process uses one
/// ([`resolve`]).
pub struct CtlDns {
    lookup: LookupFn,
    state: Mutex<State>,
}

impl CtlDns {
    fn new(lookup: LookupFn) -> Arc<Self> {
        Arc::new(Self {
            lookup,
            state: Mutex::new(State::default()),
        })
    }

    fn system() -> Arc<Self> {
        Self::new(Arc::new(|hostport: String| {
            Box::pin(async move { Ok(tokio::net::lookup_host(hostport).await?.collect()) })
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `hostport` as `host:port`. A remembered answer comes back at once, a
    /// stale one with a refresh started behind it; a name never resolved waits
    /// for its first lookup, at most [`FIRST_LOOKUP_BOUND`]. Empty = no answer.
    pub async fn resolve(self: &Arc<Self>, hostport: &str) -> Vec<SocketAddr> {
        let outcome = {
            let mut st = self.lock();
            match st.entries.get(hostport) {
                Some(e) if Instant::now() < e.until => return e.addrs.clone(),
                Some(e) => {
                    let stale = e.addrs.clone();
                    let _ = self.start_lookup(&mut st, hostport);
                    return stale;
                }
                None => self.start_lookup(&mut st, hostport),
            }
        };
        wait_settled(outcome, FIRST_LOOKUP_BOUND)
            .await
            .unwrap_or_default()
    }

    /// The answer just failed the caller (every address refused or timed out):
    /// stop trusting it, and look again behind the caller. Its next attempt
    /// gets whatever the lookup finds, or the same answer if it finds nothing.
    pub fn distrust(self: &Arc<Self>, hostport: &str) {
        let mut st = self.lock();
        let Some(e) = st.entries.get_mut(hostport) else {
            return;
        };
        e.until = Instant::now();
        let _ = self.start_lookup(&mut st, hostport);
    }

    /// One lookup in flight per name; a second caller joins the first.
    fn start_lookup(self: &Arc<Self>, st: &mut State, hostport: &str) -> Outcome {
        if let Some(rx) = st.in_flight.get(hostport) {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        st.in_flight.insert(hostport.to_string(), rx.clone());
        let this = Arc::clone(self);
        let key = hostport.to_string();
        let lookup = (self.lookup)(key.clone());
        tokio::spawn(async move {
            let found = lookup.await.unwrap_or_default();
            this.settle(&key, &found);
            let _ = tx.send(Some(found));
        });
        rx
    }

    fn settle(&self, hostport: &str, found: &[SocketAddr]) {
        let mut st = self.lock();
        st.in_flight.remove(hostport);
        if !found.is_empty() {
            st.entries.insert(
                hostport.to_string(),
                Entry {
                    addrs: found.to_vec(),
                    until: Instant::now() + TTL,
                },
            );
            debug!(%hostport, count = found.len(), "ctl_dns: resolved");
        } else if let Some(e) = st.entries.get_mut(hostport) {
            e.until = Instant::now() + RETRY_AFTER;
            info!(
                %hostport,
                retry_s = RETRY_AFTER.as_secs(),
                "ctl_dns: lookup failed — serving the last good answer"
            );
        }
    }
}

/// The settled outcome, or `None` if it does not settle within `bound`.
async fn wait_settled(mut rx: Outcome, bound: Duration) -> Option<Vec<SocketAddr>> {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        if let Some(found) = rx.borrow().clone() {
            return Some(found);
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            // Timed out, or the lookup task is gone.
            _ => return None,
        }
    }
}

fn global() -> &'static Arc<CtlDns> {
    static GLOBAL: OnceLock<Arc<CtlDns>> = OnceLock::new();
    GLOBAL.get_or_init(CtlDns::system)
}

/// [`CtlDns::resolve`] on the process's cache.
pub async fn resolve(hostport: &str) -> Vec<SocketAddr> {
    global().resolve(hostport).await
}

/// [`CtlDns::distrust`] on the process's cache.
pub fn distrust(hostport: &str) {
    global().distrust(hostport)
}

/// Record an answer learned some other way, trusted for [`TTL`]. Its test use
/// is a name no resolver will ever answer, served from memory.
pub fn remember(hostport: &str, addrs: &[SocketAddr]) {
    if addrs.is_empty() {
        return;
    }
    global().lock().entries.insert(
        hostport.to_string(),
        Entry {
            addrs: addrs.to_vec(),
            until: Instant::now() + TTL,
        },
    );
}

/// `host:port` for `host`, bracketing a v6 literal.
pub fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A lookup that answers `answer` after `delay` (None = never answers),
    /// counting its calls.
    fn fake(
        delay: Option<Duration>,
        answer: std::io::Result<Vec<SocketAddr>>,
    ) -> (Arc<CtlDns>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let answer = Arc::new(answer.map_err(|e| e.kind()));
        let dns = CtlDns::new(Arc::new(move |_hostport: String| {
            counter.fetch_add(1, Ordering::SeqCst);
            let answer = Arc::clone(&answer);
            Box::pin(async move {
                match delay {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
                answer.as_ref().clone().map_err(std::io::Error::from)
            })
        }));
        (dns, calls)
    }

    fn remember(dns: &Arc<CtlDns>, hostport: &str, addrs: &[SocketAddr], until: Instant) {
        dns.lock().entries.insert(
            hostport.to_string(),
            Entry {
                addrs: addrs.to_vec(),
                until,
            },
        );
    }

    /// FR-48 — a fresh answer is served without any lookup.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_answer_needs_no_lookup() {
        let (dns, calls) = fake(Some(Duration::ZERO), Ok(vec![addr("192.0.2.1:443")]));
        let first = dns.resolve("server.example:443").await;
        assert_eq!(first, vec![addr("192.0.2.1:443")]);
        for _ in 0..5 {
            assert_eq!(dns.resolve("server.example:443").await, first);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one lookup per TTL");
    }

    /// #2187 — the field case. The exit's DNS has died (the lookup never
    /// answers) and the answer is past its TTL: the caller gets the last good
    /// answer AT ONCE, and callers in the meantime share one lookup.
    #[tokio::test(start_paused = true)]
    async fn a_dead_resolver_never_delays_a_remembered_name() {
        let (dns, calls) = fake(None, Ok(vec![]));
        let good = [addr("192.0.2.7:3478")];
        remember(&dns, "coturn.example:3478", &good, Instant::now());

        let started = tokio::time::Instant::now();
        for _ in 0..3 {
            assert_eq!(dns.resolve("coturn.example:3478").await, good.to_vec());
        }
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "the caller must not wait on the dead lookup"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one lookup in flight, shared"
        );
    }

    /// A refresh that fails keeps the last good answer and does not look again
    /// before [`RETRY_AFTER`].
    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_keeps_the_answer_and_waits_before_retrying() {
        let (dns, calls) = fake(
            Some(Duration::from_secs(11)),
            Err(std::io::ErrorKind::TimedOut.into()),
        );
        let good = [addr("192.0.2.9:443")];
        remember(&dns, "server.example:443", &good, Instant::now());

        assert_eq!(dns.resolve("server.example:443").await, good.to_vec());
        tokio::time::sleep(Duration::from_secs(12)).await; // the refresh fails
        assert_eq!(dns.resolve("server.example:443").await, good.to_vec());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no new lookup inside RETRY_AFTER"
        );
    }

    /// A name never resolved waits for its first lookup, at most
    /// [`FIRST_LOOKUP_BOUND`]; an answer that lands later is kept.
    #[tokio::test(start_paused = true)]
    async fn a_name_never_resolved_waits_bounded_and_keeps_a_late_answer() {
        let (dns, calls) = fake(
            Some(Duration::from_secs(8)),
            Ok(vec![addr("192.0.2.3:443")]),
        );
        let started = tokio::time::Instant::now();
        assert!(dns.resolve("late.example:443").await.is_empty());
        assert_eq!(started.elapsed(), FIRST_LOOKUP_BOUND);
        tokio::time::sleep(Duration::from_secs(4)).await; // the lookup lands
        assert_eq!(
            dns.resolve("late.example:443").await,
            vec![addr("192.0.2.3:443")]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A failed first lookup caches nothing: the next call asks again.
    #[tokio::test(start_paused = true)]
    async fn a_failed_first_lookup_is_not_remembered() {
        let (dns, calls) = fake(
            Some(Duration::ZERO),
            Err(std::io::ErrorKind::NotFound.into()),
        );
        assert!(dns.resolve("nx.example:443").await.is_empty());
        assert!(dns.resolve("nx.example:443").await.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// An answer the caller could not use (every address refused) is no
    /// longer trusted: the next call starts a refresh.
    #[tokio::test(start_paused = true)]
    async fn distrust_starts_a_refresh() {
        let (dns, calls) = fake(Some(Duration::ZERO), Ok(vec![addr("192.0.2.4:443")]));
        remember(
            &dns,
            "moved.example:443",
            &[addr("192.0.2.99:443")],
            Instant::now() + TTL,
        );
        dns.distrust("moved.example:443");
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            dns.resolve("moved.example:443").await,
            vec![addr("192.0.2.4:443")]
        );
    }

    #[test]
    fn hostport_brackets_a_v6_literal() {
        assert_eq!(
            hostport("meshharbor.itachi.fans", 443),
            "meshharbor.itachi.fans:443"
        );
        assert_eq!(hostport("2001:db8::1", 3478), "[2001:db8::1]:3478");
        assert_eq!(hostport("[2001:db8::1]", 3478), "[2001:db8::1]:3478");
    }
}
