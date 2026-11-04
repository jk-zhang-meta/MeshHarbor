// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The **originating** side of Roomler SSH — this device asking the server for
//! a session on another one (`meshharbor ssh <device>`).
//!
//! Deliberately separate from [`crate::ssh`], which is the SERVING side. That
//! module only exists in builds with an overlay feature (no overlay ⇒ no
//! address to serve SSH on), but the answer to a request we originated arrives
//! on the plain control WS and must be deliverable in ANY build — so the
//! waiter registry lives here, ungated.
//!
//! Mirrors `exec::expect_response` exactly: register a oneshot under the
//! request id BEFORE sending, hand the receiver to the caller, and let a guard
//! deregister on drop so an abandoned caller cannot leak a slot that a later
//! id could be delivered into.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tokio::sync::oneshot;

/// What the server answered. Either a place to dial or a refusal — never
/// both, and never neither.
#[derive(Debug, Default, Clone)]
pub struct SshGrantAnswer {
    pub address: Option<String>,
    pub port: Option<u16>,
    /// The target's SSH host public key (P6a). `None` = the device reported
    /// none, i.e. it cannot prove itself. NOT "any key is fine".
    pub host_pubkey: Option<String>,
    pub grant_id: Option<String>,
    pub expires_at_ms: Option<u64>,
    pub error: Option<String>,
    /// FR-90 P3-8-2b — the agent session's ticket the server held the
    /// request to, echoed. `None` on a person's request, and from a server
    /// before P3-8-1b, which ignored the ticket and answered as the owner's.
    pub ssh_ticket_id: Option<String>,
}

type Pending = HashMap<String, oneshot::Sender<SshGrantAnswer>>;

static PENDING: OnceLock<Mutex<Pending>> = OnceLock::new();

fn lock_pending() -> MutexGuard<'static, Pending> {
    PENDING
        .get_or_init(|| Mutex::new(HashMap::new()))
        // A panic while holding this lock would otherwise poison every later
        // SSH request for the life of the process; the map itself is plain
        // data, so recovering is strictly better than propagating.
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Register a waiter for `request_id`. Call this BEFORE sending the request —
/// a fast answer could otherwise arrive with nowhere to go.
pub fn expect_response(request_id: &str) -> (PendingGuard, oneshot::Receiver<SshGrantAnswer>) {
    let (tx, rx) = oneshot::channel();
    lock_pending().insert(request_id.to_string(), tx);
    (
        PendingGuard {
            request_id: request_id.to_string(),
        },
        rx,
    )
}

/// Deliver an answer to whoever is parked on `request_id`. An unknown id means
/// that caller already gave up — dropping is correct, not an error.
pub fn deliver(request_id: &str, answer: SshGrantAnswer) {
    if let Some(tx) = lock_pending().remove(request_id) {
        let _ = tx.send(answer);
    }
}

/// Deregisters its request id on drop, so an abandoned caller can't leak a
/// slot that a later id-reuse would deliver into.
pub struct PendingGuard {
    request_id: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock_pending().remove(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_answer_reaches_the_waiter() {
        let (_g, rx) = expect_response("r1");
        deliver(
            "r1",
            SshGrantAnswer {
                address: Some("100.65.4.30".into()),
                host_pubkey: Some("ssh-ed25519 AAAA".into()),
                ..Default::default()
            },
        );
        let got = rx.await.expect("waiter still registered");
        assert_eq!(got.address.as_deref(), Some("100.65.4.30"));
        assert!(got.host_pubkey.is_some());
    }

    #[tokio::test]
    async fn a_dropped_guard_frees_the_slot() {
        // The failure this prevents: an abandoned request id staying in the
        // map, so a LATER request that happened to reuse it would be answered
        // into a channel nobody reads — and the real caller would hang.
        let (guard, _rx) = expect_response("r2");
        drop(guard);
        assert!(
            lock_pending().get("r2").is_none(),
            "the slot must be gone once its caller has"
        );
        // Delivering to nobody is a no-op, never a panic.
        deliver("r2", SshGrantAnswer::default());
    }

    #[tokio::test]
    async fn two_requests_do_not_cross() {
        let (_g1, rx1) = expect_response("a");
        let (_g2, rx2) = expect_response("b");
        deliver(
            "b",
            SshGrantAnswer {
                grant_id: Some("for-b".into()),
                ..Default::default()
            },
        );
        assert_eq!(rx2.await.unwrap().grant_id.as_deref(), Some("for-b"));
        // `a` is still parked and untouched.
        assert!(lock_pending().contains_key("a"));
        drop(rx1);
    }
}
