// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-83 — the server's half of the SSH grant acknowledgement.
//!
//! `decide()` registers a waiter here BEFORE it pushes `rc:ssh.grant`, and the
//! target's `rc:ssh.grant_ack` resolves it. Until the ack arrives the caller is
//! not told where to dial: "queued for the device" is not "the device has it",
//! and a caller whose control path was faster than the target's used to dial
//! into a device that had not heard of it yet (#1597).
//!
//! A waiter is keyed by the grant id and BOUND to the agent the grant was
//! pushed to. Grant ids are ObjectIds — structured, not secret — so an ack
//! from any other socket confirms nothing and does not even consume the slot
//! (otherwise a device could cancel someone else's wait).
//!
//! Pod-local, like the Hub's exec waiters: the push only succeeds when the
//! target's socket is on this pod, and its ack arrives on that same socket.

use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_remote_control::models::SshGrantRefusal;
use tokio::sync::oneshot;

/// What became of one grant, as far as the server can know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The device holds the grant; a connection with its key now succeeds.
    Recorded,
    /// The device will never honour it, and said why.
    Refused(SshGrantRefusal),
    /// No answer within the bound — or the waiter was abandoned.
    Unconfirmed,
}

struct Waiter {
    agent_id: ObjectId,
    /// FR-105 — a grant for the device's SYSTEM service. Only the service's
    /// CLAIM confirms it ([`SshGrantAcks::deliver_claim`]); the worker's own
    /// ack can only refuse it. A worker the signed-in user controls must not
    /// be able to tell the caller "dial now" for a grant the service never
    /// took.
    via_service: bool,
    tx: oneshot::Sender<Option<SshGrantRefusal>>,
}

/// In-flight grants awaiting their target's acknowledgement.
#[derive(Default)]
pub struct SshGrantAcks {
    waiters: DashMap<String, Waiter>,
}

impl SshGrantAcks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Park on `agent_id`'s answer to `grant_id`.
    ///
    /// Register BEFORE the push: an ack that beats the caller back to this
    /// table must find somewhere to land. The returned guard deregisters on
    /// every exit path — a failed push, a legacy agent that will never ack, a
    /// timeout — so an abandoned slot cannot outlive its request.
    pub fn expect(self: &Arc<Self>, grant_id: &str, agent_id: ObjectId) -> PendingAck {
        self.register(grant_id, agent_id, false)
    }

    /// FR-105 — [`Self::expect`] for a grant routed to the device's SYSTEM
    /// service: confirmed only by the service's claim.
    pub fn expect_via_service(self: &Arc<Self>, grant_id: &str, agent_id: ObjectId) -> PendingAck {
        self.register(grant_id, agent_id, true)
    }

    fn register(
        self: &Arc<Self>,
        grant_id: &str,
        agent_id: ObjectId,
        via_service: bool,
    ) -> PendingAck {
        let (tx, rx) = oneshot::channel();
        self.waiters.insert(
            grant_id.to_string(),
            Waiter {
                agent_id,
                via_service,
                tx,
            },
        );
        PendingAck {
            acks: Arc::clone(self),
            grant_id: grant_id.to_string(),
            rx,
        }
    }

    /// Hand the device's `rc:ssh.grant_ack` to whoever is parked on it.
    /// `false` = nobody was: the caller already gave up, never waited (a
    /// legacy path), or the ack came from a socket other than the target's,
    /// which is refused WITHOUT removing the slot, so the real target can
    /// still answer.
    ///
    /// FR-105 — for a via-service grant only a REFUSAL is taken from the
    /// worker (the person's `ssh_enabled` off is still theirs to say). A
    /// "recorded" from the worker confirms nothing and leaves the slot for
    /// the service's claim.
    pub fn deliver(
        &self,
        grant_id: &str,
        from_agent: ObjectId,
        refused: Option<SshGrantRefusal>,
    ) -> bool {
        match self.waiters.remove_if(grant_id, |_, w| {
            w.agent_id == from_agent && (!w.via_service || refused.is_some())
        }) {
            Some((_, w)) => w.tx.send(refused).is_ok(),
            None => false,
        }
    }

    /// FR-105 — the device's SYSTEM service claimed the grant on THIS pod:
    /// it holds the grant, so the caller may dial. `false` = nobody here
    /// waits on it as a via-service grant for that device (the caller is on
    /// another pod and reads the claim from the shared row, or gave up).
    pub fn deliver_claim(&self, grant_id: &str, from_agent: ObjectId) -> bool {
        match self
            .waiters
            .remove_if(grant_id, |_, w| w.agent_id == from_agent && w.via_service)
        {
            Some((_, w)) => w.tx.send(None).is_ok(),
            None => false,
        }
    }

    /// Grants currently awaiting an ack. Tests and diagnostics only.
    pub fn pending(&self) -> usize {
        self.waiters.len()
    }
}

/// One caller parked on one grant. Dropping it deregisters the slot.
pub struct PendingAck {
    acks: Arc<SshGrantAcks>,
    grant_id: String,
    rx: oneshot::Receiver<Option<SshGrantRefusal>>,
}

impl PendingAck {
    /// Wait at most `bound` for the target's answer.
    pub async fn wait(mut self, bound: Duration) -> AckOutcome {
        match tokio::time::timeout(bound, &mut self.rx).await {
            Ok(Ok(None)) => AckOutcome::Recorded,
            Ok(Ok(Some(r))) => AckOutcome::Refused(r),
            // Sender dropped without an answer, or the bound expired.
            Ok(Err(_)) | Err(_) => AckOutcome::Unconfirmed,
        }
    }

    /// FR-105 — [`Self::wait`] for a via-service grant. The service's claim
    /// can land on ANY pod, so besides the claim or refusal delivered here,
    /// `claimed()` (a read of the shared row) is asked every `poll`.
    pub async fn wait_or_claimed<F, Fut>(
        mut self,
        bound: Duration,
        poll: Duration,
        mut claimed: F,
    ) -> AckOutcome
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            tokio::select! {
                answer = &mut self.rx => {
                    return match answer {
                        Ok(None) => AckOutcome::Recorded,
                        Ok(Some(r)) => AckOutcome::Refused(r),
                        Err(_) => AckOutcome::Unconfirmed,
                    };
                }
                () = tokio::time::sleep(poll) => {
                    if claimed().await {
                        return AckOutcome::Recorded;
                    }
                }
                () = tokio::time::sleep_until(deadline) => return AckOutcome::Unconfirmed,
            }
        }
    }
}

impl Drop for PendingAck {
    fn drop(&mut self) {
        self.acks.waiters.remove(&self.grant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn the_targets_ack_resolves_the_wait() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let pending = acks.expect("g1", target);
        assert!(acks.deliver("g1", target, None));
        assert_eq!(pending.wait(SHORT).await, AckOutcome::Recorded);
        assert_eq!(acks.pending(), 0);
    }

    #[tokio::test]
    async fn a_refusal_carries_its_reason() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let pending = acks.expect("g1", target);
        assert!(acks.deliver("g1", target, Some(SshGrantRefusal::SshDisabled)));
        assert_eq!(
            pending.wait(SHORT).await,
            AckOutcome::Refused(SshGrantRefusal::SshDisabled)
        );
    }

    /// AC5 — grant ids are ObjectIds: structured, not secret. An ack from any
    /// socket but the target's must confirm nothing AND leave the slot for
    /// the real answer; consuming it would let one device cancel another's
    /// wait.
    #[tokio::test]
    async fn an_ack_from_another_agent_confirms_nothing_and_leaves_the_slot() {
        let acks = Arc::new(SshGrantAcks::new());
        let (target, stranger) = (ObjectId::new(), ObjectId::new());
        let pending = acks.expect("g1", target);

        assert!(!acks.deliver("g1", stranger, None), "a stranger's ack");
        assert_eq!(acks.pending(), 1, "the slot survives the stranger");

        assert!(acks.deliver("g1", target, None));
        assert_eq!(pending.wait(SHORT).await, AckOutcome::Recorded);
    }

    /// AC3 — silence is `Unconfirmed`, and the slot does not outlive it.
    #[tokio::test]
    async fn silence_is_unconfirmed_and_the_slot_is_released() {
        let acks = Arc::new(SshGrantAcks::new());
        let pending = acks.expect("g1", ObjectId::new());
        assert_eq!(pending.wait(SHORT).await, AckOutcome::Unconfirmed);
        assert_eq!(acks.pending(), 0);
    }

    /// A caller that stopped waiting (legacy agent, failed push) must not
    /// leave a slot a late ack could land in.
    #[tokio::test]
    async fn dropping_the_guard_deregisters_and_a_late_ack_lands_nowhere() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        drop(acks.expect("g1", target));
        assert_eq!(acks.pending(), 0);
        assert!(!acks.deliver("g1", target, None));
    }

    /// FR-105 — a via-service grant: the worker's "recorded" confirms
    /// nothing and leaves the slot; only the service's claim does.
    #[tokio::test]
    async fn only_the_services_claim_confirms_a_service_grant() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let pending = acks.expect_via_service("g1", target);

        assert!(!acks.deliver("g1", target, None), "the worker's own ack");
        assert_eq!(acks.pending(), 1, "the slot waits for the claim");
        assert!(
            !acks.deliver_claim("g1", ObjectId::new()),
            "another device's claim"
        );

        assert!(acks.deliver_claim("g1", target));
        assert_eq!(pending.wait(SHORT).await, AckOutcome::Recorded);
    }

    /// FR-105 — the worker can still REFUSE a via-service grant: the
    /// person's own `ssh_enabled` off is theirs to say.
    #[tokio::test]
    async fn the_worker_can_still_refuse_a_service_grant() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let pending = acks.expect_via_service("g1", target);
        assert!(acks.deliver("g1", target, Some(SshGrantRefusal::SshDisabled)));
        assert_eq!(
            pending.wait(SHORT).await,
            AckOutcome::Refused(SshGrantRefusal::SshDisabled)
        );
    }

    /// FR-105 — a claim confirms nothing for a grant the WORKER holds.
    #[tokio::test]
    async fn a_claim_does_not_confirm_a_worker_grant() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let _pending = acks.expect("g1", target);
        assert!(!acks.deliver_claim("g1", target));
        assert_eq!(acks.pending(), 1);
    }

    /// FR-105 — a claim that landed on another pod is read from the shared
    /// row, and that is enough; silence until the bound is `Unconfirmed`.
    #[tokio::test]
    async fn a_claim_on_another_pod_is_read_from_the_row() {
        let acks = Arc::new(SshGrantAcks::new());
        let pending = acks.expect_via_service("g1", ObjectId::new());
        let polls = std::sync::atomic::AtomicU32::new(0);
        let outcome = pending
            .wait_or_claimed(Duration::from_secs(5), Duration::from_millis(10), || {
                let n = polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move { n >= 2 }
            })
            .await;
        assert_eq!(outcome, AckOutcome::Recorded);

        let silent = acks.expect_via_service("g2", ObjectId::new());
        let outcome = silent
            .wait_or_claimed(SHORT, Duration::from_millis(10), || async { false })
            .await;
        assert_eq!(outcome, AckOutcome::Unconfirmed);
        assert_eq!(acks.pending(), 0);
    }

    /// An ack that arrives BEFORE the caller starts waiting — the device
    /// answered faster than `decide()` got from the push to the await — is
    /// kept, not lost.
    #[tokio::test]
    async fn an_ack_that_beats_the_wait_is_not_lost() {
        let acks = Arc::new(SshGrantAcks::new());
        let target = ObjectId::new();
        let pending = acks.expect("g1", target);
        assert!(acks.deliver("g1", target, None));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pending.wait(SHORT).await, AckOutcome::Recorded);
    }
}
