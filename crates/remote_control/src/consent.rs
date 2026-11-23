// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Consent flow.
//!
//! When a controller requests a session, the server creates a oneshot channel
//! and stores its sender in the session's pending state. The agent receives
//! `rc:request`, prompts the user, and replies with `rc:consent`. The server
//! resolves the oneshot. If the agent doesn't reply within the timeout, the
//! server resolves with `Timeout` and tears down the session.
//!
//! FR-27 — a `granted: false` is not one thing. "The person at the machine
//! pressed Deny", "the prompt stood there and nobody answered" and "no surface
//! on that host could raise a prompt at all" have different causes and
//! different fixes, and collapsing them was actively misleading: the agent's
//! own prompt timeout produced `granted: false`, which the hub terminated as
//! `UserDenied`, so the controller was told a human had refused them when in
//! fact nobody had been asked. [`ConsentDenyReason`] rides `rc:consent`
//! alongside `granted` so the three stay distinguishable end to end.

use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentOutcome {
    Granted,
    /// A human at the device refused.
    Denied,
    /// The window closed with no answer — either the agent said so, or our own
    /// waiter expired.
    Timeout,
    /// The device could raise no prompt at all (no desktop session, no
    /// companion, nothing). Distinct from `Timeout` because nobody was ever
    /// asked, so "try again and answer it" is the wrong advice.
    NoPromptSurface,
    /// FR-129 — the device asks for a two-factor code and none came: ask the person for one.
    TwoFactorRequired,
    /// FR-129 — the code was wrong, expired or already used.
    TwoFactorInvalid,
    /// FR-129 — too many wrong codes, or the device cannot read its state: not now.
    TwoFactorLocked,
}

/// Why an agent answered `granted: false`.
///
/// Carried on the wire as a plain string (`ClientMsg::Consent::reason`), for
/// the same reason `AgentCaps.rpc` is a `Vec<String>`: agents in the field span
/// many releases, and a newer one must be able to name a reason this server has
/// never heard of without the frame failing to parse. Both sides go through
/// this type so neither can misspell one — the `RpcCap` pattern.
///
/// ⚠️ The wire spellings are a compatibility surface. Renaming one does not
/// fail loudly; it silently turns every report from a deployed agent into
/// `None`, i.e. back into "the user denied you". Locked by
/// `deny_reason_wire_strings_are_locked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDenyReason {
    /// The on-host prompt was raised and its window closed unanswered.
    HostTimeout,
    /// No prompt surface was reachable, so no human was ever asked.
    NoPromptSurface,
    /// FR-129 — the device asks for a two-factor code and the request carried none.
    TwoFactorRequired,
    /// FR-129 — the code was wrong, expired or already used.
    TwoFactorInvalid,
    /// FR-129 — too many wrong codes; checking resumes later.
    TwoFactorLocked,
    /// FR-129 — the device cannot read its two-factor state, so it refuses every code.
    TwoFactorUnavailable,
}

impl ConsentDenyReason {
    /// Every variant — a test walks this so a new one cannot be added without
    /// a wire spelling.
    pub const ALL: &'static [ConsentDenyReason] = &[
        ConsentDenyReason::HostTimeout,
        ConsentDenyReason::NoPromptSurface,
        ConsentDenyReason::TwoFactorRequired,
        ConsentDenyReason::TwoFactorInvalid,
        ConsentDenyReason::TwoFactorLocked,
        ConsentDenyReason::TwoFactorUnavailable,
    ];

    pub fn wire(self) -> &'static str {
        match self {
            ConsentDenyReason::HostTimeout => "timeout",
            ConsentDenyReason::NoPromptSurface => "no_prompt_surface",
            ConsentDenyReason::TwoFactorRequired => "two_factor_required",
            ConsentDenyReason::TwoFactorInvalid => "two_factor_invalid",
            ConsentDenyReason::TwoFactorLocked => "two_factor_locked",
            ConsentDenyReason::TwoFactorUnavailable => "two_factor_unavailable",
        }
    }

    /// `None` for an absent or unrecognised reason — which correctly reads as
    /// "an ordinary deny", the pre-FR-27 meaning of a bare `granted: false`.
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.wire() == s)
    }

    fn outcome(self) -> ConsentOutcome {
        match self {
            ConsentDenyReason::HostTimeout => ConsentOutcome::Timeout,
            ConsentDenyReason::NoPromptSurface => ConsentOutcome::NoPromptSurface,
            ConsentDenyReason::TwoFactorRequired => ConsentOutcome::TwoFactorRequired,
            ConsentDenyReason::TwoFactorInvalid => ConsentOutcome::TwoFactorInvalid,
            ConsentDenyReason::TwoFactorLocked | ConsentDenyReason::TwoFactorUnavailable => {
                ConsentOutcome::TwoFactorLocked
            }
        }
    }
}

/// Resolve a wire `(granted, reason)` pair into the outcome the hub acts on.
/// One place, so the "absent reason ⇒ explicit deny" default cannot drift
/// between the WS dispatcher and the approve-link route.
pub fn outcome_of(granted: bool, reason: Option<&str>) -> ConsentOutcome {
    if granted {
        return ConsentOutcome::Granted;
    }
    match reason.and_then(ConsentDenyReason::from_wire) {
        Some(r) => r.outcome(),
        None => ConsentOutcome::Denied,
    }
}

/// The attended window: how long a plain-`prompt` on-host prompt stands, and how
/// long the hub waits for it.
///
/// 5 minutes. Field CORPLAP-1, 2026-08-29: a device set to
/// plain `prompt` may be LOCKED when the session starts — the operator has to
/// walk to the machine, unlock it, and only then can they see and approve the
/// prompt. 30 s was not enough to do that, so the controller timed out before
/// the human arrived. Plain `prompt` has no remote fallback, so this window is
/// the only chance to answer and must be generous.
///
/// ⚠️ `prompt_then_email` does NOT use this — its host half is
/// [`HOST_PROMPT_TIMEOUT`] (short), because its emailed link is the real
/// fallback and a five-minute modal on someone's screen is an obstruction.
pub const DEFAULT_CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// The window for a mode whose approval reaches a HUMAN somewhere else — email
/// link, push card. Minutes rather than seconds, because the owner has to be
/// reached, read it and act.
pub const ASYNC_CONSENT_TIMEOUT: Duration = Duration::from_secs(300);

/// FR-27 — how long the ON-HOST half of `prompt_then_email` stands.
///
/// Deliberately SHORT (30 s), and deliberately NOT [`DEFAULT_CONSENT_TIMEOUT`]
/// (now 5 min) nor [`ASYNC_CONSENT_TIMEOUT`]: a modal that sits on someone's
/// screen for minutes is an obstruction, and here — unlike plain `prompt` — the
/// emailed link IS the fallback, so the host half need only catch someone
/// already sitting there and then hand over. A host timeout hands over to the
/// owner rather than ending the session — see `Hub::deliver_consent`. (Plain
/// `prompt` waits the full 5 min precisely because it has no email to hand to.)
pub const HOST_PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// FR-27 — how much LONGER than the window it announced the hub waits for the
/// agent's own verdict before falling back to a bare `ConsentTimeout`.
///
/// The agent's prompt window and the hub's fallback timer are both set from
/// the same `consent_timeout_secs`, so on every non-answer they expire
/// together and the hub's fires ~130 ms earlier — measured on mars twice
/// (2026-08-29: `ConsentTimeout` at t+30.000 s, the agent's
/// `reason="no_prompt_surface"` at t+30.138 s). The agent's verdict is the
/// one that carries a REASON — "nobody answered" vs "there was nobody to
/// ask" — and the whole of finding 3 was that those need telling apart; a
/// hub that terminates first throws the reason away. So the hub's own timer
/// is a backstop for a DEAD agent, not a peer of the agent's, and it runs
/// after the agent has had time to say what happened.
///
/// ⚠️ Applied to the hub's wait ONLY, never to the number sent on the wire —
/// the on-host prompt still stands for exactly the announced window.
pub const CONSENT_VERDICT_GRACE: Duration = Duration::from_secs(5);

/// The hub's actual wait for a window it announced as `window`.
pub fn hub_consent_deadline(window: Duration) -> Duration {
    window + CONSENT_VERDICT_GRACE
}

/// Channel used by the hub to deliver the agent's consent decision.
pub struct ConsentSlot {
    tx: oneshot::Sender<ConsentOutcome>,
}

impl ConsentSlot {
    pub fn new() -> (Self, ConsentWaiter) {
        let (tx, rx) = oneshot::channel();
        (Self { tx }, ConsentWaiter { rx })
    }

    /// Called by the signaling layer when the agent's `rc:consent` arrives.
    /// Returns Err if the waiter already gave up.
    pub fn resolve(self, outcome: ConsentOutcome) -> Result<()> {
        self.tx
            .send(outcome)
            .map_err(|_| Error::BadMessage("consent waiter dropped"))
    }
}

pub struct ConsentWaiter {
    rx: oneshot::Receiver<ConsentOutcome>,
}

impl ConsentWaiter {
    pub async fn wait(self, dur: Duration) -> ConsentOutcome {
        match timeout(dur, self.rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => ConsentOutcome::Timeout, // sender dropped
            Err(_) => ConsentOutcome::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mars race, replayed on a paused clock: the window is 30 s, the
    /// agent's verdict lands 138 ms AFTER it (the measured gap), and the hub
    /// must still receive that verdict — with its reason — rather than
    /// having already given up with a bare Timeout.
    #[tokio::test(start_paused = true)]
    async fn a_verdict_just_after_the_window_still_beats_the_fallback() {
        let (slot, waiter) = ConsentSlot::new();
        let window = DEFAULT_CONSENT_TIMEOUT;
        let wait = tokio::spawn(waiter.wait(hub_consent_deadline(window)));
        // ⚠️ Poll the waiter ONCE before moving the clock: a spawned task is
        // not polled by `spawn`, and `timeout` registers its timer on first
        // poll — advance first and the timer is armed at the already-advanced
        // instant, the window never "expires", and this test passes without
        // testing anything (it did, until the negative control below caught
        // it).
        tokio::task::yield_now().await;
        tokio::time::advance(window + Duration::from_millis(138)).await;
        // Let the waiter observe the elapsed clock — with a bare-window wait
        // this is where it would have given up.
        tokio::task::yield_now().await;
        slot.resolve(ConsentOutcome::NoPromptSurface).unwrap();
        assert_eq!(wait.await.unwrap(), ConsentOutcome::NoPromptSurface);
    }

    /// The negative control — the pre-fix behaviour, kept reproducible: with
    /// the hub waiting exactly the announced window, the same 138 ms-late
    /// verdict is thrown away and the controller gets a bare Timeout. This
    /// is what mars did on 0.4.16 AND 0.4.18; if this test ever starts
    /// failing, the race test above has stopped testing anything.
    #[tokio::test(start_paused = true)]
    async fn without_the_grace_the_fallback_wins_the_race() {
        let (slot, waiter) = ConsentSlot::new();
        let window = DEFAULT_CONSENT_TIMEOUT;
        let wait = tokio::spawn(waiter.wait(window));
        tokio::task::yield_now().await; // arm the timer at t0 (see above)
        tokio::time::advance(window + Duration::from_millis(138)).await;
        tokio::task::yield_now().await;
        // The waiter has already resolved to Timeout; the agent's verdict
        // finds nobody listening.
        assert!(slot.resolve(ConsentOutcome::NoPromptSurface).is_err());
        assert_eq!(wait.await.unwrap(), ConsentOutcome::Timeout);
    }

    /// And the backstop still exists: an agent that never answers at all is
    /// timed out by the hub, not waited on forever.
    #[tokio::test(start_paused = true)]
    async fn a_silent_agent_is_still_timed_out_after_the_grace() {
        let (_slot, waiter) = ConsentSlot::new();
        let wait = tokio::spawn(waiter.wait(hub_consent_deadline(DEFAULT_CONSENT_TIMEOUT)));
        tokio::task::yield_now().await; // arm the timer at t0 (see above)
        tokio::time::advance(
            DEFAULT_CONSENT_TIMEOUT + CONSENT_VERDICT_GRACE + Duration::from_millis(1),
        )
        .await;
        assert_eq!(wait.await.unwrap(), ConsentOutcome::Timeout);
    }

    #[test]
    fn the_grace_is_added_to_the_wait_not_to_the_window() {
        // The wire number the agent prompts for is the WINDOW; only the hub's
        // wait is longer. If these were ever equal the race would be back.
        assert!(hub_consent_deadline(DEFAULT_CONSENT_TIMEOUT) > DEFAULT_CONSENT_TIMEOUT);
        assert_eq!(
            hub_consent_deadline(ASYNC_CONSENT_TIMEOUT),
            ASYNC_CONSENT_TIMEOUT + CONSENT_VERDICT_GRACE
        );
    }

    #[tokio::test]
    async fn granted() {
        let (slot, waiter) = ConsentSlot::new();
        slot.resolve(ConsentOutcome::Granted).unwrap();
        assert_eq!(
            waiter.wait(Duration::from_millis(50)).await,
            ConsentOutcome::Granted
        );
    }

    #[tokio::test]
    async fn denied() {
        let (slot, waiter) = ConsentSlot::new();
        slot.resolve(ConsentOutcome::Denied).unwrap();
        assert_eq!(
            waiter.wait(Duration::from_millis(50)).await,
            ConsentOutcome::Denied
        );
    }

    #[tokio::test]
    async fn times_out() {
        let (_slot, waiter) = ConsentSlot::new();
        let t0 = std::time::Instant::now();
        let outcome = waiter.wait(Duration::from_millis(20)).await;
        assert_eq!(outcome, ConsentOutcome::Timeout);
        assert!(t0.elapsed() < Duration::from_millis(100));
    }

    /// FR-27 — the defect this type exists to close: an agent-side prompt
    /// timeout used to arrive as a bare `granted: false` and be reported to the
    /// controller as "the user denied your request".
    #[test]
    fn a_bare_false_is_a_deny_but_a_reasoned_one_is_not() {
        assert_eq!(outcome_of(false, None), ConsentOutcome::Denied);
        assert_eq!(outcome_of(false, Some("timeout")), ConsentOutcome::Timeout);
        assert_eq!(
            outcome_of(false, Some("no_prompt_surface")),
            ConsentOutcome::NoPromptSurface
        );
    }

    /// A reason from a NEWER agent that this server has never heard of must
    /// degrade to the historical meaning, never fail the frame.
    #[test]
    fn an_unknown_reason_degrades_to_deny() {
        assert_eq!(
            outcome_of(false, Some("invented_in_a_later_release")),
            ConsentOutcome::Denied
        );
        assert!(ConsentDenyReason::from_wire("").is_none());
    }

    /// `granted: true` wins regardless of what else is on the frame — a reason
    /// alongside a grant is nonsense, and it must not be able to deny.
    #[test]
    fn a_grant_ignores_any_reason() {
        assert_eq!(outcome_of(true, Some("timeout")), ConsentOutcome::Granted);
        assert_eq!(outcome_of(true, None), ConsentOutcome::Granted);
    }

    /// Renaming a spelling doesn't fail loudly — it silently turns every
    /// deployed agent's report back into "denied". Pin them.
    #[test]
    fn deny_reason_wire_strings_are_locked() {
        assert_eq!(ConsentDenyReason::HostTimeout.wire(), "timeout");
        assert_eq!(
            ConsentDenyReason::NoPromptSurface.wire(),
            "no_prompt_surface"
        );
        // FR-129 — the device's two-factor refusals, the same spellings as
        // `meshharbor_node_core::two_factor::Refusal::wire`.
        assert_eq!(
            ConsentDenyReason::TwoFactorRequired.wire(),
            "two_factor_required"
        );
        assert_eq!(
            ConsentDenyReason::TwoFactorInvalid.wire(),
            "two_factor_invalid"
        );
        assert_eq!(
            ConsentDenyReason::TwoFactorLocked.wire(),
            "two_factor_locked"
        );
        assert_eq!(
            ConsentDenyReason::TwoFactorUnavailable.wire(),
            "two_factor_unavailable"
        );
        assert_eq!(
            outcome_of(false, Some("two_factor_unavailable")),
            ConsentOutcome::TwoFactorLocked
        );
        for r in ConsentDenyReason::ALL {
            assert_eq!(ConsentDenyReason::from_wire(r.wire()), Some(*r));
        }
    }

    /// `prompt_then_email`'s host half is SHORT — shorter than both the plain
    /// attended window (which is long, 5 min, so a human can reach a locked
    /// machine) and the async window — because its emailed link is the fallback,
    /// so the host modal need not linger. A five-minute modal is an obstruction;
    /// the owner, reached remotely, is who gets the long window.
    #[test]
    fn the_prompt_then_email_host_window_is_short() {
        assert!(HOST_PROMPT_TIMEOUT < DEFAULT_CONSENT_TIMEOUT);
        assert!(HOST_PROMPT_TIMEOUT < ASYNC_CONSENT_TIMEOUT);
        // Plain prompt has no remote fallback, so it waits the full async span.
        assert_eq!(DEFAULT_CONSENT_TIMEOUT, ASYNC_CONSENT_TIMEOUT);
    }
}
