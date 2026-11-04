// SPDX-License-Identifier: AGPL-3.0-only
//! FR-32 — the single decision point for plan-limit checks.
//!
//! `Plan::limits()` publishes fourteen numbers through `GET /api/stripe/plans`
//! and we take money against them. Before FR-32 exactly three were read back:
//! `max_devices` (twice) and `max_tunnel_clients` (once), each as a hand-rolled
//! count-compare-format block. The other eleven were advertised and enforced
//! nowhere.
//!
//! Eleven more copies of that block would be eleven chances to forget the mode
//! check, the log line, or the record. So the comparison lives here instead —
//! the same argument the SSH work settled on, where `decide` returns
//! `Result<Granted, SshDenyReason>` and `dispatch` records *both* arms in one
//! place: the refusals are the load-bearing rows, so recording them cannot be
//! per-call-site.

use meshharbor_db::models::{Plan, PlanEnforcement, PlanLimits};

/// Which advertised limit a check is about.
///
/// The `match` in [`Limit::describe`] is exhaustive, so adding a field to
/// [`PlanLimits`] fails to compile until someone decides whether it is a gate.
/// Same structural trick as `RpcCap::wire()` — the compiler asks the question
/// that review would otherwise have to remember to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    // ── Established before FR-32: always enforced ───────────────────
    MaxDevices,
    MaxTunnelClients,
    // ── Wired by FR-32: subject to `PlanEnforcement` ────────────────
    MaxMembers,
    MaxChannels,
    StorageBytes,
    VideoMaxParticipants,
    MaxConcurrentSessions,
    ExitNodes,
    MagicDns,
    Recordings,
    CloudIntegrations,
    // ── Wired by FR-115 ──────────────────────────────────────────────
    /// How long one meeting may run, in minutes — "may it run one more
    /// minute?", so `used` is the minutes it has already run.
    MeetingMinutes,
}

impl Limit {
    /// The wire spelling (FR-102 P4: the `limit` dimension of a counted
    /// collision). Exhaustive, so a new limit is named before it compiles.
    pub fn as_str(self) -> &'static str {
        match self {
            Limit::MaxDevices => "max_devices",
            Limit::MaxTunnelClients => "max_tunnel_clients",
            Limit::MaxMembers => "max_members",
            Limit::MaxChannels => "max_channels",
            Limit::StorageBytes => "storage_bytes",
            Limit::VideoMaxParticipants => "video_max_participants",
            Limit::MaxConcurrentSessions => "max_concurrent_sessions",
            Limit::ExitNodes => "exit_nodes",
            Limit::MagicDns => "magic_dns",
            Limit::Recordings => "recordings",
            Limit::CloudIntegrations => "cloud_integrations",
            Limit::MeetingMinutes => "meeting_max_minutes",
        }
    }

    /// Was this limit already enforced before FR-32?
    ///
    /// ⚠ **Load-bearing.** `PlanEnforcement` exists to stage *new* enforcement
    /// safely, not to hand anyone a switch that turns the device cap off. An
    /// established limit therefore ignores the mode and always refuses.
    ///
    /// Without this, re-pointing the three existing call sites through
    /// [`check`] would silently downgrade them to warnings the moment this
    /// lands, because the mode defaults to [`PlanEnforcement::Warn`] — a
    /// billing regression introduced by a refactor that reads as a cleanup.
    ///
    /// FR-115 D2 added `MaxMembers`: with per-seat pricing, Free's ten users
    /// is the line a team crosses into a paid plan, so the operator made it
    /// a cap rather than an observation. Grandfathering does not arise —
    /// paid plans have no member cap, and no Free org was over ten when it
    /// landed (the FR-115 census).
    ///
    /// FR-115 P3 added `MaxConcurrentSessions`, the fence on Free that
    /// replaces "personal use" detection. The hub enforces it at session
    /// start (`Hub::create_session_full`); listing it here keeps any future
    /// check through this function from softening it under `warn`.
    ///
    /// FR-115 P5 added the two meeting fences, `VideoMaxParticipants` and
    /// `MeetingMinutes`: "10 people, 60 minutes" is what the Free ladder
    /// sells, and a fence that `warn` (every new org's default) lets through
    /// is not one. The participant count can only under-count (it reads the
    /// owner pod's room), so the cap fails open, never on a seat that exists.
    pub fn is_established(self) -> bool {
        matches!(
            self,
            Limit::MaxDevices
                | Limit::MaxTunnelClients
                | Limit::MaxMembers
                | Limit::MaxConcurrentSessions
                | Limit::VideoMaxParticipants
                | Limit::MeetingMinutes
        )
    }

    /// The limit's value for a plan, plus the noun used in the refusal message.
    ///
    /// `None` = the plan does not cap this limit (an unlimited count, or an
    /// enabled boolean feature).
    pub fn describe(self, limits: &PlanLimits) -> (Option<u64>, &'static str) {
        match self {
            Limit::MaxDevices => (count_cap(limits.max_devices), "devices"),
            Limit::MaxTunnelClients => (count_cap(limits.max_tunnel_clients), "tunnel clients"),
            Limit::MaxMembers => (count_cap(limits.max_members), "members"),
            Limit::MaxChannels => (count_cap(limits.max_channels), "channels"),
            Limit::StorageBytes => (Some(limits.storage_bytes), "bytes of storage"),
            Limit::VideoMaxParticipants => (
                count_cap(limits.video_max_participants),
                "call participants",
            ),
            Limit::MaxConcurrentSessions => (
                count_cap(limits.max_concurrent_sessions),
                "concurrent remote-control sessions",
            ),
            // Boolean features: `false` caps at zero, `true` does not cap.
            Limit::ExitNodes => (bool_cap(limits.exit_nodes), "exit nodes"),
            Limit::MagicDns => (bool_cap(limits.magic_dns), "MagicDNS"),
            Limit::Recordings => (bool_cap(limits.recordings), "recordings"),
            Limit::CloudIntegrations => (bool_cap(limits.cloud_integrations), "cloud integrations"),
            Limit::MeetingMinutes => (
                count_cap(limits.meeting_max_minutes),
                "minutes of meeting time",
            ),
        }
    }
}

/// A boolean feature as a cap: off means zero allowed, on means uncapped.
fn bool_cap(enabled: bool) -> Option<u64> {
    if enabled { None } else { Some(0) }
}

/// A counted cap, honouring this codebase's **unlimited sentinel**.
///
/// ⚠ `PlanLimits` spells "unlimited" as `u32::MAX` (`Pro.max_members`,
/// `Pro.max_channels`, `Business.max_concurrent_sessions`, …), not as an
/// `Option`. Comparing against it as if it were a real number is wrong twice
/// over: it would refuse a tenant that the plan matrix calls unlimited, and it
/// would file denial records with a bogus `max` of 4 294 967 295 — poisoning
/// exactly the data P2 and P3 are supposed to read.
///
/// A unit test pins this; it is the reason the test exists.
fn count_cap(v: u32) -> Option<u64> {
    if v == u32::MAX { None } else { Some(v as u64) }
}

/// A limit that was exceeded. Returned only when the caller must refuse.
#[derive(Debug, Clone)]
pub struct QuotaDenial {
    pub limit: Limit,
    pub plan: Plan,
    pub used: u64,
    pub max: u64,
    pub noun: &'static str,
}

impl QuotaDenial {
    /// Is this a disabled *feature* rather than an exhausted *count*?
    ///
    /// A boolean feature that the plan does not include caps at zero, so the
    /// counting wording ("0 of 0 recordings used") would be nonsense. The two
    /// cases need different sentences, and the distinction is `max == 0`.
    pub fn is_feature_gate(&self) -> bool {
        self.max == 0
    }

    /// The message shown to the caller. Deliberately the same shape the three
    /// pre-FR-32 sites already used, so P0 is observable-behaviour-neutral.
    pub fn message(&self) -> String {
        if self.is_feature_gate() {
            return format!(
                "{} {} not available on the {:?} plan. Upgrade to enable.",
                capitalise(self.noun),
                if self.noun.ends_with('s') {
                    "are"
                } else {
                    "is"
                },
                self.plan,
            );
        }
        format!(
            "{} limit reached for the {:?} plan ({} of {} {} used). \
             Upgrade the plan or remove one first.",
            capitalise(self.noun),
            self.plan,
            self.used,
            self.max,
            self.noun,
        )
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Check one limit for a tenant.
///
/// `used` is the count *before* the operation the caller is about to perform,
/// so the comparison is `used >= max` — matching the three pre-FR-32 sites,
/// where a tenant at exactly its cap is refused the next one.
///
/// Returns `Ok(())` when the operation may proceed. That includes the
/// [`PlanEnforcement::Warn`] case, which records the denial and lets the
/// request through — the observe phase must produce data without refusing.
pub fn check(
    plan: Plan,
    mode: PlanEnforcement,
    limit: Limit,
    used: u64,
) -> Result<(), QuotaDenial> {
    // "May I add one more?" is the delta form with delta = 1.
    check_delta(plan, mode, limit, used, 1)
}

/// Check whether `delta` more units fit under the limit.
///
/// ⚠ The counted limits add ONE thing at a time, so `used >= max` is the right
/// test for them. `storage_bytes` does not: a tenant at 99 MB of 100 MB must be
/// refused a 10 MB upload and ALLOWED a 100 KB one, which `used >= max` cannot
/// express — it would accept both, right up until the quota was already blown,
/// and then reject a 1-byte file. The size is only knowable after the multipart
/// body is read, so the check is inherently "current + incoming", not "current".
///
/// Refuses when `current + delta > max`, so a file that exactly fills the quota
/// still fits.
pub fn check_delta(
    plan: Plan,
    mode: PlanEnforcement,
    limit: Limit,
    current: u64,
    delta: u64,
) -> Result<(), QuotaDenial> {
    check_inner(plan, mode, limit, current, delta)
}

fn check_inner(
    plan: Plan,
    mode: PlanEnforcement,
    limit: Limit,
    used: u64,
    delta: u64,
) -> Result<(), QuotaDenial> {
    evaluate(plan, mode, limit, used, delta).into_result()
}

/// FR-102 P4 — the whole verdict of one check: the collision, when the
/// limit was hit (whether or not it refuses — `warn` mode lets it through),
/// and whether it refuses. `meshharbor_core::quota` counts the collision per
/// org; [`check`] and its siblings keep answering only the refusal.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// The limit was exceeded (the warn line was written for it).
    pub collision: Option<QuotaDenial>,
    /// The collision refuses the operation.
    pub enforced: bool,
}

impl Verdict {
    fn pass() -> Self {
        Self {
            collision: None,
            enforced: false,
        }
    }

    /// `Err` only when the collision refuses.
    pub fn into_result(self) -> Result<(), QuotaDenial> {
        match (self.collision, self.enforced) {
            (Some(denial), true) => Err(denial),
            _ => Ok(()),
        }
    }
}

/// [`check_delta`]'s decision, with the collision visible even when it does
/// not refuse. The warn line is written here, once per collision. One seat —
/// an org's own check goes through [`evaluate_for`] with its billed seats.
pub fn evaluate(plan: Plan, mode: PlanEnforcement, limit: Limit, used: u64, delta: u64) -> Verdict {
    evaluate_for(plan, 1, mode, limit, used, delta)
}

/// FR-115 — [`evaluate`] for an org billed for `seats` seats: the per-seat
/// limits (`storage_bytes`, `max_concurrent_sessions`) are scaled by
/// [`Plan::limits_for`] before the comparison. `meshharbor_core::quota` passes
/// `Tenant::billed_seats`.
pub fn evaluate_for(
    plan: Plan,
    seats: u32,
    mode: PlanEnforcement,
    limit: Limit,
    used: u64,
    delta: u64,
) -> Verdict {
    // `Off` means no check runs — but never for a limit that was already
    // enforced before FR-32, which the mode was never meant to reach.
    if matches!(mode, PlanEnforcement::Off) && !limit.is_established() {
        return Verdict::pass();
    }

    let limits = plan.limits_for(seats);
    let (Some(max), noun) = limit.describe(&limits) else {
        return Verdict::pass(); // uncapped for this plan
    };

    // Saturating, so a pathological delta cannot wrap into "fits".
    if used.saturating_add(delta) <= max {
        return Verdict::pass();
    }

    // An established limit ignores the mode entirely — see `is_established`.
    let enforcing = limit.is_established() || matches!(mode, PlanEnforcement::Enforce);
    let denial = QuotaDenial {
        limit,
        plan,
        used,
        max,
        noun,
    };

    // Every denial is recorded here, in both arms, exactly once. A gate that
    // forgets to log is a gate whose impact cannot be measured before P2 flips
    // it, which is the whole reason the observe phase exists.
    tracing::warn!(
        limit = ?limit,
        plan = ?denial.plan,
        used = denial.used,
        max = denial.max,
        mode = ?mode,
        enforced = enforcing,
        "plan limit exceeded"
    );

    Verdict {
        collision: Some(denial),
        enforced: enforcing,
    }
}

/// Gate a boolean plan feature.
///
/// The counted form of [`check`] already models this — a feature the plan does
/// not include caps at zero, so `used = 0` trips it — but spelling that at each
/// call site would mean writing a bare `0` whose meaning is not local. This
/// names it instead.
pub fn require_feature(plan: Plan, mode: PlanEnforcement, limit: Limit) -> Result<(), QuotaDenial> {
    check(plan, mode, limit, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Free (FR-115): storage 1 GiB (wired by FR-32, subject to the mode);
    // max_members = 10, video_max_participants = 10 and meetings of 60
    // minutes (ESTABLISHED since FR-115); max_devices = 100; recordings and
    // exit nodes off, MagicDNS on.

    const GIB: u64 = meshharbor_db::models::tenant::GIB;

    #[test]
    fn under_the_cap_always_passes() {
        for mode in [
            PlanEnforcement::Off,
            PlanEnforcement::Warn,
            PlanEnforcement::Enforce,
        ] {
            assert!(check_delta(Plan::Free, mode, Limit::StorageBytes, GIB - 10, 10).is_ok());
            assert!(check(Plan::Free, mode, Limit::MaxMembers, 9).is_ok());
            assert!(check(Plan::Free, mode, Limit::VideoMaxParticipants, 9).is_ok());
        }
    }

    #[test]
    fn warn_records_but_does_not_refuse() {
        // Over the cap: the observe phase must let this through.
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Warn,
                Limit::StorageBytes,
                GIB,
                1
            )
            .is_ok()
        );
    }

    #[test]
    fn enforce_refuses_at_the_cap() {
        let d = check_delta(
            Plan::Free,
            PlanEnforcement::Enforce,
            Limit::StorageBytes,
            GIB,
            1,
        )
        .expect_err("a full Free org's next byte must be refused under Enforce");
        assert_eq!(d.used, GIB);
        assert_eq!(d.max, GIB);
        assert_eq!(d.limit, Limit::StorageBytes);
    }

    #[test]
    fn off_disables_a_newly_wired_limit() {
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Off,
                Limit::StorageBytes,
                999 * GIB,
                1
            )
            .is_ok()
        );
    }

    /// FR-115 P5 — "10 people, 60 minutes" is what Free sells, so neither
    /// fence may soften under `warn`, every new org's default. A meeting
    /// asks "may I run one more minute?", so `used` is the minutes it has
    /// run: 59 passes, 60 is the end.
    #[test]
    fn the_free_meeting_fences_ignore_the_mode() {
        for mode in [
            PlanEnforcement::Off,
            PlanEnforcement::Warn,
            PlanEnforcement::Enforce,
        ] {
            let d = check(Plan::Free, mode, Limit::VideoMaxParticipants, 10)
                .expect_err("an eleventh person in a Free meeting must be refused");
            assert_eq!((d.used, d.max), (10, 10));

            assert!(check(Plan::Free, mode, Limit::MeetingMinutes, 59).is_ok());
            let d = check(Plan::Free, mode, Limit::MeetingMinutes, 60)
                .expect_err("a Free meeting ends at 60 minutes");
            assert_eq!((d.used, d.max), (60, 60));
        }
        // Paid meetings have no length cap at all (the unlimited sentinel).
        for plan in [Plan::Pro, Plan::Business, Plan::Enterprise] {
            assert!(
                check(
                    plan.clone(),
                    PlanEnforcement::Enforce,
                    Limit::MeetingMinutes,
                    100_000
                )
                .is_ok(),
                "{plan:?} meetings must not end on a clock"
            );
        }
    }

    /// The regression this whole `is_established` distinction exists to stop:
    /// P0 re-points the device cap through `check`, and the mode defaults to
    /// `Warn`. If the mode applied to it, shipping P0 would stop enforcing the
    /// device limit fleet-wide — a billing regression that reads as a cleanup.
    #[test]
    fn an_established_limit_ignores_the_mode() {
        for mode in [
            PlanEnforcement::Off,
            PlanEnforcement::Warn,
            PlanEnforcement::Enforce,
        ] {
            assert!(
                check(Plan::Free, mode, Limit::MaxDevices, 100).is_err(),
                "max_devices must refuse under {mode:?} — it was enforced before FR-32"
            );
            assert!(
                check(Plan::Free, mode, Limit::MaxTunnelClients, 100).is_err(),
                "max_tunnel_clients must refuse under {mode:?} — it was enforced before FR-32"
            );
            assert!(
                check(Plan::Free, mode, Limit::MaxConcurrentSessions, 1).is_err(),
                "FR-115 P3 — Free's one session at a time holds under {mode:?}"
            );
        }
    }

    /// FR-115 D2 — Free's ten users is a cap in every mode: per-seat pricing
    /// makes it the line a team crosses into a paid plan, so `warn` and `off`
    /// must not soften it the way they soften the FR-32 gates.
    #[test]
    fn the_free_member_cap_ignores_the_mode() {
        for mode in [
            PlanEnforcement::Off,
            PlanEnforcement::Warn,
            PlanEnforcement::Enforce,
        ] {
            let d = check(Plan::Free, mode, Limit::MaxMembers, 10)
                .expect_err("an eleventh member of a Free org must be refused");
            assert_eq!((d.used, d.max), (10, 10));
            assert!(check(Plan::Free, mode, Limit::MaxMembers, 9).is_ok());
        }
        // A paid plan has no member cap at all: every user is a billed seat.
        assert!(
            check(
                Plan::Pro,
                PlanEnforcement::Enforce,
                Limit::MaxMembers,
                5_000
            )
            .is_ok()
        );
    }

    /// A disabled feature must not be described with counting words. "0 of 0
    /// recordings used. Upgrade the plan or remove one first" tells a customer
    /// to remove something that does not exist.
    #[test]
    fn a_feature_gate_reads_as_a_feature_not_a_count() {
        let d = require_feature(Plan::Free, PlanEnforcement::Enforce, Limit::Recordings)
            .expect_err("Free does not include recordings");
        assert!(d.is_feature_gate());
        let m = d.message();
        assert_eq!(
            m,
            "Recordings are not available on the Free plan. Upgrade to enable."
        );
        assert!(
            !m.contains("0 of 0"),
            "feature gates must not use counting words: {m}"
        );

        // Singular noun agreement — "MagicDNS is", not "MagicDNS are". Every
        // plan has MagicDNS since FR-115, so the denial is built by hand.
        let d = QuotaDenial {
            limit: Limit::MagicDns,
            plan: Plan::Free,
            used: 0,
            max: 0,
            noun: "MagicDNS",
        };
        assert_eq!(
            d.message(),
            "MagicDNS is not available on the Free plan. Upgrade to enable."
        );
    }

    /// A count that runs out is still described by counting.
    #[test]
    fn a_count_gate_keeps_the_counting_message() {
        let d = check(Plan::Free, PlanEnforcement::Enforce, Limit::MaxMembers, 10).unwrap_err();
        assert!(!d.is_feature_gate());
        assert!(
            d.message().contains("10 of 10 members used"),
            "{}",
            d.message()
        );
    }

    /// `require_feature` passes when the plan includes the feature.
    #[test]
    fn require_feature_passes_when_the_plan_includes_it() {
        assert!(require_feature(Plan::Pro, PlanEnforcement::Enforce, Limit::MagicDns).is_ok());
        assert!(require_feature(Plan::Pro, PlanEnforcement::Enforce, Limit::ExitNodes).is_ok());
        assert!(
            require_feature(Plan::Business, PlanEnforcement::Enforce, Limit::Recordings).is_ok()
        );
        // FR-115 — MagicDNS is on Free; exit nodes wait for the relay throttle.
        assert!(require_feature(Plan::Free, PlanEnforcement::Enforce, Limit::MagicDns).is_ok());
        assert!(require_feature(Plan::Free, PlanEnforcement::Enforce, Limit::ExitNodes).is_err());
        // ...and Warn never refuses, even for a feature the plan lacks.
        assert!(require_feature(Plan::Free, PlanEnforcement::Warn, Limit::Recordings).is_ok());
    }

    /// The bug the delta form exists to prevent: a tenant near its storage
    /// quota must be judged on the SIZE of what they are uploading, not merely
    /// on whether they are already at the cap.
    #[test]
    fn storage_is_judged_on_the_incoming_size() {
        const MB: u64 = 1024 * 1024;
        // Free.storage_bytes is 1 GiB; sit the tenant 1 MB under it.
        let used = meshharbor_db::models::tenant::GIB - MB;

        // A 100 KB file still fits...
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::StorageBytes,
                used,
                100 * 1024
            )
            .is_ok()
        );
        // ...a 10 MB file does not.
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::StorageBytes,
                used,
                10 * MB
            )
            .is_err()
        );
        // A file that EXACTLY fills the remaining quota is allowed — `>` not `>=`.
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::StorageBytes,
                used,
                MB
            )
            .is_ok()
        );
        // One byte more is not.
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::StorageBytes,
                used,
                MB + 1
            )
            .is_err()
        );
    }

    /// A pathological delta must not wrap into "fits".
    #[test]
    fn a_saturating_delta_cannot_overflow_into_success() {
        assert!(
            check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::StorageBytes,
                u64::MAX,
                1
            )
            .is_err()
        );
    }

    /// `check` is the delta form with delta = 1, so the two must agree.
    #[test]
    fn check_is_delta_of_one() {
        for used in [0u64, 5, 9, 10, 11] {
            let a = check(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::MaxMembers,
                used,
            )
            .is_err();
            let b = check_delta(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::MaxMembers,
                used,
                1,
            )
            .is_err();
            assert_eq!(a, b, "disagreement at used={used}");
        }
    }

    #[test]
    fn a_disabled_boolean_feature_caps_at_zero() {
        // Free has recordings = false, so even the first one is refused.
        assert!(check(Plan::Free, PlanEnforcement::Enforce, Limit::Recordings, 0).is_err());
        // Business has recordings = true, so it is uncapped.
        assert!(
            check(
                Plan::Business,
                PlanEnforcement::Enforce,
                Limit::Recordings,
                500
            )
            .is_ok()
        );
    }

    /// `PlanLimits` spells "unlimited" as `u32::MAX`, not as an `Option`.
    /// Treating that as a real cap would refuse a tenant the plan matrix calls
    /// unlimited, and would file denial rows with a bogus max — corrupting the
    /// dataset P2/P3 exist to read. This test caught exactly that bug.
    #[test]
    fn the_unlimited_sentinel_is_not_a_cap() {
        // Pro: max_members = u32::MAX. Business: max_concurrent_sessions = u32::MAX.
        assert!(
            check(
                Plan::Pro,
                PlanEnforcement::Enforce,
                Limit::MaxMembers,
                u64::MAX
            )
            .is_ok()
        );
        assert!(
            check(
                Plan::Pro,
                PlanEnforcement::Enforce,
                Limit::MaxChannels,
                1_000_000
            )
            .is_ok()
        );
        // FR-115 — chat has no cap on Free either.
        assert!(
            check(
                Plan::Free,
                PlanEnforcement::Enforce,
                Limit::MaxChannels,
                1_000_000
            )
            .is_ok()
        );
        assert!(
            check(
                Plan::Business,
                PlanEnforcement::Enforce,
                Limit::MaxConcurrentSessions,
                9_999
            )
            .is_ok()
        );
        // ...but a real cap on the same field still bites.
        assert!(check(Plan::Free, PlanEnforcement::Enforce, Limit::MaxMembers, 10).is_err());
    }

    /// FR-115 — an org's check is against its BILLED seats: Pro's one
    /// session per seat lets a three-seat org run three, not four; storage
    /// scales the same way; a count that is per org (devices) does not.
    #[test]
    fn per_seat_limits_are_checked_against_the_billed_seats() {
        let e = PlanEnforcement::Enforce;
        assert!(
            evaluate_for(Plan::Pro, 3, e, Limit::MaxConcurrentSessions, 2, 1)
                .collision
                .is_none()
        );
        let v = evaluate_for(Plan::Pro, 3, e, Limit::MaxConcurrentSessions, 3, 1);
        assert_eq!(v.collision.as_ref().map(|d| d.max), Some(3));

        let gib = meshharbor_db::models::tenant::GIB;
        assert!(
            evaluate_for(Plan::Pro, 4, e, Limit::StorageBytes, 35 * gib, gib)
                .collision
                .is_none(),
            "4 seats hold 40 GiB"
        );
        assert!(
            evaluate_for(Plan::Pro, 4, e, Limit::StorageBytes, 40 * gib, 1)
                .collision
                .is_some()
        );
        assert_eq!(
            evaluate_for(Plan::Pro, 4, e, Limit::MaxDevices, 1_000, 1)
                .collision
                .map(|d| d.max),
            Some(1_000),
            "devices are per org, not per seat"
        );
        // `evaluate` is one seat.
        assert_eq!(
            evaluate(Plan::Pro, e, Limit::MaxConcurrentSessions, 1, 1)
                .collision
                .map(|d| d.max),
            Some(1)
        );
    }

    /// FR-102 P4 — the verdict shows a collision in `warn` mode too (the
    /// upgrade-intent signal must not depend on enforcement), refuses only
    /// when enforcing, and is empty under the cap or with checks `off`.
    #[test]
    fn a_collision_is_visible_whether_or_not_it_refuses() {
        let storage = Limit::StorageBytes;
        let warn = evaluate(Plan::Free, PlanEnforcement::Warn, storage, GIB, 1);
        assert!(warn.collision.is_some());
        assert!(!warn.enforced);
        assert!(warn.into_result().is_ok(), "warn lets it through");

        let enforce = evaluate(Plan::Free, PlanEnforcement::Enforce, storage, GIB, 1);
        assert!(enforce.collision.is_some() && enforce.enforced);
        assert!(enforce.into_result().is_err());

        let under = evaluate(Plan::Free, PlanEnforcement::Enforce, storage, GIB - 1, 1);
        assert!(under.collision.is_none());

        let off = evaluate(Plan::Free, PlanEnforcement::Off, storage, 99 * GIB, 1);
        assert!(off.collision.is_none(), "off runs no check, counts nothing");

        // An established limit ignores the mode: off still collides, and refuses.
        for (limit, at) in [
            (Limit::MaxDevices, 100),
            (Limit::MaxMembers, 10),
            (Limit::VideoMaxParticipants, 10),
            (Limit::MeetingMinutes, 60),
        ] {
            let v = evaluate(Plan::Free, PlanEnforcement::Off, limit, at, 1);
            assert!(v.collision.is_some() && v.enforced, "{limit:?} at {at}");
        }
    }

    /// The `limit` dimension's spellings are stored keys.
    #[test]
    fn limit_spellings_are_locked() {
        assert_eq!(Limit::MaxMembers.as_str(), "max_members");
        assert_eq!(Limit::MaxDevices.as_str(), "max_devices");
        assert_eq!(Limit::StorageBytes.as_str(), "storage_bytes");
        assert_eq!(Limit::MagicDns.as_str(), "magic_dns");
        assert_eq!(Limit::CloudIntegrations.as_str(), "cloud_integrations");
        assert_eq!(
            Limit::VideoMaxParticipants.as_str(),
            "video_max_participants"
        );
        assert_eq!(Limit::MeetingMinutes.as_str(), "meeting_max_minutes");
    }
}
