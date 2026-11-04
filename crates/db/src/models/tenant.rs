// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub owner_id: ObjectId,
    pub plan: Plan,
    pub features: Vec<String>,
    pub settings: TenantSettings,
    pub billing: Option<BillingInfo>,
    pub integrations: Option<IntegrationSettings>,
    #[serde(default)]
    pub is_archived: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub deleted_at: Option<DateTime>,
}

/// FR-32 — how far plan-limit checks are allowed to go for a tenant.
///
/// Mirrors [`crate::models::OverlayNetwork`]'s `acl_mode` deliberately, and for
/// the same reason: turning eleven previously-unenforced gates on against a live
/// fleet would lock out tenants that *we* let over the line.
///
/// # ⚠ `Warn` is the default BY STANDING DECISION — do not "fix" it
///
/// The original reason was the observe phase: a mode that does nothing produces
/// no data, and learning who *would* be denied was the point. **That reason is
/// spent.** The observe phase is over, every existing tenant has been moved to
/// [`Self::Enforce`], and the argument for keeping `Warn` as the default is now
/// a different one:
///
/// The grandfathering hazard does not apply to a NEW tenant — it starts at zero
/// usage and cannot be retroactively over a limit. So `Warn` here is not a
/// safety net; it is a deliberate **go-to-market choice** (operator, 2026-08-30):
/// while the product is in early growth, a promising signup must not be stopped
/// at 10 members or 100 MB before anyone has spoken to them.
///
/// The consequence is worth stating plainly, because it looks like a bug: with
/// this default, the advertised plan limits **do not fire for anyone who signs
/// up**. That is intended for now.
///
/// **Revisit when** the product leaves early growth, or when a real (non-test,
/// non-internal) tenant is on a paid plan — whichever comes first. Flipping
/// `#[default]` to `Enforce` is the whole change; the mode stays as a per-tenant
/// escape hatch and as the grandfathering mechanism for any future gate
/// introduced against existing usage. See FR-32 (#898).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlanEnforcement {
    /// No check runs at all.
    Off,
    /// The check runs and the denial is recorded, but the request succeeds.
    #[default]
    Warn,
    /// The denial is returned to the caller.
    Enforce,
}

/// FR-101 P2 — one remote-session feature (clipboard, files, audio), as an org
/// allows it. Stored lowercase.
///
/// ⚠️ A value this build does not know reads as [`Self::Off`], never as an
/// error: an unknown string would otherwise fail the WHOLE tenant document
/// after a rollback from a server that wrote it, and the strict direction is
/// the one a security policy may fail in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RcFeaturePolicy {
    /// Allowed, subject to the session's grant.
    #[default]
    On,
    /// Allowed only on a session the person at the device approves, on a
    /// prompt that names the feature. Refused on any other: an auto-granting
    /// device, the owner's own session without `prompt_owner`, break-glass,
    /// and an approval by the owner's email or push rather than by the
    /// person there.
    Ask,
    /// Never.
    Off,
}

impl<'de> Deserialize<'de> for RcFeaturePolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Any BSON type, not only a string: a number or a null in a
        // hand-edited row must not fail the document either.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Text(String),
            Other(serde::de::IgnoredAny),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Text(s) if s == "on" => Self::On,
            Raw::Text(s) if s == "ask" => Self::Ask,
            // "off", anything a newer server may have written, and anything
            // that is not a string at all.
            _ => Self::Off,
        })
    }
}

/// FR-101 P2 — the org's remote-desktop session policy: per feature, whether
/// a session in this org may carry it. Every field defaults to `on`, so a
/// tenant document from before the feature behaves exactly as it always did.
/// The hub strips what it refuses (naming why); the device enforces it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RcSessionPolicy {
    #[serde(default)]
    pub clipboard: RcFeaturePolicy,
    #[serde(default)]
    pub files: RcFeaturePolicy,
    #[serde(default)]
    pub audio: RcFeaturePolicy,
}

/// FR-101 P4b — how long a remote-desktop session in this org may last, and
/// how long it may sit idle. Nothing set (every row older than the fields) is
/// no limit, the behaviour from before them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RcSessionLimits {
    /// A session ends this many seconds after it started (went live), with
    /// `EndReason::IdleTimeout`. `None` = no maximum. The route accepts one
    /// minute to one day; a smaller stored value still works (the tests use
    /// one), so the hub reads whatever is here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_secs: Option<u32>,
    /// P4b-2 — a session ends after this many seconds with no input from its
    /// controller and no significant change on the screen, with
    /// `EndReason::IdleTimeout`. `None` = no idle limit. Measured and enforced
    /// by the AGENT, the one party that sees both; the device's own
    /// `AccessPolicy::auto_terminate_idle_minutes` may set a shorter one. The
    /// same range and the same leniency as [`Self::max_secs`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    #[default]
    Free,
    Pro,
    Business,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    #[serde(default = "default_locale")]
    pub default_locale: String,
    #[serde(default)]
    pub default_message_notifications: NotificationLevel,
    #[serde(default)]
    pub mfa_required: bool,
    #[serde(default)]
    pub allow_guest_access: bool,
    // FR-32 — `max_members` and `file_upload_limit` lived here and were REMOVED.
    // They shadowed `PlanLimits::{max_members, storage_bytes}` and had zero
    // readers in the entire workspace — not two enforcers disagreeing, two dead
    // fields shadowing two dead fields. They also disagreed with the plan they
    // shadowed by 10x (this defaulted to 100; Free's PlanLimits says 10), so
    // wiring the wrong one would have changed who is over the line.
    //
    // `PlanLimits` is the single source of truth: it is what
    // `GET /api/stripe/plans` publishes, what `BillingView.vue` renders, and
    // what the billing test asserts. Serde ignores the leftover key in existing
    // tenant documents, so no migration is needed.
    //
    // A per-tenant override may well be wanted for bespoke Enterprise deals —
    // the same problem as the phantom `Enterprise` tier. Add it deliberately
    // then, with stated semantics, rather than inheriting one from an accident.
    /// Phase 2 MagicDNS — the tenant's overlay DNS suffix (e.g.
    /// `"myorg.roomler.net"`). When set, overlay nodes run a local split-DNS
    /// resolver that answers `<node-name>.<domain>` with the peer's overlay IP.
    /// `None` = MagicDNS off for the tenant.
    #[serde(default)]
    pub magic_dns_domain: Option<String>,
    /// Phase 2 MagicDNS — upstream nameservers the resolver forwards
    /// non-overlay queries to (e.g. `["1.1.1.1"]`). Empty = use the node's
    /// existing system resolvers as the fallback.
    #[serde(default)]
    pub magic_dns_nameservers: Vec<String>,
    /// Fleet RPC — the org-wide kill-switch (gate 1 of four). `false` (the
    /// default, and what every pre-feature row deserialises to) means no
    /// device in this org accepts a remote command, whatever its own
    /// `ExecPolicy` says. Flipping it on still leaves each device off until
    /// its own policy is enabled.
    #[serde(default)]
    pub remote_exec_enabled: bool,
    /// FR-94 — refuse a Windows command rather than run it as the signed-in
    /// user. With it on, a Windows device must offer `exec-system`: an
    /// administrator anchored it, so its SYSTEM service runs the command.
    /// Otherwise the request is refused as `SystemRequired`. `false` by
    /// default and for every pre-FR-94 row: an unanchored device keeps
    /// working as the worker, and reports so in the audit (`ran_as: worker`).
    #[serde(default)]
    pub exec_require_system: bool,
    /// Roomler SSH — the org-wide kill-switch (gate 1 of four), the twin of
    /// [`Self::remote_exec_enabled`] and deliberately a SEPARATE switch: an org
    /// that allows bounded diagnostic commands has not thereby allowed
    /// interactive sessions. `false` by default and for every pre-feature row;
    /// flipping it on still leaves each device off until its own `SshPolicy`
    /// is enabled.
    #[serde(default)]
    pub remote_ssh_enabled: bool,

    /// FR-52 — cross-org remote access: the org-wide kill-switch (gate 1 of
    /// five). `false` by default and for every pre-feature row, and while it
    /// is false a connect code does not resolve at all — no device in this org
    /// can be reached by anyone outside it, whatever its own
    /// `ExternalAccessPolicy` says and whatever its owner enabled locally.
    ///
    /// A THIRD switch beside [`Self::remote_exec_enabled`] and
    /// [`Self::remote_ssh_enabled`], and separate from both for the reason
    /// those two are separate from each other — more so, in fact: those govern
    /// what a MEMBER of this org may do, and this one governs whether a
    /// stranger may do anything at all. Nothing about allowing employees to
    /// run commands implies allowing outsiders onto a screen.
    ///
    /// ⚠️ Flipping it on opens nothing on its own: each device still needs an
    /// admin's approval (gate 2), its owner's local opt-in (gate 3), the
    /// device-held password (gate 4) and consent (gate 5).
    #[serde(default)]
    pub external_rc_enabled: bool,

    /// FR-51 — org-wide switch for EPHEMERAL ENROLLMENT KEYS (gate 1 of the
    /// key path). `false` (the default, and what every pre-feature row
    /// deserialises to) means the mint route refuses and — deliberately —
    /// every already-minted key stops working too: the gate is checked on
    /// each USE, ahead of the key's own use-claim, so flipping this off is
    /// an org-wide revocation that burns nothing.
    ///
    /// A separate switch from the exec/SSH pair for the same reason they are
    /// separate from each other: a standing credential that mints device
    /// identities is its own grant, not an implication of any other.
    #[serde(default)]
    pub ephemeral_keys_enabled: bool,

    /// FR-92 — the org-wide DENY for keep busy (pointer patterns a
    /// controller can leave running on a device to keep it active). Unlike the
    /// switches above this one is a deny, and `false` — the default, and what
    /// every pre-feature row deserialises to — means ALLOWED: the operator's
    /// decision is "on by default, with an org deny". Some orgs ban mouse
    /// jigglers because they defeat a screen-lock policy; this is theirs.
    ///
    /// Delivered as a standing `rc:agent.keep_busy_policy` on every connect
    /// and on change, and enforced BY THE DEVICE (the strictest of every org it
    /// is enrolled in): a deny also stops a keep busy already running.
    #[serde(default)]
    pub keep_busy_denied: bool,

    /// FR-92 P8 — the org's DEFAULT keep-busy pattern: what a viewer's menu
    /// pre-selects for a device the person has no remembered choice on.
    /// `None` (the default, and every pre-feature row) = the product default,
    /// `circle`. Validated at the route against the agent's exact wire names
    /// (`meshharbor_remote_control::models::KEEP_BUSY_PATTERNS`), so a stored
    /// value is always one the agent can draw.
    ///
    /// A preference, not a policy: it never reaches the agent (no wire
    /// change), and a person's own remembered choice for a device wins over
    /// it. Readable by any member of the org, settable with MANAGE_TENANT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_busy_default_pattern: Option<String>,

    /// FR-32 — how far plan-limit checks may go for this tenant. Defaults to
    /// `Warn`, so a pre-FR-32 tenant document deserialises into observe mode:
    /// every newly wired gate is measured and logged, and none of them refuse.
    ///
    /// ⚠ This does NOT apply to the limits that were already enforced before
    /// FR-32 (`max_devices`, `max_tunnel_clients`) — see
    /// `meshharbor_services::quota::Limit::is_established`. An established
    /// limit always enforces, so setting `Off` can never silently un-enforce
    /// the device cap.
    #[serde(default)]
    pub plan_enforcement: PlanEnforcement,

    /// FR-101 P2 — which sensitive features a remote-desktop session in this
    /// org may carry (clipboard, files, audio: `on | ask | off`). All `on` by
    /// default and for every pre-feature row. Readable by any member (every
    /// session in the org is told its effect), settable with MANAGE_TENANT.
    #[serde(default)]
    pub rc_session: RcSessionPolicy,

    /// FR-101 P4b — how long a remote-desktop session in this org may last.
    /// No limit by default and for every pre-feature row (operator decision
    /// 2, 2026-10-14: off for existing tenants). Readable by any member,
    /// settable with MANAGE_TENANT.
    #[serde(default)]
    pub rc_limits: RcSessionLimits,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            default_locale: default_locale(),
            default_message_notifications: NotificationLevel::default(),
            mfa_required: false,
            allow_guest_access: false,
            magic_dns_domain: None,
            magic_dns_nameservers: Vec::new(),
            remote_exec_enabled: false,
            exec_require_system: false,
            remote_ssh_enabled: false,
            external_rc_enabled: false,
            ephemeral_keys_enabled: false,
            keep_busy_denied: false,
            keep_busy_default_pattern: None,
            plan_enforcement: PlanEnforcement::default(),
            rc_session: RcSessionPolicy::default(),
            rc_limits: RcSessionLimits::default(),
        }
    }
}

fn default_locale() -> String {
    "en-US".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationLevel {
    #[default]
    All,
    Mentions,
    Nothing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingInfo {
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    pub current_period_end: Option<DateTime>,
    #[serde(default)]
    pub status: SubscriptionStatus,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    /// FR-115 — the subscription's quantity: the seats the org is billed
    /// for, as Stripe last reported them. `None` on every row from before
    /// per-seat billing and until the first subscription event lands; the
    /// limits then count one seat ([`Tenant::billed_seats`]), so a missing
    /// number can only under-grant.
    #[serde(default)]
    pub seats: Option<u32>,
    /// FR-115 — `month` or `year`, as the subscription's price says. Stored
    /// as the wire string and read through [`BillingInterval::parse`], so a
    /// value this build does not know can never fail the tenant document.
    #[serde(default)]
    pub interval: Option<String>,
    /// FR-115 — `usd` or `eur`, the subscription's currency. Same storage
    /// rule as `interval` ([`BillingCurrency::parse`]).
    #[serde(default)]
    pub currency: Option<String>,
}

impl BillingInfo {
    /// The interval, when it is one this build knows.
    pub fn interval(&self) -> Option<BillingInterval> {
        self.interval.as_deref().and_then(BillingInterval::parse)
    }

    /// The currency, when it is one this build knows.
    pub fn currency(&self) -> Option<BillingCurrency> {
        self.currency.as_deref().and_then(BillingCurrency::parse)
    }
}

/// FR-115 — how often a paid plan is billed. Annual is two months free:
/// the price of ten months ([`Plan::price_cents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingInterval {
    Month,
    Year,
}

impl BillingInterval {
    pub const ALL: [BillingInterval; 2] = [BillingInterval::Month, BillingInterval::Year];

    /// The wire spelling — Stripe's `recurring.interval`, and ours.
    pub fn as_str(self) -> &'static str {
        match self {
            BillingInterval::Month => "month",
            BillingInterval::Year => "year",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "month" => Some(BillingInterval::Month),
            "year" => Some(BillingInterval::Year),
            _ => None,
        }
    }
}

/// FR-115 — the currencies a paid plan is sold in. The amounts are the same
/// number in both ([`Plan::price_cents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingCurrency {
    Usd,
    Eur,
}

impl BillingCurrency {
    pub const ALL: [BillingCurrency; 2] = [BillingCurrency::Usd, BillingCurrency::Eur];

    /// The wire spelling — Stripe's lower-case ISO 4217 code, and ours.
    pub fn as_str(self) -> &'static str {
        match self {
            BillingCurrency::Usd => "usd",
            BillingCurrency::Eur => "eur",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "usd" => Some(BillingCurrency::Usd),
            "eur" => Some(BillingCurrency::Eur),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    #[default]
    Active,
    PastDue,
    Canceled,
    Trialing,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSettings {
    pub google_drive: Option<OAuthCredential>,
    pub onedrive: Option<OAuthCredential>,
    pub dropbox: Option<OAuthCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredential {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime>,
}

impl Tenant {
    pub const COLLECTION: &'static str = "tenants";

    /// FR-115 — the seats this org's limits are computed for: the
    /// subscription's quantity on a paid plan, at least one; one on Free,
    /// which has no seats. A paid org whose first subscription event has not
    /// landed counts one seat — a missing number may only under-grant.
    pub fn billed_seats(&self) -> u32 {
        match self.plan {
            Plan::Free => 1,
            _ => self
                .billing
                .as_ref()
                .and_then(|b| b.seats)
                .unwrap_or(1)
                .max(1),
        }
    }

    /// FR-115 — this org's limits: its plan's, scaled to its billed seats.
    pub fn limits(&self) -> PlanLimits {
        self.plan.limits_for(self.billed_seats())
    }
}

/// One gigabyte of relayed traffic. Decimal, as network volumes are counted;
/// storage stays binary (`GIB`), as it always was.
pub const GB: u64 = 1_000_000_000;
/// One gibibyte of storage.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// FR-115 — the plan matrix: priced PER SEAT, with the network given away
/// (Tailscale-style device counts, every mesh feature on Free) and the
/// limits on what costs money or grows with the customer — concurrent
/// remote sessions, relayed bytes, meeting time, seats. Serialized into
/// `/api/stripe/plans`, snapshot-locked by `crates/tests/src/billing_tests.rs`
/// + `ui/e2e/billing.spec.ts` (update them in tandem with any change here).
///
/// ⚠️ "Unlimited" is `u32::MAX` for a count (and `-1` for history), never an
/// `Option` — `services::quota::count_cap` is what reads it as uncapped.
#[derive(Debug, Serialize)]
pub struct PlanLimits {
    // ── Fleet (primary) ─────────────────────────────────────────────
    /// Enrolled remote-control devices (`agents` rows, tombstones
    /// excluded). Enforced at agent enrollment.
    pub max_devices: u32,
    /// Enrolled tunnel clients. Enforced at tunnel enrollment.
    pub max_tunnel_clients: u32,
    /// Overlay mesh membership (private network between the tenant's
    /// nodes). On for every plan — it's the product's spine.
    pub overlay_mesh: bool,
    /// Exit nodes (route a node's whole egress through a mesh peer). Free
    /// gets them once the relay throttle exists (FR-115 P4d): an exit node
    /// whose path falls to DERP is the one way Free could cost real money.
    pub exit_nodes: bool,
    /// MagicDNS (tenant overlay DNS domain).
    pub magic_dns: bool,
    /// Concurrent remote-control sessions per tenant (FR-115 P3 enforces
    /// it). Per seat on a `per_seat` plan.
    pub max_concurrent_sessions: u32,
    /// FR-115 — relayed bytes (DERP + TURN) a month at full speed; past it
    /// the org is throttled, never refused (decision D4). Direct traffic and
    /// the org's own relays are never counted. Per seat on a `per_seat`
    /// plan. Enforced from FR-115 P4.
    pub relay_bytes_per_month: u64,
    // ── Collaboration (bundled) ─────────────────────────────────────
    pub max_members: u32,
    pub max_channels: u32,
    pub max_message_history: i64,
    /// Per seat on a `per_seat` plan.
    pub storage_bytes: u64,
    pub video_max_participants: u32,
    /// FR-115 — the longest meeting, in minutes; `u32::MAX` = no cap.
    /// Enforced from FR-115 P5.
    pub meeting_max_minutes: u32,
    pub cloud_integrations: bool,
    pub recordings: bool,
    /// FR-115 — `storage_bytes`, `max_concurrent_sessions` and
    /// `relay_bytes_per_month` are per seat on this plan: the values above
    /// are ONE seat's, and [`Plan::limits_for`] scales them. Free has no
    /// seats, so its values are the org's.
    pub per_seat: bool,
}

impl Plan {
    /// One seat's limits — what `/api/stripe/plans` publishes, the number a
    /// person reads as "per user". An org's own limits are
    /// [`Tenant::limits`].
    pub fn limits(&self) -> PlanLimits {
        self.limits_for(1)
    }

    /// The limits for an org billed for `seats` seats (at least one). The
    /// per-seat numbers multiply, saturating; an unlimited one stays
    /// unlimited.
    pub fn limits_for(&self, seats: u32) -> PlanLimits {
        let mut limits = match self {
            Plan::Free => PlanLimits {
                // FR-115 — devices cost nothing on a direct path, so Free
                // matches what the mesh vendors give away (it was 3).
                max_devices: 100,
                max_tunnel_clients: 100,
                overlay_mesh: true,
                exit_nodes: false,
                magic_dns: true,
                max_concurrent_sessions: 1,
                relay_bytes_per_month: 10 * GB,
                // FR-115 D2 — ten users, and ESTABLISHED: enforced whatever
                // `plan_enforcement` says (`services::quota::Limit`).
                max_members: 10,
                max_channels: u32::MAX,
                max_message_history: -1,
                storage_bytes: GIB,
                // FR-32 moved Free from 0 to 4 participants because 0 was
                // never enforced and people held calls; FR-115 moves it to 10
                // with a 60-minute meeting, the free-tier norm.
                video_max_participants: 10,
                meeting_max_minutes: 60,
                cloud_integrations: false,
                recordings: false,
                per_seat: false,
            },
            Plan::Pro => PlanLimits {
                max_devices: 1_000,
                max_tunnel_clients: 1_000,
                overlay_mesh: true,
                exit_nodes: true,
                magic_dns: true,
                max_concurrent_sessions: 1,
                relay_bytes_per_month: 25 * GB,
                max_members: u32::MAX,
                max_channels: u32::MAX,
                max_message_history: -1,
                storage_bytes: 10 * GIB,
                video_max_participants: 50,
                meeting_max_minutes: u32::MAX,
                cloud_integrations: true,
                recordings: false,
                per_seat: true,
            },
            Plan::Business | Plan::Enterprise => PlanLimits {
                max_devices: 5_000,
                max_tunnel_clients: 5_000,
                overlay_mesh: true,
                exit_nodes: true,
                magic_dns: true,
                max_concurrent_sessions: u32::MAX,
                relay_bytes_per_month: 100 * GB,
                max_members: u32::MAX,
                max_channels: u32::MAX,
                max_message_history: -1,
                storage_bytes: 50 * GIB,
                video_max_participants: 100,
                meeting_max_minutes: u32::MAX,
                cloud_integrations: true,
                recordings: true,
                per_seat: true,
            },
        };
        if limits.per_seat {
            let seats = seats.max(1);
            if limits.max_concurrent_sessions != u32::MAX {
                limits.max_concurrent_sessions =
                    limits.max_concurrent_sessions.saturating_mul(seats);
            }
            limits.storage_bytes = limits.storage_bytes.saturating_mul(u64::from(seats));
            limits.relay_bytes_per_month = limits
                .relay_bytes_per_month
                .saturating_mul(u64::from(seats));
        }
        limits
    }

    /// The list price of one seat for a month, in US cents — what the MRR
    /// estimate multiplies (`routes::cost::mrr_estimate_cents`).
    pub fn price_monthly_cents(&self) -> u32 {
        self.price_cents(BillingInterval::Month, BillingCurrency::Usd)
    }

    /// FR-115 — the list price of one seat for one `interval`, in the
    /// minor unit of `currency`. The same number in USD and EUR; annual is
    /// two months free (ten months' price). Stripe's Prices are created to
    /// match these, and `billing_tests.rs` locks them.
    pub fn price_cents(&self, interval: BillingInterval, _currency: BillingCurrency) -> u32 {
        let month = match self {
            Plan::Free => 0,
            Plan::Pro => 800,
            Plan::Business | Plan::Enterprise => 1600,
        };
        match interval {
            BillingInterval::Month => month,
            BillingInterval::Year => month * 10,
        }
    }

    /// The wire id stored in tenant documents and matched in the webhook.
    pub fn id(&self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Pro => "pro",
            Plan::Business => "business",
            Plan::Enterprise => "enterprise",
        }
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    fn tenant(plan: Plan, seats: Option<u32>) -> Tenant {
        Tenant {
            id: None,
            name: "t".into(),
            slug: "t".into(),
            description: None,
            icon: None,
            owner_id: bson::oid::ObjectId::new(),
            plan,
            features: vec![],
            settings: TenantSettings::default(),
            billing: seats.map(|s| BillingInfo {
                customer_id: None,
                subscription_id: None,
                current_period_end: None,
                status: SubscriptionStatus::Active,
                cancel_at_period_end: false,
                seats: Some(s),
                interval: None,
                currency: None,
            }),
            integrations: None,
            is_archived: false,
            created_at: DateTime::now(),
            updated_at: DateTime::now(),
            deleted_at: None,
        }
    }

    /// FR-115 — the Free plan gives the network away and fences what costs.
    #[test]
    fn free_gives_devices_and_mesh_and_fences_concurrency() {
        let free = Plan::Free.limits();
        assert_eq!(free.max_devices, 100);
        assert_eq!(free.max_tunnel_clients, 100);
        assert!(free.magic_dns);
        assert!(
            !free.exit_nodes,
            "exit nodes wait for the relay throttle (P4d)"
        );
        assert_eq!(free.max_concurrent_sessions, 1);
        assert_eq!(free.max_members, 10);
        assert_eq!(free.relay_bytes_per_month, 10 * GB);
        assert_eq!(free.meeting_max_minutes, 60);
        assert!(!free.per_seat);
    }

    /// Per-seat numbers multiply with the seats; unlimited stays unlimited;
    /// the counts that are not per seat do not move.
    #[test]
    fn per_seat_limits_scale_with_seats() {
        let one = Plan::Pro.limits_for(1);
        let five = Plan::Pro.limits_for(5);
        assert_eq!(
            five.max_concurrent_sessions,
            5 * one.max_concurrent_sessions
        );
        assert_eq!(five.storage_bytes, 5 * one.storage_bytes);
        assert_eq!(five.relay_bytes_per_month, 5 * one.relay_bytes_per_month);
        assert_eq!(five.max_devices, one.max_devices, "devices are per org");

        let biz = Plan::Business.limits_for(40);
        assert_eq!(
            biz.max_concurrent_sessions,
            u32::MAX,
            "unlimited stays unlimited"
        );

        // Free has no seats: a seat count changes nothing.
        assert_eq!(Plan::Free.limits_for(7).max_concurrent_sessions, 1);
        assert_eq!(Plan::Free.limits_for(7).storage_bytes, GIB);
    }

    /// Zero and absurd seat counts are clamped and saturate — never a wrap.
    #[test]
    fn seat_scaling_never_wraps() {
        assert_eq!(
            Plan::Pro.limits_for(0).max_concurrent_sessions,
            1,
            "zero seats counts as one"
        );
        let huge = Plan::Business.limits_for(u32::MAX);
        assert_eq!(huge.storage_bytes, u64::MAX, "50 GiB x u32::MAX saturates");
        assert_eq!(huge.relay_bytes_per_month, u64::MAX);
        assert_eq!(
            Plan::Pro.limits_for(u32::MAX).max_concurrent_sessions,
            u32::MAX
        );
    }

    /// A tenant's limits read its billed seats; a paid org with no seat
    /// count yet counts one, and Free always one.
    #[test]
    fn a_tenant_is_limited_by_its_billed_seats() {
        assert_eq!(
            tenant(Plan::Pro, Some(3)).limits().max_concurrent_sessions,
            3
        );
        assert_eq!(tenant(Plan::Pro, None).billed_seats(), 1);
        assert_eq!(tenant(Plan::Pro, Some(0)).billed_seats(), 1);
        assert_eq!(tenant(Plan::Free, Some(9)).billed_seats(), 1);
    }

    /// Annual is two months free, and the same number in both currencies.
    #[test]
    fn annual_is_ten_months_and_eur_matches_usd() {
        for plan in [Plan::Pro, Plan::Business] {
            let m = plan.price_cents(BillingInterval::Month, BillingCurrency::Usd);
            assert_eq!(
                plan.price_cents(BillingInterval::Year, BillingCurrency::Usd),
                10 * m
            );
            for i in BillingInterval::ALL {
                assert_eq!(
                    plan.price_cents(i, BillingCurrency::Eur),
                    plan.price_cents(i, BillingCurrency::Usd)
                );
            }
        }
        assert_eq!(Plan::Pro.price_monthly_cents(), 800);
        assert_eq!(Plan::Business.price_monthly_cents(), 1600);
    }

    /// An interval or currency a newer server wrote reads as unknown, and
    /// the tenant document still loads.
    #[test]
    fn unknown_interval_and_currency_never_fail_the_document() {
        let b: BillingInfo = serde_json::from_value(serde_json::json!({
            "customer_id": null, "subscription_id": null, "current_period_end": null,
            "interval": "fortnight", "currency": "jpy"
        }))
        .unwrap();
        assert_eq!(b.interval(), None);
        assert_eq!(b.currency(), None);
        assert_eq!(b.seats, None);
        let b: BillingInfo = serde_json::from_value(serde_json::json!({
            "customer_id": null, "subscription_id": null, "current_period_end": null,
            "seats": 4, "interval": "year", "currency": "eur"
        }))
        .unwrap();
        assert_eq!(b.interval(), Some(BillingInterval::Year));
        assert_eq!(b.currency(), Some(BillingCurrency::Eur));
    }
}

#[cfg(test)]
mod rc_session_tests {
    use super::*;

    /// FR-101 P2 — a tenant document from before the feature has no
    /// `rc_session`: everything stays `on`, exactly today's behaviour.
    #[test]
    fn a_pre_feature_tenant_allows_every_session_feature() {
        let s: TenantSettings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(s.rc_session, RcSessionPolicy::default());
        assert_eq!(s.rc_session.clipboard, RcFeaturePolicy::On);
        assert_eq!(s.rc_session.files, RcFeaturePolicy::On);
        assert_eq!(s.rc_session.audio, RcFeaturePolicy::On);
    }

    #[test]
    fn the_three_values_round_trip_lowercase() {
        let p = RcSessionPolicy {
            clipboard: RcFeaturePolicy::Ask,
            files: RcFeaturePolicy::Off,
            audio: RcFeaturePolicy::On,
        };
        let v = serde_json::to_value(p).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"clipboard":"ask","files":"off","audio":"on"})
        );
        let back: RcSessionPolicy = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }

    /// A value a newer server wrote reads as `off`: the whole tenant document
    /// must still load after a rollback, and the strict direction is the only
    /// one a security policy may fail in.
    #[test]
    fn an_unknown_value_reads_as_off_and_never_fails_the_document() {
        let s: TenantSettings = serde_json::from_value(serde_json::json!({
            "rc_session": {"clipboard": "on_with_banner", "files": "ask"}
        }))
        .unwrap();
        assert_eq!(s.rc_session.clipboard, RcFeaturePolicy::Off);
        assert_eq!(s.rc_session.files, RcFeaturePolicy::Ask);
        assert_eq!(s.rc_session.audio, RcFeaturePolicy::On);
    }

    /// Not even a string: a number, a null, an object. Each reads as `off`,
    /// and the document still loads.
    #[test]
    fn a_value_of_the_wrong_type_reads_as_off_too() {
        let s: TenantSettings = serde_json::from_value(serde_json::json!({
            "rc_session": {"clipboard": 3, "files": null, "audio": {"x": 1}}
        }))
        .unwrap();
        assert_eq!(s.rc_session.clipboard, RcFeaturePolicy::Off);
        assert_eq!(s.rc_session.files, RcFeaturePolicy::Off);
        assert_eq!(s.rc_session.audio, RcFeaturePolicy::Off);
    }

    /// The driver's own path, BSON both ways: what `$set` writes is what the
    /// typed cursor reads, and a hand-edited Int32 still loads.
    #[test]
    fn the_policy_round_trips_through_bson() {
        let p = RcSessionPolicy {
            clipboard: RcFeaturePolicy::Off,
            files: RcFeaturePolicy::Ask,
            audio: RcFeaturePolicy::On,
        };
        let raw = bson::to_raw_document_buf(&p).unwrap();
        let back: RcSessionPolicy = bson::from_slice(raw.as_bytes()).unwrap();
        assert_eq!(back, p);
        let edited = bson::doc! { "clipboard": 1_i32, "files": "ask" };
        let raw = bson::to_raw_document_buf(&edited).unwrap();
        let back: RcSessionPolicy = bson::from_slice(raw.as_bytes()).unwrap();
        assert_eq!(back.clipboard, RcFeaturePolicy::Off);
        assert_eq!(back.files, RcFeaturePolicy::Ask);
        assert_eq!(back.audio, RcFeaturePolicy::On);
    }

    /// FR-101 P4b — a tenant document from before the limits has none: no
    /// maximum, exactly today's behaviour. A set limit round-trips, and an
    /// unset one is left off the document rather than stored as `null`.
    #[test]
    fn a_pre_feature_tenant_has_no_session_limit() {
        let s: TenantSettings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(s.rc_limits, RcSessionLimits::default());
        assert_eq!(s.rc_limits.max_secs, None);
        assert_eq!(s.rc_limits.idle_secs, None);
        let set = RcSessionLimits {
            max_secs: Some(7200),
            idle_secs: None,
        };
        let v = serde_json::to_value(set).unwrap();
        assert_eq!(v, serde_json::json!({"max_secs": 7200}));
        assert_eq!(serde_json::from_value::<RcSessionLimits>(v).unwrap(), set);
        assert_eq!(
            serde_json::to_value(RcSessionLimits::default()).unwrap(),
            serde_json::json!({})
        );
    }

    /// P4b-2 — a row written before the idle limit existed (one carrying only
    /// `max_secs`) has no idle limit, and the two limits stay independent.
    #[test]
    fn the_idle_limit_is_its_own_field() {
        let old: RcSessionLimits =
            serde_json::from_value(serde_json::json!({"max_secs": 3600})).unwrap();
        assert_eq!(old.max_secs, Some(3600));
        assert_eq!(old.idle_secs, None);
        let idle_only = RcSessionLimits {
            max_secs: None,
            idle_secs: Some(900),
        };
        let v = serde_json::to_value(idle_only).unwrap();
        assert_eq!(v, serde_json::json!({"idle_secs": 900}));
        assert_eq!(
            serde_json::from_value::<RcSessionLimits>(v).unwrap(),
            idle_only
        );
    }
}
