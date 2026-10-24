// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

/// The development default for `app.frontend_url`.
///
/// A constant rather than a literal because two places need to agree on it: the
/// default below, and the production startup check that warns when a deployment
/// is still running on it (FR-50 P3, `crates/api/src/main.rs`). Written twice,
/// they drift, and the drift is silent in the direction that matters — the
/// check simply stops firing and nobody learns their links are broken.
pub const DEFAULT_FRONTEND_URL: &str = "http://localhost:5000";

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub app: AppSettings,
    pub database: DatabaseSettings,
    pub jwt: JwtSettings,
    pub redis: RedisSettings,
    pub s3: S3Settings,
    pub mediasoup: MediasoupSettings,
    pub turn: TurnSettings,
    pub oauth: OAuthSettings,
    pub stripe: StripeSettings,
    pub giphy: GiphySettings,
    pub email: EmailSettings,
    /// FR-58 — the newsletter From identity. `#[serde(default)]` so existing
    /// config files and env sets stay valid; unset falls back to `email.from_*`.
    #[serde(default)]
    pub newsletter: NewsletterSettings,
    pub push: PushSettings,
    pub auth: AuthSettings,
    pub rc: RcSettings,
    pub relay: RelaySettings,
    pub releases: ReleasesSettings,
    pub overlay: OverlaySettings,
    pub stats: StatsSettings,
    /// FR-102 — growth observability: the exclusion list and the taxonomy's
    /// routes (P1), the daily digest (P1d). Absent ⇒ the routes serve and the
    /// digest is OFF.
    #[serde(default)]
    pub growth: GrowthSettings,
    /// FR-20 P5 — unit costs for the metered resources. Deliberately
    /// **not** `Default`: absent means *not priced*, never zero.
    #[serde(default)]
    pub relay_costs: RelayCosts,
    /// FR-69 — per-module runtime switches. Absent ⇒ everything on, which is
    /// exactly today's server.
    #[serde(default)]
    pub modules: ModulesSettings,
    /// FR-90 P1g — which organizations agent sessions serve once
    /// `[modules] hive` is on. Absent ⇒ every one.
    #[serde(default)]
    pub hive: HiveSettings,
    /// FR-90 P3-1 — the vault: which organizations it serves once
    /// `[modules] vault` is on, and its key-encryption key. Absent ⇒ every
    /// organization, and no KEK.
    #[serde(default)]
    pub vault: VaultSettings,
    /// #1731 — the stall watchdog. Absent ⇒ on, with its defaults.
    #[serde(default)]
    pub diag: DiagSettings,
    /// FR-115 P5 — the plan's meeting-length cap. Absent ⇒ on.
    #[serde(default)]
    pub meetings: MeetingsSettings,
    /// FR-115 P4a — the relay allowance on DERP. Absent ⇒ off.
    #[serde(default)]
    pub relay_allowance: RelayAllowanceSettings,
}

/// FR-90 P3-1 — `[vault]`, env `ROOMLER__VAULT__*`.
///
/// ⚠️ `kek` is the vault's root secret: whoever holds it and a copy of the
/// database reads every secret. `Debug` is written by hand so it never
/// prints, and nothing that reports settings may serialise this struct.
#[derive(Deserialize, Clone, Default)]
pub struct VaultSettings {
    /// The organizations the vault serves, as comma-separated ids
    /// (`ROOMLER__VAULT__TENANTS=<id>,<id>`), with `hive.tenants`'s rules:
    /// empty or `*` is every organization, a list is only those, and an
    /// entry that is no id matches nothing.
    ///
    /// ⚠️ A list switches the module ON by itself ([`Settings::vault_on`]):
    /// the form a hosted server uses, because it fails safe — no older image
    /// reads it. Clearing the list is the kill switch.
    #[serde(default)]
    pub tenants: String,
    /// The key-encryption key (`ROOMLER__VAULT__KEK`): an `age` X25519
    /// identity, `AGE-SECRET-KEY-1…` as `age-keygen` writes it — or the
    /// whole text of such a file. A hosted server mounts it from a sealed
    /// secret.
    #[serde(default)]
    pub kek: String,
    /// Or the path of an `age-keygen` identity file
    /// (`ROOMLER__VAULT__KEK_FILE`). Both set is refused: the two may
    /// disagree, and the vault does not guess.
    #[serde(default)]
    pub kek_file: String,
    /// P3-3c — how often each pod checks the leases its connected devices
    /// hold, in seconds (`ROOMLER__VAULT__REVOKE_SWEEP_SECS`): the longest a
    /// session's end or move, or a change made on another pod, waits to be
    /// pushed to the device. 0 or absent: 10.
    #[serde(default)]
    pub revoke_sweep_secs: u64,
    /// P3-6b — the providers a dynamic secret is leased for, as
    /// comma-separated names (`ROOMLER__VAULT__PROVIDERS=postgres`). Empty —
    /// the default — or `*` is every provider this build knows; a list is
    /// only those. A provider left out is refused `not_served`, and a word
    /// that names no provider serves nothing: `none` turns them all off.
    #[serde(default)]
    pub providers: String,
    /// P3-9-1 — the organizations whose PEOPLE the vault lends to through
    /// `roomler connect` (`ROOMLER__VAULT__PEOPLE=<id>,<id>`): a person's
    /// endpoint, decided by Cedar's `secret:connect` for the device's owner.
    /// ⚠️ Opt-in, the opposite sense to `tenants`: empty — the default — is
    /// NO organization, `*` every one the vault serves, a list only those.
    /// An organization the vault serves for its sessions lends nothing to
    /// its people until it is listed here too. Clearing it is the kill
    /// switch: every person's live lease is taken back at its device's next
    /// sweep.
    #[serde(default)]
    pub people: String,
}

impl std::fmt::Debug for VaultSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSettings")
            .field("tenants", &self.tenants)
            .field(
                "kek",
                &if self.kek.trim().is_empty() {
                    "<unset>"
                } else {
                    "<redacted>"
                },
            )
            .field("kek_file", &self.kek_file)
            .field("revoke_sweep_secs", &self.revoke_sweep_secs)
            .field("providers", &self.providers)
            .field("people", &self.people)
            .finish()
    }
}

/// FR-90 P1g — `[hive]`, env `ROOMLER__HIVE__*`.
#[derive(Debug, Deserialize, Clone)]
pub struct HiveSettings {
    /// The organizations agent sessions serve, as comma-separated ids
    /// (`ROOMLER__HIVE__TENANTS=<id>,<id>`). Empty — the default — or `*` is
    /// every organization; a list is only those, and every other one is
    /// answered as if the module were not there for it. A hosted server opens
    /// the pillar to a test organization this way before anyone else.
    ///
    /// ⚠️ A list switches the module ON by itself ([`Settings::hive_on`]),
    /// with no `ROOMLER__MODULES__HIVE`. That is the form a hosted server
    /// uses, because it fails safe: no older image reads a list as the
    /// switch, so promoting one leaves the pillar off — where
    /// `modules.hive = true` on an image from before P1g, which never reads
    /// the list, would open it to every organization. Clearing the list is
    /// the kill switch.
    ///
    /// ⚠️ `String`, not `Vec<String>`, for the reason on
    /// [`JwtSettings::previous_secrets`]: an env var cannot become a sequence.
    #[serde(default)]
    pub tenants: String,
    /// FR-90 P2c — the replicaset (`ROOMLER__HIVE__REPLICASET`): an
    /// organization's replica policy, placement, and the frames that make a
    /// device a member. Default OFF, P2's server kill switch: off, the policy
    /// routes answer as if they were not there and no session gets a
    /// replicaset, so a roll that ships it exposes nothing.
    #[serde(default)]
    pub replicaset: bool,
    /// FR-90 P2e-3 — how long a promotion waits for the member it moves to
    /// to answer its prepare (`ROOMLER__HIVE__PROMOTE_PREPARE_SECS`).
    #[serde(default = "hive_default_promote_prepare_secs")]
    pub promote_prepare_secs: u64,
    /// FR-90 P2e-3 — how long it waits for the primary's `rc:hive.drained`.
    /// ⚠️ Longer than the device's turn cut
    /// (`hive::promote_limits::DRAIN_TURN_CUT_SECS`, 60 s), and a margin for
    /// the last checkpoint: a shorter one fails every drain of a long turn.
    #[serde(default = "hive_default_promote_drain_secs")]
    pub promote_drain_secs: u64,
    /// FR-90 P2e-3 — how long it waits for the member's copy to reach the
    /// drained tip. A slow carrier (the DERP floor, a laptop on a corporate
    /// network) is where an operator lengthens it.
    #[serde(default = "hive_default_promote_sync_secs")]
    pub promote_sync_secs: u64,
    /// FR-90 P2f-1 — how long a teleport waits for its target's copy to
    /// catch up with the primary's before it drains the session
    /// (`ROOMLER__HIVE__PROMOTE_JOIN_SECS`): the whole copy moves in this
    /// time, while the session still runs. ⚠️ Under the device's own
    /// admission of the target's join (`hive::promote_limits::
    /// TELEPORT_ADMISSION_SECS`, 30 min): a join re-sent after that is
    /// refused `not_prepared`.
    #[serde(default = "hive_default_promote_join_secs")]
    pub promote_join_secs: u64,
    /// FR-90 P2f-2b — a teleport's target may take the workspace's first
    /// pack as one thin against what its folder's repository holds already
    /// (`ROOMLER__HIVE__TELEPORT_HAVE_WANT`; git's have and want). Default
    /// OFF until the operator confirms FR-90's decision 16: such a target
    /// holds the checkpoint without its whole pack's blobs.
    #[serde(default)]
    pub teleport_have_want: bool,
    /// FR-90 P2f-3 — how long a fork waits for its device's copy to reach
    /// the session's last checkpoint, as its primary last reported it
    /// (`ROOMLER__HIVE__FORK_COPY_SECS`), before it is refused
    /// `copy_behind`: a fork is made at the last checkpoint the device's
    /// copy holds. ⚠️ A member that follows the session reports where its
    /// copy ends at once, then at most every
    /// `replica_limits::TIP_INTERVAL_SECS` (5 s): a bound below that can
    /// refuse a copy that holds the checkpoint but has not said so yet
    /// (measured: 5.2 s, two checkpoints 13 ms apart).
    #[serde(default = "hive_default_fork_copy_secs")]
    pub fork_copy_secs: u64,
    /// FR-90 P2g-3 — how often the server purges the sessions an
    /// organization's `retention_days` no longer keeps
    /// (`ROOMLER__HIVE__RETENTION_SWEEP_SECS`): one pod a cycle, by a claim
    /// in the database. `0` is no sweep; with `replicaset` off there is none
    /// either. An organization's `retention_days = 0` keeps its sessions for
    /// ever whatever this says.
    #[serde(default = "hive_default_retention_sweep_secs")]
    pub retention_sweep_secs: u64,
}

fn hive_default_promote_prepare_secs() -> u64 {
    30
}

fn hive_default_promote_join_secs() -> u64 {
    600
}

fn hive_default_promote_drain_secs() -> u64 {
    75
}

fn hive_default_promote_sync_secs() -> u64 {
    120
}

fn hive_default_fork_copy_secs() -> u64 {
    30
}

impl Default for HiveSettings {
    fn default() -> Self {
        Self {
            tenants: String::new(),
            replicaset: false,
            promote_prepare_secs: hive_default_promote_prepare_secs(),
            promote_drain_secs: hive_default_promote_drain_secs(),
            promote_sync_secs: hive_default_promote_sync_secs(),
            promote_join_secs: hive_default_promote_join_secs(),
            teleport_have_want: false,
            fork_copy_secs: hive_default_fork_copy_secs(),
            retention_sweep_secs: hive_default_retention_sweep_secs(),
        }
    }
}

fn hive_default_retention_sweep_secs() -> u64 {
    3600
}

/// #1731 — `[diag]`, env `ROOMLER__DIAG__*`: the stall watchdog.
///
/// A `roomler2` pod went silent twice in 9 h — not one log line, `/health`
/// unanswered — until the liveness probe killed it ~105 s later, taking the
/// only evidence with it. The watchdog notices the runtime has stopped
/// making progress, writes every thread's stack and syscall to a file in
/// `stall_dump_dir`, and the NEXT process logs that file at boot. The
/// directory must outlive a container restart (an `emptyDir` in the
/// deployment) or the dump dies with the container it describes.
#[derive(Debug, Deserialize, Clone)]
pub struct DiagSettings {
    /// On or off. Unset follows `app.environment`: on in `production`, off
    /// elsewhere, because on a developer's box a debugger pause longer than the
    /// threshold would read as a stall and signal every thread.
    #[serde(default)]
    pub stall_watchdog: Option<bool>,
    /// How long the runtime's heartbeat may go unseen before it counts as a
    /// stall. Well inside the liveness budget (5 × 15 s probes + grace).
    #[serde(default = "diag_default_threshold_secs")]
    pub stall_threshold_secs: u64,
    #[serde(default = "diag_default_dump_dir")]
    pub stall_dump_dir: String,
}

fn diag_default_threshold_secs() -> u64 {
    10
}

fn diag_default_dump_dir() -> String {
    "/var/lib/roomler/diag".to_string()
}

impl Default for DiagSettings {
    fn default() -> Self {
        Self {
            stall_watchdog: None,
            stall_threshold_secs: diag_default_threshold_secs(),
            stall_dump_dir: diag_default_dump_dir(),
        }
    }
}

/// FR-115 P5 — `[meetings]`, env `ROOMLER__MEETINGS__*`.
#[derive(Debug, Deserialize, Clone)]
pub struct MeetingsSettings {
    /// A plan's meeting-length cap: a Free meeting is warned five minutes
    /// before its sixty and ended at them. `false` lets every meeting run
    /// as long as it likes — the P5 kill switch. Default **on**.
    /// Env: `ROOMLER__MEETINGS__FREE_CAP`.
    #[serde(default = "meetings_default_on")]
    pub free_cap: bool,
}

fn meetings_default_on() -> bool {
    true
}

impl Default for MeetingsSettings {
    fn default() -> Self {
        Self {
            free_cap: meetings_default_on(),
        }
    }
}

/// FR-115 P4a — `[relay_allowance]`, env `ROOMLER__RELAY_ALLOWANCE__*`: an
/// org past its plan's monthly relay allowance keeps its DERP floor, at a
/// throttled rate for bulk frames only (a WireGuard handshake and disco are
/// never held back). Default **off**: it ships dark, and is switched on
/// after the fleet measurement O3 asks for.
#[derive(Debug, Deserialize, Clone)]
pub struct RelayAllowanceSettings {
    /// The kill switch. `false`: no over-allowance set is published, and
    /// every pod drops the one it holds within a refresh period.
    /// Env: `ROOMLER__RELAY_ALLOWANCE__ENABLED`.
    #[serde(default)]
    pub enabled: bool,
    /// The throttled rate for a Free org over its allowance, in kbit/s, per
    /// network (the org's mesh). Env: `ROOMLER__RELAY_ALLOWANCE__FREE_RATE_KBPS`.
    #[serde(default = "relay_allowance_free_rate_kbps")]
    pub free_rate_kbps: u32,
    /// The same for a paid plan. Env: `ROOMLER__RELAY_ALLOWANCE__PAID_RATE_KBPS`.
    #[serde(default = "relay_allowance_paid_rate_kbps")]
    pub paid_rate_kbps: u32,
    /// FR-115 P4b — read coturn's statistics DB (`--redis-statsdb`) into
    /// `turn_bytes` per org. Off until coturn publishes there; `false` is
    /// the kill switch (no subscription). Env:
    /// `ROOMLER__RELAY_ALLOWANCE__TURN_ATTRIBUTION`.
    #[serde(default)]
    pub turn_attribution: bool,
}

fn relay_allowance_free_rate_kbps() -> u32 {
    1_000
}

fn relay_allowance_paid_rate_kbps() -> u32 {
    4_000
}

impl Default for RelayAllowanceSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            free_rate_kbps: relay_allowance_free_rate_kbps(),
            paid_rate_kbps: relay_allowance_paid_rate_kbps(),
            turn_attribution: false,
        }
    }
}

/// FR-69 — the per-module runtime switches (`[modules]`, env
/// `ROOMLER__MODULES__<ID>=false`).
///
/// `false` unmounts a compiled module on a pod without a rebuild — the
/// per-module kill switch during the roll that introduces it. Each switch
/// takes effect with the PR that extracts its module (P2 onwards); until
/// then it is recorded and logged at boot, and `GET /api/capabilities`
/// reports it under `switched_off`, but the routes still serve.
#[derive(Debug, Deserialize, Clone)]
pub struct ModulesSettings {
    #[serde(default = "modules_default_on")]
    pub chat: bool,
    #[serde(default = "modules_default_on")]
    pub conference: bool,
    #[serde(default = "modules_default_on")]
    pub fleet: bool,
    #[serde(default = "modules_default_on")]
    pub remote: bool,
    #[serde(default = "modules_default_on")]
    pub network: bool,
    #[serde(default = "modules_default_on")]
    pub saas: bool,
    /// FR-90 — agent sessions. **Default OFF**, like `vault`: it is the P0
    /// kill switch while the pillar is built, so a roll that ships the code
    /// exposes nothing until an operator turns it on
    /// (`ROOMLER__MODULES__HIVE=true`, or a `hive.tenants` list — read
    /// [`Settings::hive_on`], never this field alone). Listed in
    /// [`Self::DEFAULT_OFF`].
    #[serde(default)]
    pub hive: bool,
    /// FR-90 P3-1 — the vault. **Default OFF**, for the same reason:
    /// `ROOMLER__MODULES__VAULT=true`, or a `vault.tenants` list — read
    /// [`Settings::vault_on`], never this field alone. Listed in
    /// [`Self::DEFAULT_OFF`].
    #[serde(default)]
    pub vault: bool,
}

fn modules_default_on() -> bool {
    true
}

impl Default for ModulesSettings {
    fn default() -> Self {
        Self {
            chat: true,
            conference: true,
            fleet: true,
            remote: true,
            network: true,
            saas: true,
            hive: false,
            vault: false,
        }
    }
}

impl ModulesSettings {
    /// Modules whose switch is OFF unless an operator turns it on. Their
    /// absence from a build that does not link them is the default, not a
    /// configuration worth a boot warning.
    pub const DEFAULT_OFF: &'static [&'static str] = &["hive", "vault"];

    /// The module ids an operator has switched off, in the composition order
    /// of `roomler_core::graph::MODULES` — including a default-off module
    /// nobody switched on, so `modules = compiled − switched_off` holds.
    ///
    /// ⚠️ It cannot see a `hive.tenants` or `vault.tenants` list, which also
    /// switches its module on; the boot log and `/api/capabilities` read
    /// [`Settings::switched_off`].
    pub fn switched_off(&self) -> Vec<&'static str> {
        let mut off = Vec::new();
        if !self.saas {
            off.push("saas");
        }
        if !self.chat {
            off.push("chat");
        }
        if !self.conference {
            off.push("conference");
        }
        if !self.fleet {
            off.push("fleet");
        }
        if !self.remote {
            off.push("remote");
        }
        if !self.network {
            off.push("network");
        }
        if !self.hive {
            off.push("hive");
        }
        if !self.vault {
            off.push("vault");
        }
        off
    }
}

/// Multi-org P2b — tenant-block addressing for the overlay mesh.
///
/// Every tenant shares `100.64.0.0/10` today, with each network's host cursor
/// seeded at 1 — so tenant A's `100.64.0.7` and tenant B's `100.64.0.7` are
/// the same address on a host enrolled in both. Blocks carve each tenant a
/// disjoint slice so one daemon can carry N orgs on one interface.
///
/// FR-47 — carving is ON by default. It shipped `false` for a staged rollout
/// and then stayed off, which made isolation opt-in: measured on prod
/// 2026-08-31, two of four overlay networks were still on the shared `/10`
/// and **held overlapping addresses**, because nothing carves a network the
/// operator does not explicitly ask for. A default that has to be remembered
/// is not a default.
///
/// Flipping it affects only networks created AFTER the flip — `ensure_block`'s
/// virginity guard refuses to re-base a network that has already leased an
/// address. Migrating an existing tenant stays an explicit admin action
/// (`POST …/overlay-block/renumber`), because it has to cycle every node's WS
/// to re-bind their addresses.
///
/// `blocks_enabled=false` remains the kill switch, and is still exactly the
/// pre-P2b behaviour.
#[derive(Debug, Clone, Deserialize)]
pub struct OverlaySettings {
    /// Carve a fresh block for every NEWLY created tenant overlay network.
    /// Env: `ROOMLER__OVERLAY__BLOCKS_ENABLED`.
    pub blocks_enabled: bool,
    /// Prefix of a carved block, `/16` … `/22`. `/22` = 1022 devices per
    /// tenant and 4 032 tenants inside the `/10`.
    /// Env: `ROOMLER__OVERLAY__BLOCK_PREFIX`.
    pub block_prefix: u8,
    /// Minimum agent/tunnel-client version allowed on a renumbered tenant.
    /// Below this the boot reconciler purges the node's OWN on-link route at
    /// daemon start (it kept only the literal `100.64.0.0/…`), which
    /// blackholes the mesh for that host — so a migration refuses to run over
    /// a fleet that hasn't caught up. `--force` on the endpoint overrides.
    /// Env: `ROOMLER__OVERLAY__BLOCK_VERSION_FLOOR`.
    pub block_version_floor: String,
    /// FR-47 P5c — let a network hold MORE THAN ONE block, so an org that
    /// fills its first one is given another instead of being refused. The
    /// ordinal space is the blocks concatenated in allocation order, so
    /// growth costs no device its address.
    ///
    /// Default OFF, and off is exactly today's behaviour: `allocate_host`
    /// refuses at the single block's ceiling.
    ///
    /// ⚠️ Turning this on is a **one-way door for the schema**. The registry's
    /// partial-unique index on `overlay_blocks.network_id` IS the
    /// one-block-per-network invariant, so it has to be dropped before a
    /// second block can be inserted — and once a network holds two, putting
    /// the index back would fail. The drop happens at startup and only when
    /// this flag is on, so a deployment that never enables it keeps the guard.
    ///
    /// Env: `ROOMLER__OVERLAY__MULTI_BLOCK_ENABLED`.
    pub multi_block_enabled: bool,
}

impl Default for OverlaySettings {
    fn default() -> Self {
        Self {
            blocks_enabled: true,
            block_prefix: 22,
            // rc.301 shipped the P2a forward-compat set (prefix-aware
            // keep-set, bounded IPAM, remove-before-upsert deltas, gated DNS).
            block_version_floor: "0.3.0-rc.301".to_string(),
            multi_block_enabled: false,
        }
    }
}

/// Multi-region relay PoPs (regional coturn + DERP). Regions are fleet
/// infrastructure — like `turn.worker_urls` they live in operator config, not
/// the DB. `regions` is a JSON array of region specs (see
/// `remote_control::turn_creds::RelayRegionSpec`):
/// `[{"id":"us-east","turn_url":"turn:coturn-us-east.roomler.ai:3478",
///    "derp_url":"wss://derp-us-east.roomler.ai/derp",
///    "caps":{"tls_443_tcp":false}}, …]`
/// With `regions_enabled=false` (default) every issuance path uses the
/// legacy `turn.*` single-region config — provably unchanged behaviour.
#[derive(Debug, Clone, Deserialize)]
pub struct RelaySettings {
    /// Master gate for region-aware TURN/DERP issuance.
    /// Env: `ROOMLER__RELAY__REGIONS_ENABLED`.
    pub regions_enabled: bool,
    /// JSON array of relay region specs. Env: `ROOMLER__RELAY__REGIONS`.
    pub regions: Option<String>,
    /// Ed25519 private key (base64 PKCS#8 DER) minting regional-DERP
    /// admission tickets; PoP relays hold only the derived PUBLIC key.
    /// Generate: `openssl genpkey -algorithm ed25519 -outform DER | base64 -w0`.
    /// Env: `ROOMLER__RELAY__DERP_TICKET_PRIVATE_KEY`.
    pub derp_ticket_private_key: Option<String>,
    /// PoP `/stats` poll cadence in seconds; 0 disables the poller (regions
    /// then never mark busy). Env: `ROOMLER__RELAY__STATS_POLL_SECS`.
    pub stats_poll_secs: u64,
    /// Busy when a PoP's `load5 / cpus` exceeds this.
    /// Env: `ROOMLER__RELAY__BUSY_LOAD`.
    pub busy_load: f64,
    /// Busy when a PoP's sustained egress exceeds this many Mbps (sized for
    /// the 500 Mbps-capped OVH PoPs). Env: `ROOMLER__RELAY__BUSY_TX_MBPS`.
    pub busy_tx_mbps: f64,
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            regions_enabled: false,
            regions: None,
            derp_ticket_private_key: None,
            stats_poll_secs: 30,
            busy_load: 1.5,
            busy_tx_mbps: 400.0,
        }
    }
}

/// Observability / analytics (stats collectors, rollups, platform admin).
///
/// Collectors are additive writers (relay-PoP samples, per-agent heartbeat
/// buckets, presence transition events, call sessions) into `stats_*`
/// collections with deterministic `_id`s — every writer is an idempotent
/// upsert, which is what makes the 2-pod deployment safe without leases.
/// `enabled=false` is a kill switch that stops all stats writes and the
/// rollup task; read endpoints then serve `{enabled:false}`.
#[derive(Debug, Clone, Deserialize)]
pub struct StatsSettings {
    /// Master gate for stats collection + rollups.
    /// Env: `ROOMLER__STATS__ENABLED`.
    pub enabled: bool,
    /// Comma-separated **user ObjectIds** (24-hex) granted the platform
    /// observability dashboards. Deliberately ids, not emails: OAuth
    /// linking matches accounts by bare email, so an email allowlist
    /// would turn a provider-asserted address into platform-root.
    /// Env: `ROOMLER__STATS__PLATFORM_ADMINS`.
    pub platform_admins: Option<String>,
    /// Path to a MaxMind-format country database (DB-IP / GeoLite2) for
    /// the platform user analytics. Unset or empty ⇒ every session records
    /// `unknown` — an honest gap, never a guessed country. Nothing is
    /// vendored into the repo; the server IMAGE sets this to the DB-IP
    /// "IP to Country Lite" database it carries (CC BY 4.0, #1896,
    /// `files/geoip/README.md`), and an env value overrides it, or turns it
    /// off when empty. Env: `ROOMLER__STATS__GEOIP_MMDB`.
    pub geoip_mmdb: Option<String>,
}

impl Default for StatsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            platform_admins: None,
            geoip_mmdb: None,
        }
    }
}

/// FR-102 — `[growth]`, env `ROOMLER__GROWTH__*`: the growth-observability
/// surface under `/api/admin/growth/*` (platform admins only, like
/// `/admin/stats`), and the daily digest job (`docs/growth-observability.md`).
#[derive(Debug, Deserialize, Clone)]
pub struct GrowthSettings {
    /// Gate for the `/api/admin/growth/*` routes. Default **on**: it gates
    /// only platform-admin views and a read is cheap. `false` answers 404
    /// on every one of them — the P2 kill switch.
    /// Env: `ROOMLER__GROWTH__ENABLED`.
    #[serde(default = "growth_default_on")]
    pub enabled: bool,
    /// The daily digest job (P1d). Default **off**, so a self-hosted server
    /// never starts mailing its admins a report they did not ask for; the
    /// hosted configuration turns it on. Env: `ROOMLER__GROWTH__DIGEST_ENABLED`.
    #[serde(default)]
    pub digest_enabled: bool,
    /// The UTC hour (0–23) after which the PREVIOUS UTC day's digest is
    /// computed and sent. 6 by default: purestat closes a session 30 min
    /// after its last event, so by 06:00 the day is complete on both planes.
    /// A value past 23 reads as 6. Env: `ROOMLER__GROWTH__DIGEST_HOUR_UTC`.
    #[serde(default = "growth_default_digest_hour")]
    pub digest_hour_utc: u8,
    /// Comma-separated recipient addresses. Empty — the default — mails the
    /// platform admins at their proven `users.email`.
    /// Env: `ROOMLER__GROWTH__DIGEST_TO`.
    ///
    /// ⚠️ `String`, not `Vec<String>`, for the reason on
    /// [`JwtSettings::previous_secrets`]: an env var cannot become a sequence.
    #[serde(default)]
    pub digest_to: String,
    /// purestat's base URL, for the web sections of the digest (the v1 query
    /// at `{purestat_url}/api/v1/query`). Env: `ROOMLER__GROWTH__PURESTAT_URL`.
    #[serde(default = "growth_default_purestat_url")]
    pub purestat_url: String,
    /// A purestat API key scoped to the site (`X-API-Key`). Empty — the
    /// default — leaves the website, blog and campaign sections "not
    /// measured", never 0. Never logged. Env: `ROOMLER__GROWTH__PURESTAT_API_KEY`.
    #[serde(default)]
    pub purestat_api_key: String,
    /// P3 — count installer, latest-release and install-script fetches by
    /// client class into `growth_daily` (`docs/growth-observability.md`, the
    /// install trace). Default **on**: the counters are this server's own
    /// (a self-hosted server keeps them and sends them nowhere), carry no
    /// User-Agent and no IP, and never count the updater. `false` is the
    /// kill switch. Env: `ROOMLER__GROWTH__INSTALL_COUNTERS`.
    #[serde(default = "growth_default_on")]
    pub install_counters: bool,
    /// P3c — the operator's internal source networks: comma-separated CIDRs
    /// (`203.0.113.0/24, 2001:db8::/32`) or bare addresses. A counted fetch
    /// whose client address — derived exactly as the per-IP limiter derives
    /// it — falls inside is counted under the client class `internal`
    /// instead of its own, so the lab's and the operator's own installs stop
    /// inflating the install section, and the digest says how many were left
    /// out. The address is compared in memory and dropped; nothing stores
    /// it. Empty — the default — changes nothing, and the digest's internal
    /// count reads "not measured". An entry that does not parse is warned
    /// about once at boot and skipped. Env: `ROOMLER__GROWTH__INTERNAL_NETWORKS`.
    ///
    /// ⚠️ `String`, not `Vec<String>`, for `digest_to`'s reason.
    #[serde(default)]
    pub internal_networks: String,
    /// P3b — accept the setup wizard's opt-in diagnostics at
    /// `POST /api/setup/diagnostics` (`docs/growth-observability.md`, the
    /// install trace). Default **on**, for `install_counters`'s reason: the
    /// rows are this server's own — a self-hosted server receives its own
    /// wizards' and sends them nowhere — they exist only when the person
    /// ticked the box in the wizard, and they carry a random run id and
    /// codes, never an address, a User-Agent, a name or a path. The three
    /// jobs that default OFF (`digest_enabled`, `weekly_enabled`, `alerts`)
    /// are off because they MAIL people; this writes a row the admin asked
    /// the wizard to send. `false` is the kill switch: the route answers
    /// the empty 404 of a path that does not exist, and the wizard treats
    /// that like any other failure — silently. Env:
    /// `ROOMLER__GROWTH__SETUP_DIAGNOSTICS`.
    #[serde(default = "growth_default_on")]
    pub setup_diagnostics: bool,
    /// P10 — the weekly roll-up job: once the clock passes Monday
    /// `digest_hour_utc`, the past ISO week (Mon–Sun, UTC) is computed,
    /// stored in `growth_weekly` and mailed once to the digest's recipients.
    /// Default **off**, for the digest's reason. Env:
    /// `ROOMLER__GROWTH__WEEKLY_ENABLED`.
    #[serde(default)]
    pub weekly_enabled: bool,
    /// P9b — the post-session rating (spec §3f, D10): after a remote session
    /// of 30 s or more the viewer offers a thumbs up or down with optional
    /// reason chips, at most once a day per person, dismissible, never
    /// blocking. Stored in `session_feedback` on THIS server and sent
    /// nowhere (a self-hosted server keeps its own). Default **on**, for
    /// `install_counters`'s reason: no mail, no outside party, and a person
    /// chooses to answer. `false` is the kill switch: the viewer never
    /// offers the prompt (`/api/capabilities` says so) and the route answers
    /// the empty 404 of a path that does not exist. Env:
    /// `ROOMLER__GROWTH__FEEDBACK`.
    #[serde(default = "growth_default_on")]
    pub feedback: bool,
    /// P10 — the alert rules (`docs/growth-observability.md`, alerts): an
    /// hourly host job that opens a `growth_alerts` row when a rule fires,
    /// mails the digest's recipients at most once per rule per day, and
    /// clears the row when the condition goes away. Default **off**: the
    /// rules read this server's own numbers, but a self-hosted server never
    /// starts mailing its admins unasked. Env: `ROOMLER__GROWTH__ALERTS`.
    #[serde(default)]
    pub alerts: bool,
    /// P7 — the GitHub repository (`owner/name`) whose public counters the
    /// `saas` puller reads once a day: stars, forks, watchers and every
    /// release asset's download count, stored as cumulative snapshots and
    /// differenced into daily deltas. They need no credential (a handful of
    /// the 60 unauthenticated requests an hour). Empty switches the puller
    /// off. `saas` is hosted-only, so no self-hosted server ever asks.
    /// Env: `ROOMLER__GROWTH__GITHUB_REPO`.
    #[serde(default = "growth_default_github_repo")]
    pub github_repo: String,
    /// P7 — GitHub's REST API base. Only a test changes it.
    /// Env: `ROOMLER__GROWTH__GITHUB_API_URL`.
    #[serde(default = "growth_default_github_api_url")]
    pub github_api_url: String,
    /// P7 — an optional read-only token for the repository's traffic
    /// (views, clones and referrers; GitHub keeps 14 days of it, so it is
    /// pulled daily). A fine-grained token scoped to this one repository
    /// with the "Administration: read" permission is enough. Empty — the
    /// default — leaves traffic "not measured"; the public counters never
    /// need it. Never logged. Env: `ROOMLER__GROWTH__GITHUB_TOKEN`.
    #[serde(default)]
    pub github_token: String,
    /// P7 — the Search Console property the `saas` puller reads, as Search
    /// Console names it (`sc-domain:roomler.ai`, or a URL-prefix property's
    /// `https://…/`). Env: `ROOMLER__GROWTH__SEARCH_CONSOLE_SITE`.
    #[serde(default = "growth_default_search_console_site")]
    pub search_console_site: String,
    /// P7 — a service account's JSON key (the file Google Cloud hands out),
    /// whose `client_email` is a user of the property. Empty — the default
    /// — pulls nothing and leaves every search cell "not measured". Never
    /// logged, never echoed in an error. Env:
    /// `ROOMLER__GROWTH__SEARCH_CONSOLE_KEY`.
    #[serde(default)]
    pub search_console_key: String,
    /// P7 — the Search Console API base. Only a test changes it.
    /// Env: `ROOMLER__GROWTH__SEARCH_CONSOLE_API_URL`.
    #[serde(default = "growth_default_search_console_api_url")]
    pub search_console_api_url: String,
    /// P7 — the site as verified in Bing Webmaster Tools (`https://…/`).
    /// Env: `ROOMLER__GROWTH__BING_SITE_URL`.
    #[serde(default = "growth_default_bing_site_url")]
    pub bing_site_url: String,
    /// P7 — a Bing Webmaster API key. Empty — the default — pulls nothing
    /// and leaves the Bing cells "not measured". Never logged.
    /// Env: `ROOMLER__GROWTH__BING_API_KEY`.
    #[serde(default)]
    pub bing_api_key: String,
    /// P7 — the Bing Webmaster JSON API base. Only a test changes it.
    /// Env: `ROOMLER__GROWTH__BING_API_URL`.
    #[serde(default = "growth_default_bing_api_url")]
    pub bing_api_url: String,
    /// P7 — the blog's Atom feed, the list of posts the Content table and
    /// URL Inspection read. Empty — the default — is
    /// `{app.frontend_url}/blog/feed.xml`. Env: `ROOMLER__GROWTH__BLOG_FEED_URL`.
    #[serde(default)]
    pub blog_feed_url: String,
}

fn growth_default_on() -> bool {
    true
}

fn growth_default_search_console_site() -> String {
    "sc-domain:roomler.ai".to_string()
}

fn growth_default_search_console_api_url() -> String {
    "https://searchconsole.googleapis.com".to_string()
}

fn growth_default_bing_site_url() -> String {
    "https://roomler.ai/".to_string()
}

fn growth_default_bing_api_url() -> String {
    "https://ssl.bing.com/webmaster/api.svc/json".to_string()
}

fn growth_default_github_repo() -> String {
    "gjovanov/roomler-ai".to_string()
}

fn growth_default_github_api_url() -> String {
    "https://api.github.com".to_string()
}

fn growth_default_digest_hour() -> u8 {
    6
}

fn growth_default_purestat_url() -> String {
    "https://purestat.ai".to_string()
}

impl Default for GrowthSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            digest_enabled: false,
            digest_hour_utc: growth_default_digest_hour(),
            digest_to: String::new(),
            purestat_url: growth_default_purestat_url(),
            purestat_api_key: String::new(),
            install_counters: true,
            internal_networks: String::new(),
            setup_diagnostics: true,
            weekly_enabled: false,
            alerts: false,
            feedback: true,
            github_repo: growth_default_github_repo(),
            github_api_url: growth_default_github_api_url(),
            github_token: String::new(),
            search_console_site: growth_default_search_console_site(),
            search_console_key: String::new(),
            search_console_api_url: growth_default_search_console_api_url(),
            bing_site_url: growth_default_bing_site_url(),
            bing_api_key: String::new(),
            bing_api_url: growth_default_bing_api_url(),
            blog_feed_url: String::new(),
        }
    }
}

impl GrowthSettings {
    /// `digest_to` as a list: split on commas, trimmed, empties dropped.
    pub fn digest_recipients(&self) -> Vec<String> {
        self.digest_to
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// `digest_hour_utc` clamped to a real hour — a misconfigured 25 must
    /// not become "never".
    pub fn digest_hour(&self) -> u8 {
        if self.digest_hour_utc <= 23 {
            self.digest_hour_utc
        } else {
            growth_default_digest_hour()
        }
    }

    /// Whether the web sections can be measured at all.
    pub fn purestat_configured(&self) -> bool {
        !self.purestat_api_key.trim().is_empty()
    }

    /// P7 — the repository the GitHub puller reads, when it is a plausible
    /// `owner/name` (one slash, both halves non-empty, GitHub's characters
    /// only); `None` switches the puller off rather than asking GitHub for
    /// a path a typo built.
    pub fn github_repo(&self) -> Option<&str> {
        let repo = self.github_repo.trim();
        let (owner, name) = repo.split_once('/')?;
        let ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 100
                && !s.chars().all(|c| c == '.')
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        (ok(owner) && ok(name)).then_some(repo)
    }

    /// P7 — whether repository traffic can be read at all.
    pub fn github_traffic_configured(&self) -> bool {
        !self.github_token.trim().is_empty()
    }

    /// P7 — whether a Search Console key is set (whether it PARSES is the
    /// puller's to say, once, at boot).
    pub fn search_console_configured(&self) -> bool {
        !self.search_console_key.trim().is_empty() && !self.search_console_site.trim().is_empty()
    }

    /// P7 — whether a Bing Webmaster key is set.
    pub fn bing_configured(&self) -> bool {
        !self.bing_api_key.trim().is_empty() && !self.bing_site_url.trim().is_empty()
    }
}

/// GitHub-releases proxy cache (`routes::releases`, consumed by the
/// `/api/{agent,tunnel,setup}/latest-release` + installer handlers).
///
/// The cache is per-pod and in-process, so with N pods a freshly published
/// release stays invisible for up to one TTL on each of them independently.
/// `refresh_token` gates `POST /api/releases/refresh`, which the release
/// workflows call right after publishing to bust every pod's copy at once;
/// `cache_ttl_secs` is the backstop that heals a missed refresh.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleasesSettings {
    /// Shared secret for `POST /api/releases/refresh` (`Authorization:
    /// Bearer <token>`). **Unset ⇒ the endpoint is disabled (503)** — there
    /// is deliberately no permissive default, since an open refresh endpoint
    /// would let anyone burn GitHub's 60-req/h unauthenticated quota.
    /// Env: `ROOMLER__RELEASES__REFRESH_TOKEN`.
    pub refresh_token: Option<String>,
    /// TTL of the cached releases list. 15 min: one consolidated cache means
    /// N pods × 4 fetches/h, comfortably under GitHub's 60/h unauthenticated
    /// cap, while bounding worst-case staleness when the refresh call never
    /// lands. Env: `ROOMLER__RELEASES__CACHE_TTL_SECS`.
    pub cache_ttl_secs: u64,
}

impl Default for ReleasesSettings {
    fn default() -> Self {
        Self {
            refresh_token: None,
            cache_ttl_secs: 900,
        }
    }
}

/// Remote-control WS liveness (Phase A-1). Settings (not consts) so the
/// two-pod integration tests can run 2-3 s deadlines instead of 90 s
/// waits. Env: `ROOMLER__RC__WS_RX_DEADLINE_SECS` etc.
#[derive(Debug, Clone, Deserialize)]
pub struct RcSettings {
    /// Reap an agent/tunnel WS after this many seconds without ANY
    /// inbound frame (the agent pings every 25 s and heartbeats every
    /// 30 s, so a healthy leg is never silent this long).
    pub ws_rx_deadline_secs: u64,
    /// How often the read loop checks the deadline.
    pub ws_liveness_tick_secs: u64,
    /// P4 — per-tenant coalescing window for `device:presence` fan-out.
    /// A pod roll reconnects a whole fleet within seconds; batching turns
    /// that into one WS event per tenant instead of one per agent.
    /// Env: `ROOMLER__RC__PRESENCE_BATCH_MS`.
    pub presence_batch_ms: u64,
    /// P4 — interval of the cluster-singleton presence staleness sweep
    /// (stale/offline transitions have no socket-teardown moment to hook).
    /// Env: `ROOMLER__RC__PRESENCE_SWEEP_SECS`.
    pub presence_sweep_secs: u64,
    /// PR-1 rehome — direction guard band. On a cross-pod rc/tunnel miss
    /// the agent is judged PARKED (and nudged) only when the requesting
    /// conn is at least this much newer than the agent's presence record;
    /// anything closer is ambiguous (an LB map flip between two dials)
    /// and resolves to the free move: the controller re-dials. Ambiguity
    /// self-heals toward nudging — the record's since_ms is frozen while
    /// every controller retry re-establishes the conn, so the delta grows.
    /// Env: `ROOMLER__RC__REHOME_DIRECTION_GUARD_MS`.
    pub rehome_direction_guard_ms: i64,
    /// PR-1 rehome — owner-side pacing: minimum seconds between agent-WS
    /// nudge cycles per agent. A cycle tears the agent's rc/tunnel/overlay
    /// planes for seconds, so it must never flap.
    /// Env: `ROOMLER__RC__NUDGE_COOLDOWN_SECS`.
    pub nudge_cooldown_secs: u64,
    /// PR-1 rehome — nudge attempts inside the reset window before the
    /// agent is declared stuck (split evidence) and further nudges pause.
    /// Env: `ROOMLER__RC__NUDGE_MAX_ATTEMPTS`.
    pub nudge_max_attempts: u32,
    /// PR-1 rehome — quiet period after which the attempt counter resets.
    /// Env: `ROOMLER__RC__NUDGE_ATTEMPTS_RESET_SECS`.
    pub nudge_attempts_reset_secs: u64,
    /// PR-1 rehome — requester-side throttle: minimum ms between
    /// `rc.agent_nudge` RPCs per agent from this pod (a click storm sent
    /// 11 RPCs in 15 s at one refusing owner in the 2026-08-04 incident).
    /// Env: `ROOMLER__RC__NUDGE_REQUESTER_THROTTLE_MS`.
    pub nudge_requester_throttle_ms: u64,
    /// R3 — grace before a tunnel session is terminated when its TARGET
    /// agent's control WS drops. `0` (default) = terminate immediately
    /// (pre-R3 behaviour). `>0` = wait this many seconds, then terminate
    /// ONLY if the agent is still offline everywhere (same-pod hub +
    /// cross-pod Redis presence) — pairs with the agent's
    /// `tunnel_peers_survive_reattach` so an established QUIC/derp session
    /// rides out a corp-VPN control-WS blip instead of being re-opened.
    /// Env: `ROOMLER__RC__TUNNEL_GRACE_SECS`.
    pub tunnel_grace_secs: u64,
    /// FR-51 — master switch for the ephemeral-node reaper. Default **false**:
    /// zero queries, zero deletes, byte-for-byte pre-FR-51 behaviour. Flipping
    /// it on only ever affects rows that were enrolled `ephemeral: true` —
    /// every pre-FR-51 row deserialises permanent and the reap predicate
    /// cannot match it. Env: `ROOMLER__RC__EPHEMERAL_REAPER_ENABLED`.
    pub ephemeral_reaper_enabled: bool,
    /// FR-51 — reap cycle interval. Like the presence sweep, the cycle is a
    /// cluster singleton (DB-name-scoped Redis NX claim), so this is the
    /// deployment's cadence, not a per-pod one.
    /// Env: `ROOMLER__RC__EPHEMERAL_REAP_INTERVAL_SECS`.
    pub ephemeral_reap_interval_secs: u64,
    /// FR-51 — inactivity deadline for an ephemeral device whose enrollment
    /// key set no per-device override. 900 s (15 min): long enough that a
    /// network blip or a pod roll is not a deleted device, short enough that
    /// a finished CI runner does not linger as quota. The reaper clamps every
    /// effective TTL (this one included) to a 60 s floor at read time.
    /// Env: `ROOMLER__RC__EPHEMERAL_DEFAULT_TTL_SECS`.
    pub ephemeral_default_ttl_secs: u64,
    /// FR-94 — route Fleet RPC through a Windows device's SYSTEM service
    /// (the doorbell → claim → result path) when the device advertises
    /// `exec-system`. Default **true**: only a device that was anchored by an
    /// administrator ever advertises that word, so this changes nothing for
    /// any other device. `false` is the server's kill switch. Every command
    /// then takes the worker path as before FR-94, and the org setting
    /// `exec_require_system` refuses Windows commands instead of running
    /// them as the worker. Env: `ROOMLER__RC__EXEC_VIA_SERVICE`.
    #[serde(default = "default_true")]
    pub exec_via_service: bool,
    /// FR-105 — route roomler SSH grants through a Windows device's SYSTEM
    /// service (port 2223, the service's host key, the claim) when the device
    /// advertises `ssh-system` and its service published an endpoint under its
    /// current anchor. Default **true**: nothing advertises that word unless
    /// an administrator raised the anchor's `ssh` ceiling on the device, so
    /// this changes nothing for any other device. `false` is the server's kill
    /// switch: every grant goes to the worker as before FR-105.
    /// Env: `ROOMLER__RC__SSH_VIA_SERVICE`.
    #[serde(default = "default_true")]
    pub ssh_via_service: bool,
    /// FR-103 — serve `POST /api/agent/self/renew` and
    /// `POST /api/tunnel-client/renew`. Default **true**. `false` is the
    /// kill switch: both answer 404, and a device keeps the token it has,
    /// exactly as before FR-103. Env: `ROOMLER__RC__TOKEN_RENEWAL`.
    #[serde(default = "default_true")]
    pub token_renewal: bool,
    /// FR-103 — refuse an agent or tunnel-client token whose `gen` claim is
    /// not the row's `token_gen`, i.e. one minted before the device was
    /// removed. Default **true**. Every row never removed is at 0, as is every
    /// pre-FR-103 token, so this refuses nothing else. `false` is the kill
    /// switch if it ever does. Env: `ROOMLER__RC__TOKEN_GENERATION_CHECK`.
    #[serde(default = "default_true")]
    pub token_generation_check: bool,
    /// FR-103 — the lifetime of a freshly minted agent or tunnel-client
    /// token, in seconds. Default one year. A test knob: the integration lane
    /// and a throwaway stack shorten it to prove expiry and the renewal grace.
    /// Never shortened on prod. Env: `ROOMLER__RC__AGENT_TOKEN_TTL_SECS`.
    #[serde(default = "default_agent_token_ttl_secs")]
    pub agent_token_ttl_secs: u64,
    /// #2267 — a removal tells a CONNECTED device at once: the kick queues
    /// `rc:goodbye AgentDeleted` on its socket, and its daemon stops as it
    /// would at its next connection. Default **true**. `false` is the kill
    /// switch: the kick only takes the device out of the hub, and the device
    /// keeps its socket until something else drops it, as before #2267.
    /// Env: `ROOMLER__RC__REMOVAL_GOODBYE`.
    #[serde(default = "default_true")]
    pub removal_goodbye: bool,
    /// FR-115 P3 — refuse a NEW remote session once the device's org runs as
    /// many at once as its plan allows (Free: one, Pro: one per seat).
    /// Default **true**. `false` is the kill switch: no cap, as before
    /// FR-115. A live session is never ended either way.
    /// Env: `ROOMLER__RC__ORG_SESSION_CAP`.
    #[serde(default = "default_true")]
    pub org_session_cap: bool,
    /// FR-115 P3b — count concurrent remote sessions cluster-wide, in Redis
    /// (`roomler_core::cluster::session_slots`): an org's sessions to its own
    /// devices and the external (FR-52) sessions run for it share its slots,
    /// and an account in no org gets Free's one. Default **false** (shipped
    /// dark): P3's count on the hub that owns the device, with external
    /// sessions uncapped, as before. Needs `org_session_cap` on too.
    /// Env: `ROOMLER__RC__SESSION_SLOTS`.
    #[serde(default)]
    pub session_slots: bool,
}

fn default_agent_token_ttl_secs() -> u64 {
    365 * 24 * 60 * 60
}

impl Default for RcSettings {
    fn default() -> Self {
        Self {
            ws_rx_deadline_secs: 90,
            ws_liveness_tick_secs: 30,
            presence_batch_ms: 2000,
            presence_sweep_secs: 30,
            rehome_direction_guard_ms: 5000,
            nudge_cooldown_secs: 60,
            nudge_max_attempts: 3,
            nudge_attempts_reset_secs: 600,
            nudge_requester_throttle_ms: 5000,
            tunnel_grace_secs: 0,
            ephemeral_reaper_enabled: false,
            ephemeral_reap_interval_secs: 60,
            ephemeral_default_ttl_secs: 900,
            exec_via_service: true,
            ssh_via_service: true,
            token_renewal: true,
            token_generation_check: true,
            agent_token_ttl_secs: default_agent_token_ttl_secs(),
            removal_goodbye: true,
            org_session_cap: true,
            session_slots: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccountApprovalSettings {
    /// Opt-in deployment policy; unrelated application features are unchanged.
    #[serde(default)]
    pub enabled: bool,
    /// Explicit existing user ObjectId. Never inferred from signup order/email.
    #[serde(default)]
    pub owner_user_id: Option<String>,
}

impl Default for AccountApprovalSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            owner_user_id: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthSettings {
    #[serde(default)]
    pub account_approval: AccountApprovalSettings,
    /// When true, `register` sets `is_verified: true` on the new user
    /// directly, bypassing the email activation flow. Default false —
    /// production keeps the email-link activation as the only path.
    /// Used only by the e2e overlay (`ROOMLER__AUTH__AUTO_VERIFY=true`)
    /// so Playwright specs can `register → login` without an SMTP
    /// capture. Phase 4 of the e2e plan replaces this with Mailpit
    /// + a helper that pulls the activation token from the inbox.
    #[serde(default)]
    pub auto_verify: bool,

    /// FR-82 — reconcile every system-managed role to its definition at
    /// startup, so a permission bit added to the code reaches organisations
    /// that already exist. Default **on**: without it a managed role stays
    /// frozen at the mask it was seeded with, which is the defect this
    /// closes (63 of 72 hosted orgs were).
    ///
    /// The kill switch (`ROOMLER__AUTH__RECONCILE_MANAGED_ROLES=false`) is
    /// for two cases and no others: a deployment that has deliberately
    /// hand-edited a managed role DOWN and wants it left alone (the
    /// reconcile is additive, so it would put the bit back on every boot),
    /// and stopping the job without rolling back an image if it ever
    /// misbehaves.
    #[serde(default = "default_true")]
    pub reconcile_managed_roles: bool,
}

/// ⚠️ Hand-written, NOT derived. `AuthSettings` carries a field whose serde
/// default is `true`, and a derived `Default` would answer `false` for it —
/// two "defaults" that disagree, where one of them is reached by config
/// parsing and the other by `AuthSettings::default()` in the test fixture.
/// The reconcile would then be silently off for every test that builds
/// settings that way, which is precisely the seam a bug would hide in.
impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            auto_verify: false,
            account_approval: AccountApprovalSettings::default(),
            reconcile_managed_roles: default_true(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthSettings {
    pub base_url: String,
    pub google: OAuthProviderSettings,
    pub facebook: OAuthProviderSettings,
    pub github: OAuthProviderSettings,
    pub linkedin: OAuthProviderSettings,
    pub microsoft: OAuthProviderSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuthProviderSettings {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppSettings {
    pub host: String,
    pub port: u16,
    pub static_dir: Option<String>,
    pub cors_origins: Vec<String>,
    pub frontend_url: String,
    /// Deployment environment label (`"development"` default). Setting it to
    /// `"production"` arms hard-fail guards — currently: refusing to boot
    /// while `jwt.secret` is still the built-in default. Prod sets
    /// `ROOMLER__APP__ENVIRONMENT=production` in the configmap.
    #[serde(default = "default_environment")]
    pub environment: String,
    /// C-1 — explicit stable pod identity override
    /// (`ROOMLER__APP__POD_ID`). Unset (the default) resolves through
    /// `ROOMLER__POD_HOST_IP` (hostNetwork ⇒ ≤1 pod/node, so the node IP
    /// IS the pod identity — the same key the LB upstream list and the
    /// mediasoup announced-ip map use) → hostname → a random dev id.
    /// Tests inject distinct values per in-process TestApp.
    #[serde(default)]
    pub pod_id: Option<String>,
    /// Sustained per-client-IP rate for `/api`, in **requests per second**.
    /// Default 1. The e2e overlay bumps this so a Playwright Job's single
    /// pod IP doesn't trip 429s during the suite.
    ///
    /// Note this is a *rate*, not an interval — see [`Self::rate_limit_period_ms`]
    /// for why that distinction is a trap worth spelling out.
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: u64,
    /// Per-IP burst cap for `/api`. Default 60. This is the real headroom
    /// for a page load: a SPA fans out to many endpoints at once, and every
    /// client behind one NAT shares the bucket.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    /// How many reverse proxies *we* control append to `X-Forwarded-For`
    /// before a request reaches axum. Everything further left in that header
    /// is client-supplied and must not be trusted. Prod chain is
    /// docker-nginx (sets the client IP) → pod-nginx (appends its peer), so
    /// exactly 1 hop is ours.
    #[serde(default = "default_rate_limit_trusted_hops")]
    pub rate_limit_trusted_hops: usize,
    /// Sustained auth-endpoint attempts per minute, per (client IP, account).
    /// Deliberately far stricter than the general `/api` limit: this is the
    /// brute-force gate, and it must not depend on starving the whole API.
    #[serde(default = "default_auth_rate_limit_per_min")]
    pub auth_rate_limit_per_min: u32,
    /// Burst cap for the auth limiter, per (client IP, account).
    #[serde(default = "default_auth_rate_limit_burst")]
    pub auth_rate_limit_burst: u32,
}

impl AppSettings {
    /// Replenish interval, in milliseconds, for one `/api` token.
    ///
    /// `tower_governor`'s builder takes the interval that replenishes ONE
    /// cell (`per_second(n)` is `Duration::from_secs(n)`), **not** a rate —
    /// so passing a req/s number straight into `per_second` silently makes
    /// the limit *n* times stricter. Prod hit exactly that on 2026-07-28.
    /// Convert here instead, and clamp: the builder rejects a zero period.
    pub fn rate_limit_period_ms(&self) -> u64 {
        (1000 / self.rate_limit_per_sec.max(1)).max(1)
    }

    /// Replenish interval, in milliseconds, for one auth-endpoint token.
    pub fn auth_rate_limit_period_ms(&self) -> u64 {
        (60_000 / u64::from(self.auth_rate_limit_per_min.max(1))).max(1)
    }
}

fn default_environment() -> String {
    "development".to_string()
}
fn default_rate_limit_per_sec() -> u64 {
    1
}
fn default_rate_limit_burst() -> u32 {
    60
}
fn default_rate_limit_trusted_hops() -> usize {
    1
}
fn default_auth_rate_limit_per_min() -> u32 {
    10
}
fn default_auth_rate_limit_burst() -> u32 {
    20
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseSettings {
    pub url: String,
    pub name: String,
    pub max_pool_size: Option<u32>,
    pub min_pool_size: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSettings {
    pub secret: String,
    /// Secrets that no longer SIGN anything but whose tokens are still
    /// accepted — comma-separated, most-recent first.
    ///
    /// This is what makes rotating `secret` a rolling change instead of a flag
    /// day. Without it, changing the secret invalidates every live token at
    /// once, including every enrolled agent's **one-year** token — which means
    /// the whole fleet re-enrolls by hand, which means in a real incident the
    /// rotation gets deferred. A control nobody can afford to use is not a
    /// control.
    ///
    /// Rotation: move the current value here, set `secret` to the new one,
    /// deploy. Both verify; only the new one signs. Drop this once the longest
    /// TTL still in flight has expired (an agent token: a year, unless they are
    /// re-issued first).
    ///
    /// ⚠️ `String`, not `Vec<String>`, on purpose: this crate feeds
    /// `Environment` sources straight into serde, and a scalar env var
    /// deserialising into a sequence FAILS (`invalid type: string, expected a
    /// sequence` — the same trap documented on `app.cors_origins` in
    /// `scripts/e2e-k8s/overlay-template/configmap-roomler2-config.yaml`). A
    /// `Vec` here could not be set by `ROOMLER__JWT__PREVIOUS_SECRETS` at all.
    #[serde(default)]
    pub previous_secrets: String,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub issuer: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisSettings {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct S3Settings {
    /// Opt-in switch for the S3/MinIO file backend. The other `s3.*`
    /// fields have always had localhost-MinIO defaults, so their mere
    /// presence can't signal intent — without this flag uploads stay on
    /// the local-disk backend (pod-ephemeral in k8s). Prod sets
    /// `ROOMLER__S3__ENABLED=true`.
    #[serde(default)]
    pub enabled: bool,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    pub region: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MediasoupSettings {
    pub num_workers: u32,
    pub listen_ip: String,
    pub announced_ip: String,
    /// S6 — per-node announced-IP override for multi-pod hostNetwork
    /// deployments: `"<node_ip>=<public_ip>,<node_ip>=<public_ip>"`.
    /// One Deployment can't template a per-node env value, so the pod
    /// gets its own node IP via the Downward API (`ROOMLER__POD_HOST_IP`,
    /// status.hostIP) and picks its public announced IP from this map.
    /// Absent / no match → `announced_ip` as before.
    #[serde(default)]
    pub announced_ip_map: Option<String>,
    pub rtc_min_port: u16,
    pub rtc_max_port: u16,
}

impl MediasoupSettings {
    /// Resolve the effective announced IP for this pod: exact
    /// `announced_ip_map` match on `pod_host_ip` wins, else the static
    /// `announced_ip` (empty → None, mediasoup announces the listen IP).
    pub fn resolve_announced_ip(&self, pod_host_ip: Option<&str>) -> Option<String> {
        if let (Some(map), Some(host_ip)) = (&self.announced_ip_map, pod_host_ip) {
            for pair in map.split(',') {
                if let Some((node, public)) = pair.split_once('=')
                    && node.trim() == host_ip.trim()
                    && !public.trim().is_empty()
                {
                    return Some(public.trim().to_string());
                }
            }
        }
        if self.announced_ip.is_empty() {
            None
        } else {
            Some(self.announced_ip.clone())
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TurnSettings {
    pub url: Option<String>,
    /// Same-worker TURN affinity: comma-separated per-worker base URLs, one
    /// per coturn worker (e.g.
    /// "turn:coturn-1.roomler.ai:3478,turn:coturn-2.roomler.ai:3478").
    /// Each is expanded into transport variants like `url`. Unset = no
    /// affinity (single-hostname DNS round-robin behaviour).
    pub worker_urls: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub shared_secret: Option<String>,
    pub force_relay: Option<bool>,
    /// Ephemeral-credential TTL in seconds; 600 (the historical hardcode)
    /// when unset. Env: `ROOMLER__TURN__TTL_SECS`.
    pub ttl_secs: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct StripeSettings {
    pub secret_key: String,
    pub webhook_secret: String,
    /// The MONTHLY Prices, one unit per seat (FR-115). Each carries a USD
    /// amount and an EUR `currency_options` entry.
    pub price_pro: String,
    pub price_business: String,
    /// FR-115 — the ANNUAL Prices (two months free). Empty = annual is not
    /// offered: `/api/stripe/plans` says so and checkout refuses `year`.
    /// Env: `ROOMLER__STRIPE__PRICE_PRO_ANNUAL`, `…__PRICE_BUSINESS_ANNUAL`.
    #[serde(default)]
    pub price_pro_annual: String,
    #[serde(default)]
    pub price_business_annual: String,
    /// FR-115 — the currencies the paid plans are offered in, comma-separated
    /// (`usd,eur`). Default `usd`: a currency is offered only once every
    /// configured Price carries an amount in it (an EUR `currency_options`
    /// entry), or a European browser, which the billing page starts on EUR,
    /// would be refused at checkout. An unknown code is ignored; nothing
    /// readable means USD. Env: `ROOMLER__STRIPE__CURRENCIES`.
    #[serde(default)]
    pub currencies: String,
    /// FR-115 — the Stripe API's base URL; empty = `https://api.stripe.com`.
    /// Tests point it at a fake. Env: `ROOMLER__STRIPE__API_BASE`.
    #[serde(default)]
    pub api_base: String,
    /// FR-115 P2's kill switch: keep each subscription's quantity equal to
    /// the org's seat count (a reconcile every 15 minutes, with proration).
    /// Off = the quantity is set at checkout and never moved.
    /// Env: `ROOMLER__STRIPE__SEAT_SYNC`.
    #[serde(default)]
    pub seat_sync: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GiphySettings {
    pub api_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailSettings {
    pub api_key: String,
    pub from_email: String,
    pub from_name: String,
    pub activation_token_ttl_minutes: u64,
    /// SMTP backend host. When set (and `api_key` is empty), the
    /// EmailService dispatches outbound mail over SMTP instead of
    /// SendGrid HTTP. Used by the e2e overlay to capture mail in
    /// Mailpit; not currently used by production.
    #[serde(default)]
    pub smtp_host: Option<String>,
    /// SMTP backend port. Pairs with `smtp_host`. No default — when
    /// `smtp_host` is set you must also set the port (Mailpit
    /// listens on 1025).
    #[serde(default)]
    pub smtp_port: Option<u16>,
}

/// FR-58 — the newsletter's own From mailbox, separate from the transactional
/// one so campaign reputation is isolated from the From that activation and
/// invite mail depend on. Both optional: unset ⇒ fall back to `email.from_*`,
/// so a self-hosted instance needs no extra configuration.
/// Env: `ROOMLER__NEWSLETTER__FROM_EMAIL` / `ROOMLER__NEWSLETTER__FROM_NAME`.
///
/// FR-102 P5 adds the delivery side (`docs/growth-observability.md`, the
/// newsletter): the key SendGrid's signed Event Webhook is verified with, and
/// the per-issue link tags.
#[derive(Debug, Deserialize, Clone)]
pub struct NewsletterSettings {
    #[serde(default)]
    pub from_email: Option<String>,
    #[serde(default)]
    pub from_name: Option<String>,
    /// FR-102 P5 (D6) — the public key SendGrid signs its Event Webhook
    /// with (Mail Settings → Event Webhook → Signature Verification): the
    /// base64 DER key SendGrid shows, or the same key as PEM. Empty — the
    /// default — and `POST /api/sendgrid/webhook` answers 404 to
    /// everything: with nothing to verify against, nothing is accepted.
    /// Env: `ROOMLER__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY`.
    #[serde(default)]
    pub event_webhook_public_key: String,
    /// FR-102 P5 (D5) — the issue's links to this site carry
    /// `utm_source=newsletter&utm_medium=email&utm_campaign=nl-<slug>`,
    /// identical for every recipient. Default **on**; `false` sends the
    /// links as written (and the issue's visits read "not measured").
    /// Env: `ROOMLER__NEWSLETTER__LINK_TAGS`.
    #[serde(default = "newsletter_default_link_tags")]
    pub link_tags: bool,
}

fn newsletter_default_link_tags() -> bool {
    true
}

impl Default for NewsletterSettings {
    fn default() -> Self {
        Self {
            from_email: None,
            from_name: None,
            event_webhook_public_key: String::new(),
            link_tags: newsletter_default_link_tags(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PushSettings {
    pub vapid_public_key: String,
    pub vapid_private_key: String,
    pub contact: String,
}

/// FR-20 P5 — what a metered unit costs us, read from `config/relay-costs.toml`
/// (or `ROOMLER__RELAY_COSTS__*`).
///
/// # Every field is `Option` on purpose
///
/// There is no default price anywhere in the code, and there must not be one.
/// An unset cost renders as **"not priced"** on `/observability`; a defaulted
/// one would render as a *number*, and a wrong cost is far worse than a
/// visibly missing one — it also produces a bogus **margin**, which is the
/// figure someone would actually make a pricing decision on. Same discipline
/// as the absent GeoIP database honestly reporting `country: unknown`.
///
/// ⚠ These are COSTS, not prices. What a customer pays lives in
/// `Plan::price_monthly_cents`; margin is the difference between the two.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RelayCosts {
    /// ISO-4217 code rendered beside every figure. No conversion happens
    /// anywhere, so every cost below must already be in this currency.
    #[serde(default)]
    pub currency: Option<String>,
    /// Cost per GB forwarded by a DERP relay on a tenant's behalf.
    #[serde(default)]
    pub derp_gb: Option<f64>,
    /// Cost per GB relayed by coturn. Priced here for completeness; the
    /// meter behind it is not collected (FR-20 P3 is blocked on coturn
    /// emitting no `user` label), so the surface reports it *unmonitored*.
    #[serde(default)]
    pub turn_gb: Option<f64>,
    /// Cost per SFU participant-hour — conference cost scales with
    /// participants x time, not with call count.
    #[serde(default)]
    pub sfu_participant_hour: Option<f64>,
}

impl Settings {
    /// FR-90 P1g — whether agent sessions are on: `[modules] hive`, or a
    /// `hive.tenants` list (see [`HiveSettings::tenants`] for why a list alone
    /// is enough).
    pub fn hive_on(&self) -> bool {
        self.modules.hive || !self.hive.tenants.trim().is_empty()
    }

    /// FR-90 P3-1 — whether the vault is on: `[modules] vault`, or a
    /// `vault.tenants` list ([`VaultSettings::tenants`]).
    pub fn vault_on(&self) -> bool {
        self.modules.vault || !self.vault.tenants.trim().is_empty()
    }

    /// [`ModulesSettings::switched_off`], with `hive` and `vault` on wherever
    /// [`Self::hive_on`] and [`Self::vault_on`] say they are — what boot
    /// logs and `GET /api/capabilities` report, so
    /// `modules = compiled − switched_off` still holds.
    pub fn switched_off(&self) -> Vec<&'static str> {
        let mut off = self.modules.switched_off();
        if self.hive_on() {
            off.retain(|m| *m != "hive");
        }
        if self.vault_on() {
            off.retain(|m| *m != "vault");
        }
        off
    }

    pub fn load() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/local").required(false))
            // FR-20 P5 — unit costs, kept in their own file so a price edit
            // is one line in one place. Optional: absent leaves every cost
            // `None`, which renders as "not priced" rather than as zero.
            .add_source(File::with_name("config/relay-costs").required(false))
            .add_source(Environment::default().separator("__").prefix("ROOMLER"))
            .set_default("app.host", "0.0.0.0")?
            .set_default("app.port", 3000)?
            .set_default("app.cors_origins", Vec::<String>::new())?
            .set_default("app.environment", "development")?
            // The Vite dev server listens on 5000 (`ui/vite.config.ts`), not
            // Vite's 5173 scaffold default. This value is the ONLY origin the
            // CORS layer trusts when `cors_origins` is unset, and since #680
            // it is also the only origin allowed to authenticate a `/ws`
            // handshake with the session cookie — so a wrong default is a
            // local-dev outage, not a cosmetic mismatch. Production overrides
            // it via `ROOMLER__APP__FRONTEND_URL` and is unaffected.
            .set_default("app.frontend_url", DEFAULT_FRONTEND_URL)?
            .set_default("app.rate_limit_per_sec", 1)?
            .set_default("app.rate_limit_burst", 60)?
            .set_default("app.rate_limit_trusted_hops", 1)?
            .set_default("app.auth_rate_limit_per_min", 10)?
            .set_default("app.auth_rate_limit_burst", 20)?
            .set_default("database.url", "mongodb://localhost:27019")?
            .set_default("database.name", "roomler-ai")?
            .set_default("jwt.secret", "change-me-in-production")?
            // Access token: 1 week (was 1 hour). The shorter TTL was
            // partnered with a much longer refresh, but operators
            // were getting kicked back to /login mid-session every
            // hour which the auto-refresh flow doesn't always
            // recover from cleanly. 1-week access trades off some
            // exposure on a leaked token for substantially better
            // session continuity. Refresh extended to 30 days so
            // the refresh > access invariant still holds.
            .set_default("jwt.previous_secrets", "")?
            .set_default("jwt.access_token_ttl_secs", 604800)?
            .set_default("jwt.refresh_token_ttl_secs", 2_592_000)?
            .set_default("jwt.issuer", "roomler-ai")?
            .set_default("redis.url", "redis://127.0.0.1:6379")?
            .set_default("rc.ws_rx_deadline_secs", 90)?
            .set_default("rc.ws_liveness_tick_secs", 30)?
            .set_default("rc.presence_batch_ms", 2000)?
            .set_default("rc.presence_sweep_secs", 30)?
            .set_default("rc.rehome_direction_guard_ms", 5000)?
            .set_default("rc.nudge_cooldown_secs", 60)?
            .set_default("rc.nudge_max_attempts", 3)?
            .set_default("rc.nudge_attempts_reset_secs", 600)?
            .set_default("rc.nudge_requester_throttle_ms", 5000)?
            .set_default("rc.tunnel_grace_secs", 0)?
            .set_default("rc.ephemeral_reaper_enabled", false)?
            .set_default("rc.ephemeral_reap_interval_secs", 60)?
            .set_default("rc.ephemeral_default_ttl_secs", 900)?
            .set_default("rc.exec_via_service", true)?
            .set_default("rc.ssh_via_service", true)?
            .set_default("rc.token_renewal", true)?
            .set_default("rc.token_generation_check", true)?
            .set_default("rc.agent_token_ttl_secs", 365 * 24 * 60 * 60)?
            .set_default("rc.removal_goodbye", true)?
            .set_default("rc.org_session_cap", true)?
            .set_default("rc.session_slots", false)?
            .set_default("s3.enabled", false)?
            .set_default("s3.endpoint", "http://localhost:9000")?
            .set_default("s3.access_key", "minioadmin")?
            .set_default("s3.secret_key", "minioadmin")?
            .set_default("s3.bucket", "roomler-ai")?
            .set_default("s3.region", "us-east-1")?
            .set_default("mediasoup.num_workers", 2)?
            .set_default("mediasoup.listen_ip", "0.0.0.0")?
            .set_default("mediasoup.announced_ip", "127.0.0.1")?
            .set_default("mediasoup.rtc_min_port", 40000)?
            .set_default("mediasoup.rtc_max_port", 49999)?
            .set_default("turn.url", None::<String>)?
            .set_default("turn.worker_urls", None::<String>)?
            .set_default("turn.username", None::<String>)?
            .set_default("turn.password", None::<String>)?
            .set_default("turn.force_relay", false)?
            .set_default("turn.ttl_secs", None::<i64>)?
            .set_default("relay.regions_enabled", false)?
            .set_default("relay.regions", None::<String>)?
            .set_default("relay.derp_ticket_private_key", None::<String>)?
            .set_default("relay.stats_poll_secs", 30)?
            .set_default("relay.busy_load", 1.5)?
            .set_default("relay.busy_tx_mbps", 400.0)?
            .set_default("releases.refresh_token", None::<String>)?
            .set_default("releases.cache_ttl_secs", 900)?
            .set_default("stats.enabled", true)?
            .set_default("stats.platform_admins", None::<String>)?
            .set_default("stats.geoip_mmdb", None::<String>)?
            .set_default("overlay.blocks_enabled", true)?
            .set_default("overlay.block_prefix", 22)?
            .set_default("overlay.multi_block_enabled", false)?
            .set_default("overlay.block_version_floor", "0.3.0-rc.301")?
            .set_default("oauth.base_url", "http://localhost:5001")?
            .set_default("oauth.google.client_id", "")?
            .set_default("oauth.google.client_secret", "")?
            .set_default("oauth.facebook.client_id", "")?
            .set_default("oauth.facebook.client_secret", "")?
            .set_default("oauth.github.client_id", "")?
            .set_default("oauth.github.client_secret", "")?
            .set_default("oauth.linkedin.client_id", "")?
            .set_default("oauth.linkedin.client_secret", "")?
            .set_default("oauth.microsoft.client_id", "")?
            .set_default("oauth.microsoft.client_secret", "")?
            .set_default("stripe.secret_key", "")?
            .set_default("stripe.webhook_secret", "")?
            .set_default("stripe.price_pro", "")?
            .set_default("stripe.price_business", "")?
            .set_default("stripe.price_pro_annual", "")?
            .set_default("stripe.price_business_annual", "")?
            .set_default("stripe.currencies", "usd")?
            .set_default("stripe.api_base", "")?
            .set_default("stripe.seat_sync", true)?
            .set_default("giphy.api_key", "")?
            .set_default("email.api_key", "")?
            .set_default("email.from_email", "noreply@roomler.ai")?
            .set_default("email.from_name", "Roomler")?
            .set_default("email.activation_token_ttl_minutes", 5u64)?
            .set_default("email.smtp_host", None::<String>)?
            .set_default("email.smtp_port", None::<u16>)?
            .set_default("push.vapid_public_key", "")?
            .set_default("push.vapid_private_key", "")?
            .set_default("push.contact", "mailto:noreply@roomler.ai")?
            .set_default("auth.auto_verify", false)?
            .build()?;

        config.try_deserialize()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::load().expect("Failed to load default settings")
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::AppSettings;

    fn app(per_sec: u64, auth_per_min: u32) -> AppSettings {
        AppSettings {
            host: "0.0.0.0".into(),
            port: 3000,
            static_dir: None,
            cors_origins: vec![],
            frontend_url: "http://localhost".into(),
            environment: "development".into(),
            pod_id: None,
            rate_limit_per_sec: per_sec,
            rate_limit_burst: 60,
            rate_limit_trusted_hops: 1,
            auth_rate_limit_per_min: auth_per_min,
            auth_rate_limit_burst: 20,
        }
    }

    /// The whole point of the helper: a req/s number must become a
    /// *shorter* interval, never a longer one. Passing 10 straight into
    /// `per_second` took prod from 1 req/s down to 0.1 req/s on 2026-07-28.
    #[test]
    fn higher_rate_means_shorter_period() {
        assert_eq!(app(1, 10).rate_limit_period_ms(), 1000);
        assert_eq!(app(10, 10).rate_limit_period_ms(), 100);
        assert_eq!(app(100, 10).rate_limit_period_ms(), 10);
        assert!(app(50, 10).rate_limit_period_ms() < app(5, 10).rate_limit_period_ms());
    }

    /// The builder rejects a zero period, so both ends must clamp.
    #[test]
    fn period_never_zero() {
        assert_eq!(app(0, 0).rate_limit_period_ms(), 1000);
        assert_eq!(app(5000, 0).rate_limit_period_ms(), 1);
        assert_eq!(app(1, 0).auth_rate_limit_period_ms(), 60_000);
        assert_eq!(app(1, 120_000).auth_rate_limit_period_ms(), 1);
    }

    #[test]
    fn auth_period_matches_per_minute() {
        assert_eq!(app(1, 10).auth_rate_limit_period_ms(), 6_000);
        assert_eq!(app(1, 60).auth_rate_limit_period_ms(), 1_000);
    }
}

#[cfg(test)]
mod s6_tests {
    use super::MediasoupSettings;

    fn ms(announced: &str, map: Option<&str>) -> MediasoupSettings {
        MediasoupSettings {
            num_workers: 1,
            listen_ip: "0.0.0.0".into(),
            announced_ip: announced.into(),
            announced_ip_map: map.map(|s| s.to_string()),
            rtc_min_port: 40000,
            rtc_max_port: 49999,
        }
    }

    #[test]
    fn announced_ip_map_matches_pod_host() {
        let s = ms(
            "5.9.157.221",
            Some("10.10.30.11=5.9.157.221,10.10.20.11=5.9.157.226"),
        );
        assert_eq!(
            s.resolve_announced_ip(Some("10.10.20.11")).as_deref(),
            Some("5.9.157.226")
        );
        assert_eq!(
            s.resolve_announced_ip(Some("10.10.30.11")).as_deref(),
            Some("5.9.157.221")
        );
    }

    #[test]
    fn announced_ip_map_falls_back_to_static() {
        let s = ms("5.9.157.221", Some("10.10.30.11=5.9.157.221"));
        // Unknown node → static value.
        assert_eq!(
            s.resolve_announced_ip(Some("192.168.1.1")).as_deref(),
            Some("5.9.157.221")
        );
        // No pod host ip (non-k8s run) → static value.
        assert_eq!(s.resolve_announced_ip(None).as_deref(), Some("5.9.157.221"));
        // No map at all → static value.
        let s2 = ms("1.2.3.4", None);
        assert_eq!(
            s2.resolve_announced_ip(Some("10.10.30.11")).as_deref(),
            Some("1.2.3.4")
        );
        // Empty static + no match → None (mediasoup announces listen ip).
        let s3 = ms("", None);
        assert_eq!(s3.resolve_announced_ip(Some("10.10.30.11")), None);
    }

    #[test]
    fn announced_ip_map_tolerates_whitespace_and_junk() {
        let s = ms("", Some(" 10.10.30.11 = 5.9.157.221 ,junk,also=,x"));
        assert_eq!(
            s.resolve_announced_ip(Some("10.10.30.11")).as_deref(),
            Some("5.9.157.221")
        );
        assert_eq!(s.resolve_announced_ip(Some("also")), None);
    }
}

#[cfg(test)]
mod hive_settings_tests {
    use super::HiveSettings;

    /// FR-90 P2f-2b — a teleport's have and want ships OFF, both where the
    /// settings are built whole and where a file leaves the key out: what
    /// turns it on is the operator's word on decision 16, never an upgrade.
    #[test]
    fn a_teleports_have_and_want_is_off_until_turned_on() {
        assert!(!HiveSettings::default().teleport_have_want);
        let absent: HiveSettings = toml::from_str("").expect("every key defaults");
        assert!(!absent.teleport_have_want, "a file without the key");
        let on: HiveSettings = toml::from_str("teleport_have_want = true").unwrap();
        assert!(on.teleport_have_want);
    }
}

#[cfg(test)]
mod vault_settings_tests {
    use super::{ModulesSettings, VaultSettings};

    /// FR-90 P3-1 — the vault ships OFF and listed as such, and a file that
    /// leaves every key out is a vault with no KEK.
    #[test]
    fn the_vault_is_off_until_turned_on() {
        let m = ModulesSettings::default();
        assert!(!m.vault);
        assert!(ModulesSettings::DEFAULT_OFF.contains(&"vault"));
        assert!(m.switched_off().contains(&"vault"));
        let absent: VaultSettings = toml::from_str("").expect("every key defaults");
        assert!(absent.tenants.is_empty() && absent.kek.is_empty() && absent.kek_file.is_empty());
        // P3-9-1 — and lends to no organization's people.
        assert!(absent.people.is_empty());
    }

    /// ⚠️ The KEK is the vault's root secret: whatever prints settings must
    /// not print it.
    #[test]
    fn the_kek_never_prints() {
        // Not key-shaped on purpose: a secret scanner must not take a test's
        // probe for a leaked key.
        let key = "AGE-SECRET-KEY-1-REDACTION-PROBE-NOT-A-KEY";
        let s = VaultSettings {
            tenants: "65f0000000000000000000a1".into(),
            kek: key.into(),
            kek_file: String::new(),
            revoke_sweep_secs: 0,
            providers: String::new(),
            people: String::new(),
        };
        let shown = format!("{s:?} {s:#?}");
        assert!(!shown.contains(key), "{shown}");
        assert!(!shown.contains("REDACTION-PROBE"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("65f0000000000000000000a1"), "{shown}");
        assert!(format!("{:?}", VaultSettings::default()).contains("<unset>"));
    }
}

#[cfg(test)]
mod growth_settings_tests {
    use super::GrowthSettings;

    /// FR-102 — the digest ships OFF, both where the settings are built whole
    /// and where a file leaves every key out; the routes ship ON; the
    /// recipient list and the hour read the way the hosted config writes them.
    #[test]
    fn the_digest_is_off_and_the_routes_are_on_by_default() {
        let d = GrowthSettings::default();
        assert!(d.enabled);
        assert!(!d.digest_enabled);
        assert_eq!(d.digest_hour(), 6);
        assert!(d.digest_recipients().is_empty());
        assert!(!d.purestat_configured());
        assert_eq!(d.purestat_url, "https://purestat.ai");
        let absent: GrowthSettings = toml::from_str("").expect("every key defaults");
        assert!(!absent.digest_enabled);
        assert!(absent.enabled);
        // P10 — the weekly roll-up and the alerts ship OFF too, and read
        // from a file as they do from the env.
        assert!(!d.weekly_enabled && !d.alerts);
        assert!(!absent.weekly_enabled && !absent.alerts);
        let p10: GrowthSettings = toml::from_str("weekly_enabled = true\nalerts = true").unwrap();
        assert!(p10.weekly_enabled && p10.alerts);
        // P3 — the fetch counters are on unless switched off; the switch
        // reads from a file as it does from the env.
        assert!(d.install_counters && absent.install_counters);
        let off: GrowthSettings = toml::from_str("install_counters = false").unwrap();
        assert!(!off.install_counters);
        // P3c — no internal network unless the operator names one; the
        // list is one string, as it arrives from the env.
        assert!(d.internal_networks.is_empty() && absent.internal_networks.is_empty());
        let lab: GrowthSettings =
            toml::from_str("internal_networks = \"203.0.113.0/24, 2001:db8::/32\"").unwrap();
        assert_eq!(lab.internal_networks, "203.0.113.0/24, 2001:db8::/32");
        // P7 — the GitHub puller reads the hosted repo by default and needs
        // no token for its counters; traffic needs one. A repo that is not
        // `owner/name` switches the puller off rather than build a path.
        assert_eq!(d.github_repo(), Some("gjovanov/roomler-ai"));
        assert_eq!(absent.github_repo(), Some("gjovanov/roomler-ai"));
        assert_eq!(d.github_api_url, "https://api.github.com");
        assert!(!d.github_traffic_configured());
        for bad in [
            "",
            "  ",
            "roomler-ai",
            "/x",
            "x/",
            "a/b/c",
            "a b/c",
            "a/../b",
            "a/..",
            "./b",
        ] {
            let s: GrowthSettings = toml::from_str(&format!("github_repo = {bad:?}")).unwrap();
            assert_eq!(s.github_repo(), None, "{bad:?}");
        }
        let gh: GrowthSettings =
            toml::from_str("github_repo = \" acme/site.io \"\ngithub_token = \"t\"").unwrap();
        assert_eq!(gh.github_repo(), Some("acme/site.io"));
        assert!(gh.github_traffic_configured());
        // P7 — the search pullers: the hosted property and site by default,
        // and nothing configured until a key is set.
        assert_eq!(d.search_console_site, "sc-domain:roomler.ai");
        assert_eq!(d.bing_site_url, "https://roomler.ai/");
        assert!(!d.search_console_configured() && !d.bing_configured());
        assert!(!absent.search_console_configured() && !absent.bing_configured());
        assert!(d.blog_feed_url.is_empty());
        let keyed: GrowthSettings =
            toml::from_str("search_console_key = \"{}\"\nbing_api_key = \"k\"").unwrap();
        assert!(keyed.search_console_configured() && keyed.bing_configured());
        // P3b — the wizard's opt-in diagnostics are accepted unless switched
        // off (the same reason as the counters: the rows are the server's
        // own, opt-in at the source, and name nobody).
        assert!(d.setup_diagnostics && absent.setup_diagnostics);
        let off: GrowthSettings = toml::from_str("setup_diagnostics = false").unwrap();
        assert!(!off.setup_diagnostics);
        let set: GrowthSettings = toml::from_str(
            "digest_enabled = true\ndigest_hour_utc = 7\ndigest_to = \" a@x.test, ,b@x.test \"\npurestat_api_key = \"k\"",
        )
        .unwrap();
        assert!(set.digest_enabled);
        assert_eq!(set.digest_hour(), 7);
        assert_eq!(set.digest_recipients(), vec!["a@x.test", "b@x.test"]);
        assert!(set.purestat_configured());
        let late: GrowthSettings = toml::from_str("digest_hour_utc = 25").unwrap();
        assert_eq!(late.digest_hour(), 6, "out of range reads as the default");
    }
}

#[cfg(test)]
mod relay_cost_file_tests {
    use super::RelayCosts;

    /// The shipped `config/relay-costs.toml` must actually parse into the
    /// struct, with every field populated.
    ///
    /// This exists because a mistyped key there fails *silently and safely*:
    /// serde leaves the field `None`, the surface renders "not priced", and
    /// nothing errors — so the deployment looks configured while quietly
    /// pricing nothing. That is the failure mode most likely to survive
    /// review, since the file reads correctly to a human.
    #[test]
    fn the_shipped_cost_file_parses_with_every_field_set() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/relay-costs.toml");
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{path}: {e} — the file is the single source of prices"));

        #[derive(serde::Deserialize)]
        struct Wrapper {
            relay_costs: RelayCosts,
        }
        let w: Wrapper = toml::from_str(&raw).expect("relay-costs.toml must be valid TOML");
        let c = w.relay_costs;

        assert!(
            c.currency.is_some(),
            "currency unset — figures would render bare"
        );
        assert!(
            c.derp_gb.is_some(),
            "derp_gb unset — the one meter we actually collect"
        );
        assert!(c.turn_gb.is_some(), "turn_gb unset");
        assert!(
            c.sfu_participant_hour.is_some(),
            "sfu_participant_hour unset"
        );
        // A zero cost is indistinguishable on screen from "free to serve", and
        // it is never what an operator means by filling this file in.
        assert!(c.derp_gb.unwrap() > 0.0);
        assert!(c.sfu_participant_hour.unwrap() > 0.0);
    }
}

#[cfg(test)]
mod account_approval_tests {
    use super::*;
    #[test]
    fn account_approval_is_opt_in_without_implicit_owner() {
        let settings = AuthSettings::default();
        assert!(!settings.account_approval.enabled);
        assert!(settings.account_approval.owner_user_id.is_none());
        assert!(settings.reconcile_managed_roles);
    }
}
