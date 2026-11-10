// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 — the Hive wire vocabulary: what the server and a device say ABOUT
//! an agent session, never what is in one.
//!
//! The lifecycle frames (`crate::signaling`): the server's `rc:hive.start`
//! and `rc:hive.stop`, the device's `rc:hive.start_ack`, `rc:hive.state` and
//! `rc:hive.turn`. None of them carries a prompt, a tool argument, a tool
//! output or a line of transcript, and the tests in `signaling` lock their
//! field sets so they cannot grow one: content travels device-to-browser
//! over the viewer peer and device-to-device between replicas, never through
//! the server (`docs/meshharbor-hive-design.md` §3.3).
//!
//! The viewer peer's signalling (P0d-2, `rc:hive.view.*`) is a grant, its
//! answer, and the SDP and ICE of a data-only WebRTC peer — the server relays
//! the handshake and never sees what then flows over the peer.
//!
//! The server pushes a Hive frame only to an agent advertising
//! [`crate::models::RpcCap::Hive`]: a caller is waiting for the answer, and a
//! pre-feature agent drops an unknown tag at `debug!`, which would read as a
//! hang (the `exec` rule).
//!
//! Everything a device REFUSES with is decoded leniently — an unknown word
//! from a newer agent is still a refusal ([`HiveRefusal::Other`]), and an
//! unknown run state is "a state this build cannot name" rather than an error
//! failing the whole frame. The reasons are the same as FR-83's grant ack;
//! see `grant_refusal_lenient` in `signaling`.

use serde::{Deserialize, Deserializer, Serialize};

/// The one harness P0 runs: Claude Code, headless on stream-json.
pub const HARNESS_CLAUDE_CODE: &str = "claude-code";

/// Server-side bounds on the Hive frames. Duplicated by no one: the device
/// reads them from here too, so a clamp cannot drift between the two ends.
pub mod hive_limits {
    /// How long a start request holds its caller for the device's answer.
    /// An ack that arrives later still lands on the record — the caller is
    /// told `starting` and learns the outcome from the session itself.
    pub const START_ACK_TIMEOUT_SECS: u64 = 10;
    /// A `starting` session still unanswered when its device reconnects is
    /// started again on that connection only within this window; past it,
    /// the start is marked `lost` rather than launching a session its owner
    /// may have given up on an hour ago.
    pub const START_REDELIVERY_WINDOW_SECS: i64 = 10 * 60;
    /// Session starts per (user, device) per minute, enforced AFTER the
    /// identity gates so a refusal is attributable (the exec rule).
    pub const START_RATE_PER_MINUTE: u32 = 10;
    /// The folder as typed. The device resolves and confines it; the server
    /// only refuses what no filesystem would accept.
    pub const MAX_FOLDER_LEN: usize = 1024;
    pub const MAX_TITLE_LEN: usize = 200;
    /// A device's `detail` is clamped by the device AND again on receipt.
    pub const MAX_DETAIL_LEN: usize = 512;
    /// FR-90 P1b — entries one `rc:hive.manifest` may carry. A device runs
    /// `hive_max_sessions`, a handful; a longer list is not a device's.
    pub const MAX_MANIFEST: usize = 256;
    /// FR-90 P1e — the most one rendered core-memory document (`CLAUDE.md`,
    /// the auto-memory `MEMORY.md`) may hold in `rc:hive.memory`. The
    /// budgets — 4,500 characters into `CLAUDE.md`, 800 into `MEMORY.md` —
    /// fit with room for headings even at four bytes a character; a larger
    /// one is no snapshot this server rendered, and the device drops it.
    pub const MAX_CORE_MEMORY_BYTES: usize = 32 * 1024;
    /// FR-90 P1j — keys one `rc:hive.adopt` may carry: the `hive_accounts`
    /// keys that map to one account. A handful; a longer list is no
    /// device's.
    pub const MAX_ADOPT_KEYS: usize = 8;
    /// A key as the device holds it: a user id, or an address.
    pub const MAX_ADOPT_KEY_LEN: usize = 320;
    /// The device's id for one offer, echoed by the ack.
    pub const MAX_ADOPT_ID_LEN: usize = 64;
    /// The local account name, as the device reports it.
    pub const MAX_ACCOUNT_LEN: usize = 64;
    /// Live adopted sessions one device may hold.
    pub const MAX_ADOPTED_PER_DEVICE: usize = 16;
    /// Adopt offers per device per minute — a terminal session is offered
    /// once, so more is a device in a loop or one that lies.
    pub const ADOPT_RATE_PER_MINUTE: u32 = 20;
}

/// FR-90 P1b — one session a device runs, in `rc:hive.manifest`: its id and
/// fence, nothing more.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiveManifestEntry {
    #[serde(with = "crate::serde_helpers::oid_hex")]
    pub session_id: bson::oid::ObjectId,
    pub fence: u64,
}

/// FR-90 P0d-2 — bounds on a viewer peer, read by both ends.
pub mod view_limits {
    /// A view grant's life, sent as a RELATIVE `ttl_secs` so the device sets
    /// its own deadline on receipt — a device whose clock is off must not
    /// refuse every grant, nor keep one past its time. The browser renews at
    /// half-life while the room is open, and the server re-checks the
    /// viewer's right to read on every renewal: a member taken out of the
    /// room loses the view within this bound.
    pub const GRANT_TTL_SECS: u32 = 10 * 60;
    /// How long the server waits for the device to confirm a grant before it
    /// tells the browser no. The browser dials only after the device said
    /// yes (FR-83).
    pub const GRANT_ACK_TIMEOUT_SECS: u64 = 10;
    /// Viewer peers one device serves at once.
    pub const MAX_PER_DEVICE: usize = 32;
    /// Viewer peers one session has at once.
    pub const MAX_PER_SESSION: usize = 8;
    /// View opens per (user, session) per minute, after the identity gates.
    pub const OPEN_RATE_PER_MINUTE: u32 = 20;
}

/// FR-90 P2i — full-text search over an archive replica's copies, through a
/// search grant's viewer peer. The query and what it finds travel only over
/// the peer; these bound what the peer carries and what a device serves.
pub mod search_limits {
    /// The most sessions one grant names: the store's own bound on a search
    /// filter (`meshharbor_hive_node::store::MAX_SEARCH_SESSIONS`).
    pub const MAX_SESSIONS: usize = 500;
    /// The longest query, in characters. It is taken as plain words.
    pub const MAX_QUERY_CHARS: usize = 200;
    /// The most hits one search answers, and how many when it does not say.
    pub const MAX_HITS: usize = 50;
    pub const DEFAULT_HITS: usize = 20;
    /// How soon after one search a grant may ask the next: the store's one
    /// writer answers every search, and a typing viewer must not crowd out
    /// the copies it is meant to search.
    pub const MIN_INTERVAL_MS: u64 = 250;
    /// Search grants one device serves at once, within its viewers
    /// ([`super::view_limits::MAX_PER_DEVICE`]).
    pub const MAX_PER_DEVICE: usize = 8;
    /// FR-90 P2i-2 — search opens per (user, organization) per minute, after
    /// the identity gates. A grant serves many searches; an open is the
    /// server's read of what the person may search, and is paced as a view's.
    pub const OPEN_RATE_PER_MINUTE: u32 = 20;
}

/// Why a device refused a view grant, carried in `rc:hive.view.grant_ack`.
/// Absent = the device holds the session and will answer the viewer's offer.
///
/// ⚠️ Decoded LENIENTLY, like [`HiveRefusal`]: an unknown word is
/// [`Self::Other`], still a refusal — never "the browser may dial".
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveViewRefusal {
    /// The device's own `hive_enabled` is off.
    HiveDisabled,
    /// The device holds no transcript of this session — it never ran it, or
    /// its store was lost.
    NoSession,
    /// [`view_limits::MAX_PER_DEVICE`] or [`view_limits::MAX_PER_SESSION`].
    AtCapacity,
    /// A word this build does not know.
    Other,
}

impl HiveViewRefusal {
    /// The spelling on the wire. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HiveDisabled => "hive_disabled",
            Self::NoSession => "no_session",
            Self::AtCapacity => "at_capacity",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveViewRefusal; 4] = [
        Self::HiveDisabled,
        Self::NoSession,
        Self::AtCapacity,
        Self::Other,
    ];
}

/// Why a device refused `rc:hive.start`, carried in `rc:hive.start_ack`.
///
/// Absent from the ack = ACCEPTED: the device passed its own gates and is
/// launching the harness; what happens next arrives as `rc:hive.state`.
/// Present = no session runs, and the word says which of the device's gates
/// said no — each one has a different fix, which is why they are not folded.
///
/// ⚠️ Decoded LENIENTLY ([`refusal_lenient`]): an unknown word lands on
/// [`Self::Other`], still a refusal. It must never land on "accepted" — that
/// would show a session as starting on a device that has just said no.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveRefusal {
    /// Gate 4 — the device's own `hive_enabled` is off (the default).
    HiveDisabled,
    /// `hive_accounts` maps no local account to the starting user. Never a
    /// fallback to the daemon's own identity, which is SYSTEM/root.
    NoAccount,
    /// Windows: nobody is signed in at the console, so there is no account a
    /// session could run as (design D2 — no S4U, no stored credentials).
    NoConsoleUser,
    /// The folder does not resolve under a `hive_roots` entry, or
    /// `hive_roots` is empty — which means nowhere, never anywhere.
    FolderNotAllowed,
    /// The harness is not installed where the mapped account can run it.
    HarnessMissing,
    /// The harness was found but did not start.
    LaunchFailed,
    /// The device already runs `hive_max_sessions` sessions.
    AtCapacity,
    /// FR-90 decision 15 — macOS: the account the session would run as may
    /// use `sudo` without a password, and the device's own
    /// `hive_allow_passwordless_sudo` is off. A Mac's `sudo` reads the
    /// account's groups from the directory, so no group a session drops can
    /// stop it, and the session would have root.
    PasswordlessSudo,
    /// FR-90 P2f-2d — a teleport's folder holds work of its own: a repository
    /// whose folder is neither what its `HEAD` holds nor what this session
    /// last left there, or a folder in no repository that holds files. The
    /// copy would be refused there only after the lease moved; the detail
    /// names a sibling folder the session could go to instead.
    FolderDirty,
    /// A word this build does not know.
    Other,
}

impl HiveRefusal {
    /// The spelling on the wire and in the session record. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HiveDisabled => "hive_disabled",
            Self::NoAccount => "no_account",
            Self::NoConsoleUser => "no_console_user",
            Self::FolderNotAllowed => "folder_not_allowed",
            Self::HarnessMissing => "harness_missing",
            Self::LaunchFailed => "launch_failed",
            Self::AtCapacity => "at_capacity",
            Self::PasswordlessSudo => "passwordless_sudo",
            Self::FolderDirty => "folder_dirty",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveRefusal; 10] = [
        Self::HiveDisabled,
        Self::NoAccount,
        Self::NoConsoleUser,
        Self::FolderNotAllowed,
        Self::HarnessMissing,
        Self::LaunchFailed,
        Self::AtCapacity,
        Self::PasswordlessSudo,
        Self::FolderDirty,
        Self::Other,
    ];
}

/// FR-90 P1j — why the server did not adopt a terminal session, carried in
/// `rc:hive.adopt_ack`. Absent = adopted: the record exists and the device
/// mirrors the session.
///
/// ⚠️ Decoded LENIENTLY ([`adopt_refusal_lenient`]): an unknown word is
/// [`Self::Other`], still a refusal — never "adopted", which would have the
/// device mirror a terminal into a session nobody has a record of.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveAdoptRefusal {
    /// The device's organization is not one agent sessions serve
    /// (`hive.tenants`, P1g).
    HiveNotEnabled,
    /// No key the device sent names an account that exists here.
    NoAccount,
    /// The keys name two or more people: the account is shared, so whose
    /// terminal this is cannot be known, and it is never guessed.
    AmbiguousAccount,
    /// The one person the keys name is not a member of the device's org.
    NotAMember,
    /// The device already holds [`hive_limits::MAX_ADOPTED_PER_DEVICE`].
    AtCapacity,
    /// More than [`hive_limits::ADOPT_RATE_PER_MINUTE`] offers.
    RateLimited,
    /// A word this build does not know.
    Other,
}

impl HiveAdoptRefusal {
    /// The spelling on the wire and in `hive_audit`. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HiveNotEnabled => "hive_not_enabled",
            Self::NoAccount => "no_account",
            Self::AmbiguousAccount => "ambiguous_account",
            Self::NotAMember => "not_a_member",
            Self::AtCapacity => "at_capacity",
            Self::RateLimited => "rate_limited",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveAdoptRefusal; 7] = [
        Self::HiveNotEnabled,
        Self::NoAccount,
        Self::AmbiguousAccount,
        Self::NotAMember,
        Self::AtCapacity,
        Self::RateLimited,
        Self::Other,
    ];
}

/// Lenient decoder for `rc:hive.adopt_ack`'s `refused`, as
/// [`refusal_lenient`]: only absent or `null` means adopted.
pub(crate) fn adopt_refusal_lenient<'de, D>(de: D) -> Result<Option<HiveAdoptRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveAdoptRefusal::Other));
    };
    Ok(Some(
        HiveAdoptRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveAdoptRefusal::Other),
    ))
}

/// Where a running session is, as its device reports it in `rc:hive.state`.
/// The server's record mirrors it; nothing here says what the session is
/// doing, only whether it is.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveRunState {
    /// The harness is up and waiting for a prompt.
    Idle,
    /// A turn is running.
    Running,
    /// A tool call is waiting for a person's answer.
    AwaitingApproval,
    /// The harness exited and the session is over on this device — stopped,
    /// finished, or crashed (`detail` says which).
    Ended,
}

impl HiveRunState {
    /// The spelling on the wire and in the session record. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Ended => "ended",
        }
    }
}

/// How a turn stands, as its device reports it in `rc:hive.turn`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveTurnStatus {
    /// A prompt went in; the turn is under way.
    Running,
    /// The turn finished.
    Ok,
    /// The turn finished with an error (the harness's own `is_error`).
    Error,
    /// The harness stopped mid-turn — a stop, a crash, a daemon restart.
    Interrupted,
}

impl HiveTurnStatus {
    /// The spelling on the wire. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Interrupted => "interrupted",
        }
    }
}

/// FR-90 P1a-2 — how an approval stands, as its device reports it in
/// `rc:hive.approval`. Which tool and what it would do are not here and
/// cannot be: they travel device-to-browser over the viewer peer.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveApprovalStatus {
    /// Waiting for a driver.
    Open,
    /// A driver allowed it.
    Allowed,
    /// A driver denied it.
    Denied,
    /// Nobody answered in time.
    Expired,
    /// The harness let go, or the session ended, first.
    Withdrawn,
}

impl HiveApprovalStatus {
    /// The spelling on the wire and in `agent_approvals`. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveApprovalStatus; 5] = [
        Self::Open,
        Self::Allowed,
        Self::Denied,
        Self::Expired,
        Self::Withdrawn,
    ];
}

/// Lenient decoder for `rc:hive.approval`'s `status`, as
/// [`turn_status_lenient`]: a word this build cannot name is `None`, and the
/// stub keeps what it said.
pub(crate) fn approval_status_lenient<'de, D>(de: D) -> Result<Option<HiveApprovalStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(None);
    };
    Ok(HiveApprovalStatus::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .ok())
}

/// Lenient decoder for `rc:hive.start_ack`'s `refused`. Only an absent or
/// `null` value means accepted; anything present that is not a known word —
/// an unknown string, a number, an object from some future shape — is
/// [`HiveRefusal::Other`].
pub(crate) fn refusal_lenient<'de, D>(de: D) -> Result<Option<HiveRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveRefusal::Other));
    };
    // Re-parse through the derive so the spellings live in exactly one place.
    Ok(Some(
        HiveRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveRefusal::Other),
    ))
}

/// Lenient decoder for `rc:hive.view.grant_ack`'s `refused`, as
/// [`refusal_lenient`]: only absent or `null` lets the browser dial.
pub(crate) fn view_refusal_lenient<'de, D>(de: D) -> Result<Option<HiveViewRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveViewRefusal::Other));
    };
    Ok(Some(
        HiveViewRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveViewRefusal::Other),
    ))
}

/// Lenient decoder for `rc:hive.state`'s `state`: a state this build cannot
/// name is `None` — the server keeps what it knew and logs the word — rather
/// than a hard error that would drop the frame and every later one shaped
/// like it.
pub(crate) fn run_state_lenient<'de, D>(de: D) -> Result<Option<HiveRunState>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(None);
    };
    Ok(HiveRunState::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .ok())
}

/// Lenient decoder for `rc:hive.turn`'s `status`, as [`run_state_lenient`]:
/// a status this build cannot name is `None`, and the stub keeps what it said.
pub(crate) fn turn_status_lenient<'de, D>(de: D) -> Result<Option<HiveTurnStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(None);
    };
    Ok(HiveTurnStatus::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .ok())
}

/// FR-90 P2c-3 — bounds on the replica frames (`rc:hive.replica.*`), read by
/// both ends.
pub mod replica_limits {
    /// Sessions one `rc:hive.replica.manifest` may carry. An archive replica
    /// holds every session the rules give it for the retention, so this is
    /// far above [`super::hive_limits::MAX_MANIFEST`]; a device that holds
    /// more sends its newest first.
    pub const MAX_REPLICA_MANIFEST: usize = 4096;
    /// A member reports a session's tip at most this often, and again at
    /// each checkpoint.
    pub const TIP_INTERVAL_SECS: u64 = 5;
    /// A hash on the replica frames: BLAKE3, as lowercase hex.
    pub const HASH_HEX_LEN: usize = 64;
    /// FR-90 P2e-5b — the most fence marks one `rc:hive.replica.join`
    /// carries: one per fence a promotion superseded. A join with more is
    /// refused whole by the device, never taken in part.
    pub const MAX_FENCE_MARKS: usize = 256;
}

/// Whether `s` is a hash as the replica frames carry it: exactly
/// [`replica_limits::HASH_HEX_LEN`] lowercase hex characters. Anything else
/// from a device is dropped, never stored.
pub fn is_hash_hex(s: &str) -> bool {
    s.len() == replica_limits::HASH_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// FR-90 P2c-3 — why a device is asked to hold a copy of a session, in
/// `rc:hive.replica.join`: the role placement chose for it. The device checks
/// its own gate for each: `hive_replica` for a member, `hive_archive` as well
/// for an archive, for the primary that it runs the session at that fence,
/// and for a teleport that it passed the session's teleport prepare.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveReplicaRole {
    /// An archive replica an `ADMINISTRATOR` designated.
    Archive,
    /// One of the session owner's own devices.
    Owner,
    /// P2c-4 — the device that runs the session: it has members now, so it
    /// takes a checkpoint at each turn's end from here on, as a start with
    /// `replicated` would have had it do. Sent to a session that gained its
    /// first member after it started, over the connection that runs it.
    /// P2f-1a — the device takes its first checkpoint at once when no turn
    /// runs, and says where its copy ends either way: how far a member that
    /// joins now has to catch up.
    Primary,
    /// P2f-1a — the device the session's owner is moving the session to,
    /// which holds no copy of it yet: it takes one to run the session there.
    /// The device admits it only after its own gates passed a
    /// [`crate::signaling::ServerMsg::HivePrepare`] with `teleport` for the
    /// session, whatever its `hive_replica`: a device that will RUN a session
    /// needs `hive_enabled`, not `hive_replica`.
    Teleport,
}

impl HiveReplicaRole {
    /// The spelling on the wire. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Owner => "owner",
            Self::Primary => "primary",
            Self::Teleport => "teleport",
        }
    }

    /// Every role this build knows.
    pub const ALL: [HiveReplicaRole; 4] =
        [Self::Archive, Self::Owner, Self::Primary, Self::Teleport];
}

/// Lenient decoder for `rc:hive.replica.join`'s `role`: a role this build
/// cannot name is `None`, so the device still reads the frame and refuses it
/// (`other`) instead of dropping it unanswered.
pub(crate) fn replica_role_lenient<'de, D>(de: D) -> Result<Option<HiveReplicaRole>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(None);
    };
    Ok(HiveReplicaRole::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .ok())
}

/// FR-90 P2c-3 — why a device refused `rc:hive.replica.join`, carried in
/// `rc:hive.replica.join_ack`. Absent = the device holds the session now: its
/// floor for it is at the join's fence, and it takes the copy when the
/// carrier brings it (P2d). Each word names a different gate with a
/// different fix, so none is folded into another.
///
/// ⚠️ Decoded LENIENTLY ([`join_refusal_lenient`]): an unknown word is
/// [`Self::Other`], still a refusal. It must never land on "joined": that
/// would count a copy on a device that has just said no.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveJoinRefusal {
    /// The device's own `hive_replica` is off.
    ReplicaDisabled,
    /// Asked as an archive replica, and the device's own `hive_archive` is
    /// off.
    ArchiveDisabled,
    /// The join came on a secondary org's connection: a device holds copies
    /// only for its primary org.
    SecondaryOrg,
    /// The device purged this session. Removal is final.
    Purged,
    /// The join's fence is older than the floor the device holds for it.
    StaleFence,
    /// The device's store is at its `hive_store_quota_mib`.
    Quota,
    /// P2f-1a — a teleport's join for a session no teleport prepare passed
    /// here: the gates that let a device RUN the session (its account, its
    /// folder, `hive_enabled`) are the prepare's, and they were not asked.
    NotPrepared,
    /// A word this build does not know, or a role it cannot name.
    Other,
}

impl HiveJoinRefusal {
    /// The spelling on the wire and in the session record. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplicaDisabled => "replica_disabled",
            Self::ArchiveDisabled => "archive_disabled",
            Self::SecondaryOrg => "secondary_org",
            Self::Purged => "purged",
            Self::StaleFence => "stale_fence",
            Self::Quota => "quota",
            Self::NotPrepared => "not_prepared",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveJoinRefusal; 8] = [
        Self::ReplicaDisabled,
        Self::ArchiveDisabled,
        Self::SecondaryOrg,
        Self::Purged,
        Self::StaleFence,
        Self::Quota,
        Self::NotPrepared,
        Self::Other,
    ];
}

/// Lenient decoder for `rc:hive.replica.join_ack`'s `refused`, as
/// [`refusal_lenient`]: only absent or `null` means joined.
pub(crate) fn join_refusal_lenient<'de, D>(de: D) -> Result<Option<HiveJoinRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveJoinRefusal::Other));
    };
    Ok(Some(
        HiveJoinRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveJoinRefusal::Other),
    ))
}

/// FR-90 P2e-5b — where a fence a promotion superseded ended: the `seq` of
/// the last event written at `fence`, and that event's hash. A member whose
/// floor rose past `fence` still takes that fence's events up to here, and
/// at `seq` only the event whose hash this is.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveFenceMark {
    pub fence: u64,
    pub seq: u64,
    pub hash: String,
}

/// FR-90 P2e-6a — where a device's copy of a session ends, as its
/// `rc:hive.prepare_ack` says it: the fence of its newest event, its `seq`,
/// and its hash. A promotion away from an unreachable primary moves the
/// lease to exactly this.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveCopyTip {
    pub fence: u64,
    pub seq: u64,
    pub hash: String,
}

/// FR-90 P2c-3 — a checkpoint a member holds: the `seq` of its `checkpoint`
/// event, and that event's hash.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveCheckpointMark {
    pub seq: u64,
    pub hash: String,
}

/// FR-90 P2f-3 — the session a fork was made from, as every start of the
/// fork carries it: its record's id, whose copy a device takes the fork from
/// at the fork's first start, and its harness session, which that start
/// resumes from (`--resume <it> --fork-session`) and whose history and tool
/// results the fork's own checkpoints keep beside its own.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveForkOf {
    #[serde(with = "crate::serde_helpers::oid_hex")]
    pub session_id: bson::oid::ObjectId,
    pub harness_session: String,
}

/// FR-90 P2f-5 — a place a session ran before, as `rc:hive.move` names it:
/// the device's name and the folder, as the record holds them. Its old turns
/// keep the paths they had there.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HivePlace {
    pub device_name: String,
    pub folder: String,
}

/// FR-90 P2c-3 — one session a device holds a copy of, in
/// `rc:hive.replica.manifest`: where its copy ends. Numbers and hashes only.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveReplicaManifestEntry {
    #[serde(with = "crate::serde_helpers::oid_hex")]
    pub session_id: bson::oid::ObjectId,
    /// The fence of the event at `seq`.
    pub fence: u64,
    pub seq: u64,
    /// That event's hash.
    pub hash: String,
    /// The newest checkpoint the copy holds, when it holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<HiveCheckpointMark>,
}

/// FR-90 P2g-3c — what keeps a device's copy of a session, as
/// `rc:hive.retain` says it: the organization's `retention_days`, and the
/// session's end once it is over. The device's own clock does the rest. The
/// copy of a session that is over goes `days` after its end, online or not,
/// when the server's retention sweep would purge it. The copy of a live one
/// goes `days` after the device last heard from the server, so a device that
/// misses a purge by staying offline keeps it no longer than that (design
/// §4.4).
///
/// ⚠️ Days and an end, never an instant. An instant for a live session would
/// have to be renewed for as long as the session lives, and a server that
/// stopped renewing it (a bug, the switch off) would have every member delete
/// every live session's copy. A device that hears nothing keeps what it holds.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveRetainWord {
    #[serde(with = "crate::serde_helpers::oid_hex")]
    pub session_id: bson::oid::ObjectId,
    /// The organization's `retention_days`; `0` keeps the session for ever.
    pub days: u32,
    /// When the session ended, in ms since the epoch, as the sweep counts it
    /// (its `ended_at`, else its last update): only once it is over
    /// (`ended`, `refused`, `lost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<i64>,
}

/// FR-90 P2g-3c — a copy the device purged on its own clock, as its
/// `rc:hive.replica.manifest` says so: the session, and when, by the device's
/// clock. The server stops counting it as a copy held there.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HiveCopyPurged {
    #[serde(with = "crate::serde_helpers::oid_hex")]
    pub session_id: bson::oid::ObjectId,
    pub at_ms: i64,
}

/// FR-90 P2g-3c — bounds on the retention word's frames
/// (`rc:hive.retain_ask` · `rc:hive.retain`) and on what a manifest says the
/// device's own clock purged, read by both ends.
pub mod retain_limits {
    /// Sessions one `rc:hive.retain_ask` may name: as many as a replica
    /// manifest carries. A longer ask is no device's, and is answered with
    /// nothing.
    pub const MAX_RETAIN_ASK: usize = super::replica_limits::MAX_REPLICA_MANIFEST;
    /// Copies purged on the device's own clock one manifest may name.
    pub const MAX_COPY_PURGED: usize = 1024;
    /// How often a device that stays connected asks again: a policy changed
    /// meanwhile, or a session that ended, reaches it within a day.
    pub const RETAIN_ASK_EVERY_SECS: u64 = 24 * 60 * 60;
    /// How many manifests name a copy the device purged on its own clock:
    /// one could be lost with the connection it went on.
    pub const COPY_PURGED_REPORTS: u32 = 3;
}

/// FR-90 P2d — bounds on the replica stream's frames
/// (`rc:hive.replica.want` · `grant` · `ready` · `dial` · `candidate` ·
/// `refused` · `close`), read by both ends.
pub mod stream_limits {
    /// A stream grant's life, sent as a RELATIVE `ttl_secs`, so a device
    /// whose clock is off neither refuses every grant nor keeps one past its
    /// time. A member renews at half-life while it follows, from the top of
    /// the ladder again (P2d-4).
    pub const GRANT_TTL_SECS: u32 = 10 * 60;
    /// How long the server waits for the source's `ready` before it tells
    /// the member no. A relay's allocation alone can take ~20 s on a
    /// UDP-hostile network (#1761), so this is above the view's 10 s.
    pub const GRANT_ACK_TIMEOUT_SECS: u64 = 30;
    /// Grants one member holds for one session at once: the one it follows,
    /// and the renewal that replaces it once it carries (make-before-break).
    pub const MAX_PER_MEMBER_SESSION: usize = 2;
    /// Streams one source serves at once.
    pub const MAX_PER_SOURCE: usize = 32;
    /// Wants per (member, session) per minute, after the identity gates:
    /// three rungs and a renewal, with room to spare.
    pub const WANT_RATE_PER_MINUTE: u32 = 12;
    /// Addresses one `ready` may offer, and the longest of them.
    pub const MAX_ADDRS: usize = 8;
    pub const MAX_ADDR_LEN: usize = 64;
    /// A WireGuard key, which addresses a device on DERP: lowercase hex.
    pub const PUBKEY_HEX_LEN: usize = 64;
}

/// Whether `s` is a WireGuard key as the stream frames carry it: exactly
/// [`stream_limits::PUBKEY_HEX_LEN`] lowercase hex characters.
pub fn is_pubkey_hex(s: &str) -> bool {
    s.len() == stream_limits::PUBKEY_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `addr` is one a device could be reached at over a stream: never
/// the unspecified address, port 0, multicast or broadcast. Read by both
/// ends: the server, of each address a `ready` offers and each `candidate`
/// it relays, and the device, of each address it dials or permits. The
/// addresses travel between two devices through the server, and a device
/// dials as SYSTEM or root, so a multicast address relayed to every member
/// of a tenant would have each of them spray its own network; the device's
/// check is the one that holds against a compromised server or source.
pub fn is_dialable(addr: &std::net::SocketAddr) -> bool {
    let ip = addr.ip();
    addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast())
}

/// FR-90 P2d — the rung of the ladder a replica stream tries (spec §3b, "The
/// carrier"). The member names one in each `rc:hive.replica.want`, from the
/// top, and climbs down a rung when one does not carry. Every renewal starts
/// from the top again, so a member that fell to a relay is back on a direct
/// path at the first renewal that finds one: never ratchet.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveStreamPath {
    /// QUIC between the two devices' own sockets: host and server-reflexive
    /// candidates, hole-punched. There is no relay to see anything.
    Direct,
    /// QUIC through a TURN relay, over UDP or TURNS on TCP 443, with the
    /// grant's credentials. The relay sees QUIC packets: ciphertext.
    Relay,
    /// `quic-derp-v1`: QUIC framed over each device's established `/derp`
    /// WebSocket, addressed by WireGuard key. Both must be overlay nodes.
    Derp,
}

impl HiveStreamPath {
    /// The spelling on the wire. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Derp => "derp",
        }
    }

    /// Every rung this build knows, from the top.
    pub const ALL: [HiveStreamPath; 3] = [Self::Direct, Self::Relay, Self::Derp];
}

/// Lenient decoder for a stream frame's `path`: a rung this build cannot
/// name is `None`, so the frame still decodes and is refused in words,
/// never dropped unanswered.
pub(crate) fn stream_path_lenient<'de, D>(de: D) -> Result<Option<HiveStreamPath>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(None);
    };
    Ok(HiveStreamPath::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .ok())
}

/// FR-90 P2d — why a member gets no stream this time: the server's word in
/// `rc:hive.replica.refused`, or the source's, in `rc:hive.replica.ready`
/// and relayed. Each names a different gate with a different fix.
///
/// ⚠️ Decoded LENIENTLY ([`stream_refusal_lenient`]): an unknown word is
/// [`Self::Other`], still a refusal. It must never land on "ready": the
/// member would dial a source that has just said no.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveStreamRefusal {
    /// The asking device is not a joined member of the session.
    NotAMember,
    /// The want named another fence than the session's.
    StaleFence,
    /// The source is not connected here.
    SourceOffline,
    /// The source's build carries no replica stream (`hive-stream`).
    SourceUnsupported,
    /// The rung cannot be had: a relay where no TURN server is configured,
    /// DERP without both devices' keys, or a rung this build cannot name.
    PathUnavailable,
    /// Too many wants from this member for this session.
    RateLimited,
    /// The source serves as many streams as it may.
    Busy,
    /// The source does not hold the session it was asked to serve.
    NotHeld,
    /// The source did not answer in time.
    NoAnswer,
    /// A word this build does not know.
    Other,
}

impl HiveStreamRefusal {
    /// The spelling on the wire and in the audit. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAMember => "not_a_member",
            Self::StaleFence => "stale_fence",
            Self::SourceOffline => "source_offline",
            Self::SourceUnsupported => "source_unsupported",
            Self::PathUnavailable => "path_unavailable",
            Self::RateLimited => "rate_limited",
            Self::Busy => "busy",
            Self::NotHeld => "not_held",
            Self::NoAnswer => "no_answer",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveStreamRefusal; 10] = [
        Self::NotAMember,
        Self::StaleFence,
        Self::SourceOffline,
        Self::SourceUnsupported,
        Self::PathUnavailable,
        Self::RateLimited,
        Self::Busy,
        Self::NotHeld,
        Self::NoAnswer,
        Self::Other,
    ];
}

/// Lenient decoder for a stream refusal: present and not a known word is
/// [`HiveStreamRefusal::Other`], never "ready"; absent or `null` is `None`.
pub(crate) fn stream_refusal_lenient<'de, D>(de: D) -> Result<Option<HiveStreamRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveStreamRefusal::Other));
    };
    Ok(Some(
        HiveStreamRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveStreamRefusal::Other),
    ))
}

/// FR-90 P2e-3 — bounds on a promotion's frames (`rc:hive.prepare` · `drain`
/// · `drained` · `move`), read by both ends.
pub mod promote_limits {
    /// How long a drained primary lets the running turn go on before it cuts
    /// it. The server waits this long for `rc:hive.drained`, and a margin for
    /// the last checkpoint after it.
    pub const DRAIN_TURN_CUT_SECS: u64 = 60;

    /// FR-90 P2e-6a — how long a primary must have been unreachable, its
    /// control connection gone and no heartbeat heard, before its session is
    /// moved away from it with no drain: the device's own receive deadline
    /// (80 s), then the grace its sidecar serves model calls for after it
    /// last heard from the server (120 s), and a margin (30 s). By then the
    /// device makes no model call, whatever it still runs. ⚠️ Couples to
    /// `WS_RX_DEADLINE` and `OFFLINE_GRACE` in `meshharbord`: a test there holds
    /// this to their sum.
    pub const UNREACHABLE_SECS: u64 = 80 + 120 + 30;

    /// FR-90 P2f-1a — how long a device admits a teleport's join after its
    /// teleport prepare passed: the join comes right behind the prepare's
    /// answer, and again at each connection until the device answers it.
    /// ⚠️ The server's wait for the target's copy (`hive.promote_join_secs`)
    /// must stay under it, or a join re-sent late is refused `not_prepared`.
    pub const TELEPORT_ADMISSION_SECS: u64 = 30 * 60;

    /// FR-90 P2f-5 — the most earlier places one `rc:hive.move` names, the
    /// newest, one per folder. The record's path map is bounded by the fence
    /// marks' bound; this bounds the frame.
    pub const MAX_EARLIER_PLACES: usize = 16;
}

/// FR-90 P2e-3 — why a primary did not drain a session, carried in
/// `rc:hive.drained`. Absent = drained: it takes no new prompt, its turn has
/// ended, and its copy ends at the tip the frame names. Each word names a
/// different cause, so none is folded into another.
///
/// ⚠️ Decoded LENIENTLY ([`drain_refusal_lenient`]): an unknown word is
/// [`Self::Other`], still a refusal. It must never land on "drained": that
/// would move the lease off a primary whose copy may end past the tip the
/// server waits for.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HiveDrainRefusal {
    /// The device does not run the session at the drain's fence.
    NotRunning,
    /// A word this build does not know.
    Other,
}

impl HiveDrainRefusal {
    /// The spelling on the wire, in the audit and in the room. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRunning => "not_running",
            Self::Other => "other",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HiveDrainRefusal; 2] = [Self::NotRunning, Self::Other];
}

/// Lenient decoder for `rc:hive.drained`'s `refused`, as
/// [`refusal_lenient`]: only absent or `null` means drained.
pub(crate) fn drain_refusal_lenient<'de, D>(de: D) -> Result<Option<HiveDrainRefusal>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(word) = raw else {
        return Ok(Some(HiveDrainRefusal::Other));
    };
    Ok(Some(
        HiveDrainRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
        )
        .unwrap_or(HiveDrainRefusal::Other),
    ))
}

/// FR-90 P2g — how one part of a purge went on a device, as its
/// `rc:hive.purge_ack` says it: the daemon's own copy (`store`), or what the
/// session's account holds of it (`account`). Each word has its own fix, so
/// none is folded into another: a part `failed` stays pending at the server,
/// its reason with it, and the purge is sent again.
///
/// ⚠️ Decoded LENIENTLY ([`purge_part_lenient`]): an unknown word is
/// [`Self::Failed`]. It must never read as done: a purge would be complete
/// on a word this server does not know, and the copy kept.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HivePurgePart {
    /// Deleted, now or by an earlier delivery of the same purge.
    Done,
    /// The device held nothing of it there.
    NotThere,
    /// It could not be deleted; why is the acknowledgement's `detail`.
    Failed,
}

impl HivePurgePart {
    /// The spelling on the wire and in the audit. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::NotThere => "not_there",
            Self::Failed => "failed",
        }
    }

    /// Every word this build knows.
    pub const ALL: [HivePurgePart; 3] = [Self::Done, Self::NotThere, Self::Failed];

    /// Whether the part needs nothing more from the device.
    pub const fn closed(self) -> bool {
        !matches!(self, Self::Failed)
    }
}

/// Lenient decoder for a purge part: a word this build does not know, or no
/// word at all, is [`HivePurgePart::Failed`].
pub(crate) fn purge_part_lenient<'de, D>(de: D) -> Result<HivePurgePart, D::Error>
where
    D: Deserializer<'de>,
{
    let serde_json::Value::String(word) = serde_json::Value::deserialize(de)? else {
        return Ok(HivePurgePart::Failed);
    };
    Ok(HivePurgePart::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(word.as_str()),
    )
    .unwrap_or(HivePurgePart::Failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WIRE LOCK — FR-90 P2g: the purge's part words; a word a newer device
    /// sends, or none, is `failed`, never `done`: a purge must not read as
    /// complete on a word this build does not know.
    #[test]
    fn purge_part_words_are_locked_and_an_unknown_one_is_failed() {
        let words: Vec<&str> = HivePurgePart::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(words, ["done", "not_there", "failed"]);
        for p in HivePurgePart::ALL {
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                serde_json::Value::String(p.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct A {
            #[serde(deserialize_with = "purge_part_lenient")]
            store: HivePurgePart,
        }
        let a = |j: &str| serde_json::from_str::<A>(j).unwrap().store;
        assert_eq!(a(r#"{"store":"done"}"#), HivePurgePart::Done);
        assert_eq!(a(r#"{"store":"not_there"}"#), HivePurgePart::NotThere);
        assert_eq!(a(r#"{"store":"vanished"}"#), HivePurgePart::Failed);
        assert_eq!(a(r#"{"store":7}"#), HivePurgePart::Failed);
        assert_eq!(a(r#"{"store":null}"#), HivePurgePart::Failed);
        assert!(HivePurgePart::Done.closed() && HivePurgePart::NotThere.closed());
        assert!(!HivePurgePart::Failed.closed());
    }

    /// WIRE LOCK — the approval words, and a newer device's word is unnamed,
    /// never an error that drops the frame.
    #[test]
    fn approval_status_words_are_locked_and_unknown_ones_are_unnamed() {
        let words: Vec<&str> = HiveApprovalStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(words, ["open", "allowed", "denied", "expired", "withdrawn"]);
        for s in HiveApprovalStatus::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::Value::String(s.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct A {
            #[serde(default, deserialize_with = "approval_status_lenient")]
            status: Option<HiveApprovalStatus>,
        }
        let a = |j: &str| serde_json::from_str::<A>(j).unwrap().status;
        assert_eq!(a(r#"{"status":"open"}"#), Some(HiveApprovalStatus::Open));
        assert_eq!(a(r#"{"status":"delegated"}"#), None);
        assert_eq!(a(r#"{"status":1}"#), None);
        assert_eq!(a("{}"), None);
    }

    #[test]
    fn turn_status_words_are_locked_and_unknown_ones_are_unnamed() {
        for (s, w) in [
            (HiveTurnStatus::Running, "running"),
            (HiveTurnStatus::Ok, "ok"),
            (HiveTurnStatus::Error, "error"),
            (HiveTurnStatus::Interrupted, "interrupted"),
        ] {
            assert_eq!(s.as_str(), w);
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(w));
        }
        #[derive(Deserialize)]
        struct T {
            #[serde(default, deserialize_with = "turn_status_lenient")]
            status: Option<HiveTurnStatus>,
        }
        let t = |j: &str| serde_json::from_str::<T>(j).unwrap().status;
        assert_eq!(t(r#"{"status":"ok"}"#), Some(HiveTurnStatus::Ok));
        assert_eq!(t(r#"{"status":"paused"}"#), None);
        assert_eq!(t("{}"), None);
    }

    /// WIRE LOCK — what a device sends and what the record stores. Spelled
    /// out literally so a rename has to be a deliberate edit here.
    #[test]
    fn refusal_words_are_locked_and_match_serde() {
        let words: Vec<&str> = HiveRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "hive_disabled",
                "no_account",
                "no_console_user",
                "folder_not_allowed",
                "harness_missing",
                "launch_failed",
                "at_capacity",
                "passwordless_sudo",
                "folder_dirty",
                "other",
            ]
        );
        for r in HiveRefusal::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().into()),
                "{r:?}"
            );
        }
    }

    #[test]
    fn run_state_words_are_locked_and_match_serde() {
        for (s, w) in [
            (HiveRunState::Idle, "idle"),
            (HiveRunState::Running, "running"),
            (HiveRunState::AwaitingApproval, "awaiting_approval"),
            (HiveRunState::Ended, "ended"),
        ] {
            assert_eq!(s.as_str(), w);
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(w));
        }
    }

    #[derive(Deserialize)]
    struct Ack {
        #[serde(default, deserialize_with = "refusal_lenient")]
        refused: Option<HiveRefusal>,
    }

    fn ack(json: &str) -> Option<HiveRefusal> {
        serde_json::from_str::<Ack>(json)
            .expect("an ack decodes")
            .refused
    }

    /// The direction of the fallback is the point: anything PRESENT is a
    /// refusal, and only absence or `null` is acceptance.
    #[test]
    fn an_unknown_refusal_is_still_a_refusal() {
        assert_eq!(ack("{}"), None);
        assert_eq!(ack(r#"{"refused":null}"#), None);
        assert_eq!(
            ack(r#"{"refused":"no_account"}"#),
            Some(HiveRefusal::NoAccount)
        );
        assert_eq!(
            ack(r#"{"refused":"quota_exhausted"}"#),
            Some(HiveRefusal::Other),
            "a newer device's word"
        );
        assert_eq!(ack(r#"{"refused":7}"#), Some(HiveRefusal::Other));
        assert_eq!(ack(r#"{"refused":{"kind":"x"}}"#), Some(HiveRefusal::Other));
    }

    /// WIRE LOCK for the view refusals, and the fallback's direction: an
    /// unknown word still refuses — the browser must never be told to dial on
    /// a word nobody here understood.
    #[test]
    fn view_refusals_are_locked_and_an_unknown_one_still_refuses() {
        let words: Vec<&str> = HiveViewRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            ["hive_disabled", "no_session", "at_capacity", "other"]
        );
        for r in HiveViewRefusal::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct V {
            #[serde(default, deserialize_with = "view_refusal_lenient")]
            refused: Option<HiveViewRefusal>,
        }
        let v = |j: &str| serde_json::from_str::<V>(j).unwrap().refused;
        assert_eq!(v("{}"), None);
        assert_eq!(v(r#"{"refused":null}"#), None);
        assert_eq!(
            v(r#"{"refused":"no_session"}"#),
            Some(HiveViewRefusal::NoSession)
        );
        assert_eq!(
            v(r#"{"refused":"viewer_banned"}"#),
            Some(HiveViewRefusal::Other)
        );
        assert_eq!(v(r#"{"refused":false}"#), Some(HiveViewRefusal::Other));
    }

    /// FR-90 P1j — WIRE LOCK for the adopt refusals, and the fallback's
    /// direction: an unknown word still refuses, so a device never mirrors a
    /// terminal into a session the server did not record.
    #[test]
    fn adopt_refusals_are_locked_and_an_unknown_one_still_refuses() {
        let words: Vec<&str> = HiveAdoptRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "hive_not_enabled",
                "no_account",
                "ambiguous_account",
                "not_a_member",
                "at_capacity",
                "rate_limited",
                "other"
            ]
        );
        for r in HiveAdoptRefusal::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct A {
            #[serde(default, deserialize_with = "adopt_refusal_lenient")]
            refused: Option<HiveAdoptRefusal>,
        }
        let a = |j: &str| serde_json::from_str::<A>(j).unwrap().refused;
        assert_eq!(a("{}"), None);
        assert_eq!(a(r#"{"refused":null}"#), None);
        assert_eq!(
            a(r#"{"refused":"ambiguous_account"}"#),
            Some(HiveAdoptRefusal::AmbiguousAccount)
        );
        assert_eq!(
            a(r#"{"refused":"terminal_banned"}"#),
            Some(HiveAdoptRefusal::Other)
        );
        assert_eq!(a(r#"{"refused":0}"#), Some(HiveAdoptRefusal::Other));
    }

    #[derive(Deserialize)]
    struct State {
        #[serde(default, deserialize_with = "run_state_lenient")]
        state: Option<HiveRunState>,
    }

    #[test]
    fn an_unknown_run_state_is_unnamed_not_an_error() {
        let s = |j: &str| serde_json::from_str::<State>(j).expect("decodes").state;
        assert_eq!(s(r#"{"state":"running"}"#), Some(HiveRunState::Running));
        assert_eq!(s(r#"{"state":"compacting"}"#), None);
        assert_eq!(s(r#"{"state":3}"#), None);
        assert_eq!(s("{}"), None);
    }

    /// FR-90 P2c-3 — WIRE LOCK for the join refusals, and the fallback's
    /// direction: an unknown word still refuses, so a copy is never counted
    /// on a device that said no in a word this build cannot read.
    #[test]
    fn join_refusals_are_locked_and_an_unknown_one_still_refuses() {
        let words: Vec<&str> = HiveJoinRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "replica_disabled",
                "archive_disabled",
                "secondary_org",
                "purged",
                "stale_fence",
                "quota",
                "not_prepared",
                "other"
            ]
        );
        for r in HiveJoinRefusal::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct J {
            #[serde(default, deserialize_with = "join_refusal_lenient")]
            refused: Option<HiveJoinRefusal>,
        }
        let j = |s: &str| serde_json::from_str::<J>(s).unwrap().refused;
        assert_eq!(j("{}"), None);
        assert_eq!(j(r#"{"refused":null}"#), None);
        assert_eq!(j(r#"{"refused":"purged"}"#), Some(HiveJoinRefusal::Purged));
        assert_eq!(
            j(r#"{"refused":"disk_on_fire"}"#),
            Some(HiveJoinRefusal::Other)
        );
        assert_eq!(j(r#"{"refused":1}"#), Some(HiveJoinRefusal::Other));
    }

    /// FR-90 P2c-3 — the roles are locked, and a role this build cannot name
    /// is `None`: the frame still decodes, and the device refuses it.
    #[test]
    fn replica_roles_are_locked_and_an_unknown_one_is_unnamed() {
        let words: Vec<&str> = HiveReplicaRole::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(words, ["archive", "owner", "primary", "teleport"]);
        for r in HiveReplicaRole::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::json!(r.as_str())
            );
        }
        #[derive(Deserialize)]
        struct R {
            #[serde(default, deserialize_with = "replica_role_lenient")]
            role: Option<HiveReplicaRole>,
        }
        let r = |s: &str| serde_json::from_str::<R>(s).unwrap().role;
        assert_eq!(r(r#"{"role":"archive"}"#), Some(HiveReplicaRole::Archive));
        assert_eq!(r(r#"{"role":"primary"}"#), Some(HiveReplicaRole::Primary));
        assert_eq!(r(r#"{"role":"teleport"}"#), Some(HiveReplicaRole::Teleport));
        assert_eq!(r(r#"{"role":"witness"}"#), None);
        assert_eq!(r(r#"{"role":2}"#), None);
        assert_eq!(r("{}"), None);
    }

    /// FR-90 P2d — the rungs are locked, top first, and one this build cannot
    /// name is `None`: the want still decodes, and is refused in words.
    #[test]
    fn stream_paths_are_locked_top_first_and_an_unknown_one_is_unnamed() {
        let words: Vec<&str> = HiveStreamPath::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(words, ["direct", "relay", "derp"]);
        for p in HiveStreamPath::ALL {
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                serde_json::json!(p.as_str())
            );
        }
        #[derive(Deserialize)]
        struct P {
            #[serde(default, deserialize_with = "stream_path_lenient")]
            path: Option<HiveStreamPath>,
        }
        let p = |s: &str| serde_json::from_str::<P>(s).unwrap().path;
        assert_eq!(p(r#"{"path":"derp"}"#), Some(HiveStreamPath::Derp));
        assert_eq!(p(r#"{"path":"carrier-pigeon"}"#), None);
        assert_eq!(p(r#"{"path":3}"#), None);
        assert_eq!(p("{}"), None);
    }

    /// FR-90 P2d — the refusal words are locked, and anything present that
    /// is not one is still a refusal (`other`), never "ready".
    #[test]
    fn stream_refusals_are_locked_and_never_read_as_ready() {
        let words: Vec<&str> = HiveStreamRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "not_a_member",
                "stale_fence",
                "source_offline",
                "source_unsupported",
                "path_unavailable",
                "rate_limited",
                "busy",
                "not_held",
                "no_answer",
                "other",
            ]
        );
        for r in HiveStreamRefusal::ALL {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::json!(r.as_str())
            );
        }
        #[derive(Deserialize)]
        struct R {
            #[serde(default, deserialize_with = "stream_refusal_lenient")]
            refused: Option<HiveStreamRefusal>,
        }
        let r = |s: &str| serde_json::from_str::<R>(s).unwrap().refused;
        assert_eq!(r(r#"{"refused":"busy"}"#), Some(HiveStreamRefusal::Busy));
        assert_eq!(
            r(r#"{"refused":"moon_in_wrong_phase"}"#),
            Some(HiveStreamRefusal::Other)
        );
        assert_eq!(r(r#"{"refused":7}"#), Some(HiveStreamRefusal::Other));
        assert_eq!(r(r#"{"refused":null}"#), None);
        assert_eq!(r("{}"), None);
    }

    /// A WireGuard key is 64 lowercase hex characters, and nothing else is.
    #[test]
    fn a_pubkey_is_64_lowercase_hex_characters() {
        let good = "89abcdef".repeat(8);
        assert!(is_pubkey_hex(&good));
        assert!(!is_pubkey_hex(&good.to_uppercase()));
        assert!(!is_pubkey_hex(&good[..63]));
        assert!(!is_pubkey_hex(&"z".repeat(64)));
    }

    /// Only an address a device could be reached at is dialable: never the
    /// unspecified address, port 0, multicast or broadcast.
    #[test]
    fn only_an_address_a_device_could_be_reached_at_is_dialable() {
        for a in [
            "192.168.1.20:41000",
            "203.0.113.7:41000",
            "127.0.0.1:41000",
            "[2001:db8::1]:41000",
        ] {
            assert!(is_dialable(&a.parse().unwrap()), "{a} is dialable");
        }
        for a in [
            "0.0.0.0:41000",
            "192.168.1.20:0",
            "224.0.0.251:5353",
            "239.255.255.250:1900",
            "255.255.255.255:41000",
            "[ff02::1]:41000",
            "[::]:41000",
        ] {
            assert!(!is_dialable(&a.parse().unwrap()), "{a} is never dialable");
        }
    }

    /// FR-90 P2e-3 — WIRE LOCK: the drain's refusal words, and anything else
    /// present is still a refusal, never "drained".
    #[test]
    fn drain_refusal_words_are_locked_and_unknown_ones_still_refuse() {
        assert_eq!(
            HiveDrainRefusal::ALL.map(HiveDrainRefusal::as_str),
            ["not_running", "other"]
        );
        for w in HiveDrainRefusal::ALL {
            assert_eq!(
                serde_json::to_value(w).unwrap(),
                serde_json::Value::String(w.as_str().into())
            );
        }
        #[derive(Deserialize)]
        struct R {
            #[serde(default, deserialize_with = "drain_refusal_lenient")]
            refused: Option<HiveDrainRefusal>,
        }
        let r = |s: &str| serde_json::from_str::<R>(s).unwrap().refused;
        assert_eq!(
            r(r#"{"refused":"not_running"}"#),
            Some(HiveDrainRefusal::NotRunning)
        );
        assert_eq!(
            r(r#"{"refused":"too_tired"}"#),
            Some(HiveDrainRefusal::Other)
        );
        assert_eq!(r(r#"{"refused":3}"#), Some(HiveDrainRefusal::Other));
        assert_eq!(r(r#"{"refused":null}"#), None);
        assert_eq!(r("{}"), None);
    }

    /// A hash is 64 lowercase hex characters, and nothing else is one.
    #[test]
    fn a_hash_is_64_lowercase_hex_characters() {
        let good = "0123456789abcdef".repeat(4);
        assert!(is_hash_hex(&good));
        assert!(!is_hash_hex(&good.to_uppercase()), "lowercase only");
        assert!(!is_hash_hex(&good[..63]));
        assert!(!is_hash_hex(&format!("{good}0")));
        assert!(!is_hash_hex(&"g".repeat(64)));
        assert!(!is_hash_hex(""));
    }
}
