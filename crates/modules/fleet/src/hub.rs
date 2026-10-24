// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `Hub` — process-global registry of online agents and live sessions.
//!
//! The Hub is `Clone`-able (it's a thin Arc handle) and is shared across all
//! Axum WS handlers. It owns:
//!
//! - `agents`:   `agent_id` → connected agent's tx + metadata
//! - `sessions`: `session_id` → live session state
//!
//! All concurrent access goes through `DashMap` so we don't take a global
//! lock on every signaling message. The session inner state is wrapped in
//! `parking_lot::Mutex` because it's read+modified together (state machine).

use bson::oid::ObjectId;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{debug, info, warn};

use roomler_core::cluster::session_slots::{Lease, SessionSlots};

use roomler_ai_remote_control::audit::AuditSink;
use roomler_ai_remote_control::consent::{
    ASYNC_CONSENT_TIMEOUT, ConsentOutcome, DEFAULT_CONSENT_TIMEOUT, HOST_PROMPT_TIMEOUT,
    hub_consent_deadline,
};
use roomler_ai_remote_control::error::{Error, Result};
use roomler_ai_remote_control::models::{
    AgentCaps, AuditKind, ConsentMode, EndReason, ExecOutcome, FeaturePolicy, LockOnEnd, OsKind,
    RecordCap, RpcCap, SessionPhase, SessionPolicy,
};
use roomler_ai_remote_control::permissions::Permissions;
use roomler_ai_remote_control::session::{ClientTx, LiveSession};
use roomler_ai_remote_control::signaling::{
    AgentCloseReason, ClientMsg, IceServer, LIMIT_NO_COMMON_CODEC, LocalRelayDescriptor, Role,
    ServerMsg,
};
use roomler_ai_remote_control::turn_creds::{
    self, RelayLoadMap, TurnConfig, TurnMap, ice_servers_for_session, pick_region_with_load,
};

const SERVER_TX_CAPACITY: usize = 64;

// The consent windows (`DEFAULT_CONSENT_TIMEOUT`, `ASYNC_CONSENT_TIMEOUT`,
// `HOST_PROMPT_TIMEOUT`) live in `roomler_ai_remote_control::consent` — FR-27 moved
// `ASYNC_CONSENT_TIMEOUT` there from here, because the on-host and owner-side
// windows now differ within a single mode and the split needs one home.

/// How long a session may sit in `Negotiating` (consent granted, `Ready`
/// pushed) without the controller's SDP offer before the Hub terminates it.
/// Generous: a live controller sends its offer within milliseconds of
/// `rc:ready`; only a controller that never received `Ready` waits longer.
const NEGOTIATING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Loopback-TURN corp-relay (Phase 2) guard. The overlay assigns node IPs from
/// the RFC 6598 CGNAT range 100.64.0.0/10 (v4) or a ULA `fc00::/7` (v6, derived
/// from the v4). The Hub only appends a controller-supplied `local_relay` TURN
/// entry to the REMOTE agent's ICE servers when its address is inside that
/// range — so a malicious controller can't coerce the agent's TURN client into
/// probing an arbitrary host. (Media is DTLS-E2E regardless, but keeping the
/// agent pointed only at overlay IPs bounds the blast radius to its own mesh.)
fn is_overlay_relay_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        // 100.64.0.0/10 == 100.64.0.0 – 100.127.255.255
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        // fc00::/7 — the overlay's ULA space (today the agent hands out its v4
        // overlay IP; this keeps a future v6 relay from being rejected).
        Ok(std::net::IpAddr::V6(v6)) => (v6.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

// ────────────────────────────────────────────────────────────────────────────

pub struct ConnectedAgent {
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub owner_user_id: ObjectId,
    pub os: OsKind,
    pub tx: ClientTx,
    pub active_sessions: u8,
    pub max_sessions: u8,
    /// P6 — the agent advertises the InputArbiter capability
    /// (`AgentCaps.input` contains `"arbiter"`): concurrent input is
    /// serialized + modifier-fenced agent-side, so `create_session` does
    /// NOT apply the P3 single-INPUT-holder downgrade. Pre-P6 agents
    /// (false) keep the P3 strip.
    pub input_arbiter: bool,
    /// rc.53: signalled by [`Hub::register_agent`] when a newer
    /// connection displaces this one. The WS handler's read-loop
    /// `select!`s on `socket_rx.next()` AND `cancel.notified()`, so
    /// the displaced socket exits cleanly within milliseconds of the
    /// displacement Goodbye landing — instead of lingering up to one
    /// 25 s keepalive interval waiting for a ping-send to fail.
    pub cancel: Arc<Notify>,
    /// The agent's nearest relay region (`relay_regions` id), used to pick the
    /// per-session TURN config. Seeded from the DB row at registration and
    /// refreshed live when a probe report lands ([`Hub::set_agent_relay_home`]);
    /// `None` = the legacy default region.
    pub relay_home: Option<String>,
    /// The agent's regions ordered by measured RTT (nearest first) — the
    /// load-aware fallback ladder when [`relay_home`](Self::relay_home) is
    /// busy. Empty until a probe report lands.
    pub region_prefs: Vec<String>,
    /// Fleet RPC — the agent advertises `AgentCaps.rpc` containing `exec`.
    /// Distilled to a bool at registration so the Hub stays caps-agnostic,
    /// like [`ConnectedAgent::input_arbiter`]. `false` ⇒ refuse the request
    /// with [`Error::ExecUnsupported`] rather than pushing a frame the agent
    /// will silently drop.
    pub supports_exec: bool,
    /// FR-94 — the agent advertises `exec-system`: an administrator anchored
    /// this Windows device, and its SYSTEM service answered the worker's
    /// health ring. Set after registration and on every caps re-announcement,
    /// because the service can come up or be anchored while the worker is
    /// connected. Kept per connection, like
    /// [`Self::supports_ssh_grant_ack`]: a rollback must not leave the server
    /// routing commands to a doorbell the running agent cannot ring.
    pub supports_exec_system: bool,
    /// FR-105 — the agent advertises `ssh-system`: its anchor allows SSH (the
    /// `ssh` ceiling is not `off`) and its SYSTEM service answered the
    /// worker's health ring. Per connection and re-announced, exactly as
    /// [`Self::supports_exec_system`].
    pub supports_ssh_system: bool,
    /// FR-97 P5a — the agent advertises `console-user`: a Linux or macOS
    /// build that runs a command as the person at its screen when the frame
    /// says `run_as: console_user`. Per CONNECTION, never read from the
    /// stored row: an older agent ignores the field and runs the command as
    /// root, so after a rollback the row's promise would be exactly that.
    /// `false` ⇒ [`Hub::exec_on_agent`] refuses such a frame.
    pub supports_console_user: bool,
    /// Roomler SSH — the agent advertises `AgentCaps.rpc` containing `ssh`,
    /// i.e. it was built with the `ssh-server` feature and will record an
    /// `rc:ssh.grant`. Same rationale as [`Self::supports_exec`]: pushing a
    /// grant to a build that drops it would leave the caller dialling a port
    /// that authenticates nobody, with nothing anywhere saying why.
    pub supports_ssh: bool,
    /// FR-83 — the agent advertises `ssh-grant-ack`: it answers every grant
    /// with `rc:ssh.grant_ack` once the grant is redeemable, so the server may
    /// hold the caller for it. Kept per CONNECTION, never read from the stored
    /// row: after a rollback the row still promises an ack the running agent
    /// never sends, and every grant to it would wait out the bound and then
    /// be refused.
    pub supports_ssh_grant_ack: bool,
    /// FR-85 P3 — what the agent says about remote recording in
    /// `AgentCaps.record`. Kept per CONNECTION, like
    /// [`Self::supports_ssh_grant_ack`]: the stored row outlives an owner's
    /// OFF and a rollback alike. Anything but [`RecordSupport::Serves`] ⇒
    /// `create_session` strips `Permissions::RECORD`.
    pub record_support: RecordSupport,
    /// FR-99 — what the agent says about privacy mode in `AgentCaps.rpc`.
    /// Per CONNECTION, like [`Self::record_support`]: the stored row outlives
    /// an owner's OFF and a rollback alike, and a rolled-back agent that never
    /// knew the `PRIVACY` name would fail the whole `rc:request` carrying it.
    /// Anything but [`PrivacySupport::Serves`] ⇒ `create_session` strips it.
    pub privacy_support: PrivacySupport,
    /// FR-101 P2 — the agent advertises `session-policy` in `AgentCaps.rpc`:
    /// its prompt names the features the policy says to `ask` about. Per
    /// CONNECTION, like [`Self::privacy_support`]; `false` ⇒ an `ask` feature
    /// is stripped (`device_cannot_ask`): an older agent's prompt shows raw
    /// permission names at most, never audio, and it checks no policy.
    pub asks_features: bool,
    /// FR-101 P2b — the device owner's own floor (`AgentCaps.session_policy`),
    /// so a feature the device will refuse is stripped here with
    /// `device_policy_off` and the viewer is told why. Informative: the agent
    /// enforces it whatever this says. Per CONNECTION; `None` = no floor.
    pub device_session_policy: Option<SessionPolicy>,
    /// FR-101 P4b-2 — the agent advertises `idle-timeout` in `AgentCaps.rpc`:
    /// it ends a session that sits idle past `Request.idle_secs`. Per
    /// CONNECTION, like [`Self::asks_features`]; `false` ⇒ the idle limit
    /// still rides the request (an older agent ignores it) but the viewer is
    /// not told one, since nothing would keep it.
    pub enforces_idle: bool,
    /// FR-99 P3b — the agent advertises `lock-on-end` in `AgentCaps.rpc`: it
    /// takes `Request.lock_on_end` into the lock at the session's end. Per
    /// CONNECTION; `false` ⇒ the ask is not sent, and the audit row records
    /// it as not enforced.
    pub honours_lock_on_end: bool,
    /// FR-92 — the agent advertises `keep-busy` in `AgentCaps.input`: it
    /// parses `rc:agent.keep_busy_policy`. Per CONNECTION; a pre-FR-92 agent
    /// would log every policy frame as an unknown `rc:*` at WARN.
    pub supports_keep_busy: bool,
    /// FR-90 — the agent advertises `hive`: it answers `rc:hive.start` with
    /// `rc:hive.start_ack` and reports sessions with `rc:hive.state`. Per
    /// CONNECTION, for [`Self::supports_ssh_grant_ack`]'s reason — a stored
    /// row outlives a rollback, and a start pushed to an agent that drops it
    /// would leave the caller waiting on silence.
    pub supports_hive: bool,
    /// FR-90 P0d-2 — the agent advertises `hive-view`: it answers a view
    /// grant with `rc:hive.view.grant_ack` and serves a viewer peer. Per
    /// connection, for the same reason; `hive` does NOT imply it.
    pub supports_hive_view: bool,
    /// FR-90 P1e — the agent advertises `hive-memory`: it understands a
    /// session's core-memory snapshot (`rc:hive.memory`). Per connection, for
    /// the same reason; `hive` does NOT imply it.
    pub supports_hive_memory: bool,
    /// FR-90 P1j — the agent advertises `hive-adopt`: it mirrors terminal
    /// sessions its accounts adopted, and its owner allowed it (`hive_adopt`).
    /// An `rc:hive.adopt` from a connection without it is refused unread. Per
    /// connection, for the same reason; `hive` does NOT imply it.
    pub supports_hive_adopt: bool,
    /// FR-90 P2c-3 — the agent advertises `hive-replica`: it answers
    /// `rc:hive.replica.join`, and its owner lets it hold copies
    /// (`hive_replica`). Per connection, for the same reason; `hive` does NOT
    /// imply it.
    pub supports_hive_replica: bool,
    /// FR-90 P2d — the agent advertises `hive-stream`: it serves a session it
    /// holds to a member over QUIC, and asks for and dials one as a member.
    /// A grant goes only to a connection with it. Per connection, for the same
    /// reason; neither `hive` nor `hive-replica` implies it.
    pub supports_hive_stream: bool,
    /// FR-90 P2e-2 — the agent advertises `hive-lease`: it holds a leased
    /// session to the server's word on each connection (`rc:hive.lease`).
    /// The word, and a start that asks for it, go only to a connection with
    /// it. Per connection, for the same reason; `hive` does NOT imply it.
    pub supports_hive_lease: bool,
    /// FR-90 P2e-3 — the agent advertises `hive-promote`: it answers a
    /// promotion's prepare and drain, and runs its move. The server promotes
    /// only between two connections with it. Per connection, for the same
    /// reason; neither `hive` nor `hive-lease` implies it.
    pub supports_hive_promote: bool,
    /// FR-90 P2f-1 — the agent advertises `hive-teleport`: as a teleport's
    /// target it answers a prepare that asks no copy and takes the join that
    /// prepare admits; as its primary it says where its copy ends at a join.
    /// The server teleports only between two connections with it. Per
    /// connection, for the same reason; `hive-promote` does NOT imply it.
    pub supports_hive_teleport: bool,
    /// FR-90 P2f-3 — the agent advertises `hive-fork`: a start that names
    /// the session it forks starts from its parent's copy there. A build
    /// before it would start the fork EMPTY, so a fork's every start goes
    /// only to a connection with it. Per connection, for the same reason;
    /// `hive` does NOT imply it.
    pub supports_hive_fork: bool,
    /// FR-90 P2f-4b — the agent advertises `hive-manage`: a start carrying
    /// `from_terminal` makes a terminal session it adopted a managed one.
    /// A build before it would start the conversation afresh, so such a
    /// start goes only to a connection with it. Per connection; `hive` does
    /// NOT imply it.
    pub supports_hive_manage: bool,
    /// FR-90 P2g-2 — the agent advertises `hive-purge`: it deletes a session
    /// on `rc:hive.purge` and answers per part. A build before it has no
    /// such frame, so a purge goes only to a connection with it, and waits
    /// for one. Per connection; `hive` does NOT imply it.
    pub supports_hive_purge: bool,
    /// FR-90 P2g-4a — the agent advertises `hive-purge-all`: it purges every
    /// session it holds on `rc:hive.purge_all`, sent at its removal. A build
    /// of P2g-1 to P2g-3d purges a session and cannot decode this frame, so
    /// it is sent only to a connection with it. Per connection; neither `hive`
    /// nor `hive-purge` implies it.
    pub supports_hive_purge_all: bool,
    /// FR-90 P2i-2 — the agent advertises `hive-search`: an archive replica
    /// that answers a search over the copies it holds
    /// (`rc:hive.search.grant`). A search grant goes only to a connection
    /// with it and with `hive-view`, whose frames carry the search's peer.
    /// Per connection; neither `hive`, `hive-replica` nor `hive-archive`
    /// implies it.
    pub supports_hive_search: bool,
    /// #2267 — `rc:hive.purge_all` was queued to this connection, which
    /// happens only at its removal. Unless the connection drains (below), the
    /// removal's kick then leaves the socket open instead of telling the
    /// device: such a daemon exits at once on `rc:goodbye AgentDeleted`, which
    /// would cut its purge short.
    pub removal_purge_pushed: bool,
    /// #2294 — the agent advertises `hive-purge-drain`: on the goodbye it
    /// finishes a removal purge before it exits, so a purged connection is
    /// told like any other. Per connection; `hive-purge-all` does NOT imply it.
    pub supports_hive_purge_drain: bool,
}

/// #2267 — what a removal's kick did to the device's connection on this pod
/// ([`Hub::kick_removed_agent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KickOutcome {
    /// This pod holds no connection for the device.
    NotRegistered,
    /// Taken out of the hub, and `rc:goodbye AgentDeleted` queued behind
    /// whatever was queued to it before. The device closes the socket.
    Told,
    /// Taken out of the hub and not told: the caller asked not to (the device
    /// is leaving by itself, or `rc.removal_goodbye` is off).
    NotTold,
    /// Taken out of the hub and not told, because this removal queued it
    /// `rc:hive.purge_all` and its build exits at once on the goodbye (no
    /// `hive-purge-drain`). Its socket stays open, as before #2267.
    KeptForPurge,
    /// Taken out of the hub; the goodbye could not be queued (the channel is
    /// full or closed). The socket ends as it did before #2267.
    GoodbyeLost,
}

/// FR-85 P3 — what a device says about remote recording, from its caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordSupport {
    /// No recorder can serve a remote session here: an agent that predates
    /// recording, a build without it, `ROOMLERD_RECORDING=0`, or a host that
    /// cannot record at all. Nothing to offer a controller.
    #[default]
    None,
    /// P3c-2 — a recorder could, but the owner has not allowed remote
    /// recording (`available` without `remote`).
    NotOptedIn,
    /// The owner allowed it: the agent serves the `record` DataChannel
    /// (`remote`).
    Serves,
}

impl RecordSupport {
    /// ⚠️ Equality matching on the words (`has_record`): `remote` is a
    /// prefix of `remote-audio`. `remote` alone also reads as a recorder,
    /// because an agent built before `available` existed says only that.
    pub fn from_caps(caps: &AgentCaps) -> Self {
        if caps.has_record(RecordCap::Remote) {
            Self::Serves
        } else if caps.has_record(RecordCap::Available) {
            Self::NotOptedIn
        } else {
            Self::None
        }
    }
}

/// FR-85 P3 — the RECORD part of a grant: kept only when the controller may
/// record AND the agent serves it; otherwise stripped, with the reason (for
/// the audit and the viewer). A grant without RECORD passes untouched.
///
/// P3c-2 — a device with no recorder at all is named FIRST
/// (`device_cannot_record`): there is nothing there to allow or refuse, and
/// a viewer shows no Record control for it rather than one that explains a
/// permission nobody could grant.
pub fn record_grant(
    permissions: Permissions,
    may_record: bool,
    device: RecordSupport,
) -> (Permissions, Option<&'static str>) {
    if !permissions.contains(Permissions::RECORD) {
        return (permissions, None);
    }
    if device == RecordSupport::None {
        return (
            permissions - Permissions::RECORD,
            Some("device_cannot_record"),
        );
    }
    if !may_record {
        return (
            permissions - Permissions::RECORD,
            Some("controller_not_allowed"),
        );
    }
    if device != RecordSupport::Serves {
        return (
            permissions - Permissions::RECORD,
            Some("device_not_opted_in"),
        );
    }
    (permissions, None)
}

/// FR-99 — what a device says about privacy mode, from its `rpc` words.
/// [`RecordSupport`]'s shape, for its reason: "the owner has not allowed it"
/// is worth a sentence in the viewer, "this device cannot do it" is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivacySupport {
    /// No curtain is possible here: an agent that predates privacy mode, a
    /// platform with no way to keep a window out of capture (macOS,
    /// Wayland), or a build without it. ⚠️ Such an agent may not even know
    /// the `PRIVACY` name, so it must never be sent one.
    #[default]
    None,
    /// A curtain is possible, but the device's owner has not allowed privacy
    /// mode (`privacy-available` without `privacy-mode`).
    NotOptedIn,
    /// The owner allowed it, and the agent serves it (`privacy-mode`).
    Serves,
}

impl PrivacySupport {
    /// Equality-matched through [`AgentCaps::has_rpc`]. `privacy-mode` wins
    /// over `privacy-available`: an agent that says both serves it.
    pub fn from_caps(caps: &AgentCaps) -> Self {
        if caps.has_rpc(RpcCap::PrivacyMode) {
            Self::Serves
        } else if caps.has_rpc(RpcCap::PrivacyAvailable) {
            Self::NotOptedIn
        } else {
            Self::None
        }
    }
}

/// FR-99 — the PRIVACY part of a grant, [`record_grant`]'s shape: kept only
/// for a session that is not break-glass, on an agent that serves privacy
/// mode; otherwise stripped, with the reason (for the audit and the viewer).
/// A grant without PRIVACY passes untouched.
///
/// ⚠️ Break-glass never covers the screen (FR-99 decision 1, 2026-10-14). It
/// is the one session nobody at the device was asked about, audited and
/// mailed to the owner — and a curtain would hide it from the only person in
/// a position to object. The same rule as RECORD.
///
/// ⚠️ Nor does a session from OUTSIDE the organization (FR-52 decision 13,
/// 2026-10-19). The person at the device let a stranger in on a password and
/// a name the stranger chose, and is the only one placed to see what that
/// stranger then does: a curtain would hide it from them. The same sessions
/// are never recorded (`controller_not_allowed`, FR-52 §10). The device
/// strips both again on its own terms (`roomlerd`'s `extauth::admit_session`),
/// so this gate is not the only thing keeping them out.
///
/// A device that cannot curtain at all is named FIRST, as in
/// [`record_grant`]: there is nothing there to allow or refuse.
pub fn privacy_grant(
    permissions: Permissions,
    break_glass: bool,
    external: bool,
    device: PrivacySupport,
) -> (Permissions, Option<&'static str>) {
    if !permissions.contains(Permissions::PRIVACY) {
        return (permissions, None);
    }
    if device == PrivacySupport::None {
        return (
            permissions - Permissions::PRIVACY,
            Some("device_cannot_curtain"),
        );
    }
    if break_glass {
        return (permissions - Permissions::PRIVACY, Some("break_glass"));
    }
    if external {
        return (permissions - Permissions::PRIVACY, Some("outside_the_org"));
    }
    if device != PrivacySupport::Serves {
        return (
            permissions - Permissions::PRIVACY,
            Some("device_not_opted_in"),
        );
    }
    (permissions, None)
}

/// FR-101 P2 — why a session feature was refused, keyed by the feature's wire
/// name (`clipboard`, `files`, `audio`). Empty = nothing refused.
pub type FeatureRefusals = BTreeMap<&'static str, &'static str>;

/// FR-101 P2 — the org's session policy, as the authz gate could read it.
///
/// An enum rather than an `Option` on purpose: on the agent's wire an absent
/// `session_policy` means "unrestricted", and the opposite sense here behind
/// the same `None` is the kind of thing a later reader "simplifies".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgPolicy {
    /// Read from the tenant row: all `on` for an org that set nothing.
    Read(SessionPolicy),
    /// The tenant row could not be read (a database error, or no row). The
    /// session goes ahead, as it did before the feature, but every feature
    /// asked for is refused (`policy_unavailable`) rather than granted on a
    /// guess: a blip must not hand over what an org switched off.
    Unavailable,
}

impl OrgPolicy {
    /// What the agent is told in `ServerMsg::Request::session_policy`: the
    /// org's policy when it restricts anything, nothing when it does not,
    /// and all `off` when it could not be read (the hub refused every
    /// feature, and the agent should hold the same line).
    pub fn for_agent(self) -> Option<SessionPolicy> {
        match self {
            Self::Read(p) => (!p.is_unrestricted()).then_some(p),
            Self::Unavailable => Some(SessionPolicy {
                clipboard: FeaturePolicy::Off,
                files: FeaturePolicy::Off,
                audio: FeaturePolicy::Off,
            }),
        }
    }
}

/// FR-101 P2 — the clipboard, files and audio part of a grant under the org's
/// session policy: [`record_grant`]'s shape, for three features at once.
/// CLIPBOARD and FILES are permission bits. Audio is `audio_enabled`, which is
/// what the agent adds its track on (it reads no bit), so the unused AUDIO bit
/// goes with it. A feature the controller did not ask for is never named.
///
/// P2b — the device owner's floor (`device`, from its caps) combines with the
/// org's policy, the stricter winning, exactly as the agent combines them.
///
/// - `off` strips it for every controller: the owner, an ADMINISTRATOR and
///   break-glass alike. `org_policy_off` when the org said so (even if the
///   device did too), else `device_policy_off`.
/// - `ask` keeps it only under [`ConsentMode::Prompt`], the one mode in which
///   the person at the device is who approves, and only on an agent whose
///   prompt names the feature (`session-policy`). Otherwise it is stripped:
///   `needs_consent` when nobody there is asked (`auto`, which covers the
///   owner's own session without `prompt_owner` and break-glass; `email` and
///   `push`; `prompt_then_email`, whose approval may come from the owner's
///   mail instead), else `device_cannot_ask`.
///
/// `needs_consent` is named first: it holds whatever the agent's version, so
/// updating the device would not lift it. A policy that could not be read
/// refuses every feature asked for, `policy_unavailable`.
pub fn feature_grant(
    permissions: Permissions,
    audio_enabled: bool,
    policy: OrgPolicy,
    device: Option<SessionPolicy>,
    consent_mode: ConsentMode,
    agent_asks: bool,
) -> (Permissions, bool, FeatureRefusals) {
    let device = device.unwrap_or_default();
    let verdict = |pick: fn(&SessionPolicy) -> FeaturePolicy| -> Option<&'static str> {
        let OrgPolicy::Read(read) = policy else {
            return Some("policy_unavailable");
        };
        let (org_p, device_p) = (pick(&read), pick(&device));
        match org_p.stricter(device_p) {
            FeaturePolicy::On => None,
            FeaturePolicy::Off if org_p == FeaturePolicy::Off => Some("org_policy_off"),
            FeaturePolicy::Off => Some("device_policy_off"),
            FeaturePolicy::Ask if consent_mode != ConsentMode::Prompt => Some("needs_consent"),
            FeaturePolicy::Ask if !agent_asks => Some("device_cannot_ask"),
            FeaturePolicy::Ask => None,
        }
    };
    let mut permissions = permissions;
    let mut audio_enabled = audio_enabled;
    let mut refused = FeatureRefusals::new();
    if permissions.contains(Permissions::CLIPBOARD)
        && let Some(why) = verdict(|p| p.clipboard)
    {
        permissions -= Permissions::CLIPBOARD;
        refused.insert("clipboard", why);
    }
    if permissions.contains(Permissions::FILES)
        && let Some(why) = verdict(|p| p.files)
    {
        permissions -= Permissions::FILES;
        refused.insert("files", why);
    }
    if (audio_enabled || permissions.contains(Permissions::AUDIO))
        && let Some(why) = verdict(|p| p.audio)
    {
        audio_enabled = false;
        permissions -= Permissions::AUDIO;
        refused.insert("audio", why);
    }
    (permissions, audio_enabled, refused)
}

/// FR-101 P2 — [`FeatureRefusals`] for the wire and the audit: `None` when
/// nothing was refused, so the field stays off both.
pub fn refusals_wire(refused: &FeatureRefusals) -> Option<BTreeMap<String, String>> {
    (!refused.is_empty()).then(|| {
        refused
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    })
}

/// FR-101 P4b-2 — the limit a `ClientMsg::Terminate` may name: `idle`, and
/// only from the AGENT ending a session as `IdleTimeout`. Only the device
/// measures idleness; a controller claiming it, or the agent pairing it with
/// another reason, names nothing, and the session ends on its reason alone.
/// #2251 — likewise `no_common_codec`, only from the agent ending a session
/// as `Error`: only the device holds both halves of it (the codecs its RTP
/// track can send, and the offer that carries none of them). A controller's
/// claim would put the device's verdict in the audit and stop every other
/// viewer's retry.
/// A `&'static str` so the hub's own vocabulary is what reaches the viewer
/// and the audit, never a string off the wire.
pub fn device_end_limit(
    role: Role,
    reason: EndReason,
    claimed: Option<&str>,
) -> Option<&'static str> {
    match (role, reason, claimed) {
        (Role::Agent, EndReason::IdleTimeout, Some("idle")) => Some("idle"),
        (Role::Agent, EndReason::Error, Some(LIMIT_NO_COMMON_CODEC)) => Some(LIMIT_NO_COMMON_CODEC),
        _ => None,
    }
}

pub struct ConnectedController {
    pub user_id: ObjectId,
    pub tx: ClientTx,
}

/// Deregisters an exec waiter on every exit path from
/// [`Hub::exec_on_agent`] — an early `send_to_agent` error or an expired
/// deadline must not leave a slot behind that a later request id could be
/// delivered into.
struct ExecWaiterGuard {
    hub: Hub,
    request_id: String,
}

impl Drop for ExecWaiterGuard {
    fn drop(&mut self) {
        self.hub.inner.exec_waiters.remove(&self.request_id);
    }
}

/// FR-94 — a command pushed to a device whose SYSTEM service runs it
/// ([`Hub::start_exec`]). `rx` resolves when a result reaches THIS pod: the
/// worker's own `rc:rpc.result` (a refusal, a declined prompt, a doorbell
/// nobody answered) or the service's result route landing here. A result
/// posted to another pod is in the shared `exec_pending` row instead, which
/// the caller polls. Dropping it deregisters the waiter, exactly as
/// `exec_on_agent` does.
pub struct StartedExec {
    pub rx: oneshot::Receiver<ExecOutcome>,
    _guard: ExecWaiterGuard,
}

/// FR-97 P5a — does this frame ask the device to run a command as someone
/// other than itself (`rc:rpc.exec` carrying `run_as`)? Only a connection
/// advertising `console-user` may be sent one.
fn asks_console_user(msg: &ServerMsg) -> bool {
    matches!(
        msg,
        ServerMsg::RpcExec {
            run_as: Some(_),
            ..
        }
    )
}

/// Emitted by [`Hub::create_session`] to have the API layer notify the device
/// OWNER. Two flavours, distinguished by `override_reason`:
/// * `None` — Email/Push consent modes: the owner must APPROVE (the API persists
///   a `ConsentRequest` + sends the approve-link; the owner's approve/deny later
///   calls [`Hub::deliver_consent`], resolving the SAME slot the waiter awaits).
/// * `Some(reason)` — an admin break-glass already happened: an INFORMATIONAL
///   "your device was accessed" notice (no approval needed, no token).
///
/// The Hub stays DB-agnostic — it just publishes; the API consumer resolves the
/// owner from `agent_id`.
/// PR-1 — outcome of an idle-nudge attempt (`nudge_agent_if_idle`).
/// The refusal reason rides the `rc.agent_nudge` bus reply so the
/// requesting pod can log and count truthfully instead of a bare bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NudgeOutcome {
    /// The WS cycle fired (cancel notify latched).
    Nudged,
    /// Live rc session(s) — never cycle a screen someone is viewing.
    RcBusy,
    /// Caller-computed tunnel busy-ness (sessions targeting the agent
    /// or originated by it — the caller owns those indices).
    ExtraBusy,
    /// The agent is not registered in this pod's hub.
    NotRegistered,
}

impl NudgeOutcome {
    /// Wire label for the bus reply (`reason` field).
    pub fn reason(&self) -> &'static str {
        match self {
            NudgeOutcome::Nudged => "nudged",
            NudgeOutcome::RcBusy => "rc_busy",
            NudgeOutcome::ExtraBusy => "tunnel_busy",
            NudgeOutcome::NotRegistered => "not_registered",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsentEvent {
    pub session_id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    pub controller_name: String,
    pub mode: ConsentMode,
    /// Same window the waiter uses — the consumer sizes the `ConsentRequest`
    /// TTL to match so a stale link can't resolve a long-gone session.
    pub timeout_secs: u32,
    /// `Some` ⇒ this is a break-glass NOTICE (already-granted), carrying the
    /// admin's reason; `None` ⇒ an Email/Push APPROVAL request.
    pub override_reason: Option<String>,
}

pub struct HubInner {
    /// Online agents, keyed by agent_id.
    agents: DashMap<ObjectId, ConnectedAgent>,

    /// Live sessions (anything not yet `Closed`).
    sessions: DashMap<ObjectId, Arc<Mutex<LiveSession>>>,

    /// Per-controller-user connections (one user may have multiple browser tabs).
    controllers: DashMap<ObjectId, Vec<ClientTx>>,

    /// TURN issuance — region-keyed; a disabled/regionless map behaves exactly
    /// like the old `Option<TurnConfig>` (its `default`).
    turn: TurnMap,

    /// Live per-region load written by the API's `/stats` poller; consulted
    /// when FREEZING a session's region at create time. Empty (tests / poller
    /// off) = nothing is ever busy.
    relay_load: RelayLoadMap,

    /// Audit sink.
    audit: AuditSink,

    /// Phase 4 — async-consent event sink (Email/Push). `None` (tests / no email
    /// configured) drops the events and those sessions fall back to the waiter
    /// timeout.
    consent_tx: Option<mpsc::Sender<ConsentEvent>>,

    /// Fleet RPC — callers parked on a `rc:rpc.result`, keyed by request id.
    /// Same-pod only: the agent's WS receive path and the HTTP handler that
    /// is awaiting live in one process, and the API layer routes a request to
    /// the owner pod BEFORE reaching the Hub (see `ws/rc_relay.rs`).
    exec_waiters: DashMap<String, oneshot::Sender<ExecOutcome>>,

    /// FR-115 P3b — the cluster-wide slot record, set once at startup when
    /// the deployment has Redis (`roomler_core::cluster::session_slots`).
    session_slots: std::sync::OnceLock<SessionSlots>,
    /// FR-115 P3b — the live sessions that hold a slot, each with the lease
    /// this pod renews (`slot_leases`) and gives back when the session ends
    /// (`terminate_with_limit`, the one place every session ends).
    slotted: DashMap<ObjectId, Lease>,
}

#[derive(Clone)]
pub struct Hub {
    inner: Arc<HubInner>,
}

impl Hub {
    pub fn new(audit: AuditSink, turn: Option<TurnConfig>) -> Self {
        Self::new_with_consent(audit, TurnMap::single(turn), None, Default::default())
    }

    /// Like [`Hub::new`] but wires the Phase-4 async-consent event sender,
    /// the full region-keyed [`TurnMap`], and the live region-load table.
    pub fn new_with_consent(
        audit: AuditSink,
        turn: TurnMap,
        consent_tx: Option<mpsc::Sender<ConsentEvent>>,
        relay_load: RelayLoadMap,
    ) -> Self {
        Self {
            inner: Arc::new(HubInner {
                agents: DashMap::new(),
                sessions: DashMap::new(),
                controllers: DashMap::new(),
                turn,
                relay_load,
                audit,
                consent_tx,
                exec_waiters: DashMap::new(),
                session_slots: std::sync::OnceLock::new(),
                slotted: DashMap::new(),
            }),
        }
    }

    /// FR-115 P3b — hand the hub the slot record (once, at startup).
    pub fn set_session_slots(&self, slots: SessionSlots) {
        let _ = self.inner.session_slots.set(slots);
    }

    /// FR-115 P3b — this pod's live slot leases, for the renewal round.
    pub fn slot_leases(&self) -> Vec<Lease> {
        self.inner
            .slotted
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    /// FR-115 P3b — give a slot back, off the caller's thread. A failed or
    /// impossible release (no runtime) is backed up by the lease's own TTL.
    fn release_slot(&self, lease: Lease) {
        let Some(slots) = self.inner.session_slots.get().cloned() else {
            return;
        };
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Err(e) = slots.release(lease.scope, lease.session).await {
                    warn!(
                        session = %lease.session,
                        %e,
                        "session slot: release failed; its lease expires on its own"
                    );
                }
            });
        }
    }

    // ─── connection registration ──────────────────────────────────────

    /// Called by the WS handler when an agent finishes auth+hello.
    /// Returns `(tx, cancel, rx)`:
    ///
    ///   * `tx` — clone of the channel registered in `ConnectedAgent.tx`.
    ///     The WS handler captures this so its later `unregister_agent`
    ///     call can identify "still my entry?" via `ClientTx::same_channel`
    ///     and avoid evicting a NEWER displacing connection's entry
    ///     (rc.53 race fix; the pre-rc.53 unregister unconditionally
    ///     removed by `agent_id`).
    ///   * `cancel` — `Arc<Notify>` the WS handler `select!`s on so a
    ///     displacement triggers an immediate read-loop exit, NOT a 25 s
    ///     wait for the agent's own keepalive ping to fail.
    ///   * `rx` — pump source for `pump_server_messages`.
    // Eight positional args, all of them distinct facts about the connecting
    // agent that the Hub must hold. Bundling them into a struct would move the
    // "did you pass the right bool?" hazard from the call site to the literal
    // without removing it, for one call site in production code.
    #[allow(clippy::too_many_arguments)]
    pub fn register_agent(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        os: OsKind,
        max_sessions: u8,
        // P6 — whether the agent's caps advertise the InputArbiter (see
        // [`ConnectedAgent::input_arbiter`]).
        input_arbiter: bool,
        // Fleet RPC — whether the agent's caps advertise `rpc: ["exec", …]`
        // (see [`ConnectedAgent::supports_exec`]).
        supports_exec: bool,
    ) -> (ClientTx, Arc<Notify>, mpsc::Receiver<ServerMsg>) {
        let (tx, rx) = mpsc::channel(SERVER_TX_CAPACITY);
        let cancel = Arc::new(Notify::new());
        let entry = ConnectedAgent {
            agent_id,
            tenant_id,
            owner_user_id,
            os,
            tx: tx.clone(),
            active_sessions: 0,
            max_sessions,
            input_arbiter,
            cancel: cancel.clone(),
            relay_home: None,
            region_prefs: Vec::new(),
            supports_exec,
            // Set right after registration by `set_agent_ssh_support`, so this
            // signature — which already carries an
            // `allow(clippy::too_many_arguments)` — does not grow a ninth
            // positional bool that every test would have to thread through.
            // `false` is the safe starting point: an agent whose capability is
            // never recorded is treated as unable to serve SSH.
            // FR-94 — set right after registration, like `supports_ssh`; an
            // agent whose word is never recorded takes the worker path.
            supports_exec_system: false,
            // FR-105 — the same: an unrecorded word takes the worker path.
            supports_ssh_system: false,
            // FR-97 P5a — set right after registration; an agent whose word
            // is never recorded is sent no `run_as`.
            supports_console_user: false,
            supports_ssh: false,
            // Same setter, same reasoning: `false` = answered without waiting,
            // exactly as before FR-83.
            supports_ssh_grant_ack: false,
            // FR-85 P3 — set by `set_agent_record_support` right after
            // registration; `None` (RECORD stripped) until it is.
            record_support: RecordSupport::None,
            // FR-99 — set by `set_agent_privacy_support`; `None` (PRIVACY
            // stripped, never sent) until it is.
            privacy_support: PrivacySupport::None,
            // FR-101 P2 — set by `set_agent_asks_features`; `false` (an `ask`
            // feature stripped) until it is.
            asks_features: false,
            // FR-101 P2b — set by `set_agent_device_session_policy`.
            device_session_policy: None,
            // FR-101 P4b-2 — set by `set_agent_enforces_idle`; `false` (no
            // idle limit promised to a viewer) until it is.
            enforces_idle: false,
            // FR-99 P3b — set by `set_agent_honours_lock_on_end`; `false` (no
            // lock ask sent) until it is.
            honours_lock_on_end: false,
            // FR-92 — set by `set_agent_keep_busy_support`; `false` = no
            // policy frame is ever pushed to this connection.
            supports_keep_busy: false,
            // FR-90 — set by `set_agent_hive_support`; `false` = no session
            // frame is ever pushed to this connection.
            supports_hive: false,
            // FR-90 P0d-2 — set by `set_agent_hive_view_support`; `false` = no
            // view grant is ever pushed to this connection.
            supports_hive_view: false,
            // FR-90 P1e — set by `set_agent_hive_memory_support`; `false` = no
            // core memory is ever pushed to this connection.
            supports_hive_memory: false,
            // FR-90 P1j — set by `set_agent_hive_adopt_support`; `false` = an
            // adopt offer from this connection is never honoured.
            supports_hive_adopt: false,
            // FR-90 P2c-3 — set by `set_agent_hive_replica_support`; `false` = no
            // join is ever pushed to this connection.
            supports_hive_replica: false,
            // FR-90 P2d — set by `set_agent_hive_stream_support`; `false` = no
            // stream grant is ever pushed to this connection.
            supports_hive_stream: false,
            // FR-90 P2e-2 — set by `set_agent_hive_lease_support`; `false` = no
            // lease word, and no leased start, is ever sent to this connection.
            supports_hive_lease: false,
            // FR-90 P2e-3 — set by `set_agent_hive_promote_support`; `false` =
            // no promotion starts on, or moves away from, this connection.
            supports_hive_promote: false,
            // FR-90 P2f-1 — set by `set_agent_hive_teleport_support`; `false` =
            // no teleport moves a session to, or away from, this connection.
            supports_hive_teleport: false,
            // FR-90 P2f-3 — set by `set_agent_hive_fork_support`; `false` = no
            // fork's start is ever sent to this connection.
            supports_hive_fork: false,
            // FR-90 P2f-4b — set by `set_agent_hive_manage_support`; `false` =
            // no start that makes a terminal session managed is sent here.
            supports_hive_manage: false,
            // FR-90 P2g-2 — set by `set_agent_hive_purge_support`; `false` = no
            // purge is ever sent to this connection.
            supports_hive_purge: false,
            // FR-90 P2g-4a — set by `set_agent_hive_purge_all_support`; `false`
            // = no removal's purge is ever sent to this connection.
            supports_hive_purge_all: false,
            // FR-90 P2i-2 — set by `set_agent_hive_search_support`; `false` =
            // no search grant is ever pushed to this connection.
            supports_hive_search: false,
            // #2267 — set by `push_hive_purge_all` once the frame is queued.
            removal_purge_pushed: false,
            // #2294 — set by `set_agent_hive_purge_drain_support`; `false` =
            // a purged connection is not told at its removal, as before.
            supports_hive_purge_drain: false,
        };
        if let Some(prev) = self.inner.agents.insert(agent_id, entry) {
            // rc.53: don't just `drop(prev)` — that leaves the old WS
            // read-loop polling `socket_rx.next()` for up to one 25 s
            // keepalive interval before the agent's own ping fails and
            // surfaces as a transient. Instead:
            //   1. Push a structured `ServerMsg::Goodbye {
            //      reason: ReplacedByNewerConnection }` via try_send.
            //   2. `notify_waiters()` on the cancel so the read-loop
            //      exits within milliseconds.
            //   3. drop(prev) — closes the channel; pump task exits
            //      cleanly after forwarding the Goodbye to the socket.
            warn!(
                "agent {} reconnected; notifying previous connection with ReplacedByNewerConnection and dropping",
                agent_id
            );
            let goodbye = ServerMsg::Goodbye {
                reason: AgentCloseReason::ReplacedByNewerConnection,
                message: format!(
                    "Another agent is connecting with the same agent_id ({agent_id}); \
                     this connection is being closed. Check for a duplicate install \
                     (another physical host with a copy of this config.toml, the tray \
                     companion, etc.) or re-enrol to mint a fresh agent_id."
                ),
            };
            match prev.tx.try_send(goodbye) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // SERVER_TX_CAPACITY is 64; under contention the pump
                    // may not have drained yet. Operator sees this and
                    // knows the displaced agent likely missed the message
                    // and will reconnect via the raw-close path.
                    warn!(
                        "agent {agent_id} displacement goodbye dropped (channel full); \
                         displaced agent will see raw close only"
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Displaced agent's pump task already exited; the
                    // socket-close path will fire on its next read.
                }
            }
            // `notify_one` (NOT notify_waiters) — the former LATCHES the
            // notification when no waiter is parked, the latter just
            // broadcasts to currently-parked waiters. Auto-fail #5 in
            // the v2 plan: if the displacement fires before the
            // displaced handler entered its select-loop (extreme race),
            // notify_waiters would lose the signal and the old socket
            // would linger waiting on its 25 s keepalive. notify_one's
            // permit storage closes that hole.
            prev.cancel.notify_one();
            drop(prev);
        }
        info!("agent {} online", agent_id);
        // Task #8 — agent-authoritative session resync. An ACTIVE session
        // cannot survive the agent's control-WS death: every agent-side
        // connection-teardown path closes its peers, and the fresh
        // connection starts with none — so any Active row still pinned to
        // this agent is a ZOMBIE whose Terminate was lost with the dying WS
        // (field 2026-08-15 winhost-a: red frame held, capacity held, the
        // controller's live tab retried into AgentBusy until a host-side
        // click). Reap now: `terminate` notifies the possibly-still-live
        // controller tab (its UI unblocks and may auto-reconnect), frees
        // the capacity slot, and re-sends Terminate over THIS fresh agent
        // connection, clearing a leaked indicator/peer. Mid-setup phases
        // (AwaitingConsent / Negotiating) are deliberately spared — they
        // legitimately span a WS flap and the consent re-push below plus
        // the negotiating reaper own their lifecycle.
        let zombies: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter(|e| {
                let s = e.value().lock();
                s.agent_id == agent_id && s.phase == SessionPhase::Active
            })
            .map(|e| *e.key())
            .collect();
        for session_id in zombies {
            warn!(
                %agent_id, %session_id,
                "agent re-registered with a stale ACTIVE session — reaping the zombie \
                 (its Terminate died with the previous control WS)"
            );
            let _ = self.terminate(session_id, EndReason::AgentDisconnect);
        }
        // Re-push any consent-pending Request to the fresh connection: an
        // agent whose control WS flapped between the Request and its
        // `rc:consent` reply lost the exchange (2026-08-05 winhost-a — three
        // sessions parked in AwaitingConsent during a VPN-churn window). The
        // agent handles a duplicate Request idempotently (its consent broker
        // re-runs; a second `rc:consent` for an already-resolved slot is a
        // benign "consent already delivered" warn).
        for e in self.inner.sessions.iter() {
            let request = {
                let s = e.value().lock();
                if s.agent_id == agent_id && s.phase == SessionPhase::AwaitingConsent {
                    s.pending_request.clone()
                } else {
                    None
                }
            };
            if let Some(req) = request {
                info!(
                    session = %e.key().to_hex(),
                    "agent {} reconnected with consent pending — re-pushing Request",
                    agent_id
                );
                let _ = tx.try_send(req);
            }
        }
        (tx, cancel, rx)
    }

    /// Unregister a connected agent. The optional `tx` is the channel
    /// the caller captured at registration time; when provided, the
    /// removal happens ONLY if the currently-registered tx is still
    /// the same channel. This protects against a pre-existing race
    /// (rc.53 critique #4) where a displaced `handle_agent_socket`'s
    /// late unregister evicted the NEWER displacing connection's
    /// registry entry, killing its in-flight sessions.
    ///
    /// `None` removes unconditionally. A device's REMOVAL does not come
    /// here: it goes through [`Self::kick_removed_agent`], which also tells
    /// the device (#2267).
    ///
    /// Returns whether the removal was OURS (Phase A-1): callers gate
    /// the Mongo `mark_status(Offline)` + Redis presence delete on it,
    /// because a displaced handler's late teardown writing Offline over
    /// the displacing connection's Online was a live status-clobber
    /// race (the same race rc.53 fixed for the registry entry itself).
    pub fn unregister_agent(&self, agent_id: ObjectId, tx: Option<&ClientTx>) -> bool {
        if let Some(expected_tx) = tx {
            // Identity-gated removal. Read the current entry's tx
            // under the DashMap lock and compare; if it doesn't match
            // ours, a newer connection has already taken over this
            // slot — leave it alone.
            let still_ours = self
                .inner
                .agents
                .get(&agent_id)
                .map(|a| ptr_eq(&a.tx, expected_tx))
                .unwrap_or(false);
            if !still_ours {
                info!(
                    "agent {} unregister skipped (tx no longer matches; newer connection holds the slot)",
                    agent_id
                );
                return false;
            }
        }
        let removed = self.inner.agents.remove(&agent_id).is_some();
        if removed {
            info!("agent {} offline", agent_id);
            self.end_agent_sessions(agent_id);
        }
        removed
    }

    /// Force-close every session tied to this agent.
    fn end_agent_sessions(&self, agent_id: ObjectId) {
        let dead: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter_map(|s| {
                let live = s.value().lock();
                (live.agent_id == agent_id).then_some(*s.key())
            })
            .collect();
        for sid in dead {
            let _ = self.terminate(sid, EndReason::AgentDisconnect);
        }
    }

    /// #2267 — the kick at the end of a device's removal (fleet's
    /// `removal::remove_agent_device`, an archive's revocation, and the `kick`
    /// control event on the pod that holds the socket).
    ///
    /// The entry leaves the hub first, as [`Self::unregister_agent`] with no
    /// tx identity, so nothing addresses the device from here on and its
    /// sessions end. Then, when `goodbye`, `rc:goodbye AgentDeleted` is queued
    /// on the connection the entry held. The channel is FIFO and the socket's
    /// handler keeps its own sender, so the pump still delivers what was
    /// queued before (P2g-4a's purge) and then the goodbye. The daemon stops
    /// on it exactly as it does at a refused connection (exit 7), and closes
    /// the socket itself, so no cancel is needed. Before #2267 the kick ended
    /// here without the goodbye, and the device kept its socket until
    /// something else dropped it.
    ///
    /// ⚠️ An entry that this removal pushed `rc:hive.purge_all` is told only
    /// when its build drains (`hive-purge-drain`, #2294): that daemon finishes
    /// the purge before it exits on the goodbye. One of `agent-v0.4.137` or
    /// `0.4.138` would exit at once and cut its purge short, so its socket
    /// stays open as before, which P2g-4a relies on.
    pub fn kick_removed_agent(&self, agent_id: ObjectId, goodbye: bool) -> KickOutcome {
        let Some((_, entry)) = self.inner.agents.remove(&agent_id) else {
            return KickOutcome::NotRegistered;
        };
        info!("agent {} offline (removed)", agent_id);
        self.end_agent_sessions(agent_id);
        if !goodbye {
            return KickOutcome::NotTold;
        }
        if entry.removal_purge_pushed && !entry.supports_hive_purge_drain {
            info!(
                %agent_id,
                "removed device not told: it was sent its purge, which the goodbye's exit would cut short; its socket stays open"
            );
            return KickOutcome::KeptForPurge;
        }
        let msg = ServerMsg::Goodbye {
            reason: AgentCloseReason::AgentDeleted,
            message: "This device was removed from its organization. Re-enrol it with a \
                      fresh enrollment token from the admin UI \
                      (`roomlerd re-enroll --token <jwt>`)."
                .into(),
        };
        match entry.tx.try_send(msg) {
            Ok(()) => KickOutcome::Told,
            Err(e) => {
                warn!(%agent_id, %e, "removed device's goodbye not queued; its socket ends as before #2267");
                KickOutcome::GoodbyeLost
            }
        }
    }

    /// C-2 — the idle-agent nudge: close an agent's WS (via its
    /// displacement-cancel notify — the read loop exits within
    /// milliseconds and runs the normal teardown) so its reconnect
    /// re-hashes through the LB onto the pod the current map points at.
    /// STRICTLY idle-only: an active rc session or (per `extra_busy`,
    /// the caller's tunnel-session checks) a live tunnel flow means the
    /// truthful answer to the requester is "busy", not a forced move —
    /// a cycle tears the agent's rc + tunnel + overlay planes for
    /// seconds. PR-1: the outcome names the refusal reason so the bus
    /// reply (and the requesting pod's logs) stay truthful.
    pub fn nudge_agent_if_idle(&self, agent_id: ObjectId, extra_busy: bool) -> NudgeOutcome {
        if extra_busy {
            return NudgeOutcome::ExtraBusy;
        }
        let Some(agent) = self.inner.agents.get(&agent_id) else {
            return NudgeOutcome::NotRegistered;
        };
        if agent.active_sessions > 0 {
            return NudgeOutcome::RcBusy;
        }
        info!(
            "agent {} nudged (idle) — cycling its WS for LB re-hash",
            agent_id
        );
        // `notify_one` (NOT notify_waiters) — same rationale as the
        // displacement path in `register_agent`: notify_one LATCHES a
        // permit when no waiter is parked, so a nudge landing while the
        // read loop is between select iterations (mid-dispatch, mid-Mongo
        // write) still fires on the next `cancel.notified()`. The old
        // notify_waiters here silently LOST exactly those nudges while
        // still reporting success to the requesting pod.
        agent.cancel.notify_one();
        NudgeOutcome::Nudged
    }

    /// Multi-org P2b — cycle an agent's WS UNCONDITIONALLY, for a tenant
    /// overlay renumber. `false` when this pod doesn't hold the socket (the
    /// ctrl event reaches every pod; exactly one acts).
    ///
    /// Unlike [`Self::nudge_agent_if_idle`] this does NOT refuse a busy
    /// agent, and that is the point: the agent's overlay `self_ip` is bound
    /// once at establish, so a renumbered node keeps using its OLD address
    /// until the socket is re-established — there is no idle moment to wait
    /// for on a mesh that is in use. The caller is an explicit admin action
    /// that already reported which nodes it would cycle.
    ///
    /// ⚠️ A cycle tears the agent's rc/tunnel/overlay planes for seconds, and
    /// a host behind a strict corporate VPN can come back RELAY-LOCKED (it
    /// loses its established direct path and can't re-punch while the VPN
    /// client is armed). Renumber during a maintenance window.
    pub fn cycle_agent_ws(&self, agent_id: ObjectId) -> bool {
        let Some(agent) = self.inner.agents.get(&agent_id) else {
            return false;
        };
        info!("agent {agent_id} WS cycled (overlay renumber)");
        // notify_one, not notify_waiters — same latching rationale as the
        // nudge path: a cycle landing while the read loop is mid-dispatch
        // must still fire on the next `cancel.notified()`.
        agent.cancel.notify_one();
        true
    }

    /// Phase A-1 graceful shutdown: fire every registered agent's
    /// displacement-cancel notify so each read loop exits within
    /// milliseconds and runs its OWN teardown (unregister, gated
    /// mark-offline, presence release) — the per-socket teardown is the
    /// single source of cleanup truth, so shutdown reuses it instead of
    /// duplicating it. Returns the notified agent ids for the caller's
    /// belt-and-braces bulk cleanup.
    pub fn cancel_all_agents(&self) -> Vec<ObjectId> {
        let ids: Vec<ObjectId> = self.inner.agents.iter().map(|a| *a.key()).collect();
        for entry in self.inner.agents.iter() {
            entry.value().cancel.notify_waiters();
        }
        ids
    }

    /// Called by the WS handler when a controller browser tab connects.
    pub fn register_controller(&self, user_id: ObjectId) -> (ClientTx, mpsc::Receiver<ServerMsg>) {
        let (tx, rx) = mpsc::channel(SERVER_TX_CAPACITY);
        self.inner
            .controllers
            .entry(user_id)
            .or_default()
            .push(tx.clone());
        (tx, rx)
    }

    pub fn unregister_controller(&self, user_id: ObjectId, tx: &ClientTx) {
        if let Some(mut list) = self.inner.controllers.get_mut(&user_id) {
            list.retain(|t| !ptr_eq(t, tx));
        }

        // Terminate any sessions THIS CONNECTION still owns. Without this
        // the agent's active_sessions counter never drops when a browser
        // tab closes mid-session, and subsequent Connect attempts fail
        // with AgentBusy until the agent itself disconnects.
        //
        // P3 — keyed by the departing TX, not the user_id: this was
        // user-keyed and killed EVERY session of the user on ANY one tab
        // close — tab A's org-switch redial (#307 `setTenantAffinity`
        // closes the WS) tore down tab B's live session, and with
        // N-session support one closing watcher tab would have killed the
        // user's other sessions. A session mid-setup (tx not yet
        // registered) keeps its live channel, so it is never a false
        // positive; a session whose channel is already CLOSED is reaped
        // regardless of which tab it belonged to (the rc.185 orphan sweep
        // in `create_session` remains the belt for races).
        let orphaned: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter(|e| {
                let s = e.value().lock();
                s.controller_user_id == user_id
                    && s.controller_tx
                        .as_ref()
                        .map(|t| ptr_eq(t, tx) || t.is_closed())
                        .unwrap_or(false)
            })
            .map(|e| *e.key())
            .collect();
        for session_id in orphaned {
            let _ = self.terminate(session_id, EndReason::ControllerHangup);
        }
    }

    /// P3 — a live session's `(tenant_id, controller_user_id)`, for
    /// route-side authz + cross-pod ctrl tenant checks. `None` when this
    /// pod's hub doesn't hold the session (pod-local under S6).
    pub fn session_snapshot(&self, session_id: ObjectId) -> Option<(ObjectId, ObjectId)> {
        let arc = self.inner.sessions.get(&session_id)?;
        let s = arc.value().lock();
        Some((s.tenant_id, s.controller_user_id))
    }

    /// Refresh the cached relay home (+ RTT-ordered fallback ladder) of a
    /// connected agent — called by the WS layer at hello (from the DB row)
    /// and whenever a probe report changes the agent's picture. A
    /// disconnected agent is a no-op.
    pub fn set_agent_relay_home(
        &self,
        agent_id: ObjectId,
        home: Option<String>,
        prefs: Vec<String>,
    ) {
        if let Some(mut a) = self.inner.agents.get_mut(&agent_id) {
            a.relay_home = home;
            a.region_prefs = prefs;
        }
    }

    /// The connected agent's relay home, if any. Pub for the WS layer's
    /// probe-report hysteresis (compare-before-move).
    pub fn agent_relay_home(&self, agent_id: ObjectId) -> Option<String> {
        self.inner
            .agents
            .get(&agent_id)
            .and_then(|a| a.relay_home.clone())
    }

    /// The region frozen on a live session at create time (`None` = default
    /// region, or the session is gone).
    fn session_relay_region(&self, session_id: ObjectId) -> Option<String> {
        self.inner
            .sessions
            .get(&session_id)
            .and_then(|arc| arc.value().lock().relay_region.clone())
    }

    /// FR-115 P4b — the TURN `user_id` for a session's credentials: the
    /// controller, charged to the org that pays for the session's relay (the
    /// session's org), so coturn's statistics name it.
    fn turn_user(user_id: ObjectId, org: ObjectId) -> String {
        turn_creds::charged(&user_id.to_hex(), &org.to_hex())
    }

    // ─── session lifecycle ────────────────────────────────────────────

    /// Controller asked to start a session against `agent_id`.
    /// Creates the session, notifies the agent, returns the new session id.
    /// The caller (WS dispatcher) is expected to follow up by awaiting consent
    /// in a spawned task — see [`Self::run_consent_flow`].
    // Each new field on `rc:session.request` lands as another arg
    // here. Clippy's 7-arg threshold is conservative for an internal
    // helper whose call sites are exhaustive; allowing it is cheaper
    // than building a builder we'd never use elsewhere.
    #[allow(clippy::too_many_arguments)]
    pub fn create_session(
        &self,
        agent_id: ObjectId,
        controller_user_id: ObjectId,
        controller_name: String,
        controller_tx: ClientTx,
        permissions: Permissions,
        browser_caps: Vec<String>,
        preferred_transport: Option<String>,
        chroma_pref: Option<String>,
        chunk_framing: Option<bool>,
        audio_enabled: bool,
        consent_mode: ConsentMode,
        override_reason: Option<String>,
        local_relay: Option<LocalRelayDescriptor>,
        input_mode: Option<roomler_ai_remote_control::models::InputMode>,
        tenant_name: Option<String>,
    ) -> Result<ObjectId> {
        // FR-85 P3 — a caller that does not say may NOT record: RECORD is
        // stripped (the safe default for every path but the authz-gated one).
        // #1882 — nor may its session use the overlay: off is the default.
        // FR-101 P2 — and no org policy is known here, so nothing is
        // restricted by one: only tests take this path; production sessions
        // come through `dispatch`, whose context the authz gate filled.
        // FR-52 P4 — nor is it external: only the extauth relay makes one.
        self.create_session_full(
            agent_id,
            controller_user_id,
            controller_name,
            controller_tx,
            permissions,
            browser_caps,
            preferred_transport,
            chroma_pref,
            chunk_framing,
            audio_enabled,
            consent_mode,
            override_reason,
            local_relay,
            false,
            input_mode,
            tenant_name,
            false,
            OrgPolicy::Read(SessionPolicy::default()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// [`Self::create_session`], with the authz gate's `may_record` (FR-85
    /// P3): `Permissions::RECORD` survives only when it is `true` AND the
    /// agent serves remote recording.
    #[allow(clippy::too_many_arguments)]
    pub fn create_session_full(
        &self,
        agent_id: ObjectId,
        controller_user_id: ObjectId,
        controller_name: String,
        controller_tx: ClientTx,
        permissions: Permissions,
        browser_caps: Vec<String>,
        preferred_transport: Option<String>,
        chroma_pref: Option<String>,
        chunk_framing: Option<bool>,
        audio_enabled: bool,
        consent_mode: ConsentMode,
        override_reason: Option<String>,
        local_relay: Option<LocalRelayDescriptor>,
        // #1882 — the device's `AccessPolicy.rc_overlay`, resolved by the
        // authz gate. Rides `ServerMsg::Request`, and gates whether
        // `forward_offer` hands the agent `local_relay` at all.
        rc_overlay: bool,
        input_mode: Option<roomler_ai_remote_control::models::InputMode>,
        // Multi-org — display name of the requesting org, for the host's
        // consent prompt. See `ServerMsg::Request::tenant_name`.
        tenant_name: Option<String>,
        may_record: bool,
        // FR-101 P2 — the org's session policy, read by the authz gate.
        session_policy: OrgPolicy,
        // FR-101 P4b — the org's maximum session length, armed when the
        // session goes live. `None` = no limit.
        max_duration: Option<std::time::Duration>,
        // FR-101 P4b-2 — the idle limit, in seconds: the shorter of the org's
        // and the device's own, resolved by the authz gate. The device keeps
        // it; `None` = no idle limit.
        idle_secs: Option<u32>,
        // FR-99 P3b — what the device's access policy asks of the session's
        // end, resolved by the authz gate. `None` = nothing asked.
        lock_on_end: Option<LockOnEnd>,
        // FR-52 P4 — `Some` for an EXTERNAL session: the login the device must
        // bind it to, forwarded in `ServerMsg::Request`. Passed only by the
        // extauth relay (`roomler_ai_mod_remote::extauth`), after it found the
        // principal's verified login and checked the device advertises
        // `external-session`; `dispatch` always passes `None`.
        external: Option<roomler_ai_remote_control::signaling::ExternalGrant>,
        // FR-115 P3 — how many remote sessions the device's organization may
        // run at once (`DispatchCtx::org_session_cap`). `None` = no cap.
        org_session_cap: Option<u32>,
        // FR-115 P3b — a cluster-wide slot the async caller already claimed
        // for this session: the session is created under the lease's id, and
        // the hub renews the lease and gives it back when the session ends.
        // The caller passes `org_session_cap: None` with it (the slot IS the
        // count), and releases the slot itself when no session took its id
        // (a refusal, or a coalesced duplicate that returned another id).
        slot: Option<Lease>,
    ) -> Result<ObjectId> {
        self.create_session_full_scoped(
            agent_id,
            controller_user_id,
            controller_name,
            controller_tx,
            permissions,
            browser_caps,
            preferred_transport,
            chroma_pref,
            chunk_framing,
            audio_enabled,
            consent_mode,
            override_reason,
            local_relay,
            rc_overlay,
            input_mode,
            tenant_name,
            may_record,
            session_policy,
            max_duration,
            idle_secs,
            lock_on_end,
            external,
            org_session_cap,
            slot,
            None,
        )
    }

    fn create_session_full_scoped(
        &self,
        agent_id: ObjectId,
        controller_user_id: ObjectId,
        controller_name: String,
        controller_tx: ClientTx,
        permissions: Permissions,
        browser_caps: Vec<String>,
        preferred_transport: Option<String>,
        chroma_pref: Option<String>,
        chunk_framing: Option<bool>,
        audio_enabled: bool,
        consent_mode: ConsentMode,
        override_reason: Option<String>,
        local_relay: Option<LocalRelayDescriptor>,
        // #1882 — the device's `AccessPolicy.rc_overlay`, resolved by the
        // authz gate. Rides `ServerMsg::Request`, and gates whether
        // `forward_offer` hands the agent `local_relay` at all.
        rc_overlay: bool,
        input_mode: Option<roomler_ai_remote_control::models::InputMode>,
        // Multi-org — display name of the requesting org, for the host's
        // consent prompt. See `ServerMsg::Request::tenant_name`.
        tenant_name: Option<String>,
        may_record: bool,
        // FR-101 P2 — the org's session policy, read by the authz gate.
        session_policy: OrgPolicy,
        // FR-101 P4b — the org's maximum session length, armed when the
        // session goes live. `None` = no limit.
        max_duration: Option<std::time::Duration>,
        // FR-101 P4b-2 — the idle limit, in seconds: the shorter of the org's
        // and the device's own, resolved by the authz gate. The device keeps
        // it; `None` = no idle limit.
        idle_secs: Option<u32>,
        // FR-99 P3b — what the device's access policy asks of the session's
        // end, resolved by the authz gate. `None` = nothing asked.
        lock_on_end: Option<LockOnEnd>,
        // FR-52 P4 — `Some` for an EXTERNAL session: the login the device must
        // bind it to, forwarded in `ServerMsg::Request`. Passed only by the
        // extauth relay (`roomler_ai_mod_remote::extauth`), after it found the
        // principal's verified login and checked the device advertises
        // `external-session`; `dispatch` always passes `None`.
        external: Option<roomler_ai_remote_control::signaling::ExternalGrant>,
        // FR-115 P3 — how many remote sessions the device's organization may
        // run at once (`DispatchCtx::org_session_cap`). `None` = no cap.
        org_session_cap: Option<u32>,
        // FR-115 P3b — a cluster-wide slot the async caller already claimed
        // for this session: the session is created under the lease's id, and
        // the hub renews the lease and gives it back when the session ends.
        // The caller passes `org_session_cap: None` with it (the slot IS the
        // count), and releases the slot itself when no session took its id
        // (a refusal, or a coalesced duplicate that returned another id).
        slot: Option<Lease>,
        share_grant_id: Option<ObjectId>,
    ) -> Result<ObjectId> {
        let permissions = if share_grant_id.is_some() {
            permissions & (Permissions::VIEW | Permissions::INPUT | Permissions::FILES)
        } else {
            permissions
        };
        let device_share_scope = share_grant_id.map(|grant_id| {
            roomler_ai_remote_control::session::DeviceShareSessionScope {
                grant_id,
                ceiling: permissions,
            }
        });

        // rc.185 — self-heal the fast connect→disconnect race. A controller
        // that connects then drops before teardown completes can leave an
        // ORPHANED session pinned to this agent: `active_sessions` stays
        // elevated (the next reconnect hits `AgentBusy`) AND the agent's
        // "being viewed" red-frame indicator never clears (the
        // controller-disconnect cleanup missed the not-yet-registered
        // session, or the best-effort Terminate raced the socket close, or
        // the peer sits ~30 s in ICE-`Disconnected` before it reaches
        // `Failed` and self-terminates). Before the capacity gate, reap any
        // of THIS agent's sessions whose controller channel is already
        // closed. `terminate()` frees the counter AND re-sends
        // `ServerMsg::Terminate` to the agent, which clears the stale
        // indicator + peer. Mirrors the iterate-and-lock pattern in
        // `unregister_controller`; a mid-setup session keeps a live
        // controller_tx so it is never a false positive.
        let orphaned: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter_map(|e| {
                let dead_controller = {
                    let s = e.value().lock();
                    s.agent_id == agent_id
                        && s.controller_tx
                            .as_ref()
                            .map(|tx| tx.is_closed())
                            .unwrap_or(true)
                };
                dead_controller.then(|| *e.key())
            })
            .collect();
        for sid in orphaned {
            let _ = self.terminate(sid, EndReason::ControllerHangup);
        }

        // #1045 — coalesce a DUPLICATE request that arrives on the SAME
        // controller CONNECTION already holding a LIVE session against this
        // agent, instead of minting a second. One Connect can emit two
        // `rc:session.request`s: an un-scoped transient `rc:error` (e.g. an
        // `agent_offline` bounced by our own hangup for a prior session while
        // the agent WS flaps) fires the viewer's reconnect ladder while the
        // first session still sits in AwaitingConsent, and that retry rides the
        // SAME WS socket. The orphan reap above only clears DEAD controllers; a
        // still-pending first session keeps an OPEN controller_tx, so on a P6
        // agent (max_sessions >= 2 for multi-viewer, which lets the request past
        // the AgentBusy gate below) the second request created a second session
        // AND a second host consent prompt on a second surface (the native panel
        // is single-instance, so #2 fell to the companion — the field symptom).
        //
        // Keyed on the CONNECTION (`same_channel`), not the user: two genuine
        // TABS of one user are two WS connections and must each get their own
        // session (multi-viewer + #307's per-connection teardown stay intact);
        // a retry from one tab is the same channel. Re-point the requester at the
        // existing session — no new agent Request means no second prompt, and the
        // session counter is untouched.
        let existing = self.inner.sessions.iter().find_map(|e| {
            let s = e.value().lock();
            let is_dup = s.agent_id == agent_id
                && s.device_share_scope() == device_share_scope
                && s.controller_tx
                    .as_ref()
                    .map(|tx| ptr_eq(tx, &controller_tx) && !tx.is_closed())
                    .unwrap_or(false);
            is_dup.then(|| {
                (
                    s.id,
                    s.permissions(),
                    s.record_refused,
                    s.privacy_refused,
                    s.features_refused.clone(),
                    s.idle_secs,
                )
            })
        });
        if let Some((
            existing_id,
            existing_perms,
            existing_record_refused,
            existing_privacy_refused,
            existing_features_refused,
            existing_idle_secs,
        )) = existing
        {
            info!(
                "coalescing duplicate rc:session.request from controller {} to agent {} onto live \
                 session {} (same connection; no second consent prompt)",
                controller_user_id.to_hex(),
                agent_id.to_hex(),
                existing_id.to_hex()
            );
            // Answer the requesting controller with the REAL session id so its
            // viewer converges on the one session. Sent to the NEW controller_tx
            // (this request's socket) — the same controller. Every retry path
            // resets the viewer to `requesting` before it re-sends, so the
            // `rc:session.created` handler adopts this id rather than treating it
            // as a ghost.
            let _ = controller_tx.try_send(ServerMsg::SessionCreated {
                session_id: existing_id,
                // FR-52 P4 — an outsider never needs the internal id.
                agent_id: if external.is_some() {
                    ObjectId::from_bytes([0; 12])
                } else {
                    agent_id
                },
                permissions: Some(existing_perms),
                // FR-85 P3 — the SAME grant, so the same reason: a retry
                // must not read as "RECORD was never asked for".
                record_refused: existing_record_refused.map(str::to_string),
                // FR-99 — and the same for PRIVACY.
                privacy_refused: existing_privacy_refused.map(str::to_string),
                // FR-101 P2 — and for the features the policy refused.
                features_refused: refusals_wire(&existing_features_refused),
                // FR-101 P4b-2 — and the idle limit it runs under.
                idle_secs: existing_idle_secs,
            });
            return Ok(existing_id);
        }

        // FR-115 P3 — the organization's concurrent-session cap. After the
        // duplicate coalesce above (a retry on the same connection re-points
        // at its own session and spends no slot), before the device's slot
        // is taken below. Counted on this hub, the one that owns the device:
        // under tenant affinity that is every live session of the device's
        // org, and the cross-pod relay brings a request from the other pod
        // here with its cap. It refuses only the NEW session; a live one is
        // never ended (business-model §6 rule 4).
        // ⚠️ The count and the insert below are not one atomic step, so two
        // starts in the same instant can both pass: at worst an org runs one
        // session over its plan for that session's life, which a plan fence
        // can afford and a lock on every session start could not.
        if let Some(cap) = org_session_cap {
            let org = self
                .inner
                .agents
                .get(&agent_id)
                .map(|a| a.tenant_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            let mut live: u32 = 0;
            let mut holder: Option<(ObjectId, ObjectId)> = None;
            for e in self.inner.sessions.iter() {
                let s = e.value().lock();
                if s.tenant_id == org && s.phase != SessionPhase::Closed {
                    live = live.saturating_add(1);
                    holder.get_or_insert((s.controller_user_id, s.agent_id));
                }
            }
            if live >= cap {
                let (holder_user, holder_agent) = holder.unwrap_or((controller_user_id, agent_id));
                info!(
                    org = %org.to_hex(), cap, live,
                    controller = %controller_user_id.to_hex(), agent = %agent_id.to_hex(),
                    "rc:session.request refused: the organization is at its plan's session cap"
                );
                return Err(Error::OrgSessionLimit {
                    cap,
                    holder_user: holder_user.to_hex(),
                    holder_agent: holder_agent.to_hex(),
                });
            }
        }

        let (
            agent_org,
            agent_arbitrates,
            agent_records,
            agent_privacy,
            agent_asks,
            agent_floor,
            agent_enforces_idle,
            agent_honours_lock,
        ) = {
            let mut agent = self
                .inner
                .agents
                .get_mut(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if agent.active_sessions >= agent.max_sessions {
                return Err(Error::AgentBusy);
            }
            agent.active_sessions += 1;
            (
                agent.tenant_id,
                agent.input_arbiter,
                agent.record_support,
                agent.privacy_support,
                agent.asks_features,
                agent.device_session_policy,
                agent.enforces_idle,
                agent.honours_lock_on_end,
            )
        };

        // Multi-user P3 back-compat — the FILES bit becomes agent-ENFORCED in
        // this release, but every pre-P3 viewer requests the legacy triple
        // (VIEW|INPUT|CLIPBOARD, also `Permissions::default()`) and file
        // transfer has ALWAYS worked under it. Grandfather exactly that grant
        // to include FILES so a cached pre-P3 tab doesn't lose its file
        // toolbar against a P3 agent; new viewers request FILES explicitly,
        // and any OTHER combination (a genuine view-only watcher, a narrowed
        // grant) is taken literally. Remove once pre-P3 viewers age out.
        //
        // ⚠️ FR-52 P4 — NEVER for an external session. Its grant was clamped
        // to the org's ceiling before it got here, and a ceiling of exactly
        // VIEW|INPUT|CLIPBOARD would come out of this line with FILES added:
        // file transfer for an outsider that no admin granted. There are no
        // pre-P3 external viewers to grandfather.
        let permissions = if external.is_none() && permissions == Permissions::default() {
            permissions | Permissions::FILES
        } else {
            permissions
        };

        // Multi-user P3 → P6 — the single-INPUT-holder rule is now
        // CONDITIONAL on the agent's capabilities. A P6 agent advertises the
        // InputArbiter (`AgentCaps.input` contains "arbiter"): all its
        // sessions' events flow through ONE fenced injection worker
        // (free-for-all default, exclusive floor per policy/in-session
        // toggle), so concurrent INPUT grants are safe and the strip is
        // lifted. A pre-P6 agent injects per-session with no fencing —
        // for those, a session requested while another LIVE session holds
        // INPUT is still downgraded to view-effective (INPUT stripped;
        // VIEW/CLIPBOARD/FILES kept). The effective grant travels in
        // `SessionCreated.permissions` (viewer) and `Request.permissions`
        // (agent-enforced on the input DC).
        let permissions = if permissions.contains(Permissions::INPUT)
            && !agent_arbitrates
            && self.inner.sessions.iter().any(|e| {
                let s = e.value().lock();
                s.agent_id == agent_id && s.permissions().contains(Permissions::INPUT)
            }) {
            info!(
                "agent {} already has an INPUT-holding session and does not arbitrate — new \
                 session is view-effective (P3 single-holder rule for pre-P6 agents)",
                agent_id.to_hex()
            );
            permissions - Permissions::INPUT
        } else {
            permissions
        };

        // FR-85 P3 — RECORD survives only for a controller the authz gate let
        // record (owner / ADMINISTRATOR / RECORD_REMOTE_SCREEN, never
        // break-glass) on an agent that serves it (its owner opted in, so it
        // advertises the `record` cap). Anything else is stripped here, and
        // the reason travels in the audit and to the viewer — never silently.
        let (permissions, record_refused) = record_grant(permissions, may_record, agent_records);

        // FR-99 — PRIVACY survives only on an agent that serves privacy mode
        // (its owner opted in, so it advertises `privacy-mode`), never under
        // break-glass, and never for a controller from outside the org
        // (FR-52). The authz gate sets `override_reason` for a validated
        // ADMINISTRATOR force and only then, so it IS the break-glass signal
        // here — on this pod and on an owner pod the frame was relayed to
        // alike, since the relay carries it. `external` is set by the extauth
        // relay alone, on whichever pod holds the device. Anything else is
        // stripped BEFORE `rc:request` is built: an agent that does not know
        // the name would fail the whole frame.
        let (permissions, privacy_refused) = privacy_grant(
            permissions,
            override_reason.is_some(),
            external.is_some(),
            agent_privacy,
        );

        // FR-101 P2 — clipboard, files and audio under the org's policy:
        // `off` is stripped for every controller, and `ask` survives only a
        // host prompt that names it. After the FILES grandfathering above, so
        // a legacy grant's implied FILES is refused like an explicit one;
        // before `rc:request` is built, so the agent and the viewer see the
        // same grant. A break-glass session reaches here as `Auto`, so it
        // never keeps an `ask` feature. P2b — with the device owner's floor
        // from its caps, so what the device will refuse is named here too.
        let (permissions, audio_enabled, features_refused) = feature_grant(
            permissions,
            audio_enabled,
            session_policy,
            agent_floor,
            consent_mode,
            agent_asks,
        );
        if !features_refused.is_empty() {
            info!(
                agent = %agent_id.to_hex(),
                controller = %controller_user_id.to_hex(),
                refused = ?features_refused,
                "rc:session.request — session features refused by policy"
            );
        }

        // FR-115 P3b — the id the caller claimed a slot for, when it did.
        let session_id = slot.as_ref().map_or_else(ObjectId::new, |l| l.session);
        let (mut live, waiter) = LiveSession::new(
            session_id,
            agent_id,
            agent_org,
            controller_user_id,
            permissions,
            controller_tx.clone(),
        );
        if let Some(scope) = device_share_scope {
            live.bind_device_share(scope)?;
            live.set_shared_lease_epoch(uuid::Uuid::new_v4().to_string())?;
        }
        // Loopback-TURN corp-relay (Phase 2): remember the controller's local
        // agent TURN descriptor so `forward_offer` can hand the REMOTE agent a
        // relay it reaches over the overlay. Validated at use, not here.
        live.local_relay = local_relay;
        live.rc_overlay = rc_overlay;
        // FR-27 — `deliver_consent` needs the mode to know whether a host-side
        // timeout ends the session or hands over to the owner's emailed link.
        live.consent_mode = consent_mode;
        // FR-85 P3 — kept for a duplicate request coalesced onto this session.
        live.record_refused = record_refused;
        // FR-99 — likewise.
        live.privacy_refused = privacy_refused;
        // FR-101 P2 — likewise.
        live.features_refused = features_refused.clone();
        // FR-101 P4b — armed when the session goes live (`forward_answer`).
        live.max_duration = max_duration;
        // FR-101 P4b-2 — the idle limit is the DEVICE's to keep, so the
        // viewer is told one only where the agent advertises it: a limit an
        // older agent ignores would be a promise nothing keeps.
        let idle_told = idle_secs.filter(|_| agent_enforces_idle);
        live.idle_secs = idle_told;
        // Multi-region relay: freeze the session's region NOW — a load-aware
        // pick over the agent's home + its RTT-ordered prefs — so Ready/
        // Offer/Answer all issue from the same PoP regardless of mid-setup
        // home or busy-flag churn.
        live.relay_region = self
            .inner
            .agents
            .get(&agent_id)
            .map(|a| (a.relay_home.clone(), a.region_prefs.clone()))
            .and_then(|(home, prefs)| {
                pick_region_with_load(
                    &self.inner.turn,
                    &self.inner.relay_load,
                    home.as_deref(),
                    &prefs,
                )
            });
        self.inner
            .sessions
            .insert(session_id, Arc::new(Mutex::new(live)));
        // FR-115 P3b — from here the session holds its slot: renewed by this
        // pod, given back when it ends.
        if let Some(lease) = slot {
            self.inner.slotted.insert(session_id, lease);
        }

        // Tell the controller the session id + its EFFECTIVE grant (which the
        // single-INPUT-holder rule above may have narrowed).
        //
        // FR-52 P4 — an EXTERNAL controller gets a zero agent id: it named the
        // device by connect code, and an outsider never needs the internal id
        // (the property `rc:extauth.session` is shaped around).
        let _ = controller_tx.try_send(ServerMsg::SessionCreated {
            session_id,
            agent_id: if external.is_some() {
                ObjectId::from_bytes([0; 12])
            } else {
                agent_id
            },
            permissions: Some(permissions),
            record_refused: record_refused.map(str::to_string),
            privacy_refused: privacy_refused.map(str::to_string),
            features_refused: refusals_wire(&features_refused),
            idle_secs: idle_told,
        });

        // Per-mode consent window: modes with an owner-side (email/push) leg get
        // a much longer window than the pure on-host prompt — `PromptThenEmail`
        // included, since its host prompt runs alongside the emailed link and the
        // owner needs time to act.
        let timeout = match consent_mode {
            ConsentMode::Email | ConsentMode::Push | ConsentMode::PromptThenEmail => {
                ASYNC_CONSENT_TIMEOUT
            }
            _ => DEFAULT_CONSENT_TIMEOUT,
        };
        // FR-27 — the ON-HOST half of that window. Same as the session window
        // for a plain attended prompt; the attended window (not the async one)
        // for `PromptThenEmail`, whose host modal has no business standing on
        // someone's screen for five minutes while the owner reads their mail.
        // A host timeout under that mode does NOT end the session — see
        // `deliver_consent`.
        let host_prompt_timeout = match consent_mode {
            ConsentMode::PromptThenEmail => HOST_PROMPT_TIMEOUT,
            _ => timeout,
        };

        // Move to AwaitingConsent and tell the agent. The agent always gets the
        // Request (it needs the codec / transport context) + the mode directive;
        // for Email/Push it will NOT respond — the owner resolves the slot.
        let shared_lease = self.shared_lease(session_id);
        let request = ServerMsg::Request {
            shared_lease,
            session_id,
            controller_user_id,
            controller_name: controller_name.clone(),
            permissions,
            consent_timeout_secs: timeout.as_secs() as u32,
            browser_caps,
            preferred_transport,
            chroma_pref,
            chunk_framing,
            audio_enabled,
            // Server-authoritative directive: the agent obeys this rather than
            // its local `auto_grant_session`. `Auto` → immediate grant;
            // `Prompt` → on-host prompt; `Email`/`Push` → wait (owner resolves).
            consent_mode: Some(consent_mode),
            host_prompt_timeout_secs: Some(host_prompt_timeout.as_secs() as u32),
            // P6 — the device policy's arbitration mode for the agent's
            // InputArbiter (first session seeds; toggles win afterwards).
            input_mode,
            // Multi-org — so the host prompt names the asking organization.
            tenant_name,
            // #1882 — may this session's ICE use the overlay (default off).
            rc_overlay,
            // FR-101 P2 — the org's policy, for an agent that names `ask`
            // features on its prompt and enforces the rest. Left off the
            // frame when it restricts nothing, as before the field.
            session_policy: session_policy.for_agent(),
            // FR-101 P4b-2 — the idle limit, to every agent: one that keeps it
            // measures and ends the session; an older one ignores the field.
            idle_secs,
            // FR-99 P3b — the lock ask, only to an agent that honours it.
            lock_on_end: lock_on_end.filter(|_| agent_honours_lock),
            // FR-52 P4 — and, for an outsider, the login the device must bind
            // this session to. Kept in `pending_request` below, so a re-push
            // after an agent-socket flap carries it too.
            external,
        };
        // Keep the Request while consent is pending so `register_agent` can
        // re-push it if the agent's control WS flaps before `rc:consent`
        // lands (the exchange is otherwise lost and the session parks in
        // AwaitingConsent until the consent timeout).
        self.with_session(session_id, |s| {
            s.pending_request = Some(request.clone());
            s.transition(SessionPhase::AwaitingConsent)
        })?;
        let agent_tx = self.agent_tx(agent_id)?;
        let _ = agent_tx.try_send(request);

        self.audit(
            session_id,
            agent_id,
            agent_org,
            AuditKind::SessionRequested {
                controller_user_id,
                controller_name: controller_name.clone(),
                permissions,
                record_stripped: record_refused.map(str::to_string),
                privacy_stripped: privacy_refused.map(str::to_string),
                features_stripped: refusals_wire(&features_refused),
                idle_secs,
                idle_enforced: idle_secs.map(|_| agent_enforces_idle),
                lock_on_end,
                lock_enforced: lock_on_end.map(|_| agent_honours_lock),
            },
        );
        self.audit(session_id, agent_id, agent_org, AuditKind::ConsentPrompted);

        // Phase 5 — record the break-glass BEFORE the session proceeds. The API
        // gate only sets `override_reason` for a validated `ADMINISTRATOR` force;
        // `consent_mode` was resolved to `Auto` alongside it, so consent is
        // skipped and this audit is the accountability trail for it.
        let override_for_notify = override_reason.clone();
        if let Some(reason) = override_reason {
            self.audit(
                session_id,
                agent_id,
                agent_org,
                AuditKind::AdminOverride { reason },
            );
        }

        // Phase 4/5 — owner-side notification: an Email/Push APPROVAL request, or
        // (when a break-glass just happened) an informational "your device was
        // accessed" NOTICE. Best-effort; the API consumer resolves the owner from
        // `agent_id`. With no consumer wired the session relies on the waiter.
        if (matches!(
            consent_mode,
            ConsentMode::Email | ConsentMode::Push | ConsentMode::PromptThenEmail
        ) || override_for_notify.is_some())
            && let Some(tx) = &self.inner.consent_tx
        {
            let _ = tx.try_send(ConsentEvent {
                session_id,
                agent_id,
                tenant_id: agent_org,
                controller_user_id,
                controller_name,
                mode: consent_mode,
                timeout_secs: timeout.as_secs() as u32,
                override_reason: override_for_notify,
            });
        }

        // Spawn the consent watcher. FR-27: it waits GRACE longer than the
        // window it just announced to the agent, because the agent's verdict
        // arrives ~130 ms after that window on every non-answer and is the
        // one carrying a reason (`timeout` vs `no_prompt_surface`). Measured
        // on mars 2026-08-29: with an equal wait the hub terminated first and
        // every `no_prompt_surface` reached the controller as "nobody
        // answered". This timer is the backstop for a dead agent, not a
        // competitor of a live one — see `consent::CONSENT_VERDICT_GRACE`.
        let hub = self.clone();
        tokio::spawn(async move {
            let outcome = waiter.wait(hub_consent_deadline(timeout)).await;
            hub.handle_consent_outcome(session_id, outcome);
        });

        Ok(session_id)
    }

    fn handle_consent_outcome(&self, session_id: ObjectId, outcome: ConsentOutcome) {
        let (agent_id, tenant_id, controller_tx) = {
            let Some(arc) = self.inner.sessions.get(&session_id) else {
                return;
            };
            let s = arc.value().lock();
            (s.agent_id, s.tenant_id, s.controller_tx.clone())
        };

        match outcome {
            ConsentOutcome::Granted => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentGranted);
                if let Err(e) = self.with_session(session_id, |s| {
                    s.pending_request = None;
                    s.transition(SessionPhase::Negotiating)
                }) {
                    warn!("post-consent transition failed: {e}");
                    let _ = self.terminate(session_id, EndReason::Error);
                    return;
                }
                // Tell the controller it can send its offer.
                if let Some(tx) = controller_tx {
                    let user_id = self.controller_for(session_id).unwrap_or_default();
                    // Region policy: the session's region was FROZEN (load-
                    // aware, agent-nearest) at create — all three issuance
                    // pushes read it so both ICE ends land on one PoP.
                    let region = self.session_relay_region(session_id);
                    let ice = ice_servers_for_session(
                        &Self::turn_user(user_id, tenant_id),
                        &session_id.to_hex(),
                        self.inner.turn.cfg_for(region.as_deref()),
                    );
                    let _ = tx.try_send(ServerMsg::Ready {
                        session_id,
                        ice_servers: ice,
                    });
                }
                // Negotiating reaper: consent granted + `Ready` pushed, but the
                // controller's offer never arrives when its socket died or its
                // reply raced a client teardown. Without a deadline the session
                // sits in `Negotiating` forever while the browser shows
                // "awaiting consent" (2026-08-05 winhost-a). `EndReason::Error`
                // is deliberate — the controller's terminate handler treats it
                // as retryable, so a live UI auto-reconnects cleanly.
                let hub = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(NEGOTIATING_TIMEOUT).await;
                    hub.reap_stalled_negotiation(session_id);
                });
            }
            ConsentOutcome::Denied => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentDenied);
                let _ = self.terminate(session_id, EndReason::UserDenied);
            }
            ConsentOutcome::Timeout => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentTimedOut);
                let _ = self.terminate(session_id, EndReason::ConsentTimeout);
            }
            // FR-27 — audited as a timeout (nobody answered is what happened)
            // but terminated distinctly, because the controller's next move is
            // different: nobody CAN answer on that host until it gets a prompt
            // surface, or the device moves to email/push.
            ConsentOutcome::NoPromptSurface => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentTimedOut);
                let _ = self.terminate(session_id, EndReason::NoPromptSurface);
            }
        }
    }

    /// Negotiating reaper body: terminate a session whose consent was granted
    /// but whose controller never sent an offer (it never heard `Ready`).
    /// No-op when the offer arrived or the session already moved on.
    fn reap_stalled_negotiation(&self, session_id: ObjectId) {
        let stalled = self
            .inner
            .sessions
            .get(&session_id)
            .map(|arc| {
                let s = arc.value().lock();
                s.phase == SessionPhase::Negotiating && !s.offer_seen
            })
            .unwrap_or(false);
        if stalled {
            warn!(
                session = %session_id.to_hex(),
                "consent granted but no SDP offer within {}s — the controller \
                 likely never received Ready; terminating so its ladder can retry",
                NEGOTIATING_TIMEOUT.as_secs()
            );
            let _ = self.terminate(session_id, EndReason::Error);
        }
    }

    /// Caller: WS dispatcher when it sees `rc:consent` from agent.
    /// Resolve a session's consent slot from an agent reply or an approve-link.
    ///
    /// `reason` is FR-27's `rc:consent.reason` — absent (or unrecognised) means
    /// an ordinary deny, which is what a bare `granted: false` has always meant.
    /// The approve-link route passes `None`: a human clicked a button there.
    pub fn deliver_consent(
        &self,
        session_id: ObjectId,
        granted: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let outcome = roomler_ai_remote_control::consent::outcome_of(granted, reason);
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;

        // FR-27 — `prompt_then_email` runs BOTH legs. The host modal closes
        // after the attended window while the emailed link stays live for the
        // full async one, so a host-side non-answer is a handover, not a
        // verdict: leave the slot armed and let the owner (or our own waiter)
        // decide. An explicit host Deny is a verdict and does resolve — the
        // person at the machine said no.
        let handover = {
            let s = arc.value().lock();
            s.consent_mode == ConsentMode::PromptThenEmail
                && matches!(
                    outcome,
                    ConsentOutcome::Timeout | ConsentOutcome::NoPromptSurface
                )
        };
        if handover {
            info!(
                session = %session_id.to_hex(), ?outcome,
                "host prompt went unanswered under prompt_then_email — session stays open \
                 for the owner's approve-link"
            );
            // The agent HAS the Request and has already acted on it; a
            // reconnect must not replay the modal.
            arc.value().lock().pending_request = None;
            return Ok(());
        }

        let slot = {
            let mut s = arc.value().lock();
            // Consent is in flight — the agent evidently has the Request, so
            // a later agent reconnect must not replay it.
            s.pending_request = None;
            s.consent_slot.take()
        };
        slot.ok_or_else(|| Error::BadMessage("consent already delivered"))?
            .resolve(outcome)
    }

    // ─── SDP / ICE forwarding ────────────────────────────────────────

    /// Forward controller's SDP offer to the agent.
    /// `extauth_mac` (FR-52 P4) is relayed verbatim: the server never holds the
    /// key to check it and must never drop it — the device refuses an external
    /// offer without one.
    ///
    /// ⚠️ Only after consent, and only once — see `LiveSession::admit_offer`.
    /// The agent builds a peer from any offer that reaches it, so this is the
    /// server's half of the consent gate for the media path; before it, an
    /// offer sent straight after `rc:session.created` streamed the screen
    /// while the host's prompt still stood.
    pub fn forward_offer(
        &self,
        session_id: ObjectId,
        sdp: String,
        extauth_mac: Option<String>,
        // FR-100 P1b — relayed verbatim, as `extauth_mac` is: the nonce the
        // device signs its answer against. The hub never reads it.
        peer_auth: Option<roomler_ai_remote_control::signaling::PeerAuthOffer>,
    ) -> Result<()> {
        let (agent_id, local_relay, rc_overlay, region, org, shared_lease) =
            self.with_session(session_id, |s| {
                // Also what stands the negotiating reaper down: once an offer
                // exists, the ICE layer owns liveness.
                s.admit_offer()?;
                Ok((
                    s.agent_id,
                    s.local_relay.clone(),
                    s.rc_overlay,
                    s.relay_region.clone(),
                    s.tenant_id,
                    match s.device_share_scope() {
                        Some(scope) => {
                            Some(roomler_ai_remote_control::signaling::SharedSessionLease {
                                grant_id: scope.grant_id,
                                lease_epoch: s
                                    .shared_lease_epoch()
                                    .ok_or(Error::PermissionDenied(
                                        "shared session missing immutable lease",
                                    ))?
                                    .to_string(),
                            })
                        }
                        None => None,
                    },
                ))
            })?;
        let user_id = self.controller_for(session_id).unwrap_or_default();
        let mut ice = ice_servers_for_session(
            &Self::turn_user(user_id, org),
            &session_id.to_hex(),
            self.inner.turn.cfg_for(region.as_deref()),
        );
        // Loopback-TURN corp-relay (Phase 2): if the controller forwarded its
        // local agent's TURN descriptor, hand the REMOTE agent a relay it can
        // reach over the overlay (WFP-permitted, corp-traversal proven). This is
        // the SdpOffer→agent push — the one place the remote agent learns its
        // ICE servers — so it's where the overlay relay must be added. The IP is
        // validated inside the CGNAT overlay range so a controller can't coerce
        // the agent's TURN client into probing an arbitrary host.
        //
        // #1882 — and only for a device that lets RC use the overlay at all.
        // The relay IS an overlay path (the agent reaches it over the mesh), so
        // with the device's `rc_overlay` off it would be a candidate the agent
        // only discards; withholding it here also covers agents too old to.
        if let Some(lr) = local_relay {
            if !rc_overlay {
                info!(
                    session = %session_id.to_hex(),
                    relay = %format!("turn:{}:{}", lr.overlay_ip, lr.turn_port),
                    "loopback-TURN: not offered — the device does not let remote desktop use the overlay (rc_overlay off)"
                );
            } else if is_overlay_relay_ip(&lr.overlay_ip) && lr.turn_port != 0 {
                info!(
                    session = %session_id.to_hex(),
                    relay = %format!("turn:{}:{}", lr.overlay_ip, lr.turn_port),
                    "loopback-TURN: adding local-agent overlay relay to agent ICE"
                );
                ice.push(IceServer {
                    urls: vec![format!("turn:{}:{}", lr.overlay_ip, lr.turn_port)],
                    username: Some(lr.username),
                    credential: Some(lr.credential),
                });
            } else {
                warn!(
                    session = %session_id.to_hex(),
                    overlay_ip = %lr.overlay_ip,
                    turn_port = lr.turn_port,
                    "loopback-TURN: rejecting local_relay (not an overlay address)"
                );
            }
        }
        let agent_tx = self.agent_tx(agent_id)?;
        agent_tx
            .try_send(ServerMsg::SdpOffer {
                shared_lease,
                session_id,
                sdp,
                ice_servers: ice,
                extauth_mac,
                peer_auth,
            })
            .map_err(|_| Error::SendFailed)
    }

    /// Forward agent's SDP answer to the controller. `extauth_mac` (FR-52 P4)
    /// and `peer_auth` (FR-100 P1b, the device's signature) relayed verbatim,
    /// as for the offer: the browser is the party that checks them.
    ///
    /// FR-100 P1c — `peer_auth_verdict`, what the device concluded about the
    /// browser that offered the session, is the hub's to RECORD, not to relay:
    /// it lands on the session's `SessionStarted` audit row. A word this build
    /// does not know is not recorded (a newer device's vocabulary is not this
    /// server's to guess at), and nothing about it ever fails the answer.
    pub fn forward_answer(
        &self,
        session_id: ObjectId,
        sdp: String,
        extauth_mac: Option<String>,
        peer_auth: Option<roomler_ai_remote_control::signaling::PeerAuthAnswer>,
        peer_auth_verdict: Option<String>,
    ) -> Result<()> {
        let (controller_tx, user_id, region, org) = {
            let arc = self
                .inner
                .sessions
                .get(&session_id)
                .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
            let s = arc.value().lock();
            (
                s.controller_tx.clone(),
                s.controller_user_id,
                s.relay_region.clone(),
                s.tenant_id,
            )
        };
        let tx = controller_tx.ok_or(Error::SendFailed)?;
        let ice = ice_servers_for_session(
            &Self::turn_user(user_id, org),
            &session_id.to_hex(),
            self.inner.turn.cfg_for(region.as_deref()),
        );
        tx.try_send(ServerMsg::SdpAnswer {
            session_id,
            sdp,
            ice_servers: ice,
            extauth_mac,
            peer_auth,
        })
        .map_err(|_| Error::SendFailed)?;

        // Once the answer is in flight, mark the session active.
        // (The peers may still be doing ICE, but signaling is done from our POV.)
        self.with_session(session_id, |s| s.transition(SessionPhase::Active))?;
        let (sid, aid, oid, max_duration) = self.with_session(session_id, |s| {
            Ok((s.id, s.agent_id, s.tenant_id, s.max_duration.take()))
        })?;
        let peer_auth = peer_auth_verdict.filter(|v| {
            let known = roomler_ai_remote_control::signaling::peer_auth_verdict_is_known(v);
            if !known {
                debug!(session = %sid.to_hex(), verdict = %v.escape_debug(),
                    "peer-auth: a verdict this server does not know, not recorded");
            }
            known
        });
        self.audit(sid, aid, oid, AuditKind::SessionStarted { peer_auth });
        // FR-101 P4b — the org's maximum length runs from here, the moment the
        // session went live, not from the request: consent can take minutes.
        // Taken above, so a renegotiation never arms a second timer. A session
        // that ended first is simply gone when it fires (`terminate` is
        // idempotent, and a session id is never reused).
        if let Some(limit) = max_duration {
            let hub = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(limit).await;
                if hub.inner.sessions.contains_key(&sid) {
                    info!(
                        session = %sid.to_hex(),
                        limit_secs = limit.as_secs(),
                        "rc session reached the org's maximum length — ending it"
                    );
                    let _ =
                        hub.terminate_with_limit(sid, EndReason::IdleTimeout, Some("max_duration"));
                }
            });
        }
        Ok(())
    }

    /// Forward an ICE candidate to whichever side didn't send it.
    pub fn forward_ice(
        &self,
        role: Role,
        session_id: ObjectId,
        candidate: serde_json::Value,
    ) -> Result<()> {
        let (agent_id, controller_tx) = {
            let arc = self
                .inner
                .sessions
                .get(&session_id)
                .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
            let s = arc.value().lock();
            (s.agent_id, s.controller_tx.clone())
        };
        let dest_tx = match role {
            Role::Controller => self.agent_tx(agent_id)?, // controller → agent
            Role::Agent => controller_tx.ok_or(Error::SendFailed)?,
        };
        dest_tx
            .try_send(ServerMsg::Ice {
                session_id,
                candidate,
            })
            .map_err(|_| Error::SendFailed)
    }

    // ─── termination ─────────────────────────────────────────────────

    pub fn terminate(&self, session_id: ObjectId, reason: EndReason) -> Result<()> {
        self.terminate_with_limit(session_id, reason, None)
    }

    /// FR-101 P4b — [`Self::terminate`], naming the limit that ended the
    /// session (`max_duration`) on `rc:terminate` and in the audit row, so a
    /// viewer and a reader of the audit can tell it from idleness.
    pub fn terminate_with_limit(
        &self,
        session_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
    ) -> Result<()> {
        let Some((_, arc)) = self.inner.sessions.remove(&session_id) else {
            return Ok(()); // already gone, idempotent
        };
        // FR-115 P3b — the session's slot goes back with it.
        if let Some((_, lease)) = self.inner.slotted.remove(&session_id) {
            self.release_slot(lease);
        }

        let (agent_id, tenant_id, controller_tx) = {
            let mut s = arc.lock();
            // Best-effort transition; ignore if already closed.
            let _ = s.transition(SessionPhase::Closed);
            (s.agent_id, s.tenant_id, s.controller_tx.clone())
        };

        // Decrement agent session counter.
        if let Some(mut a) = self.inner.agents.get_mut(&agent_id) {
            a.active_sessions = a.active_sessions.saturating_sub(1);
        }

        // Notify both sides (best-effort; either may be gone).
        let msg = ServerMsg::Terminate {
            session_id,
            reason,
            limit: limit.map(str::to_string),
        };
        if let Some(tx) = controller_tx {
            let _ = tx.try_send(msg.clone());
        }
        if let Ok(agent_tx) = self.agent_tx(agent_id) {
            let _ = agent_tx.try_send(msg);
        }

        self.audit(
            session_id,
            agent_id,
            tenant_id,
            AuditKind::SessionEnded {
                reason,
                limit: limit.map(str::to_string),
            },
        );
        Ok(())
    }

    // ─── helpers ─────────────────────────────────────────────────────

    fn agent_tx(&self, agent_id: ObjectId) -> Result<ClientTx> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.tx.clone())
            .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))
    }

    /// Push a `ServerMsg` straight to a connected agent. Returns
    /// `AgentOffline` if the agent isn't currently registered,
    /// `SendFailed` if the channel is full (rare — the agent rx pump
    /// reads as fast as it can serialise + write to the socket).
    ///
    /// Used by the `roomler` relay path in
    /// `crates/api/src/ws/tunnel.rs` to forward
    /// `ServerMsg::TcpForwardForward` / `TcpHalfClose` /
    /// `TcpClosed` / `TunnelTerminate` to the agent on behalf of a
    /// connected tunnel-client. Distinct from the remote-control
    /// session flow which goes through `dispatch`.
    /// Multi-org — send to an agent ONLY when it is registered here under
    /// `tenant_id`. `Err(AgentOffline)` when this pod doesn't hold it.
    ///
    /// The tenant re-check is what makes the cross-pod ctrl fan-out safe:
    /// that envelope carries a live enrollment token, and every pod applies
    /// it, so a mismatched (or forged) envelope must not be able to hand
    /// another tenant's agent a token for an org it was never meant to join.
    pub fn send_to_agent_in_tenant(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        let registered_tenant = self
            .inner
            .agents
            .get(&agent_id)
            .map(|a| a.tenant_id)
            .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
        if registered_tenant != tenant_id {
            return Err(Error::AgentOffline(agent_id.to_hex()));
        }
        self.send_to_agent(agent_id, msg)
    }

    // ─── Fleet RPC broker ────────────────────────────────────────────
    //
    // Push a command to a device and park the caller on its answer. Purely
    // same-pod: the API layer has already routed the request to whichever pod
    // holds the agent's WS (`ws/rc_relay.rs`), so by the time we're here the
    // agent's tx and the waiter live in one process.

    /// Does this device's agent understand `rc:rpc.exec`? `None` = not online
    /// here.
    pub fn agent_supports_exec(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner.agents.get(&agent_id).map(|a| a.supports_exec)
    }

    /// Push an authorization to a device and return as soon as it is QUEUED.
    ///
    /// Queued is not recorded (#1597): the frame still has to cross the
    /// device's control connection, which on a corp laptop behind a
    /// TLS-inspecting middlebox was measured seconds slower than the caller's.
    /// So `Ok(true)` says this connection ANSWERS grants (`ssh-grant-ack`,
    /// FR-83) and the caller must not be told where to dial until
    /// `rc:ssh.grant_ack` arrives; `Ok(false)` is a pre-FR-83 agent, which
    /// never will, and is answered as before. Read here, in the lookup that
    /// validates the push, rather than in a separate query a reconnect could
    /// fall between.
    ///
    /// The SESSION itself still runs over a path the server is not on. The
    /// failures reported here are the ones visible from here: not connected,
    /// wrong tenant, or a build that would drop the frame.
    pub fn push_ssh_grant(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<bool> {
        let acks = {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            // Cross-tenant is reported as offline, deliberately: a caller in
            // org A must not be able to tell org B's devices apart from
            // absent ones.
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_ssh {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
            entry.supports_ssh_grant_ack
        };
        self.send_to_agent(agent_id, msg)?;
        Ok(acks)
    }

    /// Whether a connected agent advertises the `ssh` RPC capability.
    pub fn agent_supports_ssh(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner.agents.get(&agent_id).map(|a| a.supports_ssh)
    }

    /// Record an agent's `ssh` capability, immediately after registration.
    ///
    /// Deliberately not a `register_agent` parameter — see the field's
    /// initialiser. No-op if the agent is already gone, which is the correct
    /// outcome: there is nothing to serve.
    pub fn set_agent_ssh_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_ssh = supports;
        }
    }

    /// FR-94 — record whether this connection runs exec as SYSTEM through
    /// its service (`exec-system`). Called after registration and on every
    /// caps re-announcement. No-op if the agent is already gone.
    pub fn set_agent_exec_system_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_exec_system = supports;
        }
    }

    /// FR-94 — does the agent, connected to THIS pod, run exec as SYSTEM?
    /// `None` = not connected here. Exec reaches only an agent on this pod
    /// anyway ([`Self::exec_on_agent`]).
    pub fn agent_supports_exec_system(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_exec_system)
    }

    /// FR-105 — record whether this connection serves SSH from its SYSTEM
    /// service (`ssh-system`). As [`Self::set_agent_exec_system_support`].
    pub fn set_agent_ssh_system_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_ssh_system = supports;
        }
    }

    /// FR-105 — does the agent, connected to THIS pod, serve SSH from its
    /// SYSTEM service? `None` = not connected here: a grant reaches only an
    /// agent on this pod anyway.
    pub fn agent_supports_ssh_system(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_ssh_system)
    }

    /// FR-97 P5a — record whether this connection runs a command as the
    /// person at its screen (`console-user`). Called after registration. A
    /// property of the build, so a caps re-announcement cannot change it.
    /// No-op if the agent is already gone.
    pub fn set_agent_console_user_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_console_user = supports;
        }
    }

    /// FR-97 P5a — does the agent, connected to THIS pod, run a command as
    /// the person at its screen? `None` = not connected here: exec reaches
    /// only an agent on this pod anyway ([`Self::exec_on_agent`]).
    pub fn agent_supports_console_user(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_console_user)
    }

    /// FR-83 — record whether this connection acknowledges grants
    /// (`ssh-grant-ack`), alongside [`Self::set_agent_ssh_support`] and for
    /// the same reasons. A separate setter rather than a second positional
    /// bool on that one: two adjacent bools are exactly the call a transposed
    /// argument turns into "waits on every grant to an agent that never
    /// answers".
    pub fn set_agent_ssh_grant_ack(&self, agent_id: ObjectId, acks: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_ssh_grant_ack = acks;
        }
    }

    /// FR-85 P3 — record what the agent says about remote recording (its
    /// hello's, or a heartbeat's, `AgentCaps.record`; see
    /// [`RecordSupport::from_caps`]).
    pub fn set_agent_record_support(&self, agent_id: ObjectId, support: RecordSupport) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.record_support = support;
        }
    }

    /// FR-99 — record what the agent says about privacy mode (its hello's,
    /// or a heartbeat's, `AgentCaps.rpc`; see [`PrivacySupport::from_caps`]).
    pub fn set_agent_privacy_support(&self, agent_id: ObjectId, support: PrivacySupport) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.privacy_support = support;
        }
    }

    /// FR-101 P2 — record whether the agent's prompt names `ask` features
    /// (its hello's, or a heartbeat's, `AgentCaps.rpc` has `session-policy`).
    pub fn set_agent_asks_features(&self, agent_id: ObjectId, asks: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.asks_features = asks;
        }
    }

    /// FR-101 P4b-2 — record whether the agent keeps an idle limit (its
    /// hello's, or a heartbeat's, `AgentCaps.rpc` has `idle-timeout`).
    pub fn set_agent_enforces_idle(&self, agent_id: ObjectId, enforces: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.enforces_idle = enforces;
        }
    }

    /// FR-99 P3b — record whether the agent honours a lock ask (its hello's,
    /// or a heartbeat's, `AgentCaps.rpc` has `lock-on-end`).
    pub fn set_agent_honours_lock_on_end(&self, agent_id: ObjectId, honours: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.honours_lock_on_end = honours;
        }
    }

    /// FR-101 P2b — record the device owner's floor (its hello's, or a
    /// heartbeat's, `AgentCaps.session_policy`).
    pub fn set_agent_device_session_policy(
        &self,
        agent_id: ObjectId,
        policy: Option<SessionPolicy>,
    ) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.device_session_policy = policy;
        }
    }

    /// FR-92 — record whether this connection parses the keep-busy policy
    /// (its hello's, or a heartbeat's, `AgentCaps.input` has `keep-busy`).
    /// Returns what it was before, so a caller can act on the word
    /// REAPPEARING rather than on every caps announcement; `false` for an
    /// agent this pod does not hold.
    pub fn set_agent_keep_busy_support(&self, agent_id: ObjectId, supports: bool) -> bool {
        match self.inner.agents.get_mut(&agent_id) {
            Some(mut entry) => std::mem::replace(&mut entry.supports_keep_busy, supports),
            None => false,
        }
    }

    /// FR-92 — push an org's keep-busy policy to every agent of `tenant_id`
    /// connected to THIS pod that parses it. Returns how many it reached. A
    /// tenant's sockets live on one pod (tenant affinity), but the admin's
    /// PUT can land on any: the caller also publishes the change on the rc
    /// ctrl lane, and every pod runs this for its own agents.
    pub fn push_keep_busy_policy(&self, tenant_id: ObjectId, denied: bool) -> usize {
        let targets: Vec<ObjectId> = self
            .inner
            .agents
            .iter()
            .filter(|a| a.tenant_id == tenant_id && a.supports_keep_busy)
            .map(|a| a.agent_id)
            .collect();
        targets
            .into_iter()
            .filter(|id| {
                self.send_to_agent(*id, ServerMsg::KeepBusyPolicy { denied })
                    .is_ok()
            })
            .count()
    }

    /// FR-90 — record whether this connection runs Hive sessions (`hive`),
    /// right after registration, like [`Self::set_agent_ssh_support`].
    pub fn set_agent_hive_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive = supports;
        }
    }

    /// FR-90 — whether a connected agent advertises `hive`. `None` = not
    /// online on this pod.
    pub fn agent_supports_hive(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner.agents.get(&agent_id).map(|a| a.supports_hive)
    }

    /// FR-90 — whether THIS connection advertises `hive`. `tx` is the sender
    /// [`Self::register_agent`] returned to it, matched as
    /// [`Self::unregister_agent`] matches a displaced handler's. `None` = not
    /// online on this pod, or a newer connection holds the slot. A newer
    /// entry is never an older connection's word, least of all while it is
    /// half-registered: it reads `false` until its caps are recorded.
    pub fn agent_supports_hive_on(&self, agent_id: ObjectId, tx: &ClientTx) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive)
    }

    /// FR-90 — push a Hive frame (`rc:hive.start` / `rc:hive.stop` /
    /// `rc:hive.demote`) to a device, checked in the lookup that sends it so a
    /// reconnect cannot fall between the check and the push: offline (or
    /// another tenant's — reported identically, so org A cannot tell org B's
    /// devices from absent ones) is [`Error::AgentOffline`]; a connection that
    /// did not advertise `hive` is [`Error::ExecUnsupported`] and receives
    /// nothing.
    pub fn push_hive(&self, agent_id: ObjectId, tenant_id: ObjectId, msg: ServerMsg) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P0d-2 — record whether this connection serves viewer peers
    /// (`hive-view`), right after registration.
    pub fn set_agent_hive_view_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_view = supports;
        }
    }

    /// FR-90 P0d-2 — whether a connected agent advertises `hive-view`.
    /// `None` = not online on this pod.
    pub fn agent_supports_hive_view(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_hive_view)
    }

    /// FR-90 P1e — record whether this connection understands core memory
    /// (`hive-memory`), right after registration.
    pub fn set_agent_hive_memory_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_memory = supports;
        }
    }

    /// FR-90 P1j — record whether this connection mirrors adopted terminal
    /// sessions (`hive-adopt`), right after registration.
    pub fn set_agent_hive_adopt_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_adopt = supports;
        }
    }

    /// FR-90 P1j — whether a connected agent advertises `hive-adopt`.
    /// `None` = not online on this pod.
    pub fn agent_supports_hive_adopt(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_hive_adopt)
    }

    /// FR-90 P1j — answer an adopt offer (`rc:hive.adopt_ack`), checked in the
    /// lookup that sends it, as [`Self::push_hive`]: offline or another
    /// tenant's is [`Error::AgentOffline`]; a connection without `hive-adopt`
    /// is [`Error::ExecUnsupported`] and receives nothing.
    pub fn push_hive_adopt(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_adopt {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2d-5 — whether the device's CURRENT connection on this pod may
    /// serve a viewer from a copy it holds: it advertises `hive-view` and
    /// `hive-replica` both, in `tenant_id`. Not online here, or another
    /// tenant's, is `false`, as [`Self::push_hive_view`] would answer it.
    pub fn agent_serves_copies(&self, agent_id: ObjectId, tenant_id: ObjectId) -> bool {
        self.inner.agents.get(&agent_id).is_some_and(|a| {
            a.tenant_id == tenant_id && a.supports_hive_view && a.supports_hive_replica
        })
    }

    /// FR-90 P2c-3 — record whether this connection holds copies
    /// (`hive-replica`), right after registration.
    pub fn set_agent_hive_replica_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_replica = supports;
        }
    }

    /// FR-90 P2c-3 — whether THIS connection advertises `hive-replica`, as
    /// [`Self::agent_supports_hive_on`]: `None` = not online on this pod, or a
    /// newer connection holds the slot.
    pub fn agent_supports_hive_replica_on(
        &self,
        agent_id: ObjectId,
        tx: &ClientTx,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive_replica)
    }

    /// FR-90 P2c-3 — push a join (`rc:hive.replica.join`), checked in the
    /// lookup that sends it, as [`Self::push_hive`]: offline or another
    /// tenant's is [`Error::AgentOffline`]; a connection without
    /// `hive-replica` is [`Error::ExecUnsupported`] and receives nothing — the
    /// join stays pending until a connection that holds copies asks.
    pub fn push_hive_replica(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_replica {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2e-2 — record whether this connection holds leased sessions to
    /// the server's word (`hive-lease`), right after registration.
    pub fn set_agent_hive_lease_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_lease = supports;
        }
    }

    /// FR-90 P2e-2 — whether THIS connection advertises `hive-lease`, as
    /// [`Self::agent_supports_hive_on`]: `None` = not online on this pod, or a
    /// newer connection holds the slot.
    pub fn agent_supports_hive_lease_on(&self, agent_id: ObjectId, tx: &ClientTx) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive_lease)
    }

    /// FR-90 P2e-2 — whether the device's CURRENT connection on this pod
    /// advertises `hive-lease`: `None` = not online here, or another
    /// tenant's (answered alike, as [`Self::push_hive`] answers).
    pub fn agent_supports_hive_lease(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.supports_hive_lease)
    }

    /// FR-90 P2e-2 — push the lease word (`rc:hive.lease`) to the device's
    /// CURRENT connection, checked in the lookup that sends it, as
    /// [`Self::push_hive`]: offline or another tenant's is
    /// [`Error::AgentOffline`]; a connection without `hive-lease` is
    /// [`Error::ExecUnsupported`] and receives nothing.
    pub fn push_hive_lease(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_lease {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2e-2 — push the lease word (`rc:hive.lease`) to THIS connection
    /// only, checked in the lookup that sends it: a connection that is not
    /// the one in the slot (a newer one displaced it), or another tenant's,
    /// is [`Error::AgentOffline`]; one without `hive-lease` is
    /// [`Error::ExecUnsupported`] and receives nothing. A word is worth
    /// something only on the connection it names, so it never falls through
    /// to a newer one.
    pub fn push_hive_lease_on(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        tx: &ClientTx,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id || !ptr_eq(&entry.tx, tx) {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_lease {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        // On `tx` itself, never through the slot: should a newer connection
        // take the slot meanwhile, the word does not move to it.
        tx.try_send(msg).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => Error::SendFailed,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                Error::AgentOffline(agent_id.to_hex())
            }
        })
    }

    /// FR-90 P2g-3c — push `msg` on `tx`, this agent's own connection, as the
    /// answer to what that connection asked (`rc:hive.retain`): only while it
    /// is the current one, of `tenant_id`, and runs Hive. As
    /// [`Self::push_hive_lease_on`], never through the slot, so an answer
    /// does not move to a newer connection.
    pub fn push_hive_on(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        tx: &ClientTx,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id || !ptr_eq(&entry.tx, tx) {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        tx.try_send(msg).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => Error::SendFailed,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                Error::AgentOffline(agent_id.to_hex())
            }
        })
    }

    /// FR-90 P2e-3 — record whether this connection takes part in a
    /// promotion (`hive-promote`), right after registration.
    pub fn set_agent_hive_promote_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_promote = supports;
        }
    }

    /// FR-90 P2e-3 — whether the device's CURRENT connection on this pod
    /// advertises everything a promotion asks of either end: `hive`,
    /// `hive-lease` and `hive-promote`. `None` = not online here, or another
    /// tenant's (answered alike, as [`Self::push_hive`] answers).
    pub fn agent_supports_hive_promote(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.supports_hive && a.supports_hive_lease && a.supports_hive_promote)
    }

    /// FR-90 P2e-3 — push a promotion frame (`rc:hive.prepare`, `drain`,
    /// `move`), checked in the lookup that sends it, as [`Self::push_hive`]:
    /// offline or another tenant's is [`Error::AgentOffline`]; a connection
    /// without `hive-promote` is [`Error::ExecUnsupported`] and receives
    /// nothing.
    pub fn push_hive_promote(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_promote {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2f-1 — record whether this connection takes part in a teleport
    /// (`hive-teleport`), right after registration.
    pub fn set_agent_hive_teleport_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_teleport = supports;
        }
    }

    /// FR-90 P2f-1 — whether the device's CURRENT connection on this pod
    /// advertises everything a teleport asks of either end: what a promotion
    /// asks ([`Self::agent_supports_hive_promote`]) and `hive-teleport`.
    /// `None` = not online here, or another tenant's (answered alike, as
    /// [`Self::push_hive`] answers).
    pub fn agent_supports_hive_teleport(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| {
                a.supports_hive
                    && a.supports_hive_lease
                    && a.supports_hive_promote
                    && a.supports_hive_teleport
            })
    }

    /// FR-90 P2f-1 — whether THIS connection advertises `hive-teleport`, as
    /// [`Self::agent_supports_hive_on`]: `None` = not online on this pod, or
    /// a newer connection holds the slot.
    pub fn agent_supports_hive_teleport_on(
        &self,
        agent_id: ObjectId,
        tx: &ClientTx,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive_teleport)
    }

    /// FR-90 P2f-1 — push a teleport's frame (its prepare, and its target's
    /// join), checked in the lookup that sends it, as [`Self::push_hive`]:
    /// offline or another tenant's is [`Error::AgentOffline`]; a connection
    /// without `hive-teleport` is [`Error::ExecUnsupported`] and receives
    /// nothing. A target's join goes here, not through
    /// [`Self::push_hive_replica`]: its owner need not let it hold copies.
    pub fn push_hive_teleport(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_teleport {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2f-3 — record whether this connection starts a fork from its
    /// parent's copy (`hive-fork`), right after registration.
    pub fn set_agent_hive_fork_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_fork = supports;
        }
    }

    /// FR-90 P2f-3 — whether the device's CURRENT connection on this pod
    /// runs sessions and starts a fork: `hive` and `hive-fork`. `None` = not
    /// online here, or another tenant's (answered alike, as
    /// [`Self::push_hive`] answers).
    pub fn agent_supports_hive_fork(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.supports_hive && a.supports_hive_fork)
    }

    /// FR-90 P2f-3 — whether THIS connection advertises `hive-fork`, as
    /// [`Self::agent_supports_hive_on`]: `None` = not online on this pod, or
    /// a newer connection holds the slot.
    pub fn agent_supports_hive_fork_on(&self, agent_id: ObjectId, tx: &ClientTx) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive && a.supports_hive_fork)
    }

    /// FR-90 P2f-3 — push a fork's start, checked in the lookup that sends
    /// it, as [`Self::push_hive`]: offline or another tenant's is
    /// [`Error::AgentOffline`]; a connection without `hive` and `hive-fork`
    /// is [`Error::ExecUnsupported`] and receives nothing. A fork's start
    /// never goes through [`Self::push_hive`]: a build that ignores
    /// `fork_of` would start the fork empty.
    pub fn push_hive_fork(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !(entry.supports_hive && entry.supports_hive_fork) {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2f-4b — record whether this connection makes a terminal
    /// session it adopted a managed one (`hive-manage`), right after
    /// registration.
    pub fn set_agent_hive_manage_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_manage = supports;
        }
    }

    /// FR-90 P2f-4b — whether the device's CURRENT connection on this pod
    /// runs sessions and makes a terminal session managed: `hive` and
    /// `hive-manage`. `None` = not online here, or another tenant's.
    pub fn agent_supports_hive_manage(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.supports_hive && a.supports_hive_manage)
    }

    /// FR-90 P2f-4b — push a start that makes a terminal session managed,
    /// checked in the lookup that sends it, as [`Self::push_hive_fork`]:
    /// offline or another tenant's is [`Error::AgentOffline`]; a connection
    /// without `hive` and `hive-manage` is [`Error::ExecUnsupported`] and
    /// receives nothing. Never through [`Self::push_hive`]: a build that
    /// ignores `from_terminal` would start the conversation afresh.
    pub fn push_hive_manage(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !(entry.supports_hive && entry.supports_hive_manage) {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2g-2 — record whether this connection purges a session on
    /// `rc:hive.purge` (`hive-purge`), right after registration.
    pub fn set_agent_hive_purge_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_purge = supports;
        }
    }

    /// FR-90 P2g-2 — whether THIS connection runs sessions and purges one
    /// (`hive` and `hive-purge`), as [`Self::agent_supports_hive_on`]: `None`
    /// = not online on this pod, or a newer connection holds the slot.
    pub fn agent_supports_hive_purge_on(&self, agent_id: ObjectId, tx: &ClientTx) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive && a.supports_hive_purge)
    }

    /// FR-90 P2g-2 — push `rc:hive.purge`, checked in the lookup that sends
    /// it, as [`Self::push_hive_fork`]: offline or another tenant's is
    /// [`Error::AgentOffline`]; a connection without `hive` and `hive-purge`
    /// is [`Error::ExecUnsupported`] and receives nothing. A build before it
    /// does not know the frame, so the purge waits for one that does.
    pub fn push_hive_purge(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !(entry.supports_hive && entry.supports_hive_purge) {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// #2294 — record whether this connection finishes a removal purge before
    /// it exits on the goodbye (`hive-purge-drain`), right after registration.
    pub fn set_agent_hive_purge_drain_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_purge_drain = supports;
        }
    }

    /// FR-90 P2g-4a — record whether this connection purges every session it
    /// holds on `rc:hive.purge_all` (`hive-purge-all`), right after
    /// registration.
    pub fn set_agent_hive_purge_all_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_purge_all = supports;
        }
    }

    /// FR-90 P2g-4a — push `rc:hive.purge_all {purge_id}` to a device being
    /// removed, checked in the lookup that sends it, as
    /// [`Self::push_hive_purge`]: offline or another tenant's is
    /// [`Error::AgentOffline`]; a connection without `hive` and
    /// `hive-purge-all` is [`Error::ExecUnsupported`] and receives nothing. A
    /// build of P2g-1 to P2g-3d says `hive-purge` and cannot decode the frame.
    pub fn push_hive_purge_all(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        purge_id: ObjectId,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !(entry.supports_hive && entry.supports_hive_purge_all) {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, ServerMsg::HivePurgeAll { purge_id })?;
        // #2267 — the removal's kick, right after, must not tell this
        // connection: the goodbye's exit would cut the purge short.
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.removal_purge_pushed = true;
        }
        Ok(())
    }

    /// FR-90 P2i-2 — record whether this connection answers a search over
    /// the copies it holds (`hive-search`), right after registration.
    pub fn set_agent_hive_search_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_search = supports;
        }
    }

    /// FR-90 P2i-2 — whether the device's CURRENT connection on this pod
    /// answers a search over its copies: it advertises `hive-search` and
    /// `hive-view` both (the search's peer rides the view's frames), in
    /// `tenant_id`. Not online here, or another tenant's, is `false`, as
    /// [`Self::push_hive_search`] would answer it.
    pub fn agent_searches(&self, agent_id: ObjectId, tenant_id: ObjectId) -> bool {
        self.inner.agents.get(&agent_id).is_some_and(|a| {
            a.tenant_id == tenant_id && a.supports_hive_view && a.supports_hive_search
        })
    }

    /// FR-90 P2i-2 — push a search grant (`rc:hive.search.grant`), checked in
    /// the lookup that sends it, as [`Self::push_hive_view`]: offline or
    /// another tenant's is [`Error::AgentOffline`]; a connection without
    /// `hive-view` and `hive-search` is [`Error::ExecUnsupported`] and receives
    /// nothing. A build before P2i-1 drops the frame unread, and its searcher
    /// would wait for an answer that never comes.
    pub fn push_hive_search(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !(entry.supports_hive_view && entry.supports_hive_search) {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P2d — record whether this connection carries replica streams
    /// (`hive-stream`), right after registration.
    pub fn set_agent_hive_stream_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_hive_stream = supports;
        }
    }

    /// FR-90 P2d — whether THIS connection advertises `hive-stream`, as
    /// [`Self::agent_supports_hive_on`]: `None` = not online on this pod, or a
    /// newer connection holds the slot.
    pub fn agent_supports_hive_stream_on(&self, agent_id: ObjectId, tx: &ClientTx) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| ptr_eq(&a.tx, tx))
            .map(|a| a.supports_hive_stream)
    }

    /// FR-90 P2d — whether the device's CURRENT connection on this pod
    /// advertises `hive-stream`: `None` = not online here, or another
    /// tenant's (answered alike, as [`Self::push_hive`] answers).
    pub fn agent_supports_hive_stream(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.supports_hive_stream)
    }

    /// FR-90 P2d — push a stream frame (`rc:hive.replica.grant`, `dial`,
    /// `candidate`, `refused`, `close`), checked in the lookup that sends it,
    /// as [`Self::push_hive`]: offline or another tenant's is
    /// [`Error::AgentOffline`]; a connection without `hive-stream` is
    /// [`Error::ExecUnsupported`] and receives nothing.
    pub fn push_hive_stream(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_stream {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P1e — whether a connected agent advertises `hive-memory`.
    /// `None` = not online on this pod.
    pub fn agent_supports_hive_memory(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_hive_memory)
    }

    /// FR-90 P1e — push a session's core memory (`rc:hive.memory`), checked
    /// in the lookup that sends it, as [`Self::push_hive`]: offline or another
    /// tenant's is [`Error::AgentOffline`]; a connection without `hive-memory`
    /// is [`Error::ExecUnsupported`] and receives nothing — its session runs
    /// without core memory, which is never a reason to refuse the start.
    pub fn push_hive_memory(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_memory {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-90 P0d-2 — push a viewer-peer frame (`rc:hive.view.*`), checked in
    /// the lookup that sends it, as [`Self::push_hive`]: offline or another
    /// tenant's is [`Error::AgentOffline`]; a connection without `hive-view`
    /// is [`Error::ExecUnsupported`] and receives nothing.
    pub fn push_hive_view(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        msg: ServerMsg,
    ) -> Result<()> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_hive_view {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        self.send_to_agent(agent_id, msg)
    }

    /// FR-85 P3 — a LIVE session's `(agent_id, controller_user_id,
    /// effective grant)`, for checking what an agent reports about it.
    /// `None` once the session has ended (callers fall back to the stored
    /// `remote_sessions` row: a recording's last report arrives after its
    /// session is gone).
    /// Exactly one live watchdog per immutable share-bound session (retries coalesce).
    pub fn shared_lease(
        &self,
        session_id: ObjectId,
    ) -> Option<roomler_ai_remote_control::signaling::SharedSessionLease> {
        let e = self.inner.sessions.get(&session_id)?;
        let s = e.value().lock();
        Some(roomler_ai_remote_control::signaling::SharedSessionLease {
            grant_id: s.device_share_scope()?.grant_id,
            lease_epoch: s.shared_lease_epoch()?.to_string(),
        })
    }
    pub fn claim_device_share_watch(&self, session_id: ObjectId, grant_id: ObjectId) -> bool {
        self.inner
            .sessions
            .get(&session_id)
            .is_some_and(|e| e.value().lock().claim_share_watch(grant_id))
    }

    pub fn session_grant(&self, session_id: ObjectId) -> Option<(ObjectId, ObjectId, Permissions)> {
        self.inner.sessions.get(&session_id).map(|e| {
            let s = e.value().lock();
            (s.agent_id, s.controller_user_id, s.permissions())
        })
    }

    /// Push `rc:rpc.exec` and await the matching `rc:rpc.result`.
    ///
    /// `msg` must be a [`ServerMsg::RpcExec`] carrying `request_id`; the
    /// caller mints it so it can also address a later cancel. The `deadline`
    /// is the CALLER's patience and should exceed the command's own
    /// `timeout_ms` — the agent answers its own timeout, and getting that
    /// answer ("timed out after 30000ms") is strictly more useful than the
    /// server giving up first and reporting nothing.
    ///
    /// The tenant re-check mirrors [`Self::send_to_agent_in_tenant`]: a device
    /// borrowed by a second org must not be reachable from a first org's
    /// request just because both know its id.
    pub async fn exec_on_agent(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        request_id: String,
        msg: ServerMsg,
        deadline: std::time::Duration,
    ) -> Result<ExecOutcome> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            // Refuse loudly rather than push a frame a pre-feature agent
            // drops in its unknown-tag branch — that would spend the whole
            // deadline waiting for silence and read to the operator as a
            // hung device.
            if !entry.supports_exec {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
            // FR-97 P5a — and never a `run_as` to a connection that does not
            // know it: that agent would run the command as root. Checked
            // here, at the push, so no caller can get it wrong.
            if asks_console_user(&msg) && !entry.supports_console_user {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }

        let (tx, rx) = oneshot::channel();
        self.inner.exec_waiters.insert(request_id.clone(), tx);
        // Deregister on EVERY exit from here on, so an early error or an
        // expired deadline can't leave a slot a later id would deliver into.
        let _guard = ExecWaiterGuard {
            hub: self.clone(),
            request_id: request_id.clone(),
        };

        self.send_to_agent(agent_id, msg)?;

        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(outcome)) => Ok(outcome),
            // The waiter slot was dropped without a result — the agent's WS
            // died mid-command.
            Ok(Err(_)) => Err(Error::AgentOffline(agent_id.to_hex())),
            Err(_) => Err(Error::ExecTimeout(agent_id.to_hex())),
        }
    }

    /// FR-94 — the service path's first half of [`Self::exec_on_agent`]: the
    /// same checks (connected here, in this tenant, `exec` advertised), the
    /// same waiter, the frame pushed. The waiting is the caller's, because it
    /// must also watch the shared store for a result posted to another pod.
    pub fn start_exec(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        request_id: String,
        msg: ServerMsg,
    ) -> Result<StartedExec> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
            if !entry.supports_exec {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
            // FR-97 P5a — as in `exec_on_agent`.
            if asks_console_user(&msg) && !entry.supports_console_user {
                return Err(Error::ExecUnsupported(agent_id.to_hex()));
            }
        }
        let (tx, rx) = oneshot::channel();
        self.inner.exec_waiters.insert(request_id.clone(), tx);
        let guard = ExecWaiterGuard {
            hub: self.clone(),
            request_id,
        };
        // On a send error the guard drops here and takes the waiter with it.
        self.send_to_agent(agent_id, msg)?;
        Ok(StartedExec { rx, _guard: guard })
    }

    /// Hand a `rc:rpc.result` to whoever is parked on it. `false` = nobody
    /// was, which just means that caller already gave up.
    pub fn deliver_exec_result(&self, request_id: &str, outcome: ExecOutcome) -> bool {
        match self.inner.exec_waiters.remove(request_id) {
            Some((_, tx)) => tx.send(outcome).is_ok(),
            None => false,
        }
    }

    /// Push `rc:rpc.cancel`. The device still answers with a `rc:rpc.result`
    /// carrying `error`, so the parked caller resolves rather than waiting out
    /// its deadline.
    pub fn cancel_exec(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        request_id: String,
    ) -> Result<()> {
        self.send_to_agent_in_tenant(agent_id, tenant_id, ServerMsg::RpcCancel { request_id })
    }

    pub fn send_to_agent(&self, agent_id: ObjectId, msg: ServerMsg) -> Result<()> {
        let tx = self.agent_tx(agent_id)?;
        tx.try_send(msg).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => Error::SendFailed,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                Error::AgentOffline(agent_id.to_hex())
            }
        })
    }

    fn controller_for(&self, session_id: ObjectId) -> Option<ObjectId> {
        self.inner
            .sessions
            .get(&session_id)
            .map(|s| s.value().lock().controller_user_id)
    }

    fn with_session<F, R>(&self, session_id: ObjectId, f: F) -> Result<R>
    where
        F: FnOnce(&mut LiveSession) -> Result<R>,
    {
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
        let mut s = arc.value().lock();
        f(&mut s)
    }

    fn audit(&self, sid: ObjectId, aid: ObjectId, oid: ObjectId, k: AuditKind) {
        self.inner.audit.record(sid, aid, oid, k);
    }

    // ─── introspection (for /api/sessions and admin) ─────────────────

    pub fn online_agents(&self) -> Vec<ObjectId> {
        self.inner.agents.iter().map(|e| *e.key()).collect()
    }

    pub fn is_agent_online(&self, agent_id: ObjectId) -> bool {
        self.inner.agents.contains_key(&agent_id)
    }

    /// FR-115 P3b — the org of a device connected to THIS hub: whose slots a
    /// same-org session to it takes. `None` when it is on another pod.
    pub fn agent_org(&self, agent_id: ObjectId) -> Option<ObjectId> {
        self.inner.agents.get(&agent_id).map(|a| a.tenant_id)
    }

    pub fn live_sessions(&self) -> usize {
        self.inner.sessions.len()
    }
}

fn ptr_eq(a: &ClientTx, b: &ClientTx) -> bool {
    // mpsc::Sender doesn't expose pointer identity directly; use same_channel.
    a.same_channel(b)
}

// ────────────────────────────────────────────────────────────────────────────
// High-level dispatch — the WS handler funnels every parsed ClientMsg here.
// ────────────────────────────────────────────────────────────────────────────

pub struct DispatchCtx {
    pub role: Role,
    pub user_id: Option<ObjectId>,  // Some for Controller
    pub agent_id: Option<ObjectId>, // Some for Agent
    pub controller_name: Option<String>,
    pub controller_tx: Option<ClientTx>,
    /// Phase 2 — the server-resolved consent mode for a controller's
    /// `SessionRequest` (self-control → `Auto`; else the device's effective
    /// mode). The API WS layer computes it (it has the DB access the Hub lacks)
    /// and sets it here; `create_session` forwards it to the agent. Ignored for
    /// non-request messages and agent-role dispatch (defaults to `Prompt`).
    pub consent_mode: ConsentMode,
    /// Phase 5 — a VALIDATED admin break-glass reason (the API gate confirmed the
    /// controller is an `ADMINISTRATOR` forcing a device they don't own). `Some`
    /// ⇒ consent was skipped; `create_session` records an `AdminOverride` audit.
    /// The `SessionRequest` wire field is NOT trusted directly — only this.
    pub override_reason: Option<String>,
    /// P6 — the device's `AccessPolicy.input_mode`, resolved by the API WS
    /// layer alongside `consent_mode`; forwarded to the agent's InputArbiter
    /// in `ServerMsg::Request`. `None` = agent default (free).
    pub input_mode: Option<roomler_ai_remote_control::models::InputMode>,
    /// Multi-org — the display name of the organization the request is made
    /// in, resolved by the API WS layer (the Hub has no DB access) and
    /// forwarded in `ServerMsg::Request` so the host's consent prompt can
    /// say WHICH org is asking. `None` = older caller / lookup failed; the
    /// agent then falls back to its org label.
    pub tenant_name: Option<String>,
    /// FR-85 P3 — may this controller record? Resolved by the API WS layer's
    /// authz gate (owner / ADMINISTRATOR / `RECORD_REMOTE_SCREEN`, never
    /// break-glass). `create_session` strips `Permissions::RECORD` when it is
    /// `false`. Ignored for non-request messages and agent-role dispatch.
    pub may_record: bool,
    /// #1882 — the device's `AccessPolicy.rc_overlay`, resolved by the API WS
    /// layer's authz gate (the Hub has no DB access). Forwarded to the agent
    /// in `ServerMsg::Request`; `forward_offer` withholds the overlay
    /// `local_relay` TURN when it is `false`. Ignored for non-request messages
    /// and agent-role dispatch.
    pub rc_overlay: bool,
    /// FR-101 P2 — the org's session policy for clipboard, files and audio,
    /// read by the API WS layer's authz gate from the tenant row it already
    /// loads. `create_session` strips what it refuses (see [`feature_grant`])
    /// and forwards it to the agent. ⚠️ The cross-pod relay carries it too,
    /// or a session that lands on the other pod would skip the policy.
    /// Ignored for non-request messages and agent-role dispatch.
    pub session_policy: OrgPolicy,
    /// FR-101 P4b — the org's maximum session length, from the same tenant
    /// row; the relay carries it too. `None` = no limit. Ignored for
    /// non-request messages and agent-role dispatch.
    pub max_duration: Option<std::time::Duration>,
    /// FR-101 P4b-2 — the idle limit in seconds: the shorter of the org's
    /// (the same tenant row) and the device's own (`AccessPolicy`). The relay
    /// carries it too. `None` = none. Ignored for non-request messages and
    /// agent-role dispatch.
    pub idle_secs: Option<u32>,
    /// FR-99 P3b — what the device's access policy asks of the session's end
    /// (`AccessPolicy::lock_on_end_ask`). The relay carries it too, or a
    /// session landing on the other pod would drop the ask. `None` = nothing
    /// asked. Ignored for non-request messages and agent-role dispatch.
    pub lock_on_end: Option<LockOnEnd>,
    /// FR-115 P3 — how many remote sessions the DEVICE's organization may run
    /// at once, from its plan and billed seats (`Tenant::limits`), resolved by
    /// the API WS layer's authz gate. `create_session` counts the org's live
    /// sessions on this hub — the one that owns the device, so the count is
    /// the org's under tenant affinity — and refuses a new one at the cap.
    /// ⚠️ The cross-pod relay carries it too, or a session landing on the
    /// other pod would skip the cap. `None` = no cap (an unlimited plan, the
    /// kill switch, or an unreadable tenant row: never refuse on a guess).
    pub org_session_cap: Option<u32>,
    /// FR-115 P3b — the cluster-wide slot the caller claimed for this request
    /// (`create_session_full`'s `slot`); set only by the pod that owns the
    /// device, together with `org_session_cap: None`. `None` everywhere else.
    pub slot: Option<Lease>,
}

impl Hub {
    /// Multi-user P3 security — is the dispatching CONNECTION a party to the
    /// session (the controller that owns it, or the agent it targets)?
    ///
    /// Session ids are not secrets: every tenant member sees them in the
    /// sessions listing/audit, and with N-session support watchers hold them
    /// legitimately. Pre-P3, `dispatch` matched `Terminate` / `SdpOffer` /
    /// `Ice` on session_id alone — any authenticated user who learned an id
    /// could kill the session or inject SDP/ICE into its signalling.
    /// Server-side paths with their own authz (the HTTP terminate route,
    /// orphan reaps, teardown sweeps) call the underlying methods directly
    /// and are unaffected.
    fn check_session_party(&self, ctx: &DispatchCtx, session_id: ObjectId) -> Result<()> {
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
        let s = arc.value().lock();
        let is_party = match ctx.role {
            Role::Controller => ctx.user_id == Some(s.controller_user_id),
            Role::Agent => ctx.agent_id == Some(s.agent_id),
        };
        drop(s);
        if is_party {
            Ok(())
        } else {
            warn!(
                "rc dispatch refused: {:?} connection is not a party to session {}",
                ctx.role,
                session_id.to_hex()
            );
            Err(Error::PermissionDenied("not a party to this session"))
        }
    }

    pub fn dispatch(&self, ctx: &DispatchCtx, msg: ClientMsg) -> Result<()> {
        self.dispatch_capturing_session(ctx, msg, &mut None)
    }

    /// Exact created/coalesced session ID for a caller that must bind a live scope.
    pub fn dispatch_capturing_session(
        &self,
        ctx: &DispatchCtx,
        msg: ClientMsg,
        created: &mut Option<ObjectId>,
    ) -> Result<()> {
        *created = None;
        match (ctx.role, msg) {
            (
                Role::Controller,
                ClientMsg::SessionRequest {
                    agent_id,
                    share_grant_id, // checked by remote's explicit share PDP, not a Hub authority
                    permissions,
                    browser_caps,
                    preferred_transport,
                    chroma_pref,
                    chunk_framing,
                    audio_enabled,
                    // Ignored here — the Hub can't validate admin; the API gate
                    // validates the wire field and re-supplies it via `ctx`.
                    override_reason: _,
                    // Loopback-TURN corp-relay (Phase 2): the descriptor is a
                    // self-minted local-agent TURN; safe to pass through (the
                    // media is DTLS-E2E), overlay-IP-validated in forward_offer.
                    local_relay,
                },
            ) => {
                // Forward browser codec caps verbatim to the agent in
                // the ServerMsg::Request envelope. The agent picks the
                // best intersection with its own AgentCaps and uses it
                // to choose the encoder + advertise the codec in SDP.
                // `preferred_transport` (Phase Y.3) is forwarded the
                // same way; the agent matches it against its own
                // AgentCaps.transports and decides whether to honour
                // or fall back to the WebRTC video track.
                let user_id = ctx.user_id.ok_or(Error::PermissionDenied("no user"))?;
                let name = ctx.controller_name.clone().unwrap_or_default();
                let tx = ctx.controller_tx.clone().ok_or(Error::SendFailed)?;
                let session_id = self.create_session_full_scoped(
                    agent_id,
                    user_id,
                    name,
                    tx,
                    permissions,
                    browser_caps,
                    preferred_transport,
                    chroma_pref,
                    chunk_framing,
                    audio_enabled,
                    ctx.consent_mode,
                    ctx.override_reason.clone(),
                    local_relay,
                    ctx.rc_overlay,
                    ctx.input_mode,
                    ctx.tenant_name.clone(),
                    ctx.may_record,
                    ctx.session_policy,
                    ctx.max_duration,
                    ctx.idle_secs,
                    ctx.lock_on_end,
                    // FR-52 P4 — a session a controller REQUESTED is never
                    // external. The one caller that passes `Some` is the
                    // extauth relay, which calls `create_session` directly
                    // after finding the principal's verified login — so no
                    // frame a controller sends can make a session external,
                    // or an external one ordinary.
                    None,
                    // FR-115 P3 — the device org's session cap, from the
                    // authz gate (or the relay, for the other pod).
                    ctx.org_session_cap,
                    // FR-115 P3b — the slot the owner pod claimed, if any.
                    ctx.slot.clone(),
                    share_grant_id,
                )?;
                *created = Some(session_id);
                Ok(())
            }
            (
                Role::Controller,
                ClientMsg::SdpOffer {
                    session_id,
                    sdp,
                    extauth_mac,
                    peer_auth,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.forward_offer(session_id, sdp, extauth_mac, peer_auth)
            }
            (
                Role::Agent,
                ClientMsg::SdpAnswer {
                    session_id,
                    sdp,
                    extauth_mac,
                    peer_auth,
                    peer_auth_verdict,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.forward_answer(session_id, sdp, extauth_mac, peer_auth, peer_auth_verdict)
            }
            (
                Role::Agent,
                ClientMsg::Consent {
                    session_id,
                    granted,
                    ref reason,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.deliver_consent(session_id, granted, reason.as_deref())
            }
            (
                Role::Agent,
                ClientMsg::ConsentPending {
                    session_id,
                    host_locked,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                // FR-34 — relay the locked-host hint to the controller so its
                // "awaiting consent" wait can explain the delay. Advisory only:
                // a missing session or a dropped controller_tx is a no-op, not
                // an error — the consent outcome is entirely unaffected.
                if let Some(arc) = self.inner.sessions.get(&session_id) {
                    let tx = arc.value().lock().controller_tx.clone();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(ServerMsg::ConsentPending {
                            session_id,
                            host_locked,
                        });
                    }
                }
                Ok(())
            }
            (
                role,
                ClientMsg::Ice {
                    session_id,
                    candidate,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.forward_ice(role, session_id, candidate)
            }
            (
                role,
                ClientMsg::Terminate {
                    session_id,
                    reason,
                    limit,
                },
            ) => {
                // FR-27 P10 — `HostDisconnect` is a claim only the DEVICE can
                // make ("the person at this screen ended it"): it is what the
                // viewer shows as such and does not auto-reconnect from, and
                // the audit records it as the host's decision. A controller
                // saying it about its own hangup is recorded as what it is.
                // (It also keeps the echo away from a pre-P10 agent, which
                // cannot decode the variant.)
                let reason = match (role, reason) {
                    (Role::Controller, EndReason::HostDisconnect) => EndReason::ControllerHangup,
                    (_, r) => r,
                };
                // FR-101 P4b-2 — and the idle limit is the device's claim too:
                // only it measures idleness, so `limit: "idle"` is named on the
                // way out only from the agent and only with `IdleTimeout`
                // (#2251: `no_common_codec` only with `Error`). A controller's
                // word, or any other spelling, names no limit.
                let limit = device_end_limit(role, reason, limit.as_deref());
                // Terminate stays IDEMPOTENT on an already-gone session (the
                // agent's overlay-badge disconnect and teardown races rely on
                // it) — only a live session enforces the party check.
                match self.check_session_party(ctx, session_id) {
                    Ok(()) => self.terminate_with_limit(session_id, reason, limit),
                    Err(Error::SessionNotFound(_)) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            (_, ClientMsg::Ping { id: _ }) => Ok(()), // pong handled by WS layer
            (
                _,
                ClientMsg::AgentHello { .. }
                | ClientMsg::AgentHeartbeat { .. }
                | ClientMsg::RelayProbeReport { .. }
                | ClientMsg::SessionStats { .. }
                | ClientMsg::DerpTicketRequest {},
            ) => {
                // Hello is handled at registration time; heartbeat and
                // session stats are consumed by the WS layer (they need
                // AppState/Mongo, which the Hub deliberately doesn't hold).
                Ok(())
            }
            (role, msg) => {
                warn!("unexpected msg for role {role:?}: {:?}", msg);
                Err(Error::BadMessage("wrong role for message"))
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::Client;
    use roomler_ai_remote_control::audit::AuditSink;
    use std::time::Duration;

    async fn test_hub() -> Hub {
        // Use an in-memory-ish setup: Mongo isn't actually contacted unless we
        // record audit; the channel buffers it and we never let the task tick.
        // For a real CI test that exercises Mongo, see the integration tests.
        let client = Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("mongo for tests");
        let db = client.database("rc_test");
        let (audit, _h) = AuditSink::spawn(db);
        Hub::new(audit, None)
    }

    /// Task #8 — agent-authoritative resync: an ACTIVE session still pinned
    /// to a (re)registering agent is a zombie (its Terminate died with the
    /// old control WS) and is reaped — the controller's live tab is
    /// notified (UI unblocks), capacity frees, and the FRESH agent
    /// connection gets the Terminate (clears a leaked indicator/peer).
    /// Mid-setup sessions (consent pending) legitimately span a WS flap and
    /// are spared for the consent re-push + negotiating reaper to own.
    #[tokio::test]
    async fn reregister_reaps_active_zombies_but_spares_midsetup() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let owner = ObjectId::new();
        let (_atx, _cancel, _arx) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);

        // Session A → Active (the zombie-to-be).
        let (ctl_a, mut ctl_a_rx) = mpsc::channel(8);
        let sid_a = hub
            .create_session(
                agent_id,
                owner,
                "Goran".into(),
                ctl_a,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        hub.deliver_consent(sid_a, true, None).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        hub.with_session(sid_a, |s| s.transition(SessionPhase::Active))
            .unwrap();

        // Session B → stays AwaitingConsent (mid-setup, must survive).
        let (ctl_b, mut ctl_b_rx) = mpsc::channel(8);
        let sid_b = hub
            .create_session(
                agent_id,
                owner,
                "Goran".into(),
                ctl_b,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // The agent's control WS died and reconnected: re-register.
        let (_atx2, _cancel2, mut arx2) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);

        let mut a_ctl_terminated = false;
        while let Ok(m) = ctl_a_rx.try_recv() {
            if matches!(
                m,
                ServerMsg::Terminate { session_id, reason: EndReason::AgentDisconnect, .. }
                    if session_id == sid_a
            ) {
                a_ctl_terminated = true;
            }
        }
        assert!(
            a_ctl_terminated,
            "active zombie's controller must be notified so its UI unblocks"
        );
        let mut a_agent_told = false;
        while let Ok(m) = arx2.try_recv() {
            if matches!(m, ServerMsg::Terminate { session_id, .. } if session_id == sid_a) {
                a_agent_told = true;
            }
        }
        assert!(
            a_agent_told,
            "the FRESH agent connection must get the Terminate (clears a leaked indicator)"
        );
        while let Ok(m) = ctl_b_rx.try_recv() {
            assert!(
                !matches!(m, ServerMsg::Terminate { session_id, .. } if session_id == sid_b),
                "mid-setup session must survive the flap"
            );
        }
    }

    #[tokio::test]
    async fn rejects_session_for_offline_agent() {
        let hub = test_hub().await;
        let (tx, _rx) = mpsc::channel(8);
        let res = hub.create_session(
            ObjectId::new(),
            ObjectId::new(),
            "Goran".into(),
            tx,
            Permissions::default(),
            Vec::new(),
            None,
            None,  // chroma_pref
            None,  // chunk_framing
            false, // audio_enabled
            ConsentMode::Prompt,
            None, // override_reason
            None, // local_relay
            None, // input_mode
            None, // tenant_name
        );
        assert!(matches!(res, Err(Error::AgentOffline(_))));
    }

    /// FR-52 P4 — an EXTERNAL session: the outsider is never told the device's
    /// internal id (they named a connect code), the device is told which login
    /// to bind the session to, and the FILES grandfather rule — which widens
    /// exactly VIEW|INPUT|CLIPBOARD — leaves an outsider's clamped grant alone.
    #[tokio::test]
    async fn an_external_session_names_its_login_and_keeps_its_grant() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let grant = roomler_ai_remote_control::signaling::ExternalGrant {
            attempt_id: "a1".into(),
        };
        let clamped = Permissions::default(); // VIEW | INPUT | CLIPBOARD
        hub.create_session_full(
            agent_id,
            ObjectId::new(),
            "Outsider".into(),
            ctl_tx,
            clamped,
            Vec::new(),
            None,
            None,
            None,
            false,
            ConsentMode::Prompt,
            None,
            None,
            false, // rc_overlay
            None,
            None,
            false, // may_record
            OrgPolicy::Read(SessionPolicy::default()),
            None,
            None,
            None,
            Some(grant.clone()),
            None,
            None,
        )
        .unwrap();
        match ctl_rx.recv().await {
            Some(ServerMsg::SessionCreated {
                agent_id: told,
                permissions,
                ..
            }) => {
                assert_eq!(told, ObjectId::from_bytes([0; 12]));
                assert_eq!(
                    permissions,
                    Some(clamped),
                    "no FILES for an outsider no admin granted it to"
                );
            }
            other => panic!("expected rc:session.created, got {other:?}"),
        }
        loop {
            match agent_rx.recv().await {
                Some(ServerMsg::Request {
                    external,
                    permissions,
                    ..
                }) => {
                    assert_eq!(external, Some(grant));
                    assert_eq!(permissions, clamped);
                    break;
                }
                Some(_) => continue,
                None => panic!("the agent channel closed before the Request"),
            }
        }
    }

    #[tokio::test]
    async fn end_to_end_consent_grant() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,  // chroma_pref
                None,  // chunk_framing
                false, // audio_enabled
                ConsentMode::Prompt,
                None, // override_reason
                None, // local_relay
                None, // input_mode
                None, // tenant_name
            )
            .unwrap();

        // Controller should immediately receive SessionCreated.
        let m = ctl_rx.try_recv().unwrap();
        assert!(matches!(m, ServerMsg::SessionCreated { .. }));

        // Deliver consent.
        hub.deliver_consent(sid, true, None).unwrap();

        // Give the consent task a tick to fire.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Controller should now have a Ready message.
        let m = ctl_rx.try_recv().unwrap();
        assert!(matches!(m, ServerMsg::Ready { .. }));
    }

    /// 2026-08-05 winhost-a wedge, leg A — an agent whose control WS flaps
    /// between the `Request` and its `rc:consent` reply loses the exchange.
    /// `register_agent` must re-push the pending Request on the fresh
    /// connection, and must NOT re-push once consent was delivered.
    #[tokio::test]
    async fn request_repushed_on_agent_reregister() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let owner = ObjectId::new();
        let (_tx1, _cancel1, mut rx1) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);
        let (ctl_tx, _ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        // Original connection got the Request…
        let m = rx1.try_recv().unwrap();
        assert!(matches!(m, ServerMsg::Request { session_id, .. } if session_id == sid));

        // …then the agent's WS flaps (reply never arrives). The fresh
        // registration must receive the Request again.
        let (_tx2, _cancel2, mut rx2) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);
        let repushed = rx2.try_recv().unwrap();
        assert!(
            matches!(repushed, ServerMsg::Request { session_id, .. } if session_id == sid),
            "fresh agent connection must get the consent-pending Request first"
        );

        // Consent lands → the pending Request is cleared; a further
        // reconnect must NOT see it replayed.
        hub.deliver_consent(sid, true, None).unwrap();
        let (_tx3, _cancel3, mut rx3) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);
        assert!(
            !matches!(rx3.try_recv(), Ok(ServerMsg::Request { .. })),
            "no Request replay after consent was delivered"
        );
    }

    /// 2026-08-05 winhost-a wedge, leg B — consent granted + `Ready` pushed but
    /// the controller never sends an offer (it never received `Ready`).
    /// The negotiating reaper must terminate with `EndReason::Error` (which
    /// the controller's ladder treats as retryable); a session whose offer
    /// DID arrive must be left alone.
    #[tokio::test(start_paused = true)]
    async fn negotiating_reaper_terminates_offerless_session() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let _created = ctl_rx.recv().await.unwrap();
        hub.deliver_consent(sid, true, None).unwrap();
        let m = ctl_rx.recv().await.unwrap();
        assert!(matches!(m, ServerMsg::Ready { .. }));

        // No offer follows. Paused-clock sleep auto-advances through both the
        // consent watcher and the reaper timer.
        tokio::time::sleep(NEGOTIATING_TIMEOUT + Duration::from_secs(1)).await;
        let m = ctl_rx.recv().await.unwrap();
        assert!(
            matches!(m, ServerMsg::Terminate { session_id, reason: EndReason::Error, .. } if session_id == sid),
            "offerless Negotiating session must be reaped with the retryable Error reason"
        );
    }

    /// Reaper stand-down: an offer arriving inside the window keeps the
    /// session alive past the deadline.
    #[tokio::test(start_paused = true)]
    async fn negotiating_reaper_spares_session_with_offer() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let _created = ctl_rx.recv().await.unwrap();
        hub.deliver_consent(sid, true, None).unwrap();
        let _ready = ctl_rx.recv().await.unwrap();
        // Drain the agent's Request so the offer forward has room.
        let _req = agent_rx.recv().await.unwrap();

        hub.forward_offer(sid, "v=0".into(), None, None).unwrap();
        tokio::time::sleep(NEGOTIATING_TIMEOUT + Duration::from_secs(1)).await;
        assert!(
            ctl_rx.try_recv().is_err(),
            "session with an offer must not be reaped at the deadline"
        );
    }

    /// FR-100 P1b — the hub relays both halves of peer auth verbatim: the
    /// browser's ask to the agent, the device's signature to the browser. It
    /// checks neither, and must drop neither.
    #[tokio::test]
    async fn the_hub_relays_peer_auth_verbatim_both_ways() {
        use roomler_ai_remote_control::signaling::{PeerAuthAnswer, PeerAuthOffer};
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let _created = ctl_rx.recv().await.unwrap();
        hub.deliver_consent(sid, true, None).unwrap();
        let _ready = ctl_rx.recv().await.unwrap();
        let _req = agent_rx.recv().await.unwrap();

        // Any string: the hub never reads the nonce, only carries it.
        let ask = PeerAuthOffer {
            nonce: "a nonce the hub never reads".into(),
            // FR-100 P2b's fields ride the same struct, so verbatim covers them.
            key: Some("a key the hub never reads".into()),
            sig: Some("a signature the hub never reads".into()),
        };
        hub.forward_offer(sid, "v=0".into(), None, Some(ask.clone()))
            .unwrap();
        match agent_rx.recv().await.unwrap() {
            ServerMsg::SdpOffer { peer_auth, .. } => assert_eq!(peer_auth, Some(ask)),
            other => panic!("expected the offer, got {other:?}"),
        }
        let signed = PeerAuthAnswer {
            key: "the device's key".into(),
            sig: "its signature".into(),
        };
        hub.forward_answer(
            sid,
            "v=0".into(),
            None,
            Some(signed.clone()),
            Some("verified".into()),
        )
        .unwrap();
        loop {
            if let ServerMsg::SdpAnswer { peer_auth, .. } = ctl_rx.recv().await.unwrap() {
                assert_eq!(peer_auth, Some(signed));
                break;
            }
        }
    }

    /// FR-101 P4b — drive a session to live: consent, offer, answer.
    async fn go_live(
        hub: &Hub,
        sid: ObjectId,
        ctl_rx: &mut mpsc::Receiver<ServerMsg>,
        agent_rx: &mut mpsc::Receiver<ServerMsg>,
    ) {
        let _created = ctl_rx.recv().await.unwrap();
        hub.deliver_consent(sid, true, None).unwrap();
        let _ready = ctl_rx.recv().await.unwrap();
        let _req = agent_rx.recv().await.unwrap();
        hub.forward_offer(sid, "v=0".into(), None, None).unwrap();
        hub.forward_answer(sid, "v=0".into(), None, None, None)
            .unwrap();
    }

    /// FR-101 P4b — the next `rc:terminate` on a channel, within `within`.
    async fn next_terminate(
        rx: &mut mpsc::Receiver<ServerMsg>,
        within: Duration,
    ) -> Option<(EndReason, Option<String>)> {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(Some(m)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            if let ServerMsg::Terminate { reason, limit, .. } = m {
                return Some((reason, limit));
            }
        }
        None
    }

    /// FR-101 P4b — the org's maximum session length runs from the moment the
    /// session went live, and ends it as `IdleTimeout` with `limit:
    /// max_duration`, at both ends. Not before its time; and a session with
    /// no limit is untouched.
    #[tokio::test]
    async fn a_session_ends_at_the_orgs_maximum_length() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            true,
            false,
        );
        let open = |hub: &Hub, tx: ClientTx, max: Option<Duration>| {
            hub.create_session_full(
                agent_id,
                ObjectId::new(),
                "ctl".into(),
                tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false,
                None,
                None,
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                max,
                None,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap()
        };

        let (tx, mut ctl_rx) = mpsc::channel(16);
        let sid = open(&hub, tx, Some(Duration::from_millis(400)));
        go_live(&hub, sid, &mut ctl_rx, &mut agent_rx).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            hub.inner.sessions.contains_key(&sid),
            "ended before its maximum length"
        );
        let told = next_terminate(&mut ctl_rx, Duration::from_secs(3)).await;
        assert_eq!(
            told,
            Some((EndReason::IdleTimeout, Some("max_duration".to_string()))),
            "the controller is told which limit ended it"
        );
        let told = next_terminate(&mut agent_rx, Duration::from_secs(1)).await;
        assert_eq!(
            told,
            Some((EndReason::IdleTimeout, Some("max_duration".to_string()))),
            "and so is the agent"
        );
        assert!(!hub.inner.sessions.contains_key(&sid));

        // The control: no limit, the session lives on.
        let (tx, mut ctl_rx) = mpsc::channel(16);
        let sid = open(&hub, tx, None);
        go_live(&hub, sid, &mut ctl_rx, &mut agent_rx).await;
        assert_eq!(
            next_terminate(&mut ctl_rx, Duration::from_millis(800)).await,
            None
        );
        assert!(hub.inner.sessions.contains_key(&sid));
    }

    /// FR-101 P4b-2 — the idle limit rides `rc:request` to every agent, but a
    /// viewer is told it only where the device keeps it (`idle-timeout`). And
    /// when the device ends a session as idle, both ends hear which limit did.
    #[tokio::test]
    async fn the_device_ends_an_idle_session_and_both_ends_hear_why() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            true,
            false,
        );
        let open = |hub: &Hub, tx: ClientTx, idle: Option<u32>| {
            hub.create_session_full(
                agent_id,
                ObjectId::new(),
                "ctl".into(),
                tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false,
                None,
                None,
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                idle,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap()
        };
        let told_viewer = |m: ServerMsg| match m {
            ServerMsg::SessionCreated { idle_secs, .. } => idle_secs,
            other => panic!("expected rc:session.created, got {other:?}"),
        };
        let told_agent = |m: ServerMsg| match m {
            ServerMsg::Request { idle_secs, .. } => idle_secs,
            other => panic!("expected rc:request, got {other:?}"),
        };

        // An agent that does not advertise `idle-timeout`: the limit rides
        // the request (it may be newer than its caps say, and an older one
        // ignores the field), and the viewer is promised nothing.
        let (tx, mut ctl_rx) = mpsc::channel(16);
        let sid = open(&hub, tx, Some(120));
        assert_eq!(told_viewer(ctl_rx.recv().await.unwrap()), None);
        assert_eq!(told_agent(agent_rx.recv().await.unwrap()), Some(120));
        hub.terminate(sid, EndReason::ControllerHangup).unwrap();
        let _ = next_terminate(&mut agent_rx, Duration::from_secs(1)).await;

        // One that does: the viewer is told, and the device's end names it.
        hub.set_agent_enforces_idle(agent_id, true);
        let (tx, mut ctl_rx) = mpsc::channel(16);
        let sid = open(&hub, tx, Some(120));
        assert_eq!(told_viewer(ctl_rx.recv().await.unwrap()), Some(120));
        assert_eq!(told_agent(agent_rx.recv().await.unwrap()), Some(120));
        hub.deliver_consent(sid, true, None).unwrap();
        // The grant moves the session on asynchronously: `rc:ready` says it did.
        assert!(matches!(
            ctl_rx.recv().await.unwrap(),
            ServerMsg::Ready { .. }
        ));
        hub.forward_offer(sid, "v=0".into(), None, None).unwrap();
        hub.forward_answer(sid, "v=0".into(), None, None, None)
            .unwrap();
        let device = DispatchCtx {
            role: Role::Agent,
            user_id: None,
            agent_id: Some(agent_id),
            controller_name: None,
            controller_tx: None,
            consent_mode: ConsentMode::Prompt,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Unavailable,
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
            slot: None,
        };
        hub.dispatch(
            &device,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::IdleTimeout,
                limit: Some("idle".into()),
            },
        )
        .unwrap();
        let idle = Some((EndReason::IdleTimeout, Some("idle".to_string())));
        assert_eq!(
            next_terminate(&mut ctl_rx, Duration::from_secs(1)).await,
            idle,
            "the controller is told the device's idle limit ended it"
        );
        assert_eq!(
            next_terminate(&mut agent_rx, Duration::from_secs(1)).await,
            idle,
            "and the agent hears it echoed"
        );
        assert!(!hub.inner.sessions.contains_key(&sid));

        // No session to the same device sneaks a limit onto a request that
        // carries none.
        let (tx, mut ctl_rx) = mpsc::channel(16);
        let _sid = open(&hub, tx, None);
        assert_eq!(told_viewer(ctl_rx.recv().await.unwrap()), None);
        assert_eq!(told_agent(agent_rx.recv().await.unwrap()), None);
    }

    /// FR-101 P4b-2 — only the device names the idle limit, and only with
    /// the reason it belongs to; the hub's own vocabulary is what goes out.
    #[test]
    fn only_the_device_names_the_idle_limit() {
        use EndReason::{AgentHangup, IdleTimeout};
        assert_eq!(
            device_end_limit(Role::Agent, IdleTimeout, Some("idle")),
            Some("idle")
        );
        assert_eq!(
            device_end_limit(Role::Controller, IdleTimeout, Some("idle")),
            None,
            "a controller does not measure idleness"
        );
        assert_eq!(
            device_end_limit(Role::Agent, AgentHangup, Some("idle")),
            None
        );
        assert_eq!(
            device_end_limit(Role::Agent, IdleTimeout, Some("max_duration")),
            None,
            "the maximum length is the hub's to name, not the device's"
        );
        assert_eq!(
            device_end_limit(Role::Agent, IdleTimeout, Some("IDLE")),
            None
        );
        assert_eq!(device_end_limit(Role::Agent, IdleTimeout, None), None);
    }

    /// #2251 — `no_common_codec` is the device's to name too, and only with
    /// `Error`, the reason it rides on.
    #[test]
    fn only_the_device_names_no_common_codec() {
        use EndReason::{AgentHangup, IdleTimeout};
        assert_eq!(
            device_end_limit(Role::Agent, EndReason::Error, Some("no_common_codec")),
            Some("no_common_codec")
        );
        assert_eq!(
            device_end_limit(Role::Controller, EndReason::Error, Some("no_common_codec")),
            None,
            "only the device holds both halves: its RTP codecs and the offer"
        );
        assert_eq!(
            device_end_limit(Role::Agent, IdleTimeout, Some("no_common_codec")),
            None
        );
        assert_eq!(
            device_end_limit(Role::Agent, AgentHangup, Some("no_common_codec")),
            None
        );
        assert_eq!(
            device_end_limit(Role::Agent, EndReason::Error, Some("NO_COMMON_CODEC")),
            None
        );
        assert_eq!(
            device_end_limit(Role::Agent, EndReason::Error, Some("idle")),
            None,
            "the idle limit stays with `IdleTimeout`"
        );
        assert_eq!(device_end_limit(Role::Agent, EndReason::Error, None), None);
    }

    /// The media path's consent gate. The agent builds a peer from any offer
    /// that reaches it, so the Hub must not forward one before consent — or
    /// the controller that owns the session skips the host's prompt by
    /// offering straight after `rc:session.created` — nor a second one, which
    /// rebuilt the agent's peer under the default grant.
    #[tokio::test]
    async fn an_offer_reaches_the_agent_only_after_consent_and_only_once() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let owner = ObjectId::new();
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                owner,
                "Owner".into(),
                ctl_tx.clone(),
                Permissions::VIEW,
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let owner_ctx = DispatchCtx {
            role: Role::Controller,
            user_id: Some(owner),
            agent_id: None,
            controller_name: None,
            controller_tx: Some(ctl_tx.clone()),
            consent_mode: ConsentMode::Prompt,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Read(SessionPolicy::default()),
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
            slot: None,
        };
        let offer = || ClientMsg::SdpOffer {
            session_id: sid,
            sdp: "v=0".into(),
            extauth_mac: None,
            peer_auth: None,
        };
        let offers_at_agent = |rx: &mut mpsc::Receiver<ServerMsg>| {
            let mut n = 0;
            while let Ok(m) = rx.try_recv() {
                if matches!(m, ServerMsg::SdpOffer { .. }) {
                    n += 1;
                }
            }
            n
        };
        assert!(matches!(
            ctl_rx.recv().await,
            Some(ServerMsg::SessionCreated { .. })
        ));

        // While the host is still being asked.
        let early = hub.dispatch(&owner_ctx, offer());
        assert!(
            matches!(early, Err(Error::BadPhase(_, "awaiting_consent"))),
            "an offer before consent must be refused, got {early:?}"
        );
        assert_eq!(
            offers_at_agent(&mut agent_rx),
            0,
            "nothing reached the agent"
        );

        hub.deliver_consent(sid, true, None).unwrap();
        assert!(matches!(ctl_rx.recv().await, Some(ServerMsg::Ready { .. })));
        hub.dispatch(&owner_ctx, offer()).unwrap();
        assert_eq!(
            offers_at_agent(&mut agent_rx),
            1,
            "the one legitimate offer"
        );

        let again = hub.dispatch(&owner_ctx, offer());
        assert!(
            matches!(again, Err(Error::BadPhase(_, "offer_already_forwarded"))),
            "a second offer must be refused, got {again:?}"
        );
        hub.forward_answer(sid, "v=0".into(), None, None, None)
            .unwrap();
        let live = hub.dispatch(&owner_ctx, offer());
        assert!(
            matches!(live, Err(Error::BadPhase(_, "active"))),
            "a re-offer on a live session must be refused, got {live:?}"
        );
        assert_eq!(offers_at_agent(&mut agent_rx), 0, "and neither reached it");
        assert!(
            hub.session_snapshot(sid).is_some(),
            "a refused offer does not end the session"
        );
    }

    /// P3 security — `dispatch` refuses session verbs from a connection
    /// that is not a party to the session (any authenticated user who
    /// learned a session id could previously Terminate it or inject
    /// SDP/ICE), while the owning controller and the session's agent pass,
    /// and Terminate stays idempotent for an already-gone session.
    #[tokio::test]
    async fn dispatch_enforces_session_party() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let owner = ObjectId::new();
        let (ctl_tx, _ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session(
                agent_id,
                owner,
                "Owner".into(),
                ctl_tx.clone(),
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let ctx_for = |role: Role, user: Option<ObjectId>, agent: Option<ObjectId>| DispatchCtx {
            role,
            user_id: user,
            agent_id: agent,
            controller_name: None,
            controller_tx: Some(ctl_tx.clone()),
            consent_mode: ConsentMode::Prompt,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Read(SessionPolicy::default()),
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
            slot: None,
        };
        let stranger = ctx_for(Role::Controller, Some(ObjectId::new()), None);
        let owner_ctx = ctx_for(Role::Controller, Some(owner), None);
        let session_agent = ctx_for(Role::Agent, None, Some(agent_id));
        let other_agent = ctx_for(Role::Agent, None, Some(ObjectId::new()));

        // A stranger cannot terminate, offer, or trickle ICE.
        for msg in [
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::ControllerHangup,
                limit: None,
            },
            ClientMsg::SdpOffer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: None,
                peer_auth: None,
            },
            ClientMsg::Ice {
                session_id: sid,
                candidate: serde_json::json!({}),
            },
        ] {
            let res = hub.dispatch(&stranger, msg);
            assert!(
                matches!(res, Err(Error::PermissionDenied(_))),
                "stranger must be refused, got {res:?}"
            );
        }
        // A DIFFERENT agent cannot answer/consent/ICE into the session.
        for msg in [
            ClientMsg::SdpAnswer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: None,
                peer_auth: None,
                peer_auth_verdict: None,
            },
            ClientMsg::Consent {
                session_id: sid,
                granted: true,
                reason: None,
            },
            ClientMsg::Ice {
                session_id: sid,
                candidate: serde_json::json!({}),
            },
        ] {
            let res = hub.dispatch(&other_agent, msg);
            assert!(
                matches!(res, Err(Error::PermissionDenied(_))),
                "foreign agent must be refused, got {res:?}"
            );
        }
        assert!(
            hub.session_snapshot(sid).is_some(),
            "session must survive every refused attempt"
        );

        // The session's OWN agent passes the check (consent resolves).
        hub.dispatch(
            &session_agent,
            ClientMsg::Consent {
                session_id: sid,
                granted: true,
                reason: None,
            },
        )
        .unwrap();

        // The owning controller may terminate; a repeat (session gone) is
        // idempotent Ok, and a stranger's attempt on a MISSING session is
        // also Ok (nothing to protect, matches pre-P3 idempotency).
        hub.dispatch(
            &owner_ctx,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::ControllerHangup,
                limit: None,
            },
        )
        .unwrap();
        hub.dispatch(
            &owner_ctx,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::ControllerHangup,
                limit: None,
            },
        )
        .unwrap();
        hub.dispatch(
            &stranger,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::ControllerHangup,
                limit: None,
            },
        )
        .unwrap();
    }

    /// FR-27 P10 — `host_disconnect` reaches the controller as the DEVICE's
    /// word only. The agent's Terminate carries it through unchanged (the
    /// viewer keys its notice on it); the same reason from the controller's
    /// own socket is recorded as `controller_hangup`, so the audit's "the
    /// person at the device ended it" cannot be written by the viewer.
    #[tokio::test]
    async fn host_disconnect_is_the_devices_claim_only() {
        async fn ended_as(ctl_rx: &mut mpsc::Receiver<ServerMsg>, sid: ObjectId) -> EndReason {
            loop {
                match ctl_rx.recv().await.expect("the controller hears the end") {
                    ServerMsg::Terminate {
                        session_id, reason, ..
                    } if session_id == sid => {
                        return reason;
                    }
                    _ => continue,
                }
            }
        }
        let open = |hub: &Hub, agent_id: ObjectId, owner: ObjectId, ctl_tx: ClientTx| {
            hub.create_session(
                agent_id,
                owner,
                "Owner".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap()
        };
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let owner = ObjectId::new();
        let (ctl_tx, mut ctl_rx) = mpsc::channel(16);
        let ctx_for = |role: Role, user: Option<ObjectId>, agent: Option<ObjectId>| DispatchCtx {
            role,
            user_id: user,
            agent_id: agent,
            controller_name: None,
            controller_tx: Some(ctl_tx.clone()),
            consent_mode: ConsentMode::Prompt,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Read(SessionPolicy::default()),
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
            slot: None,
        };
        let device = ctx_for(Role::Agent, None, Some(agent_id));
        let viewer = ctx_for(Role::Controller, Some(owner), None);

        // The device's Disconnect: the reason goes through as it is.
        let sid = open(&hub, agent_id, owner, ctl_tx.clone());
        hub.dispatch(
            &device,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::HostDisconnect,
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(ended_as(&mut ctl_rx, sid).await, EndReason::HostDisconnect);

        // The same words from the viewer are recorded as its own hangup.
        let sid = open(&hub, agent_id, owner, ctl_tx.clone());
        hub.dispatch(
            &viewer,
            ClientMsg::Terminate {
                session_id: sid,
                reason: EndReason::HostDisconnect,
                limit: None,
            },
        )
        .unwrap();
        assert_eq!(
            ended_as(&mut ctl_rx, sid).await,
            EndReason::ControllerHangup
        );
    }

    /// FR-85 P3 — RECORD is kept only when BOTH gates say yes: the
    /// controller may record, and the device serves it. Each refusal is named.
    #[test]
    fn record_is_granted_only_when_the_controller_may_and_the_device_serves_it() {
        use RecordSupport::{None as NoRecorder, NotOptedIn, Serves};
        let want = Permissions::VIEW | Permissions::RECORD;
        assert_eq!(record_grant(want, true, Serves), (want, None));
        assert_eq!(
            record_grant(want, false, Serves),
            (Permissions::VIEW, Some("controller_not_allowed"))
        );
        assert_eq!(
            record_grant(want, true, NotOptedIn),
            (Permissions::VIEW, Some("device_not_opted_in"))
        );
        // Both refusals: the controller's is the one named (it is what the
        // viewer's user can do something about least).
        assert_eq!(
            record_grant(want, false, NotOptedIn),
            (Permissions::VIEW, Some("controller_not_allowed"))
        );
        // P3c-2 — a device with no recorder is named before anything else,
        // whoever asks: there is nothing to allow or refuse there, and the
        // viewer shows no Record control for it.
        for may in [true, false] {
            assert_eq!(
                record_grant(want, may, NoRecorder),
                (Permissions::VIEW, Some("device_cannot_record"))
            );
        }
        // A grant that never asked for RECORD passes untouched, with no reason.
        assert_eq!(
            record_grant(Permissions::default(), false, NoRecorder),
            (Permissions::default(), None)
        );
    }

    /// P3c-2 — the caps words, read by equality: `available` alone is a
    /// recorder whose owner has not opted in; `remote` (with or without
    /// `available`, since an agent built before `available` sends only
    /// `remote`) serves; nothing, or a word from the future, is no recorder.
    #[test]
    fn record_support_reads_the_caps_words_by_equality() {
        let caps = |words: &[&str]| AgentCaps {
            record: words.iter().map(|w| w.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(RecordSupport::from_caps(&caps(&[])), RecordSupport::None);
        assert_eq!(
            RecordSupport::from_caps(&caps(&["available"])),
            RecordSupport::NotOptedIn
        );
        assert_eq!(
            RecordSupport::from_caps(&caps(&["available", "remote"])),
            RecordSupport::Serves
        );
        assert_eq!(
            RecordSupport::from_caps(&caps(&["remote"])),
            RecordSupport::Serves
        );
        // `remote-audio` without `remote` is not serving: `remote` is a
        // prefix of it, and only equality keeps them apart.
        assert_eq!(
            RecordSupport::from_caps(&caps(&["remote-audio"])),
            RecordSupport::None
        );
        assert_eq!(
            RecordSupport::from_caps(&caps(&["available-4k"])),
            RecordSupport::None
        );
    }

    /// FR-85 P3 — end to end through `create_session_full`: an agent whose
    /// owner has not opted in gets no RECORD (and the viewer is told why);
    /// one that serves recording keeps it for an allowed controller; and the
    /// legacy `create_session` (no authz verdict) never grants it.
    #[tokio::test]
    async fn the_hub_strips_record_unless_both_gates_allow_it() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            8,
            true,
            false,
        );
        let ask = |hub: &Hub, may_record: bool| {
            let (tx, mut rx) = mpsc::channel(8);
            hub.create_session_full(
                agent_id,
                ObjectId::new(),
                "ctl".into(),
                tx,
                Permissions::VIEW | Permissions::RECORD,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false, // rc_overlay
                None,
                None,
                may_record,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap();
            match rx.try_recv().unwrap() {
                ServerMsg::SessionCreated {
                    permissions,
                    record_refused,
                    ..
                } => (permissions.unwrap(), record_refused),
                other => panic!("expected SessionCreated, got {other:?}"),
            }
        };

        // The device has advertised nothing: no recorder there at all.
        let (p, why) = ask(&hub, true);
        assert!(!p.contains(Permissions::RECORD));
        assert_eq!(why.as_deref(), Some("device_cannot_record"));

        // A recorder, but its owner never opted in.
        hub.set_agent_record_support(agent_id, RecordSupport::NotOptedIn);
        let (p, why) = ask(&hub, true);
        assert!(!p.contains(Permissions::RECORD));
        assert_eq!(why.as_deref(), Some("device_not_opted_in"));

        hub.set_agent_record_support(agent_id, RecordSupport::Serves);
        let (p, why) = ask(&hub, true);
        assert!(p.contains(Permissions::RECORD), "both gates allow it");
        assert_eq!(why, None);

        let (p, why) = ask(&hub, false);
        assert!(!p.contains(Permissions::RECORD));
        assert_eq!(why.as_deref(), Some("controller_not_allowed"));

        // The legacy entry point carries no authz verdict: never RECORD.
        let (tx, mut rx) = mpsc::channel(8);
        hub.create_session(
            agent_id,
            ObjectId::new(),
            "legacy".into(),
            tx,
            Permissions::VIEW | Permissions::RECORD,
            Vec::new(),
            None,
            None,
            None,
            false,
            ConsentMode::Prompt,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        match rx.try_recv().unwrap() {
            ServerMsg::SessionCreated { permissions, .. } => {
                assert!(!permissions.unwrap().contains(Permissions::RECORD))
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }

    /// FR-85 P3 — a duplicate request on the SAME connection coalesces onto
    /// the live session (#1045) and is answered with its grant. It must also
    /// carry that grant's refusal: the repeated permissions lack RECORD, and
    /// a bare `None` would tell the viewer RECORD was never asked for.
    #[tokio::test]
    async fn a_coalesced_duplicate_repeats_the_record_refusal() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            8,
            true,
            false,
        );
        // A recorder whose owner has not opted in (P3c-2: without it, the
        // device would read as having no recorder at all).
        hub.set_agent_record_support(agent_id, RecordSupport::NotOptedIn);
        let (tx, mut rx) = mpsc::channel(8);
        let user = ObjectId::new();
        let ask = |hub: &Hub| {
            hub.create_session_full(
                agent_id,
                user,
                "ctl".into(),
                tx.clone(),
                Permissions::VIEW | Permissions::RECORD,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false, // rc_overlay
                None,
                None,
                true,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap()
        };
        let first = ask(&hub);
        let second = ask(&hub);
        assert_eq!(first, second, "the duplicate must coalesce");
        for _ in 0..2 {
            match rx.try_recv().unwrap() {
                ServerMsg::SessionCreated {
                    permissions,
                    record_refused,
                    ..
                } => {
                    assert!(!permissions.unwrap().contains(Permissions::RECORD));
                    assert_eq!(record_refused.as_deref(), Some("device_not_opted_in"));
                }
                other => panic!("expected SessionCreated, got {other:?}"),
            }
        }
    }

    /// FR-99 — PRIVACY is kept only off break-glass, on a device that serves
    /// it. Each refusal is named, a device that cannot curtain first.
    #[test]
    fn privacy_is_granted_only_off_break_glass_on_a_serving_device() {
        use PrivacySupport::{None as NoCurtain, NotOptedIn, Serves};
        let want = Permissions::VIEW | Permissions::INPUT | Permissions::PRIVACY;
        let rest = Permissions::VIEW | Permissions::INPUT;
        let member = false; // not external: FR-52's case has its own test
        assert_eq!(privacy_grant(want, false, member, Serves), (want, None));
        assert_eq!(
            privacy_grant(want, true, member, Serves),
            (rest, Some("break_glass"))
        );
        assert_eq!(
            privacy_grant(want, false, member, NotOptedIn),
            (rest, Some("device_not_opted_in"))
        );
        // Both refusals: break-glass is named, as the controller's is for
        // RECORD.
        assert_eq!(
            privacy_grant(want, true, member, NotOptedIn),
            (rest, Some("break_glass"))
        );
        for break_glass in [true, false] {
            assert_eq!(
                privacy_grant(want, break_glass, member, NoCurtain),
                (rest, Some("device_cannot_curtain"))
            );
        }
        // A grant that never asked passes untouched, with no reason.
        assert_eq!(
            privacy_grant(Permissions::default(), true, member, NoCurtain),
            (Permissions::default(), None)
        );
        // It strips PRIVACY alone — RECORD's own gate decides RECORD.
        let both = want | Permissions::RECORD;
        assert_eq!(
            privacy_grant(both, true, member, Serves),
            (rest | Permissions::RECORD, Some("break_glass"))
        );
    }

    /// FR-52 decision 13 — a session from outside the org never holds
    /// PRIVACY, even on a device whose owner allowed privacy mode, and the
    /// strip is named. A device that cannot curtain is still named first.
    #[test]
    fn an_outsiders_session_never_holds_privacy() {
        use PrivacySupport::{None as NoCurtain, NotOptedIn, Serves};
        let want = Permissions::VIEW | Permissions::INPUT | Permissions::PRIVACY;
        let rest = Permissions::VIEW | Permissions::INPUT;
        let (member, outsider) = (false, true);
        // The control: a member, same device, same ask, keeps it.
        assert_eq!(privacy_grant(want, false, member, Serves), (want, None));
        assert_eq!(
            privacy_grant(want, false, outsider, Serves),
            (rest, Some("outside_the_org"))
        );
        // Not opted in: the SESSION's reason is named, because the owner
        // opting in would not change the answer.
        assert_eq!(
            privacy_grant(want, false, outsider, NotOptedIn),
            (rest, Some("outside_the_org"))
        );
        assert_eq!(
            privacy_grant(want, false, outsider, NoCurtain),
            (rest, Some("device_cannot_curtain"))
        );
        // PRIVACY alone: RECORD is `record_grant`'s, and a grant that never
        // asked passes untouched.
        assert_eq!(
            privacy_grant(want | Permissions::RECORD, false, outsider, Serves),
            (rest | Permissions::RECORD, Some("outside_the_org"))
        );
        assert_eq!(privacy_grant(rest, false, outsider, Serves), (rest, None));
    }

    /// FR-99 — the `rpc` words, read by equality: `privacy-available` alone
    /// is a curtain its owner has not allowed; `privacy-mode` serves; nothing,
    /// a near miss, or a word from the future is no curtain at all.
    #[test]
    fn privacy_support_reads_the_rpc_words_by_equality() {
        let caps = |words: &[&str]| AgentCaps {
            rpc: words.iter().map(|w| w.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(PrivacySupport::from_caps(&caps(&[])), PrivacySupport::None);
        assert_eq!(
            PrivacySupport::from_caps(&caps(&["exec", "privacy-available"])),
            PrivacySupport::NotOptedIn
        );
        assert_eq!(
            PrivacySupport::from_caps(&caps(&["privacy-available", "privacy-mode"])),
            PrivacySupport::Serves
        );
        assert_eq!(
            PrivacySupport::from_caps(&caps(&["privacy-mode"])),
            PrivacySupport::Serves
        );
        for near_miss in ["privacy", "privacy-mode-2", "privacy-modes", "PRIVACY-MODE"] {
            assert_eq!(
                PrivacySupport::from_caps(&caps(&[near_miss])),
                PrivacySupport::None,
                "{near_miss}"
            );
        }
    }

    /// FR-99 — end to end through `create_session_full`, reading what the
    /// AGENT is sent as well as what the viewer is told. An agent that does
    /// not serve privacy mode must never see the name: on the names-only wire
    /// an agent that predates it would fail the whole `rc:request`.
    #[tokio::test]
    async fn the_hub_strips_privacy_before_the_agent_can_see_it() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Windows,
            8,
            true,
            false,
        );
        let mut ask_as = |hub: &Hub, override_reason: Option<&str>, external: bool| {
            let (tx, mut rx) = mpsc::channel(8);
            hub.create_session_full(
                agent_id,
                ObjectId::new(),
                "ctl".into(),
                tx,
                Permissions::VIEW | Permissions::INPUT | Permissions::PRIVACY,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                override_reason.map(str::to_string),
                None,
                false, // rc_overlay
                None,
                None,
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                // FR-52 P4 — what the extauth relay passes for an outsider.
                external.then(|| roomler_ai_remote_control::signaling::ExternalGrant {
                    attempt_id: "a1".into(),
                }),
                None,
                None,
            )
            .unwrap();
            let (granted, why) = match rx.try_recv().unwrap() {
                ServerMsg::SessionCreated {
                    permissions,
                    privacy_refused,
                    ..
                } => (permissions.unwrap(), privacy_refused),
                other => panic!("expected SessionCreated, got {other:?}"),
            };
            let sent = loop {
                match agent_rx.try_recv().unwrap() {
                    ServerMsg::Request { permissions, .. } => break permissions,
                    _ => continue,
                }
            };
            assert_eq!(sent, granted, "the agent is sent the viewer's grant");
            (granted, why)
        };

        // Nothing advertised: an agent that may not know the name at all.
        let (p, why) = ask_as(&hub, None, false);
        assert!(!p.contains(Permissions::PRIVACY));
        assert!(
            p.contains(Permissions::VIEW | Permissions::INPUT),
            "the rest survives"
        );
        assert_eq!(why.as_deref(), Some("device_cannot_curtain"));

        hub.set_agent_privacy_support(agent_id, PrivacySupport::NotOptedIn);
        let (p, why) = ask_as(&hub, None, false);
        assert!(!p.contains(Permissions::PRIVACY));
        assert_eq!(why.as_deref(), Some("device_not_opted_in"));

        hub.set_agent_privacy_support(agent_id, PrivacySupport::Serves);
        let (p, why) = ask_as(&hub, None, false);
        assert!(
            p.contains(Permissions::PRIVACY),
            "a serving device, no break-glass"
        );
        assert_eq!(why, None);

        // Break-glass on a serving device: still never.
        let (p, why) = ask_as(&hub, Some("server room fire"), false);
        assert!(!p.contains(Permissions::PRIVACY));
        assert_eq!(why.as_deref(), Some("break_glass"));

        // FR-52 decision 13 — an outsider on the same serving device: never,
        // and the agent is not sent the name either.
        let (p, why) = ask_as(&hub, None, true);
        assert!(!p.contains(Permissions::PRIVACY));
        assert!(
            p.contains(Permissions::VIEW | Permissions::INPUT),
            "the rest survives"
        );
        assert_eq!(why.as_deref(), Some("outside_the_org"));

        // The owner switches it off while connected (the agent re-announces
        // `privacy-available` alone): the next grant drops it.
        hub.set_agent_privacy_support(agent_id, PrivacySupport::NotOptedIn);
        let (p, why) = ask_as(&hub, None, false);
        assert!(!p.contains(Permissions::PRIVACY));
        assert_eq!(why.as_deref(), Some("device_not_opted_in"));
    }

    fn policy(clipboard: FeaturePolicy, files: FeaturePolicy, audio: FeaturePolicy) -> OrgPolicy {
        OrgPolicy::Read(SessionPolicy {
            clipboard,
            files,
            audio,
        })
    }

    /// FR-101 P2 — the pure decision, every value and every consent mode.
    #[test]
    fn feature_grant_follows_the_org_policy() {
        use FeaturePolicy::{Ask, Off, On};
        // The org's half alone: no floor from the device.
        let feature_grant = |p, a, o, m, asks| super::feature_grant(p, a, o, None, m, asks);
        let all =
            Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD | Permissions::FILES;
        let base = Permissions::VIEW | Permissions::INPUT;

        // Unrestricted: everything asked for is kept, nothing named.
        let (p, audio, why) =
            feature_grant(all, true, policy(On, On, On), ConsentMode::Auto, false);
        assert_eq!((p, audio), (all, true));
        assert!(why.is_empty());

        // `off` strips for every consent mode, and names only what was asked.
        for mode in [
            ConsentMode::Auto,
            ConsentMode::Prompt,
            ConsentMode::Email,
            ConsentMode::Push,
            ConsentMode::PromptThenEmail,
        ] {
            let (p, audio, why) = feature_grant(all, true, policy(On, Off, Off), mode, true);
            assert_eq!(p, base | Permissions::CLIPBOARD, "{mode:?}");
            assert!(!audio, "{mode:?}");
            assert_eq!(why.get("files"), Some(&"org_policy_off"), "{mode:?}");
            assert_eq!(why.get("audio"), Some(&"org_policy_off"), "{mode:?}");
            assert_eq!(why.get("clipboard"), None, "{mode:?}");
        }
        let (p, audio, why) = feature_grant(
            base,
            false,
            policy(Off, Off, Off),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!((p, audio), (base, false));
        assert!(why.is_empty(), "nothing asked for, nothing named: {why:?}");

        // `ask` survives only a prompt the device's agent can name it on.
        let (p, _, why) =
            feature_grant(all, false, policy(Ask, Ask, On), ConsentMode::Prompt, true);
        assert_eq!(p, all);
        assert!(why.is_empty());
        let (p, _, why) =
            feature_grant(all, false, policy(Ask, Ask, On), ConsentMode::Prompt, false);
        assert_eq!(p, base);
        assert_eq!(why.get("clipboard"), Some(&"device_cannot_ask"));
        assert_eq!(why.get("files"), Some(&"device_cannot_ask"));
        // Every other mode asks nobody at the device, whatever the agent can
        // do — and that reason is named first.
        for mode in [
            ConsentMode::Auto,
            ConsentMode::Email,
            ConsentMode::Push,
            ConsentMode::PromptThenEmail,
        ] {
            for asks in [true, false] {
                let (p, audio, why) = feature_grant(all, true, policy(Ask, On, Ask), mode, asks);
                assert_eq!(p, base | Permissions::FILES, "{mode:?} {asks}");
                assert!(!audio, "{mode:?} {asks}");
                assert_eq!(why.get("clipboard"), Some(&"needs_consent"), "{mode:?}");
                assert_eq!(why.get("audio"), Some(&"needs_consent"), "{mode:?}");
            }
        }

        // Audio is the flag, and the unused AUDIO bit goes with it.
        let (p, audio, why) = feature_grant(
            base | Permissions::AUDIO,
            false,
            policy(On, On, Off),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!((p, audio), (base, false));
        assert_eq!(why.get("audio"), Some(&"org_policy_off"));

        // A policy nobody could read refuses every feature asked for, and
        // nothing else.
        let (p, audio, why) =
            feature_grant(all, true, OrgPolicy::Unavailable, ConsentMode::Prompt, true);
        assert_eq!((p, audio), (base, false));
        for f in ["clipboard", "files", "audio"] {
            assert_eq!(why.get(f), Some(&"policy_unavailable"), "{f}");
        }
        let (p, audio, why) = feature_grant(
            base,
            false,
            OrgPolicy::Unavailable,
            ConsentMode::Prompt,
            true,
        );
        assert_eq!((p, audio), (base, false));
        assert!(why.is_empty());
    }

    /// FR-101 P2b — the device owner's floor, from its caps, combines with
    /// the org's policy (the stricter wins) and is named as the device's.
    #[test]
    fn feature_grant_follows_the_device_floor() {
        use FeaturePolicy::{Ask, Off, On};
        let all =
            Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD | Permissions::FILES;
        let base = Permissions::VIEW | Permissions::INPUT;
        let floor = |c, f, a| {
            Some(SessionPolicy {
                clipboard: c,
                files: f,
                audio: a,
            })
        };

        // The device's `off`, under an org that set nothing.
        let (p, audio, why) = feature_grant(
            all,
            true,
            policy(On, On, On),
            floor(On, Off, Off),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!((p, audio), (base | Permissions::CLIPBOARD, false));
        assert_eq!(why.get("files"), Some(&"device_policy_off"));
        assert_eq!(why.get("audio"), Some(&"device_policy_off"));
        assert_eq!(why.get("clipboard"), None);

        // Both say `off`: the org's is the one named.
        let (_, _, why) = feature_grant(
            all,
            false,
            policy(On, Off, On),
            floor(On, Off, On),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!(why.get("files"), Some(&"org_policy_off"));

        // The device's `ask` follows the org's `ask` rule: kept on a prompt an
        // agent can name it on, `needs_consent` where nobody is asked.
        let (p, _, why) = feature_grant(
            all,
            false,
            policy(On, On, On),
            floor(Ask, On, On),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!(p, all);
        assert!(why.is_empty());
        let (p, _, why) = feature_grant(
            all,
            false,
            policy(On, On, On),
            floor(Ask, On, On),
            ConsentMode::Auto,
            true,
        );
        assert_eq!(p, all - Permissions::CLIPBOARD);
        assert_eq!(why.get("clipboard"), Some(&"needs_consent"));

        // The org's `off` beats the device's `ask`, and the device's `off`
        // beats the org's `ask`.
        let (_, _, why) = feature_grant(
            all,
            false,
            policy(Off, Ask, On),
            floor(Ask, Off, On),
            ConsentMode::Prompt,
            true,
        );
        assert_eq!(why.get("clipboard"), Some(&"org_policy_off"));
        assert_eq!(why.get("files"), Some(&"device_policy_off"));

        // No floor reported is no floor.
        let (p, audio, why) = feature_grant(
            all,
            true,
            policy(On, On, On),
            None,
            ConsentMode::Auto,
            false,
        );
        assert_eq!((p, audio), (all, true));
        assert!(why.is_empty());
    }

    /// FR-101 P2 — what the agent is told: nothing for an unrestricted
    /// policy (the frame as before the field), the policy otherwise, and all
    /// `off` when it could not be read.
    #[test]
    fn the_agent_is_told_the_policy_only_when_it_restricts() {
        use FeaturePolicy::{Ask, Off, On};
        assert_eq!(policy(On, On, On).for_agent(), None);
        let p = SessionPolicy {
            clipboard: Ask,
            files: Off,
            audio: On,
        };
        assert_eq!(OrgPolicy::Read(p).for_agent(), Some(p));
        assert_eq!(
            OrgPolicy::Unavailable.for_agent(),
            Some(SessionPolicy {
                clipboard: Off,
                files: Off,
                audio: Off,
            })
        );
    }

    /// FR-101 P2 — end to end through `create_session_full`: the viewer's
    /// reasons, the agent's grant and flag, and a duplicate request that
    /// repeats them.
    #[tokio::test]
    async fn the_hub_applies_the_org_policy_to_both_ends() {
        use FeaturePolicy::{Ask, Off, On};
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Windows,
            8,
            true,
            false,
        );
        type Told = (
            Permissions,
            Option<BTreeMap<String, String>>,
            Permissions,
            bool,
            Option<SessionPolicy>,
        );
        let mut ask = |hub: &Hub,
                       tx: ClientTx,
                       rx: &mut mpsc::Receiver<ServerMsg>,
                       wants: Permissions,
                       org: OrgPolicy|
         -> Told {
            hub.create_session_full(
                agent_id,
                ObjectId::new(),
                "ctl".into(),
                tx,
                wants,
                Vec::new(),
                None,
                None,
                None,
                true, // audio_enabled
                ConsentMode::Prompt,
                None,
                None,
                false, // rc_overlay
                None,
                None,
                false,
                org,
                None,
                None,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap();
            let (granted, refused) = match rx.try_recv().unwrap() {
                ServerMsg::SessionCreated {
                    permissions,
                    features_refused,
                    ..
                } => (permissions.unwrap(), features_refused),
                other => panic!("expected SessionCreated, got {other:?}"),
            };
            let (sent, audio, sent_policy) = loop {
                match agent_rx.try_recv().unwrap() {
                    ServerMsg::Request {
                        permissions,
                        audio_enabled,
                        session_policy,
                        ..
                    } => break (permissions, audio_enabled, session_policy),
                    _ => continue,
                }
            };
            (granted, refused, sent, audio, sent_policy)
        };
        let all =
            Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD | Permissions::FILES;
        let org = policy(Ask, Off, Off);

        // An agent that cannot ask: `ask` and `off` both go, each named.
        let (tx, mut rx) = mpsc::channel(8);
        let first_tx = tx.clone();
        let (granted, refused, sent, audio, sent_policy) = ask(&hub, tx, &mut rx, all, org);
        assert_eq!(granted, Permissions::VIEW | Permissions::INPUT);
        assert_eq!(sent, granted, "the agent is sent the viewer's grant");
        assert!(!audio, "no audio track is asked of the agent");
        let named = refused.expect("named");
        assert_eq!(
            named.get("clipboard").map(String::as_str),
            Some("device_cannot_ask")
        );
        assert_eq!(
            named.get("files").map(String::as_str),
            Some("org_policy_off")
        );
        assert_eq!(
            named.get("audio").map(String::as_str),
            Some("org_policy_off")
        );
        let OrgPolicy::Read(org_read) = org else {
            unreachable!()
        };
        assert_eq!(sent_policy, Some(org_read), "the agent is told the policy");

        // The same request again on the same connection is coalesced onto
        // that session (no second prompt), and repeats the same reasons.
        hub.create_session_full(
            agent_id,
            ObjectId::new(),
            "ctl".into(),
            first_tx,
            all,
            Vec::new(),
            None,
            None,
            None,
            true,
            ConsentMode::Prompt,
            None,
            None,
            false,
            None,
            None,
            false,
            org,
            None,
            None,
            None,
            None, // external (FR-52 P4)
            None,
            None,
        )
        .unwrap();
        match rx.try_recv().unwrap() {
            ServerMsg::SessionCreated {
                features_refused, ..
            } => assert_eq!(features_refused.as_ref(), Some(&named)),
            other => panic!("expected the coalesced SessionCreated, got {other:?}"),
        }

        // An agent whose prompt names `ask` features keeps the clipboard.
        hub.set_agent_asks_features(agent_id, true);
        let (tx, mut rx) = mpsc::channel(8);
        let (granted, refused, sent, _, _) = ask(&hub, tx, &mut rx, all, org);
        assert_eq!(
            granted,
            Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD
        );
        assert_eq!(sent, granted);
        let refused = refused.expect("files and audio still named");
        assert_eq!(refused.get("clipboard"), None);

        // The legacy grant's implied FILES is refused like an explicit one.
        let (tx, mut rx) = mpsc::channel(8);
        let (granted, refused, _, _, _) = ask(
            &hub,
            tx,
            &mut rx,
            Permissions::default(),
            policy(On, Off, On),
        );
        assert!(!granted.contains(Permissions::FILES));
        assert_eq!(
            refused.expect("named").get("files").map(String::as_str),
            Some("org_policy_off")
        );

        // An unrestricted org: the frame carries no policy at all.
        let (tx, mut rx) = mpsc::channel(8);
        let (granted, refused, _, audio, sent_policy) =
            ask(&hub, tx, &mut rx, all, policy(On, On, On));
        assert_eq!(granted, all);
        assert_eq!(refused, None);
        assert!(audio);
        assert_eq!(sent_policy, None);

        // P2b — the device reports its own floor: what it will refuse is
        // stripped here too, named as the device's, under an org that set
        // nothing.
        hub.set_agent_device_session_policy(
            agent_id,
            Some(SessionPolicy {
                files: Off,
                ..SessionPolicy::default()
            }),
        );
        let (tx, mut rx) = mpsc::channel(8);
        let (granted, refused, sent, audio, _) = ask(&hub, tx, &mut rx, all, policy(On, On, On));
        assert!(!granted.contains(Permissions::FILES));
        assert_eq!(sent, granted);
        assert!(audio, "the floor did not touch audio");
        assert_eq!(
            refused.expect("named").get("files").map(String::as_str),
            Some("device_policy_off")
        );
    }

    /// Multi-user P3 — ONE INPUT holder per agent: a second concurrent
    /// session is created view-effective (INPUT stripped, everything else
    /// kept), the effective grant rides `SessionCreated.permissions`, and
    /// INPUT becomes grantable again once the holder's session ends.
    #[tokio::test]
    async fn second_concurrent_session_is_input_stripped_until_holder_ends() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );

        let mk = |hub: &Hub, name: &str, tx: ClientTx| {
            hub.create_session(
                agent_id,
                ObjectId::new(),
                name.into(),
                tx,
                Permissions::default(), // VIEW | INPUT | CLIPBOARD
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
        };
        let effective = |rx: &mut mpsc::Receiver<ServerMsg>| match rx.try_recv().unwrap() {
            ServerMsg::SessionCreated { permissions, .. } => {
                permissions.expect("P3 server always reports the effective grant")
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        };

        let (tx_a, mut rx_a) = mpsc::channel(8);
        let sid_a = mk(&hub, "holder", tx_a).unwrap();
        let perms_a = effective(&mut rx_a);
        assert!(
            perms_a.contains(Permissions::INPUT),
            "first session holds INPUT"
        );

        let (tx_b, mut rx_b) = mpsc::channel(8);
        let sid_b = mk(&hub, "watcher", tx_b).unwrap();
        let perms_b = effective(&mut rx_b);
        assert!(
            !perms_b.contains(Permissions::INPUT),
            "second concurrent session must be view-effective, got {perms_b:?}"
        );
        assert!(perms_b.contains(Permissions::VIEW), "everything else kept");
        assert!(perms_b.contains(Permissions::CLIPBOARD));
        assert_ne!(sid_a, sid_b);

        // Holder ends → the next session gets INPUT again (B keeps its
        // narrowed grant — re-offer is by NEW session, not retro-upgrade).
        hub.terminate(sid_a, EndReason::ControllerHangup).unwrap();
        let (tx_c, mut rx_c) = mpsc::channel(8);
        let _sid_c = mk(&hub, "next", tx_c).unwrap();
        let perms_c = effective(&mut rx_c);
        assert!(
            perms_c.contains(Permissions::INPUT),
            "INPUT re-offered once the holder ended, got {perms_c:?}"
        );
    }

    /// P6 — an agent that advertises the InputArbiter capability lifts the
    /// P3 single-INPUT-holder rule: concurrent sessions BOTH keep their
    /// INPUT grant (the agent serializes + fences them; exclusive-mode
    /// floor control is agent-side).
    #[tokio::test]
    async fn arbitrating_agent_keeps_input_on_concurrent_sessions() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            true, // P6 — arbiter-capable
            false,
        );

        let mk = |hub: &Hub, name: &str, tx: ClientTx| {
            hub.create_session(
                agent_id,
                ObjectId::new(),
                name.into(),
                tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                Some(roomler_ai_remote_control::models::InputMode::Exclusive),
                None, // tenant_name
            )
        };
        let effective = |rx: &mut mpsc::Receiver<ServerMsg>| match rx.try_recv().unwrap() {
            ServerMsg::SessionCreated { permissions, .. } => permissions.unwrap(),
            other => panic!("expected SessionCreated, got {other:?}"),
        };

        let (tx_a, mut rx_a) = mpsc::channel(8);
        mk(&hub, "first", tx_a).unwrap();
        assert!(effective(&mut rx_a).contains(Permissions::INPUT));

        let (tx_b, mut rx_b) = mpsc::channel(8);
        mk(&hub, "second", tx_b).unwrap();
        assert!(
            effective(&mut rx_b).contains(Permissions::INPUT),
            "arbitrating agent: second concurrent session KEEPS INPUT"
        );

        // The device policy's input_mode rides `ServerMsg::Request` to the
        // agent's arbiter.
        match agent_rx.try_recv().unwrap() {
            ServerMsg::Request { input_mode, .. } => {
                assert_eq!(
                    input_mode,
                    Some(roomler_ai_remote_control::models::InputMode::Exclusive)
                );
            }
            other => panic!("expected Request, got {other:?}"),
        }
    }

    /// P3 — `unregister_controller` is per-CONNECTION: closing tab A must
    /// not tear down the same user's live session on tab B (pre-P3 it was
    /// user-keyed and killed every session — #307's org-switch redial in
    /// one tab killed the other tab's live session).
    #[tokio::test]
    async fn unregister_controller_kills_only_that_tabs_sessions() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, _agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let user = ObjectId::new();

        let (tx_a, _rx_a) = hub.register_controller(user);
        let (tx_b, _rx_b) = hub.register_controller(user);
        let sid_a = hub
            .create_session(
                agent_id,
                user,
                "tab A".into(),
                tx_a.clone(),
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let sid_b = hub
            .create_session(
                agent_id,
                user,
                "tab B".into(),
                tx_b.clone(),
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Tab A closes: only A's session goes.
        hub.unregister_controller(user, &tx_a);
        assert!(
            hub.session_snapshot(sid_a).is_none(),
            "tab A's session must be reaped"
        );
        assert!(
            hub.session_snapshot(sid_b).is_some(),
            "tab B's live session must SURVIVE tab A's close"
        );

        // Tab B closes: its session goes too.
        hub.unregister_controller(user, &tx_b);
        assert!(hub.session_snapshot(sid_b).is_none());
    }

    // rc.185 — the fast connect→disconnect reconnect fix. An orphaned
    // session (controller channel closed) must NOT permanently pin
    // `active_sessions`; the next create_session reaps it and succeeds.
    #[tokio::test]
    async fn create_session_reaps_orphan_from_dead_controller() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        // max_sessions = 1 so a single orphan blocks reconnect pre-fix.
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            1,
            false,
            false,
        );

        // Controller A connects, then "disconnects" (drop its receiver) —
        // the fast connect→disconnect that used to leave a stuck session.
        let (ctl_tx_a, ctl_rx_a) = mpsc::channel(8);
        let sid_a = hub
            .create_session(
                agent_id,
                ObjectId::new(),
                "A".into(),
                ctl_tx_a,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None, // local_relay
                None, // input_mode
                None, // tenant_name
            )
            .unwrap();
        drop(ctl_rx_a); // controller gone → the session's controller_tx.is_closed()

        // Controller B reconnects. Pre-fix this returned AgentBusy because
        // A's orphan still held the only slot. The reap must free it.
        let (ctl_tx_b, _ctl_rx_b) = mpsc::channel(8);
        let res_b = hub.create_session(
            agent_id,
            ObjectId::new(),
            "B".into(),
            ctl_tx_b,
            Permissions::default(),
            Vec::new(),
            None,
            None,
            None, // chunk_framing
            false,
            ConsentMode::Prompt,
            None,
            None, // local_relay
            None, // input_mode
            None, // tenant_name
        );
        assert!(
            res_b.is_ok(),
            "reconnect must reap the orphaned session and succeed, got {res_b:?}"
        );
        assert_ne!(res_b.as_ref().unwrap(), &sid_a, "should be a fresh session");

        // The reap must have re-sent a Terminate to the agent for A (so the
        // agent clears its stale indicator + peer). The agent's queue holds
        // A's Request, then B's — plus a Terminate for A somewhere between.
        let mut saw_terminate_for_a = false;
        while let Ok(msg) = agent_rx.try_recv() {
            if let ServerMsg::Terminate { session_id, .. } = msg
                && session_id == sid_a
            {
                saw_terminate_for_a = true;
            }
        }
        assert!(
            saw_terminate_for_a,
            "agent must be told to terminate the orphaned session (clears the indicator)"
        );

        // Counter integrity: with B live and max_sessions=1, a THIRD live
        // controller must still be rejected — the reap freed exactly one slot,
        // it didn't leak the counter to 0.
        let (ctl_tx_c, _ctl_rx_c) = mpsc::channel(8);
        let res_c = hub.create_session(
            agent_id,
            ObjectId::new(),
            "C".into(),
            ctl_tx_c,
            Permissions::default(),
            Vec::new(),
            None,
            None,
            None, // chunk_framing
            false,
            ConsentMode::Prompt,
            None,
            None, // local_relay
            None, // input_mode
            None, // tenant_name
        );
        assert!(
            matches!(res_c, Err(Error::AgentBusy)),
            "a live session must still occupy the slot, got {res_c:?}"
        );
    }

    /// FR-115 P3 — the org's concurrent-session cap. With a cap of one: a
    /// second session to ANOTHER device of the same org is refused, naming a
    /// session that holds the slot; a device of another org is not affected;
    /// the holder's own retry on its connection coalesces instead of being
    /// refused; ending the session frees the slot; and no cap (`None`, an
    /// unlimited plan or the kill switch) refuses nothing.
    #[tokio::test]
    async fn the_org_session_cap_counts_live_sessions_of_the_devices_org() {
        let hub = test_hub().await;
        let org = ObjectId::new();
        let (dev_a, dev_b, dev_other) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _a = hub.register_agent(dev_a, org, ObjectId::new(), OsKind::Linux, 2, false, false);
        let _b = hub.register_agent(dev_b, org, ObjectId::new(), OsKind::Linux, 2, false, false);
        let _o = hub.register_agent(
            dev_other,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            2,
            false,
            false,
        );
        let start = |agent: ObjectId, user: ObjectId, tx: ClientTx, cap: Option<u32>| {
            hub.create_session_full(
                agent,
                user,
                "user".into(),
                tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false,
                None,
                None,
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None,
                cap,
                None,
            )
        };
        let (holder, other_user) = (ObjectId::new(), ObjectId::new());
        let (tx1, _rx1) = mpsc::channel(8);
        let first = start(dev_a, holder, tx1.clone(), Some(1)).expect("the first session fits");

        // A second session in the same org, to another device: refused.
        let (tx2, _rx2) = mpsc::channel(8);
        match start(dev_b, other_user, tx2.clone(), Some(1)) {
            Err(Error::OrgSessionLimit {
                cap,
                holder_user,
                holder_agent,
            }) => {
                assert_eq!(cap, 1);
                assert_eq!(holder_user, holder.to_hex());
                assert_eq!(holder_agent, dev_a.to_hex());
            }
            other => panic!("expected OrgSessionLimit, got {other:?}"),
        }

        // Another org's device keeps its own count.
        let (tx3, _rx3) = mpsc::channel(8);
        start(dev_other, other_user, tx3, Some(1)).expect("another org has its own count");

        // The holder's retry on the same connection coalesces onto its session.
        assert_eq!(start(dev_a, holder, tx1.clone(), Some(1)).unwrap(), first);

        // Ending the session frees the slot for a new one.
        let _ = hub.terminate(first, EndReason::ControllerHangup);
        assert!(hub.session_snapshot(first).is_none());
        start(dev_b, other_user, tx2, Some(1)).expect("the freed slot fits a new session");

        // No cap refuses nothing, even with the org's one slot taken.
        let (tx4, _rx4) = mpsc::channel(8);
        start(dev_a, ObjectId::new(), tx4, None).expect("no cap, no refusal");
    }

    /// #1045 — a DUPLICATE `rc:session.request` on the SAME controller
    /// connection (the viewer's reconnect ladder re-firing while the first
    /// session still awaits consent, on the same WS socket) must COALESCE onto
    /// the live session, not mint a second: a second session means a second host
    /// consent prompt on a second surface (native panel single-instance =>
    /// companion), the field symptom. Two DIFFERENT connections (real tabs /
    /// multi-viewer) must still each get their own — #307's per-connection rule.
    #[tokio::test]
    async fn create_session_coalesces_duplicate_on_same_connection() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        // max_sessions = 3 (a P6 multi-viewer agent) so the duplicate is NOT
        // caught by the AgentBusy gate — this is the case the field hit.
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let user = ObjectId::new();

        // One WS connection → one controller_tx. Both requests ride clones of
        // it, so `same_channel` sees them as the same tab. `ctl_rx` stays alive
        // so the channel isn't closed (a closed one would be orphan-reaped).
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid1 = hub
            .create_session(
                agent_id,
                user,
                "tab A".into(),
                ctl_tx.clone(),
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None, // local_relay
                None, // input_mode
                None, // tenant_name
            )
            .unwrap();
        // The retry: same connection, second request.
        let sid2 = hub
            .create_session(
                agent_id,
                user,
                "tab A (retry)".into(),
                ctl_tx.clone(),
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None, // local_relay
                None, // input_mode
                None, // tenant_name
            )
            .unwrap();
        assert_eq!(
            sid2, sid1,
            "the duplicate must coalesce onto the live session"
        );
        assert!(
            hub.session_snapshot(sid1).is_some(),
            "the one live session must survive"
        );

        // The core: the agent is prompted EXACTLY ONCE, not twice.
        let mut requests = 0;
        while let Ok(msg) = agent_rx.try_recv() {
            if matches!(msg, ServerMsg::Request { .. }) {
                requests += 1;
            }
        }
        assert_eq!(
            requests, 1,
            "the agent must receive exactly one Request => one consent prompt"
        );

        // The requester learns the REAL session id from BOTH answers, so its
        // viewer converges on the single session.
        let mut created = Vec::new();
        while let Ok(msg) = ctl_rx.try_recv() {
            if let ServerMsg::SessionCreated { session_id, .. } = msg {
                created.push(session_id);
            }
        }
        assert_eq!(
            created,
            vec![sid1, sid1],
            "both SessionCreated answers point at the live session"
        );

        // Guard against over-coalescing: a SECOND, DIFFERENT connection (a real
        // second tab / second viewer) must still get its OWN session.
        let (ctl_tx2, _ctl_rx2) = mpsc::channel(8);
        let sid3 = hub
            .create_session(
                agent_id,
                user,
                "tab B".into(),
                ctl_tx2,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                None, // local_relay
                None, // input_mode
                None, // tenant_name
            )
            .unwrap();
        assert_ne!(
            sid3, sid1,
            "a different connection is a different session (multi-viewer / #307)"
        );
    }

    /// A session whose controller forwarded a loopback-TURN descriptor at
    /// `overlay_ip`, on a device whose `rc_overlay` is as given, offered once.
    /// Returns what the agent was told in `rc:request` and the `turn:` URLs
    /// its `rc:sdp.offer` carried.
    async fn session_with_local_relay(overlay_ip: &str, rc_overlay: bool) -> (bool, Vec<String>) {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let sid = hub
            .create_session_full(
                agent_id,
                ObjectId::new(),
                "Goran".into(),
                ctl_tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None, // chunk_framing
                false,
                ConsentMode::Prompt,
                None,
                Some(LocalRelayDescriptor {
                    turn_port: 47989,
                    overlay_ip: overlay_ip.into(),
                    username: "1700000600:uid".into(),
                    credential: "abcd1234".into(),
                }),
                rc_overlay,
                None,
                None, // tenant_name
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None, // external (FR-52 P4)
                None,
                None,
            )
            .unwrap();

        grant_and_await_ready(&hub, sid, &mut ctl_rx).await;
        hub.forward_offer(sid, "v=0".into(), None, None).unwrap();

        let mut told = None;
        // `None` until the offer is seen: the callers' "no `turn:` URL"
        // assertions must not be satisfied by an offer that never arrived.
        let mut turn_urls: Option<Vec<String>> = None;
        while let Ok(msg) = agent_rx.try_recv() {
            match msg {
                ServerMsg::Request { rc_overlay, .. } => told = Some(rc_overlay),
                ServerMsg::SdpOffer { ice_servers, .. } => {
                    turn_urls = Some(
                        ice_servers
                            .iter()
                            .flat_map(|s| s.urls.iter().cloned())
                            .filter(|u| u.starts_with("turn:"))
                            .collect(),
                    );
                }
                _ => {}
            }
        }
        (
            told.expect("the agent got its rc:request"),
            turn_urls.expect("the offer reached the agent"),
        )
    }

    /// Loopback-TURN corp-relay (Phase 2): a session that forwarded a local
    /// agent's overlay TURN descriptor must have `forward_offer` append
    /// `turn:{overlay_ip}:{port}` to the REMOTE agent's ICE servers (the
    /// SdpOffer→agent push) — this is what lets the corp-Chrome viewer relay
    /// through the local agent's overlay instead of the capped far coturn.
    /// #1882 — only on a device whose `rc_overlay` is on, which the agent is
    /// told in the same session's `rc:request`.
    #[tokio::test]
    async fn forward_offer_appends_overlay_local_relay_to_agent_ice() {
        let (told, turn_urls) = session_with_local_relay("100.64.0.9", true).await;
        assert!(
            told,
            "rc:request must tell the agent the overlay is allowed"
        );
        assert_eq!(
            turn_urls,
            vec!["turn:100.64.0.9:47989".to_string()],
            "forward_offer must append the local-agent overlay relay to the agent's ICE"
        );
    }

    /// #1882 — the default. The relay is an overlay path, so a device that
    /// keeps remote desktop off the overlay never gets it, and is told so.
    #[tokio::test]
    async fn forward_offer_withholds_the_overlay_relay_when_rc_overlay_is_off() {
        let (told, turn_urls) = session_with_local_relay("100.64.0.9", false).await;
        assert!(!told, "rc:request must tell the agent the overlay is off");
        assert!(
            turn_urls.is_empty(),
            "an overlay relay must not reach a device with rc_overlay off: {turn_urls:?}"
        );
    }

    /// The overlay-range guard: a non-overlay `local_relay` (e.g. a public IP a
    /// malicious controller injected) must NOT be forwarded to the agent's TURN
    /// client — the agent should never be pointed at an arbitrary host.
    /// #1882 — asserted on a device whose `rc_overlay` is ON, so it is the
    /// range check that refuses here, not the default.
    #[tokio::test]
    async fn forward_offer_rejects_non_overlay_local_relay() {
        // public — must be rejected
        let (_, turn_urls) = session_with_local_relay("8.8.8.8", true).await;
        assert!(
            turn_urls.is_empty(),
            "a non-overlay relay must be rejected, not forwarded to the agent's TURN client"
        );
    }

    /// Consent granted, and the controller told so: the one state in which
    /// the Hub forwards an offer.
    async fn grant_and_await_ready(
        hub: &Hub,
        sid: ObjectId,
        ctl_rx: &mut mpsc::Receiver<ServerMsg>,
    ) {
        hub.deliver_consent(sid, true, None).unwrap();
        loop {
            match ctl_rx.recv().await {
                Some(ServerMsg::Ready { .. }) => return,
                Some(_) => continue,
                None => panic!("the controller channel closed before rc:ready"),
            }
        }
    }

    #[test]
    fn overlay_relay_ip_predicate_covers_cgnat_and_ula() {
        // 100.64.0.0/10 — the overlay's CGNAT v4 space.
        assert!(is_overlay_relay_ip("100.64.0.1"));
        assert!(is_overlay_relay_ip("100.100.5.5"));
        assert!(is_overlay_relay_ip("100.127.255.255"));
        // Just outside the /10.
        assert!(!is_overlay_relay_ip("100.63.255.255"));
        assert!(!is_overlay_relay_ip("100.128.0.0"));
        // Other private / public / loopback / garbage.
        assert!(!is_overlay_relay_ip("192.168.1.1"));
        assert!(!is_overlay_relay_ip("8.8.8.8"));
        assert!(!is_overlay_relay_ip("127.0.0.1"));
        assert!(!is_overlay_relay_ip("not-an-ip"));
        // fc00::/7 ULA (future overlay v6) accepted; public v6 rejected.
        assert!(is_overlay_relay_ip("fd00::1"));
        assert!(!is_overlay_relay_ip("2001:4860:4860::8888"));
    }

    // ─── rc.53 Phase 2b: Hub displacement notify-then-close ──────────

    #[tokio::test]
    async fn displacement_sends_goodbye_then_notifies_cancel() {
        // The headline rc.53 fix: when a second connection arrives
        // for the same agent_id, the FIRST connection's pump rx must
        // receive a `ServerMsg::Goodbye{ReplacedByNewerConnection}`
        // AND its cancel notify must fire so the read-loop exits
        // within milliseconds (not 25 s waiting on keepalive).
        let hub = test_hub().await;
        let agent_id = ObjectId::new();

        let (_tx1, cancel1, mut rx1) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (_tx2, _cancel2, _rx2) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );

        // First connection's pump rx should immediately have the
        // Goodbye queued; the channel hasn't been polled yet so
        // try_recv finds the message.
        let msg = rx1
            .try_recv()
            .expect("displaced connection should receive Goodbye");
        match msg {
            ServerMsg::Goodbye { reason, message } => {
                assert_eq!(reason, AgentCloseReason::ReplacedByNewerConnection);
                assert!(
                    message.contains(&agent_id.to_hex()),
                    "Goodbye message should mention the agent_id: {message}"
                );
            }
            other => panic!("expected Goodbye on displaced rx, got {other:?}"),
        }

        // cancel1 must have a stored notify-permit waiting. We use
        // `notify_one` (not `notify_waiters`) in register_agent
        // precisely so that the displacement signal latches even if
        // the displaced handler hasn't entered its select-loop yet.
        // `.notified()` here consumes that permit and resolves
        // immediately. A 50 ms timeout is generous for any CI
        // scheduler jitter — production wakes in microseconds.
        tokio::time::timeout(Duration::from_millis(50), cancel1.notified())
            .await
            .expect(
                "displacement must store a notify permit so the displaced read-loop \
                 exits within milliseconds (rc.53 auto-fail #5 mitigation)",
            );
    }

    #[tokio::test]
    async fn unregister_agent_with_stale_tx_is_noop() {
        // rc.53 race fix: the displaced `handle_agent_socket`
        // eventually exits its read-loop and calls `unregister_agent`.
        // By then the registry entry is the NEW connection's. The
        // pre-rc.53 code unconditionally removed by agent_id, which
        // evicted the NEW entry and killed its sessions. Phase 2b's
        // `Option<&ClientTx>` gates the removal on identity match.
        let hub = test_hub().await;
        let agent_id = ObjectId::new();

        let (tx1, _cancel1, _rx1) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let (_tx2, _cancel2, _rx2) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );

        // tx1 is now stale (tx2 holds the slot). Stale-tx unregister
        // must NOT evict tx2's entry.
        hub.unregister_agent(agent_id, Some(&tx1));
        assert!(
            hub.is_agent_online(agent_id),
            "stale-tx unregister evicted the NEW connection — rc.53 race regression"
        );
    }

    #[tokio::test]
    async fn unregister_agent_with_none_tx_always_removes() {
        // No tx identity: the call must always remove unconditionally.
        // (A removal's kick is `kick_removed_agent`, tested below.)
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_tx, _cancel, _rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        assert!(hub.is_agent_online(agent_id));

        hub.unregister_agent(agent_id, None);
        assert!(
            !hub.is_agent_online(agent_id),
            "None-tx unregister must always remove (admin-kick path)"
        );
    }

    #[tokio::test]
    async fn unregister_agent_with_matching_tx_removes() {
        // Sanity: when the tx still matches, removal proceeds normally.
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (tx, _cancel, _rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        assert!(hub.is_agent_online(agent_id));

        hub.unregister_agent(agent_id, Some(&tx));
        assert!(
            !hub.is_agent_online(agent_id),
            "matching-tx unregister must remove the entry"
        );
    }

    // ─── #2267: a removal's kick tells the device ────────────────────

    fn register_linux(
        hub: &Hub,
        agent_id: ObjectId,
        tenant_id: ObjectId,
    ) -> mpsc::Receiver<ServerMsg> {
        let (_tx, _cancel, rx) = hub.register_agent(
            agent_id,
            tenant_id,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        rx
    }

    #[tokio::test]
    async fn a_removal_kick_tells_the_device_after_what_was_queued_before() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let mut rx = register_linux(&hub, agent_id, ObjectId::new());
        hub.send_to_agent(agent_id, ServerMsg::Pong { id: 7 })
            .expect("queued before the kick");

        assert_eq!(hub.kick_removed_agent(agent_id, true), KickOutcome::Told);

        assert!(
            !hub.is_agent_online(agent_id),
            "nothing addresses a removed device"
        );
        // FIFO: the frame queued before the kick is delivered first, so a
        // removal hook's last word still reaches the device.
        assert!(matches!(rx.try_recv(), Ok(ServerMsg::Pong { id: 7 })));
        match rx.try_recv() {
            Ok(ServerMsg::Goodbye { reason, .. }) => {
                assert_eq!(reason, AgentCloseReason::AgentDeleted)
            }
            other => panic!("expected the removal's goodbye, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_removal_kick_without_goodbye_only_unregisters() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let mut rx = register_linux(&hub, agent_id, ObjectId::new());

        assert_eq!(
            hub.kick_removed_agent(agent_id, false),
            KickOutcome::NotTold
        );

        assert!(!hub.is_agent_online(agent_id));
        assert!(rx.try_recv().is_err(), "the kill switch sends nothing");
        assert_eq!(
            hub.kick_removed_agent(agent_id, true),
            KickOutcome::NotRegistered,
            "a second kick, or another pod's, finds nothing"
        );
    }

    #[tokio::test]
    async fn a_removal_kick_keeps_a_purging_device_open() {
        // FR-90 P2g-4a: the device purges after its frame lands, and the
        // goodbye's exit is immediate, so the purge's connection is not told.
        let hub = test_hub().await;
        let (agent_id, tenant_id, purge) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut rx = register_linux(&hub, agent_id, tenant_id);
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_purge_all_support(agent_id, true);
        hub.push_hive_purge_all(agent_id, tenant_id, purge)
            .expect("pushed");

        assert_eq!(
            hub.kick_removed_agent(agent_id, true),
            KickOutcome::KeptForPurge
        );

        assert!(!hub.is_agent_online(agent_id));
        assert!(
            matches!(rx.try_recv(), Ok(ServerMsg::HivePurgeAll { purge_id }) if purge_id == purge)
        );
        assert!(rx.try_recv().is_err(), "no goodbye behind the purge");
    }

    #[tokio::test]
    async fn a_draining_device_is_told_after_its_purge() {
        // #2294: a build that finishes its removal purge before its goodbye
        // exit (`hive-purge-drain`) is told, and the goodbye follows the
        // purge's frame on the same channel.
        let hub = test_hub().await;
        let (agent_id, tenant_id, purge) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut rx = register_linux(&hub, agent_id, tenant_id);
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_purge_all_support(agent_id, true);
        hub.set_agent_hive_purge_drain_support(agent_id, true);
        hub.push_hive_purge_all(agent_id, tenant_id, purge)
            .expect("pushed");

        assert_eq!(hub.kick_removed_agent(agent_id, true), KickOutcome::Told);

        assert!(
            matches!(rx.try_recv(), Ok(ServerMsg::HivePurgeAll { purge_id }) if purge_id == purge)
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ServerMsg::Goodbye {
                reason: AgentCloseReason::AgentDeleted,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_refused_purge_push_does_not_keep_the_device_open() {
        // Only a frame that was queued holds the goodbye back: a connection
        // without `hive-purge-all` is sent no purge, so it is told.
        let hub = test_hub().await;
        let (agent_id, tenant_id) = (ObjectId::new(), ObjectId::new());
        let mut rx = register_linux(&hub, agent_id, tenant_id);
        hub.set_agent_hive_support(agent_id, true);
        assert!(
            hub.push_hive_purge_all(agent_id, tenant_id, ObjectId::new())
                .is_err()
        );

        assert_eq!(hub.kick_removed_agent(agent_id, true), KickOutcome::Told);
        assert!(matches!(rx.try_recv(), Ok(ServerMsg::Goodbye { .. })));
    }

    #[tokio::test]
    async fn a_search_grant_goes_only_to_a_connection_that_searches() {
        // FR-90 P2i-2 — `hive-search` and `hive-view` both: the search's peer
        // rides the view's frames, and a build before P2i-1 drops the grant.
        let hub = test_hub().await;
        let (agent_id, tenant_id) = (ObjectId::new(), ObjectId::new());
        let grant = |grant_id| ServerMsg::HiveSearchGrant {
            grant_id,
            user_id: ObjectId::new(),
            sessions: vec![ObjectId::new()],
            ttl_secs: 600,
        };
        assert!(
            matches!(
                hub.push_hive_search(agent_id, tenant_id, grant(ObjectId::new())),
                Err(Error::AgentOffline(_))
            ),
            "not online here"
        );
        let mut rx = register_linux(&hub, agent_id, tenant_id);
        for (view, search) in [(false, false), (true, false), (false, true)] {
            hub.set_agent_hive_view_support(agent_id, view);
            hub.set_agent_hive_search_support(agent_id, search);
            assert!(
                !hub.agent_searches(agent_id, tenant_id),
                "view {view}, search {search}"
            );
            assert!(
                matches!(
                    hub.push_hive_search(agent_id, tenant_id, grant(ObjectId::new())),
                    Err(Error::ExecUnsupported(_))
                ),
                "view {view}, search {search}"
            );
        }
        assert!(rx.try_recv().is_err(), "nothing was sent");

        hub.set_agent_hive_view_support(agent_id, true);
        hub.set_agent_hive_search_support(agent_id, true);
        let other = ObjectId::new();
        assert!(!hub.agent_searches(agent_id, other), "another tenant's");
        assert!(matches!(
            hub.push_hive_search(agent_id, other, grant(ObjectId::new())),
            Err(Error::AgentOffline(_))
        ));
        assert!(hub.agent_searches(agent_id, tenant_id));
        let gid = ObjectId::new();
        hub.push_hive_search(agent_id, tenant_id, grant(gid))
            .expect("pushed");
        assert!(matches!(
            rx.try_recv(),
            Ok(ServerMsg::HiveSearchGrant { grant_id, .. }) if grant_id == gid
        ));
    }

    #[tokio::test]
    async fn the_kick_control_event_tells_the_device_only_when_it_says_so() {
        // The pod holding the socket applies the removing pod's decision. An
        // envelope without `goodbye` comes from a pod before #2267 and keeps
        // that pod's behaviour (unregister only).
        let hub = test_hub().await;
        let kick = |aid: ObjectId, goodbye: Option<bool>| {
            let mut v = serde_json::json!({
                "class": "rc",
                "evt": "kick",
                "agent_id": aid.to_hex(),
            });
            if let Some(g) = goodbye {
                v["goodbye"] = serde_json::json!(g);
            }
            v
        };

        let old = ObjectId::new();
        let mut rx_old = register_linux(&hub, old, ObjectId::new());
        crate::ctrl::apply_rc_ctrl(&hub, &kick(old, None));
        assert!(!hub.is_agent_online(old));
        assert!(
            rx_old.try_recv().is_err(),
            "an old pod's kick tells nothing"
        );

        let told = ObjectId::new();
        let mut rx_told = register_linux(&hub, told, ObjectId::new());
        crate::ctrl::apply_rc_ctrl(&hub, &kick(told, Some(true)));
        assert!(!hub.is_agent_online(told));
        assert!(matches!(
            rx_told.try_recv(),
            Ok(ServerMsg::Goodbye {
                reason: AgentCloseReason::AgentDeleted,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn hive_support_is_the_word_of_the_connection_that_holds_the_slot() {
        // FR-90: an agent socket's hello reconciles the device's agent
        // sessions on what ITS connection advertised. A displaced connection
        // reading the newer entry instead, half-registered with the `false`
        // placeholder, would end the sessions of a device that runs them.
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (tenant, owner) = (ObjectId::new(), ObjectId::new());
        let (old, _cancel1, _rx1) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);
        assert_eq!(
            hub.agent_supports_hive_on(agent_id, &old),
            Some(false),
            "a registration reads `false` until its caps are recorded"
        );
        hub.set_agent_hive_support(agent_id, true);
        assert_eq!(hub.agent_supports_hive_on(agent_id, &old), Some(true));

        // A newer connection takes the slot: whatever its entry says, from
        // the placeholder on, the old connection has no word.
        let (new, _cancel2, _rx2) =
            hub.register_agent(agent_id, tenant, owner, OsKind::Linux, 3, false, false);
        assert_eq!(
            hub.agent_supports_hive_on(agent_id, &old),
            None,
            "a half-registered newer entry read as the displaced connection's `false`"
        );
        assert_eq!(hub.agent_supports_hive_on(agent_id, &new), Some(false));
        for supports in [true, false] {
            hub.set_agent_hive_support(agent_id, supports);
            assert_eq!(
                hub.agent_supports_hive_on(agent_id, &old),
                None,
                "the newer entry ({supports}) read as the displaced connection's word"
            );
            assert_eq!(hub.agent_supports_hive_on(agent_id, &new), Some(supports));
        }

        // Once nobody holds the slot, nobody has a word.
        assert!(hub.unregister_agent(agent_id, Some(&new)));
        assert_eq!(hub.agent_supports_hive_on(agent_id, &new), None);
        assert_eq!(hub.agent_supports_hive_on(agent_id, &old), None);
    }

    /// FR-90 P2f-1 — a teleport's frames reach only a connection that
    /// advertises `hive-teleport`: one that holds copies and runs sessions
    /// takes no teleport, and another org's is not reachable at all. The
    /// route's gate and the join's re-send read the same word first; this is
    /// the gate in the lookup that sends.
    #[tokio::test]
    async fn a_teleports_frame_reaches_only_a_connection_that_takes_a_teleport() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let join = || ServerMsg::HiveReplicaJoin {
            session_id: ObjectId::new(),
            fence: 1,
            role: Some(roomler_ai_remote_control::hive::HiveReplicaRole::Teleport),
            fences: Vec::new(),
        };
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_replica_support(agent_id, true);
        let err = hub
            .push_hive_teleport(agent_id, tenant, join())
            .expect_err("a connection without hive-teleport");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        hub.set_agent_hive_teleport_support(agent_id, true);
        let err = hub
            .push_hive_teleport(agent_id, ObjectId::new(), join())
            .expect_err("another org's connection");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        hub.push_hive_teleport(agent_id, tenant, join())
            .expect("a connection that takes a teleport");
        assert!(
            matches!(agent_rx.try_recv(), Ok(ServerMsg::HiveReplicaJoin { .. })),
            "the frame reached it"
        );
    }

    /// FR-90 P2f-3 — a fork's start reaches only a connection that runs
    /// sessions and advertises `hive-fork`: one that runs sessions and takes
    /// teleports would start the fork empty, and another org's is not
    /// reachable at all.
    #[tokio::test]
    async fn a_forks_start_reaches_only_a_connection_that_starts_forks() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let stop = || ServerMsg::HiveStop {
            session_id: ObjectId::new(),
            fence: 1,
            reason: "owner".into(),
        };
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_teleport_support(agent_id, true);
        assert_eq!(hub.agent_supports_hive_fork(agent_id, tenant), Some(false));
        assert_eq!(hub.agent_supports_hive_fork_on(agent_id, &tx), Some(false));
        let err = hub
            .push_hive_fork(agent_id, tenant, stop())
            .expect_err("a connection without hive-fork");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        hub.set_agent_hive_fork_support(agent_id, true);
        assert_eq!(
            hub.agent_supports_hive_fork(agent_id, ObjectId::new()),
            None
        );
        let err = hub
            .push_hive_fork(agent_id, ObjectId::new(), stop())
            .expect_err("another org's connection");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        assert_eq!(hub.agent_supports_hive_fork(agent_id, tenant), Some(true));
        assert_eq!(hub.agent_supports_hive_fork_on(agent_id, &tx), Some(true));
        hub.push_hive_fork(agent_id, tenant, stop())
            .expect("a connection that starts forks");
        assert!(
            matches!(agent_rx.try_recv(), Ok(ServerMsg::HiveStop { .. })),
            "it reached the connection"
        );
        // `hive-fork` without `hive` starts nothing.
        hub.set_agent_hive_support(agent_id, false);
        assert_eq!(hub.agent_supports_hive_fork(agent_id, tenant), Some(false));
        assert!(hub.push_hive_fork(agent_id, tenant, stop()).is_err());
    }

    /// FR-90 P2f-4b — a start that makes a terminal session managed reaches
    /// only a connection that runs sessions and advertises `hive-manage`:
    /// one that adopts and starts forks would start the conversation afresh,
    /// and another org's is not reachable at all.
    #[tokio::test]
    async fn a_made_managed_start_reaches_only_a_connection_that_makes_one() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let stop = || ServerMsg::HiveStop {
            session_id: ObjectId::new(),
            fence: 1,
            reason: "owner".into(),
        };
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_fork_support(agent_id, true);
        assert_eq!(
            hub.agent_supports_hive_manage(agent_id, tenant),
            Some(false)
        );
        let err = hub
            .push_hive_manage(agent_id, tenant, stop())
            .expect_err("a connection without hive-manage");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        hub.set_agent_hive_manage_support(agent_id, true);
        assert_eq!(
            hub.agent_supports_hive_manage(agent_id, ObjectId::new()),
            None
        );
        let err = hub
            .push_hive_manage(agent_id, ObjectId::new(), stop())
            .expect_err("another org's connection");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        assert_eq!(hub.agent_supports_hive_manage(agent_id, tenant), Some(true));
        hub.push_hive_manage(agent_id, tenant, stop())
            .expect("a connection that makes one");
        assert!(
            matches!(agent_rx.try_recv(), Ok(ServerMsg::HiveStop { .. })),
            "it reached the connection"
        );
        // `hive-manage` without `hive` makes nothing.
        hub.set_agent_hive_support(agent_id, false);
        assert_eq!(
            hub.agent_supports_hive_manage(agent_id, tenant),
            Some(false)
        );
        assert!(hub.push_hive_manage(agent_id, tenant, stop()).is_err());
    }

    /// FR-90 P2g-2 — a purge reaches only a connection that purges: a build
    /// before `hive-purge` does not know the frame, another org's connection
    /// is not reachable, and a connection a newer one displaced is asked
    /// nothing about what it advertised.
    #[tokio::test]
    async fn a_purge_reaches_only_a_connection_that_purges() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let purge = || ServerMsg::HivePurge {
            purge_id: ObjectId::new(),
            session_id: ObjectId::new(),
            leaving: false,
        };
        hub.set_agent_hive_support(agent_id, true);
        hub.set_agent_hive_manage_support(agent_id, true);
        assert_eq!(hub.agent_supports_hive_purge_on(agent_id, &tx), Some(false));
        let err = hub
            .push_hive_purge(agent_id, tenant, purge())
            .expect_err("a connection without hive-purge");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        hub.set_agent_hive_purge_support(agent_id, true);
        let err = hub
            .push_hive_purge(agent_id, ObjectId::new(), purge())
            .expect_err("another org's connection");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "nothing reached it");

        assert_eq!(hub.agent_supports_hive_purge_on(agent_id, &tx), Some(true));
        hub.push_hive_purge(agent_id, tenant, purge())
            .expect("a connection that purges");
        assert!(
            matches!(agent_rx.try_recv(), Ok(ServerMsg::HivePurge { .. })),
            "it reached the connection"
        );
        // `hive-purge` without `hive` purges nothing.
        hub.set_agent_hive_support(agent_id, false);
        assert_eq!(hub.agent_supports_hive_purge_on(agent_id, &tx), Some(false));
        assert!(hub.push_hive_purge(agent_id, tenant, purge()).is_err());

        // A newer connection holds the slot: the old one decides nothing.
        let (_tx2, _cancel2, _rx2) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        assert_eq!(hub.agent_supports_hive_purge_on(agent_id, &tx), None);
    }

    /// FR-90 P2g-3b — fleet's `hive_purge` control event, as every pod
    /// applies it: pushed to each connection it names that this hub holds, of
    /// the envelope's tenant; nothing for another tenant's, and nothing past
    /// the envelope's cap. P2g-4a — and `hive_purge_all`, a removed device's:
    /// to its connection, of its tenant, advertising `hive-purge-all`.
    #[tokio::test]
    async fn a_hive_purge_from_another_pod_reaches_only_its_tenants_connection() {
        let hub = test_hub().await;
        let tenant = ObjectId::new();
        let (agent_id, other) = (ObjectId::new(), ObjectId::new());
        let (_tx, _cancel, mut rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let (_tx2, _cancel2, mut other_rx) = hub.register_agent(
            other,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        for a in [agent_id, other] {
            hub.set_agent_hive_support(a, true);
            hub.set_agent_hive_purge_support(a, true);
        }
        let (purge, session) = (ObjectId::new(), ObjectId::new());
        let envelope = |tid: ObjectId, agents: &[ObjectId]| {
            serde_json::json!({
                "class": "rc",
                "evt": "hive_purge",
                "tenant_id": tid.to_hex(),
                "purge_id": purge.to_hex(),
                "session_id": session.to_hex(),
                "agent_ids": agents.iter().map(|a| a.to_hex()).collect::<Vec<_>>(),
            })
        };

        crate::ctrl::apply_rc_ctrl(&hub, &envelope(ObjectId::new(), &[agent_id]));
        assert!(
            rx.try_recv().is_err(),
            "another tenant's envelope pushes nothing"
        );

        crate::ctrl::apply_rc_ctrl(&hub, &envelope(tenant, &[other, agent_id]));
        match rx.try_recv() {
            Ok(ServerMsg::HivePurge {
                purge_id,
                session_id,
                leaving,
            }) => assert_eq!(
                (purge_id, session_id, leaving),
                (purge, session, false),
                "an envelope with no word, from a pod before P2k-3: a whole session's"
            ),
            got => panic!("the purge reached its connection: {got:?}"),
        }
        // FR-90 P2k-3 — a leaving member's copy alone, from another pod: the
        // pod that holds the socket says so too.
        let mut leaving_envelope = envelope(tenant, &[agent_id]);
        leaving_envelope["leaving"] = serde_json::json!(true);
        crate::ctrl::apply_rc_ctrl(&hub, &leaving_envelope);
        match rx.try_recv() {
            Ok(ServerMsg::HivePurge { leaving, .. }) => {
                assert!(leaving, "a leaving member's purge says so on the device")
            }
            got => panic!("the leaving purge reached its connection: {got:?}"),
        }
        assert!(
            other_rx.try_recv().is_err(),
            "another tenant's connection the envelope names hears nothing"
        );

        let mut many = vec![ObjectId::new(); crate::ctrl::MAX_HIVE_PURGE_AGENTS];
        many.push(agent_id);
        crate::ctrl::apply_rc_ctrl(&hub, &envelope(tenant, &many));
        assert!(
            rx.try_recv().is_err(),
            "an id past the envelope's cap is not applied"
        );

        // P2g-4a — a removed device's purge of everything, from another pod.
        let all = |tid: ObjectId| {
            serde_json::json!({
                "class": "rc",
                "evt": "hive_purge_all",
                "tenant_id": tid.to_hex(),
                "agent_id": agent_id.to_hex(),
                "purge_id": purge.to_hex(),
            })
        };
        crate::ctrl::apply_rc_ctrl(&hub, &all(tenant));
        assert!(
            rx.try_recv().is_err(),
            "a build that purges a session but predates the frame is sent none"
        );
        hub.set_agent_hive_purge_all_support(agent_id, true);
        crate::ctrl::apply_rc_ctrl(&hub, &all(ObjectId::new()));
        assert!(
            rx.try_recv().is_err(),
            "another tenant's purge of everything pushes nothing"
        );
        crate::ctrl::apply_rc_ctrl(&hub, &all(tenant));
        assert!(
            matches!(rx.try_recv(), Ok(ServerMsg::HivePurgeAll { purge_id }) if purge_id == purge),
            "a removed device's purge of everything reached its connection"
        );
    }

    /// FR-90 P2g-3c — an answer goes on the connection that asked, while it
    /// is the current one, of its tenant, running Hive: never another
    /// tenant's, never a build without Hive, never a newer connection's.
    #[tokio::test]
    async fn an_answer_goes_only_on_the_connection_that_asked() {
        let hub = test_hub().await;
        let (agent_id, tenant) = (ObjectId::new(), ObjectId::new());
        let (tx, _cancel, mut rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let answer = || ServerMsg::HiveRetain { words: Vec::new() };
        let err = hub
            .push_hive_on(agent_id, tenant, &tx, answer())
            .expect_err("a build without Hive");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        hub.set_agent_hive_support(agent_id, true);
        let err = hub
            .push_hive_on(agent_id, ObjectId::new(), &tx, answer())
            .expect_err("another tenant's");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
        assert!(rx.try_recv().is_err(), "nothing reached it");
        hub.push_hive_on(agent_id, tenant, &tx, answer())
            .expect("its own connection");
        assert!(
            matches!(rx.try_recv(), Ok(ServerMsg::HiveRetain { .. })),
            "the answer reached the connection that asked"
        );

        // A newer connection holds the slot: the old one is answered nothing,
        // and nothing moves to the new one.
        let (_tx2, _cancel2, mut rx2) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        hub.set_agent_hive_support(agent_id, true);
        assert!(
            hub.push_hive_on(agent_id, tenant, &tx, answer()).is_err(),
            "a connection a newer one displaced is answered nothing"
        );
        assert!(
            rx2.try_recv().is_err(),
            "an answer to the old connection never reaches the new one"
        );
    }

    // ─── Fleet RPC broker ────────────────────────────────────────────

    fn exec_msg(request_id: &str) -> ServerMsg {
        ServerMsg::RpcExec {
            request_id: request_id.to_string(),
            shell: "bash".into(),
            command: "id".into(),
            timeout_ms: 1_000,
            max_output_bytes: 1024,
            cwd: None,
            caller: "tester".into(),
            consent_mode: Some(ConsentMode::Auto),
            via_service: false,
            run_as: None,
        }
    }

    #[tokio::test]
    async fn exec_round_trips_push_and_result() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true, // exec-capable
        );

        let h = hub.clone();
        let waiter = tokio::spawn(async move {
            h.exec_on_agent(
                agent_id,
                tenant,
                "req-1".into(),
                exec_msg("req-1"),
                std::time::Duration::from_secs(5),
            )
            .await
        });

        // The push must actually reach the agent's channel...
        match agent_rx.recv().await.expect("agent got a frame") {
            ServerMsg::RpcExec { request_id, .. } => assert_eq!(request_id, "req-1"),
            other => panic!("expected RpcExec, got {other:?}"),
        }
        // ...and the result must resolve the parked caller.
        assert!(hub.deliver_exec_result(
            "req-1",
            ExecOutcome {
                exit_code: Some(0),
                stdout: "uid=0(root)".into(),
                ..Default::default()
            },
        ));

        let out = waiter.await.unwrap().expect("exec resolved");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, "uid=0(root)");
    }

    #[tokio::test]
    async fn exec_refuses_an_agent_without_the_capability() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false, // pre-Fleet-RPC agent
        );

        let err = hub
            .exec_on_agent(
                agent_id,
                tenant,
                "req-2".into(),
                exec_msg("req-2"),
                std::time::Duration::from_secs(5),
            )
            .await
            .expect_err("must refuse");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        // And crucially: nothing was pushed. Sending anyway would spend the
        // caller's whole deadline waiting for a frame the agent silently
        // drops, which reads as a hung device rather than an old one.
        assert!(
            agent_rx.try_recv().is_err(),
            "must not push to an old agent"
        );
    }

    /// FR-97 P5a — a command that names `run_as` reaches only a connection
    /// advertising `console-user`. Any other agent ignores the field and runs
    /// the command as root, so the hub sends it nothing, whatever the caller
    /// checked before.
    #[tokio::test]
    async fn exec_as_the_person_reaches_only_a_connection_that_drops_to_them() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );
        let as_person = |id: &str| {
            let mut msg = exec_msg(id);
            if let ServerMsg::RpcExec { run_as, .. } = &mut msg {
                *run_as = Some("console_user".into());
            }
            msg
        };

        // No word recorded: refused, nothing pushed.
        let err = hub
            .exec_on_agent(
                agent_id,
                tenant,
                "req-p1".into(),
                as_person("req-p1"),
                std::time::Duration::from_secs(5),
            )
            .await
            .expect_err("must refuse");
        assert!(matches!(err, Error::ExecUnsupported(_)), "got {err:?}");
        assert!(agent_rx.try_recv().is_err(), "must not push run_as");
        assert_eq!(hub.agent_supports_console_user(agent_id), Some(false));

        // The word recorded: pushed with `run_as`.
        hub.set_agent_console_user_support(agent_id, true);
        let h = hub.clone();
        let waiter = tokio::spawn(async move {
            h.exec_on_agent(
                agent_id,
                tenant,
                "req-p2".into(),
                as_person("req-p2"),
                std::time::Duration::from_secs(5),
            )
            .await
        });
        match agent_rx.recv().await.expect("agent got a frame") {
            ServerMsg::RpcExec { run_as, .. } => {
                assert_eq!(run_as.as_deref(), Some("console_user"))
            }
            other => panic!("expected RpcExec, got {other:?}"),
        }
        assert!(hub.deliver_exec_result("req-p2", ExecOutcome::default()));
        waiter.await.unwrap().expect("exec resolved");
    }

    #[tokio::test]
    async fn exec_refuses_cross_tenant() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (_tx, _cancel, _rx) = hub.register_agent(
            agent_id,
            ObjectId::new(), // registered under one org…
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );

        let err = hub
            .exec_on_agent(
                agent_id,
                ObjectId::new(), // …asked for by another
                "req-3".into(),
                exec_msg("req-3"),
                std::time::Duration::from_secs(5),
            )
            .await
            .expect_err("a borrowed device must not be reachable cross-org");
        assert!(matches!(err, Error::AgentOffline(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn exec_deadline_expires_and_deregisters_the_waiter() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let (_tx, _cancel, _rx) = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            true,
        );

        let err = hub
            .exec_on_agent(
                agent_id,
                tenant,
                "req-4".into(),
                exec_msg("req-4"),
                std::time::Duration::from_millis(50),
            )
            .await
            .expect_err("nobody answered");
        assert!(matches!(err, Error::ExecTimeout(_)), "got {err:?}");

        // The slot must be gone — otherwise a late result (or a reused id)
        // would be delivered into an abandoned waiter.
        assert!(
            !hub.deliver_exec_result("req-4", ExecOutcome::default()),
            "waiter must have been deregistered"
        );
    }
}
