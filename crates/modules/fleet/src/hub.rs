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

use meshharbor_core::business_authority::BusinessZone;
use meshharbor_core::cluster::session_slots::{Lease, SessionSlots};
use meshharbor_core::ice_zones::{IceGateMode, IceServerZones};

use meshharbor_remote_control::audit::AuditSink;
use meshharbor_remote_control::consent::{
    ASYNC_CONSENT_TIMEOUT, ConsentOutcome, DEFAULT_CONSENT_TIMEOUT, HOST_PROMPT_TIMEOUT,
    hub_consent_deadline,
};
use meshharbor_remote_control::error::{Error, Result};
use meshharbor_remote_control::models::{
    AgentCaps, AuditKind, ConsentMode, EndReason, ExecOutcome, FeaturePolicy, LockOnEnd, OsKind,
    RecordCap, RpcCap, SessionPhase, SessionPolicy,
};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::session::{
    ClientTx, FileChildControllerScope, LiveSession, ZoneRoute,
};
use meshharbor_remote_control::signaling::{
    AgentCloseReason, ClientMsg, IceServer, LIMIT_NO_COMMON_CODEC, LocalRelayDescriptor, Role,
    ServerMsg,
};
use meshharbor_remote_control::turn_creds::{
    self, RelayLoadMap, TurnConfig, TurnMap, ice_servers_for_session, pick_region_with_load,
};

const SERVER_TX_CAPACITY: usize = 64;

// The consent windows (`DEFAULT_CONSENT_TIMEOUT`, `ASYNC_CONSENT_TIMEOUT`,
// `HOST_PROMPT_TIMEOUT`) live in `meshharbor_remote_control::consent` — FR-27 moved
// `ASYNC_CONSENT_TIMEOUT` there from here, because the on-host and owner-side
// windows now differ within a single mode and the split needs one home.

// An internal call-site choice, never deserialized from a controller/relay frame.
#[derive(Clone, Copy)]
enum SessionCreationOrigin {
    Unknown,
    LocalPdp,
}

/// How long a session may sit in `Negotiating` (consent granted, `Ready`
/// pushed) without the controller's SDP offer before the Hub terminates it.
/// Generous: a live controller sends its offer within milliseconds of
/// `rc:ready`; only a controller that never received `Ready` waits longer.
const NEGOTIATING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// X14 — fail-closed deadline for the agent to acknowledge `rc:file.child.revoke`.
/// If `rc:file.child.revoke_ack` does not arrive within 5 seconds of a child
/// revocation, the Hub terminates the parent session (`EndReason::AdminTerminated`)
/// rather than leaving an unverified child transport alive.
pub const FILE_CHILD_REVOKE_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Loopback-TURN corp-relay (Phase 2) guard. The overlay assigns node IPs from
/// the RFC 6598 CGNAT range 100.64.0.0/10 (v4) or a ULA `fc00::/7` (v6, derived
/// from the v4). The Hub only appends a controller-supplied `local_relay` TURN
/// entry to the REMOTE agent's ICE servers when its address is inside that
/// range — so a malicious controller can't coerce the agent's TURN client into
/// probing an arbitrary host. (Media is DTLS-E2E regardless, but keeping the
/// agent pointed only at overlay IPs bounds the blast radius to its own mesh.)
/// FR-121 — the candidate line inside a trickled ICE candidate: the browser
/// sends `{ candidate, sdpMid, … }`, an agent may send the bare string.
/// `None` for an end-of-candidates marker or an unknown shape.
fn candidate_text(candidate: &serde_json::Value) -> Option<&str> {
    match candidate {
        serde_json::Value::String(s) => Some(s.as_str()),
        other => other.get("candidate")?.as_str(),
    }
    .filter(|s| !s.is_empty())
}

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
    /// MeshHarbor SSH — the agent advertises `AgentCaps.rpc` containing `ssh`,
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
    /// FR-141 — the agent advertises `ssh-resume` in `AgentCaps.rpc`: it
    /// supports persistent SSH PTY host survival and `rc:ssh.revoke`.
    pub supports_ssh_resume: bool,
    /// FR-141 — the agent advertises `rc-continue` in `AgentCaps.rpc`: it
    /// honours `Request.continues` after a graceful restart.
    pub supports_rc_continue: bool,
    /// 0.5.0 — the agent advertises `silent-monitor` in `AgentCaps.input`:
    /// it honours `ServerMsg::Request::silent_monitor` and
    /// `ServerMsg::AdminTakeover` without raising a host banner or prompt.
    pub supports_silent_monitor: bool,
    /// Dynamic org-relay serving control (`rc:overlay.peer_relay_serve`).
    pub supports_relay_control: bool,
    /// Multi-region relay PoP target push (`rc:relay.regions`).
    pub supports_relay_regions: bool,
    /// Current connection's `relay-server` capability word (updated on hello
    /// and heartbeat so org-relay eligibility sees runtime flips immediately).
    pub supports_relay_server: bool,
    /// FR-128 — the agent advertises `management-path` in `AgentCaps.rpc`: it
    /// parses `rc:agent.management_path`.
    pub supports_management_path: bool,
    /// FR-134 — the agent advertises `management-entry` in `AgentCaps.rpc`: it
    /// can start/stop its management entry listener live on `rc:agent.management_entry`.
    pub supports_management_entry: bool,
    /// FR-128/FR-134 — the TCP port this connection's management entry is currently
    /// listening on (`None` when not listening).
    pub management_entry_port: Option<u16>,
    /// FR-137 — the gateway `agent_id` whose management entry attested this agent's
    /// current control WS connection (`None` for direct or unattested connections).
    pub via_management_entry: Option<ObjectId>,
    /// FR-138 — whether this connection currently reports its OS default route on a
    /// VPN/virtual interface (`AgentCaps::default_route_vpn`).
    pub default_route_vpn: bool,
    /// FR-130 — the device advertises `rc-resume` on this connection: it can
    /// read `rc:agent.resume_window`, the only frame an announce sends. An
    /// older agent drops the unknown tag, so it is never sent one.
    pub advertises_resume: bool,
    /// FR-130 — the window, in seconds, announced to THIS connection
    /// (`rc:agent.resume_window`): set at registration for a device that
    /// advertises `rc-resume` and is in the resume scope while
    /// `rc.session_resume_secs` is above 0. `Some` ⇒ the connection's loss
    /// detaches its live sessions instead of ending them
    /// ([`Hub::unregister_agent`]). Per CONNECTION, like every word above:
    /// the next connection is announced its own, or none.
    pub resume_window: Option<u32>,
    /// FR-130 — the sessions this connection's hello claims back that are not
    /// answered yet. Each holds a place in the device's capacity (the busy
    /// gate counts it) from the registration until the claim is answered,
    /// so a new request cannot slip into a slot a kept session holds.
    pub pending_claims: Vec<ObjectId>,
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
    /// recording, a build without it, `MESHHARBORD_RECORDING=0`, or a host that
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
/// strips both again on its own terms (`meshharbord`'s `extauth::admit_session`),
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
/// A device's answer about its accounts: the list after the operation, or its refusal.
pub type LocalAccountsAnswer =
    std::result::Result<Vec<meshharbor_remote_control::signaling::LocalAccount>, String>;

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

    /// 0.5.0 — Per-agent serialization mutex for silent-monitor admission,
    /// cap checks, takeover ownership, and parent teardown (prevents
    /// admission-vs-teardown races and dual-admin takeover conflicts).
    agent_monitor_locks: DashMap<ObjectId, Arc<Mutex<()>>>,

    /// 0.5.0 — Live SSH sessions (classic, persistent PTY, and shared SSH),
    /// keyed by `grant_id` (or synthetic key-list key) for the unified
    /// real-time monitoring console and active admin disconnect.
    live_ssh: DashMap<String, LiveSshSessionInfo>,

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
    /// Same-pod only: the agent's WS receive path and the awaiting HTTP
    /// handler live in one process; a pod without the device's socket answers
    /// offline (`agent_exec.rs`), and FR-94's service path uses `exec_pending`.
    exec_waiters: DashMap<String, oneshot::Sender<ExecOutcome>>,

    /// MeshHarbor — owners parked on a `rc:accounts.result`, keyed by request
    /// id. Same-pod only, like [`Self::exec_waiters`].
    account_waiters: DashMap<String, oneshot::Sender<LocalAccountsAnswer>>,

    /// FR-115 P3b — the cluster-wide slot record, set once at startup when
    /// the deployment has Redis (`meshharbor_core::cluster::session_slots`).
    session_slots: std::sync::OnceLock<SessionSlots>,
    /// FR-115 P3b — the live sessions that hold a slot, each with the lease
    /// this pod renews (`slot_leases`) and gives back when the session ends
    /// (`terminate_with_limit`, the one place every session ends).
    slotted: DashMap<ObjectId, Lease>,

    /// X14 — independent direction kill switches so disabling upload never
    /// affects download (and vice versa).
    file_child_download_disabled: std::sync::atomic::AtomicBool,
    file_child_upload_disabled: std::sync::atomic::AtomicBool,

    /// MeshHarbor #21 — relay locality. Set once at startup when
    /// `app.business_isolation` is not `off`; unset (tests, isolation off)
    /// hands every ICE server out as before.
    ice_gate: std::sync::OnceLock<IceGate>,
    /// #21 — each online agent's business zone, as its CURRENT control
    /// connection (named by `conn_id`) was observed opening. Written once the
    /// connection's observation lands, removed at that connection's teardown
    /// only while it still names it; a displaced connection never clears, or
    /// overwrites, its replacement's zone.
    agent_zones: DashMap<ObjectId, (String, BusinessZone)>,
    /// Observed trusted public IP of each online agent's current control WS.
    agent_live_ips: DashMap<ObjectId, (String, std::net::IpAddr)>,
    /// FR-138 — active control-WS `conn_id` for each online agent (tracked even when
    /// the WS connects from a non-public/loopback address).
    agent_live_conn_ids: DashMap<ObjectId, String>,
    /// FR-138 — per-agent in-memory zone hysteresis state scoped to `conn_id`.
    agent_zone_hysteresis:
        DashMap<ObjectId, meshharbor_remote_control::models::ConnectionZoneHysteresis>,
    /// Per-device revisioned Logical Network Zone ICE/STUN policy.
    agent_zone_ice_policies: DashMap<ObjectId, AgentZoneIcePolicy>,
    /// Shared DNS-refreshed ICE server zone/country map (independent of `#21` gate mode).
    ice_zones: std::sync::OnceLock<Arc<IceServerZones>>,
    /// Optional GeoIP database for synchronous literal-IP STUN/TURN country checks.
    geoip: std::sync::OnceLock<Arc<meshharbor_core::user_analytics::GeoIp>>,
    /// FR-121 — `turn.stun_urls` parsed: `(zone id, url)`, `None` = global.
    zone_stun: std::sync::OnceLock<Vec<(Option<String>, String)>>,
}

/// Per-device Logical Network Zone ICE/STUN policy cached on the Hub.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentZoneIcePolicy {
    pub policy_revision: u64,
    pub strict: bool,
    pub allowed_countries: std::collections::HashSet<String>,
    /// FR-121 — the zone the device resolved to (`None`: unresolved, which
    /// is strict, or a tenant without zones when `zones` is empty).
    pub zone: Option<String>,
    /// FR-121 — the tenant's zones, as a session route needs them: to place
    /// an address that belongs to no device (a controller's candidate).
    pub zones: Arc<Vec<ZoneRouteInfo>>,
}

/// FR-121 — one logical network zone, as the hub routes a session by it.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ZoneRouteInfo {
    pub id: String,
    pub auto_countries: Vec<String>,
    pub is_default: bool,
    /// `cross_zone_mode == RouterOnly`: this zone meets others only through
    /// its gateways.
    pub router_only: bool,
}

/// FR-121 — the `rc:error` code that tells a controller on no mesh node its
/// session can only fail (an advisory: the attempt is not ended).
pub const ZONE_REQUIRES_MESH_CONTROLLER: &str = "zone_requires_mesh_controller";

/// The countries a zone's STUN/TURN infrastructure may sit in, for its
/// strict-zone ICE filter: the countries the operator declared for it
/// (`auto_countries`); only a zone that declares none takes its gateways'
/// observed countries instead.
///
/// Field (2026-11-19): the CN zone declares CN, and its one gateway's public
/// address reads HK. Taking the union made HK "inside" the CN zone, so a CN
/// device's remote-desktop ICE kept the centre's TLS TURN in HK, and the host
/// dialled it from the mainland during a session — business traffic leaving
/// the zone (blocked at the border, but attempted). A gateway is admitted as
/// a gateway, by id, never by lending the whole zone its country.
pub fn zone_infra_countries(
    declared: &[String],
    gateway_countries: impl IntoIterator<Item = String>,
) -> std::collections::HashSet<String> {
    let declared: std::collections::HashSet<String> =
        declared.iter().map(|c| c.to_ascii_uppercase()).collect();
    if !declared.is_empty() {
        return declared;
    }
    gateway_countries
        .into_iter()
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// FR-121 — a tenant's zones as the hub routes a remote-desktop session.
pub fn zone_route_infos(
    zones: &[meshharbor_remote_control::models::NetworkZone],
) -> Arc<Vec<ZoneRouteInfo>> {
    Arc::new(
        zones
            .iter()
            .map(|z| ZoneRouteInfo {
                id: z.id.clone(),
                auto_countries: z
                    .auto_countries
                    .iter()
                    .map(|c| c.to_ascii_uppercase())
                    .collect(),
                is_default: z.is_default,
                router_only: z.cross_zone_mode
                    == meshharbor_remote_control::models::CrossZoneMode::RouterOnly,
            })
            .collect(),
    )
}

impl AgentZoneIcePolicy {
    /// FR-121 — the zone fields for the cross-pod `zone_policy` ctrl event.
    pub fn zone_json(&self) -> (serde_json::Value, serde_json::Value) {
        (
            serde_json::json!(self.zone),
            serde_json::to_value(self.zones.as_ref()).unwrap_or(serde_json::Value::Null),
        )
    }

    /// FR-121 — read them back; absent (an older pod) is no zones.
    pub fn zone_from_json(ctrl: &serde_json::Value) -> (Option<String>, Arc<Vec<ZoneRouteInfo>>) {
        (
            ctrl.get("zone").and_then(|v| v.as_str()).map(str::to_owned),
            Arc::new(
                ctrl.get("zones")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
            ),
        )
    }
}

/// FR-121 — where a device or an address sits among a tenant's zones, the
/// hub's mirror of `DeviceZoneResolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneRes<'a> {
    Unconfigured,
    Unresolved,
    Resolved(&'a ZoneRouteInfo),
}

impl<'a> ZoneRes<'a> {
    fn of_policy(p: &'a AgentZoneIcePolicy) -> Self {
        if p.zones.is_empty() {
            // A strict policy with no zone table is the fail-closed reading
            // of a zone snapshot that could not be read: unresolved, never
            // "no zones".
            return if p.strict {
                ZoneRes::Unresolved
            } else {
                ZoneRes::Unconfigured
            };
        }
        match p
            .zone
            .as_deref()
            .and_then(|id| p.zones.iter().find(|z| z.id == id))
        {
            Some(z) => ZoneRes::Resolved(z),
            None => ZoneRes::Unresolved,
        }
    }

    /// An address that is no device's: its country's zone, else the default
    /// zone — `resolve_device_zone` without a pin.
    fn of_country(zones: &'a [ZoneRouteInfo], country: Option<&str>) -> Self {
        if zones.is_empty() {
            return ZoneRes::Unconfigured;
        }
        if let Some(cc) = country.map(str::trim).filter(|c| !c.is_empty())
            && let Some(z) = zones
                .iter()
                .find(|z| z.auto_countries.iter().any(|a| a.eq_ignore_ascii_case(cc)))
        {
            return ZoneRes::Resolved(z);
        }
        match zones.iter().find(|z| z.is_default) {
            Some(z) => ZoneRes::Resolved(z),
            None => ZoneRes::Unresolved,
        }
    }
}

/// FR-121 — the mesh's own pair rule (`network_zones::pair_requires_backbone_only`):
/// may these two meet only through the zone gateways?
fn zones_need_gateways(a: ZoneRes<'_>, b: ZoneRes<'_>) -> bool {
    match (a, b) {
        (ZoneRes::Unconfigured, ZoneRes::Unconfigured) => false,
        (ZoneRes::Unresolved, _) | (_, ZoneRes::Unresolved) => true,
        (ZoneRes::Resolved(za), ZoneRes::Resolved(zb)) => {
            za.id != zb.id && (za.router_only || zb.router_only)
        }
        _ => true,
    }
}

/// FR-121 — the `typ` of an ICE candidate line (`host`, `srflx`, `relay`, …).
fn candidate_type(candidate: &str) -> Option<&str> {
    let mut it = candidate.split_whitespace();
    it.by_ref().find(|t| *t == "typ")?;
    it.next()
}

/// MeshHarbor #21 — the hub's relay-locality gate (`app.rc_ice_zone_mode`):
/// which ICE servers sit in which zone, whether withholding the others is
/// enforced or only logged, and the `warn` line dedupe.
pub struct IceGate {
    pub zones: Arc<IceServerZones>,
    pub mode: IceGateMode,
    pub dedupe: meshharbor_core::ice_zones::LogDedupe,
}

impl IceGate {
    pub fn new(zones: Arc<IceServerZones>, mode: IceGateMode) -> Self {
        Self {
            zones,
            mode,
            dedupe: Default::default(),
        }
    }
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
        let download_disabled =
            std::env::var("MESHHARBOR_DISABLE_FILE_CHILD_DOWNLOAD").is_ok_and(|v| {
                meshharbor_remote_control::signaling::parse_file_child_disable_switch(&v)
            });
        let upload_disabled =
            std::env::var("MESHHARBOR_DISABLE_FILE_CHILD_UPLOAD").is_ok_and(|v| {
                meshharbor_remote_control::signaling::parse_file_child_disable_switch(&v)
            });
        Self {
            inner: Arc::new(HubInner {
                agents: DashMap::new(),
                sessions: DashMap::new(),
                agent_monitor_locks: DashMap::new(),
                live_ssh: DashMap::new(),
                controllers: DashMap::new(),
                turn,
                relay_load,
                audit,
                consent_tx,
                exec_waiters: DashMap::new(),
                account_waiters: DashMap::new(),
                session_slots: std::sync::OnceLock::new(),
                slotted: DashMap::new(),
                file_child_download_disabled: std::sync::atomic::AtomicBool::new(download_disabled),
                file_child_upload_disabled: std::sync::atomic::AtomicBool::new(upload_disabled),
                ice_gate: std::sync::OnceLock::new(),
                agent_zones: DashMap::new(),
                agent_live_ips: DashMap::new(),
                agent_live_conn_ids: DashMap::new(),
                agent_zone_hysteresis: DashMap::new(),
                agent_zone_ice_policies: DashMap::new(),
                ice_zones: std::sync::OnceLock::new(),
                geoip: std::sync::OnceLock::new(),
                zone_stun: std::sync::OnceLock::new(),
            }),
        }
    }

    pub fn is_file_child_direction_disabled(
        &self,
        direction: meshharbor_remote_control::signaling::FileChildDirection,
    ) -> bool {
        use meshharbor_remote_control::signaling::FileChildDirection;
        use std::sync::atomic::Ordering;
        match direction {
            FileChildDirection::Download => self
                .inner
                .file_child_download_disabled
                .load(Ordering::Relaxed),
            FileChildDirection::Upload => self
                .inner
                .file_child_upload_disabled
                .load(Ordering::Relaxed),
        }
    }

    pub fn set_file_child_direction_disabled(
        &self,
        direction: meshharbor_remote_control::signaling::FileChildDirection,
        disabled: bool,
    ) {
        use meshharbor_remote_control::signaling::FileChildDirection;
        use std::sync::atomic::Ordering;
        match direction {
            FileChildDirection::Download => {
                self.inner
                    .file_child_download_disabled
                    .store(disabled, Ordering::Relaxed);
            }
            FileChildDirection::Upload => {
                self.inner
                    .file_child_upload_disabled
                    .store(disabled, Ordering::Relaxed);
            }
        }
        if disabled {
            for entry in self.inner.sessions.iter() {
                let mut s = entry.value().lock();
                s.set_file_children_enabled_for(direction, false);
            }
        }
    }

    /// FR-115 P3b — hand the hub the slot record (once, at startup).
    pub fn set_session_slots(&self, slots: SessionSlots) {
        let _ = self.inner.session_slots.set(slots);
    }

    /// #21 — install the relay-locality gate (once, at startup).
    pub fn set_ice_gate(&self, gate: IceGate) {
        let _ = self.inner.ice_zones.set(gate.zones.clone());
        let _ = self.inner.ice_gate.set(gate);
    }

    pub fn set_ice_zones(&self, zones: Arc<IceServerZones>) {
        let _ = self.inner.ice_zones.set(zones);
    }

    pub fn set_geoip(&self, geoip: Arc<meshharbor_core::user_analytics::GeoIp>) {
        let _ = self.inner.geoip.set(geoip);
    }

    /// FR-121 — the operator's zone-tagged STUN servers (`turn.stun_urls`).
    pub fn set_zone_stun(&self, stun: Vec<(Option<String>, String)>) {
        let _ = self.inner.zone_stun.set(stun);
    }

    /// FR-121 — `ice` plus the STUN servers the operator pinned to
    /// `agent_id`'s zone, first. Field (2026-11-19): a strict CN-zone session
    /// kept only `turns:<hk-host>:5349`, which the border blocks, so neither
    /// side gathered a server-reflexive address and a same-zone pair whose
    /// mesh path is direct never connected. A zone's own STUN servers are what
    /// the mesh already uses there; they are added after the zone filter
    /// because the operator's tag, not GeoIP, says where they belong.
    fn with_zone_stun(&self, agent_id: ObjectId, mut ice: Vec<IceServer>) -> Vec<IceServer> {
        let Some(cfg) = self.inner.zone_stun.get() else {
            return ice;
        };
        let Some(zone) = self.agent_zone_ice_policy(agent_id).and_then(|p| p.zone) else {
            return ice;
        };
        let have: std::collections::HashSet<String> =
            ice.iter().flat_map(|s| s.urls.iter().cloned()).collect();
        let urls: Vec<String> = cfg
            .iter()
            .filter(|(z, u)| z.as_deref() == Some(zone.as_str()) && !have.contains(u))
            .map(|(_, u)| u.clone())
            .collect();
        if !urls.is_empty() {
            ice.insert(
                0,
                IceServer {
                    urls,
                    username: None,
                    credential: None,
                },
            );
        }
        ice
    }

    /// #21 — the relay-locality gate, when isolation is on.
    pub fn ice_gate(&self) -> Option<&IceGate> {
        self.inner.ice_gate.get()
    }

    /// #21 — record `agent_id`'s zone as connection `conn_id` observed it.
    /// `None` (no zone evidence) removes any earlier entry, so it is never
    /// stale.
    pub fn set_agent_business_zone(
        &self,
        agent_id: ObjectId,
        conn_id: &str,
        zone: Option<BusinessZone>,
    ) {
        match zone {
            Some(z) => {
                self.inner
                    .agent_zones
                    .insert(agent_id, (conn_id.to_string(), z));
            }
            None => {
                self.inner.agent_zones.remove(&agent_id);
            }
        }
    }

    /// #21 — drop `agent_id`'s zone, but only while it still belongs to
    /// connection `conn_id`.
    pub fn clear_agent_business_zone(&self, agent_id: ObjectId, conn_id: &str) {
        self.inner
            .agent_zones
            .remove_if(&agent_id, |_, (c, _)| c == conn_id);
    }

    /// #21 — `agent_id`'s current business zone, if its connection has one.
    pub fn agent_business_zone(&self, agent_id: ObjectId) -> Option<BusinessZone> {
        self.inner.agent_zones.get(&agent_id).map(|e| e.1)
    }

    pub fn set_agent_live_public_ip(
        &self,
        agent_id: ObjectId,
        conn_id: &str,
        ip: Option<std::net::IpAddr>,
    ) {
        self.inner
            .agent_live_conn_ids
            .insert(agent_id, conn_id.to_string());
        match ip.and_then(meshharbor_core::user_analytics::canonical_public_ip) {
            Some(clean) => {
                self.inner
                    .agent_live_ips
                    .insert(agent_id, (conn_id.to_string(), clean));
            }
            None => {
                self.inner.agent_live_ips.remove(&agent_id);
            }
        }
    }

    pub fn clear_agent_live_public_ip(&self, agent_id: ObjectId, conn_id: &str) {
        self.inner
            .agent_live_ips
            .remove_if(&agent_id, |_, (c, _)| c == conn_id);
        self.inner
            .agent_live_conn_ids
            .remove_if(&agent_id, |_, c| c == conn_id);
    }

    pub fn agent_live_public_ip(&self, agent_id: ObjectId) -> Option<std::net::IpAddr> {
        self.inner.agent_live_ips.get(&agent_id).map(|e| e.1)
    }

    /// FR-138 — live control-WS `conn_id` for `agent_id`, if connected on this pod.
    pub fn agent_live_conn_id(&self, agent_id: ObjectId) -> Option<String> {
        self.inner
            .agent_live_conn_ids
            .get(&agent_id)
            .map(|e| e.value().clone())
    }

    /// FR-138 — evaluate anti-flapping hysteresis for an incoming physical-path egress probe.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_probe_hysteresis(
        &self,
        agent_id: ObjectId,
        conn_id: &str,
        current_zone_id: Option<&str>,
        probe_country: Option<&str>,
        probe_zone_id: Option<&str>,
        ws_country: Option<&str>,
        default_route_vpn: bool,
        now_ms: i64,
    ) -> meshharbor_remote_control::models::ProbeHysteresisDecision {
        let mut entry = self
            .inner
            .agent_zone_hysteresis
            .entry(agent_id)
            .or_default();
        meshharbor_remote_control::models::evaluate_probe_hysteresis(
            entry.value_mut(),
            conn_id,
            current_zone_id,
            probe_country,
            probe_zone_id,
            ws_country,
            default_route_vpn,
            now_ms,
        )
    }

    /// FR-138 — drop per-connection hysteresis state when `conn_id` disconnects.
    pub fn clear_zone_hysteresis(&self, agent_id: ObjectId, conn_id: &str) {
        self.inner
            .agent_zone_hysteresis
            .remove_if(&agent_id, |_, st| st.conn_id == conn_id);
    }

    /// FR-138 — shift any pending hysteresis candidate timestamp backwards by `delta_ms`.
    /// Intended for deterministic tests verifying the 10-minute anti-flapping window.
    pub fn backdate_zone_hysteresis(&self, agent_id: ObjectId, delta_ms: i64) -> bool {
        if let Some(mut entry) = self.inner.agent_zone_hysteresis.get_mut(&agent_id)
            && let Some(ref mut pending) = entry.value_mut().pending
        {
            pending.first_seen_ms = pending.first_seen_ms.saturating_sub(delta_ms);
            return true;
        }
        false
    }

    /// Install a revisioned zone ICE policy for `agent_id`. Rejects stale
    /// updates whose `policy_revision` is strictly older than what is already stored,
    /// and combines equal-revision discrepancies conservatively (`strict = cur.strict || policy.strict`,
    /// intersecting `allowed_countries` among strict policies) so ties can never relax restrictions.
    pub fn set_agent_zone_ice_policy(
        &self,
        agent_id: ObjectId,
        policy: AgentZoneIcePolicy,
    ) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.inner.agent_zone_ice_policies.entry(agent_id) {
            Entry::Occupied(mut e) => {
                let cur = e.get();
                if policy.policy_revision < cur.policy_revision {
                    return false;
                }
                if policy.policy_revision == cur.policy_revision && cur != &policy {
                    let strict = cur.strict || policy.strict;
                    let allowed_countries = match (cur.strict, policy.strict) {
                        (true, true) => cur
                            .allowed_countries
                            .intersection(&policy.allowed_countries)
                            .cloned()
                            .collect(),
                        (true, false) => cur.allowed_countries.clone(),
                        (false, true) => policy.allowed_countries.clone(),
                        (false, false) => cur
                            .allowed_countries
                            .intersection(&policy.allowed_countries)
                            .cloned()
                            .collect(),
                    };
                    // FR-121 — two readings of one revision disagree on the
                    // zone: unresolved (strict) until a newer one settles it.
                    let zone = if cur.zone == policy.zone {
                        cur.zone.clone()
                    } else {
                        None
                    };
                    let zones = if policy.zones.is_empty() {
                        cur.zones.clone()
                    } else {
                        policy.zones.clone()
                    };
                    let combined = AgentZoneIcePolicy {
                        policy_revision: policy.policy_revision,
                        strict,
                        allowed_countries,
                        zone,
                        zones,
                    };
                    let changed = &combined != cur;
                    e.insert(combined);
                    return changed;
                }
                e.insert(policy);
                true
            }
            Entry::Vacant(v) => {
                v.insert(policy);
                true
            }
        }
    }

    pub fn agent_zone_ice_policy(&self, agent_id: ObjectId) -> Option<AgentZoneIcePolicy> {
        self.inner
            .agent_zone_ice_policies
            .get(&agent_id)
            .map(|e| e.value().clone())
    }

    pub fn url_matches_allowed_countries(
        &self,
        url: &str,
        allowed: &std::collections::HashSet<String>,
    ) -> bool {
        if allowed.is_empty() {
            return false;
        }
        let Some(geoip) = self.inner.geoip.get() else {
            return false;
        };
        if let Some((host, _)) = meshharbor_core::ice_zones::host_of(url)
            && let Ok(ip) = host.parse::<std::net::IpAddr>()
        {
            return geoip
                .security_lookup(ip)
                .country_code
                .is_some_and(|cc| allowed.contains(&cc.to_ascii_uppercase()));
        }
        if let Some(zones) = self
            .inner
            .ice_zones
            .get()
            .or_else(|| self.inner.ice_gate.get().map(|g| &g.zones))
        {
            return zones.url_matches_countries(geoip, url, allowed);
        }
        false
    }

    /// FR-121 — does `agent_id` sit in a STRICT logical network zone (its
    /// zone's links are gateway-only)?
    pub fn agent_zone_strict(&self, agent_id: ObjectId) -> bool {
        self.agent_zone_ice_policy(agent_id)
            .is_some_and(|p| p.strict)
    }

    /// FR-121 — the zone route of a session from a controller to `agent_id`.
    /// The controller is placed by its local agent (`ctrl_agent`, from the
    /// loopback-TURN descriptor) when that agent is a device of the same org
    /// connected here; otherwise it sits on no mesh node and each of its
    /// public addresses is placed on its own as it arrives.
    pub fn zone_route_for(&self, agent_id: ObjectId, ctrl_agent: Option<ObjectId>) -> ZoneRoute {
        let Some(target) = self.agent_zone_ice_policy(agent_id) else {
            return ZoneRoute::Open;
        };
        let target_res = ZoneRes::of_policy(&target);
        if target_res == ZoneRes::Unconfigured {
            return ZoneRoute::Open;
        }
        let org = self.agent_org(agent_id);
        let ctrl = ctrl_agent
            .filter(|c| *c != agent_id && org.is_some() && self.agent_org(*c) == org)
            .and_then(|c| self.agent_zone_ice_policy(c));
        match ctrl {
            Some(c) if zones_need_gateways(ZoneRes::of_policy(&c), target_res) => ZoneRoute::Mesh,
            Some(_) => ZoneRoute::Direct {
                mesh_fallback: true,
            },
            None => ZoneRoute::Direct {
                mesh_fallback: false,
            },
        }
    }

    /// FR-121 — may this candidate from the controller reach `agent_id`
    /// under `route`? `mesh_ip` is the controller's own overlay address (its
    /// loopback-TURN relay). On `Mesh` only that relay passes. On `Direct` a
    /// name (mDNS `.local`) or a non-public address passes — it cannot sit in
    /// another zone by itself — as does the mesh relay with `mesh_fallback`;
    /// a public address passes only when its zone may meet the device
    /// directly by the mesh's own pair rule. No GeoIP places it nowhere,
    /// which is strict.
    pub fn zone_admits_candidate(
        &self,
        agent_id: ObjectId,
        route: ZoneRoute,
        mesh_ip: Option<std::net::IpAddr>,
        candidate: &str,
    ) -> bool {
        let ip = meshharbor_core::ice_zones::candidate_ip(candidate);
        match route {
            ZoneRoute::Open => true,
            ZoneRoute::Mesh => {
                candidate_type(candidate) == Some("relay") && ip.is_some() && ip == mesh_ip
            }
            ZoneRoute::Direct { mesh_fallback } => {
                let Some(ip) = ip else { return true };
                if mesh_fallback && Some(ip) == mesh_ip {
                    return true;
                }
                if !meshharbor_core::ice_zones::is_public_ip(ip) {
                    return true;
                }
                let Some(target) = self.agent_zone_ice_policy(agent_id) else {
                    return false;
                };
                let country = self
                    .inner
                    .geoip
                    .get()
                    .and_then(|g| g.security_lookup(ip).country_code)
                    .map(|c| c.to_ascii_uppercase());
                let addr = match country {
                    Some(cc) => ZoneRes::of_country(&target.zones, Some(&cc)),
                    None => ZoneRes::Unresolved,
                };
                !zones_need_gateways(addr, ZoneRes::of_policy(&target))
            }
        }
    }

    /// FR-121 — may this candidate from the DEVICE reach the controller?
    /// Only on `Mesh` is anything withheld: the device's own relay inside the
    /// mesh (a non-public relay address) is the one path that route allows.
    fn zone_admits_agent_candidate(route: ZoneRoute, candidate: &str) -> bool {
        match route {
            ZoneRoute::Mesh => {
                candidate_type(candidate) == Some("relay")
                    && meshharbor_core::ice_zones::candidate_ip(candidate)
                        .is_some_and(|ip| !meshharbor_core::ice_zones::is_public_ip(ip))
            }
            _ => true,
        }
    }

    /// FR-121 — may a trickled candidate from `role` reach the other side?
    fn zone_admits_trickle(
        &self,
        agent_id: ObjectId,
        session_id: ObjectId,
        role: Role,
        candidate: &serde_json::Value,
    ) -> bool {
        let Some(c) = candidate_text(candidate) else {
            return true; // end-of-candidates
        };
        let (route, mesh_ip) = self.session_zone(session_id);
        let ok = match role {
            Role::Controller => self.zone_admits_candidate(agent_id, route, mesh_ip, c),
            Role::Agent => Self::zone_admits_agent_candidate(route, c),
        };
        if matches!(role, Role::Controller) {
            self.zone_note_controller_candidate(session_id, route, c, ok);
        }
        if !ok {
            info!(
                session = %session_id.to_hex(),
                agent = %agent_id.to_hex(),
                ?route,
                from = ?role,
                "rc zone route: a candidate the zones do not allow dropped"
            );
        }
        ok
    }

    /// FR-121 — a controller on no mesh node (a `Direct` route with no mesh
    /// fallback) whose public address the zones do not let meet the device
    /// can only fail: say so the moment that address is dropped, while nothing
    /// public has passed, instead of letting ICE run out its clock (the
    /// viewer showed the sentence only after a 15 s timeout and a redial).
    /// Advisory, once per session: the attempt goes on, so a LAN path the
    /// zones cannot see still connects (and clears the viewer's notice).
    fn zone_note_controller_candidate(
        &self,
        session_id: ObjectId,
        route: ZoneRoute,
        candidate: &str,
        admitted: bool,
    ) {
        if route
            != (ZoneRoute::Direct {
                mesh_fallback: false,
            })
        {
            return;
        }
        let Some(ip) = meshharbor_core::ice_zones::candidate_ip(candidate) else {
            return;
        };
        if !meshharbor_core::ice_zones::is_public_ip(ip) {
            return;
        }
        let Some(arc) = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())
        else {
            return;
        };
        let tx = {
            let mut s = arc.lock();
            if admitted {
                s.zone_public_admitted += 1;
                return;
            }
            let decisive = matches!(candidate_type(candidate), Some("srflx") | Some("relay"));
            if !decisive || s.zone_advised || s.zone_public_admitted > 0 || s.local_relay.is_some()
            {
                return;
            }
            s.zone_advised = true;
            s.controller_tx.clone()
        };
        info!(
            session = %session_id.to_hex(),
            "rc zone route: the controller is on no mesh node and its zone cannot meet the device directly — told it"
        );
        if let Some(tx) = tx {
            let _ = tx.try_send(ServerMsg::Error {
                session_id: Some(session_id),
                code: ZONE_REQUIRES_MESH_CONTROLLER.to_string(),
                message: "this device is in another network zone; connect from a device signed in to MeshHarbor".to_string(),
                open_nonce: None,
            });
        }
    }

    /// FR-121 — a session's route and the controller's mesh relay address.
    fn session_zone(&self, session_id: ObjectId) -> (ZoneRoute, Option<std::net::IpAddr>) {
        self.inner
            .sessions
            .get(&session_id)
            .map(|arc| {
                let s = arc.value().lock();
                // Only an overlay address counts as the relay: a descriptor
                // naming a public one would let a relay candidate out of the
                // mesh.
                (
                    s.zone_route,
                    s.local_relay
                        .as_ref()
                        .filter(|lr| is_overlay_relay_ip(&lr.overlay_ip))
                        .and_then(|lr| lr.overlay_ip.parse().ok()),
                )
            })
            .unwrap_or((ZoneRoute::Open, None))
    }

    /// FR-121 — the browser named its local agent only with its offer (the
    /// request never waits for the probe): adopt that descriptor and settle
    /// the zone route with it, before the offer goes on to the device.
    pub fn settle_zone_route(
        &self,
        session_id: ObjectId,
        local_relay: Option<LocalRelayDescriptor>,
    ) {
        let Some(lr) = local_relay else { return };
        let Some(arc) = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())
        else {
            return;
        };
        let agent_id = {
            let mut s = arc.lock();
            if s.local_relay.is_some() || s.zone_route == ZoneRoute::Open {
                return;
            }
            s.local_relay = Some(lr.clone());
            s.agent_id
        };
        let ctrl = lr
            .agent_id
            .as_deref()
            .and_then(|a| ObjectId::parse_str(a).ok());
        let route = self.zone_route_for(agent_id, ctrl);
        arc.lock().zone_route = route;
        info!(
            session = %session_id.to_hex(),
            ?route,
            "rc zone route: settled with the controller's local agent"
        );
    }

    /// FR-121 — `sdp` without the `a=candidate:` lines `route` does not let
    /// reach the other side (`from_controller`: the offer's, else the answer's).
    fn zone_filter_sdp(
        &self,
        agent_id: ObjectId,
        session_id: ObjectId,
        from_controller: bool,
        sdp: String,
    ) -> String {
        let (route, mesh_ip) = self.session_zone(session_id);
        if route == ZoneRoute::Open {
            return sdp;
        }
        let mut dropped = 0usize;
        let kept: String = sdp
            .split_inclusive('\n')
            .filter(|line| {
                let l = line.trim_start();
                let keep = !l.starts_with("a=candidate:")
                    || if from_controller {
                        self.zone_admits_candidate(agent_id, route, mesh_ip, l)
                    } else {
                        Self::zone_admits_agent_candidate(route, l)
                    };
                dropped += usize::from(!keep);
                keep
            })
            .collect();
        if dropped > 0 {
            info!(
                session = %session_id.to_hex(),
                agent = %agent_id.to_hex(),
                ?route,
                dropped,
                "rc zone route: SDP candidates the zones do not allow dropped"
            );
        }
        kept
    }

    /// FR-121 — the ICE servers a viewer of `agent_id` may use: the device's
    /// own strict-zone list when it has one, else `ice` unchanged. The viewer
    /// builds its peer connection from `/api/turn/credentials`, so without
    /// this its relay candidate would sit on a server outside the zone.
    pub fn viewer_zone_ice(&self, agent_id: ObjectId, ice: Vec<IceServer>) -> Vec<IceServer> {
        if !self.agent_zone_strict(agent_id) {
            return self.with_zone_stun(agent_id, ice);
        }
        self.zone_local_ice(agent_id, ObjectId::new(), ice)
    }

    /// #21 relay locality + Logical Network Zone strict country gate: the ICE
    /// servers of a session with `agent_id`, kept to the device's own zone.
    fn zone_local_ice(
        &self,
        agent_id: ObjectId,
        session_id: ObjectId,
        ice: Vec<IceServer>,
    ) -> Vec<IceServer> {
        let filtered = self.zone_filtered_ice(agent_id, session_id, ice);
        self.with_zone_stun(agent_id, filtered)
    }

    /// [`Self::zone_local_ice`] before the zone's own STUN servers are added.
    fn zone_filtered_ice(
        &self,
        agent_id: ObjectId,
        session_id: ObjectId,
        ice: Vec<IceServer>,
    ) -> Vec<IceServer> {
        if let Some(policy) = self.agent_zone_ice_policy(agent_id)
            && policy.strict
        {
            let mut kept = Vec::with_capacity(ice.len());
            let mut withheld_urls = 0usize;
            let mut kept_urls = 0usize;
            for mut srv in ice {
                let before = srv.urls.len();
                srv.urls
                    .retain(|u| self.url_matches_allowed_countries(u, &policy.allowed_countries));
                kept_urls += srv.urls.len();
                withheld_urls += before - srv.urls.len();
                if !srv.urls.is_empty() {
                    kept.push(srv);
                }
            }
            if withheld_urls > 0 {
                info!(
                    session = %session_id.to_hex(),
                    agent = %agent_id.to_hex(),
                    policy_revision = policy.policy_revision,
                    withheld = withheld_urls,
                    kept = kept_urls,
                    "rc ice zone: STUN/TURN outside the device's strict network zone withheld"
                );
            }
            return kept;
        }
        let Some(gate) = self.inner.ice_gate.get() else {
            return ice;
        };
        let zone = self.agent_business_zone(agent_id);
        let f = meshharbor_core::ice_zones::keep_in_zone(ice.clone(), zone, |u| {
            gate.zones.zone_of_url(u)
        });
        if f.withheld_urls == 0 {
            return ice;
        }
        match gate.mode {
            IceGateMode::Enforce => {
                info!(
                    session = %session_id.to_hex(),
                    agent = %agent_id.to_hex(),
                    ?zone,
                    withheld = f.withheld_urls,
                    kept = f.kept_urls,
                    reason = f.reason,
                    "rc ice zone: STUN/TURN outside the device's zone withheld"
                );
                f.kept
            }
            IceGateMode::Warn => {
                // One line per device while the verdict stays the same: the
                // three issuances of one session, and every later session within
                // `WARN_DEDUPE`, would otherwise each repeat it.
                let verdict = format!(
                    "zone={zone:?} kept={} withheld={} reason={}",
                    f.kept_urls, f.withheld_urls, f.reason
                );
                if gate.dedupe.first_in(
                    &agent_id.to_hex(),
                    &verdict,
                    meshharbor_core::ice_zones::WARN_DEDUPE,
                ) {
                    warn!(
                        session = %session_id.to_hex(),
                        agent = %agent_id.to_hex(),
                        device_zone = ?zone,
                        kept = f.kept_urls,
                        would_withhold = f.withheld_urls,
                        reason = f.reason,
                        "rc ice zone (warn): would withhold STUN/TURN outside the device's zone; nothing changed (app.rc_ice_zone_mode=enforce applies it)"
                    );
                }
                ice
            }
        }
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
        let reg = self.register_agent_resuming(
            agent_id,
            tenant_id,
            owner_user_id,
            os,
            max_sessions,
            input_arbiter,
            supports_exec,
            ResumeHello::default(),
        );
        (reg.tx, reg.cancel, reg.rx)
    }

    /// FR-130 — [`Self::register_agent`], with what the hello said about
    /// resuming: whether the device advertises `rc-resume`, the window this
    /// connection is announced (`None`: none) and the sessions it claims back.
    /// Each claim the window admits holds a place in the device's capacity
    /// from here until it is answered, and is spared the in-memory reap
    /// below: whether it goes on is the claim's to decide. With no window,
    /// every claim is refused at once and the reap runs as it always has.
    #[allow(clippy::too_many_arguments)]
    pub fn register_agent_resuming(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        os: OsKind,
        max_sessions: u8,
        input_arbiter: bool,
        supports_exec: bool,
        hello: ResumeHello,
    ) -> Registration {
        let resume_window = hello.window;
        let (claims, refused) = resume::sort_claims(hello.window, hello.kept, max_sessions);
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
            supports_ssh_resume: false,
            supports_rc_continue: false,
            supports_silent_monitor: false,
            supports_relay_control: false,
            supports_relay_regions: false,
            supports_relay_server: false,
            supports_management_path: false,
            supports_management_entry: false,
            management_entry_port: None,
            via_management_entry: None,
            default_route_vpn: false,
            // FR-130 — whether the device keeps its peers at all, the window
            // this connection is announced, and the claims it holds a place
            // for until they are answered.
            advertises_resume: hello.advertised,
            resume_window,
            pending_claims: claims.clone(),
        };
        // FR-130 — a row created before this instant belongs to an earlier
        // connection: the registration read's line.
        let registered_at = bson::DateTime::now();
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
        //
        // FR-130 — a session this hello claims back is spared: the device
        // kept its peer, and the claim decides whether it goes on. With no
        // window there are no claims, and every Active session is reaped as
        // it always was.
        let zombies: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter(|e| {
                let s = e.value().lock();
                s.agent_id == agent_id && s.phase == SessionPhase::Active
            })
            .map(|e| *e.key())
            .filter(|sid| !claims.contains(sid))
            .collect();
        for session_id in &zombies {
            warn!(
                %agent_id, %session_id,
                "agent re-registered with a stale ACTIVE session — reaping the zombie \
                 (its Terminate died with the previous control WS)"
            );
            let _ = self.end_own(*session_id, EndReason::AgentDisconnect, None);
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
        Registration {
            tx,
            cancel,
            rx,
            claims,
            refused,
            reaped: zombies,
            registered_at,
        }
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
        // Keep the identity comparison and removal under the same DashMap
        // shard lock: a replacement must not slip between them.
        let removed = match tx {
            Some(expected_tx) => self.inner.agents.remove_if(&agent_id, |_, agent| {
                let matches = ptr_eq(&agent.tx, expected_tx);
                #[cfg(test)]
                if matches {
                    tests::pause_agent_remove_if_armed(agent_id);
                }
                matches
            }),
            None => self.inner.agents.remove(&agent_id),
        };
        // FR-130 — the entry itself comes out, not only the fact that it
        // did: the window its connection was announced decides below whether
        // its live sessions end or are kept for the device to claim back.
        let Some((_, entry)) = removed else {
            if tx.is_some() {
                info!(
                    "agent {} unregister skipped (tx no longer matches; newer connection holds the slot)",
                    agent_id
                );
            }
            return false;
        };
        info!("agent {} offline", agent_id);
        match entry.resume_window {
            // FR-130 — this connection was announced a window: its live
            // sessions outlive the socket (the device keeps their peers),
            // and the rest end as they always have.
            Some(window_secs) => self.detach_agent_sessions(agent_id, window_secs),
            None => self.end_agent_sessions(agent_id),
        }
        // 0.5.0 — drop non-resumable live SSH sessions on the departed agent so
        // the real-time monitoring view never holds ghost rows after disconnect.
        self.inner
            .live_ssh
            .retain(|_, s| s.agent_id != agent_id || s.resume_allowed);
        true
    }

    /// Force-close every session tied to this agent. FR-130 — an end the hub
    /// decides on its own, so each is fenced at the number the hub holds.
    pub(crate) fn end_agent_sessions(&self, agent_id: ObjectId) {
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
            let _ = self.end_own(sid, EndReason::AgentDisconnect, None);
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
        let msg = ServerMsg::Goodbye {
            reason: AgentCloseReason::AgentDeleted,
            message: "This device was removed from its organization. Re-enrol it with a \
                      fresh enrollment token from the admin UI \
                      (`meshharbord re-enroll --token <jwt>`)."
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
        // FR-130 — a claim not answered yet is a session the device holds.
        if agent.active_sessions > 0 || !agent.pending_claims.is_empty() {
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
        // FR-130 — a session its viewer may hold is kept for the viewer to
        // rejoin (`hold.rs`); everything else ends here as it always has.
        for session_id in orphaned {
            let _ = self.viewer_gone(session_id, tx);
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
    /// Consent is then awaited on a task the session spawns itself
    /// ([`Self::create_session_full`]), ending in `handle_consent_outcome`.
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
        input_mode: Option<meshharbor_remote_control::models::InputMode>,
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
        input_mode: Option<meshharbor_remote_control::models::InputMode>,
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
        // extauth relay (`meshharbor_mod_remote::extauth`), after it found the
        // principal's verified login and checked the device advertises
        // `external-session`; `dispatch` always passes `None`.
        external: Option<meshharbor_remote_control::signaling::ExternalGrant>,
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
            None,
            SessionCreationOrigin::Unknown,
            None,
            None,
            None,
            false,
            None,
        )
    }

    // Preserve the existing session-creation interface shared by browser and
    // scoped-share callers; grouping its policy fields is unrelated to linting.
    #[allow(clippy::too_many_arguments)]
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
        input_mode: Option<meshharbor_remote_control::models::InputMode>,
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
        // extauth relay (`meshharbor_mod_remote::extauth`), after it found the
        // principal's verified login and checked the device advertises
        // `external-session`; `dispatch` always passes `None`.
        external: Option<meshharbor_remote_control::signaling::ExternalGrant>,
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
        // MeshHarbor — the share account a shared session's file operations
        // run as (`DispatchCtx::share_files_account`); ignored without a share.
        share_files_account: Option<String>,
        origin: SessionCreationOrigin,
        initial_resolution: Option<meshharbor_remote_control::signaling::InitialResolution>,
        // FR-129 — the person's two-factor code, relayed to the device in the Request and
        // checked there; the hub never reads it.
        two_factor_code: Option<meshharbor_remote_control::models::Confidential>,
        // FR-141 — validated prior session id when the viewer is auto-continuing
        // after an agent restart (`DispatchCtx::continues`).
        continues: Option<ObjectId>,
        // 0.5.0 — server-validated admin silent monitor (`DispatchCtx::silent_monitor`).
        silent_monitor: bool,
        // 0.5.0 — optional specific active regular session bound to this silent monitor.
        monitor_target_session_id: Option<ObjectId>,
    ) -> Result<ObjectId> {
        // 0.5.0 — clamp silent monitoring parameters defensively inside the Hub:
        // silent monitors never record, never lock on end, never idle-out, never
        // carry audio/clipboard/files, never escalate VIEW-only into INPUT, and
        // always auto-consent on an active host.
        let (
            permissions,
            audio_enabled,
            consent_mode,
            override_reason,
            may_record,
            max_duration,
            idle_secs,
            lock_on_end,
            org_session_cap,
            continues,
            share_grant_id,
            monitor_target_session_id,
        ) = if silent_monitor {
            (
                permissions & (Permissions::VIEW | Permissions::INPUT),
                false,
                ConsentMode::Auto,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
                monitor_target_session_id,
            )
        } else {
            (
                permissions,
                audio_enabled,
                consent_mode,
                override_reason,
                may_record,
                max_duration,
                idle_secs,
                lock_on_end,
                org_session_cap,
                continues,
                share_grant_id,
                None,
            )
        };
        // Positive provenance requires the dedicated, post-PDP local entry.
        // Optional scopes below only veto it; their absence never creates it.
        let controller_scope = if !silent_monitor
            && matches!(origin, SessionCreationOrigin::LocalPdp)
            && share_grant_id.is_none()
            && external.is_none()
            && override_reason.is_none()
            && matches!(consent_mode, ConsentMode::Auto | ConsentMode::Prompt)
        {
            FileChildControllerScope::local_pdp(consent_mode)
        } else {
            FileChildControllerScope::unknown(
                consent_mode,
                external.as_ref().map(|grant| grant.attempt_id.clone()),
                override_reason.is_some(),
            )
        };
        let permissions = if share_grant_id.is_some() {
            permissions & (Permissions::VIEW | Permissions::INPUT | Permissions::FILES)
        } else {
            permissions
        };
        let device_share_scope = share_grant_id.map(|grant_id| {
            meshharbor_remote_control::session::DeviceShareSessionScope {
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
        //
        // FR-130 — a session with NO controller is never an orphan here: a
        // session a device's claim rebuilt waits for its viewer's rejoin with
        // none, and so does one held through its viewer's socket loss. Before
        // FR-130 no session was ever without one. A session held for its
        // viewer (`hold::held_for_viewer`: its controller gone or closed) is
        // spared against ANOTHER person's request, and reaped as before for
        // its own person's: a page too old to send `replaces`, or that
        // person's other tab. The remote module reaps those first, before it
        // claims the org's slot (`Hub::reap_held_for`).
        let orphaned: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter_map(|e| {
                let dead_controller = {
                    let s = e.value().lock();
                    let gone = s.controller_tx.as_ref().is_none_or(|tx| tx.is_closed());
                    let held = hold::held_for_viewer(&s) && gone;
                    s.agent_id == agent_id
                        && if held {
                            s.controller_user_id == controller_user_id
                        } else {
                            s.controller_tx.as_ref().is_some_and(|tx| tx.is_closed())
                        }
                };
                dead_controller.then(|| *e.key())
            })
            .collect();
        for sid in orphaned {
            let _ = self.end_own(sid, EndReason::ControllerHangup, None);
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
                && s.controller_user_id == controller_user_id
                && s.silent_monitor == silent_monitor
                && s.matches_file_child_controller_scope(&controller_scope)
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
                    s.resume_secs,
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
            existing_resume_secs,
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
                // FR-130 — and whether it may be held, as its first answer
                // said.
                resume_secs: existing_resume_secs,
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
                if s.tenant_id == org && !s.silent_monitor && s.phase != SessionPhase::Closed {
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

        // 0.5.0 — Silent admin monitoring requires:
        // 1. An agent that explicitly advertises `silent-monitor` (fail-closed
        //    for older daemons that would otherwise show a host banner).
        // 2. An `Active` (post-consent, live) non-monitor RC session in the
        //    same tenant on this device — matching `monitor_target_session_id`
        //    when provided.
        // 3. Per-agent lock held across admission check, cap enforcement (< 2),
        //    and insertion into `self.inner.sessions` so admission cannot race
        //    parent teardown or overshoot the cap.
        let monitor_lock_arc = if silent_monitor {
            Some(self.agent_monitor_lock(agent_id))
        } else {
            None
        };
        let _monitor_guard = monitor_lock_arc.as_ref().map(|m| m.lock());
        if silent_monitor {
            let (agent_tenant, supports_sm) = {
                let agent = self
                    .inner
                    .agents
                    .get(&agent_id)
                    .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
                (agent.tenant_id, agent.supports_silent_monitor)
            };
            if !supports_sm {
                return Err(Error::PermissionDenied(
                    "target agent version does not support silent monitoring",
                ));
            }
            let mut has_active_target = false;
            let mut active_monitors = 0usize;
            for e in self.inner.sessions.iter() {
                let s = e.value().lock();
                if s.agent_id != agent_id
                    || s.tenant_id != agent_tenant
                    || s.phase == SessionPhase::Closed
                {
                    continue;
                }
                if s.silent_monitor {
                    active_monitors += 1;
                } else if s.phase == SessionPhase::Active {
                    if let Some(target_sid) = monitor_target_session_id {
                        if s.id == target_sid {
                            has_active_target = true;
                        }
                    } else {
                        has_active_target = true;
                    }
                }
            }
            if !has_active_target {
                return Err(Error::PermissionDenied(
                    "no active remote control session on this device",
                ));
            }
            if active_monitors >= 2 {
                return Err(Error::AgentBusy);
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
            agent_window,
            agent_rc_continue,
        ) = {
            let mut agent = self
                .inner
                .agents
                .get_mut(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            // FR-130 — a claim not answered yet holds its place: a new request
            // cannot slip into a slot a kept session holds. Silent monitors
            // bypass regular user capacity so monitoring works even when
            // max_sessions == 1.
            if !silent_monitor {
                if usize::from(agent.active_sessions) + agent.pending_claims.len()
                    >= usize::from(agent.max_sessions)
                {
                    return Err(Error::AgentBusy);
                }
                agent.active_sessions += 1;
            }
            (
                agent.tenant_id,
                agent.input_arbiter,
                agent.record_support,
                agent.privacy_support,
                agent.asks_features,
                agent.device_session_policy,
                agent.enforces_idle,
                agent.honours_lock_on_end,
                // FR-130 — the window this connection was announced, if any.
                agent.resume_window,
                // FR-141 — whether this agent honours `Request.continues`.
                agent.supports_rc_continue,
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
        let (mut live, waiter) = LiveSession::new_with_controller_scope(
            session_id,
            agent_id,
            agent_org,
            controller_user_id,
            permissions,
            controller_tx.clone(),
            controller_scope,
        );
        live.controller_name = controller_name.clone();
        live.silent_monitor = silent_monitor;
        live.monitor_target_session_id = monitor_target_session_id;
        if let Some(scope) = device_share_scope {
            live.bind_device_share(scope)?;
            live.set_shared_lease_epoch(uuid::Uuid::new_v4().to_string())?;
            // The account rides the lease only when the session can touch
            // files at all; the device decides what an absent one means.
            if live.permissions().contains(Permissions::FILES) {
                live.set_shared_files_account(share_files_account)?;
            }
        }
        // Loopback-TURN corp-relay (Phase 2): remember the controller's local
        // agent TURN descriptor so `forward_offer` can hand the REMOTE agent a
        // relay it reaches over the overlay. Validated at use, not here.
        // FR-121 — the zone route, from the controller's local agent when its
        // descriptor names one.
        let ctrl_agent = local_relay
            .as_ref()
            .and_then(|lr| lr.agent_id.as_deref())
            .and_then(|a| ObjectId::parse_str(a).ok());
        live.zone_route = self.zone_route_for(agent_id, ctrl_agent);
        let zone_route = live.zone_route;
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
        live.set_file_children_opted_in_for(
            meshharbor_remote_control::signaling::FileChildDirection::Download,
            !self.is_file_child_direction_disabled(
                meshharbor_remote_control::signaling::FileChildDirection::Download,
            ) && browser_caps.iter().any(|c| c == "file-child-download"),
        );
        live.set_file_children_opted_in_for(
            meshharbor_remote_control::signaling::FileChildDirection::Upload,
            !self.is_file_child_direction_disabled(
                meshharbor_remote_control::signaling::FileChildDirection::Upload,
            ) && browser_caps.iter().any(|c| c == "file-child-upload"),
        );
        // FR-130 — an outsider's session, FR-52's external one or one opened
        // through a device share, is never held or resumed (upstream's D3;
        // a share's lease needs the centre every few seconds).
        live.external = external.is_some() || share_grant_id.is_some();
        let live_external = live.external;
        // FR-130 — its viewer may hold it through a socket's loss for the
        // window the device's connection holds (a positive one); never an
        // outsider's.
        let resume_secs = if silent_monitor {
            None
        } else {
            agent_window.filter(|&w| w > 0 && !live_external)
        };
        live.resume_secs = resume_secs;
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
            // FR-130 — this session may be held, for this long: the page then
            // keeps it through a socket's loss and claims it back with
            // `rc:session.rejoin`. Absent with no window, as before.
            resume_secs,
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
        // FR-130 (review 1, L6) — the row's `external` marker, where a claim
        // refuses it (D3): only while the device's connection holds a window,
        // so with none the row is the one it always was.
        let external_marked = live_external && agent_window.is_some_and(|w| w > 0);
        let request = ServerMsg::Request {
            two_factor_code,
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
            // FR-121 — how the zones let this session's media travel.
            zone_route: zone_route.wire().map(str::to_owned),
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
            initial_resolution,
            continues: continues.filter(|_| agent_rc_continue && !live_external),
            silent_monitor,
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
                external: external_marked,
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
                    let _ = self.end_own(session_id, EndReason::Error, None);
                    return;
                }
                // Tell the controller it can send its offer.
                if let Some(tx) = controller_tx {
                    let user_id = self.controller_for(session_id).unwrap_or_default();
                    // Region policy: the session's region was FROZEN (load-
                    // aware, agent-nearest) at create — all three issuance
                    // pushes read it so both ICE ends land on one PoP.
                    let region = self.session_relay_region(session_id);
                    let ice = self.zone_local_ice(
                        agent_id,
                        session_id,
                        ice_servers_for_session(
                            &Self::turn_user(user_id, tenant_id),
                            &session_id.to_hex(),
                            self.inner.turn.cfg_for(region.as_deref()),
                        ),
                    );
                    let zone_route = self.session_zone(session_id).0.wire().map(str::to_owned);
                    let _ = tx.try_send(ServerMsg::Ready {
                        session_id,
                        ice_servers: ice,
                        zone_route,
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
            // FR-129 — the DEVICE refused on two-factor (it checks the code itself). Audited
            // as a refusal; ended with the reason, so the viewer asks the person for a code.
            ConsentOutcome::TwoFactorRequired => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentDenied);
                let _ = self.terminate(session_id, EndReason::TwoFactorRequired);
            }
            ConsentOutcome::TwoFactorInvalid => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentDenied);
                let _ = self.terminate(session_id, EndReason::TwoFactorInvalid);
            }
            ConsentOutcome::TwoFactorLocked => {
                self.audit(session_id, agent_id, tenant_id, AuditKind::ConsentDenied);
                let _ = self.terminate(session_id, EndReason::TwoFactorLocked);
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
            let _ = self.end_own(session_id, EndReason::Error, None);
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
        let outcome = meshharbor_remote_control::consent::outcome_of(granted, reason);
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
        peer_auth: Option<meshharbor_remote_control::signaling::PeerAuthOffer>,
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
                            Some(meshharbor_remote_control::signaling::SharedSessionLease {
                                grant_id: scope.grant_id,
                                lease_epoch: s
                                    .shared_lease_epoch()
                                    .ok_or(Error::PermissionDenied(
                                        "shared session missing immutable lease",
                                    ))?
                                    .to_string(),
                                account: s.shared_files_account().map(str::to_owned),
                            })
                        }
                        None => None,
                    },
                ))
            })?;
        let user_id = self.controller_for(session_id).unwrap_or_default();
        // #21 — filtered BEFORE the loopback overlay relay is added below: that
        // relay is an overlay address the agent reaches over the mesh, which the
        // netmap already keeps inside one zone.
        let mut ice = self.zone_local_ice(
            agent_id,
            session_id,
            ice_servers_for_session(
                &Self::turn_user(user_id, org),
                &session_id.to_hex(),
                self.inner.turn.cfg_for(region.as_deref()),
            ),
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
        // FR-121 — under zones the device relays through its OWN loopback TURN
        // (a netstack node could not reach the controller's over an OS socket).
        let local_relay =
            local_relay.filter(|_| self.session_zone(session_id).0 == ZoneRoute::Open);
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
        // FR-121 — a candidate the browser gathered before its offer rides in
        // the SDP, not a trickle; it gets the same zone check.
        let sdp = self.zone_filter_sdp(agent_id, session_id, true, sdp);
        let agent_tx = self.agent_tx(agent_id)?;
        agent_tx
            .try_send(ServerMsg::SdpOffer {
                shared_lease,
                session_id,
                sdp,
                ice_servers: ice,
                extauth_mac,
                peer_auth,
                zone_route: self.session_zone(session_id).0.wire().map(str::to_owned),
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
        peer_auth: Option<meshharbor_remote_control::signaling::PeerAuthAnswer>,
        peer_auth_verdict: Option<String>,
    ) -> Result<()> {
        let (controller_tx, user_id, region, org, agent_id) = {
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
                s.agent_id,
            )
        };
        let tx = controller_tx.ok_or(Error::SendFailed)?;
        let sdp = self.zone_filter_sdp(agent_id, session_id, false, sdp);
        let ice = self.zone_local_ice(
            agent_id,
            session_id,
            ice_servers_for_session(
                &Self::turn_user(user_id, org),
                &session_id.to_hex(),
                self.inner.turn.cfg_for(region.as_deref()),
            ),
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
        let (sid, aid, oid, max_duration, attach_seq) = self.with_session(session_id, |s| {
            Ok((
                s.id,
                s.agent_id,
                s.tenant_id,
                s.max_duration.take(),
                s.attach_seq,
            ))
        })?;
        let peer_auth = peer_auth_verdict.filter(|v| {
            let known = meshharbor_remote_control::signaling::peer_auth_verdict_is_known(v);
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
        // idempotent, and a session id is never reused). FR-130 — a session a
        // claim resumes keeps its id, so the timer also checks the fencing
        // number it was armed at: the resume arms its own, from `started_at`.
        if let Some(limit) = max_duration {
            self.arm_max_duration(sid, attach_seq, limit, limit);
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
        // FR-121 — neither side hears of a candidate the zones do not let
        // meet the other, so neither ICE agent ever sends there.
        if !self.zone_admits_trickle(agent_id, session_id, role, &candidate) {
            return Ok(());
        }
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
    ///
    /// FR-130 — an end someone asked for (an admin's, the controller's, the
    /// device's): written to the row at any fencing number, as every end was
    /// before. An end the hub decides on its own goes through
    /// [`Self::end_own`].
    pub fn terminate_with_limit(
        &self,
        session_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
    ) -> Result<()> {
        self.end_session(session_id, reason, limit, EndWrite::Asked)
    }

    /// FR-130 — an end the hub decides on its own (a socket loss, an orphan,
    /// the length limit, a reaper): written fenced at the number the hub
    /// holds, so it cannot end a session another pod resumed.
    pub(crate) fn end_own(
        &self,
        session_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
    ) -> Result<()> {
        self.end_session(session_id, reason, limit, EndWrite::Own)
    }

    /// The one place a session this hub holds ends: out of the map, its slot
    /// given back, the device's count freed, both ends told, and the end
    /// written to its row as `write` says.
    fn end_session(
        &self,
        session_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
        write: EndWrite,
    ) -> Result<()> {
        let Some((_, arc)) = self.inner.sessions.remove(&session_id) else {
            return Ok(()); // already gone, idempotent
        };
        self.end_removed(session_id, &arc, reason, limit, write);
        Ok(())
    }

    /// [`Self::end_session`], once the session is out of the map: the caller
    /// took exactly this copy out (FR-130's refused claim removes the copy it
    /// read, and no other).
    fn end_removed(
        &self,
        session_id: ObjectId,
        arc: &Arc<Mutex<LiveSession>>,
        reason: EndReason,
        limit: Option<&'static str>,
        write: EndWrite,
    ) {
        // FR-115 P3b — the session's slot goes back with it.
        if let Some((_, lease)) = self.inner.slotted.remove(&session_id) {
            self.release_slot(lease);
        }

        let (agent_id, tenant_id, controller_tx, attach_seq, silent_monitor) = {
            let mut s = arc.lock();
            // Best-effort transition; ignore if already closed.
            let _ = s.transition(SessionPhase::Closed);
            (
                s.agent_id,
                s.tenant_id,
                s.controller_tx.clone(),
                s.attach_seq,
                s.silent_monitor,
            )
        };

        // Decrement agent session counter (only for non-monitor sessions).
        if !silent_monitor
            && let Some(mut a) = self.inner.agents.get_mut(&agent_id)
        {
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

        // 0.5.0 — When a regular session ends, cleanly tear down:
        // 1. Any silent monitor specifically bound to `session_id`, AND
        // 2. When no other `Active` regular session remains on `agent_id`, all
        //    remaining silent monitors on `agent_id`.
        // Serialized under `agent_monitor_lock` so concurrent monitor admission
        // cannot land on an idle device after cleanup runs.
        if !silent_monitor {
            let to_close: Vec<ObjectId> = {
                let lock = self.agent_monitor_lock(agent_id);
                let _guard = lock.lock();
                let mut has_other_active_regular = false;
                let mut bound_monitors = Vec::new();
                let mut other_monitors = Vec::new();
                for e in self.inner.sessions.iter() {
                    let s = e.value().lock();
                    if s.agent_id != agent_id || s.phase == SessionPhase::Closed {
                        continue;
                    }
                    if s.silent_monitor {
                        if s.monitor_target_session_id == Some(session_id) {
                            bound_monitors.push(*e.key());
                        } else {
                            other_monitors.push(*e.key());
                        }
                    } else if s.phase == SessionPhase::Active {
                        has_other_active_regular = true;
                    }
                }
                if !has_other_active_regular {
                    bound_monitors.extend(other_monitors);
                }
                bound_monitors
            };
            for mid in to_close {
                let _ = self.end_session(
                    mid,
                    EndReason::ControllerHangup,
                    Some("target_session_ended"),
                    EndWrite::Asked,
                );
            }
        }

        let attach_seq = match write {
            EndWrite::Asked => None,
            EndWrite::Own => Some(attach_seq),
            // FR-130 — the row already holds the end this one follows.
            EndWrite::Nothing => return,
        };
        let end_kind = AuditKind::SessionEnded {
            reason,
            limit: limit.map(str::to_string),
            attach_seq,
            ended_at: None,
            end_source: None,
        };
        if silent_monitor {
            self.inner
                .audit
                .record_trail(session_id, agent_id, tenant_id, end_kind);
        } else {
            self.inner
                .audit
                .record(session_id, agent_id, tenant_id, end_kind);
        }
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
    /// Used by the `mh` relay path in the network module's
    /// `crates/modules/network/src/tunnel.rs` to forward
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
    // same-pod: the agent's tx and the waiter live in one process, and a pod
    // that does not hold the agent's WS answers the request as offline
    // (`agent_exec.rs`).

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

    /// FR-141 — record per-connection `ssh-resume` and `rc-continue` capability
    /// support from the agent's live hello / caps announcement. Returns whether
    /// `ssh-resume` was previously enabled on this connection.
    pub fn set_agent_fr141_support(
        &self,
        agent_id: ObjectId,
        ssh_resume: bool,
        rc_continue: bool,
    ) -> bool {
        match self.inner.agents.get_mut(&agent_id) {
            Some(mut entry) => {
                entry.supports_rc_continue = rc_continue;
                std::mem::replace(&mut entry.supports_ssh_resume, ssh_resume)
            }
            None => false,
        }
    }

    /// 0.5.0 — record whether this live agent connection advertises
    /// `silent-monitor` in `AgentCaps.input` (fail-closed for older agents).
    pub fn set_agent_silent_monitor(&self, agent_id: ObjectId, supported: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_silent_monitor = supported;
        }
    }

    fn agent_monitor_lock(&self, agent_id: ObjectId) -> Arc<Mutex<()>> {
        self.inner
            .agent_monitor_locks
            .entry(agent_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// FR-141 — push `rc:ssh.revoke` to every `ssh-resume`-capable agent in
    /// `tenant_id` connected to THIS pod (e.g. when org `remote_ssh_enabled` is
    /// switched off). Returns how many agents received the frame.
    pub fn push_ssh_revoke_org(&self, tenant_id: ObjectId, reason: &str) -> usize {
        self.push_ssh_revoke_org_scoped(tenant_id, "org", None, None, Some(reason.to_string()))
    }

    /// Push a scoped `rc:ssh.revoke` (`"org"`, `"principal"`, `"session"`, etc.)
    /// to every online agent in `tenant_id` connected to THIS pod, and prune
    /// matching entries from the live SSH monitoring table.
    pub fn push_ssh_revoke_org_scoped(
        &self,
        tenant_id: ObjectId,
        scope: &str,
        principal: Option<String>,
        sid: Option<String>,
        reason: Option<String>,
    ) -> usize {
        let targets: Vec<ObjectId> = self
            .inner
            .agents
            .iter()
            .filter(|a| a.tenant_id == tenant_id)
            .map(|a| a.agent_id)
            .collect();
        let mut delivered = 0usize;
        for id in targets {
            if self
                .send_to_agent(
                    id,
                    ServerMsg::SshRevoke {
                        scope: scope.to_string(),
                        principal: principal.clone(),
                        sid: sid.clone(),
                        reason: reason.clone(),
                    },
                )
                .is_ok()
            {
                delivered += 1;
                self.prune_live_ssh_by_revoke(
                    tenant_id,
                    Some(id),
                    scope,
                    principal.as_deref(),
                    sid.as_deref(),
                );
            }
        }
        delivered
    }

    /// Push `rc:ssh.revoke` to one online agent in `tenant_id` connected to
    /// THIS pod (e.g. device SSH policy turned off, principal removed, or
    /// administrator force-disconnecting a live SSH session).
    pub fn push_ssh_revoke_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        scope: &str,
        principal: Option<String>,
        sid: Option<String>,
        reason: Option<String>,
    ) -> bool {
        let eligible = self
            .inner
            .agents
            .get(&agent_id)
            .is_some_and(|a| a.tenant_id == tenant_id);
        if !eligible {
            return false;
        }
        let sent = self
            .send_to_agent(
                agent_id,
                ServerMsg::SshRevoke {
                    scope: scope.to_string(),
                    principal: principal.clone(),
                    sid: sid.clone(),
                    reason,
                },
            )
            .is_ok();
        if sent {
            self.prune_live_ssh_by_revoke(
                tenant_id,
                Some(agent_id),
                scope,
                principal.as_deref(),
                sid.as_deref(),
            );
        }
        sent
    }

    fn prune_live_ssh_by_revoke(
        &self,
        tenant_id: ObjectId,
        agent_id: Option<ObjectId>,
        scope: &str,
        principal: Option<&str>,
        sid: Option<&str>,
    ) {
        self.inner.live_ssh.retain(|k, s| {
            if s.tenant_id != tenant_id {
                return true;
            }
            if let Some(aid) = agent_id
                && s.agent_id != aid
            {
                return true;
            }
            match scope {
                "session" => !sid.is_some_and(|target| {
                    k == target || s.grant_id.as_deref() == Some(target)
                }),
                "principal" => !principal.is_some_and(|p| {
                    s.user_id.is_some_and(|u| u.to_hex() == p) || s.caller == p
                }),
                _ => false,
            }
        });
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

    pub fn set_agent_relay_control_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_relay_control = supports;
        }
    }

    pub fn set_agent_relay_regions_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_relay_regions = supports;
        }
    }

    /// Push the updated `ServerMsg::RelayRegions` target list to a live agent
    /// using its current revisioned `AgentZoneIcePolicy` (sending an empty list
    /// if strict zone policy filters out every configured region so the daemon
    /// stops probing removed foreign STUN targets).
    pub fn push_relay_regions_for_agent(&self, tenant_id: ObjectId, agent_id: ObjectId) -> bool {
        let eligible = self
            .inner
            .agents
            .get(&agent_id)
            .is_some_and(|a| a.tenant_id == tenant_id && a.supports_relay_regions);
        if !eligible {
            return false;
        }
        let Some((mut regions, rev)) =
            meshharbor_remote_control::turn_creds::relay_regions_wire(&self.inner.turn)
        else {
            return false;
        };
        let policy = self.agent_zone_ice_policy(agent_id);
        if let Some(p) = &policy
            && p.strict
        {
            regions.retain(|r| {
                let stun_url = format!("stun:{}", r.stun);
                self.url_matches_allowed_countries(&stun_url, &p.allowed_countries)
            });
        }
        let policy_revision = policy.map(|p| p.policy_revision);
        self.send_to_agent_in_tenant(
            agent_id,
            tenant_id,
            ServerMsg::RelayRegions {
                regions,
                rev,
                policy_revision,
            },
        )
        .is_ok()
    }

    pub fn set_agent_relay_server_support(&self, agent_id: ObjectId, supports: bool) -> bool {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            let prev = entry.supports_relay_server;
            entry.supports_relay_server = supports;
            return prev != supports;
        }
        false
    }

    pub fn set_agent_management_path_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_management_path = supports;
        }
    }

    pub fn set_agent_management_entry_support(&self, agent_id: ObjectId, supports: bool) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.supports_management_entry = supports;
        }
    }

    /// Record the management entry port currently advertised by `agent_id`.
    /// Returns `true` if the value changed.
    pub fn set_agent_management_entry_port(&self, agent_id: ObjectId, port: Option<u16>) -> bool {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            let prev = entry.management_entry_port;
            entry.management_entry_port = port;
            return prev != port;
        }
        false
    }

    /// FR-137 — the management entry TCP port currently listening on a live agent
    /// connection (`None` when offline or not listening).
    pub fn agent_management_entry_port(&self, agent_id: ObjectId) -> Option<u16> {
        self.inner
            .agents
            .get(&agent_id)
            .and_then(|a| a.management_entry_port)
            .filter(|p| *p != 0)
    }

    /// FR-137 — record which zone gateway management entry `agent_id` connected through
    /// on its current control WS (`None` for direct or unattested connections).
    pub fn set_agent_via_management_entry(&self, agent_id: ObjectId, entry_id: Option<ObjectId>) {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            entry.via_management_entry = entry_id;
        }
    }

    /// FR-137 — live count of currently connected agents in `tenant_id` whose control
    /// socket arrived attested through each gateway management entry.
    pub fn management_entry_device_counts(
        &self,
        tenant_id: ObjectId,
    ) -> std::collections::HashMap<ObjectId, usize> {
        let mut counts = std::collections::HashMap::new();
        for entry in self.inner.agents.iter() {
            if entry.tenant_id == tenant_id
                && let Some(gw_id) = entry.via_management_entry
            {
                *counts.entry(gw_id).or_insert(0) += 1;
            }
        }
        counts
    }

    /// FR-138 — record whether `agent_id`'s live connection reports a VPN default route.
    /// Returns `true` if the value changed.
    pub fn set_agent_default_route_vpn(&self, agent_id: ObjectId, vpn: bool) -> bool {
        if let Some(mut entry) = self.inner.agents.get_mut(&agent_id) {
            let prev = entry.default_route_vpn;
            entry.default_route_vpn = vpn;
            return prev != vpn;
        }
        false
    }

    /// FR-134 — push `rc:agent.management_path` to a live agent on this pod when it
    /// advertises `management-path`.
    pub fn push_management_path(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        direct: bool,
        entries: Vec<String>,
    ) -> bool {
        let eligible = self
            .inner
            .agents
            .get(&agent_id)
            .is_some_and(|a| a.tenant_id == tenant_id && a.supports_management_path);
        if !eligible {
            return false;
        }
        self.send_to_agent_in_tenant(
            agent_id,
            tenant_id,
            ServerMsg::ManagementPath { direct, entries },
        )
        .is_ok()
    }

    /// FR-134 — push `rc:agent.management_entry` to a live agent on this pod.
    /// A non-empty key goes to any agent advertising `management-entry` or an already-bound
    /// `management_entry_port`; an empty key (stop/revoke) goes only to agents advertising
    /// `management-entry` so pre-FR-134 agents are untouched.
    pub fn push_management_entry_key(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        key: meshharbor_remote_control::management_entry::EntryKey,
    ) -> bool {
        let revoking = key.0.is_empty();
        let eligible = self.inner.agents.get(&agent_id).is_some_and(|a| {
            a.tenant_id == tenant_id
                && if revoking {
                    a.supports_management_entry
                } else {
                    a.supports_management_entry || a.management_entry_port.is_some()
                }
        });
        if !eligible {
            return false;
        }
        self.send_to_agent_in_tenant(agent_id, tenant_id, ServerMsg::ManagementEntryKey { key })
            .is_ok()
    }

    pub fn agent_supports_relay_server(&self, agent_id: ObjectId) -> Option<bool> {
        self.inner
            .agents
            .get(&agent_id)
            .map(|a| a.supports_relay_server)
    }

    /// Push the authoritative `peer_relay_policy.serve` directive to a
    /// connected agent on this pod when it advertises `relay-control`.
    pub fn push_peer_relay_serve(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        serve: bool,
        revision: Option<u64>,
        backbone_endpoints: Vec<String>,
    ) -> bool {
        let eligible = self
            .inner
            .agents
            .get(&agent_id)
            .is_some_and(|a| a.tenant_id == tenant_id && a.supports_relay_control);
        if !eligible {
            return false;
        }
        self.send_to_agent_in_tenant(
            agent_id,
            tenant_id,
            ServerMsg::PeerRelayServe {
                serve,
                revision,
                backbone_endpoints,
            },
        )
        .is_ok()
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
    ) -> Option<meshharbor_remote_control::signaling::SharedSessionLease> {
        let e = self.inner.sessions.get(&session_id)?;
        let s = e.value().lock();
        Some(meshharbor_remote_control::signaling::SharedSessionLease {
            grant_id: s.device_share_scope()?.grant_id,
            lease_epoch: s.shared_lease_epoch()?.to_string(),
            account: s.shared_files_account().map(str::to_owned),
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

    /// X14 — inspect a live parent session before querying MongoDB for fresh
    /// tenant/agent policy revisions. Never holds the session lock across `.await`.
    pub fn session_file_child_target(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
    ) -> Result<(
        ObjectId,
        ObjectId,
        Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    )> {
        self.session_file_child_target_for_direction(
            session_id,
            user_id,
            controller_tx,
            meshharbor_remote_control::signaling::FileChildDirection::Download,
        )
    }

    pub fn session_file_child_target_for_direction(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
        direction: meshharbor_remote_control::signaling::FileChildDirection,
    ) -> Result<(
        ObjectId,
        ObjectId,
        Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    )> {
        if self.is_file_child_direction_disabled(direction) {
            return Err(Error::PermissionDenied(
                "file child transport direction is disabled",
            ));
        }
        self.with_session(session_id, |s| {
            if s.controller_user_id != user_id {
                return Err(Error::PermissionDenied("not the parent controller"));
            }
            if !s
                .controller_tx
                .as_ref()
                .is_some_and(|current| ptr_eq(current, controller_tx) && !current.is_closed())
            {
                return Err(Error::PermissionDenied(
                    "not the parent controller connection",
                ));
            }
            if s.device_share_scope().is_some() {
                return Err(Error::PermissionDenied(
                    "shared child inheritance unavailable",
                ));
            }
            if s.is_file_children_revoked() {
                return Err(Error::PermissionDenied(
                    "file child transports revoked for this session",
                ));
            }
            if !s.is_file_children_opted_in_for(direction)
                && !s.is_file_children_enabled_for(direction)
            {
                return Err(Error::PermissionDenied(
                    "file child transport is not enabled for this session",
                ));
            }
            if s.phase != SessionPhase::Active || !s.permissions().contains(Permissions::FILES) {
                return Err(Error::PermissionDenied(
                    "file child parent session is not active with FILES permission",
                ));
            }
            Ok((s.agent_id, s.tenant_id, s.file_child_policy_snapshot()))
        })
    }

    /// X14 — check whether the background file-child policy watcher should
    /// continue polling MongoDB for `session_id`. When no `Reserved` or
    /// `Active` child slots remain (`s.file_children.is_empty()`), this
    /// atomically resets `file_child_watch_started = false` and returns
    /// `Ok(false)` so the watcher exits without querying MongoDB while idle,
    /// and a future `rc:file.child.reserve` will re-claim the watcher.
    pub fn poll_file_child_watch_target(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
    ) -> Result<bool> {
        self.with_session(session_id, |s| {
            if s.controller_user_id != user_id {
                return Err(Error::PermissionDenied("not the parent controller"));
            }
            if !s
                .controller_tx
                .as_ref()
                .is_some_and(|current| ptr_eq(current, controller_tx) && !current.is_closed())
            {
                return Err(Error::PermissionDenied(
                    "not the parent controller connection",
                ));
            }
            if s.device_share_scope().is_some() {
                return Err(Error::PermissionDenied(
                    "shared child inheritance unavailable",
                ));
            }
            if s.is_file_children_revoked() {
                return Err(Error::PermissionDenied(
                    "file child transports revoked for this session",
                ));
            }
            if !s.is_any_file_children_opted_in_or_enabled() {
                return Err(Error::PermissionDenied(
                    "file child transport is not enabled for this session",
                ));
            }
            if s.phase != SessionPhase::Active || !s.permissions().contains(Permissions::FILES) {
                return Err(Error::PermissionDenied(
                    "file child parent session is not active with FILES permission",
                ));
            }
            if s.release_file_child_watch_if_idle() {
                return Ok(false);
            }
            Ok(true)
        })
    }

    /// X14 — release the background policy-watcher claim if `session_id` has no
    /// `Reserved` or `Active` file-child slots. Returns `true` when the session
    /// is now idle (or gone).
    pub fn release_file_child_watch_if_idle(&self, session_id: ObjectId) -> bool {
        self.with_session(session_id, |s| Ok(s.release_file_child_watch_if_idle()))
            .unwrap_or(true)
    }

    /// X14 — ensure the background policy-watcher flag is claimed when at least
    /// one `Reserved` or `Active` file-child slot is present on `session_id`.
    pub fn ensure_file_child_watch_started(&self, session_id: ObjectId) -> bool {
        self.with_session(session_id, |s| {
            Ok(s.has_file_children() && s.claim_file_child_watch())
        })
        .unwrap_or(false)
    }

    /// X14 — re-lock the parent session after the live DB PDP and bind or
    /// compare `(tenant.security_revision(), agent.access_policy_revision())`.
    /// On success, enables file-child capability on the parent session and
    /// returns `Ok(true)` the first time so the caller can spawn the background
    /// policy watcher once. On mismatch or `None`, irreversibly revokes child
    /// capability, notifies both peers (`rc:file.child.revoke`), and arms the
    /// 5-second fail-closed ACK deadline.
    pub fn admit_file_child_policy_snapshot(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
        current: Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    ) -> Result<bool> {
        self.admit_file_child_policy_snapshot_inner(
            session_id,
            user_id,
            controller_tx,
            None,
            current,
        )
    }

    pub fn admit_file_child_policy_snapshot_for_direction(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
        direction: meshharbor_remote_control::signaling::FileChildDirection,
        current: Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    ) -> Result<bool> {
        if self.is_file_child_direction_disabled(direction) {
            return Err(Error::PermissionDenied(
                "file child transport direction is disabled",
            ));
        }
        self.admit_file_child_policy_snapshot_inner(
            session_id,
            user_id,
            controller_tx,
            Some(direction),
            current,
        )
    }

    fn admit_file_child_policy_snapshot_inner(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        controller_tx: &ClientTx,
        direction: Option<meshharbor_remote_control::signaling::FileChildDirection>,
        current: Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    ) -> Result<bool> {
        use meshharbor_remote_control::signaling::FileChildDirection;
        let outcome = self.with_session(session_id, |s| {
            if s.controller_user_id != user_id {
                return Err(Error::PermissionDenied("not the parent controller"));
            }
            if !s.controller_tx.as_ref().is_some_and(|current_tx| {
                ptr_eq(current_tx, controller_tx) && !current_tx.is_closed()
            }) {
                return Err(Error::PermissionDenied(
                    "not the parent controller connection",
                ));
            }
            if s.device_share_scope().is_some() {
                return Err(Error::PermissionDenied(
                    "shared child inheritance unavailable",
                ));
            }
            if let Some(dir) = direction
                && !s.is_file_children_opted_in_for(dir)
                && !s.is_file_children_enabled_for(dir)
            {
                return Err(Error::PermissionDenied(
                    "file child transport is not enabled for this session",
                ));
            }
            let was_revoked = s.is_file_children_revoked();
            match s.verify_or_bind_file_child_policy_snapshot(current) {
                Ok(()) => {
                    match direction {
                        Some(dir) => s.set_file_children_enabled_for(dir, true),
                        None => {
                            if s.is_file_children_opted_in_for(FileChildDirection::Upload)
                                || s.is_file_children_enabled_for(FileChildDirection::Upload)
                            {
                                s.set_file_children_enabled_for(FileChildDirection::Upload, true);
                            }
                            if s.is_file_children_opted_in_for(FileChildDirection::Download)
                                || s.is_file_children_enabled_for(FileChildDirection::Download)
                                || !s.is_any_file_children_opted_in_or_enabled()
                            {
                                s.set_file_children_enabled_for(FileChildDirection::Download, true);
                            }
                        }
                    }
                    Ok(Ok(s.claim_file_child_watch()))
                }
                Err(err) => {
                    let newly_revoked = !was_revoked && s.is_file_children_revoked();
                    Ok(Err((
                        err,
                        newly_revoked,
                        s.agent_id,
                        s.controller_tx.clone(),
                    )))
                }
            }
        })?;

        match outcome {
            Ok(start_watch) => Ok(start_watch),
            Err((err, newly_revoked, agent_id, ctl_tx)) => {
                if newly_revoked {
                    self.notify_and_arm_file_child_revoke(
                        session_id,
                        agent_id,
                        ctl_tx,
                        "policy_revision_changed",
                    );
                }
                Err(err)
            }
        }
    }

    /// X14 — irreversibly revoke all download-only file child capability on
    /// `session_id`, push `rc:file.child.revoke` to both peers, and arm the
    /// 5-second fail-closed ACK timer that terminates the parent session if
    /// the agent does not answer with `rc:file.child.revoke_ack`.
    pub fn revoke_file_children(&self, session_id: ObjectId, reason: &str) -> Result<bool> {
        let (first, agent_id, ctl_tx) = self.with_session(session_id, |s| {
            let first = s.revoke_file_children_irreversibly();
            Ok((first, s.agent_id, s.controller_tx.clone()))
        })?;
        if first {
            self.notify_and_arm_file_child_revoke(session_id, agent_id, ctl_tx, reason);
        }
        Ok(first)
    }

    fn notify_and_arm_file_child_revoke(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        controller_tx: Option<ClientTx>,
        reason: &str,
    ) {
        let msg = ServerMsg::FileChildRevoke {
            session_id,
            reason: reason.to_string(),
        };
        if let Some(tx) = controller_tx {
            let _ = tx.try_send(msg.clone());
        }
        let _ = self.send_to_agent(agent_id, msg);
        let hub = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(FILE_CHILD_REVOKE_ACK_TIMEOUT).await;
            hub.enforce_file_child_revoke_deadline(session_id);
        });
    }

    fn enforce_file_child_revoke_deadline(&self, session_id: ObjectId) {
        let pending = self
            .inner
            .sessions
            .get(&session_id)
            .map(|arc| {
                let s = arc.value().lock();
                s.phase != SessionPhase::Closed && s.is_file_child_revoke_pending_ack()
            })
            .unwrap_or(false);
        if pending {
            warn!(
                session = %session_id.to_hex(),
                "file child revocation not acknowledged within {}s — terminating parent session fail-closed",
                FILE_CHILD_REVOKE_ACK_TIMEOUT.as_secs()
            );
            let _ = self.terminate(session_id, EndReason::AdminTerminated);
        }
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

    /// MeshHarbor — ask a device connected HERE for its login accounts, or to
    /// create one. The outer error is the transport (offline, timeout); the
    /// inner `Err` is the device's own refusal, in its words.
    pub async fn local_accounts(
        &self,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        op: meshharbor_remote_control::signaling::LocalAccountOp,
        deadline: std::time::Duration,
    ) -> Result<LocalAccountsAnswer> {
        {
            let entry = self
                .inner
                .agents
                .get(&agent_id)
                .ok_or_else(|| Error::AgentOffline(agent_id.to_hex()))?;
            if entry.tenant_id != tenant_id {
                return Err(Error::AgentOffline(agent_id.to_hex()));
            }
        }
        let request_id = ObjectId::new().to_hex();
        let (tx, rx) = oneshot::channel();
        self.inner.account_waiters.insert(request_id.clone(), tx);
        struct Unpark<'a>(&'a Hub, String);
        impl Drop for Unpark<'_> {
            fn drop(&mut self) {
                self.0.inner.account_waiters.remove(&self.1);
            }
        }
        let _unpark = Unpark(self, request_id.clone());
        self.send_to_agent(agent_id, ServerMsg::LocalAccountsRequest { request_id, op })?;
        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(Error::AgentOffline(agent_id.to_hex())),
            Err(_) => Err(Error::ExecTimeout(agent_id.to_hex())),
        }
    }

    /// Hand a `rc:accounts.result` to the owner parked on it. `false` = nobody was.
    pub fn deliver_local_accounts(&self, request_id: &str, answer: LocalAccountsAnswer) -> bool {
        match self.inner.account_waiters.remove(request_id) {
            Some((_, tx)) => tx.send(answer).is_ok(),
            None => false,
        }
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
        let silent = self
            .inner
            .sessions
            .get(&sid)
            .is_some_and(|s| s.value().lock().silent_monitor);
        if silent {
            self.inner.audit.record_trail(sid, aid, oid, k);
        } else {
            self.inner.audit.record(sid, aid, oid, k);
        }
    }

    // ─── introspection (for /api/sessions and admin monitoring) ──────

    /// 0.5.0 — Authoritatively toggle admin takeover on a live silent monitor
    /// session: verifies tenant + owner + `Active` phase, enforces a single
    /// authoritative takeover holder per target device, delivers
    /// `ServerMsg::AdminTakeover` over the authenticated agent WS, and updates
    /// hub state only after delivery succeeds.
    pub fn set_silent_monitor_takeover(
        &self,
        tenant_id: ObjectId,
        session_id: ObjectId,
        controller_user_id: ObjectId,
        active: bool,
    ) -> Result<ObjectId> {
        let agent_id = {
            let arc = self
                .inner
                .sessions
                .get(&session_id)
                .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
            let s = arc.value().lock();
            if s.tenant_id != tenant_id
                || !s.silent_monitor
                || s.controller_user_id != controller_user_id
            {
                return Err(Error::PermissionDenied("not your silent monitor session"));
            }
            if active && s.phase != SessionPhase::Active {
                return Err(Error::PermissionDenied(
                    "silent monitor session is not active yet",
                ));
            }
            if active && !s.permissions().contains(Permissions::INPUT) {
                return Err(Error::PermissionDenied(
                    "silent monitor session does not hold input permission",
                ));
            }
            s.agent_id
        };
        let lock = self.agent_monitor_lock(agent_id);
        let _guard = lock.lock();
        if active {
            // Single authoritative takeover owner per target device.
            for e in self.inner.sessions.iter() {
                if *e.key() == session_id {
                    continue;
                }
                let other = e.value().lock();
                if other.agent_id == agent_id
                    && other.silent_monitor
                    && other.phase != SessionPhase::Closed
                    && other.admin_takeover_active
                {
                    return Err(Error::AgentBusy);
                }
            }
        }
        // Push server-authorized takeover frame to the agent BEFORE committing
        // local state so an offline/unreachable agent never fakes success.
        self.send_to_agent(
            agent_id,
            ServerMsg::AdminTakeover { session_id, active },
        )?;
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
        let mut s = arc.value().lock();
        if s.tenant_id != tenant_id
            || !s.silent_monitor
            || s.controller_user_id != controller_user_id
        {
            return Err(Error::PermissionDenied("not your silent monitor session"));
        }
        s.admin_takeover_active = active;
        info!(
            tenant = %tenant_id,
            agent = %agent_id,
            monitor_session = %session_id,
            admin_user = %controller_user_id,
            active,
            "silent monitor: server-authorized admin takeover toggled"
        );
        Ok(agent_id)
    }

    /// 0.5.0 — Live non-monitor RC sessions for a tenant, enriched with whether
    /// an administrator is currently watching or has taken over each target.
    pub fn live_rc_sessions(&self, tenant_id: ObjectId) -> Vec<LiveRcSessionInfo> {
        let mut monitor_state: std::collections::HashMap<ObjectId, (usize, bool)> =
            std::collections::HashMap::new();
        for e in self.inner.sessions.iter() {
            let s = e.value().lock();
            if s.tenant_id == tenant_id && s.silent_monitor && s.phase != SessionPhase::Closed {
                let entry = monitor_state.entry(s.agent_id).or_insert((0, false));
                entry.0 += 1;
                if s.admin_takeover_active {
                    entry.1 = true;
                }
            }
        }
        let mut out = Vec::new();
        for e in self.inner.sessions.iter() {
            let s = e.value().lock();
            if s.tenant_id != tenant_id || s.silent_monitor || s.phase == SessionPhase::Closed {
                continue;
            }
            let (watcher_count, admin_taken_over) =
                monitor_state.get(&s.agent_id).copied().unwrap_or((0, false));
            out.push(LiveRcSessionInfo {
                session_id: s.id,
                agent_id: s.agent_id,
                tenant_id: s.tenant_id,
                controller_user_id: s.controller_user_id,
                controller_name: s.controller_name.clone(),
                phase: s.phase,
                created_at: s.created_at,
                started_at: s.started_at,
                stats: s.stats.clone(),
                external: s.external,
                share_grant_id: s.device_share_scope().map(|sc| sc.grant_id),
                permissions: s.permissions(),
                admin_watching: watcher_count > 0,
                admin_watcher_count: watcher_count,
                admin_taken_over,
            });
        }
        out
    }

    /// 0.5.0 — Record a newly issued SSH grant (or live shared SSH bridge) in
    /// the in-memory live SSH monitoring table.
    pub fn note_ssh_grant_issued(&self, info: LiveSshSessionInfo) {
        self.prune_stale_live_ssh();
        self.inner.live_ssh.insert(info.key.clone(), info);
    }

    /// 0.5.0 — Update live SSH session state from device-reported
    /// `ClientMsg::SshActivity` envelopes (`SessionOpen`, `SessionClose`, etc.).
    pub fn note_ssh_activity(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        grant_id: Option<&str>,
        caller: &str,
        kind: meshharbor_remote_control::models::SshActivityKind,
    ) {
        use meshharbor_remote_control::models::SshActivityKind;
        let key = grant_id
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("keylist:{agent_id}:{caller}"));
        if matches!(kind, SshActivityKind::SessionClose) {
            self.inner
                .live_ssh
                .remove_if(&key, |_, s| s.tenant_id == tenant_id && s.agent_id == agent_id);
            return;
        }
        let now = bson::DateTime::now();
        if let Some(mut entry) = self.inner.live_ssh.get_mut(&key) {
            if entry.tenant_id == tenant_id && entry.agent_id == agent_id {
                if matches!(kind, SshActivityKind::SessionOpen) && entry.phase != "active" {
                    entry.started_at = now;
                }
                entry.phase = "active";
                entry.last_activity_at = now;
                if !matches!(kind, SshActivityKind::SessionOpen) {
                    entry.activity_count = entry.activity_count.saturating_add(1);
                }
            }
            return;
        }
        // Key-list session (no server grant) or session reopened after pod roll.
        let is_key_list = grant_id.is_none();
        self.inner.live_ssh.insert(
            key.clone(),
            LiveSshSessionInfo {
                key,
                tenant_id,
                agent_id,
                user_id: None,
                origin_agent_id: None,
                grant_id: grant_id.map(str::to_string),
                shared_session_id: None,
                share_grant_id: None,
                source: if is_key_list {
                    "key_list".to_string()
                } else {
                    "cli".to_string()
                },
                caller: caller.to_string(),
                account_mode: None,
                ran_as: None,
                resume_allowed: false,
                phase: "active",
                started_at: now,
                last_activity_at: now,
                expires_at_ms: None,
                session_secs: None,
                activity_count: if matches!(kind, SshActivityKind::SessionOpen) {
                    0
                } else {
                    1
                },
            },
        );
    }

    pub fn remove_live_ssh_scoped(
        &self,
        tenant_id: ObjectId,
        agent_id: Option<ObjectId>,
        key: &str,
    ) -> Option<LiveSshSessionInfo> {
        self.inner
            .live_ssh
            .remove_if(key, |_, s| {
                s.tenant_id == tenant_id && agent_id.is_none_or(|a| s.agent_id == a)
            })
            .map(|(_, v)| v)
    }

    pub fn get_live_ssh(&self, tenant_id: ObjectId, key: &str) -> Option<LiveSshSessionInfo> {
        self.inner
            .live_ssh
            .get(key)
            .filter(|e| e.tenant_id == tenant_id)
            .map(|e| e.clone())
    }

    fn prune_stale_live_ssh(&self) {
        let now_ms = bson::DateTime::now().timestamp_millis().max(0) as u64;
        self.inner.live_ssh.retain(|_, s| {
            let started_ms = s.started_at.timestamp_millis().max(0) as u64;
            if s.phase == "granted" {
                // An unredeemed grant expires cleanly at `expires_at_ms` (+5 s grace).
                if let Some(exp) = s.expires_at_ms {
                    return now_ms <= exp.saturating_add(5_000);
                }
                return now_ms.saturating_sub(started_ms) <= 120_000;
            }
            // Active session bound: drop if past `started + session_secs + 60s`
            // (or 24 h fallback when unbounded, e.g. key-list).
            let max_ms = s
                .session_secs
                .map(|secs| secs.saturating_mul(1_000).saturating_add(60_000))
                .unwrap_or(24 * 3600 * 1_000);
            now_ms.saturating_sub(started_ms) <= max_ms
        });
    }

    /// 0.5.0 — Live SSH sessions in `tenant_id` (classic, persistent PTY, and
    /// shared SSH), pruning expired unredeemed grants first.
    pub fn live_ssh_sessions(&self, tenant_id: ObjectId) -> Vec<LiveSshSessionInfo> {
        self.prune_stale_live_ssh();
        self.inner
            .live_ssh
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .map(|e| e.clone())
            .collect()
    }

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
    pub input_mode: Option<meshharbor_remote_control::models::InputMode>,
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
    /// MeshHarbor — the share account a SHARED session's file operations run
    /// as on the device, resolved by the API WS layer's share gate from the
    /// grant (`device_share::files_gate`) and frozen into the session's
    /// `SharedSessionLease::account`. `None` for every non-shared request and
    /// for a share without an account; the device then decides by its own
    /// privilege. Never taken from the controller's frame.
    pub share_files_account: Option<String>,
    /// FR-141 — server-validated previous session ID that this request
    /// continues after a graceful target daemon restart (<= 120 s ago).
    /// Never trusted directly from `ClientMsg::SessionRequest::continues_from`.
    pub continues: Option<ObjectId>,
    /// 0.5.0 — server-validated admin silent monitoring session (watch +
    /// optional takeover of an active RC session). Never trusted directly from
    /// `ClientMsg::SessionRequest::silent_monitor`.
    pub silent_monitor: bool,
}

/// Snapshot of one active non-monitor RC session for the unified live
/// monitoring console (`GET /api/tenant/{id}/monitoring/live`).
#[derive(Debug, Clone)]
pub struct LiveRcSessionInfo {
    pub session_id: ObjectId,
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    pub controller_name: String,
    pub phase: SessionPhase,
    pub created_at: bson::DateTime,
    pub started_at: Option<bson::DateTime>,
    pub stats: meshharbor_remote_control::models::SessionStats,
    pub external: bool,
    pub share_grant_id: Option<ObjectId>,
    pub permissions: Permissions,
    pub admin_watching: bool,
    pub admin_watcher_count: usize,
    pub admin_taken_over: bool,
}

/// 0.5.0 — Snapshot of one active SSH session (classic overlay, persistent
/// PTY, key-list, or device-shared SSH) tracked by the Hub for unified live
/// monitoring and active admin disconnect.
#[derive(Debug, Clone)]
pub struct LiveSshSessionInfo {
    pub key: String,
    pub tenant_id: ObjectId,
    pub agent_id: ObjectId,
    pub user_id: Option<ObjectId>,
    pub origin_agent_id: Option<ObjectId>,
    pub grant_id: Option<String>,
    pub shared_session_id: Option<ObjectId>,
    pub share_grant_id: Option<ObjectId>,
    pub source: String,
    pub caller: String,
    pub account_mode: Option<String>,
    pub ran_as: Option<String>,
    pub resume_allowed: bool,
    pub phase: &'static str,
    pub started_at: bson::DateTime,
    pub last_activity_at: bson::DateTime,
    pub expires_at_ms: Option<u64>,
    pub session_secs: Option<u64>,
    pub activity_count: u64,
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
        self.dispatch_with_origin(ctx, msg, created, SessionCreationOrigin::Unknown)
    }

    /// Backend-only entry for remote's module-private, authenticated local-PDP
    /// request. This is not a wire authority and must never be called by relay
    /// dispatch, legacy/full creation, external access or share creation.
    #[doc(hidden)]
    pub fn dispatch_local_pdp_session_request(
        &self,
        ctx: &DispatchCtx,
        msg: ClientMsg,
        policy_snapshot: Option<meshharbor_remote_control::session::FileChildPolicySnapshot>,
    ) -> Result<()> {
        if ctx.role != Role::Controller
            || ctx.user_id.is_none()
            || ctx.controller_tx.is_none()
            || ctx.override_reason.is_some()
            || !matches!(ctx.consent_mode, ConsentMode::Auto | ConsentMode::Prompt)
            || !matches!(
                &msg,
                ClientMsg::SessionRequest {
                    share_grant_id: None,
                    ..
                }
            )
        {
            return Err(Error::PermissionDenied(
                "local PDP session source unavailable",
            ));
        }
        let mut created = None;
        self.dispatch_with_origin(ctx, msg, &mut created, SessionCreationOrigin::LocalPdp)?;
        if let (Some(session_id), Some(snapshot)) = (created, policy_snapshot) {
            let _ = self.with_session(session_id, |s| {
                s.seed_file_child_policy_snapshot(snapshot);
                Ok(())
            });
        }
        Ok(())
    }

    /// Read-only test observation; never enables a capability or exposes scope data.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn file_child_local_pdp_for_tests(&self, session_id: ObjectId) -> Option<bool> {
        self.with_session(session_id, |s| Ok(s.file_child_local_pdp_for_tests()))
            .ok()
    }

    fn dispatch_with_origin(
        &self,
        ctx: &DispatchCtx,
        msg: ClientMsg,
        created: &mut Option<ObjectId>,
        origin: SessionCreationOrigin,
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
                    initial_resolution,
                    two_factor_code,
                    // FR-130 — the held session this redial gives up. The
                    // remote module ends it before this request meets any
                    // capacity gate, the org's slot it claims before this
                    // dispatch included (`Hub::end_replaced`).
                    replaces: _,
                    // FR-141 — validated against MongoDB by the remote module
                    // and passed via `ctx.continues`; raw wire field ignored.
                    continues_from: _,
                    // 0.5.0 — validated by the remote authz gate and passed via
                    // `ctx.silent_monitor`; raw wire field ignored.
                    silent_monitor: _,
                    monitor_target_session_id,
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
                    // Server-resolved by the share gate, never read from the
                    // controller's frame.
                    ctx.share_files_account.clone(),
                    origin,
                    initial_resolution,
                    two_factor_code,
                    ctx.continues,
                    ctx.silent_monitor,
                    if ctx.silent_monitor {
                        monitor_target_session_id
                    } else {
                        None
                    },
                )?;
                *created = Some(session_id);
                Ok(())
            }
            (
                Role::Controller,
                ClientMsg::FileChildReserve {
                    session_id,
                    transfer_id,
                    direction,
                },
            ) => self.with_session(session_id, |s| {
                if self.is_file_child_direction_disabled(direction) {
                    return Err(Error::PermissionDenied(
                        "file child transport direction is disabled",
                    ));
                }
                if ctx.user_id != Some(s.controller_user_id) {
                    return Err(Error::PermissionDenied("not the parent controller"));
                }
                let requester = ctx
                    .controller_tx
                    .as_ref()
                    .ok_or(Error::PermissionDenied("missing controller connection"))?;
                let controller = s
                    .controller_tx
                    .as_ref()
                    .filter(|current| ptr_eq(current, requester))
                    .cloned()
                    .ok_or(Error::PermissionDenied(
                        "not the parent controller connection",
                    ))?;
                if controller.is_closed() {
                    return Err(Error::SendFailed);
                }
                if s.device_share_scope().is_some() {
                    return Err(Error::PermissionDenied(
                        "shared child inheritance unavailable",
                    ));
                }
                let child_id = s.reserve_file_child_for_direction(&transfer_id, direction)?;
                let reply = ServerMsg::FileChildReserved {
                    session_id,
                    child_id,
                    transfer_id: transfer_id.clone(),
                    direction,
                };
                // No await or agent message: parent closure and permission
                // updates cannot interleave with this exact Reserved rollback.
                if controller.try_send(reply).is_err() {
                    s.cancel_file_child_reservation(child_id, &transfer_id)?;
                    return Err(Error::SendFailed);
                }
                Ok(())
            }),
            (
                Role::Controller,
                ClientMsg::FileSdpOffer {
                    session_id,
                    child_id,
                    transfer_id,
                    direction,
                    sdp,
                    proof,
                },
            ) => self.with_session(session_id, |s| {
                if self.is_file_child_direction_disabled(direction) {
                    return Err(Error::PermissionDenied(
                        "file child transport direction is disabled",
                    ));
                }
                if ctx.user_id != Some(s.controller_user_id) {
                    return Err(Error::PermissionDenied("not the parent controller"));
                }
                let requester = ctx
                    .controller_tx
                    .as_ref()
                    .ok_or(Error::PermissionDenied("missing controller connection"))?;
                if !s
                    .controller_tx
                    .as_ref()
                    .is_some_and(|current| ptr_eq(current, requester) && !current.is_closed())
                {
                    return Err(Error::PermissionDenied(
                        "not the parent controller connection",
                    ));
                }
                let agent_id = s.agent_id;
                s.enqueue_file_child_offer_for_direction(child_id, &transfer_id, direction, || {
                    self.agent_tx(agent_id)?
                        .try_send(ServerMsg::FileSdpOffer {
                            session_id,
                            child_id,
                            transfer_id: transfer_id.clone(),
                            direction,
                            sdp,
                            proof,
                        })
                        .map_err(|_| Error::SendFailed)
                })
            }),
            (
                Role::Agent,
                ClientMsg::FileSdpAnswer {
                    session_id,
                    child_id,
                    transfer_id,
                    sdp,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                let (controller_tx, user_id, region, org, agent_id) =
                    self.with_session(session_id, |s| {
                        if !s.has_active_file_child(child_id, &transfer_id) {
                            return Err(Error::PermissionDenied("file child is not active"));
                        }
                        Ok((
                            s.controller_tx.clone(),
                            s.controller_user_id,
                            s.relay_region.clone(),
                            s.tenant_id,
                            s.agent_id,
                        ))
                    })?;
                let tx = controller_tx.ok_or(Error::SendFailed)?;
                let ice_servers = self.zone_local_ice(
                    agent_id,
                    session_id,
                    ice_servers_for_session(
                        &Self::turn_user(user_id, org),
                        &session_id.to_hex(),
                        self.inner.turn.cfg_for(region.as_deref()),
                    ),
                );
                tx.try_send(ServerMsg::FileSdpAnswer {
                    session_id,
                    child_id,
                    transfer_id,
                    sdp,
                    ice_servers,
                })
                .map_err(|_| Error::SendFailed)
            }
            (
                role,
                ClientMsg::FileIce {
                    session_id,
                    child_id,
                    transfer_id,
                    candidate,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                let (agent_id, controller_tx) = self.with_session(session_id, |s| {
                    if role == Role::Controller {
                        let requester = ctx
                            .controller_tx
                            .as_ref()
                            .ok_or(Error::PermissionDenied("missing controller connection"))?;
                        if !s.controller_tx.as_ref().is_some_and(|current| {
                            ptr_eq(current, requester) && !current.is_closed()
                        }) {
                            return Err(Error::PermissionDenied(
                                "not the parent controller connection",
                            ));
                        }
                    }
                    if !s.has_active_file_child(child_id, &transfer_id) {
                        return Err(Error::PermissionDenied("file child is not active"));
                    }
                    Ok((s.agent_id, s.controller_tx.clone()))
                })?;
                // FR-121 — a file child is a peer connection of the same
                // session: the same zone rule, both ways.
                if !self.zone_admits_trickle(agent_id, session_id, role, &candidate) {
                    return Ok(());
                }
                let dest_tx = match role {
                    Role::Controller => self.agent_tx(agent_id)?,
                    Role::Agent => controller_tx.ok_or(Error::SendFailed)?,
                };
                dest_tx
                    .try_send(ServerMsg::FileIce {
                        session_id,
                        child_id,
                        transfer_id,
                        candidate,
                    })
                    .map_err(|_| Error::SendFailed)
            }
            (
                role,
                ClientMsg::FileChildComplete {
                    session_id,
                    child_id,
                    transfer_id,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                let (agent_id, controller_tx) = self.with_session(session_id, |s| {
                    if role == Role::Controller {
                        let requester = ctx
                            .controller_tx
                            .as_ref()
                            .ok_or(Error::PermissionDenied("missing controller connection"))?;
                        if !s.controller_tx.as_ref().is_some_and(|current| {
                            ptr_eq(current, requester) && !current.is_closed()
                        }) {
                            return Err(Error::PermissionDenied(
                                "not the parent controller connection",
                            ));
                        }
                    }
                    s.complete_file_child(child_id, &transfer_id)?;
                    Ok((s.agent_id, s.controller_tx.clone()))
                })?;
                let msg = ServerMsg::FileChildComplete {
                    session_id,
                    child_id,
                    transfer_id,
                };
                match role {
                    Role::Controller => {
                        let _ = self.send_to_agent(agent_id, msg);
                    }
                    Role::Agent => {
                        if let Some(tx) = controller_tx {
                            let _ = tx.try_send(msg);
                        }
                    }
                }
                Ok(())
            }
            (
                Role::Agent,
                ClientMsg::FileChildRevokeAck {
                    session_id,
                    closed_children: _,
                    in_flight_buffered_bytes: _,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.with_session(session_id, |s| {
                    s.ack_file_child_revocation();
                    Ok(())
                })
            }
            (
                Role::Controller,
                ClientMsg::SdpOffer {
                    session_id,
                    sdp,
                    extauth_mac,
                    peer_auth,
                    local_relay,
                },
            ) => {
                self.check_session_party(ctx, session_id)?;
                self.settle_zone_route(session_id, local_relay);
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
            // FR-130 — a viewer's claim on a session held for it. The remote
            // module answers it on the pod the viewer's socket is on: it checks
            // that the row names this person and runs the gate a request runs
            // before it binds here or relays here (`remote::rejoin`). This arm
            // is the bind, on the hub that holds the session.
            (Role::Controller, ClientMsg::SessionRejoin { session_id }) => {
                let user_id = ctx.user_id.ok_or(Error::PermissionDenied("no user"))?;
                let tx = ctx.controller_tx.clone().ok_or(Error::SendFailed)?;
                self.rejoin(session_id, user_id, &tx)
            }
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

// FR-130 — the hub's half of a session that outlives its device's control
// socket: the detach, the claim's bookkeeping and the row ends of sessions no
// hub holds. At the end of the file so no anchor above moves.
mod resume;
use resume::EndWrite;
pub use resume::{Registration, ResumeHello, Resumed, ResumedSession, RowEnd};
// FR-130 P1b-2 — the hub's half of a session that outlives its VIEWER's
// socket: the hold, the rejoin, `replaces`, and the orphan reap's same-person
// rule.
mod hold;
pub use hold::HeldParties;

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::audit::AuditSink;
    use meshharbor_remote_control::signaling::{FileChildDirection, FileChildOfferProof};
    use mongodb::Client;
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
        let grant = meshharbor_remote_control::signaling::ExternalGrant {
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

    /// FR-129 — the DEVICE refusing on two-factor ends the session with that reason (the
    /// viewer then asks the person for a code), never as "a human refused you".
    #[tokio::test]
    async fn a_two_factor_refusal_ends_the_session_with_its_reason() {
        let hub = test_hub().await;
        for (wire, want) in [
            ("two_factor_required", EndReason::TwoFactorRequired),
            ("two_factor_invalid", EndReason::TwoFactorInvalid),
            ("two_factor_locked", EndReason::TwoFactorLocked),
            ("two_factor_unavailable", EndReason::TwoFactorLocked),
        ] {
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
            assert!(matches!(
                ctl_rx.try_recv().unwrap(),
                ServerMsg::SessionCreated { .. }
            ));
            hub.deliver_consent(sid, false, Some(wire)).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut ended = None;
            while let Ok(m) = ctl_rx.try_recv() {
                if let ServerMsg::Terminate { reason, .. } = m {
                    ended = Some(reason);
                }
            }
            assert_eq!(ended, Some(want), "{wire}");
        }
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
        use meshharbor_remote_control::signaling::{PeerAuthAnswer, PeerAuthOffer};
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
        };
        let offer = || ClientMsg::SdpOffer {
            session_id: sid,
            sdp: "v=0".into(),
            extauth_mac: None,
            peer_auth: None,
            local_relay: None,
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

    #[tokio::test]
    async fn unavailable_child_capability_denies_offer_and_preserves_remote_session() {
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
                Permissions::VIEW | Permissions::FILES,
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
        let owner_ctx = DispatchCtx {
            role: Role::Controller,
            user_id: Some(owner),
            agent_id: None,
            controller_name: None,
            controller_tx: Some(ctl_tx),
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
        };
        assert!(matches!(
            ctl_rx.recv().await,
            Some(ServerMsg::SessionCreated { .. })
        ));
        hub.deliver_consent(sid, true, None).unwrap();
        assert!(matches!(ctl_rx.recv().await, Some(ServerMsg::Ready { .. })));
        hub.dispatch(
            &owner_ctx,
            ClientMsg::SdpOffer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: None,
                peer_auth: None,
                local_relay: None,
            },
        )
        .unwrap();
        hub.forward_answer(sid, "v=0".into(), None, None, None)
            .unwrap();
        while agent_rx.try_recv().is_ok() {}

        let child_id = ObjectId::new().to_hex();
        let request = serde_json::json!({
            "t": "rc:file.sdp.offer",
            "session_id": sid.to_hex(),
            "child_id": child_id,
            "transfer_id": "download-test",
            "direction": "download",
            "sdp": "v=0",
            // Synthetic wire data only. Agent-side identity verification is
            // a separate mandatory gate, not established by this Hub test.
            "proof": {"nonce": "synthetic", "key": "synthetic", "sig": "synthetic"},
        });
        let parsed: ClientMsg = serde_json::from_value(request)
            .expect("a download child offer must be a recognized session message");
        assert!(hub.dispatch(&owner_ctx, parsed).is_err());
        assert!(
            agent_rx.try_recv().is_err(),
            "no child offer may reach an agent without explicit capability"
        );
        assert!(
            hub.session_snapshot(sid).is_some(),
            "the original remote session remains active"
        );
    }

    fn file_child_session_request(agent_id: ObjectId) -> ClientMsg {
        ClientMsg::SessionRequest {
            two_factor_code: None,
            agent_id,
            share_grant_id: None,
            permissions: Permissions::VIEW | Permissions::FILES,
            browser_caps: Vec::new(),
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            override_reason: None,
            local_relay: None,
            initial_resolution: None,
            replaces: None,
            continues_from: None,
            silent_monitor: false,
            monitor_target_session_id: None,
        }
    }

    struct FileChildDispatchFixture {
        hub: Hub,
        sid: ObjectId,
        owner: ObjectId,
        controller_tx: ClientTx,
        controller_rx: mpsc::Receiver<ServerMsg>,
        agent_tx: ClientTx,
        agent_rx: mpsc::Receiver<ServerMsg>,
        other_agent_rx: mpsc::Receiver<ServerMsg>,
        _audit_events: meshharbor_remote_control::audit::AuditTestRx,
    }
    impl FileChildDispatchFixture {
        async fn new() -> Self {
            // No Mongo client, flusher, network, agent task, or child PC.
            let (audit, audit_events) = AuditSink::channel_for_tests();
            let hub = Hub::new(audit, None);
            let agent = ObjectId::new();
            let owner = ObjectId::new();
            let (agent_tx, _, mut agent_rx) = hub.register_agent(
                agent,
                ObjectId::new(),
                owner,
                OsKind::Linux,
                3,
                false,
                false,
            );
            let (_, _, other_agent_rx) = hub.register_agent(
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                OsKind::Linux,
                3,
                false,
                false,
            );
            let (controller_tx, mut controller_rx) = mpsc::channel(16);
            hub.dispatch_local_pdp_session_request(
                &Self::context(owner, controller_tx.clone()),
                file_child_session_request(agent),
                meshharbor_remote_control::session::FileChildPolicySnapshot::new(Some(2), Some(4)),
            )
            .unwrap();
            let sid = match controller_rx.try_recv().unwrap() {
                ServerMsg::SessionCreated { session_id, .. } => session_id,
                other => panic!("expected parent creation, got {other:?}"),
            };
            assert_eq!(hub.file_child_local_pdp_for_tests(sid), Some(true));
            hub.deliver_consent(sid, true, None).unwrap();
            let ready = tokio::time::timeout(Duration::from_secs(2), controller_rx.recv())
                .await
                .expect("bounded synthetic consent Ready");
            assert!(matches!(ready, Some(ServerMsg::Ready { .. })));
            hub.dispatch(
                &Self::context(owner, controller_tx.clone()),
                ClientMsg::SdpOffer {
                    session_id: sid,
                    sdp: "v=0".into(),
                    extauth_mac: None,
                    peer_auth: None,
                    local_relay: None,
                },
            )
            .unwrap();
            hub.forward_answer(sid, "v=0".into(), None, None, None)
                .unwrap();
            assert!(matches!(
                controller_rx.try_recv(),
                Ok(ServerMsg::SdpAnswer { .. })
            ));
            while agent_rx.try_recv().is_ok() {}
            hub.with_session(sid, |s| {
                assert_eq!(s.phase, SessionPhase::Active);
                assert!(s.permissions().contains(Permissions::FILES));
                Ok(())
            })
            .unwrap();
            Self {
                hub,
                sid,
                owner,
                controller_tx,
                controller_rx,
                agent_tx,
                agent_rx,
                other_agent_rx,
                _audit_events: audit_events,
            }
        }
        fn context(owner: ObjectId, tx: ClientTx) -> DispatchCtx {
            DispatchCtx {
                role: Role::Controller,
                user_id: Some(owner),
                agent_id: None,
                controller_tx: Some(tx),
                controller_name: None,
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
                share_files_account: None,
                continues: None,
                silent_monitor: false,
            }
        }
        fn ctx(&self) -> DispatchCtx {
            Self::context(self.owner, self.controller_tx.clone())
        }
        fn enable_for_test(&self) {
            self.hub
                .with_session(self.sid, |s| {
                    s.set_file_children_enabled(true);
                    Ok(())
                })
                .unwrap();
        }
        fn reserve_message(&self, transfer: &str) -> ClientMsg {
            ClientMsg::FileChildReserve {
                session_id: self.sid,
                transfer_id: transfer.into(),
                direction: FileChildDirection::Download,
            }
        }
        fn reserve(&mut self, transfer: &str) -> ObjectId {
            self.hub
                .dispatch(&self.ctx(), self.reserve_message(transfer))
                .unwrap();
            match self
                .controller_rx
                .try_recv()
                .expect("reserve must enqueue its bound reply")
            {
                ServerMsg::FileChildReserved {
                    session_id,
                    child_id,
                    transfer_id,
                    direction: FileChildDirection::Download,
                } => {
                    assert_eq!(session_id, self.sid);
                    assert_eq!(transfer_id, transfer);
                    child_id
                }
                other => panic!("unexpected reserve reply: {other:?}"),
            }
        }
        fn offer(&self, child: ObjectId, transfer: &str) -> ClientMsg {
            ClientMsg::FileSdpOffer {
                session_id: self.sid,
                child_id: child,
                transfer_id: transfer.into(),
                direction: FileChildDirection::Download,
                sdp: "v=0\r\na=fingerprint:sha-256 AA:BB:CC\r\n".into(),
                // Deliberately opaque at the Hub: only the real agent's
                // parent-bound crypto gate can authenticate these bytes.
                // This test never constructs that agent or claims acceptance.
                proof: FileChildOfferProof {
                    nonce: "opaque-nonce".into(),
                    key: "opaque-key".into(),
                    sig: "opaque-signature".into(),
                },
            }
        }
        fn binding(&self, child: ObjectId, transfer: &str) -> Option<bool> {
            self.hub
                .with_session(self.sid, |s| {
                    Ok(s.file_child_active_for_tests(child, transfer))
                })
                .unwrap()
        }
        fn no_offer(&mut self) {
            assert!(
                self.agent_rx.try_recv().is_err(),
                "refusal must not enqueue an agent offer"
            );
            assert!(
                self.other_agent_rx.try_recv().is_err(),
                "unrelated agent must stay untouched"
            );
        }
    }

    #[tokio::test]
    async fn file_child_default_capability_stays_off_for_local_pdp_parent() {
        let mut f = FileChildDispatchFixture::new().await;
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.reserve_message("disabled"))
                .is_err()
        );
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.offer(ObjectId::new(), "disabled"))
                .is_err()
        );
        f.no_offer();
        assert!(f.controller_rx.try_recv().is_err());
        assert!(f.hub.session_snapshot(f.sid).is_some());
    }

    #[tokio::test]
    async fn file_child_controller_origin_is_frozen_and_not_selected_by_legacy_or_relay_wire() {
        let f = FileChildDispatchFixture::new().await;
        let ctx = f.ctx();
        let agent = f.hub.with_session(f.sid, |s| Ok(s.agent_id)).unwrap();
        let mut receiver = f.controller_rx;
        // The same authorized local producer may retry, without a new source stamp.
        f.hub
            .dispatch_local_pdp_session_request(&ctx, file_child_session_request(agent), None)
            .unwrap();
        assert!(
            matches!(receiver.try_recv(), Ok(ServerMsg::SessionCreated { session_id, .. }) if session_id == f.sid)
        );
        // Relay and old dispatch consume only wire+DispatchCtx. Unknown JSON
        // fields cannot choose the server-only creator, even on this exact tab.
        let mut wire = serde_json::to_value(file_child_session_request(agent)).unwrap();
        wire["local_pdp"] = serde_json::json!(true);
        wire["file_child_controller_scope"] = serde_json::json!({"local_pdp": true});
        f.hub
            .dispatch(&ctx, serde_json::from_value(wire).unwrap())
            .unwrap();
        let unknown = match receiver.try_recv().unwrap() {
            ServerMsg::SessionCreated { session_id, .. } => session_id,
            other => panic!("expected Unknown parent, got {other:?}"),
        };
        assert_ne!(
            unknown, f.sid,
            "coalescing must not upgrade Unknown or inherit a trusted source"
        );
        assert_eq!(f.hub.file_child_local_pdp_for_tests(unknown), Some(false));
        // Legacy create delegates through the public full constructor, both
        // deliberately Unknown, and may coalesce only with that same scope.
        let legacy = f
            .hub
            .create_session(
                agent,
                f.owner,
                "Synthetic".into(),
                f.controller_tx.clone(),
                Permissions::VIEW | Permissions::FILES,
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
        assert_eq!(legacy, unknown);
        assert!(
            matches!(receiver.try_recv(), Ok(ServerMsg::SessionCreated { session_id, .. }) if session_id == unknown)
        );
        f.hub
            .with_session(unknown, |s| {
                s.set_file_children_enabled(true);
                s.phase = SessionPhase::Active;
                assert!(s.reserve_file_child("cannot-inherit").is_err());
                Ok(())
            })
            .unwrap();
        // No owner-remote consent / override / share request may select the
        // dedicated local source. Rejection leaves both original scopes frozen.
        for mode in [
            ConsentMode::Email,
            ConsentMode::Push,
            ConsentMode::PromptThenEmail,
        ] {
            let invalid = DispatchCtx {
                consent_mode: mode,
                ..FileChildDispatchFixture::context(f.owner, f.controller_tx.clone())
            };
            assert!(
                f.hub
                    .dispatch_local_pdp_session_request(
                        &invalid,
                        file_child_session_request(agent),
                        None,
                    )
                    .is_err()
            );
        }
        let invalid = DispatchCtx {
            override_reason: Some("synthetic".into()),
            ..FileChildDispatchFixture::context(f.owner, f.controller_tx.clone())
        };
        assert!(
            f.hub
                .dispatch_local_pdp_session_request(
                    &invalid,
                    file_child_session_request(agent),
                    None,
                )
                .is_err()
        );
        let mut shared = file_child_session_request(agent);
        if let ClientMsg::SessionRequest { share_grant_id, .. } = &mut shared {
            *share_grant_id = Some(ObjectId::new());
        }
        assert!(
            f.hub
                .dispatch_local_pdp_session_request(&ctx, shared, None)
                .is_err()
        );
        assert_eq!(f.hub.file_child_local_pdp_for_tests(f.sid), Some(true));
        assert_eq!(f.hub.file_child_local_pdp_for_tests(unknown), Some(false));
    }

    #[tokio::test]
    async fn file_child_offer_forwards_only_matching_reserved_parent_tab() {
        use meshharbor_remote_control::session::DeviceShareSessionScope;

        type Fixture = FileChildDispatchFixture;

        let mut f = Fixture::new().await;
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.reserve_message("default-off"))
                .is_err()
        );
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.offer(ObjectId::new(), "default-off"))
                .is_err()
        );
        assert!(f.controller_rx.try_recv().is_err());
        f.no_offer();
        assert!(
            f.hub.session_snapshot(f.sid).is_some(),
            "default refusal preserves the parent"
        );

        f.enable_for_test();
        let active = f.reserve("active");
        let (tab_tx, mut tab_rx) = mpsc::channel(16);
        for ctx in [
            Fixture::context(f.owner, tab_tx),
            Fixture::context(ObjectId::new(), f.controller_tx.clone()),
        ] {
            assert!(f.hub.dispatch(&ctx, f.offer(active, "active")).is_err());
            assert_eq!(f.binding(active, "active"), Some(false));
            f.no_offer();
        }
        assert!(tab_rx.try_recv().is_err());
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.offer(active, "wrong-transfer"))
                .is_err()
        );
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.offer(ObjectId::new(), "active"))
                .is_err()
        );
        let mut missing_parent = f.offer(active, "active");
        if let ClientMsg::FileSdpOffer { session_id, .. } = &mut missing_parent {
            *session_id = ObjectId::new();
        }
        assert!(f.hub.dispatch(&f.ctx(), missing_parent).is_err());
        assert_eq!(f.binding(active, "active"), Some(false));
        f.no_offer();

        let offer = f.offer(active, "active");
        let expected = serde_json::to_value(&offer).unwrap();
        let forwarded = f.hub.dispatch(&f.ctx(), offer);
        assert!(
            forwarded.is_ok(),
            "X14 reserved file child offer must dispatch once to its parent agent: {forwarded:?}"
        );
        // Nobody polls the fake agent: Active here means queue admission,
        // not remote delivery, proof verification, or an established PC.
        assert_eq!(f.agent_rx.len(), 1);
        assert_eq!(f.binding(active, "active"), Some(true));
        assert!(f.other_agent_rx.try_recv().is_err());
        assert_eq!(
            serde_json::to_value(f.agent_rx.try_recv().unwrap()).unwrap(),
            expected
        );
        assert!(f.hub.dispatch(&f.ctx(), f.offer(active, "active")).is_err());
        f.no_offer();

        let kept = f.reserve("kept");
        // Both bounded mpsc failure variants must roll back only the offered
        // Reserved binding. The already-Active child and another reservation
        // survive; no failed attempt can become Active or consume a slot.
        for closed in [false, true] {
            let failed = f.reserve("send-failed");
            if closed {
                f.agent_rx.close();
                assert!(f.agent_tx.is_closed());
            } else {
                assert_eq!(f.agent_rx.len(), 0);
                for _ in 0..f.agent_tx.max_capacity() {
                    f.agent_tx.try_send(ServerMsg::Pong { id: 7 }).unwrap();
                }
                assert_eq!(f.agent_tx.capacity(), 0);
            }
            assert!(matches!(
                f.hub.dispatch(&f.ctx(), f.offer(failed, "send-failed")),
                Err(Error::SendFailed)
            ));
            assert_eq!(f.binding(failed, "send-failed"), None);
            assert_eq!(f.binding(active, "active"), Some(true));
            assert_eq!(f.binding(kept, "kept"), Some(false));
            let first = f.reserve("filler-1");
            let second = f.reserve("filler-2");
            assert!(
                f.hub
                    .dispatch(&f.ctx(), f.reserve_message("fifth"))
                    .is_err()
            );
            assert!(f.controller_rx.try_recv().is_err());
            f.hub
                .with_session(f.sid, |s| {
                    assert!(s.cancel_file_child_reservation(active, "active").is_err());
                    assert!(
                        s.cancel_file_child_reservation(kept, "wrong-transfer")
                            .is_err()
                    );
                    s.cancel_file_child_reservation(first, "filler-1")?;
                    s.cancel_file_child_reservation(second, "filler-2")?;
                    Ok(())
                })
                .unwrap();
            if !closed {
                let mut count = 0;
                while let Ok(msg) = f.agent_rx.try_recv() {
                    assert!(matches!(msg, ServerMsg::Pong { id: 7 }));
                    count += 1;
                }
                assert_eq!(count, f.agent_tx.max_capacity());
            }
            assert!(f.other_agent_rx.try_recv().is_err());
        }

        let mut shared = Fixture::new().await;
        shared.enable_for_test();
        let child = shared.reserve("scoped");
        shared
            .hub
            .with_session(shared.sid, |s| {
                s.bind_device_share(DeviceShareSessionScope {
                    grant_id: ObjectId::new(),
                    ceiling: Permissions::VIEW | Permissions::FILES,
                })
            })
            .unwrap();
        assert!(
            shared
                .hub
                .dispatch(&shared.ctx(), shared.offer(child, "scoped"))
                .is_err()
        );
        shared.no_offer();

        let mut narrowed = Fixture::new().await;
        narrowed.enable_for_test();
        let child = narrowed.reserve("narrowed");
        narrowed
            .hub
            .with_session(narrowed.sid, |s| {
                s.set_permissions(Permissions::VIEW);
                Ok(())
            })
            .unwrap();
        assert!(
            narrowed
                .hub
                .dispatch(&narrowed.ctx(), narrowed.offer(child, "narrowed"))
                .is_err()
        );
        assert_eq!(narrowed.binding(child, "narrowed"), None);
        narrowed
            .hub
            .with_session(narrowed.sid, |s| {
                s.set_permissions(Permissions::VIEW | Permissions::FILES);
                s.set_file_children_enabled(true);
                Ok(())
            })
            .unwrap();
        assert!(
            narrowed
                .hub
                .dispatch(&narrowed.ctx(), narrowed.offer(child, "narrowed"))
                .is_err()
        );
        narrowed.no_offer(); // Local setter gate only, not a remote revocation claim.

        let mut ended = Fixture::new().await;
        ended.enable_for_test();
        let child = ended.reserve("ended");
        ended
            .hub
            .terminate(ended.sid, EndReason::ControllerHangup)
            .unwrap();
        assert!(ended.hub.session_snapshot(ended.sid).is_none());
        assert!(
            ended
                .hub
                .dispatch(&ended.ctx(), ended.offer(child, "ended"))
                .is_err()
        );
        while let Ok(msg) = ended.agent_rx.try_recv() {
            assert!(
                matches!(msg, ServerMsg::Terminate { session_id, .. } if session_id == ended.sid)
            );
        }
        assert!(ended.other_agent_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn file_reservation_is_parent_bound_and_rejected_after_close_or_files_loss() {
        use meshharbor_remote_control::signaling::{FileChildDirection, FileChildOfferProof};
        use std::collections::HashSet;

        async fn next(rx: &mut mpsc::Receiver<ServerMsg>) -> ServerMsg {
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("bounded synthetic parent setup")
                .expect("controller remains connected")
        }
        fn reserved(
            rx: &mut mpsc::Receiver<ServerMsg>,
            parent: ObjectId,
            transfer: &str,
        ) -> ObjectId {
            match rx
                .try_recv()
                .expect("successful synchronous reserve must enqueue its reply")
            {
                ServerMsg::FileChildReserved {
                    session_id,
                    child_id,
                    transfer_id,
                    direction: FileChildDirection::Download,
                } => {
                    assert_eq!(session_id, parent);
                    assert_eq!(transfer_id, transfer);
                    child_id
                }
                other => panic!("expected bound server reservation, got {other:?}"),
            }
        }
        // No localhost Mongo Client, DB flusher, sockets, or child PCs. Keep
        // the bounded receiver alive so ordinary audit records can be queued.
        let (audit, _audit_events) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let agent = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
            agent,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let owner = ObjectId::new();
        let (ctl_tx, mut ctl_rx) = mpsc::channel(8);
        let context = |role, user_id, agent_id, controller_tx| DispatchCtx {
            role,
            user_id,
            agent_id,
            controller_tx,
            controller_name: None,
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
        };
        let owner_ctx = context(Role::Controller, Some(owner), None, Some(ctl_tx.clone()));
        hub.dispatch_local_pdp_session_request(&owner_ctx, file_child_session_request(agent), None)
            .unwrap();
        let sid = match next(&mut ctl_rx).await {
            ServerMsg::SessionCreated { session_id, .. } => session_id,
            other => panic!("expected parent creation, got {other:?}"),
        };
        let reserve = |session_id, transfer: &str| ClientMsg::FileChildReserve {
            session_id,
            transfer_id: transfer.into(),
            direction: FileChildDirection::Download,
        };
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "before-consent"))
                .is_err()
        );
        hub.deliver_consent(sid, true, None).unwrap();
        assert!(matches!(next(&mut ctl_rx).await, ServerMsg::Ready { .. }));
        hub.dispatch(
            &owner_ctx,
            ClientMsg::SdpOffer {
                session_id: sid,
                sdp: "v=0".into(),
                extauth_mac: None,
                peer_auth: None,
                local_relay: None,
            },
        )
        .unwrap();
        hub.forward_answer(sid, "v=0".into(), None, None, None)
            .unwrap();
        assert!(matches!(
            next(&mut ctl_rx).await,
            ServerMsg::SdpAnswer { .. }
        ));
        while agent_rx.try_recv().is_ok() {}
        assert!(
            hub.session_grant(sid)
                .unwrap()
                .2
                .contains(Permissions::FILES),
            "fixture must really have an effective FILES grant"
        );
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "default-off"))
                .is_err()
        );
        assert!(ctl_rx.try_recv().is_err());
        assert!(
            hub.session_snapshot(sid).is_some(),
            "default refusal preserves ordinary RC"
        );

        // Explicit test setup only; no production negotiation or caller field
        // enables this gate. Probe and reset the existing state gate so a bad
        // fixture cannot be mistaken for the missing dispatcher behavior.
        hub.with_session(sid, |s| {
            assert_eq!(s.phase, SessionPhase::Active);
            s.set_file_children_enabled(true);
            s.reserve_file_child("fixture-gate-probe")?;
            s.set_file_children_enabled(false);
            s.set_file_children_enabled(true);
            Ok(())
        })
        .unwrap();
        let stranger = context(
            Role::Controller,
            Some(ObjectId::new()),
            None,
            Some(ctl_tx.clone()),
        );
        let (other_tx, mut other_rx) = mpsc::channel(8);
        let other_tab = context(Role::Controller, Some(owner), None, Some(other_tx));
        let agent_ctx = context(Role::Agent, None, Some(agent), None);
        for ctx in [&stranger, &other_tab, &agent_ctx] {
            assert!(
                hub.dispatch(ctx, reserve(sid, "not-this-parent-connection"))
                    .is_err()
            );
        }
        assert!(
            other_rx.try_recv().is_err(),
            "same user on another tab receives no reservation"
        );
        assert!(
            hub.dispatch(&owner_ctx, reserve(ObjectId::new(), "missing-parent"))
                .is_err()
        );
        for transfer in [String::new(), "x".repeat(129), "bad\ntransfer".into()] {
            assert!(hub.dispatch(&owner_ctx, reserve(sid, &transfer)).is_err());
        }
        assert!(ctl_rx.try_recv().is_err());
        let mut children = HashSet::new();
        for _ in 0..4 {
            let result = hub.dispatch(&owner_ctx, reserve(sid, "download-test"));
            assert!(
                result.is_ok(),
                "enabled active FILES parent must dispatch a server reservation for its current tab: {result:?}"
            );
            assert!(children.insert(reserved(&mut ctl_rx, sid, "download-test")));
        }
        assert!(hub.dispatch(&owner_ctx, reserve(sid, "fifth")).is_err());
        assert!(
            agent_rx.try_recv().is_err(),
            "reservations never reach the agent as child offers"
        );
        let offered = *children.iter().next().unwrap();
        assert!(
            hub.dispatch(
                &owner_ctx,
                ClientMsg::FileSdpOffer {
                    session_id: sid,
                    child_id: offered,
                    transfer_id: "wrong-transfer".into(),
                    direction: FileChildDirection::Download,
                    sdp: "v=0".into(),
                    proof: FileChildOfferProof {
                        nonce: "synthetic".into(),
                        key: "synthetic".into(),
                        sig: "synthetic".into()
                    },
                }
            )
            .is_err(),
            "an offer must match its reserved transfer even with the test capability"
        );
        assert!(agent_rx.try_recv().is_err());

        // This simulates the existing local effective-permission setter. It
        // does not prove an admin route, remote notification, or transport stop.
        hub.with_session(sid, |s| {
            s.set_permissions(Permissions::VIEW);
            Ok(())
        })
        .unwrap();
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "files-withdrawn"))
                .is_err()
        );
        hub.with_session(sid, |s| {
            s.set_permissions(Permissions::VIEW | Permissions::FILES);
            Ok(())
        })
        .unwrap();
        assert!(
            hub.dispatch(
                &owner_ctx,
                reserve(sid, "files-restored-without-renegotiation")
            )
            .is_err()
        );
        hub.with_session(sid, |s| {
            s.set_file_children_enabled(true);
            for child in &children {
                assert!(s.admit_file_child(*child, "download-test").is_err());
                assert!(s.complete_file_child(*child, "download-test").is_err());
            }
            Ok(())
        })
        .unwrap();

        // Existing Active and Reserved records make a wrong rollback visible:
        // freeing one old record while leaking the new one must not pass.
        let (active, kept) = hub
            .with_session(sid, |s| {
                let active = s.reserve_file_child("active-fixture")?;
                s.admit_file_child(active, "active-fixture")?;
                let kept = s.reserve_file_child("reserved-fixture")?;
                assert!(
                    s.cancel_file_child_reservation(active, "active-fixture")
                        .is_err()
                );
                assert!(
                    s.cancel_file_child_reservation(kept, "wrong-transfer")
                        .is_err()
                );
                Ok((active, kept))
            })
            .unwrap();
        let filler = ServerMsg::Error {
            session_id: None,
            code: "fixture".into(),
            message: "bounded reply queue".into(),
            open_nonce: None,
        };
        for _ in 0..8 {
            ctl_tx.try_send(filler.clone()).unwrap();
        }
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "failed-reply"))
                .is_err(),
            "a full reply queue must not be reported as a successful reservation"
        );
        while ctl_rx.try_recv().is_ok() {}
        hub.with_session(sid, |s| {
            s.complete_file_child(active, "active-fixture")?;
            let replacement = s.reserve_file_child("active-replacement")?;
            s.admit_file_child(replacement, "active-replacement")?;
            s.admit_file_child(kept, "reserved-fixture")?;
            Ok(())
        })
        .expect("reply rollback preserves each pre-existing Active/Reserved binding");
        for transfer in ["remaining-one", "remaining-two"] {
            hub.dispatch(&owner_ctx, reserve(sid, transfer)).unwrap();
            reserved(&mut ctl_rx, sid, transfer);
        }
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "overflow-after-rollback"))
                .is_err(),
            "exactly two slots remain after the failed reply; no leak or unrelated release"
        );
        assert!(hub.session_snapshot(sid).is_some());

        hub.with_session(sid, |s| {
            s.set_file_children_enabled(false);
            s.set_file_children_enabled(true);
            Ok(())
        })
        .unwrap();
        drop(ctl_rx);
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "closed-reply-channel"))
                .is_err()
        );
        if hub.session_snapshot(sid).is_some() {
            hub.with_session(sid, |s| {
                for _ in 0..4 {
                    s.reserve_file_child("closed-channel-budget-check")?;
                }
                assert!(s.reserve_file_child("fifth").is_err());
                Ok(())
            })
            .expect("closed reply either ends the parent or leaves no leaked reservation");
        }
        hub.terminate(sid, EndReason::ControllerHangup).unwrap();
        assert!(hub.session_snapshot(sid).is_none());
        assert!(
            hub.dispatch(&owner_ctx, reserve(sid, "after-parent-close"))
                .is_err()
        );
        let frames: Vec<_> = std::iter::from_fn(|| agent_rx.try_recv().ok()).collect();
        assert!(
            frames
                .iter()
                .all(|frame| !matches!(frame, ServerMsg::FileSdpOffer { .. })),
            "no branch in the reservation test starts a child transport"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn file_child_revocation_notifies_peers_and_keeps_parent_when_acked_within_5s() {
        use meshharbor_remote_control::session::FileChildPolicySnapshot;

        let mut f = FileChildDispatchFixture::new().await;
        let agent = f.hub.with_session(f.sid, |s| Ok(s.agent_id)).unwrap();
        let snap1 = FileChildPolicySnapshot::new(Some(2), Some(4));
        let started_watch = f
            .hub
            .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap1)
            .expect("initial policy snapshot must bind and enable child capability");
        assert!(started_watch, "first snapshot bind must claim the watcher");
        assert!(
            !f.hub
                .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap1)
                .unwrap(),
            "subsequent matching snapshot must not spawn a duplicate watcher"
        );

        let child = f.reserve("striped-dl");
        f.hub
            .dispatch(&f.ctx(), f.offer(child, "striped-dl"))
            .unwrap();
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileSdpOffer { child_id, .. }) if child_id == child
        ));

        let agent_ctx = DispatchCtx {
            role: Role::Agent,
            user_id: None,
            agent_id: Some(agent),
            controller_tx: None,
            controller_name: None,
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
        };
        f.hub
            .dispatch(
                &agent_ctx,
                ClientMsg::FileSdpAnswer {
                    session_id: f.sid,
                    child_id: child,
                    transfer_id: "striped-dl".into(),
                    sdp: "v=0\r\na=answer\r\n".into(),
                },
            )
            .unwrap();
        assert!(matches!(
            f.controller_rx.try_recv(),
            Ok(ServerMsg::FileSdpAnswer { child_id, .. }) if child_id == child
        ));

        f.hub
            .dispatch(
                &f.ctx(),
                ClientMsg::FileIce {
                    session_id: f.sid,
                    child_id: child,
                    transfer_id: "striped-dl".into(),
                    candidate: serde_json::json!({"candidate": "candidate:1"}),
                },
            )
            .unwrap();
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileIce { child_id, .. }) if child_id == child
        ));

        // Simulate ABA or policy tightening advancing tenant security_rev from 2 -> 3.
        let snap2 = FileChildPolicySnapshot::new(Some(3), Some(4));
        assert!(
            f.hub
                .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap2)
                .is_err(),
            "revision mismatch must fail closed"
        );
        assert!(matches!(
            f.controller_rx.try_recv(),
            Ok(ServerMsg::FileChildRevoke { session_id, .. }) if session_id == f.sid
        ));
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileChildRevoke { session_id, .. }) if session_id == f.sid
        ));

        // Agent acknowledges within the 5-second deadline.
        f.hub
            .dispatch(
                &agent_ctx,
                ClientMsg::FileChildRevokeAck {
                    session_id: f.sid,
                    closed_children: 1,
                    in_flight_buffered_bytes: 0,
                },
            )
            .unwrap();

        tokio::time::sleep(FILE_CHILD_REVOKE_ACK_TIMEOUT + Duration::from_secs(1)).await;
        assert!(
            f.hub.session_snapshot(f.sid).is_some(),
            "parent session must remain alive when agent acknowledges child revocation in time"
        );
        // And child capability stays irreversibly revoked for this parent session.
        assert!(
            f.hub
                .dispatch(&f.ctx(), f.reserve_message("after-revoke"))
                .is_err()
        );
    }

    #[tokio::test]
    async fn file_child_watcher_stops_when_idle_and_restarts_on_next_reserve() {
        use meshharbor_remote_control::session::FileChildPolicySnapshot;

        let mut f = FileChildDispatchFixture::new().await;
        let snap = FileChildPolicySnapshot::new(Some(2), Some(4));

        // 1. First admission claims the watcher.
        assert!(
            f.hub
                .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap)
                .unwrap()
        );
        // Before any child slot is reserved, an idle poll releases the watcher.
        assert!(
            !f.hub
                .poll_file_child_watch_target(f.sid, f.owner, &f.controller_tx)
                .unwrap()
        );
        // Next reserve admission re-claims the watcher.
        assert!(
            f.hub
                .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap)
                .unwrap()
        );
        let child = f.reserve("dl-batch-1");
        // While Reserved, watcher stays active.
        assert!(
            f.hub
                .poll_file_child_watch_target(f.sid, f.owner, &f.controller_tx)
                .unwrap()
        );
        f.hub
            .dispatch(&f.ctx(), f.offer(child, "dl-batch-1"))
            .unwrap();
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileSdpOffer { .. })
        ));
        // While Active, watcher stays active.
        assert!(
            f.hub
                .poll_file_child_watch_target(f.sid, f.owner, &f.controller_tx)
                .unwrap()
        );
        // Completing the last active child allows the watcher to exit on the next poll.
        f.hub
            .dispatch(
                &f.ctx(),
                ClientMsg::FileChildComplete {
                    session_id: f.sid,
                    child_id: child,
                    transfer_id: "dl-batch-1".into(),
                },
            )
            .unwrap();
        assert!(
            !f.hub
                .poll_file_child_watch_target(f.sid, f.owner, &f.controller_tx)
                .unwrap(),
            "watcher must exit when no Reserved/Active children remain"
        );
        // And the next reserve admission re-claims `start_watch = true` while still enforcing the bound snapshot.
        assert!(
            f.hub
                .admit_file_child_policy_snapshot(f.sid, f.owner, &f.controller_tx, snap)
                .unwrap(),
            "next reserve after idle watcher exit must return start_watch = true"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn file_child_revocation_without_ack_within_5s_terminates_parent_fail_closed() {
        let mut f = FileChildDispatchFixture::new().await;
        f.enable_for_test();
        let child = f.reserve("unacked-revoke");
        f.hub
            .dispatch(&f.ctx(), f.offer(child, "unacked-revoke"))
            .unwrap();
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileSdpOffer { .. })
        ));

        f.hub
            .revoke_file_children(f.sid, "policy_tightened")
            .unwrap();
        assert!(matches!(
            f.controller_rx.try_recv(),
            Ok(ServerMsg::FileChildRevoke { session_id, .. }) if session_id == f.sid
        ));
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileChildRevoke { session_id, .. }) if session_id == f.sid
        ));

        // No FileChildRevokeAck arrives within 5 seconds -> fail-closed parent termination.
        tokio::time::sleep(FILE_CHILD_REVOKE_ACK_TIMEOUT + Duration::from_secs(1)).await;
        assert!(
            f.hub.session_snapshot(f.sid).is_none(),
            "unacknowledged child revocation must terminate the parent session after 5s"
        );
        assert!(matches!(
            f.controller_rx.try_recv(),
            Ok(ServerMsg::Terminate { session_id, reason: EndReason::AdminTerminated, .. })
                if session_id == f.sid
        ));
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::Terminate { session_id, reason: EndReason::AdminTerminated, .. })
                if session_id == f.sid
        ));
    }

    #[tokio::test]
    async fn file_child_upload_opt_in_and_kill_switch_are_independent_of_download() {
        use meshharbor_remote_control::session::FileChildPolicySnapshot;

        let mut f = FileChildDispatchFixture::new().await;
        let snap = FileChildPolicySnapshot::new(Some(2), Some(4));

        // Opt in only to download first: upload admission must be denied.
        f.hub
            .with_session(f.sid, |s| {
                s.set_file_children_opted_in_for(FileChildDirection::Download, true);
                s.set_file_children_opted_in_for(FileChildDirection::Upload, false);
                Ok(())
            })
            .unwrap();
        f.hub
            .admit_file_child_policy_snapshot_for_direction(
                f.sid,
                f.owner,
                &f.controller_tx,
                FileChildDirection::Download,
                snap,
            )
            .expect("download opted in");
        assert!(
            f.hub
                .admit_file_child_policy_snapshot_for_direction(
                    f.sid,
                    f.owner,
                    &f.controller_tx,
                    FileChildDirection::Upload,
                    snap,
                )
                .is_err(),
            "upload must be denied when only download is opted in"
        );

        // Opt in to upload as well.
        f.hub
            .with_session(f.sid, |s| {
                s.set_file_children_opted_in_for(FileChildDirection::Upload, true);
                Ok(())
            })
            .unwrap();
        f.hub
            .admit_file_child_policy_snapshot_for_direction(
                f.sid,
                f.owner,
                &f.controller_tx,
                FileChildDirection::Upload,
                snap,
            )
            .expect("upload opted in");

        // Reserve and offer an upload child.
        f.hub
            .dispatch(
                &f.ctx(),
                ClientMsg::FileChildReserve {
                    session_id: f.sid,
                    transfer_id: "up-1".into(),
                    direction: FileChildDirection::Upload,
                },
            )
            .unwrap();
        let up_cid = match f.controller_rx.try_recv().unwrap() {
            ServerMsg::FileChildReserved {
                child_id,
                direction: FileChildDirection::Upload,
                ..
            } => child_id,
            other => panic!("expected upload reservation, got {other:?}"),
        };

        // Cross-direction offer (Download offer against Upload reservation) is rejected.
        assert!(
            f.hub.dispatch(&f.ctx(), f.offer(up_cid, "up-1")).is_err(),
            "download offer must not consume an upload reservation"
        );
        // Matching Upload offer succeeds.
        f.hub
            .dispatch(
                &f.ctx(),
                ClientMsg::FileSdpOffer {
                    session_id: f.sid,
                    child_id: up_cid,
                    transfer_id: "up-1".into(),
                    direction: FileChildDirection::Upload,
                    sdp: "v=0\r\na=fingerprint:sha-256 AA:BB:CC\r\n".into(),
                    proof: FileChildOfferProof {
                        nonce: "opaque-nonce".into(),
                        key: "opaque-key".into(),
                        sig: "opaque-signature".into(),
                    },
                },
            )
            .unwrap();
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileSdpOffer {
                child_id,
                direction: FileChildDirection::Upload,
                ..
            }) if child_id == up_cid
        ));

        // Flip ONLY the upload kill switch: upload fails closed while download keeps working!
        f.hub
            .set_file_child_direction_disabled(FileChildDirection::Upload, true);
        assert!(
            f.hub
                .dispatch(
                    &f.ctx(),
                    ClientMsg::FileChildReserve {
                        session_id: f.sid,
                        transfer_id: "up-blocked".into(),
                        direction: FileChildDirection::Upload,
                    },
                )
                .is_err(),
            "upload kill switch must block upload reservations"
        );
        let dl_cid = f.reserve("dl-still-works");
        f.hub
            .dispatch(&f.ctx(), f.offer(dl_cid, "dl-still-works"))
            .expect("download must continue working when only upload kill switch is set");
        assert!(matches!(
            f.agent_rx.try_recv(),
            Ok(ServerMsg::FileSdpOffer {
                child_id,
                direction: FileChildDirection::Download,
                ..
            }) if child_id == dl_cid
        ));
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
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
                local_relay: None,
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
            share_files_account: None,
            continues: None,
            silent_monitor: false,
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
                external.then(|| meshharbor_remote_control::signaling::ExternalGrant {
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
        let controller_id = ObjectId::new();
        let mut ask = |hub: &Hub,
                       tx: ClientTx,
                       rx: &mut mpsc::Receiver<ServerMsg>,
                       wants: Permissions,
                       org: OrgPolicy|
         -> Told {
            hub.create_session_full(
                agent_id,
                controller_id,
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
            controller_id,
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
                Some(meshharbor_remote_control::models::InputMode::Exclusive),
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
                    Some(meshharbor_remote_control::models::InputMode::Exclusive)
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

    /// The CN zone declares CN; its gateway's address reads HK. HK must not
    /// become "inside" the zone (the centre's TURN would pass the strict
    /// filter). A zone that declares no country still takes its gateways'.
    #[test]
    fn a_zone_that_declares_its_countries_keeps_to_them() {
        let set = |v: &[&str]| {
            v.iter()
                .map(|s| s.to_string())
                .collect::<std::collections::HashSet<_>>()
        };
        assert_eq!(
            zone_infra_countries(&["cn".into()], vec!["HK".to_string()]),
            set(&["CN"])
        );
        assert_eq!(
            zone_infra_countries(&[], vec!["hk".to_string(), "JP".to_string()]),
            set(&["HK", "JP"])
        );
        assert!(zone_infra_countries(&[], Vec::<String>::new()).is_empty());
    }

    /// FR-121 — a controller on no mesh node, cross-zone to a strict device:
    /// the moment its public address is dropped (nothing public passed), it
    /// is told once that the session can only fail, instead of ICE running
    /// out its 15 s clock first. A host name, or a public candidate that
    /// passed, says nothing of the kind.
    #[tokio::test]
    async fn a_controller_on_no_mesh_node_is_told_at_once() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let tenant = ObjectId::new();
        let _ = hub.register_agent(
            agent_id,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        let zones = Arc::new(vec![ZoneRouteInfo {
            id: "cn".into(),
            auto_countries: vec!["CN".into()],
            is_default: false,
            router_only: true,
        }]);
        assert!(hub.set_agent_zone_ice_policy(
            agent_id,
            AgentZoneIcePolicy {
                policy_revision: 1,
                strict: true,
                allowed_countries: ["CN".to_string()].into_iter().collect(),
                zone: Some("cn".into()),
                zones,
            },
        ));
        let (ctl_tx, mut ctl_rx) = mpsc::channel(16);
        let sid = hub
            .create_session_full(
                agent_id,
                tenant,
                "op".into(),
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
                false,
                None,
                None,
                false,
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            hub.session_zone(sid).0,
            ZoneRoute::Direct {
                mesh_fallback: false
            }
        );
        grant_and_await_ready(&hub, sid, &mut ctl_rx).await;
        let cand = |c: &str| serde_json::json!({ "candidate": c, "sdpMid": "0" });
        let advisories = |rx: &mut mpsc::Receiver<ServerMsg>| {
            let mut n = 0;
            while let Ok(m) = rx.try_recv() {
                if let ServerMsg::Error {
                    code, session_id, ..
                } = m
                {
                    assert_eq!(session_id, Some(sid));
                    assert_eq!(code, ZONE_REQUIRES_MESH_CONTROLLER);
                    n += 1;
                }
            }
            n
        };
        // An mDNS host name passes and decides nothing.
        assert!(hub.zone_admits_trickle(
            agent_id,
            sid,
            Role::Controller,
            &cand("candidate:1 1 udp 2122260223 4a2f.local 50000 typ host")
        ));
        assert_eq!(advisories(&mut ctl_rx), 0);
        // Its public address (no GeoIP here: nowhere, so dropped) tells it, once.
        let srflx =
            cand("candidate:2 1 udp 1686052607 203.0.113.7 50000 typ srflx raddr 0.0.0.0 rport 0");
        assert!(!hub.zone_admits_trickle(agent_id, sid, Role::Controller, &srflx));
        assert!(!hub.zone_admits_trickle(agent_id, sid, Role::Controller, &srflx));
        assert_eq!(advisories(&mut ctl_rx), 1);

        // A public candidate that passed first: no advisory.
        let (ctl_tx2, mut ctl_rx2) = mpsc::channel(16);
        let sid2 = hub
            .create_session_full(
                agent_id,
                tenant,
                "op".into(),
                ctl_tx2,
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
                None,
                None,
            )
            .unwrap();
        {
            grant_and_await_ready(&hub, sid2, &mut ctl_rx2).await;
            hub.zone_note_controller_candidate(
                sid2,
                ZoneRoute::Direct {
                    mesh_fallback: false,
                },
                "candidate:3 1 udp 1686052607 198.51.100.9 50000 typ srflx raddr 0.0.0.0 rport 0",
                true,
            );
            assert!(!hub.zone_admits_trickle(agent_id, sid2, Role::Controller, &srflx));
            let mut n = 0;
            while let Ok(m) = ctl_rx2.try_recv() {
                if matches!(m, ServerMsg::Error { .. }) {
                    n += 1;
                }
            }
            assert_eq!(
                n, 0,
                "something public passed: the session may still connect"
            );
        }
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
                    agent_id: None,
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

    // Test-only pause inside the actual DashMap conditional-removal closure.
    // A fresh ObjectId scopes the hook to this test's own registry entry.
    type RemovePause = (
        ObjectId,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    );
    fn remove_pause() -> &'static std::sync::Mutex<Option<RemovePause>> {
        static PAUSE: std::sync::OnceLock<std::sync::Mutex<Option<RemovePause>>> =
            std::sync::OnceLock::new();
        PAUSE.get_or_init(|| std::sync::Mutex::new(None))
    }
    pub(super) fn pause_agent_remove_if_armed(agent: ObjectId) {
        let pause = {
            let mut slot = remove_pause().lock().unwrap();
            if slot.as_ref().is_some_and(|entry| entry.0 == agent) {
                slot.take()
            } else {
                None
            }
        };
        if let Some((_, reached, resume)) = pause {
            reached.send(()).unwrap();
            resume
                .recv_timeout(Duration::from_secs(5))
                .expect("test must resume conditional remove");
        }
    }

    // Draft: requires the normal fleet test fixture. Never run in this task.
    #[tokio::test]
    async fn unregister_compare_and_remove_blocks_replacement_in_the_same_shard() {
        use std::{sync::mpsc, thread};
        let hub = test_hub().await;
        let (agent, tenant, owner) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let (old, _cancel, _rx) =
            hub.register_agent(agent, tenant, owner, OsKind::Linux, 3, false, false);
        let (reached_tx, reached_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        *remove_pause().lock().unwrap() = Some((agent, reached_tx, resume_rx));
        let old_hub = hub.clone();
        let old_thread = thread::spawn(move || old_hub.unregister_agent(agent, Some(&old)));
        reached_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("remove predicate reached");
        // Unlike a fixed sleep, this directly observes that the predicate is
        // inside the map's write lock, before the removal has completed.
        assert!(matches!(
            hub.inner.agents.try_get_mut(&agent),
            dashmap::try_result::TryResult::Locked
        ));
        let (started_tx, started_rx) = mpsc::channel();
        let new_hub = hub.clone();
        let new_thread = thread::spawn(move || {
            started_tx.send(()).unwrap();
            new_hub.register_agent(agent, tenant, owner, OsKind::Linux, 3, false, false)
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("replacement thread started");
        resume_tx.send(()).unwrap();
        assert!(old_thread.join().unwrap());
        let (new, _cancel, _rx) = new_thread.join().unwrap();
        let current = hub.agent_tx(agent).expect("replacement remains registered");
        assert!(ptr_eq(&current, &new));
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
        let (tx2, _cancel2, _rx2) = hub.register_agent(
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
        assert!(!hub.unregister_agent(agent_id, Some(&tx1)));
        assert!(ptr_eq(&hub.agent_tx(agent_id).unwrap(), &tx2));
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

        assert!(hub.unregister_agent(agent_id, None));
        assert!(!hub.unregister_agent(agent_id, None));
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

        assert!(hub.unregister_agent(agent_id, Some(&tx)));
        assert!(!hub.unregister_agent(agent_id, Some(&tx)));
        assert!(
            !hub.is_agent_online(agent_id),
            "matching-tx unregister must remove the entry"
        );
    }

    #[tokio::test]
    async fn unregister_agent_accepts_same_channel_after_receiver_closed() {
        let hub = test_hub().await;
        let agent_id = ObjectId::new();
        let (tx, _cancel, rx) = hub.register_agent(
            agent_id,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        drop(rx);
        assert!(hub.unregister_agent(agent_id, Some(&tx)));
        assert!(!hub.unregister_agent(agent_id, Some(&tx)));
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

    // ─── Fleet RPC broker ────────────────────────────────────────────

    fn exec_msg(request_id: &str) -> ServerMsg {
        ServerMsg::RpcExec {
            two_factor_code: None,
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

    #[test]
    fn file_child_disable_switch_treats_on_yes_and_non_false_values_as_disabled() {
        use meshharbor_remote_control::signaling::parse_file_child_disable_switch;
        for val in ["1", "true", "TRUE", "on", "ON", "yes", "YES", "disabled"] {
            assert!(
                parse_file_child_disable_switch(val),
                "server/agent shared parser must treat {val:?} as disabled"
            );
        }
        for val in ["", "  ", "0", "false", "FALSE", "no", "NO", "off", "OFF"] {
            assert!(
                !parse_file_child_disable_switch(val),
                "server/agent shared parser must treat {val:?} as not disabled"
            );
        }
    }
}

/// MeshHarbor #21 relay locality — the hub's ICE gate.
#[cfg(test)]
mod ice_zone_gate_tests {
    use super::*;
    use meshharbor_remote_control::audit::AuditSink;

    fn turn() -> TurnConfig {
        TurnConfig {
            urls: vec![
                "turn:cn-turn.example:3478?transport=udp".into(),
                "turn:us-turn.example:3478?transport=udp".into(),
            ],
            workers: vec![],
            shared_secret: "s".into(),
            ttl_secs: 600,
        }
    }

    fn zones() -> Arc<IceServerZones> {
        let z = Arc::new(IceServerZones::default());
        z.set("cn-turn.example", Some(BusinessZone::Mainland));
        z.set("us-turn.example", Some(BusinessZone::NonMainland));
        z.set("stun.cloudflare.com", Some(BusinessZone::NonMainland));
        z.set("stun.l.google.com", Some(BusinessZone::NonMainland));
        z
    }

    fn urls(v: Vec<IceServer>) -> Vec<String> {
        v.into_iter().flat_map(|s| s.urls).collect()
    }

    #[tokio::test]
    async fn rc_ice_is_kept_to_the_devices_zone_and_a_zoneless_device_gets_none() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, Some(turn()));
        let ice = || ice_servers_for_session("u", "s", Some(&turn()));
        let (agent, session) = (ObjectId::new(), ObjectId::new());

        // No gate (isolation off, or a test hub): handed out unchanged.
        assert_eq!(urls(hub.zone_local_ice(agent, session, ice())), urls(ice()));

        hub.set_ice_gate(IceGate::new(zones(), IceGateMode::Enforce));
        // A device with no zone on record gets no ICE server at all.
        assert!(hub.zone_local_ice(agent, session, ice()).is_empty());

        // A mainland device keeps only the mainland TURN; every STUN server
        // here is outside the line, so none survives.
        hub.set_agent_business_zone(agent, "c1", Some(BusinessZone::Mainland));
        assert_eq!(
            urls(hub.zone_local_ice(agent, session, ice())),
            vec!["turn:cn-turn.example:3478?transport=udp".to_string()]
        );

        // A displaced connection's teardown never clears its replacement.
        hub.clear_agent_business_zone(agent, "c0");
        assert_eq!(hub.agent_business_zone(agent), Some(BusinessZone::Mainland));
        hub.clear_agent_business_zone(agent, "c1");
        assert_eq!(hub.agent_business_zone(agent), None);
    }

    /// FR-121 — a session's ICE (the device's and the viewer's) leads with
    /// the STUN servers the operator pinned to the device's zone, kept even
    /// when the zone filter strips everything else; another zone's servers
    /// never come along, and a device with no resolved zone gets none.
    #[tokio::test]
    async fn a_session_gets_its_zones_own_stun_servers() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, Some(turn()));
        hub.set_zone_stun(meshharbor_remote_control::turn_creds::parse_zone_stun_urls(
            "cn=stun:192.0.2.10:3478, non-cn=stun:198.51.100.10:3478, stun:203.0.113.10:3478",
        ));
        let ice = || ice_servers_for_session("u", "s", Some(&turn()));
        let (agent, session) = (ObjectId::new(), ObjectId::new());
        // No zone on record (handled as strict): no zone's STUN is added.
        assert!(
            !urls(hub.viewer_zone_ice(agent, ice()))
                .iter()
                .any(|u| u.contains("192.0.2.10"))
        );
        let policy = |strict: bool| AgentZoneIcePolicy {
            // A newer revision: an equal one may never relax strictness.
            policy_revision: if strict { 1 } else { 2 },
            strict,
            allowed_countries: ["CN".to_string()].into_iter().collect(),
            zone: Some("cn".into()),
            ..Default::default()
        };
        // A strict zone whose filter keeps nothing still gets its STUN.
        hub.set_agent_zone_ice_policy(agent, policy(true));
        for got in [
            hub.viewer_zone_ice(agent, ice()),
            hub.zone_local_ice(agent, session, ice()),
        ] {
            let got = urls(got);
            assert_eq!(
                got.first().map(String::as_str),
                Some("stun:192.0.2.10:3478"),
                "{got:?}"
            );
            assert!(
                !got.iter()
                    .any(|u| u.contains("198.51.100.10") || u.contains("203.0.113.10")),
                "{got:?}"
            );
        }
        // A zone that is not strict keeps its servers and leads with the STUN.
        hub.set_agent_zone_ice_policy(agent, policy(false));
        let got = urls(hub.viewer_zone_ice(agent, ice()));
        assert_eq!(got[0], "stun:192.0.2.10:3478");
        assert_eq!(&got[1..], &urls(ice())[..]);
    }

    #[tokio::test]
    async fn warn_mode_hands_everything_out() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, Some(turn()));
        hub.set_ice_gate(IceGate::new(zones(), IceGateMode::Warn));
        let ice = ice_servers_for_session("u", "s", Some(&turn()));
        let (agent, session) = (ObjectId::new(), ObjectId::new());
        hub.set_agent_business_zone(agent, "c1", Some(BusinessZone::Mainland));
        // Withholding would apply (both STUN URLs and the US TURN), but `warn`
        // changes nothing, every time.
        for _ in 0..3 {
            assert_eq!(
                urls(hub.zone_local_ice(agent, session, ice.clone())),
                urls(ice.clone())
            );
        }
        // The verdict was recorded once for this device (then suppressed).
        let gate = hub.ice_gate().unwrap();
        assert!(!gate.dedupe.first_in(
            &agent.to_hex(),
            "zone=Some(Mainland) kept=1 withheld=3 reason=outside_device_zone",
            meshharbor_core::ice_zones::WARN_DEDUPE
        ));
    }

    /// `off` installs no gate at all (`ice_zones::gate_mode` is `None`), and a
    /// hub with no gate hands out exactly what it did before #21.
    #[tokio::test]
    async fn off_installs_no_gate_and_changes_nothing() {
        assert!(meshharbor_core::ice_zones::gate_mode("off").is_none());
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, Some(turn()));
        assert!(hub.ice_gate().is_none());
        let ice = ice_servers_for_session("u", "s", Some(&turn()));
        let agent = ObjectId::new();
        hub.set_agent_business_zone(agent, "c1", Some(BusinessZone::Mainland));
        assert_eq!(
            urls(hub.zone_local_ice(agent, ObjectId::new(), ice.clone())),
            urls(ice)
        );
    }

    /// FR-121 — a session follows the zones the way the mesh does: no zones,
    /// nothing changes; a controller on a mesh node in the same zone meets the
    /// device directly with a mesh fallback, one in another gateway-only zone
    /// only over the mesh; a controller on no mesh node is checked address by
    /// address, and with no GeoIP a public address is nowhere, so refused.
    #[tokio::test]
    async fn a_session_follows_the_zone_routes() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let tenant = ObjectId::new();
        let (host, same, other, bare) = (
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        );
        for a in [host, same, other] {
            let _ = hub.register_agent(a, tenant, ObjectId::new(), OsKind::Linux, 3, false, false);
        }
        let zones = Arc::new(vec![
            ZoneRouteInfo {
                id: "cn".into(),
                auto_countries: vec!["CN".into()],
                is_default: false,
                router_only: true,
            },
            ZoneRouteInfo {
                id: "rest".into(),
                auto_countries: vec![],
                is_default: true,
                router_only: true,
            },
        ]);
        let pol = |zone: &str| AgentZoneIcePolicy {
            policy_revision: 1,
            strict: true,
            allowed_countries: ["CN".to_string()].into_iter().collect(),
            zone: Some(zone.into()),
            zones: zones.clone(),
        };
        assert!(hub.set_agent_zone_ice_policy(host, pol("cn")));
        assert!(hub.set_agent_zone_ice_policy(same, pol("cn")));
        assert!(hub.set_agent_zone_ice_policy(other, pol("rest")));

        assert_eq!(
            hub.zone_route_for(bare, None),
            ZoneRoute::Open,
            "no policy, no zones"
        );
        // A snapshot the server could not read is strict with no zone table:
        // unresolved, so nothing meets it directly by an address.
        let unread = ObjectId::new();
        let _ = hub.register_agent(
            unread,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            3,
            false,
            false,
        );
        assert!(hub.set_agent_zone_ice_policy(
            unread,
            AgentZoneIcePolicy {
                policy_revision: 0,
                strict: true,
                ..Default::default()
            },
        ));
        assert_eq!(
            hub.zone_route_for(unread, None),
            ZoneRoute::Direct {
                mesh_fallback: false
            }
        );
        assert_eq!(
            hub.zone_route_for(host, Some(same)),
            ZoneRoute::Direct {
                mesh_fallback: true
            }
        );
        assert_eq!(hub.zone_route_for(host, Some(other)), ZoneRoute::Mesh);
        assert_eq!(
            hub.zone_route_for(host, None),
            ZoneRoute::Direct {
                mesh_fallback: false
            }
        );
        assert_eq!(
            hub.zone_route_for(host, Some(ObjectId::new())),
            ZoneRoute::Direct {
                mesh_fallback: false
            },
            "a local agent this hub does not know places nobody"
        );

        let mesh_ip: Option<std::net::IpAddr> = Some("100.64.7.20".parse().unwrap());
        let relay =
            "candidate:7 1 udp 16777215 100.64.7.20 40001 typ relay raddr 127.0.0.1 rport 1";
        let stray_relay =
            "candidate:8 1 udp 16777215 100.64.7.99 40002 typ relay raddr 127.0.0.1 rport 1";
        let public =
            "candidate:4 1 udp 1686052607 198.51.100.7 54323 typ srflx raddr 10.0.0.2 rport 1";
        let lan = "candidate:3 1 udp 2122260223 192.168.1.30 54322 typ host";
        let mdns = "candidate:5 1 udp 2122260223 4a5b6c7d-0000-1111-2222-333344445555.local 54324 typ host";
        let open = ZoneRoute::Open;
        let direct = ZoneRoute::Direct {
            mesh_fallback: true,
        };
        let bare_direct = ZoneRoute::Direct {
            mesh_fallback: false,
        };
        assert!(hub.zone_admits_candidate(host, open, None, public));
        // Mesh: the controller's own mesh relay and nothing else.
        assert!(hub.zone_admits_candidate(host, ZoneRoute::Mesh, mesh_ip, relay));
        for c in [stray_relay, public, lan, mdns] {
            assert!(
                !hub.zone_admits_candidate(host, ZoneRoute::Mesh, mesh_ip, c),
                "{c}"
            );
        }
        // Direct: LAN, names and (with the fallback) the mesh relay pass; a
        // public address with no GeoIP is in no zone.
        for c in [lan, mdns, relay] {
            assert!(hub.zone_admits_candidate(host, direct, mesh_ip, c), "{c}");
        }
        assert!(hub.zone_admits_candidate(host, bare_direct, None, lan));
        assert!(!hub.zone_admits_candidate(host, direct, mesh_ip, public));
        // The device's side on Mesh: its relay inside the mesh only.
        let agent_relay =
            "candidate:9 1 udp 16777215 100.64.7.14 40003 typ relay raddr 127.0.0.1 rport 1";
        assert!(Hub::zone_admits_agent_candidate(
            ZoneRoute::Mesh,
            agent_relay
        ));
        assert!(!Hub::zone_admits_agent_candidate(ZoneRoute::Mesh, public));
        assert!(!Hub::zone_admits_agent_candidate(ZoneRoute::Mesh, lan));
        assert!(Hub::zone_admits_agent_candidate(direct, public));

        assert_eq!(candidate_type(public), Some("srflx"));
        assert_eq!(
            candidate_text(&serde_json::json!({ "candidate": public, "sdpMid": "0" })),
            Some(public)
        );
        assert_eq!(
            candidate_text(&serde_json::json!({ "candidate": "" })),
            None
        );
    }

    /// FR-121 — the zones a device is placed in by address: a country's zone,
    /// else the default; and the mesh's pair rule over them.
    #[test]
    fn addresses_are_placed_and_paired_like_devices() {
        let zones = vec![
            ZoneRouteInfo {
                id: "cn".into(),
                auto_countries: vec!["CN".into()],
                is_default: false,
                router_only: true,
            },
            ZoneRouteInfo {
                id: "rest".into(),
                is_default: true,
                ..Default::default()
            },
        ];
        let cn = ZoneRes::of_country(&zones, Some("cn"));
        let de = ZoneRes::of_country(&zones, Some("DE"));
        assert!(matches!(cn, ZoneRes::Resolved(z) if z.id == "cn"));
        assert!(matches!(de, ZoneRes::Resolved(z) if z.id == "rest"));
        assert!(!zones_need_gateways(cn, cn), "same zone meets directly");
        assert!(zones_need_gateways(cn, de), "either side gateway-only");
        assert!(!zones_need_gateways(de, de));
        assert!(zones_need_gateways(ZoneRes::Unresolved, de));
        assert_eq!(ZoneRes::of_country(&[], Some("CN")), ZoneRes::Unconfigured);
        assert!(!zones_need_gateways(
            ZoneRes::Unconfigured,
            ZoneRes::Unconfigured
        ));
    }

    #[tokio::test]
    async fn zone_ice_policy_rejects_stale_and_combines_equal_revisions_conservatively() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let agent = ObjectId::new();
        let set = |items: &[&str]| -> std::collections::HashSet<String> {
            items.iter().map(|s| (*s).to_string()).collect()
        };

        // 1. Permissive rev=3 followed by strict rev=3 tightens conservatively.
        assert!(hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 3,
                strict: false,
                allowed_countries: set(&["US", "HK"]),
                ..Default::default()
            },
        ));
        assert!(hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 3,
                strict: true,
                allowed_countries: set(&["CN", "HK"]),
                ..Default::default()
            },
        ));
        assert_eq!(
            hub.agent_zone_ice_policy(agent),
            Some(AgentZoneIcePolicy {
                policy_revision: 3,
                strict: true,
                allowed_countries: set(&["CN", "HK"]),
                ..Default::default()
            })
        );

        // 2. Equal-revision permissive update can NEVER relax strictness or countries.
        assert!(!hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 3,
                strict: false,
                allowed_countries: set(&[]),
                ..Default::default()
            },
        ));
        assert_eq!(
            hub.agent_zone_ice_policy(agent).unwrap().allowed_countries,
            set(&["CN", "HK"])
        );
        assert!(hub.agent_zone_ice_policy(agent).unwrap().strict);

        // 3. Equal-revision strict update intersects allowed_countries.
        assert!(hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 3,
                strict: true,
                allowed_countries: set(&["CN", "JP"]),
                ..Default::default()
            },
        ));
        assert_eq!(
            hub.agent_zone_ice_policy(agent),
            Some(AgentZoneIcePolicy {
                policy_revision: 3,
                strict: true,
                allowed_countries: set(&["CN"]),
                ..Default::default()
            })
        );

        // 4. Stale revision (< 3) is rejected outright; newer revision (> 3) replaces.
        assert!(!hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 2,
                strict: false,
                allowed_countries: set(&["US"]),
                ..Default::default()
            },
        ));
        assert!(hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 4,
                strict: false,
                allowed_countries: set(&["US"]),
                ..Default::default()
            },
        ));
        assert_eq!(
            hub.agent_zone_ice_policy(agent),
            Some(AgentZoneIcePolicy {
                policy_revision: 4,
                strict: false,
                allowed_countries: set(&["US"]),
                ..Default::default()
            })
        );
    }

    #[test]
    fn management_entry_device_counts_tracks_live_connections_per_tenant_and_drops_on_disconnect() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let tenant_a = ObjectId::new();
        let tenant_b = ObjectId::new();
        let owner = ObjectId::new();
        let gw_1 = ObjectId::new();
        let gw_2 = ObjectId::new();
        let dev_1 = ObjectId::new();
        let dev_2 = ObjectId::new();
        let dev_direct = ObjectId::new();
        let dev_other_tenant = ObjectId::new();

        // Gateway listening port is live-only and drops on unregister.
        let (gw_tx, _, _) =
            hub.register_agent(gw_1, tenant_a, owner, OsKind::Linux, 1, false, false);
        assert_eq!(hub.agent_management_entry_port(gw_1), None);
        assert!(hub.set_agent_management_entry_port(gw_1, Some(18443)));
        assert_eq!(hub.agent_management_entry_port(gw_1), Some(18443));

        let (tx1, _, _) =
            hub.register_agent(dev_1, tenant_a, owner, OsKind::Linux, 1, false, false);
        let (tx2, _, _) =
            hub.register_agent(dev_2, tenant_a, owner, OsKind::Macos, 1, false, false);
        let (_txd, _, _) = hub.register_agent(
            dev_direct,
            tenant_a,
            owner,
            OsKind::Windows,
            1,
            false,
            false,
        );
        let (_txo, _, _) = hub.register_agent(
            dev_other_tenant,
            tenant_b,
            owner,
            OsKind::Linux,
            1,
            false,
            false,
        );

        hub.set_agent_via_management_entry(dev_1, Some(gw_1));
        hub.set_agent_via_management_entry(dev_2, Some(gw_1));
        hub.set_agent_via_management_entry(dev_direct, None);
        hub.set_agent_via_management_entry(dev_other_tenant, Some(gw_1));

        let counts_a = hub.management_entry_device_counts(tenant_a);
        assert_eq!(counts_a.get(&gw_1).copied(), Some(2));
        assert_eq!(counts_a.get(&gw_2).copied(), None);
        let counts_b = hub.management_entry_device_counts(tenant_b);
        assert_eq!(counts_b.get(&gw_1).copied(), Some(1));

        // Displacing dev_2 with a new connection resets its via_management_entry until re-set.
        let (tx2_new, _, _) =
            hub.register_agent(dev_2, tenant_a, owner, OsKind::Macos, 1, false, false);
        assert_eq!(
            hub.management_entry_device_counts(tenant_a)
                .get(&gw_1)
                .copied(),
            Some(1)
        );
        // Late unregister from the displaced socket must not affect the newer registration.
        hub.set_agent_via_management_entry(dev_2, Some(gw_2));
        hub.unregister_agent(dev_2, Some(&tx2));
        let counts_after_move = hub.management_entry_device_counts(tenant_a);
        assert_eq!(counts_after_move.get(&gw_1).copied(), Some(1));
        assert_eq!(counts_after_move.get(&gw_2).copied(), Some(1));

        // Unregistering live sockets drops counts and live gateway port.
        hub.unregister_agent(dev_1, Some(&tx1));
        hub.unregister_agent(dev_2, Some(&tx2_new));
        hub.unregister_agent(gw_1, Some(&gw_tx));
        assert!(hub.management_entry_device_counts(tenant_a).is_empty());
        assert_eq!(hub.agent_management_entry_port(gw_1), None);
    }

    #[tokio::test]
    async fn silent_admin_monitor_gate_takeover_and_auto_teardown() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let tenant = ObjectId::new();
        let owner = ObjectId::new();
        let controller = ObjectId::new();
        let admin = ObjectId::new();
        let other_admin = ObjectId::new();
        let agent = ObjectId::new();
        let (_agent_tx, _cancel, mut agent_rx) =
            hub.register_agent(agent, tenant, owner, OsKind::Linux, 1, true, false);
        let (ctrl_tx, _ctrl_rx) = mpsc::channel(32);
        let (admin_tx, mut admin_rx) = mpsc::channel(32);
        let full_perms =
            Permissions::VIEW | Permissions::INPUT | Permissions::CLIPBOARD | Permissions::FILES;

        // Open a regular RC session (fills agent.max_sessions == 1).
        let reg_id = hub
            .create_session_full_scoped(
                agent,
                controller,
                "Alice".into(),
                ctrl_tx.clone(),
                Permissions::VIEW | Permissions::INPUT,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Auto,
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
                None,
                None,
                None,
                None,
                SessionCreationOrigin::Unknown,
                None,
                None,
                None,
                false,
                None,
            )
            .expect("regular session");
        let _ = agent_rx.try_recv();

        // Gate 1: legacy agent without `silent-monitor` capability is refused.
        assert!(
            hub.create_session_full_scoped(
                agent,
                admin,
                "Admin".into(),
                admin_tx.clone(),
                full_perms,
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
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                SessionCreationOrigin::Unknown,
                None,
                None,
                None,
                true,
                Some(reg_id),
            )
            .is_err(),
            "legacy agent without silent-monitor capability must refuse"
        );
        hub.set_agent_silent_monitor(agent, true);

        // Gate 2: a pre-consent (Pending/AwaitingConsent) session MUST NOT admit a silent monitor!
        assert!(
            hub.create_session_full_scoped(
                agent,
                admin,
                "Admin".into(),
                admin_tx.clone(),
                full_perms,
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
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                SessionCreationOrigin::Unknown,
                None,
                None,
                None,
                true,
                Some(reg_id),
            )
            .is_err(),
            "silent monitor must require an Active regular session"
        );

        // Transition regular session to Active (post-consent, live media).
        hub.with_session(reg_id, |s| {
            s.phase = SessionPhase::Active;
            Ok(())
        })
        .unwrap();

        // Silent monitor attaches bound to `reg_id` even though max_sessions == 1.
        let mon_id = hub
            .create_session_full_scoped(
                agent,
                admin,
                "Admin".into(),
                admin_tx.clone(),
                full_perms,
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
                OrgPolicy::Read(SessionPolicy::default()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                SessionCreationOrigin::Unknown,
                None,
                None,
                None,
                true,
                Some(reg_id),
            )
            .expect("silent monitor attaches");
        // Verify Request sent to agent carried silent_monitor: true and clamped perms.
        let req = agent_rx.try_recv().expect("agent request");
        match req {
            ServerMsg::Request {
                silent_monitor,
                permissions,
                ..
            } => {
                assert!(silent_monitor);
                assert_eq!(permissions, Permissions::VIEW | Permissions::INPUT);
            }
            other => panic!("unexpected agent msg: {other:?}"),
        }

        // Transition monitor to Active before takeover.
        hub.with_session(mon_id, |s| {
            s.phase = SessionPhase::Active;
            Ok(())
        })
        .unwrap();

        // live_rc_sessions lists ONLY the regular session, annotated with admin_watching.
        let live = hub.live_rc_sessions(tenant);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].session_id, reg_id);
        assert!(live[0].admin_watching);
        assert_eq!(live[0].admin_watcher_count, 1);
        assert!(!live[0].admin_taken_over);

        // Takeover rejects a different user, accepts the watching admin, and pushes ServerMsg::AdminTakeover.
        assert!(hub.set_silent_monitor_takeover(tenant, mon_id, other_admin, true).is_err());
        assert_eq!(
            hub.set_silent_monitor_takeover(tenant, mon_id, admin, true).unwrap(),
            agent
        );
        match agent_rx.try_recv().expect("agent receives AdminTakeover") {
            ServerMsg::AdminTakeover { session_id, active } => {
                assert_eq!(session_id, mon_id);
                assert!(active);
            }
            other => panic!("expected AdminTakeover, got {other:?}"),
        }
        let live = hub.live_rc_sessions(tenant);
        assert!(live[0].admin_taken_over);

        // A second silent monitor (VIEW-only) does NOT escalate to INPUT and cannot steal takeover.
        let (admin2_tx, _admin2_rx) = mpsc::channel(32);
        let mon2_id = hub
            .create_session_full_scoped(
                agent,
                other_admin,
                "Admin2".into(),
                admin2_tx,
                Permissions::VIEW,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Auto,
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
                None,
                None,
                None,
                None,
                SessionCreationOrigin::Unknown,
                None,
                None,
                None,
                true,
                Some(reg_id),
            )
            .expect("second view-only monitor attaches");
        match agent_rx.try_recv().expect("second monitor request") {
            ServerMsg::Request { permissions, .. } => {
                assert_eq!(permissions, Permissions::VIEW, "VIEW-only monitor must never escalate to INPUT");
            }
            other => panic!("unexpected msg: {other:?}"),
        }
        hub.with_session(mon2_id, |s| {
            s.phase = SessionPhase::Active;
            Ok(())
        })
        .unwrap();
        assert!(hub.set_silent_monitor_takeover(tenant, mon2_id, other_admin, true).is_err());

        // Terminating the regular session auto-closes bound silent monitors too.
        hub.terminate(reg_id, EndReason::ControllerHangup)
            .expect("end regular");
        assert!(hub.live_rc_sessions(tenant).is_empty());
        assert!(hub.session_snapshot(mon_id).is_none());
        assert!(hub.session_snapshot(mon2_id).is_none());
        let mut saw_target_ended = false;
        while let Ok(msg) = admin_rx.try_recv() {
            if matches!(
                msg,
                ServerMsg::Terminate { session_id, limit: Some(ref l), .. }
                    if session_id == mon_id && l == "target_session_ended"
            ) {
                saw_target_ended = true;
            }
        }
        assert!(saw_target_ended, "silent monitor must receive target_session_ended");
    }

    #[tokio::test]
    async fn live_ssh_registry_tracks_lifecycle_and_universal_revoke() {
        let (audit, _ev) = AuditSink::channel_for_tests();
        let hub = Hub::new(audit, None);
        let tenant = ObjectId::new();
        let owner = ObjectId::new();
        let agent = ObjectId::new();
        // supports_ssh_resume defaults to false; push_ssh_revoke_agent MUST still deliver!
        let (_tx, _cancel, mut rx) =
            hub.register_agent(agent, tenant, owner, OsKind::Linux, 1, false, false);

        let now = bson::DateTime::now();
        let exp = (now.timestamp_millis().max(0) as u64) + 60_000;
        hub.note_ssh_grant_issued(LiveSshSessionInfo {
            key: "grant-abc".into(),
            tenant_id: tenant,
            agent_id: agent,
            user_id: Some(owner),
            origin_agent_id: None,
            grant_id: Some("grant-abc".into()),
            shared_session_id: None,
            share_grant_id: None,
            source: "cli".into(),
            caller: "Alice".into(),
            account_mode: Some("console_user".into()),
            ran_as: Some("worker".into()),
            resume_allowed: false,
            phase: "granted",
            started_at: now,
            last_activity_at: now,
            expires_at_ms: Some(exp),
            session_secs: Some(3600),
            activity_count: 0,
        });
        assert_eq!(hub.live_ssh_sessions(tenant).len(), 1);
        assert_eq!(hub.live_ssh_sessions(tenant)[0].phase, "granted");

        hub.note_ssh_activity(
            tenant,
            agent,
            Some("grant-abc"),
            "ssh:Alice@100.64.0.1",
            meshharbor_remote_control::models::SshActivityKind::SessionOpen,
        );
        assert_eq!(hub.live_ssh_sessions(tenant)[0].phase, "active");

        assert!(hub.push_ssh_revoke_agent(
            tenant,
            agent,
            "session",
            None,
            Some("grant-abc".into()),
            Some("admin_disconnect".into()),
        ));
        assert!(hub.live_ssh_sessions(tenant).is_empty());
        match rx.try_recv().expect("agent receives SshRevoke") {
            ServerMsg::SshRevoke { scope, sid, .. } => {
                assert_eq!(scope, "session");
                assert_eq!(sid.as_deref(), Some("grant-abc"));
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}
