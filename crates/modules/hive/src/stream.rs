// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2d-1 — the replica stream's grants, the server's half (spec §3b,
//! "The carrier"). A member asks for a stream of a session it holds a copy
//! of, on one rung of the ladder. The server checks the ask, mints a grant
//! and pushes it to the source, and tells the member to dial only once the
//! source said it is ready (FR-83). Then the two devices speak QUIC between
//! themselves, directly or through a relay that sees ciphertext only, and the
//! server is out of the byte path.
//!
//! | Frame | From → to | What the server does |
//! |---|---|---|
//! | `rc:hive.replica.want` | member → server | checks the member, the fence, the rung, the rate and the source; mints a grant |
//! | `rc:hive.replica.grant` | server → source | the token, the credentials, the member's key on `derp` |
//! | `rc:hive.replica.ready` | source → server | ready: the member is sent `dial`; refused: the member is sent `refused`, with the source's word |
//! | `rc:hive.replica.candidate` | member → server → source | relayed for a confirmed `relay` grant only |
//! | `rc:hive.replica.close` | either side | the grant is forgotten, and the other side told |
//!
//! The source is the session's primary in P2d. A fresher member serving
//! when the primary is away comes with promotion (P2e).
//!
//! ⚠️ A grant is pod-local, like a view grant: both devices' sockets must be
//! on the pod that mints it. Tenant affinity puts an org's devices on one
//! pod. While a roll moves them, a want is refused `source_offline`, and the
//! member asks again.
//! ⚠️ A frame is read only from a connection advertising `hive-stream`, and
//! everything in it is a claim checked against the record: a device that is
//! not a joined member is refused as one that asked about a session it
//! cannot see, and a frame naming someone else's grant moves nothing.
//! ⚠️ With the replicaset's switch off, no stream frame is answered or sent.

use std::net::SocketAddr;
use std::time::Duration;

use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_remote_control::hive::{
    HiveStreamPath, HiveStreamRefusal, hive_limits, is_dialable, is_hash_hex, is_pubkey_hex,
    stream_limits,
};
use meshharbor_remote_control::signaling::{ClientMsg, IceServer, ServerMsg};
use meshharbor_remote_control::turn_creds::ice_servers_for_session_with_ttl;
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::agent_socket::clamp_words;
use crate::model::{AgentSession, MemberState};
use crate::placement::MemberRole;
use crate::routes::Audit;

/// The TURN credential's life. It bounds the allocation's whole life, and a
/// stream outlives its grant until the renewal that replaces it carries.
const TURN_TTL_SECS: u32 = 2 * stream_limits::GRANT_TTL_SECS;
/// The longest `reason` a close carries on.
const MAX_REASON_CHARS: usize = 64;
/// Past a grant's life before the server forgets it: the devices keep it
/// to its `ttl_secs` on their own clocks, from receipt.
const EXPIRY_SLACK_SECS: u64 = 30;

struct Grant {
    tenant_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    path: HiveStreamPath,
    member_id: ObjectId,
    source_id: ObjectId,
    token: String,
    /// The member's credentials, minted with the source's for one TURN
    /// worker: the grant is the session key both share.
    member_ice: Vec<IceServer>,
    /// The source confirmed it: the member was told to dial.
    ready: bool,
}

/// The stream grants this pod minted.
pub struct StreamGrants {
    map: DashMap<ObjectId, Grant>,
}

impl Default for StreamGrants {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamGrants {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// An unguessable token, as the tunnel's: both devices receive it over
/// their own authenticated sockets, so it needs no signature, only
/// randomness. Two v4 UUIDs are 244 bits of it.
fn mint_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// An address a device may be told to dial: an IP literal and a port, never
/// a name another resolver could answer differently, and one a device could
/// be reached at ([`is_dialable`]: never the unspecified address, port 0,
/// multicast or broadcast). The device checks it again before it dials or
/// permits: this check is the server's courtesy, the device's the gate.
fn dialable(addr: &str) -> bool {
    addr.len() <= stream_limits::MAX_ADDR_LEN
        && addr.parse::<SocketAddr>().is_ok_and(|a| is_dialable(&a))
}

/// The credentials a device gets for a grant: STUN always, so it can learn
/// its server-reflexive address; TURN on the `relay` rung only.
fn ice_for(
    state: &HiveState,
    device: ObjectId,
    grant_id: ObjectId,
    path: HiveStreamPath,
) -> Vec<IceServer> {
    let turn = match path {
        HiveStreamPath::Relay => state.core.turn_map.cfg_for(None),
        HiveStreamPath::Direct | HiveStreamPath::Derp => None,
    };
    ice_servers_for_session_with_ttl(&device.to_hex(), &grant_id.to_hex(), turn, TURN_TTL_SECS)
}

fn push(state: &HiveState, tenant_id: ObjectId, device: ObjectId, msg: ServerMsg) -> bool {
    match state.fleet.rc_hub.push_hive_stream(device, tenant_id, msg) {
        Ok(()) => true,
        Err(e) => {
            debug!(device = %device, %e, "hive: a stream frame was not sent");
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn refuse(
    state: &HiveState,
    tenant_id: ObjectId,
    member: ObjectId,
    session_id: ObjectId,
    fence: u64,
    path: Option<HiveStreamPath>,
    reason: HiveStreamRefusal,
    detail: Option<String>,
) {
    push(
        state,
        tenant_id,
        member,
        ServerMsg::HiveReplicaRefused {
            session_id,
            fence,
            path,
            reason: Some(reason),
            detail,
        },
    );
}

fn audit(
    s: &AgentSession,
    member: ObjectId,
    outcome: &'static str,
    reason: Option<&'static str>,
) -> Audit {
    Audit {
        tenant_id: s.tenant_id,
        // The copies are the session owner's: the row names them, as a
        // placement's does.
        user_id: s.owner_id,
        target_id: None,
        device_id: member,
        session_id: s.id,
        action: "stream",
        outcome,
        reason,
    }
}

/// Whether `member` holds `s` as a joined member, never its primary.
fn joined_member(s: &AgentSession, member: ObjectId) -> bool {
    s.replicaset.as_ref().is_some_and(|r| {
        r.members.iter().any(|m| {
            m.device_id == member
                && m.role != MemberRole::Primary.as_str()
                && m.state == MemberState::Joined
        })
    })
}

/// A stream frame from a device, read on THIS connection only because it
/// advertises `hive-stream` (`agent_socket`).
pub(crate) async fn on_device_frame(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    msg: ClientMsg,
) {
    if !state.replicaset {
        return debug!(device = %device_id, "hive: a stream frame with the replicaset off — dropped");
    }
    match msg {
        ClientMsg::HiveReplicaWant {
            session_id,
            fence,
            seq,
            hash,
            path,
            derp_pubkey,
        } => {
            on_want(
                state,
                tenant_id,
                device_id,
                session_id,
                fence,
                seq,
                &hash,
                path,
                derp_pubkey,
            )
            .await
        }
        ClientMsg::HiveReplicaReady {
            grant_id,
            refused,
            detail,
            cert_fingerprint,
            addrs,
            derp_pubkey,
        } => {
            on_ready(
                state,
                device_id,
                grant_id,
                refused,
                detail,
                cert_fingerprint,
                addrs,
                derp_pubkey,
            )
            .await
        }
        ClientMsg::HiveReplicaCandidate { grant_id, addr } => {
            on_candidate(state, device_id, grant_id, &addr)
        }
        ClientMsg::HiveReplicaClose { grant_id, reason } => {
            on_close(state, device_id, grant_id, &reason)
        }
        other => debug!(?other, "hive: not a stream frame"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn on_want(
    state: &HiveState,
    tenant_id: ObjectId,
    member: ObjectId,
    session_id: ObjectId,
    fence: u64,
    seq: u64,
    hash: &str,
    path: Option<HiveStreamPath>,
    derp_pubkey: Option<String>,
) {
    if !is_hash_hex(hash) {
        return debug!(device = %member, "hive: a want with a malformed hash — dropped");
    }
    let no = |reason: HiveStreamRefusal| {
        refuse(
            state, tenant_id, member, session_id, fence, path, reason, None,
        )
    };
    // Not there, another org's, not a member's, and purged (P2g-2) answer
    // alike: the answer says nothing about a session the device cannot hold.
    let s = match state.sessions.find(session_id).await {
        Ok(Some(s))
            if s.tenant_id == tenant_id && s.purged.is_none() && joined_member(&s, member) =>
        {
            s
        }
        Ok(_) => return no(HiveStreamRefusal::NotAMember),
        Err(e) => {
            warn!(session = %session_id, %e, "hive: a want could not read its session");
            return no(HiveStreamRefusal::Other);
        }
    };
    let refuse_audited = |reason: HiveStreamRefusal| {
        let row = audit(&s, member, "refused", Some(reason.as_str()));
        no(reason);
        row
    };
    if u64::try_from(s.fence).ok() != Some(fence) {
        return refuse_audited(HiveStreamRefusal::StaleFence)
            .write(state)
            .await;
    }
    let Some(path) = path else {
        return refuse_audited(HiveStreamRefusal::PathUnavailable)
            .write(state)
            .await;
    };
    let member_derp_pubkey = match path {
        HiveStreamPath::Derp => match derp_pubkey.filter(|k| is_pubkey_hex(k)) {
            Some(k) => Some(k),
            None => {
                return refuse_audited(HiveStreamRefusal::PathUnavailable)
                    .write(state)
                    .await;
            }
        },
        HiveStreamPath::Relay if state.core.turn_map.cfg_for(None).is_none() => {
            return refuse_audited(HiveStreamRefusal::PathUnavailable)
                .write(state)
                .await;
        }
        HiveStreamPath::Direct | HiveStreamPath::Relay => None,
    };
    if !state
        .stream_limiter
        .check(member, session_id, stream_limits::WANT_RATE_PER_MINUTE)
    {
        return refuse_audited(HiveStreamRefusal::RateLimited)
            .write(state)
            .await;
    }
    let source = s.location.device_id;
    match state
        .fleet
        .rc_hub
        .agent_supports_hive_stream(source, tenant_id)
    {
        None => {
            return refuse_audited(HiveStreamRefusal::SourceOffline)
                .write(state)
                .await;
        }
        Some(false) => {
            return refuse_audited(HiveStreamRefusal::SourceUnsupported)
                .write(state)
                .await;
        }
        Some(true) => {}
    }
    let serving = state
        .stream_grants
        .map
        .iter()
        .filter(|g| g.source_id == source)
        .count();
    if serving >= stream_limits::MAX_PER_SOURCE {
        return refuse_audited(HiveStreamRefusal::Busy).write(state).await;
    }
    // Make-before-break: the member keeps the grant it follows while the
    // next one comes up; past that, the oldest goes.
    let mine: Vec<ObjectId> = state
        .stream_grants
        .map
        .iter()
        .filter(|g| g.member_id == member && g.session_id == session_id)
        .map(|g| *g.key())
        .collect();
    if let Some(&oldest) = mine
        .iter()
        .min()
        .filter(|_| mine.len() >= stream_limits::MAX_PER_MEMBER_SESSION)
    {
        // ObjectIds sort by when they were minted.
        end_where(state, |g_id, _| g_id == oldest, "replaced");
    }

    let grant_id = ObjectId::new();
    let token = mint_token();
    let member_ice = ice_for(state, member, grant_id, path);
    let source_ice = ice_for(state, source, grant_id, path);
    // The grant BEFORE the push: the source's answer, however fast, must
    // find it.
    state.stream_grants.map.insert(
        grant_id,
        Grant {
            tenant_id,
            session_id,
            fence,
            path,
            member_id: member,
            source_id: source,
            token: token.clone(),
            member_ice,
            ready: false,
        },
    );
    let grant = ServerMsg::HiveReplicaGrant {
        grant_id,
        session_id,
        fence,
        member_id: member,
        path: Some(path),
        token,
        ice_servers: source_ice,
        ttl_secs: stream_limits::GRANT_TTL_SECS,
        member_derp_pubkey,
    };
    if !push(state, tenant_id, source, grant) {
        state.stream_grants.map.remove(&grant_id);
        return refuse_audited(HiveStreamRefusal::SourceOffline)
            .write(state)
            .await;
    }
    audit(&s, member, "sent", None).write(state).await;
    info!(
        grant = %grant_id, session = %session_id, member = %member, source = %source,
        path = path.as_str(), from_seq = seq, "hive: stream granted"
    );

    // A source that never answers: the member is told so, and the source
    // told to drop the grant should its answer arrive after all. Then, past
    // the grant's life, the server forgets it.
    let state = state.clone();
    tokio::spawn(async move {
        let ack = Duration::from_secs(stream_limits::GRANT_ACK_TIMEOUT_SECS);
        tokio::time::sleep(ack).await;
        if let Some((_, g)) = state
            .stream_grants
            .map
            .remove_if(&grant_id, |_, g| !g.ready)
        {
            push(
                &state,
                g.tenant_id,
                g.source_id,
                ServerMsg::HiveReplicaClose {
                    grant_id,
                    reason: "no_answer".into(),
                },
            );
            refuse(
                &state,
                g.tenant_id,
                g.member_id,
                g.session_id,
                g.fence,
                Some(g.path),
                HiveStreamRefusal::NoAnswer,
                Some("the source did not answer in time".into()),
            );
            info!(grant = %grant_id, "hive: a stream grant went unanswered");
            return;
        }
        let life =
            Duration::from_secs(u64::from(stream_limits::GRANT_TTL_SECS) + EXPIRY_SLACK_SECS);
        tokio::time::sleep(life.saturating_sub(ack)).await;
        state.stream_grants.map.remove(&grant_id);
    });
}

#[allow(clippy::too_many_arguments)]
async fn on_ready(
    state: &HiveState,
    source: ObjectId,
    grant_id: ObjectId,
    refused: Option<HiveStreamRefusal>,
    detail: Option<String>,
    cert_fingerprint: Option<String>,
    addrs: Vec<String>,
    derp_pubkey: Option<String>,
) {
    // Only the source's own answer to a grant still waiting for it.
    let Some(path) = state
        .stream_grants
        .map
        .get(&grant_id)
        .filter(|g| g.source_id == source && !g.ready)
        .map(|g| g.path)
    else {
        return debug!(grant = %grant_id, device = %source, "hive: a ready for no grant of this device's");
    };
    let detail = clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
    // What the member is told to dial must be dialable: a fingerprint as one
    // is written, IP literals, a key on the `derp` rung.
    let well_formed = refused.is_none()
        && cert_fingerprint.as_deref().is_some_and(is_hash_hex)
        && addrs.len() <= stream_limits::MAX_ADDRS
        && addrs.iter().all(|a| dialable(a))
        && match path {
            HiveStreamPath::Derp => derp_pubkey.as_deref().is_some_and(is_pubkey_hex),
            HiveStreamPath::Direct | HiveStreamPath::Relay => !addrs.is_empty(),
        };
    let word = match (refused, well_formed) {
        (Some(word), _) => Some(word),
        (None, false) => Some(HiveStreamRefusal::Other),
        (None, true) => None,
    };
    if let Some(word) = word {
        let Some((_, g)) = state.stream_grants.map.remove(&grant_id) else {
            return;
        };
        let detail = detail.or_else(|| {
            refused
                .is_none()
                .then(|| "the source's answer could not be dialed".to_string())
        });
        refuse(
            state,
            g.tenant_id,
            g.member_id,
            g.session_id,
            g.fence,
            Some(g.path),
            word,
            detail,
        );
        if refused.is_none() {
            // Malformed: the source's endpoint is told to go too.
            push(
                state,
                g.tenant_id,
                source,
                ServerMsg::HiveReplicaClose {
                    grant_id,
                    reason: "malformed".into(),
                },
            );
        }
        info!(grant = %grant_id, refused = word.as_str(), "hive: a stream was not served");
        if let Ok(Some(s)) = state.sessions.find(g.session_id).await {
            audit(&s, g.member_id, "refused", Some(word.as_str()))
                .write(state)
                .await;
        }
        return;
    }
    let dial = {
        let Some(mut g) = state.stream_grants.map.get_mut(&grant_id) else {
            return;
        };
        g.ready = true;
        (
            g.tenant_id,
            g.member_id,
            g.session_id,
            ServerMsg::HiveReplicaDial {
                grant_id,
                session_id: g.session_id,
                fence: g.fence,
                source_id: source,
                path: Some(g.path),
                token: g.token.clone(),
                cert_fingerprint: cert_fingerprint.unwrap_or_default(),
                addrs,
                derp_pubkey: match g.path {
                    HiveStreamPath::Derp => derp_pubkey,
                    HiveStreamPath::Direct | HiveStreamPath::Relay => None,
                },
                ice_servers: g.member_ice.clone(),
                ttl_secs: stream_limits::GRANT_TTL_SECS,
            },
        )
    };
    let (tenant_id, member, session_id, msg) = dial;
    if !push(state, tenant_id, member, msg) {
        // The member left between its want and the source's answer.
        state.stream_grants.map.remove(&grant_id);
        push(
            state,
            tenant_id,
            source,
            ServerMsg::HiveReplicaClose {
                grant_id,
                reason: "member_offline".into(),
            },
        );
        return;
    }
    info!(grant = %grant_id, session = %session_id, member = %member, "hive: stream ready — the member dials");
    if let Ok(Some(s)) = state.sessions.find(session_id).await {
        audit(&s, member, "ready", None).write(state).await;
    }
}

/// The member's relayed address, to the source of a confirmed `relay` grant
/// only.
fn on_candidate(state: &HiveState, member: ObjectId, grant_id: ObjectId, addr: &str) {
    if !dialable(addr) {
        return debug!(grant = %grant_id, "hive: a candidate that is no address — dropped");
    }
    let Some((tenant_id, source)) = state
        .stream_grants
        .map
        .get(&grant_id)
        .filter(|g| g.member_id == member && g.ready && g.path == HiveStreamPath::Relay)
        .map(|g| (g.tenant_id, g.source_id))
    else {
        return debug!(grant = %grant_id, device = %member, "hive: a candidate for no relay grant of this member's");
    };
    push(
        state,
        tenant_id,
        source,
        ServerMsg::HiveReplicaCandidate {
            grant_id,
            addr: addr.to_string(),
        },
    );
}

/// A device ended a stream it is a side of: the server forgets the grant,
/// and the other side is told.
fn on_close(state: &HiveState, device: ObjectId, grant_id: ObjectId, reason: &str) {
    let Some((_, g)) = state.stream_grants.map.remove_if(&grant_id, |_, g| {
        g.member_id == device || g.source_id == device
    }) else {
        return;
    };
    let other = if g.member_id == device {
        g.source_id
    } else {
        g.member_id
    };
    let reason: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_CHARS)
        .collect();
    push(
        state,
        g.tenant_id,
        other,
        ServerMsg::HiveReplicaClose { grant_id, reason },
    );
}

/// End every grant `select` picks, telling both sides. Returns how many.
fn end_where(state: &HiveState, select: impl Fn(ObjectId, &Grant) -> bool, reason: &str) -> usize {
    let ids: Vec<ObjectId> = state
        .stream_grants
        .map
        .iter()
        .filter(|g| select(*g.key(), g.value()))
        .map(|g| *g.key())
        .collect();
    let mut ended = 0;
    for grant_id in ids {
        let Some((_, g)) = state.stream_grants.map.remove(&grant_id) else {
            continue;
        };
        ended += 1;
        for side in [g.member_id, g.source_id] {
            push(
                state,
                g.tenant_id,
                side,
                ServerMsg::HiveReplicaClose {
                    grant_id,
                    reason: reason.to_string(),
                },
            );
        }
    }
    ended
}

/// A device removed: every stream it is a side of ends, as member or source.
pub(crate) fn end_for_device(state: &HiveState, device: ObjectId, reason: &str) -> usize {
    end_where(
        state,
        |_, g| g.member_id == device || g.source_id == device,
        reason,
    )
}

/// FR-90 P2e-3 — the session's lease moved: every stream of it ends, the
/// old primary's to its members above all. A member follows the new primary
/// once it has answered its join at the new fence, and nothing the old one
/// still sends can reach it on a grant the server ended.
pub(crate) fn end_for_session(state: &HiveState, session_id: ObjectId, reason: &str) -> usize {
    end_where(state, |_, g| g.session_id == session_id, reason)
}

/// A member placement let go (`leaving`): its streams of that session end
/// at once, not at their grant's end. A tag taken off must stop the copy
/// following, whatever it still holds until the purge.
pub(crate) fn end_for_member(
    state: &HiveState,
    session_id: ObjectId,
    member: ObjectId,
    reason: &str,
) -> usize {
    end_where(
        state,
        |_, g| g.session_id == session_id && g.member_id == member,
        reason,
    )
}
