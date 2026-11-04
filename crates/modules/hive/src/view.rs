// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0d-2b — the viewer peer, server side: the `hive:view.*` namespace on
//! the user socket, and the grants it mints.
//!
//! A member of a session's room asks to read it; the server checks the asker
//! (in the org, in the session's room — anyone else is told `not_found`, the
//! answer a bogus id gets), the device (online here, advertising
//! `hive-view`), and a rate; mints a GRANT and pushes it to the device. The
//! browser is told `ready` — with the ICE servers minted for this peer — only
//! after the DEVICE confirmed the grant (FR-83): before that it has nothing to
//! dial. Then the server relays the WebRTC handshake, and never sees what
//! flows over the peer.
//!
//! # The browser's frames (`{type, data}` on the user socket)
//!
//! | in | out |
//! |---|---|
//! | `hive:view.open {session_id, ref?}` | `hive:view.ready {ref, grant_id, session_id, ice_servers, ttl_secs, may_prompt}` or `hive:view.refused {ref, session_id, reason, message?}` |
//! | `hive:view.offer {grant_id, sdp}` | `hive:view.answer {grant_id, sdp}` |
//! | `hive:view.ice {grant_id, candidate}` | `hive:view.ice {grant_id, candidate}` |
//! | `hive:view.renew {grant_id}` | `hive:view.renewed {grant_id, ttl_secs}` |
//! | `hive:view.close {grant_id}` | `hive:view.closed {grant_id, reason}` (also unasked) |
//! | `hive:search.open {tenant_id, ref?}` (P2i-2) | `hive:search.ready {ref, grant_id, ice_servers, ttl_secs, sessions}` or `hive:search.refused {ref, reason, message?}`; the peer then takes the view's frames above, by its grant |
//!
//! # Whose grant it is
//!
//! A grant belongs to ONE browser connection and ONE device. A frame naming it
//! from any other connection, user or device moves nothing — grant ids are
//! ObjectIds, structured, not secret. The table is pod-local, like the start
//! waiters: the grant is pushed only when the device's socket is on this pod,
//! its answers arrive on that socket, and replies to the browser are routed
//! (`send_to_connection_routed`) wherever its socket is.
//!
//! The grant ends when the browser closes it or its socket closes, when the
//! device reports it closed, when a renewal finds the viewer no longer in the
//! room, when the viewer's membership, the device or the org is removed, or
//! when the session's owner changes the viewer's part in it (P1c,
//! `role_changed`: a grant carries `may_prompt` as minted).
//!
//! # Who serves it (P2d-5)
//!
//! The session's primary, while it can serve a view. Else, with the
//! replicaset's switch on, the freshest member's copy
//! ([`crate::replica::freshest_copy`]), on a connection that advertises
//! `hive-view` and `hive-replica` both. A copy is read only: a driver's grant
//! is minted toward the primary alone, the one device a prompt can reach. With
//! neither, the primary's own word refuses (`device_offline`,
//! `device_unsupported`). The audit row of a view from a copy says `copy`.
//!
//! # A search (P2i-2)
//!
//! A SEARCH grant goes to the organization's designated archive replica that
//! searches (`hive-search`, online here; of several, the one that holds the
//! most of what the asker may read). It names the sessions the asker may read
//! whose copy that device holds as a member, the most recently active first,
//! at most [`search_limits::MAX_SESSIONS`]; the device searches only those it
//! does hold. It sits in the same table as a view's, so the device's answer,
//! the peer's frames and every end of a grant are a view's; it views no
//! session (`session_id` is [`NO_SESSION`]). A renewal asks again whether the
//! asker is in the organization and in every room through which they read a
//! session it names; one lost closes it, and the browser opens a search named
//! afresh. The server never holds a query or a word a search found: they
//! travel only over the peer.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_remote_control::hive::{search_limits, view_limits};
use meshharbor_remote_control::signaling::{ClientMsg, IceServer, ServerMsg};
use meshharbor_remote_control::turn_creds::ice_servers_for_session_with_ttl;
use meshharbor_core::{WsCtx, WsHandler};
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::access::may_read;
use crate::dao::HeldCopy;
use crate::routes::Audit;

/// Open grants one browser connection may hold.
const MAX_PER_CONNECTION: usize = 4;
/// The largest SDP or candidate a browser may send through.
const MAX_SDP_BYTES: usize = 64 * 1024;
const MAX_CANDIDATE_BYTES: usize = 4 * 1024;
/// A browser's `ref`, echoed back, capped.
const MAX_REF: usize = 64;
/// The TURN credential's life. Its timestamp bounds the ALLOCATION's whole life
/// (refreshes re-authenticate with the same username), and a viewer peer
/// stays open as long as its room — renewing the grant renews nothing here.
/// The config TTL (600 s by default) would cut a relayed viewer at ten
/// minutes, the bug the overlay's warm grants hit (72 h there).
const TURN_TTL_SECS: u32 = 12 * 3600;
/// FR-90 P2i-2 — a search grant's session: it views none. The zero id, which
/// no session record carries, so no session's end or move ever matches it.
const NO_SESSION: ObjectId = ObjectId::from_bytes([0; 12]);

struct Grant {
    tenant_id: ObjectId,
    session_id: ObjectId,
    device_id: ObjectId,
    user_id: ObjectId,
    connection_id: String,
    may_prompt: bool,
    /// The device confirmed it: the browser may dial.
    ready: bool,
    /// Minted once, the same for both ends.
    ice_servers: Vec<IceServer>,
    reference: Option<String>,
    /// FR-90 P2i-2 — a search grant's scope; `None` for a view.
    search: Option<SearchScope>,
}

/// FR-90 P2i-2 — what a search grant names.
struct SearchScope {
    /// The sessions it names, as the device was sent them.
    sessions: Vec<ObjectId>,
    /// The rooms through which its user reads a session it names (each once;
    /// none for the sessions they own): a renewal asks their membership in
    /// every one again.
    rooms: Vec<ObjectId>,
}

/// The view grants this pod holds.
#[derive(Default)]
pub struct ViewGrants {
    map: DashMap<ObjectId, Grant>,
}

impl ViewGrants {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants held now. Tests and diagnostics only.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn take_where(&self, keep: impl Fn(&Grant) -> bool) -> Vec<(ObjectId, Grant)> {
        let ids: Vec<ObjectId> = self
            .map
            .iter()
            .filter(|e| !keep(e.value()))
            .map(|e| *e.key())
            .collect();
        ids.into_iter()
            .filter_map(|id| self.map.remove(&id))
            .collect()
    }
}

/// The `hive` namespace on the user socket.
pub struct HiveView {
    pub state: HiveState,
}

#[async_trait]
impl WsHandler for HiveView {
    async fn handle(&self, ctx: &WsCtx, msg: Value) -> anyhow::Result<()> {
        let kind = msg.get("type").and_then(Value::as_str).unwrap_or("");
        let data = msg.get("data").cloned().unwrap_or(Value::Null);
        match kind {
            "hive:view.open" => open(&self.state, ctx, &data).await,
            "hive:view.offer" => offer(&self.state, ctx, &data),
            "hive:view.ice" => ice(&self.state, ctx, &data),
            "hive:view.renew" => renew(&self.state, ctx, &data).await,
            "hive:view.close" => close(&self.state, ctx, &data).await,
            "hive:search.open" => open_search(&self.state, ctx, &data).await,
            other => debug!(user = %ctx.principal, kind = other, "hive: an unknown view frame"),
        }
        Ok(())
    }

    /// The browser is gone: so is every grant it held.
    async fn closed(&self, ctx: &WsCtx) {
        let gone = self
            .state
            .view_grants
            .take_where(|g| g.connection_id != ctx.connection_id);
        for (grant_id, g) in gone {
            tell_device_closed(&self.state, grant_id, &g, "viewer_left");
        }
    }
}

fn grant_id_of(data: &Value) -> Option<ObjectId> {
    data.get("grant_id")
        .and_then(Value::as_str)
        .and_then(|s| ObjectId::parse_str(s).ok())
}

/// Send `{type, data}` to one browser connection, wherever its socket is.
async fn to_browser(state: &HiveState, connection_id: &str, kind: &str, data: Value) {
    meshharbor_core::ws::dispatcher::send_to_connection_routed(
        &state.core.ws_storage,
        &state.core.redis_pubsub,
        connection_id,
        &json!({ "type": kind, "data": data }),
    )
    .await;
}

fn tell_device_closed(state: &HiveState, grant_id: ObjectId, g: &Grant, reason: &str) {
    let msg = ServerMsg::HiveViewClose {
        grant_id,
        reason: reason.to_string(),
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive_view(g.device_id, g.tenant_id, msg)
    {
        debug!(grant = %grant_id, %e, "hive: a view close did not reach the device");
    }
}

async fn open(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let reference: Option<String> = data
        .get("ref")
        .and_then(Value::as_str)
        .map(|r| r.chars().take(MAX_REF).collect());
    let session_hex = data
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let refuse = |reason: &'static str, message: Option<String>| {
        let data = json!({
            "ref": reference,
            "session_id": session_hex,
            "reason": reason,
            "message": message,
        });
        async move { to_browser(state, &ctx.connection_id, "hive:view.refused", data).await }
    };

    let user = ctx.principal;
    let session = match ObjectId::parse_str(&session_hex) {
        Ok(sid) => state.sessions.find(sid).await.ok().flatten(),
        Err(_) => None,
    };
    // Not readable, not there, and not served (P1g) answer alike: nobody
    // learns from the answer what they could not read.
    let s = match session {
        Some(s) if state.scope.serves(s.tenant_id) && may_read(state, &s, user).await => s,
        _ => return refuse("not_found", None).await,
    };
    let Some(sid) = s.id else {
        return refuse("not_found", None).await;
    };
    // P2d-5 — the primary while it can serve; else, with the replicaset on,
    // the freshest member's copy, read only. With none, the primary's own
    // word refuses (`device_offline`, `device_unsupported`).
    let primary = s.location.device_id;
    let copy = (state.replicaset
        && state.fleet.rc_hub.agent_supports_hive_view(primary) != Some(true))
    .then(|| {
        crate::replica::freshest_copy(&s, |d| {
            state.fleet.rc_hub.agent_serves_copies(d, s.tenant_id)
        })
    })
    .flatten();
    let device_id = copy.unwrap_or(primary);
    let audit = |outcome: &'static str, reason: Option<&'static str>| Audit {
        tenant_id: s.tenant_id,
        user_id: user,
        target_id: None,
        device_id,
        session_id: Some(sid),
        action: "view",
        outcome,
        reason,
    };

    let refused_by_server = match state.fleet.rc_hub.agent_supports_hive_view(device_id) {
        None => Some("device_offline"),
        Some(false) => Some("device_unsupported"),
        Some(true) => None,
    }
    .or_else(|| {
        let held = state
            .view_grants
            .map
            .iter()
            .filter(|g| g.connection_id == ctx.connection_id)
            .count();
        (held >= MAX_PER_CONNECTION).then_some("too_many_views")
    })
    .or_else(|| {
        (!state
            .view_limiter
            .check(user, sid, view_limits::OPEN_RATE_PER_MINUTE))
        .then_some("rate_limited")
    });
    if let Some(reason) = refused_by_server {
        audit("refused", Some(reason)).write(state).await;
        return refuse(reason, None).await;
    }

    // A driver prompts a live session; every other member reads (P1c). The
    // grant keeps what it was minted with: a change of who drives ends the
    // person's grants (`end_session_grants_of`), and the view they reopen is
    // minted afresh. P2d-5 — never toward a copy: the harness runs on the
    // primary, the one device a prompt can reach.
    let may_prompt = crate::access::drives_now(&s, user) && copy.is_none();
    // The address goes with a DRIVER's grant only (P1c-2): the device maps a
    // driver who is not the starter through its own `hive_accounts`, which
    // may name people by address. A reader's never leaves the server.
    let (user_name, user_email) = match state.users.base.find_by_id(user).await {
        Ok(u) => (u.display_name, may_prompt.then_some(u.email)),
        Err(_) => (String::new(), None),
    };
    let grant_id = ObjectId::new();
    let ice_servers = ice_servers_for_session_with_ttl(
        &user.to_hex(),
        &grant_id.to_hex(),
        state.core.turn_map.cfg_for(None),
        TURN_TTL_SECS,
    );
    // The grant BEFORE the push: the device's answer, however fast, must find
    // it.
    state.view_grants.map.insert(
        grant_id,
        Grant {
            tenant_id: s.tenant_id,
            session_id: sid,
            device_id,
            user_id: user,
            connection_id: ctx.connection_id.clone(),
            may_prompt,
            ready: false,
            ice_servers,
            reference: reference.clone(),
            search: None,
        },
    );
    let push = ServerMsg::HiveViewGrant {
        grant_id,
        session_id: sid,
        user_id: user,
        user_name,
        may_prompt,
        user_email,
        ttl_secs: view_limits::GRANT_TTL_SECS,
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive_view(device_id, s.tenant_id, push)
    {
        state.view_grants.map.remove(&grant_id);
        let reason = match e {
            meshharbor_remote_control::error::Error::ExecUnsupported(_) => "device_unsupported",
            _ => "device_offline",
        };
        audit("refused", Some(reason)).write(state).await;
        return refuse(reason, None).await;
    }
    // P2d-5 — the row says when the view is a member's copy.
    audit("sent", copy.map(|_| "copy")).write(state).await;
    info!(
        grant = %grant_id, session = %sid, device = %device_id, user = %user, may_prompt,
        copy = copy.is_some(), "hive: view granted"
    );
    await_answer(state, grant_id);
}

/// A device that never answers a grant: the browser is told, and the device
/// told to drop the grant should its answer arrive after all.
fn await_answer(state: &HiveState, grant_id: ObjectId) {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(view_limits::GRANT_ACK_TIMEOUT_SECS)).await;
        let Some((_, g)) = state.view_grants.map.remove_if(&grant_id, |_, g| !g.ready) else {
            return;
        };
        tell_device_closed(&state, grant_id, &g, "no_answer");
        let (kind, data) = refused_frame(
            &g,
            "no_answer",
            Some("the device did not answer in time".to_string()),
        );
        to_browser(&state, &g.connection_id, kind, data).await;
    });
}

/// The browser's word that a grant was refused: a view's names its session,
/// a search's (P2i-2) none.
fn refused_frame(g: &Grant, reason: &str, message: Option<String>) -> (&'static str, Value) {
    match g.search {
        None => (
            "hive:view.refused",
            json!({
                "ref": g.reference,
                "session_id": g.session_id.to_hex(),
                "reason": reason,
                "message": message,
            }),
        ),
        Some(_) => (
            "hive:search.refused",
            json!({ "ref": g.reference, "reason": reason, "message": message }),
        ),
    }
}

/// The browser's word that the device confirmed a grant, so it may dial: a
/// view's says whether it may prompt, a search's (P2i-2) how many sessions
/// it named.
fn ready_frame(grant_id: ObjectId, g: &Grant) -> (&'static str, Value) {
    match &g.search {
        None => (
            "hive:view.ready",
            json!({
                "ref": g.reference,
                "grant_id": grant_id.to_hex(),
                "session_id": g.session_id.to_hex(),
                "ice_servers": g.ice_servers,
                "ttl_secs": view_limits::GRANT_TTL_SECS,
                "may_prompt": g.may_prompt,
            }),
        ),
        Some(s) => (
            "hive:search.ready",
            json!({
                "ref": g.reference,
                "grant_id": grant_id.to_hex(),
                "ice_servers": g.ice_servers,
                "ttl_secs": view_limits::GRANT_TTL_SECS,
                "sessions": s.sessions.len(),
            }),
        ),
    }
}

/// FR-90 P2i-2 — `hive:search.open {tenant_id, ref?}`: a search grant toward
/// the organization's archive replica, naming the sessions the asker may read
/// whose copy it holds (the module docs, "A search").
async fn open_search(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let reference: Option<String> = data
        .get("ref")
        .and_then(Value::as_str)
        .map(|r| r.chars().take(MAX_REF).collect());
    let refuse = |reason: &'static str| {
        let data = json!({ "ref": reference, "reason": reason, "message": Value::Null });
        async move { to_browser(state, &ctx.connection_id, "hive:search.refused", data).await }
    };
    let user = ctx.principal;
    // An organization the asker is not in, one agent sessions do not serve
    // (P1g), and a server that copies no sessions answer alike: nobody learns
    // from the answer what they could not search.
    let tenant = data
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|t| ObjectId::parse_str(t).ok());
    let tid = match tenant {
        Some(t)
            if state.replicaset
                && state.scope.serves(t)
                && matches!(state.tenants.is_member(t, user).await, Ok(true)) =>
        {
            t
        }
        _ => return refuse("not_found").await,
    };
    // The organization's designated archive replicas that search, online
    // here, in the policy's order.
    let designated = match state.policies.get(tid).await {
        Ok(p) => p.map(|p| p.archive_devices).unwrap_or_default(),
        Err(e) => {
            warn!(tenant = %tid, %e, "hive: a search could not read the organization's policy");
            return refuse("unavailable").await;
        }
    };
    let searching: Vec<ObjectId> = designated
        .into_iter()
        .filter(|d| state.fleet.rc_hub.agent_searches(*d, tid))
        .collect();
    let Some(&first) = searching.first() else {
        return refuse("no_archive_replica").await;
    };
    let audit = |device_id: ObjectId, outcome: &'static str, reason: Option<&'static str>| Audit {
        tenant_id: tid,
        user_id: user,
        target_id: None,
        device_id,
        session_id: None,
        action: "search",
        outcome,
        reason,
    };

    // The cheap refusals before the reads: one connection's grants, and the
    // pace, after the identity gates.
    let held_here = state
        .view_grants
        .map
        .iter()
        .filter(|g| g.connection_id == ctx.connection_id)
        .count();
    let paced = (held_here >= MAX_PER_CONNECTION)
        .then_some("too_many_views")
        .or_else(|| {
            (!state
                .view_limiter
                .check(user, tid, search_limits::OPEN_RATE_PER_MINUTE))
            .then_some("rate_limited")
        });
    if let Some(reason) = paced {
        audit(first, "refused", Some(reason)).write(state).await;
        return refuse(reason).await;
    }

    // What the asker may read through a room: every room they are in. A read
    // that fails refuses, rather than search less than they may read without
    // saying so.
    let rooms = match state.chat.rooms_of(tid, user).await {
        Ok(r) => r,
        Err(e) => {
            warn!(tenant = %tid, user = %user, %e, "hive: a search could not read the asker's rooms");
            audit(first, "refused", Some("unavailable"))
                .write(state)
                .await;
            return refuse("unavailable").await;
        }
    };
    // The one that holds the most of what the asker may read; the first in
    // the policy's order among equals.
    let mut best: Option<(ObjectId, Vec<HeldCopy>)> = None;
    for device in searching {
        match state
            .sessions
            .searchable(
                tid,
                device,
                user,
                &rooms,
                search_limits::MAX_SESSIONS as i64,
            )
            .await
        {
            Ok(held) if best.as_ref().is_none_or(|(_, b)| held.len() > b.len()) => {
                best = Some((device, held));
            }
            Ok(_) => {}
            Err(e) => {
                warn!(device = %device, %e, "hive: a search could not read what an archive replica holds")
            }
        }
    }
    let Some((device_id, held)) = best else {
        audit(first, "refused", Some("unavailable"))
            .write(state)
            .await;
        return refuse("unavailable").await;
    };
    let named = u32::try_from(held.len()).unwrap_or(u32::MAX);
    if held.is_empty() {
        audit(device_id, "refused", Some("no_session"))
            .write_counted(state, Some(0))
            .await;
        return refuse("no_session").await;
    }

    let sessions: Vec<ObjectId> = held.iter().map(|h| h.session_id).collect();
    let mut via: Vec<ObjectId> = held
        .iter()
        .filter(|h| h.owner_id != user)
        .filter_map(|h| h.room_id)
        .collect();
    via.sort_unstable();
    via.dedup();
    let grant_id = ObjectId::new();
    let ice_servers = ice_servers_for_session_with_ttl(
        &user.to_hex(),
        &grant_id.to_hex(),
        state.core.turn_map.cfg_for(None),
        TURN_TTL_SECS,
    );
    // The grant BEFORE the push: the device's answer, however fast, must find
    // it.
    state.view_grants.map.insert(
        grant_id,
        Grant {
            tenant_id: tid,
            session_id: NO_SESSION,
            device_id,
            user_id: user,
            connection_id: ctx.connection_id.clone(),
            may_prompt: false,
            ready: false,
            ice_servers,
            reference: reference.clone(),
            search: Some(SearchScope {
                sessions: sessions.clone(),
                rooms: via,
            }),
        },
    );
    let push = ServerMsg::HiveSearchGrant {
        grant_id,
        user_id: user,
        sessions,
        ttl_secs: view_limits::GRANT_TTL_SECS,
    };
    if let Err(e) = state.fleet.rc_hub.push_hive_search(device_id, tid, push) {
        state.view_grants.map.remove(&grant_id);
        let reason = match e {
            meshharbor_remote_control::error::Error::ExecUnsupported(_) => "device_unsupported",
            _ => "device_offline",
        };
        audit(device_id, "refused", Some(reason))
            .write_counted(state, Some(named))
            .await;
        return refuse(reason).await;
    }
    audit(device_id, "sent", None)
        .write_counted(state, Some(named))
        .await;
    info!(
        grant = %grant_id, device = %device_id, user = %user, sessions = named,
        "hive: search granted"
    );
    await_answer(state, grant_id);
}

/// The grant `data` names, if THIS connection's user holds it and the device
/// confirmed it.
fn ready_grant_of(
    state: &HiveState,
    ctx: &WsCtx,
    data: &Value,
) -> Option<(ObjectId, ObjectId, ObjectId)> {
    let grant_id = grant_id_of(data)?;
    let g = state.view_grants.map.get(&grant_id)?;
    (g.connection_id == ctx.connection_id && g.user_id == ctx.principal && g.ready).then_some((
        grant_id,
        g.device_id,
        g.tenant_id,
    ))
}

fn offer(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let Some((grant_id, device_id, tenant_id)) = ready_grant_of(state, ctx, data) else {
        return debug!(user = %ctx.principal, "hive: a view offer for no ready grant of this connection");
    };
    let Some(sdp) = data.get("sdp").and_then(Value::as_str) else {
        return;
    };
    if sdp.len() > MAX_SDP_BYTES {
        return warn!(grant = %grant_id, bytes = sdp.len(), "hive: an oversized view offer — dropped");
    }
    let ice_servers = state
        .view_grants
        .map
        .get(&grant_id)
        .map(|g| g.ice_servers.clone())
        .unwrap_or_default();
    let msg = ServerMsg::HiveViewOffer {
        grant_id,
        sdp: sdp.to_string(),
        ice_servers,
    };
    if let Err(e) = state.fleet.rc_hub.push_hive_view(device_id, tenant_id, msg) {
        debug!(grant = %grant_id, %e, "hive: a view offer did not reach the device");
    }
}

fn ice(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let Some((grant_id, device_id, tenant_id)) = ready_grant_of(state, ctx, data) else {
        return;
    };
    let Some(candidate) = data.get("candidate") else {
        return;
    };
    if candidate.to_string().len() > MAX_CANDIDATE_BYTES {
        return;
    }
    let msg = ServerMsg::HiveViewIce {
        grant_id,
        candidate: candidate.clone(),
    };
    if let Err(e) = state.fleet.rc_hub.push_hive_view(device_id, tenant_id, msg) {
        debug!(grant = %grant_id, %e, "hive: a view candidate did not reach the device");
    }
}

/// A renewal re-checks the viewer's right to read: one no longer in the
/// room loses the view now, not when the TTL runs out.
async fn renew(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let Some((grant_id, device_id, tenant_id)) = ready_grant_of(state, ctx, data) else {
        return;
    };
    let (session_id, search_rooms) = match state.view_grants.map.get(&grant_id) {
        Some(g) => (g.session_id, g.search.as_ref().map(|s| s.rooms.clone())),
        None => return,
    };
    let still = match search_rooms {
        Some(rooms) => still_searches(state, tenant_id, ctx.principal, &rooms).await,
        None => match state.sessions.find(session_id).await {
            Ok(Some(s)) => may_read(state, &s, ctx.principal).await,
            _ => false,
        },
    };
    if !still {
        if let Some((_, g)) = state.view_grants.map.remove(&grant_id) {
            tell_device_closed(state, grant_id, &g, "not_a_member");
        }
        return to_browser(
            state,
            &ctx.connection_id,
            "hive:view.closed",
            json!({"grant_id": grant_id.to_hex(), "reason": "not_a_member"}),
        )
        .await;
    }
    let msg = ServerMsg::HiveViewRenew {
        grant_id,
        ttl_secs: view_limits::GRANT_TTL_SECS,
    };
    if let Err(e) = state.fleet.rc_hub.push_hive_view(device_id, tenant_id, msg) {
        debug!(grant = %grant_id, %e, "hive: a view renewal did not reach the device");
        return;
    }
    to_browser(
        state,
        &ctx.connection_id,
        "hive:view.renewed",
        json!({"grant_id": grant_id.to_hex(), "ttl_secs": view_limits::GRANT_TTL_SECS}),
    )
    .await;
}

/// FR-90 P2i-2 — whether `user` may still search what their grant named: in
/// the organization, and a member of every room through which they read a
/// session it names. One lost closes the grant, and the browser opens a
/// search named afresh. A session purged since does not: its device purged
/// its copy, and there is nothing of it left to find.
async fn still_searches(
    state: &HiveState,
    tenant_id: ObjectId,
    user: ObjectId,
    rooms: &[ObjectId],
) -> bool {
    if !matches!(state.tenants.is_member(tenant_id, user).await, Ok(true)) {
        return false;
    }
    match state.chat.member_rooms_of(tenant_id, user, rooms).await {
        Ok(held) => {
            let held: HashSet<ObjectId> = held.into_iter().collect();
            rooms.iter().all(|r| held.contains(r))
        }
        Err(_) => false,
    }
}

async fn close(state: &HiveState, ctx: &WsCtx, data: &Value) {
    let Some(grant_id) = grant_id_of(data) else {
        return;
    };
    let Some((_, g)) = state
        .view_grants
        .map
        .remove_if(&grant_id, |_, g| g.connection_id == ctx.connection_id)
    else {
        return;
    };
    tell_device_closed(state, grant_id, &g, "viewer_closed");
    to_browser(
        state,
        &ctx.connection_id,
        "hive:view.closed",
        json!({"grant_id": grant_id.to_hex(), "reason": "viewer_closed"}),
    )
    .await;
}

/// A device's view frame, in the order its connection sent it. Applied only
/// to a grant pushed to THAT device.
pub(crate) async fn on_device_frame(state: &HiveState, device_id: ObjectId, msg: ClientMsg) {
    match msg {
        ClientMsg::HiveViewGrantAck {
            grant_id,
            refused,
            detail,
        } => {
            let reply = {
                let Some(mut g) = state.view_grants.map.get_mut(&grant_id) else {
                    return debug!(grant = %grant_id, "hive: a view ack for no grant here");
                };
                if g.device_id != device_id || g.ready {
                    return;
                }
                match refused {
                    None => {
                        g.ready = true;
                        let (kind, data) = ready_frame(grant_id, &g);
                        Ok((g.connection_id.clone(), kind, data))
                    }
                    Some(word) => Err(word),
                }
            };
            match reply {
                Ok((conn, kind, data)) => to_browser(state, &conn, kind, data).await,
                Err(word) => {
                    let Some((_, g)) = state.view_grants.map.remove(&grant_id) else {
                        return;
                    };
                    info!(
                        grant = %grant_id, refused = word.as_str(), search = g.search.is_some(),
                        "hive: the device refused a grant"
                    );
                    let message = crate::agent_socket::clamp_words(
                        detail,
                        meshharbor_remote_control::hive::hive_limits::MAX_DETAIL_LEN,
                    );
                    let (kind, data) = refused_frame(&g, word.as_str(), message);
                    to_browser(state, &g.connection_id, kind, data).await;
                }
            }
        }
        ClientMsg::HiveViewAnswer { grant_id, sdp } => {
            if sdp.len() > MAX_SDP_BYTES {
                return;
            }
            if let Some(conn) = ready_for_device(state, grant_id, device_id) {
                to_browser(
                    state,
                    &conn,
                    "hive:view.answer",
                    json!({"grant_id": grant_id.to_hex(), "sdp": sdp}),
                )
                .await;
            }
        }
        ClientMsg::HiveViewIce {
            grant_id,
            candidate,
        } => {
            if candidate.to_string().len() > MAX_CANDIDATE_BYTES {
                return;
            }
            if let Some(conn) = ready_for_device(state, grant_id, device_id) {
                to_browser(
                    state,
                    &conn,
                    "hive:view.ice",
                    json!({"grant_id": grant_id.to_hex(), "candidate": candidate}),
                )
                .await;
            }
        }
        ClientMsg::HiveViewClosed { grant_id, reason } => {
            let Some((_, g)) = state
                .view_grants
                .map
                .remove_if(&grant_id, |_, g| g.device_id == device_id)
            else {
                return;
            };
            let reason: String = reason.chars().take(64).collect();
            to_browser(
                state,
                &g.connection_id,
                "hive:view.closed",
                json!({"grant_id": grant_id.to_hex(), "reason": reason}),
            )
            .await;
        }
        other => debug!(?other, "hive: not a view frame"),
    }
}

/// The browser connection of a CONFIRMED grant pushed to `device_id`.
fn ready_for_device(state: &HiveState, grant_id: ObjectId, device_id: ObjectId) -> Option<String> {
    let g = state.view_grants.map.get(&grant_id)?;
    (g.device_id == device_id && g.ready).then(|| g.connection_id.clone())
}

/// End every grant `which` selects: the device is told (unless it is the
/// one going away) and so is the browser.
pub(crate) async fn end_grants(
    state: &HiveState,
    which: impl Fn(&ObjectId, &ObjectId, &ObjectId) -> bool,
    reason: &str,
    tell_device: bool,
) -> usize {
    let gone = state
        .view_grants
        .take_where(|g| !which(&g.tenant_id, &g.user_id, &g.device_id));
    end_taken(state, gone, reason, tell_device).await
}

/// P1c — end `user`'s grants on ONE session: their part in it changed (they
/// now drive it, or no longer do, or left it), so what a grant says about
/// whether they may prompt is stale. A browser told `role_changed` opens the
/// view again and is granted afresh.
pub(crate) async fn end_session_grants_of(
    state: &HiveState,
    session_id: ObjectId,
    user: ObjectId,
    reason: &str,
) -> usize {
    let gone = state
        .view_grants
        .take_where(|g| !(g.session_id == session_id && g.user_id == user));
    end_taken(state, gone, reason, true).await
}

/// FR-90 P2i-2 — end `user`'s search grants that name `session_id`: they no
/// longer read it (taken out of its room). The browser opens a search named
/// afresh. A change of their part that leaves them reading it ends none.
pub(crate) async fn end_searches_naming(
    state: &HiveState,
    session_id: ObjectId,
    user: ObjectId,
    reason: &str,
) -> usize {
    let gone = state.view_grants.take_where(|g| {
        !(g.user_id == user
            && g.search
                .as_ref()
                .is_some_and(|s| s.sessions.contains(&session_id)))
    });
    end_taken(state, gone, reason, true).await
}

/// FR-90 P2e-3 — end every grant on ONE session, whoever holds it and
/// whichever device serves it: the session moved, so a driver's grant toward
/// the old primary reaches no harness, and every view is opened afresh
/// toward where the session runs now.
pub(crate) async fn end_grants_of_session(
    state: &HiveState,
    session_id: ObjectId,
    reason: &str,
) -> usize {
    let gone = state.view_grants.take_where(|g| g.session_id != session_id);
    end_taken(state, gone, reason, true).await
}

async fn end_taken(
    state: &HiveState,
    gone: Vec<(ObjectId, Grant)>,
    reason: &str,
    tell_device: bool,
) -> usize {
    let n = gone.len();
    for (grant_id, g) in gone {
        if tell_device {
            tell_device_closed(state, grant_id, &g, reason);
        }
        to_browser(
            state,
            &g.connection_id,
            "hive:view.closed",
            json!({"grant_id": grant_id.to_hex(), "reason": reason}),
        )
        .await;
    }
    n
}
