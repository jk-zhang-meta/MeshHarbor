// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The `network`-owned arms of the agent socket that have not moved yet
//! (FR-69): SSH activity + the SSH request leg, key-rotation reports, DERP
//! tickets, relay probe reports, and the tunnel relay (this agent as a
//! tunnel TARGET). The socket itself is the fleet module's since P5c and the
//! controller's `rc:*` path is the remote module's since P6; what is left
//! here leaves with `network` (P7).

use bson::oid::ObjectId;
use meshharbor_remote_control::signaling::{ClientMsg, RelayRegionRtt, ServerMsg};
use tracing::{debug, info, warn};

use crate::NetworkState;

// FR-69 P5a: the rc control pair (publish + apply) is the fleet module's now;
// re-exported so every path in this crate reads as before.
pub use meshharbor_mod_fleet::ctrl::{apply_rc_ctrl, publish_rc_ctrl};
// FR-69 P5c — the agent socket and its pump moved to the fleet module too;
// the tunnel socket and the controller socket share the pump, and the relay
// probe report (network's, still here) reads the RTT ladder the hello uses.
pub use meshharbor_mod_fleet::socket::{prefs_from_rtt, pump_server_messages};

/// Minimum spacing between Mongo persists of an agent's probe table. The
/// Hub's live copy refreshes on EVERY report regardless.
const PROBE_PERSIST_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Persist one device-reported SSH activity row (P8).
///
/// Everything trustworthy in the row — which tenant, which device — is taken
/// from the authenticated connection by the caller and passed in here;
/// everything else is the device's claim. Best-effort by design: a log line
/// must never be able to disturb a live session, so a failed insert is warned
/// and dropped.
///
/// `detail` is re-clamped server-side. The device already caps it, but a
/// length bound that only exists on the reporting side is not a bound.
#[allow(clippy::too_many_arguments)]
pub async fn record_ssh_activity(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    grant_id: Option<String>,
    caller: String,
    kind: meshharbor_remote_control::models::SshActivityKind,
    detail: Option<String>,
    exit_code: Option<i32>,
    allowed: bool,
) {
    use meshharbor_remote_control::models::SshActivityEvent;

    let detail = detail.map(|mut d| {
        if d.chars().count() > SshActivityEvent::MAX_DETAIL {
            d = d.chars().take(SshActivityEvent::MAX_DETAIL).collect();
            d.push('…');
        }
        d
    });
    let event = SshActivityEvent {
        id: None,
        tenant_id,
        agent_id,
        grant_id,
        caller,
        kind,
        detail,
        exit_code,
        allowed,
        at: bson::DateTime::now(),
    };
    if let Err(e) = state.ssh_activity.record(event).await {
        warn!(%agent_id, %e, "ssh_activity insert failed");
    }
}

/// FR-40 — persist a device's [`ClientMsg::KeyRotated`] onto its agent row.
/// Same rules as the config report: last report wins, `reported_at`
/// is stamped here, `detail` is re-clamped on receipt. Public keys only —
/// the frame has no field for anything else, by construction.
#[allow(clippy::too_many_arguments)]
pub async fn record_key_rotation_report(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    request_id: String,
    outcome: meshharbor_remote_control::models::KeyRotationOutcome,
    old_public_key: Option<String>,
    new_public_key: Option<String>,
    key_epoch: u32,
    detail: Option<String>,
) {
    use meshharbor_remote_control::models::KeyRotationReport;

    let clamp = |s: String, max: usize| -> String {
        if s.chars().count() > max {
            let mut t: String = s.chars().take(max).collect();
            t.push('…');
            t
        } else {
            s
        }
    };
    // A WireGuard public key is 44 base64 chars; anything longer is not one.
    const MAX_KEY: usize = 64;
    let report = KeyRotationReport {
        request_id: clamp(request_id, 64),
        outcome,
        old_public_key: old_public_key.map(|k| clamp(k, MAX_KEY)),
        new_public_key: new_public_key.map(|k| clamp(k, MAX_KEY)),
        key_epoch,
        detail: detail.map(|d| clamp(d, KeyRotationReport::MAX_DETAIL)),
        reported_at: bson::DateTime::now(),
    };
    info!(
        %agent_id, request_id = %report.request_id, outcome = ?report.outcome,
        key_epoch, "overlay-key rotation reported by the device"
    );
    if let Err(e) = state
        .fleet
        .agents
        .record_key_rotation_report(tenant_id, agent_id, &report)
        .await
    {
        warn!(%agent_id, %e, "key rotation report write failed");
    }
}

/// The device-originated SSH leg (`mh ssh <device>`).
///
/// Mirrors the fleet module's exec request and goes through the SAME
/// [`agent_ssh::dispatch`] the HTTP route uses, so there is exactly one place
/// where the gates are evaluated regardless of how the request arrived.
///
/// [`agent_ssh::dispatch`]: crate::routes::agent_ssh::dispatch
#[allow(clippy::too_many_arguments)]
pub async fn handle_agent_ssh_request(
    state: &NetworkState,
    tenant_id: bson::oid::ObjectId,
    origin_agent_id: bson::oid::ObjectId,
    request_id: String,
    target: String,
    public_key: String,
    session_secs: u64,
    // FR-90 P3-8-1b — an agent session's ticket, when a session asks.
    ssh_ticket: Option<String>,
    reply_tx: meshharbor_remote_control::session::ClientTx,
) {
    // A refusal carries no address, so it carries no host key either — the two
    // are only ever meaningful together.
    let fail = |msg: String| ServerMsg::SshResponse {
        request_id: request_id.clone(),
        address: None,
        port: None,
        grant_id: None,
        host_pubkey: None,
        expires_at_ms: None,
        error: Some(msg),
        ssh_ticket_id: None,
    };

    // The origin's owner is the person whose permissions this runs under. A
    // device whose row vanished mid-flight has no principal, so it gets
    // nothing — and LIVE means a removed device counts as vanished.
    let origin = match state
        .fleet
        .agents
        .find_live_in_tenant(tenant_id, origin_agent_id)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            let _ = reply_tx.try_send(fail(format!("origin device unknown: {e}")));
            return;
        }
    };

    let agent =
        match meshharbor_mod_fleet::socket::resolve_exec_target(&state.fleet, tenant_id, &target)
            .await
        {
            Some(a) => a,
            None => {
                let _ = reply_tx.try_send(fail(format!("no device named {target:?} in this org")));
                return;
            }
        };

    // FR-90 P3-8-1b — an agent session's request is the session's. Its ticket
    // is bound here, where the origin device and the resolved target are both
    // known, and the outcome rides the caller into `dispatch`, which audits it
    // whatever it is: a ticket that does not hold is refused there, never
    // answered as the device owner's request instead.
    use crate::routes::agent_ssh::{CallerSession, bind_ssh_ticket};
    let session = match ssh_ticket.as_deref() {
        None => CallerSession::None,
        Some(token) => match bind_ssh_ticket(
            &state.core.auth,
            tenant_id,
            Some(origin_agent_id),
            agent.id.unwrap_or_default(),
            token,
        ) {
            Ok(s) => CallerSession::Bound(s),
            Err(why) => CallerSession::Refused(why),
        },
    };
    // The person accountable: a session's owner, who need not own the device
    // it runs on; else the origin device's owner.
    let accountable = match &session {
        CallerSession::Bound(s) => s.owner_user_id,
        CallerSession::None | CallerSession::Refused(_) => origin.owner_user_id,
    };

    // "<person> (via <device>)" — the target's log and consent prompt name
    // both the human accountable and the box the request came from; for a
    // session, the session too.
    let who = state
        .users
        .base
        .find_by_id(accountable)
        .await
        .map(|u| u.display_name)
        .unwrap_or_else(|_| accountable.to_hex());
    let display = match &session {
        CallerSession::Bound(s) => {
            format!(
                "agent session {} of {who} (via {})",
                s.session_id, origin.name
            )
        }
        CallerSession::None | CallerSession::Refused(_) => format!("{who} (via {})", origin.name),
    };
    let caller = crate::routes::agent_ssh::Caller {
        user_id: accountable,
        display,
        origin_agent_id: Some(origin_agent_id),
        session,
    };

    let res = crate::routes::agent_ssh::dispatch(
        state,
        tenant_id,
        &agent,
        &caller,
        &public_key,
        session_secs,
    )
    .await;

    // EXHAUSTIVE — this hand-written mapping is how `host_pubkey` went missing
    // on this leg in the first place: the HTTP response gained the field and a
    // field-by-field literal silently kept sending the old shape, which
    // compiles perfectly. Binding every field means the next addition has to be
    // decided about rather than forgotten.
    let crate::routes::agent_ssh::SshResponseBody {
        address,
        port,
        // Dropped on purpose: this leg answers a device that named its own
        // target, so echoing the MagicDNS name back tells it nothing it did
        // not just say. The HTTP leg keeps it for display.
        name: _,
        grant_id,
        host_pubkey,
        expires_at_ms,
        error,
        ssh_ticket_id,
    } = res;
    let msg = ServerMsg::SshResponse {
        request_id: request_id.clone(),
        address,
        port,
        grant_id,
        host_pubkey,
        expires_at_ms,
        error,
        ssh_ticket_id,
    };
    if reply_tx.try_send(msg).is_err() {
        warn!(%origin_agent_id, %request_id, "rc:ssh.response undeliverable — origin WS gone");
    }
}

/// A zone's spelling in a DERP ticket: exactly what `BusinessZone`
/// serializes to (snake_case), so the PoP compares the strings the API's own
/// JSON carries. Locked by `zone_claim_is_the_serde_spelling`.
fn zone_claim(z: meshharbor_core::business_authority::BusinessZone) -> &'static str {
    use meshharbor_core::business_authority::BusinessZone;
    match z {
        BusinessZone::Mainland => "mainland",
        BusinessZone::NonMainland => "non_mainland",
    }
}

/// Multi-region DERP: answer a ticket request. The ticket binds the agent's
/// overlay `(network_id, wg_public_key)` — exactly the invariants the central
/// `/derp` enforces from Mongo, so a PoP relay can enforce them with the
/// PUBLIC key alone.
pub async fn handle_derp_ticket_request(
    state: &NetworkState,
    agent_id: ObjectId,
    tx: &tokio::sync::mpsc::Sender<ServerMsg>,
) {
    let Some(signer) = &state.derp_ticket else {
        debug!(%agent_id, "derp ticket requested but no signer configured");
        return;
    };
    let Some(node) =
        crate::overlay::current_node(state, crate::overlay::NodeIdentity::Agent(agent_id)).await
    else {
        debug!(%agent_id, "derp ticket requested but agent has no overlay node");
        return;
    };
    // MeshHarbor #21 — under `enforce` the ticket names the node's zone, and a
    // PoP relays only between equal zones (`derp_ticket::DerpTicketClaims::zone`).
    // A node with no known zone relays to nobody, so it gets no ticket: it
    // keeps the central `/derp`, whose table applies the same rule.
    let zone = if crate::business_isolation::mode(state) == crate::business_isolation::Mode::Enforce
    {
        match crate::org_relay::node_zone(state, &node).await {
            Some(z) => Some(zone_claim(z)),
            None => {
                info!(%agent_id, "derp ticket withheld — business isolation is enforced and this node has no known zone");
                return;
            }
        }
    } else {
        None
    };
    match signer.mint_in_zone(&node.network_id.to_hex(), &node.wg_public_key, zone) {
        Ok((ticket, exp)) => {
            let _ = tx.try_send(ServerMsg::DerpTicket { ticket, exp });
        }
        Err(e) => warn!(%agent_id, %e, "derp ticket mint failed"),
    }
}

/// Multi-region relay PoPs: derive the agent's `relay_home` from a probe
/// report and fan it out (Hub live copy always; Mongo rate-limited).
///
/// Hysteresis: the home only MOVES when the best region improves on the
/// current home's measured RTT by >20%, or the current home stopped being
/// measurable (dropped from the region set, or all its samples timed out).
/// This keeps a border-line agent from flapping between two near-equal PoPs —
/// the sticky pair cache protects live pairs, this protects everything else.
pub async fn handle_relay_probe_report(
    state: &NetworkState,
    agent_id: ObjectId,
    results: &[RelayRegionRtt],
    last_persist: &mut Option<std::time::Instant>,
) {
    let map = &state.turn_map;
    if !map.enabled || map.regions.is_empty() {
        return;
    }
    let known: Vec<&RelayRegionRtt> = results
        .iter()
        .filter(|r| map.regions.contains_key(&r.region))
        .collect();
    let best = known
        .iter()
        .filter_map(|r| r.rtt_ms.map(|ms| (ms, r.region.as_str())))
        .min();
    let current = state.fleet.rc_hub.agent_relay_home(agent_id);
    let new_home: Option<String> = match (best, current.as_deref()) {
        // Nothing measurable (full-UDP-block / dead PoPs) → default region.
        (None, _) => None,
        (Some((_, b)), None) => Some(b.to_string()),
        (Some((best_ms, b)), Some(cur)) => {
            let cur_ms = known
                .iter()
                .find(|r| r.region == cur)
                .and_then(|r| r.rtt_ms);
            match cur_ms {
                None => Some(b.to_string()),
                Some(c) if f64::from(best_ms) < f64::from(c) * 0.8 => Some(b.to_string()),
                Some(_) => Some(cur.to_string()),
            }
        }
    };
    state
        .fleet
        .rc_hub
        .set_agent_relay_home(agent_id, new_home.clone(), prefs_from_rtt(results));
    let due = last_persist
        .map(|t| t.elapsed() >= PROBE_PERSIST_MIN_INTERVAL)
        .unwrap_or(true);
    if !due {
        return;
    }
    *last_persist = Some(std::time::Instant::now());
    if let Err(e) = state
        .fleet
        .agents
        .set_relay_home(agent_id, new_home.as_deref(), results)
        .await
    {
        warn!(%agent_id, %e, "set_relay_home (agents) failed");
    }
    if let Err(e) = state
        .overlay_nodes
        .set_relay_home_for_agent(agent_id, new_home.as_deref())
        .await
    {
        warn!(%agent_id, %e, "set_relay_home (overlay_nodes) failed");
    }
    debug!(%agent_id, home = ?new_home, "relay probe report processed");
}

/// Intercept tunnel-flow `ClientMsg` variants from the agent and route
/// the corresponding `ServerMsg` to the registered tunnel-client (if
/// any) keyed by `session_id`. Non-tunnel variants are returned
/// unchanged so the caller can pass them to the Hub.
///
/// Returns `None` if the message was consumed by the tunnel relay
/// (don't dispatch to the Hub afterwards), or `Some(parsed)` if the
/// caller should continue with Hub dispatch.
pub async fn relay_tunnel_msg_from_agent(
    state: &NetworkState,
    parsed: ClientMsg,
) -> Option<ClientMsg> {
    match parsed {
        ClientMsg::TcpForwardAccept {
            session_id,
            flow_id,
            dc_index,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TcpForwardAccept {
                    session_id,
                    flow_id,
                    dc_index,
                },
            )
            .await;
            None
        }
        ClientMsg::TcpForwardReject {
            session_id,
            flow_id,
            kind,
            reason,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TcpForwardReject {
                    session_id,
                    flow_id,
                    kind,
                    reason,
                },
            )
            .await;
            None
        }
        ClientMsg::TcpHalfClose {
            session_id,
            flow_id,
            direction,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TcpHalfClose {
                    session_id,
                    flow_id,
                    direction,
                },
            )
            .await;
            None
        }
        // The AGENT end of a flow closing. Byte counts are deliberately
        // ignored here: the audit row is written once, from the
        // ORIGINATOR's close (see `ws::tunnel::audit_tcp_close`), and
        // booking both ends would double every flow's volume.
        ClientMsg::TcpClosed {
            session_id,
            flow_id,
            reason,
            ..
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TcpClosed {
                    session_id,
                    flow_id,
                    reason,
                },
            )
            .await;
            None
        }
        // UDP ASSOCIATE relays — mirror the Tcp* variants above. The
        // agent bound a UDP socket (Accept) / rejected / closed a UDP
        // flow; relay each to the tunnel-client by session_id.
        ClientMsg::UdpForwardAccept {
            session_id,
            flow_id,
            dc_index,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::UdpForwardAccept {
                    session_id,
                    flow_id,
                    dc_index,
                },
            )
            .await;
            None
        }
        ClientMsg::UdpForwardReject {
            session_id,
            flow_id,
            kind,
            reason,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::UdpForwardReject {
                    session_id,
                    flow_id,
                    kind,
                    reason,
                },
            )
            .await;
            None
        }
        ClientMsg::UdpClosed {
            session_id,
            flow_id,
            reason,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::UdpClosed {
                    session_id,
                    flow_id,
                    reason,
                },
            )
            .await;
            None
        }
        ClientMsg::TunnelTerminate { session_id, reason } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TunnelTerminate { session_id, reason },
            )
            .await;
            None
        }
        ClientMsg::TunnelSdpAnswer { session_id, sdp } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TunnelSdpAnswer { session_id, sdp },
            )
            .await;
            None
        }
        ClientMsg::TunnelIce {
            session_id,
            candidate,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TunnelIce {
                    session_id,
                    candidate,
                },
            )
            .await;
            None
        }
        // Phase 1c: the agent's QUIC endpoint is up — relay its cert
        // fingerprint (for the client to pin) + dialable addrs to the
        // tunnel-client so it can connect the direct P2P QUIC link.
        ClientMsg::TunnelQuicReady {
            session_id,
            cert_fingerprint,
            addrs,
            derp_pubkey,
        } => {
            relay_to_client(
                state,
                session_id,
                ServerMsg::TunnelQuicReady {
                    session_id,
                    cert_fingerprint,
                    addrs,
                    // R4 — relayed verbatim; the client needs the agent's
                    // DERP identity to dial the quic-derp-v1 leg.
                    derp_pubkey,
                },
            )
            .await;
            None
        }
        // `TunnelHello` / `TunnelOpen` / `TcpForwardRequest` /
        // `TunnelSdpOffer` are tunnel-client → server messages;
        // agents shouldn't emit them. Pass through to the Hub so a
        // misbehaving agent gets a `bad_message` rather than being
        // silently dropped.
        other => Some(other),
    }
}

/// Push a `ServerMsg` to the tunnel-client registered for
/// `session_id`. No-op when the client has gone away (peer torn
/// down between agent emit + relay).
async fn relay_to_client(state: &NetworkState, session_id: bson::oid::ObjectId, msg: ServerMsg) {
    let Some(tx) = state
        .tunnel_clients_by_session
        .get(&session_id)
        .map(|entry| entry.value().clone())
    else {
        debug!(%session_id, "agent → client relay: no registered tunnel-client; dropping");
        // C-3 split evidence: if ANOTHER pod owns this session's record,
        // the drop was a cross-pod split (the agent's WS re-homed away
        // from the client's pod), not a torn-down client. Counted like
        // the A2b agent probe; throttled to 1/5 s.
        if let Some(dir) = state.cluster_directory.clone() {
            static LAST_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

            let now = bson::DateTime::now().timestamp_millis();
            let last = LAST_MS.load(std::sync::atomic::Ordering::Relaxed);
            if now - last >= 5_000
                && LAST_MS
                    .compare_exchange(
                        last,
                        now,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
            {
                tokio::spawn(async move {
                    let key = meshharbor_core::cluster::directory::tunnel_key(&session_id.to_hex());
                    if let Ok(Some(owner)) = dir.get(&key).await
                        && dir.is_foreign(&owner)
                    {
                        let total = meshharbor_core::cluster::metrics::SPLIT_EVIDENCE_TOTAL
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        warn!(
                            session = %session_id, owner = %owner, total,
                            "SPLIT EVIDENCE: tunnel relay dropped but another pod owns the session"
                        );
                    }
                });
            }
        }
        return;
    };
    if let Err(e) = tx.send(msg).await {
        debug!(%session_id, %e, "agent → client relay: channel closed");
    }
}

#[cfg(test)]
mod tests {
    use meshharbor_core::business_authority::BusinessZone;

    /// A PoP compares ticket zones as strings; renaming one here without the
    /// enum's serde spelling (or vice versa) would make every zoned pair look
    /// cross-zone, or worse, two zones look equal.
    #[test]
    fn zone_claim_is_the_serde_spelling() {
        for z in [BusinessZone::Mainland, BusinessZone::NonMainland] {
            assert_eq!(
                serde_json::to_value(z).unwrap(),
                serde_json::Value::String(super::zone_claim(z).to_string())
            );
        }
        assert_ne!(
            super::zone_claim(BusinessZone::Mainland),
            super::zone_claim(BusinessZone::NonMainland)
        );
    }
}
