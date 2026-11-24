// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-128 / FR-134 — the centre is a zone of its own: how each device may reach it, and what a
//! management entry may say about the devices that come through it.
//!
//! Three things, all decided here and nowhere else:
//!
//! - [`path_for`]: whether the device may dial the centre directly (FR-134: only a zone's own
//!   approved gateways and devices in the centre zone `is_centre = true`; every other device in a
//!   zone uses its zone's entries regardless of `cross_zone_mode`), and its zone's entries: the
//!   zone's approved gateways that run a management entry, at their public addresses.
//! - [`entry_key`]: the key a gateway signs attestations with (derived, never stored).
//! - [`resolve_origin`]: at the `/ws?role=agent` upgrade, the connection's origin. A valid
//!   attestation from a current entry of the device's own org replaces the entry's address with
//!   the device's. A connection from a current entry's address without one gets no address: an
//!   entry must not lend its zone.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use bson::oid::ObjectId;
use meshharbor_core::client_ip::ConnectionOrigin;
use meshharbor_core::user_analytics::canonical_public_ip;
use meshharbor_remote_control::management_entry as me;
use meshharbor_remote_control::models::{Agent, AgentCaps, OverlayNetwork, OverlayNode, RpcCap};
use tracing::{info, warn};

use crate::FleetState;

/// At most this many entry addresses go to one device.
pub(crate) const MAX_ENTRIES: usize = 8;
/// At most this many addresses of one entry.
const MAX_ADDRS_PER_ENTRY: usize = 3;
/// The longest `entry=` token read.
const MAX_TOKEN_LEN: usize = 2048;

/// Does this device parse `rc:agent.management_path`? Equality on the verb.
pub(crate) fn advertises(caps: &AgentCaps) -> bool {
    caps.has_rpc(RpcCap::ManagementPath)
}

/// FR-134 — can this device start/stop its management entry listener live on
/// `rc:agent.management_entry`? Equality on the verb.
pub(crate) fn advertises_entry(caps: &AgentCaps) -> bool {
    caps.has_rpc(RpcCap::ManagementEntry)
}

/// Is `agent` an approved gateway of some zone of its org's network?
pub(crate) fn is_gateway(net: Option<&OverlayNetwork>, agent: &Agent) -> bool {
    let (Some(net), Some(id)) = (net, agent.id) else {
        return false;
    };
    let hex = id.to_hex();
    agent.peer_relay_policy.serve && net.zones.iter().any(|z| z.gateway_relay_ids.contains(&hex))
}

/// The key `agent` signs attestations with, while it is a gateway that runs (or can start) an
/// entry. Pre-FR-134 agents only receive a key when they already bound `management_entry_port`;
/// FR-134 agents advertising `management-entry` receive a key as soon as they are a gateway and
/// bind the listener live on receipt.
pub(crate) fn entry_key(
    state: &FleetState,
    net: Option<&OverlayNetwork>,
    agent: &Agent,
) -> Option<me::EntryKey> {
    if !state.settings.app.management_entries
        || (agent.capabilities.management_entry_port.is_none()
            && !advertises_entry(&agent.capabilities))
        || !is_gateway(net, agent)
    {
        return None;
    }
    let id = agent.id?;
    Some(me::EntryKey::from_bytes(&me::derive_key(
        state.settings.jwt.secret.as_bytes(),
        &id.to_hex(),
        agent.token_gen,
    )))
}

/// The public addresses an entry is dialed at: the admin's static endpoints first (written for
/// exactly this: a host whose inbound address is not its egress), then the node's own public
/// addresses. Each paired with the entry port; public addresses only (`canonical_public_ip`;
/// the device drops private ones again), since a pushed dial target must not reach into a
/// private network.
fn entry_addrs<'a>(
    static_endpoints: &'a [String],
    node_endpoints: impl Iterator<Item = &'a String>,
    port: u16,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let ips = static_endpoints
        .iter()
        .chain(node_endpoints)
        .filter_map(|e| e.parse::<SocketAddr>().ok())
        .map(|sa| sa.ip());
    for ip in ips {
        let Some(ip) = canonical_public_ip(ip) else {
            continue;
        };
        let s = SocketAddr::new(ip, port).to_string();
        if !out.contains(&s) {
            out.push(s);
        }
        if out.len() >= MAX_ADDRS_PER_ENTRY {
            break;
        }
    }
    out
}

/// A node's own addresses, in the order `relay_endpoints` reads them.
fn node_endpoints(node: Option<&OverlayNode>) -> impl Iterator<Item = &String> {
    node.into_iter().flat_map(|n| {
        n.srflx_endpoints
            .iter()
            .chain(&n.lan_endpoints)
            .chain(&n.endpoints)
    })
}

/// FR-128 / FR-134 — how `agent` may reach the centre: `(direct, entries)`.
///
/// `policy` is the connect-time zone ICE policy (`compute_ice_policy_from_snapshot`). A device
/// with no resolved zone (an org without zones, or unresolved) keeps direct and gets no entries:
/// management must stay reachable, and an entry belongs to a zone. Inside a zone, ONLY that
/// zone's own approved gateways and members of the centre zone (`is_centre = true`) dial the
/// centre directly — every other device reaches the centre through its zone's entries, whether
/// the zone's `cross_zone_mode` is `router_only` or `direct_preferred`.
pub(crate) fn path_for(
    state: &FleetState,
    net: Option<&OverlayNetwork>,
    agent: &Agent,
    policy: &crate::hub::AgentZoneIcePolicy,
    approved_relays: &[Agent],
    gateway_nodes: &HashMap<ObjectId, OverlayNode>,
) -> (bool, Vec<String>) {
    if !state.settings.app.management_entries {
        return (true, Vec::new());
    }
    let (Some(net), Some(zone_id)) = (net, policy.zone.as_deref()) else {
        return (true, Vec::new());
    };
    let Some(zone) = net.zones.iter().find(|z| z.id == zone_id) else {
        return (true, Vec::new());
    };
    let self_hex = agent.id.map(|id| id.to_hex());
    let is_own_gateway = agent.peer_relay_policy.serve
        && self_hex
            .as_deref()
            .is_some_and(|h| zone.gateway_relay_ids.iter().any(|g| g == h));
    let direct = is_own_gateway || zone.is_centre;
    let mut entries = Vec::new();
    for gw_hex in &zone.gateway_relay_ids {
        if self_hex.as_deref() == Some(gw_hex.as_str()) {
            continue;
        }
        let Ok(gw_id) = ObjectId::parse_str(gw_hex) else {
            continue;
        };
        let Some(gw) = approved_relays.iter().find(|r| r.id == Some(gw_id)) else {
            continue;
        };
        let Some(port) = gw.capabilities.management_entry_port.filter(|p| *p != 0) else {
            continue;
        };
        let mut addrs = entry_addrs(
            &gw.peer_relay_policy.static_endpoints,
            node_endpoints(gateway_nodes.get(&gw_id)),
            port,
        );
        if addrs.is_empty()
            && let Some(ip) = gw
                .public_ip
                .as_deref()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .and_then(canonical_public_ip)
        {
            addrs.push(SocketAddr::new(ip, port).to_string());
        }
        for a in addrs {
            if entries.len() >= MAX_ENTRIES {
                break;
            }
            if !entries.contains(&a) {
                entries.push(a);
            }
        }
    }
    (direct, entries)
}

/// FR-134 — re-push `ManagementPath` and `ManagementEntryKey` (grant or empty revocation) to all
/// live agents in `tenant_id` after a zone, assignment, relay-policy, or gateway entry-port
/// change. Delivered locally on this pod and broadcast on `rc ctrl` for multi-pod deployments.
pub async fn sync_tenant_management_paths(state: &FleetState, tenant_id: ObjectId) {
    let net_dao = meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&state.core.db);
    let node_dao = meshharbor_services::dao::overlay_node::OverlayNodeDao::new(&state.core.db);
    let mut snapshot = None;
    for _ in 0..5 {
        let Ok(net1) = net_dao.find_for_tenant(tenant_id).await else {
            return;
        };
        let Ok(active_agents) = state.agents.list_all_active_for_tenant(tenant_id).await else {
            return;
        };
        let approved_relays: Vec<Agent> = active_agents
            .iter()
            .filter(|a| a.peer_relay_policy.serve)
            .cloned()
            .collect();
        let mut gateway_nodes = HashMap::new();
        for gw in &approved_relays {
            if gw.capabilities.management_entry_port.is_none() {
                continue;
            }
            let Some(gw_id) = gw.id else { continue };
            match node_dao
                .find_live_by_tenant_and_machine(tenant_id, &gw.machine_id)
                .await
            {
                Ok(Some(node)) => {
                    gateway_nodes.insert(gw_id, node);
                }
                Ok(None) => {}
                Err(_) => return,
            }
        }
        let Ok(net2) = net_dao.find_for_tenant(tenant_id).await else {
            return;
        };
        let consistent = match (&net1, &net2) {
            (None, None) => true,
            (Some(a), Some(b)) => a.zone_revision == b.zone_revision,
            _ => false,
        };
        if consistent {
            snapshot = Some((net1, active_agents, approved_relays, gateway_nodes));
            break;
        }
    }
    let Some((net, active_agents, approved_relays, gateway_nodes)) = snapshot else {
        return;
    };
    let tid_hex = tenant_id.to_hex();
    for agent in &active_agents {
        let Some(aid) = agent.id else { continue };
        let aid_hex = aid.to_hex();
        let policy = crate::socket::compute_ice_policy_from_snapshot(
            state,
            net.as_ref(),
            agent,
            &approved_relays,
        );
        if advertises(&agent.capabilities) {
            let (direct, entries) = path_for(
                state,
                net.as_ref(),
                agent,
                &policy,
                &approved_relays,
                &gateway_nodes,
            );
            state
                .rc_hub
                .push_management_path(tenant_id, aid, direct, entries.clone());
            crate::ctrl::publish_rc_ctrl(
                state,
                "management_path",
                serde_json::json!({
                    "tenant_id": tid_hex,
                    "agent_id": aid_hex,
                    "direct": direct,
                    "entries": entries,
                }),
            )
            .await;
        }
        if let Some(key) = entry_key(state, net.as_ref(), agent) {
            state
                .rc_hub
                .push_management_entry_key(tenant_id, aid, key.clone());
            crate::ctrl::publish_rc_ctrl(
                state,
                "management_entry_key",
                serde_json::json!({
                    "tenant_id": tid_hex,
                    "agent_id": aid_hex,
                    "key": key.0,
                }),
            )
            .await;
        } else if advertises_entry(&agent.capabilities)
            && agent.capabilities.management_entry_port.is_some()
        {
            // No longer a gateway (or management_entries disabled): tell the live agent to stop
            // its entry listener.
            state
                .rc_hub
                .push_management_entry_key(tenant_id, aid, me::EntryKey(String::new()));
            crate::ctrl::publish_rc_ctrl(
                state,
                "management_entry_key",
                serde_json::json!({
                    "tenant_id": tid_hex,
                    "agent_id": aid_hex,
                    "key": "",
                }),
            )
            .await;
        }
    }
}

/// The gateways of `agent`'s zone that run an entry: whose overlay nodes `path_for` needs.
pub(crate) fn zone_entry_gateways<'a>(
    net: Option<&OverlayNetwork>,
    policy: &crate::hub::AgentZoneIcePolicy,
    approved_relays: &'a [Agent],
) -> Vec<&'a Agent> {
    let (Some(net), Some(zone_id)) = (net, policy.zone.as_deref()) else {
        return Vec::new();
    };
    let Some(zone) = net.zones.iter().find(|z| z.id == zone_id) else {
        return Vec::new();
    };
    approved_relays
        .iter()
        .filter(|r| {
            r.capabilities.management_entry_port.is_some()
                && r.id
                    .is_some_and(|id| zone.gateway_relay_ids.iter().any(|g| *g == id.to_hex()))
        })
        .collect()
}

/// FR-128 — the origin of an agent connection, after the management-entry rules. Called by the
/// upgrade before anything reads the origin (zone observation, `public_ip`).
pub async fn resolve_origin(
    state: &FleetState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    entry: Option<&str>,
    origin: ConnectionOrigin,
) -> ConnectionOrigin {
    if !state.settings.app.management_entries {
        return origin;
    }
    let Some(client) = origin.client_ip() else {
        return origin;
    };
    if let Some(token) = entry.filter(|t| !t.is_empty()) {
        match check_token(state, tenant_id, token, client).await {
            Ok((entry_id, att)) => {
                // A device on the entry's own private network has no public address of its own:
                // it is where the entry is, so the entry's address is the true one.
                return match canonical_public_ip(att.ip) {
                    Some(ip) => {
                        info!(%agent_id, entry = %entry_id, device_ip = %ip,
                            "management entry: connection attested, origin is the device's address");
                        origin.through_management_entry(ip)
                    }
                    None => {
                        info!(%agent_id, entry = %entry_id,
                            "management entry: device on the entry's private network, origin is the entry's address");
                        origin
                    }
                };
            }
            Err(reason) => {
                warn!(%agent_id, reason, "management entry: attestation refused");
            }
        }
    }
    let entries = match state
        .agents
        .find_management_entries_at(tenant_id, &client.to_string())
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(%agent_id, %e, "management entry: entry lookup failed, origin kept");
            return origin;
        }
    };
    if entries.iter().all(|e| e.id == Some(agent_id)) {
        return origin;
    }
    // Only a CURRENT entry (an approved gateway of one of the org's zones) withholds.
    let net =
        match meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&state.core.db)
            .find_for_tenant(tenant_id)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(%agent_id, %e, "management entry: network read failed, origin kept");
                return origin;
            }
        };
    let current = entries
        .iter()
        .find(|e| e.id != Some(agent_id) && is_gateway(net.as_ref(), e));
    match current {
        Some(e) => {
            // An approved relay is the org's own infrastructure, and may share a provider's
            // egress with a gateway (two hosts of one provider behind one NAT): it keeps the
            // address it comes from, as before FR-128, or it would lose its zone and its lines.
            if let Ok(row) = state.agents.find_live_in_tenant(tenant_id, agent_id).await
                && row.peer_relay_policy.serve
            {
                info!(%agent_id, entry = ?e.id, %client,
                    "management entry: an approved relay shares an entry's address; origin kept");
                return origin;
            }
            warn!(%agent_id, entry = ?e.id, %client,
                "management entry: a connection from an entry's address without its attestation takes no address");
            origin.unattested_entry()
        }
        None => origin,
    }
}

async fn check_token(
    state: &FleetState,
    tenant_id: ObjectId,
    token: &str,
    client: IpAddr,
) -> Result<(ObjectId, me::Attestation), &'static str> {
    if token.len() > MAX_TOKEN_LEN {
        return Err("too_long");
    }
    let entry_hex = me::entry_id(token).map_err(me::Refusal::as_str)?;
    let entry_id = ObjectId::parse_str(&entry_hex).map_err(|_| "entry_id")?;
    // The SAME org: an entry attests only for its own org's devices.
    let entry = state
        .agents
        .find_live_in_tenant(tenant_id, entry_id)
        .await
        .map_err(|_| "entry_not_in_org")?;
    let net = meshharbor_services::dao::overlay_network::OverlayNetworkDao::new(&state.core.db)
        .find_for_tenant(tenant_id)
        .await
        .map_err(|_| "network_read_failed")?;
    let Some(key) = entry_key(state, net.as_ref(), &entry) else {
        return Err("not_a_current_entry");
    };
    // The connection must really come from that entry: a token is not a bearer credential.
    let from_entry = state.rc_hub.agent_live_public_ip(entry_id) == Some(client)
        || entry
            .public_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .and_then(canonical_public_ip)
            == Some(client);
    if !from_entry {
        return Err("not_from_entry");
    }
    let key = key.bytes().ok_or("key")?;
    let now = bson::DateTime::now().timestamp_millis() / 1000;
    let att = me::verify(&key, token, now).map_err(me::Refusal::as_str)?;
    Ok((entry_id, att))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn entry_addresses_are_public_static_first_and_bounded() {
        let statics = v(&["198.51.100.9:3478", "10.0.0.1:3478"]);
        let node = v(&[
            "203.0.113.5:41641",
            "192.168.1.2:41641",
            "203.0.113.5:9",
            "203.0.113.6:9",
            "203.0.113.7:9",
        ]);
        assert_eq!(
            entry_addrs(&statics, node.iter(), 18443),
            v(&[
                "198.51.100.9:18443",
                "203.0.113.5:18443",
                "203.0.113.6:18443"
            ])
        );
        assert!(entry_addrs(&v(&["127.0.0.1:1"]), [].iter(), 18443).is_empty());
    }
}
