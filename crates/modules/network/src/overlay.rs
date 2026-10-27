// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Overlay-network broker — the control plane for the Tailscale-style
//! L3 mesh (Phase 1 + 2).
//!
//! Overlay `rc:overlay.*` messages arrive on **both** WS roles (the
//! agent WS in [`super::remote_control`] and the tunnel-client WS in
//! [`super::tunnel`]), so this module exposes role-agnostic handlers
//! keyed by a [`NodeIdentity`] rather than owning its own socket loop.
//! Both read loops route their parsed overlay variants through
//! [`relay_overlay_msg_from_node`].
//!
//! Responsibilities:
//! * **IPAM** — allocate (or rehydrate) a stable overlay IP per node
//!   from the tenant's [`OverlayNetwork`].
//! * **Netmap distribution** — reply a full `rc:overlay.netmap` to a
//!   joiner and fan `rc:overlay.netmap_delta` upserts/removes to its
//!   permitted peers on join/endpoint-change/leave.
//! * **Relay grants** — mint short-lived coturn creds (keyed by a
//!   symmetric `pair_key`) on demand for a WG-over-coturn relay leg.
//!
//! The broker is **never** in the data path: the netmap travels the
//! authenticated TLS+JWT WS channel; the WG ciphertext rides UDP /
//! coturn directly between nodes.
//!
//! Reachability is ACL-precomputed server-side. Phase 1 ships
//! `reachable = same tenant + same network` (peers are sourced from a
//! tenant+network-scoped query, so the cross-tenant gate is structural);
//! Phase 4 swaps in `policy::evaluate_overlay`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::{DateTime, oid::ObjectId};
use roomler_ai_remote_control::models::{OverlayAclMode, OverlayPolicy};
use roomler_ai_remote_control::{
    models::{AgentStatus, NodeRef, OverlayNode, PeerRelayMode},
    signaling::{
        ClientMsg, IceServer, NetmapPeer, OverlayJoinRefusal, OverlayNetworkInfo,
        RelayStrategyWire, ServerMsg,
    },
    turn_creds,
    worker_pick::pick_worker_fnv1a,
};
use roomler_ai_services::dao::base::DaoError;
use roomler_ai_services::dao::overlay_node::NewOverlayNode;
use tokio::net::lookup_host;
use tracing::{debug, warn};
use tunnel_core::policy::{
    OverlayPeerRef, OverlaySource, evaluate_overlay, evaluate_overlay_ingress,
};

use roomler_core::turn::build_turn_config;

use crate::NetworkState;
use crate::business_isolation::{self, Zones};

/// Which underlying host an overlay message arrived from, captured at
/// the WS handler so the broker can resolve the node + route replies.
#[derive(Debug, Clone, Copy)]
pub enum NodeIdentity {
    Agent(ObjectId),
    TunnelClient(ObjectId),
}

impl NodeIdentity {
    fn node_ref(self) -> NodeRef {
        match self {
            NodeIdentity::Agent(id) => NodeRef::Agent { agent_id: id },
            NodeIdentity::TunnelClient(id) => NodeRef::TunnelClient {
                tunnel_client_id: id,
            },
        }
    }
}

/// Intercept `rc:overlay.*` variants and drive the broker. Returns
/// `None` when the message was consumed, or `Some(parsed)` so the
/// caller's existing dispatch handles non-overlay traffic. Shared by
/// both WS read loops.
pub async fn relay_overlay_msg_from_node(
    state: &NetworkState,
    ident: NodeIdentity,
    parsed: ClientMsg,
) -> Option<ClientMsg> {
    match parsed {
        ClientMsg::OverlayJoin {
            wg_public_key,
            key_epoch,
            instance,
            endpoints,
            supports_quic,
            supports_relay_single,
            supports_derp,
            supports_forced_derp,
            supports_server_relay_strategy,
            supports_derp_floor,
            supports_overlay_echo,
            supports_org_relay,
            supports_org_relay_multi_candidate,
            supports_org_relay_discovery_cursor,
            supports_path_trial_v1,
            supports_path_backbone_v1,
            relay_backbone_ready,
            supports_backbone_only_v1,
            supports_join_refusal,
            org_primary,
            relay_port,
            advertised_routes,
            route_offer_withheld,
            ..
        } => {
            handle_overlay_join(
                state,
                ident,
                wg_public_key,
                key_epoch,
                instance,
                endpoints,
                supports_quic,
                supports_relay_single,
                supports_derp,
                supports_forced_derp,
                supports_server_relay_strategy,
                supports_derp_floor,
                supports_overlay_echo,
                supports_org_relay,
                supports_org_relay_multi_candidate,
                supports_org_relay_discovery_cursor,
                supports_path_trial_v1,
                supports_path_backbone_v1,
                relay_backbone_ready,
                supports_backbone_only_v1,
                supports_join_refusal,
                org_primary,
                relay_port,
                advertised_routes,
                route_offer_withheld,
            )
            .await;
            None
        }
        ClientMsg::OverlayEndpoints { candidates } => {
            handle_overlay_endpoints(state, ident, candidates).await;
            None
        }
        ClientMsg::OverlaySrflx {
            candidates,
            nat,
            udp_dialer_ok,
        } => {
            handle_overlay_srflx(state, ident, candidates, nat, udp_dialer_ok).await;
            None
        }
        ClientMsg::OverlayNetcheck { caps } => {
            handle_overlay_netcheck(state, ident, caps).await;
            None
        }
        ClientMsg::OverlayLeave {} => {
            handle_overlay_leave(state, ident).await;
            None
        }
        ClientMsg::OverlayRelayRequest {
            peer_node_id,
            current_kind,
            reason,
            derp_mux_failed,
        } => {
            handle_overlay_relay_request(
                state,
                ident,
                peer_node_id,
                RelayRequestEvidence {
                    current_kind,
                    reason,
                    derp_mux_failed,
                },
            )
            .await;
            None
        }
        ClientMsg::OverlayOrgRelayFallbackRequest { peer_node_id, request_id } => {
            handle_org_relay_fallback_request(state, ident, peer_node_id, request_id).await;
            None
        }
        ClientMsg::OverlayOrgRelayLoss { peer_node_id, vni, packets, lost } => {
            handle_org_relay_loss(state, ident, peer_node_id, vni, packets, lost).await;
            None
        }
        ClientMsg::OverlayPathTrialRequest {
            peer_node_id,
            relay_node_id,
            request_id,
            exit_relay_node_id,
        } => {
            crate::org_relay::path_trial_request(
                state,
                ident,
                peer_node_id,
                relay_node_id,
                request_id,
                exit_relay_node_id,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialReady { trial_id } => {
            crate::org_relay::path_trial_update(
                state,
                ident,
                trial_id,
                crate::org_relay::PathTrialUpdate::Ready,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialCommitted { trial_id } => {
            crate::org_relay::path_trial_update(
                state,
                ident,
                trial_id,
                crate::org_relay::PathTrialUpdate::Committed,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialAbort { trial_id } => {
            crate::org_relay::path_trial_update(
                state,
                ident,
                trial_id,
                crate::org_relay::PathTrialUpdate::Abort,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialReturnRequest {
            trial_id,
            return_id,
        } => {
            crate::org_relay::path_trial_return_update(
                state,
                ident,
                trial_id,
                return_id,
                crate::org_relay::PathTrialReturnUpdate::Request,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialReturnReady {
            trial_id,
            return_id,
        } => {
            crate::org_relay::path_trial_return_update(
                state,
                ident,
                trial_id,
                return_id,
                crate::org_relay::PathTrialReturnUpdate::Ready,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialReturned {
            trial_id,
            return_id,
        } => {
            crate::org_relay::path_trial_return_update(
                state,
                ident,
                trial_id,
                return_id,
                crate::org_relay::PathTrialReturnUpdate::Returned,
            )
            .await;
            None
        }
        ClientMsg::OverlayPathTrialReturnAbort {
            trial_id,
            return_id,
        } => {
            crate::org_relay::path_trial_return_update(
                state,
                ident,
                trial_id,
                return_id,
                crate::org_relay::PathTrialReturnUpdate::Abort,
            )
            .await;
            None
        }
        ClientMsg::OverlayOrgRelayDiscover {
            peer_node_id,
            request_id,
            cursor,
        } => {
            handle_org_relay_discover(state, ident, peer_node_id, request_id, cursor).await;
            None
        }
        ClientMsg::OverlayWarmRelayRequest {} => {
            handle_overlay_warm_relay_request(state, ident).await;
            None
        }
        ClientMsg::OverlayRelayProbe {
            relay_node_id,
            endpoint,
            reachable,
            rtt_ms,
        } => {
            crate::org_relay::handle_relay_probe(
                state,
                ident,
                relay_node_id,
                endpoint,
                reachable,
                rtt_ms,
            )
            .await;
            None
        }
        other => Some(other),
    }
}

/// C4 stage 1 — pair-less coturn creds for the node's standing WARM
/// allocation (`docs/overlay-warm-relay.md`). Creds are keyed by the node's
/// own id (no pair exists yet), and the grant confers NO reach: coturn
/// permissions toward peers are opened at pairing time, and pairing still
/// goes through the ACL-checked `relay_request` path. Request-driven only —
/// never pushed — so it needs no hello capability flag.
async fn handle_overlay_warm_relay_request(state: &NetworkState, ident: NodeIdentity) {
    let Some(self_node) = current_node(state, ident).await else {
        debug!(?ident, "overlay.warm_relay_request before join; ignoring");
        return;
    };
    let Some(self_id) = self_node.id else { return };
    let warm_key = self_id.to_hex();
    // C4 stage 1.5 — long-lived creds: the cred timestamp bounds the
    // allocation's TOTAL life (refreshes re-authenticate with the same
    // username), and the warm allocation's whole point is surviving a
    // weekend into Monday's VPN connect. 72 h; the agent re-requests and
    // re-establishes fresh whenever it expires while UDP works.
    const WARM_CRED_TTL_SECS: u32 = 72 * 3600;
    let ice_servers = overlay_ice_servers_with_ttl(
        state,
        &warm_key,
        Some(self_node.tenant_id),
        self_node.relay_home.as_deref(),
        self_node.relay_home.as_deref(),
        Some(WARM_CRED_TTL_SECS),
        needs_tls_relay(&self_node),
    )
    .await;
    debug!(node = %self_id, "overlay relay: warm-allocation creds granted (72h)");
    send_to_node(
        state,
        &self_node,
        ServerMsg::OverlayWarmRelayGrant { ice_servers },
    )
    .await;
}

/// Join: IPAM (allocate or rehydrate) → persist → full netmap to the
/// joiner → upsert delta to each permitted peer.
#[allow(clippy::too_many_arguments)]
async fn handle_overlay_join(
    state: &NetworkState,
    ident: NodeIdentity,
    wg_public_key: String,
    key_epoch: u32,
    instance: Option<String>,
    endpoints: Vec<String>,
    supports_quic: bool,
    supports_relay_single: bool,
    supports_derp: bool,
    supports_forced_derp: bool,
    supports_server_relay_strategy: bool,
    supports_derp_floor: bool,
    supports_overlay_echo: bool,
    supports_org_relay: bool,
    supports_org_relay_multi_candidate: bool,
    supports_org_relay_discovery_cursor: bool,
    supports_path_trial_v1: bool,
    supports_path_backbone_v1: bool,
    relay_backbone_ready: bool,
    supports_backbone_only_v1: bool,
    supports_join_refusal: bool,
    org_primary: Option<bool>,
    relay_port: Option<u16>,
    advertised_routes: Vec<String>,
    route_offer_withheld: Option<String>,
) {
    let node_ref = ident.node_ref();
    // FR-97 P0b — the device's own words, shown to admins: bounded and kept to
    // printable text, whatever the device sent (it bounds its own to 200).
    let route_offer_withheld = route_offer_withheld
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(300)
                .collect::<String>()
        })
        .filter(|s| !s.trim().is_empty());
    // FR-47 — refuse OUT LOUD. Every early return below used to be a
    // server-side `warn!` and nothing else, leaving the node waiting on a
    // netmap that would never arrive; `refuse` sends the reason when the node
    // can read one and logs it either way.
    let refuse = |reason: OverlayJoinRefusal, detail: String| {
        let node_ref = node_ref.clone();
        async move {
            tracing::error!(
                ?node_ref, ?reason, %detail,
                alert = "overlay_join_refused",
                "overlay.join: refused"
            );
            if supports_join_refusal {
                send_to_node_ref(
                    state,
                    &node_ref,
                    ServerMsg::OverlayJoinRefused { reason, detail },
                )
                .await;
            }
        }
    };
    let Some((tenant_id, machine_id, display_name)) =
        resolve_tenant_and_machine(state, ident).await
    else {
        warn!(?ident, "overlay.join from an unknown node; ignoring");
        return;
    };
    // Phase 0 — the DNS-safe base label from the node's display name.
    let base_name = dns_label(&display_name, &machine_id);
    // Phase 1 — drop malformed CIDRs so a bad advertisement can't poison state.
    let advertised_routes = sanitize_cidrs(advertised_routes);

    let network = match state.overlay_networks.get_or_create(tenant_id).await {
        Ok(n) => n,
        Err(e) => {
            refuse(OverlayJoinRefusal::NetworkUnavailable, format!("{e}")).await;
            return;
        }
    };
    let Some(network_id) = network.id else {
        warn!(%tenant_id, "overlay network missing _id");
        return;
    };

    // Rehydrate-on-rejoin (keeps the leased IP) or allocate a fresh one. The
    // lookup is LIVE-scoped: a machine that was removed from the fleet had its
    // node tombstoned and its host number recycled, so it must come back as a
    // brand-new node with a fresh lease rather than reviving the tombstone.
    // The WG public key is client-supplied but is used as an ADDRESSING key
    // (DERP registration authorizes against it; WireGuard keys peers by it).
    // Refuse a key already held by a DIFFERENT live node in this network —
    // otherwise a second enrolled device can advertise a peer's key and
    // black-hole its DERP traffic. Rotation by the SAME machine is unaffected.
    match state
        .overlay_nodes
        .wg_key_taken_by_other(network_id, &wg_public_key, &machine_id)
        .await
    {
        Ok(true) => {
            warn!(
                %tenant_id, %machine_id,
                "overlay.join: refused — wg_public_key already held by another live node"
            );
            return;
        }
        Ok(false) => {}
        Err(e) => {
            // Fail CLOSED: this check exists to stop one node hijacking
            // another's identity, so an unverifiable claim must not proceed.
            warn!(%tenant_id, %e, "overlay.join: wg key uniqueness check failed");
            return;
        }
    }

    let self_node = match state
        .overlay_nodes
        .find_live_by_tenant_and_machine(tenant_id, &machine_id)
        .await
    {
        Ok(Some(existing)) => {
            let Some(id) = existing.id else { return };
            // Keep the existing stable name (DNS mustn't churn on rejoin);
            // backfill a freshly-deduped one for a pre-Phase-0 empty row.
            let name = if existing.name.is_empty() {
                unique_node_name(state, tenant_id, network_id, &base_name, Some(id)).await
            } else {
                existing.name.clone()
            };
            match state
                .overlay_nodes
                .rehydrate(
                    id,
                    &node_ref,
                    &name,
                    &wg_public_key,
                    key_epoch,
                    &endpoints,
                    supports_quic,
                    supports_relay_single,
                    supports_derp,
                    supports_forced_derp,
                    supports_server_relay_strategy,
                    supports_derp_floor,
                    supports_overlay_echo,
                    supports_org_relay,
                    &advertised_routes,
                    route_offer_withheld.as_deref(),
                )
                .await
            {
                Ok(n) => n,
                Err(e) => {
                    warn!(%tenant_id, %e, "overlay.join: rehydrate failed");
                    return;
                }
            }
        }
        Ok(None) => {
            // Fresh node — a per-network-unique name from the base label.
            let name = unique_node_name(state, tenant_id, network_id, &base_name, None).await;
            // Bounded retry: a `DuplicateKey` here means the address we were
            // handed is somehow already held by a live row (a poisoned free
            // pool). Before the retry this logged and returned, silently
            // locking the device out of the overlay for the daemon's lifetime;
            // now the bad entry is already consumed off the pool and the next
            // allocate gets a clean one.
            // FR-47 P5c — the network's address space. One block for every
            // network that has not grown, which is byte-for-byte the old
            // `network.max_host()` / `overlay_ip(network.cidr, …)` pair.
            let blocks = state.overlay_networks.block_list(&network).await;
            const CREATE_ATTEMPTS: usize = 3;
            let mut created = None;
            for attempt in 1..=CREATE_ATTEMPTS {
                // Multi-org P2a: the allocation is bounded by the network's
                // OWN block ceiling — exhaustion refuses the join loudly
                // instead of leasing into a neighbor tenant's block.
                //
                // FR-47 P5c: with multi-block on, a full space GROWS instead
                // of refusing — a block is appended at the tail, which adds
                // ordinals above everything already leased and moves no
                // existing device. Off (the default), this is exactly the
                // P2a call it replaces.
                let alloc = if state.settings.overlay.multi_block_enabled {
                    state
                        .overlay_networks
                        .allocate_host_or_grow(&network, state.settings.overlay.block_prefix)
                        .await
                } else {
                    state
                        .overlay_networks
                        .allocate_host(network_id, blocks.capacity())
                        .await
                };
                let host = match alloc {
                    Ok(h) => h,
                    Err(e) => {
                        // Exhaustion vs a store fault are different problems
                        // with different fixes: one needs a bigger block, the
                        // other needs a retry. `allocate_host` reports
                        // exhaustion as `Validation`, everything else as a
                        // driver error.
                        let reason = match e {
                            DaoError::Validation(_) => OverlayJoinRefusal::AddressSpaceExhausted,
                            _ => OverlayJoinRefusal::StoreUnavailable,
                        };
                        refuse(reason, format!("{e}")).await;
                        return;
                    }
                };
                // FR-47 P5c — resolve through the BLOCK LIST, not the
                // network's single cidr: past the first block, ordinal N does
                // not live in `network.cidr` at all. A single-block list is
                // byte-for-byte `overlay_ip`, so this is unchanged for every
                // network that has not grown.
                //
                // Re-read after a possible grow — `blocks` above was captured
                // before the allocation, so it would not know about a block
                // this very call appended.
                let blocks = state.overlay_networks.block_list(&network).await;
                let Some(ip) = blocks.ip_for_ordinal(host) else {
                    refuse(
                        OverlayJoinRefusal::NetworkUnavailable,
                        format!(
                            "the network's address space {:?} cannot express host \
                             ordinal {host}",
                            blocks.cidrs()
                        ),
                    )
                    .await;
                    return;
                };
                match state
                    .overlay_nodes
                    .create(NewOverlayNode {
                        tenant_id,
                        node_ref: node_ref.clone(),
                        network_id,
                        machine_id: machine_id.clone(),
                        name: name.clone(),
                        overlay_ip: ip.clone(),
                        wg_public_key: wg_public_key.clone(),
                        key_epoch,
                        endpoints: endpoints.clone(),
                        supports_quic,
                        supports_relay_single,
                        supports_derp,
                        supports_forced_derp,
                        supports_server_relay_strategy,
                        supports_derp_floor,
                        supports_overlay_echo,
                        supports_org_relay,
                        advertised_routes: advertised_routes.clone(),
                        route_offer_withheld: route_offer_withheld.clone(),
                    })
                    .await
                {
                    Ok(n) => {
                        created = Some(n);
                        break;
                    }
                    Err(DaoError::DuplicateKey(e)) if attempt < CREATE_ATTEMPTS => {
                        warn!(%tenant_id, overlay_ip = %ip, attempt, %e,
                            "overlay.join: allocated address is already taken; re-allocating");
                    }
                    Err(e) => {
                        warn!(%tenant_id, %e, "overlay.join: node create failed");
                        return;
                    }
                }
            }
            match created {
                Some(n) => n,
                None => return,
            }
        }
        Err(e) => {
            warn!(%tenant_id, %e, "overlay.join: node lookup failed");
            return;
        }
    };
    // FR-19 P3c — what the join said beyond the row, for the mint: whether
    // this is the device's PRIMARY org and which port its relay server
    // listens on. Pod-local by design (the mint runs on this pod, by tenant
    // affinity) and overwritten on every rejoin so nothing stale survives a
    // build or an org that stopped saying it.
    if let Some(id) = self_node.id {
        let previous = state.org_relay.join_extras(id);
        let listener_changed = state.org_relay.note_join(
            id,
            crate::org_relay::JoinExtras {
                org_primary,
                relay_port,
                relay_withdrawn: false,
                supports_org_relay_multi_candidate,
                supports_org_relay_discovery_cursor,
                supports_path_trial_v1,
                supports_path_backbone_v1,
                relay_backbone_ready,
                supports_backbone_only_v1,
            },
        );
        let mut withdrawn = crate::org_relay::revoke_backbone_node_sync(
            state,
            tenant_id,
            id,
            previous.supports_path_backbone_v1 && !supports_path_backbone_v1,
            previous.relay_backbone_ready && !relay_backbone_ready,
        );
        if (previous.supports_backbone_only_v1 && !supports_backbone_only_v1)
            || (previous.relay_backbone_ready && !relay_backbone_ready)
        {
            withdrawn.extend(crate::org_relay::revoke_line_node_sync(state, tenant_id, id));
        }
        if listener_changed && let NodeRef::Agent { agent_id } = &self_node.node_ref {
            // The authenticated node withdrew or replaced its actual listener.
            // Retire only sessions it SERVES, never its healthy direct peers.
            crate::org_relay::revoke_relay_agent(state, tenant_id, *agent_id, "listener_changed")
                .await;
        }
        for event in withdrawn {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                state.peer_relay_audit.record(event),
            )
            .await;
        }
    }

    let all = match state
        .overlay_nodes
        .list_active_in_network(tenant_id, network_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(%tenant_id, %e, "overlay.join: peer list failed");
            return;
        }
    };

    let epoch = next_epoch();
    // P9 — presence: ghost rows (clean-leave Offline, or an agent whose
    // heartbeat went stale) ship `reachable = false` in the FULL netmap
    // instead of resurrecting as dialable peers on every rejoin.
    let reach = reachability(state, &all).await;
    // Overlay ACL — the joiner's view is shaped for the JOINER. This half is
    // naturally per-recipient because the full netmap is built for exactly one
    // node; the delta fan-out below is the half that had to be un-broadcast.
    // FR-84 D5a — the shaping is `shape_full_netmap`, shared with the
    // device's own `/api/agent/self/devices` listing so that list can never
    // show a peer the netmap withholds.
    // MeshHarbor #21 — under `enforce`, give the joiner's own observation a
    // moment to land before shaping, or it is shown nobody until it rejoins.
    let iso = business_isolation::mode(state);
    let joiner_zone = business_isolation::joiner_zone(state, iso, &self_node).await;
    // GEO-05 — a device that roamed into the other zone ends here, on its
    // rejoin: its sessions that no longer fit are revoked at once rather
    // than at expiry. Under `warn` only once its zone is known, so a late
    // observation is not logged as a refusal.
    if (iso == business_isolation::Mode::Enforce || joiner_zone.is_some())
        && let NodeRef::Agent { agent_id } = &self_node.node_ref
    {
        crate::org_relay::recheck_zones(state, *agent_id, "zone_changed").await;
    }
    let lines = business_isolation::lines(state, iso, self_node.tenant_id).await;
    let ShapedNetmap {
        acl,
        self_src: joiner_src,
        peers,
    } = shape_full_netmap(state, &self_node, &all, &reach).await;

    // FR-40 — stamp what this device PRESENTED, as verified above, onto its
    // agent row: the server's own record of the device's current overlay
    // public key, and the half of a rotation the control plane can vouch for
    // (a `rc:agent.key_rotated` report is a claim; this join is the proof).
    // Stamped on every join, not only after a rotation, so the dashboard can
    // always show the key. Best-effort, off the netmap path.
    if let NodeIdentity::Agent(agent_id) = ident {
        let identity = roomler_ai_remote_control::models::OverlayIdentity {
            public_key: self_node.wg_public_key.clone(),
            key_epoch: self_node.key_epoch,
            joined_at: bson::DateTime::now(),
        };
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = st
                .fleet
                .agents
                .record_overlay_identity(tenant_id, agent_id, &identity)
                .await
            {
                warn!(%tenant_id, %agent_id, %e, "overlay.join: overlay_identity write failed");
            }
        });
    }

    // Overlay ACL — refresh the DERP relay allow table off the join path. A
    // join is when a NEW pubkey can enter the network, and the table is keyed by
    // pubkey, so it would otherwise stay stale (fail-open) for that node until
    // the next policy edit. Spawned: it re-reads every node, and the joiner must
    // not wait on that to get its netmap. #21 enforce needs the table for its
    // zones even when the ACL is off.
    if acl.gating() || iso == business_isolation::Mode::Enforce {
        let st = state.clone();
        tokio::spawn(async move {
            super::derp_acl::rebuild(&st, tenant_id, network_id).await;
        });
    }

    // Phase 2 MagicDNS — carry the tenant's DNS suffix + upstreams so the node
    // brings up its split-DNS resolver. Absent tenant settings → MagicDNS off.
    let (magic_domain, nameservers) = match state.tenants.base.find_by_id(tenant_id).await {
        Ok(t) => (
            t.settings.magic_dns_domain.clone(),
            t.settings.magic_dns_nameservers.clone(),
        ),
        Err(e) => {
            debug!(%tenant_id, %e, "overlay.join: tenant fetch for MagicDNS failed; DNS off");
            (None, Vec::new())
        }
    };

    // FR-47 P5d — the network's address space, read once for the netmap. Not
    // reused from the allocation path above: a node that REHYDRATED never went
    // near it, and a node that grew the space during its own join would hold a
    // list captured before the block it caused.
    let join_blocks = state.overlay_networks.block_list(&network).await;

    if let Some(id) = self_node.id {
        state.admission_nodes.insert(id, self_node.clone());
        // Before the netmap, so the node's first requests already count afresh.
        forget_restarted_grants(state, id, instance.as_deref());
    }

    // Full netmap → joiner.
    send_to_node(
        state,
        &self_node,
        ServerMsg::OverlayNetmap {
            org_relay_discovery: true,
            path_trial_v1: true,
            self_ip: self_node.overlay_ip.clone(),
            network: OverlayNetworkInfo {
                // FR-47 P5d — the block containing THIS node's own address,
                // because that is what its TUN netmask and NAT scope must be
                // derived from. `cidr_for_ip` returns the network's only block
                // for every network that has not grown, so this is byte-for-
                // byte the previous value there — which is every network until
                // `multi_block_enabled` is turned on.
                //
                // Falls back to the network's own cidr if the node's address
                // somehow inverts under no block (a row leased under a
                // since-changed range): the old value is a better answer than
                // an empty string.
                cidr: join_blocks
                    .cidr_for_ip(&self_node.overlay_ip)
                    .unwrap_or(&network.cidr)
                    .to_string(),
                cidrs: join_blocks.cidrs().to_vec(),
                org_relay_fallback_v1: true,
                org_relay_loss_v1: true,
                mtu: network.mtu,
                magic_domain,
                nameservers,
                // W2 MagicDNS — the joiner's own name, for self-resolution
                // (`<own-name>.<domain>`): peers exclude self, so without
                // this the node's resolver NXDOMAINs its own name.
                self_name: (!self_node.name.is_empty()).then(|| self_node.name.clone()),
                // NAT-traversal Phase B — the STUN endpoints a node queries to
                // gather its srflx candidates, derived from the configured
                // coturn workers (a `turn:host:port` UDP listener also answers
                // STUN Binding). Empty when TURN is unconfigured → srflx inert.
                stun_urls: stun_urls_from_turn(state),
                relay_probe_targets: crate::org_relay::probe_targets(state, &self_node).await,
                backbone_probe_targets: crate::org_relay::backbone_probe_targets(state, &self_node)
                    .await,
            },
            peers,
            epoch,
        },
    )
    .await;

    // Upsert delta → every peer, shaped PER RECIPIENT. The joiner is live by
    // construction. A recipient that may not see the joiner gets an explicit
    // `removes` rather than mere omission: omitting a peer (or shipping
    // `reachable: false`) is a no-op against an already-installed peer — only
    // the removes branch tears down the WG peer, its route and its carrier.
    for peer in all.iter().filter(|n| n.id != self_node.id) {
        let peer_src = overlay_source_of(state, peer).await;
        // The shaped peer here is the JOINER, whose identity we already have.
        let joiner_ingress = acl.enforcing().then_some(&joiner_src);
        // U2 — this recipient's edge is `peer → self_node` (the joiner).
        let verdict = server_relay_verdict(state, peer, &self_node);
        let recipient_zone = business_isolation::zone_of(state, iso, peer).await;
        let zones = Zones {
            mode: iso,
            recipient: recipient_zone,
            peer: joiner_zone,
            line: lines.connects(recipient_zone, joiner_zone)
                && business_isolation::rides_lines(state, peer),
            servers: lines.server_pair(peer, &self_node),
        };
        let (upserts, removes) =
            match shape_peer(&acl, &peer_src, &self_node, joiner_ingress, true, zones) {
                Some(mut u) => {
                    stamp_verdict(&mut u, verdict);
                    (vec![u], vec![])
                }
                None => (vec![], vec![self_node.id.unwrap_or_default()]),
            };
        send_to_node(
            state,
            peer,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts,
                removes,
            },
        )
        .await;
    }

    // P7 — a node that restarted mid-escalation lost its client-side DERP pin
    // (it lives in process memory); re-push any unexpired forced pairs so it
    // can't resume the broken TURN tier against a still-pinned peer. This is
    // the ONLY re-delivery path a single-relay DIALER has — it never sends a
    // relay_request, so it can't pick the pin back up reactively.
    repush_forced_pairs_on_join(state, &self_node).await;
}

/// Trickle: update the node's candidates → fan an upsert delta so peers
/// learn the new endpoints.
async fn handle_overlay_endpoints(
    state: &NetworkState,
    ident: NodeIdentity,
    candidates: Vec<String>,
) {
    let Some(self_node) = current_node(state, ident).await else {
        debug!(?ident, "overlay.endpoints before join; ignoring");
        return;
    };
    let Some(self_id) = self_node.id else { return };
    if let Err(e) = state
        .overlay_nodes
        .update_endpoints(self_id, &candidates)
        .await
    {
        warn!(%self_id, %e, "overlay.endpoints: update failed");
        return;
    }

    let mut updated = self_node;
    updated.endpoints = candidates;
    let epoch = next_epoch();
    fan_upsert_shaped(state, &updated, epoch, true).await;
}

/// NAT-traversal Phase B/C — the node trickled its server-reflexive (srflx)
/// candidates (and, Phase C, its probed `nat` type). Store them in the SEPARATE
/// `srflx_endpoints`/`srflx_nat` bucket (so a relay trickle can't clobber them)
/// → fan an upsert delta so peers learn the srflx + NAT type and can dial this
/// node directly through its NAT (skipping the punch only when both ends are
/// symmetric). Stored verbatim: the dial side already filters to public IPv4
/// (`direct::pick_public_endpoint`), and a peer only dials the srflx of an
/// ACL-authorised netmap peer — same trust model as `endpoints`/`lan_endpoints`.
async fn handle_overlay_srflx(
    state: &NetworkState,
    ident: NodeIdentity,
    candidates: Vec<String>,
    nat: Option<String>,
    udp_dialer_ok: Option<bool>,
) {
    let Some(self_node) = current_node(state, ident).await else {
        debug!(?ident, "overlay.srflx before join; ignoring");
        return;
    };
    let Some(self_id) = self_node.id else { return };
    // Dialer honesty — a latch flip is rare, role-flipping evidence; make it
    // greppable on the server the moment it lands.
    if udp_dialer_ok == Some(false) && self_node.udp_dialer_ok != Some(false) {
        tracing::info!(
            %self_id, node = %self_node.name,
            "overlay.srflx: node declared NOT dialer-capable (raw dials to relay-band ports don't land) — its pairs anchor from here"
        );
    }
    if let Err(e) = state
        .overlay_nodes
        .update_srflx_endpoints(self_id, &candidates, nat.as_deref(), udp_dialer_ok)
        .await
    {
        warn!(%self_id, %e, "overlay.srflx: update failed");
        return;
    }

    let mut updated = self_node;
    updated.srflx_endpoints = candidates;
    updated.srflx_nat = nat;
    updated.udp_dialer_ok = udp_dialer_ok;
    let epoch = next_epoch();
    fan_upsert_shaped(state, &updated, epoch, true).await;
    // GEO-04 — a trickled address can contradict the zone the node's
    // sessions were minted on.
    if business_isolation::mode(state) == business_isolation::Mode::Enforce
        && let NodeRef::Agent { agent_id } = &updated.node_ref
    {
        crate::org_relay::recheck_zones(state, *agent_id, "zone_conflict").await;
    }
}

/// Phase B (overlay v3) — store a node's measured capability vector and fan
/// the delta (peers re-read `NetmapPeer.caps` behind the freshness gate).
/// A CHANGED vector logs at INFO — it is exactly the evidence the selection
/// layers act on from PR-B3.
async fn handle_overlay_netcheck(
    state: &NetworkState,
    ident: NodeIdentity,
    caps: roomler_ai_remote_control::signaling::CapVectorWire,
) {
    let Some(self_node) = current_node(state, ident).await else {
        debug!(?ident, "overlay.netcheck before join; ignoring");
        return;
    };
    let Some(self_id) = self_node.id else { return };
    if self_node.caps != Some(caps) {
        tracing::info!(
            %self_id, node = %self_node.name,
            stun_udp = caps.stun_udp,
            relay_band_udp = ?caps.relay_band_udp,
            derp_ws_ok = caps.derp_ws_ok,
            "overlay.netcheck: capability vector changed"
        );
    }
    if let Err(e) = state
        .overlay_nodes
        .update_netcheck_caps(self_id, caps)
        .await
    {
        warn!(%self_id, %e, "overlay.netcheck: store failed");
        return;
    }
    let mut updated = self_node;
    updated.caps = Some(caps);
    updated.caps_measured_at = Some(bson::DateTime::now());
    let epoch = next_epoch();
    fan_upsert_shaped(state, &updated, epoch, true).await;
}

/// Phase B — the freshness gate: a vector older than 3× the measurement
/// cadence (20 min) is surfaced as ABSENT, so a stalled prober can never
/// stay fleet-authoritative (consumers then fall back to presence rules).
fn fresh_caps(node: &OverlayNode) -> Option<roomler_ai_remote_control::signaling::CapVectorWire> {
    const CAPS_FRESH_MS: i64 = 60 * 60 * 1000; // 3 × the 20-min cadence
    let at = node.caps_measured_at?;
    let age_ms = bson::DateTime::now().timestamp_millis() - at.timestamp_millis();
    if age_ms > CAPS_FRESH_MS {
        return None;
    }
    node.caps
}

/// Phase E — does this end need a TLS variant to reach coturn AT ALL?
/// Measured `!stun_udp` when a fresh vector exists, srflx-emptiness as the
/// legacy proxy otherwise. Feeds the region-level grant filter
/// (`select_pair_region`) so a TLS-only end is never granted a region
/// without a TLS listener.
fn needs_tls_relay(node: &OverlayNode) -> bool {
    fresh_caps(node)
        .map(|c| !c.stun_udp)
        .unwrap_or_else(|| node.srflx_endpoints.is_empty())
}

/// Graceful leave (or WS teardown): mark offline + tell peers to drop.
/// Security removal is not an ordinary offline event: recipients must drop
/// installed keys/routes, not retain a cached peer. Operates only on live
/// same-network join snapshots and bounded outbound queues; never queries DB.
pub fn revoke_agent_admission(state: &NetworkState, agent_id: ObjectId) {
    let victims: Vec<_> = state
        .admission_nodes
        .iter()
        .filter(|entry| matches!(entry.node_ref, NodeRef::Agent { agent_id: id } if id == agent_id))
        .map(|entry| entry.value().clone())
        .collect();
    for node in victims {
        let Some(id) = node.id else { continue };
        state.admission_nodes.remove(&id);
        let msg = ServerMsg::OverlayNetmapDelta {
            epoch: next_epoch(),
            upserts: vec![],
            removes: vec![id],
        };
        for peer in state
            .admission_nodes
            .iter()
            .filter(|p| p.tenant_id == node.tenant_id && p.network_id == node.network_id)
        {
            match peer.node_ref {
                NodeRef::Agent { agent_id } => {
                    let _ = state.fleet.rc_hub.send_to_agent(agent_id, msg.clone());
                }
                NodeRef::TunnelClient { tunnel_client_id } => {
                    if let Some(tx) = state.overlay_nodes_by_id.get(&tunnel_client_id) {
                        let _ = tx.try_send(msg.clone());
                    }
                }
            }
        }
        if let Ok(bytes) = BASE64.decode(&node.wg_public_key) {
            if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
                state.derp_registry.remove(&(node.network_id, key));
                if let Some(cancel) = state.derp_cancels.get(&(node.network_id, key)) {
                    cancel.notify_one();
                }
            }
        }
    }
}

pub async fn handle_overlay_leave(state: &NetworkState, ident: NodeIdentity) {
    let Some(self_node) = current_node(state, ident).await else {
        return; // never joined the overlay — nothing to tear down
    };
    let Some(self_id) = self_node.id else { return };
    state.admission_nodes.remove(&self_id);
    // FR-19 — a party that leaves takes its relay sessions with it: the
    // other member and the relay hear the revoke now rather than at the
    // session's absolute lifetime.
    crate::org_relay::revoke_node(state, self_id, "device_left").await;
    let _ = state
        .overlay_nodes
        .mark_status(self_id, AgentStatus::Offline)
        .await;
    let epoch = next_epoch();
    // Grey the row out; do NOT delete it. A `removes` delta made every
    // connected peer drop the node from `current_peers` entirely, so a host
    // that merely restarted VANISHED from `roomler peers` — while a host that
    // was already down when you joined rendered a normal `offline` row (it
    // arrives in the full netmap with P9 presence). Same server state, two
    // renderings, decided purely by when you happened to join.
    //
    // An offline upsert is also strictly less work for the receiver than the
    // remove was: `peer_config_from_netmap` drops `reachable = false` peers,
    // so peers stop dialing/probing this node IMMEDIATELY rather than at
    // their next rejoin — which is the same goal P9 pursued from the join
    // side. `removes` keeps its one honest producer, `release_overlay_node`:
    // a device that was actually released does disappear.
    fan_upsert_shaped(state, &self_node, epoch, false).await;
}

/// U1 — the requester's self-reported evidence riding a relay request. All
/// fields default-inert for legacy clients.
struct RelayRequestEvidence {
    current_kind: Option<String>,
    reason: Option<String>,
    derp_mux_failed: bool,
}

/// Metadata-only discovery, not the TURN/session allocation path. Source
/// identity comes from the authenticated socket, never a caller-supplied id.
async fn handle_org_relay_discover(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_node_id: ObjectId,
    request_id: u64,
    cursor: Option<roomler_ai_remote_control::signaling::OrgRelayDiscoveryCursorWire>,
) {
    let Some(requester) = current_node(state, ident).await else {
        return;
    };
    let Some(requester_id) = requester.id else {
        return;
    };
    // A reserved self-key on the existing limiter: mint candidates exclude
    // the requester, so this never consumes its requester->relay mint budget.
    // Bound before a peer lookup; arbitrary ids cannot create limiter keys.
    if !state
        .relay_rate_limiter
        .check_bounded(requester_id, requester_id, 6)
    {
        return;
    }
    let peer = match state.overlay_nodes.base.find_by_id(peer_node_id).await {
        Ok(peer) if peer.tenant_id == requester.tenant_id && peer_node_id != requester_id => peer,
        _ => return,
    };
    // Same pair visibility guard as relay_request, with unreadable policy
    // inputs failing closed rather than leaking discovery metadata.
    let Ok(acl) = try_load_acl(state, requester.tenant_id, PolicyLoad::Always).await else {
        return;
    };
    if acl.enforcing() {
        let Ok(source) = try_overlay_source_of(state, &requester).await else {
            return;
        };
        let routes = peer.effective_routes();
        if !evaluate_overlay(
            &acl.policies,
            &source,
            OverlayPeerRef {
                node_id: peer_node_id,
                overlay_ip: &peer.overlay_ip,
                approved_routes: &routes,
            },
        )
        .visible
        {
            return;
        }
    }
    crate::org_relay::discover(state, &requester, &peer, request_id, cursor).await;
}

/// ORG-only recovery is deliberately separate from TURN allocation/churn.
/// The authenticated socket supplies the requester; policy reads fail closed.
async fn handle_org_relay_fallback_request(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_node_id: ObjectId,
    request_id: u64,
) {
    let Some(requester) = current_node(state, ident).await else { return };
    let Some(requester_id) = requester.id else { return };
    // One bounded key per authenticated requester, distinct from discovery's
    // self-key and every real requester->relay mint key. No arbitrary peer
    // lookup can grow the limiter; retries cannot bypass the mint ceiling.
    // A client queues at most 64 per 60s. Two adjacent batches may arrive
    // inside one server window; keep query admission separate from mint's 30.
    if !state.relay_rate_limiter.check_bounded(requester_id, ObjectId::from_bytes([0; 12]), 128) {
        return;
    }
    let peer = match state.overlay_nodes.base.find_by_id(peer_node_id).await {
        Ok(peer) if peer.tenant_id == requester.tenant_id
            && peer_node_id != requester_id && peer.deleted_at.is_none() => peer,
        _ => return,
    };
    let pk = pair_key(requester_id, peer_node_id);
    if org_fallback_forced_derp(state, &pk) { return; }
    let Ok(acl) = try_load_acl(state, requester.tenant_id, PolicyLoad::Always).await else { return };
    if acl.enforcing() {
        let Ok(source) = try_overlay_source_of(state, &requester).await else { return };
        let routes = peer.effective_routes();
        if !evaluate_overlay(&acl.policies, &source, OverlayPeerRef {
            node_id: peer_node_id, overlay_ip: &peer.overlay_ip, approved_routes: &routes,
        }).visible { return; }
    }
    debug!(requester = %requester_id, peer = %peer_node_id, request_id,
        "org-relay: ORG-only fallback requested");
    crate::org_relay::maybe_mint_fallback(state, &requester, &peer).await;
}

/// Read-only: ORG queries never consume a TURN grant or clear/refresh its pin.
pub(crate) fn org_fallback_forced_derp(state: &NetworkState, pk: &str) -> bool {
    state.relay_pair_churn.get(pk).is_some_and(|pc| forced_active(&pc, Instant::now()))
}

/// Mint symmetric coturn creds for a relay leg to `peer_node_id`.
async fn handle_overlay_relay_request(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_node_id: ObjectId,
    evidence: RelayRequestEvidence,
) {
    let Some(self_node) = current_node(state, ident).await else {
        debug!(?ident, "overlay.relay_request before join; ignoring");
        return;
    };
    let Some(self_id) = self_node.id else { return };

    // Cross-tenant gate: the peer must be in the requester's tenant.
    let peer = match state.overlay_nodes.base.find_by_id(peer_node_id).await {
        Ok(p) if p.tenant_id == self_node.tenant_id => p,
        Ok(p) => {
            warn!(%self_id, peer = %peer_node_id, peer_tenant = %p.tenant_id,
                "overlay.relay_request across tenants; refusing");
            return;
        }
        Err(e) => {
            debug!(peer = %peer_node_id, %e, "overlay.relay_request: peer not found");
            return;
        }
    };

    // Overlay ACL — a TURN grant is a carrier for the very pair the netmap may
    // have just denied. Without this check a denied pair simply asks for relay
    // credentials and routes around the netmap, which would make the whole ACL
    // decorative. Enforced only in `Enforce` mode; `Warn` logs and grants.
    let acl = load_acl(state, self_node.tenant_id).await;
    if !matches!(acl.mode, OverlayAclMode::Off) {
        let src = overlay_source_of(state, &self_node).await;
        // FR-97 P0b — the same offered set the netmap fans.
        let routes = peer.effective_routes();
        let access = evaluate_overlay(
            &acl.policies,
            &src,
            OverlayPeerRef {
                node_id: peer_node_id,
                overlay_ip: &peer.overlay_ip,
                approved_routes: &routes,
            },
        );
        if !access.visible {
            if acl.enforcing() {
                warn!(%self_id, peer = %peer_node_id,
                    "overlay acl: relay_request for a peer this node may not reach; refusing");
                return;
            }
            debug!(%self_id, peer = %peer_node_id,
                "overlay acl [warn]: would refuse relay_request");
        }
    }

    // FR-19 P3c — offer an org relay for this pair when the org allows one.
    // Runs alongside the TURN grant below, never instead of it: the client
    // cascade (P4) prefers Org when a session arrives, and a pair without
    // one keeps exactly the path it has today.
    crate::org_relay::maybe_mint(state, &self_node, &peer).await;

    // #21 — no TURN or forced-DERP carrier across the mainland line, whatever
    // the ACL says. After the org offer, whose planner refuses (and audits)
    // the same pair on its own.
    if business_isolation::refuses_pair(state, &self_node, &peer, "turn grant").await {
        return;
    }

    let pair_key = pair_key(self_id, peer_node_id);

    // P7 — forced-DERP escalation: a request that lands shortly after a prior
    // grant for the same pair means that grant's carrier already died (the
    // corp-middlebox TURN-churn signature). Count those grant→re-request
    // cycles; past the threshold, push `rc:overlay.force_derp` to BOTH ends
    // (never grant-borne — the single-relay DIALER never requests, so it
    // would never see a grant field) and skip the TURN grant entirely. Gated
    // on BOTH ends advertising the capability, so a mixed-version pair can
    // never split tiers.
    // U1 — the silent-veto healer: a requester whose `/derp` mux open FAILED
    // cannot honor a pin, so an active pin for this pair is a hard dark
    // window (client ignores it, server refuses TURN for the TTL). Clear the
    // pin and fall through to a normal grant; the capability gate below also
    // refuses NEW escalations while the flag rides.
    if evidence.derp_mux_failed
        && let Some(mut pc) = state.relay_pair_churn.get_mut(&pair_key)
        && forced_active(&pc, Instant::now())
    {
        pc.forced_until = None;
        pc.forced_derp_url = None;
        warn!(
            %pair_key, requester = %self_id,
            "overlay relay: requester reports its /derp mux failed — clearing the forced-DERP pin (silent-veto healer)"
        );
    }
    let pair_supports_forced_derp = forced_derp_enabled()
        && !evidence.derp_mux_failed
        && self_node.supports_forced_derp
        && self_node.supports_derp
        && peer.supports_forced_derp
        && peer.supports_derp;
    if pair_supports_forced_derp
        && note_relay_request(state, &pair_key, evidence.current_kind.as_deref())
    {
        let derp_url = pair_derp_url(state, &self_node, &peer, &pair_key);
        tracing::info!(
            %pair_key, requester = %self_id, peer = %peer_node_id,
            replacing = evidence.current_kind.as_deref().unwrap_or("-"),
            reason = evidence.reason.as_deref().unwrap_or("-"),
            relay = derp_url.as_deref().unwrap_or("central"),
            "overlay relay: TURN churn threshold — escalating pair to forced DERP"
        );
        push_pair_pin(
            state,
            (&self_node, self_id),
            (&peer, peer.id.unwrap_or(peer_node_id)),
            &pair_key,
            derp_url,
        )
        .await;
        return;
    }

    // Both ends derive identical creds from the symmetric pair_key, AND the
    // broker pins them to a single deterministic coturn worker (see
    // `overlay_ice_servers`) so the relay-to-relay leg is an intra-worker
    // hairpin that never crosses buildhost's dual-public-IP SNAT.
    let ice_servers = overlay_ice_servers(
        state,
        &pair_key,
        Some(self_node.tenant_id),
        self_node.relay_home.as_deref(),
        peer.relay_home.as_deref(),
        needs_tls_relay(&self_node) || needs_tls_relay(&peer),
    )
    .await;

    // U1 — the evidence line for grants (the escalation path logs its own):
    // a died-carrier refresh names what died and why; a fresh establishment
    // carries neither. INFO because a died-DERP re-grant is exactly the
    // one-way-loop evidence the split-brain diagnosis greps for.
    if evidence.current_kind.is_some() || evidence.reason.is_some() {
        tracing::info!(
            %pair_key, requester = %self_id,
            replacing = evidence.current_kind.as_deref().unwrap_or("-"),
            reason = evidence.reason.as_deref().unwrap_or("-"),
            "overlay relay: re-granting after a died carrier"
        );
    }
    // P7 — arm the churn detector: a re-request for this pair arriving after
    // this grant (past the dedup gap) counts as one churn cycle. Armed before
    // the send so `pair_key` can move into the grant.
    note_grant_sent(state, &pair_key);
    send_to_node(
        state,
        &self_node,
        ServerMsg::OverlayRelayGrant {
            ice_servers,
            peer_node_id: peer.id.unwrap_or(peer_node_id),
            pair_key,
        },
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// P7 — forced-DERP escalation (per-pair TURN-churn tracking)
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding window a pair's churn cycles are counted within.
const CHURN_WINDOW: Duration = Duration::from_secs(600);
/// Grant→re-request cycles inside [`CHURN_WINDOW`] that trigger escalation.
/// At the client's ~30 s teardown/re-request cadence this is ~2 min of
/// sustained churn — fast enough to matter, slow enough that a transient
/// blip never escalates.
const CHURN_CYCLES_TO_ESCALATE: u32 = 3;
/// How long an escalated pair stays pinned to DERP (server TTL, mirrored to
/// both clients in `ttl_ms`). Stands alone — a forced pair stops sending
/// relay_requests, so nothing refreshes it; expiry simply lets the next
/// establishment cycle try TURN again.
const FORCED_DERP_TTL: Duration = Duration::from_secs(1800);
/// A request arriving within this gap of the pair's last grant is a client
/// retry/duplicate, not a died-carrier cycle.
const CYCLE_MIN_GAP: Duration = Duration::from_secs(5);
/// Hard cap on tracked pairs — a `retain` sweep drops stale entries past it
/// (reset-on-access TTLs alone never evict idle keys).
const CHURN_MAP_CAP: usize = 10_000;

/// P7 — per-pair TURN-relay churn state (see `AppState::relay_pair_churn`).
#[derive(Debug, Default)]
pub struct PairChurn {
    /// Completed grant→re-request cycles inside the current window.
    cycles: u32,
    /// When the current counting window opened.
    window_start: Option<Instant>,
    /// When the last TURN grant for this pair was sent; a re-request after it
    /// (past [`CYCLE_MIN_GAP`]) = one churn cycle. Cleared once consumed so a
    /// burst of retries counts once per grant.
    last_grant_at: Option<Instant>,
    /// While unexpired, the pair is escalated (mirrors the client-side pin).
    forced_until: Option<Instant>,
    /// Multi-region DERP: the regional relay URL this pair was escalated onto
    /// (`None` = central `/derp`). Stored at escalation so every repush hands
    /// both ends the SAME URL for the pin's whole lifetime.
    forced_derp_url: Option<String>,
}

/// P7 — is this pair currently under an unexpired forced-DERP TTL?
fn forced_active(pc: &PairChurn, now: Instant) -> bool {
    pc.forced_until.is_some_and(|t| now < t)
}

/// P7 — pure decision core: note a relay_request for a pair at `now`.
/// Returns `true` when the pair should be (or already is) escalated — the
/// caller then pushes `force_derp` to both ends instead of granting. Kept
/// state-free of `AppState` so the threshold arithmetic is unit-tested
/// directly.
pub fn churn_note_request(pc: &mut PairChurn, now: Instant) -> bool {
    if forced_active(pc, now) {
        // Mid-TTL re-request = a client that restarted and lost its pin;
        // re-escalate it (the peer keeps its own pin).
        return true;
    }
    pc.forced_until = None;
    let Some(granted) = pc.last_grant_at else {
        // No grant on record (fresh pair / post-restart / post-expiry first
        // contact) — a first request is never churn.
        return false;
    };
    if now.duration_since(granted) < CYCLE_MIN_GAP {
        return false; // client retry burst, not a died carrier
    }
    pc.last_grant_at = None; // consume: one cycle per grant
    match pc.window_start {
        Some(ws) if now.duration_since(ws) <= CHURN_WINDOW => pc.cycles += 1,
        _ => {
            pc.window_start = Some(now);
            pc.cycles = 1;
        }
    }
    if pc.cycles >= CHURN_CYCLES_TO_ESCALATE {
        pc.forced_until = Some(now + FORCED_DERP_TTL);
        pc.cycles = 0;
        pc.window_start = None;
        return true;
    }
    false
}

/// P7 — [`churn_note_request`] for a request that names the carrier it
/// replaces. An ORG carrier is not TURN: its session ended because the server
/// revoked it or its relay left, and the ORG planner has already judged that
/// (loss pin, next relay). So such a request counts no cycle and consumes no
/// grant; a standing pin still answers it.
pub fn churn_note_replacement(pc: &mut PairChurn, now: Instant, replacing: Option<&str>) -> bool {
    if replacing == Some("org") {
        return forced_active(pc, now);
    }
    churn_note_request(pc, now)
}

/// P7 — kill-switch: `ROOMLER__OVERLAY__FORCED_DERP=0|false` disables the
/// escalation entirely (default ON — it is additionally gated on both ends'
/// advertised capability and the churn threshold).
fn forced_derp_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("ROOMLER__OVERLAY__FORCED_DERP").as_deref(),
            Ok("0") | Ok("false") | Ok("off")
        )
    })
}

/// P7 — record + decide for a live request (the impure wrapper around
/// [`churn_note_replacement`]), with the size-capped stale sweep.
fn note_relay_request(state: &NetworkState, pair_key: &str, replacing: Option<&str>) -> bool {
    let now = Instant::now();
    if state.relay_pair_churn.len() > CHURN_MAP_CAP {
        state.relay_pair_churn.retain(|_, pc| {
            forced_active(pc, now)
                || pc
                    .window_start
                    .is_some_and(|ws| now.duration_since(ws) <= CHURN_WINDOW)
                || pc
                    .last_grant_at
                    .is_some_and(|g| now.duration_since(g) <= CHURN_WINDOW)
        });
    }
    let mut entry = state
        .relay_pair_churn
        .entry(pair_key.to_string())
        .or_default();
    churn_note_replacement(entry.value_mut(), now, replacing)
}

/// U1 — pure arming rule: stamp `last_grant_at` ONLY when unarmed.
///
/// The old unconditional re-stamp had a starvation hole: a sub-
/// [`CYCLE_MIN_GAP`] re-request is not counted (correct — retry burst), but
/// the grant it still received re-stamped `last_grant_at`, pushing the gap
/// anchor forward — so two ends alternating requests faster than the gap
/// could churn indefinitely without EVER counting a cycle. Anchoring on the
/// FIRST grant of a burst bounds the dedup window to one burst: a "burst"
/// that outlives the gap counts, as it should (a client re-requesting for
/// longer than the dedup window is not deduplicating, it is churning).
pub fn arm_grant(pc: &mut PairChurn, now: Instant) {
    if pc.last_grant_at.is_none() {
        pc.last_grant_at = Some(now);
    }
}

/// P7 — arm the cycle detector after sending a TURN grant.
fn note_grant_sent(state: &NetworkState, pair_key: &str) {
    if let Some(mut pc) = state.relay_pair_churn.get_mut(pair_key) {
        arm_grant(pc.value_mut(), Instant::now());
    } else {
        state.relay_pair_churn.insert(
            pair_key.to_string(),
            PairChurn {
                last_grant_at: Some(Instant::now()),
                ..Default::default()
            },
        );
    }
}

/// P7 — a join under a new process instance is a restart: the node's armed
/// TURN grants were for carriers that died with the old process, so its
/// fresh requests must not count as churn against them (field 2026-10-27,
/// rf-e17c20cfdb71: a relay restarted twice and its three pairs were pinned
/// to DERP for 30 min). Its pairs keep only a standing pin, which the rejoin
/// re-push re-delivers. A reconnect (same instance), a first-seen instance
/// and an older node (none) change nothing.
fn forget_restarted_grants(state: &NetworkState, node_id: ObjectId, instance: Option<&str>) {
    let Some(instance) = instance else { return };
    let previous = state.node_instances.insert(node_id, instance.to_owned());
    if previous.is_none_or(|p| p == instance) {
        return;
    }
    let hex = node_id.to_hex();
    for mut e in state.relay_pair_churn.iter_mut() {
        if e.key().split(':').any(|k| k == hex) {
            let pc = e.value_mut();
            pc.last_grant_at = None;
            pc.cycles = 0;
            pc.window_start = None;
        }
    }
}

/// P7 — on (re)join, re-push any unexpired forced-DERP pins involving this
/// node (its in-process pin died with the old process; the single-relay
/// DIALER has no reactive path to relearn it). Scans the pair map — tiny in
/// practice (forced pairs are rare + capped).
async fn repush_forced_pairs_on_join(state: &NetworkState, node: &OverlayNode) {
    if !forced_derp_enabled() || !node.supports_forced_derp || !node.supports_derp {
        return;
    }
    let Some(self_id) = node.id else { return };
    let self_hex = self_id.to_hex();
    let now = Instant::now();
    let peers: Vec<(ObjectId, u64, Option<String>)> = state
        .relay_pair_churn
        .iter()
        .filter_map(|e| {
            // Remaining (not full) TTL, so both ends keep expiring together.
            let remaining = e.value().forced_until?.checked_duration_since(now)?;
            let (a, b) = e.key().split_once(':')?;
            let peer = if a == self_hex {
                ObjectId::parse_str(b).ok()?
            } else if b == self_hex {
                ObjectId::parse_str(a).ok()?
            } else {
                return None;
            };
            Some((
                peer,
                remaining.as_millis() as u64,
                e.value().forced_derp_url.clone(),
            ))
        })
        .collect();
    for (peer_id, ttl_ms, derp_url) in peers {
        tracing::info!(node = %self_id, peer = %peer_id, ttl_ms,
            relay = derp_url.as_deref().unwrap_or("central"),
            "overlay relay: re-pushing forced-DERP pin on rejoin");
        send_to_node(
            state,
            node,
            ServerMsg::OverlayForceDerp {
                peer_node_id: peer_id,
                ttl_ms,
                derp_url,
            },
        )
        .await;
    }
}

/// Multi-region DERP: the pair's regional relay, from the same sticky region
/// the TURN grants use (symmetric — the server computes once and pushes the
/// SAME url to both ends). `None` = central.
fn pair_derp_url(
    state: &NetworkState,
    a: &OverlayNode,
    b: &OverlayNode,
    pair_key: &str,
) -> Option<String> {
    sticky_pair_region(
        &state.turn_map,
        &state.relay_load,
        pair_key,
        a.relay_home.as_deref(),
        b.relay_home.as_deref(),
        needs_tls_relay(a) || needs_tls_relay(b),
    )
    .and_then(|region| {
        state
            .turn_map
            .specs
            .iter()
            .find(|s| s.id == region)
            .and_then(|s| s.derp_url.clone())
    })
}

/// P7 — push the pair's standing pin to BOTH ends and re-stamp their
/// verdicts. `derp_url` is stored on the churn entry so every repush during
/// this pin reuses it.
async fn push_pair_pin(
    state: &NetworkState,
    (a, a_id): (&OverlayNode, ObjectId),
    (b, b_id): (&OverlayNode, ObjectId),
    pair_key: &str,
    derp_url: Option<String>,
) {
    // U1 — a mid-pin re-push must carry the REMAINING TTL, not restart
    // the clock: the escalation path re-pushed the full window on every
    // mid-pin re-request while the server's own `forced_until` stood
    // still, so the two ends' pins ratcheted apart (the join re-push
    // already used remaining; now both do). A FRESH escalation just set
    // `forced_until = now + FORCED_DERP_TTL`, so the same read yields
    // the full window there.
    let ttl_ms = state
        .relay_pair_churn
        .get(pair_key)
        .and_then(|pc| pc.forced_until)
        .map(|until| until.saturating_duration_since(Instant::now()))
        .filter(|d| !d.is_zero())
        .unwrap_or(FORCED_DERP_TTL)
        .as_millis() as u64;
    if let Some(mut pc) = state.relay_pair_churn.get_mut(pair_key) {
        pc.forced_derp_url = derp_url.clone();
    }
    send_to_node(
        state,
        a,
        ServerMsg::OverlayForceDerp {
            peer_node_id: b_id,
            ttl_ms,
            derp_url: derp_url.clone(),
        },
    )
    .await;
    send_to_node(
        state,
        b,
        ServerMsg::OverlayForceDerp {
            peer_node_id: a_id,
            ttl_ms,
            derp_url,
        },
    )
    .await;
    // D2 (overlay v3) — the pin through the VERDICT channel too: both
    // ends get the other's row re-stamped NOW (`pinned` resolves to
    // verdict=Derp inside `server_relay_verdict`), so a D1 consumer
    // flips tiers off the stamp at escalation time instead of waiting
    // for the next incidental trickle to re-fan it. `OverlayForceDerp`
    // above stays for wire compat (pre-D1 nodes) and as the TTL
    // carrier; when the pin lapses the next fan re-stamps the
    // capability-derived verdict and the pair regrades per Phase C.
    fan_pair_verdicts(state, a, b).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORG loss — a lossy org-relay carrier fails the pair's relay tier
// ─────────────────────────────────────────────────────────────────────────────

/// A window must span this many of the peer's packets to be judged.
const ORG_LOSS_MIN_PACKETS: u64 = 1000;
/// The share of a window's packets (percent) whose loss fails the pair's ORG
/// carrier. Loss-based TCP over a 50 ms path is held near 1.4 Mbit/s at 3%
/// loss and 0.7 Mbit/s at 8% (Mathis). Field, 2026-10-26: an org relay whose
/// ingress lost 7–10% carried ~2 Mbit/s, while DERP through the same host
/// carried 23–33.
const ORG_LOSS_FAIL_PCT: u64 = 5;
/// How long a failed pair stays pinned to DERP: a third of the churn pin,
/// because a relay's ingress loss follows its load. The members' ladder then
/// measures ORG again, at the cost of one ~30 s window on it.
const ORG_LOSS_PIN_TTL: Duration = Duration::from_secs(600);

/// Pure: does a window of `packets` with `lost` of them missing fail the
/// pair's ORG carrier? A smaller window fails too when its loss is clearly
/// over the line (`tunnel_core::loss::loss_clearly_at_least`): a member closes one
/// early for a light stream, which needs minutes for 1000 packets.
pub fn org_loss_fails(packets: u64, lost: u64) -> bool {
    (packets >= ORG_LOSS_MIN_PACKETS
        && lost.min(packets).saturating_mul(100) >= packets.saturating_mul(ORG_LOSS_FAIL_PCT))
        || tunnel_core::loss::loss_clearly_at_least(
            packets,
            lost,
            ORG_LOSS_FAIL_PCT as f64,
        )
}

/// Pure: pin a pair for an ORG loss verdict. Never shortens a pin already
/// standing, such as a churn pin's 30 minutes.
pub fn org_loss_pin(pc: &mut PairChurn, now: Instant) {
    let until = now + ORG_LOSS_PIN_TTL;
    if pc.forced_until.is_none_or(|t| t < until) {
        pc.forced_until = Some(until);
    }
}

/// Kill switch: `ROOMLER__OVERLAY__ORG_LOSS_PIN=0|false|off` keeps every ORG
/// carrier whatever it loses; reports are then logged only. Default ON. The
/// pin also needs [`forced_derp_enabled`] and both ends' DERP capability.
fn org_loss_pin_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("ROOMLER__OVERLAY__ORG_LOSS_PIN").as_deref(),
            Ok("0") | Ok("false") | Ok("off")
        )
    })
}

/// A member's ORG loss report (`rc:overlay.org_relay_loss`): one closed
/// window of the stream its peer sends over their session. A window that
/// [`org_loss_fails`] marks that relay lossy for the pair for
/// [`ORG_LOSS_PIN_TTL`], and the session is revoked (audited
/// `org_relay_lossy`). If the planner still finds a relay for the pair (in
/// its zone, granted, live), the pair is minted there at once. Only when none
/// is left does it fail the pair's relay tier the way TURN churn does (P7):
/// both ends are pinned to DERP for the same TTL, and every mint path
/// refuses the pair until the pin lapses. Then the members' ladder climbs
/// back to ORG and the next windows measure it again. Direct re-upgrade is
/// untouched.
///
/// The server decides, over the measured counts. A report counts only for
/// the reporter's own live session (anything else is dropped), and one
/// member's report is enough: the loss is in its peer's direction, and one
/// crippled direction cripples the pair's TCP both ways, through its ACKs.
/// A member can fail only its own pair's ORG tier, which it could already
/// do by dropping packets.
async fn handle_org_relay_loss(
    state: &NetworkState,
    ident: NodeIdentity,
    peer_node_id: ObjectId,
    vni: u32,
    packets: u64,
    lost: u64,
) {
    let Some(reporter) = current_node(state, ident).await else { return };
    let Some(reporter_id) = reporter.id else { return };
    let loss_pct = format!("{:.1}", lost.min(packets) as f64 * 100.0 / packets.max(1) as f64);
    let Some(session) = crate::org_relay::reported_session(state, reporter_id, peer_node_id, vni)
    else {
        debug!(reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            "org-relay: loss report names no live session of the reporter; dropped");
        return;
    };
    if !org_loss_fails(packets, lost) {
        debug!(reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            "org-relay: loss report under the threshold; the carrier stays");
        return;
    }
    // #21 — a cross-border pair has no other carrier to move to: DERP, TURN
    // and a one-hop relay are refused across the line by rule.
    if session.line.is_some() {
        tracing::info!(reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            "overlay relay: cross-border line lossy, kept: nothing else may carry the pair");
        return;
    }
    if !matches!(
        crate::org_relay::peer_relay_mode(state, reporter.tenant_id).await,
        PeerRelayMode::On | PeerRelayMode::Auto
    ) {
        return;
    }
    let peer = match state.overlay_nodes.base.find_by_id(peer_node_id).await {
        Ok(p) if p.tenant_id == reporter.tenant_id && p.deleted_at.is_none() => p,
        _ => return,
    };
    let pk = session.pair_key.clone();
    if !org_loss_pin_enabled() {
        tracing::info!(%pk, reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            "overlay relay: ORG carrier lossy, kept: the loss pin is switched off");
        return;
    }
    // Another relay in the zone first. This one sits out the pin for the
    // pair; if the planner still finds a relay, the pair moves there rather
    // than to DERP. The revoke frees the lossy relay's session first, so the
    // mint is the pair's only live one.
    let lossy_relay = session.relay.node_id;
    state
        .org_relay
        .mark_lossy(&pk, lossy_relay, Instant::now() + ORG_LOSS_PIN_TTL);
    if let Some(next) = crate::org_relay::next_relay(state, &reporter, &peer).await {
        tracing::info!(%pk, reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            %lossy_relay, next_relay = %next,
            "overlay relay: ORG carrier lossy, moving the pair to another relay for {}s",
            ORG_LOSS_PIN_TTL.as_secs());
        crate::org_relay::revoke_where(state, "org_relay_lossy", |s| {
            s.pair_key == pk && s.vni == session.vni && s.generation == session.generation
        })
        .await;
        crate::org_relay::maybe_mint(state, &reporter, &peer).await;
        return;
    }
    if !(forced_derp_enabled()
        && reporter.supports_forced_derp
        && reporter.supports_derp
        && peer.supports_forced_derp
        && peer.supports_derp)
    {
        tracing::info!(%pk, reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
            "overlay relay: ORG carrier lossy, kept: no other relay, and an end cannot ride DERP");
        return;
    }
    // Pin first, so each member moves straight to DERP on the pin; the
    // revoke that follows then finds its session already gone, and frees
    // the relay's.
    org_loss_pin(
        state.relay_pair_churn.entry(pk.clone()).or_default().value_mut(),
        Instant::now(),
    );
    let derp_url = pair_derp_url(state, &reporter, &peer, &pk);
    tracing::info!(%pk, reporter = %reporter_id, peer = %peer_node_id, vni, packets, %loss_pct,
        relay = derp_url.as_deref().unwrap_or("central"),
        "overlay relay: ORG carrier lossy, pinning the pair to DERP for {}s",
        ORG_LOSS_PIN_TTL.as_secs());
    push_pair_pin(state, (&reporter, reporter_id), (&peer, peer_node_id), &pk, derp_url).await;
    crate::org_relay::revoke_where(state, "org_relay_lossy", |s| {
        s.pair_key == pk && s.vni == session.vni && s.generation == session.generation
    })
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Re-fan a node's current netmap entry to its peers as an upsert delta — used
/// when something OUT of band changes the node's wire shape (Phase 1: an admin
/// approving/revoking its subnet `routes`), so peers pick it up immediately
/// instead of waiting for the next join. Best-effort.
pub async fn refan_node(state: &NetworkState, node: &OverlayNode) {
    // P9 — an out-of-band refan (admin route approval) can target a node
    // that is currently offline; carry its real presence, not a blanket true.
    let reach = reachability(state, std::slice::from_ref(node)).await;
    fan_upsert_shaped(state, node, next_epoch(), is_reachable(&reach, node)).await;
}

/// Propagate a fleet-level device rename onto the device's live overlay node:
/// derive the new MagicDNS label from the new display name, de-dup it within
/// the network (excluding the node itself, so a no-op rename keeps its label),
/// write it, and re-fan the node so every peer's netmap + MagicDNS resolve the
/// new name immediately.
///
/// Returns the label now on the node (`Some(new_or_unchanged_label)`) or
/// `None` when even the index-race retry lost — the fleet rename stands
/// either way, only the DNS label kept its old value.
///
/// ⚠️ Deliberately does NOT push a full netmap at the renamed node itself:
/// `self_name` rides only `ServerMsg::OverlayNetmap` (join-time), and the
/// client's mid-session full-netmap arm is field-untested. The device serves
/// its own new self-name after its next reconnect; its PEERS see it live.
pub async fn propagate_node_rename(
    state: &NetworkState,
    node: &OverlayNode,
    new_display_name: &str,
) -> Option<String> {
    let node_id = node.id?;
    let base = dns_label(new_display_name, &node.machine_id);
    let wanted =
        unique_node_name(state, node.tenant_id, node.network_id, &base, Some(node_id)).await;
    if wanted == node.name {
        return Some(wanted); // label unchanged — nothing to write or fan
    }
    let updated = match state.overlay_nodes.set_name(node_id, &wanted).await {
        Ok(n) => n,
        Err(DaoError::DuplicateKey(_)) => {
            // Lost the in-flight race the best-effort de-dup couldn't see —
            // an epoch suffix is unique by construction.
            let fallback = format!("{base}-{}", next_epoch());
            match state.overlay_nodes.set_name(node_id, &fallback).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(%e, node = %node_id.to_hex(),
                        "overlay rename lost the unique-name race twice — keeping the old DNS label");
                    return None;
                }
            }
        }
        Err(e) => {
            tracing::warn!(%e, node = %node_id.to_hex(),
                "overlay rename failed — keeping the old DNS label");
            return None;
        }
    };
    let label = updated.name.clone();
    tracing::info!(node = %node_id.to_hex(), old = %node.name, new = %label,
        "overlay node renamed — refanning peers");
    refan_node(state, &updated).await;
    Some(label)
}

/// What a successful [`release_overlay_node`] freed — for the route responses
/// and the operator-facing log line.
pub struct ReleasedNode {
    pub node_id: ObjectId,
    pub name: String,
    pub overlay_ip: String,
    /// `false` when the host number could NOT be returned to the pool (CIDR
    /// drift, or the pool is at its cap). The release still succeeded — the
    /// address just leaks out of the `/10` instead of being recycled.
    pub host_recycled: bool,
}

/// Release ONE overlay node: evict it from the mesh and return its host number
/// to the tenant's free pool. The single writer behind every removal path
/// (agent DELETE, admin evict, tunnel-client DELETE).
///
/// Idempotent — `None` means the node was already released and the caller must
/// do nothing further.
///
/// THE ORDER IS LOAD-BEARING:
///
/// 1. Read the peer list FIRST, while the node is still live. Afterwards it is
///    gone from `list_active_in_network`.
///
/// 2. CAS-tombstone via [`OverlayNodeDao::release`]. Winning that CAS is the
///    release TOKEN: only the winner proceeds, so two concurrent removal paths
///    can never both pool the same host number.
///
/// 3. Return the host to the pool ONLY AFTER the tombstone commits. NEVER
///    before — a crash between "pooled" and "tombstoned" would hand the address
///    to a second joiner while the first row still holds it, and the unique
///    `(tenant, network, overlay_ip)` index would then lock that joiner out of
///    the overlay for good. A crash in this order merely LEAKS one host number
///    out of a 4.2 M-address `/10`.
///
/// 4. Fan `removes` to the pinned peers, and to the released node itself so a
///    prune-aware client tears its carriers down instead of squatting an
///    address that is now recyclable.
pub async fn release_overlay_node(
    state: &NetworkState,
    node: &OverlayNode,
    reason: &str,
) -> Option<ReleasedNode> {
    let node_id = node.id?;

    // 1 — peers, read while the node is still live.
    let peers = state
        .overlay_nodes
        .list_active_in_network(node.tenant_id, node.network_id)
        .await
        .unwrap_or_default();

    // 2 — CAS. Losing it means someone else already released this node: do NOT
    //     re-fan and do NOT re-pool.
    let before = match state.overlay_nodes.release(node_id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            debug!(%node_id, "overlay release: already released; no-op");
            return None;
        }
        Err(e) => {
            warn!(%node_id, %e, "overlay release: tombstone failed");
            return None;
        }
    };
    // FR-19 — trigger 4 of §7: a removed device's relay sessions (as member
    // or as relay) are torn down by push, not left to expire.
    crate::org_relay::revoke_node(state, node_id, "device_removed").await;

    // 3 — pool the host. Best-effort: a failure leaks, never conflicts.
    let host = state
        .overlay_networks
        .base
        .find_by_id(before.network_id)
        .await
        .ok()
        .and_then(|net| net.host_of_ip(&before.overlay_ip));
    let host_recycled = match host {
        Some(h) => state
            .overlay_networks
            .release_host(before.network_id, h)
            .await
            .unwrap_or(false),
        None => {
            warn!(%node_id, ip = %before.overlay_ip,
                "overlay release: address is not derivable from the network CIDR; not recycling");
            false
        }
    };

    // 4 — tell the peers, then the node itself.
    let epoch = next_epoch();
    fan_delta_to(state, &peers, Some(node_id), epoch, vec![], vec![node_id]).await;
    send_to_node(
        state,
        &before,
        ServerMsg::OverlayNetmapDelta {
            epoch,
            upserts: vec![],
            removes: vec![node_id],
        },
    )
    .await;
    // #1186 — the two sends above reach only sockets homed on THIS pod, and
    // two removal initiators are not tenant-affine: `self/unenroll` has no
    // tenant in its path (IP-hashed by the LB) and the FR-51 reaper runs on
    // the NX-claim winner. Field-measured 2026-09-01: a live peer with a
    // stable WS on the affine pod never heard a self-unenroll's removes and
    // kept WG-handshaking at the dead peer until its next rejoin. Broadcast
    // the event so every OTHER pod re-fans to the sockets it holds — the
    // self-echo is filtered at the subscriber, a duplicate removes at a
    // client is an idempotent no-op, and a pod with no sockets fans to
    // nobody. Joins never need this: an upsert rides the joiner's own
    // tenant-affine WS.
    roomler_ai_mod_fleet::ctrl::publish_rc_ctrl(
        state,
        "overlay_removes",
        serde_json::json!({
            "tenant_id": before.tenant_id.to_hex(),
            "network_id": before.network_id.to_hex(),
            "node_id": node_id.to_hex(),
            "epoch": epoch,
        }),
    )
    .await;

    // Drop any DERP registration this node holds. Already inert (it is keyed by
    // pubkey and no peer carries this node's key any more, and `handle_derp_socket`
    // resolves through the live-only `current_node`), but tidy. C-5: also fire
    // the cancel so the socket actually closes (its teardown then releases the
    // directory record; a re-dial fails registration — the node row is gone).
    if let Ok(pk) = BASE64.decode(&before.wg_public_key)
        && let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice())
    {
        state.derp_registry.remove(&(before.network_id, pk));
        if let Some(cancel) = state.derp_cancels.get(&(before.network_id, pk)) {
            cancel.notify_one();
        }
    }

    tracing::info!(
        tenant_id = %before.tenant_id, %node_id, name = %before.name,
        overlay_ip = %before.overlay_ip, host_recycled, reason,
        "overlay node released"
    );

    Some(ReleasedNode {
        node_id,
        name: before.name,
        overlay_ip: before.overlay_ip,
        host_recycled,
    })
}

/// #1186 — re-fan a removal that was initiated on ANOTHER pod to the sockets
/// THIS pod holds. The counterpart of the `overlay_removes` publish in
/// [`release_overlay_node`]; parsing is deliberately fail-silent (a malformed
/// envelope is a bug at the publisher, and dropping it costs one push that
/// the peer's next rejoin heals — the pre-#1186 status quo).
///
/// The removed node's row is already tombstoned when this runs, so the peer
/// list cannot contain it; the tombstone is still read so the released node
/// ITSELF also hears the delta when its socket is homed here (mirroring the
/// local path's second send).
pub async fn apply_removes_ctrl(state: &NetworkState, ctrl: &serde_json::Value) {
    let (Some(tid), Some(net), Some(node_id)) = (
        ctrl.get("tenant_id")
            .and_then(|v| v.as_str())
            .and_then(|s| ObjectId::parse_str(s).ok()),
        ctrl.get("network_id")
            .and_then(|v| v.as_str())
            .and_then(|s| ObjectId::parse_str(s).ok()),
        ctrl.get("node_id")
            .and_then(|v| v.as_str())
            .and_then(|s| ObjectId::parse_str(s).ok()),
    ) else {
        return;
    };
    let epoch = ctrl.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);

    let peers = state
        .overlay_nodes
        .list_active_in_network(tid, net)
        .await
        .unwrap_or_default();
    fan_delta_to(state, &peers, Some(node_id), epoch, vec![], vec![node_id]).await;
    if let Ok(tombstone) = state.overlay_nodes.base.find_by_id(node_id).await {
        send_to_node(
            state,
            &tombstone,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts: vec![],
                removes: vec![node_id],
            },
        )
        .await;
    }
    debug!(%tid, %node_id, peers = peers.len(),
        "overlay: removes re-fanned from another pod's removal");
}

/// #1186 — drain the channel the redis ctrl subscriber feeds `overlay_removes`
/// envelopes into. A channel + late spawn rather than handling inline because
/// the subscriber loop is spawned mid-`AppState::new` and cannot capture the
/// full state the re-fan needs (`apply_rc_ctrl` is hub-only by the same
/// constraint).
pub fn spawn_removes_applier(
    state: NetworkState,
    mut rx: tokio::sync::mpsc::Receiver<serde_json::Value>,
) {
    tokio::spawn(async move {
        while let Some(ctrl) = rx.recv().await {
            apply_removes_ctrl(&state, &ctrl).await;
        }
    });
}

/// Release the live overlay node backing `expect` on `machine_id`, if any.
///
/// Resolves via the indexed `(tenant_id, machine_id)` lookup and THEN verifies
/// `node_ref`: an agent and a tunnel-client on the same box share a
/// `machine_id`, and the unique index means only ONE of them can own the
/// overlay node — so deleting the agent must not release a node the
/// still-enrolled tunnel-client owns.
pub async fn release_overlay_node_for(
    state: &NetworkState,
    tenant_id: ObjectId,
    machine_id: &str,
    expect: &NodeRef,
    reason: &str,
) -> Option<ReleasedNode> {
    let node = state
        .overlay_nodes
        .find_live_by_tenant_and_machine(tenant_id, machine_id)
        .await
        .ok()
        .flatten()?;
    if &node.node_ref != expect {
        debug!(%tenant_id, machine_id,
            "overlay release: the node on this machine belongs to another role; skipping");
        return None;
    }
    release_overlay_node(state, &node, reason).await
}

/// Fan a delta to every active peer of `self_node` in its network.
/// Fan an upsert of `node` to its peers, **shaped per recipient** by the
/// tenant's overlay ACL.
///
/// Replaces the old build-once-clone-N-times fan-out: the entry a recipient
/// receives now depends on what that recipient is allowed to see. A recipient
/// that may not see `node` is sent an explicit `removes` rather than simply
/// being skipped — omitting a peer from a delta (or shipping it with
/// `reachable: false`) does NOT tear down an already-installed peer; only the
/// removes branch drops the WG peer, its route and its carrier.
async fn fan_upsert_shaped(state: &NetworkState, node: &OverlayNode, epoch: u64, reachable: bool) {
    let peers = match state
        .overlay_nodes
        .list_active_in_network(node.tenant_id, node.network_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "overlay: peer list for delta fan-out failed");
            return;
        }
    };
    let acl = load_acl(state, node.tenant_id).await;
    let iso = business_isolation::mode(state);
    let node_zone = business_isolation::zone_of(state, iso, node).await;
    let lines = business_isolation::lines(state, iso, node.tenant_id).await;
    // P4 — the fanned node is the SHAPED peer for every recipient, so its
    // identity is resolved once, not per recipient.
    let node_src = if acl.enforcing() {
        Some(overlay_source_of(state, node).await)
    } else {
        None
    };
    // D0 (overlay v3) — the REVERSE direction. This fan re-stamps the
    // `peer → changed-node` verdict for every recipient, but the changed
    // node itself would receive nothing — so after a one-sided change its
    // OWN `node → peer` verdicts stay a generation behind. Under
    // server-authoritative selection (U3) that skew is a silent wedge:
    // both-anchor reads "blocked", and both-DIALER means neither end
    // allocates, no link forms, no handshake deadline fires, so no
    // conviction and no re-probe ever detect it. Push the changed node one
    // delta re-stamping its outgoing edges whenever it is present and
    // U2-capable (verdicts are the only per-edge data its change moves;
    // pre-U2 nodes ignore stamps, so the delta would be pure noise there).
    let reverse = reachable && node.supports_server_relay_strategy;
    let (node_recip_src, peer_reach) = if reverse {
        (
            Some(overlay_source_of(state, node).await),
            reachability(state, &peers).await,
        )
    } else {
        (None, HashMap::new())
    };
    let mut reverse_rows: Vec<NetmapPeer> = Vec::new();
    for peer in peers.iter().filter(|p| p.id != node.id) {
        let src = overlay_source_of(state, peer).await;
        // U2 — the edge is `recipient=peer → this fanned node`; both full
        // rows are in hand, so stamp the server verdict onto the shaped peer.
        let verdict = server_relay_verdict(state, peer, node);
        let peer_zone = business_isolation::zone_of(state, iso, peer).await;
        let zones = Zones {
            mode: iso,
            recipient: peer_zone,
            peer: node_zone,
            line: lines.connects(peer_zone, node_zone)
                && business_isolation::rides_lines(state, peer),
            servers: lines.server_pair(peer, node),
        };
        let (upserts, removes) =
            match shape_peer(&acl, &src, node, node_src.as_ref(), reachable, zones) {
                Some(mut u) => {
                    stamp_verdict(&mut u, verdict);
                    (vec![u], vec![])
                }
                None => (vec![], vec![node.id.unwrap_or_default()]),
            };
        send_to_node(
            state,
            peer,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts,
                removes,
            },
        )
        .await;
        // D0 — the mirror row for the changed node: recipient=node,
        // shaped=peer, verdict for the `node → peer` edge. Same shaping
        // rules as any row toward `node` (ACL from its source; the peer's
        // real presence, not the changed node's).
        if let Some(rsrc) = node_recip_src.as_ref() {
            let rev_verdict = server_relay_verdict(state, node, peer);
            let peer_src_arg = if acl.enforcing() { Some(&src) } else { None };
            let back = Zones {
                mode: iso,
                recipient: node_zone,
                peer: peer_zone,
                line: lines.connects(node_zone, peer_zone)
                    && business_isolation::rides_lines(state, node),
                servers: lines.server_pair(node, peer),
            };
            if let Some(mut r) = shape_peer(
                &acl,
                rsrc,
                peer,
                peer_src_arg,
                is_reachable(&peer_reach, peer),
                back,
            ) {
                stamp_verdict(&mut r, rev_verdict);
                reverse_rows.push(r);
            }
        }
    }
    if !reverse_rows.is_empty() {
        debug!(
            node = %node.name,
            rows = reverse_rows.len(),
            epoch,
            "overlay: reverse verdict delta — re-stamping the changed node's outgoing edges (D0)"
        );
        send_to_node(
            state,
            node,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts: reverse_rows,
                removes: vec![],
            },
        )
        .await;
    }
}

/// D2 — re-stamp ONE pair's verdicts on both ends, now.
///
/// Used by the P7 escalation so the forced-DERP decision rides the verdict
/// channel at the moment it is made (D1 consumers act on stamps; the live
/// `OverlayForceDerp` push covers pre-D1 nodes and carries the TTL). Each
/// end receives the OTHER's row, ACL-shaped from its own source, with the
/// verdict for its outgoing edge — the same two halves
/// [`fan_upsert_shaped`] maintains on ordinary changes.
async fn fan_pair_verdicts(state: &NetworkState, a: &OverlayNode, b: &OverlayNode) {
    let acl = load_acl(state, a.tenant_id).await;
    let a_src = overlay_source_of(state, a).await;
    let b_src = overlay_source_of(state, b).await;
    let reach = reachability(state, std::slice::from_ref(b)).await;
    let epoch = next_epoch();
    // Toward `a`: b's row, stamped with the a→b verdict. The requester `a`
    // is on a live WS by construction; `b`'s presence comes from the
    // snapshot so a dead peer's row does not read dialable.
    let b_reach = is_reachable(&reach, b);
    let enforcing = acl.enforcing();
    let iso = business_isolation::mode(state);
    let (a_zone, b_zone) = (
        business_isolation::zone_of(state, iso, a).await,
        business_isolation::zone_of(state, iso, b).await,
    );
    let lines = business_isolation::lines(state, iso, a.tenant_id).await;
    if a.supports_server_relay_strategy
        && let Some(mut row) = shape_peer(
            &acl,
            &a_src,
            b,
            if enforcing { Some(&b_src) } else { None },
            b_reach,
            Zones {
                mode: iso,
                recipient: a_zone,
                peer: b_zone,
                line: lines.connects(a_zone, b_zone) && business_isolation::rides_lines(state, a),
                servers: lines.server_pair(a, b),
            },
        )
    {
        stamp_verdict(&mut row, server_relay_verdict(state, a, b));
        send_to_node(
            state,
            a,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts: vec![row],
                removes: vec![],
            },
        )
        .await;
    }
    if b.supports_server_relay_strategy
        && let Some(mut row) = shape_peer(
            &acl,
            &b_src,
            a,
            if enforcing { Some(&a_src) } else { None },
            true,
            Zones {
                mode: iso,
                recipient: b_zone,
                peer: a_zone,
                line: lines.connects(b_zone, a_zone) && business_isolation::rides_lines(state, b),
                servers: lines.server_pair(b, a),
            },
        )
    {
        stamp_verdict(&mut row, server_relay_verdict(state, b, a));
        send_to_node(
            state,
            b,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts: vec![row],
                removes: vec![],
            },
        )
        .await;
    }
    debug!(
        a = %a.name, b = %b.name, epoch,
        "overlay: pair verdicts re-stamped at escalation (D2)"
    );
}

/// Fan a delta to an EXPLICIT peer list, skipping `exclude`.
///
/// Split out of [`fan_delta_to_peers`] for the release path, which must read
/// its peers BEFORE the node is tombstoned — afterwards the released node is
/// gone from `list_active_in_network`. Pinning the list makes that ordering
/// visible in the code instead of implied, and saves a round-trip.
async fn fan_delta_to(
    state: &NetworkState,
    peers: &[OverlayNode],
    exclude: Option<ObjectId>,
    epoch: u64,
    upserts: Vec<NetmapPeer>,
    removes: Vec<ObjectId>,
) {
    for peer in peers.iter().filter(|n| n.id != exclude) {
        send_to_node(
            state,
            peer,
            ServerMsg::OverlayNetmapDelta {
                epoch,
                upserts: upserts.clone(),
                removes: removes.clone(),
            },
        )
        .await;
    }
}

/// Deliver a `ServerMsg` to one overlay node, resolving its `node_ref`:
/// agent nodes go through the Hub, tunnel-client nodes through the
/// connection-lifetime registry. Best-effort — an offline node is
/// simply skipped (it re-syncs on its next join).
pub async fn send_to_node(state: &NetworkState, node: &OverlayNode, msg: ServerMsg) {
    match &node.node_ref {
        NodeRef::Agent { agent_id } => {
            if let Err(e) = state.fleet.rc_hub.send_to_agent(*agent_id, msg) {
                debug!(agent_id = %agent_id, %e, "overlay: agent node unreachable; skipped");
            }
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            // Clone the Sender out of the DashMap Ref so the shard guard
            // isn't held across the `.await` (the established pattern in
            // `remote_control::relay_to_client`).
            let tx = state
                .overlay_nodes_by_id
                .get(tunnel_client_id)
                .map(|e| e.value().clone());
            match tx {
                Some(tx) => {
                    if let Err(e) = tx.send(msg).await {
                        debug!(%tunnel_client_id, %e, "overlay: client node channel closed; skipped");
                    }
                }
                None => debug!(%tunnel_client_id, "overlay: client node not connected; skipped"),
            }
        }
    }
}

/// [`send_to_node`] by [`NodeRef`] alone — for callers that hold a session
/// record rather than a row (FR-19's mint re-push and revoke).
pub async fn send_to_node_ref(state: &NetworkState, node_ref: &NodeRef, msg: ServerMsg) {
    match node_ref {
        NodeRef::Agent { agent_id } => {
            if let Err(e) = state.fleet.rc_hub.send_to_agent(*agent_id, msg) {
                debug!(agent_id = %agent_id, %e, "overlay: agent node unreachable; skipped");
            }
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            let tx = state
                .overlay_nodes_by_id
                .get(tunnel_client_id)
                .map(|e| e.value().clone());
            match tx {
                Some(tx) => {
                    if let Err(e) = tx.send(msg).await {
                        debug!(%tunnel_client_id, %e, "overlay: client node channel closed; skipped");
                    }
                }
                None => debug!(%tunnel_client_id, "overlay: client node not connected; skipped"),
            }
        }
    }
}

/// Resolve the underlying `(tenant_id, machine_id)` for a node identity.
/// Returns `(tenant_id, machine_id, display_name)` for the identity — the
/// display name is the underlying agent/tunnel-client `name` (Phase 0, for the
/// overlay node name / MagicDNS).
async fn resolve_tenant_and_machine(
    state: &NetworkState,
    ident: NodeIdentity,
) -> Option<(ObjectId, String, String)> {
    match ident {
        NodeIdentity::Agent(id) => state
            .fleet
            .agents
            .base
            .find_by_id(id)
            .await
            .ok()
            .map(|a| (a.tenant_id, a.machine_id, a.name)),
        NodeIdentity::TunnelClient(id) => state
            .tunnel_clients
            .base
            .find_by_id(id)
            .await
            .ok()
            .map(|c| (c.tenant_id, c.machine_id, c.name)),
    }
}

/// Fetch the joined `OverlayNode` row for an identity (post-join ops).
///
/// Live-only, so every post-join handler (endpoints, srflx, leave,
/// relay_request, DERP registration) silently no-ops for a RELEASED node — which
/// is correct: the release already fanned its `removes`. The `deleted_at` filter
/// below is redundant now that the lookup is scoped; kept as belt and braces.
pub async fn current_node(state: &NetworkState, ident: NodeIdentity) -> Option<OverlayNode> {
    let (tenant_id, machine_id, _name) = resolve_tenant_and_machine(state, ident).await?;
    state
        .overlay_nodes
        .find_live_by_tenant_and_machine(tenant_id, &machine_id)
        .await
        .ok()
        .flatten()
        .filter(|n| n.deleted_at.is_none())
}

/// Sanitize a display name to a single DNS label — lowercase `[a-z0-9-]`, no
/// leading/trailing dashes, no dash runs, ≤63 chars. Falls back to `fallback`
/// (the machine_id) then `"node"` when the name yields no usable characters.
fn dns_label(display: &str, fallback: &str) -> String {
    fn sanitize(s: &str) -> String {
        let mut out = String::new();
        let mut prev_dash = false;
        for c in s.chars() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() {
                out.push(c);
                prev_dash = false;
            } else if !out.is_empty() && !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        }
        out.truncate(63);
        while out.ends_with('-') {
            out.pop();
        }
        out
    }
    let primary = sanitize(display);
    if !primary.is_empty() {
        return primary;
    }
    let fb = sanitize(fallback);
    if !fb.is_empty() {
        return fb;
    }
    "node".to_string()
}

/// Make `base` unique among the network's node names (append `-2`, `-3`, …),
/// ignoring `exclude` (self, when backfilling). Best-effort — a lost race is
/// still caught by the unique `(tenant,network,name)` index.
async fn unique_node_name(
    state: &NetworkState,
    tenant_id: ObjectId,
    network_id: ObjectId,
    base: &str,
    exclude: Option<ObjectId>,
) -> String {
    let taken: std::collections::HashSet<String> = state
        .overlay_nodes
        .list_active_in_network(tenant_id, network_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.id != exclude)
        .map(|n| n.name)
        .filter(|s| !s.is_empty())
        .collect();
    if !taken.contains(base) {
        return base.to_string();
    }
    for i in 2..1000 {
        let candidate = format!("{base}-{i}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", next_epoch())
}

/// P9 — how stale a backing agent's heartbeat may be before its overlay row
/// ships `reachable = false`. Heartbeats refresh `agents.last_seen_at` every
/// ~30 s ([`roomler_ai_services::dao::AgentDao::touch_heartbeat`]); 120 s =
/// four missed beats, tolerant of a transient stall but killing day-old
/// ghosts on the first netmap that carries them.
const NODE_STALE_AFTER_MS: i64 = 120_000;

/// P9 — presence for the netmap: `reachable = false` for a row that cleanly
/// left (status `Offline` — the leave handler's mark) or whose backing
/// agent's heartbeat went stale. Peers render such rows `offline` and stop
/// burning dials / probes / REKEY handshakes on them (field 2026-07-28: a
/// dead duplicate enrollment sat "blocked" in every netmap for a day while
/// both sides hammered its stale endpoints — full netmaps resurrected it as
/// dialable on every rejoin, undoing the leave-time remove delta).
/// Tunnel-client rows have no heartbeat trail — status alone decides (a pod
/// crash can leave one Online-but-gone until its next clean leave; a
/// periodic stale-sweep is the v2). FAIL-OPEN: a freshness-query error reads
/// as "everything reachable" — a DB blip must not mark the fleet offline.
pub async fn reachability(state: &NetworkState, nodes: &[OverlayNode]) -> HashMap<ObjectId, bool> {
    let agent_ids: Vec<ObjectId> = nodes
        .iter()
        .filter_map(|n| match &n.node_ref {
            NodeRef::Agent { agent_id } => Some(*agent_id),
            NodeRef::TunnelClient { .. } => None,
        })
        .collect();
    let fresh = match state
        .fleet
        .agents
        .last_seen_fresh(&agent_ids, NODE_STALE_AFTER_MS)
        .await
    {
        Ok(m) => Some(m),
        Err(e) => {
            warn!(%e, "overlay: agent freshness query failed; failing open");
            None
        }
    };
    nodes
        .iter()
        .filter_map(|n| {
            let id = n.id?;
            let up = matches!(n.status, AgentStatus::Online)
                && match &n.node_ref {
                    NodeRef::Agent { agent_id } => fresh
                        .as_ref()
                        .map(|m| m.get(agent_id).copied().unwrap_or(false))
                        .unwrap_or(true),
                    NodeRef::TunnelClient { .. } => true,
                };
            Some((id, up))
        })
        .collect()
}

/// The `reachable` a node's netmap row ships, from a [`reachability`] map.
/// Fail-open for a row that somehow missed the map (no `_id`).
fn is_reachable(reach: &HashMap<ObjectId, bool>, node: &OverlayNode) -> bool {
    node.id.and_then(|i| reach.get(&i)).copied().unwrap_or(true)
}

// ────────────────────────────────────────────────────────────────────────────
// Overlay ACL (L3)
// ────────────────────────────────────────────────────────────────────────────

/// One tenant's ACL posture + rules, loaded once per netmap event.
///
/// Cheap to build and short-lived on purpose: netmap events are joins, leaves,
/// endpoint trickles and admin edits — orders of magnitude rarer than the
/// per-flow tunnel gate, so there is nothing to cache yet.
#[derive(Clone)]
pub struct AclCtx {
    pub mode: OverlayAclMode,
    pub policies: Vec<OverlayPolicy>,
}

impl AclCtx {
    pub fn off() -> Self {
        Self {
            mode: OverlayAclMode::Off,
            policies: Vec::new(),
        }
    }
    pub fn enforcing(&self) -> bool {
        matches!(self.mode, OverlayAclMode::Enforce)
    }
    /// `true` when the ACL is doing anything at all (`Warn` or `Enforce`).
    /// `Warn` still evaluates — that's what produces the pre-cutover evidence —
    /// so "is a table worth building?" is this, not [`enforcing`](Self::enforcing).
    pub fn gating(&self) -> bool {
        !matches!(self.mode, OverlayAclMode::Off)
    }
}

/// Whether [`try_load_acl`] reads the policy rows when the tenant's mode is
/// `Off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLoad {
    /// Netmap shaping: under `Off` the rules are never consulted, so the read
    /// is skipped — the pre-FR-19 read profile, byte for byte.
    WhenGating,
    /// FR-19 relay grants are an affirmative capability evaluated regardless
    /// of `acl_mode` (spec §4), so the rows are needed under `Off` too.
    Always,
}

/// Load the tenant's ACL posture and rules, surfacing a read failure to the
/// caller instead of deciding for it.
///
/// This exists because "fail closed" was not expressible through
/// [`load_acl`]: its error path returns [`AclCtx::off`], byte-identical to a
/// tenant that genuinely has ACLs disabled, so a caller shaped like the relay
/// gate would take the "no ACL configured" branch on a Mongo blip and GRANT
/// while its author believed it refused (FR-19 §4). The relay mint uses this
/// and answers `PolicyUnreadable`; the netmap path keeps its open posture via
/// the wrapper below.
pub async fn try_load_acl(
    state: &NetworkState,
    tenant_id: ObjectId,
    load: PolicyLoad,
) -> Result<AclCtx, DaoError> {
    let mode = state
        .overlay_networks
        .get_or_create(tenant_id)
        .await?
        .acl_mode;
    if load == PolicyLoad::WhenGating && matches!(mode, OverlayAclMode::Off) {
        return Ok(AclCtx::off());
    }
    let policies = state
        .overlay_policies
        .list_active_for_tenant(tenant_id)
        .await?;
    Ok(AclCtx { mode, policies })
}

/// Load the tenant's ACL posture and rules for NETMAP shaping.
///
/// A read failure never becomes "ACL off" (#18, v039 ACL-02: an unavailable
/// policy must not turn into allow-all). It shapes with the last policy this
/// process read for the tenant, which keeps the mesh as it was instead of
/// tearing it down on a transient Mongo blip; with none read yet it fails
/// CLOSED. Logged at ERROR either way. The relay mint refuses outright
/// instead ([`try_load_acl`]).
pub async fn load_acl(state: &NetworkState, tenant_id: ObjectId) -> AclCtx {
    settle_acl(
        tenant_id,
        try_load_acl(state, tenant_id, PolicyLoad::WhenGating).await,
    )
}

/// The last ACL each tenant's netmap was shaped with, in this process.
static LAST_GOOD_ACL: std::sync::LazyLock<dashmap::DashMap<ObjectId, AclCtx>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

fn settle_acl<E: std::fmt::Display>(tenant_id: ObjectId, read: Result<AclCtx, E>) -> AclCtx {
    match read {
        Ok(acl) => {
            LAST_GOOD_ACL.insert(tenant_id, acl.clone());
            acl
        }
        Err(e) => match LAST_GOOD_ACL.get(&tenant_id) {
            Some(last) => {
                tracing::error!(%tenant_id, %e, "overlay acl: read failed; shaping with the last policy read");
                last.clone()
            }
            None => {
                tracing::error!(%tenant_id, %e, "overlay acl: read failed and none read yet; failing CLOSED");
                AclCtx {
                    mode: OverlayAclMode::Enforce,
                    policies: Vec::new(),
                }
            }
        },
    }
}

/// Resolve the identity a decision is being made FOR: the node itself, plus
/// the owner + roles of its backing agent / tunnel client so `UserId` /
/// `RoleId` selectors can match — or the read error, when the backing row or
/// the membership could not be read.
///
/// The strict form. A `UserId`/`RoleId`-scoped grant cannot be evaluated for
/// a node whose owner is unknown, and a caller deciding an affirmative
/// capability (the FR-19 relay grant) must refuse rather than fall through to
/// "matches only `AllNodes`". Netmap shaping keeps its degrading posture via
/// [`overlay_source_of`].
pub async fn try_overlay_source_of(
    state: &NetworkState,
    node: &OverlayNode,
) -> Result<OverlaySource, DaoError> {
    let owner_user_id = match &node.node_ref {
        NodeRef::Agent { agent_id } => {
            state
                .fleet
                .agents
                .base
                .find_by_id(*agent_id)
                .await?
                .owner_user_id
        }
        NodeRef::TunnelClient { tunnel_client_id } => {
            state
                .tunnel_clients
                .base
                .find_by_id(*tunnel_client_id)
                .await?
                .owner_user_id
        }
    };
    let role_ids = state
        .tenants
        .member_role_ids(node.tenant_id, owner_user_id)
        .await?;
    Ok(OverlaySource {
        node_id: node.id.unwrap_or_default(),
        owner_user_id: Some(owner_user_id),
        role_ids,
    })
}

/// [`try_overlay_source_of`] for NETMAP shaping: degrades instead of failing —
/// an unknown owner matches only `AllNodes` / `NodeId` rules and unreadable
/// roles match none — because a spurious error here would withhold peers.
///
/// Each swallowed error is LOGGED. Before FR-19 this was `.ok()` and
/// `unwrap_or_default()`: a scoped rule silently failing to match, with no
/// trace to explain a peer that vanished from a netmap.
pub async fn overlay_source_of(state: &NetworkState, node: &OverlayNode) -> OverlaySource {
    let node_id = node.id.unwrap_or_default();
    let owner = match &node.node_ref {
        NodeRef::Agent { agent_id } => state
            .fleet
            .agents
            .base
            .find_by_id(*agent_id)
            .await
            .map(|a| a.owner_user_id),
        NodeRef::TunnelClient { tunnel_client_id } => state
            .tunnel_clients
            .base
            .find_by_id(*tunnel_client_id)
            .await
            .map(|c| c.owner_user_id),
    };
    let owner_user_id = match owner {
        Ok(uid) => Some(uid),
        Err(e) => {
            warn!(%node_id, %e,
                "overlay acl: backing row unreadable; owner-scoped rules will not match this node");
            None
        }
    };
    let role_ids = match owner_user_id {
        Some(uid) => match state.tenants.member_role_ids(node.tenant_id, uid).await {
            Ok(roles) => roles,
            Err(e) => {
                warn!(%node_id, %e,
                    "overlay acl: roles unreadable; role-scoped rules will not match this node");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    OverlaySource {
        node_id,
        owner_user_id,
        role_ids,
    }
}

/// Shape one peer for one recipient. `None` = withhold it entirely.
///
/// In `Warn` mode the permissive peer is returned but every difference is
/// logged, which is what makes the cutover to `Enforce` evidence-driven rather
/// than a leap of faith.
/// `peer_src` is the PEER's own identity, needed to compile the ingress rules it
/// may use against this recipient — the reverse direction of the visibility
/// question. `None` ⇒ ship no rules (`ingress_rules: None`), which the node
/// reads as "the ACL compiled nothing, fall back to the coarse local scope".
/// Callers pass `None` unless the tenant is ENFORCING, so `warn` can never cause
/// a node to drop: warn's whole contract is that it observes and never denies.
/// U2 — the server's relay-tier verdict for the edge `recipient → peer`, or
/// `None` when the server must NOT stamp one (either end hasn't opted into
/// `supports_server_relay_strategy` — then that end computes locally from its
/// own view, and a one-sided verdict would manufacture anchor/dialer
/// disagreements). A pure port of the client's `relay_strategy()`: the server
/// holds a strict superset of the inputs at netmap-build time (both ends'
/// srflx presence, capabilities, pubkeys, and its OWN forced-DERP pin), and
/// is the only party that can flip both ends of a pair atomically.
///
/// Symmetric by construction: for the reverse edge the server swaps `my`/
/// `peer`, so exactly one end is stamped `SingleRelayAnchor` and the other
/// `SingleRelayDialer` (UDP-capability first, smaller-pubkey tie-break — the
/// same rule and the same raw-byte comparison the client uses).
fn server_relay_verdict(
    state: &NetworkState,
    recipient: &OverlayNode,
    peer: &OverlayNode,
) -> Option<RelayStrategyWire> {
    // Force-DERP pin wins first (the server owns it), gated on both ends'
    // DERP support exactly as the client's pin check is.
    let pinned = recipient.supports_derp
        && peer.supports_derp
        && matches!((recipient.id, peer.id), (Some(a), Some(b))
            if state
                .relay_pair_churn
                .get(&pair_key(a, b))
                .is_some_and(|pc| forced_active(&pc, Instant::now())));
    // FR-19 — an ACTIVE org-relay session for this pair outranks every rule
    // below: the mint already applied the gates, and the client cascade picks
    // Org over Turn/Derp when a session exists (§6). Gated on BOTH ends'
    // `supports_org_relay` like every other capability, and on both accepting
    // server verdicts at all, so a pre-FR-19 end never sees the tag.
    if recipient.supports_org_relay
        && peer.supports_org_relay
        && recipient.supports_server_relay_strategy
        && peer.supports_server_relay_strategy
        && let (Some(a), Some(b)) = (recipient.id, peer.id)
        && state.org_relay.active_session(&pair_key(a, b)).is_some()
    {
        return Some(RelayStrategyWire::OrgRelay);
    }
    verdict_from_nodes(recipient, peer, pinned)
}

/// U2 — the node-level verdict (the pin resolved to a bool by the caller so
/// this stays `AppState`-free and unit-testable). Applies the both-ends
/// capability gate, decodes the pubkeys for the tie-break, and delegates the
/// rule set to [`relay_verdict_core`].
fn verdict_from_nodes(
    recipient: &OverlayNode,
    peer: &OverlayNode,
    pinned: bool,
) -> Option<RelayStrategyWire> {
    if !(recipient.supports_server_relay_strategy && peer.supports_server_relay_strategy) {
        return None;
    }
    // The tie-break compares RAW pubkey bytes (base64 string order ≠ byte
    // order), so decode both. On a decode failure, withhold — never guess a
    // role, which could put both ends on the same anchor/dialer side.
    let (Ok(my_pk), Ok(peer_pk)) = (
        BASE64.decode(&recipient.wg_public_key),
        BASE64.decode(&peer.wg_public_key),
    ) else {
        return None;
    };
    // B3 — MEASURED capability supersedes the derived inputs when BOTH ends
    // hold a fresh vector carrying the relay-band bit (mirrors the client's
    // rule in `relay_strategy` exactly: one-sided measurement keeps the
    // legacy rules, so a mixed pair can never split roles; no srflx ANDing
    // on the measured branch — the probe ran over the exact dial path).
    let measured = match (
        fresh_caps(recipient).and_then(|c| c.relay_band_udp),
        fresh_caps(peer).and_then(|c| c.relay_band_udp),
    ) {
        (Some(mine), Some(theirs)) => Some((mine, theirs)),
        _ => None,
    };
    let (my_udp_ok, peer_udp_ok) = measured.unwrap_or((
        effective_udp_ok(
            !recipient.srflx_endpoints.is_empty(),
            recipient.udp_dialer_ok,
            peer.udp_dialer_ok,
        ),
        effective_udp_ok(
            !peer.srflx_endpoints.is_empty(),
            peer.udp_dialer_ok,
            recipient.udp_dialer_ok,
        ),
    ));
    Some(relay_verdict_core(
        pinned,
        recipient.supports_derp && peer.supports_derp,
        recipient.supports_relay_single && peer.supports_relay_single,
        my_udp_ok,
        peer_udp_ok,
        !recipient.srflx_endpoints.is_empty(),
        !peer.srflx_endpoints.is_empty(),
        &my_pk,
        &peer_pk,
    ))
}

/// Dialer honesty — one side's effective UDP-capability for the role split.
/// Mirrors the client's rule in `tunnel_core::overlay::relay_link` exactly:
/// a `Some(false)` verdict (this host proved its raw dials to relay-band
/// ports don't land) counts ONLY when the OTHER end carries the field too
/// (`None` = pre-honesty agent ⇒ both ends keep the legacy srflx-only
/// inputs, so a mixed-version pair can never split roles).
fn effective_udp_ok(srflx_ok: bool, own_flag: Option<bool>, other_flag: Option<bool>) -> bool {
    srflx_ok && (own_flag.unwrap_or(true) || other_flag.is_none())
}

/// U2 — the PURE relay-tier decision (the pin + capability lookups resolved
/// to booleans by [`server_relay_verdict`]). A verbatim transcription of the
/// client's `relay_strategy()` in `tunnel_core::overlay::relay_link`: the
/// pin first, then single-relay by UDP-capability with a smaller-raw-pubkey
/// tie-break, then DERP for a both-blocked pair, then both-allocate. The two
/// MUST stay in lockstep — the `server_verdict_matches_client_rules` matrix
/// is the lock, and U3 only deletes the client copy once this parity holds.
#[allow(clippy::too_many_arguments)]
fn relay_verdict_core(
    pinned: bool,
    both_derp: bool,
    both_single: bool,
    my_udp_ok: bool,
    peer_udp_ok: bool,
    my_srflx_ok: bool,
    peer_srflx_ok: bool,
    my_pk: &[u8],
    peer_pk: &[u8],
) -> RelayStrategyWire {
    if pinned {
        return RelayStrategyWire::Derp;
    }
    if both_single {
        match (my_udp_ok, peer_udp_ok) {
            (true, false) => return RelayStrategyWire::SingleRelayDialer,
            (false, true) => return RelayStrategyWire::SingleRelayAnchor,
            (true, true) => {
                return if my_pk < peer_pk {
                    RelayStrategyWire::SingleRelayAnchor
                } else {
                    RelayStrategyWire::SingleRelayDialer
                };
            }
            (false, false) => {} // neither can raw-dial → DERP below
        }
    }
    // DERP keyed on the RAW srflx signals (the client rule verbatim): the
    // lazy `/derp` mux only exists on srflx-empty nodes, so an honesty-
    // latched (srflx-present) host must land BothAllocate — its
    // client→:3478 allocation socket is exactly what still works there.
    if both_derp && !my_srflx_ok && !peer_srflx_ok {
        return RelayStrategyWire::Derp;
    }
    RelayStrategyWire::BothAllocate
}

/// What [`shape_full_netmap`] produced for one node: the peers its full
/// netmap carries, plus the ACL posture and the node's own identity the
/// shaping was made under — the join path keeps using both after the full
/// netmap (the delta fan-out compiles the joiner's ingress rules from
/// `self_src`; the DERP allow-table refresh keys on `acl.gating()`).
pub struct ShapedNetmap {
    pub acl: AclCtx,
    pub self_src: OverlaySource,
    pub peers: Vec<NetmapPeer>,
}

/// The full netmap ONE node receives: every live peer in `all` (self
/// excluded), shaped for that node under the tenant's ACL posture, with the
/// presence verdict from `reach` and the server's relay-tier verdict per edge.
///
/// This is the join path's shaping, verbatim (`handle_overlay_join` calls it),
/// extracted in FR-84 D5a because the device's own listing
/// (`GET /api/agent/self/devices`) must show exactly what the netmap carries
/// — a second implementation of "who may this node see" would drift from the
/// first, and the direction it drifts in is the one that lists a peer the
/// netmap withholds. The semantics therefore fall out of [`shape_peer`]:
/// `off` and `warn` return every live peer, `enforce` only the visible set.
///
/// ⚠️ `load_acl` goes through `get_or_create`, which can ALLOCATE a network
/// row (and, with blocks on, carve a block) for a tenant that has none. A
/// read-only caller must find the tenant's network and this node's live row
/// first — both of which the join path has by construction — and call this
/// only then. `self_node` must be a LIVE row of `all`'s network.
pub async fn shape_full_netmap(
    state: &NetworkState,
    self_node: &OverlayNode,
    all: &[OverlayNode],
    reach: &HashMap<ObjectId, bool>,
) -> ShapedNetmap {
    let acl = load_acl(state, self_node.tenant_id).await;
    let self_src = overlay_source_of(state, self_node).await;
    let iso = business_isolation::mode(state);
    let self_zone = business_isolation::zone_of(state, iso, self_node).await;
    let lines = business_isolation::lines(state, iso, self_node.tenant_id).await;
    let rides = business_isolation::rides_lines(state, self_node);
    let mut peers: Vec<NetmapPeer> = Vec::new();
    for n in all.iter().filter(|n| n.id != self_node.id) {
        let peer_zone = business_isolation::zone_of(state, iso, n).await;
        let zones = Zones {
            mode: iso,
            recipient: self_zone,
            peer: peer_zone,
            line: rides && lines.connects(self_zone, peer_zone),
            servers: lines.server_pair(self_node, n),
        };
        // P4 — resolving the peer's own identity costs up to 2 reads, so do it
        // ONLY when the tenant is enforcing and the rules will actually ship.
        // An `off`/`warn` tenant's join path is unchanged.
        let peer_src = if acl.enforcing() {
            Some(overlay_source_of(state, n).await)
        } else {
            None
        };
        if let Some(mut p) = shape_peer(
            &acl,
            &self_src,
            n,
            peer_src.as_ref(),
            is_reachable(reach, n),
            zones,
        ) {
            // U2 — the recipient's full-netmap edge is `self_node → n`.
            stamp_verdict(&mut p, server_relay_verdict(state, self_node, n));
            peers.push(p);
        }
    }
    ShapedNetmap {
        acl,
        self_src,
        peers,
    }
}

fn shape_peer(
    acl: &AclCtx,
    src: &OverlaySource,
    peer: &OverlayNode,
    peer_src: Option<&OverlaySource>,
    reachable: bool,
    zones: Zones,
) -> Option<NetmapPeer> {
    let unbound;
    let peer = match routes_outside_their_zone(peer, zones) {
        Some(p) => {
            unbound = p;
            &unbound
        }
        None => peer,
    };
    // MeshHarbor #21 exception — a cross-zone peer an approved line connects
    // is shaped like any other (the ACL still decides), then stripped to the
    // line: no address to dial, no DERP or TURN to try.
    if zones.line_only() {
        debug!(source = %src.node_id, peer = %peer.name, ?zones,
            "business isolation: peer shown backbone-only (an approved cross-border line)");
        return shape_peer_zoned(acl, src, peer, peer_src, reachable, Zones::OFF).map(line_only);
    }
    shape_peer_zoned(acl, src, peer, peer_src, reachable, zones)
}

/// v039 GEO-06 — `peer` without its routes, when its route approval is bound
/// to a zone it is not observed in under `enforce`: a router that roamed (or
/// whose zone evidence is gone) keeps its peer entry but offers nothing, so
/// it never claims a private CIDR another zone's router serves.
fn routes_outside_their_zone(peer: &OverlayNode, zones: Zones) -> Option<OverlayNode> {
    let bound = peer.routes_zone.as_deref()?;
    (zones.mode == business_isolation::Mode::Enforce
        && !peer.approved_routes.is_empty()
        && zones.peer.map(business_isolation::zone_tag) != Some(bound))
    .then(|| OverlayNode {
        approved_routes: Vec::new(),
        ..peer.clone()
    })
}

/// Stamp the server's relay verdict (U2) onto a shaped row. A line peer
/// rides its line alone, so it is never told a tier (field, 2026-10-26: a
/// D0 re-stamp told a member DERP toward its line peer; `/derp` dropped the
/// frames, but the member wasted its first carrier on it).
fn stamp_verdict(p: &mut NetmapPeer, verdict: Option<RelayStrategyWire>) {
    if !p.backbone_only {
        p.relay_strategy = verdict;
    }
}

/// A peer as a recipient may reach it only over a cross-border line.
fn line_only(mut p: NetmapPeer) -> NetmapPeer {
    p.backbone_only = true;
    p.endpoints.clear();
    p.lan_endpoints.clear();
    p.srflx_endpoints.clear();
    p.srflx_nat = Default::default();
    p.relay_home = Default::default();
    p.warm_relay_endpoint = Default::default();
    p.supports_relay_single = false;
    p.supports_derp = false;
    p.supports_forced_derp = false;
    p.supports_derp_floor = false;
    p.relay_strategy = None;
    p
}

fn shape_peer_zoned(
    acl: &AclCtx,
    src: &OverlaySource,
    peer: &OverlayNode,
    peer_src: Option<&OverlaySource>,
    reachable: bool,
    zones: Zones,
) -> Option<NetmapPeer> {
    // MeshHarbor #21 — the hard mainland/non-mainland rule comes BEFORE the
    // ACL: no grant, share or relay can make a peer across it visible.
    if zones.denies() {
        if zones.withholds() {
            debug!(source = %src.node_id, peer = %peer.name, ?zones,
                "business isolation: WITHHOLD peer (zones differ or unknown, or servers without a link)");
            return None;
        }
        debug!(source = %src.node_id, peer = %peer.name, ?zones,
            "business isolation [warn]: would WITHHOLD peer (zones differ or unknown, or servers without a link)");
    }
    // Two linked servers: the link IS the decision, both ways, every port —
    // the topology view shows exactly what connects. Only under `enforce`;
    // `warn` changes nothing but the log.
    if zones.mode == business_isolation::Mode::Enforce && zones.servers == Some(true) {
        return Some(to_netmap_peer(peer, reachable));
    }
    if matches!(acl.mode, OverlayAclMode::Off) {
        return Some(to_netmap_peer(peer, reachable));
    }
    // FR-97 P0b — the ACL grants from what the peer OFFERS, the same set
    // `to_netmap_peer` fans; a route visible only through an approval the
    // device withdrew must not make the peer visible either.
    let routes = peer.effective_routes();
    let access = evaluate_overlay(
        &acl.policies,
        src,
        OverlayPeerRef {
            node_id: peer.id.unwrap_or_default(),
            overlay_ip: &peer.overlay_ip,
            approved_routes: &routes,
        },
    );
    if !acl.enforcing() {
        if !access.visible {
            debug!(source = %src.node_id, peer = %peer.name,
                "overlay acl [warn]: would WITHHOLD peer");
        } else if access.routes.len() != routes.len() {
            debug!(source = %src.node_id, peer = %peer.name,
                granted = access.routes.len(), approved = routes.len(),
                "overlay acl [warn]: would narrow routes");
        }
        return Some(to_netmap_peer(peer, reachable));
    }
    if !access.visible {
        return None;
    }
    let mut shaped = to_netmap_peer(peer, reachable);
    shaped.routes = access.routes;
    // P4 — per-source ingress rules: what THIS peer may address through the
    // recipient, including the port/proto dimensions `routes` cannot carry.
    // Always `Some` when compiled, even when empty — an empty grant is a DENY
    // and must not be confused with "no ACL".
    if let Some(ps) = peer_src {
        shaped.ingress_rules = Some(evaluate_overlay_ingress(&acl.policies, ps, src.node_id));
    }
    Some(shaped)
}

/// Structural fields come from the row; `reachable` is the caller's presence
/// verdict ([`reachability`] for peer lists; `true` for a node's OWN upsert —
/// the sender of a live WS message is reachable by construction).
///
/// This is the PERMISSIVE shape. Access control is applied by [`shape_peer`],
/// which decides whether a given recipient sees this peer at all and narrows
/// `routes` to the subset that recipient may install — `reachable` deliberately
/// stays a presence signal, because shipping `reachable: false` does not tear
/// down an already-installed peer (only a `removes` does).
fn to_netmap_peer(node: &OverlayNode, reachable: bool) -> NetmapPeer {
    NetmapPeer {
        node_id: node.id.unwrap_or_default(),
        overlay_ip: node.overlay_ip.clone(),
        name: node.name.clone(),
        wg_public_key: node.wg_public_key.clone(),
        // rc.135 — union the DIRECT LAN bucket with the trickled (srflx/relay)
        // bucket, LAN first, deduped. The relay trickle REPLACES `endpoints`,
        // so a node that allocated a relay would otherwise advertise no LAN
        // address and every peer would fall back to the relay path. Keeping
        // `lan_endpoints` separate and unioning here lets a same-subnet peer
        // always find the LAN candidate (field fix 2026-06-27).
        endpoints: union_endpoints(&node.lan_endpoints, &node.endpoints),
        // NAT-traversal Phase A — surface the join-time NIC bucket VERBATIM
        // (NOT unioned with the relay trickle). A globally-routable address in
        // here tells a peer this node's NIC holds a public IP, so it can be
        // dialed directly without STUN (the direct-to-public tier). It must stay
        // separate from `endpoints` because that union also carries coturn
        // relayed addresses, and on this fleet the coturn worker IPs are the
        // host public IPs — indistinguishable from a real public-on-NIC endpoint
        // in the union. Empty for a client that advertised no public endpoint.
        lan_endpoints: node.lan_endpoints.clone(),
        // NAT-traversal Phase B — surface the srflx bucket VERBATIM (its own
        // provenance, like `lan_endpoints`): a peer behind a different NAT dials
        // these to reach a 1:1/cone-NAT'd node directly. Empty until the node
        // gathers + trickles srflx (`rc:overlay.srflx`).
        srflx_endpoints: node.srflx_endpoints.clone(),
        // Phase C — surface the node's probed NAT type so a dialer can skip a
        // futile both-symmetric punch (VERBATIM, like srflx_endpoints).
        srflx_nat: node.srflx_nat.clone(),
        // Phase B — the measured capability vector behind the freshness
        // gate (stale ⇒ absent ⇒ consumers fall back to presence rules).
        caps: fresh_caps(node),
        // Dialer honesty — surface the node's raw-dial verdict VERBATIM
        // (`None` = pre-honesty agent; peers then keep legacy role inputs).
        udp_dialer_ok: node.udp_dialer_ok,
        relay_home: node.relay_home.clone(),
        // C4 stage 2 (PR-B) — surface the node's standing warm-leg address
        // (heartbeat-mirrored) so a single-relay dialer can dial this anchor
        // the moment its pair dies, without waiting for the per-pair relay
        // advert to crawl through a possibly-captured control WS.
        warm_relay_endpoint: node.warm_relay_endpoint.clone(),
        reachable,
        supports_quic: node.supports_quic,
        // Phase D — surface the node's single-relay capability so a peer only
        // picks single-relay when both ends advertise it (else both-allocate).
        supports_relay_single: node.supports_relay_single,
        // Phase D (DERP) — surface the node's DERP capability so a both-UDP-blocked
        // pair only picks DERP when both ends advertise it.
        supports_derp: node.supports_derp,
        // U2 — echo forced-DERP support (not surfaced pre-U2) + the
        // per-edge relay verdict. `relay_strategy` is the PERMISSIVE default
        // (`None` = client computes locally); the call sites that hold BOTH
        // the recipient and this peer's full node stamp it via
        // `server_relay_verdict`.
        supports_forced_derp: node.supports_forced_derp,
        // Phase A (overlay v3) — echo the floor capability so a pair is only
        // floored on DERP at birth when BOTH ends run the permanent mux.
        supports_derp_floor: node.supports_derp_floor,
        relay_strategy: None,
        backbone_only: false,
        // Data-probe — echo the peer's overlay-native-echo capability so
        // probers pick the engine echo over ICMP for capable peers.
        supports_overlay_echo: node.supports_overlay_echo,
        supports_org_relay: node.supports_org_relay,
        // Only routes the admin APPROVED and the device still ADVERTISES reach
        // peers (FR-97 P0b, `OverlayNode::effective_routes`): an approval
        // outlives a rejoin, so on its own it is not an offer. Once the
        // tenant's overlay ACL is enforcing, only the subset THIS recipient
        // may install (see `shape_peer`). `to_netmap_peer` keeps the permissive
        // default so every legacy call site is unchanged.
        routes: node.effective_routes(),
        // P3b-3 — expose the backing agent id (bridging overlay-node-id →
        // agents._id) so a controlling node can join this peer to a
        // daemon-originated tunnel flow and label it `ConnectionType::Tunnel`.
        // `None` for a tunnel-client node.
        agent_id: match &node.node_ref {
            NodeRef::Agent { agent_id } => Some(*agent_id),
            NodeRef::TunnelClient { .. } => None,
        },
        // P4 — the PERMISSIVE shape carries no ACL. `shape_peer` fills this in
        // (with `Some`, possibly empty) only when the tenant is enforcing;
        // leaving it `None` here is what makes an `off`/`warn` tenant's netmap
        // byte-identical to a pre-P4 server's.
        ingress_rules: None,
    }
}

/// Keep only well-formed IPv4 CIDR strings (`a.b.c.d/nn`, prefix ≤ 32) so a
/// malformed or malicious advertisement can't poison the stored/distributed
/// route set. (Phase 1.)
fn sanitize_cidrs(routes: Vec<String>) -> Vec<String> {
    routes
        .into_iter()
        .filter(|r| {
            let Some((ip, pfx)) = r.split_once('/') else {
                return false;
            };
            ip.parse::<std::net::Ipv4Addr>().is_ok() && pfx.parse::<u8>().is_ok_and(|p| p <= 32)
        })
        .collect()
}

/// `lan ∪ rest`, LAN first, order-preserving dedup.
fn union_endpoints(lan: &[String], rest: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lan.len() + rest.len());
    for ep in lan.iter().chain(rest.iter()) {
        if !out.contains(ep) {
            out.push(ep.clone());
        }
    }
    out
}

/// Symmetric per-pair key so both ends mint identical coturn creds.
pub fn pair_key(a: ObjectId, b: ObjectId) -> String {
    let (x, y) = (a.to_hex(), b.to_hex());
    if x <= y {
        format!("{x}:{y}")
    } else {
        format!("{y}:{x}")
    }
}

/// Monotonic-enough netmap epoch. A wall-clock millisecond stamp avoids
/// per-network shared state; Phase 5 (resync) replaces this with a
/// persisted per-network counter.
fn next_epoch() -> u64 {
    DateTime::now().timestamp_millis().max(0) as u64
}

/// Overlay relay creds, pinned to ONE coturn worker for this pair.
///
/// The relay-to-relay leg must hairpin on a single worker — cross-worker
/// traffic drops under buildhost's dual-public-IP SNAT (the flakiness the QUIC
/// tunnel pinned around in rc.112). The agent's own deterministic pick
/// (`relay_link::pick_worker`) can't co-locate the two nodes because they
/// resolve `coturn.roomler.ai` to *different* IP sets per host. The broker
/// resolves it ONCE and picks one worker by `pair_key`, so its choice is
/// authoritative for both peers → guaranteed intra-worker hairpin. Falls back
/// to the hostname-based servers (pre-fix behaviour) with no TURN config or on
/// DNS failure.
async fn overlay_ice_servers(
    state: &NetworkState,
    pair_key: &str,
    charge_to: Option<ObjectId>,
    home_a: Option<&str>,
    home_b: Option<&str>,
    needs_tls: bool,
) -> Vec<IceServer> {
    overlay_ice_servers_with_ttl(state, pair_key, charge_to, home_a, home_b, None, needs_tls).await
}

/// C4 stage 1.5 — [`overlay_ice_servers`] with an optional credential-TTL
/// override. The WARM grant passes a long TTL (the cred timestamp bounds
/// the allocation's total life; the 600 s pair TTL killed every warm
/// allocation at the 10-minute mark); pair grants keep the config TTL.
///
/// `charge_to` — FR-115 P4b: the org that pays for this pair's relay, put
/// into the TURN username (`turn_creds::charged`) so coturn's statistics name
/// it. The region pick stays keyed by the bare `pair_key`.
async fn overlay_ice_servers_with_ttl(
    state: &NetworkState,
    pair_key: &str,
    charge_to: Option<ObjectId>,
    home_a: Option<&str>,
    home_b: Option<&str>,
    ttl_override: Option<u32>,
    needs_tls: bool,
) -> Vec<IceServer> {
    let principal = match charge_to {
        Some(org) => turn_creds::charged(pair_key, &org.to_hex()),
        None => pair_key.to_string(),
    };
    let region = sticky_pair_region(
        &state.turn_map,
        &state.relay_load,
        pair_key,
        home_a,
        home_b,
        needs_tls,
    );
    if region.is_some() {
        roomler_core::cluster::metrics::bump(
            &roomler_core::cluster::metrics::RELAY_REGION_PICK_TOTAL,
        );
    }
    let Some(turn_cfg) = state.turn_map.cfg_for(region.as_deref()) else {
        return turn_creds::ice_servers_for_with_ttl(&principal, None, ttl_override);
    };
    let servers = turn_creds::ice_servers_for_with_ttl(&principal, Some(turn_cfg), ttl_override);
    let Some((host, port)) = turn_cfg
        .urls
        .first()
        .and_then(|u| roomler_ai_remote_control::turn_url::host_port(u))
    else {
        return servers;
    };
    let Some(ip) = resolve_pick_worker(&host, port, pair_key).await else {
        warn!(%host, "overlay relay: coturn DNS resolve failed; not pinning a worker");
        return servers;
    };
    let ip_s = ip.to_string();
    rewrite_ice_hosts(servers, &host, &ip_s)
}

/// Rewrite the coturn hostname to the pinned worker `ip` in every ICE URL —
/// EXCEPT `turns:` (TLS) URLs, which keep the hostname so the agent's TLS SNI +
/// certificate verification match coturn's DNS-only cert. Pinning the worker IP
/// is correct for the UDP tier (no TLS); on the TURNS/TCP tier an IP host makes
/// rustls verify a DNS cert against an IP literal → `NotValidForName` → the
/// handshake fails on the UDP-blocked corp VPNs that are the ONLY nets to reach
/// Tier 3. The same-worker hairpin for TURNS is restored separately via a
/// `&pin=` dial hint (rc.140); here we simply leave `turns:` hostnames intact.
fn rewrite_ice_hosts(servers: Vec<IceServer>, host: &str, ip: &str) -> Vec<IceServer> {
    servers
        .into_iter()
        .map(|mut s| {
            for u in s.urls.iter_mut() {
                if u.starts_with("turns:") {
                    // Keep the hostname for TLS SNI + cert verification, and
                    // append `&pin=<ip>` so the agent DIALS the pinned worker
                    // while still presenting the hostname coturn's cert matches
                    // (rc.140) — restores the same-worker hairpin over TURNS.
                    if !u.contains("pin=") {
                        let sep = if u.contains('?') { '&' } else { '?' };
                        u.push_str(&format!("{sep}pin={ip}"));
                    }
                    continue;
                }
                *u = u.replace(host, ip);
            }
            s
        })
        .collect()
}

/// `host:port` of a `turn:`/`turns:` url (strips scheme + `?query`), e.g.
/// `turn:coturn.roomler.ai:3478?transport=udp` → `coturn.roomler.ai:3478`.
/// `None` if there's no `host:port` pair.
fn turn_url_host_port(u: &str) -> Option<String> {
    let rest = u
        .strip_prefix("turns:")
        .or_else(|| u.strip_prefix("turn:"))?;
    let hp = rest.split('?').next()?;
    (!hp.is_empty() && hp.contains(':')).then(|| hp.to_string())
}

/// NAT-traversal Phase B — the STUN endpoints a joining node queries to gather
/// its server-reflexive candidates, derived from the configured coturn workers.
/// A coturn `turn:host:port` UDP listener also answers STUN Binding requests, so
/// each UDP `turn:` URL maps to a `stun:host:port`. `turns:` (TLS) and
/// `?transport=tcp` variants are skipped — plain STUN is UDP. Deduped.
/// If no UDP worker is available (including TLS-only/no authenticated TURN),
/// reuse the canonical public STUN list. Discovery does not require TURN auth.
fn stun_urls_from_turn(state: &NetworkState) -> Vec<String> {
    let urls = build_turn_config(&state.settings.turn)
        .map(|cfg| cfg.urls)
        .unwrap_or_default();
    stun_urls_from_turn_urls(&urls)
}

/// Pure core of [`stun_urls_from_turn`] — testable without an `AppState`.
fn stun_urls_from_turn_urls(turn_urls: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in turn_urls {
        if u.starts_with("turns:") || u.contains("transport=tcp") {
            continue;
        }
        let Some(hp) = turn_url_host_port(u) else {
            continue;
        };
        let stun = format!("stun:{hp}");
        if !out.contains(&stun) {
            out.push(stun);
        }
    }
    if out.is_empty() {
        turn_creds::default_stun_servers()
            .into_iter()
            .flat_map(|server| server.urls)
            .collect()
    } else {
        out
    }
}

/// Short-TTL process cache of resolved coturn worker IP sets, keyed by host
/// (one entry per region's coturn hostname).
///
/// The relay pin MUST be identical for BOTH ends of a pair — they co-locate on
/// one coturn worker so the relay-to-relay leg is an intra-worker hairpin
/// (cross-worker traffic drops under buildhost's dual-public-IP SNAT). But
/// `lookup_host` can return a rotating subset/order per call, so two grants for
/// the same pair seconds apart could resolve **different-sized** IP sets and
/// `pick_worker_fnv1a` (FNV `% len`) would then pick DIFFERENT workers — exactly
/// the field split (DEVBOX on one worker, the VPN'd peer on another → 100% loss).
/// Resolving ONCE and caching for a short TTL makes every grant in the window
/// share one stable set → one pin. On a transient resolve failure we reuse the
/// last-good set rather than emit an unpinned grant that would round-robin the
/// pair apart. (Both peers of a pair land on the SAME pod — the front LB
/// hashes on tenant — so this process cache is authoritative per pair.)
/// host → (resolved-at, worker IPs) — one entry per region's coturn hostname.
type WorkerSets = std::collections::HashMap<String, (Instant, Vec<IpAddr>)>;
static WORKER_SET_CACHE: Mutex<Option<WorkerSets>> = Mutex::new(None);
const WORKER_SET_TTL: Duration = Duration::from_secs(300);

/// Resolve a coturn host's worker IPs through [`WORKER_SET_CACHE`] so the pin
/// is stable across grants. Returns the cached set while fresh; otherwise
/// resolves, caches, and returns; on resolve failure reuses the host's
/// last-good set (empty only before its first successful resolve).
async fn resolve_workers_cached(host: &str, port: u16) -> Vec<IpAddr> {
    {
        let mut guard = WORKER_SET_CACHE.lock().unwrap();
        let cache = guard.get_or_insert_with(Default::default);
        if let Some((at, ips)) = cache.get(host)
            && at.elapsed() < WORKER_SET_TTL
            && !ips.is_empty()
        {
            return ips.clone();
        }
    }
    let mut ips: Vec<IpAddr> = match lookup_host((host, port)).await {
        Ok(addrs) => addrs.map(|s| s.ip()).collect(),
        Err(_) => Vec::new(),
    };
    ips.sort();
    ips.dedup();
    let mut guard = WORKER_SET_CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(Default::default);
    if !ips.is_empty() {
        cache.insert(host.to_string(), (Instant::now(), ips.clone()));
        return ips;
    }
    // Transient resolve failure: reuse the last-good set (even if past TTL) so a
    // DNS blip doesn't unpin grants and split pairs across workers.
    cache
        .get(host)
        .map(|(_, ips)| ips.clone())
        .unwrap_or_default()
}

/// Sticky per-pair relay region. A re-grant inside the TTL reuses the prior
/// choice even if a probe report moved a home meanwhile — the worker pin and
/// the region must stay stable for a LIVE pair, or its two ends land on
/// different PoPs and the relay carries nothing. TTL-expired entries recompute
/// (a dead pair's next establishment cycle may then move regions).
const PAIR_REGION_TTL: Duration = Duration::from_secs(600);
/// pair_key → (chosen region, decided-at). `None` region = the default.
type PairRegions = std::collections::HashMap<String, (Option<String>, Instant)>;
static PAIR_REGION_CACHE: Mutex<Option<PairRegions>> = Mutex::new(None);

fn sticky_pair_region(
    map: &roomler_ai_remote_control::turn_creds::TurnMap,
    load: &roomler_ai_remote_control::turn_creds::RelayLoadMap,
    pair_key: &str,
    home_a: Option<&str>,
    home_b: Option<&str>,
    needs_tls: bool,
) -> Option<String> {
    if !map.enabled {
        return None;
    }
    let mut guard = PAIR_REGION_CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(Default::default);
    if let Some((region, at)) = cache.get(pair_key)
        && at.elapsed() < PAIR_REGION_TTL
    {
        return region.clone();
    }
    // Opportunistic sweep so dead pairs don't accrete on a long-lived pod.
    if cache.len() > 2048 {
        cache.retain(|_, (_, at)| at.elapsed() < PAIR_REGION_TTL);
    }
    let region = turn_creds::select_pair_region(map, load, home_a, home_b, pair_key, needs_tls);
    cache.insert(pair_key.to_string(), (region.clone(), Instant::now()));
    region
}

/// Resolve `host` (cached, stable) and pick one IPv4 worker, indexed by
/// `pair_key`. Both ends of a pair get the identical result → intra-worker
/// hairpin.
async fn resolve_pick_worker(host: &str, port: u16, pair_key: &str) -> Option<IpAddr> {
    let ips = resolve_workers_cached(host, port).await;
    // Both peers of a pair share the `pair_key`, and the broker hands them
    // the SAME single result, so they co-locate. The pick is the ONE shared
    // `remote_control::worker_pick` implementation (invariant I6) — the
    // overlay client computes its own fallback pick with the same fn.
    pick_worker_fnv1a(pair_key, ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `overlay_ip` and its inverse `overlay_host` now live in
    // `roomler_ai_remote_control::models` (the free pool needs the inverse, and
    // the model crate is shared with `services` and the agent). Their tests —
    // including the round-trip that pins the two together — moved with them.

    /// A node row with just enough shape for `to_netmap_peer`.
    fn node(name: &str, ip: &str) -> OverlayNode {
        let now = bson::DateTime::now();
        OverlayNode {
            id: Some(ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap()),
            tenant_id: ObjectId::new(),
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: ObjectId::new(),
            machine_id: "machine".into(),
            name: name.into(),
            overlay_ip: ip.into(),
            wg_public_key: "cHVia2V5".into(),
            key_epoch: 0,
            endpoints: vec!["1.2.3.4:1234".into()],
            lan_endpoints: vec!["192.168.1.5:41641".into()],
            srflx_endpoints: vec!["5.6.7.8:5678".into()],
            srflx_nat: Some("cone".into()),
            caps: None,
            caps_measured_at: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            supports_quic: true,
            supports_relay_single: true,
            supports_derp: true,
            supports_forced_derp: true,
            supports_server_relay_strategy: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            supports_org_relay: false,
            advertised_routes: vec![],
            approved_routes: vec![],
            is_exit_node: false,
            routes_zone: None,
            route_offer_withheld: None,
            status: AgentStatus::Online,
            last_seen_at: now,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// The leave path fans THIS shape. `reachable = false` is what makes a
    /// receiving peer render the row `offline` (`online: np.reachable`) and
    /// stop dialing it (`peer_config_from_netmap` drops unreachable peers) —
    /// instead of the row vanishing, which is what a `removes` delta did.
    #[test]
    fn leave_upsert_is_the_same_row_marked_unreachable() {
        let n = node("corplap-3-wsl", "100.64.0.7");
        let peer = to_netmap_peer(&n, false);

        assert!(
            !peer.reachable,
            "a node that just left must not be dialable"
        );
        // Identity must survive, or the receiver can't match it to the row it
        // already holds and the delta silently creates a duplicate/no-op.
        assert_eq!(peer.node_id, n.id.unwrap());
        assert_eq!(peer.overlay_ip, "100.64.0.7");
        assert_eq!(peer.name, "corplap-3-wsl");
        assert_eq!(peer.wg_public_key, "cHVia2V5");
    }

    /// FR-97 P0b — an approval outlives a rejoin, so on its own it is not an
    /// offer. A node that stopped advertising its `/0` (the operator turned
    /// the exit off, or the device found it cannot NAT) stops being an exit in
    /// its peers' netmaps at the next fan, while its other approved routes keep
    /// flowing; the exit returns by itself when the offer does.
    #[test]
    fn only_approved_routes_the_node_still_advertises_reach_peers() {
        let mut n = node("exit", "100.64.0.9");
        n.is_exit_node = true;
        n.approved_routes = vec!["10.1.0.0/24".into(), "0.0.0.0/0".into()];
        n.advertised_routes = vec!["10.1.0.0/24".into()];
        assert_eq!(
            to_netmap_peer(&n, true).routes,
            vec!["10.1.0.0/24".to_string()],
            "a /0 the device no longer offers must not reach a single peer"
        );

        n.advertised_routes.push("0.0.0.0/0".into());
        assert_eq!(
            to_netmap_peer(&n, true).routes,
            vec!["10.1.0.0/24".to_string(), "0.0.0.0/0".to_string()],
            "the offer is back, and the stored approval with it"
        );

        n.approved_routes.clear();
        assert!(
            to_netmap_peer(&n, true).routes.is_empty(),
            "an offer the admin never approved reaches no one either"
        );
    }

    /// FR-97 P0b — under an enforcing ACL, a peer visible ONLY through a
    /// subnet grant is withheld once the device stops offering that subnet. The
    /// ACL grants from the same offered set the netmap fans; an approval the
    /// device withdrew must not keep the gateway visible.
    #[test]
    fn an_enforcing_acl_grants_only_what_the_peer_still_offers() {
        use roomler_ai_remote_control::models::{
            OverlayRule, OverlaySelector, OverlayTarget, PortRange, ProtocolKind,
        };
        let now = bson::DateTime::now();
        let acl = AclCtx {
            mode: OverlayAclMode::Enforce,
            policies: vec![OverlayPolicy {
                id: None,
                tenant_id: ObjectId::new(),
                name: "the lab subnet".into(),
                enabled: true,
                sources: vec![OverlaySelector::AllNodes],
                via: vec![OverlayTarget::AllNodes],
                // Covers the subnet, NOT the router's own overlay address: the
                // router is visible only through the route it carries.
                destinations: vec![OverlayRule {
                    cidr: "10.1.0.0/24".into(),
                    port_range: PortRange {
                        low: 1,
                        high: u16::MAX,
                    },
                    proto: ProtocolKind::Any,
                }],
                created_at: now,
                updated_at: now,
                deleted_at: None,
            }],
        };
        let src = OverlaySource {
            node_id: ObjectId::new(),
            owner_user_id: None,
            role_ids: vec![],
        };
        let mut router = node("router", "100.64.0.9");
        router.approved_routes = vec!["10.1.0.0/24".into()];
        router.advertised_routes = vec!["10.1.0.0/24".into()];
        let shaped = shape_peer(&acl, &src, &router, None, true, Zones::OFF)
            .expect("visible through the subnet it offers");
        assert_eq!(shaped.routes, vec!["10.1.0.0/24".to_string()]);

        router.advertised_routes.clear();
        assert!(
            shape_peer(&acl, &src, &router, None, true, Zones::OFF).is_none(),
            "an approval the device no longer offers grants nothing"
        );
    }

    /// A line peer is never told a relay tier: every stamping site goes
    /// through `stamp_verdict`, which leaves the line's cleared verdict alone.
    #[test]
    fn a_line_peer_is_never_stamped_a_relay_tier() {
        let n = node("member", "100.64.0.15");
        let mut plain = to_netmap_peer(&n, true);
        stamp_verdict(&mut plain, Some(RelayStrategyWire::Derp));
        assert_eq!(plain.relay_strategy, Some(RelayStrategyWire::Derp));
        let mut line = line_only(to_netmap_peer(&n, true));
        stamp_verdict(&mut line, Some(RelayStrategyWire::Derp));
        assert_eq!(line.relay_strategy, None);
    }

    /// #18 — an unreadable policy never shapes as "ACL off": the last one read
    /// stands in, and with none read yet the netmap fails closed.
    #[test]
    fn an_unreadable_acl_is_never_allow_all() {
        let tenant = ObjectId::new();
        let closed = settle_acl(tenant, Err::<AclCtx, _>("mongo down"));
        assert!(
            closed.enforcing() && closed.policies.is_empty(),
            "none read yet: closed"
        );
        settle_acl::<&str>(tenant, Ok(AclCtx::off()));
        assert!(
            !settle_acl(tenant, Err::<AclCtx, _>("blip")).gating(),
            "the last read stands"
        );
    }

    /// Guards the join path against regressing to a blanket `true`: presence
    /// is the caller's verdict, and both verdicts must be expressible.
    #[test]
    fn to_netmap_peer_carries_presence_verbatim() {
        let n = node("buildhost", "100.64.0.14");
        assert!(to_netmap_peer(&n, true).reachable);
        assert!(!to_netmap_peer(&n, false).reachable);
    }

    #[test]
    fn pair_key_is_symmetric() {
        let a = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let b = ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap();
        assert_eq!(pair_key(a, b), pair_key(b, a));
        assert!(pair_key(a, b).contains(&a.to_hex()));
    }

    /// Dialer honesty — the effective-UDP input rule must mirror the client's
    /// (`tunnel_core::overlay::relay_link::relay_strategy`) exactly: a
    /// `Some(false)` verdict counts only when the OTHER end carries the field
    /// (`None` = pre-honesty agent ⇒ legacy srflx-only inputs on both ends).
    #[test]
    fn effective_udp_ok_mirrors_the_client_honesty_rule() {
        // Legacy everywhere: no flags ⇒ srflx alone decides.
        assert!(effective_udp_ok(true, None, None));
        assert!(!effective_udp_ok(false, None, None));
        // Latched host vs honesty-capable other ⇒ NOT udp-capable (anchors).
        assert!(!effective_udp_ok(true, Some(false), Some(true)));
        assert!(!effective_udp_ok(true, Some(false), Some(false)));
        // Latched host vs PRE-honesty other ⇒ legacy (a mixed pair must not
        // split roles).
        assert!(effective_udp_ok(true, Some(false), None));
        // A healthy new host is unaffected in every mix.
        assert!(effective_udp_ok(true, Some(true), Some(false)));
        assert!(effective_udp_ok(true, Some(true), None));
        // srflx gates everything, flags or not.
        assert!(!effective_udp_ok(false, Some(true), Some(true)));
    }

    /// U2 — the PARITY LOCK: the server's pure verdict core must reproduce the
    /// client's `relay_strategy()` rules exactly (the client's own doc-comment
    /// truth table, transcribed). U3 deletes the client copy only while this
    /// holds; any divergence between the two implementations breaks here.
    #[test]
    fn server_verdict_matches_client_rules() {
        use RelayStrategyWire::*;
        let lo = [1u8; 32]; // smaller raw pubkey
        let hi = [9u8; 32];
        // Legacy rows (no honesty latch): effective == raw srflx.
        let core =
            |pinned, both_derp, both_single, my_udp, peer_udp, a: &[u8; 32], b: &[u8; 32]| {
                relay_verdict_core(
                    pinned,
                    both_derp,
                    both_single,
                    my_udp,
                    peer_udp,
                    my_udp,
                    peer_udp,
                    a,
                    b,
                )
            };
        // Pin wins over everything.
        assert_eq!(core(true, false, true, true, true, &lo, &hi), Derp);
        assert_eq!(core(true, false, false, false, false, &lo, &hi), Derp);
        // single-relay by UDP capability (both advertise single):
        //   we-ok / peer-blocked → WE dial (peer anchors)
        assert_eq!(
            core(false, false, true, true, false, &lo, &hi),
            SingleRelayDialer
        );
        //   we-blocked / peer-ok → WE anchor
        assert_eq!(
            core(false, false, true, false, true, &lo, &hi),
            SingleRelayAnchor
        );
        //   both-ok → smaller raw pubkey anchors (and its mirror dials)
        assert_eq!(
            core(false, false, true, true, true, &lo, &hi),
            SingleRelayAnchor
        );
        assert_eq!(
            core(false, false, true, true, true, &hi, &lo),
            SingleRelayDialer
        );
        // both-blocked + both support DERP → DERP (the only both-blocked tier)
        assert_eq!(core(false, true, true, false, false, &lo, &hi), Derp);
        // both-blocked but NO shared DERP → both-allocate
        assert_eq!(
            core(false, false, true, false, false, &lo, &hi),
            BothAllocate
        );
        // single-relay NOT mutually advertised → both-allocate even if UDP-ok
        assert_eq!(
            core(false, false, false, true, false, &lo, &hi),
            BothAllocate
        );

        // Honesty rows (rc.393 storm lock): a LATCHED host has effective
        // udp=false but raw srflx=true — it must anchor in single-relay,
        // and a both-latched pair must land BothAllocate, NEVER Derp (the
        // lazy /derp mux only exists on srflx-EMPTY nodes; stamping Derp
        // deadlocked exactly the pairs the storm blocked).
        assert_eq!(
            relay_verdict_core(false, true, true, false, true, true, true, &hi, &lo),
            SingleRelayAnchor,
            "latched (srflx-present) host anchors regardless of pubkey"
        );
        assert_eq!(
            relay_verdict_core(false, true, true, false, false, true, true, &lo, &hi),
            BothAllocate,
            "both-latched srflx-present pair must NOT be stamped Derp"
        );
        assert_eq!(
            relay_verdict_core(false, true, true, false, false, true, false, &lo, &hi),
            BothAllocate,
            "latched host vs genuinely udp-blocked peer: mixed srflx ⇒ both-allocate"
        );
    }

    /// U2 — the both-ends capability gate + the anchor/dialer SYMMETRY (the
    /// whole reason it's server-computed): the reverse edge swaps my/peer, so
    /// exactly one end is stamped anchor and the other dialer.
    #[test]
    fn server_verdict_gated_and_symmetric() {
        let mut a = node("a", "100.64.0.2");
        let mut b = node("b", "100.64.0.4");
        a.wg_public_key = BASE64.encode([1u8; 32]);
        b.wg_public_key = BASE64.encode([9u8; 32]);
        a.supports_server_relay_strategy = true;
        b.supports_server_relay_strategy = true;
        // Both UDP-capable, both advertise single-relay → smaller pubkey (a)
        // anchors; the reverse edge sees a dialer. `node()` sets both
        // supports_relay_single = true. No pin (pinned = false).
        a.srflx_endpoints = vec!["1.2.3.4:5".into()];
        b.srflx_endpoints = vec!["6.7.8.9:0".into()];
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor)
        );
        assert_eq!(
            verdict_from_nodes(&b, &a, false),
            Some(RelayStrategyWire::SingleRelayDialer)
        );
        // One end unflagged → the server withholds the verdict entirely (both
        // ends then compute locally, staying symmetric on their own).
        b.supports_server_relay_strategy = false;
        assert_eq!(verdict_from_nodes(&a, &b, false), None);
        assert_eq!(verdict_from_nodes(&b, &a, false), None);
    }

    /// D0 — after a ONE-SIDED input change, re-computing BOTH directions
    /// from the same row generation must land a coherent anchor/dialer
    /// pair. The reverse fan (`fan_upsert_shaped`) delivers the
    /// `changed-node → peer` half to the changed node itself; this locks
    /// that the two halves can never disagree when both are stamped from
    /// the same rows — the both-dialer wedge requires a GENERATION split,
    /// never a rule split.
    #[test]
    fn one_sided_change_restamps_a_coherent_pair() {
        let mut a = node("a", "100.64.0.2");
        let mut b = node("b", "100.64.0.4");
        a.wg_public_key = BASE64.encode([1u8; 32]);
        b.wg_public_key = BASE64.encode([9u8; 32]);
        a.supports_server_relay_strategy = true;
        b.supports_server_relay_strategy = true;
        a.srflx_endpoints = vec!["1.2.3.4:5".into()];
        b.srflx_endpoints = vec!["6.7.8.9:0".into()];
        // Baseline: both udp-ok ⇒ smaller pubkey (a) anchors.
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor)
        );
        // One-sided flip: a loses its srflx. Both directions re-stamped
        // from the SAME new generation stay complementary.
        a.srflx_endpoints.clear();
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor),
            "blocked side anchors"
        );
        assert_eq!(
            verdict_from_nodes(&b, &a, false),
            Some(RelayStrategyWire::SingleRelayDialer),
            "capable side dials — coherent with the reverse half"
        );
        // One-sided MEASURED flip: a's fresh vector says the band is
        // dropped while b's says it works — still exactly one dialer.
        use roomler_ai_remote_control::signaling::CapVectorWire;
        a.srflx_endpoints = vec!["1.2.3.4:5".into()];
        a.caps = Some(CapVectorWire {
            stun_udp: true,
            relay_band_udp: Some(false),
            derp_ws_ok: true,
        });
        a.caps_measured_at = Some(bson::DateTime::now());
        b.caps = Some(CapVectorWire {
            stun_udp: true,
            relay_band_udp: Some(true),
            derp_ws_ok: true,
        });
        b.caps_measured_at = Some(bson::DateTime::now());
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor)
        );
        assert_eq!(
            verdict_from_nodes(&b, &a, false),
            Some(RelayStrategyWire::SingleRelayDialer)
        );
    }

    /// B3 — the MEASURED relay-band pair supersedes the srflx/latch inputs
    /// when BOTH ends hold a fresh vector (mirrors the client's
    /// `relay_strategy` measured branch); one-sided or STALE measurement
    /// keeps the legacy rules verbatim.
    #[test]
    fn server_verdict_measured_branch_and_freshness() {
        use roomler_ai_remote_control::signaling::CapVectorWire;
        let caps = |band: Option<bool>| {
            Some(CapVectorWire {
                stun_udp: true,
                relay_band_udp: band,
                derp_ws_ok: true,
            })
        };
        let mut a = node("a", "100.64.0.2");
        let mut b = node("b", "100.64.0.4");
        a.wg_public_key = BASE64.encode([1u8; 32]);
        b.wg_public_key = BASE64.encode([9u8; 32]);
        a.supports_server_relay_strategy = true;
        b.supports_server_relay_strategy = true;
        // The corplap case, measured: srflx PRESENT + no latch, but the probe
        // proved a's relay band is dropped ⇒ a anchors, b dials — despite
        // the srflx/pubkey inputs saying otherwise.
        a.srflx_endpoints = vec!["1.2.3.4:5".into()];
        b.srflx_endpoints = vec!["6.7.8.9:0".into()];
        a.caps = caps(Some(false));
        a.caps_measured_at = Some(bson::DateTime::now());
        b.caps = caps(Some(true));
        b.caps_measured_at = Some(bson::DateTime::now());
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor),
            "measured relay-band-blocked host anchors despite srflx presence"
        );
        assert_eq!(
            verdict_from_nodes(&b, &a, false),
            Some(RelayStrategyWire::SingleRelayDialer),
            "reverse edge stays symmetric on the measured inputs"
        );
        // Measurement outranks the latch: a's latch says blocked, but a
        // fresh probe proved the band works ⇒ legacy latch inputs ignored.
        a.udp_dialer_ok = Some(false);
        a.caps = caps(Some(true));
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor),
            "both measured-capable ⇒ pubkey tie-break (smaller anchors), latch ignored"
        );
        // One-sided measurement (peer's vector carries no band bit) ⇒ the
        // legacy rules apply — and the latch now counts again (b carries
        // the honesty field, so a's Some(false) is honoured).
        b.caps = caps(None);
        b.udp_dialer_ok = Some(true);
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor),
            "one-sided measurement ⇒ legacy inputs (latched a anchors)"
        );
        // STALE measurement = absent: an hour-old vector on a must not
        // engage the measured branch either.
        a.udp_dialer_ok = None;
        a.caps = caps(Some(false));
        a.caps_measured_at = Some(bson::DateTime::from_millis(
            bson::DateTime::now().timestamp_millis() - 61 * 60 * 1000,
        ));
        b.caps = caps(Some(true));
        assert_eq!(
            verdict_from_nodes(&a, &b, false),
            Some(RelayStrategyWire::SingleRelayAnchor),
            "stale vector ⇒ legacy srflx inputs (both udp-ok ⇒ smaller pubkey anchors)"
        );
    }

    #[test]
    fn turn_url_host_port_keeps_the_port() {
        assert_eq!(
            turn_url_host_port("turn:coturn.roomler.ai:3478?transport=udp").as_deref(),
            Some("coturn.roomler.ai:3478")
        );
        assert_eq!(
            turn_url_host_port("turn:coturn.roomler.ai:443").as_deref(),
            Some("coturn.roomler.ai:443")
        );
        // No port → None (STUN needs an explicit endpoint).
        assert_eq!(turn_url_host_port("turn:coturn.roomler.ai"), None);
    }

    #[test]
    fn stun_urls_derives_udp_turn_only() {
        // The full expansion `build_turn_config` produces from a plain base URL:
        // UDP `turn:` on 3478 + 443, plus TCP + TLS variants. STUN wants only the
        // UDP `turn:` listeners → two `stun:` URLs, deduped, TLS/TCP skipped.
        let turn_urls = vec![
            "turn:coturn.roomler.ai:3478".to_string(),
            "turn:coturn.roomler.ai:443?transport=udp".to_string(),
            "turn:coturn.roomler.ai:3478?transport=tcp".to_string(),
            "turns:coturn.roomler.ai:5349?transport=tcp".to_string(),
            "turns:coturn.roomler.ai:443?transport=udp".to_string(),
            "turns:coturn.roomler.ai:443?transport=tcp".to_string(),
        ];
        assert_eq!(
            stun_urls_from_turn_urls(&turn_urls),
            vec![
                "stun:coturn.roomler.ai:3478".to_string(),
                "stun:coturn.roomler.ai:443".to_string(),
            ]
        );
        // No usable UDP TURN worker still permits unauthenticated discovery.
        assert_eq!(
            stun_urls_from_turn_urls(&[]),
            turn_creds::default_stun_servers()
                .into_iter()
                .flat_map(|server| server.urls)
                .collect::<Vec<_>>()
        );
        // A same host:port on both UDP transports dedupes.
        assert_eq!(
            stun_urls_from_turn_urls(&[
                "turn:1.2.3.4:3478".to_string(),
                "turn:1.2.3.4:3478?transport=udp".to_string(),
            ]),
            vec!["stun:1.2.3.4:3478".to_string()]
        );
    }


    /// Pure settings/builder coverage: no state, network, secret read or mint.
    fn overlay_stun_test_settings(
        url: Option<&str>,
        secret: bool,
    ) -> roomler_ai_config::TurnSettings {
        roomler_ai_config::TurnSettings {
            url: url.map(str::to_owned),
            worker_urls: None,
            username: None,
            password: None,
            shared_secret: secret.then(|| "fixture-only-secret".to_string()),
            force_relay: Some(false),
            ttl_secs: Some(600),
        }
    }

    fn overlay_stun_urls_for_settings(turn: &roomler_ai_config::TurnSettings) -> Vec<String> {
        let urls = build_turn_config(turn)
            .map(|cfg| cfg.urls)
            .unwrap_or_default();
        stun_urls_from_turn_urls(&urls)
    }

    fn overlay_stun_canonical_urls() -> Vec<String> {
        turn_creds::default_stun_servers()
            .into_iter()
            .flat_map(|server| {
                assert!(server.username.is_none() && server.credential.is_none());
                server.urls
            })
            .collect()
    }

    #[test]
    fn overlay_stun_empty_and_blank_turn_reuse_credential_free_canonical_list() {
        let expected = overlay_stun_canonical_urls();
        assert_eq!(
            expected,
            vec![
                "stun:stun.cloudflare.com:3478",
                "stun:stun.l.google.com:19302"
            ]
        );
        assert_eq!(stun_urls_from_turn_urls(&[]), expected);
        for url in [None, Some(""), Some("   ")] {
            assert_eq!(
                overlay_stun_urls_for_settings(&overlay_stun_test_settings(url, true)),
                expected
            );
        }
    }

    #[test]
    fn overlay_stun_explicit_udp_turn_retains_priority_order_and_deduplication() {
        let urls = vec![
            "turn:worker-b.example:3479?transport=udp".to_string(),
            "turns:worker-a.example:5349?transport=tcp".to_string(),
            "turn:worker-a.example:3478?transport=udp".to_string(),
            "turn:worker-b.example:3479".to_string(),
            "turn:worker-a.example:3478?transport=tcp".to_string(),
        ];
        assert_eq!(
            stun_urls_from_turn_urls(&urls),
            vec!["stun:worker-b.example:3479", "stun:worker-a.example:3478"]
        );
        assert_eq!(
            overlay_stun_urls_for_settings(&overlay_stun_test_settings(
                Some("turn:worker-b.example:3479?transport=udp"),
                true
            )),
            vec!["stun:worker-b.example:3479"]
        );
    }

    #[test]
    fn overlay_stun_tls_or_tcp_only_never_reinterprets_listener_as_udp() {
        let expected = overlay_stun_canonical_urls();
        for url in [
            "turns:tls.example:5349?transport=tcp",
            "turns:tls.example:443?transport=udp",
            "turn:tcp.example:3478?transport=tcp",
        ] {
            let actual =
                overlay_stun_urls_for_settings(&overlay_stun_test_settings(Some(url), true));
            assert_eq!(actual, expected);
            assert!(actual.iter().all(|u| u.starts_with("stun:")
                && !u.contains("tls.example")
                && !u.contains("tcp.example")));
        }
    }

    #[test]
    fn overlay_stun_missing_turn_secret_still_discovers_without_minting_turn() {
        for url in [
            None,
            Some("turn:worker.example:3478?transport=udp"),
            Some("turns:tls.example:5349?transport=tcp"),
        ] {
            let settings = overlay_stun_test_settings(url, false);
            assert!(
                build_turn_config(&settings).is_none(),
                "TURN auth remains unavailable without a secret"
            );
            assert_eq!(
                overlay_stun_urls_for_settings(&settings),
                overlay_stun_canonical_urls()
            );
            assert_eq!(settings.force_relay, Some(false));
        }
    }

    #[test]
    fn overlay_stun_fallback_does_not_modify_configured_turn_or_credentials() {
        let settings =
            overlay_stun_test_settings(Some("turns:tls.example:5349?transport=tcp"), true);
        let before = build_turn_config(&settings).unwrap();
        assert_eq!(
            overlay_stun_urls_for_settings(&settings),
            overlay_stun_canonical_urls()
        );
        let after = build_turn_config(&settings).unwrap();
        assert_eq!(before.urls, after.urls);
        assert_eq!(before.workers, after.workers);
        assert_eq!(before.ttl_secs, after.ttl_secs);
        assert_eq!(before.shared_secret, after.shared_secret);
        assert_eq!(settings.force_relay, Some(false));
    }

    #[test]
    fn rewrite_ice_hosts_pins_udp_ip_but_turns_keeps_hostname_plus_pin() {
        // The pinned worker IP replaces the hostname on UDP/STUN URLs (no TLS),
        // but `turns:` (TLS) URLs keep the hostname for SNI/cert verification and
        // instead get a `&pin=<ip>` dial hint — an IP host would fail cert
        // verification (NotValidForName), yet we still need the same-worker pin.
        let servers = vec![IceServer {
            urls: vec![
                "stun:coturn.roomler.ai:3478".to_string(),
                "turn:coturn.roomler.ai:3478?transport=udp".to_string(),
                "turn:coturn.roomler.ai:443?transport=udp".to_string(),
                "turns:coturn.roomler.ai:443?transport=tcp".to_string(),
                "turns:coturn.roomler.ai:5349?transport=tcp".to_string(),
            ],
            username: Some("u".to_string()),
            credential: Some("c".to_string()),
        }];
        let out = rewrite_ice_hosts(servers, "coturn.roomler.ai", "94.130.141.74");
        assert_eq!(
            out[0].urls,
            vec![
                "stun:94.130.141.74:3478".to_string(),
                "turn:94.130.141.74:3478?transport=udp".to_string(),
                "turn:94.130.141.74:443?transport=udp".to_string(),
                "turns:coturn.roomler.ai:443?transport=tcp&pin=94.130.141.74".to_string(),
                "turns:coturn.roomler.ai:5349?transport=tcp&pin=94.130.141.74".to_string(),
            ]
        );
    }

    /// worker-pick golden vector (invariant I6): the broker's pick is
    /// byte-pinned to the exact value the shared `remote_control::worker_pick`
    /// suite pins — the overlay client's fallback pick asserts the same
    /// literals, so broker↔client agreement can't silently drift.
    #[test]
    fn worker_pick_agrees_with_golden_vector() {
        let a: IpAddr = "5.9.157.221".parse().unwrap();
        let b: IpAddr = "5.9.157.226".parse().unwrap();
        let c: IpAddr = "94.130.141.74".parse().unwrap();
        let key = "507f1f77bcf86cd799439011:507f1f77bcf86cd799439012";
        // FNV-1a(key) = 0xad37_bde0_cdd9_5470; % 3 = 2 → third sorted IPv4.
        assert_eq!(pick_worker_fnv1a(key, vec![a, b, c]), Some(c));
        assert_eq!(pick_worker_fnv1a(key, vec![c, a, b, b]), Some(c)); // shuffled + dup
        // ipv6 filtered; empty → None
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(pick_worker_fnv1a(key, vec![v6, a]), Some(a));
        assert!(pick_worker_fnv1a(key, vec![]).is_none());
    }

    /// P7 — the churn detector's arithmetic: only grant→re-request cycles
    /// count, retry bursts and restart-storms don't, the threshold escalates,
    /// and a mid-TTL request re-escalates without re-counting.
    #[test]
    fn churn_cycles_escalate_and_restarts_do_not() {
        let t0 = Instant::now();
        let mut pc = PairChurn::default();

        // A request with NO prior grant (fresh pair / agent restart) never
        // counts — a crash-looping agent can re-request forever harmlessly.
        assert!(!churn_note_request(&mut pc, t0));
        assert_eq!(pc.cycles, 0);

        // grant → quick retry inside the dedup gap: not a cycle.
        pc.last_grant_at = Some(t0);
        assert!(!churn_note_request(&mut pc, t0 + Duration::from_secs(2)));
        assert_eq!(pc.cycles, 0);

        // Three real grant→re-request cycles ⇒ escalate on the third. (The
        // reassignments below model `note_grant_sent` arming the detector.)
        pc.last_grant_at = Some(t0);
        assert!(!churn_note_request(&mut pc, t0 + Duration::from_secs(30)));
        assert_eq!(pc.cycles, 1);
        // One cycle per grant: a second re-request without a new grant is inert.
        assert!(!churn_note_request(&mut pc, t0 + Duration::from_secs(40)));
        assert_eq!(pc.cycles, 1);
        pc.last_grant_at = Some(t0 + Duration::from_secs(45));
        assert!(!churn_note_request(&mut pc, t0 + Duration::from_secs(75)));
        assert_eq!(pc.cycles, 2);
        pc.last_grant_at = Some(t0 + Duration::from_secs(80));
        assert!(
            churn_note_request(&mut pc, t0 + Duration::from_secs(110)),
            "third cycle inside the window must escalate"
        );
        assert!(pc.forced_until.is_some(), "TTL stamped");

        // Mid-TTL request (a restarted end re-requesting): re-escalate.
        assert!(churn_note_request(&mut pc, t0 + Duration::from_secs(120)));

        // Past the TTL: back to normal counting (first request post-expiry
        // has no grant on record ⇒ not churn).
        let after = t0 + Duration::from_secs(110) + FORCED_DERP_TTL + Duration::from_secs(1);
        assert!(!churn_note_request(&mut pc, after));
        assert_eq!(pc.cycles, 0);
    }

    /// Field 2026-10-27 (rf-84f661a5a7e3): a request that replaces an ORG
    /// carrier is no TURN churn. The pair's three ORG sessions ended (a relay
    /// stopped, a lossy relay revoked, the relay stopped again) and each
    /// re-request counted a cycle, so the pair was pinned to DERP for 30 min
    /// with no TURN carrier ever dying, and stayed there after a relay came
    /// back. Such a request counts nothing and consumes no grant; a standing
    /// pin still answers it.
    #[test]
    fn an_org_replacement_is_not_turn_churn() {
        let t0 = Instant::now();
        let mut pc = PairChurn::default();
        for n in 1..=5u64 {
            pc.last_grant_at = Some(t0 + Duration::from_secs(60 * (n - 1)));
            assert!(
                !churn_note_replacement(
                    &mut pc,
                    t0 + Duration::from_secs(60 * n - 30),
                    Some("org")
                ),
                "ORG replacement #{n} must not escalate"
            );
            assert_eq!(pc.cycles, 0);
            assert!(
                pc.last_grant_at.is_some(),
                "the grant stays armed for a TURN death"
            );
        }
        assert!(pc.forced_until.is_none());

        // A TURN (or DERP) replacement still counts, through the same entry.
        let mut pc = PairChurn::default();
        for (n, kind) in [(1u64, Some("turn")), (2, Some("derp")), (3, None)] {
            pc.last_grant_at = Some(t0 + Duration::from_secs(30 * (n - 1)));
            let escalated =
                churn_note_replacement(&mut pc, t0 + Duration::from_secs(30 * n - 10), kind);
            assert_eq!(escalated, n == 3, "{kind:?}");
        }

        // A standing pin answers an ORG replacement (a restarted end).
        assert!(churn_note_replacement(
            &mut pc,
            t0 + Duration::from_secs(100),
            Some("org")
        ));
    }

    /// ORG loss — a window fails the carrier at 5% of at least 1000
    /// packets; a lost count above the span (a malformed report) is capped.
    #[test]
    fn org_loss_fails_at_five_percent_of_a_judgeable_window() {
        assert!(org_loss_fails(31_000, 2_294), "7.4%, the field's relay");
        assert!(org_loss_fails(1_000, 50), "exactly 5%");
        assert!(!org_loss_fails(1_000, 49));
        assert!(
            !org_loss_fails(999, 60),
            "6% of 999: too few, not clearly over"
        );
        assert!(
            org_loss_fails(200, 20),
            "10% of a light stream's 200: clearly over"
        );
        assert!(!org_loss_fails(99, 99), "under the early floor");
        assert!(!org_loss_fails(0, 0));
        assert!(org_loss_fails(2_000, u64::MAX), "capped at the span");
        assert!(!org_loss_fails(u64::MAX, 0), "no overflow");
    }

    /// ORG loss — the verdict pins the pair for 10 minutes, after which the
    /// churn arithmetic counts afresh, and never shortens a longer pin.
    #[test]
    fn org_loss_pins_the_pair_and_keeps_a_longer_pin() {
        let t0 = Instant::now();
        let mut pc = PairChurn::default();
        org_loss_pin(&mut pc, t0);
        assert_eq!(pc.forced_until, Some(t0 + ORG_LOSS_PIN_TTL));
        assert!(forced_active(&pc, t0 + ORG_LOSS_PIN_TTL - Duration::from_secs(1)));
        assert!(
            churn_note_request(&mut pc, t0 + Duration::from_secs(60)),
            "a TURN request inside the pin is re-escalated, not granted"
        );
        assert!(!forced_active(&pc, t0 + ORG_LOSS_PIN_TTL));
        assert!(!churn_note_request(&mut pc, t0 + ORG_LOSS_PIN_TTL));
        assert_eq!(pc.forced_until, None, "the lapsed pin is cleared");

        let mut churned = PairChurn {
            forced_until: Some(t0 + FORCED_DERP_TTL),
            ..Default::default()
        };
        org_loss_pin(&mut churned, t0);
        assert_eq!(churned.forced_until, Some(t0 + FORCED_DERP_TTL));
        org_loss_pin(&mut churned, t0 + FORCED_DERP_TTL);
        assert_eq!(
            churned.forced_until,
            Some(t0 + FORCED_DERP_TTL + ORG_LOSS_PIN_TTL),
            "a later verdict extends it"
        );
    }

    /// U1 — the burst-starvation lock: two ends alternating request→grant
    /// FASTER than [`CYCLE_MIN_GAP`] must still escalate. The old
    /// unconditional re-stamp in `note_grant_sent` pushed the gap anchor
    /// forward on every uncounted grant, so such a pair churned forever
    /// without a single counted cycle; [`arm_grant`] anchors on the FIRST
    /// grant of a burst instead.
    #[test]
    fn alternating_fast_requests_cannot_starve_the_counter() {
        let t0 = Instant::now();
        let mut pc = PairChurn::default();
        arm_grant(&mut pc, t0);
        let mut now = t0;
        let mut escalated_at = None;
        for i in 0..40 {
            now += Duration::from_secs(2);
            if churn_note_request(&mut pc, now) {
                escalated_at = Some(i);
                break;
            }
            arm_grant(&mut pc, now);
        }
        assert!(
            escalated_at.is_some(),
            "sub-gap alternation must eventually count cycles and escalate"
        );
        // And the anchor rule itself: arming while armed is a no-op.
        let mut pc = PairChurn::default();
        arm_grant(&mut pc, t0);
        arm_grant(&mut pc, t0 + Duration::from_secs(3));
        assert_eq!(pc.last_grant_at, Some(t0), "first grant of a burst anchors");
    }

    /// P7 — cycles outside the sliding window don't accumulate.
    #[test]
    fn churn_window_resets_stale_counts() {
        let t0 = Instant::now();
        let mut pc = PairChurn {
            last_grant_at: Some(t0),
            ..Default::default()
        };
        assert!(!churn_note_request(&mut pc, t0 + Duration::from_secs(30)));
        assert_eq!(pc.cycles, 1);
        // Next cycle lands AFTER the window: the count restarts at 1.
        let late = t0 + CHURN_WINDOW + Duration::from_secs(60);
        pc.last_grant_at = Some(late - Duration::from_secs(30));
        assert!(!churn_note_request(&mut pc, late));
        assert_eq!(pc.cycles, 1, "stale window must reset, not accumulate");
    }
}
