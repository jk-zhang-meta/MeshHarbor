// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-69 P5a — the host's TRANSITIONAL hook implementations: what `network`
//! will register through `Module::hooks` once it is a module, implemented
//! over the host's own overlay code until then and registered under the
//! `network` id, so the fleet module's cascades already run in
//! [`meshharbor_core::hooks::HOOK_ORDER`] through the core registry.
//!
//! When `network` is extracted (P7) this file goes with it — the `impl`
//! moves, the registration becomes the module's own.

use async_trait::async_trait;
use bson::oid::ObjectId;
use meshharbor_core::hooks::{
    FleetLifecycle, ReleasedLease, RenamePropagation, TenantArchived, TenantLifecycle,
};
use meshharbor_remote_control::models::NodeRef;

use crate::NetworkState;

/// The overlay lease + MagicDNS label holder, over the host's overlay code.
pub struct NetworkHooks {
    pub state: NetworkState,
}

#[async_trait]
impl FleetLifecycle for NetworkHooks {
    /// Release the overlay lease BEFORE the row delete and BEFORE the kick
    /// (the kick's WS teardown runs `handle_overlay_leave`, which must find an
    /// already-tombstoned node rather than race the release CAS).
    async fn agent_removed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        machine_id: &str,
        reason: &str,
    ) -> anyhow::Result<Option<ReleasedLease>> {
        let released = crate::overlay::release_overlay_node_for(
            &self.state,
            tenant_id,
            machine_id,
            &NodeRef::Agent { agent_id },
            reason,
        )
        .await;
        Ok(released.map(|r| ReleasedLease {
            overlay_ip: r.overlay_ip,
        }))
    }

    /// Best-effort propagation onto the live overlay node: peers see the new
    /// MagicDNS label immediately (delta re-fan); the device itself re-learns
    /// its self-name on its next reconnect.
    async fn agent_renamed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        name: &str,
    ) -> anyhow::Result<RenamePropagation> {
        let Some(node) = self
            .state
            .overlay_nodes
            .find_live_by_agent(tenant_id, agent_id)
            .await?
        else {
            return Ok(RenamePropagation::NoLiveNode);
        };
        Ok(
            match crate::overlay::propagate_node_rename(&self.state, &node, name).await {
                Some(label) => RenamePropagation::Propagated(label),
                None => RenamePropagation::Failed,
            },
        )
    }

    /// P7b — the tunnel sessions this node holds FOR the agent: the ones
    /// targeting it, and (PR-1) the ones it originated through declared
    /// routes. The per-connection session map is invisible to fleet's nudge
    /// handler, so without this answer a routes-only agent read as IDLE and
    /// got its WS cycled — tearing every declared route plus its overlay
    /// carriers. The reason string is what the nudge reply carries.
    async fn agent_busy(&self, agent_id: ObjectId) -> Option<&'static str> {
        let target_busy = self
            .state
            .tunnel_sessions_by_target_agent
            .get(&agent_id)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let origin_busy = self
            .state
            .tunnel_sessions_by_origin_agent
            .get(&agent_id)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if origin_busy && !target_busy {
            Some("origin_busy")
        } else if target_busy || origin_busy {
            Some("tunnel_busy")
        } else {
            None
        }
    }

    async fn agent_updated(&self, tenant_id: ObjectId, agent_id: ObjectId) -> anyhow::Result<()> {
        // A temporary device's invitations may be what changed: its mark
        // follows them BEFORE the fan, or an ended inviter would keep it.
        crate::overlay::sync_temporary_mark(&self.state, tenant_id, agent_id).await?;
        crate::overlay::publish_and_refan_tenant_authority(
            &self.state,
            tenant_id,
            true,
            "agent_updated",
        )
        .await;
        Ok(())
    }
}

/// Network's side of the tenant cascade (P7b, from the host's archive
/// route): release every overlay node — which pools its address and tells
/// the peers — then quarantine the tenant's block, never re-issue it (a
/// device that never saw the archive still thinks it owns an address in that
/// range).
pub struct NetworkTenantHooks {
    pub state: NetworkState,
}

#[async_trait]
impl TenantLifecycle for NetworkTenantHooks {
    async fn member_removed(&self, tenant_id: ObjectId, _user_id: ObjectId) -> anyhow::Result<()> {
        crate::overlay::publish_and_refan_tenant_authority(
            &self.state,
            tenant_id,
            true,
            "member_removed",
        )
        .await;
        Ok(())
    }

    async fn tenant_archived(
        &self,
        tenant_id: ObjectId,
        reason: &str,
    ) -> anyhow::Result<TenantArchived> {
        let state = &self.state;
        let network = state
            .overlay_networks
            .find_for_tenant(tenant_id)
            .await
            .ok()
            .flatten();
        let mut nodes_released = 0u64;
        if let Some(net) = &network
            && let Some(net_id) = net.id
        {
            let nodes = state
                .overlay_nodes
                .list_active_in_network(tenant_id, net_id)
                .await
                .unwrap_or_default();
            for n in &nodes {
                if crate::overlay::release_overlay_node(state, n, reason)
                    .await
                    .is_some()
                {
                    nodes_released += 1;
                }
            }
        }

        let mut block_quarantined = None;
        if let Some(net_id) = network.as_ref().and_then(|n| n.id)
            && let Ok(Some(block)) = state
                .overlay_networks
                .blocks()
                .find_assigned_for_network(net_id)
                .await
            && let Some(bid) = block.id
            && state
                .overlay_networks
                .blocks()
                .quarantine(bid, reason)
                .await
                .unwrap_or(false)
        {
            block_quarantined = Some(block.cidr);
        }

        Ok(TenantArchived {
            devices_revoked: 0,
            nodes_released,
            block_quarantined,
        })
    }
}
