// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fleet's side of the tenant cascade (FR-69 P7b): when an organization is
//! archived, every device's enrollment is revoked. The agent's long-lived JWT
//! stays cryptographically valid for its full year, so the row is the only
//! thing that can withdraw it — `soft_delete` is what every auth path already
//! checks. The archive route calls the core registry, which runs this after
//! the network module's release of the mesh (`HOOK_ORDER`).

use std::sync::Arc;

use async_trait::async_trait;
use bson::oid::ObjectId;
use meshharbor_core::hooks::{TenantArchived, TenantLifecycle};

use crate::FleetState;

/// The device revocation half of an archive.
pub struct FleetTenantHooks {
    pub state: FleetState,
}

#[async_trait]
impl TenantLifecycle for FleetTenantHooks {
    async fn tenant_archived(
        &self,
        tenant_id: ObjectId,
        _reason: &str,
    ) -> anyhow::Result<TenantArchived> {
        let agents = self
            .state
            .agents
            .list_all_active_for_tenant(tenant_id)
            .await
            .unwrap_or_default();
        let mut devices_revoked = 0u64;
        for a in &agents {
            if let Some(id) = a.id
                && self
                    .state
                    .agents
                    .soft_delete(tenant_id, id)
                    .await
                    .unwrap_or(false)
            {
                devices_revoked += 1;
                // #2267 — and a connected one is kicked and told, as a removal
                // does. Before, its socket and even its hub entry outlived the
                // revocation until something else dropped the socket.
                crate::removal::kick(&self.state, id, self.state.settings.rc.removal_goodbye).await;
            }
        }
        Ok(TenantArchived {
            devices_revoked,
            ..TenantArchived::default()
        })
    }
}

/// What fleet registers with the core registry: the tenant cascade only —
/// fleet is the CALLER of the agent cascade, never a holder.
pub fn hooks(state: &FleetState) -> meshharbor_core::Hooks {
    meshharbor_core::Hooks {
        tenant: Some(Arc::new(FleetTenantHooks {
            state: state.clone(),
        })),
        fleet: None,
        session: None,
    }
}
