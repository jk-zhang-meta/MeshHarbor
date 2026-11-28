// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The inverse edges (FR-69 D6): what a module does when core — or the
//! module that owns a record — tells it that record is going away.
//!
//! The call graph is a DAG (`conference → chat`, `remote → fleet`,
//! `network → fleet`), so the module that OWNS a record can never call the
//! modules that hold state about it: fleet cannot ask network to release an
//! overlay lease, or remote to terminate a session. Those flows exist today
//! as direct calls inside the host; here they are **typed hook traits**,
//! registered at composition time and invoked in [`HOOK_ORDER`] — session
//! holders → lease holders → the record owner — by whoever runs the cascade.
//!
//! Hooks must be idempotent: a cascade can be re-run after a crash mid-way
//! (already true of the code they replace). A hook a profile does not
//! compile is simply not registered, and the cascade skips it.
//!
//! # Registry
//!
//! [`HookRegistry`] lives on `Core` (`core.hooks`) and is shared through
//! every `Core` clone, so a module built BEFORE the host finished composing
//! still sees the hooks registered after it. The host registers each mounted
//! module's [`Module::hooks`](crate::Module::hooks) under the module's id; until
//! a module is extracted, the host registers its own implementation of that
//! module's hooks under the same id (the transitional shape P5a introduced —
//! the network steps of the agent cascade run from host code, but through
//! this registry, in this order).

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bson::oid::ObjectId;

/// The order the cascade runs in: session holders (`remote`) release first,
/// then lease holders (`network`), then the record owner (`fleet`).
pub const HOOK_ORDER: &[&str] = &["remote", "network", "fleet"];

/// What a lease holder freed when an agent was removed — the one piece of
/// hook output a caller reports back (the admin delete route answers with
/// the overlay address it released).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedLease {
    pub overlay_ip: String,
}

/// What a derived-label holder did with an agent rename. Three outcomes on
/// purpose: the agent route reports "no live node" and "propagation failed"
/// differently, and folding them would lose that on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenamePropagation {
    /// The holder has nothing live for this agent — nothing to propagate.
    NoLiveNode,
    /// A live record exists but the new label could not be applied.
    Failed,
    /// The label the record carries now.
    Propagated(String),
}

/// What the holders did when a tenant was archived — summed across them by
/// [`HookRegistry::tenant_archived`], because the archive route reports the
/// counts (P7b: fleet revokes the devices, network releases the mesh and
/// quarantines the block).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantArchived {
    pub devices_revoked: u64,
    pub nodes_released: u64,
    /// The overlay block quarantined, as a CIDR, if the tenant held one.
    pub block_quarantined: Option<String>,
}

/// Hooks core invokes on tenant events.
#[async_trait]
pub trait TenantLifecycle: Send + Sync {
    /// The tenant was archived: the flag is already set, so nothing new can
    /// enroll or start; tear down what you hold for it and say how much.
    async fn tenant_archived(
        &self,
        tenant_id: ObjectId,
        reason: &str,
    ) -> anyhow::Result<TenantArchived> {
        let _ = (tenant_id, reason);
        Ok(TenantArchived::default())
    }

    async fn member_removed(&self, tenant_id: ObjectId, user_id: ObjectId) -> anyhow::Result<()> {
        let _ = (tenant_id, user_id);
        Ok(())
    }
}

/// Hooks `fleet` invokes on agent events. Implemented by the modules that hold
/// state ABOUT an agent (`remote`: sessions; `network`: the overlay lease,
/// tunnels, the MagicDNS label) — never by fleet itself, which is the caller.
#[async_trait]
pub trait FleetLifecycle: Send + Sync {
    /// The agent is being removed (admin delete, self-unenroll, the ephemeral
    /// reaper). Release what you hold for it. Runs BEFORE the row is deleted
    /// or tombstoned and BEFORE the socket is kicked — the order the overlay
    /// release has always needed (the kick's teardown must find an
    /// already-tombstoned node rather than race the release CAS). Return the
    /// lease you freed, if any.
    async fn agent_removed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        machine_id: &str,
        reason: &str,
    ) -> anyhow::Result<Option<ReleasedLease>> {
        let _ = (tenant_id, agent_id, machine_id, reason);
        Ok(None)
    }

    /// The agent's name changed. A holder of a derived label (the overlay
    /// node's MagicDNS name) propagates it and says what happened.
    async fn agent_renamed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        name: &str,
    ) -> anyhow::Result<RenamePropagation> {
        let _ = (tenant_id, agent_id, name);
        Ok(RenamePropagation::NoLiveNode)
    }

    async fn agent_offline(&self, tenant_id: ObjectId, agent_id: ObjectId) -> anyhow::Result<()> {
        let _ = (tenant_id, agent_id);
        Ok(())
    }

    /// FR-90 P2c-4 — something a holder decides from changed: the agent's
    /// tags or its owner, now stored. `hive` decides again where the org's
    /// sessions are copied: a tag taken off can make a device leave a
    /// session's replicaset, an owner changed can take it out of another
    /// person's. A failing holder is an error for the caller to report.
    async fn agent_updated(&self, tenant_id: ObjectId, agent_id: ObjectId) -> anyhow::Result<()> {
        let _ = (tenant_id, agent_id);
        Ok(())
    }

    /// Capability changes must report authority refresh failures, unlike
    /// ordinary metadata updates whose holders may retain best-effort behavior.
    async fn agent_access_changed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> anyhow::Result<()> {
        self.agent_updated(tenant_id, agent_id).await
    }

    /// Is the agent doing something a holder would lose if its socket were
    /// cycled? Fleet's owner-side rehome nudge asks this before cycling an
    /// idle-looking agent (P7b): `network` answers while tunnel sessions
    /// target the agent (`"tunnel_busy"`) or were originated by it
    /// (`"origin_busy"`, PR-1 — the per-connection session map is invisible
    /// to fleet, and without this a routes-only agent read as IDLE and got
    /// its WS cycled). The string is the refusal reason the nudge reply
    /// carries, verbatim.
    async fn agent_busy(&self, agent_id: ObjectId) -> Option<&'static str> {
        let _ = agent_id;
        None
    }
}

/// What one module registers: the hook traits it implements.
#[derive(Clone, Default)]
pub struct Hooks {
    pub tenant: Option<Arc<dyn TenantLifecycle>>,
    pub fleet: Option<Arc<dyn FleetLifecycle>>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field("tenant", &self.tenant.is_some())
            .field("fleet", &self.fleet.is_some())
            .finish()
    }
}

/// Every registered module's hooks, keyed by module id, invoked in
/// [`HOOK_ORDER`]. Shared (an `Arc`) so a registration made after a `Core`
/// was cloned is visible to that clone.
#[derive(Clone, Default)]
pub struct HookRegistry {
    inner: Arc<RwLock<Vec<(&'static str, Hooks)>>>,
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&'static str> = self.registered();
        f.debug_struct("HookRegistry")
            .field("modules", &ids)
            .finish()
    }
}

impl HookRegistry {
    /// Register `hooks` under a module id. A second registration for the same
    /// id replaces the first (a module's hooks are one object).
    pub fn register(&self, module: &'static str, hooks: Hooks) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.retain(|(id, _)| *id != module);
        inner.push((module, hooks));
    }

    /// The module ids with hooks registered, in [`HOOK_ORDER`].
    pub fn registered(&self) -> Vec<&'static str> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        HOOK_ORDER
            .iter()
            .copied()
            .filter(|id| inner.iter().any(|(m, _)| m == id))
            .collect()
    }

    /// The registered [`FleetLifecycle`] hooks, in [`HOOK_ORDER`].
    pub fn fleet_lifecycles(&self) -> Vec<(&'static str, Arc<dyn FleetLifecycle>)> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        HOOK_ORDER
            .iter()
            .filter_map(|id| {
                inner
                    .iter()
                    .find(|(m, _)| m == id)
                    .and_then(|(_, h)| h.fleet.clone())
                    .map(|h| (*id, h))
            })
            .collect()
    }

    /// The registered [`TenantLifecycle`] hooks, in [`HOOK_ORDER`].
    pub fn tenant_lifecycles(&self) -> Vec<(&'static str, Arc<dyn TenantLifecycle>)> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        HOOK_ORDER
            .iter()
            .filter_map(|id| {
                inner
                    .iter()
                    .find(|(m, _)| m == id)
                    .and_then(|(_, h)| h.tenant.clone())
                    .map(|h| (*id, h))
            })
            .collect()
    }

    /// Run every `agent_removed` hook in order. The first lease a holder
    /// reports is the cascade's answer; a failing hook stops the cascade —
    /// removing the row while a holder still has the lease is exactly the
    /// state this order exists to prevent.
    pub async fn agent_removed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        machine_id: &str,
        reason: &str,
    ) -> anyhow::Result<Option<ReleasedLease>> {
        let mut released = None;
        for (module, hook) in self.fleet_lifecycles() {
            let out = hook
                .agent_removed(tenant_id, agent_id, machine_id, reason)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: agent_removed: {e}"))?;
            if released.is_none() {
                released = out;
            }
        }
        Ok(released)
    }

    /// Run every `agent_renamed` hook in order; the first holder that had a
    /// live record decides the outcome. A failing hook is an error for the
    /// caller to report — a rename that did not reach the mesh must not read
    /// as one that did.
    pub async fn agent_renamed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        name: &str,
    ) -> anyhow::Result<RenamePropagation> {
        let mut outcome = RenamePropagation::NoLiveNode;
        for (module, hook) in self.fleet_lifecycles() {
            let out = hook
                .agent_renamed(tenant_id, agent_id, name)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: agent_renamed: {e}"))?;
            if outcome == RenamePropagation::NoLiveNode {
                outcome = out;
            }
        }
        Ok(outcome)
    }

    /// FR-90 P2c-4 — run every `agent_updated` hook in order. A failing hook
    /// stops the run and is the caller's to report: a tag taken off that did
    /// not reach placement must not read as done.
    pub async fn agent_updated(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> anyhow::Result<()> {
        for (module, hook) in self.fleet_lifecycles() {
            hook.agent_updated(tenant_id, agent_id)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: agent_updated: {e}"))?;
        }
        Ok(())
    }

    pub async fn agent_access_changed(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> anyhow::Result<()> {
        for (module, hook) in self.fleet_lifecycles() {
            hook.agent_access_changed(tenant_id, agent_id)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: agent_access_changed: {e}"))?;
        }
        Ok(())
    }

    /// The first holder that would lose work if the agent's socket were
    /// cycled, with its reason; `None` = every holder reads the agent idle.
    pub async fn agent_busy(&self, agent_id: ObjectId) -> Option<&'static str> {
        for (_, hook) in self.fleet_lifecycles() {
            if let Some(reason) = hook.agent_busy(agent_id).await {
                return Some(reason);
            }
        }
        None
    }

    /// Run every `member_removed` hook in order (FR-90: `hive` ends the
    /// member's agent sessions). Called BEFORE the membership row goes, the
    /// agent cascade's order: a failing holder stops it and the caller
    /// reports the error, so a removal never reads as clean while a pillar
    /// still runs something for that member — and a retry still finds a
    /// member to remove and holders to re-run.
    pub async fn member_removed(
        &self,
        tenant_id: ObjectId,
        user_id: ObjectId,
    ) -> anyhow::Result<()> {
        for (module, hook) in self.tenant_lifecycles() {
            hook.member_removed(tenant_id, user_id)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: member_removed: {e}"))?;
        }
        Ok(())
    }

    /// Run every `tenant_archived` hook in order and sum what they did. A
    /// failing holder stops the cascade — the caller reports the error
    /// rather than an archive that silently left a pillar's state behind.
    pub async fn tenant_archived(
        &self,
        tenant_id: ObjectId,
        reason: &str,
    ) -> anyhow::Result<TenantArchived> {
        let mut total = TenantArchived::default();
        for (module, hook) in self.tenant_lifecycles() {
            let out = hook
                .tenant_archived(tenant_id, reason)
                .await
                .map_err(|e| anyhow::anyhow!("{module}: tenant_archived: {e}"))?;
            total.devices_revoked += out.devices_revoked;
            total.nodes_released += out.nodes_released;
            if total.block_quarantined.is_none() {
                total.block_quarantined = out.block_quarantined;
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::MODULES;

    #[test]
    fn hook_order_covers_every_module_exactly_once() {
        let mut sorted: Vec<&str> = HOOK_ORDER.to_vec();
        sorted.sort_unstable();
        let mut modules: Vec<&str> = MODULES.to_vec();
        modules.sort_unstable();
        assert_eq!(sorted, modules);
    }

    #[test]
    fn session_holders_run_before_lease_holders_before_the_record_owner() {
        let pos = |id: &str| HOOK_ORDER.iter().position(|m| *m == id).unwrap();
        assert!(pos("remote") < pos("network"));
        assert!(pos("network") < pos("fleet"));
    }

    struct Releases(&'static str);

    #[async_trait]
    impl FleetLifecycle for Releases {
        async fn agent_removed(
            &self,
            _tenant_id: ObjectId,
            _agent_id: ObjectId,
            _machine_id: &str,
            _reason: &str,
        ) -> anyhow::Result<Option<ReleasedLease>> {
            Ok(Some(ReleasedLease {
                overlay_ip: self.0.to_string(),
            }))
        }
    }

    struct Fails;

    #[async_trait]
    impl FleetLifecycle for Fails {
        async fn agent_removed(
            &self,
            _tenant_id: ObjectId,
            _agent_id: ObjectId,
            _machine_id: &str,
            _reason: &str,
        ) -> anyhow::Result<Option<ReleasedLease>> {
            anyhow::bail!("lease still held")
        }
    }

    #[tokio::test]
    async fn hooks_run_in_hook_order_regardless_of_registration_order() {
        let reg = HookRegistry::default();
        reg.register(
            "fleet",
            Hooks {
                fleet: Some(Arc::new(Releases("from-fleet"))),
                ..Default::default()
            },
        );
        reg.register(
            "network",
            Hooks {
                fleet: Some(Arc::new(Releases("100.65.4.2"))),
                ..Default::default()
            },
        );
        assert_eq!(reg.registered(), vec!["network", "fleet"]);
        // network runs before fleet, so its lease is the cascade's answer.
        let out = reg
            .agent_removed(ObjectId::new(), ObjectId::new(), "m", "test")
            .await
            .unwrap();
        assert_eq!(out.map(|r| r.overlay_ip).as_deref(), Some("100.65.4.2"));
    }

    #[tokio::test]
    async fn a_failing_holder_stops_the_cascade() {
        let reg = HookRegistry::default();
        reg.register(
            "network",
            Hooks {
                fleet: Some(Arc::new(Fails)),
                ..Default::default()
            },
        );
        let err = reg
            .agent_removed(ObjectId::new(), ObjectId::new(), "m", "test")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("network: agent_removed"));
    }

    /// Records the order `member_removed` reached each holder, and fails on
    /// request.
    struct Member {
        id: &'static str,
        seen: Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    #[async_trait]
    impl TenantLifecycle for Member {
        async fn member_removed(
            &self,
            _tenant_id: ObjectId,
            _user_id: ObjectId,
        ) -> anyhow::Result<()> {
            self.seen.lock().unwrap().push(self.id);
            if self.fail {
                anyhow::bail!("sessions still live");
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn member_removed_runs_in_hook_order_and_a_failure_stops_it() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let reg = HookRegistry::default();
        for (id, fail) in [("fleet", false), ("remote", false)] {
            reg.register(
                id,
                Hooks {
                    tenant: Some(Arc::new(Member {
                        id,
                        seen: seen.clone(),
                        fail,
                    })),
                    ..Default::default()
                },
            );
        }
        reg.member_removed(ObjectId::new(), ObjectId::new())
            .await
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), vec!["remote", "fleet"]);

        seen.lock().unwrap().clear();
        reg.register(
            "remote",
            Hooks {
                tenant: Some(Arc::new(Member {
                    id: "remote",
                    seen: seen.clone(),
                    fail: true,
                })),
                ..Default::default()
            },
        );
        let err = reg
            .member_removed(ObjectId::new(), ObjectId::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("remote: member_removed"), "{err}");
        assert_eq!(*seen.lock().unwrap(), vec!["remote"], "the cascade stopped");
    }

    #[test]
    fn a_re_registration_replaces_the_first() {
        let reg = HookRegistry::default();
        reg.register("network", Hooks::default());
        reg.register("network", Hooks::default());
        assert_eq!(reg.registered(), vec!["network"]);
    }

    #[tokio::test]
    async fn an_empty_registry_is_a_no_op_cascade() {
        let reg = HookRegistry::default();
        let out = reg
            .agent_removed(ObjectId::new(), ObjectId::new(), "m", "test")
            .await
            .unwrap();
        assert!(out.is_none());
        assert_eq!(
            reg.agent_renamed(ObjectId::new(), ObjectId::new(), "n")
                .await
                .unwrap(),
            RenamePropagation::NoLiveNode
        );
    }
}
