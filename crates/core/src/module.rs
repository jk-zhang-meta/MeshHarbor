// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! The [`Module`] contract and the [`Core`] every module is initialised with.

use std::future::Future;

use axum::Router;
use meshharbor_config::Settings;

use crate::{Capabilities, Core, Hooks, IndexSet, Job, TenantCtx, WsRegistration};

/// What a pillar module is, to the host.
///
/// The host composes concrete implementors under `#[cfg(feature)]`, in a fixed
/// order, and calls each method exactly where its doc says. Nothing here is
/// `dyn`: the module set is closed at build time, and a closed set is what
/// lets the compiler say "this module forgot its indexes" instead of a profile
/// discovering it at 03:00.
///
/// The methods with default bodies are the ones a module may genuinely not
/// need; [`Module::routes`] and [`Module::capabilities`] have none because a
/// module with neither is not a module.
pub trait Module: Sized + Send + Sync + 'static {
    /// The module's stable identifier — the key in `[modules]` settings, the
    /// name in `GET /api/capabilities` and `/health`, the feature name on the
    /// host. Must be one of [`crate::graph::MODULES`].
    const ID: &'static str;

    /// The other modules' state this module is built ON — the module edges
    /// of [`crate::graph::EDGES`] as a type (P6). `()` for a module that
    /// depends on core alone; `remote`'s is the fleet module's state, because
    /// the Hub is ONE live object and a module that re-created it would
    /// dispatch into an empty registry. The host supplies it in composition
    /// order, so a dependency is always initialised before its dependant.
    type Deps: Send + 'static;

    /// Build the module's state. Runs once at boot, after `Core` is up and
    /// before any route is mounted; failure aborts the boot (a half-composed
    /// server is worse than a stopped one). `Core` is a bundle of `Arc`s and
    /// is passed by value: the module keeps its own clone as the first field
    /// of its state and derefs to it.
    fn init(
        core: Core,
        settings: &Settings,
        deps: Self::Deps,
    ) -> impl Future<Output = anyhow::Result<Self>> + Send;

    /// The runtime switch: `false` unmounts the module on a pod that still
    /// links it — routes not mounted, WS namespaces not registered, jobs not
    /// started, hooks not invoked. This is the per-module kill switch during the
    /// roll that introduced it. P1 wires it to `[modules] <ID> = false`; until
    /// then every module is on.
    fn enabled(settings: &Settings) -> bool {
        let _ = settings;
        true
    }

    /// What this module offers a given tenant, computed per request — the
    /// intersection of *compiled*, *enabled*, *plan* and *tenant settings*.
    /// Never persisted: "disabled by build" and "disabled by plan" must hit one
    /// check path.
    fn capabilities(&self, tenant: &TenantCtx) -> Capabilities;

    /// The module's HTTP routes, with its own state already applied, mounted by
    /// the host under `/api` **inside** the per-IP governor. Paths are given
    /// in full (`/tenant/{tenant_id}/room`, `/agent/enroll`); the host adds
    /// nothing but the `/api` prefix and the shared layers.
    fn routes(&self) -> Router;

    /// Routes the host mounts **outside** the governor — the Stripe webhook is
    /// the one example today (signature-authenticated; retry bursts from fixed
    /// IPs would trip the per-IP limiter). Empty for almost every module.
    fn unlimited_routes(&self) -> Router {
        Router::new()
    }

    /// WebSocket participation: namespace handlers on the shared `/ws` socket
    /// and, for `network`, the extra `/derp` upgrade endpoint. The socket, the
    /// role gate, the affinity check and the fan-out stay in core.
    fn ws(&self) -> WsRegistration {
        WsRegistration::default()
    }

    /// The index sets this module owns. Core applies every module's sets in
    /// composition order and refuses to boot if two modules claim one
    /// collection. Shape never changes in a move — only the owner.
    fn indexes(&self) -> Vec<IndexSet> {
        Vec::new()
    }

    /// The same sets for an explicit `multi_block` schema switch (FR-47 P5c:
    /// the overlay block registry has two mutually exclusive index plans).
    /// The composition snapshot records BOTH plans, so it asks each module
    /// through this rather than through [`Module::indexes`], which answers
    /// for the running deployment's setting. A module whose sets do not vary
    /// keeps the default.
    fn indexes_for(&self, multi_block: bool) -> Vec<IndexSet> {
        let _ = multi_block;
        self.indexes()
    }

    /// Background work: leader-gated startup maintenance and periodic sweeps.
    /// The host owns the leader lease and the scheduler; a module only declares.
    fn jobs(&self) -> Vec<Job> {
        Vec::new()
    }

    /// The inverse edges — what this module does when core tells it a tenant
    /// was archived or an agent removed. Invoked in [`crate::hooks::HOOK_ORDER`].
    fn hooks(&self) -> Hooks {
        Hooks::default()
    }

    /// Orderly stop, after routes are unmounted and before core shuts down.
    fn shutdown(&self) -> impl Future<Output = ()> + Send {
        async {}
    }
}
