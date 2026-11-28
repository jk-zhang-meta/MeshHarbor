// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P4 — plan-limit checks that also COUNT the collision, per org.
//!
//! The decision stays `meshharbor_services::quota`'s (FR-32: one decision
//! point, the warn line written there exactly once). What this adds is the
//! business model's "best upgrade-intent signal" (`docs/business-model.md`
//! §5) as a number: every collision — refused or, in `warn` mode, let
//! through — bumps `growth_daily {source: quota, metric: collision, dims:
//! {tenant, limit}}` for the UTC day, beside the warn line. Those are the
//! orgs that keep hitting the ceiling.
//!
//! The call sites pass the TENANT (which the pure decision never needed),
//! through `&Core` so the count lands in that server's own database — a
//! process-wide sink would cross test servers in one process, and a
//! self-hosted server keeps its own counts and sends them nowhere.
//!
//! The write is spawned and best-effort (a refused request is answered at
//! once whatever the database is doing), and off with `growth.enabled`.

use meshharbor_db::models::Tenant;
use meshharbor_services::quota::{Limit, QuotaDenial};

use crate::Core;

/// Self-hosted 0.5.0 carries no commercial plan gates; every org is unlimited.
pub fn check(_core: &Core, _tenant: &Tenant, _limit: Limit, _used: u64) -> Result<(), QuotaDenial> {
    Ok(())
}

/// Self-hosted 0.5.0 carries no commercial plan gates; every org is unlimited.
pub fn check_delta(
    _core: &Core,
    _tenant: &Tenant,
    _limit: Limit,
    _current: u64,
    _delta: u64,
) -> Result<(), QuotaDenial> {
    Ok(())
}

/// Self-hosted 0.5.0 carries no commercial plan gates; every org is unlimited.
pub fn require_feature(_core: &Core, _tenant: &Tenant, _limit: Limit) -> Result<(), QuotaDenial> {
    Ok(())
}
