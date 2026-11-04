// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-1 — multi-pod cluster foundation (see `docs/multi-pod-scale-out.md`).
//!
//! Three pieces, all fail-soft when Redis is absent:
//! - [`identity`]: stable `pod_id` + per-process `epoch` fencing token.
//! - [`directory`]: entity → owning-pod records (LWW for connection-bound
//!   entities, NX for server-materialized ones), three shared Lua ops.
//! - [`bus`]: per-pod channels + request/reply with deadlines; the RPC
//!   deadline is the ACTIVE failure detector, directory TTLs the passive
//!   backstop, `meshharbor:pod-alive:*` advisory only.
//!
//! FR-69 P1b — moved here from `crates/api/src/cluster/` unchanged; the
//! per-pod metrics snapshot stayed behind in the api crate because it reads
//! module-owned counters. The api crate re-exports these three under their
//! old paths.

pub mod bus;
pub mod directory;
pub mod identity;
pub mod metrics;
pub mod session_slots;
