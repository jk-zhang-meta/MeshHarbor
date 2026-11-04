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
//!   backstop, `roomler:pod-alive:*` advisory only.

// FR-69 P1b — the three pieces above are core (`meshharbor_core::cluster`);
// re-exported so every `crate::cluster::{bus, directory, identity}` path in
// this crate reads as before. The metrics snapshot stays here: it reads
// module-owned counters.
pub use meshharbor_core::cluster::{bus, directory, identity};
pub mod metrics;
