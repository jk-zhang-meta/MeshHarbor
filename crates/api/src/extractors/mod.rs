// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// FR-69 P1d — the core-only extractors live in `meshharbor_core::extractors`;
// re-exported so every `crate::extractors::{auth, tenant}` path in this
// crate reads as before.
pub use meshharbor_core::extractors::{auth, tenant};

// FR-84 D5a — the agent-JWT extractor for the host's `/api/agent/self/*`
// routes: the fleet module's decision, plus "no fleet ⇒ 503".
#[cfg(feature = "fleet")]
pub mod auth_agent;
