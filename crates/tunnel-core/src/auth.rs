// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Audience-name pointers for the tunnel JWT types.
//!
//! Canonical claim shapes + issue/verify functions live in
//! `crates/services/src/auth/mod.rs` alongside the existing
//! `Access` / `Refresh` / `Enrollment` / `Agent` pattern. This module
//! is intentionally thin — the `meshharbor` CLI stores tokens as
//! opaque strings and never decodes them, so it doesn't need the
//! claim structs.
//!
//! The audience names below are the `token_type` field's wire form
//! (lowercase snake_case from `serde(rename_all = "snake_case")`).
//! Use them in WS query-string role checks and audit log entries.

pub const TOKEN_TYPE_TUNNEL_CLIENT: &str = "tunnel_client";
pub const TOKEN_TYPE_TUNNEL_ENROLLMENT: &str = "tunnel_enrollment";
