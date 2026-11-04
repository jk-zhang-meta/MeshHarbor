// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `rc:tunnel.*` envelope re-exports.
//!
//! The actual enum variants land in `meshharbor-remote-control`'s
//! `ClientMsg` / `ServerMsg` in T2 (additive — they share the
//! `rc:*` namespace per plan §"What changed from v1" — fold into
//! `rc:*`, no second WS endpoint). This module re-exports them so
//! `roomler` and the agent's `tunnel::` module have a single
//! import path that hides the layering.
//!
//! Empty in T1; populated in T2 once the wire variants exist.
