// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// FR-69 P7b — the frame ceiling is core's (`meshharbor_core::ws::upgrade`),
// shared by every upgrade whoever owns it; re-exported so the paths in this
// crate read as before.
pub use meshharbor_core::ws::upgrade::MAX_WS_MESSAGE_BYTES;

pub mod handler;

// FR-69 P1b — the connection registry, the fan-out primitives and the Redis
// pub/sub layer are core (`meshharbor_core::ws`); re-exported here so every
// `crate::ws::{storage, dispatcher, redis_pubsub}` path in this crate reads
// as before.
pub use meshharbor_core::ws::{dispatcher, redis_pubsub, storage};
