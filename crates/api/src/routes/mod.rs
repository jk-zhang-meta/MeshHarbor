// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// FR-69 — the host's remaining route files. The collaboration routes are the
// `chat` and `conference` modules' (P3, P4); device management (agents,
// enrollment, consent, exec, remote config, releases and the installer
// proxies, logs, crashes) is the `fleet` module's (P5a). What is left here is
// core's, `remote`'s and `network`'s, until their own PRs.
pub mod account_approval;
pub mod auth;
pub mod background_task;
pub mod capabilities;
pub mod cluster;
pub mod cost;
// The unified device listing joins agents (fleet, required) with tunnel
// clients and overlay nodes (network, optional): a composition view over two
// modules, which is the host's to hold — a `remote` profile has no network
// module and still has a devices page.
#[cfg(feature = "fleet")]
pub mod device;
// FR-84 D5a — a device's OWN view of its org (`/api/agent/self/*`), the same
// composition over fleet (required) + network (optional), agent-token
// authenticated. Host-owned for the same reason as `device`.
#[cfg(feature = "fleet")]
pub mod agent_self;
// FR-88 P1a — the platform admin's activation view: sign-ups (core's users)
// joined with device enrollments (fleet's agents, optional — `activated` is
// `null` without them). A view over core and one optional module, so the
// host's, next to its `/admin/stats` siblings.
pub mod attribution;
pub mod integration;
pub mod invite;
pub mod notification;
pub mod oauth;
pub mod push;
pub mod role;
pub mod stats;
pub mod tenant;
pub mod usage;

pub mod user;

#[cfg(feature = "fleet")]
pub mod device_share;

#[cfg(feature = "fleet")]
pub mod account_devices;
