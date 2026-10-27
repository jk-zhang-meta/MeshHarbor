// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Roomler AI tunnel core.
//!
//! Shared building blocks for the `roomler` CLI (controller side)
//! and the `roomlerd` tunnel service (target side):
//!
//! * [`transport`] — pluggable data-plane (`webrtc-dc-v1` today;
//!   `wireguard-v1` in v0.5). Capability-negotiated at peer setup.
//! * [`auth`]      — `TunnelClient` / `TunnelEnrollment` JWT claim
//!   shapes. The actual issue/verify functions live in
//!   `crates/services/src/auth/mod.rs` next to the existing Agent /
//!   Enrollment / Access / Refresh pattern.
//! * [`policy`]    — ACL evaluation (`subject × target × destination`).
//!   Pure functions, table-driven tests.
//! * [`mux`]       — `flow_id` framing (4-byte LE prefix per DC message)
//!   so multiple TCP flows share a fixed DC pool without per-flow RTT
//!   setup. See plan §4.
//! * [`forward`]   — bidirectional TCP↔DC pump with event-driven
//!   backpressure (`bufferedAmountLowThreshold`), lifted from the
//!   rc.19 file-DC pattern.
//! * [`signaling`] — re-exports the `rc:tunnel.*` envelope variants
//!   that land in `remote_control::signaling` in T2 (today: stub).
//!
//! Multi-tenancy invariant: every code path that touches a tenant id
//! must compare `tunnel_client.tenant_id == agent.tenant_id` BEFORE
//! evaluating any policy (defence-in-depth — see plan §7). The
//! cross-tenant integration test in `crates/tests/src/tunnel_tests.rs`
//! locks this; do not relax it.

pub mod auth;
/// Node env-var reads: `ROOMLERD_*`, then the older `ROOMLER_NODE_*`.
/// #2187 — the daemon's own control-plane names, resolved so that no caller
/// ever waits on a resolver that has stopped answering for a name it has
/// resolved before.
pub mod ctl_dns;
/// Tunnel-client session driver — the shared flow vocabulary (P3b-1); the session
/// orchestration + the `TunnelSignaling` seam fold in at P3b-2.
pub mod driver;
pub mod env;
pub mod evidence;
/// FR-86 P1 — the flow-owned listener: one loopback port bound for the life of
/// a flow, served through whichever `driver::Carrier` is current, holding
/// connections (bounded) while none is.
pub mod flow_listener;
pub mod forward;
/// LocalAPI — the daemon's local control surface (P1: read-only protocol).
///
/// P3e lever E moved the module OUT to the leaf crate `roomler-localapi` and
/// re-exports it here, so `tunnel_core::localapi::…` still resolves for every
/// existing caller. The point of the move is the other direction: a thin
/// client (the desktop companion) can now depend on the protocol WITHOUT
/// compiling this crate's data plane — webrtc, quinn, turn and rustls are
/// non-optional here, 285 crates in the default graph.
pub use roomler_localapi as localapi;
/// v039 — the ORG loss-window test shared by member and server.
pub mod loss;
pub mod mux;
/// Overlay L3 data plane (userspace WireGuard mesh) — feature `overlay`.
#[cfg(feature = "overlay")]
pub mod overlay;
/// #1882 — the address space the overlay runs on (every org's v4 blocks + the
/// derived-v6 ULA), for code outside the overlay that must tell whether an
/// address is reached through the mesh (remote desktop's ICE). Ungated: the
/// overlay WRITES it, but a build without one still asks.
pub mod overlay_footprint;
/// The pinned-key check of a release artifact's `.asc` sidecar. Here, not in
/// the agent, so the CLI's `self-update` shares it (FR-97 P6b).
pub mod pgp_verify;
pub mod policy;
pub mod signaling;
/// The tunnel-session driver's signaling seam — the cloneable sink + single-
/// consumer source `run_tunnel_session` rides instead of owning a WebSocket.
pub mod signaling_link;
/// SOCKS5 server + client wire codec — the userspace-mode proxy + mesh chaining.
pub mod socks5;
pub mod transport;
/// SOCKS5 UDP ASSOCIATE relay for the tunnel client's userspace mode.
pub mod udp;
/// Windows Defender Firewall rules for THIS binary — the inbound-UDP allow
/// rule (one definition for the overlay's self-heal AND the SCM service
/// host, #1698) and the cleanup of prompt-written Block rules. Pure parts
/// build everywhere; the effectful parts are `#[cfg(windows)]`.
pub mod winfw;
