// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Feature-shaped bridge from the tunnel layer to `netstate` (R1, 2026-08-25).
//!
//! The tunnel flow supervisor and the route reconciler both want ONE thing
//! from the network monitor: "wake me when the network materially moved, so
//! I retry NOW instead of waiting out a backoff that a transition just
//! invalidated" — the same shape the control-WS reconnect ladder proved in
//! `signaling.rs` (its `next_major_netchange`). `netstate` compiles only
//! under tunnel-core's `overlay` feature, so this module owns the two-arm
//! cfg so its consumers don't repeat it.
//!
//! Storm guard: netstate itself damps to ≤1 material Major per 120 s
//! (`MAJOR_PUBLISH_COOLDOWN`), so a flapping network cannot pin retry
//! ladders to their floor — the #506 lesson, inherited rather than
//! re-implemented.

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub(crate) type NetRx = tokio::sync::broadcast::Receiver<tunnel_core::overlay::netstate::NetDelta>;
#[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
pub(crate) type NetRx = std::convert::Infallible;

/// Subscribe to netstate deltas, `None` when the monitor is absent
/// (feature off / disabled by config / backend failed).
pub(crate) fn subscribe() -> Option<NetRx> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        tunnel_core::overlay::netstate::handle().map(|h| h.subscribe())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        None
    }
}

/// R4 — the PRIMARY org's live DERP mux as a tunnel handle (feature-shaped:
/// the overlay module only exists under overlay-l3/netstack; other builds
/// have no derp identity and keep the classic ladder).
pub(crate) fn primary_derp_tunnel_handle() -> Option<tunnel_core::transport::derp::DerpTunnelHandle>
{
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        crate::overlay::primary_derp_tunnel_handle()
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        None
    }
}

/// R4 — a specific tenant's live DERP mux as a tunnel handle (feature-shaped).
pub(crate) fn derp_tunnel_handle(
    tenant: &str,
) -> Option<tunnel_core::transport::derp::DerpTunnelHandle> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        crate::overlay::derp_tunnel_handle(tenant)
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant;
        None
    }
}

/// Yield the next material Major's summary (`Lagged` counts as one — the
/// conservative read); pend forever with no subscription. Cancel-safe, so
/// it can race a backoff sleep in `tokio::select!`.
pub(crate) async fn next_major(rx: &mut Option<NetRx>) -> String {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        tunnel_core::overlay::netstate::next_major(rx).await
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = rx;
        std::future::pending().await
    }
}
