// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 — org-relay: framing, and the reachability responder.
//!
//! * [`wire`] — Geneve framing and the shape rules (P1a, #816). Re-exported at
//!   this level so call sites read `orgrelay::is_org_relay_shaped(..)`.
//! * [`responder`] — the P1 **bind-only** reachability responder: it answers
//!   probes and forwards nothing. There is no session table and no data path
//!   here; those arrive with P2.

pub mod backbone;
pub mod bind;
pub mod client;
pub(crate) mod discovery;
pub mod member;
pub mod prober;
pub mod responder;
pub mod server;
pub mod session;
mod wire;

pub use wire::*;

/// The default org-relay UDP port.
///
/// **3478, measured rather than chosen.** FR-19's E2E-3 sent Geneve-shaped
/// probes from three fleet clients to a responder on a public host: the
/// corp-managed, symmetric-NAT host the feature exists for reached **3478 and
/// no other port** — 11000 (coturn's relay band) and 41641 (a high port) both
/// failed outright. The reference design's suggested high port would have been
/// unreachable by its own target population.
pub const DEFAULT_RELAY_SERVER_PORT: u16 = 3478;

/// Is this node offering itself as an org relay?
///
/// **Opt-in**: only `1|true|yes|on` enables it. That direction is deliberate —
/// this is FR-19's gate 4, the refusal that survives a compromised server, so
/// the failure mode of a typo must be "off", never "on".
pub fn relay_server_enabled() -> bool {
    crate::env::flag("RELAY_SERVER_ENABLED", false)
}

/// The configured listen port, falling back to [`DEFAULT_RELAY_SERVER_PORT`].
///
/// An unparseable or out-of-range value falls back rather than failing: the
/// config surface already validates and rejects at set time, so a bad value
/// here means someone hand-edited the file, and refusing to listen at all
/// would be a worse answer than listening where the fleet expects.
pub fn relay_server_port() -> u16 {
    crate::env::node_env("RELAY_SERVER_PORT")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
        .unwrap_or(DEFAULT_RELAY_SERVER_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is a field measurement, so pin it: changing it silently
    /// would strand the only population this feature can serve.
    #[test]
    fn default_port_is_the_measured_one() {
        assert_eq!(DEFAULT_RELAY_SERVER_PORT, 3478);
    }
}
