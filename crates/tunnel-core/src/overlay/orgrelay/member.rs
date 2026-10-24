// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P4b — what a MEMBER keeps about the org-relay sessions the server
//! minted for it, and the bind job the runtime runs off-loop for one.
//!
//! The coordinator (`relay_link.rs`) owns these by PEER; the runtime spawns
//! [`OrgBindJob`]s and commits their result. Kept here rather than inside the
//! coordinator so the types stay next to the client they drive and the
//! ceilings the member enforces are in one place.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;

use super::bind::BindSecret;
use super::client::OrgRelayConn;

/// The member re-clamps every server-supplied lifetime against its own
/// ceilings (the Roomler SSH rule: server values only ever shorten). These
/// mirror the server's `peer_relay_limits`, but a longer value from a
/// misbehaving server is still cut here.
pub const MAX_BIND_BUDGET: Duration = Duration::from_secs(30);
pub const MAX_LIFETIME: Duration = Duration::from_secs(3600);
/// Floor for one endpoint's attempt inside the bind budget: a corp path can
/// take a couple of seconds to deliver a first UDP datagram, and a budget
/// split too thin across many endpoints would fail them all.
pub const MIN_PER_ENDPOINT: Duration = Duration::from_secs(3);

/// One minted session as this member holds it.
#[derive(Clone)]
pub struct OrgSession {
    pub vni: u32,
    pub generation: u64,
    pub relay_node_id: ObjectId,
    /// The relay's endpoints in the server's try order.
    pub endpoints: Vec<SocketAddr>,
    pub secret: BindSecret,
    /// What the relay allows for the bind, already clamped.
    pub bind_budget: Duration,
    /// Absolute end of the session on the MEMBER's clock, from receipt.
    pub expires_at: Instant,
    /// The bound carrier once the bind committed; `close()`d on revoke or
    /// expiry so the owning carrier's dead latch fires.
    pub conn: Option<Arc<OrgRelayConn>>,
}

impl OrgSession {
    pub fn is_live(&self, now: Instant) -> bool {
        self.expires_at > now
    }

    /// Build a session from the `rc:overlay.relay_session` fields. `None` when
    /// the secret is not 32 base64 bytes or no endpoint parses — a frame the
    /// member cannot act on is ignored, never half-applied.
    pub fn from_wire(
        vni: u32,
        generation: u64,
        relay_node_id: ObjectId,
        relay_endpoints: &[String],
        bind_secret_b64: &str,
        bind_secs: u32,
        max_lifetime_secs: u32,
    ) -> Option<Self> {
        let raw = BASE64.decode(bind_secret_b64).ok()?;
        let secret = BindSecret::from_bytes(<[u8; 32]>::try_from(raw.as_slice()).ok()?);
        let endpoints: Vec<SocketAddr> = relay_endpoints
            .iter()
            .filter_map(|e| e.parse().ok())
            .collect();
        if endpoints.is_empty() {
            return None;
        }
        let now = Instant::now();
        Some(Self {
            vni,
            generation,
            relay_node_id,
            endpoints,
            secret,
            bind_budget: Duration::from_secs(u64::from(bind_secs)).min(MAX_BIND_BUDGET),
            expires_at: now + Duration::from_secs(u64::from(max_lifetime_secs)).min(MAX_LIFETIME),
            conn: None,
        })
    }
}

/// A bind the runtime runs OFF-LOOP for a peer: a network round trip per
/// endpoint, so it never runs on the data-plane loop (the rc.218 rule that
/// moved the TURN allocate off-loop for the same reason).
#[derive(Clone)]
pub struct OrgBindJob {
    /// Identity captured at bind start, rechecked before a late commit.
    pub peer_public_key: [u8; 32],
    pub peer_overlay_ip: Ipv4Addr,
    pub node_id: ObjectId,
    pub relay_node_id: ObjectId,
    pub vni: u32,
    pub generation: u64,
    pub endpoints: Vec<SocketAddr>,
    pub secret: BindSecret,
    pub per_endpoint: Duration,
}

/// Split the bind budget across the endpoints to try, never below
/// [`MIN_PER_ENDPOINT`] and never above the whole budget.
pub fn per_endpoint_budget(bind_budget: Duration, endpoints: usize) -> Duration {
    let n = u32::try_from(endpoints.max(1)).unwrap_or(u32::MAX);
    (bind_budget / n).max(MIN_PER_ENDPOINT).min(bind_budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wire_clamps_and_refuses_the_unusable() {
        let secret = BASE64.encode([7u8; 32]);
        let s = OrgSession::from_wire(
            9,
            2,
            ObjectId::new(),
            &["8.8.8.8:3478".into(), "not-an-endpoint".into()],
            &secret,
            600,
            86_400,
        )
        .expect("one good endpoint is enough");
        assert_eq!(s.endpoints.len(), 1, "the unparseable endpoint is dropped");
        assert_eq!(
            s.bind_budget, MAX_BIND_BUDGET,
            "600 s is clamped to the ceiling"
        );
        assert!(s.expires_at <= Instant::now() + MAX_LIFETIME);
        assert!(
            OrgSession::from_wire(
                9,
                2,
                ObjectId::new(),
                &["8.8.8.8:3478".into()],
                "short",
                30,
                60
            )
            .is_none()
        );
        assert!(
            OrgSession::from_wire(9, 2, ObjectId::new(), &["nope".into()], &secret, 30, 60)
                .is_none()
        );
    }

    #[test]
    fn per_endpoint_budget_respects_both_bounds() {
        assert_eq!(
            per_endpoint_budget(Duration::from_secs(30), 2),
            Duration::from_secs(15)
        );
        assert_eq!(
            per_endpoint_budget(Duration::from_secs(30), 30),
            MIN_PER_ENDPOINT
        );
        assert_eq!(
            per_endpoint_budget(Duration::from_secs(2), 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            per_endpoint_budget(Duration::from_secs(30), 0),
            Duration::from_secs(30)
        );
    }
}
