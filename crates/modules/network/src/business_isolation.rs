// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #21 — hard mainland/non-mainland isolation of business
//! discovery (the user's §2.5 rule).
//!
//! The rule: mainland nodes may discover and connect only to mainland nodes,
//! and non-mainland only to non-mainland. No ACL, share, relay, NAT or server
//! hop can override it, and an unknown, untrusted or expired zone fails
//! closed. The zone is the one observed on the node's LIVE connection when it
//! opened (`org_relay::node_zone`). It cannot change for that connection's
//! life, and a reconnect re-joins, which re-shapes.
//!
//! Netmaps: `overlay::shape_peer` consults [`Zones`] before any ACL, so the
//! full netmap, every delta and the device's own listing
//! (`shape_full_netmap`) withhold the same peers. A withheld peer goes out as
//! an explicit `removes`, which tears down an installed carrier.
//!
//! Carriers: a client that already holds a withheld peer's id or key must not
//! get a carrier around the netmap. [`pair_zone`] gates the TURN grant
//! (`overlay::handle_overlay_relay_request`) and every org relay plan
//! (`org_relay::plan_mint_candidates_reusing`, which also requires the relay
//! in the pair's zone), and the DERP allow table carries each node's zone
//! (`derp_acl`).
//!
//! Management traffic (`www.itachi.fans`) never passes through here.
//!
//! The setting is `app.business_isolation`: `off` | `warn` | `enforce`.
//! `warn`, the default, logs what `enforce` would withhold: a server
//! without zone evidence (no GeoIP database, no trusted proxy chain) would
//! otherwise cut every business mesh the moment it is deployed.

use std::time::Duration;

use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{NodeRef, OverlayNode};
use roomler_core::business_authority::BusinessZone;

use tracing::{info, warn};

use crate::NetworkState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Warn,
    Enforce,
}

impl Mode {
    /// Anything but `off` or `warn` reads as `enforce`: a mistyped value of
    /// a security setting must not silently disable it.
    pub fn parse(s: &str) -> Mode {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Mode::Off,
            "warn" => Mode::Warn,
            _ => Mode::Enforce,
        }
    }
}

pub fn mode(state: &NetworkState) -> Mode {
    Mode::parse(&state.core.settings.app.business_isolation)
}

/// The zones one shaping decision is about: the recipient's and the shaped
/// peer's. `None` is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Zones {
    pub mode: Mode,
    pub recipient: Option<BusinessZone>,
    pub peer: Option<BusinessZone>,
    /// An approved cross-border line connects the two zones, and the
    /// recipient can ride a peer over it alone ([`Lines`]).
    pub line: bool,
}

impl Zones {
    pub const OFF: Zones = Zones {
        mode: Mode::Off,
        recipient: None,
        peer: None,
        line: false,
    };

    /// Both zones known and equal.
    pub fn same(&self) -> bool {
        matches!((self.recipient, self.peer), (Some(a), Some(b)) if a == b)
    }

    /// The rule says no: zones differ or one is unknown. Under `off` the
    /// rule is not consulted at all.
    pub fn denies(&self) -> bool {
        self.mode != Mode::Off && !self.same()
    }

    /// Withhold the peer from the recipient (only under `enforce`).
    pub fn withholds(&self) -> bool {
        self.mode == Mode::Enforce && self.denies() && !self.line_only()
    }

    /// The one exception (the user's 2026-10-26 rule): two known, different
    /// zones an approved cross-border line connects, toward a recipient that
    /// rides such a peer over the line alone. Shown as `backbone_only`.
    pub fn line_only(&self) -> bool {
        self.mode == Mode::Enforce
            && self.line
            && matches!((self.recipient, self.peer), (Some(a), Some(b)) if a != b)
    }
}

/// The zone pairs that approved cross-border lines connect in a tenant
/// ([`crate::org_relay::cross_border_lines`]). Empty unless the rule is
/// enforced: under `warn` and `off` nothing is withheld to begin with.
#[derive(Clone, Debug, Default)]
pub struct Lines(pub Vec<(BusinessZone, BusinessZone)>);

impl Lines {
    pub fn connects(&self, a: Option<BusinessZone>, b: Option<BusinessZone>) -> bool {
        matches!((a, b), (Some(a), Some(b)) if a != b
            && self.0.iter().any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a)))
    }
}

pub async fn lines(state: &NetworkState, mode: Mode, tenant_id: bson::oid::ObjectId) -> Lines {
    if mode != Mode::Enforce {
        return Lines::default();
    }
    Lines(crate::org_relay::cross_border_lines(state, tenant_id).await)
}

/// Whether `recipient` joined able to ride a line-only peer.
pub fn rides_lines(state: &NetworkState, recipient: &OverlayNode) -> bool {
    recipient
        .id
        .is_some_and(|id| state.org_relay.join_extras(id).supports_backbone_only_v1)
}

/// A node's zone, looked up only when the rule is on (each lookup reads the
/// device row).
pub async fn zone_of(state: &NetworkState, mode: Mode, node: &OverlayNode) -> Option<BusinessZone> {
    if mode == Mode::Off {
        return None;
    }
    crate::org_relay::node_zone(state, node).await
}

/// How long a join waits for its own connection's zone under `enforce`.
/// The observation is recorded beside the hello, so it is normally there
/// already; without the wait, a joiner whose evidence lands a moment late
/// would be shown nobody until its next rejoin.
pub const JOIN_ZONE_WAIT: Duration = Duration::from_secs(2);

/// The joiner's zone, waiting up to [`JOIN_ZONE_WAIT`] for it under `enforce`.
pub async fn joiner_zone(
    state: &NetworkState,
    mode: Mode,
    node: &OverlayNode,
) -> Option<BusinessZone> {
    let deadline = tokio::time::Instant::now() + JOIN_ZONE_WAIT;
    loop {
        let z = zone_of(state, mode, node).await;
        if z.is_some() || mode != Mode::Enforce || tokio::time::Instant::now() >= deadline {
            return z;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The zone `a` and `b` share, `None` when they differ or either is unknown.
/// Only meaningful when `mode` is not `Off` (no lookups are made then).
pub async fn pair_zone(
    state: &NetworkState,
    mode: Mode,
    a: &OverlayNode,
    b: &OverlayNode,
) -> Option<BusinessZone> {
    let zones = Zones {
        mode,
        recipient: zone_of(state, mode, a).await,
        peer: zone_of(state, mode, b).await,
        line: false,
    };
    zones.same().then_some(zones.recipient).flatten()
}

/// Whether a carrier (`what`) between `a` and `b` must be refused: `true`
/// only under `enforce`. `warn` logs the refusal it would make.
pub async fn refuses_pair(
    state: &NetworkState,
    a: &OverlayNode,
    b: &OverlayNode,
    what: &str,
) -> bool {
    refuses_parties(
        state,
        (a.tenant_id, &a.node_ref),
        (b.tenant_id, &b.node_ref),
        what,
    )
    .await
}

/// [`refuses_pair`] for two devices known by tenant and reference: a carrier
/// the center brokers outside the overlay (a tunnel, #22) names devices, not
/// overlay nodes.
pub async fn refuses_parties(
    state: &NetworkState,
    a: (ObjectId, &NodeRef),
    b: (ObjectId, &NodeRef),
    what: &str,
) -> bool {
    let mode = mode(state);
    if mode == Mode::Off {
        return false;
    }
    let zones = Zones {
        mode,
        recipient: crate::org_relay::party_zone(state, a.0, a.1).await,
        peer: crate::org_relay::party_zone(state, b.0, b.1).await,
        line: false,
    };
    if zones.same() {
        return false;
    }
    let (a, b) = (a.1, b.1);
    if mode == Mode::Enforce {
        warn!(
            ?a,
            ?b,
            what,
            "business isolation: pair not in one zone; refusing"
        );
        return true;
    }
    info!(
        ?a,
        ?b,
        what,
        "business isolation [warn]: would refuse a pair not in one zone"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use BusinessZone::{Mainland, NonMainland};

    fn z(mode: Mode, recipient: Option<BusinessZone>, peer: Option<BusinessZone>) -> Zones {
        Zones {
            mode,
            recipient,
            peer,
            line: false,
        }
    }

    #[test]
    fn a_line_shows_only_a_known_cross_zone_peer_and_only_under_enforce() {
        let line = |mode, r, p| Zones {
            line: true,
            ..z(mode, r, p)
        };
        let cross = line(Mode::Enforce, Some(Mainland), Some(NonMainland));
        assert!(cross.line_only() && !cross.withholds());
        assert!(
            !z(Mode::Enforce, Some(Mainland), Some(NonMainland)).line_only(),
            "no line"
        );
        assert!(
            line(Mode::Enforce, Some(Mainland), None).withholds(),
            "unknown still fails closed"
        );
        assert!(!line(Mode::Warn, Some(Mainland), Some(NonMainland)).line_only());
        let lines = Lines(vec![(Mainland, NonMainland)]);
        assert!(
            lines.connects(Some(NonMainland), Some(Mainland)),
            "either direction"
        );
        assert!(!lines.connects(Some(Mainland), Some(Mainland)));
        assert!(!lines.connects(None, Some(Mainland)));
    }

    #[test]
    fn only_a_shared_known_zone_passes() {
        assert!(!z(Mode::Enforce, Some(Mainland), Some(Mainland)).withholds());
        assert!(!z(Mode::Enforce, Some(NonMainland), Some(NonMainland)).withholds());
        assert!(z(Mode::Enforce, Some(Mainland), Some(NonMainland)).withholds());
        assert!(
            z(Mode::Enforce, Some(NonMainland), None).withholds(),
            "unknown fails closed"
        );
        assert!(
            z(Mode::Enforce, None, None).withholds(),
            "two unknowns are not a match"
        );
    }

    #[test]
    fn warn_reports_and_off_does_not_consult() {
        let cross = z(Mode::Warn, Some(Mainland), Some(NonMainland));
        assert!(cross.denies() && !cross.withholds());
        assert!(!z(Mode::Off, Some(Mainland), Some(NonMainland)).denies());
        assert!(!Zones::OFF.denies());
    }

    #[test]
    fn an_unrecognised_setting_enforces() {
        assert_eq!(Mode::parse("off"), Mode::Off);
        assert_eq!(Mode::parse(" WARN "), Mode::Warn);
        assert_eq!(Mode::parse("enforce"), Mode::Enforce);
        assert_eq!(Mode::parse("enforced"), Mode::Enforce);
        assert_eq!(Mode::parse(""), Mode::Enforce);
    }
}
