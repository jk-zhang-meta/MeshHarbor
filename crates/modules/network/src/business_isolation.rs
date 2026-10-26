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
//! Servers: two devices whose central role is Server are judged by the
//! tenant's server topology instead of their zones — an enabled
//! [`ServerLink`](roomler_ai_remote_control::models::ServerLink) between them
//! connects them, whatever their zones; none (or a disabled one) separates
//! them, even inside one zone. A pair with any other device (a client, or a
//! device with no current role) keeps the zone rule.
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
    /// Both are servers: `Some(linked)`, and the server topology alone
    /// decides ([`Lines::server_pair`]). `None` for any other pair.
    pub servers: Option<bool>,
}

impl Zones {
    pub const OFF: Zones = Zones {
        mode: Mode::Off,
        recipient: None,
        peer: None,
        line: false,
        servers: None,
    };

    /// The pair may meet: two linked servers, or both zones known and equal.
    pub fn same(&self) -> bool {
        match self.servers {
            Some(linked) => linked,
            None => matches!((self.recipient, self.peer), (Some(a), Some(b)) if a == b),
        }
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
            && self.servers.is_none()
            && matches!((self.recipient, self.peer), (Some(a), Some(b)) if a != b)
    }
}

/// The zone pairs that approved cross-border lines connect in a tenant
/// ([`crate::org_relay::cross_border_lines`]). Empty unless the rule is
/// enforced: under `warn` and `off` nothing is withheld to begin with.
///
/// Also the tenant's server topology: the agents whose central role is
/// Server, and the enabled links between them (read under `warn` and
/// `enforce`, so `warn` logs what a missing link would cut).
#[derive(Clone, Debug, Default)]
pub struct Lines {
    pub lines: Vec<(BusinessZone, BusinessZone)>,
    pub servers: std::collections::HashSet<ObjectId>,
    pub links: std::collections::HashSet<(ObjectId, ObjectId)>,
}

impl Lines {
    pub fn connects(&self, a: Option<BusinessZone>, b: Option<BusinessZone>) -> bool {
        matches!((a, b), (Some(a), Some(b)) if a != b
            && self.lines.iter().any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a)))
    }

    /// Both are servers: whether an enabled link joins them. `None` when
    /// either is not a server (the zone rule applies).
    pub fn server_pair(&self, a: &OverlayNode, b: &OverlayNode) -> Option<bool> {
        self.server_refs(&a.node_ref, &b.node_ref)
    }

    /// [`Self::server_pair`] by reference.
    pub fn server_refs(&self, a: &NodeRef, b: &NodeRef) -> Option<bool> {
        let (NodeRef::Agent { agent_id: x }, NodeRef::Agent { agent_id: y }) = (a, b) else {
            return None;
        };
        (self.servers.contains(x) && self.servers.contains(y)).then(|| {
            self.links
                .contains(&roomler_ai_remote_control::models::ServerLink::ordered(
                    *x, *y,
                ))
        })
    }
}

pub async fn lines(state: &NetworkState, mode: Mode, tenant_id: ObjectId) -> Lines {
    if mode == Mode::Off {
        return Lines::default();
    }
    // Every read fails closed: no role read means no servers (the zone rule
    // then applies to everyone), no network read means no links.
    let servers = roomler_core::business_authority::current_server_agents(&state.core, tenant_id)
        .await
        .map(|agents| agents.into_iter().filter_map(|a| a.id).collect())
        .unwrap_or_default();
    let links = state
        .overlay_networks
        .find_for_tenant(tenant_id)
        .await
        .ok()
        .flatten()
        .map(|n| {
            n.server_links
                .into_iter()
                .filter(|l| l.enabled)
                .map(|l| (l.a, l.b))
                .collect()
        })
        .unwrap_or_default();
    let lines = if mode == Mode::Enforce {
        crate::org_relay::cross_border_lines(state, tenant_id).await
    } else {
        Vec::new()
    };
    Lines {
        lines,
        servers,
        links,
    }
}

/// What may carry a pair: one shared zone, a server link (the relay may sit
/// in either server's zone), or nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permit {
    Zone(BusinessZone),
    Linked(Option<BusinessZone>, Option<BusinessZone>),
    Denied,
}

impl Permit {
    /// The zones a relay carrying the pair may be in.
    pub fn relay_zones(&self) -> Vec<BusinessZone> {
        match *self {
            Permit::Zone(z) => vec![z],
            Permit::Linked(a, b) => a.into_iter().chain(b).collect(),
            Permit::Denied => Vec::new(),
        }
    }
}

/// The [`Permit`] for two devices of one tenant, known by reference. Only
/// meaningful when `mode` is not `Off` (no lookups are made then).
pub async fn permit_refs(
    state: &NetworkState,
    mode: Mode,
    tenant_id: ObjectId,
    a: &NodeRef,
    b: &NodeRef,
) -> Permit {
    if mode == Mode::Off {
        return Permit::Denied;
    }
    let za = crate::org_relay::party_zone(state, tenant_id, a).await;
    let zb = crate::org_relay::party_zone(state, tenant_id, b).await;
    match lines(state, mode, tenant_id).await.server_refs(a, b) {
        Some(true) => Permit::Linked(za, zb),
        Some(false) => Permit::Denied,
        None => match (za, zb) {
            (Some(x), Some(y)) if x == y => Permit::Zone(x),
            _ => Permit::Denied,
        },
    }
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

/// The [`Permit`] for two overlay nodes.
pub async fn pair_permit(
    state: &NetworkState,
    mode: Mode,
    a: &OverlayNode,
    b: &OverlayNode,
) -> Permit {
    permit_refs(state, mode, a.tenant_id, &a.node_ref, &b.node_ref).await
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
    if a.0 == b.0 && permit_refs(state, mode, a.0, a.1, b.1).await != Permit::Denied {
        return false;
    }
    let (a, b) = (a.1, b.1);
    if mode == Mode::Enforce {
        warn!(
            ?a,
            ?b,
            what,
            "business isolation: pair not in one zone (or servers without a link); refusing"
        );
        return true;
    }
    info!(
        ?a,
        ?b,
        what,
        "business isolation [warn]: would refuse a pair not in one zone (or servers without a link)"
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
            servers: None,
        }
    }

    #[test]
    fn servers_meet_by_link_alone() {
        let s = |mode, r, p, linked| Zones {
            servers: Some(linked),
            ..z(mode, r, p)
        };
        // Linked across the line: met; unlinked inside one zone: withheld.
        assert!(!s(Mode::Enforce, Some(Mainland), Some(NonMainland), true).withholds());
        assert!(s(Mode::Enforce, Some(Mainland), Some(Mainland), false).withholds());
        assert!(
            !s(Mode::Enforce, None, None, true).withholds(),
            "a link needs no zone"
        );
        assert!(!s(Mode::Warn, Some(Mainland), Some(Mainland), false).withholds());
        assert!(
            s(Mode::Warn, Some(Mainland), Some(Mainland), false).denies(),
            "warn logs it"
        );
        let line_too = Zones {
            line: true,
            ..s(Mode::Enforce, Some(Mainland), Some(NonMainland), false)
        };
        assert!(
            !line_too.line_only() && line_too.withholds(),
            "a line is for clients"
        );
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
        let lines = Lines {
            lines: vec![(Mainland, NonMainland)],
            ..Lines::default()
        };
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
