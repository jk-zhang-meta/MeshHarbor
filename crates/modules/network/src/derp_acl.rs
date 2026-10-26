// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Overlay-ACL gate for the `/derp` relay tier.
//!
//! # Why this exists
//!
//! The overlay ACL shapes each recipient's netmap, so an HONEST client never
//! learns a withheld peer's WireGuard public key. But `/derp` is addressed BY
//! pubkey: a stale or modified client that already holds a denied peer's key
//! could hand it to the relay and be forwarded, routing straight around the
//! netmap. The TURN relay-grant path is gated in
//! `ws::overlay::handle_overlay_relay_request`; this closes the matching hole on
//! the DERP tier, which was the last "relay around the ACL" path.
//!
//! # Why a precomputed table
//!
//! [`super::derp::forward_frame`] is a **synchronous, per-datagram** hot path.
//! An async policy read there would be a serious throughput regression, so the
//! decision is precomputed into a per-network table and consulted with one
//! lock-free [`DashMap`] lookup per frame.
//!
//! The permission is exactly netmap visibility: if the ACL would let S see P,
//! S may relay to P. Reusing `evaluate_overlay` rather than inventing a second
//! predicate is what keeps the two tiers from drifting apart — a pair that is
//! invisible in the netmap can never become relayable here.
//!
//! # Failure posture: OPEN
//!
//! A missing table entry permits the frame. This matches
//! `ws::overlay::load_acl`, which also fails open, and the reasoning is the
//! same: a spurious deny here would sever a corp pair's ONLY working carrier
//! (DERP serves precisely the both-UDP-blocked pairs that have no alternative),
//! whereas a spurious allow costs one relayed datagram on a tier an honest
//! client would not have used. The table is rebuilt on every policy change and
//! on join, so the open window is a brief one after a restart.
//!
//! # MeshHarbor #21 isolation
//!
//! Under `app.business_isolation = enforce` the table also carries each
//! node's business zone, and a frame passes only between two nodes with the
//! same known zone, whatever the ACL mode (a node with no zone relays to
//! nobody). The table is built for that even when the ACL is off. The
//! restart window above stays open for it too; the netmap, which withholds
//! the cross-zone key from an honest client, is the first line.

use bson::oid::ObjectId;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use roomler_ai_remote_control::models::OverlayNode;
use roomler_core::business_authority::BusinessZone;
use tunnel_core::policy::{OverlayPeerRef, evaluate_overlay};

use crate::NetworkState;
use crate::derp_types::DerpPubKey;

/// One network's relay permissions: `src_pubkey → {dst_pubkey}`.
#[derive(Debug, Default)]
pub struct DerpAllowTable {
    /// Whether the tenant is ENFORCING. The table is built for `Warn` too, so
    /// the would-be denials are counted and logged before anyone flips —
    /// the same evidence-first cutover the netmap shaping uses.
    enforcing: bool,
    allow: HashMap<DerpPubKey, HashSet<DerpPubKey>>,
    /// #21 `enforce`: each node's zone; `None` when isolation is not enforced.
    zones: Option<HashMap<DerpPubKey, BusinessZone>>,
    /// Under `enforce`, the servers' keys and the linked pairs (stored in
    /// both orders): two servers relay to each other exactly when linked.
    servers: HashSet<DerpPubKey>,
    links: HashSet<(DerpPubKey, DerpPubKey)>,
}

impl DerpAllowTable {
    /// May `src` relay a frame to `dst`? Always `true` when neither the ACL
    /// nor the isolation is enforced.
    pub fn permits(&self, src: &DerpPubKey, dst: &DerpPubKey) -> bool {
        if self.zones.is_some() && self.servers.contains(src) && self.servers.contains(dst) {
            return self.links.contains(&(*src, *dst));
        }
        (!self.enforcing || self.allow.get(src).is_some_and(|s| s.contains(dst)))
            && self
                .zones
                .as_ref()
                .is_none_or(|z| matches!((z.get(src), z.get(dst)), (Some(a), Some(b)) if a == b))
    }

    /// `true` when a denial should actually drop the frame (vs. only be logged).
    pub fn enforcing(&self) -> bool {
        self.enforcing
    }

    /// Test builder so the DERP relay's tests can exercise the gate without
    /// standing up Mongo (the fields stay private to this module otherwise).
    /// `pub` and NOT `cfg(test)`: the relay and its tests live in the host
    /// crate until P7b, and `cfg(test)` does not cross crates (FR-69 P7a).
    #[doc(hidden)]
    pub fn for_test(enforcing: bool, pairs: &[(DerpPubKey, DerpPubKey)]) -> Self {
        let mut allow: HashMap<DerpPubKey, HashSet<DerpPubKey>> = HashMap::new();
        for (s, d) in pairs {
            allow.entry(*s).or_default().insert(*d);
        }
        Self {
            enforcing,
            allow,
            ..Self::default()
        }
    }

    /// Test builder for the server topology (see [`Self::for_test`]).
    #[doc(hidden)]
    pub fn for_test_servers(
        zones: &[(DerpPubKey, BusinessZone)],
        servers: &[DerpPubKey],
        links: &[(DerpPubKey, DerpPubKey)],
    ) -> Self {
        Self {
            zones: Some(zones.iter().copied().collect()),
            servers: servers.iter().copied().collect(),
            links: links.iter().flat_map(|&(a, b)| [(a, b), (b, a)]).collect(),
            ..Self::default()
        }
    }

    /// Test builder for the #21 zone gate (see [`Self::for_test`]).
    #[doc(hidden)]
    pub fn for_test_zones(zones: &[(DerpPubKey, BusinessZone)]) -> Self {
        Self {
            zones: Some(zones.iter().copied().collect()),
            ..Self::default()
        }
    }
}

/// `network_id → allow table`. Lives in [`AppState`]; absent = fail open.
pub type DerpAclCache = Arc<DashMap<ObjectId, Arc<DerpAllowTable>>>;

/// Decode a node's stored base64 WireGuard key into the 32-byte DERP address.
/// `None` for a malformed/short key — such a node simply gets no entry, which
/// (fail-open) leaves it ungated rather than unreachable.
fn pubkey_of(node: &OverlayNode) -> Option<DerpPubKey> {
    BASE64.decode(&node.wg_public_key).ok()?.try_into().ok()
}

/// Recompute one network's table and publish it atomically.
///
/// Build-then-swap, never invalidate-then-rebuild: there is no window in which
/// the network has no table (which, being fail-open, would be a window with no
/// gate at all). O(N²) over the network's nodes, but it runs only on policy
/// changes and joins — never per datagram, and never on an endpoint trickle,
/// which cannot change an ACL decision.
pub async fn rebuild(state: &NetworkState, tenant_id: ObjectId, network_id: ObjectId) {
    let acl = super::overlay::load_acl(state, tenant_id).await;
    let isolating =
        super::business_isolation::mode(state) == super::business_isolation::Mode::Enforce;
    // `Off` needs no table: `permits` would allow everything anyway, and
    // dropping the entry keeps a disabled tenant's memory at zero.
    if !acl.gating() && !isolating {
        state.derp_acl.remove(&network_id);
        return;
    }
    let nodes = match state
        .overlay_nodes
        .list_active_in_network(tenant_id, network_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            // Keep the PREVIOUS table rather than dropping to fail-open on a
            // transient Mongo blip.
            tracing::error!(%tenant_id, %e, "derp acl: node list failed; keeping the previous table");
            return;
        }
    };

    // One `OverlaySource` per node (owner + roles), resolved once and reused
    // across the N² pair evaluation. None when only the isolation gates: the
    // pair loop below then has nothing to zip.
    let mut sources = Vec::with_capacity(nodes.len());
    for n in nodes.iter().filter(|_| acl.gating()) {
        sources.push(super::overlay::overlay_source_of(state, n).await);
    }

    let mut zones = isolating.then(HashMap::new);
    if let Some(zones) = zones.as_mut() {
        for n in &nodes {
            let mode = super::business_isolation::Mode::Enforce;
            if let (Some(pk), Some(zone)) = (
                pubkey_of(n),
                super::business_isolation::zone_of(state, mode, n).await,
            ) {
                zones.insert(pk, zone);
            }
        }
    }

    let mut allow: HashMap<DerpPubKey, HashSet<DerpPubKey>> = HashMap::new();
    for (src_node, src) in nodes.iter().zip(&sources) {
        let Some(src_pk) = pubkey_of(src_node) else {
            continue;
        };
        let entry = allow.entry(src_pk).or_default();
        for peer in nodes.iter().filter(|p| p.id != src_node.id) {
            let Some(peer_pk) = pubkey_of(peer) else {
                continue;
            };
            // FR-97 P0b — the routes the peer OFFERS, as the netmap fans them.
            let routes = peer.effective_routes();
            let access = evaluate_overlay(
                &acl.policies,
                src,
                OverlayPeerRef {
                    node_id: peer.id.unwrap_or_default(),
                    overlay_ip: &peer.overlay_ip,
                    approved_routes: &routes,
                },
            );
            if access.visible {
                entry.insert(peer_pk);
            }
        }
    }

    // The server topology: which keys are servers, and which server pairs are
    // linked (both orders, so `permits` needs one lookup).
    let mut servers = HashSet::new();
    let mut links = HashSet::new();
    if isolating {
        let topo = super::business_isolation::lines(
            state,
            super::business_isolation::Mode::Enforce,
            tenant_id,
        )
        .await;
        let keyed: Vec<(&OverlayNode, DerpPubKey)> = nodes
            .iter()
            .filter_map(|n| Some((n, pubkey_of(n)?)))
            .collect();
        for (x, xk) in &keyed {
            for (y, yk) in &keyed {
                if let Some(linked) = topo.server_pair(x, y) {
                    servers.insert(*xk);
                    servers.insert(*yk);
                    if linked {
                        links.insert((*xk, *yk));
                    }
                }
            }
        }
    }

    let pairs: usize = allow.values().map(|s| s.len()).sum();
    tracing::info!(
        %tenant_id, %network_id,
        nodes = nodes.len(), pairs,
        enforcing = acl.enforcing(),
        zoned = zones.as_ref().map(|z| z.len()),
        "derp acl: allow table rebuilt"
    );
    state.derp_acl.insert(
        network_id,
        Arc::new(DerpAllowTable {
            enforcing: acl.enforcing(),
            allow,
            zones,
            servers,
            links,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> DerpPubKey {
        [b; 32]
    }

    fn table(enforcing: bool, pairs: &[(DerpPubKey, DerpPubKey)]) -> DerpAllowTable {
        DerpAllowTable::for_test(enforcing, pairs)
    }

    #[test]
    fn servers_relay_to_each_other_by_link_alone() {
        use BusinessZone::{Mainland, NonMainland};
        let (cn, us, us2, client) = (pk(1), pk(2), pk(3), pk(4));
        let t = DerpAllowTable::for_test_servers(
            &[
                (cn, Mainland),
                (us, NonMainland),
                (us2, NonMainland),
                (client, NonMainland),
            ],
            &[cn, us, us2],
            &[(cn, us)],
        );
        assert!(
            t.permits(&cn, &us) && t.permits(&us, &cn),
            "linked across the line"
        );
        assert!(!t.permits(&us, &us2), "unlinked inside one zone");
        assert!(t.permits(&client, &us), "a client keeps the zone rule");
        assert!(!t.permits(&client, &cn));
    }

    #[test]
    fn enforcing_table_permits_only_listed_pairs() {
        let t = table(true, &[(pk(1), pk(2))]);
        assert!(t.permits(&pk(1), &pk(2)));
        // Not symmetric by construction — the table stores what was evaluated.
        assert!(!t.permits(&pk(2), &pk(1)));
        // A pubkey with no entry at all is denied, not defaulted open: once a
        // tenant is enforcing, an unknown sender must not relay.
        assert!(!t.permits(&pk(9), &pk(2)));
        assert!(!t.permits(&pk(1), &pk(3)));
    }

    #[test]
    fn warn_table_permits_everything_including_unlisted() {
        // Built and populated, but non-enforcing: the counters are real while
        // no frame is ever dropped — the evidence-first cutover.
        let t = table(false, &[(pk(1), pk(2))]);
        assert!(t.permits(&pk(1), &pk(2)));
        assert!(t.permits(&pk(7), &pk(8)));
        assert!(!t.enforcing());
    }

    #[test]
    fn absent_table_is_fail_open_at_the_call_site() {
        // The cache miss (not the table) is what fails open; a DEFAULT table is
        // non-enforcing, so a bug that inserts one can't silently sever a
        // network either.
        let t = DerpAllowTable::default();
        assert!(t.permits(&pk(1), &pk(2)));
    }

    #[test]
    fn isolation_relays_only_inside_one_known_zone() {
        use BusinessZone::{Mainland, NonMainland};
        let t = DerpAllowTable::for_test_zones(&[
            (pk(1), Mainland),
            (pk(2), Mainland),
            (pk(3), NonMainland),
        ]);
        assert!(t.permits(&pk(1), &pk(2)));
        assert!(!t.permits(&pk(1), &pk(3)) && !t.permits(&pk(3), &pk(1)));
        // No zone fails closed, both ways.
        assert!(!t.permits(&pk(9), &pk(1)) && !t.permits(&pk(1), &pk(9)));
    }

    #[test]
    fn isolation_applies_under_a_warn_acl_too() {
        // The ACL only logs, but the zone gate still drops.
        let mut t = DerpAllowTable::for_test_zones(&[
            (pk(1), BusinessZone::Mainland),
            (pk(2), BusinessZone::NonMainland),
        ]);
        t.allow.entry(pk(1)).or_default().insert(pk(2));
        assert!(!t.enforcing() && !t.permits(&pk(1), &pk(2)));
    }
}
