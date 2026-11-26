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
//! # Failure posture: a MISSING table denies; the table is built before serve
//!
//! Every network that has been built carries an entry, including a network
//! whose ACL and isolation are both off: it gets an OPEN table
//! ([`DerpAllowTable::default`] permits everything). So a cache miss means
//! only "not built in this process yet", and `forward_frame` drops the frame.
//!
//! What keeps that from severing the floor is LOAD BEFORE SERVE:
//! `derp::handle_derp_socket` calls [`ensure_built`] before a node may
//! register, single-flight per network and bounded by
//! [`ENSURE_BUILT_TIMEOUT`]. A build that fails or times out refuses the
//! registration; the client reconnects on its own backoff, which retries the
//! build. It stays deny until a build succeeds and never turns into allow.
//!
//! Before this (MeshHarbor items #18/#21, 2026-11-11), a miss permitted the
//! frame, and after every restart the cache was empty until each network's
//! next join or policy change. That left a window in which an enforcing
//! tenant's ACL and the cross-zone rule were both open on this tier.
//!
//! What still fails open is unchanged and lives upstream:
//! `overlay::load_acl` reads a failed policy load as "no ACL". That case
//! builds an open table here, as before.
//!
//! # MeshHarbor #21 isolation
//!
//! Under `app.business_isolation = enforce` the table also carries each
//! node's business zone, and a frame passes only between two nodes with the
//! same known zone, whatever the ACL mode (a node with no zone relays to
//! nobody). The table is built for that even when the ACL is off. The
//! netmap, which withholds the cross-zone key from an honest client, is the
//! first line; this table is the second.

use bson::oid::ObjectId;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use meshharbor_core::business_authority::BusinessZone;
use meshharbor_remote_control::models::OverlayNode;
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
    /// Under `business_isolation = enforce` + `business_unknown_role = enforce`,
    /// the pubkeys of devices with an approved role (`Client` or `Server`).
    approved_roles: Option<HashSet<DerpPubKey>>,
    /// Logical Network Zone resolution (`zone_id`, `cross_zone_mode`) per node pubkey
    /// when `OverlayNetwork.zones` is non-empty; `UnresolvedStrict` nodes are omitted.
    network_zones: Option<
        HashMap<
            DerpPubKey,
            (
                String,
                meshharbor_remote_control::models::CrossZoneMode,
            ),
        >,
    >,
    /// Monotonic `OverlayNetwork.zone_revision` captured for this table (`None` for unit-test fixtures).
    zone_revision: Option<u64>,
    /// FR-124 — nodes in a strict zone whose countries do not hold this
    /// relay (or unresolved under zones): they relay to nobody and nobody to
    /// them, and they may not register at all ([`Self::refuses_registration`]).
    /// The netmap, which offers such a pair no DERP tier, is the first line.
    central_relay_denied: HashSet<DerpPubKey>,
}

impl DerpAllowTable {
    /// May `src` relay a frame to `dst`? Always `true` when neither the ACL
    /// nor the isolation is enforced.
    pub fn permits(&self, src: &DerpPubKey, dst: &DerpPubKey) -> bool {
        if self.central_relay_denied.contains(src) || self.central_relay_denied.contains(dst) {
            return false;
        }
        if let Some(nz) = &self.network_zones {
            use meshharbor_remote_control::models::CrossZoneMode;
            match (nz.get(src), nz.get(dst)) {
                (Some((za, _)), Some((zb, _))) if za == zb => {}
                (
                    Some((_, CrossZoneMode::DirectPreferred)),
                    Some((_, CrossZoneMode::DirectPreferred)),
                ) => {}
                _ => return false,
            }
        }
        if let Some(approved) = &self.approved_roles
            && (!approved.contains(src) || !approved.contains(dst))
        {
            return false;
        }
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

    /// FR-124 — `pk`'s zone keeps it off this relay: the registration is
    /// refused (and a live one closed), so the node holds no `/derp` socket to
    /// a relay outside its zone, not merely one whose frames are dropped.
    pub fn refuses_registration(&self, pk: &DerpPubKey) -> bool {
        self.central_relay_denied.contains(pk)
    }

    /// Test builder for the FR-124 zone-locality gate (see [`Self::for_test`]).
    #[doc(hidden)]
    pub fn for_test_central_relay_denied(denied: &[DerpPubKey]) -> Self {
        Self {
            central_relay_denied: denied.iter().copied().collect(),
            ..Self::default()
        }
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

/// `network_id → allow table`. Lives in [`AppState`]. An entry exists for
/// every network built in this process (an OPEN table when nothing gates),
/// so absent = not built yet, which DENIES (see the module docs).
pub type DerpAclCache = Arc<DashMap<ObjectId, Arc<DerpAllowTable>>>;

/// Upper bound on how long a `/derp` registration waits for its network's
/// first table build after a restart. Past it the registration is refused
/// and the client's reconnect retries.
pub const ENSURE_BUILT_TIMEOUT: Duration = Duration::from_secs(10);

/// Single-flight per network: a reconnect wave after a restart builds each
/// table ONCE, not once per registering node (the build is O(N²)).
static BUILD_LOCKS: LazyLock<DashMap<ObjectId, Arc<tokio::sync::Mutex<()>>>> =
    LazyLock::new(DashMap::new);

fn network_rebuild_lock(network_id: ObjectId) -> Arc<tokio::sync::Mutex<()>> {
    BUILD_LOCKS
        .entry(network_id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Load before serve: make sure `network_id` has a table in this process.
///
/// Returns `true` when an entry exists, whether it was already built or built
/// now. Returns `false` when the build failed or overran
/// [`ENSURE_BUILT_TIMEOUT`]; the caller must then refuse to serve the node. A
/// `false` never inserts anything, so the network stays deny.
pub async fn ensure_built(state: &NetworkState, tenant_id: ObjectId, network_id: ObjectId) -> bool {
    if state.derp_acl.contains_key(&network_id) {
        return true;
    }
    let lock = network_rebuild_lock(network_id);
    let build = async {
        let _single_flight = lock.lock().await;
        // Another registration or rebuild may have built it while we waited.
        if state.derp_acl.contains_key(&network_id) {
            return true;
        }
        rebuild_locked(state, tenant_id, network_id).await
            && state.derp_acl.contains_key(&network_id)
    };
    tokio::time::timeout(ENSURE_BUILT_TIMEOUT, build)
        .await
        .unwrap_or(false)
}

/// Decode a node's stored base64 WireGuard key into the 32-byte DERP address.
/// `None` for a malformed/short key — such a node simply gets no entry, which
/// (fail-open) leaves it ungated rather than unreachable.
fn pubkey_of(node: &OverlayNode) -> Option<DerpPubKey> {
    BASE64.decode(&node.wg_public_key).ok()?.try_into().ok()
}

fn build_overlay_allow_table(
    policies: &[meshharbor_remote_control::models::OverlayPolicy],
    nodes: &[OverlayNode],
    sources: &[tunnel_core::policy::OverlaySource],
) -> HashMap<DerpPubKey, HashSet<DerpPubKey>> {
    let bidir = super::overlay::bidir_peer_visibility_enabled();
    let mut allow: HashMap<DerpPubKey, HashSet<DerpPubKey>> = HashMap::new();
    for (src_node, src) in nodes.iter().zip(sources) {
        let Some(src_pk) = pubkey_of(src_node) else {
            continue;
        };
        allow.entry(src_pk).or_default();
        for peer in nodes.iter().filter(|p| p.id != src_node.id) {
            let Some(peer_pk) = pubkey_of(peer) else {
                continue;
            };
            // FR-97 P0b — the routes the peer OFFERS, as the netmap fans them.
            let routes = peer.effective_routes();
            let access = evaluate_overlay(
                policies,
                src,
                OverlayPeerRef {
                    node_id: peer.id.unwrap_or_default(),
                    overlay_ip: &peer.overlay_ip,
                    approved_routes: &routes,
                },
            );
            if access.visible {
                allow.entry(src_pk).or_default().insert(peer_pk);
                // T9-1 — if either direction passes `evaluate_overlay`, `/derp`
                // must forward frames in BOTH directions so WireGuard handshakes
                // and admitted replies complete; direction & port/proto stay
                // enforced on the receiving node by `Ingress::permits`.
                if bidir {
                    allow.entry(peer_pk).or_default().insert(src_pk);
                }
            }
        }
    }
    allow
}

fn install_fenced_derp_table(
    cache: &DerpAclCache,
    network_id: ObjectId,
    snap_rev: u64,
    current_db_rev: Option<u64>,
    table: Arc<DerpAllowTable>,
) -> bool {
    if current_db_rev != Some(snap_rev) {
        return false;
    }
    use dashmap::mapref::entry::Entry;
    match cache.entry(network_id) {
        Entry::Occupied(mut e) => {
            if e.get().zone_revision.is_some_and(|r| r > snap_rev) {
                return false;
            }
            e.insert(table);
            true
        }
        Entry::Vacant(v) => {
            v.insert(table);
            true
        }
    }
}

fn commit_open_or_keep_on_zone_read<T>(
    cache: &DerpAclCache,
    network_id: ObjectId,
    acl_gating: bool,
    isolating: bool,
    zone_snapshot: Result<(bool, u64, T), ()>,
    current_db_rev: Option<u64>,
) -> Option<(bool, u64, T)> {
    let (has_zones, snap_rev, snap) = zone_snapshot.ok()?;
    if !acl_gating && !isolating && !has_zones {
        let open = Arc::new(DerpAllowTable {
            zone_revision: Some(snap_rev),
            ..DerpAllowTable::default()
        });
        if !install_fenced_derp_table(cache, network_id, snap_rev, current_db_rev, open) {
            return None;
        }
        return Some((false, snap_rev, snap));
    }
    Some((has_zones, snap_rev, snap))
}

async fn current_db_zone_revision(state: &NetworkState, tenant_id: ObjectId) -> Option<u64> {
    state
        .overlay_networks
        .find_for_tenant(tenant_id)
        .await
        .ok()
        .map(|opt| opt.map_or(0, |n| n.zone_revision))
}

/// Recompute one network's table and publish it atomically.
///
/// Serialized per `network_id` from snapshot acquisition through publication, and
/// fenced on `OverlayNetwork.zone_revision` before every cache insertion so an
/// older delayed rebuild can never overwrite a newer zone restriction.
pub async fn rebuild(state: &NetworkState, tenant_id: ObjectId, network_id: ObjectId) -> bool {
    let lock = network_rebuild_lock(network_id);
    let _guard = lock.lock().await;
    rebuild_locked(state, tenant_id, network_id).await
}

async fn rebuild_locked(state: &NetworkState, tenant_id: ObjectId, network_id: ObjectId) -> bool {
    let acl = super::overlay::load_acl(state, tenant_id).await;
    let isolating =
        super::business_isolation::mode(state) == super::business_isolation::Mode::Enforce;
    let snap = crate::network_zones::TenantZoneSnapshot::load_consistent(state, tenant_id).await;
    let snap_res = if snap.read_failed || snap.superseded {
        tracing::warn!(
            %tenant_id,
            %network_id,
            read_failed = snap.read_failed,
            superseded = snap.superseded,
            "derp acl: network zones snapshot unreadable or superseded; keeping the previous table"
        );
        Err(())
    } else {
        Ok((snap.has_zones(), snap.revision, snap))
    };
    let db_rev_for_open = if snap_res
        .as_ref()
        .is_ok_and(|(has_zones, _, _)| !acl.gating() && !isolating && !*has_zones)
    {
        current_db_zone_revision(state, tenant_id).await
    } else {
        None
    };
    let Some((has_network_zones, snap_rev, snap)) = commit_open_or_keep_on_zone_read(
        &state.derp_acl,
        network_id,
        acl.gating(),
        isolating,
        snap_res,
        db_rev_for_open,
    ) else {
        return false;
    };
    // `Off` gets an OPEN table rather than no entry: a miss now means "not
    // built" and denies, so an ungated network must still be marked built.
    // `DerpAllowTable::default()` permits every pair, and costs a few empty
    // collections per network.
    if !acl.gating() && !isolating && !has_network_zones {
        return true;
    }
    let now = bson::DateTime::now();
    let nodes: Vec<_> = match state
        .overlay_nodes
        .list_active_in_network(tenant_id, network_id)
        .await
    {
        Ok(v) => v
            .into_iter()
            .filter(|n| n.is_key_authorized_at(now))
            .collect(),
        Err(e) => {
            // Keep the PREVIOUS table rather than dropping to fail-open on a
            // transient Mongo blip.
            tracing::error!(%tenant_id, %e, "derp acl: node list failed; keeping the previous table");
            return false;
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

    let allow = build_overlay_allow_table(&acl.policies, &nodes, &sources);

    // The server topology and approved-role set: which keys are servers, which
    // server pairs are linked, and which keys hold an approved role.
    let mut servers = HashSet::new();
    let mut links = HashSet::new();
    let mut approved_roles = None;
    let mut warn_unknown: Vec<(&OverlayNode, DerpPubKey)> = Vec::new();
    let mut all_keyed: Vec<(&OverlayNode, DerpPubKey)> = Vec::new();
    if isolating {
        let topo = super::business_isolation::lines(
            state,
            super::business_isolation::Mode::Enforce,
            tenant_id,
        )
        .await;
        if topo.roles_read_failed {
            tracing::error!(
                %tenant_id,
                %network_id,
                "derp acl: role approval read failed; keeping the previous table"
            );
            return false;
        }
        all_keyed = nodes
            .iter()
            .filter_map(|n| Some((n, pubkey_of(n)?)))
            .collect();
        for (x, xk) in &all_keyed {
            for (y, yk) in &all_keyed {
                if let Some(linked) = topo.server_pair(x, y) {
                    servers.insert(*xk);
                    servers.insert(*yk);
                    if linked {
                        links.insert((*xk, *yk));
                    }
                }
            }
        }
        match topo.unknown_role {
            super::business_isolation::Mode::Enforce => {
                let mut approved = HashSet::new();
                for (n, pk) in &all_keyed {
                    if topo.node_role_known(n) {
                        approved.insert(*pk);
                    }
                }
                approved_roles = Some(approved);
            }
            super::business_isolation::Mode::Warn => {
                for (n, pk) in &all_keyed {
                    if !topo.node_role_known(n) {
                        warn_unknown.push((n, *pk));
                    }
                }
            }
            super::business_isolation::Mode::Off => {}
        }
    }

    let mut central_relay_denied = HashSet::new();
    let network_zones = if has_network_zones {
        let mut nz = HashMap::new();
        for n in &nodes {
            let Some(pk) = pubkey_of(n) else { continue };
            let res = snap.resolve_node_sync(n);
            if !snap.central_relay_allowed(res) {
                central_relay_denied.insert(pk);
            }
            if let meshharbor_remote_control::models::DeviceZoneResolution::Resolved(z) = res {
                nz.insert(pk, (z.id.clone(), z.cross_zone_mode));
            }
        }
        Some(nz)
    } else {
        None
    };

    let pairs: usize = allow.values().map(|s| s.len()).sum();
    let table = Arc::new(DerpAllowTable {
        enforcing: acl.enforcing(),
        allow,
        zones,
        servers,
        links,
        approved_roles,
        network_zones,
        zone_revision: Some(snap_rev),
        central_relay_denied,
    });
    if !warn_unknown.is_empty() {
        let mut unknown_with_peers = Vec::new();
        for (n, pk) in &warn_unknown {
            if all_keyed
                .iter()
                .any(|(other, opk)| other.id != n.id && table.permits(pk, opk))
            {
                let label = super::business_isolation::Lines::node_label(n);
                if !unknown_with_peers.contains(&label) {
                    unknown_with_peers.push(label);
                }
            }
        }
        super::business_isolation::log_unknown_role_with_peers(
            tenant_id,
            "derp_acl",
            &unknown_with_peers,
        );
    }
    let current_db_rev = current_db_zone_revision(state, tenant_id).await;
    if !install_fenced_derp_table(
        &state.derp_acl,
        network_id,
        snap_rev,
        current_db_rev,
        table.clone(),
    ) {
        tracing::info!(
            %tenant_id, %network_id, snap_rev, ?current_db_rev,
            "derp acl: discarding superseded table rebuild"
        );
        return false;
    }
    tracing::info!(
        %tenant_id, %network_id,
        nodes = nodes.len(), pairs,
        enforcing = table.enforcing,
        zone_revision = snap_rev,
        zoned = table.zones.as_ref().map(|z| z.len()),
        "derp acl: allow table rebuilt"
    );
    true
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

    /// FR-124 — a node whose zone keeps it off this relay relays to nobody,
    /// nobody relays to it, and it may not register; everyone else is as before.
    #[test]
    fn a_node_its_zone_keeps_off_this_relay_relays_to_nobody_and_may_not_register() {
        let (confined, a, b) = (pk(0x61), pk(0x62), pk(0x63));
        let t = DerpAllowTable::for_test_central_relay_denied(&[confined]);
        assert!(!t.permits(&confined, &a));
        assert!(!t.permits(&a, &confined));
        assert!(
            t.permits(&a, &b),
            "an open table stays open for everyone else"
        );
        assert!(t.refuses_registration(&confined));
        assert!(!t.refuses_registration(&a));
    }

    #[test]
    fn unknown_role_enforce_denies_unapproved_derp_pubkey() {
        use BusinessZone::NonMainland;
        let (approved_a, approved_b, unapproved) = (pk(10), pk(11), pk(12));
        let mut t = DerpAllowTable::for_test_servers(
            &[
                (approved_a, NonMainland),
                (approved_b, NonMainland),
                (unapproved, NonMainland),
            ],
            &[],
            &[],
        );
        assert!(
            t.permits(&approved_a, &unapproved),
            "before approved_roles filter"
        );
        t.approved_roles = Some(HashSet::from([approved_a, approved_b]));
        assert!(t.permits(&approved_a, &approved_b));
        assert!(
            !t.permits(&approved_a, &unapproved),
            "unapproved dst denied"
        );
        assert!(
            !t.permits(&unapproved, &approved_a),
            "unapproved src denied"
        );
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
    fn the_default_table_is_the_open_marker_for_an_ungated_network() {
        // An ungated network is marked built with a DEFAULT table, which must
        // permit every pair. The cache MISS is what denies, at the call site in
        // `derp::forward_frame`, not this table.
        let t = DerpAllowTable::default();
        assert!(t.permits(&pk(1), &pk(2)));
        assert!(!t.enforcing());
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

    #[test]
    fn t9_1_one_way_policy_permits_derp_frames_in_both_directions() {
        use meshharbor_remote_control::models::{
            AgentStatus, NodeRef, OverlayPolicy, OverlayRule, OverlaySelector, OverlayTarget,
            PortRange, ProtocolKind,
        };
        use tunnel_core::policy::OverlaySource;

        let now = bson::DateTime::now();
        let tid = ObjectId::new();
        let net_id = ObjectId::new();
        let mk_node = |name: &str, ip: &str, key: DerpPubKey| OverlayNode {
            supports_invite_deadlines: true,
            personal_access_owner_id: None,
            temporary: None,
            id: Some(ObjectId::new()),
            tenant_id: tid,
            node_ref: NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            network_id: net_id,
            machine_id: name.into(),
            name: name.into(),
            overlay_ip: ip.into(),
            wg_public_key: BASE64.encode(key),
            key_epoch: 0,
            retired_wg_keys: vec![],
            key_issued_at: Some(now),
            key_ttl_secs: None,
            key_expires_at: None,
            key_revoked_at: None,
            reauth_required: false,
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            caps: None,
            caps_measured_at: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: true,
            supports_forced_derp: false,
            supports_server_relay_strategy: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            supports_p2pctl: false,
            supports_org_relay: false,
            advertised_routes: vec![],
            approved_routes: vec![],
            is_exit_node: false,
            routes_zone: None,
            route_offer_withheld: None,
            status: AgentStatus::Online,
            last_seen_at: now,
            applied_auth_revision: 0,
            applied_netmap_epoch: 0,
            applied_auth_at: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let (ka, kb, kc) = (pk(0x11), pk(0x22), pk(0x33));
        let na = mk_node("a", "100.64.0.10", ka);
        let nb = mk_node("b", "100.64.0.11", kb);
        let nc = mk_node("c", "100.64.0.12", kc);
        let nodes = vec![na.clone(), nb.clone(), nc.clone()];
        let sources: Vec<OverlaySource> = nodes
            .iter()
            .map(|n| OverlaySource {
                node_id: n.id.unwrap(),
                owner_user_id: None,
                role_ids: vec![],
            })
            .collect();
        let policies = vec![OverlayPolicy {
            id: Some(ObjectId::new()),
            tenant_id: tid,
            name: "one-way-a-to-b".into(),
            enabled: true,
            sources: vec![OverlaySelector::NodeId {
                node_id: na.id.unwrap(),
            }],
            via: vec![OverlayTarget::NodeId {
                node_id: nb.id.unwrap(),
            }],
            destinations: vec![OverlayRule {
                expires_at_ms: None,
                cidr: "100.64.0.11/32".into(),
                port_range: PortRange { low: 22, high: 22 },
                proto: ProtocolKind::Tcp,
            }],
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }];
        let allow = build_overlay_allow_table(&policies, &nodes, &sources);
        let t = DerpAllowTable {
            enforcing: true,
            allow,
            ..DerpAllowTable::default()
        };
        assert!(t.permits(&ka, &kb), "forward A -> B DERP frame permitted");
        assert!(
            t.permits(&kb, &ka),
            "reverse B -> A DERP frame must ALSO be permitted for WG handshake & replies"
        );
        assert!(!t.permits(&ka, &kc) && !t.permits(&kc, &ka));
        assert!(!t.permits(&kb, &kc) && !t.permits(&kc, &kb));
    }

    #[test]
    fn restricted_read_failed_never_installs_open_table_and_preserves_existing() {
        use meshharbor_remote_control::models::CrossZoneMode;
        let cache: DerpAclCache = Arc::new(DashMap::new());
        let net_id = ObjectId::new();
        let (cn, hk, global) = (pk(0x41), pk(0x42), pk(0x43));

        // 1. Cold cache + DB read failure under ACL=off, isolation=off:
        //    must return None (rebuild -> false) and leave cache empty (miss = deny),
        //    NEVER inserting DerpAllowTable::default()!
        assert!(
            commit_open_or_keep_on_zone_read::<()>(&cache, net_id, false, false, Err(()), None)
                .is_none()
        );
        assert!(
            !cache.contains_key(&net_id),
            "failed zone read on cold cache must fail closed, never install open table"
        );

        // 2. Warm cache holding a zone-gated table + DB read failure:
        //    must preserve the existing restricted table intact!
        let existing = Arc::new(DerpAllowTable {
            network_zones: Some(HashMap::from([
                (cn, ("cn".into(), CrossZoneMode::RouterOnly)),
                (hk, ("hk".into(), CrossZoneMode::DirectPreferred)),
                (global, ("global".into(), CrossZoneMode::DirectPreferred)),
            ])),
            zone_revision: Some(5),
            ..DerpAllowTable::default()
        });
        assert!(!existing.permits(&cn, &hk));
        assert!(!existing.permits(&hk, &cn));
        assert!(existing.permits(&hk, &global));
        cache.insert(net_id, existing);

        assert!(
            commit_open_or_keep_on_zone_read::<()>(&cache, net_id, false, false, Err(()), None)
                .is_none()
        );
        let preserved = cache.get(&net_id).expect("previous table preserved");
        assert!(
            !preserved.permits(&cn, &hk),
            "failed zone read must preserve existing restricted DERP table"
        );
    }

    #[tokio::test]
    async fn delayed_older_rebuild_is_fenced_and_never_overwrites_newer_zone_restriction() {
        use meshharbor_remote_control::models::CrossZoneMode;
        let cache: DerpAclCache = Arc::new(DashMap::new());
        let net_id = ObjectId::new();
        let (cn, hk) = (pk(0x51), pk(0x52));

        let permissive_r1 = Arc::new(DerpAllowTable {
            network_zones: Some(HashMap::from([
                (cn, ("cn".into(), CrossZoneMode::DirectPreferred)),
                (hk, ("hk".into(), CrossZoneMode::DirectPreferred)),
            ])),
            zone_revision: Some(1),
            ..DerpAllowTable::default()
        });
        let strict_r2 = Arc::new(DerpAllowTable {
            network_zones: Some(HashMap::from([
                (cn, ("cn".into(), CrossZoneMode::RouterOnly)),
                (hk, ("hk".into(), CrossZoneMode::DirectPreferred)),
            ])),
            zone_revision: Some(2),
            ..DerpAllowTable::default()
        });

        let (a_paused_tx, a_paused_rx) = tokio::sync::oneshot::channel();
        let (b_done_tx, b_done_rx) = tokio::sync::oneshot::channel();

        // Simulate deterministic delayed older rebuild A (captured r=1) vs newer rebuild B (r=2).
        let cache_a = cache.clone();
        let task_a = tokio::spawn(async move {
            let _ = a_paused_tx.send(());
            let _ = b_done_rx.await;
            // Both DB revision (Some(2)) and cached table revision (Some(2)) reject snap_rev = 1!
            let ok_vs_db = install_fenced_derp_table(&cache_a, net_id, 1, Some(2), permissive_r1.clone());
            let ok_vs_cache = install_fenced_derp_table(&cache_a, net_id, 1, Some(1), permissive_r1);
            (ok_vs_db, ok_vs_cache)
        });

        let _ = a_paused_rx.await;
        assert!(install_fenced_derp_table(&cache, net_id, 2, Some(2), strict_r2));
        let _ = b_done_tx.send(());

        let (ok_vs_db, ok_vs_cache) = task_a.await.unwrap();
        assert!(!ok_vs_db && !ok_vs_cache, "stale r=1 rebuild must be rejected");
        assert!(
            commit_open_or_keep_on_zone_read(&cache, net_id, false, false, Ok((false, 1, ())), Some(2))
                .is_none(),
            "stale open-table insertion must also be fenced"
        );
        let final_tbl = cache.get(&net_id).expect("r=2 table remains installed");
        assert_eq!(final_tbl.zone_revision, Some(2));
        assert!(
            !final_tbl.permits(&cn, &hk),
            "r=2 RouterOnly restriction must remain enforced"
        );
    }
}
