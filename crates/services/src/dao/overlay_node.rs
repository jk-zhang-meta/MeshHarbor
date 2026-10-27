// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use mongodb::options::ReturnDocument;
use roomler_ai_remote_control::models::{AgentStatus, DEFAULT_ROUTE_V4, NodeRef, OverlayNode};

use super::base::{BaseDao, DaoResult};

/// Overlay membership rows — one per host (agent or tunnel-client) that
/// has joined a tenant's virtual LAN. Keyed for rehydrate by
/// `(tenant_id, machine_id)` like `agents` / `tunnel_clients`.
pub struct OverlayNodeDao {
    pub base: BaseDao<OverlayNode>,
}

impl OverlayNodeDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, OverlayNode::COLLECTION),
        }
    }

    /// Locate the LIVE overlay node for `(tenant_id, machine_id)`. The join
    /// path calls this first and rehydrates (keeping the leased overlay IP)
    /// instead of allocating a new one.
    ///
    /// Scoped to `deleted_at: null` because removal tombstones IN PLACE: a
    /// released machine keeps its row as the forensic record, and re-enrolling
    /// the SAME machine must NOT revive it — removal is FINAL, so the device
    /// comes back as a brand-new node with a fresh IP and a freshly-deduped
    /// name.
    ///
    /// The scoping is MANDATORY, not cosmetic: the `(tenant_id, machine_id)`
    /// unique index is partial on live rows, so several tombstones may share a
    /// `machine_id` alongside one live row, and an unscoped `find_one` would
    /// return an arbitrary one of them — making a live node look absent.
    pub async fn find_live_by_tenant_and_machine(
        &self,
        tenant_id: ObjectId,
        machine_id: &str,
    ) -> DaoResult<Option<OverlayNode>> {
        self.base
            .find_one(doc! {
                "tenant_id": tenant_id,
                "machine_id": machine_id,
                "deleted_at": null,
            })
            .await
    }
}

/// Everything [`OverlayNodeDao::create`] needs, by NAME.
///
/// This was 17 positional arguments and it went wrong twice, in ways a
/// struct makes unrepresentable:
///
/// - it grew three `bool`s and its eight test callers were not updated, which
///   stopped `crates/tests` compiling for months (#603). Named fields do not
///   prevent that, but they make the fix mechanical instead of a matter of
///   counting commas across seven consecutive `false`s;
/// - a fixture passed `mach-shut` where the agent had enrolled as `shut-mach`
///   (#612). `machine_id` and `name` are ADJACENT and both `String`, so the
///   transposition compiled cleanly and cost a long diagnosis. It cannot now.
///
/// Deliberately NO `Default`: a new field must break every call site, because
/// the whole point is that someone decides what it should be there. A default
/// would restore the silent-drift class this replaces.
pub struct NewOverlayNode {
    pub tenant_id: ObjectId,
    pub node_ref: NodeRef,
    pub network_id: ObjectId,
    /// MUST be the id the agent/tunnel-client enrolled with — `current_node`
    /// resolves a socket to its node by `{tenant_id, machine_id}`, so a row
    /// under any other machine id is invisible to the overlay and `/derp`.
    pub machine_id: String,
    /// Display name. NOT an identity — see `machine_id`.
    pub name: String,
    pub overlay_ip: String,
    pub wg_public_key: String,
    pub key_epoch: u32,
    pub endpoints: Vec<String>,
    pub supports_quic: bool,
    pub supports_relay_single: bool,
    pub supports_derp: bool,
    pub supports_forced_derp: bool,
    pub supports_server_relay_strategy: bool,
    pub supports_derp_floor: bool,
    pub supports_overlay_echo: bool,
    pub supports_org_relay: bool,
    pub advertised_routes: Vec<String>,
    /// FR-97 P0b — the join's word on why `advertised_routes` is empty
    /// although the device was configured to offer routes. `None` = offering
    /// as configured.
    pub route_offer_withheld: Option<String>,
}

impl OverlayNodeDao {
    /// Is `wg_public_key` already held by a LIVE node in this network that is
    /// NOT `machine_id`?
    ///
    /// The WG public key arrives verbatim from the joining client and is then
    /// used as an ADDRESSING key: `/derp` authorizes a registration by
    /// comparing against the node row's key, and WireGuard itself keys peers by
    /// pubkey. Without this check a second enrolled device in the same tenant
    /// could join advertising ANOTHER device's key and black-hole its DERP
    /// traffic (registration is last-writer-wins) or capture its peer entry.
    /// Nothing proves possession of the private half, so uniqueness is the
    /// cheap structural defence.
    ///
    /// Live-scoped: tombstones keep their key as the forensic record and must
    /// not block a new joiner.
    pub async fn wg_key_taken_by_other(
        &self,
        network_id: ObjectId,
        wg_public_key: &str,
        machine_id: &str,
    ) -> DaoResult<bool> {
        Ok(self
            .base
            .find_one(doc! {
                "network_id": network_id,
                "wg_public_key": wg_public_key,
                "machine_id": { "$ne": machine_id },
                "deleted_at": null,
            })
            .await?
            .is_some())
    }

    /// Insert a fresh node with a freshly-allocated overlay IP.
    pub async fn create(&self, new: NewOverlayNode) -> DaoResult<OverlayNode> {
        let NewOverlayNode {
            tenant_id,
            node_ref,
            network_id,
            machine_id,
            name,
            overlay_ip,
            wg_public_key,
            key_epoch,
            endpoints,
            supports_quic,
            supports_relay_single,
            supports_derp,
            supports_forced_derp,
            supports_server_relay_strategy,
            supports_derp_floor,
            supports_overlay_echo,
            supports_org_relay,
            advertised_routes,
            route_offer_withheld,
        } = new;
        let now = DateTime::now();
        let node = OverlayNode {
            id: None,
            tenant_id,
            node_ref,
            network_id,
            machine_id,
            name,
            overlay_ip,
            wg_public_key,
            key_epoch,
            // The join carries the agent's DIRECT LAN candidates; seed BOTH
            // buckets. The relay trickle later replaces `endpoints` only —
            // `lan_endpoints` survives so peers keep seeing the LAN address.
            lan_endpoints: endpoints.clone(),
            endpoints,
            // Phase B — no srflx until the node gathers it (post-join, via STUN)
            // and trickles it up on `rc:overlay.srflx`.
            srflx_endpoints: Vec::new(),
            // Phase C — NAT type is unknown until the node probes + trickles it.
            srflx_nat: None,
            caps: None,
            caps_measured_at: None,
            udp_dialer_ok: None,
            relay_home: None,
            // C4 stage 2 (PR-B) — no warm leg until the node's runtime
            // establishes one and its heartbeats mirror it here.
            warm_relay_endpoint: None,
            supports_quic,
            supports_relay_single,
            supports_derp,
            supports_forced_derp,
            supports_server_relay_strategy,
            supports_derp_floor,
            supports_overlay_echo,
            supports_org_relay,
            // Phase 1 — the node's claimed routes; nothing approved until an
            // admin acts, so a fresh node routes for no one.
            advertised_routes,
            approved_routes: Vec::new(),
            // P5 — never an exit node until an admin toggles it on.
            is_exit_node: false,
            routes_zone: None,
            route_offer_withheld,
            status: AgentStatus::Online,
            last_seen_at: now,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let id = self.base.insert_one(&node).await?;
        self.base.find_by_id(id).await
    }

    /// Re-join: refresh the WG key + endpoints + node_ref, mark Online. Keeps
    /// the existing `overlay_ip`. Returns the updated row.
    ///
    /// Only ever reached for a LIVE row (the lookup is
    /// [`Self::find_live_by_tenant_and_machine`]), so the `deleted_at: Null` in
    /// the `$set` below is a vestigial no-op — kept as belt-and-braces in case
    /// the lookup is ever widened.
    #[allow(clippy::too_many_arguments)]
    pub async fn rehydrate(
        &self,
        node_id: ObjectId,
        node_ref: &NodeRef,
        name: &str,
        wg_public_key: &str,
        key_epoch: u32,
        endpoints: &[String],
        supports_quic: bool,
        supports_relay_single: bool,
        supports_derp: bool,
        supports_forced_derp: bool,
        supports_server_relay_strategy: bool,
        supports_derp_floor: bool,
        supports_overlay_echo: bool,
        supports_org_relay: bool,
        advertised_routes: &[String],
        route_offer_withheld: Option<&str>,
    ) -> DaoResult<OverlayNode> {
        let node_ref_bson = bson::to_bson(node_ref).unwrap_or(bson::Bson::Null);
        self.base
            .update_by_id(
                node_id,
                doc! {
                    "$set": {
                        "node_ref": node_ref_bson,
                        // Phase 0 — the join handler passes the stable name
                        // (existing name reused, or a freshly deduped one when
                        // backfilling a pre-Phase-0 row).
                        "name": name,
                        // Phase 1 — refresh the CLAIMED routes on each join.
                        // `approved_routes` is admin-controlled and intentionally
                        // NOT touched here, so approvals survive a rejoin.
                        "advertised_routes": advertised_routes,
                        // FR-97 P0b — and why they are empty, refreshed with
                        // them: null clears a reason the device no longer has.
                        "route_offer_withheld": route_offer_withheld,
                        "wg_public_key": wg_public_key,
                        "key_epoch": key_epoch as i64,
                        // Refresh BOTH buckets from the join (rc.135) — a DHCP
                        // IP change is picked up, and the LAN bucket is restored
                        // before the next relay trickle replaces `endpoints`.
                        "endpoints": endpoints,
                        "lan_endpoints": endpoints,
                        // Phase B — clear stale srflx on re-join; the node
                        // re-gathers + re-trickles fresh srflx this connection
                        // (a prior session's NAT mapping is meaningless now).
                        "srflx_endpoints": [],
                        // Phase C (A8) — clear the stale NAT class in the SAME
                        // $set (a prior session's NAT type is meaningless after
                        // a roam); the node re-probes + re-trickles it.
                        "srflx_nat": bson::Bson::Null,
                        // Dialer honesty — clear with the srflx bucket: the
                        // restarted runtime re-earns the verdict (and its
                        // first srflx trickle re-declares it).
                        "udp_dialer_ok": bson::Bson::Null,
                        // Phase B — the capability vector is re-measured
                        // ~45 s after start; a prior session's measurements
                        // are meaningless on a possibly-new network.
                        "caps": bson::Bson::Null,
                        "caps_measured_at": bson::Bson::Null,
                        // C4 stage 2 (PR-B) — clear the stale warm-leg address
                        // for the same reason: a restarted runtime holds no
                        // allocation; its heartbeats re-mirror a fresh one.
                        "warm_relay_endpoint": bson::Bson::Null,
                        // rc.142 — refresh the QUIC capability on each re-join
                        // (an operator may flip ROOMLERD_OVERLAY_QUIC).
                        "supports_quic": supports_quic,
                        // Phase D — refresh the single-relay capability on each
                        // re-join (an operator may flip OVERLAY_RELAY_SINGLE).
                        "supports_relay_single": supports_relay_single,
                        // Phase D (DERP) — refresh the DERP capability on each
                        // re-join (an operator may flip OVERLAY_DERP).
                        "supports_derp": supports_derp,
                        // P7 — refresh the forced-DERP capability likewise.
                        "supports_forced_derp": supports_forced_derp,
                        // U2 — refresh the server-relay-strategy opt-in likewise
                        // (an operator may flip OVERLAY_SERVER_RELAY_STRATEGY).
                        "supports_server_relay_strategy": supports_server_relay_strategy,
                        "supports_derp_floor": supports_derp_floor,
                        // Data-probe — refresh the overlay-native-echo capability
                        // on each re-join (a downgrade must clear it). Hand-built
                        // doc: adding the field HERE is load-bearing (a doc!{} miss
                        // is not a compile error and silently never persists).
                        "supports_overlay_echo": supports_overlay_echo,
                        "supports_org_relay": supports_org_relay,
                        "status": bson::to_bson(&AgentStatus::Online).unwrap(),
                        "last_seen_at": DateTime::now(),
                        "updated_at": DateTime::now(),
                        "deleted_at": bson::Bson::Null,
                    }
                },
            )
            .await?;
        self.base.find_by_id(node_id).await
    }

    /// Compare-and-swap tombstone: mark the node released ONLY if it is still
    /// live, returning the PRE-image (so the caller can recover the overlay IP
    /// it was holding). `None` ⇒ someone else already released it — a
    /// double-clicked evict, or an evict racing the agent DELETE — and the
    /// caller must do nothing further.
    ///
    /// Winning this CAS is the release TOKEN: it is what keeps a host number
    /// from being returned to the free pool twice, which would hand two live
    /// nodes the same overlay IP.
    ///
    /// `overlay_ip`, `name`, `wg_public_key`, `machine_id` and `node_ref` are
    /// deliberately KEPT — the tombstone is the record of who held an address,
    /// which matters precisely because addresses now recycle. Uniqueness on the
    /// IP and the name is scoped to live rows, so a tombstone holds neither.
    /// Every live node's overlay address, across ALL tenants.
    ///
    /// Cross-tenant on purpose: the block registry is global, so "is this
    /// range still occupied?" is a global question. Only the reclaim path
    /// asks it, and only when an operator does.
    pub async fn all_live_overlay_ips(&self) -> DaoResult<Vec<String>> {
        Ok(self
            .base
            .find_many(doc! { "deleted_at": null }, None)
            .await?
            .into_iter()
            .map(|n| n.overlay_ip)
            .collect())
    }

    pub async fn release(&self, node_id: ObjectId) -> DaoResult<Option<OverlayNode>> {
        let now = DateTime::now();
        Ok(self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": node_id, "deleted_at": null },
                doc! { "$set": {
                    // `Unenrolled`, not `Offline`: an offline node is coming
                    // back, a released one is not.
                    "status": bson::to_bson(&AgentStatus::Unenrolled).unwrap(),
                    // Revoke the ADMIN GRANTS. Not strictly required — a
                    // re-enroll creates a fresh row with both empty, and the
                    // approval surface only lists live nodes — but a future
                    // "restore node" action must never silently reinstate
                    // exit-node authority.
                    "approved_routes": Vec::<String>::new(),
                    "is_exit_node": false,
                    "deleted_at": now,
                    "updated_at": now,
                } },
            )
            .return_document(ReturnDocument::Before)
            .await?)
    }

    /// All active (non-deleted) nodes in a network — the netmap source.
    pub async fn list_active_in_network(
        &self,
        tenant_id: ObjectId,
        network_id: ObjectId,
    ) -> DaoResult<Vec<OverlayNode>> {
        self.base
            .find_many(
                doc! { "tenant_id": tenant_id, "network_id": network_id, "deleted_at": null },
                Some(doc! { "created_at": 1 }),
            )
            .await
    }

    /// Replace the node's trickled connectivity candidates.
    pub async fn update_endpoints(
        &self,
        node_id: ObjectId,
        endpoints: &[String],
    ) -> DaoResult<bool> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "endpoints": endpoints,
                    "last_seen_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// Phase B/C — replace the node's server-reflexive (srflx) candidates and
    /// its probed NAT type. A SEPARATE bucket from `endpoints` (relay) /
    /// `lan_endpoints` (public NIC) so a srflx trickle never clobbers a relay/LAN
    /// address and vice-versa. `nat` (`Some("cone"|"symmetric")` / `None` when
    /// unknown) is stored alongside so peers can skip a both-symmetric punch.
    /// Multi-region relay PoPs: mirror an AGENT's derived `relay_home` onto
    /// its live overlay-node row(s) — the netmap already fans `relay_home`
    /// per peer, and the broker's pair-region pick reads it from here.
    /// The LIVE overlay row for an agent, if it has one.
    ///
    /// Roomler SSH needs it to tell a caller where to dial. Live-scoped
    /// (`deleted_at: null`) on purpose: a tombstone keeps the address it once
    /// held as a forensic record, and handing that out would send the caller
    /// to whoever holds it now.
    pub async fn find_live_by_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> DaoResult<Option<OverlayNode>> {
        self.base
            .find_one(doc! {
                "tenant_id": tenant_id,
                "node_ref.kind": "agent",
                "node_ref.id": agent_id,
                "deleted_at": bson::Bson::Null,
            })
            .await
    }

    /// Twin of [`Self::find_live_by_agent`] for tunnel-client-backed nodes —
    /// keyed by node_ref (the `{tenant_id, "node_ref.id"}` index), not
    /// machine_id, so it can't confuse an agent and a tunnel client that
    /// coexist on one host with different machine-id derivations.
    pub async fn find_live_by_tunnel_client(
        &self,
        tenant_id: ObjectId,
        tunnel_client_id: ObjectId,
    ) -> DaoResult<Option<OverlayNode>> {
        self.base
            .find_one(doc! {
                "tenant_id": tenant_id,
                "node_ref.kind": "tunnel_client",
                "node_ref.id": tunnel_client_id,
                "deleted_at": bson::Bson::Null,
            })
            .await
    }

    pub async fn set_relay_home_for_agent(
        &self,
        agent_id: ObjectId,
        relay_home: Option<&str>,
    ) -> DaoResult<u64> {
        self.base
            .update_many(
                doc! {
                    "node_ref.kind": "agent",
                    "node_ref.id": agent_id,
                    "deleted_at": bson::Bson::Null,
                },
                doc! { "$set": {
                    "relay_home": relay_home,
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// C4 stage 2 (PR-B) — mirror an agent's STANDING warm-leg relayed address
    /// onto its live overlay-node row(s), where the netmap builder reads it
    /// (the netmap is built from OVERLAY_NODES, not agents — PR-A's
    /// `agents.warm_relay_endpoint` write alone never reaches a peer).
    /// `$unset` while no leg is live so a stale address can never be served
    /// as a dial target. Called per heartbeat alongside `touch_heartbeat`.
    pub async fn set_warm_relay_for_agent(
        &self,
        agent_id: ObjectId,
        warm_relay: Option<&str>,
    ) -> DaoResult<u64> {
        let filter = doc! {
            "node_ref.kind": "agent",
            "node_ref.id": agent_id,
            "deleted_at": bson::Bson::Null,
        };
        let update = match warm_relay {
            Some(ep) => doc! { "$set": {
                "warm_relay_endpoint": ep,
                "updated_at": DateTime::now(),
            } },
            None => doc! {
                "$set": { "updated_at": DateTime::now() },
                "$unset": { "warm_relay_endpoint": "" },
            },
        };
        self.base.update_many(filter, update).await
    }

    pub async fn update_srflx_endpoints(
        &self,
        node_id: ObjectId,
        srflx_endpoints: &[String],
        nat: Option<&str>,
        udp_dialer_ok: Option<bool>,
    ) -> DaoResult<bool> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "srflx_endpoints": srflx_endpoints,
                    "srflx_nat": nat.map(|s| s.to_string()),
                    // Dialer honesty — set EXPLICITLY (None ⇒ Bson::Null ⇒
                    // "pre-honesty agent"), never omitted: a hand-built doc
                    // silently drops absent fields.
                    "udp_dialer_ok": udp_dialer_ok,
                    "last_seen_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// Phase B (overlay v3) — store a freshly-measured capability vector
    /// with its receipt stamp (the freshness gate's input). Explicit `$set`
    /// on both fields — a hand-built doc silently drops absent keys.
    pub async fn update_netcheck_caps(
        &self,
        node_id: ObjectId,
        caps: roomler_ai_remote_control::signaling::CapVectorWire,
    ) -> DaoResult<bool> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "caps": bson::to_bson(&caps).unwrap_or(bson::Bson::Null),
                    "caps_measured_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    pub async fn mark_status(&self, node_id: ObjectId, status: AgentStatus) -> DaoResult<bool> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "status": bson::to_bson(&status).unwrap(),
                    "last_seen_at": DateTime::now(),
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// P2b — move a LIVE node to a new overlay address as part of a tenant
    /// renumber. Scoped to `(node_id, network_id)` so a plan computed against
    /// one network can never write into another's row.
    ///
    /// Ordering matters at the call site: the unique
    /// `(tenant_id, network_id, overlay_ip)` index is over LIVE rows, so a
    /// renumber that lands two nodes on the same address fails loudly on the
    /// second write instead of silently duplicating a lease. Since a plan
    /// always targets a DIFFERENT block than the one currently in use, no
    /// intermediate state can collide with an unmoved node.
    pub async fn set_overlay_ip(
        &self,
        node_id: ObjectId,
        network_id: ObjectId,
        overlay_ip: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": node_id, "network_id": network_id, "deleted_at": null },
                doc! { "$set": {
                    "overlay_ip": overlay_ip,
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// Phase 1 — set the admin-APPROVED subnet routes for a node and return the
    /// updated row. The caller must first verify the node belongs to the admin's
    /// tenant and that each route is among the node's `advertised_routes`.
    /// Rename the node's MagicDNS label. The caller owns sanitization +
    /// in-network de-dup (`ws::overlay::propagate_node_rename`); the unique
    /// partial `(tenant, network, name)` index is the final arbiter — a lost
    /// race surfaces as `DaoError::DuplicateKey` for the caller to retry.
    pub async fn set_name(&self, node_id: ObjectId, name: &str) -> DaoResult<OverlayNode> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "name": name,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(node_id).await
    }

    pub async fn set_approved_routes(
        &self,
        node_id: ObjectId,
        approved_routes: &[String],
        routes_zone: Option<&str>,
    ) -> DaoResult<OverlayNode> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "approved_routes": approved_routes,
                    "routes_zone": routes_zone,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(node_id).await
    }

    /// P5 — designate (or un-designate) a node as an exit node. Sets the
    /// `is_exit_node` flag AND adds/removes `0.0.0.0/0` in `approved_routes`
    /// (the data-plane signal). The caller verifies tenant ownership and, when
    /// enabling, that the node advertised `0.0.0.0/0`. This is the ONLY path
    /// that puts a `/0` into `approved_routes` — the per-CIDR
    /// [`Self::set_approved_routes`] rejects it.
    pub async fn set_exit_node(&self, node_id: ObjectId, enabled: bool) -> DaoResult<OverlayNode> {
        // Read-modify-write the approved list so we preserve any subnet CIDRs
        // the node also routes while flipping just the default route.
        let node = self.base.find_by_id(node_id).await?;
        let mut approved: Vec<String> = node
            .approved_routes
            .into_iter()
            .filter(|r| r != DEFAULT_ROUTE_V4)
            .collect();
        if enabled {
            approved.push(DEFAULT_ROUTE_V4.to_string());
        }
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": {
                    "is_exit_node": enabled,
                    "approved_routes": &approved,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        self.base.find_by_id(node_id).await
    }

    pub async fn touch_heartbeat(&self, node_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_by_id(
                node_id,
                doc! { "$set": { "last_seen_at": DateTime::now() } },
            )
            .await
    }
}
