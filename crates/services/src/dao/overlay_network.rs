// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::{DateTime, doc, oid::ObjectId};
use mongodb::Database;
use mongodb::options::ReturnDocument;
use roomler_ai_remote_control::models::{BlockList, OverlayAclMode, OverlayNetwork, PeerRelayMode};

use super::base::{BaseDao, DaoError, DaoResult};
use super::overlay_block::OverlayBlockDao;

/// IPAM authority for tenant overlay networks. One row per tenant; the
/// host cursor (`next_host`) is bumped atomically so concurrent joins
/// never collide on an overlay IP.
pub struct OverlayNetworkDao {
    pub base: BaseDao<OverlayNetwork>,
    /// P2b — the global block registry. Owned here (not injected) because
    /// carving a block is part of creating a network: every caller of
    /// `get_or_create` must get a network whose CIDR already matches the
    /// registry, or the two authorities drift.
    blocks: OverlayBlockDao,
    /// P2b — when set, a NEWLY created network is carved a block of this
    /// prefix instead of sharing the legacy `100.64.0.0/10`. `None` (the
    /// default, and the shipped default until the flag is flipped per
    /// deployment) keeps the pre-P2b behaviour exactly.
    block_prefix: Option<u8>,
}

impl OverlayNetworkDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, OverlayNetwork::COLLECTION),
            blocks: OverlayBlockDao::new(db),
            block_prefix: None,
        }
    }

    /// P2b — enable tenant-block carving for networks created from here on.
    /// Existing networks are NOT migrated: that is the explicit, admin-driven
    /// renumber endpoint's job (it has to cycle every node's WS).
    pub fn with_block_prefix(mut self, prefix: Option<u8>) -> Self {
        self.block_prefix = prefix;
        self
    }

    /// The block registry, for callers that need to read or retire a block
    /// (the renumber endpoint).
    pub fn blocks(&self) -> &OverlayBlockDao {
        &self.blocks
    }

    /// FR-47 P5b — a network's address space as a [`BlockList`].
    ///
    /// One entry today for every network in existence, so this is the
    /// single-block path and therefore byte-for-byte the old
    /// `overlay_ip`/`overlay_host` behaviour (pinned by
    /// `a_single_block_list_is_exactly_the_old_pair`). It becomes multi-entry
    /// only once P5c starts appending blocks on exhaustion.
    ///
    /// Falls back to the network's own `cidr` when the registry has nothing:
    /// that is a LEGACY network on the shared `/10`, which never had a block
    /// row and must still be addressable.
    pub async fn block_list(&self, net: &OverlayNetwork) -> BlockList {
        let Some(network_id) = net.id else {
            return BlockList::single(&net.cidr);
        };
        match self
            .blocks
            .find_assigned_for_network_ordered(network_id)
            .await
        {
            Ok(blocks) if !blocks.is_empty() => BlockList::new(blocks.into_iter().map(|b| b.cidr)),
            // A registry read failure must not invent an address space. The
            // network's own cidr is what every pre-P5b code path used, so
            // falling back to it degrades to today's behaviour rather than to
            // an empty list that would refuse every lease.
            Ok(_) => BlockList::single(&net.cidr),
            Err(e) => {
                tracing::warn!(%network_id, %e, "overlay: block list read failed; using the network cidr");
                BlockList::single(&net.cidr)
            }
        }
    }

    /// P2b — the prefix new networks are carved at, when carving is on.
    pub fn block_prefix(&self) -> Option<u8> {
        self.block_prefix
    }

    /// The tenant's network if it HAS one, without creating it.
    ///
    /// [`Self::get_or_create`] is right for anything joining the mesh;
    /// teardown paths (archiving an org) must not conjure a network row for
    /// a tenant that never had one just to ask whether it did.
    pub async fn find_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<Option<OverlayNetwork>> {
        self.base.find_one(doc! { "tenant_id": tenant_id }).await
    }

    /// Fetch the tenant's overlay network, creating it with the default
    /// CIDR/MTU on first use. Race-safe via the `(tenant_id)` unique
    /// index: a losing concurrent insert re-reads the winner's row.
    pub async fn get_or_create(&self, tenant_id: ObjectId) -> DaoResult<OverlayNetwork> {
        if let Some(net) = self.base.find_one(doc! { "tenant_id": tenant_id }).await? {
            return self.ensure_block(net).await;
        }
        let now = DateTime::now();
        let net = OverlayNetwork {
            id: None,
            tenant_id,
            cidr: OverlayNetwork::DEFAULT_CIDR.to_string(),
            // Host 0 is the network address — start handing out from 1.
            next_host: 1,
            free_hosts: Vec::new(),
            mtu: OverlayNetwork::DEFAULT_MTU,
            // New networks start permissive too — the ACL is opt-in per tenant
            // so that turning the feature on can never black-hole a live mesh.
            acl_mode: OverlayAclMode::default(),
            peer_relay_mode: Default::default(),
            server_links: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        let created = match self.base.insert_one(&net).await {
            Ok(id) => self.base.find_by_id(id).await?,
            // Lost the create race — the other writer's row is now
            // present; read it back.
            Err(DaoError::DuplicateKey(_)) => self
                .base
                .find_one(doc! { "tenant_id": tenant_id })
                .await?
                .ok_or(DaoError::NotFound)?,
            Err(e) => return Err(e),
        };
        self.ensure_block(created).await
    }

    /// P2b — give a VIRGIN network its own block out of the global registry.
    ///
    /// Idempotent and cheap: with carving off (the default) it is a pure
    /// return, and once a network's CIDR is a block the guard below short-
    /// circuits on the very next call, so the overlay join path pays at most
    /// one extra query per network — ever.
    ///
    /// The virginity guard is deliberate. A network that has already leased
    /// an address (`next_host > 1`, or anything in the free pool) must NOT be
    /// silently re-based under live nodes: changing `cidr` alone would leave
    /// every leased `overlay_ip` outside the new block, which
    /// [`overlay_host`](roomler_ai_remote_control::models::overlay_host) then
    /// refuses to invert — the fleet would keep its old addresses while the
    /// server believed they were unleased. Migrating a populated network is
    /// the renumber endpoint's job: it rewrites the node rows and cycles the
    /// sockets in the same operation.
    async fn ensure_block(&self, net: OverlayNetwork) -> DaoResult<OverlayNetwork> {
        let Some(prefix) = self.block_prefix else {
            return Ok(net);
        };
        let virgin = net.cidr == OverlayNetwork::DEFAULT_CIDR
            && net.next_host <= 1
            && net.free_hosts.is_empty();
        let Some(network_id) = net.id.filter(|_| virgin) else {
            return Ok(net);
        };

        // A block from an interrupted carve (row inserted, CIDR write lost)
        // is reused rather than leaking a second one.
        let block = match self.blocks.find_assigned_for_network(network_id).await? {
            Some(b) => b,
            None => match self
                .blocks
                .allocate(net.tenant_id, network_id, prefix, 0)
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    // Never fail the join over this: the tenant simply stays
                    // on the legacy shared range, which is exactly where it
                    // was before P2b. Loud, because a full registry needs an
                    // operator.
                    //
                    // FR-47 — the message names the CONSEQUENCE, not just the
                    // failure. Landing on the shared `/10` is not a degraded
                    // mode this tenant absorbs privately: every tenant that
                    // takes this branch is seeded at `.1`, so they hold each
                    // OTHER's addresses, and a device enrolled in two of them
                    // is refused outright. That is the exact collision class
                    // blocks exist to prevent, so an operator reading the log
                    // has to see it stated rather than inferred from "carve
                    // failed".
                    tracing::error!(
                        tenant_id = %net.tenant_id, %network_id, %e,
                        alert = "overlay_block_carve_failed",
                        "overlay blocks: carve FAILED; tenant falls back to the shared \
                         100.64.0.0/10 and will now OVERLAP every other tenant that did \
                         the same — allocate registry space or a wider prefix"
                    );
                    return Ok(net);
                }
            },
        };

        self.base
            .update_one(
                doc! { "_id": network_id },
                doc! { "$set": { "cidr": &block.cidr, "updated_at": DateTime::now() } },
            )
            .await?;
        tracing::info!(
            tenant_id = %net.tenant_id, %network_id, cidr = %block.cidr, slot = block.slot,
            "overlay blocks: carved a tenant block"
        );
        let mut net = net;
        net.cidr = block.cidr;
        Ok(net)
    }

    /// P2b — commit a renumber: re-base the network on `new_cidr` and reset
    /// the IPAM cursor to match the freshly-written node addresses.
    ///
    /// The free pool is CLEARED, not translated: its entries are ordinals of
    /// the OLD block, and the renumber has already compacted every live node
    /// into the new one, so anything below the new cursor is genuinely free
    /// and will be handed out by the cursor branch anyway.
    pub async fn apply_renumber(
        &self,
        network_id: ObjectId,
        new_cidr: &str,
        next_host: u32,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": network_id },
                doc! { "$set": {
                    "cidr": new_cidr,
                    "next_host": next_host,
                    "free_hosts": Vec::<i64>::new(),
                    "updated_at": DateTime::now(),
                }},
            )
            .await
    }

    /// Set the tenant's overlay ACL posture (`off` | `warn` | `enforce`).
    ///
    /// Creates the network row if the tenant has never joined the overlay, so
    /// an admin can stage the posture before the first node appears.
    /// Add, enable or disable the server link between agents `x` and `y`
    /// (replacing any row for the pair), or remove it (`enabled: None`).
    pub async fn set_server_link(
        &self,
        tenant_id: ObjectId,
        x: ObjectId,
        y: ObjectId,
        enabled: Option<bool>,
    ) -> DaoResult<bool> {
        let (a, b) = roomler_ai_remote_control::models::ServerLink::ordered(x, y);
        self.get_or_create(tenant_id).await?;
        self.base
            .update_one(
                doc! { "tenant_id": tenant_id },
                doc! { "$pull": { "server_links": { "a": a, "b": b } } },
            )
            .await?;
        let Some(enabled) = enabled else {
            return Ok(true);
        };
        self.base
            .update_one(
                doc! { "tenant_id": tenant_id },
                doc! {
                    "$push": { "server_links": { "a": a, "b": b, "enabled": enabled } },
                    "$set": { "updated_at": DateTime::now() },
                },
            )
            .await
    }

    pub async fn set_acl_mode(&self, tenant_id: ObjectId, mode: OverlayAclMode) -> DaoResult<bool> {
        self.get_or_create(tenant_id).await?;
        self.base
            .update_one(
                doc! { "tenant_id": tenant_id },
                doc! { "$set": {
                    "acl_mode": bson::to_bson(&mode).unwrap_or(bson::Bson::Null),
                    "updated_at": DateTime::now(),
                }},
            )
            .await
    }

    /// FR-47 P5c — claim a host ordinal, **growing the address space** rather
    /// than refusing when it is full.
    ///
    /// The ordinal space is the network's blocks concatenated in allocation
    /// order, so appending a block at the tail adds ordinals above everything
    /// already leased and moves nothing. That is what makes growth free: no
    /// device changes address, no WS is cycled, no version floor applies —
    /// none of the things that make a *renumber* disruptive.
    ///
    /// ⚠️ Only a network that already HAS a block can grow. A legacy network
    /// on the shared `/10` is deliberately excluded: appending to it would be
    /// its first registry row and would re-base its addresses, which is the
    /// renumber endpoint's job. It also cannot need this — a `/10` holds 4.19
    /// million ordinals.
    ///
    /// Returns the same `Validation` exhaustion error as
    /// [`Self::allocate_host`] when growth is impossible, so the caller's
    /// refusal path is unchanged.
    pub async fn allocate_host_or_grow(&self, net: &OverlayNetwork, prefix: u8) -> DaoResult<u32> {
        let Some(network_id) = net.id else {
            return Err(DaoError::NotFound);
        };
        let blocks = self.block_list(net).await;
        match self.allocate_host(network_id, blocks.capacity()).await {
            Ok(h) => return Ok(h),
            // Only exhaustion is worth growing for. A store fault must
            // propagate: carving a block because Mongo hiccuped would spend a
            // globally-unique range on a retryable error.
            Err(DaoError::Validation(_)) => {}
            Err(e) => return Err(e),
        }

        let assigned = self
            .blocks
            .find_assigned_for_network_ordered(network_id)
            .await?;
        if assigned.is_empty() {
            // Legacy network — see the note above. Report exhaustion as-is.
            return self.allocate_host(network_id, blocks.capacity()).await;
        }
        let seq = assigned.len() as u32;
        let block = self
            .blocks
            .allocate(net.tenant_id, network_id, prefix, seq)
            .await?;
        tracing::warn!(
            tenant_id = %net.tenant_id, %network_id, cidr = %block.cidr, seq,
            alert = "overlay_block_grown",
            "overlay blocks: address space GREW — the network filled its previous \
             block(s) and was appended a new range; no existing device changed address"
        );

        // Re-read the space WITH the new block and allocate from the extended
        // ceiling. Deliberately a fresh read rather than arithmetic on the old
        // capacity: the registry is the authority on what this network holds,
        // and a concurrent grow would make a computed ceiling wrong.
        let grown = self.block_list(net).await;
        self.allocate_host(network_id, grown.capacity()).await
    }

    /// FR-19 gate 1 — set the tenant's peer-relay posture (`off` | `warn` |
    /// `on`). Same shape as [`Self::set_acl_mode`], including creating the
    /// row, so an admin can stage the posture before the first node joins.
    pub async fn set_peer_relay_mode(
        &self,
        tenant_id: ObjectId,
        mode: PeerRelayMode,
    ) -> DaoResult<bool> {
        self.get_or_create(tenant_id).await?;
        self.base
            .update_one(
                doc! { "tenant_id": tenant_id },
                doc! { "$set": {
                    "peer_relay_mode": bson::to_bson(&mode).unwrap_or(bson::Bson::Null),
                    "updated_at": DateTime::now(),
                }},
            )
            .await
    }

    /// Claim a host number for `network_id`. Prefers a RECYCLED host from the
    /// tenant's free pool (FIFO — oldest release first, so an address gets the
    /// longest cool-down before reuse); falls back to bumping the monotonic
    /// `next_host` cursor when the pool is empty.
    ///
    /// Both branches are single atomic `find_one_and_update`s, so N concurrent
    /// joiners can never be handed the same host: MongoDB serialises updates to
    /// one document, and each racer gets its OWN pre-image — racer A sees
    /// `[7, 9]` and takes 7 while racer B sees `[9]` and takes 9.
    ///
    /// Multi-org P2a — `max_host` is the network's OWN block ceiling
    /// ([`OverlayNetwork::max_host`], computed by the caller from the row it
    /// already holds). The cursor previously grew unbounded; under
    /// tenant-block addressing (P2b) that would silently walk into the
    /// NEIGHBOR tenant's block — the exact collision class blocks exist to
    /// kill. Exhaustion is a loud [`DaoError::Validation`], never a
    /// wrapped-around or out-of-block address. A popped pool entry above the
    /// ceiling (a since-shrunk CIDR) is DISCARDED — a leak, never a
    /// conflict — and the cursor branch decides.
    pub async fn allocate_host(&self, network_id: ObjectId, max_host: u32) -> DaoResult<u32> {
        // 1) The pool. `free_hosts.0: {$exists: true}` is the "array is
        //    non-empty" test — an empty pool simply fails to match and we fall
        //    through to the cursor.
        let popped = self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": network_id, "free_hosts.0": { "$exists": true } },
                doc! {
                    "$pop": { "free_hosts": -1 },
                    "$set": { "updated_at": DateTime::now() },
                },
            )
            .return_document(ReturnDocument::Before)
            .await?;
        if let Some(before) = popped
            && let Some(host) = before.free_hosts.first().copied()
        {
            if host <= max_host {
                return Ok(host);
            }
            tracing::warn!(
                %network_id, host, max_host,
                "overlay ipam: discarding pooled host above the block ceiling \
                 (CIDR shrank since it was released)"
            );
        }

        // 2) Pool empty — bump the cursor, but ONLY while it is within the
        //    block. The bound rides the atomic filter, so N concurrent
        //    joiners racing the last host serialize correctly: exactly one
        //    gets it, the rest fail the match and land in the exhaustion arm.
        let before = self
            .base
            .collection()
            .find_one_and_update(
                doc! { "_id": network_id, "next_host": { "$lte": max_host as i64 } },
                doc! { "$inc": { "next_host": 1 }, "$set": { "updated_at": DateTime::now() } },
            )
            .return_document(ReturnDocument::Before)
            .await?;
        match before {
            Some(b) => Ok(b.next_host),
            None => {
                // Row missing vs cursor-past-ceiling: only the latter is
                // exhaustion; keep NotFound honest for a deleted network.
                if self.base.find_by_id(network_id).await.is_ok() {
                    Err(DaoError::Validation(format!(
                        "overlay network {network_id} exhausted: every host \
                         ordinal up to {max_host} is leased (grow the tenant's \
                         block or release unused devices)"
                    )))
                } else {
                    Err(DaoError::NotFound)
                }
            }
        }
    }

    /// Return a host number to the tenant's free pool so a future join can
    /// recycle it. `true` when the pool actually accepted it.
    ///
    /// `$addToSet` (not `$push`) is deliberate: a double release — an admin
    /// evicting a node at the same moment the agent DELETE fires — would
    /// otherwise seed the pool with a duplicate, hand two live nodes the same
    /// overlay IP, and trip the unique `(tenant_id, network_id, overlay_ip)`
    /// index on the second `create`, locking that device out of the overlay
    /// permanently. The caller's compare-and-swap tombstone makes that
    /// unreachable; this is the second layer.
    ///
    /// A rejected release is never an error for the caller: the host simply
    /// LEAKS out of a 4.2 M-address `/10`.
    pub async fn release_host(&self, network_id: ObjectId, host: u32) -> DaoResult<bool> {
        // Host 0 is the network address and was never issued.
        if host == 0 {
            return Ok(false);
        }
        let mut filter = doc! {
            "_id": network_id,
            // Only recycle a host the cursor actually issued. Guards against a
            // CIDR edit making the ip→host inverse meaningless.
            "next_host": { "$gt": host as i64 },
        };
        // Size cap: the element at index MAX being absent ⇒ len <= MAX.
        filter.insert(
            format!("free_hosts.{}", OverlayNetwork::MAX_FREE_HOSTS),
            doc! { "$exists": false },
        );

        // NOT via `BaseDao::update_one`: that helper builds an empty
        // `$setOnInsert` when the update carries no `$set`, which Mongo rejects.
        let res = self
            .base
            .collection()
            .update_one(
                filter,
                doc! {
                    "$addToSet": { "free_hosts": host as i64 },
                    "$set": { "updated_at": DateTime::now() },
                },
            )
            .await?;
        Ok(res.modified_count > 0)
    }
}
