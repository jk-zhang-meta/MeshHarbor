// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use std::collections::HashMap;

use bson::{DateTime, Document, doc, oid::ObjectId};
use mongodb::Database;
use roomler_ai_remote_control::models::{
    AccessPolicy, Agent, AgentCaps, AgentStatus, DesiredConfig, DisplayInfo, ExecPolicy,
    ExternalAccessPolicy, InstallInfo, OsKind, PeerRelayPolicy, RpcCap, SshPolicy,
};

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct AgentDao {
    pub base: BaseDao<Agent>,
}

/// FR-92 P7 — the slice of the agent row a heartbeat read BEFORE it wrote
/// ([`AgentDao::touch_heartbeat`]): what the device last said about keep
/// busy, and the name to denormalise into a history row.
#[derive(Debug, Clone)]
pub struct HeartbeatBefore {
    /// The previous stored brief; `None` = the device had not said (unknown,
    /// never "off").
    pub keep_busy: Option<roomler_ai_remote_control::models::KeepBusyBrief>,
    pub name: String,
    pub display_name: Option<String>,
}

impl HeartbeatBefore {
    /// The label the device list shows: the admin's friendly name, else the
    /// machine's.
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }
}

impl AgentDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, Agent::COLLECTION),
        }
    }

    /// `install` is the enroll request's claim, already clamped by the route
    /// (FR-102 P3); `None` = the request did not say, stored as `unknown` so
    /// a row this code created can be told from one that predates it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        name: String,
        machine_id: String,
        os: OsKind,
        agent_version: String,
        agent_token_hash: String,
        install: Option<InstallInfo>,
    ) -> DaoResult<Agent> {
        let agent = Self::new_row(
            tenant_id,
            owner_user_id,
            name,
            machine_id,
            os,
            agent_version,
            agent_token_hash,
            install,
        );
        let id = self.base.insert_one(&agent).await?;
        self.base.find_by_id(id).await
    }

    /// FR-51 P2 — create a device that arrived on an EPHEMERAL enrollment
    /// key: same fresh row as [`Self::create`], stamped ephemeral with the
    /// key's TTL and the key's id. There is deliberately no rehydrate
    /// counterpart — an ephemeral enrollment must never revive or take over
    /// an existing row (FR-51 F1), so its caller treats a duplicate-key
    /// refusal as final.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_ephemeral(
        &self,
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        name: String,
        machine_id: String,
        os: OsKind,
        agent_version: String,
        key_id: ObjectId,
        ttl_secs: Option<u64>,
        install: Option<InstallInfo>,
    ) -> DaoResult<Agent> {
        let mut agent = Self::new_row(
            tenant_id,
            owner_user_id,
            name,
            machine_id,
            os,
            agent_version,
            String::new(),
            install,
        );
        agent.ephemeral = true;
        agent.ephemeral_ttl_secs = ttl_secs;
        agent.enroll_key_id = Some(key_id);
        let id = self.base.insert_one(&agent).await?;
        self.base.find_by_id(id).await
    }

    /// The one place a fresh device row is shaped — both `create` paths call
    /// it, so a new `Agent` field is decided here exactly once.
    #[allow(clippy::too_many_arguments)]
    fn new_row(
        tenant_id: ObjectId,
        owner_user_id: ObjectId,
        name: String,
        machine_id: String,
        os: OsKind,
        agent_version: String,
        agent_token_hash: String,
        install: Option<InstallInfo>,
    ) -> Agent {
        let now = DateTime::now();
        Agent {
            id: None,
            tenant_id,
            owner_user_id,
            enrolled_by: Some(owner_user_id),
            name,
            display_name: None,
            tags: Vec::new(),
            name_admin_set: false,
            machine_id,
            // FR-51 — permanent unless the ENROLLMENT CREDENTIAL said
            // otherwise (`create_ephemeral` overrides these three from the
            // key; the request body must never be able to set them).
            ephemeral: false,
            ephemeral_ttl_secs: None,
            enroll_key_id: None,
            os,
            // FR-97 P0d — the hello reports it; enrolment never does.
            arch: None,
            arch_emulated: false,
            agent_version,
            // FR-27 — unknown until the device's first heartbeat, for the same
            // reason as the host key below: enrolment never reaches the machine.
            companion_version: None,
            keep_busy: None,
            // Unknown until the device's first hello — enrolment does not
            // reach the machine, so there is nothing to record yet.
            ssh_host_pubkey: String::new(),
            // FR-90 P3-3a — the same: only a running daemon holds a vault key.
            vault_key: String::new(),
            // FR-100 P1a — and the device key is made on the device, at its
            // first hello.
            peer_auth_key: String::new(),
            agent_token_hash,
            // FR-103 — a new row starts at generation 0; only a removal
            // advances it.
            token_gen: 0,
            token_exp: None,
            status: AgentStatus::Offline,
            last_seen_at: now,
            last_presence: None,
            warm_relay_endpoint: None,
            displays: Vec::new(),
            capabilities: AgentCaps::default(),
            access_policy: AccessPolicy::default(),
            // Fleet RPC off on a new device — enabling it is a deliberate
            // admin act, never a side effect of enrollment.
            exec_policy: ExecPolicy::default(),
            // FR-94 — and never anchored by enrolling: anchoring is its own
            // elevated, admin-issued act (`POST /api/agent/anchor`).
            exec_anchor: None,
            // FR-105 — published by the device's SYSTEM service, never here.
            ssh_service: None,
            // FR-104 — stamped by the enroll route once the row exists
            // (`record_enrollment`).
            enrolled_with_jti: None,
            // FR-102 P3 — the request's claim, or `unknown` when it made none.
            // Always `Some` on a row this code creates: `None` is reserved
            // for rows that predate the install trace.
            install: Some(install.unwrap_or_else(InstallInfo::unknown)),
            ssh_policy: SshPolicy::default(),
            peer_relay_policy: Default::default(),
            // FR-52 gate 2 closed, and NO connect code. A code is minted on
            // demand rather than at enrollment, so a fleet that never uses
            // this feature carries nothing for it — and until one exists the
            // device is simply unaddressable from outside the org.
            external_access_policy: Default::default(),
            connect_code: None,
            connect_code_rotated_at: None,
            // Nothing requested until an operator asks for something
            // (docs/remote-config.md). A freshly enrolled device must not
            // arrive carrying a config intent nobody wrote.
            desired_config: DesiredConfig::default(),
            // The device has never spoken, so it has said nothing. Distinct
            // from "it said nothing happened" — see `Agent::config_report`.
            config_report: None,
            key_rotation: None,
            key_rotation_report: None,
            overlay_identity: None,
            routes: Vec::new(),
            advertised_routes: Vec::new(),
            relay_home: None,
            relay_rtt: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Locate an agent by `(tenant_id, machine_id)` regardless of soft-delete
    /// state. The unique index on this pair is unconditional, so a soft-deleted
    /// row still occupies the slot — the enroll path calls this to detect that
    /// case and rehydrate via [`Self::rehydrate`] rather than failing with E11000.
    pub async fn find_by_tenant_and_machine(
        &self,
        tenant_id: ObjectId,
        machine_id: &str,
    ) -> DaoResult<Option<Agent>> {
        self.base
            .find_one(doc! {
                "tenant_id": tenant_id,
                "machine_id": machine_id,
            })
            .await
    }

    /// Refresh an existing agent row at re-enrollment time: clear `deleted_at`
    /// (in case the row was soft-deleted), update os / agent_version from the
    /// new enrollment payload, bump `updated_at`. Returns the updated row so
    /// the caller can issue a fresh agent token against it.
    ///
    /// `name` is refreshed ONLY while `name_admin_set` is unset: machine-
    /// reported names keep flowing for never-renamed devices, but a re-enroll
    /// must not silently revert an admin rename (it used to — the rename
    /// route existed while every re-enroll clobbered its effect).
    ///
    /// `install` (FR-102 P3) is refreshed only when the re-enrolling request
    /// SAID how it was installed: a re-enroll by an agent from before P3, or
    /// a `roomlerd re-enroll` (which sends nothing), must not downgrade a
    /// known method to `unknown`.
    pub async fn rehydrate(
        &self,
        agent_id: ObjectId,
        name: &str,
        os: OsKind,
        agent_version: &str,
        install: Option<&InstallInfo>,
    ) -> DaoResult<Agent> {
        let os_bson = bson::to_bson(&os).unwrap_or(bson::Bson::Null);
        let mut set = doc! {
            "os": os_bson,
            "agent_version": agent_version,
            "updated_at": DateTime::now(),
            "deleted_at": bson::Bson::Null,
        };
        if let Some(install) = install {
            set.insert(
                "install",
                bson::to_bson(install).unwrap_or(bson::Bson::Null),
            );
        }
        self.base
            .update_by_id(agent_id, doc! { "$set": set })
            .await?;
        // Second, FILTERED update for the name half — update_by_id can't
        // carry the extra predicate. Matching zero docs (admin-renamed row)
        // is the intended no-op, not an error.
        self.base
            .update_one(
                doc! { "_id": agent_id, "name_admin_set": { "$ne": true } },
                doc! { "$set": { "name": name } },
            )
            .await?;
        self.base.find_by_id(agent_id).await
    }

    /// FR-104 — record which enrollment token enrolled (or revived) this row.
    /// An `anchor: true` token may anchor exactly this device afterwards; a
    /// later enrollment with another token moves the binding to that one.
    pub async fn record_enrollment(&self, agent_id: ObjectId, jti: &str) -> DaoResult<bool> {
        self.base
            .update_by_id(agent_id, doc! { "$set": { "enrolled_with_jti": jti } })
            .await
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        params: &PaginationParams,
    ) -> DaoResult<PaginatedResult<Agent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "deleted_at": null },
                Some(doc! { "created_at": -1 }),
                params,
            )
            .await
    }

    /// Every non-tombstoned device in the tenant, unpaginated.
    ///
    /// For whole-org operations (archiving revokes them all) rather than UI
    /// lists — those want [`Self::list_for_tenant`] and its pagination.
    pub async fn list_all_active_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<Vec<Agent>> {
        self.base
            .find_many(doc! { "tenant_id": tenant_id, "deleted_at": null }, None)
            .await
    }

    /// FR-90 P2c-2b — the live devices of `tenant_id` that could hold a copy
    /// of a session `owner` runs: those whose last hello advertised
    /// `hive-replica` and that are the owner's own (`owner_user_id` AND
    /// `enrolled_by`) or among `archives`. A prefilter only: placement checks
    /// every rule again on what this returns. The array match is equality,
    /// so `hive-replicas` would not match — the `RpcCap` rule.
    pub async fn list_replica_candidates(
        &self,
        tenant_id: ObjectId,
        owner: ObjectId,
        archives: &[ObjectId],
    ) -> DaoResult<Vec<Agent>> {
        self.base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "deleted_at": null,
                    "capabilities.rpc": RpcCap::HiveReplica.wire(),
                    "$or": [
                        { "owner_user_id": owner, "enrolled_by": owner },
                        { "_id": { "$in": archives } },
                    ],
                },
                None,
            )
            .await
    }

    /// FR-88 P1a — `(tenant_id, created_at)` of every device ever enrolled
    /// in any of `tenant_ids`, tombstones included: the activation view asks
    /// whether an org enrolled a device within a window, and a device that
    /// was later removed still answers yes. (An ephemeral row is hard-deleted
    /// by its reaper and is genuinely gone — that under-count is accepted.)
    /// A projection over the raw document, not the typed row: two fields per
    /// device is all the join needs.
    pub async fn enrollments_for_tenants(
        &self,
        tenant_ids: &[ObjectId],
    ) -> DaoResult<Vec<(ObjectId, DateTime)>> {
        use futures::TryStreamExt;
        if tenant_ids.is_empty() {
            return Ok(Vec::new());
        }
        let coll = self.base.collection().clone_with_type::<Document>();
        let mut cursor = coll
            .find(doc! { "tenant_id": { "$in": tenant_ids } })
            .projection(doc! { "_id": 0, "tenant_id": 1, "created_at": 1 })
            .await?;
        let mut out = Vec::new();
        while let Some(d) = cursor.try_next().await? {
            if let (Ok(tid), Ok(at)) = (d.get_object_id("tenant_id"), d.get_datetime("created_at"))
            {
                out.push((tid, *at));
            }
        }
        Ok(out)
    }

    /// S5 — active (non-tombstoned) devices in the tenant, for the plan
    /// device-cap check at enrollment.
    pub async fn count_active_for_tenant(&self, tenant_id: ObjectId) -> DaoResult<u64> {
        self.base
            .count(doc! { "tenant_id": tenant_id, "deleted_at": null })
            .await
    }

    /// The per-device lookup every per-agent route, write and session start
    /// wants: this id, this tenant, and LIVE. A removed device is `NotFound`
    /// here exactly as it is absent from [`Self::list_for_tenant`] — the two
    /// disagreeing was #1821: `GET …/agent/{id}` answered 200 with the whole
    /// tombstone, and every per-device write (config, policies, owner
    /// settings) landed on it, so a stale page could keep editing a device
    /// that no longer existed.
    ///
    /// There is deliberately no un-suffixed `find_in_tenant` any more: a
    /// caller chooses LIVE or [`Self::find_any_in_tenant`] by name, and the
    /// compiler asks the question of every future call site too.
    pub async fn find_live_in_tenant(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> DaoResult<Agent> {
        self.base
            .find_live_by_id_in_tenant(tenant_id, agent_id)
            .await
    }

    /// The per-device lookup that also returns a TOMBSTONE — for the readers
    /// whose job is the tombstone, and nothing else:
    ///
    /// * the revocation checks (`auth_agent`, the agent WS upgrade, DERP) read
    ///   `deleted_at` to tell a device *why* it is refused. The WS one sends
    ///   the typed `rc:goodbye AgentDeleted` the daemon exits 7 on — a plain
    ///   `NotFound` there would drop the socket and leave the device
    ///   reconnecting forever against what reads as a network fault;
    /// * an audit view of a removed device's history, where "removed" must
    ///   not mean "unauditable".
    ///
    /// Never for a write, never for a session start, never for a GET of the
    /// device itself — those are [`Self::find_live_in_tenant`].
    pub async fn find_any_in_tenant(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> DaoResult<Agent> {
        self.base.find_by_id_in_tenant(tenant_id, agent_id).await
    }

    /// The filter every ADMIN-driven setter below writes through: this row,
    /// in this tenant, and LIVE (#1821). The routes look the device up live
    /// first; this closes the window between that read and the write, and
    /// holds for a caller that never did the read ("a gate applies at every
    /// entry point, or it is a courtesy"). A tombstone matches nothing, so the
    /// setter reports `false` and the removal time it carries stays as it was.
    ///
    /// The DEVICE-written fields (`record_config_report`, the key-rotation
    /// report, the overlay identity) deliberately keep the plain
    /// `{_id, tenant_id}` filter: their writer was already gated by
    /// `auth_agent`, and a report that races the removal is still what the
    /// host said — it is the server's own audit rows that settle a dispute.
    fn live_row(tenant_id: ObjectId, agent_id: ObjectId) -> Document {
        doc! { "_id": agent_id, "tenant_id": tenant_id, "deleted_at": null }
    }

    /// FR-43 P2c — refresh only the capability blob, mid-connection.
    ///
    /// Caps otherwise arrive once, in `rc:agent.hello`, which is too early for
    /// a macOS daemon: it must say hello immediately (being reachable before
    /// anyone logs in is the whole reason its half exists), while the GUI
    /// worker whose `permissions` it reports attaches later — or never, when
    /// nobody is logged in.
    ///
    /// ⚠️ Deliberately narrower than [`Self::update_hello`]: it touches
    /// `capabilities` and nothing else. A heartbeat is not a hello, and letting
    /// it rewrite `agent_version` / `displays` / `ssh_host_pubkey` would let a
    /// frequent message quietly restate things only a reconnect should.
    pub async fn update_capabilities(
        &self,
        agent_id: ObjectId,
        capabilities: &AgentCaps,
    ) -> DaoResult<bool> {
        let caps_bson = bson::to_bson(capabilities).unwrap_or(bson::Bson::Null);
        self.base
            .update_by_id(agent_id, doc! { "$set": { "capabilities": caps_bson } })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_hello(
        &self,
        agent_id: ObjectId,
        agent_version: &str,
        displays: &[DisplayInfo],
        capabilities: &AgentCaps,
        advertised_routes: &[String],
        ssh_host_pubkey: &str,
        vault_key: &str,
        peer_auth_key: &str,
        arch: &str,
        arch_emulated: bool,
        conn_id: &str,
    ) -> DaoResult<bool> {
        let displays_bson = bson::to_bson(displays).unwrap_or(bson::Bson::Array(vec![]));
        let caps_bson = bson::to_bson(capabilities).unwrap_or(bson::Bson::Null);
        let advertised_bson = bson::to_bson(advertised_routes).unwrap_or(bson::Bson::Array(vec![]));
        // Written on EVERY hello, including when empty. A device that
        // switched SSH off, or downgraded to a build without it, must stop
        // advertising a key it no longer holds — leaving the old value would
        // have clients verifying against an identity that is gone.
        let mut set = doc! {
            "agent_version": agent_version,
            "displays": displays_bson,
            "capabilities": caps_bson,
            "advertised_routes": advertised_bson,
            "ssh_host_pubkey": ssh_host_pubkey,
            // FR-90 P3-3a — on every hello too, and for a stronger reason:
            // the daemon makes a new vault key at each start, so a key left
            // standing would name a process that is gone.
            "vault_key": vault_key,
            // FR-100 P1a — on every hello, the empty string included, for
            // the host key's reason: a rollback to a build without a device
            // key must not leave browsers expecting its signature.
            "peer_auth_key": peer_auth_key,
            "status": bson::to_bson(&AgentStatus::Online).unwrap(),
            "last_seen_at": DateTime::now(),
            // #2552 — the connection that wrote this hello: its teardown
            // writes `Offline` only while the row still names it
            // ([`Self::mark_offline_if_conn`]).
            "conn_id": conn_id,
        };
        // FR-97 P0d — the hardware does not change, so only a hello that
        // reports it writes it: a rollback to an agent predating the field
        // keeps the last value instead of erasing it.
        if !arch.is_empty() {
            set.insert("arch", arch);
            set.insert("arch_emulated", arch_emulated);
        }
        self.base.update_by_id(agent_id, doc! { "$set": set }).await
    }

    /// #2552 — a connection's teardown: `Offline`, but only while the row
    /// still names `conn_id`, the connection that wrote its hello. A newer
    /// hello (a fast reconnect, on this pod or another) has written its own
    /// `conn_id`, so this late write matches nothing and the row stays
    /// `Online`, in whichever order the two writes land. Answers whether it
    /// wrote.
    ///
    /// ⚠️ A row this connection's hello never reached (that write is best
    /// effort) names some other `conn_id`, or none, and is left as it is:
    /// the presence sweep heals it from the heartbeat, as it heals the row a
    /// hard-killed pod leaves `Online`.
    pub async fn mark_offline_if_conn(&self, agent_id: ObjectId, conn_id: &str) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": agent_id, "conn_id": conn_id },
                doc! {
                    "$set": {
                        "status": bson::to_bson(&AgentStatus::Offline).unwrap(),
                        "last_seen_at": DateTime::now(),
                    }
                },
            )
            .await
    }

    pub async fn mark_status(&self, agent_id: ObjectId, status: AgentStatus) -> DaoResult<bool> {
        self.base
            .update_by_id(
                agent_id,
                doc! {
                    "$set": {
                        "status": bson::to_bson(&status).unwrap(),
                        "last_seen_at": DateTime::now(),
                    }
                },
            )
            .await
    }

    /// Refresh `last_seen_at` from a periodic agent heartbeat. Hello +
    /// mark_status touch the same field, but they only fire at session
    /// boundaries (connect / disconnect); without this method a long-
    /// lived but quiet agent stays at "last_seen = hello time" forever.
    /// 30 s heartbeat cadence on the agent keeps the field fresh enough
    /// that "agent online" can be defined as `last_seen_at > now - 90 s`.
    ///
    /// Phase A-1: also re-asserts `status: Online`. A heartbeat only
    /// arrives over a live registered WS, so Online is definitionally
    /// true — and this bounds any status-clobber race (a displaced
    /// handler's or a late reaper's wrongful `Offline`) to ≤30 s.
    ///
    /// FR-92 P7: ONE `find_one_and_update` that hands back the row as it was
    /// BEFORE this beat ([`HeartbeatBefore`]), so the caller can derive a
    /// keep-busy edge from the previous brief against the new one with no
    /// second round trip. `None` = no row matched (the device was removed
    /// while its socket was still up).
    pub async fn touch_heartbeat(
        &self,
        agent_id: ObjectId,
        warm_relay: Option<&str>,
        companion_version: Option<&str>,
        keep_busy: Option<&roomler_ai_remote_control::models::KeepBusyBrief>,
    ) -> DaoResult<Option<HeartbeatBefore>> {
        // C4 stage 2 — the standing warm allocation's relayed address rides
        // the same per-heartbeat write: stored pair-less so a peer can be
        // handed a dial target for this agent without waking its (possibly
        // captured) control WS; `$unset` while no leg is live so a stale
        // address can never be served.
        let mut set = doc! {
            "last_seen_at": DateTime::now(),
            "status": bson::to_bson(&AgentStatus::Online).unwrap(),
        };
        let mut unset = Document::new();
        match warm_relay {
            Some(ep) => {
                set.insert("warm_relay_endpoint", ep);
            }
            None => {
                unset.insert("warm_relay_endpoint", "");
            }
        }
        // FR-27 — the companion version follows the same present/absent rule
        // as the warm leg, and for the same reason: a stale value is worse
        // than none. An agent that stops finding a companion (uninstalled, or
        // a probe that started failing) must clear the field rather than leave
        // the grid asserting a version that is no longer on the host.
        //
        // ⚠️ A PRE-FR-27 agent sends no field at all, which arrives here as
        // `None` and therefore `$unset` — correct, because such an agent also
        // never set it, so there is nothing to erase.
        match companion_version {
            Some(v) => {
                set.insert("companion_version", v);
            }
            None => {
                unset.insert("companion_version", "");
            }
        }
        // FR-92 P5b — keep busy, by the same present/absent rule: a device
        // that stops saying (an older build after a rollback, a supervised
        // Mac's daemon) must read as unknown, not as the last thing it said.
        match keep_busy.and_then(|b| bson::to_bson(b).ok()) {
            Some(b) => {
                set.insert("keep_busy", b);
            }
            None => {
                unset.insert("keep_busy", "");
            }
        }
        // `update_one` would stamp this; a raw find-and-update must itself.
        set.insert("updated_at", DateTime::now());
        let update = if unset.is_empty() {
            doc! { "$set": set }
        } else {
            doc! { "$set": set, "$unset": unset }
        };
        // Projected, so it is read as a plain document: an `Agent` cannot
        // deserialise from three fields.
        let before = self
            .base
            .collection()
            .clone_with_type::<Document>()
            .find_one_and_update(doc! { "_id": agent_id }, update)
            .projection(doc! { "keep_busy": 1, "name": 1, "display_name": 1 })
            .return_document(mongodb::options::ReturnDocument::Before)
            .await?;
        Ok(before.map(|d| HeartbeatBefore {
            // An unreadable stored brief reads as "the device did not say",
            // the same as an absent one: unknown, never off.
            keep_busy: d
                .get_document("keep_busy")
                .ok()
                .and_then(|b| bson::from_document(b.clone()).ok()),
            name: d.get_str("name").unwrap_or_default().to_string(),
            display_name: d.get_str("display_name").ok().map(str::to_string),
        }))
    }

    /// Multi-region relay PoPs: persist the agent's derived `relay_home` and
    /// its full probe table (observability). Called from the WS probe-report
    /// handler, already hysteresis- and rate-limited there.
    pub async fn set_relay_home(
        &self,
        agent_id: ObjectId,
        relay_home: Option<&str>,
        relay_rtt: &[roomler_ai_remote_control::signaling::RelayRegionRtt],
    ) -> DaoResult<bool> {
        let rtt_bson = bson::to_bson(relay_rtt).unwrap_or(bson::Bson::Array(vec![]));
        self.base
            .update_by_id(
                agent_id,
                doc! { "$set": {
                    "relay_home": relay_home,
                    "relay_rtt": rtt_bson,
                    "updated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// Phase A-1 graceful shutdown: bulk-offline the agents whose WSs
    /// this pod held (belt-and-braces behind the per-socket teardowns).
    pub async fn mark_status_many(&self, ids: &[ObjectId], status: AgentStatus) -> DaoResult<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        self.base
            .update_many(
                doc! { "_id": { "$in": ids.to_vec() } },
                doc! { "$set": {
                    "status": bson::to_bson(&status).unwrap(),
                    "last_seen_at": DateTime::now(),
                } },
            )
            .await
    }

    /// P4 — CAS on the `last_presence` broadcast ledger. Returns `true` iff
    /// THIS caller moved the field (i.e. it should fan the `device:presence`
    /// transition out); a concurrent path on any pod that already recorded
    /// the same value loses the race and stays silent. Tombstoned rows never
    /// match — a deleted device must not resurrect as a badge event.
    pub async fn set_presence_if_changed(
        &self,
        agent_id: ObjectId,
        presence: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "_id": agent_id,
                    "deleted_at": null,
                    "last_presence": { "$ne": presence },
                },
                doc! { "$set": { "last_presence": presence } },
            )
            .await
    }

    /// P4 — the presence sweeper's scan set: every non-tombstoned row whose
    /// Mongo status still claims Online OR whose last BROADCAST presence was
    /// online/stale. The second arm is what catches a pod that died without
    /// teardown (its shutdown belt may have flipped `status` while the
    /// ledger still says "online" — the offline event is still owed).
    pub async fn find_presence_scan_set(&self) -> DaoResult<Vec<Agent>> {
        self.base
            .find_many(
                doc! {
                    "deleted_at": null,
                    "$or": [
                        { "status": bson::to_bson(&AgentStatus::Online).unwrap() },
                        { "last_presence": { "$in": ["online", "stale"] } },
                    ],
                },
                None,
            )
            .await
    }

    /// P9 — batched heartbeat freshness for the overlay netmap's presence
    /// check: which of `ids` heartbeated within `within_ms`? One `$in` query;
    /// ids missing from the result read STALE (an orphaned overlay row must
    /// not look dialable).
    pub async fn last_seen_fresh(
        &self,
        ids: &[ObjectId],
        within_ms: i64,
    ) -> DaoResult<HashMap<ObjectId, bool>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let cutoff = DateTime::from_millis(DateTime::now().timestamp_millis() - within_ms);
        let rows = self
            .base
            .find_many(doc! { "_id": { "$in": ids.to_vec() } }, None)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|a| a.id.map(|id| (id, a.last_seen_at > cutoff)))
            .collect())
    }

    pub async fn update_access_policy(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        policy: &AccessPolicy,
    ) -> DaoResult<bool> {
        let policy_bson = bson::to_bson(policy).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "access_policy": policy_bson } },
            )
            .await
    }

    /// Replace the device's Fleet-RPC policy (gate 3). A `MANAGE_AGENTS`
    /// admin action, deliberately separate from `update_access_policy`:
    /// "may watch your screen" and "may run a root shell" must never be
    /// reachable through the same call.
    pub async fn update_exec_policy(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        policy: &ExecPolicy,
    ) -> DaoResult<bool> {
        let policy_bson = bson::to_bson(policy).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "exec_policy": policy_bson } },
            )
            .await
    }

    /// Replace the device's roomler-SSH policy (gate 3). A `MANAGE_AGENTS`
    /// admin action, exactly like [`Self::update_exec_policy`] — and kept
    /// separate from it so enabling one can never be a side effect of
    /// enabling the other.
    pub async fn update_ssh_policy(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        policy: &SshPolicy,
    ) -> DaoResult<bool> {
        let policy_bson = bson::to_bson(policy).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "ssh_policy": policy_bson } },
            )
            .await
    }

    /// FR-19 gate 3 — replace the device's org-relay approval. A
    /// `MANAGE_AGENTS` + `EXEC_DEVICE` admin action (`routes::peer_relay`),
    /// kept separate from the exec/SSH setters for the reason they are
    /// separate from each other: approving one power must never be a side
    /// effect of approving another.
    pub async fn update_peer_relay_policy(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        policy: &PeerRelayPolicy,
    ) -> DaoResult<bool> {
        let policy_bson = bson::to_bson(policy)?;
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "peer_relay_policy": policy_bson } },
            )
            .await
    }

    /// Apply a signed single-use enrollment's explicit relay approval without
    /// replacing any other policy fields. Generation + live-row predicates
    /// prevent approving a removed/revived device from a stale enrollment read.
    /// A matching already-approved row is success too (matched, not modified).
    pub async fn grant_relay_server(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        token_gen: u32,
    ) -> DaoResult<bool> {
        let mut filter = Self::live_row(tenant_id, agent_id);
        if token_gen == 0 {
            // Older rows omit generation and deserialize as zero.
            filter.insert(
                "$or",
                bson::bson!([
                    { "token_gen": 0 }, { "token_gen": { "$exists": false } }
                ]),
            );
        } else {
            filter.insert("token_gen", i64::from(token_gen));
        }
        let result = self
            .base
            .collection()
            .update_one(
                filter,
                doc! { "$set": {
                    "peer_relay_policy.serve": true,
                    "updated_at": DateTime::now(),
                } },
            )
            .await?;
        Ok(result.matched_count == 1)
    }

    /// Every live device the tenant has approved to serve as an org relay.
    /// Gate 3 only: whether it is also SERVING is gate 4, read off its
    /// advertised `relay-server` capability, and whether it is online is the
    /// presence path's answer — neither is this row's to give.
    pub async fn list_relay_approved(&self, tenant_id: ObjectId) -> DaoResult<Vec<Agent>> {
        self.base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "deleted_at": null,
                    "peer_relay_policy.serve": true,
                },
                Some(doc! { "name": 1 }),
            )
            .await
    }

    /// FR-52 gate 2 — replace the device's cross-org access approval. A
    /// `MANAGE_AGENTS` + `REMOTE_CONTROL` admin action
    /// (`routes::external_access`), kept separate from the exec / SSH /
    /// peer-relay setters for the same reason those are separate from each
    /// other: approving one power must never be a side effect of approving
    /// another, and this one admits a stranger.
    pub async fn update_external_access_policy(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        policy: &ExternalAccessPolicy,
    ) -> DaoResult<bool> {
        let policy_bson = bson::to_bson(policy).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                doc! { "_id": agent_id, "tenant_id": tenant_id },
                doc! { "$set": { "external_access_policy": policy_bson } },
            )
            .await
    }

    /// FR-52 — mint or rotate the device's connect code.
    ///
    /// Rotation IS the revocation story for a leaked code, so the previous
    /// value is overwritten rather than kept: a code that still resolved after
    /// being rotated away would make rotation cosmetic.
    ///
    /// ⚠️ The unique index on `connect_code` is global and covers tombstones,
    /// so a collision here is a genuine (astronomically unlikely) 60-bit
    /// birthday hit, not a soft-deleted row in the way. The caller retries;
    /// see `routes::external_access::rotate_connect_code`.
    pub async fn set_connect_code(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        code: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! { "_id": agent_id, "tenant_id": tenant_id },
                doc! { "$set": {
                    "connect_code": code,
                    "connect_code_rotated_at": DateTime::now(),
                } },
            )
            .await
    }

    /// FR-52 — resolve a canonical connect code to its device.
    ///
    /// ⚠️ **Live rows only.** The unique index deliberately covers tombstones
    /// so a code can never be recycled onto a different machine, but a removed
    /// device must not answer: `deleted_at: null` here is what makes removal
    /// final for external callers too, exactly as
    /// `find_live_by_tenant_and_machine` does for re-enrollment.
    ///
    /// ⚠️ Not tenant-scoped, because a stranger types a code with no org
    /// context. That is safe only because the code is not the authorization —
    /// every gate is still evaluated against the row this returns.
    pub async fn find_by_connect_code(&self, code: &str) -> DaoResult<Option<Agent>> {
        self.base
            .find_one(doc! { "connect_code": code, "deleted_at": null })
            .await
    }

    /// Every live device the tenant has approved for cross-org access. Gate 2
    /// only: whether the device itself opted in is gate 3 and lives on the
    /// host, and whether a password is set is gate 4 — neither is this row's
    /// to answer.
    pub async fn list_external_approved(&self, tenant_id: ObjectId) -> DaoResult<Vec<Agent>> {
        self.base
            .find_many(
                doc! {
                    "tenant_id": tenant_id,
                    "deleted_at": null,
                    "external_access_policy.approved": true,
                },
                Some(doc! { "name": 1 }),
            )
            .await
    }

    /// Record the DEVICE's own report on a pushed desired-config
    /// (`docs/remote-config.md`).
    ///
    /// ⚠️ Unlike every other setter on this type, the writer here is the
    /// DEVICE, not an admin — so this must never grow into a general "let the
    /// agent patch its own row" primitive. It writes one field, whose whole
    /// meaning is "this is what the host claims"; `config_audit` holds the
    /// server's own record of what was asked for, and that is the side a
    /// dispute is settled on.
    ///
    /// Last-report-wins: the question this answers is "did the current
    /// revision land?", which is about now, not about history.
    pub async fn record_config_report(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        report: &roomler_ai_remote_control::models::ConfigReport,
    ) -> DaoResult<bool> {
        let report_bson = bson::to_bson(report).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                doc! { "_id": agent_id, "tenant_id": tenant_id },
                doc! { "$set": { "config_report": report_bson } },
            )
            .await
    }

    /// FR-40 — record an operator's standing rotation order on the row (the
    /// desired state the connect-time reconcile reads). Replaces any earlier
    /// order: a rotation is idempotent in intent, and the report is matched by
    /// `request_id`, so an answer to the superseded order cannot be mistaken
    /// for an answer to this one.
    pub async fn record_key_rotation_request(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        request: &roomler_ai_remote_control::models::KeyRotationRequest,
    ) -> DaoResult<bool> {
        let bson = bson::to_bson(request).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "key_rotation": bson } },
            )
            .await
    }

    /// FR-40 — stamp the moment an order reached a live socket. Guarded on
    /// the `request_id` so a late delivery of a superseded order cannot mark
    /// the current one as delivered.
    pub async fn mark_key_rotation_delivered(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        request_id: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                doc! {
                    "_id": agent_id,
                    "tenant_id": tenant_id,
                    "key_rotation.request_id": request_id,
                },
                doc! { "$set": { "key_rotation.delivered_at": bson::DateTime::now() } },
            )
            .await
    }

    /// FR-40 — the DEVICE's answer (same discipline as
    /// [`Self::record_config_report`]: one field, written by the device,
    /// meaning "this is what the host claims"; `key_rotation_audit` holds the
    /// server's own record of what was ordered).
    pub async fn record_key_rotation_report(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        report: &roomler_ai_remote_control::models::KeyRotationReport,
    ) -> DaoResult<bool> {
        use roomler_ai_remote_control::models::KeyRotationOutcome;

        let bson = bson::to_bson(report).unwrap_or(bson::Bson::Null);
        // P1b — a rotation that happened, happened. A LATER refusal for the
        // SAME order (the duplicate-delivery race: the reconnect re-received
        // the order and the device refused it under its own ceiling) must
        // not overwrite the device's `rotated`. Any report about a different
        // order, and any `rotated`, still replaces. Returns `false` when the
        // write was withheld.
        let filter = if report.outcome == KeyRotationOutcome::Rotated {
            doc! { "_id": agent_id, "tenant_id": tenant_id }
        } else {
            doc! {
                "_id": agent_id,
                "tenant_id": tenant_id,
                "$nor": [ {
                    "key_rotation_report.request_id": &report.request_id,
                    "key_rotation_report.outcome": "rotated",
                } ],
            }
        };
        self.base
            .update_one(filter, doc! { "$set": { "key_rotation_report": bson } })
            .await
    }

    /// FR-40 — what the device presented at its overlay join, as `ws::overlay`
    /// verified it. Stamped on EVERY join (not only after a rotation), so the
    /// row always carries the device's current overlay public key.
    pub async fn record_overlay_identity(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        identity: &roomler_ai_remote_control::models::OverlayIdentity,
    ) -> DaoResult<bool> {
        let bson = bson::to_bson(identity).unwrap_or(bson::Bson::Null);
        self.base
            .update_one(
                doc! { "_id": agent_id, "tenant_id": tenant_id },
                doc! { "$set": { "overlay_identity": bson } },
            )
            .await
    }

    /// Replace the agent's advertised subnet-router CIDRs (mesh Phase 2). A
    /// `MANAGE_AGENTS` admin action. Callers pass already validated +
    /// canonicalized CIDR strings (see `normalize_routes` in the agent route
    /// handler); the mesh client longest-prefix-matches a LAN target IP
    /// against these to pick the covering agent. Still gated server-side by
    /// the tenant's `tunnel_policies` — routes only steer the dial, they
    /// don't authorize it.
    pub async fn update_routes(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        routes: &[String],
    ) -> DaoResult<bool> {
        let routes_bson = bson::to_bson(routes).unwrap_or(bson::Bson::Array(vec![]));
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "routes": routes_bson } },
            )
            .await
    }

    pub async fn rename(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        name: &str,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                // The flag is what stops the next re-enroll's `rehydrate`
                // from clobbering this rename with the machine-reported name.
                doc! { "$set": { "name": name, "name_admin_set": true } },
            )
            .await
    }

    /// Set/clear the friendly display label. Display-only — never propagates
    /// to the overlay/MagicDNS name.
    pub async fn set_display_name(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        display_name: Option<&str>,
    ) -> DaoResult<bool> {
        let update = match display_name {
            Some(v) => doc! { "$set": { "display_name": v } },
            None => doc! { "$unset": { "display_name": "" } },
        };
        self.base
            .update_one(Self::live_row(tenant_id, agent_id), update)
            .await
    }

    /// Replace the device's whole tag list (the UI edits it as a set).
    pub async fn set_tags(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        tags: &[String],
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "tags": tags.to_vec() } },
            )
            .await
    }

    /// FR-105 — record what this device's SYSTEM service published about its
    /// SSH endpoint. Written only while the row is LIVE and still carries the
    /// anchor the publishing credential named, so a publish racing a
    /// re-anchor, an un-anchor or a removal writes nothing (`false`).
    pub async fn publish_ssh_service(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        endpoint: &roomler_ai_remote_control::models::SshServiceEndpoint,
    ) -> DaoResult<bool> {
        let mut filter = Self::live_row(tenant_id, agent_id);
        filter.insert("exec_anchor.anchor_id", endpoint.anchor_id.as_str());
        let endpoint = bson::to_bson(endpoint)?;
        self.base
            .update_one(filter, doc! { "$set": { "ssh_service": endpoint } })
            .await
    }

    /// Tombstone a LIVE row. `deleted_at` is the removal time and is written
    /// once: a repeat on a tombstone matches nothing and reports `false`
    /// rather than re-stamping it. The route 404s a repeat `DELETE` before
    /// reaching here (#1821); this keeps the removal hooks' and the archive
    /// sweep's calls to the same answer.
    ///
    /// #2133: a removal also ENDS the device's FR-94 exec anchor, in the same
    /// update. Enrolling the same machine again revives this row in place
    /// ([`Self::rehydrate`]), and an anchor left here would revive with it.
    /// The service credential still on the machine's disk would then be
    /// accepted again, with no elevated step. Removing a device must do at
    /// least what un-anchoring it does.
    ///
    /// FR-103: the same update advances `token_gen`, so every agent token
    /// minted before the removal is refused from now on, including after a
    /// revival: re-enrollment mints at the new generation. `rehydrate`
    /// touches neither field, because re-enrolling a LIVE device keeps both.
    pub async fn soft_delete(&self, tenant_id: ObjectId, agent_id: ObjectId) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! {
                    "$set": { "deleted_at": DateTime::now() },
                    "$unset": { "exec_anchor": "" },
                    "$inc": { "token_gen": 1 },
                },
            )
            .await
    }

    /// FR-103: record the `exp` (unix seconds) of the token a device just
    /// connected with, for the device list's "credential expires". Best-effort
    /// by design: the caller logs a failure and carries on.
    pub async fn stamp_token_exp(&self, agent_id: ObjectId, exp_unix: i64) -> DaoResult<bool> {
        self.base
            .update_by_id(
                agent_id,
                doc! { "$set": { "token_exp": DateTime::from_millis(exp_unix.saturating_mul(1000)) } },
            )
            .await
    }

    /// FR-51 — remove an EPHEMERAL row outright. The `(tenant_id, machine_id)`
    /// unique index is not partial on `deleted_at`, so a tombstoned ephemeral
    /// row would reserve its random, never-reused machine_id forever — every
    /// reaped CI run would permanently burn an index entry. Guarded on
    /// `ephemeral: true` in the filter so this can never hard-delete a
    /// permanent device, whatever the caller believed about the row.
    pub async fn hard_delete_ephemeral(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
    ) -> DaoResult<bool> {
        let n = self
            .base
            .hard_delete(doc! {
                "_id": agent_id,
                "tenant_id": tenant_id,
                "ephemeral": true,
            })
            .await?;
        Ok(n > 0)
    }

    /// FR-51 — rows the reaper should LOOK AT: live, ephemeral, and silent for
    /// at least the floor TTL. Deliberately its own query, never the presence
    /// sweep's scan set — `run_presence_sweep` settles an absent row to
    /// `last_presence: "offline"`, after which it matches neither branch of
    /// `find_presence_scan_set` and is never scanned again, so a reaper hung
    /// off that loop would see each row exactly once and any deadline longer
    /// than one sweep interval would silently never fire.
    ///
    /// This is only the CANDIDATE set (pre-filtered by the 60 s floor so the
    /// fetch stays tiny); the reaper re-checks each row against its own
    /// effective TTL and against live presence before removing anything.
    pub async fn find_ephemeral_reap_candidates(
        &self,
        min_silence_ms: i64,
    ) -> DaoResult<Vec<Agent>> {
        let cutoff = DateTime::from_millis(DateTime::now().timestamp_millis() - min_silence_ms);
        self.base
            .find_many(
                doc! {
                    "ephemeral": true,
                    "deleted_at": null,
                    "last_seen_at": { "$lt": cutoff },
                },
                None,
            )
            .await
    }

    /// FR-51 — stamp a row ephemeral (with an optional per-device TTL
    /// override). P2's enrollment path sets this at CREATE time from the
    /// enrollment key; this setter exists for the reaper's tests and for
    /// backfilling a row minted before its key's flag was honoured. There is
    /// deliberately no inverse: a device never becomes permanent again — the
    /// two directions must not be crossable after the fact.
    pub async fn set_ephemeral(
        &self,
        agent_id: ObjectId,
        ttl_secs: Option<u64>,
    ) -> DaoResult<bool> {
        let ttl_bson = match ttl_secs {
            Some(t) => bson::Bson::Int64(t as i64),
            None => bson::Bson::Null,
        };
        self.base
            .update_by_id(
                agent_id,
                doc! { "$set": { "ephemeral": true, "ephemeral_ttl_secs": ttl_bson } },
            )
            .await
    }

    /// Reassign the device owner (a `MANAGE_AGENTS` admin action). Leaves
    /// `enrolled_by` untouched — that's the audit trail of who first enrolled it.
    pub async fn update_owner(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        owner_user_id: ObjectId,
    ) -> DaoResult<bool> {
        self.base
            .update_one(
                Self::live_row(tenant_id, agent_id),
                doc! { "$set": { "owner_user_id": owner_user_id } },
            )
            .await
    }
}
