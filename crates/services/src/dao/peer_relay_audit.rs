// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-19 peer-relay decision log (`peer_relay_audit`).
//!
//! Two decisions land here, both arms of each: an admin's APPROVAL of a device
//! as an org relay (`routes::peer_relay::set_policy`) and the server's MINT of
//! a relay session between two nodes (`ws::overlay`, P3c). The refused rows
//! are the point — an admin probing which devices they can turn into a
//! chokepoint, or a node probing which peers it can reach through one, must
//! leave a trace.
//!
//! ⚠️ A mint row records the DECISION, never the session: the server pushes a
//! session to three devices and its involvement ends there. Bytes relayed are
//! the relay device's own account of itself (`NodeStatus`) — a claim — and are
//! deliberately not folded in here, the same split as `ssh_audit` /
//! `ssh_activity`.
//!
//! ⚠️ With `peer_relay_mode = off` NOTHING is written: the acceptance
//! criterion is zero rows, so the mint checks the mode before it audits.
//!
//! Writes are best-effort and must never gate the request; the caller logs a
//! failed insert and proceeds. Rows TTL out after 90 days
//! (`crates/db/src/indexes.rs`), matching the other decision logs.

use bson::{doc, oid::ObjectId};
use meshharbor_remote_control::models::PeerRelayAuditEvent;
use mongodb::Database;

use super::base::{BaseDao, DaoResult, PaginatedResult, PaginationParams};

pub struct PeerRelayAuditDao {
    pub base: BaseDao<PeerRelayAuditEvent>,
}

impl PeerRelayAuditDao {
    pub fn new(db: &Database) -> Self {
        Self {
            base: BaseDao::new(db, PeerRelayAuditEvent::COLLECTION),
        }
    }

    /// Record one decision, granted or refused. The event carries its own
    /// `denied`, so both arms come through here and a new refusal cannot
    /// forget to audit itself.
    pub async fn record(&self, event: PeerRelayAuditEvent) -> DaoResult<ObjectId> {
        self.base.insert_one(&event).await
    }

    /// Org-wide, newest first.
    pub async fn list_for_tenant(
        &self,
        tenant_id: ObjectId,
        pagination: &PaginationParams,
    ) -> DaoResult<PaginatedResult<PeerRelayAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id },
                Some(doc! { "at": -1 }),
                pagination,
            )
            .await
    }

    /// "Who made this device a relay, and what has been routed through it?"
    /// — newest first. One query because `agent_id` names the device on both
    /// action kinds.
    pub async fn list_for_agent(
        &self,
        tenant_id: ObjectId,
        agent_id: ObjectId,
        pagination: &PaginationParams,
    ) -> DaoResult<PaginatedResult<PeerRelayAuditEvent>> {
        self.base
            .find_paginated(
                doc! { "tenant_id": tenant_id, "agent_id": agent_id },
                Some(doc! { "at": -1 }),
                pagination,
            )
            .await
    }
}
