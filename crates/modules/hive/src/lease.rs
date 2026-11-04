// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2e-2 — the lease word: the server's `rc:hive.lease`, telling a
//! device on one connection that it holds a session at a fence.
//!
//! A leased session runs on a device, and calls the model there, after a
//! restart or a reconnect only once the server has said so on THAT connection
//! (spec §3b): a reconnect clears the device's offline clock at once, and a
//! restart resumes what it hosted before the server has said anything, so a
//! primary that was demoted while it could not hear would otherwise run until
//! the demote landed. The start is the word for its own connection; after
//! that, every connection's manifest is answered with one for each leased
//! session the record holds there ([`crate::agent_socket`]).
//!
//! | Who is leased | Why |
//! |---|---|
//! | a session whose record names a member besides its primary (`replica::replicated`), whatever the replicaset's switch says now | a member is what a promotion moves a session to; a session alone keeps P1's behaviour |
//! | on a connection advertising `hive-lease` only | a build before P2e-2 never waits for the word, and drops a frame it cannot read |

use bson::oid::ObjectId;
use meshharbor_remote_control::signaling::ServerMsg;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::HiveState;

/// The word on `conn`, the connection whose manifest it answers, and on no
/// other: `false` when that connection is gone or displaced, or does not
/// advertise `hive-lease`.
pub(crate) fn push_on(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    conn: &mpsc::Sender<ServerMsg>,
    session_id: ObjectId,
    fence: u64,
) -> bool {
    let msg = ServerMsg::HiveLease { session_id, fence };
    match state
        .fleet
        .rc_hub
        .push_hive_lease_on(device_id, tenant_id, conn, msg)
    {
        Ok(()) => {
            info!(session = %session_id, device = %device_id, fence, "hive: lease word sent");
            true
        }
        Err(e) => {
            debug!(session = %session_id, device = %device_id, %e, "hive: lease word not sent");
            false
        }
    }
}

/// The word on the device's current connection: for a session that became
/// leased while it runs (its first member placed), so the device holds it
/// to the word from its next connection on.
pub(crate) fn push(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
) -> bool {
    let msg = ServerMsg::HiveLease { session_id, fence };
    match state
        .fleet
        .rc_hub
        .push_hive_lease(device_id, tenant_id, msg)
    {
        Ok(()) => {
            info!(session = %session_id, device = %device_id, fence, "hive: lease word sent");
            true
        }
        Err(e) => {
            debug!(session = %session_id, device = %device_id, %e, "hive: lease word not sent");
            false
        }
    }
}
