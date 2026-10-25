// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #19 (v039 §4): accept, check and keep the read-only network
//! inventory each agent reports ([`ClientMsg::NetInventory`]).
//!
//! What makes a snapshot acceptable:
//!
//! - **Identity is the socket's.** The row is the authenticated connection's
//!   agent and tenant; the frame names neither.
//! - **Order.** `boot_id` is random per agent process and `seq` rises within
//!   it. A frame from the stored boot with a `seq` at or below the stored one
//!   is a replay or stale; a frame from one of the last [`RETIRED_BOOTS`]
//!   boots is a late frame from an old process. A new boot starts over.
//! - **Whole or nothing.** Pages of one `seq` assemble per connection, must
//!   all arrive within [`ASSEMBLY_WINDOW`], and the merged snapshot must pass
//!   [`NetInventory::validate`]; anything else is dropped, never stored as a
//!   smaller "complete" picture.
//! - **Freshness is the server's.** `received_at` is the server clock;
//!   [`FRESH_FOR`] after it the snapshot reads as stale, and a heartbeat
//!   never extends it. The node's own `observed_at_ms` is only shown.
//!
//! [`ClientMsg::NetInventory`]: roomler_ai_remote_control::signaling::ClientMsg::NetInventory

use std::time::{Duration, Instant};

use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_remote_control::net_inventory::{MAX_BOOT_ID, MAX_PAGES, NetInventory};
use roomler_core::AgentCtx;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::NetworkState;

pub const COLLECTION: &str = "node_net_inventory";
/// A snapshot counts as current this long after it arrived. Agents send a
/// full one every 5 min, so two can be missed before it reads stale.
pub const FRESH_FOR: Duration = Duration::from_secs(15 * 60);
/// Rows of nodes that stopped reporting are deleted this long after their
/// last snapshot (TTL index on `expires_at`).
pub const KEEP_FOR: Duration = Duration::from_secs(7 * 24 * 3600);
/// The pages of one snapshot must all arrive within this.
pub const ASSEMBLY_WINDOW: Duration = Duration::from_secs(30);
/// Earlier boots remembered, so a late frame from an old process is stale.
pub const RETIRED_BOOTS: usize = 4;

/// The stored snapshot: one row per agent.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InventoryRow {
    #[serde(rename = "_id")]
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub boot_id: String,
    pub seq: u64,
    #[serde(default)]
    pub retired_boots: Vec<String>,
    pub received_at: DateTime,
    pub expires_at: DateTime,
    pub observed_at_ms: i64,
    pub inventory: NetInventory,
}

impl InventoryRow {
    pub fn fresh(&self, now: DateTime) -> bool {
        now.timestamp_millis() - self.received_at.timestamp_millis() < FRESH_FOR.as_millis() as i64
    }
}

/// One frame's header and body.
pub struct Page {
    pub boot_id: String,
    pub seq: u64,
    pub page: u16,
    pub pages: u16,
    pub observed_at_ms: i64,
    pub inventory: NetInventory,
}

/// The pages of the snapshot a connection is sending.
#[derive(Default)]
pub struct Assembly {
    current: Option<InProgress>,
}

struct InProgress {
    boot_id: String,
    seq: u64,
    started: Instant,
    observed_at_ms: i64,
    pages: Vec<Option<NetInventory>>,
}

fn valid_boot_id(b: &str) -> bool {
    !b.is_empty()
        && b.len() <= MAX_BOOT_ID
        && b.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Why a frame or snapshot was not stored (logged, and returned for tests).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// More pages are due.
    Pending,
    Stored,
    Rejected(String),
    Stale(String),
}

impl Assembly {
    /// Add a frame; `Some(snapshot)` once its last page is in.
    fn add(
        &mut self,
        p: Page,
        now: Instant,
    ) -> Result<Option<(String, u64, i64, NetInventory)>, Outcome> {
        if !valid_boot_id(&p.boot_id) {
            return Err(Outcome::Rejected("malformed boot_id".into()));
        }
        if p.pages == 0 || p.pages > MAX_PAGES || p.page >= p.pages {
            return Err(Outcome::Rejected(format!("page {} of {}", p.page, p.pages)));
        }
        let same = self
            .current
            .as_ref()
            .is_some_and(|c| c.boot_id == p.boot_id && c.seq == p.seq);
        if !same {
            // A frame of an OLDER seq than the one being assembled is late.
            if let Some(c) = &self.current
                && c.boot_id == p.boot_id
                && p.seq < c.seq
                && now.duration_since(c.started) < ASSEMBLY_WINDOW
            {
                return Err(Outcome::Stale(format!("seq {} behind {}", p.seq, c.seq)));
            }
            self.current = Some(InProgress {
                boot_id: p.boot_id.clone(),
                seq: p.seq,
                started: now,
                observed_at_ms: p.observed_at_ms,
                pages: (0..p.pages).map(|_| None).collect(),
            });
        }
        let c = self.current.as_mut().expect("set above");
        if now.duration_since(c.started) >= ASSEMBLY_WINDOW {
            self.current = None;
            return Err(Outcome::Rejected(
                "pages arrived past the assembly window".into(),
            ));
        }
        if c.pages.len() != p.pages as usize {
            self.current = None;
            return Err(Outcome::Rejected("page count changed mid-snapshot".into()));
        }
        if p.page == 0 {
            c.observed_at_ms = p.observed_at_ms;
        }
        c.pages[p.page as usize].get_or_insert(p.inventory);
        if c.pages.iter().any(Option::is_none) {
            return Ok(None);
        }
        let c = self.current.take().expect("set above");
        let merged = NetInventory::merge(c.pages.into_iter().map(|p| p.expect("all in")).collect())
            .map_err(Outcome::Rejected)?;
        merged.validate().map_err(Outcome::Rejected)?;
        Ok(Some((c.boot_id, c.seq, c.observed_at_ms, merged)))
    }
}

/// Take one frame from the connection `ctx`, storing the snapshot it
/// completes.
pub async fn receive(
    state: &NetworkState,
    ctx: &AgentCtx,
    assembly: &mut Assembly,
    page: Page,
) -> Outcome {
    let outcome = match assembly.add(page, Instant::now()) {
        Err(o) => o,
        Ok(None) => Outcome::Pending,
        Ok(Some((boot_id, seq, observed_at_ms, inventory))) => {
            store(
                state,
                ctx.tenant_id,
                ctx.agent_id,
                boot_id,
                seq,
                observed_at_ms,
                inventory,
            )
            .await
        }
    };
    match &outcome {
        Outcome::Rejected(why) => warn!(agent = %ctx.agent_id, %why, "net inventory: rejected"),
        Outcome::Stale(why) => debug!(agent = %ctx.agent_id, %why, "net inventory: stale, dropped"),
        Outcome::Stored => debug!(agent = %ctx.agent_id, "net inventory: stored"),
        Outcome::Pending => {}
    }
    outcome
}

/// Upsert `agent_id`'s row unless what is stored is as new or newer. The
/// order check and the write are one conditional update, so two racing
/// connections cannot store out of order.
pub async fn store(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    boot_id: String,
    seq: u64,
    observed_at_ms: i64,
    inventory: NetInventory,
) -> Outcome {
    let rows = state.core.db.collection::<InventoryRow>(COLLECTION);
    let prior = match rows.find_one(doc! { "_id": agent_id }).await {
        Ok(p) => p,
        Err(e) => return Outcome::Rejected(format!("read failed: {e}")),
    };
    let mut retired = Vec::new();
    if let Some(p) = &prior {
        if p.tenant_id != tenant_id {
            return Outcome::Rejected("row belongs to another tenant".into());
        }
        if p.retired_boots.contains(&boot_id) {
            return Outcome::Stale("frame from a retired boot".into());
        }
        if p.boot_id == boot_id && seq <= p.seq {
            return Outcome::Stale(format!("seq {seq} not after stored {}", p.seq));
        }
        retired = p.retired_boots.clone();
        if p.boot_id != boot_id {
            retired.retain(|b| b != &p.boot_id);
            retired.insert(0, p.boot_id.clone());
            retired.truncate(RETIRED_BOOTS);
        }
    }
    let now = DateTime::now();
    let row = InventoryRow {
        agent_id,
        tenant_id,
        boot_id: boot_id.clone(),
        seq,
        retired_boots: retired,
        received_at: now,
        expires_at: DateTime::from_millis(now.timestamp_millis() + KEEP_FOR.as_millis() as i64),
        observed_at_ms,
        inventory,
    };
    // Matches only the row as read (or no row): a racing writer that got
    // there first makes this an insert of an existing `_id`, a duplicate key.
    let filter = match &prior {
        Some(p) => doc! { "_id": agent_id, "boot_id": &p.boot_id, "seq": p.seq as i64 },
        None => doc! { "_id": agent_id },
    };
    let res = if prior.is_some() {
        rows.replace_one(filter, &row)
            .await
            .map(|r| r.matched_count == 1)
    } else {
        rows.insert_one(&row).await.map(|_| true)
    };
    match res {
        Ok(true) => Outcome::Stored,
        Ok(false) => Outcome::Stale("a newer snapshot landed first".into()),
        Err(e) if e.to_string().contains("E11000") => {
            Outcome::Stale("a newer snapshot landed first".into())
        }
        Err(e) => Outcome::Rejected(format!("write failed: {e}")),
    }
}

/// The tenant's rows, newest first.
pub async fn list(state: &NetworkState, tenant_id: ObjectId) -> Result<Vec<InventoryRow>, String> {
    use futures::TryStreamExt;
    state
        .core
        .db
        .collection::<InventoryRow>(COLLECTION)
        .find(doc! { "tenant_id": tenant_id })
        .sort(doc! { "received_at": -1 })
        .limit(2000)
        .await
        .map_err(|e| e.to_string())?
        .try_collect()
        .await
        .map_err(|e| e.to_string())
}

/// One agent's row, only within `tenant_id`.
pub async fn get(
    state: &NetworkState,
    tenant_id: ObjectId,
    agent_id: ObjectId,
) -> Result<Option<InventoryRow>, String> {
    state
        .core
        .db
        .collection::<InventoryRow>(COLLECTION)
        .find_one(doc! { "_id": agent_id, "tenant_id": tenant_id })
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use roomler_ai_remote_control::net_inventory::{Route, Section};

    fn inv(routes: usize) -> NetInventory {
        NetInventory {
            os: "linux".into(),
            namespaces: "host_only".into(),
            routes: Section::capped(
                (0..routes)
                    .map(|i| Route {
                        family: roomler_ai_remote_control::net_inventory::Family::V4,
                        table: "main".into(),
                        dst: format!("10.0.{}.0/24", i % 256),
                        kind: "unicast".into(),
                        gateway: None,
                        dev: None,
                        protocol: None,
                        metric: None,
                    })
                    .collect(),
                4096,
            ),
            ..Default::default()
        }
    }

    fn pages(boot: &str, seq: u64, inv: NetInventory, per: usize) -> Vec<Page> {
        let split = inv.split(per);
        let n = split.len() as u16;
        split
            .into_iter()
            .enumerate()
            .map(|(i, inventory)| Page {
                boot_id: boot.into(),
                seq,
                page: i as u16,
                pages: n,
                observed_at_ms: 1,
                inventory,
            })
            .collect()
    }

    #[test]
    fn pages_assemble_in_any_order_and_duplicates_are_harmless() {
        let mut a = Assembly::default();
        let t = Instant::now();
        let mut ps: Vec<Option<Page>> = pages("b1", 1, inv(30), 10).into_iter().map(Some).collect();
        assert_eq!(ps.len(), 3);
        let dup = pages("b1", 1, inv(30), 10).swap_remove(1);
        assert!(a.add(ps[1].take().unwrap(), t).unwrap().is_none());
        assert!(a.add(dup, t).unwrap().is_none());
        assert!(a.add(ps[2].take().unwrap(), t).unwrap().is_none());
        let (boot, seq, _, whole) = a.add(ps[0].take().unwrap(), t).unwrap().expect("complete");
        assert_eq!(
            (boot.as_str(), seq, whole.routes.items.len()),
            ("b1", 1, 30)
        );
    }

    #[test]
    fn a_page_set_must_finish_inside_the_window() {
        let mut a = Assembly::default();
        let t = Instant::now();
        let mut ps = pages("b1", 1, inv(30), 10);
        a.add(ps.remove(0), t).unwrap();
        let late = a.add(ps.remove(0), t + ASSEMBLY_WINDOW);
        assert!(matches!(late, Err(Outcome::Rejected(_))));
    }

    #[test]
    fn malformed_headers_and_snapshots_are_rejected() {
        let mut a = Assembly::default();
        let t = Instant::now();
        let mut p = pages("b1", 1, inv(1), 10).remove(0);
        p.boot_id = "has space".into();
        assert!(matches!(a.add(p, t), Err(Outcome::Rejected(_))));
        let mut p = pages("b1", 1, inv(1), 10).remove(0);
        p.page = 1;
        assert!(
            matches!(a.add(p, t), Err(Outcome::Rejected(_))),
            "page past pages"
        );
        let mut p = pages("b1", 1, inv(1), 10).remove(0);
        p.pages = MAX_PAGES + 1;
        p.page = 0;
        assert!(matches!(a.add(p, t), Err(Outcome::Rejected(_))));
        // A truncated section that still claims `complete` fails validation.
        let mut bad = inv(5);
        bad.routes.items.pop();
        let p = pages("b1", 2, bad, 10).remove(0);
        assert!(matches!(a.add(p, t), Err(Outcome::Rejected(_))));
    }

    #[test]
    fn an_older_seq_cannot_interrupt_a_newer_assembly() {
        let mut a = Assembly::default();
        let t = Instant::now();
        let mut new = pages("b1", 5, inv(20), 10);
        a.add(new.remove(0), t).unwrap();
        let old = pages("b1", 4, inv(1), 10).remove(0);
        assert!(matches!(a.add(old, t), Err(Outcome::Stale(_))));
        assert!(
            a.add(new.remove(0), t).unwrap().is_some(),
            "the newer one still completes"
        );
    }
}
