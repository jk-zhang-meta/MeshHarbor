// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-5 — DERP directory + registration-driven rehome.
//!
//! The DERP relay is pod-local by design: two mesh peers only exchange
//! frames if their `/derp` sockets terminate on the SAME pod, and a
//! cross-pod destination is a **silent drop** (byte-identical to
//! peer-offline). A network is tenant-scoped and every dial carries the
//! same `tid`, so under a consistent LB map all of a network's sockets
//! converge on one pod — splits are stale-socket artifacts (parked WSs
//! from before a topology flip).
//!
//! The cure is **rehome, never forward**: no WG-rate bytes ever ride
//! the bus. Each registration writes an LWW record
//! (`roomler:own:derp:<net>:<pubkey>`) plus a per-network member index,
//! then runs one convergence sweep: the pod of the NEWEST registration
//! is the target (the newest dial reflects the LB's *current* verdict —
//! rehoming toward a parked majority would chase the past), and every
//! other pod is asked (`derp.rehome` RPC, or locally) to close its
//! sockets for that network. The closed clients reconnect through the
//! LB and re-land converged.
//!
//! Ping-pong guards on the CLOSING side: ≥60 s cooldown per
//! (network, pubkey), 3 attempts per 10 min window, then the
//! split-evidence counter fires instead (a stable split that rehome
//! cannot fix — surface it, don't thrash).

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::NetworkState;
use crate::derp_types::{DerpKey, DerpPubKey};
use meshharbor_core::cluster::directory::{OwnerRecord, derp_key, derpnet_key};
use meshharbor_core::cluster::metrics::DERP_REHOME_STUCK_TOTAL;

const REHOME_COOLDOWN: Duration = Duration::from_secs(60);
const REHOME_MAX_ATTEMPTS: u32 = 3;
const ATTEMPTS_RESET_AFTER: Duration = Duration::from_secs(600);

/// Per-(network, pubkey) close pacing on the closing pod.
#[derive(Debug, Clone, Copy, Default)]
pub struct RehomeCooldown {
    last: Option<Instant>,
    attempts: u32,
}

pub type RehomeCooldowns = DashMap<(ObjectId, String), RehomeCooldown>;

pub fn pk_hex(pk: &DerpPubKey) -> String {
    pk.iter().map(|b| format!("{b:02x}")).collect()
}

fn pk_from_hex(s: &str) -> Option<DerpPubKey> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Registration hook: write the LWW record + the per-network member
/// index, then run one convergence sweep.
pub async fn on_derp_register(
    state: &NetworkState,
    network_id: ObjectId,
    pk: &DerpPubKey,
    agent_id: ObjectId,
) {
    let Some(dir) = state.cluster_directory.clone() else {
        return;
    };
    let net_hex = network_id.to_hex();
    let member = pk_hex(pk);
    let token = dir.owner_token(&agent_id.to_hex());
    let key = derp_key(&net_hex, &member);
    if let Err(e) = dir.claim_lww(&key, &token).await {
        debug!(%network_id, %e, "derp directory claim failed");
        return;
    }
    state.derp_presence_tokens.insert((network_id, *pk), token);
    if let Err(e) = dir.set_add(&derpnet_key(&net_hex), &member).await {
        debug!(%network_id, %e, "derp net-index add failed");
    }
    // Sweep off the registration path: a dead peer pod costs an RPC
    // deadline and must not delay this socket's frame pumping.
    let st = state.clone();
    tokio::spawn(async move {
        converge_network(&st, network_id).await;
    });
}

/// Teardown hook: release the record (compare-DEL) and, when we were
/// the last owner, drop the member from the network index. A displaced
/// older socket never gets here (the registry remove is same-channel
/// guarded), so it can't free the newer registration.
pub async fn on_derp_teardown(state: &NetworkState, network_id: ObjectId, pk: &DerpPubKey) {
    let Some((_, token)) = state.derp_presence_tokens.remove(&(network_id, *pk)) else {
        return;
    };
    let Some(dir) = state.cluster_directory.clone() else {
        return;
    };
    let net_hex = network_id.to_hex();
    let member = pk_hex(pk);
    match dir.release(&derp_key(&net_hex, &member), &token).await {
        Ok(true) => {
            let _ = dir.set_remove(&derpnet_key(&net_hex), &member).await;
        }
        Ok(false) => {} // re-homed elsewhere — the record is theirs now
        Err(e) => debug!(%network_id, %e, "derp record release failed (TTL backstop)"),
    }
}

/// One convergence sweep over a network's live registrations. Target =
/// the pod of the newest record; every other pod gets a rehome for its
/// members (locally short-circuited for ourselves).
pub async fn converge_network(state: &NetworkState, network_id: ObjectId) {
    let Some(dir) = state.cluster_directory.clone() else {
        return;
    };
    let net_hex = network_id.to_hex();
    let members = match dir.set_members(&derpnet_key(&net_hex)).await {
        Ok(m) if m.len() > 1 => m,
        _ => return,
    };
    let keys: Vec<String> = members.iter().map(|m| derp_key(&net_hex, m)).collect();
    let Ok(records) = dir.get_many(&keys).await else {
        return;
    };

    let mut by_pod: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut newest: Option<(i64, String)> = None;
    for (member, raw) in members.iter().zip(records.iter()) {
        match raw.as_deref().and_then(OwnerRecord::parse) {
            Some(rec) => {
                let candidate = (rec.since_ms, rec.pod_id.clone());
                if newest.as_ref().map(|n| candidate > *n).unwrap_or(true) {
                    newest = Some(candidate);
                }
                by_pod.entry(rec.pod_id).or_default().push(member.clone());
            }
            // TTL-expired or garbage — lazily prune the index.
            None => {
                let _ = dir.set_remove(&derpnet_key(&net_hex), member).await;
            }
        }
    }
    if by_pod.len() < 2 {
        return;
    }
    let Some((_, target_pod)) = newest else {
        return;
    };
    info!(
        %network_id,
        %target_pod,
        pods = by_pod.len(),
        "derp network split across pods — rehoming toward newest registration"
    );
    for (pod, pks) in by_pod {
        if pod == target_pod {
            continue;
        }
        if pod == state.pod.pod_id {
            local_rehome_close(state, network_id, &pks);
        } else if let Some(bus) = state.cluster_bus.clone() {
            let body = serde_json::json!({
                "network_id": net_hex,
                "pubkeys": pks,
            });
            if let Err(e) = bus.request(&pod, "derp.rehome", body).await {
                // Presumed-dead pod: its records TTL out within 90 s and
                // the next registration converges cleanly.
                debug!(%network_id, %pod, %e, "derp.rehome RPC failed");
            }
        }
    }
}

/// Close local DERP sockets for the given pubkeys (cooldown-paced).
/// The socket loop's cancel arm breaks, teardown releases the record,
/// and the client's reconnect re-lands per the current LB map.
pub fn local_rehome_close(state: &NetworkState, network_id: ObjectId, pks: &[String]) {
    for member in pks {
        let Some(pk) = pk_from_hex(member) else {
            continue;
        };
        if !rehome_allowed(&state.derp_rehome_cooldowns, network_id, member) {
            continue;
        }
        if let Some(cancel) = state.derp_cancels.get(&(network_id, pk)) {
            info!(%network_id, pubkey = %member, "derp: closing socket for cluster rehome");
            meshharbor_core::cluster::metrics::bump(
                &meshharbor_core::cluster::metrics::DERP_REHOME_CLOSE_TOTAL,
            );
            cancel.notify_one();
        }
    }
}

/// The ping-pong guard. `true` = go ahead (attempt booked).
fn rehome_allowed(cooldowns: &RehomeCooldowns, network_id: ObjectId, member: &str) -> bool {
    rehome_allowed_at(cooldowns, network_id, member, Instant::now())
}

/// Time-injected core (tests advance a synthetic clock — subtracting
/// from a fresh runner's `Instant::now()` can underflow the monotonic
/// epoch and panic).
fn rehome_allowed_at(
    cooldowns: &RehomeCooldowns,
    network_id: ObjectId,
    member: &str,
    now: Instant,
) -> bool {
    let mut entry = cooldowns
        .entry((network_id, member.to_string()))
        .or_default();
    if let Some(last) = entry.last {
        let since = now.duration_since(last);
        if since >= ATTEMPTS_RESET_AFTER {
            entry.attempts = 0;
        } else if since < REHOME_COOLDOWN {
            return false;
        }
    }
    if entry.attempts >= REHOME_MAX_ATTEMPTS {
        let total = DERP_REHOME_STUCK_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        warn!(
            %network_id,
            pubkey = %member,
            derp_rehome_stuck_total = total,
            "SPLIT EVIDENCE: derp rehome attempts capped — stable split not converging"
        );
        return false;
    }
    entry.last = Some(now);
    entry.attempts += 1;
    true
}

/// Wire the C-5 machinery: the owner-side rehome handler + the derp
/// record refresh lives in the shared directory heartbeat (state.rs).
pub fn wire_derp_cluster(state: &NetworkState) {
    if let Some(bus) = &state.cluster_bus {
        let st = state.clone();
        bus.register("derp.rehome", move |body| {
            let st = st.clone();
            Box::pin(async move {
                let net = body
                    .get("network_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| ObjectId::parse_str(s).ok())
                    .ok_or_else(|| "missing network_id".to_string())?;
                let pks: Vec<String> = body
                    .get("pubkeys")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                local_rehome_close(&st, net, &pks);
                Ok(serde_json::json!({ "ok": true }))
            })
        });
    }
}

/// Purge one connection's cancel handle iff it is still `ours` (a newer
/// registration may have replaced it — same discipline as the registry).
pub fn remove_cancel_if_ours(
    state: &NetworkState,
    key: &DerpKey,
    ours: &std::sync::Arc<tokio::sync::Notify>,
) {
    state
        .derp_cancels
        .remove_if(key, |_, c| std::sync::Arc::ptr_eq(c, ours));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pk_hex_roundtrip() {
        let mut pk = [0u8; 32];
        pk[0] = 0xab;
        pk[31] = 0x01;
        let h = pk_hex(&pk);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab"));
        assert_eq!(pk_from_hex(&h), Some(pk));
        assert_eq!(pk_from_hex("zz"), None);
    }

    #[test]
    fn rehome_cooldown_paces_caps_and_resets() {
        let cooldowns = RehomeCooldowns::new();
        let net = ObjectId::new();
        let member = "aa".repeat(32);
        let t0 = Instant::now();
        let step = REHOME_COOLDOWN + Duration::from_secs(1);

        // First attempt allowed; a re-try inside the cooldown is paced.
        assert!(rehome_allowed_at(&cooldowns, net, &member, t0));
        assert!(!rehome_allowed_at(
            &cooldowns,
            net,
            &member,
            t0 + Duration::from_secs(5)
        ));

        // Past the cooldown → attempts 2 and 3 book.
        assert!(rehome_allowed_at(&cooldowns, net, &member, t0 + step));
        assert!(rehome_allowed_at(&cooldowns, net, &member, t0 + step * 2));

        // Attempt 4 within the window → capped (stuck counter fires).
        let before = DERP_REHOME_STUCK_TOTAL.load(Ordering::Relaxed);
        assert!(!rehome_allowed_at(&cooldowns, net, &member, t0 + step * 3));
        assert_eq!(DERP_REHOME_STUCK_TOTAL.load(Ordering::Relaxed), before + 1);

        // A quiet 10 min resets the window.
        let t_reset = t0 + step * 3 + ATTEMPTS_RESET_AFTER + Duration::from_secs(1);
        assert!(rehome_allowed_at(&cooldowns, net, &member, t_reset));

        // A different pubkey is unaffected throughout.
        assert!(rehome_allowed_at(&cooldowns, net, &"bb".repeat(32), t0));
    }
}
