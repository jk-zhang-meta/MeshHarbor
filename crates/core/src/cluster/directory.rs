// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-1 — the ownership directory: entity → owning-pod records in Redis.
//!
//! One record per live entity (`agent`, later `tunnel`/`derp`/`media`),
//! value = the canonical owner token `"<pod_id>/<epoch>/<extra>/<since_ms>"`.
//! Redis here is a DIRECTORY, not a database: every record is re-derivable
//! from a live socket/registry, every reader fails soft to the pod-local
//! answer, and TTL expiry is the passive backstop behind explicit release.
//!
//! Claim disciplines per namespace (the architecture's Q1):
//! - **LWW** (`claim_lww`): connection-bound entities — the newest live
//!   socket is definitionally the owner (mirrors the rc-hub's displacement
//!   rule). Plain `SET`.
//! - **NX** (`claim_nx`): server-materialized state with no client-owned
//!   socket (media rooms, C-4) — two creations = split-brain, so creation
//!   itself must be mutually exclusive.
//!
//! Three Lua ops shared by all namespaces: claim, refresh-if-mine
//! (foreign ⇒ CONFLICT — the fold trigger), compare-delete.

use redis::aio::ConnectionManager;

/// TTL for connection-bound records (3× the 30 s heartbeat).
pub const DIRECTORY_TTL_SECS: u64 = 90;

/// `if GET==token then DEL` — the classic single-key lock release.
const COMPARE_DEL: &str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";

/// Refresh-if-mine: mine ⇒ re-SET (full value + TTL, so a wrongful delete
/// self-heals); absent ⇒ re-SET (we hold the live entity — re-derive the
/// record); foreign ⇒ 0 = CONFLICT (caller folds / logs, never overwrites).
const REFRESH_IF_MINE: &str = "local v = redis.call('GET', KEYS[1]) \
     if v == false or v == ARGV[1] then \
       redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2]) return 1 \
     else return 0 end";

/// A parsed directory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRecord {
    pub pod_id: String,
    pub epoch: String,
    pub extra: String,
    pub since_ms: i64,
}

impl OwnerRecord {
    pub fn parse(raw: &str) -> Option<Self> {
        let mut it = raw.splitn(4, '/');
        let pod_id = it.next()?.to_string();
        let epoch = it.next()?.to_string();
        let extra = it.next()?.to_string();
        let since_ms = it.next()?.parse().ok()?;
        Some(Self {
            pod_id,
            epoch,
            extra,
            since_ms,
        })
    }
}

/// Outcome of an NX claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Won,
    /// Someone else holds the claim (raw owner token).
    Foreign(String),
}

/// The directory client. Cheap to clone (ConnectionManager is).
#[derive(Clone)]
pub struct OwnershipDirectory {
    conn: ConnectionManager,
    origin: String,
}

impl OwnershipDirectory {
    pub fn new(conn: ConnectionManager, origin: String) -> Self {
        Self { conn, origin }
    }

    /// Mint the owner token this pod writes for one entity registration.
    /// `extra` is a per-registration discriminator (e.g. a conn id) so a
    /// same-pod reconnect's late release can't free the new claim. Must
    /// not contain `/`.
    pub fn owner_token(&self, extra: &str) -> String {
        debug_assert!(!extra.contains('/'));
        format!(
            "{}/{}/{}",
            self.origin,
            extra,
            bson::DateTime::now().timestamp_millis()
        )
    }

    /// Whether `raw` names an owner other than THIS pod process.
    pub fn is_foreign(&self, raw: &str) -> bool {
        !raw.starts_with(&self.origin)
    }

    /// LWW claim/refresh: full `SET … EX` — newest wins.
    pub async fn claim_lww(&self, key: &str, token: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::cmd("SET")
            .arg(key)
            .arg(token)
            .arg("EX")
            .arg(DIRECTORY_TTL_SECS)
            .query_async::<()>(&mut conn)
            .await
    }

    /// NX claim (mutex namespaces): `SET NX EX`; on loss returns the
    /// current holder.
    pub async fn claim_nx(
        &self,
        key: &str,
        token: &str,
        ttl_secs: u64,
    ) -> Result<ClaimOutcome, redis::RedisError> {
        let mut conn = self.conn.clone();
        let set: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(token)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await?;
        if set.is_some() {
            return Ok(ClaimOutcome::Won);
        }
        let holder: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
        match holder {
            // The holder vanished between our SET NX and GET — retry once.
            None => {
                let set2: Option<String> = redis::cmd("SET")
                    .arg(key)
                    .arg(token)
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl_secs)
                    .query_async(&mut conn)
                    .await?;
                if set2.is_some() {
                    Ok(ClaimOutcome::Won)
                } else {
                    let h: Option<String> =
                        redis::cmd("GET").arg(key).query_async(&mut conn).await?;
                    Ok(ClaimOutcome::Foreign(h.unwrap_or_default()))
                }
            }
            Some(h) => Ok(ClaimOutcome::Foreign(h)),
        }
    }

    /// Refresh-if-mine. `Ok(true)` = still ours (or re-asserted after an
    /// expiry); `Ok(false)` = CONFLICT: a foreign owner holds the key —
    /// the caller must treat its local copy as claim-lost (fold), never
    /// overwrite.
    pub async fn refresh_if_mine(
        &self,
        key: &str,
        token: &str,
        ttl_secs: u64,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(REFRESH_IF_MINE)
            .key(key)
            .arg(token)
            .arg(ttl_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(n > 0)
    }

    /// Compare-and-delete: release only if we still own it. Returns
    /// whether a delete happened.
    pub async fn release(&self, key: &str, token: &str) -> Result<bool, redis::RedisError> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(COMPARE_DEL)
            .key(key)
            .arg(token)
            .invoke_async(&mut conn)
            .await?;
        Ok(n > 0)
    }

    /// Raw read of one record.
    pub async fn get(&self, key: &str) -> Result<Option<String>, redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::cmd("GET").arg(key).query_async(&mut conn).await
    }

    /// Batched read (`MGET`) preserving input order.
    pub async fn get_many(
        &self,
        keys: &[String],
    ) -> Result<Vec<Option<String>>, redis::RedisError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("MGET");
        for k in keys {
            cmd.arg(k);
        }
        cmd.query_async(&mut conn).await
    }

    // C-5 — member-index sets (per-network DERP membership). The set is
    // an INDEX, not a truth source: per-member ownership lives in the
    // keyed records; readers lazily prune members whose record is gone.
    // A 1 h idle TTL (refreshed on every add) keeps dead networks from
    // accreting keys.

    pub async fn set_add(&self, key: &str, member: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::pipe()
            .cmd("SADD")
            .arg(key)
            .arg(member)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(3600)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
    }

    pub async fn set_remove(&self, key: &str, member: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::cmd("SREM")
            .arg(key)
            .arg(member)
            .query_async::<()>(&mut conn)
            .await
    }

    pub async fn set_members(&self, key: &str) -> Result<Vec<String>, redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::cmd("SMEMBERS").arg(key).query_async(&mut conn).await
    }

    /// C-6 — cursor-driven `SCAN MATCH` (never `KEYS`): used by the
    /// status snapshot for the handful of `meshharbor:pod-alive:*` records.
    pub async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, redis::RedisError> {
        let mut conn = self.conn.clone();
        let mut cursor: u64 = 0;
        let mut out = Vec::new();
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;
            out.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(out)
    }
}

/// Key builders — ONE place per namespace so producers and readers can
/// never drift. (`agent` keeps the Phase A-1 key name for continuity.)
pub fn agent_key(agent_id_hex: &str) -> String {
    format!("meshharbor:agent-online:{agent_id_hex}")
}
pub fn pod_alive_key(pod_id: &str) -> String {
    format!("meshharbor:pod-alive:{pod_id}")
}

/// C-3 — tunnel session ownership records (observability + the C-6
/// metrics; liveness is the session map, TTL reaps ≤90 s after teardown).
pub fn tunnel_key(session_hex: &str) -> String {
    format!("meshharbor:own:tunnel:{session_hex}")
}

/// C-4 — media room claims: the SET-NX namespace (creation is mutually
/// exclusive — see `ws/media_cluster.rs`). Short TTL: a crashed owner's
/// room is unusable, so the claim must free fast for the rejoin path.
pub const MEDIA_TTL_SECS: u64 = 30;
pub fn media_key(room_hex: &str) -> String {
    format!("meshharbor:own:media:{room_hex}")
}

/// C-5 — DERP registrations (LWW: a reconnect for the same pubkey is
/// definitionally the newer owner) + the per-network member index the
/// convergence sweep reads. Pubkeys as lowercase hex (base64 would put
/// `/` inside the token format).
pub fn derp_key(net_hex: &str, pubkey_hex: &str) -> String {
    format!("meshharbor:own:derp:{net_hex}:{pubkey_hex}")
}
pub fn derpnet_key(net_hex: &str) -> String {
    format!("meshharbor:own:derpnet:{net_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_record_roundtrip() {
        let r = OwnerRecord::parse("10.10.30.11/ab12cd34/conn-9/1754160000000").unwrap();
        assert_eq!(r.pod_id, "10.10.30.11");
        assert_eq!(r.epoch, "ab12cd34");
        assert_eq!(r.extra, "conn-9");
        assert_eq!(r.since_ms, 1_754_160_000_000);
        assert!(OwnerRecord::parse("garbage").is_none());
    }
}
