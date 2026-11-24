// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P3b — remote-session slots: a cluster-wide count of the concurrent
//! remote sessions an org (or an account in no org) runs, kept in Redis on
//! the cluster directory's own discipline (`directory.rs`). Redis is a
//! directory here, not a database: every record can be re-derived from the
//! live hubs, a reader fails soft, and a TTL backs up every release.
//!
//! * One sorted set per payer, `meshharbor:rc:slots:{db}:{org|user}:{id}`:
//!   member = session id, score = lease expiry (ms).
//! * One hash per session, `meshharbor:rc:slot:{db}:{session}`: the holder (user
//!   and device), which the refusal names.
//!
//! The hub that holds a session renews its lease every [`SLOT_RENEW_SECS`];
//! a lease lives [`SLOT_TTL_SECS`]. A pod that dies stops renewing, and its
//! slots free themselves within a lease. A Redis restart loses the sets, and
//! the next renewal round puts back every session its hub still holds
//! ([`SessionSlots::restore`]). Renewal itself only updates (`ZADD XX`), so a
//! session released while a round was in flight is never put back, and only
//! lengthens (`GT` on the score, Redis 6.2, and on both keys' expiry, Redis
//! 7.0: the floor), so a round in flight never shortens a lease FR-130 kept.
//!
//! FR-130 (review 1, L5) — a detached session is held by no pod, so nobody
//! renews its lease through the gap. The detach keeps it once, in Redis,
//! until the session's `resume_by` plus [`SLOT_KEEP_PAST_RESUME_MS`]
//! ([`SessionSlots::keep`]): a window longer than what was left of the lease
//! (up to 120 s against 60-90 s) no longer loses the slot, and the pod that
//! detached the session may die meanwhile. Every writer only lengthens a key's
//! expiry (PR D's review, LOW 5): the claim reads `PTTL` before it writes one,
//! and a restore writes `PEXPIRE … NX`, then `GT`. So another session's claim
//! in the org, or a restore after Redis lost a lease, never takes a kept lease
//! away with its set before its deadline, at any window up to the 120 s cap.
//! A keep never revives a lease that has already lapsed (LOW 7).
//!
//! The holder record names the claiming pod. A caller refused by a full set
//! may drop a holder that ITS OWN pod claimed but no longer holds (a release
//! that failed): that pod is the one that would know. It never judges another
//! pod's holders (`meshharbor_mod_remote::slots`).
//!
//! The claim is ONE Lua script (drop expired, already mine → renew, under the
//! cap → add, else full), so two starts in the same instant cannot both pass
//! (the count/insert race P3's hub count documents). The member is the
//! session id, so a retried claim for the same session renews it rather
//! than spending a second slot.

use bson::oid::ObjectId;
use redis::aio::ConnectionManager;

/// How long a lease lives without renewal: three renewal rounds, the same
/// ratio as the directory's records (`DIRECTORY_TTL_SECS`).
pub const SLOT_TTL_SECS: u64 = 90;
/// How often the pod that holds a session renews its lease.
pub const SLOT_RENEW_SECS: u64 = 30;
/// FR-130 (L5) — how long past a detached session's `resume_by` its lease is
/// kept: a claim that lands at the deadline still finds its own slot, and a
/// session nobody claims gives the slot back this long after it.
pub const SLOT_KEEP_PAST_RESUME_MS: i64 = 10_000;

/// Whose slots a session takes (FR-115 O6 + O7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotScope {
    /// An org: its members' sessions to its own devices, and the external
    /// sessions they run for it into other orgs.
    Org(ObjectId),
    /// An account in no org: Free's quota, counted against the account.
    User(ObjectId),
}

/// A session that holds a slot (hex ids), and the pod whose hub holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotHolder {
    pub session: String,
    pub user: String,
    pub device: String,
    /// The pod that claimed it, whose hub holds the session and renews it.
    /// Empty when the holder's record had already expired.
    pub pod: String,
}

/// What a claim found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotClaim {
    /// A slot was free, and is now this session's.
    Claimed,
    /// This session already held a slot: its lease was renewed (a retry).
    Renewed,
    /// Every slot is held: every live holder, soonest-expiring first, for
    /// the refusal and for the caller's stale check.
    Full(Vec<SlotHolder>),
}

/// One live session's lease, as its pod renews it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub scope: SlotScope,
    pub session: ObjectId,
    pub user: ObjectId,
    pub device: ObjectId,
}

/// KEYS[1] = the payer's set, KEYS[2] = this session's holder hash.
/// ARGV: now_ms, ttl_ms, cap, session, user, device, the holder-key prefix,
/// the claiming pod. A full set answers every live holder (at most 64: a cap
/// past that is never one a refusal has to name). Both keys' expiries only
/// lengthen (FR-130, PR D's review, LOW 5): the set may hold a lease a detach
/// kept past a lease's TTL, and the claim of another session must not take it
/// away with the set early. The score is the claimed lease's own: a claim
/// that renews its own session's lease sets it to a full lease from now, and
/// the hub that holds the session renews it from there.
const CLAIM: &str = r#"
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local mine = redis.call('ZSCORE', KEYS[1], ARGV[4])
if mine or redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], now + ttl, ARGV[4])
  if redis.call('PTTL', KEYS[1]) < ttl then redis.call('PEXPIRE', KEYS[1], ttl) end
  redis.call('HSET', KEYS[2], 'user', ARGV[5], 'device', ARGV[6], 'pod', ARGV[8])
  if redis.call('PTTL', KEYS[2]) < ttl then redis.call('PEXPIRE', KEYS[2], ttl) end
  if mine then return {'renewed'} end
  return {'claimed'}
end
local out = {'full'}
for _, m in ipairs(redis.call('ZRANGE', KEYS[1], 0, 63)) do
  local h = redis.call('HMGET', ARGV[7] .. m, 'user', 'device', 'pod')
  table.insert(out, m)
  table.insert(out, h[1] or '')
  table.insert(out, h[2] or '')
  table.insert(out, h[3] or '')
end
return out
"#;

/// FR-130 (L5) — KEYS[1] = the payer's set, KEYS[2] = the session's holder
/// hash. ARGV: the session, keep-until ms, now ms. Only lengthens, and only
/// a lease that is still live: a session released meanwhile stays released,
/// and a lease that lapsed but no claim has purged yet stays lapsed (PR D's
/// review, LOW 7), since its holder record may be gone with it.
const KEEP: &str = r#"
local cur = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not cur or tonumber(cur) <= tonumber(ARGV[3]) then return 0 end
local keep = tonumber(ARGV[2])
if tonumber(cur) < keep then redis.call('ZADD', KEYS[1], 'XX', keep, ARGV[1]) end
local left = keep - tonumber(ARGV[3])
if left > 0 then
  if redis.call('PTTL', KEYS[1]) < left then redis.call('PEXPIRE', KEYS[1], left) end
  if redis.call('PTTL', KEYS[2]) < left then redis.call('PEXPIRE', KEYS[2], left) end
end
return 1
"#;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Give `key` an expiry of at least `ttl_ms` without ever shortening one:
/// `NX` sets it when the key has none, `GT` raises a shorter one. (`GT`
/// alone treats a key with no expiry as infinite and leaves it so.)
fn lengthen(pipe: &mut redis::Pipeline, key: &str, ttl_ms: u64) {
    pipe.cmd("PEXPIRE")
        .arg(key)
        .arg(ttl_ms)
        .arg("NX")
        .ignore()
        .cmd("PEXPIRE")
        .arg(key)
        .arg(ttl_ms)
        .arg("GT")
        .ignore();
}

/// The slot record, scoped to one database so two deployments (or two
/// tests) that share a Redis never count each other's sessions.
#[derive(Clone)]
pub struct SessionSlots {
    conn: ConnectionManager,
    db: String,
}

impl SessionSlots {
    pub fn new(conn: ConnectionManager, db_name: &str) -> Self {
        Self {
            conn,
            db: db_name.to_string(),
        }
    }

    /// The payer's set.
    pub fn slots_key(&self, scope: SlotScope) -> String {
        match scope {
            SlotScope::Org(id) => format!("meshharbor:rc:slots:{}:org:{}", self.db, id.to_hex()),
            SlotScope::User(id) => format!("meshharbor:rc:slots:{}:user:{}", self.db, id.to_hex()),
        }
    }

    fn holder_prefix(&self) -> String {
        format!("meshharbor:rc:slot:{}:", self.db)
    }

    fn holder_key(&self, session: ObjectId) -> String {
        format!("{}{}", self.holder_prefix(), session.to_hex())
    }

    /// Claim one of `scope`'s `cap` slots for `session`, held on `pod`
    /// (atomic; see the module docs). A `cap` of 0 is always full.
    pub async fn claim(
        &self,
        scope: SlotScope,
        session: ObjectId,
        user: ObjectId,
        device: ObjectId,
        cap: u32,
        pod: &str,
    ) -> Result<SlotClaim, redis::RedisError> {
        let mut conn = self.conn.clone();
        let out: Vec<String> = redis::Script::new(CLAIM)
            .key(self.slots_key(scope))
            .key(self.holder_key(session))
            .arg(now_ms())
            .arg(SLOT_TTL_SECS * 1000)
            .arg(cap)
            .arg(session.to_hex())
            .arg(user.to_hex())
            .arg(device.to_hex())
            .arg(self.holder_prefix())
            .arg(pod)
            .invoke_async(&mut conn)
            .await?;
        Ok(match out.first().map(String::as_str) {
            Some("claimed") => SlotClaim::Claimed,
            Some("renewed") => SlotClaim::Renewed,
            _ => SlotClaim::Full(
                out.get(1..)
                    .unwrap_or_default()
                    .chunks_exact(4)
                    .map(|h| SlotHolder {
                        session: h[0].clone(),
                        user: h[1].clone(),
                        device: h[2].clone(),
                        pod: h[3].clone(),
                    })
                    .collect(),
            ),
        })
    }

    /// Renew this pod's leases in one round trip, and answer the ones whose
    /// slot was MISSING. An update only (`ZADD XX`), never an upsert: a
    /// session that ended while the round was in flight has had its slot
    /// released, and an upsert would put it back for a whole lease. A missing
    /// lease is either that, or a Redis that lost the set (a restart); the
    /// caller tells them apart by asking its hub, and [`Self::restore`]s only
    /// the sessions it still holds.
    ///
    /// FR-130 (L5) — and it only lengthens (`GT`): a session detached while
    /// the round was in flight left this pod's leases, and its lease, kept
    /// until its `resume_by` plus [`SLOT_KEEP_PAST_RESUME_MS`], is never cut
    /// back to this round's expiry. Such a lease answers as missing too (no
    /// change), and the hub no longer holds its session, so it is not put back.
    pub async fn renew(&self, leases: &[Lease]) -> Result<Vec<Lease>, redis::RedisError> {
        if leases.is_empty() {
            return Ok(Vec::new());
        }
        let ttl_ms = SLOT_TTL_SECS * 1000;
        let until = now_ms() + ttl_ms;
        let mut pipe = redis::pipe();
        for l in leases {
            let slots = self.slots_key(l.scope);
            pipe.cmd("ZADD")
                .arg(&slots)
                .arg("XX")
                .arg("GT")
                .arg("CH")
                .arg(until)
                .arg(l.session.to_hex())
                .cmd("PEXPIRE")
                .arg(&slots)
                .arg(ttl_ms)
                .arg("GT")
                .ignore()
                .cmd("PEXPIRE")
                .arg(self.holder_key(l.session))
                .arg(ttl_ms)
                .arg("GT")
                .ignore();
        }
        let mut conn = self.conn.clone();
        let changed: Vec<i64> = pipe.query_async(&mut conn).await?;
        Ok(leases
            .iter()
            .zip(changed)
            .filter(|(_, c)| *c == 0)
            .map(|(l, _)| l.clone())
            .collect())
    }

    /// Put back the slots of sessions `pod`'s hub still holds but Redis lost
    /// (an upsert). Only for sessions the caller has just seen live.
    ///
    /// FR-130 (PR D's review, LOW 5) — and it only lengthens: the score is
    /// written `GT` (a missing lease is added, a live one never lowered), and
    /// each key's expiry `NX`, then `GT` (set when it has none, raised when it
    /// is shorter), so a round that answered a kept lease as missing, or put
    /// back another lease of the org, never cuts a kept lease or its set back
    /// to 90 s. Redis 7.0, the floor the renewal already needs.
    pub async fn restore(&self, leases: &[Lease], pod: &str) -> Result<(), redis::RedisError> {
        if leases.is_empty() {
            return Ok(());
        }
        let ttl_ms = SLOT_TTL_SECS * 1000;
        let until = now_ms() + ttl_ms;
        let mut pipe = redis::pipe();
        for l in leases {
            let slots = self.slots_key(l.scope);
            let holder = self.holder_key(l.session);
            pipe.cmd("ZADD")
                .arg(&slots)
                .arg("GT")
                .arg(until)
                .arg(l.session.to_hex())
                .ignore();
            lengthen(&mut pipe, &slots, ttl_ms);
            pipe.cmd("HSET")
                .arg(&holder)
                .arg("user")
                .arg(l.user.to_hex())
                .arg("device")
                .arg(l.device.to_hex())
                .arg("pod")
                .arg(pod)
                .ignore();
            lengthen(&mut pipe, &holder, ttl_ms);
        }
        let mut conn = self.conn.clone();
        pipe.query_async::<()>(&mut conn).await
    }

    /// FR-130 (L5) — keep `session`'s lease, and both keys it lives in, until
    /// `until_ms` (its `resume_by` plus [`SLOT_KEEP_PAST_RESUME_MS`]): what a
    /// detach writes once, so the slot outlives the gap with no pod renewing
    /// it. Only lengthens, and only a lease that still exists: `false` when
    /// there was none (released, or already lapsed).
    pub async fn keep(
        &self,
        scope: SlotScope,
        session: ObjectId,
        until_ms: i64,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = self.conn.clone();
        let kept: i64 = redis::Script::new(KEEP)
            .key(self.slots_key(scope))
            .key(self.holder_key(session))
            .arg(session.to_hex())
            .arg(until_ms)
            .arg(now_ms())
            .invoke_async(&mut conn)
            .await?;
        Ok(kept == 1)
    }

    /// Give `session`'s slot back. Idempotent; the TTL backs it up when this
    /// never runs (a pod that died).
    pub async fn release(
        &self,
        scope: SlotScope,
        session: ObjectId,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::pipe()
            .cmd("ZREM")
            .arg(self.slots_key(scope))
            .arg(session.to_hex())
            .ignore()
            .cmd("DEL")
            .arg(self.holder_key(session))
            .ignore()
            .query_async::<()>(&mut conn)
            .await
    }

    /// The live leases `scope` holds now (expired ones are not counted).
    pub async fn held(&self, scope: SlotScope) -> Result<u64, redis::RedisError> {
        let mut conn = self.conn.clone();
        redis::cmd("ZCOUNT")
            .arg(self.slots_key(scope))
            .arg(format!("({}", now_ms()))
            .arg("+inf")
            .query_async(&mut conn)
            .await
    }
}
