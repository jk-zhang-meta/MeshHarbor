// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use redis::aio::ConnectionManager;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

const CHANNEL_NAME: &str = "meshharbor:ws";

/// TTL on `meshharbor:online:<uid>` keys. Refreshed by each pod's 30 s
/// heartbeat while the user has local connections — 3× headroom so a
/// single missed beat (GC pause, Redis blip) doesn't flap presence.
const ONLINE_TTL_SECS: u64 = 90;

/// Manages Redis Pub/Sub for cross-instance WebSocket event distribution.
///
/// Each application instance publishes WS events to a shared Redis channel.
/// A background subscriber task receives messages from other instances and
/// forwards them to local WebSocket connections via a broadcast channel.
///
/// Every published envelope carries this instance's `instance_id`; the
/// subscriber loop in `main.rs` drops envelopes whose origin matches its own
/// id. Without that guard the publishing pod's own subscription re-delivers
/// every event locally (local delivery already happened in
/// `dispatcher::broadcast_with_redis`) — the "double notification" bug.
#[derive(Clone)]
pub struct RedisPubSub {
    publisher: ConnectionManager,
    channel: String,
    instance_id: String,
}

impl RedisPubSub {
    /// C-1: `origin` is the cluster identity's `<pod_id>/<epoch>` string
    /// (was a random per-process UUID). The stable pod prefix is what lets
    /// ownership records name their pod; the per-process epoch keeps the
    /// self-echo guard and the user-online SREM semantics identical to the
    /// old random id.
    pub async fn new(redis_url: &str, origin: String) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let publisher = ConnectionManager::new(client).await?;
        info!("Redis Pub/Sub publisher connected to {}", redis_url);
        Ok(Self {
            publisher,
            channel: CHANNEL_NAME.to_string(),
            instance_id: origin,
        })
    }

    /// Per-process origin id stamped on every published envelope.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// A clone of the multiplexed command connection — the cluster
    /// directory + bus publisher ride the same manager.
    pub fn connection(&self) -> ConnectionManager {
        self.publisher.clone()
    }

    /// Publish a message to Redis for other instances to receive.
    pub async fn publish(&self, message: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("PUBLISH")
            .arg(&self.channel)
            .arg(message)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    /// Round-trip a PING on the publisher connection — the `/health/ready`
    /// dependency check.
    pub async fn ping(&self) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("PING").query_async::<String>(&mut conn).await?;
        Ok(())
    }

    /// A key's remaining TTL in seconds — Redis's own answer: `-2` when the
    /// key is absent, `-1` when it has no expiry. For tests and diagnostics
    /// that assert a parked value actually expires (FR-88's OAuth parking
    /// spot), not for application logic.
    pub async fn ttl_secs(&self, key: &str) -> Result<i64, redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("TTL").arg(key).query_async(&mut conn).await
    }

    // ── S6 cross-pod online registry ────────────────────────────────
    //
    // `WsStorage::is_connected` only sees THIS pod's sockets. With two
    // pods, the offline-dedupe in `routes/helpers.rs` would push+email
    // every user whose WS lives on the other pod. Each pod mirrors its
    // local user set into Redis: one SET per user
    // (`meshharbor:online:<uid>`) whose members are instance ids, with a
    // key TTL refreshed by a 30 s heartbeat — so a crashed pod's
    // entries age out within `ONLINE_TTL_SECS` instead of leaking
    // forever. The registry is advisory (dedupe/UX), not authoritative
    // presence: a ≤90 s stale window on pod crash is acceptable.

    fn online_key(user_id_hex: &str) -> String {
        format!("meshharbor:online:{user_id_hex}")
    }

    /// Mark a user online from this instance (idempotent) and refresh
    /// the key's TTL.
    pub async fn online_add(&self, user_id_hex: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        let key = Self::online_key(user_id_hex);
        redis::pipe()
            .cmd("SADD")
            .arg(&key)
            .arg(&self.instance_id)
            .ignore()
            .cmd("EXPIRE")
            .arg(&key)
            .arg(ONLINE_TTL_SECS)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
    }

    /// Remove this instance's membership when the user's LAST local
    /// connection closes. Redis drops the set key automatically once
    /// its final member is removed.
    pub async fn online_remove(&self, user_id_hex: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("SREM")
            .arg(Self::online_key(user_id_hex))
            .arg(&self.instance_id)
            .query_async::<()>(&mut conn)
            .await
    }

    /// Whether ANY instance currently claims this user online.
    pub async fn online_anywhere(&self, user_id_hex: &str) -> Result<bool, redis::RedisError> {
        let mut conn = self.publisher.clone();
        let n: i64 = redis::cmd("EXISTS")
            .arg(Self::online_key(user_id_hex))
            .query_async(&mut conn)
            .await?;
        Ok(n > 0)
    }

    // ── Agent presence directory (Phase A-1 / S6 split incident) ────
    //
    // The rc-hub is pod-local, so "is this agent reachable?" was
    // answerable only on the pod holding its WS — the listing badge fell
    // back to heartbeat freshness, which lies (green-but-`agent_offline`,
    // field incidents 2026-07-29 + 2026-08-02). Each pod now mirrors its
    // hub registrations into one Redis STRING per agent:
    //
    //   meshharbor:agent-online:<agent_id_hex> = "<instance_id>:<conn_id>:<since_ms>"
    //
    // Semantics: plain SET (newest-wins — mirrors the Hub's displacement
    // rule where the newest live socket owns the slot); refreshed as a
    // full `SET … EX` on each received heartbeat so a wrongful delete
    // self-heals within one beat; deleted via COMPARE-and-delete on the
    // full value (a bare GET+DEL races a fresh re-home on another pod).
    // Key existence == fresh (TTL-expired keys vanish); the value's
    // instance prefix answers "mine or foreign?". This record is
    // re-derivable from the live socket at any time — Redis is a
    // directory, not a database; every reader must fail-soft to the
    // pod-local answer when Redis is down.

    /// TTL on `meshharbor:agent-online:<id>` — same 3×-heartbeat headroom as
    /// the user registry (agent heartbeats every 30 s).
    const AGENT_TTL_SECS: u64 = 90;

    /// Compare-and-delete: release the key only if we still own it.
    /// The classic single-key lock-release script.
    const AGENT_DEL_SCRIPT: &'static str = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";

    fn agent_key(agent_id_hex: &str) -> String {
        format!("meshharbor:agent-online:{agent_id_hex}")
    }

    /// The owner token this instance writes for one agent registration.
    /// `conn_id` is minted per WS registration, so a reconnect on the
    /// SAME pod still produces a distinct token (the old socket's late
    /// compare-DEL can't release the new socket's claim). C-1: the format
    /// is the canonical directory record `<pod>/<epoch>/<conn>/<since>`
    /// (`cluster::directory::OwnerRecord::parse`able — C-2's rehome reads
    /// the pod out of it). Records only live 90 s, so a mixed-format
    /// deploy window is self-clearing.
    pub fn agent_owner_token(&self, conn_id: &str, since_ms: i64) -> String {
        format!("{}/{}/{}", self.instance_id, conn_id, since_ms)
    }

    /// Claim/refresh this agent's presence record (full SET + TTL —
    /// newest-wins by design).
    pub async fn agent_presence_set(
        &self,
        agent_id_hex: &str,
        owner_token: &str,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("SET")
            .arg(Self::agent_key(agent_id_hex))
            .arg(owner_token)
            .arg("EX")
            .arg(Self::AGENT_TTL_SECS)
            .query_async::<()>(&mut conn)
            .await
    }

    /// Release this agent's presence record IF we still own it (a newer
    /// registration's overwrite survives our late teardown). Returns
    /// whether a delete actually happened.
    pub async fn agent_presence_del_if_owned(
        &self,
        agent_id_hex: &str,
        owner_token: &str,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = self.publisher.clone();
        let n: i64 = redis::Script::new(Self::AGENT_DEL_SCRIPT)
            .key(Self::agent_key(agent_id_hex))
            .arg(owner_token)
            .invoke_async(&mut conn)
            .await?;
        Ok(n > 0)
    }

    /// P4 — whether ANY pod currently claims this agent's presence record.
    /// The teardown path uses this to tell "our compare-DEL lost to a
    /// NEWER registration" (⇒ suppress the offline event) apart from "the
    /// key was already gone" (⇒ the agent really is unreachable).
    pub async fn agent_presence_exists(
        &self,
        agent_id_hex: &str,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = self.publisher.clone();
        let n: i64 = redis::cmd("EXISTS")
            .arg(Self::agent_key(agent_id_hex))
            .query_async(&mut conn)
            .await?;
        Ok(n > 0)
    }

    /// P4 — one-shot NX claim (`SET key <instance> NX EX ttl`) for
    /// cluster-singleton periodic work (the presence staleness sweep).
    /// Returns whether THIS instance won the cycle. Never released — the
    /// TTL is the cycle length, so the claim self-expires.
    pub async fn try_claim(&self, key: &str, ttl_secs: u64) -> Result<bool, redis::RedisError> {
        let mut conn = self.publisher.clone();
        let res: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(&self.instance_id)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await?;
        Ok(res.is_some())
    }

    /// FR-115 P4a — a value every pod reads and one pod writes (`SET key
    /// value EX ttl`). The TTL is the fail-open backstop: a writer that
    /// stops lets the value lapse rather than leave it in force.
    pub async fn kv_set_ex(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs.max(1))
            .query_async::<()>(&mut conn)
            .await
    }

    /// FR-115 P4a — the value at `key`; `None` when absent.
    pub async fn kv_get(&self, key: &str) -> Result<Option<String>, redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("GET").arg(key).query_async(&mut conn).await
    }

    /// FR-115 P4b — publish `message` on any `channel` (coturn's statistics
    /// channels are someone else's; the tests play coturn through this).
    pub async fn publish_to(&self, channel: &str, message: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("PUBLISH")
            .arg(channel)
            .arg(message)
            .query_async::<()>(&mut conn)
            .await
    }

    /// FR-115 P4a — remove `key` (absent is fine).
    pub async fn kv_del(&self, key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.publisher.clone();
        redis::cmd("DEL")
            .arg(key)
            .query_async::<()>(&mut conn)
            .await
    }

    /// Batched presence read for the agent listing: one MGET over all
    /// ids, `Some(owner_token)` per present (⇒ fresh, TTL-enforced) key.
    pub async fn agent_presence_get_many(
        &self,
        agent_id_hexes: &[String],
    ) -> Result<Vec<Option<String>>, redis::RedisError> {
        if agent_id_hexes.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.publisher.clone();
        let mut cmd = redis::cmd("MGET");
        for hex in agent_id_hexes {
            cmd.arg(Self::agent_key(hex));
        }
        cmd.query_async(&mut conn).await
    }

    /// Whether a foreign (other-pod) instance currently owns this agent's
    /// presence record — the split-evidence probe.
    pub async fn agent_presence_foreign(
        &self,
        agent_id_hex: &str,
    ) -> Result<Option<String>, redis::RedisError> {
        let mut conn = self.publisher.clone();
        let v: Option<String> = redis::cmd("GET")
            .arg(Self::agent_key(agent_id_hex))
            .query_async(&mut conn)
            .await?;
        Ok(v.filter(|owner| !owner.starts_with(&self.instance_id)))
    }

    /// Spawn the subscriber task with reconnect-and-backoff. Before S0 a
    /// dropped Redis connection ended the subscription permanently (one
    /// error log, then silent local-only delivery forever). `alive` mirrors
    /// whether a subscription is currently established — read by
    /// `/health/ready`.
    pub fn subscribe_with_reconnect(
        redis_url: String,
        tx: broadcast::Sender<String>,
        alive: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            let mut backoff_secs = 1u64;
            loop {
                match Self::run_subscription(&redis_url, &tx, &alive).await {
                    Ok(()) => {
                        // A live subscription ended (Redis restart / network
                        // blip) — retry promptly.
                        backoff_secs = 1;
                        warn!("Redis Pub/Sub subscription stream ended; reconnecting");
                    }
                    Err(e) => {
                        warn!("Redis Pub/Sub subscribe failed: {e}; retrying in {backoff_secs}s");
                    }
                }
                alive.store(false, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        });
    }

    /// One subscription lifetime: connect, subscribe, pump messages until the
    /// stream ends. `Ok(())` = the subscription was established and later
    /// ended; `Err` = it never got established.
    async fn run_subscription(
        redis_url: &str,
        tx: &broadcast::Sender<String>,
        alive: &AtomicBool,
    ) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(CHANNEL_NAME).await?;
        alive.store(true, Ordering::Relaxed);
        info!("Redis Pub/Sub subscribed to channel: {}", CHANNEL_NAME);

        use futures::StreamExt;
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            match msg.get_payload::<String>() {
                Ok(payload) => {
                    // broadcast::send only fails if there are no receivers,
                    // which is fine — it means no one is listening yet.
                    let _ = tx.send(payload);
                }
                Err(e) => {
                    error!("Failed to decode Redis Pub/Sub payload: {}", e);
                }
            }
        }
        Ok(())
    }
}
