// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! C-1 — the inter-pod control bus: per-pod Redis channels + a thin
//! request/reply layer.
//!
//! Each pod subscribes to `meshharbor:pod:<pod_id>` (STABLE across restarts —
//! a new process re-subscribes to the same channel and NACKs requests for
//! entities it doesn't hold, actively pruning the previous epoch's stale
//! directory records). Envelope:
//!
//! ```json
//! {"v":1, "origin":"<pod/epoch>", "kind":"req"|"rep", "class":"sys"|...,
//!  "corr":"<uuid>", "reply_to":"<pod_id>", "conn":null, "body":{...}}
//! ```
//!
//! Delivery class: at-most-once, per-publisher FIFO (Redis pub/sub), no
//! bus-level retries — every consumer path has a redial/retry fallback.
//! **The RPC deadline is the active failure detector**: a timed-out
//! request means the owner is presumed dead; callers compare-DEL the
//! directory record they acted on and fall back per subsystem. Control
//! frames ONLY — no data plane on the bus, ever.
//!
//! C-1 ships the transport + `sys.ping` (the test surface) + NACK for
//! unknown classes. Real consumers arrive with C-2 (rc nudge), C-4
//! (media command routing) and C-5 (derp rehome).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use super::identity::PodIdentity;

/// Default RPC deadline. Media ops that create routers/transports use
/// [`PodBus::request_with_deadline`] and 5 s.
pub const RPC_DEADLINE: Duration = Duration::from_secs(2);

/// Pod-alive advisory record cadence (never the primary detector).
pub const POD_ALIVE_TTL_SECS: u64 = 45;
pub const POD_ALIVE_REFRESH: Duration = Duration::from_secs(15);

fn pod_channel(pod_id: &str) -> String {
    format!("meshharbor:pod:{pod_id}")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub origin: String,
    pub kind: String, // "req" | "rep"
    pub class: String,
    pub corr: String,
    /// Pod id to publish the reply onto (req only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Connection-id addressing (C-4 media events); unused in C-1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn: Option<String>,
    pub body: serde_json::Value,
}

/// Errors a requester can see.
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("bus rpc deadline elapsed ({0:?}) — owner presumed dead")]
    Deadline(Duration),
    #[error("bus unavailable: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("owner NACKed: {0}")]
    Nack(String),
}

/// Handler for one `class` of requests. Returns the reply body, or
/// `Err(reason)` → a structured NACK.
pub type ReqHandler = Arc<
    dyn Fn(
            serde_json::Value,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send>,
        > + Send
        + Sync,
>;

pub struct PodBus {
    identity: PodIdentity,
    publisher: ConnectionManager,
    pending: DashMap<String, oneshot::Sender<Result<serde_json::Value, String>>>,
    handlers: DashMap<String, ReqHandler>,
    /// Mirrors whether the per-pod subscription is live (readiness /
    /// fail-soft signal for callers).
    pub sub_alive: Arc<AtomicBool>,
}

impl PodBus {
    /// Construct + spawn the subscriber and the pod-alive heartbeat.
    /// `redis_url` gets its own subscription connection (a pub/sub
    /// connection can't multiplex commands).
    pub fn start(
        identity: PodIdentity,
        publisher: ConnectionManager,
        redis_url: String,
    ) -> Arc<Self> {
        let bus = Arc::new(Self {
            identity,
            publisher,
            pending: DashMap::new(),
            handlers: DashMap::new(),
            sub_alive: Arc::new(AtomicBool::new(false)),
        });

        // sys.ping — the C-1 test/diagnostic surface.
        bus.register("sys.ping", |body| {
            Box::pin(async move { Ok(serde_json::json!({ "pong": body })) })
        });

        // Subscriber with reconnect-and-backoff (same discipline as the
        // global channel's subscriber in redis_pubsub.rs).
        {
            let bus = bus.clone();
            tokio::spawn(async move {
                let channel = pod_channel(&bus.identity.pod_id);
                let mut backoff = 1u64;
                loop {
                    match Self::run_subscription(&bus, &redis_url, &channel).await {
                        Ok(()) => {
                            backoff = 1;
                            warn!(%channel, "pod bus subscription ended; reconnecting");
                        }
                        Err(e) => {
                            warn!(%channel, %e, "pod bus subscribe failed; retrying in {backoff}s");
                        }
                    }
                    bus.sub_alive.store(false, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
                }
            });
        }

        // Pod-alive advisory key.
        {
            let bus = bus.clone();
            tokio::spawn(async move {
                let key = super::directory::pod_alive_key(&bus.identity.pod_id);
                loop {
                    let mut conn = bus.publisher.clone();
                    let _ = redis::cmd("SET")
                        .arg(&key)
                        .arg(bus.identity.origin())
                        .arg("EX")
                        .arg(POD_ALIVE_TTL_SECS)
                        .query_async::<()>(&mut conn)
                        .await;
                    tokio::time::sleep(POD_ALIVE_REFRESH).await;
                }
            });
        }

        bus
    }

    pub fn pod_id(&self) -> &str {
        &self.identity.pod_id
    }

    pub fn origin(&self) -> String {
        self.identity.origin()
    }

    /// Register the handler for one request class (later stages: `rc.*`,
    /// `media.*`, `derp.*`). Last registration wins.
    pub fn register<F>(&self, class: &str, handler: F)
    where
        F: Fn(
                serde_json::Value,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send>,
            > + Send
            + Sync
            + 'static,
    {
        self.handlers.insert(class.to_string(), Arc::new(handler));
    }

    /// Request/reply against `target_pod` with the default deadline.
    pub async fn request(
        &self,
        target_pod: &str,
        class: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, BusError> {
        self.request_with_deadline(target_pod, class, body, RPC_DEADLINE)
            .await
    }

    pub async fn request_with_deadline(
        &self,
        target_pod: &str,
        class: &str,
        body: serde_json::Value,
        deadline: Duration,
    ) -> Result<serde_json::Value, BusError> {
        let corr = uuid::Uuid::new_v4().simple().to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.insert(corr.clone(), tx);

        let env = Envelope {
            v: 1,
            origin: self.identity.origin(),
            kind: "req".into(),
            class: class.into(),
            corr: corr.clone(),
            reply_to: Some(self.identity.pod_id.clone()),
            conn: None,
            body,
        };
        let payload = serde_json::to_string(&env).expect("envelope serializes");
        let publish = async {
            let mut conn = self.publisher.clone();
            redis::cmd("PUBLISH")
                .arg(pod_channel(target_pod))
                .arg(&payload)
                .query_async::<()>(&mut conn)
                .await
        };
        if let Err(e) = publish.await {
            self.pending.remove(&corr);
            return Err(BusError::Redis(e));
        }

        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(nack))) => Err(BusError::Nack(nack)),
            // Sender dropped without reply — treat as deadline-class.
            Ok(Err(_)) => {
                super::metrics::bump(&super::metrics::BUS_DEADLINE_TOTAL);
                Err(BusError::Deadline(deadline))
            }
            Err(_) => {
                self.pending.remove(&corr);
                super::metrics::bump(&super::metrics::BUS_DEADLINE_TOTAL);
                Err(BusError::Deadline(deadline))
            }
        }
    }

    async fn run_subscription(
        bus: &Arc<Self>,
        redis_url: &str,
        channel: &str,
    ) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(channel).await?;
        bus.sub_alive.store(true, Ordering::Relaxed);
        info!(%channel, pod = %bus.identity.pod_id, "pod bus subscribed");

        use futures::StreamExt;
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let Ok(payload) = msg.get_payload::<String>() else {
                continue;
            };
            let Ok(env) = serde_json::from_str::<Envelope>(&payload) else {
                debug!("pod bus: undecodable envelope dropped");
                continue;
            };
            // A restarted process must ignore ITS OWN stale in-flight
            // messages only by corr-miss; same-origin reqs are legal
            // (self-RPC is pointless but harmless).
            match env.kind.as_str() {
                "rep" => {
                    if let Some((_, tx)) = bus.pending.remove(&env.corr) {
                        let res = if let Some(nack) = env.body.get("nack").and_then(|n| n.as_str())
                        {
                            Err(nack.to_string())
                        } else {
                            Ok(env.body)
                        };
                        let _ = tx.send(res);
                    }
                }
                "req" => {
                    let Some(reply_to) = env.reply_to.clone() else {
                        continue;
                    };
                    let handler = bus.handlers.get(&env.class).map(|h| h.clone());
                    let bus2 = bus.clone();
                    tokio::spawn(async move {
                        let body = match handler {
                            Some(h) => h(env.body).await,
                            // Unknown class / entity ⇒ structured NACK, so
                            // a caller learns "not here" instead of eating
                            // the deadline (and can prune stale records).
                            None => Err(format!("no handler for class {}", env.class)),
                        };
                        let rep = Envelope {
                            v: 1,
                            origin: bus2.identity.origin(),
                            kind: "rep".into(),
                            class: env.class,
                            corr: env.corr,
                            reply_to: None,
                            conn: None,
                            body: match body {
                                Ok(v) => v,
                                Err(nack) => serde_json::json!({ "nack": nack }),
                            },
                        };
                        let payload = serde_json::to_string(&rep).expect("envelope serializes");
                        let mut conn = bus2.publisher.clone();
                        let _ = redis::cmd("PUBLISH")
                            .arg(pod_channel(&reply_to))
                            .arg(&payload)
                            .query_async::<()>(&mut conn)
                            .await;
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}
