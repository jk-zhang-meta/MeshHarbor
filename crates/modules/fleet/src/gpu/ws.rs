// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Browser WebSocket live GPU push handler (`gpu:subscribe` /
//! `gpu:unsubscribe`).
//!
//! Subscribers authenticate over the existing `/ws` socket (`Role::User`).
//! Visibility is computed with the exact same `visible_tenant_and_shared_gpu_agents`
//! check used by `GET /api/tenant/{tid}/gpu/fleet`, so a socket only ever
//! receives `gpu:update` pushes for GPU servers that user is authorized to view.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bson::oid::ObjectId;
use meshharbor_core::ws::dispatcher::send_to_connection_routed;
use meshharbor_core::{WsCtx, WsHandler};
use meshharbor_remote_control::models::RpcCap;
use serde::Deserialize;

use crate::FleetState;

use super::routes::visible_tenant_and_shared_gpu_agents;

/// Active WebSocket subscription for one browser tab viewing the GPU page.
#[derive(Debug, Clone)]
pub(super) struct GpuWsSubscription {
    pub connection_id: String,
    pub user_id: ObjectId,
    pub tenant_id: ObjectId,
    pub interval_ms: u32,
    /// Authorized `agent_id -> (source, read_only)` snapshot for this subscriber.
    pub visible_agents: HashMap<ObjectId, (&'static str, bool)>,
    pub expires_at: Instant,
}

/// Subscription TTL — browsers renew every ~15 s while visible and unsubscribe
/// explicitly when hidden or leaving the GPU page.
pub(super) const WS_SUB_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
struct SubscribeData {
    tenant_id: String,
    #[serde(default)]
    interval_ms: Option<u32>,
}

/// FR-69 namespace handler for `gpu:*` browser WebSocket frames.
pub struct GpuWs {
    pub state: FleetState,
}

#[async_trait]
impl WsHandler for GpuWs {
    async fn handle(&self, ctx: &WsCtx, msg: serde_json::Value) -> anyhow::Result<()> {
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match msg_type {
            "gpu:subscribe" => {
                if !self.state.gpu.settings.enabled {
                    return Ok(());
                }
                let Some(data) = msg.get("data").cloned() else {
                    return Ok(());
                };
                let Ok(req) = serde_json::from_value::<SubscribeData>(data) else {
                    return Ok(());
                };
                let Ok(tid) = ObjectId::parse_str(req.tenant_id.trim()) else {
                    return Ok(());
                };

                let entries =
                    match visible_tenant_and_shared_gpu_agents(&self.state, tid, ctx.principal)
                        .await
                    {
                        Ok(e) => e,
                        Err(_) => return Ok(()),
                    };

                let interval_ms = self.state.gpu.effective_viewer_interval_ms(req.interval_ms);
                let mut visible_agents = HashMap::with_capacity(entries.len());
                let mut lease_targets = Vec::with_capacity(entries.len());
                for (agent, source, read_only) in entries {
                    if let Some(aid) = agent.id {
                        visible_agents.insert(aid, (source, read_only));
                        lease_targets.push((aid, agent.capabilities.has_rpc(RpcCap::Gpu)));
                    }
                }
                let host_count = visible_agents.len();

                self.state.gpu.upsert_ws_subscription(
                    &self.state.rc_hub,
                    GpuWsSubscription {
                        connection_id: ctx.connection_id.clone(),
                        user_id: ctx.principal,
                        tenant_id: tid,
                        interval_ms,
                        visible_agents,
                        expires_at: Instant::now() + WS_SUB_TTL,
                    },
                    &lease_targets,
                );

                let ack = serde_json::json!({
                    "type": "gpu:subscribed",
                    "data": {
                        "tenant_id": tid.to_hex(),
                        "interval_ms": interval_ms,
                        "host_count": host_count,
                    }
                });
                send_to_connection_routed(
                    &self.state.core.ws_storage,
                    &self.state.core.redis_pubsub,
                    &ctx.connection_id,
                    &ack,
                )
                .await;
                Ok(())
            }
            "gpu:unsubscribe" => {
                self.state
                    .gpu
                    .remove_ws_subscription(&self.state.rc_hub, &ctx.connection_id);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn closed(&self, ctx: &WsCtx) {
        self.state
            .gpu
            .remove_ws_subscription(&self.state.rc_hub, &ctx.connection_id);
    }
}
