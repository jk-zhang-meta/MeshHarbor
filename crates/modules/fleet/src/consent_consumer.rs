// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Phase 4 — the owner-side consent consumer: the Hub emits a `ConsentEvent`
//! for each Email/Push session; this task resolves the owner, persists a
//! `ConsentRequest` row and sends the email / web-push, plus an in-app
//! notification. FR-69 P5a — moved from the host's `state.rs` unchanged.

use std::sync::Arc;

use meshharbor_remote_control::models::ConsentMode;
use meshharbor_services::{
    EmailService, PushService,
    dao::{
        agent::AgentDao, consent_request::ConsentRequestDao, notification::NotificationDao,
        push_subscription::PushSubscriptionDao, user::UserDao,
    },
};
use meshharbor_core::ws::{redis_pubsub::RedisPubSub, storage::WsStorage};
use tokio::sync::mpsc;

use crate::hub::ConsentEvent;

/// Dependencies the Phase-4 owner-consent consumer needs — cheap `Arc` clones of
/// the relevant DAOs / services, captured at module init.
pub struct ConsentConsumerDeps {
    pub agents: Arc<AgentDao>,
    pub users: Arc<UserDao>,
    pub consent_requests: Arc<ConsentRequestDao>,
    pub push_subscriptions: Arc<PushSubscriptionDao>,
    pub email: Option<Arc<EmailService>>,
    pub push: Option<Arc<PushService>>,
    pub base_url: String,
    /// P4 — the owner also gets an IN-APP notification row + `notification:new`
    /// WS push (the email/web-push above are useless when the owner is sitting
    /// in the app on another org's page).
    pub notifications: Arc<NotificationDao>,
    pub ws_storage: Arc<WsStorage>,
    pub redis_pubsub: Option<Arc<RedisPubSub>>,
}

/// P4 — persist an in-app Notification for the device owner and push it over
/// WS (`notification:new`, same payload shape as `routes::helpers`). Consent
/// requests carry the approve/deny page as their link; break-glass notices
/// link the device list. Best-effort — the email/push legs stay authoritative.
async fn consent_in_app_notification(
    deps: &ConsentConsumerDeps,
    ev: &ConsentEvent,
    owner_id: bson::oid::ObjectId,
    title: String,
    body: String,
    link: String,
) {
    let created = deps
        .notifications
        .create(
            ev.tenant_id,
            owner_id,
            meshharbor_db::models::NotificationType::ConsentRequest,
            title,
            body,
            Some(link),
            meshharbor_db::models::NotificationSource {
                entity_type: "remote_session".to_string(),
                entity_id: ev.session_id,
                actor_id: Some(ev.controller_user_id),
            },
        )
        .await;
    match created {
        Ok(n) => {
            let event = serde_json::json!({
                "type": "notification:new",
                "data": {
                    "id": n.id.map(|i| i.to_hex()).unwrap_or_default(),
                    "tenant_id": ev.tenant_id.to_hex(),
                    "title": n.title,
                    "body": n.body,
                    "link": n.link,
                    "notification_type": "consent_request",
                    "created_at": n.created_at.try_to_rfc3339_string().unwrap_or_default(),
                }
            });
            meshharbor_core::ws::dispatcher::send_to_user_with_redis(
                &deps.ws_storage,
                &deps.redis_pubsub,
                &owner_id,
                &event,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(session = %ev.session_id, %e, "consent in-app notification failed");
        }
    }
}

/// Spawn the background task that turns Hub [`ConsentEvent`]s (Email/Push sessions
/// awaiting the device owner) into a `ConsentRequest` row + an email / web-push
/// carrying the approve-link. One task for the process lifetime; a per-event
/// failure is logged, never fatal.
pub fn spawn_consent_consumer(mut rx: mpsc::Receiver<ConsentEvent>, deps: ConsentConsumerDeps) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Err(e) = handle_consent_event(&deps, &ev).await {
                tracing::warn!(session = %ev.session_id, %e, "owner-consent notification failed");
            }
        }
    });
}

pub async fn handle_consent_event(
    deps: &ConsentConsumerDeps,
    ev: &ConsentEvent,
) -> anyhow::Result<()> {
    // Resolve the device owner + display name (the Hub is DB-agnostic, so it
    // only knows the agent_id).
    let agent = deps.agents.base.find_by_id(ev.agent_id).await?;
    let owner_id = agent.owner_user_id;
    let device_name = agent.name.clone();

    // Phase 5 — break-glass NOTICE: an admin already forced the session, so this
    // is informational (no approval, no ConsentRequest). Tell the owner their
    // device was accessed + why, then we're done.
    if let Some(reason) = &ev.override_reason {
        consent_in_app_notification(
            deps,
            ev,
            owner_id,
            "Device accessed (admin override)".to_string(),
            format!(
                "{} accessed {} via admin break-glass. Reason: {}",
                ev.controller_name, device_name, reason
            ),
            format!("/tenant/{}/devices", ev.tenant_id.to_hex()),
        )
        .await;
        if let Some(email) = &deps.email {
            let owner = deps.users.base.find_by_id(owner_id).await?;
            let _ = email
                .send_override_notice(&owner.email, &ev.controller_name, &device_name, reason)
                .await;
        }
        if let Some(push) = &deps.push {
            let subs = deps
                .push_subscriptions
                .find_by_user(owner_id)
                .await
                .unwrap_or_default();
            let body = format!(
                "{} accessed {} via admin break-glass. Reason: {}",
                ev.controller_name, device_name, reason
            );
            for sub in subs {
                let _ = push
                    .send(
                        &sub.endpoint,
                        &sub.keys.auth,
                        &sub.keys.p256dh,
                        "Device accessed (admin override)",
                        &body,
                        None,
                    )
                    .await;
            }
        }
        return Ok(());
    }

    // Persist the request with a fresh capability token + a TTL that matches the
    // session's consent window (a stale link can't resolve a long-gone session).
    let req = deps
        .consent_requests
        .create(
            ev.tenant_id,
            ev.session_id,
            ev.agent_id,
            ev.controller_user_id,
            ev.controller_name.clone(),
            owner_id,
            ev.timeout_secs as i64,
        )
        .await?;

    let consent_url = format!(
        "{}/consent/{}",
        deps.base_url.trim_end_matches('/'),
        req.token
    );

    // P4 — in-app row + WS for the owner alongside the email/push leg. The
    // link is the RELATIVE approve/deny page (in-app navigation).
    consent_in_app_notification(
        deps,
        ev,
        owner_id,
        "Remote control request".to_string(),
        format!("{} wants to control {}", ev.controller_name, device_name),
        format!("/consent/{}", req.token),
    )
    .await;

    match ev.mode {
        // Email + PromptThenEmail both email the owner an approve-link. For
        // PromptThenEmail the agent ALSO prompts on the host in parallel — either
        // the person at the console or the owner via the link can approve, first
        // wins (both resolve the same slot within the shared timeout).
        ConsentMode::Email | ConsentMode::PromptThenEmail => {
            let owner = deps.users.base.find_by_id(owner_id).await?;
            match &deps.email {
                Some(email) => {
                    email
                        .send_consent_request(
                            &owner.email,
                            &ev.controller_name,
                            &device_name,
                            &consent_url,
                        )
                        .await?;
                }
                None => tracing::warn!(
                    session = %ev.session_id,
                    "Email consent mode but no email service is configured — owner cannot approve"
                ),
            }
        }
        ConsentMode::Push => match &deps.push {
            Some(push) => {
                let subs = deps.push_subscriptions.find_by_user(owner_id).await?;
                if subs.is_empty() {
                    tracing::warn!(
                        session = %ev.session_id,
                        "Push consent mode but the owner has no push subscriptions"
                    );
                }
                let title = "Remote control request";
                let body = format!("{} wants to control {}", ev.controller_name, device_name);
                for sub in subs {
                    // Best-effort per subscription (a stale endpoint shouldn't
                    // block the others).
                    let _ = push
                        .send(
                            &sub.endpoint,
                            &sub.keys.auth,
                            &sub.keys.p256dh,
                            title,
                            &body,
                            Some(&consent_url),
                        )
                        .await;
                }
            }
            None => tracing::warn!(
                session = %ev.session_id,
                "Push consent mode but no push service is configured — owner cannot approve"
            ),
        },
        // The Hub only emits events for Email/Push; other modes never reach here.
        _ => {}
    }

    Ok(())
}
