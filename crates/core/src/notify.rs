// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! In-app notifications with their offline fallbacks (web push, email), the
//! way chat mentions and call starts use them.
//!
//! FR-69 P3 — moved from the api crate's `routes/helpers.rs` unchanged. Core
//! because two modules need it (`chat` for mentions, `conference` for call
//! starts) and it is notifications infrastructure: the `notifications` DAO,
//! the socket fan-out, push and email are all core's.

use bson::oid::ObjectId;
use meshharbor_db::models::{NotificationSource, NotificationType};

use crate::{Core, ws};

/// Parameters for creating and dispatching notifications.
pub struct NotifyParams {
    pub tenant_id: ObjectId,
    pub notification_type: NotificationType,
    pub title: String,
    pub body: String,
    pub link: String,
    pub source: NotificationSource,
    pub ws_type_label: &'static str,
}

/// Create a notification for a single user and send it via WebSocket.
/// S6 — cross-pod connectivity check for the offline push/email dedupe.
/// Local sockets win (fast path); otherwise consult the Redis online
/// registry so a user whose WS lives on the OTHER pod isn't spammed
/// with push+email for every mention. Registry unavailable → treat as
/// offline (matches the pre-S6 single-pod behaviour of "not here = not
/// connected").
async fn user_online_anywhere(state: &Core, user_id: &ObjectId) -> bool {
    if state.ws_storage.is_connected(user_id) {
        return true;
    }
    if let Some(pubsub) = &state.redis_pubsub
        && let Ok(online) = pubsub.online_anywhere(&user_id.to_hex()).await
    {
        return online;
    }
    false
}

async fn create_and_send_notification(
    state: &Core,
    params: &NotifyParams,
    user_id: ObjectId,
) -> bool {
    match state
        .notifications
        .create(
            params.tenant_id,
            user_id,
            params.notification_type.clone(),
            params.title.clone(),
            params.body.clone(),
            Some(params.link.clone()),
            params.source.clone(),
        )
        .await
    {
        Ok(notification) => {
            let notif_event = serde_json::json!({
                "type": "notification:new",
                "data": {
                    "id": notification.id.unwrap().to_hex(),
                    // P4 — clients route non-active-org notifications into the
                    // per-org badge store; without the tenant they can't.
                    "tenant_id": params.tenant_id.to_hex(),
                    "title": notification.title,
                    "body": notification.body,
                    "link": notification.link,
                    "notification_type": params.ws_type_label,
                    "created_at": notification.created_at.try_to_rfc3339_string().unwrap_or_default(),
                }
            });
            ws::dispatcher::send_to_user_with_redis(
                &state.ws_storage,
                &state.redis_pubsub,
                &user_id,
                &notif_event,
            )
            .await;
            true
        }
        Err(e) => {
            tracing::error!(
                "Failed to create {} notification for {}: {}",
                params.ws_type_label,
                user_id,
                e
            );
            false
        }
    }
}

/// Send push notifications for a list of offline user IDs (spawns a background task).
fn spawn_push_for_offline(
    state: &Core,
    offline_user_ids: Vec<ObjectId>,
    title: String,
    body: String,
    link: String,
) {
    if offline_user_ids.is_empty() {
        return;
    }
    if let Some(ref push_svc) = state.push {
        let push = push_svc.clone();
        let subs_dao = state.push_subscriptions.clone();
        tokio::spawn(async move {
            if let Ok(subs) = subs_dao.find_by_users(&offline_user_ids).await {
                for sub in subs {
                    let _ = push
                        .send(
                            &sub.endpoint,
                            &sub.keys.auth,
                            &sub.keys.p256dh,
                            &title,
                            &body,
                            Some(&link),
                        )
                        .await;
                }
            }
        });
    }
}

/// Send email notification for a single offline user about a mention (spawns a background task).
fn spawn_mention_email(
    state: &Core,
    user_id: ObjectId,
    mentioner_name: String,
    room_name: String,
    preview: String,
    tenant_id_str: &str,
    room_id_str: &str,
) {
    if let Some(ref email_svc) = state.email {
        let email_svc = email_svc.clone();
        let users = state.users.clone();
        let link_url = format!(
            "{}/tenant/{}/room/{}",
            state.settings.oauth.base_url, tenant_id_str, room_id_str
        );
        tokio::spawn(async move {
            if let Ok(user) = users.base.find_by_id(user_id).await
                && let Err(e) = email_svc
                    .send_mention_notification(
                        &user.email,
                        &mentioner_name,
                        &room_name,
                        &preview,
                        &link_url,
                    )
                    .await
            {
                tracing::warn!(%e, "Failed to send mention email");
            }
        });
    }
}

/// Create notifications and send push/email for mentioned users in a message.
#[allow(clippy::too_many_arguments)]
pub async fn notify_mentions(
    state: &Core,
    tenant_id: ObjectId,
    _room_id: ObjectId,
    message_id: ObjectId,
    author_id: ObjectId,
    mentioned_user_ids: &[ObjectId],
    room_name: &str,
    content_preview: &str,
    mentioner_name: &str,
    tenant_id_str: &str,
    room_id_str: &str,
) {
    let params = NotifyParams {
        tenant_id,
        notification_type: NotificationType::Mention,
        title: format!("Mentioned in #{}", room_name),
        body: content_preview.chars().take(200).collect(),
        link: format!(
            "/tenant/{}/room/{}?msg={}",
            tenant_id_str,
            room_id_str,
            message_id.to_hex()
        ),
        source: NotificationSource {
            entity_type: "message".to_string(),
            entity_id: message_id,
            actor_id: Some(author_id),
        },
        ws_type_label: "mention",
    };

    let mut offline_ids = Vec::new();

    for user_id in mentioned_user_ids {
        if *user_id == author_id {
            continue;
        }

        create_and_send_notification(state, &params, *user_id).await;

        if !user_online_anywhere(state, user_id).await {
            spawn_mention_email(
                state,
                *user_id,
                mentioner_name.to_string(),
                room_name.to_string(),
                params.body.clone(),
                tenant_id_str,
                room_id_str,
            );
            offline_ids.push(*user_id);
        }
    }

    spawn_push_for_offline(
        state,
        offline_ids,
        params.title,
        params.body,
        format!("/tenant/{}/room/{}", tenant_id_str, room_id_str),
    );
}

/// Create call-started notifications for room members and send push to offline users.
#[allow(clippy::too_many_arguments)]
pub async fn notify_call_started(
    state: &Core,
    tenant_id: ObjectId,
    room_id: ObjectId,
    caller_id: ObjectId,
    member_ids: &[ObjectId],
    room_name: &str,
    caller_name: &str,
    tenant_id_str: &str,
    room_id_str: &str,
) {
    let params = NotifyParams {
        tenant_id,
        notification_type: NotificationType::Call,
        title: format!("Call started in #{}", room_name),
        body: format!("{} started a call", caller_name),
        link: format!("/tenant/{}/room/{}/call", tenant_id_str, room_id_str),
        source: NotificationSource {
            entity_type: "room".to_string(),
            entity_id: room_id,
            actor_id: Some(caller_id),
        },
        ws_type_label: "call",
    };

    let mut offline_ids = Vec::new();

    for uid in member_ids {
        if *uid == caller_id {
            continue;
        }

        create_and_send_notification(state, &params, *uid).await;

        if !user_online_anywhere(state, uid).await {
            offline_ids.push(*uid);
        }
    }

    spawn_push_for_offline(state, offline_ids, params.title, params.body, params.link);
}

/// Who also gets a web push, beyond the in-app notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushTo {
    /// Only the users with no socket anywhere — a mention, a call.
    Offline,
    /// Everyone notified: for a notification whose whole point is reaching
    /// a person away from the screen (FR-90's approvals — a desk with the
    /// app open is not a phone in a pocket).
    Everyone,
}

/// Notify `users` in the app and over their sockets, and by web push as
/// `push` says. No email: what needs a person NOW is not an email.
pub async fn notify_users(state: &Core, params: &NotifyParams, users: &[ObjectId], push: PushTo) {
    let mut pushed = Vec::new();
    for user_id in users {
        create_and_send_notification(state, params, *user_id).await;
        if push == PushTo::Everyone || !user_online_anywhere(state, user_id).await {
            pushed.push(*user_id);
        }
    }
    spawn_push_for_offline(
        state,
        pushed,
        params.title.clone(),
        params.body.clone(),
        params.link.clone(),
    );
}
