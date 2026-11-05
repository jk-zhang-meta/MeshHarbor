// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Audit log writer + the `remote_sessions` row projection.
//!
//! Audit writes must never block a session-control path. We fan them through
//! a bounded mpsc channel with a background flusher. Backpressure: if the
//! channel is full, we drop the event and log a warning — better than
//! stalling input forwarding.
//!
//! Multi-user P3 — the SAME event stream now maintains the durable
//! [`RemoteSession`] rows (`remote_sessions` was write-dead since v1: the
//! DAO had zero call sites, so `GET session` / `session_audit` 404'd on a
//! collection that was never populated). Projecting from the audit stream
//! rather than sprinkling DAO calls through the Hub gets every terminate
//! path — reaps, watchdogs, admin kicks, cross-pod ctrl — for free, because
//! they all emit `SessionEnded`.

use bson::{DateTime, doc, oid::ObjectId};
use mongodb::{Collection, Database};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::models::{AuditKind, EndReason, RemoteAuditEvent, RemoteSession, SessionPhase};

const AUDIT_BUFFER: usize = 4096;

#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<RemoteAuditEvent>,
}

impl AuditSink {
    /// In-memory test seam: no database client, flusher task, or network IO.
    /// Available to downstream crate tests, where dependency cfg(test) is off.
    #[doc(hidden)]
    pub fn channel_for_tests() -> (Self, mpsc::Receiver<RemoteAuditEvent>) {
        let (tx, rx) = mpsc::channel(AUDIT_BUFFER);
        (Self { tx }, rx)
    }

    /// Spawns the background flusher. Drop the returned JoinHandle on shutdown.
    pub fn spawn(db: Database) -> (Self, tokio::task::JoinHandle<()>) {
        let coll: Collection<RemoteAuditEvent> = db.collection(RemoteAuditEvent::COLLECTION);
        let sessions: Collection<RemoteSession> = db.collection(RemoteSession::COLLECTION);
        let (tx, mut rx) = mpsc::channel::<RemoteAuditEvent>(AUDIT_BUFFER);

        let handle = tokio::spawn(async move {
            // Batch up to 64 events or 200ms, whichever first.
            let mut buf = Vec::with_capacity(64);
            loop {
                let timeout = tokio::time::sleep(std::time::Duration::from_millis(200));
                tokio::pin!(timeout);

                tokio::select! {
                    maybe = rx.recv() => match maybe {
                        Some(ev) => {
                            buf.push(ev);
                            // drain anything else available without awaiting
                            while let Ok(more) = rx.try_recv() {
                                buf.push(more);
                                if buf.len() >= 64 { break; }
                            }
                            if buf.len() >= 64 {
                                flush(&coll, &sessions, &mut buf).await;
                            }
                        }
                        None => {
                            // channel closed
                            if !buf.is_empty() { flush(&coll, &sessions, &mut buf).await; }
                            break;
                        }
                    },
                    _ = &mut timeout => {
                        if !buf.is_empty() { flush(&coll, &sessions, &mut buf).await; }
                    }
                }
            }
        });

        (Self { tx }, handle)
    }

    pub fn record(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        event: AuditKind,
    ) {
        let ev = RemoteAuditEvent {
            id: None,
            session_id,
            agent_id,
            tenant_id,
            at: DateTime::now(),
            event,
        };
        if let Err(e) = self.tx.try_send(ev) {
            warn!("audit channel full, dropping event: {e}");
        }
    }
}

async fn flush(
    coll: &Collection<RemoteAuditEvent>,
    sessions: &Collection<RemoteSession>,
    buf: &mut Vec<RemoteAuditEvent>,
) {
    // Project session mutations BEFORE draining the buffer into the audit
    // insert. Session events are low-rate (a handful per minute at fleet
    // scale), so per-event updates are fine; every write is best-effort —
    // the projection is a VIEW of the audit truth, never a gate on it.
    for ev in buf.iter() {
        project_session(sessions, ev).await;
    }
    if let Err(e) = coll.insert_many(buf.drain(..)).await {
        error!("audit insert_many failed: {e}");
    }
}

/// Multi-user P3 — apply one audit event to the `remote_sessions` row it
/// concerns. Upsert-shaped so replays / out-of-order flushes degrade to
/// no-ops rather than duplicates (`_id` = the session id).
async fn project_session(sessions: &Collection<RemoteSession>, ev: &RemoteAuditEvent) {
    let res = match &ev.event {
        AuditKind::SessionRequested {
            controller_user_id,
            permissions,
            ..
        } => {
            let row = RemoteSession {
                id: Some(ev.session_id),
                agent_id: ev.agent_id,
                tenant_id: ev.tenant_id,
                controller_user_id: *controller_user_id,
                watchers: Vec::new(),
                permissions: *permissions,
                phase: SessionPhase::AwaitingConsent,
                created_at: ev.at,
                started_at: None,
                ended_at: None,
                end_reason: None,
                recording_url: None,
                stats: Default::default(),
                // FR-102 P9c — recorded by the live stats merge once the
                // session reaches Active; absent at creation.
                carrier: None,
            };
            let doc = match bson::to_document(&row) {
                Ok(d) => d,
                Err(e) => {
                    debug!(%e, "audit: session row serialise failed");
                    return;
                }
            };
            sessions
                .update_one(doc! { "_id": ev.session_id }, doc! { "$setOnInsert": doc })
                .upsert(true)
                .await
                .map(|_| ())
        }
        AuditKind::ConsentGranted => set_phase(sessions, ev, SessionPhase::Negotiating).await,
        AuditKind::SessionStarted { .. } => sessions
            .update_one(
                doc! { "_id": ev.session_id },
                doc! { "$set": {
                    "phase": bson::to_bson(&SessionPhase::Active).unwrap_or(bson::Bson::Null),
                    "started_at": ev.at,
                }},
            )
            .await
            .map(|_| ()),
        AuditKind::ConsentDenied => end_session(sessions, ev, EndReason::UserDenied).await,
        AuditKind::ConsentTimedOut => end_session(sessions, ev, EndReason::ConsentTimeout).await,
        AuditKind::SessionEnded { reason, .. } => end_session(sessions, ev, *reason).await,
        AuditKind::PermissionsChanged { permissions } => sessions
            .update_one(
                doc! { "_id": ev.session_id },
                doc! { "$set": {
                    "permissions": bson::to_bson(permissions).unwrap_or(bson::Bson::Null),
                }},
            )
            .await
            .map(|_| ()),
        AuditKind::WatcherJoined { user_id } => sessions
            .update_one(
                doc! { "_id": ev.session_id },
                doc! { "$addToSet": { "watchers": user_id } },
            )
            .await
            .map(|_| ()),
        AuditKind::WatcherLeft { user_id } => sessions
            .update_one(
                doc! { "_id": ev.session_id },
                doc! { "$pull": { "watchers": user_id } },
            )
            .await
            .map(|_| ()),
        // Prompted / clipboard / files / keyframe / override events don't
        // change the session row.
        _ => Ok(()),
    };
    if let Err(e) = res {
        debug!(session = %ev.session_id, %e, "audit: session projection write failed");
    }
}

async fn set_phase(
    sessions: &Collection<RemoteSession>,
    ev: &RemoteAuditEvent,
    phase: SessionPhase,
) -> Result<(), mongodb::error::Error> {
    sessions
        .update_one(
            doc! { "_id": ev.session_id },
            doc! { "$set": { "phase": bson::to_bson(&phase).unwrap_or(bson::Bson::Null) } },
        )
        .await
        .map(|_| ())
}

async fn end_session(
    sessions: &Collection<RemoteSession>,
    ev: &RemoteAuditEvent,
    reason: EndReason,
) -> Result<(), mongodb::error::Error> {
    sessions
        .update_one(
            doc! { "_id": ev.session_id },
            doc! { "$set": {
                "phase": bson::to_bson(&SessionPhase::Closed).unwrap_or(bson::Bson::Null),
                "ended_at": ev.at,
                "end_reason": bson::to_bson(&reason).unwrap_or(bson::Bson::Null),
            }},
        )
        .await
        .map(|_| ())
}
