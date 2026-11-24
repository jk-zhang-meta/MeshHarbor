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

/// One event on its way to the flusher, and whether its session row is
/// projected from it.
struct Queued {
    ev: RemoteAuditEvent,
    /// FR-130 — `false` for an event whose row its writer already wrote
    /// itself ([`AuditSink::record_trail`]): the audit keeps the event, and
    /// the row is left as the writer left it.
    project: bool,
}

/// The receiving end of [`AuditSink::channel_for_tests`]: holding it keeps
/// the sink's channel open, and nothing reads it.
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub struct AuditTestRx(#[allow(dead_code)] mpsc::Receiver<Queued>);

#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<Queued>,
}

impl AuditSink {
    /// In-memory test seam: no database client, flusher task, or network IO.
    /// Downstream crate tests explicitly enable `test-fixtures` because a
    /// dependency does not inherit their `cfg(test)`.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn channel_for_tests() -> (Self, AuditTestRx) {
        let (tx, rx) = mpsc::channel(AUDIT_BUFFER);
        (Self { tx }, AuditTestRx(rx))
    }

    /// Spawns the background flusher. Drop the returned JoinHandle on shutdown.
    pub fn spawn(db: Database) -> (Self, tokio::task::JoinHandle<()>) {
        let coll: Collection<RemoteAuditEvent> = db.collection(RemoteAuditEvent::COLLECTION);
        let sessions: Collection<RemoteSession> = db.collection(RemoteSession::COLLECTION);
        let (tx, mut rx) = mpsc::channel::<Queued>(AUDIT_BUFFER);

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
        self.queue(session_id, agent_id, tenant_id, event, true);
    }

    /// FR-130 — [`Self::record`] for an event whose session row its writer
    /// already wrote, with a condition the projection does not know: the end
    /// of a session no hub holds, written straight to the row so that the
    /// write lands before the control event that follows it. The audit keeps
    /// the event; the row is not projected from it.
    pub fn record_trail(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        event: AuditKind,
    ) {
        self.queue(session_id, agent_id, tenant_id, event, false);
    }

    fn queue(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        event: AuditKind,
        project: bool,
    ) {
        let ev = RemoteAuditEvent {
            id: None,
            session_id,
            agent_id,
            tenant_id,
            at: DateTime::now(),
            event,
        };
        if let Err(e) = self.tx.try_send(Queued { ev, project }) {
            warn!("audit channel full, dropping event: {e}");
        }
    }
}

async fn flush(
    coll: &Collection<RemoteAuditEvent>,
    sessions: &Collection<RemoteSession>,
    buf: &mut Vec<Queued>,
) {
    // Project session mutations BEFORE draining the buffer into the audit
    // insert. Session events are low-rate (a handful per minute at fleet
    // scale), so per-event updates are fine; every write is best-effort —
    // the projection is a VIEW of the audit truth, never a gate on it.
    for q in buf.iter().filter(|q| q.project) {
        project_session(sessions, &q.ev).await;
    }
    if let Err(e) = coll.insert_many(buf.drain(..).map(|q| q.ev)).await {
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
            external,
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
                // FR-130 — none is written unset, so this projection writes
                // the row it wrote before them: fencing number 0 (absent),
                // nothing detached, no stats merge yet, an end not inferred.
                attach_seq: 0,
                detached_at: None,
                resume_by: None,
                stats_at: None,
                end_source: None,
                // Review 1, L6 — the event carries it only under a window.
                external: *external,
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
        // FR-130 — an end someone asked for (no fencing number) is the write
        // every end made before; an end a hub decided on its own is fenced.
        AuditKind::SessionEnded {
            reason,
            attach_seq: None,
            ..
        } => end_session(sessions, ev, *reason).await,
        AuditKind::SessionEnded {
            reason,
            attach_seq: Some(seq),
            ended_at,
            end_source,
            ..
        } => end_fenced(sessions, ev, *reason, *seq, *ended_at, *end_source).await,
        // FR-130 — the detach, at the number the detaching hub held: a pod
        // that no longer holds the session (another resumed it, at a higher
        // number) writes nothing, and nor does a detach of a row not live.
        AuditKind::SessionDetached {
            attach_seq,
            resume_by,
        } => sessions
            .update_one(
                doc! {
                    "_id": ev.session_id,
                    "attach_seq": at_seq(*attach_seq),
                    "ended_at": bson::Bson::Null,
                    "phase": bson::to_bson(&SessionPhase::Active).unwrap_or(bson::Bson::Null),
                },
                doc! { "$set": { "detached_at": ev.at, "resume_by": *resume_by } },
            )
            .await
            .map(|_| ()),
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
        // change the session row. Nor does `SessionResumed`: the claim that
        // resumed the session already wrote it, in the one conditional update
        // that bumped `attach_seq` (the count of resumes) and cleared the
        // detach (FR-130 §4.4). An `Unknown` kind (a newer build's) never
        // does.
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

/// An end someone asked for (an admin's, the controller's, the device's, a
/// consent verdict): written at any fencing number, and over an earlier SEEN
/// end, as every end was before FR-130. FR-27 relies on that: a device with no
/// prompt surface is audited `consent_timeout` and then ended
/// `no_prompt_surface` on the same row, and the row reads the second.
///
/// FR-130 (review 2, N11) — but never over an INFERRED end (`end_source`
/// set: the registration read, the sweep, the one-time close, a detached
/// session's redial). Such a row was ended because the session was over, by
/// the best evidence there was, and a later asked end can only come from a
/// copy some pod still held of a session already ended (a half-open socket
/// kept it): its reason and its `now` would rewrite the row's end and leave
/// the mark on it. `{end_source: null}` matches a row with no `end_source`
/// at all, which is every row but an inferred one.
async fn end_session(
    sessions: &Collection<RemoteSession>,
    ev: &RemoteAuditEvent,
    reason: EndReason,
) -> Result<(), mongodb::error::Error> {
    sessions
        .update_one(
            doc! { "_id": ev.session_id, "end_source": bson::Bson::Null },
            doc! { "$set": {
                "phase": bson::to_bson(&SessionPhase::Closed).unwrap_or(bson::Bson::Null),
                "ended_at": ev.at,
                "end_reason": bson::to_bson(&reason).unwrap_or(bson::Bson::Null),
            }},
        )
        .await
        .map(|_| ())
}

/// FR-130 — the filter for a row still at fencing number `seq`. A row stores
/// no number until a claim bumps it (`RemoteSession::attach_seq` is absent at
/// 0), so 0 matches a missing field too.
pub fn at_seq(seq: u32) -> bson::Bson {
    if seq == 0 {
        bson::Bson::Document(doc! { "$in": [0, bson::Bson::Null] })
    } else {
        bson::Bson::Int64(i64::from(seq))
    }
}

/// FR-130 — an end a hub decided on its own: it lands only on a row that is
/// still open and still at the number the hub held, so a late write from a
/// pod that lost the session (its sink batches, a half-open socket kept it)
/// cannot end one another pod resumed. `ended_at` dates an end nobody saw by
/// the row's own last clock, and `end_source` says so on the row.
async fn end_fenced(
    sessions: &Collection<RemoteSession>,
    ev: &RemoteAuditEvent,
    reason: EndReason,
    seq: u32,
    ended_at: Option<DateTime>,
    end_source: Option<crate::models::EndSource>,
) -> Result<(), mongodb::error::Error> {
    let mut set = doc! {
        "phase": bson::to_bson(&SessionPhase::Closed).unwrap_or(bson::Bson::Null),
        "ended_at": ended_at.unwrap_or(ev.at),
        "end_reason": bson::to_bson(&reason).unwrap_or(bson::Bson::Null),
    };
    if let Some(source) = end_source {
        set.insert(
            "end_source",
            bson::to_bson(&source).unwrap_or(bson::Bson::Null),
        );
    }
    sessions
        .update_one(
            doc! {
                "_id": ev.session_id,
                "attach_seq": at_seq(seq),
                "ended_at": bson::Bson::Null,
            },
            doc! { "$set": set },
        )
        .await
        .map(|_| ())
}
