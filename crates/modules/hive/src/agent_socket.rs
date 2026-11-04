// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `hive`'s half of the agent socket: the device's `rc:hive.start_ack` and
//! `rc:hive.state`, dispatched here by `ClientMsg::namespace()`, and the
//! reconcile a device gets when it connects.
//!
//! # Ordered, and off the read loop
//!
//! A session's reports must apply in the order the device sent them —
//! `running`, `awaiting_approval`, `running`, `idle` arrive within
//! milliseconds of each other — and a database write must never stall the
//! socket's read loop, whose receive-liveness deadline would then reap a
//! healthy device. So each CONNECTION gets one queue and one task that drains
//! it in order; the handler only enqueues. (`conn_id`, never `agent_id`: two
//! connections of one device overlap during a displacement.)
//!
//! # Reconcile on connect
//!
//! The only delivery path for a device that was not connected when it was
//! told something — the remote-config rule: an offline device converges
//! through the same code as an online one. On every connection the device is
//! re-sent the stops it has not confirmed, and the starts it never answered
//! (within [`hive_limits::START_REDELIVERY_WINDOW_SECS`]; older ones are
//! `lost`, not launched an hour after someone gave up on them). A device that
//! reconnects as a build without Hive cannot be running anything: what it ran
//! ends, its pending stops end and its pending starts are lost. Each
//! connection decides on its own caps only: one a newer connection displaced
//! decides nothing.
//!
//! # What is over stays over
//!
//! A session the server ended while its device could not hear — its starter
//! removed, its org archived — is not pending anything, so reconcile sends it
//! nothing. The device learns from its own reports instead: one that says it
//! RUNS a session whose record is over is answered with a stop
//! ([`stop_if_over`]). That covers the replay a device sends on every
//! connection, so a removed member's session cannot outlive one reconnect.
//!
//! # What the device no longer runs (P1b)
//!
//! The opposite case: the record says a session runs, the device does not
//! run it. A restarted daemon holds no replay of what it ran, so every
//! connection also carries `rc:hive.manifest`, the sessions the device runs
//! NOW; the server ends each one it holds as running there that the list
//! leaves out ([`end_what_the_device_does_not_run`]). An unanswered start is
//! not "running" — reconcile owns it — and no manifest at all from a build
//! that runs Hive (an older one) changes nothing. A build WITHOUT Hive sends
//! none either, and runs none of them: reconcile ends them as an empty
//! manifest would ([`reconcile_on_connect`]).

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use bson::{DateTime, doc, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_remote_control::{
    error::Error as HubError,
    hive::{
        HiveCopyPurged, HiveCopyTip, HiveDrainRefusal, HiveJoinRefusal, HiveManifestEntry,
        HivePurgePart, HiveRefusal, HiveReplicaManifestEntry, HiveRunState, HiveTurnStatus,
        hive_limits,
    },
    signaling::{ClientMsg, ServerMsg},
};
use meshharbor_core::{AgentCtx, AgentMsgHandler, AgentSocketLifecycle};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::model::SessionStatus;
use crate::{HiveState, room};

/// Reports queued per connection before new ones are dropped. A device
/// sends a handful per turn; a full queue means a flood or a stalled
/// database, and dropping is better than holding the read loop.
const REPORT_QUEUE: usize = 256;

/// Longest local account name kept from a device's answer.
const MAX_ACCOUNT_LEN: usize = 128;

enum Report {
    StartAck {
        session_id: ObjectId,
        fence: u64,
        refused: Option<HiveRefusal>,
        account: Option<String>,
        detail: Option<String>,
    },
    State {
        session_id: ObjectId,
        fence: u64,
        state: Option<HiveRunState>,
        detail: Option<String>,
    },
    Turn {
        session_id: ObjectId,
        fence: u64,
        report: room::TurnReport,
    },
    /// P1a-2 — an approval opened or ended (`rc:hive.approval`).
    Approval {
        session_id: ObjectId,
        fence: u64,
        report: room::ApprovalReport,
    },
    /// P1b — the sessions the device runs now (`rc:hive.manifest`).
    Manifest(Vec<HiveManifestEntry>),
    /// P1j — a terminal session the device offers for a record
    /// (`rc:hive.adopt`).
    Adopt(crate::adopt::Offer),
    /// P2c-3 — a member's answer to its join (`rc:hive.replica.join_ack`).
    JoinAck {
        session_id: ObjectId,
        fence: u64,
        refused: Option<HiveJoinRefusal>,
        detail: Option<String>,
    },
    /// P2c-3 — where a member's copy ends (`rc:hive.replica.tip`).
    Tip(HiveReplicaManifestEntry),
    /// P2c-3 — every session the device holds a copy of
    /// (`rc:hive.replica.manifest`), and (P2g-3c) each copy its own clock
    /// purged.
    ReplicaManifest {
        sessions: Vec<HiveReplicaManifestEntry>,
        purged: Vec<HiveCopyPurged>,
    },
    /// P2g-3c — what keeps each copy the device holds, asked on this
    /// connection (`rc:hive.retain_ask`).
    RetainAsk(Vec<ObjectId>),
    /// P2e-3 — a member's answer to a promotion's prepare
    /// (`rc:hive.prepare_ack`).
    PrepareAck {
        session_id: ObjectId,
        fence: u64,
        refused: Option<HiveRefusal>,
        detail: Option<String>,
        /// P2e-6a — where the member's copy ends, when it is ready.
        tip: Option<HiveCopyTip>,
    },
    /// P2e-3 — a primary's answer to a promotion's drain (`rc:hive.drained`).
    Drained {
        session_id: ObjectId,
        fence: u64,
        seq: Option<u64>,
        hash: Option<String>,
        refused: Option<HiveDrainRefusal>,
        detail: Option<String>,
    },
    /// P2g-2 — a device's answer to a purge (`rc:hive.purge_ack`).
    PurgeAck {
        purge_id: ObjectId,
        session_id: ObjectId,
        store: HivePurgePart,
        account: HivePurgePart,
        detail: Option<String>,
    },
    /// P2d — a stream frame (`rc:hive.replica.want` · `ready` ·
    /// `candidate` · `close`), from a connection advertising `hive-stream`.
    Stream(ClientMsg),
    /// P0d-2 — a viewer-peer frame (`rc:hive.view.*`). In the same queue:
    /// the device's answer must reach the browser before its candidates.
    View(ClientMsg),
}

/// A device's words, kept short and on one line: they are shown to a person
/// and written to logs, and the device may be compromised.
pub(crate) fn clamp_words(s: Option<String>, max_chars: usize) -> Option<String> {
    let s = s?;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max_chars)
        .collect();
    let cleaned = cleaned.trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

pub struct HiveAgentSocket {
    state: HiveState,
    conns: DashMap<String, mpsc::Sender<Report>>,
}

impl HiveAgentSocket {
    pub fn new(state: HiveState) -> Self {
        Self {
            state,
            conns: DashMap::new(),
        }
    }
}

#[async_trait]
impl AgentMsgHandler for HiveAgentSocket {
    async fn handle(&self, ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg> {
        let report = match msg {
            ClientMsg::HiveStartAck {
                session_id,
                fence,
                refused,
                account,
                detail,
            } => Report::StartAck {
                session_id,
                fence,
                refused,
                account,
                detail,
            },
            ClientMsg::HiveState {
                session_id,
                fence,
                state,
                detail,
            } => Report::State {
                session_id,
                fence,
                state,
                detail,
            },
            ClientMsg::HiveTurn {
                session_id,
                fence,
                turn,
                status,
                prompted_by,
                steps,
                duration_ms,
                cost_usd,
            } => Report::Turn {
                session_id,
                fence,
                report: room::TurnReport {
                    turn,
                    status,
                    prompted_by,
                    steps,
                    duration_ms,
                    cost_usd,
                },
            },
            ClientMsg::HiveApproval {
                session_id,
                fence,
                approval_id,
                turn,
                status,
                answered_by,
            } => Report::Approval {
                session_id,
                fence,
                report: room::ApprovalReport {
                    approval_id,
                    turn,
                    status,
                    answered_by,
                },
            },
            ClientMsg::HiveManifest { sessions } => Report::Manifest(sessions),
            ClientMsg::HiveAdopt {
                adopt_id,
                harness_session,
                keys,
                account,
                folder,
            } => Report::Adopt(crate::adopt::Offer {
                adopt_id,
                harness_session,
                keys,
                account,
                folder,
            }),
            ClientMsg::HiveReplicaJoinAck {
                session_id,
                fence,
                refused,
                detail,
            } => Report::JoinAck {
                session_id,
                fence,
                refused,
                detail,
            },
            ClientMsg::HiveReplicaTip {
                session_id,
                fence,
                seq,
                hash,
                checkpoint,
            } => Report::Tip(HiveReplicaManifestEntry {
                session_id,
                fence,
                seq,
                hash,
                checkpoint,
            }),
            ClientMsg::HiveReplicaManifest { sessions, purged } => {
                Report::ReplicaManifest { sessions, purged }
            }
            ClientMsg::HiveRetainAsk { sessions } => Report::RetainAsk(sessions),
            // P2e-3 — applied only to the promotion waiting on THIS device,
            // at the fence it named: the record is the gate.
            ClientMsg::HivePrepareAck {
                session_id,
                fence,
                refused,
                account: _,
                detail,
                tip,
            } => Report::PrepareAck {
                session_id,
                fence,
                refused,
                detail,
                tip,
            },
            ClientMsg::HiveDrained {
                session_id,
                fence,
                seq,
                hash,
                refused,
                detail,
            } => Report::Drained {
                session_id,
                fence,
                seq,
                hash,
                refused,
                detail,
            },
            // P2d — read only from a connection that advertises
            // `hive-stream`: a build that does not carry streams has nothing
            // to say about one. Checked here, against THIS connection.
            stream @ (ClientMsg::HiveReplicaWant { .. }
            | ClientMsg::HiveReplicaReady { .. }
            | ClientMsg::HiveReplicaCandidate { .. }
            | ClientMsg::HiveReplicaClose { .. }) => {
                if self
                    .state
                    .fleet
                    .rc_hub
                    .agent_supports_hive_stream_on(ctx.agent_id, &ctx.tx)
                    != Some(true)
                {
                    debug!(agent_id = %ctx.agent_id, "hive: a stream frame from a connection without hive-stream — dropped");
                    return None;
                }
                Report::Stream(stream)
            }
            view @ (ClientMsg::HiveViewGrantAck { .. }
            | ClientMsg::HiveViewAnswer { .. }
            | ClientMsg::HiveViewIce { .. }
            | ClientMsg::HiveViewClosed { .. }) => Report::View(view),
            // P2g-2 — applied only to THIS device's entry of the purge: the
            // socket names the device, never the frame.
            ClientMsg::HivePurgeAck {
                purge_id,
                session_id,
                store,
                account,
                detail,
            } => Report::PurgeAck {
                purge_id,
                session_id,
                store,
                account,
                detail,
            },
            other => return Some(other),
        };
        let tx = self.conns.get(&ctx.conn_id).map(|e| e.value().clone());
        match tx {
            Some(tx) => {
                if tx.try_send(report).is_err() {
                    warn!(
                        agent_id = %ctx.agent_id,
                        "hive: report queue full or closed — a device report was dropped"
                    );
                }
            }
            None => warn!(
                agent_id = %ctx.agent_id,
                "hive: report on a connection that never said hello — dropped"
            ),
        }
        None
    }
}

#[async_trait]
impl AgentSocketLifecycle for HiveAgentSocket {
    async fn hello(&self, ctx: &AgentCtx) {
        let (tx, rx) = mpsc::channel(REPORT_QUEUE);
        self.conns.insert(ctx.conn_id.clone(), tx);
        let state = self.state.clone();
        let (tenant_id, device_id) = (ctx.tenant_id, ctx.agent_id);
        // This connection's sender in the hub: reconcile reads what THIS
        // connection advertised, never a newer one's entry.
        let conn = ctx.tx.clone();
        tokio::spawn(async move {
            if state.scope.serves(tenant_id) {
                // P2g-2 — what it must purge goes FIRST, before anything else
                // it is sent; with the replicaset's switch off, issued purges
                // wait.
                if state.replicaset {
                    crate::purge::reconcile_purges(&state, tenant_id, device_id, &conn).await;
                }
                reconcile_on_connect(&state, tenant_id, device_id, &conn).await;
                // P2c-4 — with the replicaset's switch off, no replica frame
                // goes at all, for sessions placed while it was on as well: a
                // primary's join turns checkpoints on.
                if state.replicaset {
                    // P2c-3 — the joins it has still to answer: as a member,
                    // if this connection holds copies, and as a primary.
                    crate::replica::reconcile_joins(&state, tenant_id, device_id, &conn).await;
                    // And what it runs that was never placed.
                    if state.fleet.rc_hub.agent_supports_hive_on(device_id, &conn) == Some(true) {
                        match crate::placement::place_unplaced(&state, tenant_id, device_id).await {
                            Ok(0) => {}
                            Ok(placed) => {
                                info!(device = %device_id, placed, "hive: sessions from before placement placed");
                            }
                            Err(e) => {
                                warn!(device = %device_id, %e, "hive: sessions from before placement were not placed");
                            }
                        }
                    }
                }
            } else {
                end_unserved(&state, tenant_id, device_id).await;
            }
            // P2e-2 — the reports are read with the connection held WEAKLY: a
            // manifest is answered on the connection that sent it, and a held
            // sender would keep a closed or displaced connection's channel
            // open as long as its reports are read.
            let weak = conn.downgrade();
            drop(conn);
            apply_reports(&state, tenant_id, device_id, rx, weak).await;
        });
    }

    /// Dropping the sender ends the drain task once the queue is empty.
    async fn closing(&self, ctx: &AgentCtx) {
        self.conns.remove(&ctx.conn_id);
    }
}

/// Apply one connection's reports, in order, until it closes. `conn` is that
/// connection's sender in the hub, held weakly.
async fn apply_reports(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    mut rx: mpsc::Receiver<Report>,
    conn: mpsc::WeakSender<ServerMsg>,
) {
    while let Some(report) = rx.recv().await {
        match report {
            Report::StartAck {
                session_id,
                fence,
                refused,
                account,
                detail,
            } => {
                let detail = clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
                // P2e-3 — a moved start the member refused is the
                // promotion's to answer: the lease moves back, and the
                // session is NOT refused. Never one at the first fence, which
                // no promotion starts: those cost no read.
                if let Some(word) = refused
                    && fence > 1
                    && crate::promote::on_start_refused(
                        state,
                        session_id,
                        device_id,
                        fence,
                        word,
                        detail.clone(),
                    )
                    .await
                {
                    continue;
                }
                // P2f-4b — a terminal session's start as a managed one,
                // refused: the adopted session it was again, never a refused
                // managed session. It costs a read only for a refusal.
                if let Some(word) = refused
                    && crate::manage::on_start_refused(
                        state,
                        session_id,
                        device_id,
                        fence,
                        word,
                        detail.clone(),
                    )
                    .await
                {
                    continue;
                }
                let applied = match refused {
                    None => {
                        let account = clamp_words(account, MAX_ACCOUNT_LEN);
                        state
                            .sessions
                            .accept(session_id, device_id, fence, account)
                            .await
                    }
                    Some(word) => {
                        state
                            .sessions
                            .refuse(session_id, device_id, fence, word.as_str(), detail)
                            .await
                    }
                };
                match applied {
                    Ok(true) => {
                        info!(
                            session = %session_id, device = %device_id,
                            refused = refused.map(HiveRefusal::as_str),
                            "hive: the device answered a start"
                        );
                        // AFTER the write: the woken caller re-reads the record.
                        state.start_acks.deliver(session_id, device_id);
                        // P2e-3 — a moved start's acceptance ends its
                        // promotion, and the promotion's note says it moved.
                        let moved = refused.is_none()
                            && fence > 1
                            && crate::promote::on_launched(state, session_id, device_id, fence)
                                .await;
                        if let Ok(Some(s)) = state.sessions.find(session_id).await {
                            // And say so in the session's room (P0d) — for a
                            // first start: one at a later fence is a move's, or
                            // a move back's, whose notes are the promotion's.
                            if !moved && (refused.is_some() || s.fence <= 1) {
                                let text = match refused {
                                    // P2f-4b — a terminal session made a managed one.
                                    None if s.from_terminal.is_some() => {
                                        room::made_managed_note(&s)
                                    }
                                    None => room::started_note(&s),
                                    Some(_) => room::refused_note(&s),
                                };
                                room::note(state, &s, text).await;
                            }
                            // P2g-4b — a fork's first start answered: the copy
                            // of its parent it was made from, should a member
                            // that leaves hold it, need not stay for it.
                            if let Some(parent) = &s.parent
                                && s.fence <= 1
                            {
                                crate::purge::settle_session(state, parent.session_id).await;
                            }
                        }
                        // P2c-3 — it runs: its members may hold copies now.
                        // P2c-4: only while the replicaset's switch is on.
                        if refused.is_none() && state.replicaset {
                            crate::replica::send_joins(state, session_id).await;
                        }
                    }
                    Ok(false) => {
                        debug!(
                            session = %session_id, device = %device_id, fence,
                            "hive: a start answer matched no unanswered start — a duplicate, \
                             a stale fence, or not this device's session"
                        );
                        // It launched something the record gave up on (ended
                        // while the start was in flight, or `lost`).
                        if refused.is_none() {
                            stop_if_over(state, tenant_id, session_id, device_id, fence).await;
                        }
                    }
                    Err(e) => {
                        warn!(session = %session_id, %e, "hive: a start answer was not recorded")
                    }
                }
            }
            Report::State {
                session_id,
                fence,
                state: run,
                detail,
            } => {
                let Some(run) = run else {
                    debug!(
                        session = %session_id,
                        "hive: a run state this build cannot name — keeping what it knew"
                    );
                    continue;
                };
                let applied = match run {
                    HiveRunState::Ended => {
                        let detail = clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
                        state
                            .sessions
                            .report_ended(session_id, device_id, fence, detail)
                            .await
                    }
                    other => {
                        state
                            .sessions
                            .report_state(session_id, device_id, fence, other)
                            .await
                    }
                };
                match applied {
                    Ok(true) => {
                        debug!(session = %session_id, state = run.as_str(), "hive: session state");
                        // P2e-3 — the moved start's run state is the member's
                        // word that it runs it: the promotion is done, even
                        // should the start's answer be lost.
                        // At the first fence, which no promotion starts, it
                        // costs no read.
                        if run != HiveRunState::Ended && fence > 1 {
                            crate::promote::on_launched(state, session_id, device_id, fence).await;
                        }
                        if run == HiveRunState::Ended
                            && let Ok(Some(s)) = state.sessions.find(session_id).await
                        {
                            room::note(state, &s, room::ended_note(&s)).await;
                            // The device withdraws its own open approvals as
                            // it ends; this covers a frame of theirs it lost.
                            room::withdraw_approvals(state, &s).await;
                        }
                    }
                    Ok(false) => {
                        debug!(
                            session = %session_id, device = %device_id, fence, state = run.as_str(),
                            "hive: a state report matched no live session at that fence on this device"
                        );
                        if run != HiveRunState::Ended {
                            stop_if_over(state, tenant_id, session_id, device_id, fence).await;
                        }
                    }
                    Err(e) => {
                        warn!(session = %session_id, %e, "hive: a state report was not recorded")
                    }
                }
            }
            Report::Turn {
                session_id,
                fence,
                report,
            } => {
                // The same ownership rule as every device report: only the
                // session's own device, at its current fence.
                match state.sessions.find(session_id).await {
                    Ok(Some(s))
                        if s.location.device_id == device_id
                            && u64::try_from(s.fence).ok() == Some(fence) =>
                    {
                        if !s.status.is_terminal() {
                            room::turn_stub(state, &s, report).await;
                            continue;
                        }
                        // Over on the record. The device may still FINISH the
                        // stub it has (the turn its stop interrupted), never
                        // open a new one; a turn it says is running, it stops.
                        let running = matches!(report.status, Some(HiveTurnStatus::Running) | None);
                        if running {
                            stop_if_over(state, tenant_id, session_id, device_id, fence).await;
                        } else if s.last_turn.is_some_and(|t| t.turn == report.turn) {
                            room::turn_stub(state, &s, report).await;
                        }
                    }
                    // P2e-1 — an old primary still running turns of it.
                    Ok(Some(s)) if s.location.device_id != device_id => {
                        demote_if_elsewhere(state, tenant_id, device_id, &s);
                    }
                    Ok(_) => debug!(
                        session = %session_id, device = %device_id, fence,
                        "hive: a turn report for no session of this device at that fence"
                    ),
                    Err(e) => warn!(session = %session_id, %e, "hive: a turn report was not read"),
                }
            }
            Report::Approval {
                session_id,
                fence,
                report,
            } => {
                // The ownership rule again: only the session's own device, at
                // its current fence. An opening in a session that is over is
                // refused by `room::approval`; an end always applies, so a
                // stub cannot be left saying "needs approval".
                match state.sessions.find(session_id).await {
                    Ok(Some(s))
                        if s.location.device_id == device_id
                            && u64::try_from(s.fence).ok() == Some(fence) =>
                    {
                        room::approval(state, &s, report).await;
                    }
                    // P2e-1 — an old primary still asking for approvals.
                    Ok(Some(s)) if s.location.device_id != device_id => {
                        demote_if_elsewhere(state, tenant_id, device_id, &s);
                    }
                    Ok(_) => debug!(
                        session = %session_id, device = %device_id, fence,
                        "hive: an approval report for no session of this device at that fence"
                    ),
                    Err(e) => {
                        warn!(session = %session_id, %e, "hive: an approval report was not read")
                    }
                }
            }
            Report::Manifest(sessions) => {
                end_what_the_device_does_not_run(state, tenant_id, device_id, &sessions).await;
                answer_manifest(state, tenant_id, device_id, &sessions, &conn).await;
            }
            Report::JoinAck {
                session_id,
                fence,
                refused,
                detail,
            } => {
                crate::replica::on_join_ack(state, device_id, session_id, fence, refused, detail)
                    .await
            }
            Report::Tip(tip) => crate::replica::on_tip(state, device_id, tip).await,
            Report::ReplicaManifest { sessions, purged } => {
                crate::replica::on_manifest(state, device_id, sessions, purged).await
            }
            Report::RetainAsk(sessions) => {
                crate::retention::answer(state, tenant_id, device_id, sessions, &conn).await
            }
            Report::PrepareAck {
                session_id,
                fence,
                refused,
                detail,
                tip,
            } => {
                crate::promote::on_prepare_ack(
                    state, device_id, session_id, fence, refused, detail, tip,
                )
                .await
            }
            Report::Drained {
                session_id,
                fence,
                seq,
                hash,
                refused,
                detail,
            } => {
                crate::promote::on_drained(
                    state, device_id, session_id, fence, seq, hash, refused, detail,
                )
                .await
            }
            Report::PurgeAck {
                purge_id,
                session_id,
                store,
                account,
                detail,
            } => {
                crate::purge::on_ack(
                    state, tenant_id, device_id, purge_id, session_id, store, account, detail,
                )
                .await
            }
            Report::Adopt(offer) => crate::adopt::offer(state, tenant_id, device_id, offer).await,
            Report::View(msg) => crate::view::on_device_frame(state, device_id, msg).await,
            Report::Stream(msg) => {
                crate::stream::on_device_frame(state, tenant_id, device_id, msg).await
            }
        }
    }
}

/// P1b — the device says which sessions it runs now. Every session the
/// server holds as running there that the list leaves out is over — the
/// daemon restarted, or the harness ended and the word was lost past its
/// replay — and nothing else would ever say so (finding 7). Ended here, with
/// its room told and its open approvals withdrawn. An oversized list is not
/// a device's, and changes nothing: the safe direction. A connection without
/// `hive` gets the empty list from [`reconcile_on_connect`]. What the list
/// names is answered by [`answer_manifest`].
async fn end_what_the_device_does_not_run(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    manifest: &[HiveManifestEntry],
) {
    if manifest.len() > hive_limits::MAX_MANIFEST {
        warn!(device = %device_id, entries = manifest.len(), "hive: an oversized manifest — ignored");
        return;
    }
    let runs: HashSet<(ObjectId, u64)> = manifest.iter().map(|e| (e.session_id, e.fence)).collect();
    let held = match state.sessions.running_on_device(tenant_id, device_id).await {
        Ok(held) => held,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: the device's sessions were not read for its manifest");
            return;
        }
    };
    for s in held {
        let Some(sid) = s.id else { continue };
        if runs.contains(&(sid, u64::try_from(s.fence).unwrap_or_default())) {
            continue;
        }
        let stopping = s.status == SessionStatus::Stopping;
        match state
            .sessions
            .end_not_on_device(sid, device_id, s.fence, stopping)
            .await
        {
            Ok(true) => {
                info!(session = %sid, device = %device_id, "hive: the device no longer runs a session — ended");
                room::note_ended(state, sid).await;
            }
            Ok(false) => {}
            Err(e) => {
                warn!(session = %sid, %e, "hive: a session the device no longer runs was not ended")
            }
        }
    }
}

/// The device says it RUNS a session — `session_id` at `fence` — that the
/// record says is over: tell it to stop. Nothing else would ever reach that
/// process (reconcile re-sends only what is pending), and the record is the
/// source of truth. A device answers a stop for a session it does not run with
/// `ended`, which changes nothing here, so this cannot loop.
///
/// P2e-1 — and one the record holds on ANOTHER device is told it no longer
/// holds it ([`demote_if_elsewhere`]).
async fn stop_if_over(
    state: &HiveState,
    tenant_id: ObjectId,
    session_id: ObjectId,
    device_id: ObjectId,
    fence: u64,
) {
    let s = match state.sessions.find(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            warn!(session = %session_id, %e, "hive: a report's session was not read");
            return;
        }
    };
    if demote_if_elsewhere(state, tenant_id, device_id, &s) {
        return;
    }
    // The session's own device, then: told to stop only what is over.
    if !s.status.is_terminal() {
        return;
    }
    tell_to_stop(state, &s, session_id, device_id, fence);
}

/// Tell `device_id` to stop `s`, which is over, at `fence`: the fence it
/// says it holds the session at.
fn tell_to_stop(
    state: &HiveState,
    s: &crate::model::AgentSession,
    session_id: ObjectId,
    device_id: ObjectId,
    fence: u64,
) {
    let msg = ServerMsg::HiveStop {
        session_id,
        fence,
        reason: s.end_reason.clone().unwrap_or_else(|| "ended".to_string()),
    };
    match state.fleet.rc_hub.push_hive(device_id, s.tenant_id, msg) {
        Ok(()) => info!(
            session = %session_id, device = %device_id, fence,
            "hive: the device still runs a session that is over — told to stop"
        ),
        Err(e) => {
            debug!(session = %session_id, %e, "hive: a stop for a session that is over was not sent")
        }
    }
}

/// FR-90 P2e — every session the device's manifest names is answered from
/// its record, in one read of this organization's sessions:
/// - held on ANOTHER device: `rc:hive.demote`, at the record's fence (P2e-1,
///   [`demote_if_elsewhere`]);
/// - over: `rc:hive.stop`, as for any report of a session that is over. A
///   leased session the device holds back for the word (P2e-2) would
///   otherwise wait for one that never comes;
/// - held here at the fence the list names, and leased: `rc:hive.lease`, on
///   the connection that sent the list and no other (P2e-2, [`crate::lease`]).
///   Not while a promotion drains the device (P2e-3): the word would lift
///   the drain while the lease is in motion. A promotion past its deadline
///   is failed first, and the word goes.
///
/// One held here at another fence is the device's own to settle: a start at
/// the newer fence supersedes it there (P2e-1).
async fn answer_manifest(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    manifest: &[HiveManifestEntry],
    conn: &mpsc::WeakSender<ServerMsg>,
) {
    if manifest.is_empty() || manifest.len() > hive_limits::MAX_MANIFEST {
        return;
    }
    let named: HashMap<ObjectId, u64> = manifest.iter().map(|e| (e.session_id, e.fence)).collect();
    let ids: Vec<ObjectId> = named.keys().copied().collect();
    let sessions = match state.sessions.find_many_in_tenant(tenant_id, &ids).await {
        Ok(s) => s,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: the sessions a manifest names were not read");
            return;
        }
    };
    for s in &sessions {
        let Some(sid) = s.id else { continue };
        let Some(&fence) = named.get(&sid) else {
            continue;
        };
        if demote_if_elsewhere(state, tenant_id, device_id, s) {
            continue;
        }
        if s.status.is_terminal() {
            tell_to_stop(state, s, sid, device_id, fence);
            continue;
        }
        // P2e-3 — none while the device is drained for a move: the lease is
        // in motion, and the word would lift the drain.
        if u64::try_from(s.fence).ok() == Some(fence)
            && crate::replica::replicated(s)
            && !crate::promote::withholds_word(state, s).await
            && let Some(conn) = conn.upgrade()
        {
            crate::lease::push_on(state, tenant_id, device_id, &conn, sid, fence);
        }
    }
}

/// FR-90 P2e-1 — a device reported a session the record holds on ANOTHER
/// device: it is told it no longer holds it (`rc:hive.demote`, at the
/// record's fence), and what it runs of it at an older fence ends there. An
/// old primary hears it this way when it could not be told at a move, or
/// when it comes back after one. Another organization's session tells the
/// device nothing and changes nothing. `true` when the record is elsewhere.
fn demote_if_elsewhere(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    s: &crate::model::AgentSession,
) -> bool {
    if s.location.device_id == device_id {
        return false;
    }
    let Some(session_id) = s.id else {
        return true;
    };
    if s.tenant_id != tenant_id {
        debug!(session = %session_id, device = %device_id, "hive: a report naming another organization's session — ignored");
        return true;
    }
    let fence = u64::try_from(s.fence).unwrap_or_default();
    let msg = ServerMsg::HiveDemote {
        session_id,
        fence,
        reason: "not_location".to_string(),
    };
    match state.fleet.rc_hub.push_hive(device_id, tenant_id, msg) {
        Ok(()) => info!(
            session = %session_id, device = %device_id, fence,
            "hive: a device reported a session held elsewhere — demoted"
        ),
        Err(e) => debug!(session = %session_id, %e, "hive: a demote was not sent"),
    }
    true
}

/// P1g — agent sessions no longer serve this device's organization (it left
/// `hive.tenants`): nothing is re-sent, and what the device still runs for it
/// ends and is told to stop. The device's manifest, read next, stops anything
/// the push did not reach.
async fn end_unserved(state: &HiveState, tenant_id: ObjectId, device_id: ObjectId) {
    match crate::hooks::end_and_tell(
        state,
        doc! { "tenant_id": tenant_id, "location.device_id": device_id },
        "hive_not_enabled",
    )
    .await
    {
        Ok(0) => {}
        Ok(ended) => info!(
            tenant = %tenant_id,
            device = %device_id,
            ended,
            "hive: the organization is not served — its sessions on the device ended"
        ),
        Err(e) => {
            warn!(device = %device_id, %e, "hive: an unserved organization's sessions were not ended")
        }
    }
}

/// Re-send what a device missed while it was not connected here. `conn` is
/// this connection's sender in the hub ([`AgentCtx::tx`]).
pub(crate) async fn reconcile_on_connect(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    conn: &mpsc::Sender<ServerMsg>,
) {
    // Read once, for THIS connection. The hub records a connection's caps
    // before its hello runs (`fleet/src/socket.rs`), and answers only while
    // the slot is still this connection's. `None` = it is not: a newer
    // connection displaced it (and may not have recorded its caps yet), or it
    // is gone. Then this connection decides nothing, and the one that holds
    // the slot reconciles for itself.
    let supports_hive = state.fleet.rc_hub.agent_supports_hive_on(device_id, conn);
    // ⚠️ A build without `hive` runs no session, and sends no manifest to say
    // so: what the record holds as running here would read `idle` for ever.
    // Field, 2026-10-10: a Windows device ran an accepted session, then
    // updated itself to 0.4.123, whose build has no `hive`. A crash-loop
    // rollback to an older build, or a build made without `hive`, does the
    // same. So it gets the empty manifest, before what is pending is read: a
    // session ended here is pending nothing, and `end_now` and `mark_lost`
    // below miss one already ended, so none is noted twice. Only on
    // `Some(false)`: unknown is not "no".
    if supports_hive == Some(false) {
        end_what_the_device_does_not_run(state, tenant_id, device_id, &[]).await;
    }
    // ⚠️ `None` is not "no `hive`" here either. Read that way (the old
    // `unwrap_or(false)`), it ended the pending stops and lost the pending
    // starts of a device whose agent runs Hive: one whose socket dropped at
    // once, or whose newer connection had not recorded its caps yet. A
    // connection that no longer owns the hub's entry does nothing; one that
    // genuinely lacks `hive` still ends its stops and loses its starts below.
    let Some(runs_hive) = supports_hive else {
        return;
    };
    let pending = match state.sessions.needing_delivery(tenant_id, device_id).await {
        Ok(p) => p,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: reconcile-on-connect could not read sessions");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let now_ms = DateTime::now().timestamp_millis();

    for s in pending {
        let Some(sid) = s.id else { continue };
        let fence = u64::try_from(s.fence).unwrap_or_default();
        match s.status {
            SessionStatus::Stopping if !runs_hive => {
                if let Ok(true) = state
                    .sessions
                    .end_now(
                        sid,
                        "stopped",
                        "the device's agent no longer runs agent sessions",
                    )
                    .await
                {
                    room::note_ended(state, sid).await;
                }
            }
            SessionStatus::Stopping => {
                let msg = ServerMsg::HiveStop {
                    session_id: sid,
                    fence,
                    reason: "owner".to_string(),
                };
                match state.fleet.rc_hub.push_hive(device_id, tenant_id, msg) {
                    Ok(()) => {
                        info!(session = %sid, device = %device_id, "hive: stop re-sent on connect")
                    }
                    Err(e) => debug!(session = %sid, %e, "hive: stop not re-sent"),
                }
            }
            // P2f-4b — a terminal session being made a managed one is never
            // lost: it is the adopted session it was again.
            SessionStatus::Starting if !runs_hive && s.managing() => {
                crate::manage::restore(
                    state,
                    &s,
                    "device_unsupported",
                    Some(
                        "the device reconnected with an agent that does not run agent sessions"
                            .into(),
                    ),
                )
                .await;
            }
            SessionStatus::Starting if !runs_hive => {
                if let Ok(true) = state
                    .sessions
                    .mark_lost(
                        sid,
                        "the device reconnected with an agent that does not run agent sessions",
                    )
                    .await
                {
                    room::note_ended(state, sid).await;
                }
            }
            SessionStatus::Starting => {
                // P2e-3 — a start past the first fence is a move's, or a move
                // back's. P2e-6b — and it is sent again however late its
                // device comes back: the window bounds a session's FIRST
                // start, whose caller has gone. A moved session's conversation
                // lives on, and its record was made long before the move.
                let moved = s.fence > 1;
                // P2f-4b — a terminal session being made a managed one counts
                // from its asking: its record is the adoption's, made long
                // before. Past the window it is the adopted session it was.
                let managing = s.from_terminal.as_ref().filter(|_| s.managing());
                let since = managing.map_or(s.created_at, |f| f.at);
                let age_ms = now_ms.saturating_sub(since.timestamp_millis());
                if !moved && age_ms > hive_limits::START_REDELIVERY_WINDOW_SECS * 1000 {
                    if managing.is_some() {
                        crate::manage::restore(
                            state,
                            &s,
                            "never_answered",
                            Some("the device came back after the start's redelivery window".into()),
                        )
                        .await;
                    } else if let Ok(true) = state
                        .sessions
                        .mark_lost(
                            sid,
                            "the device came back after the start's redelivery window",
                        )
                        .await
                    {
                        room::note_ended(state, sid).await;
                    }
                    continue;
                }
                let Ok(owner) = state.users.base.find_by_id(s.owner_id).await else {
                    warn!(session = %sid, "hive: start not re-sent — its owner could not be read");
                    continue;
                };
                // The device hears its join as the primary and the record's
                // `rc:hive.move` first, as when it was first sent, and resumes
                // the conversation. P2e-6b — from where the record says the
                // start came; a record from before it, from its move's.
                if moved {
                    let (from, by) = match (&s.moved, &s.promotion) {
                        (Some(m), _) => (m.from.clone(), m.by),
                        (None, Some(p)) if p.to == device_id => (p.from.clone(), p.by),
                        _ => (s.location.clone(), s.owner_id),
                    };
                    crate::promote::before_start(state, &s, &from, by).await;
                }
                // P1e — its core memory next, the same frozen snapshot the
                // first start carried; a device without `hive-memory` gets
                // none, as it got none then.
                match state.brain.snapshot_of(sid).await {
                    Ok(Some(m)) => {
                        let frame = crate::routes::memory_frame(&m, fence);
                        let _ = state
                            .fleet
                            .rc_hub
                            .push_hive_memory(device_id, tenant_id, frame);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!(session = %sid, %e, "hive: core memory not re-sent")
                    }
                }
                // Idempotent on the device by session id + fence: one that
                // launched it and lost only the answer says `accepted` again.
                // P2c-4 — and replicated only while the switch is on: a
                // session placed while it was on runs alone once it is off,
                // as every session did in P1. P2e-2 — leased with it, on a
                // connection that holds a lease to the server's word.
                let replicated = state.replicaset && crate::replica::replicated(&s);
                let lease = replicated
                    && state
                        .fleet
                        .rc_hub
                        .agent_supports_hive_lease_on(device_id, conn)
                        == Some(true);
                let msg = ServerMsg::HiveStart {
                    session_id: sid,
                    harness: s.harness.id.clone(),
                    harness_session: s.harness.session.clone(),
                    fence,
                    folder: s.location.folder.clone(),
                    user_id: s.owner_id,
                    user_email: owner.email,
                    caller: owner.display_name,
                    resume: moved,
                    replicated,
                    lease,
                    // P2f-3 — a fork's every start says what it was made from.
                    fork_of: s.fork_of(),
                    // P2f-4b — and a terminal session's, being made a managed
                    // one, says so again.
                    from_terminal: managing.is_some(),
                };
                match crate::routes::push_start(state, &s, device_id, msg) {
                    Ok(()) => {
                        info!(session = %sid, device = %device_id, "hive: unanswered start re-sent on connect")
                    }
                    // P2f-3 — a fork's start goes only to a connection that
                    // starts forks (a build before them would start it
                    // empty), so it waits for the next one that does.
                    Err(e) if s.parent.is_some() => {
                        warn!(session = %sid, %e, "hive: a fork's start not re-sent — it goes again on a connection that starts forks")
                    }
                    // P2f-4b — the device came back as a build that does not
                    // make one: the adopted session it was again.
                    Err(HubError::ExecUnsupported(_)) if managing.is_some() => {
                        crate::manage::restore(
                            state,
                            &s,
                            "device_unsupported",
                            Some(
                                "the device reconnected with an agent that does not make \
                                 terminal sessions managed"
                                    .into(),
                            ),
                        )
                        .await;
                    }
                    Err(e) => debug!(session = %sid, %e, "hive: start not re-sent"),
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_devices_words_are_one_short_line_or_nothing() {
        assert_eq!(
            clamp_words(Some("no such dir\n\u{1b}[2Jcleared".into()), 100).as_deref(),
            Some("no such dir  [2Jcleared")
        );
        assert_eq!(clamp_words(Some("x".repeat(600)), 512).unwrap().len(), 512);
        assert_eq!(clamp_words(Some(" \n\t ".into()), 100), None);
        assert_eq!(clamp_words(None, 100), None);
        // Cut on characters, never inside one.
        assert_eq!(clamp_words(Some("ééé".into()), 2).as_deref(), Some("éé"));
    }
}
