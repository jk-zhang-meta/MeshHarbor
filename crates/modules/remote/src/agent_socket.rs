// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! `remote`'s half of the agent socket (FR-69 P6): registered on the core's
//! `AgentSocketRegistry` under this module's id at init, so the fleet
//! module's socket dispatches the `Owner::Remote` messages here without
//! naming this crate.

use async_trait::async_trait;
use bson::oid::ObjectId;
use roomler_ai_remote_control::models::{
    PrivacyActivityEvent, PrivacyActivityKind, RecordingActivityEvent, RecordingActivityKind,
    TransferActivityEvent, TransferActivityKind,
};
use roomler_ai_remote_control::permissions::Permissions;
use roomler_ai_remote_control::signaling::{ClientMsg, TransferDirection, Transfers};
use roomler_core::{AgentCtx, AgentMsgHandler};
use tracing::{debug, warn};

use crate::RemoteState;

/// `remote`'s half of the agent socket: the session-stats merge, (FR-85 P3)
/// remote-recording activity, (FR-101 P3) the clipboard and file traffic
/// carried on the stats, and (FR-99 P1d) privacy-mode activity. Everything
/// else remote-owned (session request, SDP, ICE, terminate) is the Hub's own
/// dispatch, which the socket runs on whatever a handler hands back.
pub struct RemoteAgentSocket {
    state: RemoteState,
}

impl RemoteAgentSocket {
    pub fn new(state: RemoteState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl AgentMsgHandler for RemoteAgentSocket {
    async fn handle(&self, ctx: &AgentCtx, msg: ClientMsg) -> Option<ClientMsg> {
        match msg {
            ClientMsg::SharedLeaseChallenge {
                session_id,
                grant_id,
                lease_epoch,
                challenge_id,
            } => {
                crate::device_share::renew_lease(
                    &self.state,
                    ctx,
                    session_id,
                    grant_id,
                    lease_epoch,
                    challenge_id,
                )
                .await;
                None
            }
            ClientMsg::SessionStats {
                session_id,
                bytes_sent,
                bytes_recv,
                fps,
                rtt_ms,
                keyframe_requests,
                input_events,
                shared_seconds,
                mixed_dial_seconds,
                transfers,
                carrier,
            } => {
                let sid = ObjectId::parse_str(&session_id).ok();
                // FR-101 P3 — an audit, not a statistic: kept whether or not
                // stats are on.
                if let Some(sid) = sid
                    && !transfers.is_empty()
                {
                    self.record_transfers(ctx, sid, transfers).await;
                }
                if self.state.settings.stats.enabled
                    && let Some(sid) = sid
                {
                    let stats = roomler_ai_remote_control::models::SessionStats {
                        bytes_sent,
                        bytes_recv,
                        peak_fps: fps,
                        avg_rtt_ms: rtt_ms,
                        keyframe_requests,
                        input_events,
                        shared_seconds,
                        mixed_dial_seconds,
                    };
                    // FR-102 P9c — the carrier, when the agent named one and
                    // it is a code: anything else is dropped and the row
                    // stays as it was (unknown, never direct).
                    let carrier = carrier
                        .as_deref()
                        .and_then(roomler_ai_remote_control::models::session_carrier_label);
                    if let Err(e) = self
                        .state
                        .remote_sessions
                        .merge_live_stats(sid, ctx.agent_id, &stats, carrier)
                        .await
                    {
                        debug!(agent = %ctx.agent_id, %e, "session stats merge failed");
                    }
                }
                None
            }
            ClientMsg::RecordingActivity {
                session_id,
                kind,
                name,
                bytes,
                duration_ms,
                reason,
            } => {
                self.record_activity(ctx, session_id, kind, name, bytes, duration_ms, reason)
                    .await;
                None
            }
            ClientMsg::PrivacyActivity {
                session_id,
                kind,
                reason,
            } => {
                self.record_privacy(ctx, session_id, kind, reason).await;
                None
            }
            // FR-52 P3c — the device's answers to a relayed login. Delivered
            // only to a waiter registered for THIS agent (`ctx.agent_id` is the
            // authenticated socket's, never the frame's); anything else lands
            // nowhere. Consumed either way — never handed to the Hub.
            ClientMsg::ExtauthKe2 { attempt_id, ke2 } => {
                let answer = crate::extauth::DeviceAnswer::Ke2(ke2);
                if !self
                    .state
                    .extauth
                    .deliver(&attempt_id, ctx.agent_id, answer)
                {
                    debug!(agent = %ctx.agent_id, %attempt_id, "extauth: KE2 for no waiting step");
                }
                None
            }
            ClientMsg::ExtauthOutcome {
                attempt_id,
                refused,
                retry_after_secs,
            } => {
                let answer = crate::extauth::DeviceAnswer::Outcome {
                    refused,
                    retry_after_secs,
                };
                if !self
                    .state
                    .extauth
                    .deliver(&attempt_id, ctx.agent_id, answer)
                {
                    debug!(agent = %ctx.agent_id, %attempt_id, "extauth: outcome for no waiting step");
                }
                None
            }
            other => Some(other),
        }
    }
}

impl RemoteAgentSocket {
    /// FR-85 P3 — record what a device reports about a remote recording,
    /// but ONLY for a session of THIS agent whose grant held `RECORD`: a
    /// device must not be able to write activity against a session that
    /// could not record, or against another device's. The live session is
    /// checked first; after it has ended (a recording's last report arrives
    /// after its session is gone) the stored `remote_sessions` row decides.
    #[allow(clippy::too_many_arguments)]
    async fn record_activity(
        &self,
        ctx: &AgentCtx,
        session_id: ObjectId,
        kind: RecordingActivityKind,
        name: Option<String>,
        bytes: Option<u64>,
        duration_ms: Option<u64>,
        reason: Option<String>,
    ) {
        let Some((agent_id, controller_user_id, permissions)) =
            self.grant_of(ctx, session_id).await
        else {
            debug!(agent = %ctx.agent_id, %session_id, "recording activity for an unknown session — dropped");
            return;
        };
        if agent_id != ctx.agent_id || !permissions.contains(Permissions::RECORD) {
            warn!(
                agent = %ctx.agent_id,
                %session_id,
                "recording activity for a session this device could not record — dropped"
            );
            return;
        }
        let clip = |s: Option<String>| {
            s.map(|t| t.chars().take(RecordingActivityEvent::MAX_TEXT).collect())
        };
        let event = RecordingActivityEvent {
            id: None,
            tenant_id: ctx.tenant_id,
            agent_id: ctx.agent_id,
            session_id,
            controller_user_id,
            kind,
            name: clip(name),
            bytes,
            duration_ms,
            reason: clip(reason),
            at: bson::DateTime::now(),
        };
        if let Err(e) = self.state.recording_activity.record(event).await {
            // Best-effort, like every activity log: never gates the session.
            debug!(agent = %ctx.agent_id, %e, "recording activity write failed");
        }
    }

    /// FR-99 P1d — record what a device reports about privacy mode, but ONLY
    /// for a session of THIS agent whose grant held `PRIVACY`: a device must
    /// not be able to write a curtain into a session that could not have one,
    /// or into another device's. A `worker_exit` arrives from the next process
    /// to start, after its session is gone, so the stored session row decides
    /// then ([`Self::grant_of`]). A reason that is not a short code is dropped
    /// and the row kept: the fact stands, the free text does not.
    async fn record_privacy(
        &self,
        ctx: &AgentCtx,
        session_id: ObjectId,
        kind: PrivacyActivityKind,
        reason: Option<String>,
    ) {
        let Some((agent_id, controller_user_id, permissions)) =
            self.grant_of(ctx, session_id).await
        else {
            debug!(agent = %ctx.agent_id, %session_id, "privacy activity for an unknown session — dropped");
            return;
        };
        if agent_id != ctx.agent_id || !permissions.contains(Permissions::PRIVACY) {
            warn!(
                agent = %ctx.agent_id,
                %session_id,
                "privacy activity for a session this device could not curtain — dropped"
            );
            return;
        }
        let reason = reason.filter(|r| {
            let ok = PrivacyActivityEvent::is_reason_code(r);
            if !ok {
                debug!(agent = %ctx.agent_id, %session_id, "privacy activity reason is not a code — dropped");
            }
            ok
        });
        let event = PrivacyActivityEvent {
            id: None,
            tenant_id: ctx.tenant_id,
            agent_id: ctx.agent_id,
            session_id,
            controller_user_id,
            kind,
            reason,
            at: bson::DateTime::now(),
        };
        if let Err(e) = self.state.privacy_activity.record(event).await {
            // Best-effort, like every activity log: never gates the session.
            debug!(agent = %ctx.agent_id, %e, "privacy activity write failed");
        }
    }

    /// The session's (agent, controller, grant). The live session first;
    /// after it ended (a device's last report arrives after its session is
    /// gone), the stored `remote_sessions` row, looked up within the
    /// reporting device's tenant.
    async fn grant_of(
        &self,
        ctx: &AgentCtx,
        session_id: ObjectId,
    ) -> Option<(ObjectId, ObjectId, Permissions)> {
        match self.state.fleet.rc_hub.session_grant(session_id) {
            Some(g) => Some(g),
            None => self
                .state
                .remote_sessions
                .find_in_tenant(ctx.tenant_id, session_id)
                .await
                .ok()
                .map(|s| (s.agent_id, s.controller_user_id, s.permissions)),
        }
    }

    /// FR-101 P3 — keep the clipboard and file traffic a device reports, but
    /// ONLY for a session of THIS agent, and only the kind its grant allowed:
    /// clipboard traffic needs `CLIPBOARD`, files need `FILES`. A device must
    /// not write about a session it does not hold, or claim traffic the
    /// session could not carry. The clipboard tallies are cumulative; the
    /// readings stored on the session turn them into what this sample adds.
    async fn record_transfers(&self, ctx: &AgentCtx, session_id: ObjectId, t: Transfers) {
        let Some((agent_id, controller_user_id, permissions)) =
            self.grant_of(ctx, session_id).await
        else {
            debug!(agent = %ctx.agent_id, %session_id, "transfer activity for an unknown session — dropped");
            return;
        };
        if agent_id != ctx.agent_id {
            warn!(
                agent = %ctx.agent_id,
                %session_id,
                "transfer activity for another device's session — dropped"
            );
            return;
        }
        let at = bson::DateTime::now();
        let row = |kind, count, bytes, name_sha256| TransferActivityEvent {
            id: None,
            tenant_id: ctx.tenant_id,
            agent_id: ctx.agent_id,
            session_id,
            controller_user_id,
            kind,
            count,
            bytes,
            name_sha256,
            at,
        };
        let mut rows = Vec::new();

        if !t.clipboard_to_host.is_zero() || !t.clipboard_from_host.is_zero() {
            if !permissions.contains(Permissions::CLIPBOARD) {
                warn!(
                    agent = %ctx.agent_id,
                    %session_id,
                    "clipboard traffic for a session without CLIPBOARD — dropped"
                );
            } else {
                match self
                    .state
                    .remote_sessions
                    .fold_clipboard_totals(
                        session_id,
                        ctx.agent_id,
                        t.clipboard_to_host,
                        t.clipboard_from_host,
                    )
                    .await
                {
                    Ok(Some((to_before, from_before))) => {
                        let to = t.clipboard_to_host.since(to_before);
                        if to.count > 0 {
                            rows.push(row(
                                TransferActivityKind::ClipboardToHost,
                                to.count,
                                to.bytes,
                                None,
                            ));
                        }
                        let from = t.clipboard_from_host.since(from_before);
                        if from.count > 0 {
                            rows.push(row(
                                TransferActivityKind::ClipboardFromHost,
                                from.count,
                                from.bytes,
                                None,
                            ));
                        }
                    }
                    // The session's row is written by the audit sink, which
                    // batches. The tallies are cumulative, so the next sample
                    // carries this one's too.
                    Ok(None) => {
                        debug!(agent = %ctx.agent_id, %session_id, "no session row yet — clipboard tallies wait for the next sample");
                    }
                    Err(e) => {
                        debug!(agent = %ctx.agent_id, %session_id, %e, "clipboard tally fold failed");
                    }
                }
            }
        }

        if !t.files.is_empty() {
            if !permissions.contains(Permissions::FILES) {
                warn!(
                    agent = %ctx.agent_id,
                    %session_id,
                    files = t.files.len(),
                    "file traffic for a session without FILES — dropped"
                );
            } else {
                let listed = t.files.len();
                for f in t
                    .files
                    .into_iter()
                    .take(TransferActivityEvent::MAX_FILES_PER_SAMPLE)
                {
                    if !TransferActivityEvent::is_name_hash(&f.name_sha256) {
                        debug!(agent = %ctx.agent_id, %session_id, "a file note without a SHA-256 name hash — dropped");
                        continue;
                    }
                    let kind = match f.dir {
                        TransferDirection::ToHost => TransferActivityKind::FileToHost,
                        TransferDirection::FromHost => TransferActivityKind::FileFromHost,
                    };
                    rows.push(row(kind, 1, f.bytes, Some(f.name_sha256)));
                }
                if listed > TransferActivityEvent::MAX_FILES_PER_SAMPLE {
                    warn!(
                        agent = %ctx.agent_id,
                        %session_id,
                        listed,
                        kept = TransferActivityEvent::MAX_FILES_PER_SAMPLE,
                        "more files in one sample than are kept"
                    );
                }
            }
        }

        if let Err(e) = self.state.transfer_activity.record_many(&rows).await {
            // Best-effort, like every activity log: never gates the session.
            debug!(agent = %ctx.agent_id, %e, "transfer activity write failed");
        }
    }
}
