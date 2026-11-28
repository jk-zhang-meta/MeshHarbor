// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — SSH subsystem `meshharbor-pty@v1` handler and bidirectional
//! channel ⇄ `ssh-pty-host` IPC relay.

use std::time::Duration;

use meshharbor_node_core::pty_resume::{
    DEFAULT_ORPHAN_TTL_SECS, DEFAULT_RING_BYTES, PROTO_VERSION, RefuseReason, RunAsDescriptor,
    SessionDescriptor, SessionId, SessionMode,
    frame::{FrameDecoder, HelloFrame, OpenedFrame, WireFrame},
    ipc::{AttachStartFrame, IpcFrame, SpawnSpec},
    now_unix_ms,
};
use meshharbor_remote_control::models::{SshActivityKind, ssh_limits};
use rand::RngCore;
use russh::ChannelId;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::{
    HostIpcStream, ResumeLookup, mark_detached, mark_ended, resume_enabled_globally,
    snapshot_enabled_globally, spawn_session, verify_and_attach,
};

/// Everything the `meshharbor-pty@v1` subsystem task needs from `ssh::Handler`.
pub struct SubsystemContext {
    pub handle: russh::server::Handle,
    pub channel: ChannelId,
    pub org_id: String,
    pub agent_id: String,
    pub host_key_fp: String,
    pub client_key_fp: String,
    pub client_key_in_authorized_list: bool,
    pub classic_counted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub via_service: bool,
    pub peer: std::net::SocketAddr,
    /// `Some` if the connection authenticated as a fresh grant or key-list session;
    /// `None` if authenticated as `ConnClass::ResumeOnly`.
    pub open_auth: Option<OpenAuthContext>,
    /// `Some` if authenticated as `ConnClass::ResumeOnly` (may ONLY send `Attach`).
    pub resume_only: Option<ResumeLookup>,
    pub activity: Option<(crate::ssh::ActivitySink, Option<String>, String)>,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Entitlement resolved at auth for `WireFrame::Open`.
pub struct OpenAuthContext {
    pub principal: String,
    pub caller_label: String,
    pub grant_id: Option<String>,
    pub run_as: Result<crate::exec::RunAs, String>,
    pub consent_sentinel: Option<String>,
    pub asker: crate::ssh::Asker,
    pub session_secs: u64,
    pub deadline: Option<tokio::time::Instant>,
    pub resume_allowed: Option<bool>,
    pub key_list_auth: bool,
}

/// Serve one `meshharbor-pty@v1` SSH subsystem channel.
pub async fn run_subsystem(mut ctx: SubsystemContext, mut in_rx: mpsc::Receiver<Vec<u8>>) {
    let mut server_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut server_nonce);

    let mut caps = vec!["bytes".to_string()];
    if snapshot_enabled_globally() {
        caps.push("snapshot".to_string());
    }
    let hello = WireFrame::Hello(HelloFrame {
        proto_max: PROTO_VERSION,
        server_nonce,
        caps,
    });
    if send_wire(&ctx.handle, ctx.channel, &hello).await.is_err() {
        return;
    }

    let mut decoder = FrameDecoder::new();
    // Wait up to 10 s for the opening `Open` or `Attach` frame.
    let first = match tokio::time::timeout(
        Duration::from_secs(10),
        read_next_wire(&mut in_rx, &mut decoder),
    )
    .await
    {
        Ok(Ok(Some(frame))) => frame,
        _ => {
            let _ = ctx.handle.close(ctx.channel).await;
            return;
        }
    };

    match first {
        WireFrame::Open(open) => {
            if ctx.resume_only.is_some() {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "resume-only connection may only Attach to an existing session"
                            .into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }
            let Some(auth) = ctx.open_auth.take() else {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "no open session entitlement".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            };
            if ctx.via_service
                || !resume_enabled_globally()
                || !(auth.key_list_auth || auth.resume_allowed == Some(true))
            {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "resumable SSH is disabled by policy on this device".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }
            if open.mode != SessionMode::Pty {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "only interactive PTY mode is currently enabled".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            let run_as = match auth.run_as {
                Ok(r) => r,
                Err(why) => {
                    let _ = send_wire(
                        &ctx.handle,
                        ctx.channel,
                        &WireFrame::Refused(RefuseReason::Policy { detail: why }),
                    )
                    .await;
                    let _ = ctx.handle.close(ctx.channel).await;
                    return;
                }
            };

            // Enforce the exact same operator consent gate as classic shells!
            if let Some(sentinel) = &auth.consent_sentinel
                && let Err(why) = await_subsystem_consent(
                    &auth.asker,
                    &auth.caller_label,
                    sentinel,
                    "open a resumable interactive shell",
                )
                .await
            {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy { detail: why }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            let sid = SessionId::generate();
            let now = now_unix_ms();
            // Compute remaining lifetime from the resolved grant deadline so
            // delayed subsystem opens never reset or extend the session clock!
            let ttl_secs = match auth.deadline {
                Some(dl) => {
                    let now_inst = tokio::time::Instant::now();
                    if dl <= now_inst {
                        let _ = send_wire(
                            &ctx.handle,
                            ctx.channel,
                            &WireFrame::Refused(RefuseReason::Expired),
                        )
                        .await;
                        let _ = ctx.handle.close(ctx.channel).await;
                        return;
                    }
                    dl.saturating_duration_since(now_inst)
                        .as_secs()
                        .clamp(1, ssh_limits::MAX_SESSION_SECS)
                }
                None => ssh_limits::clamp_session_secs(auth.session_secs),
            };
            let deadline_ms = now.saturating_add(ttl_secs * 1000);
            let detach_ttl_ms = ttl_secs * 1000;
            let orphan_ttl_ms = DEFAULT_ORPHAN_TTL_SECS * 1000;

            let cmd_digest = open
                .command
                .as_ref()
                .map(|c| hex::encode(Sha256::digest(c.as_bytes())));
            let run_as_desc = match &run_as {
                crate::exec::RunAs::Daemon => RunAsDescriptor::Daemon,
                crate::exec::RunAs::ConsoleUser => RunAsDescriptor::ConsoleUser,
                crate::exec::RunAs::Named(u) => RunAsDescriptor::Named {
                    username: u.clone(),
                    uid: None,
                    gid: None,
                },
            };

            let descriptor = SessionDescriptor {
                sid,
                org_id: ctx.org_id.clone(),
                agent_id: ctx.agent_id.clone(),
                principal: auth.principal.clone(),
                grant_id: auth.grant_id.clone(),
                client_key_fp: ctx.client_key_fp.clone(),
                host_key_fp: ctx.host_key_fp.clone(),
                run_as: run_as_desc.clone(),
                mode: open.mode,
                cmd_digest,
                created_ms: now,
                deadline_ms,
                detach_ttl_ms,
                orphan_ttl_ms,
                two_factor_at_ms: None,
                offline_iat_ms: None,
                offline_exp_ms: None,
                via_service: ctx.via_service,
                key_list_auth: auth.key_list_auth,
                policy_digest: String::new(),
                epoch: 1,
            };

            let spec = SpawnSpec {
                mode: open.mode,
                term: if open.term.is_empty() {
                    "xterm-256color".into()
                } else {
                    open.term
                },
                cols: open.cols,
                rows: open.rows,
                command: open.command,
                env: meshharbor_node_core::pty_resume::filter_open_env(&open.env),
                run_as: run_as_desc,
                ring_bytes: DEFAULT_RING_BYTES as u32,
            };

            // 0.5.0 — Re-check revocation AFTER consent wait and right before
            // spawning the persistent PTY so an admin disconnect during consent
            // or auth can never create a surviving resumable shell.
            if crate::ssh::is_grant_or_principal_revoked(
                &ctx.org_id,
                auth.grant_id.as_deref(),
                &auth.principal,
                &auth.caller_label,
            ) {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "session revoked by administrator".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            let spawned = match spawn_session(descriptor, spec).await {
                Ok(s) => s,
                Err(reason) => {
                    let _ = send_wire(&ctx.handle, ctx.channel, &WireFrame::Refused(reason)).await;
                    let _ = ctx.handle.close(ctx.channel).await;
                    return;
                }
            };

            // 0.5.0 — Post-spawn tombstone re-check closes the async spawn
            // window: if revocation landed while `spawn_session` was starting
            // the PTY host, immediately terminate the newly created session.
            if crate::ssh::is_grant_or_principal_revoked(
                &ctx.org_id,
                auth.grant_id.as_deref(),
                &auth.principal,
                &auth.caller_label,
            ) {
                let _ = super::terminate_session_in_org(
                    &ctx.org_id,
                    &sid.to_hex(),
                    meshharbor_node_core::pty_resume::TerminateReason::Revoked,
                )
                .await;
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "session revoked by administrator".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            let attach_gen = spawned.attach_gen;
            let opened = WireFrame::Opened(OpenedFrame {
                session_id: sid,
                resume_secret: *spawned.resume_secret,
                persist: spawned.entry.persist.clone(),
                deadline_ms,
                detach_ttl_ms,
                ring_bytes: DEFAULT_RING_BYTES as u32,
            });
            if send_wire(&ctx.handle, ctx.channel, &opened).await.is_err() {
                mark_detached(&sid, attach_gen);
                return;
            }
            // FR-96 P2b: only release the classic connection hold when the
            // session actually survives daemon restart (containers / degraded
            // hosts stay counted so auto-update holds off while active!).
            if spawned.entry.persist.survives_restart {
                crate::ssh::release_classic_connection_slot(&ctx.classic_counted);
            }

            if let Some((sink, grant_id, caller)) = &ctx.activity {
                sink.report(
                    grant_id.clone(),
                    caller,
                    SshActivityKind::Shell,
                    Some(format!("persistent sid={}", sid.short_hex())),
                    None,
                    true,
                );
            }

            // Immediately attach the initial stream on the host so live PTY bytes
            // start flowing right after `Opened` with zero extra RTT.
            let mut stream = spawned.stream;
            if IpcFrame::AttachStart(AttachStartFrame {
                last_rx: 0,
                c2s_next_client: 0,
                cols: open.cols,
                rows: open.rows,
                snapshot_allowed: snapshot_enabled_globally(),
                server_proof: [0u8; 32],
            })
            .write_to(&mut stream)
            .await
            .is_err()
            {
                mark_detached(&sid, attach_gen);
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            // Swallow the initial synthetic `Attached` frame from the host on Open,
            // since the client already received `Opened` and expects live `Data` next.
            match tokio::time::timeout(Duration::from_secs(2), IpcFrame::read_from(&mut stream))
                .await
            {
                Ok(Ok(Some(IpcFrame::Wire(WireFrame::Attached(_))))) => {}
                _ => {
                    mark_detached(&sid, attach_gen);
                    let _ = ctx.handle.close(ctx.channel).await;
                    return;
                }
            }

            relay_loop(sid, attach_gen, stream, in_rx, decoder, ctx).await;
        }

        WireFrame::Attach(attach) => {
            if ctx.via_service || !resume_enabled_globally() {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::Policy {
                        detail: "resumable SSH is disabled by policy on this device".into(),
                    }),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }
            // If auth matched a tombstone, deliver exact terminal reason now.
            if let Some(ResumeLookup::Tombstone { reason, .. }) = ctx.resume_only {
                let _ = send_wire(&ctx.handle, ctx.channel, &WireFrame::Refused(reason)).await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }
            // Enforce that a ResumeOnly connection can ONLY attach to its bound sid.
            if let Some(ResumeLookup::Live(bound_sid)) = ctx.resume_only
                && bound_sid != attach.session_id
            {
                let _ = send_wire(
                    &ctx.handle,
                    ctx.channel,
                    &WireFrame::Refused(RefuseReason::BadProof),
                )
                .await;
                let _ = ctx.handle.close(ctx.channel).await;
                return;
            }

            let attached = match verify_and_attach(
                &ctx.org_id,
                &attach.session_id,
                &server_nonce,
                &attach.client_nonce,
                &attach.proof,
                &ctx.host_key_fp,
                &ctx.client_key_fp,
                ctx.client_key_in_authorized_list,
                attach.last_rx,
                attach.c2s_next,
                attach.cols,
                attach.rows,
            )
            .await
            {
                Ok(a) => a,
                Err(reason) => {
                    warn!(
                        peer = %ctx.peer,
                        sid = %attach.session_id.short_hex(),
                        ?reason,
                        "ssh-persist: attach refused"
                    );
                    let _ = send_wire(&ctx.handle, ctx.channel, &WireFrame::Refused(reason)).await;
                    let _ = ctx.handle.close(ctx.channel).await;
                    return;
                }
            };

            if attached.entry.persist.survives_restart {
                crate::ssh::release_classic_connection_slot(&ctx.classic_counted);
            }

            info!(
                peer = %ctx.peer,
                sid = %attach.session_id.short_hex(),
                principal = %attached.entry.descriptor.principal,
                "ssh-persist: client reattached to surviving PTY session"
            );

            // Best-effort person-at-the-device awareness log/activity.
            if let Some((sink, grant_id, caller)) = &ctx.activity {
                sink.report(
                    grant_id.clone(),
                    caller,
                    SshActivityKind::Shell,
                    Some(format!("resumed sid={}", attach.session_id.short_hex())),
                    None,
                    true,
                );
            }

            relay_loop(
                attach.session_id,
                attached.attach_gen,
                attached.stream,
                in_rx,
                decoder,
                ctx,
            )
            .await;
        }

        _ => {
            let _ = send_wire(
                &ctx.handle,
                ctx.channel,
                &WireFrame::Refused(RefuseReason::Policy {
                    detail: "expected Open or Attach as first frame".into(),
                }),
            )
            .await;
            let _ = ctx.handle.close(ctx.channel).await;
        }
    }
}

async fn relay_loop(
    sid: SessionId,
    attach_gen: u64,
    stream: HostIpcStream,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    mut decoder: FrameDecoder,
    ctx: SubsystemContext,
) {
    let (mut ipc_rd, mut ipc_wr) = tokio::io::split(stream);
    // Dedicated reader task makes `tokio::select!` 100% cancel-safe (partial
    // `IpcFrame::read_from` reads can NEVER be cancelled mid-frame!).
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<IpcFrame>(128);
    let ipc_reader = tokio::spawn(async move {
        while let Ok(Some(frame)) = IpcFrame::read_from(&mut ipc_rd).await {
            if ipc_tx.send(frame).await.is_err() {
                break;
            }
        }
    });

    let mut terminated_or_exited = false;
    let mut superseded_flag = false;

    'outer: loop {
        // First drain any already-buffered client frames from `decoder`.
        while let Ok(Some(wf)) = decoder.next_wire() {
            let is_detach = matches!(wf, WireFrame::Detach);
            let is_term = matches!(wf, WireFrame::Terminate);
            if IpcFrame::Wire(wf).write_to(&mut ipc_wr).await.is_err() {
                break 'outer;
            }
            if is_detach {
                debug!(sid = %sid.short_hex(), "ssh-persist: client detached cleanly");
                break 'outer;
            }
            if is_term {
                // Wait briefly for the host to confirm child termination with
                // `WireFrame::Exited` so `mh ssh --kill` / `~.` get confirmed exit.
                let wait_until = tokio::time::Instant::now() + Duration::from_secs(3);
                while tokio::time::Instant::now() < wait_until {
                    let rem = wait_until.saturating_duration_since(tokio::time::Instant::now());
                    match tokio::time::timeout(rem, ipc_rx.recv()).await {
                        Ok(Some(IpcFrame::Wire(WireFrame::Exited(st)))) => {
                            mark_ended(&sid, st.clone());
                            terminated_or_exited = true;
                            let _ =
                                send_wire(&ctx.handle, ctx.channel, &WireFrame::Exited(st)).await;
                            break;
                        }
                        Ok(Some(IpcFrame::Wire(other))) => {
                            let _ = send_wire(&ctx.handle, ctx.channel, &other).await;
                        }
                        Ok(Some(_)) => continue,
                        Ok(None) | Err(_) => break,
                    }
                }
                break 'outer;
            }
        }

        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                // Daemon shutting down or session generation cancelled.
                // Do NOT kill the host here — CloseAccess explicitly calls
                // `ssh_persist::terminate_all`, while restart/update leaves hosts alive!
                break;
            }
            chunk = in_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        decoder.push(&bytes);
                    }
                    None => break,
                }
            }
            frame = ipc_rx.recv() => {
                match frame {
                    Some(IpcFrame::Wire(wf)) => {
                        let superseded = matches!(
                            wf,
                            WireFrame::Notice(meshharbor_node_core::pty_resume::NoticeKind::Superseded)
                        );
                        let exited_status = if let WireFrame::Exited(ref st) = wf {
                            Some(st.clone())
                        } else {
                            None
                        };
                        if send_wire(&ctx.handle, ctx.channel, &wf).await.is_err() {
                            // Do NOT mark_ended before `Exited` actually wrote
                            // to the SSH channel — a drop right here leaves the
                            // session replayable so the client can reconnect and
                            // receive its final output + exit status.
                            break;
                        }
                        if let Some(st) = exited_status {
                            mark_ended(&sid, st);
                            terminated_or_exited = true;
                        }
                        if superseded {
                            superseded_flag = true;
                            break;
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }

    ipc_reader.abort();
    if !terminated_or_exited && !superseded_flag {
        mark_detached(&sid, attach_gen);
    }
    let _ = ctx.handle.close(ctx.channel).await;
}

async fn read_next_wire(
    in_rx: &mut mpsc::Receiver<Vec<u8>>,
    decoder: &mut FrameDecoder,
) -> Result<Option<WireFrame>, String> {
    loop {
        if let Some(frame) = decoder.next_wire().map_err(|e| e.to_string())? {
            return Ok(Some(frame));
        }
        match in_rx.recv().await {
            Some(chunk) => decoder.push(&chunk),
            None => return Ok(None),
        }
    }
}

async fn send_wire(
    handle: &russh::server::Handle,
    channel: ChannelId,
    frame: &WireFrame,
) -> Result<(), ()> {
    let raw = frame.encode().map_err(|_| ())?;
    handle.data(channel, raw).await.map_err(|_| ())
}

async fn await_subsystem_consent(
    asker: &crate::ssh::Asker,
    caller: &str,
    sentinel: &str,
    summary: &str,
) -> Result<(), String> {
    crate::ssh::ask_here_for_subsystem(asker, caller, sentinel, summary).await
}
