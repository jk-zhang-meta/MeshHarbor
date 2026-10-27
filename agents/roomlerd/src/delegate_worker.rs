// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-43 P2a — the worker side of the GUI-worker delegation channel.
//!
//! The counterpart to [`crate::delegate`]. A worker the macOS supervisor
//! spawned is told so with `run --supervised` and reads its attach secret as
//! one line on **stdin**, then dials the daemon's LocalAPI socket and holds the
//! channel open for the daemon to push sessions down in P2b.
//!
//! ## Why stdin, and not the environment
//!
//! Because the environment does not arrive. The spawn chain runs through
//! `sudo`, and this host's `/etc/sudoers` carries the stock `Defaults
//! env_reset`, so everything the parent sets is discarded — measured on a real
//! Mac, and the reason P1's `ROOMLER_MACOS_SUPERVISED` marker turned out never
//! to have reached a single worker. Nothing noticed because nothing read it
//! yet.
//!
//! Of the three channels that DO survive the chain (measured: stdin, `sudo -E`,
//! and a `VAR=value` argument), stdin is the only one that is neither
//! world-readable nor dependent on sudoers policy:
//!
//! | channel | who can read it |
//! |---|---|
//! | `VAR=value` argument | **any** user on the box, via `ps` |
//! | `sudo -E` environment | root and the owning uid — but silently empty again if a policy ever sets `!setenv` |
//! | **stdin** | only the parent that holds the pipe |
//!
//! The `--supervised` flag is deliberately in argv, where it is harmless and
//! actually useful to an operator reading `ps`; only the secret is on the
//! pipe.
//!
//! ## Why a DEDICATED socket, and not the LocalAPI one
//!
//! Because an unprivileged worker cannot open the control socket, and must not
//! be able to: `/var/run/meshharbor/meshharbor.sock` is `0600 root` inside a `0700
//! root` directory, and it carries `config set`, `route add` and the rest. The
//! first shape of this code dialled it and failed in the field with
//! `Permission denied (os error 13)`.
//!
//! The fix is better than the thing it replaces. The delegation channel now has
//! its own `0600`-owned-by-the-worker socket in a `0711` directory, which means
//! LocalAPI keeps its request/response invariant **completely untouched** —
//! there is no longer any streaming exception on the control protocol at all.
//! The exception was the invasive part of the design; the field removed it.
//!
//! The worker still DIALS rather than listens: the daemon knows the console uid
//! and can create the endpoint before spawning, so there is no ordering
//! problem, and a channel that exists exactly when a worker is alive to serve
//! it is the honest shape.
//!
//! ## Failure is quiet and non-fatal, deliberately
//!
//! P2a's worker is still fully enrolled and still serves its own rc sessions.
//! A failed attach therefore costs nothing today, and must not take the worker
//! down: the supervisor would respawn it, fail again, and after
//! `MAX_FAST_EXITS` give up on a machine whose remote-desktop half was working
//! perfectly well. It retries on a ladder and says so, once per transition.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::delegate::DelegateFrame;
use crate::delegate::WorkerInbound;
use crate::delegate::write_frame;
use roomler_ai_remote_control::signaling::ClientMsg;

/// How often the worker proves the channel is alive.
///
/// A channel with no traffic is indistinguishable from a wedged one, and the
/// daemon needs to know which *before* a controller is waiting on it. 20 s is
/// well inside any reasonable session-setup budget and costs two small frames a
/// minute.
const PING_EVERY: Duration = Duration::from_secs(20);

/// Reconnect ladder bounds. The floor is short because a daemon restart is the
/// common cause and it comes back in seconds; the ceiling is low because the
/// worker is idle anyway and a minute of blindness after a transient failure is
/// a minute of a feature not working.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// What this worker tells the daemon it can do: the capture grants it holds
/// (FR-43 P2c) and, FR-85 P1e-mac, its `record` caps — the DEVICE's row
/// advertises them, because a delegated session records here, with this
/// process's recorder and under the person's own gates.
fn own_caps() -> roomler_ai_remote_control::models::AgentCaps {
    let caps = crate::encode::caps::detect();
    #[cfg(feature = "recording")]
    let caps = roomler_ai_remote_control::models::AgentCaps {
        record: crate::recording::remote::advertised(),
        ..caps
    };
    caps
}

/// FR-85 P1e-mac — the person's remote-recording gates, watched so a change
/// re-sends [`own_caps`]. Without the recorder there is nothing to watch.
#[cfg(feature = "recording")]
type GateWatch = tokio::sync::watch::Receiver<crate::recording::remote::Gates>;
#[cfg(not(feature = "recording"))]
struct GateWatch;

fn watch_gates() -> GateWatch {
    #[cfg(feature = "recording")]
    {
        crate::recording::remote::subscribe_gates()
    }
    #[cfg(not(feature = "recording"))]
    {
        GateWatch
    }
}

/// Resolves when the gates change; never, without the recorder (or if their
/// sender is ever gone, which a `static` cannot be — pending beats spinning).
async fn gates_changed(w: &mut GateWatch) {
    #[cfg(feature = "recording")]
    {
        if w.changed().await.is_ok() {
            return;
        }
    }
    #[cfg(not(feature = "recording"))]
    let _ = w;
    std::future::pending::<()>().await
}

/// Run the worker's side of the channel for the process lifetime.
///
/// Returns immediately unless this process was started as `run --supervised`,
/// which is every case except a worker the supervisor itself spawned:
/// launchd-owned workers, a hand-run `meshharbord run`, and the daemon.
pub async fn run(
    supervised: bool,
    // FR-43 P2b-2 — the signalling loop's two ends: delegated messages go IN,
    // a delegated session's replies come OUT. `None` when this process is not
    // a worker, in which case `supervised` is false too and we return at once.
    channels: Option<(
        tokio::sync::mpsc::Sender<WorkerInbound>,
        tokio::sync::mpsc::Receiver<ClientMsg>,
    )>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if !supervised {
        tracing::debug!("delegation: not a supervised worker; not attaching");
        return;
    }
    let Some((to_signaling, mut from_signaling)) = channels else {
        tracing::warn!("delegation: --supervised but no signalling channels; not attaching");
        return;
    };
    let Some(secret) = read_secret_from_stdin().await else {
        // LOUD, not silent: `--supervised` with no secret means the supervisor
        // and the worker disagree about how the secret travels, which is
        // exactly the failure that made P1's env marker a no-op for three
        // releases without anyone noticing.
        tracing::warn!(
            "delegation: started with --supervised but no secret arrived on stdin; not attaching"
        );
        return;
    };

    let mut backoff = BACKOFF_MIN;
    let mut last_error: Option<String> = None;
    loop {
        match attach_once(&secret, &to_signaling, &mut from_signaling, &mut shutdown).await {
            Ok(()) => {
                tracing::info!("delegation: channel closed by the daemon");
                backoff = BACKOFF_MIN;
                last_error = None;
            }
            Err(e) => {
                let msg = e.to_string();
                // Log the transition, not every retry: this loop runs for the
                // worker's whole life and a daemon that is simply absent would
                // otherwise fill the log with one line per second.
                if last_error.as_deref() != Some(msg.as_str()) {
                    tracing::warn!(
                        error = %msg,
                        retry_in_secs = backoff.as_secs(),
                        "delegation: attach failed"
                    );
                    last_error = Some(msg);
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

/// One attach attempt: connect, authorise, then pump until the channel ends.
async fn attach_once(
    secret: &str,
    to_signaling: &tokio::sync::mpsc::Sender<WorkerInbound>,
    from_signaling: &mut tokio::sync::mpsc::Receiver<ClientMsg>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    // Dial the daemon's DEDICATED delegation socket, not the LocalAPI control
    // socket. The control socket is `0600 root` in a `0700 root` directory —
    // an unprivileged worker cannot open it, and it should not be able to: it
    // carries `config set`, `route add` and the rest. Field-measured on the
    // MacBook, where the first shape of this code failed with
    // `Permission denied (os error 13)`.
    let uid = unsafe { libc::getuid() };
    let path = crate::delegate::socket_path(uid);
    let mut stream = tokio::net::UnixStream::connect(&path).await?;
    {
        use tokio::io::AsyncWriteExt;
        stream.write_all(secret.as_bytes()).await?;
        stream
            .write_all(
                b"
",
            )
            .await?;
        stream.flush().await?;
    }
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();

    // The daemon greets an accepted attach and silently closes a refused one,
    // so "the stream ended before a greeting" IS the refusal. There is
    // deliberately no reason on the wire — see `delegate::serve`.
    let greeting = match lines.next_line().await? {
        Some(line) => line,
        None => {
            return Err(std::io::Error::other(
                "daemon refused the attach (no greeting)",
            ));
        }
    };
    match serde_json::from_str::<DelegateFrame>(&greeting) {
        Ok(DelegateFrame::Attached { daemon_version }) => {
            if daemon_version != env!("CARGO_PKG_VERSION") {
                // Not fatal: the two halves are replaced independently, so a
                // brief mismatch across an update is normal. Worth saying once,
                // because a PERSISTENT mismatch means one half is not being
                // restarted and that is a real deployment fault.
                tracing::warn!(
                    daemon_version = %daemon_version,
                    worker_version = env!("CARGO_PKG_VERSION"),
                    "delegation: attached to a daemon of a different version"
                );
            } else {
                tracing::info!(version = %daemon_version, "delegation: attached to the daemon");
            }
        }
        Ok(other) => {
            return Err(std::io::Error::other(format!(
                "expected an `attached` greeting, got {other:?}"
            )));
        }
        Err(e) => {
            return Err(std::io::Error::other(format!("unparseable greeting: {e}")));
        }
    }

    // FR-43 P2c — tell the daemon what THIS process can do, as the first thing
    // after the handshake. The daemon is in session 0 and honestly reports
    // `no-gui-session`; these are the grants that make the DEVICE a capture
    // target, and without them its row tells the operator it is not one.
    //
    // Sent once per attach rather than on a timer: a permission change on macOS
    // requires re-launching the process anyway (TCC grants are read at start),
    // so a re-attach is exactly when it can differ. FR-85 P1e-mac — except the
    // `record` caps, which follow the person's live remote-recording gate: a
    // change re-sends them (the arm below). Subscribed BEFORE the first
    // announcement, so a change in between is never missed.
    let mut gates = watch_gates();
    {
        let caps = own_caps();
        tracing::info!(
            permissions = ?caps.permissions,
            record = ?caps.record,
            "delegation: announcing our capabilities to the daemon"
        );
        write_frame(
            &mut wr,
            &DelegateFrame::WorkerCaps {
                caps: Box::new(caps),
            },
        )
        .await?;
    }

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line? {
                    None => return Ok(()),
                    Some(line) if line.trim().is_empty() => {}
                    Some(line) => match serde_json::from_str::<DelegateFrame>(&line) {
                        Ok(DelegateFrame::Ping) => write_frame(&mut wr, &DelegateFrame::Pong).await?,
                        Ok(DelegateFrame::Pong) => {}
                        Ok(DelegateFrame::Attached { .. }) => {
                            tracing::debug!("delegation: a second `attached` frame; ignoring");
                        }
                        // Params must reach the signalling loop BEFORE the
                        // offer that consumes them; one ordered channel both
                        // ways is what guarantees it.
                        Ok(DelegateFrame::SessionParams(p)) => {
                            let sid = p.session_id.clone();
                            if to_signaling.try_send(WorkerInbound::Params(p)).is_err() {
                                tracing::warn!(
                                    session_id = %sid,
                                    "delegation: signalling queue full or closed; dropped session params"
                                );
                            }
                        }
                        Ok(DelegateFrame::ToWorker { msg }) => {
                            let kind = crate::delegate::server_msg_kind(&msg);
                            // A full queue means the signalling loop is wedged,
                            // not merely busy. Dropping and SAYING SO beats
                            // blocking this loop, which would also stop the
                            // liveness ping and make the daemon think the
                            // channel died when it is the loop that is stuck.
                            if to_signaling.try_send(WorkerInbound::Msg(msg)).is_err() {
                                tracing::warn!(
                                    kind,
                                    "delegation: signalling queue full or closed; dropped a message"
                                );
                            } else {
                                tracing::debug!(kind, "delegation: serving an rc message");
                            }
                        }
                        // #1882 — the overlay's blocks, from the daemon that
                        // runs it. This process runs none, and its OWN
                        // sessions resolve the device's `rc_overlay` against
                        // this registry: empty, the `utunN` address read as
                        // foreign and stayed a host candidate.
                        Ok(DelegateFrame::OverlayFootprint { v4_nets }) => {
                            tunnel_core::overlay_footprint::note_v4_blocks(&v4_nets);
                            tracing::info!(
                                blocks = v4_nets.len(),
                                "delegation: the daemon's overlay footprint received"
                            );
                        }
                        // FR-92 — a `roomler keep-busy status|off` reached the
                        // DAEMON's LocalAPI (a root caller never sees our
                        // per-user socket), and keep busy runs HERE. Answered
                        // inline: a status is immediate and an `off` waits at
                        // most `LOCAL_OFF_WAIT`, well inside the ping cadence.
                        Ok(DelegateFrame::KeepBusyAsk { id, off }) => {
                            let info = crate::keep_busy::answer_local(off).await;
                            tracing::info!(
                                id,
                                off,
                                on = info.on,
                                phase = %info.phase,
                                "delegation: answered the daemon's keep-busy question"
                            );
                            write_frame(
                                &mut wr,
                                &DelegateFrame::KeepBusyTold {
                                    id,
                                    info: Box::new(info),
                                },
                            )
                            .await?;
                        }
                        Ok(
                            DelegateFrame::FromWorker { .. }
                            | DelegateFrame::WorkerCaps { .. }
                            | DelegateFrame::KeepBusyTold { .. },
                        ) => {
                            // Worker → daemon only. A daemon sending one is
                            // confused about which end it is.
                            tracing::warn!("delegation: daemon sent a worker-only frame; ignoring");
                        }
                        // Skip, never close: a NEWER daemon may push a frame
                        // this worker has never heard of, and an additive
                        // protocol is only additive if old readers skip it.
                        Err(e) => tracing::debug!(error = %e, "delegation: skipping a frame"),
                    },
                }
            }
            // Replies from a delegated session: the answer, its peer's ICE,
            // its stats, its terminate. Written from THIS loop so they are
            // ordered with respect to each other and to the liveness frames.
            reply = from_signaling.recv() => {
                match reply {
                    Some(msg) => {
                        write_frame(&mut wr, &DelegateFrame::FromWorker { msg: Box::new(msg) })
                            .await?;
                    }
                    // The signalling loop is gone; so is any session it held.
                    None => return Ok(()),
                }
            }
            _ = tokio::time::sleep(PING_EVERY) => {
                write_frame(&mut wr, &DelegateFrame::Ping).await?;
            }
            // FR-85 P1e-mac — the person switched remote recording on or off:
            // the device's row must say so within a heartbeat, and an OFF
            // must stop the hub granting RECORD.
            () = gates_changed(&mut gates) => {
                let caps = own_caps();
                tracing::info!(
                    record = ?caps.record,
                    "delegation: the remote-recording gates changed; re-announcing our capabilities"
                );
                write_frame(
                    &mut wr,
                    &DelegateFrame::WorkerCaps {
                        caps: Box::new(caps),
                    },
                )
                .await?;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Read the attach secret: one line on stdin, bounded.
///
/// Bounded because a worker that hangs waiting for a line that will never come
/// is worse than one that gives up — the supervisor would see a process that
/// starts and does nothing, and the operator would see a remote-desktop half
/// that is running and useless. Five seconds is far longer than a parent that
/// already has the secret in hand needs.
async fn read_secret_from_stdin() -> Option<String> {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut line)
            .await
    })
    .await;
    match read {
        Ok(Ok(n)) if n > 0 => {
            let secret = line.trim().to_string();
            (!secret.is_empty()).then_some(secret)
        }
        Ok(Ok(_)) => None,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "delegation: could not read the secret from stdin");
            None
        }
        Err(_) => {
            tracing::warn!("delegation: timed out waiting for the secret on stdin");
            None
        }
    }
}
