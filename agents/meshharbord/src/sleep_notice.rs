// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-93 P5h — a computer going to sleep says so to every viewer first.
//!
//! A sleeping host says nothing, so its viewer saw the picture stop with no
//! reason. Measured on the FR-93 lab (2026-10-15, GNOME 50 per-user, 0.4.136):
//! the viewer dropped 5.6 s into a suspend and showed no reason for the 30 s
//! the computer slept. AC7's rule is "recover within 10 s, or name the reason".
//!
//! So while any remote-control session is live, the daemon holds a logind
//! **delay** inhibitor on `sleep`. logind announces every sleep with
//! `PrepareForSleep(true)` and then waits for its delay inhibitors (up to its
//! `InhibitDelayMaxSec`, 5 s by default). The watcher sends each live
//! session's controller `rc:media-waiting` for `host_sleep` over that
//! session's own control channel, lets go, and the computer sleeps. After the
//! wake the viewer reconnects by itself, and the new session names whatever
//! then holds the picture back (a lock screen: P5b).
//!
//! ⚠️ A *delay* inhibitor, never a *block*: the person at the computer keeps
//! the last word about sleep. Keeping a host awake through a session is
//! FR-55's rule 1, not this.
//! ⚠️ Held only while a session is live, so an idle daemon shows nothing in
//! `systemd-inhibit --list`.
//!
//! The registry is on every platform (every session registers its control
//! channel); the watcher is Linux's, and needs D-Bus (`portal-capture`, which
//! every shipped Linux agent carries through `full`).
//!
//! Kill switch `ROOMLERD_SLEEP_NOTICE=0`; P2d-2's `ROOMLERD_MEDIA_WAITING=0`
//! silences it as it does every waiting notice.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bson::oid::ObjectId;
use webrtc::data_channel::RTCDataChannel;

/// A session's control channel, as the session keeps it: empty until the
/// viewer opens it.
pub type ControlDc = Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>;

fn registry() -> &'static Mutex<HashMap<u64, (ObjectId, ControlDc)>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, (ObjectId, ControlDc)>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A live session's place in the registry. Dropped with the session.
pub struct Registration(u64);

impl Drop for Registration {
    fn drop(&mut self) {
        registry()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

/// A remote-control session is live: its controller is told when this
/// computer goes to sleep, for as long as the registration lives.
pub fn register(session: ObjectId, control_dc: ControlDc) -> Registration {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, (session, control_dc));
    Registration(id)
}

/// How many sessions would be told right now.
pub fn live() -> usize {
    registry().lock().unwrap_or_else(|p| p.into_inner()).len()
}

/// FR-93 P5h kill switch `ROOMLERD_SLEEP_NOTICE=0`: no inhibitor, no notice,
/// as before P5h.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
fn enabled() -> bool {
    tunnel_core::env::flag("SLEEP_NOTICE", true)
}

/// Tell every live session's controller that this computer is going to sleep,
/// each within a bound, all at once. How many it reached.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
async fn tell_all() -> usize {
    let Some(payload) = crate::peer::host_sleep_notice() else {
        return 0;
    };
    let channels: Vec<ControlDc> = registry()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .values()
        .map(|(_, dc)| dc.clone())
        .collect();
    let sends = channels.iter().map(|dc| {
        crate::peer::send_control_notice(
            dc,
            &payload,
            std::time::Duration::from_millis(100),
            SEND_DEADLINE,
            std::time::Duration::from_secs(1),
        )
    });
    futures::future::join_all(sends)
        .await
        .into_iter()
        .filter(|sent| *sent)
        .count()
}

/// How long one session's notice may take. Well inside logind's 5 s default
/// for a delay inhibitor, so the computer sleeps on time even when a viewer's
/// channel is not open.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
const SEND_DEADLINE: std::time::Duration = std::time::Duration::from_millis(1500);

/// Whether the watcher should hold its delay inhibitor, and what to do now:
/// take it, let it go, or leave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
enum Lock {
    Take,
    Release,
    Keep,
}

/// [`Lock`] as a pure rule: held exactly while a session is live, and never
/// taken while a sleep is under way. logind refuses an inhibitor for a sleep
/// it is already carrying out (`OperationInProgress`, measured on the FR-93
/// lab), and the next one is taken after the wake.
#[cfg_attr(
    not(all(target_os = "linux", feature = "portal-capture")),
    allow(dead_code)
)]
fn lock_step(live_sessions: usize, held: bool, sleeping: bool) -> Lock {
    match (live_sessions > 0 && !sleeping, held) {
        (true, false) => Lock::Take,
        (false, true) => Lock::Release,
        _ => Lock::Keep,
    }
}

/// Start the watcher, once per process. `runtime` sends the notices: the
/// watcher is a plain thread, because zbus's blocking API panics on a runtime
/// thread.
#[cfg(all(target_os = "linux", feature = "portal-capture"))]
pub fn start(runtime: tokio::runtime::Handle) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    if !enabled() {
        tracing::info!("sleep notice off (ROOMLERD_SLEEP_NOTICE=0, FR-93 P5h)");
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("sleep-notice".into())
        .spawn(move || linux::watch(runtime));
    if let Err(e) = spawned {
        tracing::warn!(%e, "sleep notice: no thread to watch logind (FR-93 P5h)");
    }
}

/// Nothing to watch where there is no logind.
#[cfg(not(all(target_os = "linux", feature = "portal-capture")))]
pub fn start(_runtime: tokio::runtime::Handle) {}

#[cfg(all(target_os = "linux", feature = "portal-capture"))]
mod linux {
    use super::{Lock, live, lock_step, tell_all};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    const LOGIND: &str = "org.freedesktop.login1";
    const LOGIND_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";

    /// How often the inhibitor is matched to the live sessions.
    const TICK: Duration = Duration::from_secs(2);

    /// Forever: a watcher that lost logind (a restarted logind, no system bus
    /// yet at boot) tries again a minute later.
    pub(super) fn watch(runtime: tokio::runtime::Handle) {
        loop {
            if let Err(e) = watch_once(&runtime) {
                tracing::warn!(%e, "sleep notice: logind unavailable; trying again in 60 s (FR-93 P5h)");
            }
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    fn watch_once(runtime: &tokio::runtime::Handle) -> anyhow::Result<()> {
        let conn = zbus::blocking::Connection::system()?;
        let manager = zbus::blocking::Proxy::new(&conn, LOGIND, LOGIND_PATH, MANAGER)?;
        // zbus's blocking signal iterator has no timed `next`, so the signals
        // are read on their own thread and handed over a channel the tick can
        // wait on with a bound.
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let signals = manager.clone();
        std::thread::Builder::new()
            .name("sleep-notice-signals".into())
            .spawn(move || {
                let Ok(mut stream) = signals.receive_signal("PrepareForSleep") else {
                    return;
                };
                for msg in &mut stream {
                    let Ok(start) = msg.body().deserialize::<bool>() else {
                        continue;
                    };
                    if tx.send(start).is_err() {
                        return;
                    }
                }
            })?;
        tracing::info!("sleep notice: watching logind for sleep (FR-93 P5h)");
        let mut lock: Option<zbus::zvariant::OwnedFd> = None;
        // From `PrepareForSleep(true)` to `(false)`: the sleep is under way.
        let mut sleeping = false;
        loop {
            // A wake whose signal never arrived still ends the sleep: logind's
            // own property says whether one is under way.
            if sleeping
                && manager
                    .get_property::<bool>("PreparingForSleep")
                    .is_ok_and(|p| !p)
            {
                sleeping = false;
            }
            match lock_step(live(), lock.is_some(), sleeping) {
                Lock::Take => match take(&manager) {
                    Ok(fd) => lock = Some(fd),
                    Err(e) => {
                        tracing::warn!(%e, "sleep notice: logind refused a delay inhibitor (FR-93 P5h)")
                    }
                },
                Lock::Release => lock = None,
                Lock::Keep => {}
            }
            match rx.recv_timeout(TICK) {
                Ok(true) => {
                    let sessions = live();
                    let told = runtime.block_on(tell_all());
                    tracing::info!(
                        sessions,
                        told,
                        "the computer is going to sleep: viewers told (FR-93 P5h)"
                    );
                    // Let it sleep. The next tick after the wake takes the
                    // inhibitor again if a session is still live.
                    lock = None;
                    sleeping = true;
                }
                Ok(false) => {
                    sleeping = false;
                    tracing::info!("the computer woke up (FR-93 P5h)");
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("logind's PrepareForSleep stream ended")
                }
            }
        }
    }

    /// A logind delay inhibitor on sleep, held for as long as its fd is.
    fn take(manager: &zbus::blocking::Proxy<'_>) -> zbus::Result<zbus::zvariant::OwnedFd> {
        manager
            .call_method(
                "Inhibit",
                &(
                    "sleep",
                    "Roomler",
                    "tell remote viewers that this computer is going to sleep",
                    "delay",
                ),
            )?
            .body()
            .deserialize::<zbus::zvariant::OwnedFd>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-93 P5h — the inhibitor is held exactly while a session is live:
    /// taken with the first, let go with the last, and nothing in between.
    /// Never taken while a sleep is under way: logind refuses it then.
    #[test]
    fn the_inhibitor_is_held_exactly_while_a_session_is_live() {
        assert_eq!(lock_step(1, false, false), Lock::Take);
        assert_eq!(lock_step(2, true, false), Lock::Keep);
        assert_eq!(lock_step(0, true, false), Lock::Release);
        assert_eq!(lock_step(0, false, false), Lock::Keep);
        assert_eq!(lock_step(1, false, true), Lock::Keep);
        assert_eq!(lock_step(1, true, true), Lock::Release);
    }

    /// P5h — a session is told for exactly as long as it is registered. By
    /// its own entries: the registry is process-wide, so another test's
    /// sessions may be in it too.
    #[test]
    fn a_session_is_registered_until_it_ends() {
        let listed = |id: u64| registry().lock().unwrap().contains_key(&id);
        let dc: ControlDc = Arc::new(tokio::sync::Mutex::new(None));
        let a = register(ObjectId::new(), dc.clone());
        let b = register(ObjectId::new(), dc);
        let (ida, idb) = (a.0, b.0);
        assert!(listed(ida) && listed(idb));
        assert!(live() >= 2);
        drop(a);
        assert!(!listed(ida) && listed(idb));
        drop(b);
        assert!(!listed(idb));
    }

    /// P5h — the notice is a `host_sleep` wait, with its hint, and it lasts as
    /// long as any host wait (no sleep has a known end).
    #[test]
    fn the_notice_names_the_sleep() {
        let notice = crate::peer::host_sleep_notice().expect("on by default");
        let v: serde_json::Value = serde_json::from_str(&notice).expect("JSON");
        assert_eq!(v["t"], "rc:media-waiting");
        assert_eq!(v["for"], "host_sleep");
        assert_eq!(v["waits_ms"], 3_600_000);
        assert!(
            v["hint"].as_str().unwrap().contains("going to sleep"),
            "{notice}"
        );
    }
}
