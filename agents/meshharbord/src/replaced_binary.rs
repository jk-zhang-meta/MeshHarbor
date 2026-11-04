// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-96 P2b — a per-user Linux daemon restarts onto its replaced binary,
//! once nothing it serves would be cut.
//!
//! Nothing else does it. The root update helper (P1) installs as root and
//! never speaks to the user's daemon; the `.deb`'s postinst reloads units and,
//! by rule, never restarts anything; an admin's `apt upgrade` and a hand
//! install leave the daemon on the old image until the next reboot. So the
//! daemon watches its own binary (D2) and restarts when idle (D1), with a
//! ceiling.
//!
//! **Replaced** means the file this process runs is not the file its exec path
//! names now, by `(st_dev, st_ino)`. `/proc/self/exe` keeps naming the running
//! image whether it was unlinked (dpkg) or renamed (the tarball's `.prev`), so
//! a ` (deleted)` suffix is not the test; the inode is. Every installer in use
//! replaces by rename, and writing over a running executable fails `ETXTBSY`,
//! so another inode is another file. At start the two must agree, or this
//! filesystem cannot tell a replacement and the watch stands down.
//!
//! A replacement is acted on only once it has **settled** ([`SETTLE`]: an
//! install writes the binary before its libraries and units), and only if the
//! new binary **answers `--version`** with a version other than this one's: a
//! file that cannot run is never restarted onto, and a reinstall of the same
//! release is not worth cutting anything for.
//!
//! **Idle** ([`Busy`]) is: no remote-control session, no SSH connection, no
//! transfer or recording — work a restart cuts, and does cut after
//! [`CEILING`] — and no network transition in the last 10 min and no
//! in-process install in flight: states a restart could wedge, never forced.
//! Running agent turns are waited for as an install waits for them.
//!
//! The restart itself is FR-84 D3's
//! ([`crate::localapi_state::RestartHandle::arm_from_within`]): only under a
//! supervisor that relaunches the process, rate-limited by the persisted
//! record, read back from systemd before anything exits.

use std::time::{Duration, Instant};

/// How often the binary is looked at.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);

/// How long a replacement must stay put before it is acted on: an install
/// places the binary first and its libraries and units after it.
pub const SETTLE: Duration = Duration::from_secs(120);

/// D1's ceiling: after this long waiting for idle, the work is cut.
pub const CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// After a refused restart, or a binary that did not answer `--version`, the
/// next attempt.
pub const RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

/// How long the new binary gets to answer `--version`.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// While a restart is deferred, how often that is logged.
pub const DEFER_LOG_EVERY: Duration = Duration::from_secs(60 * 60);

/// A file's identity on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

/// What `--version` said about the binary at the exec path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It runs, and is another version (newer, or an admin's deliberate
    /// downgrade: either way it is what is installed).
    Other(String),
    /// It runs, and is this version: nothing to restart for.
    Same,
    /// It did not answer: never restarted onto, asked again after
    /// [`RETRY_AFTER`].
    Unusable(String),
}

/// What a restart would cut, or wedge, right now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Busy {
    pub rc_sessions: usize,
    pub ssh_connections: usize,
    /// File transfers in flight, plus a screen recording
    /// ([`crate::updater::active_work`]).
    pub work: usize,
    /// The network moved in the last 10 min (R5b: a restart beside a VPN
    /// transition can lock the machine out).
    pub net_transition: bool,
    /// This daemon spawned an installer in the last 10 min: the in-process
    /// path restarts the daemon itself, and a restart now would kill the
    /// installer it is waiting on.
    pub install_in_flight: bool,
}

impl Busy {
    /// Work a restart would CUT — cut after [`CEILING`].
    pub fn cuttable(&self) -> bool {
        self.rc_sessions + self.ssh_connections + self.work > 0
    }

    /// States a restart could WEDGE — never forced.
    pub fn unforceable(&self) -> bool {
        self.net_transition || self.install_in_flight
    }
}

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if self.rc_sessions > 0 {
            parts.push(format!("{} remote-control session(s)", self.rc_sessions));
        }
        if self.ssh_connections > 0 {
            parts.push(format!("{} SSH connection(s)", self.ssh_connections));
        }
        if self.work > 0 {
            parts.push(format!("{} transfer(s) or recording", self.work));
        }
        if self.net_transition {
            parts.push("the network moved in the last 10 min".into());
        }
        if self.install_in_flight {
            parts.push("an install of this daemon's own is in flight".into());
        }
        if parts.is_empty() {
            f.write_str("nothing")
        } else {
            f.write_str(&parts.join(", "))
        }
    }
}

/// A replacement being followed.
#[derive(Debug, Clone)]
pub struct Pending {
    pub id: FileId,
    /// When this replacement was first seen.
    pub since: Instant,
    pub verdict: Option<Verdict>,
    /// Not before this: a refused restart's, or an unusable binary's, retry.
    pub retry_at: Option<Instant>,
}

/// One look's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The running binary is the installed one, or the replacement is not
    /// worth acting on.
    Nothing,
    /// Replaced; waiting for it to stay put.
    Settling,
    /// Settled: ask the new binary its version.
    Probe,
    /// Waiting: for idle, or for a retry.
    Wait,
    /// Restart now. `cut`: the ceiling forces it over work it cuts.
    Restart { cut: bool },
}

/// The policy. Pure — every input is a parameter — so the whole of it is a
/// unit test.
pub fn decide(pending: Option<&Pending>, now: Instant, busy: &Busy) -> Step {
    let Some(p) = pending else {
        return Step::Nothing;
    };
    let age = now.saturating_duration_since(p.since);
    if age < SETTLE {
        return Step::Settling;
    }
    let retry_due = p.retry_at.is_none_or(|t| now >= t);
    match &p.verdict {
        None => Step::Probe,
        Some(Verdict::Same) => Step::Nothing,
        Some(Verdict::Unusable(_)) if retry_due => Step::Probe,
        Some(Verdict::Unusable(_)) => Step::Wait,
        Some(Verdict::Other(_)) => {
            if !retry_due || busy.unforceable() {
                Step::Wait
            } else if !busy.cuttable() {
                Step::Restart { cut: false }
            } else if age >= CEILING {
                Step::Restart { cut: true }
            } else {
                Step::Wait
            }
        }
    }
}

/// `meshharbord --version`'s answer, against the version this process runs.
/// Pure. The answer must be clap's `roomlerd <version>` exactly: anything else
/// at the exec path (another program, a truncated file that still runs) is not
/// restarted onto.
pub fn verdict_from(stdout: &str, running: &str) -> Verdict {
    let out = stdout.trim();
    match out.strip_prefix("roomlerd ") {
        Some(v) if !v.is_empty() && !v.contains(char::is_whitespace) => {
            if v == running {
                Verdict::Same
            } else {
                Verdict::Other(v.to_string())
            }
        }
        _ => Verdict::Unusable(format!(
            "unexpected --version answer {:?}",
            out.chars().take(80).collect::<String>()
        )),
    }
}

/// The path this process was started as: `argv[0]` when it is absolute
/// (systemd passes `ExecStart=`'s path), else the resolved executable. Pure.
pub fn pick_exec_path(
    arg0: Option<&std::ffi::OsStr>,
    current_exe: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    match arg0.map(std::path::Path::new) {
        Some(p) if p.is_absolute() => Some(p.to_path_buf()),
        _ => current_exe,
    }
}

/// The identity of the file `path` names, through symlinks.
#[cfg(unix)]
pub fn file_id(path: &std::path::Path) -> std::io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path)?;
    Ok(FileId {
        dev: m.dev(),
        ino: m.ino(),
    })
}

/// Start the watch on a daemon it applies to: Linux, NOT root (a system
/// install is unchanged — FR-96 AC4), the FR's kill switch not set, and a
/// supervisor that will relaunch the process. `None` otherwise, with the
/// reason logged where an operator would want it.
#[cfg(target_os = "linux")]
pub fn spawn(
    shutdown: tokio::sync::watch::Receiver<bool>,
    restart: crate::localapi_state::RestartHandle,
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) -> Option<tokio::task::JoinHandle<()>> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return None;
    }
    if !tunnel_core::env::flag("UPDATE_HELPER", true) {
        tracing::info!(
            "replaced-binary watch: off (ROOMLERD_UPDATE_HELPER=0) — after an upgrade this daemon \
             runs the old binary until it is restarted"
        );
        return None;
    }
    if !restart.supervision().is_supervised() {
        tracing::info!(
            "replaced-binary watch: off — no supervisor this process can identify would relaunch \
             it, so it never exits for a replaced binary; restart it after an upgrade"
        );
        return None;
    }
    Some(tokio::spawn(watch(shutdown, restart, rc_sessions)))
}

/// The path this process was started as, and the file it runs — if the two
/// agree, which is the premise every later comparison rests on.
#[cfg(target_os = "linux")]
fn baseline() -> Result<(std::path::PathBuf, FileId), String> {
    let running = file_id(std::path::Path::new("/proc/self/exe"))
        .map_err(|e| format!("cannot read /proc/self/exe: {e}"))?;
    let path = pick_exec_path(
        std::env::args_os().next().as_deref(),
        std::env::current_exe().ok(),
    )
    .ok_or_else(|| "cannot tell the path this process was started as".to_string())?;
    match file_id(&path) {
        Ok(id) if id == running => Ok((path, running)),
        Ok(_) => Err(format!(
            "{} is not the file this process runs (replaced already, or a filesystem that cannot \
             tell)",
            path.display()
        )),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// What a restart would cut or wedge, now.
#[cfg(target_os = "linux")]
fn busy_now(rc_sessions: &crate::rc_sessions::RcSessionRegistry) -> Busy {
    Busy {
        rc_sessions: rc_sessions.list().len(),
        ssh_connections: ssh_connections(),
        work: crate::updater::active_work(),
        net_transition: crate::updater::net_transition_recent(),
        install_in_flight: crate::updater::update_in_flight(),
    }
}

/// Open SSH connections; none in a build without an overlay to serve on.
#[cfg(target_os = "linux")]
fn ssh_connections() -> usize {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        crate::ssh::live_connections()
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        0
    }
}

/// Ask the binary at `path` its version.
#[cfg(target_os = "linux")]
async fn probe(path: &std::path::Path) -> Verdict {
    let mut cmd = tokio::process::Command::new(path);
    cmd.arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(PROBE_TIMEOUT, cmd.output()).await {
        Err(_) => Verdict::Unusable(format!(
            "no --version answer within {} s",
            PROBE_TIMEOUT.as_secs()
        )),
        Ok(Err(e)) => Verdict::Unusable(format!("could not run it: {e}")),
        Ok(Ok(out)) if !out.status.success() => {
            Verdict::Unusable(format!("--version exited {}", out.status))
        }
        Ok(Ok(out)) => verdict_from(
            &String::from_utf8_lossy(&out.stdout),
            env!("CARGO_PKG_VERSION"),
        ),
    }
}

/// The watch. Ends when the daemon shuts down, or when it has started the
/// daemon's own graceful shutdown for the restart.
#[cfg(target_os = "linux")]
async fn watch(
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    restart: crate::localapi_state::RestartHandle,
    rc_sessions: crate::rc_sessions::RcSessionRegistry,
) {
    use tracing::{info, warn};
    let (path, running) = match baseline() {
        Ok(b) => b,
        Err(why) => {
            info!(%why, "replaced-binary watch: off");
            return;
        }
    };
    info!(
        path = %path.display(),
        supervisor = restart.supervision().wire(),
        "replaced-binary watch: armed — restarts onto a replaced binary once idle (FR-96 P2b)"
    );
    let running_version = env!("CARGO_PKG_VERSION");
    let mut pending: Option<Pending> = None;
    let mut deferral_logged: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(CHECK_EVERY) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
        let now = Instant::now();
        match file_id(&path) {
            Ok(id) if id == running => {
                if pending.take().is_some() {
                    info!(path = %path.display(),
                        "replaced-binary watch: the running binary is back at its path — nothing to restart for");
                }
                continue;
            }
            Ok(id) => {
                if pending.as_ref().is_none_or(|p| p.id != id) {
                    info!(
                        path = %path.display(),
                        settle_secs = SETTLE.as_secs(),
                        "replaced-binary watch: the binary was replaced — waiting for it to settle"
                    );
                    pending = Some(Pending {
                        id,
                        since: now,
                        verdict: None,
                        retry_at: None,
                    });
                    deferral_logged = None;
                }
            }
            Err(e) => {
                // Mid-install (between an installer's renames), or removed.
                // Nothing to restart onto either way.
                if pending.take().is_some() {
                    info!(path = %path.display(), error = %e,
                        "replaced-binary watch: the binary is gone from its path — waiting");
                }
                continue;
            }
        }
        let Some(p) = pending.as_mut() else {
            continue;
        };
        let busy = busy_now(&rc_sessions);
        match decide(Some(&*p), now, &busy) {
            Step::Nothing | Step::Settling => {}
            Step::Probe => {
                let verdict = probe(&path).await;
                match &verdict {
                    Verdict::Other(v) => info!(
                        new = %v,
                        running = running_version,
                        "replaced-binary watch: the new binary answers — restarting onto it once idle"
                    ),
                    Verdict::Same => info!(
                        version = running_version,
                        "replaced-binary watch: replaced by the same version — nothing to restart for"
                    ),
                    Verdict::Unusable(why) => {
                        warn!(
                            path = %path.display(),
                            %why,
                            retry_in_secs = RETRY_AFTER.as_secs(),
                            "replaced-binary watch: the new binary does not answer — not restarting onto it"
                        );
                        p.retry_at = Some(now + RETRY_AFTER);
                    }
                }
                p.verdict = Some(verdict);
            }
            Step::Wait => {
                let deferred_by_work = busy.cuttable() || busy.unforceable();
                if deferred_by_work
                    && deferral_logged.is_none_or(|t| t.elapsed() >= DEFER_LOG_EVERY)
                {
                    info!(
                        %busy,
                        waited_secs = now.saturating_duration_since(p.since).as_secs(),
                        ceiling_secs = CEILING.as_secs(),
                        "replaced-binary watch: restart deferred"
                    );
                    deferral_logged = Some(now);
                }
            }
            Step::Restart { cut } => {
                let Some(Verdict::Other(new)) = p.verdict.clone() else {
                    continue;
                };
                if cut {
                    warn!(
                        %busy,
                        waited_secs = now.saturating_duration_since(p.since).as_secs(),
                        "replaced-binary watch: still busy at the ceiling — restarting anyway, which cuts it"
                    );
                }
                // Agent turns are a person's work in progress: waited for as
                // an install waits for them, and new ones held meanwhile.
                if !crate::updater::wait_for_agent_turns(&mut shutdown, "replaced-binary").await {
                    return;
                }
                // That wait can be long: look again before leaving.
                let busy = busy_now(&rc_sessions);
                if !matches!(
                    decide(Some(&*p), Instant::now(), &busy),
                    Step::Restart { .. }
                ) {
                    crate::updater::hold_agent_prompts(false);
                    continue;
                }
                let reason = format!(
                    "FR-96 P2b: {} was replaced ({running_version} -> {new})",
                    path.display()
                );
                match restart.arm_from_within(&reason).await {
                    Ok(_) => {
                        info!(
                            from = running_version,
                            to = %new,
                            "replaced-binary watch: restarting onto the replaced binary"
                        );
                        restart.commit();
                        return;
                    }
                    Err(why) => {
                        crate::updater::hold_agent_prompts(false);
                        warn!(
                            %why,
                            retry_in_secs = RETRY_AFTER.as_secs(),
                            "replaced-binary watch: the restart was refused"
                        );
                        p.retry_at = Some(Instant::now() + RETRY_AFTER);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(ino: u64) -> FileId {
        FileId { dev: 1, ino }
    }

    fn pending(since: Instant, verdict: Option<Verdict>) -> Pending {
        Pending {
            id: id(2),
            since,
            verdict,
            retry_at: None,
        }
    }

    const IDLE: Busy = Busy {
        rc_sessions: 0,
        ssh_connections: 0,
        work: 0,
        net_transition: false,
        install_in_flight: false,
    };

    fn other() -> Option<Verdict> {
        Some(Verdict::Other("0.4.999".into()))
    }

    #[test]
    fn nothing_replaced_is_nothing_to_do() {
        assert_eq!(decide(None, Instant::now(), &IDLE), Step::Nothing);
    }

    #[test]
    fn a_replacement_settles_before_anything_else() {
        let t0 = Instant::now();
        let p = pending(t0, None);
        assert_eq!(decide(Some(&p), t0, &IDLE), Step::Settling);
        assert_eq!(
            decide(Some(&p), t0 + SETTLE - Duration::from_secs(1), &IDLE),
            Step::Settling
        );
        assert_eq!(decide(Some(&p), t0 + SETTLE, &IDLE), Step::Probe);
        // Even a verdict already in hand waits out the settle.
        let p = pending(t0, other());
        assert_eq!(decide(Some(&p), t0, &IDLE), Step::Settling);
    }

    #[test]
    fn a_settled_replacement_of_another_version_restarts_when_idle() {
        let t0 = Instant::now();
        let p = pending(t0, other());
        assert_eq!(
            decide(Some(&p), t0 + SETTLE, &IDLE),
            Step::Restart { cut: false }
        );
    }

    #[test]
    fn the_same_version_is_never_restarted_onto() {
        let t0 = Instant::now();
        let p = pending(t0, Some(Verdict::Same));
        assert_eq!(decide(Some(&p), t0 + SETTLE, &IDLE), Step::Nothing);
        assert_eq!(decide(Some(&p), t0 + CEILING * 2, &IDLE), Step::Nothing);
    }

    #[test]
    fn an_unusable_binary_is_asked_again_only_after_the_retry() {
        let t0 = Instant::now();
        let mut p = pending(t0, Some(Verdict::Unusable("x".into())));
        p.retry_at = Some(t0 + SETTLE + RETRY_AFTER);
        assert_eq!(decide(Some(&p), t0 + SETTLE, &IDLE), Step::Wait);
        assert_eq!(
            decide(Some(&p), t0 + SETTLE + RETRY_AFTER, &IDLE),
            Step::Probe
        );
    }

    #[test]
    fn work_defers_the_restart_until_the_ceiling_then_is_cut() {
        let t0 = Instant::now();
        let p = pending(t0, other());
        for busy in [
            Busy {
                rc_sessions: 1,
                ..IDLE
            },
            Busy {
                ssh_connections: 1,
                ..IDLE
            },
            Busy { work: 1, ..IDLE },
        ] {
            assert_eq!(decide(Some(&p), t0 + SETTLE, &busy), Step::Wait, "{busy}");
            assert_eq!(
                decide(Some(&p), t0 + CEILING - Duration::from_secs(1), &busy),
                Step::Wait,
                "{busy}"
            );
            assert_eq!(
                decide(Some(&p), t0 + CEILING, &busy),
                Step::Restart { cut: true },
                "{busy}"
            );
        }
    }

    #[test]
    fn a_network_transition_or_an_own_install_is_never_forced() {
        let t0 = Instant::now();
        let p = pending(t0, other());
        for busy in [
            Busy {
                net_transition: true,
                ..IDLE
            },
            Busy {
                install_in_flight: true,
                ..IDLE
            },
            Busy {
                rc_sessions: 1,
                net_transition: true,
                ..IDLE
            },
        ] {
            assert_eq!(decide(Some(&p), t0 + SETTLE, &busy), Step::Wait, "{busy}");
            assert_eq!(
                decide(Some(&p), t0 + CEILING * 3, &busy),
                Step::Wait,
                "{busy}"
            );
        }
    }

    #[test]
    fn a_refused_restart_waits_for_its_retry() {
        let t0 = Instant::now();
        let mut p = pending(t0, other());
        let refused_at = t0 + SETTLE;
        p.retry_at = Some(refused_at + RETRY_AFTER);
        assert_eq!(
            decide(Some(&p), refused_at + Duration::from_secs(1), &IDLE),
            Step::Wait
        );
        assert_eq!(
            decide(Some(&p), refused_at + RETRY_AFTER, &IDLE),
            Step::Restart { cut: false }
        );
    }

    #[test]
    fn the_version_answer_must_be_roomlerd_and_one_word() {
        assert_eq!(
            verdict_from("roomlerd 0.4.134\n", "0.4.133"),
            Verdict::Other("0.4.134".into())
        );
        assert_eq!(verdict_from("roomlerd 0.4.133\n", "0.4.133"), Verdict::Same);
        // An admin's downgrade is still what is installed.
        assert_eq!(
            verdict_from("roomlerd 0.4.120", "0.4.133"),
            Verdict::Other("0.4.120".into())
        );
        for junk in [
            "",
            "roomlerd",
            "roomlerd ",
            "roomler 0.4.134",
            "roomlerd 0.4.134 extra",
            "Segmentation fault",
        ] {
            assert!(
                matches!(verdict_from(junk, "0.4.133"), Verdict::Unusable(_)),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn the_exec_path_is_argv0_when_absolute_else_the_resolved_executable() {
        use std::ffi::OsStr;
        use std::path::PathBuf;
        let exe = Some(PathBuf::from("/usr/lib/roomler/roomlerd"));
        assert_eq!(
            pick_exec_path(Some(OsStr::new("/usr/bin/meshharbord")), exe.clone()),
            Some(PathBuf::from("/usr/bin/meshharbord"))
        );
        assert_eq!(
            pick_exec_path(Some(OsStr::new("roomlerd")), exe.clone()),
            exe
        );
        assert_eq!(pick_exec_path(None, exe.clone()), exe);
        assert_eq!(pick_exec_path(Some(OsStr::new("./roomlerd")), None), None);
    }

    #[test]
    fn busy_says_what_it_would_cut() {
        assert_eq!(IDLE.to_string(), "nothing");
        let b = Busy {
            rc_sessions: 1,
            ssh_connections: 2,
            work: 1,
            net_transition: true,
            install_in_flight: true,
        };
        let s = b.to_string();
        for part in [
            "1 remote-control session",
            "2 SSH connection",
            "1 transfer",
            "network moved",
            "install",
        ] {
            assert!(s.contains(part), "{s}");
        }
        assert!(b.cuttable() && b.unforceable());
        assert!(!IDLE.cuttable() && !IDLE.unforceable());
    }

    /// The premise: the file a running process runs and the file its path
    /// names are the same identity, and an installer's rename-over gives the
    /// path another. On the very filesystem the tests run on.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rename_over_gives_the_path_another_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("roomlerd");
        std::fs::write(&bin, b"old").expect("write");
        // Hold the old file open, as a running image is held.
        let held = std::fs::File::open(&bin).expect("open");
        let before = file_id(&bin).expect("id");
        let staged = tmp.path().join(".roomlerd.new");
        std::fs::write(&staged, b"new").expect("write");
        // The tarball's `place`: the old one to `.prev`, the new one in.
        std::fs::rename(&bin, bin.with_extension("prev")).expect("prev");
        std::fs::rename(&staged, &bin).expect("rename");
        let after = file_id(&bin).expect("id");
        assert_ne!(before, after);
        use std::os::unix::fs::MetadataExt;
        let m = held.metadata().expect("held");
        assert_eq!(
            FileId {
                dev: m.dev(),
                ino: m.ino()
            },
            before,
            "the held file keeps its identity"
        );
    }

    /// The baseline this daemon checks at start holds for the test binary
    /// itself: `/proc/self/exe` and the resolved executable are one file.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_and_its_executable_are_one_file() {
        let exe = std::env::current_exe().expect("current_exe");
        assert_eq!(
            file_id(std::path::Path::new("/proc/self/exe")).expect("/proc/self/exe"),
            file_id(&exe).expect("exe"),
            "{}",
            exe.display()
        );
    }
}
