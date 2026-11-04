// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2b — a child the daemon runs as a session's account on Unix
//! (`hive-checkpoint`, P2b-3a; `hive-materialize`, P2b-4a): in a process group
//! of its own, ended whole, fed on its stdin and read on its stdout within a
//! time limit.

use std::future::Future;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{ChildStdin, Command};

/// How long an ended child's group has between TERM and KILL.
const GROUP_GRACE: Duration = Duration::from_secs(2);

/// The child's process group (`process_group(0)`: its id is the leader's
/// pid), signalled whole when the child is ended — a timeout, too much
/// output, or abandoned by a stop or a daemon going down (dropped).
/// `kill_on_drop` and `start_kill` reach the leader alone and would leave a
/// `git add` hashing the whole folder behind it.
///
/// ⚠️ TERM first: git removes its lock files on TERM, never on KILL, and a
/// lock left on the checkpoint's index refuses every checkpoint after it.
/// ⚠️ Only while the leader is unreaped: once reaped, the id may name
/// someone else's group, so it is forgotten the moment the leader is waited
/// for.
struct Group(Option<libc::pid_t>);

impl Group {
    fn signal(&self, sig: libc::c_int) {
        if let Some(pgid) = self.0 {
            // SAFETY: a plain syscall; the group's leader is our unreaped
            // child, so `pgid` names no one else's.
            unsafe { libc::killpg(pgid, sig) };
        }
    }

    /// TERM to all of it, a moment to go, then KILL; the leader is reaped
    /// either way.
    async fn end(&mut self, child: &mut tokio::process::Child) {
        self.signal(libc::SIGTERM);
        if tokio::time::timeout(GROUP_GRACE, child.wait())
            .await
            .is_err()
        {
            self.signal(libc::SIGKILL);
            let _ = child.wait().await;
        }
        self.0 = None;
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.signal(libc::SIGTERM);
    }
}

/// How a feed stopped.
pub(super) enum Fed {
    /// It wrote everything, and closed the child's stdin.
    Done,
    /// The child stopped reading: its own word says why.
    Closed,
    /// The daemon's side could not go on (a blob the store lacks): the child
    /// got a short stream, which it refuses, so this is the answer.
    Failed(String),
}

/// Run `cmd` — built with `process_group(0)`, `kill_on_drop` and piped
/// stdout and stderr — with `feed` writing its stdin when it has one, and
/// answer its stdout: at most `max` bytes, within `timeout`.
///
/// A child that fails says why in its stderr's tail, and that is the answer
/// even when the feed failed too: a child that refused stops reading, and the
/// feed then meets a closed pipe. Only a feed that failed on the daemon's
/// side ([`Fed::Failed`]) answers instead.
pub(super) async fn run_fed<F, Fut>(
    mut cmd: Command,
    name: &str,
    feed: F,
    timeout: Duration,
    max: u64,
) -> Result<Vec<u8>, String>
where
    F: FnOnce(ChildStdin) -> Fut,
    Fut: Future<Output = Fed>,
{
    let mut child = cmd.spawn().map_err(|e| format!("starting {name}: {e}"))?;
    // After `child`, so dropped before it: the group is signalled while its
    // leader is still unreaped. Never 0 or 1: `killpg(0, _)` is the daemon's
    // own group.
    let mut group = Group(
        child
            .id()
            .and_then(|p| libc::pid_t::try_from(p).ok())
            .filter(|&p| p > 1),
    );
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take();
    let said = tokio::spawn(async move {
        let mut s = Vec::new();
        if let Some(e) = stderr {
            let _ = e.take(4096).read_to_end(&mut s).await;
        }
        s
    });
    let fed = async move {
        match stdin {
            Some(stdin) => feed(stdin).await,
            None => Fed::Done,
        }
    };
    let read = async {
        let mut out = Vec::new();
        match (&mut stdout).take(max + 1).read_to_end(&mut out).await {
            Err(e) => Err(format!("reading {name}: {e}")),
            // Ended, not waited for: it may be blocked writing the rest.
            Ok(_) if out.len() as u64 > max => Err(format!("{name} wrote more than {max} bytes")),
            Ok(_) => Ok(out),
        }
    };
    let done = tokio::time::timeout(timeout, async {
        tokio::pin!(fed);
        tokio::pin!(read);
        let mut was_fed = None;
        // Both at once: a child blocked writing its stdout stops reading its
        // stdin, and a feed blocked on a full pipe would wait for it.
        let out = loop {
            tokio::select! {
                f = &mut fed, if was_fed.is_none() => was_fed = Some(f),
                out = &mut read => break out,
            }
        };
        let out = out?;
        // Its stdout is at its end, so the child is leaving, and a feed still
        // writing meets a closed pipe.
        let was_fed = match was_fed {
            Some(f) => f,
            None => fed.await,
        };
        Ok::<_, String>((out, was_fed, child.wait().await))
    })
    .await;
    let (out, was_fed, status) = match done {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            group.end(&mut child).await;
            return Err(e);
        }
        Err(_) => {
            group.end(&mut child).await;
            return Err(format!(
                "{name} did not finish within {} s",
                timeout.as_secs()
            ));
        }
    };
    // Waited for: the group's id is no longer this child's to signal.
    group.0 = None;
    let status = status.map_err(|e| format!("waiting for {name}: {e}"))?;
    if let Fed::Failed(e) = &was_fed {
        return Err(e.clone());
    }
    if !status.success() {
        let said = said.await.unwrap_or_default();
        let said = String::from_utf8_lossy(&said);
        return Err(format!("{name} failed ({status}): {}", said.trim()));
    }
    if matches!(was_fed, Fed::Closed) {
        return Err(format!("{name} stopped reading before the end"));
    }
    Ok(out)
}

/// No feed: for a child whose stdin is null.
pub(super) async fn nothing(_: ChildStdin) -> Fed {
    Fed::Done
}

/// A test's run of a script it has just written, again while that script is
/// busy (`ETXTBSY`): a thread of the same test binary that forked while the
/// script was still open for writing holds it so until its own child execs,
/// and an exec meanwhile is refused. Production runs its own binary, never a
/// script it has just written, so only a test meets it.
#[cfg(test)]
pub(super) async fn unbusy<T, Fut>(mut run: impl FnMut() -> Fut) -> Result<T, String>
where
    Fut: Future<Output = Result<T, String>>,
{
    for _ in 0..100 {
        match run().await {
            Err(e) if e.contains("Text file busy") => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            done => return done,
        }
    }
    run().await
}
