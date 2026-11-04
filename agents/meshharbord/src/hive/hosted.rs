// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1d-2 — what this device hosts, on disk, so a restarted daemon
//! resumes it.
//!
//! One file beside the replica store, `hosted.json`. Per session it holds
//! what the launch needs again — the fence, the account, the folder as the
//! start asked for it, the starter and their address, the harness session —
//! and where the session stood: the turns begun, the turn in progress and
//! who asked for it, and the approvals it has open. Root's, `0600`, in the
//! store's `0700` directory, written whole (a temporary, then a rename).
//!
//! ⚠️ A NEW turn number and a NEW approval are written before the frame
//! that tells the server, so the server never holds a turn or an approval
//! this file does not. A resume that re-used a turn number would have every
//! later stub ignored as older than the newest, and an approval the resume
//! never heard of would stay open on the record for ever. A turn's end is
//! written before its frame too, because the server edits a turn's stub to
//! whatever comes last, and a resume must never report a finished turn as
//! cut. An approval's end is written AFTER its frame: lost in between, the
//! resume withdraws it again, which the server applies only to an approval
//! still open.
//!
//! ⚠️ From the moment the daemon starts stopping, the record is FROZEN
//! (`Supervisor::hosted_update`). The teardown cuts the turn and withdraws
//! the approvals, and the frames saying so go into connections that are
//! closing. Recorded, they would be lost twice: once on the wire, and again
//! because the next daemon would find nothing left to report. The field
//! found exactly that (2026-10-08): an approval the teardown withdrew stayed
//! "needed" on the server.
//!
//! What another enrollment wrote is not this one's to resume: the file names
//! the agent it belongs to, and another agent's file is set aside unread (a
//! re-enrolled device). Not synced to disk: a clean shutdown, a restart and
//! a crash all keep what it held; a power cut may lose the last change, and
//! then P1b's manifest ends what could not be resumed.

use std::path::{Path, PathBuf};

use meshharbor_remote_control::hive::HiveForkOf;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// The file's format. A newer one is what a newer daemon wrote, read by a
/// downgraded one: not resumed, and replaced at the next write.
const VERSION: u32 = 1;

/// One session this device hosts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct HostedSession {
    /// The Hive session, hex.
    pub session: String,
    pub fence: u64,
    pub harness: String,
    /// Claude Code's own session id, a UUID — what `--resume` takes.
    pub harness_session: String,
    /// The folder as the start asked for it, checked against `hive_roots`
    /// again when the session resumes, as they are configured then.
    pub folder: String,
    /// The account it ran as. Its history is in that account's home.
    pub account: String,
    /// Who started it, hex, and the address the start carried.
    pub starter: String,
    #[serde(default)]
    pub starter_email: String,
    /// Turns begun; the next is `turns + 1`.
    #[serde(default)]
    pub turns: u32,
    /// The turn in progress, from its prompt to its `result`. Still set
    /// after a restart: the restart cut it.
    #[serde(default)]
    pub running: Option<RunningTurn>,
    /// The approvals open now, by id.
    #[serde(default)]
    pub approvals: Vec<String>,
    /// When it last resumed (unix seconds), and how many resumes in a row it
    /// did not outlive by `RESUME_STABLE`.
    #[serde(default)]
    pub resumed_at: Option<u64>,
    #[serde(default)]
    pub quick_resumes: u32,
    /// P1h — the harness this daemon launched, by pid and [`super::procs::started`]:
    /// how the next daemon tells a harness a crash left running from
    /// whatever has its pid now. Absent in a file from before P1h.
    #[serde(default)]
    pub harness_pid: Option<u32>,
    #[serde(default)]
    pub harness_started: Option<String>,
    /// P2b-3b — the server joined it as replicated, so each turn's end is
    /// checkpointed; a resume keeps doing so. Absent in a file from before.
    /// P2c-4: set later by a primary's join, while the session runs.
    #[serde(default)]
    pub replicated: bool,
    /// P2e-2 — the session is leased: after a restart it launches only once
    /// the server has said on that connection that this device still holds
    /// it (`rc:hive.lease`). Set by a start's `lease`, or by the first word.
    /// Absent in a file from before; an older daemon ignores it, and resumes
    /// on its own word as it always did.
    #[serde(default)]
    pub lease: bool,
    /// FR-90 P2f-3a — the session this one is a fork of: its checkpoints keep
    /// the parent's history beside its own, and until its own history exists
    /// a launch starts from the parent's. Absent for every other session, and
    /// in a file from before. ⚠️ A daemon before P2f-3a resumes a fork as a
    /// plain session: one never prompted starts empty there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_of: Option<HiveForkOf>,
}

/// A turn in progress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RunningTurn {
    pub turn: u32,
    /// Who asked, hex: the stub that says the turn was cut names them again.
    #[serde(default)]
    pub prompted_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Doc {
    v: u32,
    agent: String,
    sessions: Vec<HostedSession>,
}

/// The sessions this device hosts, and the file that keeps them.
#[derive(Debug, Default)]
pub(crate) struct Hosted {
    /// `None`: in memory only — no data directory, or a test.
    path: Option<PathBuf>,
    agent: String,
    sessions: Vec<HostedSession>,
}

impl Hosted {
    /// Kept in memory only: nothing survives the daemon.
    pub(crate) fn in_memory() -> Self {
        Self::default()
    }

    /// What `path` holds for the enrollment `agent`. Never fails: a file that
    /// cannot be read, holds another enrollment's sessions or a newer format
    /// resumes nothing, and the next write replaces it.
    pub(crate) fn load(path: PathBuf, agent: &str) -> Self {
        let sessions = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Doc>(&bytes) {
                Ok(doc) if doc.v > VERSION => {
                    warn!(file = %path.display(), v = doc.v,
                        "hive: the hosted sessions were written by a newer daemon — none is resumed");
                    Vec::new()
                }
                Ok(doc) if doc.agent != agent => {
                    warn!(file = %path.display(),
                        "hive: the hosted sessions belong to another enrollment — none is resumed");
                    Vec::new()
                }
                Ok(doc) => doc.sessions,
                Err(e) => {
                    warn!(file = %path.display(), %e,
                        "hive: the hosted sessions could not be read — none is resumed");
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                warn!(file = %path.display(), %e,
                    "hive: the hosted sessions could not be read — none is resumed");
                Vec::new()
            }
        };
        Self {
            path: Some(path),
            agent: agent.to_string(),
            sessions,
        }
    }

    /// The file, when there is one: what P1j's `adopted.json` sits beside.
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The enrollment the file belongs to.
    pub(crate) fn agent(&self) -> &str {
        &self.agent
    }

    pub(crate) fn sessions(&self) -> &[HostedSession] {
        &self.sessions
    }

    pub(crate) fn get(&self, session: &str) -> Option<&HostedSession> {
        self.sessions.iter().find(|s| s.session == session)
    }

    /// Record `s`, in place of the session's entry if it has one.
    pub(crate) fn put(&mut self, s: HostedSession) {
        match self.sessions.iter_mut().find(|e| e.session == s.session) {
            Some(e) => *e = s,
            None => self.sessions.push(s),
        }
        self.save();
    }

    /// Change `session`'s entry, when it has one.
    pub(crate) fn update(&mut self, session: &str, f: impl FnOnce(&mut HostedSession)) {
        if let Some(e) = self.sessions.iter_mut().find(|e| e.session == session) {
            f(e);
            self.save();
        }
    }

    /// FR-90 P2e-1 — [`Self::update`], only while `session`'s record is at
    /// `fence`: a run writes its own record, never a newer run's.
    pub(crate) fn update_at(
        &mut self,
        session: &str,
        fence: u64,
        f: impl FnOnce(&mut HostedSession),
    ) {
        if let Some(e) = self
            .sessions
            .iter_mut()
            .find(|e| e.session == session && e.fence == fence)
        {
            f(e);
            self.save();
        }
    }

    /// Forget `session`: it ended, or will not resume.
    pub(crate) fn remove(&mut self, session: &str) {
        let before = self.sessions.len();
        self.sessions.retain(|e| e.session != session);
        if self.sessions.len() != before {
            self.save();
        }
    }

    /// FR-90 P2e-1 — forget `session` while its record is at `fence` or an
    /// older one: what a run removes is its own, and a newer run's record is
    /// never an older run's to take. Whether anything went (P2g-1).
    pub(crate) fn remove_upto(&mut self, session: &str, fence: u64) -> bool {
        let before = self.sessions.len();
        self.sessions
            .retain(|e| !(e.session == session && e.fence <= fence));
        let removed = self.sessions.len() != before;
        if removed {
            self.save();
        }
        removed
    }

    /// A failure is logged and nothing else: the session runs on, and only
    /// its resume after a restart is at stake.
    fn save(&self) {
        let Some(path) = &self.path else { return };
        let doc = Doc {
            v: VERSION,
            agent: self.agent.clone(),
            sessions: self.sessions.clone(),
        };
        if let Err(e) = write_private_json(path, &doc) {
            warn!(file = %path.display(), %e,
                "hive: the hosted sessions were not saved — a restart will not resume them");
        }
    }
}

/// `path`, written whole and `0600` from its first byte: a temporary in the
/// same directory, then a rename over the old file. On Windows the file takes
/// the store directory's protected DACL, SYSTEM's and Administrators', which is
/// what `0600` is for a daemon that runs as SYSTEM (P1i-2).
pub(crate) fn write_private_json<T: Serialize>(path: &Path, doc: &T) -> Result<(), String> {
    use std::io::Write;
    let bytes = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", tmp.display())),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(&bytes)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn entry(session: &str) -> HostedSession {
        HostedSession {
            session: session.into(),
            fence: 1,
            harness: "claude-code".into(),
            harness_session: "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into(),
            folder: "/home/dev/work".into(),
            account: "dev".into(),
            starter: "6ac7701eefb2037e3034e122".into(),
            starter_email: "dev@example.com".into(),
            turns: 0,
            running: None,
            approvals: Vec::new(),
            resumed_at: None,
            quick_resumes: 0,
            harness_pid: None,
            harness_started: None,
            replicated: false,
            lease: false,
            fork_of: None,
        }
    }

    #[test]
    fn what_one_daemon_hosts_the_next_one_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosted.json");
        let mut h = Hosted::load(path.clone(), "agent-a");
        assert!(h.sessions().is_empty(), "no file yet");
        h.put(entry("s1"));
        h.put(entry("s2"));
        h.update("s1", |e| {
            e.turns = 3;
            e.running = Some(RunningTurn {
                turn: 3,
                prompted_by: Some("6ac7701eefb2037e3034e122".into()),
            });
            e.approvals.push("ap-1".into());
        });
        h.remove("s2");
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "root's alone");
        }

        let again = Hosted::load(path, "agent-a");
        assert_eq!(again.sessions().len(), 1);
        let s1 = again.get("s1").unwrap();
        assert_eq!(s1.turns, 3);
        assert_eq!(s1.running.as_ref().map(|r| r.turn), Some(3));
        assert_eq!(s1.approvals, ["ap-1"]);
    }

    /// A re-enrolled device, a newer daemon's file, a torn one: none of it
    /// is resumed, and the next write replaces it.
    #[test]
    fn what_this_enrollment_did_not_write_is_not_resumed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosted.json");
        let mut h = Hosted::load(path.clone(), "agent-a");
        h.put(entry("s1"));
        assert!(Hosted::load(path.clone(), "agent-b").sessions().is_empty());

        let newer = serde_json::json!({"v": VERSION + 1, "agent": "agent-a", "sessions": []});
        std::fs::write(&path, newer.to_string()).unwrap();
        assert!(Hosted::load(path.clone(), "agent-a").sessions().is_empty());

        std::fs::write(&path, b"{\"v\":1,\"agent\":").unwrap();
        let mut torn = Hosted::load(path.clone(), "agent-a");
        assert!(torn.sessions().is_empty());
        torn.put(entry("s9"));
        assert_eq!(
            Hosted::load(path, "agent-a").sessions()[0].session,
            "s9",
            "the next write replaced it"
        );
    }

    /// A file an older daemon of this format wrote, with only the fields it
    /// knew, still reads: everything since has a default.
    #[test]
    fn an_entry_with_only_the_launch_fields_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosted.json");
        let doc = serde_json::json!({"v": 1, "agent": "a", "sessions": [{
            "session": "s1", "fence": 2, "harness": "claude-code",
            "harness_session": "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70",
            "folder": "/w", "account": "dev", "starter": "6ac7701eefb2037e3034e122"
        }]});
        std::fs::write(&path, doc.to_string()).unwrap();
        let h = Hosted::load(path, "a");
        let s = h.get("s1").unwrap();
        assert_eq!((s.fence, s.turns, s.quick_resumes), (2, 0, 0));
        assert!(s.running.is_none() && s.approvals.is_empty() && s.resumed_at.is_none());
    }

    #[test]
    fn in_memory_writes_nothing() {
        let mut h = Hosted::in_memory();
        h.put(entry("s1"));
        assert_eq!(h.sessions().len(), 1);
        h.remove("s1");
        assert!(h.sessions().is_empty());
    }
}
