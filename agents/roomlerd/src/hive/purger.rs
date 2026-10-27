// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2g-1 — `meshharbord hive-purge`: what a purged session's account holds
//! of it, deleted AS THE ACCOUNT.
//!
//! A session that ran on this device left two things under its account (spec
//! §3b, "Purges and retention"):
//!
//! | What | Where | Deleted |
//! |---|---|---|
//! | its state directory: its Claude Code config directory, and the shadow repository of a folder in no repository | `~/.roomler/hive/<sid>` | whole, never through a link |
//! | what its checkpoints left in the folder's own repository | `refs/hive/<sid>/*`, and `hive-<sid>.index` with its lock in the git directory | each ref by `git update-ref -d`, the index files removed ([`workspace::forget`]) |
//!
//! Never the person's working tree, their branches, their index or any other
//! ref: the objects the checkpoints wrote stay, unreachable, for the person's
//! own `git gc`.
//!
//! The daemon feeds the [`Request`] on stdin: what this device's own record of
//! the session's workplace says ([`super::store`]), never the server's word.
//! It starts `meshharbord hive-purge` as the account, as `hive-pack` runs. The
//! child holds the request to the account's own home: a state directory that
//! is not `$HOME/.roomler/hive/<sid>` exactly is refused, so a record that went
//! wrong cannot make it delete anything else of the account's.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::checkpointer::Runner;
use super::workspace::{self, Git};

/// The hidden subcommand: `meshharbord hive-purge`, its request on stdin.
pub const PURGE_SUBCOMMAND: &str = "hive-purge";

/// The most request bytes read.
const MAX_REQUEST: usize = 16 * 1024;

/// The most bytes the daemon reads from the child.
const MAX_OUTPUT: u64 = 4 * 1024;

/// How long the child may run: a state directory holds a session's whole
/// config directory, and a shadow repository of its folder.
pub(crate) const PURGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Bumped when the fields change their meaning; a child refuses another.
pub(crate) const REQUEST_V: u32 = 1;

/// What the daemon asks the account to delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Request {
    pub v: u32,
    /// The session, as its record names it: 24 lowercase hex digits.
    pub session: String,
    /// Its state directory on this device, as the workplace record keeps it.
    pub state_dir: PathBuf,
    /// The folder it ran in, whose repository holds its checkpoints' refs.
    pub folder: PathBuf,
}

/// What the child deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Done {
    /// Whether the state directory was there.
    pub state_dir: bool,
    /// How many refs under `refs/hive/<sid>/` went.
    pub refs: usize,
    /// How many of the checkpoints' index files went.
    pub index: usize,
}

impl Done {
    /// Whether there was anything of the session's to delete.
    pub(crate) fn any(self) -> bool {
        self.state_dir || self.refs > 0 || self.index > 0
    }
}

/// The child's work: the request held to `home`, the account's own, then
/// the repository's refs and index, then the state directory.
pub(crate) fn produce(req: &Request, home: &Path, git: &Git) -> Result<Done, String> {
    if req.v != REQUEST_V {
        return Err(format!(
            "request v{} — this build reads v{REQUEST_V}",
            req.v
        ));
    }
    let sid = req.session.as_str();
    if sid.len() != 24
        || !sid
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("{sid:?} is not a session id"));
    }
    let own = home.join(".roomler").join("hive").join(sid);
    if req.state_dir != own {
        return Err(format!(
            "{} is not this account's state directory for the session: left as it is",
            req.state_dir.display()
        ));
    }
    // The repository's traces first. A folder in no repository has its
    // shadow inside the state directory, which goes next.
    let (refs, index) = if req.folder.as_os_str().is_empty() {
        (0, 0)
    } else {
        workspace::forget(git, &req.folder, sid)?
    };
    let state_dir = match std::fs::symlink_metadata(&own) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("{}: {e}", own.display())),
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(format!(
                "{} is a link, or not a directory: left as it is",
                own.display()
            ));
        }
        Ok(_) => {
            // Entries that are links go as links: nothing is followed.
            std::fs::remove_dir_all(&own).map_err(|e| format!("{}: {e}", own.display()))?;
            true
        }
    };
    Ok(Done {
        state_dir,
        refs,
        index,
    })
}

// ─── the daemon's side ──────────────────────────────────────────────────────

/// Delete what `req` names as the session's account on this device (`who`),
/// through `run`: the child as the account, fed the request on stdin, or in
/// this process in tests.
pub(crate) async fn purge(
    run: &Runner,
    who: &super::materializer::Who,
    req: &Request,
) -> Result<Done, String> {
    match run {
        #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
        Runner::InProcess { ceiling } => {
            let home = who
                .env
                .iter()
                .find(|(k, _)| k == "HOME")
                .map(|(_, v)| PathBuf::from(v))
                .ok_or("no HOME to purge under")?;
            produce(req, &home, &Git::under(ceiling))
        }
        #[cfg(all(test, unix))]
        Runner::Failing(why) => Err((*why).to_string()),
        #[cfg(all(test, unix))]
        Runner::Hangs => std::future::pending().await,
        Runner::Subprocess => {
            let exe = PathBuf::from(super::supervisor::own_exe()?);
            #[cfg(unix)]
            {
                run_as(
                    &exe,
                    req,
                    who.account.as_deref(),
                    who.env.clone(),
                    PURGE_TIMEOUT,
                )
                .await
            }
            #[cfg(windows)]
            {
                let account = who.account.clone().ok_or("no account to run as")?;
                run_as_console_user(&exe, req, account, PURGE_TIMEOUT).await
            }
        }
    }
}

/// The daemon's side on Unix: start `exe hive-purge` as `account` (none in
/// tests: as the daemon), with `env` and nothing of the daemon's own, and feed
/// it `req` on stdin.
#[cfg(unix)]
pub(crate) async fn run_as(
    exe: &Path,
    req: &Request,
    account: Option<&str>,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    timeout: Duration,
) -> Result<Done, String> {
    use super::child::Fed;
    use std::process::Stdio;
    let bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg(PURGE_SUBCOMMAND)
        .env_clear()
        .envs(env)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own group, which a timeout ends whole, the git it started
        // included ([`super::child::run_fed`]).
        .process_group(0);
    if let Some(account) = account {
        crate::exec::apply_session_run_as(&mut cmd, account)?;
    }
    let feed = |mut stdin: tokio::process::ChildStdin| async move {
        // `stdin` is dropped at the end: the child's end of input.
        match tokio::io::AsyncWriteExt::write_all(&mut stdin, &bytes).await {
            Ok(()) => Fed::Done,
            Err(_) => Fed::Closed,
        }
    };
    let out = super::child::run_fed(cmd, PURGE_SUBCOMMAND, feed, timeout, MAX_OUTPUT).await?;
    serde_json::from_slice(&out).map_err(|e| format!("the purge's answer: {e}"))
}

/// The daemon's side on Windows: start `exe hive-purge` as the user signed in
/// at the console, `account` naming them as `hive_accounts` does, and feed it
/// `req` through a thread that feeds its pipe.
#[cfg(windows)]
pub(crate) async fn run_as_console_user(
    exe: &Path,
    req: &Request,
    account: String,
    timeout: Duration,
) -> Result<Done, String> {
    let bytes = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let exe = exe.to_path_buf();
    let child = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        use crate::hive_win;
        let console = hive_win::console_user().map_err(|(_, e)| e)?;
        hive_win::check_mapping(&account, &console).map_err(|(_, e)| e)?;
        let line = hive_win::purge_command_line(&exe)?;
        // SAFETY: `console` holds the token `spawn_as` borrows, across the call.
        let out = unsafe {
            hive_win::run_fed(
                console.spawn_as(),
                &line,
                Some(rx),
                "the purge",
                timeout,
                MAX_OUTPUT,
            )
        };
        drop(console);
        out
    });
    // The whole request, then the child's end of input.
    let _ = tx.send(bytes).await;
    drop(tx);
    let out = child
        .await
        .map_err(|e| format!("the purge's thread: {e}"))??;
    serde_json::from_slice(&out).map_err(|e| format!("the purge's answer: {e}"))
}

/// Whether this process was started as `meshharbord hive-purge`, its request on
/// stdin.
pub fn purge_args() -> bool {
    let mut args = std::env::args_os().skip(1);
    args.next().is_some_and(|a| a == PURGE_SUBCOMMAND) && args.next().is_none()
}

/// The child: read the request on stdin, delete what it names as whoever this
/// process runs as (the session's account), under that account's own home,
/// and write what went to stdout. 0 on success; 1 with a word on stderr
/// otherwise.
pub fn purge_main() -> i32 {
    let run = || -> Result<(), String> {
        let mut text = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(std::io::stdin().lock(), MAX_REQUEST as u64 + 1),
            &mut text,
        )
        .map_err(|e| format!("reading the request: {e}"))?;
        if text.len() > MAX_REQUEST {
            return Err("the request is too large".into());
        }
        let req: Request =
            serde_json::from_slice(&text).map_err(|e| format!("the request: {e}"))?;
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or("this account has no home")?;
        let done = produce(&req, &home, &Git::on_path())?;
        let line = serde_json::to_string(&done).map_err(|e| e.to_string())?;
        println!("{line}");
        Ok(())
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("roomlerd {PURGE_SUBCOMMAND}: {e}");
            1
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Command;

    const SID: &str = "6aca8ef5dac84dd57e492eb7";

    /// `git` in `dir`, as a person sets their repository up.
    fn person(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .args([
                "-c",
                "user.name=P",
                "-c",
                "user.email=p@example.com",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A home with the session's state directory, and a folder whose own
    /// repository holds the person's branch, the session's checkpoint ref,
    /// another session's, and the checkpoints' index.
    struct Rig {
        root: tempfile::TempDir,
        home: PathBuf,
        folder: PathBuf,
        state_dir: PathBuf,
    }

    fn rig() -> Rig {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let state_dir = home.join(".roomler").join("hive").join(SID);
        std::fs::create_dir_all(state_dir.join("claude").join("projects")).unwrap();
        std::fs::write(state_dir.join("claude").join("history.jsonl"), "{}\n").unwrap();
        let folder = root.path().join("work");
        std::fs::create_dir_all(&folder).unwrap();
        person(&folder, &["init", "-q", "-b", "main"]);
        std::fs::write(folder.join("notes.md"), "the person's work\n").unwrap();
        person(&folder, &["add", "notes.md"]);
        person(&folder, &["commit", "-q", "-m", "mine"]);
        let head = person(&folder, &["rev-parse", "HEAD"]);
        person(
            &folder,
            &["update-ref", &format!("refs/hive/{SID}/head"), &head],
        );
        person(
            &folder,
            &[
                "update-ref",
                "refs/hive/6aca8ef5dac84dd57e492eb8/head",
                &head,
            ],
        );
        let gd = folder.join(".git");
        std::fs::write(gd.join(format!("hive-{SID}.index")), "idx").unwrap();
        Rig {
            root,
            home,
            folder,
            state_dir,
        }
    }

    fn req(r: &Rig) -> Request {
        Request {
            v: REQUEST_V,
            session: SID.into(),
            state_dir: r.state_dir.clone(),
            folder: r.folder.clone(),
        }
    }

    /// The session's state directory, its refs and its index go; the
    /// person's branch, work tree and index, and another session's ref, stay.
    #[test]
    fn a_purge_deletes_what_the_session_left_and_nothing_of_the_persons() {
        let r = rig();
        let git = Git::under(r.root.path());
        let done = produce(&req(&r), &r.home, &git).unwrap();
        // What went first, each by itself; what the child says of it last.
        assert!(!r.state_dir.exists(), "the state directory went");
        assert!(
            person(&r.folder, &["for-each-ref", "refs/hive/"]).contains("6aca8ef5dac84dd57e492eb8"),
            "another session's ref stays"
        );
        assert!(
            !person(&r.folder, &["for-each-ref", "refs/hive/"]).contains(SID),
            "the session's refs went"
        );
        assert!(
            !r.folder
                .join(".git")
                .join(format!("hive-{SID}.index"))
                .exists(),
            "the checkpoints' index went"
        );
        assert_eq!(
            std::fs::read_to_string(r.folder.join("notes.md")).unwrap(),
            "the person's work\n",
            "the work tree stays"
        );
        assert_eq!(person(&r.folder, &["status", "--porcelain"]), "");
        assert_eq!(person(&r.folder, &["branch", "--show-current"]), "main");
        assert_eq!(
            done,
            Done {
                state_dir: true,
                refs: 1,
                index: 1
            }
        );
        // Again: nothing is there any more.
        let again = produce(&req(&r), &r.home, &git).unwrap();
        assert!(!again.any(), "{again:?}");
    }

    /// The request is held to the account's own home: a state directory that
    /// is not `$HOME/.roomler/hive/<sid>` is refused, and nothing is deleted.
    #[test]
    fn only_the_accounts_own_state_directory_for_the_session_goes() {
        let r = rig();
        let git = Git::under(r.root.path());
        for (what, wrong) in [
            ("the home itself", r.home.clone()),
            (
                "another session's",
                r.home
                    .join(".roomler")
                    .join("hive")
                    .join("6aca8ef5dac84dd57e492eb8"),
            ),
            ("up and out", r.state_dir.join("..").join("..").join("..")),
            ("the folder", r.folder.clone()),
        ] {
            let mut bad = req(&r);
            bad.state_dir = wrong;
            assert!(produce(&bad, &r.home, &git).is_err(), "{what}: refused");
        }
        let mut bad = req(&r);
        bad.session = "../../etc".into();
        assert!(
            produce(&bad, &r.home, &git).is_err(),
            "not a session id: refused"
        );
        assert!(r.state_dir.exists(), "nothing went");
        assert!(person(&r.folder, &["for-each-ref", "refs/hive/"]).contains(SID));
    }

    /// A state directory that is a link is left as it is, and so is what it
    /// points at; inside one, a link goes as a link.
    #[test]
    fn nothing_is_deleted_through_a_link() {
        let r = rig();
        let git = Git::under(r.root.path());
        let elsewhere = r.root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("keep"), "x").unwrap();
        std::os::unix::fs::symlink(&elsewhere, r.state_dir.join("claude").join("link")).unwrap();
        produce(&req(&r), &r.home, &git).unwrap();
        assert!(
            elsewhere.join("keep").exists(),
            "a link inside goes as a link"
        );

        let r = rig();
        std::fs::remove_dir_all(&r.state_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &r.state_dir).unwrap();
        let err = produce(&req(&r), &r.home, &git).unwrap_err();
        assert!(err.contains("link"), "{err}");
        assert!(
            elsewhere.join("keep").exists(),
            "the state directory as a link is left"
        );
    }

    /// A folder in no repository, or gone: only the state directory goes.
    #[test]
    fn a_folder_in_no_repository_leaves_only_the_state_directory() {
        let r = rig();
        let git = Git::under(r.root.path());
        let plain = r.root.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        for folder in [plain, r.root.path().join("gone")] {
            let r = rig();
            let mut q = req(&r);
            q.folder = folder;
            let done = produce(&q, &r.home, &git).unwrap();
            assert_eq!((done.state_dir, done.refs, done.index), (true, 0, 0));
        }
    }

    /// The child end to end: the request on stdin, the answer one line.
    #[tokio::test]
    async fn the_child_reads_its_request_and_answers_one_line() {
        use std::os::unix::fs::PermissionsExt;
        let r = rig();
        let exe = r.root.path().join("purge-child");
        std::fs::write(
            &exe,
            format!(
                "#!/bin/sh\ncat > {req}\necho '{{\"state_dir\":true,\"refs\":1,\"index\":0}}'\n",
                req = r.root.path().join("got.json").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asked = req(&r);
        let done = super::super::child::unbusy(|| {
            run_as(&exe, &asked, None, Vec::new(), Duration::from_secs(10))
        })
        .await
        .unwrap();
        assert_eq!(
            done,
            Done {
                state_dir: true,
                refs: 1,
                index: 0
            }
        );
        let got: Request =
            serde_json::from_slice(&std::fs::read(r.root.path().join("got.json")).unwrap())
                .unwrap();
        assert_eq!(got, req(&r), "the request, fed whole");
    }
}
