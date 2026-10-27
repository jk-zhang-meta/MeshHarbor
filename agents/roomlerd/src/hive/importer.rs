// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2f-4a — `meshharbord hive-import`: an ended terminal session's history,
//! put in place as a managed session's, AS THE TERMINAL'S ACCOUNT.
//!
//! An adopted session's store holds a mirror of the person's conversation
//! (P1j): events, which Claude Code cannot resume. Its history is the
//! terminal's own file, where Claude Code keeps it in the account's tree,
//! `~/.claude/projects/<the folder's name>/<id>.jsonl`, with the sub-agent
//! transcripts and saved outputs it names under `<id>/`. No checkpoint was
//! ever taken of it (spec §3b). So when its owner makes it a managed session,
//! that history is copied under the managed session's own names
//! ([`checkpoint::allowlist`]) before the harness resumes it, and the
//! session's checkpoints take it from there.
//!
//! The daemon never opens a path in an account's tree (spec §3b): it starts
//! `meshharbord hive-import` as the account, as `hive-pack` runs (P2f-2a), feeds
//! it the [`Request`] on stdin, and reads one line back,
//! `{"files":N,"bytes":B,"skipped":S}`. The child reads only what the
//! account could read itself.
//!
//! | Rule | Why |
//! |---|---|
//! | the history is the ONE regular file `<id>.jsonl` under `projects/*/` of the account's `~/.claude`, the folder's own project directory first; nothing through a link | the account's own files, where Claude Code keeps them; a link could name anything the account reads, which is the account's to share and not this tool's to follow |
//! | its first line that names a session names this one | a file of that name holding another conversation is not this session's history |
//! | whole lines only: the copy ends at the history's last newline | a terminal killed mid-write leaves a line cut short, which no resume reads |
//! | `<id>/subagents/` and `<id>/tool-results/` come with it, regular files only, within [`MAX_DEPTH`] and [`MAX_FILES`], and all of it within [`MAX_NEW_BYTES`] | the history names them, and the session's first checkpoint must be able to take the whole |
//! | the folder's auto-memory, the person's settings and their `CLAUDE.md` stay where they are | that memory is every terminal session's of the folder, not this one's; the rest is the person's |
//! | never over a history already there; each file written beside its place and renamed in, the history last | the history is what makes the launch resume: a copy cut short must not read as a whole one |
//!
//! ⚠️ A terminal run with `CLAUDE_CONFIG_DIR` set keeps its history
//! elsewhere, which the child is not told and does not look for: it finds
//! none, and says so.
//! ⚠️ The permission mode the terminal ran in is recorded in the history (a
//! `permission-mode` line) and is NOT restored by the resume: `-p --resume`
//! restores no recorded mode, and the launch pins `default` anyway (spec §8,
//! probed 2026-10-13 with Claude Code 2.1.280).

#![cfg_attr(windows, allow(dead_code))]

use std::fs;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use roomler_hive_node::checkpoint::{self, MAX_DEPTH, MAX_FILES, MAX_NEW_BYTES};
use roomler_hive_node::launch::history_path_in;
use serde::{Deserialize, Serialize};

use super::checkpointer::Runner;

/// The hidden subcommand: `meshharbord hive-import`, its request on stdin.
pub const IMPORT_SUBCOMMAND: &str = "hive-import";

/// The most request bytes read: three paths and an id.
const MAX_REQUEST: u64 = 64 * 1024;

/// The most the child answers: one line.
const MAX_ANSWER: u64 = 64 * 1024;

/// How long an import may run: a long history is copied whole.
pub(crate) const IMPORT_TIMEOUT: Duration = Duration::from_secs(300);

/// Bumped when the fields change their meaning; a child refuses another.
pub(crate) const REQUEST_V: u32 = 1;

/// How many of a history's first lines are read for the session it names:
/// Claude Code names it on its first.
const NAMING_LINES: usize = 64;

/// What the daemon asks of the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Request {
    pub v: u32,
    /// The terminal's Claude Code session id (a UUID): every name.
    pub harness_session: String,
    /// The account's Claude Code directory, `~/.claude`.
    pub claude_dir: PathBuf,
    /// The folder the terminal ran in, as this device kept it: its project
    /// directory is looked in first. `None` for a terminal adopted before
    /// P2f-4a, whose history is then the one any project directory holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// The managed session's `CLAUDE_CONFIG_DIR` on this device.
    pub config_dir: PathBuf,
}

/// What was put in place: files and bytes, and what was left out because
/// it was not a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Done {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
}

/// Claude Code's name for a folder's project directory: every character
/// that is not an ASCII letter or digit as `-` (`/home/a/x` is `-home-a-x`).
/// A name Claude Code shortens (a very long path) is not this one, and the
/// history is then the one any project directory holds.
pub(crate) fn project_name(folder: &str) -> String {
    folder
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// The child's work, as the account.
pub(crate) fn produce(req: &Request) -> Result<Done, String> {
    if req.v != REQUEST_V {
        return Err(format!(
            "a request of version {}; this build reads {REQUEST_V}",
            req.v
        ));
    }
    // Its id is part of every name: held to a UUID before it is one.
    checkpoint::allowlist(&req.harness_session).map_err(|e| e.to_string())?;
    let id = req.harness_session.as_str();
    let dest = history_path_in(&req.config_dir, id);
    if fs::symlink_metadata(&dest).is_ok() {
        return Err("the session has a history here already".into());
    }
    let project = find_project(&req.claude_dir.join("projects"), id, req.folder.as_deref())?;
    let history = project.join(format!("{id}.jsonl"));
    names_session(&history, id)?;
    let mut plan = Plan::default();
    plan.add(&history, &dest)?;
    let own = dest
        .parent()
        .ok_or("the history's place has no directory")?
        .join(id);
    for sub in ["subagents", "tool-results"] {
        plan.walk(&project.join(id).join(sub), &own.join(sub), 1)?;
    }
    plan.write()
}

/// The project directory under `projects` that holds `<id>.jsonl`, a regular
/// file in a directory that is not a link: the folder's own first, else the
/// one that does.
fn find_project(projects: &Path, id: &str, folder: Option<&str>) -> Result<PathBuf, String> {
    let file = format!("{id}.jsonl");
    let holds = |dir: &Path| {
        fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir())
            && fs::symlink_metadata(dir.join(&file)).is_ok_and(|m| m.file_type().is_file())
    };
    if let Some(own) = folder.map(|f| projects.join(project_name(f)))
        && holds(&own)
    {
        return Ok(own);
    }
    let none = || {
        "no history of the session where Claude Code keeps one (~/.claude/projects); a \
         terminal that set CLAUDE_CONFIG_DIR keeps it elsewhere"
            .to_string()
    };
    let entries = match fs::read_dir(projects) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(none()),
        Err(e) => return Err(format!("{}: {e}", projects.display())),
    };
    let mut found = None;
    for e in entries {
        let e = e.map_err(|e| format!("{}: {e}", projects.display()))?;
        if !e.file_type().is_ok_and(|t| t.is_dir()) || !holds(&e.path()) {
            continue;
        }
        if found.is_some() {
            return Err(
                "more than one project directory holds a history of the session".to_string(),
            );
        }
        found = Some(e.path());
    }
    found.ok_or_else(none)
}

/// The history names this session on its first line that names one.
fn names_session(history: &Path, id: &str) -> Result<(), String> {
    let f = fs::File::open(history).map_err(|e| format!("{}: {e}", history.display()))?;
    let reader = std::io::BufReader::new(f.take(MAX_NEW_BYTES));
    for line in reader.lines().take(NAMING_LINES) {
        let line = line.map_err(|e| format!("{}: {e}", history.display()))?;
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(named) = v.get("sessionId").and_then(|s| s.as_str()) {
            return if named == id {
                Ok(())
            } else {
                Err("the file holds another session's history".into())
            };
        }
    }
    Err("the file names no session in its first lines".into())
}

/// What a copy takes, in order, and how much of it there is.
#[derive(Default)]
struct Plan {
    /// From where, to where. The history first.
    files: Vec<(PathBuf, PathBuf)>,
    bytes: u64,
    skipped: u64,
}

impl Plan {
    fn add(&mut self, from: &Path, to: &Path) -> Result<(), String> {
        let md = fs::symlink_metadata(from).map_err(|e| format!("{}: {e}", from.display()))?;
        if !md.file_type().is_file() {
            self.skipped += 1;
            return Ok(());
        }
        if self.files.len() >= MAX_FILES {
            return Err(format!(
                "the history and its files are more than {MAX_FILES}"
            ));
        }
        self.bytes = self.bytes.saturating_add(md.len());
        if self.bytes > MAX_NEW_BYTES {
            return Err(format!(
                "the history and its files are more than {MAX_NEW_BYTES} bytes"
            ));
        }
        self.files.push((from.to_path_buf(), to.to_path_buf()));
        Ok(())
    }

    /// Every regular file under `from`, kept under `to` by the same names; a
    /// link, or anything else that is not a directory or a file, is left
    /// out. An absent `from` holds nothing.
    fn walk(&mut self, from: &Path, to: &Path, depth: usize) -> Result<(), String> {
        let md = match fs::symlink_metadata(from) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", from.display())),
        };
        if !md.file_type().is_dir() {
            self.skipped += 1;
            return Ok(());
        }
        if depth > MAX_DEPTH {
            return Err(format!(
                "{} is nested deeper than {MAX_DEPTH}",
                from.display()
            ));
        }
        let mut entries = fs::read_dir(from)
            .map_err(|e| format!("{}: {e}", from.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", from.display()))?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name();
            match e.file_type() {
                Ok(t) if t.is_dir() => self.walk(&from.join(&name), &to.join(&name), depth + 1)?,
                Ok(t) if t.is_file() => self.add(&from.join(&name), &to.join(&name))?,
                _ => self.skipped += 1,
            }
        }
        Ok(())
    }

    /// Each file beside its place, then renamed in; the history last.
    fn write(self) -> Result<Done, String> {
        let mut bytes = 0u64;
        let Some((history, rest)) = self.files.split_first() else {
            return Err("nothing to put in place".into());
        };
        for (from, to) in rest {
            bytes += copy_in(from, to, false)?;
        }
        bytes += copy_in(&history.0, &history.1, true)?;
        Ok(Done {
            files: self.files.len() as u64,
            bytes,
            skipped: self.skipped,
        })
    }
}

/// `from` to `to`: written beside it, then renamed in. `whole_lines`: cut at
/// the last newline. The bytes kept.
fn copy_in(from: &Path, to: &Path, whole_lines: bool) -> Result<u64, String> {
    let dir = to.parent().ok_or("a file's place has no directory")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = to
        .file_name()
        .ok_or("a file's place has no name")?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.hive-import"));
    let copied = (|| -> std::io::Result<u64> {
        let mut src = fs::File::open(from)?;
        // Read back too: the last newline is looked for in the copy.
        let mut out = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        let mut len = std::io::copy(&mut (&mut src).take(MAX_NEW_BYTES), &mut out)?;
        if whole_lines {
            len = last_newline(&mut out, len)?;
            out.set_len(len)?;
        }
        out.flush()?;
        out.sync_all()?;
        Ok(len)
    })();
    let len = match copied {
        Ok(0) if whole_lines => {
            let _ = fs::remove_file(&tmp);
            return Err(format!("{} holds no whole line", from.display()));
        }
        Ok(len) => len,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(format!("{}: {e}", from.display()));
        }
    };
    fs::rename(&tmp, to).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: {e}", to.display())
    })?;
    Ok(len)
}

/// Where the last line `f` holds ends: just past its last newline, read back
/// from the end in blocks; 0 when it holds none.
fn last_newline(f: &mut fs::File, len: u64) -> std::io::Result<u64> {
    const BLOCK: u64 = 64 * 1024;
    let mut end = len;
    let mut buf = vec![0u8; BLOCK as usize];
    while end > 0 {
        let start = end.saturating_sub(BLOCK);
        let n = (end - start) as usize;
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

// ─── the daemon's side ──────────────────────────────────────────────────────

/// Ask `req` of the terminal's account on this device (`who`), through
/// `run`: the child as the account, fed the request on its stdin, or in this
/// process in tests.
pub(crate) async fn import(
    run: &Runner,
    who: &super::materializer::Who,
    req: &Request,
) -> Result<Done, String> {
    match run {
        #[cfg(all(unix, any(test, feature = "hive-test-launcher")))]
        Runner::InProcess { .. } => produce(req),
        #[cfg(all(test, unix))]
        Runner::Failing(why) => Err((*why).to_string()),
        #[cfg(all(test, unix))]
        Runner::Hangs => std::future::pending().await,
        Runner::Subprocess => {
            #[cfg(unix)]
            {
                let exe = PathBuf::from(super::supervisor::own_exe()?);
                run_as(
                    &exe,
                    req,
                    who.account.as_deref(),
                    who.env.clone(),
                    IMPORT_TIMEOUT,
                )
                .await
            }
            #[cfg(windows)]
            {
                let _ = (who, req);
                Err("nothing is adopted on Windows".into())
            }
        }
    }
}

/// The daemon's side on Unix: start `exe hive-import` as `account` (none in
/// tests: as the daemon), with `env` and nothing of the daemon's own, feed it
/// `req` on stdin, and read its one line.
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
    cmd.arg(IMPORT_SUBCOMMAND)
        .env_clear()
        .envs(env)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own group, ended whole on a timeout or when abandoned.
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
    let out = super::child::run_fed(cmd, IMPORT_SUBCOMMAND, feed, timeout, MAX_ANSWER).await?;
    serde_json::from_slice(out.trim_ascii())
        .map_err(|e| format!("{IMPORT_SUBCOMMAND} answered something else: {e}"))
}

// ─── the child's side ───────────────────────────────────────────────────────

/// Whether this process was started as `meshharbord hive-import`, its request
/// on stdin.
pub fn import_args() -> bool {
    let mut args = std::env::args_os().skip(1);
    args.next().is_some_and(|a| a == IMPORT_SUBCOMMAND) && args.next().is_none()
}

/// The child: read the request on stdin, put the history in place as
/// whoever this process runs as (the terminal's account), and write one
/// line to stdout. 0 on success; 1 with a word on stderr otherwise.
pub fn import_main() -> i32 {
    let run = || -> Result<(), String> {
        let mut text = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::stdin().lock().take(MAX_REQUEST + 1),
            &mut text,
        )
        .map_err(|e| format!("reading the request: {e}"))?;
        if text.len() as u64 > MAX_REQUEST {
            return Err("the request is too large".into());
        }
        let req: Request =
            serde_json::from_slice(&text).map_err(|e| format!("the request: {e}"))?;
        let done = produce(&req)?;
        let line = serde_json::to_string(&done).map_err(|e| e.to_string())?;
        println!("{line}");
        Ok(())
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("roomlerd {IMPORT_SUBCOMMAND}: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70";
    const OTHER: &str = "0b9e3c7e-6a43-4a43-9d63-2d1b0d1c2f10";

    /// A home with a terminal's history for `ID` in the project directory of
    /// `folder`, and a managed session's config directory beside it.
    struct Home {
        dir: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn claude(&self) -> PathBuf {
            self.dir.path().join(".claude")
        }
        fn config(&self) -> PathBuf {
            self.dir.path().join("state").join("claude")
        }
        fn project(&self, folder: &str) -> PathBuf {
            self.claude().join("projects").join(project_name(folder))
        }
        /// A history naming `named`, in `folder`'s project directory.
        fn history(&self, folder: &str, named: &str, tail: &str) -> PathBuf {
            let dir = self.project(folder);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{ID}.jsonl"));
            let text = format!(
                "{{\"type\":\"permission-mode\",\"permissionMode\":\"bypassPermissions\",\"sessionId\":\"{named}\"}}\n\
                 {{\"type\":\"user\",\"sessionId\":\"{named}\",\"message\":{{\"role\":\"user\",\"content\":\"hi\"}}}}\n{tail}"
            );
            fs::write(&path, text).unwrap();
            path
        }
        fn req(&self, folder: Option<&str>) -> Request {
            Request {
                v: REQUEST_V,
                harness_session: ID.into(),
                claude_dir: self.claude(),
                folder: folder.map(str::to_string),
                config_dir: self.config(),
            }
        }
        fn put(&self) -> PathBuf {
            history_path_in(&self.config(), ID)
        }
    }

    #[test]
    fn claude_codes_name_for_a_folder() {
        assert_eq!(project_name("/home/alice/x"), "-home-alice-x");
        assert_eq!(project_name("/srv/my_app.v2"), "-srv-my-app-v2");
        assert_eq!(
            project_name(r"C:\dev\gjovanov\roomler-ai"),
            "C--dev-gjovanov-roomler-ai"
        );
    }

    #[test]
    fn the_terminals_history_comes_whole_lines_with_its_files() {
        let h = Home::new();
        let from = h.history("/home/me/work", ID, "{\"type\":\"assistant\",\"sessi");
        let own = from.parent().unwrap().join(ID);
        fs::create_dir_all(own.join("subagents")).unwrap();
        fs::write(own.join("subagents").join("agent-a1.jsonl"), "{}\n").unwrap();
        fs::write(own.join("subagents").join("agent-a1.meta.json"), "{}").unwrap();
        fs::create_dir_all(own.join("tool-results").join("deep")).unwrap();
        fs::write(own.join("tool-results").join("deep").join("b1.txt"), "out").unwrap();
        // The folder's memory is every terminal session's of it: it stays.
        fs::create_dir_all(from.parent().unwrap().join("memory")).unwrap();
        fs::write(from.parent().unwrap().join("memory").join("MEMORY.md"), "m").unwrap();
        let done = produce(&h.req(Some("/home/me/work"))).unwrap();
        assert_eq!((done.files, done.skipped), (4, 0), "{done:?}");
        let put = fs::read_to_string(h.put()).unwrap();
        assert!(
            put.ends_with("\"content\":\"hi\"}}\n"),
            "cut at the last whole line: {put}"
        );
        assert!(
            put.contains("bypassPermissions"),
            "byte for byte: its mode line stays"
        );
        let mine = h.put().parent().unwrap().join(ID);
        assert_eq!(
            fs::read_to_string(mine.join("tool-results").join("deep").join("b1.txt")).unwrap(),
            "out"
        );
        assert!(mine.join("subagents").join("agent-a1.meta.json").is_file());
        assert!(
            !h.put().parent().unwrap().join("memory").exists(),
            "the folder's memory stays where it is"
        );
        // Nothing of the copy is left beside it.
        let leftovers: Vec<_> = fs::read_dir(h.put().parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".hive-import"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn never_over_a_history_already_there() {
        let h = Home::new();
        h.history("/home/me/work", ID, "");
        fs::create_dir_all(h.put().parent().unwrap()).unwrap();
        fs::write(h.put(), "mine\n").unwrap();
        let e =
            produce(&h.req(Some("/home/me/work"))).expect_err("never over a history already there");
        assert!(e.contains("already"), "{e}");
        assert_eq!(fs::read_to_string(h.put()).unwrap(), "mine\n");
    }

    #[test]
    fn another_sessions_history_by_that_name_is_refused() {
        let h = Home::new();
        h.history("/home/me/work", OTHER, "");
        let e = produce(&h.req(Some("/home/me/work")))
            .expect_err("another session's history is refused");
        assert!(e.contains("another session"), "{e}");
        assert!(!h.put().exists());
    }

    #[test]
    fn found_in_another_project_only_when_it_is_the_one() {
        let h = Home::new();
        // The folder was renamed since, or its name was shortened: found anyway.
        h.history("/home/me/elsewhere", ID, "");
        let done = produce(&h.req(Some("/home/me/work"))).unwrap();
        assert_eq!(done.files, 1);
        // Two of them: which is the terminal's is not known.
        let h = Home::new();
        h.history("/home/me/a", ID, "");
        h.history("/home/me/b", ID, "");
        let e = produce(&h.req(None)).unwrap_err();
        assert!(e.contains("more than one"), "{e}");
        // The folder's own wins over the others.
        let h = Home::new();
        h.history("/home/me/a", ID, "");
        h.history("/home/me/work", ID, "");
        assert!(produce(&h.req(Some("/home/me/work"))).is_ok());
    }

    #[test]
    fn none_is_said_in_words() {
        let h = Home::new();
        let e = produce(&h.req(Some("/home/me/work"))).unwrap_err();
        assert!(e.contains("CLAUDE_CONFIG_DIR"), "{e}");
    }

    #[test]
    fn a_malformed_id_names_nothing() {
        let h = Home::new();
        let mut req = h.req(None);
        req.harness_session = "../../etc/passwd".into();
        assert!(produce(&req).is_err());
        req.harness_session = ID.to_uppercase();
        assert!(
            produce(&req).is_err(),
            "an upper-case form names other files"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nothing_through_a_link() {
        use std::os::unix::fs::symlink;
        let h = Home::new();
        let from = h.history("/home/me/work", ID, "");
        // A history that is a link is no history.
        let elsewhere = h.dir.path().join("elsewhere.jsonl");
        fs::rename(&from, &elsewhere).unwrap();
        symlink(&elsewhere, &from).unwrap();
        assert!(
            produce(&h.req(Some("/home/me/work"))).is_err(),
            "a history that is a link is no history"
        );
        // A file under its directory that is a link is left out, and said.
        fs::remove_file(&from).unwrap();
        fs::rename(&elsewhere, &from).unwrap();
        let own = from.parent().unwrap().join(ID).join("tool-results");
        fs::create_dir_all(&own).unwrap();
        symlink("/etc/passwd", own.join("p.txt")).unwrap();
        let done = produce(&h.req(Some("/home/me/work"))).unwrap();
        assert_eq!(
            (done.files, done.skipped),
            (1, 1),
            "a link under its directory is left out: {done:?}"
        );
        assert!(
            !h.put()
                .parent()
                .unwrap()
                .join(ID)
                .join("tool-results")
                .join("p.txt")
                .exists(),
            "nothing put in place through it"
        );
    }

    #[test]
    fn a_request_of_another_version_is_refused() {
        let h = Home::new();
        let mut req = h.req(None);
        req.v = REQUEST_V + 1;
        assert!(produce(&req).unwrap_err().contains("version"));
    }

    #[test]
    fn the_last_newline_is_found_across_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let mut text = "a".repeat(200 * 1024);
        text.push('\n');
        text.push_str(&"b".repeat(70 * 1024));
        fs::write(&path, &text).unwrap();
        let mut f = fs::OpenOptions::new().read(true).open(&path).unwrap();
        assert_eq!(
            last_newline(&mut f, text.len() as u64).unwrap(),
            200 * 1024 + 1
        );
        fs::write(&path, "no newline").unwrap();
        let mut f = fs::File::open(&path).unwrap();
        assert_eq!(last_newline(&mut f, 10).unwrap(), 0);
    }
}
