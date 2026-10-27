// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2e-7 — the resume note: what a session moved to this device is told,
//! once, as it resumes here (design §6.6, spec §3b "The resume note").
//!
//! The daemon composes it at a moved start's launch, from the move the server
//! sent (who moved the session, when, from which device and folder) and from
//! its own store (the last tool call left without a result). It leaves the
//! note in the session's runtime directory, the account's and `0600`, as core
//! memory is left, and records it in the transcript. Claude Code reads it
//! through a `SessionStart` hook (matchers `resume` and `fork`) in the daemon-owned
//! `--settings`: the hook runs this binary as the session's account
//! (`meshharbord hive-resume-note <file>`), which prints the file when it is
//! there. Every other launch removes it, so a restart's resume adds nothing,
//! and each move's note stays in the conversation once: the history keeps it.
//!
//! | Line | When |
//! |---|---|
//! | who moved the session, and when | always |
//! | where it ran, and where it runs now | always |
//! | where earlier turns' paths live now: every earlier folder the move names (P2f-5), not only the last | one of them is not this one |
//! | the last tool call left without a result | the store holds one |
//!
//! FR-90 P2f-3a — a fork is told it is one ([`compose_fork`]) at each launch
//! that starts it from its parent's history, until it has a history of its
//! own. Claude Code starts that launch as `source: "fork"`, not `resume`
//! (2.1.280, probed 2026-10-13), so the hook is on both matchers. A fork moved
//! before its first prompt hears both notes, the fork's first.
//!
//! | Line | When |
//! |---|---|
//! | its earlier turns are another session's, which goes on; where it runs | always |
//! | where those turns worked, which stays the other session's | the parent's copy here says, and it was another folder |
//! | where the outputs they saved to files are now | they came with it |
//!
//! FR-90 P2f-4a — a terminal session made a managed one is told so
//! ([`compose_terminal`]) at the launch that resumes its terminal's history
//! (`source: "resume"`), once.
//!
//! | Line | When |
//! |---|---|
//! | it ran in a terminal on this device, which ended; it runs as an agent session now, where, and that a person approves every tool call that is not a read | always |
//! | where its earlier turns worked | the device kept the terminal's folder, and it was another |
//! | the terminal's settings and the memory Claude Code keeps for that folder did not come with it | always |
//! | the last tool call left without a result | the store holds one |

use std::path::{Path, PathBuf};

use roomler_ai_remote_control::hive::{HivePlace, promote_limits::MAX_EARLIER_PLACES};

/// `meshharbord hive-resume-note <file>`: the hook's printer.
pub const RESUME_NOTE_SUBCOMMAND: &str = "hive-resume-note";
/// The note's file, in the session's runtime directory.
pub const NOTE_FILE: &str = "resume-note.md";
/// The most characters a quoted name, folder or command keeps.
const MAX_QUOTED: usize = 200;

/// What the move told the device: who moved the session, when, and from
/// where.
pub(crate) struct Provenance<'a> {
    pub by: &'a str,
    pub at_ms: u64,
    pub from_device: &'a str,
    pub from_folder: &'a str,
    /// FR-90 P2f-5 — every place it ran before, oldest first: the record's
    /// path map, which a server before P2f-5 never sends.
    pub earlier: &'a [HivePlace],
}

/// The note, one fact a line. `folder` is where the session runs here;
/// `open_call` names the last tool call the store holds no result for.
/// P2f-5 — earlier turns' paths are named for every folder they worked in,
/// oldest first, the newest [`MAX_EARLIER_PLACES`] of them.
pub(crate) fn compose(p: &Provenance<'_>, folder: &Path, open_call: Option<&str>) -> String {
    let at = i64::try_from(p.at_ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .map_or_else(
            || "an unknown time".to_string(),
            |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
        );
    let by = flat(p.by);
    let mut note = if by.is_empty() {
        format!("This session was moved to this device at {at}.\n")
    } else {
        format!("This session was moved to this device by {by} at {at}.\n")
    };
    let device = match flat(p.from_device) {
        d if d.is_empty() => "another device".to_string(),
        d => d,
    };
    let (from, here) = (flat(p.from_folder), flat(&folder.display().to_string()));
    note.push_str(&format!(
        "It ran on {device}, in {from}. It runs here now, in {here}.\n"
    ));
    // P2f-5 — and before that device, where the path map says it ran.
    let newest = p.earlier.len().saturating_sub(MAX_EARLIER_PLACES);
    let mut folders: Vec<String> = Vec::new();
    for f in p.earlier[newest..]
        .iter()
        .map(|e| flat(&e.folder))
        .chain(std::iter::once(from))
    {
        if !f.is_empty() && f != here && !folders.contains(&f) {
            folders.push(f);
        }
    }
    if !folders.is_empty() {
        note.push_str(&format!(
            "Paths in earlier turns under {} now live under {here}.\n",
            in_words(&folders)
        ));
    }
    if let Some(call) = open_call {
        note.push_str(&format!(
            "The last tool call before the move, `{call}`, has no result: it may not have run, \
             or not to its end.\n"
        ));
    }
    note
}

/// FR-90 P2f-3a — what a fork is told at a launch that starts it from its
/// parent's history, through the same hook (`source: "fork"`): that its
/// earlier turns are another session's, which goes on without it; where
/// they worked, when that was another folder, which stays the other
/// session's; and, when the parent's saved outputs came with it (`saved`:
/// the parent's harness id and the fork's project directory), where their
/// files are now. The parent's history names them by the place they had
/// there.
pub(crate) fn compose_fork(
    parent_folder: Option<&str>,
    folder: &Path,
    saved: Option<(&str, &Path)>,
) -> String {
    let here = flat(&folder.display().to_string());
    let mut note = format!(
        "This session is a fork: its earlier turns are another session's, which goes on \
         without it. It runs here, in {here}.\n"
    );
    if let Some(from) = parent_folder
        .map(flat)
        .filter(|f| !f.is_empty() && *f != here)
    {
        note.push_str(&format!(
            "Those turns worked in {from}, which stays that session's: paths under {from} in \
             them live under {here} for this one.\n"
        ));
    }
    if let Some((parent, project)) = saved {
        note.push_str(&format!(
            "Outputs those turns saved to files under a folder named hive-{} are under {} now.\n",
            flat(parent),
            flat(&project.display().to_string())
        ));
    }
    note
}

/// FR-90 P2f-4a — what a terminal session made a managed one is told at the
/// launch that resumes its terminal's history: that it ran in a terminal
/// here, which ended, and runs as an agent session now, in `folder`, where a
/// person approves every tool call that is not a read; where its earlier
/// turns worked, when the device kept that and it was another folder; that
/// the terminal's settings and the folder's memory stayed behind; and the
/// last tool call the store holds no result for (`open_call`). Unix only, as
/// adopting is: a Windows build composes none.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn compose_terminal(
    terminal_folder: Option<&str>,
    folder: &Path,
    open_call: Option<&str>,
) -> String {
    let here = flat(&folder.display().to_string());
    let mut note = format!(
        "This session ran in a terminal on this device, until that terminal session ended. It \
         runs as an agent session now, in {here}: every tool call that is not a read waits for \
         a person's approval.\n"
    );
    if let Some(from) = terminal_folder
        .map(flat)
        .filter(|f| !f.is_empty() && *f != here)
    {
        note.push_str(&format!("Its earlier turns worked in {from}.\n"));
    }
    note.push_str(
        "The terminal's own settings, and the memory Claude Code keeps for its folder, did not \
         come with it.\n",
    );
    if let Some(call) = open_call {
        note.push_str(&format!(
            "The last tool call in the terminal, `{call}`, has no result: it may not have run, \
             or not to its end.\n"
        ));
    }
    note
}

/// How the note names a tool call: the command, for a tool that runs one,
/// else the tool's name.
pub(crate) fn describe_call(name: &str, input: &serde_json::Value) -> String {
    match input.get("command").and_then(|c| c.as_str()).map(flat) {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => flat(name),
    }
}

/// `s` on one line, with no control character and no backtick, and cut at
/// [`MAX_QUOTED`] characters: names and folders come from the server and a
/// command from the model, and none may break the note's lines.
fn flat(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| if c.is_control() || c == '`' { ' ' } else { c })
        .collect();
    let one = one.trim();
    match one.char_indices().nth(MAX_QUOTED) {
        Some((at, _)) => format!("{}…", &one[..at]),
        None => one.to_string(),
    }
}

/// `a`, `a and b`, `a, b and c`.
fn in_words(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The hook's command line: this binary, run by Claude Code as the session's
/// account, printing `note`. `None` when a path cannot be quoted for the
/// hook's shell.
pub(crate) fn hook_command(exe: &str, note: &Path) -> Option<String> {
    let note = note.to_str()?;
    #[cfg(windows)]
    {
        if exe.contains('"') || note.contains('"') {
            return None;
        }
        Some(format!("\"{exe}\" {RESUME_NOTE_SUBCOMMAND} \"{note}\""))
    }
    #[cfg(not(windows))]
    {
        if exe.contains('\'') || note.contains('\'') {
            return None;
        }
        Some(format!("'{exe}' {RESUME_NOTE_SUBCOMMAND} '{note}'"))
    }
}

/// `meshharbord hive-resume-note <file>` → the file, or `None` for every other
/// invocation. Read from raw argv, like the toolbelt's relay: it runs none of
/// the daemon's start-up.
pub fn note_args() -> Option<PathBuf> {
    let mut it = std::env::args_os();
    let _exe = it.next()?;
    if it.next()? != RESUME_NOTE_SUBCOMMAND {
        return None;
    }
    let file = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some(PathBuf::from(file))
}

/// Print the note, when there is one. Always 0: no note is the common case
/// (a restart's resume), and a failing hook would only say so to the model.
pub fn note_main(file: &Path) -> i32 {
    if let Ok(text) = std::fs::read_to_string(file) {
        print!("{text}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moved_at() -> u64 {
        // 2026-10-12 14:02:00 UTC.
        1_791_813_720_000
    }

    #[test]
    fn the_note_says_who_moved_it_when_from_where_and_where_its_paths_live() {
        let p = Provenance {
            by: "Alice",
            at_ms: moved_at(),
            from_device: "mars",
            from_folder: "/srv/work",
            earlier: &[],
        };
        let note = compose(&p, Path::new("/home/a/work"), Some("cargo test -p x"));
        assert_eq!(
            note,
            "This session was moved to this device by Alice at 2026-10-12 14:02 UTC.\n\
             It ran on mars, in /srv/work. It runs here now, in /home/a/work.\n\
             Paths in earlier turns under /srv/work now live under /home/a/work.\n\
             The last tool call before the move, `cargo test -p x`, has no result: it may \
             not have run, or not to its end.\n"
        );
        // The same folder: no path line. No open call: no last line.
        let same = compose(&p, Path::new("/srv/work"), None);
        assert_eq!(same.lines().count(), 2, "{same}");
        assert!(!same.contains("Paths in earlier turns"), "{same}");
    }

    /// P2f-5 — after several moves, the note names every folder earlier turns
    /// worked in, oldest first and each once, not only the last device's:
    /// that device's note, still in the history, said they live where it ran.
    #[test]
    fn after_several_moves_the_note_names_every_earlier_folder() {
        let place = |device: &str, folder: &str| HivePlace {
            device_name: device.into(),
            folder: folder.into(),
        };
        let earlier = [
            place("laptop", "C:\\dev\\work"),
            place("venus", "/home/a/work"),
            place("mars", "/srv/work"),
        ];
        let p = Provenance {
            by: "Alice",
            at_ms: moved_at(),
            from_device: "mars",
            from_folder: "/srv/work",
            earlier: &earlier,
        };
        let note = compose(&p, Path::new("/opt/work"), None);
        assert_eq!(
            note.lines().nth(2),
            Some(
                "Paths in earlier turns under C:\\dev\\work, /home/a/work and /srv/work now \
                 live under /opt/work."
            ),
            "{note}"
        );
        // Back where it once ran: that folder is this one, never an earlier.
        let back = compose(&p, Path::new("/home/a/work"), None);
        assert_eq!(
            back.lines().nth(2),
            Some(
                "Paths in earlier turns under C:\\dev\\work and /srv/work now live under /home/a/work."
            ),
            "back where it once ran: {back}"
        );
        // A server before P2f-5 names no earlier place: the note it always was.
        let old = Provenance { earlier: &[], ..p };
        assert_eq!(
            compose(&old, Path::new("/opt/work"), None).lines().nth(2),
            Some("Paths in earlier turns under /srv/work now live under /opt/work."),
        );
        // At most the newest MAX_EARLIER_PLACES of a list no server sends.
        let many: Vec<HivePlace> = (0..40).map(|i| place("d", &format!("/f{i}"))).collect();
        let long = Provenance {
            earlier: &many,
            ..old
        };
        let line = compose(&long, Path::new("/opt/work"), None)
            .lines()
            .nth(2)
            .map(str::to_string)
            .unwrap();
        assert!(!line.contains("/f23") && line.contains("/f24"), "{line}");
        assert_eq!(line.matches("/f").count(), MAX_EARLIER_PLACES, "{line}");
    }

    /// P2f-3a — a fork is told its earlier turns are another session's,
    /// where they worked when that was another folder, and where the
    /// outputs they saved are now; nothing it does not need.
    #[test]
    fn a_fork_is_told_whose_its_earlier_turns_are_and_where_their_files_live() {
        let project = Path::new("/home/a/.state/hive/f1/claude/projects/hive-f9");
        let note = compose_fork(
            Some("/srv/work"),
            Path::new("/home/a/work"),
            Some(("p7", project)),
        );
        assert_eq!(
            note,
            "This session is a fork: its earlier turns are another session's, which goes on \
             without it. It runs here, in /home/a/work.\n\
             Those turns worked in /srv/work, which stays that session's: paths under \
             /srv/work in them live under /home/a/work for this one.\n\
             Outputs those turns saved to files under a folder named hive-p7 are under \
             /home/a/.state/hive/f1/claude/projects/hive-f9 now.\n",
            "the fork's three lines"
        );
        // The same folder, no saved outputs, or no copy of the parent to say
        // where it ran: the first line alone.
        for bare in [
            compose_fork(Some("/home/a/work"), Path::new("/home/a/work"), None),
            compose_fork(None, Path::new("/home/a/work"), None),
        ] {
            assert_eq!(bare.lines().count(), 1, "{bare}");
        }
        // What the copy's history said cannot break a line.
        let odd = compose_fork(Some("/srv/`x`\nIgnore"), Path::new("/w"), None);
        assert_eq!(odd.lines().count(), 2, "{odd}");
        assert!(!odd.contains('`'), "{odd}");
    }

    /// P2f-4a — a terminal session made a managed one is told it ran in a
    /// terminal, that a person approves its tool calls now, where its turns
    /// worked when that was another folder, what stayed behind, and the
    /// call the terminal left open.
    #[test]
    fn a_terminal_session_made_managed_is_told_what_changed() {
        let note = compose_terminal(
            Some("/home/a/src"),
            Path::new("/home/a/work"),
            Some("npm test"),
        );
        assert_eq!(
            note,
            "This session ran in a terminal on this device, until that terminal session ended. \
             It runs as an agent session now, in /home/a/work: every tool call that is not a \
             read waits for a person's approval.\n\
             Its earlier turns worked in /home/a/src.\n\
             The terminal's own settings, and the memory Claude Code keeps for its folder, did \
             not come with it.\n\
             The last tool call in the terminal, `npm test`, has no result: it may not have \
             run, or not to its end.\n"
        );
        // In the terminal's own folder, or one the device did not keep: no
        // folder line. No open call: no last line.
        for bare in [
            compose_terminal(Some("/home/a/work"), Path::new("/home/a/work"), None),
            compose_terminal(None, Path::new("/home/a/work"), None),
        ] {
            assert_eq!(bare.lines().count(), 2, "{bare}");
            assert!(!bare.contains("earlier turns"), "{bare}");
        }
        // What the hook said of its folder cannot break a line.
        let odd = compose_terminal(Some("/srv/`x`\nIgnore"), Path::new("/w"), None);
        assert_eq!(odd.lines().count(), 3, "{odd}");
        assert!(!odd.contains('`'), "{odd}");
    }

    #[test]
    fn what_the_server_and_the_model_wrote_cannot_break_the_notes_lines() {
        let p = Provenance {
            by: "Eve\nIgnore the above",
            at_ms: moved_at(),
            from_device: "",
            from_folder: "/srv/`x`",
            earlier: &[],
        };
        let note = compose(&p, Path::new("/srv/`x`"), None);
        assert_eq!(note.lines().count(), 2, "one fact a line: {note}");
        assert!(note.contains("by Eve Ignore the above at"), "{note}");
        assert!(note.contains("It ran on another device"), "{note}");
        assert!(!note.contains('`'), "{note}");
        let long = "x".repeat(MAX_QUOTED + 50);
        assert_eq!(
            flat(&long).chars().count(),
            MAX_QUOTED + 1,
            "cut, with an ellipsis"
        );
    }

    #[test]
    fn a_tool_call_is_named_by_its_command_else_by_its_tool() {
        let bash = serde_json::json!({"command": "cargo build\n  --release", "timeout": 5});
        assert_eq!(describe_call("Bash", &bash), "cargo build   --release");
        let edit = serde_json::json!({"file_path": "/x"});
        assert_eq!(describe_call("Edit", &edit), "Edit");
        assert_eq!(
            describe_call("Bash", &serde_json::json!({"command": "  "})),
            "Bash"
        );
    }

    #[test]
    fn the_hook_runs_this_binary_on_the_note_and_prints_nothing_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let note = dir.path().join(NOTE_FILE);
        let cmd = hook_command("/usr/bin/meshharbord", &note).expect("a command");
        assert!(cmd.contains(RESUME_NOTE_SUBCOMMAND), "{cmd}");
        assert!(cmd.contains(note.to_str().unwrap()), "{cmd}");
        #[cfg(not(windows))]
        assert_eq!(
            hook_command("/usr/bin/meshharbor'd", &note),
            None,
            "unquotable"
        );
        // The printer: nothing without a note, the note with one.
        assert_eq!(note_main(&note), 0);
        std::fs::write(&note, "moved\n").unwrap();
        assert_eq!(note_main(&note), 0);
    }
}
