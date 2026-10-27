// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2b-2 — a session's workspace, checkpointed through the account's own
//! `git` (decision 14), never a git built into the daemon.
//!
//! Runs AS THE SESSION'S ACCOUNT, inside `meshharbord hive-checkpoint` (P2b-3): the
//! daemon never opens a path in the account's tree. Plumbing only, through a
//! temporary index, so the person's index, branches and work tree stay as they
//! were (design §6.3):
//!
//! ```text
//! gd     = git rev-parse --absolute-git-dir           a worktree's own, or a shadow
//! idx    = $gd/hive-<sid>.index, seeded from $gd/index
//! GIT_INDEX_FILE=$idx git add -A -- .                   the folder only; ignores honoured
//! tree   = GIT_INDEX_FILE=$idx git write-tree [--prefix=<the folder>/]
//! commit = git commit-tree $tree [-p <last checkpoint's>]
//! git update-ref refs/hive/<sid>/head $commit           kept through the person's gc
//! pack   = git pack-objects --revs --thin --stdout       <commit> ^<last checkpoint's>
//! ```
//!
//! | The folder is | Repository | Taken |
//! |---|---|---|
//! | a repository's top | its own | the whole tree |
//! | inside a repository | its own | the folder's subtree only (`--prefix`), the repository's ignores still honoured |
//! | in no repository | a shadow, `<state dir>/shadow.git` | the folder, and nothing is written into it |
//!
//! ⚠️ The first checkpoint's commit has no parent, so its pack holds the whole
//! tree and none of the person's history: a member holds nothing else to
//! resolve a delta against. Each later commit is the last checkpoint's child,
//! and its pack is thin against it. The person's `HEAD` is recorded beside it,
//! for a teleport into a clone (P2f).
//!
//! ⚠️ No hook runs (`core.hooksPath` names nowhere), the fsmonitor is off and
//! nothing is signed: plumbing in a person's repository must not run their
//! hooks, or wait on their signing key, on the agent's behalf.
//!
//! ⚠️ A workspace that cannot be taken never fails the checkpoint. The config
//! directory is what a resume needs, so the workspace is skipped, in words.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use roomler_hive_node::checkpoint::{RepoKind, WorkspaceSnap, chunk_bytes};

/// The largest pack one checkpoint carries. A workspace whose first pack is
/// larger is skipped: it is not one a member can be handed each turn.
pub(crate) const MAX_PACK: usize = 512 * 1024 * 1024;

/// A lock older than this on a checkpoint's own index is stale: no checkpoint
/// is let run this long (`CHECKPOINT_TIMEOUT`, 120 s), so none still holds it.
pub(crate) const STALE_LOCK: Duration = Duration::from_secs(300);

/// FR-90 P2c — the most files, and bytes, a folder may hold that its index
/// does not have yet: what one `git add` hashes. Past either, the workspace is
/// skipped at once, in words, instead of hashing for the checkpoint's whole
/// time limit and failing: an add that is ended writes no index, so every
/// turn's end would start it over (P2b-3b).
pub(crate) const MAX_NEW_FILES: usize = 20_000;
pub(crate) const MAX_NEW_BYTES: u64 = MAX_PACK as u64;

/// Who the checkpoint commits say made them: never the person, whose name
/// would then sign a commit they did not write.
const AUTHOR_NAME: &str = "Roomler Hive";
const AUTHOR_EMAIL: &str = "hive@roomler.invalid";

/// Environment a caller's `git` could be pointed elsewhere by.
const GIT_ENV: [&str; 8] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_CONFIG_PARAMETERS",
];

/// The `git` that runs: the account's, on its `PATH`; a test names another.
pub(crate) struct Git {
    program: PathBuf,
    /// Test-only: where discovery stops (`GIT_CEILING_DIRECTORIES`), set on
    /// each command so a repository around a temp directory cannot claim a
    /// folder, without touching the process's environment.
    ceiling: Option<PathBuf>,
    /// [`MAX_NEW_FILES`] and [`MAX_NEW_BYTES`]; a test sets smaller ones.
    new_limits: (usize, u64),
}

impl Git {
    pub(crate) fn on_path() -> Self {
        Self {
            program: PathBuf::from("git"),
            ceiling: None,
            new_limits: (MAX_NEW_FILES, MAX_NEW_BYTES),
        }
    }

    #[cfg(test)]
    fn at(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            ..Self::on_path()
        }
    }

    #[cfg(any(test, all(unix, feature = "hive-test-launcher")))]
    pub(crate) fn under(ceiling: &Path) -> Self {
        Self {
            ceiling: Some(ceiling.to_path_buf()),
            ..Self::on_path()
        }
    }

    /// This git, holding a folder to `files` and `bytes` it has not taken
    /// yet in place of the real limits.
    #[cfg(test)]
    pub(crate) fn with_new_limits(self, files: usize, bytes: u64) -> Self {
        Self {
            new_limits: (files, bytes),
            ..self
        }
    }
}

/// What a workspace checkpoint came to.
#[derive(Debug)]
pub(crate) enum Outcome {
    /// The workspace and the pack's blobs, in chunk order.
    Taken {
        snap: WorkspaceSnap,
        blobs: Vec<Vec<u8>>,
    },
    /// Not taken, and why, in words for the checkpoint's `skipped`.
    Skipped(String),
}

/// The repository a folder's checkpoints are written to.
struct Repo {
    kind: RepoKind,
    git_dir: PathBuf,
    /// A shadow's work tree, the folder; an own repository finds its own.
    work_tree: Option<PathBuf>,
    /// The folder's place in its repository, `/`-terminated, or empty.
    prefix: String,
}

/// Checkpoint `folder` for the Hive session `sid` (checkpoint `n`, after turn
/// `turn`), from the last checkpoint's workspace. `state_dir` is the
/// session's own directory, where a shadow repository lives.
pub(crate) fn checkpoint(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
    sid: &str,
    n: u64,
    turn: u32,
    prev: Option<&WorkspaceSnap>,
) -> Outcome {
    match take(git, folder, state_dir, sid, n, turn, prev) {
        Ok(outcome) => outcome,
        Err(why) => Outcome::Skipped(why),
    }
}

fn take(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
    sid: &str,
    n: u64,
    turn: u32,
    prev: Option<&WorkspaceSnap>,
) -> Result<Outcome, String> {
    if sid.len() != 24
        || !sid
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("{sid:?} is not a session id"));
    }
    let repo = find_repo(git, folder, state_dir)?;
    let (tree, _) = read_folder(git, folder, &repo, sid)?;
    let head = match repo.kind {
        RepoKind::Own => run(
            cmd(git, folder, Some(&repo), None).args([
                "rev-parse",
                "--verify",
                "-q",
                "HEAD^{commit}",
            ]),
            "rev-parse HEAD",
        )
        .ok()
        .filter(|h| !h.is_empty()),
        RepoKind::Shadow => None,
    };
    let reference = format!("refs/hive/{sid}/head");
    let same_place = |p: &WorkspaceSnap| p.repo == repo.kind && p.prefix == repo.prefix;

    // A turn that changed no file writes no commit; the ref is put back if
    // someone removed it.
    if let Some(p) = prev.filter(|p| same_place(p) && p.tree == tree) {
        let kept = run(
            cmd(git, folder, Some(&repo), None).args(["update-ref", &reference, &p.commit]),
            "update-ref",
        );
        if kept.is_ok() {
            return Ok(Outcome::Taken {
                snap: WorkspaceSnap {
                    repo: repo.kind,
                    prefix: repo.prefix,
                    tree,
                    commit: p.commit.clone(),
                    base: None,
                    head,
                    pack: Vec::new(),
                },
                blobs: Vec::new(),
            });
        }
    }

    // The last checkpoint's commit is the parent while this repository still
    // holds it; otherwise the chain starts over, whole.
    let parent = prev
        .filter(|p| same_place(p))
        .map(|p| p.commit.clone())
        .filter(|c| {
            run(
                cmd(git, folder, Some(&repo), None).args([
                    "cat-file",
                    "-e",
                    &format!("{c}^{{commit}}"),
                ]),
                "cat-file",
            )
            .is_ok()
        });
    let message = format!("hive {sid} checkpoint {n} turn {turn}");
    let mut commit_tree = cmd(git, folder, Some(&repo), None);
    commit_tree
        .args(["commit-tree", "--no-gpg-sign", &tree, "-m", &message])
        .env("GIT_AUTHOR_NAME", AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", AUTHOR_EMAIL)
        .env("GIT_COMMITTER_NAME", AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", AUTHOR_EMAIL);
    if let Some(parent) = &parent {
        commit_tree.args(["-p", parent]);
    }
    let commit = run(&mut commit_tree, "commit-tree")?;
    run(
        cmd(git, folder, Some(&repo), None).args(["update-ref", &reference, &commit]),
        "update-ref",
    )?;
    let pack = pack_objects(git, folder, &repo, &commit, parent.as_slice())?;
    let (chunks, blobs) = chunk_bytes(&pack);
    Ok(Outcome::Taken {
        snap: WorkspaceSnap {
            repo: repo.kind,
            prefix: repo.prefix,
            tree,
            commit,
            base: parent,
            head,
            pack: chunks,
        },
        blobs,
    })
}

/// Remove the lock a git left on the checkpoint's own index when it was ended
/// before it could: a KILL, a power cut. Left, it refuses every checkpoint
/// after it, for good. Only an old one is removed: a running checkpoint's is
/// never older than its time limit, and the index is the session's alone.
fn clear_stale_lock(lock: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(lock) else {
        return;
    };
    let stale = meta.file_type().is_file()
        && meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > STALE_LOCK);
    if stale {
        let _ = std::fs::remove_file(lock);
    }
}

/// The folder as git reads it, through the session's temporary index
/// (`hive-<sid>.index` in the repository's git directory): every file, tracked
/// or not, ignores honoured. Its tree, and the index that holds it. In the
/// person's own repository the index is seeded from theirs, so only what
/// changed is hashed again; theirs is read, never written.
fn read_folder(
    git: &Git,
    folder: &Path,
    repo: &Repo,
    sid: &str,
) -> Result<(String, PathBuf), String> {
    let index = repo.git_dir.join(format!("hive-{sid}.index"));
    clear_stale_lock(&repo.git_dir.join(format!("hive-{sid}.index.lock")));
    if repo.kind == RepoKind::Own {
        let theirs = repo.git_dir.join("index");
        if theirs.is_file() {
            std::fs::copy(&theirs, &index).map_err(|e| format!("copying the index: {e}"))?;
        } else {
            let _ = std::fs::remove_file(&index);
        }
    }
    within_new_limits(git, folder, repo, &index)?;
    run(
        cmd(git, folder, Some(repo), Some(&index)).args(["add", "-A", "--", "."]),
        "add",
    )?;
    let tree = write_tree(git, folder, repo, &index)?;
    Ok((tree, index))
}

/// P2c — refuse, before hashing anything, a folder holding more than one
/// `git add` can take within the checkpoint's time: more than
/// [`MAX_NEW_FILES`] files, or [`MAX_NEW_BYTES`], that `index` does not have
/// yet. `git ls-files --others` walks the folder without hashing, ignores
/// honoured, and the walk stops at the first limit passed.
fn within_new_limits(git: &Git, folder: &Path, repo: &Repo, index: &Path) -> Result<(), String> {
    let (max_files, max_bytes) = git.new_limits;
    let mut c = cmd(git, folder, Some(repo), Some(index));
    c.args([
        "ls-files",
        "-z",
        "--others",
        "--exclude-standard",
        "--",
        ".",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(spawn_err)?;
    let mut stderr = child.stderr.take();
    let said = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.read_to_end(&mut s);
        }
        s
    });
    let stdout = child.stdout.take().ok_or("git ls-files has no stdout")?;
    let (mut files, mut bytes) = (0usize, 0u64);
    let mut over = false;
    for name in std::io::BufReader::new(stdout).split(0) {
        let Ok(name) = name else { break };
        let Ok(name) = std::str::from_utf8(&name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        files += 1;
        bytes += std::fs::symlink_metadata(folder.join(name)).map_or(0, |m| m.len());
        if files > max_files || bytes > max_bytes {
            over = true;
            break;
        }
    }
    if over {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "the folder holds more than one checkpoint takes ({} files or {} MiB not yet \
             in it): leave build output and other generated files to .gitignore",
            max_files,
            max_bytes >> 20
        ));
    }
    let status = child
        .wait()
        .map_err(|e| format!("waiting for git ls-files: {e}"))?;
    if !status.success() {
        let said = said.join().unwrap_or_default();
        return Err(format!("git ls-files failed: {}", tail(&said)));
    }
    Ok(())
}

/// The repository `folder` is in, or its shadow in `state_dir`.
fn find_repo(git: &Git, folder: &Path, state_dir: &Path) -> Result<Repo, String> {
    match own_repo(git, folder)? {
        Some(repo) => Ok(repo),
        None => shadow(git, folder, state_dir),
    }
}

/// The repository `folder` is in, if it is in one's work tree.
fn own_repo(git: &Git, folder: &Path) -> Result<Option<Repo>, String> {
    let inside = cmd(git, folder, None, None)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map_err(spawn_err)?;
    let answer = String::from_utf8_lossy(&inside.stdout).trim().to_string();
    if inside.status.success() && answer == "true" {
        let git_dir = run(
            cmd(git, folder, None, None).args(["rev-parse", "--absolute-git-dir"]),
            "rev-parse --absolute-git-dir",
        )?;
        let prefix = run(
            cmd(git, folder, None, None).args(["rev-parse", "--show-prefix"]),
            "rev-parse --show-prefix",
        )?;
        return Ok(Some(Repo {
            kind: RepoKind::Own,
            git_dir: PathBuf::from(git_dir),
            work_tree: None,
            prefix,
        }));
    }
    if inside.status.success() {
        // `false`: inside a repository's git directory, not its work tree.
        return Err("the folder is inside a repository's git directory".into());
    }
    Ok(None)
}

/// The shadow repository of a folder in no repository: `<state_dir>/shadow.git`,
/// made the first time.
fn shadow(git: &Git, folder: &Path, state_dir: &Path) -> Result<Repo, String> {
    let git_dir = state_dir.join("shadow.git");
    if !git_dir.join("HEAD").is_file() {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| format!("making {}: {e}", state_dir.display()))?;
        run(
            cmd(git, state_dir, None, None)
                .args(["init", "--bare", "--quiet"])
                .arg(&git_dir),
            "init",
        )?;
    }
    Ok(Repo {
        kind: RepoKind::Shadow,
        git_dir,
        work_tree: Some(folder.to_path_buf()),
        prefix: String::new(),
    })
}

/// The folder's tree. Inside a repository that is the subtree at its prefix;
/// a folder with nothing in it has the empty tree.
fn write_tree(git: &Git, folder: &Path, repo: &Repo, index: &Path) -> Result<String, String> {
    let mut c = cmd(git, folder, Some(repo), Some(index));
    c.arg("write-tree");
    if !repo.prefix.is_empty() {
        c.arg(format!("--prefix={}", repo.prefix));
    }
    let out = c.output().map_err(spawn_err)?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let said = String::from_utf8_lossy(&out.stderr);
    if !repo.prefix.is_empty() && said.contains("not found") {
        // The index holds nothing under the prefix: the folder is empty.
        let mut empty = cmd(git, folder, Some(repo), None);
        empty
            .args(["hash-object", "-t", "tree", "-w", "--stdin"])
            .stdin(Stdio::null());
        return run(&mut empty, "hash-object");
    }
    Err(format!("git write-tree failed: {}", tail(&out.stderr)))
}

/// The pack that carries `commit`: thin against `base` when there is one,
/// whole otherwise. Refused when it grows past [`MAX_PACK`].
/// `commit`'s objects but those `not` reaches: the last checkpoint's commit,
/// or (P2f-2a) the haves and their trees.
fn pack_objects(
    git: &Git,
    folder: &Path,
    repo: &Repo,
    commit: &str,
    not: &[String],
) -> Result<Vec<u8>, String> {
    let mut c = cmd(git, folder, Some(repo), None);
    c.args(["pack-objects", "--revs", "--thin", "--stdout", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(spawn_err)?;
    let mut revs = format!("{commit}\n");
    for rev in not {
        revs.push_str(&format!("^{rev}\n"));
    }
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(revs.as_bytes())
            .map_err(|e| format!("writing to git pack-objects: {e}"))?;
    }
    let mut stderr = child.stderr.take();
    let said = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.read_to_end(&mut s);
        }
        s
    });
    let mut pack = Vec::new();
    let mut stdout = child
        .stdout
        .take()
        .ok_or("git pack-objects has no stdout")?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let read = stdout
            .read(&mut buf)
            .map_err(|e| format!("reading git pack-objects: {e}"))?;
        if read == 0 {
            break;
        }
        if pack.len() + read > MAX_PACK {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "the workspace's pack is over {} MiB",
                MAX_PACK >> 20
            ));
        }
        pack.extend_from_slice(&buf[..read]);
    }
    let status = child
        .wait()
        .map_err(|e| format!("waiting for git pack-objects: {e}"))?;
    let said = said.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("git pack-objects failed: {}", tail(&said)));
    }
    Ok(pack)
}

// ─── P2f-2a: a pack against what a repository already holds ────────────────

/// FR-90 P2f-2a — the most commits a pack is asked to be thin against (git's
/// haves): the person's `HEAD` where the checkpoint was taken, the target's
/// own, a few of its branches. A request naming more is refused whole.
pub(crate) const MAX_HAVES: usize = 16;

/// FR-90 P2f-2a — an object id as git prints one: 40 lowercase hex digits
/// (SHA-1) or 64 (SHA-256). A commit another device names is held to it
/// before any git sees it, so no revision syntax (`HEAD~1`, `--all`, `^x`)
/// ever reaches one.
pub(crate) fn is_object_id(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `ids`, held to [`is_object_id`] and [`MAX_HAVES`].
fn object_ids(ids: &[String]) -> Result<(), String> {
    if ids.len() > MAX_HAVES {
        return Err(format!(
            "{} commits named, more than {MAX_HAVES}",
            ids.len()
        ));
    }
    match ids.iter().find(|id| !is_object_id(id)) {
        Some(bad) => Err(format!("{bad:?} is not a commit id")),
        None => Ok(()),
    }
}

/// Which of `candidates` `repo` holds as commits, in their order and each
/// once: one `git cat-file --batch-check` for all of them.
fn held_commits(
    git: &Git,
    cwd: &Path,
    repo: &Repo,
    candidates: &[String],
) -> Result<Vec<String>, String> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut c = cmd(git, cwd, Some(repo), None);
    c.args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(spawn_err)?;
    let input: String = candidates.iter().map(|id| format!("{id}\n")).collect();
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("writing to git cat-file: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for git cat-file: {e}"))?;
    if !out.status.success() {
        return Err(format!("git cat-file failed: {}", tail(&out.stderr)));
    }
    let answers = String::from_utf8_lossy(&out.stdout);
    let mut held: Vec<String> = Vec::new();
    for (id, line) in candidates.iter().zip(answers.lines()) {
        let mut words = line.split_whitespace();
        let named = words.next() == Some(id.as_str());
        if named && words.next() == Some("commit") && !held.contains(id) {
            held.push(id.clone());
        }
    }
    Ok(held)
}

/// The repository a folder's checkpoints go to ([`find_repo`]), and where its
/// git runs, or `None` where `find_repo` would make a shadow: a folder that is
/// missing, or in no repository and with no shadow yet. Makes nothing.
fn existing_repo(git: &Git, folder: &Path, state_dir: &Path) -> Result<Option<Repo>, String> {
    match std::fs::symlink_metadata(folder) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(format!(
                "{} is not a directory of its own",
                folder.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", folder.display())),
    }
    if let Some(repo) = own_repo(git, folder)? {
        return Ok(Some(repo));
    }
    let git_dir = state_dir.join("shadow.git");
    if !git_dir.join("HEAD").is_file() {
        return Ok(None);
    }
    Ok(Some(Repo {
        kind: RepoKind::Shadow,
        git_dir,
        work_tree: Some(folder.to_path_buf()),
        prefix: String::new(),
    }))
}

/// FR-90 P2f-2a — the pack that brings `commit` into a repository holding
/// `haves`, made from the session's own repository (the folder's, or its
/// shadow): thin against the ones of `haves` this repository holds itself,
/// and whole when it holds none. Those come back with it: the pack is of use
/// only where every one of them is held.
pub(crate) fn pack_against(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
    commit: &str,
    haves: &[String],
) -> Result<(Vec<u8>, Vec<String>), String> {
    if !is_object_id(commit) {
        return Err(format!("{commit:?} is not a commit id"));
    }
    object_ids(haves)?;
    let repo = existing_repo(git, folder, state_dir)?
        .ok_or("the session's repository is not on this device")?;
    if held_commits(git, folder, &repo, &[commit.to_string()])?.is_empty() {
        return Err(format!("the session's repository holds no commit {commit}"));
    }
    let against = held_commits(git, folder, &repo, haves)?;
    // ⚠️ Each have's tree as well as the commit. `--revs` leaves out what a
    // negative commit reaches only on the edge, a parent of what is packed;
    // a session's first checkpoint has no parent, so its pack against the
    // person's `HEAD` alone would still hold the whole tree.
    let not: Vec<String> = against
        .iter()
        .flat_map(|h| [h.clone(), format!("{h}^{{tree}}")])
        .collect();
    let pack = pack_objects(git, folder, &repo, commit, &not)?;
    Ok((pack, against))
}

/// FR-90 P2f-2a — which of `candidates` a materialize into `folder` would
/// find held already: by the folder's own repository, or by the session's
/// shadow in `state_dir` when one is there. A folder that is missing, or in
/// no repository and with no shadow yet, holds none. Unlike [`place_for`] it
/// makes nothing: it is asked before the copy is taken.
pub(crate) fn holds(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
    candidates: &[String],
) -> Result<Vec<String>, String> {
    object_ids(candidates)?;
    match existing_repo(git, folder, state_dir)? {
        Some(repo) => held_commits(git, folder, &repo, candidates),
        None => Ok(Vec::new()),
    }
}

/// FR-90 P2f-2b — the commit the folder's own repository's `HEAD` names,
/// when the folder is in one that has a commit: one more have to offer,
/// which a source holds when this clone is behind its own. A shadow's is
/// none (what it holds is the session's own, never the person's), nor is a
/// missing folder's. Makes nothing.
pub(crate) fn head_of(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
) -> Result<Option<String>, String> {
    match existing_repo(git, folder, state_dir)? {
        Some(repo) if repo.kind == RepoKind::Own => Ok(run(
            cmd(git, folder, Some(&repo), None).args([
                "rev-parse",
                "--verify",
                "-q",
                "HEAD^{commit}",
            ]),
            "rev-parse HEAD",
        )
        .ok()
        .filter(|h| is_object_id(h))),
        _ => Ok(None),
    }
}

// ─── P2b-4b: the reverse — a checkpoint's workspace put into a folder ───────

/// Where a materialize puts the workspace: the folder's own repository, or a
/// shadow for a folder in none. A missing folder gets a shadow, and is made
/// only when the workspace is switched into it.
pub(crate) struct Place {
    repo: Repo,
    folder: PathBuf,
    missing: bool,
}

impl Place {
    /// Where git runs: in the folder, or in the git directory while the
    /// folder is still missing.
    fn cwd(&self) -> &Path {
        if self.missing {
            &self.repo.git_dir
        } else {
            &self.folder
        }
    }

    pub(crate) fn kind(&self) -> RepoKind {
        self.repo.kind
    }
}

/// The place for materializing into `folder`, whose shadow, for a folder in
/// no repository, lives in `state_dir`.
pub(crate) fn place_for(git: &Git, folder: &Path, state_dir: &Path) -> Result<Place, String> {
    match std::fs::symlink_metadata(folder) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => Ok(Place {
            repo: find_repo(git, folder, state_dir)?,
            folder: folder.to_path_buf(),
            missing: false,
        }),
        Ok(_) => Err(format!(
            "{} is not a directory of its own",
            folder.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Place {
            repo: shadow(git, folder, state_dir)?,
            folder: folder.to_path_buf(),
            missing: true,
        }),
        Err(e) => Err(format!("{}: {e}", folder.display())),
    }
}

/// One pack of `len` bytes from `r`, into the place's repository through
/// `git index-pack --stdin --fix-thin`: git checks every object as it lands,
/// and resolves a thin pack's deltas against the packs before it. Nothing
/// else of the repository changes; the objects of a materialize refused
/// later are referenced by nothing, and git's own gc takes them.
pub(crate) fn index_pack(
    git: &Git,
    place: &Place,
    r: &mut impl Read,
    len: u64,
) -> Result<(), String> {
    let mut c = cmd(git, place.cwd(), Some(&place.repo), None);
    c.args(["index-pack", "--stdin", "--fix-thin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(spawn_err)?;
    let mut stderr = child.stderr.take();
    let said = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.read_to_end(&mut s);
        }
        s
    });
    // The stream's own failure, as against git's refusing the pack.
    let mut short: Option<String> = None;
    let mut left = len;
    if let Some(mut stdin) = child.stdin.take() {
        let mut buf = vec![0u8; 1 << 16];
        while left > 0 {
            let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            match r.read(&mut buf[..want]) {
                Ok(0) => {
                    short = Some("the stream ends inside a pack".into());
                    break;
                }
                Ok(n) => {
                    if stdin.write_all(&buf[..n]).is_err() {
                        // git stopped reading: its own word says why.
                        break;
                    }
                    left -= n as u64;
                }
                Err(e) => {
                    short = Some(format!("reading a pack: {e}"));
                    break;
                }
            }
        }
        // `stdin` dropped: the pack's end.
    }
    if short.is_some() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("waiting for git index-pack: {e}"))?;
    let said = said.join().unwrap_or_default();
    if let Some(why) = short {
        return Err(why);
    }
    if !status.success() {
        return Err(format!("git index-pack failed: {}", tail(&said)));
    }
    if left > 0 {
        return Err("git index-pack stopped reading the pack".into());
    }
    Ok(())
}

/// FR-90 P2f-2a — which of `ids` the place's repository holds already: a
/// substitute's pack is of use only where every commit it is thin against is.
pub(crate) fn place_holds(git: &Git, place: &Place, ids: &[String]) -> Result<Vec<String>, String> {
    object_ids(ids)?;
    held_commits(git, place.cwd(), &place.repo, ids)
}

/// The tree `commit` holds, as git hashed it from what the packs brought:
/// the checkpoint's word about its `tree` is held to it.
pub(crate) fn tree_of(git: &Git, place: &Place, commit: &str) -> Result<String, String> {
    run(
        cmd(git, place.cwd(), Some(&place.repo), None).args([
            "rev-parse",
            "--verify",
            "-q",
            &format!("{commit}^{{tree}}"),
        ]),
        "rev-parse",
    )
    .map_err(|_| format!("the packs hold no commit {commit}"))
}

/// Every path `tree` holds, recursively, `/`-separated from its root: what
/// the target's file system is held to before the folder is touched.
pub(crate) fn tree_paths(git: &Git, place: &Place, tree: &str) -> Result<Vec<String>, String> {
    let out = cmd(git, place.cwd(), Some(&place.repo), None)
        .args(["ls-tree", "-r", "-z", "--name-only", "--full-tree", tree])
        .output()
        .map_err(spawn_err)?;
    if !out.status.success() {
        return Err(format!("git ls-tree failed: {}", tail(&out.stderr)));
    }
    out.stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| {
            String::from_utf8(s.to_vec())
                .map_err(|_| "the workspace holds a name that is not UTF-8".to_string())
        })
        .collect()
}

/// What the folder holds now, read as a checkpoint reads it, and the index
/// that holds it; a missing folder holds the empty tree.
pub(crate) struct Current {
    tree: String,
    index: PathBuf,
}

/// The folder's current state, and whether it is one a materialize may
/// replace: nothing yet; exactly what its own `HEAD` holds (a clean clone);
/// exactly what this session last left in it (a member that was this
/// session's primary before: moving back); or already `tree`. Anything else
/// is the person's own work, and is refused.
pub(crate) fn judge(git: &Git, place: &Place, sid: &str, tree: &str) -> Result<Current, String> {
    match judged(git, place, sid, tree)? {
        (current, true) => Ok(current),
        (_, false) => Err(WORK_OF_ITS_OWN.into()),
    }
}

/// What [`judge`] refuses a folder for.
const WORK_OF_ITS_OWN: &str =
    "the folder holds work of its own, neither its HEAD's nor this session's";

/// FR-90 P2f-2d — whether a teleport's copy may be put into `folder`, asked
/// at its prepare, before anything moves: what [`judge`] holds the folder to
/// at the move, with no checkpoint in hand yet. `None`: it may (missing,
/// empty, exactly what its repository's `HEAD` holds, or what session `sid`
/// last left there). `Some(why)`: work of its own. A folder in no
/// repository and with no shadow of the session is read as a directory, and
/// nothing is made for it: empty, it may; holding files, it may not.
pub(crate) fn takes_a_copy(
    git: &Git,
    folder: &Path,
    state_dir: &Path,
    sid: &str,
) -> Result<Option<String>, String> {
    if existing_repo(git, folder, state_dir)?.is_none() {
        return match std::fs::read_dir(folder) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", folder.display())),
            Ok(mut entries) => Ok(entries
                .next()
                .map(|_| "it holds files, and is in no repository".to_string())),
        };
    }
    let place = place_for(git, folder, state_dir)?;
    let empty = empty_tree(git, &place)?;
    Ok(match judged(git, &place, sid, &empty)? {
        (_, true) => None,
        (_, false) => Some(
            "it is neither what its HEAD holds nor what this session last left there".to_string(),
        ),
    })
}

/// The folder's current state, and whether [`judge`] lets a materialize
/// replace it with `tree`.
fn judged(git: &Git, place: &Place, sid: &str, tree: &str) -> Result<(Current, bool), String> {
    let empty = empty_tree(git, place)?;
    let index = place.repo.git_dir.join(format!("hive-{sid}.index"));
    let now = if place.missing {
        let _ = std::fs::remove_file(&index);
        empty.clone()
    } else {
        read_folder(git, &place.folder, &place.repo, sid)?.0
    };
    let current = Current { tree: now, index };
    if current.tree == empty || current.tree == tree {
        return Ok((current, true));
    }
    let rev = |spec: String| {
        run(
            cmd(git, place.cwd(), Some(&place.repo), None).args([
                "rev-parse",
                "--verify",
                "-q",
                &spec,
            ]),
            "rev-parse",
        )
        .ok()
        .filter(|s| !s.is_empty())
    };
    if place.repo.kind == RepoKind::Own {
        let at_head = if place.repo.prefix.is_empty() {
            "HEAD^{tree}".to_string()
        } else {
            format!("HEAD:{}", place.repo.prefix.trim_end_matches('/'))
        };
        if rev(at_head).as_deref() == Some(current.tree.as_str()) {
            return Ok((current, true));
        }
    }
    let ours =
        rev(format!("refs/hive/{sid}/head^{{tree}}")).as_deref() == Some(current.tree.as_str());
    Ok((current, ours))
}

/// Move the folder from what it holds (`from`) to `tree` with git's own
/// two-tree switch (`read-tree -m -u`): what `tree` lacks is removed, what it
/// changes is rewritten with this repository's line endings and filters, and
/// an untracked file in the way is refused before anything is written. The
/// person's `HEAD`, branches and index are never touched. Then the folder is
/// held to `tree` again, read as a checkpoint reads it, and the commit kept
/// under `refs/hive/<sid>/head`, where the next checkpoint here starts.
pub(crate) fn switch(
    git: &Git,
    place: &Place,
    sid: &str,
    from: &Current,
    tree: &str,
    commit: &str,
) -> Result<(), String> {
    if place.missing {
        std::fs::create_dir_all(&place.folder)
            .map_err(|e| format!("making {}: {e}", place.folder.display()))?;
    }
    if from.tree != tree {
        let (w0, w1) = whole_trees(git, place, sid, from, tree)?;
        run(
            cmd(git, &place.folder, Some(&place.repo), Some(&from.index)).args([
                "read-tree",
                "-m",
                "-u",
                &w0,
                &w1,
            ]),
            "read-tree",
        )?;
    }
    let (after, _) = read_folder(git, &place.folder, &place.repo, sid)?;
    if after != tree {
        return Err(format!(
            "the folder reads as {after} after the switch, not the checkpoint's {tree}"
        ));
    }
    run(
        cmd(git, &place.folder, Some(&place.repo), None).args([
            "update-ref",
            &format!("refs/hive/{sid}/head"),
            commit,
        ]),
        "update-ref",
    )?;
    Ok(())
}

/// The two trees the switch moves the index between. A shadow, and a folder
/// at its repository's top, hold the folder's tree whole. A folder inside a
/// repository holds a subtree: the switch is between the whole repository's
/// trees, the index's as it is and the same with the folder's subtree
/// swapped for `tree`, so everything outside the folder stays as it is.
fn whole_trees(
    git: &Git,
    place: &Place,
    sid: &str,
    from: &Current,
    tree: &str,
) -> Result<(String, String), String> {
    if place.repo.kind == RepoKind::Shadow || place.repo.prefix.is_empty() {
        let w0 = if place.missing {
            empty_tree(git, place)?
        } else {
            from.tree.clone()
        };
        return Ok((w0, tree.to_string()));
    }
    let w0 = run(
        cmd(git, &place.folder, Some(&place.repo), Some(&from.index)).arg("write-tree"),
        "write-tree",
    )?;
    let swap = place.repo.git_dir.join(format!("hive-{sid}.swap.index"));
    let _ = std::fs::remove_file(&swap);
    let w1 = swapped(git, place, &swap, &w0, tree);
    let _ = std::fs::remove_file(&swap);
    Ok((w0, w1?))
}

/// The whole tree `w0` with the folder's subtree swapped for `tree`, built in
/// the scratch index `swap`.
fn swapped(git: &Git, place: &Place, swap: &Path, w0: &str, tree: &str) -> Result<String, String> {
    let folder = &place.folder;
    let git_at = |index: &Path| cmd(git, folder, Some(&place.repo), Some(index));
    run(git_at(swap).args(["read-tree", w0]), "read-tree")?;
    // The folder's entries out, by their paths relative to it.
    let listed = git_at(swap)
        .args(["ls-files", "-z", "--", "."])
        .output()
        .map_err(spawn_err)?;
    if !listed.status.success() {
        return Err(format!("git ls-files failed: {}", tail(&listed.stderr)));
    }
    let mut c = git_at(swap);
    c.args(["update-index", "-z", "--force-remove", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = c.spawn().map_err(spawn_err)?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&listed.stdout)
            .map_err(|e| format!("writing to git update-index: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("waiting for git update-index: {e}"))?;
    if !out.status.success() {
        return Err(format!("git update-index failed: {}", tail(&out.stderr)));
    }
    run(
        git_at(swap).args([
            "read-tree",
            &format!("--prefix={}", place.repo.prefix),
            tree,
        ]),
        "read-tree --prefix",
    )?;
    run(git_at(swap).arg("write-tree"), "write-tree")
}

/// The empty tree, as this repository's object format names it.
fn empty_tree(git: &Git, place: &Place) -> Result<String, String> {
    let mut c = cmd(git, place.cwd(), Some(&place.repo), None);
    c.args(["hash-object", "-t", "tree", "-w", "--stdin"])
        .stdin(Stdio::null());
    run(&mut c, "hash-object")
}

/// `git`, run in `folder` against `repo` (and `index`), with nothing of the
/// caller's git environment, no hook, no fsmonitor and no automatic gc.
/// FR-90 P2g-1 — what the purged session `sid`'s checkpoints left in
/// `folder`'s own repository, deleted as the account: each ref under
/// `refs/hive/<sid>/`, through `update-ref`, and the checkpoints' own index
/// with its lock in the git directory. The objects they wrote stay,
/// unreachable, for the person's own gc; the person's branches, index and
/// work tree are never touched. Nothing for a folder that is gone or in no
/// repository: a shadow lives in the session's state directory. Answers
/// `(refs deleted, index files removed)`.
pub(crate) fn forget(git: &Git, folder: &Path, sid: &str) -> Result<(usize, usize), String> {
    if sid.len() != 24
        || !sid
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("{sid:?} is not a session id"));
    }
    if !folder.is_dir() {
        return Ok((0, 0));
    }
    let Some(repo) = own_repo(git, folder)? else {
        return Ok((0, 0));
    };
    let prefix = format!("refs/hive/{sid}/");
    let listed = run(
        cmd(git, folder, Some(&repo), None).args([
            "for-each-ref",
            "--format=%(refname)",
            prefix.as_str(),
        ]),
        "for-each-ref",
    )?;
    let mut refs = 0;
    for name in listed.lines().filter(|l| !l.is_empty()) {
        // The pattern already holds it there; held again, as a ref named by
        // a repository the person owns.
        if !name.starts_with(&prefix) || name.contains("..") {
            return Err(format!("git listed {name:?} under {prefix}"));
        }
        run(
            cmd(git, folder, Some(&repo), None).args(["update-ref", "-d", name]),
            "update-ref -d",
        )?;
        refs += 1;
    }
    let mut files = 0;
    for name in [
        format!("hive-{sid}.index"),
        format!("hive-{sid}.index.lock"),
    ] {
        let path = repo.git_dir.join(&name);
        match std::fs::remove_file(&path) {
            Ok(()) => files += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("removing {}: {e}", path.display())),
        }
    }
    Ok((refs, files))
}

fn cmd(git: &Git, folder: &Path, repo: Option<&Repo>, index: Option<&Path>) -> Command {
    let mut c = Command::new(&git.program);
    c.current_dir(folder);
    for var in GIT_ENV {
        c.env_remove(var);
    }
    let no_hooks = repo.map_or_else(
        || folder.join(".roomler-hive-no-hooks"),
        |r| r.git_dir.join("hive-no-hooks"),
    );
    c.arg("-c")
        .arg(format!("core.hooksPath={}", no_hooks.display()))
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    if let Some(r) = repo
        && let Some(work_tree) = &r.work_tree
    {
        c.env("GIT_DIR", &r.git_dir).env("GIT_WORK_TREE", work_tree);
    }
    if let Some(index) = index {
        c.env("GIT_INDEX_FILE", index);
    }
    if let Some(ceiling) = &git.ceiling {
        c.env("GIT_CEILING_DIRECTORIES", ceiling);
    }
    c
}

/// Run a `git` and answer its stdout, trimmed; its stderr's tail on failure.
fn run(c: &mut Command, what: &str) -> Result<String, String> {
    let out = c.output().map_err(spawn_err)?;
    if !out.status.success() {
        return Err(format!("git {what} failed: {}", tail(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn spawn_err(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        "git was not found".into()
    } else {
        format!("running git: {e}")
    }
}

fn tail(stderr: &[u8]) -> String {
    let s = String::from_utf8_lossy(stderr);
    let s = s.trim();
    let start = s.char_indices().rev().nth(299).map_or(0, |(i, _)| i);
    s[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const SID: &str = "6aca8ef5dac84dd57e492eb7";

    /// `git` in `dir`, as a test sets up a person's repository: its own
    /// identity, no signing, no hooks, nothing from the caller's git env.
    fn person(dir: &Path, args: &[&str]) -> String {
        let mut c = Command::new("git");
        c.current_dir(dir);
        for var in GIT_ENV {
            c.env_remove(var);
        }
        let out = c
            .args([
                "-c",
                "user.name=Person",
                "-c",
                "user.email=person@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "core.autocrlf=false",
            ])
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn have_git() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    /// The paths a tree holds, recursively.
    fn files_of(dir: &Path, tree: &str) -> BTreeSet<String> {
        person(dir, &["ls-tree", "-r", "--name-only", tree])
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn write(dir: &Path, rel: &str, text: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn taken(o: Outcome) -> (WorkspaceSnap, Vec<Vec<u8>>) {
        match o {
            Outcome::Taken { snap, blobs } => (snap, blobs),
            Outcome::Skipped(why) => panic!("skipped: {why}"),
        }
    }

    fn repo_with_a_commit() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        person(dir, &["init", "-q"]);
        write(dir, "a.txt", "one\n");
        write(dir, ".gitignore", "secret.env\n");
        person(dir, &["add", "-A"]);
        person(dir, &["commit", "-q", "-m", "first"]);
        tmp
    }

    /// The person's index, branches, `HEAD` and status are as they were; the
    /// checkpoint is a parentless commit of the work tree as it is (tracked
    /// changes and untracked files, ignores honoured) under the session's ref.
    #[test]
    fn a_checkpoint_commits_the_work_tree_and_touches_nothing_of_the_persons() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let dir = tmp.path();
        let state = tempfile::tempdir().unwrap();
        write(dir, "a.txt", "one, changed\n");
        write(dir, "b.txt", "new\n");
        write(dir, "secret.env", "TOKEN=x\n");
        let git_dir = PathBuf::from(person(dir, &["rev-parse", "--absolute-git-dir"]));
        let index_before = std::fs::read(git_dir.join("index")).unwrap();
        let status_before = person(dir, &["status", "--porcelain"]);
        let branches_before = person(dir, &["for-each-ref", "refs/heads"]);
        let head_before = person(dir, &["rev-parse", "HEAD"]);

        let (snap, blobs) = taken(checkpoint(
            &Git::on_path(),
            dir,
            state.path(),
            SID,
            1,
            1,
            None,
        ));

        assert_eq!(snap.repo, RepoKind::Own);
        assert_eq!(snap.prefix, "");
        assert_eq!(snap.head.as_deref(), Some(head_before.as_str()));
        assert_eq!(snap.base, None, "the first has no parent");
        assert!(!blobs.is_empty() && !snap.pack.is_empty());
        let files = files_of(dir, &snap.tree);
        assert_eq!(
            files,
            [".gitignore", "a.txt", "b.txt"].map(String::from).into(),
            "untracked taken, ignored left out"
        );
        assert_eq!(
            person(dir, &["show", &format!("{}:a.txt", snap.tree)]),
            "one, changed",
            "the work tree's bytes, not the index's"
        );
        assert_eq!(
            person(dir, &["rev-parse", &format!("refs/hive/{SID}/head")]),
            snap.commit
        );
        assert_eq!(
            person(dir, &["rev-list", "--parents", "-n", "1", &snap.commit]),
            snap.commit,
            "no parent"
        );
        assert_eq!(
            person(dir, &["log", "-1", "--format=%an <%ae>", &snap.commit]),
            "Roomler Hive <hive@roomler.invalid>"
        );
        assert_eq!(std::fs::read(git_dir.join("index")).unwrap(), index_before);
        assert_eq!(person(dir, &["status", "--porcelain"]), status_before);
        assert_eq!(
            person(dir, &["for-each-ref", "refs/heads"]),
            branches_before
        );
        assert_eq!(person(dir, &["rev-parse", "HEAD"]), head_before);
    }

    /// A later checkpoint is the last one's child, its pack is thin against it,
    /// and a repository that applies the packs in order holds the tree; the
    /// thin pack alone does not resolve. A turn that changed nothing writes no
    /// commit.
    #[test]
    fn later_checkpoints_chain_their_packs_are_thin_and_an_idle_turn_writes_nothing() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let dir = tmp.path();
        let state = tempfile::tempdir().unwrap();
        let git = Git::on_path();
        let big: String = (0..2000).map(|i| format!("line {i}\n")).collect();
        write(dir, "big.txt", &big);
        let (one, b1) = taken(checkpoint(&git, dir, state.path(), SID, 1, 1, None));
        write(dir, "big.txt", &format!("{big}one more\n"));
        let (two, b2) = taken(checkpoint(&git, dir, state.path(), SID, 2, 2, Some(&one)));
        assert_eq!(two.base.as_deref(), Some(one.commit.as_str()));
        assert_eq!(
            person(dir, &["rev-parse", &format!("{}^", two.commit)]),
            one.commit
        );
        let (pack1, pack2) = (b1.concat(), b2.concat());
        assert!(
            pack2.len() < pack1.len(),
            "thin: {} vs {}",
            pack2.len(),
            pack1.len()
        );

        // A member's target applies them in order (P2b-4's shape).
        let target = tempfile::tempdir().unwrap();
        person(target.path(), &["init", "-q", "--bare"]);
        for pack in [&pack1, &pack2] {
            let mut c = Command::new("git");
            c.current_dir(target.path())
                .args(["index-pack", "--stdin", "--fix-thin"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            for var in GIT_ENV {
                c.env_remove(var);
            }
            let mut child = c.spawn().unwrap();
            child.stdin.take().unwrap().write_all(pack).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert_eq!(files_of(target.path(), &two.tree), files_of(dir, &two.tree));
        assert_eq!(
            person(target.path(), &["show", &format!("{}:big.txt", two.tree)]),
            format!("{big}one more").trim_end()
        );

        // The thin pack alone does not resolve: it is thin.
        let alone = tempfile::tempdir().unwrap();
        person(alone.path(), &["init", "-q", "--bare"]);
        let mut c = Command::new("git");
        c.current_dir(alone.path())
            .args(["index-pack", "--stdin", "--fix-thin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for var in GIT_ENV {
            c.env_remove(var);
        }
        let mut child = c.spawn().unwrap();
        child.stdin.take().unwrap().write_all(&pack2).unwrap();
        assert!(
            !child.wait().unwrap().success(),
            "a thin pack needs its base"
        );

        let (three, b3) = taken(checkpoint(&git, dir, state.path(), SID, 3, 3, Some(&two)));
        assert_eq!(three.commit, two.commit, "no commit for an idle turn");
        assert!(three.pack.is_empty() && b3.is_empty());
    }

    /// A folder inside a repository takes only its own subtree, with the
    /// repository's ignores still honoured; nothing outside it is in the pack.
    #[test]
    fn a_folder_inside_a_repository_takes_only_its_subtree() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        person(dir, &["init", "-q"]);
        write(dir, "top.txt", "outside the session\n");
        write(dir, ".gitignore", "*.env\n");
        write(dir, "sub/x.txt", "inside\n");
        person(dir, &["add", "-A"]);
        person(dir, &["commit", "-q", "-m", "first"]);
        write(dir, "sub/secret.env", "TOKEN=x\n");
        write(dir, "sub/y.txt", "new inside\n");
        let state = tempfile::tempdir().unwrap();
        let (snap, blobs) = taken(checkpoint(
            &Git::on_path(),
            &dir.join("sub"),
            state.path(),
            SID,
            1,
            1,
            None,
        ));
        assert_eq!(snap.prefix, "sub/");
        assert_eq!(
            files_of(dir, &snap.tree),
            ["x.txt", "y.txt"].map(String::from).into()
        );
        let pack = blobs.concat();
        assert!(
            !pack.windows(19).any(|w| w == b"outside the session"),
            "nothing outside the folder"
        );
    }

    /// A folder in no repository gets a shadow in the session's state
    /// directory, and nothing is written into the folder.
    #[test]
    fn a_folder_in_no_repository_gets_a_shadow() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let folder = tempfile::tempdir().unwrap();
        write(folder.path(), "f.txt", "plain\n");
        let state = tempfile::tempdir().unwrap();
        // Discovery stops above the temp directory, so a repository around it
        // (a dotfiles checkout of a home directory) cannot claim the folder.
        let git = Git::under(folder.path().parent().unwrap());
        let (snap, _) = taken(checkpoint(
            &git,
            folder.path(),
            state.path(),
            SID,
            1,
            1,
            None,
        ));
        assert_eq!(snap.repo, RepoKind::Shadow);
        assert!(state.path().join("shadow.git/HEAD").is_file());
        assert!(
            !folder.path().join(".git").exists(),
            "nothing written into the folder"
        );
        let shadow = state.path().join("shadow.git");
        let listed = person(&shadow, &["ls-tree", "-r", "--name-only", &snap.tree]);
        assert_eq!(listed, "f.txt");
    }

    /// A lock a git left on the checkpoint's own index, ended before it could
    /// remove it, is cleared once it is older than any checkpoint runs; a
    /// younger one is a checkpoint still running, and the add refuses.
    #[test]
    fn a_stale_lock_on_the_checkpoints_index_is_cleared_and_a_live_one_kept() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let dir = tmp.path();
        let state = tempfile::tempdir().unwrap();
        let git_dir = PathBuf::from(person(dir, &["rev-parse", "--absolute-git-dir"]));
        let lock = git_dir.join(format!("hive-{SID}.index.lock"));
        std::fs::write(&lock, b"").unwrap();
        match checkpoint(&Git::on_path(), dir, state.path(), SID, 1, 1, None) {
            Outcome::Skipped(why) => assert!(why.starts_with("git add failed"), "{why}"),
            other => panic!("a live lock is kept: {other:?}"),
        }
        assert!(lock.exists());
        let old = std::time::SystemTime::now() - STALE_LOCK - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        taken(checkpoint(
            &Git::on_path(),
            dir,
            state.path(),
            SID,
            1,
            1,
            None,
        ));
        assert!(!lock.exists(), "cleared, and git let go of its own");
    }

    /// Every file under `dir` but its `.git`, by `/`-separated path. A move
    /// keeps git's tree, not the bytes (design §6.3): a Windows checkout ends
    /// its lines as its git is configured to, so lines compare as LF there.
    fn work_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().into_string().unwrap();
                if rel.is_empty() && name == ".git" {
                    continue;
                }
                let r = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}/{name}")
                };
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), &r, out);
                } else {
                    let bytes = std::fs::read(e.path()).unwrap();
                    let bytes = if cfg!(windows) {
                        String::from_utf8_lossy(&bytes)
                            .replace("\r\n", "\n")
                            .into_bytes()
                    } else {
                        bytes
                    };
                    out.insert(r, bytes);
                }
            }
        }
        let mut out = BTreeMap::new();
        if dir.exists() {
            walk(dir, "", &mut out);
        }
        out
    }

    /// What `hive-materialize` does with a workspace's packs, the last
    /// checkpoint being `last`: the packs in, the tree held to, the folder
    /// judged and switched.
    fn materialize_into(
        git: &Git,
        folder: &Path,
        state: &Path,
        packs: &[&[u8]],
        last: &WorkspaceSnap,
    ) -> Result<RepoKind, String> {
        let place = place_for(git, folder, state)?;
        for pack in packs {
            index_pack(git, &place, &mut &pack[..], pack.len() as u64)?;
        }
        assert_eq!(tree_of(git, &place, &last.commit)?, last.tree);
        let current = judge(git, &place, SID, &last.tree)?;
        switch(git, &place, SID, &current, &last.tree, &last.commit)?;
        Ok(place.kind())
    }

    /// P2b-4b — a shadow's checkpoints, put into a folder that is not there
    /// yet, give the folder back; the next checkpoint's pack, thin against the
    /// last, moves it on, because what it holds is what the session left.
    #[test]
    fn a_shadow_materializes_into_a_missing_folder_and_moves_on_with_the_next() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let root = tempfile::tempdir().unwrap();
        let git = Git::under(root.path());
        let src = root.path().join("src");
        write(&src, "a.txt", "one\n");
        write(&src, "sub/b.txt", "bee\n");
        let src_state = root.path().join("src-state");
        let (one, p1) = taken(checkpoint(&git, &src, &src_state, SID, 1, 1, None));
        write(&src, "a.txt", "one, changed\n");
        std::fs::remove_file(src.join("sub/b.txt")).unwrap();
        write(&src, "c.txt", "sea\n");
        let (two, p2) = taken(checkpoint(&git, &src, &src_state, SID, 2, 2, Some(&one)));
        let (p1, p2) = (p1.concat(), p2.concat());

        let dst = root.path().join("dst");
        let dst_state = root.path().join("dst-state");
        let kind = materialize_into(&git, &dst, &dst_state, &[&p1, &p2], &two).unwrap();
        assert_eq!(kind, RepoKind::Shadow);
        assert_eq!(work_files(&dst), work_files(&src));
        let shadow = dst_state.join("shadow.git");
        assert_eq!(
            person(&shadow, &["rev-parse", &format!("refs/hive/{SID}/head")]),
            two.commit
        );

        write(&src, "d.txt", "dee\n");
        let (three, p3) = taken(checkpoint(&git, &src, &src_state, SID, 3, 3, Some(&two)));
        materialize_into(&git, &dst, &dst_state, &[&p3.concat()], &three).unwrap();
        assert_eq!(work_files(&dst), work_files(&src), "moved on");
    }

    /// P2b-4b — into a clean clone of the same repository, the session's
    /// changes land in the work tree, tracked and untracked, and the person's
    /// `HEAD`, branches and index stay as they were.
    #[test]
    fn a_clean_clone_is_switched_and_the_persons_head_and_index_stay() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let src = tmp.path();
        write(src, "a.txt", "one, changed\n");
        write(src, "b.txt", "new\n");
        let src_state = tempfile::tempdir().unwrap();
        let (snap, pack) = taken(checkpoint(
            &Git::on_path(),
            src,
            src_state.path(),
            SID,
            1,
            1,
            None,
        ));

        let parent = tempfile::tempdir().unwrap();
        person(
            parent.path(),
            &["clone", "-q", &src.display().to_string(), "clone"],
        );
        let dst = parent.path().join("clone");
        let git_dir = PathBuf::from(person(&dst, &["rev-parse", "--absolute-git-dir"]));
        let head = person(&dst, &["rev-parse", "HEAD"]);
        let index = std::fs::read(git_dir.join("index")).unwrap();
        let branches = person(&dst, &["for-each-ref", "refs/heads"]);
        let dst_state = tempfile::tempdir().unwrap();
        let kind = materialize_into(
            &Git::on_path(),
            &dst,
            dst_state.path(),
            &[&pack.concat()],
            &snap,
        )
        .unwrap();
        assert_eq!(kind, RepoKind::Own);
        assert_eq!(work_files(&dst), work_files(src));
        assert_eq!(person(&dst, &["rev-parse", "HEAD"]), head);
        assert_eq!(std::fs::read(git_dir.join("index")).unwrap(), index);
        assert_eq!(person(&dst, &["for-each-ref", "refs/heads"]), branches);
        assert_eq!(
            person(&dst, &["rev-parse", &format!("refs/hive/{SID}/head")]),
            snap.commit
        );
    }

    /// Text that compresses poorly: a pack holding it is not mistaken for one
    /// that does not.
    fn noise(seed: u64, lines: usize) -> String {
        let mut x = seed;
        (0..lines)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                format!("{x:016x}\n")
            })
            .collect()
    }

    /// How many objects a pack says it holds: its header's third word.
    fn objects_in(pack: &[u8]) -> u32 {
        assert_eq!(&pack[..4], b"PACK", "a pack");
        u32::from_be_bytes(pack[8..12].try_into().unwrap())
    }

    /// P2f-2a — a pack against the clone's `HEAD` holds only what the session
    /// changed: a large file it never touched stays out, the pack is a
    /// fraction of the whole one, and put into the clone it still gives the
    /// checkpoint's tree back.
    #[test]
    fn a_pack_against_a_clones_head_holds_only_the_sessions_changes() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let src = tmp.path();
        write(src, "big.txt", &noise(7, 20_000));
        person(src, &["add", "-A"]);
        person(src, &["commit", "-q", "-m", "big"]);
        let head = person(src, &["rev-parse", "HEAD"]);
        write(src, "a.txt", "one, changed\n");
        write(src, "b.txt", "new\n");
        let src_state = tempfile::tempdir().unwrap();
        let git = Git::on_path();
        let (snap, whole) = taken(checkpoint(&git, src, src_state.path(), SID, 1, 1, None));
        assert_eq!(snap.head.as_deref(), Some(head.as_str()));
        assert!(snap.base.is_none(), "the first checkpoint's pack is whole");
        let whole = whole.concat();

        let unknown = "0".repeat(40);
        let (thin, against) = pack_against(
            &git,
            src,
            src_state.path(),
            &snap.commit,
            &[unknown, head.clone()],
        )
        .unwrap();
        assert_eq!(against, vec![head.clone()], "against what it holds, only");
        // The commit, its tree and the two files the session wrote; the whole
        // pack has `.gitignore` and `big.txt` too.
        assert_eq!((objects_in(&thin), objects_in(&whole)), (4, 6));
        assert!(
            thin.len() * 50 < whole.len(),
            "thin {} bytes, whole {}",
            thin.len(),
            whole.len()
        );

        // `--no-local`: a clone from a path otherwise takes the whole object
        // store, the checkpoint's commit with it, which no clone from a
        // remote does.
        let parent = tempfile::tempdir().unwrap();
        person(
            parent.path(),
            &[
                "clone",
                "-q",
                "--no-local",
                &src.display().to_string(),
                "clone",
            ],
        );
        let dst = parent.path().join("clone");
        let dst_state = tempfile::tempdir().unwrap();
        assert_eq!(
            holds(
                &git,
                &dst,
                dst_state.path(),
                &[snap.commit.clone(), head.clone()]
            )
            .unwrap(),
            vec![head],
            "the clone holds the person's HEAD, not the checkpoint"
        );
        let kind = materialize_into(&git, &dst, dst_state.path(), &[&thin], &snap).unwrap();
        assert_eq!(kind, RepoKind::Own);
        assert_eq!(work_files(&dst), work_files(src));
    }

    /// P2f-2a — against nothing the session's repository holds, the pack is
    /// whole: it brings the checkpoint into a folder that holds nothing.
    #[test]
    fn a_pack_against_nothing_held_is_whole() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let src = tmp.path();
        write(src, "a.txt", "one, changed\n");
        let src_state = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let git = Git::under(root.path());
        let (snap, _) = taken(checkpoint(&git, src, src_state.path(), SID, 1, 1, None));
        let (pack, against) =
            pack_against(&git, src, src_state.path(), &snap.commit, &["f".repeat(40)]).unwrap();
        assert!(against.is_empty(), "{against:?}");
        let dst = root.path().join("dst");
        let kind =
            materialize_into(&git, &dst, &root.path().join("dst-state"), &[&pack], &snap).unwrap();
        assert_eq!(kind, RepoKind::Shadow);
        assert_eq!(work_files(&dst), work_files(src));
    }

    /// P2f-2a — `holds` names only the commits the folder's repository holds,
    /// in the order asked and each once; a missing folder, or one in no
    /// repository with no shadow yet, holds none and gets none made; and a
    /// name that is not a commit id is refused before any git sees it.
    #[test]
    fn holds_names_only_held_commits_makes_nothing_and_refuses_what_is_no_id() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let dir = tmp.path();
        let head = person(dir, &["rev-parse", "HEAD"]);
        let tree = person(dir, &["rev-parse", "HEAD^{tree}"]);
        let state = tempfile::tempdir().unwrap();
        let git = Git::on_path();
        let asked = ["1".repeat(40), head.clone(), head.clone(), tree];
        assert_eq!(
            holds(&git, dir, state.path(), &asked).unwrap(),
            vec![head.clone()],
            "a tree is no commit, and each is named once"
        );

        let root = tempfile::tempdir().unwrap();
        let under = Git::under(root.path());
        let plain = root.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        let plain_state = root.path().join("plain-state");
        assert!(
            holds(&under, &plain, &plain_state, std::slice::from_ref(&head))
                .unwrap()
                .is_empty()
        );
        assert!(!plain_state.exists(), "no shadow made");
        // P2f-2b — the folder's own `HEAD`, one more have to offer; none for
        // a folder in no repository, and nothing made for asking.
        assert_eq!(
            head_of(&git, dir, state.path()).unwrap(),
            Some(head.clone()),
            "a repository's own HEAD"
        );
        assert_eq!(head_of(&under, &plain, &plain_state).unwrap(), None);
        assert!(!plain_state.exists(), "no shadow made for its HEAD either");
        let missing = root.path().join("missing");
        assert_eq!(head_of(&under, &missing, &plain_state).unwrap(), None);
        assert!(
            holds(&under, &missing, &plain_state, std::slice::from_ref(&head))
                .unwrap()
                .is_empty()
        );

        for bad in [
            "HEAD".to_string(),
            "--all".to_string(),
            "A".repeat(40),
            format!("^{}", &head[..39]),
            head[..39].to_string(),
        ] {
            match holds(&git, dir, state.path(), std::slice::from_ref(&bad)) {
                Err(e) => assert!(e.contains("is not a commit id"), "{bad}: {e}"),
                Ok(held) => panic!("{bad:?} was taken as a commit id: {held:?}"),
            }
        }
        let many = vec![head.clone(); MAX_HAVES + 1];
        assert!(
            holds(&git, dir, state.path(), &many)
                .unwrap_err()
                .contains("more than")
        );
        let err = pack_against(&git, dir, state.path(), "HEAD", &[]).unwrap_err();
        assert!(err.contains("is not a commit id"), "{err}");
        let err = pack_against(&git, dir, state.path(), &"2".repeat(40), &[]).unwrap_err();
        assert!(err.contains("holds no commit"), "{err}");
    }

    /// P2f-2d — a teleport's folder may take the copy when it is missing,
    /// empty, a clean clone (exactly what its `HEAD` holds, ignored files
    /// aside), or what this session last left there; not when it holds work
    /// of its own: a change, an untracked file, or, in no repository, any
    /// file. Asking makes nothing for a folder in no repository.
    #[test]
    fn a_folder_takes_a_copy_only_when_it_holds_no_work_of_its_own() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let sid = "6acd9709a3dd4cf606f6c38c";
        let tmp = repo_with_a_commit();
        let dir = tmp.path();
        let state = tempfile::tempdir().unwrap();
        let git = Git::on_path();
        let takes = |d: &Path| takes_a_copy(&git, d, state.path(), sid).unwrap();
        assert_eq!(takes(dir), None, "a clean clone");
        write(dir, "secret.env", "ignored\n");
        assert_eq!(takes(dir), None, "an ignored file is no work of its own");
        write(dir, "a.txt", "one, changed\n");
        assert!(
            takes(dir).is_some_and(|w| w.contains("neither what its HEAD holds")),
            "a change"
        );
        write(dir, "a.txt", "one\n");
        write(dir, "new.txt", "the person's\n");
        assert!(takes(dir).is_some(), "an untracked file");
        std::fs::remove_file(dir.join("new.txt")).unwrap();
        assert_eq!(takes(dir), None, "clean again");
        // What this session last left in it: a member that ran it here.
        write(dir, "a.txt", "the session's\n");
        assert!(matches!(
            checkpoint(&git, dir, state.path(), sid, 1, 1, None),
            Outcome::Taken { .. }
        ));
        assert_eq!(takes(dir), None, "what this session last left there");
        write(dir, "a.txt", "and then the person's\n");
        assert!(takes(dir).is_some(), "past it");

        let root = tempfile::tempdir().unwrap();
        let under = Git::under(root.path());
        let plain_state = root.path().join("plain-state");
        let plain = |d: &Path| takes_a_copy(&under, d, &plain_state, sid).unwrap();
        assert_eq!(plain(&root.path().join("missing")), None, "missing");
        let empty = root.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(plain(&empty), None, "empty");
        assert!(!plain_state.exists(), "no shadow made for asking");
        let files = root.path().join("files");
        std::fs::create_dir_all(&files).unwrap();
        write(&files, "theirs.txt", "someone's own\n");
        assert!(
            plain(&files).is_some_and(|w| w.contains("no repository")),
            "files in no repository"
        );
        assert!(!plain_state.exists(), "nor for a folder that holds files");
    }

    /// P2b-4b — a folder inside a repository takes back only its own subtree;
    /// everything outside it in the clone stays as it was.
    #[test]
    fn a_folder_inside_a_repository_takes_back_only_its_subtree() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path();
        person(src, &["init", "-q"]);
        write(src, "top.txt", "outside the session\n");
        write(src, "sub/x.txt", "inside\n");
        write(src, "sub/gone.txt", "to be removed\n");
        person(src, &["add", "-A"]);
        person(src, &["commit", "-q", "-m", "first"]);
        write(src, "sub/x.txt", "inside, changed\n");
        write(src, "sub/y.txt", "new inside\n");
        std::fs::remove_file(src.join("sub/gone.txt")).unwrap();
        let src_state = tempfile::tempdir().unwrap();
        let (snap, pack) = taken(checkpoint(
            &Git::on_path(),
            &src.join("sub"),
            src_state.path(),
            SID,
            1,
            1,
            None,
        ));
        assert_eq!(snap.prefix, "sub/");

        let parent = tempfile::tempdir().unwrap();
        person(
            parent.path(),
            &["clone", "-q", &src.display().to_string(), "clone"],
        );
        let dst = parent.path().join("clone");
        write(&dst, "top.txt", "the person's own, outside the folder\n");
        let dst_state = tempfile::tempdir().unwrap();
        materialize_into(
            &Git::on_path(),
            &dst.join("sub"),
            dst_state.path(),
            &[&pack.concat()],
            &snap,
        )
        .unwrap();
        assert_eq!(work_files(&dst.join("sub")), work_files(&src.join("sub")));
        assert_eq!(
            std::fs::read_to_string(dst.join("top.txt")).unwrap(),
            "the person's own, outside the folder\n",
            "outside the folder, nothing moves"
        );
    }

    /// P2b-4b — a folder holding work of its own, neither its `HEAD`'s nor
    /// this session's, is refused, and left as it was.
    #[test]
    fn a_folder_with_work_of_its_own_is_refused_and_left_as_it_was() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let tmp = repo_with_a_commit();
        let src = tmp.path();
        write(src, "a.txt", "the session's\n");
        let src_state = tempfile::tempdir().unwrap();
        let (snap, pack) = taken(checkpoint(
            &Git::on_path(),
            src,
            src_state.path(),
            SID,
            1,
            1,
            None,
        ));
        let pack = pack.concat();

        let parent = tempfile::tempdir().unwrap();
        person(
            parent.path(),
            &["clone", "-q", &src.display().to_string(), "clone"],
        );
        let dst = parent.path().join("clone");
        write(&dst, "a.txt", "the person's own\n");
        let dst_state = tempfile::tempdir().unwrap();
        let e =
            materialize_into(&Git::on_path(), &dst, dst_state.path(), &[&pack], &snap).unwrap_err();
        assert!(e.contains("work of its own"), "{e}");
        assert_eq!(
            std::fs::read_to_string(dst.join("a.txt")).unwrap(),
            "the person's own\n"
        );

        // A folder in no repository, holding files that are not the session's.
        let other = tempfile::tempdir().unwrap();
        let folder = other.path().join("folder");
        write(&folder, "notes.txt", "someone else's\n");
        let git = Git::under(other.path());
        let e = materialize_into(&git, &folder, &other.path().join("state"), &[&pack], &snap)
            .unwrap_err();
        assert!(e.contains("work of its own"), "{e}");
        assert_eq!(
            work_files(&folder).keys().collect::<Vec<_>>(),
            ["notes.txt"]
        );
    }

    /// P2b-4b — a folder whose git cannot give the tree back is said to, and
    /// the session's ref is not moved: here a blob with CRLF line ends, into a
    /// repository that turns them into LF as it reads (`core.autocrlf=input`).
    /// (Unix: on Windows the source's own git would have turned them already.)
    #[cfg(unix)]
    #[test]
    fn a_folder_that_cannot_hold_the_tree_is_said_to_and_its_ref_stays() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let src = tempfile::tempdir().unwrap();
        person(src.path(), &["init", "-q"]);
        person(src.path(), &["config", "core.autocrlf", "false"]);
        write(src.path(), "dos.txt", "one\r\ntwo\r\n");
        let state = tempfile::tempdir().unwrap();
        let (snap, pack) = taken(checkpoint(
            &Git::on_path(),
            src.path(),
            state.path(),
            SID,
            1,
            1,
            None,
        ));

        let dst = tempfile::tempdir().unwrap();
        person(dst.path(), &["init", "-q"]);
        person(dst.path(), &["config", "core.autocrlf", "input"]);
        let dst_state = tempfile::tempdir().unwrap();
        let e = materialize_into(
            &Git::on_path(),
            dst.path(),
            dst_state.path(),
            &[&pack.concat()],
            &snap,
        )
        .unwrap_err();
        assert!(e.contains("after the switch"), "{e}");
        let ours = cmd(&Git::on_path(), dst.path(), None, None)
            .args([
                "rev-parse",
                "--verify",
                "-q",
                &format!("refs/hive/{SID}/head"),
            ])
            .output()
            .unwrap();
        assert!(!ours.status.success(), "the ref is not moved");
    }

    /// P2c — a folder holding more than one checkpoint can take is skipped at
    /// once, in words, before anything is hashed; at the limits it is taken as
    /// ever, and what it already holds, or ignores, counts for nothing. (The
    /// limits made small here; the real ones are 20,000 files and 512 MiB.)
    #[test]
    fn a_folder_too_big_for_one_checkpoint_is_skipped_at_once() {
        if !have_git() {
            return eprintln!("no git here");
        }
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("work");
        for i in 0..5 {
            write(&folder, &format!("f{i}.txt"), "x\n");
        }
        let state = root.path().join("state");
        let skipped = |o: Outcome| match o {
            Outcome::Skipped(why) => why,
            other => panic!("taken: {other:?}"),
        };
        let git = Git::under(root.path()).with_new_limits(4, u64::MAX);
        let why = skipped(checkpoint(&git, &folder, &state, SID, 1, 1, None));
        assert!(why.contains("more than one checkpoint takes"), "{why}");
        assert!(why.contains(".gitignore"), "{why}");
        let git = Git::under(root.path()).with_new_limits(5, u64::MAX);
        let (one, _) = taken(checkpoint(&git, &folder, &state, SID, 1, 1, None));

        // Only what the index does not have yet counts: one new file, by its
        // bytes.
        write(&folder, "big.txt", "more than ten bytes\n");
        let git = Git::under(root.path()).with_new_limits(5, 10);
        let why = skipped(checkpoint(&git, &folder, &state, SID, 2, 2, Some(&one)));
        assert!(why.contains("more than one checkpoint takes"), "{why}");

        // An ignored file counts for nothing.
        let tmp = repo_with_a_commit();
        write(tmp.path(), "secret.env", &"x".repeat(100));
        let git = Git::on_path().with_new_limits(5, 10);
        let src_state = tempfile::tempdir().unwrap();
        taken(checkpoint(
            &git,
            tmp.path(),
            src_state.path(),
            SID,
            1,
            1,
            None,
        ));
    }

    /// No `git`, or a session id that is not one, skips the workspace in words.
    #[test]
    fn no_git_or_a_bad_id_skips_the_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = Git::at(tmp.path().join("no-such-git"));
        match checkpoint(&missing, tmp.path(), tmp.path(), SID, 1, 1, None) {
            Outcome::Skipped(why) => assert_eq!(why, "git was not found"),
            other => panic!("{other:?}"),
        }
        match checkpoint(
            &Git::on_path(),
            tmp.path(),
            tmp.path(),
            "../etc",
            1,
            1,
            None,
        ) {
            Outcome::Skipped(why) => assert!(why.contains("not a session id"), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}
