//! Same-user updates for ~/.local/bin installs. Never invokes a root helper.
//! The reviewed transaction owns stopping/restarting the EXISTING user unit,
//! observing its LocalAPI identity, and restoring all old bytes on failure.
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};
const WHEEL: &str = "tomli-2.2.1-py3-none-any.whl";
const WHEEL_SHA: &str = "cb55c73c5f4408779d0cf3eef9f762b9c9f147a77de7b258bef0a5628adc85cc";
const TRANSACTION: &str = include_str!("../../../scripts/linux-inplace-upgrade.py");

fn home() -> Option<PathBuf> {
    // Reentrant account lookup: daemon runtime threads must not share getpwuid's buffer.
    unsafe {
        let mut record: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 65536];
        if libc::getpwuid_r(
            libc::geteuid(),
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        ) != 0
            || result.is_null()
            || record.pw_dir.is_null()
        {
            return None;
        }
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(
            std::ffi::CStr::from_ptr(record.pw_dir).to_bytes(),
        )))
    }
}
fn is_local_install(uid: u32, home: &Path, exe: &Path) -> bool {
    uid != 0 && exe == home.join(".local/bin/meshharbord")
}
pub(super) fn current() -> bool {
    home()
        .zip(std::env::current_exe().ok())
        .is_some_and(|(home, exe)| is_local_install(unsafe { libc::geteuid() }, &home, &exe))
}
fn hash(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(path)?)))
}
fn owned_regular(path: &Path, uid: u32) -> Result<()> {
    let m = path.symlink_metadata()?;
    if !m.is_file() || m.uid() != uid || path.canonicalize()? != path {
        bail!("update path must be an exact owned regular file");
    }
    Ok(())
}
fn checked(status: std::process::ExitStatus, operation: &str) -> Result<()> {
    if !status.success() {
        bail!("{operation} failed ({status})");
    }
    Ok(())
}

fn extract_payload(archive: &Path, destination: &Path) -> Result<()> {
    const EXTRACT: &str = r#"import tarfile,pathlib,sys
with tarfile.open(sys.argv[1], 'r:gz') as t:
    members=t.getmembers()
    for m in members:
        p=pathlib.PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()):
            raise RuntimeError('unsafe signed archive member')
    t.extractall(sys.argv[2], members=members)
"#;
    checked(
        Command::new("/usr/bin/python3")
            .args(["-c", EXTRACT])
            .arg(archive)
            .arg(destination)
            .status()?,
        "validated archive extraction",
    )?;
    Ok(())
}

/// Returns after OS submission only. Completion is transaction/result.json,
/// not successful systemd-run submission. The source daemon stays alive until
/// the independent service has prepared and verified its complete recovery set.
pub(super) fn launch(archive: &Path, version: &str, config: &Path) -> Result<()> {
    if !current() {
        bail!("not a same-user local installation");
    }
    let uid = unsafe { libc::geteuid() };
    prune_stages(SystemTime::now());
    let binary = std::env::current_exe()?;
    owned_regular(&binary, uid)?;
    owned_regular(config, uid)?;
    owned_regular(archive, uid)?;
    // Recheck the cryptographic envelope BEFORE extraction, execution or handoff.
    let bytes = std::fs::read(archive)?;
    let asc = std::fs::read_to_string(archive.with_extension("gz.asc"))
        .context("verified artifact signature sidecar missing")?;
    crate::pgp_verify::verify_release_artifact(&bytes, &asc)?;
    crate::artifact_version::verify_artifact_version(archive, version)
        .context("same-user update requires strict artifact version binding")?;
    // Fail before staging if no user manager/transient service facility exists.
    checked(
        Command::new("/usr/bin/systemctl")
            .args(["--user", "show-environment"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?,
        "user manager probe",
    )?;
    let mut base = home().context("service account has no home")?;
    for component in [".local", "state", "meshharbor", "updates"] {
        base.push(component);
        match base.symlink_metadata() {
            Ok(meta) if meta.is_dir() && meta.uid() == uid && base.canonicalize()? == base => {}
            Ok(_) => bail!("untrusted user update directory"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&base)?,
            Err(e) => return Err(e.into()),
        }
    }
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
    let stage = tempfile::Builder::new()
        .prefix(STAGE_PREFIX)
        .tempdir_in(base)?
        .keep();
    // Until `systemd-run` has run, nothing but this function knows the stage
    // and the daemon is untouched, so a failure removes it. Without this a host
    // whose disk is full kept a ~500 MB stage per attempt.
    let mut unsubmitted = RemoveOnDrop(Some(stage.clone()));
    let saved_archive = stage.join("payload.tar.gz");
    std::fs::write(&saved_archive, &bytes)?;
    let unpacked = stage.join("payload");
    std::fs::create_dir(&unpacked)?;
    extract_payload(&saved_archive, &unpacked)?;
    let roots: Vec<_> = std::fs::read_dir(&unpacked)?.collect::<std::io::Result<Vec<_>>>()?;
    if roots.len() != 1 || !roots[0].file_type()?.is_dir() {
        bail!("expected one release payload root");
    }
    let payload = roots[0].path();
    let candidate = payload.join("usr/bin/meshharbord");
    owned_regular(&candidate, uid)?;
    let wheel = payload.join("usr/share/meshharbor/update").join(WHEEL);
    owned_regular(&wheel, uid)?;
    if hash(&wheel)? != WHEEL_SHA {
        bail!("pinned TOML wheel mismatch");
    }
    checked(Command::new("/usr/bin/python3").args(["-s", "-c", "import sys;sys.path.insert(0,sys.argv[1]);import tomli;assert tomli.__version__=='2.2.1'"]).arg(&wheel).status()?, "verified private TOML runtime probe")?;
    let libs = payload.join("usr/lib/meshharbor");
    if !libs.is_dir() || libs.canonicalize()? != libs {
        bail!("bundled library directory missing");
    }
    // Only signed candidate bytes are executed; this also checks their loader
    // and relative RPATH before stopping the original daemon.
    let result = Command::new(&candidate).arg("--version").output()?;
    checked(result.status, "candidate --version")?;
    let actual = String::from_utf8(result.stdout)?;
    let wanted = version
        .strip_prefix("agent-v")
        .or_else(|| version.strip_prefix('v'))
        .unwrap_or(version);
    if actual.trim() != format!("meshharbord {wanted}") {
        bail!("candidate executable version mismatch");
    }
    let script = stage.join("upgrade.py");
    std::fs::write(&script, TRANSACTION)?;
    let transaction = stage.join("transaction");
    let unit = format!(
        "meshharbor-local-update-{}",
        stage.file_name().unwrap().to_string_lossy()
    );
    let status = Command::new("/usr/bin/systemd-run")
        .args(["--user", "--collect", "--quiet", "--unit"])
        .arg(&unit)
        .args([
            "--property=Type=exec",
            "--property=UMask=0077",
            "--property=NoNewPrivileges=yes",
            "--property=TimeoutStartSec=infinity",
        ])
        .arg(format!(
            "--property=StandardOutput=append:{}",
            stage.join("run.log").display()
        ))
        .arg(format!(
            "--property=StandardError=append:{}",
            stage.join("run.log").display()
        ))
        .arg("/usr/bin/env")
        .arg(format!("PYTHONPATH={}", wheel.display()))
        .arg("PYTHONNOUSERSITE=1")
        .arg("/usr/bin/python3")
        .arg(&script)
        .args(["apply", "--scope", "user", "--binary"])
        .arg(&binary)
        .arg("--config")
        .arg(config)
        .arg("--candidate")
        .arg(&candidate)
        .arg("--old-sha")
        .arg(hash(&binary)?)
        .arg("--new-sha")
        .arg(hash(&candidate)?)
        .arg("--config-sha")
        .arg(hash(config)?)
        .arg("--transaction")
        .arg(&transaction)
        .arg("--library-source")
        .arg(&libs)
        .status()?;
    // From here the transaction may own the stage, even when `systemd-run`
    // reports a failure; `prune_stages` judges it later by what it wrote.
    unsubmitted.0 = None;
    checked(status, "independent same-user update service submission")?;
    tracing::info!(transaction=%transaction.display(), unit, "same-user update submitted, not yet verified; inspect result.json for activated/rolled_back/recovery_required");
    // If preparation fails before stop, this original daemon is still alive.
    // Do not leave prompts held forever merely because submission succeeded.
    let result_path = transaction.join("result.json");
    let _ = std::thread::Builder::new().name("user-update-result".into()).spawn(move || {
        for _ in 0..120 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if let Ok(raw) = std::fs::read(&result_path)
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw)
                && matches!(value.get("state").and_then(|v|v.as_str()), Some("activated" | "rolled_back" | "recovery_required")) {
                tracing::info!(state=?value.get("state"), result=%result_path.display(), "same-user update transaction reached terminal state");
                return;
            }
        }
        tracing::error!(result=%result_path.display(), "same-user update completion not observed; inspect transaction and run.log, submission is not success");
    });
    Ok(())
}

/// Name prefix of a stage under `~/.local/state/meshharbor/updates`.
const STAGE_PREFIX: &str = "update-";

/// A stage younger than this is never judged. [`launch`] hands each stage to
/// its transaction at once, and the transaction writes `prepared` within
/// seconds, before it stops anything; an hour is far past both.
const STAGE_SETTLE: Duration = Duration::from_secs(3600);

/// Removes the directory it holds when dropped, unless disarmed (`.0 = None`).
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take()
            && let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, dir = %dir.display(), "update: could not remove an unsubmitted stage");
        }
    }
}

/// What a stage's transaction last recorded (`scripts/linux-inplace-upgrade.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageState {
    /// No `result.json`. The transaction writes `prepared` before it stops the
    /// daemon, so it never did, and nothing in the stage is needed to recover.
    NeverPrepared,
    /// `activated`: the stage's `ROLLBACK.sh` restores the binary it replaced.
    Activated,
    /// `rolled_back`, by the transaction itself or later by `ROLLBACK.sh`.
    RolledBack,
    /// `prepared`, `failed`, `recovery_required` or unreadable: stopped part
    /// way, and the stage holds what a manual recovery needs. Never removed.
    Unfinished,
}

fn stage_state(stage: &Path) -> StageState {
    let transaction = stage.join("transaction");
    if transaction.join("rollback-result.json").exists() {
        return StageState::RolledBack;
    }
    let raw = match std::fs::read(transaction.join("result.json")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StageState::NeverPrepared,
        Err(_) => return StageState::Unfinished,
    };
    let value = serde_json::from_slice::<serde_json::Value>(&raw).ok();
    match value
        .as_ref()
        .and_then(|v| v.get("state"))
        .and_then(|s| s.as_str())
    {
        Some("activated") => StageState::Activated,
        Some("rolled_back") => StageState::RolledBack,
        _ => StageState::Unfinished,
    }
}

/// Remove the same-user update stages nothing needs any more. Each holds the
/// signed payload and a backup of every file it replaced (~500 MB), and before
/// this every update left one behind for good.
///
/// Kept: the newest `activated` stage (its `ROLLBACK.sh` is the way back from
/// the running binary), every unfinished one, any younger than
/// [`STAGE_SETTLE`], and any whose transaction lock is held (an apply or a
/// `ROLLBACK.sh` running now). Removed: older `activated`, `rolled_back` and
/// never-prepared stages. Best effort. Kill switch
/// `MESHHARBORD_UPDATE_STAGE_SWEEP=0`.
pub(super) fn prune_stages(now: SystemTime) {
    if !tunnel_core::env::flag("UPDATE_STAGE_SWEEP", true) {
        return;
    }
    let Some(base) = home().map(|h| h.join(".local/state/meshharbor/updates")) else {
        return;
    };
    let removed = prune_stages_in(&base, unsafe { libc::geteuid() }, now);
    if removed > 0 {
        tracing::info!(removed, dir = %base.display(), "update: removed finished same-user update stages");
    }
}

fn prune_stages_in(base: &Path, uid: u32, now: SystemTime) -> usize {
    // The same trust check `launch` applies before it writes here.
    match base.symlink_metadata() {
        Ok(meta)
            if meta.is_dir()
                && meta.uid() == uid
                && base.canonicalize().ok().as_deref() == Some(base) => {}
        _ => return 0,
    }
    let Ok(entries) = std::fs::read_dir(base) else {
        return 0;
    };
    let mut stages = Vec::new();
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(STAGE_PREFIX))
        {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = path.symlink_metadata() else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != uid {
            continue;
        }
        let settled = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= STAGE_SETTLE);
        let state = stage_state(&path);
        let activated_at = (state == StageState::Activated)
            .then(|| {
                std::fs::metadata(path.join("transaction/result.json")).and_then(|m| m.modified())
            })
            .and_then(Result::ok);
        stages.push((path, state, settled, activated_at));
    }
    let newest = stages
        .iter()
        .filter(|s| s.1 == StageState::Activated)
        .max_by_key(|s| s.3)
        .map(|s| s.0.clone());
    let mut removed = 0;
    for (path, state, settled, _) in stages {
        let finished = match state {
            StageState::Activated => Some(&path) != newest.as_ref(),
            StageState::RolledBack | StageState::NeverPrepared => true,
            StageState::Unfinished => false,
        };
        if !finished || !settled {
            continue;
        }
        // Held through the removal, so neither an apply nor a ROLLBACK.sh can
        // start on a half-removed stage.
        let lock = std::fs::File::open(path.join("transaction/lock")).ok();
        if lock.as_ref().is_some_and(|l| l.try_lock().is_err()) {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(error = %e, dir = %path.display(), "update: could not remove a finished stage")
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_user_update_scope_never_crosses_to_system_or_other_home() {
        let home = Path::new("/home/alice");
        assert!(is_local_install(
            1000,
            home,
            Path::new("/home/alice/.local/bin/meshharbord")
        ));
        assert!(!is_local_install(
            0,
            home,
            Path::new("/home/alice/.local/bin/meshharbord")
        ));
        assert!(!is_local_install(
            1000,
            home,
            Path::new("/usr/bin/meshharbord")
        ));
        assert!(!is_local_install(
            1000,
            home,
            Path::new("/home/bob/.local/bin/meshharbord")
        ));
    }
    #[test]
    fn same_user_update_rejects_unsigned_artifact() {
        assert!(
            crate::pgp_verify::verify_release_artifact(b"not a signed release", "not a signature")
                .is_err()
        );
    }
    #[test]
    fn same_user_update_archive_rejects_links_before_any_extraction() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("payload.tar.gz");
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let code = r#"import tarfile,io,sys
with tarfile.open(sys.argv[1],'w:gz') as t:
 m=tarfile.TarInfo('release/usr/bin/meshharbord');m.size=4;t.addfile(m,io.BytesIO(b'good'))
 m=tarfile.TarInfo('release/escape');m.type=tarfile.SYMTYPE;m.linkname='/tmp';t.addfile(m)
"#;
        assert!(
            Command::new("/usr/bin/python3")
                .args(["-c", code])
                .arg(&archive)
                .status()
                .unwrap()
                .success()
        );
        assert!(extract_payload(&archive, &out).is_err());
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }
    #[test]
    fn same_user_update_archive_accepts_regular_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("payload.tar.gz");
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let code = r#"import tarfile,io,sys
with tarfile.open(sys.argv[1],'w:gz') as t:
 m=tarfile.TarInfo('release/usr/bin/meshharbord');m.size=4;t.addfile(m,io.BytesIO(b'good'))
"#;
        assert!(
            Command::new("/usr/bin/python3")
                .args(["-c", code])
                .arg(&archive)
                .status()
                .unwrap()
                .success()
        );
        extract_payload(&archive, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("release/usr/bin/meshharbord")).unwrap(),
            b"good"
        );
    }

    fn stage(base: &Path, name: &str, state: Option<&str>) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(dir.join("payload")).unwrap();
        std::fs::write(dir.join("payload.tar.gz"), b"payload").unwrap();
        if let Some(state) = state {
            std::fs::create_dir(dir.join("transaction")).unwrap();
            std::fs::write(dir.join("transaction/lock"), b"").unwrap();
            std::fs::write(
                dir.join("transaction/result.json"),
                format!(r#"{{"state": "{state}"}}"#),
            )
            .unwrap();
        }
        dir
    }

    fn set_mtime(path: &Path, secs: u64) {
        std::fs::File::open(path)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn finished_update_stages_are_pruned_and_the_way_back_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let uid = unsafe { libc::geteuid() };
        let older = stage(&base, "update-older", Some("activated"));
        set_mtime(&older.join("transaction/result.json"), 1_000);
        let newer = stage(&base, "update-newer", Some("activated"));
        set_mtime(&newer.join("transaction/result.json"), 2_000);
        // Activated last, then undone by hand with its ROLLBACK.sh.
        let undone = stage(&base, "update-undone", Some("activated"));
        set_mtime(&undone.join("transaction/result.json"), 3_000);
        std::fs::write(
            undone.join("transaction/rollback-result.json"),
            br#"{"state": "rolled_back"}"#,
        )
        .unwrap();
        stage(&base, "update-rolled", Some("rolled_back"));
        stage(&base, "update-never", None);
        stage(&base, "update-recovery", Some("recovery_required"));
        stage(&base, "update-prepared", Some("prepared"));
        let busy = stage(&base, "update-busy", Some("rolled_back"));
        let held = std::fs::File::open(busy.join("transaction/lock")).unwrap();
        held.lock().unwrap();
        std::fs::create_dir(base.join("unrelated")).unwrap();

        assert_eq!(
            prune_stages_in(&base, uid, SystemTime::now()),
            0,
            "young stages are not judged"
        );
        let later = SystemTime::now() + STAGE_SETTLE + Duration::from_secs(60);
        assert_eq!(
            prune_stages_in(&base, uid + 1, later),
            0,
            "a base owned by another account"
        );
        assert_eq!(prune_stages_in(&base, uid, later), 4);
        let mut left: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "unrelated",
                "update-busy",
                "update-newer",
                "update-prepared",
                "update-recovery"
            ]
        );
        drop(held);
        assert_eq!(prune_stages_in(&base, uid, later), 1, "the lock released");
    }
}
