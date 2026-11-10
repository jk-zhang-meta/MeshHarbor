// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-4c-2 — `vault_render`: a template written into the session's
//! secrets directory with values from the vault, for as long as its leases.
//!
//! | Step | What holds |
//! |---|---|
//! | the call | `template` (at most 64 KiB, `{{ handle }}` placeholders naming 1 to 8 secrets), `dest` (a bare file name), `ttl_s` (30 to 900, default 300) |
//! | the leases | one per secret, mode `file`, audience the file's name: `prod-never-materializes` and `windows-proxy-only` refuse what they refuse, recorded. P3-6b-2b — a dynamic secret's placeholders share one lease in `short-lived` and the credential minted for it, the file living with that lease too |
//! | the directory | `<runtime>/<session>/secrets/`, the daemon's own, `0711`: the session's account opens a file whose name it knows, and lists nothing |
//! | the file | written whole (a temporary, then a rename), `0600`, handed to the session's account |
//! | its life | removed whenever its first lease is let go (its expiry, `rc:vault.revoke`, the run's end); every one an earlier process left, at the daemon's start |
//!
//! ⚠️ `file` is a MATERIALIZING mode (design §8.5): the session's account
//! reads the file, which is what it is for. The session's settings deny
//! Claude Code's Read tool there, which is UX, not a boundary: Bash can still
//! print it. Hence the permit and a person's approval of every call.

use bson::oid::ObjectId;
use serde_json::Value;
use zeroize::Zeroizing;

use super::toolbelt::VaultTools;
use super::vault_exec::{ExecTarget, Handle, Releasing, Use, handle_of, leased_values};

/// The largest template, and the largest file it may render to.
const MAX_TEMPLATE: usize = 64 * 1024;
#[cfg(unix)]
const MAX_RENDERED: usize = 256 * 1024;
/// The most secrets one template names.
const MAX_HANDLES: usize = 8;
/// How long a file lives when its call names no TTL.
const DEFAULT_TTL: u32 = 300;

/// The session's secrets directory, under its runtime directory.
#[cfg(unix)]
pub(crate) const SECRETS_DIR: &str = "secrets";

/// A piece of a template: its own text, or the value of its `n`th secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) enum Piece {
    Text(String),
    Value(usize),
}

/// One `vault_render` call, checked. Its pieces are rendered only where a
/// file is written (Unix).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct RenderRequest {
    pub(crate) pieces: Vec<Piece>,
    /// The distinct secrets, in the order they first appear.
    pub(crate) handles: Vec<Handle>,
    pub(crate) dest: String,
    pub(crate) ttl: u32,
}

/// Split a template into its text and its `{{ handle }}` placeholders. A
/// `{{` never closed is refused rather than kept as text: a placeholder the
/// writer meant would otherwise land in the file as written.
pub(crate) fn parse_template(t: &str) -> Result<(Vec<Piece>, Vec<Handle>), String> {
    let mut pieces = Vec::new();
    let mut handles: Vec<Handle> = Vec::new();
    let mut rest = t;
    while let Some(open) = rest.find("{{") {
        if open > 0 {
            pieces.push(Piece::Text(rest[..open].to_string()));
        }
        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .ok_or("a {{ is never closed: each placeholder is {{ a/secret }}")?;
        let handle = handle_of(after[..close].trim())?;
        let n = match handles.iter().position(|h| *h == handle) {
            Some(n) => n,
            None => {
                handles.push(handle);
                handles.len() - 1
            }
        };
        pieces.push(Piece::Value(n));
        rest = &after[close + 2..];
    }
    if !rest.is_empty() {
        pieces.push(Piece::Text(rest.to_string()));
    }
    if handles.is_empty() {
        return Err("the template names no secret: put each as {{ a/secret }}".into());
    }
    if handles.len() > MAX_HANDLES {
        return Err(format!("a template names at most {MAX_HANDLES} secrets"));
    }
    Ok((pieces, handles))
}

/// Check a call's arguments: what is refused here never reaches the vault.
pub(crate) fn parse(args: &Value) -> Result<RenderRequest, String> {
    use meshharbor_remote_control::vault::lease_limits::{MAX_TTL_SECS, MIN_TTL_SECS};
    let template = args
        .get("template")
        .and_then(Value::as_str)
        .ok_or("template is required")?;
    if template.len() > MAX_TEMPLATE || template.contains('\0') {
        return Err(format!(
            "a template is at most {MAX_TEMPLATE} bytes, and holds no NUL"
        ));
    }
    let dest = args
        .get("dest")
        .and_then(Value::as_str)
        .ok_or("dest is required: a file name")?;
    // A bare name, by the one rule the vault holds `exec_allow` to: never a
    // path, nothing a shell would read as a flag.
    if !meshharbor_remote_control::vault::program_name_ok(dest) {
        return Err(format!(
            "dest must be a bare file name (letters, digits, `.`, `_`, `+` or `-`, not \
             starting with `.` or `-`): got {dest:?}"
        ));
    }
    let ttl = match args.get("ttl_s") {
        None | Some(Value::Null) => DEFAULT_TTL,
        Some(v) => match v.as_u64().and_then(|s| u32::try_from(s).ok()) {
            Some(s) if (MIN_TTL_SECS..=MAX_TTL_SECS).contains(&s) => s,
            _ => {
                return Err(format!("ttl_s must be {MIN_TTL_SECS} to {MAX_TTL_SECS}"));
            }
        },
    };
    let (pieces, handles) = parse_template(template)?;
    Ok(RenderRequest {
        pieces,
        handles,
        dest: dest.to_string(),
        ttl,
    })
}

/// The template with each secret's value in place. The buffer is sized once,
/// up front: a vector that grew would leave copies of earlier values in the
/// memory it gave back, where nothing zeroes them.
#[cfg(unix)]
pub(crate) fn render(
    pieces: &[Piece],
    values: &[Zeroizing<Vec<u8>>],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let total: usize = pieces
        .iter()
        .map(|p| match p {
            Piece::Text(t) => t.len(),
            Piece::Value(n) => values[*n].len(),
        })
        .sum();
    if total > MAX_RENDERED {
        return Err(format!("the rendered file would pass {MAX_RENDERED} bytes"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    for p in pieces {
        match p {
            Piece::Text(t) => out.extend_from_slice(t.as_bytes()),
            Piece::Value(n) => out.extend_from_slice(&values[*n]),
        }
    }
    Ok(out)
}

/// `<session_dir>/secrets`, made if absent: the daemon's own, `0711`. A link
/// or anything but a directory in its place is refused, never followed.
#[cfg(unix)]
pub(crate) fn secrets_dir(session_dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = session_dir.join(SECRETS_DIR);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if !m.file_type().is_dir() => {
            return Err(format!("{} is not a plain directory", dir.display()));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// `dir/name`, written whole: a temporary made with `create_new` (a link in
/// its place is refused), `0600`, handed to `owner`, then renamed over the
/// name. Removed again if any step fails.
#[cfg(unix)]
pub(crate) fn write_file(
    dir: &std::path::Path,
    name: &str,
    bytes: &[u8],
    owner: Option<(u32, u32)>,
) -> Result<std::path::PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = dir.join(name);
    let tmp = dir.join(format!(".{name}.{:016x}", rand::random::<u64>()));
    let failed = |p: &std::path::Path, e: std::io::Error| format!("{}: {e}", p.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| failed(&tmp, e))?;
    let mut fill = || -> std::io::Result<()> {
        f.write_all(bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        Ok(())
    };
    let filled = fill();
    drop(f);
    if let Err(e) = filled {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed(&tmp, e));
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed(&path, e));
    }
    Ok(path)
}

/// Every secrets directory an earlier process left under `runtime_root`: no
/// lease outlives the process that held it (its key is new at each start),
/// so none of those files is anyone's any more. Answers how many went.
#[cfg(unix)]
pub(crate) fn sweep(runtime_root: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(runtime_root) else {
        return 0;
    };
    let mut gone = 0;
    for entry in entries.flatten() {
        let dir = entry.path().join(SECRETS_DIR);
        let is_dir = std::fs::symlink_metadata(&dir)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if is_dir && std::fs::remove_dir_all(&dir).is_ok() {
            gone += 1;
        }
    }
    gone
}

/// What a session's `vault_render` call answers: the file's path and how
/// long it lives, or why nothing was written.
pub(crate) async fn call(
    vault: &dyn VaultTools,
    session: ObjectId,
    fence: u64,
    target: Option<&ExecTarget>,
    args: &Value,
) -> Result<Value, String> {
    let req = parse(args)?;
    // The leases this call asks for itself: let go if nothing is written.
    let mut held = Releasing {
        vault,
        leases: Vec::with_capacity(req.handles.len()),
    };
    // P3-4c-3 — a lease asked for ahead toward this file, lasting at least as
    // long as the file is asked to, is taken as it is. P3-6b-2b — a dynamic
    // secret's placeholders share one lease and the credential minted for it.
    let labels: Vec<String> = req.handles.iter().map(Handle::to_string).collect();
    let handles: Vec<(&str, &Handle)> = labels
        .iter()
        .map(String::as_str)
        .zip(&req.handles)
        .collect();
    let to = Use {
        mode: "file",
        audience: &req.dest,
        ttl: req.ttl,
        covers: std::time::Duration::from_secs(u64::from(req.ttl)),
        before: "the file was written",
    };
    let (leases, values) = leased_values(vault, session, fence, &handles, &to, &mut held).await?;
    let path = write_with(target, &req, &values)?;
    // The file lives with its leases: whichever is let go first removes it.
    for lease in &leases {
        if !vault.attach(lease, &path) {
            let _ = std::fs::remove_file(&path);
            return Err("a lease ended before the file was handed over: it is removed".into());
        }
    }
    held.keep();
    // How long it lives: until the first of its leases ends.
    let ttl_s = leases
        .iter()
        .filter_map(|l| vault.left(l))
        .min()
        .map_or(0, |d| d.as_secs());
    // P3-4d-2 — the file holds these values: reported where the device's
    // owner has it report, by its name, never a value.
    vault.report(crate::vault::Report {
        session_id: session,
        fence,
        kind: meshharbor_remote_control::vault::VaultActivityKind::Render,
        lease_ids: leases,
        target: req.dest.clone(),
        exit_code: None,
        timed_out: false,
    });
    Ok(serde_json::json!({ "path": path.to_string_lossy(), "ttl_s": ttl_s }))
}

/// Render the checked call into its file.
#[cfg(unix)]
fn write_with(
    target: Option<&ExecTarget>,
    req: &RenderRequest,
    values: &[Zeroizing<Vec<u8>>],
) -> Result<std::path::PathBuf, String> {
    let target = target.ok_or("this device writes no file for a session")?;
    let dir = secrets_dir(&target.session_dir)?;
    let rendered = render(&req.pieces, values)?;
    write_file(&dir, &req.dest, &rendered, target.owner)
}

/// A Windows daemon never writes a materialized value: it has no sandbox for
/// one (AC13). The vault refuses `file` there first; this holds even if it
/// ever did not.
#[cfg(not(unix))]
fn write_with(
    _target: Option<&ExecTarget>,
    _req: &RenderRequest,
    _values: &[Zeroizing<Vec<u8>>],
) -> Result<std::path::PathBuf, String> {
    Err("this device has no sandbox for a value: it writes no file with one".into())
}

#[cfg(all(test, unix))]
mod tests;
