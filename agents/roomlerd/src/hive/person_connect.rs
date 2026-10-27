// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-9-2b — `meshharbor connect`'s endpoints, as this daemon holds them
//! for the LocalAPI connection that asked (`docs/vault.md` §23).
//!
//! The LocalAPI listener has read who asked from the OS and held them to
//! decision 26 before anything here runs ([`tunnel_core::localapi::peer_may_connect`]).
//! An endpoint opens for that account ([`Asker`]), its leases asked for the
//! device's owner (P3-9-1) and renewed while it is held (P3-9-2a). Its
//! connection reads it by id and lets it go when it closes (decision 25:
//! `meshharbor connect` in the foreground).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use serde_json::Value;
use tunnel_core::localapi::{Asker, ConnectArgs, EndpointState};

use super::toolbelt::VaultTools;
use super::vault_connect::{self, Control, DaemonPersonLeases, Person, PersonLeases, Timing};

/// Every person's endpoint this daemon holds, by id: each until the LocalAPI
/// connection that opened it closes, read by that connection meanwhile.
static HELD: LazyLock<Mutex<HashMap<u64, Control>>> = LazyLock::new(Default::default);

fn held() -> MutexGuard<'static, HashMap<u64, Control>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Open a person's endpoint for `asker` with `args`, over this daemon's lease
/// client: its id, and what the person is told.
pub(crate) async fn open(asker: &Asker, args: &ConnectArgs) -> Result<(u64, Value), String> {
    let vault = super::toolbelt::daemon_vault().ok_or(
        "this device lends no vault values: its owner has not turned its vault on \
         (vault_enabled), or it is not connected to its organization",
    )?;
    open_with(
        vault,
        Arc::new(DaemonPersonLeases),
        &super::supervisor::runtime_root(),
        asker,
        args,
        Timing::DAEMON,
    )
    .await
}

/// [`open`] over `vault` and `leases`, its directories under `runtime_root`.
pub(crate) async fn open_with(
    vault: Arc<dyn VaultTools>,
    leases: Arc<dyn PersonLeases>,
    runtime_root: &Path,
    asker: &Asker,
    args: &ConnectArgs,
    timing: Timing,
) -> Result<(u64, Value), String> {
    let args = serde_json::to_value(args).map_err(|e| format!("the request: {e}"))?;
    #[cfg(unix)]
    let (account, dir, owner) = match asker {
        Asker::Unix { uid, gid } => {
            runtime_dir(runtime_root)?;
            let dir = vault_connect::person_dir(runtime_root, *uid)?;
            (uid.to_string(), dir, (*uid, *gid))
        }
        Asker::Windows { .. } => return Err("an account named by SID asked a Unix daemon".into()),
    };
    #[cfg(unix)]
    let at = vault_connect::At {
        dir: &dir,
        owner: Some(owner),
    };
    #[cfg(windows)]
    let (account, at) = match asker {
        Asker::Windows { sid } => {
            let _ = runtime_root;
            (sid.clone(), vault_connect::At(sid))
        }
        Asker::Unix { .. } => return Err("an account named by uid asked a Windows daemon".into()),
    };
    let person = Person {
        leases,
        account,
        timing,
    };
    let (answer, control) = vault_connect::open_person(vault, person, at, &args).await?;
    let id = control.id;
    held().insert(id, control);
    Ok((id, answer))
}

/// Where endpoint `id` stands, while it is held.
pub(crate) fn state(id: u64) -> Option<EndpointState> {
    let s = held().get(&id)?.state();
    Some(EndpointState {
        left_s: s.left.as_secs(),
        renewals: s.renewals,
        refused: s.refused,
        closed: s.closed,
    })
}

/// The connection that opened endpoint `id` closed: close it, with every
/// connection it serves, and let its leases go.
pub(crate) fn release(id: u64) {
    if let Some(control) = held().remove(&id) {
        control.close("the command that held it ended");
    }
}

/// The daemon's runtime directory, made as a session's start makes it when
/// none has run since boot: the daemon's own, `0755`. A link or a file there
/// is refused, never followed.
#[cfg(unix)]
fn runtime_dir(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(root) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(format!("{} is not a plain directory", root.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("{}: {e}", root.display()))
        }
        Err(e) => Err(format!("{}: {e}", root.display())),
    }
}
