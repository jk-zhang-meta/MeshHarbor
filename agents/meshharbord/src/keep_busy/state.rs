// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 — the per-person store. Keep-busy outlives the session, the
//! daemon's self-updates and a reboot, until someone switches it off.
//!
//! **Per signed-in person**, not per device: it resumes at THAT person's next
//! login, and someone else signing in starts with it off — a device-wide flag
//! would start moving a stranger's mouse. It is also the only place every
//! worker identity can write: the machine-global config dir is hardened to
//! SYSTEM + Administrators, and the default Windows worker runs as the user.
//!
//! Never inside `config.toml`: that file is root/SYSTEM-owned on system
//! installs, is written under an in-process lock, is reported to the
//! server, and `adopt_local` would read every toggle as a config edit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::engine::{Activation, Settings};
use super::patterns::{Pattern, Size, Speed};

pub const FILE_NAME: &str = "keep-busy.json";
const VERSION: u32 = 1;

/// The file. Every field defaults, so a newer or older agent reads what it
/// understands; unknown keys survive a load/save (`extra`), so a downgrade
/// cannot erase a newer agent's state.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Stored {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub on: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_off_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_at_ms: Option<u64>,
    /// The last-known org deny per enrolled tenant (hex id), so a deny holds
    /// at boot, before the agent reaches the server.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub org_denied: BTreeMap<String, bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Stored {
    /// Record an activation (or its absence), keeping what else the file
    /// holds.
    pub fn with_activation(mut self, a: Option<&Activation>) -> Stored {
        self.version = VERSION;
        match a {
            Some(a) => {
                self.on = true;
                self.pattern = Some(a.settings.pattern.wire().into());
                self.size = Some(a.settings.size.wire().into());
                self.speed = Some(a.settings.speed.wire().into());
                self.resume_after_s = Some(a.settings.resume_after.as_secs());
                self.auto_off_at_ms = a.settings.auto_off_at_ms;
                self.set_by = Some(a.set_by.clone());
                self.set_at_ms = Some(a.set_at_ms);
            }
            None => {
                self.on = false;
                self.pattern = None;
                self.size = None;
                self.speed = None;
                self.resume_after_s = None;
                self.auto_off_at_ms = None;
                self.set_by = None;
                self.set_at_ms = None;
            }
        }
        self
    }

    /// The stored activation, if it is on and still valid at `wall_ms`. An
    /// unreadable value turns it OFF — a store this agent cannot understand
    /// must never move anyone's mouse.
    pub fn activation(&self, wall_ms: u64) -> Option<Activation> {
        if !self.on {
            return None;
        }
        if self.auto_off_at_ms.is_some_and(|at| wall_ms >= at) {
            return None;
        }
        let d = Settings::default();
        let settings = Settings {
            pattern: match &self.pattern {
                Some(p) => Pattern::from_wire(p)?,
                None => d.pattern,
            },
            size: match &self.size {
                Some(s) => Size::from_wire(s)?,
                None => d.size,
            },
            speed: match &self.speed {
                Some(s) => Speed::from_wire(s)?,
                None => d.speed,
            },
            resume_after: self
                .resume_after_s
                .map(Duration::from_secs)
                .unwrap_or(d.resume_after),
            auto_off_at_ms: self.auto_off_at_ms,
        };
        Some(Activation {
            settings,
            set_by: self.set_by.clone().unwrap_or_default(),
            set_at_ms: self.set_at_ms.unwrap_or_default(),
        })
    }
}

/// Run a store read or write with the right identity. Under a Windows
/// SystemContext worker the file sits in the PERSON's profile, which they
/// control, so it is touched as them (`win_identity::as_session_user`): a
/// link they planted there must never steer a SYSTEM write. `None` when that
/// identity cannot be had — nothing was touched.
fn as_owner<T>(f: impl FnOnce() -> T) -> Option<T> {
    #[cfg(target_os = "windows")]
    {
        if crate::win_identity::process_is_local_system() {
            return crate::win_identity::as_session_user(f);
        }
    }
    Some(f())
}

/// Read the store. Missing, unreadable or corrupt ⇒ the default (off) — and
/// so is a store this process may not read as its owner.
pub fn load_from(path: &Path) -> Stored {
    as_owner(|| load_unchecked(path)).unwrap_or_else(|| {
        tracing::warn!(
            path = %path.display(),
            "keep-busy: cannot act as the signed-in person — treating keep-busy as off"
        );
        Stored::default()
    })
}

fn load_unchecked(path: &Path) -> Stored {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Stored::default();
    };
    match serde_json::from_str::<Stored>(&raw) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "keep-busy: store unreadable — treating keep-busy as off"
            );
            Stored::default()
        }
    }
}

/// Write the store atomically (temp file + rename), creating the directory —
/// as the person whose store it is ([`as_owner`]).
pub fn save_to(path: &Path, s: &Stored) -> std::io::Result<()> {
    as_owner(|| save_unchecked(path, s)).unwrap_or_else(|| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cannot act as the signed-in person",
        ))
    })
}

fn save_unchecked(path: &Path, s: &Stored) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(s).map_err(std::io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Where the signed-in person's store lives.
///
/// Windows: a SystemContext worker runs as SYSTEM, whose own profile is the
/// wrong person — it resolves the console user's profile instead
/// (`session_user_profile_dir`, SeTcb), the same file the user-context
/// worker writes through its own `project_dirs()`, and reads and writes it
/// AS that user ([`load_from`], [`save_to`]).
///
/// Linux, root daemon: the person signed in at our display (logind), stored
/// under ROOT's own data dir as `keep-busy-<uid>.json` — never in their home.
/// A root write into a directory the person controls can be steered by a
/// link they plant (the symlink-to-`/etc/shadow` class); a file in root's
/// directory cannot. `None` while nobody is signed in (a greeter is nobody).
pub fn default_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if crate::win_identity::process_is_local_system() {
            let profile = crate::win_identity::session_user_profile_dir()?;
            return Some(
                crate::appdirs::data_local_dir_in_profile(Path::new(&profile)).join(FILE_NAME),
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        if is_root() {
            let person = super::logind::session_for_display(None).filter(|s| s.is_user())?;
            return crate::appdirs::project_dirs()
                .map(|d| d.data_local_dir().join(root_store_name(person.uid)));
        }
    }
    crate::appdirs::project_dirs().map(|d| d.data_local_dir().join(FILE_NAME))
}

/// A root daemon's store for the person with `uid`.
pub fn root_store_name(uid: u32) -> String {
    format!("keep-busy-{uid}.json")
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Can the person signed in change under this running process? A Windows
/// SystemContext worker serves whoever is at the console, and a root Linux
/// daemon outlives every login; a user-context worker, a per-user daemon
/// and a macOS GUI worker each run AS one person for their whole life.
pub fn person_can_change() -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::win_identity::process_is_local_system()
    }
    #[cfg(target_os = "linux")]
    {
        is_root()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Did anyone leave keep busy on, so that a login has something to
/// restore? Only a root Linux daemon can answer cheaply (every person's
/// store is in its own directory) and needs to: finding the person there
/// spawns `loginctl`. Elsewhere the answer is "maybe".
pub fn someone_left_it_on() -> bool {
    #[cfg(target_os = "linux")]
    {
        if is_root() {
            return crate::appdirs::project_dirs()
                .is_some_and(|d| any_left_on_in(d.data_local_dir()));
        }
    }
    true
}

/// Any `keep-busy-<uid>.json` in `dir` that is on?
pub fn any_left_on_in(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.starts_with("keep-busy-") && name.ends_with(".json") && load_from(&e.path()).on
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act() -> Activation {
        Activation {
            settings: Settings {
                pattern: Pattern::Heart,
                size: Size::L,
                speed: Speed::Slow,
                resume_after: Duration::from_secs(60),
                auto_off_at_ms: Some(10_000),
            },
            set_by: "Alice".into(),
            set_at_ms: 5,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("roomlerd-keep-busy-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    /// A root daemon keeps one store per person, in its own directory, and
    /// can tell without asking logind whether any of them is on.
    #[test]
    fn a_root_daemon_keeps_each_persons_store_apart() {
        assert_eq!(root_store_name(1000), "keep-busy-1000.json");
        let dir = tmp("root").parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!any_left_on_in(&dir), "nothing stored");
        save_to(
            &dir.join(root_store_name(1000)),
            &Stored::default().with_activation(None),
        )
        .unwrap();
        assert!(!any_left_on_in(&dir), "stored, but off");
        save_to(
            &dir.join(FILE_NAME),
            &Stored::default().with_activation(Some(&act())),
        )
        .unwrap();
        assert!(
            !any_left_on_in(&dir),
            "a per-user daemon's own file is nobody's per-person store"
        );
        save_to(
            &dir.join(root_store_name(1001)),
            &Stored::default().with_activation(Some(&act())),
        )
        .unwrap();
        assert!(any_left_on_in(&dir));
        assert!(!any_left_on_in(&dir.join("missing")));
    }

    #[test]
    fn an_activation_round_trips_through_the_file() {
        let path = tmp("round");
        let s = Stored::default().with_activation(Some(&act()));
        save_to(&path, &s).unwrap();
        let back = load_from(&path);
        assert_eq!(back.activation(0), Some(act()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn off_missing_corrupt_and_expired_all_read_as_off() {
        assert_eq!(Stored::default().activation(0), None);
        let path = tmp("corrupt");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(load_from(&path).activation(0), None);
        assert_eq!(
            load_from(&path.with_file_name("missing.json")).activation(0),
            None
        );
        let s = Stored::default().with_activation(Some(&act()));
        assert_eq!(s.activation(10_000), None, "past its auto-off");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_value_this_agent_does_not_know_turns_it_off_not_into_a_guess() {
        let mut s = Stored::default().with_activation(Some(&act()));
        s.pattern = Some("hyperspiral".into());
        assert_eq!(s.activation(0), None);
    }

    #[test]
    fn unknown_keys_survive_a_load_and_save() {
        let path = tmp("extra");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"version":9,"on":false,"from_the_future":{"x":1}}"#,
        )
        .unwrap();
        let s = load_from(&path).with_activation(Some(&act()));
        save_to(&path, &s).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("from_the_future"), "{raw}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn turning_off_clears_the_settings_but_keeps_the_org_record() {
        let mut s = Stored::default().with_activation(Some(&act()));
        s.org_denied.insert("abc".into(), true);
        let s = s.with_activation(None);
        assert!(!s.on && s.pattern.is_none() && s.set_by.is_none());
        assert_eq!(s.org_denied.get("abc"), Some(&true));
    }
}
