// SPDX-License-Identifier: AGPL-3.0-only
//! MeshHarbor — the device's local login accounts, for choosing what an SSH
//! share runs as (`rc:accounts.request`).
//!
//! The owner picks an existing account, or has the device create one, with or
//! without the right to become root. The device keeps the last word:
//!
//! * nothing is listed or created unless its own `ssh_enabled` is on — the
//!   same device-owned switch that decides whether any SSH session runs here;
//! * an administrator account is refused under `ssh_max_privilege =
//!   console_user`, the device's ceiling against root sessions, so a server
//!   can never obtain more through this path than the device already allows;
//! * only portable POSIX names, never an existing account, and only local
//!   accounts are read (`/etc/passwd`, the local directory node) — never a
//!   directory service, which would list a whole organization.
//!
//! A created account has NO password: SSH sessions reach it through the
//! daemon's own privilege drop, so nothing needs one. Its administrator right is
//! therefore a passwordless sudo rule in `sudoers.d` — a sudo that asked for a
//! password nobody has would be no right at all.

use roomler_ai_remote_control::signaling::{LocalAccount, LocalAccountOp};

use crate::config::AgentConfig;

/// Answer one request: the accounts after the operation, or why it refused.
pub fn handle(cfg: &AgentConfig, op: &LocalAccountOp) -> Result<Vec<LocalAccount>, String> {
    if !cfg.ssh_enabled {
        return Err(
            "embedded SSH is not enabled on this device (ssh_enabled), so it does \
                    not list or create accounts for sharing"
                .into(),
        );
    }
    match op {
        LocalAccountOp::List => imp::list(),
        LocalAccountOp::Create { name, admin } => {
            if !valid_name(name) {
                return Err(
                    "an account name must be a Linux/macOS user name (lowercase \
                            letters, digits, _ and -, at most 32)"
                        .into(),
                );
            }
            if *admin && cfg.ssh_max_privilege.as_deref() == Some("console_user") {
                return Err(
                    "this device's ssh_max_privilege forbids administrator sessions, \
                            so it does not create an administrator account"
                        .into(),
                );
            }
            imp::create(name, *admin)?;
            imp::list()
        }
    }
}

/// The server's rule (`valid_share_account`), held here too: the device decides.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Where the passwordless sudo rule for a created administrator lives.
#[cfg(unix)]
fn sudoers_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/etc/sudoers.d/meshharbor-{name}"))
}

/// Write `<name> ALL=(ALL:ALL) NOPASSWD: ALL` to `sudoers.d`, checked by
/// `visudo` before it is moved into place: a malformed file there breaks sudo
/// for everyone on the machine.
#[cfg(unix)]
fn write_sudo_rule(name: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = std::path::Path::new("/etc/sudoers.d");
    if !dir.is_dir() {
        return Err(
            "this device has no /etc/sudoers.d, so it cannot grant administrator \
                    rights"
                .into(),
        );
    }
    let visudo = ["/usr/sbin/visudo", "/usr/bin/visudo", "/sbin/visudo"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or("sudo (visudo) is not installed on this device")?;
    let target = sudoers_path(name);
    // A name sudo would skip (it ignores files containing `.` or ending `~`)
    // cannot occur: `valid_name` admits neither.
    let tmp = dir.join(format!(".meshharbor-{name}.tmp"));
    let body = format!(
        "# Written by MeshHarbor for an SSH share account; removing this file removes the right.\n\
         {name} ALL=(ALL:ALL) NOPASSWD: ALL\n"
    );
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o440))
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing the sudo rule: {e}"));
    }
    let checked = std::process::Command::new(visudo)
        .args(["-c", "-q", "-f"])
        .arg(&tmp)
        .output();
    match checked {
        Ok(o) if o.status.success() => {}
        _ => {
            let _ = std::fs::remove_file(&tmp);
            return Err("visudo rejected the sudo rule; nothing was installed".into());
        }
    }
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("installing the sudo rule: {e}")
    })
}

#[cfg(unix)]
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().next().unwrap_or("").trim();
        return Err(format!("{program} failed: {first}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(unix)]
fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "the MeshHarbor daemon on this device does not run as root, so it \
                    cannot create accounts"
                .into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    /// Login accounts from `/etc/passwd` only: a regular uid and a real shell.
    pub fn list() -> Result<Vec<LocalAccount>, String> {
        let passwd =
            std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
        let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
        Ok(parse(&passwd, &groups, |n| sudoers_path(n).exists()))
    }

    pub fn parse(passwd: &str, groups: &str, has_rule: impl Fn(&str) -> bool) -> Vec<LocalAccount> {
        let admins: Vec<&str> = groups
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() >= 4 && matches!(f[0], "sudo" | "wheel" | "admin")).then(|| f[3])
            })
            .flat_map(|m| m.split(','))
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .collect();
        let mut out: Vec<LocalAccount> = passwd
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                if f.len() < 7 || !valid_name(f[0]) {
                    return None;
                }
                let uid: u32 = f[2].parse().ok()?;
                let shell = f[6].trim();
                let login =
                    !shell.is_empty() && !shell.ends_with("nologin") && !shell.ends_with("false");
                ((1000..60000).contains(&uid) && login).then(|| LocalAccount {
                    name: f[0].to_string(),
                    uid,
                    admin: admins.contains(&f[0]) || has_rule(f[0]),
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn create(name: &str, admin: bool) -> Result<(), String> {
        require_root()?;
        if list_all_names()?.iter().any(|n| n == name) {
            return Err(format!(
                "an account named {name} already exists; choose it instead"
            ));
        }
        let useradd = ["/usr/sbin/useradd", "/sbin/useradd"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .ok_or("useradd is not installed on this device")?;
        let shell = if std::path::Path::new("/bin/bash").exists() {
            "/bin/bash"
        } else {
            "/bin/sh"
        };
        // No password is set: the account is locked for password logins and is
        // reached only through the daemon's own privilege drop.
        run(
            useradd,
            &[
                "--create-home",
                "--shell",
                shell,
                "--comment",
                "MeshHarbor shared SSH account",
                "--",
                name,
            ],
        )?;
        if admin && let Err(e) = write_sudo_rule(name) {
            // Never leave half of what was asked: an account without the right
            // the owner chose would be shared under a false description.
            let _ = run("/usr/sbin/userdel", &["--remove", "--", name]);
            return Err(e);
        }
        Ok(())
    }

    /// Every local name, whatever its uid: a new account must not shadow one.
    fn list_all_names() -> Result<Vec<String>, String> {
        let passwd =
            std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
        Ok(passwd
            .lines()
            .filter_map(|l| l.split(':').next())
            .map(str::to_string)
            .collect())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// Accounts from the LOCAL directory node only (`dscl .`), uid ≥ 501 and
    /// not a `_service` account.
    pub fn list() -> Result<Vec<LocalAccount>, String> {
        let users = run("/usr/bin/dscl", &[".", "-list", "/Users", "UniqueID"])?;
        let admins = run(
            "/usr/bin/dscl",
            &[".", "-read", "/Groups/admin", "GroupMembership"],
        )
        .unwrap_or_default();
        Ok(parse(&users, &admins, |n| sudoers_path(n).exists()))
    }

    pub fn parse(users: &str, admins: &str, has_rule: impl Fn(&str) -> bool) -> Vec<LocalAccount> {
        let admins: Vec<&str> = admins
            .split_whitespace()
            .filter(|w| *w != "GroupMembership:")
            .collect();
        let mut out: Vec<LocalAccount> = users
            .lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let name = it.next()?;
                let uid: u32 = it.next()?.parse().ok()?;
                (uid >= 501 && uid < 60000 && valid_name(name)).then(|| LocalAccount {
                    name: name.to_string(),
                    uid,
                    admin: admins.contains(&name) || has_rule(name),
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn create(name: &str, admin: bool) -> Result<(), String> {
        require_root()?;
        let users = run("/usr/bin/dscl", &[".", "-list", "/Users", "UniqueID"])?;
        let mut max = 500u32;
        for l in users.lines() {
            let mut it = l.split_whitespace();
            let (Some(n), Some(u)) = (it.next(), it.next()) else {
                continue;
            };
            if n == name {
                return Err(format!(
                    "an account named {name} already exists; choose it instead"
                ));
            }
            match u.parse::<u32>() {
                Ok(u) if u < 60000 => max = max.max(u),
                _ => {}
            }
        }
        let uid = (max + 1).to_string();
        let path = format!("/Users/{name}");
        let home = format!("/Users/{name}");
        let steps: [&[&str]; 7] = [
            &[".", "-create", &path],
            &[".", "-create", &path, "UniqueID", &uid],
            &[".", "-create", &path, "PrimaryGroupID", "20"],
            &[".", "-create", &path, "UserShell", "/bin/zsh"],
            &[
                ".",
                "-create",
                &path,
                "RealName",
                "MeshHarbor shared SSH account",
            ],
            &[".", "-create", &path, "NFSHomeDirectory", &home],
            // `*` = no password can ever match: reached only by the daemon's drop.
            &[".", "-create", &path, "Password", "*"],
        ];
        let undo = || {
            let _ = run("/usr/bin/dscl", &[".", "-delete", &path]);
        };
        for args in steps {
            if let Err(e) = run("/usr/bin/dscl", args) {
                undo();
                return Err(e);
            }
        }
        if let Err(e) = run("/usr/sbin/createhomedir", &["-c", "-u", name]) {
            undo();
            return Err(e);
        }
        if admin {
            let granted = run(
                "/usr/sbin/dseditgroup",
                &["-o", "edit", "-a", name, "-t", "user", "admin"],
            )
            .and_then(|_| write_sudo_rule(name));
            if let Err(e) = granted {
                undo();
                return Err(e);
            }
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::*;
    pub fn list() -> Result<Vec<LocalAccount>, String> {
        Err("choosing an account for SSH sharing is available on Linux and macOS devices".into())
    }
    pub fn create(_: &str, _: bool) -> Result<(), String> {
        list().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_listed_or_created_unless_the_device_enabled_ssh() {
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = false;
        assert!(handle(&cfg, &LocalAccountOp::List).is_err());
        let create = LocalAccountOp::Create {
            name: "alice".into(),
            admin: false,
        };
        assert!(handle(&cfg, &create).unwrap_err().contains("ssh_enabled"));
    }

    #[test]
    fn an_administrator_is_refused_under_the_devices_ceiling_before_anything_runs() {
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = true;
        cfg.ssh_max_privilege = Some("console_user".into());
        let create = LocalAccountOp::Create {
            name: "alice".into(),
            admin: true,
        };
        assert!(
            handle(&cfg, &create)
                .unwrap_err()
                .contains("ssh_max_privilege")
        );
    }

    #[test]
    fn a_malformed_name_never_reaches_a_command() {
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = true;
        for bad in [
            "",
            "Root",
            "-rf",
            "a b",
            "../x",
            "a.b",
            "x;id",
            &"a".repeat(33),
        ] {
            let create = LocalAccountOp::Create {
                name: bad.into(),
                admin: false,
            };
            assert!(
                handle(&cfg, &create).unwrap_err().contains("user name"),
                "{bad:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_lists_regular_login_accounts_with_their_admin_right() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n\
                      nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n\
                      bob:x:1001:1001::/home/bob:/bin/bash\n\
                      alice:x:1000:1000::/home/alice:/bin/zsh\n\
                      svc:x:1002:1002::/srv:/bin/false\n\
                      share1:x:1003:1003::/home/share1:/bin/bash\n\
                      Bad:x:1004:1004::/home/x:/bin/bash\n";
        let groups = "sudo:x:27:alice\nwheel:x:10:\nusers:x:100:bob\n";
        let got = imp::parse(passwd, groups, |n| n == "share1");
        let names: Vec<(&str, bool)> = got.iter().map(|a| (a.name.as_str(), a.admin)).collect();
        assert_eq!(
            names,
            vec![("alice", true), ("bob", false), ("share1", true)]
        );
    }

    /// The real thing, against the real `useradd`/`dscl`, `visudo` and `sudo`: run ONLY in a
    /// disposable root (an overlay over `/`, a VM), as root, with
    /// `MESHHARBOR_LIVE_ACCOUNTS=1`. It creates `mhshare1` (administrator) and `mhshare2`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[ignore = "creates real OS accounts: disposable root only"]
    fn live_create_lists_and_grants_exactly_what_was_asked() {
        assert_eq!(
            std::env::var("MESHHARBOR_LIVE_ACCOUNTS").as_deref(),
            Ok("1"),
            "refusing: this creates real accounts"
        );
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = true;
        let create = |name: &str, admin: bool| {
            handle(
                &cfg,
                &LocalAccountOp::Create {
                    name: name.into(),
                    admin,
                },
            )
        };
        let after = create("mhshare1", true).expect("create administrator");
        assert!(
            after.iter().any(|a| a.name == "mhshare1" && a.admin),
            "{after:?}"
        );
        let after = create("mhshare2", false).expect("create plain account");
        assert!(
            after.iter().any(|a| a.name == "mhshare2" && !a.admin),
            "{after:?}"
        );
        assert!(
            create("mhshare1", false)
                .unwrap_err()
                .contains("already exists")
        );
        let listed = handle(&cfg, &LocalAccountOp::List).unwrap();
        assert!(listed.iter().any(|a| a.name == "mhshare1" && a.admin));
        assert!(listed.iter().any(|a| a.name == "mhshare2" && !a.admin));

        // macOS `su` has no `-s`; the account's own shell (zsh) runs the command there.
        let sh = |user: &str, cmd: &str| {
            let args: Vec<&str> = if cfg!(target_os = "macos") {
                vec![user, "-c", cmd]
            } else {
                vec!["-s", "/bin/sh", user, "-c", cmd]
            };
            std::process::Command::new("/usr/bin/su").args(args).output().unwrap()
        };
        let root = sh("mhshare1", "sudo -n id -u");
        assert!(root.status.success(), "{root:?}");
        assert_eq!(
            String::from_utf8_lossy(&root.stdout).trim(),
            "0",
            "administrator becomes root without a password"
        );
        assert!(
            !sh("mhshare2", "sudo -n true").status.success(),
            "a plain account cannot"
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(sudoers_path("mhshare1"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o440);
            assert!(!sudoers_path("mhshare2").exists());
            let status = std::process::Command::new("/usr/bin/passwd")
                .args(["-S", "mhshare1"])
                .output()
                .unwrap();
            let status = String::from_utf8_lossy(&status.stdout).to_string();
            assert_eq!(
                status.split_whitespace().nth(1),
                Some("L"),
                "no usable password: {status}"
            );
            assert!(std::path::Path::new("/home/mhshare1").is_dir());
            let whole = std::process::Command::new("/usr/sbin/visudo")
                .arg("-c")
                .output()
                .unwrap();
            assert!(
                whole.status.success(),
                "the machine's sudo configuration stays valid"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_lists_local_people_not_service_accounts() {
        let users = "_spotlight 89\nroot 0\nnobody -2\njane 501\nkim 502\n";
        let admins = "GroupMembership: root jane\n";
        let got = imp::parse(users, admins, |_| false);
        let names: Vec<(&str, bool)> = got.iter().map(|a| (a.name.as_str(), a.admin)).collect();
        assert_eq!(names, vec![("jane", true), ("kim", false)]);
    }
}
