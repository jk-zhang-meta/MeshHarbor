// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 decision 15 — on a Mac, whether a session's account may use `sudo`
//! without a password.
//!
//! A session holds none of its account's administrator groups (decision 13),
//! and on Linux `no_new_privs` keeps it from `sudo` altogether. macOS has no
//! such switch, and its `sudo` reads the account's groups from the directory,
//! never from the process: field-measured with `%admin … NOPASSWD` as the only
//! passwordless rule, a session without the admin group still got root
//! (FR-90 §8). So an account with any passwordless rule, by user or by group,
//! would hand its sessions root there. A start as one is refused
//! (`passwordless_sudo`) unless the device's owner allows it
//! (`hive_allow_passwordless_sudo`, never pushable).
//!
//! ⚠️ Asked AS ROOT, `sudo -l -U <account>`, never as the account. Listing
//! another account's rules authenticates nobody. Asking as the account
//! (`sudo -n -l`) would fail on every Mac whose `sudo` asks for a password,
//! which is every Mac nobody changed, and have PAM try to authenticate the
//! account at every start, in the unified log (field-measured, FR-90 §8).

use meshharbor_remote_control::hive::HiveRefusal;

/// How long the listing gets: a sudoers kept in a directory service can be
/// slow, and a check that does not answer refuses the start.
#[cfg(target_os = "macos")]
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What `sudo -l -U` printed (`LC_ALL=C`). `Some(true)` when a rule needs
/// no password (a `NOPASSWD:` tag) or a Defaults entry turns authentication
/// off (`!authenticate`). `Some(false)` when it lists rules that all ask for
/// one, or says the account may not run `sudo`. `None` when it says neither,
/// which the caller refuses: a check that cannot be read never lets a start
/// through.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn read_listing(out: &str) -> Option<bool> {
    if out.contains("NOPASSWD") || out.contains("!authenticate") {
        return Some(true);
    }
    let lists = out.contains("may run the following commands");
    let denied = out.contains("is not allowed to run sudo");
    (lists || denied).then_some(false)
}

/// The gate's word for an account: `Ok` lets the start through. `allowed`
/// is the device's `hive_allow_passwordless_sudo`; `checked` is what the
/// listing said, or why there is none.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn decide(
    account: &str,
    allowed: bool,
    checked: Result<bool, String>,
) -> Result<(), (HiveRefusal, String)> {
    if allowed {
        return Ok(());
    }
    match checked {
        Ok(false) => Ok(()),
        Ok(true) => Err((
            HiveRefusal::PasswordlessSudo,
            format!(
                "{account} may use sudo without a password, which would give the agent root on \
                 this Mac: its sudo reads the account's groups from the directory, so a session \
                 cannot drop them. Give {account} a sudo that asks for a password, or set \
                 hive_allow_passwordless_sudo"
            ),
        )),
        Err(e) => Err((
            HiveRefusal::LaunchFailed,
            format!("could not tell whether {account} may use sudo without a password: {e}"),
        )),
    }
}

/// Decision 15's gate for a start as `account`: on a Mac, the listing, then
/// [`decide`]. Elsewhere there is nothing to check.
pub(crate) async fn gate(account: &str, allowed: bool) -> Result<(), (HiveRefusal, String)> {
    #[cfg(target_os = "macos")]
    if !allowed {
        // A missing account is refused as missing, as the launch would.
        crate::exec::account_home(account).map_err(|e| (HiveRefusal::NoAccount, e))?;
        return decide(account, false, passwordless(account).await);
    }
    let _ = (account, allowed);
    Ok(())
}

/// `sudo -l -U <account>` as the daemon (root), read by [`read_listing`].
#[cfg(target_os = "macos")]
async fn passwordless(account: &str) -> Result<bool, String> {
    use std::process::Stdio;
    let mut cmd = tokio::process::Command::new("/usr/bin/sudo");
    cmd.args(["-n", "-l", "-U", account])
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let out = tokio::time::timeout(CHECK_TIMEOUT, cmd.output())
        .await
        .map_err(|_| {
            format!(
                "`sudo -l -U {account}` did not answer within {} s",
                CHECK_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("running `sudo -l -U {account}`: {e}"))?;
    read_listing(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        let said = String::from_utf8_lossy(&out.stderr);
        let said: String = said.trim().chars().take(200).collect();
        format!(
            "`sudo -l -U {account}` listed nothing (exit {:?}): {said}",
            out.status.code()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What sudo 1.9 prints for an account, in the shapes a Mac's sudoers
    /// gives: the rules after "may run the following commands", Defaults
    /// above them.
    fn listing(defaults: &str, rules: &[&str]) -> String {
        let mut s = format!(
            "Matching Defaults entries for admin on mac:\n    {defaults}\n\n\
             Runas and Command-specific defaults for admin:\n    \
             Defaults!/usr/sbin/visudo env_keep+=\"SUDO_EDITOR EDITOR VISUAL\"\n\n\
             User admin may run the following commands on mac:\n"
        );
        for r in rules {
            s.push_str("    ");
            s.push_str(r);
            s.push('\n');
        }
        s
    }

    /// A passwordless rule by user or by group lists the same way, since
    /// `sudo -l -U` resolves the account's groups; so do a tag on one command
    /// and authentication turned off in Defaults. A Mac nobody changed lists
    /// `(ALL) ALL`, which asks; an account outside sudoers is told so; and
    /// anything else is unreadable, which refuses.
    #[test]
    fn a_passwordless_rule_of_any_shape_is_found_and_nothing_else() {
        let env = "env_reset, env_keep+=BLOCKSIZE, lecture_file=/etc/sudo_lecture";
        assert_eq!(read_listing(&listing(env, &["(ALL) ALL"])), Some(false));
        assert_eq!(
            read_listing(&listing(env, &["(ALL) ALL", "(ALL) NOPASSWD: ALL"])),
            Some(true)
        );
        assert_eq!(
            read_listing(&listing(env, &["(root) NOPASSWD: /usr/bin/true"])),
            Some(true),
            "a passwordless rule for one command is root by that command"
        );
        assert_eq!(
            read_listing(&listing(&format!("{env}, !authenticate"), &["(ALL) ALL"])),
            Some(true)
        );
        assert_eq!(
            read_listing("User guest is not allowed to run sudo on mac.\n"),
            Some(false)
        );
        assert_eq!(read_listing(""), None);
        assert_eq!(read_listing("sudo: unknown user ghost\n"), None);
    }

    /// The owner's word lets every start through; otherwise a passwordless
    /// account is `passwordless_sudo`, and a check that failed refuses too,
    /// in words, never as a pass.
    #[test]
    fn the_gate_refuses_a_passwordless_account_unless_its_owner_allows_it() {
        assert!(decide("admin", true, Ok(true)).is_ok());
        assert!(decide("admin", true, Err("timeout".into())).is_ok());
        assert!(decide("admin", false, Ok(false)).is_ok());
        let (r, why) = decide("admin", false, Ok(true)).unwrap_err();
        assert_eq!(r, HiveRefusal::PasswordlessSudo);
        assert!(
            why.contains("admin may use sudo without a password"),
            "{why}"
        );
        assert!(why.contains("hive_allow_passwordless_sudo"), "{why}");
        let (r, why) =
            decide("admin", false, Err("did not answer within 10 s".into())).unwrap_err();
        assert_eq!(r, HiveRefusal::LaunchFailed);
        assert!(why.contains("did not answer"), "{why}");
    }

    /// Off a Mac there is nothing to check: Linux sessions cannot `sudo`
    /// (`no_new_privs`), and Windows sessions run restricted.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn off_a_mac_the_gate_lets_every_start_through() {
        assert!(gate("anyone", false).await.is_ok());
        assert!(gate("anyone", true).await.is_ok());
    }
}
