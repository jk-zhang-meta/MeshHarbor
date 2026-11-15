// SPDX-License-Identifier: MPL-2.0
//! Dedicated native-user namespace in the OS credential store. No filesystem
//! fallback; an unavailable/locked vault is an explicit sign-in error.
use super::{UserProfile, trusted_base};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
pub struct SavedSession {
    pub server: String,
    pub refresh_token: String,
    pub user: UserProfile,
}
impl std::fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedSession")
            .field("server", &self.server)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}
fn key(server: &str) -> Result<String> {
    let base = trusted_base(server)?.to_string();
    Ok(format!(
        "MeshHarbor:native-user:v1:{:x}",
        Sha256::digest(base.as_bytes())
    ))
}
pub fn save(saved: &SavedSession) -> Result<()> {
    saved.user.validate()?;
    if saved.refresh_token.is_empty() {
        bail!("missing native user credential");
    }
    platform::write(&key(&saved.server)?, &serde_json::to_string(saved)?)
}
pub fn load(server: &str) -> Result<Option<SavedSession>> {
    let Some(raw) = platform::read(&key(server)?)? else {
        return Ok(None);
    };
    let saved: SavedSession =
        serde_json::from_str(&raw).context("invalid OS user session record")?;
    if trusted_base(&saved.server)? != trusted_base(server)? {
        bail!("OS session server scope mismatch");
    }
    saved.user.validate()?;
    Ok(Some(saved))
}
pub fn delete(server: &str) -> Result<()> {
    platform::delete(&key(server)?)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::Security::Credentials::*;
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    pub fn write(key: &str, value: &str) -> Result<()> {
        let mut target = wide(key);
        let mut user = wide("MeshHarbor native user session");
        let mut blob = value.as_bytes().to_vec();
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            UserName: user.as_mut_ptr(),
            CredentialBlobSize: blob.len().try_into()?,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..unsafe { std::mem::zeroed() }
        };
        let result = unsafe { CredWriteW(&cred, 0) };
        for byte in &mut blob {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        if result == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    pub fn read(key: &str) -> Result<Option<String>> {
        let mut ptr = std::ptr::null_mut();
        if unsafe { CredReadW(wide(key).as_ptr(), CRED_TYPE_GENERIC, 0, &mut ptr) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(1168) {
                return Ok(None);
            }
            return Err(error.into());
        }
        let value = unsafe {
            String::from_utf8(
                std::slice::from_raw_parts(
                    (*ptr).CredentialBlob,
                    (*ptr).CredentialBlobSize as usize,
                )
                .to_vec(),
            )
        };
        unsafe {
            CredFree(ptr.cast());
        }
        Ok(Some(value.context("invalid OS credential bytes")?))
    }
    pub fn delete(key: &str) -> Result<()> {
        if unsafe { CredDeleteW(wide(key).as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1168) {
                return Err(error.into());
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<std::process::Output> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("OS credential store unavailable")?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .context("OS vault input missing")?
                .write_all(input.as_bytes())?;
        }
        // Bound a locked/unavailable keychain helper. Only our own helper is
        // terminated, never a desktop application or an OS credential daemon.
        let started = std::time::Instant::now();
        while child.try_wait()?.is_none() {
            if started.elapsed() > std::time::Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                bail!("OS credential store timed out; outcome unconfirmed");
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        // Never include tool output in an error: it can contain secret data.
        child
            .wait_with_output()
            .context("OS credential store failed")
    }
    pub fn write(key: &str, value: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        let output = run(
            "secret-tool",
            &[
                "store",
                "--label=MeshHarbor signed-in account",
                "service",
                "meshharbor-native-user",
                "scope",
                key,
            ],
            Some(value),
        )?;
        #[cfg(target_os = "macos")]
        let output = {
            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let command = format!(
                "add-generic-password -U -a \"native-user\" -s \"{}\" -w \"{}\"\n",
                esc(key),
                esc(value)
            );
            run("/usr/bin/security", &["-i"], Some(&command))?
        };
        if !output.status.success() {
            bail!("OS credential store refused saving the session");
        }
        Ok(())
    }
    pub fn read(key: &str) -> Result<Option<String>> {
        #[cfg(target_os = "linux")]
        let output = run(
            "secret-tool",
            &["lookup", "service", "meshharbor-native-user", "scope", key],
            None,
        )?;
        #[cfg(target_os = "macos")]
        let output = run(
            "/usr/bin/security",
            &["find-generic-password", "-s", key, "-w"],
            None,
        )?;
        if !output.status.success() {
            #[cfg(target_os = "macos")]
            if output.status.code() == Some(44) {
                return Ok(None);
            }
            #[cfg(target_os = "linux")]
            if output.status.code() == Some(1) && output.stderr.is_empty() {
                return Ok(None);
            }
            bail!("OS credential store is locked or unavailable");
        }
        Ok(Some(
            String::from_utf8(output.stdout)
                .context("invalid OS vault text")?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        ))
    }
    pub fn delete(key: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        let output = run(
            "secret-tool",
            &["clear", "service", "meshharbor-native-user", "scope", key],
            None,
        )?;
        #[cfg(target_os = "macos")]
        let output = run(
            "/usr/bin/security",
            &["delete-generic-password", "-s", key],
            None,
        )?;
        if !output.status.success() {
            bail!("OS credential store did not delete the session");
        }
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;
    pub fn write(_: &str, _: &str) -> Result<()> {
        bail!("OS user credential store is not supported")
    }
    pub fn read(_: &str) -> Result<Option<String>> {
        bail!("OS user credential store is not supported")
    }
    pub fn delete(_: &str) -> Result<()> {
        bail!("OS user credential store is not supported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vault_keys_are_origin_prefix_and_purpose_scoped() {
        let a = key("https://example.com/a").unwrap();
        assert!(a.starts_with("MeshHarbor:native-user:v1:"));
        assert_ne!(a, key("https://example.com/ab").unwrap());
        assert_ne!(a, key("https://example.net/a").unwrap());
        assert_eq!(a, key("https://example.com/a/").unwrap());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit isolated synthetic Windows credential-store fixture only"]
    fn windows_user_vault_roundtrip_isolated_fixture() {
        let origin = format!(
            "https://native-user-vault-fixture-{:032x}.invalid/task",
            rand::random::<u128>()
        );
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = super::delete(&self.0);
            }
        }
        let _cleanup = Cleanup(origin.clone());
        assert!(load(&origin).unwrap().is_none());
        let saved = SavedSession {
            server: origin.clone(),
            refresh_token: "synthetic-not-a-real-user-credential".into(),
            user: UserProfile {
                id: "fixture-only".into(),
                email: "fixture@example.com".into(),
                email_verified: true,
            },
        };
        save(&saved).unwrap();
        let loaded = load(&origin).unwrap().unwrap();
        assert_eq!(loaded.user, saved.user);
        assert_eq!(loaded.refresh_token, saved.refresh_token);
        delete(&origin).unwrap();
        assert!(load(&origin).unwrap().is_none());
    }
}
