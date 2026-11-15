// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Elevated executor for `meshharbord enroll-personal-system`.
//!
//! Enrolls or promotes this machine's personal account into the system-wide
//! configuration (`/etc/meshharbor/config.toml` on Linux/macOS,
//! `%PROGRAMDATA%\meshharbor\meshharbor\config.toml` on Windows), installs and
//! starts the platform's root/`SYSTEM` service, anchors the Windows `SYSTEM`
//! exec + SSH service ceiling with the same single-approval enrollment token,
//! and cleanly retires any competing per-user daemon so the machine comes
//! online with full Administrator / `root` privileges immediately.

use anyhow::{Context, Result, bail};
use meshharbor_node_core::{device_invite, personal_system};
use std::path::{Path, PathBuf};

/// Entrypoint invoked by `meshharbord enroll-personal-system`. Records any
/// failure into the caller's pre-created `status_file` before returning `Err`.
pub async fn run_cli(request_file: &Path, status_file: &Path) -> Result<()> {
    let res = execute(request_file).await;
    if let Err(ref err) = res {
        personal_system::write_status_error(status_file, &format!("{err:#}"));
    }
    res
}

async fn execute(request_file: &Path) -> Result<()> {
    if !personal_system::is_process_elevated() {
        bail!("enroll-personal-system must run with Administrator / root privileges");
    }
    let req = personal_system::consume_request_file(request_file)?;
    let device_name = req.device_name.trim();
    if device_name.is_empty() {
        bail!("device name is empty");
    }

    #[cfg(windows)]
    let target_path = {
        let p = crate::config::machine_global_config_path();
        harden_windows_machine_global_root(&p)?;
        p
    };
    #[cfg(not(windows))]
    let target_path = {
        let p = PathBuf::from(crate::service::system::CONFIG);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        p
    };

    let existing = if target_path.exists() {
        Some(crate::config::load(&target_path).context("reading existing system config")?)
    } else if let Some(seed_raw) = req.seed_config_toml.as_deref()
        && let Ok(seed_cfg) = toml::from_str::<crate::config::AgentConfig>(seed_raw)
    {
        seed_sidecar_json_if_absent(
            &target_path,
            "temporary.json",
            req.seed_temporary_json.as_deref(),
        );
        Some(seed_cfg)
    } else {
        None
    };
    merge_seed_invitation_history(&target_path, req.seed_history_json.as_deref());

    let machine_id = existing
        .as_ref()
        .map(|cfg| cfg.machine_id.clone())
        .unwrap_or_else(|| crate::machine::derive_machine_id(&target_path));

    let fresh_cfg = crate::enrollment::enroll_with_existing_identity(
        crate::enrollment::EnrollInputs {
            server_url: &req.server_url,
            enrollment_token: &req.enrollment_token,
            machine_id: &machine_id,
            machine_name: device_name,
            install: Some(crate::enrollment::InstallInfo::new(
                crate::enrollment::InstallMethod::Manual,
                crate::enrollment::InstallScope::System,
            )),
        },
        existing
            .as_ref()
            .and_then(|cfg| {
                crate::enrollment::existing_identity_for(cfg, &req.server_url, &req.enrollment_token)
            }),
    )
    .await
    .context("enrolling device with server")?;

    let enrolled_agent_id = fresh_cfg.agent_id.clone();
    let (mut cfg, outcome) = merge_and_promote_personal_enrollment(
        &target_path,
        existing,
        fresh_cfg,
        req.replace,
    )?;

    if crate::enrollment::takes_service_install_defaults(cfg!(windows), &outcome) {
        crate::enrollment::apply_service_install_defaults(&mut cfg);
    }

    #[cfg(target_os = "macos")]
    {
        cfg.macos_supervise_gui_worker = true;
    }

    crate::config::save(&target_path, &cfg).context("saving system config")?;

    let history = device_invite::read_history(&target_path);
    if !history.is_empty()
        && let Err(e) = device_invite::link(&cfg.server_url, &cfg.agent_token, &history).await
    {
        tracing::warn!(error = %e, "invitation history link will retry when the system daemon connects");
    }

    activate_platform_system_service(&req, &target_path, &enrolled_agent_id).await
}

fn merge_seed_invitation_history(target_config: &Path, raw: Option<&str>) {
    let Some(raw) = raw else {
        return;
    };
    let Ok(entries) = serde_json::from_str::<Vec<device_invite::HistoryEntry>>(raw) else {
        return;
    };
    for entry in entries {
        let _ = device_invite::append_history(target_config, entry);
    }
}

fn seed_sidecar_json_if_absent(target_config: &Path, file_name: &str, raw: Option<&str>) {
    let Some(raw) = raw else {
        return;
    };
    if serde_json::from_str::<serde_json::Value>(raw).is_err() {
        return;
    }
    let Some(dir) = target_config.parent() else {
        return;
    };
    let dst = dir.join(file_name);
    if dst.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(&dst) {
        use std::io::Write;
        let _ = f.write_all(raw.as_bytes());
        let _ = f.sync_all();
    }
}

#[cfg(windows)]
fn harden_windows_machine_global_root(config_path: &Path) -> Result<()> {
    let Some(root_dir) = config_path.parent().and_then(Path::parent) else {
        return Ok(());
    };
    std::fs::create_dir_all(root_dir)
        .with_context(|| format!("creating {}", root_dir.display()))?;
    let out = std::process::Command::new("icacls")
        .arg(root_dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .output()
        .context("running icacls on ProgramData\\meshharbor")?;
    if !out.status.success() {
        bail!(
            "icacls hardening failed on {}: {}",
            root_dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn stage_windows_service_binary() -> Result<PathBuf> {
    let current = std::env::current_exe().context("locating current meshharbord.exe")?;
    let pf_roots = meshharbor_node_core::companion_autostart::program_files_dirs();
    if personal_system::is_trusted_windows_service_exe(&current, &pf_roots) {
        return Ok(current);
    }
    let pf_base = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("ProgramFiles environment variable is missing"))?;
    let install_dir = pf_base.join("MeshHarbor");
    std::fs::create_dir_all(&install_dir)
        .with_context(|| format!("creating {}", install_dir.display()))?;

    let acl = std::process::Command::new("icacls")
        .arg(&install_dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-545:(OI)(CI)RX")
        .output()
        .context("hardening ProgramFiles\\MeshHarbor ACL")?;
    if !acl.status.success() {
        bail!(
            "icacls failed on {}: {}",
            install_dir.display(),
            String::from_utf8_lossy(&acl.stderr).trim()
        );
    }

    let staged_exe = install_dir.join("meshharbord.exe");
    copy_replacing_windows_file(&current, &staged_exe)?;

    if let Some(src_dir) = current.parent() {
        for sibling in ["meshharbor.exe", "mh.exe", "meshharbor-desktop.exe", "wintun.dll"] {
            let s = src_dir.join(sibling);
            if s.is_file() {
                let _ = copy_replacing_windows_file(&s, &install_dir.join(sibling));
            }
        }
    }

    let refreshed_roots = meshharbor_node_core::companion_autostart::program_files_dirs();
    if !personal_system::is_trusted_windows_service_exe(&staged_exe, &refreshed_roots) {
        bail!(
            "staged service binary {} is outside ProgramFiles",
            staged_exe.display()
        );
    }
    Ok(staged_exe)
}

#[cfg(windows)]
fn copy_replacing_windows_file(src: &Path, dst: &Path) -> Result<()> {
    let tmp = dst.with_extension("exe.staging");
    std::fs::copy(src, &tmp)
        .with_context(|| format!("staging {} -> {}", src.display(), tmp.display()))?;
    if dst.exists() {
        let old = dst.with_extension("exe.old");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(dst, &old);
    }
    std::fs::rename(&tmp, dst)
        .with_context(|| format!("activating staged binary {}", dst.display()))?;
    Ok(())
}

#[cfg(windows)]
async fn activate_platform_system_service(
    req: &personal_system::SystemEnrollRequest,
    target_path: &Path,
    enrolled_agent_id: &str,
) -> Result<()> {
    let service_exe = stage_windows_service_binary()?;

    let _ = crate::service::stop(target_path);
    let _ = crate::service::uninstall();

    crate::win_service::install(&service_exe)
        .context("installing MeshHarbor Windows SCM service")?;
    let _ = crate::win_service::environment::set_service_env_var(
        "MESHHARBORD_ENABLE_SYSTEM_SWAP",
        "1",
    );

    crate::exec_service::anchor_cli(crate::exec_service::AnchorAction::Create {
        server: req.server_url.clone(),
        token: req.enrollment_token.clone(),
        device: enrolled_agent_id.to_string(),
        force: true,
        exec_enabled: true,
        ssh: Some(meshharbor_remote_control::models::SshServiceCeiling::System),
    })
    .await
    .context("anchoring Windows SYSTEM exec and SSH capabilities")?;

    crate::win_service::environment::restart_service(std::time::Duration::from_secs(30))
        .context("starting MeshHarbor Windows SCM service")?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn activate_platform_system_service(
    req: &personal_system::SystemEnrollRequest,
    _target_path: &Path,
    _enrolled_agent_id: &str,
) -> Result<()> {
    ensure_linux_root_binary_and_unit()?;
    stop_linux_non_root_daemons(req.calling_uid);

    crate::service::install_system().context("enabling meshharbord.service")?;
    let status = std::process::Command::new("systemctl")
        .args(["restart", crate::service::system::LINUX_UNIT])
        .stdin(std::process::Stdio::null())
        .status()
        .context("restarting meshharbord.service")?;
    if !status.success() {
        bail!("systemctl restart {} exited with {status}", crate::service::system::LINUX_UNIT);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_linux_root_binary_and_unit() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let pkg_bin = Path::new("/usr/bin/meshharbord");
    let local_bin = Path::new("/usr/local/bin/meshharbord");
    let daemon_bin = if pkg_bin.is_file() {
        pkg_bin
    } else {
        let cur = std::env::current_exe().context("locating current meshharbord binary")?;
        if cur != local_bin {
            std::fs::create_dir_all("/usr/local/bin").context("creating /usr/local/bin")?;
            let tmp = Path::new("/usr/local/bin/.meshharbord.staging");
            let _ = std::fs::remove_file(tmp);
            std::fs::copy(&cur, tmp).context("staging /usr/local/bin/meshharbord")?;
            std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o755))?;
            std::fs::rename(tmp, local_bin).context("installing /usr/local/bin/meshharbord")?;
        }
        local_bin
    };

    let unit_exists = crate::service::system::LINUX_UNIT_FILES
        .iter()
        .any(|p| Path::new(p).exists());
    if !unit_exists {
        const SHIPPED_UNIT: &str = include_str!("../packaging/linux/meshharbord.service");
        let unit_body = if daemon_bin == pkg_bin {
            SHIPPED_UNIT.to_string()
        } else {
            SHIPPED_UNIT.replace(
                "ExecStart=/usr/bin/meshharbord ",
                "ExecStart=/usr/local/bin/meshharbord ",
            )
        };
        let etc_unit = Path::new("/etc/systemd/system/meshharbord.service");
        if let Some(parent) = etc_unit.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(etc_unit, unit_body.as_bytes())
            .context("writing /etc/systemd/system/meshharbord.service")?;
        std::fs::set_permissions(etc_unit, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stop_linux_non_root_daemons(calling_uid: Option<u32>) {
    if let Some(uid) = calling_uid.filter(|u| *u != 0) {
        let _ = std::process::Command::new("systemctl")
            .arg(format!("--machine={uid}@.host"))
            .args(["--user", "disable", "--now", "meshharbor.service"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let my_pid = std::process::id();
    let non_root_pids = || -> Vec<i32> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid == my_pid || pid <= 1 {
                continue;
            }
            let p = entry.path();
            let Ok(comm) = std::fs::read_to_string(p.join("comm")) else {
                continue;
            };
            if comm.trim() != "meshharbord" {
                continue;
            }
            let Ok(status) = std::fs::read_to_string(p.join("status")) else {
                continue;
            };
            let real_uid = status.lines().find_map(|line| {
                line.strip_prefix("Uid:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u32>()
                    .ok()
            });
            if real_uid.is_some_and(|u| u != 0) {
                out.push(pid as i32);
            }
        }
        out
    };

    let pids = non_root_pids();
    if pids.is_empty() {
        return;
    }
    for pid in &pids {
        unsafe {
            let _ = libc::kill(*pid, libc::SIGTERM);
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if non_root_pids().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
async fn activate_platform_system_service(
    req: &personal_system::SystemEnrollRequest,
    _target_path: &Path,
    _enrolled_agent_id: &str,
) -> Result<()> {
    if let Some(uid) = req.calling_uid.filter(|u| *u != 0) {
        let domain_service = format!("gui/{uid}/fans.itachi.meshharbor.agent");
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &domain_service])
            .stdin(std::process::Stdio::null())
            .output();
        let _ = std::process::Command::new("launchctl")
            .args(["disable", &domain_service])
            .stdin(std::process::Stdio::null())
            .output();
    }

    let dst_plist = Path::new("/Library/LaunchDaemons/fans.itachi.meshharbor.daemon.plist");
    let shipped_plist = Path::new("/Library/MeshHarbor/fans.itachi.meshharbor.daemon.plist");
    if !dst_plist.exists() && shipped_plist.is_file() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = dst_plist.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(shipped_plist, dst_plist)
            .context("installing fans.itachi.meshharbor.daemon.plist")?;
        std::fs::set_permissions(dst_plist, std::fs::Permissions::from_mode(0o644))?;
    }

    crate::service::install_system().context("enabling fans.itachi.meshharbor.daemon")?;
    let out = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", "system/fans.itachi.meshharbor.daemon"])
        .stdin(std::process::Stdio::null())
        .output()
        .context("restarting fans.itachi.meshharbor.daemon")?;
    if !out.status.success() {
        bail!(
            "launchctl kickstart failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}


/// Merge a newly approved personal account enrollment into `existing` at
/// `target_path`, turning on its overlay, promoting it to primary when the
/// existing primary was invitation-only (SIAT), and clearing any temporary
/// invitation marker on an enrollment that just became a personal account.
fn merge_and_promote_personal_enrollment(
    target_path: &Path,
    existing: Option<crate::config::AgentConfig>,
    fresh_cfg: crate::config::AgentConfig,
    replace: bool,
) -> Result<(crate::config::AgentConfig, crate::enrollment::EnrollOutcome)> {
    use crate::enrollment::EnrollOutcome;

    let markers = device_invite::read_markers(target_path);
    let old_primary = existing.as_ref().map(|c| c.agent_id.clone());
    let primary_was_invited = !replace
        && old_primary.as_ref().is_some_and(|id| {
            markers.contains_key(id) || markers.contains_key(device_invite::PRIMARY_KEY)
        });

    let (mut cfg, outcome) =
        crate::enrollment::apply_enrollment(existing, fresh_cfg, None, replace)
            .context("merging system enrollment")?;

    crate::org_join::apply_overlay_flag(&mut cfg, &outcome);

    match &outcome {
        EnrollOutcome::AppendedOrg { label } | EnrollOutcome::RefreshedOrg { label } => {
            if let Some(org_id) = cfg.find_org(label).map(|o| o.agent_id.clone()) {
                // This org is now a permanent personal enrollment, never temporary.
                let _ = device_invite::write_marker_for(target_path, &org_id, false, None);
            }
            if primary_was_invited {
                crate::config::promote_keeping_mesh(&mut cfg, label, None)
                    .context("promoting personal account beside invitations")?;
                if let (Some(id), Some(info)) =
                    (old_primary, markers.get(device_invite::PRIMARY_KEY))
                {
                    let _ = device_invite::write_marker_for(target_path, &id, true, Some(info));
                }
            }
        }
        EnrollOutcome::FreshPrimary
        | EnrollOutcome::RefreshedPrimary
        | EnrollOutcome::ReplacedPrimary => {
            if let Some(ref old_id) = old_primary
                && old_id != &cfg.agent_id
            {
                let _ = device_invite::write_marker_for(target_path, old_id, true, None);
            }
            let _ = device_invite::write_marker_for(target_path, &cfg.agent_id, true, None);
        }
    }

    Ok((cfg, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_cfg(server: &str, tenant: &str, agent_id: &str, name: &str) -> crate::config::AgentConfig {
        toml::from_str(&format!(
            "server_url = {server:?}\ntenant_id = {tenant:?}\nagent_id = {agent_id:?}\nagent_token = \"tok-{agent_id}\"\nmachine_id = \"mid-test-001\"\nmachine_name = {name:?}\n"
        ))
        .unwrap()
    }

    #[test]
    fn same_org_siat_conversion_clears_temporary_marker_and_enables_overlay() {
        let dir = std::env::temp_dir().join(format!(
            "mh-psexec-same-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");

        let existing = mk_cfg("https://mh.example", "t1", "aid-siat", "my-box");
        crate::config::save(&target, &existing).unwrap();
        std::fs::write(
            dir.join("temporary.json"),
            r#"{"access_until_ms":1900000000000,"inviter":"Prof"}"#,
        )
        .unwrap();

        let fresh = mk_cfg("https://mh.example", "t1", "aid-siat", "my-box");
        let (merged, _outcome) =
            merge_and_promote_personal_enrollment(&target, Some(existing), fresh, false).unwrap();
        assert!(merged.overlay_enabled, "personal login enables primary overlay");
        let markers = device_invite::read_markers(&target);
        assert!(
            markers.is_empty(),
            "same-org personal conversion must clear temporary SIAT marker: {markers:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_org_siat_conversion_promotes_personal_to_primary_and_keeps_invitation_marker() {
        let dir = std::env::temp_dir().join(format!(
            "mh-psexec-cross-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");

        let existing = mk_cfg("https://mh.example", "tenant-siat", "aid-siat", "my-box");
        crate::config::save(&target, &existing).unwrap();
        std::fs::write(
            dir.join("temporary.json"),
            r#"{"access_until_ms":1900000000000,"inviter":"Prof"}"#,
        )
        .unwrap();

        let fresh = mk_cfg("https://mh.example", "tenant-own", "aid-own", "my-box");
        let (merged, _outcome) =
            merge_and_promote_personal_enrollment(&target, Some(existing), fresh, false).unwrap();
        assert_eq!(merged.agent_id, "aid-own");
        assert_eq!(merged.tenant_id, "tenant-own");
        assert_eq!(merged.orgs.len(), 1);
        assert_eq!(merged.orgs[0].agent_id, "aid-siat");

        let markers = device_invite::read_markers(&target);
        assert!(!markers.contains_key(device_invite::PRIMARY_KEY));
        assert!(!markers.contains_key("aid-own"));
        assert!(
            markers.contains_key("aid-siat"),
            "demoted SIAT invitation must keep its temporary marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_org_siat_conversion_with_keyed_marker_and_history_merge() {
        let dir = std::env::temp_dir().join(format!(
            "mh-psexec-keyed-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");

        let existing = mk_cfg("https://mh.example", "tenant-siat", "aid-siat", "my-box");
        crate::config::save(&target, &existing).unwrap();
        std::fs::write(
            dir.join("temporary.json"),
            r#"{"enrollments":{"aid-siat":{"access_until_ms":1900000000000,"inviter":"Prof"}}}"#,
        )
        .unwrap();
        merge_seed_invitation_history(
            &target,
            Some(r#"[{"invite_id":"inv-1","proof":"secret","server_url":"https://mh.example","tenant_id":"tenant-siat","org":"SIAT","inviter":"Prof","access_until_ms":1900000000000,"accepted_at_ms":1800000000000}]"#),
        );

        let fresh = mk_cfg("https://mh.example", "tenant-own", "aid-own", "my-box");
        let (merged, _outcome) =
            merge_and_promote_personal_enrollment(&target, Some(existing), fresh, false).unwrap();
        assert_eq!(merged.agent_id, "aid-own");
        assert!(merged.overlay_enabled, "promoted primary must keep its overlay enabled");
        assert_eq!(merged.orgs.len(), 1);
        assert_eq!(merged.orgs[0].agent_id, "aid-siat");

        let markers = device_invite::read_markers(&target);
        assert!(markers.contains_key("aid-siat"));
        assert!(!markers.contains_key("aid-own"));

        let hist = device_invite::read_history(&target);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].invite_id, "inv-1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
