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
use std::collections::{BTreeMap, HashSet};
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

    let ParsedSeedInputs {
        cfg: seed_cfg,
        markers: seed_markers,
        history: seed_history,
    } = parse_seed_migration_inputs(&req)?;

    #[cfg(windows)]
    let (target_path, existing_sys) = {
        let p = crate::config::machine_global_config_path();
        let existing = win_security::prepare_and_load_trusted_windows_config(&p)?;
        (p, existing)
    };
    #[cfg(not(windows))]
    let (target_path, existing_sys) = {
        use std::os::unix::fs::PermissionsExt;
        let p = PathBuf::from(crate::service::system::CONFIG);
        ensure_trusted_unix_config_paths(&p)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        ensure_trusted_unix_config_paths(&p)?;
        let existing = if p.exists() {
            Some(crate::config::load(&p).context("reading existing system config")?)
        } else {
            None
        };
        (p, existing)
    };

    let machine_id = existing_sys
        .as_ref()
        .map(|cfg| cfg.machine_id.clone())
        .or_else(|| seed_cfg.as_ref().map(|cfg| cfg.machine_id.clone()))
        .unwrap_or_else(|| crate::machine::derive_machine_id(&target_path));

    let existing_identity = existing_sys
        .as_ref()
        .and_then(|cfg| {
            crate::enrollment::existing_identity_for(cfg, &req.server_url, &req.enrollment_token)
        })
        .or_else(|| {
            seed_cfg.as_ref().and_then(|cfg| {
                crate::enrollment::existing_identity_for(
                    cfg,
                    &req.server_url,
                    &req.enrollment_token,
                )
            })
        });

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
        existing_identity,
    )
    .await
    .context("enrolling device with server")?;

    let combined_existing = fold_seeded_user_config(
        &target_path,
        existing_sys,
        seed_cfg,
        &seed_markers,
        &fresh_cfg,
        req.replace,
    )?;
    merge_seed_invitation_history(&target_path, &seed_history)?;

    let enrolled_agent_id = fresh_cfg.agent_id.clone();
    let (mut cfg, outcome) = merge_and_promote_personal_enrollment(
        &target_path,
        combined_existing,
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

    #[cfg(not(windows))]
    ensure_trusted_unix_config_paths(&target_path)?;
    crate::config::save(&target_path, &cfg).context("saving system config")?;
    #[cfg(windows)]
    win_security::harden_saved_config_subtree(&target_path)?;

    let history = device_invite::read_history(&target_path);
    if !history.is_empty()
        && let Err(e) = device_invite::link(&cfg.server_url, &cfg.agent_token, &history).await
    {
        tracing::warn!(error = %e, "invitation history link will retry when the system daemon connects");
    }

    activate_platform_system_service(&req, &target_path, &enrolled_agent_id).await
}

#[cfg(not(windows))]
fn ensure_trusted_unix_config_paths(config_path: &Path) -> Result<()> {
    for candidate in [
        config_path.to_path_buf(),
        config_path.with_extension("toml.prev"),
        config_path.with_extension("toml.tmp"),
        device_invite::marker_path(config_path),
        device_invite::history_path(config_path),
    ] {
        if let Some(link) = personal_system::untrusted_promotion_link_component(&candidate) {
            bail!(
                "system config path {} contains untrusted symbolic link {}",
                candidate.display(),
                link.display()
            );
        }
    }
    Ok(())
}

/// Pure cross-OS helper: given `exe` and candidate `%ProgramFiles%` roots, returns
/// `(matched_pf_root, subdirs_strictly_between_pf_root_and_exe)` in top-down order.
/// Returns `None` if `exe` is outside `pf_roots` OR sits directly in `pf_root` with
/// no application subdirectory (`C:\Program Files\meshharbord.exe`).
#[cfg_attr(not(windows), allow(dead_code))]
fn pf_subdirs_between_root_and_exe(
    exe: &Path,
    pf_roots: &[PathBuf],
) -> Option<(PathBuf, Vec<PathBuf>)> {
    fn norm_parts(p: &Path) -> Vec<String> {
        p.to_string_lossy()
            .replace('/', "\\")
            .split('\\')
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect()
    }
    let exe_parts = norm_parts(exe);
    for root in pf_roots {
        let root_parts = norm_parts(root);
        if root_parts.is_empty() || exe_parts.len() <= root_parts.len() + 1 {
            continue;
        }
        let prefix_matches = root_parts
            .iter()
            .zip(exe_parts.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if !prefix_matches {
            continue;
        }
        let mut cur = root_parts.join("\\");
        let mut subdirs = Vec::new();
        for seg in &exe_parts[root_parts.len()..exe_parts.len() - 1] {
            cur.push('\\');
            cur.push_str(seg);
            subdirs.push(PathBuf::from(&cur));
        }
        if !subdirs.is_empty() {
            return Some((PathBuf::from(root_parts.join("\\")), subdirs));
        }
    }
    None
}

struct ParsedSeedInputs {
    cfg: Option<crate::config::AgentConfig>,
    markers: BTreeMap<String, device_invite::TemporaryInfo>,
    history: Vec<device_invite::HistoryEntry>,
}

fn parse_seed_migration_inputs(
    req: &personal_system::SystemEnrollRequest,
) -> Result<ParsedSeedInputs> {
    let cfg = match req.seed_config_toml.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(
            toml::from_str::<crate::config::AgentConfig>(raw)
                .context("parsing per-user config.toml snapshot for system migration")?,
        ),
        _ => None,
    };
    let markers = match req.seed_temporary_json.as_deref() {
        Some(raw) => device_invite::parse_markers_strict(raw)
            .context("parsing per-user temporary.json snapshot for system migration")?,
        None => BTreeMap::new(),
    };
    let history = match req.seed_history_json.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str::<Vec<device_invite::HistoryEntry>>(raw)
                .context("parsing per-user invites.json snapshot for system migration")?
        }
        _ => Vec::new(),
    };
    Ok(ParsedSeedInputs {
        cfg,
        markers,
        history,
    })
}

fn merge_seed_invitation_history(
    target_config: &Path,
    entries: &[device_invite::HistoryEntry],
) -> Result<()> {
    for entry in entries {
        device_invite::append_history(target_config, entry.clone())
            .context("merging per-user invitation history into system config")?;
    }
    Ok(())
}

fn same_org_identity(server_a: &str, tenant_a: &str, server_b: &str, tenant_b: &str) -> bool {
    device_invite::base(server_a) == device_invite::base(server_b) && tenant_a == tenant_b
}

/// Candidate enrollment extracted from a per-user `AgentConfig` snapshot.
struct SeedCandidate {
    label_hint: Option<String>,
    entry: crate::config::OrgEntry,
    marker: Option<device_invite::TemporaryInfo>,
}

fn candidates_from_user_config(
    u_cfg: crate::config::AgentConfig,
    seed_markers: &BTreeMap<String, device_invite::TemporaryInfo>,
) -> Vec<SeedCandidate> {
    let mut out = Vec::with_capacity(1 + u_cfg.orgs.len());
    let primary_marker = seed_markers
        .get(&u_cfg.agent_id)
        .or_else(|| seed_markers.get(device_invite::PRIMARY_KEY))
        .cloned();
    if !u_cfg.server_url.trim().is_empty()
        && !u_cfg.agent_id.trim().is_empty()
        && !u_cfg.agent_token.trim().is_empty()
    {
        let mode = if u_cfg.overlay_enabled {
            crate::config::OrgOverlayMode::Netstack
        } else {
            crate::config::OrgOverlayMode::Off
        };
        out.push(SeedCandidate {
            label_hint: None,
            entry: crate::config::OrgEntry {
                label: String::new(),
                server_url: u_cfg.server_url,
                ws_url: u_cfg.ws_url,
                agent_token: u_cfg.agent_token,
                agent_id: u_cfg.agent_id,
                tenant_id: u_cfg.tenant_id,
                enabled: true,
                overlay_mode: mode,
                overlay_wg_secret_key: u_cfg.overlay_wg_secret_key,
                overlay_wg_key_epoch: u_cfg.overlay_wg_key_epoch,
                overlay_advertised_routes: u_cfg.overlay_advertised_routes,
                overlay_exit_node_enabled: u_cfg.overlay_exit_node_enabled,
                advertise_routes: u_cfg.advertise_routes,
                netstack_socks_port: None,
            },
            marker: primary_marker,
        });
    }
    for org in u_cfg.orgs {
        if org.server_url.trim().is_empty()
            || org.agent_id.trim().is_empty()
            || org.agent_token.trim().is_empty()
        {
            continue;
        }
        let marker = seed_markers.get(&org.agent_id).cloned();
        let hint = Some(org.label.clone());
        out.push(SeedCandidate {
            label_hint: hint,
            entry: org,
            marker,
        });
    }
    out
}

/// Fold any per-user enrollments and `temporary.json` markers into `existing_sys`
/// BEFORE `merge_and_promote_personal_enrollment` runs, ensuring zero per-user
/// enrollments (e.g. SIAT invitations) are ever lost when user files are retired.
fn fold_seeded_user_config(
    target_path: &Path,
    existing_sys: Option<crate::config::AgentConfig>,
    seed_cfg: Option<crate::config::AgentConfig>,
    seed_markers: &BTreeMap<String, device_invite::TemporaryInfo>,
    fresh_cfg: &crate::config::AgentConfig,
    replace: bool,
) -> Result<Option<crate::config::AgentConfig>> {
    let Some(u_cfg) = seed_cfg else {
        return Ok(existing_sys);
    };

    let Some(mut sys_cfg) = existing_sys else {
        let primary_id = u_cfg.agent_id.clone();
        for (key, info) in seed_markers {
            if key == device_invite::PRIMARY_KEY {
                if !primary_id.is_empty() {
                    device_invite::write_marker_for(target_path, &primary_id, true, Some(info))
                        .context("seeding primary temporary marker")?;
                }
            } else {
                let is_prim = key == &primary_id;
                device_invite::write_marker_for(target_path, key, is_prim, Some(info))
                    .context("seeding temporary marker")?;
            }
        }
        return Ok(Some(u_cfg));
    };

    let sys_markers = device_invite::read_markers(target_path);
    for mut cand in candidates_from_user_config(u_cfg, seed_markers) {
        let existing_match_id =
            if same_org_identity(&sys_cfg.server_url, &sys_cfg.tenant_id, &cand.entry.server_url, &cand.entry.tenant_id) {
                Some((true, sys_cfg.agent_id.clone()))
            } else {
                sys_cfg
                    .orgs
                    .iter()
                    .find(|o| {
                        same_org_identity(
                            &o.server_url,
                            &o.tenant_id,
                            &cand.entry.server_url,
                            &cand.entry.tenant_id,
                        )
                    })
                    .map(|o| (false, o.agent_id.clone()))
            };

        if let Some((is_sys_primary, sys_agent_id)) = existing_match_id {
            if sys_agent_id == cand.entry.agent_id {
                if let Some(ref info) = cand.marker
                    && !sys_markers.contains_key(&sys_agent_id)
                {
                    device_invite::write_marker_for(
                        target_path,
                        &sys_agent_id,
                        is_sys_primary,
                        Some(info),
                    )
                    .context("preserving temporary marker on shared enrollment")?;
                }
                continue;
            }
            let refreshed_by_login = same_org_identity(
                &cand.entry.server_url,
                &cand.entry.tenant_id,
                &fresh_cfg.server_url,
                &fresh_cfg.tenant_id,
            );
            if refreshed_by_login {
                continue;
            }
            if replace && is_sys_primary {
                // `sys_cfg` primary is about to be replaced by `fresh_cfg`; keep
                // this user enrollment in `[[orgs]]` under a temporary non-colliding
                // slot only if it does not duplicate `fresh_cfg` (checked above).
                // Clear `sys_cfg`'s outgoing primary identity match by falling through
                // after `apply_enrollment(..., force_replace=true)`? No: `apply_enrollment`
                // drops orgs matching the NEW primary, not the old primary, so pushing
                // into `sys_cfg.orgs` right now is safe and `validate_orgs` passes once
                // `fresh_cfg` replaces `sys_cfg`'s primary!
            } else {
                bail!(
                    "per-user config holds a distinct enrollment ({}) for {} (tenant {}) \
                     while system config already holds ({}); refusing to retire per-user \
                     credentials automatically",
                    cand.entry.agent_id,
                    cand.entry.server_url,
                    cand.entry.tenant_id,
                    sys_agent_id
                );
            }
        }

        // Normalize `Tun` on a migrated secondary when multi-org TUN prerequisites
        // are not active on `sys_cfg`, keeping the org reachable via userspace netstack.
        if cand.entry.overlay_mode == crate::config::OrgOverlayMode::Tun
            && (!sys_cfg.overlay_multi_org
                || device_invite::base(&sys_cfg.server_url)
                    != device_invite::base(&cand.entry.server_url))
        {
            cand.entry.overlay_mode = crate::config::OrgOverlayMode::Netstack;
        }

        let label = cand
            .label_hint
            .as_deref()
            .and_then(|h| crate::enrollment::unique_org_label(&sys_cfg, Some(h), &cand.entry.server_url).ok())
            .map(Ok)
            .unwrap_or_else(|| {
                crate::enrollment::unique_org_label(&sys_cfg, None, &cand.entry.server_url)
            })?;
        cand.entry.label = label;
        let aid = cand.entry.agent_id.clone();
        sys_cfg.orgs.push(cand.entry);
        if let Some(ref info) = cand.marker {
            device_invite::write_marker_for(target_path, &aid, false, Some(info))
                .context("migrating per-user temporary invitation marker")?;
        }
    }

    Ok(Some(sys_cfg))
}

#[cfg(windows)]
mod win_security {
    use anyhow::{Context, Result, bail};
    use std::io::Read;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, LUID, LocalFree};
    use std::path::PathBuf;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, AdjustTokenPrivileges,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, IsWellKnownSid,
        LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, SetFileSecurityW, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Administrators own it; SYSTEM and Administrators alone have Full Access; inheritance off.
    pub(super) const DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    pub(super) const FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    /// `%ProgramFiles%\MeshHarbor`: Administrators own it; SYSTEM + Administrators Full Access;
    /// Builtin Users read+execute (`0x1200a9`); inheritance off.
    pub(super) const PF_DIR_SDDL: &str =
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    pub(super) const PF_FILE_SDDL: &str =
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";

    const WRITE_LIKE: u32 = 0x2 // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x4 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x10 // FILE_WRITE_EA
        | 0x40 // FILE_DELETE_CHILD
        | 0x100 // FILE_WRITE_ATTRIBUTES
        | 0x1_0000 // DELETE
        | 0x4_0000 // WRITE_DAC
        | 0x8_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const INHERIT_ONLY_ACE: u8 = 0x08;
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

    struct Sddl {
        sa: SECURITY_ATTRIBUTES,
        psd: PSECURITY_DESCRIPTOR,
    }

    impl Sddl {
        fn new(sddl: &str) -> std::io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: NUL-terminated UTF-16 string; `psd` freed in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut psd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                sa: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: psd,
                    bInheritHandle: 0,
                },
                psd,
            })
        }

        fn attributes(&mut self) -> *mut SECURITY_ATTRIBUTES {
            &raw mut self.sa
        }
    }

    impl Drop for Sddl {
        fn drop(&mut self) {
            // SAFETY: `psd` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.psd as _) };
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_well_known(sid: PSID, kind: i32) -> bool {
        !sid.is_null() && unsafe { IsWellKnownSid(sid, kind) } != 0
    }

    fn is_trusted_sid(sid: PSID) -> bool {
        is_well_known(sid, WinLocalSystemSid) || is_well_known(sid, WinBuiltinAdministratorsSid)
    }

    fn is_trusted_installer_sid(sid: PSID) -> bool {
        if sid.is_null() {
            return false;
        }
        // NT SERVICE\TrustedInstaller: S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        const TI_SDDL_SID: &str =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        let wsid: Vec<u16> = TI_SDDL_SID.encode_utf16().chain(std::iter::once(0)).collect();
        let mut ti_psid: PSID = std::ptr::null_mut();
        // SAFETY: NUL-terminated string SID; `ti_psid` freed via LocalFree on success.
        let ok = unsafe { ConvertStringSidToSidW(wsid.as_ptr(), &mut ti_psid) };
        if ok == 0 || ti_psid.is_null() {
            return false;
        }
        let eq = unsafe { EqualSid(sid, ti_psid) != 0 };
        unsafe { LocalFree(ti_psid as _) };
        eq
    }

    fn is_pf_trusted_sid(sid: PSID) -> bool {
        is_trusted_sid(sid) || is_trusted_installer_sid(sid)
    }

    pub(super) fn enable_admin_security_privileges() {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            ) == 0
            {
                return;
            }
            for priv_name in ["SeTakeOwnershipPrivilege", "SeRestorePrivilege"] {
                let wname: Vec<u16> = priv_name.encode_utf16().chain(std::iter::once(0)).collect();
                let mut luid = LUID {
                    LowPart: 0,
                    HighPart: 0,
                };
                if LookupPrivilegeValueW(std::ptr::null(), wname.as_ptr(), &mut luid) != 0 {
                    let tp = TOKEN_PRIVILEGES {
                        PrivilegeCount: 1,
                        Privileges: [LUID_AND_ATTRIBUTES {
                            Luid: luid,
                            Attributes: SE_PRIVILEGE_ENABLED,
                        }],
                    };
                    let _ = AdjustTokenPrivileges(
                        token,
                        0,
                        &tp,
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
            }
            let _ = CloseHandle(token);
        }
    }

    fn check_security_handle(
        handle: HANDLE,
        what: &Path,
        require_no_untrusted_writers: bool,
    ) -> Result<()> {
        check_security_handle_with(handle, what, require_no_untrusted_writers, false)
    }

    fn check_pf_security_handle(
        handle: HANDLE,
        what: &Path,
        require_no_untrusted_writers: bool,
    ) -> Result<()> {
        check_security_handle_with(handle, what, require_no_untrusted_writers, true)
    }

    fn check_security_handle_with(
        handle: HANDLE,
        what: &Path,
        require_no_untrusted_writers: bool,
        allow_trusted_installer: bool,
    ) -> Result<()> {
        let sid_ok = |sid: PSID| {
            if allow_trusted_installer {
                is_pf_trusted_sid(sid)
            } else {
                is_trusted_sid(sid)
            }
        };
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `handle` is live with READ_CONTROL; `psd` freed below.
        let rc = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut psd,
            )
        };
        if rc != 0 {
            bail!(
                "reading security descriptor of {}: Win32 error {rc}",
                what.display()
            );
        }
        let verdict = (|| -> Result<()> {
            if !sid_ok(owner) {
                bail!(
                    "{} is not owned by a trusted system/administrator principal; refusing untrusted object",
                    what.display()
                );
            }
            if !require_no_untrusted_writers {
                return Ok(());
            }
            if dacl.is_null() {
                bail!("{} has a NULL DACL (writable by everyone)", what.display());
            }
            let mut info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            // SAFETY: `dacl` is valid inside `psd`.
            let ok = unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut info).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            };
            if ok == 0 {
                bail!("reading DACL information of {}", what.display());
            }
            for i in 0..info.AceCount {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 || ace.is_null() {
                    bail!("reading ACE #{i} of {}", what.display());
                }
                let header = unsafe { &*(ace as *const ACE_HEADER) };
                if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                match header.AceType {
                    ACCESS_DENIED_ACE_TYPE => continue,
                    ACCESS_ALLOWED_ACE_TYPE => {
                        let mask = unsafe {
                            std::ptr::read_unaligned((ace as *const u8).add(4) as *const u32)
                        };
                        let sid = unsafe { (ace as *mut u8).add(8) } as PSID;
                        if mask & WRITE_LIKE != 0 && !sid_ok(sid) {
                            bail!(
                                "{} grants write-like access (mask 0x{mask:08x}) to a non-admin principal; refusing untrusted object",
                                what.display()
                            );
                        }
                    }
                    other => {
                        bail!(
                            "{} contains unrecognized ACE type {other}; failing closed",
                            what.display()
                        );
                    }
                }
            }
            Ok(())
        })();
        unsafe { LocalFree(psd as _) };
        verdict
    }

    pub(super) fn apply_sddl_to_path(path: &Path, sddl: &str) -> Result<()> {
        let sd = Sddl::new(sddl)
            .with_context(|| format!("compiling SDDL for {}", path.display()))?;
        let wpath = wide(path);
        // SAFETY: `wpath` is NUL-terminated and `sd.psd` outlives the call.
        let ok = unsafe {
            SetFileSecurityW(
                wpath.as_ptr(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.psd,
            )
        };
        if ok == 0 {
            bail!(
                "applying protected security descriptor to {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    fn open_plain_dir_handle(dir: &Path) -> Result<Option<std::fs::File>> {
        let f = match std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => bail!("opening directory {}: {e}", dir.display()),
        };
        let meta = f
            .metadata()
            .with_context(|| format!("stat directory {}", dir.display()))?;
        if !meta.is_dir() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            bail!("{} is not a plain non-reparse directory", dir.display());
        }
        Ok(Some(f))
    }

    pub(super) fn ensure_trusted_directory(
        dir: &Path,
        sddl: &str,
        require_existing_dacl_clean: bool,
    ) -> Result<()> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(dir) {
            bail!(
                "refusing symbolic link or junction component {} on {}",
                link.display(),
                dir.display()
            );
        }
        if let Some(existing_handle) = open_plain_dir_handle(dir)? {
            check_security_handle(
                existing_handle.as_raw_handle() as HANDLE,
                dir,
                require_existing_dacl_clean,
            )?;
            drop(existing_handle);
            apply_sddl_to_path(dir, sddl)?;
        } else {
            if let Some(parent) = dir.parent()
                && !parent.exists()
            {
                bail!("parent directory {} does not exist", parent.display());
            }
            let mut sd = Sddl::new(sddl)
                .with_context(|| format!("compiling directory SDDL for {}", dir.display()))?;
            let wdir = wide(dir);
            // SAFETY: NUL-terminated `wdir`, valid `SECURITY_ATTRIBUTES`.
            if unsafe { CreateDirectoryW(wdir.as_ptr(), sd.attributes()) } == 0 {
                let err = std::io::Error::last_os_error();
                bail!("creating secure directory {}: {err}", dir.display());
            }
        }
        let verified = open_plain_dir_handle(dir)?
            .ok_or_else(|| anyhow::anyhow!("directory {} disappeared after creation", dir.display()))?;
        check_security_handle(verified.as_raw_handle() as HANDLE, dir, true)
    }

    fn open_verified_private_file(path: &Path) -> Result<Option<(std::fs::File, u64)>> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(path) {
            bail!(
                "refusing symbolic link or junction component {} on {}",
                link.display(),
                path.display()
            );
        }
        let f = match std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => bail!("opening {}: {e}", path.display()),
        };
        let raw_h = f.as_raw_handle() as HANDLE;
        if unsafe { GetFileType(raw_h) } != FILE_TYPE_DISK {
            bail!("{} is not a regular disk file", path.display());
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(raw_h, &mut info) } == 0 {
            bail!(
                "GetFileInformationByHandle({}): {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        const FORBIDDEN: u32 =
            FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE;
        if (info.dwFileAttributes & FORBIDDEN) != 0 || info.nNumberOfLinks != 1 {
            bail!(
                "{} must be a single-link non-reparse regular file",
                path.display()
            );
        }
        check_security_handle(raw_h, path, true)?;
        let size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
        Ok(Some((f, size)))
    }

    pub(super) fn prepare_and_load_trusted_windows_config(
        config_path: &Path,
    ) -> Result<Option<crate::config::AgentConfig>> {
        enable_admin_security_privileges();
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(config_path) {
            bail!(
                "machine-global config path {} contains link/junction {}",
                config_path.display(),
                link.display()
            );
        }
        let config_dir = config_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("config path {} has no parent", config_path.display()))?;
        let root_dir = config_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("config dir {} has no parent", config_dir.display()))?;

        // `root_dir` (`%ProgramData%\meshharbor`): must be owned by SYSTEM/Administrators
        // if already present (refuses attacker-precreated ProgramData\meshharbor), then
        // locked down to DIR_SDDL.
        ensure_trusted_directory(root_dir, DIR_SDDL, false)?;
        // `config_dir` (`%ProgramData%\meshharbor\meshharbor`): if already present, must
        // ALREADY have both trusted owner AND zero non-admin writers before anything inside
        // it is trusted.
        ensure_trusted_directory(config_dir, DIR_SDDL, true)?;

        for sidecar in [
            config_path.with_extension("toml.prev"),
            meshharbor_node_core::device_invite::marker_path(config_path),
            meshharbor_node_core::device_invite::history_path(config_path),
        ] {
            if let Some((f, _len)) = open_verified_private_file(&sidecar)? {
                drop(f);
                apply_sddl_to_path(&sidecar, FILE_SDDL)?;
            }
        }

        let Some((file, len)) = open_verified_private_file(config_path)? else {
            return Ok(None);
        };
        if len > MAX_CONFIG_BYTES {
            bail!(
                "existing system config {} exceeds {} bytes",
                config_path.display(),
                MAX_CONFIG_BYTES
            );
        }
        let mut raw = String::new();
        (&file)
            .take(MAX_CONFIG_BYTES)
            .read_to_string(&mut raw)
            .with_context(|| format!("reading verified system config {}", config_path.display()))?;
        drop(file);
        apply_sddl_to_path(config_path, FILE_SDDL)?;
        let parsed: crate::config::AgentConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing verified system config {}", config_path.display()))?;
        Ok(Some(parsed))
    }

    pub(super) fn harden_saved_config_subtree(config_path: &Path) -> Result<()> {
        let Some(config_dir) = config_path.parent() else {
            return Ok(());
        };
        if let Some(root_dir) = config_dir.parent() {
            ensure_trusted_directory(root_dir, DIR_SDDL, true)?;
        }
        ensure_trusted_directory(config_dir, DIR_SDDL, true)?;
        for file_path in [
            config_path.to_path_buf(),
            config_path.with_extension("toml.prev"),
            meshharbor_node_core::device_invite::marker_path(config_path),
            meshharbor_node_core::device_invite::history_path(config_path),
        ] {
            if file_path.exists() {
                apply_sddl_to_path(&file_path, FILE_SDDL)?;
                let verified = open_verified_private_file(&file_path)?.ok_or_else(|| {
                    anyhow::anyhow!("{} disappeared during security verification", file_path.display())
                })?;
                drop(verified);
            }
        }
        Ok(())
    }

    pub(super) fn verify_pf_root_readonly(pf_root: &Path) -> Result<()> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(pf_root) {
            bail!(
                "ProgramFiles root {} contains symbolic link or junction {}",
                pf_root.display(),
                link.display()
            );
        }
        let handle = open_plain_dir_handle(pf_root)?
            .ok_or_else(|| anyhow::anyhow!("ProgramFiles root {} does not exist", pf_root.display()))?;
        check_pf_security_handle(handle.as_raw_handle() as HANDLE, pf_root, true)
    }

    pub(super) fn ensure_trusted_pf_directory(dir: &Path) -> Result<()> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(dir) {
            bail!(
                "refusing symbolic link or junction component {} on {}",
                link.display(),
                dir.display()
            );
        }
        if let Some(existing_handle) = open_plain_dir_handle(dir)? {
            check_pf_security_handle(existing_handle.as_raw_handle() as HANDLE, dir, true)?;
            drop(existing_handle);
            apply_sddl_to_path(dir, PF_DIR_SDDL)?;
        } else {
            if let Some(parent) = dir.parent()
                && !parent.exists()
            {
                bail!("parent directory {} does not exist", parent.display());
            }
            let mut sd = Sddl::new(PF_DIR_SDDL)
                .with_context(|| format!("compiling PF_DIR_SDDL for {}", dir.display()))?;
            let wdir = wide(dir);
            if unsafe { CreateDirectoryW(wdir.as_ptr(), sd.attributes()) } == 0 {
                let err = std::io::Error::last_os_error();
                bail!("creating secure ProgramFiles directory {}: {err}", dir.display());
            }
        }
        let verified = open_plain_dir_handle(dir)?.ok_or_else(|| {
            anyhow::anyhow!("ProgramFiles directory {} disappeared after hardening", dir.display())
        })?;
        check_security_handle(verified.as_raw_handle() as HANDLE, dir, true)
    }

    fn verify_and_harden_pf_file(path: &Path) -> Result<()> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(path) {
            bail!(
                "refusing symbolic link or junction component {} on {}",
                link.display(),
                path.display()
            );
        }
        // Allow FILE_SHARE_READ | FILE_SHARE_DELETE so an executing service/CLI binary
        // can be inspected without ERROR_SHARING_VIOLATION, while still denying
        // FILE_SHARE_WRITE so any open writer handle fails closed immediately.
        let open_pf_readonly = || -> Result<std::fs::File> {
            let f = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .with_context(|| format!("opening ProgramFiles binary/asset {}", path.display()))?;
            let raw_h = f.as_raw_handle() as HANDLE;
            if unsafe { GetFileType(raw_h) } != FILE_TYPE_DISK {
                bail!("{} is not a regular disk file", path.display());
            }
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandle(raw_h, &mut info) } == 0 {
                bail!(
                    "GetFileInformationByHandle({}): {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
            const FORBIDDEN: u32 =
                FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE;
            if (info.dwFileAttributes & FORBIDDEN) != 0 || info.nNumberOfLinks != 1 {
                bail!(
                    "{} must be a single-link non-reparse regular file",
                    path.display()
                );
            }
            Ok(f)
        };

        let pre = open_pf_readonly()?;
        check_pf_security_handle(pre.as_raw_handle() as HANDLE, path, true)?;
        drop(pre);

        apply_sddl_to_path(path, PF_FILE_SDDL)?;

        let post = open_pf_readonly()?;
        check_security_handle(post.as_raw_handle() as HANDLE, path, true)
    }

    pub(super) fn verify_and_harden_pf_dir_entries(dir: &Path, depth: usize) -> Result<()> {
        if depth > 4 {
            bail!(
                "ProgramFiles install directory {} exceeds maximum nesting depth",
                dir.display()
            );
        }
        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("reading ProgramFiles directory {}", dir.display()))?
        {
            let entry = entry?;
            let p = entry.path();
            let meta = std::fs::symlink_metadata(&p)
                .with_context(|| format!("stat {}", p.display()))?;
            if meta.file_type().is_symlink()
                || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            {
                bail!("refusing reparse point {} inside {}", p.display(), dir.display());
            }
            if meta.is_dir() {
                ensure_trusted_pf_directory(&p)?;
                verify_and_harden_pf_dir_entries(&p, depth + 1)?;
            } else if meta.is_file() {
                verify_and_harden_pf_file(&p)?;
            } else {
                bail!("refusing non-regular entry {} inside {}", p.display(), dir.display());
            }
        }
        Ok(())
    }

    pub(super) fn verify_and_harden_program_files_install(
        exe: &Path,
        pf_roots: &[PathBuf],
    ) -> Result<()> {
        if let Some(link) = meshharbor_node_core::recording_dir::link_component(exe) {
            bail!(
                "ProgramFiles executable {} contains symbolic link or junction {}",
                exe.display(),
                link.display()
            );
        }
        let (pf_root, subdirs) = super::pf_subdirs_between_root_and_exe(exe, pf_roots)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} is not inside a dedicated subdirectory under ProgramFiles",
                    exe.display()
                )
            })?;
        verify_pf_root_readonly(&pf_root)?;
        for sub in &subdirs {
            ensure_trusted_pf_directory(sub)?;
        }
        verify_and_harden_pf_file(exe)?;
        if let Some(install_dir) = subdirs.last() {
            verify_and_harden_pf_dir_entries(install_dir, 0)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn stage_windows_service_binary() -> Result<PathBuf> {
    win_security::enable_admin_security_privileges();
    let current = std::env::current_exe().context("locating current meshharbord.exe")?;
    let pf_roots = meshharbor_node_core::companion_autostart::program_files_dirs();
    if personal_system::is_trusted_windows_service_exe(&current, &pf_roots)
        && pf_subdirs_between_root_and_exe(&current, &pf_roots).is_some()
        && meshharbor_node_core::recording_dir::link_component(&current).is_none()
    {
        win_security::verify_and_harden_program_files_install(&current, &pf_roots)?;
        return Ok(current);
    }

    let pf_base = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("ProgramFiles environment variable is missing"))?;
    win_security::verify_pf_root_readonly(&pf_base)?;

    let install_dir = pf_base.join("MeshHarbor");
    win_security::ensure_trusted_pf_directory(&install_dir)?;
    win_security::verify_and_harden_pf_dir_entries(&install_dir, 0)?;

    let staged_exe = install_dir.join("meshharbord.exe");
    copy_replacing_windows_file(&current, &staged_exe)?;

    if let Some(src_dir) = current.parent() {
        for sibling in [
            "meshharbor.exe",
            "meshharbor-agent.exe",
            "mh.exe",
            "meshharbor-shim.exe",
            "meshharbor-desktop.exe",
            "wintun.dll",
            "msvcp140.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
        ] {
            let s = src_dir.join(sibling);
            if s.is_file() {
                copy_replacing_windows_file(&s, &install_dir.join(sibling))?;
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
    win_security::verify_and_harden_program_files_install(&staged_exe, &refreshed_roots)?;
    Ok(staged_exe)
}

#[cfg(windows)]
fn copy_replacing_windows_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(link) = meshharbor_node_core::recording_dir::link_component(dst) {
        bail!(
            "refusing to stage binary over symbolic link or junction {}",
            link.display()
        );
    }
    let fname = dst
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("destination {} has no file name", dst.display()))?
        .to_string_lossy();
    let tmp = dst.with_file_name(format!("{fname}.staging"));
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(src, &tmp)
        .with_context(|| format!("staging {} -> {}", src.display(), tmp.display()))?;
    win_security::apply_sddl_to_path(&tmp, win_security::PF_FILE_SDDL)?;
    if dst.exists() {
        let old = dst.with_file_name(format!("{fname}.old"));
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(dst, &old);
        std::fs::rename(&tmp, dst)
            .with_context(|| format!("activating staged binary {}", dst.display()))?;
        let _ = std::fs::remove_file(&old);
    } else {
        std::fs::rename(&tmp, dst)
            .with_context(|| format!("activating staged binary {}", dst.display()))?;
    }
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
    target_path: &Path,
    _enrolled_agent_id: &str,
) -> Result<()> {
    ensure_linux_root_binary_and_unit()?;

    // Verify all service-installation preconditions AND systemd availability
    // BEFORE stopping any existing non-root user daemon.
    let shipped = crate::service::system::LINUX_UNIT_FILES
        .iter()
        .any(|p| Path::new(p).exists());
    if let Some(why) = crate::service::system::install_refusal(
        crate::service::system::Os::Linux,
        crate::appdirs::running_as_root(),
        shipped,
        target_path.exists(),
    ) {
        bail!("{why}");
    }
    let reload = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .stdin(std::process::Stdio::null())
        .output()
        .context("running systemctl daemon-reload")?;
    if !reload.status.success() {
        bail!(
            "systemctl daemon-reload failed: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        );
    }

    stop_linux_non_root_daemons(req.calling_uid);

    crate::service::install_system().context("enabling meshharbord.service")?;
    let status = std::process::Command::new("systemctl")
        .args(["restart", crate::service::system::LINUX_UNIT])
        .stdin(std::process::Stdio::null())
        .status()
        .context("restarting meshharbord.service")?;
    if !status.success() {
        bail!(
            "systemctl restart {} exited with {status}",
            crate::service::system::LINUX_UNIT
        );
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
        let tmp_unit = Path::new("/etc/systemd/system/.meshharbord.service.staging");
        let _ = std::fs::remove_file(tmp_unit);
        std::fs::write(tmp_unit, unit_body.as_bytes())
            .context("writing /etc/systemd/system/meshharbord.service")?;
        std::fs::set_permissions(tmp_unit, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(tmp_unit, etc_unit)
            .context("installing /etc/systemd/system/meshharbord.service")?;
    }
    Ok(())
}

/// True iff `/proc/<pid>/cmdline` (NUL-separated argv) represents an actual
/// `meshharbord` daemon instance (`run` subcommand or default subcommand-less
/// invocation), NEVER a CLI verb such as `login`, `enroll-personal-system`,
/// `status`, `ssh`, `service`, etc.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_meshharbord_daemon_cmdline(cmdline: &[u8]) -> bool {
    let mut parts: Vec<&str> = match std::str::from_utf8(cmdline) {
        Ok(s) => s.split('\0').collect(),
        Err(_) => return false,
    };
    while parts.last().is_some_and(|s| s.is_empty()) {
        parts.pop();
    }
    let Some(argv0) = parts.first().copied() else {
        return false;
    };
    let Some(bin_name) = Path::new(argv0).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if bin_name != "meshharbord" && bin_name != "meshharbor-agent" {
        return false;
    }

    let args = &parts[1..];
    for arg in args {
        if matches!(*arg, "-h" | "--help" | "-V" | "--version" | "--supervised") {
            return false;
        }
    }

    let mut idx = 0usize;
    let mut subcommand: Option<&str> = None;
    while idx < args.len() {
        let tok = args[idx];
        if tok == "--config" {
            if idx + 1 >= args.len() {
                return false;
            }
            idx += 2;
            continue;
        }
        if tok.starts_with("--config=") {
            idx += 1;
            continue;
        }
        if tok.starts_with('-') {
            // Unknown top-level flag before a subcommand is not a valid bare daemon.
            return false;
        }
        subcommand = Some(tok);
        break;
    }

    matches!(subcommand, None | Some("run"))
}

/// Walk `PPid:` in `<proc_root>/<pid>/status` to collect `start_pid` and all of
/// its ancestor PIDs (bounded to 64 hops so a synthetic cycle terminates).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ancestor_pids_from_proc(proc_root: &Path, start_pid: u32) -> HashSet<u32> {
    let mut visited = HashSet::new();
    let mut cur = start_pid;
    for _ in 0..64 {
        if cur == 0 || !visited.insert(cur) {
            break;
        }
        let status_path = proc_root.join(cur.to_string()).join("status");
        let Ok(status) = std::fs::read_to_string(status_path) else {
            break;
        };
        let Some(ppid) = status.lines().find_map(|line| {
            line.strip_prefix("PPid:")?
                .split_whitespace()
                .next()?
                .parse::<u32>()
                .ok()
        }) else {
            break;
        };
        if ppid <= 1 {
            break;
        }
        cur = ppid;
    }
    visited
}

#[cfg(target_os = "linux")]
fn stop_linux_non_root_daemons(calling_uid: Option<u32>) {
    let _ = &is_meshharbord_daemon_cmdline;
    let _ = &ancestor_pids_from_proc;

    if let Some(uid) = calling_uid.filter(|u| *u != 0) {
        for unit in ["meshharbor.service", "meshharbor-agent.service"] {
            let _ = std::process::Command::new("systemctl")
                .arg(format!("--machine={uid}@.host"))
                .args(["--user", "disable", "--now", unit])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    let excluded = ancestor_pids_from_proc(Path::new("/proc"), std::process::id());
    let non_root_daemon_pids = || -> Vec<i32> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid <= 1 || excluded.contains(&pid) {
                continue;
            }
            let p = entry.path();
            let Ok(cmdline) = std::fs::read(p.join("cmdline")) else {
                continue;
            };
            if !is_meshharbord_daemon_cmdline(&cmdline) {
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

    let pids = non_root_daemon_pids();
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
        if non_root_daemon_pids().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
async fn activate_platform_system_service(
    req: &personal_system::SystemEnrollRequest,
    target_path: &Path,
    _enrolled_agent_id: &str,
) -> Result<()> {
    let _ = (&is_meshharbord_daemon_cmdline, &ancestor_pids_from_proc);

    // Check LaunchDaemon installation preflight BEFORE stopping the user LaunchAgent.
    if let Some(why) = crate::service::system::install_refusal(
        crate::service::system::Os::MacOs,
        crate::appdirs::running_as_root(),
        Path::new(crate::service::system::MACOS_PLIST_SOURCE).exists(),
        target_path.exists(),
    ) {
        bail!("{why}");
    }

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
                device_invite::write_marker_for(target_path, &org_id, false, None)
                    .context("clearing temporary marker on personal org")?;
            }
            if primary_was_invited {
                crate::config::promote_keeping_mesh(&mut cfg, label, None)
                    .context("promoting personal account beside invitations")?;
                if let (Some(id), Some(info)) =
                    (old_primary, markers.get(device_invite::PRIMARY_KEY))
                {
                    device_invite::write_marker_for(target_path, &id, true, Some(info))
                        .context("re-keying demoted primary temporary marker")?;
                }
            }
        }
        EnrollOutcome::FreshPrimary
        | EnrollOutcome::RefreshedPrimary
        | EnrollOutcome::ReplacedPrimary => {
            if let Some(ref old_id) = old_primary
                && old_id != &cfg.agent_id
            {
                device_invite::write_marker_for(target_path, old_id, true, None)
                    .context("clearing replaced primary marker")?;
            }
            device_invite::write_marker_for(target_path, &cfg.agent_id, true, None)
                .context("clearing primary temporary marker")?;
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
        let hist_entries: Vec<device_invite::HistoryEntry> = serde_json::from_str(
            r#"[{"invite_id":"inv-1","proof":"secret","server_url":"https://mh.example","tenant_id":"tenant-siat","org":"SIAT","inviter":"Prof","access_until_ms":1900000000000,"accepted_at_ms":1800000000000}]"#,
        )
        .unwrap();
        merge_seed_invitation_history(&target, &hist_entries).unwrap();

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

    #[test]
    fn existing_system_org_b_plus_user_siat_org_a_plus_personal_org_c_preserves_all_three() {
        let dir = std::env::temp_dir().join(format!(
            "mh-psexec-3way-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");

        // System already holds Org B (permanent primary).
        let sys_cfg = mk_cfg("https://mh.example", "tenant-b", "aid-sys-b", "my-box");
        crate::config::save(&target, &sys_cfg).unwrap();

        // User config holds SIAT Org A (primary, with legacy temporary.json) + secondary Org D.
        let mut user_cfg = mk_cfg("https://mh.example", "tenant-siat-a", "aid-user-a", "my-box");
        user_cfg.overlay_enabled = true;
        let (user_cfg, _) = crate::enrollment::apply_enrollment(
            Some(user_cfg),
            mk_cfg("https://other.example", "tenant-d", "aid-user-d", "my-box"),
            Some("lab-d"),
            false,
        )
        .unwrap();
        let seed_markers = device_invite::parse_markers_strict(
            r#"{"access_until_ms":1900000000000,"inviter":"Prof A","org":"SIAT-A"}"#,
        )
        .unwrap();

        // User signs into personal Org C.
        let fresh_c = mk_cfg("https://mh.example", "tenant-own-c", "aid-own-c", "my-box");

        let combined = fold_seeded_user_config(
            &target,
            Some(sys_cfg),
            Some(user_cfg),
            &seed_markers,
            &fresh_c,
            false,
        )
        .unwrap();
        let (merged, _outcome) =
            merge_and_promote_personal_enrollment(&target, combined, fresh_c, false).unwrap();

        assert_eq!(merged.agent_id, "aid-sys-b");
        assert!(merged.validate_orgs().is_empty(), "{:?}", merged.validate_orgs());
        let org_ids: HashSet<&str> = merged.orgs.iter().map(|o| o.agent_id.as_str()).collect();
        assert!(org_ids.contains("aid-user-a"), "SIAT Org A must survive: {org_ids:?}");
        assert!(org_ids.contains("aid-user-d"), "Secondary Org D must survive: {org_ids:?}");
        assert!(org_ids.contains("aid-own-c"), "Personal Org C must be added: {org_ids:?}");

        let markers = device_invite::read_markers(&target);
        assert!(
            markers.contains_key("aid-user-a"),
            "SIAT Org A temporary marker must be migrated: {markers:?}"
        );
        assert!(!markers.contains_key("aid-own-c"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conflicting_third_party_org_enrollment_fails_closed_before_retirement() {
        let dir = std::env::temp_dir().join(format!(
            "mh-psexec-conflict-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.toml");

        let sys_cfg = mk_cfg("https://mh.example", "tenant-b", "aid-sys-b", "my-box");
        let user_cfg = mk_cfg("https://mh.example/", "tenant-b", "aid-user-b", "my-box");
        let fresh_c = mk_cfg("https://mh.example", "tenant-c", "aid-own-c", "my-box");

        let err = fold_seeded_user_config(
            &target,
            Some(sys_cfg),
            Some(user_cfg),
            &BTreeMap::new(),
            &fresh_c,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("distinct enrollment"),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_seed_snapshots_fail_closed() {
        let mut bad_toml = personal_system::SystemEnrollRequest {
            server_url: "https://mh.example".into(),
            enrollment_token: "tok".into(),
            device_name: "box".into(),
            replace: false,
            calling_uid: Some(1000),
            seed_config_toml: Some("not = [valid toml".into()),
            seed_temporary_json: None,
            seed_history_json: None,
        };
        assert!(parse_seed_migration_inputs(&bad_toml).is_err());

        bad_toml.seed_config_toml = None;
        bad_toml.seed_temporary_json = Some("{broken json".into());
        assert!(parse_seed_migration_inputs(&bad_toml).is_err());

        bad_toml.seed_temporary_json = Some(r#"{"unexpected":123}"#.into());
        assert!(parse_seed_migration_inputs(&bad_toml).is_err());

        bad_toml.seed_temporary_json = None;
        bad_toml.seed_history_json = Some("[broken]".into());
        assert!(parse_seed_migration_inputs(&bad_toml).is_err());
    }

    #[test]
    fn daemon_cmdline_classifier_matches_only_daemon_invocations() {
        assert!(is_meshharbord_daemon_cmdline(b"/usr/bin/meshharbord\0run\0"));
        assert!(is_meshharbord_daemon_cmdline(
            b"/usr/bin/meshharbord\0--config\0/etc/meshharbor/config.toml\0run\0"
        ));
        assert!(is_meshharbord_daemon_cmdline(
            b"meshharbord\0--config=/home/u/.config/meshharbor/config.toml\0run\0"
        ));
        assert!(is_meshharbord_daemon_cmdline(b"/usr/bin/meshharbord\0"));
        assert!(is_meshharbord_daemon_cmdline(b"meshharbor-agent\0run\0"));

        // Must NEVER match CLI verbs (`mh login` execs `meshharbord login ...`)!
        assert!(!is_meshharbord_daemon_cmdline(b"/usr/bin/meshharbord\0login\0"));
        assert!(!is_meshharbord_daemon_cmdline(
            b"/usr/bin/meshharbord\0--config\0/tmp/c.toml\0login\0--no-browser\0"
        ));
        assert!(!is_meshharbord_daemon_cmdline(
            b"/usr/bin/meshharbord\0enroll-personal-system\0--request-file\0/tmp/r\0"
        ));
        assert!(!is_meshharbord_daemon_cmdline(b"meshharbord\0status\0"));
        assert!(!is_meshharbord_daemon_cmdline(b"meshharbord\0ssh\0box\0"));
        assert!(!is_meshharbord_daemon_cmdline(b"meshharbord\0service\0status\0"));
        assert!(!is_meshharbord_daemon_cmdline(b"meshharbord\0--version\0"));
        assert!(!is_meshharbord_daemon_cmdline(b"meshharbord\0run\0--help\0"));
        assert!(!is_meshharbord_daemon_cmdline(b"/usr/bin/mh\0login\0"));
        assert!(!is_meshharbord_daemon_cmdline(b""));
    }

    #[test]
    fn ancestor_pids_walks_ppid_chain_and_handles_cycles() {
        let dir = std::env::temp_dir().join(format!(
            "mh-proc-anc-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        for (pid, ppid) in [(100u32, 1u32), (200, 100), (300, 200), (400, 300)] {
            let pdir = dir.join(pid.to_string());
            std::fs::create_dir_all(&pdir).unwrap();
            std::fs::write(pdir.join("status"), format!("Name:\tmeshharbord\nPPid:\t{ppid}\n"))
                .unwrap();
        }
        let anc = ancestor_pids_from_proc(&dir, 400);
        assert_eq!(anc, HashSet::from([400, 300, 200, 100]));

        // Cycle safety
        for (pid, ppid) in [(500u32, 600u32), (600, 500)] {
            let pdir = dir.join(pid.to_string());
            std::fs::create_dir_all(&pdir).unwrap();
            std::fs::write(pdir.join("status"), format!("PPid:\t{ppid}\n")).unwrap();
        }
        let cyc = ancestor_pids_from_proc(&dir, 500);
        assert_eq!(cyc, HashSet::from([500, 600]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pf_subdirs_helper_requires_application_subdir_below_program_files() {
        let roots = vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        let (root, subs) = pf_subdirs_between_root_and_exe(
            Path::new(r"C:\Program Files\MeshHarbor\meshharbord.exe"),
            &roots,
        )
        .unwrap();
        assert_eq!(root, PathBuf::from(r"C:\Program Files"));
        assert_eq!(subs, vec![PathBuf::from(r"C:\Program Files\MeshHarbor")]);

        // Directly inside Program Files root (no subdirectory) must return None!
        assert!(
            pf_subdirs_between_root_and_exe(
                Path::new(r"C:\Program Files\meshharbord.exe"),
                &roots
            )
            .is_none()
        );

        // Outside Program Files must return None!
        assert!(
            pf_subdirs_between_root_and_exe(
                Path::new(r"C:\Users\alice\MeshHarbor\meshharbord.exe"),
                &roots
            )
            .is_none()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_config_paths_reject_symlink_config_and_sidecars() {
        let raw_base = std::env::temp_dir().join(format!(
            "mh-unix-cfg-paths-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&raw_base).unwrap();
        let dir = std::fs::canonicalize(&raw_base).unwrap().join("meshharbor");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.toml");
        std::fs::write(&cfg_path, r#"machine_id = "m""#).unwrap();
        assert!(ensure_trusted_unix_config_paths(&cfg_path).is_ok());

        let victim = raw_base.join("victim.json");
        std::fs::write(&victim, "{}").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("temporary.json")).unwrap();
        assert!(
            ensure_trusted_unix_config_paths(&cfg_path).is_err(),
            "symlink sidecar temporary.json must be rejected"
        );
        std::fs::remove_file(dir.join("temporary.json")).unwrap();

        std::os::unix::fs::symlink(&victim, dir.join("invites.json")).unwrap();
        assert!(
            ensure_trusted_unix_config_paths(&cfg_path).is_err(),
            "symlink sidecar invites.json must be rejected"
        );

        let _ = std::fs::remove_dir_all(&raw_base);
    }

    #[cfg(windows)]
    #[test]
    fn real_program_files_passes_and_user_dir_is_rejected_by_win_security() {
        if let Some(pf) = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")) {
            let pf_path = PathBuf::from(pf);
            if pf_path.is_dir() {
                win_security::verify_pf_root_readonly(&pf_path)
                    .expect("real Windows ProgramFiles root must pass PF security check (including TrustedInstaller)");
            }
        }
        let user_dir = std::env::temp_dir().join(format!(
            "mh-win-sec-untrusted-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        std::fs::create_dir_all(&user_dir).unwrap();
        if !personal_system::is_process_elevated() {
            assert!(
                win_security::verify_pf_root_readonly(&user_dir).is_err(),
                "unprivileged user temp directory must be rejected by PF security check"
            );
        }
        let _ = std::fs::remove_dir_all(&user_dir);
    }
}
