// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P4a — a real Ctrl+Alt+Del on Windows.
//!
//! The viewer's button typed three ordinary keys, which apps on the desktop
//! receive and the Windows lock and sign-in screens never do: those answer only
//! the secure attention sequence (SAS), which the kernel raises for the physical
//! chord and `SendSAS` raises for software. `SendSAS(FALSE)` is honoured only
//! from a service process, and only where the `SoftwareSASGeneration` policy
//! lets services generate one.
//!
//! ⚠️ **Measured: the SystemContext worker cannot send it itself.** The worker
//! runs as SYSTEM, but in the person's session, spawned by the service and not
//! the service: its `SendSAS(FALSE)` returns, and the lock screen never moves.
//! So the SCM host, the service process in session 0, sends it, and the worker
//! only asks: the host creates a named event only SYSTEM may signal
//! (`win_service::sas_relay`) and hands its name to the worker
//! (`--sas-event`); the worker signals it; the host's thread re-checks the
//! policy and calls `SendSAS(FALSE)`.
//!
//! So the daemon offers the real sequence (`input: sas` in the hello, and no
//! `keys-only` entry) only when both hold: this worker can ask the service (it
//! runs as SYSTEM, the SystemContext worker of an SCM install, and was handed
//! the relay), and the policy lets services. Anywhere else the button keeps
//! typing keys, and its title says why. The policy is read, never written: it
//! is a security setting, and on a managed laptop it is the organisation's.
//!
//! `sas.dll` is loaded when the host sends, never imported: a binary that
//! imports a DLL some Windows edition lacks does not start at all. It is loaded
//! from System32 only, so a SYSTEM process can never pick up a planted copy.
//!
//! The decision is pure and compiled on every OS, so the lanes that never run
//! Windows tests still check it.

/// What `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`'s
/// `SoftwareSASGeneration` lets generate a SAS. Absent, Windows lets only Ease
/// of Access applications on the secure desktop do it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasPolicy {
    /// 0: nothing may.
    Nothing,
    /// 1: services may.
    Services,
    /// 2, or the value absent: Ease of Access applications only.
    EaseOfAccess,
    /// 3: services and Ease of Access applications.
    ServicesAndEaseOfAccess,
    /// A value Windows does not define: read as "services may not".
    Unknown(u32),
}

impl SasPolicy {
    /// The policy a registry read gives: `None` when the value is absent.
    pub fn from_value(value: Option<u32>) -> Self {
        match value {
            None | Some(2) => Self::EaseOfAccess,
            Some(0) => Self::Nothing,
            Some(1) => Self::Services,
            Some(3) => Self::ServicesAndEaseOfAccess,
            Some(other) => Self::Unknown(other),
        }
    }

    /// Whether a service's `SendSAS(FALSE)` may raise it.
    pub fn lets_services(self) -> bool {
        matches!(self, Self::Services | Self::ServicesAndEaseOfAccess)
    }
}

/// Why this host types keys instead of sending the real sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasRefusal {
    /// This daemon cannot ask the service to send it: a per-user install, an
    /// SCM install whose worker runs as the signed-in person, or a daemon run
    /// by hand.
    NoService,
    /// The policy lets no service generate a SAS.
    Policy(SasPolicy),
}

impl SasRefusal {
    /// One sentence for the viewer's title, after the button's own words.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoService => {
                "Ctrl+Alt+Del is sent as ordinary keys: apps on the desktop get it, but the Windows lock and sign-in screens do not. Only the Roomler service can send the real one, through a worker running as SYSTEM, and this install has none"
            }
            Self::Policy(_) => {
                "Ctrl+Alt+Del is sent as ordinary keys: apps on the desktop get it, but the Windows lock and sign-in screens do not. Windows' software Secure Attention Sequence policy (SoftwareSASGeneration) lets no service send the real one here"
            }
        }
    }
}

/// The decision: the real sequence needs a worker that can ask the service AND
/// a policy that lets services generate it.
pub fn decide(reaches_service: bool, policy: SasPolicy) -> Result<(), SasRefusal> {
    if !reaches_service {
        return Err(SasRefusal::NoService);
    }
    if !policy.lets_services() {
        return Err(SasRefusal::Policy(policy));
    }
    Ok(())
}

/// The relay the SCM host handed this worker (`--sas-event`).
#[cfg(target_os = "windows")]
static HOST_RELAY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The worker's half: remember the host's relay, once, at start.
#[cfg(target_os = "windows")]
pub fn set_host_relay(name: String) {
    let _ = HOST_RELAY.set(name);
}

/// Whether this worker can have the real sequence sent now. Decided at every
/// announcement, and the heartbeat re-announces when the answer changes.
#[cfg(target_os = "windows")]
pub fn availability() -> Result<(), SasRefusal> {
    decide(
        HOST_RELAY.get().is_some() && imp::is_system(),
        SasPolicy::from_value(imp::read_policy()),
    )
}

/// The worker's half of a send: ask the service, which sends it.
#[cfg(target_os = "windows")]
pub fn send() -> anyhow::Result<()> {
    let Some(name) = HOST_RELAY.get() else {
        anyhow::bail!("no service relay to ask");
    };
    imp::signal(name)
}

/// The service's half: called by the host's relay thread, which re-checks the
/// policy itself, never trusting that the worker did.
#[cfg(target_os = "windows")]
pub fn host_send() -> anyhow::Result<()> {
    let policy = SasPolicy::from_value(imp::read_policy());
    if !policy.lets_services() {
        anyhow::bail!("the policy lets no service send it ({policy:?})");
    }
    imp::send_sas()
}

#[cfg(target_os = "windows")]
mod imp {
    use anyhow::{Result, bail};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, FreeLibrary};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW,
    };
    use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent};

    /// `EVENT_MODIFY_STATE`: enough to signal, which the relay's DACL grants
    /// SYSTEM alone.
    const EVENT_MODIFY_STATE: u32 = 0x0002;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// `SoftwareSASGeneration`, or `None` when it is absent or unreadable.
    pub fn read_policy() -> Option<u32> {
        let key = wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        let name = wide("SoftwareSASGeneration");
        let mut value: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        // SAFETY: `key` and `name` are NUL-terminated UTF-16 buffers; `value`
        // and `size` are valid out-pointers sized for the DWORD asked for.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        (rc == ERROR_SUCCESS).then_some(value)
    }

    /// Whether this process runs as LocalSystem (the SystemContext worker):
    /// the only kind the relay's DACL lets signal.
    pub fn is_system() -> bool {
        #[cfg(feature = "system-context")]
        {
            crate::system_context::worker_role::probe_self()
                .map(|role| role.is_system_context())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "system-context"))]
        {
            false
        }
    }

    /// Signal the host's relay event.
    pub fn signal(name: &str) -> Result<()> {
        let name_w = wide(name);
        // SAFETY: `name_w` is NUL-terminated; we ask for EVENT_MODIFY_STATE only.
        let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name_w.as_ptr()) };
        if handle.is_null() {
            bail!("the service relay: {}", std::io::Error::last_os_error());
        }
        // SAFETY: `handle` was just opened with EVENT_MODIFY_STATE.
        let ok = unsafe { SetEvent(handle) };
        let err = std::io::Error::last_os_error();
        // SAFETY: closed once; nothing else holds this handle.
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            bail!("the service relay: {err}");
        }
        Ok(())
    }

    /// `SendSAS(FALSE)`, from the service process.
    pub fn send_sas() -> Result<()> {
        let dll = wide("sas.dll");
        // SAFETY: `dll` is a NUL-terminated UTF-16 buffer; System32 only, so a
        // copy planted beside the binary is never the one loaded.
        let lib = unsafe {
            LoadLibraryExW(
                dll.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if lib.is_null() {
            bail!("sas.dll: {}", std::io::Error::last_os_error());
        }
        // SAFETY: `lib` is the module just loaded; the name is NUL-terminated.
        let proc = unsafe { GetProcAddress(lib, c"SendSAS".as_ptr().cast()) };
        let Some(proc) = proc else {
            // SAFETY: `lib` came from LoadLibraryExW and is freed once.
            unsafe { FreeLibrary(lib) };
            bail!("sas.dll has no SendSAS");
        };
        // SAFETY: `SendSAS` is `VOID SendSAS(BOOL AsUser)`, stdcall/system; the
        // pointer came from GetProcAddress for exactly that export.
        let send_sas: unsafe extern "system" fn(i32) = unsafe { std::mem::transmute(proc) };
        // FALSE: as a service. TRUE would be an Ease of Access application's
        // call, which needs uiAccess and the policy's other half.
        // SAFETY: a plain call into the export with a BOOL argument.
        unsafe { send_sas(0) };
        // SAFETY: as above, freed once; SendSAS has returned.
        unsafe { FreeLibrary(lib) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_value_reads_as_windows_documents_it() {
        assert_eq!(SasPolicy::from_value(None), SasPolicy::EaseOfAccess);
        assert_eq!(SasPolicy::from_value(Some(0)), SasPolicy::Nothing);
        assert_eq!(SasPolicy::from_value(Some(1)), SasPolicy::Services);
        assert_eq!(SasPolicy::from_value(Some(2)), SasPolicy::EaseOfAccess);
        assert_eq!(
            SasPolicy::from_value(Some(3)),
            SasPolicy::ServicesAndEaseOfAccess
        );
        assert_eq!(SasPolicy::from_value(Some(7)), SasPolicy::Unknown(7));
    }

    /// Only 1 and 3 let a service send it. An absent value is NOT "services
    /// may": Windows' default lets only Ease of Access applications.
    #[test]
    fn only_a_policy_that_names_services_lets_the_daemon_send_it() {
        let lets: Vec<bool> = [None, Some(0), Some(1), Some(2), Some(3), Some(9)]
            .into_iter()
            .map(|v| SasPolicy::from_value(v).lets_services())
            .collect();
        assert_eq!(lets, [false, false, true, false, true, false]);
    }

    #[test]
    fn the_real_sequence_needs_the_service_and_the_policy() {
        assert_eq!(decide(true, SasPolicy::Services), Ok(()));
        assert_eq!(decide(true, SasPolicy::ServicesAndEaseOfAccess), Ok(()));
        assert_eq!(
            decide(false, SasPolicy::Services),
            Err(SasRefusal::NoService),
            "a per-user install, however open the policy"
        );
        assert_eq!(
            decide(true, SasPolicy::EaseOfAccess),
            Err(SasRefusal::Policy(SasPolicy::EaseOfAccess)),
            "the service is there, but Windows' default policy"
        );
        assert_eq!(
            decide(false, SasPolicy::Nothing),
            Err(SasRefusal::NoService),
            "no service is said first: without it the policy does not matter"
        );
    }

    /// The reasons extend the button's own words; each says what reaches the
    /// lock screen and what would change it.
    #[test]
    fn each_refusal_says_why() {
        assert!(SasRefusal::NoService.reason().contains("Roomler service"));
        assert!(
            SasRefusal::Policy(SasPolicy::Nothing)
                .reason()
                .contains("SoftwareSASGeneration")
        );
    }
}
