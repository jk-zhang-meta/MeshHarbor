// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P4 — host mute: while a privacy curtain is up, the host's speakers
//! are muted, and the controller keeps the audio.
//!
//! P0 measured it (2026-10-16): with the default render endpoint muted, the
//! agent's WASAPI loopback carried the same audio as unmuted, so a mute
//! silences the person at the device and not the remote session.
//!
//! The rules, each from what the mute is:
//! - **It is one machine-wide setting**, so there is one guard per process: the
//!   first curtain up mutes, the last one down restores.
//! - **It persists.** This process restores only what it muted: an endpoint
//!   that was muted already is left muted. A note is written BEFORE muting and
//!   removed after restoring, so the next process restores a mute this one died
//!   holding ([`HostMute::restore_leftover`]).
//! - **It is not a lock.** The person can unmute from the volume flyout. At
//!   the restore an endpoint they unmuted is left alone: it is theirs.
//!
//! Windows only, like the curtain. Elsewhere [`SystemSpeakers`] has no endpoint
//! and the curtain goes up without a mute.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{info, warn};

/// The host's default render endpoint, or a fake in tests.
pub trait Speakers: Send + Sync + 'static {
    /// Is the endpoint muted? `None` when there is no endpoint, or no way to
    /// ask from here.
    fn muted(&self) -> Option<bool>;
    /// Mute or unmute it. `false` when that failed.
    fn set_muted(&self, mute: bool) -> bool;
}

/// The real endpoint: Core Audio's `IAudioEndpointVolume` on the default
/// render device. Nothing on other platforms.
pub struct SystemSpeakers;

#[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
mod win {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::Media::Audio::Endpoints::IAudioEndpointVolume;
    use windows::Win32::Media::Audio::{
        IMMDeviceEnumerator, MMDeviceEnumerator, eConsole, eRender,
    };
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };

    /// Run `f` on the default render endpoint's volume control, with COM held
    /// for the call. `None` when there is no endpoint or a call failed.
    pub(super) fn with_endpoint<T>(
        f: impl FnOnce(&IAudioEndpointVolume) -> Option<T>,
    ) -> Option<T> {
        // SAFETY: plain COM calls on this thread. A thread that already holds
        // COM in another mode answers RPC_E_CHANGED_MODE, and the calls below
        // still work there; only a successful init is balanced by an uninit.
        unsafe {
            let inited = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
            let out = (|| {
                let devices: IMMDeviceEnumerator =
                    CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL).ok()?;
                let device = devices.GetDefaultAudioEndpoint(eRender, eConsole).ok()?;
                let volume: IAudioEndpointVolume = device.Activate(CLSCTX_ALL, None).ok()?;
                f(&volume)
            })();
            if inited {
                CoUninitialize();
            }
            out
        }
    }

    pub(super) fn muted() -> Option<bool> {
        // SAFETY: a COM call on a live interface.
        with_endpoint(|v| unsafe { v.GetMute() }.ok().map(|b| b.as_bool()))
    }

    pub(super) fn set_muted(mute: bool) -> bool {
        // SAFETY: a COM call on a live interface; a null event context.
        with_endpoint(|v| unsafe { v.SetMute(BOOL::from(mute), std::ptr::null()) }.ok()).is_some()
    }
}

impl Speakers for SystemSpeakers {
    fn muted(&self) -> Option<bool> {
        #[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
        {
            win::muted()
        }
        #[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
        {
            None
        }
    }

    fn set_muted(&self, mute: bool) -> bool {
        #[cfg(all(target_os = "windows", feature = "viewer-indicator"))]
        {
            win::set_muted(mute)
        }
        #[cfg(not(all(target_os = "windows", feature = "viewer-indicator")))]
        {
            let _ = mute;
            false
        }
    }
}

#[derive(Default)]
struct State {
    /// Curtains up in this process.
    holders: usize,
    /// This process muted the endpoint, and owes the restore.
    muted_by_us: bool,
}

/// The process's guard over the host's speakers.
pub struct HostMute {
    speakers: Arc<dyn Speakers>,
    /// The note that this process muted the speakers, written before it does.
    note: Option<PathBuf>,
    state: Mutex<State>,
}

impl HostMute {
    pub fn new(speakers: Arc<dyn Speakers>, note: Option<PathBuf>) -> Self {
        Self {
            speakers,
            note,
            state: Mutex::new(State::default()),
        }
    }

    /// `host-mute.json` beside the curtain ledger, in this process's own local
    /// data dir: the next process of the same install finds it.
    fn default_note() -> Option<PathBuf> {
        meshharbor_node_core::appdirs::project_dirs()
            .map(|p| p.data_local_dir().join("host-mute.json"))
    }

    fn write_note(&self) {
        let Some(path) = &self.note else { return };
        let res = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(path, br#"{"muted_by_this_install":true}"#));
        if let Err(e) = res {
            warn!(%e, path = %path.display(), "host mute: the note could not be written");
        }
    }

    fn clear_note(&self) {
        let Some(path) = &self.note else { return };
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(%e, path = %path.display(), "host mute: the note could not be removed");
        }
    }

    /// A curtain went up. The answer is whether the host's speakers are muted
    /// now: `Some(true)` muted (by this call or already), `Some(false)` when
    /// muting failed, `None` when there is no endpoint to mute.
    pub fn hold(&self) -> Option<bool> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.holders += 1;
        if st.muted_by_us {
            return Some(true);
        }
        match self.speakers.muted()? {
            // Muted already, by the person or anyone: theirs, never restored.
            true => Some(true),
            false => {
                // Noted BEFORE the mute: a process that dies between the two
                // leaves a note for an endpoint it may not have muted, which
                // the restore then finds unmuted and leaves alone.
                self.write_note();
                if self.speakers.set_muted(true) {
                    st.muted_by_us = true;
                    info!("host mute: the host's speakers are muted while privacy mode is on");
                    Some(true)
                } else {
                    self.clear_note();
                    warn!("host mute: the host's speakers could not be muted");
                    Some(false)
                }
            }
        }
    }

    /// A curtain came down. The last one restores what this process muted,
    /// unless the person unmuted it in the meantime: that is theirs to do.
    pub fn release(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.holders = st.holders.saturating_sub(1);
        if st.holders > 0 || !st.muted_by_us {
            return;
        }
        st.muted_by_us = false;
        match self.speakers.muted() {
            Some(true) => {
                if self.speakers.set_muted(false) {
                    info!("host mute: the host's speakers are unmuted again");
                } else {
                    warn!("host mute: the host's speakers could not be unmuted; the note stays");
                    return;
                }
            }
            Some(false) => info!("host mute: the person unmuted the speakers; left as they are"),
            None => warn!("host mute: the endpoint is gone; nothing to restore"),
        }
        self.clear_note();
    }

    /// At start-up, before any curtain of this process: a previous process of
    /// this install died holding a mute. Restore it, and say so.
    pub fn restore_leftover(&self) {
        let Some(path) = &self.note else { return };
        if !path.exists() {
            return;
        }
        match self.speakers.muted() {
            Some(true) => {
                if self.speakers.set_muted(false) {
                    info!("host mute: the previous process ended with the speakers muted; unmuted");
                } else {
                    warn!(
                        "host mute: the previous process's mute could not be undone; the note stays"
                    );
                    return;
                }
            }
            Some(false) => info!("host mute: the previous process's mute was already undone"),
            None => info!("host mute: no endpoint to restore; clearing the note"),
        }
        self.clear_note();
    }
}

/// The process's guard.
pub fn host_mute() -> Arc<HostMute> {
    static GUARD: OnceLock<Arc<HostMute>> = OnceLock::new();
    GUARD
        .get_or_init(|| {
            Arc::new(HostMute::new(
                Arc::new(SystemSpeakers),
                HostMute::default_note(),
            ))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An endpoint whose mute is a flag; `None` = no endpoint.
    struct Fake {
        muted: Mutex<Option<bool>>,
        sets: Mutex<Vec<bool>>,
        fail_set: bool,
    }

    impl Fake {
        fn new(muted: Option<bool>) -> Arc<Self> {
            Arc::new(Self {
                muted: Mutex::new(muted),
                sets: Mutex::new(Vec::new()),
                fail_set: false,
            })
        }
        fn now(&self) -> Option<bool> {
            *self.muted.lock().unwrap()
        }
        fn person_sets(&self, m: bool) {
            *self.muted.lock().unwrap() = Some(m);
        }
    }

    impl Speakers for Fake {
        fn muted(&self) -> Option<bool> {
            *self.muted.lock().unwrap()
        }
        fn set_muted(&self, mute: bool) -> bool {
            if self.fail_set {
                return false;
            }
            self.sets.lock().unwrap().push(mute);
            let mut m = self.muted.lock().unwrap();
            if m.is_some() {
                *m = Some(mute);
            }
            true
        }
    }

    fn guard(fake: &Arc<Fake>) -> (HostMute, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let g = HostMute::new(fake.clone(), Some(dir.path().join("host-mute.json")));
        (g, dir)
    }

    #[test]
    fn the_first_curtain_mutes_and_the_last_restores() {
        let fake = Fake::new(Some(false));
        let (g, dir) = guard(&fake);
        assert_eq!(g.hold(), Some(true));
        assert_eq!(g.hold(), Some(true), "a second curtain: still muted");
        assert_eq!(*fake.sets.lock().unwrap(), vec![true], "muted once");
        assert!(
            dir.path().join("host-mute.json").exists(),
            "noted while muted"
        );
        g.release();
        assert_eq!(fake.now(), Some(true), "one curtain still up");
        g.release();
        assert_eq!(fake.now(), Some(false), "the last one restores");
        assert!(
            !dir.path().join("host-mute.json").exists(),
            "and clears the note"
        );
    }

    #[test]
    fn an_endpoint_muted_already_is_never_unmuted() {
        let fake = Fake::new(Some(true));
        let (g, dir) = guard(&fake);
        assert_eq!(g.hold(), Some(true));
        g.release();
        assert_eq!(fake.now(), Some(true), "it was the person's mute");
        assert!(fake.sets.lock().unwrap().is_empty(), "never touched");
        assert!(!dir.path().join("host-mute.json").exists(), "nothing noted");
    }

    #[test]
    fn a_person_who_unmuted_is_left_alone() {
        let fake = Fake::new(Some(false));
        let (g, _dir) = guard(&fake);
        assert_eq!(g.hold(), Some(true));
        fake.person_sets(false);
        g.release();
        assert_eq!(*fake.sets.lock().unwrap(), vec![true], "no second set");
        assert_eq!(fake.now(), Some(false));
    }

    #[test]
    fn no_endpoint_means_no_mute_and_no_note() {
        let fake = Fake::new(None);
        let (g, dir) = guard(&fake);
        assert_eq!(g.hold(), None);
        g.release();
        assert!(fake.sets.lock().unwrap().is_empty());
        assert!(!dir.path().join("host-mute.json").exists());
    }

    #[test]
    fn a_mute_that_fails_says_so_and_leaves_no_note() {
        let fake = Arc::new(Fake {
            muted: Mutex::new(Some(false)),
            sets: Mutex::new(Vec::new()),
            fail_set: true,
        });
        let (g, dir) = guard(&fake);
        assert_eq!(g.hold(), Some(false));
        assert!(!dir.path().join("host-mute.json").exists());
        g.release();
        assert_eq!(fake.now(), Some(false));
    }

    #[test]
    fn the_next_process_restores_a_mute_the_last_one_died_holding() {
        let fake = Fake::new(Some(false));
        let dir = tempfile::tempdir().unwrap();
        let note = dir.path().join("host-mute.json");
        {
            let dying = HostMute::new(fake.clone(), Some(note.clone()));
            assert_eq!(dying.hold(), Some(true));
            // The process dies here: no release.
        }
        assert_eq!(fake.now(), Some(true));
        let next = HostMute::new(fake.clone(), Some(note.clone()));
        next.restore_leftover();
        assert_eq!(fake.now(), Some(false), "restored");
        assert!(!note.exists(), "and the note cleared");
        // A second start finds nothing to do.
        next.restore_leftover();
        assert_eq!(*fake.sets.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn no_note_means_the_next_process_touches_nothing() {
        let fake = Fake::new(Some(true));
        let (g, _dir) = guard(&fake);
        g.restore_leftover();
        assert_eq!(fake.now(), Some(true), "the person's own mute");
        assert!(fake.sets.lock().unwrap().is_empty());
    }
}
