// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-112 P1 — the encoder asks for its clock.
//!
//! A software encoder works a fraction of every frame period: at 30 fps it
//! encodes, then sleeps until the next frame. Linux's energy-aware scheduler
//! sees a thread like that as small. It places it on an efficiency core and
//! lets `schedutil` lower the clock until the work nearly fills its period.
//! Measured on an Apple M2 Pro (Fedora Asahi Remix, FR-112 §2): the same
//! OpenH264 frame takes 6 ms back to back and 17–20 ms at a 30 fps cadence, and
//! the live pump reported 16.1 ms. With the encoder's threads clamped
//! (`uclamp_min` 1024) the same frame took 5.3 ms live, and the VP9-444 pump at
//! a 60 fps target went from 19 to 56 fps with no other change.
//!
//! The clamp is this module's whole job. A thread asks for its own clock with
//! `sched_setattr(SCHED_FLAG_UTIL_CLAMP_MIN)`, keeping its policy and
//! priority. The scheduler then counts it as a big task: a performance core and
//! a high clock, **but only while it is runnable**, so an encoder waiting for a
//! still screen costs nothing more. Threads it creates afterwards inherit the
//! clamp: libvpx creates its worker threads at the first encode, from the
//! encoder thread, so they carry it too.
//!
//! Who asks: the encoder thread (`encode::thread`), OpenH264's worker, and the
//! DRM capture worker. Nothing else of the daemon does.
//!
//! A kernel without util clamping (`CONFIG_UCLAMP_TASK` off) refuses the
//! request, and the encoder runs as before; the log says so once. macOS and
//! Windows answer `NotLinux` until their own phase (FR-112 P3).
//!
//! Kill switch: `ROOMLERD_ENCODER_CLOCK=0`.

use std::sync::Mutex;

/// The clamp asked for: the full scale, "run me as fast as this CPU runs"
/// while the thread is runnable (FR-112 D5).
pub const CLAMP_MIN: u32 = 1024;

/// What a thread's request did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The thread now carries `uclamp_min = CLAMP_MIN`.
    Clamped,
    /// The kill switch is set; nothing was asked.
    Off,
    /// The kernel refused (its `errno`): no util clamping, or a cgroup limit.
    Refused(i32),
    /// Not Linux: nothing to ask for here yet (FR-112 P3).
    NotLinux,
}

/// `ROOMLERD_ENCODER_CLOCK`, on unless set false.
pub fn enabled() -> bool {
    tunnel_core::env::flag("ENCODER_CLOCK", true)
}

/// Ask for this thread's clock. Call it first thing on a thread that encodes
/// or captures, before it creates any thread of its own.
pub fn ask_for_this_thread(role: &'static str) -> Outcome {
    let outcome = ask(enabled());
    say_once(role, outcome);
    outcome
}

/// The request itself, with the switch passed in (tests decide it without
/// touching the environment, which other tests read concurrently).
fn ask(enabled: bool) -> Outcome {
    if enabled {
        imp::clamp_min(CLAMP_MIN)
    } else {
        Outcome::Off
    }
}

/// One line per role per process: the first thread of a role says what it got,
/// and the rest (one per session) stay quiet.
fn say_once(role: &'static str, outcome: Outcome) {
    static SAID: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if said.contains(&role) {
        return;
    }
    said.push(role);
    match outcome {
        Outcome::Clamped => tracing::info!(
            role,
            uclamp_min = CLAMP_MIN,
            "encoder clock: asked for (FR-112; ROOMLERD_ENCODER_CLOCK=0 turns it off)"
        ),
        Outcome::Off => tracing::info!(
            role,
            "encoder clock: not asked for (ROOMLERD_ENCODER_CLOCK=0, FR-112)"
        ),
        Outcome::Refused(errno) => tracing::info!(
            role,
            errno,
            "encoder clock: the kernel refused a utilisation clamp (no CONFIG_UCLAMP_TASK, or a cgroup limit); \
             the encoder runs at the clock the scheduler picks (FR-112)"
        ),
        Outcome::NotLinux => {}
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::Outcome;

    /// `struct sched_attr`, `SCHED_ATTR_SIZE_VER1`: the first layout that
    /// carries the util clamps (linux/sched/types.h).
    #[repr(C)]
    #[derive(Debug, Default)]
    pub(super) struct SchedAttr {
        pub size: u32,
        pub sched_policy: u32,
        pub sched_flags: u64,
        pub sched_nice: i32,
        pub sched_priority: u32,
        pub sched_runtime: u64,
        pub sched_deadline: u64,
        pub sched_period: u64,
        pub sched_util_min: u32,
        pub sched_util_max: u32,
    }

    /// Keep the policy and its parameters: the request changes the clamp only.
    pub(super) const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;
    pub(super) const SCHED_FLAG_KEEP_PARAMS: u64 = 0x10;
    pub(super) const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 0x20;

    /// The request this module makes, built in one place so a test can pin it.
    pub(super) fn request(min: u32) -> SchedAttr {
        SchedAttr {
            size: std::mem::size_of::<SchedAttr>() as u32,
            sched_flags: SCHED_FLAG_KEEP_POLICY
                | SCHED_FLAG_KEEP_PARAMS
                | SCHED_FLAG_UTIL_CLAMP_MIN,
            sched_util_min: min,
            ..Default::default()
        }
    }

    pub(super) fn clamp_min(min: u32) -> Outcome {
        let attr = request(min);
        // SAFETY: `attr` is a valid `sched_attr` whose `size` is its own; pid 0
        // is the calling thread; flags 0. The kernel only reads it.
        let r = unsafe { libc::syscall(libc::SYS_sched_setattr, 0, &attr as *const SchedAttr, 0) };
        if r == 0 {
            Outcome::Clamped
        } else {
            Outcome::Refused(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    /// The calling thread's `sched_util_min` as the kernel reports it.
    #[cfg(test)]
    pub(super) fn read_min() -> std::io::Result<u32> {
        let mut attr = SchedAttr::default();
        // SAFETY: `attr` is writable and `size` bytes long; pid 0 is the calling
        // thread; flags 0.
        let r = unsafe {
            libc::syscall(
                libc::SYS_sched_getattr,
                0,
                &mut attr as *mut SchedAttr,
                std::mem::size_of::<SchedAttr>() as u32,
                0,
            )
        };
        if r == 0 {
            Ok(attr.sched_util_min)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub(super) fn clamp_min(_min: u32) -> super::Outcome {
        super::Outcome::NotLinux
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kill switch asks for nothing.
    #[test]
    fn the_kill_switch_asks_for_nothing() {
        assert_eq!(ask(false), Outcome::Off);
    }

    /// The request is a VER1 `sched_attr` (56 bytes, the first size that carries
    /// the clamps) that changes the clamp and nothing else.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_request_changes_the_clamp_and_nothing_else() {
        let attr = imp::request(CLAMP_MIN);
        assert_eq!(attr.size, 56, "SCHED_ATTR_SIZE_VER1");
        assert_eq!(
            attr.sched_flags,
            imp::SCHED_FLAG_KEEP_POLICY
                | imp::SCHED_FLAG_KEEP_PARAMS
                | imp::SCHED_FLAG_UTIL_CLAMP_MIN,
            "policy and priority kept, only the minimum clamp set"
        );
        assert_eq!(attr.sched_util_min, 1024);
        assert_eq!(
            (attr.sched_policy, attr.sched_priority, attr.sched_nice),
            (0, 0, 0)
        );
    }

    /// On a kernel with util clamping the thread reads its clamp back, and a
    /// thread it then creates inherits it (libvpx's workers rely on that). A
    /// kernel without it refuses, which is the documented fallback.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_thread_reads_its_clamp_back_and_its_children_inherit_it() {
        std::thread::spawn(|| match ask(true) {
            Outcome::Clamped => {
                assert_eq!(imp::read_min().expect("sched_getattr"), CLAMP_MIN);
                let child = std::thread::spawn(|| imp::read_min().expect("sched_getattr"))
                    .join()
                    .expect("child thread");
                assert_eq!(child, CLAMP_MIN, "a thread created after the request inherits it");
            }
            Outcome::Refused(errno) => {
                eprintln!("this kernel has no util clamping (errno {errno}); the fallback is to run as before")
            }
            other => panic!("unexpected outcome on Linux: {other:?}"),
        })
        .join()
        .expect("test thread");
    }
}
