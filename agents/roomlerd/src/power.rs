// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-55 — keep the device reachable instead of letting it quietly sleep.
//!
//! A device that sleeps is a device that is offline, and until this module there
//! was nothing in the product with any opinion about power at all:
//! `IOPMAssertion`, `SetThreadExecutionState`, `PowerCreateRequest` and
//! `systemd-inhibit` had zero occurrences across the tree.
//!
//! Measured on the operator's MacBook (2026-09-01): the idle timer is **one
//! minute** (`pmset -g`: `sleep 1`), and it really sleeps on AC —
//! `Entering Sleep state due to 'Idle Sleep'` and `'Clamshell Sleep'`.
//!
//! ## Two rules, and the first is not a policy
//!
//! 1. **An active session always holds the machine awake.** A remote-desktop or
//!    SSH session must not be cut by an idle timer, and that is true whatever
//!    the standing policy says. ⚠️ Today this happens on macOS only BY
//!    ACCIDENT: injecting input tickles `IOHIDSystem`, which registers as user
//!    activity. So a session where someone is *typing* is protected and a
//!    **view-only** one is not — and watching a long build is exactly the case
//!    that most wants to stay up.
//! 2. **Everything else is opt-in, default off.** A remote-access tool that
//!    silently drains a laptop battery earns the reputation it gets, so
//!    [`PowerPolicy`] is device-owned with the same last-word rule as
//!    `exec_enabled` and `ssh_enabled` (`docs/remote-config.md`).
//!
//! ## What this cannot do
//!
//! ⚠️ **macOS clamshell sleep ignores idle-sleep assertions** on a laptop with
//! no external display. Closing the lid puts the machine to sleep no matter
//! what we hold. That is an OS limit, not a bug here, and the UI that offers
//! the policy has to say so — otherwise the feature looks broken to exactly the
//! person who enabled it.
//!
//! ⚠️ Nothing here wakes a machine that is already asleep. That needs a magic
//! packet from a peer on the same L2 (FR-55 P5); `womp` is already enabled on
//! the MacBook and the overlay already knows which peers share a LAN.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How often the keeper re-reads the world. A poll rather than an event
/// subscription: AC transitions and session start/stop are both cheap to
/// observe and neither is latency-critical — being five seconds late to release
/// an assertion costs nothing.
pub const POLL: Duration = Duration::from_secs(5);

/// The device-owned standing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerPolicy {
    /// Never ask the OS to stay awake for the mesh. The default, and
    /// byte-for-byte the behaviour before FR-55.
    #[default]
    Never,
    /// Stay awake only while on mains power. The setting most laptops want:
    /// reachable at a desk, and not a dead battery in a bag.
    OnAc,
    /// Always stay awake.
    Always,
}

impl PowerPolicy {
    /// Parse the config value.
    ///
    /// ⚠️ An unrecognised value is [`PowerPolicy::Never`], never `Always`: the
    /// cost of a wrong "off" is a device that sleeps, and the cost of a wrong
    /// "on" is someone's battery. Same direction as every other gate here.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "always" => PowerPolicy::Always,
            "on-ac" | "on_ac" | "ac" => PowerPolicy::OnAc,
            _ => PowerPolicy::Never,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PowerPolicy::Never => "never",
            PowerPolicy::OnAc => "on-ac",
            PowerPolicy::Always => "always",
        }
    }
}

/// What the keeper knows when it decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inputs {
    pub policy: PowerPolicy,
    /// `None` when this platform could not tell. Deliberately three-valued:
    /// "on battery" and "we do not know" must not be collapsed, or `on-ac`
    /// silently becomes `always` on a host whose power source we cannot read.
    pub on_ac: Option<bool>,
    /// Any live remote-control or SSH session.
    pub session_active: bool,
}

/// The whole policy, in one testable place.
///
/// Pure and NOT behind a `cfg`, because the platform backends below compile
/// only on their own OS — and logic that only compiles on one platform is logic
/// the other lanes never verify. Same reasoning as
/// [`crate::macos_supervisor::decide`].
pub fn should_stay_awake(i: Inputs) -> bool {
    // Rule 1: a session outranks the policy. Cutting a live session with an
    // idle timer is never what anyone wanted, and this is the case that needs
    // no configuration to be correct.
    if i.session_active {
        return true;
    }
    match i.policy {
        PowerPolicy::Never => false,
        PowerPolicy::Always => true,
        // Unknown power source behaves as "on battery": see `Inputs::on_ac`.
        PowerPolicy::OnAc => i.on_ac.unwrap_or(false),
    }
}

/// Live work that must not be interrupted by an idle timer.
///
/// A COUNT, not a flag: two concurrent SSH sessions must not have the first one
/// to end clear the second one's protection. Shared as an `Arc` because the
/// things that hold it — an SSH handler, an `exec` run — are created all over
/// the daemon and have no other reason to know about each other.
pub type ActivityCounter = Arc<AtomicUsize>;

pub fn new_activity_counter() -> ActivityCounter {
    Arc::new(AtomicUsize::new(0))
}

/// The device-wide counter.
///
/// ⚠️ A process global, unlike the consent broker which this codebase
/// deliberately un-globalised. The difference is what absence MEANS: a missing
/// broker would have to fail one way or the other on a security question, so
/// "no broker" had to be unrepresentable. A missing counter can only mean "the
/// machine may sleep", which is the safe direction — and a machine has exactly
/// ONE power state, so a per-connection instance would be wrong rather than
/// merely inconvenient.
pub fn shared_activity() -> &'static ActivityCounter {
    static ACTIVITY: std::sync::OnceLock<ActivityCounter> = std::sync::OnceLock::new();
    ACTIVITY.get_or_init(new_activity_counter)
}

/// Holds the machine awake for as long as it lives.
///
/// RAII rather than paired calls, for the reason `ssh::Handler`'s own `Drop`
/// gives: a session ends in many ways — clean exit, the client vanishing, a
/// deadline firing, a consent refusal — and only one of them is a path someone
/// would remember to annotate. Dropping the guard is the event they all share,
/// and a missed decrement would pin the machine awake until the daemon
/// restarted.
pub struct ActivityGuard(ActivityCounter);

impl ActivityGuard {
    pub fn new(counter: &ActivityCounter) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Why the OS is being asked to stay awake — shown in `pmset -g assertions` and
/// `powercfg /requests`, so an operator inspecting the machine finds a sentence
/// rather than a process name.
const REASON: &str = "roomler: keeping this device reachable";

/// Holds (and releases) the platform's stay-awake request.
///
/// Reconciling rather than toggling: the keeper computes what SHOULD be held
/// and makes reality match, so a missed transition self-heals on the next poll
/// instead of leaving an assertion pinned forever.
pub struct PowerKeeper {
    policy: PowerPolicy,
    held: Option<imp::Handle>,
    /// Logged once, not per poll: a platform that cannot do this would
    /// otherwise print a line every five seconds for the daemon's whole life.
    warned_unsupported: bool,
}

impl PowerKeeper {
    pub fn new(policy: PowerPolicy) -> Self {
        Self {
            policy,
            held: None,
            warned_unsupported: false,
        }
    }

    /// Make the OS state match the decision. Idempotent.
    pub fn reconcile(&mut self, session_active: bool) {
        let on_ac = imp::on_ac();
        let want = should_stay_awake(Inputs {
            policy: self.policy,
            on_ac,
            session_active,
        });
        match (want, self.held.is_some()) {
            (true, false) => match imp::acquire(REASON) {
                Ok(h) => {
                    tracing::info!(
                        policy = self.policy.as_str(),
                        on_ac = ?on_ac,
                        session_active,
                        "power: holding the device awake"
                    );
                    self.held = Some(h);
                }
                Err(e) => {
                    if !self.warned_unsupported {
                        self.warned_unsupported = true;
                        tracing::warn!(
                            error = %e,
                            "power: cannot ask this OS to stay awake — the device may sleep and go offline"
                        );
                    }
                }
            },
            (false, true) => {
                if let Some(h) = self.held.take() {
                    imp::release(h);
                    tracing::info!(
                        policy = self.policy.as_str(),
                        "power: released the device to sleep normally"
                    );
                }
            }
            _ => {}
        }
    }
}

impl Drop for PowerKeeper {
    /// Release on the way out. An assertion that outlives the daemon would be a
    /// machine that never sleeps again until reboot — the exact
    /// "worse than the bug it fixes" shape FR-43's orphan taught.
    fn drop(&mut self) {
        if let Some(h) = self.held.take() {
            imp::release(h);
        }
    }
}

/// What the display assertions are called in `pmset -g assertions`.
#[cfg(target_os = "macos")]
const DISPLAY_REASON: &str = "roomler: a remote viewer is watching this screen";

/// macOS — the screen a remote viewer is watching has to be ON.
///
/// A sleeping display composites nothing, so a `CGDisplayStream` opened on it
/// delivers no frame at all: the session connects, the capture opens, no
/// encoder is ever built, and the viewer gives up and reconnects — in a loop.
/// Field-hit 2026-10-15 on a MacBook whose display had idled off
/// (`system_profiler SPDisplaysDataType`: `Display Asleep: Yes`) while the
/// machine itself stayed up.
///
/// The keeper above cannot fix that and should not: it holds
/// `PreventUserIdleSystemSleep`, which keeps the MACHINE reachable and lets the
/// display go dark on purpose. An SSH session or an `exec` has no business
/// lighting the screen. Only capture needs the pixels, so only capture takes
/// this — held by the capture worker, for exactly as long as it captures.
///
/// Two assertions, for two jobs:
/// * `IOPMAssertionDeclareUserActivity` (`caffeinate -u`) — the user is
///   active, so power the display on NOW if it is off.
/// * `PreventUserIdleDisplaySleep` (`caffeinate -d`) — keep it on while the
///   capture lives. A view-only session injects no input to count as activity,
///   so without this it would go dark again at the display-sleep timeout.
///
/// Both are released on drop, and powerd drops both itself when the process
/// dies, so neither can outlive the capture that took it.
///
/// ⚠️ Waking the display unlocks nothing: a locked Mac wakes to its lock
/// screen, and that is what the viewer sees.
/// ⚠️ A closed lid with no external display cannot be woken by any assertion
/// (the module note above).
#[cfg(target_os = "macos")]
pub struct DisplayAwake {
    activity: Option<imp::Handle>,
    hold: Option<imp::Handle>,
    was_asleep: bool,
}

#[cfg(target_os = "macos")]
impl DisplayAwake {
    pub fn acquire() -> Self {
        let was_asleep = imp::display_asleep();
        let activity = imp::declare_user_activity(DISPLAY_REASON)
            .inspect_err(
                |e| tracing::warn!(error = %e, "power: could not wake the display for a viewer"),
            )
            .ok();
        let hold = imp::acquire_typed(imp::DISPLAY_ASSERTION_TYPE, DISPLAY_REASON)
            .inspect_err(
                |e| tracing::warn!(error = %e, "power: could not keep the display on for a viewer"),
            )
            .ok();
        tracing::info!(
            was_asleep,
            woke = activity.is_some(),
            held = hold.is_some(),
            "power: a viewer is watching — the display stays on while they do"
        );
        Self {
            activity,
            hold,
            was_asleep,
        }
    }

    /// Whether the main display was asleep when the viewer arrived.
    pub fn was_asleep(&self) -> bool {
        self.was_asleep
    }
}

#[cfg(target_os = "macos")]
impl Drop for DisplayAwake {
    fn drop(&mut self) {
        for h in [self.hold.take(), self.activity.take()]
            .into_iter()
            .flatten()
        {
            imp::release(h);
        }
    }
}

/// Run the keeper for the process lifetime.
///
/// `sessions` reports whether any rc session is live; it is polled rather than
/// subscribed to, so a session that ends in any of the several ways a session
/// can end still releases the assertion.
pub async fn run(
    policy: PowerPolicy,
    sessions: Option<crate::rc_sessions::RcSessionRegistry>,
    activity: ActivityCounter,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // NOTE: no early return for `Never`. That policy means "do not keep this
    // machine awake FOR THE MESH" — a live session must still hold it, and
    // returning here would have made `never` silently mean "let sessions die
    // too". The keeper is cheap: one `load` and one platform call every 5 s.
    tracing::info!(policy = policy.as_str(), "power: keeper started (FR-55)");
    let mut keeper = PowerKeeper::new(policy);
    loop {
        // Two independent sources, because they cover different work: the
        // registry knows about rc sessions, and the counter about SSH sessions
        // and `exec` runs, which have no row there.
        let session_active = sessions
            .as_ref()
            .map(|s| !s.list().is_empty())
            .unwrap_or(false)
            || activity.load(Ordering::Relaxed) > 0;
        keeper.reconcile(session_active);
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // `keeper` drops here, releasing the assertion.
                    tracing::info!("power: keeper stopping");
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS — IOKit power assertions
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;

    pub struct Handle(u32);

    type CFStringRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    /// `kIOPMAssertionLevelOn`.
    const ASSERTION_LEVEL_ON: u32 = 255;

    /// `kIOPMAssertionTypePreventUserIdleSystemSleep` — what `caffeinate -i`
    /// takes, and the predictable choice.
    ///
    /// ⚠️ The alternative is `NetworkClientActive`, which is semantically
    /// exact for "this machine serves the network" and may interact better
    /// with Power Nap. FR-55 lists picking between them as an open decision to
    /// MEASURE; this one is chosen because its behaviour is well understood,
    /// not because it is known to be better.
    const ASSERTION_TYPE: &str = "PreventUserIdleSystemSleep";

    /// `kIOPMAssertionTypePreventUserIdleDisplaySleep` — what `caffeinate -d`
    /// takes. It implies the system stays up as well.
    pub const DISPLAY_ASSERTION_TYPE: &str = "PreventUserIdleDisplaySleep";
    /// `kIOPMUserActiveLocal`: the user is at the machine, so the display
    /// powers on. Not `kIOPMUserActiveRemote`, which by its header keeps
    /// components at the power level of a user who is NOT in front of the
    /// screen — and a remote viewer needs exactly the screen.
    const USER_ACTIVE_LOCAL: u32 = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFRelease(cf: *const c_void);
    }

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOPMAssertionCreateWithName(
            assertion_type: CFStringRef,
            assertion_level: u32,
            assertion_name: CFStringRef,
            assertion_id: *mut u32,
        ) -> i32;
        fn IOPMAssertionRelease(assertion_id: u32) -> i32;
        /// What `caffeinate -u` calls: declares the user active, which powers
        /// the display on if it is off. Any process may call it.
        fn IOPMAssertionDeclareUserActivity(
            assertion_name: CFStringRef,
            user_type: u32,
            assertion_id: *mut u32,
        ) -> i32;
        /// Returns `kIOPSTimeRemainingUnlimited` (-2.0) on mains power,
        /// `kIOPSTimeRemainingUnknown` (-1.0) while it is still working it out,
        /// and a positive number of seconds on battery. One call, a plain
        /// `f64` return, and no CoreFoundation objects to own — which is why
        /// it is used here rather than `IOPSCopyPowerSourcesInfo`.
        fn IOPSGetTimeRemainingEstimate() -> f64;
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGMainDisplayID() -> u32;
        /// `boolean_t` — an `int`.
        fn CGDisplayIsAsleep(display: u32) -> i32;
    }

    /// Wrap a Rust `&str` as a CFString. Caller owns the result.
    ///
    /// SAFETY: the bytes outlive the call, and CoreFoundation copies them.
    fn cfstr(s: &str) -> CFStringRef {
        unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                s.as_ptr(),
                s.len() as isize,
                CF_STRING_ENCODING_UTF8,
                0,
            )
        }
    }

    pub fn acquire(reason: &str) -> std::io::Result<Handle> {
        acquire_typed(
            super::ASSERTION_TYPE_OVERRIDE.unwrap_or(ASSERTION_TYPE),
            reason,
        )
    }

    pub fn acquire_typed(ty: &str, reason: &str) -> std::io::Result<Handle> {
        let ty = cfstr(ty);
        let name = cfstr(reason);
        if ty.is_null() || name.is_null() {
            // SAFETY: CFRelease tolerates only non-null; guarded.
            unsafe {
                if !ty.is_null() {
                    CFRelease(ty);
                }
                if !name.is_null() {
                    CFRelease(name);
                }
            }
            return Err(std::io::Error::other("could not build CFStrings"));
        }
        let mut id: u32 = 0;
        // SAFETY: both CFStrings are valid and non-null for the call; `id` is a
        // valid out-pointer. IOKit copies what it needs.
        let rc = unsafe { IOPMAssertionCreateWithName(ty, ASSERTION_LEVEL_ON, name, &mut id) };
        // SAFETY: we own both strings and IOKit does not retain them past the
        // call in a way that requires us to hold them.
        unsafe {
            CFRelease(ty);
            CFRelease(name);
        }
        if rc == 0 {
            Ok(Handle(id))
        } else {
            Err(std::io::Error::other(format!(
                "IOPMAssertionCreateWithName failed: {rc}"
            )))
        }
    }

    pub fn release(h: Handle) {
        // SAFETY: `h.0` is an id IOKit gave us and we have not released yet —
        // `Handle` is not `Copy`, so it cannot be released twice.
        unsafe {
            IOPMAssertionRelease(h.0);
        }
    }

    /// Wake the display, as `caffeinate -u` does. The returned assertion
    /// postpones display sleep until it is released (or powerd times it out
    /// at the display-sleep setting — releasing a timed-out id is harmless).
    pub fn declare_user_activity(reason: &str) -> std::io::Result<Handle> {
        let name = cfstr(reason);
        if name.is_null() {
            return Err(std::io::Error::other("could not build a CFString"));
        }
        let mut id: u32 = 0;
        // SAFETY: `name` is a valid, non-null CFString for the call and `id` a
        // valid out-pointer.
        let rc = unsafe { IOPMAssertionDeclareUserActivity(name, USER_ACTIVE_LOCAL, &mut id) };
        // SAFETY: we own `name`; IOKit copies what it keeps.
        unsafe { CFRelease(name) };
        if rc == 0 {
            Ok(Handle(id))
        } else {
            Err(std::io::Error::other(format!(
                "IOPMAssertionDeclareUserActivity failed: {rc}"
            )))
        }
    }

    pub fn display_asleep() -> bool {
        // SAFETY: neither call takes a pointer; the id is one CoreGraphics
        // just returned.
        unsafe { CGDisplayIsAsleep(CGMainDisplayID()) != 0 }
    }

    pub fn on_ac() -> Option<bool> {
        /// `kIOPSTimeRemainingUnlimited`.
        const UNLIMITED: f64 = -2.0;
        /// `kIOPSTimeRemainingUnknown`.
        const UNKNOWN: f64 = -1.0;
        // SAFETY: takes no arguments and cannot fail.
        let t = unsafe { IOPSGetTimeRemainingEstimate() };
        if t == UNLIMITED {
            Some(true)
        } else if t == UNKNOWN {
            None
        } else {
            Some(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Windows — a power request, not SetThreadExecutionState
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    // ⚠️ These live in TWO modules, not one: the request APIs and the request
    // TYPE are under `System::Power`, while the reason CONTEXT that describes
    // them is under `System::Threading`.
    use windows_sys::Win32::System::Power::{
        GetSystemPowerStatus, PowerClearRequest, PowerCreateRequest, PowerRequestSystemRequired,
        PowerSetRequest, SYSTEM_POWER_STATUS,
    };
    use windows_sys::Win32::System::Threading::{
        POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0,
    };

    pub struct Handle(HANDLE);
    // SAFETY: a power-request HANDLE is just a kernel handle; it is not bound
    // to the creating thread, and we only ever touch it from the keeper.
    unsafe impl Send for Handle {}

    pub fn acquire(reason: &str) -> std::io::Result<Handle> {
        // ⚠️ `PowerCreateRequest`, NOT `SetThreadExecutionState`: the latter is
        // per-THREAD, so it is tied to whichever tokio worker happened to run
        // the call and is documented as unreliable from a service — which is
        // exactly how `roomlerd` runs on a fleet host.
        let mut wide: Vec<u16> = reason.encode_utf16().collect();
        wide.push(0);
        let ctx = REASON_CONTEXT {
            Version: 0,
            Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
            Reason: REASON_CONTEXT_0 {
                SimpleReasonString: wide.as_mut_ptr(),
            },
        };
        // SAFETY: `ctx` and the string it points at are alive for the call, and
        // Windows copies the reason string into the request object.
        let h = unsafe { PowerCreateRequest(&ctx) };
        if h.is_null() || h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `h` is the handle just created.
        let ok = unsafe { PowerSetRequest(h, PowerRequestSystemRequired) };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: closing the handle we just created.
            unsafe {
                CloseHandle(h);
            }
            return Err(e);
        }
        Ok(Handle(h))
    }

    pub fn release(h: Handle) {
        // SAFETY: `h.0` was created by `acquire` and set once; clearing an
        // already-clear request is harmless, and `Handle` is not `Copy`.
        unsafe {
            PowerClearRequest(h.0, PowerRequestSystemRequired);
            CloseHandle(h.0);
        }
    }

    pub fn on_ac() -> Option<bool> {
        let mut st: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-pointer for the call.
        let ok = unsafe { GetSystemPowerStatus(&mut st) };
        if ok == 0 {
            return None;
        }
        match st.ACLineStatus {
            0 => Some(false),
            1 => Some(true),
            // 255 = "unknown", which must NOT be read as mains.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux with D-Bus — a logind inhibitor (FR-97 P3b)
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "linux", feature = "portal-capture"))]
mod imp {
    /// The inhibitor lives exactly as long as this fd: logind drops it the
    /// moment the fd closes, so a daemon that crashes cannot leave the machine
    /// pinned awake (the shape FR-43's orphan taught).
    pub struct Handle {
        _fd: std::os::fd::OwnedFd,
    }

    /// Ask logind for a `block` inhibitor, from a plain thread: zbus's
    /// blocking API panics inside the tokio runtime the keeper runs on.
    ///
    /// `sleep:idle` first. A per-user daemon runs outside every login session,
    /// where logind's polkit policy grants only `idle`
    /// (`inhibit-block-sleep` is `allow_any=no`), so it falls back to that and
    /// says so. A root daemon gets both.
    pub fn acquire(reason: &str) -> std::io::Result<Handle> {
        let why = reason.to_owned();
        std::thread::Builder::new()
            .name("power-inhibit".into())
            .spawn(move || inhibit(&why))?
            .join()
            .map_err(|_| std::io::Error::other("the logind inhibit thread panicked"))?
    }

    fn inhibit(why: &str) -> std::io::Result<Handle> {
        let conn = zbus::blocking::Connection::system().map_err(std::io::Error::other)?;
        let mut refused = String::from("nothing asked");
        for what in ["sleep:idle", "idle"] {
            match conn.call_method(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1",
                Some("org.freedesktop.login1.Manager"),
                "Inhibit",
                &(what, "roomlerd", why, "block"),
            ) {
                Ok(reply) => {
                    let fd = reply
                        .body()
                        .deserialize::<zbus::zvariant::OwnedFd>()
                        .map_err(std::io::Error::other)?;
                    if what != "sleep:idle" {
                        tracing::warn!(
                            %refused,
                            "power: logind refused a sleep inhibitor (a per-user daemon is outside every login session); holding idle only"
                        );
                    }
                    tracing::info!(what, "power: logind inhibitor taken");
                    return Ok(Handle {
                        _fd: std::os::fd::OwnedFd::from(fd),
                    });
                }
                Err(e) => refused = e.to_string(),
            }
        }
        Err(std::io::Error::other(format!(
            "logind refused an inhibitor: {refused}"
        )))
    }

    /// Closing the fd is the release.
    pub fn release(_h: Handle) {}

    pub fn on_ac() -> Option<bool> {
        super::sysfs_on_ac()
    }
}

// ---------------------------------------------------------------------------
// Everything else — a Linux build without D-Bus, and the rest
// ---------------------------------------------------------------------------
#[cfg(not(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", feature = "portal-capture")
)))]
mod imp {
    pub struct Handle;

    /// ⚠️ Fails LOUDLY once rather than pretending. logind's `Inhibit()` is
    /// D-Bus-only (no file or sysctl takes a sleep lock), and this build has no
    /// D-Bus stack: `zbus` comes with `portal-capture`, which every shipped
    /// Linux build carries (`full`), so only a hand-built agent lands here.
    pub fn acquire(_reason: &str) -> std::io::Result<Handle> {
        Err(std::io::Error::other(
            "no sleep-inhibit backend in this build (logind needs D-Bus: the portal-capture feature)",
        ))
    }

    pub fn release(_h: Handle) {}

    pub fn on_ac() -> Option<bool> {
        super::sysfs_on_ac()
    }
}

/// Readable without D-Bus, so the policy can at least be REPORTED correctly
/// even where it cannot be enforced.
#[cfg(not(any(target_os = "macos", windows)))]
fn sysfs_on_ac() -> Option<bool> {
    let dir = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let mut saw_mains = false;
    for e in dir.flatten() {
        let p = e.path();
        let kind = std::fs::read_to_string(p.join("type")).unwrap_or_default();
        if kind.trim() != "Mains" {
            continue;
        }
        saw_mains = true;
        if std::fs::read_to_string(p.join("online"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
        {
            return Some(true);
        }
    }
    // A machine with a mains supply that reports offline is on battery; a
    // machine with NO mains supply at all (a server, a VM) tells us nothing
    // about a battery, so say so rather than guess.
    saw_mains.then_some(false)
}

/// Escape hatch for the macOS assertion type, so the open decision in FR-55 can
/// be measured on a real host without a rebuild. `None` everywhere else.
#[cfg(target_os = "macos")]
static ASSERTION_TYPE_OVERRIDE: Option<&str> = None;

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs {
        Inputs {
            policy: PowerPolicy::Never,
            on_ac: Some(true),
            session_active: false,
        }
    }

    /// The rule that needs no configuration to be correct: a live session is
    /// never cut by an idle timer.
    ///
    /// ⚠️ It must hold under `Never` too — that policy means "do not keep this
    /// machine awake FOR THE MESH", not "let a session you are watching die".
    #[test]
    fn an_active_session_outranks_every_policy() {
        for policy in [PowerPolicy::Never, PowerPolicy::OnAc, PowerPolicy::Always] {
            for on_ac in [Some(true), Some(false), None] {
                assert!(
                    should_stay_awake(Inputs {
                        policy,
                        on_ac,
                        session_active: true,
                    }),
                    "a live session must win over {policy:?} / on_ac={on_ac:?}"
                );
            }
        }
    }

    /// The default must be byte-for-byte the pre-FR-55 world.
    #[test]
    fn never_is_the_default_and_holds_nothing() {
        assert_eq!(PowerPolicy::default(), PowerPolicy::Never);
        assert!(!should_stay_awake(base()));
        assert!(!should_stay_awake(Inputs {
            on_ac: Some(false),
            ..base()
        }));
    }

    /// `on-ac` is the setting a laptop wants, so the battery case is the one
    /// that must not regress.
    #[test]
    fn on_ac_follows_the_power_source() {
        assert!(should_stay_awake(Inputs {
            policy: PowerPolicy::OnAc,
            on_ac: Some(true),
            ..base()
        }));
        assert!(!should_stay_awake(Inputs {
            policy: PowerPolicy::OnAc,
            on_ac: Some(false),
            ..base()
        }));
    }

    /// ⚠️ "On battery" and "we could not tell" must not be collapsed: reading
    /// an unknown power source as mains would turn `on-ac` into `always` on
    /// every host whose supply we cannot see, which is the failure mode that
    /// drains a battery in a bag.
    #[test]
    fn an_unknown_power_source_is_treated_as_battery() {
        assert!(!should_stay_awake(Inputs {
            policy: PowerPolicy::OnAc,
            on_ac: None,
            ..base()
        }));
        // …but `always` still means always: the operator said so explicitly.
        assert!(should_stay_awake(Inputs {
            policy: PowerPolicy::Always,
            on_ac: None,
            ..base()
        }));
    }

    /// An unrecognised config value must fail SAFE. A typo'd `power_policy`
    /// should cost reachability, never someone's battery.
    #[test]
    fn an_unparseable_policy_is_never() {
        assert_eq!(PowerPolicy::parse("always"), PowerPolicy::Always);
        assert_eq!(PowerPolicy::parse("on-ac"), PowerPolicy::OnAc);
        assert_eq!(PowerPolicy::parse("on_ac"), PowerPolicy::OnAc);
        assert_eq!(PowerPolicy::parse("  ALWAYS  "), PowerPolicy::Always);
        assert_eq!(PowerPolicy::parse("never"), PowerPolicy::Never);
        assert_eq!(PowerPolicy::parse(""), PowerPolicy::Never);
        assert_eq!(PowerPolicy::parse("alwyas"), PowerPolicy::Never);
        assert_eq!(PowerPolicy::parse("yes"), PowerPolicy::Never);
    }

    /// The config value round-trips, so `meshharbor config get` shows back what
    /// was set rather than a normalised surprise.
    #[test]
    fn the_policy_round_trips_through_its_config_string() {
        for p in [PowerPolicy::Never, PowerPolicy::OnAc, PowerPolicy::Always] {
            assert_eq!(PowerPolicy::parse(p.as_str()), p);
        }
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;

    /// A count, not a flag. Two overlapping sessions, the first ending, and the
    /// machine must still be held — the bug a `bool` would have.
    #[test]
    fn overlapping_work_keeps_the_machine_held() {
        let c = new_activity_counter();
        assert_eq!(c.load(Ordering::Relaxed), 0);
        let a = ActivityGuard::new(&c);
        let b = ActivityGuard::new(&c);
        assert_eq!(c.load(Ordering::Relaxed), 2);
        drop(a);
        assert_eq!(
            c.load(Ordering::Relaxed),
            1,
            "one session ending must not release another's hold"
        );
        drop(b);
        assert_eq!(c.load(Ordering::Relaxed), 0);
    }

    /// The guard must survive being moved into a struct that is dropped on an
    /// unusual path — which is every path an SSH session actually takes.
    #[test]
    fn a_guard_released_by_unwinding_still_decrements() {
        let c = new_activity_counter();
        let res = std::panic::catch_unwind({
            let c = c.clone();
            move || {
                let _g = ActivityGuard::new(&c);
                panic!("session died the ugly way");
            }
        });
        assert!(res.is_err());
        assert_eq!(
            c.load(Ordering::Relaxed),
            0,
            "a guard dropped by unwinding must still release"
        );
    }
}
