// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P3a — reach PipeWire without linking it.
//!
//! [P2b](super::screencast) ends with a PipeWire node id and a connection fd
//! the portal handed us. This is the step that uses that fd — and the step the
//! whole FR has been shaped around, because *how* we reach `libpipewire`
//! decides whether the daemon still starts on hosts that will never run a
//! portal.
//!
//! ## Why `dlopen`, spelled out once
//!
//! Linking `libpipewire` puts it in `roomlerd`'s `DT_NEEDED` on **every** Linux
//! build. A missing `.so` there does not degrade a feature — the loader refuses
//! to start the process at all. Cluster nodes, containers and headless fleet
//! hosts would carry it for nothing and break if it went missing. This project
//! has already paid for that once, when vendored FFmpeg dylibs baked a Homebrew
//! path into the macOS agent and dyld killed it at launch on every end-user
//! Mac.
//!
//! ⚠️ **A helper subcommand does not fix this.** `roomlerd portal-helper` is the
//! same ELF as `roomlerd`; linking for the helper's sake links for everyone.
//! The subcommand bought the *session context* (P2a); only `dlopen` buys the
//! *linkage*. It would have been easy to reach here believing P2a settled it.
//!
//! So: resolved at runtime, and every failure is a status this backend reports
//! rather than a condition anything else has to survive.
//!
//! ## What this phase does and does not prove
//!
//! It loads the library, initialises PipeWire, builds a context, and connects
//! **the portal's fd** to it. A successful connect means the socket was
//! accepted and a core proxy exists — the fd is real and usable.
//!
//! ⚠️ It does **not** prove frames flow. Format negotiation (SPA PODs) and
//! buffer delivery are P3b, and claiming otherwise from a non-null pointer
//! would be exactly the kind of unfalsifiable "it works" this FR keeps
//! rejecting.
//!
//! ## Dependencies added: none
//!
//! `libc` was already in the graph. There is no `pipewire` crate here on
//! purpose — adding one would link the library and undo the whole point.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Arc;

/// Sonames to try, most specific first.
///
/// The versioned soname is what packages actually install; the bare `.so` is
/// the `-devel` symlink and is often absent on a runtime-only host. Trying
/// both costs nothing and covers distros that ship only one.
const CANDIDATES: &[&str] = &["libpipewire-0.3.so.0", "libpipewire-0.3.so"];

/// What came of trying to reach PipeWire with the portal's fd.
///
/// Reported rather than logged, because the three cases need different things
/// done about them and a bool would flatten them: *not tried* (the portal gave
/// us no fd), *connected*, and *the library is missing or refused us*.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PipeWireStatus {
    /// No fd to try — the handshake did not get that far.
    NotAttempted,
    /// The portal's fd is live PipeWire, but no stream was opened. ⚠️ This
    /// does **not** mean frames flow — it is P3a's answer, kept because
    /// "reached the daemon" and "agreed a format" fail for different reasons
    /// and an operator needs to know which happened.
    Connected {
        library_version: String,
    },
    /// A stream connected and the compositor agreed a concrete format. ⚠️
    /// Still not frames: buffer delivery is P3c.
    Negotiated {
        library_version: String,
        format: NegotiatedFormat,
        /// `None` when only negotiation was asked for. `Some` carries what
        /// actually arrived in the buffers — which is the only thing that
        /// distinguishes a working capture from a black one.
        frames: Option<FrameReport>,
    },
    Failed(String),
}

impl std::fmt::Display for PipeWireStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeWireStatus::NotAttempted => write!(f, "not attempted (no fd)"),
            PipeWireStatus::Connected { library_version } => {
                write!(f, "connected (libpipewire {library_version}), no stream")
            }
            PipeWireStatus::Negotiated {
                library_version,
                format,
                frames: None,
            } => write!(f, "negotiated {format} (libpipewire {library_version})"),
            PipeWireStatus::Negotiated {
                library_version,
                format,
                frames: Some(fr),
            } => write!(
                f,
                "negotiated {format}; {fr} (libpipewire {library_version})"
            ),
            PipeWireStatus::Failed(why) => write!(f, "unavailable — {why}"),
        }
    }
}

/// P3a — load the library and connect the fd, keeping nothing.
///
/// Superseded by [`negotiate_status`] for the capture path, and kept because
/// it isolates one question: is the fd live PipeWire at all? When negotiation
/// fails, running this says whether the problem is the connection or the
/// format.
pub fn probe(source: PwSource) -> PipeWireStatus {
    let lib = match Lib::load() {
        Ok(l) => l,
        Err(e) => return PipeWireStatus::Failed(e.to_string()),
    };
    match Connection::open(lib, source) {
        Ok(conn) => PipeWireStatus::Connected {
            library_version: conn.library_version(),
        },
        Err(e) => PipeWireStatus::Failed(e.to_string()),
    }
}

/// P3b-ii — connect a stream to the portal's node and report what the
/// compositor agreed to.
pub fn negotiate_status(
    source: PwSource,
    node_id: u32,
    max_fps: u32,
    want_frames: u32,
) -> PipeWireStatus {
    // Read before the source moves: the version is worth reporting on both arms,
    // and by the time negotiation fails the library handle is gone.
    let library_version = match Lib::load() {
        Ok(l) => l.version(),
        Err(e) => return PipeWireStatus::Failed(e.to_string()),
    };
    match negotiate(source, node_id, max_fps, want_frames) {
        Ok((format, frames)) => PipeWireStatus::Negotiated {
            library_version,
            format,
            frames,
        },
        Err(e) => PipeWireStatus::Failed(e.to_string()),
    }
}

/// Why PipeWire could not be reached. Every arm is reportable, because on a
/// host with no PipeWire this backend being unavailable is the *correct*
/// outcome, not a fault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PwError {
    /// No candidate soname could be loaded. Carries what was tried, so the
    /// reader is not left guessing which name to install.
    NotFound {
        tried: Vec<String>,
        last: String,
    },
    /// The library loaded but is missing a symbol we need — a PipeWire too old
    /// or too new. Named, because "PipeWire failed" would send someone to the
    /// wrong place entirely.
    MissingSymbol(String),
    /// `pw_context_new` failed.
    NoContext,
    /// `pw_context_connect_fd` refused the portal's fd.
    ConnectFailed(String),
    Other(String),
}

impl std::fmt::Display for PwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwError::NotFound { tried, last } => write!(
                f,
                "libpipewire not present (tried {}): {last}",
                tried.join(", ")
            ),
            PwError::MissingSymbol(s) => {
                write!(f, "libpipewire is missing {s} — unexpected version")
            }
            PwError::NoContext => write!(f, "pw_context_new returned null"),
            PwError::ConnectFailed(e) => {
                write!(f, "pw_context_connect_fd refused the portal fd: {e}")
            }
            PwError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// Declare the entry points once: field name **is** the C symbol name, and the
/// type is used both for the field and for the `transmute`.
///
/// 🔑 Worth the macro. Written by hand, a symbol string and its field can
/// drift apart — you resolve `"pw_context_connect"` into the field you call as
/// `pw_context_connect_fd` and get a signature mismatch at runtime, in FFI,
/// where the failure is memory corruption rather than an error. Here they are
/// the same token, so they cannot disagree.
macro_rules! pw_syms {
    ($($name:ident: $t:ty,)*) => {
        /// The resolved entry points.
        ///
        /// Only what P3a needs. Stream creation and SPA POD building arrive in
        /// P3b; resolving symbols we do not call yet would make a *newer*
        /// PipeWire that dropped one of them look broken here for no reason.
        struct Syms { $($name: $t,)* }

        impl Syms {
            /// # Safety
            /// `handle` must be a live `dlopen` handle for libpipewire.
            unsafe fn resolve(handle: *mut c_void) -> Result<Self, PwError> {
                Ok(Self { $($name: {
                    let c = CString::new(stringify!($name)).expect("ident has no NUL");
                    let p = unsafe { libc::dlsym(handle, c.as_ptr()) };
                    if p.is_null() {
                        return Err(PwError::MissingSymbol(stringify!($name).into()));
                    }
                    // SAFETY: the signature is the one libpipewire declares
                    // for this symbol, transcribed from its headers. RTLD_NOW
                    // has already proven the symbol exists in the library we
                    // actually loaded.
                    unsafe { std::mem::transmute::<*mut c_void, $t>(p) }
                },)* })
            }
        }
    };
}

pw_syms! {
    pw_init: unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char),
    pw_get_library_version: unsafe extern "C" fn() -> *const c_char,
    pw_main_loop_new: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    pw_main_loop_get_loop: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pw_main_loop_destroy: unsafe extern "C" fn(*mut c_void),
    pw_main_loop_run: unsafe extern "C" fn(*mut c_void) -> c_int,
    pw_main_loop_quit: unsafe extern "C" fn(*mut c_void) -> c_int,
    pw_context_new: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void,
    pw_context_destroy: unsafe extern "C" fn(*mut c_void),
    pw_context_connect_fd:
        unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize) -> *mut c_void,
    // FR-45 P5 — mutter's own ScreenCast API hands out a NODE ID, not a remote
    // fd, so that path connects to the session's own PipeWire the ordinary
    // way. Same core afterwards; only the way in differs.
    pw_context_connect: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void,
    pw_core_disconnect: unsafe extern "C" fn(*mut c_void) -> c_int,
    // ⚠️ `_new_string`, not `pw_properties_new` — the latter is VARARGS, which
    // cannot be called through a plain `dlsym`'d function pointer without
    // pinning the exact argument list. This one takes "k=v k=v" and is a
    // normal C function.
    pw_properties_new_string: unsafe extern "C" fn(*const c_char) -> *mut c_void,
    pw_stream_new: unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void) -> *mut c_void,
    pw_stream_add_listener:
        unsafe extern "C" fn(*mut c_void, *mut c_void, *const PwStreamEvents, *mut c_void),
    pw_stream_connect: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        u32,
        u32,
        *const *const c_void,
        u32,
    ) -> c_int,
    pw_stream_destroy: unsafe extern "C" fn(*mut c_void),
    pw_stream_dequeue_buffer: unsafe extern "C" fn(*mut c_void) -> *mut PwBuffer,
    pw_stream_queue_buffer: unsafe extern "C" fn(*mut c_void, *mut PwBuffer) -> c_int,
}

/// A loaded `libpipewire`.
///
/// ⚠️ The handle is **never `dlclose`d**. PipeWire keeps global state and
/// spawns threads; unloading it underneath them is a crash waiting for a
/// quiet moment. Leaking one handle for the life of a process that has
/// decided to use PipeWire is the cheap, correct trade — the same reason
/// nobody `dlclose`s a plugin host.
pub struct Lib {
    syms: Syms,
}

// SAFETY: `Syms` holds only function pointers into a library that is never
// unloaded, so sharing them across threads is sound. PipeWire's own objects
// are NOT thread-safe and are confined to `Connection`, which is not `Send`.
unsafe impl Send for Lib {}
unsafe impl Sync for Lib {}

impl Lib {
    /// Load PipeWire, or say precisely why not.
    pub fn load() -> Result<Arc<Self>, PwError> {
        Self::load_from(CANDIDATES)
    }

    /// The load, parameterised over candidate names so the not-found path can
    /// be tested without uninstalling anything.
    pub fn load_from(candidates: &[&str]) -> Result<Arc<Self>, PwError> {
        let mut tried = Vec::new();
        let mut last = String::from("no candidates given");
        for name in candidates {
            tried.push((*name).to_string());
            let Ok(cname) = CString::new(*name) else {
                last = format!("{name}: not a valid library name");
                continue;
            };
            // RTLD_NOW so a missing symbol surfaces here rather than at the
            // first call, and RTLD_LOCAL so PipeWire's symbols cannot leak
            // into anything else this process later loads.
            let handle = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                last = dlerror_string().unwrap_or_else(|| format!("{name}: dlopen failed"));
                continue;
            }
            return Ok(Arc::new(Self {
                syms: unsafe { Syms::resolve(handle) }?,
            }));
        }
        Err(PwError::NotFound { tried, last })
    }

    pub fn version(&self) -> String {
        let p = unsafe { (self.syms.pw_get_library_version)() };
        if p.is_null() {
            return "unknown".into();
        }
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Deliberately terse: the interesting fact about a loaded library is which
/// version it is, and the resolved pointers are noise in any log line.
impl std::fmt::Debug for Lib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lib")
            .field("version", &self.version())
            .finish()
    }
}

fn dlerror_string() -> Option<String> {
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// A live connection to the session's PipeWire, made through the portal's fd.
///
/// Not `Send`: PipeWire's loop and core belong to the thread that made them.
pub struct Connection {
    lib: Arc<Lib>,
    main_loop: *mut c_void,
    context: *mut c_void,
    core: *mut c_void,
}

/// Where a PipeWire connection comes from.
///
/// The portal hands out a **remote fd** (`OpenPipeWireRemote`); mutter's own
/// ScreenCast API (FR-45 P5) hands out only a node id and expects us to reach
/// the session's PipeWire the ordinary way. Everything after the connect is
/// identical, so the difference is confined to this enum.
pub enum PwSource {
    /// The portal's fd. ⚠️ Ownership transfers to PipeWire on success.
    Fd(std::os::fd::OwnedFd),
    /// The session's own PipeWire, via `PIPEWIRE_REMOTE`/`XDG_RUNTIME_DIR` —
    /// which is correct here because the helper already runs AS the session
    /// user, whose PipeWire this is.
    Session,
}

impl Connection {
    /// Connect to PipeWire, from either source.
    ///
    /// ⚠️ **`pw_context_connect_fd` takes ownership of the fd** and closes it
    /// on disconnect, so the fd is handed over as a raw descriptor and must
    /// not be closed here. Passing a borrowed fd and letting Rust close it too
    /// is a double close — which on a busy process closes *somebody else's*
    /// descriptor, the ugliest class of bug to chase.
    pub fn open(lib: Arc<Lib>, source: PwSource) -> Result<Self, PwError> {
        use std::os::fd::IntoRawFd;

        // `pw_init` is process-global and must run once. Running it per
        // connection is documented as harmless but pointless; running it never
        // leaves the type system uninitialised.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| unsafe {
            (lib.syms.pw_init)(std::ptr::null_mut(), std::ptr::null_mut());
        });

        let main_loop = unsafe { (lib.syms.pw_main_loop_new)(std::ptr::null()) };
        if main_loop.is_null() {
            return Err(PwError::Other("pw_main_loop_new returned null".into()));
        }
        let loop_ = unsafe { (lib.syms.pw_main_loop_get_loop)(main_loop) };
        let context = unsafe { (lib.syms.pw_context_new)(loop_, std::ptr::null_mut(), 0) };
        if context.is_null() {
            unsafe { (lib.syms.pw_main_loop_destroy)(main_loop) };
            return Err(PwError::NoContext);
        }

        let (core, raw_fd) = match source {
            PwSource::Fd(fd) => {
                let raw = fd.into_raw_fd();
                let core = unsafe {
                    (lib.syms.pw_context_connect_fd)(context, raw, std::ptr::null_mut(), 0)
                };
                (core, Some(raw))
            }
            PwSource::Session => {
                let core =
                    unsafe { (lib.syms.pw_context_connect)(context, std::ptr::null_mut(), 0) };
                (core, None)
            }
        };
        if core.is_null() {
            let why = std::io::Error::last_os_error().to_string();
            // The fd's ownership only transfers on success, so close it here.
            if let Some(raw) = raw_fd {
                unsafe { libc::close(raw) };
            }
            unsafe { (lib.syms.pw_context_destroy)(context) };
            unsafe { (lib.syms.pw_main_loop_destroy)(main_loop) };
            return Err(PwError::ConnectFailed(why));
        }

        Ok(Self {
            lib,
            main_loop,
            context,
            core,
        })
    }

    pub fn library_version(&self) -> String {
        self.lib.version()
    }
}

impl Drop for Connection {
    /// ⚠️ Order is load-bearing and is the reverse of construction: the core
    /// is a proxy inside the context, and the context runs on the loop.
    /// Destroying the loop first frees memory the other two still reference.
    fn drop(&mut self) {
        unsafe {
            (self.lib.syms.pw_core_disconnect)(self.core);
            (self.lib.syms.pw_context_destroy)(self.context);
            (self.lib.syms.pw_main_loop_destroy)(self.main_loop);
        }
    }
}

// ── P3b-ii: connect a stream and negotiate a format ─────────────────────

/// `struct pw_stream_events`, transcribed from `pipewire/stream.h`.
///
/// ⚠️ **Every field and its order is load-bearing.** This is a vtable the
/// library indexes by offset: one missing or reordered pointer means it calls
/// the wrong function with the wrong arguments. The list is complete as of
/// `PW_VERSION_STREAM_EVENTS = 2` — `version` tells the library how much of
/// this struct it may read, so declaring 2 while providing fewer fields would
/// invite it past the end.
#[repr(C)]
struct PwStreamEvents {
    version: u32,
    destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    state_changed: Option<unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_char)>,
    control_info: Option<unsafe extern "C" fn(*mut c_void, u32, *const c_void)>,
    io_changed: Option<unsafe extern "C" fn(*mut c_void, u32, *mut c_void, u32)>,
    param_changed: Option<unsafe extern "C" fn(*mut c_void, u32, *const c_void)>,
    add_buffer: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    remove_buffer: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    process: Option<unsafe extern "C" fn(*mut c_void)>,
    drained: Option<unsafe extern "C" fn(*mut c_void)>,
    command: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
    trigger_done: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// `struct spa_hook` — six pointers (`spa_list` × 2, `spa_callbacks` × 2,
/// `removed`, `priv`). Opaque to us: the library initialises and owns it, we
/// only have to provide storage that does not move and outlives the stream.
#[repr(C)]
struct SpaHook([usize; 6]);

/// `enum pw_stream_flags`, and the direction.
const PW_DIRECTION_INPUT: c_int = 0;
const PW_STREAM_FLAG_AUTOCONNECT: u32 = 1 << 0;
const PW_STREAM_FLAG_MAP_BUFFERS: u32 = 1 << 2;
/// `enum pw_stream_state` — frames flow only while `STREAMING`.
pub const PW_STREAM_STATE_STREAMING: i32 = 3;
/// `enum spa_param_type` — the *negotiated* format (not `EnumFormat`).
const SPA_PARAM_FORMAT: u32 = 4;

// ── P3c-i: buffers ──────────────────────────────────────────────────────

/// `struct pw_buffer`, `pipewire/stream.h`.
#[repr(C)]
struct PwBuffer {
    buffer: *mut SpaBuffer,
    user_data: *mut c_void,
    size: u64,
    requested: u64,
    time: u64,
}

/// `struct spa_buffer`, `spa/buffer/buffer.h`.
#[repr(C)]
struct SpaBuffer {
    n_metas: u32,
    n_datas: u32,
    metas: *mut c_void,
    datas: *mut SpaData,
}

/// `struct spa_data`. ⚠️ `fd` is `int64_t`, not an `int` — getting that wrong
/// shifts every field after it.
#[repr(C)]
struct SpaData {
    ty: u32,
    flags: u32,
    fd: i64,
    mapoffset: u32,
    maxsize: u32,
    data: *mut c_void,
    chunk: *mut SpaChunk,
}

/// `struct spa_chunk` — where the *valid* bytes are. `maxsize` is the
/// allocation; this is the frame.
#[repr(C)]
struct SpaChunk {
    offset: u32,
    size: u32,
    stride: i32,
    flags: i32,
}

/// `enum spa_data_type`.
const SPA_DATA_MEM_PTR: u32 = 1;
const SPA_DATA_MEM_FD: u32 = 2;
const SPA_DATA_DMA_BUF: u32 = 3;

fn data_type_name(t: u32) -> &'static str {
    match t {
        0 => "Invalid",
        SPA_DATA_MEM_PTR => "MemPtr",
        SPA_DATA_MEM_FD => "MemFd",
        SPA_DATA_DMA_BUF => "DmaBuf",
        4 => "MemId",
        _ => "unknown",
    }
}

/// What actually arrived in the buffers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrameReport {
    pub frames: u32,
    /// `enum spa_data_type` of the first plane.
    pub data_type: u32,
    pub data_type_name: String,
    pub stride: i32,
    /// `chunk.size` — the valid bytes, not the allocation.
    pub bytes: u32,
    /// How many of the sampled bytes were non-zero, and how many were looked
    /// at. 🔑 **This is the point of the whole report**: a black frame and a
    /// working capture are both "frames received", and only content tells them
    /// apart.
    pub nonzero_sampled: u32,
    pub sampled: u32,
    /// Cheap hash of the sampled bytes. Two runs differing here means the
    /// screen changed between them — i.e. these are live pixels, not a
    /// constant.
    pub checksum: u32,
    /// Set when the buffer could not be read at all, with the reason.
    pub unreadable: Option<String>,
}

impl std::fmt::Display for FrameReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(why) = &self.unreadable {
            return write!(
                f,
                "{} frame(s) as {} but unreadable — {why}",
                self.frames, self.data_type_name
            );
        }
        write!(
            f,
            "{} frame(s), {} stride={} {} bytes, {}/{} sampled bytes non-zero, checksum {:#010x}",
            self.frames,
            self.data_type_name,
            self.stride,
            self.bytes,
            self.nonzero_sampled,
            self.sampled,
            self.checksum
        )
    }
}

/// Walk a frame cheaply: hash and count non-zero bytes over a sample.
///
/// Sampled rather than read whole because this runs in the realtime-ish
/// `process` callback and a 4K frame is 33 MB. The stride is prime so the
/// sample cannot align with a repeating pattern and miss content — a full read
/// would be no more convincing and much slower.
fn sample(bytes: &[u8]) -> (u32, u32, u32) {
    const STEP: usize = 997;
    let (mut hash, mut nonzero, mut n) = (2166136261u32, 0u32, 0u32);
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        hash = (hash ^ b as u32).wrapping_mul(16777619);
        if b != 0 {
            nonzero += 1;
        }
        n += 1;
        i += STEP;
    }
    (hash, nonzero, n)
}

/// The format the compositor actually agreed to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NegotiatedFormat {
    /// `enum spa_video_format` — 8 is BGRx, 12 BGRA, 7 RGBx, 11 RGBA.
    pub video_format: u32,
    pub width: u32,
    pub height: u32,
    pub fps_num: u32,
    pub fps_denom: u32,
}

impl std::fmt::Display for NegotiatedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.video_format {
            7 => "RGBx",
            8 => "BGRx",
            11 => "RGBA",
            12 => "BGRA",
            other => return write!(f, "format#{other} {}x{}", self.width, self.height),
        };
        write!(
            f,
            "{name} {}x{} @ {}/{}",
            self.width, self.height, self.fps_num, self.fps_denom
        )
    }
}

/// Shared with the C callbacks. Reached only from the loop thread.
struct Shared {
    lib: Arc<Lib>,
    main_loop: *mut c_void,
    /// Set once the stream exists, so `process` can dequeue from it.
    stream: Option<*mut c_void>,
    /// 0 means "stop as soon as a format is settled" — the P3b-ii behaviour,
    /// kept because it isolates negotiation from delivery when one of them
    /// breaks.
    want_frames: u32,
    frames: u32,
    format: Option<NegotiatedFormat>,
    first_frame: Option<FrameReport>,
    /// Where copied frames go, when streaming. `None` = P3c-i's
    /// count-and-report mode.
    frame_tx: Option<std::sync::mpsc::SyncSender<(super::wire::FrameHeader, Vec<u8>)>>,
    /// Frames thrown away because the consumer was behind. Counted rather than
    /// silent: a capture dropping most of what it produces is a very different
    /// problem from one producing nothing.
    dropped: u64,
    outcome: Option<Result<NegotiatedFormat, String>>,
    /// How many Format params arrived that could not be used yet. Reported so
    /// a timeout can say whether nothing came at all or several came and none
    /// fixated — different problems with different fixes.
    rejected: u32,
    /// FR-93 P5c — the stream's state as the loop last reported it, for a
    /// streaming caller: a stream whose source vanished goes to paused and
    /// reports no error.
    state: Option<Arc<std::sync::atomic::AtomicI32>>,
}

impl Shared {
    /// Record a verdict and stop the loop. Only the FIRST verdict counts: a
    /// stream can report an error after a good format, and overwriting a
    /// success with a late teardown message would lose the answer.
    fn finish(&mut self, r: Result<NegotiatedFormat, String>) {
        if self.outcome.is_none() {
            self.outcome = Some(r);
        }
        unsafe { (self.lib.syms.pw_main_loop_quit)(self.main_loop) };
    }
}

/// ⚠️ A panic must never cross back into C — that is undefined behaviour, not
/// a crash with a message. Every callback body goes through this.
fn guard(data: *mut c_void, f: impl FnOnce(&mut Shared)) {
    if data.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `data` is the `Shared` we handed to `pw_stream_add_listener`,
        // which outlives the stream, and PipeWire calls back only from the
        // loop thread, so there is no aliasing.
        let shared = unsafe { &mut *(data as *mut Shared) };
        f(shared)
    }));
}

/// `pw_stream_state` in words, for the helper's log and its errors.
fn state_name(s: i32) -> &'static str {
    match s {
        -1 => "in error",
        0 => "unconnected",
        1 => "connecting",
        2 => "paused",
        3 => "streaming",
        _ => "in an unknown state",
    }
}

unsafe extern "C" fn on_state_changed(
    data: *mut c_void,
    _old: c_int,
    state: c_int,
    error: *const c_char,
) {
    // FR-93 P5i — said as it happens: a stream that stays `paused` is one the
    // compositor never drove, which a missing frame alone cannot tell apart
    // from a format that produces nothing.
    eprintln!(
        "portal-helper: the PipeWire stream is {}",
        state_name(state)
    );
    guard(data, |shared| {
        if let Some(cell) = &shared.state {
            cell.store(state, std::sync::atomic::Ordering::Relaxed);
        }
        // -1 is PW_STREAM_STATE_ERROR. Anything else is progress, and the
        // format arrives via param_changed rather than here.
        if state == -1 {
            let why = if error.is_null() {
                "the stream reported an error with no message".to_string()
            } else {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            shared.finish(Err(why));
        }
    });
}

/// Called when a buffer is ready. Dequeue, look, queue it straight back.
///
/// ⚠️ The buffer **must** be returned with `pw_stream_queue_buffer` on every
/// path. Holding them starves the pool and the stream simply stops — silently,
/// looking exactly like a source that produced nothing.
unsafe extern "C" fn on_process(data: *mut c_void) {
    guard(data, |shared| {
        let Some(stream) = shared.stream else { return };
        let pw_buf = unsafe { (shared.lib.syms.pw_stream_dequeue_buffer)(stream) };
        if pw_buf.is_null() {
            // Out of buffers is normal back-pressure, not an error.
            return;
        }
        shared.frames += 1;
        // Inspect only the first frame in depth; after that just count, so a
        // slow callback cannot become the reason frames stop arriving.
        if shared.frames == 1 {
            shared.first_frame = Some(unsafe { inspect(pw_buf) });
        }
        // P3c-ii — copy out and hand off, while the buffer is still ours.
        if let Some(tx) = &shared.frame_tx
            && let Some(fmt) = &shared.format
            && let Some((h, bytes)) = unsafe { copy_out(pw_buf, fmt) }
        {
            // ⚠️ DROP when the consumer is behind; never block. This runs on
            // PipeWire's own thread, so waiting here stalls the compositor's
            // producer — and a capture pipeline wants the NEWEST frame, not a
            // queue of stale ones.
            if tx.try_send((h, bytes)).is_err() {
                shared.dropped += 1;
            }
        }
        unsafe { (shared.lib.syms.pw_stream_queue_buffer)(stream, pw_buf) };

        if shared.frames >= shared.want_frames {
            let format = shared.format.clone();
            match format {
                Some(f) => shared.finish(Ok(f)),
                // Frames without a format should be impossible; say so rather
                // than inventing one.
                None => shared.finish(Err("frames arrived before a format did".into())),
            }
        }
    });
}

/// Copy the pixels out of a buffer, with a header describing them.
///
/// ⚠️ Copied while the buffer is still dequeued — it goes back to the
/// compositor immediately after, and reading it later is reading pixels
/// someone else is writing.
///
/// # Safety
/// `pw_buf` must be a buffer just dequeued from the stream.
unsafe fn copy_out(
    pw_buf: *mut PwBuffer,
    fmt: &NegotiatedFormat,
) -> Option<(super::wire::FrameHeader, Vec<u8>)> {
    let spa_buf = unsafe { (*pw_buf).buffer };
    if spa_buf.is_null() || unsafe { (*spa_buf).n_datas } == 0 {
        return None;
    }
    let d = unsafe { &*(*spa_buf).datas };
    // A DmaBuf is not mapped; there is nothing to copy. P3c-i reports the type
    // so this is diagnosable rather than a silent absence of frames.
    if d.data.is_null() || d.chunk.is_null() {
        return None;
    }
    let chunk = unsafe { &*d.chunk };
    if chunk.size == 0 || chunk.stride <= 0 {
        return None;
    }
    let offset = (chunk.offset as usize).min(d.maxsize as usize);
    let len = (chunk.size as usize).min(d.maxsize as usize - offset);
    let bytes = unsafe { std::slice::from_raw_parts((d.data as *const u8).add(offset), len) };
    Some((
        super::wire::FrameHeader {
            width: fmt.width,
            height: fmt.height,
            stride: chunk.stride as u32,
            video_format: fmt.video_format,
            len: len as u32,
        },
        bytes.to_vec(),
    ))
}

/// Read what one buffer says about itself.
///
/// # Safety
/// `pw_buf` must be a buffer just dequeued from the stream.
unsafe fn inspect(pw_buf: *mut PwBuffer) -> FrameReport {
    let mut r = FrameReport {
        frames: 0,
        data_type: 0,
        data_type_name: "none".into(),
        stride: 0,
        bytes: 0,
        nonzero_sampled: 0,
        sampled: 0,
        checksum: 0,
        unreadable: None,
    };
    let spa_buf = unsafe { (*pw_buf).buffer };
    if spa_buf.is_null() || unsafe { (*spa_buf).n_datas } == 0 {
        r.unreadable = Some("the buffer carried no data planes".into());
        return r;
    }
    let d = unsafe { &*(*spa_buf).datas };
    r.data_type = d.ty;
    r.data_type_name = data_type_name(d.ty).to_string();

    let chunk = d.chunk;
    if chunk.is_null() {
        r.unreadable = Some("the plane has no chunk".into());
        return r;
    }
    let chunk = unsafe { &*chunk };
    r.stride = chunk.stride;
    r.bytes = chunk.size;

    // ⚠️ A DmaBuf is NOT mapped, even with MAP_BUFFERS — `data` is null and
    // the pixels live on the GPU. Reading it needs a GBM/EGL import, which is
    // a whole dependency this FR has been avoiding. Report it rather than
    // dereferencing null, because "which memory type did we get" is exactly
    // the question P3c-ii has to answer.
    if d.data.is_null() {
        r.unreadable = Some(format!(
            "{} planes are not mmap'd (data is null) — a DmaBuf needs a GBM import",
            r.data_type_name
        ));
        return r;
    }
    if chunk.size == 0 {
        r.unreadable = Some("the chunk is empty".into());
        return r;
    }

    // Clamp to the allocation: `offset`/`size` come from the producer and the
    // header says to treat them modulo `maxsize`.
    let offset = (chunk.offset as usize).min(d.maxsize as usize);
    let len = (chunk.size as usize).min(d.maxsize as usize - offset);
    let bytes = unsafe { std::slice::from_raw_parts((d.data as *const u8).add(offset), len) };
    let (checksum, nonzero, sampled) = sample(bytes);
    r.checksum = checksum;
    r.nonzero_sampled = nonzero;
    r.sampled = sampled;
    r
}

unsafe extern "C" fn on_param_changed(data: *mut c_void, id: u32, param: *const c_void) {
    guard(data, |shared| {
        // A null param means "this parameter was cleared", and ids other than
        // Format are none of our business — neither is an error.
        if id != SPA_PARAM_FORMAT || param.is_null() {
            return;
        }
        let bytes = match unsafe { copy_pod(param) } {
            Some(b) => b,
            None => return shared.finish(Err("the format param was unreadable".into())),
        };
        match parse_format(&bytes) {
            Ok(f) => {
                shared.format = Some(f.clone());
                // With frames wanted, a settled format is the START, not the
                // finish: keep the loop running so `process` can deliver.
                if shared.want_frames == 0 {
                    shared.finish(Ok(f));
                }
            }
            // ⚠️ Do NOT finish here. `param_changed` can fire more than once,
            // and an early one may still carry choices where the final one
            // carries values — PipeWire fixates as it negotiates. Treating the
            // first Format as final turned a working stream into
            // "the negotiated video format is not a plain id" in the field.
            // Keep waiting; the deadline is the backstop.
            Err(why) => {
                shared.rejected += 1;
                eprintln!(
                    "portal-helper: format #{} not usable yet ({why}); contents: {}",
                    shared.rejected,
                    describe(&bytes)
                );
            }
        }
    });
}

/// A one-line summary of a format POD, for when it could not be used.
///
/// Exists because "not a plain id" on its own does not say *what* arrived, and
/// the alternative is another build-and-deploy cycle to find out.
fn describe(bytes: &[u8]) -> String {
    use super::pod::{ParsedValue, parse_object};
    match parse_object(bytes) {
        Err(e) => format!("<unparseable: {e}>"),
        Ok(o) => {
            let props: Vec<String> = o
                .props
                .iter()
                .map(|(k, v)| {
                    let v = match v {
                        ParsedValue::Id(x) => format!("Id({x})"),
                        ParsedValue::Int(x) => format!("Int({x})"),
                        ParsedValue::Rectangle { width, height } => format!("{width}x{height}"),
                        ParsedValue::Fraction { num, denom } => format!("{num}/{denom}"),
                        ParsedValue::Choice { kind, first } => {
                            format!("choice(kind={kind}, {first:?})")
                        }
                        ParsedValue::Unsupported { pod_type } => format!("pod-type#{pod_type}"),
                    };
                    format!("0x{k:x}={v}")
                })
                .collect();
            format!(
                "object#{:x} id={} [{}]",
                o.object_type,
                o.id,
                props.join(" ")
            )
        }
    }
}

/// Copy a POD out of the library's memory so it can be parsed safely.
///
/// ⚠️ The length comes from the data itself, so it is sanity-bounded before
/// being used to build a slice: a corrupt header must not become a read of
/// gigabytes from another process's heap.
///
/// # Safety
/// `p` must point to a readable `spa_pod` header.
unsafe fn copy_pod(p: *const c_void) -> Option<Vec<u8>> {
    const MAX_POD: usize = 1 << 20;
    let header = unsafe { std::slice::from_raw_parts(p as *const u8, 8) };
    let size = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if size > MAX_POD {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(p as *const u8, 8 + size) }.to_vec())
}

fn parse_format(bytes: &[u8]) -> Result<NegotiatedFormat, String> {
    use super::pod::{ParsedValue, parse_object, ty};
    let o = parse_object(bytes).map_err(|e| format!("parsing the negotiated format: {e}"))?;

    // ⚠️ Every lookup goes through `.fixed()`. SPA writes a settled value as a
    // `Choice(None)` holding one element — a negotiated format on GNOME 48
    // arrives with EVERY property wrapped that way, `mediaType` included. A
    // `Range` or `Enum` still means "not settled yet" and `.fixed()` returns
    // None, which keeps the caller waiting instead of reporting a default as
    // though it were agreed.
    let Some(ParsedValue::Id(video_format)) = o
        .get(ty::FORMAT_VIDEO_FORMAT)
        .ok_or("the negotiated format has no video format")?
        .fixed()
    else {
        return Err("the video format is not settled yet".into());
    };
    let Some(ParsedValue::Rectangle { width, height }) = o
        .get(ty::FORMAT_VIDEO_SIZE)
        .ok_or("the negotiated format has no size")?
        .fixed()
    else {
        return Err("the size is not settled yet".into());
    };
    let (video_format, width, height) = (*video_format, *width, *height);
    // Framerate is genuinely optional — some sources leave it unset rather
    // than committing to a rate — so its absence is 0/1, not a failure.
    let (fps_num, fps_denom) = match o.get(ty::FORMAT_VIDEO_FRAMERATE).and_then(|v| v.fixed()) {
        Some(ParsedValue::Fraction { num, denom }) => (*num, *denom),
        _ => (0, 1),
    };
    Ok(NegotiatedFormat {
        video_format,
        width,
        height,
        fps_num,
        fps_denom,
    })
}

/// Connect a stream to `node_id` and return the format the compositor agreed
/// to.
///
/// ⚠️ Runs the PipeWire loop on a **detached** thread and waits with a
/// deadline. `pw_main_loop_run` blocks, and `pw_main_loop_quit` is only safe
/// from the loop's own thread — so on a timeout the loop is left running and
/// the process is expected to exit shortly after reporting. That is acceptable
/// precisely because this is a short-lived helper; it would not be in the
/// daemon, which is one more reason the daemon does not do this.
pub fn negotiate(
    source: PwSource,
    node_id: u32,
    max_fps: u32,
    want_frames: u32,
) -> Result<(NegotiatedFormat, Option<FrameReport>), PwError> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = negotiate_blocking(source, node_id, max_fps, want_frames, None, None);
        // The receiver may already have timed out; nothing to do about that.
        let _ = tx.send(r);
    });
    rx.recv_timeout(NEGOTIATE_TIMEOUT)
        .unwrap_or_else(|_| Err(PwError::Other("format negotiation timed out".into())))
}

const NEGOTIATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[allow(clippy::type_complexity)]
fn negotiate_blocking(
    source: PwSource,
    node_id: u32,
    max_fps: u32,
    want_frames: u32,
    frame_tx: Option<std::sync::mpsc::SyncSender<(super::wire::FrameHeader, Vec<u8>)>>,
    state: Option<Arc<std::sync::atomic::AtomicI32>>,
) -> Result<(NegotiatedFormat, Option<FrameReport>), PwError> {
    let lib = Lib::load()?;
    let conn = Connection::open(lib.clone(), source)?;

    let props_str = CString::new("media.type=Video media.category=Capture media.role=Screen")
        .map_err(|e| PwError::Other(e.to_string()))?;
    let props = unsafe { (lib.syms.pw_properties_new_string)(props_str.as_ptr()) };
    let name = CString::new("roomler-portal-capture").expect("literal has no NUL");
    // ⚠️ `pw_stream_new` TAKES OWNERSHIP of `props` — it must not be freed
    // here, on success or failure.
    let stream = unsafe { (lib.syms.pw_stream_new)(conn.core, name.as_ptr(), props) };
    if stream.is_null() {
        return Err(PwError::Other("pw_stream_new returned null".into()));
    }

    // These three must outlive the stream: the library keeps the pointers.
    let mut shared = Box::new(Shared {
        lib: lib.clone(),
        main_loop: conn.main_loop,
        // Set below, once the stream exists.
        stream: None,
        want_frames,
        frames: 0,
        format: None,
        first_frame: None,
        frame_tx,
        dropped: 0,
        outcome: None,
        rejected: 0,
        state,
    });
    shared.stream = Some(stream);
    let events = Box::new(PwStreamEvents {
        version: 2,
        destroy: None,
        state_changed: Some(on_state_changed),
        control_info: None,
        io_changed: None,
        param_changed: Some(on_param_changed),
        add_buffer: None,
        remove_buffer: None,
        // Registered only when frames are wanted: with none wanted this is
        // pure negotiation and a process callback would just churn buffers.
        process: (want_frames > 0).then_some(on_process as _),
        // NOTE: when streaming, `want_frames` is u32::MAX, so the callback is
        // registered and the loop never reaches its own finish condition.
        drained: None,
        command: None,
        trigger_done: None,
    });
    let mut hook = Box::new(SpaHook([0; 6]));

    unsafe {
        (lib.syms.pw_stream_add_listener)(
            stream,
            &mut *hook as *mut SpaHook as *mut c_void,
            &*events,
            &mut *shared as *mut Shared as *mut c_void,
        );
    }

    let param = super::pod::video_enum_format(max_fps)
        .map_err(PwError::Other)?
        .to_pod();
    let params = [param.as_ptr() as *const c_void];
    let rc = unsafe {
        (lib.syms.pw_stream_connect)(
            stream,
            PW_DIRECTION_INPUT,
            node_id,
            PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
            params.as_ptr(),
            1,
        )
    };
    if rc < 0 {
        unsafe { (lib.syms.pw_stream_destroy)(stream) };
        return Err(PwError::Other(format!(
            "pw_stream_connect failed: {}",
            std::io::Error::from_raw_os_error(-rc)
        )));
    }

    // Blocks until a callback calls `pw_main_loop_quit`.
    unsafe { (lib.syms.pw_main_loop_run)(conn.main_loop) };

    let outcome = shared.outcome.take();
    unsafe { (lib.syms.pw_stream_destroy)(stream) };
    drop(conn);

    let frames = shared.first_frame.take().map(|mut fr| {
        fr.frames = shared.frames;
        fr
    });
    match outcome {
        Some(Ok(f)) => Ok((f, frames)),
        Some(Err(e)) => Err(PwError::Other(e)),
        None => Err(PwError::Other(
            "the PipeWire loop ended without negotiating a format".into(),
        )),
    }
}

/// A running capture: the agreed format, plus frames as they arrive.
pub struct StreamHandle {
    pub format: NegotiatedFormat,
    /// ⚠️ Bounded and lossy by design — see the `try_send` in `on_process`.
    /// A closed channel means the PipeWire loop stopped.
    pub frames: std::sync::mpsc::Receiver<(super::wire::FrameHeader, Vec<u8>)>,
    /// FR-93 P5c — the stream's `pw_stream_state` as its loop last reported
    /// it ([`PW_STREAM_STATE_STREAMING`] while frames can flow).
    pub state: Arc<std::sync::atomic::AtomicI32>,
    /// FR-93 P5e — the frame that settled the format, for the caller to send
    /// first. On a still desktop it can be the only one for a long while: the
    /// compositors send frames on damage.
    pub first: Option<(super::wire::FrameHeader, Vec<u8>)>,
}

/// Open a stream and keep it running, delivering frames until dropped.
///
/// ⚠️ The PipeWire loop thread is **detached and never joined**: it lives for
/// the life of the helper process, which ends when the daemon closes its pipe.
/// Acceptable for the same reason the negotiation timeout was — this is a
/// short-lived helper, not the daemon.
pub fn stream(source: PwSource, node_id: u32, max_fps: u32) -> Result<StreamHandle, PwError> {
    // Depth 2: enough that a brief hiccup in the writer costs no frame, small
    // enough that what arrives is always nearly current.
    let (frame_tx, frames) = std::sync::mpsc::sync_channel(2);
    let (err_tx, err_rx) = std::sync::mpsc::channel();
    // FR-93 P5c — the stream's state, for a caller that must tell a stream
    // whose source vanished (paused, no error) from an idle one.
    let state = Arc::new(std::sync::atomic::AtomicI32::new(0));
    let loop_state = Arc::clone(&state);

    std::thread::spawn(move || {
        // u32::MAX so the loop never satisfies its finish condition and runs
        // until the process ends.
        let r = negotiate_blocking(
            source,
            node_id,
            max_fps,
            u32::MAX,
            Some(frame_tx),
            Some(loop_state),
        );
        // Only reached once the loop has ended, which for a stream is a fault.
        let _ = err_tx.send(r.err());
    });

    // 🔑 Wait for a FRAME, not for negotiation: a format that never produces
    // pixels is the failure this whole phase exists to catch, and the header
    // carries the format anyway.
    let deadline = std::time::Instant::now() + NEGOTIATE_TIMEOUT;
    let first = loop {
        match frames.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(frame) => break frame,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(e)) = err_rx.try_recv() {
                    return Err(e);
                }
                if std::time::Instant::now() >= deadline {
                    // FR-93 P5i — which state the stream reached says whose
                    // turn it was. Measured on KDE (real hardware): after one
                    // spell every new stream stayed `paused` (KWin, the
                    // driver, never triggered a frame) until KWin restarted.
                    return Err(PwError::Other(format!(
                        "no frame arrived before the deadline (the stream was {})",
                        state_name(state.load(std::sync::atomic::Ordering::Relaxed))
                    )));
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(match err_rx.try_recv() {
                    Ok(Some(e)) => e,
                    _ => PwError::Other("the PipeWire loop ended".into()),
                });
            }
        }
    };

    // FR-93 P5e — that first frame settles the format, and is then handed to
    // the caller too. It used to be dropped, on the belief that frames would
    // keep coming. They don't: mutter and KWin send a frame when something on
    // screen changes, so on a still desktop the first one can be the only one
    // for minutes. Measured on GNOME 50: a session started on a still desktop
    // showed nothing until the viewer's mouse moved.
    let (video_format, width, height) = (first.0.video_format, first.0.width, first.0.height);
    Ok(StreamHandle {
        format: NegotiatedFormat {
            video_format,
            width,
            height,
            fps_num: 0,
            fps_denom: 1,
        },
        frames,
        state,
        first: Some(first),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with no PipeWire must get an answer that names what was looked
    /// for. "PipeWire unavailable" sends an operator hunting; a list of
    /// sonames is a next step.
    #[test]
    fn a_missing_library_names_what_was_tried() {
        let err = Lib::load_from(&["libdefinitely-not-here-xyz.so.9"]).unwrap_err();
        match &err {
            PwError::NotFound { tried, .. } => {
                assert_eq!(tried, &["libdefinitely-not-here-xyz.so.9"]);
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("libdefinitely-not-here-xyz.so.9"), "{msg}");
    }

    /// An empty candidate list must not silently look like success.
    #[test]
    fn no_candidates_is_an_error_not_a_load() {
        assert!(matches!(Lib::load_from(&[]), Err(PwError::NotFound { .. })));
    }

    /// The versioned soname has to come first: it is what packages install,
    /// while the bare `.so` is a `-devel` symlink that is usually absent on a
    /// runtime-only host. Reversing these would work on developer machines and
    /// fail across the fleet — the worst possible way round.
    #[test]
    fn the_versioned_soname_is_tried_first() {
        assert_eq!(CANDIDATES[0], "libpipewire-0.3.so.0");
        assert!(CANDIDATES.contains(&"libpipewire-0.3.so"));
    }

    /// Every failure must be reportable rather than fatal — on a host with no
    /// PipeWire, this backend being unavailable is the correct outcome.
    #[test]
    fn every_error_says_something_useful() {
        let all = [
            PwError::NotFound {
                tried: vec!["a".into()],
                last: "no such file".into(),
            },
            PwError::MissingSymbol("pw_init".into()),
            PwError::NoContext,
            PwError::ConnectFailed("EBADF".into()),
            PwError::Other("x".into()),
        ];
        for e in all {
            assert!(!e.to_string().is_empty(), "{e:?} has no message");
        }
    }

    /// FR-93 P5i — every `pw_stream_state` has its word, and a state a newer
    /// PipeWire adds is said as unknown rather than as one it is not.
    #[test]
    fn every_stream_state_has_a_word() {
        use super::state_name;
        assert_eq!(
            state_name(2),
            "paused",
            "the state a never-driven stream stays in"
        );
        assert_eq!(state_name(3), "streaming");
        for s in -1..=3 {
            assert_ne!(state_name(s), "in an unknown state", "{s}");
        }
        assert_eq!(state_name(9), "in an unknown state");
    }
}
