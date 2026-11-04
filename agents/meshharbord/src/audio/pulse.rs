// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-97 P3c-2 — the computer's sound on Linux: the default output's monitor,
//! recorded through Pulse's own client library.
//!
//! PulseAudio and PipeWire's Pulse server (`pipewire-pulse`) both resolve the
//! device name `@DEFAULT_MONITOR@` to the monitor of the default sink: what the
//! computer plays, never a microphone. cpal cannot reach it, because its one
//! Linux host is ALSA (`crate::audio_source`).
//!
//! Two ways in, picked by [`crate::audio_source::linux_route`]:
//!
//! - [`PulseCapture`] records in this process: a per-user daemon, or the
//!   recorder child, which already runs as the person at the screen.
//! - [`HelperCapture`] has the seat user's `portal-helper --audio` record and
//!   write raw PCM on its stdout ([`serve_helper`]): a root daemon reaches no
//!   session's sound server itself, since PulseAudio admits a client by uid or
//!   cookie.
//!
//! ## Why `dlopen`
//! `libpulse-simple.so.0` is on nearly every Linux desktop: PulseAudio and
//! PipeWire installs both ship libpulse for their clients. Most servers lack
//! it. A link would stop the agent from STARTING on such a host; `dlopen`
//! makes that host say why it has no session audio, and nothing else changes.
//! The libpipewire pattern (`capture::portal::pipewire`).
//!
//! ## Threads
//! `pa_simple` blocks and is not thread-safe. So ONE plain thread owns it from
//! `pa_simple_new` to `pa_simple_free` and hands 10 ms frames to the async pump
//! over a bounded channel, the cpal backend's shape.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::{AudioCapture, AudioFrame};
use crate::audio_source::{AudioUnavailable, AudioUnavailableCode};

/// The device every Pulse server resolves to the default sink's monitor.
pub const DEFAULT_MONITOR: &str = "@DEFAULT_MONITOR@";
/// The Opus encoder's own format, so nothing is resampled on the way.
pub const RATE: u32 = 48_000;
pub const CHANNELS: u16 = 2;
/// One read: 10 ms of 48 kHz stereo s16 (480 frames × 2 channels × 2 bytes).
pub const CHUNK_BYTES: usize = 1920;
/// The cpal backend's depth: ~640 ms of slack, bounded.
const CHANNEL_DEPTH: usize = 64;
/// How long an open may take. A dead server refuses at once; this covers a
/// wedged one, and a helper that never starts.
const OPEN_TIMEOUT: Duration = Duration::from_secs(8);

/// The helper's first stdout line before PCM, or its one line of refusal.
const STREAM_MARKER: &str = "ROOMLER_AUDIO_STREAM:";
const FAILED_MARKER: &str = "ROOMLER_AUDIO_FAILED:";

const CANDIDATES: &[&str] = &["libpulse-simple.so.0", "libpulse-simple.so"];

// `pa_stream_direction_t::PA_STREAM_RECORD`.
const PA_STREAM_RECORD: c_int = 2;
// `pa_sample_format_t::PA_SAMPLE_S16LE`.
const PA_SAMPLE_S16LE: c_int = 3;

/// `pa_sample_spec`, from `<pulse/sample.h>`.
#[repr(C)]
struct PaSampleSpec {
    format: c_int,
    rate: u32,
    channels: u8,
}

/// `pa_buffer_attr`, from `<pulse/def.h>`. `u32::MAX` is "the server's default".
#[repr(C)]
struct PaBufferAttr {
    maxlength: u32,
    tlength: u32,
    prebuf: u32,
    minreq: u32,
    fragsize: u32,
}

type NewFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *const c_char,
    *const PaSampleSpec,
    *const c_void,
    *const PaBufferAttr,
    *mut c_int,
) -> *mut c_void;
type ReadFn = unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *mut c_int) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type StrerrorFn = unsafe extern "C" fn(c_int) -> *const c_char;

/// The four entry points, resolved once and never unloaded.
struct Lib {
    new: NewFn,
    read: ReadFn,
    free: FreeFn,
    strerror: StrerrorFn,
}

/// The library, loaded on first use. The error is the reason the host gives.
fn lib() -> Result<&'static Lib, String> {
    static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
    LIB.get_or_init(load).as_ref().map_err(Clone::clone)
}

/// Whether the loader finds and loads `libpulse-simple.so.0`, wherever it is.
pub fn loadable() -> bool {
    lib().is_ok()
}

/// Whether `libpulse-simple.so.0` is on disk where the loader looks, without
/// loading it. The hello's question: a root daemon never loads the library
/// itself (its helper does), and libpulse pulls a dozen more into whatever
/// loads it. A library somewhere unusual reads as absent: an honest "no".
pub fn present() -> bool {
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("LD_LIBRARY_PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    dirs.extend(
        [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/usr/lib64",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/lib/aarch64-linux-gnu",
            "/lib64",
            "/lib",
        ]
        .map(std::path::PathBuf::from),
    );
    dirs.iter().any(|d| d.join(CANDIDATES[0]).exists())
}

fn load() -> Result<Lib, String> {
    let mut last = String::from("no candidates given");
    for name in CANDIDATES {
        let cname = CString::new(*name).expect("a library name has no NUL");
        // RTLD_NOW so a missing symbol surfaces here rather than at the first
        // call; RTLD_LOCAL so libpulse's symbols leak into nothing else.
        // SAFETY: dlopen takes a NUL-terminated name; the handle is kept for
        // the life of the process (never dlclose'd), so the pointers below
        // stay valid.
        let handle = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            last = dlerror_string().unwrap_or_else(|| format!("{name}: dlopen failed"));
            continue;
        }
        // SAFETY: each symbol is transmuted to the signature `<pulse/simple.h>`
        // and `<pulse/error.h>` declare for it. `pa_strerror` is libpulse's, which
        // libpulse-simple depends on, so dlsym finds it through this handle.
        unsafe {
            return Ok(Lib {
                new: std::mem::transmute::<*mut c_void, NewFn>(sym(handle, "pa_simple_new")?),
                read: std::mem::transmute::<*mut c_void, ReadFn>(sym(handle, "pa_simple_read")?),
                free: std::mem::transmute::<*mut c_void, FreeFn>(sym(handle, "pa_simple_free")?),
                strerror: std::mem::transmute::<*mut c_void, StrerrorFn>(sym(
                    handle,
                    "pa_strerror",
                )?),
            });
        }
    }
    Err(last)
}

/// # Safety
/// `handle` must be a live `dlopen` handle.
unsafe fn sym(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    let c = CString::new(name).expect("a symbol name has no NUL");
    // SAFETY: the caller guarantees the handle; `c` is NUL-terminated.
    let p = unsafe { libc::dlsym(handle, c.as_ptr()) };
    if p.is_null() {
        Err(format!("libpulse-simple has no {name}"))
    } else {
        Ok(p)
    }
}

fn dlerror_string() -> Option<String> {
    // SAFETY: dlerror returns NULL or a NUL-terminated string valid until the
    // next dl* call on this thread; it is copied at once.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        None
    } else {
        // SAFETY: non-null and NUL-terminated, per dlerror's contract.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

fn strerror(lib: &Lib, code: c_int) -> String {
    // SAFETY: pa_strerror returns a static string (or NULL for an unknown code).
    let p = unsafe { (lib.strerror)(code) };
    if p.is_null() {
        format!("Pulse error {code}")
    } else {
        // SAFETY: non-null, NUL-terminated, static.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Which reason a `pa_simple_new` error is. The detail always carries
/// libpulse's own words, so a code this misreads still says what happened.
fn classify(code: c_int) -> AudioUnavailableCode {
    match code {
        // PA_ERR_NOENTITY: no such device (no default sink, so no monitor).
        5 => AudioUnavailableCode::NoMonitor,
        // ACCESS, CONNECTIONREFUSED, TIMEOUT, AUTHKEY, CONNECTIONTERMINATED,
        // INVALIDSERVER: there is no sound server this process may talk to.
        1 | 6 | 8 | 9 | 11 | 13 => AudioUnavailableCode::NoSoundServer,
        _ => AudioUnavailableCode::BackendError,
    }
}

/// Little-endian s16 bytes to samples. A trailing odd byte is dropped (never
/// produced: every read is [`CHUNK_BYTES`]).
pub fn s16le_to_i16(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// An open `pa_simple` record stream. Owned by one thread; freed on drop.
struct Stream {
    lib: &'static Lib,
    s: *mut c_void,
}

impl Stream {
    /// Connect to the server this process reaches (`PULSE_SERVER`, else
    /// `$XDG_RUNTIME_DIR/pulse/native`) and record `device`.
    fn open(device: &str) -> Result<Self, AudioUnavailable> {
        let lib = lib().map_err(|why| {
            AudioUnavailable::new(
                AudioUnavailableCode::NoSoundServer,
                format!("no Pulse client library: {why}"),
            )
        })?;
        let name = CString::new("roomlerd").expect("no NUL");
        let stream_name = CString::new("remote session audio").expect("no NUL");
        let dev = CString::new(device).map_err(|_| {
            AudioUnavailable::new(
                AudioUnavailableCode::BackendError,
                "a device name with a NUL",
            )
        })?;
        let spec = PaSampleSpec {
            format: PA_SAMPLE_S16LE,
            rate: RATE,
            channels: CHANNELS as u8,
        };
        let attr = PaBufferAttr {
            maxlength: u32::MAX,
            tlength: u32::MAX,
            prebuf: u32::MAX,
            minreq: u32::MAX,
            // The capture latency: one read's worth.
            fragsize: CHUNK_BYTES as u32,
        };
        let mut err: c_int = 0;
        // SAFETY: every pointer is valid for the call (the CStrings and
        // structs outlive it); a NULL server means the default; a NULL
        // channel map means the default for two channels.
        let s = unsafe {
            (lib.new)(
                std::ptr::null(),
                name.as_ptr(),
                PA_STREAM_RECORD,
                dev.as_ptr(),
                stream_name.as_ptr(),
                &spec,
                std::ptr::null(),
                &attr,
                &mut err,
            )
        };
        if s.is_null() {
            return Err(AudioUnavailable::new(
                classify(err),
                format!("the sound server refused {device}: {}", strerror(lib, err)),
            ));
        }
        Ok(Self { lib, s })
    }

    /// One blocking read of exactly `buf.len()` bytes.
    fn read(&mut self, buf: &mut [u8]) -> Result<(), String> {
        let mut err: c_int = 0;
        // SAFETY: `s` is live until drop; `buf` is valid for `len` bytes.
        let rc = unsafe { (self.lib.read)(self.s, buf.as_mut_ptr().cast(), buf.len(), &mut err) };
        if rc < 0 {
            Err(format!("pa_simple_read: {}", strerror(self.lib, err)))
        } else {
            Ok(())
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: `s` came from pa_simple_new and is freed exactly once.
        unsafe { (self.lib.free)(self.s) };
    }
}

/// The frames a reader thread hands over, and the reason it stopped.
struct Bridge {
    rx: mpsc::Receiver<AudioFrame>,
    stop: Arc<AtomicBool>,
    stopped_because: Arc<Mutex<Option<String>>>,
}

impl Bridge {
    async fn next(&mut self) -> anyhow::Result<Option<AudioFrame>> {
        match self.rx.recv().await {
            Some(f) => Ok(Some(f)),
            // The reader ended. A reason makes it a failure the pump reports
            // (`rc:audio-unavailable`); none means it was asked to stop.
            None => match self
                .stopped_because
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                Some(why) => Err(anyhow::anyhow!(why)),
                None => Ok(None),
            },
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Hand `chunk` to the pump: never blocks, and a full channel drops it (the
/// encoder is behind; latency stays bounded). `false` once the pump is gone.
fn hand_over(tx: &mpsc::Sender<AudioFrame>, chunk: &[u8]) -> bool {
    use mpsc::error::TrySendError;
    let frame = AudioFrame {
        samples: s16le_to_i16(chunk),
        channels: CHANNELS,
        sample_rate: RATE,
    };
    !matches!(tx.try_send(frame), Err(TrySendError::Closed(_)))
}

/// The default output's monitor, recorded in this process.
pub struct PulseCapture {
    bridge: Bridge,
}

impl PulseCapture {
    /// Record [`DEFAULT_MONITOR`] (or `device`) and start the reader thread.
    /// Returns once the server accepted the stream, or with its reason.
    pub fn open(device: &str) -> Result<Self, AudioUnavailable> {
        let (tx, rx) = mpsc::channel::<AudioFrame>(CHANNEL_DEPTH);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), AudioUnavailable>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped_because = Arc::new(Mutex::new(None));
        let (stop_t, why_t) = (stop.clone(), stopped_because.clone());
        let device = device.to_owned();
        std::thread::Builder::new()
            .name("audio-pulse".into())
            .spawn(move || {
                let mut stream = match Stream::open(&device) {
                    Ok(s) => s,
                    Err(reason) => {
                        let _ = ready_tx.send(Err(reason));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                let mut buf = vec![0u8; CHUNK_BYTES];
                while !stop_t.load(Ordering::Relaxed) {
                    if let Err(why) = stream.read(&mut buf) {
                        *why_t.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
                        break;
                    }
                    if !hand_over(&tx, &buf) {
                        break;
                    }
                }
            })
            .map_err(|e| {
                AudioUnavailable::new(
                    AudioUnavailableCode::BackendError,
                    format!("starting the Pulse reader: {e}"),
                )
            })?;
        match ready_rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(())) => {
                tracing::info!(
                    device = DEFAULT_MONITOR,
                    "audio: recording the sound server's monitor"
                );
                Ok(Self {
                    bridge: Bridge {
                        rx,
                        stop,
                        stopped_because,
                    },
                })
            }
            Ok(Err(reason)) => Err(reason),
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                Err(AudioUnavailable::new(
                    AudioUnavailableCode::NoSoundServer,
                    "the sound server did not answer within 8 s",
                ))
            }
        }
    }
}

#[async_trait]
impl AudioCapture for PulseCapture {
    async fn next_frame(&mut self) -> anyhow::Result<Option<AudioFrame>> {
        self.bridge.next().await
    }
}

// ── The seat user's half: `roomlerd portal-helper --audio` ─────────────────

/// The helper's whole job, run AS the person at the screen: record the
/// session's monitor and write raw 48 kHz stereo s16le on stdout until the
/// daemon closes the pipe. One marked line comes first: the stream, or the
/// reason there is none. Everything diagnostic goes to stderr.
pub fn serve_helper() {
    let mut out = std::io::stdout().lock();
    let mut stream = match Stream::open(DEFAULT_MONITOR) {
        Ok(s) => s,
        Err(reason) => {
            let line = serde_json::json!({ "code": reason.code.wire(), "detail": reason.detail });
            let _ = writeln!(out, "{FAILED_MARKER}{line}");
            let _ = out.flush();
            return;
        }
    };
    let started = serde_json::json!({ "rate": RATE, "channels": CHANNELS });
    if writeln!(out, "{STREAM_MARKER}{started}")
        .and_then(|_| out.flush())
        .is_err()
    {
        return;
    }
    eprintln!("portal-helper: recording {DEFAULT_MONITOR}");
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        if let Err(why) = stream.read(&mut buf) {
            eprintln!("portal-helper: {why}");
            return;
        }
        // A closed pipe is the daemon saying stop.
        if out.write_all(&buf).and_then(|_| out.flush()).is_err() {
            return;
        }
    }
}

/// The helper's first line, read by the daemon: the stream started, or the
/// helper's own reason. Anything else before it is skipped (a library's
/// stray output); the helper's diagnostics go to stderr.
pub fn read_helper_handshake(r: &mut impl BufRead) -> Result<(), AudioUnavailable> {
    let mut line = String::new();
    for _ in 0..16 {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let l = line.trim();
        if l.starts_with(STREAM_MARKER) {
            return Ok(());
        }
        if let Some(json) = l.strip_prefix(FAILED_MARKER) {
            let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
            let detail = v["detail"].as_str().unwrap_or(json).to_owned();
            let code = match v["code"].as_str() {
                Some("no_monitor") => AudioUnavailableCode::NoMonitor,
                Some("no_sound_server") => AudioUnavailableCode::NoSoundServer,
                _ => AudioUnavailableCode::BackendError,
            };
            return Err(AudioUnavailable::new(code, detail));
        }
    }
    Err(AudioUnavailable::new(
        AudioUnavailableCode::BackendError,
        "the session helper exited without starting a stream",
    ))
}

/// The default output's monitor, recorded by the seat user's helper: the root
/// daemon's way in.
#[cfg(feature = "portal-capture")]
pub struct HelperCapture {
    bridge: Bridge,
    child: Option<std::process::Child>,
}

#[cfg(feature = "portal-capture")]
impl HelperCapture {
    /// Start `portal-helper --audio` as the person at the screen, wait for
    /// its handshake, and read its PCM on a thread.
    pub fn spawn() -> Result<Self, AudioUnavailable> {
        use crate::capture::portal::helper::{SpawnError, spawn_child};
        // Here, not at the top: only this path reads a byte stream, and a
        // build without the helper must not carry an unused import.
        use std::io::Read;
        let mut child = spawn_child(&["--audio"], false).map_err(|e| match e {
            SpawnError::NoSession => AudioUnavailable::new(
                AudioUnavailableCode::NoSession,
                "nobody is signed in at this machine's screen",
            ),
            SpawnError::Other(why) => {
                AudioUnavailable::new(AudioUnavailableCode::BackendError, why)
            }
        })?;
        let Some(stdout) = child.stdout.take() else {
            reap(child);
            return Err(AudioUnavailable::new(
                AudioUnavailableCode::BackendError,
                "the session helper has no stdout",
            ));
        };
        let (tx, rx) = mpsc::channel::<AudioFrame>(CHANNEL_DEPTH);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), AudioUnavailable>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped_because = Arc::new(Mutex::new(None));
        let (stop_t, why_t) = (stop.clone(), stopped_because.clone());
        let started = std::thread::Builder::new()
            .name("audio-helper".into())
            .spawn(move || {
                let mut r = std::io::BufReader::new(stdout);
                if let Err(reason) = read_helper_handshake(&mut r) {
                    let _ = ready_tx.send(Err(reason));
                    return;
                }
                let _ = ready_tx.send(Ok(()));
                let mut buf = vec![0u8; CHUNK_BYTES];
                while !stop_t.load(Ordering::Relaxed) {
                    if let Err(e) = r.read_exact(&mut buf) {
                        *why_t.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(format!("the session helper stopped: {e}"));
                        break;
                    }
                    if !hand_over(&tx, &buf) {
                        break;
                    }
                }
                // Dropping the reader closes the pipe: the helper's next write
                // fails and it exits.
            });
        if let Err(e) = started {
            reap(child);
            return Err(AudioUnavailable::new(
                AudioUnavailableCode::BackendError,
                format!("starting the helper reader: {e}"),
            ));
        }
        match ready_rx.recv_timeout(OPEN_TIMEOUT) {
            Ok(Ok(())) => {
                tracing::info!("audio: the session helper records the sound server's monitor");
                Ok(Self {
                    bridge: Bridge {
                        rx,
                        stop,
                        stopped_because,
                    },
                    child: Some(child),
                })
            }
            Ok(Err(reason)) => {
                reap(child);
                Err(reason)
            }
            Err(_) => {
                stop.store(true, Ordering::Relaxed);
                reap(child);
                Err(AudioUnavailable::new(
                    AudioUnavailableCode::NoSoundServer,
                    "the session helper did not start a stream within 8 s",
                ))
            }
        }
    }
}

#[cfg(feature = "portal-capture")]
impl Drop for HelperCapture {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap(child);
        }
    }
}

#[cfg(feature = "portal-capture")]
#[async_trait]
impl AudioCapture for HelperCapture {
    async fn next_frame(&mut self) -> anyhow::Result<Option<AudioFrame>> {
        self.bridge.next().await
    }
}

/// Stop the helper and collect its exit, off the caller's thread: a drop runs
/// inside the async pump, which must not block on `wait`.
#[cfg(feature = "portal-capture")]
fn reap(mut child: std::process::Child) {
    let _ = child.kill();
    let _ = std::thread::Builder::new()
        .name("audio-helper-reap".into())
        .spawn(move || {
            let _ = child.wait();
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_little_endian_pairs() {
        assert_eq!(
            s16le_to_i16(&[0x01, 0x00, 0xff, 0x7f, 0x00, 0x80]),
            vec![1, i16::MAX, i16::MIN]
        );
        // A chunk is 10 ms of stereo at 48 kHz.
        assert_eq!(s16le_to_i16(&[0u8; CHUNK_BYTES]).len(), 960);
    }

    #[test]
    fn the_handshake_starts_a_stream_or_carries_the_helpers_reason() {
        let mut ok = std::io::Cursor::new(format!("noise\n{STREAM_MARKER}{{\"rate\":48000}}\n"));
        assert_eq!(read_helper_handshake(&mut ok), Ok(()));
        let mut refused = std::io::Cursor::new(format!(
            "{FAILED_MARKER}{{\"code\":\"no_sound_server\",\"detail\":\"Connection refused\"}}\n"
        ));
        let why = read_helper_handshake(&mut refused).unwrap_err();
        assert_eq!(why.code, AudioUnavailableCode::NoSoundServer);
        assert_eq!(why.detail, "Connection refused");
        let mut silent = std::io::Cursor::new(String::new());
        assert_eq!(
            read_helper_handshake(&mut silent).unwrap_err().code,
            AudioUnavailableCode::BackendError
        );
    }

    #[test]
    fn a_server_that_is_not_there_is_named_as_such() {
        assert_eq!(classify(6), AudioUnavailableCode::NoSoundServer);
        assert_eq!(classify(5), AudioUnavailableCode::NoMonitor);
        assert_eq!(classify(25), AudioUnavailableCode::BackendError);
    }
}
