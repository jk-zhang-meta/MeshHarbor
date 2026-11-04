// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P2b — open a ScreenCast session through the desktop portal.
//! FR-45 P4 — or a **RemoteDesktop** session, which is a ScreenCast session
//! that can also inject input.
//!
//! [P2a](super::helper) established that the daemon can *reach* the portal, by
//! running a helper inside the console user's session. This is what that helper
//! goes on to do: the four-step handshake, ending with a PipeWire node id and a
//! connection fd.
//!
//! ## The Request/Response pattern, and the one way to get it wrong
//!
//! Portal methods do not return their result. They return the object path of a
//! `Request`, and the answer arrives later as a `Response` **signal** on that
//! path — because a portal call can take as long as a human takes to read a
//! dialog.
//!
//! ⚠️ The subscription must be armed **before** the method is called. The
//! request path is derivable in advance (that is why `handle_token` exists),
//! and arming afterwards is a race the portal wins whenever it answers without
//! asking anyone — exactly the restore-token case this phase depends on.
//!
//! ## How input changes the handshake (P4) — and how it deliberately doesn't
//!
//! A RemoteDesktop session is not a second session next to the capture one: it
//! is the SAME session, created and started through the RemoteDesktop
//! interface instead, with `SelectDevices` slotted in before the unchanged
//! `SelectSources`. One session means one consent dialog covering both "see"
//! and "touch", one restore token, and one PipeWire stream — the shape
//! gnome-remote-desktop uses. `Start` and `CreateSession` move to the
//! interface that owns the session; `SelectSources` and `OpenPipeWireRemote`
//! stay on ScreenCast, addressed at the shared session path.
//!
//! ⚠️ Persistence moves with ownership: an input session persists through
//! `SelectDevices.persist_mode` (RemoteDesktop v2+), NOT through
//! `SelectSources` — the portal ignores ScreenCast persistence options on a
//! remote desktop session. And the two grants are stored apart
//! ([`TokenStore`]): a capture-only token cannot restore an input session,
//! and quietly widening a stored "see" grant into "see and touch" without a
//! dialog is exactly what must not happen.
//!
//! ## 🔑 The PipeWire fd stays HERE
//!
//! The FR-45 plan originally had this phase pass the fd back to the daemon
//! over `SCM_RIGHTS`, inherited from FR-36's design, while also saying P3 would
//! consume PipeWire *inside the helper*. Those cannot both be true, so the
//! question got decided here rather than left to P3:
//!
//! **The helper consumes PipeWire; the fd never crosses to the daemon.**
//!
//! 1. *Fault isolation.* This project already paid for putting third-party
//!    driver code in the daemon's address space: a vendor probe that faulted
//!    took `roomlerd` down and the service manager restarted it straight back
//!    into the same fault — a crash-loop, not a degraded agent (`encode::caps`
//!    is a child process for that reason). `libpipewire` loads SPA plugins and
//!    sits on the same vendor GPU stacks. A fault there should cost capture,
//!    not the daemon.
//!  2. *It is not the slower choice.* PipeWire negotiates a small **pool** of
//!    buffers (dmabuf or memfd). Those fds cross once, at negotiation; per
//!    frame only "buffer N is ready" flows. Frames crossing a process boundary
//!    does not mean pixels being copied.
//! 3. *The helper already runs as the session's user*, whose PipeWire this is.
//!
//! So `SCM_RIGHTS` still appears in FR-45, but in P3 and carrying **buffer**
//! fds — not here carrying the connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use zbus::zvariant::{OwnedValue, Value};

use super::{PORTAL_BUS, PORTAL_PATH, REMOTE_DESKTOP_IFACE, SCREENCAST_IFACE};

const REQUEST_IFACE: &str = "org.freedesktop.portal.Request";
/// FR-93 P6c — the session object, whose `Closed` says the portal ended it.
const SESSION_IFACE: &str = "org.freedesktop.portal.Session";

/// `SelectSources.types` — monitors only.
///
/// ⚠️ Deliberately NOT `VIRTUAL` (4). A virtual source asks the compositor to
/// *create a new monitor*, which changes the desktop the operator is looking
/// at. That may become a real option for headless hosts, but it must be an
/// explicit choice, never a default that silently rearranges someone's screen.
const SOURCE_MONITOR: u32 = 1;

/// `SelectSources.types` — a single application window (FR-56 P4).
///
/// ⚠️ There is no way to say WHICH window: the portal shows the user its own
/// picker and hands back whatever they choose. That is not a limitation we can
/// engineer around — `org.gnome.Shell.Introspect`, the only API that could name
/// a window, answers `GetWindows is not allowed` on GNOME (measured, Shell
/// 48.8), so mutter's `RecordWindow` has no id to take either.
const SOURCE_WINDOW: u32 = 2;

/// `SelectSources.cursor_mode` values.
const CURSOR_HIDDEN: u32 = 1;
const CURSOR_EMBEDDED: u32 = 2;

/// `SelectDevices.types` — the RemoteDesktop device kinds we ask for. No
/// touchscreen (4): nothing on the wire maps to it yet (`InputMsg::Touch` is
/// dropped by every backend), and asking for a grant nothing uses widens the
/// consent dialog for no capability.
const DEVICE_KEYBOARD: u32 = 1;
const DEVICE_POINTER: u32 = 2;

/// `persist_mode` — persist until the user revokes it.
///
/// This is what makes the phase testable without a human in the loop twice:
/// the first `Start` prompts and hands back a `restore_token`; a later start
/// carrying that token is answered without a dialog.
const PERSIST_UNTIL_REVOKED: u32 = 2;

/// Portal response codes.
const RESPONSE_OK: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;

/// What the session records: a whole monitor, or one application window.
///
/// FR-56 P4 — the RAIL-shaped half of Remote Apps. WSLg has been doing this on
/// the same machines all along (`rdprail-shell`), one Linux window per Windows
/// window; here it means the viewer sees ONE app instead of the desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Monitor,
    /// ⚠️ Attended by construction: the portal shows a WINDOW PICKER and the
    /// person at the screen chooses. Nothing on this side selects the window,
    /// and on an unattended host nobody answers the picker — which is why the
    /// switch defaults off.
    Window,
}

impl SourceKind {
    fn types_mask(self) -> u32 {
        match self {
            SourceKind::Monitor => SOURCE_MONITOR,
            SourceKind::Window => SOURCE_WINDOW,
        }
    }
}

/// What kind of session to open. It changes which portal interface OWNS the
/// session — and therefore what the consent dialog asks for and which token
/// store the grant lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// ScreenCast only: pixels, no input. Detection, `capture-smoke`, and the
    /// kill-switch (`ROOMLERD_PORTAL_INPUT=0`) path.
    CaptureOnly,
    /// RemoteDesktop: the same pixels, plus keyboard+pointer injection.
    WithInput,
}

/// One screencast stream the portal handed us.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamInfo {
    /// The PipeWire node to attach to. The whole point of the handshake.
    pub node_id: u32,
    /// Advertised size, when the portal gives one. `None` is not an error —
    /// the authoritative PIXEL size comes from PipeWire's format negotiation
    /// in P3. ⚠️ For input this pair is not a fallback but the primary: it is
    /// the stream's LOGICAL size, the coordinate space
    /// `NotifyPointerMotionAbsolute` expects, and under a HiDPI scale factor
    /// it differs from the pixel size.
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub source_type: Option<u32>,
}

/// What the helper reports back about a session it opened.
///
/// Serialisable because it crosses the helper→daemon process boundary. The fd
/// deliberately is not in here; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionReport {
    pub streams: Vec<StreamInfo>,
    /// Whether a grant was persisted for next time — **not the token itself**.
    ///
    /// ⚠️ The token deliberately does not travel in this struct. It is a
    /// standing grant to screencast someone's desktop without asking again,
    /// the child both stores and reloads it, and the daemon has no use for it.
    /// Carrying it here would have put a credential on a pipe and into every
    /// future `Debug` of this type for no purpose — the first version of this
    /// struct did exactly that while its own docs claimed the daemon never
    /// sees it. `false` means the portal declined to persist the grant, which
    /// is its right, and costs one dialog next time.
    pub restore_token_stored: bool,
    /// Whether `OpenPipeWireRemote` actually yielded a usable fd. Reported
    /// rather than assumed: everything up to it can succeed and still leave
    /// nothing to connect to.
    pub pipewire_fd_ok: bool,
    /// Whether we SENT a restore token. Paired with `elapsed_ms` this is what
    /// makes "did it prompt?" answerable: a restored session returns in
    /// milliseconds, a prompted one takes as long as a human takes.
    pub restore_token_sent: bool,
    /// P4 — whether the portal granted input devices on this session. Always
    /// `false` for [`SessionKind::CaptureOnly`]; for `WithInput` it reports
    /// what `Start` actually returned, because a compositor may grant the
    /// pixels and not the devices. `serde(default)` so a report from an older
    /// helper reads as "no input", never as a parse failure.
    #[serde(default)]
    pub input_granted: bool,
    pub elapsed_ms: u64,
    /// What the portal says it can do, for the log. Cheap, and the difference
    /// between "we chose hidden" and "hidden was all it had".
    pub cursor_mode_used: u32,
    pub available_cursor_modes: Option<u32>,
    pub available_source_types: Option<u32>,
    /// P3a — what came of handing the fd to PipeWire. Filled in after the
    /// handshake by whoever chose to try, so a caller that only wants the
    /// session still gets an honest `NotAttempted` rather than a false
    /// negative.
    pub pipewire: super::pipewire::PipeWireStatus,
}

impl SessionReport {
    /// FR-85 P1d — whether the compositor draws the pointer into the stream:
    /// what a recording made from it says about its pointer.
    pub fn cursor_embedded(&self) -> bool {
        self.cursor_mode_used == CURSOR_EMBEDDED
    }
}

/// Why a session could not be opened. Separated from a bare string because
/// **cancelled is not a failure** — it is a person saying no, and the caller
/// must not retry it as though it were a transient fault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OpenError {
    /// The human declined, or the dialog was dismissed.
    Cancelled,
    /// The portal ended the request for its own reasons.
    Ended,
    /// Anything else, with the detail.
    Failed(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Cancelled => write!(f, "the person at the screen declined the request"),
            // FR-93 P2d-4 — these words now reach the viewer, inside FR-80's
            // 200-character cap. Measured on the FR-93 lab's KDE guest with its
            // portal backend stopped: the frontend still offered ScreenCast,
            // and ended every request at once, with no dialog. Both are user
            // services (`systemctl --user restart …`).
            OpenError::Ended => write!(
                f,
                "the portal ended the request on its own: its backend \
                 (xdg-desktop-portal-kde, -gnome) may be stopped; restart it, then \
                 xdg-desktop-portal"
            ),
            OpenError::Failed(why) => write!(f, "{why}"),
        }
    }
}

impl OpenError {
    fn failed(why: impl std::fmt::Display) -> Self {
        OpenError::Failed(why.to_string())
    }
}

/// Run the handshake.
///
/// Blocking, and it can block for as long as a human takes to answer a dialog
/// — the caller bounds it, not this function.
///
/// ⚠️ **Runs on its own thread, and that is not optional.** `zbus`'s blocking
/// API panics when called from inside a tokio runtime, and `portal-helper` is
/// dispatched from `#[tokio::main]`. [`super::detect`] already carried this
/// guard and this function was written without it, which cost a field run:
/// *"Cannot start a runtime from within a runtime"*, before any portal call
/// was made. The guard belongs HERE rather than at each call site, so the next
/// entry point cannot reintroduce it.
pub fn open(kind: SessionKind, source: SourceKind) -> Result<Session, OpenError> {
    std::thread::spawn(move || open_blocking(kind, source))
        .join()
        .unwrap_or_else(|_| Err(OpenError::failed("the portal handshake thread panicked")))
}

fn open_blocking(kind: SessionKind, source: SourceKind) -> Result<Session, OpenError> {
    let started = Instant::now();
    // 🔑 The token is loaded and stored HERE, so it never leaves this module.
    // A caller that cannot hold the credential cannot leak it — which is a
    // stronger guarantee than a caller that holds it and is careful.
    let store = TokenStore::for_current_user(kind, source);
    let restore_token = store.load();
    let restore_token = restore_token.as_deref();
    let restore_token_sent = restore_token.is_some();
    let conn = zbus::blocking::Connection::session()
        .map_err(|e| OpenError::failed(format!("session bus: {e}")))?;
    let screencast = zbus::blocking::Proxy::new(&conn, PORTAL_BUS, PORTAL_PATH, SCREENCAST_IFACE)
        .map_err(|e| OpenError::failed(format!("portal proxy: {e}")))?;

    // The proxy that OWNS the session: CreateSession and Start go through it.
    // For an input session that is RemoteDesktop; SelectSources and
    // OpenPipeWireRemote stay on ScreenCast either way, addressed at the
    // shared session path.
    let remote_desktop;
    let owner = match kind {
        SessionKind::CaptureOnly => &screencast,
        SessionKind::WithInput => {
            remote_desktop =
                zbus::blocking::Proxy::new(&conn, PORTAL_BUS, PORTAL_PATH, REMOTE_DESKTOP_IFACE)
                    .map_err(|e| OpenError::failed(format!("remote-desktop proxy: {e}")))?;
            &remote_desktop
        }
    };

    let available_cursor_modes = screencast.get_property::<u32>("AvailableCursorModes").ok();
    let available_source_types = screencast.get_property::<u32>("AvailableSourceTypes").ok();

    // Ask for an embedded cursor when the portal offers one — matching what
    // the DRM backend produces — and fall back rather than failing, since a
    // stream with no pointer still beats no stream.
    let cursor_mode = match available_cursor_modes {
        Some(m) if m & CURSOR_EMBEDDED != 0 => CURSOR_EMBEDDED,
        _ => CURSOR_HIDDEN,
    };

    // ── 1. CreateSession — on the owning interface ──────────────────────
    let (req_token, sess_token) = (next_token("cs"), next_token("ss"));
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(req_token.as_str()));
    opts.insert("session_handle_token", Value::from(sess_token.as_str()));
    let results = call_with_response(&conn, owner, "CreateSession", &(opts,), &req_token)?;
    let session_handle = results
        .get("session_handle")
        .and_then(string_of)
        .ok_or_else(|| OpenError::failed("CreateSession returned no session_handle"))?;
    // ⚠️ `session_handle` is an object path on the wire, not a string. Sending
    // it as `s` is accepted by serde and rejected by the portal with a
    // signature mismatch that names neither the argument nor the call.
    let sess_path = object_path(&session_handle)?;

    // ── 1b. SelectDevices — input sessions only ─────────────────────────
    //
    // Persistence rides HERE for an input session (RemoteDesktop v2+), not on
    // SelectSources: one session, one grant, one token — covering both the
    // pixels and the devices. On v1 there is nothing to persist through, so
    // the session works but prompts every time, and saying so beats silence.
    if kind == SessionKind::WithInput {
        let rd_version = owner.get_property::<u32>("version").ok();
        let persistable = rd_version.is_some_and(|v| v >= 2);
        if !persistable {
            tracing::warn!(
                ?rd_version,
                "portal: RemoteDesktop cannot persist grants — every session will prompt"
            );
        }
        let req_token = next_token("dev");
        let mut opts: HashMap<&str, Value> = HashMap::new();
        opts.insert("handle_token", Value::from(req_token.as_str()));
        opts.insert("types", Value::from(DEVICE_KEYBOARD | DEVICE_POINTER));
        if persistable {
            opts.insert("persist_mode", Value::from(PERSIST_UNTIL_REVOKED));
            if let Some(tok) = restore_token {
                opts.insert("restore_token", Value::from(tok));
            }
        }
        call_with_response(
            &conn,
            owner,
            "SelectDevices",
            &(&sess_path, opts),
            &req_token,
        )?;
    }

    // ── 2. SelectSources — always on ScreenCast ─────────────────────────
    let req_token = next_token("sel");
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(req_token.as_str()));
    opts.insert("types", Value::from(source.types_mask()));
    opts.insert("multiple", Value::from(false));
    opts.insert("cursor_mode", Value::from(cursor_mode));
    if kind == SessionKind::CaptureOnly {
        opts.insert("persist_mode", Value::from(PERSIST_UNTIL_REVOKED));
        if let Some(tok) = restore_token {
            opts.insert("restore_token", Value::from(tok));
        }
    }
    call_with_response(
        &conn,
        &screencast,
        "SelectSources",
        &(&sess_path, opts),
        &req_token,
    )?;

    // ── 3. Start — on the owner; this is the step that can show a dialog ─
    let req_token = next_token("start");
    let mut opts: HashMap<&str, Value> = HashMap::new();
    opts.insert("handle_token", Value::from(req_token.as_str()));
    let results = call_with_response(&conn, owner, "Start", &(&sess_path, "", opts), &req_token)?;

    let streams = results
        .get("streams")
        .map(parse_streams)
        .transpose()?
        .unwrap_or_default();
    if streams.is_empty() {
        return Err(OpenError::failed(
            "the portal granted the request but returned no streams",
        ));
    }
    // What the compositor actually granted — asked-for is not given. A
    // capture-only session honestly reports no input rather than absent-means
    // -whatever.
    let devices_granted = match kind {
        SessionKind::CaptureOnly => 0,
        SessionKind::WithInput => results.get("devices").and_then(u32_of).unwrap_or(0),
    };
    // ⚠️ BOTH devices required, not "any" (`== mask`, not `& mask != 0`). The
    // downstream route has no per-device split — `try_route` claims EVERY input
    // event — so a partial grant (say pointer refused, keyboard granted) would
    // otherwise report input working while every mouse event is claimed by the
    // portal and silently dropped for the ungranted class. Treating a partial
    // grant as "no input" degrades to a capture-only session, which is the safe
    // outcome. GNOME grants all-or-nothing today, so this only ever bites a
    // future compositor that grants partially — but it bites safely.
    let want = DEVICE_KEYBOARD | DEVICE_POINTER;
    let input_granted = devices_granted & want == want;
    if kind == SessionKind::WithInput && !input_granted {
        tracing::warn!(
            devices_granted,
            "portal: the session started without BOTH keyboard and pointer granted — capture only"
        );
    }
    // Persisted immediately, before anything is reported: a caller that reads
    // the report and re-runs must find the token already on disk, or the
    // second run prompts again and the whole point of persisting is lost.
    let restore_token_stored = match results.get("restore_token").and_then(string_of) {
        Some(tok) => match store.save(&tok) {
            Ok(()) => true,
            Err(e) => {
                // Not fatal: the session is open and usable. It costs one
                // dialog next time, and saying so beats silence.
                tracing::warn!(%e, "portal: could not persist the restore token");
                false
            }
        },
        None => false,
    };

    // ── 4. OpenPipeWireRemote — a direct call, NOT a Request ────────────
    //
    // The fd is KEPT from P3a onward. It is the connection to the session's
    // PipeWire, and it is what `pipewire::probe` (and later the stream) uses.
    // It never travels to the daemon — see the module docs.
    let pipewire_fd = match screencast.call_method(
        "OpenPipeWireRemote",
        &(&sess_path, HashMap::<&str, Value>::new()),
    ) {
        Ok(msg) => match msg.body().deserialize::<zbus::zvariant::OwnedFd>() {
            Ok(fd) => Some(std::os::fd::OwnedFd::from(fd)),
            Err(e) => {
                tracing::warn!(%e, "portal: OpenPipeWireRemote returned no usable fd");
                None
            }
        },
        Err(e) => {
            tracing::warn!(%e, "portal: OpenPipeWireRemote failed");
            None
        }
    };

    Ok(Session {
        report: SessionReport {
            streams,
            restore_token_stored,
            pipewire_fd_ok: pipewire_fd.is_some(),
            restore_token_sent,
            input_granted,
            elapsed_ms: started.elapsed().as_millis() as u64,
            cursor_mode_used: cursor_mode,
            available_cursor_modes,
            available_source_types,
            // Filled in by the caller, which owns the decision to try.
            pipewire: super::pipewire::PipeWireStatus::NotAttempted,
        },
        pipewire_fd,
        input_session: input_granted.then(|| sess_path.clone().into()),
        path: sess_path.into(),
        conn,
    })
}

/// An opened session: what to report, plus the things that cannot be reported.
///
/// ⚠️ The fd is deliberately outside [`SessionReport`], which is the
/// serialisable half. A file descriptor cannot cross that boundary and — per
/// the module docs — must not: it stays in this process, where PipeWire is
/// consumed.
pub struct Session {
    pub report: SessionReport,
    /// `None` when `OpenPipeWireRemote` gave us nothing. Everything before it
    /// can succeed and still leave no connection, which is why
    /// `pipewire_fd_ok` is reported rather than assumed.
    pub pipewire_fd: Option<std::os::fd::OwnedFd>,
    /// P4 — the session's object path, present exactly when input devices
    /// were granted. What [`super::input::InputContext`] addresses `Notify*`
    /// calls at.
    pub input_session: Option<zbus::zvariant::OwnedObjectPath>,
    /// FR-93 P6c — the session's object path, always: [`Self::on_closed`]
    /// watches it.
    path: zbus::zvariant::OwnedObjectPath,
    /// ⚠️⚠️ **Holding this open is what keeps the PipeWire node alive.**
    ///
    /// A portal session is owned by the D-Bus connection that created it. Drop
    /// the connection and the portal tears the session down, which removes the
    /// node — and a stream connecting to it then fails with the wonderfully
    /// unhelpful `no target node available`, long after the handshake that
    /// looked completely successful.
    ///
    /// Measured, not guessed: the first field run of P3b-ii failed exactly
    /// that way because this field did not exist and the connection died when
    /// `open_blocking` returned. Private on purpose — [`Self::connection`]
    /// hands out a borrow for the input path, and nothing can *take* it.
    conn: zbus::blocking::Connection,
}

impl Session {
    /// The connection the session lives on. The input pump builds its
    /// RemoteDesktop proxy over this — same connection, same session.
    pub fn connection(&self) -> &zbus::blocking::Connection {
        &self.conn
    }

    /// FR-93 P6c — `on_closed` runs, once, when the portal closes this
    /// session: the person at the screen ended it with the desktop's own
    /// control (KDE's End in its screen-sharing indicator), or the compositor
    /// closed it (GNOME, at a screen lock). On its own thread, on this
    /// session's own connection: the portal sends `Closed` to the session's
    /// owner only, so a second connection would never hear it. A watcher that
    /// cannot subscribe says so and watches nothing, which leaves the capture
    /// to end with its stream, as before.
    pub fn on_closed(&self, on_closed: impl FnOnce() + Send + 'static) {
        let path = self.path.clone();
        let conn = self.conn.clone();
        let spawned = std::thread::Builder::new()
            .name("portal-closed".into())
            .spawn(move || {
                let proxy =
                    match zbus::blocking::Proxy::new(&conn, PORTAL_BUS, &path, SESSION_IFACE) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!(
                                "portal-helper: could not watch the portal session for Closed \
                                 ({e}); a share ended at the screen ends with its stream"
                            );
                            return;
                        }
                    };
                let mut closed = match proxy.receive_signal("Closed") {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "portal-helper: could not subscribe to the portal session's Closed \
                             ({e}); a share ended at the screen ends with its stream"
                        );
                        return;
                    }
                };
                if closed.next().is_some() {
                    on_closed();
                }
            });
        if let Err(e) = spawned {
            eprintln!("portal-helper: no thread to watch the portal session for Closed ({e})");
        }
    }
}

/// Where the portal's `restore_token` lives between runs.
///
/// ⚠️ **In the USER's state directory, never the daemon's config.** The token
/// is a standing grant to screencast this person's desktop without asking
/// again — it is theirs, it is scoped to their session, and a root-owned
/// host-global config file is the wrong shape for it in every respect. The
/// helper already runs as them, so it reads and writes this itself and the
/// token never reaches the daemon at all.
///
/// ⚠️ **One file per session kind.** An input session's token attests a wider
/// grant ("see and touch") than a capture session's ("see"), and the portal
/// will not restore a session of one shape from the other's token anyway —
/// sharing the file would just burn whichever grant was stored first.
///
/// ⚠️ Mode 0600, and the directory 0700, for the same reason `config.toml` is:
/// anything that can read it can re-open the grant.
pub struct TokenStore {
    path: std::path::PathBuf,
}

impl TokenStore {
    /// `$XDG_STATE_HOME/roomler/portal-restore-token[-rd]`, falling back to
    /// the spec's default of `$HOME/.local/state`.
    pub fn for_current_user(kind: SessionKind, source: SourceKind) -> Self {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".local").join("state"))
            })
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        // ⚠️ A window grant and a monitor grant are DIFFERENT grants: the
        // portal will not restore one from the other's token, and reusing the
        // file would burn whichever was stored first — the same reason the
        // input grant already lives apart.
        let file = match (kind, source) {
            (SessionKind::CaptureOnly, SourceKind::Monitor) => "portal-restore-token",
            (SessionKind::WithInput, SourceKind::Monitor) => "portal-restore-token-rd",
            (SessionKind::CaptureOnly, SourceKind::Window) => "portal-restore-token-win",
            (SessionKind::WithInput, SourceKind::Window) => "portal-restore-token-rd-win",
        };
        Self {
            path: base.join("roomler").join(file),
        }
    }

    /// A store at an explicit path. Exists so the behaviour can be tested
    /// without mutating `XDG_STATE_HOME`, which is process-global and would
    /// make the test order-dependent against every other test in the binary.
    pub fn at(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    /// The stored token, or `None` — including when the file is absent, empty
    /// or unreadable. A missing token is not an error; it costs one dialog.
    pub fn load(&self) -> Option<String> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        let tok = raw.trim();
        (!tok.is_empty()).then(|| tok.to_string())
    }

    pub fn save(&self, token: &str) -> std::io::Result<()> {
        use std::io::Write;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        // Written through a temp file and renamed: a half-written token would
        // be silently useless (one surprise dialog), and the atomic swap costs
        // nothing here.
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(token.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)
    }
}

// ── the Request/Response plumbing ───────────────────────────────────────

/// Arm the `Response` subscription, make the call, wait for the answer.
///
/// ⚠️ The order inside is the whole point: subscribe, *then* call. See the
/// module docs — a portal that answers without asking a human (the restore
/// path) can respond before a subscription made afterwards exists.
fn call_with_response<B>(
    conn: &zbus::blocking::Connection,
    portal: &zbus::blocking::Proxy<'_>,
    method: &str,
    body: &B,
    handle_token: &str,
) -> Result<HashMap<String, OwnedValue>, OpenError>
where
    B: serde::ser::Serialize + zbus::zvariant::DynamicType,
{
    let path = request_path(conn, handle_token)?;
    let req = zbus::blocking::Proxy::new(conn, PORTAL_BUS, path.as_str(), REQUEST_IFACE)
        .map_err(|e| OpenError::failed(format!("request proxy for {method}: {e}")))?;
    let mut signals = req
        .receive_signal("Response")
        .map_err(|e| OpenError::failed(format!("subscribing to {method} response: {e}")))?;

    portal
        .call_method(method, body)
        .map_err(|e| OpenError::failed(format!("{method}: {e}")))?;

    let msg = signals
        .next()
        .ok_or_else(|| OpenError::failed(format!("{method}: the response stream ended")))?;
    let (code, results) = msg
        .body()
        .deserialize::<(u32, HashMap<String, OwnedValue>)>()
        .map_err(|e| OpenError::failed(format!("{method} response body: {e}")))?;

    match code {
        RESPONSE_OK => Ok(results),
        RESPONSE_CANCELLED => Err(OpenError::Cancelled),
        _ => Err(OpenError::Ended),
    }
}

/// Where the portal will publish the `Response` for `token`.
///
/// Derived, not discovered, because it has to be known *before* the call.
fn request_path(conn: &zbus::blocking::Connection, token: &str) -> Result<String, OpenError> {
    let unique = conn
        .unique_name()
        .ok_or_else(|| OpenError::failed("the session connection has no unique name"))?;
    Ok(request_path_for(unique.as_str(), token))
}

/// The path-mangling rule from the portal spec, split out so it can be tested
/// without a bus: strip the leading `:` and turn every `.` into `_`.
fn request_path_for(unique_name: &str, token: &str) -> String {
    let sender = unique_name.trim_start_matches(':').replace('.', "_");
    format!("/org/freedesktop/portal/desktop/request/{sender}/{token}")
}

/// A fresh `handle_token`. Must be unique per call and a legal D-Bus path
/// element, so it is `[A-Za-z0-9_]` only — no uuid crate, no randomness
/// needed, since uniqueness is only required within this connection.
fn next_token(kind: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "roomler_{kind}_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn object_path(s: &str) -> Result<zbus::zvariant::ObjectPath<'static>, OpenError> {
    zbus::zvariant::ObjectPath::try_from(s.to_string())
        .map_err(|e| OpenError::failed(format!("session handle {s:?} is not an object path: {e}")))
}

// ── value plucking ──────────────────────────────────────────────────────

/// A `String` out of an `a{sv}` value, whatever wrapping it arrived in.
fn string_of(v: &OwnedValue) -> Option<String> {
    match <&Value>::from(v) {
        Value::Str(s) => Some(s.to_string()),
        Value::ObjectPath(p) => Some(p.to_string()),
        _ => None,
    }
}

/// A `u32` out of an `a{sv}` value — the `devices` bitmask in a Start
/// response.
fn u32_of(v: &OwnedValue) -> Option<u32> {
    match <&Value>::from(v) {
        Value::U32(n) => Some(*n),
        _ => None,
    }
}

/// `streams` is `a(ua{sv})`.
///
/// Parsed structurally rather than through a derive, because a portal that
/// adds a field to the stream dict must not turn into a failure to capture.
/// Anything unrecognised is skipped; only the node id is required.
fn parse_streams(v: &OwnedValue) -> Result<Vec<StreamInfo>, OpenError> {
    let Value::Array(arr) = <&Value>::from(v) else {
        return Err(OpenError::failed("streams was not an array"));
    };
    let mut out = Vec::new();
    for item in arr.inner() {
        let Value::Structure(s) = item else { continue };
        let fields = s.fields();
        let Some(Value::U32(node_id)) = fields.first() else {
            continue;
        };
        let (mut width, mut height, mut source_type) = (None, None, None);
        if let Some(Value::Dict(d)) = fields.get(1) {
            for (k, val) in d.iter() {
                let Value::Str(k) = k else { continue };
                // Values in an a{sv} arrive boxed in a variant.
                let val = match val {
                    Value::Value(inner) => inner.as_ref(),
                    other => other,
                };
                match k.as_str() {
                    "size" => {
                        if let Value::Structure(sz) = val {
                            let f = sz.fields();
                            if let (Some(Value::I32(w)), Some(Value::I32(h))) =
                                (f.first(), f.get(1))
                            {
                                width = Some(*w);
                                height = Some(*h);
                            }
                        }
                    }
                    "source_type" => {
                        if let Value::U32(t) = val {
                            source_type = Some(*t);
                        }
                    }
                    _ => {}
                }
            }
        }
        out.push(StreamInfo {
            node_id: *node_id,
            width,
            height,
            source_type,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mangling rule is in the portal spec and is not guessable from the
    /// result: get it wrong and the subscription sits on a path the portal
    /// never publishes to, so the call hangs forever instead of failing.
    #[test]
    fn request_path_strips_the_colon_and_replaces_dots() {
        assert_eq!(
            request_path_for(":1.284", "roomler_cs_9_0"),
            "/org/freedesktop/portal/desktop/request/1_284/roomler_cs_9_0"
        );
    }

    /// Tokens must be legal D-Bus path elements and must not repeat within a
    /// connection — two calls sharing one token would have their responses
    /// delivered to the same subscription.
    #[test]
    fn tokens_are_unique_and_path_safe() {
        let a = next_token("cs");
        let b = next_token("cs");
        assert_ne!(a, b);
        for t in [&a, &b] {
            assert!(
                t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{t} is not a legal path element"
            );
        }
    }

    /// Build the `a{sv}` half of a stream entry.
    fn props(pairs: Vec<(&'static str, Value<'static>)>) -> zbus::zvariant::Dict<'static, 'static> {
        let mut d = zbus::zvariant::Dict::new(
            &zbus::zvariant::Signature::Str,
            &zbus::zvariant::Signature::Variant,
        );
        for (k, v) in pairs {
            // ⚠️ Boxed EXPLICITLY as a variant. `Value::from(some_value)` is
            // identity, not a box, so writing that here would build an a{sv}
            // whose values are bare — a shape the portal never sends, and the
            // test would then be checking a case that cannot occur.
            d.append(Value::from(k), Value::Value(Box::new(v))).unwrap();
        }
        d
    }

    /// `(ua{sv})`. Built with the builder because `Dict` is not `Type`, so the
    /// tuple `From` impl does not apply to it.
    fn stream_entry(node: u32, p: zbus::zvariant::Dict<'static, 'static>) -> Value<'static> {
        Value::from(
            zbus::zvariant::StructureBuilder::new()
                .add_field(node)
                .append_field(Value::from(p))
                .build()
                .unwrap(),
        )
    }

    fn dict_stream(node: u32, w: i32, h: i32) -> Value<'static> {
        stream_entry(
            node,
            props(vec![
                ("size", Value::from((w, h))),
                ("source_type", Value::from(1u32)),
            ]),
        )
    }

    /// Wrap entries as the portal's `a(ua{sv})`.
    ///
    /// ⚠️ NOT `Value::from(vec![…])`. That builds an `av` — an array of
    /// *variants* — so every element arrives boxed, which is a shape the
    /// portal never sends. The first draft of these tests did exactly that and
    /// failed against correct parsing code, which is the right way round: the
    /// element signature is taken from a real entry so the array can only have
    /// the shape the entries actually are.
    fn streams_value(entries: Vec<Value<'static>>) -> OwnedValue {
        let sig = entries
            .first()
            .expect("need at least one entry to take a signature from")
            .value_signature()
            .clone();
        let mut arr = zbus::zvariant::Array::new(&sig);
        for e in entries {
            arr.append(e).unwrap();
        }
        OwnedValue::try_from(Value::from(arr)).unwrap()
    }

    #[test]
    fn streams_are_parsed_out_of_the_portal_shape() {
        let owned = streams_value(vec![dict_stream(42, 1920, 1080)]);
        let got = parse_streams(&owned).unwrap();
        assert_eq!(
            got,
            vec![StreamInfo {
                node_id: 42,
                width: Some(1920),
                height: Some(1080),
                source_type: Some(1),
            }]
        );
    }

    /// A portal that grows a field must not cost us the capture. Only the node
    /// id is required; everything else is best-effort.
    #[test]
    fn an_unknown_stream_property_is_ignored_not_fatal() {
        let owned = streams_value(vec![stream_entry(
            7,
            props(vec![("something_new_in_2027", Value::from("surprise"))]),
        )]);
        let got = parse_streams(&owned).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].node_id, 7);
        assert_eq!(got[0].width, None);
    }

    /// The `devices` bitmask arrives boxed in a variant like every `a{sv}`
    /// value; a non-u32 there reads as "nothing granted", never a panic.
    #[test]
    fn devices_bitmask_is_plucked_or_refused() {
        let n = OwnedValue::try_from(Value::from(3u32)).unwrap();
        assert_eq!(u32_of(&n), Some(3));
        let s = OwnedValue::try_from(Value::from("3")).unwrap();
        assert_eq!(u32_of(&s), None);
    }

    /// The token is a standing grant to screencast someone's desktop without
    /// asking again. It round-trips, and it lands 0600 — anything that can
    /// read it can re-open the grant.
    #[test]
    fn the_restore_token_round_trips_and_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("roomler-portal-tok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = TokenStore::at(dir.join("roomler").join("portal-restore-token"));

        // Absent is not an error — it costs one dialog, nothing more.
        assert_eq!(store.load(), None);

        store.save("tok-abc123").unwrap();
        assert_eq!(store.load().as_deref(), Some("tok-abc123"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("roomler").join("portal-restore-token"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "restore token must not be readable by others");
        }

        // Overwriting must replace, not append — a concatenated token is a
        // silent failure that looks exactly like a revoked grant.
        store.save("tok-second").unwrap();
        assert_eq!(store.load().as_deref(), Some("tok-second"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty or whitespace-only file must read as "no token", not as a
    /// token that is the empty string — the portal would reject that and the
    /// failure would look like a revoked grant rather than a corrupt file.
    #[test]
    fn a_blank_token_file_reads_as_absent() {
        let dir = std::env::temp_dir().join(format!("roomler-portal-blank-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("portal-restore-token");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "  \n").unwrap();
        assert_eq!(TokenStore::at(path).load(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every distinct grant lives in its OWN file. An input token attests more
    /// than a capture token, and a WINDOW grant is a different grant from a
    /// MONITOR one — the portal will not restore either from the other's
    /// token, so sharing a file would silently burn whichever was stored
    /// first and cost a surprise dialog.
    ///
    /// ⚠️ All four must be pairwise distinct; asserting only that two differ
    /// would pass with three of them colliding.
    #[test]
    fn token_stores_are_separated_by_every_grant_dimension() {
        use std::collections::HashSet;
        let all = [
            (SessionKind::CaptureOnly, SourceKind::Monitor),
            (SessionKind::WithInput, SourceKind::Monitor),
            (SessionKind::CaptureOnly, SourceKind::Window),
            (SessionKind::WithInput, SourceKind::Window),
        ]
        .map(|(k, s)| TokenStore::for_current_user(k, s).path);

        let unique: HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "every grant needs its own file");

        let name = |p: &std::path::PathBuf| p.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            name(&all[1]).ends_with("-rd"),
            "input store is the -rd file"
        );
        assert!(
            name(&all[2]).ends_with("-win"),
            "window store is the -win file"
        );
        assert!(
            name(&all[3]).ends_with("-rd-win"),
            "input+window is -rd-win"
        );
    }

    /// Cancelled has to stay distinguishable from a fault all the way out:
    /// a person saying no must never be retried as a transient error.
    #[test]
    fn cancelled_reads_as_a_person_not_a_fault() {
        assert!(OpenError::Cancelled.to_string().contains("declined"));
        assert_ne!(OpenError::Cancelled, OpenError::Ended);
    }

    /// FR-93 P2d-4 — a request the portal ended itself reaches the viewer, so
    /// it says what to check rather than only that it ended.
    #[test]
    fn an_ended_request_says_what_to_check() {
        let why = OpenError::Ended.to_string();
        assert!(why.contains("restart it, then xdg-desktop-portal"), "{why}");
        assert!(!why.contains("declined"), "{why}");
        // Whole inside FR-80's cap, with the prefix the cascade puts on it.
        let shown = format!("the desktop portal did not share the screen: {why}");
        let max = crate::capture::CaptureUnavailable::DETAIL_MAX;
        assert!(shown.chars().count() <= max, "{shown}");
    }

    /// A report serialised WITHOUT `input_granted` (an older helper) must
    /// deserialise as "no input", never fail — the daemon and helper can skew
    /// by one revision across an update.
    #[test]
    fn a_report_without_input_granted_reads_as_no_input() {
        let json = r#"{
            "streams": [],
            "restore_token_stored": false,
            "pipewire_fd_ok": false,
            "restore_token_sent": false,
            "elapsed_ms": 1,
            "cursor_mode_used": 1,
            "available_cursor_modes": null,
            "available_source_types": null,
            "pipewire": "NotAttempted"
        }"#;
        let r: SessionReport = serde_json::from_str(json).unwrap();
        assert!(!r.input_granted);
    }
}
