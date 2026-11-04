use block::{Block, ConcreteBlock};
use libc::c_void;
use super::ffi::*;
use super::config::Config;
use super::display::Display;
use super::frame::Frame;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

pub struct Capturer {
    stream: CGDisplayStreamRef,
    queue: DispatchQueue,
    // MESHHARBOR PATCH: see `Drop`.
    stop: Arc<StopLatch>,

    width: usize,
    height: usize,
    format: PixelFormat,
    display: Display
}

impl Capturer {
    pub fn new<F: Fn(Frame) + 'static>(
        display: Display,
        width: usize,
        height: usize,
        format: PixelFormat,
        config: Config,
        handler: F
    ) -> Result<Capturer, CGError> {
        let stop = Arc::new(StopLatch::default());
        let on_stop = stop.clone();
        let handler: FrameAvailableHandler =
            ConcreteBlock::new(move |status, _, surface, _| {
                use self::CGDisplayStreamFrameStatus::*;
                if status == FrameComplete {
                    handler(unsafe { Frame::new(surface) });
                } else if status == Stopped {
                    // MESHHARBOR PATCH: the stream's last word — see `Drop`.
                    on_stop.stopped();
                }
            }).copy();

        let queue = unsafe {
            dispatch_queue_create(
                b"quadrupleslap.scrap\0".as_ptr() as *const i8,
                ptr::null_mut()
            )
        };

        let stream = unsafe {
            let config = config.build();
            let stream = CGDisplayStreamCreateWithDispatchQueue(
                display.id(),
                width,
                height,
                format,
                config,
                queue,
                &*handler as *const Block<_, _> as *const c_void
            );
            CFRelease(config);
            stream
        };

        match unsafe { CGDisplayStreamStart(stream) } {
            CGError::Success => Ok(Capturer {
                stream, queue, stop, width, height, format, display
            }),
            x => Err(x)
        }
    }

    pub fn width(&self) -> usize { self.width }
    pub fn height(&self) -> usize { self.height }
    pub fn format(&self) -> PixelFormat { self.format }
    pub fn display(&self) -> Display { self.display }
}

impl Drop for Capturer {
    /// MESHHARBOR PATCH: release the stream only once CoreGraphics is done with it.
    ///
    /// Upstream stopped the stream and released it on the next line, with a
    /// `TODO: Maybe it should wait until Stopped before releasing?` — and the
    /// answer is yes. `CGDisplayStreamStop` is ASYNCHRONOUS: per its header,
    /// the handler "will eventually be called with a status of
    /// kCGDisplayStreamFrameStatusStopped. After that point it is safe to
    /// release the CGDisplayStream." Releasing before that freed the stream
    /// under a frame delivery CoreGraphics had already queued, and the queue
    /// then ran it: `EXC_BAD_ACCESS` in SkyLight's
    /// `_CGYDisplayStreamFrameAvailable`, on the `quadrupleslap.scrap` queue,
    /// moments after a session ended. Field-hit on a MacBook 2026-10-15: the
    /// GUI worker crashed after every session, and each crash lengthened the
    /// supervisor's restart backoff while the next viewer waited.
    ///
    /// So `Drop` only stops the stream and hands it to the latch. The release
    /// happens after `Stopped` has arrived, from a thread of its own, behind a
    /// barrier on the queue — never on the queue itself, whose current item
    /// may be CoreGraphics' delivery still holding the stream. A `Stopped`
    /// that never comes leaks one stream: survivable, where a release under
    /// CoreGraphics' feet is not.
    ///
    /// ⚠️ Nothing here blocks, so dropping a capturer from inside its own
    /// frame handler (on the queue) cannot deadlock.
    fn drop(&mut self) {
        unsafe {
            let _ = CGDisplayStreamStop(self.stream);
        }
        self.stop.release_once_stopped(Owned {
            stream: self.stream,
            queue: self.queue
        });
    }
}

/// MESHHARBOR PATCH: what `Drop` and the `Stopped` delivery agree on. Whichever
/// of the two comes second starts the release, so neither order can release
/// early and neither can lose the stream.
#[derive(Default)]
struct StopLatch {
    state: Mutex<StopState>
}

#[derive(Default)]
struct StopState {
    /// CoreGraphics delivered `Stopped`: it will not touch the stream again.
    stopped: bool,
    /// The capturer was dropped before `Stopped` arrived.
    pending: Option<Owned>
}

impl StopLatch {
    fn lock(&self) -> MutexGuard<'_, StopState> {
        // Poisoning cannot leave this state half-written — both writers set a
        // single field — so a poisoned lock is still a usable one.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// From the handler, on the stream's queue.
    fn stopped(&self) {
        let pending = {
            let mut state = self.lock();
            state.stopped = true;
            state.pending.take()
        };
        if let Some(owned) = pending {
            owned.release_off_queue();
        }
    }

    /// From `Drop`, after `CGDisplayStreamStop`.
    fn release_once_stopped(&self, owned: Owned) {
        let mut state = self.lock();
        if state.stopped {
            drop(state);
            owned.release_off_queue();
        } else {
            state.pending = Some(owned);
        }
    }
}

/// MESHHARBOR PATCH: the two references `Capturer` owns, once it no longer can.
struct Owned {
    stream: CGDisplayStreamRef,
    queue: DispatchQueue
}

// SAFETY: a CoreFoundation object and a dispatch queue, each released exactly
// once from whichever thread ends up holding this. Both are documented as safe
// to release from any thread, and nothing here dereferences either one.
unsafe impl Send for Owned {}

impl Owned {
    fn release_off_queue(self) {
        let spawned = thread::Builder::new()
            .name("scrap-stream-release".into())
            // A method call, so the closure moves the whole `Owned` (which
            // is `Send`) rather than its two raw pointers (which are not).
            .spawn(move || self.release_now());
        // No thread, no release: a leaked stream is survivable, a release
        // on the queue is the bug this exists to fix.
        drop(spawned);
    }

    fn release_now(self) {
        unsafe {
            // Waits out whatever is running on the queue — when called from
            // the `Stopped` delivery, that delivery itself — and anything
            // queued behind it.
            dispatch_sync_f(self.queue, ptr::null_mut(), drained);
            CFRelease(self.stream);
            dispatch_release(self.queue);
        }
    }
}

extern "C" fn drained(_: *mut c_void) {}
