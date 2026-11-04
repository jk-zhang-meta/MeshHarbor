// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! P5 (multi-org program) — shared-floor encoder for the DC video transports.
//!
//! With `rc_max_sessions` ≥ 2 (rc.302), every concurrent viewer used to run
//! its OWN capture + encoder: two viewers of one host = two DXGI
//! duplications + two HW encode streams — double the GPU cost for identical
//! pixels, and the DDA seat limit (~4) burns twice as fast. This module
//! makes DC-transport sessions with an IDENTICAL hard profile (same
//! transport + codec + chroma) share ONE capture + ONE encoder:
//!
//!   * The FIRST session's pump runs unchanged ("owner": capture, encode,
//!     AIMD, flip/settle/backstop machinery all stay per-pump).
//!   * Later same-profile sessions register as FOLLOWERS: they get every
//!     encoded packet the owner emits, via their own DC chunker task, and
//!     never open a capturer or encoder.
//!   * Per-viewer inputs merge into the owner's loop as a FLOOR: any
//!     viewer's keyframe request forces an IDR for the shared stream; the
//!     frame-skip divisor is the MAX across viewers (slowest decoder wins);
//!     the resolution/priority dials merge to the most conservative; a
//!     congested follower gates frame PRODUCTION exactly like the owner's
//!     own full send-queue (rc.111) — the AIMD then lowers the shared
//!     bitrate. Frames are never dropped per-viewer post-encode: skipping
//!     one viewer's deltas would break ITS reference chain (the 13-byte DC
//!     header has no sequence/recovery), so the floor paces the SOURCE.
//!   * A JOINER decodes nothing until a keyframe: joining sets a
//!     pipeline-wide IDR request and the follower's fan-out stays gated
//!     until the first key-flagged packet (the existing per-pump min-gap
//!     clamps still bound IDR churn).
//!   * SPILL: when one viewer's sustained rate sits far from the others
//!     (it would drag the floor down — or be dragged — indefinitely), the
//!     most deviant FOLLOWER detaches and re-dispatches into its own pump,
//!     bounded so an agent never runs more than [`MAX_PIPELINES`] encoder
//!     pipelines because of spilling.
//!   * The owner leaving closes the pipeline: followers detach and
//!     re-dispatch (first one becomes the new owner, the rest re-join) —
//!     a one-time IDR hiccup instead of fragile in-place promotion.
//!
//! WebRTC-track sessions are excluded by design (mediasoup-style per-track
//! REMB rate control stays per-session). Escape hatch:
//! `ROOMLERD_SHARED_ENCODER=0` (config key `shared_encoder`) restores
//! the rc.302 pump-per-session behaviour without a rebuild.
//!
//! Everything stateful here is abort-safe: both the owner's [`Pipeline`]
//! and a follower's [`FollowerGuard`] detach in `Drop`, and session
//! teardown aborts the media task — the guards run at the await point.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use webrtc::data_channel::RTCDataChannel;

use crate::encode::viewer_rate::ViewerRateController;
use crate::peer::TargetResolution;

/// Ceiling on encoder pipelines created BY SPILLING. Organic distinct
/// profiles (different codecs negotiated) still each get a pump — the
/// session cap bounds those; this bound only stops spill from re-deriving
/// one-encoder-per-viewer.
pub const MAX_PIPELINES: usize = 2;

/// Divisor ratio (max/min across the pipeline's viewers) that counts as a
/// spill-worthy deviation…
pub const SPILL_RATIO: u32 = 4;
/// …once it has held for this many consecutive viewer-rate windows (~1 s
/// each). Resets as soon as the ratio drops below [`SPILL_RESET_RATIO`].
pub const SPILL_AFTER_WINDOWS: u32 = 10;
/// Below this ratio the deviation counter resets (hysteresis: a viewer
/// hovering around the threshold never ping-pongs between shared and own).
pub const SPILL_RESET_RATIO: u32 = 2;

/// Follower DC send-queue depth. Matches the owner pump's direct-path depth;
/// a slower follower link surfaces as a full queue → the production gate +
/// AIMD floor react, so the depth is a burst buffer, not a latency budget.
const FOLLOWER_SEND_DEPTH: usize = 12;

/// Hard profile key — the part of a session's negotiated video profile that
/// CANNOT merge (the browser built its decoder for it).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PipelineKey {
    /// FFmpeg DC pump — keyed by the codec label ("HEVC"/"AV1"/"VP9"/"H264").
    FfmpegDc(&'static str),
    /// libvpx VP9 DC pump — keyed by chroma (444 vs 420 are different VP9
    /// profiles; the viewer's decoder config differs).
    Vp9Dc { chroma_444: bool },
}

/// Whether shared pipelines are enabled (default ON;
/// `ROOMLERD_SHARED_ENCODER=0` / `false` reverts to pump-per-session).
pub fn sharing_enabled() -> bool {
    !matches!(
        tunnel_core::env::node_env("SHARED_ENCODER").as_deref(),
        Some("0") | Some("false")
    )
}

/// Why a follower's wait ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetachReason {
    /// The owner pump exited (session closed / encoder fatal) — re-dispatch;
    /// re-joining (or becoming the new owner) is correct.
    PipelineClosed,
    /// The spill gate evicted this viewer — spawn an OWN pump; do not
    /// immediately re-join the pipeline it was just evicted from.
    Spilled,
}

/// The per-session handles a follower contributes to the shared pipeline —
/// clones of exactly the Arcs its own pump would have consumed.
pub struct FollowerSink {
    pub session_id: bson::oid::ObjectId,
    pub video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    pub control_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    pub keyframe_requested: Arc<AtomicBool>,
    pub target_resolution: Arc<Mutex<TargetResolution>>,
    pub quality_state: Arc<AtomicU8>,
    pub viewer_report: Arc<crate::encode::viewer_rate::ViewerFeedback>,
    pub priority: Arc<AtomicU8>,
    pub capture_native_dims: Arc<AtomicU64>,
    pub encoded_dims: Arc<AtomicU64>,
    /// FR-17 — whether THIS follower's controller negotiated per-chunk
    /// framing (`chunk-framing` in `rc:session.request`). It is a per-SESSION
    /// property, so a follower can disagree with the owner; the follower
    /// chunker MUST frame exactly as this follower's browser expects, or the
    /// receiver parses a chunk header out of raw payload and decodes nothing
    /// (field 2026-08-30: every chunk-framing follower was a black screen —
    /// the owner framed, the follower chunker did not).
    pub chunk_framing: bool,
}

struct DetachState {
    notify: tokio::sync::Notify,
    reason: Mutex<Option<DetachReason>>,
}

struct Follower {
    sink: FollowerSink,
    send_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    /// False until the first key-flagged packet is forwarded — the joiner
    /// gate (a delta before the first IDR is undecodable for this viewer).
    synced: bool,
    viewer_rate: ViewerRateController,
    divisor: u32,
    /// Consecutive spill-qualifying windows (see [`SPILL_AFTER_WINDOWS`]).
    spill_strikes: u32,
    detach: Arc<DetachState>,
}

impl Follower {
    fn detach(&self, reason: DetachReason) {
        let mut r = self.detach.reason.lock().unwrap();
        if r.is_none() {
            *r = Some(reason);
        }
        drop(r);
        self.detach.notify.notify_waiters();
    }
}

#[derive(Default)]
struct PipelineInner {
    followers: Vec<Follower>,
    /// Set on follower join (and on a synced follower's forced desync) —
    /// consumed by the owner's keyframe-merge point.
    kf_needed: bool,
    /// Last `rc:video-info` payload the owner published — replayed to
    /// joiners so their stats badge is honest without waiting for the next
    /// owner-side refresh.
    video_info: Option<String>,
    /// Owner marks this when its pump exits; blocks late joins racing the
    /// registry removal.
    closed: bool,
    /// Millis (process-epoch) of the owner's last loop iteration —
    /// [`Pipeline::beat`]. Joiners treat a silent owner as DEAD (rc.443):
    /// field 2026-08-21, corplap — an av1_qsv driver hang froze the owner pump
    /// INSIDE `enc.encode()` (inline-blocking, no await to time out), its
    /// session was torn down, but the never-returning task never dropped
    /// its `Pipeline`, so the registry entry survived and every subsequent
    /// same-profile viewer joined a corpse ("no video after 4 attempts")
    /// until a daemon restart.
    last_beat_ms: AtomicU64,
}

/// Owner silence beyond this ⇒ the pipeline is a corpse a joiner may evict.
/// The owner beats every pump-loop iteration (including backpressure skips
/// and empty polls, ≤ ~35 ms apart in a healthy pump), so 10 s of silence
/// only ever means a wedged task.
const PIPELINE_STALE: Duration = Duration::from_secs(10);

/// Millis since a process-stable epoch (first use). Monotonic — safe for
/// staleness arithmetic across tasks. Biased by one minute so values near
/// process start can still be AGED backwards (`force_stale`'s subtraction
/// would otherwise saturate at 0 and read as fresh).
fn now_ms() -> u64 {
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    60_000
        + EPOCH
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
}

type Registry = Mutex<HashMap<PipelineKey, Arc<Mutex<PipelineInner>>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many shared pipelines are currently registered (spill budget input).
fn pipeline_count() -> usize {
    registry().lock().unwrap().len()
}

// ─── Owner side ─────────────────────────────────────────────────────────

/// Owner-held handle for one shared pipeline. Register at pump start, call
/// the merge helpers from the loop, `fan_out` at the send point. Drop (incl.
/// task abort) detaches every follower with [`DetachReason::PipelineClosed`]
/// and removes the registry entry.
pub struct Pipeline {
    key: PipelineKey,
    inner: Arc<Mutex<PipelineInner>>,
    /// False when another pump already owned the key (duplicate profile
    /// race) — this pipeline then runs standalone and never gets followers.
    registered: bool,
    owner_session: bson::oid::ObjectId,
}

impl Pipeline {
    /// Register the calling pump as the owner for `key`. If the key is
    /// already owned (two same-profile pumps raced), the returned pipeline
    /// is standalone — valid, merge helpers are no-ops, no followers.
    pub fn register(key: PipelineKey, owner_session: bson::oid::ObjectId) -> Self {
        let inner = Arc::new(Mutex::new(PipelineInner::default()));
        inner.lock().unwrap().last_beat_ms.store(now_ms(), Relaxed);
        let mut reg = registry().lock().unwrap();
        let registered = match reg.entry(key) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(inner.clone());
                true
            }
        };
        drop(reg);
        if !registered {
            tracing::debug!(?key, %owner_session, "media_share: key already owned — running standalone pump");
        }
        Self {
            key,
            inner,
            registered,
            owner_session,
        }
    }

    /// Owner-liveness beat — call once per pump-loop iteration (any arm:
    /// real frame, empty poll, backpressure skip). A joiner finding this
    /// stale by [`PIPELINE_STALE`] evicts the registration (rc.443 — a
    /// driver-hung owner can never drop its `Pipeline` itself).
    pub fn beat(&self) {
        self.inner
            .lock()
            .unwrap()
            .last_beat_ms
            .store(now_ms(), Relaxed);
    }

    /// Test hook: age the beat past the staleness horizon.
    #[cfg(test)]
    fn force_stale(&self) {
        self.inner.lock().unwrap().last_beat_ms.store(
            now_ms().saturating_sub(PIPELINE_STALE.as_millis() as u64 + 1_000),
            Relaxed,
        );
    }

    /// Viewers on this pipeline beyond the owner.
    pub fn follower_count(&self) -> usize {
        self.inner.lock().unwrap().followers.len()
    }

    /// FR-93 P6c — the sessions following this pipeline. An owner whose
    /// capture was stopped at the screen ends them before itself: had it gone
    /// first, they would detach, re-dispatch, and open the capture the person
    /// had just stopped.
    pub fn follower_sessions(&self) -> Vec<bson::oid::ObjectId> {
        self.inner
            .lock()
            .unwrap()
            .followers
            .iter()
            .map(|f| f.sink.session_id)
            .collect()
    }

    /// Any viewer (follower atomics + the join flag) wants an IDR. Consumes
    /// the requests, mirroring `keyframe_requested.swap(false)`.
    pub fn take_keyframe_requested(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let mut wanted = std::mem::take(&mut inner.kf_needed);
        for f in &inner.followers {
            if f.sink
                .keyframe_requested
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                wanted = true;
            }
        }
        wanted
    }

    /// Floor-merge of the resolution dial: the smallest requested area wins
    /// (`Native` requests no constraint). Composes BEFORE the relay/auto
    /// caps exactly like the owner's own dial.
    pub fn merged_target(&self, own: TargetResolution) -> TargetResolution {
        let inner = self.inner.lock().unwrap();
        let mut best = own;
        for f in &inner.followers {
            let t = *f.sink.target_resolution.lock().unwrap();
            best = smaller_target(best, t);
        }
        best
    }

    /// FR-119 P2b-2 — floor-merge of the frame-rate ask: the smallest across
    /// the viewers, and a viewer that asked nothing asks for today's rate
    /// (`None` wins). A viewer on a 60 Hz screen never receives a heavier
    /// stream than it asked for.
    pub fn merged_fps_ask(&self, own: Option<u32>) -> Option<u32> {
        let inner = self.inner.lock().unwrap();
        inner.followers.iter().fold(own, |merged, f| {
            match (merged, f.sink.viewer_report.fps_ask()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            }
        })
    }

    /// Floor-merge of the Priority dial's relay resolution cap: the smallest
    /// cap across viewers (None = uncapped for that viewer).
    pub fn merged_priority_cap(&self, own_cap: Option<u32>, constrained: bool) -> Option<u32> {
        self.merged_priority_cap_by(own_cap, |p| {
            crate::encode::priority_relay_cap(p, constrained)
        })
    }

    /// [`Self::merged_priority_cap`] with the per-dial cap supplied — the
    /// FR-70 M3a plan producer's form, which resolves the dial caps once per
    /// pump (`encode::priority_relay_cap_for`) instead of reading env for
    /// every follower on every frame. The reader above is this applied.
    pub fn merged_priority_cap_by(
        &self,
        own_cap: Option<u32>,
        cap_of: impl Fn(u8) -> Option<u32>,
    ) -> Option<u32> {
        let inner = self.inner.lock().unwrap();
        let mut cap = own_cap;
        for f in &inner.followers {
            let p = f.sink.priority.load(Relaxed);
            let fc = cap_of(p);
            cap = match (cap, fc) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (None, Some(b)) => Some(b),
                (a, None) => a,
            };
        }
        cap
    }

    /// P7b (merge-aware idle refine) — is the pipeline's merged cap LIFTABLE
    /// at rest? True iff every viewer whose Priority dial contributes a cap
    /// (`priority_relay_cap(..) == Some`) also passes `idle_refine_applies`.
    /// Viewers contributing NO cap (Sharper; Balanced on direct) never block
    /// — they asked for native anyway. Vacuously true when nothing caps (the
    /// caller's merged-cap-clamps check already gates that case). Field
    /// 2026-08-20 (winhost-b): owner=Sharper + follower=Smoother parked the
    /// shared stream at 1024 with refine dead — the floor-merge took the
    /// follower's cap while eligibility read only the owner's dial, giving
    /// the worst combination (capped AND never crisp at rest). With a single
    /// viewer this reduces exactly to `idle_refine_applies(own_prio, _)`.
    pub fn merged_refine_eligible(&self, own_prio: u8, constrained: bool) -> bool {
        let blocks = |p: u8| {
            crate::encode::priority_relay_cap(p, constrained).is_some()
                && !crate::encode::idle_refine_applies(p, constrained)
        };
        if blocks(own_prio) {
            return false;
        }
        let inner = self.inner.lock().unwrap();
        !inner
            .followers
            .iter()
            .any(|f| blocks(f.sink.priority.load(Relaxed)))
    }

    /// P8 Phase 4 (mixed-dial telemetry) — does any follower's dial pair
    /// (Priority, resolution pick) differ from the owner's? This is the
    /// share-shape a per-viewer pipeline (SVC / tiered transcode) would
    /// serve better than the floor-merge; the pumps count it into the
    /// session stats per heartbeat window so the SVC decision is made on
    /// field data. False with zero followers (nothing shared).
    pub fn dials_mixed(&self, own_prio: u8, own_target: TargetResolution) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.followers.iter().any(|f| {
            f.sink.priority.load(Relaxed) != own_prio
                || *f.sink.target_resolution.lock().unwrap() != own_target
        })
    }

    /// Floor-merge of the quality dial (lowest value = most conservative;
    /// the VP9 pump's semantics). The FFmpeg pump ignores quality.
    pub fn min_quality(&self, own: u8) -> u8 {
        let inner = self.inner.lock().unwrap();
        inner
            .followers
            .iter()
            .map(|f| f.sink.quality_state.load(Relaxed))
            .fold(own, u8::min)
    }

    /// True when any follower's send queue is full — folded into the
    /// owner's rc.111 production gate so the whole pipeline paces to the
    /// slowest link (the pre-encode floor; never per-viewer delta drops).
    pub fn followers_congested(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.followers.iter().any(|f| f.send_tx.capacity() == 0)
    }

    /// Step every follower's viewer-rate controller for this ~1 s window and
    /// return the MAX divisor across followers (the owner takes the max with
    /// its own). Also runs the spill gate: a sustained large deviation
    /// between the pipeline's fastest and slowest viewer detaches the most
    /// deviant FOLLOWER (bounded by the pipeline budget).
    pub fn step_viewer_windows(&self, own_divisor: u32, capture_fps: u32) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        let mut max_div = 1u32;
        for f in inner.followers.iter_mut() {
            let raw = f.sink.viewer_report.take_report();
            let (fps, struggling) = crate::encode::viewer_rate::unpack_report(raw);
            f.divisor = f.viewer_rate.observe(fps, struggling, capture_fps);
            max_div = max_div.max(f.divisor);
        }
        // Spill gate — only meaningful with ≥2 viewers total and only when
        // spawning another pipeline stays inside the budget.
        if !inner.followers.is_empty() && pipeline_count() < MAX_PIPELINES {
            let divs: Vec<u32> = std::iter::once(own_divisor)
                .chain(inner.followers.iter().map(|f| f.divisor))
                .collect();
            let lo = *divs.iter().min().unwrap_or(&1);
            let hi = *divs.iter().max().unwrap_or(&1);
            let deviating = ratio_qualifies(lo, hi, SPILL_RATIO);
            let resets = !ratio_qualifies(lo, hi, SPILL_RESET_RATIO);
            let mut spill_idx: Option<usize> = None;
            for (i, f) in inner.followers.iter_mut().enumerate() {
                if resets {
                    f.spill_strikes = 0;
                    continue;
                }
                // Only the most deviant follower accumulates strikes: the
                // one whose divisor sits farthest from the OWNER's (the
                // owner cannot spill — it holds the capture/encoder).
                let is_most_deviant = deviating
                    && f.divisor.abs_diff(own_divisor)
                        >= divs
                            .iter()
                            .map(|d| d.abs_diff(own_divisor))
                            .max()
                            .unwrap_or(0)
                    && f.divisor != own_divisor;
                if is_most_deviant {
                    f.spill_strikes += 1;
                    if f.spill_strikes >= SPILL_AFTER_WINDOWS {
                        spill_idx = Some(i);
                    }
                } else {
                    f.spill_strikes = 0;
                }
            }
            if let Some(i) = spill_idx {
                let f = inner.followers.remove(i);
                tracing::info!(
                    session = %f.sink.session_id,
                    owner = %self.owner_session,
                    divisor = f.divisor,
                    own_divisor,
                    "media_share: sustained rate deviation — spilling viewer to its own encoder"
                );
                f.detach(DetachReason::Spilled);
            }
        }
        max_div
    }

    /// Forward one framed wire packet to every follower and mirror the dim
    /// atomics (the cursor pumps of follower sessions scale off them).
    /// Called on the owner's hot path — sync + try_send only.
    ///
    /// Sync gating: an unsynced follower skips deltas until the first
    /// keyframe. A synced follower whose queue is full at a delta is
    /// DESYNCED (its reference chain just broke) and a pipeline IDR is
    /// requested — the production-gate floor makes this rare (races only).
    pub fn fan_out(
        &self,
        wire: &bytes::Bytes,
        is_keyframe: bool,
        native_dims: u64,
        encoded_dims: u64,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.followers.is_empty() {
            return;
        }
        let mut need_kf = false;
        for f in inner.followers.iter_mut() {
            f.sink.capture_native_dims.store(native_dims, Relaxed);
            f.sink.encoded_dims.store(encoded_dims, Relaxed);
            if !f.synced {
                if !is_keyframe {
                    continue;
                }
                f.synced = true;
            }
            match f.send_tx.try_send(wire.clone()) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Whatever was dropped (delta OR the IDR later deltas
                    // will reference), this viewer's chain is broken —
                    // desync and resync at the next keyframe. The
                    // production-gate floor makes this a race-only path.
                    f.synced = false;
                    need_kf = true;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Chunker died (guard drop races) — the follower's guard
                    // removal will prune it; skip meanwhile.
                }
            }
        }
        if need_kf {
            inner.kf_needed = true;
        }
    }

    /// Publish the owner's `rc:video-info` payload: stored for joiner replay
    /// and pushed to every follower's control DC (spawned — control DCs are
    /// async).
    pub fn publish_video_info(&self, payload: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.video_info = Some(payload.clone());
        let targets: Vec<_> = inner
            .followers
            .iter()
            .map(|f| f.sink.control_dc.clone())
            .collect();
        drop(inner);
        for cdc in targets {
            let payload = payload.clone();
            tokio::spawn(async move {
                if let Some(dc) = cdc.lock().await.clone() {
                    let _ = dc.send_text(payload).await;
                }
            });
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        if self.registered {
            // Identity-aware removal (rc.443): a stale-evicted owner's LATE
            // drop (the wedged driver call finally returning, or process
            // teardown) must not delete the entry a NEW owner registered
            // after the eviction — remove only if the entry is still ours.
            let mut reg = registry().lock().unwrap();
            if let Some(cur) = reg.get(&self.key)
                && Arc::ptr_eq(cur, &self.inner)
            {
                reg.remove(&self.key);
            }
        }
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        for f in inner.followers.drain(..) {
            f.detach(DetachReason::PipelineClosed);
        }
    }
}

// ─── Follower side ──────────────────────────────────────────────────────

/// Follower-held handle. Await [`FollowerGuard::detached`]; Drop (session
/// teardown aborts the media task) removes the follower from the pipeline.
pub struct FollowerGuard {
    inner: Arc<Mutex<PipelineInner>>,
    session_id: bson::oid::ObjectId,
    detach: Arc<DetachState>,
}

impl FollowerGuard {
    /// Resolves when the pipeline closes or the spill gate evicts this
    /// viewer.
    pub async fn detached(&self) -> DetachReason {
        loop {
            if let Some(r) = *self.detach.reason.lock().unwrap() {
                return r;
            }
            self.detach.notify.notified().await;
        }
    }
}

impl Drop for FollowerGuard {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .followers
            .retain(|f| f.sink.session_id != self.session_id);
    }
}

/// Join `key`'s pipeline as a follower. `None` when sharing is off, no
/// pipeline owns the key, or the pipeline is closing. On success the
/// follower's DC chunker task is running, a pipeline IDR is requested, and
/// the last `rc:video-info` (if any) is replayed to this viewer.
pub fn try_join(
    key: PipelineKey,
    sink: FollowerSink,
    capture_fps_hint: u32,
) -> Option<FollowerGuard> {
    if !sharing_enabled() {
        return None;
    }
    let inner = registry().lock().unwrap().get(&key)?.clone();
    let mut guard = inner.lock().unwrap();
    if guard.closed {
        return None;
    }
    // rc.443 — stale-owner eviction. An owner whose pump task is wedged
    // (field: av1_qsv driver hang inside the inline-blocking encode) never
    // drops its `Pipeline`, so the entry outlives the session and every
    // joiner becomes a follower of a corpse. A silent beat for
    // `PIPELINE_STALE` can only mean that wedge (a healthy loop beats every
    // few ms); evict the entry and refuse the join — the caller then runs
    // its own pump, which registers freshly as the new owner.
    let silent_ms = now_ms().saturating_sub(guard.last_beat_ms.load(Relaxed));
    if silent_ms > PIPELINE_STALE.as_millis() as u64 {
        guard.closed = true;
        for f in guard.followers.drain(..) {
            f.detach(DetachReason::PipelineClosed);
        }
        drop(guard);
        let mut reg = registry().lock().unwrap();
        if let Some(cur) = reg.get(&key)
            && Arc::ptr_eq(cur, &inner)
        {
            reg.remove(&key);
        }
        tracing::warn!(
            ?key,
            silent_ms,
            "media_share: evicted stale pipeline (owner pump silent — wedged encode?); joiner will own a fresh one"
        );
        return None;
    }
    let session_id = sink.session_id;
    let (send_tx, send_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(FOLLOWER_SEND_DEPTH);
    spawn_follower_chunker(
        session_id,
        sink.video_bytes_dc.clone(),
        send_rx,
        sink.chunk_framing,
    );
    let detach = Arc::new(DetachState {
        notify: tokio::sync::Notify::new(),
        reason: Mutex::new(None),
    });
    // Replay the badge so the joiner's stats chip is honest immediately.
    if let Some(info) = guard.video_info.clone() {
        let cdc = sink.control_dc.clone();
        tokio::spawn(async move {
            if let Some(dc) = cdc.lock().await.clone() {
                let _ = dc.send_text(info).await;
            }
        });
    }
    guard.followers.push(Follower {
        sink,
        send_tx,
        synced: false,
        viewer_rate: ViewerRateController::new(capture_fps_hint.max(1)),
        divisor: 1,
        spill_strikes: 0,
        detach: detach.clone(),
    });
    // The joiner needs an IDR before anything it receives decodes.
    guard.kf_needed = true;
    drop(guard);
    tracing::info!(%session_id, ?key, "media_share: joined shared encoder pipeline as follower");
    Some(FollowerGuard {
        inner,
        session_id,
        detach,
    })
}

/// P6/P5 field fix (2026-08-05) — a follower's control DC just opened.
///
/// `try_join` replays the owner's last `rc:video-info` at JOIN time, but a
/// follower registers during `AgentPeer::new`, before any data channel
/// exists — the replay found an empty stash and was dropped, so a
/// follower's badge fell back to the selection-derived label and never
/// showed `shared ×N`. Re-send it now that the DC is live. No-op when the
/// session isn't a follower or the owner hasn't published yet.
pub fn replay_video_info(session: bson::oid::ObjectId) {
    let pipelines: Vec<Arc<Mutex<PipelineInner>>> =
        registry().lock().unwrap().values().cloned().collect();
    for inner in pipelines {
        let guard = inner.lock().unwrap();
        let Some(info) = guard.video_info.clone() else {
            continue;
        };
        let Some(f) = guard
            .followers
            .iter()
            .find(|f| f.sink.session_id == session)
        else {
            continue;
        };
        let cdc = f.sink.control_dc.clone();
        drop(guard);
        tokio::spawn(async move {
            if let Some(dc) = cdc.lock().await.clone() {
                let _ = dc.send_text(info).await;
            }
        });
        return;
    }
}

/// A follower's `video-bytes` DC just opened.
///
/// The join forces a pipeline IDR the instant the follower registers (during
/// `AgentPeer::new`, ~33 ms after `try_join`), but this video DC finishes
/// negotiating hundreds of ms later — and [`spawn_follower_chunker`] DROPS
/// anything that arrives while the DC is `None`/`!Open`. So that join-IDR is
/// lost, yet [`Pipeline::fan_out`] already flipped the follower to `synced`
/// when it queued it: the follower then receives only deltas it cannot
/// decode — a BLACK SCREEN until the next natural keyframe. Now that the DC
/// is live, reset the follower to unsynced and request a fresh IDR so it
/// re-syncs onto a keyframe the chunker will actually deliver. No-op when the
/// session is a leader (not in any pipeline's follower list) — mirrors
/// [`replay_video_info`], which handles the same race for the control DC.
pub fn resync_follower(session: bson::oid::ObjectId) {
    let pipelines: Vec<Arc<Mutex<PipelineInner>>> =
        registry().lock().unwrap().values().cloned().collect();
    for inner in pipelines {
        let mut guard = inner.lock().unwrap();
        let found = guard.followers.iter_mut().any(|f| {
            if f.sink.session_id == session {
                f.synced = false;
                true
            } else {
                false
            }
        });
        if found {
            guard.kf_needed = true;
            tracing::info!(
                %session,
                "media_share: follower video DC live — re-syncing onto a fresh IDR (join-IDR was dropped pre-open)"
            );
            return;
        }
    }
}

/// The follower's DC send task — the same 16 KiB chunk discipline as the
/// owner pumps' send tasks (single consumer per DC keeps chunk order for
/// the browser reassembler).
fn spawn_follower_chunker(
    session_id: bson::oid::ObjectId,
    video_bytes_dc: Arc<tokio::sync::Mutex<Option<Arc<RTCDataChannel>>>>,
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    chunk_framing: bool,
) {
    tokio::spawn(async move {
        const SCTP_CHUNK_SIZE: usize = 16 * 1024;
        // Per-follower frame sequence, exactly like the owner's send task:
        // the browser reassembler compares it for equality only, so a
        // follower's numbering being independent of the owner's is fine.
        let mut frame_seq: u32 = 0;
        while let Some(wire) = rx.recv().await {
            let Some(dc) = video_bytes_dc.lock().await.clone() else {
                continue;
            };
            if dc.ready_state()
                != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
            {
                continue;
            }
            let total = wire.len();
            let chunk_count = total.div_ceil(SCTP_CHUNK_SIZE).max(1) as u16;
            let mut chunk_idx: u16 = 0;
            frame_seq = frame_seq.wrapping_add(1);
            let mut off = 0usize;
            while off < total {
                let end = (off + SCTP_CHUNK_SIZE).min(total);
                // MUST match the owner's send task (`media_pump_ffmpeg_dc`):
                // apply the FR-17 8-byte chunk header when this follower
                // negotiated it, or send raw slices when it did not. Sending
                // raw slices to a chunk-framing browser hands it a chunk
                // header parsed from AV1 payload — undecodable, a black screen.
                let res = if chunk_framing {
                    let framed = crate::peer::chunk_framed(
                        frame_seq,
                        chunk_idx,
                        chunk_count,
                        &wire.slice(off..end),
                    );
                    dc.send(&bytes::Bytes::from(framed)).await
                } else {
                    dc.send(&wire.slice(off..end)).await
                };
                if let Err(e) = res {
                    tracing::debug!(session = %session_id, %e, "media_share follower: DC send failed");
                    break;
                }
                off = end;
                chunk_idx = chunk_idx.wrapping_add(1);
            }
        }
        tracing::debug!(session = %session_id, "media_share follower chunker exiting");
    });
}

// ─── Pure helpers ───────────────────────────────────────────────────────

/// The smaller (more conservative) of two resolution dials by target area;
/// `Native` imposes no constraint.
fn smaller_target(a: TargetResolution, b: TargetResolution) -> TargetResolution {
    match (a, b) {
        (TargetResolution::Native, other) => other,
        (me, TargetResolution::Native) => me,
        (
            TargetResolution::Fixed {
                width: aw,
                height: ah,
            },
            TargetResolution::Fixed {
                width: bw,
                height: bh,
            },
        ) => {
            if (bw as u64 * bh as u64) < (aw as u64 * ah as u64) {
                TargetResolution::Fixed {
                    width: bw,
                    height: bh,
                }
            } else {
                TargetResolution::Fixed {
                    width: aw,
                    height: ah,
                }
            }
        }
    }
}

/// Whether `hi` deviates from `lo` by at least `ratio`× (divisor space:
/// divisor 1 vs 4 = a 4× fps gap).
fn ratio_qualifies(lo: u32, hi: u32, ratio: u32) -> bool {
    hi >= lo.max(1).saturating_mul(ratio)
}

/// The registry (and its `pipeline_count()` spill-budget input) is
/// process-global, and cargo runs tests concurrently — a sibling test's live
/// pipeline would flip the budget gate mid-test. Every registry-touching test
/// holds this, in this module and elsewhere in the crate (FR-93 P6c's
/// `peer.rs` test builds a pipeline too). `unwrap_or_else(into_inner)`
/// un-poisons after a failed test so the rest still report their own results.
#[cfg(test)]
pub(crate) fn test_serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
// The SERIAL guard is deliberately held across awaits: it serializes whole
// tests against the process-global registry, and every await inside is a
// local Notify (no cross-test lock dependency → no deadlock).
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use bson::oid::ObjectId;

    use super::test_serial as serial;

    fn sink(session: ObjectId) -> FollowerSink {
        FollowerSink {
            session_id: session,
            video_bytes_dc: Arc::new(tokio::sync::Mutex::new(None)),
            control_dc: Arc::new(tokio::sync::Mutex::new(None)),
            keyframe_requested: Arc::new(AtomicBool::new(false)),
            target_resolution: Arc::new(Mutex::new(TargetResolution::Native)),
            quality_state: Arc::new(AtomicU8::new(2)),
            viewer_report: Arc::new(crate::encode::viewer_rate::ViewerFeedback::new()),
            priority: Arc::new(AtomicU8::new(1)),
            capture_native_dims: Arc::new(AtomicU64::new(0)),
            encoded_dims: Arc::new(AtomicU64::new(0)),
            chunk_framing: false,
        }
    }

    /// Unique keys per test — the registry is process-global and cargo runs
    /// tests concurrently, so tests share it. Vp9Dc's two chroma variants +
    /// distinct FfmpegDc labels give each test an isolated slot.
    #[tokio::test]
    async fn join_requires_a_registered_owner_and_owner_drop_detaches() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-A");
        assert!(
            try_join(key, sink(ObjectId::new()), 60).is_none(),
            "no owner yet"
        );

        let owner = Pipeline::register(key, ObjectId::new());
        let guard = try_join(key, sink(ObjectId::new()), 60).expect("join");
        assert_eq!(owner.follower_count(), 1);
        // Joining requested a pipeline IDR.
        assert!(owner.take_keyframe_requested());
        assert!(!owner.take_keyframe_requested(), "consumed");

        drop(owner);
        assert_eq!(guard.detached().await, DetachReason::PipelineClosed);
        // Registry slot is free again.
        assert!(registry().lock().unwrap().get(&key).is_none());
    }

    /// FR-93 P6c — the owner names its followers' sessions, and a follower
    /// that left is no longer named.
    #[tokio::test]
    async fn the_owner_names_its_followers_sessions() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-P6C-NAMES");
        let owner = Pipeline::register(key, ObjectId::new());
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let ga = try_join(key, sink(a), 60).expect("join a");
        let _gb = try_join(key, sink(b), 60).expect("join b");
        let mut named = owner.follower_sessions();
        named.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(named, want);
        drop(ga);
        assert_eq!(owner.follower_sessions(), vec![b]);
    }

    /// rc.443 — a joiner finding the owner's beat stale evicts the corpse
    /// and the key becomes ownable again (field: a driver-hung owner pump
    /// can never drop its `Pipeline`, so every viewer joined a dead
    /// pipeline until the daemon restarted).
    #[tokio::test]
    async fn stale_owner_is_evicted_and_key_becomes_ownable() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-STALE");
        let wedged = Pipeline::register(key, ObjectId::new());
        // A live follower on the corpse must be detached by the eviction.
        let orphan = try_join(key, sink(ObjectId::new()), 60).expect("join while fresh");

        wedged.force_stale();
        assert!(
            try_join(key, sink(ObjectId::new()), 60).is_none(),
            "stale owner must refuse the join (and evict)"
        );
        assert!(
            registry().lock().unwrap().get(&key).is_none(),
            "eviction must free the registry slot"
        );
        assert_eq!(orphan.detached().await, DetachReason::PipelineClosed);

        // The would-be joiner now registers as a fresh owner...
        let fresh = Pipeline::register(key, ObjectId::new());
        assert!(
            try_join(key, sink(ObjectId::new()), 60).is_some(),
            "fresh owner is joinable"
        );
        // ...and the wedged owner's LATE drop (driver call finally
        // returning) must NOT delete the fresh registration.
        drop(wedged);
        assert!(
            registry().lock().unwrap().get(&key).is_some(),
            "late drop of the evicted owner deleted the new registration"
        );
        drop(fresh);
        assert!(registry().lock().unwrap().get(&key).is_none());
    }

    /// rc.443 — a beating owner is never evicted: the staleness horizon
    /// only trips on genuine silence.
    #[tokio::test]
    async fn beating_owner_is_not_evicted() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-BEAT");
        let owner = Pipeline::register(key, ObjectId::new());
        owner.beat();
        assert!(
            try_join(key, sink(ObjectId::new()), 60).is_some(),
            "fresh beat must admit the join"
        );
        drop(owner);
    }

    #[tokio::test]
    async fn duplicate_owner_registration_runs_standalone() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-B");
        let first = Pipeline::register(key, ObjectId::new());
        let second = Pipeline::register(key, ObjectId::new());
        assert!(first.registered);
        assert!(!second.registered);
        // Standalone pipeline never sees followers; dropping it must NOT
        // free the first owner's registry slot.
        drop(second);
        assert!(registry().lock().unwrap().get(&key).is_some());
        drop(first);
        assert!(registry().lock().unwrap().get(&key).is_none());
    }

    #[tokio::test]
    async fn follower_guard_drop_leaves_the_pipeline() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-C");
        let owner = Pipeline::register(key, ObjectId::new());
        let guard = try_join(key, sink(ObjectId::new()), 60).expect("join");
        assert_eq!(owner.follower_count(), 1);
        drop(guard); // session teardown aborts the media task → guard drops
        assert_eq!(owner.follower_count(), 0);
    }

    #[tokio::test]
    async fn fan_out_gates_joiner_on_keyframe_then_streams() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-D");
        let owner = Pipeline::register(key, ObjectId::new());
        let _guard = try_join(key, sink(ObjectId::new()), 60).expect("join");

        let delta = bytes::Bytes::from_static(b"delta");
        let kf = bytes::Bytes::from_static(b"key");
        // Deltas before the first keyframe are skipped for the joiner.
        owner.fan_out(&delta, false, 0, 0);
        {
            let inner = owner.inner.lock().unwrap();
            assert!(!inner.followers[0].synced);
            assert_eq!(
                inner.followers[0].send_tx.capacity(),
                FOLLOWER_SEND_DEPTH,
                "no delta queued pre-sync"
            );
        }
        // The keyframe syncs and is forwarded; deltas flow after.
        owner.fan_out(&kf, true, 0, 0);
        owner.fan_out(&delta, false, 0, 0);
        let inner = owner.inner.lock().unwrap();
        assert!(inner.followers[0].synced);
        assert_eq!(
            inner.followers[0].send_tx.capacity(),
            FOLLOWER_SEND_DEPTH - 2,
            "kf + delta queued"
        );
    }

    #[tokio::test]
    async fn fan_out_full_queue_desyncs_and_requests_idr() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-E");
        let owner = Pipeline::register(key, ObjectId::new());
        let _guard = try_join(key, sink(ObjectId::new()), 60).expect("join");

        let kf = bytes::Bytes::from_static(b"key");
        let delta = bytes::Bytes::from_static(b"delta");
        owner.fan_out(&kf, true, 0, 0);
        // Fill the queue (chunker can't drain: DC handle is None → it parks
        // on recv, then discards; but we saturate faster than it drains by
        // never yielding to it inside this sync loop).
        for _ in 0..(FOLLOWER_SEND_DEPTH + 4) {
            owner.fan_out(&delta, false, 0, 0);
        }
        let inner = owner.inner.lock().unwrap();
        assert!(!inner.followers[0].synced, "overflow desyncs the follower");
        assert!(inner.kf_needed, "resync IDR requested");
    }

    #[tokio::test]
    async fn merges_take_the_floor() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-F");
        let owner = Pipeline::register(key, ObjectId::new());
        let s = sink(ObjectId::new());
        *s.target_resolution.lock().unwrap() = TargetResolution::Fixed {
            width: 1280,
            height: 720,
        };
        s.quality_state.store(0, Relaxed);
        let _g = try_join(key, s, 60).expect("join");

        // Resolution: the smaller area wins.
        let merged = owner.merged_target(TargetResolution::Fixed {
            width: 2560,
            height: 1440,
        });
        assert_eq!(
            merged,
            TargetResolution::Fixed {
                width: 1280,
                height: 720
            }
        );
        // Native owner + Fixed follower → the Fixed constraint.
        let merged = owner.merged_target(TargetResolution::Native);
        assert_eq!(
            merged,
            TargetResolution::Fixed {
                width: 1280,
                height: 720
            }
        );
        // Quality: min.
        assert_eq!(owner.min_quality(2), 0);
    }

    /// FR-119 P2b-2 — the frame-rate ask merges to the smallest, and a viewer
    /// that asked nothing holds the stream at today's rate.
    #[tokio::test]
    async fn the_frame_rate_ask_takes_the_floor() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-FPS");
        let owner = Pipeline::register(key, ObjectId::new());
        assert_eq!(owner.merged_fps_ask(Some(144)), Some(144), "alone");
        let s = sink(ObjectId::new());
        let follower_report = s.viewer_report.clone();
        let _g = try_join(key, s, 60).expect("join");
        assert_eq!(owner.merged_fps_ask(Some(144)), None, "it asked nothing");
        follower_report.store_fps_ask(120);
        assert_eq!(owner.merged_fps_ask(Some(144)), Some(120));
        assert_eq!(owner.merged_fps_ask(None), None);
    }

    // P8 Phase 4 — the mixed-dial predicate: false with no followers,
    // false when everyone matches the owner, true on either a Priority
    // or a resolution-pick divergence.
    #[tokio::test]
    async fn dials_mixed_detects_any_divergence() {
        let _s = serial();
        use crate::encode::priority::{BALANCED, SMOOTHER};
        let key = PipelineKey::FfmpegDc("TEST-MIXED");
        let owner = Pipeline::register(key, ObjectId::new());
        assert!(
            !owner.dials_mixed(BALANCED, TargetResolution::Native),
            "no followers = nothing shared, nothing mixed"
        );

        let s = sink(ObjectId::new());
        s.priority.store(BALANCED, Relaxed);
        let _g = try_join(key, s, 60).expect("join");
        assert!(
            !owner.dials_mixed(BALANCED, TargetResolution::Native),
            "identical dials are not mixed"
        );
        assert!(
            owner.dials_mixed(SMOOTHER, TargetResolution::Native),
            "priority divergence is mixed"
        );
        assert!(
            owner.dials_mixed(
                BALANCED,
                TargetResolution::Fixed {
                    width: 1280,
                    height: 720
                }
            ),
            "resolution-pick divergence is mixed"
        );
    }

    #[tokio::test]
    async fn step_viewer_windows_returns_max_follower_divisor() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-G");
        let owner = Pipeline::register(key, ObjectId::new());
        let s = sink(ObjectId::new());
        let report = s.viewer_report.clone();
        let _g = try_join(key, s, 60).expect("join");

        // The follower reports a struggling 20 fps decode → its controller
        // caps below 20 → divisor > 1. Owner's divisor 1 → max wins.
        report.store_report(crate::encode::viewer_rate::pack_report(20, true));
        let div = owner.step_viewer_windows(1, 60);
        assert!(
            div > 1,
            "struggling follower must raise the shared divisor, got {div}"
        );
    }

    #[tokio::test]
    async fn spill_evicts_the_deviant_follower_after_sustained_windows() {
        let _s = serial();
        let key = PipelineKey::FfmpegDc("TEST-H");
        let owner = Pipeline::register(key, ObjectId::new());
        let s = sink(ObjectId::new());
        let report = s.viewer_report.clone();
        let guard = try_join(key, s, 60).expect("join");

        // Drive the follower to the floor divisor (cap 12 → divisor 5 at 60)
        // while the owner stays at divisor 1 → ratio 5 ≥ SPILL_RATIO.
        for _ in 0..SPILL_AFTER_WINDOWS + 6 {
            report.store_report(crate::encode::viewer_rate::pack_report(5, true));
            owner.step_viewer_windows(1, 60);
        }
        assert_eq!(owner.follower_count(), 0, "deviant follower spilled");
        assert_eq!(guard.detached().await, DetachReason::Spilled);
    }

    #[tokio::test]
    async fn spill_respects_the_pipeline_budget() {
        let _s = serial();
        // Two pipelines registered = budget exhausted → no spilling even
        // under sustained deviation.
        let key = PipelineKey::FfmpegDc("TEST-I");
        let other = Pipeline::register(PipelineKey::FfmpegDc("TEST-I2"), ObjectId::new());
        let owner = Pipeline::register(key, ObjectId::new());
        let s = sink(ObjectId::new());
        let report = s.viewer_report.clone();
        let _g = try_join(key, s, 60).expect("join");

        for _ in 0..SPILL_AFTER_WINDOWS * 2 {
            report.store_report(crate::encode::viewer_rate::pack_report(5, true));
            owner.step_viewer_windows(1, 60);
        }
        assert_eq!(
            owner.follower_count(),
            1,
            "budget-capped pipeline keeps the slow viewer (floor holds)"
        );
        drop(other);
    }

    /// P7b — the merge-aware refine-eligibility decision table. Every
    /// cap-contributing dial must be refine-applicable; no-cap dials
    /// (Sharper anywhere; Balanced on direct) never block.
    ///
    /// Env hygiene: `idle_refine_applies` consults
    /// ROOMLERD_IDLE_REFINE_BALANCED for the Balanced rows — cleared
    /// up front so the table asserts the DEFAULT (ON since P7c) semantics,
    /// then set to "0" for the blocked-Balanced rows and removed again
    /// before the serial guard drops. (The env flip itself is locked by
    /// `encode::tests::idle_refine_applies_matrix`; that test restores the
    /// var after itself, so the cross-module interleaving window is µs.)
    #[tokio::test]
    async fn merged_refine_eligible_decision_table() {
        let _s = serial();
        // rc.445 — the dial caps (and with them this whole merge) exist
        // only behind the restore switch now; hold the shared env lock
        // since `encode::tests` also toggles this var.
        let _env = crate::encode::RELAY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // SAFETY: same contract as the sibling env-clearing tests.
        unsafe {
            tunnel_core::env::test_env::clear("IDLE_REFINE_BALANCED");
            tunnel_core::env::test_env::set_as("ROOMLERD_", "PRIORITY_RES_CAP", "1");
        }
        use crate::encode::priority::{BALANCED, SHARPER, SMOOTHER};
        let key = PipelineKey::FfmpegDc("TEST-REFINE");
        let owner = Pipeline::register(key, ObjectId::new());

        // Single viewer reduces to idle_refine_applies(own): Smoother
        // refines, Sharper is vacuously eligible (no cap — the caller's
        // merged-cap-clamps gate is what makes it a no-op), and since P7c
        // Balanced's B1 relay cap is liftable by default too.
        assert!(owner.merged_refine_eligible(SMOOTHER, true));
        assert!(owner.merged_refine_eligible(SMOOTHER, false));
        assert!(owner.merged_refine_eligible(SHARPER, true));
        assert!(owner.merged_refine_eligible(BALANCED, true));
        assert!(owner.merged_refine_eligible(BALANCED, false));

        // THE field case (winhost-b 2026-08-20): owner=Sharper +
        // follower=Smoother — the follower's liftable cap clamps, Sharper
        // contributes none ⇒ eligible.
        let s = sink(ObjectId::new());
        let follower_prio = s.priority.clone();
        follower_prio.store(SMOOTHER, std::sync::atomic::Ordering::Relaxed);
        let guard = try_join(key, s, 60).expect("join");
        assert!(owner.merged_refine_eligible(SHARPER, true));
        assert!(owner.merged_refine_eligible(SHARPER, false));

        // With the Balanced kill switch thrown, a Balanced dial's relay cap
        // is NOT liftable: single-viewer Balanced blocks, and a Smoother
        // owner + Balanced follower blocks on relay; on direct Balanced
        // contributes no cap ⇒ eligible either way.
        unsafe { tunnel_core::env::test_env::set_as("ROOMLERD_", "IDLE_REFINE_BALANCED", "0") };
        follower_prio.store(BALANCED, std::sync::atomic::Ordering::Relaxed);
        assert!(!owner.merged_refine_eligible(SMOOTHER, true));
        assert!(owner.merged_refine_eligible(SMOOTHER, false));
        assert!(!owner.merged_refine_eligible(BALANCED, true));
        unsafe { tunnel_core::env::test_env::clear("IDLE_REFINE_BALANCED") };

        // Default-on: the same mixed pair is eligible on relay too.
        assert!(owner.merged_refine_eligible(SMOOTHER, true));

        // Back to an all-liftable pair.
        follower_prio.store(SMOOTHER, std::sync::atomic::Ordering::Relaxed);
        assert!(owner.merged_refine_eligible(SMOOTHER, true));

        // Follower leaves → single-viewer semantics return.
        drop(guard);
        assert_eq!(owner.follower_count(), 0);
        assert!(owner.merged_refine_eligible(SHARPER, true));
        drop(owner);
        // rc.445 default (caps off): nothing can block — eligibility is
        // vacuous, matching the caller's capped_below_native=false gate.
        unsafe { tunnel_core::env::test_env::clear("PRIORITY_RES_CAP") };
        let owner = Pipeline::register(key, ObjectId::new());
        assert!(owner.merged_refine_eligible(SMOOTHER, true));
        assert!(owner.merged_refine_eligible(BALANCED, true));
        drop(owner);
    }

    #[test]
    fn ratio_and_target_helpers() {
        assert!(ratio_qualifies(1, 4, 4));
        assert!(!ratio_qualifies(1, 3, 4));
        assert!(ratio_qualifies(2, 8, 4));
        assert!(!ratio_qualifies(0, 0, 2));

        let a = TargetResolution::Fixed {
            width: 1920,
            height: 1080,
        };
        let b = TargetResolution::Fixed {
            width: 1280,
            height: 720,
        };
        assert_eq!(smaller_target(a, b), b);
        assert_eq!(smaller_target(b, a), b);
        assert_eq!(smaller_target(TargetResolution::Native, a), a);
        assert_eq!(
            smaller_target(TargetResolution::Native, TargetResolution::Native),
            TargetResolution::Native
        );
    }
}
