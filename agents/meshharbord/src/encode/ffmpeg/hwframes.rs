// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD

//! FR-77 P4 / FR-78 P1 — the hardware device and frame contexts the
//! `*_vaapi`, `*_d3d12va` and `*_vulkan` encoders need, which nothing else
//! in the cascade does.
//!
//! NVENC, QSV and AMF open their own device behind the encoder; these three
//! take hardware frames (`AV_PIX_FMT_VAAPI` / `AV_PIX_FMT_D3D12` /
//! `AV_PIX_FMT_VULKAN`) from an `AVHWFramesContext` bound to an
//! `AVHWDeviceContext`, so the pump has to (1) open a device, (2) allocate
//! a frame pool in the encoder's software format (NV12, or the 4:4:4 form),
//! and (3) upload every software frame into that pool before `send_frame`.
//! ffmpeg-next 9 wraps none of this, hence the raw `ffmpeg_sys_next` calls,
//! each one bounded to this file. The sequence is the SAME for all three
//! device types — only the device candidates differ:
//!
//! | kind | opens | candidates, in order |
//! |---|---|---|
//! | VAAPI (Linux) | a DRM render node | pinned `vaapi_device`, then `/dev/dri/renderD128`…`135` that exist |
//! | D3D12 (Windows) | a DXGI adapter by index | pinned `d3d12_adapter`, then `0`…`3` |
//! | Vulkan (Linux, Windows) | a physical device by index or name | pinned `vulkan_device`, then `0`…`3` |
//!
//! Each candidate device is opened lazily and ONCE per process and kept;
//! which device an encoder lands on is decided by its OPEN
//! (`open_on_some_device`: the preferred device first, then the rest), because
//! that is a per-codec, per-driver fact — on a two-GPU laptop device 0 is the
//! iGPU, which may lack the codec (no AV1 on an RDNA2 iGPU) or the video-encode
//! queue altogether (measured: the dev box's Vulkan device 0 had no
//! `VK_KHR_video_encode_queue`, the RTX did). The winner is remembered, so a
//! session lands where the probe proved. A kind with no usable device says so
//! once and every name of that kind fails in one line; the cascade moves on.
//! Both D3D12 and Vulkan are dlopen'd by FFmpeg itself (`d3d12.dll` /
//! `vulkan-1.dll` / `libvulkan.so.1`), so a host without them loses cells,
//! never the daemon.
//!
//! `/dev/dxg` (WSL2's GPU device) is deliberately NOT a VAAPI candidate,
//! measured 2026-09-08: a WSL2 distro has no `/dev/dri` at all, `/dev/dxg` is
//! a misc-major node (10:125), and libva's DRM display refuses anything that
//! is not a DRM-major character device with nothing but an `fstat`.

use anyhow::{Result, anyhow};
use ffmpeg_next::frame;
use ffmpeg_next::sys as ff;

/// The three hardware-frame backends, keyed by the FFmpeg encoder name's
/// suffix. `None` = a software-frame encoder (NVENC, QSV, AMF, VideoToolbox
/// take NV12 / planar / packed frames straight from the pump).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HwKind {
    Vaapi,
    D3d12,
    Vulkan,
}

impl HwKind {
    pub(crate) fn of(name: &str) -> Option<Self> {
        if name.ends_with("_vaapi") {
            Some(Self::Vaapi)
        } else if name.ends_with("_d3d12va") {
            Some(Self::D3d12)
        } else if name.ends_with("_vulkan") {
            Some(Self::Vulkan)
        } else {
            None
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Vaapi => "vaapi",
            Self::D3d12 => "d3d12",
            Self::Vulkan => "vulkan",
        }
    }

    // The stub (macOS) never opens a device, so these are dead there.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    fn hw_type(self) -> ff::AVHWDeviceType {
        match self {
            Self::Vaapi => ff::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
            Self::D3d12 => ff::AVHWDeviceType::AV_HWDEVICE_TYPE_D3D12VA,
            Self::Vulkan => ff::AVHWDeviceType::AV_HWDEVICE_TYPE_VULKAN,
        }
    }

    /// The hardware pixel format the encoder is opened with (the pool's
    /// `format`); the pool's `sw_format` carries the real layout.
    pub(crate) fn pixel(self) -> ff::AVPixelFormat {
        match self {
            Self::Vaapi => ff::AVPixelFormat::AV_PIX_FMT_VAAPI,
            Self::D3d12 => ff::AVPixelFormat::AV_PIX_FMT_D3D12,
            Self::Vulkan => ff::AVPixelFormat::AV_PIX_FMT_VULKAN,
        }
    }

    /// The frame pool's software format: what the pump uploads. 4:4:4 is
    /// packed VUYX on VAAPI (FFmpeg n9's VAAPI encoders list VUYX, never
    /// planar) and planar `yuv444p` on Vulkan (the driver's format list is
    /// consulted at open); D3D12 video encode is 4:2:0 only (NV12 / P010),
    /// so it is never asked for 4:4:4 and takes NV12 regardless.
    pub(crate) fn sw_format(self, chroma444: bool) -> ff::AVPixelFormat {
        match (self, chroma444) {
            (Self::Vaapi, true) => ff::AVPixelFormat::AV_PIX_FMT_VUYX,
            (Self::Vulkan, true) => ff::AVPixelFormat::AV_PIX_FMT_YUV444P,
            _ => ff::AVPixelFormat::AV_PIX_FMT_NV12,
        }
    }

    /// Whether this backend's 4:4:4 input is the packed VUYX layout (the
    /// pump then interleaves the planes) rather than planar `yuv444p`.
    pub(crate) fn packed444(self) -> bool {
        matches!(self, Self::Vaapi)
    }

    /// The device strings to try, in order. `pinned` is the kind's config
    /// key; `exists` answers for a path so the VAAPI order is testable
    /// without a `/dev`. A `None` entry = "let FFmpeg pick" (Vulkan's
    /// default device).
    // The stub (macOS) never opens a device, so these are dead there.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    pub(crate) fn candidates(
        self,
        pinned: Option<&str>,
        exists: &dyn Fn(&str) -> bool,
    ) -> Vec<Option<String>> {
        if let Some(p) = pinned.map(str::trim).filter(|p| !p.is_empty()) {
            return vec![Some(p.to_string())];
        }
        match self {
            Self::Vaapi => (128..=135)
                .map(|n| format!("/dev/dri/renderD{n}"))
                .filter(|p| exists(p))
                .map(Some)
                .collect(),
            // Both by index, 0..3: on a two-GPU laptop device 0 is the iGPU
            // and the dGPU is 1 — the open decides which one can encode
            // (`open_on_some_device`), so every index is a candidate.
            Self::D3d12 | Self::Vulkan => (0..=3).map(|n| Some(n.to_string())).collect(),
        }
    }

    /// The config key (as the `ROOMLERD_*` suffix) that pins this kind's
    /// device.
    // The stub (macOS) never opens a device, so these are dead there.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    pub(crate) fn pin_key(self) -> &'static str {
        match self {
            Self::Vaapi => "VAAPI_DEVICE",
            Self::D3d12 => "D3D12_ADAPTER",
            Self::Vulkan => "VULKAN_DEVICE",
        }
    }

    /// Which kinds this OS can open at all. The other kinds' names fail in
    /// one line before any FFI: VAAPI is Linux's, D3D12 is Windows's, Vulkan
    /// is both (macOS is VideoToolbox's, and its FFmpeg tree carries none).
    // The stub (macOS) never opens a device, so these are dead there.
    #[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
    pub(crate) fn supported_here(self) -> bool {
        match self {
            Self::Vaapi => cfg!(target_os = "linux"),
            Self::D3d12 => cfg!(target_os = "windows"),
            Self::Vulkan => cfg!(any(target_os = "linux", target_os = "windows")),
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
pub(crate) fn pinned_device(kind: HwKind) -> Option<String> {
    tunnel_core::env::node_env(kind.pin_key()).filter(|v| !v.trim().is_empty())
}

/// FFmpeg's error text for a negative return.
#[allow(dead_code)]
fn ff_err(rc: i32) -> String {
    let mut buf = [0u8; 128];
    // SAFETY: fixed-size buffer, FFmpeg NUL-terminates within it.
    unsafe {
        ff::av_strerror(rc, buf.as_mut_ptr() as *mut std::os::raw::c_char, buf.len());
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    format!("{} ({})", String::from_utf8_lossy(&buf[..end]), rc)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod real {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    /// A process-wide hardware device: an `AVBufferRef` to the
    /// `AVHWDeviceContext`. The candidate it was opened on is logged at open;
    /// nothing reads it afterwards, so it is not kept.
    pub(crate) struct Device {
        buf: *mut ff::AVBufferRef,
    }
    // SAFETY: the device context is reference-counted and thread-safe to
    // share by FFmpeg's contract (every hwframes ctx takes its own ref); the
    // pointer is never mutated after creation.
    unsafe impl Send for Device {}
    unsafe impl Sync for Device {}

    /// One candidate device of a kind: opened lazily, once, and kept for
    /// the process (a device that failed to open stays failed — the
    /// hardware does not change under a running daemon).
    struct Slot {
        cand: Option<String>,
        state: SlotState,
    }

    enum SlotState {
        Untried,
        Failed,
        Open(Arc<Device>),
    }

    struct Kind {
        slots: Mutex<Vec<Slot>>,
        /// The index of the device the last successful open used: tried
        /// first next time, so a session lands on the device the probe
        /// proved without re-walking the failures.
        preferred: AtomicUsize,
    }

    static VAAPI: OnceLock<Kind> = OnceLock::new();
    static D3D12: OnceLock<Kind> = OnceLock::new();
    static VULKAN: OnceLock<Kind> = OnceLock::new();

    fn kind_state(kind: HwKind) -> &'static Kind {
        let slot = match kind {
            HwKind::Vaapi => &VAAPI,
            HwKind::D3d12 => &D3D12,
            HwKind::Vulkan => &VULKAN,
        };
        slot.get_or_init(|| {
            let exists = |p: &str| std::path::Path::new(p).exists();
            let cands = if kind.supported_here() {
                kind.candidates(pinned_device(kind).as_deref(), &exists)
            } else {
                Vec::new()
            };
            if cands.is_empty() {
                tracing::info!(
                    backend = kind.label(),
                    "hwframes: no device candidate on this host — no cells for this backend"
                );
            }
            Kind {
                slots: Mutex::new(
                    cands
                        .into_iter()
                        .map(|cand| Slot {
                            cand,
                            state: SlotState::Untried,
                        })
                        .collect(),
                ),
                preferred: AtomicUsize::new(0),
            }
        })
    }

    /// Run `open` against the kind's candidate devices — the preferred one
    /// first, then the rest in order — until it succeeds. Each device is
    /// opened lazily and once; each failure (of the device, or of `open` on
    /// it) is logged and the next candidate tried. The error of the last
    /// attempt comes back when none worked.
    ///
    /// Why the OPEN decides and not the device: which physical device can
    /// run a given encoder is a per-codec, per-driver fact (an RDNA2 iGPU
    /// has HEVC but no AV1; a Vulkan device may lack the video-encode
    /// queue entirely), and the only honest probe of it is the encoder's
    /// own open.
    pub(crate) fn open_on_some_device<T>(
        kind: HwKind,
        mut open: impl FnMut(&Device) -> Result<T>,
    ) -> Result<T> {
        let state = kind_state(kind);
        let n = state.slots.lock().unwrap_or_else(|e| e.into_inner()).len();
        if n == 0 {
            return Err(anyhow!("no {} device on this host", kind.label()));
        }
        let start = state.preferred.load(Ordering::Relaxed) % n;
        let mut last_err: Option<anyhow::Error> = None;
        for step in 0..n {
            let idx = (start + step) % n;
            let (cand, dev) = {
                let mut slots = state.slots.lock().unwrap_or_else(|e| e.into_inner());
                let slot = &mut slots[idx];
                if let SlotState::Untried = slot.state {
                    slot.state = match open_device(kind, slot.cand.as_deref()) {
                        Ok(buf) => {
                            tracing::info!(
                                backend = kind.label(),
                                device = slot.cand.as_deref().unwrap_or("(default)"),
                                "hwframes: device opened"
                            );
                            SlotState::Open(Arc::new(Device { buf }))
                        }
                        Err(e) => {
                            tracing::info!(
                                backend = kind.label(),
                                device = slot.cand.as_deref().unwrap_or("(default)"),
                                %e,
                                "hwframes: device did not open"
                            );
                            SlotState::Failed
                        }
                    };
                }
                match &slot.state {
                    SlotState::Open(dev) => (slot.cand.clone(), Arc::clone(dev)),
                    _ => continue,
                }
            };
            match open(&dev) {
                Ok(v) => {
                    if state.preferred.swap(idx, Ordering::Relaxed) != idx {
                        tracing::info!(
                            backend = kind.label(),
                            device = cand.as_deref().unwrap_or("(default)"),
                            "hwframes: encoder opened on this device — preferred from now on"
                        );
                    }
                    return Ok(v);
                }
                Err(e) => {
                    tracing::debug!(
                        backend = kind.label(),
                        device = cand.as_deref().unwrap_or("(default)"),
                        %e,
                        "hwframes: open failed on this device — trying the next"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no {} device opened on this host", kind.label())))
    }

    fn open_device(kind: HwKind, device: Option<&str>) -> Result<*mut ff::AVBufferRef> {
        let c = device
            .map(|d| CString::new(d).map_err(|_| anyhow!("device string has a NUL")))
            .transpose()?;
        let mut buf: *mut ff::AVBufferRef = std::ptr::null_mut();
        // SAFETY: `buf` is a valid out-pointer, `c` outlives the call (a
        // null device string means "default"), no options dict, no flags.
        // On failure FFmpeg leaves `buf` null.
        let rc = unsafe {
            ff::av_hwdevice_ctx_create(
                &mut buf,
                kind.hw_type(),
                c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 || buf.is_null() {
            return Err(anyhow!(
                "av_hwdevice_ctx_create({}, {}) failed: {}",
                kind.label(),
                device.unwrap_or("default"),
                ff_err(rc)
            ));
        }
        Ok(buf)
    }

    /// One encoder's frame pool on a shared device.
    pub(crate) struct Frames {
        buf: *mut ff::AVBufferRef,
    }
    // SAFETY: the frames context is reference-counted; the encoder that
    // owns this handle is the only user of the pool from the media thread.
    unsafe impl Send for Frames {}

    impl Frames {
        pub(crate) fn new(
            dev: &Device,
            kind: HwKind,
            sw_format: ff::AVPixelFormat,
            width: u32,
            height: u32,
        ) -> Result<Self> {
            // SAFETY: `dev.buf` is a live device ref; the returned buffer's
            // data IS an AVHWFramesContext by FFmpeg's contract.
            let buf = unsafe { ff::av_hwframe_ctx_alloc(dev.buf) };
            if buf.is_null() {
                return Err(anyhow!("av_hwframe_ctx_alloc failed"));
            }
            // SAFETY: as above; the fields are plain ints/enums set before
            // init, exactly as `ffmpeg -init_hw_device` does.
            let rc = unsafe {
                let ctx = (*buf).data as *mut ff::AVHWFramesContext;
                (*ctx).format = kind.pixel();
                (*ctx).sw_format = sw_format;
                (*ctx).width = width as i32;
                (*ctx).height = height as i32;
                // A generous pool: the pump holds at most a handful in
                // flight (async_depth=1), the rest is headroom for the
                // driver's own reordering.
                (*ctx).initial_pool_size = 20;
                ff::av_hwframe_ctx_init(buf)
            };
            if rc < 0 {
                let mut b = buf;
                // SAFETY: unref the buffer we own; sets it null.
                unsafe { ff::av_buffer_unref(&mut b) };
                return Err(anyhow!(
                    "av_hwframe_ctx_init({}) failed: {}",
                    kind.label(),
                    ff_err(rc)
                ));
            }
            Ok(Self { buf })
        }

        /// A NEW reference for an encoder's `hw_frames_ctx` (the codec
        /// context unrefs it when it is freed).
        pub(crate) fn new_ref(&self) -> *mut ff::AVBufferRef {
            // SAFETY: `self.buf` is live for as long as `self`.
            unsafe { ff::av_buffer_ref(self.buf) }
        }

        /// Upload one software frame (NV12 / VUYX / yuv444p, pts + pict_type
        /// set) into a pool frame the encoder accepts. `copy_props` carries
        /// the pts and the forced-I picture type across.
        pub(crate) fn upload(&self, sw: &frame::Video) -> Result<frame::Video> {
            let mut hw = frame::Video::empty();
            // SAFETY: `hw` is an empty AVFrame we own; the pool hands it a
            // hardware surface; `sw` is a fully populated software frame.
            unsafe {
                let rc = ff::av_hwframe_get_buffer(self.buf, hw.as_mut_ptr(), 0);
                if rc < 0 {
                    return Err(anyhow!("av_hwframe_get_buffer failed: {}", ff_err(rc)));
                }
                let rc = ff::av_hwframe_transfer_data(hw.as_mut_ptr(), sw.as_ptr(), 0);
                if rc < 0 {
                    return Err(anyhow!("av_hwframe_transfer_data failed: {}", ff_err(rc)));
                }
                let rc = ff::av_frame_copy_props(hw.as_mut_ptr(), sw.as_ptr());
                if rc < 0 {
                    return Err(anyhow!("av_frame_copy_props failed: {}", ff_err(rc)));
                }
            }
            Ok(hw)
        }
    }

    impl Drop for Frames {
        fn drop(&mut self) {
            // SAFETY: we own exactly one ref; unref sets the pointer null.
            unsafe { ff::av_buffer_unref(&mut self.buf) };
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[allow(unused_imports)]
pub(crate) use real::{Device, Frames, open_on_some_device};

/// macOS: no hardware-frame backend at all (its FFmpeg tree carries only
/// VideoToolbox, which takes software frames). The types exist so the
/// encoder's code has ONE shape everywhere.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod stub {
    use super::*;

    pub(crate) struct Device;

    pub(crate) fn open_on_some_device<T>(
        kind: HwKind,
        _open: impl FnMut(&Device) -> Result<T>,
    ) -> Result<T> {
        Err(anyhow!(
            "no {} device on this host (hardware frames are Linux/Windows-only)",
            kind.label()
        ))
    }

    pub(crate) struct Frames;

    impl Frames {
        pub(crate) fn new(
            _dev: &Device,
            _kind: HwKind,
            _sw: ff::AVPixelFormat,
            _w: u32,
            _h: u32,
        ) -> Result<Self> {
            Err(anyhow!("hardware frames are Linux/Windows-only"))
        }
        pub(crate) fn new_ref(&self) -> *mut ff::AVBufferRef {
            std::ptr::null_mut()
        }
        pub(crate) fn upload(&self, _sw: &frame::Video) -> Result<frame::Video> {
            Err(anyhow!("hardware frames are Linux/Windows-only"))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[allow(unused_imports)]
pub(crate) use stub::{Device, Frames, open_on_some_device};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_follow_the_name_suffix() {
        assert_eq!(HwKind::of("hevc_vaapi"), Some(HwKind::Vaapi));
        assert_eq!(HwKind::of("h264_d3d12va"), Some(HwKind::D3d12));
        assert_eq!(HwKind::of("av1_vulkan"), Some(HwKind::Vulkan));
        assert_eq!(HwKind::of("hevc_nvenc"), None);
        assert_eq!(HwKind::of("hevc_videotoolbox"), None);
        assert_eq!(HwKind::of("vp9_qsv"), None);
    }

    /// The pin wins outright; otherwise VAAPI walks the render nodes in
    /// numeric order (only the ones that exist, never `/dev/dxg`), D3D12
    /// walks adapter indices 0–3, and Vulkan hands FFmpeg the default.
    #[test]
    fn candidates_per_kind() {
        let all = |_: &str| true;
        assert_eq!(
            HwKind::Vaapi.candidates(Some(" /dev/dri/renderD129 "), &all),
            vec![Some("/dev/dri/renderD129".to_string())]
        );
        assert_eq!(
            HwKind::Vaapi
                .candidates(Some("  "), &all)
                .first()
                .cloned()
                .flatten(),
            Some("/dev/dri/renderD128".to_string()),
            "a blank pin is no pin"
        );
        let v = HwKind::Vaapi.candidates(None, &all);
        assert_eq!(v.len(), 8);
        assert_eq!(v[7].as_deref(), Some("/dev/dri/renderD135"));
        assert!(!v.iter().flatten().any(|p| p.contains("dxg")));
        let wsl = |p: &str| p == "/dev/dxg";
        assert!(HwKind::Vaapi.candidates(None, &wsl).is_empty());

        let d = HwKind::D3d12.candidates(None, &all);
        assert_eq!(d.len(), 4);
        assert_eq!(d[0].as_deref(), Some("0"));
        assert_eq!(
            HwKind::D3d12.candidates(Some("1"), &all),
            vec![Some("1".to_string())]
        );

        assert_eq!(HwKind::Vulkan.candidates(None, &all).len(), 4);
        assert_eq!(
            HwKind::Vulkan.candidates(Some("NVIDIA GeForce RTX 5090"), &all),
            vec![Some("NVIDIA GeForce RTX 5090".to_string())]
        );
    }

    #[test]
    fn the_pool_format_follows_the_kind_and_the_chroma() {
        assert_eq!(
            HwKind::Vaapi.sw_format(false),
            ff::AVPixelFormat::AV_PIX_FMT_NV12
        );
        assert_eq!(
            HwKind::Vaapi.sw_format(true),
            ff::AVPixelFormat::AV_PIX_FMT_VUYX
        );
        assert_eq!(
            HwKind::Vulkan.sw_format(true),
            ff::AVPixelFormat::AV_PIX_FMT_YUV444P
        );
        assert_eq!(
            HwKind::D3d12.sw_format(true),
            ff::AVPixelFormat::AV_PIX_FMT_NV12,
            "D3D12 video encode is 4:2:0 only — never asked, never packed"
        );
        assert!(HwKind::Vaapi.packed444());
        assert!(!HwKind::Vulkan.packed444());
        assert!(!HwKind::D3d12.packed444());
    }

    #[test]
    fn each_kind_has_its_os() {
        assert_eq!(HwKind::Vaapi.supported_here(), cfg!(target_os = "linux"));
        assert_eq!(HwKind::D3d12.supported_here(), cfg!(target_os = "windows"));
        assert_eq!(
            HwKind::Vulkan.supported_here(),
            cfg!(any(target_os = "linux", target_os = "windows"))
        );
        assert_eq!(HwKind::Vaapi.pin_key(), "VAAPI_DEVICE");
        assert_eq!(HwKind::D3d12.pin_key(), "D3D12_ADAPTER");
        assert_eq!(HwKind::Vulkan.pin_key(), "VULKAN_DEVICE");
    }
}
