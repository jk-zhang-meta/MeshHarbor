# FR-118: GPU-resident frames — a captured frame stays on the GPU until the encoder takes it

**Issue:** [#2669](https://github.com/gjovanov/roomler-ai/issues/2669) · **Status:** proposed 2026-10-21 —
spec and claim · **Owner:** the agent's capture and encode path · **Anchors:** master `c636c6e8c` ·
**Program:** [StarDesk teardown](../plans/stardesk-teardown-program.md), wave 2 ("zero-copy") ·
**Builds on:** [FR-70](FR-70-media-pipeline-leaves-the-runtime.md) (the encoder thread, M1),
[FR-77](FR-77-encoder-chroma-matrix.md) (cells and the probe), [FR-107](FR-107-drm-capture-throughput.md)
(the DRM arm's GPU path), [FR-16](FR-16-rc-quality-benchmark.md) / [FR-98](FR-98-input-to-photon-budget.md)
(L0 and L4) · **Unblocks:** [FR-119](FR-119-high-refresh-streaming.md) above 60 fps

## 1. Goal

On a host whose screen and hardware encoder share a GPU, a captured frame goes from the capture surface to
the encoder **without leaving the GPU**. Scaling and the BGRA → NV12 conversion happen on the GPU, and the
encoder takes the GPU surface. A frame is read back into CPU memory only when something that runs on the
CPU asks for it.

Today every hardware-encoded frame makes a round trip. The capture backend copies the GPU surface into
system memory, the pump converts it to NV12 on the CPU, and the encoder copies it back onto the GPU (§2).
StarDesk advertises a "Zero-Copy pipeline". The question for us is narrower and measurable: **how much of
each frame's time is that round trip, on the encoders the fleet actually runs?** The pump's heartbeat
cannot answer it yet (§3), so P0 measures before anything is built.

## 2. Evidence

### 2.1 Where the copies happen (master `c636c6e8c`)

| Step | Where | What it costs |
|---|---|---|
| WGC reads every arrived frame back, **inside `FrameArrived`**, before the latest-wins slot | `capture/wgc_backend.rs:610` → `copy_to_cpu` `:771` (`CopyResource` `:804`, then a synchronous `Map` and a row copy into a `Vec`) | A GPU → CPU copy plus a CPU stall per frame, including frames the slot then drops |
| WGC's D3D11 device is on the **default adapter** | `create_d3d11_device` `wgc_backend.rs:729`, `None` at `:740` ("defer until that's a real field issue") | Which GPU holds the frames is not decided by anyone |
| The SystemContext DXGI arm reads back too, and its device is bound to the adapter that **owns the output** | `system_context/dxgi_direct.rs:366` (`find_primary_output` `:1071`); `read_acquired` `:861`; its Phase B GPU scale still ends in a readback (`vp_blt_and_read` `:702`) | Desktop Duplication cannot cross adapters (`E_INVALIDARG`), so on that arm the capture adapter is fixed |
| `Frame` owns a `Vec<u8>` | `capture/mod.rs:85`, `data` at `:90`; `PixelFormat` is `Bgra`, `Nv12` or `I420` (`:281`) | The contract has no way to say "this frame is on the GPU" |
| The pump converts BGRA → NV12 (or I444) **on the CPU**, BT.601 limited range | `FfmpegEncoder::convert_bgra` `encode/ffmpeg/encoder.rs:1814` (dcv, banded threads above 2 MP); the matrix is `encode/color.rs:16` | Per-pixel CPU work on every frame |
| …then copies the planes into an `AVFrame`, uploads it for the VAAPI / D3D12 / Vulkan encoders, and submits | `encode_sync` `encoder.rs:2386`; `HwKind` `encode/ffmpeg/hwframes.rs:50` (those three kinds only) | The VAAPI, D3D12 and Vulkan cells make the full GPU → CPU → GPU round trip in our code; NVENC, QSV and AMF do the upload inside `send_frame` |
| The portal arm copies twice | `capture/portal/pipewire.rs:806` (out of the PipeWire buffer), then the helper's stdout into the daemon (`capture/portal/wire.rs`, which argues for exactly this as a first version); a DmaBuf buffer is reported, never read | Two CPU copies, by design until a measurement says otherwise |
| macOS copies the `CGDisplayStream` surface into the `Vec` | `capture/scrap_backend.rs` (the vendored scrap's quartz arm) | One copy per frame |

### 2.2 What the fleet measures today (7 days to 2026-10-21, read-only)

From `agent_logs`: 142 538 FFmpeg DC pump heartbeats from 11 hosts, read-only, from mars. The "encode"
column is the pump's `avg_encode_ms` (`peer.rs:9499`): the time inside `encode_sync`, so **conversion,
copies, upload, submission and the packet drain together** (§3). The fps columns are the delivered rate
between consecutive heartbeats (spaced 2.0 s). The median sits at 16–17 fps on almost every host because an
idle desktop produces few frames, which is not a limit. So the table shows the top of the distribution, p99
and max, and how many windows reached 50 fps.

| Encoder | Encode geometry | Windows | Encode ms (median / p90) | fps p99 / max (60 targeted) | Windows ≥ 50 fps |
|---|---|---|---|---|---|
| `hevc_qsv` | 1366×768 | 21 378 | 7.6 / 7.9 | 35.9 / 60.4 | 73 |
| `hevc_qsv` | 1920×1080 | 96 013 | 10.6 / 11.2 | 19.0 / 60.1 | 14 |
| `av1_qsv` | 1920×1200 | 4 715 | 11.9 / 12.8 | 48.0 / 59.0 | 28 |
| `hevc_qsv` | **2880×1800** | 591 | **24.4 / 25.6** | **27.6 / 29.4** | **0** |
| `av1_nvenc` | 1920×1200, direct | 88 | 9.9 / 10.9 | 57.6 / 57.6 | 2 |
| `hevc_nvenc` | 1920×1200, direct, the same host | 136 | **21.7 / 24.7** | **26.8 / 31.8** | **0** |
| `av1_nvenc` | 2560×1600 | 513 | 16.4 / 17.8 | 54.3 / 58.3 | 21 |
| `hevc_videotoolbox` | 3024×1964 | 803 | 6.3 / 6.6 | 54.6 / 55.1 | 645 of 794 |
| `hevc_vaapi` | 1600×900, a virtual desktop | 105 | 4.2 / 4.8 | 40.3 / 41.1 | 0 |

> [!IMPORTANT]
> **The 2880×1800 `hevc_qsv` laptop never reached 30 fps** in 590 windows, against a 60 fps target. At
> 1080p the QSV encode stage already takes **10.6 ms**: 64 % of a 60 fps frame period, and more than a whole
> 120 fps period (8.3 ms). At the measured cost, the CPU path cannot carry 120 fps at 1080p on any of these
> encoders.

## 3. What the numbers do and do not say

- **"Encode" is five things.** `encode_sync` runs `convert_bgra`, `build_av_frame` (a plane copy), the hardware
  upload, `send_frame` and `drain_packets` in one timed call. How much of the 10.6 ms is the CPU round trip and
  how much is the hardware encoding is **not known**. Nothing in this FR is built until P0 splits it.
- **Not every slow cell is a copy problem.** On the host that runs both, `hevc_nvenc` takes 22 ms where
  `av1_nvenc` takes 10–11 ms. The CPU work is the same for both, so at most ~11 ms of the 22 is conversion and
  copies. The rest is HEVC NVENC itself on that GPU, and a GPU-resident frame would not fix it. Recorded so that
  P2's result is not read as a promise for every encoder.
- **The capture readback is off the pump's clock.** WGC reads back on its own worker thread (§2.1), so its
  cost shows up as frame age (latency) and CPU load, not as pump time. `avg_capture_ms` also includes the wait
  for a frame on an event-driven backend. P0 measures the readback itself, on the capture thread.

## 4. Design

### 4.1 The contract first (C0)

```rust
pub enum FrameData {
    Cpu(Vec<u8>),
    /// Windows: a texture from the capture's own pool, on the capture device.
    D3d11(D3d11Frame),
    /// macOS: the IOSurface the stream delivered, its use count held.
    IoSurface(IoSurfaceFrame),
    /// Linux: a dma-buf (fd, modifier, planes) exported by the DRM arm.
    DmaBuf(DmaBufFrame),
}
```

`Frame.data` becomes `FrameData`. `Frame::cpu()` returns the bytes. On a GPU frame it reads them back
**once**, with today's code, and keeps them. Every consumer that has not moved keeps working and pays the copy
only when it asks:

| Consumer | Anchor | After C0 |
|---|---|---|
| the pump's CPU resample | `encode/resample.rs:461`, `:463` | `cpu()`; on the GPU path the scale happens on the GPU first (§4.3), so it passes through |
| `FfmpegEncoder::convert_bgra` | `encode/ffmpeg/encoder.rs:1814` | takes the GPU surface instead, on a GPU cell |
| libvpx (VP9 4:4:4), openh264, Media Foundation | `encode/libvpx.rs`, `encode/openh264_backend.rs:455`, `encode/mf/sync_pipeline.rs:313` | `cpu()`, unchanged |
| the idle detector's hash | `session_idle.rs:218` | `cpu()`; it samples a few rows, and the cost is measured in P2 |
| the recorder and its pointer | `recording/recorder.rs`, `recording/pointer.rs` | `cpu()`, unchanged |

While only `Cpu` is produced (P1), behaviour is byte-identical. That is P1's test.

### 4.2 The adapter rule

A frame stays on the GPU only when the capture surface and the encoder are on **the same adapter**: equal
`AdapterLuid`, read from the live capture device (`IDXGIDevice::GetAdapter`), never assumed. Otherwise the frame
is read back, which is exactly today's path.

- **SystemContext (DXGI):** the device is on the output's adapter by construction (§2.1).
- **WGC:** the device is on the default adapter today. WGC itself can deliver to a device on another adapter (the
  OS copies across), so creating the WGC device on the **encoder's** adapter would make the LUIDs equal on a
  hybrid laptop at the price of an OS-side cross-adapter copy. Whether that beats today's path is measured, not
  assumed (open decision 1).
- **Linux:** the DRM arm's dma-buf lives on the scanout's render node, and VAAPI must open that node.

> [!WARNING]
> An adapter mismatch must never produce a wrong picture. It falls back to the readback, and the session
> reports why (§4.6).

### 4.3 Windows

- **Scale and convert on the GPU.** One D3D11 `VideoProcessorBlt` from the BGRA capture texture into an NV12
  texture at the encode box. The output colour space is **BT.601, limited range**: the matrix the CPU path uses
  today (`encode/color.rs:16`). A host that flips paths must not change colour. The DXGI arm already builds a
  VideoProcessor for its Phase B scale (`dxgi_direct.rs:203`–`326`); this generalises it to NV12 output and gives
  it to WGC.
- **One device, shared.** `HwKind::D3d11va` wraps the **capture's** `ID3D11Device` with
  `av_hwdevice_ctx_alloc` (never `_create`, which would open a second device), then
  `AVD3D11VADeviceContext.device` and `av_hwdevice_ctx_init`. The capture worker and the encoder thread (FR-70
  M1) then use one immediate context from two threads. That needs `ID3D10Multithread::SetMultithreadProtected`,
  or FFmpeg's lock callbacks shared with the capture thread. P2 picks one and proves it under load.
- **Never hand over the capture pool's own surface.** `CopyResource` into a texture from the encoder's frame pool,
  then release the WGC frame. Holding WGC's surface past `FrameArrived` stalls the capture.
- **Per backend:** NVENC takes `AV_PIX_FMT_D3D11` frames on its own adapter. QSV takes a device and frames
  **derived** from the D3D11VA ones (`av_hwdevice_ctx_create_derived`, `av_hwframe_ctx_create_derived`). AMF
  takes `AV_PIX_FMT_D3D11` frames. The first cell is QSV (§5): the panel and the encoder share the Intel adapter
  on the fleet's QSV laptops, and that is where the measured cost is largest.

### 4.4 macOS

The stream's `IOSurface` becomes a `CVPixelBuffer` (`CVPixelBufferCreateWithIOSurface`, no copy) and reaches
VideoToolbox as an `AV_PIX_FMT_VIDEOTOOLBOX` frame. VideoToolbox converts BGRA itself. The surface's use count
is held until the encoder releases the frame. `CGDisplayStream` recycles a small pool, so a held surface must
never outlive one frame period. The capture API is deprecated on recent macOS versions; that migration is
FR-97's, and this phase rides whichever API delivers the surface.

### 4.5 Linux

The DRM arm already imports the scanout through EGL (FR-107 P3, `capture/drm_gpu.rs`) and reads it back. The
GPU path exports a dma-buf instead, as `AV_PIX_FMT_DRM_PRIME`, and maps it to VAAPI (`av_hwframe_map`) for
`*_vaapi`. The scanout's modifier must be one the VAAPI driver can import; otherwise the readback is used. The
portal and mutter arms stay on the copy. Passing the compositor's buffers to the daemon needs a per-frame
lifetime handshake, and `wire.rs` already records why that waits for a measurement.

### 4.6 A GPU cell is a cell

The GPU input path is a property of a **cell** (encoder × chroma × input path). Every rule in the
`encoder-cells` skill applies:

- **The probe proves an open.** The probe child opens the GPU-input form on a D3D11 device of the **same
  adapter** (Windows), on the render node (Linux), or with a `CVPixelBuffer` (macOS), and reports it. Any failure
  means no GPU cell, never a crashed daemon.
- **Only a session proves the cell.** The first sessions on a new cell are read for decode errors, keyframe
  requests and colour before the cell is trusted.
- **One kill switch, honoured everywhere.** `MESHHARBORD_ZERO_COPY` (config `zero_copy`), default OFF for one
  release. Plus `zero_copy_deny` in the `encoder_cells_deny` shape (`name:path`). Both are honoured by the probe
  **and** by session dispatch: "a kill switch a child process honours and the daemon ignores keeps nothing out of
  the daemon".
- **The session says which path it took and why.** The heartbeat and `rc:video-info` carry
  `input_path = gpu | cpu`, and for `cpu` a reason: `switch_off`, `denied`, `adapter_mismatch`,
  `consumer_needs_cpu`, `open_failed`. Without the reason, "zero-copy did nothing" is unattributable.

```mermaid
flowchart LR
  subgraph today["Today: every hardware cell"]
    A1[capture surface<br/>GPU] -->|CopyResource + Map| B1[Vec&lt;u8&gt; BGRA<br/>CPU]
    B1 -->|dcv BGRA→NV12| C1[NV12 planes<br/>CPU]
    C1 -->|AVFrame copy| D1[AVFrame<br/>CPU]
    D1 -->|upload inside send_frame,<br/>or hwframes upload| E1[encoder<br/>GPU]
  end
  subgraph gpu["FR-118: same adapter, switch on"]
    A2[capture surface<br/>GPU] -->|CopyResource into<br/>the encoder's pool| B2[pool texture<br/>GPU]
    B2 -->|VideoProcessorBlt<br/>scale + BT.601 NV12| C2[NV12 texture<br/>GPU]
    C2 -->|AV_PIX_FMT_D3D11| E2[encoder<br/>GPU]
    B2 -.->|cpu(): only when a CPU<br/>consumer asks| F2[Vec&lt;u8&gt;]
  end
```

## 5. Phases

| P | Scope | Kill switch | Status |
|---|---|---|---|
| P0 | **The split.** `encode_sync`'s five steps timed apart: `avg_convert_ms`, `avg_upload_ms`, `avg_submit_ms`, `avg_drain_ms` on the FFmpeg DC heartbeat, plus `avg_readback_ms` from WGC's capture thread (the DXGI arm is split with P4). Then a fleet read, per encoder × geometry | none: telemetry, a handful of `Instant` pairs per frame, no knobs read in the frame path | **built** (§5.1), ships with the next agent release; the fleet read is AC1 |
| P1 | **C0, the contract.** `FrameData` + `Frame::cpu()`. Only `Cpu` is produced | none: no behaviour change, byte-identical by test | — |
| P2 | **Windows, WGC → QSV, the first cell.** The GPU scale + NV12 conversion, `HwKind::D3d11va` on the capture device, the adapter rule, the probe's GPU-input open, the session's `input_path` and reason | `MESHHARBORD_ZERO_COPY` (default OFF) + `zero_copy_deny` | — |
| P3 | NVENC and AMF on D3D11 frames; open decision 1 measured on a hybrid laptop | the same | — |
| P4 | The SystemContext DXGI arm (the lock screen and UAC) | the same | — |
| P5 | macOS: IOSurface → VideoToolbox | the same | — |
| P6 | Linux: the DRM arm's dma-buf → VAAPI | the same | — |
| P7 | Docs and the final field table | — | — |

P0 decides the rest. If convert + copy + upload turn out to be a small share of the encode stage on a backend,
that backend's phase is not built, and the reason is recorded here.

### 5.1 P0 — as built (2026-10-21)

Telemetry only, on the FFmpeg DC pump's heartbeat. No knob is read in the frame path, and nothing changes
what the pump does.

| Heartbeat field | What it times | Where |
|---|---|---|
| `avg_convert_ms` | `convert_bgra` and the `AVFrame` build: the CPU colour conversion and a plane copy | `encode_sync`, `agents/meshharbord/src/encode/ffmpeg/encoder.rs` |
| `avg_upload_ms` | the hardware-frame upload: VAAPI, D3D12 and Vulkan; zero for every other encoder | the same |
| `avg_submit_ms` | `send_frame`, where NVENC, QSV and AMF upload a software frame themselves | the same |
| `avg_drain_ms` | receiving the packets | the same |
| `avg_readback_ms` | WGC's copy of the capture surface into CPU memory, on its capture thread. This is off the pump's clock, so `avg_capture_ms` never contained it | the `FrameArrived` handler, `agents/meshharbord/src/capture/wgc_backend.rs` |

- **The four parts add up to the encode stage** (`avg_encode_ms` also includes the hop to FR-70's encoder
  thread). They are cumulative per encoder (`StageTimes`, carried by `rate_stats()`) and reported per frame
  over each heartbeat window. A background swap keeps the encoder struct, so it keeps counting. An inline
  re-open builds a new encoder, and each encoder carries its own id, so a window never diffs two encoders'
  totals.
- **The DXGI arm is not split here.** Its readback runs while the pump waits for the worker's reply, so it is
  already inside `avg_capture_ms`, together with the acquire wait. It is split with P4. Every other backend
  reports `avg_readback_ms = 0`: scrap copies on the pump's clock, and the synthetic source has nothing to
  read back.
- **Tests:** five. They cover the window rule (the per-frame difference, an empty window, a new encoder
  starting its own window even after it has counted more frames, distinct ids) and the readback window
  (including a reopened capturer).
- **Negative controls:** run together, each fails exactly its target, 2 failed / 3 passed. In NC1 the window
  ignores the encoder id: `left: None, right: Some([12.0, 1.0, 2.0, 0.5])`. In NC2 the readback window loses its
  reopen rule and panics on the u64 underflow the rule prevents.

## 6. Acceptance criteria

- [ ] **AC1 — the split, measured.** P0 has shipped, and a fleet week is read per encoder × geometry into the
  §9 log: the share of the encode stage that is conversion, copy and upload, against submission and drain, and
  the capture thread's readback. This is the red record for AC3 and AC4.
- [ ] **AC2 — C0 is invisible.** `Frame::cpu()` on a GPU frame returns the bytes today's readback returns:
  tested on a Windows CI device (WARP is enough), and on the synthetic source. L0's cells read the same within
  their spread, with only `Cpu` produced.
- [ ] **AC3 — the first cell, in the field.** On a QSV host whose panel is on the Intel adapter, 20-minute
  sessions with the switch on and off, back to back, on the same content. Pass if all of these hold: the encode
  stage per frame falls by at least the conversion + copy + upload share P0 measured on that host, minus the GPU
  conversion's own time; process CPU falls; zero viewer decode errors, and no rise in keyframe requests; a test
  pattern decodes to within ±2 code values of the CPU path in every plane. The off-session is the red run.
- [ ] **AC4 — the slow laptop.** A host at ≥ 2560×1600 on QSV reaches a peak of **≥ 50 fps** with the switch on;
  §2.2's 2880×1800 laptop peaked at 29.4 over 590 windows. If P0 shows the hardware encode itself is the bound
  there, this AC records the measured bound instead, and why.
- [ ] **AC5 — the adapter rule.** A host whose capture and encoder adapters differ never takes the GPU path:
  unit-tested on the rule, and seen on one hybrid host in the field as `input_path=cpu reason=adapter_mismatch`.
- [ ] **AC6 — the gate holds at every entry point.** With the switch off, or the cell denied, neither the probe
  nor a session opens the GPU-input form. Tested at both entry points.
- [ ] **AC7 — every further cell, or its reason.** NVENC, AMF, the DXGI arm, VideoToolbox and VAAPI are each
  field-verified like AC3, or deferred with the measurement that deferred them.
- [ ] **AC8 — docs.** `docs/encoders.md` (the input path as a cell dimension, the switch, the denylist) and
  `docs/remote-control.md` (the frame path, both arms, as the §4.6 mermaid diagram with the measured numbers).
  Linked from `docs/README.md`.

## 7. Open decisions

1. **Which adapter WGC's device uses.** The default adapter (today), or the encoder's adapter, letting the OS
   copy across on a hybrid laptop. Recommended: keep the default until P3 measures the encoder's-adapter variant
   on a hybrid laptop against the readback.
2. **The default.** Recommended: OFF for one release, then ON per cell after a clean fleet week of that cell
   (decode errors, keyframe requests, `input_path` reasons), never globally.
3. **Colour.** Recommended: BT.601 limited range on the GPU path, matching today's CPU path, so the switch never
   changes the picture. Moving both paths to BT.709 with VUI signalled is a separate decision for every viewer.
4. **Who converts to NV12.** Our VideoProcessor (one matrix we control and test), or the encoder from BGRA (NVENC
   ARGB input, QSV RGB4: one pass fewer, each with its own matrix). Recommended: VideoProcessor first. Encoder-side
   RGB input is measured afterwards as an optimisation, per backend, against AC3's colour check.

## 8. Out of scope

- The portal and mutter arms' dma-bufs: fd passing and the compositor's buffer lifetime (`wire.rs`).
- GPU input for the D3D12 and Vulkan encoders (a D3D11 → D3D12 shared-handle path), Media Foundation's H.264 on
  the RTP track, and X11 (XShm is CPU memory by construction).
- Raising the frame rate: [FR-119](FR-119-high-refresh-streaming.md). HDR: wave 3.
- HEVC NVENC's own cost on the host in §2.2: an encoder setting, not a copy.

## 9. Field-verification log

| Date | Build | Cell | Result |
|---|---|---|---|
| 2026-10-21 | fleet, agents 0.4.135–0.4.148 | every FFmpeg DC session for 7 days: 142 538 heartbeats, 11 hosts | **The red record, before P0.** §2.2's table. The 2880×1800 `hevc_qsv` laptop peaked at 29.4 fps against 60. At 1080p, QSV's encode stage takes 10.6 ms. `hevc_nvenc` takes 22 ms where `av1_nvenc` takes 10–11 ms on the same host, so that host's cap is not a copy |

## 10. Related

- [FR-119](FR-119-high-refresh-streaming.md): above 60 fps needs the encode stage under one period; this FR is
  how that is reached on the CPU-bound cells.
- [FR-70](FR-70-media-pipeline-leaves-the-runtime.md): the encoder thread this design shares a device with.
- [FR-77](FR-77-encoder-chroma-matrix.md) and `docs/encoders.md`: the cell model, the probe and the denylist.
- [FR-107](FR-107-drm-capture-throughput.md): the DRM arm's EGL import, which P6 builds on.
- [FR-98](FR-98-input-to-photon-budget.md): the readback is latency as well as CPU; L4 sees it.
- `docs/plans/stardesk-teardown-program.md` §3: the design notes this spec started from.
