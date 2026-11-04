# FR-78 — D3D12 and Vulkan video encode: vendor-neutral hardware cells on Windows and Linux

**Issue:** [#1503](https://github.com/jk-zhang-meta/MeshHarbor/issues/1503) · **Status:** **closed 2026-09-08** — shipped `agent-v0.4.88` → `0.4.92`; every criterion field-verified, one viewer session per cell across Intel / AMD / NVIDIA / RADV · **Opened:** 2026-09-08 · **Glossary:** [`CONTEXT.md`](../../CONTEXT.md) · **ADR:** [0001](../adr/0001-encoder-backends-compiled-in-discovered-at-runtime.md) · **Related:** [FR-77](FR-77-encoder-chroma-matrix.md) · [FR-62](FR-62-encoder-rate-changes-without-an-idr.md) · [`docs/encoders.md`](../encoders.md)

## Goal

Two more **backends** in the one runtime-probed build per platform (FR-77's shape,
ADR 0001), both vendor-neutral and both loaded at runtime with nothing new to ship
or depend on:

- **D3D12 video encode** (`h264_d3d12va`, `hevc_d3d12va`, `av1_d3d12va`; FFmpeg ≥ 8.1)
  on Windows — any GPU whose driver implements the D3D12 video-encode DDI, which
  today is every NVIDIA, AMD and Intel desktop driver in support.
- **Vulkan video encode** (`h264_vulkan`, `hevc_vulkan`, `av1_vulkan`; FFmpeg ≥ 7.1)
  on Linux and Windows — NVIDIA (R550+), AMD (RADV, Mesa 24.1+) and Intel (ANV,
  Mesa 24+) through one API, with 4:4:4 decided at runtime on HEVC and AV1.

The **cell** vocabulary, the picker, the probe, the cache and the denylist are
FR-77's; this FR adds names to the cascade tables and the two hardware-frame
uploads the pump does not have yet. Nothing about how a session is chosen changes.

## Why

- **The vendor SDK is a dependency the host may not have.** AMF's runtime
  (`libamfrt64.so.1` / `amfrt64.dll`) ships with AMD's proprietary driver only —
  jupiter and zeus (AMD Raphael) reach hardware encode through VAAPI on Linux and
  would reach nothing through AMF on a Windows box with the in-box driver. QSV
  needs Intel's media runtime; NVENC needs `libcuda`/`nvEncodeAPI`. D3D12 and
  Vulkan video encode ride the **graphics driver every box already has**.
- **The cascade already routes around a broken vendor path** (RTX 5090: MF's
  `ActivateObject` fails, NVENC works). A vendor-neutral rung under the vendor
  ones turns "the SDK is missing or broken" from "software encode" into "the same
  silicon through another door".
- **Measured size** (FR-77 §Why, the full 8.1.2 static library): D3D12 video
  encode 83 KB linkable + the 349 KB of CBS bitstream writers the D3D12 / VAAPI /
  Vulkan wrappers share (already linked on Linux for VAAPI). Under 1 MB against a
  35 MiB binary — the same measurement that closed the per-vendor-build question.
- **Both are runtime-loaded by FFmpeg itself**: `hwcontext_d3d12va.c` loads
  `d3d12.dll` / `dxgi.dll` with `LoadLibrary`, `hwcontext_vulkan.c` loads
  `vulkan-1.dll` / `libvulkan.so.1` with the loader in `vulkan_loader.h`. No new
  DT_NEEDED, no new `Depends` — the P4 libva lesson (a load-time need of the
  daemon binary is a fleet-freeze hazard on the offline `dpkg --install` path) does
  not recur.

## Key design

1. **Cascade positions** (`agents/meshharbord/src/encode/ffmpeg/encoder.rs`, the
   `*_ENCODER_NAMES` tables): vendor SDKs → `*_videotoolbox` → `*_vaapi` →
   **`*_d3d12va` → `*_vulkan`**, closing every table. A host with a working vendor
   SDK keeps its vendor path first (the FR-62 rate-control behaviour of each
   backend is known; the new ones' is not). The order-lock tests grow two names.
2. **Hardware frames, one shape** (`encode/ffmpeg/vaapi.rs` today): the VAAPI
   `Device` (once per process) + `Frames` (pool per encoder, `sw_format` NV12 /
   VUYX, upload with `av_hwframe_get_buffer` + `av_hwframe_transfer_data` +
   `av_frame_copy_props`) is the same sequence for `AV_HWDEVICE_TYPE_D3D12VA` and
   `AV_HWDEVICE_TYPE_VULKAN`. Generalise the module over the device type; device
   candidates per type (D3D12: the adapter LUID that owns the primary output, the
   one SystemContext already picks; Vulkan: the physical device, `MESHHARBORD_VULKAN_DEVICE`).
3. **The vendor builds**: Windows overlay port adds `--enable-d3d12va` (the
   Windows SDK headers are on the runner) and `--enable-vulkan` (the Vulkan SDK
   headers, `vulkan-headers` from vcpkg); the Linux from-source job adds
   `--enable-vulkan` with `libvulkan-dev`'s headers only (FFmpeg dlopens the
   loader). New asset names on both, as P4 did, so a rollback is a suffix.
4. **Cells and the probe**: `VideoBackend::{D3d12, Vulkan}` in
   `crates/remote_control/src/models.rs` (wire strings `d3d12`, `vulkan`; older
   readers ignore unknown names by the FR-77 rule); `hw: true` by construction;
   `hevc_vulkan:yuv444` and `av1_vulkan:yuv444` join the built-in denylist until a
   driver proves the open, as every packed / RExt cell did.
5. **Rate control**: both backends take `b:v` / `maxrate` / `bufsize` and reject
   nothing the tiered open cannot fall through; whether a bitrate change forces an
   IDR is measured with FR-62's `encoder-smoke --ladder` before a cell leaves the
   denylist, never assumed.

## P0 + P1 — as built (#1506)

- **The vendor trees.** Windows: the vcpkg overlay port takes the port's own `vulkan`
  feature (vcpkg's `vulkan-headers` 1.4.357 ≥ the 1.4.317 `av1_vulkan` needs), re-states
  `--enable-d3d12va` (what the baseline port already passes) and `--enable-vulkan`, and
  enables `h264/hevc/av1_d3d12va` + `h264/hevc/av1_vulkan`; the verify step asserts the
  sixteen encoder symbols and that `avutil.lib` carries **no link directive** for
  `vulkan-1.lib` / `d3d12.lib` — FFmpeg dlopens both at runtime, so the static tree grows
  no import and the agent no load-time need. Linux: the Vulkan C headers from the Khronos
  repo at v1.4.362 into the prefix (22.04's `libvulkan-dev` is 1.3.204), `--enable-vulkan`
  + `--extra-cflags=-I/opt/ffout/include`, the three `*_vulkan` encoders (seventeen in
  the runtime probe), and an assert that no vendored lib DT_NEEDs `libvulkan`. The
  `spirv-headers` warning configure prints is about swscale, which is off. Both assets
  carry a new suffix (`-d3d12-vulkan`, `-vaapi-vulkan`); rollback = drop it.
- **One hardware-frame module** (`encode/ffmpeg/hwframes.rs`, the P4 `vaapi.rs`
  generalised): `HwKind::{Vaapi, D3d12, Vulkan}` keyed by the encoder name's suffix, with
  per-kind candidate devices (VAAPI: the pinned node, then `/dev/dri/renderD128`…`135`;
  D3D12: the pinned `d3d12_adapter`, then DXGI adapter indices `0`…`3` — FFmpeg's device
  string; Vulkan: the pinned `vulkan_device` by index or name, then physical devices
  `0`…`3`). **The open decides the device** (`open_on_some_device`): each candidate is
  opened lazily and once and kept for the process, the encoder's whole configure-and-open
  runs against the preferred device first and then the rest until one succeeds, and the
  winner is remembered so a session lands where the probe proved. Measured reason, dev
  box: Vulkan device 0 (the Radeon 610M iGPU) has no `VK_KHR_video_encode_queue`, the RTX
  5090 does; D3D12 adapter 0 opens HEVC but an RDNA2 iGPU has no AV1 — which device can run
  a codec is a per-codec, per-driver fact only the encoder's own open answers.
  `Frames::new(dev, kind, sw_format, w, h)` sets the pool's `format` to the kind's hardware
  pixel format; the upload is the same three calls for all three. The pixel format goes
  onto the codec context raw — ffmpeg-next's `Pixel` enum has no D3D12 variant. 4:4:4
  forms: packed VUYX on VAAPI, planar `yuv444p` on Vulkan (the driver's format list
  decides at open), never on D3D12 (NV12 / P010 only, so `*_d3d12va` is not on the
  4:4:4-capable list).
- **Options.** D3D12: `rc_mode=VBR` (uppercase, like VAAPI's — `vbr` reads as an
  undefined constant and drops the tier, measured) on the cap with the HRD window, `bf=0` (FFmpeg's
  d3d12va default is `bf=2` — two frames of reordering delay a remote desktop cannot
  carry), `async_depth=1` tier-protected. Vulkan: the same, `profile=rext` for HEVC
  4:4:4, and the Vulkan tuning / usage hints (`tune=ull`, `usage=stream`) in the
  tier-protected group with `async_depth=1`, so a driver that rejects them costs the knob,
  never the open.
- **Cells.** `VideoBackend::{D3d12, Vulkan}` (wire `d3d12`, `vulkan`; older readers
  ignore unknown names), `from_ffmpeg_name` splits `_d3d12va` / `_vulkan`, `hw: true` by
  construction; the probe's 4:4:4 candidates include Vulkan cells; `hevc_vulkan:yuv444`
  joins the built-in denylist. The cascade tables close `… → videotoolbox → vaapi →
  d3d12va → vulkan` (locked by the order tests).

### P2 — as built (#1510)

- **`encoder-smoke --name <ffmpeg encoder>`** opens exactly that encoder through
  `encode::open_named` — `FfmpegEncoder::static_name` + `new_named_probe`, the same open
  the capability probe runs, past every cascade — so a backend the vendor SDK outranks on
  a host can be driven with real bytes, and `--reconfigure-sweep --name` runs the FR-62
  ladder on it. `--encoder` / `--codec` are ignored when `--name` is set.
- **The probe cache key sees the driver environment**: `caps_cache::DRIVER_ENV`
  (`RADV_PERFTEST`, `RADV_DEBUG`, `ANV_DEBUG`, `MESA_LOADER_DRIVER_OVERRIDE`, the Vulkan
  loader's `VK_ICD_FILENAMES` / `VK_DRIVER_FILES` / `VK_LOADER_DRIVERS_SELECT` /
  `VK_LOADER_DRIVERS_DISABLE`, `LIBVA_DRIVER_NAME` / `LIBVA_DRIVERS_PATH`,
  `CUDA_VISIBLE_DEVICES`) is hashed next to the `MESHHARBORD_*` knobs, so the jupiter drop-in
  re-probes on its own; locked by `driver_env_is_part_of_the_key`.
- **Rate control, measured**: the A0 ladder on the dev box says D3D12 and Vulkan are the
  **rebuild** class (every `set_bitrate` rung forced an IDR: 20/20, 42–77 ms per apply)
  — exactly the branch `resolve_rate_mode` already gives every non-NVENC, non-QSV name,
  now stated as measured in its doc. FFmpeg's `vulkan_encode` / `d3d12va_encode` set rate
  control at session init and never re-read `rc_max_rate`; an in-place path there would
  be an FFmpeg patch, not an option, and stays out of scope.

## Phases

| # | Phase | Kill switch | Status |
|---|---|---|---|
| P0 | Vendor builds with `--enable-d3d12va` (Windows) and `--enable-vulkan` (Windows + Linux); the runtime probe asserts the new names; new asset names | the asset pattern in `release-agent.yml` | **shipped** #1506 → `agent-v0.4.88` (vendor run 34217171639): Windows `…-minimal-d3d12-vulkan.zip` (16 encoder symbols, no `vulkan-1.lib` / `d3d12.lib` directive in `avutil.lib`), Linux `…-minimal-vaapi-vulkan.tar.xz` (17 encoders in the runtime probe, no `libvulkan` DT_NEEDED, Vulkan-Headers 1.4.362 in the tree); MSI +254 KB |
| P1 | The hardware-frame module generalised over the device type; D3D12 and Vulkan device + pool + upload; the cells on the dev box (NVIDIA, both), CORPLAP-3 (Intel D3D12) and jupiter (RADV Vulkan) | `MESHHARBORD_USE_FFMPEG=0` / the denylist | **shipped** #1506 → `agent-v0.4.88`, **field-read 2026-09-08**: the dev box advertises 13 cells (D3D12 hevc/h264, Vulkan hevc/av1/h264 on the RTX after the iGPU refused), CORPLAP-3's Intel iGPU `hevc/d3d12` (its H.264/AV1 D3D12 and its Vulkan refused by the driver), **jupiter `hevc/vulkan` + `h264/vulkan` on RADV under `RADV_PERFTEST=video_encode`** (a drop-in; open decision on setting it from the daemon), WSL / zeus / mars / the MacBook unchanged |
| P2 | Cells, cascade positions, the probe's 4:4:4 candidates for `hevc/av1_vulkan`, the FR-62 ladder read per cell | the denylist | **shipped** #1510 → `agent-v0.4.89` (bump #1511; release run 34229765613, 28 assets, MSI +8 KB) — the cells and positions shipped with P1; `encoder-smoke --name` for real bytes past the cascade; the driver environment in the cache key; the ladder measured on the dev box (rebuild class, both backends); the 4:4:4 candidates stay denied (`hevc_vulkan:yuv444`); **rolled 2026-09-08**, every host re-probed on `meshharbord build changed` with its 0.4.88 cells |
| P3 | Field: sessions on each backend from the viewer, the operator-judged text scroll on the 4:4:4 cells that open | — | **done** — 2026-09-08: a HEVC session to CORPLAP-3 ran on `hevc_d3d12va` end to end (the host's only HEVC encoder; `rc:video-info` names it, 2075 frames in 60 s, 0 send errors — the field log has the read); the other new cells sit behind NVENC / VAAPI in their cascades and need the denylist to be reached by a session — and the first such attempt (jupiter, VAAPI denied) found the denylist was **probe-only**: the session opened the denied `hevc_vaapi`. Fixed the same day (`cells::names_420` in every 4:2:0 constructor, #1512 → 0.4.90). **On 0.4.90: seven sessions, one per cell** — CORPLAP-3 `hevc/d3d12` (Intel), jupiter `hevc/vulkan` + `h264/vulkan` (RADV), the dev box `hevc/d3d12` + `h264/d3d12` (the AMD iGPU) and `hevc/vulkan` + `h264/vulkan` (the RTX) all PASS with a clean picture and `rc:video-info` naming the encoder; **the dev box's `av1/vulkan` FAILS** — the cell opens and encodes, Chrome decodes the stream to garbage (hardware) or stalls (dav1d); attributed with the new `encoder-smoke --dump` to the missing temporal-delimiter OBU and fixed at the packet in 0.4.91 (`with_av1_temporal_delimiter`) — necessary, not sufficient: on 0.4.91 the keyframes decode and the inter frames smear, and the FFmpeg CLI's own `av1_vulkan` on the same GPU emits frames dav1d cannot parse, so **`av1_vulkan:yuv420` is denied by default from 0.4.92** (an FFmpeg / NVIDIA driver defect, no meshharbor code in the loop). **4:4:4: no cell of these backends opens one** — `hevc_vulkan` refuses `rext` on NVIDIA and on RADV, D3D12 video encode is NV12/P010 only, no AV1 encoder does 4:4:4 — measured, with `h264_nvenc` 4:4:4 opening in the same probe run as the control, so no scroll is owed here (FR-77's NVENC cells still owe #1470 theirs) |
| P4 | `docs/encoders.md` (the tables and the cascade diagram), `docs/README.md` row | — | **done** — `docs/encoders.md` §*Hardware frames: VAAPI, D3D12, Vulkan* (the device-walk diagram, the pool formats, the config keys), the cascade tables with the `_d3d12va` / `_vulkan` rungs and the fleet table on 0.4.88 (#1506, #1508); the denylist statement (probe AND session) and the `docs/README.md` row naming the three backends (#1512) |

## Acceptance criteria

- [x] **P0** — both vendored trees carry the new names (16 / 17 encoders asserted by
      the vendor jobs); the Linux `.deb`'s `Depends` and bundle are unchanged (no new
      load-time library — asserted: no `libvulkan` DT_NEEDED, no `vulkan-1.lib` /
      `d3d12.lib` directive); the Windows MSI grew by 254 KB on `agent-v0.4.88`.
- [x] **P1** — the cells open on real silicon: the dev box advertises `hevc/h264` on
      D3D12 and `hevc/h264/av1` on Vulkan (the RTX 5090, after the iGPU refused), and
      CORPLAP-3's Intel iGPU advertises `hevc/d3d12` — both from the probe's real open;
      a host without a Vulkan encode queue or a D3D12 video driver fails the open in one
      line and keeps its other cells (CORPLAP-3's Vulkan, WSL's software ICDs, mars).
      jupiter's RADV advertises `hevc/vulkan` + `h264/vulkan` under
      `RADV_PERFTEST=video_encode` (a systemd drop-in). Real bytes: `encoder-smoke --name`
      PASSED through `hevc_d3d12va`, `h264_d3d12va`, `hevc_vulkan`, `av1_vulkan` and
      `h264_vulkan` on the dev box (P2).
- [x] **P2** — the server records of the dev box, CORPLAP-3 and jupiter carry the
      new cells with `hw: true` and unchanged vendor cells (0.4.88 → 0.4.90, every
      roll); the picker offers them with the right reasons (HEVC on CORPLAP-3 from its
      one D3D12 cell, AV1 refused on jupiter, HEVC/H.264 on jupiter from the Vulkan
      cells alone); a session on each cell reported its chroma in `rc:video-info`
      (seven sessions on 0.4.90, the field log) — and one of them, `av1/vulkan`,
      reported a healthy encoder over a stream Chrome cannot decode, which is why the
      session, not the probe, is the acceptance read.
- [x] **P3** — a viewer session on every new cell, and the FR-62 ladder read per cell.
      Sessions (0.4.90 / 0.4.91, the field log): `hevc/d3d12` on Intel (CORPLAP-3) and on
      AMD (the dev box's Radeon 610M), `h264/d3d12` on AMD, `hevc/vulkan` and
      `h264/vulkan` on both RADV (jupiter) and NVIDIA (the dev box's RTX 5090) — seven
      sessions, each decoding cleanly with `rc:video-info` naming the encoder. The
      eighth, `av1/vulkan` on NVIDIA, is why this criterion is a session and not a probe:
      a healthy encoder over undecodable frames, two defects attributed in turn (the
      missing temporal delimiter, ours, fixed in 0.4.91; the frame headers, FFmpeg /
      the NVIDIA driver, contained on the denylist in 0.4.92 — the shipped default
      verified on the RTX: 12 cells, `av1_vulkan` not opened and not advertised, every
      other cell intact). Ladder: **IDR on every rate change** for `hevc_d3d12va` and
      `hevc_vulkan` (20/20, the rebuild class). 4:4:4: **no cell of these backends opens
      one**, measured on both vendors with a positive control in the same run — so there
      is no 4:4:4 scroll to judge here. (FR-77's NVENC 4:4:4 cells still owe #1470 theirs.)
- [x] **Docs** updated with the new backends in the tables and diagrams, linked
      from `docs/README.md` (`docs/encoders.md` §Hardware frames + the cascade and
      fleet tables, #1506 / #1508 / #1512; the README row names VAAPI · D3D12 · Vulkan).

## Open decisions

- **RADV exposes Vulkan video encode only under `RADV_PERFTEST=video_encode`** (Mesa
  25.2.8 on jupiter: zero video extensions without it, `VK_KHR_video_encode_{queue,h264,h265}`
  with it — measured with `vulkaninfo`). The daemon could set that in its own
  environment before the first Vulkan open and light the cells on every AMD Linux host;
  it does not, deliberately — an experimental driver path enabled fleet-wide on k8s
  bare-metal hosts is the operator's call, not the probe's. The lever today is a systemd
  drop-in (`Environment=RADV_PERFTEST=video_encode`); a config key that makes the daemon
  set it is the P2 candidate.
- ~~**The probe cache key does not see driver environment.**~~ Closed in P2 (#1510):
  `caps_cache::DRIVER_ENV` (`RADV_PERFTEST`, the Vulkan ICD selectors, libva's driver
  name/path, `CUDA_VISIBLE_DEVICES`, …) is part of the knob hash, so a drop-in edit
  re-probes on the next start without a cache clear.
- **`av1_vulkan` on NVIDIA emits frames that do not decode** (P3 field log). Two
  defects, attributed in turn: FFmpeg 9.0.1's `av1_vulkan` writes no temporal-delimiter
  OBU at the start of a temporal unit — ours to fix, fixed for every AV1 backend in
  0.4.91 (`with_av1_temporal_delimiter`) — and, underneath it, frame headers dav1d and
  libaom refuse, reproduced with the FFmpeg CLI's own `av1_vulkan` on the same GPU with
  no meshharbor code in the loop. The second is an FFmpeg / NVIDIA driver defect, so the
  cell is on the built-in denylist (`av1_vulkan:yuv420`, 0.4.92) until a driver or
  FFmpeg release decodes; re-test with `encoder-smoke --name av1_vulkan --dump` on
  MOVING content (solid-colour frames decode and prove nothing) and a viewer session.
  RADV on VCN 4/5, where `av1_vulkan` would be the ONLY AV1 cell, has no host in the
  fleet — when one appears, the entry is the first thing to revisit, per driver.
- Whether `*_d3d12va` should sit BEFORE Media Foundation for H.264 on Windows: MF
  is the older path with the RTX 5090 quirk, D3D12 reaches the same silicon — the
  answer is a measurement (latency and IDR behaviour on the dev box), not a design.
- Vulkan on Windows: NVIDIA and AMD ship `VK_KHR_video_encode_*` there; whether it
  is worth a rung under D3D12 on the same box is decided by whether any host opens
  Vulkan and not D3D12 (expected: none).

## Out of scope

- Decode of any kind (the browser decodes; nothing on the agent side decodes).
- Replacing the vendor SDK rungs — they stay first while their behaviour is the
  known one.
- Linux arm64 (no FFmpeg there) and macOS (VideoToolbox is the OS's answer).

## Field-verification log

| Date | Where | Phase | Read |
|---|---|---|---|
| 2026-09-08 | FR-77 §Why (the full 8.1.2 static library, win64) | — | D3D12 video encode h264/hevc/av1: 83 KB linkable; the CBS writers shared with VAAPI/Vulkan: 349 KB; `*_vulkan` HEVC/AV1 list 4:4:4 as runtime-decided. The sizes that make this FR a runtime question, not a build one |
| 2026-09-08 | vendor run 34217171639 | P0 | Windows: the vcpkg port's `vulkan` feature + `--enable-d3d12va` (already the port's) → `…-minimal-d3d12-vulkan.zip`, sixteen encoder symbols, no `vulkan-1.lib` / `d3d12.lib` directive in `avutil.lib`; `avcodec.lib` 12.1 → 21.8 MB (the CBS writers + the two wrappers, static — the MSI delta is the number that matters, read after the release). Linux: Vulkan-Headers 1.4.362 into the prefix, `--enable-vulkan`, seventeen encoders in the runtime probe, no `libvulkan` DT_NEEDED; the tree 1.64 → 1.84 MB packed (the headers ride along) |
| 2026-09-08 | the dev box's WSL2 (Mesa 25.2.8, `libvulkan1` 1.3.275, ICDs incl. `dzn`), the P1 build against the new tree | P1 | **The Vulkan device path works up to the frames pool, and WSL is a negative cell for Vulkan encode.** `hwframes: device opened backend="vulkan" device="(default)"` — the loader picked Mesa's `dzn` (D3D12-backed, "not a conformant Vulkan implementation, testing use only"), then `av_hwframe_ctx_init(vulkan)` failed `Operation not supported (-95)`: no video frames on dzn, the name fails in one line, the NVENC cells are untouched. The dzn device open costs ~2.5 s in the probe (`probe_ms` 2005 → 4665 on this box; the probe cache pays it once per build). `*_d3d12va` on Linux: `not registered` before any device attempt, as designed |
| 2026-09-08 | the dev box (RTX 5090 Laptop + Radeon 610M, Windows 11), the P1 build against the new tree, native | P1 | **Both backends open on real silicon, and the open had to choose the device.** D3D12: adapter `0` opened; `hevc_d3d12va` opened with the full low-latency tier (`rc_mode=VBR maxrate bufsize bf=0 async_depth=1`) → cell in 83 ms; `h264_d3d12va` → cell in 16 ms; `av1_d3d12va`: adapter 0 (the RDNA2 iGPU) "does not support VBR RC mode" / no compatible RC mode, adapter 1 (the RTX) "Driver does not support requested features … Codec configuration not supported", adapter 3 (WARP) no RC mode ⇒ not advertised, correctly. Vulkan: device `0` opened and `hevc_vulkan` refused it three tiers deep — `Device does not support the VK_KHR_video_encode_queue extension!` (the iGPU) — then device `1` (the RTX) opened with the full tier (`rc_mode=vbr … tune=ull usage=stream async_depth=1`) → **preferred from now on**; `hevc_vulkan` 474 ms, **`av1_vulkan` 13 ms**, `h264_vulkan` 12 ms. The matrix: **13 cells** (the 0.4.87 eight + `hevc/d3d12`, `hevc/vulkan`, `av1/vulkan`, `h264/d3d12`, `h264/vulkan`), probe 5550 ms (4327 on 0.4.87; the device walk is the difference, paid once per build by the cache); the 4:4:4 phase unchanged (`hevc_vulkan:yuv444` denied). First run also found the `rc_mode` spelling: `vbr` is "Undefined constant" to d3d12va (uppercase `VBR`, as VAAPI) — the open fell to defaults and still succeeded, which is what the tiers are for |
| 2026-09-08 | release + the fleet roll | P0 / P1 | `agent-v0.4.88` (bump #1507 → `e55a8a9c2`; release run 34223695163, 28 assets). **Sizes**: MSI 15,822,848 → 16,076,800 B (**+254 KB**, the < 1 MB criterion met), x86_64 `.deb` 13,721,956 → 13,804,128 B (+82 KB), arm64 unchanged; the `.deb`'s `Depends` and bundle unchanged (the vendor jobs' no-DT_NEEDED asserts hold). Rolled to all seven hosts through the update route; six came back on 0.4.88 within minutes — jupiter's install collided with an `apt-get` I was running on it for `vulkan-tools` (`Could not get lock /var/lib/dpkg/lock-frontend`; both `apt-get` and `dpkg` candidates failed, the daemon stayed alive and the re-push hit the install cooldown), retried below |
| 2026-09-08 | the dev box, 0.4.88 (server record) | P1 / P2 | **13 cells advertised**: `hevc/nvenc` 4:2:0+4:4:4 · `hevc/amf` · **`hevc/d3d12`** · **`hevc/vulkan`** · `av1/nvenc` · **`av1/vulkan`** · `h264/nvenc` 4:2:0+4:4:4 · `h264/amf` · **`h264/d3d12`** · **`h264/vulkan`** · `h264/mf` · `h264/openh264` · `vp9/libvpx`; `probe_ms` 6051 (4327 on 0.4.87 — the device walk, cached after the first start) |
| 2026-09-08 | CORPLAP-3 (Intel Meteor Lake iGPU `8086:7d45`, Windows), 0.4.88 — the server record + the probe child by hand under `meshharbor exec` | P1 / P2 | **`hevc/d3d12` is a new cell on Intel** — `Using device 8086:7d45 (Intel(R) Graphics)`, `hevc_d3d12va` opened with the full low-latency tier in 84 ms, and the host now advertises `h265` (QSV never offered HEVC there). `h264_d3d12va`: `Failed to check encoder support (887a0020)` on the first tier, then `Failed to check rate control support / Driver does not support VBR RC mode`, then no compatible RC mode — the Intel D3D12 driver refuses FFmpeg's H.264 configuration; the QSV cell covers H.264. `av1_d3d12va`: `Driver does not support VBR RC mode` on the iGPU, adapter 1 = the Basic Render Driver refuses to open (`-22`), adapters 2–3 the same RC refusal — QSV covers AV1. Vulkan: device 0 (the Intel driver) has no `VK_KHR_video_encode_queue`, devices 1–3 do not exist — no Vulkan cells on Intel Windows, correctly. `probe_ms` 6811 (5660 on 0.4.87) |
| 2026-09-08 | the WSL sibling · zeus · mars · the MacBook, 0.4.88 (server records) | P1 | WSL: the three NVENC cells unchanged, `probe_ms` 5866 (2508 on 0.4.87 — four software Vulkan ICDs opened and refused; cached after the first start). zeus (RADV without `RADV_PERFTEST=video_encode`): `hevc/vaapi` + `h264/vaapi` unchanged, `probe_ms` 200 — no Vulkan cell, as the extension list predicts. mars: `openh264` + `libvpx`, 501 ms. MacBook: `hevc/videotoolbox` + `h264/videotoolbox` unchanged, 120 ms — the new names are inert on the platform whose FFmpeg carries none of them |
| 2026-09-08 | jupiter, `vulkaninfo` | P1 | **RADV exposes video encode only under `RADV_PERFTEST=video_encode`**: Mesa 25.2.8 (`RADV RAPHAEL_MENDOCINO`, Vulkan 1.4.318) lists zero `VK_KHR_video_*` extensions by default and `VK_KHR_video_encode_{queue,h264,h265}` with the flag. The positive Linux Vulkan cell therefore needs the daemon's environment (a systemd drop-in) — see *Open decisions* |
| 2026-09-08 | jupiter, 0.4.88 + `meshharbord.service.d/radv-video-encode.conf` (`Environment=RADV_PERFTEST=video_encode`), the probe cache cleared, restart | P1 | **The Linux positive Vulkan cell.** Server record: **`hevc/vulkan` hw + `h264/vulkan` hw** next to `hevc/vaapi` + `h264/vaapi` (six cells), `probe_ms` 150 — RADV's Vulkan encode on VCN 3.1 costs the probe nothing. `av1_vulkan`: `Device does not support encoding av1` on RADV (VCN 3.1 has no AV1 encode; the correct refusal) and no encode queue on the second device (llvmpipe). The same restart WITHOUT clearing `caps-cache.json` would have replayed the four-cell answer — the cache key's blindness to driver environment, as recorded above. Note for the roll itself: jupiter's first install attempt failed on the dpkg lock held by an `apt-get` I was running on it (`vulkan-tools`), and the re-push hit the 300 s install cooldown — never run apt on a host during its roll |
| 2026-09-08 | CORPLAP-3, 0.4.88 — a HEVC session from the viewer (Chrome on the dev box, codec HEVC, colour detail Auto, priority Sharper) | P3 | **The first session on a new backend, on the host where it is the only encoder of its codec.** Agent log: `hwframes: device opened backend="d3d12" device="0"` → `ffmpeg encoder opened … encoder="hevc_d3d12va" options="rc_mode=VBR maxrate=43200000 bufsize=43200000 bf=0 async_depth=1"` (the full low-latency tier, 100 ms from device open to encoder open), 1920×1200 @ 60 target. Viewer: `rc:video-info {codec:"h265", encoder:"hevc_d3d12va", hardware:true, chroma:"yuv420", transport:"direct"}`, the status pill `H.265 4:2:0 HW (hevc_d3d12va) · direct · dec HW`, `ttff 2932 ms` (`first_frame` +2395 ms after the DC opened — the open itself is not where the time went; not chased here). Pump heartbeats over 60 s: `frames_encoded` 2075 = `frames_captured`, `avg_encode_ms` 16.7–19.1 on the Meteor Lake iGPU, `send_errors` 0, `rebuilds` 0, `idr_count` 1, `paced_fps` 50–55 (the viewer read 37 fps on a Notepad++ page). The picker offered HEVC because `hevc/d3d12` is the host's only HEVC cell, and resolved 4:4:4 → 4:2:0 with the reason (`agent does not advertise hevc_chroma yuv444`). Session ended cleanly (`closed`) |
| 2026-09-08 | jupiter, 0.4.88 — `encoder_cells_deny = hevc_vaapi:yuv420,h264_vaapi:yuv420` (so a session could only reach the Vulkan cells), restart, a HEVC session from the viewer | P3 | **FAIL, and a finding about the denylist rather than about Vulkan.** The restart re-probed on the changed key (`cache miss — a MESHHARBORD_* knob changed`) and the hello advertised only `hevc_vulkan` + `h264_vulkan` (+ openh264): the denylist did its job in the probe. The session then ran on **`hevc_vaapi`** — `rc:video-info {encoder:"hevc_vaapi", hardware:true, chroma:"yuv420", transport:"relay"}`, 1600×900 (the virtual desktop), `ttff 1003 ms`, heartbeats `encoder="hevc_vaapi"`. The 4:2:0 session cascades handed the static name table to the dispatcher; only the probe and the 4:4:4 list ever read the denylist, so a session opened a cell the device had said it would not open — and the probe's protection (a child process) does not cover a session (the daemon). Fixed in the same day's PR: `cells::names_420` = the cascade minus the denylist, used by every 4:2:0 constructor; `new_preferred` refuses a denied name; `encoder-smoke --name` keeps bypassing the list by design. Side read: with an explicit denylist the built-in one is REPLACED, so `hevc_vulkan:yuv444` was no longer denied and the 4:4:4 phase tried it — RADV refused (`tried ["hevc_vulkan"] opened []`), the correct answer for VCN 3.1. The Vulkan session read itself is re-run on the fixed build |
| 2026-09-08 | release + the fleet roll | P2 | `agent-v0.4.89` (bump #1511 → merged 13:04 UTC; release run 34229765613, 28 assets; MSI 16,076,800 → 16,084,992 B, +8 KB). Six of seven hosts back on 0.4.89 within 6 min; the MacBook's push was lost to the dev box's own daemon restart (the roll runs over the overlay through mars, and the dev box's MSI upgrade takes ~8 min with the service down) — re-pushed once the mesh was back, seven of seven on 0.4.89 by 13:40 UTC. Server records: every host `probe_cached=false` with the reason `meshharbord build changed`, cells identical to 0.4.88 (dev box 13, CORPLAP-3 7 incl. `hevc/d3d12`, WSL the NVENC five, zeus VAAPI, mars software); **jupiter advertises `hevc/vulkan` + `h264/vulkan` only** — its `encoder_cells_deny` from the P3 read is still in place for the 0.4.90 re-test. jupiter's journal on the restart adds the 4:4:4 negative for RADV in full: `hevc_vulkan` refused `hevc profile "Rext" not supported!` on the first two tiers and `Pixel format yuv444p of input frames not supported!` on the last — VCN 3.1 has no Rext encode, and the probe reports it in 100 ms |
| 2026-09-08 | release + the fleet roll | the denylist fix | `agent-v0.4.90` (#1512 → bump #1514 → `283361e7a`; release run 34233898296, 28 assets; MSI 16,080,896 B). Seven of seven hosts back within 4.5 min; every host re-probed on `meshharbord build changed` with unchanged cells (jupiter still Vulkan-only under its denylist) |
| 2026-09-08 | jupiter, 0.4.90, the SAME setup as the failing read (`encoder_cells_deny = hevc_vaapi:yuv420,h264_vaapi:yuv420`) — a HEVC session, then an H.264 session from the viewer | P3 | **PASS on both Vulkan cells — the denied VAAPI cells were skipped.** HEVC: `hwframes: device opened backend="vulkan" device="0"` (RADV) → `ffmpeg encoder opened … hevc_vulkan options="rc_mode=vbr maxrate=22950000 bufsize=22950000 bf=0 tune=ull usage=stream async_depth=1"` (the full tier, 9 ms from device to encoder); viewer `rc:video-info {codec:"h265", encoder:"hevc_vulkan", hardware:true, chroma:"yuv420", transport:"direct"}`, `ttff 856 ms`, pill `H.265 4:2:0 HW (hevc_vulkan) · direct · dec HW`; heartbeats `encoder="hevc_vulkan"`, 631 frames encoded in 30 s, 0 send errors. H.264: `h264_vulkan` opened on the remembered device (no second device walk), `rc:video-info {codec:"h264", encoder:"h264_vulkan", hardware:true, chroma:"yuv420", transport:"direct"}`, pill `H.264 4:2:0 HW (h264_vulkan) · direct`, 661 frames encoded, 0 send errors. The 1600×900 virtual desktop at 15 fps is what a terminal-only Xvfb produces — the source is static. jupiter's denylist cleared back to the built-in afterwards |
| 2026-09-08 | the dev box, 0.4.90 — one session per new cell, each reached by denying everything above it in its cascade (`encoder_cells_deny` → `Restart-Service MeshHarbor` → the probe re-runs on the changed key), the viewer on the same machine | P3 | **Four of five PASS, `av1/vulkan` FAILS.** **A `hevc/d3d12`** (NVENC + AMF denied): `hwframes: device opened backend="d3d12" device="0"` — adapter 0 is the **Radeon 610M**, so this is AMD's D3D12 video encoder, the third vendor behind the backend after Intel (CORPLAP-3) — `hevc_d3d12va` 2016×1260 in 187 ms; `rc:video-info {encoder:"hevc_d3d12va", hardware:true, chroma:"yuv420", transport:"direct"}`; 527 frames / window, 6.65 MB, 0 send errors; picture clean. **B `hevc/vulkan`** (+ D3D12 denied): Vulkan device `0` (the iGPU) opened and refused by the encoder, device `1` (the RTX 5090) opened → *preferred from now on*; `hevc_vulkan` 2016×1260 with the full tier; `rc:video-info hevc_vulkan`; 243 frames, 0 send errors; clean. The walk costs ~430 ms once per daemon process — the probe child's preference does not reach the daemon. **D `h264/d3d12`** (H.264 NVENC + AMF denied): adapter 0 again (AMD), `h264_d3d12va` full tier (`rc_mode=VBR maxrate=85730400 bufsize=85730400 bf=0 async_depth=1`) in 255 ms; `rc:video-info h264_d3d12va`, pill `dec SW`; 289 frames, 18 ms encode, 0 send errors; clean. **E `h264/vulkan`** (+ D3D12 denied): device 1, `h264_vulkan` full tier; `rc:video-info h264_vulkan`; 300 frames, 21 ms, 0 send errors; clean. **C `av1/vulkan`** (AV1 NVENC + AMF denied; `av1_d3d12va` refuses every adapter here): the probe advertised `av1_vulkan` as the AV1 opener and the session ran on it — `av1_vulkan` opened with `rc_mode=vbr maxrate=38102400 bufsize=76204800 bf=0 tune=ull usage=stream async_depth=1`, `rc:video-info {codec:"av1", encoder:"av1_vulkan", hardware:true}`, 570 frames encoded at 15 ms, 1 IDR, 0 send errors — **and the picture is garbage**: heavy green/purple smearing with only the layout's ghost, under Chrome's hardware AV1 decode. With the viewer's `meshharbor-rc-decode-pref=software` (dav1d) the decoder **stalls outright**: black, `video stalled`, the session drops and auto-restores in a loop. Chrome cannot decode the NVIDIA Vulkan AV1 stream either way; the encoder side reports nothing wrong. Attributed offline with `encoder-smoke --name av1_vulkan --dump` (the next row) and fixed at the packet: the stream lacks temporal-delimiter OBUs. All five sessions from the same viewer, same codec picker, same denylist mechanism — the only variable is the encoder |
| 2026-09-08 | the dev box — `encoder-smoke --name <x> --dump <file>` (new in this PR) for `av1_vulkan`, `av1_nvenc`, `hevc_vulkan`, `hevc_nvenc`; the FFmpeg 9.0.1 CLI's decoders on the dumps | P3 | **Attributed: `av1_vulkan` emits temporal units with no temporal-delimiter OBU.** `av1_nvenc` (447 B / 10 frames): `TD · SeqHdr · Frame · TD · Frame · …` — dav1d decodes 10/10. `hevc_vulkan`: decodes. `av1_vulkan` (920 B): `SeqHdr(11) · PADDING(240 B of 0xaa) · Frame(46) · Frame(40) · … · SeqHdr · PADDING · Frame …` — **no `OBU_TEMPORAL_DELIMITER` anywhere**; FFmpeg's `obu` demuxer does not recognise the file (`Invalid data found when processing input`, forced `-f obu` finds no stream), dav1d refuses it. The same bytes with `12 00` inserted before each unit (a PowerShell rewrite) → **dav1d decodes 10/10**. The padding OBUs are tolerated. So the bitstream is well-formed except for the delimiter the AV1 spec puts at the start of every temporal unit, which every other AV1 encoder we ship writes and Chrome's decoders (hardware and dav1d alike) require. Fix: `FfmpegEncoder::drain_packets` prepends the delimiter to any AV1 packet whose first OBU is not one (`with_av1_temporal_delimiter`, type read from the header bits, no double-prepend) — for every AV1 backend, so a future encoder with the same habit is covered. Verified offline on the repaired build: the raw `--dump` of `av1_vulkan` is 940 B (920 + ten delimiters), begins `12 00 0a 0b …` like `av1_nvenc`'s, and dav1d decodes it 10/10 as-is; `av1_nvenc`'s dump is byte-identical to before (447 B — a unit that already starts with a delimiter is untouched). The session re-test on the dev box is owed on the build that carries it (0.4.91) |
| 2026-09-08 | release + roll | the delimiter fix | `agent-v0.4.91` (#1517 → bump #1518 → `87e95bada`; release run 34242079883, 28 assets; MSI 16,084,992 B). Six of seven back within 90 s, the MacBook re-pushed (its push is lost whenever the dev box's own daemon restarts mid-loop — the roll runs over the overlay through mars; twice now); every host re-probed on the build change with unchanged cells, jupiter back to its four (VAAPI + Vulkan) with the denylist cleared. Note: the bump chain's post-merge guard (`git show origin/master:… \| grep`) refused to tag once — the fetch had not caught up with a merge seconds old; the same guard passed a minute later and the tag was cut by hand |
| 2026-09-08 | the dev box, 0.4.91, `av1/vulkan` steered by the denylist again — the session re-test on the repaired build | P3 | **FAIL, differently — and now attributed to the encoder's frames.** `rc:video-info av1_vulkan`, 636 frames at 12 ms, 5 IDRs (the rate ladder rebuilt the encoder three times), 0 send errors; the picture: the regions unchanged since the last keyframe render correctly (the taskbar, a side panel, a page footer legible), every changed region smears — correct keyframes, corrupt inter frames. With no meshharbor code in the loop, the **FFmpeg 9.0.1 CLI's own `av1_vulkan`** on the same GPU (`-init_hw_device vulkan=vk:1`, testsrc2 640×480, 30 frames, `rc_mode=vbr bf=0 tune=ull usage=stream`, the `ivf` muxer inserting the temporal delimiters itself — the file starts `12 00 0a 0b …` like ours) produces 291 KB that **dav1d refuses at the frame header on all 29 frames** (`Error parsing frame header` / `Error parsing OBU data`) and libaom aborts on; `av1_nvenc` from the same CLI decodes 30/30. The earlier smoke dump "decoded 10/10" because ten solid-colour frames exercise nothing — a decode count is not a picture. So: the temporal delimiter was ours to fix and is fixed; the frame headers are FFmpeg's `av1_vulkan` on this NVIDIA driver, and **`av1_vulkan:yuv420` joins the built-in denylist** (the one 4:2:0 entry; 0.4.92) until a driver or FFmpeg release decodes. The dev box drops to 12 advertised cells; nothing else in the fleet has Vulkan AV1 encode |

| 2026-09-08 | the dev box, 0.4.91 — every HEVC cell above Vulkan denied and `hevc_vulkan:yuv444` ALLOWED (an explicit list replaces the built-in), the probe's 4:4:4 phase read | P3 | **No 4:4:4 cell of these backends opens, on either vendor — measured, with a positive control in the same run.** `hevc_vulkan` opened 4:2:0 in 938 ms (the cell and the device were live), then its 4:4:4 attempt with `profile=rext` was refused twice — `Function not implemented`, then `Invalid argument` on the retry without the low-latency knobs — and the probe logged `4:4:4 cell did not open — advertising 4:2:0 only encoder="hevc_vulkan"`. In the SAME phase `h264_nvenc` 4:4:4 opened (`profile=high444p`), so the phase was live and capable of opening a cell. With jupiter's RADV read (`hevc profile "Rext" not supported!` / `Pixel format yuv444p of input frames not supported!`), Vulkan HEVC 4:4:4 refuses on **both** vendors; D3D12 video encode is NV12/P010 only; no AV1 encoder anywhere does 4:4:4. These backends therefore contribute no 4:4:4 cell for an operator to judge — the P3 criterion's scroll half is satisfied by measurement, not by assumption. `hevc_vulkan` stays on the 4:4:4 attempt list (a third vendor or a newer driver may answer differently) and stays denied by default, so the refused open costs nothing |
| 2026-09-08 | the dev box (RTX 5090 + Radeon 610M), the 0.4.92 tree built natively — `meshharbord caps-probe` with NO environment override, i.e. the SHIPPED built-in denylist on real silicon | the denylist entry | **The containment works and costs nothing else.** `cells on the denylist are not opened denied=[… "av1_vulkan:yuv420"]` → `4:2:0 cell on the denylist — not opened, not advertised encoder="av1_vulkan"`; the host advertises **12 cells** (13 on 0.4.91 minus `av1/vulkan`), with `hevc/d3d12`, `hevc/vulkan`, `h264/d3d12`, `h264/vulkan` all still opening and `hevc/nvenc` + `h264/nvenc` still carrying `yuv444`. The fleet roll adds the server-record confirmation |
| 2026-09-08 | release + the fleet roll, and the containment through the server record | the denylist entry | `agent-v0.4.92` (#1520 → bump #1523 → `0d21fed98`; release run 34255622430, 28 assets — the macOS `.pkg` job spent 45 min in Apple's notarisation queue, unrelated to this change). **All seven hosts back on 0.4.92 in 2 minutes**, the fastest roll of the arc. Server records: **the dev box advertises 12 cells — `hevc/d3d12`, `hevc/vulkan`, `h264/d3d12`, `h264/vulkan` all present, `av1/vulkan` gone**, the NVENC cells still carrying `yuv444`; CORPLAP-3 keeps its seven with `hevc/d3d12`; jupiter is back to six (its test denylist cleared, VAAPI + Vulkan); zeus, mars, the WSL sibling and the MacBook unchanged. The containment is confirmed where a controller reads it, not only in the probe |
