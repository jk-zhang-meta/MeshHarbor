---
name: encoder-cells
description: The invariants that govern roomler's video-encoder surface — the capability probe (child processes, phases, cache, denylist), the codec × backend × chroma cell matrix, and the per-backend FFmpeg gotchas (NVENC, QSV, AMF, VAAPI, D3D12, Vulkan, VideoToolbox). Load BEFORE touching anything under agents/meshharbord/src/encode/, the caps/hello wire, encoder cascades or chroma selection, before adding or denying a codec/backend cell, when a host advertises no hardware or a session paints garbage, or when changing the vendored FFmpeg build. FR-77 / FR-78.
---

# Encoder cells and the capability probe

Reference doc: **[`docs/encoders.md`](../../../docs/encoders.md)** — the full
matrix, cascade tables and field log. This file is the set of invariants that
are cheap to break and expensive to have broken.

## 1 · The probe is a child process, and any failure means "no hardware"

`encode::caps::detect()` spawns `roomlerd caps-probe` (hidden subcommand), reads
one `MESHHARBOR_CAPS_JSON:{…}` line, and treats **any** failure — non-zero exit,
killed by a signal, 60 s timeout, unspawnable, unparseable — as *every hardware
codec is unavailable*, falling back to `compute_caps(false)`.

A capability probe is untrusted third-party code by definition (vendor drivers,
GPU firmware) and does not belong in the daemon's address space. Before this, a
fault inside a probe took `roomlerd` down and the service manager restarted it
straight back into the same probe — a **crash-loop**, not a degraded agent.

⚠️ `MESHHARBORD_HW_AUTO=0` / `MESHHARBORD_ENCODER=software` do **not** skip the probe.
Those pick an *encoder*; the probe enumerates what to **advertise**.
⚠️ The child sets `MESHHARBORD_CAPS_CHILD=1`; `detect()` seeing it computes
in-process — that is the recursion guard.
⚠️ stdout is **marker-parsed**, not last-line-parsed, so anything else logging
there cannot be mistaken for the result. The child's stderr is **inherited on
purpose** so per-codec probe lines land in the daemon log next to the verdict.

### Anything derived from CONFIG belongs in the PARENT

The child does **not** inherit the process-local S2 config-fallback registry
(`tunnel_core::env::register_config_fallbacks`). `child::probe()` exports every
registered knob as a real `MESHHARBORD_*` env var
(`config_fallbacks_for_child`, precedence preserved) and `detect()` recomputes
`caps.rpc = rpc_caps()` in the **parent**.

Before that, a config-only `relay_server_enabled = true` started the relay server
in-process while the hello never advertised `relay-server`, so the FR-19 mint
could only ever answer `no_relay`.

### Two children, not one (0.4.85)

| Phase (`MESHHARBORD_CAPS_PHASE`) | Opens |
|---|---|
| `base` | every 4:2:0 open + the software cells + the vp9_qsv IDR verdict |
| `444` | only the 4:4:4 forms of `candidates_444`, answered as `MESHHARBOR_CAPS_444:[…]`, folded in by `merge_444` |

The 0.4.84 roll found the cost of one child: a laptop's Intel media runtime died
with `0xc0000005` on the first `vp9_qsv` 4:4:4 open and the daemon advertised
**no hardware at all**. A dying 4:4:4 child now costs only the 4:4:4 forms.

⚠️ **The child's stderr reaches no log on a service host.** It announces every
open on stdout (`MESHHARBOR_CAPS_PROGRESS:<name>:yuv444`, line-buffered so it
survives the crash) and the parent quotes the last one — *that* is the
`encoder_cells_deny` entry to add.

## 2 · The cache

`caps-cache.json` next to the daemon's logs (`encode/caps_cache.rs`), keyed on
exactly what it depends on: the **build** (crate version + exe length/mtime), the
**hardware fingerprint** (`encode/hwid.rs`), and a **SHA-256 of every `MESHHARBORD_*`
knob**. Any mismatch, a format bump, or **7 days** re-probes. `caps_cache = false`
/ `MESHHARBORD_CAPS_CACHE=0` switches read and write off. macOS has no key ⇒ no
cache (its probe is ~120 ms).

⚠️ **Only a result with a HARDWARE cell is cached.** A no-hardware answer is the
cheap case *and* the one a service that starts before the display driver
produces; freezing it for a week would be a silent fleet regression.
⚠️ A hit takes **only** the driver-derived fields (`hw_encoders`, `codecs`,
`transports`, `hevc_chroma`, `vp9_chroma`, `video_cells`). Permissions, the
GUI-session state and every verb list are recomputed by the running process
(`caps::merge_cached`) — they change without any driver changing.
⚠️ On a Windows SCM host the **worker** (console session) runs the probe and owns
the cache file, not the supervisor's `service-logs`.

## 3 · The denylist is a kill switch — it must apply at EVERY entry point

`MESHHARBORD_ENCODER_CELLS_DENY` (`name:chroma`, comma-separated, empty = deny
nothing) **replaces** the built-in list. A denied cell is never opened — by the
probe **and** by a session, both reading `cells::names_420` / `names_444`.

⚠️ Until 0.4.90 only the probe read it: the 4:2:0 session cascades handed the
static table to the dispatcher, and a HEVC session opened a denied `hevc_vaapi`
while the hello advertised only the Vulkan cells.

> **A kill switch a child process honours and the daemon ignores keeps nothing
> out of the daemon.**

Also a config key (`encoder_cells_deny`, validated `name:chroma` or `none`),
pushable through remote config with `MANAGE_AGENTS` alone — it only ever
*removes* cells. The device reports `needs_restart`. Since 0.4.87 it gates **both**
chroma forms.

## 4 · A probe proves an OPEN; only a SESSION proves a CELL

`av1_vulkan` on an RTX 5090 opened, encoded, reported nothing wrong — and Chrome
painted garbage or stalled. FFmpeg's `av1_vulkan` emits temporal units **without**
the temporal-delimiter OBU every other AV1 encoder starts with.

`FfmpegEncoder::drain_packets` now prepends the delimiter to any AV1 packet
lacking one (`with_av1_temporal_delimiter`), for every AV1 backend — **necessary,
not sufficient**: the repaired build still showed correct keyframes and corrupt
inter frames, and the FFmpeg CLI's own `av1_vulkan` on the same GPU emits frames
dav1d cannot parse. That is an FFmpeg 9.0.1 / NVIDIA driver defect with no
roomler code in the loop, so `av1_vulkan:yuv420` is the built-in denylist's one
4:2:0 entry.

Diagnostic that attributed it in one run:
`encoder-smoke --name <x> --dump <file>` + the FFmpeg CLI's dav1d.

## 5 · Per-backend traps

⚠️ **Never flush an FFmpeg encoder that never took a frame.** `FfmpegEncoder::drop`
used to `send_eof` unconditionally, and a `hevc_vaapi` that had no picture issued
SEGVs inside `avcodec_send_frame(NULL)` on radeonsi — the probe child died on
every start and the host advertised no hardware, while `encoder-smoke` (ten
frames, then drop) passed. The flush runs only when `frame_count > 0`, reset per
rebuild.

| Backend | Trap |
|---|---|
| **NVENC** | 4:4:4 is planar `yuv444p`. `h264_nvenc` 4:4:4 needs `profile=high444p` — `rext` is HEVC-only and reads as "cannot" |
| **QSV** | 4:4:4 is packed **VUYX**, never planar (this is why the FR-77 P1 `vp9_qsv` 4:4:4 open failed). Profile (`rext` / `profile1`) set explicitly in the `base` tier. `hw: true` only on the oneVPL build (`qsv_is_hardware_by_construction`) |
| **VAAPI** | Takes **hardware frames**; `encode/ffmpeg/vaapi.rs` holds the raw `ffmpeg_sys_next` calls. Device opens ONCE per process; each encoder gets a frame pool whose ref goes onto `hw_frames_ctx` **before** `open`. libva + libdrm are **bundled**, with **no `Depends`** — a `Depends: libva2` only holds where apt reaches a mirror, and the updater's offline `dpkg --install` replaces the binary *before* the dependency failure |
| **D3D12 / Vulkan** | `dlopen`'d by FFmpeg itself — the vendor jobs assert **no link directive / DT_NEEDED**, so a host without them loses cells, never the daemon. Set `bf=0` (both default to `bf=2`). `rc_mode` constants are **UPPERCASE** for d3d12va (`VBR`), lowercase for Vulkan (`vbr`) |
| **VideoToolbox** | macOS ships **no FFmpeg at all**. Wiring it needs BOTH the `*_videotoolbox` names in the tables **and** a re-run of `vendor-ffmpeg-macos.yml` — restoring the feature alone re-ships a dyld crash on every end-user Mac |

⚠️ **The OPEN decides the device** (`open_on_some_device`: preferred first, then
the rest, winner remembered). Vulkan device 0 may be an iGPU with no
`VK_KHR_video_encode_queue`; "first device that opens" would strand the discrete
GPU's cells.

⚠️ **VP9 has NO 4:2:0 fallback on a rejected 4:4:4 open** (`new_vp9_adaptive`
returns `Err`): the viewer configured its decoder for profile 1, and a VP9 profile
mismatch is a blank canvas. The session dispatch probes the exact cell first and
runs libvpx when it cannot open. HEVC and H.264 fall back to 4:2:0 and report the
truth.

## 6 · Selection order

**CLI `--encoder` > env `MESHHARBORD_ENCODER` > `encoder_preference` in config TOML >
`Auto`.** Values: `auto` | `hardware` (`hw`/`mf`) | `software` (`sw`/`openh264`).
`Auto` on Windows runs the MF H.264 probe-and-rollback cascade then falls back to
openh264; everywhere else it is openh264 only. `MESHHARBORD_HW_AUTO=0` reverts to
openh264-first without a rebuild.

Legacy caps fields keep their exact pre-FR-77 meaning (first backend that opens),
and **`data-channel-vp9-444` stays on the wire forever**. Unknown cell names are
ignored, never an error. The viewer derives cells for old agents in
`ui/src/composables/videoCells.ts` — the one reading the picker and the admin
chips share.
