# ffmpeg-meshharbor

Custom vcpkg port that builds a stripped FFmpeg for the MeshHarbor agent.

## What it builds

Encoders only — the browser does the decoding via WebCodecs:

- `hevc_nvenc`, `hevc_qsv`, `hevc_amf` — HEVC across the three vendor HW backends
- `h264_nvenc`, `h264_qsv`, `h264_amf` — H.264 across the same
- `vp9_qsv` — Intel-only HW VP9 (NVENC + AMF don't support VP9 encode)
- `libvpx-vp9` — SW VP9 fallback

Hardware acceleration: `d3d11va` (Windows), `cuda` (NVIDIA).

Everything else — decoders, demuxers, muxers, parsers, filters, BSFs, protocols,
network, iconv, zlib, bzlib, lzma, GPL components — disabled.

## Why a custom port

The upstream vcpkg `ffmpeg` port is feature-gated but still bundles most
encoders/decoders/parsers when you select `nvcodec` / `qsv` / `amf`. Our
agent only encodes (browser decodes), so ~80% of upstream's `libavcodec` +
`libavformat` is dead weight. Stripping it saves ~30 MB of static library,
landing at ~6 MB compressed delta in the agent MSI (vs ~20 MB for upstream).

## Phased rollout (Option B HEVC plan)

| RC | Status |
|----|--------|
| rc.64 (this RC) | Port files checked in. **NOT wired to CI.** Documentation-only. The portfile emits `FATAL_ERROR` if vcpkg tries to build it, so an accidental install fails fast. |
| rc.65 | Port wired into `release-agent.yml`. CI installs it via `vcpkg install --x-overlay-ports=agents/meshharbord/vcpkg-ports/`. `ffmpeg-next` 7.x dep added to Cargo.toml. Version pair verified to compile with `hevc_qsv` + `vp9_qsv` symbols reachable. MSI size delta measured. HARD STOP if >+8 MB compressed. |
| rc.66 | `src/encode/ffmpeg/` module gains a real `FfmpegEncoder` that implements the existing `VideoEncoder` trait. D3D11VA zero-copy from day 1. Behind `MESHHARBORD_USE_FFMPEG=1` env var; MF cascade still default. |
| rc.67 | `caps::detect` advertises `data-channel-hevc`. HEVC DC framer reuses VP9-444's 13-byte header. Anti-IDR-storm coalescer included. |
| rc.68 | Browser HEVC worker. Pre-flight WebCodecs spike (2026-05-26) locked the design: Annex-B, 4-byte start codes, no description. |
| rc.69 | `vp9_qsv` HW path for Intel iGPU. Unlocks Iris Xe field-test host from CPU-bound 17 fps → ~60 fps target. |
| rc.70 | Single codec-selector dropdown UX. |
| rc.71+ | AIMD tuning, field hotfixes. |
| rc.74-75 | Linux VAAPI, macOS VideoToolbox. |

## Linking model

- **FFmpeg**: statically linked into `meshharbord.exe`. No separate DLL ships.
- **libmfx** (Intel oneVPL dispatcher): statically linked. Bundled.
- **NVENC** (`nvEncodeAPI64.dll`): loaded at runtime from NVIDIA driver. Not bundled.
- **AMF** (`amfrt64.dll`): loaded at runtime from AMD driver. Not bundled.

Net MSI growth: ~6 MB compressed (8 MB → ~14 MB agent MSI).

## Why not just use upstream `ffmpeg`?

We could. We chose a custom port for two reasons:

1. **Binary size**: upstream's feature-gated build still pulls in ~80% of
   libavcodec + libavformat that we don't need. Roughly +15 MB compressed
   in the MSI vs the stripped build.

2. **Attack surface**: every parser, demuxer, and decoder is a fuzz target.
   The agent runs as `LocalSystem` on hosts in the perMachine SystemContext
   flavour (M3 A1 + rc.26). Disabling everything we don't call reduces the
   blast radius if a CVE lands in, say, `libavformat`'s matroska demuxer.

If maintaining a custom port turns out to be more work than the binary-size +
attack-surface win is worth, we'd switch to `ffmpeg[nvcodec,qsv,amf]` with
the upstream port and accept the larger MSI. This is the documented
fallback in the rc.65 critique (#14 "AMF-drop as paper armor" — better to
ship a slightly larger upstream port than to drop AMF support).

## References

- Pre-flight HEVC WebCodecs spike: the retired `docs/hevc-webcodecs-spike.html` (git history)
- Plan critique + decisions: memory entry `project_hevc_webcodecs_go.md`
- RustDesk's equivalent (their `hwcodec` private repo vendors a similar
  stripped FFmpeg): https://github.com/rustdesk-org/hwcodec
- Upstream vcpkg ffmpeg port: https://github.com/microsoft/vcpkg/tree/master/ports/ffmpeg
