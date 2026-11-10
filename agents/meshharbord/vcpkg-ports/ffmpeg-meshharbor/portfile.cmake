# =============================================================================
# ffmpeg-meshharbor — stripped FFmpeg port for the MeshHarbor agent.
#
# This is a custom vcpkg port that builds a minimal FFmpeg with ONLY the
# encoders MeshHarbor needs:
#
#   HEVC: hevc_nvenc, hevc_qsv, hevc_amf
#   H.264: h264_nvenc, h264_qsv, h264_amf
#   VP9:  vp9_qsv (Intel HW only — NVENC/AMF don't support VP9 encode),
#         libvpx-vp9 (SW fallback)
#
# Hardware acceleration: d3d11va (Windows), cuda (NVIDIA)
#
# Everything else — decoders, demuxers, muxers, parsers, filters, BSFs,
# protocols, devices, network, locale, iconv, zlib, bzlib, lzma — is
# disabled. The browser does decode via WebCodecs; the agent only encodes.
#
# Compared to upstream vcpkg's `ffmpeg` port (which is feature-gated but
# still enables ~all encoders/decoders/parsers), this saves an estimated
# ~30 MB of static library, leaving ~6 MB compressed delta in the MSI.
#
# STATUS:
#   rc.64 — port files checked in, NOT wired to CI. Documentation-only.
#   rc.65 — wired into `release-agent.yml`, exercised on Windows CI,
#           ffmpeg-next 7.x version pair verified to compile against
#           this port's output. MSI size delta measured.
#   rc.66 — `src/encode/ffmpeg/` calls into ffmpeg-next which links
#           against this port. Real HEVC/H.264/VP9 encoder dispatch.
#
# Pre-flight HEVC WebCodecs spike (2026-05-26) locked the framer design:
# Annex-B, 4-byte start codes, no description on VideoDecoder.configure().
# See the retired `docs/hevc-webcodecs-spike.html` (git history) for the test page that proved this.
# =============================================================================

# TODO(rc.65): pin the SHA512 once we settle on the FFmpeg release. n7.1
# was released 2024-09-30 and ships QSV via oneVPL, NVENC, AMF, plus the
# `--disable-everything --enable-encoder=...` granular config we rely on.
# The SHA512 below is a placeholder; rc.65 CI will fail loudly until it's
# updated, at which point we lock the value.
set(FFMPEG_VERSION "n7.1")
set(FFMPEG_REF "n7.1")

# vcpkg_from_github will be enabled in rc.65 when this port is actually
# built by CI. For rc.64 the port is documentation-only — CI does not
# reference it. We emit a fatal_error so an accidental
# `vcpkg install ffmpeg-meshharbor` during rc.64 fails fast rather than
# silently producing a half-baked artifact.
message(FATAL_ERROR
    "ffmpeg-meshharbor is documentation-only in rc.64 — the port is not yet wired into CI.\n"
    "rc.65 implements + tests this port. Until then, the agent's Cargo.toml `ffmpeg-encoder` feature is header-only:\n"
    "  see agents/meshharbord/src/encode/ffmpeg/mod.rs (returns available()=false).\n"
    "Build the agent without `ffmpeg-encoder` for rc.64.")

# -----------------------------------------------------------------------------
# Reference implementation (commented out for rc.64; landing in rc.65).
# -----------------------------------------------------------------------------
#
# vcpkg_from_github(
#     OUT_SOURCE_PATH SOURCE_PATH
#     REPO FFmpeg/FFmpeg
#     REF ${FFMPEG_REF}
#     SHA512 # TODO(rc.65): pin
#     HEAD_REF master
# )
#
# # Vendor SDK header paths from sibling vcpkg ports.
# x_vcpkg_pkgconfig_get_modules(
#     PREFIX ffnv_pc
#     MODULES ffnvcodec
#     LIBRARIES
# )
#
# # Stripped FFmpeg configure. The encoder list intentionally excludes
# # av1_* — MeshHarbor's plan is HEVC/H.264/VP9, and the RTX 5090 Blackwell
# # AV1 MFT issue is unresolved upstream (Known Issues). Add av1_nvenc /
# # av1_qsv / av1_amf here once that lands.
# vcpkg_configure_make(
#     SOURCE_PATH "${SOURCE_PATH}"
#     COPY_SOURCE
#     OPTIONS
#         # Strip everything by default.
#         --disable-everything
#         --disable-debug
#         --disable-doc
#         --disable-network
#         --disable-iconv
#         --disable-zlib
#         --disable-bzlib
#         --disable-lzma
#         --disable-protocols
#         --disable-devices
#         --disable-demuxers
#         --disable-muxers
#         --disable-decoders
#         --disable-parsers
#         --disable-bsfs
#         --disable-filters
#         --disable-encoders
#
#         # Re-enable just the encoders we ship.
#         --enable-encoder=hevc_nvenc
#         --enable-encoder=hevc_qsv
#         --enable-encoder=hevc_amf
#         --enable-encoder=h264_nvenc
#         --enable-encoder=h264_qsv
#         --enable-encoder=h264_amf
#         --enable-encoder=vp9_qsv
#         --enable-encoder=libvpx-vp9
#
#         # Hardware accelerators — both consumed by the VRAM zero-copy
#         # path in rc.66's FfmpegEncoder.
#         --enable-hwaccel=d3d11va
#         --enable-hwaccel=cuda
#
#         # External libs for the HW encoders.
#         --enable-libvpx          # for libvpx-vp9 SW fallback + vp9_qsv plumbing
#         --enable-libmfx          # Intel oneVPL/MFX dispatcher (QSV)
#         --enable-amf             # AMD AMF
#         --enable-nvenc           # NVIDIA NVENC (uses ffnvcodec headers)
#         --enable-cuda
#         --enable-cuvid
#         --enable-d3d11va
#
#         # Static linkage.
#         --enable-static
#         --disable-shared
#         --enable-pic
#
#         # We ship LGPL only — no GPL components (libx264/libx265 etc.).
#         --disable-gpl
#         --disable-nonfree
#
#         # Force a known config so vcpkg's caching is deterministic.
#         --pkg-config-flags=--static
# )
#
# vcpkg_install_make()
#
# # FFmpeg ships its own pkg-config files; vcpkg_fixup_pkgconfig
# # rewrites the prefix paths to be relocatable.
# vcpkg_fixup_pkgconfig()
#
# # Strip the .pc files that reference disabled libs (we disabled
# # avformat's protocols, so libavformat.pc would lie about its deps).
# # TODO(rc.65): audit + prune the pkg-config files after install.
#
# file(INSTALL "${SOURCE_PATH}/COPYING.LGPLv2.1"
#      DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}"
#      RENAME copyright)
