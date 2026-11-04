# Relinking the Roomler agent against your own FFmpeg

This page exists to make an LGPL right **exercisable** rather than theoretical.

The Windows Roomler agent (`roomlerd.exe`) links FFmpeg **statically**. FFmpeg is
LGPL-2.1-or-later, and §6 of that licence gives you the right to modify FFmpeg
and relink the application against your modified version. Below is how to do it.

If you only want to check that we are complying, the short version is: **the
whole application is open source, so the "work that uses the Library" is
available to you as source code, which is what LGPL-2.1 §6(a) asks for.** You do
not need anything from us that is not already published.

---

## Why no object-file archive is needed

LGPL-2.1 §6(a) requires the distributor to accompany the work with

> the complete corresponding machine-readable source code for the Library …
> **and**, if the work is an executable linked with the Library, with the
> complete machine-readable "work that uses the Library", **as object code
> and/or source code**, so that the user can modify the Library and then relink
> to produce a modified executable containing the modified Library.

Both halves are satisfied by publication, not by request:

| §6(a) requires | Where it is |
|---|---|
| Complete source of **the Library** | [`vendored-ffmpeg-9.0.1`](https://github.com/gjovanov/roomler-ai/releases/tag/vendored-ffmpeg-9.0.1) → `ffmpeg-<version>-corresponding-source.tar.xz` (upstream + every patch our builds apply + the full build recipe) |
| The **"work that uses the Library"**, as **source code** | This repository. The agent is MPL-2.0; `agents/meshharbord` and every crate it depends on are public. |
| Terms permitting modification and debugging | MPL-2.0 for our code; upstream licences for vendored crates |

The written offer in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) stands
in addition to this, not instead of it.

Our customisation is the configure flag set, which selects components, plus two
sets of source patches:

| patches | applied by | in the tarball |
|---|---|---|
| ours, [`.github/ffmpeg-patches/`](../.github/ffmpeg-patches/) (since FR-62: one NVENC patch so a bitrate change does not force an IDR) | the Windows and Linux builds | `patches/`, with a SHA-256 manifest |
| the vcpkg `ffmpeg` port's own (14: build-system fixes, plus one API addition) | the Windows build | `vcpkg-port-ffmpeg/`, at the baseline the recipe pins |

So "the Library as used in that binary" is reproducible from what is published.
Two checks keep it that way. Every shipped tree carries a `ROOMLER-PATCHES.txt`
manifest that the release lane compares with the committed patches. And the
release lane refuses to tag while the published tarball was built from a
different patch set, vcpkg baseline or build recipe than the release's own
checkout. The recipe has been checked since FR-85 P4c: the configure options
live there, not in a patch, and P4c changed them (the software H.264 decoder
and the AAC encoder the screen recorder needs).

⚠️ Until 2026-09-24 the tarball carried neither set, although this page said its
`recipe/` applied them. The recipe *referenced* the patch directory without
shipping it, which was invisible to anyone who read the recipe instead of the
tarball.

---

## Procedure

### 1. Get the FFmpeg corresponding source

```bash
gh release download vendored-ffmpeg-9.0.1 --repo gjovanov/roomler-ai \
  --pattern 'ffmpeg-*-corresponding-source.tar.xz*'
sha256sum -c ffmpeg-n9.0.1-corresponding-source.tar.xz.sha256
tar xf ffmpeg-n9.0.1-corresponding-source.tar.xz
```

You now have the upstream tarball, `patches/` (ours), `vcpkg-port-ffmpeg/` (the
port the Windows build starts from) and `recipe/`, which contains the exact
workflows that produced our binaries. To start from exactly the library we
shipped on Linux, apply `patches/` first:

```bash
tar xf ffmpeg-n9.0.1.tar.gz && cd FFmpeg-n9.0.1
for p in ../patches/*.patch; do patch -p1 < "$p"; done
```

The Windows build applies the same patches through the vcpkg port's `PATCHES`
list, ahead of the port's own; `recipe/vendor-ffmpeg-windows.yml` shows how.

### 2. Modify and build FFmpeg

Make your changes, then build with the same component set we use — the flags are
in `recipe/vendor-ffmpeg-windows.yml`. The build must produce a tree laid out
like a normal prefix install:

```
<your-prefix>/
  include/
  lib/
    *.lib                 (or *.a / *.so on Unix)
    pkgconfig/
      libavcodec.pc
      libavutil.pc
```

⚠️ The **`.pc` files are load-bearing** — the Rust build finds FFmpeg through
`pkg-config`, not through hard-coded paths. If they are missing or their `prefix=`
is wrong, the build fails at the `ffmpeg-sys-next` step rather than silently
linking the wrong library.

You may of course build FFmpeg **shared** instead of static; nothing in the agent
requires static linkage.

### 3. Relink the agent

```bash
git clone https://github.com/gjovanov/roomler-ai
cd roomler-ai
git checkout <the tag matching your binary, e.g. agent-v0.4.13>
```

Point `pkg-config` at your build and rebuild. Windows (PowerShell), matching the
release workflow:

```powershell
$env:PKG_CONFIG_PATH = "<your-prefix>/lib/pkgconfig"
cargo build -p meshharbord --release --features `
  "full-hw,vp9-444,system-context,ffmpeg-encoder,overlay-l3,overlay-netstack,ssh-server"
```

Linux:

```bash
export FFMPEG_DIR=<your-prefix>
export PKG_CONFIG_PATH=<your-prefix>/lib/pkgconfig
cargo build -p meshharbord --release \
  --features "full,vp9-444,vp9-444-bindgen,overlay-l3,overlay-netstack,ffmpeg-encoder,ssh-server"
```

The result is `target/release/roomlerd(.exe)`, linked against **your** FFmpeg.

⚠️ Use the feature list for the platform you are reproducing — they differ. macOS
ships FFmpeg again since 2026-08-25 (a `--disable-everything` tree with the three
`*_videotoolbox` encoders, as shared dylibs built with `--disable-autodetect` so
nothing Homebrew is baked in), and Linux x86_64's tree carries libva + libdrm
built into it since FR-77 P4. Since FR-85 P4c every platform's tree also carries
the software `h264` decoder and the `aac` encoder, for the screen recorder's
editor and sound (the `-h264dec-aac` assets; never an `hevc` decoder). The
authoritative lists are the `cargo build` lines in
`.github/workflows/release-agent.yml`, and the `recording` feature is in `full`.

⚠️ Windows also needs libvpx for the VP9-4:4:4 path; the workflow vendors it the
same way (`vendor-libvpx-windows.yml`) and appends it to `PKG_CONFIG_PATH`. If
you do not need VP9-4:4:4, drop the `vp9-444` features.

### 4. Verify it works

```bash
./roomlerd --version
./roomlerd encoder-smoke --codec hevc     # exercises the FFmpeg encoder path
```

`encoder-smoke` feeds synthetic frames through the hardware cascade and reports
which encoder opened. That is the quickest confirmation that your FFmpeg is the
one actually being used.

---

## Note on the signature

A relinked binary is **not** signed by us, and our auto-updater deliberately
refuses artifacts that are not signed by `G ROX LTD` (see
[docs/code-signing.md](code-signing.md)). This is a security control, not a
restriction on your §6 rights: your modified build runs fine, but it will not be
distributed by our update channel, and you should point it away from that channel
or manage updates yourself.

---

Problems following this? **legal@roomler.ai** — if a step here does not work, the
compliance claim is wrong and we want to fix it.
